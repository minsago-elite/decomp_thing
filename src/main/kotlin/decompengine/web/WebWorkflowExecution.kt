package decompengine.web

import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentTaskProgress
import decompengine.agent.AgentToolEvent
import decompengine.agent.AgentWorkflowPhase
import decompengine.agent.AgentWorkflowProgress
import decompengine.agent.AgentWorkflowRunObservation
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowUsage
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

internal enum class WorkflowLimitExhaustion { WALL_CLOCK, IDLE, OUTPUT_BYTES, TOOL_CALLS }

/**
 * Observations used to enforce one attempt's recorded limits. Output is the retained byte total of
 * the attempt's own report directory; tool calls and tokens come only from metered agent progress.
 */
internal class WorkflowExecutionMeter(
    private val reportsDirectory: Path,
    val toolCallsMetered: Boolean,
    private val maximumEntries: Int = 250_000,
    private val nanoTime: () -> Long = System::nanoTime,
) {
    private val toolCallIds = HashSet<String>()
    private val toolCalls = AtomicLong()
    private val inputTokens = AtomicLong(-1)
    private val outputTokens = AtomicLong(-1)
    private val cachedInputTokens = AtomicLong(-1)
    private val lastActivity = AtomicLong(nanoTime())

    fun activity() { lastActivity.set(nanoTime()) }
    fun lastActivityNanos(): Long = lastActivity.get()
    fun toolCalls(): Long = toolCalls.get()

    fun observe(event: AgentExecutionEvent) {
        activity()
        if (event is AgentToolEvent) synchronized(toolCallIds) {
            // A bounded identity set; beyond it each event is counted, which can only over-count.
            if (toolCallIds.size >= 100_000 || toolCallIds.add(event.toolCallId)) toolCalls.incrementAndGet()
        }
    }

    fun receipt(receipt: AgentExecutionReceipt) {
        activity()
        val usage = (receipt.outcome as? AgentExecutionOutcome.Returned)?.result?.usage ?: return
        fun add(target: AtomicLong, value: Long?) {
            if (value == null) return
            target.updateAndGet { current -> val base = maxOf(current, 0); if (Long.MAX_VALUE - base < value) Long.MAX_VALUE else base + value }
        }
        add(inputTokens, usage.inputTokens); add(outputTokens, usage.outputTokens); add(cachedInputTokens, usage.cachedInputTokens)
    }

    /** Exact retained bytes, or null when the bounded walk could not complete (treated as exhausted). */
    fun outputBytes(): Long? {
        if (!Files.isDirectory(reportsDirectory)) return 0
        var total = 0L
        var entries = 0
        return try {
            Files.walkFileTree(reportsDirectory, object : SimpleFileVisitor<Path>() {
                override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
                    if (++entries > maximumEntries) throw WalkLimit()
                    return FileVisitResult.CONTINUE
                }
                override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                    if (++entries > maximumEntries) throw WalkLimit()
                    total = if (Long.MAX_VALUE - total < attrs.size()) Long.MAX_VALUE else total + attrs.size()
                    return FileVisitResult.CONTINUE
                }
                // A file removed during the walk is simply no longer retained output.
                override fun visitFileFailed(file: Path, exc: java.io.IOException): FileVisitResult = FileVisitResult.CONTINUE
            })
            total
        } catch (_: WalkLimit) { null } catch (_: java.io.IOException) { total }
    }

    fun usage(wallClockMillis: Long): WorkflowUsage = WorkflowUsage(
        inputTokens = inputTokens.get().takeIf { it >= 0 }?.toULong(),
        outputTokens = outputTokens.get().takeIf { it >= 0 }?.toULong(),
        cachedInputTokens = cachedInputTokens.get().takeIf { it >= 0 }?.toULong(),
        toolCalls = if (toolCallsMetered) toolCalls.get().toULong() else null,
        wallClockMs = wallClockMillis.coerceAtLeast(0).toULong(),
    )

    private class WalkLimit : RuntimeException(null, null, false, false)
}

/** Every agent callback is activity; tool identities and returned usage are metered, then delegated unchanged. */
internal class MeteredWorkflowProgress(
    private val delegate: AgentWorkflowProgress,
    private val meter: WorkflowExecutionMeter,
) : AgentWorkflowProgress {
    override fun beginTask(taskId: String, request: AgentExecutionRequest): AgentTaskProgress {
        meter.activity(); return metered(delegate.beginTask(taskId, request))
    }
    override fun beginTask(taskId: String, request: AgentExecutionRequest, workflowRunId: String): AgentTaskProgress {
        meter.activity(); return metered(delegate.beginTask(taskId, request, workflowRunId))
    }
    override fun phase(phase: AgentWorkflowPhase, taskId: String?, acceptedRevisionSha256: String?) {
        meter.activity(); delegate.phase(phase, taskId, acceptedRevisionSha256)
    }
    override fun runState(observation: AgentWorkflowRunObservation) { meter.activity(); delegate.runState(observation) }

    private fun metered(task: AgentTaskProgress) = object : AgentTaskProgress {
        override fun event(event: AgentExecutionEvent) { meter.observe(event); task.event(event) }
        override fun complete(receipt: AgentExecutionReceipt) { meter.receipt(receipt); task.complete(receipt) }
    }
}

internal sealed interface BoundedWorkflowResult<out T> {
    data class Returned<T>(val value: T) : BoundedWorkflowResult<T>
    data class Threw(val failure: Throwable) : BoundedWorkflowResult<Nothing>
    data class Exhausted(val limit: WorkflowLimitExhaustion) : BoundedWorkflowResult<Nothing>
}

/**
 * Runs one workflow body on an owned child thread and enforces the attempt's recorded limits.
 * A breached limit or caller interruption interrupts the child, which must stop its own process
 * trees; this never returns while the child is alive. Caller interruption is rethrown after the
 * child stops, so the service records cancellation or interruption rather than an outcome.
 */
internal class BoundedWorkflowExecutor(
    private val pollMillis: Long = 250,
    private val outputPollMillis: Long = 2_000,
    private val reinterruptMillis: Long = 1_000,
    private val nanoTime: () -> Long = System::nanoTime,
) {
    init { require(pollMillis in 1..10_000 && outputPollMillis >= pollMillis && reinterruptMillis >= pollMillis) }

    fun <T> run(limits: WorkflowExecutionLimits, meter: WorkflowExecutionMeter, body: () -> T): Pair<BoundedWorkflowResult<T>, WorkflowUsage> {
        val started = nanoTime()
        var result: BoundedWorkflowResult<T>? = null
        val child = Thread({
            result = try { BoundedWorkflowResult.Returned(body()) } catch (failure: Throwable) { BoundedWorkflowResult.Threw(failure) }
        }, "decomp-web-workflow-child").apply { isDaemon = true }
        meter.activity()
        child.start()
        var exhausted: WorkflowLimitExhaustion? = null
        var lastOutput: Long? = null
        var nextOutputCheck = started
        try {
            while (child.isAlive) {
                child.join(pollMillis)
                if (!child.isAlive) break
                val now = nanoTime()
                if (now >= nextOutputCheck) {
                    nextOutputCheck = now + TimeUnit.MILLISECONDS.toNanos(outputPollMillis)
                    val bytes = meter.outputBytes()
                    if (bytes == null || bytes.toULong() > limits.maxOutputBytes) { exhausted = WorkflowLimitExhaustion.OUTPUT_BYTES; break }
                    if (bytes != lastOutput) { if (lastOutput != null) meter.activity(); lastOutput = bytes }
                }
                exhausted = when {
                    elapsed(now, started) > limits.wallClockMs -> WorkflowLimitExhaustion.WALL_CLOCK
                    meter.toolCallsMetered && meter.toolCalls().toULong() > limits.maxToolCalls -> WorkflowLimitExhaustion.TOOL_CALLS
                    elapsed(now, meter.lastActivityNanos()) > limits.idleMs -> WorkflowLimitExhaustion.IDLE
                    else -> null
                }
                if (exhausted != null) break
            }
        } catch (interrupted: InterruptedException) {
            stop(child)
            throw interrupted
        }
        if (exhausted != null) stop(child)
        val wall = TimeUnit.NANOSECONDS.toMillis(nanoTime() - started)
        // A body that finished after a breach was observed still exceeded its declared bound.
        val finished = exhausted?.let { BoundedWorkflowResult.Exhausted(it) } ?: checkNotNull(result)
        val final = if (finished is BoundedWorkflowResult.Returned && meter.toolCallsMetered &&
            meter.toolCalls().toULong() > limits.maxToolCalls) BoundedWorkflowResult.Exhausted(WorkflowLimitExhaustion.TOOL_CALLS)
        else if (finished is BoundedWorkflowResult.Returned && meter.outputBytes().let { it == null || it.toULong() > limits.maxOutputBytes })
            BoundedWorkflowResult.Exhausted(WorkflowLimitExhaustion.OUTPUT_BYTES)
        else finished
        return final to meter.usage(wall)
    }

    /** Interrupt repeatedly until the child exits; preserve a caller interrupt observed meanwhile. */
    private fun stop(child: Thread) {
        var interrupted = false
        var nextInterrupt = 0L
        while (child.isAlive) {
            val now = nanoTime()
            if (now >= nextInterrupt) { child.interrupt(); nextInterrupt = now + TimeUnit.MILLISECONDS.toNanos(reinterruptMillis) }
            try { child.join(pollMillis) } catch (_: InterruptedException) { interrupted = true }
        }
        if (interrupted) Thread.currentThread().interrupt()
    }

    private fun elapsed(now: Long, since: Long): ULong = TimeUnit.NANOSECONDS.toMillis(maxOf(0, now - since)).toULong()
}
