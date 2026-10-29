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
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.NoSuchFileException
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
    private val toolCalls = AtomicLong()
    private val inputTokens = AtomicLong(-1)
    private val outputTokens = AtomicLong(-1)
    private val cachedInputTokens = AtomicLong(-1)
    private val lastActivity = AtomicLong(nanoTime())

    fun activity() { lastActivity.set(nanoTime()) }
    fun lastActivityNanos(): Long = lastActivity.get()
    fun toolCalls(): Long = toolCalls.get()

    /**
     * One agent invocation. Tool-call identities are unique only within an invocation, so each one
     * deduplicates its own updates and adds its distinct calls to the attempt total. A returned
     * receipt that reports more calls than were observed raises the total to that report.
     */
    inner class Invocation internal constructor() {
        private val identities = HashSet<String>()
        private var counted = 0L

        fun observe(event: AgentExecutionEvent) {
            activity()
            if (event is AgentToolEvent) synchronized(this) {
                // A bounded identity set; beyond it each event is counted, which can only over-count.
                if (identities.size >= 100_000 || identities.add(event.toolCallId)) count(1)
            }
        }

        fun receipt(receipt: AgentExecutionReceipt) {
            activity()
            val usage = (receipt.outcome as? AgentExecutionOutcome.Returned)?.result?.usage ?: return
            synchronized(this) { usage.toolCalls?.toLong()?.let { reported -> if (reported > counted) count(reported - counted) } }
            fun add(target: AtomicLong, value: Long?) {
                if (value == null) return
                target.updateAndGet { current -> val base = maxOf(current, 0); if (Long.MAX_VALUE - base < value) Long.MAX_VALUE else base + value }
            }
            add(inputTokens, usage.inputTokens); add(outputTokens, usage.outputTokens); add(cachedInputTokens, usage.cachedInputTokens)
        }

        private fun count(calls: Long) {
            counted += calls
            toolCalls.updateAndGet { if (Long.MAX_VALUE - it < calls) Long.MAX_VALUE else it + calls }
        }
    }

    fun invocation(): Invocation = Invocation()

    /** Exact retained bytes, or null when the bounded walk could not complete (treated as exhausted). */
    fun outputBytes(): Long? {
        // isDirectory collapses absence, denied reads, links and replaced roots into false. Only
        // known absence is empty output; every other incomplete observation must fail closed.
        val root = try {
            Files.readAttributes(reportsDirectory, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        } catch (_: NoSuchFileException) { return 0L } catch (_: java.io.IOException) { return null }
        if (!root.isDirectory) return null
        var total = 0L
        var entries = 0
        return try {
            Files.walkFileTree(reportsDirectory, object : SimpleFileVisitor<Path>() {
                override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
                    if (++entries > maximumEntries) throw WalkLimit()
                    return FileVisitResult.CONTINUE
                }
                override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                    // The root may have been replaced after its initial metadata read.
                    if (file == reportsDirectory || ++entries > maximumEntries) throw WalkLimit()
                    total = if (Long.MAX_VALUE - total < attrs.size()) Long.MAX_VALUE else total + attrs.size()
                    return FileVisitResult.CONTINUE
                }
                // A vanished entry is no longer retained. Denied/incomplete reads cannot prove a
                // byte total and must not turn an unreadable subtree into zero/partial output.
                override fun visitFileFailed(file: Path, exc: java.io.IOException): FileVisitResult {
                    if (exc is NoSuchFileException) return FileVisitResult.CONTINUE
                    throw exc
                }
            })
            total
        } catch (_: WalkLimit) { null } catch (_: java.io.IOException) { null }
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

    // Each task is one agent invocation with its own tool-call identity space.
    private fun metered(task: AgentTaskProgress): AgentTaskProgress {
        val invocation = meter.invocation()
        return object : AgentTaskProgress {
            override fun event(event: AgentExecutionEvent) { invocation.observe(event); task.event(event) }
            override fun complete(receipt: AgentExecutionReceipt) { invocation.receipt(receipt); task.complete(receipt) }
        }
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
        var lastOutput: Long? = meter.outputBytes()
        child.start()
        var exhausted: WorkflowLimitExhaustion? = null
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
        val finishedAt = nanoTime()
        val wall = TimeUnit.NANOSECONDS.toMillis(finishedAt - started)
        // A body that finished between samples is still held to every declared bound.
        val finished = exhausted?.let { BoundedWorkflowResult.Exhausted(it) } ?: checkNotNull(result)
        val final = if (finished !is BoundedWorkflowResult.Returned) finished else {
            val output = meter.outputBytes()
            when {
                elapsed(finishedAt, started) > limits.wallClockMs -> BoundedWorkflowResult.Exhausted(WorkflowLimitExhaustion.WALL_CLOCK)
                meter.toolCallsMetered && meter.toolCalls().toULong() > limits.maxToolCalls ->
                    BoundedWorkflowResult.Exhausted(WorkflowLimitExhaustion.TOOL_CALLS)
                output == null || output.toULong() > limits.maxOutputBytes -> BoundedWorkflowResult.Exhausted(WorkflowLimitExhaustion.OUTPUT_BYTES)
                // Output written since the last sample is activity of unknown time, so it cannot prove idleness.
                output == lastOutput && elapsed(finishedAt, meter.lastActivityNanos()) > limits.idleMs ->
                    BoundedWorkflowResult.Exhausted(WorkflowLimitExhaustion.IDLE)
                else -> finished
            }
        }
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
