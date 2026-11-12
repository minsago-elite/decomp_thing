package decompengine.web

import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentTaskProgress
import decompengine.agent.AgentTurnIdentity
import decompengine.agent.AgentToolEvent
import decompengine.agent.AgentWorkflowPhase
import decompengine.agent.AgentWorkflowProgress
import decompengine.agent.AgentWorkflowRunObservation
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowUsage
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.NoSuchFileException
import java.nio.file.Path
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
    private val outputBytesOverride: (() -> Long?)? = null,
) {
    private val toolCalls = AtomicLong()
    private val inputTokens = AtomicLong(-1)
    private val outputTokens = AtomicLong(-1)
    private val cachedInputTokens = AtomicLong(-1)
    private val lastActivity = AtomicLong(nanoTime())
    @Volatile private var executionStartedNanos: Long? = null
    @Volatile private var publicationDecisionAdmitted = false
    @Volatile private var limitObservedBeforePublication: WorkflowLimitExhaustion? = null
    private var callerCancelledBeforePublication = false

    fun activity() { lastActivity.set(nanoTime()) }
    fun lastActivityNanos(): Long = lastActivity.get()
    fun toolCalls(): Long = toolCalls.get()

    @Synchronized
    fun beginExecution(startedNanos: Long) { executionStartedNanos = startedNanos }

    /** Returns false only after the final publication admission has closed the limit boundary. */
    @Synchronized
    fun observeLimit(limit: WorkflowLimitExhaustion): Boolean {
        if (publicationDecisionAdmitted) return false
        if (limitObservedBeforePublication == null) limitObservedBeforePublication = limit
        return true
    }

    fun admitPublication(limits: WorkflowExecutionLimits) {
        val started = checkNotNull(executionStartedNanos) { "workflow execution has not started" }
        val output = outputBytes()
        synchronized(this) {
            if (callerCancelledBeforePublication) throw InterruptedException("workflow cancelled before publication admission")
            val now = nanoTime()
            val elapsedWall = TimeUnit.NANOSECONDS.toMillis(maxOf(0L, now - started)).toULong()
            val elapsedIdle = TimeUnit.NANOSECONDS.toMillis(maxOf(0L, now - lastActivity.get())).toULong()
            val reason = limitObservedBeforePublication ?: when {
                elapsedWall > limits.wallClockMs -> WorkflowLimitExhaustion.WALL_CLOCK
                toolCallsMetered && toolCalls().toULong() > limits.maxToolCalls -> WorkflowLimitExhaustion.TOOL_CALLS
                output == null || output.toULong() > limits.maxOutputBytes -> WorkflowLimitExhaustion.OUTPUT_BYTES
                elapsedIdle > limits.idleMs -> WorkflowLimitExhaustion.IDLE
                else -> null
            }
            if (reason != null) {
                limitObservedBeforePublication = reason
                throw WorkflowPublicationLimitExceeded(reason)
            }
            publicationDecisionAdmitted = true
        }
    }

    /** Cancellation and publication admission share this monitor as their linearization point. */
    @Synchronized
    fun requestCancellationBeforePublication(): Boolean {
        if (publicationDecisionAdmitted) return false
        callerCancelledBeforePublication = true
        return true
    }

    fun publicationDecisionIsAdmitted(): Boolean = publicationDecisionAdmitted

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
        outputBytesOverride?.let { return it() }
        // Inspect the retained tree through descriptor metadata and O_NOATIME directory reads.
        // Ordinary Files.walkFileTree advances directory atime, which is part of the exact source
        // witness captured by repair publication and would make the metering read mutate its input.
        val rootState = try {
            Files.readAttributes(reportsDirectory, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        } catch (_: NoSuchFileException) { return 0L } catch (_: java.io.IOException) { return null }
        if (!rootState.isDirectory || maximumEntries <= 0) return null
        var total = 0L
        var entries = 0
        return try {
            LinuxFilesystemSyscalls.openRoot(reportsDirectory).use { root ->
                val rootIdentity = LinuxFilesystemSyscalls.identity(root.fd)
                if (!rootIdentity.isDirectory || rootIdentity.isSymbolicLink) {
                    throw java.io.IOException("output root is not a directory")
                }
                entries = 1

                fun visit(directory: decompengine.acp.LinuxDescriptor) {
                    val names = LinuxFilesystemSyscalls.directoryEntryNamesWithoutAtime(
                        directory,
                        maximumEntries,
                        onEntry = {
                            if (entries >= maximumEntries) throw WalkLimit()
                            entries++
                        },
                    )
                    for (name in names) {
                        val entry = LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, name)
                        if (entry == null) {
                            // Match Files.walkFileTree's vanished-entry behavior.
                            entries--
                            continue
                        }
                        entry.use { pinnedEntry ->
                            val state = LinuxFilesystemSyscalls.fileState(pinnedEntry)
                            if (state.identity.isDirectory && !state.identity.isSymbolicLink) {
                                LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, name).use { childDirectory ->
                                    val opened = LinuxFilesystemSyscalls.identity(childDirectory.fd)
                                    if (opened.key != state.identity.key || opened.mountId != state.identity.mountId) {
                                        throw java.io.IOException("output directory changed during metering")
                                    }
                                    visit(childDirectory)
                                }
                            } else {
                                total = if (Long.MAX_VALUE - total < state.size) Long.MAX_VALUE else total + state.size
                            }
                        }
                    }
                }

                visit(root)
            }
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

    /** Snapshot measured usage at the durable publication boundary, before it can be acknowledged. */
    fun usageSoFar(): WorkflowUsage {
        val started = checkNotNull(executionStartedNanos) { "workflow execution has not started" }
        return usage(TimeUnit.NANOSECONDS.toMillis(maxOf(0L, nanoTime() - started)))
    }

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
    override fun beginTask(
        taskId: String,
        request: AgentExecutionRequest,
        turnIdentity: AgentTurnIdentity,
    ): AgentTaskProgress {
        meter.activity(); return metered(delegate.beginTask(taskId, request, turnIdentity))
    }
    override fun beginTask(taskId: String, request: AgentExecutionRequest, workflowRunId: String): AgentTaskProgress {
        meter.activity(); return metered(delegate.beginTask(taskId, request, workflowRunId))
    }
    override fun beginTask(
        taskId: String,
        request: AgentExecutionRequest,
        workflowRunId: String,
        turnIdentity: AgentTurnIdentity,
    ): AgentTaskProgress {
        meter.activity(); return metered(delegate.beginTask(taskId, request, workflowRunId, turnIdentity))
    }
    override fun phase(phase: AgentWorkflowPhase, taskId: String?, acceptedRevisionSha256: String?) {
        meter.activity(); delegate.phase(phase, taskId, acceptedRevisionSha256)
    }
    override fun runState(observation: AgentWorkflowRunObservation) { meter.activity(); delegate.runState(observation) }

    // Each task is one agent invocation with its own tool-call identity space.
    private fun metered(task: AgentTaskProgress): AgentTaskProgress {
        val invocation = meter.invocation()
        return object : AgentTaskProgress {
            override val turnIdentity: AgentTurnIdentity? get() = task.turnIdentity
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

internal class WorkflowPublicationLimitExceeded(val limit: WorkflowLimitExhaustion) :
    RuntimeException("workflow limit exceeded before publication: ${limit.name}", null, false, false)

/**
 * Runs one workflow body on an owned child thread and enforces the attempt's recorded limits.
 * A breached limit or caller interruption interrupts the child, which must stop its own process
 * trees; this never returns while the child is alive. Caller interruption is rethrown after the
 * child stops, so the service records cancellation or interruption rather than an outcome.
 */
internal class BoundedWorkflowExecutor(
    private val pollMillis: Long = 250,
    private val outputPollMillis: Long = 2_000,
    private val nanoTime: () -> Long = System::nanoTime,
) {
    init { require(pollMillis in 1..10_000 && outputPollMillis >= pollMillis) }

    fun <T> run(limits: WorkflowExecutionLimits, meter: WorkflowExecutionMeter, body: () -> T): Pair<BoundedWorkflowResult<T>, WorkflowUsage> {
        val started = nanoTime()
        meter.beginExecution(started)
        var result: BoundedWorkflowResult<T>? = null
        val child = Thread({
            result = try { BoundedWorkflowResult.Returned(body()) } catch (failure: Throwable) { BoundedWorkflowResult.Threw(failure) }
        }, "decomp-web-workflow-child").apply { isDaemon = true }
        meter.activity()
        var lastOutput: Long? = meter.outputBytes()
        child.start()
        var exhausted: WorkflowLimitExhaustion? = null
        var cancelledBeforePublication: InterruptedException? = null
        var nextOutputCheck = started
        try {
            while (child.isAlive) {
                child.join(pollMillis)
                if (!child.isAlive) break
                val now = nanoTime()
                if (now >= nextOutputCheck) {
                    nextOutputCheck = now + TimeUnit.MILLISECONDS.toNanos(outputPollMillis)
                    val bytes = meter.outputBytes()
                    if (bytes == null || bytes.toULong() > limits.maxOutputBytes) {
                        if (meter.observeLimit(WorkflowLimitExhaustion.OUTPUT_BYTES)) {
                            exhausted = WorkflowLimitExhaustion.OUTPUT_BYTES
                            break
                        }
                    } else if (bytes != lastOutput) { if (lastOutput != null) meter.activity(); lastOutput = bytes }
                }
                exhausted = when {
                    elapsed(now, started) > limits.wallClockMs -> WorkflowLimitExhaustion.WALL_CLOCK
                    meter.toolCallsMetered && meter.toolCalls().toULong() > limits.maxToolCalls -> WorkflowLimitExhaustion.TOOL_CALLS
                    elapsed(now, meter.lastActivityNanos()) > limits.idleMs -> WorkflowLimitExhaustion.IDLE
                    else -> null
                }
                if (exhausted != null) {
                    if (meter.observeLimit(checkNotNull(exhausted))) break
                    exhausted = null
                }
            }
        } catch (interrupted: InterruptedException) {
            if (meter.requestCancellationBeforePublication()) {
                stop(child)
                // The child may have discovered that cancellation interrupted rollback and
                // left a durable publication journal pending. Inspect its completed result
                // before classifying this as ordinary cancellation.
                cancelledBeforePublication = interrupted
            }
            // Publication admission is the cancellation linearization point. Do not interrupt the
            // publisher after it has durably decided to replace the accepted generation. Let it
            // finish; the service already persisted the cancellation request before interrupting
            // this worker and resolves that race as completion because publication admission won.
            while (child.isAlive) {
                try { child.join(pollMillis) } catch (_: InterruptedException) { /* admission already won */ }
            }
        }
        if (exhausted != null) stop(child)
        // A body that finished between samples is still held to every declared bound.
        val bodyResult = checkNotNull(result)
        val pendingPublication = (bodyResult as? BoundedWorkflowResult.Threw)?.failure
            as? decompengine.project.ReconstructionPublicationPendingException
        if (pendingPublication != null) throw pendingPublication
        cancelledBeforePublication?.let { throw it }
        val publicationLimit = (bodyResult as? BoundedWorkflowResult.Threw)?.failure as? WorkflowPublicationLimitExceeded
        val finished = exhausted?.let { BoundedWorkflowResult.Exhausted(it) }
            ?: publicationLimit?.let { BoundedWorkflowResult.Exhausted(it.limit) }
            ?: bodyResult
        val needsFinalMeasurement = finished !is BoundedWorkflowResult.Exhausted && !meter.publicationDecisionIsAdmitted()
        val finalOutput = if (needsFinalMeasurement) meter.outputBytes() else null
        // The final bounded output walk is part of execution time, so sample the clock afterwards.
        val finishedAt = nanoTime()
        val wall = TimeUnit.NANOSECONDS.toMillis(finishedAt - started)
        val final = if (!needsFinalMeasurement) finished else {
            val limit = when {
                elapsed(finishedAt, started) > limits.wallClockMs -> BoundedWorkflowResult.Exhausted(WorkflowLimitExhaustion.WALL_CLOCK)
                meter.toolCallsMetered && meter.toolCalls().toULong() > limits.maxToolCalls ->
                    BoundedWorkflowResult.Exhausted(WorkflowLimitExhaustion.TOOL_CALLS)
                finalOutput == null || finalOutput.toULong() > limits.maxOutputBytes -> BoundedWorkflowResult.Exhausted(WorkflowLimitExhaustion.OUTPUT_BYTES)
                // Output written since the last sample is activity of unknown time, so it cannot prove idleness.
                finalOutput == lastOutput && elapsed(finishedAt, meter.lastActivityNanos()) > limits.idleMs ->
                    BoundedWorkflowResult.Exhausted(WorkflowLimitExhaustion.IDLE)
                else -> null
            }
            limit ?: finished
        }
        return final to meter.usage(wall)
    }

    /**
     * Signal cancellation once, then wait for the owned child to finish its cleanup.
     * Repeated interrupts are unsafe here: a child may be handling the first interruption by
     * rolling back an undecided durable publication, and interrupting its recovery I/O can turn
     * a normal cancellation into a permanently pending transaction. A body that ignores its
     * interrupt already prevents this method from returning; repeating the signal cannot make
     * that non-cooperative body safe to abandon.
     */
    private fun stop(child: Thread) {
        var interrupted = false
        child.interrupt()
        while (child.isAlive) {
            try { child.join(pollMillis) } catch (_: InterruptedException) { interrupted = true }
        }
        if (interrupted) Thread.currentThread().interrupt()
    }

    private fun elapsed(now: Long, since: Long): ULong = TimeUnit.NANOSECONDS.toMillis(maxOf(0, now - since)).toULong()
}
