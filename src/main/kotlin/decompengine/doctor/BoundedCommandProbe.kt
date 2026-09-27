package decompengine.doctor

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.file.Path
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit

internal data class CommandProbeLimits(
    val maximumWallClockMillis: Long = 60_000,
    val maximumOutputBytes: Int = 1_048_576,
    val cleanupMillis: Long = 5_000,
) {
    init {
        require(maximumWallClockMillis in 1..60_000) { "command probe wall-clock limit must be between 1 and 60000 milliseconds" }
        require(maximumOutputBytes in 1..1_048_576) { "command probe output limit must be between 1 and 1048576 bytes" }
        require(cleanupMillis in 1..5_000) { "command probe cleanup limit must be between 1 and 5000 milliseconds" }
    }
}

internal enum class CommandProbeLimitKind { TIMEOUT, OUTPUT_LIMIT }

internal class CommandProbeLimitException(val kind: CommandProbeLimitKind, message: String) : IOException(message)

/**
 * One monotonic allowance, optionally sharing an ancestor's remaining time and output.
 * Output accounting is atomic across the ancestry. Observed overflow bytes are charged even
 * when they cannot be retained, and an exceeded output allowance remains failed.
 */
internal class CommandProbeBudget(val limits: CommandProbeLimits, private val parent: CommandProbeBudget? = null) {
    private val startedNanos = System.nanoTime()
    private val allowanceNanos = TimeUnit.MILLISECONDS.toNanos(limits.maximumWallClockMillis)
    private val accountingLock: Any = parent?.accountingLock ?: Any()
    private var outputBytes = 0L
    private var outputFailure: CommandProbeLimitException? = null

    fun checkpoint(stage: String) {
        remainingNanos(stage)
    }

    fun remainingNanos(stage: String): Long {
        requireNotInterrupted(stage)
        synchronized(accountingLock) {
            requireOutputAvailable()
        }
        val now = System.nanoTime()
        var remaining = Long.MAX_VALUE
        var current: CommandProbeBudget? = this
        while (current != null) {
            val available = current.allowanceNanos - (now - current.startedNanos)
            if (available <= 0) {
                throw CommandProbeLimitException(
                    CommandProbeLimitKind.TIMEOUT,
                    "command probe exceeded ${current.limits.maximumWallClockMillis} milliseconds during $stage",
                )
            }
            remaining = minOf(remaining, available)
            current = current.parent
        }
        return remaining
    }

    fun remainingOutputBytes(): Int {
        requireNotInterrupted("output accounting")
        return synchronized(accountingLock) {
            requireOutputAvailable()
            var remaining = Int.MAX_VALUE
            var current: CommandProbeBudget? = this
            while (current != null) {
                remaining = minOf(remaining, (current.limits.maximumOutputBytes - current.outputBytes).toInt())
                current = current.parent
            }
            remaining
        }
    }

    fun consumeOutputBytes(count: Int) {
        require(count >= 0) { "command probe output count must not be negative" }
        requireNotInterrupted("output accounting")
        synchronized(accountingLock) {
            requireOutputAvailable()
            var current: CommandProbeBudget? = this
            while (current != null) {
                current.outputBytes += count.toLong()
                if (current.outputBytes > current.limits.maximumOutputBytes) {
                    current.outputFailure = CommandProbeLimitException(
                        CommandProbeLimitKind.OUTPUT_LIMIT,
                        "command probe output exceeded ${current.limits.maximumOutputBytes} bytes",
                    )
                }
                current = current.parent
            }
            requireOutputAvailable()
        }
    }

    internal fun effectiveCleanupMillis(): Long {
        var remaining = limits.cleanupMillis
        var current = parent
        while (current != null) {
            remaining = minOf(remaining, current.limits.cleanupMillis)
            current = current.parent
        }
        return remaining
    }

    private fun requireOutputAvailable() {
        var current: CommandProbeBudget? = this
        while (current != null) {
            current.outputFailure?.let { throw it }
            current = current.parent
        }
    }
}

internal interface BudgetedCommandProbe : CommandProbe {
    fun run(command: List<String>, workingDirectory: Path?, budget: CommandProbeBudget): CommandProbeResult

    override fun run(command: List<String>, workingDirectory: Path?): CommandProbeResult =
        run(command, workingDirectory, CommandProbeBudget(CommandProbeLimits()))
}

/**
 * Bounded local diagnostics for ordinary cooperating tools, without execution authority.
 * ProcessHandle snapshots cannot establish containment or find every reparented descendant.
 * Native start/discovery/signalling calls are cooperatively checked, not preemptible. Stream
 * closure and capture use owned daemon workers; incomplete cleanup is an explicit failure.
 */
internal class BoundedSystemCommandProbe(private val limits: CommandProbeLimits = CommandProbeLimits()) : BudgetedCommandProbe {
    override fun run(command: List<String>, workingDirectory: Path?, budget: CommandProbeBudget): CommandProbeResult {
        val localBudget = CommandProbeBudget(limits, budget)
        localBudget.checkpoint("before preparing command probe")
        val builder = ProcessBuilder(command.toList())
            .directory(workingDirectory?.toFile())
            .redirectErrorStream(true)
        localBudget.checkpoint("before starting command probe")
        val process = builder.start()
        val observed = linkedMapOf<Long, ProcessHandle>()
        var root: ProcessHandle? = null
        var capture: ProbeWorker<String>? = null
        var stdinClose: ProbeWorker<Unit>? = null
        var primaryFailure: Throwable? = null
        try {
            root = process.toHandle()
            observed[root.pid()] = root
            localBudget.checkpoint("after starting command probe")
            stdinClose = ProbeWorker("doctor-command-stdin-close") { process.outputStream.close() }
            capture = ProbeWorker("doctor-command-output") { captureOutput(process, localBudget) }
            while (true) {
                localBudget.checkpoint("waiting for command probe")
                discoverDescendants(root, observed) { localBudget.checkpoint("discovering command probe children") }
                if (stdinClose.isDone) stdinClose.result()
                if (capture.isDone) capture.result()
                val exited = !process.isAlive
                if (exited) {
                    // The root has finished; ordinary observed children must not hold the pipe open.
                    observed.values.forEach { handle ->
                        localBudget.checkpoint("stopping completed command probe children")
                        if (handle.isAlive) handle.destroyForcibly()
                    }
                }
                if (exited && capture.isDone && stdinClose.isDone) break
                val remaining = localBudget.remainingNanos("waiting for command probe output and exit")
                val waitNanos = minOf(remaining, PROBE_POLL_NANOS)
                if (!exited) process.waitFor(waitNanos, TimeUnit.NANOSECONDS)
                else TimeUnit.NANOSECONDS.sleep(waitNanos)
            }
            val result = CommandProbeResult(process.exitValue(), capture.result())
            localBudget.checkpoint("before completing command probe")
            return result
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            cleanupProbe(process, root, observed, capture, stdinClose, localBudget.effectiveCleanupMillis(), primaryFailure)
        }
    }
}

private fun captureOutput(process: Process, budget: CommandProbeBudget): String {
    budget.checkpoint("before capturing command probe output")
    // Allocating the admitted capacity once keeps ByteArrayOutputStream from doubling beyond it.
    val output = ByteArrayOutputStream(budget.remainingOutputBytes())
    val buffer = ByteArray(PROBE_CAPTURE_BYTES)
    while (true) {
        budget.checkpoint("before reading command probe output")
        val maximumRead = minOf(buffer.size, budget.remainingOutputBytes() + 1)
        val count = process.inputStream.read(buffer, 0, maximumRead)
        if (count > 0) budget.consumeOutputBytes(count)
        budget.checkpoint("after reading command probe output")
        if (count < 0) break
        if (count > 0) output.write(buffer, 0, count)
    }
    budget.checkpoint("before decoding command probe output")
    val result = output.toString(Charsets.UTF_8)
    budget.checkpoint("after decoding command probe output")
    return result
}

private fun discoverDescendants(root: ProcessHandle, observed: MutableMap<Long, ProcessHandle>, checkpoint: () -> Unit) {
    checkpoint()
    root.descendants().use { descendants ->
        val iterator = descendants.iterator()
        var visited = 0
        while (true) {
            checkpoint()
            val hasNext = iterator.hasNext()
            checkpoint()
            if (!hasNext) break
            val handle = iterator.next()
            checkpoint()
            visited++
            if (visited >= MAXIMUM_TRACKED_PROCESSES ||
                (handle.pid() !in observed && observed.size >= MAXIMUM_TRACKED_PROCESSES)
            ) {
                throw IOException("command probe exceeds $MAXIMUM_TRACKED_PROCESSES tracked processes including its root")
            }
            observed[handle.pid()] = handle
        }
    }
    checkpoint()
}

private class ProbeWorker<T>(name: String, action: () -> T) {
    private val task = FutureTask(Callable { action() })
    val thread: Thread = Thread(task, name).apply {
        isDaemon = true
        start()
    }
    val isDone: Boolean get() = task.isDone

    fun result(): T = try {
        task.get()
    } catch (failure: ExecutionException) {
        throw failure.cause ?: failure
    }
}

/** Cleanup has one additional allowance and never calls the possibly exhausted command budget. */
private fun cleanupProbe(
    process: Process,
    root: ProcessHandle?,
    observed: MutableMap<Long, ProcessHandle>,
    capture: ProbeWorker<String>?,
    stdinClose: ProbeWorker<Unit>?,
    cleanupMillis: Long,
    primaryFailure: Throwable?,
) {
    val started = System.nanoTime()
    val allowance = TimeUnit.MILLISECONDS.toNanos(cleanupMillis)
    var interrupted = Thread.interrupted() || primaryFailure is InterruptedException
    var cleanupFailure: Throwable? = null
    fun remaining(): Long = allowance - (System.nanoTime() - started)
    fun record(failure: Throwable) {
        if (failure === primaryFailure || failure === cleanupFailure) return
        val previous = cleanupFailure
        if (previous == null) cleanupFailure = failure else previous.addSuppressed(failure)
    }
    fun requireRemaining() {
        if (remaining() <= 0) throw IOException("command probe cleanup exceeded $cleanupMillis milliseconds")
    }
    fun attempt(action: () -> Unit) {
        try {
            requireRemaining()
            action()
            requireRemaining()
        } catch (failure: Throwable) {
            record(failure)
        }
    }
    val workers = mutableListOf<ProbeWorker<*>>()
    val closeWorkers = mutableListOf<ProbeWorker<Unit>>()
    capture?.let { workers += it }
    stdinClose?.let { workers += it; closeWorkers += it }
    try {
        var ownedRoot = root
        attempt {
            if (ownedRoot == null) ownedRoot = process.toHandle()
            val handle = requireNotNull(ownedRoot)
            observed[handle.pid()] = handle
            discoverDescendants(handle, observed, ::requireRemaining)
        }
        observed.values.forEach { handle ->
            attempt { if (handle.isAlive) handle.destroyForcibly() }
        }
        if (ownedRoot == null) record(IOException("command probe cleanup could not obtain its owned root handle"))

        fun closeInWorker(name: String, close: () -> Unit) {
            attempt {
                val worker = ProbeWorker(name, close)
                workers += worker
                closeWorkers += worker
            }
        }
        if (stdinClose == null) closeInWorker("doctor-command-stdin-close") { process.outputStream.close() }
        closeInWorker("doctor-command-stdout-close") { process.inputStream.close() }
        closeInWorker("doctor-command-stderr-close") { process.errorStream.close() }
        capture?.thread?.interrupt()

        while (remaining() > 0) {
            val processesAlive = observed.values.any { it.isAlive }
            val worker = workers.firstOrNull { it.thread.isAlive }
            if (!processesAlive && worker == null) break
            try {
                val waitNanos = minOf(remaining(), PROBE_POLL_NANOS)
                if (waitNanos <= 0) break
                if (worker != null) TimeUnit.NANOSECONDS.timedJoin(worker.thread, waitNanos)
                else TimeUnit.NANOSECONDS.sleep(waitNanos)
            } catch (_: InterruptedException) {
                interrupted = true
            }
        }
        val liveProcesses = observed.values.count { it.isAlive }
        val liveWorkers = workers.count { it.thread.isAlive }
        if (liveProcesses != 0 || liveWorkers != 0) {
            record(IOException(
                "command probe cleanup incomplete after $cleanupMillis milliseconds: " +
                    "$liveProcesses observed processes and $liveWorkers owned workers remain",
            ))
        }
        closeWorkers.filter { it.isDone }.forEach { worker ->
            try {
                worker.result()
            } catch (failure: Throwable) {
                record(failure)
            }
        }
    } catch (failure: Throwable) {
        record(failure)
    } finally {
        interrupted = Thread.interrupted() || interrupted
        if (interrupted) Thread.currentThread().interrupt()
    }
    val failure = if (interrupted && primaryFailure == null) {
        InterruptedException("command probe interrupted during cleanup").also { cancellation ->
            cleanupFailure?.let(cancellation::addSuppressed)
        }
    } else cleanupFailure
    if (failure != null) {
        if (primaryFailure != null) primaryFailure.addSuppressed(failure) else throw failure
    }
}

private fun requireNotInterrupted(stage: String) {
    if (Thread.currentThread().isInterrupted) throw InterruptedException("command probe interrupted during $stage")
}

private const val PROBE_CAPTURE_BYTES = 8192
private const val MAXIMUM_TRACKED_PROCESSES = 64
private val PROBE_POLL_NANOS = TimeUnit.MILLISECONDS.toNanos(10)
