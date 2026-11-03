package decompengine.analysis

import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.IdentityHashMap
import java.util.concurrent.atomic.AtomicReference

/** Native process creation may ignore interruption. All analysis launchers share this fixed cap. */
internal val ANALYSIS_PROCESS_LAUNCH_EXECUTOR: Executor = ThreadPoolExecutor(
    0, 2, 60L, TimeUnit.SECONDS, SynchronousQueue(),
    { task -> Thread(task, "analysis-process-launch").apply { isDaemon = true } },
    ThreadPoolExecutor.AbortPolicy(),
)

/** Transfers ownership once, or retains it until an abandoned launch has been stopped. */
internal class BoundedAnalysisProcessLaunch(
    private val executor: Executor = ANALYSIS_PROCESS_LAUNCH_EXECUTOR,
) {
    private data class QuarantinedOwner(
        val retainedReferences: MutableList<Any> = ArrayList(),
        val failures: MutableList<Throwable> = ArrayList(),
    )

    /** Also serializes the admission decision with quarantine publication. */
    private val quarantineLock = Any()
    private val quarantineFailure = AtomicReference<Throwable?>()
    private val quarantinedOwners = IdentityHashMap<Process, QuarantinedOwner>()

    /** Retains every uncertain process owner; repeated reports coalesce by process/reference identity. */
    internal fun quarantineUnconfirmedCleanup(failure: Throwable, process: Process, retainedOwner: Any) {
        synchronized(quarantineLock) {
            quarantineFailure.compareAndSet(null, failure)
            val owner = quarantinedOwners.getOrPut(process) { QuarantinedOwner() }
            if (owner.retainedReferences.none { it === process }) owner.retainedReferences.add(process)
            if (owner.retainedReferences.none { it === retainedOwner }) owner.retainedReferences.add(retainedOwner)
            if (owner.failures.none { it === failure }) owner.failures.add(failure)
        }
    }

    internal fun hasQuarantinedOwner(): Boolean = quarantineFailure.get() != null
    internal fun quarantinedProcessCount(): Int = synchronized(quarantineLock) { quarantinedOwners.size }
    internal fun hasQuarantinedProcess(process: Process): Boolean = synchronized(quarantineLock) {
        quarantinedOwners.containsKey(process)
    }
    internal fun retainedQuarantineReferenceCount(process: Process): Int = synchronized(quarantineLock) {
        quarantinedOwners[process]?.retainedReferences?.size ?: 0
    }
    internal fun retainedQuarantineOwnerForTests(process: Process): Any? = synchronized(quarantineLock) {
        quarantinedOwners[process]?.retainedReferences?.firstOrNull { it !== process }
    }
    internal fun quarantinedFailureCount(process: Process): Int = synchronized(quarantineLock) {
        quarantinedOwners[process]?.failures?.size ?: 0
    }

    fun start(
        checkpoint: (String) -> Unit,
        processStarter: () -> Process,
        stopLateProcess: (Process) -> Unit,
    ): Process = startWithAdmission(checkpoint, processStarter, stopLateProcess) {}

    /** Reports only proven refusal before a supplier is accepted; late launches remain owned. */
    fun startWithAdmission(
        checkpoint: (String) -> Unit,
        processStarter: () -> Process,
        stopLateProcess: (Process) -> Unit,
        onNotAdmitted: (Throwable) -> Unit,
    ): Process {
        fun refused(failure: Throwable): Nothing {
            try { onNotAdmitted(failure) }
            catch (callbackFailure: Throwable) {
                if (callbackFailure !== failure) failure.addSuppressed(callbackFailure)
            }
            throw failure
        }
        try {
            quarantineFailure.get()?.let {
                throw GhidraAnalysisException("analysis launch is unavailable after an unconfirmed worker cleanup", it)
            }
            checkpoint("before admitting export process launch")
        } catch (failure: Throwable) { refused(failure) }
        try {
            synchronized(quarantineLock) {
                quarantineFailure.get()?.let {
                    throw GhidraAnalysisException("analysis launch is unavailable after an unconfirmed worker cleanup", it)
                }
            }
        } catch (failure: GhidraAnalysisException) {
            refused(failure)
        }
        // Passing the protected check is the logical admission point. Submission stays outside
        // the quarantine lock because Executor.execute/ThreadFactory may block or run inline.
        // A launch admitted here may finish after quarantine; its existing late-cleanup callback
        // remains responsible for any process it creates.
        val launched = try {
            CompletableFuture.supplyAsync(processStarter, executor)
        } catch (failure: RejectedExecutionException) {
            refused(GhidraAnalysisException("analysis process launch capacity is exhausted", failure))
        }
        try {
            while (true) {
                checkpoint("while starting export process")
                val process = try {
                    launched.get(25, TimeUnit.MILLISECONDS)
                } catch (_: java.util.concurrent.TimeoutException) {
                    continue
                } catch (failure: ExecutionException) {
                    throw failure.cause ?: failure
                }
                // Keep the process in this cleanup scope until ownership can be returned.
                checkpoint("after starting export process")
                return process
            }
        } catch (failure: Throwable) {
            // Do not cancel the future: a native launch can still return an owned process later.
            // If it is already complete, this bounded cleanup runs here; otherwise it runs in
            // the capped launch thread when creation finishes. No unbounded cleanup pool exists.
            launched.whenComplete { process, _ ->
                if (process != null) {
                    try {
                        stopLateProcess(process)
                    } catch (cleanupFailure: Throwable) {
                        quarantineUnconfirmedCleanup(cleanupFailure, process, process)
                        if (cleanupFailure !== failure) failure.addSuppressed(cleanupFailure)
                    }
                }
            }
            throw failure
        }
    }
}
