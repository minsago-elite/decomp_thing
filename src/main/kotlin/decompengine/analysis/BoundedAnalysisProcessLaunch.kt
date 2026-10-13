package decompengine.analysis

import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
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
    private val lateCleanupFailure = AtomicReference<Throwable?>()

    fun start(
        checkpoint: (String) -> Unit,
        processStarter: () -> Process,
        stopLateProcess: (Process) -> Unit,
    ): Process {
        lateCleanupFailure.get()?.let {
            throw GhidraAnalysisException("analysis launch is unavailable after an unconfirmed late-worker cleanup", it)
        }
        checkpoint("before admitting export process launch")
        val launched = try {
            CompletableFuture.supplyAsync(processStarter, executor)
        } catch (failure: RejectedExecutionException) {
            throw GhidraAnalysisException("analysis process launch capacity is exhausted", failure)
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
                        lateCleanupFailure.compareAndSet(null, cleanupFailure)
                        if (cleanupFailure !== failure) failure.addSuppressed(cleanupFailure)
                    }
                }
            }
            throw failure
        }
    }
}
