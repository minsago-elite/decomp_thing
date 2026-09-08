package decompengine.web

import java.util.concurrent.CountDownLatch
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** One periodic task; no per-job timers or queued work. Storage ownership outlives its last work callback. */
internal class WebProgressRetentionWorker(intervalMs: Long, step: () -> Unit, stopped: () -> Unit) {
    @Volatile private var started = false
    @Volatile private var finished = false
    private val notified = CountDownLatch(1)
    private val interval = intervalMs.also { require(it in 1..3_600_000) }
    private val executor = object : ScheduledThreadPoolExecutor(1, { task ->
        Thread({
            try { task.run() }
            finally {
                // Worker.run has released the executor's main lock. Never acquire service/storage
                // monitors from terminated(), which executes while that lock is still held.
                if (finished) try { stopped() } finally { notified.countDown() }
            }
        }, "decomp-web-progress-retention").apply { isDaemon = true }
    }) {
        override fun terminated() {
            // All work callbacks have left; notify the owner only after releasing executor locks.
            finished = true
        }
    }.apply { removeOnCancelPolicy = true }
    private val work = Runnable(step)

    @Synchronized fun start() {
        if (started) return
        check(!executor.isShutdown)
        started = true
        executor.scheduleWithFixedDelay(work, interval, interval, TimeUnit.MILLISECONDS)
    }
    fun stop() { executor.shutdownNow() }
    fun awaitStopped(nanos: Long) { if (started && nanos > 0) notified.await(nanos, TimeUnit.NANOSECONDS) }
    val isIdle: Boolean get() = !started || finished
}

internal data class WebProgressRetentionStatus(
    val enabled: Boolean, val examined: Long, val expired: Long, val failures: Long, val lastFailureCode: String?,
)
