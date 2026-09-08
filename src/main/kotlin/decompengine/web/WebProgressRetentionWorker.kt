package decompengine.web

import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** One periodic task; no per-job timers or queued work. Storage ownership outlives its last work callback. */
internal class WebProgressRetentionWorker(intervalMs: Long, step: () -> Unit, stopped: () -> Unit) {
    @Volatile private var started = false
    @Volatile private var finished = false
    private val interval = intervalMs.also { require(it in 1..3_600_000) }
    private val executor = object : ScheduledThreadPoolExecutor(1, { task ->
        Thread(task, "decomp-web-progress-retention").apply { isDaemon = true }
    }) {
        override fun terminated() {
            // All work callbacks have left; remaining executor teardown cannot access storage.
            finished = true
            stopped()
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
    fun awaitStopped(nanos: Long) { if (nanos > 0) executor.awaitTermination(nanos, TimeUnit.NANOSECONDS) }
    val isIdle: Boolean get() = !started || finished
}

internal data class WebProgressRetentionStatus(
    val enabled: Boolean, val examined: Long, val expired: Long, val failures: Long, val lastFailureCode: String?,
)
