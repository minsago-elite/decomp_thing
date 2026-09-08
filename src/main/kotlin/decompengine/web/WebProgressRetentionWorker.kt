package decompengine.web

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.buildJsonObject
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

/** Process-local scan counters, sampled for private bootstrap; never an expiry completion promise. */
internal fun webProgressRetentionStatus(status: WebProgressRetentionStatus): JsonObject =
    buildJsonObject {
        put("enabled", JsonPrimitive(status.enabled))
        put("sampledAt", JsonPrimitive(java.time.Instant.now().toString()))
        put("examined", JsonPrimitive(status.examined.toString()))
        put("expired", JsonPrimitive(status.expired.toString()))
        put("failures", JsonPrimitive(status.failures.toString()))
        put("lastFailureCode", status.lastFailureCode?.let { JsonPrimitive(it) } ?: JsonNull)
    }
