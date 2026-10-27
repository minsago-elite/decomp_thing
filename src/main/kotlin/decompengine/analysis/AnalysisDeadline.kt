package decompengine.analysis

import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** One invocation's elapsed allowance; checkpoints and the watchdog enforce it, and child limits can only shorten it. */
internal class AnalysisDeadline private constructor(
    private val startedNanos: Long,
    private val maximumNanos: Long,
    private val description: String,
    private val parent: AnalysisDeadline?,
    private val timeoutAdvice: String?,
) {
    val maximumMillis: Long get() = TimeUnit.NANOSECONDS.toMillis(maximumNanos)
    val parentMaximumMillis: Long? get() = parent?.maximumMillis

    fun checkpoint(stage: String) {
        remainingAt(System.nanoTime(), stage, rejectExpired = true)
    }

    fun remainingNanos(stage: String): Long = remainingAt(System.nanoTime(), stage, rejectExpired = true)

    /** Timed waits need zero on expiration so their existing diagnostic cleanup path can run. */
    fun remainingNanosOrZero(): Long = remainingAt(System.nanoTime(), "while waiting for analysis", rejectExpired = false)

    /** Interrupts an in-flight synchronous phase at expiry and waits for its cancellation cleanup to finish. */
    fun <T> enforceDuring(stage: String, operation: () -> T): T = enforceDuring(stage, { action, allowance ->
        val watchdog = WATCHDOG.schedule(action, allowance, TimeUnit.NANOSECONDS)
        AutoCloseable { watchdog.cancel(false) }
    }, operation)

    /** An internal scheduling seam permits controlled delivery races without replacing the shared clock. */
    internal fun <T> enforceDuring(stage: String, schedule: (Runnable, Long) -> AutoCloseable, operation: () -> T): T {
        checkpoint("before $stage")
        val allowance = remainingNanos("before $stage")
        val thread = Thread.currentThread()
        val delivery = Any()
        var retired = false
        var expired = false
        fun retire(): Boolean = synchronized(delivery) {
            retired = true
            expired
        }
        val watchdog = schedule(Runnable {
            synchronized(delivery) {
                if (!retired) {
                    expired = true
                    // Retirement must not pass a dispatch that can still interrupt this caller.
                    thread.interrupt()
                }
            }
        }, allowance)
        try {
            val result = operation()
            if (retire()) throw timeoutDuring(stage)
            checkpoint("after $stage")
            return result
        } catch (failure: Throwable) {
            val timedOut = retire()
            if (failure is Error) throw failure
            if (timedOut) throw timeoutDuring(stage, failure)
            throw failure
        } finally {
            retire()
            watchdog.close()
        }
    }

    private fun timeoutDuring(stage: String, cause: Throwable? = null): GhidraAnalysisException {
        // InterruptedException clears the flag in most blocking APIs; also clear it for APIs that
        // return after observing the watchdog interrupt so it cannot affect the caller's next task.
        Thread.interrupted()
        var observedExpiration: GhidraAnalysisException? = null
        val baseMessage = try {
            checkpoint("during $stage")
            "$description exceeded $maximumMillis milliseconds during $stage"
        } catch (expired: GhidraAnalysisException) {
            observedExpiration = expired
            expired.message ?: "$description exceeded $maximumMillis milliseconds during $stage"
        }
        val message = if (timeoutAdvice == null) baseMessage else "$baseMessage; $timeoutAdvice"
        return GhidraAnalysisException(message, cause).also { timeout ->
            observedExpiration?.let(timeout::addSuppressed)
        }
    }

    private fun remainingAt(now: Long, stage: String, rejectExpired: Boolean): Long {
        if (Thread.currentThread().isInterrupted) throw InterruptedException("analysis cancelled $stage")
        val parentRemaining = parent?.remainingAt(now, stage, rejectExpired) ?: Long.MAX_VALUE
        val elapsed = now - startedNanos
        val remaining = if (elapsed < 0 || elapsed >= maximumNanos) 0L else maximumNanos - elapsed
        if (rejectExpired && remaining == 0L) {
            throw GhidraAnalysisException("$description exceeded $maximumMillis milliseconds $stage")
        }
        return minOf(remaining, parentRemaining)
    }

    companion object {
        const val RECOVERY_TIMEOUT_ADVICE = "rerun with the same output directory to resume durable function checkpoints"

        private val WATCHDOG = ScheduledThreadPoolExecutor(1) { task ->
            Thread(task, "analysis-deadline-watchdog").apply { isDaemon = true }
        }.apply {
            removeOnCancelPolicy = true
        }

        fun start(
            maximumNanos: Long,
            description: String,
            parent: AnalysisDeadline? = null,
            timeoutAdvice: String? = parent?.timeoutAdvice,
        ): AnalysisDeadline {
            require(maximumNanos in 1..TimeUnit.HOURS.toNanos(24)) { "analysis deadline must be positive and at most 24 hours" }
            return AnalysisDeadline(System.nanoTime(), maximumNanos, description, parent, timeoutAdvice)
        }
    }
}
