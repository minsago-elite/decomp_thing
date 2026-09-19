package decompengine.analysis

import java.util.concurrent.TimeUnit

/** One invocation's cooperative elapsed allowance; child limits can only shorten it. */
internal class AnalysisDeadline private constructor(
    private val startedNanos: Long,
    private val maximumNanos: Long,
    private val description: String,
    private val parent: AnalysisDeadline?,
) {
    val maximumMillis: Long get() = TimeUnit.NANOSECONDS.toMillis(maximumNanos)
    val parentMaximumMillis: Long? get() = parent?.maximumMillis

    fun checkpoint(stage: String) {
        remainingAt(System.nanoTime(), stage, rejectExpired = true)
    }

    fun remainingNanos(stage: String): Long = remainingAt(System.nanoTime(), stage, rejectExpired = true)

    /** Timed waits need zero on expiration so their existing diagnostic cleanup path can run. */
    fun remainingNanosOrZero(): Long = remainingAt(System.nanoTime(), "while waiting for analysis", rejectExpired = false)

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
        fun start(maximumNanos: Long, description: String, parent: AnalysisDeadline? = null): AnalysisDeadline {
            require(maximumNanos in 1..TimeUnit.HOURS.toNanos(24)) { "analysis deadline must be positive and at most 24 hours" }
            return AnalysisDeadline(System.nanoTime(), maximumNanos, description, parent)
        }
    }
}
