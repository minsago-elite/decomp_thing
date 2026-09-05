package decompengine.oracle.fulltree

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Same-process monotonic budget; this object cannot be restored from a receipt. */
internal class ContainedCommandOperationDeadline(
    val maximumWallMillis: Long,
    private val nanoClock: () -> Long = System::nanoTime,
) {
    private val started = nanoClock()
    private val maximumNanos: Long
    private var rejected = false

    init {
        require(maximumWallMillis in 1_000L..86_400_000L && maximumWallMillis % 1_000L == 0L)
        maximumNanos = maximumWallMillis * 1_000_000L
    }

    val policy: JsonObject get() = JsonObject(mapOf(
        "provider" to JsonPrimitive("kotlin-contained-operation-wall-deadline-v1"),
        "maximumWallMillis" to JsonPrimitive(maximumWallMillis),
        "startedMonotonicNanos" to JsonPrimitive(started),
    ))

    @Synchronized
    private fun remainingNanos(): Long {
        check(!rejected) { "contained operation wall deadline is no longer usable" }
        val elapsed = nanoClock() - started
        if (elapsed < 0 || elapsed >= maximumNanos) {
            rejected = true
            error("contained operation wall deadline expired or clock regressed")
        }
        return maximumNanos - elapsed
    }

    fun requireCurrent() { remainingNanos() }

    fun remainingMillis(ceiling: Long): Long {
        require(ceiling > 0)
        val remaining = minOf(ceiling, remainingNanos() / 1_000_000L)
        check(remaining > 0) { "contained operation has less than one millisecond remaining" }
        return remaining
    }

    fun remainingWholeSecondsMillis(ceiling: Long): Long {
        val remaining = remainingMillis(ceiling) / 1_000L * 1_000L
        check(remaining >= 1_000L) { "contained operation has less than one service second remaining" }
        return remaining
    }

    fun snapshot(): JsonObject {
        val remaining = remainingNanos()
        return JsonObject(policy + mapOf(
            "elapsedNanos" to JsonPrimitive(maximumNanos - remaining),
            "remainingNanos" to JsonPrimitive(remaining),
        ))
    }
}
