package decompengine.oracle.fulltree

import java.time.Duration

internal fun awaitColdSystemdManagerBusRegistration(
    query: (Duration) -> String,
    nanoTime: () -> Long = System::nanoTime,
    pause: (Long) -> Unit = Thread::sleep,
) {
    val started = nanoTime()
    val budget = Duration.ofSeconds(2).toNanos()
    fun remaining(): Long {
        val elapsed = nanoTime() - started
        if (elapsed < 0L || elapsed >= budget) {
            throw FullTreeFunctionObservationIsolationException("cold systemd manager bus registration deadline expired")
        }
        return budget - elapsed
    }
    repeat(81) {
        val output = query(Duration.ofNanos(remaining()))
        val registered = parseColdSystemdBusctlBooleanReply(output, "manager bus registration")
        val remainingNanos = remaining()
        if (registered) return
        pause(minOf(25L, Duration.ofNanos(remainingNanos).toMillis().coerceAtLeast(1L)))
    }
    throw FullTreeFunctionObservationIsolationException("cold systemd manager bus registration query bound exhausted")
}
