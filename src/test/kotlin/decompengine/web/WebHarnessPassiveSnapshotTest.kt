package decompengine.web

import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class WebHarnessPassiveSnapshotTest {
    @Test
    fun `passive empty and closed snapshots never invoke the configured probe`() {
        val calls = AtomicInteger()
        var now = 0L
        val projector = WebHarnessReadinessProjector(
            probe = { calls.incrementAndGet(); error("private-config-token") },
            ttlNanos = 1_000, nanoTime = { now },
        )
        try {
            repeat(3) {
                now += 1_000
                val snapshot = projector.snapshot()
                assertEquals("unavailable", snapshot.state)
                assertEquals("READINESS_UNVERIFIED", snapshot.reasonCode)
                assertFalse(snapshot.toString().contains("private-config-token"))
                assertEquals(0, calls.get())
            }
        } finally { projector.close() }
        assertEquals("PROBE_FAILED", projector.snapshot().reasonCode)
        assertEquals(0, calls.get())
    }

    @Test
    fun `only an explicit refresh publishes a snapshot and expiry never refreshes it`() {
        val calls = AtomicInteger()
        var now = 0L
        val supported = WebHarnessReadiness("supported", null, "observed")
        val unsupported = WebHarnessReadiness("unsupported", "HARNESS_UNSUPPORTED", "unsupported selection")
        val projector = WebHarnessReadinessProjector(
            probe = { if (calls.incrementAndGet() == 1) supported else unsupported },
            ttlNanos = 1_000, nanoTime = { now },
        )
        try {
            assertEquals("READINESS_UNVERIFIED", projector.snapshot().reasonCode)
            assertEquals(0, calls.get())
            assertEquals(supported, projector.current())
            assertEquals(supported, projector.snapshot())
            now = 999
            assertEquals(supported, projector.snapshot())
            now = 1_000
            assertEquals("READINESS_UNVERIFIED", projector.snapshot().reasonCode)
            now = -1
            assertEquals("READINESS_UNVERIFIED", projector.snapshot().reasonCode)
            assertEquals(1, calls.get())
            now = 1_000
            assertEquals(unsupported, projector.current())
            assertEquals(unsupported, projector.snapshot())
            assertEquals(2, calls.get())
        } finally { projector.close() }
        assertEquals("PROBE_FAILED", projector.snapshot().reasonCode)
        assertEquals(2, calls.get())
    }

    @Test
    fun `a passive snapshot does not acquire the active refresh monitor`() {
        lateinit var projector: WebHarnessReadinessProjector
        val supported = WebHarnessReadiness("supported", null, "observed")
        projector = WebHarnessReadinessProjector(probe = {
            // The refresh caller holds its monitor while this callback runs on the executor.
            // A monitor-taking snapshot would wait for the refresh that is waiting for it.
            assertEquals("READINESS_UNVERIFIED", projector.snapshot().reasonCode)
            supported
        })
        try {
            assertEquals(supported, projector.current())
            assertEquals(supported, projector.snapshot())
        } finally { projector.close() }
    }
}
