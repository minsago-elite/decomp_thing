package decompengine.web

import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class WebHarnessReadinessTest {
    @Test
    fun `missing config is unavailable with a fixed reason and unknown selection is unsupported`() {
        val missing = WebHarnessReadinessProjector.probeEnvironment(emptyMap())
        assertEquals("unavailable", missing.state)
        assertEquals("HARNESS_NOT_CONFIGURED", missing.reasonCode)
        val unknown = WebHarnessReadinessProjector.probeEnvironment(mapOf("ACP_HARNESS" to "direct"))
        assertEquals("unsupported", unknown.state)
        assertEquals("HARNESS_UNSUPPORTED", unknown.reasonCode)
    }

    @Test
    fun `invalid configuration never discloses environment or exception text`() {
        val secret = "sk-secret-value-123"
        val result = WebHarnessReadinessProjector.probeEnvironment(
            mapOf("ACP_CONFIG_FILE" to "/nonexistent/$secret.json", "API_KEY" to secret),
        )
        assertEquals("unavailable", result.state)
        assertEquals("HARNESS_CONFIGURATION_INVALID", result.reasonCode)
        assertFalse(result.toString().contains(secret))
        assertFalse(result.toString().contains("/nonexistent"))
    }

    @Test
    fun `a hung probe is bounded by the deadline and reported as a timeout`() {
        val release = CountDownLatch(1)
        val projector = WebHarnessReadinessProjector(probe = { release.await(); WebHarnessReadiness("supported", null, "") }, timeoutMillis = 100)
        try {
            val started = System.nanoTime()
            val result = projector.current()
            assertTrue((System.nanoTime() - started) < 5_000_000_000L)
            assertEquals("unavailable", result.state)
            assertEquals("PROBE_TIMEOUT", result.reasonCode)
        } finally { release.countDown() }
    }

    @Test
    fun `results are cached within the ttl and refreshed after it`() {
        val calls = AtomicInteger()
        var now = 0L
        val projector = WebHarnessReadinessProjector(
            probe = { calls.incrementAndGet(); WebHarnessReadiness("supported", null, "ok") },
            ttlNanos = 1_000, nanoTime = { now },
        )
        assertNull(projector.current().reasonCode)
        now = 999
        projector.current()
        assertEquals(1, calls.get())
        now = 1_000
        projector.current()
        assertEquals(2, calls.get())
    }

    @Test
    fun `a throwing probe is reported without its message`() {
        val result = WebHarnessReadinessProjector(probe = { error("token=abc") }).current()
        assertEquals("PROBE_FAILED", result.reasonCode)
        assertFalse(result.message.contains("abc"))
    }
}
