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
    fun `a configured harness is ready only when every sandbox prerequisite is available`() {
        val environment = mapOf(
            "ACP_HARNESS" to "legacy-openai", "BASE_URL" to "https://example.invalid/v1",
            "API_KEY" to "legacy-key", "MODEL" to "legacy-model",
        )
        val directory = java.nio.file.Files.createTempDirectory(java.nio.file.Path.of("build"), "readiness")
        try {
            val bwrap = directory.resolve("bwrap")
            val timeout = directory.resolve("timeout")
            fun probe(json: Boolean, ghidra: Boolean = true) =
                WebHarnessReadinessProjector.probeEnvironment(environment, bwrap, timeout, { json }, { ghidra })
            val missing = probe(true)
            assertEquals("SANDBOX_HELPER_MISSING", missing.reasonCode)
            assertFalse(missing.toString().contains("legacy-key"))
            java.nio.file.Files.createFile(bwrap).toFile().setExecutable(true)
            assertEquals("SANDBOX_HELPER_MISSING", probe(true).reasonCode)
            java.nio.file.Files.createFile(timeout).toFile().setExecutable(true)
            assertEquals("SANDBOX_HELPER_MISSING", probe(false).reasonCode)
            assertEquals("GHIDRA_MISSING", probe(true, ghidra = false).reasonCode)
            val ready = probe(true)
            assertEquals("supported", ready.state)
            assertNull(ready.reasonCode)
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test
    fun `failed inspection blocks only the selected harness even when sandbox readiness already failed`() {
        val missing = WebPrerequisite(false, "SANDBOX_HELPER_MISSING", "Sandbox helpers are unavailable.")
        val facts = WebWorkflowPrerequisites(WebPrerequisite.AVAILABLE, missing, WebPrerequisite.AVAILABLE,
            harnesses = mapOf(WebAgentHarness.ACP to WebHarnessFacts(WebPrerequisite.AVAILABLE, null, selected = true),
                WebAgentHarness.LEGACY_OPENAI to WebHarnessFacts(WebPrerequisite.AVAILABLE, null)))
        val readiness = WebHarnessReadiness("unavailable", missing.reasonCode, missing.message,
            configurationIdentity = "current-config", prerequisites = facts)
        val failed = readiness.withAgentInspection(WebAgentPreflightSnapshot("failed", "inspection_1",
            WebAgentPreflight.REASON_FAILED, "current-config"))
        assertEquals(readiness.state, failed.state); assertEquals(readiness.reasonCode, failed.reasonCode)
        assertEquals(missing, failed.prerequisites?.sandbox)
        assertEquals(WebAgentPreflight.REASON_FAILED, failed.prerequisites?.agent?.reasonCode)
        assertEquals(WebAgentPreflight.REASON_FAILED, failed.prerequisites?.harness(WebAgentHarness.ACP)?.reasonCode)
        assertTrue(failed.prerequisites!!.harness(WebAgentHarness.LEGACY_OPENAI).available)
        assertEquals(readiness, readiness.withAgentInspection(WebAgentPreflightSnapshot("failed", "inspection_2",
            WebAgentPreflight.REASON_FAILED, "other-config")))
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
    fun `a legacy selection without its required settings is not reported as supported`() {
        val result = WebHarnessReadinessProjector.probeEnvironment(mapOf("ACP_HARNESS" to "legacy-openai"))
        assertEquals("HARNESS_CONFIGURATION_INVALID", result.reasonCode)
    }

    @Test
    fun `an abandoned probe is not multiplied and readiness recovers once it ends`() {
        val calls = AtomicInteger()
        val release = CountDownLatch(1)
        var now = 0L
        val projector = WebHarnessReadinessProjector(
            probe = {
                if (calls.incrementAndGet() == 1) {
                    while (release.count > 0) { try { release.await() } catch (_: InterruptedException) { /* ignore */ } }
                }
                WebHarnessReadiness("supported", null, "ok")
            },
            timeoutMillis = 100, ttlNanos = 1_000, nanoTime = { now },
        )
        assertEquals("PROBE_TIMEOUT", projector.current().reasonCode)
        now = 1_000
        assertEquals("PROBE_TIMEOUT", projector.current().reasonCode)
        assertEquals(1, calls.get(), "no second probe may start while the abandoned one still runs")
        release.countDown()
        val deadline = System.nanoTime() + 5_000_000_000L
        var state = ""
        while (state != "supported" && System.nanoTime() < deadline) {
            now += 1_000
            state = projector.current().state
            if (state != "supported") Thread.sleep(20)
        }
        assertEquals("supported", state)
        projector.close()
        now += 1_000
        assertEquals("PROBE_FAILED", projector.current().reasonCode)
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
