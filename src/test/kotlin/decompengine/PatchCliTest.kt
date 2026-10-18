package decompengine

import decompengine.mvp.MvpPatchException
import decompengine.repair.RepairClientAgentHarness
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.PrintStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue

class PatchCliTest {
    @Test
    fun `patch terminal diagnostics redact ordinary failures after cleanup with correct exit status`() {
        val configured = "synthetic-patch-configured-value"
        val bearer = "unregistered-patch-bearer"
        val basic = "c3ludGhldGljOnNlbnRpbmVs"
        val message = "before; $configured; Bearer $bearer; Authorization: Basic $basic; after"
        val cases = listOf(IllegalArgumentException(message) to 2, MvpPatchException(message) to 1, IOException(message) to 1)
        for ((failure, expectedStatus) in cases) {
            val cause = IllegalStateException("PRIVATE_PATCH_CAUSE")
            val suppressed = IllegalStateException("PRIVATE_PATCH_SUPPRESSED")
            failure.initCause(cause)
            failure.addSuppressed(suppressed)
            var closed = false
            val bytes = ByteArrayOutputStream()
            val console = object : PrintStream(bytes, true, Charsets.UTF_8) {
                override fun println(line: String?) {
                    assertTrue(closed, "terminal output preceded action cleanup")
                    super.println(line)
                }
            }
            console.use {
                assertEquals(expectedStatus, runPatchCliAction(listOf(configured), console) {
                    AutoCloseable { closed = true }.use { throw failure }
                })
            }
            val prefix = if (expectedStatus == 2) "configuration error" else "patch failed"
            assertEquals("$prefix: before; [redacted]; Bearer [redacted]; Authorization: [redacted]; after",
                bytes.toString(Charsets.UTF_8).trim())
            val text = bytes.toString(Charsets.UTF_8)
            listOf(configured, bearer, basic, "PRIVATE_PATCH_CAUSE", "PRIVATE_PATCH_SUPPRESSED").forEach {
                assertFalse(text.contains(it))
            }
            assertSame(cause, failure.cause)
            assertSame(suppressed, failure.suppressed.single())
        }
    }

    @Test
    fun `patch terminal boundary preserves success interruption fatal errors and private fallback markers`() {
        val bytes = ByteArrayOutputStream()
        PrintStream(bytes, true, Charsets.UTF_8).use { console ->
            assertEquals(0, runPatchCliAction(emptyList(), console) { })
            assertEquals("", bytes.toString(Charsets.UTF_8))
            val fatal = AssertionError("fatal patch sentinel")
            assertSame(fatal, assertFailsWith<AssertionError> {
                runPatchCliAction(emptyList(), console) { throw fatal }
            })
            assertEquals("", bytes.toString(Charsets.UTF_8))
            val initiallyInterrupted = Thread.interrupted()
            try {
                assertEquals(1, runPatchCliAction(emptyList(), console) {
                    throw InterruptedException("password=synthetic-interrupted-password")
                })
                assertTrue(Thread.currentThread().isInterrupted)
                assertEquals("patch failed: password=[redacted]", bytes.toString(Charsets.UTF_8).trim())
            } finally {
                Thread.interrupted()
                if (initiallyInterrupted) Thread.currentThread().interrupt()
            }
            bytes.reset()
            assertEquals(1, runPatchCliAction(listOf("[oversized text omitted]"), console) {
                throw IOException("x".repeat(16_385))
            })
            assertEquals("patch failed:", bytes.toString(Charsets.UTF_8).trim())
            bytes.reset()
            var actions = 0
            assertEquals(2, runPatchCliAction(List(4097) { "PRIVATE_PATCH_CONFIGURATION" }, console) { actions++ })
            assertEquals(2, runPatchCliAction(listOf("x".repeat(1024 * 1024 + 1)), console) { actions++ })
            assertEquals(0, actions)
            assertEquals("", bytes.toString(Charsets.UTF_8))
        }
    }

    @Test
    fun `legacy API variables do not trigger an implicit direct patch workflow`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            selectPatchStrategy(null, legacyEnvironment())
        }

        assertTrue(failure.message.orEmpty().contains("ACP_CONFIG_FILE is required"))
    }

    @Test
    fun `legacy OpenAI patch workflow requires exact opt-in and reports stable provenance`() {
        val environment = object : AbstractMap<String, String>() {
            override val entries: Set<Map.Entry<String, String>>
                get() = error("patch harness override must not enumerate the ambient environment")

            override fun get(key: String): String? = legacyEnvironment()[key]
        }

        val strategy = selectPatchStrategy("legacy-openai", environment)

        assertIs<RepairClientAgentHarness>(strategy.harness)
        assertEquals(
            "agent-harness-v1:legacy-openai:contract-1:acp-none:sdk-none:" +
                "implementation-legacy-openai-compatible:configuration-none:deprecated",
            strategy.harnessProvenance,
        )
    }

    @Test
    fun `patch workflow passes harness names to the strict factory unchanged`() {
        listOf("direct", "ACP", " acp", "legacy-openai ", "").forEach { selected ->
            assertFailsWith<IllegalArgumentException>(selected) {
                selectPatchStrategy(selected, legacyEnvironment())
            }
        }
    }

    @Test
    fun `explicit ACP patch selection still requires structured provisioning`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            selectPatchStrategy("acp", legacyEnvironment())
        }

        assertTrue(failure.message.orEmpty().contains("ACP_CONFIG_FILE is required"))
    }

    private fun legacyEnvironment(): Map<String, String> = mapOf(
        "BASE_URL" to "https://example.invalid/v1",
        "API_KEY" to "test-key",
        "MODEL" to "test-model",
    )
}
