package decompengine

import decompengine.mvp.MvpPatchException
import decompengine.jobs.ProgressRedactor
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
    fun `workflow provenance masks complete prefixes and evidence only framing`() {
        val bytes = ByteArrayOutputStream()
        PrintStream(bytes, true, Charsets.UTF_8).use { output ->
            for ((command, prefix) in listOf(WorkflowCliCommand.PATCH to "harness provenance",
                WorkflowCliCommand.RECONSTRUCT to "harness provenance", WorkflowCliCommand.REPAIR to "repair harness")) {
                renderWorkflowProvenance(command, "public-descriptor", ProgressRedactor(emptyList()), output)
                assertEquals("$prefix: public-descriptor\n", bytes.toString(Charsets.UTF_8))
                bytes.reset()
                for (value in listOf("$prefix: private-descriptor", "$prefix: private-descriptor\n", prefix)) {
                    renderWorkflowProvenance(command, "private-descriptor", ProgressRedactor(listOf(value)), output)
                    assertFalse(bytes.toString(Charsets.UTF_8).contains(value))
                    assertTrue(bytes.toString(Charsets.UTF_8).contains("[redacted]"))
                    bytes.reset()
                }
                val longDescriptor = "x".repeat(600)
                renderWorkflowProvenance(command, longDescriptor, ProgressRedactor(listOf("$prefix: $longDescriptor")), output)
                assertEquals("[redacted]\n", bytes.toString(Charsets.UTF_8))
                bytes.reset()
            }
            renderWorkflowProvenance(WorkflowCliCommand.RECONSTRUCT, null, ProgressRedactor(emptyList()), output)
            assertEquals("harness: none (evidence-only)\n", bytes.toString(Charsets.UTF_8))
            bytes.reset()
            renderWorkflowProvenance(WorkflowCliCommand.RECONSTRUCT, null,
                ProgressRedactor(listOf("harness: none (evidence-only)")), output)
            assertEquals("[redacted]\n", bytes.toString(Charsets.UTF_8))
            bytes.reset()
            for (command in listOf(WorkflowCliCommand.PATCH, WorkflowCliCommand.REPAIR)) {
                assertFailsWith<IllegalArgumentException> {
                    renderWorkflowProvenance(command, null, ProgressRedactor(emptyList()), output)
                }
                assertEquals("", bytes.toString(Charsets.UTF_8))
            }
        }
    }

    @Test
    fun `long workflow failure previews retain a safe terminal newline`() {
        val bytes = ByteArrayOutputStream()
        PrintStream(bytes, true, Charsets.UTF_8).use { output ->
            for (command in WorkflowCliCommand.entries) {
                val message = "visible ".repeat(100)
                renderWorkflowFailure(command, message, ProgressRedactor(emptyList()), output)
                val text = bytes.toString(Charsets.UTF_8)
                assertTrue(text.startsWith("${command.failurePrefix}: visible "))
                assertTrue(text.endsWith("… [preview truncated]\n"), text)
                assertEquals(1, text.count { it == '\n' })
                assertTrue(text.length < 600)
                bytes.reset()
                val markerAndNewline = "… [preview truncated]\n"
                renderWorkflowFailure(command, message, ProgressRedactor(listOf(markerAndNewline)), output)
                assertFalse(bytes.toString(Charsets.UTF_8).contains(markerAndNewline))
                bytes.reset()
                renderWorkflowFailure(command, "short", ProgressRedactor(emptyList()), output)
                assertEquals("${command.failurePrefix}: short\n", bytes.toString(Charsets.UTF_8))
                bytes.reset()
            }
        }
    }

    @Test
    fun `workflow terminal framing is masked together with raw failure detail`() {
        val bytes = ByteArrayOutputStream()
        PrintStream(bytes, true, Charsets.UTF_8).use { output ->
            val cases = listOf(
                WorkflowCliCommand.PATCH to "patch failed",
                WorkflowCliCommand.RECONSTRUCT to "reconstruction failed",
                WorkflowCliCommand.REPAIR to "repair unavailable or failed",
            )
            for ((command, prefix) in cases) {
                for (value in listOf("$prefix: visible", "$prefix: visible\n", prefix)) {
                    val values = listOf(value)
                    when (command) {
                        WorkflowCliCommand.PATCH -> assertEquals(1, runPatchCliAction(values, output) {
                            throw IOException("visible")
                        })
                        WorkflowCliCommand.RECONSTRUCT -> assertEquals(1, runReconstructionCliAction(values, output) {
                            throw IOException("visible")
                        })
                        WorkflowCliCommand.REPAIR -> renderWorkflowFailure(command, "visible", ProgressRedactor(values), output)
                    }
                    assertFalse(bytes.toString(Charsets.UTF_8).contains(value), "framing exposed $value")
                    assertTrue(bytes.toString(Charsets.UTF_8).contains("[redacted]"))
                    bytes.reset()
                }
            }
            assertEquals(2, runPatchCliAction(listOf("configuration error: visible"), output) {
                throw IllegalArgumentException("visible")
            })
            assertEquals("[redacted]\n", bytes.toString(Charsets.UTF_8))
            bytes.reset()
            val oversizedDetail = "z".repeat(16_370)
            assertEquals(1, runReconstructionCliAction(listOf("reconstruction failed: $oversizedDetail"), output) {
                throw IOException(oversizedDetail)
            })
            assertFalse(bytes.toString(Charsets.UTF_8).contains("zzz"))
            bytes.reset()
            val longSecret = "reconstruction failed: " + "x".repeat(600)
            assertEquals(1, runReconstructionCliAction(listOf(longSecret), output) {
                throw IOException("x".repeat(600))
            })
            assertEquals("[redacted]\n", bytes.toString(Charsets.UTF_8))
        }
    }

    @Test
    fun `every workflow usage masks complete constants boundaries and rejected inventories`() {
        val bytes = ByteArrayOutputStream()
        PrintStream(bytes, true, Charsets.UTF_8).use { output ->
            for ((command, name) in listOf(WorkflowCliCommand.PATCH to "patch",
                WorkflowCliCommand.RECONSTRUCT to "reconstruct", WorkflowCliCommand.REPAIR to "repair")) {
                val prefix = "usage: llm_bin_patch $name"
                assertEquals(2, renderWorkflowUsageError(command, "unexpected argument: private", listOf("private"), output))
                assertTrue(bytes.toString(Charsets.UTF_8).startsWith("unexpected argument: [redacted]\n$prefix "))
                assertFalse(bytes.toString(Charsets.UTF_8).contains("private"))
                bytes.reset()
                for (secret in listOf(prefix, "boundary\nusage:", "legacy-openai]\n")) {
                    assertEquals(2, renderWorkflowUsageError(command, "boundary", listOf(secret), output))
                    assertFalse(bytes.toString(Charsets.UTF_8).contains(secret))
                    bytes.reset()
                }
                val tooMany = object : AbstractCollection<String>() {
                    override val size: Int = 4097
                    override fun iterator(): Iterator<String> = error("rejected inventory must not be iterated")
                }
                for (values in listOf(tooMany, listOf("x".repeat(1024 * 1024 + 1)))) {
                    assertEquals(2, renderWorkflowUsageError(command, "PRIVATE_ARGUMENT", values, output))
                    assertEquals("", bytes.toString(Charsets.UTF_8))
                }
                assertEquals(2, renderWorkflowUsageError(command, "x".repeat(16_385), emptyList(), output))
                assertEquals("", bytes.toString(Charsets.UTF_8))
            }
        }
    }

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
                override fun print(line: String?) {
                    assertTrue(closed, "terminal output preceded action cleanup")
                    super.print(line)
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
