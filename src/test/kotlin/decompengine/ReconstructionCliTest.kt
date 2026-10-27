package decompengine

import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentWorkflowPhase
import decompengine.jobs.AgentProgressJournal
import decompengine.mvp.MvpPatchException
import decompengine.project.BoundedLlmModuleReconstructor
import decompengine.project.GeneratedCEvidenceCarrier
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.GeneratedCNinjaReconstructionProfile
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertNotEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ReconstructionCliTest {
    @Test
    fun `reconstruction completion masks paths and full framing while preserving computed public SHA`() {
        val bytes = ByteArrayOutputStream()
        val hash = "1".repeat(64)
        val ending = "recovery accuracy: unassessed; see the source tree's confidence and unresolved reports\n"
        PrintStream(bytes, true, Charsets.UTF_8).use { output ->
            renderReconstructionSuccess("/output/public/source-tree", "/output/public/source-tree.zip", hash, emptyList(), output)
            assertEquals("source tree: /output/public/source-tree\narchive: /output/public/source-tree.zip\narchive sha256: $hash\n$ending",
                bytes.toString(Charsets.UTF_8))
            bytes.reset()
            val privatePath = "SYNTHETIC_RECON_PATH_KEY"
            renderReconstructionSuccess("/output/$privatePath/source-tree", "/output/$privatePath/source-tree.zip", hash,
                listOf(privatePath, "1"), output)
            assertEquals("source tree: /output/[REDACTED]/source-tree\narchive: /output/[REDACTED]/source-tree.zip\narchive sha256: $hash\n$ending",
                bytes.toString(Charsets.UTF_8))
            assertFalse(bytes.toString(Charsets.UTF_8).contains(privatePath))
            bytes.reset()
            renderReconstructionSuccess("before\u000Cafter", "/public/result.zip", hash, listOf("beforeafter"), output)
            assertTrue(bytes.toString(Charsets.UTF_8).startsWith("source tree: [REDACTED]\n"))
            bytes.reset()
            for (value in listOf("source tree:", "boundary\narchive:", "unresolved reports\n")) {
                renderReconstructionSuccess("boundary", "/public/result.zip", hash, listOf(value), output)
                assertFalse(bytes.toString(Charsets.UTF_8).contains(value))
                assertTrue(bytes.toString(Charsets.UTF_8).contains("archive sha256: $hash\n"))
                assertTrue(bytes.toString(Charsets.UTF_8).endsWith("\n"))
                bytes.reset()
            }
            renderReconstructionSuccess("project", "archive.zip", hash, listOf("1", "unresolved reports\n"), output)
            assertTrue(bytes.toString(Charsets.UTF_8).contains("archive sha256: $hash\n"))
            assertTrue(bytes.toString(Charsets.UTF_8).endsWith("[REDACTED]\n"))
            bytes.reset()
        }
    }

    @Test
    fun `reconstruction completion admits inventory hash and complete byte budget before any output`() {
        val bytes = ByteArrayOutputStream()
        val hash = "a".repeat(64)
        PrintStream(bytes, true, Charsets.UTF_8).use { output ->
            val tooMany = object : AbstractCollection<String>() {
                override val size: Int = 4097
                override fun iterator(): Iterator<String> = error("rejected inventory must not be iterated")
            }
            for (values in listOf(tooMany, listOf("x".repeat(1024 * 1024 + 1)))) {
                assertFailsWith<IllegalArgumentException> {
                    renderReconstructionSuccess("project", "archive.zip", hash, values, output)
                }
                assertEquals("", bytes.toString(Charsets.UTF_8))
            }
            assertFailsWith<IllegalArgumentException> {
                renderReconstructionSuccess("project", "archive.zip", "INVALID_HASH", emptyList(), output)
            }
            assertEquals("", bytes.toString(Charsets.UTF_8))
            assertFailsWith<MvpPatchException> {
                renderReconstructionSuccess("x".repeat(16_385), "archive.zip", hash, emptyList(), output)
            }
            assertEquals("", bytes.toString(Charsets.UTF_8))
            assertFailsWith<MvpPatchException> {
                renderReconstructionSuccess("project", "archive.zip", hash, listOf("archive sha256: ${hash.take(4)}"), output)
            }
            assertEquals("", bytes.toString(Charsets.UTF_8))
            for (values in listOf(listOf("unresolved reports\n", "[REDACTED]\n"), listOf("\u0000\n"))) {
                assertFailsWith<MvpPatchException> {
                    renderReconstructionSuccess("project", "archive.zip", hash, values, output)
                }
                assertEquals("", bytes.toString(Charsets.UTF_8))
            }
        }
    }

    @Test
    fun `reconstruction redactor rejection returns failure without exposing configuration or running action`() {
        var oversizedIterations = 0
        val noIteration = object : AbstractCollection<String>() {
            override val size: Int get() = 4097
            override fun iterator(): Iterator<String> {
                oversizedIterations++
                error("oversized inventory must be rejected before iteration")
            }
        }
        val brokenInventory = object : AbstractCollection<String>() {
            override val size: Int get() = 1
            override fun iterator(): Iterator<String> = error("PRIVATE_CONFIGURATION_SENTINEL")
        }
        val rejected = listOf(noIteration, brokenInventory, listOf("x".repeat(1024 * 1024 + 1)),
            List(4097) { "[oversized text omitted]" })
        val bytes = ByteArrayOutputStream()
        var actions = 0
        PrintStream(bytes, true, Charsets.UTF_8).use { console ->
            rejected.forEach { inventory ->
                assertEquals(1, runReconstructionCliAction(inventory, console) { actions++ })
                assertEquals("", bytes.toString(Charsets.UTF_8))
            }
            val initiallyInterrupted = Thread.interrupted()
            try {
                val interruptedInventory = object : AbstractCollection<String>() {
                    override val size: Int get() = 1
                    override fun iterator(): Iterator<String> = throw InterruptedException("PRIVATE_CONFIGURATION_SENTINEL")
                }
                assertEquals(1, runReconstructionCliAction(interruptedInventory, console) { actions++ })
                assertTrue(Thread.currentThread().isInterrupted)
                assertEquals("", bytes.toString(Charsets.UTF_8))
            } finally {
                Thread.interrupted()
                if (initiallyInterrupted) Thread.currentThread().interrupt()
            }
        }
        assertEquals(0, actions)
        assertEquals(0, oversizedIterations)
    }

    @Test
    fun `reconstruction failure closes progress before emitting only a redacted terminal diagnostic`() {
        val root = Files.createTempDirectory(
            Files.createDirectories(Path.of("build/test-tmp/reconstruction-cli-diagnostics")), "journal-",
        )
        val configured = "synthetic-cli-configured-value"
        val bearer = "unregistered-cli-bearer-value"
        val apiKey = "unregistered-cli-api-value"
        val cause = IllegalStateException("PRIVATE_CAUSE_SENTINEL")
        val suppressed = IllegalArgumentException("PRIVATE_SUPPRESSED_SENTINEL")
        val failure = AgentExecutionException(
            AgentFailure(AgentFailureKind.PROTOCOL, "before; $configured; Bearer $bearer; api_key=$apiKey; after"),
            cause,
        ).apply { addSuppressed(suppressed) }
        val bytes = ByteArrayOutputStream()
        var terminalObserved = false
        val console = object : PrintStream(bytes, true, Charsets.UTF_8) {
            override fun print(line: String?) {
                if (line?.startsWith("reconstruction failed:") == true) {
                    // Check ownership at emission, before the terminal boundary has returned.
                    AgentProgressJournal(root, "reconstruction").use { }
                    terminalObserved = true
                }
                super.print(line)
            }
        }
        console.use {
            val exitCode = runReconstructionCliAction(listOf(configured), console) {
                withReconstructionCliProgress(root, listOf(configured), console) { progress ->
                    progress.phase(AgentWorkflowPhase.FAILED)
                    throw failure
                }
            }
            assertEquals(1, exitCode)
        }
        assertTrue(terminalObserved)
        val lines = bytes.toString(Charsets.UTF_8).lineSequence().filter { it.isNotEmpty() }.toList()
        assertEquals(listOf("reconstruction: failed",
            "reconstruction failed: before; [redacted]; Bearer [redacted]; api_key=[redacted]; after"), lines)
        val text = bytes.toString(Charsets.UTF_8)
        listOf(configured, bearer, apiKey, "PRIVATE_CAUSE_SENTINEL", "PRIVATE_SUPPRESSED_SENTINEL", "AgentExecutionException")
            .forEach { assertFalse(text.contains(it)) }
        assertSame(cause, failure.cause)
        assertSame(suppressed, failure.suppressed.single())
    }

    @Test
    fun `reconstruction terminal boundary preserves success interruption and fatal errors`() {
        val bytes = ByteArrayOutputStream()
        PrintStream(bytes, true, Charsets.UTF_8).use { console ->
            assertEquals(0, runReconstructionCliAction(emptyList(), console) { })
            assertEquals("", bytes.toString(Charsets.UTF_8))
            val fatal = AssertionError("fatal sentinel")
            assertSame(fatal, assertFailsWith<AssertionError> {
                runReconstructionCliAction(emptyList(), console) { throw fatal }
            })
            assertEquals("", bytes.toString(Charsets.UTF_8))
            val initiallyInterrupted = Thread.interrupted()
            try {
                assertEquals(1, runReconstructionCliAction(emptyList(), console) {
                    throw InterruptedException("Bearer synthetic-interrupted-credential")
                })
                assertTrue(Thread.currentThread().isInterrupted)
                assertEquals("reconstruction failed: Bearer [redacted]", bytes.toString(Charsets.UTF_8).trim())
            } finally {
                Thread.interrupted()
                if (initiallyInterrupted) Thread.currentThread().interrupt()
            }
        }
    }

    @Test
    fun `evidence-only reconstruction is agent-free and does not inspect the environment`() {
        val inaccessibleEnvironment = object : AbstractMap<String, String>() {
            override val entries: Set<Map.Entry<String, String>>
                get() = error("evidence-only reconstruction must not enumerate the environment")

            override fun get(key: String): String? =
                error("evidence-only reconstruction must not read $key")
        }

        for (base in listOf(GeneratedCMakeReconstructionProfile.descriptor, GeneratedCNinjaReconstructionProfile.descriptor)) {
            val strategy = selectReconstructionStrategy(
                evidenceOnly = true,
                maximumContext = 120_000,
                harnessOverride = null,
                environment = inaccessibleEnvironment,
                profile = base,
            )
            assertEquals(base.id, strategy.profile.id)
            assertNotEquals(base.sha256, strategy.profile.sha256)
            assertEquals(GeneratedCEvidenceCarrier.profile(base).sha256, strategy.profile.sha256)
            assertEquals(listOf(GeneratedCEvidenceCarrier.PURPOSE),
                strategy.profile.adapterConfiguration[GeneratedCEvidenceCarrier.PURPOSE_KEY])
            assertSame(GeneratedCEvidenceCarrier.reconstructor, strategy.reconstructor)
            assertNull(strategy.harnessProvenance)
        }
    }

    @Test
    fun `evidence-only reconstruction rejects an explicit harness`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            selectReconstructionStrategy(
                evidenceOnly = true,
                maximumContext = 120_000,
                harnessOverride = "acp",
                environment = emptyMap(),
            )
        }

        assertEquals("--harness cannot be used with --evidence-only", failure.message)
    }

    @Test
    fun `legacy API variables do not trigger an implicit direct reconstruction`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            selectReconstructionStrategy(
                evidenceOnly = false,
                maximumContext = 120_000,
                harnessOverride = null,
                environment = legacyEnvironment(),
            )
        }

        assertTrue(failure.message.orEmpty().contains("ACP_CONFIG_FILE is required"))
    }

    @Test
    fun `legacy OpenAI reconstruction requires exact opt-in and reports stable provenance`() {
        val environment = object : AbstractMap<String, String>() {
            override val entries: Set<Map.Entry<String, String>>
                get() = error("CLI harness override must not enumerate the ambient environment")

            override fun get(key: String): String? = legacyEnvironment()[key]
        }
        val strategy = selectReconstructionStrategy(
            evidenceOnly = false,
            maximumContext = 4_096,
            harnessOverride = "legacy-openai",
            environment = environment,
        )

        assertIs<BoundedLlmModuleReconstructor>(strategy.reconstructor)
        assertTrue(!strategy.reconstructor.cacheIdentity().contains("factory-unbound"))
        assertEquals(
            "agent-harness-v1:legacy-openai:contract-1:acp-none:sdk-none:" +
                "implementation-legacy-openai-compatible:configuration-dd717430f0b3a8c1cb7dffc593dca057df544cb2ca0c6bf10107c4f7f7751fef:deprecated",
            strategy.harnessProvenance,
        )
    }

    @Test
    fun `reconstruction passes harness names to the strict factory unchanged`() {
        listOf("direct", "ACP", " acp", "legacy-openai ", "").forEach { selected ->
            assertFailsWith<IllegalArgumentException>(selected) {
                selectReconstructionStrategy(
                    evidenceOnly = false,
                    maximumContext = 120_000,
                    harnessOverride = selected,
                    environment = legacyEnvironment(),
                )
            }
        }
    }

    private fun legacyEnvironment(): Map<String, String> = mapOf(
        "BASE_URL" to "https://example.invalid/v1",
        "API_KEY" to "test-key",
        "MODEL" to "test-model",
    )
}
