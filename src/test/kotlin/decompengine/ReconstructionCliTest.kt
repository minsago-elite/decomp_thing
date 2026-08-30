package decompengine

import decompengine.project.BoundedLlmModuleReconstructor
import decompengine.project.EvidenceModuleReconstructor
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ReconstructionCliTest {
    @Test
    fun `evidence-only reconstruction is agent-free and does not inspect the environment`() {
        val inaccessibleEnvironment = object : AbstractMap<String, String>() {
            override val entries: Set<Map.Entry<String, String>>
                get() = error("evidence-only reconstruction must not enumerate the environment")

            override fun get(key: String): String? =
                error("evidence-only reconstruction must not read $key")
        }

        val strategy = selectReconstructionStrategy(
            evidenceOnly = true,
            maximumContext = 120_000,
            harnessOverride = null,
            environment = inaccessibleEnvironment,
        )

        assertIs<EvidenceModuleReconstructor>(strategy.reconstructor)
        assertNull(strategy.harnessProvenance)
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
        assertEquals(
            "agent-harness-v1:legacy-openai:contract-1:acp-none:sdk-none:" +
                "implementation-legacy-openai-compatible:configuration-none:deprecated",
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
