package decompengine

import decompengine.repair.RepairClientAgentHarness
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class PatchCliTest {
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
