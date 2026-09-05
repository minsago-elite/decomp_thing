package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
import decompengine.project.BoundedLlmModuleReconstructor
import decompengine.project.EvidenceModuleReconstructor
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SourceTreeJobReconstructorTest {
    @Test
    fun `web reconstruction defaults to ACP and never infers legacy use from credentials`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            selectWebReconstructionStrategy(
                mapOf(
                    "BASE_URL" to "https://example.invalid/v1",
                    "API_KEY" to "old-implicit-key",
                    "MODEL" to "old-implicit-model",
                ),
            )
        }

        assertTrue(failure.message.orEmpty().contains("ACP_CONFIG_FILE is required"))
    }

    @Test
    fun `legacy OpenAI web reconstruction requires explicit harness opt-in and records deprecation`() {
        val strategy = selectWebReconstructionStrategy(legacyEnvironment())

        assertEquals(WebReconstructionMode.AGENT, strategy.mode)
        assertIs<BoundedLlmModuleReconstructor>(strategy.reconstructor)
        assertTrue(!strategy.reconstructor.cacheIdentity().contains("factory-unbound"))
        val provenance = requireNotNull(strategy.harnessProvenance)
        assertEquals("legacy-openai", provenance.harness)
        assertTrue(provenance.deprecated)
        assertEquals(
            "agent-harness-v1:legacy-openai:contract-1:acp-none:sdk-none:" +
                "implementation-legacy-openai-compatible:configuration-none:deprecated",
            provenance.stableDescriptor,
        )

        val report = Json.parseToJsonElement(renderWebReconstructionHarnessSelection(strategy)).jsonObject
        assertEquals(1, report.getValue("schemaVersion").jsonPrimitive.int)
        assertEquals("agent", report.getValue("mode").jsonPrimitive.content)
        val selection = report.getValue("selection").jsonObject
        assertEquals(provenance.stableDescriptor, selection.getValue("stableDescriptor").jsonPrimitive.content)
        assertEquals("legacy-openai", selection.getValue("harness").jsonPrimitive.content)
        assertTrue(selection.getValue("deprecated").jsonPrimitive.boolean)
        assertTrue("legacy-key" !in report.toString())
    }

    @Test
    fun `web evidence-only reconstruction is explicit and does not resolve a harness`() {
        val environment = object : AbstractMap<String, String>() {
            override val entries: Set<Map.Entry<String, String>>
                get() = error("evidence-only web reconstruction must not enumerate the environment")

            override fun get(key: String): String? =
                if (key == "WEB_RECONSTRUCTION_MODE") "evidence-only" else {
                    error("evidence-only web reconstruction must not read $key")
                }
        }

        val strategy = selectWebReconstructionStrategy(environment)

        assertEquals(WebReconstructionMode.EVIDENCE_ONLY, strategy.mode)
        assertIs<EvidenceModuleReconstructor>(strategy.reconstructor)
        assertNull(strategy.harnessProvenance)
        val report = Json.parseToJsonElement(renderWebReconstructionHarnessSelection(strategy)).jsonObject
        assertEquals("evidence-only", report.getValue("mode").jsonPrimitive.content)
        assertEquals(JsonNull, report.getValue("selection"))
    }

    @Test
    fun `unknown web reconstruction modes fail closed`() {
        listOf("", "ACP", " agent", "legacy-openai", "evidence-only ").forEach { configured ->
            val failure = assertFailsWith<IllegalArgumentException>(configured) {
                selectWebReconstructionStrategy(mapOf("WEB_RECONSTRUCTION_MODE" to configured))
            }
            assertTrue(failure.message.orEmpty().contains("must be exactly agent or evidence-only"))
        }
    }

    @Test
    fun `web job persists stable harness selection before bundled analysis`() {
        val root = createTempDirectory("web-reconstruction-selection-")
        val store = JobStore(root)
        val job = store.createFromUpload("fixture.elf", elfFixture())
        val reports = store.reportsDirectory(job.id)

        val failure = assertFailsWith<IllegalStateException> {
            SourceTreeJobReconstructor(legacyEnvironment(), decompengine.project.ProgramModelAnalyzer { _, _ ->
                error("expected analysis failure")
            }).reconstruct(job, reports)
        }

        assertEquals("expected analysis failure", failure.message)
        val artifact = reports.resolve("reconstruction_harness_selection.json")
        assertTrue(artifact.exists())
        val report = Json.parseToJsonElement(artifact.readText()).jsonObject
        assertEquals("agent", report.getValue("mode").jsonPrimitive.content)
        assertEquals(
            "legacy-openai",
            report.getValue("selection").jsonObject.getValue("harness").jsonPrimitive.content,
        )
    }

    private fun legacyEnvironment(): Map<String, String> = mapOf(
        "ACP_HARNESS" to "legacy-openai",
        "BASE_URL" to "https://example.invalid/v1",
        "API_KEY" to "legacy-key",
        "MODEL" to "legacy-model",
    )
}
