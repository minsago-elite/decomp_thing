package decompengine.project

import decompengine.agent.AgentHarness
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class HistoricalModulePromptReplayTest {
    @Test
    fun `historical v3 prompt rendering preserves exact Make and Ninja commitments`() {
        for (profile in ReconstructionProfiles.builtIn) {
            val model = model()
            val module = DeterministicModulePlanner(layout = profile.layout).plan(model).modules.single()
            val request = ModuleReconstructionRequest(
                module, model, "x".repeat(4096), "int alpha_run(void);", "/* private interface */",
                mapOf("include/modules/dep.h" to "int dep(void);"), Path.of("unused-workspace"),
                observedBehavior = "authored observation", profile = profile,
            )
            val historical = modulePromptEvidence(request, legacy = true).text
            assertEquals(5515, historical.length)
            assertEquals("b85179ae06e54680ce7c5d5113e8d39169bfc2a2bab34bc24acdb9276180a064",
                sha256(historical.toByteArray()))
            assertNotEquals(historical, modulePromptEvidence(request).text)
        }
    }

    @Test
    fun `input fingerprint provider claims follow the full versioned identity`() {
        val prefix = "agent:authored:context-4096:factory-${"a".repeat(64)}"
        assertEquals("module-reconstruction-input-v2", archivedModuleInputFingerprintProvider("$prefix:v3"))
        assertEquals("module-reconstruction-input-v3", archivedModuleInputFingerprintProvider("$prefix:v4"))
        for (identity in listOf("evidence-v4", "agent:authored:v4", "$prefix:v4:extra", "$prefix:v5")) {
            assertEquals("module-reconstruction-input-v2", archivedModuleInputFingerprintProvider(identity))
        }
    }

    @Test
    fun `historical fallback archive replays v3 inputs and rejects a v4 relabel`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val temp = Files.createTempDirectory(scratch, "historical-module-prompt-")
        try {
            for (base in ReconstructionProfiles.builtIn) {
                val profile = ReconstructionProfile(base.schemaVersion, base.id, base.layout,
                    base.budgets.copy(reconstructionMaximumContextCharacters = 1), base.adapterConfiguration)
                val project = temp.resolve(profile.id)
                val model = model()
                val plan = DeterministicModulePlanner(layout = profile.layout).plan(model)
                val module = plan.modules.single()
                val observation = "historical authored observation"
                SourceTreeGenerator.generate(model, project, profile = profile,
                    reconstructor = BoundedLlmModuleReconstructor(AgentHarness { _, _ -> error("must not dispatch") }),
                    observedBehavior = observation)
                val inputs = ProfileModulePromptInputs(model, plan, profile)
                val request = inputs.request(module.id, project, observation)
                val prompt = modulePromptEvidence(request, legacy = true).text
                val promptHash = sha256(prompt.toByteArray())
                val fingerprint = inputs.fingerprint(request, legacy = true)
                assertNotEquals(fingerprint, inputs.fingerprint(request))
                val checkpointPath = profile.layout.declaration("module-evidence")
                    .materialize(mapOf("module" to module.id))
                val confidencePath = profile.layout.declaration("confidence-evidence").materialize()
                val checkpoint = readObject(project.resolve(checkpointPath))
                val legacyIdentity = checkpoint.getValue("reconstructorIdentity").jsonPrimitive.content
                    .replace(Regex(":v[34]$"), ":v3")

                fun retainVersion(identity: String, provider: String) {
                    val revisedCheckpoint = JsonObject(LinkedHashMap(checkpoint).apply {
                        put("generator", JsonPrimitive("unresolved:$identity"))
                        put("reconstructorIdentity", JsonPrimitive(identity))
                        put("fingerprint", JsonPrimitive(fingerprint))
                        put("promptSha256", JsonPrimitive(promptHash))
                        put("promptCharacters", JsonPrimitive(prompt.length))
                        put("preDispatchObservedBehavior", JsonPrimitive(observation))
                        put("issues", JsonArray(checkpoint.getValue("issues").jsonArray.map { item ->
                            JsonObject(LinkedHashMap(item.jsonObject).apply {
                                if (getValue("code").jsonPrimitive.content == "context-budget-exceeded") {
                                    put("message", JsonPrimitive("module context required ${prompt.length} characters; limit=1"))
                                }
                            })
                        }))
                    })
                    project.resolve(checkpointPath).writeText(revisedCheckpoint.toString() + "\n")
                    val confidence = readObject(project.resolve(confidencePath))
                    val revisedConfidence = JsonObject(LinkedHashMap(confidence).apply {
                        put("modules", JsonArray(confidence.getValue("modules").jsonArray.map { item ->
                            JsonObject(LinkedHashMap(item.jsonObject).apply {
                                val revision = getValue("revisionEvidence").jsonObject
                                put("revisionEvidence", JsonObject(LinkedHashMap(revision).apply {
                                    put("inputFingerprint", JsonPrimitive(fingerprint))
                                    put("inputFingerprintProvider", JsonPrimitive(provider))
                                    put("checkpointSha256", JsonPrimitive(sha256(project.resolve(checkpointPath).readBytes())))
                                }))
                            })
                        }))
                    })
                    project.resolve(confidencePath).writeText(revisedConfidence.toString() + "\n")
                    val manifest = readObject(project.resolve("source_tree_manifest.json"))
                    val revisedManifest = JsonObject(LinkedHashMap(manifest).apply {
                        put("files", JsonArray(manifest.getValue("files").jsonArray.map { item ->
                            JsonObject(LinkedHashMap(item.jsonObject).apply {
                                val path = getValue("path").jsonPrimitive.content
                                when (path) {
                                    checkpointPath, confidencePath -> put("sha256", JsonPrimitive(sha256(project.resolve(path).readBytes())))
                                    module.sourcePath -> {
                                        put("generator", JsonPrimitive("unresolved:$identity"))
                                        put("promptSha256", JsonPrimitive(promptHash))
                                    }
                                }
                            })
                        }))
                    })
                    project.resolve("source_tree_manifest.json").writeText(revisedManifest.toString() + "\n")
                }

                fun verify() = SourceTreeManifestReader.read(project, profile).let { manifest ->
                    ReconstructionAcpEvidenceArchiveVerifier.verify(project,
                        manifest.files.associate { it.path to sha256(project.resolve(it.path).readBytes()) },
                        manifest.files.associate { it.path to Files.size(project.resolve(it.path)) }, manifest, profile)
                }

                retainVersion(legacyIdentity, "module-reconstruction-input-v2")
                assertTrue(verify().isEmpty())
                assertTrue(ArchivalProjectAuditor.audit(project, profile, publish = false)
                    .moduleConfidenceEvidenceProblems.isEmpty())
                retainVersion(legacyIdentity, "module-reconstruction-input-v3")
                val providerFailure = assertFailsWith<IllegalArgumentException> {
                    ArchivalProjectAuditor.audit(project, profile, publish = false)
                }
                assertTrue(providerFailure.message.orEmpty().contains("historical reconstruction checkpoint"))
                retainVersion(legacyIdentity.removeSuffix(":v3") + ":v4", "module-reconstruction-input-v3")
                val failure = assertFailsWith<IllegalArgumentException> { verify() }
                assertTrue(failure.message.orEmpty().contains("independently rendered inputs"), failure.message)
            }
        } finally {
            Files.walk(temp).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    private fun readObject(path: Path) = Json.parseToJsonElement(path.readText()).jsonObject

    private fun model() = RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
        RecoveredFunction("fn_alpha", "alpha_run", 0x1000UL, "int alpha_run(void)",
            "int alpha_run(void) { return 7; }"),
    ))
}
