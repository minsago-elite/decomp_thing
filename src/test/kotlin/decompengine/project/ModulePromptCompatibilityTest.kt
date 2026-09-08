package decompengine.project

import decompengine.agent.AgentHarness
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentStopReason
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class ModulePromptCompatibilityTest {
    @Test
    fun `generated C prompt commitments remain stable for Make and Ninja`() {
        for (base in ReconstructionProfiles.builtIn) {
            for ((configuredBudget, profileBudget) in listOf(4096 to 120000, 120000 to 4096, 4096 to 4096)) {
                val profile = withBudget(base, profileBudget)
                var invoked = false
                val reconstructor = BoundedLlmModuleReconstructor(
                    AgentHarness { _, _ -> invoked = true; error("must not execute") }, configuredBudget,
                )
                val failure = assertFailsWith<ModuleContextBudgetExceededException> {
                    reconstructor.reconstruct(request(profile, Path.of("unused-workspace")))
                }
                // Recorded from the production prompt path before extraction into the adapter.
                assertEquals(5515, failure.promptCharacters)
                assertEquals("b85179ae06e54680ce7c5d5113e8d39169bfc2a2bab34bc24acdb9276180a064", failure.promptSha256)
                assertEquals(4096, failure.promptBudgetCharacters)
                assertTrue(":context-4096:" in reconstructor.cacheIdentity(profile))
                assertEquals(profileBudget, profile.budgets.reconstructionMaximumContextCharacters)
                assertFalse(invoked)
            }
        }
    }

    @Test
    fun `candidate assessment applies profile budgets to every agent identity form`() {
        for ((generator, identity) in listOf(
            "agent:authored" to "custom", "authored" to "agent:authored", "unresolved:agent:authored" to "custom",
        )) {
            val profile = withBudget(GeneratedCMakeReconstructionProfile.descriptor, 4096)
            val project = createTempDirectory("candidate-profile-budget-")
            val reconstructor = object : ModuleReconstructor {
                override fun cacheIdentity(): String = identity
                override fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule =
                    EvidenceModuleReconstructor(true).reconstruct(request).copy(
                        generator = generator, promptCharacters = 10, promptBudgetCharacters = 4097,
                    )
            }
            val manifest = SourceTreeGenerator.generate(model(), project, profile = profile, reconstructor = reconstructor)
            assertEquals(listOf("fn_alpha"), manifest.unresolvedImplementationIds)
            val module = DeterministicModulePlanner(layout = profile.layout).plan(model()).modules.single()
            val checkpoint = Json.parseToJsonElement(project.resolve(
                profile.layout.declaration("module-evidence").materialize(mapOf("module" to module.id)),
            ).readText()).jsonObject
            assertEquals(JsonPrimitive(false), checkpoint.getValue("accepted"))
            assertEquals(kotlinx.serialization.json.JsonNull, checkpoint.getValue("compilation"))
            assertTrue(checkpoint.getValue("issues").jsonArray.any {
                it.jsonObject.getValue("code").jsonPrimitive.content == "prompt-budget-invalid"
            })
        }
    }

    @Test
    fun `exact profile prompt limit is dispatched and recorded on cancellation`() {
        for (base in ReconstructionProfiles.builtIn) {
            val profile = withBudget(base, 5515)
            var calls = 0
            val reconstructor = BoundedLlmModuleReconstructor(AgentHarness { _, _ ->
                calls++
                AgentExecutionResult(AgentStopReason.CANCELLED)
            })
            val failure = assertFailsWith<ModuleReconstructionInterruptedException> {
                reconstructor.reconstruct(request(profile, createTempDirectory("exact-prompt-budget-")))
            }
            assertEquals(1, calls)
            assertEquals(5515, failure.promptCharacters)
            assertEquals(5515, failure.promptBudgetCharacters)
            assertTrue(":context-5515:" in reconstructor.cacheIdentity(profile))
            assertEquals(reconstructor.cacheIdentity(), reconstructor.cacheIdentity(base))
        }
    }

    @Test
    fun `workflow records profile budget and identity for undispatched modules`() {
        for (base in ReconstructionProfiles.builtIn) {
            val profile = withBudget(base, 1)
            val project = createTempDirectory("profile-module-budget-")
            val reconstructor = BoundedLlmModuleReconstructor(AgentHarness { _, _ -> error("must not execute") })
            val manifest = SourceTreeGenerator.generate(model(), project, profile = profile, reconstructor = reconstructor)
            assertEquals(listOf("fn_alpha"), manifest.unresolvedImplementationIds)
            val module = DeterministicModulePlanner(layout = profile.layout).plan(model()).modules.single()
            val checkpoint = Json.parseToJsonElement(project.resolve(
                profile.layout.declaration("module-evidence").materialize(mapOf("module" to module.id)),
            ).readText()).jsonObject
            assertEquals(JsonPrimitive(1), checkpoint.getValue("promptBudgetCharacters"))
            assertEquals(JsonPrimitive(reconstructor.cacheIdentity(profile)), checkpoint.getValue("reconstructorIdentity"))
            assertEquals(JsonPrimitive(false), checkpoint.getValue("accepted"))
            assertTrue(checkpoint.getValue("issues").jsonArray.any {
                it.jsonObject.getValue("code").jsonPrimitive.content == "context-budget-exceeded"
            })
            val generationEvidence = Json.parseToJsonElement(
                project.resolve("reports/confidence.json").readText(),
            ).jsonObject.getValue("sourceGenerationBudgetEvidence").jsonObject
            val moduleEvidence = generationEvidence.getValue("modules").jsonArray.single().jsonObject
            assertTrue(moduleEvidence.getValue("promptCharacters").jsonPrimitive.content.toInt() > 1)
            assertEquals("1", moduleEvidence.getValue("promptBudgetCharacters").jsonPrimitive.content)
            assertEquals("unresolved", moduleEvidence.getValue("outcome").jsonPrimitive.content)
        }
    }

    private fun model() = RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
        RecoveredFunction("fn_alpha", "alpha_run", 0x1000UL, "int alpha_run(void)",
            "int alpha_run(void) { return 7; }"),
    ))

    private fun request(profile: ReconstructionProfile, workspace: Path): ModuleReconstructionRequest {
        val model = model()
        val module = DeterministicModulePlanner(layout = profile.layout).plan(model).modules.single()
        return ModuleReconstructionRequest(module, model, "x".repeat(4096),
            "int alpha_run(void);", "/* private interface */", mapOf("include/modules/dep.h" to "int dep(void);"),
            workspace, observedBehavior = "authored observation", profile = profile)
    }

    private fun withBudget(base: ReconstructionProfile, budget: Int) = ReconstructionProfile(
        schemaVersion = base.schemaVersion,
        id = base.id,
        layout = base.layout,
        budgets = base.budgets.copy(reconstructionMaximumContextCharacters = budget),
        adapterConfiguration = base.adapterConfiguration,
    )
}
