package decompengine.project

import decompengine.agent.AgentHarness
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith

class ModulePromptCompatibilityTest {
    @Test
    fun `generated C prompt commitments remain stable for Make and Ninja`() {
        val model = RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
            RecoveredFunction("fn_alpha", "alpha_run", 0x1000UL, "int alpha_run(void)",
                "int alpha_run(void) { return 7; }"),
        ))
        for (profile in ReconstructionProfiles.builtIn) {
            val module = DeterministicModulePlanner(layout = profile.layout).plan(model).modules.single()
            var invoked = false
            val reconstructor = BoundedLlmModuleReconstructor(AgentHarness { _, _ -> invoked = true; error("must not execute") }, 4096)
            val failure = assertFailsWith<ModuleContextBudgetExceededException> {
                reconstructor.reconstruct(ModuleReconstructionRequest(module, model, "x".repeat(4096),
                    "int alpha_run(void);", "/* private interface */", mapOf("include/modules/dep.h" to "int dep(void);"),
                    Path.of("unused-workspace"), observedBehavior = "authored observation", profile = profile))
            }
            // Recorded from the production prompt path before extraction into the adapter.
            assertEquals(5515, failure.promptCharacters)
            assertEquals("b85179ae06e54680ce7c5d5113e8d39169bfc2a2bab34bc24acdb9276180a064", failure.promptSha256)
            assertFalse(invoked)
        }
    }
}
