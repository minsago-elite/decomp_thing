package decompengine.project

import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentHarness
import decompengine.agent.AgentOperation
import decompengine.agent.AgentStopReason
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class ModuleMinimalContextTest {
    @Test
    fun `incoming caller discriminates otherwise identical module context and input identity`() {
        for (profile in ReconstructionProfiles.builtIn) {
            val first = request(profile)
            val second = first.copy(model = first.model.copy(functions = first.model.functions.map {
                if (it.id == "caller") it.copy(name = "different_caller", prototype = "int different_caller(void)") else it
            }))
            val a = modulePromptEvidence(first)
            val b = modulePromptEvidence(second)
            assertNotEquals(a.text, b.text)
            assertNotEquals(sha256(a.text.toByteArray()), sha256(b.text.toByteArray()))
            assertNotEquals(selectedModuleInputFingerprint(first), selectedModuleInputFingerprint(second))
            assertTrue(a.evidence.contains("incoming callers into this module:\ncaller"))
            assertTrue(a.evidence.contains("outgoing callees from this module:\ncallee"))
            assertFalse(a.evidence.contains("SECRET_CALLER_BODY"))
        }
    }

    @Test
    fun `selected interfaces include dependencies but omit unrelated sibling declarations and bodies`() {
        val request = request()
        val evidence = modulePromptEvidence(request)
        assertTrue(evidence.evidence.contains("typedef struct needed needed_t;"))
        assertTrue(evidence.evidence.contains("struct needed { int value; };"))
        assertTrue(evidence.evidence.contains("int dependency(needed_t *value)"))
        assertTrue(evidence.evidence.contains("external_counter"))
        listOf("UNRELATED_TYPE", "unrelated_sibling", "unrelated_global", "SECRET_CALLEE_BODY", "FULL_HEADER_SECRET")
            .forEach { assertFalse(evidence.text.contains(it), it) }
        val unrelatedChanged = request.copy(
            sharedHeader = "different unrelated broad header",
            dependencyHeaders = request.dependencyHeaders.mapValues { "other broad sibling declarations" },
            model = request.model.copy(functions = request.model.functions.map {
                if (it.id == "unrelated") it.copy(decompiledC = "changed unrelated body") else it
            }, globals = request.model.globals.map { if (it.id == "counter") it.copy(initializer = "UNRELATED_MODE") else it },
                types = request.model.types.map {
                if (it.id == "unrelated_type") it.copy(declaration = "struct ANOTHER_UNRELATED { long x; };") else it
            }),
        )
        assertEquals(evidence.text, modulePromptEvidence(unrelatedChanged).text)
        assertEquals(selectedModuleInputFingerprint(request), selectedModuleInputFingerprint(unrelatedChanged))
    }

    @Test
    fun `every dispatched context character is bounded and no workspace read can expand context`() {
        for (base in ReconstructionProfiles.builtIn) {
            val initial = request(base).let { request -> request.copy(model = request.model.copy(
                functions = request.model.functions.map { if (it.id == "local") it.copy(
                    decompiledC = it.decompiledC + "\n/*" + "owned evidence ".repeat(400) + "*/") else it },
            )) }
            val size = modulePromptEvidence(initial).text.length
            var captured: AgentExecutionRequest? = null
            val harness = AgentHarness { agentRequest, _ ->
                captured = agentRequest
                AgentExecutionResult(AgentStopReason.NO_CHANGES)
            }
            val bounded = BoundedLlmModuleReconstructor(harness, maximumContextCharacters = size)
            assertFailsWith<IllegalArgumentException> { bounded.reconstruct(initial) }
            val dispatched = requireNotNull(captured)
            val actual = decompengine.agent.renderAgentPrompt(dispatched.objective, dispatched.contextInputs)
            assertTrue(actual.contains("Context inputs (immutable):\n--- recovered-module-evidence [text/plain]\n"))
            assertEquals(modulePromptEvidence(initial).text, actual)
            assertEquals(size, actual.length)
            assertEquals(setOf(AgentOperation.WRITE_FILE, AgentOperation.CREATE_FILE), dispatched.accessPolicy.allowedOperations)
            assertEquals(listOf("src/modules/local.c"), dispatched.accessPolicy.pathRules.map { it.path.relativePath })
            assertTrue(dispatched.contextInputs[0].content.contains("--- include/modules/dependency.h ---"))
            captured = null
            val failure = assertFailsWith<ModuleContextBudgetExceededException> {
                BoundedLlmModuleReconstructor(harness, maximumContextCharacters = size - 1).reconstruct(initial)
            }
            assertEquals(size, failure.promptCharacters)
            assertEquals(size - 1, failure.promptBudgetCharacters)
            assertEquals(null, captured)
        }
    }

    @Test
    fun `incoming caller context alone can exceed the budget before dispatch`() {
        val original = request()
        val baselineCharacters = modulePromptEvidence(original).text.length
        val enlarged = original.copy(model = original.model.copy(functions = original.model.functions.map {
            if (it.id == "caller") it.copy(prototype = it.prototype + " /*" + "caller evidence ".repeat(1000) + "*/") else it
        }))
        var dispatched = false
        val reconstructor = BoundedLlmModuleReconstructor(AgentHarness { _, _ ->
            dispatched = true
            error("over-budget incoming caller must not dispatch")
        }, maximumContextCharacters = maxOf(4096, baselineCharacters))
        val failure = assertFailsWith<ModuleContextBudgetExceededException> { reconstructor.reconstruct(enlarged) }
        assertEquals(modulePromptEvidence(enlarged).text.length, failure.promptCharacters)
        assertTrue(failure.promptCharacters > failure.promptBudgetCharacters)
        assertFalse(dispatched)
    }

    @Test
    fun `cross module declarations require explicit recovered ownership`() {
        assertFailsWith<IllegalArgumentException> { modulePromptEvidence(request().copy(modulePlan = null)) }
    }

    private fun request(profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor): ModuleReconstructionRequest {
        val local = PlannedModule("local", "src/modules/local.c", "include/modules/local.h", listOf("local"), emptyList(),
            typeIds = listOf("unrelated_type"), boundaryEvidence = listOf("owned local function"))
        val dependency = PlannedModule("dependency", "src/modules/dependency.c", "include/modules/dependency.h",
            listOf("callee", "unrelated"), listOf("counter", "unrelated_global"), boundaryEvidence = emptyList())
        val caller = PlannedModule("callers", "src/modules/callers.c", "include/modules/callers.h",
            listOf("caller"), emptyList(), boundaryEvidence = emptyList())
        val model = RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
            RecoveredFunction("local", "local_function", 0x100u, "int local_function(needed_t *value)",
                "int local_function(needed_t *value) { return dependency(value) + external_counter; }",
                calls = setOf("callee"), referencedGlobals = setOf("counter")),
            RecoveredFunction("callee", "dependency", 0x200u, "int dependency(needed_t *value)", "SECRET_CALLEE_BODY"),
            RecoveredFunction("unrelated", "unrelated_sibling", 0x300u, "int unrelated_sibling(void)"),
            RecoveredFunction("caller", "incoming_caller", 0x400u, "int incoming_caller(void)", "SECRET_CALLER_BODY", calls = setOf("local")),
        ), globals = listOf(
            RecoveredGlobal("counter", "external_counter", 0x500u, "int"),
            RecoveredGlobal("unrelated_global", "unrelated_global", 0x600u, "int"),
        ), types = listOf(
            RecoveredType("needed_tag", "struct needed { int value; };"),
            RecoveredType("needed_alias", "typedef struct needed needed_t;"),
            RecoveredType("unrelated_type", "struct UNRELATED_TYPE { int value; };"),
            RecoveredType("unrelated_enum", "enum unrelated_mode { UNRELATED_MODE = 1 };"),
        ))
        val root = Path.of("build/test-scratch/minimal-context").toAbsolutePath()
        Files.createDirectories(root)
        return ModuleReconstructionRequest(local, model, "FULL_HEADER_SECRET", "FULL_HEADER_SECRET", "FULL_HEADER_SECRET",
            mapOf(dependency.headerPath to "FULL_HEADER_SECRET"), root, profile = profile,
            modulePlan = ModulePlan(modules = listOf(local, dependency, caller)))
    }
}
