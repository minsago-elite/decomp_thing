package decompengine.project

import decompengine.repair.RepairClient
import decompengine.repair.RepairRequest
import decompengine.repair.RepairResponse
import decompengine.repair.SourcePatch
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SourceTreeTest {
    @Test
    fun `generator emits buildable multi-module tree and provenance manifest`() {
        val project = createTempDirectory("source-tree-")
        val manifest = SourceTreeGenerator.generate(model(), project)

        assertTrue(project.resolve("src/modules/parse.c").exists())
        assertTrue(project.resolve("src/modules/render.c").exists())
        assertTrue(project.resolve("include/modules/parse.h").readText().contains("fn_0000000000401000"))
        assertTrue(project.resolve("include/decomp_types.h").readText().contains("struct recovered_state"))
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        assertEquals(manifest.editablePaths, SourceTreeManifestReader.editablePaths(project))
        assertTrue(project.resolve("source_tree_manifest.json").readText().contains("input-sha"))
        val confidence = project.resolve("reports/confidence.json").readText()
        assertTrue(confidence.contains("\"id\":\"parse\""))
        assertTrue(confidence.contains("\"projectScore\""))
        assertTrue(confidence.contains("behavioral equivalence is not implied"))
    }

    @Test
    fun `LLM reconstruction is restricted to the planned module path`() {
        val project = createTempDirectory("source-tree-llm-")
        val client = object : RepairClient {
            override fun requestRepair(request: RepairRequest): RepairResponse {
                assertTrue(request.prompt.contains("src/modules/parse.c"))
                return RepairResponse("module", listOf(SourcePatch("src/modules/parse.c", "#include \"modules/parse.h\"\nint parse_input(void) { return 0; }\n")))
            }
        }
        val oneModule = model().copy(functions = model().functions.take(1), globals = emptyList())

        SourceTreeGenerator.generate(oneModule, project, reconstructor = BoundedLlmModuleReconstructor(client))

        assertTrue(project.resolve("src/modules/parse.c").readText().contains("parse_input"))
        assertTrue(project.resolve("source_tree_manifest.json").readText().contains("\"generator\": \"llm\""))
    }

    @Test
    fun `LLM reconstruction enforces context budget before making a request`() {
        var called = false
        val client = object : RepairClient {
            override fun requestRepair(request: RepairRequest): RepairResponse {
                called = true
                error("unexpected")
            }
        }
        val reconstructor = BoundedLlmModuleReconstructor(client, 4_096)
        val huge = model().copy(functions = listOf(model().functions.first().copy(decompiledC = "x".repeat(10_000))))
        val module = DeterministicModulePlanner().plan(huge).modules.single()

        assertFailsWith<IllegalArgumentException> {
            reconstructor.reconstruct(ModuleReconstructionRequest(module, huge, "header", "module", emptyMap()))
        }
        assertTrue(!called)
    }

    @Test
    fun `unchanged modules resume from checkpoints without regeneration`() {
        val project = createTempDirectory("source-tree-resume-")
        SourceTreeGenerator.generate(model(), project)
        val before = project.resolve("src/modules/parse.c").readText()
        val refusing = ModuleReconstructor { error("unchanged module was regenerated") }

        SourceTreeGenerator.generate(model(), project, reconstructor = refusing)

        assertEquals(before, project.resolve("src/modules/parse.c").readText())
        assertTrue(project.resolve("reports/modules/parse.json").exists())
        assertTrue(project.resolve("reports/modules/render.json").exists())
    }

    private fun model() = RecoveredProgramModel(
        inputSha256 = "input-sha",
        functions = listOf(
            RecoveredFunction("fn_0000000000401000", "parse_input", 0x401000UL, "int parse_input(void)", calls = setOf("fn_0000000000401020")),
            RecoveredFunction("fn_0000000000401020", "render_page", 0x401020UL, "int render_page(void)", referencedGlobals = setOf("global_404000")),
        ),
        globals = listOf(RecoveredGlobal("global_404000", "page_count", 0x404000UL, "int")),
        types = listOf(RecoveredType("type_state", "struct recovered_state { int count; };", 0x404000UL)),
    )
}
