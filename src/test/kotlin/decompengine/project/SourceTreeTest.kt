package decompengine.project

import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentHarness
import decompengine.agent.AgentOperation
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentWorkspacePath
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SourceTreeTest {
    @Test
    fun `generator emits buildable multi-module tree and provenance manifest`() {
        val project = createTempDirectory("source-tree-")
        val progress = mutableListOf<String>()
        val manifest = SourceTreeGenerator.generate(model(), project, onModuleProgress = { _, _, module -> progress += module })

        assertTrue(project.resolve("src/modules/parse.c").exists())
        assertTrue(project.resolve("src/modules/render.c").exists())
        assertTrue(project.resolve("src/modules/parse_internal.h").readText().contains("fn_0000000000401000"))
        assertTrue(project.resolve("include/modules/render.h").readText().contains("fn_0000000000401020"))
        assertTrue(project.resolve("include/decomp_types.h").readText().contains("struct recovered_state"))
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        assertEquals(manifest.editablePaths, SourceTreeManifestReader.editablePaths(project))
        assertTrue(project.resolve("source_tree_manifest.json").readText().contains("input-sha"))
        assertEquals(listOf("render", "parse"), progress)
        val confidence = project.resolve("reports/confidence.json").readText()
        assertTrue(confidence.contains("\"id\":\"parse\""))
        assertTrue(confidence.contains("\"projectScore\""))
        assertTrue(confidence.contains("behavioral equivalence is not implied"))
        assertTrue(project.resolve("UNRESOLVED.md").readText().contains("does not claim universal behavioral equivalence"))
    }

    @Test
    fun `LLM reconstruction is restricted to the planned module path`() {
        val project = createTempDirectory("source-tree-llm-")
        val harness = object : AgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                assertTrue(request.objective.contains("src/modules/parse.c"))
                assertTrue(request.contextInputs.single { it.id == "observed-behavior" }.content.contains("case default: stdout=ok"))
                val path = AgentWorkspacePath("project", "src/modules/parse.c")
                assertTrue(request.accessPolicy.allows(path, AgentOperation.CREATE_FILE))
                val source = "#include \"modules/parse.h\"\nint parse_input(void) { return 0; }\n"
                val target = path.resolve(request.workspaceRoots)
                target.writeText(source)
                return AgentExecutionResult(
                    AgentStopReason.COMPLETED,
                    "module reconstructed in workspace",
                    listOf(AgentFileChange(path, AgentFileChangeKind.CREATED, null, sha256(source.toByteArray()), source.length.toLong())),
                )
            }
        }
        val oneModule = model().copy(functions = model().functions.take(1), globals = emptyList())

        SourceTreeGenerator.generate(
            oneModule,
            project,
            reconstructor = BoundedLlmModuleReconstructor(harness),
            observedBehavior = "case default: stdout=ok",
        )

        assertTrue(project.resolve("src/modules/parse.c").readText().contains("parse_input"))
        assertTrue(project.resolve("source_tree_manifest.json").readText().contains("\"generator\": \"agent:unspecified\""))
    }

    @Test
    fun `LLM reconstruction enforces context budget before making a request`() {
        var called = false
        val harness = object : AgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                called = true
                error("unexpected")
            }
        }
        val reconstructor = BoundedLlmModuleReconstructor(harness, 4_096)
        val huge = model().copy(functions = listOf(model().functions.first().copy(decompiledC = "x".repeat(10_000))))
        val module = DeterministicModulePlanner().plan(huge).modules.single()

        assertFailsWith<IllegalArgumentException> {
            reconstructor.reconstruct(
                ModuleReconstructionRequest(
                    module,
                    huge,
                    "header",
                    "module",
                    "private",
                    emptyMap(),
                    createTempDirectory("source-tree-context-budget-"),
                ),
            )
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

    @Test
    fun `build rejects unowned implementation files`() {
        val project = createTempDirectory("source-tree-unowned-")
        SourceTreeGenerator.generate(model(), project)
        project.resolve("src/rogue.c").writeText("int rogue(void) { return 1; }\n")

        val failure = assertFailsWith<BuildException> { MakeProjectBuilder.build(project) }

        assertTrue(failure.message.orEmpty().contains("failed to build"))
        assertTrue(project.resolve("reports/build.log").readText().contains("unowned C files"))
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
