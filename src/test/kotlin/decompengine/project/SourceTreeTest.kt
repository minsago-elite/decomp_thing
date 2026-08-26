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
import kotlin.test.assertFalse
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
                val source = "#include \"modules/parse.h\"\n/* fn_0000000000401000 */\nint parse_input(void) { return 17; }\n"
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
        val checkpoint = project.resolve("reports/modules/parse.json").readText()
        assertTrue(checkpoint.contains("\"accepted\": true"))
        assertTrue(checkpoint.contains("\"promptCharacters\":"))
        assertTrue(checkpoint.contains("\"promptBudgetCharacters\": 120000"))
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
        SourceTreeGenerator.generate(model(), project, reconstructor = validReconstructor())
        val before = project.resolve("src/modules/parse.c").readText()
        val refusing = ModuleReconstructor { error("unchanged module was regenerated") }

        SourceTreeGenerator.generate(model(), project, reconstructor = refusing)

        assertEquals(before, project.resolve("src/modules/parse.c").readText())
        assertTrue(project.resolve("reports/modules/parse.json").exists())
        assertTrue(project.resolve("reports/modules/render.json").exists())
    }

    @Test
    fun `evidence-only placeholders are explicit unresolved implementations`() {
        val project = createTempDirectory("source-tree-evidence-only-")

        val manifest = SourceTreeGenerator.generate(model(), project)

        assertEquals(
            (model().functions.map { it.id } + model().globals.map { it.id }).sorted(),
            manifest.unresolvedImplementationIds.sorted(),
        )
        assertTrue(manifest.files.filter { it.path.endsWith(".c") && "/modules/" in it.path }.all { it.acceptedImplementation == false })
        assertTrue(project.resolve("reports/modules/parse.json").readText().contains("evidence-only-placeholder"))
        val unresolved = project.resolve("UNRESOLVED.md").readText()
        assertTrue(unresolved.contains("fn_0000000000401000"))
        assertTrue(unresolved.contains("reports/modules/parse.json"))
    }

    @Test
    fun `generic agent return stubs are rejected with attributable evidence`() {
        val project = createTempDirectory("source-tree-generic-agent-")
        val harness = writingHarness(
            "/* fn_0000000000401000 */\nint parse_input(void) { return 0; }\n",
        )
        val oneModule = model().copy(functions = model().functions.take(1), globals = emptyList())

        val manifest = SourceTreeGenerator.generate(
            oneModule,
            project,
            reconstructor = BoundedLlmModuleReconstructor(harness),
        )

        assertEquals(listOf("fn_0000000000401000"), manifest.unresolvedImplementationIds)
        assertEquals(false, manifest.files.single { it.path == "src/modules/parse.c" }.acceptedImplementation)
        val checkpoint = project.resolve("reports/modules/parse.json").readText()
        assertTrue(checkpoint.contains("generic-return-placeholder"))
        assertTrue(checkpoint.contains("\"status\":\"unresolved\""))
    }

    @Test
    fun `partial agent modules and undefined decompiler types are never accepted`() {
        val project = createTempDirectory("source-tree-partial-agent-")
        val functions = listOf(
            model().functions[0].copy(name = "parse_first", calls = emptySet()),
            model().functions[1].copy(name = "parse_second", referencedGlobals = emptySet()),
        )
        val sameModule = model().copy(functions = functions, globals = emptyList())
        val harness = writingHarness(
            "/* fn_0000000000401000 */\nundefined8 parse_first(void) { return 17; }\n",
        )

        val manifest = SourceTreeGenerator.generate(
            sameModule,
            project,
            reconstructor = BoundedLlmModuleReconstructor(harness),
        )

        assertEquals(functions.map { it.id }.sorted(), manifest.unresolvedImplementationIds.sorted())
        val checkpoint = project.resolve("reports/modules/parse.json").readText()
        assertTrue(checkpoint.contains("undefined-decompiler-type"))
        assertTrue(checkpoint.contains("missing-function-definition"))
        assertTrue(checkpoint.contains("fn_0000000000401020"))
    }

    @Test
    fun `global provenance without a definition is explicitly unresolved`() {
        val project = createTempDirectory("source-tree-missing-global-")
        val onlyGlobal = model().copy(functions = emptyList())
        val reconstructor = ModuleReconstructor {
            val source = """
                /* global_404000; page_count is referenced but not defined */
                extern int page_count;
                int copied_count = page_count;
            """.trimIndent() + "\n"
            ReconstructedModule(source, "scripted", sha256(source.toByteArray()))
        }

        val manifest = SourceTreeGenerator.generate(onlyGlobal, project, reconstructor = reconstructor)

        assertEquals(listOf("global_404000"), manifest.unresolvedImplementationIds)
        assertTrue(project.resolve("reports/modules/core.json").readText().contains("missing-global-definition"))
    }

    @Test
    fun `undefined decompiler types in comments and literals do not reject valid code`() {
        val project = createTempDirectory("source-tree-undefined-comment-")
        val oneModule = model().copy(functions = model().functions.take(1), globals = emptyList())
        val reconstructor = ModuleReconstructor {
            val source = """
                /* fn_0000000000401000; recovered undefined8 note */
                int parse_input(void) {
                    const char *message = "copied one byte";
                    return message[0] == 'b' ? 17 : 18;
                }
            """.trimIndent() + "\n"
            ReconstructedModule(source, "scripted", sha256(source.toByteArray()))
        }

        val manifest = SourceTreeGenerator.generate(oneModule, project, reconstructor = reconstructor)

        assertTrue(manifest.unresolvedImplementationIds.isEmpty())
        assertTrue(project.resolve("reports/modules/parse.json").readText().contains("\"accepted\": true"))
    }

    @Test
    fun `checkpoint source hash prevents a changed implementation from being silently resumed`() {
        val project = createTempDirectory("source-tree-checkpoint-hash-")
        var calls = 0
        val reconstructor = validReconstructor { calls++ }
        SourceTreeGenerator.generate(model(), project, reconstructor = reconstructor)
        val parse = project.resolve("src/modules/parse.c")
        val accepted = parse.readText()
        parse.writeText(accepted.replace("return 4096", "return 99"))

        SourceTreeGenerator.generate(model(), project, reconstructor = reconstructor)

        assertEquals(3, calls, "only the source whose checkpoint hash changed should be regenerated")
        assertEquals(accepted, parse.readText())
        assertTrue(project.resolve("reports/modules/parse.json").readText().contains(sha256(accepted.toByteArray())))
    }

    @Test
    fun `interrupted generation preserves accepted module bytes and resumes at the unfinished module`() {
        val project = createTempDirectory("source-tree-interrupted-")
        val interrupted = object : ModuleReconstructor {
            override fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule {
                if (request.module.id == "parse") {
                    throw ModuleReconstructionInterruptedException(
                        request.module.id,
                        AgentStopReason.CANCELLED,
                        "operator requested stop",
                    )
                }
                return validReconstructor().reconstruct(request)
            }

            override fun cacheIdentity(): String = "interrupting-test"
        }

        assertFailsWith<ModuleReconstructionInterruptedException> {
            SourceTreeGenerator.generate(model(), project, reconstructor = interrupted)
        }
        val acceptedPath = project.resolve("src/modules/render.c")
        val acceptedHash = sha256(acceptedPath.readText().toByteArray())
        val attempt = project.resolve("reports/modules/parse.attempt.json")
        assertTrue(attempt.readText().contains("\"stopReason\": \"cancelled\""))

        val resumed = object : ModuleReconstructor {
            override fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule {
                check(request.module.id == "parse") { "accepted render module was regenerated" }
                return validReconstructor().reconstruct(request)
            }

            override fun cacheIdentity(): String = "resuming-test"
        }
        val manifest = SourceTreeGenerator.generate(model(), project, reconstructor = resumed)

        assertEquals(acceptedHash, sha256(acceptedPath.readText().toByteArray()))
        assertTrue(manifest.unresolvedImplementationIds.isEmpty())
        assertFalse(attempt.exists())
    }

    @Test
    fun `oversized planned modules are never sent and remain explicitly unresolved`() {
        val project = createTempDirectory("source-tree-budget-failure-")
        var calls = 0
        val harness = object : AgentHarness {
            override fun execute(
                request: AgentExecutionRequest,
                onEvent: (AgentExecutionEvent) -> Unit,
            ): AgentExecutionResult {
                calls++
                error("oversized prompt was sent")
            }
        }
        val huge = model().copy(
            functions = model().functions.map { it.copy(decompiledC = "x".repeat(10_000)) },
        )

        val manifest = SourceTreeGenerator.generate(
            huge,
            project,
            reconstructor = BoundedLlmModuleReconstructor(harness, 4_096),
        )

        assertEquals(0, calls)
        assertEquals(
            (huge.functions.map { it.id } + huge.globals.map { it.id }).sorted(),
            manifest.unresolvedImplementationIds.sorted(),
        )
        listOf("parse", "render").forEach { module ->
            val report = project.resolve("reports/modules/$module.json").readText()
            assertTrue(report.contains("context-budget-exceeded"))
            assertTrue(report.contains("\"promptBudgetCharacters\": 4096"))
            assertTrue(report.contains("\"accepted\": false"))
        }
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

    private fun writingHarness(source: String): AgentHarness = object : AgentHarness {
        override fun execute(
            request: AgentExecutionRequest,
            onEvent: (AgentExecutionEvent) -> Unit,
        ): AgentExecutionResult {
            val target = request.accessPolicy.pathRules.single { rule -> AgentOperation.WRITE_FILE in rule.operations }.path
            val path = target.resolve(request.workspaceRoots)
            val before = path.takeIf { it.exists() }?.readText()?.toByteArray()
            path.writeText(source)
            return AgentExecutionResult(
                AgentStopReason.COMPLETED,
                "scripted module result",
                listOf(
                    AgentFileChange(
                        target,
                        if (before == null) AgentFileChangeKind.CREATED else AgentFileChangeKind.MODIFIED,
                        before?.let(::sha256),
                        sha256(source.toByteArray()),
                        source.toByteArray().size.toLong(),
                    ),
                ),
            )
        }

        override fun implementationIdentifier(): String = "source-tree-test"
    }

    private fun validReconstructor(onCall: () -> Unit = {}): ModuleReconstructor = ModuleReconstructor { request ->
        onCall()
        val functions = request.module.functionIds.map { id -> request.model.functions.single { it.id == id } }
        val globals = request.module.globalIds.map { id -> request.model.globals.single { it.id == id } }
        val source = buildString {
            append("#include \"modules/${request.module.id}.h\"\n")
            globals.forEach { global ->
                append("/* ${global.id} */\nint ${global.name} = 1;\n")
            }
            functions.forEach { function ->
                append("/* ${function.id} */\n")
                append("int ${function.name}(void) { return ${function.address.toLong() and 0xffff}; }\n")
            }
        }
        ReconstructedModule(source, "scripted-valid", sha256(source.toByteArray()))
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
