package decompengine.project

import decompengine.agent.AgentWorkflowPhase
import decompengine.agent.AgentWorkflowProgress
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GeneratedCPlaceholderValidationTest {
    @Test
    fun `renamed typed zero results remain unresolved through the compiler-backed generation gate`() {
        for ((prototype, recovered) in listOf(
            "int convert(int value)" to "int convert(int value) { return value + 1; }",
            "const char *convert(int value)" to "const char *convert(int value) { return value ? \"yes\" : \"no\"; }",
            "struct result convert(int value)" to "struct result convert(int value) { struct result answer = {value}; return answer; }",
            "result_alias convert(int value)" to "result_alias convert(int value) { result_alias answer = {value}; return answer; }",
            "int (*convert(int value))(int)" to "int (*convert(int value))(int) { return value ? first : second; }",
        )) {
            val project = project()
            val model = model(function(prototype, recovered), main()).copy(types = TYPES)
            val manifest = SourceTreeGenerator.generate(model, project, reconstructor = ModuleReconstructor { request ->
                val evidence = EvidenceModuleReconstructor().reconstruct(request)
                evidence.copy(source = evidence.source.replace("decomp_placeholder_result", "renamed_result"),
                    generator = "scripted-agent", issues = emptyList())
            })
            assertTrue("fn_convert" in manifest.unresolvedImplementationIds, prototype)
            val reports = Files.walk(project.resolve("reports/modules")).use { paths ->
                paths.filter { it.toString().endsWith(".json") }.toList().map { it.readText() }
            }
            assertTrue(reports.any { it.contains("generic-return-placeholder") && it.contains("fn_convert") }, prototype)
            assertEquals(0, MakeProjectBuilder.build(project).returnCode, prototype)
        }
    }

    @Test
    fun `placeholder normalization changes only the declared and returned name`() {
        val context = GeneratedCDeclarationContext(TYPES)
        for ((prototype, body) in listOf(
            "int convert(void)" to "int chosen = {0}; return chosen;",
            "const char *convert(void)" to "const char *chosen = {0}; return chosen;",
            "struct result convert(void)" to "struct result result = {0}; return result;",
            "result_alias convert(void)" to "result_alias result = {0}; return result;",
            "int (*convert(void))(int result)" to "int (*result)(int result) = {0}; return result;",
        )) {
            assertTrue(isGeneratedCPlaceholderBody(function(prototype), body, context), "$prototype: $body")
        }
        val aggregate = function("struct result convert(void)")
        assertFalse(isGeneratedCPlaceholderBody(aggregate, "struct different result = {0}; return result;", context))
        assertFalse(isGeneratedCPlaceholderBody(aggregate, "struct result result = {0}; return other;", context))
    }

    @Test
    fun `optional dead parameter bookkeeping cannot disguise zero result stubs`() {
        val function = function("int convert(volatile int value)", "int convert(volatile int value) { return value + 1; }")
        for (body in listOf(
            "int candidate = {0}; return candidate;",
            "if (0) { (void)value; } int candidate = {0}; return candidate;",
            "if (0) {} int candidate = {0}; return candidate;",
            "/* renamed */ int candidate /* local */ = { /* zero */ 0 }; return candidate; // result",
        )) {
            assertTrue(isGeneratedCPlaceholderBody(function, body), body)
            val issues = assess(function, body)
            assertTrue(issues.any { it.code == "generic-return-placeholder" && it.entityIds == listOf("fn_convert") }, "$body: $issues")
        }
        val voidFunction = function("void convert(int value)", "void convert(int value) { use(value); }")
        assertTrue(isGeneratedCPlaceholderBody(voidFunction, "return;"))
        assertTrue(isGeneratedCPlaceholderBody(voidFunction, "if (0) { (void)value; } return;"))
    }

    @Test
    fun `additional behavior and different initializers are not erased by placeholder matching`() {
        val function = function("int convert(volatile int value)", "int convert(volatile int value) { return value + 1; }")
        for (body in listOf(
            "int candidate = {1}; return candidate;",
            "int candidate = {0}; candidate = value; return candidate;",
            "int candidate = {0}; observe(value); return candidate;",
            "int candidate = {0}; return other;",
            "if (value) { observe(value); } int candidate = {0}; return candidate;",
            "(void)value; int candidate = {0}; return candidate;", // An observable volatile read.
            "if (0) { (void)observe(value); } int candidate = {0}; return candidate;",
        )) {
            assertFalse(isGeneratedCPlaceholderBody(function, body), body)
            assertTrue(assess(function, body).none { it.code == "generic-return-placeholder" }, body)
        }
        val aggregate = function("struct result convert(void)")
        assertFalse(isGeneratedCPlaceholderBody(aggregate,
            "struct result candidate = {0}; candidate.value = 17; return candidate;", GeneratedCDeclarationContext(TYPES)))
    }

    @Test
    fun `retained trivial evidence still permits an equivalent renamed result`() {
        val project = project()
        val function = function("struct result convert(void)",
            "struct result convert(void) { struct result result = {0}; return result; }")
        val model = model(function, main()).copy(types = TYPES)
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = ModuleReconstructor { request ->
            val evidence = EvidenceModuleReconstructor().reconstruct(request)
            evidence.copy(source = evidence.source.replace("decomp_placeholder_result", "different_local_name"),
                generator = "scripted-agent", issues = emptyList())
        })
        assertTrue(manifest.unresolvedImplementationIds.isEmpty(), manifest.unresolvedImplementationIds.toString())
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
    }

    @Test
    fun `formerly accepted renamed placeholders cannot be reused or restored as accepted revisions`() {
        for (changeFingerprint in listOf(false, true)) {
            val project = project()
            val model = model(function("int convert(int value)", "int convert(int value) { return value + 1; }"), main())
            val overrides = mapOf("fn_convert" to "core", "fn_main" to "core")
            var reconstructCalls = 0
            var initialGeneration = true
            var initialRequest: ModuleReconstructionRequest? = null
            val acceptedBaselines = mutableListOf<String?>()
            val reconstructor = ModuleReconstructor { request ->
                reconstructCalls++
                acceptedBaselines += request.acceptedSourceSha256
                if (initialGeneration) {
                    initialRequest = request
                    RecoveredCModuleReconstructor().reconstruct(request).copy(generator = "scripted-agent")
                } else {
                    val evidence = EvidenceModuleReconstructor().reconstruct(request)
                    evidence.copy(source = evidence.source.replace("decomp_placeholder_result", "current_unresolved_result"),
                        generator = "scripted-agent", issues = emptyList())
                }
            }
            val initial = SourceTreeGenerator.generate(model, project, reconstructor = reconstructor, overrides = overrides)
            assertTrue(initial.unresolvedImplementationIds.isEmpty(), initial.unresolvedImplementationIds.toString())
            assertEquals(1, reconstructCalls)
            val checkpointPath = project.resolve("reports/modules/core.json")
            val sourcePath = project.resolve("src/modules/core.c")
            val checkpoint = Json.parseToJsonElement(checkpointPath.readText()).jsonObject
            assertEquals("true", checkpoint.getValue("accepted").jsonPrimitive.content)
            val compilation = checkpoint.getValue("compilation").jsonObject
            assertEquals("passed", compilation.getValue("outcome").jsonPrimitive.content)

            // Simulate a checkpoint accepted by the older matcher: its metadata and exact source
            // digest agree, but the source is now rejected by the current adapter policy.
            val staleSource = EvidenceModuleReconstructor().reconstruct(requireNotNull(initialRequest)).source
                .replace("decomp_placeholder_result", "formerly_accepted_result").trimEnd() + "\n"
            val staleSha256 = sha256(staleSource.toByteArray())
            sourcePath.writeText(staleSource)
            checkpointPath.writeText(JsonObject(checkpoint + mapOf(
                "sourceSha256" to JsonPrimitive(staleSha256),
                "compilation" to JsonObject(compilation + ("sourceSha256" to JsonPrimitive(staleSha256))),
            )).toString())
            initialGeneration = false
            val phases = mutableListOf<AgentWorkflowPhase>()
            val progress = object : AgentWorkflowProgress by AgentWorkflowProgress.NONE {
                override fun phase(phase: AgentWorkflowPhase, taskId: String?, acceptedRevisionSha256: String?) {
                    phases += phase
                }
            }
            val regenerated = SourceTreeGenerator.generate(model, project, reconstructor = reconstructor,
                overrides = overrides, observedBehavior = if (changeFingerprint) "new observation" else null,
                progress = progress)

            assertEquals(2, reconstructCalls, "stale checkpoint reused; changeFingerprint=$changeFingerprint")
            assertNull(acceptedBaselines.last(), "stale checkpoint offered as a rollback baseline")
            assertTrue("fn_convert" in regenerated.unresolvedImplementationIds)
            assertTrue(AgentWorkflowPhase.UNRESOLVED in phases, phases.toString())
            assertFalse(AgentWorkflowPhase.ACCEPTED in phases, phases.toString())
            assertFalse(AgentWorkflowPhase.ROLLED_BACK in phases, phases.toString())
            val currentSource = sourcePath.readText()
            assertTrue(currentSource.contains("current_unresolved_result"), currentSource)
            assertFalse(currentSource.contains("formerly_accepted_result"), currentSource)
            val currentCheckpoint = Json.parseToJsonElement(checkpointPath.readText()).jsonObject
            assertEquals("false", currentCheckpoint.getValue("accepted").jsonPrimitive.content)
            assertEquals(sha256(currentSource.toByteArray()), currentCheckpoint.getValue("sourceSha256").jsonPrimitive.content)
            assertTrue(currentCheckpoint.getValue("issues").jsonArray.any { issue ->
                issue.jsonObject.getValue("code").jsonPrimitive.content == "generic-return-placeholder" &&
                    issue.jsonObject.getValue("entityIds").jsonArray.any { it.jsonPrimitive.content == "fn_convert" }
            }, currentCheckpoint.toString())
            assertTrue(project.resolve("UNRESOLVED.md").readText().contains("fn_convert"))
            assertFalse(Files.exists(project.resolve("reports/modules/core.attempt.json")), "invalid baseline triggered rollback")
        }
    }

    private fun assess(function: RecoveredFunction, body: String): List<ModuleReconstructionIssue> {
        val model = model(function)
        val module = DeterministicModulePlanner().plan(model).modules.single()
        return GeneratedCCandidateValidation.assess(module, model, "scripted-agent", "/* ${function.id} */\n${function.prototype} {\n$body\n}")
    }

    private fun function(prototype: String, recovered: String? = null) = RecoveredFunction("fn_convert", "convert", 200UL, prototype, recovered)
    private fun main() = RecoveredFunction("fn_main", "main", 100UL, "int main(void)", "int main(void) { return 0; }")
    private fun model(vararg functions: RecoveredFunction) = RecoveredProgramModel(inputSha256 = "placeholder-validation", functions = functions.toList())
    private fun project(): Path = Files.createTempDirectory(Path.of("build", "generated-c-placeholder-tests").createDirectories(), "project-")

    private companion object {
        val TYPES = listOf(RecoveredType("result_type", "struct result { int value; };"),
            RecoveredType("result_alias", "typedef struct result result_alias;"))
    }
}
