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
    fun `equivalent pure zero initializers remain placeholders while meaningful expressions survive`() {
        val context = GeneratedCDeclarationContext(TYPES)
        for (prototype in listOf("int convert(void)", "const char *convert(void)",
            "struct result convert(void)", "int (*convert(void))(int)")) {
            val function = function(prototype)
            val declaration = when (prototype) {
                "int convert(void)" -> "int candidate"
                "const char *convert(void)" -> "const char *candidate"
                "struct result convert(void)" -> "struct result candidate"
                else -> "int (*candidate)(int)"
            }
            for (initializer in listOf("{0,}", "{ 0U, }", "{{0},}", "{0, 0}", "{(+00),}", "0", "(0x0ULL)")) {
                assertTrue(isGeneratedCPlaceholderBody(function, "$declaration = $initializer; return ((candidate));", context),
                    "$prototype: $initializer")
            }
            for (initializer in listOf("{1,}", "{0,1}", "{observe(),0}", "{0 * observe()}", "{value}",
                "{0 + value}", "{0 / value}", "{}", "{0,,}", "{0;}", "(int)0")) {
                assertFalse(isGeneratedCPlaceholderBody(function, "$declaration = $initializer; return candidate;", context),
                    "$prototype: $initializer")
            }
        }
        for (zero in listOf("0U", "0x00UL", "(00)", "+(0)", "-0")) {
            assertTrue(isGeneratedCSimpleReturnBody("if (0) { (void)value; } return $zero;"), zero)
        }
        assertFalse(isGeneratedCSimpleReturnBody("return 0 * observe();"))
        val nestedZero = "(".repeat(256) + "0" + ")".repeat(256)
        val nestedName = "(".repeat(256) + "candidate" + ")".repeat(256)
        assertTrue(isGeneratedCSimpleReturnBody("return $nestedZero;"))
        assertTrue(isGeneratedCPlaceholderBody(function("int convert(void)"), "int candidate = $nestedZero; return $nestedName;"))
        assertTrue(isGeneratedCPlaceholderBody(function("struct result convert(void)"),
            "struct result candidate = " + "{".repeat(256) + "0" + "}".repeat(256) + "; return candidate;", context))
        assertFalse(isGeneratedCSimpleReturnBody("return " + "(".repeat(256) + "1" + ")".repeat(256) + ";"))
    }

    @Test
    fun `floating zero spellings cannot disguise direct or typed return placeholders`() {
        val function = function("double convert(void)", "double convert(void) { return observe(); }")
        for (zero in listOf("0.0", "0.0f", "0.L", ".0", "00.000F", "0e0", "0E+12L", "0.0e-9000",
            "0x0p0", "0X00.00P+12F", "0x.0p-4L", "-(0.0)", "+(.0f)",
            "0.0f128", "0.0f64", "0.0f32", "0.0f32x", "0.0f64x", "0.0df", "0.0dd", "0.0dl",
            "0.0q", "0.0Q", "0.0w", "0.0d", "0.0D", "0.0bf16", "0.0f16", "0.0f64i", "0.0if64",
            "0.0i", "0.0j", "0.0fi", "0.0if", "0.0Li", "0.0iL", "0i", "0Ui", "0iU",
            "0b0", "0B00", "0wb", "0uwb", "0wbu", "0ULLi")) {
            for (body in listOf("return $zero;", "double candidate = $zero; return candidate;",
                "double candidate = {$zero,}; ; return ((candidate));")) {
                assertTrue(assess(function, body).any {
                    it.code == "generic-return-placeholder" && it.entityIds == listOf("fn_convert")
                }, body)
            }
        }
        // Do not underflow nonzero constants, join separated tokens, or erase side effects.
        for (value in listOf("0.1", "1e-9999", "0x1p-9999", "0x0.1p0", "0.0 + observe()",
            "0 .0", "0/* gap */.0", "0e + 0", "0.0ff", "0x0.0", "0f", "0.0foo",
            "0.1f128", "1e-9999df", "0.1i", "0.1q", "0.1bf16", "0b1", "1wb", "1uwb")) {
            assertFalse(isGeneratedCSimpleReturnBody("return $value;"), value)
            assertFalse(isGeneratedCPlaceholderBody(function, "double candidate = $value; return candidate;"), value)
        }
        for (body in listOf("return 0.0;", "double candidate = -0x0p0; return candidate;")) {
            assertTrue(assess(function.copy(decompiledC = "double convert(void) { $body }"), body)
                .none { it.code == "generic-return-placeholder" }, body)
        }
    }

    @Test
    fun `floating zero candidates compile but remain unresolved at generation admission`() {
        for (type in listOf("float", "double", "long double")) {
            val prototype = "$type convert(void)"
            val input = model(function(prototype, "$prototype { return 1.5; }"), main())
            val project = project()
            val manifest = SourceTreeGenerator.generate(input, project, reconstructor = ModuleReconstructor { request ->
                val evidence = EvidenceModuleReconstructor().reconstruct(request)
                evidence.copy(source = evidence.source.replace("= {0};", "= 0.0f;"),
                    generator = "scripted-agent", issues = emptyList())
            })
            assertTrue("fn_convert" in manifest.unresolvedImplementationIds, type)
            assertTrue(Files.walk(project.resolve("reports/modules")).use { paths ->
                paths.filter { it.toString().endsWith(".json") }.toList().any { it.readText().contains("generic-return-placeholder") }
            }, type)
            assertEquals(0, MakeProjectBuilder.build(project).returnCode, type)
        }
    }

    @Test
    fun `trailing comma zero candidates compile but cannot become accepted implementations`() {
        for ((prototype, recovered) in listOf(
            "int convert(int value)" to "int convert(int value) { return value + 1; }",
            "const char *convert(int value)" to "const char *convert(int value) { return value ? \"yes\" : \"no\"; }",
            "struct result convert(int value)" to "struct result convert(int value) { struct result answer = {value}; return answer; }",
        )) {
            val project = project()
            val input = model(function(prototype, recovered), main()).copy(types = TYPES)
            val manifest = SourceTreeGenerator.generate(input, project, reconstructor = ModuleReconstructor { request ->
                val evidence = EvidenceModuleReconstructor().reconstruct(request)
                evidence.copy(source = evidence.source.replace("= {0};", "= {0,};"),
                    generator = "scripted-agent", issues = emptyList())
            })
            assertTrue("fn_convert" in manifest.unresolvedImplementationIds, prototype)
            assertTrue(project.resolve("UNRESOLVED.md").readText().contains("fn_convert"), prototype)
            assertTrue(Files.walk(project.resolve("reports/modules")).use { paths ->
                paths.filter { it.toString().endsWith(".json") }.toList().any { it.readText().contains("generic-return-placeholder") }
            }, prototype)
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
    fun `empty statements cannot disguise typed void or direct zero return stubs`() {
        val context = GeneratedCDeclarationContext(TYPES)
        for ((prototype, body) in listOf(
            "int convert(int value)" to ";; if (0) { ;; (void)value; ;; }; ; int candidate = {0}; ;; return candidate; ;;",
            "const char *convert(void)" to "; const char *candidate = {0}; ; return candidate; ;",
            "struct result convert(void)" to "; struct result candidate = {0}; ; return candidate; ;",
            "int (*convert(void))(int)" to "; int (*candidate)(int) = {0}; ; return candidate; ;",
            "void convert(int value)" to "; if (0) { ; (void)value; ; }; return; ;",
            "void convert(void)" to "; return; ;",
        )) {
            assertTrue(isGeneratedCPlaceholderBody(function(prototype), body, context), "$prototype: $body")
        }
        for ((prototype, body) in listOf(
            "int convert(void)" to "; return 0; ;",
            "void convert(void)" to "; return; ;",
        )) {
            assertTrue(isGeneratedCSimpleReturnBody(body), body)
            assertTrue(assess(function(prototype, "$prototype { observe(); }"), body)
                .any { it.code == "generic-return-placeholder" && it.entityIds == listOf("fn_convert") }, body)
            // Empty statements in retained trivial evidence do not turn it into nontrivial evidence.
            assertTrue(assess(function(prototype, "$prototype { $body }"), body)
                .none { it.code == "generic-return-placeholder" }, body)
        }
    }

    @Test
    fun `empty-statement evidence stubs compile but remain unresolved through candidate admission`() {
        for ((prototype, recovered) in listOf(
            "int convert(int value)" to "int convert(int value) { return value + 1; }",
            "void convert(int *value)" to "void convert(int *value) { *value += 1; }",
        )) {
            val project = project()
            val manifest = SourceTreeGenerator.generate(model(function(prototype, recovered), main()), project,
                reconstructor = ModuleReconstructor { request ->
                    val evidence = EvidenceModuleReconstructor().reconstruct(request)
                    evidence.copy(source = evidence.source
                        .replace("if (0) {", "; ; if (0) { ; ;")
                        .replace("(void)value;", "(void)value; ; ;")
                        .replace("= {0};", "= {0}; ; ;")
                        .replace("return decomp_placeholder_result;", "return decomp_placeholder_result; ; ;")
                        .replace("return;", "return; ; ;")
                        .replace("decomp_placeholder_result", "candidate_result"),
                        generator = "scripted-agent", issues = emptyList())
                })
            assertTrue("fn_convert" in manifest.unresolvedImplementationIds, prototype)
            val reports = Files.walk(project.resolve("reports/modules")).use { paths ->
                paths.filter { it.toString().endsWith(".json") }.toList().map { Json.parseToJsonElement(it.readText()).jsonObject }
            }
            assertTrue(reports.any { report ->
                report.getValue("accepted").jsonPrimitive.content == "false" &&
                    report.getValue("issues").jsonArray.any { issue ->
                        issue.jsonObject.getValue("code").jsonPrimitive.content == "generic-return-placeholder" &&
                            issue.jsonObject.getValue("entityIds").jsonArray.any { it.jsonPrimitive.content == "fn_convert" }
                    }
            }, "$prototype: $reports")
            assertEquals(0, MakeProjectBuilder.build(project).returnCode, prototype)
        }
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
            "if (0); { (void)value; } int candidate = {0}; return candidate;", // The volatile read executes.
            "int candidate = {0}; if (value); return candidate;",
            "int candidate = {0}; while (value); return candidate;",
            "int candidate = {0}; for (; value;); return candidate;",
            "int candidate = {0}; do ; while (value); return candidate;",
            "int candidate = {0}; label: ; return candidate;",
            "int candidate = {0}; return; candidate;",
            "int candidate = {0}; return candidate; ; observe(value);",
            "int candidate = {0;}; return candidate;", // Never remove tokens inside an initializer.
            "int candidate = {0} return candidate;", // The declaration terminator remains required.
            "if (0) { (void); value; } int candidate = {0}; return candidate;",
        )) {
            assertFalse(isGeneratedCPlaceholderBody(function, body), body)
            assertTrue(assess(function, body).none { it.code == "generic-return-placeholder" }, body)
        }
        for (body in listOf("if (value); return 0;", "while (value); return 0;", "for (;;); return 0;",
            "label: ; return 0;", "return; value;", "return 0; ; observe(value);", "return ; 0;", "return 0")) {
            assertFalse(isGeneratedCSimpleReturnBody(body), body)
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
    fun `formerly accepted empty-statement placeholders cannot be reused or restored as accepted revisions`() {
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
                .replace("decomp_placeholder_result", "formerly_accepted_result")
                .replace("= {0};", "= {0,}; ; ;").trimEnd() + "\n"
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
