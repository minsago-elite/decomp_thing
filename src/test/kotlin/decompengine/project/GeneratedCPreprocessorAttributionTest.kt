package decompengine.project

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GeneratedCPreprocessorAttributionTest {
    @Test
    fun `inactive scalar and qualified function pointer globals never satisfy either attribution path`() {
        for ((type, declaration) in listOf("int" to "int item = 7;", "int (* const)(int)" to "int (* const item)(int) = 0;")) {
            val model = model(global(type))
            for (conditional in listOf(
                "#if 0\n$declaration\n#endif",
                "#if 1\n$declaration\n#endif", // No source-level condition evaluator is implied.
                "#if 1\n#if 0\n$declaration\n#endif\n#endif",
                "#if 1\nint other;\n#else\n$declaration\n#endif",
                "#if 1\nint other;\n#elif 0\n$declaration\n#else\nint another;\n#endif",
                "#ifdef MISSING_FEATURE\n$declaration\n#endif",
                "#ifndef OPTIONAL_FEATURE\n$declaration\n#endif",
                "# /**/ if 0\n$declaration\n#endif",
            )) {
                val source = "/* global_item */\n$conditional\n"
                assertNotNull(generatedCAttributionPreprocessorIssue(source), source)
                assertFalse(generatedCGlobalDefinition(source, "item"), source)
                assertUnsupported(model, source, "global_item")
            }
        }
    }

    @Test
    fun `macro rewriting alternate directive tokens and line splicing stay explicitly unresolved`() {
        val model = model(global("int"))
        for (source in listOf(
            "#define item renamed_storage\nint item = 7;",
            "#define DECLARE(name) int name = 7;\nDECLARE(item)",
            "#define ENABLED 0\n#if ENABLED\nint item = 7;\n#endif",
            "#undef item\nint item = 7;",
            "#pragma redefine_extname item renamed_storage\nint item = 7;",
            "#include HEADER_NAME\nint item = 7;",
            "%:if 0\nint item = 7;\n%:endif",
            "??=if 0\nint item = 7;\n??=endif",
            "#i\\\nf 0\nint item = 7;\n#endif",
            "#i??/\nf 0\nint item = 7;\n#endif",
            "// physical CR ends this comment\r#if 0\rint item = 7;\r#endif",
        )) {
            val attributed = "/* global_item */\n$source\n"
            assertNotNull(generatedCAttributionPreprocessorIssue(attributed), source)
            assertFalse(generatedCGlobalDefinition(attributed, "item"), source)
            assertUnsupported(model, attributed, "global_item")
        }
    }

    @Test
    fun `inactive function definitions and recovered trivial evidence do not establish implementations`() {
        val main = main()
        val program = model(functions = listOf(main))
        for (source in listOf(
            "#if 0\nint main(void) { return 17; }\n#endif",
            "#define main renamed_main\nint main(void) { return 17; }",
            "#if 1\nint other(void) { return 17; }\n#else\nint main(void) { return 17; }\n#endif",
        )) {
            assertNull(generatedCFunctionBody(source, "main"), source)
            assertUnsupported(program, "/* fn_main */\n$source\n", "fn_main")
        }
        val recovered = main.copy(decompiledC = "#if 0\nint main(void) { return 0; }\n#else\nint main(void) { return 17; }\n#endif")
        val issues = assess(model(functions = listOf(recovered)), "/* fn_main */\nint main(void) { return 0; }")
        assertTrue(issues.any { it.code == "generic-return-placeholder" && it.entityIds == listOf("fn_main") }, issues.toString())
    }

    @Test
    fun `literal includes and directive text in comments and literals preserve unconditional attribution`() {
        val source = """
            #include "core_internal.h"
            #include <stdint.h>
            # /* null directive */
            /* #define item renamed_storage
               #if 0
               #endif */
            // #undef item
            /* global_item */
            int item = 7;
            /* fn_main */
            int main(void) {
                const char *note = "#if 0\n#define item renamed_storage";
                return note[0] == '#' ? item : 17;
            }
        """.trimIndent()
        assertNull(generatedCAttributionPreprocessorIssue(source))
        assertTrue(generatedCGlobalDefinition(source, "item"))
        assertNotNull(generatedCFunctionBody(source, "main"))
        assertTrue(assess(model(global("int"), functions = listOf(main())), source).isEmpty())
    }

    @Test
    fun `unused inactive or renamed globals compile and link but remain unresolved in generated projects`() {
        for (type in listOf("int", "int (* const)(int)")) {
            for (rename in listOf(false, true)) {
                val project = project()
                val global = global(type)
                val model = model(global, functions = listOf(main()))
                val manifest = SourceTreeGenerator.generate(model, project, overrides = OWNERS,
                    reconstructor = ModuleReconstructor { request ->
                        val recovered = RecoveredCModuleReconstructor().reconstruct(request)
                        val declaration = globalDeclaration(global, external = false)
                        assertTrue(recovered.source.contains(declaration), recovered.source)
                        val replacement = if (rename) "#define item renamed_storage\n$declaration\n#undef item"
                            else "#if 0\n$declaration\n#endif"
                        recovered.copy(source = recovered.source.replace(declaration, replacement), generator = "scripted-agent", issues = emptyList())
                    })
                assertTrue("global_item" in manifest.unresolvedImplementationIds, "$type, rename=$rename")
                val checkpoint = Json.parseToJsonElement(project.resolve("reports/modules/core.json").readText()).jsonObject
                assertEquals("false", checkpoint.getValue("accepted").jsonPrimitive.content)
                assertTrue(checkpoint.getValue("issues").jsonArray.any { issue ->
                    val row = issue.jsonObject
                    row.getValue("code").jsonPrimitive.content == "unsupported-preprocessor-attribution" &&
                        row.getValue("entityIds").jsonArray.map { it.jsonPrimitive.content } == listOf("global_item")
                }, checkpoint.toString())
                // A compiler/linker success alone cannot prove ownership of an unused global.
                assertEquals(0, MakeProjectBuilder.build(project).returnCode, "$type, rename=$rename")
            }
        }
    }

    @Test
    fun `unconditional generated definitions with referenced globals remain accepted and link`() {
        for ((type, body) in listOf("int" to "return item + 17;", "int (* const)(int)" to "return item == 0 ? 17 : 18;")) {
            val project = project()
            val main = main().copy(decompiledC = "int main(void) { $body }", referencedGlobals = setOf("global_item"))
            val manifest = SourceTreeGenerator.generate(model(global(type), functions = listOf(main)), project,
                overrides = OWNERS, reconstructor = RecoveredCModuleReconstructor())
            assertTrue(manifest.unresolvedImplementationIds.isEmpty(), "$type: ${manifest.unresolvedImplementationIds}")
            assertEquals(0, MakeProjectBuilder.build(project).returnCode, type)
        }
    }

    private fun assertUnsupported(model: RecoveredProgramModel, source: String, id: String) {
        val issues = assess(model, source)
        assertTrue(issues.any { it.code == "unsupported-preprocessor-attribution" && it.entityIds == listOf(id) }, "$source: $issues")
    }

    private fun assess(model: RecoveredProgramModel, source: String): List<ModuleReconstructionIssue> {
        val owners = (model.functions.map { it.id } + model.globals.map { it.id }).associateWith { "core" }
        val module = DeterministicModulePlanner().plan(model, owners).modules.single()
        return GeneratedCCandidateValidation.assess(module, model, "scripted-agent", source)
    }

    private fun main() = RecoveredFunction("fn_main", "main", 100UL, "int main(void)", "int main(void) { return 17; }")
    private fun global(type: String) = RecoveredGlobal("global_item", "item", 300UL, type)
    private fun model(vararg globals: RecoveredGlobal, functions: List<RecoveredFunction> = emptyList()) =
        RecoveredProgramModel(inputSha256 = "preprocessor-attribution", functions = functions, globals = globals.toList())
    private fun project(): Path = Files.createTempDirectory(Path.of("build", "generated-c-preprocessor-tests").createDirectories(), "project-")

    private companion object {
        val OWNERS = mapOf("global_item" to "core", "fn_main" to "core")
    }
}
