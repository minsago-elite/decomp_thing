package decompengine.project

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GeneratedCDeclarationsTest {
    @Test
    fun `prototype retains return parameters qualifiers and variadic declarators`() {
        for (prototype in listOf(
            "unsigned long convert(unsigned short count, const char *restrict text)",
            "const char *convert(int byte, volatile unsigned long *undefined, ...)",
            "struct result convert(int (*callback)(int left, int right), const int values[static 4])",
            "int (*convert(int count))(const char *text)",
            "named_result (convert)(named_argument value)",
        )) {
            assertEquals(prototype, normalizedPrototype(function("convert", prototype)))
        }
    }

    @Test
    fun `recovered body return type cannot override prototype and main is never specialized`() {
        assertEquals("long main(void)", normalizedPrototype(function("main", "long main(void)", "int main(int argc, char **argv) { return 0; }")))
        assertEquals("named_result convert(int count)", normalizedPrototype(function("convert", "named_result convert(int count)", "void convert(void) {}")))
    }

    @Test
    fun `safe name changes only the function identifier including names repeated in types and comments`() {
        val prototype = "struct __state * /* __state */ __state(struct __state *value, int (*callback)(struct __state *))"
        val expected = "struct __state * /* __state */ recovered___state(struct __state *value, int (*callback)(struct __state *))"
        assertEquals(expected, normalizedPrototype(function("__state", prototype)))
        assertEquals("int odd_name(int value)", normalizedPrototype(function("odd.name", "int odd.name(int value)")))
    }

    @Test
    fun `empty parameter lists are retained as unspecified and only explicit void permits an entry call`() {
        assertEquals("int entry()", normalizedPrototype(function("entry", "int entry()")))
        assertFalse(recoveredDeclaration(function("entry", "int entry()")).explicitNoParameters)
        assertTrue(recoveredDeclaration(function("entry", "int entry(/* no arguments */ void)")).explicitNoParameters)
        for (prototype in listOf("int entry()", "int entry(int value)", "int entry(int count, ...)", "static int entry(void)")) {
            val model = model(function("entry", prototype))
            val failure = assertFailsWith<IllegalArgumentException>(prototype) {
                GeneratedCProjectRendering(model, DeterministicModulePlanner().plan(model)).entrypoint()
            }
            assertTrue(failure.message.orEmpty().contains("fn_entry"), failure.message)
        }
        for ((prototype, expectedCall) in listOf("extern int entry(void)" to "return entry();", "void entry(void)" to "entry();\n    return 0;")) {
            val model = model(function("entry", prototype))
            val entry = requireNotNull(GeneratedCProjectRendering(model, DeterministicModulePlanner().plan(model)).entrypoint())
            assertTrue(entry.source.contains(expectedCall), entry.source)
            assertFalse(entry.source.contains("extern extern"), entry.source)
        }
    }

    @Test
    fun `trailing line comments cannot swallow rendered declarations or placeholder bodies`() {
        for (prototype in listOf("int main(void); // retained", "int main(void) // retained")) {
            val project = project()
            val model = model(function("main", prototype))
            SourceTreeGenerator.generate(model, project, reconstructor = EvidenceModuleReconstructor())
            assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        }
        assertEquals("extern int item // retained\n;", globalDeclaration(global("int // retained"), true))
    }

    @Test
    fun `malformed mismatched and excessively nested prototypes fail against their entity`() {
        for (prototype in listOf("", "convert(int value)", "int different(void)", "int convert(int,)", "int convert(void, int value)",
            "int convert(int value;)", "int convert(int value", "int convert(int value]", "int convert(void); int other(void)",
            "int convert(void) /* unclosed", "int (*convert)(void)", "typedef int convert(void)",
            "int " + "(".repeat(70) + "convert" + ")".repeat(70) + "(void)")) {
            val failure = assertFailsWith<IllegalArgumentException>(prototype) { normalizedPrototype(function("convert", prototype)) }
            assertTrue(failure.message.orEmpty().contains("fn_convert"), failure.message)
        }
    }

    @Test
    fun `global abstract declarators preserve named types arrays and qualified function pointers`() {
        assertEquals("extern undefined8 item;", globalDeclaration(global("undefined8"), true))
        assertEquals("extern const unsigned long item[3][4];", globalDeclaration(global("const unsigned long[3][4]"), true))
        assertEquals("extern int (* const item)(int value, const char *text);", globalDeclaration(global("int (* const)(int value, const char *text)"), true))
        assertEquals("extern const struct result * item;", globalDeclaration(global("const struct result *"), true))
        assertEquals("int item = {0};", globalDeclaration(global("int"), false))
        assertEquals("int item = 7 /* retained value */;", globalDeclaration(global("int").copy(initializer = "7 /* retained value */"), false))
        assertEquals("int item = 7 // retained value\n;", globalDeclaration(global("int").copy(initializer = "7 // retained value"), false))
        assertEquals("int item = unknown_value;", globalDeclaration(global("int").copy(initializer = "unknown_value"), false))
        assertEquals("const char item[8] = \"a b\";", globalDeclaration(global("const char[8]").copy(initializer = "\"a b\""), false))
        for (type in listOf("", "int named", "int(int)", "struct { int x; }")) {
            assertTrue(assertFailsWith<IllegalArgumentException> { globalDeclaration(global(type), true) }.message.orEmpty().contains("global_item"))
        }
    }

    @Test
    fun `missing global array extent cannot be manufactured by zero initialization`() {
        val failure = assertFailsWith<IllegalArgumentException> { globalDeclaration(global("int[]"), false) }
        assertTrue(failure.message.orEmpty().contains("global_item"), failure.message)
        assertTrue(failure.message.orEmpty().contains("extent"), failure.message)
        assertEquals("extern int item[];", globalDeclaration(global("int[]"), true))
        assertEquals("int item[] = {1, 2};", globalDeclaration(global("int[]").copy(initializer = "{1, 2}"), false))
        assertEquals("int (* item)[] = {0};", globalDeclaration(global("int (*)[]"), false))
    }

    @Test
    fun `parameter bookkeeping respects nested declarators and never executes volatile reads`() {
        val recovered = "int (*factory(volatile int unused, int (*callback)(int left, int right), int values[3]))(int) { return 0; }"
        val marked = markRecoveredParametersUsed(recovered, function("factory", "int (*factory(volatile int unused, int (*callback)(int left, int right), int values[3]))(int)", recovered))
        assertTrue(marked.contains("if (0) {\n        (void)unused;\n        (void)callback;\n        (void)values;\n    }"), marked)
        assertFalse(marked.contains("(void)left"), marked)
        assertFalse(marked.contains("(void)right"), marked)
        assertTrue(marked.endsWith("return 0; }"), marked)
    }

    @Test
    fun `cross module parameterized calls build under the strict profile`() {
        val project = project()
        val model = model(
            function("parse_sum", "long parse_sum(int byte, const unsigned long *undefined, int (*transform)(int), const int values[static 2])",
                "long parse_sum(int byte, const unsigned long *undefined, int (*transform)(int), const int values[static 2]) { return byte + *undefined + transform(values[0]) + values[1]; }"),
            function("transform_value", "int transform_value(int value)", "int transform_value(int value) { return value * 2; }"),
            function("factory", "int (*factory(int unused))(int)", "int (*factory(int unused))(int) { return 0; }"),
            function("main", "int main(void)", "int main(void) { const unsigned long scale = 5; const int values[2] = {3, 4}; return parse_sum(2, &scale, transform_value, values) == 17 && factory(1) == 0 ? 0 : 1; }")
                .copy(calls = setOf("fn_parse_sum", "fn_transform_value", "fn_factory")),
        )
        val before = model.toJson()
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor())
        assertTrue(manifest.unresolvedImplementationIds.isEmpty(), manifest.unresolvedImplementationIds.toString())
        assertEquals(before, model.toJson())
        val modules = Json.parseToJsonElement(project.resolve("reports/module_plan.json").readText()).jsonObject.getValue("modules").jsonArray
        assertTrue(modules.size > 1)
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        assertEquals(0, ProcessBuilder(project.resolve("build/reconstructed").toAbsolutePath().toString()).start().waitFor())
    }

    @Test
    fun `unknown signature and global types fail the actual compiler and remain unresolved`() {
        for (unknown in listOf("undefined8", "byte", "pointer")) {
            val project = project()
            val model = model(function("main", "int main(void)", "int main(void) { return 0; }"),
                function("convert", "$unknown convert($unknown value)", "$unknown convert($unknown value) { return value; }"))
                .copy(globals = listOf(global(unknown)))
            val manifest = SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor())
            assertTrue("fn_convert" in manifest.unresolvedImplementationIds, unknown)
            assertTrue("global_item" in manifest.unresolvedImplementationIds, unknown)
            val diagnostics = Files.walk(project.resolve("reports/modules")).use { paths ->
                paths.filter { it.toString().endsWith(".json") }.toList().joinToString("\n") { it.readText() }
            }
            assertTrue(diagnostics.contains("module-compilation-failed"), diagnostics)
            assertTrue(project.resolve("UNRESOLVED.md").readText().contains("fn_convert"))
            assertFailsWith<BuildException> { MakeProjectBuilder.build(project) }
            val buildDiagnostics = Files.walk(project.resolve("reports/build/modules")).use { paths ->
                paths.filter { it.toString().endsWith(".log") }.toList().joinToString("\n") { it.readText() }
            }
            assertTrue(buildDiagnostics.contains(unknown), buildDiagnostics)
        }
    }

    @Test
    fun `explicit named typedefs and placeholder-like parameter identifiers remain valid`() {
        val project = project()
        val model = model(
            function("convert", "undefined8 convert(byte undefined, pointer value)", "undefined8 convert(byte undefined, pointer value) { return undefined + (value != 0); }"),
            function("main", "int main(void)", "int main(void) { return convert(0, 0); }").copy(calls = setOf("fn_convert")),
        ).copy(types = listOf(RecoveredType("named_types", "typedef unsigned long undefined8;\ntypedef unsigned char byte;\ntypedef void *pointer;")),
            globals = listOf(global("undefined8")))
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor())
        assertTrue(manifest.unresolvedImplementationIds.isEmpty(), manifest.unresolvedImplementationIds.toString())
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
    }

    @Test
    fun `evidence placeholders preserve qualified variadic array and aggregate signatures but remain unresolved`() {
        val project = project()
        val model = model(
            function("main", "int main(void)"),
            function("convert", "struct result convert(volatile int byte, const int values[static 2], int (*callback)(int, int), ...)"),
            function("factory", "int (*factory(int unused))(int)"),
            function("clear", "extern void clear(int byte)"),
            function("lookup", "const char *lookup(unsigned long key)"),
        ).copy(types = listOf(RecoveredType("result_type", "struct result { int value; };")))
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = EvidenceModuleReconstructor())
        assertEquals(model.functions.map { it.id }.sorted(), manifest.unresolvedImplementationIds.sorted())
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        val diagnostics = Files.walk(project.resolve("reports/modules")).use { paths ->
            paths.filter { it.toString().endsWith(".json") }.toList().joinToString("\n") { it.readText() }
        }
        assertTrue(diagnostics.contains("evidence-only-placeholder"), diagnostics)
    }

    @Test
    fun `agent copies of typed evidence placeholders cannot become accepted implementations`() {
        for ((prototype, recovered) in listOf(
            "int convert(int value)" to "int convert(int value) { return value + 1; }",
            "const char *convert(int value)" to "const char *convert(int value) { return value ? \"yes\" : \"no\"; }",
            "struct result convert(int value)" to "struct result convert(int value) { struct result result = {value}; return result; }",
        )) {
            val project = project()
            val model = model(function("convert", prototype, recovered), function("main", "int main(void)", "int main(void) { return 0; }"))
                .copy(types = listOf(RecoveredType("result_type", "struct result { int value; };")))
            val manifest = SourceTreeGenerator.generate(model, project, reconstructor = ModuleReconstructor { request ->
                EvidenceModuleReconstructor().reconstruct(request).copy(generator = "scripted-agent", issues = emptyList())
            })
            assertTrue("fn_convert" in manifest.unresolvedImplementationIds, prototype)
            val reports = Files.walk(project.resolve("reports/modules")).use { paths ->
                paths.filter { it.toString().endsWith(".json") }.toList().map { it.readText() }
            }
            assertTrue(reports.any { it.contains("generic-return-placeholder") }, prototype)
            assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        }
    }

    @Test
    fun `retained complex global definitions are recognized and compile`() {
        for (type in listOf("int (* const)(int)", "int (**)(int)", "int (*[2])(int)")) {
            val project = project()
            val model = model(function("main", "int main(void)", "int main(void) { return 0; }"))
                .copy(globals = listOf(global(type)))
            val manifest = SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor())
            assertTrue(manifest.unresolvedImplementationIds.isEmpty(), "$type: ${manifest.unresolvedImplementationIds}")
            assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        }
    }

    @Test
    fun `typedefs and references never satisfy global definition attribution`() {
        val model = model(function("main", "int main(void)", "int main(void) { return 0; }"))
            .copy(globals = listOf(global("int (* const)(int)")))
        val module = DeterministicModulePlanner().plan(model).modules.single { "global_item" in it.globalIds }
        for (declaration in listOf(
            "typedef int item;",
            "typedef int (*item)(int);",
            "typedef int (* const item)(int);",
            "typedef int (**item)(int);",
            "extern int (* const item)(int);",
            "int main(void) { int (* const item)(int) = 0; return item != 0; }",
        )) {
            val source = "/* global_item fn_main */\n$declaration"
            assertFalse(generatedCGlobalDefinition(source, "item"), declaration)
            val issues = GeneratedCCandidateValidation.assess(module, model, "scripted-agent", source)
            assertTrue(issues.any { it.code == "missing-global-definition" && it.entityIds == listOf("global_item") }, "$declaration: $issues")
        }
    }

    @Test
    fun `recovered definition conflicting with declared return type fails rather than changing header`() {
        val project = project()
        val model = model(function("main", "int main(void)", "int main(void) { return 0; }"),
            function("convert", "long convert(int value)", "void convert(int value) {}"))
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor())
        assertTrue("fn_convert" in manifest.unresolvedImplementationIds)
        assertTrue(Files.walk(project.resolve("src")).use { files ->
            files.filter { it.fileName.toString().endsWith("_internal.h") }.toList().any { it.readText().contains("long convert(int value)") }
        })
    }

    private fun function(name: String, prototype: String, recovered: String? = null) =
        RecoveredFunction("fn_$name", name, if (name == "main") 100UL else 200UL, prototype, recovered)
    private fun global(type: String) = RecoveredGlobal("global_item", "item", 300UL, type)
    private fun model(vararg functions: RecoveredFunction) = RecoveredProgramModel(inputSha256 = "strict-declarations", functions = functions.toList())
    private fun project(): Path = Files.createTempDirectory(Path.of("build", "generated-c-declaration-tests").createDirectories(), "project-")
}
