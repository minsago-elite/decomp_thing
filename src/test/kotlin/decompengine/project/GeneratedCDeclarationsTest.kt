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

    @Test
    fun `noreturn evidence placeholders are rejected with their function identity`() {
        for (prototype in listOf("_Noreturn void stop(void)", "_Noreturn Void stop(int value)")) {
            val model = model(function("stop", prototype), function("main", "int main(void)"))
                .copy(types = listOf(RecoveredType("void_type", "typedef void Void;")))
            val failure = assertFailsWith<IllegalArgumentException>(prototype) {
                SourceTreeGenerator.generate(model, project(), reconstructor = EvidenceModuleReconstructor())
            }
            assertTrue(failure.message.orEmpty().contains("fn_stop"), failure.message)
            assertTrue(failure.message.orEmpty().contains("_Noreturn"), failure.message)
        }
    }

    @Test
    fun `genuine noreturn implementation compiles with the compiler library declaration`() {
        val project = project()
        val prototype = "_Noreturn Void stop(void)"
        val model = model(
            function("stop", prototype, "$prototype { abort(); }"),
            function("main", "int main(void)", "int main(void) { return 0; }"),
        ).copy(types = listOf(RecoveredType("void_type", "typedef void Void;")))
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = ModuleReconstructor { request ->
            val recovered = RecoveredCModuleReconstructor().reconstruct(request)
            recovered.copy(source = "#include <stdlib.h>\n" + recovered.source)
        })
        assertTrue(manifest.unresolvedImplementationIds.isEmpty(), manifest.unresolvedImplementationIds.toString())
        assertTrue(sourceFiles(project).any {
            it.contains("$prototype {") && Regex("\\{\\s*abort\\(\\);\\s*}").containsMatchIn(it)
        })
        assertFalse(sourceFiles(project).any { Regex("\\bvoid\\s+abort\\s*\\(").containsMatchIn(it) })
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
    }

    @Test
    fun `entrypoint rejects nonstatus return types before creating artifacts`() {
        val declarations = "typedef int *Pointer; typedef int (*Callback)(void); " +
            "typedef struct { int value; } Result; typedef double Real; typedef Unavailable Unknown;"
        for (prototype in listOf(
            "int *entry(void)", "int (*entry(void))(int)", "struct result entry(void)",
            "double entry(void)", "Unavailable entry(void)", "Pointer entry(void)",
            "Callback entry(void)", "Result entry(void)", "Real entry(void)", "Unknown entry(void)",
        )) {
            val project = project()
            val model = model(function("entry", prototype)).copy(types = listOf(
                RecoveredType("entry_types", "struct result { int value; }; $declarations"),
            ))
            val failure = assertFailsWith<IllegalArgumentException>(prototype) {
                SourceTreeGenerator.generate(model, project, reconstructor = EvidenceModuleReconstructor())
            }
            assertTrue(failure.message.orEmpty().contains("fn_entry"), failure.message)
            assertTrue(Files.list(project).use { !it.findAny().isPresent }, "generation wrote artifacts for $prototype")
        }
    }

    @Test
    fun `known integer entry return types retain the program exit status`() {
        for (returnType in listOf("int", "unsigned long", "size_t", "Status")) {
            val project = project()
            val prototype = "$returnType entry(void)"
            val model = model(function("entry", prototype, "$prototype { return 17; }"))
                .copy(types = listOf(RecoveredType("status_type", "typedef unsigned int ExitCode; typedef ExitCode Status;")))
            val manifest = SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor())
            assertTrue(manifest.unresolvedImplementationIds.isEmpty(), "$returnType: ${manifest.unresolvedImplementationIds}")
            assertEquals(0, MakeProjectBuilder.build(project).returnCode)
            assertEquals(17, ProcessBuilder(project.resolve("build/reconstructed").toAbsolutePath().toString()).start().waitFor(), returnType)
        }
    }

    @Test
    fun `void typedef chains preserve named declarations for parameters and returns`() {
        val project = project()
        val model = model(
            function("clear", "VoidAlias clear(int value)"),
            function("main", "int main(VoidAlias)"),
        ).copy(types = listOf(RecoveredType("void_types", "typedef void Void; typedef Void VoidAlias;")))
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = EvidenceModuleReconstructor())
        assertEquals(setOf("fn_clear", "fn_main"), manifest.unresolvedImplementationIds.toSet())
        val sources = sourceFiles(project)
        assertTrue(sources.any { it.contains("VoidAlias clear(int value)") })
        assertTrue(sources.any { it.contains("int main(VoidAlias)") })
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
    }

    @Test
    fun `sole void typedef parameter admits an entry call without rewriting its prototype`() {
        val project = project()
        val prototype = "int entry(Void)"
        val model = model(function("entry", prototype, "$prototype { return 17; }"))
            .copy(types = listOf(RecoveredType("void_type", "typedef void Void;")))
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor())
        assertTrue(manifest.unresolvedImplementationIds.isEmpty(), manifest.unresolvedImplementationIds.toString())
        val sources = sourceFiles(project)
        assertTrue(sources.any { it.contains("$prototype;") }, sources.toString())
        assertTrue(sources.any { it.contains("$prototype {") }, sources.toString())
        assertFalse(sources.any { it.contains("int entry(void)") }, sources.toString())
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        assertEquals(17, ProcessBuilder(project.resolve("build/reconstructed").toAbsolutePath().toString()).start().waitFor())
    }

    @Test
    fun `cross module static and inline callees fail with the callee identity`() {
        for (qualifier in listOf("static", "inline", "static inline", "extern inline")) {
            val model = model(
                function("helper", "$qualifier int helper(int value)", "$qualifier int helper(int value) { return value + 1; }"),
                function("main", "int main(void)", "int main(void) { return helper(16); }").copy(calls = setOf("fn_helper")),
            )
            val failure = assertFailsWith<IllegalArgumentException>(qualifier) {
                SourceTreeGenerator.generate(model, project(), reconstructor = RecoveredCModuleReconstructor(),
                    overrides = mapOf("fn_helper" to "helper", "fn_main" to "entry"))
            }
            assertTrue(failure.message.orEmpty().contains("fn_helper"), failure.message)
        }
    }

    @Test
    fun `plain inline definitions reject before reconstruction even when callers share their module`() {
        for (called in listOf(true, false)) {
            val project = project()
            val prototype = "inline int helper(int value)"
            val model = model(
                function("helper", prototype, "$prototype { return value + 3; }"),
                function("main", "int main(void)", if (called) "int main(void) { return helper(14); }" else "int main(void) { return 0; }")
                    .copy(calls = if (called) setOf("fn_helper") else emptySet()),
            )
            var reconstructions = 0
            val failure = assertFailsWith<IllegalArgumentException>("called=$called") {
                SourceTreeGenerator.generate(model, project, reconstructor = ModuleReconstructor { request ->
                    reconstructions++
                    RecoveredCModuleReconstructor().reconstruct(request)
                }, overrides = mapOf("fn_helper" to "core", "fn_main" to "core"))
            }
            assertTrue(failure.message.orEmpty().contains("fn_helper"), failure.message)
            assertTrue(failure.message.orEmpty().contains("external inline"), failure.message)
            assertEquals(0, reconstructions)
            assertTrue(Files.list(project).use { !it.findAny().isPresent }, "unsupported inline generated artifacts")
        }
    }

    @Test
    fun `private static inline implementation remains valid within its planned module`() {
        val project = project()
        val prototype = "static inline int helper(int value)"
        val model = model(
            function("helper", prototype, "$prototype { return value + 3; }"),
            function("main", "int main(void)", "int main(void) { return helper(14); }").copy(calls = setOf("fn_helper")),
        )
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor(),
            overrides = mapOf("fn_helper" to "core", "fn_main" to "core"))
        assertTrue(manifest.unresolvedImplementationIds.isEmpty(), manifest.unresolvedImplementationIds.toString())
        assertTrue(sourceFiles(project).any { it.contains("$prototype {") })
        assertTrue(project.resolve("src/modules/core_internal.h").readText().contains("$prototype;"))
        assertFalse(project.resolve("include/modules/core.h").readText().contains("helper("))
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        assertEquals(17, ProcessBuilder(project.resolve("build/reconstructed").toAbsolutePath().toString()).start().waitFor())
    }

    @Test
    fun `unreferenced private static functions remain buildable in evidence and recovered modes`() {
        for (includeRecovered in listOf(false, true)) {
            val project = project()
            val prototype = "static int helper(int value)"
            val model = model(
                function("helper", prototype, "$prototype { return value + 3; }"),
                function("main", "int main(void)", "int main(void) { return 17; }"),
            )
            val before = model.toJson()
            val reconstructor = if (includeRecovered) RecoveredCModuleReconstructor() else EvidenceModuleReconstructor()
            val manifest = SourceTreeGenerator.generate(model, project, reconstructor = reconstructor,
                overrides = mapOf("fn_helper" to "utility", "fn_main" to "entry"))
            if (includeRecovered) {
                assertTrue(manifest.unresolvedImplementationIds.isEmpty(), manifest.unresolvedImplementationIds.toString())
            } else {
                assertTrue("fn_helper" in manifest.unresolvedImplementationIds)
            }
            assertEquals(before, model.toJson())
            assertTrue(project.resolve("src/modules/utility_internal.h").readText().contains("__attribute__((unused))\n$prototype;"))
            assertTrue(project.resolve("src/modules/utility.c").readText().contains("$prototype {"))
            assertFalse(project.resolve("include/modules/utility.h").readText().contains("helper("))
            assertEquals(0, MakeProjectBuilder.build(project).returnCode, "includeRecovered=$includeRecovered")
        }
    }

    @Test
    fun `private static address references remain usable without recorded call edges`() {
        val project = project()
        val prototype = "static int helper(int value)"
        val model = model(
            function("helper", prototype, "$prototype { return value + 3; }"),
            function("main", "int main(void)", "int main(void) { int (*callback)(int) = helper; return callback(14); }"),
        )
        assertTrue(model.functions.all { it.calls.isEmpty() })
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor(),
            overrides = mapOf("fn_helper" to "core", "fn_main" to "core"))
        assertTrue(manifest.unresolvedImplementationIds.isEmpty(), manifest.unresolvedImplementationIds.toString())
        assertTrue(project.resolve("src/modules/core_internal.h").readText().contains("__attribute__((unused))\n$prototype;"))
        assertTrue(project.resolve("src/modules/core.c").readText().contains("$prototype {"))
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        assertEquals(17, ProcessBuilder(project.resolve("build/reconstructed").toAbsolutePath().toString()).start().waitFor())
    }

    @Test
    fun `private static unused suppression leaves warnings inside the recovered body enforced`() {
        val project = project()
        val model = model(
            function("helper", "static int helper(int value)",
                "static int helper(int value) { int ignored_local = 17; return value + 3; }"),
            function("main", "int main(void)", "int main(void) { return 0; }"),
        )
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor(),
            overrides = mapOf("fn_helper" to "utility", "fn_main" to "entry"))
        assertTrue("fn_helper" in manifest.unresolvedImplementationIds)
        val report = project.resolve("reports/modules/utility.json").readText()
        assertTrue(report.contains("module-compilation-failed"), report)
        assertFailsWith<BuildException> { MakeProjectBuilder.build(project) }
        val diagnostics = Files.walk(project.resolve("reports/build/modules")).use { paths ->
            paths.filter { it.toString().endsWith(".log") }.toList().joinToString("\n") { it.readText() }
        }
        assertTrue(diagnostics.contains("ignored_local"), diagnostics)
    }

    @Test
    fun `private extern inline implementation retains an external definition for an indirect same module call`() {
        val project = project()
        val prototype = "extern inline int helper(int value)"
        val model = model(
            function("helper", prototype, "$prototype { return value + 3; }"),
            function("main", "int main(void)", "int main(void) { int (*callback)(int) = helper; return callback(14); }")
                .copy(calls = setOf("fn_helper")),
        )
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor(),
            overrides = mapOf("fn_helper" to "core", "fn_main" to "core"))
        assertTrue(manifest.unresolvedImplementationIds.isEmpty(), manifest.unresolvedImplementationIds.toString())
        assertTrue(sourceFiles(project).any { it.contains("$prototype {") })
        assertTrue(project.resolve("src/modules/core_internal.h").readText().contains("$prototype;"))
        assertFalse(project.resolve("include/modules/core.h").readText().contains("helper("))
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        assertEquals(17, ProcessBuilder(project.resolve("build/reconstructed").toAbsolutePath().toString()).start().waitFor())
    }

    @Test
    fun `typedef hidden unsized global arrays cannot acquire an invented extent`() {
        for (type in listOf("Values", "Alias", "const Alias")) {
            val model = model(function("main", "int main(void)", "int main(void) { return 0; }"))
                .copy(types = listOf(RecoveredType("array_types", "typedef int Values[]; typedef Values Alias;")),
                    globals = listOf(global(type)))
            val failure = assertFailsWith<IllegalArgumentException>(type) {
                SourceTreeGenerator.generate(model, project(), reconstructor = RecoveredCModuleReconstructor())
            }
            assertTrue(failure.message.orEmpty().contains("global_item"), failure.message)
            assertTrue(failure.message.orEmpty().contains("extent"), failure.message)
        }
    }

    @Test
    fun `typedef arrays keep supplied initializers and permit fixed extents and pointers`() {
        val project = project()
        val model = model(function("main", "int main(void)", "int main(void) { return values[0] + values[1]; }")
            .copy(referencedGlobals = setOf("global_values")))
            .copy(types = listOf(RecoveredType("array_types", "typedef int Values[]; typedef Values *Pointer; " +
                "typedef int Fixed[2]; typedef int (*Callbacks[2])(int);")),
                globals = listOf(
                    RecoveredGlobal("global_values", "values", 300UL, "Values", initializer = "{8, 9}"),
                    RecoveredGlobal("global_pointer", "pointer", 304UL, "Pointer"),
                    RecoveredGlobal("global_pointer_array", "pointer_array", 308UL, "Values *"),
                    RecoveredGlobal("global_fixed", "fixed", 312UL, "Fixed"),
                    RecoveredGlobal("global_const_fixed", "const_fixed", 316UL, "const Fixed"),
                    RecoveredGlobal("global_callbacks", "callbacks", 320UL, "Callbacks"),
                ))
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor())
        assertTrue(manifest.unresolvedImplementationIds.isEmpty(), manifest.unresolvedImplementationIds.toString())
        assertTrue(sourceFiles(project).any { it.contains("Values values = {8, 9};") })
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        assertEquals(17, ProcessBuilder(project.resolve("build/reconstructed").toAbsolutePath().toString()).start().waitFor())
    }

    @Test
    fun `multiple typedef declarators and qualified alias chains compile unchanged`() {
        val project = project()
        val declarations = "typedef int Scalar, *Pointer, Vector[2]; " +
            "typedef Scalar Status, OtherStatus; typedef const Scalar Qualified; typedef Qualified QualifiedAlias; " +
            "typedef int Scalar; /* compatible repeated declaration */"
        val model = model(function("entry", "OtherStatus entry(void)", "OtherStatus entry(void) { return item; }")
            .copy(referencedGlobals = setOf("global_item")))
            .copy(types = listOf(RecoveredType("chained_types", declarations)), globals = listOf(
                global("QualifiedAlias").copy(initializer = "17"),
                RecoveredGlobal("global_pointer", "pointer", 304UL, "Pointer"),
                RecoveredGlobal("global_vector", "vector", 308UL, "Vector"),
            ))
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor())
        assertTrue(manifest.unresolvedImplementationIds.isEmpty(), manifest.unresolvedImplementationIds.toString())
        assertTrue(project.resolve("include/decomp_types.h").readText().contains(declarations))
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        assertEquals(17, ProcessBuilder(project.resolve("build/reconstructed").toAbsolutePath().toString()).start().waitFor())
    }

    @Test
    fun `cyclic and excessively deep typedef chains reject the affected entity`() {
        val longChain = "typedef int Alias0;\n" + (1..66).joinToString("\n") { "typedef Alias${it - 1} Alias$it;" }
        for ((declarations, alias, reason) in listOf(
            Triple("typedef Second First; typedef First Second;", "First", "cycl"),
            Triple(longChain, "Alias66", "depth"),
        )) {
            val types = listOf(RecoveredType("alias_types", declarations))
            for ((model, entityId) in listOf(
                model(function("entry", "$alias entry(void)")).copy(types = types) to "fn_entry",
                model(function("main", "int main(void)")).copy(types = types, globals = listOf(global(alias))) to "global_item",
            )) {
                val failure = assertFailsWith<IllegalArgumentException>("$entityId: $reason") {
                    SourceTreeGenerator.generate(model, project(), reconstructor = EvidenceModuleReconstructor())
                }
                assertTrue(failure.message.orEmpty().contains(entityId), failure.message)
                assertTrue(failure.message.orEmpty().contains(reason, ignoreCase = true), failure.message)
            }
        }
    }

    @Test
    fun `typedef depth bound is independent of a previously cached alias`() {
        val types = listOf(RecoveredType("aliases", "typedef int Alias0;\n" +
            (1..64).joinToString("\n") { "typedef Alias${it - 1} Alias$it;" }))
        for (warm in listOf(false, true)) {
            val context = GeneratedCDeclarationContext(types)
            if (warm) recoveredDeclaration(function("warm", "Alias63 warm(void)"), context)
            val failure = assertFailsWith<IllegalArgumentException> {
                recoveredDeclaration(function("entry", "Alias64 entry(void)"), context)
            }
            assertTrue(failure.message.orEmpty().contains("fn_entry"), failure.message)
            assertTrue(failure.message.orEmpty().contains("depth 64"), failure.message)
        }
    }

    @Test
    fun `context cache observes changed typedef inventory contents`() {
        val types = mutableListOf(RecoveredType("alias", "typedef int Value;"))
        val cache = GeneratedCDeclarationContextCache()
        assertEquals("Value item = {0};", globalDeclaration(global("Value"), false, cache.forTypes(types)))
        types[0] = RecoveredType("alias", "typedef int Value[];")
        val failure = assertFailsWith<IllegalArgumentException> {
            globalDeclaration(global("Value"), false, cache.forTypes(types))
        }
        assertTrue(failure.message.orEmpty().contains("global_item"), failure.message)
        assertTrue(failure.message.orEmpty().contains("extent"), failure.message)
    }

    @Test
    fun `agent copies of typedef void placeholders remain unresolved including parameter bookkeeping`() {
        for ((prototype, recovered) in listOf(
            "Void convert(void)" to "Void convert(void) { abort(); }",
            "VoidAlias convert(int value)" to "VoidAlias convert(int value) { if (value) abort(); }",
        )) {
            val project = project()
            val model = model(function("convert", prototype, recovered), function("main", "int main(void)", "int main(void) { return 0; }"))
                .copy(types = listOf(RecoveredType("void_types", "typedef void Void; typedef Void VoidAlias;")))
            val manifest = SourceTreeGenerator.generate(model, project, reconstructor = ModuleReconstructor { request ->
                EvidenceModuleReconstructor().reconstruct(request).copy(generator = "scripted-agent", issues = emptyList())
            })
            assertTrue("fn_convert" in manifest.unresolvedImplementationIds, prototype)
            val reports = Files.walk(project.resolve("reports/modules")).use { paths ->
                paths.filter { it.toString().endsWith(".json") }.toList().map { it.readText() }
            }
            assertTrue(reports.any { it.contains("generic-return-placeholder") && it.contains("fn_convert") }, reports.toString())
            if (prototype.contains("int value")) {
                assertTrue(sourceFiles(project).any { it.contains("if (0)") && it.contains("(void)value;") })
            }
            assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        }
    }

    private fun sourceFiles(project: Path): List<String> = Files.walk(project.resolve("src")).use { paths ->
        paths.filter { it.toString().endsWith(".c") }.toList().map { it.readText() }
    }

    private fun function(name: String, prototype: String, recovered: String? = null) =
        RecoveredFunction("fn_$name", name, if (name == "main") 100UL else 200UL, prototype, recovered)
    private fun global(type: String) = RecoveredGlobal("global_item", "item", 300UL, type)
    private fun model(vararg functions: RecoveredFunction) = RecoveredProgramModel(inputSha256 = "strict-declarations", functions = functions.toList())
    private fun project(): Path = Files.createTempDirectory(Path.of("build", "generated-c-declaration-tests").createDirectories(), "project-")
}
