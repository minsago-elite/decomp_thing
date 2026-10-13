package decompengine.project

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GeneratedCAtomicDeclarationsTest {
    @Test
    fun `atomic specifiers and qualifiers retain their exact declaration spelling`() {
        for (prototype in listOf(
            "int read(_Atomic(int) value)",
            "int read(_Atomic /* retained */ ( const int * ) value)",
            "int read(_Atomic(_Atomic(int) *) value)",
            "int read(_Atomic(int (*)(int)) callback)",
            "int read(_Atomic int value)",
            "int read(int * _Atomic value)",
            "_Atomic(int) *read(_Atomic(int) *value)",
        )) {
            assertEquals(prototype, normalizedPrototype(function("read", prototype)))
        }
        assertEquals("extern _Atomic(int) item;", globalDeclaration(global("_Atomic(int)"), true))
        assertEquals("_Atomic /* retained */ (int *) item = 0;",
            globalDeclaration(global("_Atomic /* retained */ (int *)").copy(initializer = "0"), false))
        assertEquals("_Atomic int item = 17;", globalDeclaration(global("_Atomic int").copy(initializer = "17"), false))
        assertEquals("int * _Atomic item = 0;", globalDeclaration(global("int * _Atomic").copy(initializer = "0"), false))
    }

    @Test
    fun `atomic typedefs retain integer shapes without treating atomic void as a void parameter list`() {
        val context = GeneratedCDeclarationContext(listOf(RecoveredType("atomic_types",
            "typedef _Atomic(int) AtomicInt; typedef AtomicInt AtomicAlias; " +
                "typedef void Void; typedef _Atomic(Void) AtomicVoid; typedef _Atomic Void QualifiedAtomicVoid; " +
                "typedef _Atomic(void *) AtomicPointer;")))
        for (type in listOf("_Atomic(int)", "AtomicInt", "AtomicAlias", "_Atomic int")) {
            assertEquals("return entry();", recoveredDeclaration(function("entry", "$type entry(void)"), context).entryCall("entry"))
        }
        for (type in listOf("_Atomic(void)", "_Atomic(Void)", "AtomicVoid", "_Atomic void", "_Atomic Void", "QualifiedAtomicVoid")) {
            assertFalse(recoveredDeclaration(function("read", "int read($type)"), context).explicitNoParameters, type)
            assertFailsWith<IllegalArgumentException>(type) {
                recoveredDeclaration(function("entry", "$type entry(void)"), context).entryCall("entry")
            }
        }
        assertFailsWith<IllegalArgumentException> {
            recoveredDeclaration(function("entry", "AtomicPointer entry(void)"), context).entryCall("entry")
        }
    }

    @Test
    fun `atomic void qualifiers never change the cached unqualified alias shape`() {
        for (warm in listOf(false, true)) {
            val context = GeneratedCDeclarationContext(listOf(RecoveredType("void_types",
                "typedef void Void; typedef _Atomic Void QualifiedAtomicVoid;")))
            if (warm) assertTrue(recoveredDeclaration(function("read", "int read(Void)"), context).explicitNoParameters)
            for (type in listOf("_Atomic Void", "QualifiedAtomicVoid")) {
                assertFalse(recoveredDeclaration(function("read", "int read($type)"), context).explicitNoParameters, "$type warm=$warm")
                assertTrue(recoveredDeclaration(function("read", "int read(Void)"), context).explicitNoParameters, "$type warm=$warm")
                assertEquals("entry();\n    return 0;",
                    recoveredDeclaration(function("entry", "Void entry(void)"), context).entryCall("entry"))
            }
        }
    }

    @Test
    fun `atomic aliases cannot hide an unsized array extent`() {
        val context = GeneratedCDeclarationContext(listOf(RecoveredType("atomic_arrays",
            "typedef int Values[]; typedef _Atomic(Values) AtomicValues; typedef AtomicValues AtomicAlias;")))
        for (type in listOf("_Atomic(Values)", "AtomicValues", "AtomicAlias")) {
            val failure = assertFailsWith<IllegalArgumentException>(type) { globalDeclaration(global(type), false, context) }
            assertTrue(failure.message.orEmpty().contains("global_item"), failure.message)
            assertTrue(failure.message.orEmpty().contains("extent"), failure.message)
            assertEquals("extern $type item;", globalDeclaration(global(type), true, context))
            // Invalid atomic array targets retain their spelling for the compiler when evidence supplies an initializer.
            assertEquals("$type item = {1, 2};", globalDeclaration(global(type).copy(initializer = "{1, 2}"), false, context))
        }
        assertEquals("_Atomic(Values *) item = 0;",
            globalDeclaration(global("_Atomic(Values *)").copy(initializer = "0"), false, context))
    }

    @Test
    fun `atomic type names reject named storage malformed and excessive nested declarations`() {
        for (type in listOf("_Atomic()", "_Atomic(int named)", "_Atomic(static int)", "_Atomic(int;)",
            "_Atomic(int", "_Atomic(int])", "_Atomic(".repeat(65) + "int" + ")".repeat(65))) {
            val failure = assertFailsWith<IllegalArgumentException>(type) {
                normalizedPrototype(function("read", "int read($type value)"))
            }
            assertTrue(failure.message.orEmpty().contains("fn_read"), failure.message)
        }
    }

    @Test
    fun `atomic wrappers share the alias resolution depth budget even with cached aliases`() {
        val types = listOf(RecoveredType("atomic_chain", "typedef int Alias0;\n" +
            (1..32).joinToString("\n") { "typedef _Atomic(Alias${it - 1}) Alias$it;" }))
        for (warm in listOf(false, true)) {
            val context = GeneratedCDeclarationContext(types)
            if (warm) recoveredDeclaration(function("warm", "Alias31 warm(void)"), context)
            val failure = assertFailsWith<IllegalArgumentException>("warm=$warm") {
                recoveredDeclaration(function("entry", "Alias32 entry(void)"), context)
            }
            assertTrue(failure.message.orEmpty().contains("fn_entry"), failure.message)
            assertTrue(failure.message.orEmpty().contains("depth 64"), failure.message)
        }
        val cyclic = GeneratedCDeclarationContext(listOf(RecoveredType("atomic_cycle",
            "typedef _Atomic(Second) First; typedef First Second;")))
        val failure = assertFailsWith<IllegalArgumentException> {
            recoveredDeclaration(function("entry", "First entry(void)"), cyclic)
        }
        assertTrue(failure.message.orEmpty().contains("cyclic"), failure.message)
    }

    @Test
    fun `retained atomic parameters globals typedefs and nested pointers build and execute`() {
        val functions = listOf(
            function("read_atomic", "int read_atomic(_Atomic(int) value)", "int read_atomic(_Atomic(int) value) { return value; }"),
            function("read_alias", "int read_alias(AtomicInt value)", "int read_alias(AtomicInt value) { return value; }"),
            function("identity", "_Atomic(int) *identity(_Atomic(int) *value)", "_Atomic(int) *identity(_Atomic(int) *value) { return value; }"),
            function("read_pointer", "int *read_pointer(_Atomic(int *) value)", "int *read_pointer(_Atomic(int *) value) { return value; }"),
            function("read_nested", "int read_nested(_Atomic(_Atomic(int) *) value)", "int read_nested(_Atomic(_Atomic(int) *) value) { return *value; }"),
            function("read_qualified", "int read_qualified(_Atomic int value)", "int read_qualified(_Atomic int value) { return value; }"),
            function("read_pointer_qualified", "int *read_pointer_qualified(int * _Atomic value)", "int *read_pointer_qualified(int * _Atomic value) { return value; }"),
        )
        val globals = listOf(
            RecoveredGlobal("global_plain", "plain", 300UL, "int", initializer = "3"),
            RecoveredGlobal("global_count", "count", 304UL, "_Atomic(int)", initializer = "7"),
            RecoveredGlobal("global_alias_count", "alias_count", 308UL, "AtomicInt", initializer = "5"),
            RecoveredGlobal("global_pointer", "pointer", 312UL, "AtomicPointer", initializer = "&plain"),
            RecoveredGlobal("global_nested", "nested", 316UL, "_Atomic(_Atomic(int) *)", initializer = "&count"),
            RecoveredGlobal("global_array_pointer", "array_pointer", 320UL, "_Atomic(Values *)", initializer = "0"),
            RecoveredGlobal("global_qualified", "qualified", 324UL, "_Atomic int", initializer = "2"),
        )
        val main = function("main", "int main(void)", "int main(void) { " +
            "return read_atomic(count) + read_alias(alias_count) + read_nested(nested) + *identity(&count) + " +
            "*read_pointer(pointer) + read_qualified(qualified) + *read_pointer_qualified(pointer) == 34 ? 0 : 1; }")
            .copy(calls = functions.map { it.id }.toSet(), referencedGlobals = globals.map { it.id }.toSet())
        val types = "typedef _Atomic(int) AtomicInt; typedef _Atomic(int *) AtomicPointer; typedef int Values[];"
        val model = model(*(functions + main).toTypedArray()).copy(types = listOf(RecoveredType("atomic_types", types)), globals = globals)
        val before = model.toJson()
        val project = project()
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor())
        assertTrue(manifest.unresolvedImplementationIds.isEmpty(), manifest.unresolvedImplementationIds.toString())
        assertEquals(before, model.toJson())
        assertTrue(project.resolve("include/decomp_types.h").readText().contains(types))
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        assertEquals(0, ProcessBuilder(project.resolve("build/reconstructed").toAbsolutePath().toString()).start().waitFor())
    }

    @Test
    fun `atomic parameter and pointer result placeholders remain unresolved through the compiler gate`() {
        val atomic = function("read", "_Atomic(int) *read(_Atomic(int) *value, AtomicInt offset)",
            "_Atomic(int) *read(_Atomic(int) *value, AtomicInt offset) { return value + offset; }")
        val model = model(atomic, function("main", "int main(void)", "int main(void) { return 0; }"))
            .copy(types = listOf(RecoveredType("atomic_type", "typedef _Atomic(int) AtomicInt;")))
        val project = project()
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = ModuleReconstructor { request ->
            val evidence = EvidenceModuleReconstructor().reconstruct(request)
            evidence.copy(source = evidence.source.replace("decomp_placeholder_result", "renamed_atomic_result"),
                generator = "scripted-agent", issues = emptyList())
        })
        assertTrue("fn_read" in manifest.unresolvedImplementationIds)
        val reports = Files.walk(project.resolve("reports/modules")).use { paths ->
            paths.filter { it.toString().endsWith(".json") }.toList().map { it.readText() }
        }
        assertTrue(reports.any { it.contains("generic-return-placeholder") && it.contains("fn_read") }, reports.toString())
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
    }

    @Test
    fun `invalid atomic target types reach the compiler without rewriting the retained spelling`() {
        val project = project()
        val model = model(function("main", "int main(void)", "int main(void) { return 0; }"))
            .copy(globals = listOf(global("_Atomic(void)").copy(initializer = "0")))
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = RecoveredCModuleReconstructor())
        assertTrue("global_item" in manifest.unresolvedImplementationIds)
        assertTrue(Files.walk(project.resolve("src")).use { paths ->
            paths.filter { it.toString().endsWith(".c") }.toList().any { it.readText().contains("_Atomic(void) item = 0;") }
        })
        assertFailsWith<BuildException> { MakeProjectBuilder.build(project) }
    }

    private fun function(name: String, prototype: String, recovered: String? = null) =
        RecoveredFunction("fn_$name", name, if (name == "main") 100UL else 200UL, prototype, recovered)
    private fun global(type: String) = RecoveredGlobal("global_item", "item", 300UL, type)
    private fun model(vararg functions: RecoveredFunction) = RecoveredProgramModel(inputSha256 = "atomic-declarations", functions = functions.toList())
    private fun project(): Path = Files.createTempDirectory(Path.of("build", "generated-c-atomic-tests").createDirectories(), "project-")
}
