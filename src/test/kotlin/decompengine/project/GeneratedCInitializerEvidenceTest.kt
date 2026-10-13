package decompengine.project

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class GeneratedCInitializerEvidenceTest {
    @Test
    fun `blank recovered initializers stay unavailable without changing canonical model bytes`() {
        for (blank in listOf("", " \t\n")) {
            for (mode in listOf("evidence", "recovered", "fallback")) {
                val global = RecoveredGlobal("global_empty", "empty", 300UL, "int", initializer = blank)
                val input = model(listOf(global))
                val before = input.toJson()
                val project = project()
                val reconstructor = when (mode) {
                    "recovered" -> RecoveredCModuleReconstructor()
                    "fallback" -> ModuleReconstructor { throw IllegalStateException("fixture failure") }
                    else -> EvidenceModuleReconstructor()
                }
                val manifest = SourceTreeGenerator.generate(input, project, reconstructor = reconstructor)
                assertEquals(before, input.toJson())
                assertTrue(global.id in manifest.unresolvedImplementationIds, mode)
                assertTrue(project.resolve("UNRESOLVED.md").readText().contains(global.id), mode)
                val reports = Files.walk(project.resolve("reports/modules")).use { paths ->
                    paths.filter { it.toString().endsWith(".json") }.toList().joinToString("\n") { it.readText() }
                }
                assertTrue(reports.contains(if (mode == "recovered") "global-initializer-unavailable" else "evidence-only-placeholder"), reports)
                assertEquals(0, MakeProjectBuilder.build(project).returnCode, mode)
            }
        }
        val context = GeneratedCDeclarationContext(listOf(RecoveredType("array", "typedef int Values[];")))
        for (type in listOf("int[]", "Values")) {
            val error = assertFailsWith<IllegalArgumentException> {
                globalDeclaration(RecoveredGlobal("global_array", "array", 300UL, type, initializer = ""), false, context)
            }
            assertTrue(error.message.orEmpty().contains("extent"), error.message)
        }
        assertEquals("char text[1] = \"\";", globalDeclaration(RecoveredGlobal("text", "text", 300UL, "char[1]", initializer = "\"\""), false))
    }

    @Test
    fun `atomic object qualifiers and typedefs select scalar zero without changing ordinary or retained initializers`() {
        val context = GeneratedCDeclarationContext(TYPES)
        for (type in ATOMIC_TYPES) {
            assertTrue(globalDeclaration(RecoveredGlobal("global_atomic", "item", 300UL, type), false, context).endsWith(" = 0;"), type)
            assertTrue(globalDeclaration(RecoveredGlobal("global_atomic", "item", 300UL, type, initializer = "{0}"), false, context)
                .endsWith(" = {0};"), type)
        }
        // The pointer qualifier belongs to the closest object, never every pointer in its type.
        for (type in listOf("int * _Atomic *", "_Atomic(int) *", "Pointer")) {
            assertTrue(globalDeclaration(RecoveredGlobal("global_pointer", "item", 300UL, type), false, context).endsWith(" = {0};"), type)
        }
        assertTrue(globalDeclaration(RecoveredGlobal("array", "array", 300UL, "_Atomic(int)[2]"), false, context).endsWith(" = {0};"))
        val ordinary = RecoveredGlobal("ordinary", "ordinary", 300UL, "int")
        assertEquals("int ordinary = {0};", globalDeclaration(ordinary, false, context))
        val atomicFunction = RecoveredFunction("fn_atomic", "atomic_result", 200UL, "AtomicInt atomic_result(void)")
        assertTrue(recoveredDeclaration(atomicFunction, context).placeholderBody().contains(" = 0;"))
        assertTrue(isGeneratedCPlaceholderBody(atomicFunction, "AtomicInt chosen = {0,}; return chosen;", context))
    }

    @Test
    fun `atomic missing-value evidence builds with GCC`() = atomicBuild("gcc")

    @Test
    fun `atomic missing-value evidence builds with Clang`() {
        val available = runCatching {
            val process = ProcessBuilder("clang", "--version").redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD).start()
            try { process.waitFor(5, TimeUnit.SECONDS) && process.exitValue() == 0 }
            finally { if (process.isAlive) process.destroyForcibly() }
        }.getOrDefault(false)
        assumeTrue(available, "Clang-specific compiler qualification requires clang")
        atomicBuild("clang")
    }

    private fun atomicBuild(compiler: String) {
        val input = model(ATOMIC_TYPES.mapIndexed { index, type ->
            RecoveredGlobal("atomic_$index", "atomic_$index", (300 + index * 8).toULong(), type)
        }).copy(types = TYPES)
        val before = input.toJson()
        val project = project()
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val profile = ReconstructionProfile(base.schemaVersion, base.id, base.layout, base.budgets,
            base.adapterConfiguration + ("compiler-driver" to listOf(compiler)))
        val manifest = SourceTreeGenerator.generate(input, project, reconstructor = EvidenceModuleReconstructor(), profile = profile)
        assertEquals(before, input.toJson())
        assertTrue(manifest.unresolvedImplementationIds.containsAll(input.globals.map { it.id }))
        assertEquals(0, MakeProjectBuilder.build(project, ProjectBuildConfiguration(compilerExecutable = compiler), profile).returnCode)
    }

    private fun model(globals: List<RecoveredGlobal>) = RecoveredProgramModel(inputSha256 = "initializer-evidence",
        functions = listOf(RecoveredFunction("fn_main", "main", 100UL, "int main(void)", "int main(void) { return 0; }")), globals = globals)
    private fun project(): Path = Files.createTempDirectory(Path.of("build", "generated-c-initializer-tests").createDirectories(), "project-")
    private companion object {
        val TYPES = listOf(RecoveredType("atomic_types", "typedef _Atomic(int) AtomicInt; typedef AtomicInt Alias; " +
            "typedef int *Pointer; typedef _Atomic(Pointer) AtomicPointer; typedef int * _Atomic QualifiedPointer;"))
        val ATOMIC_TYPES = listOf("_Atomic(int)", "_Atomic int", "AtomicInt", "Alias", "int * _Atomic", "int ** _Atomic",
            "_Atomic(int *)", "AtomicPointer", "QualifiedPointer", "_Atomic Pointer", "_Atomic(double)")
    }
}
