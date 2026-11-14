package decompengine.project

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.TestInfo
import org.junit.jupiter.api.parallel.Execution
import org.junit.jupiter.api.parallel.ExecutionMode
import org.junit.jupiter.api.parallel.ResourceLock

@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock("contained-module-compilation-runtime")
class GeneratedCCommentSafetyTest {
    @BeforeEach
    fun requireConfiguredCompiler(test: TestInfo) = requireHostedModuleCompiler(test)

    @Test
    fun `escaped line comments in retained prototypes reject with the function identity`() {
        for (ending in ESCAPED_ENDINGS) {
            val function = function("int convert(void) // retained note $ending")
            val failure = assertFailsWith<IllegalArgumentException> { normalizedPrototype(function) }
            assertTrue(failure.message.orEmpty().contains("fn_convert"), failure.message)
            assertTrue(failure.message.orEmpty().contains("line comment ending in backslash"), failure.message)
            val generation = assertFailsWith<IllegalArgumentException> {
                SourceTreeGenerator.generate(model(function), project(), reconstructor = EvidenceModuleReconstructor())
            }
            assertTrue(generation.message.orEmpty().contains("fn_convert"), generation.message)
        }
    }

    @Test
    fun `escaped line comments in global types and initializers reject with the object identity`() {
        for (ending in ESCAPED_ENDINGS) {
            for (external in listOf(false, true)) {
                val global = RecoveredGlobal("global_value", "value", 300UL, "int // retained type $ending")
                val failure = assertFailsWith<IllegalArgumentException> { globalDeclaration(global, external) }
                assertTrue(failure.message.orEmpty().contains("global_value"), failure.message)
                assertTrue(failure.message.orEmpty().contains("line comment ending in backslash"), failure.message)
            }
            val global = RecoveredGlobal("global_value", "value", 300UL, "int", initializer = "17 // retained initializer $ending")
            val failure = assertFailsWith<IllegalArgumentException> { globalDeclaration(global, false) }
            assertTrue(failure.message.orEmpty().contains("global_value"), failure.message)
            assertTrue(failure.message.orEmpty().contains("line comment ending in backslash"), failure.message)
        }
    }

    @Test
    @Tag("ci-live")
    fun `internal backslashes in retained line comments remain buildable without changing declarations`() {
        val prototype = "int convert(void) // retained \\ character"
        assertEquals("$prototype\n", normalizedPrototype(function(prototype)))
        val global = RecoveredGlobal("global_value", "value", 300UL, "int // retained \\ type",
            initializer = "17 // retained \\ initializer")
        assertTrue(globalDeclaration(global, false).contains("17 // retained \\ initializer\n;"))
        val project = project()
        val input = model(function(prototype, "int convert(void) { return value; }"), main())
            .copy(globals = listOf(global))
        val manifest = SourceTreeGenerator.generate(input, project, reconstructor = RecoveredCModuleReconstructor(),
            overrides = mapOf("fn_convert" to "core", "fn_main" to "core", "global_value" to "core"))
        assertTrue(manifest.unresolvedImplementationIds.isEmpty(), manifest.unresolvedImplementationIds.toString())
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        assertEquals(17, ProcessBuilder(project.resolve("build/reconstructed").toAbsolutePath().toString()).start().waitFor())
    }

    private fun function(prototype: String, recovered: String? = null) =
        RecoveredFunction("fn_convert", "convert", 200UL, prototype, recovered)
    private fun main() = RecoveredFunction("fn_main", "main", 100UL, "int main(void)",
        "int main(void) { return convert(); }", calls = setOf("fn_convert"))
    private fun model(vararg functions: RecoveredFunction) =
        RecoveredProgramModel(inputSha256 = "comment-safety", functions = functions.toList())
    private fun project(): Path = Files.createTempDirectory(Path.of("build", "generated-c-comment-tests").createDirectories(), "project-")

    private companion object {
        val ESCAPED_ENDINGS = listOf("\\", "\\\n", "\\\n\n", "\\\r\n", "\\ \t\n", "\\\ncontinued comment",
            "\\\rcontinued comment", "??/", "??/\n", "??/\rcontinued comment")
    }
}
