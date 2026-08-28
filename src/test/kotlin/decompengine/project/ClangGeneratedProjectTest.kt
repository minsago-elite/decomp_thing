package decompengine.project

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.io.path.isExecutable
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class ClangGeneratedProjectTest {
    @Test
    fun `clang builds a generated multi-module project with strict warnings`() {
        val clang = requireClang()
        val project = createTempDirectory("clang-generated-project-")
        val functions = buildList {
            repeat(15) { index ->
                add(
                    RecoveredFunction(
                        id = "fn_parse_$index",
                        name = "parse_$index",
                        address = (0x1000 + index * 0x10).toULong(),
                        prototype = "int parse_$index(void)",
                    ),
                )
                add(
                    RecoveredFunction(
                        id = "fn_render_$index",
                        name = "render_$index",
                        address = (0x3000 + index * 0x10).toULong(),
                        prototype = "int render_$index(void)",
                    ),
                )
            }
        }
        SourceTreeGenerator.generate(
            RecoveredProgramModel(inputSha256 = "clang-multi-module", functions = functions),
            project,
        )

        val report = MakeProjectBuilder.build(
            project,
            ProjectBuildConfiguration(compilerExecutable = clang.toString()),
        )

        assertEquals(0, report.returnCode)
        assertTrue(report.command.contains("CC=$clang"))
        assertTrue(project.resolve("build/reconstructed").isExecutable())
        assertTrue(project.resolve("src/modules").listDirectoryEntries("*.c").size >= 2)
        val contract = project.resolve("reports/build_contract.json").readText()
        val instructions = project.resolve("BUILDING.md").readText()
        assertTrue(contract.contains("C compiler ($clang)"), contract)
        assertTrue(instructions.contains("configured C compiler `$clang`"), instructions)
        assertFalse(instructions.contains("requires GNU Make, GCC"), instructions)
    }

    @Test
    fun `clang diagnostics remain attributed to the generated source owner`() {
        val clang = requireClang()
        val project = createTempDirectory("clang-generated-warning-")
        SourceTreeGenerator.generate(
            RecoveredProgramModel(
                inputSha256 = "clang-warning",
                functions = listOf(
                    RecoveredFunction(
                        id = "fn_warning",
                        name = "warning_fixture",
                        address = 0x1000UL,
                        prototype = "int warning_fixture(void)",
                        decompiledC = "int warning_fixture(void) { int unused; return 0; }",
                    ),
                ),
            ),
            project,
            reconstructor = RecoveredCModuleReconstructor(),
        )

        val failure = runCatching {
            MakeProjectBuilder.build(
                project,
                ProjectBuildConfiguration(compilerExecutable = clang.toString()),
            )
        }.exceptionOrNull()

        assertTrue(failure is BuildException, failure.toString())
        val diagnostic = project.resolve("reports/build/modules").listDirectoryEntries("*.log")
            .single { it.readText().contains("source=src/modules/") }
            .readText()
        assertTrue(diagnostic.contains("status=failed"), diagnostic)
        assertTrue(diagnostic.contains("unused variable"), diagnostic)
        assertTrue(diagnostic.contains("-Werror"), diagnostic)
    }

    private fun requireClang(): Path {
        val configured = System.getenv("DECOMP_TEST_CLANG")?.takeIf(String::isNotBlank)
        if (configured == null) {
            check(System.getenv("DECOMP_REQUIRE_CLANG_TESTS") != "1") {
                "DECOMP_REQUIRE_CLANG_TESTS=1 requires DECOMP_TEST_CLANG"
            }
            assumeTrue(false, "set DECOMP_TEST_CLANG to run Clang compatibility tests")
        }
        val clang = Path.of(configured).toAbsolutePath().normalize()
        if (!Files.isRegularFile(clang) || !clang.isExecutable()) {
            check(System.getenv("DECOMP_REQUIRE_CLANG_TESTS") != "1") {
                "configured Clang is not an executable regular file: $clang"
            }
            assumeTrue(false, "configured Clang is unavailable: $clang")
        }
        return clang
    }
}
