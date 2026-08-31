package decompengine.oracle.provenance

import decompengine.oracle.core.OracleArtifacts
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class LlvmFunctionOracleGeneratorCliTest {
    @Test
    fun `CLI rejects malformed duplicate and authority-expanding options before publication`(): Unit =
        withPrivateDirectory { root ->
            val output = root.resolve("function-recovery-oracle.json")
            val required = listOf(
                "--manifest",
                "missing-manifest.json",
                "--exclusions",
                "missing-exclusions.json",
                "--artifact-root",
                root.toString(),
                "--output",
                output.toString(),
            )
            val hostile = listOf(
                emptyList(),
                listOf("--manifest"),
                listOf("manifest", "missing.json"),
                required + listOf("--schema", "forged-schema.json"),
                required + listOf("--near-miss-bytes", "32"),
                required + listOf("--rich-artifact", "forged-rich"),
                required + listOf("--manifest", "replacement-manifest.json"),
                required.mapIndexed { index, value -> if (index == 1) "" else value },
            )
            hostile.forEach { arguments ->
                val standard = ArrayList<String>()
                val errors = ArrayList<String>()
                assertEquals(
                    1,
                    LlvmFunctionOracleGeneratorCli.run(
                        arguments.toTypedArray(),
                        stdout = standard::add,
                        stderr = errors::add,
                    ),
                )
                assertTrue(standard.isEmpty(), arguments.toString())
                assertEquals(1, errors.size, arguments.toString())
                assertTrue(errors.single().startsWith("LLVM function-oracle generation failed:"))
                assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS), arguments.toString())
            }
        }

    @Test
    fun `valid CLI shape delegates to raw validation and fails closed for missing inputs`(): Unit =
        withPrivateDirectory { root ->
            val output = root.resolve("function-recovery-oracle.json")
            val errors = ArrayList<String>()
            val result = LlvmFunctionOracleGeneratorCli.run(
                arrayOf(
                    "--manifest",
                    root.resolve("missing-manifest.json").toString(),
                    "--exclusions",
                    root.resolve("missing-exclusions.json").toString(),
                    "--artifact-root",
                    root.toString(),
                    "--output",
                    output.toString(),
                ),
                stdout = { throw AssertionError("failed generation must not print success") },
                stderr = errors::add,
            )
            assertEquals(1, result)
            assertEquals(1, errors.size)
            assertTrue(errors.single().contains("artifact manifest verification failed"), errors.single())
            assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS))
        }

    @Test
    fun `CLI JVM entry point accepts only an argument vector`() {
        val main = LlvmFunctionOracleGeneratorCli::class.java.declaredMethods.filter { it.name == "main" }
        assertEquals(1, main.size)
        assertTrue(Modifier.isStatic(main.single().modifiers))
        assertEquals(listOf(Array<String>::class.java), main.single().parameterTypes.toList())
    }

    @Test
    fun `Gradle and required workflow use only Kotlin generation authority`() {
        val build = Path.of("build.gradle.kts").readText()
        val workflow = Path.of(".github/workflows/llvm-oracle-model.yml").readText()
        assertTrue(build.contains("taskName = \"generateLlvmFunctionRecoveryOracle\""))
        assertTrue(build.contains("entryPoint = \"decompengine.oracle.provenance.LlvmFunctionOracleGeneratorCli\""))

        val generationStep = workflow
            .substringAfter("- name: Regenerate deterministic Clang function oracle in Kotlin")
            .substringBefore("- name: Authenticate checked Clang behavior reference evidence in Kotlin")
        assertTrue(generationStep.contains("install -d -m 0700 \"\$RUNNER_TEMP/llvm-function-oracle\""))
        assertTrue(generationStep.contains("./gradlew --no-daemon generateLlvmFunctionRecoveryOracle"))
        listOf("--manifest", "--exclusions", "--artifact-root", "--output").forEach { option ->
            assertTrue(generationStep.contains(option), option)
        }
        listOf("--schema", "--near-miss-bytes", "--rich-artifact", "--stripped-artifact").forEach { option ->
            assertFalse(generationStep.contains(option), option)
        }
        assertTrue(
            generationStep.contains(
                "cmp \"\$RUNNER_TEMP/llvm-function-oracle/function-recovery-oracle.json\"",
            ),
        )
        assertFalse(generationStep.contains("python3"))
        assertFalse(workflow.contains("python3 scripts/generate-llvm-function-recovery-oracle.py"))
        assertTrue(workflow.contains("Run non-authoritative Python compatibility regressions"))

        listOf(
            "scripts/generate-llvm-function-recovery-oracle.py",
            "oracle/llvm/generate_function_recovery_oracle.py",
            "oracle/function_recovery_oracle.py",
        ).forEach { path ->
            val compatibility = Path.of(path).readText()
            assertTrue(compatibility.contains("non-authoritative"), path)
            assertTrue(compatibility.contains("cannot"), path)
            assertTrue(compatibility.contains("Kotlin"), path)
        }
    }

    @Test
    fun `real CLI reproduces the checked oracle through the narrow surface`() {
        val rawRoot = System.getenv("LLVM_ORACLE_ARTIFACT_ROOT")?.takeIf(String::isNotBlank)
        assumeTrue(rawRoot != null, "set LLVM_ORACLE_ARTIFACT_ROOT for the long CLI parity proof")
        withPrivateDirectory { root ->
            val output = root.resolve("function-recovery-oracle.json")
            val standard = ArrayList<String>()
            val errors = ArrayList<String>()
            assertEquals(
                0,
                LlvmFunctionOracleGeneratorCli.run(
                    arrayOf(
                        "--manifest",
                        "oracle/llvm/22.1.6/oracle-manifest.json",
                        "--exclusions",
                        "oracle/llvm/22.1.6/function-recovery-exclusions.json",
                        "--artifact-root",
                        checkNotNull(rawRoot),
                        "--output",
                        output.toString(),
                    ),
                    stdout = standard::add,
                    stderr = errors::add,
                ),
            )
            val expected = Files.readAllBytes(Path.of("oracle/llvm/22.1.6/function-recovery-oracle.json"))
            assertTrue(errors.isEmpty(), errors.toString())
            assertEquals(2, standard.size)
            assertTrue(standard.last().contains("4303 functions"), standard.toString())
            assertEquals(EXPECTED_SHA256, OracleArtifacts.sha256(Files.readAllBytes(output)))
            assertContentEquals(expected, Files.readAllBytes(output))
            assertEquals(
                PosixFilePermissions.fromString("r--------"),
                Files.getPosixFilePermissions(output, LinkOption.NOFOLLOW_LINKS),
            )
        }
    }

    private inline fun <T> withPrivateDirectory(action: (Path) -> T): T {
        val directory = createTempDirectory("llvm-function-oracle-cli-").toAbsolutePath().normalize()
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
        return try {
            action(directory)
        } finally {
            if (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
                Files.walk(directory).use { paths -> paths.toList() }
                    .sortedWith(Comparator.reverseOrder())
                    .forEach(Files::deleteIfExists)
            }
        }
    }

    private companion object {
        const val EXPECTED_SHA256 =
            "a37d6eda0fb9b95fa884c8ce4eff358ab7bf424fa9b990e61cb4f465f3e0410c"
    }
}
