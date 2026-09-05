package decompengine.validation

import decompengine.oracle.core.OracleArtifacts
import decompengine.project.ArchivalProjectAuditor
import decompengine.project.MakeProjectBuilder
import decompengine.project.RecoveredCModuleReconstructor
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import decompengine.project.SourceTreeGenerator
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.isExecutable
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BehaviorValidationTest {
    @Test
    fun `real sandbox reads retained case files through read-only isolated mounts`() {
        val tempDir = createTempDirectory("validation-file-mounts-")
        val source = """
            #include <stdio.h>
            int main(int argc, char **argv) {
                if (argc != 2) return 2;
                FILE *input = fopen(argv[1], "rb");
                if (!input) return 3;
                int character;
                while ((character = fgetc(input)) != EOF) {
                    if (fputc(character, stdout) == EOF) return 4;
                }
                if (ferror(input)) return 5;
                fclose(input);
                FILE *writable = fopen(argv[1], "ab");
                if (writable) { fclose(writable); return 6; }
                fputs("read-only\n", stderr);
                return 0;
            }
        """.trimIndent() + "\n"
        val original = compileC(tempDir, "file-original", source)
        val project = tempDir.resolve("project")
        SourceTreeGenerator.generate(
            RecoveredProgramModel(
                inputSha256 = OracleArtifacts.sha256(java.nio.file.Files.readAllBytes(original)),
                functions = listOf(RecoveredFunction("fn_1000", "main", 0x1000UL,
                    "int main(int argc, char **argv)", decompiledC = source)),
            ), project, reconstructor = RecoveredCModuleReconstructor(),
        )
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        val rebuilt = project.resolve("build/reconstructed")
        val payload = byteArrayOf(0, 1, 10, 127, -128, -1)
        val data = java.nio.file.Files.write(tempDir.resolve("payload.bin"), payload)
        val empty = java.nio.file.Files.write(tempDir.resolve("empty.bin"), byteArrayOf())
        val report = BehaviorComparator().compare(
            "file_mounts", original, rebuilt,
            listOf(
                ProcessInput("bytes", listOf("/inputs/nested/payload.bin")),
                ProcessInput("empty", listOf("/inputs/empty.bin")),
                ProcessInput("undeclared", listOf("/inputs/nested/payload.bin")),
            ),
            project.resolve("reports"), BehaviorProjectContext(project),
            fileInputs = mapOf(
                "bytes" to mapOf("nested/payload.bin" to data),
                "empty" to mapOf("empty.bin" to empty),
            ),
        )
        for (case in report.cases.take(2)) {
            assertEquals(0, case.original.exitCode)
            assertEquals(0, case.rebuilt.exitCode)
            assertEquals("read-only\n", case.original.stderr.decodeToString())
            assertEquals("read-only\n", case.rebuilt.stderr.decodeToString())
        }
        assertTrue(report.cases[0].original.stdout.contentEquals(payload))
        assertTrue(report.cases[0].rebuilt.stdout.contentEquals(payload))
        assertTrue(report.cases[1].original.stdout.isEmpty())
        assertTrue(report.cases[1].rebuilt.stdout.isEmpty())
        assertEquals(3, report.cases[2].original.exitCode)
        assertEquals(3, report.cases[2].rebuilt.exitCode)
        assertTrue(java.nio.file.Files.readAllBytes(data).contentEquals(payload))
        BehaviorEvidence.decode(java.nio.file.Files.readAllBytes(report.reportPath))
        val audit = ArchivalProjectAuditor.audit(project)
        assertEquals(true, audit.behaviorMatched)
        assertEquals(listOf("reports/file_mounts.behavior.json"), audit.projectBehaviorReportIds)
        assertTrue(audit.unresolvedEntityIds.isEmpty())
    }

    @Test
    fun `hello-world binary passes byte-for-byte comparison`() {
        val tempDir = createTempDirectory("validation-hello-")
        val original = compileC(tempDir, "hello-original", helloWorldSource())
        val rebuilt = compileC(tempDir, "hello-rebuilt", helloWorldSource())

        val report = BehaviorComparator().compare(
            id = "hello_world",
            originalBinary = original,
            rebuiltBinary = rebuilt,
            cases = listOf(ProcessInput(id = "default")),
            reportsDir = tempDir.resolve("reports"),
        )

        assertTrue(report.matches)
        assertTrue(report.reportPath.readText().contains("\"stdoutMatches\": true"))
        assertTrue(report.cases.single().original.stdout.contentEquals("hello, world\n".toByteArray()))
    }

    @Test
    fun `argv-processing binary passes byte-for-byte comparison`() {
        val tempDir = createTempDirectory("validation-argv-")
        val original = compileC(tempDir, "argv-original", argvEchoSource())
        val rebuilt = compileC(tempDir, "argv-rebuilt", argvEchoSource())

        val report = BehaviorComparator().compare(
            id = "argv_echo",
            originalBinary = original,
            rebuiltBinary = rebuilt,
            cases = listOf(
                ProcessInput(id = "no_args"),
                ProcessInput(id = "two_args", args = listOf("alpha", "beta")),
            ),
            reportsDir = tempDir.resolve("reports"),
        )

        assertTrue(report.matches)
        assertEquals("argc=3\narg1=alpha\narg2=beta\n", report.cases.last().rebuilt.stdout.decodeToString())
    }

    @Test
    fun `stdin-processing binary passes byte-for-byte comparison`() {
        val tempDir = createTempDirectory("validation-stdin-")
        val original = compileC(tempDir, "stdin-original", stdinEchoSource())
        val rebuilt = compileC(tempDir, "stdin-rebuilt", stdinEchoSource())

        val report = BehaviorComparator().compare(
            id = "stdin_echo",
            originalBinary = original,
            rebuiltBinary = rebuilt,
            cases = listOf(
                ProcessInput(id = "empty"),
                ProcessInput(id = "payload", stdin = "one\ntwo\n".toByteArray()),
            ),
            reportsDir = tempDir.resolve("reports"),
        )

        assertTrue(report.matches)
        assertEquals("stdin:one\nstdin:two\n", report.cases.last().original.stdout.decodeToString())
    }

    @Test
    fun `exit code stdout and stderr are compared byte-for-byte`() {
        val tempDir = createTempDirectory("validation-mismatch-")
        val original = compileC(tempDir, "original", "int main(void) { return 0; }\n")
        val rebuilt = compileC(tempDir, "rebuilt", "int main(void) { return 1; }\n")

        val exception = assertFailsWith<BehaviorMismatchException> {
            BehaviorComparator().compare(
                id = "exit_mismatch",
                originalBinary = original,
                rebuiltBinary = rebuilt,
                cases = listOf(ProcessInput(id = "default")),
                reportsDir = tempDir.resolve("reports"),
            )
        }

        val report = tempDir.resolve("reports/exit_mismatch.behavior.json").readText()
        assertTrue(exception.message!!.contains("behavior comparison failed"))
        assertTrue(report.contains("\"matches\": false"))
        assertTrue(report.contains("\"exitCodeMatches\": false"))
    }

    @Test
    fun `sandboxed execution is mandatory and visible in reports`() {
        val tempDir = createTempDirectory("validation-sandbox-")
        val original = compileC(tempDir, "original", helloWorldSource())
        val rebuilt = compileC(tempDir, "rebuilt", helloWorldSource())
        val sandbox = SandboxRunner()

        val report = BehaviorComparator(sandbox).compare(
            id = "sandbox_required",
            originalBinary = original,
            rebuiltBinary = rebuilt,
            cases = listOf(ProcessInput(id = "default")),
            reportsDir = tempDir.resolve("reports"),
        )

        val command = report.cases.single().original.sandboxCommand
        assertTrue(command.contains("/usr/bin/bwrap"))
        assertTrue(command.contains("--ro-bind"))
        assertTrue(command.contains("--die-with-parent"))
        if (sandbox.networkIsolationSupported()) {
            assertTrue(command.contains("--unshare-net"))
        } else {
            assertFalse(command.contains("--unshare-net"))
        }
        val json = report.reportPath.readText()
        assertTrue(json.contains("\"sandbox\": \"bubblewrap\""))
        assertTrue(json.contains("\"networkIsolated\""))
        assertEquals(sandbox.networkIsolationSupported(), report.networkIsolated)
        assertEquals(sandbox.networkIsolationSupported(), report.cases.single().original.networkIsolated)
    }

    private fun compileC(tempDir: java.nio.file.Path, name: String, source: String): java.nio.file.Path {
        val buildDir = tempDir.resolve(name).createDirectories()
        val sourcePath = buildDir.resolve("$name.c")
        val binaryPath = buildDir.resolve(name)
        sourcePath.writeText(source)

        val process = ProcessBuilder("gcc", sourcePath.pathString, "-o", binaryPath.pathString)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        check(exitCode == 0) { "gcc failed for $name: $output" }
        check(binaryPath.exists() && binaryPath.isExecutable()) { "gcc did not create executable $binaryPath" }
        return binaryPath
    }

    private fun helloWorldSource(): String = """
        #include <stdio.h>

        int main(void) {
            puts("hello, world");
            return 0;
        }
    """.trimIndent() + "\n"

    private fun argvEchoSource(): String = """
        #include <stdio.h>

        int main(int argc, char **argv) {
            printf("argc=%d\n", argc);
            for (int i = 1; i < argc; i++) {
                printf("arg%d=%s\n", i, argv[i]);
            }
            return 0;
        }
    """.trimIndent() + "\n"

    private fun stdinEchoSource(): String = """
        #include <stdio.h>

        int main(void) {
            char line[256];
            while (fgets(line, sizeof(line), stdin) != NULL) {
                printf("stdin:%s", line);
            }
            return 0;
        }
    """.trimIndent() + "\n"
}
