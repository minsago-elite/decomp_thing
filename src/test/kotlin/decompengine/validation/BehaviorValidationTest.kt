package decompengine.validation

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
