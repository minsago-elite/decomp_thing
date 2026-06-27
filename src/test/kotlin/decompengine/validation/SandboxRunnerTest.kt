package decompengine.validation

import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.isExecutable
import kotlin.io.path.pathString
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SandboxRunnerTest {
    @Test
    fun `sandboxed run captures stdout exit code and uses bwrap`() {
        val tempDir = createTempDirectory("sandbox-capture-")
        val binary = compileHello(tempDir)

        val output = SandboxRunner().run(binary, ProcessInput(id = "default"))

        assertTrue(output.sandboxCommand.contains("/usr/bin/bwrap"))
        assertTrue(output.sandboxCommand.contains("--ro-bind"))
        assertTrue(output.sandboxCommand.contains("--die-with-parent"))
        assertEquals(0, output.exitCode)
        assertEquals("hello, world\n", output.stdout.decodeToString())
    }

    @Test
    fun `network isolation flag reflects the sandbox command`() {
        val tempDir = createTempDirectory("sandbox-flag-")
        val binary = compileHello(tempDir)

        val withNet = SandboxRunner(networkIsolation = true).run(binary, ProcessInput(id = "default"))
        val withoutNet = SandboxRunner(networkIsolation = false).run(binary, ProcessInput(id = "default"))

        assertTrue(withNet.sandboxCommand.contains("--unshare-net"))
        assertFalse(withoutNet.sandboxCommand.contains("--unshare-net"))
        assertTrue(withNet.networkIsolated)
        assertFalse(withoutNet.networkIsolated)
        assertTrue(withoutNet.stdout.contentEquals(withNet.stdout))
    }

    @Test
    fun `capability probe reports a stable value for the environment`() {
        val supported = SandboxRunner().networkIsolationSupported()
        val probedAgain = SandboxRunner().networkIsolationSupported()
        assertEquals(supported, probedAgain)
    }

    @Test
    fun `missing bubblewrap is reported loudly rather than silently executing unsandboxed`() {
        val tempDir = createTempDirectory("sandbox-missing-")
        val binary = compileHello(tempDir)

        val runner = SandboxRunner(
            bwrapPath = java.nio.file.Path.of("/nonexistent/bwrap"),
            timeoutPath = java.nio.file.Path.of("/usr/bin/timeout"),
            networkIsolation = false,
        )

        assertFailsWith<SandboxUnavailableException> {
            runner.run(binary, ProcessInput(id = "default"))
        }
    }

    private fun compileHello(tempDir: java.nio.file.Path): java.nio.file.Path {
        val buildDir = tempDir.resolve("hello").createDirectories()
        val sourcePath = buildDir.resolve("hello.c")
        val binaryPath = buildDir.resolve("hello")
        sourcePath.writeText(
            """
            #include <stdio.h>

            int main(void) {
                puts("hello, world");
                return 0;
            }
            """.trimIndent() + "\n",
        )
        val process = ProcessBuilder("gcc", sourcePath.pathString, "-o", binaryPath.pathString)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        check(exitCode == 0) { "gcc failed: $output" }
        check(binaryPath.exists() && binaryPath.isExecutable()) { "gcc did not create executable" }
        return binaryPath
    }
}
