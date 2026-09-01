package decompengine.oracle.behavior

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.Comparator
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HostedNativeExecutionIsolatedTest {
    @Test
    fun `closed standard descriptors are reserved before retained execution`() {
        if (!supported()) return

        val outcome = runProbe("closed-stdio")

        assertEquals("exit=0", outcome.result, outcome.output)
        assertFalse(outcome.spawned, outcome.output)
    }

    @Test
    fun `ignored SIGCHLD is rejected before retained execution can spawn`() {
        if (!supported()) return

        val outcome = runProbe("ignored-sigchld")

        assertTrue(
            outcome.result.startsWith("failure=") &&
                outcome.result.contains("requires default waitable SIGCHLD disposition"),
            "${outcome.result}\n${outcome.output}",
        )
        assertFalse(outcome.spawned, outcome.output)
    }

    private fun runProbe(mode: String): ProbeOutcome {
        val root = createTempDirectory("hosted-native-isolated-$mode-").toAbsolutePath().normalize()
        val resultMarker = root.resolve("result.txt")
        val spawnMarker = root.resolve("spawned.txt")
        val processOutput = root.resolve("process-output.txt")
        val java = Path.of(System.getProperty("java.home"), "bin", "java").toAbsolutePath().normalize()
        val process = ProcessBuilder(
            java.toString(),
            "-cp",
            System.getProperty("java.class.path"),
            HostedNativeExecutionIsolatedMain::class.java.name,
            mode,
            root.toString(),
            resultMarker.toString(),
            spawnMarker.toString(),
        ).redirectErrorStream(true)
            .redirectOutput(processOutput.toFile())
            .start()
        try {
            val exited = process.waitFor(PROBE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            if (!exited) {
                process.destroyForcibly()
                process.waitFor(PROBE_CLEANUP_SECONDS, TimeUnit.SECONDS)
            }
            val output = readBoundedOutput(processOutput)
            assertTrue(exited, "isolated hosted-native probe did not exit:\n$output")
            assertEquals(0, process.exitValue(), output)
            assertTrue(
                Files.isRegularFile(resultMarker, LinkOption.NOFOLLOW_LINKS),
                "isolated hosted-native probe did not publish its result:\n$output",
            )
            return ProbeOutcome(
                Files.readString(resultMarker),
                Files.exists(spawnMarker, LinkOption.NOFOLLOW_LINKS),
                output,
            )
        } finally {
            if (process.isAlive) {
                process.destroyForcibly()
                process.waitFor(PROBE_CLEANUP_SECONDS, TimeUnit.SECONDS)
            }
            deleteTree(root)
        }
    }

    private fun readBoundedOutput(path: Path): String {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return ""
        Files.newInputStream(path).use { input ->
            val bytes = input.readNBytes(MAXIMUM_PROBE_OUTPUT_BYTES + 1)
            assertTrue(bytes.size <= MAXIMUM_PROBE_OUTPUT_BYTES, "isolated hosted-native probe output is oversized")
            return bytes.toString(Charsets.UTF_8)
        }
    }

    private fun supported(): Boolean =
        System.getProperty("os.name", "") == "Linux" &&
            System.getProperty("os.arch", "") in setOf("amd64", "x86_64") &&
            Files.isDirectory(Path.of("/proc/self/fd")) &&
            Files.isRegularFile(Path.of("/usr/bin/true"), LinkOption.NOFOLLOW_LINKS) &&
            Files.isRegularFile(Path.of("/bin/sh").toRealPath(), LinkOption.NOFOLLOW_LINKS)

    private fun deleteTree(root: Path) {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
        Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    private data class ProbeOutcome(
        val result: String,
        val spawned: Boolean,
        val output: String,
    )

    private companion object {
        const val PROBE_TIMEOUT_SECONDS = 15L
        const val PROBE_CLEANUP_SECONDS = 5L
        const val MAXIMUM_PROBE_OUTPUT_BYTES = 64 * 1024
    }
}
