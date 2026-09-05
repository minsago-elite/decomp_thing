package decompengine.oracle.provenance

import decompengine.oracle.core.OracleArtifacts
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LlvmToolchainBuildScriptTest {
    @Test
    fun `successful image build retains exact recipe arguments without a retry`() {
        val result = runScript(listOf(0))
        assertEquals(0, result.status)
        assertEquals(listOf(EXPECTED_COMMAND), result.commands)
        assertEquals(emptyList(), result.sleeps)
        assertTrue(result.output.contains("attempt 1/2"))
        assertFalse(result.output.contains("attempt 2/2"))
    }

    @Test
    fun `ordinary build failure retries the unchanged recipe once`() {
        val result = runScript(listOf(1, 0))
        assertEquals(0, result.status)
        assertEquals(listOf(EXPECTED_COMMAND, EXPECTED_COMMAND), result.commands)
        assertEquals(listOf("5"), result.sleeps)
        assertTrue(result.output.contains("attempt 2/2"))
    }

    @Test
    fun `two failed builds preserve the final failure and never start a third`() {
        val result = runScript(listOf(1, 1, 0))
        assertEquals(1, result.status)
        assertEquals(listOf(EXPECTED_COMMAND, EXPECTED_COMMAND), result.commands)
        assertEquals(listOf("5"), result.sleeps)
        assertTrue(result.output.contains("no further attempt"))
    }

    @Test
    fun `timeout kill signal and launcher failures are not treated as retryable completion`() {
        for (status in listOf(124, 125, 126, 127, 130, 137, 143)) {
            val result = runScript(listOf(status, 0))
            assertEquals(status, result.status)
            assertEquals(listOf(EXPECTED_COMMAND), result.commands)
            assertEquals(emptyList(), result.sleeps)
            assertFalse(result.output.contains("attempt 2/2"))
        }
    }

    @Test
    fun `second attempt timeout remains failure without falling through to image verification`() {
        val result = runScript(listOf(1, 124, 0))
        assertEquals(124, result.status)
        assertEquals(listOf(EXPECTED_COMMAND, EXPECTED_COMMAND), result.commands)
        assertEquals(listOf("5"), result.sleeps)
    }

    @Test
    fun `caller arguments cannot override pinned build identity or network deadline`() {
        for (argument in listOf("--platform=linux/arm64", "--build-arg", "--file=/tmp/other", "--timeout=0")) {
            val result = runScript(listOf(0), listOf(argument))
            assertEquals(64, result.status)
            assertEquals(emptyList(), result.commands)
            assertEquals(emptyList(), result.sleeps)
        }
    }

    @Test
    fun `real timeout forwards Docker completion status without replacing the retry decision`() {
        for (statuses in listOf(listOf(0), listOf(1, 0), listOf(1, 1), listOf(137))) {
            val result = runScript(statuses, realTimeout = true)
            assertEquals(statuses.last(), result.status)
            assertEquals(List(statuses.size) { EXPECTED_COMMAND.drop(4) }, result.commands)
            assertEquals(if (statuses.size == 2) listOf("5") else emptyList(), result.sleeps)
        }
    }

    @Test
    fun `both workflows use the wrapper without changing frozen provenance or verification gates`() {
        val model = Files.readString(Path.of(".github/workflows/llvm-oracle-model.yml"))
        val rebuild = Files.readString(Path.of(".github/workflows/llvm-oracle-rebuild.yml"))
        for (workflow in listOf(model, rebuild)) {
            assertTrue(workflow.contains("bash scripts/ci-build-llvm-toolchain.sh"))
            assertFalse(workflow.contains("docker buildx build"))
            assertTrue(workflow.contains("docker image inspect --format '{{.Id}}'"))
            assertTrue(workflow.contains("decompengine.oracle.provenance.LlvmBuildEnvironmentVerifierCli"))
        }
        assertTrue(model.contains("timeout-minutes: 45"))
        assertTrue(model.contains("./gradlew --no-daemon verifyLlvmToolchainReproduction"))
        assertTrue(model.contains("DECOMP_REQUIRE_LLVM_HOSTED_WORKER_IMAGE: \"1\""))
        assertEquals("97e2d13915806242c14489b5a8b1417bd0478f3a11dc05e76888ba2ab43b1291",
            OracleArtifacts.sha256(Files.readAllBytes(Path.of("oracle/llvm/22.1.6/build-toolchain.Dockerfile"))))
        assertEquals("14a383bc5792b7ace786cbbd8964383469c1ffa5a4bb06a99e38c71518643f4f",
            OracleArtifacts.sha256(Files.readAllBytes(Path.of("oracle/llvm/22.1.6/toolchain-reproduction.json"))))
    }

    private fun runScript(
        statuses: List<Int>, arguments: List<String> = emptyList(), realTimeout: Boolean = false,
    ): ScriptResult {
        val root = createTempDirectory("llvm-toolchain-build-script-")
        try {
            val binaries = Files.createDirectory(root.resolve("bin"))
            val commands = root.resolve("commands")
            val sleeps = root.resolve("sleeps")
            val counter = root.resolve("counter")
            val statusFile = root.resolve("statuses")
            Files.writeString(statusFile, statuses.joinToString("\n", postfix = "\n"))
            val commandStub = Files.writeString(binaries.resolve(if (realTimeout) "docker" else "timeout"), """
                #!/usr/bin/env bash
                set -euo pipefail
                count=0
                if [[ -f "${'$'}TEST_COUNTER" ]]; then read -r count < "${'$'}TEST_COUNTER"; fi
                count=${'$'}((count + 1))
                printf '%s\n' "${'$'}count" > "${'$'}TEST_COUNTER"
                printf '%s\n' '---' "${'$'}@" >> "${'$'}TEST_COMMANDS"
                status=${'$'}(sed -n "${'$'}{count}p" "${'$'}TEST_STATUSES")
                exit "${'$'}{status:-99}"
            """.trimIndent() + "\n")
            val sleep = Files.writeString(binaries.resolve("sleep"), """
                #!/usr/bin/env bash
                set -euo pipefail
                printf '%s\n' "${'$'}@" >> "${'$'}TEST_SLEEPS"
            """.trimIndent() + "\n")
            for (script in listOf(commandStub, sleep)) {
                Files.setPosixFilePermissions(script, PosixFilePermissions.fromString("rwx------"))
            }
            val command = listOf("/bin/bash", Path.of("scripts/ci-build-llvm-toolchain.sh").toAbsolutePath().toString()) + arguments
            val builder = ProcessBuilder(command).directory(root.toFile()).redirectErrorStream(true)
            builder.environment().apply {
                clear()
                put("PATH", "$binaries:/usr/bin:/bin")
                put("HOME", root.toString())
                put("LC_ALL", "C")
                put("TEST_COUNTER", counter.toString())
                put("TEST_COMMANDS", commands.toString())
                put("TEST_STATUSES", statusFile.toString())
                put("TEST_SLEEPS", sleeps.toString())
            }
            val process = builder.start()
            try {
                process.outputStream.close()
                assertTrue(process.waitFor(10, TimeUnit.SECONDS), "LLVM build-script stub did not terminate")
                val output = process.inputStream.use { input ->
                    val bytes = input.readNBytes(16 * 1024 + 1)
                    assertTrue(bytes.size <= 16 * 1024)
                    bytes.toString(Charsets.UTF_8)
                }
                val recorded = if (Files.exists(commands)) Files.readString(commands)
                    .split("---\n").filter(String::isNotEmpty).map { it.trimEnd().lines() } else emptyList()
                return ScriptResult(process.exitValue(), output, recorded,
                    if (Files.exists(sleeps)) Files.readAllLines(sleeps) else emptyList())
            } finally {
                if (process.isAlive) {
                    process.destroyForcibly()
                    assertTrue(process.waitFor(5, TimeUnit.SECONDS))
                }
            }
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private data class ScriptResult(val status: Int, val output: String, val commands: List<List<String>>, val sleeps: List<String>)

    private companion object {
        val EXPECTED_COMMAND = listOf(
            "--signal=INT", "--kill-after=30s", "900s", "docker", "buildx", "build", "--no-cache",
            "--platform", "linux/amd64", "--build-arg", "SOURCE_DATE_EPOCH=1779182222", "--load",
            "--progress", "plain", "--tag", "decomp-llvm-oracle-toolchain:22.1.6", "--file",
            "oracle/llvm/22.1.6/build-toolchain.Dockerfile", "oracle/llvm/22.1.6",
        )
    }
}
