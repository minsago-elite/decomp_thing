package decompengine.mvp

import java.nio.file.Files
import java.time.Duration
import java.util.concurrent.CompletableFuture
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BinaryExecutionTest {
    @Test
    fun `spool runner executes with no inherited credentials and attests network isolation`() {
        val temp = createTempDirectory("binary-runner-")
        val root = temp.resolve("root").createDirectories()
        val control = temp.resolve("control")
        val executable = root.resolve("probe.sh")
        executable.writeText("#!/bin/sh\nprintf '%s|%s' \"${'$'}{API_KEY-unset}\" \"${'$'}{ASAN_OPTIONS-unset}\"\n")
        executable.toFile().setExecutable(true)
        val runner = BinaryRunnerService(control, listOf(root), networkIsolated = true)
        val boundary = SpoolBinaryExecutionBoundary(control, Duration.ofSeconds(3))

        val future = CompletableFuture.supplyAsync {
            boundary.execute(executable, root, mapOf("ASAN_OPTIONS" to "halt_on_error=1"))
        }
        while (!future.isDone) {
            runner.processOne()
            Thread.sleep(10)
        }
        val result = future.get()

        assertEquals(0, result.exitCode)
        assertEquals("unset|halt_on_error=1", result.stdout)
        assertTrue(result.isolation.networkIsolated)
        assertTrue(result.isolation.credentialsIsolated)
        assertFalse(control.resolve("responses").toFile().listFiles().orEmpty().any())
    }

    @Test
    fun `runner rejects paths outside explicit roots`() {
        val temp = createTempDirectory("binary-runner-path-")
        val root = temp.resolve("root").createDirectories()
        val control = temp.resolve("control")
        val outside = temp.resolve("outside.sh")
        outside.writeText("#!/bin/sh\nexit 0\n")
        outside.toFile().setExecutable(true)
        val runner = BinaryRunnerService(control, listOf(root), networkIsolated = true)
        val boundary = SpoolBinaryExecutionBoundary(control, Duration.ofSeconds(3))

        val future = CompletableFuture.supplyAsync { boundary.execute(outside, temp, emptyMap()) }
        while (!future.isDone) {
            runner.processOne()
            Thread.sleep(10)
        }
        val failure = assertFailsWith<Exception> { future.get() }

        assertTrue(failure.cause?.message.orEmpty().contains("outside runner roots"))
    }

    @Test
    fun `boundary rejects credential-bearing environment before queuing`() {
        val temp = createTempDirectory("binary-runner-env-")
        val boundary = SpoolBinaryExecutionBoundary(temp.resolve("control"))

        val failure = assertFailsWith<IllegalArgumentException> {
            boundary.execute(temp.resolve("program"), temp, mapOf("API_KEY" to "secret"))
        }

        assertTrue(failure.message.orEmpty().contains("unauthorized keys"))
        assertTrue(Files.list(temp.resolve("control/requests")).use { it.findAny().isEmpty })
    }

    @Test
    fun `compose runner has no credentials network or broad write mounts`() {
        val compose = java.nio.file.Path.of("compose.yaml").readText()
        val runner = compose.substringAfter("  binary-runner:").substringBefore("\nvolumes:")

        assertTrue(runner.contains("network_mode: none"))
        assertTrue(runner.contains("read_only: true"))
        assertTrue(runner.contains("no-new-privileges:true"))
        assertTrue(runner.contains("${'$'}{INPUT_DIR:-./input}:/input:ro"))
        assertTrue(runner.contains("${'$'}{OUTPUT_DIR:-./output}:/output:ro"))
        assertFalse(runner.contains("env_file"))
        assertFalse(runner.contains("API_KEY"))
        assertFalse(runner.contains("privileged"))
        assertFalse(runner.contains("SYS_ADMIN"))
    }
}
