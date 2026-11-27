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
    fun `private bubblewrap process namespace permits leak and argument evidence`() {
        for ((filename, case) in listOf(
            "09_memory_leak.c" to MvpVulnerabilityCase.MEMORY_LEAK,
            "10_command_injection.c" to MvpVulnerabilityCase.COMMAND_INJECTION,
        )) {
            val temp = createTempDirectory("binary-real-boundary-${case.id}-")
            val source = temp.resolve("decompiled.c")
            source.writeText(java.nio.file.Path.of("benchmarks/fixtures/c-vul/src/$filename").readText())
            val executable = temp.resolve("probe")
            val compiler = ProcessBuilder("clang", "-O1", "-g", "-fsanitize=address,undefined", source.toString(), "-o", executable.toString())
                .redirectErrorStream(true).start()
            val diagnostic = compiler.inputStream.bufferedReader().readText()
            assertEquals(0, compiler.waitFor(), diagnostic)
            val result = BubblewrapBinaryExecutionBoundary().execute(executable, temp, case.environment, case.arguments)
            result.isolation.requireSecure()
            assertTrue(case.matchesFinding(result.exitCode, result.combined), result.combined)
        }
    }

    @Test
    fun `arguments retain literal boundaries across the spool without shell expansion`() {
        val temp = createTempDirectory("binary-runner-argv-")
        val root = temp.resolve("root").createDirectories()
        val control = temp.resolve("control")
        val executable = root.resolve("probe.sh")
        executable.writeText("#!/bin/sh\nprintf '<%s>\\n' \"${'$'}@\"\n")
        executable.toFile().setExecutable(true)
        val arguments = listOf("", "two words", "literal; printf OTHER", "${'$'}(printf OTHER)", "quotes'\"")
        val runner = BinaryRunnerService(control, listOf(root), networkIsolated = true)
        val boundary = SpoolBinaryExecutionBoundary(control, Duration.ofSeconds(3))
        val future = CompletableFuture.supplyAsync { boundary.execute(executable, root, emptyMap(), arguments) }
        while (!future.isDone) { runner.processOne(); Thread.sleep(10) }
        val result = future.get()
        assertEquals(0, result.exitCode)
        assertEquals(arguments.joinToString("") { "<$it>\n" }, result.stdout)
        assertEquals("", result.stderr)
    }

    @Test
    fun `invalid arguments refuse before queuing and legacy boundaries never drop arguments`() {
        val temp = createTempDirectory("binary-runner-argv-refusal-")
        val boundary = SpoolBinaryExecutionBoundary(temp.resolve("control"))
        for (arguments in listOf(List(33) { "x" }, listOf("nul\u0000value"), listOf("é".repeat(2049)), List(5) { "x".repeat(4096) })) {
            assertFailsWith<IllegalArgumentException> { boundary.execute(temp.resolve("program"), temp, emptyMap(), arguments) }
        }
        assertTrue(Files.list(temp.resolve("control/requests")).use { it.findAny().isEmpty })
        val legacy = BinaryExecutionBoundary { _, _, _ -> error("must not silently omit arguments") }
        assertFailsWith<IllegalArgumentException> { legacy.execute(temp.resolve("program"), temp, emptyMap(), listOf("input")) }
    }

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
