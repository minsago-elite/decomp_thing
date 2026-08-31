package decompengine.acp

import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LinuxBoundedSessionProcessTest {
    @Test
    fun capturesSeparatedOutputWithClearedDeclaredEnvironment() {
        requireLinux()
        val result = LinuxBoundedSessionProcess.execute(
            command(
                "/bin/sh",
                "-c",
                "test \"\${BOUND_VALUE-}\" = exact && test \"\${HOME-unset}\" = unset; " +
                    "printf stdout; printf stderr >&2",
                environment = mapOf("BOUND_VALUE" to "exact"),
            ),
        )
        assertEquals(0, result.exitCode)
        assertNull(result.signal)
        assertContentEquals("stdout".toByteArray(), result.stdout)
        assertContentEquals("stderr".toByteArray(), result.stderr)
    }

    @Test
    fun returnsClosedExitAndSignalSemantics() {
        requireLinux()
        val exited = LinuxBoundedSessionProcess.execute(command("/bin/sh", "-c", "exit 23"))
        assertEquals(23, exited.exitCode)
        assertNull(exited.signal)

        val signaled = LinuxBoundedSessionProcess.execute(command("/bin/sh", "-c", "kill -TERM \$\$"))
        assertNull(signaled.exitCode)
        assertEquals(15, signaled.signal)
    }

    @Test
    fun outputOverflowKillsAnOrdinarySameSessionChildAndReapsTheLeader() {
        requireLinux()
        val marker = Files.createTempFile("bounded-session-child-", ".pid")
        try {
            val failure = assertFailsWith<LinuxBoundedSessionOutputLimitException> {
                LinuxBoundedSessionProcess.execute(
                    command(
                        "/bin/sh",
                        "-c",
                        "sleep 30 & child=\$!; printf '%s' \"\$child\" > '${marker}'; " +
                            "while :; do printf 0123456789; done",
                        maximumStdoutBytes = 64,
                    ),
                )
            }
            assertTrue(failure.message.orEmpty().contains("stdout"))
            val child = Files.readString(marker).trim().toLong()
            assertEventuallyAbsent(child)
        } finally {
            Files.deleteIfExists(marker)
        }
    }

    @Test
    fun timeoutKillsAnOrdinarySameSessionChildAndReapsTheLeader() {
        requireLinux()
        val marker = Files.createTempFile("bounded-session-timeout-child-", ".pid")
        try {
            assertFailsWith<LinuxBoundedSessionTimeoutException> {
                LinuxBoundedSessionProcess.execute(
                    command(
                        "/bin/sh",
                        "-c",
                        "sleep 30 & child=\$!; printf '%s' \"\$child\" > '${marker}'; wait",
                        timeout = Duration.ofMillis(100),
                    ),
                )
            }
            val child = Files.readString(marker).trim().toLong()
            assertEventuallyAbsent(child)
        } finally {
            Files.deleteIfExists(marker)
        }
    }

    @Test
    fun validatesHardBoundsBeforeStartingAnything() {
        assertFailsWith<IllegalArgumentException> {
            LinuxBoundedSessionCommand(
                arguments = listOf("/bin/true"),
                environment = emptyMap(),
                timeout = Duration.ofSeconds(31),
                maximumStdoutBytes = 1,
                maximumStderrBytes = 1,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            LinuxBoundedSessionCommand(
                arguments = listOf("/bin/true"),
                environment = emptyMap(),
                timeout = Duration.ofSeconds(1),
                maximumStdoutBytes = 1024 * 1024 + 1,
                maximumStderrBytes = 1,
            )
        }
    }

    @Test
    fun rejectsRelativeOrLexicallyNonNormalizedExecutablePathsBeforeSpawn() {
        listOf("bin/true", "/bin/../bin/true", "/").forEach { executable ->
            assertFailsWith<IllegalArgumentException> {
                LinuxBoundedSessionCommand(
                    arguments = listOf(executable),
                    environment = emptyMap(),
                    timeout = Duration.ofSeconds(1),
                    maximumStdoutBytes = 1,
                    maximumStderrBytes = 1,
                )
            }
        }
    }

    @Test
    fun pidfdOpenFailureStillSignalsAndReapsTheReservedLeader() {
        requireLinux()
        var spawnedPid = -1L
        val started = System.nanoTime()
        val failure = assertFailsWith<LinuxBoundedSessionException> {
            LinuxBoundedSessionProcess.executeForNonAuthoritativeTest(
                command("/bin/sleep", "30"),
                NonAuthoritativeSessionTestHook(
                    forcePidfdOpenFailure = true,
                    spawnedPidObserver = { spawnedPid = it },
                ),
            )
        }
        assertTrue(failure !is LinuxBoundedSessionCleanupException)
        assertTrue(failure.message.orEmpty().contains("pidfd-pinned"))
        assertTrue(spawnedPid > 0L)
        assertFalse(Files.exists(Path.of("/proc", spawnedPid.toString())))
        assertTrue(Duration.ofNanos(System.nanoTime() - started) < Duration.ofSeconds(2))
    }

    @Test
    fun reservesEveryClosedStandardDescriptorBeforeAllocatingPipes() {
        for (mask in 0..7) {
            val open = (0..2).filterTo(linkedSetOf()) { mask and (1 shl it) != 0 }
            val initiallyOpen = open.toSet()
            val closed = mutableListOf<Int>()
            fun lowestAvailable(): Int = generateSequence(0) { it + 1 }.first { it !in open }
            val reserved = reserveClosedStandardDescriptors(
                descriptorIsOpen = { it in open },
                openNullReadWrite = { lowestAvailable().also(open::add) },
                closeDescriptor = { closed += it; open -= it },
            )
            assertEquals((0..2).filter { it !in initiallyOpen }, reserved)
            assertTrue((0..2).all { it in open })
            assertTrue(closed.isEmpty())
        }

        val mismatchClosed = mutableListOf<Int>()
        assertFailsWith<LinuxBoundedSessionException> {
            reserveClosedStandardDescriptors(
                descriptorIsOpen = { false },
                openNullReadWrite = { 7 },
                closeDescriptor = mismatchClosed::add,
            )
        }
        assertEquals(listOf(7), mismatchClosed)
    }

    private fun command(
        vararg arguments: String,
        environment: Map<String, String> = emptyMap(),
        timeout: Duration = Duration.ofSeconds(2),
        maximumStdoutBytes: Int = 1024,
        maximumStderrBytes: Int = 1024,
    ): LinuxBoundedSessionCommand = LinuxBoundedSessionCommand(
        arguments = arguments.toList(),
        environment = environment,
        timeout = timeout,
        maximumStdoutBytes = maximumStdoutBytes,
        maximumStderrBytes = maximumStderrBytes,
    )

    private fun assertEventuallyAbsent(pid: Long) {
        val path = Path.of("/proc", pid.toString())
        repeat(100) {
            if (!Files.exists(path)) return
            Thread.sleep(10)
        }
        assertFalse(Files.exists(path), "bounded session child remained live: $pid")
    }

    private fun requireLinux() {
        assertEquals("Linux", System.getProperty("os.name"))
    }
}
