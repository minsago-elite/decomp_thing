package decompengine.doctor

import decompengine.oracle.fulltree.inControlTemporaryDirectory
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class BoundedCommandProbeTest {
    @Test
    fun `exact byte ceiling accepts UTF8 output with stderr merged in order`() {
        val expected = "café\nλ\n"
        val probe = BoundedSystemCommandProbe(limits(outputBytes = expected.toByteArray(Charsets.UTF_8).size))

        val result = probe.run(listOf(
            "/bin/sh", "-c", "printf '%s' \"\$1\"; printf '%s' \"\$2\" >&2",
            "authored-output", "café\n", "λ\n",
        ), null)

        assertEquals(0, result.exitCode)
        assertEquals(expected, result.output)
    }

    @Test
    fun `one ordinary byte beyond the output ceiling reports exhaustion`() {
        val probe = BoundedSystemCommandProbe(limits(outputBytes = 5))

        val failure = assertFailsWith<CommandProbeLimitException> {
            probe.run(printf("abcdef"), null)
        }

        assertEquals(CommandProbeLimitKind.OUTPUT_LIMIT, failure.kind)
    }

    @Test
    fun `earlier runner or parent deadline stops the owned worker`() = inControlTemporaryDirectory { root ->
        for ((index, timeouts) in listOf(5_000L to 300L, 300L to 5_000L).withIndex()) {
            val caseRoot = root.resolve("case-$index").createDirectories()
            withOwnedSleepCommand(caseRoot) { command, pidFile ->
                val probe = BoundedSystemCommandProbe(limits(milliseconds = timeouts.first))
                val parent = CommandProbeBudget(limits(milliseconds = timeouts.second))
                val started = System.nanoTime()

                val failure = assertFailsWith<CommandProbeLimitException> {
                    probe.run(command, caseRoot, parent)
                }

                assertEquals(CommandProbeLimitKind.TIMEOUT, failure.kind)
                assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(3), "probe used the longer allowance")
                assertWorkerStopped(pidFile)
            }
        }
    }

    @Test
    fun `caller interruption propagates directly after owned worker cleanup`() = inControlTemporaryDirectory { root ->
        withOwnedSleepCommand(root) { command, pidFile ->
            val failure = AtomicReference<Throwable?>()
            val probe = BoundedSystemCommandProbe(limits())
            val worker = Thread {
                try {
                    probe.run(command, root)
                } catch (problem: Throwable) {
                    failure.set(problem)
                }
            }
            var process: ProcessHandle? = null
            try {
                worker.start()
                process = awaitOwnedWorker(pidFile, worker, failure)
                assertTrue(process.isAlive)

                worker.interrupt()
                worker.join(3_000)

                assertFalse(worker.isAlive, "cancelled probe call did not return")
                assertIs<InterruptedException>(failure.get())
                assertFalse(process.isAlive, "cancelled probe retained its owned worker")
            } finally {
                if (worker.isAlive) worker.interrupt()
                process?.let { if (it.isAlive) it.destroyForcibly() }
                worker.join(3_000)
            }
        }
    }

    @Test
    fun `expired parent rejects before launching a marker command`() = inControlTemporaryDirectory { root ->
        val marker = root.resolve("launched")
        val probe = BoundedSystemCommandProbe(limits())
        val parent = CommandProbeBudget(limits(milliseconds = 10))
        Thread.sleep(25)

        val failure = assertFailsWith<CommandProbeLimitException> {
            probe.run(listOf("/usr/bin/touch", marker.toString()), root, parent)
        }

        assertEquals(CommandProbeLimitKind.TIMEOUT, failure.kind)
        assertFalse(marker.exists())
    }

    @Test
    fun `successful commands consume one shared output allowance`() {
        val probe = BoundedSystemCommandProbe(limits(outputBytes = 64))
        val parent = CommandProbeBudget(limits(outputBytes = 4))

        assertEquals("é", probe.run(printf("é"), null, parent).output)
        assertEquals(2, parent.remainingOutputBytes())
        assertEquals("ok", probe.run(printf("ok"), null, parent).output)
        assertEquals(0, parent.remainingOutputBytes())
        val failure = assertFailsWith<CommandProbeLimitException> {
            probe.run(printf("x"), null, parent)
        }

        assertEquals(CommandProbeLimitKind.OUTPUT_LIMIT, failure.kind)
    }

    @Test
    fun `stricter runner output limit charges the parent without exhausting its remaining allowance`() {
        val probe = BoundedSystemCommandProbe(limits(outputBytes = 3))
        val parent = CommandProbeBudget(limits(outputBytes = 64))

        val failure = assertFailsWith<CommandProbeLimitException> {
            probe.run(printf("four"), null, parent)
        }

        assertEquals(CommandProbeLimitKind.OUTPUT_LIMIT, failure.kind)
        assertEquals(60, parent.remainingOutputBytes())
        assertEquals("ok", probe.run(printf("ok"), null, parent).output)
        assertEquals(58, parent.remainingOutputBytes())
    }

    @Test
    fun `probe forwards its working directory and closes stdin`() = inControlTemporaryDirectory { root ->
        val directory = root.resolve("working directory").createDirectories()
        directory.resolve("authored.txt").writeText("authored working directory\n")
        val probe = BoundedSystemCommandProbe(limits())

        val result = probe.run(listOf(
            "/bin/sh", "-c", "cat authored.txt; if IFS= read -r line; then exit 19; fi; printf 'stdin closed\\n'",
        ), directory)

        assertEquals(0, result.exitCode)
        assertEquals("authored working directory\nstdin closed\n", result.output)
    }

    private fun limits(milliseconds: Long = 5_000, outputBytes: Int = 1_024) = CommandProbeLimits(
        maximumWallClockMillis = milliseconds,
        maximumOutputBytes = outputBytes,
        cleanupMillis = 500,
    )

    private fun printf(text: String) = listOf("/usr/bin/printf", "%s", text)

    private fun awaitOwnedWorker(
        pidFile: Path,
        worker: Thread,
        failure: AtomicReference<Throwable?>,
    ): ProcessHandle {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (worker.isAlive && System.nanoTime() < deadline) {
            val pid = if (pidFile.exists()) pidFile.readText().trim().toLongOrNull() else null
            if (pid != null) return ProcessHandle.of(pid).orElseThrow()
            Thread.sleep(5)
        }
        error("owned probe did not start: ${failure.get()}")
    }

    private fun assertWorkerStopped(pidFile: Path) {
        assertTrue(pidFile.exists(), "owned worker should have started before its deadline")
        val pid = pidFile.readText().trim().toLong()
        assertFalse(ProcessHandle.of(pid).map { it.isAlive }.orElse(false), "owned probe worker is still alive")
    }

    private inline fun withOwnedSleepCommand(root: Path, block: (List<String>, Path) -> Unit) {
        val pidFile = root.resolve("worker.pid")
        val command = listOf(
            "/bin/sh", "-c", "printf '%s\\n' \"\$\$\" > \"\$1\"; exec /bin/sleep 10",
            "authored-probe", pidFile.toString(),
        )
        try {
            block(command, pidFile)
        } finally {
            if (pidFile.exists()) {
                val pid = pidFile.readText().trim().toLongOrNull()
                pid?.let { ProcessHandle.of(it).orElse(null) }?.let { process ->
                    if (process.isAlive) {
                        process.destroyForcibly()
                        process.onExit().get(2, TimeUnit.SECONDS)
                    }
                }
            }
        }
    }
}
