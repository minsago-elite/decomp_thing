package decompengine.exploration

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs

/** Inert helper processes only: no angr, Python or analyzed binary runs here. */
class OwnedExplorationProcessTest {
    @Test
    fun `interrupting angr generation kills and awaits its whole helper process tree`() {
        val parent = Files.createDirectories(Path.of("build/test-tmp/owned-exploration").toAbsolutePath())
        val directory = Files.createTempDirectory(parent, "angr-")
        try {
            val pids = directory.resolve("pids")
            // Stands in for /usr/bin/timeout: it starts a long-lived child, like timeout starting Python.
            val helper = directory.resolve("timeout").also {
                it.writeText("#!/bin/sh\nsleep 300 &\necho \"$$ $!\" > '$pids'\nwait\n")
                it.toFile().setExecutable(true)
            }
            val failure = AtomicReference<Throwable>()
            val worker = Thread {
                try { PythonAngrExplorer(python = Path.of("/bin/true"), timeout = helper).generate(directory.resolve("binary")) }
                catch (thrown: Throwable) { failure.set(thrown) }
            }
            worker.start()
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while ((!Files.exists(pids) || pids.readText().trim().split(' ').size < 2) && System.nanoTime() < deadline) Thread.sleep(10)
            val (shell, sleeper) = pids.readText().trim().split(' ').map(String::toLong)
            worker.interrupt(); worker.join(10_000)
            assertFalse(worker.isAlive)
            assertIs<InterruptedException>(failure.get())
            // The generator returned only after every helper exited.
            assertFalse(ProcessHandle.of(shell).map(ProcessHandle::isAlive).orElse(false), "helper shell outlived cancellation")
            assertFalse(ProcessHandle.of(sleeper).map(ProcessHandle::isAlive).orElse(false), "helper child outlived cancellation")
        } finally { directory.toFile().deleteRecursively() }
    }
}
