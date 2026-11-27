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
import kotlin.test.assertTrue

/** Inert helper processes only: no angr, Python or analyzed binary runs here. */
class OwnedExplorationProcessTest {
    @Test
    fun `interrupting angr generation kills and awaits its whole helper process tree`() =
        interruptedHelper("#!/bin/sh\nsleep 300 &\necho \"$$ $!\" > '%s'\nwait\n")

    @Test
    fun `a descendant its parent never reaps cannot hang cancellation`() =
        // The helper execs into a process that never waits: its killed child stays a zombie until the helper dies.
        interruptedHelper("#!/bin/sh\nsleep 300 &\necho \"$$ $!\" > '%s'\nexec sleep 400\n")

    @Test
    fun `interrupting strings hints kills a helper whose child still holds its output pipe`() =
        // The child inherits stdout, so a blocking pipe read would never reach EOF before the kill.
        interruptedHelper("#!/bin/sh\nsleep 300 &\necho \"$$ $!\" > '%s'\nwait\n") { helper, directory ->
            StaticHintGenerator(stringsPath = helper).generate(directory.resolve("binary"))
        }

    @Test
    fun `successful strings helper exit cleans a descendant that retains stdout`() =
        exitedHelper { helper, directory -> StaticHintGenerator(stringsPath = helper).generate(directory.resolve("binary")) }

    @Test
    fun `successful angr helper exit cleans a descendant that retains both pipes`() =
        exitedHelper { helper, directory ->
            PythonAngrExplorer(python = Path.of("/bin/true"), timeout = helper).generate(directory.resolve("binary"))
        }

    private fun exitedHelper(run: (Path, Path) -> Unit) {
        val parent = Files.createDirectories(Path.of("build/test-tmp/owned-exploration").toAbsolutePath())
        val directory = Files.createTempDirectory(parent, "exited-")
        var worker: Thread? = null
        var ownedPids = emptyList<Long>()
        try {
            val pids = directory.resolve("pids")
            val helper = directory.resolve("helper").also {
                // The leader exits normally; its observed child retains stdout/stderr for five minutes.
                it.writeText("#!/bin/sh\nsleep 300 &\necho \"$$ $!\" > '$pids'\nsleep 0.3\nexit 0\n")
                it.toFile().setExecutable(true)
            }
            worker = Thread {
                // Empty output is intentionally not valid angr JSON. We care about owned completion.
                try { run(helper, directory) } catch (_: IllegalStateException) { }
            }.apply { isDaemon = true; start() }
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (!Files.exists(pids) && System.nanoTime() < deadline) Thread.sleep(10)
            ownedPids = pids.readText().trim().split(' ').map(String::toLong)
            worker.join(5_000)
            assertFalse(worker.isAlive, "normal helper exit left an inherited-pipe reader blocked")
            ownedPids.forEach { pid ->
                assertTrue(ProcessHandle.of(pid).map { !it.isAlive || isZombie(pid) }.orElse(true), "helper member outlived completion")
            }
            assertFalse(Thread.getAllStackTraces().keys.any { it.isAlive && it.name.startsWith("decomp-exploration-") },
                "owned reader outlived helper completion")
        } finally {
            // Even a failed regression only stops its own inert fixture processes.
            ownedPids.reversed().forEach { pid -> ProcessHandle.of(pid).ifPresent { it.destroyForcibly() } }
            worker?.interrupt(); worker?.join(5_000)
            directory.toFile().deleteRecursively()
        }
    }

    private fun interruptedHelper(script: String, run: (Path, Path) -> Unit = { helper, directory ->
        PythonAngrExplorer(python = Path.of("/bin/true"), timeout = helper).generate(directory.resolve("binary"))
    }) {
        val parent = Files.createDirectories(Path.of("build/test-tmp/owned-exploration").toAbsolutePath())
        val directory = Files.createTempDirectory(parent, "angr-")
        try {
            val pids = directory.resolve("pids")
            // Stands in for /usr/bin/timeout: it starts a long-lived child, like timeout starting Python.
            val helper = directory.resolve("timeout").also {
                it.writeText(script.format(pids))
                it.toFile().setExecutable(true)
            }
            val failure = AtomicReference<Throwable>()
            val worker = Thread {
                try { run(helper, directory) }
                catch (thrown: Throwable) { failure.set(thrown) }
            }
            worker.start()
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while ((!Files.exists(pids) || pids.readText().trim().split(' ').size < 2) && System.nanoTime() < deadline) Thread.sleep(10)
            val (shell, child) = pids.readText().trim().split(' ').map(String::toLong)
            worker.interrupt(); worker.join(15_000)
            assertFalse(worker.isAlive, "cancellation did not return")
            assertIs<InterruptedException>(failure.get())
            // The generator returned only after every helper exited (an unreaped zombie holds nothing).
            fun stopped(pid: Long) = ProcessHandle.of(pid).map { !it.isAlive || isZombie(pid) }.orElse(true)
            assertTrue(stopped(shell), "helper outlived cancellation")
            assertTrue(stopped(child), "helper child outlived cancellation")
        } finally { directory.toFile().deleteRecursively() }
    }
}
