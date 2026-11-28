package decompengine.exploration

import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

internal data class OwnedExplorationOutput(val exitCode: Int, val stdout: String, val stderr: String)

/**
 * One ownership scope covers both helper exit and output completion. Readers are dedicated owned
 * threads, not common-pool tasks. Remember descendant HANDLES while the helper lives: discovering
 * descendants only after its exit loses reparented pipe writers. This is cooperative helper-tree
 * cleanup, not containment against fork/exit races or deliberate reparenting/session escape (#71).
 */
internal fun collectOwnedExplorationProcess(process: Process): OwnedExplorationOutput {
    val descendants = linkedSetOf<ProcessHandle>()
    fun rememberDescendants() { process.descendants().use { members -> members.forEach(descendants::add) } }
    val stdout = FutureTask(Callable { process.inputStream.bufferedReader().use { it.readText() } })
    val stderr = FutureTask(Callable { process.errorStream.bufferedReader().use { it.readText() } })
    val readers = listOf(Thread(stdout, "decomp-exploration-stdout"), Thread(stderr, "decomp-exploration-stderr"))
    var reinterrupt = false
    var primary: Throwable? = null

    fun stop(member: ProcessHandle, exited: () -> Boolean) {
        if (exited()) return
        member.destroyForcibly()
        while (!exited()) {
            try { member.onExit().get(25, TimeUnit.MILLISECONDS) }
            catch (_: InterruptedException) { reinterrupt = true }
            catch (_: TimeoutException) { member.destroyForcibly() }
            catch (_: ExecutionException) { }
        }
    }
    fun stopDescendants() {
        // Deepest first, while a surviving parent can still reap its children. Zombies hold no pipe.
        descendants.toList().reversed().forEach { member -> stop(member) { !member.isAlive || isZombie(member.pid()) } }
    }
    try {
        rememberDescendants()
        readers.forEach { it.isDaemon = true; it.start() }
        do {
            rememberDescendants()
        } while (!process.waitFor(10, TimeUnit.MILLISECONDS))
        // A successful leader must not leave an observed descendant retaining a pipe indefinitely.
        stopDescendants()
        return OwnedExplorationOutput(process.exitValue(), stdout.get(), stderr.get())
    } catch (failure: Throwable) {
        primary = failure
        throw failure
    } finally {
        reinterrupt = Thread.interrupted() || reinterrupt
        rememberDescendants()
        stopDescendants()
        stop(process.toHandle()) { !process.isAlive } // JVM reaps its own direct child.
        // Kill writers BEFORE closing streams: ProcessPipeInputStream.close may wait for a read lock.
        var closeFailure: java.io.IOException? = null
        for (stream in listOf(process.outputStream, process.inputStream, process.errorStream)) {
            try { stream.close() } catch (failure: java.io.IOException) { closeFailure = closeFailure ?: failure }
        }
        for (reader in readers) while (reader.isAlive) {
            try { reader.join(25) } catch (_: InterruptedException) { reinterrupt = true }
        }
        if (reinterrupt) Thread.currentThread().interrupt()
        closeFailure?.let { failure -> primary?.addSuppressed(failure) ?: throw failure }
    }
}
