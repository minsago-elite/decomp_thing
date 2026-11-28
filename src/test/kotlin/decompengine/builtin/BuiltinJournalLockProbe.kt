package decompengine.builtin

import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.util.concurrent.TimeUnit

/**
 * Child-process probe for the journal's cross-process lock. POSIX record locks belong to a process, and the
 * JVM's own lock table hides them from other channels in the same JVM, so only another process can observe
 * whether the operating-system lock is still held.
 */
object BuiltinJournalLockProbe {
    @JvmStatic fun main(args: Array<String>) {
        FileChannel.open(Path.of(args.single()), READ, WRITE, NOFOLLOW_LINKS).use { channel ->
            val lock = channel.tryLock()
            print(if (lock == null) "LOCKED" else "FREE")
            lock?.release()
        }
    }

    /**
     * Returns LOCKED or FREE as observed by a fresh JVM. Output goes to a file under [scratch] so waiting never depends
     * on stream EOF. The wait has a deadline, and a surviving child is forcibly terminated and reaped.
     */
    fun observe(path: Path, scratch: Path): String {
        val classPath = listOf(BuiltinJournalLockProbe::class.java, KotlinVersion::class.java).joinToString(java.io.File.pathSeparator) {
            Path.of(requireNotNull(it.protectionDomain.codeSource).location.toURI()).toString()
        }
        val output = Files.createTempFile(scratch, "journal-lock-probe-", ".out")
        val process = ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-cp", classPath, BuiltinJournalLockProbe::class.java.name, path.toString())
            .redirectErrorStream(true).redirectOutput(output.toFile()).redirectInput(ProcessBuilder.Redirect.from(java.io.File("/dev/null")))
            .start()
        var primary: Throwable? = null
        try {
            check(process.waitFor(PROBE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) { "lock probe timed out" }
            val text = Files.readString(output)
            check(process.exitValue() == 0) { "lock probe failed: $text" }
            return text
        } catch (failure: Throwable) {
            primary = failure; throw failure
        } finally {
            if (process.isAlive) {
                process.destroyForcibly()
                val survived = reap(process)
                if (survived != null) { if (primary != null) primary.addSuppressed(survived) else throw survived }
            }
        }
    }

    /**
     * Waits for a killed child against one deadline, continuing through interrupts so the test never exits before the
     * child is confirmed stopped. The interrupt status is restored afterwards. Returns a failure if the child survives.
     */
    private fun reap(process: Process): Throwable? {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(REAP_TIMEOUT_SECONDS)
        var interrupted = false
        try {
            while (true) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) return if (process.isAlive) IllegalStateException("lock probe survived forced termination") else null
                try {
                    if (process.waitFor(remaining, TimeUnit.NANOSECONDS)) return null
                } catch (_: InterruptedException) {
                    interrupted = true
                }
            }
        } finally {
            if (interrupted) Thread.currentThread().interrupt()
        }
    }

    private const val PROBE_TIMEOUT_SECONDS = 120L
    private const val REAP_TIMEOUT_SECONDS = 30L
}
