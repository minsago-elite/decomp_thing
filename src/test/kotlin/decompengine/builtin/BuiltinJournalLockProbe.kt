package decompengine.builtin

import java.nio.channels.FileChannel
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

    /** Returns LOCKED or FREE as observed by a fresh JVM. */
    fun observe(path: Path): String {
        val classPath = listOf(BuiltinJournalLockProbe::class.java, KotlinVersion::class.java).joinToString(java.io.File.pathSeparator) {
            Path.of(requireNotNull(it.protectionDomain.codeSource).location.toURI()).toString()
        }
        val process = ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-cp", classPath, BuiltinJournalLockProbe::class.java.name, path.toString()).redirectErrorStream(true).start()
        val output = process.inputStream.readAllBytes().toString(Charsets.UTF_8)
        check(process.waitFor(120, TimeUnit.SECONDS)) { "lock probe timed out" }
        check(process.exitValue() == 0) { "lock probe failed: $output" }
        return output
    }
}
