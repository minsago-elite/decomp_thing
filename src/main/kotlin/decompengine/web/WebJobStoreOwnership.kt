package decompengine.web

import java.nio.channels.FileChannel
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE
import java.nio.file.StandardOpenOption.WRITE

/** Cooperative web-server ownership; the lock file must never be unlinked while in use. */
internal class WebJobStoreOwnership private constructor(
    private val root: Path,
    private val channel: FileChannel,
) : AutoCloseable {
    override fun close() = synchronized(owners) {
        channel.close()
        if (owners[root] === this) owners.remove(root)
        Unit
    }

    companion object {
        private val owners = mutableMapOf<Path, WebJobStoreOwnership>()

        fun acquire(root: Path): WebJobStoreOwnership {
            Files.createDirectories(root)
            val canonicalRoot = root.toRealPath()
            return synchronized(owners) {
                // Some platforms release process locks when any channel to that file closes.
                // Reject local contenders before opening a second channel.
                check(canonicalRoot !in owners) { "Job store already has a live web server owner" }
                val channel = FileChannel.open(canonicalRoot.resolve(".web-owner.lock"), CREATE, WRITE, NOFOLLOW_LINKS)
                try {
                    val lock = try { channel.tryLock() } catch (_: OverlappingFileLockException) { null }
                    check(lock != null) { "Job store already has a live web server owner" }
                    WebJobStoreOwnership(canonicalRoot, channel).also { owners[canonicalRoot] = it }
                } catch (failure: Exception) {
                    try { channel.close() } catch (cleanup: Exception) { failure.addSuppressed(cleanup) }
                    throw failure
                }
            }
        }
    }
}
