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
    private var channel: FileChannel?,
) : AutoCloseable {
    override fun close() = synchronized(owners) {
        channel?.close()
        channel = null
        if (owners[root] === this) owners.remove(root)
        Unit
    }

    /**
     * Create the cross-JVM lock file once the storage root exists. A server that started before its
     * root was created only holds in-process exclusion until storage is initialized; a competing
     * process holding the lock is rejected before any storage is opened.
     */
    internal fun ensureLockFile() {
        if (channel != null) return
        synchronized(owners) {
            if (channel != null) return
            Files.createDirectories(root)
            val opened = FileChannel.open(root.resolve(".web-owner.lock"), CREATE, WRITE, NOFOLLOW_LINKS)
            try {
                val lock = try { opened.tryLock() } catch (_: OverlappingFileLockException) { null }
                check(lock != null) { "Job store already has a live web server owner" }
                channel = opened
            } catch (failure: Exception) {
                try { opened.close() } catch (cleanup: Exception) { failure.addSuppressed(cleanup) }
                throw failure
            }
        }
    }

    companion object {
        private val owners = mutableMapOf<Path, WebJobStoreOwnership>()

        fun acquire(root: Path): WebJobStoreOwnership {
            val canonicalRoot = if (Files.exists(root, NOFOLLOW_LINKS)) root.toRealPath() else root.toAbsolutePath().normalize()
            return synchronized(owners) {
                // Some platforms release process locks when any channel to that file closes.
                // Reject local contenders before opening a second channel.
                check(canonicalRoot !in owners) { "Job store already has a live web server owner" }
                if (Files.isDirectory(canonicalRoot, NOFOLLOW_LINKS)) {
                    val channel = FileChannel.open(canonicalRoot.resolve(".web-owner.lock"), CREATE, WRITE, NOFOLLOW_LINKS)
                    try {
                        val lock = try { channel.tryLock() } catch (_: OverlappingFileLockException) { null }
                        check(lock != null) { "Job store already has a live web server owner" }
                        WebJobStoreOwnership(canonicalRoot, channel).also { owners[canonicalRoot] = it }
                    } catch (failure: Exception) {
                        try { channel.close() } catch (cleanup: Exception) { failure.addSuppressed(cleanup) }
                        throw failure
                    }
                } else {
                    // The storage root does not exist yet; in-process exclusion only, upgraded on first
                    // storage initialization so read-only servers never create storage.
                    WebJobStoreOwnership(canonicalRoot, null).also { owners[canonicalRoot] = it }
                }
            }
        }
    }
}
