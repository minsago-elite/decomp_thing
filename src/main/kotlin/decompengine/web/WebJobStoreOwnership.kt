package decompengine.web

import java.nio.channels.FileChannel
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE
import java.nio.file.StandardOpenOption.WRITE

/** Resolve existing ancestors without creating storage or guessing that an unreadable path is absent. */
internal fun canonicalWebJobStoreRoot(
    root: Path, knownAbsent: (Path) -> Boolean, realPath: (Path) -> Path,
): Path {
    require(root.isAbsolute) { "Web job storage path must be absolute" }
    var existing = root.normalize()
    val missing = java.util.ArrayDeque<Path>()
    while (knownAbsent(existing)) {
        missing.addFirst(checkNotNull(existing.fileName) { "Web job storage path has no existing ancestor" })
        existing = checkNotNull(existing.parent) { "Web job storage path has no existing ancestor" }
    }
    var canonical = realPath(existing)
    for (name in missing) canonical = canonical.resolve(name)
    return canonical.normalize()
}

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
            val canonicalRoot = canonicalWebJobStoreRoot(root.toAbsolutePath().normalize(),
                knownAbsent = { Files.notExists(it, NOFOLLOW_LINKS) }, realPath = { it.toRealPath() })
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
