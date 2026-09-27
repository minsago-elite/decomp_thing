package decompengine.jobs

import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes

/** Coordinate in-process callers before opening another descriptor for a POSIX-locked inode.
 * Closing any descriptor for that inode can release process-scoped native locks.
 */
internal class AgentProgressJournalLease private constructor(
    private val key: Any, private val channel: FileChannel, private val lock: FileLock,
) : AutoCloseable {
    private var closed = false
    @Synchronized override fun close() {
        if (closed) return
        closed = true
        try { if (lock.isValid) lock.release() } finally {
            try { channel.close() } finally { synchronized(owners) { owners.remove(key) } }
        }
    }

    companion object {
        private val owners = mutableSetOf<Any>()

        fun tryAcquire(directory: Path, open: () -> FileChannel): AgentProgressJournalLease? {
            val attributes = Files.readAttributes(directory, BasicFileAttributes::class.java)
            require(attributes.isDirectory) { "progress lease requires a directory" }
            val key = directory.fileSystem to (attributes.fileKey() ?: directory.toRealPath())
            synchronized(owners) { if (!owners.add(key)) return null }
            var channel: FileChannel? = null
            try {
                channel = open()
                val lock = try { channel.tryLock() } catch (_: OverlappingFileLockException) { null }
                if (lock != null) return AgentProgressJournalLease(key, channel, lock)
                channel.close()
                synchronized(owners) { owners.remove(key) }
                return null
            } catch (failure: Throwable) {
                try { channel?.close() } finally { synchronized(owners) { owners.remove(key) } }
                throw failure
            }
        }
    }
}
