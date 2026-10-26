package decompengine.git

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.SecureDirectoryStream
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.BasicFileAttributeView

/**
 * Import object bytes through pinned directory descriptors. NOFOLLOW_LINKS on Files.copy would
 * preserve a raced-in link, not reject it. Here the source open refuses links and the destination
 * is always a new regular file. Renaming a source ancestor cannot redirect descriptor-relative
 * opens. Providers without secure directory streams fail closed rather than use path-based copy.
 */
internal object GitImportObjectCopy {
    /** Files and directories together: directory breadth is charged before anything is created. */
    const val MAX_ENTRIES = 100_000
    private const val MAX_BYTES = 512L * 1024 * 1024

    /** [beforeOpen] is an internal deterministic replacement-race test seam; [maxEntries] is lowered only by tests. */
    fun copy(source: Path, target: Path, maxEntries: Int = MAX_ENTRIES, beforeOpen: (Path) -> Unit = {}) {
        var entries = 0
        var bytes = 0L
        fun walk(directory: SecureDirectoryStream<Path>, destination: Path, relative: Path, depth: Int) {
            for (entry in directory) {
                GitStorage.checkInterrupted()
                val name = entry.fileName
                val path = relative.resolve(name)
                val attributes = directory.getFileAttributeView(name, BasicFileAttributeView::class.java, NOFOLLOW_LINKS).readAttributes()
                if (attributes.isSymbolicLink || (!attributes.isDirectory && !attributes.isRegularFile)) unsupported()
                if (depth == 0 && name.toString() == "info") continue
                beforeOpen(path)
                if (attributes.isDirectory) {
                    if (depth >= 3) unsupported()
                    // Empty directories cost inodes too, so they count against the same entry quota.
                    if (++entries > maxEntries) tooLarge()
                    directory.newDirectoryStream(name, NOFOLLOW_LINKS).use { child ->
                        walk(child, GitStorage.directories(destination, name.toString()), path, depth + 1)
                    }
                } else {
                    if (++entries > maxEntries || attributes.size() > MAX_BYTES - bytes) tooLarge()
                    if (name.toString().startsWith("tmp_") || name.toString().endsWith(".lock")) continue
                    directory.newByteChannel(name, setOf(READ, NOFOLLOW_LINKS)).use { input ->
                        // Size is taken from the opened descriptor as well, not just the walk-time stat.
                        if (input.size() != attributes.size()) unsupported()
                        Files.newByteChannel(destination.resolve(name), setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS)).use { output ->
                            val buffer = ByteBuffer.allocate(64 * 1024)
                            var copied = 0L
                            while (true) {
                                GitStorage.checkInterrupted()
                                buffer.clear()
                                val count = input.read(buffer)
                                if (count < 0) break
                                if (count.toLong() > MAX_BYTES - bytes) tooLarge()
                                bytes += count
                                copied += count
                                if (copied > attributes.size()) unsupported()
                                buffer.flip()
                                while (buffer.hasRemaining()) output.write(buffer)
                            }
                            if (copied != attributes.size()) unsupported()
                        }
                    }
                }
            }
        }
        try {
            openPinned(source.toAbsolutePath().normalize()).use { directory ->
                walk(directory, target, Path.of(""), 0)
            }
        } catch (failure: java.io.InterruptedIOException) {
            throw failure
        } catch (_: IOException) {
            unsupported()
        }
    }

    /** Pin every ancestor from the filesystem root, rejecting links at the actual directory open. */
    private fun openPinned(path: Path): SecureDirectoryStream<Path> {
        val stream = Files.newDirectoryStream(path.root)
        if (stream !is SecureDirectoryStream<Path>) {
            stream.close()
            unsupported()
        }
        var current: SecureDirectoryStream<Path> = stream
        try {
            for (component in path) {
                GitStorage.checkInterrupted()
                val next = current.newDirectoryStream(component, NOFOLLOW_LINKS)
                current.close()
                current = next
            }
            return current
        } catch (failure: Throwable) {
            current.close()
            throw failure
        }
    }

    private fun unsupported(): Nothing = throw GitOperationFailure("REPOSITORY_UNSUPPORTED",
        "The repository object store is not safely readable as ordinary files and directories.")
    private fun tooLarge(): Nothing = throw GitOperationFailure("REPOSITORY_UNSUPPORTED", "The repository exceeds the import size limits.")
}
