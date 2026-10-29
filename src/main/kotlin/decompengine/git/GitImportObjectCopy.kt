package decompengine.git

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.BasicFileAttributes

/**
 * Import object bytes through pinned directory descriptors. The shared Linux boundary opens each
 * leaf with O_PATH, authenticates its descriptor as a regular file, then reopens that exact inode
 * with O_NONBLOCK for reading. A raced-in FIFO therefore cannot block the worker at open, and a
 * link or renamed ancestor cannot redirect the read. Destinations are always new regular files.
 * Unsupported native/procfs boundaries fail closed; there is no pathname-copy fallback.
 */
internal object GitImportObjectCopy {
    /** Files and directories together: directory breadth is charged before anything is created. */
    const val MAX_ENTRIES = 100_000
    private const val MAX_BYTES = 512L * 1024 * 1024

    /** [beforeOpen] is an internal deterministic replacement-race test seam; [maxEntries] is lowered only by tests. */
    fun copy(source: Path, target: Path, maxEntries: Int = MAX_ENTRIES, beforeOpen: (Path) -> Unit = {}) {
        var entries = 0
        var bytes = 0L
        fun walk(directory: LinuxDescriptor, destination: Path, relative: Path, depth: Int) {
            // Only this process's kernel-owned magic link is followed, while we own the descriptor.
            Files.newDirectoryStream(LinuxFilesystemSyscalls.descriptorPath(directory)).use { children ->
                for (entry in children) {
                    GitStorage.checkInterrupted()
                    val name = entry.fileName
                    val path = relative.resolve(name)
                    val attributes = Files.readAttributes(entry, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
                    if (attributes.isSymbolicLink || (!attributes.isDirectory && !attributes.isRegularFile)) unsupported()
                    if (depth == 0 && name.toString() == "info") continue
                    beforeOpen(path)
                    GitStorage.checkInterrupted()
                    if (attributes.isDirectory) {
                        if (depth >= 3) unsupported()
                        // Empty directories cost inodes too, so they count against the same entry quota.
                        if (++entries > maxEntries) tooLarge()
                        LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, name.toString()).use { child ->
                            walk(child, GitStorage.directories(destination, name.toString()), path, depth + 1)
                        }
                    } else {
                        if (++entries > maxEntries || attributes.size() > MAX_BYTES - bytes) tooLarge()
                        if (name.toString().startsWith("tmp_") || name.toString().endsWith(".lock")) continue
                        val pinned = LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, name.toString()) ?: unsupported()
                        pinned.use { input ->
                            // Size is read from the authenticated inode, not its mutable source name.
                            if (Files.size(LinuxFilesystemSyscalls.descriptorPath(input)) != attributes.size()) unsupported()
                            Files.newOutputStream(destination.resolve(name), CREATE_NEW, WRITE, NOFOLLOW_LINKS).use { output ->
                                val copied = LinuxFilesystemSyscalls.copyReadableTo(input, output,
                                    minOf(attributes.size(), MAX_BYTES - bytes), cancellationCheck = GitStorage::checkInterrupted)
                                if (copied != attributes.size()) unsupported()
                                bytes += copied
                            }
                        }
                    }
                }
            }
        }
        try {
            LinuxFilesystemSyscalls.requireSupported(source)
            openPinned(source.toAbsolutePath().normalize()).use { directory ->
                walk(directory, target, Path.of(""), 0)
            }
        } catch (failure: java.io.InterruptedIOException) {
            throw failure
        } catch (_: IOException) {
            unsupported()
        } catch (_: LinkageError) {
            unsupported()
        }
    }

    /** Pin every ancestor from the filesystem root, rejecting links at the actual directory open. */
    private fun openPinned(path: Path): LinuxDescriptor {
        var current = LinuxFilesystemSyscalls.openRoot(path.root)
        try {
            for (component in path) {
                GitStorage.checkInterrupted()
                val next = LinuxFilesystemSyscalls.openDirectoryAt(current.fd, component.toString())
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
