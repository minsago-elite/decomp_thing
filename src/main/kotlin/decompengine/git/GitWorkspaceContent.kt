package decompengine.git

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.git.GitStorage.hex
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.WRITE
import java.security.MessageDigest

/** Bounded content commitments, shared by reviewed status and the bytes captured for staging. */
internal object GitWorkspaceContent {
    class Budget(var remaining: Long = GitSourceCopy.MAX_BYTES)

    /** Never follow a leaf link. The optional destination receives exactly the hashed bytes. */
    fun fingerprint(root: Path, file: Path, budget: Budget, destination: Path? = null,
        beforeOpen: (Path) -> Unit = {}): String {
        val stat = GitRepositoryInspector.worktreeStat(root, file) ?: return "absent"
        if (stat.isDirectory) return "directory"
        if (!stat.isRegularFile && !stat.isSymbolicLink) unavailable()
        var ancestor = file.parent
        while (ancestor != root) {
            if (ancestor == null || !Files.isDirectory(ancestor, NOFOLLOW_LINKS)) unavailable()
            ancestor = ancestor.parent
        }
        val digest = MessageDigest.getInstance("SHA-256")
        val mode = if (stat.isSymbolicLink) "120000" else if (Files.isExecutable(file)) "100755" else "100644"
        val output = destination?.let { Files.newOutputStream(it, CREATE_NEW, WRITE) }
        try {
            if (stat.isSymbolicLink) {
                val target = Files.readSymbolicLink(file).toString()
                // Do not silently authorize a lossy native filename conversion.
                if ('\uFFFD' in target) unavailable()
                val bytes = target.toByteArray(Charsets.UTF_8)
                consume(bytes, bytes.size, budget, digest, output)
            } else {
                if (stat.size() > budget.remaining) unavailable()
                try {
                    LinuxFilesystemSyscalls.requireSupported(root)
                    openPinnedParent(root, file.parent).use { parent ->
                        beforeOpen(file)
                        GitStorage.checkInterrupted()
                        // O_PATH authenticates the opened inode as a regular file before an
                        // O_NONBLOCK readable descriptor is reopened from that same inode.
                        LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, file.fileName.toString())
                            ?.use { pinned ->
                                val pinnedPath = LinuxFilesystemSyscalls.descriptorPath(pinned)
                                val openedSize = Files.size(pinnedPath)
                                if (openedSize != stat.size()) unavailable()
                                val openedMode = if (pinned.identity.mode and 0x49 != 0) "100755" else "100644"
                                if (openedMode != mode) unavailable()
                                val hashingOutput = object : OutputStream() {
                                    override fun write(value: Int) {
                                        val one = byteArrayOf(value.toByte())
                                        if (budget.remaining < 1) unavailable()
                                        budget.remaining--
                                        digest.update(one)
                                        output?.write(value)
                                    }
                                    override fun write(bytes: ByteArray, offset: Int, length: Int) {
                                        if (length > budget.remaining) unavailable()
                                        budget.remaining -= length
                                        digest.update(bytes, offset, length)
                                        output?.write(bytes, offset, length)
                                    }
                                }
                                val copied = LinuxFilesystemSyscalls.copyReadableTo(pinned, hashingOutput, stat.size(),
                                    cancellationCheck = GitStorage::checkInterrupted)
                                if (copied != stat.size()) unavailable()
                            } ?: unavailable()
                    }
                } catch (_: java.io.IOException) { unavailable() }
            }
        } finally { output?.close() }
        return "$mode:${digest.digest().hex()}"
    }

    /** Pin each directory component before opening a leaf; callers own the returned descriptor. */
    private fun openPinnedParent(root: Path, parent: Path): LinuxDescriptor {
        val absoluteRoot = root.toAbsolutePath().normalize()
        val absoluteParent = parent.toAbsolutePath().normalize()
        if (!absoluteParent.startsWith(absoluteRoot)) unavailable()
        var current = LinuxFilesystemSyscalls.openRoot(absoluteRoot.root)
        try {
            for (component in absoluteRoot.root.relativize(absoluteParent)) {
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

    private fun consume(bytes: ByteArray, count: Int, budget: Budget, digest: MessageDigest, output: OutputStream?) {
        if (count > budget.remaining) unavailable()
        budget.remaining -= count
        digest.update(bytes, 0, count)
        output?.write(bytes, 0, count)
    }

    private fun unavailable(): Nothing = throw GitRepositoryException("REPOSITORY_UNAVAILABLE",
        "Work-tree content could not be captured exactly within its bounds. Read the current status before trying again.")
}
