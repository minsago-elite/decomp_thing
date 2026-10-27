package decompengine.git

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.SecureDirectoryStream
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributeView
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFileAttributeView
import java.security.MessageDigest
import java.util.UUID

/** Descriptor-relative conflict access. No pathname is reopened after checking containment. */
internal object GitConflictFiles {
    data class Observation(val text: String?, val sha256: String, val size: Long?, val mode: String = "100644")

    private fun unsupported(): Nothing = GitWorkspaceMutations.refuse("UNSUPPORTED_CONFLICT",
        "This conflicted path cannot be opened as a contained plain file on this filesystem.")

    private fun changed(): Nothing = GitWorkspaceMutations.refuse("CONTENT_CHANGED",
        "The file changed since it was reviewed. Read it again; nothing was overwritten.")

    /** Traverse from the filesystem root, retaining every directory handle and refusing all links. */
    fun <T> withParent(workTree: Path, path: String, block: (SecureDirectoryStream<Path>, Path) -> T): T {
        val relative = Path.of(path)
        if (relative.isAbsolute || relative.nameCount == 0 || relative.any { it.toString() in setOf("", ".", "..") }) unsupported()
        val absolute = workTree.toAbsolutePath().normalize().resolve(relative)
        val opened = mutableListOf<SecureDirectoryStream<Path>>()
        try {
            val root = Files.newDirectoryStream(absolute.root)
            if (root !is SecureDirectoryStream<Path>) { root.close(); unsupported() }
            opened += root
            var directory: SecureDirectoryStream<Path> = root
            for (part in absolute.parent) {
                directory = directory.newDirectoryStream(part, NOFOLLOW_LINKS)
                opened += directory
            }
            return block(directory, absolute.fileName)
        } catch (_: IOException) { unsupported() }
        catch (_: UnsupportedOperationException) { unsupported() }
        finally { opened.asReversed().forEach { it.close() } }
    }

    private fun attributes(directory: SecureDirectoryStream<Path>, name: Path): BasicFileAttributes? = try {
        directory.getFileAttributeView(name, BasicFileAttributeView::class.java, NOFOLLOW_LINKS).readAttributes()
    } catch (_: NoSuchFileException) { null }

    private fun same(a: BasicFileAttributes?, b: BasicFileAttributes?): Boolean =
        a?.fileKey() == b?.fileKey() && a?.size() == b?.size() && a?.lastModifiedTime() == b?.lastModifiedTime()

    /** Text, token and size all describe the same bytes read through one retained channel. */
    fun observe(workTree: Path, path: String): Observation = withParent(workTree, path) { directory, name -> observe(directory, name) }

    internal fun observe(directory: SecureDirectoryStream<Path>, name: Path, afterOpen: () -> Unit = {}): Observation {
        val before = attributes(directory, name) ?: return Observation("", "absent", null)
        if (!before.isRegularFile) unsupported()
        val digest = MessageDigest.getInstance("SHA-256")
        val text = ByteArrayOutputStream()
        var size = 0L
        directory.newByteChannel(name, setOf(StandardOpenOption.READ, NOFOLLOW_LINKS)).use { channel ->
            afterOpen()
            val buffer = ByteBuffer.allocate(64 * 1024)
            while (true) {
                buffer.clear()
                val count = channel.read(buffer)
                if (count < 0) break
                digest.update(buffer.array(), 0, count)
                if (size <= GitIntegrations.MAX_TEXT_BYTES) {
                    text.write(buffer.array(), 0, minOf(count, GitIntegrations.MAX_TEXT_BYTES + 1 - text.size()))
                }
                size += count
            }
        }
        val executable = directory.getFileAttributeView(name, PosixFileAttributeView::class.java, NOFOLLOW_LINKS)
            ?.readAttributes()?.permissions()?.contains(java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE) == true
        if (size != before.size() || !same(before, attributes(directory, name))) changed()
        return Observation(GitIntegrations.utf8(text.toByteArray()), digest.digest().joinToString("") { "%02x".format(it) }, size,
            if (executable) "100755" else "100644")
    }

    /** Pin the same directory used for both secure rename and fsync. Never reopen a mutable
     * pathname to flush: a renamed ancestor must not redirect durability to another directory. */
    private fun <T> withDurableParent(workTree: Path, path: String,
        block: (SecureDirectoryStream<Path>, Path, LinuxDescriptor) -> T): T {
        val relative = Path.of(path)
        if (relative.isAbsolute || relative.nameCount == 0 || relative.any { it.toString() in setOf("", ".", "..") }) unsupported()
        val absolute = workTree.toAbsolutePath().normalize().resolve(relative)
        var pinned: LinuxDescriptor? = null
        try {
            LinuxFilesystemSyscalls.requireSupported(workTree)
            pinned = LinuxFilesystemSyscalls.openRoot(absolute.root)
            for (part in absolute.parent) {
                val next = LinuxFilesystemSyscalls.openDirectoryAt(checkNotNull(pinned).fd, part.toString())
                checkNotNull(pinned).close()
                pinned = next
            }
            Files.newDirectoryStream(LinuxFilesystemSyscalls.descriptorPath(checkNotNull(pinned))).use { directory ->
                if (directory !is SecureDirectoryStream<Path>) unsupported()
                return block(directory, absolute.fileName, checkNotNull(pinned))
            }
        } catch (_: IOException) { unsupported() }
        catch (_: UnsupportedOperationException) { unsupported() }
        finally { pinned?.close() }
    }

    internal enum class DurabilityPoint { PREPARED_FILE, PUBLISHED_DIRECTORY }

    /** Prepare and force privately, then recheck the digest under the workflow lease boundary.
     * A successful return follows fsync of the exact directory in which the rename occurred. */
    fun replace(workTree: Path, path: String, expected: String, bytes: ByteArray,
        afterSync: (DurabilityPoint) -> Unit = {}, beforePublish: () -> Unit) {
        withDurableParent(workTree, path) { directory, name, pinned ->
            val permissions = try {
                directory.getFileAttributeView(name, PosixFileAttributeView::class.java, NOFOLLOW_LINKS)?.readAttributes()?.permissions()
            } catch (_: NoSuchFileException) { null }
            val temporary = Path.of(".conflict-${UUID.randomUUID()}.tmp")
            try {
                directory.newByteChannel(temporary, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, NOFOLLOW_LINKS)).use { channel ->
                    val buffer = ByteBuffer.wrap(bytes)
                    while (buffer.hasRemaining()) channel.write(buffer)
                    if (permissions != null) directory.getFileAttributeView(temporary, PosixFileAttributeView::class.java, NOFOLLOW_LINKS).setPermissions(permissions)
                    (channel as? FileChannel ?: unsupported()).force(true)
                }
                afterSync(DurabilityPoint.PREPARED_FILE)
                beforePublish()
                if (observe(directory, name).sha256 != expected) changed()
                directory.move(temporary, directory, name)
                LinuxFilesystemSyscalls.synchronize(pinned)
                afterSync(DurabilityPoint.PUBLISHED_DIRECTORY)
            } finally { try { directory.deleteFile(temporary) } catch (_: NoSuchFileException) { } }
        }
    }
}
