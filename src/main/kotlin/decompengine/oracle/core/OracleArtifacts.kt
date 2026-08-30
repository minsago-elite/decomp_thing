package decompengine.oracle.core

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.security.SecureRandom

data class OracleArtifactLimits(val maximumBytes: Int = 4 * 1024 * 1024) {
    init {
        require(maximumBytes in 1..HARD_MAXIMUM_BYTES) { "maximumBytes is outside the supported range" }
    }

    private companion object {
        const val HARD_MAXIMUM_BYTES = 64 * 1024 * 1024
    }
}

class OracleArtifactException(message: String, cause: Throwable? = null) : IOException(message, cause)

/** An immutable copy of a bounded artifact and the digest of those exact bytes. */
class OracleArtifactSnapshot internal constructor(content: ByteArray) {
    private val storedBytes = content.copyOf()

    val bytes: ByteArray
        get() = storedBytes.copyOf()

    val size: Int = storedBytes.size
    val sha256: String = OracleArtifacts.sha256(storedBytes)
}

/**
 * Bounded reads and durable same-directory publication for canonical oracle artifacts.
 *
 * The artifact and its immediate parent must not be writable by group or other principals. Java NIO
 * does not expose descriptor-relative stat/rename operations or the identity of an open channel, so
 * both the regular-file owner and directory owner are cooperating members of the trusted process
 * boundary. They must not mutate file contents or replace pathnames during an operation.
 */
object OracleArtifacts {
    fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString(separator = "") { byte ->
            (byte.toInt() and 0xff).toString(16).padStart(2, '0')
        }

    fun read(path: Path, limits: OracleArtifactLimits = OracleArtifactLimits()): OracleArtifactSnapshot =
        read(path, limits) {}

    /** Deterministic fault-injection seam; post-open validation remains mandatory after [afterOpen]. */
    internal fun read(
        path: Path,
        limits: OracleArtifactLimits,
        afterOpen: () -> Unit,
    ): OracleArtifactSnapshot {
        val target = validatedAbsolutePath(path)
        validateParentDirectory(target.parent)
        requireTrustedDirectory(target.parent)
        val before = readRegularFileAttributes(target)
        val beforePermissions = readTrustedArtifactPermissions(target)
        val expectedSize = checkedSize(before.size(), limits)
        val bytes = ByteArray(expectedSize)

        try {
            FileChannel.open(target, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
                afterOpen()
                val destination = ByteBuffer.wrap(bytes)
                while (destination.hasRemaining()) {
                    if (channel.read(destination) < 0) {
                        throw OracleArtifactException("artifact changed size during the bounded read")
                    }
                }
                if (channel.read(ByteBuffer.allocate(1)) >= 0 || channel.size() != expectedSize.toLong()) {
                    throw OracleArtifactException("artifact changed size during the bounded read")
                }
            }
        } catch (failure: OracleArtifactException) {
            throw failure
        } catch (failure: Exception) {
            throw OracleArtifactException("could not read the bounded artifact", failure)
        }

        val after = readRegularFileAttributes(target)
        val afterPermissions = readTrustedArtifactPermissions(target)
        if (!sameFileVersion(before, after)) {
            throw OracleArtifactException("artifact identity or metadata changed during the bounded read")
        }
        if (beforePermissions != afterPermissions) {
            throw OracleArtifactException("artifact permissions changed during the bounded read")
        }
        return OracleArtifactSnapshot(bytes)
    }

    fun publishAtomically(
        path: Path,
        bytes: ByteArray,
        limits: OracleArtifactLimits = OracleArtifactLimits(),
    ): OracleArtifactSnapshot {
        if (bytes.size > limits.maximumBytes) {
            throw OracleArtifactException("artifact exceeds the configured byte limit")
        }
        val payload = bytes.copyOf()
        val target = validatedAbsolutePath(path)
        val parent = target.parent
        val parentIdentity = validateParentDirectory(parent)
        requireTrustedDirectory(parent)
        validatePublicationTarget(target)
        forceDirectory(parent, "directory durability is unavailable before publication")

        var temporary: Path? = null
        var temporaryIdentity: Any? = null
        var temporaryChannel: FileChannel? = null
        var committed = false
        var primaryFailure: Throwable? = null
        try {
            val created = createPrivateTemporary(parent)
            temporary = created.path
            temporaryIdentity = created.identity
            temporaryChannel = created.channel
            writeAndSync(created.channel, payload)
            ensureTemporaryIdentity(created.path, created.identity)
            ensureDirectoryIdentity(parent, parentIdentity)
            validatePublicationTarget(target)
            try {
                Files.move(
                    temporary,
                    target,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (failure: AtomicMoveNotSupportedException) {
                throw OracleArtifactException("the filesystem does not support atomic artifact replacement", failure)
            }
            committed = true
            temporary = null
            created.channel.close()
            temporaryChannel = null
            forceDirectory(parent, "artifact was committed but directory durability could not be confirmed")
            ensureDirectoryIdentity(parent, parentIdentity)
            val snapshot = read(target, limits)
            if (!MessageDigest.isEqual(snapshot.bytes, payload)) {
                throw OracleArtifactException("published artifact does not match the committed bytes")
            }
            return snapshot
        } catch (failure: Throwable) {
            primaryFailure = failure
            if (failure is OracleArtifactException) throw failure
            val state = if (committed) "after committing the artifact" else "before committing the artifact"
            throw OracleArtifactException("atomic artifact publication failed $state", failure)
        } finally {
            try {
                temporaryChannel?.close()
            } catch (closeFailure: Throwable) {
                if (primaryFailure != null) primaryFailure.addSuppressed(closeFailure)
                else throw OracleArtifactException("could not close the artifact temporary", closeFailure)
            }
            val leftover = temporary
            if (leftover != null) {
                try {
                    deleteOwnedTemporary(leftover, temporaryIdentity)
                    forceDirectory(parent, "temporary cleanup could not be made durable")
                } catch (cleanupFailure: Throwable) {
                    if (primaryFailure != null) {
                        primaryFailure.addSuppressed(cleanupFailure)
                    } else {
                        throw OracleArtifactException("could not safely clean up the publication temporary", cleanupFailure)
                    }
                }
            }
        }
    }

    private fun validatedAbsolutePath(path: Path): Path {
        val target = path.toAbsolutePath().normalize()
        if (target.parent == null || target.fileName == null) {
            throw OracleArtifactException("artifact path must name a file beneath an existing directory")
        }
        return target
    }

    private fun validateParentDirectory(parent: Path): Any {
        val attributes = try {
            Files.readAttributes(parent, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw OracleArtifactException("artifact parent directory is unavailable", failure)
        }
        if (!attributes.isDirectory || attributes.isSymbolicLink) {
            throw OracleArtifactException("artifact parent must be a real directory")
        }
        val realParent = try {
            parent.toRealPath()
        } catch (failure: Exception) {
            throw OracleArtifactException("artifact parent directory cannot be resolved", failure)
        }
        if (realParent != parent) {
            throw OracleArtifactException("symbolic links are not allowed in the artifact parent path")
        }
        return attributes.fileKey()
            ?: throw OracleArtifactException("filesystem does not expose a stable parent-directory identity")
    }

    private fun ensureDirectoryIdentity(parent: Path, expectedIdentity: Any) {
        val current = validateParentDirectory(parent)
        if (current != expectedIdentity) throw OracleArtifactException("artifact parent directory changed during publication")
    }

    private fun readRegularFileAttributes(target: Path): BasicFileAttributes {
        val attributes = try {
            Files.readAttributes(target, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw OracleArtifactException("artifact is unavailable", failure)
        }
        if (!attributes.isRegularFile || attributes.isSymbolicLink) {
            throw OracleArtifactException("artifact must be a regular file and may not be a symbolic link")
        }
        if (attributes.fileKey() == null) {
            throw OracleArtifactException("filesystem does not expose a stable artifact identity")
        }
        return attributes
    }

    private fun validatePublicationTarget(target: Path) {
        if (!Files.exists(target, LinkOption.NOFOLLOW_LINKS)) return
        readRegularFileAttributes(target)
    }

    private fun checkedSize(size: Long, limits: OracleArtifactLimits): Int {
        if (size < 0 || size > limits.maximumBytes.toLong() || size > Int.MAX_VALUE.toLong()) {
            throw OracleArtifactException("artifact exceeds the configured byte limit")
        }
        return size.toInt()
    }

    private fun sameFileVersion(before: BasicFileAttributes, after: BasicFileAttributes): Boolean =
        before.fileKey() == after.fileKey() &&
            before.size() == after.size() &&
            before.lastModifiedTime() == after.lastModifiedTime()

    private fun requireTrustedDirectory(parent: Path) {
        val view = Files.getFileAttributeView(
            parent,
            PosixFileAttributeView::class.java,
            LinkOption.NOFOLLOW_LINKS,
        ) ?: throw OracleArtifactException("private artifact handling requires POSIX file permissions")
        val permissions = try {
            view.readAttributes().permissions()
        } catch (failure: Exception) {
            throw OracleArtifactException("artifact parent permissions could not be verified", failure)
        }
        if (PosixFilePermission.GROUP_WRITE in permissions || PosixFilePermission.OTHERS_WRITE in permissions) {
            throw OracleArtifactException("artifact parent may not be writable by group or other principals")
        }
    }

    private fun readTrustedArtifactPermissions(target: Path): Set<PosixFilePermission> {
        val view = Files.getFileAttributeView(
            target,
            PosixFileAttributeView::class.java,
            LinkOption.NOFOLLOW_LINKS,
        ) ?: throw OracleArtifactException("private artifact handling requires POSIX file permissions")
        val permissions = try {
            view.readAttributes().permissions()
        } catch (failure: Exception) {
            throw OracleArtifactException("artifact permissions could not be verified", failure)
        }
        if (PosixFilePermission.GROUP_WRITE in permissions || PosixFilePermission.OTHERS_WRITE in permissions) {
            throw OracleArtifactException("artifact may not be writable by group or other principals")
        }
        return HashSet(permissions)
    }

    private fun ensureTemporaryIdentity(path: Path, expectedIdentity: Any) {
        val attributes = readRegularFileAttributes(path)
        if (attributes.fileKey() != expectedIdentity) {
            throw OracleArtifactException("artifact temporary changed identity before publication")
        }
        val permissions = try {
            Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw OracleArtifactException("artifact temporary permissions could not be verified", failure)
        }
        if (permissions != PRIVATE_FILE_PERMISSIONS) {
            throw OracleArtifactException("artifact temporary lost its private permissions")
        }
    }

    private fun createPrivateTemporary(parent: Path): OpenTemporary {
        repeat(MAXIMUM_TEMPORARY_ATTEMPTS) {
            val name = ".decomp-oracle-${randomToken()}.tmp"
            val candidate = parent.resolve(name)
            var channel: FileChannel? = null
            var created = false
            try {
                channel = FileChannel.open(
                    candidate,
                    setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
                    PosixFilePermissions.asFileAttribute(PRIVATE_FILE_PERMISSIONS),
                )
                created = true
                val identity = readRegularFileAttributes(candidate).fileKey()
                    ?: throw OracleArtifactException("temporary artifact has no stable filesystem identity")
                ensureTemporaryIdentity(candidate, identity)
                return OpenTemporary(candidate, identity, channel)
            } catch (_: java.nio.file.FileAlreadyExistsException) {
                channel?.close()
                // Try another cryptographically random name.
            } catch (failure: Throwable) {
                try {
                    channel?.close()
                    if (created) Files.deleteIfExists(candidate)
                    if (created) forceDirectory(parent, "temporary creation cleanup could not be made durable")
                } catch (cleanupFailure: Throwable) {
                    failure.addSuppressed(cleanupFailure)
                }
                if (failure is OracleArtifactException) throw failure
                throw OracleArtifactException("could not create a private same-directory temporary", failure)
            }
        }
        throw OracleArtifactException("could not allocate a unique artifact temporary")
    }

    private fun writeAndSync(channel: FileChannel, bytes: ByteArray) {
        try {
            channel.position(0)
            val source = ByteBuffer.wrap(bytes)
            while (source.hasRemaining()) channel.write(source)
            channel.truncate(bytes.size.toLong())
            channel.force(true)
        } catch (failure: Exception) {
            throw OracleArtifactException("could not write and synchronize the artifact temporary", failure)
        }
    }

    private data class OpenTemporary(
        val path: Path,
        val identity: Any,
        val channel: FileChannel,
    )

    private fun forceDirectory(parent: Path, message: String) {
        try {
            FileChannel.open(parent, StandardOpenOption.READ).use { channel -> channel.force(true) }
        } catch (failure: Exception) {
            throw OracleArtifactException(message, failure)
        }
    }

    private fun deleteOwnedTemporary(path: Path, expectedIdentity: Any?) {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return
        val current = readRegularFileAttributes(path).fileKey()
        if (expectedIdentity == null || current != expectedIdentity) {
            throw OracleArtifactException("publication temporary identity changed; refusing to delete it")
        }
        Files.delete(path)
    }

    private fun randomToken(): String {
        val bytes = ByteArray(16)
        RANDOM.nextBytes(bytes)
        return bytes.joinToString(separator = "") { byte ->
            (byte.toInt() and 0xff).toString(16).padStart(2, '0')
        }
    }

    private const val MAXIMUM_TEMPORARY_ATTEMPTS = 16
    private val RANDOM = SecureRandom()
    private val PRIVATE_FILE_PERMISSIONS = PosixFilePermissions.fromString("rw-------")
}
