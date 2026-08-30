package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
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

data class StructuralPublishedReportV1(
    val path: Path,
    val sha256: String,
    val sizeBytes: Int,
)

internal object StructuralRecoveryV1Publication {
    /*
     * This protects against non-owner principals by requiring non-group/non-other-writable
     * POSIX files and directories and by rechecking stable identities around the atomic move.
     * Java NIO cannot make the complete sequence descriptor-relative, so the regular-file
     * owner and directory owner remain cooperating members of the publication boundary and
     * must not mutate names, contents, or modes during the operation.
     */
    fun publish(path: Path, bytes: ByteArray, maximumBytes: Int): StructuralPublishedReportV1 =
        publish(path, bytes, maximumBytes) {}

    /** Internal deterministic failure seam; all validation and cleanup still run after the callback. */
    internal fun publish(
        path: Path,
        bytes: ByteArray,
        maximumBytes: Int,
        beforeCommit: () -> Unit,
    ): StructuralPublishedReportV1 {
        if (bytes.size > maximumBytes) structuralFail("structural report exceeds its publication byte limit")
        val payload = bytes.copyOf()
        val target = path.toAbsolutePath().normalize()
        if (target.fileName == null || target.parent == null) structuralFail("structural report path must name a file")
        val parent = target.parent
        val parentState = directoryState(parent)
        validatePublicationTarget(target)
        forceDirectory(parent, "directory durability is unavailable before structural report publication")

        var temporary: OpenTemporary? = null
        var committed = false
        var primaryFailure: Throwable? = null
        try {
            temporary = createTemporary(parent)
            writeAndSync(temporary.channel, payload)
            temporary.channel.close()
            ensureTemporary(temporary.path, temporary.identity)
            ensureDirectory(parent, parentState)
            validatePublicationTarget(target)
            beforeCommit()
            ensureTemporary(temporary.path, temporary.identity)
            ensureDirectory(parent, parentState)
            validatePublicationTarget(target)
            try {
                Files.move(
                    temporary.path,
                    target,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (failure: AtomicMoveNotSupportedException) {
                throw StructuralRecoveryV1Exception("filesystem does not support atomic structural report replacement", failure)
            }
            committed = true
            temporary = null
            forceDirectory(parent, "structural report committed but directory durability could not be confirmed")
            ensureDirectory(parent, parentState)
            val verified = readCommitted(target, payload.size)
            if (!MessageDigest.isEqual(verified, payload)) structuralFail("published structural report differs from committed bytes")
            return StructuralPublishedReportV1(target, OracleArtifacts.sha256(payload), payload.size)
        } catch (failure: Throwable) {
            primaryFailure = failure
            if (failure is StructuralRecoveryV1Exception) throw failure
            val state = if (committed) "after commit" else "before commit"
            throw StructuralRecoveryV1Exception("atomic structural report publication failed $state", failure)
        } finally {
            val leftover = temporary
            if (leftover != null) {
                try {
                    if (leftover.channel.isOpen) leftover.channel.close()
                    deleteOwnedTemporary(leftover.path, leftover.identity)
                    forceDirectory(parent, "structural publication temporary cleanup was not durable")
                } catch (cleanupFailure: Throwable) {
                    if (primaryFailure != null) primaryFailure.addSuppressed(cleanupFailure)
                    else throw StructuralRecoveryV1Exception("could not clean structural publication temporary", cleanupFailure)
                }
            }
        }
    }

    private data class DirectoryState(
        val identity: Any,
        val permissions: Set<PosixFilePermission>,
    )

    private data class OpenTemporary(
        val path: Path,
        val identity: Any,
        val channel: FileChannel,
    )

    private fun directoryState(parent: Path): DirectoryState {
        val attributes = try {
            Files.readAttributes(parent, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw StructuralRecoveryV1Exception("structural report parent directory is unavailable", failure)
        }
        if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
            structuralFail("structural report parent must be a stable real directory")
        }
        val real = try {
            parent.toRealPath()
        } catch (failure: Exception) {
            throw StructuralRecoveryV1Exception("structural report parent cannot be resolved", failure)
        }
        if (real != parent) structuralFail("symbolic links are forbidden in the structural report parent path")
        val permissions = trustedPermissions(parent, directory = true)
        return DirectoryState(checkNotNull(attributes.fileKey()), permissions)
    }

    private fun ensureDirectory(parent: Path, expected: DirectoryState) {
        val current = directoryState(parent)
        if (current != expected) structuralFail("structural report parent identity or permissions changed during publication")
    }

    private fun trustedPermissions(path: Path, directory: Boolean): Set<PosixFilePermission> {
        val view = Files.getFileAttributeView(path, PosixFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS)
            ?: structuralFail("structural report publication requires POSIX permissions")
        val permissions = try {
            view.readAttributes().permissions().toSet()
        } catch (failure: Exception) {
            throw StructuralRecoveryV1Exception("structural report permissions cannot be verified", failure)
        }
        if (PosixFilePermission.GROUP_WRITE in permissions || PosixFilePermission.OTHERS_WRITE in permissions) {
            structuralFail(if (directory) "structural report parent is writable by untrusted principals" else "structural report is writable by untrusted principals")
        }
        return permissions
    }

    private fun validatePublicationTarget(target: Path) {
        if (!Files.exists(target, LinkOption.NOFOLLOW_LINKS)) return
        val attributes = try {
            Files.readAttributes(target, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw StructuralRecoveryV1Exception("structural report target cannot be inspected", failure)
        }
        if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
            structuralFail("structural report target must be absent or a stable regular file")
        }
    }

    private fun createTemporary(parent: Path): OpenTemporary {
        repeat(16) {
            val path = parent.resolve(".structural-v1-${randomToken()}.tmp")
            var channel: FileChannel? = null
            try {
                channel = FileChannel.open(
                    path,
                    setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
                    PosixFilePermissions.asFileAttribute(PRIVATE_FILE_PERMISSIONS),
                )
                val identity = stableRegularIdentity(path)
                ensureTemporary(path, identity)
                return OpenTemporary(path, identity, channel)
            } catch (_: java.nio.file.FileAlreadyExistsException) {
                channel?.close()
            } catch (failure: Throwable) {
                try {
                    channel?.close()
                    Files.deleteIfExists(path)
                } catch (cleanupFailure: Throwable) {
                    failure.addSuppressed(cleanupFailure)
                }
                if (failure is StructuralRecoveryV1Exception) throw failure
                throw StructuralRecoveryV1Exception("could not create private structural report temporary", failure)
            }
        }
        structuralFail("could not allocate a unique structural report temporary")
    }

    private fun stableRegularIdentity(path: Path): Any {
        val attributes = try {
            Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw StructuralRecoveryV1Exception("structural report file cannot be inspected", failure)
        }
        if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
            structuralFail("structural report file is not a stable regular file")
        }
        return checkNotNull(attributes.fileKey())
    }

    private fun ensureTemporary(path: Path, identity: Any) {
        if (stableRegularIdentity(path) != identity || Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS) != PRIVATE_FILE_PERMISSIONS) {
            structuralFail("structural report temporary identity or permissions changed")
        }
    }

    private fun writeAndSync(channel: FileChannel, payload: ByteArray) {
        try {
            val source = ByteBuffer.wrap(payload)
            while (source.hasRemaining()) channel.write(source)
            channel.truncate(payload.size.toLong())
            channel.force(true)
            if (channel.size() != payload.size.toLong()) structuralFail("structural report temporary has the wrong size")
        } catch (failure: StructuralRecoveryV1Exception) {
            throw failure
        } catch (failure: Exception) {
            throw StructuralRecoveryV1Exception("could not write structural report temporary", failure)
        }
    }

    private fun readCommitted(path: Path, expectedSize: Int): ByteArray {
        val beforeIdentity = stableRegularIdentity(path)
        val beforePermissions = trustedPermissions(path, directory = false)
        val before = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (before.size() != expectedSize.toLong()) structuralFail("published structural report has the wrong size")
        val bytes = ByteArray(expectedSize)
        try {
            FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
                val destination = ByteBuffer.wrap(bytes)
                while (destination.hasRemaining()) {
                    if (channel.read(destination) < 0) structuralFail("published structural report changed size while read")
                }
                if (channel.read(ByteBuffer.allocate(1)) >= 0 || channel.size() != expectedSize.toLong()) {
                    structuralFail("published structural report changed size while read")
                }
            }
        } catch (failure: StructuralRecoveryV1Exception) {
            throw failure
        } catch (failure: Exception) {
            throw StructuralRecoveryV1Exception("published structural report cannot be verified", failure)
        }
        val after = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        val afterPermissions = trustedPermissions(path, directory = false)
        if (stableRegularIdentity(path) != beforeIdentity || before.size() != after.size() ||
            before.lastModifiedTime() != after.lastModifiedTime() || beforePermissions != afterPermissions
        ) structuralFail("published structural report changed during verification")
        return bytes
    }

    private fun deleteOwnedTemporary(path: Path, identity: Any) {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return
        if (stableRegularIdentity(path) != identity) structuralFail("temporary identity changed; refusing cleanup")
        Files.delete(path)
    }

    private fun forceDirectory(parent: Path, message: String) {
        try {
            FileChannel.open(parent, StandardOpenOption.READ).use { it.force(true) }
        } catch (failure: Exception) {
            throw StructuralRecoveryV1Exception(message, failure)
        }
    }

    private fun randomToken(): String {
        val bytes = ByteArray(16)
        RANDOM.nextBytes(bytes)
        return bytes.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
    }

    private val PRIVATE_FILE_PERMISSIONS = PosixFilePermissions.fromString("rw-------")
    private val RANDOM = SecureRandom()
}
