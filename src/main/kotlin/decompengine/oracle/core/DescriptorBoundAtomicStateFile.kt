package decompengine.oracle.core

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import java.io.IOException
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest

/** Crash points used to exercise the durable no-replace publication protocol boundaries. */
internal enum class DescriptorBoundStateFaultPoint {
    AFTER_UNNAMED_FILE_SYNC,
    AFTER_TEMPORARY_DIRECTORY_SYNC,
    AFTER_PUBLICATION_RENAME,
    AFTER_PUBLICATION_DIRECTORY_SYNC,
}

internal fun interface DescriptorBoundStateFaultInjector {
    fun hit(point: DescriptorBoundStateFaultPoint)
}

internal class DescriptorBoundStateSnapshot(
    bytes: ByteArray,
    val identity: LinuxFileIdentity,
) {
    private val contents = bytes.copyOf()

    val bytes: ByteArray
        get() = contents.copyOf()
}

/** One still-open immutable state inode retained across parse, validation, and recovery rename. */
internal class DescriptorBoundStateInspection internal constructor(
    bytes: ByteArray,
    val identity: LinuxFileIdentity,
    internal val descriptor: LinuxDescriptor,
) : AutoCloseable {
    private val contents = bytes.copyOf()

    val bytes: ByteArray
        get() = contents.copyOf()

    fun snapshot(): DescriptorBoundStateSnapshot = DescriptorBoundStateSnapshot(contents, identity)

    override fun close() = descriptor.close()
}

/** One still-open immutable executable inode retained with only its streamed size and SHA-256. */
internal class DescriptorBoundExecutableDigestInspection internal constructor(
    val bytes: Long,
    val sha256: String,
    val identity: LinuxFileIdentity,
    private val descriptor: LinuxDescriptor,
) : AutoCloseable {
    override fun close() = descriptor.close()
}

/**
 * Publishes one immutable state file through a pinned owner-controlled directory.
 *
 * The deterministic temporary name is part of the recovery protocol. A retry accepts it only when
 * its descriptor-authenticated bytes exactly equal the requested immutable value. Unknown residue
 * is retained and rejected. No path-based overwrite or non-atomic fallback exists. The caller must
 * hold cooperative exclusive ownership of the directory and exclude same-UID name mutation.
 */
internal object DescriptorBoundAtomicStateFile {
    /** Preflights the same owner-only parent requirement used by every publication/read path. */
    fun requireOwnerOnlyParent(parent: LinuxDescriptor) = requireParent(parent)

    fun publishNoReplace(
        parent: LinuxDescriptor,
        name: String,
        bytes: ByteArray,
        maximumBytes: Int,
        faultInjector: DescriptorBoundStateFaultInjector? = null,
    ): DescriptorBoundStateSnapshot = publishNoReplaceWithMode(
        parent,
        name,
        bytes,
        maximumBytes,
        MAXIMUM_STATE_FILE_BYTES,
        OWNER_READ_ONLY_MODE,
        faultInjector,
    )

    /** Publishes immutable transport bytes which are owner-readable and owner-executable. */
    fun publishExecutableNoReplace(
        parent: LinuxDescriptor,
        name: String,
        bytes: ByteArray,
        maximumBytes: Int,
        faultInjector: DescriptorBoundStateFaultInjector? = null,
    ): DescriptorBoundStateSnapshot = publishNoReplaceWithMode(
        parent,
        name,
        bytes,
        maximumBytes,
        MAXIMUM_EXECUTABLE_BYTES,
        OWNER_READ_EXECUTE_MODE,
        faultInjector,
    )

    private fun publishNoReplaceWithMode(
        parent: LinuxDescriptor,
        name: String,
        bytes: ByteArray,
        maximumBytes: Int,
        maximumAllowedBytes: Int,
        ownerMode: Int,
        faultInjector: DescriptorBoundStateFaultInjector?,
    ): DescriptorBoundStateSnapshot {
        requireName(name)
        require(maximumBytes in 1..maximumAllowedBytes)
        require(bytes.isNotEmpty() && bytes.size <= maximumBytes) {
            "immutable state bytes exceed their configured bound"
        }
        val expectedBytes = bytes.copyOf()
        requireParent(parent)
        val temporaryName = temporaryName(name)

        readWithModeOrNull(parent, name, maximumBytes, ownerMode)?.let { existing ->
            requireExactBytes(existing.bytes, expectedBytes, "immutable state target")
            if (readWithModeOrNull(parent, temporaryName, maximumBytes, ownerMode) != null) {
                stateFail("immutable state target and temporary both exist")
            }
            requireNamedIdentity(parent, name, existing.identity, "immutable state target")
            // A prior process may have died after rename but before its directory sync.
            LinuxFilesystemSyscalls.synchronize(parent)
            return readRequiredWithMode(parent, name, maximumBytes, ownerMode)
        }

        readWithModeOrNull(parent, temporaryName, maximumBytes, ownerMode)?.let { temporary ->
            requireExactBytes(temporary.bytes, expectedBytes, "immutable state temporary")
            requireNamedIdentity(parent, temporaryName, temporary.identity, "immutable state temporary")
            LinuxFilesystemSyscalls.renameNoReplace(parent.fd, temporaryName, name)
            faultInjector?.hit(DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_RENAME)
            LinuxFilesystemSyscalls.synchronize(parent)
            faultInjector?.hit(DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_DIRECTORY_SYNC)
            return readRequiredWithMode(parent, name, maximumBytes, ownerMode).also { published ->
                requireExactBytes(published.bytes, expectedBytes, "immutable state target")
                if (!sameFile(published.identity, temporary.identity)) {
                    stateFail("immutable state target differs from its recovered temporary")
                }
            }
        }

        var prepared: LinuxDescriptor? = null
        try {
            prepared = LinuxFilesystemSyscalls.createTemporaryAt(parent.fd)
            LinuxFilesystemSyscalls.write(prepared, expectedBytes) {}
            LinuxFilesystemSyscalls.chmod(prepared, ownerMode)
            LinuxFilesystemSyscalls.synchronize(prepared)
            val unnamedIdentity = LinuxFilesystemSyscalls.identity(prepared.fd)
            requireUnnamedFile(unnamedIdentity, parent.identity, ownerMode)
            faultInjector?.hit(DescriptorBoundStateFaultPoint.AFTER_UNNAMED_FILE_SYNC)

            LinuxFilesystemSyscalls.linkTemporaryAt(prepared, parent.fd, temporaryName)
            val materialized = readRequiredWithMode(parent, temporaryName, maximumBytes, ownerMode)
            requireExactBytes(materialized.bytes, expectedBytes, "immutable state temporary")
            if (!sameFile(materialized.identity, unnamedIdentity)) {
                stateFail("immutable state temporary differs from its unnamed inode")
            }
            LinuxFilesystemSyscalls.synchronize(parent)
            faultInjector?.hit(DescriptorBoundStateFaultPoint.AFTER_TEMPORARY_DIRECTORY_SYNC)

            LinuxFilesystemSyscalls.renameNoReplace(parent.fd, temporaryName, name)
            faultInjector?.hit(DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_RENAME)
            LinuxFilesystemSyscalls.synchronize(parent)
            faultInjector?.hit(DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_DIRECTORY_SYNC)
            return readRequiredWithMode(parent, name, maximumBytes, ownerMode).also { published ->
                requireExactBytes(published.bytes, expectedBytes, "immutable state target")
                if (!sameFile(published.identity, unnamedIdentity)) {
                    stateFail("immutable state target differs from its prepared inode")
                }
            }
        } finally {
            prepared?.close()
        }
    }

    fun readOrNull(
        parent: LinuxDescriptor,
        name: String,
        maximumBytes: Int,
    ): DescriptorBoundStateSnapshot? = inspectOrNull(parent, name, maximumBytes)?.use { inspection ->
        inspection.snapshot()
    }

    private fun readWithModeOrNull(
        parent: LinuxDescriptor,
        name: String,
        maximumBytes: Int,
        ownerMode: Int,
    ): DescriptorBoundStateSnapshot? = inspectWithModeOrNull(
        parent,
        name,
        maximumBytes,
        MAXIMUM_EXECUTABLE_BYTES,
        ownerMode,
    )?.use { inspection ->
        inspection.snapshot()
    }

    fun inspectOrNull(
        parent: LinuxDescriptor,
        name: String,
        maximumBytes: Int,
    ): DescriptorBoundStateInspection? = inspectWithModeOrNull(
        parent,
        name,
        maximumBytes,
        MAXIMUM_STATE_FILE_BYTES,
        OWNER_READ_ONLY_MODE,
    )

    /** Opens one already-published immutable executable while enforcing its exact 0500 mode. */
    fun inspectExecutableOrNull(
        parent: LinuxDescriptor,
        name: String,
        maximumBytes: Int,
    ): DescriptorBoundStateInspection? = inspectWithModeOrNull(
        parent,
        name,
        maximumBytes,
        MAXIMUM_EXECUTABLE_BYTES,
        OWNER_READ_EXECUTE_MODE,
    )

    /**
     * Opens one immutable executable by its pinned parent and streams its exact size and SHA-256.
     *
     * Unlike [inspectExecutableOrNull], the returned inspection retains no executable byte array.
     */
    fun inspectExecutableDigestOrNull(
        parent: LinuxDescriptor,
        name: String,
        maximumBytes: Int,
    ): DescriptorBoundExecutableDigestInspection? {
        requireStateName(name)
        require(maximumBytes in 1..MAXIMUM_EXECUTABLE_BYTES)
        requireParent(parent)
        val selected = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name) ?: return null
        try {
            requireManagedFile(
                selected.identity,
                parent.identity,
                OWNER_READ_EXECUTE_MODE,
                "immutable executable",
            )
            val digest = MessageDigest.getInstance("SHA-256")
            val bytes = LinuxFilesystemSyscalls.copyReadableTo(
                selected,
                MessageDigestOutputStream(digest),
                maximumBytes.toLong(),
            )
            if (bytes !in 1L..maximumBytes.toLong()) {
                stateFail("immutable executable must contain 1..$maximumBytes bytes")
            }
            val after = selected.whileOpen(LinuxFilesystemSyscalls::identity)
            if (after != selected.identity) stateFail("immutable executable changed while it was hashed")
            requireNamedIdentity(parent, name, after, "immutable executable")
            return DescriptorBoundExecutableDigestInspection(
                bytes,
                digest.digest().hex(),
                after,
                selected,
            )
        } catch (failure: Throwable) {
            selected.close()
            throw failure
        }
    }

    private fun inspectWithModeOrNull(
        parent: LinuxDescriptor,
        name: String,
        maximumBytes: Int,
        maximumAllowedBytes: Int,
        ownerMode: Int,
    ): DescriptorBoundStateInspection? {
        requireStateName(name)
        require(maximumBytes in 1..maximumAllowedBytes)
        requireParent(parent)
        val selected = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name) ?: return null
        try {
            requireManagedFile(selected.identity, parent.identity, ownerMode, "immutable state file")
            val bytes = LinuxFilesystemSyscalls.openReadableFrom(selected).use { readable ->
                LinuxFilesystemSyscalls.read(readable, maximumBytes) {}
            }
            val after = selected.whileOpen(LinuxFilesystemSyscalls::identity)
            if (after != selected.identity) stateFail("immutable state file changed while it was read")
            requireNamedIdentity(parent, name, after, "immutable state file")
            return DescriptorBoundStateInspection(bytes, after, selected)
        } catch (failure: Throwable) {
            selected.close()
            throw failure
        }
    }

    /**
     * Completes only the already-inspected deterministic temporary publication.
     *
     * Unlike [publishNoReplace], this recovery primitive never creates replacement bytes. The
     * temporary must still have the exact inspected inode and contents, and the target must remain
     * absent. Any collision or drift is retained and rejected.
     */
    fun completeExistingTemporaryNoReplace(
        parent: LinuxDescriptor,
        name: String,
        expectedTemporary: DescriptorBoundStateInspection,
        maximumBytes: Int,
        faultInjector: DescriptorBoundStateFaultInjector? = null,
    ): DescriptorBoundStateSnapshot {
        requireName(name)
        require(maximumBytes in 1..MAXIMUM_STATE_FILE_BYTES)
        requireParent(parent)
        val expectedBytes = expectedTemporary.bytes
        require(expectedBytes.isNotEmpty() && expectedBytes.size <= maximumBytes) {
            "immutable state bytes exceed their configured bound"
        }
        if (readOrNull(parent, name, maximumBytes) != null) {
            stateFail("immutable state recovery target already exists")
        }
        val temporaryName = temporaryName(name)
        val current = readOrNull(parent, temporaryName, maximumBytes)
            ?: stateFail("immutable state recovery temporary is missing")
        requireExactBytes(current.bytes, expectedBytes, "immutable state recovery temporary")
        val pinnedIdentity = expectedTemporary.descriptor.whileOpen(LinuxFilesystemSyscalls::identity)
        if (pinnedIdentity != expectedTemporary.identity || current.identity != pinnedIdentity) {
            stateFail("immutable state recovery temporary changed identity")
        }
        requireNamedIdentity(parent, temporaryName, current.identity, "immutable state recovery temporary")
        LinuxFilesystemSyscalls.renameNoReplace(parent.fd, temporaryName, name)
        faultInjector?.hit(DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_RENAME)
        LinuxFilesystemSyscalls.synchronize(parent)
        faultInjector?.hit(DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_DIRECTORY_SYNC)
        return readRequired(parent, name, maximumBytes).also { published ->
            requireExactBytes(published.bytes, expectedBytes, "immutable state recovery target")
            if (!sameFile(published.identity, pinnedIdentity)) {
                stateFail("immutable state recovery target differs from its inspected temporary")
            }
        }
    }

    fun temporaryName(name: String): String {
        requireName(name)
        return ".$name.atomic"
    }

    private fun readRequired(
        parent: LinuxDescriptor,
        name: String,
        maximumBytes: Int,
    ): DescriptorBoundStateSnapshot = readOrNull(parent, name, maximumBytes)
        ?: stateFail("immutable state file is missing: $name")

    private fun readRequiredWithMode(
        parent: LinuxDescriptor,
        name: String,
        maximumBytes: Int,
        ownerMode: Int,
    ): DescriptorBoundStateSnapshot = readWithModeOrNull(parent, name, maximumBytes, ownerMode)
        ?: stateFail("immutable state file is missing: $name")

    private fun requireParent(parent: LinuxDescriptor) {
        val current = LinuxFilesystemSyscalls.identity(parent.fd)
        val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
        if (
            !sameDirectory(current, parent.identity) || current.uid != uid ||
            current.mode.permissions != OWNER_DIRECTORY_MODE
        ) stateFail("immutable state parent is not a pinned owner-only directory")
    }

    private fun requireManagedFile(
        actual: LinuxFileIdentity,
        parent: LinuxFileIdentity,
        ownerMode: Int,
        label: String,
    ) {
        if (
            !actual.isRegularFile || actual.isDirectory || actual.isSymbolicLink || actual.linkCount != 1 ||
            actual.mountId != parent.mountId || actual.uid != parent.uid ||
            actual.mode.permissions != ownerMode
        ) stateFail("$label is not a single-link owner-only file on its parent filesystem")
    }

    private fun requireUnnamedFile(actual: LinuxFileIdentity, parent: LinuxFileIdentity, ownerMode: Int) {
        if (
            !actual.isRegularFile || actual.isDirectory || actual.isSymbolicLink || actual.linkCount != 0 ||
            actual.mountId != parent.mountId || actual.uid != parent.uid ||
            actual.mode.permissions != ownerMode
        ) stateFail("prepared immutable state is not an owner-only unnamed file")
    }

    private fun requireNamedIdentity(
        parent: LinuxDescriptor,
        name: String,
        expected: LinuxFileIdentity,
        label: String,
    ) {
        val current = LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name)
            ?: stateFail("$label disappeared")
        current.use {
            if (current.identity != expected || current.identity.isSymbolicLink) {
                stateFail("$label changed identity")
            }
        }
    }

    private fun requireExactBytes(actual: ByteArray, expected: ByteArray, label: String) {
        if (!MessageDigest.isEqual(actual, expected)) stateFail("$label has different immutable bytes")
    }

    private fun requireName(name: String) {
        require(name.matches(STATE_NAME)) { "immutable state file name is invalid" }
    }

    private fun requireStateName(name: String) {
        require(name.matches(STATE_NAME) || name.matches(TEMPORARY_STATE_NAME)) {
            "immutable state file name is invalid"
        }
    }

    private fun sameFile(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
        first.key == second.key && first.mountId == second.mountId &&
            first.uid == second.uid && first.gid == second.gid &&
            first.isRegularFile && second.isRegularFile &&
            !first.isDirectory && !second.isDirectory &&
            !first.isSymbolicLink && !second.isSymbolicLink

    private fun sameDirectory(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
        first.key == second.key && first.mountId == second.mountId &&
            first.uid == second.uid && first.gid == second.gid &&
            first.isDirectory && second.isDirectory &&
            !first.isSymbolicLink && !second.isSymbolicLink
}

private class MessageDigestOutputStream(private val digest: MessageDigest) : OutputStream() {
    override fun write(value: Int) = digest.update(value.toByte())

    override fun write(bytes: ByteArray, offset: Int, length: Int) = digest.update(bytes, offset, length)
}

private fun ByteArray.hex(): String = joinToString("") { byte ->
    "%02x".format(byte.toInt() and 0xff)
}

private fun stateFail(message: String): Nothing = throw IOException(message)

private const val OWNER_DIRECTORY_MODE = 0x1c0 // 0700
private const val OWNER_READ_ONLY_MODE = 0x100 // 0400
private const val OWNER_READ_EXECUTE_MODE = 0x140 // 0500
private const val MAXIMUM_STATE_FILE_BYTES = 1024 * 1024
private const val MAXIMUM_EXECUTABLE_BYTES = 512 * 1024 * 1024
private val STATE_NAME = Regex("[a-z0-9][a-z0-9._-]{0,126}[a-z0-9]")
private val TEMPORARY_STATE_NAME = Regex("\\.[a-z0-9][a-z0-9._-]{0,126}[a-z0-9]\\.atomic")
