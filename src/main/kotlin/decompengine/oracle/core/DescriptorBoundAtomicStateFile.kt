package decompengine.oracle.core

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import java.io.IOException
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

/**
 * Publishes one immutable state file through a pinned owner-controlled directory.
 *
 * The deterministic temporary name is part of the recovery protocol. A retry accepts it only when
 * its descriptor-authenticated bytes exactly equal the requested immutable value. Unknown residue
 * is retained and rejected. No path-based overwrite or non-atomic fallback exists. The caller must
 * hold cooperative exclusive ownership of the directory and exclude same-UID name mutation.
 */
internal object DescriptorBoundAtomicStateFile {
    fun publishNoReplace(
        parent: LinuxDescriptor,
        name: String,
        bytes: ByteArray,
        maximumBytes: Int,
        faultInjector: DescriptorBoundStateFaultInjector? = null,
    ): DescriptorBoundStateSnapshot {
        requireName(name)
        require(maximumBytes in 1..MAXIMUM_STATE_FILE_BYTES)
        require(bytes.isNotEmpty() && bytes.size <= maximumBytes) {
            "immutable state bytes exceed their configured bound"
        }
        val expectedBytes = bytes.copyOf()
        requireParent(parent)
        val temporaryName = temporaryName(name)

        readOrNull(parent, name, maximumBytes)?.let { existing ->
            requireExactBytes(existing.bytes, expectedBytes, "immutable state target")
            if (readOrNull(parent, temporaryName, maximumBytes) != null) {
                stateFail("immutable state target and temporary both exist")
            }
            requireNamedIdentity(parent, name, existing.identity, "immutable state target")
            // A prior process may have died after rename but before its directory sync.
            LinuxFilesystemSyscalls.synchronize(parent)
            return readRequired(parent, name, maximumBytes)
        }

        readOrNull(parent, temporaryName, maximumBytes)?.let { temporary ->
            requireExactBytes(temporary.bytes, expectedBytes, "immutable state temporary")
            requireNamedIdentity(parent, temporaryName, temporary.identity, "immutable state temporary")
            LinuxFilesystemSyscalls.renameNoReplace(parent.fd, temporaryName, name)
            faultInjector?.hit(DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_RENAME)
            LinuxFilesystemSyscalls.synchronize(parent)
            faultInjector?.hit(DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_DIRECTORY_SYNC)
            return readRequired(parent, name, maximumBytes).also { published ->
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
            LinuxFilesystemSyscalls.chmod(prepared, OWNER_READ_ONLY_MODE)
            LinuxFilesystemSyscalls.synchronize(prepared)
            val unnamedIdentity = LinuxFilesystemSyscalls.identity(prepared.fd)
            requireUnnamedFile(unnamedIdentity, parent.identity)
            faultInjector?.hit(DescriptorBoundStateFaultPoint.AFTER_UNNAMED_FILE_SYNC)

            LinuxFilesystemSyscalls.linkTemporaryAt(prepared, parent.fd, temporaryName)
            val materialized = readRequired(parent, temporaryName, maximumBytes)
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
            return readRequired(parent, name, maximumBytes).also { published ->
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
    ): DescriptorBoundStateSnapshot? {
        requireStateName(name)
        require(maximumBytes in 1..MAXIMUM_STATE_FILE_BYTES)
        requireParent(parent)
        val selected = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name) ?: return null
        selected.use { authorized ->
            requireManagedFile(authorized.identity, parent.identity, "immutable state file")
            val bytes = LinuxFilesystemSyscalls.openReadableFrom(authorized).use { readable ->
                LinuxFilesystemSyscalls.read(readable, maximumBytes) {}
            }
            val after = LinuxFilesystemSyscalls.identity(authorized.fd)
            if (after != authorized.identity) stateFail("immutable state file changed while it was read")
            requireNamedIdentity(parent, name, after, "immutable state file")
            return DescriptorBoundStateSnapshot(bytes, after)
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
        label: String,
    ) {
        if (
            !actual.isRegularFile || actual.isDirectory || actual.isSymbolicLink || actual.linkCount != 1 ||
            actual.mountId != parent.mountId || actual.uid != parent.uid ||
            actual.mode.permissions != OWNER_READ_ONLY_MODE
        ) stateFail("$label is not a single-link owner-only file on its parent filesystem")
    }

    private fun requireUnnamedFile(actual: LinuxFileIdentity, parent: LinuxFileIdentity) {
        if (
            !actual.isRegularFile || actual.isDirectory || actual.isSymbolicLink || actual.linkCount != 0 ||
            actual.mountId != parent.mountId || actual.uid != parent.uid ||
            actual.mode.permissions != OWNER_READ_ONLY_MODE
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

private fun stateFail(message: String): Nothing = throw IOException(message)

private const val OWNER_DIRECTORY_MODE = 0x1c0 // 0700
private const val OWNER_READ_ONLY_MODE = 0x100 // 0400
private const val MAXIMUM_STATE_FILE_BYTES = 1024 * 1024
private val STATE_NAME = Regex("[a-z0-9][a-z0-9._-]{0,126}[a-z0-9]")
private val TEMPORARY_STATE_NAME = Regex("\\.[a-z0-9][a-z0-9._-]{0,126}[a-z0-9]\\.atomic")
