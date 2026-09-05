package decompengine.repair

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxSyscallException
import decompengine.acp.permissions
import java.io.IOException
import java.nio.file.Path

/**
 * Descriptor-owned durable state for one repair project.
 *
 * All retained paths below are kernel-owned `/proc/self/fd` views of descriptors held by this
 * object. They are compatibility arguments for code which already performs descriptor-bound reads;
 * no mutable project pathname is re-resolved after this store is opened.
 */
internal class RepairStateStore private constructor(
    private val projectRoot: LinuxDescriptor,
    private val reports: LinuxDescriptor,
    private val revisions: LinuxDescriptor,
    private val blobs: LinuxDescriptor,
    private val faultInjector: ModuleRevisionFaultInjector?,
) : AutoCloseable {
    private var closed = false

    val projectPath: Path = LinuxFilesystemSyscalls.descriptorPath(projectRoot)
    val reportsPath: Path = LinuxFilesystemSyscalls.descriptorPath(reports)
    val revisionsPath: Path = LinuxFilesystemSyscalls.descriptorPath(revisions)
    val blobsPath: Path = LinuxFilesystemSyscalls.descriptorPath(blobs)

    fun graphExists(): Boolean = exists(revisions, GRAPH_NAME)

    fun bindingExists(): Boolean = exists(revisions, RECOVERY_BINDING_NAME)

    fun blobExists(name: String): Boolean = exists(blobs, name)

    fun revisionFileExists(name: String): Boolean {
        requireRevisionFileName(name)
        return exists(revisions, name)
    }

    fun rootFileExists(name: String): Boolean = exists(projectRoot, name)

    fun readGraph(maximumBytes: Long): ByteArray =
        readRequired(revisions, revisionsPath, GRAPH_NAME, maximumBytes, "repair revision graph")

    fun readBinding(maximumBytes: Long): ByteArray =
        readRequired(revisions, revisionsPath, RECOVERY_BINDING_NAME, maximumBytes, "repair recovery binding")

    fun readBlob(name: String, maximumBytes: Long): StableRegularFile =
        readRequiredStable(blobs, blobsPath, name, maximumBytes, "repair revision blob")

    fun readRevisionFile(name: String, maximumBytes: Long): StableRegularFile {
        requireRevisionFileName(name)
        return readRequiredStable(revisions, revisionsPath, name, maximumBytes, "repair revision evidence")
    }

    fun writeGraph(bytes: ByteArray) = writeAtomically(revisions, GRAPH_NAME, bytes, "revision-state")

    fun preserveLegacyState(kind: String, bytes: ByteArray, maximumBytes: Long) {
        require(kind in setOf("graph", "history"))
        require(bytes.size.toLong() <= maximumBytes)
        val digest = decompengine.project.sha256(bytes)
        val name = "legacy-$kind-$digest.json"
        if (exists(revisions, name)) {
            require(readRequiredStable(revisions, revisionsPath, name, maximumBytes, "legacy repair state").bytes.contentEquals(bytes))
        } else {
            writeAtomically(revisions, name, bytes, "legacy-repair-state", requireAbsent = true)
        }
    }

    fun writeBinding(bytes: ByteArray) =
        writeAtomically(revisions, RECOVERY_BINDING_NAME, bytes, "recovery-binding")

    fun writeBlob(name: String, bytes: ByteArray) = writeAtomically(blobs, name, bytes, "revision-blob")

    /**
     * Publishes content-addressed invocation evidence once. A repeated publication is accepted
     * only when the descriptor-pinned existing bytes are identical; an existing different file is
     * never exchanged or overwritten.
     */
    fun writeImmutableRevisionFile(name: String, bytes: ByteArray, maximumBytes: Long) {
        requireRevisionFileName(name)
        require(bytes.size.toLong() <= maximumBytes) {
            "repair revision evidence exceeds its $maximumBytes-byte limit"
        }
        if (exists(revisions, name)) {
            val existing = readRequiredStable(
                revisions,
                revisionsPath,
                name,
                maximumBytes,
                "immutable repair revision evidence",
            )
            require(existing.bytes.contentEquals(bytes)) {
                "immutable repair revision evidence already exists with different content: $name"
            }
            return
        }
        writeAtomically(revisions, name, bytes, "revision-invocation-evidence", requireAbsent = true)
    }

    fun writeReport(name: String, bytes: ByteArray) = writeAtomically(reports, name, bytes, "repair-report")

    fun writeRoot(name: String, bytes: ByteArray) = writeAtomically(projectRoot, name, bytes, "project-evidence")

    fun blobNames(maximumEntries: Int): List<String> {
        checkOpen()
        return LinuxFilesystemSyscalls.directoryEntryNames(blobs, maximumEntries).sorted()
    }

    fun receiptFileNames(maximumEntries: Int): List<String> {
        checkOpen()
        return LinuxFilesystemSyscalls.directoryEntryNames(revisions, maximumEntries)
            .filter(REVISION_EVIDENCE_NAME::matches)
            .sorted()
    }

    fun cleanupUnboundBlobs(maximumEntries: Int, maximumBlobBytes: Long) {
        checkOpen()
        val names = blobNames(maximumEntries)
        val digests = names.associateWith { name ->
            when {
                name.matches(SHA256_NAME) -> name
                BLOB_ATOMIC_NAME.matchEntire(name) != null ->
                    requireNotNull(BLOB_ATOMIC_NAME.matchEntire(name)).groupValues[1]
                BLOB_CLEANUP_NAME.matchEntire(name) != null ->
                    requireNotNull(BLOB_CLEANUP_NAME.matchEntire(name)).groupValues[1]
                else -> throw IOException("unbound repair blob directory contains an unowned entry: $name")
            }
        }
        names.forEach { name ->
            val observed = readRequiredStable(
                blobs,
                blobsPath,
                name,
                maximumBlobBytes,
                "unbound repair blob",
            )
            require(observed.sha256 == digests.getValue(name)) {
                "unbound repair blob content does not match its content-addressed name: $name"
            }
            requireNamedIdentity(blobs, name, observed.identity, "unbound repair blob")
            LinuxFilesystemSyscalls.unlink(blobs.fd, name)
        }
        if (names.isNotEmpty()) LinuxFilesystemSyscalls.synchronize(blobs)
    }

    fun synchronizeBlobs() = LinuxFilesystemSyscalls.synchronize(blobs)

    fun cleanupGraphTemporary() = cleanupAtomicTemporary(revisions, GRAPH_NAME)

    fun cleanupBindingTemporary() = cleanupAtomicTemporary(revisions, RECOVERY_BINDING_NAME)

    fun cleanupBlobTemporary(digest: String) {
        require(digest.matches(SHA256_NAME)) { "repair blob cleanup digest is invalid" }
        cleanupAtomicTemporary(blobs, digest)
    }

    fun cleanupReportTemporary(name: String) = cleanupAtomicTemporary(reports, name)

    fun cleanupRootTemporary(name: String) = cleanupAtomicTemporary(projectRoot, name)

    override fun close() {
        if (closed) return
        closed = true
        blobs.close()
        revisions.close()
        reports.close()
    }

    private fun exists(parent: LinuxDescriptor, name: String): Boolean {
        checkOpen()
        return LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)?.use { file ->
            requireManagedRegularFile(file.identity, parent.identity, "repair-owned state file")
            true
        } ?: false
    }

    private fun readRequired(
        parent: LinuxDescriptor,
        parentPath: Path,
        name: String,
        maximumBytes: Long,
        label: String,
    ): ByteArray = readRequiredStable(parent, parentPath, name, maximumBytes, label).bytes

    private fun readRequiredStable(
        parent: LinuxDescriptor,
        parentPath: Path,
        name: String,
        maximumBytes: Long,
        label: String,
    ): StableRegularFile {
        checkOpen()
        val authorized = requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)) {
            "$label is missing"
        }
        authorized.use {
            requireManagedRegularFile(authorized.identity, parent.identity, label)
            val observed = readStableRegularFile(parentPath, name, maximumBytes)
            require(observed.identity.key == authorized.identity.key &&
                observed.identity.mountId == authorized.identity.mountId) {
                "$label identity changed while it was read"
            }
            return observed
        }
    }

    private fun writeAtomically(
        parent: LinuxDescriptor,
        name: String,
        bytes: ByteArray,
        scope: String,
        requireAbsent: Boolean = false,
    ) {
        checkOpen()
        val temporaryName = atomicTemporaryName(name)
        var linked = false
        var exchanged = false
        var committed = false
        var crashed = false
        var target: LinuxDescriptor? = null
        var prepared: LinuxDescriptor? = null
        try {
            target = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)
            val targetIdentity = target?.identity
            targetIdentity?.let { requireManagedRegularFile(it, parent.identity, "repair evidence target") }
            require(!requireAbsent || targetIdentity == null) {
                "immutable repair evidence target already exists: $name"
            }
            cleanupAtomicTemporary(parent, name)
            prepared = LinuxFilesystemSyscalls.createTemporaryAt(parent.fd)
            LinuxFilesystemSyscalls.write(prepared, bytes) { }
            LinuxFilesystemSyscalls.chmod(prepared, targetIdentity?.mode?.permissions ?: OWNER_READ_WRITE)
            LinuxFilesystemSyscalls.synchronize(prepared)
            val unnamedIdentity = LinuxFilesystemSyscalls.identity(prepared.fd)
            requirePreparedRegularFile(unnamedIdentity, parent.identity, "prepared repair evidence")
            LinuxFilesystemSyscalls.linkTemporaryAt(prepared, parent.fd, temporaryName)
            linked = true
            val preparedIdentity = requireNotNull(
                LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, temporaryName),
            ).use { materialized ->
                requireManagedRegularFile(materialized.identity, parent.identity, "prepared repair evidence")
                require(materialized.identity.key == unnamedIdentity.key &&
                    materialized.identity.mountId == unnamedIdentity.mountId) {
                    "prepared repair evidence changed while it was materialized"
                }
                materialized.identity
            }
            requireNamedIdentity(parent, temporaryName, preparedIdentity, "prepared repair evidence")
            // Make the recovery name durable before it participates in an exchange.
            LinuxFilesystemSyscalls.synchronize(parent)
            faultInjector?.hit(ModuleRevisionFaultPoint.AfterStateTemporaryDirectorySync(scope, name))
            if (targetIdentity == null) {
                var published = false
                try {
                    LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)?.use {
                        error("repair evidence target appeared before atomic publication")
                    }
                    LinuxFilesystemSyscalls.renameNoReplace(parent.fd, temporaryName, name)
                    published = true
                    linked = false
                    requireNamedIdentity(parent, name, preparedIdentity, "published repair evidence")
                    faultInjector?.hit(ModuleRevisionFaultPoint.AfterStatePublicationExchange(scope, name))
                    LinuxFilesystemSyscalls.synchronize(parent)
                } catch (failure: Throwable) {
                    if (failure is Exception) {
                        if (published) {
                            rollbackNewPublication(parent, name, temporaryName, preparedIdentity, failure)
                            linked = true
                        }
                    } else {
                        crashed = true
                    }
                    throw failure
                }
            } else {
                try {
                    requireNamedIdentity(parent, name, targetIdentity, "repair evidence target")
                    LinuxFilesystemSyscalls.exchange(parent.fd, temporaryName, name)
                    exchanged = true
                    requireNamedIdentity(parent, name, preparedIdentity, "published repair evidence")
                    requireNamedIdentity(parent, temporaryName, targetIdentity, "displaced repair evidence")
                    faultInjector?.hit(ModuleRevisionFaultPoint.AfterStatePublicationExchange(scope, name))
                    LinuxFilesystemSyscalls.synchronize(parent)
                } catch (failure: Throwable) {
                    if (failure is Exception) {
                        if (exchanged) {
                            rollbackStateExchange(parent, name, temporaryName, targetIdentity, preparedIdentity, failure)
                            exchanged = false
                        }
                    } else {
                        crashed = true
                    }
                    throw failure
                }
            }
            committed = true
            try {
                faultInjector?.hit(ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync(scope, name))
            } catch (failure: Throwable) {
                if (failure is Exception) {
                    // The published target and its directory entry are already durable.
                } else {
                    crashed = true
                    throw failure
                }
            }
            if (exchanged) {
                // The target publication was already durable. Failure here leaves only a bounded,
                // exact cleanup name which the next store operation removes before proceeding.
                try {
                    requireNamedIdentity(
                        parent,
                        temporaryName,
                        requireNotNull(targetIdentity),
                        "displaced repair evidence",
                    )
                    LinuxFilesystemSyscalls.unlink(parent.fd, temporaryName)
                    exchanged = false
                    linked = false
                    LinuxFilesystemSyscalls.synchronize(parent)
                } catch (_: Exception) {
                    // A future operation removes the exact reserved cleanup name.
                }
            }
        } catch (failure: Throwable) {
            if (failure !is Exception) crashed = true
            throw failure
        } finally {
            prepared?.close()
            target?.close()
            if (!crashed && !committed && (linked || exchanged)) {
                runCatching { cleanupAtomicTemporary(parent, name) }
            }
        }
    }

    private fun cleanupAtomicTemporary(parent: LinuxDescriptor, targetName: String) {
        checkOpen()
        val temporaryName = atomicTemporaryName(targetName)
        val temporary = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, temporaryName) ?: return
        temporary.use {
            requireManagedRegularFile(temporary.identity, parent.identity, "repair evidence temporary")
            requireNamedIdentity(parent, temporaryName, temporary.identity, "repair evidence temporary")
            LinuxFilesystemSyscalls.unlink(parent.fd, temporaryName)
            LinuxFilesystemSyscalls.synchronize(parent)
        }
    }

    private fun checkOpen() = check(!closed) { "repair state store is closed" }

    private fun requireRevisionFileName(name: String) {
        require(name.matches(REVISION_EVIDENCE_NAME)) { "repair revision evidence name is invalid" }
    }

    companion object {
        fun open(
            projectRoot: LinuxDescriptor,
            faultInjector: ModuleRevisionFaultInjector? = null,
        ): RepairStateStore {
            val currentRoot = LinuxFilesystemSyscalls.identity(projectRoot.fd)
            require(currentRoot.key == projectRoot.identity.key && currentRoot.mountId == projectRoot.identity.mountId) {
                "repair project root descriptor identity changed"
            }
            requireSecureDirectory(currentRoot, currentRoot, "repair project root")
            var reports: LinuxDescriptor? = null
            var revisions: LinuxDescriptor? = null
            var blobs: LinuxDescriptor? = null
            try {
                reports = openOrCreateDirectory(projectRoot, REPORTS_NAME)
                revisions = openOrCreateDirectory(reports, REVISIONS_NAME)
                blobs = openOrCreateDirectory(revisions, BLOBS_NAME)
                return RepairStateStore(projectRoot, reports, revisions, blobs, faultInjector)
            } catch (failure: Throwable) {
                blobs?.close()
                revisions?.close()
                reports?.close()
                throw failure
            }
        }
    }
}

private fun openOrCreateDirectory(parent: LinuxDescriptor, name: String): LinuxDescriptor {
    val opened = try {
        LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name)
    } catch (failure: LinuxSyscallException) {
        if (failure.errno != LinuxFilesystemSyscalls.ENOENT) throw failure
        try {
            LinuxFilesystemSyscalls.createDirectory(parent.fd, name, OWNER_ALL)
        } catch (creationFailure: LinuxSyscallException) {
            if (creationFailure.errno != LinuxFilesystemSyscalls.EEXIST) throw creationFailure
        }
        LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name)
    }
    try {
        requireSecureDirectory(opened.identity, parent.identity, "repair state directory $name")
        requireNamedIdentity(parent, name, opened.identity, "repair state directory $name")
        // Also covers an EEXIST loser: no caller may use the selected child until its parent name
        // has been forced durable by this process.
        LinuxFilesystemSyscalls.synchronize(parent)
        return opened
    } catch (failure: Throwable) {
        opened.close()
        throw failure
    }
}

private fun requireSecureDirectory(actual: LinuxFileIdentity, parent: LinuxFileIdentity, label: String) {
    require(actual.isDirectory && !actual.isRegularFile && !actual.isSymbolicLink &&
        actual.mountId == parent.mountId && actual.uid == parent.uid &&
        actual.mode.permissions and GROUP_OR_OTHER_WRITE == 0) {
        "$label must be an owner-controlled directory on the repair project filesystem"
    }
}

private fun requireManagedRegularFile(actual: LinuxFileIdentity, parent: LinuxFileIdentity, label: String) {
    require(actual.isRegularFile && !actual.isDirectory && !actual.isSymbolicLink && actual.linkCount == 1 &&
        actual.mountId == parent.mountId && actual.uid == parent.uid &&
        actual.mode.permissions and GROUP_OR_OTHER_WRITE == 0) {
        "$label must be a single-link owner-controlled regular file on the repair state filesystem"
    }
}

private fun requirePreparedRegularFile(actual: LinuxFileIdentity, parent: LinuxFileIdentity, label: String) {
    require(actual.isRegularFile && !actual.isDirectory && !actual.isSymbolicLink && actual.linkCount == 0 &&
        actual.mountId == parent.mountId && actual.uid == parent.uid &&
        actual.mode.permissions and GROUP_OR_OTHER_WRITE == 0) {
        "$label must be an owner-controlled unnamed regular file on the repair state filesystem"
    }
}

private fun requireNamedIdentity(
    parent: LinuxDescriptor,
    name: String,
    expected: LinuxFileIdentity,
    label: String,
) {
    val current = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name)) {
        "$label disappeared"
    }
    current.use {
        require(current.identity == expected && !current.identity.isSymbolicLink) {
            "$label changed identity"
        }
    }
}

private fun rollbackNewPublication(
    parent: LinuxDescriptor,
    targetName: String,
    temporaryName: String,
    prepared: LinuxFileIdentity,
    primary: Exception,
) {
    try {
        requireNamedIdentity(parent, targetName, prepared, "indeterminate new repair evidence")
        LinuxFilesystemSyscalls.renameNoReplace(parent.fd, targetName, temporaryName)
        LinuxFilesystemSyscalls.synchronize(parent)
    } catch (rollbackFailure: Throwable) {
        val fatal = RepairStateDurabilityError("new repair evidence publication could not be rolled back")
        fatal.addSuppressed(primary)
        fatal.addSuppressed(rollbackFailure)
        throw fatal
    }
}

private fun rollbackStateExchange(
    parent: LinuxDescriptor,
    targetName: String,
    temporaryName: String,
    displaced: LinuxFileIdentity,
    prepared: LinuxFileIdentity,
    primary: Exception,
) {
    try {
        requireNamedIdentity(parent, targetName, prepared, "indeterminate published repair evidence")
        requireNamedIdentity(parent, temporaryName, displaced, "indeterminate displaced repair evidence")
        LinuxFilesystemSyscalls.exchange(parent.fd, temporaryName, targetName)
        requireNamedIdentity(parent, targetName, displaced, "restored repair evidence")
        requireNamedIdentity(parent, temporaryName, prepared, "rolled-back repair evidence")
        LinuxFilesystemSyscalls.synchronize(parent)
    } catch (rollbackFailure: Throwable) {
        val fatal = RepairStateDurabilityError("repair evidence exchange could not be rolled back durably")
        fatal.addSuppressed(primary)
        fatal.addSuppressed(rollbackFailure)
        throw fatal
    }
}

internal class RepairStateDurabilityError(message: String) : Error(message)

private fun atomicTemporaryName(targetName: String): String = ".$targetName.repair-atomic.tmp"

private const val REPORTS_NAME = "reports"
private const val REVISIONS_NAME = "repair-revisions"
private const val BLOBS_NAME = "blobs"
private const val GRAPH_NAME = "graph.json"
private const val RECOVERY_BINDING_NAME = "recovery-binding.json"
private val REVISION_EVIDENCE_NAME = Regex("revision_[A-Za-z0-9_]+\\.(?:acp|builtin)-receipt\\.json")
private const val OWNER_ALL = 0x1c0 // 0700
private const val OWNER_READ_WRITE = 0x180 // 0600
private const val GROUP_OR_OTHER_WRITE = 0x12 // 0022
private val SHA256_NAME = Regex("[0-9a-f]{64}")
private val BLOB_ATOMIC_NAME = Regex("\\.([0-9a-f]{64})\\.repair-atomic\\.tmp")
private val BLOB_CLEANUP_NAME = Regex("([0-9a-f]{64})\\.cleanup")
