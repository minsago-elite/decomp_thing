package decompengine.acp

import com.agentclientprotocol.model.FileSystemCapability
import com.agentclientprotocol.model.ReadTextFileResponse
import com.agentclientprotocol.model.WriteTextFileResponse
import com.agentclientprotocol.protocol.AcpExpectedError
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.InvalidPathException
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections
import java.util.UUID

/** Per-request bounds for the client-owned ACP text-file bridge. */
data class AcpFilesystemLimits(
    val maximumReadBytes: Int = 8 * 1024 * 1024,
    val maximumWriteBytes: Int = 8 * 1024 * 1024,
) {
    init {
        require(maximumReadBytes > 0) { "maximum ACP filesystem read size must be positive" }
        require(maximumWriteBytes > 0) { "maximum ACP filesystem write size must be positive" }
    }
}

enum class AcpFilesystemAuditOutcome { ALLOWED, DENIED, FAILED }

enum class AcpFilesystemAuditReason {
    COMPLETED,
    CAPABILITY_DISABLED,
    CANCELLED,
    INVALID_PATH,
    INVALID_ARGUMENT,
    OUTSIDE_WORKSPACE,
    AMBIGUOUS_ROOT,
    POLICY_DENIED,
    NOT_FOUND,
    NOT_REGULAR_FILE,
    SYMLINK_REJECTED,
    PATH_REPLACED,
    MOUNT_TRANSITION,
    UNSUPPORTED_METADATA,
    RESOURCE_LIMIT,
    INVALID_TEXT,
    IO_FAILURE,
}

/**
 * Metadata-only record of one ACP filesystem decision.
 *
 * The requested absolute path and file content are deliberately absent. [requestedPathSha256]
 * binds even an unresolvable request to its session, method, and decision without logging host paths.
 */
data class AcpFilesystemAuditRecord(
    val sequence: Long,
    val sessionId: String,
    val method: String,
    val requestedPathSha256: String,
    val policyPath: AgentWorkspacePath?,
    val outcome: AcpFilesystemAuditOutcome,
    val reason: AcpFilesystemAuditReason,
)

internal class AcpFilesystemAuditRecorder {
    private var nextSequence = 0L
    private val records = mutableListOf<AcpFilesystemAuditRecord>()

    fun record(
        sessionId: String,
        method: String,
        requestedPath: String,
        policyPath: AgentWorkspacePath?,
        outcome: AcpFilesystemAuditOutcome,
        reason: AcpFilesystemAuditReason,
    ) {
        val requestedPathSha256 = requestedPath.sha256()
        synchronized(records) {
            records += AcpFilesystemAuditRecord(
                sequence = nextSequence++,
                sessionId = sessionId,
                method = method,
                requestedPathSha256 = requestedPathSha256,
                policyPath = policyPath,
                outcome = outcome,
                reason = reason,
            )
        }
    }

    fun snapshot(): List<AcpFilesystemAuditRecord> = synchronized(records) {
        Collections.unmodifiableList(ArrayList(records))
    }
}

/** Test-only interleaving points are placed directly around the security-relevant native primitive. */
internal enum class AcpFilesystemRaceStage {
    AFTER_PARENT_OPENED,
    BEFORE_FINAL_OPEN,
    AFTER_FINAL_OPEN,
    AFTER_TEMPORARY_OPEN,
    AFTER_TEMPORARY_CHMOD,
    AFTER_TEMPORARY_LINK,
    BEFORE_CREATE_RENAME,
    AFTER_CREATE_RENAME,
    BEFORE_REPLACE_EXCHANGE,
    AFTER_REPLACE_EXCHANGE,
    AFTER_DISPLACED_OPEN,
    AFTER_INSTALLED_OPEN,
    AFTER_METADATA_VALIDATION,
    BEFORE_OLD_UNLINK,
    BEFORE_OWNED_UNLINK,
}

internal fun interface AcpFilesystemRaceHook {
    fun run(stage: AcpFilesystemRaceStage, requestedPath: Path)
}

/**
 * Session-scoped filesystem authority for ACP callbacks.
 *
 * Enabled sessions pin roots and descendants with Linux directory descriptors. Reads reopen an
 * authorized O_PATH descriptor through /proc/self/fd, while writes use renameat2 no-replace or an
 * exchange-and-validate transaction. Unsupported hosts fail during broker construction.
 */
internal class AcpFilesystemBroker private constructor(
    private val request: AgentExecutionRequest,
    private val limits: AcpFilesystemLimits,
    private val audit: AcpFilesystemAuditRecorder,
    private val roots: List<SecureRoot>,
    private val readEnabled: Boolean,
    private val writeEnabled: Boolean,
    private val raceHook: AcpFilesystemRaceHook?,
) : AutoCloseable {
    private val lock = Any()

    /** Frozen for the lifetime of this broker/session from the request's immutable policy snapshot. */
    val capability: FileSystemCapability? = if (readEnabled || writeEnabled) {
        FileSystemCapability(readTextFile = readEnabled, writeTextFile = writeEnabled)
    } else {
        null
    }

    suspend fun readTextFile(
        sessionId: String,
        requestedPath: String,
        line: UInt?,
        limit: UInt?,
    ): ReadTextFileResponse = synchronized(lock) {
        var policyPath: AgentWorkspacePath? = null
        try {
            if (!readEnabled) reject(AcpFilesystemAuditReason.CAPABILITY_DISABLED, "filesystem reads are disabled")
            checkpointCancellation()
            val resolved = resolve(requestedPath)
            policyPath = resolved.policyPath
            if (!request.accessPolicy.allows(resolved.policyPath, AgentOperation.READ_FILE)) {
                reject(AcpFilesystemAuditReason.POLICY_DENIED, "filesystem read is outside the workflow allowlist")
            }
            val content = openParent(resolved).use { parent ->
                raceHook?.run(AcpFilesystemRaceStage.AFTER_PARENT_OPENED, resolved.absolutePath)
                parent.verifyBindings()
                parent.openFinalOrNull(resolved.fileName).useRequired(
                    notFoundMessage = "filesystem read target does not exist",
                ) { authorized ->
                    requireReadableIdentity(authorized.identity)
                    raceHook?.run(AcpFilesystemRaceStage.BEFORE_FINAL_OPEN, resolved.absolutePath)
                    parent.verifyBindings()
                    LinuxFilesystemSyscalls.openReadableFrom(authorized).use { opened ->
                        raceHook?.run(AcpFilesystemRaceStage.AFTER_FINAL_OPEN, resolved.absolutePath)
                        if (opened.identity.key != authorized.identity.key) {
                            reject(
                                AcpFilesystemAuditReason.PATH_REPLACED,
                                "filesystem read descriptor changed during authorization",
                            )
                        }
                        requireReadableIdentity(opened.identity)
                        parent.verifyBindings()
                        parent.requireCurrentIdentity(resolved.fileName, authorized.identity)
                        val bytes = try {
                            LinuxFilesystemSyscalls.read(opened, limits.maximumReadBytes, ::checkpointCancellation)
                        } catch (_: LinuxResourceLimitException) {
                            reject(
                                AcpFilesystemAuditReason.RESOURCE_LIMIT,
                                "filesystem read exceeds the configured size limit",
                            )
                        }
                        requireReadableIdentity(LinuxFilesystemSyscalls.identity(opened.fd))
                        parent.verifyBindings()
                        parent.requireCurrentIdentity(resolved.fileName, authorized.identity)
                        selectLines(decodeUtf8(bytes), line, limit)
                    }
                }
            }
            audit.record(sessionId, READ_METHOD, requestedPath, policyPath, AcpFilesystemAuditOutcome.ALLOWED,
                AcpFilesystemAuditReason.COMPLETED)
            ReadTextFileResponse(content)
        } catch (rejected: FilesystemRejected) {
            audit.record(sessionId, READ_METHOD, requestedPath, policyPath, AcpFilesystemAuditOutcome.DENIED,
                rejected.reason)
            throw AcpExpectedError(rejected.safeMessage)
        } catch (_: NoSuchFileException) {
            audit.record(sessionId, READ_METHOD, requestedPath, policyPath, AcpFilesystemAuditOutcome.DENIED,
                AcpFilesystemAuditReason.NOT_FOUND)
            throw AcpExpectedError("filesystem read target does not exist")
        } catch (_: CharacterCodingException) {
            audit.record(sessionId, READ_METHOD, requestedPath, policyPath, AcpFilesystemAuditOutcome.DENIED,
                AcpFilesystemAuditReason.INVALID_TEXT)
            throw AcpExpectedError("filesystem read target is not valid UTF-8 text")
        } catch (_: IOException) {
            audit.record(sessionId, READ_METHOD, requestedPath, policyPath, AcpFilesystemAuditOutcome.FAILED,
                AcpFilesystemAuditReason.IO_FAILURE)
            throw AcpExpectedError("filesystem read failed safely")
        }
    }

    suspend fun writeTextFile(
        sessionId: String,
        requestedPath: String,
        content: String,
    ): WriteTextFileResponse = synchronized(lock) {
        var policyPath: AgentWorkspacePath? = null
        try {
            if (!writeEnabled) reject(AcpFilesystemAuditReason.CAPABILITY_DISABLED, "filesystem writes are disabled")
            checkpointCancellation()
            val resolved = resolve(requestedPath)
            policyPath = resolved.policyPath
            val canCreate = request.accessPolicy.allows(resolved.policyPath, AgentOperation.CREATE_FILE)
            val canWrite = request.accessPolicy.allows(resolved.policyPath, AgentOperation.WRITE_FILE)
            if (!canCreate && !canWrite) {
                reject(AcpFilesystemAuditReason.POLICY_DENIED, "filesystem write is outside the workflow allowlist")
            }
            val encoded = encodeUtf8(content, limits.maximumWriteBytes)
            openParent(resolved).use { parent ->
                parent.openFinalOrNull(resolved.fileName).use { original ->
                    requireWritableIdentity(original?.identity, canCreate, canWrite)
                    raceHook?.run(AcpFilesystemRaceStage.AFTER_PARENT_OPENED, resolved.absolutePath)
                    parent.verifyBindings()
                    parent.requireCurrentOptionalIdentity(resolved.fileName, original?.identity)
                    LinuxFilesystemSyscalls.reserveDescriptors(TRANSACTION_RESERVE_DESCRIPTORS).use { reserve ->
                        reserve.release(TEMPORARY_CREATION_DESCRIPTORS)
                        val temporary = parent.createTemporary(resolved.absolutePath, reserve)
                        try {
                            temporary.descriptor.use { temporaryDescriptor ->
                                LinuxFilesystemSyscalls.write(temporaryDescriptor, encoded, ::checkpointCancellation)
                                val replacementMetadata = if (original == null) {
                                    requireUnadornedTemporary(temporaryDescriptor)
                                    null
                                } else {
                                    prepareReplacement(original, temporaryDescriptor)
                                }
                                parent.verifyBindings()
                                parent.requireCurrentOptionalIdentity(resolved.fileName, original?.identity)
                                parent.requireCurrentIdentity(temporary.name, temporaryDescriptor.identity)
                                if (original == null) {
                                    raceHook?.run(AcpFilesystemRaceStage.BEFORE_CREATE_RENAME, resolved.absolutePath)
                                    checkpointCancellation()
                                    installCreate(
                                        parent,
                                        temporary,
                                        resolved.fileName,
                                        resolved.absolutePath,
                                        reserve,
                                    )
                                } else {
                                    raceHook?.run(AcpFilesystemRaceStage.BEFORE_REPLACE_EXCHANGE, resolved.absolutePath)
                                    checkpointCancellation()
                                    installReplacement(
                                        parent,
                                        temporary,
                                        resolved.fileName,
                                        original,
                                        requireNotNull(replacementMetadata),
                                        resolved.absolutePath,
                                        reserve,
                                    )
                                }
                            }
                        } catch (failure: Throwable) {
                            reserve.close()
                            parent.deleteOwned(
                                temporary.name,
                                temporary.descriptor.identity.key,
                                resolved.absolutePath,
                            )
                            throw failure
                        }
                    }
                }
            }
            audit.record(sessionId, WRITE_METHOD, requestedPath, policyPath, AcpFilesystemAuditOutcome.ALLOWED,
                AcpFilesystemAuditReason.COMPLETED)
            WriteTextFileResponse()
        } catch (rejected: FilesystemRejected) {
            audit.record(sessionId, WRITE_METHOD, requestedPath, policyPath, AcpFilesystemAuditOutcome.DENIED,
                rejected.reason)
            throw AcpExpectedError(rejected.safeMessage)
        } catch (_: NoSuchFileException) {
            audit.record(sessionId, WRITE_METHOD, requestedPath, policyPath, AcpFilesystemAuditOutcome.DENIED,
                AcpFilesystemAuditReason.NOT_FOUND)
            throw AcpExpectedError("filesystem write parent does not exist")
        } catch (_: CharacterCodingException) {
            audit.record(sessionId, WRITE_METHOD, requestedPath, policyPath, AcpFilesystemAuditOutcome.DENIED,
                AcpFilesystemAuditReason.INVALID_TEXT)
            throw AcpExpectedError("filesystem write content is not valid Unicode text")
        } catch (_: IOException) {
            audit.record(sessionId, WRITE_METHOD, requestedPath, policyPath, AcpFilesystemAuditOutcome.FAILED,
                AcpFilesystemAuditReason.IO_FAILURE)
            throw AcpExpectedError("filesystem write failed safely")
        }
    }

    override fun close() {
        synchronized(lock) {
            roots.asReversed().forEach { root -> runCatching { root.descriptor.close() } }
        }
    }

    private fun installCreate(
        parent: SecureParent,
        temporary: SecureTemporary,
        target: String,
        requestedPath: Path,
        reserve: LinuxDescriptorReserve,
    ) {
        try {
            LinuxFilesystemSyscalls.renameNoReplace(parent.fd, temporary.name, target)
        } catch (failure: LinuxSyscallException) {
            if (failure.errno == LinuxFilesystemSyscalls.EEXIST) {
                reject(AcpFilesystemAuditReason.PATH_REPLACED, "filesystem create target appeared during installation")
            }
            if (failure.errno == LinuxFilesystemSyscalls.ENOENT) {
                reject(AcpFilesystemAuditReason.PATH_REPLACED, "filesystem create path changed during installation")
            }
            throw failure
        }
        reserve.release(POST_COMMIT_VALIDATION_DESCRIPTORS)
        try {
            raceHook?.run(AcpFilesystemRaceStage.AFTER_CREATE_RENAME, requestedPath)
            parent.openFinalOrNull(target).useRequired(
                "filesystem create target disappeared after installation",
            ) { installed ->
                raceHook?.run(AcpFilesystemRaceStage.AFTER_INSTALLED_OPEN, requestedPath)
                val metadataMatches = installed.identity.isRegularFile &&
                    installed.identity.key == temporary.descriptor.identity.key &&
                    installed.identity.mode.permissions == CREATE_FILE_MODE &&
                    installed.identity.uid == temporary.descriptor.identity.uid &&
                    installed.identity.gid == temporary.descriptor.identity.gid &&
                    installed.identity.linkCount == 1 &&
                    LinuxFilesystemSyscalls.extendedAttributeNames(installed).isEmpty()
                if (!metadataMatches) {
                    reject(
                        AcpFilesystemAuditReason.PATH_REPLACED,
                        "filesystem create target metadata changed during installation",
                    )
                }
                raceHook?.run(AcpFilesystemRaceStage.AFTER_METADATA_VALIDATION, requestedPath)
            }
        } catch (failure: Throwable) {
            reserve.close()
            rollbackCreate(parent, temporary, target, requestedPath)
            throw failure
        }
    }

    private fun rollbackCreate(
        parent: SecureParent,
        temporary: SecureTemporary,
        target: String,
        requestedPath: Path,
    ) {
        try {
            LinuxFilesystemSyscalls.renameNoReplace(parent.fd, target, temporary.name)
            parent.openFinalOrNull(target).use { restoredTarget ->
                if (restoredTarget != null) {
                    throw IOException("filesystem create rollback left the target present")
                }
            }
            parent.openFinalOrNull(temporary.name).useRequired(
                "filesystem create rollback lost the prepared file",
            ) { restoredTemporary ->
                if (restoredTemporary.identity.key != temporary.descriptor.identity.key) {
                    throw IOException("filesystem create rollback identity mismatch")
                }
            }
            parent.deleteOwned(
                temporary.name,
                temporary.descriptor.identity.key,
                requestedPath,
                required = true,
            )
        } catch (failure: Throwable) {
            throw IOException("filesystem create rollback failed closed", failure)
        }
    }

    private fun installReplacement(
        parent: SecureParent,
        temporary: SecureTemporary,
        target: String,
        original: LinuxDescriptor,
        metadata: ReplacementMetadata,
        requestedPath: Path,
        reserve: LinuxDescriptorReserve,
    ) {
        try {
            LinuxFilesystemSyscalls.exchange(parent.fd, temporary.name, target)
        } catch (failure: LinuxSyscallException) {
            if (failure.errno == LinuxFilesystemSyscalls.ENOENT) {
                reject(AcpFilesystemAuditReason.PATH_REPLACED, "filesystem replacement path changed during installation")
            }
            throw failure
        }
        reserve.release(POST_COMMIT_VALIDATION_DESCRIPTORS)
        try {
            raceHook?.run(AcpFilesystemRaceStage.AFTER_REPLACE_EXCHANGE, requestedPath)
            parent.openFinalOrNull(temporary.name).useRequired(
                "filesystem displaced entry disappeared after exchange",
            ) { displacedDescriptor ->
                raceHook?.run(AcpFilesystemRaceStage.AFTER_DISPLACED_OPEN, requestedPath)
                parent.openFinalOrNull(target).useRequired(
                    "filesystem installed entry disappeared after exchange",
                ) { installedDescriptor ->
                    raceHook?.run(AcpFilesystemRaceStage.AFTER_INSTALLED_OPEN, requestedPath)
                    val installedMatches = metadata.matchesNewFile(
                        installedDescriptor,
                        temporary.descriptor.identity.key,
                    ) && LinuxFilesystemSyscalls.extendedAttributeNames(installedDescriptor).isEmpty()
                    val displacedMatches = metadata.matchesOriginal(displacedDescriptor) &&
                        LinuxFilesystemSyscalls.extendedAttributeNames(displacedDescriptor).isEmpty()
                    if (!installedMatches || !displacedMatches) {
                        val reason = if (displacedDescriptor.identity.isSymbolicLink) {
                            AcpFilesystemAuditReason.SYMLINK_REJECTED
                        } else {
                            AcpFilesystemAuditReason.PATH_REPLACED
                        }
                        reject(reason, "filesystem replacement target changed during installation")
                    }
                    raceHook?.run(AcpFilesystemRaceStage.AFTER_METADATA_VALIDATION, requestedPath)
                    raceHook?.run(AcpFilesystemRaceStage.BEFORE_OLD_UNLINK, requestedPath)
                    parent.deleteOwned(
                        temporary.name,
                        original.identity.key,
                        requestedPath,
                        required = true,
                        invokeOwnedUnlinkHook = false,
                    )
                }
            }
        } catch (failure: Throwable) {
            reserve.close()
            rollbackReplacement(parent, temporary, target, requestedPath)
            throw failure
        }
    }

    private fun rollbackReplacement(
        parent: SecureParent,
        temporary: SecureTemporary,
        target: String,
        requestedPath: Path,
    ) {
        try {
            val displacedKey = parent.openFinalOrNull(temporary.name).useRequired(
                "filesystem displaced entry disappeared before rollback",
            ) { displaced -> displaced.identity.key }
            val installedKey = parent.openFinalOrNull(target).useRequired(
                "filesystem installed entry disappeared before rollback",
            ) { installed -> installed.identity.key }
            LinuxFilesystemSyscalls.exchange(parent.fd, temporary.name, target)
            parent.openFinalOrNull(target).useRequired(
                "filesystem replacement target disappeared during rollback",
            ) { restoredTarget ->
                parent.openFinalOrNull(temporary.name).useRequired(
                    "filesystem replacement temporary disappeared during rollback",
                ) { restoredTemporary ->
                    if (
                        restoredTarget.identity.key != displacedKey ||
                        restoredTemporary.identity.key != installedKey
                    ) {
                        throw IOException("filesystem replacement rollback identity mismatch")
                    }
                }
            }
            if (installedKey != temporary.descriptor.identity.key) {
                throw IOException("filesystem replacement rollback did not recover the prepared file")
            }
            parent.deleteOwned(
                temporary.name,
                temporary.descriptor.identity.key,
                requestedPath,
                required = true,
            )
        } catch (failure: Throwable) {
            throw IOException("filesystem replacement rollback failed closed", failure)
        }
    }

    private fun prepareReplacement(original: LinuxDescriptor, temporary: LinuxDescriptor): ReplacementMetadata {
        if (LinuxFilesystemSyscalls.extendedAttributeNames(original).isNotEmpty()) {
            reject(AcpFilesystemAuditReason.UNSUPPORTED_METADATA,
                "filesystem replacement would discard extended metadata")
        }
        if (original.identity.linkCount != 1) {
            reject(AcpFilesystemAuditReason.UNSUPPORTED_METADATA,
                "filesystem replacement would change hard-link semantics")
        }
        requireUnadornedTemporary(temporary)
        if (temporary.identity.uid != original.identity.uid || temporary.identity.gid != original.identity.gid) {
            reject(AcpFilesystemAuditReason.UNSUPPORTED_METADATA,
                "filesystem replacement cannot preserve file ownership")
        }
        LinuxFilesystemSyscalls.chmod(temporary, original.identity.mode.permissions)
        val refreshed = LinuxFilesystemSyscalls.identity(temporary.fd)
        if (refreshed.key != temporary.identity.key ||
            refreshed.mode.permissions != original.identity.mode.permissions ||
            refreshed.uid != original.identity.uid || refreshed.gid != original.identity.gid) {
            reject(AcpFilesystemAuditReason.UNSUPPORTED_METADATA,
                "filesystem replacement cannot preserve POSIX mode and ownership")
        }
        return ReplacementMetadata(original.identity.key, original.identity.mode.permissions,
            original.identity.uid, original.identity.gid, original.identity.linkCount)
    }

    private fun requireUnadornedTemporary(temporary: LinuxDescriptor) {
        if (LinuxFilesystemSyscalls.extendedAttributeNames(temporary).isNotEmpty()) {
            reject(AcpFilesystemAuditReason.UNSUPPORTED_METADATA,
                "filesystem default metadata prevents a metadata-safe write")
        }
        val refreshed = LinuxFilesystemSyscalls.identity(temporary.fd)
        if (!refreshed.isRegularFile || refreshed.key != temporary.identity.key) {
            reject(AcpFilesystemAuditReason.PATH_REPLACED, "secure temporary file identity changed")
        }
    }

    private fun resolve(raw: String): ResolvedPath {
        val absolute = try {
            Path.of(raw)
        } catch (_: InvalidPathException) {
            reject(AcpFilesystemAuditReason.INVALID_PATH, "filesystem path is invalid")
        }
        if (!absolute.isAbsolute || absolute != absolute.normalize()) {
            reject(AcpFilesystemAuditReason.INVALID_PATH, "filesystem path must be absolute and normalized")
        }
        val candidates = roots.filter { root -> absolute.startsWith(root.declaredPath) }
        if (candidates.isEmpty()) {
            reject(AcpFilesystemAuditReason.OUTSIDE_WORKSPACE, "filesystem path is outside the authorized workspace")
        }
        val longest = candidates.maxOf { it.declaredPath.nameCount }
        val selected = candidates.filter { it.declaredPath.nameCount == longest }
        if (selected.size != 1) {
            reject(AcpFilesystemAuditReason.AMBIGUOUS_ROOT, "filesystem path matches more than one workspace root")
        }
        val root = selected.single()
        val relative = root.declaredPath.relativize(absolute)
        if (relative.nameCount == 0) {
            reject(AcpFilesystemAuditReason.INVALID_PATH, "filesystem operation requires a file path")
        }
        val relativeText = relative.toString().replace(relative.fileSystem.separator, "/")
        val policyPath = try {
            AgentWorkspacePath(root.root.id, relativeText)
        } catch (_: IllegalArgumentException) {
            reject(AcpFilesystemAuditReason.INVALID_PATH, "filesystem path is not a normalized workspace path")
        }
        return ResolvedPath(root, absolute, relative, relative.fileName.toString(), policyPath)
    }

    private fun openParent(resolved: ResolvedPath): SecureParent {
        val opened = mutableListOf<LinuxDescriptor>()
        val bindings = mutableListOf(DirectoryBinding(resolved.root.declaredPath, resolved.root.descriptor.identity.key))
        var current = resolved.root.descriptor
        try {
            val parent = resolved.relative.parent
            if (parent != null) {
                for (componentPath in parent) {
                    checkpointCancellation()
                    val component = componentPath.toString()
                    val child = try {
                        LinuxFilesystemSyscalls.openDirectoryAt(current.fd, component)
                    } catch (failure: LinuxSyscallException) {
                        classifyDirectoryOpenFailure(current.fd, component, failure)
                    }
                    if (!child.identity.isDirectory || child.identity.isSymbolicLink) {
                        child.close()
                        reject(AcpFilesystemAuditReason.NOT_REGULAR_FILE,
                            "filesystem path component is not a directory")
                    }
                    if (child.identity.mountId != resolved.root.descriptor.identity.mountId) {
                        child.close()
                        reject(
                            AcpFilesystemAuditReason.MOUNT_TRANSITION,
                            "filesystem mount transitions beneath a workspace root are not allowed",
                        )
                    }
                    opened += child
                    current = child
                    bindings += DirectoryBinding(bindings.last().hostPath.resolve(component), child.identity.key)
                }
            }
            return SecureParent(
                current,
                opened,
                bindings,
                resolved.root.descriptor.identity.mountId,
            )
        } catch (failure: Throwable) {
            opened.asReversed().forEach { descriptor -> runCatching { descriptor.close() } }
            throw failure
        }
    }

    private fun classifyDirectoryOpenFailure(parentFd: Int, component: String,
        failure: LinuxSyscallException): Nothing {
        if (failure.errno == LinuxFilesystemSyscalls.ENOENT) throw NoSuchFileException(component)
        if (failure.errno == LinuxFilesystemSyscalls.ELOOP || failure.errno == LinuxFilesystemSyscalls.ENOTDIR) {
            LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, component).use { entry ->
                if (entry == null) throw NoSuchFileException(component)
                if (entry.identity.isSymbolicLink) {
                    reject(AcpFilesystemAuditReason.SYMLINK_REJECTED, "filesystem links are not allowed")
                }
                reject(AcpFilesystemAuditReason.NOT_REGULAR_FILE,
                    "filesystem path component is not a directory")
            }
        }
        throw failure
    }

    private fun checkpointCancellation() {
        if (request.cancellation.isCancellationRequested()) {
            reject(AcpFilesystemAuditReason.CANCELLED, "filesystem operation was cancelled")
        }
    }

    private fun requireReadableIdentity(identity: LinuxFileIdentity) {
        if (identity.isSymbolicLink) {
            reject(AcpFilesystemAuditReason.SYMLINK_REJECTED, "filesystem links are not allowed")
        }
        if (!identity.isRegularFile) {
            reject(AcpFilesystemAuditReason.NOT_REGULAR_FILE,
                "filesystem read target is not a regular file")
        }
        if (identity.linkCount != 1) {
            reject(
                AcpFilesystemAuditReason.UNSUPPORTED_METADATA,
                "filesystem reads require a single-link regular file",
            )
        }
    }

    private fun requireWritableIdentity(identity: LinuxFileIdentity?, canCreate: Boolean, canWrite: Boolean) {
        if (identity == null) {
            if (!canCreate) reject(AcpFilesystemAuditReason.POLICY_DENIED,
                "workflow does not allow file creation")
            return
        }
        if (identity.isSymbolicLink) {
            reject(AcpFilesystemAuditReason.SYMLINK_REJECTED, "filesystem links are not allowed")
        }
        if (!identity.isRegularFile) {
            reject(AcpFilesystemAuditReason.NOT_REGULAR_FILE,
                "filesystem write target is not a regular file")
        }
        if (!canWrite) reject(AcpFilesystemAuditReason.POLICY_DENIED,
            "workflow does not allow file replacement")
    }

    private fun selectLines(text: String, line: UInt?, limit: UInt?): String {
        val firstLine = line?.toLong() ?: 1L
        if (firstLine == 0L) reject(AcpFilesystemAuditReason.INVALID_ARGUMENT,
            "filesystem read line must be one-based")
        val maximumLines = limit?.toLong() ?: Long.MAX_VALUE
        if (maximumLines == 0L) return ""
        var cursor = 0
        var currentLine = 1L
        while (currentLine < firstLine) {
            val newline = text.indexOf('\n', cursor)
            if (newline < 0) return ""
            cursor = newline + 1
            currentLine++
        }
        if (maximumLines == Long.MAX_VALUE) return text.substring(cursor)
        var end = cursor
        var selected = 0L
        while (selected < maximumLines && end < text.length) {
            val newline = text.indexOf('\n', end)
            if (newline < 0) {
                end = text.length
                break
            }
            end = newline + 1
            selected++
        }
        return text.substring(cursor, end)
    }

    private inner class SecureParent(
        private val descriptor: LinuxDescriptor,
        private val opened: List<LinuxDescriptor>,
        private val bindings: List<DirectoryBinding>,
        private val rootMountId: Long,
    ) : AutoCloseable {
        val fd: Int get() = descriptor.fd

        fun openFinalOrNull(name: String): LinuxDescriptor? {
            val opened = LinuxFilesystemSyscalls.openPathAtOrNull(fd, name) ?: return null
            if (opened.identity.mountId != rootMountId) {
                opened.close()
                reject(
                    AcpFilesystemAuditReason.MOUNT_TRANSITION,
                    "filesystem mount transitions beneath a workspace root are not allowed",
                )
            }
            return opened
        }

        fun verifyBindings() {
            bindings.forEach { binding ->
                checkpointCancellation()
                try {
                    LinuxFilesystemSyscalls.openAbsolutePathOrNull(binding.hostPath).use { current ->
                        if (
                            current == null ||
                            !current.identity.isDirectory ||
                            current.identity.isSymbolicLink ||
                            current.identity.key != binding.key
                        ) {
                            reject(
                                AcpFilesystemAuditReason.PATH_REPLACED,
                                "filesystem path changed during authorization",
                            )
                        }
                    }
                } catch (_: IOException) {
                    reject(
                        AcpFilesystemAuditReason.PATH_REPLACED,
                        "filesystem path changed during authorization",
                    )
                }
            }
        }

        fun requireCurrentIdentity(name: String, expected: LinuxFileIdentity) {
            openFinalOrNull(name).useRequired("filesystem target disappeared during authorization") { current ->
                if (current.identity.isSymbolicLink) {
                    reject(AcpFilesystemAuditReason.SYMLINK_REJECTED,
                        "filesystem target became a link")
                }
                if (!current.identity.isRegularFile || current.identity.key != expected.key) {
                    reject(AcpFilesystemAuditReason.PATH_REPLACED,
                        "filesystem target changed during authorization")
                }
            }
        }

        fun requireCurrentOptionalIdentity(name: String, expected: LinuxFileIdentity?) {
            openFinalOrNull(name).use { current ->
                if (expected == null && current == null) return
                if (expected == null || current == null) {
                    reject(AcpFilesystemAuditReason.PATH_REPLACED,
                        "filesystem target changed during authorization")
                }
                if (current.identity.isSymbolicLink) {
                    reject(AcpFilesystemAuditReason.SYMLINK_REJECTED,
                        "filesystem target became a link")
                }
                if (!current.identity.isRegularFile || current.identity.key != expected.key) {
                    reject(AcpFilesystemAuditReason.PATH_REPLACED,
                        "filesystem target changed during authorization")
                }
            }
        }

        fun createTemporary(requestedPath: Path, reserve: LinuxDescriptorReserve): SecureTemporary {
            val name = ".decomp-acp-${UUID.randomUUID()}.tmp"
            val descriptor = LinuxFilesystemSyscalls.createTemporaryAt(fd)
            var materialized = false
            try {
                raceHook?.run(AcpFilesystemRaceStage.AFTER_TEMPORARY_OPEN, requestedPath)
                LinuxFilesystemSyscalls.chmod(descriptor, CREATE_FILE_MODE)
                raceHook?.run(AcpFilesystemRaceStage.AFTER_TEMPORARY_CHMOD, requestedPath)
                val refreshed = LinuxFilesystemSyscalls.identity(descriptor.fd)
                if (
                    refreshed.key != descriptor.identity.key ||
                    !refreshed.isRegularFile ||
                    refreshed.mode.permissions != CREATE_FILE_MODE
                ) {
                    throw IOException("secure temporary file does not have the required identity and mode")
                }
                LinuxFilesystemSyscalls.linkTemporaryAt(descriptor, fd, name)
                materialized = true
                raceHook?.run(AcpFilesystemRaceStage.AFTER_TEMPORARY_LINK, requestedPath)
                requireCurrentIdentity(name, descriptor.identity)
                return SecureTemporary(name, descriptor)
            } catch (failure: Throwable) {
                reserve.close()
                try {
                    if (materialized) {
                        deleteOwned(
                            name,
                            descriptor.identity.key,
                            requestedPath,
                            invokeOwnedUnlinkHook = false,
                        )
                    }
                } catch (cleanupFailure: Throwable) {
                    failure.addSuppressed(cleanupFailure)
                } finally {
                    descriptor.close()
                }
                throw failure
            }
        }

        fun deleteOwned(
            name: String,
            expected: LinuxFileKey,
            requestedPath: Path,
            required: Boolean = false,
            invokeOwnedUnlinkHook: Boolean = true,
        ) {
            val quarantine = ".decomp-acp-quarantine-${UUID.randomUUID()}.tmp"
            var quarantined = false
            try {
                try {
                    LinuxFilesystemSyscalls.renameNoReplace(fd, name, quarantine)
                    quarantined = true
                } catch (failure: LinuxSyscallException) {
                    if (failure.errno == LinuxFilesystemSyscalls.ENOENT && !required) return
                    throw failure
                }
                openFinalOrNull(quarantine).useRequired(
                    "quarantined filesystem entry disappeared before cleanup",
                ) { firstInspection ->
                    if (firstInspection.identity.key != expected) {
                        throw OwnedEntryChangedException()
                    }
                }
                if (invokeOwnedUnlinkHook) {
                    raceHook?.run(AcpFilesystemRaceStage.BEFORE_OWNED_UNLINK, requestedPath)
                }
                openFinalOrNull(quarantine).useRequired(
                    "quarantined filesystem entry disappeared at cleanup",
                ) { finalInspection ->
                    if (finalInspection.identity.key != expected) {
                        throw OwnedEntryChangedException()
                    }
                    LinuxFilesystemSyscalls.unlink(fd, quarantine)
                    quarantined = false
                }
                // There must be no fallible work after the irreversible unlink above.
                return
            } catch (failure: Throwable) {
                if (quarantined) {
                    try {
                        LinuxFilesystemSyscalls.renameNoReplace(fd, quarantine, name)
                        quarantined = false
                    } catch (restoreFailure: Throwable) {
                        failure.addSuppressed(restoreFailure)
                    }
                }
                if (required || failure !is OwnedEntryChangedException) throw failure
            }
        }

        override fun close() {
            opened.asReversed().forEach { child -> runCatching { child.close() } }
        }
    }

    companion object {
        private const val READ_METHOD = "fs/read_text_file"
        private const val WRITE_METHOD = "fs/write_text_file"
        private const val CREATE_FILE_MODE = 0x180 // 0600
        private const val TRANSACTION_RESERVE_DESCRIPTORS = 8
        private const val TEMPORARY_CREATION_DESCRIPTORS = 1
        private const val POST_COMMIT_VALIDATION_DESCRIPTORS = 4

        fun open(request: AgentExecutionRequest, limits: AcpFilesystemLimits,
            audit: AcpFilesystemAuditRecorder, raceHook: AcpFilesystemRaceHook? = null): AcpFilesystemBroker {
            val readEnabled = request.accessPolicy.pathRules.any { rule ->
                AgentOperation.READ_FILE in rule.operations &&
                    AgentOperation.READ_FILE in request.accessPolicy.allowedOperations
            }
            val writeEnabled = hasEffectiveFilesystemWriteCapability(
                request.accessPolicy.pathRules,
                request.accessPolicy.allowedOperations,
            )
            if (!readEnabled && !writeEnabled) {
                return AcpFilesystemBroker(request, limits, audit, emptyList(), false, false, raceHook)
            }
            val opened = mutableListOf<SecureRoot>()
            try {
                request.workspaceRoots.forEach { root -> opened += openRoot(root) }
                return AcpFilesystemBroker(request, limits, audit,
                    opened.sortedByDescending { it.declaredPath.nameCount }, readEnabled, writeEnabled, raceHook)
            } catch (failure: Throwable) {
                opened.asReversed().forEach { root -> runCatching { root.descriptor.close() } }
                throw failure
            }
        }

        private fun openRoot(root: AgentWorkspaceRoot): SecureRoot {
            try {
                LinuxFilesystemSyscalls.requireSupported(root.path)
                val realPath = root.path.toRealPath()
                if (realPath != root.path) {
                    throw filesystemConfigurationFailure(root,
                        "workspace root must be a canonical real path")
                }
                LinuxFilesystemSyscalls.openAbsolutePathOrNull(root.path).use { lexical ->
                    if (lexical == null || !lexical.identity.isDirectory || lexical.identity.isSymbolicLink) {
                        throw filesystemConfigurationFailure(
                            root,
                            "workspace root must be a real directory, not a link",
                        )
                    }
                    val descriptor = LinuxFilesystemSyscalls.openRoot(root.path)
                    if (
                        !descriptor.identity.isDirectory ||
                        descriptor.identity.isSymbolicLink ||
                        descriptor.identity.key != lexical.identity.key ||
                        descriptor.identity.mountId != lexical.identity.mountId
                    ) {
                        descriptor.close()
                        throw filesystemConfigurationFailure(
                            root,
                            "workspace root changed while authority was opened",
                        )
                    }
                    return SecureRoot(root, root.path, descriptor)
                }
            } catch (failure: AgentExecutionException) {
                throw failure
            } catch (failure: Throwable) {
                throw filesystemConfigurationFailure(root,
                    "cannot provide race-safe Linux filesystem access", failure)
            }
        }

        private fun filesystemConfigurationFailure(root: AgentWorkspaceRoot, message: String,
            cause: Throwable? = null): AgentExecutionException = AgentExecutionException(
            AgentFailure(
                AgentFailureKind.CONFIGURATION,
                "ACP filesystem broker $message for root ${root.id}",
                details = mapOf("rootId" to root.id),
            ),
            cause,
        )
    }
}

internal fun hasEffectiveFilesystemWriteCapability(
    pathRules: Collection<AgentPathRule>,
    allowedOperations: Set<AgentOperation>,
): Boolean = pathRules.any { rule ->
    (AgentOperation.WRITE_FILE in rule.operations && AgentOperation.WRITE_FILE in allowedOperations) ||
        (AgentOperation.CREATE_FILE in rule.operations && AgentOperation.CREATE_FILE in allowedOperations)
}

private data class SecureRoot(
    val root: AgentWorkspaceRoot,
    val declaredPath: Path,
    val descriptor: LinuxDescriptor,
)

private data class ResolvedPath(
    val root: SecureRoot,
    val absolutePath: Path,
    val relative: Path,
    val fileName: String,
    val policyPath: AgentWorkspacePath,
)

private data class DirectoryBinding(val hostPath: Path, val key: LinuxFileKey)
private data class SecureTemporary(val name: String, val descriptor: LinuxDescriptor)

private data class ReplacementMetadata(
    val key: LinuxFileKey,
    val mode: Int,
    val uid: Int,
    val gid: Int,
    val linkCount: Int,
) {
    fun matchesOriginal(descriptor: LinuxDescriptor): Boolean = descriptor.identity.run {
        isRegularFile && !isSymbolicLink && key == this@ReplacementMetadata.key &&
            mode.permissions == this@ReplacementMetadata.mode &&
            uid == this@ReplacementMetadata.uid && gid == this@ReplacementMetadata.gid &&
            linkCount == this@ReplacementMetadata.linkCount
    }

    fun matchesNewFile(descriptor: LinuxDescriptor, expectedKey: LinuxFileKey): Boolean = descriptor.identity.run {
        isRegularFile && !isSymbolicLink && key == expectedKey &&
            mode.permissions == this@ReplacementMetadata.mode &&
            uid == this@ReplacementMetadata.uid && gid == this@ReplacementMetadata.gid &&
            linkCount == 1
    }
}

private class FilesystemRejected(
    val reason: AcpFilesystemAuditReason,
    val safeMessage: String,
) : RuntimeException(safeMessage)

private class OwnedEntryChangedException : IOException("owned filesystem entry changed before cleanup")

private fun reject(reason: AcpFilesystemAuditReason, safeMessage: String): Nothing =
    throw FilesystemRejected(reason, safeMessage)

private inline fun <T> LinuxDescriptor?.useRequired(notFoundMessage: String,
    block: (LinuxDescriptor) -> T): T {
    val descriptor = this ?: throw NoSuchFileException(notFoundMessage)
    return descriptor.use(block)
}

private fun decodeUtf8(content: ByteArray): String = StandardCharsets.UTF_8.newDecoder()
    .onMalformedInput(CodingErrorAction.REPORT)
    .onUnmappableCharacter(CodingErrorAction.REPORT)
    .decode(ByteBuffer.wrap(content))
    .toString()

private fun encodeUtf8(content: String, maximumBytes: Int): ByteArray {
    val encoded = StandardCharsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .encode(java.nio.CharBuffer.wrap(content))
    if (encoded.remaining() > maximumBytes) {
        reject(AcpFilesystemAuditReason.RESOURCE_LIMIT,
            "filesystem write exceeds the configured size limit")
    }
    return ByteArray(encoded.remaining()).also(encoded::get)
}

private fun String.sha256(): String = MessageDigest.getInstance("SHA-256")
    .digest(toByteArray(StandardCharsets.UTF_8))
    .joinToString("") { byte -> "%02x".format(byte) }
