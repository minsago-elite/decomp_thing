package decompengine.oracle.fulltree

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemCapacity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Locale
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class FullTreeDiskScratchException(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

internal data class FullTreeDiskScratchPolicy(
    val requiredAvailableBytes: Long,
    val maximumFilesystemBytes: Long,
    val requiredAvailableInodes: Long,
    val maximumFilesystemInodes: Long,
) {
    init {
        require(requiredAvailableBytes > 0L)
        require(maximumFilesystemBytes >= requiredAvailableBytes)
        require(requiredAvailableInodes >= MINIMUM_LEASE_INODES)
        require(maximumFilesystemInodes >= requiredAvailableInodes)
    }
}

internal data class FullTreeDiskScratchOperation(
    val operationId: String,
    val requestSha256: String,
    val shardId: String,
    val scopeSha256: String,
) {
    init {
        require(operationId.matches(SHA256)) { "disk-scratch operation ID must be a random 256-bit hex value" }
        require(requestSha256.matches(SHA256)) { "disk-scratch request digest is invalid" }
        require(shardId.matches(SHARD_IDENTIFIER)) { "disk-scratch shard identifier is invalid" }
        require(scopeSha256.matches(SHA256)) { "disk-scratch scope digest is invalid" }
    }
}

internal enum class FullTreeDiskScratchStage {
    AUTHORIZED,
    BEFORE_LAUNCH,
    AFTER_SCOPE_ATTACHMENT,
    FROZEN_BARRIER,
    AFTER_CGROUP_ABSENCE,
    BEFORE_PUBLICATION,
    AFTER_PUBLICATION,
    RELEASE,
}

/** Canonical historical acquisition record; this artifact is not current or release authority. */
internal class FullTreeDiskScratchLeaseRecord private constructor(
    val schemaVersion: Int,
    val provider: String,
    val operationId: String,
    val requestSha256: String,
    val shardId: String,
    val scopeSha256: String,
    val mountPathSha256: String,
    val mountId: Long,
    val device: Long,
    val rootInode: Long,
    val filesystemDevice: String,
    val filesystemType: String,
    val totalBytes: Long,
    val totalInodes: Long,
    val requiredAvailableBytes: Long,
    val maximumFilesystemBytes: Long,
    val requiredAvailableInodes: Long,
    val maximumFilesystemInodes: Long,
    mountFlags: List<String>,
    val leaseRootDevice: Long,
    val leaseRootInode: Long,
    val recordSha256: String,
) {
    val mountFlags: List<String> = java.util.List.copyOf(mountFlags)

    init {
        if (
            schemaVersion != DISK_SCRATCH_LEASE_SCHEMA_VERSION ||
            provider != FULL_TREE_DISK_SCRATCH_PROVIDER ||
            !operationId.matches(SHA256) || !requestSha256.matches(SHA256) ||
            !shardId.matches(SHARD_IDENTIFIER) || !scopeSha256.matches(SHA256) ||
            !mountPathSha256.matches(SHA256) || mountId <= 0L || device < 0L || rootInode <= 0L ||
            !filesystemDevice.matches(FILESYSTEM_DEVICE) || filesystemType != REQUIRED_FILESYSTEM_TYPE ||
            totalBytes <= 0L || totalInodes <= 0L || requiredAvailableBytes <= 0L ||
            maximumFilesystemBytes < requiredAvailableBytes || requiredAvailableInodes < MINIMUM_LEASE_INODES ||
            maximumFilesystemInodes < requiredAvailableInodes || totalBytes > maximumFilesystemBytes ||
            totalInodes > maximumFilesystemInodes || totalBytes < requiredAvailableBytes ||
            totalInodes < requiredAvailableInodes || mountFlags != mountFlags.distinct().sorted() ||
            mountFlags.any { !it.matches(MOUNT_OPTION) } ||
            !REQUIRED_MOUNT_FLAGS.all(mountFlags::contains) || leaseRootDevice < 0L || leaseRootInode <= 0L ||
            !recordSha256.matches(SHA256)
        ) scratchFail("disk-scratch lease record has invalid fields")
        if (recordSha256 != ZERO_SHA256 && recordSha256 != sha256(canonicalBytes(includeSelfHash = false))) {
            scratchFail("disk-scratch lease record self hash is invalid")
        }
    }

    fun canonicalBytes(): ByteArray = canonicalBytes(includeSelfHash = true)

    internal fun canonicalBytesWithoutSelfHashForTest(): ByteArray = canonicalBytes(includeSelfHash = false)

    private fun canonicalBytes(includeSelfHash: Boolean): ByteArray = OracleJson.canonicalBytes(
        JsonObject(
            buildMap {
                put("device", JsonPrimitive(device))
                put("filesystemDevice", JsonPrimitive(filesystemDevice))
                put("filesystemType", JsonPrimitive(filesystemType))
                put("leaseRootDevice", JsonPrimitive(leaseRootDevice))
                put("leaseRootInode", JsonPrimitive(leaseRootInode))
                put("maximumFilesystemBytes", JsonPrimitive(maximumFilesystemBytes))
                put("maximumFilesystemInodes", JsonPrimitive(maximumFilesystemInodes))
                put("mountFlags", JsonArray(mountFlags.map(::JsonPrimitive)))
                put("mountId", JsonPrimitive(mountId))
                put("mountPathSha256", JsonPrimitive(mountPathSha256))
                put("operationId", JsonPrimitive(operationId))
                put("provider", JsonPrimitive(provider))
                if (includeSelfHash) put("recordSha256", JsonPrimitive(recordSha256))
                put("requestSha256", JsonPrimitive(requestSha256))
                put("requiredAvailableBytes", JsonPrimitive(requiredAvailableBytes))
                put("requiredAvailableInodes", JsonPrimitive(requiredAvailableInodes))
                put("rootInode", JsonPrimitive(rootInode))
                put("schemaVersion", JsonPrimitive(schemaVersion))
                put("scopeSha256", JsonPrimitive(scopeSha256))
                put("shardId", JsonPrimitive(shardId))
                put("totalBytes", JsonPrimitive(totalBytes))
                put("totalInodes", JsonPrimitive(totalInodes))
            },
        ),
        DISK_SCRATCH_RECORD_JSON_LIMITS,
    )

    internal companion object {
        fun create(
            operation: FullTreeDiskScratchOperation,
            policy: FullTreeDiskScratchPolicy,
            mountPath: Path,
            mount: FullTreeDiskMount,
            mountIdentity: LinuxFileIdentity,
            capacity: LinuxFilesystemCapacity,
            leaseIdentity: LinuxFileIdentity,
        ): FullTreeDiskScratchLeaseRecord {
            if (!mountPath.isAbsolute || mountPath.normalize() != mountPath) {
                scratchFail("disk-scratch lease record mount path must be absolute and normalized")
            }
            val arguments = RecordArguments(
                operation,
                policy,
                mountPath,
                mount,
                mountIdentity,
                capacity,
                leaseIdentity,
            )
            val provisional = arguments.record(ZERO_SHA256)
            return arguments.record(sha256(provisional.canonicalBytes(includeSelfHash = false)))
        }

        fun parseCanonical(bytes: ByteArray): FullTreeDiskScratchLeaseRecord =
            translateScratchFailures {
                val root = OracleJson.parseCanonical(bytes, DISK_SCRATCH_RECORD_JSON_LIMITS) as? JsonObject
                    ?: scratchFail("disk-scratch lease record must be an object")
                root.requireExactRecordKeys()
                FullTreeDiskScratchLeaseRecord(
                    schemaVersion = root.recordInt("schemaVersion"),
                    provider = root.recordString("provider"),
                    operationId = root.recordString("operationId"),
                    requestSha256 = root.recordString("requestSha256"),
                    shardId = root.recordString("shardId"),
                    scopeSha256 = root.recordString("scopeSha256"),
                    mountPathSha256 = root.recordString("mountPathSha256"),
                    mountId = root.recordLong("mountId"),
                    device = root.recordLong("device"),
                    rootInode = root.recordLong("rootInode"),
                    filesystemDevice = root.recordString("filesystemDevice"),
                    filesystemType = root.recordString("filesystemType"),
                    totalBytes = root.recordLong("totalBytes"),
                    totalInodes = root.recordLong("totalInodes"),
                    requiredAvailableBytes = root.recordLong("requiredAvailableBytes"),
                    maximumFilesystemBytes = root.recordLong("maximumFilesystemBytes"),
                    requiredAvailableInodes = root.recordLong("requiredAvailableInodes"),
                    maximumFilesystemInodes = root.recordLong("maximumFilesystemInodes"),
                    mountFlags = root.recordStringArray("mountFlags"),
                    leaseRootDevice = root.recordLong("leaseRootDevice"),
                    leaseRootInode = root.recordLong("leaseRootInode"),
                    recordSha256 = root.recordString("recordSha256"),
                ).also { record ->
                    if (record.recordSha256 == ZERO_SHA256) {
                        scratchFail("disk-scratch lease record cannot retain its provisional hash")
                    }
                }
            }
    }

    private data class RecordArguments(
        val operation: FullTreeDiskScratchOperation,
        val policy: FullTreeDiskScratchPolicy,
        val mountPath: Path,
        val mount: FullTreeDiskMount,
        val mountIdentity: LinuxFileIdentity,
        val capacity: LinuxFilesystemCapacity,
        val leaseIdentity: LinuxFileIdentity,
    ) {
        fun record(selfHash: String) = FullTreeDiskScratchLeaseRecord(
            schemaVersion = DISK_SCRATCH_LEASE_SCHEMA_VERSION,
            provider = FULL_TREE_DISK_SCRATCH_PROVIDER,
            operationId = operation.operationId,
            requestSha256 = operation.requestSha256,
            shardId = operation.shardId,
            scopeSha256 = operation.scopeSha256,
            mountPathSha256 = sha256(mountPath.toString()),
            mountId = mountIdentity.mountId,
            device = mountIdentity.key.device,
            rootInode = mountIdentity.key.inode,
            filesystemDevice = mount.device,
            filesystemType = mount.fileSystemType,
            totalBytes = capacity.totalBytes,
            totalInodes = capacity.totalInodes,
            requiredAvailableBytes = policy.requiredAvailableBytes,
            maximumFilesystemBytes = policy.maximumFilesystemBytes,
            requiredAvailableInodes = policy.requiredAvailableInodes,
            maximumFilesystemInodes = policy.maximumFilesystemInodes,
            mountFlags = mount.options.sorted(),
            leaseRootDevice = leaseIdentity.key.device,
            leaseRootInode = leaseIdentity.key.inode,
            recordSha256 = selfHash,
        )
    }
}

/** Canonical, self-hashed evidence for one hard aggregate disk/inode lease. */
internal class FullTreeDiskScratchEvidence private constructor(
    val schemaVersion: Int,
    val provider: String,
    val operationId: String,
    val requestSha256: String,
    val shardId: String,
    val scopeSha256: String,
    val mountPathSha256: String,
    val mountId: Long,
    val device: Long,
    val rootInode: Long,
    val filesystemDevice: String,
    val filesystemType: String,
    val fragmentBytes: Long,
    val totalBytes: Long,
    val initialAvailableBytes: Long,
    val totalInodes: Long,
    val initialAvailableInodes: Long,
    val ownerUid: Int,
    val mode: Int,
    val mountFlags: List<String>,
    val requiredAvailableBytes: Long,
    val maximumFilesystemBytes: Long,
    val requiredAvailableInodes: Long,
    val maximumFilesystemInodes: Long,
    val leaseRootDevice: Long,
    val leaseRootInode: Long,
    val leaseRecordSha256: String,
    val evidenceSha256: String,
) {
    init {
        require(schemaVersion == DISK_SCRATCH_EVIDENCE_SCHEMA_VERSION)
        require(provider == FULL_TREE_DISK_SCRATCH_PROVIDER)
        require(operationId.matches(SHA256))
        require(requestSha256.matches(SHA256))
        require(shardId.matches(SHARD_IDENTIFIER))
        require(scopeSha256.matches(SHA256))
        require(mountPathSha256.matches(SHA256))
        require(mountId > 0L && device >= 0L && rootInode > 0L)
        require(filesystemDevice.matches(FILESYSTEM_DEVICE))
        require(filesystemType == REQUIRED_FILESYSTEM_TYPE)
        require(fragmentBytes > 0L && totalBytes > 0L)
        require(initialAvailableBytes in 0L..totalBytes)
        require(totalInodes > 0L && initialAvailableInodes in 0L..totalInodes)
        require(ownerUid >= 0 && mode == OWNER_DIRECTORY_MODE)
        require(mountFlags == mountFlags.distinct().sorted())
        require(REQUIRED_MOUNT_FLAGS.all(mountFlags::contains))
        require(requiredAvailableBytes > 0L && maximumFilesystemBytes >= requiredAvailableBytes)
        require(requiredAvailableInodes >= MINIMUM_LEASE_INODES)
        require(maximumFilesystemInodes >= requiredAvailableInodes)
        require(totalBytes <= maximumFilesystemBytes && initialAvailableBytes >= requiredAvailableBytes)
        require(totalInodes <= maximumFilesystemInodes && initialAvailableInodes >= requiredAvailableInodes)
        require(leaseRootDevice >= 0L && leaseRootInode > 0L)
        require(leaseRecordSha256.matches(SHA256))
        require(evidenceSha256.matches(SHA256))
        if (evidenceSha256 != ZERO_SHA256) {
            require(evidenceSha256 == OracleArtifacts.sha256(canonicalBytes(includeSelfHash = false))) {
                "disk-scratch evidence self hash is invalid"
            }
        }
    }

    fun canonicalBytes(): ByteArray = canonicalBytes(includeSelfHash = true)

    internal fun canonicalBytesWithoutSelfHashForTest(): ByteArray = canonicalBytes(includeSelfHash = false)

    private fun canonicalBytes(includeSelfHash: Boolean): ByteArray = OracleJson.canonicalBytes(
        JsonObject(
            buildMap {
                put("device", JsonPrimitive(device))
                if (includeSelfHash) put("evidenceSha256", JsonPrimitive(evidenceSha256))
                put("filesystemDevice", JsonPrimitive(filesystemDevice))
                put("filesystemType", JsonPrimitive(filesystemType))
                put("fragmentBytes", JsonPrimitive(fragmentBytes))
                put("initialAvailableBytes", JsonPrimitive(initialAvailableBytes))
                put("initialAvailableInodes", JsonPrimitive(initialAvailableInodes))
                put("leaseRecordSha256", JsonPrimitive(leaseRecordSha256))
                put("leaseRootDevice", JsonPrimitive(leaseRootDevice))
                put("leaseRootInode", JsonPrimitive(leaseRootInode))
                put("maximumFilesystemBytes", JsonPrimitive(maximumFilesystemBytes))
                put("maximumFilesystemInodes", JsonPrimitive(maximumFilesystemInodes))
                put("mode", JsonPrimitive(mode))
                put("mountFlags", JsonArray(mountFlags.map(::JsonPrimitive)))
                put("mountId", JsonPrimitive(mountId))
                put("mountPathSha256", JsonPrimitive(mountPathSha256))
                put("operationId", JsonPrimitive(operationId))
                put("ownerUid", JsonPrimitive(ownerUid))
                put("provider", JsonPrimitive(provider))
                put("requestSha256", JsonPrimitive(requestSha256))
                put("requiredAvailableBytes", JsonPrimitive(requiredAvailableBytes))
                put("requiredAvailableInodes", JsonPrimitive(requiredAvailableInodes))
                put("rootInode", JsonPrimitive(rootInode))
                put("schemaVersion", JsonPrimitive(schemaVersion))
                put("scopeSha256", JsonPrimitive(scopeSha256))
                put("shardId", JsonPrimitive(shardId))
                put("totalBytes", JsonPrimitive(totalBytes))
                put("totalInodes", JsonPrimitive(totalInodes))
            },
        ),
    )

    internal companion object {
        fun create(
            operation: FullTreeDiskScratchOperation,
            policy: FullTreeDiskScratchPolicy,
            mountPathSha256: String,
            mount: FullTreeDiskMount,
            mountIdentity: LinuxFileIdentity,
            capacity: LinuxFilesystemCapacity,
            leaseIdentity: LinuxFileIdentity,
            leaseRecordSha256: String,
        ): FullTreeDiskScratchEvidence {
            val arguments = EvidenceArguments(
                operation,
                policy,
                mountPathSha256,
                mount,
                mountIdentity,
                capacity,
                leaseIdentity,
                leaseRecordSha256,
            )
            val provisional = arguments.evidence(ZERO_SHA256)
            return arguments.evidence(OracleArtifacts.sha256(provisional.canonicalBytes(includeSelfHash = false)))
        }
    }

    private data class EvidenceArguments(
        val operation: FullTreeDiskScratchOperation,
        val policy: FullTreeDiskScratchPolicy,
        val mountPathSha256: String,
        val mount: FullTreeDiskMount,
        val mountIdentity: LinuxFileIdentity,
        val capacity: LinuxFilesystemCapacity,
        val leaseIdentity: LinuxFileIdentity,
        val leaseRecordSha256: String,
    ) {
        fun evidence(selfHash: String) = FullTreeDiskScratchEvidence(
            schemaVersion = DISK_SCRATCH_EVIDENCE_SCHEMA_VERSION,
            provider = FULL_TREE_DISK_SCRATCH_PROVIDER,
            operationId = operation.operationId,
            requestSha256 = operation.requestSha256,
            shardId = operation.shardId,
            scopeSha256 = operation.scopeSha256,
            mountPathSha256 = mountPathSha256,
            mountId = mountIdentity.mountId,
            device = mountIdentity.key.device,
            rootInode = mountIdentity.key.inode,
            filesystemDevice = mount.device,
            filesystemType = mount.fileSystemType,
            fragmentBytes = capacity.fragmentBytes,
            totalBytes = capacity.totalBytes,
            initialAvailableBytes = capacity.availableBytes,
            totalInodes = capacity.totalInodes,
            initialAvailableInodes = capacity.availableInodes,
            ownerUid = mountIdentity.uid,
            mode = mountIdentity.mode.permissions,
            mountFlags = mount.options.sorted(),
            requiredAvailableBytes = policy.requiredAvailableBytes,
            maximumFilesystemBytes = policy.maximumFilesystemBytes,
            requiredAvailableInodes = policy.requiredAvailableInodes,
            maximumFilesystemInodes = policy.maximumFilesystemInodes,
            leaseRootDevice = leaseIdentity.key.device,
            leaseRootInode = leaseIdentity.key.inode,
            leaseRecordSha256 = leaseRecordSha256,
            evidenceSha256 = selfHash,
        )
    }
}

/**
 * Exclusive lease over one pre-provisioned fixed-size ext4 filesystem.
 *
 * This type proves only aggregate scratch capacity and identity. It cannot by itself authorize a
 * release: stable operation recovery, worker/cgroup evidence, and whole-run accounting remain
 * separate mandatory authorities.
 */
internal class FullTreeDiskScratchLease internal constructor(
    val scratchParent: Path,
    val evidence: FullTreeDiskScratchEvidence,
    private val mountPath: Path,
    private val mountDescriptor: LinuxDescriptor,
    private val leaseName: String,
    private val leaseDescriptor: LinuxDescriptor,
    private val leaseRecordBytes: ByteArray,
    private val policy: FullTreeDiskScratchPolicy,
    private val authorizedMount: FullTreeDiskMount,
    private val authorizedCapacity: LinuxFilesystemCapacity,
) : AutoCloseable {
    private var closed = false

    @Synchronized
    fun requireCurrent(stage: FullTreeDiskScratchStage) {
        check(!closed) { "disk-scratch lease is closed" }
        requireTrustedMountAncestors(mountPath)
        requireMountCurrent(
            mountPath,
            mountDescriptor,
            policy,
            authorizedMount,
            authorizedCapacity,
            requireInitialAvailability = stage == FullTreeDiskScratchStage.AUTHORIZED,
        )
        requireSameDirectory(mountPath, mountDescriptor, "disk-scratch mount root")
        mountDescriptor.whileOpen { mountFd ->
            LinuxFilesystemSyscalls.openDirectoryAt(mountFd, leaseName).use { selected ->
                val current = LinuxFilesystemSyscalls.identity(leaseDescriptor.fd)
                if (!sameDirectory(current, selected.identity) || current.mode.permissions != OWNER_DIRECTORY_MODE) {
                    scratchFail("disk-scratch lease root changed at $stage")
                }
            }
        }
        requireSameDirectory(scratchParent, leaseDescriptor, "disk-scratch lease root")
        requireLeaseRecord()
        val names = LinuxFilesystemSyscalls.directoryEntryNames(
            leaseDescriptor,
            MAXIMUM_LEASE_ROOT_ENTRIES + 1,
        ).sorted()
        val extra = names.filter { it != LEASE_RECORD_FILE }
        if (LEASE_RECORD_FILE !in names || extra.size > 1) {
            scratchFail("disk-scratch lease root has unexpected membership at $stage")
        }
        val expectedRunName = ".function-observation-run-${evidence.operationId}"
        val requiresActiveRun = when (stage) {
            FullTreeDiskScratchStage.BEFORE_LAUNCH,
            FullTreeDiskScratchStage.AFTER_SCOPE_ATTACHMENT,
            FullTreeDiskScratchStage.FROZEN_BARRIER,
            FullTreeDiskScratchStage.AFTER_CGROUP_ABSENCE,
            -> true

            FullTreeDiskScratchStage.AUTHORIZED,
            FullTreeDiskScratchStage.BEFORE_PUBLICATION,
            FullTreeDiskScratchStage.AFTER_PUBLICATION,
            FullTreeDiskScratchStage.RELEASE,
            -> false
        }
        if (requiresActiveRun && extra != listOf(expectedRunName)) {
            scratchFail("disk-scratch lease lacks its operation-bound active run at $stage")
        }
        if (!requiresActiveRun && extra.isNotEmpty()) {
            scratchFail("disk-scratch lease unexpectedly contains an active run at $stage")
        }
        if (requiresActiveRun) {
            LinuxFilesystemSyscalls.openDirectoryAt(leaseDescriptor.fd, expectedRunName).use { run ->
                val identity = LinuxFilesystemSyscalls.identity(run.fd)
                if (
                    identity.mountId != mountDescriptor.identity.mountId ||
                    identity.uid != mountDescriptor.identity.uid ||
                    identity.mode.permissions != OWNER_DIRECTORY_MODE || identity.isSymbolicLink
                ) scratchFail("disk-scratch active run root is not private at $stage")
            }
        }
    }

    @Synchronized
    fun requireCleanAndRelease() {
        check(!closed) { "disk-scratch lease is closed" }
        var failure: Throwable? = null
        try {
            requireCurrent(FullTreeDiskScratchStage.RELEASE)
            val quarantine = ".decomp-oracle-lease-release-${evidence.operationId}"
            mountDescriptor.whileOpen { mountFd ->
                LinuxFilesystemSyscalls.renameNoReplace(mountFd, leaseName, quarantine)
                LinuxFilesystemSyscalls.openDirectoryAt(mountFd, quarantine).use { selected ->
                    if (!sameDirectory(LinuxFilesystemSyscalls.identity(leaseDescriptor.fd), selected.identity)) {
                        scratchFail("disk-scratch release selected a replacement lease root")
                    }
                }
                LinuxFilesystemSyscalls.unlink(leaseDescriptor.fd, LEASE_RECORD_FILE)
                LinuxFilesystemSyscalls.synchronize(leaseDescriptor)
                if (LinuxFilesystemSyscalls.directoryEntryNames(leaseDescriptor, 1).isNotEmpty()) {
                    scratchFail("disk-scratch lease root is not empty at release")
                }
                LinuxFilesystemSyscalls.removeDirectory(mountFd, quarantine)
                LinuxFilesystemSyscalls.synchronize(mountDescriptor)
                LinuxFilesystemSyscalls.openPathAtOrNull(mountFd, leaseName)?.use {
                    scratchFail("disk-scratch lease root remains after release")
                }
                LinuxFilesystemSyscalls.openPathAtOrNull(mountFd, quarantine)?.use {
                    scratchFail("disk-scratch lease quarantine remains after release")
                }
            }
            if (LinuxFilesystemSyscalls.identity(leaseDescriptor.fd).linkCount != 0) {
                scratchFail("disk-scratch lease descriptor remains linked after release")
            }
            if (LinuxFilesystemSyscalls.directoryEntryNames(mountDescriptor, 1).isNotEmpty()) {
                scratchFail("dedicated disk-scratch filesystem is not empty after release")
            }
        } catch (releaseFailure: Throwable) {
            failure = releaseFailure
        } finally {
            closed = true
            runCatching { leaseDescriptor.close() }.exceptionOrNull()?.let { closeFailure ->
                if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
            }
            runCatching { LinuxFilesystemSyscalls.unlock(mountDescriptor) }.exceptionOrNull()?.let { unlockFailure ->
                if (failure == null) failure = unlockFailure else failure.addSuppressed(unlockFailure)
            }
            runCatching { mountDescriptor.close() }.exceptionOrNull()?.let { closeFailure ->
                if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
            }
        }
        failure?.let { throw it }
    }

    private fun requireLeaseRecord() {
        val record = LinuxFilesystemSyscalls.openRegularFileAtOrNull(leaseDescriptor.fd, LEASE_RECORD_FILE)
            ?: scratchFail("disk-scratch lease record disappeared")
        record.use { authorized ->
            val identity = LinuxFilesystemSyscalls.identity(authorized.fd)
            if (
                identity.mountId != mountDescriptor.identity.mountId ||
                identity.uid != mountDescriptor.identity.uid ||
                identity.mode.permissions != OWNER_READ_ONLY_MODE || identity.linkCount != 1
            ) scratchFail("disk-scratch lease record identity or mode changed")
            val actual = LinuxFilesystemSyscalls.openReadableFrom(authorized).use { readable ->
                LinuxFilesystemSyscalls.read(readable, MAXIMUM_LEASE_RECORD_BYTES) {}
            }
            if (!MessageDigest.isEqual(actual, leaseRecordBytes)) {
                scratchFail("disk-scratch lease record bytes changed")
            }
        }
    }

    override fun close() {
        if (!closed) requireCleanAndRelease()
    }
}

internal enum class FullTreeDiskScratchColdPopulation {
    RECORD_ONLY,
    ACTIVE_OPERATION_RUN,
}

internal data class FullTreeDiskScratchColdSnapshot(
    val leaseRecordSha256: String,
    val recordSelfSha256: String,
    val population: FullTreeDiskScratchColdPopulation,
)

/**
 * Lock-retaining, observation-only handle for one exact residual lease.
 *
 * This handle never creates, repairs, synchronizes, renames, quarantines, unlinks, cleans, or
 * releases anything. Closing it only closes pinned descriptors and releases the mount flock. A
 * returned snapshot is neither durable evidence nor mutation/release authority. The flock is a
 * coordinator primitive for cooperating processes running as the mount owner; it is not a security
 * boundary against an unrelated same-UID process. A later recovery authority must independently
 * reconcile exact evidence before any mutation.
 */
internal class FullTreeDiskScratchColdLease internal constructor(
    private val scratchParent: Path,
    private val operation: FullTreeDiskScratchOperation,
    private val policy: FullTreeDiskScratchPolicy,
    private val mountPath: Path,
    private val mountDescriptor: LinuxDescriptor,
    private val leaseName: String,
    private val leaseDescriptor: LinuxDescriptor,
    private val recordDescriptor: LinuxDescriptor,
    private val recordBytes: ByteArray,
    private val record: FullTreeDiskScratchLeaseRecord,
    private val authorizedMount: FullTreeDiskMount,
    private val authorizedCapacity: LinuxFilesystemCapacity,
) : AutoCloseable {
    private var closed = false

    @Synchronized
    fun requireCurrent(): FullTreeDiskScratchColdSnapshot {
        check(!closed) { "disk-scratch cold lease is closed" }
        requireTrustedMountAncestors(mountPath)
        val authorized = requireMountCurrent(
            mountPath,
            mountDescriptor,
            policy,
            authorizedMount,
            authorizedCapacity,
            requireInitialAvailability = false,
        )
        requireSameDirectory(mountPath, mountDescriptor, "cold disk-scratch mount root")
        requireExactMountMembership(mountDescriptor, leaseName)
        mountDescriptor.whileOpen { mountFd ->
            LinuxFilesystemSyscalls.openDirectoryAt(mountFd, leaseName).use { selected ->
                val current = LinuxFilesystemSyscalls.identity(leaseDescriptor.fd)
                if (!sameDirectory(current, selected.identity)) {
                    scratchFail("cold disk-scratch lease root changed")
                }
            }
        }
        requireSameDirectory(scratchParent, leaseDescriptor, "cold disk-scratch lease root")
        val leaseIdentity = LinuxFilesystemSyscalls.identity(leaseDescriptor.fd)
        requireManagedLeaseDirectory(leaseIdentity, mountDescriptor.identity, "cold disk-scratch lease root")
        requirePinnedLeaseRecord(
            recordDescriptor,
            recordBytes,
            leaseDescriptor,
            mountDescriptor.identity,
        )
        requireLeaseRecordMatches(
            record,
            operation,
            policy,
            mountPath,
            authorized.mount,
            LinuxFilesystemSyscalls.identity(mountDescriptor.fd),
            authorized.capacity,
            leaseIdentity,
        )
        val population = requireColdPopulation(
            leaseDescriptor,
            mountDescriptor.identity,
            runDirectoryName(operation.operationId),
        )
        // Re-select and reauthenticate every object after content and population inspection.
        val finalAuthorized = requireMountCurrent(
            mountPath,
            mountDescriptor,
            policy,
            authorizedMount,
            authorizedCapacity,
            requireInitialAvailability = false,
        )
        requireSameDirectory(mountPath, mountDescriptor, "cold disk-scratch mount root")
        requireExactMountMembership(mountDescriptor, leaseName)
        mountDescriptor.whileOpen { mountFd ->
            LinuxFilesystemSyscalls.openDirectoryAt(mountFd, leaseName).use { selected ->
                if (!sameDirectory(
                        LinuxFilesystemSyscalls.identity(leaseDescriptor.fd),
                        LinuxFilesystemSyscalls.identity(selected.fd),
                    )
                ) scratchFail("cold disk-scratch lease root changed after inspection")
            }
        }
        requirePinnedLeaseRecord(
            recordDescriptor,
            recordBytes,
            leaseDescriptor,
            mountDescriptor.identity,
        )
        requireLeaseRecordMatches(
            record,
            operation,
            policy,
            mountPath,
            finalAuthorized.mount,
            LinuxFilesystemSyscalls.identity(mountDescriptor.fd),
            finalAuthorized.capacity,
            LinuxFilesystemSyscalls.identity(leaseDescriptor.fd),
        )
        val finalPopulation = requireColdPopulation(
            leaseDescriptor,
            mountDescriptor.identity,
            runDirectoryName(operation.operationId),
        )
        val firstRunIdentity = population.second
        val finalRunIdentity = finalPopulation.second
        if (
            finalPopulation.first != population.first ||
            (firstRunIdentity == null) != (finalRunIdentity == null) ||
            firstRunIdentity != null && !sameDirectory(firstRunIdentity, checkNotNull(finalRunIdentity))
        ) scratchFail("cold disk-scratch lease population changed before its snapshot")
        return FullTreeDiskScratchColdSnapshot(
            leaseRecordSha256 = sha256(recordBytes),
            recordSelfSha256 = record.recordSha256,
            population = finalPopulation.first,
        )
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        runCatching { recordDescriptor.close() }.exceptionOrNull()?.let { failure = it }
        runCatching { leaseDescriptor.close() }.exceptionOrNull()?.let { closeFailure ->
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        runCatching { LinuxFilesystemSyscalls.unlock(mountDescriptor) }.exceptionOrNull()?.let { unlockFailure ->
            if (failure == null) failure = unlockFailure else failure.addSuppressed(unlockFailure)
        }
        runCatching { mountDescriptor.close() }.exceptionOrNull()?.let { closeFailure ->
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        failure?.let { throw it }
    }
}

internal object FullTreeDiskScratchAuthority {
    fun openExistingReadOnly(
        provisionedMount: Path,
        operation: FullTreeDiskScratchOperation,
        policy: FullTreeDiskScratchPolicy,
    ): FullTreeDiskScratchColdLease = translateScratchFailures {
        val mountPath = provisionedMount.toAbsolutePath().normalize()
        if (!mountPath.isAbsolute || mountPath.parent == null || mountPath.toRealPath() != mountPath) {
            scratchFail("cold disk-scratch mount must be a canonical absolute non-root path")
        }
        requireTrustedMountAncestors(mountPath)
        LinuxFilesystemSyscalls.requireSupported(mountPath)
        val mountDescriptor = LinuxFilesystemSyscalls.openRoot(mountPath)
        var locked = false
        var leaseDescriptor: LinuxDescriptor? = null
        var recordDescriptor: LinuxDescriptor? = null
        try {
            requireSameDirectory(mountPath, mountDescriptor, "cold disk-scratch mount root")
            if (!LinuxFilesystemSyscalls.tryExclusiveLock(mountDescriptor)) {
                scratchFail("dedicated disk-scratch filesystem is already leased")
            }
            locked = true
            val authorized = requireMountCurrent(
                mountPath,
                mountDescriptor,
                policy,
                expectedMount = null,
                expectedCapacity = null,
                requireInitialAvailability = false,
            )
            val expectedLeaseName = ".decomp-oracle-lease-${operation.operationId}"
            requireExactMountMembership(mountDescriptor, expectedLeaseName)
            val lease = LinuxFilesystemSyscalls.openDirectoryAt(mountDescriptor.fd, expectedLeaseName)
            leaseDescriptor = lease
            val leaseIdentity = LinuxFilesystemSyscalls.identity(lease.fd)
            requireManagedLeaseDirectory(
                leaseIdentity,
                mountDescriptor.identity,
                "cold disk-scratch lease root",
            )
            requireSameDirectory(
                mountPath.resolve(expectedLeaseName),
                lease,
                "cold disk-scratch lease root",
            )
            val record = LinuxFilesystemSyscalls.openRegularFileAtOrNull(lease.fd, LEASE_RECORD_FILE)
                ?: scratchFail("cold disk-scratch lease record is absent")
            recordDescriptor = record
            requireLeaseRecordIdentity(record, mountDescriptor.identity)
            val recordBytes = LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(record).use { readable ->
                LinuxFilesystemSyscalls.read(readable, MAXIMUM_LEASE_RECORD_BYTES) {}
            }
            val parsed = FullTreeDiskScratchLeaseRecord.parseCanonical(recordBytes)
            requireLeaseRecordMatches(
                parsed,
                operation,
                policy,
                mountPath,
                authorized.mount,
                LinuxFilesystemSyscalls.identity(mountDescriptor.fd),
                authorized.capacity,
                leaseIdentity,
            )
            val cold = FullTreeDiskScratchColdLease(
                scratchParent = mountPath.resolve(expectedLeaseName),
                operation = operation,
                policy = policy,
                mountPath = mountPath,
                mountDescriptor = mountDescriptor,
                leaseName = expectedLeaseName,
                leaseDescriptor = lease,
                recordDescriptor = record,
                recordBytes = recordBytes,
                record = parsed,
                authorizedMount = authorized.mount,
                authorizedCapacity = authorized.capacity,
            )
            cold.requireCurrent()
            recordDescriptor = null
            leaseDescriptor = null
            locked = false
            cold
        } catch (failure: Throwable) {
            recordDescriptor?.let { opened ->
                runCatching { opened.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            }
            leaseDescriptor?.let { opened ->
                runCatching { opened.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            }
            if (locked) {
                runCatching { LinuxFilesystemSyscalls.unlock(mountDescriptor) }
                    .exceptionOrNull()?.let(failure::addSuppressed)
            }
            runCatching { mountDescriptor.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
    }

    fun acquireDedicatedFilesystem(
        provisionedMount: Path,
        operation: FullTreeDiskScratchOperation,
        policy: FullTreeDiskScratchPolicy,
    ): FullTreeDiskScratchLease = translateScratchFailures {
        val mountPath = provisionedMount.toAbsolutePath().normalize()
        if (!mountPath.isAbsolute || mountPath.parent == null || mountPath.toRealPath() != mountPath) {
            scratchFail("disk-scratch mount must be a canonical absolute non-root path")
        }
        requireTrustedMountAncestors(mountPath)
        LinuxFilesystemSyscalls.requireSupported(mountPath)
        val mountDescriptor = LinuxFilesystemSyscalls.openRoot(mountPath)
        var locked = false
        var leaseDescriptor: LinuxDescriptor? = null
        var leaseName: String? = null
        try {
            requireSameDirectory(mountPath, mountDescriptor, "disk-scratch mount root")
            if (!LinuxFilesystemSyscalls.tryExclusiveLock(mountDescriptor)) {
                scratchFail("dedicated disk-scratch filesystem is already leased")
            }
            locked = true
            val authorized = requireMountCurrent(
                mountPath,
                mountDescriptor,
                policy,
                expectedMount = null,
                expectedCapacity = null,
                requireInitialAvailability = true,
            )
            if (LinuxFilesystemSyscalls.directoryEntryNames(mountDescriptor, 1).isNotEmpty()) {
                scratchFail("dedicated disk-scratch filesystem requires recovery before acquisition")
            }
            val createdName = ".decomp-oracle-lease-${operation.operationId}"
            leaseName = createdName
            LinuxFilesystemSyscalls.createDirectory(mountDescriptor.fd, createdName, OWNER_DIRECTORY_MODE)
            val created = LinuxFilesystemSyscalls.openDirectoryAt(mountDescriptor.fd, createdName)
            leaseDescriptor = created
            LinuxFilesystemSyscalls.chmod(created, OWNER_DIRECTORY_MODE)
            val leaseIdentity = LinuxFilesystemSyscalls.identity(created.fd)
            if (
                leaseIdentity.mountId != mountDescriptor.identity.mountId ||
                leaseIdentity.uid != mountDescriptor.identity.uid ||
                leaseIdentity.mode.permissions != OWNER_DIRECTORY_MODE || leaseIdentity.isSymbolicLink
            ) scratchFail("created disk-scratch lease root is not private on the dedicated mount")
            val recordBytes = leaseRecordBytes(
                operation,
                policy,
                mountPath,
                authorized.mount,
                mountDescriptor.identity,
                authorized.capacity,
                leaseIdentity,
            )
            LinuxFilesystemSyscalls.createRegularFile(
                created.fd,
                LEASE_RECORD_FILE,
                OWNER_READ_WRITE_MODE,
            ).use { record ->
                LinuxFilesystemSyscalls.write(record, recordBytes) {}
                LinuxFilesystemSyscalls.chmod(record, OWNER_READ_ONLY_MODE)
                LinuxFilesystemSyscalls.synchronize(record)
            }
            LinuxFilesystemSyscalls.synchronize(created)
            LinuxFilesystemSyscalls.synchronize(mountDescriptor)
            val recordSha256 = OracleArtifacts.sha256(recordBytes)
            val evidence = FullTreeDiskScratchEvidence.create(
                operation,
                policy,
                sha256(mountPath.toString()),
                authorized.mount,
                mountDescriptor.identity,
                authorized.capacity,
                leaseIdentity,
                recordSha256,
            )
            val lease = FullTreeDiskScratchLease(
                scratchParent = mountPath.resolve(createdName),
                evidence = evidence,
                mountPath = mountPath,
                mountDescriptor = mountDescriptor,
                leaseName = createdName,
                leaseDescriptor = created,
                leaseRecordBytes = recordBytes,
                policy = policy,
                authorizedMount = authorized.mount,
                authorizedCapacity = authorized.capacity,
            )
            lease.requireCurrent(FullTreeDiskScratchStage.AUTHORIZED)
            leaseDescriptor = null
            locked = false
            lease
        } catch (failure: Throwable) {
            val created = leaseDescriptor
            val createdName = leaseName
            if (created != null && createdName != null) {
                runCatching {
                    val quarantine = ".decomp-oracle-lease-failed-${operation.operationId}"
                    mountDescriptor.whileOpen { mountFd ->
                        LinuxFilesystemSyscalls.renameNoReplace(mountFd, createdName, quarantine)
                        LinuxFilesystemSyscalls.openDirectoryAt(mountFd, quarantine).use { selected ->
                            if (!sameDirectory(LinuxFilesystemSyscalls.identity(created.fd), selected.identity)) {
                                scratchFail("failed disk-scratch cleanup selected a replacement lease root")
                            }
                            LinuxFilesystemSyscalls.openPathAtOrNull(mountFd, createdName)?.use {
                                scratchFail("failed disk-scratch lease name reappeared during cleanup")
                            }
                            LinuxFilesystemSyscalls.unlinkIfPresent(created.fd, LEASE_RECORD_FILE)
                            LinuxFilesystemSyscalls.synchronize(created)
                            if (LinuxFilesystemSyscalls.directoryEntryNames(created, 1).isNotEmpty()) {
                                scratchFail("failed disk-scratch lease root is not empty")
                            }
                            LinuxFilesystemSyscalls.removeDirectory(mountFd, quarantine)
                            if (LinuxFilesystemSyscalls.identity(created.fd).linkCount != 0) {
                                scratchFail("failed disk-scratch lease descriptor remains linked")
                            }
                        }
                        LinuxFilesystemSyscalls.synchronize(mountDescriptor)
                        LinuxFilesystemSyscalls.openPathAtOrNull(mountFd, createdName)?.use {
                            scratchFail("failed disk-scratch lease name remains after cleanup")
                        }
                        LinuxFilesystemSyscalls.openPathAtOrNull(mountFd, quarantine)?.use {
                            scratchFail("failed disk-scratch quarantine remains after cleanup")
                        }
                    }
                }.exceptionOrNull()?.let(failure::addSuppressed)
                runCatching { created.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            }
            if (locked) {
                runCatching { LinuxFilesystemSyscalls.unlock(mountDescriptor) }
                    .exceptionOrNull()?.let(failure::addSuppressed)
            }
            runCatching { mountDescriptor.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
    }
}

private data class AuthorizedDiskScratch(
    val mount: FullTreeDiskMount,
    val capacity: LinuxFilesystemCapacity,
)

internal data class FullTreeDiskMount(
    val mountId: Long,
    val parentMountId: Long,
    val device: String,
    val root: Path,
    val mountPoint: Path,
    val options: List<String>,
    val fileSystemType: String,
)

private fun requireMountCurrent(
    path: Path,
    descriptor: LinuxDescriptor,
    policy: FullTreeDiskScratchPolicy,
    expectedMount: FullTreeDiskMount?,
    expectedCapacity: LinuxFilesystemCapacity?,
    requireInitialAvailability: Boolean,
): AuthorizedDiskScratch {
    val identity = LinuxFilesystemSyscalls.identity(descriptor.fd)
    val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
    if (
        !sameDirectory(identity, descriptor.identity) || !identity.isDirectory || identity.isSymbolicLink ||
        identity.uid != uid || identity.mode.permissions != OWNER_DIRECTORY_MODE
    ) scratchFail("dedicated disk-scratch mount identity, ownership, or mode changed")
    val mounts = readFullTreeDiskMountTable()
    val matching = mounts.filter { it.mountId == identity.mountId }
    if (matching.size != 1) scratchFail("dedicated disk-scratch mount identity is absent or ambiguous")
    val mount = matching.single()
    if (
        mount.mountPoint != path || mount.root != Path.of("/") ||
        mount.fileSystemType != REQUIRED_FILESYSTEM_TYPE ||
        !REQUIRED_MOUNT_FLAGS.all(mount.options::contains)
    ) scratchFail("disk-scratch path is not the root of a safe dedicated ext4 filesystem")
    if (mounts.any { candidate ->
            candidate.mountId != mount.mountId && candidate.mountPoint.startsWith(path)
        }
    ) scratchFail("dedicated disk-scratch filesystem contains a nested mount")
    if (mounts.any { candidate ->
            candidate.mountId != mount.mountId && candidate.device == mount.device
        }
    ) scratchFail("dedicated disk-scratch filesystem has another visible mount or bind alias")
    val storeType = Files.getFileStore(path).type().lowercase(Locale.ROOT)
    if (storeType != REQUIRED_FILESYSTEM_TYPE) {
        scratchFail("disk-scratch file-store type disagrees with mountinfo")
    }
    val capacity = LinuxFilesystemSyscalls.filesystemCapacity(descriptor)
    if (capacity.readOnly || capacity.totalBytes > policy.maximumFilesystemBytes ||
        capacity.totalInodes > policy.maximumFilesystemInodes
    ) scratchFail("dedicated disk-scratch filesystem exceeds its hard policy capacity")
    if (
        requireInitialAvailability &&
        (capacity.availableBytes < policy.requiredAvailableBytes ||
            capacity.availableInodes < policy.requiredAvailableInodes)
    ) scratchFail("dedicated disk-scratch filesystem lacks required available capacity")
    if (expectedMount != null && mount != expectedMount) {
        scratchFail("dedicated disk-scratch mount record changed")
    }
    if (expectedCapacity != null &&
        (capacity.fragmentBytes != expectedCapacity.fragmentBytes ||
            capacity.totalBytes != expectedCapacity.totalBytes ||
            capacity.totalInodes != expectedCapacity.totalInodes ||
            capacity.maximumNameBytes != expectedCapacity.maximumNameBytes)
    ) scratchFail("dedicated disk-scratch filesystem capacity changed")
    return AuthorizedDiskScratch(mount, capacity)
}

private fun requireTrustedMountAncestors(path: Path) {
    var current = path.parent
    while (current != null) {
        val real = current.toRealPath(LinkOption.NOFOLLOW_LINKS)
        val attributes = Files.readAttributes(
            current,
            java.nio.file.attribute.BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        val uid = (Files.getAttribute(current, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Number).toInt()
        val mode = (Files.getAttribute(current, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Number).toInt().permissions
        if (
            real != current || !attributes.isDirectory || attributes.isSymbolicLink || uid != 0 ||
            mode and UNTRUSTED_DIRECTORY_WRITE_MODE != 0
        ) scratchFail("disk-scratch mount has an untrusted ancestor")
        current = current.parent
    }
}

private fun requireSameDirectory(path: Path, descriptor: LinuxDescriptor, label: String) {
    val current = LinuxFilesystemSyscalls.identity(descriptor.fd)
    if (!sameDirectory(current, descriptor.identity) ||
        !Files.isSameFile(path, LinuxFilesystemSyscalls.descriptorPath(descriptor))
    ) scratchFail("$label changed")
}

private fun requireExactMountMembership(mount: LinuxDescriptor, leaseName: String) {
    val names = LinuxFilesystemSyscalls.directoryEntryNames(mount, 2).sorted()
    if (names != listOf(leaseName)) {
        scratchFail("cold disk-scratch mount does not contain exactly its operation lease")
    }
}

private fun requireManagedLeaseDirectory(
    identity: LinuxFileIdentity,
    mountIdentity: LinuxFileIdentity,
    label: String,
) {
    if (
        !identity.isDirectory || identity.isSymbolicLink || identity.mountId != mountIdentity.mountId ||
        identity.key.device != mountIdentity.key.device || identity.uid != mountIdentity.uid ||
        identity.mode.permissions != OWNER_DIRECTORY_MODE
    ) scratchFail("$label identity, ownership, or mode is invalid")
}

private fun requireLeaseRecordIdentity(record: LinuxDescriptor, mountIdentity: LinuxFileIdentity) {
    val current = LinuxFilesystemSyscalls.identity(record.fd)
    if (
        !sameRegularFile(current, record.identity) || current.mountId != mountIdentity.mountId ||
        current.key.device != mountIdentity.key.device || current.uid != mountIdentity.uid ||
        current.mode.permissions != OWNER_READ_ONLY_MODE || current.linkCount != 1
    ) scratchFail("cold disk-scratch lease record identity or mode changed")
}

private fun requirePinnedLeaseRecord(
    record: LinuxDescriptor,
    expectedBytes: ByteArray,
    lease: LinuxDescriptor,
    mountIdentity: LinuxFileIdentity,
) {
    requireLeaseRecordIdentity(record, mountIdentity)
    LinuxFilesystemSyscalls.openRegularFileAtOrNull(lease.fd, LEASE_RECORD_FILE).use { named ->
        if (named == null || !sameRegularFile(LinuxFilesystemSyscalls.identity(record.fd), named.identity)) {
            scratchFail("cold disk-scratch lease record name changed")
        }
    }
    val actual = LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(record).use { readable ->
        LinuxFilesystemSyscalls.read(readable, MAXIMUM_LEASE_RECORD_BYTES) {}
    }
    if (!MessageDigest.isEqual(actual, expectedBytes)) {
        scratchFail("cold disk-scratch lease record bytes changed")
    }
    requireLeaseRecordIdentity(record, mountIdentity)
    LinuxFilesystemSyscalls.openRegularFileAtOrNull(lease.fd, LEASE_RECORD_FILE).use { named ->
        if (named == null || !sameRegularFile(LinuxFilesystemSyscalls.identity(record.fd), named.identity)) {
            scratchFail("cold disk-scratch lease record name changed after reading")
        }
    }
}

private fun requireLeaseRecordMatches(
    record: FullTreeDiskScratchLeaseRecord,
    operation: FullTreeDiskScratchOperation,
    policy: FullTreeDiskScratchPolicy,
    mountPath: Path,
    mount: FullTreeDiskMount,
    mountIdentity: LinuxFileIdentity,
    capacity: LinuxFilesystemCapacity,
    leaseIdentity: LinuxFileIdentity,
) {
    if (
        record.operationId != operation.operationId || record.requestSha256 != operation.requestSha256 ||
        record.shardId != operation.shardId || record.scopeSha256 != operation.scopeSha256 ||
        record.requiredAvailableBytes != policy.requiredAvailableBytes ||
        record.maximumFilesystemBytes != policy.maximumFilesystemBytes ||
        record.requiredAvailableInodes != policy.requiredAvailableInodes ||
        record.maximumFilesystemInodes != policy.maximumFilesystemInodes ||
        record.mountPathSha256 != sha256(mountPath.toString()) || record.mountId != mountIdentity.mountId ||
        record.mountId != mount.mountId || record.device != mountIdentity.key.device ||
        record.rootInode != mountIdentity.key.inode || record.filesystemDevice != mount.device ||
        record.filesystemType != mount.fileSystemType || record.mountFlags != mount.options.sorted() ||
        record.totalBytes != capacity.totalBytes || record.totalInodes != capacity.totalInodes ||
        record.leaseRootDevice != leaseIdentity.key.device || record.leaseRootInode != leaseIdentity.key.inode
    ) scratchFail("cold disk-scratch lease record differs from its expected operation or live filesystem")
}

private fun requireColdPopulation(
    lease: LinuxDescriptor,
    mountIdentity: LinuxFileIdentity,
    expectedRunName: String,
): Pair<FullTreeDiskScratchColdPopulation, LinuxFileIdentity?> {
    val names = LinuxFilesystemSyscalls.directoryEntryNames(
        lease,
        MAXIMUM_LEASE_ROOT_ENTRIES + 1,
    ).sorted()
    if (names == listOf(LEASE_RECORD_FILE)) {
        return FullTreeDiskScratchColdPopulation.RECORD_ONLY to null
    }
    if (names != listOf(LEASE_RECORD_FILE, expectedRunName).sorted()) {
        scratchFail("cold disk-scratch lease root contains unowned residue")
    }
    val runIdentity = LinuxFilesystemSyscalls.openDirectoryAt(lease.fd, expectedRunName).use { run ->
        val identity = LinuxFilesystemSyscalls.identity(run.fd)
        requireManagedLeaseDirectory(identity, mountIdentity, "cold disk-scratch active run root")
        identity
    }
    val after = LinuxFilesystemSyscalls.directoryEntryNames(
        lease,
        MAXIMUM_LEASE_ROOT_ENTRIES + 1,
    ).sorted()
    if (after != names) scratchFail("cold disk-scratch lease population changed during inspection")
    LinuxFilesystemSyscalls.openDirectoryAt(lease.fd, expectedRunName).use { selected ->
        if (!sameDirectory(runIdentity, LinuxFilesystemSyscalls.identity(selected.fd))) {
            scratchFail("cold disk-scratch active run root changed during inspection")
        }
    }
    return FullTreeDiskScratchColdPopulation.ACTIVE_OPERATION_RUN to runIdentity
}

private fun sameDirectory(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
    first.key == second.key && first.mountId == second.mountId &&
        first.uid == second.uid && first.gid == second.gid &&
        first.isDirectory && second.isDirectory && !first.isSymbolicLink && !second.isSymbolicLink

private fun sameRegularFile(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
    first.key == second.key && first.mountId == second.mountId &&
        first.uid == second.uid && first.gid == second.gid &&
        first.isRegularFile && second.isRegularFile &&
        !first.isDirectory && !second.isDirectory && !first.isSymbolicLink && !second.isSymbolicLink

private fun leaseRecordBytes(
    operation: FullTreeDiskScratchOperation,
    policy: FullTreeDiskScratchPolicy,
    mountPath: Path,
    mount: FullTreeDiskMount,
    mountIdentity: LinuxFileIdentity,
    capacity: LinuxFilesystemCapacity,
    leaseIdentity: LinuxFileIdentity,
): ByteArray {
    val bytes = FullTreeDiskScratchLeaseRecord.create(
        operation,
        policy,
        mountPath,
        mount,
        mountIdentity,
        capacity,
        leaseIdentity,
    ).canonicalBytes()
    if (bytes.size > MAXIMUM_LEASE_RECORD_BYTES) scratchFail("disk-scratch lease record exceeds its byte bound")
    return bytes
}

private fun readFullTreeDiskMountTable(): List<FullTreeDiskMount> {
    val text = StringBuilder()
    Files.newBufferedReader(Path.of("/proc/self/mountinfo")).use { reader ->
        var records = 0
        while (true) {
            val line = reader.readLine() ?: break
            records = Math.addExact(records, 1)
            if (records > MAXIMUM_MOUNTINFO_RECORDS || line.length > MAXIMUM_MOUNTINFO_LINE_CHARS) {
                scratchFail("mountinfo exceeds the disk-scratch parser bound")
            }
            if (text.length > MAXIMUM_MOUNTINFO_CHARS - line.length - 1) {
                scratchFail("mountinfo exceeds the disk-scratch aggregate text bound")
            }
            text.append(line).append('\n')
        }
    }
    return parseFullTreeDiskMountTable(text.toString())
}

internal fun parseFullTreeDiskMountTable(text: String): List<FullTreeDiskMount> {
    if (text.length > MAXIMUM_MOUNTINFO_CHARS || '\u0000' in text) {
        scratchFail("mountinfo input exceeds its parser bound")
    }
    val mounts = ArrayList<FullTreeDiskMount>()
    val identifiers = HashSet<Long>()
    text.lineSequence().filter(String::isNotEmpty).forEach { line ->
        if (mounts.size >= MAXIMUM_MOUNTINFO_RECORDS || line.length > MAXIMUM_MOUNTINFO_LINE_CHARS) {
            scratchFail("mountinfo input exceeds its record bound")
        }
        val separator = line.indexOf(" - ")
        if (separator <= 0) scratchFail("mountinfo contains a malformed record")
        val left = line.substring(0, separator).split(' ')
        val right = line.substring(separator + 3).split(' ')
        if (left.size < 6 || right.size < 3) scratchFail("mountinfo contains an incomplete record")
        val mountId = left[0].toLongOrNull()?.takeIf { it > 0L }
            ?: scratchFail("mountinfo mount ID is invalid")
        val parentMountId = left[1].toLongOrNull()?.takeIf { it > 0L }
            ?: scratchFail("mountinfo parent mount ID is invalid")
        if (!identifiers.add(mountId) || !left[2].matches(FILESYSTEM_DEVICE)) {
            scratchFail("mountinfo contains a duplicate identity or invalid device")
        }
        val root = decodeMountInfoPath(left[3])
        val mountPoint = decodeMountInfoPath(left[4])
        val options = left[5].split(',').filter(String::isNotEmpty)
        if (options.isEmpty() || options.size != options.distinct().size || options.any { !it.matches(MOUNT_OPTION) }) {
            scratchFail("mountinfo contains invalid mount options")
        }
        val fileSystemType = right[0]
        if (!fileSystemType.matches(FILESYSTEM_TYPE)) scratchFail("mountinfo filesystem type is invalid")
        mounts += FullTreeDiskMount(
            mountId,
            parentMountId,
            left[2],
            root,
            mountPoint,
            options.sorted(),
            fileSystemType,
        )
    }
    return mounts
}

private fun decodeMountInfoPath(encoded: String): Path {
    val decoded = StringBuilder(encoded.length)
    var index = 0
    while (index < encoded.length) {
        val character = encoded[index]
        if (character != '\\') {
            decoded.append(character)
            index += 1
            continue
        }
        if (index + 3 >= encoded.length) scratchFail("mountinfo contains a truncated escape")
        val escape = encoded.substring(index + 1, index + 4)
        decoded.append(
            when (escape) {
                "040" -> ' '
                "011" -> '\t'
                "012" -> '\n'
                "134" -> '\\'
                else -> scratchFail("mountinfo contains an unsupported escape")
            },
        )
        index += 4
    }
    val value = runCatching { Path.of(decoded.toString()).normalize() }
        .getOrElse { failure -> throw FullTreeDiskScratchException("mountinfo path is invalid", failure) }
    if (!value.isAbsolute || value.toString() != decoded.toString()) {
        scratchFail("mountinfo path is not absolute and normalized")
    }
    return value
}

private inline fun <T> translateScratchFailures(action: () -> T): T = try {
    action()
} catch (failure: FullTreeDiskScratchException) {
    throw failure
} catch (failure: Throwable) {
    throw FullTreeDiskScratchException("disk-scratch authority failed: ${failure.message}", failure)
}

private fun JsonObject.requireExactRecordKeys() {
    if (keys != DISK_SCRATCH_LEASE_RECORD_FIELDS) {
        scratchFail("disk-scratch lease record has missing or unknown fields")
    }
}

private fun JsonObject.recordString(name: String): String {
    val primitive = this[name] as? JsonPrimitive
        ?: scratchFail("disk-scratch lease record field $name must be a string")
    if (!primitive.isString) scratchFail("disk-scratch lease record field $name must be a string")
    return primitive.content
}

private fun JsonObject.recordLong(name: String): Long {
    val primitive = this[name] as? JsonPrimitive
        ?: scratchFail("disk-scratch lease record field $name must be an integer")
    if (primitive.isString) scratchFail("disk-scratch lease record field $name must be an integer")
    return primitive.content.toLongOrNull()
        ?: scratchFail("disk-scratch lease record field $name must be an integer")
}

private fun JsonObject.recordInt(name: String): Int {
    val value = recordLong(name)
    if (value !in Int.MIN_VALUE..Int.MAX_VALUE) {
        scratchFail("disk-scratch lease record field $name is outside the integer range")
    }
    return value.toInt()
}

private fun JsonObject.recordStringArray(name: String): List<String> {
    val array = this[name] as? JsonArray
        ?: scratchFail("disk-scratch lease record field $name must be an array")
    return array.map { value ->
        val primitive = value as? JsonPrimitive
            ?: scratchFail("disk-scratch lease record field $name must contain strings")
        if (!primitive.isString) scratchFail("disk-scratch lease record field $name must contain strings")
        primitive.content
    }
}

private fun sha256(bytes: ByteArray): String = OracleArtifacts.sha256(bytes)

private fun sha256(value: String): String = OracleArtifacts.sha256(value.toByteArray(Charsets.UTF_8))

private fun scratchFail(message: String): Nothing = throw FullTreeDiskScratchException(message)

private const val DISK_SCRATCH_EVIDENCE_SCHEMA_VERSION = 1
private const val DISK_SCRATCH_LEASE_SCHEMA_VERSION = 1
internal const val FULL_TREE_DISK_SCRATCH_PROVIDER = "dedicated-ext4-filesystem-v1"
private const val REQUIRED_FILESYSTEM_TYPE = "ext4"
private const val OWNER_DIRECTORY_MODE = 0x1c0 // 0700
private const val OWNER_READ_WRITE_MODE = 0x180 // 0600
private const val OWNER_READ_ONLY_MODE = 0x100 // 0400
private const val UNTRUSTED_DIRECTORY_WRITE_MODE = 0x12 // 0022
private const val MINIMUM_LEASE_INODES = 4L
private const val MAXIMUM_LEASE_ROOT_ENTRIES = 2
private const val MAXIMUM_LEASE_RECORD_BYTES = 64 * 1024
private const val MAXIMUM_MOUNTINFO_RECORDS = 100_000
private const val MAXIMUM_MOUNTINFO_LINE_CHARS = 64 * 1024
private const val MAXIMUM_MOUNTINFO_CHARS = 16 * 1024 * 1024
private const val LEASE_RECORD_FILE = "lease.json"
private val REQUIRED_MOUNT_FLAGS = listOf("rw", "nodev", "noexec", "nosuid", "noatime")
private val SHA256 = Regex("[0-9a-f]{64}")
private val ZERO_SHA256 = "0".repeat(64)
private val SHARD_IDENTIFIER = Regex("[a-z0-9]+(?:-[a-z0-9]+)*")
private val FILESYSTEM_DEVICE = Regex("[0-9]+:[0-9]+")
private val FILESYSTEM_TYPE = Regex("[A-Za-z0-9._+-]+")
private val MOUNT_OPTION = Regex("[A-Za-z0-9._=+-]+")
private val DISK_SCRATCH_RECORD_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_LEASE_RECORD_BYTES,
    maximumCanonicalBytes = MAXIMUM_LEASE_RECORD_BYTES,
    maximumDepth = 4,
    maximumNodes = 64,
    maximumStringBytes = 4096,
    maximumTotalStringBytes = 32 * 1024,
    maximumNumberCharacters = 32,
)
private val DISK_SCRATCH_LEASE_RECORD_FIELDS = setOf(
    "device",
    "filesystemDevice",
    "filesystemType",
    "leaseRootDevice",
    "leaseRootInode",
    "maximumFilesystemBytes",
    "maximumFilesystemInodes",
    "mountFlags",
    "mountId",
    "mountPathSha256",
    "operationId",
    "provider",
    "recordSha256",
    "requestSha256",
    "requiredAvailableBytes",
    "requiredAvailableInodes",
    "rootInode",
    "schemaVersion",
    "scopeSha256",
    "shardId",
    "totalBytes",
    "totalInodes",
)
