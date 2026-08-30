package decompengine.oracle.fulltree

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemCapacity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
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

internal object FullTreeDiskScratchAuthority {
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

private fun sameDirectory(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
    first.key == second.key && first.mountId == second.mountId &&
        first.uid == second.uid && first.gid == second.gid &&
        first.isDirectory && second.isDirectory && !first.isSymbolicLink && !second.isSymbolicLink

private fun leaseRecordBytes(
    operation: FullTreeDiskScratchOperation,
    policy: FullTreeDiskScratchPolicy,
    mountPath: Path,
    mount: FullTreeDiskMount,
    mountIdentity: LinuxFileIdentity,
    capacity: LinuxFilesystemCapacity,
    leaseIdentity: LinuxFileIdentity,
): ByteArray {
    val withoutHash = JsonObject(
        mapOf(
            "device" to JsonPrimitive(mountIdentity.key.device),
            "filesystemDevice" to JsonPrimitive(mount.device),
            "filesystemType" to JsonPrimitive(mount.fileSystemType),
            "leaseRootDevice" to JsonPrimitive(leaseIdentity.key.device),
            "leaseRootInode" to JsonPrimitive(leaseIdentity.key.inode),
            "maximumFilesystemBytes" to JsonPrimitive(policy.maximumFilesystemBytes),
            "maximumFilesystemInodes" to JsonPrimitive(policy.maximumFilesystemInodes),
            "mountFlags" to JsonArray(mount.options.sorted().map(::JsonPrimitive)),
            "mountId" to JsonPrimitive(mountIdentity.mountId),
            "mountPathSha256" to JsonPrimitive(sha256(mountPath.toString())),
            "operationId" to JsonPrimitive(operation.operationId),
            "provider" to JsonPrimitive(FULL_TREE_DISK_SCRATCH_PROVIDER),
            "requestSha256" to JsonPrimitive(operation.requestSha256),
            "requiredAvailableBytes" to JsonPrimitive(policy.requiredAvailableBytes),
            "requiredAvailableInodes" to JsonPrimitive(policy.requiredAvailableInodes),
            "rootInode" to JsonPrimitive(mountIdentity.key.inode),
            "schemaVersion" to JsonPrimitive(DISK_SCRATCH_LEASE_SCHEMA_VERSION),
            "scopeSha256" to JsonPrimitive(operation.scopeSha256),
            "shardId" to JsonPrimitive(operation.shardId),
            "totalBytes" to JsonPrimitive(capacity.totalBytes),
            "totalInodes" to JsonPrimitive(capacity.totalInodes),
        ),
    )
    val recordSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(withoutHash))
    val bytes = OracleJson.canonicalBytes(JsonObject(withoutHash + ("recordSha256" to JsonPrimitive(recordSha256))))
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
private val REQUIRED_MOUNT_FLAGS = listOf("rw", "nodev", "noexec", "nosuid")
private val SHA256 = Regex("[0-9a-f]{64}")
private val ZERO_SHA256 = "0".repeat(64)
private val SHARD_IDENTIFIER = Regex("[a-z0-9]+(?:-[a-z0-9]+)*")
private val FILESYSTEM_DEVICE = Regex("[0-9]+:[0-9]+")
private val FILESYSTEM_TYPE = Regex("[A-Za-z0-9._+-]+")
private val MOUNT_OPTION = Regex("[A-Za-z0-9._=+-]+")
