package decompengine.project

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.security.MessageDigest

/**
 * Proof that a reconstruction workspace owns the canonical output directory.
 * Instances can only be minted by the workspace open path.
 */
internal sealed class ReconstructionPublicationLock private constructor(
    private val root: Path,
    private val input: Path,
    private val inputSha256: String,
    private val channel: FileChannel,
    private val lock: FileLock,
    private val rootDescriptor: LinuxDescriptor,
    private val lockDescriptor: LinuxDescriptor,
    private val inputParentDescriptor: LinuxDescriptor,
    private val inputDescriptor: LinuxDescriptor,
) {
    @Volatile
    private var closed = false
    private var authorizedStageRoot: Path? = null
    private var authorizedStageInputSha256: String? = null

    internal val canonicalRoot: Path get() = synchronized(this) { validate(); root }
    internal val admittedInputSha256: String get() = inputSha256

    /** Revalidate the capability immediately before any output publication or movement. */
    @Synchronized
    fun validate() {
        check(!closed) { "reconstruction output ownership is closed" }
        check(channel.isOpen && lock.isValid) { "reconstruction output ownership lock is no longer valid" }
        check(root.toRealPath() == root) { "reconstruction output root changed its canonical path" }
        check(input.toRealPath() == input) { "reconstruction input changed its canonical path" }
        check(sameInode(LinuxFilesystemSyscalls.identity(rootDescriptor.fd), rootDescriptor.identity)) {
            "reconstruction output root descriptor identity changed"
        }
        val currentLock = LinuxFilesystemSyscalls.identity(lockDescriptor.fd)
        check(sameLockObject(currentLock, lockDescriptor.identity) && (currentLock.mode and 0xfff) == 0x180 &&
            currentLock.uid == rootDescriptor.identity.uid) {
            "reconstruction output lock descriptor identity changed"
        }
        check(sameObject(LinuxFilesystemSyscalls.identity(inputDescriptor.fd), inputDescriptor.identity)) {
            "reconstruction input descriptor identity changed"
        }
        verifyNamedRoot()
        verifyNamedLock()
        verifyNamedInput()
    }

    /** The pinned directory used by publication; callers must retain the workspace monitor. */
    @Synchronized
    internal fun rootDirectoryDescriptor(): LinuxDescriptor {
        validate()
        return rootDescriptor
    }

    /**
     * Borrow the already-held workspace lease for publication. This does not acquire another
     * operating-system lock; it verifies that the caller names this exact root and input
     * commitment, and that the input bytes still have that commitment.
     */
    @Synchronized
    fun borrow(requestedRoot: Path, requestedInputSha256: String): ReconstructionPublicationLock {
        validate()
        require(requestedRoot.toAbsolutePath().normalize() == root) {
            "publication root must use the workspace's canonical path"
        }
        require(requestedInputSha256 == inputSha256) {
            "publication input identity does not match the workspace"
        }
        val before = LinuxFilesystemSyscalls.fileState(inputDescriptor)
        val observed = sha256Descriptor(inputDescriptor)
        val after = LinuxFilesystemSyscalls.fileState(inputDescriptor)
        check(sameContentState(before, after) && observed == inputSha256) {
            "reconstruction input bytes changed during the workspace lease"
        }
        return this
    }

    /** Runs only the publisher's synchronous builder while its private stage is authorized. */
    @Synchronized
    internal fun <T> withPublicationStage(stageRoot: Path, requestedInputSha256: String, action: () -> T): T {
        borrow(root, requestedInputSha256)
        check(authorizedStageRoot == null) { "a publication stage is already active" }
        val normalized = stageRoot.toAbsolutePath().normalize()
        require(normalized.parent == root && normalized.fileName.toString().matches(
            Regex("\\.reconstruction-stage-[0-9a-f-]{36}"),
        )) { "publication stage must be a direct private child of the workspace" }
        require(stageRoot.toRealPath() == normalized) { "publication stage path changed before generation" }
        authorizedStageRoot = normalized
        authorizedStageInputSha256 = requestedInputSha256
        try {
            return action()
        } finally {
            authorizedStageRoot = null
            authorizedStageInputSha256 = null
        }
    }

    /** Rejects a valid lease reused for a different model, output root, or unstaged destination. */
    @Synchronized
    internal fun requireAuthorizedGenerationTarget(projectDir: Path, modelInputSha256: String) {
        validate()
        val stage = requireNotNull(authorizedStageRoot) {
            "transactional generation requires an active publication stage"
        }
        require(modelInputSha256 == inputSha256 && modelInputSha256 == authorizedStageInputSha256) {
            "generation model input does not match the admitted publication input"
        }
        require(projectDir.toAbsolutePath().normalize() == stage.resolve("source-tree")) {
            "transactional generation target must be inside its active publication stage"
        }
    }

    @Synchronized
    internal fun requireInvocation(outputDirectory: Path, inputPath: Path, requestedInputSha256: String) {
        borrow(root, requestedInputSha256)
        require(outputDirectory.toAbsolutePath().normalize() == root) {
            "archival output directory must be the workspace's canonical root"
        }
        require(inputPath.toRealPath() == input) {
            "archival input path must identify the workspace's admitted input"
        }
    }

    @Synchronized
    fun closeOwnership() {
        closed = true
        inputDescriptor.close()
        inputParentDescriptor.close()
        lockDescriptor.close()
        rootDescriptor.close()
    }

    private fun verifyNamedRoot() {
        LinuxFilesystemSyscalls.openRoot(root).use { named ->
            check(sameInode(named.identity, rootDescriptor.identity)) {
                "reconstruction output root name no longer identifies the leased directory"
            }
        }
    }

    private fun verifyNamedLock() {
        LinuxFilesystemSyscalls.openRegularFileAtOrNull(rootDescriptor.fd, LOCK_FILE)?.use { named ->
            check(sameLockObject(named.identity, lockDescriptor.identity) && (named.identity.mode and 0xfff) == 0x180 &&
                named.identity.uid == rootDescriptor.identity.uid) {
                "reconstruction output lock name no longer identifies the leased lock"
            }
        } ?: error("reconstruction output lock name disappeared")
    }

    private fun verifyNamedInput() {
        LinuxFilesystemSyscalls.openRegularFileAtOrNull(inputParentDescriptor.fd, input.fileName.toString())?.use { named ->
            check(sameObject(named.identity, inputDescriptor.identity)) {
                "reconstruction input name no longer identifies the admitted file"
            }
        } ?: error("reconstruction input name disappeared")
    }

    private fun sha256Descriptor(descriptor: LinuxDescriptor): String {
        // Preserve atime when the host permits O_NOATIME, while still supporting read-only host
        // bind mounts owned by another UID through the syscall helper's EPERM-only fallback.
        val before = LinuxFilesystemSyscalls.fileState(descriptor)
        val digest = MessageDigest.getInstance("SHA-256")
        LinuxFilesystemSyscalls.openReadableWithoutAtimeOrFallbackFrom(descriptor).use { readable ->
            require(readable.identity == descriptor.identity) { "reconstruction input reader changed identity" }
            val buffer = ByteArray(64 * 1024)
            var total = 0L
            while (true) {
                val bytes = LinuxFilesystemSyscalls.readWithoutAtime(readable, buffer.size)
                if (bytes.isEmpty()) break
                total = Math.addExact(total, bytes.size.toLong())
                require(total <= before.size) { "reconstruction input grew while hashing" }
                digest.update(bytes)
            }
            require(total == before.size) { "reconstruction input shrank while hashing" }
        }
        val after = LinuxFilesystemSyscalls.fileState(descriptor)
        check(sameContentState(before, after)) { "reconstruction input changed while hashing" }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun sameContentState(before: decompengine.acp.LinuxFileState, after: decompengine.acp.LinuxFileState): Boolean =
        before.identity == after.identity && before.size == after.size &&
            before.modificationTimeSeconds == after.modificationTimeSeconds &&
            before.modificationTimeNanoseconds == after.modificationTimeNanoseconds &&
            before.changeTimeSeconds == after.changeTimeSeconds &&
            before.changeTimeNanoseconds == after.changeTimeNanoseconds

    companion object {
        /** Called only by ReconstructionOutputWorkspace.openInternal after acquiring its lock. */
        internal fun opened(
            root: Path,
            input: Path,
            inputSha256: String,
            channel: FileChannel,
            lock: FileLock,
            rootDescriptor: LinuxDescriptor,
            lockDescriptor: LinuxDescriptor,
            inputParentDescriptor: LinuxDescriptor,
            inputDescriptor: LinuxDescriptor,
        ): ReconstructionPublicationLock {
            val canonicalRoot = root.toRealPath()
            val canonicalInput = input.toRealPath()
            return Opened(canonicalRoot, canonicalInput, inputSha256, channel, lock,
                rootDescriptor, lockDescriptor, inputParentDescriptor, inputDescriptor)
        }

        private fun sameObject(left: decompengine.acp.LinuxFileIdentity, right: decompengine.acp.LinuxFileIdentity): Boolean =
            left.key == right.key && left.mountId == right.mountId && left.mode == right.mode &&
                left.uid == right.uid && left.gid == right.gid && left.linkCount == right.linkCount &&
                left.isRegularFile == right.isRegularFile && left.isDirectory == right.isDirectory &&
                left.isSymbolicLink == right.isSymbolicLink

        // A legacy lock's mode is intentionally normalized while preserving its already-open
        // inode. Mode is checked against the required private value by validate(), not against
        // the pre-migration O_PATH descriptor snapshot.
        private fun sameLockObject(left: decompengine.acp.LinuxFileIdentity, right: decompengine.acp.LinuxFileIdentity): Boolean =
            left.key == right.key && left.mountId == right.mountId && left.uid == right.uid &&
                left.gid == right.gid && left.linkCount == right.linkCount && left.isRegularFile &&
                right.isRegularFile && !left.isSymbolicLink && !right.isSymbolicLink

        private fun sameInode(left: decompengine.acp.LinuxFileIdentity, right: decompengine.acp.LinuxFileIdentity): Boolean =
            left.key == right.key && left.mountId == right.mountId && left.isRegularFile == right.isRegularFile &&
                left.isDirectory == right.isDirectory && left.isSymbolicLink == right.isSymbolicLink

        private class Opened(
            root: Path,
            input: Path,
            inputSha256: String,
            channel: FileChannel,
            lock: FileLock,
            rootDescriptor: LinuxDescriptor,
            lockDescriptor: LinuxDescriptor,
            inputParentDescriptor: LinuxDescriptor,
            inputDescriptor: LinuxDescriptor,
        ) : ReconstructionPublicationLock(root, input, inputSha256, channel, lock,
            rootDescriptor, lockDescriptor, inputParentDescriptor, inputDescriptor)

        private const val LOCK_FILE = ".reconstruction.lock"
    }
}
