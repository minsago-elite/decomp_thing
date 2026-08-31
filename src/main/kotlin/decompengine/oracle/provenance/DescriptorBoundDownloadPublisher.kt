package decompengine.oracle.provenance

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxSyscallException
import decompengine.acp.permissions
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.WritableByteChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest

internal data class AuthenticatedDownloadedArtifact(
    val path: Path,
    val bytes: Long,
    val sha256: String,
)

internal class AuthenticatedReleaseDirectory(
    val path: Path,
    val descriptor: LinuxDescriptor,
    val identity: LinuxFileIdentity,
) : AutoCloseable {
    override fun close() = descriptor.close()
}

internal enum class ReleaseDirectoryPoint {
    BEFORE_CHILD_CREATE,
}

internal fun interface ReleaseDirectoryFaultInjector {
    fun hit(point: ReleaseDirectoryPoint)
}

internal enum class DownloadPublicationPoint {
    AFTER_STAGE_SYNC,
    BEFORE_LINK,
    AFTER_LINK,
    AFTER_DIRECTORY_SYNC,
    BEFORE_ACCEPTED_FILE_SYNC,
    AFTER_ACCEPTED_FILE_SYNC,
    BEFORE_ACCEPTED_DIRECTORY_SYNC,
    AFTER_ACCEPTED_DIRECTORY_SYNC,
    BEFORE_TERMINAL_ACCEPTANCE,
}

internal fun interface DownloadPublicationFaultInjector {
    fun hit(point: DownloadPublicationPoint)
}

/**
 * Streams one large input into an unnamed inode, makes it read-only, and installs it without replacement.
 *
 * The authority is intentionally Linux-only: Java NIO has no descriptor-relative `O_TMPFILE` or
 * no-replace hard-link primitive. Unsupported kernels/filesystems fail closed. A target that wins
 * a concurrent link race is accepted only after descriptor-pinned length and digest verification.
 */
internal object DescriptorBoundDownloadPublisher {
    fun materialize(
        targetPath: Path,
        expectedBytes: Long,
        expectedSha256: String,
        verifyInputs: () -> Unit,
        faultInjector: DownloadPublicationFaultInjector? = null,
        download: (WritableByteChannel) -> HttpsDownloadReceipt,
    ): AuthenticatedDownloadedArtifact {
        val target = targetPath.toAbsolutePath().normalize()
        val parent = target.parent ?: provenanceFail("release artifact path has no parent")
        openAuthenticatedReleaseDirectory(parent, "release artifact parent").use { authenticatedParent ->
            return materialize(
                authenticatedParent,
                target,
                expectedBytes,
                expectedSha256,
                verifyInputs,
                faultInjector,
                download,
            )
        }
    }

    fun materialize(
        authenticatedParent: AuthenticatedReleaseDirectory,
        targetPath: Path,
        expectedBytes: Long,
        expectedSha256: String,
        verifyInputs: () -> Unit,
        faultInjector: DownloadPublicationFaultInjector? = null,
        download: (WritableByteChannel) -> HttpsDownloadReceipt,
    ): AuthenticatedDownloadedArtifact {
        require(expectedBytes > 0L) { "expected artifact bytes must be positive" }
        require(expectedSha256.matches(SHA256)) { "expected artifact SHA-256 is invalid" }
        val target = targetPath.toAbsolutePath().normalize()
        val parent = authenticatedParent.path
        if (target.parent != parent) provenanceFail("release artifact path escapes its authenticated parent")
        val name = target.fileName?.toString() ?: provenanceFail("release artifact path has no file name")
        requireDescriptorName(name)
        val parentIdentity = authenticatedParent.identity
        val parentDescriptor = authenticatedParent.descriptor
        requirePinnedParent(parent, parentDescriptor, parentIdentity)
        verifiedNamedArtifactOrNull(
            parentDescriptor,
            name,
            target,
            expectedBytes,
            expectedSha256,
            synchronizeBeforeAcceptance = true,
            faultInjector = faultInjector,
        )?.let {
            synchronizeAcceptedDirectory(parent, parentDescriptor, parentIdentity, faultInjector)
            requireTerminalAcceptance(parent, parentDescriptor, parentIdentity, name, it.identity, faultInjector)
            return it.artifact
        }

        LinuxFilesystemSyscalls.createTemporaryAt(parentDescriptor.fd).use { stage ->
            val receipt = FileChannel.open(
                LinuxFilesystemSyscalls.stableDescriptorPath(stage.fd),
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING,
            ).use { channel ->
                val downloaded = download(channel)
                channel.force(true)
                downloaded
            }
            if (receipt.bytes != expectedBytes || receipt.sha256 != expectedSha256) {
                provenanceFail("download receipt differs from its release lock")
            }
            val staged = digestDescriptor(
                stage,
                expectedBytes,
                expectedSha256,
                "download staging inode",
                requireReadOnly = false,
            )
            LinuxFilesystemSyscalls.chmod(stage, OWNER_READ_ONLY_MODE)
            LinuxFilesystemSyscalls.synchronize(stage)
            val stageIdentity = LinuxFilesystemSyscalls.identity(stage.fd)
            if (
                !sameRegularFile(staged.identity, stageIdentity) || stageIdentity.linkCount != 0 ||
                stageIdentity.mode.permissions != OWNER_READ_ONLY_MODE ||
                staged.identity.uid != stageIdentity.uid || staged.identity.gid != stageIdentity.gid
            ) {
                provenanceFail("download staging inode identity or permissions changed")
            }
            faultInjector?.hit(DownloadPublicationPoint.AFTER_STAGE_SYNC)
            verifyInputs()
            requirePinnedParent(parent, parentDescriptor, parentIdentity)
            faultInjector?.hit(DownloadPublicationPoint.BEFORE_LINK)
            requirePinnedParent(parent, parentDescriptor, parentIdentity)

            try {
                LinuxFilesystemSyscalls.linkTemporaryAt(stage, parentDescriptor.fd, name)
            } catch (failure: LinuxSyscallException) {
                if (failure.errno != LinuxFilesystemSyscalls.EEXIST) throw failure
                val winner = verifiedNamedArtifactOrNull(
                    parentDescriptor,
                    name,
                    target,
                    expectedBytes,
                    expectedSha256,
                    synchronizeBeforeAcceptance = true,
                    faultInjector = faultInjector,
                ) ?: provenanceFail("release artifact race winner disappeared")
                synchronizeAcceptedDirectory(parent, parentDescriptor, parentIdentity, faultInjector)
                requireTerminalAcceptance(
                    parent,
                    parentDescriptor,
                    parentIdentity,
                    name,
                    winner.identity,
                    faultInjector,
                )
                return winner.artifact
            }

            faultInjector?.hit(DownloadPublicationPoint.AFTER_LINK)
            requirePinnedParent(parent, parentDescriptor, parentIdentity)
            LinuxFilesystemSyscalls.synchronize(parentDescriptor)
            requirePinnedParent(parent, parentDescriptor, parentIdentity)
            faultInjector?.hit(DownloadPublicationPoint.AFTER_DIRECTORY_SYNC)
            requirePinnedParent(parent, parentDescriptor, parentIdentity)
            val published = verifiedNamedArtifactOrNull(
                parentDescriptor,
                name,
                target,
                expectedBytes,
                expectedSha256,
                synchronizeBeforeAcceptance = false,
                faultInjector = faultInjector,
            ) ?: provenanceFail("published release artifact disappeared")
            requirePinnedParent(parent, parentDescriptor, parentIdentity)
            if (!samePublishedStage(stageIdentity, published.identity)) {
                provenanceFail("published release artifact differs from its staged inode")
            }
            requireTerminalAcceptance(
                parent,
                parentDescriptor,
                parentIdentity,
                name,
                published.identity,
                faultInjector,
            )
            return published.artifact
        }
    }

    fun verifyExisting(
        targetPath: Path,
        expectedBytes: Long,
        expectedSha256: String,
    ): AuthenticatedDownloadedArtifact {
        val target = targetPath.toAbsolutePath().normalize()
        val parent = target.parent ?: provenanceFail("release artifact path has no parent")
        val name = target.fileName?.toString() ?: provenanceFail("release artifact path has no file name")
        openAuthenticatedReleaseDirectory(parent, "release artifact parent").use { authenticatedParent ->
            val parentIdentity = authenticatedParent.identity
            val descriptor = authenticatedParent.descriptor
            requirePinnedParent(parent, descriptor, parentIdentity)
            val verified = verifiedNamedArtifactOrNull(
                descriptor,
                name,
                target,
                expectedBytes,
                expectedSha256,
                synchronizeBeforeAcceptance = true,
                faultInjector = null,
            )
                ?: provenanceFail("release artifact is missing: $target")
            synchronizeAcceptedDirectory(parent, descriptor, parentIdentity, null)
            requireTerminalAcceptance(parent, descriptor, parentIdentity, name, verified.identity, null)
            return verified.artifact
        }
    }

    private fun verifiedNamedArtifactOrNull(
        parent: LinuxDescriptor,
        name: String,
        target: Path,
        expectedBytes: Long,
        expectedSha256: String,
        synchronizeBeforeAcceptance: Boolean,
        faultInjector: DownloadPublicationFaultInjector?,
    ): VerifiedNamedArtifact? {
        val selected = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name) ?: return null
        selected.use {
            val verified = digestDescriptor(
                selected,
                expectedBytes,
                expectedSha256,
                "release artifact",
                requireReadOnly = true,
            )
            if (synchronizeBeforeAcceptance) {
                LinuxFilesystemSyscalls.openReadableFrom(selected).use { readable ->
                    val readableIdentity = LinuxFilesystemSyscalls.identity(readable.fd)
                    if (!sameAuthenticatedFile(verified.identity, readableIdentity)) {
                        provenanceFail("release artifact identity changed before synchronization")
                    }
                    faultInjector?.hit(DownloadPublicationPoint.BEFORE_ACCEPTED_FILE_SYNC)
                    if (!sameAuthenticatedFile(verified.identity, LinuxFilesystemSyscalls.identity(readable.fd))) {
                        provenanceFail("release artifact identity changed before synchronization")
                    }
                    LinuxFilesystemSyscalls.synchronize(readable)
                    faultInjector?.hit(DownloadPublicationPoint.AFTER_ACCEPTED_FILE_SYNC)
                    if (!sameAuthenticatedFile(verified.identity, LinuxFilesystemSyscalls.identity(readable.fd))) {
                        provenanceFail("release artifact identity changed while it was synchronized")
                    }
                }
            }
            val named = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)
                ?: provenanceFail("release artifact disappeared after verification")
            val namedIdentity = named.use {
                LinuxFilesystemSyscalls.identity(named.fd).also { identity ->
                    if (!sameAuthenticatedFile(verified.identity, identity)) {
                        provenanceFail("release artifact name changed after verification")
                    }
                }
            }
            return VerifiedNamedArtifact(
                AuthenticatedDownloadedArtifact(target, expectedBytes, expectedSha256),
                namedIdentity,
            )
        }
    }

    private fun synchronizeAcceptedDirectory(
        parentPath: Path,
        parent: LinuxDescriptor,
        expectedParent: LinuxFileIdentity,
        faultInjector: DownloadPublicationFaultInjector?,
    ) {
        requirePinnedParent(parentPath, parent, expectedParent)
        faultInjector?.hit(DownloadPublicationPoint.BEFORE_ACCEPTED_DIRECTORY_SYNC)
        requirePinnedParent(parentPath, parent, expectedParent)
        LinuxFilesystemSyscalls.synchronize(parent)
        requirePinnedParent(parentPath, parent, expectedParent)
        faultInjector?.hit(DownloadPublicationPoint.AFTER_ACCEPTED_DIRECTORY_SYNC)
        requirePinnedParent(parentPath, parent, expectedParent)
    }

    private fun requireTerminalAcceptance(
        parentPath: Path,
        parent: LinuxDescriptor,
        expectedParent: LinuxFileIdentity,
        name: String,
        expectedFile: LinuxFileIdentity,
        faultInjector: DownloadPublicationFaultInjector?,
    ) {
        faultInjector?.hit(DownloadPublicationPoint.BEFORE_TERMINAL_ACCEPTANCE)
        requirePinnedParent(parentPath, parent, expectedParent)
        LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)?.use { terminal ->
            if (!sameAuthenticatedFile(expectedFile, LinuxFilesystemSyscalls.identity(terminal.fd))) {
                provenanceFail("release artifact identity changed before terminal acceptance")
            }
        } ?: provenanceFail("release artifact disappeared before terminal acceptance")
        requirePinnedParent(parentPath, parent, expectedParent)
    }

    private fun samePublishedStage(stage: LinuxFileIdentity, published: LinuxFileIdentity): Boolean =
        sameRegularFile(stage, published) && stage.mode == published.mode &&
            stage.uid == published.uid && stage.gid == published.gid &&
            stage.linkCount == 0 && published.linkCount == 1

    private data class VerifiedNamedArtifact(
        val artifact: AuthenticatedDownloadedArtifact,
        val identity: LinuxFileIdentity,
    )

    private fun digestDescriptor(
        descriptor: LinuxDescriptor,
        expectedBytes: Long,
        expectedSha256: String,
        label: String,
        requireReadOnly: Boolean,
    ): DescriptorDigest {
        val before = LinuxFilesystemSyscalls.identity(descriptor.fd)
        if (!before.isRegularFile || before.isDirectory || before.isSymbolicLink) {
            provenanceFail("$label is not an authenticated regular file")
        }
        val forbiddenWriteMode = if (requireReadOnly) ANY_WRITE_MODE else UNTRUSTED_WRITE_MODE
        if (before.mode.permissions and forbiddenWriteMode != 0) {
            if (requireReadOnly) {
                provenanceFail("$label must have no write permission bits")
            }
            provenanceFail("$label is group-writable or other-writable")
        }
        val digest = MessageDigest.getInstance("SHA-256")
        val observed = FileChannel.open(
            LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd),
            StandardOpenOption.READ,
        ).use { channel ->
            if (channel.size() != expectedBytes) {
                provenanceFail("$label byte length mismatch: expected $expectedBytes, observed ${channel.size()}")
            }
            val buffer = ByteBuffer.allocate(BUFFER_BYTES)
            var count = 0L
            while (count < expectedBytes) {
                buffer.clear()
                buffer.limit(minOf(buffer.capacity().toLong(), expectedBytes - count).toInt())
                val read = channel.read(buffer)
                if (read <= 0) provenanceFail("$label ended while hashing")
                digest.update(buffer.array(), 0, read)
                count = Math.addExact(count, read.toLong())
            }
            buffer.clear()
            buffer.limit(1)
            if (channel.read(buffer) >= 0 || channel.size() != expectedBytes) {
                provenanceFail("$label changed size while hashing")
            }
            count
        }
        val after = LinuxFilesystemSyscalls.identity(descriptor.fd)
        if (!sameAuthenticatedFile(before, after)) {
            provenanceFail("$label identity or permissions changed while hashing")
        }
        val actualSha256 = digest.digest().hex()
        if (observed != expectedBytes || actualSha256 != expectedSha256) {
            provenanceFail("$label SHA-256 differs from its release lock")
        }
        return DescriptorDigest(after, observed, actualSha256)
    }

    private fun requirePinnedParent(path: Path, descriptor: LinuxDescriptor, expected: LinuxFileIdentity) {
        requireDirectoryBinding(path, descriptor, expected, "release artifact parent")
    }

    private fun requireDescriptorName(name: String) {
        if (name.isEmpty() || name == "." || name == ".." || '/' in name || '\u0000' in name) {
            provenanceFail("release artifact file name is invalid")
        }
    }

    private fun sameRegularFile(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
        left.key == right.key && left.mountId == right.mountId &&
            left.isRegularFile && right.isRegularFile &&
            !left.isDirectory && !right.isDirectory &&
            !left.isSymbolicLink && !right.isSymbolicLink

    private fun sameAuthenticatedFile(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
        sameRegularFile(left, right) && left.mode == right.mode && left.uid == right.uid &&
            left.gid == right.gid && left.linkCount == right.linkCount

    private data class DescriptorDigest(
        val identity: LinuxFileIdentity,
        val bytes: Long,
        val sha256: String,
    )

    private const val BUFFER_BYTES = 1024 * 1024
    private const val OWNER_READ_ONLY_MODE = 0x100 // 0400
    private const val ANY_WRITE_MODE = 0x92 // owner-write, group-write, or other-write
    private const val UNTRUSTED_WRITE_MODE = 0x12 // group-write or other-write
    private val SHA256 = Regex("[0-9a-f]{64}")
}

internal fun openAuthenticatedReleaseDirectory(path: Path, label: String): AuthenticatedReleaseDirectory =
    openAuthenticatedReleaseDirectoryOrNull(path, label) ?: provenanceFail("$label is unavailable")

internal fun openOrCreateAuthenticatedReleaseDirectory(
    path: Path,
    label: String,
    faultInjector: ReleaseDirectoryFaultInjector? = null,
): AuthenticatedReleaseDirectory {
    val normalized = path.toAbsolutePath().normalize()
    openAuthenticatedReleaseDirectoryOrNull(normalized, label)?.let { return it }
    val parentPath = normalized.parent ?: provenanceFail("$label path has no existing parent")
    val name = normalized.fileName?.toString() ?: provenanceFail("$label path has no directory name")
    requireDirectoryName(name)
    openAuthenticatedReleaseDirectory(parentPath, "$label parent").use { parent ->
        return createOrOpenAuthenticatedChild(parent, name, label, faultInjector)
    }
}

internal fun createOrOpenAuthenticatedChild(
    parent: AuthenticatedReleaseDirectory,
    name: String,
    label: String,
    faultInjector: ReleaseDirectoryFaultInjector? = null,
): AuthenticatedReleaseDirectory {
    requireDirectoryName(name)
    val path = parent.path.resolve(name).normalize()
    if (path.parent != parent.path) provenanceFail("$label escapes its authenticated parent")
    requireDirectoryBinding(parent.path, parent.descriptor, parent.identity, "$label parent")
    faultInjector?.hit(ReleaseDirectoryPoint.BEFORE_CHILD_CREATE)
    requireDirectoryBinding(parent.path, parent.descriptor, parent.identity, "$label parent")
    var created = false
    try {
        try {
            LinuxFilesystemSyscalls.createDirectory(parent.descriptor.fd, name, OWNER_DIRECTORY_MODE)
            created = true
        } catch (failure: LinuxSyscallException) {
            if (failure.errno != LinuxFilesystemSyscalls.EEXIST) throw failure
        }
        requireDirectoryBinding(parent.path, parent.descriptor, parent.identity, "$label parent")
        val descriptor = LinuxFilesystemSyscalls.openDirectoryAt(parent.descriptor.fd, name)
        val child = authenticateOpenedReleaseDirectory(path, descriptor, label)
        try {
            if (created) {
                LinuxFilesystemSyscalls.synchronize(child.descriptor)
                requireDirectoryBinding(path, child.descriptor, child.identity, label)
                LinuxFilesystemSyscalls.synchronize(parent.descriptor)
                requireDirectoryBinding(parent.path, parent.descriptor, parent.identity, "$label parent")
                requireDirectoryBinding(path, child.descriptor, child.identity, label)
            }
            return child
        } catch (failure: Throwable) {
            child.close()
            throw failure
        }
    } catch (failure: Throwable) {
        throw if (failure is ReleaseArtifactProvenanceException) {
            failure
        } else {
            ReleaseArtifactProvenanceException("cannot create or authenticate $label", failure)
        }
    }
}

private fun openAuthenticatedReleaseDirectoryOrNull(
    path: Path,
    label: String,
): AuthenticatedReleaseDirectory? {
    val normalized = path.toAbsolutePath().normalize()
    val descriptor = try {
        LinuxFilesystemSyscalls.requireSupported(normalized)
        LinuxFilesystemSyscalls.openRoot(normalized)
    } catch (failure: LinuxSyscallException) {
        if (failure.errno == LINUX_ENOENT) return null
        throw ReleaseArtifactProvenanceException("cannot authenticate $label", failure)
    } catch (failure: Exception) {
        throw ReleaseArtifactProvenanceException("cannot authenticate $label", failure)
    }
    return authenticateOpenedReleaseDirectory(normalized, descriptor, label)
}

private fun authenticateOpenedReleaseDirectory(
    path: Path,
    descriptor: LinuxDescriptor,
    label: String,
): AuthenticatedReleaseDirectory {
    try {
        val identity = LinuxFilesystemSyscalls.identity(descriptor.fd)
        requireTrustedDirectoryIdentity(identity, label)
        requireDirectoryBinding(path, descriptor, identity, label)
        return AuthenticatedReleaseDirectory(path, descriptor, identity)
    } catch (failure: Throwable) {
        descriptor.close()
        if (failure is ReleaseArtifactProvenanceException) throw failure
        throw ReleaseArtifactProvenanceException("cannot authenticate $label", failure)
    }
}

private fun requireTrustedDirectoryIdentity(identity: LinuxFileIdentity, label: String) {
    if (!identity.isDirectory || identity.isRegularFile || identity.isSymbolicLink) {
        provenanceFail("$label is not an authenticated directory")
    }
    if (identity.mode.permissions and UNTRUSTED_DIRECTORY_WRITE_MODE != 0) {
        provenanceFail("$label is group-writable or other-writable")
    }
}

private fun requireDirectoryBinding(
    path: Path,
    descriptor: LinuxDescriptor,
    expected: LinuxFileIdentity,
    label: String,
) {
    val normalized = path.toAbsolutePath().normalize()
    val before = LinuxFilesystemSyscalls.identity(descriptor.fd)
    if (!sameAuthenticatedDirectory(expected, before)) provenanceFail("$label descriptor identity changed")
    val real = try {
        normalized.toRealPath()
    } catch (failure: Exception) {
        throw ReleaseArtifactProvenanceException("$label path cannot be resolved", failure)
    }
    if (real != normalized) provenanceFail("$label path contains a symbolic-link ancestor")
    if (!Files.isSameFile(normalized, LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd))) {
        provenanceFail("$label path no longer names its authenticated directory")
    }
    val after = LinuxFilesystemSyscalls.identity(descriptor.fd)
    if (!sameAuthenticatedDirectory(expected, after)) provenanceFail("$label descriptor identity changed")
}

private fun sameAuthenticatedDirectory(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
    left.key == right.key && left.mountId == right.mountId && left.mode == right.mode &&
        left.uid == right.uid && left.gid == right.gid &&
        left.isDirectory && right.isDirectory && !left.isRegularFile && !right.isRegularFile &&
        !left.isSymbolicLink && !right.isSymbolicLink

private fun requireDirectoryName(name: String) {
    if (name.isEmpty() || name == "." || name == ".." || '/' in name || '\u0000' in name) {
        provenanceFail("release directory name is invalid")
    }
}

private const val LINUX_ENOENT = 2
private const val OWNER_DIRECTORY_MODE = 0x1c0 // 0700
private const val UNTRUSTED_DIRECTORY_WRITE_MODE = 0x12 // group-write or other-write

private fun ByteArray.hex(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}
