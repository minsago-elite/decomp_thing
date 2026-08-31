package decompengine.oracle.provenance

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import java.io.InputStream
import java.net.URI
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.time.Duration
import kotlin.system.exitProcess

internal data class AuthenticatedLlvmSourceArchive(
    val archive: AuthenticatedDownloadedArtifact,
    val detachedSignature: AuthenticatedDownloadedArtifact,
    val signatureVerification: LlvmArchiveSignatureVerification,
    val archiveSummary: BoundedTarXzSummary,
)

internal fun interface LlvmSourceLockAuthority {
    fun verify(path: Path): LlvmSourceLockVerification
}

internal fun interface LlvmArchiveSignatureAuthority {
    fun verify(
        key: VerifiedLlvmSigningKey,
        signature: ByteArray,
        archive: InputStream,
        expectedBytes: Long,
        expectedSha256: String,
    ): LlvmArchiveSignatureVerification
}

internal fun interface LlvmSourceArchiveAuthority {
    fun scan(artifact: DescriptorBoundArtifact, locked: LlvmSourceLockVerification): BoundedTarXzSummary
}

internal enum class LlvmSourceArchiveMaterializationPoint {
    AFTER_SIGNATURE_SELECTED,
    AFTER_ARCHIVE_SIGNATURE_VERIFIED,
    AFTER_ARCHIVE_SCANNED,
}

internal fun interface LlvmSourceArchiveMaterializationFaultInjector {
    fun hit(point: LlvmSourceArchiveMaterializationPoint)
}

/**
 * Fetches and authenticates the locked LLVM source pair without extracting it.
 *
 * Every semantic archive phase runs over the publisher's exact descriptor. The source lock and its
 * local key/tag evidence, plus the detached-signature descriptor, are reauthenticated before and
 * after each phase by the publisher's input callback. Same-UID/root writers remain inside the
 * cooperating authority boundary: the checks reject observable mutation and pathname substitution,
 * but make no claim to detect a fully restored, byte-identical transient mutation.
 */
internal class LlvmSourceArchiveMaterializer(
    private val downloader: BoundedHttpsDownloader = BoundedHttpsDownloader(),
    private val lockAuthority: LlvmSourceLockAuthority = LlvmSourceLockAuthority {
        LlvmSourceLockVerifier().verify(it)
    },
    private val signatureAuthority: LlvmArchiveSignatureAuthority = LlvmArchiveSignatureAuthority {
            key,
            signature,
            archive,
            expectedBytes,
            expectedSha256,
        ->
        LlvmOpenPgpVerifier.verifyArchiveSignature(
            key,
            signature,
            archive,
            expectedBytes,
            expectedSha256,
        )
    },
    private val archiveAuthority: LlvmSourceArchiveAuthority = StrictLlvmSourceArchiveAuthority,
    private val faultInjector: LlvmSourceArchiveMaterializationFaultInjector? = null,
) {
    fun materialize(lockPath: Path, outputDirectory: Path): AuthenticatedLlvmSourceArchive {
        val locked = lockAuthority.verify(lockPath)
        PinnedLlvmSourceEvidence.open(locked).use { sourceEvidence ->
            requireCurrentLock(lockPath, locked, sourceEvidence)
            openOrCreateAuthenticatedReleaseDirectory(outputDirectory, "LLVM source output directory").use { output ->
                val signaturePath = output.path.resolve(locked.detachedSignature.fileName)
                val signatureArtifact = DescriptorBoundDownloadPublisher.materialize(
                    authenticatedParent = output,
                    targetPath = signaturePath,
                    expectedBytes = locked.detachedSignature.bytes,
                    expectedSha256 = locked.detachedSignature.sha256,
                    verifyInputs = { requireCurrentLock(lockPath, locked, sourceEvidence) },
                    verificationPhases = listOf(
                        DescriptorBoundArtifactVerifier { artifact ->
                            val signature = artifact.readBounded(MAXIMUM_OPENPGP_EVIDENCE_BYTES)
                            val profile = LlvmOpenPgpVerifier.inspectArchiveSignature(signature)
                            if (profile.signerFingerprint != locked.signingFingerprint) {
                                provenanceFail("LLVM archive signature signer differs from its source lock")
                            }
                        },
                    ),
                ) { sink -> download(locked.detachedSignature, sink) }

                faultInjector?.hit(LlvmSourceArchiveMaterializationPoint.AFTER_SIGNATURE_SELECTED)
                PinnedLlvmDetachedSignature.open(output, locked).use { signatureEvidence ->
                    requireCurrentInputs(lockPath, locked, sourceEvidence, signatureEvidence)
                    var signatureVerification: LlvmArchiveSignatureVerification? = null
                    var archiveSummary: BoundedTarXzSummary? = null
                    val archivePath = output.path.resolve(locked.archive.fileName)
                    val archiveArtifact = DescriptorBoundDownloadPublisher.materialize(
                        authenticatedParent = output,
                        targetPath = archivePath,
                        expectedBytes = locked.archive.bytes,
                        expectedSha256 = locked.archive.sha256,
                        verifyInputs = {
                            requireCurrentInputs(lockPath, locked, sourceEvidence, signatureEvidence)
                        },
                        verificationPhases = listOf(
                            DescriptorBoundArtifactVerifier { artifact ->
                                val signature = signatureEvidence.bytes()
                                val verified = artifact.withReadableChannel { channel ->
                                    signatureAuthority.verify(
                                        locked.signingKey,
                                        signature,
                                        Channels.newInputStream(channel),
                                        locked.archive.bytes,
                                        locked.archive.sha256,
                                    )
                                }
                                requireArchiveSignatureResult(locked, verified)
                                signatureVerification = verified
                                faultInjector?.hit(
                                    LlvmSourceArchiveMaterializationPoint.AFTER_ARCHIVE_SIGNATURE_VERIFIED,
                                )
                            },
                            DescriptorBoundArtifactVerifier { artifact ->
                                val summary = archiveAuthority.scan(artifact, locked)
                                requireLockedArchiveContents(locked, summary)
                                archiveSummary = summary
                                faultInjector?.hit(LlvmSourceArchiveMaterializationPoint.AFTER_ARCHIVE_SCANNED)
                            },
                        ),
                    ) { sink -> download(locked.archive, sink) }

                    requireCurrentInputs(lockPath, locked, sourceEvidence, signatureEvidence)
                    return AuthenticatedLlvmSourceArchive(
                        archive = archiveArtifact,
                        detachedSignature = signatureArtifact,
                        signatureVerification = signatureVerification
                            ?: provenanceFail("LLVM archive signature verification did not complete"),
                        archiveSummary = archiveSummary
                            ?: provenanceFail("LLVM source archive scan did not complete"),
                    )
                }
            }
        }
    }

    private fun download(
        artifact: LlvmLockedSourceArtifact,
        sink: java.nio.channels.WritableByteChannel,
    ): HttpsDownloadReceipt = downloader.download(
        HttpsDownloadRequest(
            uri = URI.create(artifact.url),
            expectedBytes = artifact.bytes,
            expectedSha256 = artifact.sha256,
            userAgent = USER_AGENT,
            timeout = DOWNLOAD_TIMEOUT,
            allowedHosts = ALLOWED_RELEASE_HOSTS,
        ),
        sink,
    )

    private fun requireCurrentInputs(
        lockPath: Path,
        expected: LlvmSourceLockVerification,
        sourceEvidence: PinnedLlvmSourceEvidence,
        signatureEvidence: PinnedLlvmDetachedSignature,
    ) {
        signatureEvidence.requireCurrent()
        requireCurrentLock(lockPath, expected, sourceEvidence)
        signatureEvidence.requireCurrent()
    }

    private fun requireCurrentLock(
        lockPath: Path,
        expected: LlvmSourceLockVerification,
        sourceEvidence: PinnedLlvmSourceEvidence,
    ) {
        sourceEvidence.requireCurrent()
        val actual = lockAuthority.verify(lockPath)
        sourceEvidence.requireCurrent()
        if (expected.copy(signingKey = actual.signingKey) != actual) {
            provenanceFail("LLVM source lock or local key/tag evidence changed during materialization")
        }
    }

    private companion object {
        const val MAXIMUM_OPENPGP_EVIDENCE_BYTES = 64 * 1024
        const val USER_AGENT = "decomp-thing-llvm-source/1"
        val DOWNLOAD_TIMEOUT: Duration = Duration.ofSeconds(300)
        val ALLOWED_RELEASE_HOSTS = setOf("github.com", "release-assets.githubusercontent.com")
    }
}

/** Stable JVM entry point replacing the Python LLVM source fetch and verification authority. */
object LlvmSourceArchiveFetcherCli {
    @JvmStatic
    fun main(arguments: Array<String>) {
        val status = run(arguments)
        if (status != 0) exitProcess(status)
    }

    internal fun run(
        arguments: Array<String>,
        materialize: (Path, Path) -> AuthenticatedLlvmSourceArchive = { lock, output ->
            LlvmSourceArchiveMaterializer().materialize(lock, output)
        },
        stdout: (String) -> Unit = ::println,
        stderr: (String) -> Unit = System.err::println,
    ): Int = try {
        val options = LlvmSourceArchiveArguments.parse(arguments)
        val result = materialize(options.lock, options.output)
        successMessages(result).forEach(stdout)
        0
    } catch (failure: Exception) {
        stderr("LLVM source archive fetch failed: ${failure.message}")
        1
    }

    internal fun successMessages(result: AuthenticatedLlvmSourceArchive): List<String> = listOf(
        "verified LLVM source archive: ${result.archive.path} " +
            "(${result.archive.bytes} bytes, sha256 ${result.archive.sha256})",
        "verified LLVM source archive signature: ${result.detachedSignature.path} " +
            "(${result.detachedSignature.bytes} bytes, sha256 ${result.detachedSignature.sha256})",
        "verified LLVM source archive structure: ${result.archiveSummary.memberCount} members, " +
            "commit-PAX and ${result.archiveSummary.selected.size} locked markers",
    )
}

internal data class LlvmSourceArchiveArguments(val lock: Path, val output: Path) {
    companion object {
        fun parse(arguments: Array<String>): LlvmSourceArchiveArguments {
            var lock: Path? = null
            var output: Path? = null
            var index = 0
            while (index < arguments.size) {
                val option = arguments[index]
                if (option !in setOf("--lock", "--output")) provenanceFail("unknown option $option")
                index++
                if (index >= arguments.size) provenanceFail("$option requires a path")
                val rawValue = arguments[index]
                if (rawValue.isEmpty()) provenanceFail("$option requires a non-empty path")
                val value = Path.of(rawValue)
                when (option) {
                    "--lock" -> if (lock == null) lock = value else provenanceFail("--lock was repeated")
                    "--output" -> if (output == null) output = value else provenanceFail("--output was repeated")
                }
                index++
            }
            return LlvmSourceArchiveArguments(
                lock ?: provenanceFail("--lock is required"),
                output ?: provenanceFail("--output is required"),
            )
        }
    }
}

private object StrictLlvmSourceArchiveAuthority : LlvmSourceArchiveAuthority {
    override fun scan(
        artifact: DescriptorBoundArtifact,
        locked: LlvmSourceLockVerification,
    ): BoundedTarXzSummary = artifact.withReadableChannel { channel ->
        BoundedTarXzArchive.scan(
            source = FileChannelTarXzSource(channel),
            expectedRoot = locked.archiveRoot,
            expectedCommit = locked.commit,
            selectedRegularPaths = locked.archiveContents
                .mapTo(linkedSetOf()) { "${locked.archiveRoot}/${it.path}" },
        )
    }
}

private class FileChannelTarXzSource(private val channel: FileChannel) : BoundedTarXzSource {
    override val size: Long = channel.size()

    override fun read(position: Long, destination: ByteArray, offset: Int, length: Int): Int {
        val read = channel.read(ByteBuffer.wrap(destination, offset, length), position)
        if (read == 0 && length > 0) provenanceFail("LLVM source archive descriptor made no read progress")
        return read
    }
}

private fun requireArchiveSignatureResult(
    locked: LlvmSourceLockVerification,
    verified: LlvmArchiveSignatureVerification,
) {
    if (
        verified.bytes != locked.archive.bytes || verified.sha256 != locked.archive.sha256 ||
        verified.signerFingerprint != locked.signingFingerprint ||
        verified.signatureCreationEpochSeconds != ARCHIVE_SIGNATURE_EPOCH_SECONDS
    ) {
        provenanceFail("LLVM archive signature verification result differs from its source lock")
    }
}

private const val ARCHIVE_SIGNATURE_EPOCH_SECONDS = 1_779_316_752L

private fun requireLockedArchiveContents(
    locked: LlvmSourceLockVerification,
    summary: BoundedTarXzSummary,
) {
    val expectedPaths = locked.archiveContents.map { "${locked.archiveRoot}/${it.path}" }
    if (summary.selected.size != expectedPaths.size || summary.selected.keys != expectedPaths.toSet()) {
        provenanceFail("LLVM source archive did not expose exactly the three locked markers")
    }
    locked.archiveContents.zip(expectedPaths).forEach { (record, path) ->
        val selected = summary.selected[path]
            ?: provenanceFail("LLVM source archive is missing locked marker $path")
        if (
            selected.bytes.size.toLong() != record.bytes || selected.sha256 != record.sha256 ||
            selected.bytes.sha256() != record.sha256
        ) {
            provenanceFail("LLVM source archive marker $path differs from its source lock")
        }
        record.text?.let { expectedText ->
            if (!MessageDigest.isEqual(selected.bytes, expectedText.toByteArray(StandardCharsets.UTF_8))) {
                provenanceFail("LLVM source archive marker $path text differs from its source lock")
            }
        }
    }
}

private class PinnedLlvmSourceEvidence private constructor(
    private val directories: List<AuthenticatedReleaseDirectory>,
    private val files: List<PinnedLlvmEvidenceFile>,
) : AutoCloseable {
    fun requireCurrent() {
        directories.forEach(::requireCurrentDirectory)
        files.forEach(PinnedLlvmEvidenceFile::requireCurrent)
        directories.forEach(::requireCurrentDirectory)
    }

    override fun close() {
        files.asReversed().forEach(PinnedLlvmEvidenceFile::close)
        directories.asReversed().forEach(AuthenticatedReleaseDirectory::close)
    }

    companion object {
        fun open(locked: LlvmSourceLockVerification): PinnedLlvmSourceEvidence {
            val rootPath = locked.path.parent ?: provenanceFail("LLVM source lock has no parent")
            val directories = mutableListOf<AuthenticatedReleaseDirectory>()
            val files = mutableListOf<PinnedLlvmEvidenceFile>()
            try {
                val root = openAuthenticatedReleaseDirectory(rootPath, "LLVM source-lock directory")
                    .also(directories::add)
                val keys = openAuthenticatedReleaseDirectory(rootPath.resolve("keys"), "LLVM signing-key directory")
                    .also(directories::add)
                val tag = openAuthenticatedReleaseDirectory(rootPath.resolve("tag"), "LLVM tag-evidence directory")
                    .also(directories::add)
                files += PinnedLlvmEvidenceFile.open(
                    root,
                    locked.path.fileName.toString(),
                    locked.lockSha256,
                    MAXIMUM_LOCAL_EVIDENCE_BYTES,
                    "LLVM source lock",
                )
                files += PinnedLlvmEvidenceFile.open(
                    keys,
                    "douglas-yung-llvm-release.asc",
                    locked.signingKeySha256,
                    MAXIMUM_LOCAL_EVIDENCE_BYTES,
                    "LLVM signing key",
                )
                files += PinnedLlvmEvidenceFile.open(
                    tag,
                    "${locked.tag}.payload",
                    locked.tagPayloadSha256,
                    MAXIMUM_LOCAL_EVIDENCE_BYTES,
                    "LLVM tag payload",
                )
                files += PinnedLlvmEvidenceFile.open(
                    tag,
                    "${locked.tag}.sig",
                    locked.tagSignatureSha256,
                    MAXIMUM_LOCAL_EVIDENCE_BYTES,
                    "LLVM tag signature",
                )
                return PinnedLlvmSourceEvidence(directories, files).also { it.requireCurrent() }
            } catch (failure: Throwable) {
                files.asReversed().forEach(PinnedLlvmEvidenceFile::close)
                directories.asReversed().forEach(AuthenticatedReleaseDirectory::close)
                throw failure
            }
        }

        private const val MAXIMUM_LOCAL_EVIDENCE_BYTES = 64 * 1024
    }
}

private class PinnedLlvmDetachedSignature private constructor(
    private val file: PinnedLlvmEvidenceFile,
) : AutoCloseable {
    fun bytes(): ByteArray = file.bytes()
    fun requireCurrent() = file.requireCurrent()
    override fun close() = file.close()

    companion object {
        fun open(
            parent: AuthenticatedReleaseDirectory,
            locked: LlvmSourceLockVerification,
        ): PinnedLlvmDetachedSignature = PinnedLlvmDetachedSignature(
            PinnedLlvmEvidenceFile.open(
                parent,
                locked.detachedSignature.fileName,
                locked.detachedSignature.sha256,
                64 * 1024,
                "LLVM source archive signature",
                expectedBytes = locked.detachedSignature.bytes,
                requireReadOnly = true,
            ),
        )
    }
}

private class PinnedLlvmEvidenceFile private constructor(
    private val parent: AuthenticatedReleaseDirectory,
    private val name: String,
    private val descriptor: LinuxDescriptor,
    private val expectedIdentity: LinuxFileIdentity,
    private val expectedBytes: ByteArray,
    private val label: String,
    private val requireReadOnly: Boolean,
) : AutoCloseable {
    fun bytes(): ByteArray {
        requireCurrent()
        return expectedBytes.copyOf()
    }

    fun requireCurrent() {
        requireCurrentDirectory(parent)
        val current = LinuxFilesystemSyscalls.identity(descriptor.fd)
        if (!sameEvidenceFile(expectedIdentity, current) ||
            (requireReadOnly && current.mode.permissions and ANY_WRITE_MODE != 0)
        ) {
            provenanceFail("$label descriptor identity or permissions changed")
        }
        LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.descriptor.fd, name)?.use { named ->
            if (!sameEvidenceFile(expectedIdentity, LinuxFilesystemSyscalls.identity(named.fd))) {
                provenanceFail("$label pathname changed")
            }
        } ?: provenanceFail("$label disappeared")
        val observed = readDescriptor(descriptor, expectedBytes.size, label)
        if (!MessageDigest.isEqual(expectedBytes, observed)) provenanceFail("$label bytes changed")
        requireCurrentDirectory(parent)
    }

    override fun close() = descriptor.close()

    companion object {
        fun open(
            parent: AuthenticatedReleaseDirectory,
            name: String,
            expectedSha256: String,
            maximumBytes: Int,
            label: String,
            expectedBytes: Long? = null,
            requireReadOnly: Boolean = false,
        ): PinnedLlvmEvidenceFile {
            val descriptor = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.descriptor.fd, name)
                ?: provenanceFail("$label is unavailable")
            try {
                val identity = LinuxFilesystemSyscalls.identity(descriptor.fd)
                if (identity.mode.permissions and UNTRUSTED_WRITE_MODE != 0 ||
                    (requireReadOnly && identity.mode.permissions and ANY_WRITE_MODE != 0)
                ) {
                    provenanceFail("$label permissions are not trusted")
                }
                val bytes = readDescriptor(descriptor, maximumBytes, label)
                if (expectedBytes != null && bytes.size.toLong() != expectedBytes) {
                    provenanceFail("$label byte length differs from its source lock")
                }
                if (bytes.sha256() != expectedSha256) provenanceFail("$label SHA-256 differs from its source lock")
                return PinnedLlvmEvidenceFile(
                    parent,
                    name,
                    descriptor,
                    LinuxFilesystemSyscalls.identity(descriptor.fd),
                    bytes,
                    label,
                    requireReadOnly,
                ).also { it.requireCurrent() }
            } catch (failure: Throwable) {
                descriptor.close()
                throw failure
            }
        }
    }
}

private fun readDescriptor(descriptor: LinuxDescriptor, maximumBytes: Int, label: String): ByteArray {
    val before = LinuxFilesystemSyscalls.identity(descriptor.fd)
    val bytes = FileChannel.open(
        LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd),
        StandardOpenOption.READ,
    ).use { channel ->
        val size = channel.size()
        if (size !in 1L..maximumBytes.toLong()) provenanceFail("$label exceeds its byte bound")
        val result = ByteArray(size.toInt())
        val destination = ByteBuffer.wrap(result)
        while (destination.hasRemaining()) {
            if (channel.read(destination) <= 0) provenanceFail("$label ended during descriptor-bound reading")
        }
        if (channel.read(ByteBuffer.allocate(1)) >= 0 || channel.size() != size) {
            provenanceFail("$label changed size during descriptor-bound reading")
        }
        result
    }
    if (!sameEvidenceFile(before, LinuxFilesystemSyscalls.identity(descriptor.fd))) {
        provenanceFail("$label identity changed during descriptor-bound reading")
    }
    return bytes
}

private fun DescriptorBoundArtifact.readBounded(maximumBytes: Int): ByteArray =
    withReadableChannel { channel ->
        if (bytes > maximumBytes.toLong()) provenanceFail("descriptor-bound evidence exceeds its byte bound")
        val result = ByteArray(bytes.toInt())
        val destination = ByteBuffer.wrap(result)
        while (destination.hasRemaining()) {
            if (channel.read(destination) <= 0) provenanceFail("descriptor-bound evidence ended while reading")
        }
        if (channel.read(ByteBuffer.allocate(1)) >= 0) {
            provenanceFail("descriptor-bound evidence exceeds its locked byte length")
        }
        result
    }

private fun requireCurrentDirectory(directory: AuthenticatedReleaseDirectory) {
    val current = LinuxFilesystemSyscalls.identity(directory.descriptor.fd)
    if (!sameEvidenceDirectory(directory.identity, current)) {
        provenanceFail("authenticated evidence directory identity or permissions changed")
    }
    val real = try {
        directory.path.toRealPath()
    } catch (failure: Exception) {
        throw ReleaseArtifactProvenanceException("authenticated evidence directory is unavailable", failure)
    }
    if (real != directory.path ||
        !Files.isSameFile(directory.path, LinuxFilesystemSyscalls.stableDescriptorPath(directory.descriptor.fd))
    ) {
        provenanceFail("authenticated evidence directory pathname changed")
    }
}

private fun sameEvidenceDirectory(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
    left.key == right.key && left.mountId == right.mountId && left.mode == right.mode &&
        left.uid == right.uid && left.gid == right.gid && left.isDirectory && right.isDirectory &&
        !left.isRegularFile && !right.isRegularFile && !left.isSymbolicLink && !right.isSymbolicLink

private fun sameEvidenceFile(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
    left.key == right.key && left.mountId == right.mountId && left.mode == right.mode &&
        left.uid == right.uid && left.gid == right.gid && left.linkCount == right.linkCount &&
        left.isRegularFile && right.isRegularFile && !left.isDirectory && !right.isDirectory &&
        !left.isSymbolicLink && !right.isSymbolicLink

private fun ByteArray.sha256(): String = MessageDigest.getInstance("SHA-256").digest(this)
    .joinToString(separator = "") { byte -> (byte.toInt() and 0xff).toString(16).padStart(2, '0') }

private const val ANY_WRITE_MODE = 0x92
private const val UNTRUSTED_WRITE_MODE = 0x12
