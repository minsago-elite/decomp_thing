package decompengine.oracle.behavior

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.security.DigestOutputStream
import java.util.Comparator
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

internal class LlvmBehaviorCandidateFourWayBindingV2Exception(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

/**
 * Structural identity of exactly one archive, first-class ACP lineage index, unsigned hosted
 * receipt, and executable.
 *
 * The canonical JSON bytes and canonical domain-separated length frames hashed as the structural
 * identity are defensive copies. The framing is inert in-memory binding material, not a schema,
 * publication, receipt, or admission capability. This value authenticates no hosted build
 * execution and grants no admission, PREPARED, START, oracle, reference, scoring, certification,
 * or release authority.
 */
internal sealed interface LlvmBehaviorCandidateFourWayBindingV2Verification {
    val schemaVersion: Int
    val verificationKind: String
    val candidateStructuralIdentitySha256: String
    val canonicalBindingBytes: ByteArray
    val archiveBytes: Long
    val archiveSha256: String
    val lineageIndexBytes: Long
    val lineageIndexSha256: String
    val canonicalLineageIndexBytes: ByteArray
    val hostedReceiptBytes: Long
    val hostedReceiptSha256: String
    val canonicalHostedReceiptBytes: ByteArray
    val executableBytes: Long
    val executableSha256: String
    val sourceRevisionSha256: String
    val sourceInputCount: Int
    val acceptedAcpCount: Int
    val reconstructionAcpCount: Int
    val repairAcpCount: Int
    val acpReceiptSetSha256: String
    val acpSessionSetSha256: String
    val acpChangeSetSha256: String
    val acpLineageSetSha256: String
    val candidateSourceLineageSha256: String
    val exactFourWayStructuralBinding: Boolean
    val acpRequired: Boolean
    val acpFirstClassCandidateProducerOperator: Boolean
    val acpOracleAuthority: Boolean
    val acpReferenceAuthoringAuthority: Boolean
    val acpPolicyAuthoringAuthority: Boolean
    val acpValidationAuthority: Boolean
    val acpObservationAuthoringAuthority: Boolean
    val acpStartAuthority: Boolean
    val acpContainmentAuthority: Boolean
    val acpTerminalAbsenceAuthority: Boolean
    val acpScoringAuthority: Boolean
    val acpCertificationAuthority: Boolean
    val acpReleaseAuthority: Boolean
    val hostedBuildExecutionAuthenticated: Boolean
    val admittedArtifactBound: Boolean
    val prepared: Boolean
    val startAuthorized: Boolean
    val candidateStarted: Boolean
    val scoringAuthority: Boolean
    val certificationAuthority: Boolean
    val releaseEligible: Boolean
}

/**
 * Safe pre-authority composition checkpoint over exactly four raw paths.
 *
 * All four source inodes and their lexical parents remain pinned while private copies are passed
 * to the existing archive/lineage and receipt/executable verifiers. No parsed fact supplied by a
 * caller, legacy admission artifact, corpus, report, matrix, or manifest is accepted.
 */
internal object LlvmBehaviorCandidateFourWayBindingV2Verifier {
    fun verify(
        archivePath: Path,
        lineageIndexPath: Path,
        hostedReceiptPath: Path,
        executablePath: Path,
    ): LlvmBehaviorCandidateFourWayBindingV2Verification = verifyFourWay(
        archivePath,
        lineageIndexPath,
        hostedReceiptPath,
        executablePath,
        beforeTerminalSourceAuthentication = {},
        rawOpenFaultInjector = null,
    )

    private fun verifyFourWay(
        archivePath: Path,
        lineageIndexPath: Path,
        hostedReceiptPath: Path,
        executablePath: Path,
        beforeTerminalSourceAuthentication: () -> Unit,
        rawOpenFaultInjector: ((LlvmBehaviorCandidateFourWayBindingV2RawOpenFaultPoint) -> Unit)?,
    ): LlvmBehaviorCandidateFourWayBindingV2Verification = translateBindingFailure {
        val paths = normalizeFourWayPaths(archivePath, lineageIndexPath, hostedReceiptPath, executablePath)
        FourWayInputGuards.open(paths, rawOpenFaultInjector).use { guards ->
            requireRawLayout(paths, guards)
            val sourceDigests = captureSourceDigests(paths, guards)
            val snapshots = snapshotAll(paths, guards, sourceDigests)
            try {
                requireCurrentSources(paths, guards, sourceDigests)
                val lineage = LlvmBehaviorCandidateAcpLineageIndexV2Verifier.verify(
                    snapshots.archive,
                    snapshots.lineageIndex,
                )
                requireCurrentSources(paths, guards, sourceDigests)
                val hosted = LlvmBehaviorHostedCleanBuildV2Verifier.verify(
                    snapshots.hostedReceipt,
                    snapshots.executable,
                )
                requireCurrentSources(paths, guards, sourceDigests)
                requireLineageResultMatchesSnapshots(lineage, snapshots)
                requireHostedResultMatchesSnapshots(hosted, snapshots)
                val lineageDocument = parseVerifiedObject(
                    snapshots.lineageIndexBytes,
                    LINEAGE_INDEX_JSON_LIMITS,
                    "verified candidate ACP lineage index",
                )
                val hostedDocument = parseVerifiedObject(
                    snapshots.hostedReceiptBytes,
                    HOSTED_RECEIPT_JSON_LIMITS,
                    "verified hosted clean-build receipt",
                )
                requireFourWayProjection(lineage, lineageDocument, hostedDocument)
                val identity = deriveCandidateStructuralIdentity(snapshots, lineageDocument, lineage)

                beforeTerminalSourceAuthentication()
                requireCurrentSources(paths, guards, sourceDigests)
                verifiedResult(identity, snapshots, lineage)
            } finally {
                deletePrivateSnapshotTree(snapshots.root)
            }
        }
    }

    private fun verifiedResult(
        identity: Pair<ByteArray, String>,
        snapshots: SnapshotSet,
        lineage: LlvmBehaviorCandidateAcpLineageIndexV2,
    ): LlvmBehaviorCandidateFourWayBindingV2Verification = verifiedResultConstructor.newInstance(
        identity,
        snapshots,
        lineage,
    )

    private class VerifiedFourWayBinding private constructor(
        identity: Pair<ByteArray, String>,
        snapshots: SnapshotSet,
        lineage: LlvmBehaviorCandidateAcpLineageIndexV2,
    ) : LlvmBehaviorCandidateFourWayBindingV2Verification {
        private val storedCanonicalBinding = identity.first.copyOf()
        private val storedLineageIndex = snapshots.lineageIndexBytes.copyOf()
        private val storedHostedReceipt = snapshots.hostedReceiptBytes.copyOf()

        override val schemaVersion = 2
        override val verificationKind = FOUR_WAY_BINDING_KIND
        override val candidateStructuralIdentitySha256: String = identity.second
        override val canonicalBindingBytes: ByteArray
            get() = storedCanonicalBinding.copyOf()
        override val archiveBytes: Long = snapshots.archiveBytes
        override val archiveSha256: String = snapshots.archiveSha256
        override val lineageIndexBytes: Long = storedLineageIndex.size.toLong()
        override val lineageIndexSha256: String = OracleArtifacts.sha256(storedLineageIndex)
        override val canonicalLineageIndexBytes: ByteArray
            get() = storedLineageIndex.copyOf()
        override val hostedReceiptBytes: Long = storedHostedReceipt.size.toLong()
        override val hostedReceiptSha256: String = OracleArtifacts.sha256(storedHostedReceipt)
        override val canonicalHostedReceiptBytes: ByteArray
            get() = storedHostedReceipt.copyOf()
        override val executableBytes: Long = snapshots.executableBytes
        override val executableSha256: String = snapshots.executableSha256
        override val sourceRevisionSha256: String = lineage.sourceRevisionSha256
        override val sourceInputCount: Int = lineage.sourceInputCount
        override val acceptedAcpCount: Int = lineage.acceptedAcpCount
        override val reconstructionAcpCount: Int = lineage.reconstructionCount
        override val repairAcpCount: Int = lineage.repairCount
        override val acpReceiptSetSha256: String = lineage.receiptSetSha256
        override val acpSessionSetSha256: String = lineage.sessionSetSha256
        override val acpChangeSetSha256: String = lineage.changeSetSha256
        override val acpLineageSetSha256: String = lineage.lineageSetSha256
        override val candidateSourceLineageSha256: String = lineage.candidateSourceLineageSha256
        override val exactFourWayStructuralBinding = true
        override val acpRequired = true
        override val acpFirstClassCandidateProducerOperator = true
        override val acpOracleAuthority = false
        override val acpReferenceAuthoringAuthority = false
        override val acpPolicyAuthoringAuthority = false
        override val acpValidationAuthority = false
        override val acpObservationAuthoringAuthority = false
        override val acpStartAuthority = false
        override val acpContainmentAuthority = false
        override val acpTerminalAbsenceAuthority = false
        override val acpScoringAuthority = false
        override val acpCertificationAuthority = false
        override val acpReleaseAuthority = false
        override val hostedBuildExecutionAuthenticated = false
        override val admittedArtifactBound = false
        override val prepared = false
        override val startAuthorized = false
        override val candidateStarted = false
        override val scoringAuthority = false
        override val certificationAuthority = false
        override val releaseEligible = false

    }

    /*
     * Calling a Kotlin private constructor from its companion emits a public synthetic JVM
     * constructor. Resolve the genuinely private constructor once from the enclosing verifier so
     * the sealed implementation has no public construction path in emitted bytecode.
     */
    private val verifiedResultConstructor = VerifiedFourWayBinding::class.java.getDeclaredConstructor(
        Pair::class.java,
        SnapshotSet::class.java,
        LlvmBehaviorCandidateAcpLineageIndexV2::class.java,
    ).apply {
        if (!trySetAccessible()) bindingFail("four-way result constructor is not privately accessible")
    }
}

private data class FourWayPaths(
    val archive: Path,
    val lineageIndex: Path,
    val hostedReceipt: Path,
    val executable: Path,
) {
    val all: List<Pair<String, Path>> = listOf(
        "candidate reconstruction archive" to archive,
        "candidate ACP lineage index" to lineageIndex,
        "hosted clean-build receipt" to hostedReceipt,
        "hosted candidate executable" to executable,
    )
}

private enum class LlvmBehaviorCandidateFourWayBindingV2RawOpenFaultPoint {
    AFTER_PARENTS_PINNED,
    AFTER_ARCHIVE_PINNED,
    AFTER_LINEAGE_INDEX_PINNED,
    AFTER_HOSTED_RECEIPT_PINNED,
    AFTER_EXECUTABLE_PINNED,
}

private class PinnedFourWayParent private constructor(
    val path: Path,
    val descriptor: LinuxDescriptor,
    val identity: LinuxFileIdentity,
    private val exactOwnerDirectoryMode: Boolean,
) : AutoCloseable {
    fun requireCurrent() {
        val descriptorNow = descriptor.whileOpen(LinuxFilesystemSyscalls::identity)
        if (!samePinnedDirectory(identity, descriptorNow)) {
            bindingFail("four-way source parent descriptor identity changed")
        }
        val real = try {
            path.toRealPath()
        } catch (failure: Exception) {
            bindingFail("four-way source parent lexical path is unavailable", failure)
        }
        if (real != path ||
            !Files.isSameFile(path, LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd))
        ) {
            bindingFail("four-way source parent lexical path changed identity")
        }
        requireTrustedParentIdentity(descriptorNow, exactOwnerDirectoryMode)
        val terminal = descriptor.whileOpen(LinuxFilesystemSyscalls::identity)
        if (!samePinnedDirectory(identity, terminal)) {
            bindingFail("four-way source parent descriptor changed during currentness authentication")
        }
    }

    fun entryNames(maximumEntries: Int): Set<String> {
        requireCurrent()
        val names = try {
            LinuxFilesystemSyscalls.directoryEntryNames(descriptor, maximumEntries)
        } catch (failure: Exception) {
            bindingFail("four-way source parent cannot be enumerated descriptor-relative", failure)
        }
        requireCurrent()
        return names.toSet()
    }

    override fun close() = descriptor.close()

    companion object {
        fun open(path: Path, exactOwnerDirectoryMode: Boolean): PinnedFourWayParent {
            LinuxFilesystemSyscalls.requireSupported(path)
            val descriptor = LinuxFilesystemSyscalls.openRoot(path)
            try {
                val identity = descriptor.whileOpen(LinuxFilesystemSyscalls::identity)
                requireTrustedParentIdentity(identity, exactOwnerDirectoryMode)
                return PinnedFourWayParent(path, descriptor, identity, exactOwnerDirectoryMode)
                    .also(PinnedFourWayParent::requireCurrent)
            } catch (failure: Throwable) {
                descriptor.close()
                throw failure
            }
        }
    }
}

private class PinnedFourWayFile private constructor(
    private val parent: PinnedFourWayParent,
    val name: String,
    val label: String,
    val descriptor: LinuxDescriptor,
    val identity: LinuxFileIdentity,
    val size: Long,
    private val maximumBytes: Long,
    private val exactMode: Int?,
) : AutoCloseable {
    fun requireCurrent() {
        parent.requireCurrent()
        val descriptorNow = descriptor.whileOpen(LinuxFilesystemSyscalls::identity)
        if (!samePinnedRegularFile(identity, descriptorNow)) {
            bindingFail("$label descriptor identity or mode changed")
        }
        requireTrustedFileIdentity(descriptorNow, parent.identity, exactMode, label)
        val named = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.descriptor.fd, name)
            ?: bindingFail("$label descriptor-relative name disappeared")
        named.use {
            val namedIdentity = named.whileOpen(LinuxFilesystemSyscalls::identity)
            if (!samePinnedRegularFile(identity, namedIdentity)) {
                bindingFail("$label descriptor-relative name changed identity")
            }
        }
        val observedSize = try {
            Files.size(LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd))
        } catch (failure: Exception) {
            bindingFail("$label pinned byte length is unavailable", failure)
        }
        if (observedSize != size) bindingFail("$label changed byte length")
        parent.requireCurrent()
        val terminal = descriptor.whileOpen(LinuxFilesystemSyscalls::identity)
        if (!samePinnedRegularFile(identity, terminal)) {
            bindingFail("$label descriptor changed during currentness authentication")
        }
    }

    fun sha256(): String {
        requireCurrent()
        val digest = MessageDigest.getInstance("SHA-256")
        val observed = DigestOutputStream(OutputStream.nullOutputStream(), digest).use { output ->
            LinuxFilesystemSyscalls.copyReadableTo(descriptor, output, maximumBytes)
        }
        if (observed != size) bindingFail("$label changed byte length while descriptor-hashed")
        requireCurrent()
        return digest.digest().hex()
    }

    fun readBoundedJson(): ByteArray {
        if (maximumBytes > Int.MAX_VALUE.toLong()) bindingFail("$label JSON bound exceeds the JVM array limit")
        requireCurrent()
        val bytes = LinuxFilesystemSyscalls.openReadableFrom(descriptor).use { readable ->
            LinuxFilesystemSyscalls.read(readable, maximumBytes.toInt()) {}
        }
        if (bytes.size.toLong() != size) bindingFail("$label changed byte length while descriptor-read")
        requireCurrent()
        return bytes
    }

    fun copyTo(output: OutputStream): String {
        requireCurrent()
        val digest = MessageDigest.getInstance("SHA-256")
        val observed = DigestOutputStream(output, digest).let { digesting ->
            val copied = LinuxFilesystemSyscalls.copyReadableTo(descriptor, digesting, maximumBytes)
            digesting.flush()
            copied
        }
        if (observed != size) bindingFail("$label changed byte length while descriptor-copied")
        requireCurrent()
        return digest.digest().hex()
    }

    override fun close() = descriptor.close()

    companion object {
        fun open(
            parent: PinnedFourWayParent,
            name: String,
            label: String,
            maximumBytes: Long,
            exactMode: Int?,
        ): PinnedFourWayFile {
            parent.requireCurrent()
            val descriptor = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.descriptor.fd, name)
                ?: bindingFail("$label is unavailable descriptor-relative to its pinned parent")
            try {
                val identity = descriptor.whileOpen(LinuxFilesystemSyscalls::identity)
                requireTrustedFileIdentity(identity, parent.identity, exactMode, label)
                val size = try {
                    Files.size(LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd))
                } catch (failure: Exception) {
                    bindingFail("$label pinned byte length is unavailable", failure)
                }
                if (size !in 1L..maximumBytes) bindingFail("$label exceeds its descriptor-pinned byte bound")
                return PinnedFourWayFile(
                    parent,
                    name,
                    label,
                    descriptor,
                    identity,
                    size,
                    maximumBytes,
                    exactMode,
                ).also(PinnedFourWayFile::requireCurrent)
            } catch (failure: Throwable) {
                descriptor.close()
                throw failure
            }
        }
    }
}

private class FourWayInputGuards private constructor(
    val archive: PinnedFourWayFile,
    val lineageIndex: PinnedFourWayFile,
    val hostedReceipt: PinnedFourWayFile,
    val executable: PinnedFourWayFile,
    val parents: List<PinnedFourWayParent>,
) : AutoCloseable {
    val files: List<PinnedFourWayFile> = listOf(archive, lineageIndex, hostedReceipt, executable)

    override fun close() {
        files.asReversed().forEach { runCatching(it::close) }
        parents.asReversed().forEach { runCatching(it::close) }
    }

    companion object {
        fun open(
            paths: FourWayPaths,
            faultInjector: ((LlvmBehaviorCandidateFourWayBindingV2RawOpenFaultPoint) -> Unit)?,
        ): FourWayInputGuards {
            val parents = LinkedHashMap<Path, PinnedFourWayParent>()
            val files = ArrayList<PinnedFourWayFile>()
            try {
                val exactOwnerParents = setOf(paths.lineageIndex.parent, paths.hostedReceipt.parent)
                paths.all.map { (_, path) -> path.parent }.distinct().forEach { parentPath ->
                    parents[parentPath] = PinnedFourWayParent.open(
                        parentPath,
                        exactOwnerDirectoryMode = parentPath in exactOwnerParents,
                    )
                }
                faultInjector?.invoke(LlvmBehaviorCandidateFourWayBindingV2RawOpenFaultPoint.AFTER_PARENTS_PINNED)
                fun open(
                    path: Path,
                    label: String,
                    maximumBytes: Long,
                    exactMode: Int?,
                ): PinnedFourWayFile = PinnedFourWayFile.open(
                    requireNotNull(parents[path.parent]),
                    path.fileName.toString(),
                    label,
                    maximumBytes,
                    exactMode,
                ).also(files::add)

                val archive = open(
                    paths.archive,
                    "candidate reconstruction archive",
                    LLVM_BEHAVIOR_CANDIDATE_ACP_LINEAGE_MAXIMUM_ARCHIVE_BYTES,
                    null,
                )
                faultInjector?.invoke(LlvmBehaviorCandidateFourWayBindingV2RawOpenFaultPoint.AFTER_ARCHIVE_PINNED)
                val lineageIndex = open(
                    paths.lineageIndex,
                    "candidate ACP lineage index",
                    MAXIMUM_LINEAGE_INDEX_BYTES,
                    OWNER_READ_ONLY_MODE,
                )
                faultInjector?.invoke(
                    LlvmBehaviorCandidateFourWayBindingV2RawOpenFaultPoint.AFTER_LINEAGE_INDEX_PINNED,
                )
                val hostedReceipt = open(
                    paths.hostedReceipt,
                    "hosted clean-build receipt",
                    MAXIMUM_HOSTED_RECEIPT_BYTES,
                    OWNER_READ_ONLY_MODE,
                )
                faultInjector?.invoke(
                    LlvmBehaviorCandidateFourWayBindingV2RawOpenFaultPoint.AFTER_HOSTED_RECEIPT_PINNED,
                )
                val executable = open(
                    paths.executable,
                    "hosted candidate executable",
                    MAXIMUM_EXECUTABLE_BYTES,
                    OWNER_READ_EXECUTE_MODE,
                )
                faultInjector?.invoke(
                    LlvmBehaviorCandidateFourWayBindingV2RawOpenFaultPoint.AFTER_EXECUTABLE_PINNED,
                )
                return FourWayInputGuards(archive, lineageIndex, hostedReceipt, executable, parents.values.toList())
                    .also(FourWayInputGuards::requireCurrent)
            } catch (failure: Throwable) {
                files.asReversed().forEach { runCatching(it::close) }
                parents.values.toList().asReversed().forEach { runCatching(it::close) }
                throw failure
            }
        }
    }

    fun requireCurrent() {
        parents.forEach(PinnedFourWayParent::requireCurrent)
        files.forEach(PinnedFourWayFile::requireCurrent)
    }

    fun parent(path: Path): PinnedFourWayParent =
        parents.singleOrNull { it.path == path } ?: bindingFail("four-way source parent binding is missing")
}

private data class SnapshotSet(
    val root: Path,
    val archive: Path,
    val archiveBytes: Long,
    val archiveSha256: String,
    val lineageIndex: Path,
    val lineageIndexBytes: ByteArray,
    val hostedReceipt: Path,
    val hostedReceiptBytes: ByteArray,
    val executable: Path,
    val executableBytes: Long,
    val executableSha256: String,
)

private data class FourWaySourceDigests(
    val archiveSha256: String,
    val lineageIndexSha256: String,
    val hostedReceiptSha256: String,
    val executableSha256: String,
)

private fun normalizeFourWayPaths(
    archivePath: Path,
    lineageIndexPath: Path,
    hostedReceiptPath: Path,
    executablePath: Path,
): FourWayPaths {
    fun exact(path: Path, fixedName: String?, label: String): Path {
        if (path.fileSystem != FileSystems.getDefault() || !path.isAbsolute || path.normalize() != path ||
            path.fileName == null || path.parent == null || (fixedName != null && path.fileName.toString() != fixedName)
        ) {
            val suffix = fixedName?.let { " and use the fixed file name $it" }.orEmpty()
            bindingFail("$label path must be default-filesystem, exact, absolute, normalized, non-root$suffix")
        }
        return path
    }
    return FourWayPaths(
        exact(archivePath, null, "candidate reconstruction archive"),
        exact(lineageIndexPath, LINEAGE_INDEX_FILE_NAME, "candidate ACP lineage index"),
        exact(hostedReceiptPath, HOSTED_RECEIPT_FILE_NAME, "hosted clean-build receipt"),
        exact(executablePath, EXECUTABLE_FILE_NAME, "hosted candidate executable"),
    )
}

private fun requireRawLayout(paths: FourWayPaths, guards: FourWayInputGuards) {
    if (paths.hostedReceipt.parent != paths.executable.parent) {
        bindingFail("hosted receipt and executable must share one exact parent")
    }
    guards.files.indices.forEach { left ->
        for (right in left + 1 until guards.files.size) {
            if (guards.files[left].identity.key == guards.files[right].identity.key) {
                bindingFail("four-way candidate inputs must be four distinct inodes")
            }
        }
    }
    guards.parents.indices.forEach { left ->
        for (right in left + 1 until guards.parents.size) {
            if (guards.parents[left].identity.key == guards.parents[right].identity.key) {
                bindingFail("distinct four-way lexical parents must not alias")
            }
        }
    }
    val lineageEntries = guards.parent(paths.lineageIndex.parent).entryNames(2)
    if (lineageEntries != setOf(LINEAGE_INDEX_FILE_NAME)) {
        bindingFail("candidate ACP lineage index parent does not contain its exact reviewed file set")
    }
    val hostedEntries = guards.parent(paths.hostedReceipt.parent).entryNames(3)
    if (hostedEntries != setOf(HOSTED_RECEIPT_FILE_NAME, EXECUTABLE_FILE_NAME)) {
        bindingFail("hosted pair parent does not contain its exact reviewed file set")
    }
    guards.requireCurrent()
}

private fun snapshotAll(
    paths: FourWayPaths,
    guards: FourWayInputGuards,
    sourceDigests: FourWaySourceDigests,
): SnapshotSet {
    val root = Files.createTempDirectory("llvm-candidate-four-way-v2-").toAbsolutePath().normalize()
    try {
        Files.setPosixFilePermissions(root, OWNER_DIRECTORY_PERMISSIONS)
        if (root.toRealPath() != root) bindingFail("private four-way snapshot root contains a path alias")
        val archive = root.resolve("candidate-archive.zip")
        val indexParent = root.resolve("lineage")
        val hostedParent = root.resolve("hosted")
        Files.createDirectory(indexParent)
        Files.createDirectory(hostedParent)
        Files.setPosixFilePermissions(indexParent, OWNER_DIRECTORY_PERMISSIONS)
        Files.setPosixFilePermissions(hostedParent, OWNER_DIRECTORY_PERMISSIONS)
        val lineageIndex = indexParent.resolve(LINEAGE_INDEX_FILE_NAME)
        val hostedReceipt = hostedParent.resolve(HOSTED_RECEIPT_FILE_NAME)
        val executable = hostedParent.resolve(EXECUTABLE_FILE_NAME)

        requireCurrentSourceIdentities(paths, guards)
        val archiveSha256 = copyPinnedFile(
            guards.archive,
            archive,
            OWNER_READ_ONLY_PERMISSIONS,
            "candidate reconstruction archive",
        )
        if (archiveSha256 != sourceDigests.archiveSha256) {
            bindingFail("private archive snapshot differs from the initial four-way source set")
        }
        requireCurrentSourceIdentities(paths, guards)

        requireCurrentSourceIdentities(paths, guards)
        val lineageIndexBytes = copySmallPinnedFile(
            guards.lineageIndex,
            lineageIndex,
            OWNER_READ_ONLY_PERMISSIONS,
            "candidate ACP lineage index",
        )
        if (OracleArtifacts.sha256(lineageIndexBytes) != sourceDigests.lineageIndexSha256) {
            bindingFail("private lineage-index snapshot differs from the initial four-way source set")
        }
        requireCurrentSourceIdentities(paths, guards)

        requireCurrentSourceIdentities(paths, guards)
        val hostedReceiptBytes = copySmallPinnedFile(
            guards.hostedReceipt,
            hostedReceipt,
            OWNER_READ_ONLY_PERMISSIONS,
            "hosted clean-build receipt",
        )
        if (OracleArtifacts.sha256(hostedReceiptBytes) != sourceDigests.hostedReceiptSha256) {
            bindingFail("private hosted-receipt snapshot differs from the initial four-way source set")
        }
        requireCurrentSourceIdentities(paths, guards)

        requireCurrentSourceIdentities(paths, guards)
        val executableSha256 = copyPinnedFile(
            guards.executable,
            executable,
            OWNER_READ_EXECUTE_PERMISSIONS,
            "hosted candidate executable",
        )
        if (executableSha256 != sourceDigests.executableSha256) {
            bindingFail("private executable snapshot differs from the initial four-way source set")
        }
        requireCurrentSourceIdentities(paths, guards)
        return SnapshotSet(
            root,
            archive,
            guards.archive.size,
            archiveSha256,
            lineageIndex,
            lineageIndexBytes,
            hostedReceipt,
            hostedReceiptBytes,
            executable,
            guards.executable.size,
            executableSha256,
        )
    } catch (failure: Throwable) {
        deletePrivateSnapshotTree(root)
        throw failure
    }
}

private fun copySmallPinnedFile(
    source: PinnedFourWayFile,
    target: Path,
    permissions: Set<PosixFilePermission>,
    @Suppress("UNUSED_PARAMETER") label: String,
): ByteArray {
    val bytes = source.readBoundedJson()
    writePrivateSnapshot(target, bytes, permissions)
    return bytes
}

private fun copyPinnedFile(
    source: PinnedFourWayFile,
    target: Path,
    permissions: Set<PosixFilePermission>,
    @Suppress("UNUSED_PARAMETER") label: String,
): String {
    val digest = FileChannel.open(target, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { output ->
        val copiedSha256 = source.copyTo(Channels.newOutputStream(output))
        output.force(true)
        copiedSha256
    }
    Files.setPosixFilePermissions(target, permissions)
    requireSingleLink(target, "private $label snapshot")
    return digest
}

private fun writePrivateSnapshot(
    target: Path,
    bytes: ByteArray,
    permissions: Set<PosixFilePermission>,
) {
    FileChannel.open(target, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { channel ->
        val buffer = ByteBuffer.wrap(bytes)
        while (buffer.hasRemaining()) channel.write(buffer)
        channel.force(true)
    }
    Files.setPosixFilePermissions(target, permissions)
    requireSingleLink(target, "private four-way input snapshot")
}

private fun requireLineageResultMatchesSnapshots(
    lineage: LlvmBehaviorCandidateAcpLineageIndexV2,
    snapshots: SnapshotSet,
) {
    val indexSha256 = OracleArtifacts.sha256(snapshots.lineageIndexBytes)
    if (!lineage.candidateLineageBound || lineage.hostedBuildBound || lineage.admittedArtifactBound ||
        lineage.prepared || lineage.candidateStarted || lineage.scoringAuthority ||
        lineage.certificationAuthority || lineage.releaseEligible || lineage.schemaVersion != 2 ||
        lineage.archiveBytes != snapshots.archiveBytes || lineage.archiveSha256 != snapshots.archiveSha256 ||
        lineage.indexBytes != snapshots.lineageIndexBytes.size.toLong() || lineage.indexSha256 != indexSha256 ||
        lineage.acceptedAcpCount <= 0 ||
        lineage.acceptedAcpCount != lineage.reconstructionCount + lineage.repairCount
    ) {
        bindingFail("archive-derived ACP lineage result is outside the structural four-way boundary")
    }
}

private fun requireHostedResultMatchesSnapshots(
    hosted: LlvmBehaviorHostedCleanBuildV2PairVerification,
    snapshots: SnapshotSet,
) {
    if (hosted.schemaVersion != 2 || !hosted.exactExecutableBound || hosted.receiptFactsAuthenticated ||
        hosted.candidateLineageAuthenticated || hosted.buildExecutionAuthenticated ||
        hosted.runtimeClosureAuthenticated || hosted.hostedWorkflowAuthenticated ||
        hosted.admittedArtifactBound || hosted.candidateStarted || hosted.oracleAuthority ||
        hosted.referenceAuthoringAuthority || hosted.scoringAuthority || hosted.certificationAuthority ||
        hosted.releaseEligible || hosted.receiptBytes != snapshots.hostedReceiptBytes.size.toLong() ||
        hosted.receiptSha256 != OracleArtifacts.sha256(snapshots.hostedReceiptBytes) ||
        hosted.executableBytes != snapshots.executableBytes ||
        hosted.executableSha256 != snapshots.executableSha256 ||
        !MessageDigest.isEqual(hosted.canonicalReceiptBytes, snapshots.hostedReceiptBytes)
    ) {
        bindingFail("hosted pair result is outside the non-authoritative structural boundary")
    }
}

private fun parseVerifiedObject(bytes: ByteArray, limits: StrictJsonLimits, label: String): JsonObject {
    val parsed = try {
        OracleJson.parseCanonical(bytes, limits)
    } catch (failure: Exception) {
        bindingFail("$label lost strict canonical JSON identity", failure)
    }
    return parsed as? JsonObject ?: bindingFail("$label root must be an object")
}

private fun requireFourWayProjection(
    verified: LlvmBehaviorCandidateAcpLineageIndexV2,
    lineage: JsonObject,
    hosted: JsonObject,
) {
    val lineageArchive = lineage.requiredObject("archive", "candidate ACP lineage index")
    val lineageSource = lineage.requiredObject("source", "candidate ACP lineage index")
    val lineageAccepted = lineage.requiredObject("acceptedAcp", "candidate ACP lineage index")
    val hostedArchive = hosted.requiredObject("archive", "hosted receipt")
    val hostedLineage = hosted.requiredObject("candidateLineageIndex", "hosted receipt")
    val hostedAccepted = hostedLineage.requiredObject("acceptedAcp", "hosted receipt lineage index")
    val hostedSource = hosted.requiredObject("source", "hosted receipt")

    requireEqualLong(lineageArchive, "bytes", hostedArchive, "bytes", "archive bytes")
    requireEqualString(lineageArchive, "sha256", hostedArchive, "sha256", "archive digest")
    requireEqualLong(
        lineageArchive,
        "archiveManifestBytes",
        hostedArchive,
        "archiveManifestBytes",
        "archive manifest bytes",
    )
    requireEqualString(
        lineageArchive,
        "archiveManifestSha256",
        hostedArchive,
        "archiveManifestSha256",
        "archive manifest digest",
    )
    requireEqualLong(
        lineageArchive,
        "sourceTreeManifestBytes",
        hostedArchive,
        "sourceTreeManifestBytes",
        "source-tree manifest bytes",
    )
    requireEqualString(
        lineageArchive,
        "sourceTreeManifestSha256",
        hostedArchive,
        "sourceTreeManifestSha256",
        "source-tree manifest digest",
    )
    if (!hostedArchive.requiredBoolean("verified", "hosted receipt archive")) {
        bindingFail("hosted archive projection must acknowledge the independently verified archive")
    }

    if (hostedLineage.requiredLong("schemaVersion", "hosted receipt lineage index") != 2L ||
        hostedLineage.requiredLong("bytes", "hosted receipt lineage index") != verified.indexBytes ||
        hostedLineage.requiredString("sha256", "hosted receipt lineage index") != verified.indexSha256 ||
        hostedLineage.requiredString(
            "candidateSourceLineageSha256",
            "hosted receipt lineage index",
        ) != verified.candidateSourceLineageSha256
    ) {
        bindingFail("hosted receipt does not bind the exact independently verified ACP lineage index")
    }

    listOf("profileId", "profileSha256", "revisionAlgorithm", "revisionSha256").forEach { field ->
        requireEqualString(lineageSource, field, hostedSource, field, "source $field")
    }
    requireEqualLong(lineageSource, "inputCount", hostedSource, "inputCount", "source input count")

    listOf(
        "receiptSchemaVersion",
        "count",
        "reconstructionCount",
        "repairCount",
    ).forEach { field ->
        requireEqualLong(lineageAccepted, field, hostedAccepted, field, "accepted ACP $field")
    }
    listOf(
        "aggregateAlgorithm",
        "receiptSetSha256",
        "sessionSetSha256",
        "changeSetSha256",
        "lineageSetSha256",
    ).forEach { field ->
        requireEqualString(lineageAccepted, field, hostedAccepted, field, "accepted ACP $field")
    }

    val lineageAcpBoundary = lineage.requiredObject("acpBoundary", "candidate ACP lineage index")
    val hostedAcpBoundary = hosted.requiredObject("acpBoundary", "hosted receipt")
    if (lineageAcpBoundary != hostedAcpBoundary) {
        bindingFail("hosted receipt ACP boundary differs from the archive-derived first-class ACP boundary")
    }
    requireFirstClassZeroAuthorityAcpBoundary(lineageAcpBoundary)

    val lineageClaims = lineage.requiredObject("claims", "candidate ACP lineage index")
    val hostedClaims = hosted.requiredObject("claims", "hosted receipt")
    listOf(
        "candidateLineageBound",
        "admittedArtifactBound",
        "prepared",
        "liveContainmentVerified",
        "terminalAbsenceVerified",
        "observationsCaptured",
        "startAuthorized",
        "candidateStarted",
        "referenceTruthEstablished",
        "scoringAuthority",
        "certificationAuthority",
        "releaseEligible",
    ).forEach { field ->
        if (lineageClaims.requiredBoolean(field, "candidate ACP lineage claims") !=
            hostedClaims.requiredBoolean(field, "hosted receipt claims")
        ) {
            bindingFail("hosted receipt claim $field differs from the authenticated lineage boundary")
        }
    }
    if (lineageClaims.requiredBoolean("hostedBuildBound", "candidate ACP lineage claims") ||
        lineageClaims.requiredBoolean("runtimeIdentityVerified", "candidate ACP lineage claims") ||
        hostedClaims.requiredBoolean("liveRuntimeIdentityVerified", "hosted receipt claims") ||
        hostedClaims.requiredBoolean("runtimeClosureAuthenticated", "hosted receipt claims") ||
        hostedClaims.requiredBoolean("hostedWorkflowAuthenticated", "hosted receipt claims")
    ) {
        bindingFail("four-way checkpoint received an inconsistent structural claim boundary")
    }

    val archiveBytes = lineageArchive.requiredLong("bytes", "candidate ACP lineage archive")
    val archiveSha256 = lineageArchive.requiredDigest("sha256", "candidate ACP lineage archive")
    val sourceRevision = lineageSource.requiredDigest("revisionSha256", "candidate ACP lineage source")
    val sourceInputs = lineageSource.requiredBoundedInt("inputCount", "candidate ACP lineage source")
    val acceptedCount = lineageAccepted.requiredBoundedInt("count", "accepted ACP")
    val reconstructionCount = lineageAccepted.requiredBoundedInt("reconstructionCount", "accepted ACP")
    val repairCount = lineageAccepted.requiredBoundedInt("repairCount", "accepted ACP")
    if (archiveBytes != verified.archiveBytes || archiveSha256 != verified.archiveSha256 ||
        sourceRevision != verified.sourceRevisionSha256 || sourceInputs != verified.sourceInputCount ||
        acceptedCount != verified.acceptedAcpCount || reconstructionCount != verified.reconstructionCount ||
        repairCount != verified.repairCount || acceptedCount <= 0 ||
        acceptedCount != reconstructionCount + repairCount
    ) {
        bindingFail("canonical lineage projection differs from its archive-derived verification result")
    }

    lineageArchive.requiredLong("archiveManifestBytes", "candidate ACP lineage archive")
    lineageArchive.requiredDigest("archiveManifestSha256", "candidate ACP lineage archive")
    lineageArchive.requiredLong("sourceTreeManifestBytes", "candidate ACP lineage archive")
    lineageArchive.requiredDigest("sourceTreeManifestSha256", "candidate ACP lineage archive")
    lineageSource.requiredString("profileId", "candidate ACP lineage source")
    lineageSource.requiredDigest("profileSha256", "candidate ACP lineage source")
    val receiptSet = lineageAccepted.requiredDigest("receiptSetSha256", "accepted ACP")
    val sessionSet = lineageAccepted.requiredDigest("sessionSetSha256", "accepted ACP")
    val changeSet = lineageAccepted.requiredDigest("changeSetSha256", "accepted ACP")
    val lineageSet = lineageAccepted.requiredDigest("lineageSetSha256", "accepted ACP")
    val sourceLineage = lineage.requiredDigest(
        "candidateSourceLineageSha256",
        "candidate ACP lineage index",
    )
    if (receiptSet != verified.receiptSetSha256 ||
        sessionSet != verified.sessionSetSha256 ||
        changeSet != verified.changeSetSha256 ||
        lineageSet != verified.lineageSetSha256 ||
        sourceLineage != verified.candidateSourceLineageSha256
    ) {
        bindingFail("canonical ACP association commitments differ from the archive-derived result")
    }
}

private fun requireFirstClassZeroAuthorityAcpBoundary(boundary: JsonObject) {
    if (boundary.requiredString("role", "ACP boundary") != "first-class-candidate-producer-operator" ||
        boundary.requiredString("candidateContribution", "ACP boundary") !=
        "authenticated-session-change-provenance" ||
        boundary.requiredString("candidateProvenanceAccess", "ACP boundary") != "read-only-oracle-input" ||
        boundary.requiredString("candidateAdmissionOwner", "ACP boundary") != "kotlin-jvm-host" ||
        boundary.requiredString("candidateLiveExecutionOwner", "ACP boundary") !=
        "separately-reviewed-kotlin-jvm-host" ||
        boundary.requiredString("referenceSubjectAdmission", "ACP boundary") != "kotlin-jvm-host-only"
    ) {
        bindingFail("ACP is not the required first-class candidate producer/operator boundary")
    }
    listOf(
        "oracleAuthority",
        "referenceAuthoringAuthority",
        "policyAuthoringAuthority",
        "validationAuthority",
        "observationAuthoringAuthority",
        "startAuthority",
        "containmentAuthority",
        "terminalAbsenceAuthority",
        "scoringAuthority",
        "certificationAuthority",
        "releaseAuthority",
    ).forEach { field ->
        if (boundary.requiredBoolean(field, "ACP boundary")) {
            bindingFail("first-class ACP boundary must keep $field false")
        }
    }
}

private fun deriveCandidateStructuralIdentity(
    snapshots: SnapshotSet,
    lineageDocument: JsonObject,
    verified: LlvmBehaviorCandidateAcpLineageIndexV2,
): Pair<ByteArray, String> {
    val lineageArchive = lineageDocument.requiredObject("archive", "candidate ACP lineage index")
    val lineageSource = lineageDocument.requiredObject("source", "candidate ACP lineage index")
    val output = ByteArrayOutputStream()

    fun token(bytes: ByteArray) {
        output.write(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(bytes.size.toLong()).array())
        output.write(bytes)
    }
    fun stringField(name: String, value: String) {
        token(name.toByteArray(Charsets.UTF_8))
        token("utf8".toByteArray(Charsets.UTF_8))
        token(value.toByteArray(Charsets.UTF_8))
    }
    fun longField(name: String, value: Long) {
        token(name.toByteArray(Charsets.UTF_8))
        token("decimal-int64".toByteArray(Charsets.UTF_8))
        token(value.toString().toByteArray(Charsets.UTF_8))
    }
    fun bytesField(name: String, value: ByteArray) {
        token(name.toByteArray(Charsets.UTF_8))
        token("bytes".toByteArray(Charsets.UTF_8))
        token(value)
    }

    run {
        token("decomp-engine-candidate-four-way-binding-v2".toByteArray(Charsets.UTF_8))
        token("candidate-structural-identity-v2".toByteArray(Charsets.UTF_8))
    }
    longField("schemaVersion", 2L)
    stringField("verificationKind", FOUR_WAY_BINDING_KIND)
    longField("archive.bytes", snapshots.archiveBytes)
    stringField("archive.sha256", snapshots.archiveSha256)
    longField(
        "archive.archiveManifestBytes",
        lineageArchive.requiredLong("archiveManifestBytes", "candidate ACP lineage archive"),
    )
    stringField(
        "archive.archiveManifestSha256",
        lineageArchive.requiredDigest("archiveManifestSha256", "candidate ACP lineage archive"),
    )
    longField(
        "archive.sourceTreeManifestBytes",
        lineageArchive.requiredLong("sourceTreeManifestBytes", "candidate ACP lineage archive"),
    )
    stringField(
        "archive.sourceTreeManifestSha256",
        lineageArchive.requiredDigest("sourceTreeManifestSha256", "candidate ACP lineage archive"),
    )
    longField("lineageIndex.bytes", snapshots.lineageIndexBytes.size.toLong())
    stringField("lineageIndex.sha256", OracleArtifacts.sha256(snapshots.lineageIndexBytes))
    bytesField("lineageIndex.canonicalBytes", snapshots.lineageIndexBytes)
    stringField("source.profileId", lineageSource.requiredString("profileId", "candidate ACP lineage source"))
    stringField(
        "source.profileSha256",
        lineageSource.requiredDigest("profileSha256", "candidate ACP lineage source"),
    )
    longField("source.inputCount", verified.sourceInputCount.toLong())
    stringField("source.revisionSha256", verified.sourceRevisionSha256)
    longField("acceptedAcp.count", verified.acceptedAcpCount.toLong())
    longField("acceptedAcp.reconstructionCount", verified.reconstructionCount.toLong())
    longField("acceptedAcp.repairCount", verified.repairCount.toLong())
    stringField("acceptedAcp.receiptSetSha256", verified.receiptSetSha256)
    stringField("acceptedAcp.sessionSetSha256", verified.sessionSetSha256)
    stringField("acceptedAcp.changeSetSha256", verified.changeSetSha256)
    stringField("acceptedAcp.lineageSetSha256", verified.lineageSetSha256)
    stringField("candidateSourceLineageSha256", verified.candidateSourceLineageSha256)
    longField("hostedReceipt.bytes", snapshots.hostedReceiptBytes.size.toLong())
    stringField("hostedReceipt.sha256", OracleArtifacts.sha256(snapshots.hostedReceiptBytes))
    bytesField("hostedReceipt.canonicalBytes", snapshots.hostedReceiptBytes)
    stringField("executable.name", EXECUTABLE_FILE_NAME)
    longField("executable.bytes", snapshots.executableBytes)
    stringField("executable.sha256", snapshots.executableSha256)
    val bytes = output.toByteArray()
    return bytes to OracleArtifacts.sha256(bytes)
}

private fun captureSourceDigests(
    paths: FourWayPaths,
    guards: FourWayInputGuards,
): FourWaySourceDigests {
    requireCurrentSourceIdentities(paths, guards)
    val captured = FourWaySourceDigests(
        guards.archive.sha256(),
        guards.lineageIndex.sha256(),
        guards.hostedReceipt.sha256(),
        guards.executable.sha256(),
    )
    // A second complete pass makes the baseline a stable four-file set rather than four unrelated
    // observations sampled across a sequential hashing interval.
    requireCurrentSources(paths, guards, captured)
    return captured
}

private fun requireCurrentSources(
    paths: FourWayPaths,
    guards: FourWayInputGuards,
    digests: FourWaySourceDigests,
) {
    val expected = listOf(
        Triple(guards.archive, digests.archiveSha256, "candidate reconstruction archive"),
        Triple(guards.lineageIndex, digests.lineageIndexSha256, "candidate ACP lineage index"),
        Triple(guards.hostedReceipt, digests.hostedReceiptSha256, "hosted clean-build receipt"),
        Triple(guards.executable, digests.executableSha256, "hosted candidate executable"),
    )
    expected.forEach { (guard, sha256, label) ->
        if (guard.sha256() != sha256) {
            bindingFail("$label changed relative to the initial four-way source set")
        }
    }
    requireCurrentSourceIdentities(paths, guards)
}

private fun requireCurrentSourceIdentities(paths: FourWayPaths, guards: FourWayInputGuards) {
    guards.requireCurrent()
    requireRawLayout(paths, guards)
}

private fun requireTrustedParentIdentity(
    identity: LinuxFileIdentity,
    exactOwnerDirectoryMode: Boolean,
) {
    if (!identity.isDirectory || identity.isRegularFile || identity.isSymbolicLink ||
        identity.uid != currentUid() ||
        if (exactOwnerDirectoryMode) {
            identity.mode.permissions != OWNER_DIRECTORY_MODE
        } else {
            identity.mode.permissions and UNTRUSTED_WRITE_MODE != 0
        }
    ) {
        bindingFail("four-way source parent is not an authenticated owner-controlled directory")
    }
}

private fun requireTrustedFileIdentity(
    identity: LinuxFileIdentity,
    parentIdentity: LinuxFileIdentity,
    exactMode: Int?,
    label: String,
) {
    if (!identity.isRegularFile || identity.isDirectory || identity.isSymbolicLink ||
        identity.linkCount != 1 || identity.uid != parentIdentity.uid ||
        identity.mountId != parentIdentity.mountId ||
        if (exactMode != null) {
            identity.mode.permissions != exactMode
        } else {
            identity.mode.permissions and UNTRUSTED_WRITE_MODE != 0
        }
    ) {
        bindingFail("$label is not an authenticated single-link regular file")
    }
}

private fun samePinnedDirectory(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
    left.key == right.key && left.mountId == right.mountId && left.mode == right.mode &&
        left.uid == right.uid && left.gid == right.gid && left.linkCount == right.linkCount &&
        left.isDirectory && right.isDirectory && !left.isRegularFile && !right.isRegularFile &&
        !left.isSymbolicLink && !right.isSymbolicLink

private fun samePinnedRegularFile(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
    left.key == right.key && left.mountId == right.mountId && left.mode == right.mode &&
        left.uid == right.uid && left.gid == right.gid && left.linkCount == right.linkCount &&
        left.isRegularFile && right.isRegularFile && !left.isDirectory && !right.isDirectory &&
        !left.isSymbolicLink && !right.isSymbolicLink

private fun currentUid(): Int =
    (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()

private fun requireSingleLink(path: Path, label: String) {
    val links = try {
        (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toLong()
    } catch (failure: Exception) {
        bindingFail("$label link identity is unavailable", failure)
    }
    if (links != 1L) bindingFail("$label must not be hard-linked")
}

private fun deletePrivateSnapshotTree(root: Path) {
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
    Files.walk(root).use { paths ->
        paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
    }
}

private fun requireEqualLong(
    left: JsonObject,
    leftField: String,
    right: JsonObject,
    rightField: String,
    label: String,
) {
    if (left.requiredLong(leftField, label) != right.requiredLong(rightField, label)) {
        bindingFail("hosted receipt $label differs from the authenticated lineage")
    }
}

private fun requireEqualString(
    left: JsonObject,
    leftField: String,
    right: JsonObject,
    rightField: String,
    label: String,
) {
    if (left.requiredString(leftField, label) != right.requiredString(rightField, label)) {
        bindingFail("hosted receipt $label differs from the authenticated lineage")
    }
}

private fun JsonObject.requiredObject(name: String, label: String): JsonObject =
    this[name] as? JsonObject ?: bindingFail("$label.$name must be an object")

private fun JsonObject.requiredString(name: String, label: String): String {
    val primitive = this[name] as? JsonPrimitive ?: bindingFail("$label.$name must be a string")
    if (!primitive.isString) bindingFail("$label.$name must be a string")
    return primitive.content
}

private fun JsonObject.requiredLong(name: String, label: String): Long {
    val primitive = this[name] as? JsonPrimitive ?: bindingFail("$label.$name must be an integer")
    return primitive.longOrNull ?: bindingFail("$label.$name must be an integer")
}

private fun JsonObject.requiredBoundedInt(name: String, label: String): Int {
    val value = requiredLong(name, label)
    if (value !in 0L..Int.MAX_VALUE.toLong()) bindingFail("$label.$name exceeds the supported bound")
    return value.toInt()
}

private fun JsonObject.requiredBoolean(name: String, label: String): Boolean {
    val primitive = this[name] as? JsonPrimitive ?: bindingFail("$label.$name must be a boolean")
    return primitive.booleanOrNull ?: bindingFail("$label.$name must be a boolean")
}

private fun JsonObject.requiredDigest(name: String, label: String): String =
    requiredString(name, label).also { value ->
        if (!value.matches(SHA256)) bindingFail("$label.$name must be a lowercase SHA-256 digest")
    }

private inline fun <T> translateBindingFailure(action: () -> T): T = try {
    action()
} catch (failure: LlvmBehaviorCandidateFourWayBindingV2Exception) {
    throw failure
} catch (failure: Exception) {
    throw LlvmBehaviorCandidateFourWayBindingV2Exception(
        "candidate four-way structural verification failed: ${failure.message ?: failure.javaClass.simpleName}",
        failure,
    )
}

private fun bindingFail(message: String, cause: Throwable? = null): Nothing =
    throw LlvmBehaviorCandidateFourWayBindingV2Exception(message, cause)

private fun ByteArray.hex(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private const val FOUR_WAY_BINDING_KIND = "kotlin-jvm-candidate-four-way-structural-binding-v2"
private const val LINEAGE_INDEX_FILE_NAME = "candidate-acp-lineage-index-v2.json"
private const val HOSTED_RECEIPT_FILE_NAME = "candidate-hosted-clean-build-v2.json"
private const val EXECUTABLE_FILE_NAME = "candidate-reconstructed"
private const val MAXIMUM_LINEAGE_INDEX_BYTES = 64L * 1024L
private const val MAXIMUM_HOSTED_RECEIPT_BYTES = 128L * 1024L
private const val MAXIMUM_EXECUTABLE_BYTES = 64L * 1024L * 1024L
private const val OWNER_DIRECTORY_MODE = 0x1c0 // 0700
private const val OWNER_READ_ONLY_MODE = 0x100 // 0400
private const val OWNER_READ_EXECUTE_MODE = 0x140 // 0500
private const val UNTRUSTED_WRITE_MODE = 0x12 // group-write or other-write
private val SHA256 = Regex("[0-9a-f]{64}")
private val OWNER_DIRECTORY_PERMISSIONS = setOf(
    PosixFilePermission.OWNER_READ,
    PosixFilePermission.OWNER_WRITE,
    PosixFilePermission.OWNER_EXECUTE,
)
private val OWNER_READ_ONLY_PERMISSIONS = setOf(PosixFilePermission.OWNER_READ)
private val OWNER_READ_EXECUTE_PERMISSIONS = setOf(
    PosixFilePermission.OWNER_READ,
    PosixFilePermission.OWNER_EXECUTE,
)
private val LINEAGE_INDEX_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_LINEAGE_INDEX_BYTES.toInt(),
    maximumCanonicalBytes = MAXIMUM_LINEAGE_INDEX_BYTES.toInt(),
    maximumDepth = 16,
    maximumNodes = 512,
    maximumStringBytes = 4096,
    maximumTotalStringBytes = 32 * 1024,
)
private val HOSTED_RECEIPT_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_HOSTED_RECEIPT_BYTES.toInt(),
    maximumCanonicalBytes = MAXIMUM_HOSTED_RECEIPT_BYTES.toInt(),
    maximumDepth = 20,
    maximumNodes = 1024,
    maximumStringBytes = 4096,
    maximumTotalStringBytes = 64 * 1024,
)
