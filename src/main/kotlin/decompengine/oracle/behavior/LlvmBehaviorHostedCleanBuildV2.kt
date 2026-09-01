package decompengine.oracle.behavior

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.provenance.BoundedElfTwinV1
import decompengine.oracle.provenance.BoundedElfTwinV1Limits
import decompengine.oracle.provenance.LlvmBuildEnvironmentVerification
import decompengine.oracle.provenance.LlvmBuildEnvironmentVerifier
import decompengine.oracle.provenance.LlvmBuildToolV1
import decompengine.oracle.provenance.LlvmToolchainReproductionVerification
import decompengine.oracle.provenance.LlvmToolchainReproductionVerifier
import decompengine.project.ArchivalBundleVerifier
import decompengine.project.BuildSourceInput
import decompengine.project.BuildSourceRevision
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.VerifiedCandidateArchiveLineage
import decompengine.project.captureBuildSourceRevision
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.time.Duration
import java.util.Comparator
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class LlvmBehaviorHostedCleanBuildV2Exception(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * Result of checking one immutable unsigned worker-receipt/executable pair.
 *
 * The receipt has the reviewed canonical shape, a limited set of repeated fields agree, and its
 * candidate identity binds the exact executable bytes. Archive, lineage-index, runtime, and build
 * facts remain opaque receipt claims. This value does not prove that either recorded build ran,
 * authenticate the candidate archive, container, or workflow, admit or execute the candidate, or
 * grant oracle/reference, scoring, certification, or release authority.
 */
sealed interface LlvmBehaviorHostedCleanBuildV2PairVerification {
    val schemaVersion: Int
    val executableBytes: Long
    val executableSha256: String
    val receiptBytes: Long
    val receiptSha256: String
    val schemaSha256: String
    val canonicalReceiptBytes: ByteArray
    val exactExecutableBound: Boolean
    val receiptFactsAuthenticated: Boolean
    val candidateLineageAuthenticated: Boolean
    val buildExecutionAuthenticated: Boolean
    val runtimeClosureAuthenticated: Boolean
    val hostedWorkflowAuthenticated: Boolean
    val admittedArtifactBound: Boolean
    val candidateStarted: Boolean
    val oracleAuthority: Boolean
    val referenceAuthoringAuthority: Boolean
    val scoringAuthority: Boolean
    val certificationAuthority: Boolean
    val releaseEligible: Boolean
}

/**
 * Fixed-path inner worker for the future Kotlin-owned container coordinator.
 *
 * It is deliberately internal and has no general CLI: dependency authentication occurs after
 * Clang reads a file, so invoking this worker outside its secret-free fixed-mount container would
 * be unsafe. The future outer coordinator is the only component allowed to launch it.
 */
internal object LlvmBehaviorHostedCleanBuildV2InnerWorker {
    fun produce(): LlvmBehaviorHostedCleanBuildV2PairVerification = translateHostedFailure {
        val paths = normalizeHostedPaths()
        requireDedicatedWorkDirectory()
        requireDedicatedOutputDirectory(paths)
        requireDistinctHostedPaths(paths)

        val guards = HostedInputGuards.open(paths)
        try {
            val fixedInputs = authenticateFixedInputs(paths, guards)
            val lineageIndex = LlvmBehaviorCandidateAcpLineageIndexV2Verifier.verify(
                paths.archive,
                paths.lineageIndex,
            )
            requireLineageIndexGuards(lineageIndex, guards)
            val reproduction = LlvmToolchainReproductionVerifier().verify(
                paths.reproductionLock,
                paths.buildRecord,
                paths.dockerInspect,
            )
            requireExactReproduction(reproduction, fixedInputs)
            val buildEnvironment = LlvmBuildEnvironmentVerifier.verify(
                paths.sourceLock,
                paths.buildRecord,
                reproduction.recordedOriginImageDigest,
            )
            val tools = requireExactBuildEnvironment(buildEnvironment, reproduction, fixedInputs)

            StableControlFile.open(
                tools.compiler.path,
                MAXIMUM_TOOL_BYTES,
                "authenticated hosted compiler",
            ).use { compilerGuard ->
                StableControlFile.open(
                    tools.linker.path,
                    MAXIMUM_TOOL_BYTES,
                    "authenticated hosted linker",
                ).use { linkerGuard ->
                    requireToolGuard(tools.compiler, compilerGuard, "compiler")
                    requireToolGuard(tools.linker, linkerGuard, "linker")
                    val derived = deriveTwoCleanBuilds(
                        guards.archive,
                        lineageIndex,
                        tools,
                        compilerGuard,
                        linkerGuard,
                        reproduction.sourceDateEpoch,
                    )
                    requireToolGuard(tools.compiler, compilerGuard, "compiler")
                    requireToolGuard(tools.linker, linkerGuard, "linker")
                    requireTerminalInputs(guards, fixedInputs, lineageIndex)

                    val rendered = renderHostedReceipt(
                        lineageIndex,
                        derived.lineage,
                        reproduction,
                        tools,
                        derived.builds,
                        derived.executableBytes,
                    )
                    publishHostedPair(paths, derived.executableBytes, rendered.bytes)
                    return@translateHostedFailure LlvmBehaviorHostedCleanBuildV2Verifier.verify(
                        paths.receipt,
                        paths.executable,
                    )
                }
            }
        } finally {
            guards.close()
        }
    }
}

/** Non-authoritative local seam for exercising only the fixed direct-build mechanism. */
internal object LlvmBehaviorHostedCleanBuildV2TestSupport {
    /** Syntax-only seam which authenticates no path, receipt, runtime, or build fact. */
    fun requireNoLegacyEvidenceText(value: String) =
        translateHostedFailure { rejectLegacyHostedText(value, "hosted evidence syntax") }

    fun parseLinkDependencyManifest(bytes: ByteArray, expectedTarget: Path): List<String> =
        translateHostedFailure { parseLldLinkDependencyManifest(bytes, expectedTarget.toAbsolutePath().normalize()) }

    fun assess(
        firstSourceRoot: Path,
        secondSourceRoot: Path,
        compilerPath: Path,
        linkerPath: Path,
    ): LlvmBehaviorHostedCleanBuildV2Assessment = translateHostedFailure {
        val firstRoot = requireExactTestDirectory(firstSourceRoot, "first test source root")
        val secondRoot = requireExactTestDirectory(secondSourceRoot, "second test source root")
        val compiler = requireExactHostedPath(compilerPath, "test compiler")
        val linker = requireExactHostedPath(linkerPath, "test linker")
        val firstRevision = captureBuildSourceRevision(firstRoot)
        val secondRevision = captureBuildSourceRevision(secondRoot)
        if (firstRevision != secondRevision) hostedFail("test source roots do not have the same source revision")
        StableControlFile.open(compiler, MAXIMUM_TOOL_BYTES, "test compiler").use { compilerGuard ->
            StableControlFile.open(linker, MAXIMUM_TOOL_BYTES, "test linker").use { linkerGuard ->
                val tools = HostedTools(
                    HostedTool(
                        "compiler",
                        compiler,
                        compilerGuard.size,
                        compilerGuard.sha256(label = "test compiler"),
                        ZERO_SHA256,
                    ),
                    HostedTool(
                        "linker",
                        linker,
                        linkerGuard.size,
                        linkerGuard.sha256(label = "test linker"),
                        ZERO_SHA256,
                    ),
                )
                val scratch = Files.createTempDirectory("hosted-build-test-support-").toAbsolutePath().normalize()
                try {
                    Files.setPosixFilePermissions(scratch, OWNER_DIRECTORY_PERMISSIONS)
                    val first = runCleanBuild(
                        1,
                        firstRoot,
                        scratch.resolve("build-1"),
                        firstRevision,
                        tools,
                        compilerGuard,
                        linkerGuard,
                        EXPECTED_SOURCE_DATE_EPOCH,
                    )
                    val second = runCleanBuild(
                        2,
                        secondRoot,
                        scratch.resolve("build-2"),
                        secondRevision,
                        tools,
                        compilerGuard,
                        linkerGuard,
                        EXPECTED_SOURCE_DATE_EPOCH,
                    )
                    if (!MessageDigest.isEqual(first.executable, second.executable)) {
                        hostedFail("test clean builds produced different executable bytes")
                    }
                    LlvmBehaviorHostedCleanBuildV2Assessment(first.facts, second.facts, first.executable)
                } finally {
                    deleteScratchTree(scratch)
                }
            }
        }
    }
}

internal class LlvmBehaviorHostedCleanBuildV2Assessment private constructor(
    first: HostedBuildFacts,
    second: HostedBuildFacts,
    executable: ByteArray,
) {
    private val storedExecutable = executable.copyOf()
    val sourceRevisionSha256: String = first.sourceRevisionSha256
    val sourceCount: Int = first.sourceCount
    val firstBuildEnvironmentSha256: String = first.buildEnvironmentSha256
    val secondBuildEnvironmentSha256: String = second.buildEnvironmentSha256
    val firstCompileCommandSetSha256: String = first.compileCommandSetSha256
    val secondCompileCommandSetSha256: String = second.compileCommandSetSha256
    val dependencyCount: Int = first.dependencyCount
    val firstDependencySetSha256: String = first.dependencySetSha256
    val secondDependencySetSha256: String = second.dependencySetSha256
    val firstObjectSetSha256: String = first.objectSetSha256
    val secondObjectSetSha256: String = second.objectSetSha256
    val firstLinkCommandSha256: String = first.linkCommandSha256
    val secondLinkCommandSha256: String = second.linkCommandSha256
    val linkDependencyCount: Int = first.linkDependencyCount
    val firstLinkDependencySetSha256: String = first.linkDependencySetSha256
    val secondLinkDependencySetSha256: String = second.linkDependencySetSha256
    val firstCombinedOutputBytes: Long = first.combinedOutputBytes
    val secondCombinedOutputBytes: Long = second.combinedOutputBytes
    val firstCombinedOutputSha256: String = first.combinedOutputSha256
    val secondCombinedOutputSha256: String = second.combinedOutputSha256
    val executableBytes: Long = first.executableBytes
    val executableSha256: String = first.executableSha256
    val executable: ByteArray
        get() = storedExecutable.copyOf()

    init {
        require(first.ordinal == 1 && second.ordinal == 2)
        require(first.sourceRevisionSha256 == second.sourceRevisionSha256)
        require(first.sourceCount == second.sourceCount)
        require(first.buildEnvironmentSha256 == second.buildEnvironmentSha256)
        require(first.compileCommandSetSha256 == second.compileCommandSetSha256)
        require(first.dependencyCount == second.dependencyCount)
        require(first.dependencySetSha256 == second.dependencySetSha256)
        require(first.objectSetSha256 == second.objectSetSha256)
        require(first.linkCommandSha256 == second.linkCommandSha256)
        require(first.linkDependencyCount == second.linkDependencyCount)
        require(first.linkDependencySetSha256 == second.linkDependencySetSha256)
        require(first.combinedOutputBytes == second.combinedOutputBytes)
        require(first.combinedOutputSha256 == second.combinedOutputSha256)
        require(first.executableBytes == second.executableBytes)
        require(first.executableSha256 == second.executableSha256)
        require(storedExecutable.size.toLong() == executableBytes)
        require(OracleArtifacts.sha256(storedExecutable) == executableSha256)
    }

    companion object {
        internal operator fun invoke(
            first: HostedBuildFacts,
            second: HostedBuildFacts,
            executable: ByteArray,
        ): LlvmBehaviorHostedCleanBuildV2Assessment =
            LlvmBehaviorHostedCleanBuildV2Assessment(first, second, executable)
    }
}

private data class HostedPaths(
    val archive: Path,
    val lineageIndex: Path,
    val sourceLock: Path,
    val buildRecord: Path,
    val reproductionLock: Path,
    val dockerInspect: Path,
    val outputDirectory: Path,
) {
    val executable: Path = outputDirectory.resolve(EXECUTABLE_FILE_NAME)
    val receipt: Path = outputDirectory.resolve(RECEIPT_FILE_NAME)
}

private class HostedInputGuards private constructor(
    val archive: StableControlFile,
    val lineageIndex: StableControlFile,
    val sourceLock: StableControlFile,
    val buildRecord: StableControlFile,
    val reproductionLock: StableControlFile,
    val dockerInspect: StableControlFile,
) : AutoCloseable {
    override fun close() {
        listOf(dockerInspect, reproductionLock, buildRecord, sourceLock, lineageIndex, archive)
            .forEach { runCatching(it::close) }
    }

    companion object {
        fun open(paths: HostedPaths): HostedInputGuards {
            val opened = ArrayList<StableControlFile>()
            fun open(path: Path, maximumBytes: Long, label: String): StableControlFile =
                StableControlFile.open(path, maximumBytes, label).also(opened::add)
            try {
                return HostedInputGuards(
                    open(
                        paths.archive,
                        LLVM_BEHAVIOR_CANDIDATE_ACP_LINEAGE_MAXIMUM_ARCHIVE_BYTES,
                        "candidate reconstruction archive",
                    ),
                    open(paths.lineageIndex, MAXIMUM_LINEAGE_INDEX_BYTES, "candidate ACP lineage index"),
                    open(paths.sourceLock, MAXIMUM_SOURCE_LOCK_BYTES, "LLVM source lock"),
                    open(paths.buildRecord, MAXIMUM_BUILD_RECORD_BYTES, "LLVM build record"),
                    open(paths.reproductionLock, MAXIMUM_REPRODUCTION_LOCK_BYTES, "LLVM reproduction lock"),
                    open(paths.dockerInspect, MAXIMUM_DOCKER_INSPECT_BYTES, "Docker inspect artifact"),
                )
            } catch (failure: Throwable) {
                opened.asReversed().forEach { runCatching(it::close) }
                throw failure
            }
        }
    }
}

private data class FixedHostedInputs(
    val sourceLockSha256: String,
    val buildRecordSha256: String,
    val reproductionLockSha256: String,
    val lineageIndexSha256: String,
    val dockerInspectSha256: String,
)

private data class HostedTools(
    val compiler: HostedTool,
    val linker: HostedTool,
)

private data class HostedTool(
    val role: String,
    val path: Path,
    val bytes: Long,
    val sha256: String,
    val versionOutputSha256: String,
)

internal data class HostedBuildFacts(
    val ordinal: Int,
    val sourceRevisionSha256: String,
    val sourceCount: Int,
    val buildEnvironmentSha256: String,
    val compileCommandSetSha256: String,
    val dependencyCount: Int,
    val dependencySetSha256: String,
    val objectSetSha256: String,
    val linkCommandSha256: String,
    val linkDependencyCount: Int,
    val linkDependencySetSha256: String,
    val combinedOutputBytes: Long,
    val combinedOutputSha256: String,
    val executableBytes: Long,
    val executableSha256: String,
)

private data class CompletedCleanBuild(
    val facts: HostedBuildFacts,
    val executable: ByteArray,
)

private data class DerivedHostedBuilds(
    val lineage: VerifiedCandidateArchiveLineage,
    val builds: List<HostedBuildFacts>,
    val executableBytes: ByteArray,
    val executableSha256: String,
)

private data class RenderedHostedReceipt(val bytes: ByteArray)

private fun normalizeHostedPaths(): HostedPaths {
    val paths = HostedPaths(
        requireExactHostedPath(FIXED_ARCHIVE_PATH, "candidate reconstruction archive"),
        requireExactHostedPath(FIXED_LINEAGE_INDEX_PATH, "candidate ACP lineage index"),
        requireExactHostedPath(FIXED_SOURCE_LOCK_PATH, "LLVM source lock"),
        requireExactHostedPath(FIXED_BUILD_RECORD_PATH, "LLVM build record"),
        requireExactHostedPath(FIXED_REPRODUCTION_LOCK_PATH, "LLVM reproduction lock"),
        requireExactHostedPath(FIXED_DOCKER_INSPECT_PATH, "Docker inspect artifact"),
        requireExactHostedPath(FIXED_OUTPUT_DIRECTORY, "hosted build output directory", directory = true),
    )
    requireFixedName(paths.lineageIndex, LINEAGE_INDEX_FILE_NAME, "candidate ACP lineage index")
    requireFixedName(paths.sourceLock, SOURCE_LOCK_FILE_NAME, "LLVM source lock")
    requireFixedName(paths.buildRecord, BUILD_RECORD_FILE_NAME, "LLVM build record")
    requireFixedName(paths.reproductionLock, REPRODUCTION_LOCK_FILE_NAME, "LLVM reproduction lock")
    listOf(
        paths.archive,
        paths.lineageIndex,
        paths.sourceLock,
        paths.buildRecord,
        paths.reproductionLock,
        paths.dockerInspect,
        paths.outputDirectory,
    ).forEach { rejectLegacyHostedText(it.toString(), "hosted build path") }
    return paths
}

private fun requireExactHostedPath(path: Path, label: String, directory: Boolean = false): Path {
    if (!path.isAbsolute || path.normalize() != path || path.fileName == null || path.parent == null) {
        hostedFail("$label path must be exact, absolute, normalized, and non-root")
    }
    if (!directory && !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
        hostedFail("$label must be an existing regular file")
    }
    if (Files.isSymbolicLink(path)) hostedFail("$label must not be a symbolic link")
    return path
}

private fun requireExactTestDirectory(path: Path, label: String): Path {
    val normalized = requireExactHostedPath(path, label, directory = true)
    val attributes = readBasicAttributes(normalized, label)
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null ||
        normalized.toRealPath() != normalized
    ) {
        hostedFail("$label must be an identified real directory")
    }
    return normalized
}

private fun requireFixedName(path: Path, expected: String, label: String) {
    if (path.fileName.toString() != expected) hostedFail("$label must use the fixed file name $expected")
}

private fun requireDedicatedOutputDirectory(paths: HostedPaths) {
    val directory = paths.outputDirectory
    val attributes = readBasicAttributes(directory, "hosted build output directory")
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null ||
        directory.toRealPath() != directory
    ) {
        hostedFail("hosted build output directory must be an identified real directory")
    }
    if (Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS) != OWNER_DIRECTORY_PERMISSIONS) {
        hostedFail("hosted build output directory must be dedicated mode 0700")
    }
    val allowed = setOf(
        RECEIPT_FILE_NAME,
        EXECUTABLE_FILE_NAME,
        DescriptorBoundAtomicStateFile.temporaryName(RECEIPT_FILE_NAME),
        DescriptorBoundAtomicStateFile.temporaryName(EXECUTABLE_FILE_NAME),
    )
    val entries = Files.newDirectoryStream(directory).use { stream ->
        val bounded = ArrayList<String>(allowed.size)
        val iterator = stream.iterator()
        while (iterator.hasNext()) {
            if (bounded.size >= allowed.size) hostedFail("hosted build output directory exceeds its entry bound")
            bounded.add(iterator.next().fileName.toString())
        }
        bounded
    }
    if (entries.any { it !in allowed } || entries.size > allowed.size) {
        hostedFail("hosted build output directory contains unrelated state")
    }
}

private fun requireDedicatedWorkDirectory() {
    val attributes = readBasicAttributes(FIXED_WORK_DIRECTORY, "hosted inner-worker scratch directory")
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null ||
        FIXED_WORK_DIRECTORY.toRealPath() != FIXED_WORK_DIRECTORY ||
        Files.getPosixFilePermissions(FIXED_WORK_DIRECTORY, LinkOption.NOFOLLOW_LINKS) != OWNER_DIRECTORY_PERMISSIONS
    ) {
        hostedFail("hosted inner-worker scratch directory must be an identified empty mode-0700 mount")
    }
    if (Files.newDirectoryStream(FIXED_WORK_DIRECTORY).use { it.iterator().hasNext() }) {
        hostedFail("hosted inner-worker scratch directory contains prior state")
    }
}

private fun requireDistinctHostedPaths(paths: HostedPaths) {
    val inputs = listOf(
        "archive" to paths.archive,
        "lineage index" to paths.lineageIndex,
        "source lock" to paths.sourceLock,
        "build record" to paths.buildRecord,
        "reproduction lock" to paths.reproductionLock,
        "Docker inspect artifact" to paths.dockerInspect,
    )
    inputs.forEach { (label, path) -> requireSingleLink(path, label) }
    inputs.indices.forEach { left ->
        for (right in left + 1 until inputs.size) {
            if (inputs[left].second == inputs[right].second || Files.isSameFile(inputs[left].second, inputs[right].second)) {
                hostedFail("hosted build inputs ${inputs[left].first} and ${inputs[right].first} alias")
            }
        }
    }
    inputs.forEach { (label, input) ->
        if (input.parent == paths.outputDirectory || sameExistingFile(input, paths.executable) ||
            sameExistingFile(input, paths.receipt)
        ) {
            hostedFail("$label aliases the dedicated hosted output boundary")
        }
    }
}

private fun authenticateFixedInputs(paths: HostedPaths, guards: HostedInputGuards): FixedHostedInputs {
    val source = guards.sourceLock.sha256(label = "LLVM source lock")
    val record = guards.buildRecord.sha256(label = "LLVM build record")
    val reproduction = guards.reproductionLock.sha256(label = "LLVM reproduction lock")
    val lineage = guards.lineageIndex.sha256(label = "candidate ACP lineage index")
    val inspect = guards.dockerInspect.sha256(label = "Docker inspect artifact")
    requireFixedDigest(source, EXPECTED_SOURCE_LOCK_SHA256, "LLVM source lock")
    requireFixedDigest(record, EXPECTED_BUILD_RECORD_SHA256, "LLVM build record")
    requireFixedDigest(reproduction, EXPECTED_REPRODUCTION_LOCK_SHA256, "LLVM reproduction lock")
    return FixedHostedInputs(source, record, reproduction, lineage, inspect)
}

private fun requireLineageIndexGuards(
    index: LlvmBehaviorCandidateAcpLineageIndexV2,
    guards: HostedInputGuards,
) {
    if (!index.candidateLineageBound || index.hostedBuildBound || index.acceptedAcpCount <= 0 ||
        index.acceptedAcpCount != index.reconstructionCount + index.repairCount ||
        index.indexBytes != guards.lineageIndex.size || index.indexSha256 != guards.lineageIndex.sha256(
            label = "candidate ACP lineage index",
        )
    ) {
        hostedFail("candidate ACP lineage index does not expose the exact pre-build lineage boundary")
    }
}

private fun requireExactReproduction(
    value: LlvmToolchainReproductionVerification,
    fixed: FixedHostedInputs,
) {
    if (value.lockSha256 != fixed.reproductionLockSha256 ||
        value.dockerfileSha256 != EXPECTED_DOCKERFILE_SHA256 ||
        value.buildRecordSha256 != fixed.buildRecordSha256 ||
        value.recordedOriginImageDigest != EXPECTED_RECORDED_ORIGIN_IMAGE_DIGEST ||
        value.platform != EXPECTED_PLATFORM || value.sourceDateEpoch != EXPECTED_SOURCE_DATE_EPOCH
    ) {
        hostedFail("toolchain reproduction does not equal the reviewed hosted-build lock")
    }
}

private fun requireExactBuildEnvironment(
    value: LlvmBuildEnvironmentVerification,
    reproduction: LlvmToolchainReproductionVerification,
    fixed: FixedHostedInputs,
): HostedTools {
    if (value.sourceLockSha256 != fixed.sourceLockSha256 || value.buildRecordSha256 != fixed.buildRecordSha256 ||
        value.recordedOriginDigest != EXPECTED_RECORDED_ORIGIN_IMAGE_DIGEST
    ) {
        hostedFail("live LLVM build environment differs from the fixed input identities")
    }
    val record = value.record
    if (record.schemaVersion != 2 || record.environment.container.platform != EXPECTED_PLATFORM ||
        record.environment.container.digest != EXPECTED_RECORDED_ORIGIN_IMAGE_DIGEST ||
        record.environment.variables != EXPECTED_BUILD_ENVIRONMENT
    ) {
        hostedFail("live LLVM build record differs from the reviewed hosted environment")
    }
    val compiler = exactHostedTool(record.tools.singleOrNull { it.role == "compiler" }, EXPECTED_COMPILER)
    val linker = exactHostedTool(record.tools.singleOrNull { it.role == "linker" }, EXPECTED_LINKER)
    if (reproduction.buildRecordSha256 != value.buildRecordSha256) {
        hostedFail("toolchain reproduction and live tool verification cross-pair different build records")
    }
    return HostedTools(compiler, linker)
}

private fun exactHostedTool(actual: LlvmBuildToolV1?, expected: HostedTool): HostedTool {
    actual ?: hostedFail("LLVM build record is missing hosted ${expected.role}")
    val versionSha256 = OracleArtifacts.sha256(actual.versionOutput.toByteArray(Charsets.UTF_8))
    if (actual.role != expected.role || Path.of(actual.path) != expected.path ||
        actual.executableBytes != expected.bytes || actual.executableSha256 != expected.sha256 ||
        versionSha256 != expected.versionOutputSha256
    ) {
        hostedFail("LLVM build record ${expected.role} differs from the reviewed exact tool")
    }
    return expected
}

private fun deriveTwoCleanBuilds(
    archiveGuard: StableControlFile,
    index: LlvmBehaviorCandidateAcpLineageIndexV2,
    tools: HostedTools,
    compilerGuard: StableControlFile,
    linkerGuard: StableControlFile,
    sourceDateEpoch: String,
): DerivedHostedBuilds {
    val scratch = Files.createTempDirectory(FIXED_WORK_DIRECTORY, "llvm-hosted-clean-build-v2-")
        .toAbsolutePath().normalize()
    try {
        Files.setPosixFilePermissions(scratch, OWNER_DIRECTORY_PERMISSIONS)
        if (scratch.toRealPath() != scratch) hostedFail("hosted clean-build scratch path is not canonical")
        val snapshot = scratch.resolve("candidate-archive.zip")
        val snapshotSha256 = copyGuardedFile(
            archiveGuard,
            snapshot,
            OWNER_READ_ONLY_PERMISSIONS,
            "candidate archive snapshot",
        )
        if (snapshotSha256 != index.archiveSha256 || Files.size(snapshot) != index.archiveBytes) {
            hostedFail("private candidate archive snapshot differs from the verified lineage index")
        }

        val firstRoot = scratch.resolve("source-1")
        val secondRoot = scratch.resolve("source-2")
        val firstLineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(snapshot, firstRoot)
        val secondLineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(snapshot, secondRoot)
        requireExtractedLineage(firstLineage, index, "first")
        requireExtractedLineage(secondLineage, index, "second")
        requireSameExtractedLineage(firstLineage, secondLineage)

        val first = runCleanBuild(
            1,
            firstRoot,
            scratch.resolve("build-1"),
            firstLineage.source.sourceRevision,
            tools,
            compilerGuard,
            linkerGuard,
            sourceDateEpoch,
        )
        val second = runCleanBuild(
            2,
            secondRoot,
            scratch.resolve("build-2"),
            secondLineage.source.sourceRevision,
            tools,
            compilerGuard,
            linkerGuard,
            sourceDateEpoch,
        )
        if (!MessageDigest.isEqual(first.executable, second.executable)) {
            hostedFail("two private clean builds produced different candidate executable bytes")
        }
        if (first.facts.executableSha256 != second.facts.executableSha256 ||
            first.facts.executableBytes != second.facts.executableBytes ||
            first.facts.buildEnvironmentSha256 != second.facts.buildEnvironmentSha256 ||
            first.facts.compileCommandSetSha256 != second.facts.compileCommandSetSha256 ||
            first.facts.dependencyCount != second.facts.dependencyCount ||
            first.facts.dependencySetSha256 != second.facts.dependencySetSha256 ||
            first.facts.objectSetSha256 != second.facts.objectSetSha256 ||
            first.facts.linkCommandSha256 != second.facts.linkCommandSha256 ||
            first.facts.linkDependencyCount != second.facts.linkDependencyCount ||
            first.facts.linkDependencySetSha256 != second.facts.linkDependencySetSha256 ||
            first.facts.combinedOutputBytes != second.facts.combinedOutputBytes ||
            first.facts.combinedOutputSha256 != second.facts.combinedOutputSha256
        ) {
            hostedFail("two private clean-build environment, command, input, output, or executable facts disagree")
        }
        return DerivedHostedBuilds(
            firstLineage,
            listOf(first.facts, second.facts),
            first.executable.copyOf(),
            first.facts.executableSha256,
        )
    } finally {
        deleteScratchTree(scratch)
    }
}

private fun requireExtractedLineage(
    lineage: VerifiedCandidateArchiveLineage,
    index: LlvmBehaviorCandidateAcpLineageIndexV2,
    label: String,
) {
    val source = lineage.source
    if (source.profileId != GeneratedCMakeReconstructionProfile.PROFILE_ID ||
        source.profileSha256 != GeneratedCMakeReconstructionProfile.descriptor.sha256 ||
        source.sourceRevision.sha256 != index.sourceRevisionSha256 ||
        source.sourceRevision.inputs.size != index.sourceInputCount ||
        source.acceptedAcpContributions.size != index.acceptedAcpCount
    ) {
        hostedFail("$label clean extraction differs from authenticated ACP candidate lineage")
    }
}

private fun requireSameExtractedLineage(
    first: VerifiedCandidateArchiveLineage,
    second: VerifiedCandidateArchiveLineage,
) {
    if (first.archiveManifestBytes != second.archiveManifestBytes ||
        first.archiveManifestSha256 != second.archiveManifestSha256 ||
        first.source.profileId != second.source.profileId ||
        first.source.profileSha256 != second.source.profileSha256 ||
        first.source.sourceTreeManifestBytes != second.source.sourceTreeManifestBytes ||
        first.source.sourceTreeManifestSha256 != second.source.sourceTreeManifestSha256 ||
        first.source.sourceRevision != second.source.sourceRevision ||
        first.source.acceptedAcpContributions.size != second.source.acceptedAcpContributions.size
    ) {
        hostedFail("two verified private extractions expose different candidate lineage")
    }
}

private fun runCleanBuild(
    ordinal: Int,
    sourceRoot: Path,
    buildRoot: Path,
    sourceRevision: BuildSourceRevision,
    tools: HostedTools,
    compilerGuard: StableControlFile,
    linkerGuard: StableControlFile,
    sourceDateEpoch: String,
): CompletedCleanBuild {
    require(ordinal in 1..2)
    val buildDeadline = deadlineAfter(MAXIMUM_CLEAN_BUILD_DURATION)
    Files.createDirectory(buildRoot)
    Files.setPosixFilePermissions(buildRoot, OWNER_DIRECTORY_PERMISSIONS)
    val objectsRoot = buildRoot.resolve("objects")
    val dependenciesRoot = buildRoot.resolve("dependencies")
    val temporaryRoot = buildRoot.resolve("tmp")
    val toolRoot = buildRoot.resolve("tool")
    listOf(objectsRoot, dependenciesRoot, temporaryRoot, toolRoot).forEach {
        Files.createDirectory(it)
        Files.setPosixFilePermissions(it, OWNER_DIRECTORY_PERMISSIONS)
    }
    requireSourceRevision(sourceRoot, sourceRevision, "pre-build source revision")
    val sources = sourceRevision.inputs.filter { input ->
        input.path.startsWith("src/") && input.path.endsWith(".c")
    }
    if (sources.isEmpty() || sources.none { it.path == "src/main.c" } || sources.size > MAXIMUM_SOURCE_COUNT) {
        hostedFail("authenticated candidate must contain a bounded src/main.c translation-unit set")
    }
    if (sources.map(BuildSourceInput::path) != sources.map(BuildSourceInput::path).sorted()) {
        hostedFail("authenticated C translation units are not in canonical source order")
    }
    rejectUnsupportedCompilerInputs(sourceRoot, sourceRevision)

    val environment = sortedMapOf(
        "LC_ALL" to "C",
        "PATH" to DETERMINISTIC_PATH,
        "SOURCE_DATE_EPOCH" to sourceDateEpoch,
        "TMPDIR" to temporaryRoot.toString(),
        "TZ" to "UTC",
    )
    val environmentDigest = HostedCommitment("hosted-clean-build-environment-v2")
    environmentDigest.field("variableCount", environment.size.toLong())
    environment.entries.forEachIndexed { index, (name, value) ->
        environmentDigest.field("variable[$index].name", name)
        environmentDigest.field("variable[$index].value", canonicalizeEphemeralPaths(value, sourceRoot, buildRoot))
    }
    val commandDigest = HostedCommitment("hosted-clean-build-compile-command-set-v2")
    commandDigest.field("sourceCount", sources.size.toLong())
    val objectDigest = HostedCommitment("hosted-clean-build-object-set-v2")
    objectDigest.field("sourceCount", sources.size.toLong())
    val dependencies = sortedMapOf<String, HostedDependency>()
    val outputDigest = MessageDigest.getInstance("SHA-256")
    var outputBytes = 0L
    val objects = ArrayList<HostedBuildObject>(sources.size)
    var aggregateObjectBytes = 0L

    sources.forEachIndexed { index, source ->
        val relativeObject = "objects/${source.path.removePrefix("src/").removeSuffix(".c")}.o"
        val objectPath = buildRoot.resolve(relativeObject).normalize()
        if (!objectPath.startsWith(objectsRoot)) hostedFail("derived object path escapes its private build root")
        Files.createDirectories(objectPath.parent)
        val dependencyPath = dependenciesRoot.resolve("source-${index.toString().padStart(6, '0')}.d")
        val command = compileCommand(
            tools.compiler.path,
            sourceRoot,
            source.path,
            objectPath,
            dependencyPath,
            relativeObject,
        )
        commandDigest.command(index, canonicalizeCommand(command, sourceRoot, buildRoot))
        val result = runHostedCommand(
            command,
            environment,
            sourceRoot,
            tools,
            compilerGuard,
            linkerGuard,
            buildDeadline,
            "compile source ${source.path}",
        )
        outputBytes = addProcessOutput(outputBytes, result.output, outputDigest, sourceRoot, buildRoot)
        if (result.exitCode != 0) hostedFail("direct Clang compile failed for authenticated source ${source.path}")
        authenticateCompilerDependencies(
            dependencyPath,
            relativeObject,
            sourceRoot,
            sourceRevision,
        ).forEach { dependency ->
            val previous = dependencies.putIfAbsent(dependency.path, dependency)
            if (previous != null && previous != dependency) {
                hostedFail("compiler dependency identity changed across translation units")
            }
        }
        Files.delete(dependencyPath)
        val objectIdentity = requireRegularBuildOutput(objectPath, MAXIMUM_OBJECT_BYTES, "compiled object")
        aggregateObjectBytes = Math.addExact(aggregateObjectBytes, objectIdentity.bytes)
        if (aggregateObjectBytes > MAXIMUM_AGGREGATE_OBJECT_BYTES) {
            hostedFail("compiled objects exceed their aggregate byte bound")
        }
        objectDigest.field("object[$index].path", relativeObject)
        objectDigest.field("object[$index].bytes", objectIdentity.bytes)
        objectDigest.field("object[$index].sha256", objectIdentity.sha256)
        objects.add(HostedBuildObject(relativeObject, objectPath, objectIdentity))
    }

    if (dependencies.isEmpty() || dependencies.size > MAXIMUM_DEPENDENCIES) {
        hostedFail("clean build dependency count is outside its bound")
    }
    val dependencyDigest = HostedCommitment("hosted-clean-build-dependency-set-v2")
    dependencyDigest.field("dependencyCount", dependencies.size.toLong())
    var aggregateDependencyBytes = 0L
    dependencies.values.forEachIndexed { index, dependency ->
        aggregateDependencyBytes = Math.addExact(aggregateDependencyBytes, dependency.bytes)
        if (aggregateDependencyBytes > MAXIMUM_AGGREGATE_DEPENDENCY_BYTES) {
            hostedFail("clean build dependencies exceed their aggregate byte bound")
        }
        dependencyDigest.field("dependency[$index].path", dependency.path)
        dependencyDigest.field("dependency[$index].bytes", dependency.bytes)
        dependencyDigest.field("dependency[$index].sha256", dependency.sha256)
    }

    val privateLinker = toolRoot.resolve("ld.lld")
    val copiedLinkerSha256 = copyGuardedFile(
        linkerGuard,
        privateLinker,
        OWNER_READ_EXECUTE_PERMISSIONS,
        "private locked linker",
    )
    if (copiedLinkerSha256 != tools.linker.sha256 || Files.size(privateLinker) != tools.linker.bytes) {
        hostedFail("private linker bytes differ from the authenticated LLD")
    }
    val executablePath = buildRoot.resolve("candidate-reconstructed")
    val linkDependencyPath = dependenciesRoot.resolve("link.d")
    val linkCommand = linkCommand(
        tools.compiler.path,
        privateLinker,
        objects.map(HostedBuildObject::path),
        executablePath,
        linkDependencyPath,
    )
    val linkCommandDigest = HostedCommitment("hosted-clean-build-link-command-v2")
    linkCommandDigest.command(0, canonicalizeCommand(linkCommand, sourceRoot, buildRoot))
    val linkResult = runAuthenticatedPrivateLink(
        linkCommand = linkCommand,
        environment = environment,
        workingDirectory = sourceRoot,
        tools = tools,
        compilerGuard = compilerGuard,
        linkerGuard = linkerGuard,
        privateLinker = privateLinker,
        buildDeadline = buildDeadline,
    )
    outputBytes = addProcessOutput(outputBytes, linkResult.output, outputDigest, sourceRoot, buildRoot)
    if (linkResult.exitCode != 0) hostedFail("direct locked-Clang/LLD candidate link failed")
    val linkDependencies = authenticateLinkDependencies(linkDependencyPath, executablePath, sourceRoot, objects)
    val linkDependencyDigest = HostedCommitment("hosted-clean-build-link-dependency-set-v2")
    linkDependencyDigest.field("linkDependencyCount", linkDependencies.size.toLong())
    linkDependencies.forEachIndexed { index, dependency ->
        linkDependencyDigest.field("linkDependency[$index].path", dependency.path)
        linkDependencyDigest.field("linkDependency[$index].bytes", dependency.bytes)
        linkDependencyDigest.field("linkDependency[$index].sha256", dependency.sha256)
    }
    val executableIdentity = requireRegularBuildOutput(
        executablePath,
        MAXIMUM_EXECUTABLE_BYTES,
        "candidate executable",
        executable = true,
    )
    val elf = BoundedElfTwinV1.inspect(
        executablePath,
        BoundedElfTwinV1Limits(
            maximumFileBytes = MAXIMUM_EXECUTABLE_BYTES,
            maximumRangeBytes = MAXIMUM_EXECUTABLE_BYTES,
            maximumExecutableBytes = MAXIMUM_EXECUTABLE_BYTES,
            maximumAggregateHashedBytes = 2L * 1024L * 1024L * 1024L,
        ),
    )
    val entryPoint = elf.elf.header.entryPoint
    val entryPointIsMemoryBackedExecutable = elf.elf.programHeaders.any { header ->
        header.type == ELF_PROGRAM_HEADER_LOAD_TYPE &&
            (header.flags and ELF_PROGRAM_HEADER_EXECUTE_FLAG) != 0UL &&
            entryPoint >= header.virtualAddress &&
            entryPoint - header.virtualAddress < header.fileSize
    }
    if (elf.bytes != executableIdentity.bytes || elf.sha256 != executableIdentity.sha256 ||
        elf.elf.header.elfClass != "ELF64" || elf.elf.header.dataEncoding != "little-endian" ||
        elf.elf.header.machine != 62UL || elf.elf.header.type !in setOf(2UL, 3UL) ||
        entryPoint == 0UL || elf.elf.executableLoad.bytes <= 0L || !entryPointIsMemoryBackedExecutable
    ) {
        hostedFail("candidate output is not the required executable little-endian x86-64 ELF64")
    }
    requireSourceRevision(sourceRoot, sourceRevision, "terminal source revision")
    requireToolGuard(tools.compiler, compilerGuard, "compiler")
    requireToolGuard(tools.linker, linkerGuard, "linker")
    requireBeforeDeadline(buildDeadline, "clean build")
    val executableBytes = Files.readAllBytes(executablePath)
    if (executableBytes.size.toLong() != executableIdentity.bytes ||
        OracleArtifacts.sha256(executableBytes) != executableIdentity.sha256
    ) {
        hostedFail("candidate executable changed during bounded terminal reading")
    }
    return CompletedCleanBuild(
        HostedBuildFacts(
            ordinal,
            sourceRevision.sha256,
            sources.size,
            environmentDigest.finish(),
            commandDigest.finish(),
            dependencies.size,
            dependencyDigest.finish(),
            objectDigest.finish(),
            linkCommandDigest.finish(),
            linkDependencies.size,
            linkDependencyDigest.finish(),
            outputBytes,
            outputDigest.digest().hex(),
            executableIdentity.bytes,
            executableIdentity.sha256,
        ),
        executableBytes,
    )
}

private fun compileCommand(
    compiler: Path,
    sourceRoot: Path,
    source: String,
    output: Path,
    dependencyOutput: Path,
    dependencyTarget: String,
): List<String> = listOf(
    compiler.toString(),
    "--no-default-config",
    "-std=c11",
    "-g",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Werror=date-time",
    "-fno-gnu-inline-asm",
    "-fno-autolink",
    "-Iinclude",
    "-ffile-prefix-map=$sourceRoot=.",
    "-fdebug-prefix-map=$sourceRoot=.",
    "-fmacro-prefix-map=$sourceRoot=.",
    "-c",
    source,
    "-MD",
    "-MF",
    dependencyOutput.toString(),
    "-MT",
    dependencyTarget,
    "-o",
    output.toString(),
)

private fun linkCommand(
    compiler: Path,
    linker: Path,
    objects: List<Path>,
    output: Path,
    dependencyOutput: Path,
): List<String> = buildList {
    add(compiler.toString())
    add("--no-default-config")
    add("--ld-path=$linker")
    add("-Wl,--build-id=sha1")
    add("-Wl,--fatal-warnings")
    add("-Wl,--no-dependent-libraries")
    add("-Wl,--dependency-file=$dependencyOutput")
    objects.forEach { add(it.toString()) }
    add("-o")
    add(output.toString())
}

private data class HostedProcessResult(val exitCode: Int, val output: ByteArray)

private fun runAuthenticatedPrivateLink(
    linkCommand: List<String>,
    environment: Map<String, String>,
    workingDirectory: Path,
    tools: HostedTools,
    compilerGuard: StableControlFile,
    linkerGuard: StableControlFile,
    privateLinker: Path,
    buildDeadline: Long,
): HostedProcessResult {
    val executedLinker = tools.linker.copy(path = privateLinker)
    return StableControlFile.open(
        privateLinker,
        MAXIMUM_TOOL_BYTES,
        "private executed linker",
    ).use { privateLinkerGuard ->
        requireToolGuard(executedLinker, privateLinkerGuard, "private executed linker")
        val result = runHostedCommand(
            linkCommand,
            environment,
            workingDirectory,
            tools,
            compilerGuard,
            linkerGuard,
            buildDeadline,
            "link candidate executable",
        )
        requireToolGuard(executedLinker, privateLinkerGuard, "private executed linker")
        result
    }
}

private fun runHostedCommand(
    command: List<String>,
    environment: Map<String, String>,
    workingDirectory: Path,
    tools: HostedTools,
    compilerGuard: StableControlFile,
    linkerGuard: StableControlFile,
    buildDeadline: Long,
    label: String,
): HostedProcessResult {
    requireToolGuardMetadata(tools.compiler, compilerGuard, "compiler")
    requireToolGuardMetadata(tools.linker, linkerGuard, "linker")
    val result = HostedBuildProcessRunner.run(
        command,
        environment,
        workingDirectory,
        remainingCommandTimeout(buildDeadline, label),
        MAXIMUM_COMMAND_OUTPUT_BYTES,
        PROCESS_CLEANUP_TIMEOUT,
        label,
    )
    requireToolGuardMetadata(tools.compiler, compilerGuard, "compiler")
    requireToolGuardMetadata(tools.linker, linkerGuard, "linker")
    return result
}

private object HostedBuildProcessRunner {
    fun run(
        command: List<String>,
        environment: Map<String, String>,
        workingDirectory: Path,
        timeout: Duration,
        maximumOutputBytes: Int,
        cleanupTimeout: Duration,
        label: String,
    ): HostedProcessResult {
        if (command.isEmpty() || command.any { it.isEmpty() || '\u0000' in it }) hostedFail("$label argv is invalid")
        val process = try {
            ProcessBuilder(command)
                .redirectErrorStream(true)
                .directory(workingDirectory.toFile())
                .also { builder ->
                    builder.environment().clear()
                    builder.environment().putAll(environment)
                }
                .start()
        } catch (failure: IOException) {
            throw LlvmBehaviorHostedCleanBuildV2Exception("could not start $label", failure)
        }
        runCatching { process.outputStream.close() }
        val output = ByteArrayOutputStream(minOf(maximumOutputBytes, PROCESS_BUFFER_BYTES))
        val overflow = AtomicBoolean(false)
        val readerFailure = AtomicReference<Throwable?>(null)
        val reader = try {
            Thread.ofPlatform().daemon(true).name("hosted-clean-build-output").start {
                try {
                    val buffer = ByteArray(PROCESS_BUFFER_BYTES)
                    while (true) {
                        val count = process.inputStream.read(buffer)
                        if (count < 0) break
                        if (count == 0) continue
                        if (output.size() > maximumOutputBytes - count) {
                            overflow.set(true)
                            process.destroyForcibly()
                            break
                        }
                        output.write(buffer, 0, count)
                    }
                } catch (failure: Throwable) {
                    readerFailure.set(failure)
                }
            }
        } catch (failure: Throwable) {
            process.destroyForcibly()
            runCatching { process.waitFor(PROCESS_CLEANUP_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS) }
            throw LlvmBehaviorHostedCleanBuildV2Exception("could not start $label output reader", failure)
        }
        val descendants = linkedMapOf<Long, ProcessHandle>()
        val deadline = deadlineAfter(timeout)
        var exited = false
        var failure: LlvmBehaviorHostedCleanBuildV2Exception? = null
        try {
            while (!exited && failure == null) {
                if (!captureDescendants(process, descendants)) {
                    failure = LlvmBehaviorHostedCleanBuildV2Exception("$label exceeded its descendant-process bound")
                    continue
                }
                when {
                    overflow.get() -> failure = LlvmBehaviorHostedCleanBuildV2Exception("$label exceeded its output bound")
                    readerFailure.get() != null -> failure = LlvmBehaviorHostedCleanBuildV2Exception(
                        "could not read $label output",
                        readerFailure.get(),
                    )
                    System.nanoTime() >= deadline -> failure = LlvmBehaviorHostedCleanBuildV2Exception(
                        "$label exceeded its deadline",
                    )
                    else -> exited = process.waitFor(PROCESS_POLL_MILLIS, TimeUnit.MILLISECONDS)
                }
            }
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            failure = LlvmBehaviorHostedCleanBuildV2Exception("$label wait was interrupted", interrupted)
        }
        if (failure != null) {
            cleanupHostedProcess(process, descendants.values, reader, cleanupTimeout)?.let(failure::addSuppressed)
            throw failure
        }
        if (!captureDescendants(process, descendants)) {
            val wrapped = LlvmBehaviorHostedCleanBuildV2Exception("$label exceeded its descendant-process bound")
            cleanupHostedProcess(process, descendants.values, reader, cleanupTimeout)?.let(wrapped::addSuppressed)
            throw wrapped
        }
        val cleanupMillis = cleanupTimeout.toMillis().coerceAtLeast(1L)
        try {
            reader.join(cleanupMillis)
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            val wrapped = LlvmBehaviorHostedCleanBuildV2Exception("$label output cleanup was interrupted", interrupted)
            cleanupHostedProcess(process, descendants.values, reader, cleanupTimeout)?.let(wrapped::addSuppressed)
            throw wrapped
        }
        if (!captureDescendants(process, descendants)) {
            val wrapped = LlvmBehaviorHostedCleanBuildV2Exception("$label exceeded its descendant-process bound")
            cleanupHostedProcess(process, descendants.values, reader, cleanupTimeout)?.let(wrapped::addSuppressed)
            throw wrapped
        }
        val survivors = descendants.values.filter(ProcessHandle::isAlive)
        if (reader.isAlive || survivors.isNotEmpty()) {
            val wrapped = LlvmBehaviorHostedCleanBuildV2Exception("$label retained a process or output pipe after exit")
            cleanupHostedProcess(process, descendants.values, reader, cleanupTimeout)?.let(wrapped::addSuppressed)
            throw wrapped
        }
        readerFailure.get()?.let { throw LlvmBehaviorHostedCleanBuildV2Exception("could not read $label output", it) }
        if (overflow.get()) hostedFail("$label exceeded its output bound")
        return HostedProcessResult(process.exitValue(), output.toByteArray())
    }

    private fun captureDescendants(
        process: Process,
        captured: MutableMap<Long, ProcessHandle>,
    ): Boolean = try {
        var withinBound = true
        listOf(process.toHandle(), ProcessHandle.current()).forEach { root ->
            root.descendants().use { stream ->
                stream.limit((MAXIMUM_DESCENDANTS + 2).toLong()).forEach { handle ->
                    if (handle.pid() != process.pid()) {
                        if (captured.size >= MAXIMUM_DESCENDANTS && handle.pid() !in captured) {
                            withinBound = false
                        } else {
                            captured.putIfAbsent(handle.pid(), handle)
                        }
                    }
                }
            }
        }
        withinBound
    } catch (_: Throwable) {
        false
    }

    private fun cleanupHostedProcess(
        process: Process,
        descendants: Collection<ProcessHandle>,
        reader: Thread,
        timeout: Duration,
    ): Throwable? = try {
        descendants.toList().asReversed().forEach { runCatching { it.destroyForcibly() } }
        runCatching { process.destroyForcibly() }
        val millis = timeout.toMillis().coerceAtLeast(1L)
        runCatching { process.waitFor(millis, TimeUnit.MILLISECONDS) }
        runCatching { process.inputStream.close() }
        reader.join(millis)
        when {
            process.isAlive || descendants.any(ProcessHandle::isAlive) ->
                LlvmBehaviorHostedCleanBuildV2Exception("hosted build process survived bounded cleanup")
            reader.isAlive -> LlvmBehaviorHostedCleanBuildV2Exception("hosted build output reader survived cleanup")
            else -> null
        }
    } catch (failure: Throwable) {
        if (failure is InterruptedException) Thread.currentThread().interrupt()
        failure
    }
}

private data class BuildOutputIdentity(val bytes: Long, val sha256: String)

private data class HostedDependency(val path: String, val bytes: Long, val sha256: String)

private data class HostedBuildObject(
    val relativePath: String,
    val path: Path,
    val identity: BuildOutputIdentity,
)

private data class HostedLinkDependency(val path: String, val bytes: Long, val sha256: String)

private fun authenticateLinkDependencies(
    dependencyPath: Path,
    expectedTarget: Path,
    workingDirectory: Path,
    objects: List<HostedBuildObject>,
): List<HostedLinkDependency> {
    val attributes = readBasicAttributes(dependencyPath, "locked LLD dependency file")
    if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null ||
        attributes.size() !in 1L..MAXIMUM_LINK_DEPENDENCY_FILE_BYTES || dependencyPath.toRealPath() != dependencyPath
    ) {
        hostedFail("locked LLD dependency file is not a bounded canonical regular file")
    }
    val rawBytes = Files.readAllBytes(dependencyPath)
    val terminalAttributes = readBasicAttributes(dependencyPath, "locked LLD dependency file")
    if (rawBytes.size.toLong() != attributes.size() || attributes.fileKey() != terminalAttributes.fileKey() ||
        attributes.size() != terminalAttributes.size() ||
        attributes.lastModifiedTime() != terminalAttributes.lastModifiedTime()
    ) {
        hostedFail("locked LLD dependency file changed during reading")
    }
    val paths = parseLldLinkDependencyManifest(rawBytes, expectedTarget)

    val expectedObjects = objects.associateBy { objectFile ->
        try {
            objectFile.path.toRealPath()
        } catch (failure: Exception) {
            throw LlvmBehaviorHostedCleanBuildV2Exception("compiled object is unavailable after linking", failure)
        }
    }
    if (expectedObjects.size != objects.size) hostedFail("compiled object paths do not have distinct identities")
    val observedObjects = ArrayList<String>(objects.size)
    val cachedSystemInputs = HashMap<Path, HostedLinkDependency>()
    val dependencies = ArrayList<HostedLinkDependency>(paths.size)
    var aggregateBytes = 0L
    paths.forEach { token ->
        val raw = try {
            Path.of(token)
        } catch (failure: Exception) {
            throw LlvmBehaviorHostedCleanBuildV2Exception("locked LLD dependency file contains an invalid path", failure)
        }
        val normalized = (if (raw.isAbsolute) raw else workingDirectory.resolve(raw)).normalize()
        val real = try {
            normalized.toRealPath()
        } catch (failure: Exception) {
            throw LlvmBehaviorHostedCleanBuildV2Exception("locked LLD dependency file names an unavailable input", failure)
        }
        val objectFile = expectedObjects[real]
        val input = if (objectFile != null) {
            val terminal = requireRegularBuildOutput(objectFile.path, MAXIMUM_OBJECT_BYTES, "linked object")
            if (terminal != objectFile.identity) hostedFail("linked object changed after compilation")
            observedObjects.add(objectFile.relativePath)
            HostedLinkDependency("object:${objectFile.relativePath}", terminal.bytes, terminal.sha256)
        } else {
            cachedSystemInputs.getOrPut(real) { authenticateSystemLinkInput(real) }
        }
        aggregateBytes = Math.addExact(aggregateBytes, input.bytes)
        if (aggregateBytes > MAXIMUM_AGGREGATE_LINK_DEPENDENCY_BYTES) {
            hostedFail("locked LLD dependencies exceed their aggregate byte bound")
        }
        dependencies.add(input)
    }
    if (observedObjects != objects.map(HostedBuildObject::relativePath)) {
        hostedFail("locked LLD dependency file does not bind the exact ordered compiled-object set")
    }
    return dependencies
}

private fun parseLldLinkDependencyManifest(rawBytes: ByteArray, expectedTarget: Path): List<String> {
    if (!expectedTarget.isAbsolute || expectedTarget.normalize() != expectedTarget) {
        hostedFail("locked LLD dependency target is not absolute and normalized")
    }
    val text = decodeStrictUtf8(rawBytes, "locked LLD dependency file")
    if ('\r' in text || '\u0000' in text) hostedFail("locked LLD dependency file contains forbidden characters")
    val unfolded = text.replace("\\\n", " ")
    if ('\\' in unfolded) hostedFail("locked LLD dependency file contains unsupported escaped paths")
    val ruleLines = unfolded.lineSequence().map(String::trim).filter(String::isNotEmpty).toList()
    if (ruleLines.isEmpty()) hostedFail("locked LLD dependency file contains no rules")
    val tokens = ruleLines.first().split(DEPENDENCY_HORIZONTAL_WHITESPACE).filter(String::isNotEmpty)
    if (tokens.size < 2 || tokens.first() != "$expectedTarget:") {
        hostedFail("locked LLD dependency file does not bind its exact executable target")
    }
    val paths = tokens.drop(1)
    if (paths.isEmpty() || paths.size > MAXIMUM_LINK_DEPENDENCIES || paths.distinct().size != paths.size ||
        paths.any { !it.matches(DEPENDENCY_PATH_TOKEN) }
    ) {
        hostedFail("locked LLD dependency file does not contain a bounded ordered-unique dependency set")
    }
    if (ruleLines.drop(1) != paths.map { path -> "$path:" }) {
        hostedFail("locked LLD dependency file contains an unexpected phony-rule suffix")
    }
    return paths
}

private fun authenticateSystemLinkInput(real: Path): HostedLinkDependency {
    if (!real.isAbsolute || real.normalize() != real || real.toRealPath() != real) {
        hostedFail("system link input path is not canonical")
    }
    val allowed = SYSTEM_LIBRARY_ROOTS.any { root ->
        try {
            Files.isDirectory(root) && real.startsWith(root.toRealPath())
        } catch (_: Exception) {
            false
        }
    }
    if (!allowed) hostedFail("locked LLD input is outside reviewed container system-library roots")
    val attributes = readBasicAttributes(real, "system link input")
    if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null ||
        attributes.size() !in 1L..MAXIMUM_LINK_INPUT_BYTES
    ) {
        hostedFail("system link input is not a bounded canonical regular file")
    }
    val permissions = Files.getPosixFilePermissions(real, LinkOption.NOFOLLOW_LINKS)
    if (permissions.any { it in UNTRUSTED_WRITE_PERMISSIONS }) {
        hostedFail("system link input is writable by an untrusted principal")
    }
    val sha256 = sha256File(real, attributes.size(), MAXIMUM_LINK_INPUT_BYTES, "system link input")
    val terminal = readBasicAttributes(real, "system link input")
    if (attributes.fileKey() != terminal.fileKey() || attributes.size() != terminal.size() ||
        attributes.lastModifiedTime() != terminal.lastModifiedTime()
    ) {
        hostedFail("system link input changed during authentication")
    }
    return HostedLinkDependency("system:$real", attributes.size(), sha256)
}

private fun rejectUnsupportedCompilerInputs(sourceRoot: Path, revision: BuildSourceRevision) {
    revision.inputs.asSequence()
        .filter { it.path.startsWith("src/") || it.path.startsWith("include/") }
        .forEach { input ->
            val path = sourceRoot.resolve(input.path).normalize()
            if (!path.startsWith(sourceRoot) || Files.size(path) != input.bytes) {
                hostedFail("authenticated compiler input changed before language-policy validation")
            }
            val text = decodeStrictUtf8(Files.readAllBytes(path), "authenticated compiler input ${input.path}")
            FORBIDDEN_COMPILER_INPUT_TOKENS.forEach { token ->
                if (token in text) {
                    hostedFail("authenticated compiler input uses unsupported external-input token $token")
                }
            }
        }
}

private fun authenticateCompilerDependencies(
    dependencyPath: Path,
    expectedTarget: String,
    sourceRoot: Path,
    sourceRevision: BuildSourceRevision,
): List<HostedDependency> {
    val attributes = readBasicAttributes(dependencyPath, "compiler dependency file")
    if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null ||
        attributes.size() !in 1L..MAXIMUM_DEPENDENCY_FILE_BYTES || dependencyPath.toRealPath() != dependencyPath
    ) {
        hostedFail("compiler dependency file is not a bounded canonical regular file")
    }
    val raw = Files.readAllBytes(dependencyPath)
    if (raw.size.toLong() != attributes.size()) hostedFail("compiler dependency file changed while reading")
    val text = decodeStrictUtf8(raw, "compiler dependency file")
    if ('\r' in text || '\u0000' in text) hostedFail("compiler dependency file contains forbidden characters")
    val unfolded = text.replace("\\\n", " ")
    if ('\\' in unfolded) hostedFail("compiler dependency file contains unsupported escaped paths")
    val tokens = unfolded.trim().split(DEPENDENCY_WHITESPACE).filter(String::isNotEmpty)
    if (tokens.size < 2 || tokens.first() != "$expectedTarget:") {
        hostedFail("compiler dependency file does not bind its exact object target")
    }
    val expectedInputs = sourceRevision.inputs.associateBy(BuildSourceInput::path)
    val dependencies = linkedMapOf<String, HostedDependency>()
    tokens.drop(1).forEach { token ->
        if (!token.matches(DEPENDENCY_PATH_TOKEN)) hostedFail("compiler dependency path is not canonical")
        val rawPath = Path.of(token)
        val dependency = if (rawPath.isAbsolute) {
            authenticateSystemDependency(rawPath)
        } else {
            val normalized = sourceRoot.resolve(rawPath).normalize()
            if (!normalized.startsWith(sourceRoot)) hostedFail("compiler dependency escapes authenticated source")
            val relative = sourceRoot.relativize(normalized).toString().replace('\\', '/')
            val expected = expectedInputs[relative]
                ?: hostedFail("compiler read an archive file outside the authenticated source revision: $relative")
            if (normalized.toRealPath() != normalized || Files.size(normalized) != expected.bytes ||
                sha256DependencyFile(normalized, expected.bytes, "source dependency") != expected.sha256
            ) {
                hostedFail("compiler source dependency differs from its authenticated revision")
            }
            HostedDependency("source:$relative", expected.bytes, expected.sha256)
        }
        val previous = dependencies.putIfAbsent(dependency.path, dependency)
        if (previous != null && previous != dependency) hostedFail("compiler dependency path has conflicting identities")
    }
    if (dependencies.isEmpty()) hostedFail("compiler dependency file names no authenticated inputs")
    return dependencies.values.toList()
}

private fun authenticateSystemDependency(path: Path): HostedDependency {
    if (path.normalize() != path) hostedFail("system-header dependency path is not normalized")
    val real = try {
        path.toRealPath()
    } catch (failure: Exception) {
        throw LlvmBehaviorHostedCleanBuildV2Exception("system-header dependency is unavailable", failure)
    }
    val allowed = SYSTEM_HEADER_ROOTS.any { root ->
        Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) && real.startsWith(root.toRealPath())
    }
    if (!allowed) hostedFail("compiler dependency is outside reviewed container system-header roots")
    val attributes = readBasicAttributes(real, "system-header dependency")
    if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null ||
        attributes.size() !in 0L..MAXIMUM_DEPENDENCY_BYTES
    ) {
        hostedFail("system-header dependency is not a bounded regular file")
    }
    val permissions = Files.getPosixFilePermissions(real, LinkOption.NOFOLLOW_LINKS)
    if (permissions.any { it in UNTRUSTED_WRITE_PERMISSIONS }) {
        hostedFail("system-header dependency is writable by an untrusted principal")
    }
    return HostedDependency(
        "system:$real",
        attributes.size(),
        sha256DependencyFile(real, attributes.size(), "system-header dependency"),
    )
}

private fun sha256DependencyFile(path: Path, expectedBytes: Long, label: String): String {
    if (expectedBytes !in 0L..MAXIMUM_DEPENDENCY_BYTES) hostedFail("$label exceeds its byte bound")
    val digest = MessageDigest.getInstance("SHA-256")
    var observed = 0L
    Files.newInputStream(path, StandardOpenOption.READ).use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            observed = Math.addExact(observed, count.toLong())
            if (observed > expectedBytes) hostedFail("$label grew while hashing")
            digest.update(buffer, 0, count)
        }
    }
    if (observed != expectedBytes) hostedFail("$label ended while hashing")
    return digest.digest().hex()
}

private fun decodeStrictUtf8(bytes: ByteArray, label: String): String = try {
    StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()
} catch (failure: Exception) {
    throw LlvmBehaviorHostedCleanBuildV2Exception("$label is not valid UTF-8", failure)
}

private fun requireRegularBuildOutput(
    path: Path,
    maximumBytes: Long,
    label: String,
    executable: Boolean = false,
): BuildOutputIdentity {
    val attributes = readBasicAttributes(path, label)
    val links = (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toLong()
    if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null || links != 1L ||
        attributes.size() !in 1L..maximumBytes || path.toRealPath() != path
    ) {
        hostedFail("$label is not a bounded single-link canonical regular file")
    }
    if (executable) {
        val outputUid = (Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Number).toLong()
        val parentUid = (Files.getAttribute(path.parent, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Number).toLong()
        val permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS)
        if (outputUid != parentUid || PosixFilePermission.OWNER_EXECUTE !in permissions ||
            permissions.any { it in UNTRUSTED_WRITE_PERMISSIONS }
        ) {
            hostedFail("$label is not an owner-executable output owned by the private build principal")
        }
    }
    val sha256 = sha256File(path, attributes.size(), maximumBytes, label)
    val terminal = readBasicAttributes(path, label)
    if (attributes.fileKey() != terminal.fileKey() || attributes.size() != terminal.size() ||
        attributes.lastModifiedTime() != terminal.lastModifiedTime()
    ) {
        hostedFail("$label changed during authentication")
    }
    return BuildOutputIdentity(attributes.size(), sha256)
}

private fun requireSourceRevision(root: Path, expected: BuildSourceRevision, label: String) {
    val observed = captureBuildSourceRevision(root)
    if (observed != expected) hostedFail("$label differs from authenticated archive source")
}

private fun canonicalizeEphemeralPaths(value: String, sourceRoot: Path, buildRoot: Path): String {
    var canonical = value
    listOf(
        sourceRoot.toString() to "\${SOURCE}",
        buildRoot.toString() to "\${BUILD}",
    ).sortedByDescending { (path, _) -> path.length }
        .forEach { (path, replacement) -> canonical = canonical.replace(path, replacement) }
    return canonical
}

private fun canonicalizeCommand(command: List<String>, sourceRoot: Path, buildRoot: Path): List<String> =
    command.map { argument -> canonicalizeEphemeralPaths(argument, sourceRoot, buildRoot) }

private fun addProcessOutput(
    total: Long,
    bytes: ByteArray,
    digest: MessageDigest,
    sourceRoot: Path,
    buildRoot: Path,
): Long {
    val canonical = canonicalizeEphemeralPaths(
        decodeStrictUtf8(bytes, "successful hosted build command output"),
        sourceRoot,
        buildRoot,
    ).toByteArray(StandardCharsets.UTF_8)
    val next = Math.addExact(total, canonical.size.toLong())
    if (next > MAXIMUM_AGGREGATE_OUTPUT_BYTES) hostedFail("clean build exceeded its aggregate output bound")
    digest.update(canonical)
    return next
}

private fun renderHostedReceipt(
    index: LlvmBehaviorCandidateAcpLineageIndexV2,
    lineage: VerifiedCandidateArchiveLineage,
    reproduction: LlvmToolchainReproductionVerification,
    tools: HostedTools,
    builds: List<HostedBuildFacts>,
    executableBytes: ByteArray,
): RenderedHostedReceipt {
    if (builds.size != 2 || builds.map(HostedBuildFacts::ordinal) != listOf(1, 2)) {
        hostedFail("hosted receipt requires exactly two positional clean builds")
    }
    val executableSha256 = OracleArtifacts.sha256(executableBytes)
    builds.forEach { build ->
        if (build.sourceRevisionSha256 != index.sourceRevisionSha256 ||
            build.executableBytes != executableBytes.size.toLong() || build.executableSha256 != executableSha256
        ) {
            hostedFail("clean-build facts do not cross-bind the candidate lineage and exact executable")
        }
    }
    val schema = OracleSchemas.identity(RECEIPT_SCHEMA_NAME)
    val document = jsonObject(
        "schemaVersion" to JsonPrimitive(2),
        "kind" to JsonPrimitive(RECEIPT_KIND),
        "authority" to JsonPrimitive(RECEIPT_AUTHORITY),
        "schema" to jsonObject(
            "name" to JsonPrimitive(RECEIPT_SCHEMA_NAME),
            "sha256" to JsonPrimitive(schema.sha256),
        ),
        "archive" to jsonObject(
            "bytes" to JsonPrimitive(index.archiveBytes),
            "sha256" to JsonPrimitive(index.archiveSha256),
            "archiveManifestBytes" to JsonPrimitive(lineage.archiveManifestBytes),
            "archiveManifestSha256" to JsonPrimitive(lineage.archiveManifestSha256),
            "sourceTreeManifestBytes" to JsonPrimitive(lineage.source.sourceTreeManifestBytes),
            "sourceTreeManifestSha256" to JsonPrimitive(lineage.source.sourceTreeManifestSha256),
            "verified" to JsonPrimitive(true),
        ),
        "candidateLineageIndex" to jsonObject(
            "schemaVersion" to JsonPrimitive(index.schemaVersion),
            "bytes" to JsonPrimitive(index.indexBytes),
            "sha256" to JsonPrimitive(index.indexSha256),
            "candidateSourceLineageSha256" to JsonPrimitive(index.candidateSourceLineageSha256),
            "acceptedAcp" to jsonObject(
                "receiptSchemaVersion" to JsonPrimitive(2),
                "count" to JsonPrimitive(index.acceptedAcpCount),
                "reconstructionCount" to JsonPrimitive(index.reconstructionCount),
                "repairCount" to JsonPrimitive(index.repairCount),
                "aggregateAlgorithm" to JsonPrimitive("domain-separated-length-prefixed-sorted-leaves-v2"),
                "receiptSetSha256" to JsonPrimitive(index.receiptSetSha256),
                "sessionSetSha256" to JsonPrimitive(index.sessionSetSha256),
                "changeSetSha256" to JsonPrimitive(index.changeSetSha256),
                "lineageSetSha256" to JsonPrimitive(index.lineageSetSha256),
            ),
        ),
        "source" to jsonObject(
            "profileId" to JsonPrimitive(lineage.source.profileId),
            "profileSha256" to JsonPrimitive(lineage.source.profileSha256),
            "revisionAlgorithm" to JsonPrimitive("length-prefixed-path-bytes-sha256-v1"),
            "inputCount" to JsonPrimitive(lineage.source.sourceRevision.inputs.size),
            "revisionSha256" to JsonPrimitive(lineage.source.sourceRevision.sha256),
        ),
        "lockedToolchain" to jsonObject(
            "sourceLockSha256" to JsonPrimitive(EXPECTED_SOURCE_LOCK_SHA256),
            "reproductionLockSha256" to JsonPrimitive(reproduction.lockSha256),
            "dockerfileSha256" to JsonPrimitive(reproduction.dockerfileSha256),
            "buildRecordSha256" to JsonPrimitive(reproduction.buildRecordSha256),
            "recordedOriginImageDigest" to JsonPrimitive(reproduction.recordedOriginImageDigest),
            "inspectArtifactImageDigest" to JsonPrimitive(reproduction.observedImageDigest),
            "platform" to JsonPrimitive(reproduction.platform),
            "SOURCE_DATE_EPOCH" to JsonPrimitive(reproduction.sourceDateEpoch),
            "compiler" to toolDocument(tools.compiler),
            "linker" to toolDocument(tools.linker),
        ),
        "cleanBuilds" to JsonArray(builds.map(::buildDocument)),
        "candidateExecutable" to jsonObject(
            "name" to JsonPrimitive(EXECUTABLE_FILE_NAME),
            "format" to JsonPrimitive("ELF"),
            "elfClass" to JsonPrimitive("ELF64"),
            "endianness" to JsonPrimitive("little-endian"),
            "machine" to JsonPrimitive("x86-64"),
            "bytes" to JsonPrimitive(executableBytes.size),
            "sha256" to JsonPrimitive(executableSha256),
            "identicalAcrossBuilds" to JsonPrimitive(true),
        ),
        "runtimeClosure" to jsonObject(
            "kind" to JsonPrimitive("container-image-closure"),
            "inspectArtifactImageDigest" to JsonPrimitive(reproduction.observedImageDigest),
            "platform" to JsonPrimitive(reproduction.platform),
            "buildCount" to JsonPrimitive(2),
            "authenticated" to JsonPrimitive(false),
        ),
        "attestationBoundary" to attestationBoundaryDocument(),
        "acpBoundary" to hostedAcpBoundaryDocument(),
        "claims" to hostedClaimsDocument(),
    )
    OracleSchemas.validate(RECEIPT_SCHEMA_NAME, document)
    val bytes = try {
        OracleJson.canonicalBytes(document, RECEIPT_JSON_LIMITS)
    } catch (failure: Exception) {
        throw LlvmBehaviorHostedCleanBuildV2Exception("hosted receipt exceeds canonical JSON bounds", failure)
    }
    if (bytes.isEmpty() || bytes.size > MAXIMUM_RECEIPT_BYTES) hostedFail("hosted receipt exceeds its byte bound")
    rejectLegacyHostedText(bytes.toString(Charsets.UTF_8), "hosted receipt")
    return RenderedHostedReceipt(bytes)
}

private fun toolDocument(tool: HostedTool): JsonObject = jsonObject(
    "role" to JsonPrimitive(tool.role),
    "path" to JsonPrimitive(tool.path.toString()),
    "bytes" to JsonPrimitive(tool.bytes),
    "sha256" to JsonPrimitive(tool.sha256),
    "versionOutputSha256" to JsonPrimitive(tool.versionOutputSha256),
)

private fun buildDocument(build: HostedBuildFacts): JsonObject = jsonObject(
    "ordinal" to JsonPrimitive(build.ordinal),
    "extractionMode" to JsonPrimitive("verified-archive-private-clean-extraction"),
    "compilerMode" to JsonPrimitive("direct-clang-per-source"),
    "linkerMode" to JsonPrimitive("direct-clang"),
    "makefileExecuted" to JsonPrimitive(false),
    "buildContractTrusted" to JsonPrimitive(false),
    "sourceRevisionSha256" to JsonPrimitive(build.sourceRevisionSha256),
    "sourceCount" to JsonPrimitive(build.sourceCount),
    "buildEnvironmentSha256" to JsonPrimitive(build.buildEnvironmentSha256),
    "compileCommandSetSha256" to JsonPrimitive(build.compileCommandSetSha256),
    "dependencyCount" to JsonPrimitive(build.dependencyCount),
    "dependencySetSha256" to JsonPrimitive(build.dependencySetSha256),
    "objectSetSha256" to JsonPrimitive(build.objectSetSha256),
    "linkCommandSha256" to JsonPrimitive(build.linkCommandSha256),
    "linkDependencyCount" to JsonPrimitive(build.linkDependencyCount),
    "linkDependencySetSha256" to JsonPrimitive(build.linkDependencySetSha256),
    "combinedOutputBytes" to JsonPrimitive(build.combinedOutputBytes),
    "combinedOutputSha256" to JsonPrimitive(build.combinedOutputSha256),
    "executableBytes" to JsonPrimitive(build.executableBytes),
    "executableSha256" to JsonPrimitive(build.executableSha256),
)

private fun attestationBoundaryDocument(): JsonObject = jsonObject(
    "producerReceipt" to JsonPrimitive("unsigned-kotlin-jvm-facts"),
    "requiredMode" to JsonPrimitive("github-actions-default-slsa-v1-two-subjects"),
    "requiredSubjects" to JsonArray(
        listOf(JsonPrimitive(RECEIPT_FILE_NAME), JsonPrimitive(EXECUTABLE_FILE_NAME)),
    ),
    "hostedWorkflowAuthenticated" to JsonPrimitive(false),
    "sigstoreBundleVerified" to JsonPrimitive(false),
)

private fun hostedAcpBoundaryDocument(): JsonObject = jsonObject(
    "role" to JsonPrimitive("first-class-candidate-producer-operator"),
    "candidateContribution" to JsonPrimitive("authenticated-session-change-provenance"),
    "candidateProvenanceAccess" to JsonPrimitive("read-only-oracle-input"),
    "candidateAdmissionOwner" to JsonPrimitive("kotlin-jvm-host"),
    "candidateLiveExecutionOwner" to JsonPrimitive("separately-reviewed-kotlin-jvm-host"),
    "referenceSubjectAdmission" to JsonPrimitive("kotlin-jvm-host-only"),
    "oracleAuthority" to JsonPrimitive(false),
    "referenceAuthoringAuthority" to JsonPrimitive(false),
    "policyAuthoringAuthority" to JsonPrimitive(false),
    "validationAuthority" to JsonPrimitive(false),
    "observationAuthoringAuthority" to JsonPrimitive(false),
    "startAuthority" to JsonPrimitive(false),
    "containmentAuthority" to JsonPrimitive(false),
    "terminalAbsenceAuthority" to JsonPrimitive(false),
    "scoringAuthority" to JsonPrimitive(false),
    "certificationAuthority" to JsonPrimitive(false),
    "releaseAuthority" to JsonPrimitive(false),
)

private fun hostedClaimsDocument(): JsonObject = jsonObject(
    "verifiedArchiveBound" to JsonPrimitive(true),
    "candidateLineageBound" to JsonPrimitive(true),
    "sourceRevisionBound" to JsonPrimitive(true),
    "lockedToolchainBound" to JsonPrimitive(true),
    "runtimeInspectArtifactParsed" to JsonPrimitive(true),
    "runtimeImageInspected" to JsonPrimitive(false),
    "runtimeClosureAuthenticated" to JsonPrimitive(false),
    "twoCleanBuildsCompleted" to JsonPrimitive(true),
    "executableReproduced" to JsonPrimitive(true),
    "hostedWorkflowAuthenticated" to JsonPrimitive(false),
    "sigstoreBundleVerified" to JsonPrimitive(false),
    "admittedArtifactBound" to JsonPrimitive(false),
    "prepared" to JsonPrimitive(false),
    "liveRuntimeIdentityVerified" to JsonPrimitive(false),
    "liveContainmentVerified" to JsonPrimitive(false),
    "terminalAbsenceVerified" to JsonPrimitive(false),
    "observationsCaptured" to JsonPrimitive(false),
    "startAuthorized" to JsonPrimitive(false),
    "candidateStarted" to JsonPrimitive(false),
    "candidateExecuted" to JsonPrimitive(false),
    "oracleAuthority" to JsonPrimitive(false),
    "referenceAuthoringAuthority" to JsonPrimitive(false),
    "referenceTruthEstablished" to JsonPrimitive(false),
    "scoringAuthority" to JsonPrimitive(false),
    "certificationAuthority" to JsonPrimitive(false),
    "releaseAuthority" to JsonPrimitive(false),
    "releaseEligible" to JsonPrimitive(false),
)

private fun publishHostedPair(paths: HostedPaths, executable: ByteArray, receipt: ByteArray) {
    requireDedicatedOutputDirectory(paths)
    LinuxFilesystemSyscalls.openRoot(paths.outputDirectory).use { parent ->
        val publishedExecutable = DescriptorBoundAtomicStateFile.publishExecutableNoReplace(
            parent,
            EXECUTABLE_FILE_NAME,
            executable,
            MAXIMUM_EXECUTABLE_BYTES.toInt(),
        )
        if (!MessageDigest.isEqual(publishedExecutable.bytes, executable)) {
            hostedFail("published candidate executable differs from the reproduced bytes")
        }
        val publishedReceipt = DescriptorBoundAtomicStateFile.publishNoReplace(
            parent,
            RECEIPT_FILE_NAME,
            receipt,
            MAXIMUM_RECEIPT_BYTES,
        )
        if (!MessageDigest.isEqual(publishedReceipt.bytes, receipt)) {
            hostedFail("published hosted receipt differs from its canonical bytes")
        }
    }
}

private fun requireTerminalInputs(
    guards: HostedInputGuards,
    fixed: FixedHostedInputs,
    index: LlvmBehaviorCandidateAcpLineageIndexV2,
) {
    val checks = listOf(
        Triple(guards.archive, index.archiveSha256, "candidate reconstruction archive"),
        Triple(guards.lineageIndex, fixed.lineageIndexSha256, "candidate ACP lineage index"),
        Triple(guards.sourceLock, fixed.sourceLockSha256, "LLVM source lock"),
        Triple(guards.buildRecord, fixed.buildRecordSha256, "LLVM build record"),
        Triple(guards.reproductionLock, fixed.reproductionLockSha256, "LLVM reproduction lock"),
        Triple(guards.dockerInspect, fixed.dockerInspectSha256, "Docker inspect artifact"),
    )
    checks.forEach { (guard, expected, label) ->
        if (guard.sha256(label = label) != expected) hostedFail("$label changed during hosted clean builds")
        guard.verifyUnchanged(label)
        requireSingleLink(guard.path, label)
    }
}

private fun requireToolGuard(tool: HostedTool, guard: StableControlFile, label: String) {
    if (guard.size != tool.bytes || guard.sha256(label = "authenticated $label") != tool.sha256) {
        hostedFail("authenticated $label bytes changed")
    }
    requireToolGuardMetadata(tool, guard, label)
}

private fun requireToolGuardMetadata(tool: HostedTool, guard: StableControlFile, label: String) {
    if (guard.path != tool.path || guard.size != tool.bytes) hostedFail("authenticated $label identity disagrees")
    guard.verifyUnchanged("authenticated $label")
    requireSingleLink(tool.path, "authenticated $label")
}

private fun copyGuardedFile(
    guard: StableControlFile,
    target: Path,
    permissions: Set<PosixFilePermission>,
    label: String,
): String {
    if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) hostedFail("$label target already exists")
    val digest = MessageDigest.getInstance("SHA-256")
    var copied = 0L
    guard.slice().use { input ->
        Files.newOutputStream(target, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { output ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                copied = Math.addExact(copied, count.toLong())
                if (copied > guard.size) hostedFail("$label grew while copying")
                digest.update(buffer, 0, count)
                output.write(buffer, 0, count)
            }
        }
    }
    if (copied != guard.size) hostedFail("$label ended while copying")
    FileChannel.open(target, StandardOpenOption.WRITE).use { it.force(true) }
    Files.setPosixFilePermissions(target, permissions)
    return digest.digest().hex()
}

private class HostedCommitment(domain: String) {
    private val digest = MessageDigest.getInstance("SHA-256")

    init {
        token("decomp-engine-llvm-behavior-hosted-clean-build-v2".toByteArray(Charsets.UTF_8))
        token(domain.toByteArray(Charsets.UTF_8))
    }

    fun field(name: String, value: String) {
        token(name.toByteArray(Charsets.UTF_8))
        token(value.toByteArray(Charsets.UTF_8))
    }

    fun field(name: String, value: Long) = field(name, value.toString())

    fun command(index: Int, command: List<String>) {
        field("command[$index].argumentCount", command.size.toLong())
        command.forEachIndexed { argument, value -> field("command[$index].argument[$argument]", value) }
    }

    fun finish(): String = digest.digest().hex()

    private fun token(bytes: ByteArray) {
        digest.update(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(bytes.size.toLong()).array())
        digest.update(bytes)
    }
}

private fun sha256File(path: Path, expectedBytes: Long, maximumBytes: Long, label: String): String {
    if (expectedBytes !in 1L..maximumBytes) hostedFail("$label exceeds its byte bound")
    val digest = MessageDigest.getInstance("SHA-256")
    var observed = 0L
    Files.newInputStream(path, StandardOpenOption.READ).use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            observed = Math.addExact(observed, count.toLong())
            if (observed > expectedBytes || observed > maximumBytes) hostedFail("$label grew while hashing")
            digest.update(buffer, 0, count)
        }
    }
    if (observed != expectedBytes) hostedFail("$label ended while hashing")
    return digest.digest().hex()
}

private fun readBasicAttributes(path: Path, label: String): BasicFileAttributes = try {
    Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
} catch (failure: Exception) {
    throw LlvmBehaviorHostedCleanBuildV2Exception("$label attributes are unavailable", failure)
}

private fun requireSingleLink(path: Path, label: String) {
    val links = try {
        (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toLong()
    } catch (failure: Exception) {
        throw LlvmBehaviorHostedCleanBuildV2Exception("$label link identity is unavailable", failure)
    }
    if (links != 1L) hostedFail("$label must not be hard-linked")
}

private fun sameExistingFile(left: Path, right: Path): Boolean =
    Files.exists(left, LinkOption.NOFOLLOW_LINKS) && Files.exists(right, LinkOption.NOFOLLOW_LINKS) &&
        try {
            Files.isSameFile(left, right)
        } catch (failure: Exception) {
            throw LlvmBehaviorHostedCleanBuildV2Exception("cannot establish hosted path identity", failure)
        }

private fun deleteScratchTree(root: Path) {
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
    Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
}

private fun rejectLegacyHostedText(value: String, label: String) {
    val lower = value.lowercase(Locale.ROOT)
    FORBIDDEN_HOSTED_MARKERS.forEach { marker ->
        if (marker in lower) hostedFail("$label contains forbidden Python, remote, or legacy behavior material")
    }
}

private fun requireFixedDigest(actual: String, expected: String, label: String) {
    if (actual != expected) hostedFail("$label differs from its reviewed SHA-256")
}

private fun deadlineAfter(timeout: Duration): Long {
    val now = System.nanoTime()
    val nanos = try {
        timeout.toNanos()
    } catch (_: ArithmeticException) {
        Long.MAX_VALUE
    }
    return if (nanos >= Long.MAX_VALUE - now) Long.MAX_VALUE else now + nanos
}

private fun remainingCommandTimeout(deadline: Long, label: String): Duration {
    val remaining = deadline - System.nanoTime()
    if (remaining <= 0L) hostedFail("clean build exceeded its deadline before $label")
    return Duration.ofNanos(minOf(remaining, BUILD_COMMAND_TIMEOUT.toNanos()))
}

private fun requireBeforeDeadline(deadline: Long, label: String) {
    if (System.nanoTime() >= deadline) hostedFail("$label exceeded its deadline")
}

private fun jsonObject(vararg fields: Pair<String, JsonElement>): JsonObject = JsonObject(linkedMapOf(*fields))

private fun ByteArray.hex(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private inline fun <T> translateHostedFailure(action: () -> T): T = try {
    action()
} catch (failure: LlvmBehaviorHostedCleanBuildV2Exception) {
    throw failure
} catch (failure: Exception) {
    throw LlvmBehaviorHostedCleanBuildV2Exception(
        "hosted candidate clean build failed: ${failure.message ?: failure.javaClass.simpleName}",
        failure,
    )
}

private fun hostedFail(message: String): Nothing = throw LlvmBehaviorHostedCleanBuildV2Exception(message)

private const val RECEIPT_SCHEMA_NAME = "llvm-behavior-hosted-clean-build-v2"
private const val RECEIPT_KIND = "llvm-behavior-hosted-clean-build-v2"
private const val RECEIPT_AUTHORITY = "kotlin-jvm-unsigned-inner-clean-build-worker-v2"
private const val RECEIPT_FILE_NAME = "candidate-hosted-clean-build-v2.json"
private const val EXECUTABLE_FILE_NAME = "candidate-reconstructed"
private const val LINEAGE_INDEX_FILE_NAME = "candidate-acp-lineage-index-v2.json"
private const val SOURCE_LOCK_FILE_NAME = "source-lock.json"
private const val BUILD_RECORD_FILE_NAME = "build-record.json"
private const val REPRODUCTION_LOCK_FILE_NAME = "toolchain-reproduction.json"
private val FIXED_INPUT_DIRECTORY = Path.of("/inputs")
private val FIXED_ARCHIVE_PATH = FIXED_INPUT_DIRECTORY.resolve("candidate-reconstruction.zip")
private val FIXED_LINEAGE_INDEX_PATH = FIXED_INPUT_DIRECTORY.resolve(LINEAGE_INDEX_FILE_NAME)
private val FIXED_SOURCE_LOCK_PATH = FIXED_INPUT_DIRECTORY.resolve(SOURCE_LOCK_FILE_NAME)
private val FIXED_BUILD_RECORD_PATH = FIXED_INPUT_DIRECTORY.resolve(BUILD_RECORD_FILE_NAME)
private val FIXED_REPRODUCTION_LOCK_PATH = FIXED_INPUT_DIRECTORY.resolve(REPRODUCTION_LOCK_FILE_NAME)
private val FIXED_DOCKER_INSPECT_PATH = FIXED_INPUT_DIRECTORY.resolve("image-inspect.json")
private val FIXED_OUTPUT_DIRECTORY = Path.of("/stage-output")
private val FIXED_WORK_DIRECTORY = Path.of("/work")
private const val ELF_PROGRAM_HEADER_LOAD_TYPE = 1UL
private const val ELF_PROGRAM_HEADER_EXECUTE_FLAG = 1UL
private const val MAXIMUM_RECEIPT_BYTES = 128 * 1024
private const val MAXIMUM_LINEAGE_INDEX_BYTES = 64L * 1024L
private const val MAXIMUM_SOURCE_LOCK_BYTES = 1024L * 1024L
private const val MAXIMUM_BUILD_RECORD_BYTES = 16L * 1024L * 1024L
private const val MAXIMUM_REPRODUCTION_LOCK_BYTES = 1024L * 1024L
private const val MAXIMUM_DOCKER_INSPECT_BYTES = 16L * 1024L * 1024L
private const val MAXIMUM_TOOL_BYTES = 512L * 1024L * 1024L
private const val MAXIMUM_EXECUTABLE_BYTES = 64L * 1024L * 1024L
private const val MAXIMUM_OBJECT_BYTES = 512L * 1024L * 1024L
private const val MAXIMUM_AGGREGATE_OBJECT_BYTES = 2L * 1024L * 1024L * 1024L
private const val MAXIMUM_SOURCE_COUNT = 100_000
private const val MAXIMUM_DEPENDENCIES = 1_000_000
private const val MAXIMUM_DEPENDENCY_FILE_BYTES = 16L * 1024L * 1024L
private const val MAXIMUM_DEPENDENCY_BYTES = 128L * 1024L * 1024L
private const val MAXIMUM_AGGREGATE_DEPENDENCY_BYTES = 2L * 1024L * 1024L * 1024L
private const val MAXIMUM_LINK_DEPENDENCIES = 4096
private const val MAXIMUM_LINK_DEPENDENCY_FILE_BYTES = 16L * 1024L * 1024L
private const val MAXIMUM_LINK_INPUT_BYTES = 512L * 1024L * 1024L
private const val MAXIMUM_AGGREGATE_LINK_DEPENDENCY_BYTES = 2L * 1024L * 1024L * 1024L
private const val MAXIMUM_COMMAND_OUTPUT_BYTES = 32 * 1024 * 1024
private const val MAXIMUM_AGGREGATE_OUTPUT_BYTES = 16L * 1024L * 1024L * 1024L
private const val PROCESS_BUFFER_BYTES = 64 * 1024
private const val PROCESS_POLL_MILLIS = 25L
private const val MAXIMUM_DESCENDANTS = 256
private val BUILD_COMMAND_TIMEOUT = Duration.ofMinutes(10)
private val MAXIMUM_CLEAN_BUILD_DURATION = Duration.ofMinutes(30)
private val PROCESS_CLEANUP_TIMEOUT = Duration.ofSeconds(5)
private const val EXPECTED_SOURCE_LOCK_SHA256 = "179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306"
private const val EXPECTED_BUILD_RECORD_SHA256 = "415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005"
private const val EXPECTED_REPRODUCTION_LOCK_SHA256 = "14a383bc5792b7ace786cbbd8964383469c1ffa5a4bb06a99e38c71518643f4f"
private const val EXPECTED_DOCKERFILE_SHA256 = "97e2d13915806242c14489b5a8b1417bd0478f3a11dc05e76888ba2ab43b1291"
private const val EXPECTED_RECORDED_ORIGIN_IMAGE_DIGEST =
    "sha256:73285d9a2dad159a7171fe4bbcac7d97d285402955d8c6fb8b44b101cf2df550"
private const val EXPECTED_PLATFORM = "linux/amd64"
private const val EXPECTED_SOURCE_DATE_EPOCH = "1779182222"
private const val ZERO_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
private const val DETERMINISTIC_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
private val EXPECTED_BUILD_ENVIRONMENT = sortedMapOf(
    "LC_ALL" to "C",
    "PATH" to DETERMINISTIC_PATH,
    "SOURCE_DATE_EPOCH" to EXPECTED_SOURCE_DATE_EPOCH,
    "TZ" to "UTC",
)
private val EXPECTED_COMPILER = HostedTool(
    "compiler",
    Path.of("/usr/lib/llvm-22/bin/clang"),
    138184,
    "9dff149140cff7484c1efd85a5cfe0e3f046edcf71c63b42b5501c4a2ee462ae",
    "d6d146c61f5ba14a74f0cb00885d4068a7f1b41c88880f93d7c65187efb625ea",
)
private val EXPECTED_LINKER = HostedTool(
    "linker",
    Path.of("/usr/lib/llvm-22/bin/lld"),
    6059960,
    "057e42c6104e20a7358a51fb9abb456d74ba37997331d99183e877539da95982",
    "0b47969becd48b365d7fa9302efe7f9191742b5a3d761d008c5cf67132e78451",
)
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
private val UNTRUSTED_WRITE_PERMISSIONS = setOf(
    PosixFilePermission.GROUP_WRITE,
    PosixFilePermission.OTHERS_WRITE,
)
private val SYSTEM_HEADER_ROOTS = listOf(
    Path.of("/usr/include"),
    Path.of("/usr/local/include"),
    Path.of("/usr/lib/llvm-22/lib/clang"),
    Path.of("/usr/lib/gcc"),
    Path.of("/usr/lib/x86_64-linux-gnu"),
)
private val SYSTEM_LIBRARY_ROOTS = listOf(
    Path.of("/usr/lib"),
    Path.of("/usr/lib64"),
    Path.of("/lib"),
    Path.of("/lib64"),
)
private val DEPENDENCY_WHITESPACE = Regex("[ \\t\\n]+")
private val DEPENDENCY_HORIZONTAL_WHITESPACE = Regex("[ \\t]+")
private val DEPENDENCY_PATH_TOKEN = Regex("[A-Za-z0-9_+.,/@%:=~-]+")
private val FORBIDDEN_COMPILER_INPUT_TOKENS = listOf(
    "__has_",
    "##",
    "%:%:",
    ".incbin",
    ".include",
    "#embed",
)
private val RECEIPT_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_RECEIPT_BYTES,
    maximumCanonicalBytes = MAXIMUM_RECEIPT_BYTES,
    maximumDepth = 20,
    maximumNodes = 1024,
    maximumStringBytes = 4096,
    maximumTotalStringBytes = 64 * 1024,
)
private val FORBIDDEN_HOSTED_MARKERS = listOf(
    "python",
    "http://",
    "https://",
    "behavior-preexec-v1",
    "oci-container-v1",
    "llvm-behavior-candidate-execution-admission",
    "kotlin-host-pre-start-binding-v1",
    "llvm-behavior-runtime-preflight",
    "kotlin-host-live-runtime-preflight-v1",
)
