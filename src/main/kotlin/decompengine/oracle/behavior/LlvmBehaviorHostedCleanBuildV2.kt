package decompengine.oracle.behavior

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Platform
import com.sun.jna.Pointer
import com.sun.jna.StringArray
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
                    HostedAdoptedTools.open(tools, compilerGuard, linkerGuard).use { adoptedTools ->
                        val derived = deriveTwoCleanBuilds(
                            guards.archive,
                            lineageIndex,
                            tools,
                            adoptedTools,
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

    fun assess(
        firstSourceRoot: Path,
        secondSourceRoot: Path,
    ): LlvmBehaviorHostedCleanBuildV2Assessment = translateHostedFailure {
        val firstRoot = requireExactTestDirectory(firstSourceRoot, "first test source root")
        val secondRoot = requireExactTestDirectory(secondSourceRoot, "second test source root")
        val (compiler, linker) = requireFixedLocalTestToolchain()
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
                    HostedAdoptedTools.open(tools, compilerGuard, linkerGuard).use { adoptedTools ->
                        val first = runCleanBuild(
                            1,
                            firstRoot,
                            scratch.resolve("build-1"),
                            firstRevision,
                            tools,
                            adoptedTools,
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
                            adoptedTools,
                            compilerGuard,
                            linkerGuard,
                            EXPECTED_SOURCE_DATE_EPOCH,
                        )
                        if (!MessageDigest.isEqual(first.executable, second.executable)) {
                            hostedFail("test clean builds produced different executable bytes")
                        }
                        LlvmBehaviorHostedCleanBuildV2Assessment(first.facts, second.facts, first.executable)
                    }
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
    val linkPlanInputCount: Int = first.linkPlanInputCount
    val firstLinkPlanSha256: String = first.linkPlanSha256
    val secondLinkPlanSha256: String = second.linkPlanSha256
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
        require(first.linkPlanInputCount == second.linkPlanInputCount)
        require(first.linkPlanSha256 == second.linkPlanSha256)
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

private class HostedAdoptedTools private constructor(
    val compiler: HostedRetainedFile,
    val linker: HostedRetainedFile,
) : AutoCloseable {
    override fun close() {
        runCatching(linker::close)
        runCatching(compiler::close)
    }

    companion object {
        fun open(
            tools: HostedTools,
            compilerGuard: StableControlFile,
            linkerGuard: StableControlFile,
        ): HostedAdoptedTools {
            requireClosedGlobalLoaderConfiguration()
            var compiler: HostedRetainedFile? = null
            var linker: HostedRetainedFile? = null
            try {
                compiler = HostedRetainedFile.snapshot(
                    compilerGuard,
                    tools.compiler.bytes,
                    tools.compiler.sha256,
                    executable = true,
                    label = "retained authenticated Clang",
                )
                linker = HostedRetainedFile.snapshot(
                    linkerGuard,
                    tools.linker.bytes,
                    tools.linker.sha256,
                    executable = true,
                    label = "retained authenticated LLD",
                )
                requireToolGuard(tools.compiler, compilerGuard, "compiler")
                requireToolGuard(tools.linker, linkerGuard, "linker")
                return HostedAdoptedTools(compiler, linker)
            } catch (failure: Throwable) {
                runCatching { linker?.close() }
                runCatching { compiler?.close() }
                throw failure
            }
        }
    }
}

private fun requireClosedGlobalLoaderConfiguration() {
    if (Files.exists(GLOBAL_LOADER_PRELOAD_PATH, LinkOption.NOFOLLOW_LINKS)) {
        hostedFail("global dynamic-loader preload configuration is forbidden")
    }
}

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
    val linkPlanInputCount: Int,
    val linkPlanSha256: String,
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

private fun requireFixedLocalTestToolchain(): Pair<Path, Path> {
    val selected = FIXED_LOCAL_TEST_TOOLCHAINS.firstOrNull { (compiler, linker) ->
        Files.isRegularFile(compiler, LinkOption.NOFOLLOW_LINKS) &&
            Files.isRegularFile(linker, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(compiler) && !Files.isSymbolicLink(linker)
    } ?: hostedFail("the fixed local LLVM 22 test toolchain is unavailable")
    return requireExactHostedPath(selected.first, "fixed local test compiler") to
        requireExactHostedPath(selected.second, "fixed local test linker")
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
    adoptedTools: HostedAdoptedTools,
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
        val (firstLineage, secondLineage) = StableControlFile.open(
            snapshot,
            LLVM_BEHAVIOR_CANDIDATE_ACP_LINEAGE_MAXIMUM_ARCHIVE_BYTES,
            "private hosted candidate archive snapshot",
        ).use { snapshotGuard ->
            snapshotGuard.requireSingleLink("private hosted candidate archive snapshot")
            if (
                snapshotGuard.size != index.archiveBytes ||
                snapshotGuard.sha256(label = "private hosted candidate archive snapshot") != index.archiveSha256
            ) {
                hostedFail("private hosted candidate archive snapshot changed before extraction")
            }
            val firstLineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(snapshotGuard, firstRoot)
            val secondLineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(snapshotGuard, secondRoot)
            snapshotGuard.verifyUnchanged("private hosted candidate archive snapshot")
            snapshotGuard.requireSingleLink("private hosted candidate archive snapshot")
            firstLineage to secondLineage
        }
        requireExtractedLineage(firstLineage, index, "first")
        requireExtractedLineage(secondLineage, index, "second")
        requireSameExtractedLineage(firstLineage, secondLineage)

        val first = runCleanBuild(
            1,
            firstRoot,
            scratch.resolve("build-1"),
            firstLineage.source.sourceRevision,
            tools,
            adoptedTools,
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
            adoptedTools,
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
            first.facts.linkPlanInputCount != second.facts.linkPlanInputCount ||
            first.facts.linkPlanSha256 != second.facts.linkPlanSha256 ||
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
    adoptedTools: HostedAdoptedTools,
    compilerGuard: StableControlFile,
    linkerGuard: StableControlFile,
    sourceDateEpoch: String,
): CompletedCleanBuild {
    require(ordinal in 1..2)
    val buildDeadline = deadlineAfter(MAXIMUM_CLEAN_BUILD_DURATION)
    Files.createDirectory(buildRoot)
    Files.setPosixFilePermissions(buildRoot, OWNER_DIRECTORY_PERMISSIONS)
    val temporaryRoot = buildRoot.resolve("tmp")
    Files.createDirectory(temporaryRoot)
    Files.setPosixFilePermissions(temporaryRoot, OWNER_DIRECTORY_PERMISSIONS)
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
    val retainedInputs = adoptCandidateInputs(sourceRoot, sourceRevision)
    val objects = ArrayList<HostedBuildObject>(sources.size)
    var overlay: HostedRetainedFile? = null
    var linkPlan: HostedLinkPlan? = null
    var executable: HostedRetainedFile? = null
    try {
        val retainedOverlay = createCandidateOverlay(retainedInputs)
        overlay = retainedOverlay
        HostedPinnedDirectory.open(buildRoot, "private clean-build working directory").use { workingDirectory ->
            HostedPinnedDirectory.open(temporaryRoot, "private compiler temporary directory").use { temporaryDirectory ->
                val logicalEnvironment = sortedMapOf(
                    "LC_ALL" to "C",
                    "SOURCE_DATE_EPOCH" to sourceDateEpoch,
                    "TMPDIR" to "\${TMPDIR}",
                    "TZ" to "UTC",
                )
                val environment = sortedMapOf(
                    "LC_ALL" to "C",
                    "SOURCE_DATE_EPOCH" to sourceDateEpoch,
                    "TMPDIR" to temporaryDirectory.capabilityPath("compiler temporary directory"),
                    "TZ" to "UTC",
                )
                val environmentDigest = HostedCommitment("hosted-clean-build-environment-v2")
                environmentDigest.field("variableCount", logicalEnvironment.size.toLong())
                logicalEnvironment.entries.forEachIndexed { index, (name, value) ->
                    environmentDigest.field("variable[$index].name", name)
                    environmentDigest.field("variable[$index].value", value)
                }

                val resourceDirectory = requireCompilerResourceDirectory(tools.compiler.path)
                val resolvedLinkPlan = resolveHostedLinkPlan(
                    resourceDirectory,
                    adoptedTools,
                    environment,
                    workingDirectory,
                    tools,
                    compilerGuard,
                    linkerGuard,
                    buildDeadline,
                )
                linkPlan = resolvedLinkPlan
                val gccInstallDirectory = resolvedLinkPlan.input(HostedLinkRole.CRTBEGIN_S).originalPath.parent
                    ?: hostedFail("resolved GCC installation has no parent directory")
                val commandDigest = HostedCommitment("hosted-clean-build-compile-command-set-v2")
                commandDigest.field("sourceCount", sources.size.toLong())
                val objectDigest = HostedCommitment("hosted-clean-build-object-set-v2")
                objectDigest.field("sourceCount", sources.size.toLong())
                val dependencies = sortedMapOf<String, HostedDependency>()
                val outputDigest = MessageDigest.getInstance("SHA-256")
                var outputBytes = 0L
                var aggregateObjectBytes = 0L
                val inputsByPath = retainedInputs.associateBy(HostedCandidateInput::relativePath)

                sources.forEachIndexed { index, source ->
                    val retainedSource = inputsByPath[source.path]
                        ?: hostedFail("authenticated source is missing its retained identity")
                    val relativeObject = "objects/${source.path.removePrefix("src/").removeSuffix(".c")}.o"
                    val retainedDependencyOutput = HostedRetainedFile.writable(
                        makeExecutable = false,
                        label = "compiler dependency output",
                    )
                    var dependencyOutput: HostedRetainedFile? = retainedDependencyOutput
                    val retainedObjectOutput = HostedRetainedFile.writable(
                        makeExecutable = false,
                        label = "compiled object output",
                    )
                    var objectOutput: HostedRetainedFile? = retainedObjectOutput
                    try {
                        val invocation = compileCommand(
                            resourceDirectory,
                            gccInstallDirectory,
                            retainedSource,
                            source.path,
                            retainedObjectOutput,
                            retainedDependencyOutput,
                            retainedOverlay,
                            relativeObject,
                        )
                        commandDigest.command(index, invocation.committedArguments)
                        val result = runHostedCommand(
                            HostedExecutableRole.CLANG,
                            invocation.actualArguments,
                            environment,
                            workingDirectory,
                            adoptedTools,
                            tools,
                            compilerGuard,
                            linkerGuard,
                            buildDeadline,
                            "compile source ${source.path}",
                        )
                        outputBytes = addProcessOutput(outputBytes, result.output, outputDigest, sourceRoot, buildRoot)
                        if (result.exitCode != 0) {
                            hostedFail(
                                "retained direct Clang compile failed for authenticated source ${source.path}: " +
                                    boundedHostedFailureOutput(result.output),
                            )
                        }
                        retainedDependencyOutput.sealProduced(
                            MAXIMUM_DEPENDENCY_FILE_BYTES,
                            makeExecutable = false,
                            label = "compiler dependency output",
                        )
                        authenticateCompilerDependencies(
                            retainedDependencyOutput.readBytes(
                                MAXIMUM_DEPENDENCY_FILE_BYTES,
                                "compiler dependency output",
                            ),
                            relativeObject,
                            source.path,
                            retainedSource.retained.capabilityPath("retained compiler source"),
                            sourceRevision,
                        ).forEach { dependency ->
                            val previous = dependencies.putIfAbsent(dependency.path, dependency)
                            if (previous != null && previous != dependency) {
                                hostedFail("compiler dependency identity changed across translation units")
                            }
                        }
                        val objectIdentity = retainedObjectOutput.sealProduced(
                            MAXIMUM_OBJECT_BYTES,
                            makeExecutable = false,
                            label = "compiled object",
                        )
                        aggregateObjectBytes = Math.addExact(aggregateObjectBytes, objectIdentity.bytes)
                        if (aggregateObjectBytes > MAXIMUM_AGGREGATE_OBJECT_BYTES) {
                            hostedFail("compiled objects exceed their aggregate byte bound")
                        }
                        objectDigest.field("object[$index].path", relativeObject)
                        objectDigest.field("object[$index].bytes", objectIdentity.bytes)
                        objectDigest.field("object[$index].sha256", objectIdentity.sha256)
                        objects += HostedBuildObject(relativeObject, retainedObjectOutput, objectIdentity)
                        objectOutput = null
                    } finally {
                        dependencyOutput?.close()
                        objectOutput?.close()
                    }
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

                val linkInvocation = linkCommand(resolvedLinkPlan, objects)
                val linkCommandDigest = HostedCommitment("hosted-clean-build-link-command-v2")
                linkCommandDigest.command(0, linkInvocation.committedArguments)
                val linkCommandSha256 = linkCommandDigest.finish()
                val linkResult = runHostedCommand(
                    HostedExecutableRole.LLD,
                    linkInvocation.actualArguments,
                    environment,
                    workingDirectory,
                    adoptedTools,
                    tools,
                    compilerGuard,
                    linkerGuard,
                    buildDeadline,
                    "link candidate executable",
                )
                outputBytes = addProcessOutput(outputBytes, linkResult.stderr, outputDigest, sourceRoot, buildRoot)
                if (linkResult.exitCode != 0) {
                    hostedFail("direct retained LLD candidate link failed: ${boundedHostedFailureOutput(linkResult.stderr)}")
                }
                if (linkResult.stdout.isEmpty() || linkResult.stdout.size.toLong() > MAXIMUM_EXECUTABLE_BYTES) {
                    hostedFail("direct retained LLD did not return a bounded executable on stdout")
                }
                val retainedExecutable = HostedRetainedFile.snapshot(
                    linkResult.stdout,
                    executable = true,
                    label = "candidate executable",
                )
                executable = retainedExecutable
                val executableIdentity = BuildOutputIdentity(
                    retainedExecutable.bytes,
                    retainedExecutable.sha256,
                )
                val executableBytes = retainedExecutable.readBytes(MAXIMUM_EXECUTABLE_BYTES, "candidate executable")
                val elf = inspectRetainedExecutable(executableBytes, executableIdentity, buildRoot)
                requireHostedElf(elf, executableIdentity)

                val committedPlan = resolvedLinkPlan.committedEntries(objects)
                if (committedPlan.isEmpty() || committedPlan.size > MAXIMUM_LINK_DEPENDENCIES) {
                    hostedFail("direct retained LLD link plan is outside its input-count bound")
                }
                var aggregateLinkInputBytes = 0L
                committedPlan.forEach { input ->
                    aggregateLinkInputBytes = Math.addExact(aggregateLinkInputBytes, input.bytes)
                    if (aggregateLinkInputBytes > MAXIMUM_AGGREGATE_LINK_DEPENDENCY_BYTES) {
                        hostedFail("direct retained LLD link plan exceeds its aggregate byte bound")
                    }
                }
                val linkPlanDigest = HostedCommitment("hosted-clean-build-link-plan-v2")
                linkPlanDigest.field("linkCommandSha256", linkCommandSha256)
                linkPlanDigest.field("linkerArgv0", HostedExecutableRole.LLD.argumentZero)
                linkPlanDigest.field("linkerBytes", tools.linker.bytes)
                linkPlanDigest.field("linkerSha256", tools.linker.sha256)
                linkPlanDigest.field("inputCount", committedPlan.size.toLong())
                committedPlan.forEachIndexed { index, input ->
                    linkPlanDigest.field("input[$index].role", input.role)
                    linkPlanDigest.field("input[$index].resolution", input.resolution)
                    linkPlanDigest.field("input[$index].path", input.logicalPath)
                    linkPlanDigest.field("input[$index].bytes", input.bytes)
                    linkPlanDigest.field("input[$index].sha256", input.sha256)
                }

                requireSourceRevision(sourceRoot, sourceRevision, "terminal source revision")
                requireToolGuard(tools.compiler, compilerGuard, "compiler")
                requireToolGuard(tools.linker, linkerGuard, "linker")
                requireBeforeDeadline(buildDeadline, "clean build")
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
                        linkCommandSha256,
                        committedPlan.size,
                        linkPlanDigest.finish(),
                        outputBytes,
                        outputDigest.digest().hex(),
                        executableIdentity.bytes,
                        executableIdentity.sha256,
                    ),
                    executableBytes,
                )
            }
        }
    } finally {
        executable?.close()
        objects.asReversed().forEach { runCatching(it.retained::close) }
        linkPlan?.close()
        overlay?.close()
        retainedInputs.asReversed().forEach { runCatching(it.retained::close) }
    }
}

private fun compileCommand(
    resourceDirectory: Path,
    gccInstallDirectory: Path,
    sourceInput: HostedCandidateInput,
    source: String,
    output: HostedRetainedFile,
    dependencyOutput: HostedRetainedFile,
    overlay: HostedRetainedFile,
    dependencyTarget: String,
): HostedInvocation {
    val sourceCapability = sourceInput.retained.capabilityPath("retained compiler source")
    val overlayCapability = overlay.capabilityPath("retained candidate VFS overlay")
    val dependencyCapability = dependencyOutput.capabilityPath("compiler dependency output")
    val outputCapability = output.capabilityPath("compiled object output")
    val virtualSourceParent = VIRTUAL_CANDIDATE_ROOT.resolve(Path.of(source).parent ?: Path.of("src"))
        .normalize().toString()
    val actual = listOf(
        "--no-default-config",
        "--target=$HOSTED_TARGET_TRIPLE",
        "-resource-dir=$resourceDirectory",
        "--gcc-install-dir=$gccInstallDirectory",
        "-fintegrated-cc1",
        "-fintegrated-as",
        "-std=c11",
        "-g",
        "-fdebug-compilation-dir=.",
        "-fcoverage-compilation-dir=.",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Werror=date-time",
        "-fno-gnu-inline-asm",
        "-fno-autolink",
        "-ivfsoverlay",
        overlayCapability,
        "-iquote",
        virtualSourceParent,
        "-I$VIRTUAL_CANDIDATE_INCLUDE",
        "-ffile-prefix-map=$sourceCapability=$source",
        "-fdebug-prefix-map=$sourceCapability=$source",
        "-fmacro-prefix-map=$sourceCapability=$source",
        "-ffile-prefix-map=$VIRTUAL_CANDIDATE_ROOT=.",
        "-fdebug-prefix-map=$VIRTUAL_CANDIDATE_ROOT=.",
        "-fmacro-prefix-map=$VIRTUAL_CANDIDATE_ROOT=.",
        "-c",
        "-x",
        "c",
        sourceCapability,
        "-MD",
        "-MF",
        dependencyCapability,
        "-MT",
        dependencyTarget,
        "-o",
        outputCapability,
    )
    val committed = actual.map { argument ->
        when (argument) {
            sourceCapability -> source
            overlayCapability -> "\${CANDIDATE_VFS_OVERLAY}"
            dependencyCapability -> "dependencies/${dependencyTarget.removePrefix("objects/").removeSuffix(".o")}.d"
            outputCapability -> dependencyTarget
            "-ffile-prefix-map=$sourceCapability=$source" -> "-ffile-prefix-map=\${RETAINED_SOURCE}=$source"
            "-fdebug-prefix-map=$sourceCapability=$source" -> "-fdebug-prefix-map=\${RETAINED_SOURCE}=$source"
            "-fmacro-prefix-map=$sourceCapability=$source" -> "-fmacro-prefix-map=\${RETAINED_SOURCE}=$source"
            else -> argument
        }
    }
    return HostedInvocation(actual, listOf(HostedExecutableRole.CLANG.argumentZero) + committed)
}

private fun linkCommand(
    plan: HostedLinkPlan,
    objects: List<HostedBuildObject>,
): HostedInvocation {
    val actual = buildList {
        add("-flavor")
        add("gnu")
        add("--hash-style=gnu")
        add("--eh-frame-hdr")
        add("-m")
        add("elf_x86_64")
        add("-pie")
        add("-dynamic-linker")
        add(plan.input(HostedLinkRole.LOADER).originalPath.toString())
        add("--build-id=sha1")
        add("--fatal-warnings")
        add("--no-dependent-libraries")
        add("-o")
        add("-")
        add(plan.capability(HostedLinkRole.SCRT1))
        add(plan.capability(HostedLinkRole.CRTI))
        add(plan.capability(HostedLinkRole.CRTBEGIN_S))
        objects.forEach { add(it.retained.capabilityPath("sealed compiled object")) }
        add(plan.capability(HostedLinkRole.LIBGCC_A))
        add("--as-needed")
        add(plan.capability(HostedLinkRole.LIBGCC_S))
        add("--no-as-needed")
        add(plan.capability(HostedLinkRole.LIBC_SO_6))
        add(plan.capability(HostedLinkRole.LIBC_NONSHARED))
        add(plan.capability(HostedLinkRole.LIBGCC_A))
        add("--as-needed")
        add(plan.capability(HostedLinkRole.LIBGCC_S))
        add("--no-as-needed")
        add(plan.capability(HostedLinkRole.CRTEND_S))
        add(plan.capability(HostedLinkRole.CRTN))
    }
    val replacements = linkedMapOf<String, String>()
    HostedLinkRole.entries.forEach { role ->
        if (role != HostedLinkRole.LOADER) replacements[plan.capability(role)] = "\${LINK_INPUT:${role.factRole}}"
    }
    objects.forEach { objectFile ->
        replacements[objectFile.retained.capabilityPath("sealed compiled object")] = objectFile.relativePath
    }
    val committed = actual.map { replacements[it] ?: it }
    return HostedInvocation(actual, listOf(HostedExecutableRole.LLD.argumentZero) + committed)
}

private data class HostedInvocation(
    val actualArguments: List<String>,
    val committedArguments: List<String>,
)

private data class HostedProcessResult(
    val exitCode: Int,
    val stdout: ByteArray,
    val stderr: ByteArray,
) {
    val output: ByteArray
        get() = stdout + stderr
}

private fun runHostedCommand(
    role: HostedExecutableRole,
    arguments: List<String>,
    environment: Map<String, String>,
    workingDirectory: HostedPinnedDirectory,
    adoptedTools: HostedAdoptedTools,
    tools: HostedTools,
    compilerGuard: StableControlFile,
    linkerGuard: StableControlFile,
    buildDeadline: Long,
    label: String,
): HostedProcessResult {
    requireToolGuardMetadata(tools.compiler, compilerGuard, "compiler")
    requireToolGuardMetadata(tools.linker, linkerGuard, "linker")
    val executable = when (role) {
        HostedExecutableRole.CLANG -> adoptedTools.compiler
        HostedExecutableRole.LLD -> adoptedTools.linker
    }
    val expected = when (role) {
        HostedExecutableRole.CLANG -> tools.compiler
        HostedExecutableRole.LLD -> tools.linker
    }
    if (executable.bytes != expected.bytes || executable.sha256 != expected.sha256) {
        hostedFail("$label lost its exact adopted ${role.argumentZero} identity")
    }
    if (arguments.any { it == "-###" || it.startsWith("@") } ||
        (role == HostedExecutableRole.LLD && arguments.any { it == "-L" || it.startsWith("-L") ||
            (it.startsWith("-l") && it.length > 2) })
    ) hostedFail("$label contains an implicit or shell-text tool-selection argument")
    val result = HostedBuildProcessRunner.run(
        executable,
        role,
        arguments,
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

private enum class HostedExecutableRole(val argumentZero: String) {
    CLANG("clang"),
    LLD("ld.lld"),
}

/** One sealed anonymous inode. Its descriptor and procfs capability never leave this private file. */
private class HostedRetainedFile private constructor(
    private var descriptor: Int,
    val bytes: Long,
    val sha256: String,
    private val executable: Boolean,
) : AutoCloseable {
    @Synchronized
    fun capabilityPath(label: String): String {
        if (descriptor < 0) hostedFail("$label retained identity is closed")
        return hostedDescriptorPath(descriptor)
    }

    @Synchronized
    fun executionCapability(label: String): String {
        if (!executable) hostedFail("$label retained identity is not executable")
        if (descriptor < 0) hostedFail("$label retained identity is closed")
        return hostedDescriptorPath(descriptor)
    }

    @Synchronized
    fun sealProduced(
        maximumBytes: Long,
        makeExecutable: Boolean,
        label: String,
    ): BuildOutputIdentity {
        if (descriptor < 0) hostedFail("$label retained identity is closed")
        hostedSyscall(label, "synchronize") { HOSTED_LIBC.fsync(descriptor) }
        hostedSyscall(label, "set mode") {
            HOSTED_LIBC.fchmod(descriptor, if (makeExecutable) HOSTED_MODE_READ_EXECUTE else HOSTED_MODE_READ_ONLY)
        }
        hostedFcntlSeals(descriptor, label)
        val identity = readRetainedIdentity(descriptor, maximumBytes, label)
        if (identity.bytes <= 0L) hostedFail("$label is empty")
        return identity
    }

    @Synchronized
    fun readBytes(maximumBytes: Long, label: String): ByteArray {
        if (descriptor < 0) hostedFail("$label retained identity is closed")
        return readRetainedBytes(descriptor, maximumBytes, label)
    }

    override fun close() {
        val owned = synchronized(this) {
            val current = descriptor
            descriptor = -1
            current
        }
        if (owned >= 0) HOSTED_LIBC.close(owned)
    }

    companion object {
        fun snapshot(
            guard: StableControlFile,
            expectedBytes: Long,
            expectedSha256: String,
            executable: Boolean,
            label: String,
        ): HostedRetainedFile {
            if (expectedBytes !in 1L..MAXIMUM_TOOL_BYTES || guard.size != expectedBytes) {
                hostedFail("$label size is outside its adoption bound")
            }
            val descriptor = createHostedMemfd(executable, label)
            try {
                val digest = MessageDigest.getInstance("SHA-256")
                var copied = 0L
                guard.slice().use { input ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        copied = Math.addExact(copied, count.toLong())
                        if (copied > expectedBytes) hostedFail("$label grew during adoption")
                        digest.update(buffer, 0, count)
                        hostedWriteAll(descriptor, buffer, count, label)
                    }
                }
                val observedSha256 = digest.digest().hex()
                if (copied != expectedBytes || observedSha256 != expectedSha256) {
                    hostedFail("$label differs from its authenticated descriptor bytes")
                }
                hostedSyscall(label, "synchronize") { HOSTED_LIBC.fsync(descriptor) }
                hostedSyscall(label, "set mode") {
                    HOSTED_LIBC.fchmod(
                        descriptor,
                        if (executable) HOSTED_MODE_READ_EXECUTE else HOSTED_MODE_READ_ONLY,
                    )
                }
                hostedFcntlSeals(descriptor, label)
                val identity = readRetainedIdentity(descriptor, expectedBytes, label)
                if (identity.bytes != expectedBytes || identity.sha256 != expectedSha256) {
                    hostedFail("$label changed while its anonymous identity was sealed")
                }
                return HostedRetainedFile(descriptor, expectedBytes, expectedSha256, executable)
            } catch (failure: Throwable) {
                HOSTED_LIBC.close(descriptor)
                throw failure
            }
        }

        fun snapshot(bytes: ByteArray, executable: Boolean, label: String): HostedRetainedFile {
            val maximumBytes = if (executable) MAXIMUM_EXECUTABLE_BYTES else MAXIMUM_RETAINED_AUXILIARY_BYTES
            if (bytes.isEmpty() || bytes.size.toLong() > maximumBytes) {
                hostedFail("$label exceeds its adoption bound")
            }
            val descriptor = createHostedMemfd(executable, label)
            try {
                hostedWriteAll(descriptor, bytes, bytes.size, label)
                hostedSyscall(label, "synchronize") { HOSTED_LIBC.fsync(descriptor) }
                hostedSyscall(label, "set mode") {
                    HOSTED_LIBC.fchmod(
                        descriptor,
                        if (executable) HOSTED_MODE_READ_EXECUTE else HOSTED_MODE_READ_ONLY,
                    )
                }
                hostedFcntlSeals(descriptor, label)
                val sha256 = OracleArtifacts.sha256(bytes)
                val identity = readRetainedIdentity(descriptor, bytes.size.toLong(), label)
                if (identity.bytes != bytes.size.toLong() || identity.sha256 != sha256) {
                    hostedFail("$label changed while its anonymous identity was sealed")
                }
                return HostedRetainedFile(descriptor, identity.bytes, identity.sha256, executable)
            } catch (failure: Throwable) {
                HOSTED_LIBC.close(descriptor)
                throw failure
            }
        }

        fun writable(makeExecutable: Boolean, label: String): HostedRetainedFile {
            val descriptor = createHostedMemfd(makeExecutable, label)
            return HostedRetainedFile(descriptor, 0L, ZERO_SHA256, makeExecutable)
        }
    }
}

private class HostedPinnedDirectory private constructor(private var descriptor: Int) : AutoCloseable {
    @Synchronized
    fun addWorkingDirectoryAction(actions: Pointer, label: String) {
        if (descriptor < 0) hostedFail("$label pinned working directory is closed")
        hostedNativeResult(
            "$label configure descriptor-pinned working directory",
            HOSTED_LIBC.posix_spawn_file_actions_addfchdir_np(actions, descriptor),
        )
    }

    @Synchronized
    fun capabilityPath(label: String): String {
        if (descriptor < 0) hostedFail("$label pinned directory is closed")
        return hostedDescriptorPath(descriptor)
    }

    override fun close() {
        val owned = synchronized(this) {
            val current = descriptor
            descriptor = -1
            current
        }
        if (owned >= 0) HOSTED_LIBC.close(owned)
    }

    companion object {
        fun open(path: Path, label: String): HostedPinnedDirectory {
            if (!path.isAbsolute || path.normalize() != path || path.toRealPath() != path || !Files.isDirectory(path)) {
                hostedFail("$label is not a canonical directory")
            }
            val before = readBasicAttributes(path, label)
            val descriptor = hostedOpen(
                path.toString(),
                HOSTED_O_RDONLY or HOSTED_O_DIRECTORY or HOSTED_O_NOFOLLOW or HOSTED_O_CLOEXEC,
                label,
            )
            try {
                val descriptorPath = Path.of(hostedDescriptorPath(descriptor))
                val after = try {
                    Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
                } catch (failure: Exception) {
                    throw LlvmBehaviorHostedCleanBuildV2Exception("$label descriptor attributes are unavailable", failure)
                }
                if (!before.isDirectory || before.fileKey() == null || before.fileKey() != after.fileKey()) {
                    hostedFail("$label changed while its descriptor was pinned")
                }
                return HostedPinnedDirectory(descriptor)
            } catch (failure: Throwable) {
                HOSTED_LIBC.close(descriptor)
                throw failure
            }
        }
    }
}

private object HostedBuildProcessRunner {
    fun run(
        executable: HostedRetainedFile,
        role: HostedExecutableRole,
        arguments: List<String>,
        environment: Map<String, String>,
        workingDirectory: HostedPinnedDirectory,
        timeout: Duration,
        maximumOutputBytes: Int,
        cleanupTimeout: Duration,
        label: String,
    ): HostedProcessResult {
        val argv = listOf(role.argumentZero) + arguments
        requireHostedNativeVector(argv, environment, timeout, maximumOutputBytes, cleanupTimeout, label)
        return HostedNativeProcess(
            executable,
            role,
            argv,
            environment,
            workingDirectory,
            maximumOutputBytes,
            cleanupTimeout,
            label,
        ).execute(deadlineAfter(timeout))
    }
}

private class HostedNativeProcess(
    private val executable: HostedRetainedFile,
    private val role: HostedExecutableRole,
    private val arguments: List<String>,
    private val environment: Map<String, String>,
    private val workingDirectory: HostedPinnedDirectory,
    private val maximumOutputBytes: Int,
    private val cleanupTimeout: Duration,
    private val label: String,
) {
    private val attributes = Memory(HOSTED_OPAQUE_NATIVE_STORAGE_BYTES)
    private val fileActions = Memory(HOSTED_OPAQUE_NATIVE_STORAGE_BYTES)
    private var attributesInitialized = false
    private var fileActionsInitialized = false
    private var stdinFd = -1
    private var stdoutReadFd = -1
    private var stdoutWriteFd = -1
    private var stderrReadFd = -1
    private var stderrWriteFd = -1
    private val reservedStandardDescriptors = mutableListOf<Int>()
    private var pid = -1
    private var pidfd = -1
    private var reaped = false

    fun execute(commandDeadline: Long): HostedProcessResult {
        var primary: Throwable? = null
        try {
            requireHostedDeadline(commandDeadline, label)
            requireHostedPlatform()
            prepare(commandDeadline)
            spawn(commandDeadline)
            closeParentWriteEnds()
            makeOutputNonblocking(commandDeadline)
            val output = capture(commandDeadline)
            signalGroup(HOSTED_SIGKILL, commandDeadline, cleanup = false)
            val status = reap(commandDeadline, cleanup = false)
            val exitCode = when {
                hostedWaitExited(status) -> hostedWaitExitStatus(status)
                hostedWaitSignaled(status) -> 128 + hostedWaitTermSignal(status)
                else -> hostedFail("$label returned an unsupported wait status")
            }
            return HostedProcessResult(exitCode, output.first, output.second)
        } catch (failure: Throwable) {
            primary = failure
            if (pid > 0 && !reaped) {
                try {
                    cleanup(deadlineAfter(cleanupTimeout))
                } catch (cleanupFailure: Throwable) {
                    val wrapped = LlvmBehaviorHostedCleanBuildV2Exception(
                        "$label failed and its exact session leader could not be killed and reaped",
                        cleanupFailure,
                    )
                    wrapped.addSuppressed(failure)
                    primary = wrapped
                }
            }
            throw primary
        } finally {
            closeFd(stdoutReadFd)
            stdoutReadFd = -1
            closeFd(stdoutWriteFd)
            stdoutWriteFd = -1
            closeFd(stderrReadFd)
            stderrReadFd = -1
            closeFd(stderrWriteFd)
            stderrWriteFd = -1
            closeFd(stdinFd)
            stdinFd = -1
            reservedStandardDescriptors.forEach(::closeFd)
            reservedStandardDescriptors.clear()
            closeFd(pidfd)
            pidfd = -1
            if (fileActionsInitialized) HOSTED_LIBC.posix_spawn_file_actions_destroy(fileActions)
            if (attributesInitialized) HOSTED_LIBC.posix_spawnattr_destroy(attributes)
        }
    }

    private fun prepare(deadline: Long) {
        requireHostedDeadline(deadline, label)
        val attributesResult = HOSTED_LIBC.posix_spawnattr_init(attributes)
        if (attributesResult == 0) attributesInitialized = true
        hostedNativeResult("$label initialize spawn attributes", attributesResult)
        val defaults = Memory(HOSTED_SIGSET_BYTES)
        val mask = Memory(HOSTED_SIGSET_BYTES)
        hostedSyscall(label, "initialize default signals") { HOSTED_LIBC.sigfillset(defaults) }
        hostedSyscall(label, "exclude SIGKILL from defaults") { HOSTED_LIBC.sigdelset(defaults, HOSTED_SIGKILL) }
        hostedSyscall(label, "exclude SIGSTOP from defaults") { HOSTED_LIBC.sigdelset(defaults, HOSTED_SIGSTOP) }
        hostedSyscall(label, "initialize empty signal mask") { HOSTED_LIBC.sigemptyset(mask) }
        hostedNativeResult(
            "$label configure default signals",
            HOSTED_LIBC.posix_spawnattr_setsigdefault(attributes, defaults),
        )
        hostedNativeResult(
            "$label configure signal mask",
            HOSTED_LIBC.posix_spawnattr_setsigmask(attributes, mask),
        )
        hostedNativeResult(
            "$label configure fresh session",
            HOSTED_LIBC.posix_spawnattr_setflags(
                attributes,
                (HOSTED_POSIX_SPAWN_SETSID or HOSTED_POSIX_SPAWN_SETSIGDEF or
                    HOSTED_POSIX_SPAWN_SETSIGMASK).toShort(),
            ),
        )

        val actionsResult = HOSTED_LIBC.posix_spawn_file_actions_init(fileActions)
        if (actionsResult == 0) fileActionsInitialized = true
        hostedNativeResult("$label initialize spawn file actions", actionsResult)
        reserveClosedStandardDescriptors(deadline)
        stdinFd = hostedOpen(HOSTED_NULL_DEVICE, HOSTED_O_RDONLY or HOSTED_O_CLOEXEC, label)
        val stdoutPipe = createPipe("stdout", deadline)
        stdoutReadFd = stdoutPipe.first
        stdoutWriteFd = stdoutPipe.second
        val stderrPipe = createPipe("stderr", deadline)
        stderrReadFd = stderrPipe.first
        stderrWriteFd = stderrPipe.second
        hostedNativeResult(
            "$label bind stdin",
            HOSTED_LIBC.posix_spawn_file_actions_adddup2(fileActions, stdinFd, 0),
        )
        hostedNativeResult(
            "$label bind stdout",
            HOSTED_LIBC.posix_spawn_file_actions_adddup2(fileActions, stdoutWriteFd, 1),
        )
        hostedNativeResult(
            "$label bind stderr",
            HOSTED_LIBC.posix_spawn_file_actions_adddup2(fileActions, stderrWriteFd, 2),
        )
        listOf(stdinFd, stdoutReadFd, stdoutWriteFd, stderrReadFd, stderrWriteFd)
            .filter { it > 2 }.distinct().forEach { descriptor ->
            hostedNativeResult(
                "$label close surplus pipe descriptor",
                HOSTED_LIBC.posix_spawn_file_actions_addclose(fileActions, descriptor),
            )
        }
        workingDirectory.addWorkingDirectoryAction(fileActions, label)
        hostedNativeResult(
            "$label close inherited descriptors",
            HOSTED_LIBC.posix_spawn_file_actions_addclosefrom_np(fileActions, 3),
        )
        requireHostedDeadline(deadline, label)
    }

    private fun spawn(deadline: Long) {
        requireHostedDeadline(deadline, label)
        val pidStorage = Memory(Int.SIZE_BYTES.toLong())
        val argumentArray = StringArray(arguments.toTypedArray(), StandardCharsets.UTF_8.name())
        val environmentArray = StringArray(
            environment.entries.sortedBy { it.key }.map { (name, value) -> "$name=$value" }.toTypedArray(),
            StandardCharsets.UTF_8.name(),
        )
        val result = HOSTED_LIBC.posix_spawn(
            pidStorage,
            executable.executionCapability(label),
            fileActions,
            attributes,
            argumentArray,
            environmentArray,
        )
        if (result == 0) pid = pidStorage.getInt(0)
        hostedNativeResult("$label start exact retained ${role.argumentZero}", result)
        if (pid <= 0) hostedFail("$label returned an invalid process id")
        requireHostedDeadline(deadline, label)
        pidfd = hostedPidfdOpen(pid, deadline, label)
    }

    private fun capture(deadline: Long): Pair<ByteArray, ByteArray> {
        val stdout = HostedBoundedCapture(maximumOutputBytes, "$label stdout")
        val stderr = HostedBoundedCapture(maximumOutputBytes, "$label stderr")
        var leaderExited = false
        var exitedGroupSignaled = false
        while (true) {
            requireHostedDeadline(deadline, label)
            if (stdout.drain(stdoutReadFd, deadline)) stdoutReadFd = -1
            if (stderr.drain(stderrReadFd, deadline)) stderrReadFd = -1
            leaderExited = leaderExited || pidfdExited(deadline, cleanup = false)
            if (leaderExited) {
                if (!exitedGroupSignaled) {
                    signalGroup(HOSTED_SIGKILL, deadline, cleanup = false)
                    exitedGroupSignaled = true
                }
                if (stdoutReadFd < 0 && stderrReadFd < 0) {
                    val stdoutBytes = stdout.bytes()
                    val stderrBytes = stderr.bytes()
                    if (stdoutBytes.size.toLong() + stderrBytes.size.toLong() > maximumOutputBytes.toLong()) {
                        hostedFail("$label exceeded its aggregate output bound")
                    }
                    return stdoutBytes to stderrBytes
                }
            }
            pollOutput(if (leaderExited) HOSTED_POST_EXIT_POLL_MILLIS else HOSTED_ACTIVE_POLL_MILLIS, deadline)
        }
    }

    private fun cleanup(deadline: Long) {
        closeParentWriteEnds()
        closeFd(stdoutReadFd)
        stdoutReadFd = -1
        closeFd(stderrReadFd)
        stderrReadFd = -1
        var lastFailure: Throwable? = null
        while (true) {
            try {
                signalGroup(HOSTED_SIGKILL, deadline, cleanup = true)
                if (pidfd >= 0) signalPidfd(HOSTED_SIGKILL, deadline, cleanup = true)
                if ((pidfd >= 0 && pidfdExited(deadline, cleanup = true)) || leaderExitedWithoutReaping(deadline)) {
                    reap(deadline, cleanup = true)
                    return
                }
            } catch (failure: Throwable) {
                lastFailure = failure
            }
            if (System.nanoTime() >= deadline) {
                throw LlvmBehaviorHostedCleanBuildV2Exception("$label cleanup exceeded its deadline", lastFailure)
            }
            hostedSleep(deadline, HOSTED_CLEANUP_POLL_MILLIS, label, cleanup = true)
        }
    }

    private fun reap(deadline: Long, cleanup: Boolean): Int {
        val status = Memory(Int.SIZE_BYTES.toLong())
        var attempted = false
        while (true) {
            if (attempted) requireHostedDeadline(deadline, label, cleanup)
            val result = HOSTED_LIBC.waitpid(pid, status, HOSTED_WNOHANG)
            val error = if (result < 0) Native.getLastError() else 0
            attempted = true
            when {
                result == pid -> {
                    reaped = true
                    requireHostedDeadline(deadline, label, cleanup)
                    return status.getInt(0)
                }
                result == 0 -> hostedSleep(deadline, HOSTED_CLEANUP_POLL_MILLIS, label, cleanup)
                error == HOSTED_EINTR -> requireHostedDeadline(deadline, label, cleanup)
                else -> throw IOException("$label waitpid failed with errno $error")
            }
        }
    }

    private fun signalGroup(signal: Int, deadline: Long, cleanup: Boolean) {
        while (true) {
            requireHostedDeadline(deadline, label, cleanup)
            val result = HOSTED_LIBC.kill(-pid, signal)
            val error = if (result != 0) Native.getLastError() else 0
            if (result == 0 || error == HOSTED_ESRCH) return
            if (error != HOSTED_EINTR) throw IOException("$label process-group signal failed with errno $error")
        }
    }

    private fun signalPidfd(signal: Int, deadline: Long, cleanup: Boolean) {
        while (true) {
            requireHostedDeadline(deadline, label, cleanup)
            val result = HOSTED_LIBC.pidfd_send_signal(pidfd, signal, null, 0)
            val error = if (result != 0) Native.getLastError() else 0
            if (result == 0 || error == HOSTED_ESRCH) return
            if (error != HOSTED_EINTR) throw IOException("$label pidfd signal failed with errno $error")
        }
    }

    private fun pidfdExited(deadline: Long, cleanup: Boolean): Boolean {
        val poll = Memory(HOSTED_POLLFD_BYTES.toLong())
        poll.setInt(0, pidfd)
        poll.setShort(Int.SIZE_BYTES.toLong(), HOSTED_POLLIN.toShort())
        while (true) {
            requireHostedDeadline(deadline, label, cleanup)
            val result = HOSTED_LIBC.poll(poll, NativeLong(1), 0)
            val error = if (result < 0) Native.getLastError() else 0
            if (result >= 0) {
                val events = poll.getShort((Int.SIZE_BYTES + Short.SIZE_BYTES).toLong()).toInt() and 0xffff
                if (events and HOSTED_POLLNVAL != 0) hostedFail("$label pidfd poll observed an invalid descriptor")
                return result > 0 && events and (HOSTED_POLLIN or HOSTED_POLLHUP or HOSTED_POLLERR) != 0
            }
            if (error != HOSTED_EINTR) throw IOException("$label pidfd poll failed with errno $error")
        }
    }

    private fun pollOutput(maximumMillis: Int, deadline: Long) {
        val descriptors = listOf(stdoutReadFd, stderrReadFd).filter { it >= 0 }
        if (descriptors.isEmpty()) {
            hostedSleep(deadline, maximumMillis.toLong(), label, cleanup = false)
            return
        }
        val poll = Memory((descriptors.size * HOSTED_POLLFD_BYTES).toLong())
        descriptors.forEachIndexed { index, descriptor ->
            val offset = (index * HOSTED_POLLFD_BYTES).toLong()
            poll.setInt(offset, descriptor)
            poll.setShort(offset + Int.SIZE_BYTES, HOSTED_POLLIN.toShort())
        }
        while (true) {
            requireHostedDeadline(deadline, label)
            val remainingMillis = ((deadline - System.nanoTime()).coerceAtLeast(1L) / 1_000_000L)
                .coerceIn(1L, maximumMillis.toLong()).toInt()
            val result = HOSTED_LIBC.poll(poll, NativeLong(descriptors.size.toLong()), remainingMillis)
            val error = if (result < 0) Native.getLastError() else 0
            if (result >= 0) {
                descriptors.indices.forEach { index ->
                    val events = poll.getShort(
                        (index * HOSTED_POLLFD_BYTES + Int.SIZE_BYTES + Short.SIZE_BYTES).toLong(),
                    ).toInt() and 0xffff
                    if (events and HOSTED_POLLNVAL != 0) {
                        hostedFail("$label output poll observed an invalid descriptor")
                    }
                }
                return
            }
            if (error != HOSTED_EINTR) throw IOException("$label output poll failed with errno $error")
        }
    }

    private fun leaderExitedWithoutReaping(deadline: Long): Boolean {
        requireHostedDeadline(deadline, label, cleanup = true)
        val stat = try {
            Files.readString(Path.of("/proc", pid.toString(), "stat"))
        } catch (_: java.nio.file.NoSuchFileException) {
            return true
        }
        if (stat.toByteArray(StandardCharsets.UTF_8).size > HOSTED_MAXIMUM_PROC_STAT_BYTES) {
            hostedFail("$label proc status exceeds its bound")
        }
        val commandEnd = stat.lastIndexOf(") ")
        if (commandEnd < 0 || commandEnd + 2 >= stat.length) hostedFail("$label proc status is malformed")
        return stat[commandEnd + 2] in setOf('Z', 'X', 'x')
    }

    private fun createPipe(stream: String, deadline: Long): Pair<Int, Int> {
        requireHostedDeadline(deadline, label)
        val descriptors = Memory((2 * Int.SIZE_BYTES).toLong())
        val result = HOSTED_LIBC.pipe2(descriptors, HOSTED_O_CLOEXEC)
        if (result != 0) throw IOException("$label $stream pipe creation failed with errno ${Native.getLastError()}")
        val pipe = descriptors.getInt(0) to descriptors.getInt(Int.SIZE_BYTES.toLong())
        try {
            requireHostedDeadline(deadline, label)
            return pipe
        } catch (failure: Throwable) {
            closeFd(pipe.first)
            closeFd(pipe.second)
            throw failure
        }
    }

    private fun reserveClosedStandardDescriptors(deadline: Long) {
        for (target in 0..2) {
            requireHostedDeadline(deadline, label)
            val result = HOSTED_LIBC.fcntl(target, HOSTED_F_GETFD, 0)
            if (result >= 0) continue
            val error = Native.getLastError()
            if (error != HOSTED_EBADF) throw IOException("$label stdio inspection failed with errno $error")
            val opened = hostedOpen(HOSTED_NULL_DEVICE, HOSTED_O_RDWR or HOSTED_O_CLOEXEC, label)
            if (opened != target) {
                closeFd(opened)
                hostedFail("$label could not reserve closed standard descriptor $target")
            }
            reservedStandardDescriptors += opened
        }
    }

    private fun makeOutputNonblocking(deadline: Long) {
        requireHostedDeadline(deadline, label)
        listOf(stdoutReadFd, stderrReadFd).forEach { descriptor ->
            val flags = HOSTED_LIBC.fcntl(descriptor, HOSTED_F_GETFL, 0)
            if (flags < 0) throw IOException("$label output flags are unavailable")
            if (HOSTED_LIBC.fcntl(descriptor, HOSTED_F_SETFL, flags or HOSTED_O_NONBLOCK) < 0) {
                throw IOException("$label could not make output nonblocking")
            }
        }
    }

    private fun closeParentWriteEnds() {
        closeFd(stdinFd)
        stdinFd = -1
        closeFd(stdoutWriteFd)
        stdoutWriteFd = -1
        closeFd(stderrWriteFd)
        stderrWriteFd = -1
    }

    private fun closeFd(fd: Int) {
        if (fd >= 0) HOSTED_LIBC.close(fd)
    }
}

private class HostedBoundedCapture(private val maximumBytes: Int, private val label: String) {
    private val output = ByteArrayOutputStream(minOf(maximumBytes, PROCESS_BUFFER_BYTES))
    private val buffer = Memory(PROCESS_BUFFER_BYTES.toLong())

    fun drain(descriptor: Int, deadline: Long): Boolean {
        if (descriptor < 0) return true
        while (true) {
            requireHostedDeadline(deadline, label)
            val count = HOSTED_LIBC.read(
                descriptor,
                buffer,
                NativeLong(PROCESS_BUFFER_BYTES.toLong()),
            ).toLong()
            val error = if (count < 0L) Native.getLastError() else 0
            when {
                count > 0L -> {
                    if (count > maximumBytes.toLong() - output.size().toLong()) {
                        hostedFail("$label exceeded its output bound")
                    }
                    output.write(buffer.getByteArray(0, count.toInt()))
                }
                count == 0L -> {
                    HOSTED_LIBC.close(descriptor)
                    return true
                }
                error == HOSTED_EINTR -> continue
                error == HOSTED_EAGAIN -> return false
                else -> throw IOException("$label output read failed with errno $error")
            }
        }
    }

    fun bytes(): ByteArray = output.toByteArray()
}

private interface HostedLibC : Library {
    fun memfd_create(name: String, flags: Int): Int
    fun open(path: String, flags: Int): Int
    fun close(fd: Int): Int
    fun read(fd: Int, buffer: Pointer, count: NativeLong): NativeLong
    fun write(fd: Int, buffer: Pointer, count: NativeLong): NativeLong
    fun fsync(fd: Int): Int
    fun fchmod(fd: Int, mode: Int): Int
    fun fcntl(fd: Int, command: Int, argument: Int): Int
    fun pipe2(descriptors: Pointer, flags: Int): Int
    fun poll(descriptors: Pointer, count: NativeLong, timeoutMilliseconds: Int): Int
    fun kill(pid: Int, signal: Int): Int
    fun waitpid(pid: Int, status: Pointer, options: Int): Int
    fun pidfd_open(pid: Int, flags: Int): Int
    fun pidfd_send_signal(pidfd: Int, signal: Int, info: Pointer?, flags: Int): Int
    fun sigfillset(set: Pointer): Int
    fun sigemptyset(set: Pointer): Int
    fun sigdelset(set: Pointer, signal: Int): Int
    fun posix_spawnattr_init(attributes: Pointer): Int
    fun posix_spawnattr_destroy(attributes: Pointer): Int
    fun posix_spawnattr_setflags(attributes: Pointer, flags: Short): Int
    fun posix_spawnattr_setsigdefault(attributes: Pointer, signals: Pointer): Int
    fun posix_spawnattr_setsigmask(attributes: Pointer, signals: Pointer): Int
    fun posix_spawn_file_actions_init(actions: Pointer): Int
    fun posix_spawn_file_actions_destroy(actions: Pointer): Int
    fun posix_spawn_file_actions_adddup2(actions: Pointer, descriptor: Int, target: Int): Int
    fun posix_spawn_file_actions_addclose(actions: Pointer, descriptor: Int): Int
    fun posix_spawn_file_actions_addclosefrom_np(actions: Pointer, firstDescriptor: Int): Int
    fun posix_spawn_file_actions_addfchdir_np(actions: Pointer, descriptor: Int): Int
    fun posix_spawn(
        pid: Pointer,
        path: String,
        actions: Pointer,
        attributes: Pointer,
        arguments: Pointer,
        environment: Pointer,
    ): Int
}

private val HOSTED_LIBC: HostedLibC by lazy { Native.load(Platform.C_LIBRARY_NAME, HostedLibC::class.java) }
private val HOSTED_PARENT_PID: Long = ProcessHandle.current().pid()

private fun createHostedMemfd(executable: Boolean, label: String): Int {
    requireHostedPlatform()
    val flags = HOSTED_MFD_CLOEXEC or HOSTED_MFD_ALLOW_SEALING or
        if (executable) HOSTED_MFD_EXEC else 0
    while (true) {
        val descriptor = HOSTED_LIBC.memfd_create("decomp-hosted-retained", flags)
        if (descriptor >= 0) return descriptor
        val error = Native.getLastError()
        if (error != HOSTED_EINTR) {
            throw IOException("$label could not create an anonymous retained identity: errno $error")
        }
    }
}

private fun hostedWriteAll(descriptor: Int, bytes: ByteArray, count: Int, label: String) {
    var offset = 0
    val buffer = Memory(maxOf(1, minOf(count, DEFAULT_BUFFER_SIZE)).toLong())
    while (offset < count) {
        val amount = minOf(count - offset, DEFAULT_BUFFER_SIZE)
        buffer.write(0, bytes, offset, amount)
        var written = 0
        while (written < amount) {
            val result = HOSTED_LIBC.write(
                descriptor,
                buffer.share(written.toLong()),
                NativeLong((amount - written).toLong()),
            ).toLong()
            if (result > 0L) {
                written += result.toInt()
            } else if (result < 0L && Native.getLastError() == HOSTED_EINTR) {
                continue
            } else {
                throw IOException("$label anonymous write failed with errno ${Native.getLastError()}")
            }
        }
        offset += amount
    }
}

private fun hostedFcntlSeals(descriptor: Int, label: String) {
    val seals = HOSTED_F_SEAL_SEAL or HOSTED_F_SEAL_SHRINK or HOSTED_F_SEAL_GROW or HOSTED_F_SEAL_WRITE
    while (true) {
        if (HOSTED_LIBC.fcntl(descriptor, HOSTED_F_ADD_SEALS, seals) >= 0) break
        val error = Native.getLastError()
        if (error != HOSTED_EINTR) throw IOException("$label could not be sealed: errno $error")
    }
    val observed = HOSTED_LIBC.fcntl(descriptor, HOSTED_F_GET_SEALS, 0)
    if (observed < 0 || observed and seals != seals) hostedFail("$label did not retain all required write seals")
}

private fun readRetainedIdentity(descriptor: Int, maximumBytes: Long, label: String): BuildOutputIdentity {
    val bytes = readRetainedBytes(descriptor, maximumBytes, label)
    return BuildOutputIdentity(bytes.size.toLong(), OracleArtifacts.sha256(bytes))
}

private fun readRetainedBytes(descriptor: Int, maximumBytes: Long, label: String): ByteArray {
    if (maximumBytes !in 1L..Int.MAX_VALUE.toLong()) hostedFail("$label has an unsupported read bound")
    val output = ByteArrayOutputStream(minOf(maximumBytes.toInt(), PROCESS_BUFFER_BYTES))
    Files.newInputStream(Path.of(hostedDescriptorPath(descriptor)), StandardOpenOption.READ).use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            if (output.size().toLong() + count.toLong() > maximumBytes) hostedFail("$label exceeds its byte bound")
            output.write(buffer, 0, count)
        }
    }
    return output.toByteArray()
}

private fun hostedDescriptorPath(descriptor: Int): String =
    "/proc/$HOSTED_PARENT_PID/fd/$descriptor"

private fun hostedOpen(path: String, flags: Int, label: String): Int {
    while (true) {
        val descriptor = HOSTED_LIBC.open(path, flags)
        if (descriptor >= 0) return descriptor
        val error = Native.getLastError()
        if (error != HOSTED_EINTR) throw IOException("$label open failed with errno $error")
    }
}

private inline fun hostedSyscall(label: String, operation: String, invocation: () -> Int) {
    while (true) {
        val result = invocation()
        if (result == 0) return
        val error = Native.getLastError()
        if (error != HOSTED_EINTR) throw IOException("$label $operation failed with errno $error")
    }
}

private fun hostedNativeResult(operation: String, result: Int) {
    if (result != 0) throw IOException("$operation failed with errno $result")
}

private fun hostedPidfdOpen(pid: Int, deadline: Long, label: String): Int {
    while (true) {
        requireHostedDeadline(deadline, label)
        val descriptor = HOSTED_LIBC.pidfd_open(pid, 0)
        if (descriptor >= 0) return descriptor
        val error = Native.getLastError()
        if (error != HOSTED_EINTR) throw IOException("$label could not pin its process with pidfd: errno $error")
    }
}

private fun requireHostedPlatform() {
    if (System.getProperty("os.name", "") != "Linux" ||
        System.getProperty("os.arch", "") !in setOf("amd64", "x86_64") ||
        !Files.isDirectory(Path.of("/proc/self/fd"))
    ) {
        hostedFail("hosted retained execution requires Linux x86-64 procfs")
    }
}

private fun requireHostedNativeVector(
    arguments: List<String>,
    environment: Map<String, String>,
    timeout: Duration,
    maximumOutputBytes: Int,
    cleanupTimeout: Duration,
    label: String,
) {
    if (arguments.isEmpty() || arguments.size > MAXIMUM_HOSTED_ARGUMENTS ||
        arguments.any { it.isEmpty() || '\u0000' in it ||
            it.toByteArray(StandardCharsets.UTF_8).size > MAXIMUM_HOSTED_NATIVE_STRING_BYTES }
    ) hostedFail("$label argv is invalid or outside its count/string bound")
    val argumentBytes = arguments.sumOf { it.toByteArray(StandardCharsets.UTF_8).size.toLong() + 1L }
    if (argumentBytes > MAXIMUM_HOSTED_ARGUMENT_BYTES) hostedFail("$label argv exceeds its aggregate byte bound")
    if (environment.size > MAXIMUM_HOSTED_ENVIRONMENT_BINDINGS ||
        environment.keys.any { !it.matches(HOSTED_ENVIRONMENT_NAME) } ||
        environment.entries.any { '\u0000' in it.value } ||
        environment.keys.any { it.startsWith("LD_") } ||
        environment.keys.any { it in FORBIDDEN_HOSTED_ENVIRONMENT_NAMES }
    ) hostedFail("$label environment is not closed and deterministic")
    val environmentBytes = environment.entries.sumOf { (name, value) ->
        name.toByteArray(StandardCharsets.UTF_8).size.toLong() +
            value.toByteArray(StandardCharsets.UTF_8).size.toLong() + 2L
    }
    if (environmentBytes > MAXIMUM_HOSTED_ENVIRONMENT_BYTES) hostedFail("$label environment exceeds its byte bound")
    if (timeout.isZero || timeout.isNegative || timeout > BUILD_COMMAND_TIMEOUT ||
        cleanupTimeout.isZero || cleanupTimeout.isNegative || cleanupTimeout > PROCESS_CLEANUP_TIMEOUT ||
        maximumOutputBytes !in 0..MAXIMUM_COMMAND_OUTPUT_BYTES
    ) hostedFail("$label runtime or capture bound is invalid")
}

private fun requireHostedDeadline(deadline: Long, label: String, cleanup: Boolean = false) {
    if (System.nanoTime() < deadline) return
    hostedFail(if (cleanup) "$label cleanup exceeded its deadline" else "$label exceeded its deadline")
}

private fun hostedSleep(deadline: Long, maximumMillis: Long, label: String, cleanup: Boolean) {
    requireHostedDeadline(deadline, label, cleanup)
    val remainingNanos = deadline - System.nanoTime()
    val millis = minOf(maximumMillis, maxOf(0L, remainingNanos / 1_000_000L))
    if (millis > 0L) Thread.sleep(millis) else Thread.onSpinWait()
    requireHostedDeadline(deadline, label, cleanup)
}

private fun hostedWaitExited(status: Int): Boolean = status and 0x7f == 0
private fun hostedWaitExitStatus(status: Int): Int = status ushr 8 and 0xff
private fun hostedWaitSignaled(status: Int): Boolean = status and 0x7f in 1..0x7e
private fun hostedWaitTermSignal(status: Int): Int = status and 0x7f

private data class BuildOutputIdentity(val bytes: Long, val sha256: String)

private data class HostedDependency(val path: String, val bytes: Long, val sha256: String)

private data class HostedCandidateInput(
    val relativePath: String,
    val identity: BuildOutputIdentity,
    val retained: HostedRetainedFile,
)

private data class HostedBuildObject(
    val relativePath: String,
    val retained: HostedRetainedFile,
    val identity: BuildOutputIdentity,
)

private enum class HostedLinkRole(val queryFileName: String, val factRole: String) {
    SCRT1("Scrt1.o", "startup-scrt1"),
    CRTI("crti.o", "startup-crti"),
    CRTBEGIN_S("crtbeginS.o", "startup-crtbegin-s"),
    LIBGCC_A("libgcc.a", "compiler-runtime-libgcc-a"),
    LIBGCC_S("libgcc_s.so.1", "compiler-runtime-libgcc-s"),
    LIBC_SO_6("libc.so.6", "libc-shared"),
    LIBC_NONSHARED("libc_nonshared.a", "libc-nonshared"),
    LOADER("ld-linux-x86-64.so.2", "runtime-loader"),
    CRTEND_S("crtendS.o", "termination-crtend-s"),
    CRTN("crtn.o", "termination-crtn"),
}

private data class HostedLinkInput(
    val role: HostedLinkRole,
    val resolution: String,
    val originalPath: Path,
    val identity: BuildOutputIdentity,
    val retained: HostedRetainedFile,
)

private data class HostedCommittedLinkInput(
    val role: String,
    val resolution: String,
    val logicalPath: String,
    val bytes: Long,
    val sha256: String,
)

private class HostedLinkPlan(private val inputs: Map<HostedLinkRole, HostedLinkInput>) : AutoCloseable {
    fun input(role: HostedLinkRole): HostedLinkInput =
        inputs[role] ?: hostedFail("direct LLD link plan is missing ${role.factRole}")

    fun capability(role: HostedLinkRole): String =
        input(role).retained.capabilityPath("retained ${role.factRole} link input")

    fun committedEntries(objects: List<HostedBuildObject>): List<HostedCommittedLinkInput> = buildList {
        fun system(role: HostedLinkRole, occurrence: String = role.factRole) {
            val input = input(role)
            add(
                HostedCommittedLinkInput(
                    occurrence,
                    input.resolution,
                    "system:${input.originalPath}",
                    input.identity.bytes,
                    input.identity.sha256,
                ),
            )
        }
        system(HostedLinkRole.LOADER)
        system(HostedLinkRole.SCRT1)
        system(HostedLinkRole.CRTI)
        system(HostedLinkRole.CRTBEGIN_S)
        objects.forEachIndexed { index, objectFile ->
            add(
                HostedCommittedLinkInput(
                    "object[$index]",
                    "sealed-retained-clang-output",
                    "object:${objectFile.relativePath}",
                    objectFile.identity.bytes,
                    objectFile.identity.sha256,
                ),
            )
        }
        system(HostedLinkRole.LIBGCC_A, "compiler-runtime-libgcc-a-before-libc")
        system(HostedLinkRole.LIBGCC_S, "compiler-runtime-libgcc-s-before-libc")
        system(HostedLinkRole.LIBC_SO_6)
        system(HostedLinkRole.LIBC_NONSHARED)
        system(HostedLinkRole.LIBGCC_A, "compiler-runtime-libgcc-a-after-libc")
        system(HostedLinkRole.LIBGCC_S, "compiler-runtime-libgcc-s-after-libc")
        system(HostedLinkRole.CRTEND_S)
        system(HostedLinkRole.CRTN)
    }

    override fun close() {
        inputs.values.toList().asReversed().forEach { runCatching(it.retained::close) }
    }
}

private fun adoptCandidateInputs(
    sourceRoot: Path,
    revision: BuildSourceRevision,
): List<HostedCandidateInput> {
    val selected = revision.inputs.filter { it.path.startsWith("src/") || it.path.startsWith("include/") }
    if (selected.isEmpty() || selected.size > MAXIMUM_CANDIDATE_INPUT_COUNT) {
        hostedFail("candidate compiler-input fanout is outside its descriptor-safe bound")
    }
    val adopted = ArrayList<HostedCandidateInput>(selected.size)
    var aggregateBytes = 0L
    try {
        selected.forEach { expected ->
            if (!expected.path.matches(CANDIDATE_INPUT_PATH) ||
                expected.bytes !in 1L..MAXIMUM_CANDIDATE_INPUT_BYTES
            ) hostedFail("candidate compiler input ${expected.path} is outside its path/byte bound")
            aggregateBytes = Math.addExact(aggregateBytes, expected.bytes)
            if (aggregateBytes > MAXIMUM_AGGREGATE_CANDIDATE_INPUT_BYTES) {
                hostedFail("candidate compiler inputs exceed their aggregate byte bound")
            }
            val path = sourceRoot.resolve(expected.path).normalize()
            if (!path.startsWith(sourceRoot)) hostedFail("candidate compiler input escapes its source root")
            StableControlFile.open(path, MAXIMUM_CANDIDATE_INPUT_BYTES, "candidate compiler input").use { guard ->
                val sha256 = guard.sha256(label = "candidate compiler input ${expected.path}")
                if (guard.size != expected.bytes || sha256 != expected.sha256) {
                    hostedFail("candidate compiler input differs from its authenticated source revision")
                }
                val retained = HostedRetainedFile.snapshot(
                    guard,
                    expected.bytes,
                    expected.sha256,
                    executable = false,
                    label = "retained candidate compiler input",
                )
                try {
                    val text = decodeStrictUtf8(
                        retained.readBytes(MAXIMUM_CANDIDATE_INPUT_BYTES, "retained candidate compiler input"),
                        "authenticated compiler input ${expected.path}",
                    )
                    FORBIDDEN_COMPILER_INPUT_TOKENS.forEach { token ->
                        if (token in text) {
                            hostedFail("authenticated compiler input uses unsupported external-input token $token")
                        }
                    }
                    guard.verifyUnchanged("candidate compiler input ${expected.path}")
                    adopted += HostedCandidateInput(
                        expected.path,
                        BuildOutputIdentity(expected.bytes, expected.sha256),
                        retained,
                    )
                } catch (failure: Throwable) {
                    retained.close()
                    throw failure
                }
            }
        }
        return adopted
    } catch (failure: Throwable) {
        adopted.asReversed().forEach { runCatching(it.retained::close) }
        throw failure
    }
}

private fun createCandidateOverlay(inputs: List<HostedCandidateInput>): HostedRetainedFile {
    val roots = inputs.map { input ->
        jsonObject(
            "type" to JsonPrimitive("file"),
            "name" to JsonPrimitive(VIRTUAL_CANDIDATE_ROOT.resolve(input.relativePath).normalize().toString()),
            "use-external-name" to JsonPrimitive(false),
            "external-contents" to JsonPrimitive(input.retained.capabilityPath("candidate overlay input")),
        )
    }
    val document = jsonObject(
        "version" to JsonPrimitive(0),
        "case-sensitive" to JsonPrimitive(true),
        "use-external-names" to JsonPrimitive(false),
        "redirecting-with" to JsonPrimitive("fallthrough"),
        "roots" to JsonArray(roots),
    )
    val bytes = OracleJson.canonicalBytes(document, CANDIDATE_OVERLAY_JSON_LIMITS)
    return HostedRetainedFile.snapshot(bytes, executable = false, label = "candidate VFS overlay")
}

private fun requireCompilerResourceDirectory(compilerPath: Path): Path {
    val toolchainRoot = compilerPath.parent?.parent
        ?: hostedFail("authenticated Clang path has no reviewed resource-directory derivation")
    val candidate = listOf(
        toolchainRoot.resolve("lib/clang/$HOSTED_CLANG_RESOURCE_VERSION").normalize(),
        compilerPath.parent.resolve("../../../../lib/clang/$HOSTED_CLANG_RESOURCE_VERSION").normalize(),
    ).firstOrNull { Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) }
        ?: hostedFail("Clang resource directory is unavailable")
    val real = try {
        candidate.toRealPath()
    } catch (failure: Exception) {
        throw LlvmBehaviorHostedCleanBuildV2Exception("Clang resource directory is unavailable", failure)
    }
    if (real != candidate || !Files.isDirectory(real, LinkOption.NOFOLLOW_LINKS)) {
        hostedFail("Clang resource directory is not an exact canonical directory")
    }
    requireRootOwnedImmutablePath(real, directory = true, label = "Clang resource directory")
    return real
}

private fun resolveHostedLinkPlan(
    resourceDirectory: Path,
    adoptedTools: HostedAdoptedTools,
    environment: Map<String, String>,
    workingDirectory: HostedPinnedDirectory,
    tools: HostedTools,
    compilerGuard: StableControlFile,
    linkerGuard: StableControlFile,
    buildDeadline: Long,
): HostedLinkPlan {
    val inputs = linkedMapOf<HostedLinkRole, HostedLinkInput>()
    try {
        HostedLinkRole.entries.forEach { role ->
            val query = "--print-file-name=${role.queryFileName}"
            val result = runHostedCommand(
                HostedExecutableRole.CLANG,
                listOf(
                    "--no-default-config",
                    "--target=$HOSTED_TARGET_TRIPLE",
                    "-resource-dir=$resourceDirectory",
                    query,
                ),
                environment,
                workingDirectory,
                adoptedTools,
                tools,
                compilerGuard,
                linkerGuard,
                buildDeadline,
                "resolve fixed ${role.factRole} link input",
            )
            if (result.exitCode != 0 || result.stderr.isNotEmpty() || result.stdout.isEmpty() ||
                result.stdout.size > MAXIMUM_CLANG_QUERY_OUTPUT_BYTES
            ) hostedFail("fixed Clang query for ${role.factRole} failed or exceeded its output bound")
            val output = decodeStrictUtf8(result.stdout, "fixed Clang query for ${role.factRole}")
            if ('\r' in output || '\u0000' in output || !output.endsWith('\n') ||
                output.dropLast(1).contains('\n')
            ) hostedFail("fixed Clang query for ${role.factRole} did not return one exact line")
            val token = output.dropLast(1)
            val raw = try {
                Path.of(token)
            } catch (failure: Exception) {
                throw LlvmBehaviorHostedCleanBuildV2Exception(
                    "fixed Clang query for ${role.factRole} returned an invalid path",
                    failure,
                )
            }
            if (!raw.isAbsolute || raw.normalize().fileName?.toString() != role.queryFileName) {
                hostedFail("fixed Clang query for ${role.factRole} did not resolve its reviewed basename")
            }
            val real = try {
                raw.toRealPath()
            } catch (failure: Exception) {
                throw LlvmBehaviorHostedCleanBuildV2Exception(
                    "fixed Clang query for ${role.factRole} returned an unavailable input",
                    failure,
                )
            }
            if (real.fileName?.toString() != role.queryFileName) {
                hostedFail("fixed Clang query for ${role.factRole} changed basename after canonicalization")
            }
            val input = adoptSystemLinkInput(role, query, real)
            if (inputs.put(role, input) != null) hostedFail("fixed link plan repeats ${role.factRole}")
        }
        if (inputs.keys != HostedLinkRole.entries.toSet()) hostedFail("fixed direct LLD link plan is incomplete")
        return HostedLinkPlan(inputs)
    } catch (failure: Throwable) {
        inputs.values.toList().asReversed().forEach { runCatching(it.retained::close) }
        throw failure
    }
}

private fun adoptSystemLinkInput(
    role: HostedLinkRole,
    query: String,
    real: Path,
): HostedLinkInput {
    if (!real.isAbsolute || real.normalize() != real || real.toRealPath() != real) {
        hostedFail("${role.factRole} link input is not canonical")
    }
    val allowed = SYSTEM_LIBRARY_ROOTS.any { root ->
        try {
            Files.isDirectory(root) && real.startsWith(root.toRealPath())
        } catch (_: Exception) {
            false
        }
    }
    if (!allowed) hostedFail("${role.factRole} is outside reviewed container system-library roots")
    requireRootOwnedImmutablePath(real, directory = false, label = role.factRole)
    return StableControlFile.open(real, MAXIMUM_LINK_INPUT_BYTES, role.factRole).use { guard ->
        if (guard.size !in 1L..MAXIMUM_LINK_INPUT_BYTES) hostedFail("${role.factRole} exceeds its byte bound")
        val sha256 = guard.sha256(label = role.factRole)
        val retained = HostedRetainedFile.snapshot(
            guard,
            guard.size,
            sha256,
            executable = false,
            label = "retained ${role.factRole}",
        )
        try {
            guard.verifyUnchanged(role.factRole)
            HostedLinkInput(
                role,
                "clang-query:$query",
                real,
                BuildOutputIdentity(guard.size, sha256),
                retained,
            )
        } catch (failure: Throwable) {
            retained.close()
            throw failure
        }
    }
}

private fun requireRootOwnedImmutablePath(path: Path, directory: Boolean, label: String) {
    val attributes = readBasicAttributes(path, label)
    if (attributes.fileKey() == null || attributes.isSymbolicLink ||
        (directory && !attributes.isDirectory) || (!directory && !attributes.isRegularFile)
    ) hostedFail("$label is not the required canonical filesystem type")
    var current: Path? = path
    while (current != null) {
        val uid = (Files.getAttribute(current, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Number).toLong()
        val permissions = Files.getPosixFilePermissions(current, LinkOption.NOFOLLOW_LINKS)
        if (uid != 0L || permissions.any { it in UNTRUSTED_WRITE_PERMISSIONS }) {
            hostedFail("$label is not held below root-owned non-writable ancestors")
        }
        current = current.parent
    }
}

private fun inspectRetainedExecutable(
    bytes: ByteArray,
    identity: BuildOutputIdentity,
    buildRoot: Path,
): decompengine.oracle.provenance.BoundedElfArtifactV1 {
    if (bytes.size.toLong() != identity.bytes || OracleArtifacts.sha256(bytes) != identity.sha256) {
        hostedFail("candidate executable differs from its sealed retained identity")
    }
    val inspectionPath = buildRoot.resolve("candidate-elf-inspection").normalize()
    if (inspectionPath.parent != buildRoot || Files.exists(inspectionPath, LinkOption.NOFOLLOW_LINKS)) {
        hostedFail("private ELF inspection target is not fresh")
    }
    try {
        Files.write(inspectionPath, bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
        FileChannel.open(inspectionPath, StandardOpenOption.WRITE).use { it.force(true) }
        Files.setPosixFilePermissions(inspectionPath, OWNER_READ_ONLY_PERMISSIONS)
        return BoundedElfTwinV1.inspect(
            inspectionPath,
            BoundedElfTwinV1Limits(
                maximumFileBytes = MAXIMUM_EXECUTABLE_BYTES,
                maximumRangeBytes = MAXIMUM_EXECUTABLE_BYTES,
                maximumExecutableBytes = MAXIMUM_EXECUTABLE_BYTES,
                maximumAggregateHashedBytes = 2L * 1024L * 1024L * 1024L,
            ),
        )
    } finally {
        Files.deleteIfExists(inspectionPath)
    }
}

private fun requireHostedElf(
    elf: decompengine.oracle.provenance.BoundedElfArtifactV1,
    executableIdentity: BuildOutputIdentity,
) {
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
    ) hostedFail("candidate output is not the required executable little-endian x86-64 ELF64")
}

private fun authenticateCompilerDependencies(
    raw: ByteArray,
    expectedTarget: String,
    expectedSource: String,
    retainedSourceCapability: String,
    sourceRevision: BuildSourceRevision,
): List<HostedDependency> {
    if (raw.isEmpty() || raw.size.toLong() > MAXIMUM_DEPENDENCY_FILE_BYTES) {
        hostedFail("compiler dependency file is outside its byte bound")
    }
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
        val relative = when {
            token == retainedSourceCapability -> expectedSource
            token.startsWith("$VIRTUAL_CANDIDATE_ROOT/") -> token.removePrefix("$VIRTUAL_CANDIDATE_ROOT/")
            else -> null
        }
        val dependency = if (relative != null) {
            val expected = expectedInputs[relative]
                ?: hostedFail("compiler read an archive file outside the authenticated source revision: $relative")
            if (!relative.matches(CANDIDATE_INPUT_PATH)) {
                hostedFail("compiler dependency is not a canonical retained candidate input")
            }
            HostedDependency("source:$relative", expected.bytes, expected.sha256)
        } else {
            val rawPath = try {
                Path.of(token)
            } catch (failure: Exception) {
                throw LlvmBehaviorHostedCleanBuildV2Exception("compiler dependency path is invalid", failure)
            }
            if (!rawPath.isAbsolute || token.startsWith("/proc/")) {
                hostedFail("compiler consumed an unbound candidate or capability path")
            }
            authenticateSystemDependency(rawPath)
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
    requireRootOwnedImmutablePath(real, directory = false, label = "system-header dependency")
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

private fun boundedHostedFailureOutput(bytes: ByteArray): String {
    val bounded = if (bytes.size <= MAXIMUM_FAILURE_DIAGNOSTIC_BYTES) bytes else
        bytes.copyOf(MAXIMUM_FAILURE_DIAGNOSTIC_BYTES)
    return runCatching { decodeStrictUtf8(bounded, "hosted command failure output") }
        .getOrElse { "<non-UTF-8 output>" }
        .replace('\n', ' ')
        .trim()
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
    "compilerMode" to JsonPrimitive("retained-descriptor-clang-per-source"),
    "linkerMode" to JsonPrimitive("retained-descriptor-lld-direct"),
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
    "linkPlanInputCount" to JsonPrimitive(build.linkPlanInputCount),
    "linkPlanSha256" to JsonPrimitive(build.linkPlanSha256),
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
        guard.requireSingleLink(label)
    }
}

private fun requireToolGuard(tool: HostedTool, guard: StableControlFile, label: String) {
    if (guard.size != tool.bytes || guard.sha256(label = "authenticated $label") != tool.sha256) {
        hostedFail("authenticated $label bytes changed")
    }
    requireToolGuardMetadata(tool, guard, label)
}

private fun requireToolGuardMetadata(tool: HostedTool, guard: StableControlFile, label: String) {
    if (guard.size != tool.bytes) hostedFail("authenticated $label identity disagrees")
    guard.verifyUnchanged("authenticated $label")
    guard.requireSingleLink("authenticated $label")
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
private val GLOBAL_LOADER_PRELOAD_PATH = Path.of("/etc/ld.so.preload")
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
private const val MAXIMUM_SOURCE_COUNT = 128
private const val MAXIMUM_CANDIDATE_INPUT_COUNT = 256
private const val MAXIMUM_CANDIDATE_INPUT_BYTES = 16L * 1024L * 1024L
private const val MAXIMUM_AGGREGATE_CANDIDATE_INPUT_BYTES = 256L * 1024L * 1024L
private const val MAXIMUM_DEPENDENCIES = 1_000_000
private const val MAXIMUM_DEPENDENCY_FILE_BYTES = 16L * 1024L * 1024L
private const val MAXIMUM_DEPENDENCY_BYTES = 128L * 1024L * 1024L
private const val MAXIMUM_AGGREGATE_DEPENDENCY_BYTES = 2L * 1024L * 1024L * 1024L
private const val MAXIMUM_LINK_DEPENDENCIES = 4096
private const val MAXIMUM_LINK_INPUT_BYTES = 512L * 1024L * 1024L
private const val MAXIMUM_AGGREGATE_LINK_DEPENDENCY_BYTES = 2L * 1024L * 1024L * 1024L
private const val MAXIMUM_COMMAND_OUTPUT_BYTES = 64 * 1024 * 1024
private const val MAXIMUM_AGGREGATE_OUTPUT_BYTES = 16L * 1024L * 1024L * 1024L
private const val MAXIMUM_RETAINED_AUXILIARY_BYTES = 4L * 1024L * 1024L
private const val MAXIMUM_CLANG_QUERY_OUTPUT_BYTES = 16 * 1024
private const val MAXIMUM_FAILURE_DIAGNOSTIC_BYTES = 4096
private const val PROCESS_BUFFER_BYTES = 64 * 1024
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
private const val HOSTED_TARGET_TRIPLE = "x86_64-pc-linux-gnu"
private const val HOSTED_CLANG_RESOURCE_VERSION = "22"
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
private val FIXED_LOCAL_TEST_TOOLCHAINS = listOf(
    Path.of("/usr/lib/llvm/22/bin/clang-22") to Path.of("/usr/lib/llvm/22/bin/lld"),
    Path.of("/usr/lib/llvm-22/bin/clang") to Path.of("/usr/lib/llvm-22/bin/lld"),
)
private val OWNER_DIRECTORY_PERMISSIONS = setOf(
    PosixFilePermission.OWNER_READ,
    PosixFilePermission.OWNER_WRITE,
    PosixFilePermission.OWNER_EXECUTE,
)
private val OWNER_READ_ONLY_PERMISSIONS = setOf(PosixFilePermission.OWNER_READ)
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
private val DEPENDENCY_PATH_TOKEN = Regex("[A-Za-z0-9_+.,/@%:=~-]+")
private val CANDIDATE_INPUT_PATH = Regex("(?:src|include)/(?:[A-Za-z0-9_+.,@%=-]+/)*[A-Za-z0-9_+.,@%=-]+")
private val VIRTUAL_CANDIDATE_ROOT = Path.of("/decomp-candidate")
private val VIRTUAL_CANDIDATE_INCLUDE = VIRTUAL_CANDIDATE_ROOT.resolve("include")
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
private val CANDIDATE_OVERLAY_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_RETAINED_AUXILIARY_BYTES.toInt(),
    maximumCanonicalBytes = MAXIMUM_RETAINED_AUXILIARY_BYTES.toInt(),
    maximumDepth = 8,
    maximumNodes = 4096,
    maximumStringBytes = 16 * 1024,
    maximumTotalStringBytes = 2 * 1024 * 1024,
)
private val HOSTED_ENVIRONMENT_NAME = Regex("[A-Za-z_][A-Za-z0-9_]*")
private val FORBIDDEN_HOSTED_ENVIRONMENT_NAMES = setOf(
    "CPATH",
    "LIBRARY_PATH",
    "COMPILER_PATH",
    "GCC_EXEC_PREFIX",
    "HOME",
    "PWD",
    "GLIBC_TUNABLES",
)
private const val MAXIMUM_HOSTED_ARGUMENTS = 768
private const val MAXIMUM_HOSTED_ARGUMENT_BYTES = 256L * 1024L
private const val MAXIMUM_HOSTED_NATIVE_STRING_BYTES = 16 * 1024
private const val MAXIMUM_HOSTED_ENVIRONMENT_BINDINGS = 16
private const val MAXIMUM_HOSTED_ENVIRONMENT_BYTES = 64L * 1024L
private const val HOSTED_OPAQUE_NATIVE_STORAGE_BYTES = 4096L
private const val HOSTED_SIGSET_BYTES = 128L
private const val HOSTED_POLLFD_BYTES = 8
private const val HOSTED_ACTIVE_POLL_MILLIS = 25
private const val HOSTED_POST_EXIT_POLL_MILLIS = 5
private const val HOSTED_CLEANUP_POLL_MILLIS = 5L
private const val HOSTED_MAXIMUM_PROC_STAT_BYTES = 16 * 1024
private const val HOSTED_NULL_DEVICE = "/dev/null"
private const val HOSTED_POSIX_SPAWN_SETSIGDEF = 0x04
private const val HOSTED_POSIX_SPAWN_SETSIGMASK = 0x08
private const val HOSTED_POSIX_SPAWN_SETSID = 0x80
private const val HOSTED_MFD_CLOEXEC = 0x0001
private const val HOSTED_MFD_ALLOW_SEALING = 0x0002
private const val HOSTED_MFD_EXEC = 0x0010
private const val HOSTED_F_ADD_SEALS = 1033
private const val HOSTED_F_GET_SEALS = 1034
private const val HOSTED_F_SEAL_SEAL = 0x0001
private const val HOSTED_F_SEAL_SHRINK = 0x0002
private const val HOSTED_F_SEAL_GROW = 0x0004
private const val HOSTED_F_SEAL_WRITE = 0x0008
private const val HOSTED_MODE_READ_ONLY = 0x100
private const val HOSTED_MODE_READ_EXECUTE = 0x140
private const val HOSTED_O_RDONLY = 0
private const val HOSTED_O_RDWR = 2
private const val HOSTED_O_NONBLOCK = 0x800
private const val HOSTED_O_DIRECTORY = 0x10000
private const val HOSTED_O_NOFOLLOW = 0x20000
private const val HOSTED_O_CLOEXEC = 0x80000
private const val HOSTED_F_GETFD = 1
private const val HOSTED_F_GETFL = 3
private const val HOSTED_F_SETFL = 4
private const val HOSTED_POLLIN = 0x001
private const val HOSTED_POLLERR = 0x008
private const val HOSTED_POLLHUP = 0x010
private const val HOSTED_POLLNVAL = 0x020
private const val HOSTED_WNOHANG = 1
private const val HOSTED_SIGKILL = 9
private const val HOSTED_SIGSTOP = 19
private const val HOSTED_EINTR = 4
private const val HOSTED_EBADF = 9
private const val HOSTED_EAGAIN = 11
private const val HOSTED_ESRCH = 3
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
