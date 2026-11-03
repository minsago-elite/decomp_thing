package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.project.GlobalTypeObservationBindingsV1
import decompengine.project.GlobalTypeObservationSummaryV1
import decompengine.project.GlobalTypeObservationsV1
import decompengine.project.NativeInferredInterfaceBindingsV1
import decompengine.project.NativeInferredInterfaceObservationLimitsV1
import decompengine.project.NativeInferredInterfaceObservationsV1
import decompengine.project.NativeInferredInterfaceSummaryV1
import decompengine.project.NativeInterfaceAddressV1
import decompengine.project.NativeInterfaceBindingsV1
import decompengine.project.NativeInterfaceObservationsV1
import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Independently retained deployment identities supplied by the guarded coordinator, not report fields. */
internal data class GccBundledInterfaceCaptureBindingsV1(
    val listingCollectorSha256: String,
    val inferredCollectorSha256: String,
    val typeGraphSha256: String,
    val wrapperSha256: String,
    val nativeDecompilerSha256: String,
    val deploymentClosureSha256: String,
    val runtimeIdentitySha256: String,
    val componentClosureSha256: String,
    val globalTypeCollectorSha256: String? = null,
    val globalTypeRuntimeIdentitySha256: String? = null,
) {
    init {
        listOf(listingCollectorSha256, inferredCollectorSha256, typeGraphSha256, wrapperSha256,
            nativeDecompilerSha256, deploymentClosureSha256, runtimeIdentitySha256, componentClosureSha256)
            .forEach { require(it.matches(Regex("[a-f0-9]{64}"))) { "invalid interface capture runtime commitment" } }
        require((globalTypeCollectorSha256 == null) == (globalTypeRuntimeIdentitySha256 == null))
        listOfNotNull(globalTypeCollectorSha256, globalTypeRuntimeIdentitySha256).forEach {
            require(it.matches(Regex("[a-f0-9]{64}"))) { "invalid global/type capture runtime commitment" }
        }
    }
}

internal data class GccInterfaceCapturedFileV1(val identity: LinuxFileIdentity, val metadata: Map<String, Any>)
internal data class GccInterfaceCapturedDirectoryV1(val identity: LinuxFileIdentity, val entries: Set<String>?)

/**
 * Immutable recovered bytes and complete descriptor-set commitments. This is deliberately raw
 * evidence: only factory membership and the exact live completed owner can issue an owned operation.
 * Command streams are descriptor-owned content commitments in the later assessment; the worker
 * outcome independently authenticates their lengths, not their content hashes.
 */
internal class GccBundledInferredInterfaceSnapshot internal constructor(
    val model: GccBundledFullExportSnapshot,
    val summary: NativeInferredInterfaceSummaryV1,
    target: GccBundledInterfaceTargetEvidenceV1,
    val runtime: GccBundledInterfaceCaptureBindingsV1,
    val runIdentity: LinuxFileIdentity,
    val controlName: String,
    directories: Map<String, GccInterfaceCapturedDirectoryV1>,
    files: Map<String, GccInterfaceCapturedFileV1>,
    val capturedBytes: Long,
    listingManifest: ByteArray,
    listingObservations: ByteArray,
    inferredManifest: ByteArray,
    inferredObservations: ByteArray,
    stdout: ByteArray,
    stderr: ByteArray,
    assessment: ByteArray,
    globalTypeObservations: ByteArray? = null,
    val globalTypeSummary: GlobalTypeObservationSummaryV1? = null,
) {
    val target = target.copy(executableRanges = java.util.List.copyOf(target.executableRanges))
    internal val directories = Collections.unmodifiableMap(directories.mapValues { (_, pin) ->
        pin.copy(entries = pin.entries?.let { Collections.unmodifiableSet(LinkedHashSet(it)) })
    })
    internal val files = Collections.unmodifiableMap(files.mapValues { (_, pin) ->
        pin.copy(metadata = Collections.unmodifiableMap(HashMap(pin.metadata)))
    })
    private val listingManifestValue = listingManifest.copyOf()
    private val listingObservationsValue = listingObservations.copyOf()
    private val inferredManifestValue = inferredManifest.copyOf()
    private val inferredObservationsValue = inferredObservations.copyOf()
    private val stdoutValue = stdout.copyOf()
    private val stderrValue = stderr.copyOf()
    private val assessmentValue = assessment.copyOf()
    private val globalTypeObservationsValue = globalTypeObservations?.copyOf()
    val listingManifestBytes: ByteArray get() = listingManifestValue.copyOf()
    val listingObservationsBytes: ByteArray get() = listingObservationsValue.copyOf()
    val inferredManifestBytes: ByteArray get() = inferredManifestValue.copyOf()
    val inferredObservationsBytes: ByteArray get() = inferredObservationsValue.copyOf()
    val stdoutBytes: ByteArray get() = stdoutValue.copyOf()
    val stderrBytes: ByteArray get() = stderrValue.copyOf()
    val stdoutByteCount: Long = stdoutValue.size.toLong()
    val stderrByteCount: Long = stderrValue.size.toLong()
    val stdoutSha256: String = OracleArtifacts.sha256(stdoutValue)
    val stderrSha256: String = OracleArtifacts.sha256(stderrValue)
    val programModelBytes: ByteArray get() = model.programModel
    val assessmentBytes: ByteArray get() = assessmentValue.copyOf()
    val globalTypeObservationsBytes: ByteArray? get() = globalTypeObservationsValue?.copyOf()
    val completeObservedNativeCensus = true
    val complete = false
    val authoritativeOracleEvidence = false
    val productionInterfacesAdmitted = false
    val scored = false
    val releaseEligible = false
}

/**
 * The caller retains the same live run lease and has already authenticated worker/unit/cgroup
 * absence. The complete reports tree and the two fixed control/report streams share one aggregate;
 * zero-length streams remain required regular files. No callback can run after the final complete
 * metadata sweep. No path reopener escapes.
 */
internal object GccBundledInferredInterfaceCapture {
    internal const val LISTING_DIRECTORY = "native-interfaces-v1"
    internal const val INFERRED_DIRECTORY = "native-inferred-interfaces-v1"
    private const val REPORTS = "reports"
    private const val EXPORT = "$REPORTS/program_model.json.export"
    private const val LISTING = "$REPORTS/$LISTING_DIRECTORY"
    private const val INFERRED = "$REPORTS/$INFERRED_DIRECTORY"
    private const val MODEL_FILE = "$REPORTS/program_model.json"
    private const val LISTING_FILE = "$LISTING/native-interfaces.json"
    private const val LISTING_MANIFEST = "$LISTING/manifest.json"
    private const val INFERRED_FILE = "$INFERRED/native-inferred-interfaces.json"
    private const val INFERRED_MANIFEST = "$INFERRED/manifest.json"
    private const val GLOBAL_TYPE_FILE = "$REPORTS/native-global-type-observations-v1.json"
    private const val MAXIMUM_FILES = 300_009
    internal const val MAXIMUM_STREAM_BYTES = 64 * 1024 * 1024
    private val STREAM_NAMES = setOf("contained-command.stdout", "contained-command.stderr")
    private val BASE_REPORT_NAMES = setOf("program_model.json.export", "program_model.json", "program_model.json.progress.json", LISTING_DIRECTORY, INFERRED_DIRECTORY)
    private val EXPORT_NAMES = setOf("state.json", "planning-batches", "functions", "globals", "types", "failures")
    private val DATA_DIRECTORIES = listOf("functions", "globals", "types", "failures")
    private val BASE_SIDECARS = listOf(LISTING_MANIFEST, LISTING_FILE, INFERRED_MANIFEST, INFERRED_FILE)

    fun capture(
        run: LinuxDescriptor,
        expectedReports: LinuxFileIdentity,
        controlName: String,
        expectedControl: LinuxFileIdentity,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        target: GccBundledInterfaceTargetEvidenceV1,
        runtime: GccBundledInterfaceCaptureBindingsV1,
        limits: NativeInferredInterfaceObservationLimitsV1 = NativeInferredInterfaceObservationLimitsV1(),
        checkpoint: () -> Unit,
    ): GccBundledInferredInterfaceSnapshot = run.whileOpen {
        checkpoint()
        require(controlName.matches(Regex("control-[a-f0-9]{64}")))
        requireTarget(target)
        val runIdentity = LinuxFilesystemSyscalls.identity(run.fd)
        require(runIdentity.copy(linkCount = run.identity.linkCount) == run.identity) { "interface run descriptor changed identity" }
        requirePrivateDirectory(runIdentity, runIdentity)
        val globalTypes = runtime.globalTypeCollectorSha256 != null
        val sidecars = BASE_SIDECARS + if (globalTypes) listOf(GLOBAL_TYPE_FILE) else emptyList()
        openTree(run, controlName, expectedControl, expectedReports, globalTypes).use { tree ->
            val pinned = pinTree(tree, limits, globalTypes, checkpoint)
            val model = if (globalTypes) GccBundledFullExportCapture.captureWithGlobalTypeSiblings(run, expectedReports, artifacts,
                fullLimits(limits), checkpoint) else GccBundledFullExportCapture.captureWithInterfaceSiblings(run, expectedReports, artifacts,
                fullLimits(limits), checkpoint)
            require(model.inputSha256 == target.inputSha256 && model.inputBytes == target.inputBytes &&
                model.language == target.languageId && model.compilerSpec == target.compilerSpecId) {
                "interface capture target differs from the admitted complete model"
            }
            val streamPaths = STREAM_NAMES.map { "$controlName/reports/$it" }
            val siblingBytes = (sidecars + streamPaths).sumOf { size(pinned.files.getValue(it)) }
            require(model.capturedBytes <= limits.maximumCombinedBytes - siblingBytes &&
                model.capturedBytes + siblingBytes == pinned.bytes && model.outputFileCount + sidecars.size + STREAM_NAMES.size == pinned.files.size.toLong()) {
                "interface capture aggregate does not include exactly the complete full-export tree, both siblings and both command streams"
            }
            val modelBytes = model.programModel
            require(OracleArtifacts.sha256(modelBytes) == model.programModelSha256)
            val listingManifest = readPinned(tree, LISTING_MANIFEST, pinned.files.getValue(LISTING_MANIFEST), limits.maximumManifestBytes, checkpoint)
            val listingBytes = readPinned(tree, LISTING_FILE, pinned.files.getValue(LISTING_FILE), remainingFileBound(limits, pinned, LISTING_FILE), checkpoint)
            val inferredManifest = readPinned(tree, INFERRED_MANIFEST, pinned.files.getValue(INFERRED_MANIFEST), limits.maximumManifestBytes, checkpoint)
            val inferredBytes = readPinned(tree, INFERRED_FILE, pinned.files.getValue(INFERRED_FILE), remainingFileBound(limits, pinned, INFERRED_FILE), checkpoint)
            val globalTypeBytes = if (globalTypes) readPinned(tree, GLOBAL_TYPE_FILE, pinned.files.getValue(GLOBAL_TYPE_FILE),
                minOf(64L * 1024 * 1024, remainingFileBound(limits, pinned, GLOBAL_TYPE_FILE).toLong()).toInt(), checkpoint) else null
            val stdoutPath = "$controlName/reports/contained-command.stdout"
            val stderrPath = "$controlName/reports/contained-command.stderr"
            val stdout = readPinned(tree, stdoutPath, pinned.files.getValue(stdoutPath), MAXIMUM_STREAM_BYTES, checkpoint, allowEmpty = true)
            val stderr = readPinned(tree, stderrPath, pinned.files.getValue(stderrPath), MAXIMUM_STREAM_BYTES, checkpoint, allowEmpty = true)
            // The report's ordinal cannot authenticate a native address space. Select it only by
            // the independently admitted full descriptor, then reuse the complete mapping reader.
            val listingSummary = NativeInterfaceObservationsV1.validateBoundToSpaces(listingManifest,
                expectedBindings = { spaces ->
                    val expected = target.defaultAddressSpace
                    val selected = spaces.singleOrNull { space ->
                        space.name == expected.name && space.type == expected.type && space.sizeBits == expected.sizeBits &&
                            space.addressableUnitSize == expected.addressableUnitSize && space.overlay == expected.overlay &&
                            space.signedOffsets == expected.signedOffsets
                    } ?: error("interface address table lacks the independently admitted default RAM space")
                    NativeInterfaceBindingsV1(runtime.listingCollectorSha256, target.compilerSpecId, model.analysisToolSha256,
                        NativeInterfaceAddressV1(selected.index, target.imageBase.toString(16).padStart(16, '0')),
                        target.inputSha256, target.languageId, model.programModelBytes, model.exporterSha256, model.programModelSha256)
                }, programModelBytes = modelBytes, limits = limits.listingLimits(), checkpoint = checkpoint,
                openObservations = { ByteArrayInputStream(listingBytes) })
            val expected = NativeInferredInterfaceBindingsV1(listingSummary.bindings, runtime.inferredCollectorSha256,
                runtime.wrapperSha256, runtime.nativeDecompilerSha256, listingBytes.size.toLong(), OracleArtifacts.sha256(listingBytes),
                OracleArtifacts.sha256(listingManifest), NativeInferredInterfaceObservationsV1.configurationSha256, runtime.typeGraphSha256)
            val summary = NativeInferredInterfaceObservationsV1.validate(inferredManifest, expected, modelBytes,
                listingManifest, limits, checkpoint, { ByteArrayInputStream(listingBytes) }, { ByteArrayInputStream(inferredBytes) })
            require(summary.listing == listingSummary) { "interface validation changed the exact listing/model census" }
            val globalTypeSummary = if (globalTypeBytes != null) {
                val globalReferenceFunctionIds = listingSummary.observedFunctions.map { observed ->
                    val offset = requireNotNull(observed.entry.offsetBits) {
                        "global/type function reference owner has no independently validated listing entry"
                    }
                    require(offset.matches(Regex("[a-f0-9]{16}"))) {
                        "global/type function reference owner has a malformed listing entry"
                    }
                    "fn_$offset"
                }.toSet().also { require(it.size == listingSummary.observedFunctions.size) {
                    "global/type function owner IDs collide in the independently validated listing population"
                } }
                val selectedSpace = listingSummary.addressSpaces.singleOrNull { space ->
                    space.name == target.defaultAddressSpace.name && space.type == target.defaultAddressSpace.type &&
                        space.sizeBits == target.defaultAddressSpace.sizeBits && space.addressableUnitSize == target.defaultAddressSpace.addressableUnitSize &&
                        space.overlay == target.defaultAddressSpace.overlay && space.signedOffsets == target.defaultAddressSpace.signedOffsets
                } ?: error("global/type capture target address space is absent from the independently admitted listing profile")
                GlobalTypeObservationsV1.validate(GlobalTypeObservationBindingsV1(
                    inputSha256 = target.inputSha256, exporterSha256 = model.exporterSha256,
                    archiveSha256 = model.analysisToolSha256, programModelBytes = model.programModelBytes,
                    programModelSha256 = model.programModelSha256, languageId = target.languageId,
                    compilerSpecId = target.compilerSpecId,
                    imageBase = "as${selectedSpace.index}@${target.imageBase.toString(16).padStart(16, '0')}",
                ), globalTypeBytes.size.toLong(), OracleArtifacts.sha256(globalTypeBytes),
                    expectedFunctionIds = globalReferenceFunctionIds, checkpoint = checkpoint,
                    openObservations = { ByteArrayInputStream(globalTypeBytes) })
                    .also { require(it.functionsInCapture == listingSummary.observedFunctions.size.toLong()) {
                        "global/type function census differs from the independently validated listing population"
                    } }
            } else null
            val assessment = assessment(model, summary, target, runtime, controlName, runIdentity, pinned,
                listingManifest, inferredManifest, stdout, stderr, globalTypeSummary, globalTypeBytes, checkpoint)
            val snapshot = GccBundledInferredInterfaceSnapshot(model, summary, target, runtime, runIdentity, controlName,
                pinned.directories, pinned.files, pinned.bytes, listingManifest, listingBytes, inferredManifest, inferredBytes, stdout, stderr, assessment,
                globalTypeBytes, globalTypeSummary)
            checkpoint()
            verifyWholeSet(run, tree, runIdentity, pinned.directories, pinned.files)
            // No user/owner callback, hashing, parsing, or mutation-capable action follows this sweep.
            snapshot
        }
    }

    /** Revalidate the retained tree before durable publication. The caller still owns absence and lease. */
    fun requireUnchanged(
        run: LinuxDescriptor,
        captured: GccBundledInferredInterfaceSnapshot,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        checkpoint: () -> Unit,
    ) = run.whileOpen {
        checkpoint()
        val expectedReports = captured.directories.getValue(REPORTS).identity
        val expectedControl = captured.directories.getValue(captured.controlName).identity
        val globalTypes = captured.runtime.globalTypeCollectorSha256 != null
        openTree(run, captured.controlName, expectedControl, expectedReports, globalTypes).use { tree ->
            val current = if (globalTypes) GccBundledFullExportCapture.captureWithGlobalTypeSiblings(run, expectedReports, artifacts,
                GccResumeByteValidationLimits(transitionAggregateBytes = captured.capturedBytes), checkpoint)
            else GccBundledFullExportCapture.captureWithInterfaceSiblings(run, expectedReports, artifacts,
                GccResumeByteValidationLimits(transitionAggregateBytes = captured.capturedBytes), checkpoint)
            require(current.assessmentBytes.contentEquals(captured.model.assessmentBytes) &&
                current.sidecarManifest.contentEquals(captured.model.sidecarManifest)) { "interface paired full-export tree changed" }
            val expectedDigests = mapOf(
                LISTING_MANIFEST to captured.summary.bindings.listingManifestSha256,
                LISTING_FILE to captured.summary.bindings.listingSha256,
                INFERRED_MANIFEST to OracleArtifacts.sha256(captured.inferredManifestBytes),
                INFERRED_FILE to captured.summary.manifest.sha256,
                "${captured.controlName}/reports/contained-command.stdout" to captured.stdoutSha256,
                "${captured.controlName}/reports/contained-command.stderr" to captured.stderrSha256,
            ) + (captured.globalTypeObservationsBytes?.let { mapOf(GLOBAL_TYPE_FILE to OracleArtifacts.sha256(it)) } ?: emptyMap())
            for ((path, digest) in expectedDigests) {
                requireDigest(tree, path, captured.files.getValue(path), digest, checkpoint)
            }
            checkpoint()
            verifyWholeSet(run, tree, captured.runIdentity, captured.directories, captured.files)
        }
    }

    private data class PinnedTree(val directories: Map<String, GccInterfaceCapturedDirectoryV1>, val files: Map<String, GccInterfaceCapturedFileV1>, val bytes: Long)
    private class Tree(val run: LinuxDescriptor, val descriptors: Map<String, LinuxDescriptor>) : AutoCloseable {
        fun directory(path: String) = descriptors.getValue(path)
        fun file(path: String): Pair<LinuxDescriptor, String> = directory(path.substringBeforeLast('/')) to path.substringAfterLast('/')
        override fun close() { descriptors.values.toList().asReversed().forEach(LinuxDescriptor::close) }
    }

    private fun openTree(run: LinuxDescriptor, controlName: String, expectedControl: LinuxFileIdentity,
        expectedReports: LinuxFileIdentity, globalTypes: Boolean): Tree {
        val open = linkedMapOf<String, LinuxDescriptor>()
        try {
            fun directory(path: String, private: Boolean): LinuxDescriptor {
                val parentPath = path.substringBeforeLast('/', "")
                val parent = if (parentPath.isEmpty()) run else open.getValue(parentPath)
                val descriptor = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, path.substringAfterLast('/'))
                open[path] = descriptor
                if (private) requirePrivateDirectory(descriptor.identity, run.identity)
                else requireExportDirectory(descriptor.identity, run.identity)
                return descriptor
            }
            require(directory(controlName, true).identity == expectedControl) { "interface control directory differs from completed execution" }
            directory("$controlName/reports", true).also { requireNames(it, STREAM_NAMES) }
            val reports = directory(REPORTS, true)
            require(reports.identity.copy(linkCount = expectedReports.linkCount) == expectedReports) { "interface reports directory changed identity" }
            val reportNames = BASE_REPORT_NAMES + if (globalTypes) setOf(GLOBAL_TYPE_FILE.substringAfterLast('/')) else emptySet()
            requireNames(reports, reportNames)
            directory(EXPORT, false).also { requireNames(it, EXPORT_NAMES) }
            directory("$EXPORT/planning-batches", false).also { requireNames(it, emptySet()) }
            DATA_DIRECTORIES.forEach { directory("$EXPORT/$it", false) }
            directory(LISTING, true).also { requireNames(it, setOf("manifest.json", "native-interfaces.json")) }
            directory(INFERRED, true).also { requireNames(it, setOf("manifest.json", "native-inferred-interfaces.json")) }
            return Tree(run, open)
        } catch (failure: Throwable) {
            open.values.toList().asReversed().forEach(LinuxDescriptor::close)
            throw failure
        }
    }

    private fun pinTree(tree: Tree, limits: NativeInferredInterfaceObservationLimitsV1, globalTypes: Boolean,
        checkpoint: () -> Unit): PinnedTree {
        val directories = linkedMapOf<String, GccInterfaceCapturedDirectoryV1>()
        val paths = arrayListOf(MODEL_FILE, "$REPORTS/program_model.json.progress.json", "$EXPORT/state.json")
        for ((path, directory) in tree.descriptors) {
            checkpoint()
            val names = when {
                path.startsWith("control-") && path.endsWith("/reports") -> {
                    paths += STREAM_NAMES.sorted().map { "$path/$it" }
                    STREAM_NAMES
                }
                path.startsWith("control-") -> null
                path == REPORTS -> BASE_REPORT_NAMES + if (globalTypes) setOf(GLOBAL_TYPE_FILE.substringAfterLast('/')) else emptySet()
                path == EXPORT -> EXPORT_NAMES
                path == "$EXPORT/planning-batches" -> emptySet()
                path == LISTING -> setOf("manifest.json", "native-interfaces.json")
                path == INFERRED -> setOf("manifest.json", "native-inferred-interfaces.json")
                else -> {
                    val entries = LinuxFilesystemSyscalls.directoryEntryNames(directory,
                        GccBundledFullExportCapture.MAXIMUM_FULL_FUNCTIONS.toInt() + 1)
                    require(entries.size <= GccBundledFullExportCapture.MAXIMUM_FULL_FUNCTIONS && entries.distinct().size == entries.size)
                    require(entries.all { it.length <= 256 && it.endsWith(".json") && it.none { c -> c == '/' || c == '\\' || c.code < 32 } })
                    require(paths.size <= MAXIMUM_FILES - entries.size) { "interface full-tree file count exceeds its bound" }
                    paths += entries.sorted().map { "$path/$it" }
                    entries.toSet()
                }
            }
            names?.let { requireNames(directory, it) }
            directories[path] = GccInterfaceCapturedDirectoryV1(directory.identity, names)
        }
        val sidecars = BASE_SIDECARS + if (globalTypes) listOf(GLOBAL_TYPE_FILE) else emptyList()
        paths += sidecars
        require(paths.size <= MAXIMUM_FILES)
        val files = linkedMapOf<String, GccInterfaceCapturedFileV1>()
        val identities = hashSetOf<Triple<Long, Long, Long>>()
        var total = 0L
        for (path in paths.sorted()) {
            checkpoint()
            val (directory, name) = tree.file(path)
            val pin = pinFile(directory, name)
            val size = size(pin)
            val maximum = when {
                path.startsWith("control-") -> MAXIMUM_STREAM_BYTES.toLong()
                path in setOf(LISTING_MANIFEST, INFERRED_MANIFEST) -> limits.maximumManifestBytes.toLong()
                path == GLOBAL_TYPE_FILE -> 64L * 1024 * 1024
                path == MODEL_FILE -> limits.maximumModelBytes.toLong()
                path.startsWith("$EXPORT/functions/") -> GccBundledFullExportCapture.MAXIMUM_FULL_FUNCTION_RECORD_BYTES.toLong()
                path.startsWith("$EXPORT/globals/") || path.startsWith("$EXPORT/types/") || path.startsWith("$EXPORT/failures/") -> GccBundledFullExportCapture.MAXIMUM_FULL_EVIDENCE_RECORD_BYTES.toLong()
                path == "$EXPORT/state.json" -> GccResumeByteValidationLimits().exporterStateBytes.toLong()
                path == "$REPORTS/program_model.json.progress.json" -> GccResumeByteValidationLimits().progressBytes.toLong()
                else -> limits.maximumCombinedBytes
            }
            require(size in 0..maximum && size <= limits.maximumCombinedBytes - total) { "interface complete-tree inventory exceeds its single aggregate or file bound" }
            require(path !in sidecars || size > 0) { "interface sibling must not be empty" }
            total += size
            require(identities.add(Triple(pin.identity.key.device, pin.identity.key.inode, pin.identity.mountId))) { "interface capture files alias" }
            files[path] = pin
        }
        return PinnedTree(directories, files, total)
    }

    private fun verifyWholeSet(run: LinuxDescriptor, tree: Tree, expectedRun: LinuxFileIdentity,
        directories: Map<String, GccInterfaceCapturedDirectoryV1>, files: Map<String, GccInterfaceCapturedFileV1>) {
        require(LinuxFilesystemSyscalls.identity(run.fd) == expectedRun) { "interface run root changed during capture" }
        require(tree.descriptors.keys == directories.keys)
        for ((path, pin) in directories) {
            val parentPath = path.substringBeforeLast('/', "")
            val parent = if (parentPath.isEmpty()) run else tree.directory(parentPath)
            LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, path.substringAfterLast('/')).use { named ->
                require(named.identity == pin.identity && LinuxFilesystemSyscalls.identity(tree.directory(path).fd) == pin.identity) { "interface directory changed identity" }
            }
            pin.entries?.let { requireNames(tree.directory(path), it) }
        }
        for ((path, pin) in files) {
            val (directory, name) = tree.file(path)
            openPinnedFile(directory, name, pin).use { }
        }
    }

    private fun readPinned(tree: Tree, path: String, pin: GccInterfaceCapturedFileV1, maximumBytes: Int,
        checkpoint: () -> Unit, allowEmpty: Boolean = false): ByteArray {
        val (directory, name) = tree.file(path)
        require(size(pin) in (if (allowEmpty) 0L else 1L)..maximumBytes.toLong())
        return openPinnedFile(directory, name, pin).use { file ->
            LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(file).use { readable ->
                FileChannel.open(LinuxFilesystemSyscalls.stableDescriptorPath(readable.fd), StandardOpenOption.READ).use { channel ->
                    // Allocate the exact pinned length, never the one-GiB ceiling.
                    val result = ByteArray(size(pin).toInt())
                    val buffer = ByteBuffer.wrap(result)
                    while (buffer.hasRemaining()) {
                        checkpoint()
                        val end = buffer.limit(); buffer.limit(buffer.position() + minOf(buffer.remaining(), 64 * 1024))
                        try { require(channel.read(buffer) > 0) { "interface sibling was truncated" } }
                        finally { buffer.limit(end) }
                    }
                    checkpoint(); require(channel.read(ByteBuffer.allocate(1)) == -1) { "interface sibling grew during capture" }
                    openPinnedFile(directory, name, pin).use { }
                    result
                }
            }
        }
    }

    private fun requireDigest(tree: Tree, path: String, pin: GccInterfaceCapturedFileV1, expected: String, checkpoint: () -> Unit) {
        val (directory, name) = tree.file(path)
        openPinnedFile(directory, name, pin).use { file ->
            LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(file).use { readable ->
                FileChannel.open(LinuxFilesystemSyscalls.stableDescriptorPath(readable.fd), StandardOpenOption.READ).use { channel ->
                    val digest = MessageDigest.getInstance("SHA-256"); val buffer = ByteBuffer.allocate(64 * 1024); var bytes = 0L
                    while (true) {
                        checkpoint(); val count = channel.read(buffer); if (count == -1) break
                        require(count > 0 && bytes <= size(pin) - count) { "interface sibling changed length" }
                        bytes += count; digest.update(buffer.array(), 0, count); buffer.clear()
                    }
                    require(bytes == size(pin) && digest.digest().hex() == expected) { "interface sibling changed content" }
                }
            }
        }
        openPinnedFile(directory, name, pin).use { }
    }

    private fun pinFile(directory: LinuxDescriptor, name: String): GccInterfaceCapturedFileV1 =
        requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, name)).use { file ->
            val id = file.identity
            require(id.isRegularFile && !id.isSymbolicLink && id.linkCount == 1 && id.uid == directory.identity.uid &&
                id.mountId == directory.identity.mountId && id.mode.permissions and 0x12 == 0) {
                "interface output is not an owned single-link regular file on the retained mount"
            }
            GccInterfaceCapturedFileV1(id, metadata(file))
        }
    private fun openPinnedFile(directory: LinuxDescriptor, name: String, pin: GccInterfaceCapturedFileV1): LinuxDescriptor {
        val file = requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, name))
        try {
            require(file.identity == pin.identity && metadata(file) == pin.metadata) { "interface file changed identity or metadata" }
            return file
        } catch (failure: Throwable) { file.close(); throw failure }
    }
    private fun metadata(file: LinuxDescriptor): Map<String, Any> = Files.readAttributes(LinuxFilesystemSyscalls.stableDescriptorPath(file.fd), "unix:size,lastModifiedTime,ctime")
    private fun size(pin: GccInterfaceCapturedFileV1) = pin.metadata.getValue("size") as Long
    private fun requireNames(directory: LinuxDescriptor, expected: Set<String>) {
        require(LinuxFilesystemSyscalls.directoryEntryNames(directory, expected.size + 1).toSet() == expected) { "interface capture inventory has missing or unexpected entries" }
    }
    private fun requirePrivateDirectory(id: LinuxFileIdentity, parent: LinuxFileIdentity) {
        requireExportDirectory(id, parent)
        require(id.mode.permissions == 448) { "interface run and sibling directories must be private" }
    }
    private fun requireExportDirectory(id: LinuxFileIdentity, parent: LinuxFileIdentity) {
        require(id.isDirectory && !id.isSymbolicLink && id.uid == parent.uid && id.mountId == parent.mountId && id.mode.permissions and 0x12 == 0) {
            "interface capture directory violates retained full-export ownership"
        }
    }
    private fun requireTarget(target: GccBundledInterfaceTargetEvidenceV1) {
        require(target.engineId == "driver" && target.profileSha256.matches(Regex("[a-f0-9]{64}")) &&
            target.inputSha256.matches(Regex("[a-f0-9]{64}")) && target.inputBytes > 0 && target.profileTarget.isNotEmpty())
        require(target.languageId.isNotEmpty() && target.compilerSpecId.isNotEmpty())
        val space = target.defaultAddressSpace
        require(space.name.isNotEmpty() && space.type in setOf(1, 2, 7, 13) && !space.overlay && space.sizeBits in 1..64 && space.addressableUnitSize > 0)
    }
    private fun fullLimits(limits: NativeInferredInterfaceObservationLimitsV1) = GccResumeByteValidationLimits(
        assembledModelBytes = limits.maximumModelBytes, transitionAggregateBytes = limits.maximumCombinedBytes)
    private fun remainingFileBound(limits: NativeInferredInterfaceObservationLimitsV1, pinned: PinnedTree, path: String): Int {
        val bytes = size(pinned.files.getValue(path))
        require(bytes in 1..(limits.maximumCombinedBytes - (pinned.bytes - bytes)))
        return bytes.toInt()
    }

    private fun assessment(model: GccBundledFullExportSnapshot, summary: NativeInferredInterfaceSummaryV1,
        target: GccBundledInterfaceTargetEvidenceV1, runtime: GccBundledInterfaceCaptureBindingsV1, controlName: String,
        runIdentity: LinuxFileIdentity, pinned: PinnedTree, listingManifest: ByteArray, inferredManifest: ByteArray,
        stdout: ByteArray, stderr: ByteArray, globalTypeSummary: GlobalTypeObservationSummaryV1?,
        globalTypeBytes: ByteArray?, checkpoint: () -> Unit): ByteArray {
        val pinsDigest = MessageDigest.getInstance("SHA-256")
        for ((path, pin) in pinned.files) {
            checkpoint()
            pinsDigest.update(OracleJson.canonicalBytes(JsonObject(mapOf(
            "path" to JsonPrimitive(path), "identity" to identity(pin.identity),
            "metadata" to JsonObject(pin.metadata.mapValues { JsonPrimitive(it.value.toString()) })))))
        }
        val globalTypeFields = if (globalTypeSummary != null && globalTypeBytes != null) mapOf(
            "globalTypeCollectorSha256" to JsonPrimitive(checkNotNull(runtime.globalTypeCollectorSha256)),
            "globalTypeRuntimeIdentitySha256" to JsonPrimitive(checkNotNull(runtime.globalTypeRuntimeIdentitySha256)),
            "globalTypeObservationsBytes" to JsonPrimitive(globalTypeBytes.size),
            "globalTypeObservationsSha256" to JsonPrimitive(OracleArtifacts.sha256(globalTypeBytes)),
            "definedDataEntities" to JsonPrimitive(globalTypeSummary.definedDataEntities),
            "globalTypeNodes" to JsonPrimitive(globalTypeSummary.typeNodes),
            "globalTypeEdges" to JsonPrimitive(globalTypeSummary.typeEdges),
            "globalEnumMembers" to JsonPrimitive(globalTypeSummary.enumMembers),
            "functionGlobalReferences" to JsonPrimitive(globalTypeSummary.functionGlobalReferences),
            "unresolvedFunctionGlobalReferences" to JsonPrimitive(globalTypeSummary.unresolvedFunctionGlobalReferences),
            "globalTypeAuthorityBoundary" to JsonPrimitive(globalTypeSummary.authorityBoundary),
            "globalTypePopulationBoundary" to JsonPrimitive(globalTypeSummary.populationBoundary),
            "globalTypeSuppliedListingCensusState" to JsonPrimitive(globalTypeSummary.suppliedListingCensusState),
        ) else emptyMap()
        val fields = JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-bundled-descriptor-inferred-interface-assessment-v1"), "schemaVersion" to JsonPrimitive(1),
            "byteAssessmentAuthority" to JsonPrimitive("non-authoritative-byte-assessment"), "complete" to JsonPrimitive(false),
            "completeObservedNativeCensus" to JsonPrimitive(true), "authoritativeOracleEvidence" to JsonPrimitive(false),
            "productionInterfacesAdmitted" to JsonPrimitive(false), "scored" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
            "compilerEngineProfileSha256" to JsonPrimitive(target.profileSha256), "profileTarget" to JsonPrimitive(target.profileTarget),
            "inputSha256" to JsonPrimitive(model.inputSha256), "inputBytes" to JsonPrimitive(model.inputBytes),
            "imageBase" to JsonPrimitive(target.imageBase.toString(16).padStart(16, '0')),
            "languageId" to JsonPrimitive(target.languageId), "compilerSpecId" to JsonPrimitive(target.compilerSpecId),
            "defaultAddressSpace" to JsonObject(mapOf("name" to JsonPrimitive(target.defaultAddressSpace.name),
                "type" to JsonPrimitive(target.defaultAddressSpace.type), "sizeBits" to JsonPrimitive(target.defaultAddressSpace.sizeBits),
                "addressableUnitSize" to JsonPrimitive(target.defaultAddressSpace.addressableUnitSize),
                "overlay" to JsonPrimitive(target.defaultAddressSpace.overlay), "signedOffsets" to JsonPrimitive(target.defaultAddressSpace.signedOffsets))),
            "executableRanges" to JsonArray(target.executableRanges.map { JsonObject(mapOf(
                "startRva" to JsonPrimitive(it.start.toString(16).padStart(16, '0')),
                "endExclusiveRva" to JsonPrimitive(it.endExclusive.toString(16).padStart(16, '0')))) }),
            "programModelSha256" to JsonPrimitive(model.programModelSha256), "programModelBytes" to JsonPrimitive(model.programModelBytes),
            "fullOutputTreeSha256" to JsonPrimitive(model.outputTreeSha256), "fullOutputFileCount" to JsonPrimitive(model.outputFileCount),
            "fullCapturedBytes" to JsonPrimitive(model.capturedBytes), "capturedBytes" to JsonPrimitive(pinned.bytes),
            "stdoutBytes" to JsonPrimitive(stdout.size), "stdoutSha256" to JsonPrimitive(OracleArtifacts.sha256(stdout)),
            "stderrBytes" to JsonPrimitive(stderr.size), "stderrSha256" to JsonPrimitive(OracleArtifacts.sha256(stderr)),
            "modelAssessmentSha256" to JsonPrimitive(OracleArtifacts.sha256(model.assessmentBytes)),
            "listingCollectorSha256" to JsonPrimitive(runtime.listingCollectorSha256), "inferredCollectorSha256" to JsonPrimitive(runtime.inferredCollectorSha256),
            "typeGraphSha256" to JsonPrimitive(runtime.typeGraphSha256), "wrapperSha256" to JsonPrimitive(runtime.wrapperSha256),
            "nativeDecompilerSha256" to JsonPrimitive(runtime.nativeDecompilerSha256), "configurationSha256" to JsonPrimitive(summary.bindings.configurationSha256),
            "deploymentClosureSha256" to JsonPrimitive(runtime.deploymentClosureSha256), "runtimeIdentitySha256" to JsonPrimitive(runtime.runtimeIdentitySha256),
            "componentClosureSha256" to JsonPrimitive(runtime.componentClosureSha256),
            "listingSha256" to JsonPrimitive(summary.bindings.listingSha256), "listingBytes" to JsonPrimitive(summary.bindings.listingBytes),
            "listingManifestSha256" to JsonPrimitive(OracleArtifacts.sha256(listingManifest)), "listingManifestBytes" to JsonPrimitive(listingManifest.size),
            "inferredSha256" to JsonPrimitive(summary.manifest.sha256), "inferredBytes" to JsonPrimitive(summary.manifest.bytes),
            "inferredManifestSha256" to JsonPrimitive(OracleArtifacts.sha256(inferredManifest)), "inferredManifestBytes" to JsonPrimitive(inferredManifest.size),
            "modelFunctionCount" to JsonPrimitive(summary.listing.modelFunctions.size), "nativeFunctionCount" to JsonPrimitive(summary.scan.functions),
            "internalFunctions" to JsonPrimitive(summary.scan.internalFunctions), "externalFunctions" to JsonPrimitive(summary.scan.externalFunctions),
            "thunks" to JsonPrimitive(summary.scan.thunks), "observed" to JsonPrimitive(summary.scan.observed), "attempted" to JsonPrimitive(summary.scan.attempted),
            "parameters" to JsonPrimitive(summary.scan.parameters), "roots" to JsonPrimitive(summary.scan.roots),
            "storageVarnodes" to JsonPrimitive(summary.scan.storageVarnodes), "graphNodes" to JsonPrimitive(summary.scan.graphNodes),
            "graphEdges" to JsonPrimitive(summary.scan.graphEdges), "graphWork" to JsonPrimitive(summary.scan.graphWork),
            "dispositions" to JsonObject(summary.scan.dispositions.mapValues { JsonPrimitive(it.value) }),
            "modelMappingStates" to JsonObject(summary.listing.modelFunctions.groupingBy { it.state }.eachCount().mapValues { JsonPrimitive(it.value) }),
            "nativeMappingStates" to JsonObject(summary.listing.observedFunctions.groupingBy { it.state }.eachCount().mapValues { JsonPrimitive(it.value) }),
            "runIdentity" to identity(runIdentity), "controlName" to JsonPrimitive(controlName),
            "directoryIdentities" to JsonObject(pinned.directories.mapValues { identity(it.value.identity) }),
            "pinnedFiles" to JsonPrimitive(pinned.files.size), "descriptorPinSha256" to JsonPrimitive(pinsDigest.digest().hex()),
        ) + globalTypeFields)
        return OracleJson.canonicalBytes(JsonObject(fields + ("assessmentSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(fields))))))
    }
    private fun identity(id: LinuxFileIdentity) = JsonObject(mapOf("device" to JsonPrimitive(id.key.device), "inode" to JsonPrimitive(id.key.inode),
        "mountId" to JsonPrimitive(id.mountId), "uid" to JsonPrimitive(id.uid), "gid" to JsonPrimitive(id.gid), "mode" to JsonPrimitive(id.mode.permissions), "linkCount" to JsonPrimitive(id.linkCount)))
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
}
