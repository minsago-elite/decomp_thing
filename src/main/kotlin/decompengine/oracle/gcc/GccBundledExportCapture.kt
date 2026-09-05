package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.Locale
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

internal class GccBundledExportAssessment(
    val assessment: GccCompletedRunAssessment,
    canonicalBytes: ByteArray,
) {
    private val encoded = canonicalBytes.copyOf()
    val canonicalBytes: ByteArray get() = encoded.copyOf()
}

internal class GccBundledInterruptedExportSnapshot(
    val assessment: GccInterruptedPrefixAssessment,
    val planningPrefixSha256: String,
    inFlightArtifacts: ByteArray = OracleJson.canonicalBytes(JsonObject(emptyMap())),
) {
    private val inFlight = inFlightArtifacts.copyOf()
    val inFlightArtifacts: ByteArray get() = inFlight.copyOf()
    val inFlightArtifactsSha256: String = OracleArtifacts.sha256(inFlight)
}

internal object GccBundledExportCapture {
    fun capture(
        run: LinuxDescriptor,
        expectedReports: LinuxFileIdentity,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccBundledExportAssessment {
        return captureFiles(run, expectedReports, artifacts, limits, interrupted = false) { state, progress, batches, capture, reports ->
            val model = capture.read(reports, "program_model.json", limits.assembledModelBytes)
            val assessment = GccCompilerEngineResumeByteValidator.assessCompletedRun(state, progress, batches, model, limits)
            require(assessment.reused == 0L) { "fresh GCC execution unexpectedly reused prior records" }
            GccBundledExportAssessment(assessment, renderAssessment(assessment, capture.bytes))
        }
    }

    /** Byte validation only: the caller must separately establish exact worker absence. */
    fun captureInterruptedPrefix(
        run: LinuxDescriptor,
        expectedReports: LinuxFileIdentity,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccInterruptedPrefixAssessment = captureInterruptedSnapshot(run, expectedReports, artifacts, limits).assessment

    fun captureInterruptedSnapshot(
        run: LinuxDescriptor,
        expectedReports: LinuxFileIdentity,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccBundledInterruptedExportSnapshot = captureFiles(run, expectedReports, artifacts, limits, interrupted = true) {
            state, progress, batches, capture, reports ->
        requireNoFinalModel(reports)
        val assessment = GccCompilerEngineResumeByteValidator.assessInterruptedPrefix(state, progress, batches, limits)
        require(assessment.reused == 0L) { "fresh interrupted GCC execution unexpectedly reused prior records" }
        GccBundledInterruptedExportSnapshot(assessment, planningPrefixDigest(batches), capture.inFlightArtifacts)
    }

    fun captureResumed(
        run: LinuxDescriptor,
        expectedReports: LinuxFileIdentity,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        retained: GccBundledInterruptedExportSnapshot,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccBundledExportAssessment = captureFiles(run, expectedReports, artifacts, limits, interrupted = false) {
            state, progress, batches, capture, reports ->
        val model = capture.read(reports, "program_model.json", limits.assembledModelBytes)
        val assessment = GccCompilerEngineResumeByteValidator.assessCompletedRun(state, progress, batches, model, limits)
        val prefix = retained.assessment
        require(assessment.stateSha256 == prefix.stateSha256 && assessment.functionCount == prefix.functionCount &&
            assessment.inventorySha256 == prefix.declaredInventorySha256 && assessment.reused == prefix.completed &&
            prefix.observedBatchCount in 1..batches.size.toLong()) { "GCC resumed export differs from its retained checkpoint lineage" }
        val prefixDigest = planningPrefixDigest(batches.take(prefix.observedBatchCount.toInt()))
        require(prefixDigest == retained.planningPrefixSha256) { "GCC resumed export changed retained checkpoint bytes" }
        GccBundledExportAssessment(assessment, renderAssessment(assessment, capture.bytes, prefixDigest))
    }

    /** Live observation only. Final checkpoint validation must run after exact process absence. */
    fun observeProgress(
        run: LinuxDescriptor,
        expectedReports: LinuxFileIdentity,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccExportProgressAssessment? = LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { reports ->
        require(reports.identity.copy(linkCount = expectedReports.linkCount) == expectedReports) {
            "GCC progress reports directory changed identity"
        }
        if (!captureEntryExists(reports, "program_model.json.export") ||
            !captureEntryExists(reports, "program_model.json.progress.json")) return@use null
        LinuxFilesystemSyscalls.openDirectoryAt(reports.fd, "program_model.json.export").use { export ->
            requireCaptureDirectory(export, reports.identity)
            if (!captureEntryExists(export, "state.json")) return@use null
            val capture = BoundExportFiles(limits.transitionAggregateBytes)
            val state = capture.read(export, "state.json", limits.exporterStateBytes)
            requireInvocation(state, artifacts)
            val progress = capture.read(reports, "program_model.json.progress.json", limits.progressBytes)
            val observation = GccCompilerEngineResumeByteValidator.assessExportProgress(state, progress, limits)
            capture.verify()
            requireNamedDirectory(run, "reports", reports)
            requireNamedDirectory(reports, "program_model.json.export", export)
            observation
        }
    }

    private fun <T> captureFiles(
        run: LinuxDescriptor,
        expectedReports: LinuxFileIdentity,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        limits: GccResumeByteValidationLimits,
        interrupted: Boolean,
        assess: (ByteArray, ByteArray, List<GccPlanningBatchBytes>, BoundExportFiles, LinuxDescriptor) -> T,
    ): T {
        return LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { reports ->
            require(reports.identity.copy(linkCount = expectedReports.linkCount) == expectedReports) {
                "GCC export reports directory changed identity"
            }
            LinuxFilesystemSyscalls.openDirectoryAt(reports.fd, "program_model.json.export").use { export ->
                requireCaptureDirectory(export, reports.identity)
                LinuxFilesystemSyscalls.openDirectoryAt(export.fd, "planning-batches").use { batchesDirectory ->
                    requireCaptureDirectory(batchesDirectory, reports.identity)
                    val capture = BoundExportFiles(limits.transitionAggregateBytes)
                    val state = capture.read(export, "state.json", limits.exporterStateBytes)
                    val stateAssessment = GccCompilerEngineResumeByteValidator.assessExporterState(state, limits)
                    requireInvocation(state, artifacts)
                    val progress = capture.read(reports, "program_model.json.progress.json", limits.progressBytes)
                    val batchCount = if (interrupted) {
                        val observed = GccCompilerEngineResumeByteValidator.assessExportProgress(state, progress, limits)
                        require(observed.phase == "planning" && observed.completed > 0 &&
                            observed.completed < observed.total && observed.completed % BATCH_FUNCTIONS == 0L
                        ) { "GCC interrupted capture requires a nonterminal durable planning prefix" }
                        observed.completed / BATCH_FUNCTIONS
                    } else stateAssessment.planningBatchCount
                    val expectedNames = linkedSetOf<String>()
                    val batches = (0 until batchCount).map { index ->
                        val start = index * BATCH_FUNCTIONS
                        val end = minOf(start + BATCH_FUNCTIONS, stateAssessment.functionCount)
                        val base = String.format(Locale.ROOT, "batch-%08d-%08d", start, end)
                        fun fragment(suffix: String, maximum: Int): ByteArray {
                            val name = "$base.$suffix"
                            expectedNames += name
                            return capture.read(batchesDirectory, name, maximum)
                        }
                        GccPlanningBatchBytes(
                            fragment("checkpoint", limits.checkpointBytes),
                            fragment("functions.fragment", limits.planningFragmentBytes),
                            fragment("globals.fragment", limits.planningFragmentBytes),
                            fragment("types.fragment", limits.planningFragmentBytes),
                            fragment("failures.fragment", limits.planningFragmentBytes),
                        )
                    }
                    val capturedNames = if (interrupted) {
                        capture.captureInFlight(batchesDirectory, expectedNames, batchCount * BATCH_FUNCTIONS,
                            stateAssessment.functionCount, limits)
                    } else expectedNames
                    requireBatchNames(batchesDirectory, capturedNames)
                    val result = assess(state, progress, batches, capture, reports)
                    capture.verify()
                    requireBatchNames(batchesDirectory, capturedNames)
                    requireNamedDirectory(run, "reports", reports)
                    requireNamedDirectory(reports, "program_model.json.export", export)
                    requireNamedDirectory(export, "planning-batches", batchesDirectory)
                    if (interrupted) requireNoFinalModel(reports)
                    result
                }
            }
        }
    }
}

private fun captureEntryExists(directory: LinuxDescriptor, name: String): Boolean =
    LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, name)?.use { true } ?: false

private fun requireInvocation(state: ByteArray, artifacts: List<GccCompilerEngineContainmentArtifactIdentity>) {
    val document = OracleJson.parse(state).jsonObject
    val byRole = artifacts.associateBy { it.role }
    require(byRole.size == artifacts.size) { "GCC capture contains duplicate invocation roles" }
    for ((field, role) in mapOf(
        "inputSha256" to GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY,
        "exporterSha256" to GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE,
        "analysisToolSha256" to GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE,
    )) {
        require(document.getValue(field).jsonPrimitive.content == byRole.getValue(role).sha256) {
            "GCC export $field differs from the authenticated invocation"
        }
    }
}

private fun requireNoFinalModel(reports: LinuxDescriptor) {
    LinuxFilesystemSyscalls.openPathAtOrNull(reports.fd, "program_model.json")?.use {
        error("interrupted GCC prefix unexpectedly contains a final model")
    }
}

private class BoundExportFiles(private val maximumBytes: Long) {
    var bytes: Long = 0
        private set
    private val files = mutableListOf<BoundExportFile>()
    var inFlightArtifacts: ByteArray = OracleJson.canonicalBytes(JsonObject(emptyMap()))
        private set

    fun captureInFlight(
        directory: LinuxDescriptor,
        committed: Set<String>,
        start: Long,
        total: Long,
        limits: GccResumeByteValidationLimits,
    ): Set<String> {
        val actual = LinuxFilesystemSyscalls.directoryEntryNames(directory, committed.size + 6).toSet()
        require(actual.containsAll(committed)) { "GCC interrupted export lost committed records" }
        val extra = actual - committed
        require(extra.size <= 5 && start < total) { "GCC interrupted export exceeds its in-flight artifact bound" }
        val base = String.format(Locale.ROOT, "batch-%08d-%08d", start, minOf(start + BATCH_FUNCTIONS, total))
        val suffixes = listOf("functions.fragment", "globals.fragment", "types.fragment", "failures.fragment", "checkpoint")
        val published = suffixes.take(4).map { "$base.$it" }.takeWhile(extra::contains)
        val pending = ".$base.${suffixes[published.size]}.pending"
        require(extra == published.toSet() || extra == published.toSet() + pending) {
            "GCC interrupted export has residue outside the first incomplete batch write sequence"
        }
        val records = extra.sorted().associateWith { name ->
            val maximum = if (name.endsWith(".checkpoint.pending")) limits.checkpointBytes else limits.planningFragmentBytes
            val bytes = read(directory, name, maximum)
            JsonObject(mapOf("bytes" to JsonPrimitive(bytes.size), "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)),
                "binding" to files.last().bindingJson()))
        }
        inFlightArtifacts = OracleJson.canonicalBytes(JsonObject(records))
        return actual
    }

    fun read(directory: LinuxDescriptor, name: String, maximumFileBytes: Int): ByteArray {
        val file = requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, name)) { "GCC export file is missing: $name" }
        return file.use { selected ->
            requireCaptureFile(selected.identity, directory.identity)
            val path = LinuxFilesystemSyscalls.stableDescriptorPath(selected.fd)
            val metadata = Files.readAttributes(path, "unix:size,lastModifiedTime,ctime")
            val size = metadata.getValue("size") as Long
            require(size in 0..maximumFileBytes.toLong() && size <= maximumBytes - bytes) { "GCC export capture exceeds its byte bound" }
            bytes = Math.addExact(bytes, size)
            val captured = ByteArray(size.toInt())
            LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(selected).use { readable ->
                FileChannel.open(LinuxFilesystemSyscalls.stableDescriptorPath(readable.fd), StandardOpenOption.READ).use { channel ->
                    val buffer = ByteBuffer.wrap(captured)
                    while (buffer.hasRemaining()) require(channel.read(buffer) > 0) { "GCC export file was truncated: $name" }
                    require(channel.read(ByteBuffer.allocate(1)) == -1) { "GCC export file grew: $name" }
                }
            }
            val retained = BoundExportFile(directory, name, selected.identity, metadata)
            retained.verify()
            files += retained
            captured
        }
    }

    fun verify() = files.forEach { it.verify() }
}

private class BoundExportFile(
    private val directory: LinuxDescriptor,
    private val name: String,
    private val identity: LinuxFileIdentity,
    private val metadata: Map<String, Any>,
) {
    fun bindingJson() = JsonObject(mapOf(
        "device" to JsonPrimitive(identity.key.device), "inode" to JsonPrimitive(identity.key.inode),
        "mountId" to JsonPrimitive(identity.mountId), "uid" to JsonPrimitive(identity.uid), "gid" to JsonPrimitive(identity.gid),
        "mode" to JsonPrimitive(identity.mode.permissions), "linkCount" to JsonPrimitive(identity.linkCount),
        "metadata" to JsonObject(metadata.mapValues { JsonPrimitive(it.value.toString()) }),
    ))

    fun verify() {
        requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, name)) { "GCC export file disappeared: $name" }.use { selected ->
            require(selected.identity == identity &&
                Files.readAttributes(LinuxFilesystemSyscalls.stableDescriptorPath(selected.fd), "unix:size,lastModifiedTime,ctime") == metadata
            ) { "GCC export file changed during capture: $name" }
        }
    }
}

private fun requireCaptureFile(identity: LinuxFileIdentity, parent: LinuxFileIdentity) {
    require(identity.isRegularFile && !identity.isSymbolicLink && identity.linkCount == 1 &&
        identity.uid == parent.uid && identity.mountId == parent.mountId && identity.mode.permissions and 0x12 == 0
    ) { "GCC export file is not an owned single-link file on the retained mount" }
}

private fun requireCaptureDirectory(directory: LinuxDescriptor, parent: LinuxFileIdentity) {
    val identity = LinuxFilesystemSyscalls.identity(directory.fd)
    require(identity.isDirectory && !identity.isSymbolicLink && identity.uid == parent.uid &&
        identity.mountId == parent.mountId && identity.mode.permissions and 0x12 == 0
    ) { "GCC export directory is not owned on the retained mount" }
}

private fun requireNamedDirectory(parent: LinuxDescriptor, name: String, expected: LinuxDescriptor) {
    LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name).use { actual ->
        require(actual.identity == expected.identity && LinuxFilesystemSyscalls.identity(expected.fd) == expected.identity) {
            "GCC export directory changed during capture"
        }
    }
}

private fun requireBatchNames(directory: LinuxDescriptor, expected: Set<String>) {
    require(LinuxFilesystemSyscalls.directoryEntryNames(directory, expected.size + 1).toSet() == expected) {
        "GCC export planning directory contains missing or unexpected records"
    }
}

private fun renderAssessment(assessment: GccCompletedRunAssessment, capturedBytes: Long, prefixDigest: String? = null): ByteArray {
    val fields = linkedMapOf(
        "provider" to JsonPrimitive("gcc-bundled-descriptor-export-assessment-v1"),
        "schemaVersion" to JsonPrimitive(1),
        "byteAssessmentAuthority" to JsonPrimitive(assessment.authority),
        "complete" to JsonPrimitive(false),
        "releaseEligible" to JsonPrimitive(false),
        "stateSha256" to JsonPrimitive(assessment.stateSha256),
        "progressSha256" to JsonPrimitive(assessment.progressSha256),
        "programModelBytes" to JsonPrimitive(assessment.programModelBytes),
        "programModelSha256" to JsonPrimitive(assessment.programModelSha256),
        "functionCount" to JsonPrimitive(assessment.functionCount),
        "planningBatchCount" to JsonPrimitive(assessment.planningBatchCount),
        "inventorySha256" to JsonPrimitive(assessment.inventorySha256),
        "semanticCanonicalBytes" to JsonPrimitive(assessment.semanticCanonicalBytes),
        "semanticSha256" to JsonPrimitive(assessment.semanticSha256),
        "batchCommitmentSha256" to JsonPrimitive(assessment.batchCommitmentSha256),
        "partial" to JsonPrimitive(assessment.partial),
        "failed" to JsonPrimitive(assessment.failed),
        "reused" to JsonPrimitive(assessment.reused),
        "capturedBytes" to JsonPrimitive(capturedBytes),
    )
    if (prefixDigest != null) fields["retainedPlanningPrefixSha256"] = JsonPrimitive(prefixDigest)
    fields["assessmentSha256"] = JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(fields))))
    return OracleJson.canonicalBytes(JsonObject(fields))
}

private const val BATCH_FUNCTIONS = 512L

/** Length framing covers every byte of every retained fragment, including checkpoint serialization. */
private fun planningPrefixDigest(batches: List<GccPlanningBatchBytes>): String {
    val digest = java.security.MessageDigest.getInstance("SHA-256")
    digest.update("gcc-bundled-planning-prefix-bytes-v1\n".toByteArray(Charsets.UTF_8))
    for (batch in batches) for (bytes in listOf(batch.checkpoint, batch.functions, batch.globals, batch.types, batch.failures)) {
        digest.update(ByteBuffer.allocate(8).putLong(bytes.size.toLong()).array())
        digest.update(bytes)
    }
    return digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
}
