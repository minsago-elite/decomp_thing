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

internal object GccBundledExportCapture {
    fun capture(
        run: LinuxDescriptor,
        expectedReports: LinuxFileIdentity,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccBundledExportAssessment {
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
                    val stateDocument = OracleJson.parse(state).jsonObject
                    val byRole = artifacts.associateBy { it.role }
                    for ((field, role) in mapOf(
                        "inputSha256" to GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY,
                        "exporterSha256" to GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE,
                        "analysisToolSha256" to GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE,
                    )) {
                        require(stateDocument.getValue(field).jsonPrimitive.content == byRole.getValue(role).sha256) {
                            "GCC export $field differs from the authenticated invocation"
                        }
                    }
                    val expectedNames = linkedSetOf<String>()
                    val batches = (0 until stateAssessment.planningBatchCount).map { index ->
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
                    requireBatchNames(batchesDirectory, expectedNames)
                    val progress = capture.read(reports, "program_model.json.progress.json", limits.progressBytes)
                    val model = capture.read(reports, "program_model.json", limits.assembledModelBytes)
                    val assessment = GccCompilerEngineResumeByteValidator.assessCompletedRun(state, progress, batches, model, limits)
                    require(assessment.reused == 0L) { "fresh GCC execution unexpectedly reused prior records" }
                    capture.verify()
                    requireBatchNames(batchesDirectory, expectedNames)
                    requireNamedDirectory(run, "reports", reports)
                    requireNamedDirectory(reports, "program_model.json.export", export)
                    requireNamedDirectory(export, "planning-batches", batchesDirectory)
                    GccBundledExportAssessment(assessment, renderAssessment(assessment, capture.bytes))
                }
            }
        }
    }
}

private class BoundExportFiles(private val maximumBytes: Long) {
    var bytes: Long = 0
        private set
    private val files = mutableListOf<BoundExportFile>()

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

private fun renderAssessment(assessment: GccCompletedRunAssessment, capturedBytes: Long): ByteArray {
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
    fields["assessmentSha256"] = JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(fields))))
    return OracleJson.canonicalBytes(JsonObject(fields))
}

private const val BATCH_FUNCTIONS = 512L
