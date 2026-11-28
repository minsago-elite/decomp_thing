package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.structural.StructuralBoundaryReplayRequestV1
import decompengine.oracle.structural.StructuralBoundaryReplayWorkerV1
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/** Bytes captured after the replay worker has stopped; this object alone grants no authority. */
internal class GccBundledStructuralReplayCapture(
    observationBytes: ByteArray,
    metadataBytes: ByteArray,
    assessmentBytes: ByteArray,
) {
    private val observation = observationBytes.copyOf()
    private val metadata = metadataBytes.copyOf()
    private val assessment = assessmentBytes.copyOf()
    val observationBytes: ByteArray get() = observation.copyOf()
    val metadataBytes: ByteArray get() = metadata.copyOf()
    val assessmentBytes: ByteArray get() = assessment.copyOf()
}

/** The live coordinator owns absence checks and the run lease on both sides of this read. */
internal object GccBundledStructuralReplayOutputCapture {
    const val MAXIMUM_OBSERVATION_BYTES = 64 * 1024 * 1024
    const val MAXIMUM_METADATA_BYTES = 256 * 1024
    const val MAXIMUM_LOG_BYTES = 1024 * 1024

    fun capture(
        run: LinuxDescriptor,
        controlName: String,
        expectedControl: LinuxFileIdentity,
        request: StructuralBoundaryReplayRequestV1,
        checkpoint: () -> Unit,
    ): GccBundledStructuralReplayCapture {
        checkpoint()
        require(controlName.matches(Regex("control-[a-f0-9]{64}")))
        val runIdentity = LinuxFilesystemSyscalls.identity(run.fd)
        val runPath = LinuxFilesystemSyscalls.stableDescriptorPath(run.fd).toRealPath()
        require(request.outputDirectory == runPath.resolve(controlName).resolve("reports"))
        return LinuxFilesystemSyscalls.openDirectoryAt(run.fd, controlName).use { control ->
            require(control.identity == expectedControl)
            requirePrivate(control.identity, runIdentity)
            LinuxFilesystemSyscalls.openDirectoryAt(control.fd, "reports").use { reports ->
                requirePrivate(reports.identity, control.identity)
                val names = setOf("boundary-observation.json", "boundary-replay-output.json",
                    "contained-command.stdout", "contained-command.stderr")
                fun verify() {
                    checkpoint()
                    require(LinuxFilesystemSyscalls.identity(run.fd) == runIdentity)
                    require(LinuxFilesystemSyscalls.stableDescriptorPath(run.fd).toRealPath() == runPath)
                    LinuxFilesystemSyscalls.openDirectoryAt(run.fd, controlName).use { require(it.identity == control.identity) }
                    LinuxFilesystemSyscalls.openDirectoryAt(control.fd, "reports").use { require(it.identity == reports.identity) }
                    require(LinuxFilesystemSyscalls.directoryEntryNames(reports, names.size + 1).toSet() == names) {
                        "structural replay output contains missing or unexpected files"
                    }
                }
                verify()
                val files = GccBoundExportFiles(MAXIMUM_OBSERVATION_BYTES.toLong() + MAXIMUM_METADATA_BYTES +
                    2L * MAXIMUM_LOG_BYTES, checkpoint)
                val observation = files.read(reports, "boundary-observation.json", MAXIMUM_OBSERVATION_BYTES)
                val metadata = files.read(reports, "boundary-replay-output.json", MAXIMUM_METADATA_BYTES)
                val stdout = files.read(reports, "contained-command.stdout", MAXIMUM_LOG_BYTES)
                val stderr = files.read(reports, "contained-command.stderr", MAXIMUM_LOG_BYTES)
                StructuralBoundaryReplayWorkerV1.verifyOutput(request, observation, metadata)
                files.verify()
                verify()
                val assessment = OracleJson.canonicalBytes(JsonObject(mapOf(
                    "provider" to JsonPrimitive("descriptor-structural-boundary-replay-capture-v1"),
                    "schemaVersion" to JsonPrimitive(1),
                    "requestSha256" to JsonPrimitive(OracleArtifacts.sha256(request.canonicalBytes)),
                    "modelSha256" to JsonPrimitive(request.modelSha256),
                    "observationSha256" to JsonPrimitive(OracleArtifacts.sha256(observation)),
                    "observationBytes" to JsonPrimitive(observation.size),
                    "metadataSha256" to JsonPrimitive(OracleArtifacts.sha256(metadata)),
                    "capturedBytes" to JsonPrimitive(files.bytes),
                    "stdoutBytes" to JsonPrimitive(stdout.size), "stdoutSha256" to JsonPrimitive(OracleArtifacts.sha256(stdout)),
                    "stderrBytes" to JsonPrimitive(stderr.size), "stderrSha256" to JsonPrimitive(OracleArtifacts.sha256(stderr)),
                    "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
                )))
                GccBundledStructuralReplayCapture(observation, metadata, assessment)
            }
        }
    }

    private fun requirePrivate(identity: LinuxFileIdentity, parent: LinuxFileIdentity) {
        require(identity.isDirectory && !identity.isSymbolicLink && identity.mode.permissions == 448 &&
            identity.uid == parent.uid && identity.mountId == parent.mountId) {
            "structural replay capture requires a private directory on the retained mount"
        }
    }
}
