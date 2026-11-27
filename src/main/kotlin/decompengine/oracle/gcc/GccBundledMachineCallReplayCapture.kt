package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.machinecalls.IndependentMachineCallReportV1
import decompengine.oracle.machinecalls.IndependentMachineCallRequestV2
import decompengine.oracle.machinecalls.IndependentMachineCallRequestIdentity
import decompengine.oracle.machinecalls.IndependentMachineCallsV1
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/** Owned byte snapshot, never a caller-supplied production authority receipt. */
internal class GccBundledMachineCallReplayCapture(report: ByteArray, assessment: ByteArray) {
    private val storedReport = report.copyOf()
    private val storedAssessment = assessment.copyOf()
    val reportBytes: ByteArray get() = storedReport.copyOf()
    val assessmentBytes: ByteArray get() = storedAssessment.copyOf()
}

internal object GccBundledMachineCallReplayOutputCapture {
    const val REPORT_NAME = "independent-machine-call-observations.json"
    const val MAXIMUM_LOG_BYTES = 1024 * 1024

    fun capture(run: LinuxDescriptor, controlName: String, expectedControl: LinuxFileIdentity,
        request: IndependentMachineCallRequestIdentity, checkpoint: () -> Unit): GccBundledMachineCallReplayCapture {
        checkpoint()
        require(controlName.matches(Regex("control-[a-f0-9]{64}")))
        val runIdentity = LinuxFilesystemSyscalls.identity(run.fd)
        val runPath = LinuxFilesystemSyscalls.stableDescriptorPath(run.fd).toRealPath()
        require(request.outputPath == runPath.resolve(controlName).resolve("reports").resolve(REPORT_NAME))
        if (request is IndependentMachineCallRequestV2) {
            require(request.controlRoot == runPath.resolve(controlName)) {
                "machine-call request control root differs from the descriptor-owned run root"
            }
        }
        return LinuxFilesystemSyscalls.openDirectoryAt(run.fd, controlName).use { control ->
            require(control.identity == expectedControl)
            requirePrivate(control.identity, runIdentity)
            LinuxFilesystemSyscalls.openDirectoryAt(control.fd, "reports").use { reports ->
                requirePrivate(reports.identity, control.identity)
                val names = setOf(REPORT_NAME, "contained-command.stdout", "contained-command.stderr")
                fun verify() {
                    checkpoint()
                    require(LinuxFilesystemSyscalls.identity(run.fd) == runIdentity)
                    require(LinuxFilesystemSyscalls.stableDescriptorPath(run.fd).toRealPath() == runPath)
                    LinuxFilesystemSyscalls.openDirectoryAt(run.fd, controlName).use { require(it.identity == control.identity) }
                    LinuxFilesystemSyscalls.openDirectoryAt(control.fd, "reports").use { require(it.identity == reports.identity) }
                    require(LinuxFilesystemSyscalls.directoryEntryNames(reports, names.size + 1).toSet() == names) {
                        "independent machine-call output contains missing or unexpected files"
                    }
                }
                verify()
                val files = GccBoundExportFiles(request.limits.maximumOutputBytes.toLong() + 2L * MAXIMUM_LOG_BYTES, checkpoint)
                val report = files.read(reports, REPORT_NAME, request.limits.maximumOutputBytes)
                val stdout = files.read(reports, "contained-command.stdout", MAXIMUM_LOG_BYTES)
                val stderr = files.read(reports, "contained-command.stderr", MAXIMUM_LOG_BYTES)
                IndependentMachineCallReportV1.validateWorker(
                    OracleJson.parseCanonical(report, IndependentMachineCallsV1.outputLimits(request.limits)).jsonObject,
                    OracleArtifacts.sha256(request.canonicalBytes), request)
                files.verify()
                verify()
                val assessment = OracleJson.canonicalBytes(JsonObject(mapOf(
                    "provider" to JsonPrimitive("descriptor-independent-machine-call-replay-capture-v1"),
                    "schemaVersion" to JsonPrimitive(1),
                    "requestSha256" to JsonPrimitive(OracleArtifacts.sha256(request.canonicalBytes)),
                    "reportSha256" to JsonPrimitive(OracleArtifacts.sha256(report)),
                    "reportBytes" to JsonPrimitive(report.size), "capturedBytes" to JsonPrimitive(files.bytes),
                    "stdoutBytes" to JsonPrimitive(stdout.size), "stdoutSha256" to JsonPrimitive(OracleArtifacts.sha256(stdout)),
                    "stderrBytes" to JsonPrimitive(stderr.size), "stderrSha256" to JsonPrimitive(OracleArtifacts.sha256(stderr)),
                    "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false),
                    "negativeCompleteness" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
                )))
                GccBundledMachineCallReplayCapture(report, assessment)
            }
        }
    }

    private fun requirePrivate(identity: LinuxFileIdentity, parent: LinuxFileIdentity) {
        require(identity.isDirectory && !identity.isSymbolicLink && identity.mode.permissions == 448 &&
            identity.uid == parent.uid && identity.mountId == parent.mountId) {
            "machine-call replay capture requires a private directory on the retained mount"
        }
    }
}
