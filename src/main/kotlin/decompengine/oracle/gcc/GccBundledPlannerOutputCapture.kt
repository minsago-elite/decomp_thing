package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.KotlinContainedCommandRequest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

internal class GccBundledCapturedPlannerOutput(plan: ByteArray, assessment: ByteArray) {
    private val retainedPlan = plan.copyOf()
    private val retainedAssessment = assessment.copyOf()
    val planBytes: ByteArray get() = retainedPlan.copyOf()
    val canonicalBytes: ByteArray get() = retainedAssessment.copyOf()
}

/** Caller must establish worker absence and hold the run lease throughout capture. */
internal object GccBundledPlannerOutputCapture {
    fun capture(run: LinuxDescriptor, controlName: String, expectedControl: LinuxFileIdentity,
        request: GccBundledPlannerRequest, capturedModel: ByteArray,
        maximumStdoutBytes: Int, maximumStderrBytes: Int): GccBundledCapturedPlannerOutput {
        require(controlName.matches(Regex("control-[a-f0-9]{64}")))
        require(maximumStdoutBytes.toLong() in 0..KotlinContainedCommandRequest.MAXIMUM_LOG_BYTES &&
            maximumStderrBytes.toLong() in 0..KotlinContainedCommandRequest.MAXIMUM_LOG_BYTES)
        val runIdentity = LinuxFilesystemSyscalls.identity(run.fd)
        require(runIdentity.copy(linkCount = run.identity.linkCount) == run.identity)
        requirePrivateDirectory(runIdentity, runIdentity)
        val runPath = LinuxFilesystemSyscalls.stableDescriptorPath(run.fd).toRealPath()
        require(request.outputDirectory == runPath.resolve(controlName).resolve("reports")) {
            "planner output path differs from its retained run/control directory"
        }
        return LinuxFilesystemSyscalls.openDirectoryAt(run.fd, controlName).use { control ->
            require(control.identity == expectedControl) { "planner control directory differs from completed execution" }
            requirePrivateDirectory(control.identity, runIdentity)
            LinuxFilesystemSyscalls.openDirectoryAt(control.fd, "reports").use { reports ->
                requirePrivateDirectory(reports.identity, control.identity)
                val names = setOf("module_plan.json", "planner-output.json", "contained-command.stdout", "contained-command.stderr")
                fun verifyDirectories() {
                    require(LinuxFilesystemSyscalls.identity(run.fd) == runIdentity)
                    require(LinuxFilesystemSyscalls.stableDescriptorPath(run.fd).toRealPath() == runPath)
                    requireNamedDirectory(run, controlName, control)
                    requireNamedDirectory(control, "reports", reports)
                    require(LinuxFilesystemSyscalls.directoryEntryNames(reports, names.size + 1).toSet() == names) {
                        "planner reports contain missing or unexpected output"
                    }
                }
                verifyDirectories()
                val files = GccBoundExportFiles(request.maximumPlanBytes.toLong() + METADATA_BYTES + maximumStdoutBytes + maximumStderrBytes)
                val plan = files.read(reports, "module_plan.json", request.maximumPlanBytes)
                val metadata = files.read(reports, "planner-output.json", METADATA_BYTES)
                val stdout = files.read(reports, "contained-command.stdout", maximumStdoutBytes)
                val stderr = files.read(reports, "contained-command.stderr", maximumStderrBytes)
                val assessed = GccBundledPlannerOutputAssessment.assess(request, capturedModel, plan, metadata)
                files.verify()
                verifyDirectories()
                val fields = OracleJson.parseCanonical(assessed.canonicalBytes).jsonObject
                val record = OracleJson.canonicalBytes(JsonObject(fields + mapOf(
                    "provider" to JsonPrimitive("gcc-bundled-descriptor-planner-assessment-v1"),
                    "controlName" to JsonPrimitive(controlName),
                    "controlIdentity" to identityJson(control.identity), "reportsIdentity" to identityJson(reports.identity),
                    "capturedBytes" to JsonPrimitive(files.bytes),
                    "stdoutBytes" to JsonPrimitive(stdout.size), "stdoutSha256" to JsonPrimitive(OracleArtifacts.sha256(stdout)),
                    "stderrBytes" to JsonPrimitive(stderr.size), "stderrSha256" to JsonPrimitive(OracleArtifacts.sha256(stderr)),
                )))
                GccBundledCapturedPlannerOutput(assessed.planBytes, record)
            }
        }
    }

    private fun requirePrivateDirectory(identity: LinuxFileIdentity, parent: LinuxFileIdentity) {
        require(identity.isDirectory && !identity.isSymbolicLink && identity.mode.permissions == 448 &&
            identity.uid == parent.uid && identity.mountId == parent.mountId) { "planner capture requires an owned private directory on the retained mount" }
    }

    private fun requireNamedDirectory(parent: LinuxDescriptor, name: String, expected: LinuxDescriptor) {
        LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name).use { actual ->
            require(actual.identity == expected.identity && LinuxFilesystemSyscalls.identity(expected.fd) == expected.identity) {
                "planner capture directory changed"
            }
        }
    }

    private fun identityJson(identity: LinuxFileIdentity) = JsonObject(mapOf(
        "device" to JsonPrimitive(identity.key.device), "inode" to JsonPrimitive(identity.key.inode),
        "mountId" to JsonPrimitive(identity.mountId), "uid" to JsonPrimitive(identity.uid), "gid" to JsonPrimitive(identity.gid),
        "mode" to JsonPrimitive(identity.mode.permissions), "linkCount" to JsonPrimitive(identity.linkCount),
    ))

    private const val METADATA_BYTES = 256 * 1024
}
