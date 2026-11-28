package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.ContainedCommandOperationDeadline
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
    /** Assessment allocation admitted per captured model and plan byte; see docs/gcc-engine-cli-evidence-v1.md. */
    const val ASSESSMENT_ALLOCATION_PER_INPUT_BYTE = 128L

    fun capture(run: LinuxDescriptor, controlName: String, expectedControl: LinuxFileIdentity,
        request: GccBundledPlannerRequest, capturedModel: ByteArray,
        maximumStdoutBytes: Int, maximumStderrBytes: Int): GccBundledCapturedPlannerOutput =
        capture(run, controlName, expectedControl, request, capturedModel, maximumStdoutBytes, maximumStderrBytes) {}

    internal fun capture(run: LinuxDescriptor, controlName: String, expectedControl: LinuxFileIdentity,
        request: GccBundledPlannerRequest, capturedModel: ByteArray,
        maximumStdoutBytes: Int, maximumStderrBytes: Int, checkpoint: (String) -> Unit): GccBundledCapturedPlannerOutput =
        capture(run, controlName, expectedControl, request, capturedModel, maximumStdoutBytes, maximumStderrBytes,
            GccBundledHostMemoryBudget(MAXIMUM_HOST_ASSESSMENT_BYTES), checkpoint)

    /**
     * Production entry: capture and assessment run as one owned host step on a duplicate of [run],
     * so a blocked read or nonpreemptible parse cannot hold the caller past [deadline], and the
     * step's host allocation is held to [hostBudgetBytes].
     */
    internal fun captureOwned(work: GccBundledHostWorkTracker, run: LinuxDescriptor, controlName: String,
        expectedControl: LinuxFileIdentity, request: GccBundledPlannerRequest, capturedModel: ByteArray,
        maximumStdoutBytes: Int, maximumStderrBytes: Int, hostBudgetBytes: Long,
        deadline: ContainedCommandOperationDeadline, stageHook: (String) -> Unit = {}): GccBundledCapturedPlannerOutput {
        deadline.requireCurrent()
        val allowance = deadline.remainingMillis(Long.MAX_VALUE)
        val owned = duplicateOwnedDirectory(run)
        return work.run("planner output capture", allowance, owned) { context ->
            capture(owned, controlName, expectedControl, request, capturedModel, maximumStdoutBytes, maximumStderrBytes,
                GccBundledHostMemoryBudget(hostBudgetBytes)) { stage ->
                context.requireCurrent(stage)
                deadline.requireCurrent()
                stageHook(stage)
            }
        }
    }

    internal fun capture(run: LinuxDescriptor, controlName: String, expectedControl: LinuxFileIdentity,
        request: GccBundledPlannerRequest, capturedModel: ByteArray,
        maximumStdoutBytes: Int, maximumStderrBytes: Int, budget: GccBundledHostMemoryBudget,
        unmetered: (String) -> Unit): GccBundledCapturedPlannerOutput {
        val checkpoint: (String) -> Unit = { stage -> budget.requireWithinAdmission(stage); unmetered(stage) }
        checkpoint("before planner output capture")
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
                    checkpoint("verifying planner output directories")
                    require(LinuxFilesystemSyscalls.identity(run.fd) == runIdentity)
                    require(LinuxFilesystemSyscalls.stableDescriptorPath(run.fd).toRealPath() == runPath)
                    requireNamedDirectory(run, controlName, control)
                    requireNamedDirectory(control, "reports", reports)
                    require(LinuxFilesystemSyscalls.directoryEntryNames(reports, names.size + 1).toSet() == names) {
                        "planner reports contain missing or unexpected output"
                    }
                }
                verifyDirectories()
                val files = GccBoundExportFiles.admitting(request.maximumPlanBytes.toLong() + METADATA_BYTES + maximumStdoutBytes + maximumStderrBytes,
                    { bytes -> budget.admit("planner output file read", bytes) }) { checkpoint("reading planner output file") }
                val plan = files.read(reports, "module_plan.json", request.maximumPlanBytes)
                val metadata = files.read(reports, "planner-output.json", METADATA_BYTES)
                val (stdoutBytes, stdoutSha256) = files.digest(reports, "contained-command.stdout", maximumStdoutBytes)
                val (stderrBytes, stderrSha256) = files.digest(reports, "contained-command.stderr", maximumStderrBytes)
                checkpoint("before planner assessment")
                budget.admit("planner assessment", Math.multiplyExact(ASSESSMENT_ALLOCATION_PER_INPUT_BYTE,
                    capturedModel.size.toLong() + plan.size + metadata.size))
                val assessed = GccBundledPlannerOutputAssessment.assess(request, capturedModel, plan, metadata, checkpoint)
                files.verify()
                verifyDirectories()
                val fields = OracleJson.parseCanonical(assessed.canonicalBytes).jsonObject
                val record = OracleJson.canonicalBytes(JsonObject(fields + mapOf(
                    "provider" to JsonPrimitive("gcc-bundled-descriptor-planner-assessment-v1"),
                    "controlName" to JsonPrimitive(controlName),
                    "controlIdentity" to identityJson(control.identity), "reportsIdentity" to identityJson(reports.identity),
                    "capturedBytes" to JsonPrimitive(files.bytes),
                    "stdoutBytes" to JsonPrimitive(stdoutBytes), "stdoutSha256" to JsonPrimitive(stdoutSha256),
                    "stderrBytes" to JsonPrimitive(stderrBytes), "stderrSha256" to JsonPrimitive(stderrSha256),
                )))
                val result = GccBundledCapturedPlannerOutput(assessed.planBytes, record)
                checkpoint("before returning captured planner output")
                result
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
    private const val MAXIMUM_HOST_ASSESSMENT_BYTES = 64L * 1024 * 1024 * 1024
}
