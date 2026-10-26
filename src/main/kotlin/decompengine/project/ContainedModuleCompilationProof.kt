package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.ContainedCommandTerminalResourceEvidence
import decompengine.oracle.fulltree.ContainedCommandFileDescriptorPolicy
import decompengine.oracle.fulltree.ContainedCommandFileDescriptorLimits
import decompengine.oracle.fulltree.ContainedCommandFileDescriptorObservation
import decompengine.oracle.fulltree.containedCommandFileDescriptorAdmission
import decompengine.oracle.fulltree.FullTreeDiskScratchEvidence
import decompengine.oracle.fulltree.KotlinContainedCommandKeeper
import decompengine.oracle.fulltree.KotlinContainedCommandProtocol
import decompengine.oracle.fulltree.KotlinContainedCommandRequest
import decompengine.oracle.fulltree.isolatedObservationServiceRuntimeSeconds
import decompengine.oracle.fulltree.runDirectoryName
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Reopens historical evidence only. Parsing never constructs a live compilation or lease token. */
internal object ContainedModuleCompilationProof {
    internal class Verified internal constructor(
        val request: ContainedModuleCompilerRequest,
        val result: ContainedModuleCompilerResult,
    )

    fun verify(evidence: ModuleCompilationEvidence): Verified {
        val verified = verify(requireNotNull(evidence.containedProof) { "contained module compilation proof is missing" })
        val request = verified.request
        val result = verified.result
        val profile = request.profile
        require(evidence.sourceSha256 == request.sourceSha256 &&
            evidence.command == ContainedModuleCompilationPolicy.command(profile, request.sourcePath) &&
            evidence.outcome == if (result.outcome == "compiled-object") "passed" else "failed") {
            "module compilation evidence differs from its exact source, command, or result"
        }
        require(evidence.returnCode == result.exitCode && evidence.diagnosticsSha256 == diagnosticsSha256(result) &&
            evidence.diagnosticsBytes == result.stdoutBytes + result.stderrBytes) {
            "module compilation evidence differs from its retained diagnostics"
        }
        return verified
    }

    fun verify(record: JsonObject): Verified {
        // Callers can supply constructed JSON, so charge the same aggregate bounds as serialized evidence.
        val proof = OracleJson.parseCanonical(OracleJson.canonicalBytes(record, LIMITS), LIMITS) as JsonObject
        val version = proof.number("schemaVersion")
        require(version == 1L || version == 2L) { "unsupported contained module compilation proof" }
        proof.exact(PROOF_FIELDS + if (version == 2L) setOf("runtimeClosure") else emptySet(), "proof")
        require(proof.text("provider") == "contained-module-compilation-v$version" &&
            proof.text("scope") == "module-object" && proof.text("policyId") == ContainedModuleCompilationPolicy.POLICY_ID) {
            "unsupported contained module compilation proof"
        }
        val request = ContainedModuleCompilerRequest.parse(bytes(proof.objectField("request")))
        val result = ContainedModuleCompilerResult.parse(bytes(proof.objectField("result")))
        result.requireBinding(request)
        val runtime = ContainedModuleCompilationRuntimeConfiguration.parse(bytes(proof.objectField("runtimeConfiguration")))
        require(runtime.profileId == request.profileId && runtime.compilerExecutable == request.compilerPath &&
            runtime.compilerSha256 == request.compilerSha256) { "module compiler request differs from its configured profile or compiler" }
        val common = mapOf("profileId" to request.profileId, "profileSha256" to request.profileSha256,
            "sourceSha256" to request.sourceSha256, "snapshotSha256" to request.snapshotSha256,
            "runtimeConfigurationSha256" to runtime.configurationSha256)
        common.forEach { (field, expected) -> require(proof.text(field) == expected) { "module compiler proof $field differs" } }
        val intent = JsonObject((common + mapOf("provider" to "module-compilation-intent-v1",
            "nonce" to request.nonce, "sourcePath" to request.sourcePath)).mapValues { JsonPrimitive(it.value) })
        require(proof.objectField("intent") == intent) { "module compiler intent differs from the exact request" }
        val lease = FullTreeDiskScratchEvidence.parseCanonical(bytes(proof.objectField("diskLease")))
        require(lease.operationId == request.nonce && lease.requestSha256 == sha256(bytes(intent)) &&
            lease.shardId == "module-compile" && lease.scopeSha256 == runtime.configurationSha256 &&
            lease.mountPathSha256 == sha256(runtime.scratchMount.toString().toByteArray()) &&
            lease.requiredAvailableBytes == runtime.scratchPolicy.requiredAvailableBytes &&
            lease.maximumFilesystemBytes == runtime.scratchPolicy.maximumFilesystemBytes &&
            lease.requiredAvailableInodes == runtime.scratchPolicy.requiredAvailableInodes &&
            lease.maximumFilesystemInodes == runtime.scratchPolicy.maximumFilesystemInodes) {
            "module compiler disk lease differs from its exact operation and configured capacity"
        }
        val run = runtime.scratchMount.resolve(".decomp-oracle-lease-${request.nonce}").resolve(runDirectoryName(request.nonce))
        val control = run.resolve("control-${request.nonce}")
        require(request.snapshotRoot == run.resolve("state/snapshot") && request.outputDirectory == run.resolve("reports")) {
            "module compiler snapshot or output escaped its exact disk lease"
        }
        val command = KotlinContainedCommandRequest.parse(bytes(proof.objectField("commandRequest")))
        require(command.runDirectory == control && command.nonce == request.nonce && !command.allowInterruption &&
            command.terminalResourcePolicySha256 == ContainedCommandTerminalResourceEvidence.policySha256) {
            "module compiler command differs from its exact control and terminal policy"
        }
        if (version == 2L) {
            require(command.fileDescriptorPolicy == ContainedCommandFileDescriptorPolicy.MODULE_COMPILATION &&
                command.retainedInputVisibilitySha256 == null) {
                "module compiler command lacks the fixed file-descriptor policy or substitutes selected visibility"
            }
        } else {
            require(command.fileDescriptorPolicy == null) { "historical module proof cannot declare the new file-descriptor policy" }
        }
        require(command.command.size >= 2)
        val requestText = command.command[command.command.lastIndex - 1]
        val requestPath = Path.of(requestText)
        requireCompilerAbsolutePath(requestPath)
        require(requestPath.toString() == requestText && requestPath.fileName.toString() == "request.json" &&
            requestPath.parent.fileName?.toString()?.startsWith(".module-compilation-") == true) {
            "module compiler worker request path is not its private request file"
        }
        val forbidden = listOf(runtime.scratchMount, runtime.isolation.systemdUserRuntimeDirectory, Path.of("/proc"), Path.of("/dev")) +
            (listOf(runtime.isolation.javaRuntime) + runtime.isolation.systemLibraryMounts + runtime.compilerRuntimeMounts)
                .flatMap { listOf(it.source, it.destination) }
        require(forbidden.none { requestPath.startsWith(it) || it.startsWith(requestPath) }) {
            "module compiler worker request overlaps runtime, scratch, or system authority"
        }
        require(command.command == containedModuleCompilerCommand(runtime.isolation, requestPath, request)) {
            "module compiler command contains a different worker, classpath, or JVM option"
        }
        val attachment = proof.objectField("attachment")
        val execution = proof.objectField("execution")
        attachment.exact(ATTACHMENT_FIELDS + if (version == 2L) setOf("fileDescriptorLimits") else emptySet(), "attachment")
        execution.exact(EXECUTION_FIELDS, "execution")
        val executionVersion = if (version == 2L) 5 else 3
        require(attachment["schemaVersion"] == JsonPrimitive(executionVersion) &&
            attachment.text("provider") == "kotlin-lease-contained-command-attachment-v$executionVersion" &&
            execution["schemaVersion"] == JsonPrimitive(executionVersion) &&
            execution.text("provider") == "kotlin-lease-contained-command-execution-v$executionVersion") {
            "module compiler proof uses a different contained execution mode"
        }
        require(attachment.text("requestSha256") == command.sha256 && execution.text("requestSha256") == command.sha256 &&
            attachment.text("nonce") == request.nonce && attachment.text("deploymentClosureSha256") == runtime.configurationSha256 &&
            execution.text("deploymentClosureSha256") == runtime.configurationSha256) {
            "module compiler terminal records belong to another command or runtime"
        }
        requireCompilerDigest(attachment.text("runtimeClosureSha256"))
        val unit = "decomp-module-compile-${request.nonce.take(32)}.scope"
        require(attachment.text("unitName") == unit &&
            attachment.text("controlGroup") == "${runtime.managerControlGroup}/app.slice/$unit") {
            "module compiler terminal scope differs from its configured manager"
        }
        require(execution.text("controlDirectory") == control.toString()) { "module compiler terminal control path differs" }
        val identity = execution.objectField("controlDirectoryIdentity")
        identity.exact(setOf("name", "device", "inode", "mountId", "uid", "gid", "mode", "linkCount"), "control identity")
        require(identity.text("name") == control.fileName.toString() && identity.number("device") == lease.leaseRootDevice &&
            identity.number("inode") > 0 && identity.number("mountId") == lease.mountId &&
            identity.number("uid") == lease.ownerUid.toLong() && identity.number("gid") in 0..Int.MAX_VALUE.toLong() &&
            identity.number("mode") == 448L && identity.number("linkCount") >= 2L) {
            "module compiler control identity differs from its disk lease"
        }
        verifyResources(command, attachment, execution, request, version == 2L)
        if (version == 2L) verifyRuntimeClosure(proof.objectField("runtimeClosure"), runtime, request, command,
            requestPath, run, control, lease, attachment, execution)
        ContainedCommandTerminalResourceEvidence.verifyExecution(bytes(execution), bytes(attachment))
        val outcome = execution.objectField("outcome")
        outcome.exact(setOf("schemaVersion", "provider", "event", "nonce", "requestSha256", "keeperPid", "childPid", "exitCode",
            "elapsedMillis", "stdoutBytes", "stderrBytes", "stdoutSha256", "stderrSha256", "status", "hmacSha256"), "worker outcome")
        requireCompilerDigest(outcome.text("hmacSha256"))
        ContainedCommandTerminalResourceEvidence.requireCapturedOutput(outcome, result.canonicalBytes, byteArrayOf())
        require(outcome.number("elapsedMillis") in 0..command.maximumWallSeconds * 1000L) {
            "module compiler worker exceeded its contained wall bound"
        }
        val cleanup = proof.objectField("cleanup")
        cleanup.exact(CLEANUP_FIELDS, "cleanup")
        require(cleanup.values.all { it == JsonPrimitive(true) }) { "module compiler cleanup is incomplete" }
        return Verified(request, result)
    }

    fun diagnosticsSha256(result: ContainedModuleCompilerResult): String = sha256(bytes(JsonObject(mapOf(
        "stdoutSha256" to JsonPrimitive(result.stdoutSha256), "stdoutBytes" to JsonPrimitive(result.stdoutBytes),
        "stderrSha256" to JsonPrimitive(result.stderrSha256), "stderrBytes" to JsonPrimitive(result.stderrBytes),
    ))))

    private fun verifyResources(command: KotlinContainedCommandRequest, attachment: JsonObject, execution: JsonObject,
        request: ContainedModuleCompilerRequest, descriptorPolicy: Boolean) {
        val resources = attachment.objectField("resources")
        resources.exact(setOf("wallClockMillis", "maximumResidentBytes", "pidsMax", "maximumFileBytes",
            "maximumAddressSpaceBytes", "cpuSeconds", "serviceRuntimeSeconds") +
            if (descriptorPolicy) setOf("processorCount", "fileDescriptorPolicySha256", "maximumOpenFiles") else emptySet(), "resources")
        if (descriptorPolicy) {
            val policy = ContainedCommandFileDescriptorPolicy.MODULE_COMPILATION
            require(resources.number("processorCount") == 1L && resources.text("fileDescriptorPolicySha256") == policy.sha256 &&
                resources.number("maximumOpenFiles") == policy.maximumOpenFiles &&
                command.fileDescriptorPolicySha256 == policy.sha256 && command.maximumOpenFiles == policy.maximumOpenFiles) {
                "module compiler resources differ from the fixed file-descriptor policy"
            }
        }
        val wall = resources.number("wallClockMillis")
        require(wall in 1_000L..minOf(60_000L, moduleCompilerOperationWallMillis(request.profile)) && wall % 1000L == 0L) {
            "module compiler service wall budget is invalid"
        }
        val runtimeSeconds = isolatedObservationServiceRuntimeSeconds(wall / 1000L)
        require(resources.number("maximumResidentBytes") == 512L * 1024 * 1024 && resources.number("pidsMax") == 128L &&
            resources.number("maximumFileBytes") == ContainedModuleCompilerRequest.MAXIMUM_OBJECT_BYTES &&
            resources.number("maximumAddressSpaceBytes") == 8L * 1024 * 1024 * 1024 &&
            resources.number("cpuSeconds") == runtimeSeconds && resources.number("serviceRuntimeSeconds") == runtimeSeconds &&
            command.maximumWallSeconds == wall / 1000L && command.maximumStartWaitSeconds == minOf(runtimeSeconds, 300L) &&
            command.maximumStdoutBytes == ContainedModuleCompilerRequest.MAXIMUM_OBJECT_BYTES &&
            command.maximumStderrBytes == ContainedModuleCompilerRequest.MAXIMUM_OBJECT_BYTES) {
            "module compiler resources differ from the registered containment policy"
        }
        require(execution.number("derivationWallNanos") in 0..wall * 1_000_000) { "module compiler derivation exceeded its wall bound" }
        val cgroup = execution.objectField("cgroup")
        cgroup.exact(setOf("peakResidentBytes", "cpuNanos", "memoryMaxEvents", "memoryOomEvents", "memoryOomKillEvents"), "cgroup")
        require(cgroup.number("peakResidentBytes") in 0..512L * 1024 * 1024 &&
            cgroup.number("cpuNanos") in 0..runtimeSeconds * 1_000_000_000 &&
            listOf("memoryMaxEvents", "memoryOomEvents", "memoryOomKillEvents").all { cgroup.number(it) == 0L }) {
            "module compiler cgroup exceeded its resource bound"
        }
        val deadline = execution.objectField("operationWallTime")
        deadline.exact(setOf("provider", "maximumWallMillis", "startedMonotonicNanos", "elapsedNanos", "remainingNanos"), "operation deadline")
        val maximum = moduleCompilerOperationWallMillis(request.profile)
        val elapsed = deadline.number("elapsedNanos")
        val remaining = deadline.number("remainingNanos")
        require(deadline.text("provider") == "kotlin-contained-operation-wall-deadline-v1" &&
            deadline.number("maximumWallMillis") == maximum && elapsed in 0 until maximum * 1_000_000 &&
            remaining == maximum * 1_000_000 - elapsed && elapsed >= execution.number("derivationWallNanos")) {
            "module compiler operation deadline is invalid or exhausted"
        }
        deadline.number("startedMonotonicNanos") // Monotonic origins may be negative; they are never live clock authority.
    }

    /** Recompute declarations and joins only; archived observations do not become live authority. */
    private fun verifyRuntimeClosure(closure: JsonObject, runtime: ContainedModuleCompilationRuntimeConfiguration.Declaration,
        request: ContainedModuleCompilerRequest, command: KotlinContainedCommandRequest, requestPath: Path, run: Path,
        control: Path, lease: FullTreeDiskScratchEvidence, attachment: JsonObject, execution: JsonObject) {
        closure.exact(RUNTIME_FIELDS, "runtime closure")
        require(sha256(bytes(closure)) == attachment.text("runtimeClosureSha256")) {
            "module compiler runtime closure digest differs from its attachment"
        }
        require(closure.text("provider") == "kotlin-lease-contained-command-runtime-v5" &&
            closure.text("configurationSha256") == runtime.isolation.canonicalSha256 &&
            closure.text("deploymentClosureSha256") == runtime.configurationSha256 &&
            closure.text("keeperEntryPoint") == KotlinContainedCommandKeeper::class.java.name &&
            closure.text("requestVersion") == KotlinContainedCommandProtocol.VERSION &&
            closure.text("commandRequestProvider") == "kotlin-contained-command-request-v5" &&
            closure.text("commandRequestSha256") == command.sha256 &&
            closure.text("terminalResourcePolicySha256") == ContainedCommandTerminalResourceEvidence.policySha256) {
            "module compiler runtime closure differs from its configured command or runtime"
        }
        val mounts = JsonArray(runtime.compilerRuntimeMounts.map { mount -> JsonObject(mapOf(
            "source" to JsonPrimitive(mount.source.toString()), "destination" to JsonPrimitive(mount.destination.toString()),
            "expectedManifestSha256" to JsonPrimitive(mount.expectedManifestSha256),
        )) })
        require(closure["runtimeMounts"] == mounts) { "module compiler runtime mounts differ from their ordered configuration" }
        val inputs = closure.arrayField("readOnlyInputs")
        require(inputs.size == 2) { "module compiler runtime requires exactly its private request and configured compiler" }
        val requestInput = inputs[0] as? JsonObject ?: throw IllegalArgumentException("module compiler request input must be an object")
        val compilerInput = inputs[1] as? JsonObject ?: throw IllegalArgumentException("module compiler executable input must be an object")
        fun input(path: Path, size: Long, digest: String) = JsonObject(mapOf("path" to JsonPrimitive(path.toString()),
            "bytes" to JsonPrimitive(size), "sha256" to JsonPrimitive(digest)))
        require(requestInput == input(requestPath, request.canonicalBytes.size.toLong(), request.sha256)) {
            "module compiler retained worker request differs from its canonical bytes"
        }
        // The archive preserves the live-observed compiler size; the configured digest is its content identity.
        val compilerBytes = compilerInput.number("bytes")
        require(compilerBytes in 1..512L * 1024 * 1024 &&
            compilerInput == input(runtime.compilerExecutable, compilerBytes, runtime.compilerSha256)) {
            "module compiler retained executable differs from its configured identity or size bound"
        }
        require(closure.text("controlDirectory") == control.toString() && closure.text("writableRoot") == run.toString()) {
            "module compiler runtime paths differ from the disk lease"
        }
        val state = closure.objectField("readOnlyStateDirectory")
        state.exact(setOf("name", "device", "inode", "mountId", "uid", "gid", "mode", "linkCount"), "retained state identity")
        val controlIdentity = execution.objectField("controlDirectoryIdentity")
        require(state.text("name") == "state" && state.number("device") == lease.leaseRootDevice &&
            state.number("inode") > 0 && state.number("inode") != controlIdentity.number("inode") &&
            state.number("mountId") == lease.mountId && state.number("uid") == lease.ownerUid.toLong() &&
            state.number("gid") == controlIdentity.number("gid") && state.number("mode") == 448L && state.number("linkCount") >= 2L) {
            "module compiler retained state identity differs from its complete private lease directory"
        }
        val deadline = execution.objectField("operationWallTime")
        require(closure.objectField("operationWallDeadline") == JsonObject(deadline - setOf("elapsedNanos", "remainingNanos"))) {
            "module compiler runtime deadline differs from the completed operation"
        }
        val attachedResources = attachment.objectField("resources")
        require(closure.objectField("resources") == JsonObject(attachedResources -
            setOf("maximumAddressSpaceBytes", "cpuSeconds", "serviceRuntimeSeconds"))) {
            "module compiler runtime resources differ from its attachment"
        }
        val policy = ContainedCommandFileDescriptorPolicy.MODULE_COMPILATION
        val admission = closure.objectField("fileDescriptorAdmission")
        admission.exact(setOf("policySha256", "trustedHostMaximumOpenFiles", "launcherProcess"), "file-descriptor admission")
        val launcher = admission.objectField("launcherProcess")
        launcher.exact(setOf("hostPid", "startTimeTicks", "inheritedSoftLimit", "inheritedHardLimit"), "launcher process")
        val launcherObservation = ContainedCommandFileDescriptorObservation(launcher.number("hostPid"), launcher.number("startTimeTicks"),
            ContainedCommandFileDescriptorLimits(launcher.number("inheritedSoftLimit"), launcher.number("inheritedHardLimit")))
        require(admission == containedCommandFileDescriptorAdmission(policy, launcherObservation)) {
            "module compiler file-descriptor admission differs from the independent host ceiling"
        }
        val limits = attachment.objectField("fileDescriptorLimits")
        limits.exact(setOf("provider", "hostPid", "startTimeTicks", "softLimit", "hardLimit"), "actual file-descriptor limits")
        val observed = ContainedCommandFileDescriptorObservation(limits.number("hostPid"), limits.number("startTimeTicks"),
            ContainedCommandFileDescriptorLimits(limits.number("softLimit"), limits.number("hardLimit")))
        require(limits == observed.json()) { "module compiler actual file-descriptor observation provider differs" }
        observed.requireSelected(policy)
        val processes = attachment.arrayField("processes").map { value ->
            val process = value as? JsonObject ?: throw IllegalArgumentException("module compiler keeper process must be an object")
            process.exact(setOf("role", "hostPid", "startTimeTicks", "parentRole", "namespacePids", "executableDevice",
                "executableInode", "executableMountId"), "keeper process")
            process
        }
        val keeper = requireNotNull(processes.singleOrNull { it.text("role") == "supervisor-jvm" }) {
            "module compiler actual file-descriptor observation lacks its unique keeper"
        }
        observed.requireIdentity(keeper.number("hostPid"), keeper.number("startTimeTicks"))
    }

    private fun bytes(value: JsonObject): ByteArray = OracleJson.canonicalBytes(value, LIMITS)
    private fun JsonObject.exact(fields: Set<String>, label: String) { require(keys == fields) { "module compiler $label fields differ" } }
    private fun JsonObject.objectField(field: String): JsonObject = this[field] as? JsonObject
        ?: throw IllegalArgumentException("module compiler $field must be an object")
    private fun JsonObject.arrayField(field: String): JsonArray = this[field] as? JsonArray
        ?: throw IllegalArgumentException("module compiler $field must be an array")
    private fun JsonObject.text(field: String): String = (this[field] as? JsonPrimitive)?.takeIf { it.isString }?.content
        ?: throw IllegalArgumentException("module compiler $field must be a string")
    private fun JsonObject.number(field: String): Long {
        val value = this[field] as? JsonPrimitive ?: throw IllegalArgumentException("module compiler $field must be an integer")
        require(!value.isString && value.content.matches(Regex("0|-?[1-9][0-9]*"))) { "module compiler $field must be an integer" }
        return value.content.toLongOrNull() ?: throw IllegalArgumentException("module compiler $field exceeds its integer bound")
    }

    private val CLEANUP_FIELDS = setOf("processesAbsent", "unitAbsent", "cgroupAbsent", "scratchRemoved", "leaseReleased")
    private val PROOF_FIELDS = setOf("schemaVersion", "provider", "scope", "policyId", "profileId", "profileSha256", "sourceSha256",
        "snapshotSha256", "runtimeConfigurationSha256", "runtimeConfiguration", "intent", "request", "result", "commandRequest",
        "attachment", "execution", "diskLease", "cleanup")
    private val ATTACHMENT_FIELDS = setOf("schemaVersion", "provider", "unitName", "nonce", "bootId", "invocationId", "controlGroup",
        "cgroupDevice", "cgroupInode", "cgroupMountId", "requestSha256", "deploymentClosureSha256", "runtimeClosureSha256", "resources",
        "releaseEligible", "processes", "terminalResourcePolicySha256", "terminalResourceBaseline", "attachmentSha256")
    private val EXECUTION_FIELDS = setOf("schemaVersion", "provider", "attachmentSha256", "requestSha256", "deploymentClosureSha256",
        "outcomeSha256", "outcome", "childExitCode", "derivationWallNanos", "unitAbsent", "cgroupAbsent", "processesAbsent", "releaseEligible",
        "cgroup", "terminalResourceEvidence", "controlDirectory", "controlDirectoryIdentity", "operationWallTime", "executionSha256")
    private val RUNTIME_FIELDS = setOf("provider", "configurationSha256", "deploymentClosureSha256", "runtimeMounts", "readOnlyInputs",
        "keeperEntryPoint", "requestVersion", "commandRequestProvider", "commandRequestSha256", "resources", "terminalResourcePolicySha256",
        "fileDescriptorAdmission", "controlDirectory", "writableRoot", "readOnlyStateDirectory", "operationWallDeadline")
    private val LIMITS = StrictJsonLimits(maximumInputBytes = 4 * 1024 * 1024, maximumCanonicalBytes = 4 * 1024 * 1024,
        maximumDepth = 16, maximumNodes = 65536, maximumStringBytes = 65536, maximumTotalStringBytes = 4 * 1024 * 1024,
        maximumNumberCharacters = 32)
}
