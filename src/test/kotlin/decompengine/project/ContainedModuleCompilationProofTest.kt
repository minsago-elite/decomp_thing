package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.ContainedCommandTerminalResourceEvidence
import decompengine.oracle.fulltree.KotlinContainedCommandOutcome
import decompengine.oracle.fulltree.KotlinContainedCommandProtocol
import decompengine.oracle.fulltree.KotlinContainedCommandRequest
import decompengine.oracle.fulltree.isolatedObservationServiceRuntimeSeconds
import decompengine.oracle.fulltree.runDirectoryName
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Synthetic replay fixtures prove bindings only; they confer no live authority or production qualification. */
class ContainedModuleCompilationProofTest {
    @Test
    fun `historical proof binds exact successful object and failed compiler observations`() {
        for (success in listOf(true, false)) {
            val fixture = fixture(success)
            val verified = ContainedModuleCompilationProof.verify(fixture.proof)
            assertEquals(fixture.request.sha256, verified.request.sha256)
            assertEquals(fixture.result.sha256, verified.result.sha256)
            val evidence = fixture.evidence()
            ContainedModuleCompilationProof.verify(evidence)
            assertEquals(success, evidence.passed)
            assertFalse(evidence.authorizesAcceptance(fixture.request.sourceSha256, fixture.request.profileSha256,
                ContainedModuleCompilationPolicy.POLICY_ID))
            assertEquals(ContainedModuleCompilationProof.diagnosticsSha256(fixture.result), evidence.diagnosticsSha256)
        }
    }

    @Test
    fun `budget variant proofs preserve requested profile and reject a default budget deadline`() {
        for (base in ReconstructionProfiles.builtIn) {
            val profile = ReconstructionProfile(base.schemaVersion, base.id, base.layout,
                base.budgets.copy(buildWallClockMillis = 8345, buildMaximumOutputBytes = 4096,
                    reconstructionMaximumContextCharacters = 2048), base.adapterConfiguration)
            val fixture = fixture(profile = profile)
            val verified = ContainedModuleCompilationProof.verify(fixture.evidence())
            assertEquals(profile.sha256, verified.request.profile.sha256)
            assertEquals(profile.canonicalJson(), verified.request.profile.canonicalJson())
            assertFalse(fixture.evidence().authorizesAcceptance(fixture.request.sourceSha256, profile.sha256,
                ContainedModuleCompilationPolicy.POLICY_ID))
            val execution = fixture.proof.objectField("execution")
            val deadline = execution.objectField("operationWallTime")
            val widened = change(change(deadline, "maximumWallMillis", JsonPrimitive(120_000)),
                "remainingNanos", JsonPrimitive(119_999_000_000))
            reject(change(fixture.proof, "execution", seal(change(execution, "operationWallTime", widened), "executionSha256")))
            // All command, CPU, service, attachment and execution hashes are coherent, but this
            // wider service allowance could not have been emitted inside the requested operation.
            reject(fixture(profile = profile, serviceSeconds = 60).proof)
            val defaultFixture = fixture(profile = base)
            reject(change(fixture.proof, "result", defaultFixture.proof.getValue("result")))
            val request = fixture.proof.objectField("request")
            reject(change(fixture.proof, "request", change(request, "profile", document(base.canonicalJson().toByteArray(), canonical = false))))
        }
    }

    @Test
    fun `common evidence cannot relabel a compiler result or change exact source command or diagnostics`() {
        val fixture = fixture()
        val evidence = fixture.evidence()
        listOf<() -> ModuleCompilationEvidence>(
            { changedEvidence(evidence, sourceSha256 = OTHER) },
            { changedEvidence(evidence, command = listOf("cc", "unbound.c")) },
            { changedEvidence(evidence, outcome = "failed") }, { changedEvidence(evidence, returnCode = 1) },
            { changedEvidence(evidence, diagnosticsSha256 = OTHER) }, { changedEvidence(evidence, diagnosticsBytes = 1) },
            { changedEvidence(evidence, containedProof = null) },
        ).forEach { invalid ->
            assertFailsWith<IllegalArgumentException> { ContainedModuleCompilationProof.verify(invalid()) }
        }
        assertFailsWith<IllegalArgumentException> { changedEvidence(fixture(false).evidence(), outcome = "passed") }
    }

    @Test
    fun `closed proof requires every binding and complete cleanup`() {
        val fixture = fixture()
        fixture.proof.keys.forEach { field -> reject(JsonObject(fixture.proof - field)) }
        reject(change(fixture.proof, "unrecordedAuthority", JsonPrimitive(true)))
        listOf("provider" to JsonPrimitive("local-compiler"), "scope" to JsonPrimitive("whole-project"),
            "policyId" to JsonPrimitive("generated-c-module-validation-v2"), "schemaVersion" to JsonPrimitive("1"),
            "profileId" to JsonPrimitive(GeneratedCNinjaReconstructionProfile.PROFILE_ID), "profileSha256" to JsonPrimitive(OTHER),
            "sourceSha256" to JsonPrimitive(OTHER), "snapshotSha256" to JsonPrimitive(OTHER),
            "runtimeConfigurationSha256" to JsonPrimitive(OTHER)).forEach { (field, value) -> reject(change(fixture.proof, field, value)) }
        val cleanup = fixture.proof.objectField("cleanup")
        cleanup.keys.forEach { field ->
            reject(change(fixture.proof, "cleanup", JsonObject(cleanup - field)))
            reject(change(fixture.proof, "cleanup", change(cleanup, field, JsonPrimitive(false))))
        }
        reject(change(fixture.proof, "cleanup", change(cleanup, "unexpected", JsonPrimitive(true))))
    }

    @Test
    fun `worker result and disk lease cannot be borrowed from another request runtime or source`() {
        val fixture = fixture()
        for (field in listOf("requestSha256", "nonce", "sourceSha256", "snapshotSha256", "compilerSha256")) {
            reject(changeNested(fixture.proof, "result", field, JsonPrimitive("d".repeat(64))))
        }
        for (field in listOf("nonce", "sourceSha256", "sourcePath", "runtimeConfigurationSha256")) {
            reject(changeNested(fixture.proof, "intent", field, JsonPrimitive(OTHER)))
        }
        for ((field, value) in listOf("operationId" to JsonPrimitive(OTHER), "requestSha256" to JsonPrimitive(OTHER),
            "scopeSha256" to JsonPrimitive(OTHER), "mountPathSha256" to JsonPrimitive(OTHER),
            "shardId" to JsonPrimitive("another-operation"), "maximumFilesystemBytes" to JsonPrimitive(4L * 1024 * 1024 * 1024))) {
            val disk = seal(change(fixture.proof.objectField("diskLease"), field, value), "evidenceSha256")
            reject(change(fixture.proof, "diskLease", disk))
        }
        val changedCompiler = changeNested(fixture.proof.objectField("runtimeConfiguration"), "compiler", "sha256", JsonPrimitive("d".repeat(64)))
        reject(change(fixture.proof, "runtimeConfiguration", changedCompiler))
    }

    @Test
    fun `exact Java command rejects worker classpath option and request-path substitution`() {
        val fixture = fixture()
        val original = fixture.command.command
        val alternatives = listOf(
            listOf(original.first(), "-javaagent:/opt/attacker.jar") + original.drop(1),
            original.map { if (it == ContainedModuleCompilerWorker::class.java.name) "other.Worker" else it },
            original.map { if (it.contains("classpath-0.jar")) "/opt/unbound.jar" else it },
            original.dropLast(2) + listOf("${fixture.request.outputDirectory}/request.json", fixture.request.sha256),
            original.dropLast(2) + listOf("/opt/module-compiler/.module-compilation-fixture/request.json", fixture.request.sha256),
            original.dropLast(1) + OTHER,
        )
        alternatives.forEach { arguments -> reject(changeNested(fixture.proof, "commandRequest", "command", JsonArray(arguments.map(::JsonPrimitive)))) }
        reject(changeNested(fixture.proof, "commandRequest", "runDirectory", JsonPrimitive("/srv/unowned-control")))
        reject(changeNested(fixture.proof, "commandRequest", "allowInterruption", JsonPrimitive(true)))
        reject(changeNested(fixture.proof, "commandRequest", "terminalResourcePolicySha256", JsonPrimitive(OTHER)))
    }

    @Test
    fun `rehashed terminal records still require configured scope finite resources and captured result length`() {
        val fixture = fixture()
        val attachment = fixture.proof.objectField("attachment")
        listOf("requestSha256", "nonce", "deploymentClosureSha256").forEach { field ->
            reject(change(fixture.proof, "attachment", seal(change(attachment, field, JsonPrimitive(OTHER)), "attachmentSha256")))
        }
        reject(change(fixture.proof, "attachment", seal(change(attachment, "controlGroup", JsonPrimitive("/other/${attachment.text("unitName")}")), "attachmentSha256")))
        reject(change(fixture.proof, "attachment", seal(change(attachment, "extra", JsonPrimitive(true)), "attachmentSha256")))
        for ((field, value) in listOf("wallClockMillis" to 61_000L, "maximumResidentBytes" to 1024L * 1024 * 1024,
            "pidsMax" to 129L, "maximumFileBytes" to 128L * 1024 * 1024, "cpuSeconds" to 1L)) {
            reject(change(fixture.proof, "attachment", seal(changeNested(attachment, "resources", field, JsonPrimitive(value)), "attachmentSha256")))
        }
        val execution = fixture.proof.objectField("execution")
        for ((field, value) in listOf("controlDirectory" to JsonPrimitive("/srv/other"), "unitAbsent" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(true), "childExitCode" to JsonPrimitive(1), "extra" to JsonPrimitive(true))) {
            reject(change(fixture.proof, "execution", seal(change(execution, field, value), "executionSha256")))
        }
        val wrongOutput = change(execution.objectField("outcome"), "stdoutBytes", JsonPrimitive(fixture.result.canonicalBytes.size + 1))
        val wrongCapture = seal(change(change(execution, "outcome", wrongOutput), "outcomeSha256", JsonPrimitive(sha256(bytes(wrongOutput)))), "executionSha256")
        reject(change(fixture.proof, "execution", wrongCapture))
        reject(change(fixture.proof, "execution", seal(changeNested(execution, "operationWallTime", "remainingNanos", JsonPrimitive(0)), "executionSha256")))
        reject(change(fixture.proof, "execution", seal(changeNested(execution, "cgroup", "memoryOomEvents", JsonPrimitive(1)), "executionSha256")))
        reject(change(fixture.proof, "execution", seal(changeNested(execution, "controlDirectoryIdentity", "device", JsonPrimitive(999)), "executionSha256")))
    }

    @Test
    fun `successful child exit cannot hide terminal resource events or missing frozen proof`() {
        val fixture = fixture()
        val execution = fixture.proof.objectField("execution")
        val terminal = execution.objectField("terminalResourceEvidence")
        val changed = changeNested(terminal, "final", "pids", JsonObject(mapOf("max" to JsonPrimitive(1))))
        reject(change(fixture.proof, "execution", seal(change(execution, "terminalResourceEvidence", changed), "executionSha256")))
        reject(change(fixture.proof, "execution", seal(changeNested(execution, "terminalResourceEvidence", "keeperOnly", JsonPrimitive(false)), "executionSha256")))
        reject(change(fixture.proof, "execution", seal(JsonObject(execution - "terminalResourceEvidence"), "executionSha256")))
        assertTrue(fixture.evidence().passed)
        assertFalse(fixture(false).evidence().passed)
    }

    @Test
    fun `same-length forged worker result cannot replace pipe-authenticated bytes`() {
        val fixture = fixture()
        val retained = fixture.proof.objectField("result")
        for (field in listOf("objectSha256", "stdoutSha256", "stderrSha256")) {
            val forged = change(retained, field, JsonPrimitive("d".repeat(64)))
            assertEquals(bytes(retained).size, bytes(forged).size)
            // Request/source/profile binding and the old authenticated byte count still match.
            ContainedModuleCompilerResult.parse(bytes(forged)).requireBinding(fixture.request)
            reject(change(fixture.proof, "result", forged))
        }
    }

    private data class Fixture(val proof: JsonObject, val request: ContainedModuleCompilerRequest,
        val result: ContainedModuleCompilerResult, val command: KotlinContainedCommandRequest) {
        fun evidence() = ModuleCompilationEvidence(request.sourceSha256,
            ContainedModuleCompilationPolicy.command(request.profile, request.sourcePath),
            if (result.outcome == "compiled-object") "passed" else "failed", result.exitCode,
            ContainedModuleCompilationProof.diagnosticsSha256(result), result.stdoutBytes + result.stderrBytes, containedProof = proof)
    }

    private fun fixture(success: Boolean = true, profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
        serviceSeconds: Long = minOf(60L, moduleCompilerOperationWallMillis(profile) / 1000L)): Fixture {
        val runtimeRecord = runtimeRecord(profile.id)
        val runtime = ContainedModuleCompilationRuntimeConfiguration.parse(bytes(runtimeRecord))
        val operationMillis = moduleCompilerOperationWallMillis(profile)
        val run = runtime.scratchMount.resolve(".decomp-oracle-lease-$NONCE").resolve(runDirectoryName(NONCE))
        val control = run.resolve("control-$NONCE")
        val request = ContainedModuleCompilerRequest(NONCE, profile.id, profile.sha256, run.resolve("state/snapshot"),
            "src/modules/sample.c", listOf(ContainedModuleCompilerInput("src/modules/sample.c", SOURCE, 16)),
            runtime.compilerExecutable, runtime.compilerSha256, run.resolve("reports"),
            minOf(30_000L, profile.budgets.buildWallClockMillis), minOf(2L * 1024 * 1024, profile.budgets.buildMaximumOutputBytes),
            document(profile.canonicalJson().toByteArray(), canonical = false))
        val result = ContainedModuleCompilerResult(request.sha256, NONCE, profile.id, profile.sha256, request.snapshotSha256,
            request.sourceSha256, runtime.compilerSha256, if (success) "compiled-object" else "compiler-failed", if (success) 0 else 2,
            null, sha256(byteArrayOf()), 0, sha256(byteArrayOf()), 0, if (success) OTHER else null, if (success) 64 else null)
        val command = KotlinContainedCommandRequest(control, NONCE,
            containedModuleCompilerCommand(runtime.isolation, Path.of("/projects/example/.module-compilation-fixture/request.json"), request),
            mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"), minOf(isolatedObservationServiceRuntimeSeconds(serviceSeconds), 300),
            serviceSeconds, ContainedModuleCompilerRequest.MAXIMUM_OBJECT_BYTES, ContainedModuleCompilerRequest.MAXIMUM_OBJECT_BYTES,
            terminalResourcePolicySha256 = ContainedCommandTerminalResourceEvidence.policySha256)
        val common = mapOf("profileId" to JsonPrimitive(profile.id), "profileSha256" to JsonPrimitive(profile.sha256),
            "sourceSha256" to JsonPrimitive(request.sourceSha256), "snapshotSha256" to JsonPrimitive(request.snapshotSha256),
            "runtimeConfigurationSha256" to JsonPrimitive(runtime.configurationSha256))
        val intent = JsonObject(common + mapOf("provider" to JsonPrimitive("module-compilation-intent-v1"),
            "nonce" to JsonPrimitive(NONCE), "sourcePath" to JsonPrimitive(request.sourcePath)))
        val disk = seal(JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive("dedicated-ext4-filesystem-v1"),
            "operationId" to JsonPrimitive(NONCE), "requestSha256" to JsonPrimitive(sha256(bytes(intent))),
            "shardId" to JsonPrimitive("module-compile"), "scopeSha256" to JsonPrimitive(runtime.configurationSha256),
            "mountPathSha256" to JsonPrimitive(sha256(runtime.scratchMount.toString().toByteArray())),
            "mountId" to JsonPrimitive(2), "device" to JsonPrimitive(3), "rootInode" to JsonPrimitive(4),
            "filesystemDevice" to JsonPrimitive("8:1"), "filesystemType" to JsonPrimitive("ext4"),
            "fragmentBytes" to JsonPrimitive(4096), "totalBytes" to JsonPrimitive(1024L * 1024 * 1024),
            "initialAvailableBytes" to JsonPrimitive(512L * 1024 * 1024), "totalInodes" to JsonPrimitive(100_000),
            "initialAvailableInodes" to JsonPrimitive(99_000), "ownerUid" to JsonPrimitive(1000), "mode" to JsonPrimitive(448),
            "mountFlags" to JsonArray(listOf("noatime", "nodev", "noexec", "nosuid", "rw").map(::JsonPrimitive)),
            "requiredAvailableBytes" to JsonPrimitive(runtime.scratchPolicy.requiredAvailableBytes),
            "maximumFilesystemBytes" to JsonPrimitive(runtime.scratchPolicy.maximumFilesystemBytes),
            "requiredAvailableInodes" to JsonPrimitive(runtime.scratchPolicy.requiredAvailableInodes),
            "maximumFilesystemInodes" to JsonPrimitive(runtime.scratchPolicy.maximumFilesystemInodes),
            "leaseRootDevice" to JsonPrimitive(3), "leaseRootInode" to JsonPrimitive(5), "leaseRecordSha256" to JsonPrimitive(OTHER),
        )), "evidenceSha256")
        val unit = "decomp-module-compile-${NONCE.take(32)}.scope"
        val attachment = seal(JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(3), "provider" to JsonPrimitive("kotlin-lease-contained-command-attachment-v3"),
            "unitName" to JsonPrimitive(unit), "nonce" to JsonPrimitive(NONCE),
            "bootId" to JsonPrimitive("11111111-2222-3333-4444-555555555555"), "invocationId" to JsonPrimitive("d".repeat(32)),
            "controlGroup" to JsonPrimitive("${runtime.managerControlGroup}/app.slice/$unit"),
            "cgroupDevice" to JsonPrimitive(10), "cgroupInode" to JsonPrimitive(20), "cgroupMountId" to JsonPrimitive(30),
            "requestSha256" to JsonPrimitive(command.sha256), "deploymentClosureSha256" to JsonPrimitive(runtime.configurationSha256),
            "runtimeClosureSha256" to JsonPrimitive(OTHER), "resources" to JsonObject(mapOf(
                "wallClockMillis" to JsonPrimitive(serviceSeconds * 1000), "maximumResidentBytes" to JsonPrimitive(512L * 1024 * 1024),
                "pidsMax" to JsonPrimitive(128), "maximumFileBytes" to JsonPrimitive(ContainedModuleCompilerRequest.MAXIMUM_OBJECT_BYTES),
                "maximumAddressSpaceBytes" to JsonPrimitive(8L * 1024 * 1024 * 1024),
                "cpuSeconds" to JsonPrimitive(isolatedObservationServiceRuntimeSeconds(serviceSeconds)),
                "serviceRuntimeSeconds" to JsonPrimitive(isolatedObservationServiceRuntimeSeconds(serviceSeconds)),
            )), "releaseEligible" to JsonPrimitive(false), "processes" to keeperProcesses(),
            "terminalResourcePolicySha256" to JsonPrimitive(ContainedCommandTerminalResourceEvidence.policySha256),
            "terminalResourceBaseline" to counters().json,
        )), "attachmentSha256")
        val outcome = document(KotlinContainedCommandProtocol.outcome(ByteArray(32), command,
            KotlinContainedCommandOutcome(123, 124, 0, 1, result.canonicalBytes.size.toLong(), 0, "EXITED",
                stdoutSha256 = result.sha256, stderrSha256 = sha256(byteArrayOf()))))
        val execution = seal(JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(3), "provider" to JsonPrimitive("kotlin-lease-contained-command-execution-v3"),
            "attachmentSha256" to JsonPrimitive(sha256(bytes(attachment))), "requestSha256" to JsonPrimitive(command.sha256),
            "deploymentClosureSha256" to JsonPrimitive(runtime.configurationSha256), "outcome" to outcome,
            "outcomeSha256" to JsonPrimitive(sha256(bytes(outcome))), "childExitCode" to JsonPrimitive(0),
            "derivationWallNanos" to JsonPrimitive(1_000_000), "unitAbsent" to JsonPrimitive(true), "cgroupAbsent" to JsonPrimitive(true),
            "processesAbsent" to JsonPrimitive(true), "releaseEligible" to JsonPrimitive(false),
            "cgroup" to JsonObject(mapOf("peakResidentBytes" to JsonPrimitive(128L * 1024 * 1024), "cpuNanos" to JsonPrimitive(1000),
                "memoryMaxEvents" to JsonPrimitive(0), "memoryOomEvents" to JsonPrimitive(0), "memoryOomKillEvents" to JsonPrimitive(0))),
            "terminalResourceEvidence" to ContainedCommandTerminalResourceEvidence.create(bytes(attachment), counters()),
            "controlDirectory" to JsonPrimitive(control.toString()), "controlDirectoryIdentity" to JsonObject(mapOf(
                "name" to JsonPrimitive(control.fileName.toString()), "device" to JsonPrimitive(3), "inode" to JsonPrimitive(6),
                "mountId" to JsonPrimitive(2), "uid" to JsonPrimitive(1000), "gid" to JsonPrimitive(1000),
                "mode" to JsonPrimitive(448), "linkCount" to JsonPrimitive(6))),
            "operationWallTime" to JsonObject(mapOf("provider" to JsonPrimitive("kotlin-contained-operation-wall-deadline-v1"),
                "maximumWallMillis" to JsonPrimitive(operationMillis), "startedMonotonicNanos" to JsonPrimitive(-1000),
                "elapsedNanos" to JsonPrimitive(1_000_000), "remainingNanos" to JsonPrimitive(operationMillis * 1_000_000 - 1_000_000))),
        )), "executionSha256")
        val proof = JsonObject(common + mapOf("schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive("contained-module-compilation-v1"),
            "scope" to JsonPrimitive("module-object"), "policyId" to JsonPrimitive(ContainedModuleCompilationPolicy.POLICY_ID),
            "runtimeConfiguration" to runtimeRecord, "intent" to intent, "request" to document(request.canonicalBytes),
            "result" to document(result.canonicalBytes), "commandRequest" to document(command.canonicalBytes),
            "attachment" to attachment, "execution" to execution, "diskLease" to disk,
            "cleanup" to JsonObject(listOf("processesAbsent", "unitAbsent", "cgroupAbsent", "scratchRemoved", "leaseReleased")
                .associateWith { JsonPrimitive(true) })))
        return Fixture(proof, request, result, command)
    }

    private fun runtimeRecord(profileId: String): JsonObject {
        fun mount(source: String, destination: String = source) = JsonObject(mapOf("source" to JsonPrimitive(source),
            "destination" to JsonPrimitive(destination), "sha256" to JsonPrimitive(OTHER)))
        return JsonObject(mapOf("schemaVersion" to JsonPrimitive(1), "profileId" to JsonPrimitive(profileId),
            "compiler" to JsonObject(mapOf("path" to JsonPrimitive("/opt/module-compiler/bin/cc"), "sha256" to JsonPrimitive(OTHER))),
            "compilerRuntimeMounts" to JsonArray(listOf(mount("/opt/module-compiler"))), "scratchMount" to JsonPrimitive("/srv/module-scratch"),
            "managerControlGroup" to JsonPrimitive("/user.slice/user-1000.slice/user@1000.service"),
            "scratchPolicy" to JsonObject(mapOf("requiredAvailableBytes" to JsonPrimitive(1_048_576),
                "maximumFilesystemBytes" to JsonPrimitive(8L * 1024 * 1024 * 1024),
                "requiredAvailableInodes" to JsonPrimitive(1024), "maximumFilesystemInodes" to JsonPrimitive(1_048_576))),
            "isolation" to JsonObject(mapOf("javaExecutable" to JsonPrimitive("/opt/keeper-java/bin/java"),
                "javaRuntime" to mount("/opt/keeper-java", "/keeper-java"),
                "systemLibraryMounts" to JsonArray(listOf(mount("/opt/keeper-libraries", "/lib64"))),
                "bubblewrapExecutable" to JsonPrimitive("/opt/helpers/bwrap"), "resourceLimiterExecutable" to JsonPrimitive("/opt/helpers/prlimit"),
                "scopeSupervisorExecutable" to JsonPrimitive("/opt/helpers/systemd-run"), "scopeInspectorExecutable" to JsonPrimitive("/opt/helpers/systemctl"),
                "systemdBusControllerExecutable" to JsonPrimitive("/opt/helpers/busctl"), "systemdUserRuntimeDirectory" to JsonPrimitive("/run/user/1000"),
                "workerClassPath" to JsonArray(listOf(JsonObject(mapOf("path" to JsonPrimitive("/opt/worker/worker.jar"), "sha256" to JsonPrimitive(OTHER))))),
                "expectedJavaSha256" to JsonPrimitive(OTHER), "expectedBubblewrapSha256" to JsonPrimitive(OTHER),
                "expectedResourceLimiterSha256" to JsonPrimitive(OTHER), "expectedScopeSupervisorSha256" to JsonPrimitive(OTHER),
                "expectedScopeInspectorSha256" to JsonPrimitive(OTHER), "expectedSystemdBusControllerSha256" to JsonPrimitive(OTHER))),
        ))
    }

    private fun counters() = ContainedCommandTerminalResourceEvidence.Counters.parseKernel("max 0\n", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n")
    private fun keeperProcesses(): JsonArray {
        val roles = listOf("outer-bubblewrap", "namespace-init-bubblewrap", "supervisor-jvm")
        return JsonArray(roles.mapIndexed { index, role -> JsonObject(mapOf("role" to JsonPrimitive(role),
            "hostPid" to JsonPrimitive(1000 + index), "startTimeTicks" to JsonPrimitive(100),
            "parentRole" to if (index == 0) JsonNull else JsonPrimitive(roles[index - 1]),
            "namespacePids" to JsonArray((listOf(1000 + index) + when (index) { 1 -> listOf(1); 2 -> listOf(123); else -> emptyList() }).map(::JsonPrimitive)),
            "executableDevice" to JsonPrimitive(2), "executableInode" to JsonPrimitive(2000 + index), "executableMountId" to JsonPrimitive(3))) })
    }
    private fun reject(proof: JsonObject) { assertFailsWith<IllegalArgumentException> { ContainedModuleCompilationProof.verify(proof) } }
    private fun changedEvidence(original: ModuleCompilationEvidence, sourceSha256: String = original.sourceSha256,
        command: List<String> = original.command, outcome: String = original.outcome, returnCode: Int? = original.returnCode,
        diagnosticsSha256: String = original.diagnosticsSha256, diagnosticsBytes: Long = original.diagnosticsBytes,
        containedProof: JsonObject? = original.containedProof) =
        ModuleCompilationEvidence(sourceSha256, command, outcome, returnCode, diagnosticsSha256, diagnosticsBytes, containedProof)
    private fun change(value: JsonObject, field: String, replacement: JsonElement) = JsonObject(value + (field to replacement))
    private fun changeNested(value: JsonObject, objectField: String, field: String, replacement: JsonElement) =
        change(value, objectField, change(value.objectField(objectField), field, replacement))
    private fun seal(value: JsonObject, field: String): JsonObject {
        val unsigned = JsonObject(value - field)
        return change(unsigned, field, JsonPrimitive(sha256(bytes(unsigned))))
    }
    private fun document(bytes: ByteArray, canonical: Boolean = true) =
        (if (canonical) OracleJson.parseCanonical(bytes) else OracleJson.parse(bytes)) as JsonObject
    private fun bytes(value: JsonObject) = OracleJson.canonicalBytes(value)
    private fun JsonObject.objectField(field: String) = getValue(field) as JsonObject
    private fun JsonObject.text(field: String) = (getValue(field) as JsonPrimitive).content
    private companion object {
        val NONCE = "a".repeat(64)
        val SOURCE = "b".repeat(64)
        val OTHER = "c".repeat(64)
    }
}
