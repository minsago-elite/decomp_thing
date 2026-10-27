package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.fulltree.FullTreeDiskScratchEvidence
import decompengine.oracle.reference.ReferenceCorpusCoordinator
import decompengine.oracle.reference.ReferenceCorpusDefinition
import decompengine.oracle.reference.ReferenceCorpusDeployment
import decompengine.oracle.reference.ReferenceCorpusRetainedFailure
import decompengine.oracle.reference.ReferenceCorpusWorkerObservations
import decompengine.oracle.reference.ReferenceCorpusWorkerRequest
import decompengine.oracle.reference.ReferenceNativeRuntime
import decompengine.oracle.reference.RetainedReferenceCorpusCapture
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.Base64
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Installed reference owner: only real retained captures can reach qualification publication. */
object GccMetadataReferenceQualificationCli {
    private const val USAGE = "Usage: qualify <profileRoot> <ociLayout> <runtimeRoot> <deploymentJson> " +
        "<firstJournalRoot> <firstScratchMount> <replayJournalRoot> <replayScratchMount> <reportPath> | " +
        "provision <profileRoot> <ociLayout> <freshRuntimeRoot> <jdkRoot> <deploymentJson> <controllerUid>"

    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.isNotEmpty()) { USAGE }
        require((arguments[0] == "qualify" && arguments.size == 10) ||
            (arguments[0] == "provision" && arguments.size == 7)) { USAGE }
        if (arguments[0] == "provision") {
            val paths = arguments.slice(1..5).map(::qualificationPath)
            GccMetadataReferenceProvisioning.provision(paths[0], paths[1], paths[2], paths[3], paths[4],
                metadataReferenceControllerUid(arguments[6]))
        } else {
            val session = GccMetadataReferenceControllerSession.forUid(
                (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toLong())
            qualify(arguments.drop(1).map(::qualificationPath), session)
        }
    }

    private fun qualify(paths: List<Path>, session: GccMetadataReferenceControllerSession) {
        val (profileRoot, ociLayout, runtimeRoot, deploymentPath) = paths
        val journalRoots = listOf(paths[4], paths[6])
        val scratchMounts = listOf(paths[5], paths[7])
        val reportPath = paths[8]
        val operationRoots = journalRoots + scratchMounts
        require(operationRoots.indices.all { i -> operationRoots.drop(i + 1).none { overlaps(operationRoots[i], it) } }) {
            "qualification operations require distinct disjoint journal and scratch roots"
        }
        operationRoots.forEach { requirePrivateQualificationDirectory(it, session.uid) }
        journalRoots.forEach { root -> Files.list(root).use { require(it.findAny().isEmpty) { "qualification journal root is not fresh" } } }
        require(Files.getAttribute(scratchMounts[0], "unix:dev") != Files.getAttribute(scratchMounts[1], "unix:dev")) {
            "independent replay requires two separately provisioned scratch filesystems"
        }
        require((operationRoots + listOf(profileRoot, ociLayout, runtimeRoot, deploymentPath)).none { overlaps(reportPath, it) }) {
            "qualification report overlaps an input or retained operation"
        }
        requirePrivateQualificationDirectory(reportPath.parent, session.uid)
        require(!Files.exists(reportPath, NOFOLLOW_LINKS)) { "qualification report already exists" }
        GccMetadataReferenceInstalledController.open().use { controller ->
            StableControlFile.open(deploymentPath, 256 * 1024L, "qualification deployment").use { deploymentGuard ->
                deploymentGuard.requireSingleLink("qualification deployment")
                val deployment = ReferenceCorpusDeployment.open(deploymentPath)
                session.requireDeployment(deployment)
                controller.requireDeployment(deployment.configuration)
                val deploymentBytes = deploymentGuard.readExactly(0, deploymentGuard.size.toInt(), "qualification deployment")
                deploymentGuard.verifyUnchanged("qualification deployment admission")
                GccMetadataReferenceProfile.open(profileRoot).use { profile ->
                    FrozenGccMetadataReference.open(profileRoot).use { frozen ->
                        ReferenceNativeRuntime.admit(ociLayout, runtimeRoot, profile).use { runtime ->
                            val declarationPath = reportPath.resolveSibling(GccOrchestrationReferenceDeclaration.FILE_NAME)
                            val declaration = GccOrchestrationReferenceDeclaration.declare(profile, runtime)
                            LinuxFilesystemSyscalls.openRoot(reportPath.parent).use { destination ->
                                DescriptorBoundAtomicStateFile.publishManifestNoReplace(destination, declarationPath.fileName.toString(),
                                    declaration, GccOrchestrationReferenceDeclaration.MAXIMUM_BYTES)
                                require(Files.isSameFile(reportPath.parent, LinuxFilesystemSyscalls.descriptorPath(destination)))
                            }
                            StableControlFile.open(declarationPath, GccOrchestrationReferenceDeclaration.MAXIMUM_BYTES.toLong(),
                                "installed orchestration declaration").use { declarationGuard ->
                                declarationGuard.requireSingleLink("installed orchestration declaration")
                                require(declarationGuard.size == declaration.size.toLong() &&
                                    declarationGuard.authenticatedSha256 == OracleArtifacts.sha256(declaration)) {
                                    "installed orchestration declaration changed during publication"
                                }
                                fun capture(index: Int): RetainedReferenceCorpusCapture = try {
                                    ReferenceCorpusCoordinator.captureRetained(profile, runtime, deployment.configuration,
                                        journalRoots[index], scratchMounts[index], deployment.expectedCgroupParent)
                                } catch (failure: ReferenceCorpusRetainedFailure) {
                                    try { failure.close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
                                    throw failure
                                }
                                capture(0).use { first ->
                                    capture(1).use { replay ->
                                        require(first.operationId != replay.operationId) { "independent captures reused an operation identity" }
                                        val captures = listOf(first, replay)
                                        val checked = captures.map { captured ->
                                            captured.requireCurrent("before frozen reference comparison")
                                            GccMetadataReferenceComparison.verify(profile.definition, frozen.bytes,
                                                captured.canonicalBytes, runtime.identitySha256)
                                        }
                                        require(checked[0].stableCases.contentEquals(checked[1].stableCases)) {
                                            "independent fresh reference operations produced different stable case bytes"
                                        }
                                        val operations = captures.mapIndexed { index, captured ->
                                            qualificationOperation(captured, profile.definition, deployment,
                                                journalRoots[index], scratchMounts[index])
                                        }
                                        val report = JsonObject(mapOf(
                                            "schemaVersion" to JsonPrimitive(2),
                                            "provider" to JsonPrimitive("gcc-metadata-reference-owner-qualification-v2"),
                                            "qualificationKind" to JsonPrimitive("original-reference-execution-and-independent-replay"),
                                            "controller" to controller.evidence(),
                                            "deployment" to fileIdentity(deploymentPath, deploymentBytes),
                                            "deploymentConfigurationSha256" to JsonPrimitive(deployment.configuration.canonicalSha256),
                                            "expectedCgroupParent" to JsonPrimitive(deployment.expectedCgroupParent),
                                            "frozenReference" to fileIdentity(frozen.path, frozen.bytes),
                                            "profile" to JsonObject(mapOf("registrationId" to JsonPrimitive(profile.registrationId),
                                                "path" to JsonPrimitive(profile.profilePath.toString()), "sha256" to JsonPrimitive(profile.profileSha256),
                                                "inputs" to JsonArray(profile.inputBindings.map { binding -> JsonObject(mapOf(
                                                    "id" to JsonPrimitive(binding.id), "path" to JsonPrimitive(binding.path.toString()),
                                                    "bytes" to JsonPrimitive(binding.bytes), "sha256" to JsonPrimitive(binding.sha256))) }))),
                                            "nativeRuntime" to OracleJson.parseCanonical(runtime.canonicalBytes),
                                            "nativeRuntimeSha256" to JsonPrimitive(runtime.identitySha256),
                                            "orchestrationDeclaration" to fileIdentity(declarationPath, declaration),
                                            "operations" to JsonArray(operations),
                                            "stableCasesSha256" to JsonPrimitive(OracleArtifacts.sha256(checked[0].stableCases)),
                                            "cases" to OracleJson.parseCanonical(checked[0].stableCases, QUALIFICATION_LIMITS),
                                            "caseCount" to JsonPrimitive(19), "independentOperationCount" to JsonPrimitive(2),
                                            "processCounterPhase" to JsonPrimitive("pre-teardown-frozen-sample"),
                                            "processCountersAreTerminalFacts" to JsonPrimitive(false),
                                            "executionAuthenticated" to JsonPrimitive(true), "referenceQualified" to JsonPrimitive(true),
                                            "candidateQualified" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
                                            "scratchDisposition" to JsonPrimitive("retained-for-trusted-reset"),
                                        ))
                                        fun verifyCurrent() {
                                            captures.forEach { it.requireCurrent("qualification publication") }
                                            controller.requireCurrent("qualification publication")
                                            frozen.requireCurrent()
                                            deploymentGuard.verifyUnchanged("qualification deployment publication")
                                            profile.requireCurrent("qualification publication")
                                            runtime.requireCurrent("qualification publication")
                                            declarationGuard.verifyUnchanged("qualification orchestration declaration")
                                        }
                                        verifyCurrent()
                                        LinuxFilesystemSyscalls.openRoot(reportPath.parent).use { destination ->
                                            DescriptorBoundAtomicStateFile.publishManifestNoReplace(destination, reportPath.fileName.toString(),
                                                OracleJson.canonicalBytes(report, QUALIFICATION_LIMITS), QUALIFICATION_BYTES)
                                            require(Files.isSameFile(reportPath.parent, LinuxFilesystemSyscalls.descriptorPath(destination))) {
                                                "qualification report parent changed during publication"
                                            }
                                            verifyCurrent()
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        println("Qualified original metadata reference and independent replay: $reportPath")
        println("Candidate qualification and release remain false.")
    }
}

/** A comparison result is data only. It cannot be supplied to the production capture path. */
internal class GccMetadataReferenceComparisonResult(stableCases: ByteArray) {
    private val stored = stableCases.copyOf()
    val stableCases: ByteArray get() = stored.copyOf()
}

internal object GccMetadataReferenceComparison {
    fun verify(definition: ReferenceCorpusDefinition, frozenBytes: ByteArray, actualBytes: ByteArray,
        runtimeSha256: String): GccMetadataReferenceComparisonResult {
        require(frozenBytes.size == FROZEN_BYTES && OracleArtifacts.sha256(frozenBytes) == FROZEN_SHA256) {
            "frozen metadata reference differs from its independently fixed identity"
        }
        val expected = OracleJson.parse(frozenBytes, QUALIFICATION_LIMITS).jsonObject.getValue("cases").jsonArray
        val actual = OracleJson.parseCanonical(actualBytes, QUALIFICATION_LIMITS).jsonObject
        actual.exactFields("schemaVersion", "provider", "registrationId", "profileSha256", "nativeRuntimeSha256", "operationId",
            "intentSha256", "casesSha256", "cases", "executionSha256ByBatch", "capturedOutputBytes", "workerObservationsSha256ByBatch",
            "executionAuthenticated", "referenceAuthority", "candidateQualified", "releaseEligible", "scratchDisposition", "operationWallTime")
        require(actual["schemaVersion"] == JsonPrimitive(1) && actual["provider"] == JsonPrimitive("authenticated-reference-corpus-v1"))
        require(actual["registrationId"] == JsonPrimitive(GccMetadataReferenceProfile.REGISTRATION_ID))
        require(actual["profileSha256"] == JsonPrimitive(OracleArtifacts.sha256(definition.canonicalBytes)))
        require(actual["nativeRuntimeSha256"] == JsonPrimitive(runtimeSha256))
        listOf("operationId", "intentSha256", "casesSha256").forEach { actual.digest(it) }
        require(actual["executionAuthenticated"] == JsonPrimitive(true) && actual["referenceAuthority"] == JsonPrimitive(true) &&
            actual["candidateQualified"] == JsonPrimitive(false) && actual["releaseEligible"] == JsonPrimitive(false))
        require(actual["scratchDisposition"] == JsonPrimitive("retained-for-trusted-reset"))
        require(actual.nonnegative("capturedOutputBytes") <= definition.limits.maximumAggregateOutputBytes)
        for (field in listOf("executionSha256ByBatch", "workerObservationsSha256ByBatch")) {
            val values = actual.getValue(field).jsonObject
            require(values.keys == definition.batches.keys)
            values.keys.forEach { values.digest(it) }
        }
        val cases = actual.getValue("cases").jsonArray
        require(definition.cases.size == 19 && expected.size == 19 && cases.size == 19) { "qualification requires all nineteen cases" }
        definition.cases.indices.forEach { index ->
            val policy = definition.cases[index]
            val baseline = expected[index].jsonObject
            val case = cases[index].jsonObject
            case.exactFields("id", "batchId", "arguments", "environment", "inputs", "stdin", "repetitions", "observed")
            require(case["id"] == JsonPrimitive(policy.id) && baseline["id"] == case["id"] && case["batchId"] == JsonPrimitive(policy.batchId))
            require(case["arguments"] == JsonArray(policy.arguments.map(::JsonPrimitive)) && baseline["arguments"] == case["arguments"])
            require(baseline["categories"] == JsonArray(policy.categories.map(::JsonPrimitive)))
            val environment = JsonObject(policy.environment.mapValues { JsonPrimitive(it.value) })
            require(case["environment"] == environment && baseline.getValue("environment").jsonObject +
                ("PATH" to environment.getValue("PATH")) == environment) { "case environment differs from frozen inputs" }
            val inputs = JsonArray(policy.inputs.map { JsonObject(mapOf("path" to JsonPrimitive(it.path),
                "bytes" to JsonPrimitive(it.bytes), "sha256" to JsonPrimitive(it.sha256))) })
            require(case["inputs"] == inputs && baseline["inputs"] == inputs)
            require(rawBlob(case.getValue("stdin").jsonObject, false).contentEquals(policy.stdin))
            val stdinIdentity = baseline.getValue("stdin").jsonObject
            require(stdinIdentity["bytes"] == JsonPrimitive(policy.stdin.size) &&
                stdinIdentity["sha256"] == JsonPrimitive(OracleArtifacts.sha256(policy.stdin)))
            require(case["repetitions"] == JsonPrimitive(2) && baseline["repetitions"] == JsonPrimitive(2))
            require(case.getValue("observed") == normalizeFrozenObservation(baseline.getValue("observed").jsonObject)) {
                "${policy.id}: raw reference observation differs from the independently pinned fixture"
            }
        }
        val stable = OracleJson.canonicalBytes(cases, QUALIFICATION_LIMITS)
        require(actual["casesSha256"] == JsonPrimitive(OracleArtifacts.sha256(stable))) { "stable case digest differs" }
        return GccMetadataReferenceComparisonResult(stable)
    }

    internal fun normalizeFrozenObservation(observed: JsonObject): JsonObject {
        observed.exactFields("exitCode", "stdout", "stderr", "artifacts")
        require(observed.nonnegative("exitCode") in 0..127)
        fun stripped(blob: JsonObject): JsonObject {
            rawBlob(blob, true)
            return JsonObject(blob - "text")
        }
        return JsonObject(mapOf("exitCode" to observed.getValue("exitCode"),
            "stdout" to stripped(observed.getValue("stdout").jsonObject),
            "stderr" to stripped(observed.getValue("stderr").jsonObject),
            "artifacts" to JsonArray(observed.getValue("artifacts").jsonArray.map { value ->
                val artifact = value.jsonObject
                JsonObject(stripped(JsonObject(artifact - "path")) + ("path" to artifact.getValue("path")))
            })))
    }
}

private class FrozenGccMetadataReference private constructor(val path: Path, private val guard: StableControlFile, bytes: ByteArray) : AutoCloseable {
    private val stored = bytes.copyOf()
    val bytes: ByteArray get() = stored.copyOf()
    fun requireCurrent() = guard.verifyUnchanged("frozen GCC metadata reference")
    override fun close() = guard.close()
    companion object {
        fun open(profileRoot: Path): FrozenGccMetadataReference {
            val path = profileRoot.resolve("metadata-diagnostic-reference.json")
            val guard = StableControlFile.open(path, FROZEN_BYTES.toLong(), "frozen GCC metadata reference")
            try {
                guard.requireSingleLink("frozen GCC metadata reference")
                require(guard.size == FROZEN_BYTES.toLong() && guard.authenticatedSha256 == FROZEN_SHA256)
                return FrozenGccMetadataReference(path, guard, guard.readExactly(0, FROZEN_BYTES, "frozen GCC metadata reference"))
            } catch (failure: Throwable) { guard.close(); throw failure }
        }
    }
}

private fun qualificationOperation(capture: RetainedReferenceCorpusCapture, definition: ReferenceCorpusDefinition,
    deployment: ReferenceCorpusDeployment, journalRoot: Path, scratchMount: Path): JsonObject {
    capture.requireCurrent("qualification receipt derivation")
    val snapshots = capture.journalSnapshots()
    val referenceBytes = capture.canonicalBytes
    val reference = OracleJson.parseCanonical(referenceBytes, QUALIFICATION_LIMITS).jsonObject
    require(capture.referencePath.parent.parent == journalRoot && reference["operationId"] == JsonPrimitive(capture.operationId))
    fun document(name: String) = OracleJson.parseCanonical(snapshots.getValue(name), QUALIFICATION_LIMITS).jsonObject
    val intent = document("intent.json")
    val intentSha = OracleArtifacts.sha256(snapshots.getValue("intent.json"))
    val lease = FullTreeDiskScratchEvidence.parseCanonical(snapshots.getValue("lease.json"))
    require(lease.operationId == capture.operationId && lease.requestSha256 == intentSha)
    require(reference["intentSha256"] == JsonPrimitive(intentSha) && intent["operationId"] == JsonPrimitive(capture.operationId))
    require(intent["journalRoot"] == JsonPrimitive(journalRoot.toString()) && intent["scratchMount"] == JsonPrimitive(scratchMount.toString()))
    require(intent["profileSha256"] == reference["profileSha256"] && intent["nativeRuntimeSha256"] == reference["nativeRuntimeSha256"])
    val expectedBatches = JsonArray(definition.batches.keys.map(::JsonPrimitive))
    require(intent["batches"] == expectedBatches)
    var previous = "lease.json"
    var capturedOutputBytes = 0L
    val expectedNames = mutableSetOf("intent.json", "lease.json", "reference-observations.json", "complete.json")
    fun linked(name: String, provider: String): JsonObject {
        val value = document(name)
        value.exactFields("schemaVersion", "provider", "operationId", "intentSha256", "previousSha256", "payload", "recordSha256")
        require(value["schemaVersion"] == JsonPrimitive(1) && value["provider"] == JsonPrimitive(provider) &&
            value["operationId"] == JsonPrimitive(capture.operationId) && value["intentSha256"] == JsonPrimitive(intentSha))
        require(value["previousSha256"] == JsonPrimitive(OracleArtifacts.sha256(snapshots.getValue(previous))))
        require(value["recordSha256"] == JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(value - "recordSha256"), QUALIFICATION_LIMITS))))
        previous = name
        return value.getValue("payload").jsonObject
    }
    val batches = definition.batches.keys.map { batch ->
        val names = listOf("request", "prepared", "attached", "started", "execution", "observations", "captured").map { "$it-$batch.json" }
        expectedNames.addAll(names)
        val requestBytes = snapshots.getValue("request-$batch.json")
        val request = ReferenceCorpusWorkerRequest.parse(requestBytes)
        require(request.batchId == batch && request.operationRequestSha256 == intentSha)
        val prepared = linked("prepared-$batch.json", "reference-batch-prepared-v1")
        require(prepared["batchId"] == JsonPrimitive(batch) && prepared["requestSha256"] == JsonPrimitive(OracleArtifacts.sha256(requestBytes)) &&
            prepared["configurationSha256"] == intent.getValue("configurationSha256ByBatch").jsonObject.getValue(batch))
        val attachment = linked("attached-$batch.json", "reference-batch-attached-v1")
        require(linked("started-$batch.json", "reference-batch-start-authorized-v1").isEmpty())
        val execution = linked("execution-$batch.json", "reference-batch-executed-v1")
        val executionBytes = OracleJson.canonicalBytes(execution, QUALIFICATION_LIMITS)
        require(reference.getValue("executionSha256ByBatch").jsonObject[batch] == JsonPrimitive(OracleArtifacts.sha256(executionBytes)))
        require(execution["attachmentSha256"] == JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(attachment, QUALIFICATION_LIMITS))))
        require(execution["requestSha256"] == attachment["requestSha256"] && execution["deploymentClosureSha256"] == attachment["deploymentClosureSha256"])
        require(execution["executionSha256"] == JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(execution - "executionSha256"), QUALIFICATION_LIMITS))))
        require(execution["outcomeSha256"] == JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(execution.getValue("outcome"), QUALIFICATION_LIMITS))))
        for (field in listOf("unitAbsent", "cgroupAbsent", "processesAbsent")) require(execution[field] == JsonPrimitive(true))
        require(execution["childExitCode"] == JsonPrimitive(0) && execution["releaseEligible"] == JsonPrimitive(false))
        val observationBytes = snapshots.getValue("observations-$batch.json")
        val checked = ReferenceCorpusWorkerObservations.verify(definition, request, observationBytes)
        capturedOutputBytes = Math.addExact(capturedOutputBytes, checked.capturedOutputBytes)
        require(checked.cases == reference.getValue("cases").jsonArray.map { it.jsonObject }.filter { it["batchId"] == JsonPrimitive(batch) })
        require(reference.getValue("workerObservationsSha256ByBatch").jsonObject[batch] == JsonPrimitive(OracleArtifacts.sha256(observationBytes)))
        val captured = linked("captured-$batch.json", "reference-batch-captured-v1")
        require(captured["batchId"] == JsonPrimitive(batch) && captured["observationsSha256"] == JsonPrimitive(OracleArtifacts.sha256(observationBytes)) &&
            captured["observationsBytes"] == JsonPrimitive(observationBytes.size))
        JsonObject(mapOf("batchId" to JsonPrimitive(batch), "configurationSha256" to prepared.getValue("configurationSha256"),
            "workerCommand" to JsonArray(ReferenceCorpusCoordinator.workerCommand(deployment.configuration, request,
                capture.referencePath.parent.resolve("request-$batch.json")).map(::JsonPrimitive)),
            "workerEnvironment" to JsonObject(mapOf("LANG" to JsonPrimitive("C.UTF-8"), "LC_ALL" to JsonPrimitive("C.UTF-8"), "TZ" to JsonPrimitive("UTC"))),
            "request" to document("request-$batch.json"), "executionReceipt" to fileIdentity(capture.referencePath.parent.resolve("execution-$batch.json"), snapshots.getValue("execution-$batch.json")),
            "workerObservations" to fileIdentity(capture.referencePath.parent.resolve("observations-$batch.json"), observationBytes),
            "processCounters" to JsonObject(mapOf("phase" to JsonPrimitive("pre-teardown-frozen-sample"),
                "terminalFacts" to JsonPrimitive(false), "sample" to execution.getValue("cgroup")))))
    }
    val complete = linked("complete.json", "reference-corpus-captured-v1")
    require(reference["capturedOutputBytes"] == JsonPrimitive(capturedOutputBytes))
    require(complete["referenceSha256"] == JsonPrimitive(OracleArtifacts.sha256(referenceBytes)) &&
        complete["referenceBytes"] == JsonPrimitive(referenceBytes.size) && complete["batches"] == expectedBatches &&
        complete["candidateQualified"] == JsonPrimitive(false) && complete["releaseEligible"] == JsonPrimitive(false) &&
        complete["scratchDisposition"] == JsonPrimitive("retained-for-trusted-reset"))
    require(snapshots.keys == expectedNames && snapshots.getValue("reference-observations.json").contentEquals(referenceBytes))
    capture.requireCurrent("after qualification receipt derivation")
    return JsonObject(mapOf("operationId" to JsonPrimitive(capture.operationId), "journalRoot" to JsonPrimitive(journalRoot.toString()),
        "scratchMount" to JsonPrimitive(scratchMount.toString()), "reference" to fileIdentity(capture.referencePath, referenceBytes),
        "intent" to intent, "batches" to JsonArray(batches),
        "journalReceipts" to JsonArray(snapshots.toSortedMap().map { (name, bytes) -> fileIdentity(capture.referencePath.parent.resolve(name), bytes) })))
}

internal fun qualificationPath(value: String): Path {
    require(value.isNotEmpty() && value.length <= 4096 && value.none { it.code < 32 || it.code == 127 })
    return Path.of(value).also { require(it.isAbsolute && it.normalize() == it && it.toString() == value && it != Path.of("/")) }
}
internal fun requirePrivateQualificationDirectory(path: Path, controllerUid: Int) {
    require(controllerUid > 0) { "qualification requires an ordinary controller UID" }
    require(path.toRealPath() == path && Files.isDirectory(path, NOFOLLOW_LINKS))
    require((Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == controllerUid.toLong() &&
        (Files.getAttribute(path, "unix:mode", NOFOLLOW_LINKS) as Number).toInt() and 0xfff == 0x1c0) {
        "qualification directory must belong to the ordinary controller and have mode 0700: $path"
    }
}

/** Closed session selection only; these values never confer deployment or execution authority. */
internal class GccMetadataReferenceControllerSession private constructor(val uid: Int) {
    val runtimeDirectory: Path = Path.of("/run/user/$uid")
    val cgroupParent: String = "/user.slice/user-$uid.slice/user@$uid.service/app.slice"

    fun requireDeployment(deployment: ReferenceCorpusDeployment) {
        require(deployment.configuration.systemdUserRuntimeDirectory == runtimeDirectory &&
            deployment.expectedCgroupParent == cgroupParent) {
            "metadata deployment session differs from the ordinary controller UID"
        }
    }

    companion object {
        fun forUid(uid: Long): GccMetadataReferenceControllerSession {
            require(uid in 1..Int.MAX_VALUE.toLong()) {
                "metadata reference qualification requires an ordinary non-root controller UID"
            }
            return GccMetadataReferenceControllerSession(uid.toInt())
        }
    }
}

internal fun metadataReferenceControllerUid(value: String): Int {
    require(value.matches(Regex("[1-9][0-9]{0,9}"))) { "controller UID must be a positive canonical integer" }
    return requireNotNull(value.toIntOrNull()) { "controller UID exceeds the supported integer range" }
}
private fun overlaps(a: Path, b: Path) = a.startsWith(b) || b.startsWith(a)
private fun fileIdentity(path: Path, bytes: ByteArray) = JsonObject(mapOf("path" to JsonPrimitive(path.toString()),
    "bytes" to JsonPrimitive(bytes.size), "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes))))
private fun JsonObject.exactFields(vararg fields: String) = require(keys == fields.toSet()) { "qualification fields differ" }
private fun JsonObject.digest(name: String): String = getValue(name).jsonPrimitive.let {
    require(it.isString && it.content.matches(Regex("[0-9a-f]{64}"))) { "qualification digest is invalid" }; it.content
}
private fun JsonObject.nonnegative(name: String): Long = getValue(name).jsonPrimitive.let {
    require(!it.isString && it.content.matches(Regex("0|[1-9][0-9]*"))); it.content.toLong()
}
private fun rawBlob(value: JsonObject, allowText: Boolean): ByteArray {
    require(value.keys == setOf("bytes", "sha256", "base64") || allowText && value.keys == setOf("bytes", "sha256", "base64", "text"))
    val size = value.nonnegative("bytes")
    require(size in 0..4 * 1024 * 1024L)
    val encoded = value.getValue("base64").jsonPrimitive.let { require(it.isString); it.content }
    require(encoded.length.toLong() == (size + 2) / 3 * 4)
    val bytes = Base64.getDecoder().decode(encoded)
    require(bytes.size.toLong() == size && Base64.getEncoder().encodeToString(bytes) == encoded && OracleArtifacts.sha256(bytes) == value.digest("sha256"))
    return bytes
}
private const val FROZEN_BYTES = 43_946
private const val FROZEN_SHA256 = "e2b0af0f212f38fdc2dde56e7803f05e26cd87f2c8c412a2384e478d4cc839fb"
private const val QUALIFICATION_BYTES = 32 * 1024 * 1024
private val QUALIFICATION_LIMITS = StrictJsonLimits(maximumInputBytes = QUALIFICATION_BYTES, maximumCanonicalBytes = QUALIFICATION_BYTES,
    maximumNodes = 500_000, maximumDepth = 64, maximumStringBytes = 16 * 1024 * 1024, maximumTotalStringBytes = QUALIFICATION_BYTES)
