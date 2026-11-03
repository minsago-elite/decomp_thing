package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.*

/** Validates the existing journal envelope with the separately versioned native assessment. */
internal object GccNativeCallReceiptLineage {
    fun createBinding(operation: GccBundledNativeCallOperation): ByteArray {
        require(!operation.complete && !operation.scored && !operation.releaseEligible)
        val intentBytes = operation.intentBytes
        val intent = OracleJson.parseCanonical(intentBytes).jsonObject
        require(intent.string("provider") == "gcc-bundled-operation-intent-v5" && intent.long("schemaVersion") == 5L &&
            intent.string("engineId") in setOf("cc1", "driver") &&
            intent.string("engineId") == operation.snapshot.target.engineId && intent.string("runKind") == "fresh-control") {
            "native observation lineage requires the matching pinned fresh cc1 or driver v5 intent"
        }
        val operationId = intent.digest("operationId")
        val intentDigest = OracleArtifacts.sha256(intentBytes)
        val runtime = intent.getValue("bundledRuntime").jsonObject
        require(runtime.string("provider") == "bundled-ghidra-java-api-runtime-v8")
        val collector = runtime.getValue("nativeCallCollector").jsonObject
        require(collector.digest("sourceSha256") == operation.snapshot.summary.bindings.collectorSha256)
        val profile = intent.getValue("plannerProfile").jsonObject
        require(profile.digest("profileSha256") == operation.snapshot.target.profileSha256)
        val cli = intent.getValue("cliInvocation").jsonObject
        requireCliSelection(cli, intent.string("engineId"))
        val artifacts = intent.getValue("artifacts").jsonArray.map { it.jsonObject }
        fun artifact(role: String, bytes: Long, digest: String) {
            val item = artifacts.single { it.string("role") == role }
            require(item.long("bytes") == bytes && item.digest("sha256") == digest)
        }
        val model = operation.model
        val native = operation.snapshot
        artifact("engine-binary", model.inputBytes, model.inputSha256)
        artifact("exporter-source", model.exporterBytes, model.exporterSha256)
        artifact("ghidra-archive", model.analysisToolBytes, model.analysisToolSha256)
        val executionBytes = operation.executionReceiptBytes
        val assessmentBytes = operation.nativeAssessmentReceiptBytes
        val execution = record(executionBytes, "gcc-bundled-command-executed-v1", "execution", operationId, intentDigest)
        val assessment = record(assessmentBytes, "gcc-bundled-command-export-assessed-v1", "assessment", operationId, intentDigest)
        require(assessment.first.digest("previousSha256") == OracleArtifacts.sha256(executionBytes)) {
            "native assessment does not descend from contained execution"
        }
        val executionPayload = execution.second
        require(executionPayload.string("provider") == "kotlin-lease-contained-command-execution-v1" &&
            executionPayload.long("schemaVersion") == 1L && executionPayload.long("childExitCode") == 0L &&
            executionPayload.bool("unitAbsent") && executionPayload.bool("cgroupAbsent") &&
            executionPayload.bool("processesAbsent") && !executionPayload.bool("releaseEligible")) {
            "native execution does not prove successful worker and cgroup absence"
        }
        require(executionPayload.digest("executionSha256") ==
            OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(executionPayload - "executionSha256"))))
        val nativePayload = assessment.second
        require(nativePayload.string("provider") == "gcc-bundled-descriptor-native-call-assessment-v1" &&
            nativePayload.long("schemaVersion") == 1L && !nativePayload.bool("complete") &&
            !nativePayload.bool("scored") && !nativePayload.bool("releaseEligible") &&
            nativePayload["operationWallTime"] is JsonObject)
        require(nativePayload.digest("assessmentSha256") ==
            OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(nativePayload - "assessmentSha256"))))
        val captured = OracleJson.parseCanonical(native.assessmentBytes).jsonObject
        require(JsonObject(nativePayload - setOf("assessmentSha256", "operationWallTime")) ==
            JsonObject(captured - "assessmentSha256")) { "native receipt differs from the captured byte assessment" }
        val lineage = JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-bundled-native-call-receipt-lineage-v1"), "schemaVersion" to JsonPrimitive(1),
            "operationId" to JsonPrimitive(operationId), "intentSha256" to JsonPrimitive(intentDigest),
            "executionReceiptSha256" to JsonPrimitive(OracleArtifacts.sha256(executionBytes)),
            "executionPayloadSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(executionPayload))),
            "nativeAssessmentReceiptSha256" to JsonPrimitive(OracleArtifacts.sha256(assessmentBytes)),
            "nativeAssessmentSha256" to JsonPrimitive(nativePayload.digest("assessmentSha256")),
        ))
        val address = native.summary.bindings.imageBase
        val space = native.summary.addressSpaces[address.spaceIndex!!]
        return OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-bundled-native-call-observation-binding-v1"), "schemaVersion" to JsonPrimitive(1),
            "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
            "compilerEngineProfileSha256" to JsonPrimitive(native.target.profileSha256),
            "profileTarget" to JsonPrimitive(native.target.profileTarget),
            "inputBinary" to commitment(model.inputBytes, model.inputSha256),
            "programModel" to JsonObject(mapOf("bytes" to JsonPrimitive(model.programModelBytes),
                "sha256" to JsonPrimitive(model.programModelSha256), "functionCount" to JsonPrimitive(model.functionCount))),
            "programModelExporter" to commitment(model.exporterBytes, model.exporterSha256),
            "ghidraArchive" to commitment(model.analysisToolBytes, model.analysisToolSha256),
            "collector" to collector,
            "outputTreeSha256" to JsonPrimitive(model.outputTreeSha256),
            "nativeObservations" to commitment(native.summary.observationsBytes, native.summary.observationsSha256),
            "nativeManifest" to commitment(native.manifestBytes.size.toLong(), OracleArtifacts.sha256(native.manifestBytes)),
            "target" to JsonObject(mapOf(
                "languageId" to JsonPrimitive(native.target.languageId), "compilerSpecId" to JsonPrimitive(native.target.compilerSpecId),
                "imageBaseOffsetBits" to JsonPrimitive(address.offsetBits),
                "addressSpace" to JsonObject(mapOf("name" to JsonPrimitive(space.name), "type" to JsonPrimitive(space.type),
                    "sizeBits" to JsonPrimitive(space.sizeBits), "addressableUnitSize" to JsonPrimitive(space.addressableUnitSize),
                    "overlay" to JsonPrimitive(space.overlay), "signedOffsets" to JsonPrimitive(space.signedOffsets))),
            )),
            "coverage" to JsonPrimitive(native.summary.scanSummary.coverage),
            "nativeFunctionCount" to JsonPrimitive(native.summary.scanSummary.functions),
            "nativeThunkCount" to JsonPrimitive(native.summary.scanSummary.thunks),
            "nativeSiteCount" to JsonPrimitive(native.summary.scanSummary.sites),
            "receiptLineage" to lineage,
            "receiptLineageSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(lineage))),
        )))
    }

    internal fun requireCliSelection(cli: JsonObject, expectedEngineId: String) {
        require(expectedEngineId in setOf("cc1", "driver") && cli.string("engineId") == expectedEngineId) {
            "native CLI selection differs from its pinned capture target"
        }
        val argv = cli.getValue("argv").jsonArray
        require(argv.size in 3..33 && argv.first() == JsonPrimitive("gcc-engine-native-calls")) {
            "native CLI selection requires the native observation command"
        }
        val arguments = argv.drop(1).map { argument ->
            argument.jsonPrimitive.let { require(it.isString); it.content }
        }
        // The command accepts options before and between positionals. Reuse that parser rather
        // than assuming the engine immediately follows the command in the retained argv.
        require(GccBundledCliOptions.parse(arguments, nativeCallObservations = true).engineId == expectedEngineId) {
            "native CLI arguments differ from its pinned capture target"
        }
    }

    private fun commitment(bytes: Long, sha256: String) = JsonObject(mapOf("bytes" to JsonPrimitive(bytes), "sha256" to JsonPrimitive(sha256)))
    private fun record(bytes: ByteArray, provider: String, payloadName: String, operationId: String,
        intentSha256: String): Pair<JsonObject, JsonObject> {
        val document = OracleJson.parseCanonical(bytes).jsonObject
        require(document.keys == setOf("provider", "schemaVersion", "operationId", "intentSha256", "previousSha256",
            "complete", "releaseEligible", payloadName, "${payloadName}Sha256", "recordSha256"))
        require(document.string("provider") == provider && document.long("schemaVersion") == 1L &&
            document.digest("operationId") == operationId && document.digest("intentSha256") == intentSha256 &&
            !document.bool("complete") && !document.bool("releaseEligible"))
        document.digest("previousSha256")
        val payload = document.getValue(payloadName).jsonObject
        require(document.digest("${payloadName}Sha256") == OracleArtifacts.sha256(OracleJson.canonicalBytes(payload)))
        require(document.digest("recordSha256") == OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(document - "recordSha256"))))
        return document to payload
    }
    private fun JsonObject.string(name: String): String = getValue(name).jsonPrimitive.let {
        require(it.isString); it.content
    }
    private fun JsonObject.long(name: String): Long = getValue(name).jsonPrimitive.let {
        require(!it.isString); requireNotNull(it.longOrNull)
    }
    private fun JsonObject.bool(name: String): Boolean = getValue(name).jsonPrimitive.let {
        require(!it.isString); requireNotNull(it.booleanOrNull)
    }
    private fun JsonObject.digest(name: String): String = string(name).also { require(it.matches(Regex("[a-f0-9]{64}"))) }
}
