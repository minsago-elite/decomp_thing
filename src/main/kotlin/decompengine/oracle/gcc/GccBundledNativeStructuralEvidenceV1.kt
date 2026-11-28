package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.machinecalls.IndependentMachineCallReportV1
import decompengine.oracle.machinecalls.IndependentMachineCallsV1
import decompengine.oracle.structural.StructuralProductionReplayContract
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/** Retained joins from a genuine operation. This publication cannot admit the call scoring domain. */
internal object GccBundledNativeStructuralEvidenceV1 {
    const val BINDING_NAME = "native-structural-replay-binding.json"
    const val BOUNDARY_NAME = "native-selected-boundary-score.json"
    const val MODEL_BINDING_NAME = "native-model-structural-binding.json"
    const val CLAIMS_NAME = "native-recovered-call-claims.json"
    const val FREEZE_NAME = "native-recovered-call-freeze.json"
    const val POPULATION_NAME = "native-recovered-call-population.json"
    private val REPORT_LIMITS = StrictJsonLimits(maximumInputBytes = 64 * 1024 * 1024,
        maximumCanonicalBytes = 64 * 1024 * 1024, maximumNodes = 1_000_000,
        maximumStringBytes = 16 * 1024 * 1024, maximumTotalStringBytes = 48 * 1024 * 1024)

    fun create(operation: GccBundledMachineCallReplayOperation): ByteArray {
        val selected = operation.selectedInputs
        val request = operation.request
        val requestSha = OracleArtifacts.sha256(request.canonicalBytes)
        val report = operation.capture.reportBytes
        IndependentMachineCallReportV1.validateWorker(OracleJson.parseCanonical(report,
            IndependentMachineCallsV1.outputLimits(request.limits)).jsonObject, requestSha, request)
        val attachment = OracleJson.parseCanonical(operation.attachmentBytes).jsonObject
        val execution = OracleJson.parseCanonical(operation.executionBytes).jsonObject
        require(attachment["provider"] == JsonPrimitive("kotlin-lease-contained-command-attachment-v1") &&
            attachment["schemaVersion"] == JsonPrimitive(1) && attachment["nonce"] == JsonPrimitive(requestSha) &&
            attachment["requestSha256"] == execution["requestSha256"] && attachment["requestSha256"] != null &&
            attachment["attachmentSha256"] == JsonPrimitive(OracleArtifacts.sha256(
                OracleJson.canonicalBytes(JsonObject(attachment - "attachmentSha256")))))
        require(execution["provider"] == JsonPrimitive("kotlin-lease-contained-command-execution-v1") &&
            execution["schemaVersion"] == JsonPrimitive(1) && execution["childExitCode"] == JsonPrimitive(0) &&
            listOf("unitAbsent", "cgroupAbsent", "processesAbsent").all { execution[it] == JsonPrimitive(true) } &&
            execution["attachmentSha256"] == JsonPrimitive(OracleArtifacts.sha256(operation.attachmentBytes)) &&
            execution["executionSha256"] == JsonPrimitive(OracleArtifacts.sha256(
                OracleJson.canonicalBytes(JsonObject(execution - "executionSha256")))))
        val score = StructuralProductionReplayContract.scoreSelectedBoundary(selected)
        val parsedScore = OracleJson.parse(score, REPORT_LIMITS).jsonObject
        require(parsedScore["functionOracleSha256"] == JsonPrimitive(request.canonicalOracle.sha256))
        return OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-native-structural-replay-binding-v1"),
            "schemaVersion" to JsonPrimitive(1),
            "scope" to JsonPrimitive("selected-model-boundaries-and-owned-independent-positive-producer"),
            "profileId" to JsonPrimitive(selected.profileId), "inputSha256" to JsonPrimitive(selected.inputSha256),
            "programModelSha256" to JsonPrimitive(selected.programModelSha256),
            "programModelBytes" to JsonPrimitive(selected.programModelBytes),
            "nativeBindingSha256" to JsonPrimitive(OracleArtifacts.sha256(GccNativeCallReceiptLineage.createBinding(operation.native))),
            "nativeObservationsSha256" to JsonPrimitive(operation.native.snapshot.summary.observationsSha256),
            "nativeClaimFreezeSha256" to JsonPrimitive(OracleArtifacts.sha256(operation.frozenNativeClaims.canonicalBytes)),
            "nativeClaimsSha256" to JsonPrimitive(operation.frozenNativeClaims.claimsSha256),
            "nativePopulationSha256" to JsonPrimitive(OracleArtifacts.sha256(operation.projectedPopulationBytes)),
            "selectedBoundaryScoreSha256" to JsonPrimitive(OracleArtifacts.sha256(score)),
            "boundaryObservationSha256" to parsedScore.getValue("boundaryObservationSha256"),
            "modelBindingSha256" to JsonPrimitive(OracleArtifacts.sha256(selected.fullExportBindingBytes)),
            "producerRequestSha256" to JsonPrimitive(requestSha),
            "producerAttachmentSha256" to JsonPrimitive(OracleArtifacts.sha256(operation.attachmentBytes)),
            "producerExecutionSha256" to JsonPrimitive(OracleArtifacts.sha256(operation.executionBytes)),
            "producerCaptureSha256" to JsonPrimitive(OracleArtifacts.sha256(operation.capture.assessmentBytes)),
            "producerReportSha256" to JsonPrimitive(OracleArtifacts.sha256(report)),
            "producerReportBytes" to JsonPrimitive(report.size),
            "admittedDomains" to parsedScore.getValue("admittedDomains"),
            "unavailableDomains" to JsonArray(listOf("interfaces", "calls", "globals", "types", "calibration").map(::JsonPrimitive)),
            "callAuthority" to JsonPrimitive("unavailable-pending-population-and-external-composition"),
            "negativeCompleteness" to JsonPrimitive(false), "scored" to JsonPrimitive(false),
            "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
        )))
    }
}
