package decompengine.oracle.gcc

import decompengine.oracle.externalcalls.FrozenNativeExternalClaimsSnapshotV1
import decompengine.oracle.structural.FrozenNativeRecoveredCallPopulationV1
import decompengine.project.NativeCallBindingsV1
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.*

/** Pure join validation; the private coordinator permit remains the production authority. */
internal fun requireGccDualNativeFreezeMatches(
    core: FrozenNativeRecoveredCallPopulationV1,
    external: FrozenNativeExternalClaimsSnapshotV1,
    expectedBindings: NativeCallBindingsV1,
) {
    require(external.bindings == expectedBindings && external.inputSha256 == core.inputSha256 &&
        external.bindings.programModelSha256 == core.programModelSha256 &&
        external.bindings.programModelBytes == core.programModelBytes &&
        external.rawRecordCount == core.rawRecordCount && external.rawSiteCount == core.rawSiteCount.toLong() &&
        external.rawManifestBytes.contentEquals(core.rawManifestBytes) &&
        external.rawObservationBytes.contentEquals(core.rawObservationBytes)) {
        "dual native freezes differ from the original sources, bindings, model or complete census"
    }
}

internal object GccBundledExternalCallEvidenceV1 {
    const val EXTERNAL_CLAIMS_NAME = "native-external-call-claims.json"
    const val BINDING_NAME = "native-external-call-replay-binding.json"
    const val PAIR_NAME = "native-external-elf-pair.json"
    const val NAMESPACE_NAME = "native-external-namespace.json"
    const val LEDGER_INPUT_NAME = "native-external-call-ledger-input.json"
    const val LEDGER_REPORT_NAME = "native-external-call-ledger-report.json"
    const val PROJECTION_NAME = "native-external-call-projection.json"

    fun payloads(operation: GccBundledExternalCallReplayOperation): Map<String, ByteArray> = linkedMapOf(
        GccBundledExternalCallReplayOutputCapture.INDEPENDENT_NAME to operation.independentCapture.reportBytes,
        GccBundledExternalCallReplayOutputCapture.RECOVERED_NAME to operation.recoveredCapture.reportBytes,
        PAIR_NAME to OracleJson.canonicalBytes(operation.pair.receipt, JSON_LIMITS),
        NAMESPACE_NAME to OracleJson.canonicalBytes(operation.pair.richNamespace, JSON_LIMITS),
        LEDGER_INPUT_NAME to operation.projection.inputBytes,
        LEDGER_REPORT_NAME to operation.projection.reportBytes,
        PROJECTION_NAME to operation.projection.evidenceBytes,
        BINDING_NAME to create(operation),
    )
    fun create(operation: GccBundledExternalCallReplayOperation): ByteArray {
        fun digest(bytes: ByteArray) = JsonPrimitive(OracleArtifacts.sha256(bytes))
        fun worker(request: ByteArray, attachment: ByteArray, execution: ByteArray, capture: GccBundledExternalCallReplayCapture): JsonObject {
            requireGccExternalExecutionLineage(request, attachment, execution)
            return JsonObject(mapOf("requestSha256" to digest(request), "attachmentSha256" to digest(attachment),
                "executionSha256" to digest(execution), "captureSha256" to digest(capture.assessmentBytes),
                "reportSha256" to digest(capture.reportBytes), "reportBytes" to JsonPrimitive(capture.reportBytes.size)))
        }
        return OracleJson.canonicalBytes(JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive("gcc-native-external-production-replay-binding-v1"),
            "scope" to JsonPrimitive("owned-positive-call-population-with-explicit-unknown-coverage"),
            "nativeStructuralBindingSha256" to digest(GccBundledNativeStructuralEvidenceV1.create(operation.machine)),
            "nativeClaimFreezeSha256" to digest(operation.machine.frozenNativeClaims.canonicalBytes),
            "externalClaimsSha256" to JsonPrimitive(operation.machine.frozenNativeClaims.externalClaims.evidenceSha256),
            "pairProofSha256" to JsonPrimitive(operation.pair.receiptSha256),
            "externalNamespaceSha256" to JsonPrimitive(operation.pair.richNamespaceSha256),
            "ledgerInputSha256" to digest(operation.projection.inputBytes), "ledgerReportSha256" to digest(operation.projection.reportBytes),
            "projectionSha256" to digest(operation.projection.evidenceBytes),
            "independent" to worker(operation.independentLiveRequest.canonicalBytes, operation.independentAttachmentBytes,
                operation.independentExecutionBytes, operation.independentCapture),
            "recovered" to worker(operation.recoveredLiveRequest.canonicalBytes, operation.recoveredAttachmentBytes,
                operation.recoveredExecutionBytes, operation.recoveredCapture),
            "callAuthority" to JsonPrimitive("unavailable-pending-scoped-production-contract-admission"),
            "sourceCallPopulationComplete" to JsonPrimitive(false), "negativeCompleteness" to JsonPrimitive(false),
            "scored" to JsonPrimitive(false), "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false))))
    }
    private val JSON_LIMITS = decompengine.oracle.core.StrictJsonLimits(maximumInputBytes = 64 * 1024 * 1024,
        maximumCanonicalBytes = 64 * 1024 * 1024, maximumNodes = 1_000_000, maximumDepth = 32,
        maximumStringBytes = 4 * 1024 * 1024, maximumTotalStringBytes = 64 * 1024 * 1024)
}

/** Consistency check used only after the genuine coordinator launch and private-permit guard. */
internal fun requireGccExternalExecutionLineage(request: ByteArray, attachmentBytes: ByteArray, executionBytes: ByteArray) {
    val attachment = OracleJson.parseCanonical(attachmentBytes).jsonObject
    val execution = OracleJson.parseCanonical(executionBytes).jsonObject
    require(attachment["provider"] == JsonPrimitive("kotlin-lease-contained-command-attachment-v1") &&
        attachment["schemaVersion"] == JsonPrimitive(1) &&
        attachment["nonce"] == JsonPrimitive(OracleArtifacts.sha256(request)) &&
        attachment["requestSha256"] == execution["requestSha256"] && attachment["requestSha256"] != null &&
        attachment["attachmentSha256"] == JsonPrimitive(OracleArtifacts.sha256(
            OracleJson.canonicalBytes(JsonObject(attachment - "attachmentSha256")))))
    require(execution["provider"] == JsonPrimitive("kotlin-lease-contained-command-execution-v1") &&
        execution["schemaVersion"] == JsonPrimitive(1) && execution["childExitCode"] == JsonPrimitive(0) &&
        listOf("unitAbsent", "cgroupAbsent", "processesAbsent").all { execution[it] == JsonPrimitive(true) } &&
        execution["attachmentSha256"] == JsonPrimitive(OracleArtifacts.sha256(attachmentBytes)) &&
        execution["executionSha256"] == JsonPrimitive(OracleArtifacts.sha256(
            OracleJson.canonicalBytes(JsonObject(execution - "executionSha256")))))
}
