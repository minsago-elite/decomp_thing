package decompengine.project

import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentFailureKind
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.RepairValidationFailureKind
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** An enclosing producer operation, not an assertion that a child process started or failed here. */
internal enum class GeneratedCValidationFailurePhase(val wireName: String, val hasCase: Boolean = false) {
    SOURCE_PREPARATION("source-preparation"),
    BUILD("build"),
    BUILD_FINALIZATION("build-finalization"),
    CAPTURE_REBUILT("capture-rebuilt"),
    BEFORE_CASE("before-case", true),
    ORIGINAL_OPERATION("original-operation", true),
    REBUILT_OPERATION("rebuilt-operation", true),
    SNAPSHOT_FINALIZATION("snapshot-finalization"),
    POST_EXECUTION("post-execution"),
}

internal enum class GeneratedCValidationFailureReason(
    val wireName: String,
    val classification: RepairValidationFailureKind,
) {
    TIMEOUT("timeout", RepairValidationFailureKind.RESOURCE_EXHAUSTED),
    RESOURCE_EXHAUSTED("resource-exhausted", RepairValidationFailureKind.RESOURCE_EXHAUSTED),
    CANCELLED("cancelled", RepairValidationFailureKind.CANCELLED),
    CLEANUP_UNVERIFIED("cleanup-unverified", RepairValidationFailureKind.CLEANUP_UNVERIFIED),
    VALIDATION_FAILED("validation-failed", RepairValidationFailureKind.VALIDATION_FAILED);

    companion object {
        /** Preserve the established primary classification, including cleanup/cancellation priority. */
        fun from(classification: RepairValidationFailureKind, failure: Throwable): GeneratedCValidationFailureReason =
            when (classification) {
                RepairValidationFailureKind.CLEANUP_UNVERIFIED -> CLEANUP_UNVERIFIED
                RepairValidationFailureKind.CANCELLED -> CANCELLED
                RepairValidationFailureKind.VALIDATION_FAILED -> VALIDATION_FAILED
                RepairValidationFailureKind.RESOURCE_EXHAUSTED ->
                    if (failure is GeneratedCValidationTimeoutException ||
                        failure is AgentExecutionException && failure.failure.kind == AgentFailureKind.TIMEOUT) TIMEOUT
                    else RESOURCE_EXHAUSTED
            }
    }
}

/** Supplemental diagnostic only. The unchanged validation receipt remains the proof input. */
internal data class GeneratedCValidationFailureRecord(
    val receiptSha256: String,
    val sourceRevisionSha256: String,
    val profileSha256: String,
    val indexSha256: String,
    val regressionCorpusSha256: String,
    val runtimeSha256: String,
    val classification: RepairValidationFailureKind,
    val reason: GeneratedCValidationFailureReason,
    val phase: GeneratedCValidationFailurePhase,
    val inputCount: Int,
    val inputIndex: Int? = null,
) {
    init {
        require(listOf(receiptSha256, sourceRevisionSha256, profileSha256, indexSha256,
            regressionCorpusSha256, runtimeSha256).all { it.matches(Regex("[0-9a-f]{64}")) }) {
            "validation failure record has an invalid commitment"
        }
        require(reason.classification == classification) { "validation failure reason conflicts with its classification" }
        require(inputCount >= 0 && (inputIndex == null || phase.hasCase && inputIndex in 0 until inputCount)) {
            "validation failure input position is invalid"
        }
    }

    fun encode(): ByteArray = OracleJson.canonicalBytes(JsonObject(mapOf(
        "schemaVersion" to JsonPrimitive(1),
        "kind" to JsonPrimitive("decomp-engine.generated-c-validation-failure"),
        "authority" to JsonPrimitive("producer-diagnostic"),
        "outcome" to JsonPrimitive("failed"),
        "receiptSha256" to JsonPrimitive(receiptSha256),
        "sourceRevisionSha256" to JsonPrimitive(sourceRevisionSha256),
        "profileSha256" to JsonPrimitive(profileSha256),
        "indexSha256" to JsonPrimitive(indexSha256),
        "regressionCorpusSha256" to JsonPrimitive(regressionCorpusSha256),
        "runtimeSha256" to JsonPrimitive(runtimeSha256),
        "classification" to JsonPrimitive(classification.name.lowercase().replace('_', '-')),
        "reason" to JsonPrimitive(reason.wireName),
        "phase" to JsonPrimitive(phase.wireName),
        "inputCount" to JsonPrimitive(inputCount),
        "inputIndex" to (inputIndex?.let(::JsonPrimitive) ?: JsonNull),
    )), StrictJsonLimits(maximumInputBytes = MAXIMUM_BYTES, maximumCanonicalBytes = MAXIMUM_BYTES,
        maximumDepth = 4, maximumNodes = 64, maximumStringBytes = 128,
        maximumTotalStringBytes = 2048, maximumNumberCharacters = 10))

    fun encodeWithinReceiptBudget(receiptBytes: Long, maximumBytes: Long): ByteArray {
        require(receiptBytes >= 0 && maximumBytes >= 0) { "validation diagnostic byte budget is invalid" }
        val encoded = encode()
        if (encoded.size.toLong() > maximumBytes - receiptBytes) {
            throw RepairBudgetExceededException("validation diagnostic exceeds the retained receipt byte bound")
        }
        return encoded
    }

    companion object {
        const val MAXIMUM_BYTES = 4096
    }
}
