package decompengine.project

import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentFailureKind
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.RepairValidationFailureKind
import decompengine.repair.RepairValidationInvocation
import decompengine.repair.parseRepairValidationInvocation
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull

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
    val invocation: RepairValidationInvocation? = null,
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
        invocation?.let {
            require(it.sourceRevisionSha256 == sourceRevisionSha256 && it.profileSha256 == profileSha256 &&
                it.indexSha256 == indexSha256 && it.regressionCorpusSha256 == regressionCorpusSha256)
        }
    }

    fun encode(): ByteArray = OracleJson.canonicalBytes(JsonObject(mapOf(
        "schemaVersion" to JsonPrimitive(if (invocation == null) 1 else 2),
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
    ) + (invocation?.let { mapOf("invocation" to it.toJsonObject()) } ?: emptyMap())), StrictJsonLimits(maximumInputBytes = MAXIMUM_BYTES, maximumCanonicalBytes = MAXIMUM_BYTES,
        maximumDepth = 4, maximumNodes = 64, maximumStringBytes = 128,
        maximumTotalStringBytes = 2048, maximumNumberCharacters = 10))

    fun encodeWithinReceiptBudget(receiptBytes: Long, maximumBytes: Long, retainedCopies: Int = 1): ByteArray {
        require(receiptBytes >= 0 && maximumBytes >= 0) { "validation diagnostic byte budget is invalid" }
        require(retainedCopies in 1..2)
        val encoded = encode()
        if (encoded.size.toLong() * retainedCopies > maximumBytes - receiptBytes) {
            throw RepairBudgetExceededException("validation diagnostic exceeds the retained receipt byte bound")
        }
        return encoded
    }

    companion object {
        const val MAXIMUM_BYTES = 4096
    }
}

/** Reset commits before validation; a later encoding/write failure cannot retain an older reason. */
internal class GeneratedCValidationFailurePublication private constructor(private val replace: (String) -> Unit) {
    fun publish(record: GeneratedCValidationFailureRecord, receiptBytes: Long, maximumBytes: Long,
        retainedCopies: Int = 1): ByteArray {
        val bytes = record.encodeWithinReceiptBudget(receiptBytes, maximumBytes, retainedCopies)
        replace(bytes.toString(Charsets.UTF_8))
        return bytes
    }

    companion object {
        fun start(replace: (String) -> Unit): GeneratedCValidationFailurePublication {
            replace("")
            return GeneratedCValidationFailurePublication(replace)
        }
    }
}

/** Closed, bounded diagnostic parser. Neither schema supplies validation acceptance. */
internal fun parseGeneratedCValidationFailureRecord(bytes: ByteArray): GeneratedCValidationFailureRecord {
    val value = OracleJson.parse(bytes, StrictJsonLimits(maximumInputBytes = 4096, maximumCanonicalBytes = 4096,
        maximumDepth = 4, maximumNodes = 64, maximumStringBytes = 128,
        maximumTotalStringBytes = 2048, maximumNumberCharacters = 10)) as? JsonObject
        ?: error("validation diagnostic object type")
    fun text(name: String) = (value.getValue(name) as? JsonPrimitive)?.takeIf { it.isString }?.content
        ?: error("validation diagnostic text type")
    fun number(name: String) = requireNotNull((value.getValue(name) as? JsonPrimitive)?.takeUnless { it.isString }?.intOrNull)
    val schema = number("schemaVersion").also { require(it in 1..2) }
    require(text("kind") == "decomp-engine.generated-c-validation-failure" &&
        text("authority") == "producer-diagnostic" && text("outcome") == "failed")
    val classification = RepairValidationFailureKind.entries.single { it.name.lowercase().replace('_', '-') == text("classification") }
    val record = GeneratedCValidationFailureRecord(text("receiptSha256"), text("sourceRevisionSha256"),
        text("profileSha256"), text("indexSha256"), text("regressionCorpusSha256"), text("runtimeSha256"),
        classification, GeneratedCValidationFailureReason.entries.single { it.wireName == text("reason") },
        GeneratedCValidationFailurePhase.entries.single { it.wireName == text("phase") }, number("inputCount"),
        value.getValue("inputIndex").takeUnless { it is JsonNull }?.let { number("inputIndex") },
        if (schema == 2) parseRepairValidationInvocation(value.getValue("invocation") as? JsonObject
            ?: error("validation diagnostic invocation type")) else null)
    require(record.encode().contentEquals(bytes)) { "validation diagnostic is noncanonical or has unknown fields" }
    return record
}

/** Preserve the cleanup throwable and original failure while notifying only diagnostic state. */
internal fun finishGeneratedCValidationSnapshot(primary: Throwable?, close: () -> Unit, onFailure: () -> Unit) {
    try {
        close()
    } catch (cleanup: Throwable) {
        try {
            onFailure()
        } catch (observation: Throwable) {
            if (observation !== cleanup) cleanup.addSuppressed(observation)
        }
        primary?.let(cleanup::addSuppressed)
        throw cleanup
    }
}
