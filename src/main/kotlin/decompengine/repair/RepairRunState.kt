package decompengine.repair

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put

enum class RepairRunStatus {
    RUNNING, FULLY_ACCEPTED, COMPILE_VALID, NO_CHANGES, REJECTED, ITERATION_EXHAUSTED,
    RESOURCE_EXHAUSTED, CANCELLED, INTERRUPTED, VALIDATION_FAILED,
}

enum class RepairAttemptDisposition { LEGACY_UNVERIFIED, PROVISIONAL, REJECTED, FULLY_ACCEPTED }

/** Canonical, bounded whole-run evidence. UI events and compatibility history are projections. */
data class RepairRunState(
    val id: String,
    val status: RepairRunStatus,
    val baselineId: String,
    val acceptedHeadId: String?,
    val provisionalHeadId: String?,
    val regressionCorpusSha256: String,
    val maximumAttempts: Int,
    val attemptedCount: Int,
    val startedEpochMillis: Long,
    val deadlineEpochMillis: Long,
    val lastEvidence: RepairEvidence? = null,
    val expectedObservationsSha256: String? = null,
    val originalBinarySha256: String? = null,
) {
    val schemaVersion: Int get() = 1
    val remainingAttempts: Int get() = maximumAttempts - attemptedCount
    val terminal: Boolean get() = status != RepairRunStatus.RUNNING

    init {
        require(id.matches(Regex("run_[0-9]{8}")))
        require(maximumAttempts > 0 && attemptedCount in 0..maximumAttempts)
        require(startedEpochMillis > 0 && deadlineEpochMillis >= startedEpochMillis)
        require(regressionCorpusSha256.matches(Regex("[0-9a-f]{64}")))
        require(expectedObservationsSha256 == null || expectedObservationsSha256.matches(Regex("[0-9a-f]{64}")))
        require(originalBinarySha256 == null || originalBinarySha256.matches(Regex("[0-9a-f]{64}")))
        require(status != RepairRunStatus.FULLY_ACCEPTED || acceptedHeadId != null)
    }

    fun toJson(): String = buildJsonObject {
        put("schemaVersion", schemaVersion)
        put("id", id)
        put("status", status.name.lowercase())
        put("baselineId", baselineId)
        put("acceptedHeadId", acceptedHeadId?.let(::JsonPrimitive) ?: JsonNull)
        put("provisionalHeadId", provisionalHeadId?.let(::JsonPrimitive) ?: JsonNull)
        put("regressionCorpusSha256", regressionCorpusSha256)
        put("maximumAttempts", maximumAttempts)
        put("attemptedCount", attemptedCount)
        put("startedEpochMillis", startedEpochMillis)
        put("deadlineEpochMillis", deadlineEpochMillis)
        put("expectedObservationsSha256", expectedObservationsSha256?.let(::JsonPrimitive) ?: JsonNull)
        put("originalBinarySha256", originalBinarySha256?.let(::JsonPrimitive) ?: JsonNull)
        put("lastEvidence", lastEvidence?.let { evidence -> buildJsonObject {
            put("kind", evidence.kind)
            put("summary", evidence.summary)
            put("artifactPath", evidence.artifactPath?.let(::JsonPrimitive) ?: JsonNull)
        } } ?: JsonNull)
    }.toString()
}

internal fun parseRepairRunState(payload: String): RepairRunState {
    val value = Json.parseToJsonElement(payload).jsonObject
    require(value.getValue("schemaVersion").jsonPrimitive.int == 1)
    fun optional(name: String) = value[name]?.jsonPrimitive?.contentOrNull
    val evidence = value["lastEvidence"]?.takeUnless { it is JsonNull }?.jsonObject
    return RepairRunState(
        value.getValue("id").jsonPrimitive.content,
        RepairRunStatus.valueOf(value.getValue("status").jsonPrimitive.content.uppercase()),
        value.getValue("baselineId").jsonPrimitive.content,
        optional("acceptedHeadId"), optional("provisionalHeadId"),
        value.getValue("regressionCorpusSha256").jsonPrimitive.content,
        value.getValue("maximumAttempts").jsonPrimitive.int,
        value.getValue("attemptedCount").jsonPrimitive.int,
        value.getValue("startedEpochMillis").jsonPrimitive.long,
        value.getValue("deadlineEpochMillis").jsonPrimitive.long,
        evidence?.let { RepairEvidence(it.getValue("kind").jsonPrimitive.content,
            it.getValue("summary").jsonPrimitive.content, it["artifactPath"]?.jsonPrimitive?.contentOrNull) },
        optional("expectedObservationsSha256"),
        optional("originalBinarySha256"),
    )
}

internal fun RepairValidationProof.toStateJson(): String = buildJsonObject {
    put("sourceRevisionSha256", sourceRevisionSha256)
    put("profileSha256", profileSha256)
    put("indexSha256", indexSha256)
    put("regressionCorpusSha256", regressionCorpusSha256)
    put("originalBinarySha256", originalBinarySha256?.let(::JsonPrimitive) ?: JsonNull)
    put("rebuiltBinarySha256", rebuiltBinarySha256?.let(::JsonPrimitive) ?: JsonNull)
    put("runtimeSha256", runtimeSha256)
    put("evidenceSha256", evidenceSha256)
    put("cleanupVerified", cleanupVerified)
    put("assurance", assurance.name.lowercase())
}.toString()

internal fun parseRepairValidationProof(value: JsonObject): RepairValidationProof = RepairValidationProof(
    value.getValue("sourceRevisionSha256").jsonPrimitive.content,
    value.getValue("profileSha256").jsonPrimitive.content,
    value.getValue("indexSha256").jsonPrimitive.content,
    value.getValue("regressionCorpusSha256").jsonPrimitive.content,
    value["originalBinarySha256"]?.jsonPrimitive?.contentOrNull,
    value["rebuiltBinarySha256"]?.jsonPrimitive?.contentOrNull,
    value.getValue("runtimeSha256").jsonPrimitive.content,
    value.getValue("evidenceSha256").jsonPrimitive.content,
    value.getValue("cleanupVerified").jsonPrimitive.content.toBooleanStrict(),
    RepairValidationAssurance.valueOf(value.getValue("assurance").jsonPrimitive.content.uppercase()),
)
