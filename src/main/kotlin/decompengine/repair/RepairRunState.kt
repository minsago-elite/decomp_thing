package decompengine.repair

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

enum class RepairRunStatus {
    RUNNING, FULLY_ACCEPTED, COMPILE_VALID, NO_CHANGES, REJECTED, ITERATION_EXHAUSTED,
    RESOURCE_EXHAUSTED, CANCELLED, INTERRUPTED, VALIDATION_FAILED, ROLLBACK_FAILED,
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
    val rollbackFailureAttemptId: String? = null,
    val rollbackResolution: RepairRollbackState? = null,
    // Derived index only: graph/archive validation must match the linked rollback record.
    // Preserve schema-1 bytes on read; only new records or an actual committed failure upgrade.
    val schemaVersion: Int = 2,
    val validationDiagnostic: RepairValidationDiagnosticBinding? = null,
    val validationObservations: RepairValidationObservationLog = RepairValidationObservationLog.EMPTY,
) {
    val remainingAttempts: Int get() = maximumAttempts - attemptedCount
    val terminal: Boolean get() = status != RepairRunStatus.RUNNING

    init {
        require(schemaVersion in 1..4)
        require((status == RepairRunStatus.ROLLBACK_FAILED) == (rollbackFailureAttemptId != null))
        require((rollbackFailureAttemptId == null) == (rollbackResolution == null))
        require(schemaVersion >= 2 || rollbackFailureAttemptId == null)
        require(schemaVersion >= 3 || validationDiagnostic == null)
        require(schemaVersion >= 4 || validationObservations.entries.isEmpty())
        require(validationObservations.entries.size.toLong() <= attemptedCount.toLong() + 1)
        validationObservations.entries.forEach {
            require(it.invocation.runId == id && it.invocation.regressionCorpusSha256 == regressionCorpusSha256)
        }
        validationDiagnostic?.let {
            require(it.invocation.runId == id && it.invocation.regressionCorpusSha256 == regressionCorpusSha256)
            require(status !in setOf(RepairRunStatus.FULLY_ACCEPTED, RepairRunStatus.COMPILE_VALID))
        }
        require(rollbackFailureAttemptId == null || rollbackFailureAttemptId.matches(Regex("revision_[A-Za-z0-9_]+")))
        require(rollbackResolution == null || rollbackResolution in setOf(
            RepairRollbackState.RESTORE_FAILED_UNRESOLVED, RepairRollbackState.RESTORED_AFTER_FAILURE))
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
        if (schemaVersion >= 2) {
            put("rollbackFailureAttemptId", rollbackFailureAttemptId?.let(::JsonPrimitive) ?: JsonNull)
            put("rollbackResolution", rollbackResolution?.name?.lowercase()?.let(::JsonPrimitive) ?: JsonNull)
        }
        put("lastEvidence", lastEvidence?.let { evidence -> buildJsonObject {
            put("kind", evidence.kind)
            put("summary", evidence.summary)
            put("artifactPath", evidence.artifactPath?.let(::JsonPrimitive) ?: JsonNull)
        } } ?: JsonNull)
        if (schemaVersion >= 3) put("validationDiagnostic", validationDiagnostic?.toJsonObject() ?: JsonNull)
        if (schemaVersion >= 4) put("validationObservations", validationObservations.toJsonArray())
    }.toString()
}

internal fun parseRepairRunState(payload: String): RepairRunState {
    val value = Json.parseToJsonElement(payload).jsonObject
    val version = value.getValue("schemaVersion").jsonPrimitive.int
    require(version in 1..4)
    val common = setOf("schemaVersion", "id", "status", "baselineId", "acceptedHeadId", "provisionalHeadId",
        "regressionCorpusSha256", "maximumAttempts", "attemptedCount", "startedEpochMillis", "deadlineEpochMillis",
        "expectedObservationsSha256", "originalBinarySha256", "lastEvidence")
    val fields = common + (if (version >= 2) setOf("rollbackFailureAttemptId", "rollbackResolution") else emptySet()) +
        (if (version >= 3) setOf("validationDiagnostic") else emptySet()) +
        (if (version >= 4) setOf("validationObservations") else emptySet())
    require(value.keys.all { it in fields }) { "unknown repair run field" }
    if (version >= 2) {
        require(value.keys == fields) { "incomplete schema-$version repair run" }
        for (name in setOf("schemaVersion", "maximumAttempts", "attemptedCount", "startedEpochMillis", "deadlineEpochMillis")) {
            val primitive = value.getValue(name) as? JsonPrimitive ?: error("repair run $name is not numeric")
            require(!primitive.isString && primitive.longOrNull != null)
        }
        for (name in fields - setOf("schemaVersion", "maximumAttempts", "attemptedCount", "startedEpochMillis", "deadlineEpochMillis", "lastEvidence", "validationDiagnostic", "validationObservations")) {
            val element = value.getValue(name)
            val nullable = name in setOf("acceptedHeadId", "provisionalHeadId", "expectedObservationsSha256",
                "originalBinarySha256", "rollbackFailureAttemptId", "rollbackResolution")
            require(nullable && element is JsonNull || element is JsonPrimitive && element.isString) {
                "repair run $name is not valid text or null"
            }
        }
        require(value.getValue("status").jsonPrimitive.content in RepairRunStatus.entries.map { it.name.lowercase() })
        val resolution = value.getValue("rollbackResolution")
        require(resolution is JsonNull || resolution.jsonPrimitive.content in setOf("restore_failed_unresolved", "restored_after_failure"))
    }
    fun optional(name: String) = value[name]?.jsonPrimitive?.contentOrNull
    val evidence = value["lastEvidence"]?.takeUnless { it is JsonNull }?.jsonObject
    if (version >= 2 && evidence != null) {
        require(evidence.keys == setOf("kind", "summary", "artifactPath"))
        for (name in setOf("kind", "summary")) require((evidence.getValue(name) as? JsonPrimitive)?.isString == true)
        val artifact = evidence.getValue("artifactPath")
        require(artifact is JsonNull || artifact is JsonPrimitive && artifact.isString)
    }
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
        optional("rollbackFailureAttemptId"),
        optional("rollbackResolution")?.let { RepairRollbackState.valueOf(it.uppercase()) },
        version,
        if (version >= 3) value.getValue("validationDiagnostic").takeUnless { it is JsonNull }?.let {
            parseRepairValidationDiagnosticBinding(it as? JsonObject ?: error("validation diagnostic type"))
        } else null,
        if (version >= 4) parseRepairValidationObservationLog(value.getValue("validationObservations") as? JsonArray
            ?: error("validation observation array type"), value.getValue("attemptedCount").jsonPrimitive.int.toLong() + 1)
        else RepairValidationObservationLog.EMPTY,
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
