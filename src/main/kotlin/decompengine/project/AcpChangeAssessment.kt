package decompengine.project

import decompengine.agent.AgentStopReason
import decompengine.agent.AgentTurnIdentity
import decompengine.agent.isCanonicalAgentTurnId
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.nio.charset.StandardCharsets
import java.util.Collections

/** Whether the source observation represented by an invocation receipt is complete. */
enum class AcpChangeObservationStatus { COMPLETE, INCOMPLETE, UNKNOWN }

enum class AcpChangePolicyVerdict { ALLOW, REJECT, NOT_EVALUATED }
enum class AcpChangeValidationStatus { PASSED, FAILED, NOT_RUN, INCOMPLETE }
enum class AcpChangePublicationEligibility { REJECTED, INTERRUPTED, PROVISIONAL, VALIDATED_FOR_PUBLICATION }

/**
 * Immutable, host-authored pre-dispatch identity. It contains commitments and opaque workflow
 * identifiers only; it must never contain prompts, source bytes, credentials, or peer text.
 */
class AgentTurnIntent private constructor(
    val turnId: String,
    val workflowId: String,
    val taskId: String,
    val attemptId: String,
    val requestSha256: String,
    val profileSha256: String,
    val policySha256: String,
    val beforeSha256: String,
) {
    init {
        require(isCanonicalAgentTurnId(turnId)) { "turn intent UUID is invalid" }
        listOf(workflowId, taskId, attemptId).forEach(::requireOpaqueId)
        listOf(requestSha256, profileSha256, policySha256, beforeSha256).forEach(::requireDigest)
    }

    fun canonicalBytes(): ByteArray = OracleJson.canonicalBytes(buildJsonObject {
        put("schemaVersion", 1)
        put("turnId", turnId)
        put("workflowId", workflowId)
        put("taskId", taskId)
        put("attemptId", attemptId)
        put("requestSha256", requestSha256)
        put("profileSha256", profileSha256)
        put("policySha256", policySha256)
        put("beforeSha256", beforeSha256)
    }, LIMITS)

    val sha256: String get() = sha256(canonicalBytes())

    companion object {
        private val KEYS = setOf(
            "schemaVersion", "turnId", "workflowId", "taskId", "attemptId", "requestSha256",
            "profileSha256", "policySha256", "beforeSha256",
        )

        fun create(
            identity: AgentTurnIdentity,
            workflowId: String,
            attemptId: String,
            profileSha256: String,
            policySha256: String,
            beforeSha256: String,
        ): AgentTurnIntent = AgentTurnIntent(
            turnId = identity.turnId,
            workflowId = workflowId,
            taskId = identity.taskId,
            attemptId = attemptId,
            requestSha256 = identity.requestSha256,
            profileSha256 = profileSha256,
            policySha256 = policySha256,
            beforeSha256 = beforeSha256,
        )

        fun parse(bytes: ByteArray): AgentTurnIntent {
            val root = parseDocument(bytes)
            require(root.keys == KEYS) { "turn intent has missing, extra, or duplicate fields" }
            require(root.int("schemaVersion") == 1) { "turn intent schema is unsupported" }
            return AgentTurnIntent(
                turnId = root.text("turnId"),
                workflowId = root.text("workflowId"),
                taskId = root.text("taskId"),
                attemptId = root.text("attemptId"),
                requestSha256 = root.text("requestSha256"),
                profileSha256 = root.text("profileSha256"),
                policySha256 = root.text("policySha256"),
                beforeSha256 = root.text("beforeSha256"),
            ).also { require(it.canonicalBytes().contentEquals(bytes)) { "turn intent is not canonical" } }
        }
    }
}

/**
 * Immutable host workflow assessment for one exact intent and invocation receipt. Validation
 * references are hashes of independently persisted proof documents. Eligibility is deliberately
 * weaker than a #732 publication decision: only that transaction can commit the candidate.
 */
class AcpChangeAssessment private constructor(
    val turnId: String,
    val intentSha256: String,
    val receiptSha256: String?,
    val sessionIdSha256: String?,
    val changesSha256: String?,
    val beforeSha256: String,
    val afterSha256: String?,
    val observation: AcpChangeObservationStatus,
    val protocolStopCode: String?,
    val normalizedStopReason: AgentStopReason?,
    val policyVerdict: AcpChangePolicyVerdict,
    val policySha256: String,
    reasonCodes: Collection<String>,
    val validationStatus: AcpChangeValidationStatus,
    validationProofSha256: Collection<String>,
    val eligibility: AcpChangePublicationEligibility,
    val updatesSha256: String?,
) {
    val reasonCodes: List<String> = boundedCopy(reasonCodes, MAXIMUM_REASON_CODES)
    val validationProofSha256: List<String> = boundedCopy(validationProofSha256, MAXIMUM_VALIDATION_PROOFS)

    init {
        require(isCanonicalAgentTurnId(turnId)) { "assessment UUID is invalid" }
        listOf(intentSha256, beforeSha256, policySha256).forEach(::requireDigest)
        receiptSha256?.let(::requireDigest)
        sessionIdSha256?.let(::requireDigest)
        changesSha256?.let(::requireDigest)
        afterSha256?.let(::requireDigest)
        updatesSha256?.let(::requireDigest)
        protocolStopCode?.let {
            require(it.matches(Regex("[a-z][a-z0-9_-]{0,63}"))) { "protocol stop code is invalid" }
        }
        require(this.reasonCodes.size <= MAXIMUM_REASON_CODES && this.reasonCodes.distinct().size == this.reasonCodes.size)
        require(this.reasonCodes.all { it.matches(Regex("[a-z][a-z0-9_-]{0,63}")) }) {
            "assessment reason codes must be bounded host-authored identifiers"
        }
        require(this.validationProofSha256.size <= MAXIMUM_VALIDATION_PROOFS &&
            this.validationProofSha256.distinct().size == this.validationProofSha256.size)
        this.validationProofSha256.forEach(::requireDigest)
        require((observation == AcpChangeObservationStatus.COMPLETE) == (afterSha256 != null)) {
            "complete observations require an after commitment; incomplete or unknown observations cannot claim one"
        }
        require(eligibility != AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION ||
            (receiptSha256 != null && sessionIdSha256 != null && changesSha256 != null &&
                observation == AcpChangeObservationStatus.COMPLETE &&
                afterSha256 != null && policyVerdict == AcpChangePolicyVerdict.ALLOW &&
                validationStatus == AcpChangeValidationStatus.PASSED && validationProofSha256.isNotEmpty() &&
                normalizedStopReason in setOf(AgentStopReason.COMPLETED, AgentStopReason.NO_CHANGES))) {
            "publication eligibility requires complete changes, allowed policy, completed validation, and proof"
        }
        require(eligibility != AcpChangePublicationEligibility.REJECTED ||
            policyVerdict == AcpChangePolicyVerdict.REJECT || validationStatus == AcpChangeValidationStatus.FAILED) {
            "rejected eligibility requires a rejected policy or failed validation outcome"
        }
        require(eligibility != AcpChangePublicationEligibility.INTERRUPTED ||
            normalizedStopReason in setOf(AgentStopReason.CANCELLED, AgentStopReason.LIMIT_EXHAUSTED) ||
            observation != AcpChangeObservationStatus.COMPLETE) {
            "interrupted eligibility requires an interrupted stop or incomplete observation"
        }
    }

    fun canonicalBytes(): ByteArray = OracleJson.canonicalBytes(buildJsonObject {
        put("schemaVersion", 1)
        put("turnId", turnId)
        put("intentSha256", intentSha256)
        put("receiptSha256", receiptSha256?.let(::JsonPrimitive) ?: JsonNull)
        put("sessionIdSha256", sessionIdSha256?.let(::JsonPrimitive) ?: JsonNull)
        put("changesSha256", changesSha256?.let(::JsonPrimitive) ?: JsonNull)
        put("beforeSha256", beforeSha256)
        put("afterSha256", afterSha256?.let(::JsonPrimitive) ?: JsonNull)
        put("observation", observation.name.lowercase())
        put("protocolStopCode", protocolStopCode?.let(::JsonPrimitive) ?: JsonNull)
        put("normalizedStopReason", normalizedStopReason?.name?.lowercase()?.let(::JsonPrimitive) ?: JsonNull)
        put("policyVerdict", policyVerdict.name.lowercase())
        put("policySha256", policySha256)
        put("reasonCodes", JsonArray(reasonCodes.sorted().map(::JsonPrimitive)))
        put("validationStatus", validationStatus.name.lowercase())
        put("validationProofSha256", JsonArray(validationProofSha256.sorted().map(::JsonPrimitive)))
        put("eligibility", eligibility.name.lowercase().replace('_', '-'))
        put("updatesSha256", updatesSha256?.let(::JsonPrimitive) ?: JsonNull)
    }, LIMITS)

    val sha256: String get() = sha256(canonicalBytes())

    companion object {
        private val KEYS = setOf(
            "schemaVersion", "turnId", "intentSha256", "receiptSha256", "sessionIdSha256", "changesSha256",
            "beforeSha256", "afterSha256",
            "observation", "protocolStopCode", "normalizedStopReason", "policyVerdict", "policySha256",
            "reasonCodes", "validationStatus", "validationProofSha256", "eligibility", "updatesSha256",
        )

        fun create(
            intent: AgentTurnIntent,
            receiptSha256: String?,
            sessionIdSha256: String?,
            changesSha256: String?,
            beforeSha256: String,
            afterSha256: String?,
            observation: AcpChangeObservationStatus,
            protocolStopCode: String?,
            normalizedStopReason: AgentStopReason?,
            policyVerdict: AcpChangePolicyVerdict,
            reasonCodes: Collection<String>,
            validationStatus: AcpChangeValidationStatus,
            validationProofSha256: Collection<String>,
            eligibility: AcpChangePublicationEligibility,
            updatesSha256: String?,
        ): AcpChangeAssessment = AcpChangeAssessment(
            turnId = intent.turnId,
            intentSha256 = intent.sha256,
            receiptSha256 = receiptSha256,
            sessionIdSha256 = sessionIdSha256,
            changesSha256 = changesSha256,
            beforeSha256 = beforeSha256,
            afterSha256 = afterSha256,
            observation = observation,
            protocolStopCode = protocolStopCode,
            normalizedStopReason = normalizedStopReason,
            policyVerdict = policyVerdict,
            policySha256 = intent.policySha256,
            reasonCodes = reasonCodes,
            validationStatus = validationStatus,
            validationProofSha256 = validationProofSha256,
            eligibility = eligibility,
            updatesSha256 = updatesSha256,
        )

        fun parse(bytes: ByteArray): AcpChangeAssessment {
            val root = parseDocument(bytes)
            require(root.keys == KEYS) { "change assessment has missing, extra, or duplicate fields" }
            require(root.int("schemaVersion") == 1) { "change assessment schema is unsupported" }
            val reasons = root.array("reasonCodes").map { it.stringValue() }
            val proofs = root.array("validationProofSha256").map { it.stringValue() }
            val assessment = AcpChangeAssessment(
                turnId = root.text("turnId"),
                intentSha256 = root.text("intentSha256"),
                receiptSha256 = root.nullableText("receiptSha256"),
                sessionIdSha256 = root.nullableText("sessionIdSha256"),
                changesSha256 = root.nullableText("changesSha256"),
                beforeSha256 = root.text("beforeSha256"),
                afterSha256 = root.nullableText("afterSha256"),
                observation = enumValue<AcpChangeObservationStatus>(root.text("observation")),
                protocolStopCode = root.nullableText("protocolStopCode"),
                normalizedStopReason = root.nullableText("normalizedStopReason")?.let { AgentStopReason.valueOf(it.uppercase()) },
                policyVerdict = enumValue(root.text("policyVerdict")),
                policySha256 = root.text("policySha256"),
                reasonCodes = reasons,
                validationStatus = enumValue(root.text("validationStatus")),
                validationProofSha256 = proofs,
                eligibility = AcpChangePublicationEligibility.entries.single {
                    it.name.lowercase().replace('_', '-') == root.text("eligibility")
                },
                updatesSha256 = root.nullableText("updatesSha256"),
            )
            require(assessment.canonicalBytes().contentEquals(bytes)) { "change assessment is not canonical" }
            return assessment
        }
    }
}

private const val MAXIMUM_REASON_CODES = 256
private const val MAXIMUM_VALIDATION_PROOFS = 256
private const val MAXIMUM_EVIDENCE_DOCUMENT_BYTES = 1024 * 1024
private val LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_EVIDENCE_DOCUMENT_BYTES,
    maximumCanonicalBytes = MAXIMUM_EVIDENCE_DOCUMENT_BYTES,
    maximumDepth = 8,
    maximumNodes = 4096,
    maximumStringBytes = 4096,
    maximumTotalStringBytes = 128 * 1024,
)

private fun parseDocument(bytes: ByteArray): JsonObject {
    require(bytes.size in 1..MAXIMUM_EVIDENCE_DOCUMENT_BYTES) { "ACP evidence document exceeds its 1 MiB bound" }
    return OracleJson.parseCanonical(bytes, LIMITS).jsonObject
}

private fun JsonObject.text(name: String): String =
    this[name]?.jsonPrimitive?.let { value ->
        require(value.isString) { "ACP evidence field $name must be a string" }
        value.content
    } ?: error("ACP evidence field $name must be a string")

private fun JsonObject.nullableText(name: String): String? = when (val value = this[name]) {
    null -> error("ACP evidence field $name is missing")
    JsonNull -> null
    is JsonPrimitive -> {
        require(value.isString) { "ACP evidence field $name must be a string or null" }
        value.content
    }
    else -> error("ACP evidence field $name must be a string or null")
}

private fun JsonObject.int(name: String): Int =
    this[name]?.jsonPrimitive?.intOrNull ?: error("ACP evidence field $name must be an integer")

private fun JsonObject.array(name: String): List<JsonElement> = this[name]?.jsonArray?.toList()
    ?: error("ACP evidence field $name must be an array")

private fun JsonElement.stringValue(): String = jsonPrimitive.let { value ->
    require(value.isString) { "ACP evidence array values must be strings" }
    value.content
}

private inline fun <reified T : Enum<T>> enumValue(value: String): T = try {
    enumValueOf<T>(value.uppercase().replace('-', '_'))
} catch (failure: IllegalArgumentException) {
    throw IllegalArgumentException("ACP evidence enum value is unsupported", failure)
}

private fun requireDigest(value: String) {
    require(value.matches(Regex("[a-f0-9]{64}"))) { "ACP evidence digest is invalid" }
}

private fun requireOpaqueId(value: String) {
    require(value.toByteArray(StandardCharsets.UTF_8).size in 1..256 &&
        value.matches(Regex("[A-Za-z0-9][A-Za-z0-9._:-]{0,255}"))) {
        "ACP evidence identifier is invalid"
    }
}

private fun <T> boundedCopy(values: Collection<T>, maximum: Int): List<T> {
    require(values.size <= maximum) { "ACP evidence list exceeds its $maximum-entry bound" }
    return Collections.unmodifiableList(ArrayList(values))
}
