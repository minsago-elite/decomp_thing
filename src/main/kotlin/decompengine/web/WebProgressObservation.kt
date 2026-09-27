package decompengine.web

import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentMessageRole
import decompengine.agent.AgentPermissionDecision
import decompengine.agent.AgentPlanStatus
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentToolStatus
import decompengine.agent.AgentWorkflowPhase
import kotlinx.serialization.json.*
import java.time.Duration
import java.time.Instant
import java.util.Locale

/** One classified public view shared by legacy and v1 progress adapters. */
internal data class WebPublicProgressRecord(
    val writerId: String?,
    val workflow: String?,
    val observationKind: String,
    val sequence: String,
    val occurredAt: String?,
    val agentSequence: String?,
    val fields: JsonObject,
    val omittedFieldCount: Int,
)

/**
 * Journal prose, paths, and producer-supplied labels are private even when old records retained
 * them. Public correlation uses application-issued writer/turn IDs and explicit SHA-256
 * commitments; typed categories and measurements are checked against their source domains.
 */
internal fun publicWebProgressRecord(record: JsonObject): WebPublicProgressRecord {
    require(record.size <= 128) { "observation field budget exceeded" }
    val id = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
    fun text(value: JsonElement, maximum: Int): String {
        val primitive = value as? JsonPrimitive
        require(primitive != null && primitive.isString && primitive.content.length <= maximum) { "invalid observation text" }
        return primitive.content
    }
    fun count(value: JsonElement): String {
        val primitive = value as? JsonPrimitive
        val content = primitive?.content.orEmpty()
        require(content.matches(Regex("0|[1-9][0-9]{0,19}")) && content.toULongOrNull() != null) { "invalid observation count" }
        return content
    }
    fun digest(value: JsonElement): String = text(value, 64).also {
        require(it.matches(Regex("[a-f0-9]{64}"))) { "invalid observation commitment" }
    }
    fun enumValues(values: Array<out Enum<*>>) = values.map { it.name.lowercase(Locale.ROOT) }.toSet()
    val categories = mapOf(
        "phase" to enumValues(AgentWorkflowPhase.entries.toTypedArray()),
        "status" to (enumValues(AgentPlanStatus.entries.toTypedArray()) +
            enumValues(AgentToolStatus.entries.toTypedArray()) + "running"),
        "stopReason" to enumValues(AgentStopReason.entries.toTypedArray()),
        "failureKind" to enumValues(AgentFailureKind.entries.toTypedArray()),
        "role" to enumValues(AgentMessageRole.entries.toTypedArray()),
        "decision" to enumValues(AgentPermissionDecision.entries.toTypedArray()),
        "change" to enumValues(AgentFileChangeKind.entries.toTypedArray()),
    )
    val metadata = setOf("runId", "workflow", "kind", "sequence", "time", "agentSequence")
    val privateLabels = setOf("taskId", "workflowRunId", "revisionId", "path", "text")
    val digests = setOf("taskIdSha256", "workflowRunIdSha256", "revisionIdSha256", "requestSha256", "sessionIdSha256",
        "toolCallIdSha256", "permissionIdSha256", "messageIdSha256", "acceptedRevisionSha256", "contentSha256", "afterSha256")
    val counts = setOf("inputTokens", "outputTokens", "cachedInputTokens", "toolCalls", "contextUsedTokens", "contextWindowTokens", "chunkCharacters", "entryCount")
    val booleans = setOf("completed", "validationPending", "sourceSequenceGap", "textOmitted", "messageTrackingExhausted", "entriesTruncated")
    var omitted = 0
    var withheldText = false
    val fields = buildJsonObject {
        for ((key, value) in record) when {
            key in metadata -> Unit
            key in privateLabels -> {
                omitted++
                if (key == "text") withheldText = true
            }
            key == "entries" -> {
                omitted++
            }
            key in categories -> {
                val category = text(value, 64)
                if (category in categories.getValue(key)) put(key, category) else omitted++
            }
            key in digests -> put(key, digest(value))
            key in counts -> put(key, count(value))
            key in booleans -> {
                val primitive = value as? JsonPrimitive
                require(primitive != null && !primitive.isString && primitive.booleanOrNull != null) { "invalid observation flag" }
                put(key, primitive.boolean)
            }
            key == "turnId" -> put(key, text(value, 128).also { require(it.matches(id)) { "invalid observation turn identity" } })
            key == "wallClock" -> {
                val duration = Duration.parse(text(value, 64))
                require(!duration.isNegative) { "invalid observation duration" }
                put(key, duration.toString())
            }
            key == "reportedCostAmount" -> put(key, text(value, 64).also {
                require(it.matches(Regex("(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[Ee][+-]?[0-9]+)?")) &&
                    it.toDoubleOrNull()?.let { number -> number.isFinite() && number >= 0.0 } == true) {
                    "invalid observation cost"
                }
            })
            key == "reportedCostCurrency" -> {
                val currency = text(value, 64)
                if (currency in setOf("AUD", "CAD", "CHF", "CNY", "EUR", "GBP", "JPY", "KRW", "USD")) put(key, currency) else omitted++
            }
            else -> omitted++
        }
        if (withheldText) put("textOmitted", true)
    }
    val writerId = record["runId"]?.let { text(it, 128).also { value -> require(value.matches(id)) { "invalid observation writer identity" } } }
    val workflow = record["workflow"]?.let { value ->
        text(value, 64).takeIf { it in setOf("build", "explore", "reconstruct", "reconstruction", "repair", "validate") } ?: "unknown"
    }
    val kindValue = text(record.getValue("kind"), 64)
    val kind = kindValue.takeIf { it in setOf("run_started", "task_started", "context_usage", "message", "plan", "tool", "permission",
        "file_change", "agent_finished", "workflow_phase", "workflow_run_state") } ?: "unknown"
    val occurredAt = record["time"]?.let { value ->
        Instant.parse(text(value, 40)).toString().also {
            require(it.matches(Regex("[0-9]{4}-[0-9]{2}-[0-9]{2}T.*Z"))) { "observation date is outside the web range" }
        }
    }
    return WebPublicProgressRecord(
        writerId = writerId,
        workflow = workflow,
        observationKind = kind,
        sequence = count(record.getValue("sequence")),
        occurredAt = occurredAt,
        agentSequence = record["agentSequence"]?.let(::count),
        fields = fields,
        omittedFieldCount = omitted,
    )
}

/** Display projection only. The caller supplies an authenticated attempt binding and replay cursor. */
internal fun webProgressObservation(jobId: String, attemptId: String, cursor: String, record: JsonObject): JsonObject {
    val id = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
    require(listOf(jobId, attemptId, cursor).all { it.matches(id) }) { "invalid observation binding" }
    val public = publicWebProgressRecord(record)
    val writerId = requireNotNull(public.writerId) { "observation writer identity is unavailable" }
    val workflow = requireNotNull(public.workflow) { "observation workflow is unavailable" }
    val occurredAt = requireNotNull(public.occurredAt) { "observation time is unavailable" }
    return buildJsonObject {
        put("apiVersion", 1); put("kind", "event"); put("type", "workflow.observation")
        put("jobId", jobId); put("runId", attemptId); put("cursor", cursor); put("sequence", public.sequence)
        put("occurredAt", occurredAt); put("originRequestId", JsonNull); put("agentInvocationId", JsonNull)
        put("agentSequence", public.agentSequence?.let(::JsonPrimitive) ?: JsonNull)
        put("payload", buildJsonObject {
            put("authority", "observations"); put("writerId", writerId); put("workflow", workflow)
            put("observationKind", public.observationKind); put("fields", public.fields)
            put("omittedFieldCount", public.omittedFieldCount.toString())
        })
    }.also { require(it.toString().toByteArray(Charsets.UTF_8).size <= 65_536) { "observation byte budget exceeded" } }
}
