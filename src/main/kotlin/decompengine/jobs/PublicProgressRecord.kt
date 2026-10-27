package decompengine.jobs

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

private fun replayOmissionCount(value: JsonElement): Int {
    val primitive = value as? JsonPrimitive
    val count = primitive?.takeIf { !it.isString }?.intOrNull
    require(count != null && count >= 0) { "invalid replay omission count" }
    return count
}

/** One classified public view shared by legacy and v1 progress adapters. */
internal data class PublicProgressRecord(
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
internal fun publicProgressRecord(record: JsonObject, allowMissingKind: Boolean = false): PublicProgressRecord {
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
    fun omit() { omitted = Math.addExact(omitted, 1) }
    var withheldText = false
    // Provider reasoning is private: older journals may hold its commitments or sizes, which are withheld.
    val privateReasoning = record["role"].let { it is JsonPrimitive && it.isString && it.content == "thought" }
    val reasoningMeasurements = setOf("contentSha256", "chunkCharacters")
    val fields = buildJsonObject {
        for ((key, value) in record) when {
            privateReasoning && key in reasoningMeasurements -> {
                omit()
                withheldText = true
            }
            key in metadata -> Unit
            key == "replayOmittedFields" -> {
                omitted = Math.addExact(omitted, replayOmissionCount(value))
            }
            key in privateLabels -> {
                omit()
                if (key == "text") withheldText = true
            }
            key == "entries" -> {
                omit()
            }
            key in categories -> {
                val category = text(value, 64)
                if (category in categories.getValue(key)) put(key, category) else omit()
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
                require((it == "-0.0" || it.matches(Regex("(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[Ee][+-]?[0-9]+)?"))) &&
                    it.toDoubleOrNull()?.let { number -> number.isFinite() && number >= 0.0 } == true) {
                    "invalid observation cost"
                }
            })
            key == "reportedCostCurrency" -> {
                val currency = text(value, 64)
                if (currency in setOf("AUD", "CAD", "CHF", "CNY", "EUR", "GBP", "JPY", "KRW", "USD")) put(key, currency) else omit()
            }
            else -> omit()
        }
        if (withheldText || privateReasoning) put("textOmitted", true)
    }
    val writerId = record["runId"]?.let { text(it, 128).also { value -> require(value.matches(id)) { "invalid observation writer identity" } } }
    val workflow = record["workflow"]?.let { value ->
        text(value, 64).takeIf { it in setOf("build", "explore", "reconstruct", "reconstruction", "repair", "validate") } ?: "unknown"
    }
    val kindValue = if (allowMissingKind && "kind" !in record) "unknown" else text(record.getValue("kind"), 64)
    val kind = kindValue.takeIf { it in setOf("run_started", "task_started", "context_usage", "message", "plan", "tool", "permission",
        "file_change", "agent_finished", "workflow_phase", "workflow_run_state") } ?: "unknown"
    val occurredAt = record["time"]?.let { value ->
        Instant.parse(text(value, 40)).toString().also {
            require(it.matches(Regex("[0-9]{4}-[0-9]{2}-[0-9]{2}T.*Z"))) { "observation date is outside the web range" }
        }
    }
    return PublicProgressRecord(
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

/** Reclassify old display records before an owned writer republishes them.
 * A later mask cannot reconstruct a secret partly erased by an older formatter. Preserve typed
 * facts and commitments, but never promote historical prose/labels to current safe content.
 * The caller must first apply the journal's bounded raw decoder; this function authorizes no I/O.
 */
internal fun replayProgressRecord(record: JsonObject): JsonObject {
    require(record.size <= 128) { "observation field budget exceeded" }
    // Older journals admitted sequence-only records. Do not invent their identity, kind or time.
    val classified = try {
        publicProgressRecord(record, allowMissingKind = true)
    } catch (_: java.time.format.DateTimeParseException) {
        // JDK date parsers include their raw input in the exception message and cause.
        throw IllegalArgumentException("historical progress record contains invalid time metadata")
    }
    val numericFields = setOf("inputTokens", "outputTokens", "cachedInputTokens", "toolCalls",
        "contextUsedTokens", "contextWindowTokens", "chunkCharacters", "entryCount")
    return buildJsonObject {
        put("sequence", record.getValue("sequence"))
        classified.writerId?.let { put("runId", it) }
        classified.workflow?.let { put("workflow", it) }
        classified.occurredAt?.let { put("time", it) }
        if ("kind" in record) put("kind", classified.observationKind)
        classified.agentSequence?.let { put("agentSequence", record.getValue("agentSequence")) }
        classified.fields.forEach { (key, value) ->
            put(key, if (key in numericFields) record.getValue(key) else value)
        }
        if (classified.omittedFieldCount > 0) put("replayOmittedFields", classified.omittedFieldCount)
    }
}

/** Display-only projection of a snapshot already admitted by the bounded journal decoder. */
internal fun replayProgressSnapshot(snapshot: JsonObject): JsonObject {
    val rootFields = setOf("schemaVersion", "displayOnly", "nextSequence", "queueDropped", "historyDropped",
        "truncated", "events", "omittedSequenceRanges", "retentionExpiredAt")
    val records = snapshot.getValue("events").jsonArray
    require(records.size <= 1024) { "progress snapshot exceeds the event limit" }
    var omitted = snapshot["replayOmittedFields"]?.let(::replayOmissionCount) ?: 0
    for (key in snapshot.keys) if (key !in rootFields && key != "replayOmittedFields") {
        omitted = Math.addExact(omitted, 1)
    }
    return buildJsonObject {
        for (key in rootFields) {
            if (key == "events") put(key, JsonArray(records.map { replayProgressRecord(it.jsonObject) }))
            else snapshot[key]?.let { put(key, it) }
        }
        if (omitted > 0) put("replayOmittedFields", omitted)
    }
}
