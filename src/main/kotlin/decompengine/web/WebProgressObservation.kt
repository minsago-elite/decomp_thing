package decompengine.web

import kotlinx.serialization.json.*
import java.time.Instant

/** Display projection only. The caller supplies an authenticated attempt binding and replay cursor. */
internal fun webProgressObservation(jobId: String, attemptId: String, cursor: String, record: JsonObject): JsonObject {
    val id = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
    require(listOf(jobId, attemptId, cursor).all { it.matches(id) }) { "invalid observation binding" }
    require(record.size <= 128) { "observation field budget exceeded" }
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
    val writerId = text(record.getValue("runId"), 128).also { require(it.matches(id)) }
    val workflow = text(record.getValue("workflow"), 64).also { require(it.matches(Regex("[a-z][a-z0-9-]{0,63}"))) }
    val kind = text(record.getValue("kind"), 64).also { require(it.matches(Regex("[a-z][a-z0-9_]{0,63}"))) }
    val sequence = count(record.getValue("sequence"))
    val occurredAt = Instant.parse(text(record.getValue("time"), 40)).toString()
    require(occurredAt.matches(Regex("[0-9]{4}-[0-9]{2}-[0-9]{2}T.*Z"))) { "observation date is outside the web range" }
    val metadata = setOf("runId", "workflow", "kind", "sequence", "time", "agentSequence")
    val strings = setOf("taskId", "workflowRunId", "revisionId", "phase", "status", "stopReason", "failureKind", "role",
        "decision", "path", "change", "wallClock", "reportedCostAmount", "reportedCostCurrency")
    val digests = setOf("taskIdSha256", "workflowRunIdSha256", "revisionIdSha256", "requestSha256", "sessionIdSha256",
        "toolCallIdSha256", "permissionIdSha256", "messageIdSha256", "acceptedRevisionSha256", "contentSha256", "afterSha256")
    val counts = setOf("inputTokens", "outputTokens", "cachedInputTokens", "toolCalls", "contextUsedTokens", "contextWindowTokens", "chunkCharacters", "entryCount")
    val booleans = setOf("completed", "validationPending", "sourceSequenceGap", "textOmitted", "messageTrackingExhausted", "entriesTruncated")
    var omitted = 0
    val validatedFields = buildJsonObject {
        for ((key, value) in record) when (key) {
            in metadata -> Unit
            in strings -> put(key, text(value, 533))
            in digests -> put(key, digest(value))
            in counts -> put(key, count(value))
            in booleans -> {
                val primitive = value as? JsonPrimitive
                require(primitive != null && !primitive.isString && primitive.booleanOrNull != null) { "invalid observation flag" }
                put(key, primitive.boolean)
            }
            "text" -> put(key, text(value, 8192))
            "turnId" -> put(key, text(value, 128).also { require(it.matches(id)) })
            "entries" -> {
                val entries = value as? JsonArray
                require(entries != null && entries.size <= 8) { "observation plan budget exceeded" }
                put(key, buildJsonArray {
                    for (entry in entries) {
                        val item = entry as? JsonObject
                        require(item != null && item.keys == setOf("idSha256", "status", "text")) { "invalid observation plan item" }
                        add(buildJsonObject {
                            put("idSha256", digest(item.getValue("idSha256")))
                            put("status", text(item.getValue("status"), 64))
                            put("text", text(item.getValue("text"), 181))
                        })
                    }
                })
            }
            else -> omitted++
        }
    }
    // Known fields are still validated, but journal prose has no certified public visibility.
    val withheld = setOf("text", "entries", "path")
    omitted += validatedFields.keys.count { it in withheld }
    val fields = buildJsonObject {
        validatedFields.filterKeys { it !in withheld }.forEach { (key, value) -> put(key, value) }
        if ("text" in validatedFields) put("textOmitted", true)
    }
    return buildJsonObject {
        put("apiVersion", 1); put("kind", "event"); put("type", "workflow.observation")
        put("jobId", jobId); put("runId", attemptId); put("cursor", cursor); put("sequence", sequence)
        put("occurredAt", occurredAt); put("originRequestId", JsonNull); put("agentInvocationId", JsonNull)
        put("agentSequence", record["agentSequence"]?.let { JsonPrimitive(count(it)) } ?: JsonNull)
        put("payload", buildJsonObject {
            put("authority", "observations"); put("writerId", writerId); put("workflow", workflow); put("observationKind", kind)
            put("fields", fields); put("omittedFieldCount", omitted.toString())
        })
    }.also { require(it.toString().toByteArray(Charsets.UTF_8).size <= 65_536) { "observation byte budget exceeded" } }
}
