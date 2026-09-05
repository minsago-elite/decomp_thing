package decompengine.web

import kotlinx.serialization.json.*

/** The journal has no certified public-text marker. Expose observations, never raw prose. */
internal fun legacyProgressPresentation(snapshot: JsonObject): JsonObject = buildJsonObject {
    val rootFields = setOf("schemaVersion", "displayOnly", "nextSequence", "queueDropped", "historyDropped", "truncated")
    rootFields.forEach { key -> snapshot[key]?.let { value ->
        require(value is JsonPrimitive && value.content.length <= 32) { "invalid progress metadata" }
        put(key, value)
    } }
    val rootOmitted = snapshot.keys.count { it !in rootFields && it != "events" }
    if (rootOmitted > 0) put("presentationOmittedFields", rootOmitted)
    val eventFields = setOf(
        "sequence", "runId", "workflow", "time", "kind", "agentSequence", "taskId", "workflowRunId", "revisionId",
        "phase", "status", "stopReason", "failureKind", "role", "decision", "change", "wallClock",
        "reportedCostAmount", "reportedCostCurrency", "turnId", "taskIdSha256", "workflowRunIdSha256",
        "revisionIdSha256", "requestSha256", "sessionIdSha256", "toolCallIdSha256", "permissionIdSha256",
        "messageIdSha256", "acceptedRevisionSha256", "contentSha256", "afterSha256", "inputTokens",
        "outputTokens", "cachedInputTokens", "toolCalls", "contextUsedTokens", "contextWindowTokens",
        "chunkCharacters", "entryCount", "completed", "validationPending", "sourceSequenceGap",
        "textOmitted", "messageTrackingExhausted", "entriesTruncated",
    )
    put("events", buildJsonArray {
        for (item in snapshot.getValue("events").jsonArray) {
            val record = item.jsonObject
            add(buildJsonObject {
                var omitted = 0
                for ((key, value) in record) {
                    if (key in eventFields && value is JsonPrimitive && value.content.length <= 533) put(key, value)
                    else omitted++
                }
                if ("text" in record) put("textOmitted", true)
                if (omitted > 0) put("presentationOmittedFields", omitted)
            })
        }
    })
}
