package decompengine.web

import kotlinx.serialization.json.*

/** Legacy wire shape backed by the same classified fields as the v1 projection. */
internal fun legacyProgressPresentation(snapshot: JsonObject): JsonObject = buildJsonObject {
    val rootFields = setOf("schemaVersion", "displayOnly", "nextSequence", "queueDropped", "historyDropped", "truncated")
    rootFields.forEach { key -> snapshot[key]?.let { value ->
        require(value is JsonPrimitive && value.content.length <= 32) { "invalid progress metadata" }
        put(key, value)
    } }
    val rootOmitted = snapshot.keys.count { it !in rootFields && it != "events" }
    if (rootOmitted > 0) put("presentationOmittedFields", rootOmitted)
    put("events", buildJsonArray {
        for (item in snapshot.getValue("events").jsonArray) {
            val record = item.jsonObject
            val public = publicWebProgressRecord(record)
            add(buildJsonObject {
                put("sequence", record.getValue("sequence"))
                public.writerId?.let { put("runId", it) }
                public.workflow?.let { put("workflow", it) }
                public.occurredAt?.let { put("time", it) }
                put("kind", public.observationKind)
                public.agentSequence?.let { put("agentSequence", record.getValue("agentSequence")) }
                val numericFields = setOf("inputTokens", "outputTokens", "cachedInputTokens", "toolCalls",
                    "contextUsedTokens", "contextWindowTokens", "chunkCharacters", "entryCount")
                public.fields.forEach { (key, value) -> put(key, if (key in numericFields) record.getValue(key) else value) }
                if (public.omittedFieldCount > 0) put("presentationOmittedFields", public.omittedFieldCount)
            })
        }
    })
}
