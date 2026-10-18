package decompengine.web

import decompengine.jobs.PublicProgressRecord
import decompengine.jobs.publicProgressRecord
import kotlinx.serialization.json.*

internal typealias WebPublicProgressRecord = PublicProgressRecord

/** The web adapters and owned historical replay use the same strict field classifier. */
internal fun publicWebProgressRecord(record: JsonObject): WebPublicProgressRecord = publicProgressRecord(record)

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
