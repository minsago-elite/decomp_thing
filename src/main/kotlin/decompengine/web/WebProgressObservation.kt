package decompengine.web

import decompengine.jobs.PublicProgressRecord
import decompengine.jobs.AgentProgressJournal
import decompengine.jobs.publicProgressRecord
import decompengine.jobs.replayProgressSnapshot
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*

internal typealias WebPublicProgressRecord = PublicProgressRecord

/** The web adapters and owned historical replay use the same strict field classifier. */
internal fun publicWebProgressRecord(record: JsonObject): WebPublicProgressRecord = publicProgressRecord(record)

/** Exact display-journal namespaces only; a source/receipt basename confers no display policy. */
internal fun isProgressJournalArtifact(relativePath: String): Boolean {
    val parts = canonicalReportSegments(relativePath)
    return (parts.size == 2 && parts[1] == AgentProgressJournal.FILE_NAME) ||
        (parts.size == 4 && parts[1] == "runs" && parts[3] == AgentProgressJournal.FILE_NAME)
}

/** The caller must authorize and capture the selected artifact before projecting its display bytes. */
internal fun progressArtifactProjection(relativePath: String, bytes: ByteArray): ByteArray {
    if (!isProgressJournalArtifact(relativePath)) return bytes
    return try {
        val snapshot = replayProgressSnapshot(AgentProgressJournal.decode(bytes))
        OracleJson.canonicalBytes(snapshot, StrictJsonLimits(
            maximumInputBytes = AgentProgressJournal.MAXIMUM_READ_BYTES,
            maximumCanonicalBytes = AgentProgressJournal.MAXIMUM_READ_BYTES,
            maximumDepth = 32,
            maximumNodes = 65_536,
            maximumStringBytes = 16 * 1024,
            maximumTotalStringBytes = AgentProgressJournal.MAXIMUM_READ_BYTES,
        ))
    } catch (failure: Exception) {
        if (failure is InterruptedException || failure is java.util.concurrent.CancellationException) throw failure
        throw WebJobServiceException("PROGRESS_UNAVAILABLE", "The retained progress report is unavailable.")
    }
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
