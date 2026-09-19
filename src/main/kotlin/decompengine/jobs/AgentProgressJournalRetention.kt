package decompengine.jobs

import kotlinx.serialization.json.*
import java.time.Duration
import java.time.Instant

/** Pure retention preparation. The storage owner must stabilize the attempt and exclude writers
 * through checked atomic publication of the returned bytes. This function does not authorize a write.
 */
internal object AgentProgressJournalRetention {
    val DEFAULT_TERMINAL_RETENTION: Duration = Duration.ofHours(24)

    /** Null means no replacement is due. Terminal time comes from durable state, never file mtime
     * or observation timestamps. Pending acceptance publication must finish before maintenance.
     */
    fun expiredSnapshot(attempt: WorkflowAttempt, bytes: ByteArray, now: Instant,
        retention: Duration = DEFAULT_TERMINAL_RETENTION): ByteArray? {
        require(!retention.isNegative && !retention.isZero) { "retention must be positive" }
        if (!attempt.state.terminal || attempt.publicationPending || attempt.progressRetentionPinned) return null
        val endedAt = requireNotNull(attempt.endedAt) { "terminal attempt has no end time" }
        if (Duration.between(endedAt, now) < retention) return null
        val journal = AgentProgressJournal.decode(bytes)
        if (journal.containsKey("retentionExpiredAt")) return null
        val next = journal.getValue("nextSequence").jsonPrimitive.long
        val queue = journal.getValue("queueDropped").jsonPrimitive.long
        // Decoder proved exact accounting. Subtraction preserves all prior queue loss without overflow.
        val history = next - queue
        return buildJsonObject {
            put("schemaVersion", 1); put("displayOnly", true)
            put("nextSequence", next); put("queueDropped", queue); put("historyDropped", history)
            put("truncated", next > 0); put("events", JsonArray(emptyList()))
            put("omittedSequenceRanges", buildJsonArray {
                if (next > 0) add(buildJsonObject {
                    put("startInclusive", "0"); put("endExclusive", next.toString())
                })
            })
            put("retentionExpiredAt", now.toString())
        }.toString().toByteArray(Charsets.UTF_8).also { AgentProgressJournal.decode(it) }
    }
}
