package decompengine.jobs

import decompengine.web.WebAccessDenied
import decompengine.web.WebProgressPages
import kotlinx.serialization.json.*
import java.time.Duration
import java.time.Instant
import kotlin.test.*

class AgentProgressJournalRetentionTest {
    private val end = Instant.parse("2026-09-08T00:00:00Z")
    private val due = end.plus(Duration.ofHours(24))
    private fun attempt(state: WorkflowRunState = WorkflowRunState.COMPLETED) = WorkflowAttempt(
        runId = "attempt", jobId = "a".repeat(32), workflow = WorkflowKind.EXPLORE, state = state,
        version = "1", createdAt = end.minusSeconds(30), startedAt = end.minusSeconds(20),
        endedAt = if (state.terminal) end else null, previousRunId = null, inputRevisionId = null,
        harnessCapabilityId = null, limits = WorkflowExecutionLimits(1000u, 500u, 1000u, 1u),
        terminalReason = if (state.terminal) WorkflowTerminalReason.COMPLETED else null,
        usage = null, candidate = null, acceptedRevision = null,
    )
    private fun journal(sequences: List<Long> = listOf(0), next: Long = 1, queue: Long = 0, history: Long = 0) = buildJsonObject {
        put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", next)
        put("queueDropped", queue); put("historyDropped", history); put("truncated", queue + history > 0)
        put("events", buildJsonArray { sequences.forEach { sequence -> add(buildJsonObject {
            put("sequence", sequence); put("runId", "writer"); put("workflow", "explore")
            put("kind", "workflow_phase"); put("time", end.toString()); put("phase", "planning")
            put("text", "PRIVATE_RETAINED_PROSE")
        }) } })
    }.toString().toByteArray()

    @Test fun `expiry uses durable terminal time with an exact default boundary`() {
        val bytes = journal()
        for (state in WorkflowRunState.entries) {
            val a = attempt(state)
            assertNull(AgentProgressJournalRetention.expiredSnapshot(a, bytes, end.minusSeconds(1)))
            assertNull(AgentProgressJournalRetention.expiredSnapshot(a, bytes, due.minusNanos(1)))
            val expired = AgentProgressJournalRetention.expiredSnapshot(a, bytes, due)
            if (state.terminal) assertNotNull(expired, state.name) else assertNull(expired, state.name)
        }
        val pending = attempt().copy(candidate = WorkflowCandidate("candidate", "a".repeat(64)))
        assertNull(AgentProgressJournalRetention.expiredSnapshot(pending, bytes, due.plusSeconds(86400)))
        assertFailsWith<IllegalArgumentException> {
            AgentProgressJournalRetention.expiredSnapshot(attempt().copy(endedAt = null), bytes, due)
        }
        for (duration in listOf(Duration.ZERO, Duration.ofSeconds(-1))) assertFailsWith<IllegalArgumentException> {
            AgentProgressJournalRetention.expiredSnapshot(attempt(), bytes, due, duration)
        }
        assertNull(AgentProgressJournalRetention.expiredSnapshot(attempt(), bytes, end.plusSeconds(59), Duration.ofMinutes(1)))
        assertNotNull(AgentProgressJournalRetention.expiredSnapshot(attempt(), bytes, end.plusSeconds(60), Duration.ofMinutes(1)))
    }

    @Test fun `expiry removes the single startup record without changing source bytes or run metadata`() {
        val original = journal()
        val saved = original.copyOf()
        val a = attempt()
        val snapshot = assertNotNull(AgentProgressJournalRetention.expiredSnapshot(a, original, due))
        val expired = AgentProgressJournal.decode(snapshot)
        assertEquals("1", expired.getValue("nextSequence").jsonPrimitive.content)
        assertEquals("0", expired.getValue("queueDropped").jsonPrimitive.content)
        assertEquals("1", expired.getValue("historyDropped").jsonPrimitive.content)
        assertEquals(due.toString(), expired.getValue("retentionExpiredAt").jsonPrimitive.content)
        assertTrue(expired.getValue("events").jsonArray.isEmpty())
        assertFalse(snapshot.decodeToString().contains("PRIVATE_RETAINED_PROSE"))
        assertTrue(snapshot.size < 1024)
        assertContentEquals(saved, original)
        assertEquals(attempt(), a)
        assertNull(AgentProgressJournalRetention.expiredSnapshot(a, snapshot, due.plusSeconds(1)))
    }

    @Test fun `expiry preserves exact large queue loss and cumulative history watermarks`() {
        val next = Long.MAX_VALUE - 1
        val original = journal(listOf(next - 2, next - 1), next, queue = 1, history = next - 3)
        val expired = AgentProgressJournal.decode(assertNotNull(AgentProgressJournalRetention.expiredSnapshot(attempt(), original, due)))
        assertEquals(next.toString(), expired.getValue("nextSequence").jsonPrimitive.content)
        assertEquals("1", expired.getValue("queueDropped").jsonPrimitive.content)
        assertEquals((next - 1).toString(), expired.getValue("historyDropped").jsonPrimitive.content)
        assertEquals(Json.parseToJsonElement("""[{"startInclusive":"0","endExclusive":"$next"}]"""), expired["omittedSequenceRanges"])
        val empty = AgentProgressJournal.decode(assertNotNull(AgentProgressJournalRetention.expiredSnapshot(attempt(), journal(emptyList(), 0), due)))
        assertFalse(empty.getValue("truncated").jsonPrimitive.boolean)
        assertTrue(empty.getValue("omittedSequenceRanges").jsonArray.isEmpty())
    }

    @Test fun `expiry rejects corrupt accounting and malformed expiry markers`() {
        val base = AgentProgressJournal.decode(journal())
        val bad = listOf(
            JsonObject(base + ("queueDropped" to JsonPrimitive(1))),
            JsonObject(base + ("retentionExpiredAt" to JsonPrimitive(due.toString()))),
        )
        bad.forEach { value -> assertFails { AgentProgressJournalRetention.expiredSnapshot(attempt(), value.toString().toByteArray(), due) } }
        val expired = AgentProgressJournal.decode(assertNotNull(AgentProgressJournalRetention.expiredSnapshot(attempt(), journal(), due)))
        for (marker in listOf(JsonNull, JsonPrimitive(true), JsonPrimitive("yesterday"), JsonPrimitive("2026-09-09T00:00:00+00:00"))) {
            assertFails { AgentProgressJournal.decode(JsonObject(expired + ("retentionExpiredAt" to marker)).toString().toByteArray()) }
        }
        assertFails { AgentProgressJournal.decode(JsonObject(expired - "retentionExpiredAt").toString().toByteArray()) }
        assertFails { AgentProgressJournalRetention.expiredSnapshot(attempt(), "{".toByteArray(), due) }
    }

    @Test fun `expired record cursors report a gap and fresh watermark permits empty replay`() {
        val pages = WebProgressPages()
        val a = attempt()
        val original = journal()
        val old = pages.boundary("owner", a.jobId, a.runId, original)
        val expired = assertNotNull(AgentProgressJournalRetention.expiredSnapshot(a, original, due))
        val gap = assertFailsWith<WebAccessDenied> {
            pages.page("owner", a.jobId, a.runId, expired, "after=${old.throughCursor}")
        }
        assertEquals(410, gap.status); assertEquals("EVENT_GAP", gap.code)
        val fresh = pages.boundary("owner", a.jobId, a.runId, expired)
        assertNull(fresh.oldestCursor); assertEquals("0", fresh.throughSequence)
        assertNotNull(fresh.throughCursor); assertEquals("0", fresh.retainedEventCount)
        val page = pages.page("owner", a.jobId, a.runId, expired, "after=${fresh.throughCursor}")
        assertTrue(page.getValue("items").jsonArray.isEmpty())
        assertFalse(page.getValue("hasMore").jsonPrimitive.boolean)
        assertEquals(fresh.throughCursor, page.getValue("nextCursor").jsonPrimitive.content)
        assertEquals("1", fresh.historyDropped)
    }
}
