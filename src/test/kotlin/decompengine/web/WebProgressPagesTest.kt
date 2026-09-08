package decompengine.web

import kotlinx.serialization.json.*
import kotlin.test.*

class WebProgressPagesTest {
    private fun journal(sequences: List<Long>, next: Long = (sequences.lastOrNull() ?: -1) + 1, text: String = "fixture"): ByteArray {
        // Omissions must be accounted exactly: history eviction covers a prefix, queue drops cover the rest.
        // Empty snapshots cannot classify the initial admitted event as queue loss or single-event eviction.
        val historyDropped = if (sequences.isEmpty() && next >= 2) 2L else sequences.firstOrNull() ?: 0L
        val queueDropped = next - sequences.size - historyDropped
        return buildJsonObject {
            put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", next)
            put("queueDropped", queueDropped); put("historyDropped", historyDropped)
            put("truncated", queueDropped > 0 || historyDropped > 0)
            put("events", buildJsonArray { sequences.forEach { seq -> add(buildJsonObject {
                put("sequence", seq); put("runId", "writer_fixture"); put("workflow", "reconstruct")
                put("time", "2026-09-05T00:00:00Z"); put("kind", "message"); put("text", text)
            }) } })
        }.toString().toByteArray()
    }
    private fun cursor(page: JsonObject) = page.getValue("nextCursor").jsonPrimitive.content
    private fun sequences(page: JsonObject) = page.getValue("items").jsonArray.map { it.jsonObject.getValue("sequence").jsonPrimitive.content }
    private fun page(pages: WebProgressPages, bytes: ByteArray, query: String? = null) = pages.page("owner", "job", "attempt", bytes, query)

    @Test fun `resume returns subsequent events and supports an unchanged empty poll`() {
        val pages = WebProgressPages()
        val first = page(pages, journal(listOf(0, 1)), "limit=1")
        assertEquals(listOf("0"), sequences(first))
        assertTrue(cursor(first).length <= 128)
        val next = page(pages, journal(listOf(0, 1, 2)), "cursor=${cursor(first)}")
        assertEquals(listOf("1", "2"), sequences(next))
        val idle = page(pages, journal(listOf(0, 1, 2)), "cursor=${cursor(next)}")
        assertTrue(sequences(idle).isEmpty()); assertEquals(cursor(next), cursor(idle))
        assertFalse(idle.getValue("hasMore").jsonPrimitive.boolean)
    }

    @Test fun `target polling parameters preserve replay and reject ambiguous positions`() {
        val pages = WebProgressPages(); val bytes = journal(listOf(0, 1, 2))
        val first = page(pages, bytes, "transport=poll&limit=1")
        val anchor = cursor(first)
        val legacy = page(pages, bytes, "cursor=$anchor&limit=1")
        assertEquals(legacy, page(pages, bytes, "transport=poll&after=$anchor&limit=1"))
        assertEquals(legacy, page(pages, bytes, "after=$anchor&limit=1"))
        assertEquals(legacy, page(pages, bytes, "transport=%70oll&cursor=$anchor&limit=1"))
        for (query in listOf("transport=stream", "transport=", "transport=poll&transport=poll",
            "after=$anchor&cursor=$anchor", "after=$anchor&after=$anchor", "limit=1&limit=2",
            "transport=poll&", "transport=" + "x".repeat(4096))) {
            assertEquals("VALIDATION_FAILED", assertFailsWith<WebAccessDenied> { page(pages, bytes, query) }.code, query.take(100))
        }
        for (query in listOf("transport=poll&after=", "transport=poll&after=%26cursor%3Danything")) {
            assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { page(pages, bytes, query) }.code)
        }
        assertEquals("EVENT_GAP", assertFailsWith<WebAccessDenied> {
            page(pages, journal(listOf(1, 2)), "transport=poll&after=$anchor")
        }.code)
    }

    @Test fun `cursors reject cross session job attempt and tampering`() {
        val pages = WebProgressPages(); val bytes = journal(listOf(0, 1))
        val token = cursor(page(pages, bytes, "limit=1"))
        for ((owner, job, run) in listOf(Triple("other", "job", "attempt"), Triple("owner", "other", "attempt"), Triple("owner", "job", "other"))) {
            assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { pages.page(owner, job, run, bytes, "cursor=$token") }.code)
        }
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { page(pages, bytes, "cursor=${token.dropLast(1)}${if (token.last() == 'a') 'b' else 'a'}") }.code)
        assertEquals("EVENT_GAP", assertFailsWith<WebAccessDenied> { page(WebProgressPages(), bytes, "cursor=$token") }.code)
    }

    @Test fun `missing changed interior and trailing boundaries report explicit gaps`() {
        val pages = WebProgressPages(); val token = cursor(page(pages, journal(listOf(0, 1)), "limit=1"))
        for (bytes in listOf(journal(listOf(1, 2)), journal(listOf(0, 1), text = "changed"), journal(listOf(0, 2)), journal(listOf(0), next = 2))) {
            assertEquals("EVENT_GAP", assertFailsWith<WebAccessDenied> { page(pages, bytes, "cursor=$token") }.code)
        }
        assertEquals("EVENT_GAP", assertFailsWith<WebAccessDenied> { page(pages, journal(listOf(5, 6))) }.code)
        assertEquals("EVENT_GAP", assertFailsWith<WebAccessDenied> { page(pages, journal(emptyList(), next = 3)) }.code)
    }

    @Test fun `fresh boundary permits explicit retained-history selection and cutover`() {
        val pages = WebProgressPages(); val bytes = journal(listOf(5, 6))
        val boundary = pages.boundary("owner", "job", "attempt", bytes)
        assertEquals("6", boundary.throughSequence)
        assertEquals(listOf("5", "6"), sequences(page(pages, bytes, "cursor=${boundary.oldestCursor}")))
        assertEquals(listOf("7"), sequences(page(pages, journal(listOf(5, 6, 7)), "cursor=${boundary.throughCursor}")))
    }

    @Test fun `fresh cutover acknowledges trailing omitted sequences without a reset loop`() {
        val pages = WebProgressPages(); val bytes = journal(listOf(0, 1), next = 4)
        val boundary = pages.boundary("owner", "job", "attempt", bytes)
        assertEquals("3", boundary.throughSequence)
        val idle = page(pages, bytes, "cursor=${boundary.throughCursor}")
        assertTrue(sequences(idle).isEmpty())
        assertEquals(listOf("4"), sequences(page(pages, journal(listOf(0, 1, 4)), "cursor=${boundary.throughCursor}")))
        val huge = pages.boundary("owner", "job", "attempt", journal(listOf(Long.MAX_VALUE - 2)))
        assertTrue(huge.throughCursor!!.length <= 128)
        assertTrue(sequences(page(pages, journal(listOf(Long.MAX_VALUE - 2)), "cursor=${huge.throughCursor}")).isEmpty())
    }

    @Test fun `large observations split below the response byte ceiling without losing reachability`() {
        val pages = WebProgressPages()
        val source = Json.parseToJsonElement(journal((0L..199L).toList()).decodeToString()).jsonObject
        // Exercise the byte ceiling with retained metadata; private prose is now withheld.
        val labels = listOf("taskId", "workflowRunId", "revisionId", "phase", "status", "stopReason",
            "failureKind", "role", "decision", "change", "wallClock", "reportedCostAmount", "reportedCostCurrency")
        val bytes = JsonObject(source + ("events" to JsonArray(source.getValue("events").jsonArray.map { item ->
            JsonObject(item.jsonObject + labels.associateWith { JsonPrimitive("x".repeat(533)) })
        }))).toString().toByteArray()
        val first = page(pages, bytes, "limit=200")
        assertTrue(first.toString().toByteArray().size < 1_048_576)
        assertTrue(first.getValue("hasMore").jsonPrimitive.boolean)
        val second = page(pages, bytes, "limit=200&cursor=${cursor(first)}")
        assertEquals((0..199).map(Int::toString), sequences(first) + sequences(second))
    }

    @Test fun `malformed journals and unsupported query parameters fail explicitly`() {
        val pages = WebProgressPages()
        assertEquals("PROGRESS_UNAVAILABLE", assertFailsWith<WebAccessDenied> { page(pages, "{".toByteArray()) }.code)
        assertEquals("VALIDATION_FAILED", assertFailsWith<WebAccessDenied> { page(pages, journal(emptyList()), "search=ignored") }.code)
        assertEquals("VALIDATION_FAILED", assertFailsWith<WebAccessDenied> { page(pages, journal(emptyList()), "limit=201") }.code)
        assertEquals(emptyList(), sequences(page(pages, journal(emptyList()))))
    }
    @Test fun `gap recovery describes the same retained bytes and configured snapshot route`() {
        val pages = WebProgressPages()
        val token = cursor(page(pages, journal(listOf(0)), "limit=1"))
        val bytes = journal(listOf(1, 2))
        val failure = assertFailsWith<WebAccessDenied> {
            pages.page("owner", "job", "attempt", bytes, "after=$token", "/nested/api/v1/jobs/job/runs/attempt/snapshot")
        }
        assertEquals(410, failure.status); assertEquals("EVENT_GAP", failure.code)
        val recovery = assertNotNull(failure.eventGap)
        val retained = pages.boundary("owner", "job", "attempt", bytes)
        assertEquals(token, recovery.getValue("requestedCursor").jsonPrimitive.content)
        assertEquals(retained.oldestCursor, recovery.getValue("oldestCursor").jsonPrimitive.content)
        assertEquals(retained.throughCursor, recovery.getValue("latestCursor").jsonPrimitive.content)
        assertEquals("/nested/api/v1/jobs/job/runs/attempt/snapshot", recovery.getValue("snapshotHref").jsonPrimitive.content)
        assertEquals("job", recovery.getValue("jobId").jsonPrimitive.content)
        assertEquals("attempt", recovery.getValue("runId").jsonPrimitive.content)
    }

    @Test fun `empty retained gap has null positions and invalid cursors have no recovery disclosure`() {
        val pages = WebProgressPages()
        val failure = assertFailsWith<WebAccessDenied> { page(pages, journal(emptyList(), next = 3)) }
        val recovery = assertNotNull(failure.eventGap)
        for (key in listOf("requestedCursor", "oldestCursor", "latestCursor")) assertEquals(JsonNull, recovery[key])
        val invalid = assertFailsWith<WebAccessDenied> { page(pages, journal(listOf(0)), "after=malformed") }
        assertEquals(400, invalid.status); assertNull(invalid.eventGap)
    }

}
