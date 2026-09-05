package decompengine.web

import kotlinx.serialization.json.*
import kotlin.test.*

class WebProgressPagesTest {
    private fun journal(sequences: List<Long>, next: Long = (sequences.lastOrNull() ?: -1) + 1, text: String = "fixture"): ByteArray = buildJsonObject {
        put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", next)
        put("queueDropped", 0); put("historyDropped", 0); put("truncated", false)
        put("events", buildJsonArray { sequences.forEach { seq -> add(buildJsonObject {
            put("sequence", seq); put("runId", "writer_fixture"); put("workflow", "reconstruct")
            put("time", "2026-09-05T00:00:00Z"); put("kind", "message"); put("text", text)
        }) } })
    }.toString().toByteArray()
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

    @Test fun `cursors reject cross session job attempt and tampering`() {
        val pages = WebProgressPages(); val bytes = journal(listOf(0, 1))
        val token = cursor(page(pages, bytes, "limit=1"))
        for ((owner, job, run) in listOf(Triple("other", "job", "attempt"), Triple("owner", "other", "attempt"), Triple("owner", "job", "other"))) {
            assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { pages.page(owner, job, run, bytes, "cursor=$token") }.code)
        }
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { page(pages, bytes, "cursor=${token.dropLast(1)}${if (token.last() == 'a') 'b' else 'a'}") }.code)
        assertEquals("PROGRESS_GAP", assertFailsWith<WebAccessDenied> { page(WebProgressPages(), bytes, "cursor=$token") }.code)
    }

    @Test fun `missing changed interior and trailing boundaries report explicit gaps`() {
        val pages = WebProgressPages(); val token = cursor(page(pages, journal(listOf(0, 1)), "limit=1"))
        for (bytes in listOf(journal(listOf(1, 2)), journal(listOf(0, 1), text = "changed"), journal(listOf(0, 2)), journal(listOf(0), next = 2))) {
            assertEquals("PROGRESS_GAP", assertFailsWith<WebAccessDenied> { page(pages, bytes, "cursor=$token") }.code)
        }
        assertEquals("PROGRESS_GAP", assertFailsWith<WebAccessDenied> { page(pages, journal(listOf(5, 6))) }.code)
        assertEquals("PROGRESS_GAP", assertFailsWith<WebAccessDenied> { page(pages, journal(emptyList(), next = 3)) }.code)
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
}
