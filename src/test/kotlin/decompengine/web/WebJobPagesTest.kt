package decompengine.web

import kotlinx.serialization.json.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.*

class WebJobPagesTest {
    private fun row(id: String, name: String = "sample.elf", status: String = "uploaded", date: String = "2026-09-05T00:00:00Z") = buildJsonObject {
        put("jobId", id); put("displayFilename", name); put("status", status); put("createdAt", date)
    }
    private fun cursor(page: JsonObject) = page.getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.content
    private fun ids(page: JsonObject) = page.getValue("items").jsonArray.map { it.jsonObject.getValue("jobId").jsonPrimitive.content }

    @Test fun `retained pages replay stable rows across concurrent inserts updates and deletions`() {
        val records = mutableListOf(row("b"), row("a"), row("c"))
        var scans = 0
        val pages = WebJobPages({ scans++; records.asSequence() })
        val query = WebJobQuery(limit = 1)
        val first = pages.page("owner", query, null)
        records.clear(); records += row("z")
        val second = pages.page("owner", query, cursor(first))
        assertEquals(listOf("c"), ids(first)); assertEquals(listOf("b"), ids(second))
        assertEquals(second, pages.page("owner", query, cursor(first)))
        assertEquals(listOf("a"), ids(pages.page("owner", query, cursor(second))))
        assertEquals(1, scans)
        assertEquals(listOf("z"), ids(pages.page("owner", query, null)))
    }

    @Test fun `cursor binds session normalized filters limit signature and expiry`() {
        var clock = 0L
        val pages = WebJobPages({ sequenceOf(row("a"), row("b")) }, { clock })
        val query = WebJobQuery(limit = 1)
        val token = cursor(pages.page("owner", query, null))
        for ((owner, filter, candidate) in listOf(Triple("other", query, token), Triple("owner", query.copy(search = "other"), token),
            Triple("owner", query.copy(sort = "oldest"), token), Triple("owner", query.copy(limit = 2), token), Triple("owner", query, token + "x"))) {
            assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { pages.page(owner, filter, candidate) }.code)
        }
        clock = 120_000_000_001
        assertEquals(410, assertFailsWith<WebAccessDenied> { pages.page("owner", query, token) }.status)
    }

    @Test fun `strict filters sort instants and apply inclusive after exclusive before`() {
        val (query, _) = WebJobQuery.parse("search=SAMple&status=uploaded&createdAfter=2026-09-05T00%3A00%3A00Z&createdBefore=2026-09-06T00%3A00%3A00Z&limit=200")
        val pages = WebJobPages({ sequenceOf(row("a"), row("b", date = "2026-09-05T02:00:00+01:00"),
            row("c", status = "failed"), row("d", name = "other.elf"), row("e", date = "2026-09-06T00:00:00Z")) })
        assertEquals(listOf("b", "a"), ids(pages.page("owner", query, null)))
        listOf("sort=wrong", "sort=oldest&sort=newest", "limit=0", "limit=201", "limit=01", "limit=1&limit=2", "unknown=value", "status=bogus", "search=%FF", "search=%00",
            "createdAfter=wrong", "createdAfter=2026-09-06T00:00:00Z&createdBefore=2026-09-05T00:00:00Z", "search=" + "x".repeat(257))
            .forEach { invalid -> assertEquals(422, assertFailsWith<WebAccessDenied>(invalid) { WebJobQuery.parse(invalid) }.status) }
    }

    @Test fun `oldest first sorts by instant then identity and pages the same snapshot`() {
        val (query, _) = WebJobQuery.parse("sort=oldest&limit=2")
        val pages = WebJobPages({ sequenceOf(row("b"), row("a"), row("c", date = "2026-09-05T00:00:01Z")) })
        val first = pages.page("owner", query, null)
        assertEquals(listOf("a", "b"), ids(first))
        assertEquals(listOf("c"), ids(pages.page("owner", query, cursor(first))))
    }

    @Test fun `nanosecond date ranges retain inclusive and exclusive boundaries across offsets`() {
        val (query, _) = WebJobQuery.parse("createdAfter=2026-09-05T00%3A00%3A00.000000001Z&createdBefore=2026-09-05T09%3A00%3A00.000000003%2B09%3A00")
        val pages = WebJobPages({ sequenceOf(
            row("before", date = "2026-09-05T00:00:00Z"),
            row("inclusive", date = "2026-09-05T00:00:00.000000001Z"),
            row("inside", date = "2026-09-05T00:00:00.000000002Z"),
            row("exclusive", date = "2026-09-05T00:00:00.000000003Z"),
        ) })
        assertEquals(listOf("inside", "inclusive"), ids(pages.page("owner", query, null)))
    }

    @Test fun `ten thousand row library is bounded and evicted cursors expire explicitly`() {
        val pages = WebJobPages({ (1..10_000).asSequence().map { row(it.toString().padStart(8, '0')) } })
        val query = WebJobQuery(limit = 200)
        val first = pages.page("owner", query, null)
        assertEquals(200, ids(first).size)
        repeat(8) { pages.page("owner", query, null) }
        assertEquals("CURSOR_EXPIRED", assertFailsWith<WebAccessDenied> { pages.page("owner", query, cursor(first)) }.code)
        val tooMany = WebJobPages({ (1..10_001).asSequence().map { row(it.toString()) } })
        assertEquals("LISTING_LIMIT", assertFailsWith<WebAccessDenied> { tooMany.page("owner", query, null) }.code)
    }

    @Test fun `row and scan time ceilings fail explicitly before returning partial results`() {
        val oversized = WebJobPages({ sequenceOf(row("a", "x".repeat(4096))) })
        assertEquals("JOB_RECORD_UNAVAILABLE", assertFailsWith<WebAccessDenied> { oversized.page("owner", WebJobQuery(), null) }.code)
        var time = 0L
        val slow = WebJobPages({ sequence { yield(row("a")); time = 6_000_000_000L; yield(row("b")) } }, { time })
        assertEquals("LISTING_LIMIT", assertFailsWith<WebAccessDenied> { slow.page("owner", WebJobQuery(), null) }.code)
    }

    @Test fun `slow snapshot collection rejects competing admission without holding continuation lock`() {
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        var block = false
        val pages = WebJobPages({ sequence {
            if (block) { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)) }
            yield(row("a")); yield(row("b"))
        } })
        val query = WebJobQuery(limit = 1)
        val first = pages.page("owner", query, null)
        block = true
        val pool = Executors.newSingleThreadExecutor()
        try {
            val task = pool.submit<JsonObject> { pages.page("owner", query, null) }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            assertEquals("LISTING_BUSY", assertFailsWith<WebAccessDenied> { pages.page("owner", query, null) }.code)
            assertEquals(listOf("a"), ids(pages.page("owner", query, cursor(first))))
            release.countDown(); task.get(5, TimeUnit.SECONDS)
        } finally { release.countDown(); pool.shutdownNow() }
    }
}
