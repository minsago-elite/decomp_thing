package decompengine.web

import kotlinx.serialization.json.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.security.MessageDigest
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

class WebJobPagesTest {
    private fun row(id: String, name: String = "sample.elf", status: String = "uploaded", date: String = "2026-09-05T00:00:00Z") = buildJsonObject {
        put("jobId", id); put("displayFilename", name); put("status", status); put("createdAt", date)
    }
    private fun cursor(page: JsonObject) = page.getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.content
    private fun ids(page: JsonObject) = page.getValue("items").jsonArray.map { it.jsonObject.getValue("jobId").jsonPrimitive.content }
    private fun idDigest(vararg ids: String): String = MessageDigest.getInstance("SHA-256").run {
        ids.sorted().forEach { update(it.toByteArray(StandardCharsets.UTF_8)); update(0.toByte()) }
        digest().joinToString("") { "%02x".format(it) }
    }

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
        val firstInfo = first.getValue("page").jsonObject
        val secondInfo = second.getValue("page").jsonObject
        val firstToken = firstInfo.getValue("currentCursor").jsonPrimitive.content
        assertEquals(firstToken, secondInfo.getValue("previousCursor").jsonPrimitive.content)
        assertEquals(first, pages.page("owner", query, firstToken))
        assertEquals(first, pages.page("owner", query, secondInfo.getValue("previousCursor").jsonPrimitive.content))
        assertEquals(1, firstInfo.getValue("pageNumber").jsonPrimitive.int)
        assertEquals(2, secondInfo.getValue("pageNumber").jsonPrimitive.int)
        assertEquals(JsonNull, firstInfo.getValue("previousCursor"))
        assertEquals(1, scans)
        assertEquals(listOf("z"), ids(pages.page("owner", query, null)))
    }

    @Test fun `a deletion during collection is never published through a new snapshot`() {
        val records = mutableListOf(row("b"), row("a"))
        var scans = 0
        lateinit var pages: WebJobPages
        pages = WebJobPages({
            scans++
            val rows = records.toList()
            sequence {
                for ((index, item) in rows.withIndex()) {
                    yield(item)
                    // The first scan has already collected "b" when another request deletes it.
                    if (scans == 1 && index == 0) { records.removeAt(0); pages.invalidate() }
                }
            }
        })
        val page = pages.page("owner", WebJobQuery(limit = 1), null)
        assertEquals(2, scans, "the stale collection is discarded and the library read again")
        assertEquals(listOf("a"), ids(page))
        assertEquals(JsonNull, page.getValue("page").jsonObject.getValue("nextCursor"))
    }

    @Test fun `continuous invalidation ends in a bounded busy refusal`() {
        lateinit var pages: WebJobPages
        pages = WebJobPages({ sequence { yield(row("a")); pages.invalidate() } })
        val refusal = assertFailsWith<WebAccessDenied> { pages.page("owner", WebJobQuery(), null) }
        assertEquals(503, refusal.status); assertEquals("LISTING_BUSY", refusal.code)
    }

    @Test fun `pending deletion resumes rotate past the last attempted operation`() {
        val pending = listOf("jobdel_b", "jobdel_a", "jobdel_c")
        assertEquals("jobdel_a", nextPendingDeletion(pending, null))
        assertEquals("jobdel_b", nextPendingDeletion(pending, "jobdel_a"))
        assertEquals("jobdel_c", nextPendingDeletion(pending, "jobdel_b"))
        assertEquals("jobdel_a", nextPendingDeletion(pending, "jobdel_c"), "wraps instead of starving later operations")
        assertEquals("jobdel_c", nextPendingDeletion(listOf("jobdel_a", "jobdel_c"), "jobdel_b"))
        assertNull(nextPendingDeletion(emptyList(), "jobdel_a"))
    }

    @Test fun `generation-bound collection image reuses source rows and refreshes without changing old cursors`() {
        var generation = 7L
        var sourceRows = listOf(row("a"), row("b"), row("c"))
        var stamp = WebJobCollectionStamp("first", idDigest("a", "b", "c"), cacheable = true)
        var scans = 0
        val pages = WebJobPages({ scans++; sourceRows.asSequence() }, collectionVersion = { generation },
            collectionStamp = { _, _ -> stamp })
        val query = WebJobQuery(limit = 1)
        val first = pages.page("owner", query, null)
        assertEquals(listOf("c"), ids(first))
        assertEquals(listOf("c"), ids(pages.page("owner", query, null)))
        assertEquals(1, scans)

        sourceRows = listOf(row("z"))
        generation++
        stamp = WebJobCollectionStamp("second", idDigest("z"), cacheable = true)
        val refreshed = pages.page("owner", query, null)
        assertEquals(listOf("z"), ids(refreshed))
        assertEquals(2, scans)
        assertEquals(listOf("b"), ids(pages.page("owner", query, cursor(first))))
    }

    @Test fun `startup collection seed is adopted once and still revalidates external storage changes`() {
        var generation = 11L
        var currentRows = listOf(row("a", date = "2026-09-01T00:00:00Z"),
            row("b", date = "2026-09-02T00:00:00Z"), row("c", date = "2026-09-03T00:00:00Z"))
        fun collectionRows() = currentRows.map { item ->
            val id = item.getValue("jobId").jsonPrimitive.content
            val bytes = item.toString().toByteArray(StandardCharsets.UTF_8).size
            WebJobCollectionRow(item, java.time.Instant.parse(item.getValue("createdAt").jsonPrimitive.content), id, bytes)
        }
        fun stamp() = WebJobCollectionStamp("stamp-${currentRows.size}-${currentRows.last().getValue("jobId")}",
            idDigest(*currentRows.map { it.getValue("jobId").jsonPrimitive.content }.toTypedArray()), cacheable = true)
        val startupRows = collectionRows()
        val startupStamp = stamp()
        val seed = WebJobCollectionSeed(11, startupStamp, startupRows, startupRows.sumOf { it.bytes.toLong() } + startupStamp.retainedBytes)
        var seedReads = 0
        var scans = 0
        val pages = WebJobPages({ scans++; currentRows.asSequence() }, collectionVersion = { generation },
            collectionStamp = { _, _ -> stamp() }, collectionSeed = { seedReads++; seed.takeIf { seedReads == 1 } })

        assertEquals(listOf("c"), ids(pages.page("owner", WebJobQuery(limit = 1), null)))
        assertEquals(0, scans)
        assertEquals(1, seedReads)
        val filtered = pages.page("owner", WebJobQuery(search = "sample", sort = "oldest", limit = 2), null)
        assertEquals(listOf("a", "b"), ids(filtered))
        assertEquals(0, scans)

        currentRows = listOf(row("z"))
        val refreshedStamp = stamp()
        // Keep the version stable to exercise the persisted input stamp rather than the service generation.
        assertNotEquals(startupStamp.digest, refreshedStamp.digest)
        assertEquals(listOf("z"), ids(pages.page("owner", WebJobQuery(), null)))
        assertEquals(1, scans)
        assertEquals(11, generation)
    }

    @Test fun `filesystem stamp invalidates a quiescent image even when service generation is unchanged`() {
        var stamp = WebJobCollectionStamp("first", idDigest("a"), cacheable = true)
        var rows = listOf(row("a"))
        var scans = 0
        val pages = WebJobPages({ scans++; rows.asSequence() }, collectionVersion = { 3L },
            collectionStamp = { _, _ -> stamp })
        val query = WebJobQuery()
        assertEquals(listOf("a"), ids(pages.page("owner", query, null)))
        assertEquals(listOf("a"), ids(pages.page("owner", query, null)))
        assertEquals(1, scans)

        rows = listOf(row("b"))
        stamp = WebJobCollectionStamp("second", idDigest("b"), cacheable = true)
        assertEquals(listOf("b"), ids(pages.page("owner", query, null)))
        assertEquals(2, scans)
    }

    @Test fun `warm image stamp is serialized by listing admission`() {
        val stampCalls = AtomicInteger()
        val blockNextStamp = AtomicBoolean(false)
        val stampEntered = CountDownLatch(1)
        val releaseStamp = CountDownLatch(1)
        val stableStamp = WebJobCollectionStamp("stable", idDigest("a"), cacheable = true)
        val pages = WebJobPages({ sequenceOf(row("a")) }, collectionVersion = { 1L }, collectionStamp = { _, _ ->
            stampCalls.incrementAndGet()
            if (blockNextStamp.compareAndSet(true, false)) {
                stampEntered.countDown()
                assertTrue(releaseStamp.await(5, TimeUnit.SECONDS), "the test must release the admitted stamp")
            }
            stableStamp
        })
        val query = WebJobQuery()
        assertEquals(listOf("a"), ids(pages.page("owner", query, null))) // Populate the reusable image.
        val beforeWarmHit = stampCalls.get()
        assertEquals(2, beforeWarmHit, "a cold image is bracketed by two storage stamps")

        val callers = Executors.newFixedThreadPool(2)
        try {
            blockNextStamp.set(true)
            val admitted = callers.submit<JsonObject> { pages.page("owner", query, null) }
            assertTrue(stampEntered.await(5, TimeUnit.SECONDS), "the warm hit must stamp storage while holding admission")

            val refusal = assertFailsWith<WebAccessDenied> { pages.page("owner", query, null) }
            assertEquals("LISTING_BUSY", refusal.code)
            assertEquals(beforeWarmHit + 1, stampCalls.get(), "a competing first-page request must not start another full stamp")

            releaseStamp.countDown()
            assertEquals(listOf("a"), ids(admitted.get(5, TimeUnit.SECONDS)))
        } finally {
            releaseStamp.countDown()
            callers.shutdownNow()
            assertTrue(callers.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test fun `filesystem changes during a cold collection prevent publishing a mixed image`() {
        var stamp = WebJobCollectionStamp("before", idDigest("a"), cacheable = true)
        var scans = 0
        val pages = WebJobPages({
            scans++
            if (scans == 1) stamp = WebJobCollectionStamp("after", idDigest("b"), cacheable = true)
            sequenceOf(row(if (scans == 1) "b" else "b"))
        }, collectionVersion = { 1L }, collectionStamp = { _, _ -> stamp })

        assertEquals(listOf("b"), ids(pages.page("owner", WebJobQuery(), null)))
        assertEquals(listOf("b"), ids(pages.page("owner", WebJobQuery(), null)))
        assertEquals(2, scans, "The first cold scan crossed a storage-stamp change and must not be cached")
    }

    @Test fun `expired snapshot admission does not retain a newly collected image`() {
        var time = 0L
        var stampCalls = 0
        var scans = 0
        val pages = WebJobPages({ scans++; sequenceOf(row("a")) }, now = { time }, collectionVersion = { 1L },
            collectionStamp = { _, checkpoint ->
                checkpoint()
                if (++stampCalls == 1) time += 5_000_000_001L
                WebJobCollectionStamp("stamp", "ids", cacheable = true)
            })
        assertEquals("LISTING_LIMIT", assertFailsWith<WebAccessDenied> { pages.page("owner", WebJobQuery(), null) }.code)
        time = 6_000_000_000L
        assertEquals(listOf("a"), ids(pages.page("owner", WebJobQuery(), null)))
        assertEquals(2, scans)
    }

    @Test fun `collection invalidation retries retain the original request deadline`() {
        var time = 0L
        var generation = 1L
        var stamps = 0
        var scans = 0
        val stamp = WebJobCollectionStamp("stable", idDigest("a"), cacheable = true)
        lateinit var pages: WebJobPages
        pages = WebJobPages({ scans++; sequenceOf(row("a")) }, now = { time },
            collectionVersion = { generation }, collectionStamp = { _, checkpoint ->
                checkpoint()
                when (++stamps) {
                    1 -> { time = 4_500_000_000L; generation++; pages.invalidate() }
                    2 -> time = 5_000_000_001L
                }
                stamp
            })

        val failure = assertFailsWith<WebAccessDenied> { pages.page("owner", WebJobQuery(), null) }
        assertEquals("LISTING_LIMIT", failure.code)
        assertEquals(2, scans, "the retry starts within the remaining original allowance, then expires")
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
        val firstToken = pages.page("owner", query, token).getValue("page").jsonObject.getValue("previousCursor").jsonPrimitive.content
        for ((owner, filter, candidate) in listOf(Triple("other", query, firstToken),
            Triple("owner", query.copy(search = "other"), firstToken), Triple("owner", query.copy(limit = 2), firstToken),
            Triple("owner", query, firstToken + "x"))) {
            assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { pages.page(owner, filter, candidate) }.code)
        }
        clock = 120_000_000_001
        assertEquals(410, assertFailsWith<WebAccessDenied> { pages.page("owner", query, firstToken) }.status)
        assertEquals(410, assertFailsWith<WebAccessDenied> { pages.page("owner", query, token) }.status)
    }

    @Test fun `strict filters sort instants and apply inclusive after exclusive before`() {
        val (query, _) = WebJobQuery.parse("search=SAMple&status=uploaded&createdAfter=2026-09-05T00%3A00%3A00Z&createdBefore=2026-09-06T00%3A00%3A00Z&limit=200")
        val pages = WebJobPages({ sequenceOf(row("a"), row("b", date = "2026-09-05T02:00:00+01:00"),
            row("c", status = "failed"), row("d", name = "other.elf"), row("e", date = "2026-09-06T00:00:00Z")) })
        assertEquals(listOf("b", "a"), ids(pages.page("owner", query, null)))
        val emptyQuery = query.copy(search = "no-matching-name")
        val empty = pages.page("owner", emptyQuery, null)
        val emptyInfo = empty.getValue("page").jsonObject
        assertTrue(ids(empty).isEmpty())
        assertEquals(JsonNull, emptyInfo.getValue("previousCursor"))
        assertEquals(JsonNull, emptyInfo.getValue("nextCursor"))
        assertEquals(1, emptyInfo.getValue("pageNumber").jsonPrimitive.int)
        assertEquals(empty, pages.page("owner", emptyQuery, emptyInfo.getValue("currentCursor").jsonPrimitive.content))
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
