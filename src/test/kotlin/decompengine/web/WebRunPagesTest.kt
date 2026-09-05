package decompengine.web

import decompengine.jobs.*
import kotlinx.serialization.json.*
import java.time.Instant
import kotlin.test.*

class WebRunPagesTest {
    private val jobId = "a".repeat(32)
    private fun snapshot(count: Int): WorkflowJobSnapshot {
        val at = Instant.parse("2026-09-05T00:00:00Z")
        return WorkflowJobSnapshot(jobId, "version_1", LegacyWorkflowObservation("a".repeat(64), "uploaded", false),
            (0 until count).map { index -> WorkflowAttempt("run_$index", jobId, WorkflowKind.EXPLORE,
                WorkflowRunState.COMPLETED, "version_$index", at, at, at, null, null, null,
                WorkflowExecutionLimits(1000u, 1000u, 1024u, 0u), WorkflowTerminalReason.COMPLETED, null, null, null) }, null)
    }
    @Test fun `pages all 1024 attempts newest first without duplication and replays stable pages`() {
        val source = snapshot(1024)
        val pages = WebRunPages { source }
        val seen = mutableListOf<String>()
        var cursor: String? = null
        do {
            val query = "limit=200" + (cursor?.let { "&cursor=$it" } ?: "")
            val result = pages.page("owner", jobId, query)
            assertEquals(result, pages.page("owner", jobId, query))
            val items = result.getValue("items").jsonArray
            assertTrue(items.size <= 200)
            seen += items.map { it.jsonObject.getValue("runId").jsonPrimitive.content }
            cursor = result.getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.contentOrNull
        } while (cursor != null)
        assertEquals((0 until 1024).reversed().map { "run_$it" }, seen)
    }
    @Test fun `continuations bind session job page size and version with explicit expiry`() {
        var source = snapshot(60)
        val pages = WebRunPages { id -> source.copy(jobId = id, attempts = source.attempts.map { it.copy(jobId = id) }) }
        val first = pages.page("owner", jobId, null)
        val cursor = first.getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.content
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { pages.page("other", jobId, "cursor=$cursor") }.code)
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { pages.page("owner", "b".repeat(32), "cursor=$cursor") }.code)
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { pages.page("owner", jobId, "cursor=$cursor&limit=25") }.code)
        source = source.copy(version = "version_2")
        assertEquals("CURSOR_EXPIRED", assertFailsWith<WebAccessDenied> { pages.page("owner", jobId, "cursor=$cursor") }.code)
        assertEquals(50, pages.page("owner", jobId, null).getValue("items").jsonArray.size)
    }
    @Test fun `empty and invalid query pages are explicit`() {
        val pages = WebRunPages { snapshot(0) }
        assertTrue(pages.page("owner", jobId, null).getValue("items").jsonArray.isEmpty())
        for (query in listOf("limit=201", "limit=1&limit=2", "search=", "cursor=bad", "unknown=x")) {
            assertFailsWith<WebAccessDenied> { pages.page("owner", jobId, query) }
        }
    }
}
