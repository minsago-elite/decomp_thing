package decompengine.web

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.jobs.*
import decompengine.repair.StableFileDigest
import kotlinx.serialization.json.*
import java.time.Instant
import kotlin.test.*

/** In-memory attempts and byte arrays only. No store, listener or workflow is opened. */
class WebArtifactCatalogTest {
    private val jobId = "a".repeat(32)
    private val limits = WorkflowExecutionLimits(1000u, 1000u, 1024u, 0u)

    private fun attempt(runId: String, minute: Long, revision: String? = null) = WorkflowAttempt(runId, jobId, WorkflowKind.RECONSTRUCT,
        WorkflowRunState.COMPLETED, "version_$runId", Instant.ofEpochSecond(minute * 60), Instant.ofEpochSecond(minute * 60),
        Instant.ofEpochSecond(minute * 60 + 1), null, null, null, limits, WorkflowTerminalReason.COMPLETED, null,
        revision?.let { WorkflowCandidate(it, "d".repeat(64)) }, null)

    private class Store(var attempts: List<WorkflowAttempt>, val files: MutableMap<Pair<String, String>, ByteArray>) : WebArtifactStore {
        var hashedBytes = 0L
        val failing = mutableSetOf<Pair<String, String>>()
        var commitments: (String) -> Pair<String, String>? = { null }
        override fun attempts(jobId: String) = attempts
        override fun present(jobId: String, runId: String, path: String) = (runId to path) in files
        override fun stream(jobId: String, runId: String, path: String, declaredSize: (Long) -> Unit,
            consume: (ByteArray, Int) -> Unit, cancellationCheck: () -> Unit): StableFileDigest {
            val bytes = files[runId to path] ?: throw JobStoreException("artifact is unavailable")
            declaredSize(bytes.size.toLong())
            if ((runId to path) in failing) throw IllegalArgumentException("stable hash file changed during reading")
            bytes.toList().chunked(4096).forEach { chunk -> cancellationCheck(); consume(chunk.toByteArray(), chunk.size) }
            hashedBytes += bytes.size
            return StableFileDigest(WebExplorationArtifact.sha256(bytes), bytes.size.toLong(),
                LinuxFileIdentity(LinuxFileKey(1, 1), 0x8180, 1000, 1000, 1, 1, true, false, false))
        }
        override fun revisionCommitments(jobId: String, runId: String, revisionId: String) = commitments(runId)
    }

    private fun items(page: JsonObject) = page.getValue("items").jsonArray.map { it.jsonObject }
    private fun next(page: JsonObject) = page.getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.contentOrNull
    private fun field(item: JsonObject, key: String) = item.getValue(key).jsonPrimitive.content

    @Test fun `catalog lists only fixed authorized families with exact size type digest and verification state`() {
        val manifest = "{\"manifest\":true}".toByteArray(); val contract = "{\"contract\":true}".toByteArray()
        val store = Store(listOf(attempt("run_b", 2, "revision_b"), attempt("run_a", 1)), mutableMapOf(
            ("run_a" to "exploration.json") to "{\"x\":1}".toByteArray(),
            ("run_a" to "agent-progress.json") to "{}".toByteArray(),
            ("run_b" to "source-tree/source_tree_manifest.json") to manifest,
            ("run_b" to "source-tree/reports/build_contract.json") to contract,
            ("run_b" to "source-tree.zip") to ByteArray(10_000) { it.toByte() },
            ("run_b" to "../escape") to "never".toByteArray(),
        ))
        store.commitments = { run -> if (run == "run_b") WebExplorationArtifact.sha256(manifest) to "f".repeat(64) else null }
        val catalog = WebArtifactCatalog(store)
        val page = catalog.page("session", jobId, null, "/nested/")
        val listed = items(page)
        // Attempts in creation order, then fixed family order; the stray path is never considered.
        assertEquals(listOf("exploration-report", "progress-journal", "source-manifest", "build-contract", "source-archive"), listed.map { field(it, "family") })
        assertEquals(listOf("run_a", "run_a", "run_b", "run_b", "run_b"), listed.map { it.getValue("binding").jsonObject.getValue("runId").jsonPrimitive.content })
        assertEquals(listOf(null, null, "revision_b", "revision_b", "revision_b"), listed.map { it.getValue("binding").jsonObject.getValue("revisionId").jsonPrimitive.contentOrNull })
        assertEquals(listOf("not-verified", "not-verified", "revision-commitment", "not-verified", "not-verified"), listed.map { field(it, "verification") })
        val archive = listed.last()
        assertEquals("10000", field(archive, "sizeBytes")); assertEquals("application/zip", field(archive, "mediaType"))
        assertEquals("archive", field(archive, "role")); assertEquals(WebExplorationArtifact.sha256(ByteArray(10_000) { it.toByte() }), field(archive, "sha256"))
        assertEquals("/nested/api/v1/jobs/$jobId/artifacts/${field(archive, "artifactId")}/content", field(archive, "contentHref"))
        assertNull(next(page)); assertEquals(0, page.getValue("unavailableFiles").jsonPrimitive.int)
        assertFalse(page.toString().contains("source-tree/") || page.toString().contains("escape"))
        // The exploration family keeps the identity used by the existing report descriptor.
        assertEquals(WebExplorationArtifact.descriptor(jobId, "run_a", "{\"x\":1}".toByteArray(), "/nested/").getValue("artifactId"), listed.first().getValue("artifactId"))
    }

    @Test fun `run and revision filters are validated together and restrict the families`() {
        val store = Store(listOf(attempt("run_a", 1), attempt("run_b", 2, "revision_b")), mutableMapOf(
            ("run_a" to "exploration.json") to "{}".toByteArray(), ("run_b" to "exploration.json") to "{}".toByteArray(),
            ("run_b" to "source-tree.zip") to "zip".toByteArray()))
        val catalog = WebArtifactCatalog(store)
        assertEquals(listOf("run_b", "run_b"), items(catalog.page("s", jobId, "runId=run_b", "/")).map { it.getValue("binding").jsonObject.getValue("runId").jsonPrimitive.content })
        val revision = catalog.page("s", jobId, "runId=run_b&revisionId=revision_b", "/")
        assertEquals(listOf("source-archive"), items(revision).map { field(it, "family") })
        assertEquals("revision_b", revision.getValue("binding").jsonObject.getValue("revisionId").jsonPrimitive.content)
        assertEquals(listOf("source-manifest", "build-contract", "source-archive"), revision.getValue("catalogedFamilies").jsonArray.map { it.jsonPrimitive.content })
        assertEquals("VALIDATION_FAILED", assertFailsWith<WebAccessDenied> { catalog.page("s", jobId, "revisionId=revision_b", "/") }.code)
        assertEquals("REVISION_NOT_FOUND", assertFailsWith<WebAccessDenied> { catalog.page("s", jobId, "runId=run_a&revisionId=revision_b", "/") }.code)
        assertEquals("RUN_NOT_FOUND", assertFailsWith<WebAccessDenied> { catalog.page("s", jobId, "runId=run_other", "/") }.code)
        for (query in listOf("path=reports/x", "runId=../x", "runId=a&runId=b", "limit=0", "limit=201", "limit=01", "runId=", "cursor"))
            assertEquals(422, assertFailsWith<WebAccessDenied>(query) { catalog.page("s", jobId, query, "/") }.status, query)
    }

    @Test fun `pages are bounded signed and expire when the attempt set changes`() {
        val attempts = (1..30).map { attempt("run_%02d".format(it), it.toLong()) }
        val store = Store(attempts, attempts.associate { (it.runId to "exploration.json") to "{\"run\":\"${it.runId}\"}".toByteArray() }.toMutableMap())
        val catalog = WebArtifactCatalog(store)
        val seen = mutableListOf<String>(); var cursor: String? = null; var pages = 0
        do {
            val page = catalog.page("s", jobId, "limit=7" + (cursor?.let { "&cursor=$it" } ?: ""), "/")
            assertTrue(items(page).size <= 7); seen += items(page).map { field(it, "artifactId") }; cursor = next(page); pages++
        } while (cursor != null)
        assertEquals(30, seen.size); assertEquals(30, seen.distinct().size); assertTrue(pages >= 5)
        val first = next(catalog.page("s", jobId, "limit=7", "/"))!!
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { catalog.page("other", jobId, "limit=7&cursor=$first", "/") }.code)
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { catalog.page("s", jobId, "limit=8&cursor=$first", "/") }.code)
        store.attempts = attempts + attempt("run_99", 99)
        assertEquals("CURSOR_EXPIRED", assertFailsWith<WebAccessDenied> { catalog.page("s", jobId, "limit=7&cursor=$first", "/") }.code)
    }

    @Test fun `page hash budget unreadable and oversized files are explicit and every page advances`() {
        val attempts = (1..4).map { attempt("run_$it", it.toLong()) }
        val store = Store(attempts, attempts.associate { (it.runId to "source-tree.zip") to ByteArray(6_000) }.toMutableMap())
        store.files["run_2" to "exploration.json"] = ByteArray(20_000)
        store.failing += "run_3" to "source-tree.zip"
        val catalog = WebArtifactCatalog(store, maximumArtifactBytes = 10_000, maximumPageHashBytes = 10_000)
        val first = catalog.page("s", jobId, null, "/")
        assertEquals(1, items(first).size); assertNotNull(next(first))
        val all = mutableListOf<JsonObject>(); var unavailable = 0; var cursor: String? = null
        do {
            val page = catalog.page("s", jobId, cursor?.let { "cursor=$it" }, "/")
            all += items(page); unavailable += page.getValue("unavailableFiles").jsonPrimitive.int; cursor = next(page)
        } while (cursor != null)
        // run_2's oversized exploration report and run_3's changing archive are counted, never listed.
        assertEquals(listOf("run_1", "run_2", "run_4"), all.map { it.getValue("binding").jsonObject.getValue("runId").jsonPrimitive.content })
        assertEquals(2, unavailable)
    }

    @Test fun `detail rehashes current bytes and distinguishes missing from changed artifacts`() {
        val store = Store(listOf(attempt("run_a", 1)), mutableMapOf(("run_a" to "exploration.json") to "{\"x\":1}".toByteArray()))
        val catalog = WebArtifactCatalog(store)
        val id = field(items(catalog.page("s", jobId, null, "/")).single(), "artifactId")
        assertEquals(id, field(catalog.detail(jobId, id, "/"), "artifactId"))
        assertEquals("NOT_FOUND", assertFailsWith<WebAccessDenied> { catalog.detail(jobId, id.replace("exploration_", "progress_"), "/") }.code)
        assertEquals("NOT_FOUND", assertFailsWith<WebAccessDenied> { catalog.detail(jobId, "exploration_${"0".repeat(32)}_${"0".repeat(64)}", "/") }.code)
        assertEquals("NOT_FOUND", assertFailsWith<WebAccessDenied> { catalog.detail(jobId, "unknown_${id.substringAfter('_')}", "/") }.code)
        store.files["run_a" to "exploration.json"] = "{\"x\":2}".toByteArray()
        assertEquals("ARTIFACT_CHANGED", assertFailsWith<WebAccessDenied> { catalog.detail(jobId, id, "/") }.code)
        store.files.clear()
        assertEquals("NOT_FOUND", assertFailsWith<WebAccessDenied> { catalog.detail(jobId, id, "/") }.code)
    }

    @Test fun `byte ranges follow single range semantics and refuse unsatisfiable requests`() {
        assertEquals(WebByteRange(0, 9), parseWebByteRange("bytes=0-9", 100))
        assertEquals(WebByteRange(90, 99), parseWebByteRange("bytes=90-", 100))
        assertEquals(WebByteRange(95, 99), parseWebByteRange("bytes=-5", 100))
        assertEquals(WebByteRange(0, 99), parseWebByteRange("bytes=-500", 100))
        assertEquals(WebByteRange(50, 99), parseWebByteRange("bytes=50-1000", 100))
        for (ignored in listOf("bytes=0-1,5-6", "items=0-1", "bytes=5-3", "bytes=a-b", "bytes=01-2", "bytes= 0-1x", "bytes=-"))
            assertNull(parseWebByteRange(ignored, 100), ignored)
        for (unsatisfiable in listOf("bytes=100-", "bytes=100-200", "bytes=-0"))
            assertFailsWith<WebRangeNotSatisfiable>(unsatisfiable) { parseWebByteRange(unsatisfiable, 100) }
        assertFailsWith<WebRangeNotSatisfiable> { parseWebByteRange("bytes=0-0", 0) }
    }

    @Test fun `request deadlines renew only with progress and never beyond the absolute lifetime`() {
        val scheduler = java.util.concurrent.ScheduledThreadPoolExecutor(1)
        try {
            var now = 0L; var closed = 0
            val deadline = WebRequestDeadline(scheduler, AutoCloseable { closed++ }, 60_000, idleMs = 60_000, maximumMs = 90_000, nanoTime = { now })
            now += 500_000_000; deadline.renew() // Coalesced: less than one second since the last renewal.
            now += 80_000_000_000; deadline.renew()
            assertFalse(deadline.expired)
            now += 20_000_000_000; deadline.renew() // Beyond the absolute lifetime: no further extension.
            deadline.cancel(); assertEquals(0, closed)
            val quick = WebRequestDeadline(scheduler, AutoCloseable { closed++ }, 1)
            val stop = System.nanoTime() + 5_000_000_000
            while (!quick.expired && System.nanoTime() < stop) Thread.onSpinWait()
            assertTrue(quick.expired)
            val waitClose = System.nanoTime() + 5_000_000_000
            while (closed == 0 && System.nanoTime() < waitClose) Thread.onSpinWait()
            assertEquals(1, closed)
        } finally { scheduler.shutdownNow() }
    }

    @Test fun `download admission is bounded per server and session and always released`() {
        val downloads = WebArtifactDownloads(maximum = 2, perSession = 1)
        downloads.admit("a") {
            assertEquals("DOWNLOAD_LIMIT", assertFailsWith<WebAccessDenied> { downloads.admit("a") {} }.code)
            downloads.admit("b") {
                assertEquals(429, assertFailsWith<WebAccessDenied> { downloads.admit("c") {} }.status)
            }
        }
        assertFailsWith<IllegalStateException> { downloads.admit("a") { error("client aborted") } }
        assertEquals(0, downloads.activeCount())
        downloads.admit("a") { assertEquals(1, downloads.activeCount()) }
    }
}
