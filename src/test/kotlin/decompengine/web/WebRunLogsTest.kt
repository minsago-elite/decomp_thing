package decompengine.web

import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.WorkflowAttempt
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowJobInspection
import decompengine.jobs.WorkflowKind
import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import kotlin.io.path.createTempDirectory
import kotlin.test.*
import kotlinx.serialization.json.*

class WebRunLogsTest {
    private val root = Path.of("/srv/decomp-private-store")
    private val logs = WebRunLogs(WebLogRedaction(mapOf("job-store" to root)))
    private val sha = "a".repeat(64)

    private fun attempt(): Pair<String, WorkflowAttempt> {
        val parent = Files.createDirectories(Path.of("build/test-tmp/web-run-logs").toAbsolutePath())
        val directory = createTempDirectory(parent, "logs-")
        val job = JobStore(directory).createFromUpload("log.elf", elfFixture())
        return WorkflowAttemptStore.open(directory).use { owner ->
            val snapshot = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            job.id to owner.create(job.id, snapshot.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
        }.also { directory.toFile().deleteRecursively() }
    }

    @Test fun `queries are strict bounded and searches are literal`() {
        assertEquals(WebRunLogs.Query(1, false, 200, null), logs.parseQuery(null))
        assertEquals(WebRunLogs.Query(null, true, 50, null), logs.parseQuery("tail=true&limit=50"))
        assertEquals(WebRunLogs.Query(7, false, 500, "(a+)+\$"), logs.parseQuery("fromLine=7&limit=500&search=%28a%2B%29%2B%24"))
        for (invalid in listOf("tail=true&fromLine=2", "limit=501", "limit=0", "fromLine=0", "tail=yes", "search=", "search=a%0Ab",
            "search=" + "x".repeat(129), "regex=a", "limit=1&limit=2", "fromLine=1e3")) {
            assertEquals("VALIDATION_FAILED", assertFailsWith<WebAccessDenied>(invalid) { logs.parseQuery(invalid) }.code)
        }
    }

    @Test fun `lines are decoded redacted and rendered inert`() {
        val pair = charArrayOf(0xd83d.toChar(), 0xde00.toChar()).concatToString()
        val text = "cc -c $root/module.c\r\n" + "\u001b[31merror\u001b[0m <script>x</script>\n" +
            "spoof ‮exe.txt\n" + "x".repeat(4095) + pair + "tail\n"
        val bytes = text.toByteArray() + byteArrayOf(0xff.toByte(), 0x41)
        val capture = logs.capture(bytes, sha)
        assertEquals(5, capture.totalLines)
        val lines = capture.allLines()
        assertEquals("cc -c [job-store]/module.c", lines[0].text); assertTrue(lines[0].redacted)
        assertEquals("\\e[31merror\\e[0m <script>x</script>", lines[1].text)
        assertEquals("spoof \\u202eexe.txt", lines[2].text)
        // A cut never splits a surrogate pair.
        assertTrue(lines[3].truncated); assertEquals(4095, lines[3].text.length)
        assertTrue(lines[4].replaced); assertEquals("�A", lines[4].text)
        assertEquals(1, capture.redactedLines)
    }

    @Test fun `ranges enforce line and byte budgets with explicit markers`() {
        val (jobId, run) = attempt()
        val now = Instant.parse("2026-09-05T00:00:00Z")
        val capture = logs.capture((1..1000).joinToString("\n") { "line $it error" }.toByteArray(), sha)
        val tail = logs.range(jobId, run, capture, false, logs.parseQuery("tail=true"), now)
        val window = tail.getValue("range").jsonObject
        assertEquals("801", window.getValue("firstLine").jsonPrimitive.content)
        assertEquals("200", window.getValue("lineCount").jsonPrimitive.content)
        assertTrue(window.getValue("truncatedBefore").jsonPrimitive.boolean); assertFalse(window.getValue("truncatedAfter").jsonPrimitive.boolean)
        assertEquals(run.runId, tail.getValue("runId").jsonPrimitive.content)
        assertEquals("generated-build-log", tail.getValue("source").jsonPrimitive.content)
        assertEquals(sha, tail.getValue("sourceSha256").jsonPrimitive.content)
        val past = logs.range(jobId, run, capture, false, logs.parseQuery("fromLine=5000"), now).getValue("range").jsonObject
        assertEquals("1001", past.getValue("firstLine").jsonPrimitive.content); assertEquals("0", past.getValue("lineCount").jsonPrimitive.content)
        val search = logs.range(jobId, run, capture, false, logs.parseQuery("limit=1&search=error"), now).getValue("search").jsonObject
        assertEquals("1000", search.getValue("matchCount").jsonPrimitive.content)
        assertEquals(200, search.getValue("matches").jsonArray.size); assertTrue(search.getValue("matchesTruncated").jsonPrimitive.boolean)
        assertEquals("whole-log", search.getValue("scope").jsonPrimitive.content)

        val wide = logs.capture((1..500).joinToString("\n") { "y".repeat(4096) }.toByteArray(), sha)
        val limited = logs.range(jobId, run, wide, false, logs.parseQuery("limit=500"), now)
        val limitedWindow = limited.getValue("range").jsonObject
        assertTrue(limitedWindow.getValue("byteLimited").jsonPrimitive.boolean)
        assertTrue(limited.toString().toByteArray().size < 300 * 1024)
        assertTrue(limitedWindow.getValue("lineCount").jsonPrimitive.int in 1 until 500)
        // A byte-limited tail still ends at the final line instead of stopping partway through its window.
        val newest = logs.range(jobId, run, wide, false, logs.parseQuery("tail=true&limit=200"), now)
        val newestWindow = newest.getValue("range").jsonObject
        assertEquals("500", newest.getValue("lines").jsonArray.last().jsonObject.getValue("number").jsonPrimitive.content)
        assertFalse(newestWindow.getValue("truncatedAfter").jsonPrimitive.boolean)
        assertTrue(newestWindow.getValue("byteLimited").jsonPrimitive.boolean)
        assertEquals(500 - newestWindow.getValue("lineCount").jsonPrimitive.int + 1, newestWindow.getValue("firstLine").jsonPrimitive.int)

        val missing = logs.range(jobId, run, null, false, logs.parseQuery(null), now)
        assertEquals("missing", missing.getValue("state").jsonPrimitive.content); assertFalse("lines" in missing)
        assertEquals("oversized", logs.range(jobId, run, null, true, logs.parseQuery(null), now).getValue("state").jsonPrimitive.content)
    }

    @Test fun `downloads share the live redaction and carry provenance`() {
        val (jobId, run) = attempt()
        val capture = logs.capture("first $root/a.c\n\u001b[1mbold\n".toByteArray(), sha)
        val live = logs.range(jobId, run, capture, false, logs.parseQuery(null), Instant.EPOCH).getValue("lines").jsonArray
            .map { it.jsonObject.getValue("text").jsonPrimitive.content }
        val download = logs.download(jobId, run, capture, Instant.EPOCH).decodeToString()
        assertFalse(download.contains(root.toString())); assertFalse(download.contains("\u001b"))
        assertTrue(download.endsWith(live.joinToString("\n", postfix = "\n")))
        for (expected in listOf(jobId, run.runId, sha, "web-log-v1", "redacted lines 1", "exported 1970-01-01T00:00:00Z")) {
            assertTrue(download.contains(expected), expected)
        }
    }
}
