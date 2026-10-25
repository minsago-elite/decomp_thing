package decompengine.web

import decompengine.jobs.AgentProgressJournal
import decompengine.jobs.JobStore
import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowJobInspection
import decompengine.jobs.WorkflowKind
import decompengine.jobs.elfFixture
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Upload cleanup, snapshot-bound pagination and read limits through the real v1 listener. Failed uploads
 * leave no staging entry and no job; continuations stay inside their captured snapshot and selection.
 */
class WebBoundedReadsHttpTest {
    private val root: Path = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp")), "web-bounded-reads-")

    @AfterTest fun cleanup() { root.toFile().deleteRecursively() }

    private fun server() = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("analysis must remain inert") },
        JobReconstructor { _, _ -> error("reconstruction must remain inert") }, uiMode = WebUiMode.SPA, basePath = "/w/",
        sensitiveValues = emptyList()).also { it.start() }

    private fun digest(): Map<String, String> = Files.walk(root).use { paths ->
        paths.filter { Files.isRegularFile(it) && it.fileName.toString() != ".web-owner.lock" }.toList().associate { file ->
            root.relativize(file).toString() to MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)).joinToString("") { "%02x".format(it) }
        }
    }

    private fun entries(): Set<String> = Files.list(root).use { paths -> paths.map { it.fileName.toString() }.toList().toSet() }

    @Test
    fun `refused and abandoned uploads leave no staging entry job or changed bytes`() {
        val server = server()
        try {
            WebTestBrowser(server).use { browser ->
                val accepted = browser.upload("first.elf", elfFixture(), "bounded-upload-key-0001")
                assertEquals(201, accepted.statusCode(), accepted.text())
                val before = digest()
                val names = entries()
                fun refused(response: java.net.http.HttpResponse<ByteArray>, status: Int, code: String, label: String) {
                    assertEquals(status, response.statusCode(), "$label: ${response.text()}")
                    assertEquals(code, response.errorCode(), label)
                    assertFalse(response.headers().firstValue("Location").isPresent, "$label has no success location")
                    assertEquals(names, entries(), "$label left a staging or job entry")
                    assertEquals(before, digest(), "$label changed stored bytes")
                }
                refused(browser.upload("bad.elf", byteArrayOf(1, 2, 3), "bounded-upload-key-0002"), 422, "INVALID_ELF", "non-ELF")
                refused(browser.upload("renamed.elf", elfFixture(), "bounded-upload-key-0001"), 409, "IDEMPOTENCY_CONFLICT", "changed intent")
                refused(browser.upload("large.elf", ByteArray(StreamingMultipartUpload.MAX_REQUEST_BYTES.toInt()), "bounded-upload-key-0003"),
                    413, "UPLOAD_TOO_LARGE", "oversized upload")
                refused(browser.send("POST", "/w/api/v1/jobs", "--b\r\n".toByteArray(), mapOf("Content-Type" to "multipart/form-data; boundary=b",
                    "Idempotency-Key" to "bounded-upload-key-0004")), 400, "MALFORMED_MULTIPART", "truncated multipart")

                // A peer that declares a body and disappears partway through it must not strand its staging directory.
                val port = server.serverPort
                Socket("127.0.0.1", port).use { socket ->
                    val head = "POST /w/api/v1/jobs HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nOrigin: ${browser.origin}\r\nCookie: ${browser.cookie}\r\n" +
                        "X-CSRF-Token: ${browser.csrf}\r\nAccept: application/json\r\nIdempotency-Key: bounded-upload-key-0005\r\n" +
                        "Content-Type: multipart/form-data; boundary=fixture_boundary\r\nContent-Length: 1000000\r\n\r\n" +
                        "--fixture_boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"partial.elf\"\r\n\r\n"
                    socket.getOutputStream().write(head.toByteArray() + elfFixture() + ByteArray(65_536))
                    socket.getOutputStream().flush()
                }
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
                while (entries() != names && System.nanoTime() < deadline) Thread.sleep(10)
                assertEquals(names, entries(), "an abandoned upload left a staging entry")
                assertEquals(before, digest())
                // The replay of the accepted upload still resolves its original job.
                val replay = browser.upload("first.elf", elfFixture(), "bounded-upload-key-0001")
                assertEquals(201, replay.statusCode())
                assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElse(null))
                assertEquals(accepted.data().getValue("jobId"), replay.data().getValue("jobId"))
                assertEquals(1, JobStore(root).jobIds().size)
            }
        } finally { server.stop() }
    }

    @Test
    fun `job attempt and event continuations stay inside their snapshot session and selection`() {
        val store = JobStore(root)
        val ids = List(3) { store.createFromUpload("fixture-$it.elf", elfFixture()).id }
        val runs = WorkflowAttemptStore.open(root).use { owner ->
            ids.take(2).associateWith { id ->
                val current = (owner.inspect(id) as WorkflowJobInspection.Available).snapshot
                owner.create(id, current.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                    WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt.runId
            }
        }
        runs.forEach { (id, run) ->
            AgentProgressJournal(Files.createDirectories(root.resolve(id).resolve("reports/runs/$run")), "reconstruct")
                .use { it.phase(decompengine.agent.AgentWorkflowPhase.PLANNING) }
        }
        val server = server()
        try {
            WebTestBrowser(server).use { browser ->
                WebTestBrowser(server).use { other ->
                    fun next(page: java.net.http.HttpResponse<ByteArray>): String? =
                        page.data().getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.contentOrNull
                    fun items(page: java.net.http.HttpResponse<ByteArray>): List<String> =
                        page.data().getValue("items").jsonArray.map { it.jsonObject.getValue("jobId").jsonPrimitive.content }

                    val first = browser.get("/w/api/v1/jobs?limit=1")
                    assertEquals(200, first.statusCode(), first.text())
                    val cursor = checkNotNull(next(first))
                    for ((label, path, response) in listOf(
                        Triple("another session", "/w/api/v1/jobs?limit=1&cursor=$cursor", other),
                        Triple("another limit", "/w/api/v1/jobs?limit=2&cursor=$cursor", browser),
                        Triple("another sort", "/w/api/v1/jobs?limit=1&sort=oldest&cursor=$cursor", browser),
                        Triple("another filter", "/w/api/v1/jobs?limit=1&status=uploaded&cursor=$cursor", browser),
                        Triple("another resource", "/w/api/v1/jobs/${ids[0]}/runs?limit=1&cursor=$cursor", browser),
                    )) {
                        val refused = response.get(path)
                        assertEquals(400, refused.statusCode(), "$label: ${refused.text()}")
                        assertEquals("INVALID_CURSOR", refused.errorCode(), label)
                    }
                    // A job published mid-walk never appears inside, or duplicates rows of, the captured snapshot.
                    val inserted = browser.upload("inserted.elf", elfFixture(), "bounded-insert-key-0001")
                    assertEquals(201, inserted.statusCode())
                    val walked = items(first).toMutableList()
                    var continuation: String? = cursor
                    while (continuation != null) {
                        val page = browser.get("/w/api/v1/jobs?limit=1&cursor=$continuation")
                        assertEquals(200, page.statusCode(), page.text())
                        walked += items(page)
                        continuation = next(page)
                    }
                    assertEquals(ids.toSet(), walked.toSet(), "the walk covers exactly the captured jobs")
                    assertEquals(walked.size, walked.toSet().size, "no row is repeated")
                    assertEquals(4, items(browser.get("/w/api/v1/jobs")).size, "a fresh first page sees the new job")

                    // Event cursors are bound to their own job and attempt.
                    val (jobA, runA) = runs.entries.first().toPair()
                    val (jobB, runB) = runs.entries.last().toPair()
                    val snapshot = browser.get("/w/api/v1/jobs/$jobA/runs/$runA/snapshot")
                    assertEquals(200, snapshot.statusCode(), snapshot.text())
                    val eventCursor = checkNotNull(snapshot.data().getValue("oldestCursor").jsonPrimitive.contentOrNull)
                    assertEquals(200, browser.get("/w/api/v1/jobs/$jobA/runs/$runA/events?transport=poll&after=$eventCursor").statusCode())
                    for (path in listOf("/w/api/v1/jobs/$jobB/runs/$runB/events?transport=poll&after=$eventCursor",
                        "/w/api/v1/jobs/$jobA/runs/$runB/events?transport=poll&after=$eventCursor")) {
                        val refused = browser.get(path)
                        assertTrue(refused.statusCode() in setOf(400, 404), "$path: ${refused.text()}")
                        if (refused.statusCode() == 400) assertEquals("INVALID_CURSOR", refused.errorCode(), path)
                    }
                    val foreign = other.get("/w/api/v1/jobs/$jobA/runs/$runA/events?transport=poll&after=$eventCursor")
                    assertEquals(400, foreign.statusCode(), foreign.text())
                    assertEquals("INVALID_CURSOR", foreign.errorCode())
                }
            }
        } finally { server.stop() }
    }
}
