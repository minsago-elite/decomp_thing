package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class WebApiControllerTest {
    private val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()

    @Test
    fun `authenticated progress snapshots replay persisted observations and expose retention gaps`() {
        val root = createTempDirectory("web-progress-http-")
        val store = JobStore(root)
        val job = store.createFromUpload("inert.elf", elfFixture())
        val other = store.createFromUpload("other.elf", elfFixture())
        val run = decompengine.jobs.WorkflowAttemptStore.open(root).use { owner ->
            val original = (owner.inspect(job.id) as decompengine.jobs.WorkflowJobInspection.Available).snapshot
            owner.create(job.id, original.version, decompengine.jobs.NewWorkflowAttempt(
                decompengine.jobs.WorkflowKind.RECONSTRUCT,
                decompengine.jobs.WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u),
            )).attempt
        }
        val reports = Files.createDirectories(root.resolve(job.id).resolve("reports/runs/${run.runId}"))
        val journalFile = reports.resolve(decompengine.jobs.AgentProgressJournal.FILE_NAME)
        decompengine.jobs.AgentProgressJournal(reports, "reconstruct").use {
            it.phase(decompengine.agent.AgentWorkflowPhase.PLANNING)
        }
        val recorded = Json.parseToJsonElement(Files.readString(journalFile)).jsonObject
        Files.writeString(journalFile, JsonObject(recorded + ("events" to kotlinx.serialization.json.JsonArray(
            recorded.getValue("events").jsonArray.map { item -> JsonObject(item.jsonObject + mapOf(
                "text" to JsonPrimitive("PRIVATE_HTTP_PROSE"), "role" to JsonPrimitive("thought"),
                "path" to JsonPrimitive("/PRIVATE_HTTP_ROOT/input"),
                "entries" to kotlinx.serialization.json.JsonArray(listOf(JsonObject(mapOf(
                    "idSha256" to JsonPrimitive("a".repeat(64)), "status" to JsonPrimitive("pending"),
                    "text" to JsonPrimitive("PRIVATE_HTTP_PLAN"),
                )))),
            )) }
        ))).toString())
        var executed = false
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> executed = true },
            JobReconstructor { _, _ -> executed = true }, uiMode = WebUiMode.SPA, basePath = "/workbench/")
        server.start()
        try {
            val path = "/workbench/api/v1/jobs/${job.id}/runs/${run.runId}"
            for (suffix in listOf("snapshot", "events")) assertError(request(server, "$path/$suffix"), 401, "SESSION_REQUIRED")
            val cookie = establish(server); val headers = mapOf("Cookie" to cookie)
            assertError(request(server, "$path/events", headers = headers + ("Origin" to "https://invalid.example")), 403, "ORIGIN_DENIED")
            assertError(request(server, "$path/snapshot", "POST", "{}", headers), 405, "METHOD_NOT_ALLOWED")
            assertError(request(server, "$path/events", headers = headers + ("Accept" to "text/html")), 406, "NOT_ACCEPTABLE")
            assertError(request(server, "/workbench/api/v1/jobs/${other.id}/runs/${run.runId}/events", headers = headers), 404, "NOT_FOUND")
            val before = Files.readString(journalFile)
            val snapshot = assertEnvelope(request(server, "$path/snapshot", headers = headers), 200, "snapshot")
            assertEquals("2", snapshot.getValue("progress").jsonObject.getValue("nextSequence").jsonPrimitive.content)
            assertEquals("observations", snapshot.getValue("progress").jsonObject.getValue("authority").jsonPrimitive.content)
            val first = assertEnvelope(request(server, "$path/events?limit=1&cursor=${snapshot.getValue("oldestCursor").jsonPrimitive.content}", headers = headers), 200, "events")
            assertFalse(first.toString().contains("PRIVATE_HTTP_"))
            val fields = first.getValue("items").jsonArray.single().jsonObject.getValue("payload").jsonObject
            assertEquals("3", fields.getValue("omittedFieldCount").jsonPrimitive.content)
            assertEquals("true", fields.getValue("fields").jsonObject.getValue("textOmitted").jsonPrimitive.content)
            val firstCursor = first.getValue("nextCursor").jsonPrimitive.content
            val firstEvent = first.getValue("items").jsonArray.single().jsonObject
            assertEquals("0", firstEvent.getValue("sequence").jsonPrimitive.content)
            assertEquals(run.runId, firstEvent.getValue("runId").jsonPrimitive.content)
            assertEquals("workflow.observation", firstEvent.getValue("type").jsonPrimitive.content)
            val second = assertEnvelope(request(server, "$path/events?cursor=$firstCursor", headers = headers), 200, "events")
            assertEquals("1", second.getValue("items").jsonArray.single().jsonObject.getValue("sequence").jsonPrimitive.content)
            val through = snapshot.getValue("throughCursor").jsonPrimitive.content
            val idle = assertEnvelope(request(server, "$path/events?cursor=$through", headers = headers), 200, "events")
            assertTrue(idle.getValue("items").jsonArray.isEmpty())
            assertEquals(before, Files.readString(journalFile))
            val otherCookie = establish(server)
            assertError(request(server, "$path/events?cursor=$through", headers = mapOf("Cookie" to otherCookie)), 400, "INVALID_CURSOR")
            decompengine.jobs.AgentProgressJournal(reports, "reconstruct").use { }
            val appended = assertEnvelope(request(server, "$path/events?cursor=$through", headers = headers), 200, "events")
            assertEquals("2", appended.getValue("items").jsonArray.single().jsonObject.getValue("sequence").jsonPrimitive.content)
            val journal = Json.parseToJsonElement(Files.readString(journalFile)).jsonObject
            Files.writeString(journalFile, JsonObject(journal + mapOf(
                "historyDropped" to JsonPrimitive(1), "truncated" to JsonPrimitive(true),
                "events" to kotlinx.serialization.json.JsonArray(journal.getValue("events").jsonArray.drop(1)),
            )).toString())
            assertError(request(server, "$path/events?cursor=$firstCursor", headers = headers), 410, "PROGRESS_GAP")
            val fresh = assertEnvelope(request(server, "$path/snapshot", headers = headers), 200, "snapshot")
            assertEquals("1", fresh.getValue("progress").jsonObject.getValue("historyDropped").jsonPrimitive.content)
            assertEquals("2", fresh.getValue("progress").jsonObject.getValue("retainedEventCount").jsonPrimitive.content)
            Files.delete(journalFile)
            assertError(request(server, "$path/snapshot", headers = headers), 503, "PROGRESS_UNAVAILABLE")
            assertError(request(server, "$path/events", headers = headers), 503, "PROGRESS_UNAVAILABLE")
            assertFalse(executed)
        } finally { server.stop(); root.toFile().deleteRecursively() }
    }

    @Test
    fun `startup recovery projects durable identity while bootstrap keeps production workflow capability unavailable`() {
        val root = createTempDirectory("web-durable-projection-")
        val job = JobStore(root).createFromUpload("inert.elf", elfFixture())
        val otherJob = JobStore(root).createFromUpload("other.elf", elfFixture())
        val run = decompengine.jobs.WorkflowAttemptStore.open(root).use { owner ->
            val original = (owner.inspect(job.id) as decompengine.jobs.WorkflowJobInspection.Available).snapshot
            owner.create(job.id, original.version, decompengine.jobs.NewWorkflowAttempt(
                decompengine.jobs.WorkflowKind.RECONSTRUCT,
                decompengine.jobs.WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u),
            )).attempt
        }
        var executed = false
        val server = UploadServer("127.0.0.1", 0, root,
            JobAnalyzer { _, _ -> executed = true }, JobReconstructor { _, _ -> executed = true },
            uiMode = WebUiMode.SPA, basePath = "/workbench/")
        server.start()
        try {
            val cookie = establish(server)
            val record = root.resolve(job.id).resolve("workflow-state.json")
            val before = Files.readString(record)
            val response = request(server, "/workbench/api/v1/jobs/${job.id}", headers = mapOf("Cookie" to cookie))
            val body = assertEnvelope(response, 200, "job")
            assertEquals(run.runId, body.getValue("latestRunId").jsonPrimitive.content)
            assertEquals("interrupted", body.getValue("status").jsonPrimitive.content)
            assertEquals("null", body.getValue("acceptedRevisionId").toString())
            assertError(request(server, "/workbench/api/v1/jobs/${otherJob.id}/runs/${run.runId}", headers = mapOf("Cookie" to cookie)), 404, "NOT_FOUND")
            val history = assertEnvelope(request(server, "/workbench/api/v1/jobs/${job.id}/runs?limit=1", headers = mapOf("Cookie" to cookie)), 200, "runs")
            assertEquals(job.id, history.getValue("jobId").jsonPrimitive.content)
            assertEquals(run.runId, history.getValue("items").jsonArray.single().jsonObject.getValue("runId").jsonPrimitive.content)
            val report = assertEnvelope(request(server, "/workbench/api/v1/jobs/${job.id}/runs/${run.runId}/reports/exploration", headers = mapOf("Cookie" to cookie)), 200, "report")
            assertEquals("unknown", report.getValue("state").jsonPrimitive.content)
            assertEquals("null", report.getValue("summary").toString())
            assertEquals(run.runId, report.getValue("binding").jsonObject.getValue("runId").jsonPrimitive.content)
            val reportFile = Files.createDirectories(root.resolve(job.id).resolve("reports/runs/${run.runId}")).resolve("exploration.json")
            val raw = "{\"fixture\":\"<script>inert</script>\"}"
            Files.writeString(reportFile, raw)
            val descriptor = assertEnvelope(request(server, "/workbench/api/v1/jobs/${job.id}/runs/${run.runId}/reports/exploration", headers = mapOf("Cookie" to cookie)), 200, "report").getValue("sourceArtifact").jsonObject
            val href = descriptor.getValue("contentHref").jsonPrimitive.content
            assertError(request(server, href), 401, "SESSION_REQUIRED")
            val download = request(server, href, headers = mapOf("Cookie" to cookie))
            assertEquals(200, download.statusCode()); assertEquals(raw, download.body())
            assertEquals("application/octet-stream", download.headers().firstValue("Content-Type").orElseThrow())
            assertTrue(download.headers().firstValue("Content-Disposition").orElseThrow().startsWith("attachment;"))
            assertEquals("nosniff", download.headers().firstValue("X-Content-Type-Options").orElseThrow())
            assertEquals("sandbox; default-src 'none'", download.headers().firstValue("Content-Security-Policy").orElseThrow())
            val head = request(server, href, "HEAD", headers = mapOf("Cookie" to cookie))
            assertEquals(200, head.statusCode()); assertEquals("", head.body())
            assertEquals(raw.toByteArray().size.toString(), head.headers().firstValue("Content-Length").orElseThrow())
            assertError(request(server, href, headers = mapOf("Cookie" to cookie, "Range" to "bytes=0-2")), 400, "UNSUPPORTED_HEADER")
            Files.writeString(reportFile, "changed")
            assertError(request(server, href, headers = mapOf("Cookie" to cookie)), 409, "ARTIFACT_CHANGED")
            val runPath = "/workbench/api/v1/jobs/${job.id}/runs/${run.runId}"
            assertError(request(server, runPath), 401, "SESSION_REQUIRED")
            val attempt = assertEnvelope(request(server, runPath, headers = mapOf("Cookie" to cookie)), 200, "run")
            assertEquals(run.runId, attempt.getValue("runId").jsonPrimitive.content)
            assertEquals(job.id, attempt.getValue("jobId").jsonPrimitive.content)
            assertEquals("interrupted", attempt.getValue("state").jsonPrimitive.content)
            assertEquals("not-evaluated", attempt.getValue("acceptance").jsonPrimitive.content)
            assertEquals("PROCESS_INTERRUPTED", attempt.getValue("terminalReason").jsonPrimitive.content)
            assertEquals("null", attempt.getValue("usage").toString())
            assertError(request(server, "$runPath?latest=true", headers = mapOf("Cookie" to cookie)), 400, "VALIDATION_FAILED")
            assertError(request(server, "/workbench/api/v1/jobs/${job.id}/runs/missing", headers = mapOf("Cookie" to cookie)), 404, "NOT_FOUND")
            val bootstrap = assertEnvelope(request(server, "/workbench/api/v1/bootstrap", headers = mapOf("Cookie" to cookie)), 200, "bootstrap")
            assertTrue(bootstrap.getValue("capabilities").toString().contains("PREVIEW_UNAVAILABLE"))
            assertError(request(server, "/workbench/api/v1/jobs/${job.id}/runs", "POST", "{}", mapOf(
                "Cookie" to cookie, "X-CSRF-Token" to bootstrap.getValue("csrfToken").jsonPrimitive.content,
            )), 405, "METHOD_NOT_ALLOWED")
            assertEquals(before, Files.readString(record))
            assertFalse(executed)
        } finally { server.stop(); root.toFile().deleteRecursively() }
    }

    @Test
    fun `session exchange reload and logout use consistent no-store schema envelopes`() = withServer { server, _, _ ->
        val api = "/workbench/api/v1"
        assertError(request(server, "$api/bootstrap"), 401, "SESSION_REQUIRED")
        val token = server.issueBrowserBootstrap().token
        val session = request(server, "$api/session", "POST", "{\"token\":\"$token\"}")
        val body = assertEnvelope(session, 200, "session")
        val cookie = session.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
        val csrf = body.getValue("csrfToken").jsonPrimitive.content
        assertTrue(csrf.matches(Regex("[A-Za-z0-9_-]{43}")))
        assertFalse(session.body().contains(token))
        val bootstrap = assertEnvelope(request(server, "$api/bootstrap", headers = mapOf("Cookie" to cookie)), 200, "bootstrap")
        assertEquals(csrf, bootstrap.getValue("csrfToken").jsonPrimitive.content)
        assertEquals("/workbench/", bootstrap.getValue("basePath").jsonPrimitive.content)
        assertEquals("degraded", bootstrap.getValue("readiness").jsonPrimitive.content)
        val forbiddenAccept = request(server, "$api/session", "DELETE", headers = mapOf(
            "Cookie" to cookie, "X-CSRF-Token" to csrf, "Accept" to "application/json;q=0, */*;q=1",
        ))
        assertError(forbiddenAccept, 406, "NOT_ACCEPTABLE")
        assertEquals(200, request(server, "$api/bootstrap", headers = mapOf("Cookie" to cookie)).statusCode())
        assertError(request(server, "$api/session", "DELETE", headers = mapOf("Cookie" to cookie)), 403, "CSRF_DENIED")
        val logout = request(server, "$api/session", "DELETE", headers = mapOf("Cookie" to cookie, "X-CSRF-Token" to csrf))
        assertEquals(204, logout.statusCode())
        assertTrue(logout.body().isEmpty())
        assertEquals("no-store", logout.headers().firstValue("Cache-Control").orElseThrow())
        assertTrue(logout.headers().firstValue("Set-Cookie").orElseThrow().contains("Max-Age=0"))
        assertError(request(server, "$api/bootstrap", headers = mapOf("Cookie" to cookie)), 401, "SESSION_REQUIRED")
        assertError(request(server, "$api/session", "POST", "{\"token\":\"$token\"}"), 401, "BOOTSTRAP_REQUIRED")
    }

    @Test
    fun `private job projection preserves unsigned addresses and hides internal paths and status messages`() = withServer { server, store, jobId ->
        val api = "/workbench/api/v1"
        assertError(request(server, "$api/jobs/$jobId"), 401, "SESSION_REQUIRED")
        val cookie = establish(server)
        val response = request(server, "$api/jobs/$jobId", headers = mapOf("Cookie" to cookie))
        val job = assertEnvelope(response, 200, "job")
        assertEquals("64", job.getValue("sizeBytes").jsonPrimitive.content)
        assertEquals("0xffffffffffffffff", job.getValue("binary").jsonObject.getValue("entryPoint").jsonPrimitive.content)
        assertEquals("null", job.getValue("latestRunId").toString())
        assertEquals("null", job.getValue("acceptedRevisionId").toString())
        assertFalse(response.body().contains("binary_path"))
        assertFalse(response.body().contains("PRIVATE_STATUS_SENTINEL"))
        assertFalse(response.body().contains(store.get(jobId).binaryPath.toString()))
        val etag = response.headers().firstValue("ETag").orElseThrow()
        assertEquals("\"${job.getValue("version").jsonPrimitive.content}\"", etag)
        val unchanged = request(server, "$api/jobs/$jobId", headers = mapOf("Cookie" to cookie, "If-None-Match" to etag))
        assertEquals(304, unchanged.statusCode())
        assertTrue(unchanged.body().isEmpty())
        store.updateStatus(jobId, "complete")
        val changed = request(server, "$api/jobs/$jobId", headers = mapOf("Cookie" to cookie, "If-None-Match" to etag))
        assertEquals("completed", assertEnvelope(changed, 200, "job").getValue("status").jsonPrimitive.content)
        assertNotEquals(etag, changed.headers().firstValue("ETag").orElseThrow())
        val head = request(server, "$api/jobs/$jobId", "HEAD", headers = mapOf("Cookie" to cookie))
        assertEquals(405, head.statusCode())
        assertEquals("GET", head.headers().firstValue("Allow").orElseThrow())
        assertTrue(head.body().isEmpty())
    }

    @Test
    fun `API misses versions encoded paths and negotiation use authorized JSON failures`() = withServer { server, _, jobId ->
        val cookie = establish(server)
        for (path in listOf("/workbench/api/v1/missing", "/workbench/api/v2/jobs", "/workbench/api/jobs/legacy")) {
            assertError(request(server, path), 401, "SESSION_REQUIRED")
            assertError(request(server, path, headers = mapOf("Cookie" to cookie)), 404, "NOT_FOUND")
        }
        assertError(request(server, "/workbench/api/v1/jobs/%2e", headers = mapOf("Cookie" to cookie)), 404, "NOT_FOUND")
        assertError(request(server, "/workbench/api/v1/jobs/$jobId?unknown=1", headers = mapOf("Cookie" to cookie)), 400, "VALIDATION_FAILED")
        assertError(request(server, "/workbench/api/v1/jobs/$jobId", headers = mapOf("Cookie" to cookie, "Accept" to "text/html")), 406, "NOT_ACCEPTABLE")
        assertEquals(200, request(server, "/workbench/api/v1/jobs/$jobId", headers = mapOf("Cookie" to cookie,
            "Accept" to "text/html;q=1, application/json;q=0.5")).statusCode())
        assertError(request(server, "/workbench/api/v1/session"), 405, "METHOD_NOT_ALLOWED")
    }

    @Test
    fun `origin and forwarding policy runs before route and request validation`() = withServer { server, _, _ ->
        val headers = mapOf("Origin" to "https://example.invalid")
        for ((path, method) in listOf("/workbench/" to "GET", "/workbench/api/v1/session" to "GET",
            "/workbench/api/v1/session?invalid=1" to "POST", "/workbench/api/v1/bootstrap" to "GET")) {
            assertError(request(server, path, method, "{}", headers), 403, "ORIGIN_DENIED")
        }
        assertError(request(server, "/workbench/api/v1/session", "POST", "{}",
            mapOf("X-Forwarded-Host" to "localhost")), 403, "FORWARDED_HEADERS_DENIED")
        assertError(request(server, "/workbench/api/v1/session", "POST", "{}",
            mapOf("Content-Type" to "text/plain")), 415, "UNSUPPORTED_MEDIA_TYPE")
    }

    @Test
    fun `malformed persisted records yield safe errors while public session reads remain inert`() = withServer { server, store, jobId ->
        val cookie = establish(server)
        val record = store.get(jobId).binaryPath.parent.resolve("job.json")
        Files.writeString(record, "PRIVATE_CORRUPT_RECORD_SENTINEL {")
        val failure = request(server, "/workbench/api/v1/jobs/$jobId", headers = mapOf("Cookie" to cookie))
        assertError(failure, 503, "CORRUPT_LEGACY_JOB")
        assertFalse(failure.body().contains("PRIVATE_CORRUPT"))
        assertFalse(failure.body().contains(record.toString()))
        assertEquals(200, request(server, "/workbench/api/v1/bootstrap", headers = mapOf("Cookie" to cookie)).statusCode())
        assertEquals("PRIVATE_CORRUPT_RECORD_SENTINEL {", Files.readString(record))
    }

    @Test
    fun `private job collection enforces filters envelopes and read-only admission`() = withServer { server, _, jobId ->
        val path = "/workbench/api/v1/jobs"
        assertError(request(server, path), 401, "SESSION_REQUIRED")
        val cookie = establish(server)
        val headers = mapOf("Cookie" to cookie)
        val result = assertEnvelope(request(server, "$path?search=SYNTHETIC&limit=1", headers = headers), 200, "jobs")
        assertEquals(jobId, result.getValue("items").jsonArray.single().jsonObject.getValue("jobId").jsonPrimitive.content)
        assertEquals("null", result.getValue("page").jsonObject.getValue("nextCursor").toString())
        assertError(request(server, "$path?limit=201", headers = headers), 422, "VALIDATION_FAILED")
        assertError(request(server, "$path?cursor=invalid", headers = headers), 400, "INVALID_CURSOR")
        assertEquals(415, request(server, path, "POST", "{}", headers).statusCode())
    }

    @Test
    fun `authenticated streamed upload returns durable identity and replays without overwriting later status`() = withServer { server, store, _ ->
        val cookie = establish(server)
        val csrf = assertEnvelope(request(server, "/workbench/api/v1/bootstrap", headers = mapOf("Cookie" to cookie)), 200, "bootstrap")
            .getValue("csrfToken").jsonPrimitive.content
        val key = "fixture_upload_api_key"
        val headers = mapOf("Cookie" to cookie, "X-CSRF-Token" to csrf, "Idempotency-Key" to key)
        assertError(upload(server, elfFixture(), emptyMap()), 401, "SESSION_REQUIRED")
        assertError(upload(server, elfFixture(), headers - "X-CSRF-Token"), 403, "CSRF_DENIED")
        assertError(upload(server, elfFixture(), headers - "Idempotency-Key"), 400, "INVALID_IDEMPOTENCY_KEY")
        assertError(upload(server, elfFixture(), headers + ("Origin" to "http://invalid.example")), 403, "ORIGIN_DENIED")
        assertError(upload(server, byteArrayOf(1, 2, 3), headers), 422, "INVALID_ELF")
        val created = upload(server, elfFixture(), headers)
        val original = assertEnvelope(created, 201, "job")
        val id = original.getValue("jobId").jsonPrimitive.content
        assertEquals("/workbench/api/v1/jobs/$id", created.headers().firstValue("Location").orElseThrow())
        assertEquals("uploaded", original.getValue("status").jsonPrimitive.content)
        assertEquals(2, store.jobIds().size)
        store.updateStatus(id, "complete", "later status")
        val repeated = upload(server, elfFixture(), headers, boundary = "different_boundary")
        assertEquals(original, assertEnvelope(repeated, 201, "job"))
        assertEquals("true", repeated.headers().firstValue("Idempotency-Replayed").orElseThrow())
        assertEquals("complete", store.get(id).status)
        assertError(upload(server, byteArrayOf(9), headers), 409, "IDEMPOTENCY_CONFLICT")
        assertError(upload(server, elfFixture(), headers, filename = "renamed.elf"), 409, "IDEMPOTENCY_CONFLICT")
        assertEnvelope(upload(server, elfFixture(), headers + ("Idempotency-Key" to "fixture_different_key")), 201, "job")
        assertEquals(3, store.jobIds().size)
    }

    @Test
    fun `upload receipt survives server restart and a fresh authenticated session`() {
        val root = createTempDirectory("web-upload-restart-")
        fun start() = UploadServer("127.0.0.1", 0, root,
            JobAnalyzer { _, _ -> error("Unexpected analysis") },
            JobReconstructor { _, _ -> error("Unexpected reconstruction") },
            uiMode = WebUiMode.SPA, basePath = "/workbench/").also { it.start() }
        fun headers(server: UploadServer): Map<String, String> {
            val cookie = establish(server)
            val bootstrap = assertEnvelope(request(server, "/workbench/api/v1/bootstrap", headers = mapOf("Cookie" to cookie)), 200, "bootstrap")
            return mapOf("Cookie" to cookie, "X-CSRF-Token" to bootstrap.getValue("csrfToken").jsonPrimitive.content,
                "Idempotency-Key" to "restart_upload_fixture_key")
        }
        var server = start()
        try {
            val original = assertEnvelope(upload(server, elfFixture(), headers(server)), 201, "job")
            server.stop()
            server = start()
            val repeated = upload(server, elfFixture(), headers(server))
            assertEquals(original, assertEnvelope(repeated, 201, "job"))
            assertEquals("true", repeated.headers().firstValue("Idempotency-Replayed").orElseThrow())
            assertEquals(1, JobStore(root).jobIds().size)
        } finally { server.stop(); root.toFile().deleteRecursively() }
    }

    @Test
    fun `upload progress reads require the initiating session and preserve publication distinction`() = withServer { server, _, _ ->
        val cookie = establish(server)
        val csrf = assertEnvelope(request(server, "/workbench/api/v1/bootstrap", headers = mapOf("Cookie" to cookie)), 200, "bootstrap")
            .getValue("csrfToken").jsonPrimitive.content
        val id = "d".repeat(32)
        val path = "/workbench/api/v1/uploads/$id"
        assertError(request(server, path), 401, "SESSION_REQUIRED")
        assertError(request(server, path, headers = mapOf("Cookie" to cookie)), 404, "NOT_FOUND")
        val headers = mapOf("Cookie" to cookie, "X-CSRF-Token" to csrf, "Idempotency-Key" to "progress_fixture_key", "X-Upload-ID" to id)
        val job = assertEnvelope(upload(server, elfFixture(), headers), 201, "job")
        val progress = assertEnvelope(request(server, path, headers = mapOf("Cookie" to cookie)), 200, "uploadProgress")
        assertEquals("published", progress.getValue("state").jsonPrimitive.content)
        assertEquals(job.getValue("jobId"), progress.getValue("jobId"))
        assertTrue(progress.getValue("receivedBytes").jsonPrimitive.content.toLong() > elfFixture().size)
        assertEquals("null", progress.getValue("totalBytes").toString()) // chunked request
        assertError(upload(server, elfFixture(), headers), 409, "UPLOAD_ID_REUSED")
        val other = establish(server)
        assertError(request(server, path, headers = mapOf("Cookie" to other)), 404, "NOT_FOUND")
        val badId = "e".repeat(32)
        assertError(upload(server, byteArrayOf(1), headers + mapOf("X-Upload-ID" to badId, "Idempotency-Key" to "progress_invalid_fixture")), 422, "INVALID_ELF")
        val rejected = assertEnvelope(request(server, "/workbench/api/v1/uploads/$badId", headers = mapOf("Cookie" to cookie)), 200, "uploadProgress")
        assertEquals("unconfirmed", rejected.getValue("state").jsonPrimitive.content)
        assertEquals("null", rejected.getValue("jobId").toString())
    }

    private fun upload(server: UploadServer, bytes: ByteArray, headers: Map<String, String>, filename: String = "fixture.elf", boundary: String = "upload_api_fixture"): HttpResponse<String> {
        val origin = "http://127.0.0.1:${server.serverPort}"
        val body = "--$boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"$filename\"\r\n\r\n".toByteArray() + bytes + "\r\n--$boundary--\r\n".toByteArray()
        val builder = HttpRequest.newBuilder(URI("$origin/workbench/api/v1/jobs"))
            .POST(HttpRequest.BodyPublishers.ofInputStream { body.inputStream() }) // chunked; no Content-Length authority
        (mapOf("Accept" to "application/json", "Origin" to origin, "Content-Type" to "multipart/form-data; boundary=$boundary") + headers)
            .forEach { (key, value) -> builder.header(key, value) }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString())
    }

    private fun establish(server: UploadServer): String {
        val token = server.issueBrowserBootstrap().token
        val response = request(server, "/workbench/api/v1/session", "POST", "{\"token\":\"$token\"}")
        assertEnvelope(response, 200, "session")
        return response.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
    }

    private fun assertEnvelope(response: HttpResponse<String>, status: Int, kind: String): JsonObject {
        assertEquals(status, response.statusCode())
        assertTrue(response.headers().firstValue("Content-Type").orElseThrow().startsWith("application/json"))
        assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow())
        assertEquals("no-referrer", response.headers().firstValue("Referrer-Policy").orElseThrow())
        val body = Json.parseToJsonElement(response.body()).jsonObject
        assertEquals("1", body.getValue("apiVersion").toString())
        assertEquals(kind, body.getValue("kind").jsonPrimitive.content)
        assertEquals(body.getValue("requestId").jsonPrimitive.content, response.headers().firstValue("X-Request-ID").orElseThrow())
        val schema = Json.parseToJsonElement(Files.readString(Path.of("contracts/web/v1/contract.schema.json"))).jsonObject
        if (kind == "error") {
            val error = body.getValue("error").jsonObject
            assertEquals(setOf("code", "message", "retryable", "details", "retryAfterMs"), error.keys)
            return error
        }
        val data = body.getValue("data").jsonObject
        val expected = schema.getValue("definitions").jsonObject.getValue(kind).jsonObject.getValue("properties").jsonObject.keys
        assertEquals(expected, data.keys, "DTO fields differ from the shared producer schema")
        return data
    }

    private fun assertError(response: HttpResponse<String>, status: Int, code: String) {
        assertEquals(code, assertEnvelope(response, status, "error").getValue("code").jsonPrimitive.content)
    }

    private fun request(server: UploadServer, path: String, method: String = "GET", body: String? = null,
                        headers: Map<String, String> = emptyMap()): HttpResponse<String> {
        val origin = "http://127.0.0.1:${server.serverPort}"
        val defaults = mutableMapOf("Accept" to "application/json")
        if (method !in setOf("GET", "HEAD")) defaults.putAll(mapOf("Origin" to origin, "Content-Type" to "application/json"))
        defaults.putAll(headers)
        val builder = HttpRequest.newBuilder(URI(origin + path)).method(method,
            body?.let(HttpRequest.BodyPublishers::ofString) ?: HttpRequest.BodyPublishers.noBody())
        defaults.forEach { (key, value) -> builder.header(key, value) }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString())
    }

    private fun withServer(block: (UploadServer, JobStore, String) -> Unit) {
        val root = createTempDirectory("web-api-")
        val store = JobStore(root)
        val binary = elfFixture().also { bytes -> repeat(8) { bytes[24 + it] = 0xff.toByte() } }
        val job = store.createFromUpload("synthetic.elf", binary)
        store.updateStatus(job.id, "uploaded", "PRIVATE_STATUS_SENTINEL")
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("Unexpected analysis") },
            JobReconstructor { _, _ -> error("Unexpected reconstruction") }, uiMode = WebUiMode.SPA, basePath = "/workbench/")
        server.start()
        try { block(server, store, job.id) } finally { server.stop(); root.toFile().deleteRecursively() }
    }
}
