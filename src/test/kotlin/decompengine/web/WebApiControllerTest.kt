package decompengine.web

import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import org.junit.jupiter.api.extension.ExtendWith
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
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

@ExtendWith(RecoveryMatrixEvidence::class)
class WebApiControllerTest {
    private val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()

    @Test
    fun `bootstrap exposes bounded defaults and stable per-listener identity across sessions and restart`(): Unit {
        val parent = Files.createDirectories(Path.of("build/test-tmp/web-api-bootstrap").toAbsolutePath())
        val root = createTempDirectory(parent, "instance-")
        var executions = 0
        fun create() = UploadServer("127.0.0.1", 0, root,
            JobAnalyzer { _, _ -> executions++ }, JobReconstructor { _, _ -> executions++ },
            uiMode = WebUiMode.SPA, basePath = "/workbench/")
        fun bootstrap(server: UploadServer, cookie: String): JsonObject = assertEnvelope(
            request(server, "/workbench/api/v1/bootstrap", headers = mapOf("Cookie" to cookie)), 200, "bootstrap")
        var server = create()
        try {
            server.start()
            assertError(request(server, "/workbench/api/v1/bootstrap"), 401, "SESSION_REQUIRED")
            val cookie = establish(server)
            val first = bootstrap(server, cookie)
            val identity = first.getValue("serverInstanceId").jsonPrimitive.content
            assertEquals(identity, java.util.UUID.fromString(identity).toString())
            assertEquals(identity, bootstrap(server, cookie).getValue("serverInstanceId").jsonPrimitive.content)
            assertEquals(identity, bootstrap(server, establish(server)).getValue("serverInstanceId").jsonPrimitive.content)
            assertEquals(listOf("1"), first.getValue("apiVersions").jsonArray.map { it.jsonPrimitive.content })
            assertTrue(first.getValue("applicationBuildId").jsonPrimitive.content.isNotBlank())
            assertTrue(first.getValue("uiBuildId").jsonPrimitive.content.matches(Regex("[0-9a-f]{64}")))
            assertEquals("/workbench/", first.getValue("basePath").jsonPrimitive.content)
            assertEquals("degraded", first.getValue("readiness").jsonPrimitive.content)
            val capability = first.getValue("capabilities").jsonArray.map { it.jsonObject }
                .single { it.getValue("id").jsonPrimitive.content == "workflows" }
            assertEquals("unavailable", capability.getValue("state").jsonPrimitive.content)
            assertTrue(capability.getValue("workflows").jsonArray.isEmpty())
            val limits = first.getValue("limits").jsonObject
            assertEquals(StreamingMultipartUpload.MAX_REQUEST_BYTES.toString(), limits.getValue("maxUploadBytes").jsonPrimitive.content)
            assertEquals("30000", limits.getValue("requestDeadlineMs").jsonPrimitive.content)
            assertEquals("120000", limits.getValue("uploadDeadlineMs").jsonPrimitive.content)
            assertEquals("0", limits.getValue("maxSourceChunkBytes").jsonPrimitive.content)
            assertEquals("0", limits.getValue("maxLogChunkBytes").jsonPrimitive.content)
            assertEquals("50", limits.getValue("defaultPageLimit").jsonPrimitive.content)
            assertEquals("200", limits.getValue("maxPageLimit").jsonPrimitive.content)
            assertFalse(first.toString().contains(root.toString()))
            server.stop()
            server = create()
            server.start()
            assertError(request(server, "/workbench/api/v1/bootstrap", headers = mapOf("Cookie" to cookie)), 401, "SESSION_REQUIRED")
            val restarted = bootstrap(server, establish(server))
            assertNotEquals(identity, restarted.getValue("serverInstanceId").jsonPrimitive.content)
            assertEquals(first.getValue("applicationBuildId"), restarted.getValue("applicationBuildId"))
            assertEquals(first.getValue("uiBuildId"), restarted.getValue("uiBuildId"))
            assertEquals(first.getValue("limits"), restarted.getValue("limits"))
            assertEquals(0, executions)
        } finally { server.stop(); root.toFile().deleteRecursively() }
    }

    @Test
    fun `versioned recovery summary is private negotiated and never reclaims retained data`() = withServer { server, store, id ->
        val root = store.storageRoot
        val stage = Files.createDirectory(root.resolve(".upload-stream-v1-97001"),
            java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        val input = stage.resolve("input.elf")
        Files.writeString(input, "PRIVATE-content")
        val temporary = root.resolve(id).resolve(".job-metadata-PRIVATE-canary")
        Files.writeString(temporary, "PRIVATE-metadata")
        val metadata = Files.readAllBytes(root.resolve(id).resolve("job.json"))
        val path = "/workbench/api/v1/recovery"
        assertError(request(server, path), 401, "SESSION_REQUIRED")
        val headers = mapOf("Cookie" to establish(server))
        val summary = assertEnvelope(request(server, path, headers = headers), 200, "recovery")
        assertEquals("1", summary.getValue("schemaVersion").toString())
        assertEquals("true", summary.getValue("displayOnly").toString())
        assertEquals("true", summary.getValue("inventoryComplete").toString())
        assertEquals("1", summary.getValue("retainedUploadStages").toString())
        assertEquals("1", summary.getValue("retainedMetadataFiles").toString())
        assertEquals("31", summary.getValue("observedBytes").jsonPrimitive.content)
        assertFalse(summary.toString().contains("PRIVATE") || summary.toString().contains("canary") || summary.toString().contains(root.toString()))
        val head = request(server, path, "HEAD", headers = headers)
        assertEquals(200, head.statusCode())
        assertEquals("", head.body())
        assertError(request(server, "$path?private=PRIVATE-query", headers = headers), 400, "VALIDATION_FAILED")
        assertError(request(server, path, headers = headers + ("Accept" to "text/html")), 406, "NOT_ACCEPTABLE")
        assertError(request(server, path, "POST", "{}", headers), 405, "METHOD_NOT_ALLOWED")
        assertEquals("PRIVATE-content", Files.readString(input))
        assertEquals("PRIVATE-metadata", Files.readString(temporary))
        kotlin.test.assertContentEquals(metadata, Files.readAllBytes(root.resolve(id).resolve("job.json")))
    }

    @Test
    fun `versioned recovery keeps an incomplete zero-count inspection distinct from empty storage`() = withServer { server, store, _ ->
        val unknown = store.storageRoot.resolve(".upload-private-unknown")
        Files.writeString(unknown, "PRIVATE-layout")
        val summary = assertEnvelope(request(server, "/workbench/api/v1/recovery",
            headers = mapOf("Cookie" to establish(server))), 200, "recovery")
        assertEquals("false", summary.getValue("inventoryComplete").toString())
        assertEquals("0", summary.getValue("retainedUploadStages").toString())
        assertEquals("0", summary.getValue("retainedMetadataFiles").toString())
        assertEquals("1", summary.getValue("uninspectedEntries").toString())
        assertFalse(summary.toString().contains("PRIVATE"))
        assertEquals("PRIVATE-layout", Files.readString(unknown))
    }

    @Test
    fun `legacy and v1 uploads remain equivalent through mode changes on the same store`() {
        val root = createTempDirectory("web-adapter-parity-")
        var executions = 0
        val bytes = elfFixture().also { value -> repeat(8) { value[24 + it] = 0xff.toByte() } }
        val legacy = mutableMapOf<String, JsonObject>()
        val versioned = mutableMapOf<String, JsonObject>()
        val persisted = mutableMapOf<String, ByteArray>()
        fun server(mode: WebUiMode, action: (UploadServer) -> Unit) {
            val instance = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> executions++ },
                JobReconstructor { _, _ -> executions++ }, uiMode = mode,
                basePath = if (mode == WebUiMode.SPA) "/workbench/" else "/")
            instance.start()
            try { action(instance) } finally { instance.stop() }
        }
        fun remember(id: String) { persisted[id] = Files.readAllBytes(root.resolve(id).resolve("job.json")) }
        fun unchanged() {
            persisted.forEach { (id, original) ->
                kotlin.test.assertContentEquals(original, Files.readAllBytes(root.resolve(id).resolve("job.json")))
                kotlin.test.assertContentEquals(bytes, Files.readAllBytes(root.resolve(id).resolve("input.elf")))
            }
            assertEquals(0, executions)
        }
        try {
            server(WebUiMode.LEGACY) { instance ->
                val response = upload(instance, bytes, legacySessionHeaders(instance), filename = "legacy.elf", path = "/jobs")
                assertEquals(201, response.statusCode())
                val job = Json.parseToJsonElement(response.body()).jsonObject
                val id = job.getValue("id").jsonPrimitive.content
                legacy[id] = job
                remember(id)
                val read = request(instance, "/api/jobs/$id", headers = legacySessionHeaders(instance))
                assertEquals(200, read.statusCode())
                assertEquals(job, Json.parseToJsonElement(read.body()))
                unchanged()
            }
            server(WebUiMode.SPA) { instance ->
                val cookie = establish(instance)
                val headers = mapOf("Cookie" to cookie)
                legacy.keys.forEach { id ->
                    versioned[id] = assertEnvelope(request(instance, "/workbench/api/v1/jobs/$id", headers = headers), 200, "job")
                }
                val csrf = assertEnvelope(request(instance, "/workbench/api/v1/bootstrap", headers = headers), 200, "bootstrap")
                    .getValue("csrfToken").jsonPrimitive.content
                val uploaded = assertEnvelope(upload(instance, bytes, headers + mapOf("X-CSRF-Token" to csrf,
                    "Idempotency-Key" to "adapter_parity_upload"), filename = "versioned.elf"), 201, "job")
                val id = uploaded.getValue("jobId").jsonPrimitive.content
                versioned[id] = uploaded
                remember(id)
                unchanged()
            }
            server(WebUiMode.LEGACY) { instance ->
                versioned.keys.forEach { id ->
                    val response = request(instance, "/api/jobs/$id", headers = legacySessionHeaders(instance))
                    assertEquals(200, response.statusCode())
                    legacy[id] = Json.parseToJsonElement(response.body()).jsonObject
                }
                unchanged()
            }
            assertEquals(2, legacy.size)
            legacy.forEach { (id, old) ->
                val current = versioned.getValue(id)
                mapOf("id" to "jobId", "filename" to "displayFilename", "status" to "status",
                    "created_at" to "createdAt", "updated_at" to "updatedAt").forEach { (left, right) ->
                    assertEquals(old.getValue(left), current.getValue(right), left)
                }
                assertEquals(old.getValue("size_bytes").jsonPrimitive.content, current.getValue("sizeBytes").jsonPrimitive.content)
                val metadata = old.getValue("metadata").jsonObject
                val binary = current.getValue("binary").jsonObject
                mapOf("format" to "format", "endianness" to "endianness", "object_type" to "objectType",
                    "machine" to "machine", "os_abi" to "osAbi").forEach { (left, right) -> assertEquals(metadata[left], binary[right]) }
                assertEquals("-1", metadata.getValue("entry_point").jsonPrimitive.content)
                assertEquals("0xffffffffffffffff", binary.getValue("entryPoint").jsonPrimitive.content)
                for (public in listOf(old, current)) {
                    assertFalse(public.toString().contains(root.toString()))
                    assertFalse("binary_path" in public)
                    assertFalse("status_message" in public)
                }
            }
            unchanged()
        } finally { root.toFile().deleteRecursively() }
    }

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
            for (suffix in listOf("snapshot", "events", "queue-position")) assertError(request(server, "$path/$suffix"), 401, "SESSION_REQUIRED")
            val cookie = establish(server); val headers = mapOf("Cookie" to cookie)
            assertError(request(server, "$path/events", headers = headers + ("Origin" to "https://invalid.example")), 403, "ORIGIN_DENIED")
            assertError(request(server, "$path/snapshot", "POST", "{}", headers), 405, "METHOD_NOT_ALLOWED")
            assertError(request(server, "$path/events", headers = headers + ("Accept" to "text/html")), 406, "NOT_ACCEPTABLE")
            assertError(request(server, "/workbench/api/v1/jobs/${other.id}/runs/${run.runId}/events", headers = headers), 404, "NOT_FOUND")
            assertError(request(server, "$path/events?transport=poll", headers = headers + ("Last-Event-ID" to "fixture_cursor")), 400, "UNSUPPORTED_HEADER")
            assertError(request(server, "$path/events?transport=stream", headers = headers), 422, "VALIDATION_FAILED")
            val before = Files.readString(journalFile)
            // The queue sample names only the selected attempt and never a host diagnostic.
            val queue = request(server, "$path/queue-position", headers = headers)
            assertEquals(200, queue.statusCode())
            val queueBody = Json.parseToJsonElement(queue.body()).jsonObject
            assertEquals("queuePosition", queueBody.getValue("kind").jsonPrimitive.content)
            val queueData = queueBody.getValue("data").jsonObject
            assertEquals(job.id, queueData.getValue("jobId").jsonPrimitive.content)
            assertEquals(run.runId, queueData.getValue("runId").jsonPrimitive.content)
            assertTrue(queueData.getValue("state").jsonPrimitive.content in setOf("queued", "not-queued", "unavailable"))
            assertFalse(queue.body().contains(other.id)); assertFalse(queue.body().contains(root.toString()))
            assertError(request(server, "$path/queue-position?detail=host", headers = headers), 400, "VALIDATION_FAILED")
            assertError(request(server, "/workbench/api/v1/jobs/${other.id}/runs/${run.runId}/queue-position", headers = headers), 404, "NOT_FOUND")
            val snapshot = assertEnvelope(request(server, "$path/snapshot", headers = headers), 200, "snapshot")
            assertEquals("2", snapshot.getValue("progress").jsonObject.getValue("nextSequence").jsonPrimitive.content)
            assertEquals("observations", snapshot.getValue("progress").jsonObject.getValue("authority").jsonPrimitive.content)
            val first = assertEnvelope(request(server, "$path/events?limit=1&cursor=${snapshot.getValue("oldestCursor").jsonPrimitive.content}", headers = headers), 200, "events")
            val target = assertEnvelope(request(server, "$path/events?transport=poll&limit=1&after=${snapshot.getValue("oldestCursor").jsonPrimitive.content}", headers = headers), 200, "events")
            assertEquals(first, target)
            val stream = client.send(HttpRequest.newBuilder(URI("http://127.0.0.1:${server.serverPort}$path/events?after=${snapshot.getValue("oldestCursor").jsonPrimitive.content}&limit=1"))
                .timeout(java.time.Duration.ofSeconds(3)).header("Cookie", cookie).header("Accept", "text/event-stream").build(),
                HttpResponse.BodyHandlers.ofInputStream())
            assertEquals(200, stream.statusCode())
            assertNoWebCors(stream)
            assertTrue(stream.headers().firstValue("Content-Type").orElseThrow().startsWith("text/event-stream"))
            val streamed = stream.body().bufferedReader().use { reader ->
                java.util.concurrent.CompletableFuture.supplyAsync {
                    var line = reader.readLine()
                    while (line != null && !line.startsWith("data: ")) line = reader.readLine()
                    Json.parseToJsonElement(checkNotNull(line).removePrefix("data: "))
                }.get(3, java.util.concurrent.TimeUnit.SECONDS)
            }
            assertEquals(first.getValue("items").jsonArray.single(), streamed)
            assertError(request(server, "$path/events?after=a&cursor=a", headers = headers), 422, "VALIDATION_FAILED")
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
            // Owned replay removes the private fields, so the original byte-bound anchor changed.
            val rewritten = request(server, "$path/events?cursor=$through", headers = headers)
            assertError(rewritten, 410, "EVENT_GAP")
            val rewrittenRecovery = Json.parseToJsonElement(rewritten.body()).jsonObject
                .getValue("error").jsonObject.getValue("recovery").jsonObject
            assertEquals(through, rewrittenRecovery.getValue("requestedCursor").jsonPrimitive.content)
            assertEquals("$path/snapshot", rewrittenRecovery.getValue("snapshotHref").jsonPrimitive.content)
            val refreshed = assertEnvelope(request(server, "$path/snapshot", headers = headers), 200, "snapshot")
            val replayFirst = assertEnvelope(request(server,
                "$path/events?limit=1&cursor=${refreshed.getValue("oldestCursor").jsonPrimitive.content}", headers = headers), 200, "events")
            assertEquals("0", replayFirst.getValue("items").jsonArray.single().jsonObject.getValue("sequence").jsonPrimitive.content)
            val retainedFirstCursor = replayFirst.getValue("nextCursor").jsonPrimitive.content
            val appended = assertEnvelope(request(server, "$path/events?cursor=$retainedFirstCursor", headers = headers), 200, "events")
            assertEquals(listOf("1", "2"), appended.getValue("items").jsonArray.map {
                it.jsonObject.getValue("sequence").jsonPrimitive.content
            })
            assertFalse((replayFirst.toString() + appended.toString()).contains("PRIVATE_HTTP_"))
            val rewrittenBytes = Files.readString(journalFile)
            assertFalse(rewrittenBytes.contains("PRIVATE_HTTP_"))
            val journal = Json.parseToJsonElement(rewrittenBytes).jsonObject
            Files.writeString(journalFile, JsonObject(journal + mapOf(
                "historyDropped" to JsonPrimitive(1), "truncated" to JsonPrimitive(true),
                "events" to kotlinx.serialization.json.JsonArray(journal.getValue("events").jsonArray.drop(1)),
                // A writer that evicted history would republish its exact omission ranges.
                "omittedSequenceRanges" to kotlinx.serialization.json.buildJsonArray {
                    add(kotlinx.serialization.json.buildJsonObject {
                        put("startInclusive", JsonPrimitive("0")); put("endExclusive", JsonPrimitive("1"))
                    })
                },
            )).toString())
            val gapResponse = request(server, "$path/events?cursor=$retainedFirstCursor", headers = headers)
            assertError(gapResponse, 410, "EVENT_GAP")
            val recovery = Json.parseToJsonElement(gapResponse.body()).jsonObject.getValue("error").jsonObject.getValue("recovery").jsonObject
            assertEquals(retainedFirstCursor, recovery.getValue("requestedCursor").jsonPrimitive.content)
            assertEquals("$path/snapshot", recovery.getValue("snapshotHref").jsonPrimitive.content)
            assertEquals(job.id, recovery.getValue("jobId").jsonPrimitive.content)
            val fresh = assertEnvelope(request(server, "$path/snapshot", headers = headers), 200, "snapshot")
            assertEquals(fresh.getValue("oldestCursor"), recovery.getValue("oldestCursor"))
            assertEquals(fresh.getValue("throughCursor"), recovery.getValue("latestCursor"))
            assertEquals("1", fresh.getValue("progress").jsonObject.getValue("historyDropped").jsonPrimitive.content)
            assertEquals("2", fresh.getValue("progress").jsonObject.getValue("retainedEventCount").jsonPrimitive.content)
            Files.delete(journalFile)
            assertError(request(server, "$path/snapshot", headers = headers), 503, "PROGRESS_UNAVAILABLE")
            assertError(request(server, "$path/events", headers = headers), 503, "PROGRESS_UNAVAILABLE")
            assertFalse(executed)
        } finally { server.stop(); root.toFile().deleteRecursively() }
    }

    @Test
    fun `attempt build logs are bounded redacted ranges and the download shares their text`() {
        val root = createTempDirectory("web-run-log-http-")
        val job = JobStore(root).createFromUpload("inert.elf", elfFixture())
        val other = JobStore(root).createFromUpload("other.elf", elfFixture())
        val run = decompengine.jobs.WorkflowAttemptStore.open(root).use { owner ->
            val original = (owner.inspect(job.id) as decompengine.jobs.WorkflowJobInspection.Available).snapshot
            owner.create(job.id, original.version, decompengine.jobs.NewWorkflowAttempt(
                decompengine.jobs.WorkflowKind.RECONSTRUCT,
                decompengine.jobs.WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u),
            )).attempt
        }
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("Unexpected analysis") },
            JobReconstructor { _, _ -> error("Unexpected reconstruction") }, uiMode = WebUiMode.SPA, basePath = "/workbench/")
        server.start()
        try {
            val path = "/workbench/api/v1/jobs/${job.id}/runs/${run.runId}/logs/build"
            assertError(request(server, path), 401, "SESSION_REQUIRED")
            val headers = mapOf("Cookie" to establish(server))
            val missing = assertEnvelopeRaw(request(server, path, headers = headers), "logRange")
            assertEquals("missing", missing.getValue("state").jsonPrimitive.content)
            assertError(request(server, "$path/content", headers = headers + ("Accept" to "text/plain")), 404, "NOT_FOUND")
            val log = Files.createDirectories(root.resolve(job.id).resolve("reports/runs/${run.runId}/source-tree/reports")).resolve("build.log")
            val storeRoot = root.toAbsolutePath().normalize().toString()
            Files.writeString(log, (1..300).joinToString("\n") { "cc -c $storeRoot/m$it.c \u001b[31merror\u001b[0m" } + "\n")
            val tail = assertEnvelopeRaw(request(server, "$path?tail=true&limit=50&search=m299.c", headers = headers), "logRange")
            assertEquals("available", tail.getValue("state").jsonPrimitive.content)
            assertEquals("251", tail.getValue("range").jsonObject.getValue("firstLine").jsonPrimitive.content)
            assertEquals("300", tail.getValue("redactedLines").jsonPrimitive.content)
            assertEquals(listOf("299"), tail.getValue("search").jsonObject.getValue("matches").jsonArray.map { it.jsonPrimitive.content })
            val body = tail.toString()
            assertFalse(body.contains(storeRoot)); assertFalse(body.contains("\\u001b"))
            val lines = tail.getValue("lines").jsonArray.map { it.jsonObject.getValue("text").jsonPrimitive.content }
            assertEquals("cc -c [job-store]/m251.c \\e[31merror\\e[0m", lines.first())
            assertError(request(server, "$path?tail=true&fromLine=2", headers = headers), 422, "VALIDATION_FAILED")
            assertError(request(server, "$path?pattern=.*", headers = headers), 422, "VALIDATION_FAILED")
            assertError(request(server, "/workbench/api/v1/jobs/${other.id}/runs/${run.runId}/logs/build", headers = headers), 404, "NOT_FOUND")
            val download = request(server, "$path/content", headers = headers + ("Accept" to "text/plain"))
            assertEquals(200, download.statusCode())
            assertTrue(download.headers().firstValue("Content-Type").orElseThrow().startsWith("text/plain"))
            assertTrue(download.headers().firstValue("Content-Disposition").orElseThrow().contains("build-${run.runId}.log"))
            assertFalse(download.body().contains(storeRoot))
            assertTrue(download.body().contains("# job ${job.id} attempt ${run.runId}"))
            assertTrue(download.body().contains(lines.first() + "\n"))
            assertError(request(server, "$path/content", headers = headers + mapOf("Accept" to "text/plain", "Range" to "bytes=0-1")), 400, "UNSUPPORTED_HEADER")
            Files.write(log, ByteArray(1_000_001) { '\n'.code.toByte() })
            assertEquals("oversized", assertEnvelopeRaw(request(server, "$path?tail=true&limit=1", headers = headers), "logRange")
                .getValue("state").jsonPrimitive.content)
            assertError(request(server, "$path/content", headers = headers + ("Accept" to "text/plain")), 413, "LOG_TOO_LARGE")
        } finally { server.stop(); root.toFile().deleteRecursively() }
    }

    /** Envelope for oneOf documents whose field set depends on their state. */
    private fun assertEnvelopeRaw(response: HttpResponse<String>, kind: String): JsonObject {
        assertEquals(200, response.statusCode(), response.body())
        val body = Json.parseToJsonElement(response.body()).jsonObject
        assertEquals(kind, body.getValue("kind").jsonPrimitive.content)
        return body.getValue("data").jsonObject
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
            val downloadHeaders = mapOf("Cookie" to cookie, "Accept" to "application/octet-stream")
            assertError(request(server, href), 401, "SESSION_REQUIRED")
            val download = request(server, href, headers = downloadHeaders)
            assertEquals(200, download.statusCode()); assertEquals(raw, download.body())
            assertEquals(raw, request(server, href, headers = downloadHeaders + ("Accept" to "*/*")).body())
            assertEquals("application/octet-stream", download.headers().firstValue("Content-Type").orElseThrow())
            assertTrue(download.headers().firstValue("Content-Disposition").orElseThrow().startsWith("attachment;"))
            assertEquals("nosniff", download.headers().firstValue("X-Content-Type-Options").orElseThrow())
            assertEquals(WEB_INERT_CONTENT_SECURITY_POLICY, download.headers().firstValue("Content-Security-Policy").orElseThrow())
            assertEquals("DENY", download.headers().firstValue("X-Frame-Options").orElseThrow())
            assertEquals("no-referrer", download.headers().firstValue("Referrer-Policy").orElseThrow())
            val head = request(server, href, "HEAD", headers = downloadHeaders)
            assertEquals(200, head.statusCode()); assertEquals("", head.body())
            assertEquals(raw.toByteArray().size.toString(), head.headers().firstValue("Content-Length").orElseThrow())
            assertError(request(server, href, headers = downloadHeaders + ("Range" to "bytes=0-2")), 400, "UNSUPPORTED_HEADER")
            Files.writeString(reportFile, "changed")
            assertError(request(server, href, headers = downloadHeaders), 409, "ARTIFACT_CHANGED")
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
            // Hidden controls do not authorize a direct start or a different harness.
            for (workflow in listOf("explore", "reconstruct", "build", "validate", "repair")) {
                for (harness in listOf("\"harness_acp\"", "\"harness_builtin\"", "null")) {
                    val start = """{"workflow":"$workflow","inputRevisionId":null,"harnessCapabilityId":$harness,"limits":{"wallClockMs":"60000","idleMs":"15000","maxOutputBytes":"1048576","maxToolCalls":"16"}}"""
                    assertError(request(server, "/workbench/api/v1/jobs/${job.id}/runs", "POST", start, mapOf(
                        "Cookie" to cookie, "X-CSRF-Token" to bootstrap.getValue("csrfToken").jsonPrimitive.content,
                    )), 405, "METHOD_NOT_ALLOWED")
                    assertEquals(before, Files.readString(record), "$workflow/$harness changed durable state")
                    assertFalse(executed, "$workflow/$harness executed an adapter")
                }
            }
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
        val recovery = assertEnvelope(request(server, "/workbench/api/v1/recovery", headers = mapOf("Cookie" to cookie)), 200, "recovery")
        assertEquals("true", recovery.getValue("displayOnly").toString())
        assertFalse(recovery.toString().contains("PRIVATE_CORRUPT") || recovery.toString().contains(record.toString()))
        assertError(request(server, "/workbench/api/v1/jobs", headers = mapOf("Cookie" to cookie)), 503, "CORRUPT_LEGACY_JOB")
        assertEquals("PRIVATE_CORRUPT_RECORD_SENTINEL {", Files.readString(record))
    }

    @Test
    fun `v1 job reads reject private persisted ELF categories with a fixed diagnostic and unchanged bytes`() = withServer { server, store, jobId ->
        val cookie = establish(server)
        val headers = mapOf("Cookie" to cookie)
        val record = store.get(jobId).binaryPath.parent.resolve("job.json")
        val original = Json.parseToJsonElement(Files.readString(record)).jsonObject
        val originalMetadata = original.getValue("metadata").jsonObject
        val canary = "ENV_SECRET=/PRIVATE_HOST_ROOT IllegalStateException"
        for (field in listOf("format", "endianness", "os_abi", "object_type", "machine")) {
            val metadata = JsonObject(originalMetadata + (field to JsonPrimitive(canary)))
            val injected = JsonObject(original + ("metadata" to metadata)).toString().toByteArray()
            Files.write(record, injected)
            val detail = request(server, "/workbench/api/v1/jobs/$jobId", headers = headers)
            val list = request(server, "/workbench/api/v1/jobs", headers = headers)
            assertError(detail, 503, "JOB_RECORD_UNAVAILABLE")
            assertError(list, 503, "JOB_RECORD_UNAVAILABLE")
            for (response in listOf(detail, list)) {
                assertFalse(response.body().contains(canary))
                assertFalse(response.body().contains(record.toString()))
            }
            kotlin.test.assertContentEquals(injected, Files.readAllBytes(record))
        }
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
    fun `authenticated streamed upload returns durable identity and replays without overwriting later status`() = withServer { server, store, existingJobId ->
        val cookie = establish(server)
        val csrf = assertEnvelope(request(server, "/workbench/api/v1/bootstrap", headers = mapOf("Cookie" to cookie)), 200, "bootstrap")
            .getValue("csrfToken").jsonPrimitive.content
        val key = "fixture_upload_api_key"
        val headers = mapOf("Cookie" to cookie, "X-CSRF-Token" to csrf, "Idempotency-Key" to key)
        val existingRecord = Files.readAllBytes(store.storageRoot.resolve(existingJobId).resolve("job.json"))
        assertError(upload(server, elfFixture(), emptyMap()), 401, "SESSION_REQUIRED")
        assertError(upload(server, elfFixture(), headers - "X-CSRF-Token"), 403, "CSRF_DENIED")
        assertError(upload(server, elfFixture(), headers - "Idempotency-Key"), 400, "INVALID_IDEMPOTENCY_KEY")
        assertError(upload(server, elfFixture(), headers + ("Origin" to "http://invalid.example")), 403, "ORIGIN_DENIED")
        assertError(upload(server, byteArrayOf(1, 2, 3), headers), 422, "INVALID_ELF")
        assertEquals(listOf(existingJobId), store.jobIds())
        kotlin.test.assertContentEquals(existingRecord,
            Files.readAllBytes(store.storageRoot.resolve(existingJobId).resolve("job.json")))
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
    fun `versioned uncertain upload retains reconciliation location and replays only after restart`() {
        val temporaryRoot = Files.createDirectories(Path.of("build/test-tmp/web-upload-uncertainty").toAbsolutePath())
        val root = createTempDirectory(temporaryRoot, "v1-")
        val store = JobStore(root)
        val bytes = elfFixture()
        val prior = decompengine.jobs.WorkflowAttemptStore.open(root).use {
            store.createFromUpload("prior.elf", bytes)
        }
        val priorMetadata = Files.readAllBytes(root.resolve(prior.id).resolve("job.json"))
        val privateDiagnostic = "PRIVATE_UNCERTAIN_UPLOAD_FILESYSTEM_FAILURE"
        var executions = 0
        fun start() = UploadServer("127.0.0.1", 0, root,
            JobAnalyzer { _, _ -> executions++; error("Unexpected analysis") },
            JobReconstructor { _, _ -> executions++; error("Unexpected reconstruction") },
            uiMode = WebUiMode.SPA, basePath = "/workbench/").also { it.start() }
        fun headers(server: UploadServer): Map<String, String> {
            val cookie = establish(server)
            val bootstrap = assertEnvelope(request(server, "/workbench/api/v1/bootstrap", headers = mapOf("Cookie" to cookie)), 200, "bootstrap")
            return mapOf("Cookie" to cookie, "X-CSRF-Token" to bootstrap.getValue("csrfToken").jsonPrimitive.content,
                "Idempotency-Key" to "versioned_uncertain_upload_key")
        }
        fun priorUnchanged() {
            kotlin.test.assertContentEquals(priorMetadata, Files.readAllBytes(root.resolve(prior.id).resolve("job.json")))
            kotlin.test.assertContentEquals(bytes, Files.readAllBytes(prior.binaryPath))
            assertEquals(0, executions)
        }
        var server = start()
        try {
            val service = UploadServer::class.java.getDeclaredField("jobs").apply { isAccessible = true }.get(server) as WebJobService
            service.uploadPublisher = decompengine.jobs.StagedJobUpload(root, fault = { point ->
                if (point == decompengine.jobs.UploadPublishPoint.AFTER_RENAME) throw java.io.IOException(privateDiagnostic)
            })
            val firstHeaders = headers(server)
            val response = upload(server, bytes, firstHeaders)
            val problem = assertEnvelope(response, 409, "error")
            assertEquals("RECOVERY_REQUIRED", problem.getValue("code").jsonPrimitive.content)
            assertEquals("false", problem.getValue("retryable").toString())
            assertEquals("null", problem.getValue("retryAfterMs").toString())
            assertTrue(problem.getValue("details").jsonArray.isEmpty())
            assertEquals(null, response.headers().firstValue("Retry-After").orElse(null))
            val location = response.headers().firstValue("Location").orElseThrow()
            val id = location.substringAfterLast('/')
            assertTrue(id.matches(Regex("[a-f0-9]{32}")))
            assertEquals("/workbench/api/v1/jobs/$id", location)
            assertFalse(response.body().contains(privateDiagnostic))
            assertFalse(response.body().contains(root.toString()))
            assertEquals(setOf(prior.id, id), store.jobIds().toSet())
            val published = store.get(id)
            assertEquals("uploaded", published.status)
            kotlin.test.assertContentEquals(bytes, Files.readAllBytes(published.binaryPath))
            val publishedMetadata = Files.readAllBytes(root.resolve(id).resolve("job.json"))
            priorUnchanged()

            val denied = request(server, location)
            assertError(denied, 401, "SESSION_REQUIRED")
            assertFalse(denied.body().contains(id))
            val pendingRead = request(server, location, headers = mapOf("Cookie" to firstHeaders.getValue("Cookie")))
            assertError(pendingRead, 503, "RECOVERY_REQUIRED")
            assertEquals(null, pendingRead.headers().firstValue("Location").orElse(null))
            assertFalse(pendingRead.body().contains(privateDiagnostic))
            assertFalse(pendingRead.body().contains(root.toString()))
            val blocked = upload(server, bytes, firstHeaders)
            assertError(blocked, 503, "RECOVERY_REQUIRED")
            assertEquals(null, blocked.headers().firstValue("Location").orElse(null))
            assertEquals(null, blocked.headers().firstValue("Retry-After").orElse(null))
            assertEquals(setOf(prior.id, id), store.jobIds().toSet())
            kotlin.test.assertContentEquals(publishedMetadata, Files.readAllBytes(root.resolve(id).resolve("job.json")))
            priorUnchanged()

            server.stop()
            server = start()
            val reopenedHeaders = headers(server)
            val reconciled = assertEnvelope(request(server, location,
                headers = mapOf("Cookie" to reopenedHeaders.getValue("Cookie"))), 200, "job")
            assertEquals(id, reconciled.getValue("jobId").jsonPrimitive.content)
            assertEquals("uploaded", reconciled.getValue("status").jsonPrimitive.content)
            val replay = upload(server, bytes, reopenedHeaders)
            assertEquals(id, assertEnvelope(replay, 201, "job").getValue("jobId").jsonPrimitive.content)
            assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
            assertEquals(location, replay.headers().firstValue("Location").orElseThrow())
            assertEquals(setOf(prior.id, id), store.jobIds().toSet())
            kotlin.test.assertContentEquals(publishedMetadata, Files.readAllBytes(root.resolve(id).resolve("job.json")))
            kotlin.test.assertContentEquals(bytes, Files.readAllBytes(published.binaryPath))
            priorUnchanged()
        } finally {
            server.stop()
            root.toFile().deleteRecursively()
        }
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

    @Test
    fun `v1 errors connect response IDs to redacted server diagnostics`() {
        val diagnostics = CopyOnWriteArrayList<String>()
        fun awaitDiagnostic(expected: Int) {
            val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(2)
            while (diagnostics.size < expected && System.nanoTime() < deadline) Thread.yield()
            assertEquals(expected, diagnostics.size)
        }
        withServer(requestDiagnosticOutput = { diagnostics += it }) { server, _, jobId ->
            val canary = "private_root_and_token_canary"
            val path = "/workbench/api/v1/jobs/$jobId?untrusted=$canary"
            val unauthenticated = request(server, path)
            assertError(unauthenticated, 401, "SESSION_REQUIRED")
            awaitDiagnostic(1)
            val deniedId = unauthenticated.headers().firstValue("X-Request-ID").orElseThrow()
            assertEquals("web-http-failure request_id=$deniedId status=401 code=SESSION_REQUIRED", diagnostics.single())
            val cookie = establish(server)
            val rejectedQuery = request(server, path, headers = mapOf("Cookie" to cookie))
            assertError(rejectedQuery, 400, "VALIDATION_FAILED")
            awaitDiagnostic(2)
            val rejectedId = rejectedQuery.headers().firstValue("X-Request-ID").orElseThrow()
            assertEquals("web-http-failure request_id=$rejectedId status=400 code=VALIDATION_FAILED", diagnostics.last())
            assertEquals(2, diagnostics.size)
            assertNotEquals(deniedId, rejectedId)
            assertFalse(diagnostics.joinToString().contains(canary))
            assertFalse(unauthenticated.body().contains(canary))
            assertFalse(rejectedQuery.body().contains(canary))
        }
    }

    @Test
    fun `legacy JSON failures share the response ID with redacted server diagnostics`() {
        val diagnostics = CopyOnWriteArrayList<String>()
        val root = createTempDirectory("web-legacy-request-diagnostic-")
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("Unexpected analysis") },
            JobReconstructor { _, _ -> error("Unexpected reconstruction") },
            requestDiagnosticOutput = { diagnostics += it })
        server.start()
        try {
            val canary = "private_query_canary"
            val response = request(server, "/api/jobs/${"a".repeat(32)}?untrusted=$canary")
            assertEquals(401, response.statusCode())
            val body = Json.parseToJsonElement(response.body()).jsonObject
            val id = body.getValue("requestId").jsonPrimitive.content
            assertEquals(id, response.headers().firstValue("X-Request-ID").orElseThrow())
            assertEquals("SESSION_REQUIRED", body.getValue("error").jsonObject.getValue("code").jsonPrimitive.content)
            val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(2)
            while (diagnostics.isEmpty() && System.nanoTime() < deadline) Thread.yield()
            assertEquals("web-http-failure request_id=$id status=401 code=SESSION_REQUIRED", diagnostics.single())
            assertFalse(diagnostics.single().contains(canary))
            assertFalse(response.body().contains(canary))
        } finally { server.stop(); root.toFile().deleteRecursively() }
    }

    private fun upload(server: UploadServer, bytes: ByteArray, headers: Map<String, String>, filename: String = "fixture.elf", boundary: String = "upload_api_fixture", path: String = "/workbench/api/v1/jobs"): HttpResponse<String> {
        val origin = "http://127.0.0.1:${server.serverPort}"
        val body = "--$boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"$filename\"\r\n\r\n".toByteArray() + bytes + "\r\n--$boundary--\r\n".toByteArray()
        val builder = HttpRequest.newBuilder(URI("$origin$path"))
            .POST(HttpRequest.BodyPublishers.ofInputStream { body.inputStream() }) // chunked; no Content-Length authority
        (mapOf("Accept" to "application/json", "Origin" to origin, "Content-Type" to "multipart/form-data; boundary=$boundary") + headers)
            .forEach { (key, value) -> builder.header(key, value) }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString()).also(::assertNoWebCors)
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
        assertEquals("nosniff", response.headers().firstValue("X-Content-Type-Options").orElseThrow())
        assertEquals("DENY", response.headers().firstValue("X-Frame-Options").orElseThrow())
        assertEquals(WEB_INERT_CONTENT_SECURITY_POLICY,
            response.headers().firstValue("Content-Security-Policy").orElseThrow())
        val body = Json.parseToJsonElement(response.body()).jsonObject
        assertEquals("1", body.getValue("apiVersion").toString())
        assertEquals(kind, body.getValue("kind").jsonPrimitive.content)
        assertEquals(body.getValue("requestId").jsonPrimitive.content, response.headers().firstValue("X-Request-ID").orElseThrow())
        val schema = Json.parseToJsonElement(Files.readString(Path.of("contracts/web/v1/contract.schema.json"))).jsonObject
        if (kind == "error") {
            val error = body.getValue("error").jsonObject
            assertEquals(setOf("code", "message", "retryable", "details", "retryAfterMs") +
                if (error.getValue("code").jsonPrimitive.content == "EVENT_GAP") setOf("recovery") else emptySet(), error.keys)
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
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString()).also(::assertNoWebCors)
    }

    private fun withServer(requestDiagnosticOutput: (String) -> Unit = System.err::println,
                           block: (UploadServer, JobStore, String) -> Unit) {
        val temporaryRoot = Files.createDirectories(Path.of("build/test-tmp/web-api").toAbsolutePath())
        val root = createTempDirectory(temporaryRoot, "web-api-")
        val store = JobStore(root)
        val binary = elfFixture().also { bytes -> repeat(8) { bytes[24 + it] = 0xff.toByte() } }
        val job = store.createFromUpload("synthetic.elf", binary)
        store.updateStatus(job.id, "uploaded", "PRIVATE_STATUS_SENTINEL")
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("Unexpected analysis") },
            JobReconstructor { _, _ -> error("Unexpected reconstruction") }, uiMode = WebUiMode.SPA, basePath = "/workbench/",
            requestDiagnosticOutput = requestDiagnosticOutput)
        server.start()
        try { block(server, store, job.id) } finally { server.stop(); root.toFile().deleteRecursively() }
    }
}
