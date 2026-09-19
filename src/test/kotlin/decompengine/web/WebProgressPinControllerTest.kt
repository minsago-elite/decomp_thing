package decompengine.web

import com.sun.net.httpserver.HttpServer
import decompengine.jobs.*
import kotlinx.serialization.json.*
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.*
import java.nio.file.Files
import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.io.path.readBytes
import kotlin.test.*

class WebProgressPinControllerTest {
    private class Fixture : AutoCloseable {
        val root = Files.createTempDirectory("web-pin-http-")
        val store = JobStore(root)
        val job = store.createFromUpload("inert.elf", elfFixture())
        lateinit var owner: WorkflowAttemptStore
        var fault: WorkflowStoreFaultPoint? = null
        val service = WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected analysis") }, JobReconstructor { _, _ -> error("Unexpected reconstruction") },
            attemptStoreFactory = { WorkflowAttemptStore.open(it, java.time.Clock.systemUTC(), WorkflowStoreFaultInjector { point ->
                if (point == fault) throw java.io.IOException("PRIVATE_PIN_HTTP_CANARY")
            }).also { opened -> owner = opened } })
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val origin = "http://127.0.0.1:${server.address.port}"
        val access = LocalWebAccess(LocalWebAccessConfiguration(origin))
        val resources = WebStreamResources()
        val workers = Executors.newFixedThreadPool(2)
        val client = HttpClient.newHttpClient()
        val run: WorkflowAttempt
        val path: String
        val cookie: String
        val csrf: String
        init {
            service.initializeExistingStorage()
            val snapshot = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            run = owner.create(job.id, snapshot.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
            path = "/workbench/api/v1/jobs/${job.id}/runs/${run.runId}/progress-pin"
            val api = WebApiController(access, EmbeddedWebAssets.load(basePath = "/workbench/"), service, resources)
            server.executor = workers; server.createContext("/") { check(api.route(it)) }; server.start()
            val token = access.issueBootstrap().token
            val session = send("POST", "{\"token\":\"$token\"}", mapOf("Origin" to origin, "Content-Type" to "application/json"), "/workbench/api/v1/session")
            check(session.statusCode() == 200)
            cookie = session.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            csrf = Json.parseToJsonElement(session.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
        }
        fun send(method: String = "GET", body: String? = null, headers: Map<String, String> = emptyMap(), target: String = path): HttpResponse<String> {
            val b = HttpRequest.newBuilder(URI(origin + target)).timeout(Duration.ofSeconds(5)).method(method,
                body?.let { HttpRequest.BodyPublishers.ofInputStream { it.byteInputStream() } } ?: HttpRequest.BodyPublishers.noBody())
            b.header("Accept", "application/json"); headers.forEach { (k, v) -> b.header(k, v) }
            return client.send(b.build(), HttpResponse.BodyHandlers.ofString()).also(::assertNoWebCors)
        }
        fun headers(version: String = run.version, key: String = "http_pin_intent_0001") = mapOf("Cookie" to cookie, "Origin" to origin,
            "Content-Type" to "application/json", "X-CSRF-Token" to csrf, "If-Match" to "\"$version\"", "Idempotency-Key" to key)
        fun snapshot() = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
        override fun close() {
            fault = null; server.stop(0); resources.close(); workers.shutdownNow()
            check(workers.awaitTermination(5, TimeUnit.SECONDS)); client.close(); access.close(); service.close(); root.toFile().deleteRecursively()
        }
    }
    private fun data(response: HttpResponse<String>, status: Int = 200): JsonObject {
        assertEquals(status, response.statusCode(), response.body())
        assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow())
        val root = Json.parseToJsonElement(response.body()).jsonObject
        assertEquals(root.getValue("requestId").jsonPrimitive.content, response.headers().firstValue("X-Request-ID").orElseThrow())
        assertEquals("progressPin", root.getValue("kind").jsonPrimitive.content)
        val d = root.getValue("data").jsonObject
        assertEquals(setOf("jobId", "runId", "version", "pinned"), d.keys)
        assertEquals("\"${d.getValue("version").jsonPrimitive.content}\"", response.headers().firstValue("ETag").orElseThrow())
        return d
    }
    private fun error(response: HttpResponse<String>, status: Int, code: String? = null) {
        assertEquals(status, response.statusCode(), response.body())
        if (code != null) assertEquals(code, Json.parseToJsonElement(response.body()).jsonObject.getValue("error").jsonObject.getValue("code").jsonPrimitive.content)
        assertFalse(response.body().contains("PRIVATE_PIN_HTTP_CANARY"))
    }

    @Test fun `authenticated pin and replay expose original result while GET exposes current policy`() = Fixture().use { f ->
        error(f.send(), 401)
        val initial = data(f.send(headers = mapOf("Cookie" to f.cookie))); assertEquals(JsonPrimitive(false), initial["pinned"])
        val applied = data(f.send("PUT", "{\"pinned\":true}", f.headers()))
        assertEquals(JsonPrimitive(true), applied["pinned"])
        val version = applied.getValue("version").jsonPrimitive.content
        val receipt = f.snapshot().pinAudit.entries.single()
        assertEquals("browser_session", receipt.actor.kind); assertNotNull(receipt.actor.sessionDigest)
        assertFalse(receipt.toString().contains(f.csrf)); assertFalse(receipt.toString().contains(f.cookie))
        val unpinned = data(f.send("PUT", "{\"pinned\":false}", f.headers(version, "http_pin_intent_0002")))
        val bytes = f.root.resolve("${f.job.id}/workflow-state.json").readBytes()
        val replay = f.send("PUT", " { \"pinned\" : true } ", f.headers())
        assertEquals(applied, data(replay)); assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
        assertContentEquals(bytes, f.root.resolve("${f.job.id}/workflow-state.json").readBytes())
        assertEquals(unpinned, data(f.send(headers = mapOf("Cookie" to f.cookie))))
        error(f.send("PUT", "{\"pinned\":false}", f.headers()), 409, "IDEMPOTENCY_CONFLICT")
        error(f.send("PUT", "{\"pinned\":true}", f.headers(key = "http_pin_fresh_stale")), 412, "VERSION_CONFLICT")
    }

    @Test fun `authorization and strict request validation precede any pin publication`() = Fixture().use { f ->
        val bytes = f.root.resolve("${f.job.id}/workflow-state.json").readBytes()
        error(f.send("PUT", "{\"pinned\":true}", f.headers() - "Cookie"), 401)
        error(f.send("PUT", "{\"pinned\":true}", f.headers() + ("Content-Type" to "text/plain")), 415)
        error(f.send("PUT", "{\"pinned\":true}", f.headers() - "X-CSRF-Token"), 403)
        error(f.send("PUT", "{\"pinned\":true}", f.headers() + ("Origin" to "http://foreign.invalid")), 403)
        error(f.send("PUT", "{\"pinned\":true}", f.headers() - "If-Match"), 428)
        error(f.send("PUT", "{\"pinned\":true}", f.headers() + ("If-Match" to "*")), 400)
        error(f.send("PUT", "{\"pinned\":true}", f.headers() - "Idempotency-Key"), 400)
        error(f.send("POST", "{\"pinned\":true}", f.headers()), 405)
        error(f.send("PUT", "{\"pinned\":true}", f.headers(), f.path + "?actor=foreign"), 400)
        listOf("{}", "{\"pinned\":\"true\"}", "{\"pinned\":null}", "{\"pinned\":1}", "{\"pinned\":true,\"actor\":\"PRIVATE_PIN_HTTP_CANARY\"}", "{\"pinned\":true,\"pinned\":false}").forEach {
            error(f.send("PUT", it, f.headers()), 400)
        }
        error(f.send("PUT", " ".repeat(1025), f.headers()), 413)
        error(f.send("PUT", "{\"pinned\":true}", f.headers(), f.path.replace(f.run.runId, "foreign_run")), 404)
        assertContentEquals(bytes, f.root.resolve("${f.job.id}/workflow-state.json").readBytes())
        assertTrue(f.snapshot().pinAudit.entries.isEmpty())
    }

    @Test fun `production server exposes pin policy under its prefix and persists browser attribution`() {
        val root = Files.createTempDirectory("web-pin-production-")
        val job = JobStore(root).createFromUpload("inert.elf", elfFixture())
        val run = WorkflowAttemptStore.open(root).use { owner ->
            val view = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            owner.create(job.id, view.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
        }
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("Unexpected analysis") },
            JobReconstructor { _, _ -> error("Unexpected reconstruction") }, uiMode = WebUiMode.SPA, basePath = "/tools/")
        val client = HttpClient.newHttpClient()
        try {
            server.start()
            val origin = "http://127.0.0.1:${server.serverPort}"
            fun request(path: String, method: String = "GET", body: String? = null, headers: Map<String, String> = emptyMap()): HttpResponse<String> {
                val b = HttpRequest.newBuilder(URI(origin + path)).timeout(Duration.ofSeconds(5))
                    .method(method, body?.let(HttpRequest.BodyPublishers::ofString) ?: HttpRequest.BodyPublishers.noBody())
                b.header("Accept", "application/json"); headers.forEach { (k, v) -> b.header(k, v) }
                return client.send(b.build(), HttpResponse.BodyHandlers.ofString()).also(::assertNoWebCors)
            }
            val session = request("/tools/api/v1/session", "POST", "{\"token\":\"${server.issueBrowserBootstrap().token}\"}",
                mapOf("Origin" to origin, "Content-Type" to "application/json"))
            assertEquals(200, session.statusCode())
            val cookie = session.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            val csrf = Json.parseToJsonElement(session.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
            val path = "/tools/api/v1/jobs/${job.id}/runs/${run.runId}/progress-pin"
            val current = data(request(path, headers = mapOf("Cookie" to cookie)))
            val result = request(path, "PUT", "{\"pinned\":true}", mapOf("Cookie" to cookie, "Origin" to origin,
                "Content-Type" to "application/json", "X-CSRF-Token" to csrf, "Idempotency-Key" to "production_pin_0001",
                "If-Match" to "\"${current.getValue("version").jsonPrimitive.content}\""))
            assertEquals(JsonPrimitive(true), data(result)["pinned"])
            server.stop()
            WorkflowAttemptStore.open(root).use { owner ->
                val snapshot = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
                assertTrue(snapshot.latestRun!!.progressRetentionPinned)
                assertEquals("browser_session", snapshot.pinAudit.entries.single().actor.kind)
            }
        } finally { server.stop(); client.close(); root.toFile().deleteRecursively() }
    }

    @Test fun `receipt capacity is explicit and failed publication cannot claim success`() {
        Fixture().use { f ->
            val actor = WorkflowPinActor.browserSession("d".repeat(64))
            repeat(256) { f.owner.requestProgressRetentionPinned(f.job.id, f.run.runId, f.run.version, false, actor, "fixture_key_${it.toString().padStart(16, '0')}") }
            error(f.send("PUT", "{\"pinned\":true}", f.headers()), 429, "PIN_RECEIPT_CAPACITY")
            assertFalse(f.snapshot().latestRun!!.progressRetentionPinned)
        }
        for (point in listOf(WorkflowStoreFaultPoint.AFTER_TEMP_FSYNC, WorkflowStoreFaultPoint.AFTER_RENAME)) Fixture().use { f ->
            f.fault = point
            error(f.send("PUT", "{\"pinned\":true}", f.headers()), 503,
                if (point == WorkflowStoreFaultPoint.AFTER_RENAME) "RECOVERY_REQUIRED" else "PERSISTENCE_FAILED")
        }
    }
}
