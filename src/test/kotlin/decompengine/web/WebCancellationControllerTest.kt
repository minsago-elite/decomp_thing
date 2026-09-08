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

class WebCancellationControllerTest {
    private class Fixture : AutoCloseable {
        val root = Files.createTempDirectory("web-cancel-http-")
        val store = JobStore(root)
        val job = store.createFromUpload("inert.elf", elfFixture())
        lateinit var owner: WorkflowAttemptStore
        var fault: WorkflowStoreFaultPoint? = null
        val pending = mutableListOf<Runnable>()
        val service = WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected analysis") }, JobReconstructor { _, _ -> error("Unexpected reconstruction") },
            executor = java.util.concurrent.Executor { pending += it },
            durableAdapters = listOf(object : DurableWebWorkflowAdapter {
                override val workflow = WorkflowKind.RECONSTRUCT
                override val limits = WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u)
                override fun execute(context: DurableWebWorkflowContext): DurableWebWorkflowOutcome = error("Unexpected fixture execution")
            }), attemptStoreFactory = { WorkflowAttemptStore.open(it, java.time.Clock.systemUTC(), WorkflowStoreFaultInjector { point ->
                if (point == fault) throw java.io.IOException("PRIVATE_CANCEL_HTTP_CANARY")
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
            val started = assertIs<DurableWebWorkflowAdmission.Started>(service.startDurable(job.id, snapshot.version, DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT)))
            run = service.getAttempt(job.id, started.runId)
            path = "/workbench/api/v1/jobs/${job.id}/runs/${run.runId}/cancellation"
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
        fun headers(version: String = run.version, key: String = "http_cancel_intent_0001") = mapOf("Cookie" to cookie, "Origin" to origin,
            "Content-Type" to "application/json", "X-CSRF-Token" to csrf, "If-Match" to "\"$version\"", "Idempotency-Key" to key)
        fun snapshot() = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
        override fun close() {
            fault = null; server.stop(0); resources.close(); workers.shutdownNow()
            check(workers.awaitTermination(5, TimeUnit.SECONDS)); client.close(); access.close(); service.close(); root.toFile().deleteRecursively()
        }
    }

    private fun data(response: HttpResponse<String>): JsonObject {
        assertEquals(200, response.statusCode(), response.body())
        val envelope = Json.parseToJsonElement(response.body()).jsonObject
        assertEquals(JsonPrimitive("cancellation"), envelope["kind"])
        val data = envelope.getValue("data").jsonObject
        assertEquals(setOf("current", "acknowledgement", "replayed"), data.keys)
        assertEquals(setOf("expectedVersion", "appliedVersion", "state", "recordedAt"), data.getValue("acknowledgement").jsonObject.keys)
        val current = data.getValue("current").jsonObject
        assertEquals("\"${current.getValue("version").jsonPrimitive.content}\"", response.headers().firstValue("ETag").orElseThrow())
        assertFalse(response.body().contains("actorDigest")); assertFalse(response.body().contains("requestKeyDigest"))
        return data
    }
    private fun error(response: HttpResponse<String>, status: Int, code: String? = null) {
        assertEquals(status, response.statusCode(), response.body())
        if (code != null) assertEquals(code, Json.parseToJsonElement(response.body()).jsonObject.getValue("error").jsonObject.getValue("code").jsonPrimitive.content)
        assertFalse(response.body().contains("PRIVATE_CANCEL_HTTP_CANARY"))
    }

    @Test fun `authenticated cancellation distinguishes acknowledgement from terminal state and replay uses current ETag`() = Fixture().use { f ->
        val first = data(f.send("PUT", "{\"action\":\"cancel\"}", f.headers()))
        assertEquals(JsonPrimitive("cancelling"), first.getValue("acknowledgement").jsonObject["state"])
        val current = first.getValue("current").jsonObject
        assertEquals(JsonPrimitive("cancelled"), current["state"])
        assertEquals(JsonPrimitive("not-evaluated"), current["acceptance"])
        val pinned = f.service.setProgressRetentionPinned(f.job.id, f.run.runId, current.getValue("version").jsonPrimitive.content, true)
        val bytes = f.root.resolve("${f.job.id}/workflow-state.json").readBytes()
        val response = f.send("PUT", " { \"action\" : \"cancel\" } ", f.headers())
        val replay = data(response)
        assertEquals("true", response.headers().firstValue("Idempotency-Replayed").orElseThrow())
        assertEquals(JsonPrimitive(true), replay["replayed"])
        assertEquals(first["acknowledgement"], replay["acknowledgement"])
        assertEquals(JsonPrimitive(pinned.version), replay.getValue("current").jsonObject["version"])
        assertContentEquals(bytes, f.root.resolve("${f.job.id}/workflow-state.json").readBytes())
        error(f.send("PUT", "{\"action\":\"cancel\"}", f.headers(pinned.version)), 409, "IDEMPOTENCY_CONFLICT")
        error(f.send("PUT", "{\"action\":\"cancel\"}", f.headers(key = "http_cancel_new_stale")), 412, "VERSION_CONFLICT")
        f.pending.single().run()
        assertContentEquals(bytes, f.root.resolve("${f.job.id}/workflow-state.json").readBytes())
    }

    @Test fun `authorization and bounded closed command validation precede receipt publication`() = Fixture().use { f ->
        val bytes = f.root.resolve("${f.job.id}/workflow-state.json").readBytes()
        val body = "{\"action\":\"cancel\"}"
        error(f.send("PUT", body, f.headers() - "Cookie"), 401)
        error(f.send("PUT", body, f.headers() - "X-CSRF-Token"), 403)
        error(f.send("PUT", body, f.headers() + ("Origin" to "http://foreign.invalid")), 403)
        error(f.send("PUT", body, f.headers() + ("Content-Type" to "text/plain")), 415)
        error(f.send("PUT", body, f.headers() - "If-Match"), 428)
        error(f.send("PUT", body, f.headers() + ("If-Match" to "*")), 400)
        error(f.send("PUT", body, f.headers() - "Idempotency-Key"), 400)
        error(f.send("POST", body, f.headers()), 405)
        error(f.send("PUT", body, f.headers(), f.path + "?actor=foreign"), 400)
        error(f.send("PUT", "{}", f.headers()), 400)
        error(f.send("PUT", "{\"action\":\"cancel\",\"actor\":\"foreign\"}", f.headers()), 400)
        error(f.send("PUT", " ".repeat(1025), f.headers()), 413)
        error(f.send("PUT", body, f.headers(), f.path.replace(f.run.runId, "run_foreign")), 404)
        assertContentEquals(bytes, f.root.resolve("${f.job.id}/workflow-state.json").readBytes())
        assertEquals(WorkflowRunState.QUEUED, f.service.getAttempt(f.job.id, f.run.runId).state)
    }

    @Test fun `revoked sessions cannot retrieve a retained cancellation acknowledgement`() = Fixture().use { f ->
        data(f.send("PUT", "{\"action\":\"cancel\"}", f.headers()))
        val bytes = f.root.resolve("${f.job.id}/workflow-state.json").readBytes()
        assertEquals(204, f.send("DELETE", null, f.headers(), "/workbench/api/v1/session").statusCode())
        error(f.send("PUT", "{\"action\":\"cancel\"}", f.headers()), 401)
        assertContentEquals(bytes, f.root.resolve("${f.job.id}/workflow-state.json").readBytes())
    }

    private fun policy(response: HttpResponse<String>, eligible: Boolean, reason: String?): JsonObject {
        assertEquals(200, response.statusCode(), response.body())
        val envelope = Json.parseToJsonElement(response.body()).jsonObject
        assertEquals(JsonPrimitive("cancellationPolicy"), envelope["kind"])
        val data = envelope.getValue("data").jsonObject
        assertEquals(setOf("current", "eligible", "reasonCode"), data.keys)
        assertEquals(JsonPrimitive(eligible), data["eligible"])
        assertEquals(reason?.let(::JsonPrimitive) ?: JsonNull, data["reasonCode"])
        val current = data.getValue("current").jsonObject
        assertEquals("\"${current.getValue("version").jsonPrimitive.content}\"", response.headers().firstValue("ETag").orElseThrow())
        return current
    }

    @Test fun `authenticated policy reads do not publish commands and terminal attempts are ineligible`() = Fixture().use { f ->
        val bytes = f.root.resolve("${f.job.id}/workflow-state.json").readBytes()
        error(f.send(), 401)
        val current = policy(f.send(headers = mapOf("Cookie" to f.cookie)), true, null)
        assertEquals(JsonPrimitive(f.run.runId), current["runId"])
        assertEquals(JsonPrimitive(f.run.version), current["version"])
        error(f.send(headers = mapOf("Cookie" to f.cookie, "If-Match" to "\"${f.run.version}\"")), 400)
        assertContentEquals(bytes, f.root.resolve("${f.job.id}/workflow-state.json").readBytes())
        data(f.send("PUT", "{\"action\":\"cancel\"}", f.headers()))
        val cancelled = f.root.resolve("${f.job.id}/workflow-state.json").readBytes()
        policy(f.send(headers = mapOf("Cookie" to f.cookie)), false, "ATTEMPT_TERMINAL")
        assertContentEquals(cancelled, f.root.resolve("${f.job.id}/workflow-state.json").readBytes())
    }

    @Test fun `policy distinguishes unowned work and receipt capacity without leaking other attempt data`() = Fixture().use { f ->
        val other = f.store.createFromUpload("orphan.elf", elfFixture())
        val snapshot = (f.owner.inspect(other.id) as WorkflowJobInspection.Available).snapshot
        val orphan = f.owner.create(other.id, snapshot.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
            WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
        val orphanPath = f.path.replace(f.job.id, other.id).replace(f.run.runId, orphan.runId)
        val orphanBytes = f.root.resolve("${other.id}/workflow-state.json").readBytes()
        policy(f.send(headers = mapOf("Cookie" to f.cookie), target = orphanPath), false, "NO_OWNED_WORKER")
        assertContentEquals(orphanBytes, f.root.resolve("${other.id}/workflow-state.json").readBytes())
        val terminal = f.service.cancelDurable(f.job.id, f.run.runId, f.run.version)
        val actor = WorkflowCancellationActor.browserSession("a".repeat(64))
        repeat(WorkflowCancellationReceipts.MAX_ENTRIES) { index ->
            f.owner.requestCancellation(f.job.id, terminal.runId, terminal.version, actor, "policy_capacity_key_$index")
        }
        val started = assertIs<DurableWebWorkflowAdmission.Started>(f.service.startDurable(f.job.id, f.snapshot().version,
            DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT)))
        val next = f.service.getAttempt(f.job.id, started.runId)
        val nextPath = f.path.replace(f.run.runId, next.runId)
        val bytes = f.root.resolve("${f.job.id}/workflow-state.json").readBytes()
        val response = f.send(headers = mapOf("Cookie" to f.cookie), target = nextPath)
        policy(response, false, "CANCELLATION_RECEIPT_CAPACITY")
        assertFalse(response.body().contains(orphan.runId)); assertFalse(response.body().contains("actorDigest"))
        error(f.send("PUT", "{\"action\":\"cancel\"}", f.headers(next.version), nextPath), 429, "CANCELLATION_RECEIPT_CAPACITY")
        assertContentEquals(bytes, f.root.resolve("${f.job.id}/workflow-state.json").readBytes())
    }

}
