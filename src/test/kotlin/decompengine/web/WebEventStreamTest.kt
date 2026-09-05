package decompengine.web

import com.sun.net.httpserver.HttpServer
import kotlinx.serialization.json.*
import java.io.BufferedReader
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.*

class WebEventStreamTest {
    private class Fixture(lifetimeMs: Long = 5000) : AutoCloseable {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val origin = "http://127.0.0.1:${server.address.port}"
        val access = LocalWebAccess(LocalWebAccessConfiguration(origin))
        val resources = WebStreamResources(maximumConnections = 3, lifetimeMs = lifetimeMs)
        val pages = WebProgressPages()
        val bytes = AtomicReference(journal(listOf(0, 1)))
        val httpWorker = Executors.newSingleThreadExecutor()
        val stream = WebEventStream(access, resources, pages, { _, _ -> bytes.get() }, pollMs = 20, heartbeatMs = 40)
        val sessions = WebSessionController(access)
        val client = HttpClient.newHttpClient()
        val cookie: String
        val csrf: String
        init {
            server.executor = httpWorker
            server.createContext("/") { exchange ->
                try {
                    when (exchange.requestURI.path) {
                        "/session" -> sessions.handle(exchange)
                        "/health" -> { exchange.sendResponseHeaders(204, -1); exchange.close() }
                        "/poll" -> {
                            val owner = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead()))
                            sendWebApiResponse(exchange, 200, "events", pages.page(owner.sessionId, "job", "run", bytes.get(), exchange.requestURI.rawQuery))
                        }
                        else -> {
                            val owner = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead()))
                            stream.open(exchange, owner, "job", "run", "/api/v1/jobs/job/runs/run/snapshot")
                        }
                    }
                } catch (failure: WebAccessDenied) { access.sendDenied(exchange, failure) }
            }
            server.start()
            val token = access.issueBootstrap().token
            val response = client.send(HttpRequest.newBuilder(URI("$origin/session"))
                .header("Origin", origin).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"$token\"}")).build(), HttpResponse.BodyHandlers.ofString())
            check(response.statusCode() == 200)
            cookie = response.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            csrf = Json.parseToJsonElement(response.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
        }
        fun open(path: String = "/events", headers: Map<String, String> = emptyMap()): HttpResponse<java.io.InputStream> {
            val builder = HttpRequest.newBuilder(URI(origin + path)).timeout(Duration.ofSeconds(3))
            (mapOf("Cookie" to cookie, "Accept" to "text/event-stream") + headers).forEach { (k, v) -> builder.header(k, v) }
            return client.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream()).also(::assertNoWebCors)
        }
        override fun close() {
            resources.shutdown(); server.stop(0); resources.shutdown(); access.close(); httpWorker.shutdownNow()
        }
    }
    private fun frame(reader: BufferedReader): Map<String, String> = CompletableFuture.supplyAsync {
        val result = linkedMapOf<String, String>()
        while (true) {
            val line = reader.readLine() ?: error("Stream ended before an event")
            if (line.isEmpty() && "data" in result) break
            if (line.startsWith(":")) continue
            if (line.contains(": ")) result[line.substringBefore(": ")] = line.substringAfter(": ")
        }
        result
    }.get(3, TimeUnit.SECONDS)
    private fun eof(reader: BufferedReader) = CompletableFuture.supplyAsync {
        while (reader.readLine() != null) { }
        true
    }.get(3, TimeUnit.SECONDS)

    @Test fun `real SSE framing shares polling cursors and Last Event ID resumes after an acknowledged event`() = Fixture().use { f ->
        val first = f.open()
        assertEquals(200, first.statusCode())
        assertEquals("text/event-stream; charset=utf-8", first.headers().firstValue("Content-Type").orElseThrow())
        assertEquals("no-store", first.headers().firstValue("Cache-Control").orElseThrow())
        val event = first.body().bufferedReader().use(::frame)
        assertEquals("workflow.observation", event["event"])
        val data = Json.parseToJsonElement(event.getValue("data")).jsonObject
        assertEquals(event["id"], data.getValue("cursor").jsonPrimitive.content)
        assertEquals("0", data.getValue("sequence").jsonPrimitive.content)
        assertFalse(event.getValue("data").contains("PRIVATE_STREAM"))
        val resumed = f.open(headers = mapOf("Last-Event-ID" to event.getValue("id")))
        val next = resumed.body().bufferedReader().use(::frame)
        assertEquals("1", Json.parseToJsonElement(next.getValue("data")).jsonObject.getValue("sequence").jsonPrimitive.content)
        val poll = f.open("/poll?transport=poll&after=${event.getValue("id")}")
        val polled = poll.body().use { Json.parseToJsonElement(it.readBytes().decodeToString()).jsonObject }
        assertEquals(Json.parseToJsonElement(next.getValue("data")), polled.getValue("data").jsonObject.getValue("items").jsonArray.single())
    }

    @Test fun `two idle streams do not occupy the sole HTTP worker and logout closes both`() = Fixture().use { f ->
        val one = f.open(); val two = f.open()
        try {
            assertEquals(200, one.statusCode()); assertEquals(200, two.statusCode())
            val rejected = f.open()
            assertEquals(429, rejected.statusCode()); rejected.body().close()
            assertEquals(2, f.resources.snapshot().active)
            val health = f.client.send(HttpRequest.newBuilder(URI("${f.origin}/health")).timeout(Duration.ofSeconds(2)).build(), HttpResponse.BodyHandlers.discarding())
            assertEquals(204, health.statusCode())
            val logout = f.client.send(HttpRequest.newBuilder(URI("${f.origin}/session")).timeout(Duration.ofSeconds(2))
                .header("Cookie", f.cookie).header("Origin", f.origin).header("X-CSRF-Token", f.csrf)
                .header("Content-Type", "application/json").DELETE().build(), HttpResponse.BodyHandlers.discarding())
            assertEquals(204, logout.statusCode())
            assertTrue(eof(one.body().bufferedReader())); assertTrue(eof(two.body().bufferedReader()))
        } finally { one.body().close(); two.body().close() }
    }

    @Test fun `heartbeat comments have no event identity and the lease closes an idle connection`() = Fixture(lifetimeMs = 500).use { f ->
        val original = f.bytes.get().clone()
        val response = f.open()
        response.body().bufferedReader().use { reader ->
            val heartbeat = CompletableFuture.supplyAsync {
                reader.lineSequence().first { it == ": heartbeat" }
            }.get(3, TimeUnit.SECONDS)
            assertEquals(": heartbeat", heartbeat)
            assertEquals("", reader.readLine())
            assertTrue(eof(reader))
        }
        assertTrue(f.resources.shutdown())
        assertEquals(0, f.resources.snapshot().active)
        assertContentEquals(original, f.bytes.get())
    }

    @Test fun `retention loss emits an unnumbered gap then closes and reconnect gets HTTP gap`() = Fixture().use { f ->
        f.bytes.set(journal(listOf(0)))
        val response = f.open()
        response.body().bufferedReader().use { reader ->
            val first = frame(reader)
            f.bytes.set(journal(listOf(1)))
            val gap = frame(reader)
            assertEquals("retention.gap", gap["event"])
            assertFalse("id" in gap)
            val body = Json.parseToJsonElement(gap.getValue("data")).jsonObject
            assertEquals(JsonNull, body["cursor"]); assertEquals(JsonNull, body["sequence"])
            assertEquals(first["id"], body.getValue("payload").jsonObject.getValue("requestedCursor").jsonPrimitive.content)
            assertTrue(eof(reader))
            val reconnect = f.open(headers = mapOf("Last-Event-ID" to first.getValue("id")))
            assertEquals(410, reconnect.statusCode())
            assertTrue(reconnect.body().use { it.readBytes().decodeToString() }.contains("PROGRESS_GAP"))
        }
    }

    @Test fun `denied and ambiguous resume requests never admit a stream`() = Fixture().use { f ->
        for ((path, headers, status) in listOf(
            Triple("/events", mapOf("Cookie" to "missing=fixture"), 401),
            Triple("/events", mapOf("Origin" to "https://unconfigured.invalid"), 403),
            Triple("/events?after=fixture", mapOf("Last-Event-ID" to "fixture"), 400),
            Triple("/events", mapOf("Last-Event-ID" to "x".repeat(129)), 400),
        )) {
            val response = f.open(path, headers)
            assertEquals(status, response.statusCode()); response.body().close()
            assertEquals(0, f.resources.snapshot().active)
        }
    }

    @Test fun `SSE line fields are bounded and cannot inject extra fields`() {
        fun event(cursor: String) = buildJsonObject {
            put("type", "workflow.observation"); put("cursor", cursor); put("sequence", "0")
            put("payload", "line one\nline two")
        }
        val frame = webSseFrame(event("cursor_fixture")).decodeToString()
        assertEquals(1, frame.lineSequence().count { it.startsWith("data:") })
        assertFailsWith<IllegalArgumentException> { webSseFrame(event("bad\nid: other")) }
    }

    companion object {
        private fun journal(sequences: List<Int>) = buildJsonObject {
            put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", (sequences.lastOrNull() ?: -1) + 1)
            put("queueDropped", 0); put("historyDropped", 0); put("truncated", false)
            put("events", buildJsonArray { sequences.forEach { seq -> add(buildJsonObject {
                put("sequence", seq); put("runId", "writer_fixture"); put("workflow", "reconstruct")
                put("time", "2026-09-06T00:00:00Z"); put("kind", "message"); put("text", "PRIVATE_STREAM")
            }) } })
        }.toString().toByteArray()
    }
}
