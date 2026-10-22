package decompengine.web

import com.sun.net.httpserver.HttpServer
import decompengine.jobs.JobStore
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WebAgentPreflightTest {
    private val secret = "sk-private-agent-secret-123"
    private val calls = AtomicInteger()
    private val release = CountDownLatch(1)
    @Volatile private var behavior: () -> Unit = {}
    private val closeables = mutableListOf<AutoCloseable>()
    private val root: Path = Files.createTempDirectory(Path.of("build"), "agent-preflight-http")

    @AfterTest fun cleanup() {
        release.countDown()
        closeables.reversed().forEach { runCatching { it.close() } }
        root.toFile().deleteRecursively()
    }

    private inner class Harness {
        val service = WebJobService(JobStore(root), JobAnalyzer { _, _ -> error("unused") }, JobReconstructor { _, _ -> error("unused") })
            .also { it.initializeExistingStorage(); closeables += it }
        val server: HttpServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val origin = "http://127.0.0.1:${server.address.port}"
        val access = LocalWebAccess(LocalWebAccessConfiguration(origin, basePath = "/w/"))
        val preflight = WebAgentPreflight { calls.incrementAndGet(); behavior() }.also { closeables += it }
        val api = WebApiController(access, EmbeddedWebAssets.load(basePath = "/w/"), service,
            WebJobMutationBoundary(access, service), WebStreamResources().also { closeables += it }, agentPreflight = preflight)
        val http: HttpClient = HttpClient.newHttpClient()
        val cookie: String
        val csrf: String

        init {
            server.executor = Executors.newFixedThreadPool(4).also { pool -> closeables += AutoCloseable { pool.shutdownNow() } }
            server.createContext("/") { check(api.route(it)) }
            server.start(); closeables += AutoCloseable { server.stop(0) }
            val login = send("/w/api/v1/session", "POST", """{"token":"${access.issueBootstrap().token}"}""",
                mapOf("Origin" to origin, "Content-Type" to "application/json"))
            cookie = login.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            csrf = Json.parseToJsonElement(login.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
        }

        fun send(path: String, method: String, body: String?, headers: Map<String, String>): HttpResponse<String> {
            val request = HttpRequest.newBuilder(URI(origin + path)).timeout(Duration.ofSeconds(5)).method(method,
                body?.let { HttpRequest.BodyPublishers.ofString(it) } ?: HttpRequest.BodyPublishers.noBody())
            request.header("Accept", "application/json")
            headers.forEach { (k, v) -> request.header(k, v) }
            return http.send(request.build(), HttpResponse.BodyHandlers.ofString())
        }
        fun get(authed: Boolean = true) = send("/w/api/v1/agent/preflight", "GET", null, if (authed) mapOf("Cookie" to cookie) else emptyMap())
        fun post(body: String = """{"action":"inspect"}""", csrfToken: String? = csrf) = send("/w/api/v1/agent/preflight", "POST", body,
            buildMap { put("Cookie", cookie); put("Origin", origin); put("Content-Type", "application/json"); csrfToken?.let { put("X-CSRF-Token", it) } })
        fun data(response: HttpResponse<String>) = Json.parseToJsonElement(response.body()).jsonObject.getValue("data").jsonObject
        fun status() = data(get()).getValue("status").jsonPrimitive.content
        fun awaitStatus(expected: String) {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (status() != expected && System.nanoTime() < deadline) Thread.sleep(20)
            assertEquals(expected, status())
        }
        fun harnessCapability(): kotlinx.serialization.json.JsonObject {
            val response = send("/w/api/v1/bootstrap", "GET", null, mapOf("Cookie" to cookie))
            return data(response).getValue("capabilities").jsonArray.map { it.jsonObject }
                .single { it.getValue("id").jsonPrimitive.content == "harness" }
        }
    }

    @Test
    fun `reading requires a session and reports idle without starting the agent`() {
        val h = Harness()
        assertEquals(401, h.get(authed = false).statusCode())
        val idle = h.get()
        assertEquals(200, idle.statusCode())
        assertEquals("agentPreflight", Json.parseToJsonElement(idle.body()).jsonObject.getValue("kind").jsonPrimitive.content)
        assertEquals("idle", h.data(idle).getValue("status").jsonPrimitive.content)
        assertEquals(0, calls.get())
    }

    @Test
    fun `starting requires csrf and the exact inspect action before any agent work`() {
        val h = Harness()
        assertTrue(h.post(csrfToken = null).statusCode() in 400..499)
        assertEquals(422, h.post(body = """{"action":"login"}""").statusCode())
        assertEquals(422, h.post(body = """{"action":"inspect","extra":true}""").statusCode())
        assertEquals(400, h.post(body = "not json").statusCode())
        assertEquals(0, calls.get())
        assertEquals("idle", h.status())
    }

    @Test
    fun `an explicit start is single flight and its result is readable`() {
        val h = Harness()
        behavior = { release.await() }
        val started = h.post()
        assertEquals(202, started.statusCode())
        assertEquals("/w/api/v1/agent/preflight", started.headers().firstValue("Location").orElseThrow())
        assertEquals("inspecting", h.data(started).getValue("status").jsonPrimitive.content)
        val busy = h.post()
        assertEquals(409, busy.statusCode())
        assertTrue(busy.body().contains("AGENT_PREFLIGHT_IN_PROGRESS"))
        assertEquals(1, calls.get())
        release.countDown()
        h.awaitStatus("ready")
        assertEquals(1, calls.get())
        behavior = {}
        assertEquals(202, h.post().statusCode())
        h.awaitStatus("ready")
        assertEquals(2, calls.get())
    }

    @Test
    fun `a failing agent is a fixed code that never discloses exception text or configuration`() {
        val h = Harness()
        behavior = { throw IllegalStateException("token=$secret path=$root") }
        assertEquals(202, h.post().statusCode())
        h.awaitStatus("failed")
        val body = h.get().body()
        assertTrue(body.contains("AGENT_PREFLIGHT_FAILED"))
        assertFalse(body.contains(secret)); assertFalse(body.contains(root.toString())); assertFalse(body.contains("token="))
        val harness = h.harnessCapability()
        assertFalse(harness.toString().contains(secret))
    }

    @Test
    fun `the last explicit preflight is folded into the bootstrap harness capability without starting anything`() {
        val h = Harness()
        val before = h.harnessCapability()
        assertEquals(0, calls.get())
        behavior = { throw IllegalStateException("x") }
        assertEquals(202, h.post().statusCode())
        h.awaitStatus("failed")
        val after = h.harnessCapability()
        // Bootstrap reflects the failure only when the environment's harness is otherwise configured.
        if (before.getValue("state").jsonPrimitive.content == "supported") {
            assertEquals("unavailable", after.getValue("state").jsonPrimitive.content)
            assertEquals("AGENT_PREFLIGHT_FAILED", after.getValue("reasonCode").jsonPrimitive.content)
        } else assertEquals(before, after)
        assertEquals(1, calls.get())
    }

    @Test
    fun `closing refuses new inspections`() {
        val preflight = WebAgentPreflight { }
        preflight.close()
        assertEquals(WebAgentPreflight.Start.Closed, preflight.start())
    }

    @Test
    fun `agent inspection can only demote or annotate a configured harness`() {
        val supported = WebHarnessReadiness("supported", null, "base")
        val failed = supported.withAgentInspection("failed")
        assertEquals("unavailable", failed.state)
        assertEquals("AGENT_PREFLIGHT_FAILED", failed.reasonCode)
        for (status in listOf(null, "idle", "inspecting", "cancelled")) {
            val result = supported.withAgentInspection(status)
            assertEquals("supported", result.state)
            assertTrue(result.message.contains("unproven"), "unstarted agent readiness must not be implied: $status")
        }
        val ready = supported.withAgentInspection("ready")
        assertEquals("supported", ready.state)
        assertTrue(ready.message.contains("last operator inspection"))
        val missing = WebHarnessReadiness("unavailable", "GHIDRA_MISSING", "missing")
        assertEquals(missing, missing.withAgentInspection("ready"))
        assertEquals(missing, missing.withAgentInspection("failed"))
    }
}
