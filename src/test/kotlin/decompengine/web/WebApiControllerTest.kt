package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
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
        assertError(failure, 500, "INTERNAL_ERROR")
        assertFalse(failure.body().contains("PRIVATE_CORRUPT"))
        assertFalse(failure.body().contains(record.toString()))
        assertEquals(200, request(server, "/workbench/api/v1/bootstrap", headers = mapOf("Cookie" to cookie)).statusCode())
        assertEquals("PRIVATE_CORRUPT_RECORD_SENTINEL {", Files.readString(record))
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
