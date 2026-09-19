package decompengine.web

import com.sun.net.httpserver.HttpServer
import decompengine.jobs.AgentProgressJournal
import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.InetSocketAddress
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Wire-level compatibility matrix: use the real listener, authorization and route dispatch. */
class WebNegotiationMatrixTest {
    private val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()

    @Test
    fun `v1 route matrix negotiates JSON binary methods and unavailable capabilities`() = withServer(WebUiMode.SPA) { server, root, id ->
        val headers = session(server, "/workbench/")
        val api = "/workbench/api/v1"
        val record = Files.readAllBytes(root.resolve(id).resolve("job.json"))
        val cases = listOf(
            Case("JSON exact", "GET", "$api/jobs/$id", "application/json", 200),
            Case("JSON subtype wildcard", "GET", "$api/jobs/$id", "application/*", 200),
            Case("JSON any wildcard", "GET", "$api/jobs/$id", "*/*", 200),
            Case("JSON excluded by specific range", "GET", "$api/jobs/$id", "application/json;q=0, */*;q=1", 406, "NOT_ACCEPTABLE"),
            Case("JSON excluded by media type", "GET", "$api/bootstrap", "text/html", 406, "NOT_ACCEPTABLE"),
            Case("bounded Accept", "GET", "$api/jobs/$id", "x".repeat(513), 400, "INVALID_HEADER"),
            Case("unknown query", "GET", "$api/jobs/$id?unsupported=1", "application/json", 400, "VALIDATION_FAILED"),
            Case("missing job", "GET", "$api/jobs/${"f".repeat(32)}", "application/json", 404, "NOT_FOUND"),
            Case("unknown v1 capability", "GET", "$api/projects", "application/json", 404, "NOT_FOUND"),
            Case("unknown major", "GET", "/workbench/api/v2/jobs", "application/json", 404, "NOT_FOUND"),
            Case("read-only run collection", "POST", "$api/jobs/$id/runs", "application/json", 405, "METHOD_NOT_ALLOWED", "GET"),
            Case("job HEAD is unavailable", "HEAD", "$api/jobs/$id", "application/json", 405, allow = "GET"),
            Case("binary download excludes HTML", "GET", "$api/jobs/$id/artifacts/missing/content", "text/html", 406, "NOT_ACCEPTABLE"),
            Case("binary download excludes JSON", "GET", "$api/jobs/$id/artifacts/missing/content", "application/json", 406, "NOT_ACCEPTABLE"),
            Case("binary download accepts its type", "GET", "$api/jobs/$id/artifacts/missing/content", "application/octet-stream", 404, "NOT_FOUND"),
            Case("binary download methods", "POST", "$api/jobs/$id/artifacts/missing/content", "application/octet-stream", 405, "METHOD_NOT_ALLOWED", "GET, HEAD"),
        )
        for (case in cases) {
            val response = request(server, case.method, case.path, headers + mapOf("Accept" to case.accept))
            assertEquals(case.status, response.statusCode(), case.name)
            case.code?.let { assertError(response, it, versioned = true, case.name) }
            case.allow?.let { assertEquals(it, response.header("Allow"), case.name) }
            if (case.method == "HEAD") assertTrue(response.body().isEmpty(), case.name)
            if (case.status == 200) assertEquals("job", Json.parseToJsonElement(response.body()).jsonObject["kind"]?.jsonPrimitive?.content, case.name)
        }
        assertError(repeatedAccept(server, "$api/jobs/$id", headers), "INVALID_HEADER", versioned = true,
            label = "repeated v1 Accept")
        assertError(request(server, "POST", "$api/jobs", headers + mapOf("Accept" to "application/json")),
            "UNSUPPORTED_MEDIA_TYPE", versioned = true, label = "upload Content-Type")
        assertError(request(server, "POST", "$api/session", mapOf("Accept" to "application/json", "Content-Type" to "text/plain"), "{}"),
            "UNSUPPORTED_MEDIA_TYPE", versioned = true, label = "session Content-Type")
        assertContentEquals(record, Files.readAllBytes(root.resolve(id).resolve("job.json")))
    }

    @Test
    fun `legacy route matrix keeps old JSON shapes and qualifies the upload Accept switch`() = withServer(WebUiMode.LEGACY) { server, root, id ->
        val headers = session(server, "/")
        AgentProgressJournal(root.resolve(id).resolve("reports"), "reconstruct").use { }
        val record = Files.readAllBytes(root.resolve(id).resolve("job.json"))
        for (path in listOf("/api/jobs/$id", "/api/jobs/$id/events")) {
            for (accept in listOf("application/json", "application/*", "*/*", "text/html, application/json;q=0.5")) {
                val response = request(server, "GET", path, headers + mapOf("Accept" to accept))
                assertEquals(200, response.statusCode(), "$path $accept")
                assertEquals("application/json; charset=utf-8", response.header("Content-Type"))
                assertFalse(Json.parseToJsonElement(response.body()).jsonObject.containsKey("apiVersion"))
            }
            for (accept in listOf("text/html", "application/json;q=0, */*;q=1")) {
                assertError(request(server, "GET", path, headers + mapOf("Accept" to accept)),
                    "NOT_ACCEPTABLE", versioned = false, label = "$path $accept")
            }
            for (method in listOf("POST", "PUT", "PATCH", "DELETE", "OPTIONS")) {
                val response = request(server, method, path, headers + mapOf("Accept" to "text/html"))
                assertError(response, "METHOD_NOT_ALLOWED", versioned = false, label = "$path $method")
                assertEquals("GET, HEAD", response.header("Allow"), "$path $method")
            }
            val get = request(server, "GET", path, headers)
            val head = request(server, "HEAD", path, headers)
            assertEquals(200, head.statusCode(), path)
            assertEquals(get.header("Content-Length"), head.header("Content-Length"), path)
            assertTrue(head.body().isEmpty(), path)
        }
        assertError(request(server, "GET", "/api/unknown", headers), "NOT_FOUND", versioned = false, label = "legacy unknown")
        assertError(repeatedAccept(server, "/api/jobs/$id", headers), "INVALID_HEADER", versioned = false,
            label = "repeated legacy Accept")
        assertError(request(server, "GET", "/api/v1/jobs/$id", headers), "NOT_FOUND", versioned = false,
            label = "v1 job routes are not live in legacy mode")
        val invalidElf = byteArrayOf(1, 2, 3)
        val jsonUpload = upload(server, invalidElf, headers + mapOf("Accept" to "application/json"))
        assertError(jsonUpload, "INVALID_UPLOAD", versioned = false, label = "JSON upload failure")
        val wildcardUpload = upload(server, invalidElf, headers + mapOf("Accept" to "application/*"))
        assertError(wildcardUpload, "INVALID_UPLOAD", versioned = false, label = "JSON subtype wildcard upload")
        val htmlUpload = upload(server, invalidElf, headers + mapOf("Accept" to "application/json;q=0, text/html"))
        assertEquals(400, htmlUpload.statusCode())
        assertEquals("text/html; charset=utf-8", htmlUpload.header("Content-Type"))
        val excludedUpload = upload(server, invalidElf, headers + mapOf("Accept" to "image/png"))
        assertEquals(406, excludedUpload.statusCode())
        assertEquals("text/html; charset=utf-8", excludedUpload.header("Content-Type"))
        val htmlSuccess = upload(server, elfFixture(), headers + mapOf("Accept" to "application/json;q=0, text/html"))
        assertEquals(303, htmlSuccess.statusCode())
        assertTrue(htmlSuccess.header("Location")!!.startsWith("/jobs/"))
        val jsonSuccess = upload(server, elfFixture(), headers + mapOf("Accept" to "application/*"))
        assertEquals(201, jsonSuccess.statusCode())
        assertEquals("application/json; charset=utf-8", jsonSuccess.header("Content-Type"))
        assertFalse(Json.parseToJsonElement(jsonSuccess.body()).jsonObject.containsKey("apiVersion"))
        val wrongType = request(server, "POST", "/jobs", headers + mapOf("Accept" to "application/json", "Content-Type" to "text/plain"))
        assertError(wrongType, "UNSUPPORTED_MEDIA_TYPE", versioned = false, label = "legacy upload Content-Type")
        assertContentEquals(record, Files.readAllBytes(root.resolve(id).resolve("job.json")))
    }

    @Test
    fun `v1 session capacity is a typed retryable JSON limit over HTTP`() = withServer(WebUiMode.SPA) { server, _, _ ->
        repeat(8) { session(server, "/workbench/") }
        val token = server.issueBrowserBootstrap().token
        val response = request(server, "POST", "/workbench/api/v1/session",
            mapOf("Accept" to "application/json"), "{\"token\":\"$token\"}")
        assertEquals(429, response.statusCode())
        assertError(response, "SESSION_LIMIT", versioned = true, label = "session capacity")
        assertEquals("30", response.header("Retry-After"))
        val error = Json.parseToJsonElement(response.body()).jsonObject.getValue("error").jsonObject
        assertEquals("true", error.getValue("retryable").toString())
    }

    @Test
    fun `shared v1 error renderer keeps injected internal failures typed and private over HTTP`() {
        val listener = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val access = LocalWebAccess(LocalWebAccessConfiguration("http://127.0.0.1:${listener.address.port}"))
        listener.createContext("/api/v1/fault") { exchange ->
            access.sendDenied(exchange, WebAccessDenied(500, "INTERNAL_ERROR", "The request could not be completed."))
        }
        listener.start()
        try {
            val response = client.send(HttpRequest.newBuilder(URI("http://127.0.0.1:${listener.address.port}/api/v1/fault"))
                .header("Accept", "text/html").GET().build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(500, response.statusCode())
            assertError(response, "INTERNAL_ERROR", versioned = true, label = "injected internal failure")
            assertFalse(response.body().contains("Exception"))
        } finally { listener.stop(0); access.close() }
    }

    private data class Case(val name: String, val method: String, val path: String, val accept: String,
                            val status: Int, val code: String? = null, val allow: String? = null)

    private fun session(server: UploadServer, basePath: String): Map<String, String> {
        val token = server.issueBrowserBootstrap().token
        val response = request(server, "POST", "${basePath}api/v1/session", mapOf("Accept" to "application/json"),
            "{\"token\":\"$token\"}")
        assertEquals(200, response.statusCode())
        val csrf = Json.parseToJsonElement(response.body()).jsonObject.getValue("data").jsonObject
            .getValue("csrfToken").jsonPrimitive.content
        return mapOf("Cookie" to response.header("Set-Cookie")!!.substringBefore(';'), "X-CSRF-Token" to csrf)
    }

    private fun upload(server: UploadServer, bytes: ByteArray, headers: Map<String, String>): HttpResponse<String> {
        val boundary = "d473_matrix"
        val body = "--$boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"fixture.elf\"\r\n\r\n".toByteArray() +
            bytes + "\r\n--$boundary--\r\n".toByteArray()
        return request(server, "POST", "/jobs", headers + mapOf("Content-Type" to "multipart/form-data; boundary=$boundary"), body = body)
    }

    private fun request(server: UploadServer, method: String, path: String, headers: Map<String, String>,
                        text: String? = null, body: ByteArray? = null): HttpResponse<String> {
        val origin = "http://127.0.0.1:${server.serverPort}"
        val builder = HttpRequest.newBuilder(URI(origin + path)).method(method,
            body?.let(HttpRequest.BodyPublishers::ofByteArray) ?: text?.let(HttpRequest.BodyPublishers::ofString)
            ?: HttpRequest.BodyPublishers.noBody())
        if (method in setOf("POST", "PUT", "PATCH", "DELETE")) {
            builder.header("Origin", origin)
            builder.header("Content-Type", headers["Content-Type"] ?: "application/json")
        }
        headers.filterKeys { it != "Content-Type" }.forEach { (name, value) -> builder.header(name, value) }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString()).also(::assertNoWebCors)
    }

    private fun repeatedAccept(server: UploadServer, path: String, headers: Map<String, String>): HttpResponse<String> {
        val builder = HttpRequest.newBuilder(URI("http://127.0.0.1:${server.serverPort}$path"))
            .header("Accept", "application/json").header("Accept", "text/html")
        headers.forEach { (name, value) -> builder.header(name, value) }
        return client.send(builder.GET().build(), HttpResponse.BodyHandlers.ofString()).also(::assertNoWebCors)
    }

    private fun assertError(response: HttpResponse<String>, code: String, versioned: Boolean, label: String) {
        assertEquals("application/json; charset=utf-8", response.header("Content-Type"), label)
        assertEquals("no-store", response.header("Cache-Control"), label)
        val body = Json.parseToJsonElement(response.body()).jsonObject
        assertEquals(response.header("X-Request-ID"), body.getValue("requestId").jsonPrimitive.content, label)
        assertEquals(code, body.getValue("error").jsonObject.getValue("code").jsonPrimitive.content, label)
        assertEquals(versioned, body.containsKey("apiVersion"), label)
    }

    private fun HttpResponse<String>.header(name: String): String? = headers().firstValue(name).orElse(null)

    private fun withServer(mode: WebUiMode, block: (UploadServer, java.nio.file.Path, String) -> Unit) {
        val root = createTempDirectory("web-negotiation-matrix-")
        val id = JobStore(root).createFromUpload("fixture.elf", elfFixture()).id
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("analysis must remain inert") },
            JobReconstructor { _, _ -> error("reconstruction must remain inert") }, uiMode = mode,
            basePath = if (mode == WebUiMode.SPA) "/workbench/" else "/")
        server.start()
        try { block(server, root, id) } finally { server.stop(); root.toFile().deleteRecursively() }
    }
}
