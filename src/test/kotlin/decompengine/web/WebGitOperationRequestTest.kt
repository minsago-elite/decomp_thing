package decompengine.web

import com.sun.net.httpserver.*
import decompengine.git.GitCommitRequest
import decompengine.git.GitRepositoryRequest
import kotlinx.serialization.json.*
import java.io.InputStream
import java.io.OutputStream
import java.lang.reflect.InvocationTargetException
import java.net.InetSocketAddress
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

/** Tests the actual HTTP body parser in isolation, not authentication or application routing. */
class WebGitOperationRequestTest {
    private val ordinary = Json.parseToJsonElement(Files.readString(Path.of("contracts/web/v1/fixtures/request-git-commit.json")))
        .jsonObject.getValue("data").jsonObject.let { fixture ->
            // Design fixtures use generic IDs; the live Git parser requires full opaque file IDs.
            JsonObject(fixture + ("selectedFileIds" to JsonArray(listOf(JsonPrimitive("file_${"a".repeat(32)}")))))
        }

    private fun parse(body: JsonObject): GitRepositoryRequest {
        val controller = WebGitOperations({ error("body parsing must not reach repository storage") }, "/")
        val method = WebGitOperations::class.java.getDeclaredMethod("readRequest", HttpExchange::class.java).apply { isAccessible = true }
        return try { (method.invoke(controller, RequestExchange(body.toString())) as Pair<*, *>).first as GitRepositoryRequest }
        catch (failure: InvocationTargetException) { throw checkNotNull(failure.cause) }
    }

    @Test fun `complete merge index mode is explicit compact and parsed as a retained commit intent`() {
        val body = JsonObject(ordinary + mapOf("selectedFileIds" to JsonArray(emptyList()), "reviewedMergeIndex" to JsonPrimitive(true)))
        val request = parse(body) as GitCommitRequest
        assertTrue(request.reviewedMergeIndex); assertTrue(request.fileIds.isEmpty())
        assertEquals(ordinary.getValue("guards").jsonObject.getValue("worktreeVersion").jsonPrimitive.content, request.guards.worktreeVersion)
        assertNotEquals(request.digest, request.copy(reviewedMergeIndex = false).digest)
        assertFalse((parse(ordinary) as GitCommitRequest).reviewedMergeIndex)
    }

    @Test fun `complete merge index mode never permits partial selection or coerced values`() {
        for (body in listOf(JsonObject(ordinary + ("reviewedMergeIndex" to JsonPrimitive(true))),
            JsonObject(ordinary + ("reviewedMergeIndex" to JsonPrimitive(false))),
            JsonObject(ordinary + ("reviewedMergeIndex" to JsonPrimitive("true"))),
            JsonObject(ordinary + ("reviewedMergeIndex" to JsonNull)))) {
            assertFailsWith<WebAccessDenied> { parse(body) }
        }
        val tooMany = JsonArray((0..200).map { JsonPrimitive("file_${it.toString().padStart(32, '0')}") })
        assertFailsWith<WebAccessDenied> { parse(JsonObject(ordinary + ("selectedFileIds" to tooMany))) }
    }
}

private class RequestExchange(private val body: String) : HttpExchange() {
    override fun getRequestHeaders() = Headers()
    override fun getResponseHeaders() = Headers()
    override fun getRequestURI() = URI.create("/operations")
    override fun getRequestMethod() = "POST"
    override fun getHttpContext(): HttpContext = throw UnsupportedOperationException()
    override fun close() = Unit
    override fun getRequestBody(): InputStream = body.byteInputStream()
    override fun getResponseBody(): OutputStream = OutputStream.nullOutputStream()
    override fun sendResponseHeaders(code: Int, length: Long) = Unit
    override fun getRemoteAddress() = InetSocketAddress("127.0.0.1", 1)
    override fun getResponseCode() = -1
    override fun getLocalAddress() = InetSocketAddress("127.0.0.1", 8000)
    override fun getProtocol() = "HTTP/1.1"
    override fun getAttribute(name: String): Any? = null
    override fun setAttribute(name: String, value: Any?) = Unit
    override fun setStreams(input: InputStream?, output: OutputStream?) = Unit
    override fun getPrincipal(): HttpPrincipal? = null
}
