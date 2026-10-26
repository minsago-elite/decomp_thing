package decompengine.web

import com.sun.net.httpserver.Headers
import com.sun.net.httpserver.HttpContext
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpPrincipal
import decompengine.git.GitConflictEntry
import decompengine.git.GitPath
import decompengine.git.ManagedGitRepositories.GitConflictFileView
import kotlinx.serialization.json.*
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class WebGitConflictDetailTest {
    @Test fun `escaped near-limit sides become an explicit unsupported response`() {
        for (source in listOf("\"\";\n".repeat(50 * 1024), "\u0001".repeat(256 * 1024))) {
            val response = encodedConflictResponse(source)
            assertTrue(response.size < 1024 * 1024)
            val data = Json.parseToJsonElement(response.toString(Charsets.UTF_8)).jsonObject.getValue("data").jsonObject
            assertFalse(data.getValue("supported").jsonPrimitive.boolean)
            assertTrue(data.getValue("reason").jsonPrimitive.content.contains("JSON encoding"))
            for (side in listOf("base", "ours", "theirs", "current")) assertEquals(JsonNull, data[side])
            assertEquals("ef".repeat(32), data.getValue("currentSha256").jsonPrimitive.content)
            assertEquals(source.toByteArray().size.toString(), data.getValue("currentSizeBytes").jsonPrimitive.content)
        }
    }

    @Test fun `large sides that fit the encoded envelope remain reviewable`() {
        val source = "x".repeat(200 * 1024)
        val response = encodedConflictResponse(source)
        assertTrue(response.size < 1024 * 1024)
        val data = Json.parseToJsonElement(response.toString(Charsets.UTF_8)).jsonObject.getValue("data").jsonObject
        assertTrue(data.getValue("supported").jsonPrimitive.boolean)
        for (side in listOf("base", "ours", "theirs", "current")) assertEquals(source, data.getValue(side).jsonPrimitive.content)
    }

    @Test fun `the shared response encoder still refuses oversized responses`() {
        assertFailsWith<IllegalStateException> {
            sendWebApiResponse(ConflictMemoryExchange(), 200, "gitConflictFile", JsonPrimitive("x".repeat(1024 * 1024)))
        }
    }
}

/** Exercise the production detail budget and actual shared response envelope/byte ceiling. */
internal fun encodedConflictResponse(source: String): ByteArray {
    val fixture = Json.parseToJsonElement(Files.readString(Path.of("contracts/web/v1/fixtures/git-conflict-file.json")))
        .jsonObject.getValue("data").jsonObject
    val file = fixture.getValue("file").jsonObject
    val view = GitConflictFileView(fixture.getValue("worktreeId").jsonPrimitive.content,
        GitConflictEntry(GitPath.of("src/main.c".toByteArray()), file.getValue("baseObjectId").jsonPrimitive.content,
            file.getValue("oursObjectId").jsonPrimitive.content, file.getValue("theirsObjectId").jsonPrimitive.content),
        source, source, source, source, "ef".repeat(32), source.toByteArray().size.toLong())
    val exchange = ConflictMemoryExchange()
    sendWebApiResponse(exchange, 200, "gitConflictFile", webGitConflictDetail(fixture.getValue("repositoryId").jsonPrimitive.content, view, file))
    assertEquals(200, exchange.responseCode)
    assertEquals(exchange.output.size().toString(), exchange.responseHeaders.getFirst("Content-Length"))
    return exchange.output.toByteArray()
}

private class ConflictMemoryExchange : HttpExchange() {
    val output = ByteArrayOutputStream()
    private val incoming = Headers()
    private val outgoing = Headers()
    private var status = -1
    override fun getRequestHeaders(): Headers = incoming
    override fun getResponseHeaders(): Headers = outgoing
    override fun getRequestURI(): URI = URI.create("/conflicts/file_example_1")
    override fun getRequestMethod(): String = "GET"
    override fun getHttpContext(): HttpContext = throw UnsupportedOperationException()
    override fun close() = Unit
    override fun getRequestBody(): InputStream = InputStream.nullInputStream()
    override fun getResponseBody(): OutputStream = output
    override fun sendResponseHeaders(code: Int, length: Long) { status = code }
    override fun getRemoteAddress(): InetSocketAddress = InetSocketAddress("127.0.0.1", 1)
    override fun getResponseCode(): Int = status
    override fun getLocalAddress(): InetSocketAddress = InetSocketAddress("127.0.0.1", 8000)
    override fun getProtocol(): String = "HTTP/1.1"
    override fun getAttribute(name: String): Any? = null
    override fun setAttribute(name: String, value: Any?) = Unit
    override fun setStreams(input: InputStream?, output: OutputStream?) = Unit
    override fun getPrincipal(): HttpPrincipal? = null
}
