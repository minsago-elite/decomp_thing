package decompengine.web

import com.sun.net.httpserver.Headers
import com.sun.net.httpserver.HttpContext
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpPrincipal
import decompengine.git.GitConflictEntry
import decompengine.git.GitPath
import decompengine.git.ManagedGitRepositories.GitConflictFileView
import decompengine.git.ManagedGitRepositories.GitConflictView
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

    @Test fun `admitted long escaped paths produce bounded distinct wire labels`() {
        val parent = ("p" + "\u0001".repeat(99) + "/").repeat(15)
        val entries = (0 until 200).map { conflictEntry(parent + "conflict$it.c") }
        assertTrue(entries.first().path.display.length > 8000)
        val view = GitConflictView(worktreeId, null, true, entries, 0, entries.size, null)
        val exchange = ConflictMemoryExchange()
        val page = webGitConflicts(repositoryId, view)
        sendWebApiResponse(exchange, 200, "gitConflicts", page)
        assertTrue(exchange.output.size() < 1024 * 1024)
        val files = page.getValue("files").jsonArray
        assertEquals(200, files.size)
        assertEquals(JsonNull, page["nextOffset"])
        assertEquals(200, files.map { it.jsonObject.getValue("path").jsonPrimitive.content }.toSet().size)
        for ((index, file) in files.withIndex()) {
            val data = file.jsonObject
            val path = data.getValue("path").jsonPrimitive.content
            assertTrue(path.length <= 1024)
            assertTrue(path.contains("[truncated; file_"))
            assertTrue(data.getValue("pathEscaped").jsonPrimitive.boolean)
            assertEquals(entries[index].path.fileId(worktreeId), data.getValue("fileId").jsonPrimitive.content)
        }
    }

    @Test fun `encoded byte pages advance by exactly the returned entries without omissions`() {
        val entries = (0 until 19).map { conflictEntry("\u20ac".repeat(1800) + "/file$it.c") }
        val found = mutableListOf<String>()
        var offset = 0
        do {
            val view = GitConflictView(worktreeId, null, true, entries.drop(offset), offset, entries.size, null)
            val page = webGitConflicts(repositoryId, view, byteLimit = 7000)
            assertTrue(page.toString().toByteArray(Charsets.UTF_8).size <= 7000)
            val files = page.getValue("files").jsonArray
            assertTrue(files.size in 1..2, "the byte budget, not the item count, must end this page")
            assertEquals(offset, page.getValue("offset").jsonPrimitive.int)
            found += files.map { it.jsonObject.getValue("fileId").jsonPrimitive.content }
            offset += files.size
            assertEquals(if (offset < entries.size) JsonPrimitive(offset) else JsonNull, page["nextOffset"])
        } while (offset < entries.size)
        assertEquals(entries.map { it.path.fileId(worktreeId) }, found)
    }

    @Test fun `bounded path labels also apply to details and never split surrogate pairs`() {
        val entry = conflictEntry("\uD83D\uDE00".repeat(1000) + "/a.c")
        val file = webGitConflictEntry(entry, worktreeId)
        val path = file.getValue("path").jsonPrimitive.content
        assertTrue(path.length <= 1024)
        assertTrue(path.contains("[truncated;"))
        assertTrue(path.codePoints().noneMatch { it in 0xD800..0xDFFF })
        val view = GitConflictFileView(worktreeId, entry, "base", "ours", "theirs", "current", "ef".repeat(32), 7)
        val detail = webGitConflictDetail(repositoryId, view, file)
        assertEquals(file, detail["file"])
        assertTrue(detail.getValue("supported").jsonPrimitive.boolean)
        assertEquals("ours", detail.getValue("ours").jsonPrimitive.content)
        val ordinary = webGitConflictEntry(conflictEntry("src/main.c"), worktreeId)
        assertEquals("src/main.c", ordinary.getValue("path").jsonPrimitive.content)
        assertFalse(ordinary.getValue("pathEscaped").jsonPrimitive.boolean)
        assertTrue(webGitConflictEntry(conflictEntry("src/a\tb.c"), worktreeId).getValue("pathEscaped").jsonPrimitive.boolean)
    }

    private val repositoryId = "repo_" + "12".repeat(16)
    private val worktreeId = "worktree_" + "34".repeat(16)
    private fun conflictEntry(path: String) = GitConflictEntry(GitPath.of(path.toByteArray()), "a".repeat(40), "b".repeat(40), "c".repeat(40))

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
