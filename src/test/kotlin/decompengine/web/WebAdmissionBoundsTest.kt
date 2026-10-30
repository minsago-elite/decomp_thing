package decompengine.web

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.io.TempDir
import java.net.Socket
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Admission is bounded (16 workers, 64 queued requests) and overload is answered, not dropped: a request that
 * finds everything taken receives a stable 429 with retry guidance from a small responder pool, and only when
 * that is also busy is the connection closed. Pinned requests send a complete header block but only part of a
 * declared body, so each one holds a worker for as long as the client keeps the connection open.
 */
class WebAdmissionBoundsTest {
    @TempDir lateinit var directory: Path
    private val pinned = mutableListOf<Socket>()

    @AfterTest fun closePinned() { pinned.forEach { runCatching { it.close() } }; pinned.clear() }

    private fun pin(port: Int) {
        val socket = Socket("127.0.0.1", port)
        socket.getOutputStream().write(("POST /w/api/v1/session HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nOrigin: http://127.0.0.1:$port\r\n" +
            "Content-Type: application/json\r\nAccept: application/json\r\nContent-Length: 1024\r\n\r\n{\"token\":\"x").toByteArray())
        socket.getOutputStream().flush()
        pinned += socket
    }

    private class Raw(val status: Int?, val headers: Map<String, String>, val body: String, val failure: String?)

    /** A plain GET over its own connection; a reset or timeout is reported instead of thrown. */
    private fun get(port: Int, timeoutMs: Int = 4_000): Raw = try {
        Socket("127.0.0.1", port).use { socket ->
            socket.soTimeout = timeoutMs
            socket.getOutputStream().write("GET /w/api/v1/bootstrap HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nAccept: application/json\r\nConnection: close\r\n\r\n".toByteArray())
            socket.getOutputStream().flush()
            val text = socket.getInputStream().readBytes().decodeToString()
            if (text.isEmpty()) Raw(null, emptyMap(), "", "closed without a response") else {
                val head = text.substringBefore("\r\n\r\n").lines()
                Raw(head.first().split(' ')[1].toInt(),
                    head.drop(1).filter { ':' in it }.associate { it.substringBefore(':').lowercase() to it.substringAfter(':').trim() },
                    text.substringAfter("\r\n\r\n", ""), null)
            }
        }
    } catch (e: java.net.SocketTimeoutException) { Raw(null, emptyMap(), "", "timeout") }
    catch (e: java.io.IOException) { Raw(null, emptyMap(), "", "${e.javaClass.simpleName}") }

    private fun awaitServing(port: Int) {
        val deadline = System.nanoTime() + 20_000_000_000L
        var last: Raw
        do { Thread.sleep(200); last = get(port, 2_000) } while (last.status != 401 && System.nanoTime() < deadline)
        assertEquals(401, last.status, "the server did not recover after the load was released (${last.failure})")
    }

    private fun server() = UploadServer("127.0.0.1", 0, directory.resolve("jobs"), uiMode = WebUiMode.SPA, basePath = "/w/").also { it.start() }

    @Test
    fun `a saturated server answers with a stable 429 and retry guidance, then recovers when load is released`() {
        val server = server()
        try {
            val port = server.serverPort
            assertEquals(401, get(port).status, "an idle server answers normally")
            repeat(16 + 64) { pin(port) }
            Thread.sleep(1_500)
            for (attempt in 1..3) {
                val response = get(port)
                assertEquals(429, response.status, "attempt $attempt under overload: ${response.failure}")
                assertTrue(response.headers.getValue("content-type").startsWith("application/json"))
                assertEquals("30", response.headers["retry-after"], "retry guidance header")
                assertEquals("no-store", response.headers["cache-control"])
                assertEquals("close", response.headers["connection"]?.lowercase())
                val error = Json.parseToJsonElement(response.body).jsonObject.getValue("error").jsonObject
                assertEquals("SERVER_BUSY", error.getValue("code").jsonPrimitive.content)
                assertEquals("true", error.getValue("retryable").jsonPrimitive.content)
                assertEquals("30000", error.getValue("retryAfterMs").jsonPrimitive.content)
                assertFalse(response.body.contains("/"), "the overload body is fixed safe text")
            }
            closePinned()
            awaitServing(port)
        } finally { closePinned(); server.stop() }
    }

    @Test
    fun `when even the responder tier is busy the connection is closed, never buffered, and the server recovers`() {
        val server = server()
        try {
            val port = server.serverPort
            // 16 workers + 64 queued, then two more slow requests that occupy both responder threads.
            repeat(16 + 64 + 2) { pin(port) }
            Thread.sleep(1_500)
            val results = (1..3).map { get(port, 3_000) }
            for (result in results) {
                assertTrue(
                    result.status == 429 ||
                        (result.status == null && result.failure != null && result.failure != "timeout"),
                    "expected 429 or a closed connection; status=${result.status}, failure=${result.failure}",
                )
            }
            assertTrue(results.any { it.failure != null }, "with every tier taken, at least one request is refused by closing the connection: ${results.map { it.status ?: it.failure }}")
            closePinned()
            awaitServing(port)
        } finally { closePinned(); server.stop() }
    }
}
