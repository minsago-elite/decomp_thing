package decompengine.web

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.io.TempDir
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Admission is bounded (16 workers, 64 queued requests, 2 responders) and overload is answered, not dropped:
 * a request that finds everything taken receives a stable 429 with retry guidance from a small responder
 * pool, and only when that is also busy is the connection closed. Saturation is established from the
 * server's own executor sample, never from a sleep, so the outcome is deterministic under CI load.
 */
class WebAdmissionBoundsTest {
    @TempDir lateinit var directory: Path
    private val pinned = mutableListOf<Socket>()

    @AfterTest fun closePinned() { pinned.forEach { runCatching { it.close() } }; pinned.clear() }

    /** A complete header block with only part of a declared body: holds a worker inside its handler. */
    private fun pin(port: Int) {
        val socket = Socket("127.0.0.1", port)
        socket.getOutputStream().write(("POST /w/api/v1/session HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nOrigin: http://127.0.0.1:$port\r\n" +
            "Content-Type: application/json\r\nAccept: application/json\r\nContent-Length: 4000\r\n\r\n{\"token\":\"x").toByteArray())
        socket.getOutputStream().flush()
        pinned += socket
    }

    /** An unfinished header block: holds a worker while the JDK parses headers, before any handler runs. */
    private fun slowHeaders(port: Int): Socket = Socket("127.0.0.1", port).also { socket ->
        socket.getOutputStream().write("GET /w/api/v1/bootstrap HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nX-Slow: ".toByteArray())
        socket.getOutputStream().flush()
        pinned += socket
    }

    private class Raw(val status: Int?, val headers: Map<String, String>, val body: String, val failure: String?)

    /** One request over its own connection; a reset or timeout is reported instead of thrown. */
    private fun send(port: Int, request: String, timeoutMs: Int = 4_000): Raw = try {
        Socket("127.0.0.1", port).use { socket ->
            socket.soTimeout = timeoutMs
            socket.getOutputStream().write(request.toByteArray())
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

    private fun get(port: Int, timeoutMs: Int = 4_000, path: String = "/w/api/v1/bootstrap", headers: String = "") =
        send(port, "GET $path HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nAccept: application/json\r\n${headers}Connection: close\r\n\r\n", timeoutMs)

    private fun await(description: String, timeoutMs: Long = 30_000, condition: () -> Boolean) {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000
        while (!condition()) {
            check(System.nanoTime() < deadline) { "timed out waiting for $description" }
            Thread.sleep(20)
        }
    }

    private fun awaitServing(port: Int) {
        val deadline = System.nanoTime() + 20_000_000_000L
        var last: Raw
        do { Thread.sleep(100); last = get(port, 2_000) } while (last.status != 401 && System.nanoTime() < deadline)
        assertEquals(401, last.status, "the server did not recover after the load was released (${last.failure})")
    }

    /** Socket-level end of stream: the server closed this connection. */
    private fun closedByServer(socket: Socket, timeoutMs: Int = 10_000): Boolean = try {
        socket.soTimeout = timeoutMs
        socket.getInputStream().readBytes()
        true
    } catch (_: java.net.SocketTimeoutException) { false } catch (_: java.io.IOException) { true }

    private fun server(limits: WebAdmissionLimits = WebAdmissionLimits(requestDeadlineMs = 120_000)) =
        UploadServer("127.0.0.1", 0, directory.resolve("jobs"), uiMode = WebUiMode.SPA, basePath = "/w/",
            admissionLimits = limits).also { it.start() }

    private fun saturate(server: UploadServer) {
        repeat(16 + 64) { pin(server.serverPort) }
        await("16 active workers and 64 queued requests") {
            server.admissionSample().let { it.activeWorkers == 16 && it.queuedRequests == 64 }
        }
    }

    @Test
    fun `a saturated server answers with a stable 429 and retry guidance, then recovers when load is released`() {
        val server = server()
        try {
            val port = server.serverPort
            assertEquals(401, get(port).status, "an idle server answers normally")
            saturate(server)
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
            assertEquals(3L, server.capacity.overloadResponses.get())
            closePinned()
            awaitServing(port)
        } finally { closePinned(); server.stop() }
    }

    @Test
    fun `when even the responder tier is busy the connection is closed, never buffered, and the server recovers`() {
        val server = server()
        try {
            val port = server.serverPort
            saturate(server)
            // Two unfinished header blocks overflow to, and occupy, both responder threads.
            repeat(2) { slowHeaders(port) }
            await("both responders occupied") { server.admissionSample().activeResponders == 2 }
            val results = (1..3).map { get(port, 3_000) }
            for (result in results) {
                assertTrue(result.status == null && result.failure != null && result.failure != "timeout",
                    "expected a closed connection; status=${result.status}, failure=${result.failure}")
            }
            assertTrue(server.capacity.overloadConnectionsClosed.get() >= 3)
            closePinned()
            awaitServing(port)
        } finally { closePinned(); server.stop() }
    }

    @Test
    fun `clients that never finish their headers release every worker at the header deadline`() {
        val server = server(WebAdmissionLimits(headerDeadlineMs = 300))
        try {
            val port = server.serverPort
            val slow = (1..16 + 4).map { slowHeaders(port) }
            await("every unfinished header block to be closed") { server.capacity.headerDeadlineClosures.get() >= 20 }
            slow.forEach { assertTrue(closedByServer(it), "the server closes an unfinished header block") }
            await("idle workers") { server.admissionSample().activeWorkers == 0 }
            assertEquals(401, get(port).status, "freed workers serve new requests")
        } finally { closePinned(); server.stop() }
    }

    @Test
    fun `a stalled upload body is closed at its deadline and releases its worker and staged file handles`() {
        val server = server(WebAdmissionLimits(uploadDeadlineMs = 2_000))
        try {
            val port = server.serverPort
            val token = server.issueBrowserBootstrap().token
            val login = send(port, "POST /w/api/v1/session HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nOrigin: http://127.0.0.1:$port\r\n" +
                "Content-Type: application/json\r\nAccept: application/json\r\nContent-Length: ${token.length + 12}\r\nConnection: close\r\n\r\n" +
                "{\"token\":\"$token\"}")
            assertEquals(200, login.status)
            val cookie = login.headers.getValue("set-cookie").substringBefore(';')
            val csrf = Json.parseToJsonElement(login.body).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
            val upload = Socket("127.0.0.1", port)
            pinned += upload
            upload.getOutputStream().write(("POST /w/api/v1/jobs HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nOrigin: http://127.0.0.1:$port\r\n" +
                "Cookie: $cookie\r\nX-CSRF-Token: $csrf\r\nIdempotency-Key: stalled_upload_0123456789\r\nAccept: application/json\r\n" +
                "Content-Type: multipart/form-data; boundary=b\r\nContent-Length: 1048576\r\n\r\n" +
                "--b\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"slow.elf\"\r\n\r\n\u007fELF").toByteArray())
            upload.getOutputStream().flush()
            assertTrue(closedByServer(upload), "the server ends a stalled upload")
            await("the stalled exchange to release its worker") { server.admissionSample().activeWorkers == 0 }
            assertTrue(server.capacity.requestDeadlineClosures.get() >= 1)
            await("no open descriptor under job storage") { openDescriptorsUnder(directory.resolve("jobs")) == 0 }
            await("no retained upload stage") {
                !Files.exists(directory.resolve("jobs")) || Files.list(directory.resolve("jobs")).use { entries ->
                    entries.noneMatch { it.fileName.toString().startsWith(".upload-") }
                }
            }
            assertEquals(401, get(port).status)
        } finally { closePinned(); server.stop() }
    }

    @Test
    fun `oversized header blocks are refused and capacity reports aggregate outcomes without request content`() {
        val server = server()
        try {
            val port = server.serverPort
            val many = (1..150).joinToString("") { "X-Fill-$it: value\r\n" }
            val refused = get(port, headers = many)
            assertEquals(431, refused.status)
            assertEquals("HEADERS_TOO_LARGE", Json.parseToJsonElement(refused.body).jsonObject.getValue("error").jsonObject
                .getValue("code").jsonPrimitive.content)
            val token = server.issueBrowserBootstrap().token
            val login = send(port, "POST /w/api/v1/session HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nOrigin: http://127.0.0.1:$port\r\n" +
                "Content-Type: application/json\r\nAccept: application/json\r\nContent-Length: ${token.length + 12}\r\nConnection: close\r\n\r\n" +
                "{\"token\":\"$token\"}")
            val cookie = login.headers.getValue("set-cookie").substringBefore(';')
            get(port, path = "/w/api/v1/jobs/${"a".repeat(32)}?private=/home/secret", headers = "Cookie: $cookie\r\n")
            // An event stream answers from its own worker after the HTTP handler returned; it is still counted once.
            val stream = send(port, "GET /w/api/v1/jobs/${"b".repeat(32)}/runs/run_missing/events HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n" +
                "Accept: text/event-stream\r\nCookie: $cookie\r\nConnection: close\r\n\r\n")
            assertEquals(404, stream.status, stream.failure)
            await("the stream outcome to be recorded") { reasons(Json.parseToJsonElement(get(port, path = "/w/api/v1/capacity",
                headers = "Cookie: $cookie\r\n").body).jsonObject.getValue("data").jsonObject)["NOT_FOUND"] == 1L }
            val response = get(port, path = "/w/api/v1/capacity", headers = "Cookie: $cookie\r\n")
            assertEquals(200, response.status, response.body)
            val body = Json.parseToJsonElement(response.body).jsonObject
            assertEquals("capacity", body.getValue("kind").jsonPrimitive.content)
            val data = body.getValue("data").jsonObject
            val schema = Json.parseToJsonElement(Files.readString(Path.of("contracts/web/v1/contract.schema.json"))).jsonObject
                .getValue("definitions").jsonObject.getValue("capacity").jsonObject.getValue("properties").jsonObject
            assertEquals(schema.keys, data.keys)
            for (section in listOf("http", "streams", "outcomes")) assertEquals(
                schema.getValue(section).jsonObject.getValue("properties").jsonObject.keys, data.getValue(section).jsonObject.keys, section)
            val http = data.getValue("http").jsonObject
            assertEquals(16, http.getValue("workerLimit").jsonPrimitive.content.toInt())
            assertEquals(64, http.getValue("queueCapacity").jsonPrimitive.content.toInt())
            assertEquals("10000", http.getValue("headerDeadlineMs").jsonPrimitive.content)
            assertEquals("120000", http.getValue("requestDeadlineMs").jsonPrimitive.content)
            val streams = data.getValue("streams").jsonObject
            assertEquals(2, streams.getValue("perSessionLimit").jsonPrimitive.content.toInt())
            val outcomes = data.getValue("outcomes").jsonObject
            assertEquals("1", outcomes.getValue("headerLimitRejections").jsonPrimitive.content)
            assertEquals("0", outcomes.getValue("closedWithoutResponse").jsonPrimitive.content, "no stream is miscounted as unanswered")
            assertTrue(outcomes.getValue("clientErrors").jsonPrimitive.content.toLong() >= 2)
            val reasons = reasons(data)
            assertEquals(1L, reasons["HEADERS_TOO_LARGE"])
            assertTrue(reasons.keys.all { it.matches(Regex("[A-Z][A-Z0-9_]*")) })
            listOf("secret", "/home", "X-Fill", cookie.substringAfter('='), token).forEach { assertFalse(response.body.contains(it), it) }
            assertEquals(401, get(port, path = "/w/api/v1/capacity").status, "capacity is private to a session")
            assertEquals(400, get(port, path = "/w/api/v1/capacity?x=1", headers = "Cookie: $cookie\r\n").status)
        } finally { closePinned(); server.stop() }
    }

    private fun reasons(data: JsonObject): Map<String, Long> = data.getValue("failureReasons").jsonArray.associate {
        it.jsonObject.getValue("code").jsonPrimitive.content to it.jsonObject.getValue("count").jsonPrimitive.content.toLong()
    }

    internal fun openDescriptorsUnder(root: Path): Int {
        val descriptors = Path.of("/proc/self/fd")
        if (!Files.isDirectory(descriptors)) return 0
        val prefix = root.toAbsolutePath().normalize().toString()
        return Files.list(descriptors).use { entries ->
            // Ownership lock files are held for the listener lifetime by design; nothing else may stay open.
            entries.toList().mapNotNull { runCatching { Files.readSymbolicLink(it).toString() }.getOrNull() }
                .count { it.startsWith(prefix) && !it.endsWith("-owner.lock") }
        }
    }
}
