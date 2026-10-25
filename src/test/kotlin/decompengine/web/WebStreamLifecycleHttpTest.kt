package decompengine.web

import decompengine.jobs.AgentProgressJournal
import decompengine.jobs.JobStore
import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowJobInspection
import decompengine.jobs.WorkflowKind
import decompengine.jobs.elfFixture
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.BufferedReader
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Stream and listener lifecycle through the real UploadServer: the per-session stream cap, graceful
 * shutdown with open streams, and release of the listener, worker threads and store ownership.
 */
class WebStreamLifecycleHttpTest {
    private val root: Path = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp")), "web-stream-lifecycle-")

    @AfterTest fun cleanup() { root.toFile().deleteRecursively() }

    private fun fixture(): Pair<String, String> {
        val job = JobStore(root).createFromUpload("inert.elf", elfFixture())
        val run = WorkflowAttemptStore.open(root).use { owner ->
            val current = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            owner.create(job.id, current.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
        }
        val reports = Files.createDirectories(root.resolve(job.id).resolve("reports/runs/${run.runId}"))
        AgentProgressJournal(reports, "reconstruct").use { it.phase(decompengine.agent.AgentWorkflowPhase.PLANNING) }
        return job.id to run.runId
    }

    private fun server(shutdownMs: Long = 1000) = UploadServer("127.0.0.1", 0, root,
        JobAnalyzer { _, _ -> error("analysis must remain inert") }, JobReconstructor { _, _ -> error("reconstruction must remain inert") },
        uiMode = WebUiMode.SPA, basePath = "/w/", sensitiveValues = emptyList(), requestShutdownTimeoutMs = shutdownMs)

    private fun raw(port: Int, request: String): Pair<Socket, BufferedReader> {
        val socket = Socket("127.0.0.1", port).apply { soTimeout = 10_000 }
        socket.getOutputStream().write(request.toByteArray())
        return socket to socket.getInputStream().bufferedReader()
    }

    private fun cookie(server: UploadServer): String {
        val port = server.serverPort
        val body = "{\"token\":\"${server.issueBrowserBootstrap().token}\"}"
        val (socket, reader) = raw(port, "POST /w/api/v1/session HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nOrigin: http://127.0.0.1:$port\r\n" +
            "Content-Type: application/json\r\nAccept: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n$body")
        socket.use {
            val head = generateSequence { reader.readLine() }.takeWhile { it.isNotEmpty() }.toList()
            assertEquals("HTTP/1.1 200 OK", head.first())
            return head.first { it.startsWith("Set-Cookie:", ignoreCase = true) }.substringAfter(':').trim().substringBefore(';')
        }
    }

    /** Opens one SSE stream and returns once the server announced it, with its slot charged. */
    private fun stream(port: Int, cookie: String, jobId: String, runId: String): Pair<Socket, BufferedReader> {
        val opened = raw(port, "GET /w/api/v1/jobs/$jobId/runs/$runId/events HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n" +
            "Cookie: $cookie\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n")
        assertEquals("HTTP/1.1 200 OK", opened.second.readLine())
        while (opened.second.readLine() != ": connected") Unit
        return opened
    }

    private fun ended(reader: BufferedReader): Boolean = CompletableFuture.supplyAsync {
        try { while (reader.readLine() != null) Unit; true } catch (_: IOException) { true }
    }.get(10, TimeUnit.SECONDS)

    /** Per-listener platform threads; the process-wide diagnostic sink and virtual stream workers are excluded. */
    private fun webThreads(): Set<Thread> = Thread.getAllStackTraces().keys.filter { thread ->
        listOf("decomp-web-http", "decomp-web-deadline", "decomp-web-overload", "decomp-web-stream-deadline", "HTTP-Dispatcher")
            .any(thread.name::startsWith)
    }.toSet()

    @Test
    fun `graceful stop ends open streams and releases the listener threads and store ownership`() {
        val (jobId, runId) = fixture()
        val before = webThreads()
        val server = server()
        server.start()
        val port = server.serverPort
        val streams = try {
            val cookie = cookie(server)
            val open = listOf(stream(port, cookie, jobId, runId), stream(port, cookie, jobId, runId))
            assertEquals(2, server.streamResources.snapshot().active)
            // A third stream on the same session is a typed, retryable refusal, not a queued connection.
            val (refusedSocket, refused) = raw(port, "GET /w/api/v1/jobs/$jobId/runs/$runId/events HTTP/1.1\r\n" +
                "Host: 127.0.0.1:$port\r\nCookie: $cookie\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n")
            refusedSocket.use {
                val text = refused.readText()
                assertTrue(text.startsWith("HTTP/1.1 429 "), text)
                assertTrue(text.contains("\r\nRetry-after: 30\r\n", ignoreCase = true), text)
                val error = Json.parseToJsonElement(text.substringAfter("\r\n\r\n")).jsonObject.getValue("error").jsonObject
                assertEquals("STREAM_LIMIT", error.getValue("code").jsonPrimitive.content)
            }
            assertEquals(2, server.streamResources.snapshot().active, "a refused stream is never charged")
            open
        } catch (failure: Throwable) { server.stop(); throw failure }
        val owned = webThreads() - before
        assertTrue(owned.any { it.name.startsWith("decomp-web-http") }, "the listener owns request workers: $owned")

        server.stop()
        streams.forEach { (socket, reader) -> socket.use { assertTrue(ended(reader), "an open stream must end at shutdown") } }
        assertEquals(WebStreamResources.Snapshot(0, 0, true), server.streamResources.snapshot())
        owned.forEach { it.join(10_000) }
        assertEquals(emptyList(), owned.filter(Thread::isAlive).map(Thread::getName), "listener threads outlived stop")
        ServerSocket(port, 1, InetAddress.getByName("127.0.0.1")).close()
        server().also { it.start() }.stop()
    }

    @Test
    fun `a stream that outlives the bounded shutdown wait releases store ownership when it ends`() {
        val server = server(shutdownMs = 0)
        server.start()
        val release = CountDownLatch(1)
        val running = CountDownLatch(1)
        val session = AuthorizedWebSession("fixture-session", Instant.EPOCH, Instant.EPOCH)
        // An uncooperative writer: closing its connection and interrupting it do not end the work.
        server.streamResources.submit(session, AutoCloseable { }) {
            running.countDown()
            while (true) {
                try { if (release.await(10, TimeUnit.SECONDS)) break } catch (_: InterruptedException) { }
            }
        }
        assertTrue(running.await(10, TimeUnit.SECONDS))
        val failure = assertFailsWith<IllegalStateException> { server.stop() }
        assertEquals("HTTP requests remain active after server stop", failure.message)
        assertEquals(1, server.streamResources.snapshot().active)
        assertFailsWith<IllegalStateException>("ownership is retained while the stream still runs") { server() }

        release.countDown()
        // No second stop: the last stream reservation itself hands back store ownership.
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        var replacement: UploadServer? = null
        while (replacement == null && System.nanoTime() < deadline) {
            replacement = try { server() } catch (_: IllegalStateException) { Thread.sleep(10); null }
        }
        checkNotNull(replacement) { "store ownership was never released after the late stream ended" }
        replacement.start()
        replacement.stop()
        assertEquals(WebStreamResources.Snapshot(0, 0, true), server.streamResources.snapshot())
    }
}
