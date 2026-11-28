package decompengine.web

import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import org.junit.jupiter.api.extension.ExtendWith
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.test.*

/** Controlled request-admission and archive-worker fixtures only; no workflow or external target executes. */
@ExtendWith(RecoveryMatrixEvidence::class)
class UploadServerShutdownTest {
    @Test fun `stop drains an actual request-worker audit append without setting durable loss`() {
        val root = createTempDirectory("web-request-audit-drain-")
        val server = UploadServer("127.0.0.1", 0, root, requestShutdownTimeoutMs = 3000)
        val caller = Executors.newSingleThreadExecutor()
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        fun record() = server.audit.record(WebAuditActor.OPERATOR, WebAuditAction.SUPPORT_EXPORT,
            WebAuditTarget(), WebAuditOutcome.ACCEPTED, 200, null, null)
        server.start()
        try {
            assertEquals(1L, record()?.sequence)
            // Pause the real audit append on the actual request executor without adding a production hook.
            val append: (java.nio.channels.FileChannel, java.nio.ByteBuffer) -> Unit = { channel, bytes ->
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS))
                while (bytes.hasRemaining()) channel.write(bytes)
            }
            WebAuditLog::class.java.getDeclaredField("append").apply { isAccessible = true }.set(server.audit, append)
            val worker = UploadServer::class.java.getDeclaredField("requestExecutor").apply { isAccessible = true }.get(server)
                as java.util.concurrent.ExecutorService
            val request = worker.submit<Boolean> { server.withActiveRequest { assertEquals(2L, record()?.sequence) } }
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            val stop = caller.submit { server.stop() }
            assertFailsWith<TimeoutException> { stop.get(150, TimeUnit.MILLISECONDS) }
            assertFailsWith<IllegalStateException> { UploadServer("127.0.0.1", 0, root) }
            release.countDown()
            assertTrue(request.get(3, TimeUnit.SECONDS))
            stop.get(3, TimeUnit.SECONDS)
            val reopened = WebAuditLog(root).read()
            assertEquals(2, reopened.entries.size)
            assertTrue(reopened.complete)
            assertEquals("0", Files.readString(root.resolve(".web-audit/incomplete")))
        } finally {
            release.countDown(); caller.shutdownNow()
            assertTrue(caller.awaitTermination(5, TimeUnit.SECONDS))
            server.stop(); root.toFile().deleteRecursively()
        }
    }

    /** Hold the real fsync'd append of the server's audit log until [release]; [entered] marks it reached. */
    private fun holdAuditAppends(server: UploadServer, entered: CountDownLatch, release: CountDownLatch,
                                 finished: java.util.concurrent.atomic.AtomicBoolean = java.util.concurrent.atomic.AtomicBoolean()) {
        val append: (java.nio.channels.FileChannel, java.nio.ByteBuffer) -> Unit = { channel, bytes ->
            entered.countDown()
            check(release.await(10, TimeUnit.SECONDS))
            while (bytes.hasRemaining()) channel.write(bytes)
            finished.set(true)
        }
        WebAuditLog::class.java.getDeclaredField("append").apply { isAccessible = true }.set(server.audit, append)
    }

    /** An audited legacy session request: refused without an Origin, and recorded after its response. */
    private fun auditedRequest(server: UploadServer): Int = java.net.http.HttpClient.newHttpClient().send(
        java.net.http.HttpRequest.newBuilder(java.net.URI("http://127.0.0.1:${server.serverPort}/api/v1/session"))
            .timeout(java.time.Duration.ofSeconds(10)).header("Content-Type", "application/json")
            .POST(java.net.http.HttpRequest.BodyPublishers.ofString("{}")).build(),
        java.net.http.HttpResponse.BodyHandlers.discarding()).statusCode()

    private fun assertWholeAuditEntry(root: java.nio.file.Path, action: WebAuditAction = WebAuditAction.SESSION_START) {
        val reopened = WebAuditLog(root).read()
        assertEquals(listOf(action), reopened.entries.map { it.action })
        assertEquals(0L, reopened.unrecordedEntries)
        assertTrue(reopened.complete)
        val segment = Files.readString(root.resolve(".web-audit/current.jsonl"))
        assertTrue(segment.endsWith("\n"), "audit segment must end with a complete record")
        segment.lines().filter(String::isNotEmpty).forEach(WebAuditEntry::parse)
        assertEquals("0", Files.readString(root.resolve(".web-audit/incomplete")))
    }

    private fun elapsedMs(started: Long) = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)

    @Test fun `stop waits past the request bound for a held post-response audit append and keeps its entry whole`() {
        val root = createTempDirectory("web-post-response-audit-drain-")
        val server = UploadServer("127.0.0.1", 0, root, requestShutdownTimeoutMs = 100, auditShutdownTimeoutMs = 5000)
        val caller = Executors.newSingleThreadExecutor()
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        server.start()
        try {
            holdAuditAppends(server, entered, release)
            assertTrue(auditedRequest(server) >= 400, "the response is sent before its audit append")
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            val started = System.nanoTime()
            val stop = caller.submit<WebStopOutcome> { server.stop() }
            // Well past the 100 ms request bound, stop is still waiting for the held append.
            assertFailsWith<TimeoutException> { stop.get(600, TimeUnit.MILLISECONDS) }
            assertFailsWith<IllegalStateException> { UploadServer("127.0.0.1", 0, root) }
            release.countDown()
            assertEquals(WebStopOutcome.STOPPED, stop.get(3, TimeUnit.SECONDS))
            assertTrue(elapsedMs(started) < 4000)
            assertWholeAuditEntry(root)
            val replacement = UploadServer("127.0.0.1", 0, root)
            try { replacement.start() } finally { replacement.stop() }
        } finally {
            release.countDown(); caller.shutdownNow()
            assertTrue(caller.awaitTermination(5, TimeUnit.SECONDS))
            server.stop(); root.toFile().deleteRecursively()
        }
    }

    @Test fun `stop returns audit-pending past the audit bound and retains ownership until the append finishes`() {
        val root = createTempDirectory("web-post-response-audit-bound-")
        val server = UploadServer("127.0.0.1", 0, root, requestShutdownTimeoutMs = 50, auditShutdownTimeoutMs = 400)
        val caller = Executors.newSingleThreadExecutor()
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val finished = java.util.concurrent.atomic.AtomicBoolean()
        server.start()
        try {
            holdAuditAppends(server, entered, release, finished)
            assertTrue(auditedRequest(server) >= 400)
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            val started = System.nanoTime()
            val stop = caller.submit<WebStopOutcome> { server.stop() }
            assertEquals(WebStopOutcome.AUDIT_PENDING, stop.get(3, TimeUnit.SECONDS))
            val waited = elapsedMs(started)
            assertTrue(waited in 350..2500, "stop must wait for the audit bound and no longer: $waited ms")
            assertFalse(finished.get(), "stop returned while the append was still held")
            // The append still owns the store; a CLI stop reports unknown durability instead of success.
            assertFailsWith<IllegalStateException> { UploadServer("127.0.0.1", 0, root) }
            assertFalse(server.awaitStoreRelease(0))
            assertFailsWith<WebShutdownAuditPending> { stopWebServerForCli(server) }
            release.countDown()
            assertTrue(server.awaitStoreRelease(5000))
            assertEquals(WebStopOutcome.STOPPED, server.stop())
            assertWholeAuditEntry(root)
            val replacement = UploadServer("127.0.0.1", 0, root)
            try { replacement.start() } finally { replacement.stop() }
        } finally {
            release.countDown(); caller.shutdownNow()
            assertTrue(caller.awaitTermination(5, TimeUnit.SECONDS))
            server.stop(); root.toFile().deleteRecursively()
        }
    }

    @Test fun `an admitted append outside a completed HTTP response keeps the ordinary request bound`() {
        val root = createTempDirectory("web-unclassified-audit-")
        val server = UploadServer("127.0.0.1", 0, root, requestShutdownTimeoutMs = 100, auditShutdownTimeoutMs = 5000)
        val worker = Executors.newSingleThreadExecutor()
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        server.start()
        try {
            holdAuditAppends(server, entered, release)
            // No HTTP exchange sent a response here, so this append is ordinary request work.
            val request = worker.submit<Boolean> { server.withActiveRequest {
                server.audit.record(WebAuditActor.OPERATOR, WebAuditAction.SUPPORT_EXPORT, WebAuditTarget(),
                    WebAuditOutcome.ACCEPTED, 200, null, null)
            } }
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            val started = System.nanoTime()
            val failure = assertFailsWith<IllegalStateException> { server.stop() }
            assertEquals("HTTP requests remain active after server stop", failure.message)
            assertTrue(elapsedMs(started) < 2000, "the audit bound must not apply")
            release.countDown()
            assertTrue(request.get(3, TimeUnit.SECONDS))
            assertTrue(server.awaitStoreRelease(3000))
            assertWholeAuditEntry(root, WebAuditAction.SUPPORT_EXPORT)
        } finally {
            release.countDown(); worker.shutdownNow()
            assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS))
            server.stop(); root.toFile().deleteRecursively()
        }
    }

    @Test fun `a request that reaches its audit append only after the request deadline fails the stop`() {
        val root = createTempDirectory("web-late-audit-")
        val server = UploadServer("127.0.0.1", 0, root, requestShutdownTimeoutMs = 100, auditShutdownTimeoutMs = 5000)
        val worker = Executors.newSingleThreadExecutor()
        val handling = CountDownLatch(1); val respond = CountDownLatch(1)
        val appending = CountDownLatch(1); val release = CountDownLatch(1)
        server.start()
        try {
            holdAuditAppends(server, appending, release)
            val request = worker.submit<Boolean> { server.withActiveRequest {
                handling.countDown()
                check(respond.await(10, TimeUnit.SECONDS))
                server.postResponseAuditAppend {
                    server.audit.record(WebAuditActor.OPERATOR, WebAuditAction.SUPPORT_EXPORT, WebAuditTarget(),
                        WebAuditOutcome.ACCEPTED, 200, null, null)
                }
            } }
            assertTrue(handling.await(3, TimeUnit.SECONDS))
            // The drain decision is made while the request is still doing ordinary work at the request deadline.
            // Only then does it enter its post-response append, before stop samples ownership.
            server.requestDrainObserver = { respond.countDown(); check(appending.await(3, TimeUnit.SECONDS)) }
            val started = System.nanoTime()
            val failure = assertFailsWith<IllegalStateException> { server.stop() }
            assertEquals("HTTP requests remain active after server stop", failure.message)
            assertTrue(elapsedMs(started) < 2000, "a late append must not be reported as an expired audit bound")
            release.countDown()
            assertTrue(request.get(3, TimeUnit.SECONDS))
            assertTrue(server.awaitStoreRelease(3000))
            assertWholeAuditEntry(root, WebAuditAction.SUPPORT_EXPORT)
        } finally {
            respond.countDown(); release.countDown(); worker.shutdownNow()
            assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS))
            server.stop(); root.toFile().deleteRecursively()
        }
    }

    @Test fun `stop waits for an admitted handler and retains ownership until it leaves`() = checkDrain(false)

    @Test fun `interrupted stop still drains admitted handlers and restores the interrupt flag`() = checkDrain(true)

    private fun checkDrain(interrupted: Boolean) {
        val root = createTempDirectory("web-request-drain-")
        val server = UploadServer("127.0.0.1", 0, root, requestShutdownTimeoutMs = 3000)
        val executor = Executors.newFixedThreadPool(2)
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val stopping = CountDownLatch(1)
        server.start()
        try {
            val request = executor.submit<Boolean> {
                server.withActiveRequest { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)) }
            }
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            val stop = executor.submit<Boolean> {
                if (interrupted) Thread.currentThread().interrupt()
                stopping.countDown()
                try { server.stop(); Thread.currentThread().isInterrupted }
                finally { Thread.interrupted() }
            }
            assertTrue(stopping.await(3, TimeUnit.SECONDS))
            assertFailsWith<TimeoutException> { stop.get(150, TimeUnit.MILLISECONDS) }
            assertFailsWith<IllegalStateException> { UploadServer("127.0.0.1", 0, root) }
            release.countDown()
            assertTrue(request.get(3, TimeUnit.SECONDS))
            assertEquals(interrupted, stop.get(3, TimeUnit.SECONDS))
            val replacement = UploadServer("127.0.0.1", 0, root)
            try { replacement.start() } finally { replacement.stop() }
        } finally {
            release.countDown()
            executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
            server.stop(); root.toFile().deleteRecursively()
        }
    }

    @Test fun `interrupted SPA stop drains archive worker before closing jobs and releasing ownership`() {
        for (interruptBeforeStop in listOf(true, false)) {
            val root = createTempDirectory("web-spa-archive-drain-")
            val server = UploadServer("127.0.0.1", 0, root, uiMode = WebUiMode.SPA)
            val caller = Executors.newSingleThreadExecutor()
            val entered = CountDownLatch(1); val release = CountDownLatch(1); val stopping = CountDownLatch(1)
            val stoppingThread = java.util.concurrent.atomic.AtomicReference<Thread>()
            server.start()
            try {
                // Hold the actual archive executor without extracting/building an archive or adding a production test hook.
                val api = UploadServer::class.java.getDeclaredField("api").apply { isAccessible = true }.get(server)
                val archives = WebApiController::class.java.getDeclaredField("sourceArchives").apply { isAccessible = true }.get(api)
                val worker = WebSourceArchives::class.java.getDeclaredField("executor").apply { isAccessible = true }.get(archives)
                    as java.util.concurrent.ExecutorService
                worker.execute {
                    entered.countDown()
                    var finished = false
                    while (!finished) try { check(release.await(10, TimeUnit.SECONDS)); finished = true }
                    catch (_: InterruptedException) { } // Bounded extraction likewise need not respond to interruption.
                }
                assertTrue(entered.await(3, TimeUnit.SECONDS))
                val stop = caller.submit<Boolean> {
                    stoppingThread.set(Thread.currentThread())
                    if (interruptBeforeStop) Thread.currentThread().interrupt()
                    stopping.countDown()
                    try { server.stop(); Thread.currentThread().isInterrupted }
                    finally { Thread.interrupted() }
                }
                assertTrue(stopping.await(3, TimeUnit.SECONDS))
                assertFailsWith<TimeoutException> { stop.get(150, TimeUnit.MILLISECONDS) }
                if (!interruptBeforeStop) stoppingThread.get().interrupt()
                assertFailsWith<TimeoutException> { stop.get(150, TimeUnit.MILLISECONDS) }
                assertFailsWith<IllegalStateException> { UploadServer("127.0.0.1", 0, root) }
                release.countDown()
                assertTrue(stop.get(5, TimeUnit.SECONDS), "stop must restore interruption after cleanup")
                assertTrue(worker.isTerminated)
                val replacement = UploadServer("127.0.0.1", 0, root, uiMode = WebUiMode.SPA)
                try { replacement.start() } finally { replacement.stop() }
            } finally {
                release.countDown()
                caller.shutdownNow(); assertTrue(caller.awaitTermination(10, TimeUnit.SECONDS))
                server.stop(); root.toFile().deleteRecursively()
            }
        }
    }

    @Test fun `request drain timeout preserves ownership and later cleanup permits retry`() {
        val root = createTempDirectory("web-request-drain-timeout-")
        val server = UploadServer("127.0.0.1", 0, root, requestShutdownTimeoutMs = 100)
        val executor = Executors.newSingleThreadExecutor()
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        server.start()
        try {
            val request = executor.submit<Boolean> {
                server.withActiveRequest { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)) }
            }
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            val failure = assertFailsWith<IllegalStateException> { server.stop() }
            assertEquals("HTTP requests remain active after server stop", failure.message)
            assertFalse(server.withActiveRequest { error("request admitted after stop") })
            assertFailsWith<IllegalStateException> { UploadServer("127.0.0.1", 0, root) }
            release.countDown()
            assertTrue(request.get(3, TimeUnit.SECONDS))
            server.stop()
            val replacement = UploadServer("127.0.0.1", 0, root)
            try { replacement.start() } finally { replacement.stop() }
        } finally {
            release.countDown()
            executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
            server.stop(); root.toFile().deleteRecursively()
        }
    }


    @Test fun `stop preserves the original capacity summary when no content request entered`() {
        val root = createTempDirectory("web-phase-summary-")
        val line = java.util.concurrent.atomic.AtomicReference<String?>()
        val emitted = CountDownLatch(1)
        val server = UploadServer("127.0.0.1", 0, root, uiMode = WebUiMode.SPA,
            requestDiagnosticOutput = { value -> line.set(value); emitted.countDown() })
        server.start()
        val prefix = server.capacity.summaryLine()
        try {
            server.stop()
            assertTrue(emitted.await(2, TimeUnit.SECONDS))
            val value = line.get() ?: error("capacity line missing")
            assertEquals(prefix, value)
        } finally {
            server.stop()
            root.toFile().deleteRecursively()
        }
    }

}
