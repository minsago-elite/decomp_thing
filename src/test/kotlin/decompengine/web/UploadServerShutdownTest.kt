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
}
