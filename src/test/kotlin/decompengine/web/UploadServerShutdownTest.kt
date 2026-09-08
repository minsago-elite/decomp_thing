package decompengine.web

import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.test.*

/** Controlled request-admission fixtures only; no workflow or external target executes. */
class UploadServerShutdownTest {
    @Test fun `stop waits for an admitted handler and retains ownership until it leaves`() = checkDrain(false)

    @Test fun `interrupted stop still drains admitted handlers and restores the interrupt flag`() = checkDrain(true)

    private fun checkDrain(interrupted: Boolean) {
        val root = Files.createTempDirectory("web-request-drain-")
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

    @Test fun `request drain timeout preserves ownership and later cleanup permits retry`() {
        val root = Files.createTempDirectory("web-request-drain-timeout-")
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
