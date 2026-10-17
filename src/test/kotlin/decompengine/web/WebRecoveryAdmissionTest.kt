package decompengine.web

import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import org.junit.jupiter.api.extension.ExtendWith
import decompengine.jobs.JobStore
import decompengine.jobs.WorkflowStoreException
import decompengine.jobs.elfFixture
import java.net.BindException
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.path.*
import kotlin.test.*

@ExtendWith(RecoveryMatrixEvidence::class)
class WebRecoveryAdmissionTest {
    @Test fun `queued request cannot deadlock failed startup cleanup`() = withRoot { root ->
        val broken = root.resolve("a".repeat(32)).createDirectory()
        broken.resolve("job.json").writeText("invalid fixture")
        val server = UploadServer("127.0.0.1", 0, root)
        val port = server.serverPort
        java.net.Socket("127.0.0.1", port).use { client ->
            client.getOutputStream().apply {
                write("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".toByteArray())
                flush()
            }
            // Startup fails closed because stop precedes start; cleanup must not deadlock on
            // the queued handler that was never admitted.
            server.stop(0)
            val start = java.util.concurrent.FutureTask { assertFailsWith<IllegalStateException> { server.start() } }
            Thread(start, "failed-start-fixture").apply { isDaemon = true; start() }
            start.get(5, java.util.concurrent.TimeUnit.SECONDS)
        }
        server.stop(0)
        Files.move(broken, root.resolve("retained-invalid"))
        val replacement = UploadServer("127.0.0.1", port, root)
        try { replacement.start() } finally { replacement.stop(0) }
    }

    @Test fun `rejected duplicate start does not shut down a running server`() = withRoot { root ->
        val server = UploadServer("127.0.0.1", 0, root)
        server.start()
        try {
            assertFailsWith<IllegalStateException> { server.start() }
            val response = java.net.URI("http://127.0.0.1:${server.serverPort}/").toURL().openConnection() as java.net.HttpURLConnection
            response.setRequestProperty("Cookie", legacySessionHeaders(server).getValue("Cookie"))
            response.connectTimeout = 5000
            response.readTimeout = 5000
            try { assertEquals(200, response.responseCode) } finally { response.disconnect() }
        } finally { server.stop(0) }
    }

    @Test fun `stop before startup preserves pending records and releases its listener`() = withRoot { root ->
        val store = JobStore(root)
        val job = store.createFromUpload("fixture.elf", elfFixture())
        store.updateStatus(job.id, "queued")
        val server = UploadServer("127.0.0.1", 0, root)
        val port = server.serverPort
        server.stop()
        assertFailsWith<IllegalStateException> { server.start() }
        assertFalse(server.withActiveRequest { error("stopped server admitted work") })
        assertEquals("queued", store.get(job.id).status)
        val replacement = UploadServer("127.0.0.1", port, root)
        try {
            replacement.start()
            // Recovery projects interruption for reads without rewriting the pending record.
            assertEquals("queued", store.get(job.id).status)
        } finally { replacement.stop() }
    }

    @Test fun `incomplete startup recovery releases ownership and listener without changing statuses`() = withRoot { root ->
        val store = JobStore(root)
        val job = store.createFromUpload("fixture.elf", elfFixture())
        store.updateStatus(job.id, "analyzing")
        val metadata = root.resolve(job.id).resolve("job.json")
        val before = Files.readAllBytes(metadata)
        // Corrupt legacy jobs are quarantined by the shared service; an unknown versioned
        // upload stage is an actual initialization refusal before a listener may serve work.
        val broken = Files.createDirectory(root.resolve(".upload-stream-v1-96901"),
            java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        broken.resolve("unexpected.txt").writeText("private-retained-data")
        val port = unusedPort()
        val failure = assertFailsWith<WorkflowStoreException> { UploadServer("127.0.0.1", port, root) }
        assertEquals("UPLOAD_STAGING_RECOVERY_REQUIRED", failure.code)
        assertEquals("analyzing", store.get(job.id).status)
        assertContentEquals(before, Files.readAllBytes(metadata))
        assertEquals("private-retained-data", broken.resolve("unexpected.txt").readText())
        // Operator reconciliation retains the unknown data under an ordinary non-job name.
        Files.move(broken, root.resolve("retained-invalid"))
        val replacement = UploadServer("127.0.0.1", port, root)
        try {
            replacement.start()
            assertEquals("analyzing", store.get(job.id).status)
            assertContentEquals(before, Files.readAllBytes(metadata))
            assertEquals("private-retained-data", root.resolve("retained-invalid/unexpected.txt").readText())
        } finally { replacement.stop(0) }
    }

    @Test fun `startup thread interruption prevents the listener from starting and preserves records`() = withRoot { root ->
        val store = JobStore(root)
        val job = store.createFromUpload("fixture.elf", elfFixture())
        store.updateStatus(job.id, "queued")
        val metadata = root.resolve(job.id).resolve("job.json")
        val before = Files.readAllBytes(metadata)
        val server = UploadServer("127.0.0.1", 0, root)
        val port = server.serverPort
        var failure: Throwable? = null
        var exitedInterrupted = false
        val starter = Thread {
            Thread.currentThread().interrupt()
            try { server.start() } catch (problem: Throwable) { failure = problem }
            exitedInterrupted = Thread.currentThread().isInterrupted
        }
        starter.isDaemon = true
        starter.start()
        starter.join(15000)
        assertTrue(!starter.isAlive)
        val cancelled = assertIs<IllegalStateException>(failure)
        assertEquals("Web server startup cancelled", cancelled.message)
        assertTrue(exitedInterrupted)
        assertEquals("queued", store.get(job.id).status)
        assertContentEquals(before, Files.readAllBytes(metadata))
        assertFalse(server.withActiveRequest { error("interrupted startup must not admit requests") })
        val replacement = UploadServer("127.0.0.1", port, root)
        try {
            replacement.start()
            assertEquals("queued", store.get(job.id).status)
            assertContentEquals(before, Files.readAllBytes(metadata))
        } finally { replacement.stop(0) }
    }

    @Test fun `request admission racing the stop signal is refused once cancellation is observable`() = withRoot { root ->
        val server = UploadServer("127.0.0.1", 0, root)
        server.start()
        try {
            val stopReturned = AtomicBoolean(false)
            val refusals = AtomicInteger()
            val problems = AtomicReference<Throwable>()
            val racers = List(4) {
                Thread {
                    try {
                        var refused = 0
                        while (!stopReturned.get()) {
                            var ran = false
                            server.withActiveRequest { ran = true }
                            if (!ran) refused++
                        }
                        // Also require every racer to observe refusal after the published stop
                        // signal, even when shutdown finishes before it gets its first timeslice.
                        check(!server.withActiveRequest { error("request ran after observable stop") })
                        refused++
                        refusals.addAndGet(refused)
                    } catch (problem: Throwable) {
                        problems.set(problem)
                    }
                }
            }
            racers.forEach { racer -> racer.isDaemon = true; racer.start() }
            // stop() publishes cancellation outside lifecycleLock; admission decisions that
            // observe the signal afterwards must be refused rather than admitted past it.
            val shutdown = runCatching { server.stop() }
            stopReturned.set(true)
            racers.forEach { it.join(5000) }
            racers.forEach { check(!it.isAlive) }
            assertNull(problems.get())
            assertTrue(shutdown.isSuccess || shutdown.exceptionOrNull()?.message == "HTTP requests remain active after server stop")
            assertTrue(refusals.get() > 0)
            assertFalse(server.withActiveRequest { error("stopped server admitted work") })
        } finally { runCatching { server.stop() } }
    }

    @Test fun `listener bind failure releases store ownership for a replacement server`() = withRoot { root ->
        val occupied = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port = occupied.localPort
        try {
            assertFailsWith<BindException> { UploadServer("127.0.0.1", port, root) }
        } finally { occupied.close() }
        val replacement = UploadServer("127.0.0.1", port, root)
        try {
            replacement.start()
            assertTrue(replacement.withActiveRequest { })
        } finally { replacement.stop(0) }
    }

    private fun unusedPort(): Int = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }

    private fun withRoot(block: (Path) -> Unit) {
        val temporaryRoot = Files.createDirectories(Path.of("build/test-tmp/web-recovery-admission").toAbsolutePath())
        val root = createTempDirectory(temporaryRoot, "web-recovery-")
        try { block(root) } finally { root.toFile().deleteRecursively() }
    }
}
