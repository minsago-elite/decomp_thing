package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.JobStoreException
import decompengine.jobs.elfFixture
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.path.*
import kotlin.test.*

class WebRecoveryAdmissionTest {
    @Test fun `queued request cannot deadlock failed startup cleanup`() {
        val root = createTempDirectory("web-recovery-queued-")
        val broken = root.resolve("a".repeat(32)).createDirectory()
        broken.resolve("job.json").writeText("invalid fixture")
        val server = UploadServer("127.0.0.1", 0, root)
        val port = server.serverPort
        java.net.Socket("127.0.0.1", port).use { client ->
            client.getOutputStream().apply {
                write("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".toByteArray())
                flush()
            }
            val start = java.util.concurrent.FutureTask { assertFailsWith<JobStoreException> { server.start() } }
            Thread(start, "failed-start-fixture").apply { isDaemon = true; start() }
            val failure = start.get(5, java.util.concurrent.TimeUnit.SECONDS)
            assertEquals("Job recovery inspection is incomplete; no recovery statuses were changed", failure.message)
        }
        server.stop(0)
        Files.move(broken, root.resolve("retained-invalid"))
        val replacement = UploadServer("127.0.0.1", port, root)
        try { replacement.start() } finally { replacement.stop(0) }
    }

    @Test fun `rejected duplicate start does not shut down a running server`() {
        val server = UploadServer("127.0.0.1", 0, createTempDirectory("web-duplicate-start-"))
        server.start()
        try {
            assertFailsWith<IllegalStateException> { server.start() }
            val response = java.net.URI("http://127.0.0.1:${server.serverPort}/").toURL().openConnection() as java.net.HttpURLConnection
            response.connectTimeout = 5000
            response.readTimeout = 5000
            try { assertEquals(200, response.responseCode) } finally { response.disconnect() }
        } finally { server.stop(0) }

    @Test fun `stop before startup preserves pending records and releases its listener`() {
        val root = createTempDirectory("web-stop-before-recovery-")
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
            assertEquals("failed", store.get(job.id).status)
        } finally { replacement.stop() }
    }

    @Test fun `incomplete startup recovery releases ownership and listener without changing statuses`() {
        val root = createTempDirectory("web-recovery-admission-")
        val store = JobStore(root)
        val job = store.createFromUpload("fixture.elf", elfFixture())
        store.updateStatus(job.id, "analyzing")
        val broken = root.resolve("a".repeat(32)).createDirectory()
        broken.resolve("job.json").writeText("private-invalid-record")
        val server = UploadServer("127.0.0.1", 0, root)
        val port = server.serverPort
        try {
            val failure = assertFailsWith<JobStoreException> { server.start() }
            assertEquals("Job recovery inspection is incomplete; no recovery statuses were changed", failure.message)
            assertEquals("analyzing", store.get(job.id).status)
            assertEquals("private-invalid-record", broken.resolve("job.json").readText())
        } finally { server.stop(0) }
        // Explicitly retain the invalid fixture outside the published-job namespace.
        Files.move(broken, root.resolve("retained-invalid"))
        val replacement = UploadServer("127.0.0.1", port, root)
        try {
            replacement.start()
            assertEquals("failed", store.get(job.id).status)
            assertEquals("private-invalid-record", root.resolve("retained-invalid/job.json").readText())
        } finally { replacement.stop(0) }
    }

    @Test fun `request admission racing the stop signal is refused once cancellation is observable`() {
        val root = createTempDirectory("web-admission-fence-")
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
}
