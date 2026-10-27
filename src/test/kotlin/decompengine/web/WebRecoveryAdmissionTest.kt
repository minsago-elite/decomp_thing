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
    @Test fun `missing-root ownership keys match later existing keys through a stable parent alias`() {
        val requested = Path.of("/alias/jobs")
        val expected = Path.of("/physical/jobs")
        val checked = mutableListOf<Path>()
        val resolved = mutableListOf<Path>()
        val beforeCreation = canonicalWebJobStoreRoot(requested,
            knownAbsent = { checked.add(it); it == requested },
            realPath = { resolved.add(it); assertEquals(Path.of("/alias"), it); Path.of("/physical") })
        val afterCreation = canonicalWebJobStoreRoot(requested,
            knownAbsent = { false }, realPath = { assertEquals(requested, it); expected })
        assertEquals(expected, beforeCreation)
        assertEquals(beforeCreation, afterCreation)
        assertEquals(listOf(requested, Path.of("/alias")), checked)
        assertEquals(listOf(Path.of("/alias")), resolved)
    }

    @Test fun `ownership key discovery preserves missing names and resolves only the nearest existing ancestor`() {
        val requested = Path.of("/alias/new/inner/../jobs")
        val visited = mutableListOf<Path>()
        val resolved = mutableListOf<Path>()
        val actual = canonicalWebJobStoreRoot(requested,
            knownAbsent = { visited.add(it); it != Path.of("/alias") },
            realPath = { resolved.add(it); Path.of("/physical") })
        assertEquals(Path.of("/physical/new/jobs"), actual)
        assertEquals(listOf(Path.of("/alias/new/jobs"), Path.of("/alias/new"), Path.of("/alias")), visited)
        assertEquals(listOf(Path.of("/alias")), resolved)
        val existing = Path.of("/already-present")
        assertEquals(Path.of("/canonical-present"), canonicalWebJobStoreRoot(existing,
            knownAbsent = { assertEquals(existing, it); false },
            realPath = { assertEquals(existing, it); Path.of("/canonical-present") }))
    }

    @Test fun `indeterminate ownership paths and invalid roots cannot fall back to an unverified key`() {
        val requested = Path.of("/alias/jobs")
        val original = java.io.IOException("PRIVATE unresolved path")
        val visited = mutableListOf<Path>()
        val failure = assertFailsWith<java.io.IOException> {
            canonicalWebJobStoreRoot(requested,
                knownAbsent = { visited.add(it); false }, realPath = { throw original })
        }
        assertSame(original, failure)
        assertEquals(listOf(requested), visited)
        assertTrue(original.suppressed.isEmpty())
        assertFailsWith<IllegalArgumentException> {
            canonicalWebJobStoreRoot(Path.of("relative/jobs"),
                knownAbsent = { error("invalid input cannot inspect storage") },
                realPath = { error("invalid input cannot resolve storage") })
        }
        assertFailsWith<IllegalStateException> {
            canonicalWebJobStoreRoot(Path.of("/"), knownAbsent = { true },
                realPath = { error("a missing filesystem root cannot resolve") })
        }
    }

    @Test fun `queued request cannot deadlock failed startup cleanup`() = withRoot { root ->
        val server = UploadServer("127.0.0.1", 0, root)
        // Runtime corruption is separate from strict construction-time recovery admission.
        val broken = root.resolve("a".repeat(32)).createDirectory()
        broken.resolve("job.json").writeText("invalid fixture")
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
        // An unknown versioned upload stage refuses initialization before a listener may serve work.
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
