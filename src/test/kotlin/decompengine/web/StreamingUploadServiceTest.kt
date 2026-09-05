package decompengine.web

import decompengine.jobs.*
import java.io.ByteArrayInputStream
import java.nio.file.Files
import java.util.concurrent.*
import kotlin.io.path.createTempDirectory
import kotlin.test.*

class StreamingUploadServiceTest {
    private val type = "multipart/form-data; boundary=upload_fixture"
    private fun body() = "--upload_fixture\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"fixture.elf\"\r\n\r\n".toByteArray() + elfFixture() + "\r\n--upload_fixture--\r\n".toByteArray()
    private fun blocked(entered: CountDownLatch, release: CountDownLatch) = object : ByteArrayInputStream(body()) {
        var first = true
        override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
            if (first) {
                first = false; entered.countDown()
                var interrupted = false
                while (true) {
                    try { check(release.await(10, TimeUnit.SECONDS)); break }
                    catch (_: InterruptedException) { interrupted = true }
                }
                if (interrupted) Thread.currentThread().interrupt()
            }
            return super.read(bytes, offset, length)
        }
    }

    @Test fun `two streamed uploads allow status reads and reject extra admission without execution`() {
        val root = createTempDirectory("stream-upload-service-")
        val store = JobStore(root)
        val existing = store.createFromUpload("existing.elf", elfFixture())
        val service = WebJobService(store, JobAnalyzer { _, _ -> error("unexpected execution") }, JobReconstructor { _, _ -> error("unexpected execution") })
        val entered = CountDownLatch(2); val release = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        try {
            service.initializeExistingStorage()
            val tasks = (1..2).map { pool.submit<decompengine.jobs.Job> { service.uploadMultipart(blocked(entered, release), type) } }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            assertEquals(existing.id, service.get(existing.id).id)
            assertEquals(listOf(existing.id), store.jobIds())
            assertEquals(WebWorkflowAdmission.Unavailable, service.start(existing.id, WebWorkflow.EXPLORE))
            assertEquals("UPLOAD_CAPACITY", assertFailsWith<WebJobServiceException> { service.upload("blocked.elf", elfFixture()) }.code)
            assertEquals("UPLOAD_CAPACITY", assertFailsWith<WebJobServiceException> { service.uploadMultipart(body().inputStream(), type) }.code)
            release.countDown()
            val jobs = tasks.map { it.get(5, TimeUnit.SECONDS) }
            assertEquals(2, jobs.map { it.id }.toSet().size)
            assertTrue(jobs.all { it.status == "uploaded" })
            assertEquals(3, store.jobIds().size)
            assertFalse(Files.list(root).use { it.anyMatch { path -> path.fileName.toString().startsWith(".upload-") } })
        } finally { release.countDown(); pool.shutdownNow(); service.close(); root.toFile().deleteRecursively() }
    }

    @Test fun `active workflow denies upload before consuming bytes`() {
        val root = createTempDirectory("stream-upload-writer-")
        val store = JobStore(root)
        val existing = store.createFromUpload("existing.elf", elfFixture())
        val release = CountDownLatch(1)
        val entered = CountDownLatch(1)
        val service = WebJobService(store, JobAnalyzer { _, _ -> entered.countDown(); release.await() }, JobReconstructor { _, _ -> })
        try {
            service.initializeExistingStorage()
            assertIs<WebWorkflowAdmission.Started>(service.start(existing.id, WebWorkflow.EXPLORE))
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            val unread = object : java.io.InputStream() { override fun read(): Int = error("Must not consume denied upload") }
            assertEquals("UPLOAD_CAPACITY", assertFailsWith<WebJobServiceException> { service.uploadMultipart(unread, type) }.code)
            assertEquals(existing.id, service.get(existing.id).id)
        } finally { release.countDown(); service.close(); root.toFile().deleteRecursively() }
    }

    @Test fun `shutdown retains root ownership until an unresponsive upload stream actually exits`() {
        val root = createTempDirectory("stream-upload-shutdown-")
        val service = WebJobService(JobStore(root), JobAnalyzer { _, _ -> }, JobReconstructor { _, _ -> }, shutdownTimeoutMs = 0)
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val pool = Executors.newSingleThreadExecutor()
        try {
            service.initializeExistingStorage()
            val task = pool.submit<decompengine.jobs.Job> { service.uploadMultipart(blocked(entered, release), type) }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            assertEquals("SHUTDOWN_INCOMPLETE", assertFailsWith<WebJobServiceException> { service.close() }.code)
            assertEquals("OWNERSHIP_CONFLICT", assertFailsWith<WorkflowStoreException> { WorkflowAttemptStore.open(root) }.code)
            release.countDown()
            assertFailsWith<ExecutionException> { task.get(5, TimeUnit.SECONDS) }
            WorkflowAttemptStore.open(root).use { assertTrue(it.recoverAll().isEmpty()) }
            assertTrue(JobStore(root).jobIds().isEmpty())
            assertFalse(Files.list(root).use { it.anyMatch { path -> path.fileName.toString().startsWith(".upload-") } })
        } finally { release.countDown(); pool.shutdownNow(); service.close(); root.toFile().deleteRecursively() }
    }
}
