package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class WebJobServiceTest {
    @Test fun `scheduler reads preserve absent storage and distinguish shutdown and unknown executor metrics`() = withStore { _, root ->
        val absent = root.resolve("absent")
        WebJobService(JobStore(absent), JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor).use { service ->
            assertFailsWith<WebJobServiceException> { service.schedulerSnapshot() }
            service.initializeExistingStorage()
            val sample = assertIs<WebSchedulerSnapshot.Available>(service.schedulerSnapshot())
            assertEquals(0, sample.activeWorkers)
            assertEquals(0, sample.queuedTasks)
            assertEquals(2, sample.workerLimit)
            assertEquals(32, sample.queueCapacity)
            service.beginShutdown()
            assertTrue(assertIs<WebSchedulerSnapshot.Available>(service.schedulerSnapshot()).stopping)
            assertFalse(Files.exists(absent))
        }
        WebJobService(JobStore(absent), JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor, Executor { error("Unexpected task") }).use { service ->
            service.initializeExistingStorage()
            assertIs<WebSchedulerSnapshot.Unavailable>(service.schedulerSnapshot())
            assertFalse(Files.exists(absent))
        }
    }

    @Test fun `retained report bytes deny upload before reading body and leave status readable`() = withStore { store, root ->
        val job = store.createFromUpload("quota.elf", elfFixture())
        val reports = Files.createDirectories(root.resolve(job.id).resolve("reports"))
        val retained = Files.createFile(reports.resolve("large-report"))
        java.nio.channels.FileChannel.open(retained, java.nio.file.StandardOpenOption.WRITE).use {
            it.position(WebUploadStorage.RESERVATION_BYTES)
            it.write(java.nio.ByteBuffer.wrap(byteArrayOf(0)))
        }
        WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor,
            maximumRetainedStorageBytes = WebUploadStorage.RESERVATION_BYTES).use { service ->
            service.initializeExistingStorage()
            val unread = object : java.io.InputStream() {
                override fun read(): Int = error("Quota refusal must precede request consumption")
            }
            assertEquals("UPLOAD_STORAGE", assertFailsWith<WebJobServiceException> {
                service.uploadMultipart(unread, "multipart/form-data; boundary=test")
            }.code)
            assertEquals(job.id, service.get(job.id).id)
            assertEquals(listOf(job.id), service.list().map { it.id })
            assertTrue(Files.exists(retained))
        }
    }

    @Test
    fun `startup reconciles orphan staging under ownership and releases lease when cleanup refuses storage`() = withStore { store, root ->
        val orphan = Files.createDirectory(root.resolve(".upload-stream-v1-123"), java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
            java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        Files.writeString(orphan.resolve("input.elf"), "incomplete")
        WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor).use { service ->
            service.initializeExistingStorage()
            assertFalse(Files.exists(orphan))
            assertTrue(service.list().isEmpty())
            // Reads do not repeat maintenance after startup.
            Files.createDirectory(orphan, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
            Files.writeString(orphan.resolve("unexpected.txt"), "preserve")
            assertTrue(service.list().isEmpty())
            assertTrue(Files.exists(orphan))
        }
        WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor).use { service ->
            val failure = assertFailsWith<decompengine.jobs.WorkflowStoreException> { service.initializeExistingStorage() }
            assertEquals("UPLOAD_STAGING_RECOVERY_REQUIRED", failure.code)
        }
        assertEquals("preserve", Files.readString(orphan.resolve("unexpected.txt")))
        decompengine.jobs.WorkflowAttemptStore.open(root).use { /* failed startup did not retain ownership */ }
    }

    @Test
    fun `upload and reads stay inert and explicit adapters share the same stored job`() = withStore { store, _ ->
        val operations = mutableListOf<String>()
        WebJobService(store, JobAnalyzer { job, _ -> operations += "explore:${job.id}" },
            JobReconstructor { job, _ -> operations += "reconstruct:${job.id}" }, Executor(Runnable::run)).use { service ->
            val job = service.upload("fixture.elf", elfFixture())
            assertEquals(job, service.get(job.id))
            assertEquals(listOf(job), service.list())
            assertTrue(operations.isEmpty())
            assertIs<WebWorkflowAdmission.Started>(service.start(job.id, WebWorkflow.EXPLORE))
            assertEquals("complete", store.get(job.id).status)
            assertIs<WebWorkflowAdmission.Started>(service.start(job.id, WebWorkflow.RECONSTRUCT))
            assertEquals(listOf("explore:${job.id}", "reconstruct:${job.id}"), operations)
        }
    }

    @Test
    fun `concurrent starts admit exactly one workflow for a job`() = withStore { store, _ ->
        val tasks = ConcurrentLinkedQueue<Runnable>()
        val executions = AtomicInteger()
        WebJobService(store, JobAnalyzer { _, _ -> executions.incrementAndGet() }, inertReconstructor,
            Executor { tasks.add(it) }).use { service ->
            val job = service.upload("concurrent.elf", elfFixture())
            val callers = Executors.newFixedThreadPool(8)
            try {
                val start = CountDownLatch(1)
                val results = (1..8).map {
                    callers.submit<WebWorkflowAdmission> {
                        check(start.await(5, TimeUnit.SECONDS))
                        service.start(job.id, WebWorkflow.EXPLORE)
                    }
                }
                start.countDown()
                val admissions = results.map { it.get(5, TimeUnit.SECONDS) }
                assertEquals(1, admissions.count { it is WebWorkflowAdmission.Started })
                assertEquals(7, admissions.count { it == WebWorkflowAdmission.AlreadyRunning })
                assertEquals(1, tasks.size)
                tasks.remove().run()
                assertEquals(1, executions.get())
                assertEquals("complete", service.get(job.id).status)
            } finally {
                callers.shutdownNow()
            }
        }
    }

    @Test
    fun `worker rejection releases admission and supports a deliberate later retry`() = withStore { store, _ ->
        val submissions = AtomicInteger()
        val executions = AtomicInteger()
        val executor = Executor { task ->
            if (submissions.getAndIncrement() == 0) throw RejectedExecutionException("private detail")
            task.run()
        }
        WebJobService(store, JobAnalyzer { _, _ -> executions.incrementAndGet() }, inertReconstructor, executor).use { service ->
            val job = service.upload("capacity.elf", elfFixture())
            assertEquals(WebWorkflowAdmission.Unavailable, service.start(job.id, WebWorkflow.EXPLORE))
            assertEquals("failed", service.get(job.id).status)
            assertEquals(0, executions.get())
            assertIs<WebWorkflowAdmission.Started>(service.start(job.id, WebWorkflow.EXPLORE))
            assertEquals(1, executions.get())
        }
    }

    @Test
    fun `unexpected submission failure preserves its cause and releases a retryable job`() = withStore { store, _ ->
        val submissions = AtomicInteger()
        val executor = Executor { task ->
            if (submissions.getAndIncrement() == 0) throw AssertionError("submission fixture")
            task.run()
        }
        WebJobService(store, JobAnalyzer { _, _ -> }, inertReconstructor, executor).use { service ->
            val job = service.upload("submission.elf", elfFixture())
            val failure = assertFailsWith<AssertionError> { service.start(job.id, WebWorkflow.EXPLORE) }
            assertEquals("submission fixture", failure.message)
            assertEquals("failed", service.get(job.id).status)
            assertIs<WebWorkflowAdmission.Started>(service.start(job.id, WebWorkflow.EXPLORE))
            assertEquals("complete", service.get(job.id).status)
        }
    }

    @Test
    fun `owned workers and waiting workflows are independently bounded`() = withStore { store, _ ->
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val executed = AtomicInteger()
        WebJobService(store, JobAnalyzer { _, _ ->
            entered.countDown()
            check(release.await(5, TimeUnit.SECONDS))
            executed.incrementAndGet()
        }, inertReconstructor, workers = 1, queueCapacity = 1).use { service ->
            val jobs = (1..3).map { service.upload("bounded-$it.elf", elfFixture()) }
            try {
                assertIs<WebWorkflowAdmission.Started>(service.start(jobs[0].id, WebWorkflow.EXPLORE))
                assertTrue(entered.await(5, TimeUnit.SECONDS))
                assertIs<WebWorkflowAdmission.Started>(service.start(jobs[1].id, WebWorkflow.EXPLORE))
                assertEquals(WebWorkflowAdmission.Unavailable, service.start(jobs[2].id, WebWorkflow.EXPLORE))
                assertEquals("queued", service.get(jobs[1].id).status)
                val sample = assertIs<WebSchedulerSnapshot.Available>(service.schedulerSnapshot())
                assertEquals(1, sample.activeWorkers)
                assertEquals(1, sample.workerLimit)
                assertEquals(1, sample.queuedTasks)
                assertEquals(1, sample.queueCapacity)
                assertFalse(sample.stopping)
                release.countDown()
                await { jobs.take(2).all { service.get(it.id).status == "complete" } }
                assertEquals(2, executed.get())
            } finally {
                release.countDown()
            }
        }
    }

    @Test
    fun `close revokes borrowed pending tasks and late delivery is inert`() = withStore { store, root ->
        val tasks = mutableListOf<Runnable>()
        var executions = 0
        val service = WebJobService(store, JobAnalyzer { _, _ -> executions++ }, inertReconstructor, Executor(tasks::add))
        val job = service.upload("pending.elf", elfFixture())
        assertIs<WebWorkflowAdmission.Started>(service.start(job.id, WebWorkflow.EXPLORE))
        service.close()
        val metadata = root.resolve(job.id).resolve("job.json")
        val before = Files.readString(metadata)
        assertEquals("failed", store.get(job.id).status)
        tasks.single().run()
        assertEquals(before, Files.readString(metadata))
        assertEquals(0, executions)
        assertEquals(WebWorkflowAdmission.Unavailable, service.start(job.id, WebWorkflow.EXPLORE))
    }

    @Test
    fun `failed initial state transition cannot strand active job ownership`() = withStore { store, root ->
        val tasks = mutableListOf<Runnable>()
        WebJobService(store, JobAnalyzer { _, _ -> }, inertReconstructor, Executor(tasks::add)).use { service ->
            val job = service.upload("damaged.elf", elfFixture())
            service.start(job.id, WebWorkflow.EXPLORE)
            val metadata = root.resolve(job.id).resolve("job.json")
            val before = Files.readString(metadata)
            Files.writeString(metadata, "{")
            assertFailsWith<Exception> { tasks.removeAt(0).run() }
            Files.writeString(metadata, before)
            assertIs<WebWorkflowAdmission.Started>(service.start(job.id, WebWorkflow.EXPLORE))
            tasks.removeAt(0).run()
            assertEquals("complete", service.get(job.id).status)
        }
    }

    @Test
    fun `shutdown continues revoking tasks after one damaged record`() = withStore { store, root ->
        val tasks = mutableListOf<Runnable>()
        var executions = 0
        val service = WebJobService(store, JobAnalyzer { _, _ -> executions++ }, inertReconstructor, Executor(tasks::add))
        val jobs = (1..2).map { service.upload("pending-$it.elf", elfFixture()) }
        jobs.forEach { service.start(it.id, WebWorkflow.EXPLORE) }
        Files.writeString(root.resolve(jobs[0].id).resolve("job.json"), "{")
        assertFailsWith<Exception> { service.close() }
        assertEquals("failed", store.get(jobs[1].id).status)
        tasks.forEach(Runnable::run)
        assertEquals(0, executions)
    }

    @Test
    fun `workflow failure stores a safe diagnostic without raw exception content`() = withStore { store, root ->
        WebJobService(store, JobAnalyzer { _, _ -> error("/private/operator SECRET_FIXTURE") }, inertReconstructor,
            Executor(Runnable::run)).use { service ->
            val job = service.upload("failed.elf", elfFixture())
            service.start(job.id, WebWorkflow.EXPLORE)
            assertEquals("failed", service.get(job.id).status)
            val persisted = Files.readString(root.resolve(job.id).resolve("job.json"))
            assertFalse(persisted.contains("SECRET_FIXTURE"))
            assertFalse(persisted.contains("/private/operator"))
        }
    }

    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (!condition() && System.nanoTime() < deadline) Thread.sleep(10)
        assertTrue(condition(), "Workflow did not reach its expected state within five seconds")
    }

    private fun withStore(block: (JobStore, Path) -> Unit) {
        val root = createTempDirectory("web-job-service-")
        try {
            block(JobStore(root), root)
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private val inertReconstructor = JobReconstructor { _, _ -> }
}
