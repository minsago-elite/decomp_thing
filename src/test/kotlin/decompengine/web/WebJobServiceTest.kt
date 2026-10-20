package decompengine.web

import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import org.junit.jupiter.api.extension.ExtendWith
import decompengine.jobs.JobStore
import decompengine.jobs.AtomicUploadPublisher
import decompengine.jobs.JobStoreDirectories
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowStoreException
import decompengine.jobs.forceJobStoreDirectory
import decompengine.jobs.prepareJobStoreDirectories
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
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

@ExtendWith(RecoveryMatrixEvidence::class)
class WebJobServiceTest {
    @Test fun `startup hook precedes construction and normal shutdown reaches the published owner`() {
        val events = mutableListOf<String>()
        val owner = Any()
        lateinit var shutdown: () -> Unit
        lateinit var cancelled: () -> Boolean
        val returned = startWebServerLifecycle(registerShutdown = { action ->
            events += "register"
            shutdown = action
            val remove: () -> Unit = { events += "remove" }
            remove
        }, create = { cancellation ->
            events += "construct"
            cancelled = cancellation
            assertFalse(cancellation())
            owner
        }, start = { events += "start" }, stop = { events += "stop" })
        kotlin.test.assertSame(owner, returned)
        assertEquals(listOf("register", "construct", "start"), events)
        shutdown()
        assertTrue(cancelled())
        assertEquals(listOf("register", "construct", "start", "stop"), events)
    }

    @Test fun `shutdown during construction prevents start and cleans only a late published owner`() {
        for (failConstruction in listOf(false, true)) {
            lateinit var shutdown: () -> Unit
            var constructions = 0
            var starts = 0
            var stops = 0
            var removals = 0
            val original = IllegalStateException("authored constructor cancellation")
            val failure = assertFailsWith<IllegalStateException> {
                startWebServerLifecycle(registerShutdown = { action ->
                    shutdown = action
                    val remove: () -> Unit = { removals++ }
                    remove
                }, create = { cancellation ->
                    constructions++
                    shutdown()
                    assertTrue(cancellation())
                    if (failConstruction) throw original
                    Any()
                }, start = { starts++ }, stop = { stops++ })
            }
            if (failConstruction) kotlin.test.assertSame(original, failure)
            else assertEquals("Web server startup cancelled", failure.message)
            assertEquals(1, constructions)
            assertEquals(0, starts)
            assertEquals(if (failConstruction) 0 else 1, stops)
            assertEquals(1, removals)
        }
    }

    @Test fun `startup cleanup failures use fresh bounded wrappers without growing the original failure graph`() {
        val original = IllegalStateException("authored start failure").apply { addSuppressed(IllegalArgumentException("retained")) }
        val retained = original.suppressed
        val removal = IllegalArgumentException("authored hook cleanup failure")
        val stop = IllegalStateException("authored owner cleanup failure")
        var first: Throwable? = null
        repeat(2) {
            var starts = 0
            var stops = 0
            val failure = assertFailsWith<IllegalStateException> {
                startWebServerLifecycle(registerShutdown = {
                    val remove: () -> Unit = { throw removal }
                    remove
                }, create = { Any() }, start = { starts++; throw original }, stop = { stops++; throw stop })
            }
            kotlin.test.assertSame(original, failure.cause)
            kotlin.test.assertContentEquals(arrayOf<Throwable>(removal, stop), failure.suppressed)
            kotlin.test.assertContentEquals(retained, original.suppressed)
            assertEquals(1, starts)
            assertEquals(1, stops)
            if (first != null) assertTrue(first !== failure)
            first = failure
        }
    }

    @Test fun `cancelled or refused hook registration cannot construct a startup owner`() {
        var constructions = 0
        var removals = 0
        val cancelled = assertFailsWith<IllegalStateException> {
            startWebServerLifecycle(registerShutdown = { action ->
                action()
                val remove: () -> Unit = { removals++ }
                remove
            }, create = { constructions++; Any() }, start = { error("cancelled startup must not run") },
                stop = { error("no owner exists to stop") })
        }
        assertEquals("Web server startup cancelled", cancelled.message)
        assertEquals(0, constructions)
        assertEquals(1, removals)
        val original = IllegalStateException("authored registration refusal")
        val refused = assertFailsWith<IllegalStateException> {
            startWebServerLifecycle(registerShutdown = { throw original }, create = { constructions++; Any() },
                start = { error("unregistered startup must not run") }, stop = { error("no owner exists to stop") })
        }
        kotlin.test.assertSame(original, refused)
        assertEquals(0, constructions)
    }

    @Test
    fun `recovery inspection excludes a live multipart stage and resumes after publication`() = withStore { store, root ->
        val boundary = "recovery-overlap"
        val body = "--$boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"active.elf\"\r\n\r\n".toByteArray() +
            elfFixture() + "\r\n--$boundary--\r\n".toByteArray()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val callers = Executors.newSingleThreadExecutor()
        WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor).use { service ->
            service.initializeExistingStorage()
            val input = object : java.io.FilterInputStream(body.inputStream()) {
                private fun waitForRelease() {
                    entered.countDown()
                    check(release.await(10, TimeUnit.SECONDS))
                }
                override fun read(): Int { waitForRelease(); return super.read() }
                override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                    waitForRelease()
                    return super.read(bytes, offset, length)
                }
            }
            try {
                val uploaded = callers.submit<decompengine.jobs.Job> {
                    input.use { service.uploadMultipart(it, "multipart/form-data; boundary=$boundary") }
                }
                assertTrue(entered.await(10, TimeUnit.SECONDS))
                val stage = Files.newDirectoryStream(root, ".upload-stream-v1-*").use { it.toList().single() }
                val before = Files.readAllBytes(stage.resolve("input.elf"))
                assertEquals(1, store.recoveryInventory().retainedUploadStages)
                val failure = assertFailsWith<WebJobServiceException> { service.recoveryInventory() }
                assertEquals("RECOVERY_INSPECTION_BUSY", failure.code)
                assertEquals(failure.code, publicWebDiagnosticCode(failure.code))
                assertEquals("Recovery inspection is paused while uploads are in progress. Refresh after uploads finish.",
                    publicWebDiagnosticMessage(failure.code))
                kotlin.test.assertContentEquals(before, Files.readAllBytes(stage.resolve("input.elf")))
                assertTrue(Files.isDirectory(stage))
                release.countDown()
                val job = uploaded.get(10, TimeUnit.SECONDS)
                assertEquals(job.id, service.get(job.id).id)
                assertFalse(Files.exists(stage))
                val settled = service.recoveryInventory()
                assertTrue(settled.inventoryComplete)
                assertEquals(0, settled.retainedUploadStages)
                assertEquals(0, settled.retainedMetadataFiles)
                assertEquals(0L, settled.observedBytes)
            } finally {
                release.countDown()
                callers.shutdownNow()
                assertTrue(callers.awaitTermination(10, TimeUnit.SECONDS))
            }
        }
    }

    @Test fun `scheduler reads preserve absent storage and distinguish shutdown and unknown executor metrics`() = withStore { _, root ->
        val absent = root.resolve("absent")
        lateinit var ownedService: WebJobService
        WebJobService(JobStore(absent), JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor).use { service ->
            ownedService = service
            assertPassiveStatusReadsWithoutServiceMonitor(service)
            assertFailsWith<WebJobServiceException> { service.schedulerSnapshot() }
            service.initializeExistingStorage()
            assertPassiveStatusReadsWithoutServiceMonitor(service)
            val sample = assertIs<WebSchedulerSnapshot.Available>(service.schedulerSnapshot())
            assertEquals(0, sample.activeWorkers)
            assertEquals(0, sample.queuedTasks)
            assertEquals(2, sample.workerLimit)
            assertEquals(32, sample.queueCapacity)
            service.beginShutdown()
            assertPassiveStatusReadsWithoutServiceMonitor(service)
            assertTrue(assertIs<WebSchedulerSnapshot.Available>(service.schedulerSnapshot()).stopping)
            assertFalse(Files.exists(absent))
        }
        assertPassiveStatusReadsWithoutServiceMonitor(ownedService)
        WebJobService(JobStore(absent), JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor, Executor { error("Unexpected task") }).use { service ->
            service.initializeExistingStorage()
            assertPassiveStatusReadsWithoutServiceMonitor(service)
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

    @Test
    fun `streamed upload confirms new store ancestors under ownership before publication`() = withStore { _, root ->
        val storage = root.resolve("new-store/nested/jobs")
        val confirmed = mutableListOf<Path>()
        val store = JobStore(storage, AtomicUploadPublisher, storeDirectories = JobStoreDirectories { selected ->
            decompengine.jobs.prepareJobStoreDirectories(selected) { directory ->
                if (confirmed.isEmpty()) {
                    assertEquals("OWNERSHIP_CONFLICT", assertFailsWith<WorkflowStoreException> {
                        WorkflowAttemptStore.open(selected)
                    }.code)
                    assertFalse(Files.newDirectoryStream(selected, ".upload-*").use { it.iterator().hasNext() })
                }
                forceJobStoreDirectory(directory)
                confirmed.add(directory)
            }
        })
        WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor).use { service ->
            service.initializeExistingStorage()
            assertFalse(Files.exists(storage))
            val boundary = "directory-confirmation"
            val binary = elfFixture()
            val body = "--$boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"confirmed.elf\"\r\n\r\n".toByteArray() +
                binary + "\r\n--$boundary--\r\n".toByteArray()
            val job = body.inputStream().use { service.uploadMultipart(it, "multipart/form-data; boundary=$boundary") }
            val chain = generateSequence(storage.toRealPath()) { it.parent }.toList()
            assertEquals(chain, confirmed)
            kotlin.test.assertContentEquals(binary, Files.readAllBytes(job.binaryPath))
            assertEquals(listOf(job.id), service.list().map { it.id })
            assertEquals(chain, confirmed, "reads must not repeat initialization maintenance")
            println("job-store-directory-confirmation " + kotlinx.serialization.json.buildJsonObject {
                put("schemaVersion", kotlinx.serialization.json.JsonPrimitive(1))
                put("fixtureOnly", kotlinx.serialization.json.JsonPrimitive(true))
                put("ancestorCount", kotlinx.serialization.json.JsonPrimitive(chain.size))
                put("provider", kotlinx.serialization.json.JsonPrimitive(storage.fileSystem.provider().javaClass.name))
                put("filesystemTypes", kotlinx.serialization.json.JsonArray(chain.map { Files.getFileStore(it).type() }
                    .distinct().sorted().map { kotlinx.serialization.json.JsonPrimitive(it) }))
                for (name in listOf("java.runtime.version", "os.name", "os.arch")) {
                    put(name, kotlinx.serialization.json.JsonPrimitive(System.getProperty(name, "unavailable").take(128)))
                }
                put("underOwnership", kotlinx.serialization.json.JsonPrimitive(true))
                put("inputBytesPreserved", kotlinx.serialization.json.JsonPrimitive(true))
            })
        }
    }

    @Test
    fun `directory confirmation refusal preserves jobs releases ownership and retries before upload bytes`() = withStore { ordinary, root ->
        val prior = ordinary.createFromUpload("prior.elf", elfFixture())
        val metadata = root.resolve(prior.id).resolve("job.json")
        val before = Files.readAllBytes(metadata)
        val input = Files.readAllBytes(prior.binaryPath)
        val confirmed = mutableListOf<Path>()
        var refuse = true
        val store = JobStore(root, AtomicUploadPublisher, storeDirectories = JobStoreDirectories { selected ->
            prepareJobStoreDirectories(selected) { directory ->
                if (refuse && directory == root.toRealPath().parent) {
                    throw UnsupportedOperationException("PRIVATE-directory-provider-canary")
                }
                forceJobStoreDirectory(directory)
                confirmed.add(directory)
            }
        })
        WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor).use { service ->
            val unread = object : java.io.InputStream() {
                override fun read(): Int = error("Directory refusal must precede request consumption")
            }
            val failure = assertFailsWith<WebJobServiceException> {
                service.uploadMultipart(unread, "multipart/form-data; boundary=unread")
            }
            assertEquals("STORE_DURABILITY_UNAVAILABLE", failure.code)
            assertEquals(failure.code, publicWebDiagnosticCode(failure.code))
            assertEquals(failure.message, publicWebDiagnosticMessage(failure.code))
            assertFalse(publicWebDiagnosticMessage(failure.code).contains("PRIVATE"))
            assertEquals(listOf(root.toRealPath()), confirmed)
            kotlin.test.assertContentEquals(before, Files.readAllBytes(metadata))
            kotlin.test.assertContentEquals(input, Files.readAllBytes(prior.binaryPath))
            assertFalse(Files.newDirectoryStream(root, ".upload-*").use { it.iterator().hasNext() })
            WorkflowAttemptStore.open(root).use { /* failed admission did not retain the root lease */ }
            refuse = false
            val boundary = "directory-retry"
            val body = "--$boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"retry.elf\"\r\n\r\n".toByteArray() +
                elfFixture() + "\r\n--$boundary--\r\n".toByteArray()
            val uploaded = body.inputStream().use { service.uploadMultipart(it, "multipart/form-data; boundary=$boundary") }
            assertEquals(listOf(root.toRealPath()) + generateSequence(root.toRealPath()) { it.parent }.toList(), confirmed)
            assertEquals(setOf(prior.id, uploaded.id), service.list().map { it.id }.toSet())
            kotlin.test.assertContentEquals(before, Files.readAllBytes(metadata))
            kotlin.test.assertContentEquals(input, Files.readAllBytes(prior.binaryPath))
        }
    }

    /** Latches exercise only metadata reads on the existing fixture's service instance. */
    private fun assertPassiveStatusReadsWithoutServiceMonitor(service: WebJobService) {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val expected = java.util.concurrent.atomic.AtomicReference<Pair<Result<WebSchedulerSnapshot>, WebProgressRetentionStatus>>()
        val callers = java.util.concurrent.Executors.newFixedThreadPool(2)
        val holder = callers.submit {
            synchronized(service) {
                expected.set(runCatching { service.schedulerSnapshot() } to service.progressRetentionStatus())
                entered.countDown()
                check(release.await(20, TimeUnit.SECONDS))
            }
        }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            val actual = callers.submit<Pair<Result<WebSchedulerSnapshot>, WebProgressRetentionStatus>> {
                runCatching { service.schedulerSnapshot() } to service.progressRetentionStatus()
            }.get(5, TimeUnit.SECONDS)
            val captured = expected.get()
            assertEquals(captured.second, actual.second)
            if (captured.first.isFailure) {
                assertEquals(assertIs<WebJobServiceException>(captured.first.exceptionOrNull()).code,
                    assertIs<WebJobServiceException>(actual.first.exceptionOrNull()).code)
            } else {
                val sample = actual.first.getOrThrow()
                when (val previous = captured.first.getOrThrow()) {
                    is WebSchedulerSnapshot.Available -> assertEquals(previous.copy(sampledAt = sample.sampledAt), sample)
                    is WebSchedulerSnapshot.Unavailable -> assertEquals(previous.copy(sampledAt = sample.sampledAt), sample)
                }
            }
        } finally {
            release.countDown()
            try { holder.get(5, TimeUnit.SECONDS) }
            finally {
                callers.shutdownNow()
                assertTrue(callers.awaitTermination(10, TimeUnit.SECONDS))
            }
        }
    }

    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (!condition() && System.nanoTime() < deadline) Thread.sleep(10)
        assertTrue(condition(), "Workflow did not reach its expected state within five seconds")
    }

    private fun withStore(block: (JobStore, Path) -> Unit) {
        val temporaryRoot = Files.createDirectories(Path.of("build/test-tmp/web-job-service").toAbsolutePath())
        val root = createTempDirectory(temporaryRoot, "web-job-service-")
        try {
            block(JobStore(root), root)
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private val inertReconstructor = JobReconstructor { _, _ -> }
}
