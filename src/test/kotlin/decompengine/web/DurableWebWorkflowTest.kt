package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.WorkflowAcceptanceReference
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowCandidate
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowJobInspection
import decompengine.jobs.WorkflowKind
import decompengine.jobs.WorkflowRunState
import decompengine.jobs.WorkflowStoreException
import decompengine.jobs.WorkflowTerminalReason
import decompengine.jobs.WorkflowTransition
import decompengine.jobs.WorkflowUsage
import decompengine.jobs.WorkflowStoreFaultPoint
import decompengine.jobs.WorkflowStoreFaultInjector
import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.elfFixture
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import java.nio.file.Files
import java.nio.file.Path
import java.io.IOException
import java.time.Clock
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class DurableWebWorkflowTest {
    @Test
    fun `failed final publication remains explicitly unavailable and is never retried by the worker`() {
        listOf(WorkflowStoreFaultPoint.AFTER_TEMP_FSYNC, WorkflowStoreFaultPoint.AFTER_RENAME).forEach { point -> withRoot { root ->
            val store = JobStore(root)
            val job = store.createFromUpload("publication.elf", elfFixture())
            val failFinal = AtomicBoolean()
            val finalWrites = AtomicInteger()
            lateinit var runId: String
            val service = WebJobService(store, inertAnalyzer, inertReconstructor, Executor(Runnable::run),
                durableAdapters = listOf(adapter { context ->
                    runId = context.attempt.runId
                    failFinal.set(true)
                    DurableWebWorkflowOutcome.Completed()
                }), attemptStoreFactory = { path -> WorkflowAttemptStore.open(path, Clock.systemUTC(), WorkflowStoreFaultInjector {
                    if (failFinal.get() && it == point) {
                        finalWrites.incrementAndGet()
                        throw IOException("inert final publication fixture")
                    }
                }) })
            service.use {
                service.initializeExistingStorage()
                val expected = version(service, job.id)
                val failure = assertFailsWith<WebJobServiceException> {
                    service.startDurable(job.id, expected, DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT))
                }
                assertEquals("RECOVERY_REQUIRED", failure.code)
                assertEquals("RECOVERY_REQUIRED", assertIs<WebJobInspection.Unavailable>(service.inspect(job.id)).diagnostic.code)
                assertEquals("RECOVERY_REQUIRED", assertFailsWith<WebJobServiceException> { service.getAttempt(job.id, runId) }.code)
                assertEquals(DurableWebWorkflowAdmission.Unavailable("RECOVERY_REQUIRED"),
                    service.startDurable(job.id, expected, DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT)))
                assertEquals(WebWorkflowAdmission.Unavailable, service.start(job.id, WebWorkflow.EXPLORE))
                assertEquals("RECOVERY_REQUIRED", assertFailsWith<WebJobServiceException> { service.upload("blocked.elf", elfFixture()) }.code)
                assertEquals(1, finalWrites.get())
                assertEquals("OWNERSHIP_CONFLICT", assertFailsWith<WorkflowStoreException> { WorkflowAttemptStore.open(root) }.code)
            }
            WorkflowAttemptStore.open(root).use { reopened ->
                val recovered = reopened.recoverAfterRestart(job.id) as WorkflowJobInspection.Available
                assertEquals(if (point == WorkflowStoreFaultPoint.AFTER_RENAME) WorkflowRunState.COMPLETED else WorkflowRunState.INTERRUPTED,
                    recovered.snapshot.latestRun!!.state)
                assertEquals(null, recovered.snapshot.acceptedRevision)
            }
        } }
    }

    @Test
    fun `cooperative interrupted return publishes interruption and restores the worker interrupt flag`() = withRoot { root ->
        val store = JobStore(root)
        val job = store.createFromUpload("interrupt.elf", elfFixture())
        val service = service(store, listOf(adapter {
            Thread.currentThread().interrupt()
            DurableWebWorkflowOutcome.Completed(WorkflowCandidate("unpublished_candidate", SHA))
        }))
        service.use {
            service.initializeExistingStorage()
            val started = try {
                assertIs<DurableWebWorkflowAdmission.Started>(service.startDurable(job.id, version(service, job.id), DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT)))
                    .also { assertTrue(Thread.currentThread().isInterrupted) }
            } finally { Thread.interrupted() }
            val ended = service.getAttempt(job.id, started.runId)
            assertEquals(WorkflowRunState.INTERRUPTED, ended.state)
            assertEquals(WorkflowTerminalReason.PROCESS_INTERRUPTED, ended.terminalReason)
            assertEquals(null, ended.candidate)
            assertEquals(null, ended.acceptedRevision)
            assertEquals("OWNERSHIP_CONFLICT", assertFailsWith<WorkflowStoreException> { WorkflowAttemptStore.open(root) }.code)
        }
        WorkflowAttemptStore.open(root).use { reopened ->
            assertEquals(WorkflowRunState.INTERRUPTED, (reopened.inspect(job.id) as WorkflowJobInspection.Available).snapshot.latestRun!!.state)
        }
    }

    @Test
    fun `artifact parser rejects noncanonical components before namespace dispatch`() {
        assertEquals(listOf("reports", "file.txt"), canonicalReportSegments("reports/file.txt"))
        assertEquals(listOf("reports", "runs", "run_fixture", "file.txt"), canonicalReportSegments("reports/runs/run_fixture/file.txt"))
        listOf("reports/./file.txt", "reports/../file.txt", "reports//file.txt", "reports\\file.txt",
            "/reports/file.txt", "reports/file.txt/", "reports/runs", "reports/runs/run_fixture",
            "reports/runs/./file.txt", "reports/\u0000file.txt").forEach { invalid ->
            assertFailsWith<IllegalArgumentException> { canonicalReportSegments(invalid) }
        }
    }

    @Test
    fun `empty preview initialization and unsupported durable requests perform no storage work`() = withRoot { root ->
        val absent = root.resolve("absent")
        service(JobStore(absent)).use { service ->
            service.initializeExistingStorage()
            assertTrue(service.listInspections().isEmpty())
            assertIs<DurableWebWorkflowAdmission.Unsupported>(service.startDurable("a".repeat(32), "version_unused", DurableWebWorkflowRequest(WorkflowKind.REPAIR)))
            assertIs<WebJobInspection.Unavailable>(service.inspect("a".repeat(32)))
            assertFalse(Files.exists(absent))
        }
        assertFalse(Files.exists(absent))
    }

    @Test
    fun `durable retries retain reports outcomes and exact input without accepting successful candidates`() = withRoot { root ->
        val store = JobStore(root)
        val job = store.createFromUpload("fixture.elf", elfFixture())
        val original = root.resolve(job.id).resolve("job.json").readBytes()
        val calls = AtomicInteger()
        val selected = adapter { context ->
            assertEquals(job.binaryPath, context.job.binaryPath)
            assertEquals(LIMITS, context.attempt.limits)
            assertEquals(WorkflowRunState.RUNNING, context.attempt.state)
            context.reportsDirectory.resolve("report.txt").writeText(context.attempt.runId)
            if (calls.getAndIncrement() == 0) DurableWebWorkflowOutcome.Failed(usage = WorkflowUsage(outputTokens = ULong.MAX_VALUE))
            else DurableWebWorkflowOutcome.Completed(WorkflowCandidate("revision_candidate", SHA))
        }
        lateinit var first: DurableWebWorkflowAdmission.Started
        lateinit var second: DurableWebWorkflowAdmission.Started
        service(store, listOf(selected)).use { service ->
            service.initializeExistingStorage()
            val publicVersion = webJob(service.presentation(job.id)).getValue("version").jsonPrimitive.content
            first = assertIs(service.startDurable(job.id, publicVersion, DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT)))
            second = assertIs(service.startDurable(job.id, version(service, job.id), DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT, previousRunId = first.runId)))
            assertNotEquals(first.runId, second.runId)
            assertEquals(WorkflowRunState.FAILED, service.getAttempt(job.id, first.runId).state)
            assertEquals(ULong.MAX_VALUE, service.getAttempt(job.id, first.runId).usage!!.outputTokens)
            assertEquals(first.runId, service.getAttempt(job.id, second.runId).previousRunId)
            assertTrue(service.getAttempt(job.id, second.runId).publicationPending)
            assertEquals(first.runId, service.resolveArtifact(job.id, "reports/runs/${first.runId}/report.txt").readText())
            assertEquals(second.runId, service.resolveArtifact(job.id, "reports/runs/${second.runId}/report.txt").readText())
            assertEquals(first.runId, service.readArtifact(job.id, "reports/runs/${first.runId}/report.txt", 4096).bytes.toString(Charsets.UTF_8))
            assertFailsWith<Exception> { service.readArtifact(job.id, "reports/runs/${first.runId}/report.txt", 1) }
            assertFailsWith<WebJobServiceException> { service.readArtifact(job.id, "reports/runs/run_unknown/report.txt", 4096) }

            assertEquals(WebWorkflowAdmission.Unavailable, service.start(job.id, WebWorkflow.RECONSTRUCT))
            val dto = webJob(service.presentation(job.id))
            assertEquals(second.runId, dto.getValue("latestRunId").jsonPrimitive.content)
            assertEquals("completed", dto.getValue("status").jsonPrimitive.content)
            assertEquals("null", dto.getValue("acceptedRevisionId").toString())
            assertFalse(dto.toString().contains(root.toString()))
        }
        service(store).use { reopened ->
            reopened.initializeExistingStorage()
            assertEquals(2, (reopened.inspectDurableJob(job.id) as WorkflowJobInspection.Available).snapshot.attempts.size)
            assertTrue(reopened.getAttempt(job.id, second.runId).publicationPending)
            assertEquals("null", webJob(reopened.presentation(job.id)).getValue("acceptedRevisionId").toString())
        }
        assertContentEquals(original, root.resolve(job.id).resolve("job.json").readBytes())
    }

    @Test
    fun `available dashboard jobs retain created time descending and identity tie ordering`() = withRoot { root ->
        val store = JobStore(root)
        val jobs = (1..3).map { store.createFromUpload("order-$it.elf", elfFixture()) }
        jobs.forEachIndexed { index, job ->
            val path = root.resolve(job.id).resolve("job.json")
            val json = Json.parseToJsonElement(path.readText()).jsonObject
            path.writeText(JsonObject(json + ("created_at" to JsonPrimitive(if (index == 0) "2025-01-01T00:00:00Z" else "2026-01-01T00:00:00Z"))).toString())
        }
        service(store).use { service ->
            service.initializeExistingStorage()
            assertEquals(jobs.drop(1).map { it.id }.sortedDescending() + jobs.first().id, service.list().map { it.id })
        }
    }

    @Test
    fun `deliberate legacy retry overrides historical interruption and each status changes the shared version`() = withRoot { root ->
        val store = JobStore(root)
        val job = store.createFromUpload("legacy-retry.elf", elfFixture())
        store.updateStatus(job.id, "analyzing")
        val queued = mutableListOf<Runnable>()
        lateinit var service: WebJobService
        service = WebJobService(store, JobAnalyzer { _, _ ->
            assertEquals("running", webJob(service.presentation(job.id)).getValue("status").jsonPrimitive.content)
            assertFalse(service.presentation(job.id).legacyInterrupted)
        }, inertReconstructor, Executor { queued.add(it) }, durableAdapters = listOf(adapter { DurableWebWorkflowOutcome.Completed() }))
        service.use {
            service.initializeExistingStorage()
            val before = webJob(service.presentation(job.id))
            assertEquals("interrupted", before.getValue("status").jsonPrimitive.content)
            service.start(job.id, WebWorkflow.EXPLORE)
            val waiting = webJob(service.presentation(job.id))
            assertEquals("queued", waiting.getValue("status").jsonPrimitive.content)
            assertNotEquals(before.getValue("version"), waiting.getValue("version"))
            queued.removeAt(0).run()
            val completed = webJob(service.presentation(job.id))
            assertEquals("completed", completed.getValue("status").jsonPrimitive.content)
            assertNotEquals(waiting.getValue("version"), completed.getValue("version"))
            assertIs<DurableWebWorkflowAdmission.Started>(service.startDurable(job.id,
                completed.getValue("version").jsonPrimitive.content, DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT)))
        }
    }

    @Test
    fun `concurrent durable starts compare job versions before any adapter can execute`() = withRoot { root ->
        val queued = mutableListOf<Runnable>()
        val calls = AtomicInteger()
        val store = JobStore(root)
        val job = store.createFromUpload("concurrent.elf", elfFixture())
        service(store, listOf(adapter { calls.incrementAndGet(); DurableWebWorkflowOutcome.Completed() }), Executor { queued.add(it) }).use { service ->
            service.initializeExistingStorage()
            val expected = version(service, job.id)
            val begin = CountDownLatch(1)
            val pool = Executors.newFixedThreadPool(2)
            try {
                val results = (1..2).map { pool.submit<Any> {
                    check(begin.await(5, TimeUnit.SECONDS))
                    try { service.startDurable(job.id, expected, DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT)) }
                    catch (failure: WorkflowStoreException) { failure }
                } }
                begin.countDown()
                val answers = results.map { it.get(5, TimeUnit.SECONDS) }
                assertEquals(1, answers.count { it is DurableWebWorkflowAdmission.Started })
                assertEquals("VERSION_CONFLICT", answers.filterIsInstance<WorkflowStoreException>().single().code)
                assertEquals(1, queued.size)
                assertEquals(0, calls.get())
                queued.single().run()
                assertEquals(1, calls.get())
            } finally { pool.shutdownNow() }
        }
    }

    @Test
    fun `capacity rejection retains an unstarted refused attempt and deliberate retry gets a new identity`() = withRoot { root ->
        val attempts = AtomicInteger()
        val store = JobStore(root)
        val job = store.createFromUpload("capacity.elf", elfFixture())
        service(store, listOf(adapter { DurableWebWorkflowOutcome.Completed() }), Executor {
            if (attempts.getAndIncrement() == 0) throw java.util.concurrent.RejectedExecutionException()
            it.run()
        }).use { service ->
            service.initializeExistingStorage()
            assertEquals(DurableWebWorkflowAdmission.Unavailable("CAPACITY_UNAVAILABLE"),
                service.startDurable(job.id, version(service, job.id), DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT)))
            val refused = (service.inspectDurableJob(job.id) as WorkflowJobInspection.Available).snapshot.latestRun!!
            assertEquals(WorkflowTerminalReason.REFUSED, refused.terminalReason)
            assertEquals(null, refused.startedAt)
            val next = assertIs<DurableWebWorkflowAdmission.Started>(service.startDurable(job.id, version(service, job.id), DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT)))
            assertNotEquals(refused.runId, next.runId)
        }
    }

    @Test
    fun `startup interrupts abandoned attempts preserves accepted references and reads never recover again`() = withRoot { root ->
        val store = JobStore(root)
        val job = store.createFromUpload("restart.elf", elfFixture())
        lateinit var activeId: String
        lateinit var reference: WorkflowAcceptanceReference
        WorkflowAttemptStore.open(root).use { owner ->
            val initial = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            val queued = owner.create(job.id, initial.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS))
            val started = owner.transition(job.id, queued.attempt.runId, queued.attempt.version, WorkflowTransition.Start)
            val completed = owner.transition(job.id, started.attempt.runId, started.attempt.version,
                WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED, WorkflowCandidate("revision_retained", SHA)))
            reference = WorkflowAcceptanceReference(job.id, completed.attempt.runId, "revision_retained", SHA, "graph_node", "acceptance_artifact", SHA)
            val accepted = owner.recordAcceptedRevision(job.id, completed.attempt.runId, completed.snapshot.version, completed.attempt.version, reference)
            activeId = owner.create(job.id, accepted.snapshot.version, NewWorkflowAttempt(WorkflowKind.VALIDATE, LIMITS)).attempt.runId
        }
        var executions = 0
        service(store, listOf(adapter { executions++; DurableWebWorkflowOutcome.Completed() })).use { service ->
            service.initializeExistingStorage()
            assertEquals(WorkflowRunState.INTERRUPTED, service.getAttempt(job.id, activeId).state)
            val state = root.resolve(job.id).resolve("workflow-state.json")
            val recovered = state.readBytes()
            repeat(3) { service.inspect(job.id); service.listInspections(); service.getAttempt(job.id, activeId) }
            assertContentEquals(recovered, state.readBytes())
            assertEquals(reference, (service.inspectDurableJob(job.id) as WorkflowJobInspection.Available).snapshot.acceptedRevision)
            assertEquals("revision_retained", webJob(service.presentation(job.id)).getValue("acceptedRevisionId").jsonPrimitive.content)
            assertEquals(0, executions)
        }
    }

    @Test
    fun `corrupt records remain visible as safe isolated diagnostic rows`() = withRoot { root ->
        val store = JobStore(root)
        val good = store.createFromUpload("good.elf", elfFixture())
        val bad = store.createFromUpload("bad.elf", elfFixture())
        val path = root.resolve(bad.id).resolve("job.json")
        path.writeText("PRIVATE_SECRET_SENTINEL {")
        service(store).use { service ->
            service.initializeExistingStorage()
            val inspections = service.listInspections()
            assertEquals(2, inspections.size)
            assertEquals(good.id, inspections.filterIsInstance<WebJobInspection.Available>().single().presentation.job.id)
            val diagnostic = inspections.filterIsInstance<WebJobInspection.Unavailable>().single().diagnostic
            assertEquals(bad.id, diagnostic.jobId)
            assertEquals("CORRUPT_LEGACY_JOB", diagnostic.code)
            val html = renderDashboard(listOf(service.get(good.id)), listOf(diagnostic))
            assertTrue(html.contains(bad.id) && html.contains("CORRUPT_LEGACY_JOB") && html.contains("verified backup"))
            assertFalse(html.contains("PRIVATE_SECRET_SENTINEL") || html.contains(root.toString()))
            assertFailsWith<WebJobServiceException> { service.list() }
        }
        assertEquals("PRIVATE_SECRET_SENTINEL {", path.readText())
    }

    @Test
    fun `selected report context keeps links bound to the original run across a later retry`() = withRoot { root ->
        val store = JobStore(root)
        val job = store.createFromUpload("source.elf", elfFixture())
        service(store, listOf(adapter { context ->
            val tree = context.reportsDirectory.resolve("source-tree").createDirectories()
            val relative = "src/modules/source.c"
            val file = tree.resolve(relative)
            file.parent.createDirectories()
            file.writeText("/* ${context.attempt.runId} */")
            val profile = decompengine.project.GeneratedCMakeReconstructionProfile.descriptor
            val declaration = profile.layout.declarationForPath(relative)
            fun digest(bytes: ByteArray) = java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
            val manifest = decompengine.project.SourceTreeManifest(
                profileId = profile.id, profileSha256 = profile.sha256, inputSha256 = digest(elfFixture()),
                files = listOf(decompengine.project.GeneratedFileEvidence(path = relative, sha256 = digest(file.readBytes()),
                    generator = "llm", entityIds = listOf("fn_1000"), acceptedImplementation = true,
                    roles = declaration.roles, contentKind = declaration.contentKind)), unresolvedEntityIds = emptyList(),
            )
            tree.resolve("source_tree_manifest.json").writeText(manifest.toJson())
            DurableWebWorkflowOutcome.Completed()
        })).use { service ->
            service.initializeExistingStorage()
            val first = assertIs<DurableWebWorkflowAdmission.Started>(service.startDurable(job.id, version(service, job.id), DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT)))
            val old = service.reportContext(job.id, first.runId)
            val evidence = WebSourceEvidence(store, listOf(decompengine.project.GeneratedCMakeReconstructionProfile.descriptor), service::readArtifact)
            val before = renderJob(service.get(job.id), old, sourceTree = evidence.read(job.id, old.artifactPrefix).view())
            assertTrue(before.contains("?runId=${first.runId}"))
            assertTrue(before.contains("/source/src/modules/source.c?runId=${first.runId}"))
            assertFalse(before.contains("action=\"/jobs/${job.id}/reconstruct\""))
            service.startDurable(job.id, version(service, job.id), DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT))
            val source = service.resolveArtifact(job.id, "${old.artifactPrefix}/source-tree/src/modules/source.c").readText()
            assertTrue(source.contains(first.runId))
            assertEquals(source, evidence.read(job.id, old.artifactPrefix).text("src/modules/source.c"))
            val html = renderSourceFile(service.get(job.id), "src/modules/source.c", source, old)
            assertTrue(html.contains("reports/runs/${first.runId}/source-tree/src/modules/source.c"))
            assertEquals(job.binaryPath, service.get(job.id).binaryPath)
            val other = service.upload("other.elf", elfFixture())
            assertFailsWith<WebJobServiceException> { service.resolveArtifact(other.id, "${old.artifactPrefix}/source-tree/src/modules/source.c") }
        }
    }

    @Test
    fun `shutdown revokes borrowed queued attempts and late delivery cannot write or execute`() = withRoot { root ->
        val queued = mutableListOf<Runnable>()
        val store = JobStore(root)
        val job = store.createFromUpload("pending.elf", elfFixture())
        var executions = 0
        val service = service(store, listOf(adapter { executions++; DurableWebWorkflowOutcome.Completed() }), Executor { queued.add(it) })
        service.initializeExistingStorage()
        val started = assertIs<DurableWebWorkflowAdmission.Started>(service.startDurable(job.id, version(service, job.id), DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT)))
        service.close()
        val bytes = root.resolve(job.id).resolve("workflow-state.json").readBytes()
        queued.single().run()
        assertContentEquals(bytes, root.resolve(job.id).resolve("workflow-state.json").readBytes())
        assertEquals(0, executions)
        WorkflowAttemptStore.open(root).use { owner ->
            assertEquals(WorkflowRunState.INTERRUPTED, (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot.attempts.single { it.runId == started.runId }.state)
        }
    }

    @Test
    fun `unfinished adapter retains ownership after shutdown deadline until its worker really exits`() = withRoot { root ->
        val store = JobStore(root)
        val job = store.createFromUpload("shutdown.elf", elfFixture())
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val worker = Executors.newSingleThreadExecutor()
        val service = WebJobService(store, inertAnalyzer, inertReconstructor, worker,
            durableAdapters = listOf(adapter {
                entered.countDown()
                while (release.count > 0) try { release.await() } catch (_: InterruptedException) { /* fixture deliberately delays cooperation */ }
                DurableWebWorkflowOutcome.Completed()
            }), shutdownTimeoutMs = 20)
        try {
            service.initializeExistingStorage()
            service.startDurable(job.id, version(service, job.id), DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT))
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            assertEquals("SHUTDOWN_INCOMPLETE", assertFailsWith<WebJobServiceException> { service.close() }.code)
            assertEquals("OWNERSHIP_CONFLICT", assertFailsWith<WorkflowStoreException> { WorkflowAttemptStore.open(root) }.code)
        } finally {
            release.countDown()
            worker.shutdown()
            assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS))
            service.close()
        }
        WorkflowAttemptStore.open(root).use { owner ->
            assertEquals(WorkflowRunState.INTERRUPTED, (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot.latestRun!!.state)
        }
    }

    private fun service(store: JobStore, adapters: List<DurableWebWorkflowAdapter> = emptyList(), executor: Executor = Executor(Runnable::run)) =
        WebJobService(store, inertAnalyzer, inertReconstructor, executor, durableAdapters = adapters)
    private fun adapter(action: (DurableWebWorkflowContext) -> DurableWebWorkflowOutcome) = object : DurableWebWorkflowAdapter {
        override val workflow = WorkflowKind.RECONSTRUCT
        override val limits = LIMITS
        override fun execute(context: DurableWebWorkflowContext) = action(context)
    }
    private fun version(service: WebJobService, jobId: String) = (service.inspectDurableJob(jobId) as WorkflowJobInspection.Available).snapshot.version
    private fun withRoot(action: (Path) -> Unit) {
        val root = createTempDirectory("durable-web-")
        try { action(root) } finally { root.toFile().deleteRecursively() }
    }
    private companion object {
        val LIMITS = WorkflowExecutionLimits(60_000u, 15_000u, 1_048_576u, 16u)
        val SHA = "ab".repeat(32)
        val inertAnalyzer = JobAnalyzer { _, _ -> }
        val inertReconstructor = JobReconstructor { _, _ -> }
    }
}
