package decompengine.web

import decompengine.jobs.*
import java.io.IOException
import java.nio.file.Path
import java.time.Clock
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readBytes
import kotlin.test.*

class WebAttemptCancellationTest {
    @Test fun `queued cancellation prevents execution even when an external executor later dispatches it`() = fixture { root ->
        val pending = mutableListOf<Runnable>()
        var executions = 0
        val store = JobStore(root)
        val job = store.createFromUpload("inert.elf", elfFixture())
        service(store, Executor { pending += it }) { executions++; DurableWebWorkflowOutcome.Completed() }.use { service ->
            service.initializeExistingStorage()
            val run = start(service, job.id)
            val cancelled = service.cancelDurable(job.id, run.runId, run.version)
            assertEquals(WorkflowRunState.CANCELLED, cancelled.state)
            assertEquals(WorkflowTerminalReason.CANCELLED, cancelled.terminalReason)
            assertNull(cancelled.startedAt)
            pending.single().run()
            assertEquals(0, executions)
            assertEquals(cancelled, service.cancelDurable(job.id, run.runId, cancelled.version))
            assertEquals("VERSION_CONFLICT", assertFailsWith<WebJobServiceException> {
                service.cancelDurable(job.id, run.runId, run.version)
            }.code)
            val next = start(service, job.id)
            assertEquals(cancelled, service.cancelDurable(job.id, run.runId, cancelled.version))
            assertEquals(WorkflowRunState.QUEUED, service.getAttempt(job.id, next.runId).state)
            pending.last().run()
            assertEquals(1, executions)
        }
    }

    @Test fun `running cancellation is durable before signalling and remains pending until the worker exits`() = fixture { root ->
        for (completeDespiteCancel in listOf(false, true)) {
            val store = JobStore(root)
            val job = store.createFromUpload("inert.elf", elfFixture())
            val entered = CountDownLatch(1)
            val signalled = CountDownLatch(1)
            val release = CountDownLatch(1)
            val executor = Executors.newSingleThreadExecutor()
            val service = service(store, executor) {
                entered.countDown()
                try { release.await() } catch (_: InterruptedException) { signalled.countDown() }
                release.await()
                if (!completeDespiteCancel) throw InterruptedException("owned cancellation")
                DurableWebWorkflowOutcome.Completed()
            }
            try {
                service.initializeExistingStorage()
                val initial = start(service, job.id)
                assertTrue(entered.await(5, TimeUnit.SECONDS))
                val running = service.getAttempt(job.id, initial.runId)
                assertEquals("VERSION_CONFLICT", assertFailsWith<WebJobServiceException> {
                    service.cancelDurable(job.id, running.runId, "stale_version")
                }.code)
                val ack = service.cancelDurable(job.id, running.runId, running.version)
                assertEquals(WorkflowRunState.CANCELLING, ack.state)
                assertNull(ack.endedAt)
                assertTrue(signalled.await(5, TimeUnit.SECONDS))
                assertEquals(WorkflowRunState.CANCELLING, service.getAttempt(job.id, running.runId).state)
                val jobVersion = (service.inspectDurableJob(job.id) as WorkflowJobInspection.Available).snapshot.version
                assertEquals(DurableWebWorkflowAdmission.AlreadyRunning,
                    service.startDurable(job.id, jobVersion, DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT)))
                assertEquals(ack, service.cancelDurable(job.id, ack.runId, ack.version))
                release.countDown()
                executor.shutdown(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
                val terminal = service.getAttempt(job.id, running.runId)
                assertEquals(if (completeDespiteCancel) WorkflowRunState.COMPLETED else WorkflowRunState.CANCELLED, terminal.state)
                assertNull(terminal.acceptedRevision)
                service.close(); assertTrue(service.isIdle())
            } finally { release.countDown(); executor.shutdownNow(); executor.awaitTermination(5, TimeUnit.SECONDS); service.close() }
        }
    }

    @Test fun `failed cancellation publication distinguishes unchanged state from uncertain publication`() = fixture { root ->
        for (point in listOf(WorkflowStoreFaultPoint.AFTER_TEMP_FSYNC, WorkflowStoreFaultPoint.AFTER_RENAME)) {
            val store = JobStore(root)
            val job = store.createFromUpload("inert.elf", elfFixture())
            val pending = mutableListOf<Runnable>()
            val fail = AtomicBoolean(false)
            var executions = 0
            val service = WebJobService(store, JobAnalyzer { _, _ -> }, JobReconstructor { _, _ -> }, Executor { pending += it },
                durableAdapters = listOf(adapter { executions++; DurableWebWorkflowOutcome.Completed() }),
                attemptStoreFactory = { path -> WorkflowAttemptStore.open(path, Clock.systemUTC(), WorkflowStoreFaultInjector {
                    if (fail.get() && it == point) throw IOException("owned publication failure")
                }) })
            service.use {
                service.initializeExistingStorage()
                val run = start(service, job.id)
                fail.set(true)
                val uncertain = point == WorkflowStoreFaultPoint.AFTER_RENAME
                assertEquals(if (uncertain) "RECOVERY_REQUIRED" else "PERSISTENCE_FAILED", assertFailsWith<WebJobServiceException> {
                    service.cancelDurable(job.id, run.runId, run.version)
                }.code)
                if (!uncertain) {
                    assertEquals(run, service.getAttempt(job.id, run.runId))
                    fail.set(false)
                    pending.single().run()
                    assertEquals(1, executions)
                    assertEquals(WorkflowRunState.COMPLETED, service.getAttempt(job.id, run.runId).state)
                    return@use
                }
                val bytes = root.resolve("${job.id}/workflow-state.json").readBytes()
                pending.single().run()
                assertEquals(0, executions)
                assertContentEquals(bytes, root.resolve("${job.id}/workflow-state.json").readBytes())
                assertEquals("RECOVERY_REQUIRED", assertFailsWith<WebJobServiceException> {
                    service.cancelDurable(job.id, run.runId, run.version)
                }.code)
            }
        }
    }

    @Test fun `queued and running cancellation preserve prior accepted references and diagnostic bytes across reopen`() = fixture { root ->
        for (running in listOf(false, true)) {
            val store = JobStore(root)
            val job = store.createFromUpload("preserved.elf", elfFixture())
            lateinit var prior: WorkflowAttempt
            WorkflowAttemptStore.open(root).use { owner ->
                val initial = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
                val queued = owner.create(job.id, initial.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                    WorkflowExecutionLimits(60_000u, 15_000u, 1_048_576u, 16u)))
                val started = owner.transition(job.id, queued.attempt.runId, queued.attempt.version, WorkflowTransition.Start)
                val completed = owner.transition(job.id, started.attempt.runId, started.attempt.version,
                    WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED,
                        WorkflowCandidate("revision_retained", "ab".repeat(32))))
                val reference = WorkflowAcceptanceReference(job.id, completed.attempt.runId, "revision_retained",
                    "ab".repeat(32), "graph_fixture", "acceptance_fixture", "cd".repeat(32))
                prior = owner.recordAcceptedRevision(job.id, completed.attempt.runId, completed.snapshot.version,
                    completed.attempt.version, reference).attempt
            }
            val diagnostic = store.runReportsDirectory(job.id, prior.runId, create = true).resolve("diagnostic.txt")
            java.nio.file.Files.writeString(diagnostic, "Retained inert diagnostic")
            val bytes = diagnostic.readBytes()
            val pending = mutableListOf<Runnable>()
            val entered = CountDownLatch(1)
            val executor = Executors.newSingleThreadExecutor()
            val service = service(store, Executor { pending += it }) {
                entered.countDown()
                CountDownLatch(1).await()
                error("Interrupted fixture must not return normally")
            }
            lateinit var runId: String
            try {
                service.initializeExistingStorage()
                val queued = start(service, job.id); runId = queued.runId
                if (running) { executor.execute(pending.single()); assertTrue(entered.await(5, TimeUnit.SECONDS)) }
                val current = service.getAttempt(job.id, runId)
                val ack = service.cancelDurable(job.id, runId, current.version)
                assertEquals(if (running) WorkflowRunState.CANCELLING else WorkflowRunState.CANCELLED, ack.state)
                executor.shutdown(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
                val snapshot = (service.inspectDurableJob(job.id) as WorkflowJobInspection.Available).snapshot
                assertEquals(prior.acceptedRevision, snapshot.acceptedRevision)
                assertEquals(prior, snapshot.attempts.single { it.runId == prior.runId })
                assertEquals(WorkflowRunState.CANCELLED, snapshot.attempts.single { it.runId == runId }.state)
                assertNull(snapshot.attempts.single { it.runId == runId }.acceptedRevision)
                assertContentEquals(bytes, diagnostic.readBytes())
            } finally { executor.shutdownNow(); executor.awaitTermination(5, TimeUnit.SECONDS); service.close() }
            WorkflowAttemptStore.open(root).use { owner ->
                val snapshot = (owner.recoverAfterRestart(job.id) as WorkflowJobInspection.Available).snapshot
                assertEquals(prior.acceptedRevision, snapshot.acceptedRevision)
                assertEquals(prior, snapshot.attempts.single { it.runId == prior.runId })
                assertEquals(WorkflowRunState.CANCELLED, snapshot.attempts.single { it.runId == runId }.state)
                assertContentEquals(bytes, diagnostic.readBytes())
            }
        }
    }

    @Test fun `uncertain running cancellation retains ownership and never publishes a later completion`() = fixture { root ->
        val store = JobStore(root)
        val job = store.createFromUpload("uncertain.elf", elfFixture())
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val fail = AtomicBoolean(false)
        val interruptions = java.util.concurrent.atomic.AtomicInteger()
        val observed = java.util.concurrent.atomic.AtomicReference<Throwable>()
        val executor = Executors.newSingleThreadExecutor()
        val service = WebJobService(store, JobAnalyzer { _, _ -> }, JobReconstructor { _, _ -> },
            Executor { task -> executor.execute { try { task.run() } catch (failure: Throwable) { observed.set(failure) } } },
            shutdownTimeoutMs = 20,
            durableAdapters = listOf(adapter {
                entered.countDown()
                while (release.count != 0L) try { release.await() } catch (_: InterruptedException) { interruptions.incrementAndGet() }
                DurableWebWorkflowOutcome.Completed()
            }), attemptStoreFactory = { path -> WorkflowAttemptStore.open(path, Clock.systemUTC(), WorkflowStoreFaultInjector {
                if (fail.get() && it == WorkflowStoreFaultPoint.AFTER_RENAME) throw IOException("owned uncertain cancellation")
            }) })
        try {
            service.initializeExistingStorage()
            val queued = start(service, job.id)
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            val running = service.getAttempt(job.id, queued.runId)
            fail.set(true)
            assertEquals("RECOVERY_REQUIRED", assertFailsWith<WebJobServiceException> {
                service.cancelDurable(job.id, running.runId, running.version)
            }.code)
            assertEquals(0, interruptions.get(), "Uncertain publication must not signal cancellation")
            val bytes = root.resolve("${job.id}/workflow-state.json").readBytes()
            assertEquals("SHUTDOWN_INCOMPLETE", assertFailsWith<WebJobServiceException> { service.close() }.code)
            assertEquals("OWNERSHIP_CONFLICT", assertFailsWith<WorkflowStoreException> { WorkflowAttemptStore.open(root) }.code)
            release.countDown(); executor.shutdown(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
            assertEquals("RECOVERY_REQUIRED", assertIs<WebJobServiceException>(observed.get()).code)
            assertContentEquals(bytes, root.resolve("${job.id}/workflow-state.json").readBytes())
            assertTrue(service.isIdle())
        } finally { release.countDown(); executor.shutdownNow(); executor.awaitTermination(5, TimeUnit.SECONDS); service.close() }
        WorkflowAttemptStore.open(root).use { owner ->
            val snapshot = (owner.recoverAfterRestart(job.id) as WorkflowJobInspection.Available).snapshot
            assertEquals(WorkflowRunState.INTERRUPTED, snapshot.latestRun!!.state)
            assertNull(snapshot.acceptedRevision)
        }
    }

    @Test fun `service replay returns the recorded acknowledgement without touching a newer queued attempt`() = fixture { root ->
        val store = JobStore(root)
        val job = store.createFromUpload("replay.elf", elfFixture())
        val actor = WorkflowCancellationActor.browserSession("a".repeat(64))
        val key = "inert_service_cancel_key"
        lateinit var original: WorkflowAttempt
        lateinit var receipt: WorkflowCancellationReceipt
        val pending = mutableListOf<Runnable>()
        service(store, Executor { pending += it }) { error("No fixture should execute") }.use { service ->
            service.initializeExistingStorage()
            original = start(service, job.id)
            val first = service.requestDurableCancellation(job.id, original.runId, original.version, actor, key)
            receipt = first.receipt
            assertFalse(first.replayed)
            assertEquals(WorkflowRunState.CANCELLING, receipt.acknowledgedState)
            assertEquals(WorkflowRunState.CANCELLED, first.attempt.state)
            val next = start(service, job.id)
            val bytes = root.resolve("${job.id}/workflow-state.json").readBytes()
            val replay = service.requestDurableCancellation(job.id, original.runId, original.version, actor, key)
            assertTrue(replay.replayed); assertEquals(receipt, replay.receipt)
            assertEquals(WorkflowRunState.CANCELLED, replay.attempt.state)
            assertEquals(next, service.getAttempt(job.id, next.runId))
            assertContentEquals(bytes, root.resolve("${job.id}/workflow-state.json").readBytes())
            pending.first().run()
            assertEquals(next, service.getAttempt(job.id, next.runId))
        }
        service(store, Executor { error("Replay must not schedule work") }) { error("No fixture should execute") }.use { service ->
            service.initializeExistingStorage()
            val bytes = root.resolve("${job.id}/workflow-state.json").readBytes()
            val replay = service.requestDurableCancellation(job.id, original.runId, original.version, actor, key)
            assertTrue(replay.replayed); assertEquals(receipt, replay.receipt)
            assertEquals(WorkflowRunState.CANCELLED, replay.attempt.state)
            assertContentEquals(bytes, root.resolve("${job.id}/workflow-state.json").readBytes())
        }
    }

    @Test fun `running receipt replay never repeats interruption or rolls back a newer pin version`() = fixture { root ->
        val store = JobStore(root)
        val job = store.createFromUpload("signal.elf", elfFixture())
        val actor = WorkflowCancellationActor.browserSession("a".repeat(64))
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val signals = java.util.concurrent.atomic.AtomicInteger()
        val executor = Executors.newSingleThreadExecutor { runnable ->
            object : Thread(runnable) { override fun interrupt() { signals.incrementAndGet(); super.interrupt() } }
        }
        val service = service(store, executor) {
            entered.countDown()
            while (release.count != 0L) try { release.await() } catch (_: InterruptedException) { }
            DurableWebWorkflowOutcome.Completed()
        }
        try {
            service.initializeExistingStorage()
            val queued = start(service, job.id)
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            val current = service.getAttempt(job.id, queued.runId)
            val beforeSignals = signals.get()
            val first = service.requestDurableCancellation(job.id, current.runId, current.version, actor, "inert_running_cancel_key")
            assertEquals(beforeSignals + 1, signals.get())
            assertEquals(WorkflowRunState.CANCELLING, first.attempt.state)
            val pinned = service.setProgressRetentionPinned(job.id, current.runId, first.attempt.version, true)
            val bytes = root.resolve("${job.id}/workflow-state.json").readBytes()
            val replay = service.requestDurableCancellation(job.id, current.runId, current.version, actor, "inert_running_cancel_key")
            assertTrue(replay.replayed); assertEquals(first.receipt, replay.receipt)
            assertEquals(pinned, replay.attempt)
            assertEquals(beforeSignals + 1, signals.get())
            assertContentEquals(bytes, root.resolve("${job.id}/workflow-state.json").readBytes())
            release.countDown(); executor.shutdown(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
            val ended = service.getAttempt(job.id, current.runId)
            assertEquals(WorkflowRunState.COMPLETED, ended.state)
            assertTrue(ended.progressRetentionPinned)
            assertNull(ended.acceptedRevision)
        } finally { release.countDown(); executor.shutdownNow(); executor.awaitTermination(5, TimeUnit.SECONDS); service.close() }
    }

    @Test fun `uncertain service receipt publication prevents dispatch and replays after reopening`() = fixture { root ->
        val store = JobStore(root)
        val job = store.createFromUpload("receipt.elf", elfFixture())
        val pending = mutableListOf<Runnable>()
        val actor = WorkflowCancellationActor.browserSession("a".repeat(64))
        val fail = AtomicBoolean(false)
        lateinit var original: WorkflowAttempt
        val service = WebJobService(store, JobAnalyzer { _, _ -> }, JobReconstructor { _, _ -> }, Executor { pending += it },
            durableAdapters = listOf(adapter { error("Uncertain cancellation must not dispatch") }),
            attemptStoreFactory = { path -> WorkflowAttemptStore.open(path, Clock.systemUTC(), WorkflowStoreFaultInjector {
                if (fail.get() && it == WorkflowStoreFaultPoint.AFTER_RENAME) throw IOException("inert uncertain receipt")
            }) })
        service.use {
            service.initializeExistingStorage()
            original = start(service, job.id)
            fail.set(true)
            assertEquals("RECOVERY_REQUIRED", assertFailsWith<WebJobServiceException> {
                service.requestDurableCancellation(job.id, original.runId, original.version, actor, "inert_uncertain_key")
            }.code)
            val bytes = root.resolve("${job.id}/workflow-state.json").readBytes()
            pending.single().run()
            assertContentEquals(bytes, root.resolve("${job.id}/workflow-state.json").readBytes())
        }
        service(store, Executor { error("Replay must not dispatch") }) { error("No fixture should execute") }.use { reopened ->
            reopened.initializeExistingStorage()
            val replay = reopened.requestDurableCancellation(job.id, original.runId, original.version, actor, "inert_uncertain_key")
            assertTrue(replay.replayed)
            assertEquals(WorkflowRunState.CANCELLING, replay.receipt.acknowledgedState)
            assertEquals(WorkflowRunState.INTERRUPTED, replay.attempt.state)
        }
    }

    private fun start(service: WebJobService, jobId: String): WorkflowAttempt {
        val version = (service.inspectDurableJob(jobId) as WorkflowJobInspection.Available).snapshot.version
        val started = assertIs<DurableWebWorkflowAdmission.Started>(service.startDurable(jobId, version, DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT)))
        return service.getAttempt(jobId, started.runId)
    }
    private fun adapter(execute: () -> DurableWebWorkflowOutcome) = object : DurableWebWorkflowAdapter {
        override val workflow = WorkflowKind.RECONSTRUCT
        override val limits = WorkflowExecutionLimits(60_000u, 15_000u, 1_048_576u, 16u)
        override fun execute(context: DurableWebWorkflowContext) = execute()
    }
    private fun service(store: JobStore, executor: Executor, execute: () -> DurableWebWorkflowOutcome) =
        WebJobService(store, JobAnalyzer { _, _ -> }, JobReconstructor { _, _ -> }, executor, durableAdapters = listOf(adapter(execute)))
    private fun fixture(action: (Path) -> Unit) {
        val root = createTempDirectory("web-cancellation-")
        try { action(root) } finally { root.toFile().deleteRecursively() }
    }
}
