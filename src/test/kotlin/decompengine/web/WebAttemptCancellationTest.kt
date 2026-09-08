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
