package decompengine.web

import decompengine.jobs.*
import kotlinx.serialization.json.*
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.*

class WebProgressRetentionWorkerTest {
    @Test fun `stopped worker remains non-idle until its callback releases`() {
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val stopped = CountDownLatch(1)
        val worker = WebProgressRetentionWorker(1, {
            entered.countDown()
            while (release.count != 0L) {
                try { release.await() } catch (_: InterruptedException) { }
            }
        }, stopped::countDown)
        assertTrue(worker.isIdle)
        try {
            worker.start()
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            worker.stop()
            worker.awaitStopped(TimeUnit.MILLISECONDS.toNanos(20))
            assertFalse(worker.isIdle)
            assertEquals(1L, stopped.count)
            release.countDown()
            worker.awaitStopped(TimeUnit.SECONDS.toNanos(3))
            assertTrue(worker.isIdle); assertEquals(0L, stopped.count)
        } finally { release.countDown(); worker.stop(); worker.awaitStopped(TimeUnit.SECONDS.toNanos(3)) }
    }

    @Test fun `blocked owner notification does not hold the executor termination lock`() {
        val entered = CountDownLatch(1); val releaseWork = CountDownLatch(1)
        val notifying = CountDownLatch(1); val releaseNotification = CountDownLatch(1)
        val worker = WebProgressRetentionWorker(1, {
            entered.countDown()
            while (releaseWork.count != 0L) try { releaseWork.await() } catch (_: InterruptedException) { }
        }, {
            notifying.countDown()
            while (releaseNotification.count != 0L) try { releaseNotification.await() } catch (_: InterruptedException) { }
        })
        val stopper = java.util.concurrent.Executors.newSingleThreadExecutor()
        try {
            worker.start(); assertTrue(entered.await(3, TimeUnit.SECONDS))
            worker.stop(); releaseWork.countDown()
            assertTrue(notifying.await(3, TimeUnit.SECONDS))
            // Models another service close while the first notification waits for its monitor.
            // Previously stopped() held ThreadPoolExecutor.mainLock and this call deadlocked.
            stopper.submit { worker.stop() }.get(3, TimeUnit.SECONDS)
            assertTrue(worker.isIdle)
            releaseNotification.countDown()
            worker.awaitStopped(TimeUnit.SECONDS.toNanos(3))
        } finally {
            releaseWork.countDown(); releaseNotification.countDown()
            worker.stop(); worker.awaitStopped(TimeUnit.SECONDS.toNanos(3))
            stopper.shutdownNow(); assertTrue(stopper.awaitTermination(3, TimeUnit.SECONDS))
        }
    }

    @Test fun `opt-in service maintenance expires eligible runs preserves pins and isolates malformed journals`() {
        val root = Files.createTempDirectory("web-periodic-retention-")
        val store = JobStore(root)
        val clock = Clock.fixed(Instant.parse("2026-09-08T00:00:00Z"), ZoneOffset.UTC)
        data class Seed(val job: String, val run: WorkflowAttempt, val journal: Path)
        fun seed(owner: WorkflowAttemptStore, pinned: Boolean): Seed {
            val job = store.createFromUpload("fixture.elf", elfFixture()).id
            val view = owner.inspect(job) as WorkflowJobInspection.Available
            val queued = owner.create(job, view.snapshot.version, NewWorkflowAttempt(WorkflowKind.EXPLORE,
                WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
            val running = owner.transition(job, queued.runId, queued.version, WorkflowTransition.Start).attempt
            var done = owner.transition(job, queued.runId, running.version,
                WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.NO_CHANGES)).attempt
            if (pinned) done = owner.setProgressRetentionPinned(job, done.runId, done.version, true).attempt
            val reports = root.resolve("$job/reports/runs/${done.runId}")
            AgentProgressJournal(reports, "explore").use { }
            return Seed(job, done, reports.resolve(AgentProgressJournal.FILE_NAME))
        }
        // Twenty discoveries plus twenty attempts require more than one 32-unit callback.
        val seeds = WorkflowAttemptStore.open(root, clock).use { owner -> (0 until 20).map { seed(owner, it == 0) } }
        val pinnedBytes = Files.readAllBytes(seeds[0].journal)
        Files.writeString(seeds[2].journal, "{}")
        lateinit var owner: WorkflowAttemptStore
        val service = WebJobService(store, JobAnalyzer { _, _ -> error("unexpected analysis") },
            JobReconstructor { _, _ -> error("unexpected reconstruction") },
            attemptStoreFactory = { WorkflowAttemptStore.open(it, Clock.offset(clock, Duration.ofHours(24))).also { value -> owner = value } },
            progressRetentionIntervalMs = 10)
        try {
            assertEquals(0, service.progressRetentionStatus().examined)
            service.initializeExistingStorage()
            await { service.progressRetentionStatus().expired >= seeds.size - 2 && service.progressRetentionStatus().failures >= 1 }
            assertContentEquals(pinnedBytes, Files.readAllBytes(seeds[0].journal))
            assertTrue(AgentProgressJournal.read(seeds[1].journal.parent)!!.getValue("events").jsonArray.isEmpty())
            assertEquals("{}", Files.readString(seeds[2].journal))
            assertEquals("PROGRESS_RETENTION_FAILED", service.progressRetentionStatus().lastFailureCode)
            owner.setProgressRetentionPinned(seeds[0].job, seeds[0].run.runId, seeds[0].run.version, false)
            await { service.progressRetentionStatus().expired >= seeds.size - 1 }
            assertTrue(AgentProgressJournal.read(seeds[0].journal.parent)!!.getValue("events").jsonArray.isEmpty())
        } finally { service.close() }
        try {
            assertTrue(service.isIdle())
            val stoppedStatus = service.progressRetentionStatus()
            Thread.sleep(30)
            assertEquals(stoppedStatus, service.progressRetentionStatus())
            WorkflowAttemptStore.open(root, clock).use { assertTrue(it.inspect(seeds[0].job) is WorkflowJobInspection.Available) }
        } finally { root.toFile().deleteRecursively() }
    }

    @Test fun `periodic reads never create storage or acquire ownership for a missing root`() {
        val parent = Files.createTempDirectory("web-retention-absent-")
        val root = parent.resolve("absent")
        val service = WebJobService(JobStore(root), JobAnalyzer { _, _ -> error("unexpected analysis") },
            JobReconstructor { _, _ -> error("unexpected reconstruction") },
            attemptStoreFactory = { error("read-only maintenance acquired storage") }, progressRetentionIntervalMs = 1)
        try {
            service.initializeExistingStorage()
            Thread.sleep(30)
            assertFalse(Files.exists(root)); assertEquals(0, service.progressRetentionStatus().examined)
        } finally { service.close(); parent.toFile().deleteRecursively() }
        assertTrue(service.isIdle())
    }

    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (!condition() && System.nanoTime() < deadline) Thread.sleep(5)
        assertTrue(condition(), "bounded maintenance did not complete the fixture")
    }
}
