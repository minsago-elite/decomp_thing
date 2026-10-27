package decompengine.web

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.project.ModulePlan
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.StableRegularFile
import java.util.concurrent.CancellationException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

/** Synthetic capture callbacks only; no server, store or external analysis is started. */
class WebStructureCaptureCancellationTest {
    @Test fun `abandoned workers retain capture admission until both bodies exit`() {
        val fixture = WebStructureFixture()
        // The manifest does not commit either speculative record, so projection need not join the workers.
        val reference = fixture.revision("run_1", "revision_1", null, null)
        val inputBytes = "input".toByteArray()
        val input = StableRegularFile(inputBytes, fixture.inputSha,
            LinuxFileIdentity(LinuxFileKey(1, 1), 0x8180, 1000, 1000, 1, 1, true, false, false))
        val entered = CountDownLatch(2)
        val interrupted = CountDownLatch(2)
        val releases = List(2) { CountDownLatch(1) }
        val exited = List(2) { CountDownLatch(1) }
        val live = AtomicInteger()
        val peak = AtomicInteger()
        val evidence = WebSourceCatalogEvidence(listOf(fixture.profile), { input }) { _, path, _ ->
            val worker = when {
                path.endsWith("/reports/program_model.json") -> 0
                path.endsWith("/reports/module_plan.json") -> 1
                else -> -1
            }
            if (worker < 0) fixture.files.getValue(path)
            else {
                val count = live.incrementAndGet()
                peak.updateAndGet { maxOf(it, count) }
                entered.countDown()
                try {
                    // Model a bounded but nonpreemptible read/library parse: cancellation is observed,
                    // but the body remains alive until explicitly released by this test.
                    while (true) {
                        try { releases[worker].await(); break }
                        catch (_: InterruptedException) { interrupted.countDown() }
                    }
                    throw RepairBudgetExceededException("No speculative record in this fixture.")
                } finally {
                    live.decrementAndGet()
                    exited[worker].countDown()
                }
            }
        }
        val cache = WebProgramStructureCache()
        fun assertBusy() {
            val failure = assertFailsWith<WebAccessDenied> {
                evidence.readStructure(reference, cache) { _, _ -> fail("Abandoned workers must retain admission.") }
            }
            assertEquals(429, failure.status)
            assertEquals("SOURCE_CATALOG_BUSY", failure.code)
            // Ordinary metadata captures share the same admission boundary.
            assertEquals("SOURCE_CATALOG_BUSY", assertFailsWith<WebAccessDenied> {
                evidence.read(reference.jobId, reference.runId)
            }.code)
        }
        try {
            assertFailsWith<IllegalArgumentException> {
                evidence.readStructure(reference, cache) { _, _ ->
                    assertTrue(entered.await(5, TimeUnit.SECONDS), "Both worker bodies must start before abandonment.")
                    throw IllegalArgumentException("Refuse projection while workers are still running.")
                }
            }
            assertTrue(interrupted.await(5, TimeUnit.SECONDS), "Cancellation must reach both workers.")
            assertEquals(2, live.get())
            repeat(10) { assertBusy() }
            releases[0].countDown()
            assertTrue(exited[0].await(5, TimeUnit.SECONDS))
            assertEquals(1, live.get())
            assertBusy()
            releases[1].countDown()
            assertTrue(exited[1].await(5, TimeUnit.SECONDS))
            // Body exit precedes the executor wrapper's final release; wait for that tiny final handoff.
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (true) {
                try { evidence.read(reference.jobId, reference.runId); break }
                catch (failure: WebAccessDenied) {
                    assertEquals("SOURCE_CATALOG_BUSY", failure.code)
                    assertTrue(System.nanoTime() < deadline, "Capture admission was not released after worker exit.")
                    Thread.sleep(5)
                }
            }
            evidence.readStructure(reference, cache) { _, _ -> Unit }
            assertEquals(0, live.get())
            assertEquals(2, peak.get())
        } finally {
            releases.forEach { it.countDown() }
            exited.forEach { it.await(5, TimeUnit.SECONDS) }
        }
    }

    @Test fun `successful projection drains unused workers before returning to sequential readers`() {
        val fixture = WebStructureFixture()
        val reference = fixture.revision("run_1", "revision_1", null, null)
        val input = StableRegularFile("input".toByteArray(), fixture.inputSha,
            LinuxFileIdentity(LinuxFileKey(1, 1), 0x8180, 1000, 1000, 1, 1, true, false, false))
        val entered = CountDownLatch(2)
        val projected = CountDownLatch(1)
        val release = CountDownLatch(1)
        val returned = CountDownLatch(1)
        val live = AtomicInteger()
        val evidence = WebSourceCatalogEvidence(listOf(fixture.profile), { input }) { _, path, _ ->
            if (!path.endsWith("/reports/program_model.json") && !path.endsWith("/reports/module_plan.json")) fixture.files.getValue(path)
            else {
                live.incrementAndGet()
                entered.countDown()
                try {
                    release.await()
                    throw RepairBudgetExceededException("Uncommitted speculative record.")
                } finally { live.decrementAndGet() }
            }
        }
        val cache = WebProgramStructureCache()
        val reader = FutureTask {
            try {
                val value = evidence.readStructure(reference, cache) { _, _ ->
                    assertTrue(entered.await(5, TimeUnit.SECONDS))
                    projected.countDown()
                    "projected"
                }
                assertEquals("projected", value)
                assertEquals(0, live.get(), "A successful capture cannot return while its unused workers are live.")
                // No retries: a sequential metadata read and a cached structure read must be admitted immediately.
                repeat(20) {
                    evidence.read(reference.jobId, reference.runId)
                    evidence.readStructure(reference, cache) { _, _ -> Unit }
                }
            } finally { returned.countDown() }
        }
        val thread = Thread.ofVirtual().start(reader)
        try {
            assertTrue(projected.await(5, TimeUnit.SECONDS))
            assertFalse(returned.await(100, TimeUnit.MILLISECONDS), "Successful projection must await worker cleanup.")
            assertEquals("SOURCE_CATALOG_BUSY", assertFailsWith<WebAccessDenied> {
                evidence.read(reference.jobId, reference.runId)
            }.code)
            release.countDown()
            reader.get(5, TimeUnit.SECONDS)
        } finally {
            release.countDown()
            thread.join(5000)
        }
    }

    @Test fun `model and plan parsers propagate cooperative cancellation instead of malformed outcomes`() {
        val fixture = WebStructureFixture()
        val model = fixture.model(emptyList()).toJson().toByteArray()
        val plan = ModulePlan(modules = emptyList(), dependencyCycles = emptyList()).toJson().toByteArray()
        for (parse in listOf<() -> Unit>(
            { WebProgramStructureBuilder.parseModel(model) },
            { WebProgramStructureBuilder.parsePlan(plan) },
        )) {
            try {
                Thread.currentThread().interrupt()
                assertFailsWith<CancellationException> { parse() }
            } finally {
                Thread.interrupted() // Never leak the test's cancellation into another test or the runner.
            }
        }
    }
}
