package decompengine.web

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.project.ModulePlan
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.StableRegularFile
import java.util.concurrent.CancellationException
import java.util.concurrent.CountDownLatch
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
