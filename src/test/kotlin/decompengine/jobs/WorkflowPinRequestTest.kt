package decompengine.jobs

import kotlinx.serialization.json.*
import java.nio.file.Path
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import kotlin.io.path.*
import kotlin.test.*

class WorkflowPinRequestTest {
    private val at = Instant.parse("2026-09-08T00:00:00Z")
    private val clock = Clock.fixed(at, ZoneOffset.UTC)
    private val actor = WorkflowPinActor.browserSession("a".repeat(64))
    private val key = "private_request_canary_0001"
    private val request = NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))

    @Test fun `replay precedes CAS survives restart and returns original receipt with current attempt`() = fixture { root, job ->
        lateinit var original: WorkflowAttempt
        lateinit var first: WorkflowPinRequestResult
        WorkflowAttemptStore.open(root, clock).use { store ->
            original = store.create(job, store.snapshot(job).version, request).attempt
            first = store.requestProgressRetentionPinned(job, original.runId, original.version, true, actor, key)
            val unpinned = store.setProgressRetentionPinned(job, original.runId, first.attempt.version, false).attempt
            val bytes = root.resolve("$job/workflow-state.json").readBytes()
            val replay = store.requestProgressRetentionPinned(job, original.runId, original.version, true, actor, key)
            assertTrue(replay.replayed); assertEquals(first.receipt, replay.receipt)
            assertEquals(unpinned, replay.attempt); assertTrue(replay.receipt.pinned); assertFalse(replay.attempt.progressRetentionPinned)
            assertContentEquals(bytes, root.resolve("$job/workflow-state.json").readBytes())
            assertFalse(bytes.toString(Charsets.UTF_8).contains(key))
            assertEquals("IDEMPOTENCY_CONFLICT", assertFailsWith<WorkflowStoreException> {
                store.requestProgressRetentionPinned(job, original.runId, original.version, false, actor, key)
            }.code)
            assertEquals("IDEMPOTENCY_CONFLICT", assertFailsWith<WorkflowStoreException> {
                store.requestProgressRetentionPinned(job, original.runId, unpinned.version, true, actor, key)
            }.code)
            assertContentEquals(bytes, root.resolve("$job/workflow-state.json").readBytes())
        }
        WorkflowAttemptStore.open(root, clock).use { store ->
            store.recoverAfterRestart(job)
            val replay = store.requestProgressRetentionPinned(job, original.runId, original.version, true, actor, key)
            assertTrue(replay.replayed); assertEquals(first.receipt, replay.receipt)
            assertEquals(WorkflowRunState.INTERRUPTED, replay.attempt.state)
            assertEquals(2, store.snapshot(job).pinAudit.entries.size)
        }
    }

    @Test fun `successful no-op is recorded once without changing run version and keys are actor scoped`() = fixture { root, job ->
        WorkflowAttemptStore.open(root, clock).use { store ->
            val snapshot = store.create(job, store.snapshot(job).version, request)
            val run = snapshot.attempt
            val first = store.requestProgressRetentionPinned(job, run.runId, run.version, false, actor, key)
            assertFalse(first.replayed); assertEquals("unchanged", first.receipt.outcome); assertEquals(run, first.attempt)
            assertNotEquals(snapshot.snapshot.version, store.snapshot(job).version)
            val bytes = root.resolve("$job/workflow-state.json").readBytes()
            assertTrue(store.requestProgressRetentionPinned(job, run.runId, run.version, false, actor, key).replayed)
            assertContentEquals(bytes, root.resolve("$job/workflow-state.json").readBytes())
            val other = WorkflowPinActor.browserSession("b".repeat(64))
            val changed = store.requestProgressRetentionPinned(job, run.runId, run.version, true, other, key)
            assertFalse(changed.replayed); assertEquals("applied", changed.receipt.outcome)
            assertNotEquals(first.receipt.requestKeyDigest, changed.receipt.requestKeyDigest)
            assertEquals(2, store.snapshot(job).pinAudit.entries.size)
        }
    }

    @Test fun `concurrent duplicate requests publish one receipt and another job has its own key scope`() = fixture { root, job ->
        WorkflowAttemptStore.open(root, clock).use { store ->
            val run = store.create(job, store.snapshot(job).version, request).attempt
            val start = java.util.concurrent.CountDownLatch(1)
            val executor = java.util.concurrent.Executors.newFixedThreadPool(2)
            try {
                val futures = (0..1).map { executor.submit<WorkflowPinRequestResult> {
                    check(start.await(3, java.util.concurrent.TimeUnit.SECONDS))
                    store.requestProgressRetentionPinned(job, run.runId, run.version, true, actor, key)
                } }
                start.countDown()
                val results = futures.map { it.get(3, java.util.concurrent.TimeUnit.SECONDS) }
                assertEquals(1, results.count { it.replayed }); assertEquals(results.first().receipt, results.last().receipt)
                assertEquals(1, store.snapshot(job).pinAudit.entries.size)
                val otherJob = JobStore(root).createFromUpload("other.elf", elfFixture()).id
                val otherRun = store.create(otherJob, store.snapshot(otherJob).version, request).attempt
                val other = store.requestProgressRetentionPinned(otherJob, otherRun.runId, otherRun.version, false, actor, key)
                assertFalse(other.replayed); assertEquals(otherRun.runId, other.receipt.runId)
                assertNotEquals(results.first().receipt.requestKeyDigest, other.receipt.requestKeyDigest)
                assertEquals("RUN_NOT_FOUND", assertFailsWith<WorkflowStoreException> {
                    store.requestProgressRetentionPinned(job, otherRun.runId, otherRun.version, false, actor, key)
                }.code)
            } finally { start.countDown(); executor.shutdownNow(); assertTrue(executor.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS)) }
        }
    }

    @Test fun `capacity preserves keyed receipts for full day and later eviction is explicit`() = fixture { root, job ->
        var now = at
        val mutableClock = object : Clock() {
            override fun getZone(): ZoneId = ZoneOffset.UTC
            override fun withZone(zone: ZoneId): Clock = this
            override fun instant(): Instant = now
        }
        WorkflowAttemptStore.open(root, mutableClock).use { store ->
            val run = store.create(job, store.snapshot(job).version, request).attempt
            repeat(256) { store.requestProgressRetentionPinned(job, run.runId, run.version, false, actor, "request_key_${it.toString().padStart(16, '0')}") }
            val path = root.resolve("$job/workflow-state.json"); val bytes = path.readBytes()
            now = at.plusSeconds(86400).minusNanos(1)
            assertEquals("PIN_RECEIPT_CAPACITY", assertFailsWith<WorkflowStoreException> {
                store.requestProgressRetentionPinned(job, run.runId, run.version, true, actor, key)
            }.code)
            assertEquals("PIN_RECEIPT_CAPACITY", assertFailsWith<WorkflowStoreException> {
                store.setProgressRetentionPinned(job, run.runId, run.version, true)
            }.code)
            assertContentEquals(bytes, path.readBytes())
            assertTrue(store.requestProgressRetentionPinned(job, run.runId, run.version, false, actor, "request_key_0000000000000000").replayed)
            now = at.plusSeconds(86400)
            val changed = store.requestProgressRetentionPinned(job, run.runId, run.version, true, actor, key)
            assertTrue(changed.attempt.progressRetentionPinned)
            val audit = store.snapshot(job).pinAudit
            assertEquals(256, audit.entries.size); assertEquals(1uL, audit.omitted)
            assertEquals("VERSION_CONFLICT", assertFailsWith<WorkflowStoreException> {
                store.requestProgressRetentionPinned(job, run.runId, run.version, false, actor, "request_key_0000000000000000")
            }.code)
        }
    }

    @Test fun `request receipt and policy publish together across injected interruptions`() {
        WorkflowStoreFaultPoint.entries.forEach { point -> fixture { root, job ->
            lateinit var run: WorkflowAttempt
            WorkflowAttemptStore.open(root, clock).use { store -> run = store.create(job, store.snapshot(job).version, request).attempt }
            WorkflowAttemptStore.open(root, clock, WorkflowStoreFaultInjector { if (it == point) throw SimulatedStop() }).use { store ->
                assertFailsWith<SimulatedStop> { store.requestProgressRetentionPinned(job, run.runId, run.version, true, actor, key) }
            }
            WorkflowAttemptStore.open(root, clock).use { store ->
                store.recoverAfterRestart(job)
                val snapshot = store.snapshot(job)
                val committed = point in setOf(WorkflowStoreFaultPoint.AFTER_RENAME, WorkflowStoreFaultPoint.AFTER_DIRECTORY_FSYNC)
                assertEquals(committed, snapshot.latestRun!!.progressRetentionPinned, point.name)
                assertEquals(if (committed) 1 else 0, snapshot.pinAudit.entries.size, point.name)
                if (committed) assertTrue(store.requestProgressRetentionPinned(job, run.runId, run.version, true, actor, key).replayed)
            }
        } }
    }

    @Test fun `malformed or duplicate keyed receipts and unkeyed no-ops are rejected without rewriting`() = fixture { root, job ->
        WorkflowAttemptStore.open(root, clock).use { store ->
            val run = store.create(job, store.snapshot(job).version, request).attempt
            store.requestProgressRetentionPinned(job, run.runId, run.version, false, actor, key)
        }
        val path = root.resolve("$job/workflow-state.json")
        val rootJson = Json.parseToJsonElement(path.readText()).jsonObject
        val audit = rootJson.getValue("pinAudit").jsonObject
        val entry = audit.getValue("entries").jsonArray.single().jsonObject
        val badEntries = listOf(
            listOf(JsonObject(entry + ("requestKeyDigest" to JsonNull))),
            listOf(JsonObject(entry - "requestKeyDigest")),
            listOf(JsonObject(entry + ("requestKeyDigest" to JsonPrimitive("/private/canary")))),
            listOf(entry, JsonObject(entry + ("sequence" to JsonPrimitive("1")))),
            listOf(JsonObject(entry + ("outcome" to JsonPrimitive("applied")))),
        )
        badEntries.forEach { entries ->
            path.writeText(JsonObject(rootJson + ("pinAudit" to JsonObject(audit + ("entries" to JsonArray(entries))))).toString())
            val bytes = path.readBytes()
            WorkflowAttemptStore.open(root, clock).use { store ->
                assertEquals("CORRUPT_WORKFLOW_STATE", assertIs<WorkflowJobInspection.Unavailable>(store.inspect(job)).diagnostic.code)
            }
            assertContentEquals(bytes, path.readBytes())
        }
    }

    private class SimulatedStop : Error()
    private fun WorkflowAttemptStore.snapshot(job: String) = assertIs<WorkflowJobInspection.Available>(inspect(job)).snapshot
    private fun fixture(action: (Path, String) -> Unit) {
        val root = createTempDirectory("workflow-pin-request-")
        try { action(root, JobStore(root).createFromUpload("inert.elf", elfFixture()).id) }
        finally { root.toFile().deleteRecursively() }
    }
}
