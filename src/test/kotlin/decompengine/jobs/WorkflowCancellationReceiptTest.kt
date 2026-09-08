package decompengine.jobs

import java.nio.file.Path
import java.time.Clock
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlinx.serialization.json.*
import kotlin.test.*

class WorkflowCancellationReceiptTest {
    private val actor = WorkflowCancellationActor.browserSession("a".repeat(64))
    private val key = "inert_cancel_key_12345"
    private val request = NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WorkflowExecutionLimits(60_000u, 15_000u, 1_048_576u, 16u))

    @Test fun `replay returns original acknowledgement and current terminal state without rewriting newer attempts`() = fixture { root, job ->
        lateinit var original: WorkflowAttempt
        lateinit var receipt: WorkflowCancellationReceipt
        WorkflowAttemptStore.open(root).use { store ->
            original = store.create(job, store.snapshot(job).version, request).attempt
            val first = store.requestCancellation(job, original.runId, original.version, actor, key)
            receipt = first.receipt
            assertEquals(WorkflowRunState.CANCELLING, first.attempt.state)
            val terminal = store.transition(job, original.runId, first.attempt.version,
                WorkflowTransition.Finish(WorkflowRunState.CANCELLED, WorkflowTerminalReason.CANCELLED))
            val next = store.create(job, terminal.snapshot.version, request).attempt
            val bytes = root.resolve("$job/workflow-state.json").readBytes()
            val replay = store.requestCancellation(job, original.runId, original.version, actor, key)
            assertTrue(replay.replayed); assertEquals(receipt, replay.receipt)
            assertEquals(WorkflowRunState.CANCELLED, replay.attempt.state)
            assertEquals(WorkflowRunState.QUEUED, store.snapshot(job).attempts.single { it.runId == next.runId }.state)
            assertContentEquals(bytes, root.resolve("$job/workflow-state.json").readBytes())
            assertFalse(bytes.toString(Charsets.UTF_8).contains(key))
            assertFalse(bytes.toString(Charsets.UTF_8).contains("a".repeat(64)))
            assertEquals("IDEMPOTENCY_CONFLICT", assertFailsWith<WorkflowStoreException> {
                store.requestCancellation(job, original.runId, terminal.attempt.version, actor, key)
            }.code)
            assertEquals("VERSION_CONFLICT", assertFailsWith<WorkflowStoreException> {
                store.requestCancellation(job, original.runId, original.version, WorkflowCancellationActor.browserSession("b".repeat(64)), key)
            }.code)
        }
        WorkflowAttemptStore.open(root).use { store ->
            store.recoverAfterRestart(job)
            val bytes = root.resolve("$job/workflow-state.json").readBytes()
            val replay = store.requestCancellation(job, original.runId, original.version, actor, key)
            assertTrue(replay.replayed); assertEquals(receipt, replay.receipt)
            assertEquals(WorkflowRunState.CANCELLED, replay.attempt.state)
            assertContentEquals(bytes, root.resolve("$job/workflow-state.json").readBytes())
        }
    }

    @Test fun `concurrent duplicates commit one receipt and capacity preserves replay without evicting keys`() = fixture { root, job ->
        WorkflowAttemptStore.open(root).use { store ->
            val run = store.create(job, store.snapshot(job).version, request).attempt
            val executor = java.util.concurrent.Executors.newFixedThreadPool(2)
            val start = java.util.concurrent.CountDownLatch(1)
            val results = try {
                val futures = (0..1).map { executor.submit<WorkflowCancellationRequestResult> {
                    check(start.await(5, java.util.concurrent.TimeUnit.SECONDS))
                    store.requestCancellation(job, run.runId, run.version, actor, key)
                } }
                start.countDown(); futures.map { it.get(5, java.util.concurrent.TimeUnit.SECONDS) }
            } finally { executor.shutdownNow() }
            assertEquals(1, results.count { !it.replayed })
            assertEquals(results[0].receipt, results[1].receipt)
            val current = results[0].attempt
            for (index in 1 until WorkflowCancellationReceipts.MAX_ENTRIES)
                store.requestCancellation(job, run.runId, current.version, actor, "inert_capacity_key_$index")
            val bytes = root.resolve("$job/workflow-state.json").readBytes()
            assertEquals("CANCELLATION_RECEIPT_CAPACITY", assertFailsWith<WorkflowStoreException> {
                store.requestCancellation(job, run.runId, current.version, actor, "inert_over_capacity_key")
            }.code)
            assertTrue(store.requestCancellation(job, run.runId, run.version, actor, key).replayed)
            assertContentEquals(bytes, root.resolve("$job/workflow-state.json").readBytes())
        }
    }

    @Test fun `uncertain publication retains acknowledgement atomically through recovery`() = fixture { root, job ->
        val fail = AtomicBoolean(false)
        lateinit var run: WorkflowAttempt
        WorkflowAttemptStore.open(root, Clock.systemUTC(), WorkflowStoreFaultInjector {
            if (fail.get() && it == WorkflowStoreFaultPoint.AFTER_RENAME) throw IOException("inert uncertain cancellation")
        }).use { store ->
            run = store.create(job, store.snapshot(job).version, request).attempt
            fail.set(true)
            assertTrue(assertFailsWith<WorkflowStoreException> {
                store.requestCancellation(job, run.runId, run.version, actor, key)
            }.outcomeUnknown)
        }
        WorkflowAttemptStore.open(root).use { store ->
            store.recoverAfterRestart(job)
            val bytes = root.resolve("$job/workflow-state.json").readBytes()
            val replay = store.requestCancellation(job, run.runId, run.version, actor, key)
            assertTrue(replay.replayed)
            assertEquals(WorkflowRunState.CANCELLING, replay.receipt.acknowledgedState)
            assertEquals(WorkflowRunState.INTERRUPTED, replay.attempt.state)
            assertContentEquals(bytes, root.resolve("$job/workflow-state.json").readBytes())
        }
    }

    @Test fun `invalid receipt state and foreign targets fail closed without rewriting storage`() = fixture { root, job ->
        WorkflowAttemptStore.open(root).use { store ->
            val run = store.create(job, store.snapshot(job).version, request).attempt
            store.requestCancellation(job, run.runId, run.version, actor, key)
        }
        val path = root.resolve("$job/workflow-state.json")
        val state = Json.parseToJsonElement(path.readText()).jsonObject
        val receipts = state.getValue("cancellationReceipts").jsonObject
        val entry = receipts.getValue("entries").jsonArray.single().jsonObject
        for (changed in listOf(entry + ("acknowledgedState" to JsonPrimitive("queued")), entry + ("runId" to JsonPrimitive("run_foreign")),
            entry + mapOf("acknowledgedState" to JsonPrimitive("completed"), "appliedVersion" to entry.getValue("expectedVersion")),
            entry + ("actorDigest" to JsonPrimitive("invalid_digest")))) {
            path.writeText(JsonObject(state + ("cancellationReceipts" to JsonObject(receipts + ("entries" to JsonArray(listOf(JsonObject(changed))))))).toString())
            val bytes = path.readBytes()
            WorkflowAttemptStore.open(root).use { store ->
                assertEquals("CORRUPT_WORKFLOW_STATE", assertIs<WorkflowJobInspection.Unavailable>(store.inspect(job)).diagnostic.code)
            }
            assertContentEquals(bytes, path.readBytes())
        }
    }

    private fun WorkflowAttemptStore.snapshot(job: String) = assertIs<WorkflowJobInspection.Available>(inspect(job)).snapshot
    private fun fixture(action: (Path, String) -> Unit) {
        val root = createTempDirectory("workflow-cancel-receipt-")
        try { action(root, JobStore(root).createFromUpload("inert.elf", elfFixture()).id) }
        finally { root.toFile().deleteRecursively() }
    }
}
