package decompengine.jobs

import java.nio.file.Path
import java.time.Clock
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import org.junit.jupiter.api.extension.ExtendWith
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlinx.serialization.json.*
import kotlin.test.*

@ExtendWith(RecoveryMatrixEvidence::class)
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

    @Test fun `terminal acknowledgement and replay preserve accepted evidence and a newer pinned attempt across reopen`() = fixture { root, job ->
        lateinit var accepted: WorkflowAttempt
        lateinit var reference: WorkflowAcceptanceReference
        lateinit var receipt: WorkflowCancellationReceipt
        lateinit var diagnostic: Path
        lateinit var newerId: String
        WorkflowAttemptStore.open(root).use { store ->
            val queued = store.create(job, store.snapshot(job).version, request)
            val running = store.transition(job, queued.attempt.runId, queued.attempt.version, WorkflowTransition.Start)
            val done = store.transition(job, running.attempt.runId, running.attempt.version,
                WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED,
                    WorkflowCandidate("accepted_authored", "c".repeat(64))))
            reference = WorkflowAcceptanceReference(job, done.attempt.runId, "accepted_authored", "c".repeat(64),
                "graph_authored", "artifact_authored", "d".repeat(64))
            accepted = store.recordAcceptedRevision(job, done.attempt.runId, done.snapshot.version, done.attempt.version, reference).attempt
            diagnostic = java.nio.file.Files.createDirectories(root.resolve("$job/reports/runs/${accepted.runId}")).resolve("retained.txt")
            diagnostic.writeText("authored prior diagnostic\n")
            val newer = store.create(job, store.snapshot(job).version, request).attempt
            newerId = newer.runId
            val first = store.requestCancellation(job, accepted.runId, accepted.version, actor, key)
            assertFalse(first.replayed); assertEquals(accepted, first.attempt)
            receipt = first.receipt
            assertEquals(WorkflowRunState.COMPLETED, receipt.acknowledgedState)
            assertEquals(accepted.version, receipt.expectedVersion); assertEquals(accepted.version, receipt.appliedVersion)
            val pinned = store.setProgressRetentionPinned(job, newer.runId, newer.version, true).attempt
            val before = root.resolve("$job/workflow-state.json").readBytes()
            val replay = store.requestCancellation(job, accepted.runId, accepted.version, actor, key)
            assertTrue(replay.replayed); assertEquals(receipt, replay.receipt); assertEquals(accepted, replay.attempt)
            assertEquals(pinned, store.snapshot(job).attempts.single { it.runId == newerId })
            assertEquals(reference, store.snapshot(job).acceptedRevision)
            assertContentEquals(before, root.resolve("$job/workflow-state.json").readBytes())
            assertEquals("authored prior diagnostic\n", diagnostic.readText())
        }
        WorkflowAttemptStore.open(root).use { store ->
            store.recoverAfterRestart(job)
            val before = root.resolve("$job/workflow-state.json").readBytes()
            val replay = store.requestCancellation(job, accepted.runId, accepted.version, actor, key)
            assertTrue(replay.replayed); assertEquals(receipt, replay.receipt); assertEquals(accepted, replay.attempt)
            val newer = store.snapshot(job).attempts.single { it.runId == newerId }
            assertEquals(WorkflowRunState.INTERRUPTED, newer.state); assertTrue(newer.progressRetentionPinned)
            assertEquals(reference, store.snapshot(job).acceptedRevision)
            assertContentEquals(before, root.resolve("$job/workflow-state.json").readBytes())
            assertEquals("authored prior diagnostic\n", diagnostic.readText())
        }
    }

    @Test fun `actor job and run scopes reject stale or foreign targets without changing later work`() = fixture { root, job ->
        WorkflowAttemptStore.open(root).use { store ->
            val other = JobStore(root).createFromUpload("other.elf", elfFixture()).id
            val original = store.create(job, store.snapshot(job).version, request).attempt
            val foreign = store.create(other, store.snapshot(other).version, request).attempt
            val first = store.requestCancellation(job, original.runId, original.version, actor, key)
            val before = root.resolve("$job/workflow-state.json").readBytes()
            fun refuses(code: String, operation: () -> Unit) = assertEquals(code, assertFailsWith<WorkflowStoreException> { operation() }.code)
            refuses("VERSION_CONFLICT") {
                store.requestCancellation(job, original.runId, original.version, WorkflowCancellationActor.browserSession("b".repeat(64)), key)
            }
            refuses("INVALID_IDEMPOTENCY_KEY") { store.requestCancellation(job, original.runId, first.attempt.version, actor, "short") }
            refuses("RUN_NOT_FOUND") { store.requestCancellation(job, foreign.runId, foreign.version, actor, key) }
            refuses("RUN_NOT_FOUND") { store.requestCancellation(other, original.runId, original.version, actor, key) }
            assertContentEquals(before, root.resolve("$job/workflow-state.json").readBytes())
            val foreignRequest = store.requestCancellation(other, foreign.runId, foreign.version, actor, key)
            assertFalse(foreignRequest.replayed); assertNotEquals(first.receipt.requestKeyDigest, foreignRequest.receipt.requestKeyDigest)
            val terminal = store.transition(job, original.runId, first.attempt.version,
                WorkflowTransition.Finish(WorkflowRunState.CANCELLED, WorkflowTerminalReason.CANCELLED))
            val next = store.create(job, terminal.snapshot.version, request).attempt
            refuses("VERSION_CONFLICT") { store.requestCancellation(job, next.runId, original.version, actor, key) }
            assertEquals(WorkflowRunState.QUEUED, store.snapshot(job).latestRun!!.state)
            val nextRequest = store.requestCancellation(job, next.runId, next.version, actor, key)
            assertFalse(nextRequest.replayed); assertNotEquals(first.receipt.requestKeyDigest, nextRequest.receipt.requestKeyDigest)
            val laterBytes = root.resolve("$job/workflow-state.json").readBytes()
            assertTrue(store.requestCancellation(job, original.runId, original.version, actor, key).replayed)
            assertEquals(nextRequest.attempt, store.snapshot(job).latestRun)
            assertEquals(2, store.snapshot(job).cancellationReceipts.entries.size)
            assertContentEquals(laterBytes, root.resolve("$job/workflow-state.json").readBytes())
        }
    }

    @Test fun `all atomic write boundaries retain either no acknowledgement or the same recoverable receipt`() {
        for (point in WorkflowStoreFaultPoint.entries) fixture { root, job ->
            val armed = AtomicBoolean(false)
            lateinit var run: WorkflowAttempt
            val uncertain = point in setOf(WorkflowStoreFaultPoint.BEFORE_RENAME, WorkflowStoreFaultPoint.AFTER_RENAME)
            val receiptPublished = point in setOf(WorkflowStoreFaultPoint.AFTER_RENAME, WorkflowStoreFaultPoint.AFTER_DIRECTORY_FSYNC)
            WorkflowAttemptStore.open(root, Clock.systemUTC(), WorkflowStoreFaultInjector {
                if (armed.get() && it == point) throw IOException("authored cancellation fault $point")
            }).use { store ->
                run = store.create(job, store.snapshot(job).version, request).attempt
                val before = root.resolve("$job/workflow-state.json").readBytes()
                armed.set(true)
                if (point == WorkflowStoreFaultPoint.AFTER_DIRECTORY_FSYNC) {
                    val result = store.requestCancellation(job, run.runId, run.version, actor, key)
                    assertFalse(result.replayed)
                    assertEquals(WorkflowRunState.CANCELLING, result.attempt.state)
                    assertEquals(result.receipt, store.snapshot(job).cancellationReceipts.entries.single())
                    val committedBytes = root.resolve("$job/workflow-state.json").readBytes()
                    val replay = store.requestCancellation(job, run.runId, run.version, actor, key)
                    assertTrue(replay.replayed); assertEquals(result, replay.copy(replayed = false))
                    assertContentEquals(committedBytes, root.resolve("$job/workflow-state.json").readBytes())
                } else {
                    val failure = assertFailsWith<WorkflowStoreException> { store.requestCancellation(job, run.runId, run.version, actor, key) }
                    assertEquals("PERSISTENCE_FAILED", failure.code)
                    assertEquals(uncertain, failure.outcomeUnknown)
                    if (uncertain) {
                        assertEquals("RECOVERY_REQUIRED", assertFailsWith<WorkflowStoreException> { store.snapshot(job) }.code)
                    } else assertTrue(store.snapshot(job).cancellationReceipts.entries.isEmpty())
                    if (!receiptPublished) assertContentEquals(before, root.resolve("$job/workflow-state.json").readBytes())
                }
            }
            WorkflowAttemptStore.open(root).use { store ->
                store.recoverAfterRestart(job)
                val snapshot = store.snapshot(job)
                assertEquals(WorkflowRunState.INTERRUPTED, snapshot.latestRun!!.state)
                val before = root.resolve("$job/workflow-state.json").readBytes()
                if (receiptPublished) {
                    assertEquals(1, snapshot.cancellationReceipts.entries.size)
                    val replay = store.requestCancellation(job, run.runId, run.version, actor, key)
                    assertTrue(replay.replayed); assertEquals(WorkflowRunState.CANCELLING, replay.receipt.acknowledgedState)
                    assertEquals(WorkflowRunState.INTERRUPTED, replay.attempt.state)
                } else {
                    assertTrue(snapshot.cancellationReceipts.entries.isEmpty())
                    assertEquals("VERSION_CONFLICT", assertFailsWith<WorkflowStoreException> {
                        store.requestCancellation(job, run.runId, run.version, actor, key)
                    }.code)
                }
                assertNull(store.snapshot(job).acceptedRevision)
                assertContentEquals(before, root.resolve("$job/workflow-state.json").readBytes())
            }
        }
    }

    @Test fun `legacy omission and malformed duplicate or noncanonical receipt fields never rewrite evidence`() = fixture { root, job ->
        lateinit var run: WorkflowAttempt
        WorkflowAttemptStore.open(root).use { store ->
            run = store.create(job, store.snapshot(job).version, request).attempt
        }
        val path = root.resolve("$job/workflow-state.json")
        val legacy = path.readBytes()
        assertFalse(Json.parseToJsonElement(path.readText()).jsonObject.containsKey("cancellationReceipts"))
        WorkflowAttemptStore.open(root).use { store ->
            assertTrue(store.snapshot(job).cancellationReceipts.entries.isEmpty())
            assertContentEquals(legacy, path.readBytes())
            store.recoverAfterRestart(job)
            val current = store.snapshot(job).latestRun!!
            store.requestCancellation(job, current.runId, current.version, actor, key)
        }
        val valid = Json.parseToJsonElement(path.readText()).jsonObject
        val receipts = valid.getValue("cancellationReceipts").jsonObject
        val entry = receipts.getValue("entries").jsonArray.single().jsonObject
        val invalidEntries = listOf(
            JsonObject(entry + ("extra" to JsonPrimitive(true))),
            JsonObject(entry + ("actorDigest" to JsonPrimitive(1))),
            JsonObject(entry + ("at" to JsonPrimitive("2026-01-01T00:00:00.000Z"))),
            JsonObject(entry + ("at" to JsonPrimitive("x".repeat(41)))),
        )
        val invalidReceipts = invalidEntries.map { JsonObject(receipts + ("entries" to JsonArray(listOf(it)))) } + listOf(
            JsonObject(receipts + ("entries" to JsonArray(listOf(entry, entry)))),
            JsonObject(receipts + ("version" to JsonPrimitive(2))),
            JsonObject(receipts + ("extra" to JsonNull)),
        )
        for (changed in invalidReceipts) {
            path.writeText(JsonObject(valid + ("cancellationReceipts" to changed)).toString())
            val before = path.readBytes()
            WorkflowAttemptStore.open(root).use { store ->
                assertEquals("CORRUPT_WORKFLOW_STATE", assertIs<WorkflowJobInspection.Unavailable>(store.inspect(job)).diagnostic.code)
            }
            assertContentEquals(before, path.readBytes())
        }
    }

    @Test fun `start and cancellation receipts coexist across pins terminal state later work and reopen`() = fixture { root, job ->
        val startKey = "authored_start_receipt_key"
        val publicVersion = "authored_public_start_version"
        lateinit var original: WorkflowAttempt
        lateinit var startReceipt: WorkflowStartReceipt
        lateinit var cancellation: WorkflowCancellationReceipt
        lateinit var laterId: String
        WorkflowAttemptStore.open(root).use { store ->
            original = store.createIdempotent(job, store.snapshot(job).version, request, startKey, publicVersion).attempt
            startReceipt = assertNotNull(original.startReceipt)
            val first = store.requestCancellation(job, original.runId, original.version, actor, key)
            cancellation = first.receipt
            val pinned = store.setProgressRetentionPinned(job, original.runId, first.attempt.version, true).attempt
            val before = root.resolve("$job/workflow-state.json").readBytes()
            val startReplay = assertNotNull(store.replayStart(job, request, startKey, publicVersion))
            assertTrue(startReplay.replayed); assertEquals(pinned, startReplay.attempt)
            assertEquals(startReceipt, startReplay.attempt.startReceipt)
            val cancelReplay = store.requestCancellation(job, original.runId, original.version, actor, key)
            assertTrue(cancelReplay.replayed); assertEquals(pinned, cancelReplay.attempt)
            assertEquals(cancellation, cancelReplay.receipt)
            assertContentEquals(before, root.resolve("$job/workflow-state.json").readBytes())
            val terminal = store.transition(job, original.runId, pinned.version,
                WorkflowTransition.Finish(WorkflowRunState.CANCELLED, WorkflowTerminalReason.CANCELLED))
            assertEquals(startReceipt, terminal.attempt.startReceipt)
            laterId = store.createIdempotent(job, terminal.snapshot.version, request,
                "authored_later_start_key", "authored_later_public_version").attempt.runId
        }
        WorkflowAttemptStore.open(root).use { store ->
            store.recoverAfterRestart(job)
            val before = root.resolve("$job/workflow-state.json").readBytes()
            val startReplay = assertNotNull(store.replayStart(job, request, startKey, publicVersion))
            val cancelReplay = store.requestCancellation(job, original.runId, original.version, actor, key)
            assertEquals(WorkflowRunState.CANCELLED, startReplay.attempt.state)
            assertEquals(startReplay.attempt, cancelReplay.attempt)
            assertEquals(startReceipt, startReplay.attempt.startReceipt)
            assertEquals(cancellation, cancelReplay.receipt)
            assertEquals(laterId, store.snapshot(job).latestRun!!.runId)
            assertEquals(WorkflowRunState.INTERRUPTED, store.snapshot(job).latestRun!!.state)
            assertTrue(startReplay.attempt.progressRetentionPinned)
            assertNull(store.snapshot(job).acceptedRevision)
            assertContentEquals(before, root.resolve("$job/workflow-state.json").readBytes())
        }
    }

    private fun WorkflowAttemptStore.snapshot(job: String) = assertIs<WorkflowJobInspection.Available>(inspect(job)).snapshot
    private fun fixture(action: (Path, String) -> Unit) {
        val root = createTempDirectory("workflow-cancel-receipt-")
        try { action(root, JobStore(root).createFromUpload("inert.elf", elfFixture()).id) }
        finally { root.toFile().deleteRecursively() }
    }
}
