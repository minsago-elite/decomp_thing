package decompengine.jobs

import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.extension.ExtendWith
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@ExtendWith(RecoveryMatrixEvidence::class)
class WorkflowStartReceiptTest {
    @Test
    fun `one atomic admission retains a hashed job key and replay precedes stale CAS`() = withRoot { root ->
        val job = upload(root)
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val version = store.available(job).snapshot.version
            assertNull(store.replayStart(job, REQUEST, KEY, version))
            assertFalse(state(root, job).exists())
            val first = store.createIdempotent(job, version, REQUEST, KEY)
            assertFalse(first.replayed)
            assertEquals(WorkflowRunState.QUEUED, first.attempt.state)
            assertEquals(first.attempt.runId, first.attempt.startReceipt!!.runId)
            val before = state(root, job).readBytes()
            assertFalse(before.toString(Charsets.UTF_8).contains(KEY))
            val replay = store.createIdempotent(job, "version_stale_storage", REQUEST, KEY, version)
            assertTrue(replay.replayed)
            assertEquals(first.attempt, replay.attempt)
            assertEquals(first.snapshot, replay.snapshot)
            assertContentEquals(before, state(root, job).readBytes())
        }
    }

    @Test
    fun `old keyed replay leaves later active work and accepted evidence untouched across reopen`() = withRoot { root ->
        val job = upload(root)
        lateinit var requestVersion: String
        lateinit var originalRun: String
        lateinit var laterRun: String
        lateinit var accepted: WorkflowAcceptanceReference
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            requestVersion = store.available(job).snapshot.version
            val created = store.createIdempotent(job, requestVersion, REQUEST, KEY)
            originalRun = created.attempt.runId
            val started = store.transition(job, originalRun, created.attempt.version, WorkflowTransition.Start)
            val completed = store.transition(job, originalRun, started.attempt.version,
                WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED, WorkflowCandidate("candidate_one", SHA)))
            accepted = WorkflowAcceptanceReference(job, originalRun, "candidate_one", SHA, "graph_one", "artifact_one", "b".repeat(64))
            val published = store.recordAcceptedRevision(job, originalRun, completed.snapshot.version, completed.attempt.version, accepted)
            laterRun = store.create(job, published.snapshot.version,
                REQUEST.copy(inputRevisionId = "candidate_one", previousRunId = originalRun)).attempt.runId
            val before = state(root, job).readBytes()
            val replay = assertNotNull(store.replayStart(job, REQUEST, KEY, requestVersion))
            assertEquals(originalRun, replay.attempt.runId)
            assertEquals(WorkflowRunState.COMPLETED, replay.attempt.state)
            assertEquals(laterRun, replay.snapshot.latestRun!!.runId)
            assertEquals(accepted, replay.snapshot.acceptedRevision)
            assertContentEquals(before, state(root, job).readBytes())
        }
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val recovered = store.recoverAfterRestart(job) as WorkflowJobInspection.Available
            assertEquals(WorkflowRunState.INTERRUPTED, recovered.snapshot.latestRun!!.state)
            val before = state(root, job).readBytes()
            val replay = store.createIdempotent(job, recovered.snapshot.version, REQUEST, KEY, requestVersion)
            assertTrue(replay.replayed)
            assertEquals(originalRun, replay.attempt.runId)
            assertEquals(laterRun, replay.snapshot.latestRun!!.runId)
            assertEquals(accepted, replay.snapshot.acceptedRevision)
            assertContentEquals(before, state(root, job).readBytes())
        }
    }

    @Test
    fun `reuse with any different request field conflicts before CAS or creation`() = withRoot { root ->
        val job = upload(root)
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val version = store.available(job).snapshot.version
            store.createIdempotent(job, version, REQUEST, KEY)
            val variants = listOf(
                REQUEST.copy(workflow = WorkflowKind.REPAIR), REQUEST.copy(inputRevisionId = "revision_changed"),
                REQUEST.copy(harnessCapabilityId = "harness_changed"), REQUEST.copy(previousRunId = "run_changed"),
                REQUEST.copy(limits = LIMITS.copy(wallClockMs = 60_001uL)),
                REQUEST.copy(limits = LIMITS.copy(idleMs = 15_001uL)),
                REQUEST.copy(limits = LIMITS.copy(maxOutputBytes = 1_048_577uL)),
                REQUEST.copy(limits = LIMITS.copy(maxToolCalls = 17uL)),
            )
            val before = state(root, job).readBytes()
            variants.forEach { changed ->
                assertCode("IDEMPOTENCY_CONFLICT") { store.createIdempotent(job, "version_stale", changed, KEY, version) }
            }
            assertCode("IDEMPOTENCY_CONFLICT") { store.createIdempotent(job, "version_stale", REQUEST, KEY, "version_different_request") }
            assertContentEquals(before, state(root, job).readBytes())
            assertEquals(1, store.available(job).snapshot.attempts.size)
        }
    }

    @Test
    fun `keys are bounded job scoped and independent of a listener or session lifetime`() = withRoot { root ->
        val firstJob = upload(root); val secondJob = upload(root)
        lateinit var version: String
        lateinit var firstRun: String
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            version = store.available(firstJob).snapshot.version
            for (key in listOf("short", "x".repeat(129), "invalid/key_123456", "invalid\u0000key_123456")) {
                assertCode("INVALID_IDEMPOTENCY_KEY") { store.createIdempotent(firstJob, version, REQUEST, key) }
            }
            assertFailsWith<IllegalArgumentException> { store.createIdempotent(firstJob, version, REQUEST, KEY, "invalid version") }
            assertFalse(state(root, firstJob).exists())
            val first = store.createIdempotent(firstJob, version, REQUEST, KEY)
            val second = store.createIdempotent(secondJob, store.available(secondJob).snapshot.version, REQUEST, KEY)
            firstRun = first.attempt.runId
            assertNotEquals(firstRun, second.attempt.runId)
            assertNotEquals(first.attempt.startReceipt!!.requestKeyDigest, second.attempt.startReceipt!!.requestKeyDigest)
        }
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            store.recoverAfterRestart(firstJob)
            val replay = store.createIdempotent(firstJob, "version_ignored_for_replay", REQUEST, KEY, version)
            assertTrue(replay.replayed)
            assertEquals(firstRun, replay.attempt.runId)
            assertEquals(WorkflowRunState.INTERRUPTED, replay.attempt.state)
        }
    }

    @Test
    fun `concurrent identical keyed admissions publish one attempt and one replay`() = withRoot { root ->
        val job = upload(root)
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val version = store.available(job).snapshot.version
            val results = race { store.createIdempotent(job, version, REQUEST, KEY) }
            assertTrue(results.all { it is WorkflowStartResult })
            val starts = results.map { it as WorkflowStartResult }
            assertEquals(1, starts.count { !it.replayed }); assertEquals(1, starts.count { it.replayed })
            assertEquals(1, starts.map { it.attempt.runId }.distinct().size)
            assertEquals(1, store.available(job).snapshot.attempts.size)
        }
    }

    @Test
    fun `concurrent different intents sharing a key retain the winning attempt`() = withRoot { root ->
        val job = upload(root)
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val version = store.available(job).snapshot.version
            val results = race { index -> store.createIdempotent(job, version,
                if (index == 0) REQUEST else REQUEST.copy(workflow = WorkflowKind.REPAIR), KEY) }
            assertEquals(1, results.count { it is WorkflowStartResult })
            assertEquals(1, results.count { it is WorkflowStoreException && it.code == "IDEMPOTENCY_CONFLICT" })
            val winner = results.filterIsInstance<WorkflowStartResult>().single()
            assertEquals(winner.attempt, store.available(job).snapshot.latestRun)
        }
    }

    @Test
    fun `each atomic write fault leaves either no receipt or the original interrupted attempt`() {
        WorkflowStoreFaultPoint.entries.forEach { point -> withRoot { root ->
            val job = upload(root)
            lateinit var version: String
            var committedRun: String? = null
            WorkflowAttemptStore.open(root, CLOCK, WorkflowStoreFaultInjector {
                if (it == point) throw IOException("authored atomic start publication fault")
            }).use { store ->
                version = store.available(job).snapshot.version
                if (point == WorkflowStoreFaultPoint.AFTER_DIRECTORY_FSYNC) {
                    committedRun = store.createIdempotent(job, version, REQUEST, KEY).attempt.runId
                } else {
                    assertCode("PERSISTENCE_FAILED") { store.createIdempotent(job, version, REQUEST, KEY) }
                }
            }
            WorkflowAttemptStore.open(root, CLOCK).use { store ->
                val recovered = store.recoverAfterRestart(job) as WorkflowJobInspection.Available
                val original = recovered.snapshot.latestRun
                val committed = point in setOf(WorkflowStoreFaultPoint.AFTER_RENAME, WorkflowStoreFaultPoint.AFTER_DIRECTORY_FSYNC)
                assertEquals(committed, original != null)
                if (committedRun != null) assertEquals(committedRun, original!!.runId)
                val result = store.createIdempotent(job, recovered.snapshot.version, REQUEST, KEY, version)
                assertEquals(committed, result.replayed)
                assertEquals(1, result.snapshot.attempts.size)
                if (committed) {
                    assertEquals(original!!.runId, result.attempt.runId)
                    assertEquals(WorkflowRunState.INTERRUPTED, result.attempt.state)
                } else assertEquals(WorkflowRunState.QUEUED, result.attempt.state)
                assertNull(result.snapshot.acceptedRevision)
            }
        } }
    }

    @Test
    fun `legacy unkeyed attempts stay readable and new keys preserve exclusivity and CAS`() = withRoot { root ->
        val job = upload(root)
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val version = store.available(job).snapshot.version
            val plain = store.create(job, version, REQUEST)
            assertNull(plain.attempt.startReceipt)
            val before = state(root, job).readBytes()
            assertFalse(before.toString(Charsets.UTF_8).contains("startReceipt"))
            assertNull(store.replayStart(job, REQUEST, KEY, version))
            assertCode("VERSION_CONFLICT") { store.createIdempotent(job, version, REQUEST, KEY) }
            assertCode("ACTIVE_RUN") { store.createIdempotent(job, plain.snapshot.version, REQUEST, KEY) }
            assertContentEquals(before, state(root, job).readBytes())
        }
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            assertNull(store.available(job).snapshot.latestRun!!.startReceipt)
        }
    }

    @Test
    fun `malformed copied duplicate and intent changed receipts refuse without modifying stored bytes`() {
        for (defect in listOf("foreign-run", "intent", "version", "unknown-field", "duplicate-key")) withRoot { root ->
            val job = upload(root)
            WorkflowAttemptStore.open(root, CLOCK).use { store ->
                val first = store.createIdempotent(job, store.available(job).snapshot.version, REQUEST, KEY)
                val ended = store.transition(job, first.attempt.runId, first.attempt.version,
                    WorkflowTransition.Finish(WorkflowRunState.FAILED, WorkflowTerminalReason.REFUSED))
                store.createIdempotent(job, ended.snapshot.version, REQUEST, "second_request_key_123456")
            }
            val document = Json.parseToJsonElement(state(root, job).readText()).jsonObject
            val attempts = document.getValue("attempts").jsonArray.toMutableList()
            val first = attempts.first().jsonObject
            val receipt = first.getValue("startReceipt").jsonObject
            val changed = when (defect) {
                "foreign-run" -> JsonObject(receipt + ("runId" to JsonPrimitive("run_not_the_admitted_run")))
                "intent" -> JsonObject(receipt + ("intentSha256" to JsonPrimitive("0".repeat(64))))
                "version" -> JsonObject(receipt + ("expectedRequestVersion" to JsonPrimitive("version_tampered")))
                "unknown-field" -> JsonObject(receipt + ("extra" to JsonPrimitive(true)))
                else -> receipt
            }
            if (defect == "duplicate-key") {
                val second = attempts[1].jsonObject
                val ownReceipt = second.getValue("startReceipt").jsonObject
                attempts[1] = JsonObject(second + ("startReceipt" to JsonObject(ownReceipt +
                    ("requestKeyDigest" to receipt.getValue("requestKeyDigest")))))
            } else attempts[0] = JsonObject(first + ("startReceipt" to changed))
            state(root, job).writeText(JsonObject(document + ("attempts" to JsonArray(attempts))).toString())
            val before = state(root, job).readBytes()
            WorkflowAttemptStore.open(root, CLOCK).use { store ->
                val refusal = store.inspect(job) as WorkflowJobInspection.Unavailable
                assertEquals("CORRUPT_WORKFLOW_STATE", refusal.diagnostic.code)
                assertCode("CORRUPT_WORKFLOW_STATE") { store.replayStart(job, REQUEST, KEY, "version_unused") }
            }
            assertContentEquals(before, state(root, job).readBytes())
        }
    }

    private fun WorkflowAttemptStore.available(job: String) = inspect(job) as WorkflowJobInspection.Available
    private fun upload(root: Path) = JobStore(root).createFromUpload("authored-header.elf", elfFixture()).id
    private fun state(root: Path, job: String) = root.resolve(job).resolve("workflow-state.json")
    private fun assertCode(code: String, operation: () -> Unit) =
        assertEquals(code, assertFailsWith<WorkflowStoreException> { operation() }.code)
    private fun withRoot(operation: (Path) -> Unit) {
        val root = createTempDirectory("workflow-start-receipts-")
        try { operation(root) } finally { root.toFile().deleteRecursively() }
    }
    private fun race(operation: (Int) -> Any): List<Any> {
        val ready = CountDownLatch(2); val release = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        try {
            val results = (0..1).map { index -> pool.submit<Any> {
                ready.countDown(); check(release.await(5, TimeUnit.SECONDS))
                try { operation(index) } catch (failure: Exception) { failure }
            } }
            check(ready.await(5, TimeUnit.SECONDS)); release.countDown()
            return results.map { it.get(10, TimeUnit.SECONDS) }
        } finally { release.countDown(); pool.shutdownNow() }
    }
    private companion object {
        val CLOCK: Clock = Clock.fixed(Instant.parse("2026-09-05T00:00:00Z"), ZoneOffset.UTC)
        val LIMITS = WorkflowExecutionLimits(60_000uL, 15_000uL, 1_048_576uL, 16uL)
        val REQUEST = NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS)
        const val KEY = "operator_start_request_123456"
        val SHA = "a".repeat(64)
    }
}
