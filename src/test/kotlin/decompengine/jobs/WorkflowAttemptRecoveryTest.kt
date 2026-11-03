package decompengine.jobs

import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import org.junit.jupiter.api.extension.ExtendWith
import java.nio.file.Path
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

@ExtendWith(RecoveryMatrixEvidence::class)
class WorkflowAttemptRecoveryTest {
    @Test
    fun `retry and resume records survive reopen and replay before every CAS guard`() = withRoot { root ->
        val job = upload(root)
        lateinit var retry: WorkflowAttempt
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val failed = failedAttempt(store, job)
            val request = NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS, previousRunId = failed.runId,
                recovery = WorkflowAttemptRecovery(WorkflowRecoveryMode.RETRY))
            assertNull(store.replayRecovery(job, failed.runId, failed.version, WorkflowRecoveryMode.RETRY, null, KEY))
            retry = store.createIdempotent(job, store.available(job).snapshot.version, request, KEY, failed.version).attempt
            assertEquals(failed.runId, retry.previousRunId); assertEquals(WorkflowRecoveryMode.RETRY, retry.recovery!!.mode)
            assertNotEquals(failed.runId, retry.runId)
            val before = state(root, job).readBytes()
            // Server-selected limits/harness are not replay identity; caller intent is.
            val replay = store.replayRecovery(job, failed.runId, failed.version, WorkflowRecoveryMode.RETRY, null, KEY)!!
            assertTrue(replay.replayed); assertEquals(retry, replay.attempt)
            assertCode("IDEMPOTENCY_CONFLICT") { store.replayRecovery(job, failed.runId, failed.version, WorkflowRecoveryMode.RESUME, null, KEY) }
            assertCode("IDEMPOTENCY_CONFLICT") { store.replayRecovery(job, failed.runId, failed.version, WorkflowRecoveryMode.RETRY, "revision_x", KEY) }
            // A plain start reusing the recovery key is different intent, not a second attempt.
            assertCode("IDEMPOTENCY_CONFLICT") { store.replayStart(job, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS), KEY, failed.version) }
            assertContentEquals(before, state(root, job).readBytes())
            assertFalse(state(root, job).readText().contains(KEY))
        }
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val reopened = store.available(job).snapshot.attempts.single { it.runId == retry.runId }
            assertEquals(retry.recovery, reopened.recovery)
            val resume = WorkflowAttemptRecovery(WorkflowRecoveryMode.RESUME, WorkflowResumeRestoration.AGENT_SESSION, SHA)
            store.transition(job, reopened.runId, reopened.version, WorkflowTransition.Finish(WorkflowRunState.CANCELLED, WorkflowTerminalReason.CANCELLED))
            val cancelled = store.available(job).snapshot.attempts.last()
            val resumed = store.createIdempotent(job, store.available(job).snapshot.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS,
                previousRunId = cancelled.runId, recovery = resume), "operator_resume_request_1234", cancelled.version).attempt
            assertEquals(resume, resumed.recovery)
        }
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            assertEquals(WorkflowResumeRestoration.AGENT_SESSION, store.available(job).snapshot.attempts.last().recovery!!.restores)
        }
    }

    @Test
    fun `recovery links only the latest unsuccessful attempt through a keyed command`() = withRoot { root ->
        val job = upload(root)
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val failed = failedAttempt(store, job)
            val retry = NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS, previousRunId = failed.runId,
                recovery = WorkflowAttemptRecovery(WorkflowRecoveryMode.RETRY))
            assertCode("INVALID_PREVIOUS_RUN") { store.create(job, store.available(job).snapshot.version, retry) }
            store.createIdempotent(job, store.available(job).snapshot.version, retry, KEY, failed.version)
            val successor = store.available(job).snapshot.attempts.last()
            store.transition(job, successor.runId, successor.version, WorkflowTransition.Start)
            val running = store.available(job).snapshot.attempts.last()
            store.transition(job, running.runId, running.version, WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED))
            // The superseded predecessor and the completed successor both refuse a new linked recovery.
            assertCode("INVALID_PREVIOUS_RUN") { store.createIdempotent(job, store.available(job).snapshot.version, retry, "operator_second_key_1234", failed.version) }
            val completed = store.available(job).snapshot.attempts.last()
            assertCode("INVALID_PREVIOUS_RUN") { store.createIdempotent(job, store.available(job).snapshot.version,
                retry.copy(previousRunId = completed.runId), "operator_third_key_12345", completed.version) }
            assertEquals(2, store.available(job).snapshot.attempts.size)
        }
    }

    @Test
    fun `invalid persisted or constructed recovery provenance is refused`() = withRoot { root ->
        assertFailsWith<IllegalArgumentException> { WorkflowAttemptRecovery(WorkflowRecoveryMode.RETRY, WorkflowResumeRestoration.PROJECT_EVIDENCE, SHA) }
        assertFailsWith<IllegalArgumentException> { WorkflowAttemptRecovery(WorkflowRecoveryMode.RESUME, WorkflowResumeRestoration.PROJECT_EVIDENCE, null) }
        assertFailsWith<IllegalArgumentException> { WorkflowAttemptRecovery(WorkflowRecoveryMode.RESUME, null, SHA) }
        assertFailsWith<IllegalArgumentException> { NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS, recovery = WorkflowAttemptRecovery(WorkflowRecoveryMode.RETRY)) }
        val job = upload(root)
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val failed = failedAttempt(store, job)
            store.createIdempotent(job, store.available(job).snapshot.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS,
                previousRunId = failed.runId, recovery = WorkflowAttemptRecovery(WorkflowRecoveryMode.RETRY)), KEY, failed.version)
        }
        val original = state(root, job).readText()
        for (corrupt in listOf(
            original.replace("\"mode\": \"retry\"", "\"mode\": \"restart\""),
            original.replace("\"restores\": null", "\"restores\": \"agent-session\""),
            original.replace("\"checkpointSha256\": null", "\"checkpointSha256\": \"$SHA\", \"workspace\": \"private\""),
        )) {
            assertNotEquals(original, corrupt)
            state(root, job).writeText(corrupt)
            WorkflowAttemptStore.open(root, CLOCK).use { store ->
                assertTrue(store.inspect(job) is WorkflowJobInspection.Unavailable)
            }
        }
        state(root, job).writeText(original)
        WorkflowAttemptStore.open(root, CLOCK).use { store -> assertTrue(store.inspect(job) is WorkflowJobInspection.Available) }
    }

    private fun failedAttempt(store: WorkflowAttemptStore, job: String): WorkflowAttempt {
        val created = store.create(job, store.available(job).snapshot.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS)).attempt
        val started = store.transition(job, created.runId, created.version, WorkflowTransition.Start).attempt
        return store.transition(job, started.runId, started.version, WorkflowTransition.Finish(WorkflowRunState.FAILED, WorkflowTerminalReason.FAILED)).attempt
    }
    private fun WorkflowAttemptStore.available(job: String) = inspect(job) as WorkflowJobInspection.Available
    private fun upload(root: Path) = JobStore(root).createFromUpload("authored-header.elf", elfFixture()).id
    private fun state(root: Path, job: String) = root.resolve(job).resolve("workflow-state.json")
    private fun assertCode(code: String, operation: () -> Unit) =
        assertEquals(code, assertFailsWith<WorkflowStoreException> { operation() }.code)
    private fun withRoot(operation: (Path) -> Unit) {
        val root = createTempDirectory("workflow-attempt-recovery-")
        try { operation(root) } finally { root.toFile().deleteRecursively() }
    }
    private companion object {
        val CLOCK: Clock = Clock.fixed(Instant.parse("2026-09-05T00:00:00Z"), ZoneOffset.UTC)
        val LIMITS = WorkflowExecutionLimits(60_000uL, 15_000uL, 1_048_576uL, 16uL)
        const val KEY = "operator_recover_request_1234"
        val SHA = "c".repeat(64)
    }
}
