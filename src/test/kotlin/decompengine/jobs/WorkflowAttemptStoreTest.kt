package decompengine.jobs

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
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

class WorkflowAttemptStoreTest {
    @Test
    fun `legacy records remain readable without inventing attempts or changing original bytes`() = withRoot { root ->
        val job = upload(root)
        val original = jobJson(root, job).readBytes()
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val inspected = store.available(job)
            assertEquals("fixture.elf", inspected.legacyJob.displayFilename)
            assertTrue(inspected.snapshot.attempts.isEmpty())
            assertNull(inspected.snapshot.acceptedRevision)
            assertFalse(stateJson(root, job).exists())
            store.recoverAfterRestart(job)
            assertFalse(stateJson(root, job).exists())
            val created = store.create(job, inspected.snapshot.version, NewWorkflowAttempt(WorkflowKind.EXPLORE, LIMITS))
            assertEquals(WorkflowRunState.QUEUED, created.attempt.state)
            assertNull(created.attempt.startedAt)
            assertNull(created.attempt.acceptedRevision)
        }
        assertContentEquals(original, jobJson(root, job).readBytes())
    }

    @Test
    fun `attempt identities workflow inputs and prior terminal outcomes survive retry and reopen`() = withRoot { root ->
        val job = upload(root)
        lateinit var first: WorkflowAttempt
        lateinit var second: WorkflowAttempt
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val queued = store.create(job, store.available(job).snapshot.version,
                NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS, "revision_input", "harness_acp"))
            val running = store.transition(job, queued.attempt.runId, queued.attempt.version, WorkflowTransition.Start)
            val finished = store.transition(job, running.attempt.runId, running.attempt.version,
                WorkflowTransition.Finish(WorkflowRunState.FAILED, WorkflowTerminalReason.LIMIT_EXHAUSTED,
                    WorkflowCandidate("candidate_partial", SHA), WorkflowUsage(inputTokens = ULong.MAX_VALUE)))
            first = finished.attempt
            second = store.create(job, finished.snapshot.version,
                NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS, "revision_input", "harness_acp", first.runId)).attempt
            assertNotEquals(first.runId, second.runId)
            assertEquals(first, store.available(job).snapshot.attempts.first())
            assertFalse(first.publicationPending)
        }
        WorkflowAttemptStore.open(root, CLOCK).use { reopened ->
            val before = reopened.available(job).snapshot
            assertEquals(first, before.attempts.first())
            assertEquals(second, before.attempts.last())
            val recovered = reopened.recoverAfterRestart(job) as WorkflowJobInspection.Available
            assertEquals(first, recovered.snapshot.attempts.first())
            assertEquals(WorkflowRunState.INTERRUPTED, recovered.snapshot.attempts.last().state)
            assertEquals(WorkflowTerminalReason.PROCESS_INTERRUPTED, recovered.snapshot.attempts.last().terminalReason)
            assertNull(recovered.snapshot.acceptedRevision)
        }
    }

    @Test
    fun `completed candidate publication and canonical acceptance remain separate across restart`() = withRoot { root ->
        val job = upload(root)
        lateinit var completed: WorkflowMutation
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            completed = completeCandidate(store, job)
            assertTrue(completed.attempt.publicationPending)
            assertNull(completed.snapshot.acceptedRevision)
        }
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val recovered = store.recoverAfterRestart(job) as WorkflowJobInspection.Available
            assertEquals(completed.snapshot, recovered.snapshot)
            assertTrue(recovered.diagnostics.any { it.code == "PUBLICATION_PENDING" })
            val wrong = acceptance(job, completed.attempt).copy(revisionId = "another_revision")
            assertCode("ACCEPTANCE_BINDING_CONFLICT") { store.recordAcceptedRevision(job, completed.attempt.runId, completed.snapshot.version, completed.attempt.version, wrong) }
            val accepted = store.recordAcceptedRevision(job, completed.attempt.runId, completed.snapshot.version, completed.attempt.version, acceptance(job, completed.attempt))
            assertFalse(accepted.attempt.publicationPending)
            assertEquals(accepted.attempt.acceptedRevision, accepted.snapshot.acceptedRevision)
            val revisionBefore = stateJson(root, job).readBytes()
            store.recoverAfterRestart(job)
            assertContentEquals(revisionBefore, stateJson(root, job).readBytes())
            assertCode("VERSION_CONFLICT") { store.recordAcceptedRevision(job, completed.attempt.runId, completed.snapshot.version, completed.attempt.version, acceptance(job, completed.attempt)) }
            val retry = store.create(job, accepted.snapshot.version, NewWorkflowAttempt(WorkflowKind.VALIDATE, LIMITS, accepted.attempt.candidate!!.revisionId, previousRunId = accepted.attempt.runId))
            assertEquals(accepted.snapshot.acceptedRevision, retry.snapshot.acceptedRevision)
            assertNull(retry.attempt.acceptedRevision)
        }
    }

    @Test
    fun `CAS prevents competing starts and state changes without losing the winner`() = withRoot { root ->
        val job = upload(root)
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val initial = store.available(job).snapshot
            val startResults = race {
                store.create(job, initial.version, NewWorkflowAttempt(WorkflowKind.EXPLORE, LIMITS))
            }
            assertEquals(1, startResults.count { it is WorkflowMutation })
            assertEquals(1, startResults.count { it is WorkflowStoreException && it.code == "VERSION_CONFLICT" })
            val queued = (startResults.single { it is WorkflowMutation } as WorkflowMutation).attempt
            val transitionResults = race { number ->
                store.transition(job, queued.runId, queued.version, if (number == 0) WorkflowTransition.Start else WorkflowTransition.RequestCancellation)
            }
            assertEquals(1, transitionResults.count { it is WorkflowMutation })
            assertEquals(1, transitionResults.count { it is WorkflowStoreException && it.code == "VERSION_CONFLICT" })
            val winner = transitionResults.single { it is WorkflowMutation } as WorkflowMutation
            assertEquals(winner.attempt, store.available(job).snapshot.latestRun)
            assertEquals(1, store.available(job).snapshot.attempts.size)
        }
    }

    @Test
    fun `transition guards reject terminal rewrites wrong jobs and unstarted completion`() = withRoot { root ->
        val job = upload(root)
        val another = upload(root)
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val queued = store.create(job, store.available(job).snapshot.version, NewWorkflowAttempt(WorkflowKind.EXPLORE, LIMITS))
            assertCode("RUN_NOT_FOUND") { store.transition(another, queued.attempt.runId, queued.attempt.version, WorkflowTransition.Start) }
            assertCode("INVALID_TRANSITION") { store.transition(job, queued.attempt.runId, queued.attempt.version, WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED)) }
            val cancelling = store.transition(job, queued.attempt.runId, queued.attempt.version, WorkflowTransition.RequestCancellation)
            assertCode("INVALID_TRANSITION") { store.transition(job, cancelling.attempt.runId, cancelling.attempt.version, WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED)) }
            val cancelled = store.transition(job, cancelling.attempt.runId, cancelling.attempt.version, WorkflowTransition.Finish(WorkflowRunState.CANCELLED, WorkflowTerminalReason.CANCELLED))
            assertNull(cancelled.attempt.startedAt)
            assertNotNull(cancelled.attempt.endedAt)
            assertCode("INVALID_TRANSITION") { store.transition(job, cancelled.attempt.runId, cancelled.attempt.version, WorkflowTransition.Start) }
            assertCode("INVALID_PREVIOUS_RUN") { store.create(another, store.available(another).snapshot.version, NewWorkflowAttempt(WorkflowKind.EXPLORE, LIMITS, previousRunId = cancelled.attempt.runId)) }
        }
    }

    @Test
    fun `legacy active records are interrupted without fabricating workflow type or run identity`() = withRoot { root ->
        val job = upload(root)
        JobStore(root).updateStatus(job, "analyzing", "synthetic historical operation")
        val original = jobJson(root, job).readBytes()
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val originalSnapshot = store.available(job).snapshot
            assertCode("RECOVERY_REQUIRED") { store.create(job, originalSnapshot.version, NewWorkflowAttempt(WorkflowKind.EXPLORE, LIMITS)) }
            val recovered = store.recoverAfterRestart(job) as WorkflowJobInspection.Available
            assertTrue(recovered.snapshot.legacy.recoveredInterrupted)
            assertTrue(recovered.snapshot.attempts.isEmpty())
            assertTrue(recovered.diagnostics.any { it.code == "LEGACY_INTERRUPTED" })
            assertNull(recovered.snapshot.acceptedRevision)
            store.create(job, recovered.snapshot.version, NewWorkflowAttempt(WorkflowKind.EXPLORE, LIMITS))
        }
        assertContentEquals(original, jobJson(root, job).readBytes())
    }

    @Test
    fun `malformed legacy and workflow records stay isolated and keep their original bytes`() = withRoot { root ->
        val valid = upload(root)
        val badLegacy = upload(root)
        val badWorkflow = upload(root)
        val unknownSchema = upload(root)
        jobJson(root, badLegacy).writeText("{\"id\":\"$badLegacy\",\"id\":\"duplicate\"}")
        stateJson(root, badWorkflow).writeText("{\"schemaVersion\":1,")
        stateJson(root, unknownSchema).writeText("{\"schemaVersion\":42}")
        val originals = listOf(jobJson(root, badLegacy), stateJson(root, badWorkflow), stateJson(root, unknownSchema)).associateWith(Path::readBytes)
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val report = store.recoverAll()
            assertEquals(4, report.size)
            assertTrue(report.single { it.jobId == valid } is WorkflowJobInspection.Available)
            assertEquals("CORRUPT_LEGACY_JOB", (report.single { it.jobId == badLegacy } as WorkflowJobInspection.Unavailable).diagnostic.code)
            assertEquals("CORRUPT_WORKFLOW_STATE", (report.single { it.jobId == badWorkflow } as WorkflowJobInspection.Unavailable).diagnostic.code)
            assertEquals("UNSUPPORTED_WORKFLOW_SCHEMA", (report.single { it.jobId == unknownSchema } as WorkflowJobInspection.Unavailable).diagnostic.code)
        }
        originals.forEach { (path, bytes) -> assertContentEquals(bytes, path.readBytes()) }
    }

    @Test
    fun `corrupt accepted pointer cannot detach accepted history or silently confer acceptance`() = withRoot { root ->
        val job = upload(root)
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            val complete = completeCandidate(store, job)
            store.recordAcceptedRevision(job, complete.attempt.runId, complete.snapshot.version, complete.attempt.version, acceptance(job, complete.attempt))
        }
        val parsed = Json.parseToJsonElement(stateJson(root, job).readText()).jsonObject
        stateJson(root, job).writeText(JsonObject(parsed + ("acceptedRevision" to kotlinx.serialization.json.JsonNull)).toString())
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            assertEquals("CORRUPT_WORKFLOW_STATE", (store.inspect(job) as WorkflowJobInspection.Unavailable).diagnostic.code)
        }
    }

    @Test
    fun `ownership lease excludes another server and releases only on close`() = withRoot { root ->
        upload(root)
        val owner = WorkflowAttemptStore.open(root, CLOCK)
        assertCode("OWNERSHIP_CONFLICT") { WorkflowAttemptStore.open(root, CLOCK) }
        val process = ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-cp", System.getProperty("java.class.path"),
            WorkflowAttemptStoreLockProbe::class.java.name, root.toString(),
        ).redirectErrorStream(true).start()
        try {
            assertTrue(process.waitFor(10, TimeUnit.SECONDS))
            assertEquals(0, process.exitValue(), process.inputStream.readBytes().decodeToString())
        } finally { process.destroyForcibly(); owner.close() }
        WorkflowAttemptStore.open(root, CLOCK).use { reopened -> assertTrue(reopened.recoverAll().isNotEmpty()) }
        assertCode("STORE_CLOSED") { owner.recoverAll() }
    }

    @Test
    fun `crashes at every persistence boundary retain a complete old or new state and prior acceptance`() {
        WorkflowStoreFaultPoint.entries.forEach { point -> withRoot { root ->
            val job = upload(root)
            lateinit var accepted: WorkflowMutation
            WorkflowAttemptStore.open(root, CLOCK).use { store ->
                val complete = completeCandidate(store, job)
                accepted = store.recordAcceptedRevision(job, complete.attempt.runId, complete.snapshot.version, complete.attempt.version, acceptance(job, complete.attempt))
            }
            val original = jobJson(root, job).readBytes()
            WorkflowAttemptStore.open(root, CLOCK, WorkflowStoreFaultInjector { if (it == point) throw SimulatedCrash() }).use { store ->
                assertFailsWith<SimulatedCrash> { store.create(job, accepted.snapshot.version, NewWorkflowAttempt(WorkflowKind.VALIDATE, LIMITS)) }
                assertCode("RECOVERY_REQUIRED") { store.inspect(job) }
            }
            WorkflowAttemptStore.open(root, CLOCK).use { reopened ->
                val before = reopened.available(job).snapshot
                val published = point in setOf(WorkflowStoreFaultPoint.AFTER_RENAME, WorkflowStoreFaultPoint.AFTER_DIRECTORY_FSYNC)
                assertEquals(if (published) 2 else 1, before.attempts.size)
                assertEquals(accepted.attempt, before.attempts.first())
                assertEquals(accepted.snapshot.acceptedRevision, before.acceptedRevision)
                val recovered = reopened.recoverAfterRestart(job) as WorkflowJobInspection.Available
                assertTrue(recovered.snapshot.attempts.all { it.state.terminal })
                assertEquals(accepted.snapshot.acceptedRevision, recovered.snapshot.acceptedRevision)
                assertFalse(root.resolve(job).resolve("workflow-state.pending.json").exists())
            }
            assertContentEquals(original, jobJson(root, job).readBytes())
        } }
    }

    @Test
    fun `ordinary precommit failure preserves state postcommit failure returns success and uncertain rename requires reopen`() = withRoot { root ->
        val job = upload(root)
        lateinit var initial: WorkflowJobSnapshot
        WorkflowAttemptStore.open(root, CLOCK).use { initial = it.available(job).snapshot }
        WorkflowAttemptStore.open(root, CLOCK, WorkflowStoreFaultInjector { if (it == WorkflowStoreFaultPoint.AFTER_TEMP_FSYNC) throw IOException("synthetic failure") }).use { store ->
            val failure = assertCode("PERSISTENCE_FAILED") { store.create(job, initial.version, NewWorkflowAttempt(WorkflowKind.EXPLORE, LIMITS)) }
            assertFalse(failure.outcomeUnknown)
            assertEquals(initial, store.available(job).snapshot)
        }
        WorkflowAttemptStore.open(root, CLOCK, WorkflowStoreFaultInjector { if (it == WorkflowStoreFaultPoint.BEFORE_RENAME) throw IOException("synthetic rename failure") }).use { store ->
            val failure = assertCode("PERSISTENCE_FAILED") { store.create(job, initial.version, NewWorkflowAttempt(WorkflowKind.EXPLORE, LIMITS)) }
            assertTrue(failure.outcomeUnknown)
            assertCode("RECOVERY_REQUIRED") { store.inspect(job) }
            assertTrue(root.resolve(job).resolve("workflow-state.pending.json").exists())
        }
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            assertEquals(initial, store.available(job).snapshot)
            val recovered = store.recoverAfterRestart(job) as WorkflowJobInspection.Available
            assertEquals(initial, recovered.snapshot)
            assertFalse(root.resolve(job).resolve("workflow-state.pending.json").exists())
        }
        WorkflowAttemptStore.open(root, CLOCK, WorkflowStoreFaultInjector { if (it == WorkflowStoreFaultPoint.AFTER_RENAME) throw IOException("synthetic failure") }).use { store ->
            val failure = assertCode("PERSISTENCE_FAILED") { store.create(job, initial.version, NewWorkflowAttempt(WorkflowKind.EXPLORE, LIMITS)) }
            assertTrue(failure.outcomeUnknown)
            assertCode("RECOVERY_REQUIRED") { store.inspect(job) }
        }
        WorkflowAttemptStore.open(root, CLOCK).use { store -> store.recoverAfterRestart(job) }
        WorkflowAttemptStore.open(root, CLOCK, WorkflowStoreFaultInjector { if (it == WorkflowStoreFaultPoint.AFTER_DIRECTORY_FSYNC) throw IOException("synthetic postcommit failure") }).use { store ->
            val next = store.create(job, store.available(job).snapshot.version, NewWorkflowAttempt(WorkflowKind.EXPLORE, LIMITS))
            assertEquals(next.snapshot, store.available(job).snapshot)
        }
    }

    @Test
    fun `deep malformed records and reserved nonregular entries fail without following upload paths`() = withRoot { root ->
        val job = upload(root)
        stateJson(root, job).writeText("[".repeat(40) + "0" + "]".repeat(40))
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            assertTrue(store.inspect(job) is WorkflowJobInspection.Unavailable)
        }
        Files.delete(stateJson(root, job))
        Files.createDirectory(stateJson(root, job))
        WorkflowAttemptStore.open(root, CLOCK).use { store ->
            assertEquals("INVALID_STORAGE_ENTRY", (store.inspect(job) as WorkflowJobInspection.Unavailable).diagnostic.code)
        }
    }

    private fun completeCandidate(store: WorkflowAttemptStore, job: String): WorkflowMutation {
        val queued = store.create(job, store.available(job).snapshot.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS))
        val running = store.transition(job, queued.attempt.runId, queued.attempt.version, WorkflowTransition.Start)
        return store.transition(job, running.attempt.runId, running.attempt.version,
            WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED, WorkflowCandidate("revision_candidate", SHA)))
    }
    private fun acceptance(job: String, attempt: WorkflowAttempt): WorkflowAcceptanceReference =
        WorkflowAcceptanceReference(job, attempt.runId, attempt.candidate!!.revisionId, SHA, "graph_node", "acceptance_artifact", "cd".repeat(32))
    private fun WorkflowAttemptStore.available(job: String): WorkflowJobInspection.Available = inspect(job) as WorkflowJobInspection.Available
    private fun upload(root: Path): String = JobStore(root).createFromUpload("fixture.elf", elfFixture()).id
    private fun jobJson(root: Path, job: String): Path = root.resolve(job).resolve("job.json")
    private fun stateJson(root: Path, job: String): Path = root.resolve(job).resolve("workflow-state.json")
    private fun withRoot(action: (Path) -> Unit) {
        val root = createTempDirectory("workflow-store-")
        try { action(root) } finally { root.toFile().deleteRecursively() }
    }
    private fun assertCode(code: String, action: () -> Unit): WorkflowStoreException = assertFailsWith<WorkflowStoreException>(block = action).also { assertEquals(code, it.code) }
    private fun race(action: (Int) -> WorkflowMutation): List<Any> {
        val begin = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        try {
            val futures = (0..1).map { number -> executor.submit<Any> {
                check(begin.await(5, TimeUnit.SECONDS))
                try { action(number) } catch (failure: WorkflowStoreException) { failure }
            } }
            begin.countDown()
            return futures.map { it.get(10, TimeUnit.SECONDS) }
        } finally { executor.shutdownNow() }
    }
    private class SimulatedCrash : Error("synthetic process termination")
    private companion object {
        val CLOCK: Clock = Clock.fixed(Instant.parse("2026-09-05T00:00:00Z"), ZoneOffset.UTC)
        val LIMITS = WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u)
        val SHA = "ab".repeat(32)
    }
}

/** Separate JVM test probe; it never starts execution or mutates job state. */
object WorkflowAttemptStoreLockProbe {
    @JvmStatic fun main(args: Array<String>) {
        try {
            WorkflowAttemptStore.open(Path.of(args.single())).use { error("storage ownership was unexpectedly acquired") }
        } catch (failure: WorkflowStoreException) {
            check(failure.code == "OWNERSHIP_CONFLICT")
        }
    }
}
