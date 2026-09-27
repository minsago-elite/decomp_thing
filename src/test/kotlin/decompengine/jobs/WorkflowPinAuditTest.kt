package decompengine.jobs

import kotlinx.serialization.json.*
import java.nio.file.Path
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.io.path.*
import kotlin.test.*

class WorkflowPinAuditTest {
    private val clock = Clock.fixed(Instant.parse("2026-09-08T00:00:00Z"), ZoneOffset.UTC)
    private val request = NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))

    @Test fun `applied pin receipt is attributed versioned and preserved through lifecycle and restart`() = fixture { root, job ->
        val sessionId = "a".repeat(64)
        val actor = WorkflowPinActor.browserSession(sessionId)
        lateinit var receipt: WorkflowPinAuditEntry
        WorkflowAttemptStore.open(root, clock).use { store ->
            val queued = store.create(job, store.snapshot(job).version, request).attempt
            val pinned = store.setProgressRetentionPinned(job, queued.runId, queued.version, true, actor)
            receipt = pinned.snapshot.pinAudit.entries.single()
            assertEquals(0uL, receipt.sequence); assertEquals(clock.instant(), receipt.at)
            assertEquals(actor, receipt.actor); assertNotEquals(sessionId, receipt.actor.sessionDigest)
            assertEquals(queued.runId, receipt.runId); assertTrue(receipt.pinned)
            assertEquals(queued.version, receipt.previousVersion); assertEquals(pinned.attempt.version, receipt.appliedVersion)
            assertFalse(root.resolve("$job/workflow-state.json").readText().contains(sessionId))
            val bytes = root.resolve("$job/workflow-state.json").readBytes()
            store.setProgressRetentionPinned(job, queued.runId, pinned.attempt.version, true, actor)
            assertContentEquals(bytes, root.resolve("$job/workflow-state.json").readBytes())
            assertEquals("VERSION_CONFLICT", assertFailsWith<WorkflowStoreException> {
                store.setProgressRetentionPinned(job, queued.runId, queued.version, false, actor)
            }.code)
            assertContentEquals(bytes, root.resolve("$job/workflow-state.json").readBytes())
            store.transition(job, queued.runId, pinned.attempt.version, WorkflowTransition.Start)
        }
        WorkflowAttemptStore.open(root, clock).use { store ->
            store.recoverAfterRestart(job)
            assertEquals(receipt, store.snapshot(job).pinAudit.entries.single())
            val run = store.snapshot(job).latestRun!!
            val unpinned = store.setProgressRetentionPinned(job, run.runId, run.version, false)
            assertEquals(WorkflowPinActor.INTERNAL, unpinned.snapshot.pinAudit.entries.last().actor)
            assertFalse(unpinned.snapshot.pinAudit.entries.last().pinned)
            assertEquals(1uL, unpinned.snapshot.pinAudit.entries.last().sequence)
        }
    }

    @Test fun `receipt history bounds records and explicitly counts omitted prefix`() = fixture { root, job ->
        WorkflowAttemptStore.open(root, clock).use { store ->
            var run = store.create(job, store.snapshot(job).version, request).attempt
            repeat(WorkflowPinAudit.MAX_ENTRIES + 3) {
                run = store.setProgressRetentionPinned(job, run.runId, run.version, !run.progressRetentionPinned).attempt
            }
            val audit = store.snapshot(job).pinAudit
            assertEquals(3uL, audit.omitted); assertEquals(256, audit.entries.size)
            assertEquals((3uL..258uL).toList(), audit.entries.map { it.sequence })
            assertFailsWith<UnsupportedOperationException> { (audit.entries as MutableList).clear() }
        }
        WorkflowAttemptStore.open(root, clock).use { store ->
            assertEquals(3uL, store.snapshot(job).pinAudit.omitted)
            assertEquals(256, store.snapshot(job).pinAudit.entries.size)
        }
    }

    @Test fun `pin and applied receipt converge together across each publication interruption`() {
        WorkflowStoreFaultPoint.entries.forEach { point -> fixture { root, job ->
            lateinit var run: WorkflowAttempt
            WorkflowAttemptStore.open(root, clock).use { store -> run = store.create(job, store.snapshot(job).version, request).attempt }
            WorkflowAttemptStore.open(root, clock, WorkflowStoreFaultInjector { if (it == point) throw SimulatedStop() }).use { store ->
                assertFailsWith<SimulatedStop> { store.setProgressRetentionPinned(job, run.runId, run.version, true) }
            }
            WorkflowAttemptStore.open(root, clock).use { store ->
                store.recoverAfterRestart(job)
                val snapshot = store.snapshot(job)
                assertEquals(snapshot.latestRun!!.progressRetentionPinned, snapshot.pinAudit.entries.isNotEmpty(), point.name)
                snapshot.pinAudit.entries.singleOrNull()?.let { assertEquals(run.version, it.previousVersion) }
            }
        } }
    }

    @Test fun `invalid audit metadata is preserved and rejected instead of losing attribution`() = fixture { root, job ->
        WorkflowAttemptStore.open(root, clock).use { store ->
            val run = store.create(job, store.snapshot(job).version, request).attempt
            store.setProgressRetentionPinned(job, run.runId, run.version, true)
        }
        val path = root.resolve("$job/workflow-state.json")
        val original = Json.parseToJsonElement(path.readText()).jsonObject
        val audit = original.getValue("pinAudit").jsonObject
        val entry = audit.getValue("entries").jsonArray.single().jsonObject
        val badEntries = listOf(
            JsonObject(entry + ("sequence" to JsonPrimitive("1"))),
            JsonObject(entry + ("outcome" to JsonPrimitive("secret canary /private/path"))),
            JsonObject(entry + ("runId" to JsonPrimitive("foreign_run"))),
            JsonObject(entry + ("action" to JsonPrimitive("progress.unpin"))),
            JsonObject(entry + ("actor" to buildJsonObject { put("kind", "internal"); put("sessionDigest", "a".repeat(64)) })),
            JsonObject(entry + ("at" to JsonPrimitive("2026-09-08T00:00:00+00:00"))),
        )
        val badAudits = listOf(JsonNull, JsonPrimitive(false), JsonObject(audit + ("omitted" to JsonPrimitive("1")))) +
            badEntries.map { JsonObject(audit + ("entries" to JsonArray(listOf(it)))) }
        badAudits.forEach { bad ->
            val text = JsonObject(original + ("pinAudit" to bad)).toString(); path.writeText(text)
            WorkflowAttemptStore.open(root, clock).use { store ->
                val unavailable = assertIs<WorkflowJobInspection.Unavailable>(store.inspect(job))
                assertEquals("CORRUPT_WORKFLOW_STATE", unavailable.diagnostic.code)
                assertFalse(unavailable.diagnostic.message.contains("secret canary"))
            }
            assertEquals(text, path.readText())
        }
        path.writeText(JsonObject(original - "pinAudit").toString())
        val legacyBytes = path.readBytes()
        WorkflowAttemptStore.open(root, clock).use { store -> assertTrue(store.snapshot(job).pinAudit.entries.isEmpty()) }
        assertContentEquals(legacyBytes, path.readBytes())
    }

    private class SimulatedStop : Error()
    private fun WorkflowAttemptStore.snapshot(job: String) = assertIs<WorkflowJobInspection.Available>(inspect(job)).snapshot
    private fun fixture(action: (Path, String) -> Unit) {
        val root = createTempDirectory("workflow-pin-audit-")
        try { action(root, JobStore(root).createFromUpload("inert.elf", elfFixture()).id) }
        finally { root.toFile().deleteRecursively() }
    }
}
