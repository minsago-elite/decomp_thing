package decompengine.jobs

import decompengine.agent.*
import kotlinx.serialization.json.*
import java.nio.file.Files
import kotlin.io.path.createTempDirectory
import kotlin.io.path.fileSize
import kotlin.test.*

class AgentProgressJournalTest {
    @Test
    fun `messages redact split secrets and completion remains distinct from acceptance`() {
        val root = createTempDirectory("progress-test")
        val request = request(root)
        AgentProgressJournal(root, "reconstruction", listOf("private-credential"), maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("module-1", request)
            task.event(AgentMessageEvent(0, "peer-session-secret", AgentMessageRole.ASSISTANT, "hello private-"))
            task.event(AgentMessageEvent(1, "peer-session-secret", AgentMessageRole.ASSISTANT, "credential done", true))
            task.complete(AgentExecutionReceipt(AgentExecutionRequestBinding.capture(request), AgentExecutionOutcome.Returned(
                AgentExecutionResult(AgentStopReason.COMPLETED, session = AgentSessionReference("acp", "peer-session-secret")),
            )))
            journal.phase(AgentWorkflowPhase.BUILD_VALIDATING, "module-1")
        }
        val snapshot = AgentProgressJournal.read(root)!!
        val text = snapshot.toString()
        assertFalse(text.contains("private-"))
        assertFalse(text.contains("credential"))
        assertFalse(text.contains("peer-session-secret"))
        assertTrue(text.contains("hello [redacted] done"))
        assertTrue(text.contains("sessionIdSha256"))
        assertTrue(text.contains("\"validationPending\":true"))
        assertFalse(text.contains("acceptedRevisionSha256"))
        val events = snapshot.getValue("events").jsonArray
        assertEquals("build_validating", events.last().jsonObject["phase"]!!.jsonPrimitive.content)
        assertEquals(events.indices.map { it.toLong() }, events.map { it.jsonObject["sequence"]!!.jsonPrimitive.long })
    }

    @Test
    fun `restart retains events and allocates a new run without repeating sequence numbers`() {
        val root = createTempDirectory("progress-test")
        AgentProgressJournal(root, "repair").use { it.phase(AgentWorkflowPhase.BEHAVIOR_VALIDATING) }
        val previous = AgentProgressJournal.read(root)!!
        AgentProgressJournal(root, "repair").use { it.phase(AgentWorkflowPhase.ROLLED_BACK) }
        val current = AgentProgressJournal.read(root)!!
        val events = current.getValue("events").jsonArray
        assertEquals(previous.getValue("events").jsonArray, JsonArray(events.take(2)))
        assertEquals(2, events.map { it.jsonObject.getValue("runId").jsonPrimitive.content }.distinct().size)
        assertEquals(4, current.getValue("nextSequence").jsonPrimitive.int)
    }

    @Test
    fun `noisy stream remains bounded and records exact omission counts`() {
        val root = createTempDirectory("progress-test")
        AgentProgressJournal(root, "repair", maximumEvents = 8, maximumQueuedEvents = 2, maximumSnapshotBytes = 4096).use { journal ->
            repeat(2_000) { journal.phase(AgentWorkflowPhase.AGENT_RUNNING, "task-$it") }
        }
        val snapshot = AgentProgressJournal.read(root)!!
        val next = snapshot.getValue("nextSequence").jsonPrimitive.long
        val dropped = snapshot.getValue("queueDropped").jsonPrimitive.long + snapshot.getValue("historyDropped").jsonPrimitive.long
        assertEquals(2_001, next)
        assertEquals(next, dropped + snapshot.getValue("events").jsonArray.size)
        assertTrue(snapshot.getValue("truncated").jsonPrimitive.boolean)
        assertTrue(root.resolve(AgentProgressJournal.FILE_NAME).fileSize() <= 4096)
    }

    @Test
    fun `concurrent tasks retain invocation identity and failures carry no exception text`() {
        val root = createTempDirectory("progress-test")
        val request = request(root)
        AgentProgressJournal(root, "repair", maximumQueuedEvents = 1024).use { journal ->
            val workers = (1..8).map { n -> Thread {
                val task = journal.beginTask("task-$n", request)
                task.event(AgentToolEvent(0, "tool-$n", "compile", AgentToolStatus.SUCCEEDED))
                task.complete(AgentExecutionReceipt(AgentExecutionRequestBinding.capture(request), AgentExecutionOutcome.Failed(
                    AgentFailure(AgentFailureKind.PROCESS_CRASH, "sensitive exception content"),
                )))
            }.apply { start() } }
            workers.forEach { it.join() }
        }
        val snapshot = AgentProgressJournal.read(root)!!
        val events = snapshot["events"]!!.jsonArray.map { it.jsonObject }
        assertEquals(8, events.mapNotNull { it["turnId"]?.jsonPrimitive?.content }.distinct().size)
        assertEquals(8, events.count { it["failureKind"]?.jsonPrimitive?.content == "process_crash" })
        assertFalse(snapshot.toString().contains("sensitive exception"))
        assertEquals(25, events.size)
    }

    @Test
    fun `oversized messages omit the entire preview and cannot publish partial secrets`() {
        val root = createTempDirectory("progress-test")
        AgentProgressJournal(root, "repair", maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("task", request(root))
            task.event(AgentMessageEvent(0, "id", AgentMessageRole.ASSISTANT, "x".repeat(9_000), true))
        }
        val event = AgentProgressJournal.read(root)!!["events"]!!.jsonArray.last().jsonObject
        assertTrue(event["textOmitted"]!!.jsonPrimitive.boolean)
        assertNull(event["text"])
    }

    @Test
    fun `second writer is rejected and oversized persisted data fails bounded read`() {
        val root = createTempDirectory("progress-test")
        AgentProgressJournal(root, "repair").use {
            assertFails { AgentProgressJournal(root, "repair") }
        }
        Files.write(root.resolve(AgentProgressJournal.FILE_NAME), ByteArray(2 * 1024 * 1024 + 1))
        assertFailsWith<IllegalArgumentException> { AgentProgressJournal.read(root) }
    }

    @Test
    fun `redactor handles credential fields and removes terminal control codes`() {
        val redactor = ProgressRedactor(listOf("abc123"))
        assertEquals("api_key=[redacted] Bearer [redacted] [redacted]", redactor.text("api_key=some-value Bearer token-value abc123"))
        assertFalse(redactor.text("\u001b[31mhello").contains('\u001b'))
    }

    private fun request(root: java.nio.file.Path) = AgentExecutionRequest(
        "fixture task", listOf(AgentWorkspaceRoot("project", root.toAbsolutePath().normalize())),
        accessPolicy = AgentAccessPolicy(emptyList()),
    )
}
