package decompengine.jobs

import decompengine.agent.*
import kotlinx.serialization.json.*
import java.nio.file.Files
import kotlin.io.path.createTempDirectory
import kotlin.io.path.fileSize
import kotlin.test.*

class AgentProgressJournalTest {
    @Test
    fun `omission ranges preserve prefix interior and trailing gaps across legacy restart`() {
        val root = createTempDirectory("progress-ranges-")
        val legacy = buildJsonObject {
            put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", 7)
            put("queueDropped", 3); put("historyDropped", 2); put("truncated", true)
            put("events", buildJsonArray {
                for (sequence in listOf(2, 4)) add(buildJsonObject { put("sequence", sequence) })
            })
        }
        Files.writeString(root.resolve(AgentProgressJournal.FILE_NAME), legacy.toString())
        AgentProgressJournal(root, "repair").use { }
        val snapshot = AgentProgressJournal.read(root)!!
        val ranges = snapshot.getValue("omittedSequenceRanges").jsonArray
        assertEquals(listOf("0" to "2", "3" to "4", "5" to "7"), ranges.map {
            it.jsonObject.getValue("startInclusive").jsonPrimitive.content to
                it.jsonObject.getValue("endExclusive").jsonPrimitive.content
        })
        val corrupted = JsonObject(snapshot + ("omittedSequenceRanges" to JsonArray(emptyList())))
        Files.writeString(root.resolve(AgentProgressJournal.FILE_NAME), corrupted.toString())
        assertFailsWith<IllegalArgumentException> { AgentProgressJournal.read(root) }
    }

    @Test
    fun `persisted history rejects unexplained loss and inconsistent omission counters`() {
        val root = createTempDirectory("progress-loss-")
        AgentProgressJournal(root, "repair").use { it.phase(AgentWorkflowPhase.AGENT_RUNNING) }
        val original = AgentProgressJournal.read(root)!!
        val corruptions = listOf(
            mapOf("events" to JsonArray(original.getValue("events").jsonArray.take(1)),
                "historyDropped" to JsonPrimitive(1), "truncated" to JsonPrimitive(true)),
            mapOf("events" to JsonArray(original.getValue("events").jsonArray.drop(1))),
            mapOf("queueDropped" to JsonPrimitive(1)),
            mapOf("queueDropped" to JsonPrimitive(Long.MAX_VALUE), "historyDropped" to JsonPrimitive(Long.MAX_VALUE)),
            mapOf("truncated" to JsonPrimitive(true)),
            mapOf("events" to JsonArray(emptyList()), "queueDropped" to JsonPrimitive(2), "truncated" to JsonPrimitive(false)),
        )
        corruptions.forEach { changes ->
            val malformed = JsonObject(original + changes).toString()
            Files.writeString(root.resolve(AgentProgressJournal.FILE_NAME), malformed)
            assertFailsWith<IllegalArgumentException> { AgentProgressJournal.read(root) }
            assertFailsWith<IllegalArgumentException> { AgentProgressJournal(root, "repair") }
            assertEquals(malformed, Files.readString(root.resolve(AgentProgressJournal.FILE_NAME)))
        }
        // Failed restart validation releases ownership and never overwrites the rejected history.
        Files.writeString(root.resolve(AgentProgressJournal.FILE_NAME), original.toString())
        AgentProgressJournal(root, "repair").use { it.phase(AgentWorkflowPhase.ROLLED_BACK) }
        assertEquals(4, AgentProgressJournal.read(root)!!.getValue("nextSequence").jsonPrimitive.int)
    }

    @Test
    fun `history eviction precedes retained events while queue loss may follow them`() {
        val root = createTempDirectory("progress-prefix-")
        AgentProgressJournal(root, "repair").use { it.phase(AgentWorkflowPhase.AGENT_RUNNING) }
        val original = AgentProgressJournal.read(root)!!
        val events = original.getValue("events").jsonArray
        assertEquals(2, events.size)
        listOf(
            mapOf("events" to JsonArray(events.takeLast(1)), "historyDropped" to JsonPrimitive(1)),
            mapOf("events" to JsonArray(events.take(1)), "queueDropped" to JsonPrimitive(1)),
            mapOf("events" to JsonArray(emptyList()), "historyDropped" to JsonPrimitive(2)),
        ).forEach { changes ->
            val valid = JsonObject(original + changes + ("truncated" to JsonPrimitive(true)))
            Files.writeString(root.resolve(AgentProgressJournal.FILE_NAME), valid.toString())
            assertEquals(valid, AgentProgressJournal.read(root))
        }
    }

    @Test
    fun `completion preserves available usage including zero cache and exact elapsed duration`() {
        val root = createTempDirectory("progress-usage-")
        val request = request(root)
        AgentProgressJournal(root, "repair").use { journal ->
            journal.beginTask("with-usage", request).complete(AgentExecutionReceipt(
                AgentExecutionRequestBinding.capture(request), AgentExecutionOutcome.Returned(
                    AgentExecutionResult(AgentStopReason.NO_CHANGES, usage = AgentUsage(
                        inputTokens = 12, outputTokens = 3, cachedInputTokens = 0, toolCalls = 2,
                        wallClock = java.time.Duration.ofSeconds(4, 123456789))))))
            journal.beginTask("without-usage", request).complete(AgentExecutionReceipt(
                AgentExecutionRequestBinding.capture(request), AgentExecutionOutcome.Returned(
                    AgentExecutionResult(AgentStopReason.NO_CHANGES))))
        }
        val finished = AgentProgressJournal.read(root)!!.getValue("events").jsonArray.map { it.jsonObject }.filter {
            it["kind"]?.jsonPrimitive?.content == "agent_finished"
        }
        assertEquals(12L, finished[0].getValue("inputTokens").jsonPrimitive.long)
        assertEquals(3L, finished[0].getValue("outputTokens").jsonPrimitive.long)
        assertEquals(0L, finished[0].getValue("cachedInputTokens").jsonPrimitive.long)
        assertEquals(2, finished[0].getValue("toolCalls").jsonPrimitive.int)
        assertEquals("PT4.123456789S", finished[0].getValue("wallClock").jsonPrimitive.content)
        listOf("inputTokens", "outputTokens", "cachedInputTokens", "toolCalls", "wallClock").forEach {
            assertFalse(it in finished[1])
        }
        assertTrue(finished.all { it.getValue("validationPending").jsonPrimitive.boolean })
    }

    @Test
    fun `source sequence loss suppresses incomplete message previews`() {
        val root = createTempDirectory("progress-message-loss-")
        AgentProgressJournal(root, "reconstruction", listOf("private-credential"), maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("module", request(root))
            task.event(AgentMessageEvent(0, "tracked", AgentMessageRole.ASSISTANT, "private-"))
            task.event(AgentMessageEvent(2, "tracked", AgentMessageRole.ASSISTANT, " tail", true))
            task.event(AgentMessageEvent(3, "unseen", AgentMessageRole.ASSISTANT, "credential", true))
        }
        val snapshot = AgentProgressJournal.read(root)!!
        assertFalse(snapshot.toString().contains("private-"))
        assertFalse(snapshot.toString().contains("credential"))
        val completed = snapshot.getValue("events").jsonArray.map { it.jsonObject }.filter {
            it["completed"]?.jsonPrimitive?.booleanOrNull == true
        }
        assertEquals(2, completed.size)
        assertTrue(completed.first().getValue("sourceSequenceGap").jsonPrimitive.boolean)
        completed.forEach {
            assertTrue(it.getValue("textOmitted").jsonPrimitive.boolean)
            assertFalse("text" in it)
        }
    }

    @Test
    fun `message tracking overflow never admits a continuation after capacity is released`() {
        val root = createTempDirectory("progress-message-overflow-")
        AgentProgressJournal(root, "reconstruction", listOf("private-credential"), maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("module", request(root))
            repeat(16) { index ->
                task.event(AgentMessageEvent(index.toLong(), "tracked-$index", AgentMessageRole.ASSISTANT, "safe"))
            }
            task.event(AgentMessageEvent(16, "omitted", AgentMessageRole.ASSISTANT, "private-"))
            task.event(AgentMessageEvent(17, "tracked-0", AgentMessageRole.ASSISTANT, " complete", true))
            task.event(AgentMessageEvent(18, "omitted", AgentMessageRole.ASSISTANT, "credential", true))
            task.event(AgentMessageEvent(19, "later", AgentMessageRole.ASSISTANT, "new message", true))
        }
        val snapshot = AgentProgressJournal.read(root)!!
        assertFalse(snapshot.toString().contains("credential"))
        assertFalse(snapshot.toString().contains("private-"))
        val messages = snapshot.getValue("events").jsonArray.map { it.jsonObject }.filter {
            it["kind"]?.jsonPrimitive?.content == "message"
        }
        assertEquals("safe complete", messages[17].getValue("text").jsonPrimitive.content)
        messages.takeLast(2).forEach {
            assertTrue(it.getValue("textOmitted").jsonPrimitive.boolean)
            assertTrue(it.getValue("messageTrackingExhausted").jsonPrimitive.boolean)
            assertFalse("text" in it)
        }
        AgentProgressJournal(root, "reconstruction").use { journal ->
            journal.beginTask("next-task", request(root)).event(
                AgentMessageEvent(0, "new", AgentMessageRole.ASSISTANT, "next task is unaffected", true))
        }
        assertTrue(AgentProgressJournal.read(root).toString().contains("next task is unaffected"))
    }

    @Test
    fun `durable run and revision correlation survives writer restart without promoting provisional state`() {
        val root = createTempDirectory("progress-run-test")
        val request = request(root)
        AgentProgressJournal(root, "repair", listOf("private-run"), maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("attempt-1", request, "private-run")
            task.event(AgentPlanEvent(0, listOf(AgentPlanEntry("step-1", "continue repair", AgentPlanStatus.IN_PROGRESS))))
            task.complete(AgentExecutionReceipt(AgentExecutionRequestBinding.capture(request), AgentExecutionOutcome.Returned(
                AgentExecutionResult(AgentStopReason.COMPLETED))))
            journal.runState(AgentWorkflowRunObservation("private-run", AgentWorkflowPhase.PROVISIONAL, "revision-1", "attempt-1"))
            journal.runState(AgentWorkflowRunObservation("private-run", AgentWorkflowPhase.EXHAUSTED, "revision-1"))
        }
        val before = AgentProgressJournal.read(root)!!
        assertFalse(before.toString().contains("private-run"))
        assertFalse(before.toString().contains("acceptedRevisionSha256"))
        AgentProgressJournal(root, "repair", listOf("private-run")).use { journal ->
            journal.runState(AgentWorkflowRunObservation("next-run", AgentWorkflowPhase.ACCEPTED,
                "revision-2", "attempt-2", "a".repeat(64)))
        }
        val events = AgentProgressJournal.read(root)!!.getValue("events").jsonArray.map { it.jsonObject }
        val firstRun = events.filter { it["workflowRunId"]?.jsonPrimitive?.content == "[redacted]" }
        assertEquals(1, firstRun.map { it.getValue("workflowRunIdSha256") }.distinct().size)
        assertEquals(setOf("task_started", "plan", "agent_finished", "workflow_run_state"), firstRun.map { it.getValue("kind").jsonPrimitive.content }.toSet())
        assertEquals(listOf("provisional", "exhausted", "accepted"), events.filter {
            it["kind"]?.jsonPrimitive?.content == "workflow_run_state"
        }.map { it.getValue("phase").jsonPrimitive.content })
        assertEquals(2, events.map { it.getValue("runId") }.distinct().size)
        assertEquals("a".repeat(64), events.last().getValue("acceptedRevisionSha256").jsonPrimitive.content)
        assertEquals("revision-2", events.last().getValue("revisionId").jsonPrimitive.content)
    }

    @Test
    fun `nonaccepted run observations cannot carry accepted source identity`() {
        assertFailsWith<IllegalArgumentException> {
            AgentWorkflowRunObservation("run", AgentWorkflowPhase.PROVISIONAL, acceptedRevisionSha256 = "a".repeat(64))
        }
        assertFailsWith<IllegalArgumentException> {
            AgentWorkflowRunObservation("run", AgentWorkflowPhase.ACCEPTED)
        }
        assertFailsWith<IllegalArgumentException> {
            AgentWorkflowRunObservation("x".repeat(4097), AgentWorkflowPhase.CANCELLED)
        }
    }

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
        val omitted = snapshot.getValue("omittedSequenceRanges").jsonArray.flatMap {
            val range = it.jsonObject
            (range.getValue("startInclusive").jsonPrimitive.content.toLong() until
                range.getValue("endExclusive").jsonPrimitive.content.toLong()).toList()
        }
        val retained = snapshot.getValue("events").jsonArray.map { it.jsonObject.getValue("sequence").jsonPrimitive.long }
        assertEquals((0L until next).toList(), (omitted + retained).sorted())
        assertTrue(snapshot.getValue("omittedSequenceRanges").jsonArray.size <= retained.size + 1)
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
