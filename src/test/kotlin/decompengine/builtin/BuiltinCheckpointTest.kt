package decompengine.builtin

import decompengine.agent.*
import decompengine.builtin.provider.*
import kotlinx.serialization.json.*
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.APPEND
import java.nio.file.attribute.PosixFilePermissions
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.*

class BuiltinCheckpointTest {
    @TempDir lateinit var directory: Path
    private val sourcePath = AgentWorkspacePath("project", "source.c")
    private fun request(limits: AgentExecutionLimits = AgentExecutionLimits()) = AgentExecutionRequest("repair source",
        listOf(AgentWorkspaceRoot("project", directory.resolve("stage"))), emptyList(),
        AgentAccessPolicy(listOf(AgentPathRule(sourcePath, setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)))), limits)
    private fun snapshot(text: String) = BuiltinWorkspaceSnapshot.capture(mapOf(sourcePath to text.toByteArray()))
    private fun fixture(name: String = "fixture", decide: (Int, Int) -> BuiltinCheckpointAction = { _, calls ->
        if (calls == 1) BuiltinCheckpointAction.SUSPEND else BuiltinCheckpointAction.CONTINUE
    }): Fixture {
        Files.createDirectories(directory.resolve("stage"))
        val journalDirectory = Files.createDirectory(directory.resolve("$name-journal"))
        val checkpointDirectory = Files.createDirectory(directory.resolve("$name-checkpoints"))
        listOf(journalDirectory, checkpointDirectory).forEach { Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------")) }
        val source = directory.resolve("stage/source.c")
        Files.writeString(source, "old")
        return Fixture(source, BuiltinJournalConfiguration(journalDirectory.resolve("journal.jsonl"),
            BuiltinJournalIdentity("fixture", "scripted-v1", snapshot("old").sha256, "b".repeat(64), "c".repeat(64))),
            BuiltinCheckpointConfiguration(checkpointDirectory, decide))
    }
    private data class Fixture(val source: Path, val journal: BuiltinJournalConfiguration, val checkpoint: BuiltinCheckpointConfiguration)
    private fun answer(calls: List<ModelToolCall> = emptyList()) = ModelResponse("", calls,
        if (calls.isEmpty()) ModelFinishReason.STOP else ModelFinishReason.TOOL_CALLS, ModelUsage(100, 10, false), 1)
    private fun edit(id: String = "call1", text: String = "candidate") = ModelToolCall(id, "edit", buildJsonObject { put("text", text) })
    private fun harness(fixture: Fixture, provider: ModelProvider, session: Session = Session(fixture.source),
        limits: BuiltinLoopLimits = BuiltinLoopLimits(), secrets: List<String> = emptyList()) =
        BuiltinAgentHarness(provider, { _, _ -> session }, limits, secrets, fixture.journal, fixture.checkpoint)
    private fun suspended(fixture: Fixture, request: AgentExecutionRequest = request(), limits: BuiltinLoopLimits = BuiltinLoopLimits(),
        inputTokens: Long = 100): BuiltinCheckpointReference {
        val receipt = harness(fixture, ModelProvider { _, _ -> ModelResponse("", listOf(edit()), ModelFinishReason.TOOL_CALLS,
            ModelUsage(inputTokens, 10, false), 1) }, limits = limits).executeReceipt(request) {}
        val evidence = assertIs<BuiltinLoopEvidence>(receipt.providerEvidence)
        assertEquals(BuiltinStop.SUSPENDED, evidence.stop)
        assertEquals(AgentStopReason.CANCELLED, receipt.requireResult().stopReason)
        assertFalse(evidence.journal!!.complete)
        assertFalse(evidence.journal.indeterminate)
        assertNotNull(receipt.requireResult().session?.resumeReference)
        return assertNotNull(evidence.checkpoint)
    }

    @Test fun `fresh invocation resumes completed tool history from verified staged bytes without repeating the edit`() {
        val fixture = fixture()
        val reference = suspended(fixture)
        assertEquals("candidate", Files.readString(fixture.source))
        val reopened = Session(fixture.source)
        var calls = 0
        val receipt = harness(fixture, ModelProvider { model, _ ->
            calls++
            assertEquals(ModelRole.TOOL, model.messages.last().role)
            assertEquals("call1", model.messages.last().toolCallId)
            assertEquals("edited", model.messages.last().content)
            answer()
        }, reopened).resumeReceipt(request(), reference) {}
        assertEquals(1, calls); assertEquals(0, reopened.executions); assertTrue(reopened.closed)
        val evidence = assertIs<BuiltinLoopEvidence>(receipt.providerEvidence)
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, evidence.stop)
        assertEquals(2, evidence.modelCalls); assertEquals(1, evidence.toolCalls)
        assertEquals(200, evidence.inputTokens); assertEquals(20, evidence.outputTokens)
        assertTrue(evidence.journal!!.complete); assertFalse(evidence.journal.indeterminate)
        val inspection = BuiltinJournal.inspect(fixture.journal, AgentExecutionRequestBinding.capture(request()), evidence.journal.commitment)
        assertEquals(1, inspection.records.count { it["kind"] == JsonPrimitive("RESUME") })
        assertEquals(1, inspection.records.count { it["kind"] == JsonPrimitive("TOOL_REQUEST") })
    }

    @Test fun `consumed checkpoint cannot launch a second continuation`() {
        val fixture = fixture()
        val reference = suspended(fixture)
        var calls = 0
        val resumed = harness(fixture, ModelProvider { _, _ -> calls++; answer() })
        resumed.resumeReceipt(request(), reference) {}.requireResult()
        val rejected = resumed.resumeReceipt(request(), reference) {}
        assertIs<AgentExecutionOutcome.Failed>(rejected.outcome)
        assertEquals(1, calls)
    }

    @Test fun `reopened source tool schemas request and loop limits must match the checkpoint`() {
        for (change in listOf("source", "schemas", "request", "limits")) {
            val fixture = fixture(change)
            val reference = suspended(fixture)
            if (change == "source") Files.writeString(fixture.source, "tampered")
            var calls = 0
            val limits = if (change == "limits") BuiltinLoopLimits(maxIdenticalActions = 2) else BuiltinLoopLimits()
            val session = Session(fixture.source, description = if (change == "schemas") "different schema identity" else "edit fixture")
            val requested = if (change == "request") request(AgentExecutionLimits(maxTurns = 2)) else request()
            val rejected = harness(fixture, ModelProvider { _, _ -> calls++; answer() }, session, limits).resumeReceipt(requested, reference) {}
            assertIs<AgentExecutionOutcome.Failed>(rejected.outcome)
            assertEquals(0, calls); assertEquals(0, session.executions)
            // A failed precondition is not an execution and must not consume the valid checkpoint.
            if (change == "source") Files.writeString(fixture.source, "candidate")
            val corrected = harness(fixture, ModelProvider { _, _ -> calls++; answer() }).resumeReceipt(request(), reference) {}
            assertEquals(BuiltinStop.VALIDATION_REQUIRED, assertIs<BuiltinLoopEvidence>(corrected.providerEvidence).stop)
            assertEquals(1, calls)
        }
    }

    @Test fun `resume preserves turn tool token repetition and call-id budgets`() {
        for (budget in listOf("turns", "tools", "tokens", "repetition", "call-id")) {
            val fixture = fixture(budget)
            val requestLimits = when (budget) {
                "turns" -> AgentExecutionLimits(maxTurns = 1)
                "tools" -> AgentExecutionLimits(maxToolCalls = 1)
                "tokens" -> AgentExecutionLimits(maxInputTokens = 1700)
                else -> AgentExecutionLimits()
            }
            val req = request(requestLimits)
            val loopLimits = if (budget == "repetition") BuiltinLoopLimits(maxIdenticalActions = 1) else BuiltinLoopLimits()
            val reference = suspended(fixture, req, loopLimits, if (budget == "tokens") 1600 else 100)
            var calls = 0
            val session = Session(fixture.source)
            val receipt = harness(fixture, ModelProvider { _, _ -> calls++; answer(listOf(edit(if (budget == "call-id") "call1" else "call2"))) },
                session, loopLimits).resumeReceipt(req, reference) {}
            val stop = assertIs<BuiltinLoopEvidence>(receipt.providerEvidence).stop
            assertEquals(if (budget == "call-id") BuiltinStop.INVALID_ACTION else BuiltinStop.EXHAUSTED, stop, budget)
            assertEquals(0, session.executions, budget)
            if (budget == "turns" || budget == "tokens") assertEquals(0, calls, budget)
        }
    }

    @Test fun `redacted checkpoint cannot silently replace original model context`() {
        val fixture = fixture()
        val receipt = harness(fixture, ModelProvider { _, _ -> answer(listOf(edit(text = "private-secret"))) }, secrets = listOf("private-secret"))
            .executeReceipt(request()) {}
        val reference = assertNotNull(assertIs<BuiltinLoopEvidence>(receipt.providerEvidence).checkpoint)
        var calls = 0
        val rejected = harness(fixture, ModelProvider { _, _ -> calls++; answer() }, secrets = listOf("private-secret"))
            .resumeReceipt(request(), reference) {}
        assertIs<AgentExecutionOutcome.Failed>(rejected.outcome); assertEquals(0, calls)
        assertFalse(Files.readString(fixture.journal.path).contains("private-secret"))
    }

    @Test fun `torn journal appended intent and modified commitment prevent continuation`() {
        for (damage in listOf("torn", "intent", "marker")) {
            val fixture = fixture(damage)
            val reference = suspended(fixture)
            when (damage) {
                "torn" -> Files.write(fixture.journal.path, Files.readAllBytes(fixture.journal.path).dropLast(1).toByteArray())
                "intent" -> {
                    val store = BuiltinCheckpointStore(fixture.checkpoint, fixture.journal, request())
                    val (journal, _) = BuiltinJournal.reopenCheckpoint(fixture.journal, request(), store.read(reference), emptyList())
                    journal.use { it.append(BuiltinJournalKind.TOOL_REQUEST, buildJsonObject { put("id", "uncertain") }) }
                }
                else -> Files.writeString(fixture.checkpoint.directory.resolve(reference.fileName), "damage", APPEND)
            }
            var calls = 0
            val rejected = harness(fixture, ModelProvider { _, _ -> calls++; answer() }).resumeReceipt(request(), reference) {}
            assertIs<AgentExecutionOutcome.Failed>(rejected.outcome); assertEquals(0, calls)
        }
    }

    @Test fun `crash after durable checkpoint publication leaves a recoverable prefix and releases its lock`() {
        class SimulatedCrash : Error()
        val fixture = fixture(decide = { _, calls -> if (calls == 1) throw SimulatedCrash() else BuiltinCheckpointAction.CONTINUE })
        assertFailsWith<SimulatedCrash> {
            harness(fixture, ModelProvider { _, _ -> answer(listOf(edit())) }).executeReceipt(request()) {}
        }
        val marker = Files.list(fixture.checkpoint.directory).use { paths -> paths.toList().maxBy { it.fileName.toString().split('-')[1].toInt() } }
        val parts = marker.fileName.toString().removeSuffix(".json").split('-')
        val reference = BuiltinCheckpointReference(parts[1].toInt(), parts[2])
        val resumed = harness(fixture, ModelProvider { _, _ -> answer() }).resumeReceipt(request(), reference) {}
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, assertIs<BuiltinLoopEvidence>(resumed.providerEvidence).stop)
    }

    @Test fun `snapshot hashes are canonical bounded and distinguish path contents and root identity`() {
        val a = sourcePath
        val b = AgentWorkspacePath("project", "other.c")
        val first = BuiltinWorkspaceSnapshot.capture(linkedMapOf(a to "one".toByteArray(), b to "two".toByteArray()))
        val second = BuiltinWorkspaceSnapshot.capture(linkedMapOf(b to "two".toByteArray(), a to "one".toByteArray()))
        assertEquals(first.sha256, second.sha256)
        assertNotEquals(snapshot("old").sha256, snapshot("new").sha256)
        assertNotEquals(snapshot("old").sha256, BuiltinWorkspaceSnapshot.capture(mapOf(AgentWorkspacePath("other", "source.c") to "old".toByteArray())).sha256)
        assertFailsWith<IllegalArgumentException> { BuiltinWorkspaceSnapshot.capture(mapOf(a to ByteArray(20)), maximumBytes = 10) }
        assertFailsWith<UnsupportedOperationException> { (first.files as MutableList).clear() }
    }

    @Test fun `checkpoint store must be private separate and outside tool authority before any model call`() {
        for (location in listOf("workspace", "journal", "permissions")) {
            val original = fixture(location)
            val config = when (location) {
                "workspace" -> BuiltinCheckpointConfiguration(directory.resolve("stage"))
                "journal" -> BuiltinCheckpointConfiguration(original.journal.path.parent)
                else -> original.checkpoint.also {
                    Files.setPosixFilePermissions(it.directory, PosixFilePermissions.fromString("rwxr-xr-x"))
                }
            }
            var calls = 0
            val rejected = harness(original.copy(checkpoint = config), ModelProvider { _, _ -> calls++; answer() }).executeReceipt(request()) {}
            assertIs<AgentExecutionOutcome.Failed>(rejected.outcome); assertEquals(0, calls)
        }
    }

    @Test fun `expired checkpoint and wrong initial snapshot cannot acquire provider execution`() {
        val fixture = fixture("expiry")
        val policy = fixture.checkpoint.decide
        val paused = fixture.copy(checkpoint = BuiltinCheckpointConfiguration(fixture.checkpoint.directory, policy,
            Clock.fixed(Instant.parse("2026-09-05T00:00:00Z"), ZoneOffset.UTC)))
        val reference = suspended(paused)
        val expired = fixture.copy(checkpoint = BuiltinCheckpointConfiguration(fixture.checkpoint.directory, policy,
            Clock.fixed(Instant.parse("2026-09-07T00:00:00Z"), ZoneOffset.UTC)))
        var calls = 0
        val rejected = harness(expired, ModelProvider { _, _ -> calls++; answer() }).resumeReceipt(request(), reference) {}
        assertIs<AgentExecutionOutcome.Failed>(rejected.outcome); assertEquals(0, calls)
        val wrong = fixture("initial")
        Files.writeString(wrong.source, "different initial source")
        val initial = harness(wrong, ModelProvider { _, _ -> calls++; answer() }).executeReceipt(request()) {}
        assertIs<AgentExecutionOutcome.Failed>(initial.outcome); assertEquals(0, calls)
    }

    private inner class Session(val source: Path, val description: String = "edit fixture") : BuiltinToolSession {
        var executions = 0
        var closed = false
        override val definitions = listOf(ModelToolDefinition("edit", description, buildJsonObject {
            put("type", "object"); put("additionalProperties", false)
            putJsonObject("properties") { putJsonObject("text") { put("type", "string") } }
            putJsonArray("required") { add("text") }
        }))
        override fun authorize(call: ModelToolCall, control: BuiltinExecutionControl) = true
        override fun execute(call: ModelToolCall, control: BuiltinExecutionControl): BuiltinToolResult {
            control.checkpoint(); executions++
            Files.writeString(source, call.arguments.getValue("text").jsonPrimitive.content)
            return BuiltinToolResult("edited")
        }
        override fun checkpointSnapshot(control: BuiltinExecutionControl): BuiltinWorkspaceSnapshot {
            control.checkpoint(); return BuiltinWorkspaceSnapshot.capture(mapOf(sourcePath to Files.readAllBytes(source)))
        }
        override fun changes(control: BuiltinExecutionControl) = emptyList<AgentFileChange>()
        override fun close() { closed = true }
    }
}
