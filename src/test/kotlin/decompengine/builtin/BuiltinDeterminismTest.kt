package decompengine.builtin

import decompengine.agent.*
import decompengine.builtin.provider.*
import kotlinx.serialization.json.*
import org.junit.jupiter.api.io.TempDir
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.*

/** Exact logical determinism controls; operational clocks and their dependent integrity links are verified separately. */
class BuiltinDeterminismTest {
    @TempDir lateinit var directory: Path

    private val sourcePath = AgentWorkspacePath("project", "src/main.c")
    private val acceptedRevision = "c".repeat(64)
    private val stageIdentity = "b".repeat(64)
    private val fixedClock = Clock.fixed(Instant.parse("2026-10-01T00:00:00Z"), ZoneOffset.UTC)
    private val evidenceInputs = listOf(
        AgentContextInput("large", ("line Ω\\\"\n".repeat(2200)), mediaType = "text/plain", description = "retained source evidence"),
        AgentContextInput("small", "Unicode and escaped text: λ\\\"\n", mediaType = "text/plain", description = "included control"),
    )

    private fun request(root: Path, inputs: List<AgentContextInput> = evidenceInputs,
        cancellation: AgentCancellation = AgentCancellation.NONE) = AgentExecutionRequest(
        "repair the authorized source", listOf(AgentWorkspaceRoot("project", root)), inputs,
        AgentAccessPolicy(listOf(AgentPathRule(sourcePath, setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)))),
        AgentExecutionLimits(wallClockTimeout = Duration.ofSeconds(30)), cancellation,
    )

    private fun editDefinition() = ModelToolDefinition("edit", "Edit the staged source candidate", buildJsonObject {
        put("type", "object"); put("additionalProperties", false)
        putJsonObject("properties") { putJsonObject("text") { put("type", "string") } }
        putJsonArray("required") { add("text") }
    })

    private fun editCall(id: String = "edit-1", text: String = "candidate-source") = ModelToolCall(id, "edit",
        buildJsonObject { put("text", text) })

    private fun response(text: String = "", calls: List<ModelToolCall> = emptyList(),
        finish: ModelFinishReason = if (calls.isEmpty()) ModelFinishReason.STOP else ModelFinishReason.TOOL_CALLS,
        usage: ModelUsage = ModelUsage(80, 12, false)) = ModelResponse(text, calls, finish, usage, 1)

    private data class MessageProjection(
        val role: ModelRole,
        val content: String,
        val toolCallId: String?,
        val calls: List<String>,
    )

    private data class ToolProjection(val name: String, val description: String, val parameters: String)

    private data class LimitsProjection(
        val connect: Duration,
        val request: Duration,
        val idle: Duration,
        val maximumRequestBytes: Int,
        val maximumResponseBytes: Int,
        val maximumEventBytes: Int,
        val maximumToolCalls: Int,
        val maximumOutputTokens: Int,
        val retries: Int,
        val retryBase: Duration,
        val retryMaximum: Duration,
    )

    private data class ProviderCall(
        val messages: List<MessageProjection>,
        val tools: List<ToolProjection>,
        val fixedLimits: LimitsProjection,
        val overallTimeout: Duration,
    )

    private inner class ScriptedProvider(private val responses: List<ModelResponse>) : ModelProvider {
        private var cursor = 0
        val calls = mutableListOf<ProviderCall>()
        val consumed get() = cursor

        override fun generate(request: ModelRequest, onEvent: (ModelEvent) -> Unit): ModelResponse {
            check(cursor < responses.size) { "Scripted provider received an unexpected call" }
            val call = request
            calls += ProviderCall(
                call.messages.map { message -> MessageProjection(message.role, message.content, message.toolCallId,
                    message.toolCalls.map(::canonicalCall)) },
                call.tools.map { ToolProjection(it.name, it.description, canonicalJson(it.parameters)) },
                LimitsProjection(call.limits.connectTimeout, call.limits.requestTimeout, call.limits.streamIdleTimeout,
                    call.limits.maxRequestBytes, call.limits.maxResponseBytes, call.limits.maxEventBytes,
                    call.limits.maxToolCalls, call.limits.maxOutputTokens, call.limits.maxRetries,
                    call.limits.retryBaseDelay, call.limits.maxRetryDelay),
                call.limits.overallTimeout,
            )
            val answer = responses[cursor++]
            if (answer.text.isNotEmpty()) onEvent(ModelEvent.TextDelta(answer.text))
            answer.toolCalls.forEach { onEvent(ModelEvent.ToolCall(it)) }
            onEvent(ModelEvent.Usage(answer.usage))
            onEvent(ModelEvent.Finished(answer.finishReason))
            return answer
        }
    }

    private class Counters {
        var contextReads = 0
        var edits = 0
    }

    private inner class DeterministicTools(
        private val request: AgentExecutionRequest,
        private val workspace: Path,
        private val counters: Counters,
        private val validation: BuiltinCompletion = BuiltinCompletion.VALIDATED,
        private val failEdit: Boolean = false,
    ) : BuiltinToolSession {
        private val context = BuiltinCapturedContextTools(request, listOf(sourcePath.relativePath), 8192, 64)
        override val definitions = listOf(editDefinition()) + context.definitions
        override val supportsContextRetrieval = true

        override fun authorize(call: ModelToolCall, control: BuiltinExecutionControl): Boolean {
            control.checkpoint()
            return call.name in definitions.map { it.name }
        }

        override fun execute(call: ModelToolCall, control: BuiltinExecutionControl): BuiltinToolResult {
            control.checkpoint()
            if (call.name != "edit") {
                counters.contextReads++
                return context.execute(call, control)
            }
            counters.edits++
            if (!failEdit) Files.writeString(workspace.resolve(sourcePath.relativePath), call.arguments.getValue("text").jsonPrimitive.content)
            return BuiltinToolResult("candidate staged", failed = failEdit)
        }

        override fun changes(control: BuiltinExecutionControl): List<AgentFileChange> = sourceChange()
        override fun finalChanges(): List<AgentFileChange> = sourceChange()
        override fun validateCompletion(control: BuiltinExecutionControl) = validation
        override fun checkpointAuthoritySha256(control: BuiltinExecutionControl) = "d".repeat(64)
        override fun checkpointSnapshot(control: BuiltinExecutionControl) = BuiltinWorkspaceSnapshot.capture(
            mapOf(sourcePath to Files.readAllBytes(workspace.resolve(sourcePath.relativePath))))
        override fun restoreCheckpointStage(expectedSourceSha256: String, control: BuiltinExecutionControl) {
            check(checkpointSnapshot(control).sha256 == expectedSourceSha256)
        }
        override fun close() = Unit

        private fun sourceChange(): List<AgentFileChange> {
            val after = Files.readAllBytes(workspace.resolve(sourcePath.relativePath))
            val beforeHash = hash("old".toByteArray())
            val afterHash = hash(after)
            return if (beforeHash == afterHash) emptyList() else listOf(AgentFileChange(
                sourcePath, AgentFileChangeKind.MODIFIED, beforeHash, afterHash, after.size.toLong()))
        }
    }

    private data class RunResult(
        val request: AgentExecutionRequest,
        val journal: BuiltinJournalConfiguration,
        val checkpoint: BuiltinCheckpointConfiguration,
        val initialReceipt: AgentExecutionReceipt,
        val finalReceipt: AgentExecutionReceipt,
        val provider: ScriptedProvider,
        val counters: Counters,
        val emittedEvents: List<String>,
        val initialCommitment: BuiltinJournalCommitment,
        val checkpointReference: BuiltinCheckpointReference,
        val finalInspection: BuiltinJournalInspection,
        val finalBytes: List<Byte>,
    )

    private fun scriptedResponses() = listOf(
        response(calls = listOf(
            ModelToolCall("read-1", "read_evidence", buildJsonObject { put("id", "large"); put("offset", 0) }),
            editCall(),
        ), usage = ModelUsage(120, 35, false)),
        response(text = "candidate is ready", usage = ModelUsage(90, 14, false)),
    )

    private fun runCheckpointed(label: String, workspace: Path): RunResult {
        Files.createDirectories(workspace)
        Files.createDirectories(workspace.resolve(sourcePath.relativePath).parent)
        Files.writeString(workspace.resolve(sourcePath.relativePath), "old")
        val journalDirectory = privateDirectory(directory.resolve("$label-journal"))
        val checkpointDirectory = privateDirectory(directory.resolve("$label-checkpoints"))
        val req = request(workspace)
        val sourceHash = BuiltinWorkspaceSnapshot.capture(mapOf(sourcePath to "old".toByteArray())).sha256
        val journal = BuiltinJournalConfiguration(journalDirectory.resolve("journal.jsonl"), BuiltinJournalIdentity(
            BUILTIN_TEST_PROVIDER_IDENTITY.provider, BUILTIN_TEST_PROVIDER_IDENTITY.model, sourceHash, stageIdentity, acceptedRevision))
        val checkpoint = BuiltinCheckpointConfiguration(checkpointDirectory, { modelCalls, toolCalls ->
            if (modelCalls == 1 && toolCalls == 2) BuiltinCheckpointAction.SUSPEND else BuiltinCheckpointAction.CONTINUE
        }, fixedClock)
        val provider = ScriptedProvider(scriptedResponses())
        val counters = Counters()
        val events = mutableListOf<String>()
        val harness = harness(req, workspace, counters, provider, journal, checkpoint)
        val initial = harness.executeReceipt(req) { events += eventProjection(it) }
        val initialEvidence = evidence(initial)
        assertEquals(BuiltinStop.SUSPENDED, initialEvidence.stop)
        assertEquals(AgentStopReason.CANCELLED, initial.requireResult().stopReason)
        val reference = assertNotNull(initialEvidence.checkpoint)
        val initialCommitment = assertNotNull(initialEvidence.journal).commitment
        val prefix = BuiltinJournal.inspect(journal, AgentExecutionRequestBinding.capture(req), initialCommitment)
        assertFalse(prefix.indeterminate)
        assertTrue(prefix.endsAtCheckpoint)
        assertEquals(2, prefix.records.count { kind(it) == "CHECKPOINT" })
        verifyCheckpointRecords(prefix.records, req)
        val committed = BuiltinCheckpointStore(checkpoint, journal, req).read(reference)
        assertEquals(initialCommitment, committed)

        val resumed = harness(req, workspace, counters, provider, journal, checkpoint)
            .resumeReceipt(req, reference, acceptedRevision) { events += eventProjection(it) }
        val finalEvidence = evidence(resumed)
        assertEquals(BuiltinStop.COMPLETED, finalEvidence.stop)
        assertEquals(AgentStopReason.COMPLETED, resumed.requireResult().stopReason)
        assertEquals(1, counters.contextReads)
        assertEquals(1, counters.edits)
        assertEquals(2, provider.consumed)
        val finalCommitment = assertNotNull(finalEvidence.journal).commitment
        val inspected = BuiltinJournal.inspect(journal, AgentExecutionRequestBinding.capture(req), finalCommitment)
        assertTrue(inspected.complete)
        assertFalse(inspected.indeterminate)
        val resumeRecord = inspected.records.single { kind(it) == "RESUME" }
        val resumePayload = resumeRecord.getValue("payload").jsonObject
        assertEquals(initialCommitment.headSha256, resumePayload.getValue("checkpointHeadSha256").jsonPrimitive.content)
        assertEquals(initialCommitment.records, resumePayload.getValue("checkpointRecords").jsonPrimitive.int)
        assertEquals(reference.headSha256, resumePayload.getValue("checkpointHeadSha256").jsonPrimitive.content)
        assertEquals(reference.records, resumePayload.getValue("checkpointRecords").jsonPrimitive.int)
        assertEquals(AgentExecutionRequestBinding.capture(req), initial.requestBinding)
        assertEquals(AgentExecutionRequestBinding.capture(req), resumed.requestBinding)
        assertNull(resumed.requireResult().session)
        verifyCheckpointRecords(inspected.records, req)
        return RunResult(req, journal, checkpoint, initial, resumed, provider, counters, events.toList(),
            initialCommitment, reference, inspected, Files.readAllBytes(workspace.resolve(sourcePath.relativePath)).toList())
    }

    private fun harness(request: AgentExecutionRequest, workspace: Path, counters: Counters, provider: ScriptedProvider,
        journal: BuiltinJournalConfiguration? = null, checkpoint: BuiltinCheckpointConfiguration? = null,
        validation: BuiltinCompletion = BuiltinCompletion.VALIDATED, failEdit: Boolean = false) = BuiltinAgentHarness(
        provider.withBuiltinTestIdentity(), { req, _ -> DeterministicTools(req, workspace, counters, validation, failEdit) },
        BuiltinLoopLimits(maxContextBytes = 20_000, maxToolResultBytes = 8192, maximumEvidenceBytes = 64_000,
            contextHistoryReserveBytes = 8_000), journalConfiguration = journal, checkpointConfiguration = checkpoint,
    )

    @Test fun `identical independent checkpointed executions preserve context tool checkpoint and terminal semantics`() {
        val workspace = directory.resolve("stable-workspace/project")
        val first = runCheckpointed("repeat-a", workspace)
        val second = runCheckpointed("repeat-b", workspace)

        assertEquals(first.request.workspaceRoots, second.request.workspaceRoots)
        assertEquals(AgentExecutionRequestBinding.capture(first.request), AgentExecutionRequestBinding.capture(second.request))
        assertEquals(first.provider.calls.map { it.copy(overallTimeout = Duration.ZERO) },
            second.provider.calls.map { it.copy(overallTimeout = Duration.ZERO) })
        assertTrue(first.provider.calls.isNotEmpty())
        first.provider.calls.forEach { call ->
            assertTrue(call.overallTimeout > Duration.ZERO)
            assertTrue(call.overallTimeout <= first.request.limits.wallClockTimeout)
        }
        val firstEvidence = evidence(first.finalReceipt)
        val secondEvidence = evidence(second.finalReceipt)
        assertEquals(firstEvidence.records, secondEvidence.records)
        assertEquals(firstEvidence.contextEntries, secondEvidence.contextEntries)
        assertTrue(firstEvidence.contextEntries.any { it.id == "large" && !it.included })
        assertTrue(firstEvidence.contextEntries.any { it.id == "small" && it.included })
        assertEquals(first.counters.edits, second.counters.edits)
        assertEquals(first.counters.contextReads, second.counters.contextReads)
        assertEquals(listOf("read-1", "edit-1"), toolResults(first.finalInspection.records).map { it.getValue("callId").jsonPrimitive.content })
        assertEquals(logicalJournal(first.finalInspection.records), logicalJournal(second.finalInspection.records))
        assertEquals(outcomeProjection(first.finalReceipt), outcomeProjection(second.finalReceipt))
        listOf(first, second).forEach { run ->
            assertEquals(210L, run.finalReceipt.requireResult().usage?.inputTokens)
            assertEquals(49L, run.finalReceipt.requireResult().usage?.outputTokens)
            assertEquals(2, run.finalReceipt.requireResult().usage?.toolCalls)
            assertEquals("candidate-source".encodeToByteArray().toList(), run.finalBytes)
            assertEquals(listOf(expectedChange("candidate-source")), evidence(run.finalReceipt).candidateChanges.map(::changeProjection))
            assertEquals(listOf(expectedChange("candidate-source")), run.finalReceipt.requireResult().changes.map(::changeProjection))
        }
        verifyOutcomeClock(first.finalReceipt, first.request)
        verifyOutcomeClock(second.finalReceipt, second.request)
        assertEquals(first.finalBytes, second.finalBytes)
        assertEquals(2, first.finalInspection.records.count { kind(it) == "CHECKPOINT" })
        assertEquals(first.initialCommitment.records, first.checkpointReference.records)
        assertEquals(second.initialCommitment.records, second.checkpointReference.records)
    }

    @Test fun `suspend resume matches uninterrupted semantic outputs without replaying completed tools`() {
        val workspace = directory.resolve("resume-workspace/project")
        val resumed = runCheckpointed("resumed", workspace)
        val resumedCalls = resumed.provider.calls.map { it.messages }
        val resumedResults = toolResults(resumed.finalInspection.records)
        val resumedEvidence = evidence(resumed.finalReceipt)
        val resumedOutcome = outcomeProjection(resumed.finalReceipt)
        val resumedChanges = resumed.finalReceipt.requireResult().changes
        val resumedBytes = Files.readAllBytes(workspace.resolve(sourcePath.relativePath)).toList()
        val resumedEvents = resumed.emittedEvents
        val resumedStates = resumedEvidence.records.map { it.state }

        val directWorkspace = workspace
        Files.writeString(directWorkspace.resolve(sourcePath.relativePath), "old")
        val directJournalDirectory = privateDirectory(directory.resolve("direct-journal"))
        val directRequest = request(directWorkspace)
        val sourceHash = BuiltinWorkspaceSnapshot.capture(mapOf(sourcePath to "old".toByteArray())).sha256
        val directJournal = BuiltinJournalConfiguration(directJournalDirectory.resolve("journal.jsonl"), BuiltinJournalIdentity(
            BUILTIN_TEST_PROVIDER_IDENTITY.provider, BUILTIN_TEST_PROVIDER_IDENTITY.model, sourceHash, stageIdentity, acceptedRevision))
        val directProvider = ScriptedProvider(scriptedResponses())
        val directCounters = Counters()
        val directEvents = mutableListOf<String>()
        val directReceipt = harness(directRequest, directWorkspace, directCounters, directProvider, directJournal)
            .executeReceipt(directRequest) { directEvents += eventProjection(it) }
        val directBytes = Files.readAllBytes(directWorkspace.resolve(sourcePath.relativePath)).toList()
        val directEvidence = evidence(directReceipt)
        val directCommitment = assertNotNull(directEvidence.journal).commitment
        val directInspection = BuiltinJournal.inspect(directJournal, AgentExecutionRequestBinding.capture(directRequest), directCommitment)

        assertEquals(BuiltinStop.COMPLETED, directEvidence.stop)
        assertEquals(2, directProvider.consumed)
        assertEquals(1, directCounters.contextReads)
        assertEquals(1, directCounters.edits)
        assertEquals(resumedCalls, directProvider.calls.map { it.messages })
        assertEquals(resumedResults, toolResults(directInspection.records))
        assertEquals(resumedEvents, directEvents)
        assertEquals(resumedOutcome, outcomeProjection(directReceipt))
        assertEquals(AgentExecutionRequestBinding.capture(resumed.request), resumed.finalReceipt.requestBinding)
        assertEquals(AgentExecutionRequestBinding.capture(directRequest), directReceipt.requestBinding)
        assertNull(resumed.finalReceipt.requireResult().session)
        assertNull(directReceipt.requireResult().session)
        assertEquals(210L, directReceipt.requireResult().usage?.inputTokens)
        assertEquals(49L, directReceipt.requireResult().usage?.outputTokens)
        assertEquals(2, directReceipt.requireResult().usage?.toolCalls)
        assertEquals(listOf(expectedChange("candidate-source")), directReceipt.requireResult().changes.map(::changeProjection))
        verifyOutcomeClock(resumed.finalReceipt, resumed.request)
        verifyOutcomeClock(directReceipt, directRequest)
        assertEquals(resumedChanges, directReceipt.requireResult().changes)
        assertEquals(resumedBytes, directBytes)
        assertEquals(1, resumed.finalInspection.records.count { kind(it) == "RESUME" })
        assertEquals(0, directInspection.records.count { kind(it) == "RESUME" })
        assertEquals(2, resumedStates.count { it == BuiltinLoopState.PREPARING_CONTEXT })
        assertEquals(1, directEvidence.records.count { it.state == BuiltinLoopState.PREPARING_CONTEXT })
    }

    @Test fun `validation required remains distinct from completed while retaining only candidate changes`() {
        data class ValidationRun(
            val request: AgentExecutionRequest,
            val receipt: AgentExecutionReceipt,
            val provider: ScriptedProvider,
            val counters: Counters,
            val bytes: List<Byte>,
        )
        fun run(workspace: Path): ValidationRun {
            Files.createDirectories(workspace.resolve(sourcePath.relativePath).parent)
            Files.writeString(workspace.resolve(sourcePath.relativePath), "old")
            val req = request(workspace)
            val provider = ScriptedProvider(scriptedResponses())
            val counters = Counters()
            val receipt = harness(req, workspace, counters, provider, validation = BuiltinCompletion.REQUIRED)
                .executeReceipt(req) {}
            return ValidationRun(req, receipt, provider, counters,
                Files.readAllBytes(workspace.resolve(sourcePath.relativePath)).toList())
        }
        val workspace = directory.resolve("unaccepted-workspace/project")
        val first = run(workspace)
        val second = run(workspace)
        val firstEvidence = evidence(first.receipt)
        val secondEvidence = evidence(second.receipt)
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, firstEvidence.stop)
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, secondEvidence.stop)
        assertEquals(AgentStopReason.COMPLETED, first.receipt.requireResult().stopReason)
        assertEquals(firstEvidence.candidateChanges.map(::changeProjection),
            first.receipt.requireResult().changes.map(::changeProjection))
        assertTrue(firstEvidence.candidateChanges.isNotEmpty())
        assertEquals(first.request.workspaceRoots, second.request.workspaceRoots)
        assertEquals(AgentExecutionRequestBinding.capture(first.request), AgentExecutionRequestBinding.capture(second.request))
        assertEquals(first.provider.calls.map { it.copy(overallTimeout = Duration.ZERO) },
            second.provider.calls.map { it.copy(overallTimeout = Duration.ZERO) })
        assertEquals(firstEvidence.records, secondEvidence.records)
        assertEquals(firstEvidence.candidateChanges.map(::changeProjection), secondEvidence.candidateChanges.map(::changeProjection))
        assertEquals(outcomeProjection(first.receipt), outcomeProjection(second.receipt))
        assertEquals(first.bytes, second.bytes)
        assertEquals(1, first.counters.edits); assertEquals(1, second.counters.edits)
        assertEquals(1, first.counters.contextReads); assertEquals(1, second.counters.contextReads)
        assertEquals(2, first.provider.consumed); assertEquals(2, second.provider.consumed)
    }

    @Test fun `context ordering is deterministic while normalization preserves semantic hashes and unlisted fields`() {
        val workspace = directory.resolve("context-project")
        val firstRequest = request(workspace, evidenceInputs)
        val secondRequest = request(workspace, evidenceInputs.reversed())
        val firstPackage = assemble(firstRequest)
        val secondPackage = assemble(secondRequest)
        assertEquals(firstPackage.sha256, secondPackage.sha256)
        assertEquals(firstPackage.serializedBytes, secondPackage.serializedBytes)
        assertEquals(firstPackage.entries, secondPackage.entries)
        assertEquals(firstPackage.messages.map(::messageProjection), secondPackage.messages.map(::messageProjection))
        assertTrue(firstPackage.entries.any { it.id == "large" && !it.included })
        assertTrue(firstPackage.entries.any { it.id == "small" && it.included })
        assertNotEquals(AgentExecutionRequestBinding.capture(firstRequest), AgentExecutionRequestBinding.capture(secondRequest),
            "request identity binds caller input order and must not be normalized")

        val baseline = projectionFixture()
        val clocksChanged = projectionFixture(
            remaining = 19L, overall = 21L, previous = "f".repeat(64), frameHash = "a".repeat(64),
        )
        assertEquals(logicalJournal(listOf(baseline)), logicalJournal(listOf(clocksChanged)))
        val changedContextHash = projectionFixture(contextHash = "b".repeat(64))
        assertNotEquals(logicalJournal(listOf(baseline)), logicalJournal(listOf(changedContextHash)))
        val changedFixedTimeout = projectionFixture(requestTimeoutNanos = 44L)
        assertNotEquals(logicalJournal(listOf(baseline)), logicalJournal(listOf(changedFixedTimeout)))
        val initialCheckpoint = initialCheckpointFixture(remaining = 11)
        val initialCheckpointClockChanged = initialCheckpointFixture(remaining = 19)
        assertEquals(logicalJournal(listOf(initialCheckpoint)), logicalJournal(listOf(initialCheckpointClockChanged)))
        assertNotEquals(logicalJournal(listOf(initialCheckpoint)), logicalJournal(listOf(
            initialCheckpointFixture(remaining = 11, turns = 2))))
        val checkpoint = checkpointProjectionFixture(remaining = 11, deadline = 13, elapsed = 14)
        val checkpointClockChanged = checkpointProjectionFixture(remaining = 19, deadline = 23, elapsed = 29)
        verifyFixtureCheckpoint(checkpoint)
        verifyFixtureCheckpoint(checkpointClockChanged)
        assertEquals(logicalJournal(listOf(checkpoint)), logicalJournal(listOf(checkpointClockChanged)))
        val corruptCheckpoint = replaceJson(checkpoint, "payload", buildJsonObject {
            put("resumeState", replaceJson(checkpoint.getValue("payload").jsonObject.getValue("resumeState").jsonObject,
                "remainingWallClockNanos", JsonPrimitive(99)))
            put("stateSha256", checkpoint.getValue("payload").jsonObject.getValue("stateSha256"))
        })
        assertFails { verifyFixtureCheckpoint(corruptCheckpoint) }
        val changedCheckpointSemantic = checkpointProjectionFixture(contextHash = "b".repeat(64))
        assertNotEquals(logicalJournal(listOf(checkpoint)), logicalJournal(listOf(changedCheckpointSemantic)))
        val changedUnlistedClockLike = replaceJson(checkpoint, "payload", buildJsonObject {
            put("resumeState", replaceJson(checkpoint.getValue("payload").jsonObject.getValue("resumeState").jsonObject,
                "testDeadlineEpochMillis", JsonPrimitive(999)))
            put("stateSha256", checkpoint.getValue("payload").jsonObject.getValue("stateSha256"))
        })
        assertNotEquals(logicalJournal(listOf(checkpoint)), logicalJournal(listOf(changedUnlistedClockLike)))
        val userClockLike = replaceJson(replaceJson(baseline, "kind", JsonPrimitive("MODEL_RESPONSE")), "payload", buildJsonObject {
            put("wallClockNanos", 1); put("result", "same-looking field remains semantic")
        })
        val userClockChanged = replaceJson(userClockLike, "payload", buildJsonObject {
            put("wallClockNanos", 2); put("result", "same-looking field remains semantic")
        })
        assertNotEquals(logicalJournal(listOf(userClockLike)), logicalJournal(listOf(userClockChanged)))
        assertNotEquals(listOf(BuiltinTraceRecord(0, BuiltinLoopState.REQUESTING_MODEL, "1".repeat(64))),
            listOf(BuiltinTraceRecord(0, BuiltinLoopState.REQUESTING_MODEL, "2".repeat(64))))
    }

    private fun assemble(request: AgentExecutionRequest): BuiltinContextPackage = BuiltinContextAssembler.assemble(
        request, 12_000, 64_000, true,
        BuiltinExecutionControl(request, System.nanoTime() + Duration.ofSeconds(10).toNanos()),
    ) { messages -> contextBytes(messages) }

    private fun contextBytes(messages: List<ModelMessage>) = boundedProviderJson(12_000) { out ->
        out.writeStartArray()
        messages.forEach { message ->
            out.writeStartObject(); out.writeStringField("role", message.role.name); out.writeStringField("content", message.content)
            message.toolCallId?.let { out.writeStringField("callId", it) }
            out.writeArrayFieldStart("calls")
            message.toolCalls.forEach { out.writeString(canonicalCall(it)); out.writeString(it.id) }
            out.writeEndArray(); out.writeEndObject()
        }
        out.writeEndArray()
    }

    private fun verifyCheckpointRecords(records: List<JsonObject>, request: AgentExecutionRequest) {
        records.filter { kind(it) == "CHECKPOINT" }.forEach { record ->
            val payload = record.getValue("payload").jsonObject
            val rawState = payload["resumeState"]?.jsonObject
            if (rawState == null) {
                val wall = payload.getValue("remaining").jsonObject.getValue("wallClockNanos").jsonPrimitive.long
                assertTrue(wall in 1..request.limits.wallClockTimeout.toNanos())
                return@forEach
            }
            assertEquals(setOf("resumeState", "stateSha256"), payload.keys)
            assertEquals(JsonPrimitive(checkpointStateHash(rawState, 8 * 1024 * 1024)), payload.getValue("stateSha256"))
            val remaining = rawState.getValue("remainingWallClockNanos").jsonPrimitive.long
            val deadline = rawState.getValue("deadlineEpochMillis").jsonPrimitive.long
            val elapsed = rawState.getValue("elapsedWallClockNanos").jsonPrimitive.long
            assertTrue(remaining in 1..request.limits.wallClockTimeout.toNanos())
            assertEquals(fixedClock.millis() + remaining / 1_000_000, deadline)
            assertTrue(deadline > fixedClock.millis())
            assertTrue(elapsed in 0..Duration.ofDays(1).toNanos())
            assertTrue(rawState.getValue("contextSha256").jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")))
            assertTrue(rawState.getValue("sourceSha256").jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")))
            assertEquals(stageIdentity, rawState.getValue("stageSha256").jsonPrimitive.content)
            assertEquals(acceptedRevision, rawState.getValue("acceptedRevisionSha256").jsonPrimitive.content)
        }
    }

    private fun logicalJournal(records: List<JsonObject>): List<JsonObject> = records.map { record ->
        val kind = kind(record)
        var payload = record.getValue("payload").jsonObject
        when (kind) {
            "CHECKPOINT" -> {
                val state = payload["resumeState"]?.jsonObject
                payload = if (state != null) {
                    JsonObject(payload.toMutableMap().also { projected ->
                        projected.remove("stateSha256")
                        projected["resumeState"] = JsonObject(state.filterKeys { it !in setOf(
                            "remainingWallClockNanos", "deadlineEpochMillis", "elapsedWallClockNanos") })
                    })
                } else {
                    val remaining = payload["remaining"]?.jsonObject
                    if (remaining == null) payload else replaceJson(payload, "remaining",
                        JsonObject(remaining.filterKeys { it != "wallClockNanos" }))
                }
            }
            "MODEL_REQUEST" -> {
                val remaining = payload["remaining"]?.jsonObject
                val limits = payload["providerLimits"]?.jsonObject
                if (remaining != null) payload = replaceJson(payload, "remaining",
                    JsonObject(remaining.filterKeys { it != "wallClockNanos" }))
                if (limits != null) payload = replaceJson(payload, "providerLimits",
                    JsonObject(limits.filterKeys { it != "overallTimeoutNanos" }))
            }
            "RESUME" -> payload = JsonObject(payload.filterKeys { it != "checkpointHeadSha256" })
        }
        JsonObject(record.toMutableMap().filterKeys { it !in setOf("previous", "sha256") } + ("payload" to payload))
    }

    private fun toolResults(records: List<JsonObject>) = records.filter { kind(it) == "TOOL_RESULT" }
        .map { it.getValue("payload").jsonObject }

    private fun kind(record: JsonObject) = record.getValue("kind").jsonPrimitive.content

    private fun evidence(receipt: AgentExecutionReceipt) = assertIs<BuiltinLoopEvidence>(receipt.providerEvidence)

    private fun replaceJson(value: JsonObject, key: String, replacement: JsonElement) =
        JsonObject(value.toMutableMap().also { it[key] = replacement })

    private fun messageProjection(message: ModelMessage) = MessageProjection(message.role, message.content, message.toolCallId,
        message.toolCalls.map(::canonicalCall))

    private fun canonicalCall(call: ModelToolCall) = buildJsonObject {
        put("id", call.id); put("name", call.name); put("arguments", canonicalElement(call.arguments))
    }.toString()

    private fun canonicalJson(value: JsonElement) = canonicalElement(value).toString()

    private fun canonicalElement(value: JsonElement): JsonElement = when (value) {
        is JsonObject -> JsonObject(value.toSortedMap().mapValues { canonicalElement(it.value) })
        is JsonArray -> JsonArray(value.map(::canonicalElement))
        else -> value
    }

    private fun eventProjection(event: AgentExecutionEvent): String = when (event) {
        is AgentMessageEvent -> "message:${event.sequence}:${event.messageId}:${event.role}:${event.textDelta}:${event.completed}"
        is AgentToolEvent -> "tool:${event.sequence}:${event.toolCallId}:${event.title}:${event.status}:${event.details.toSortedMap()}"
        is AgentPermissionEvent -> "permission:${event.sequence}:${event.requestId}:${event.decision}:${event.selectedOptionId}:${event.reason}"
        is AgentFileChangeEvent -> "change:${event.sequence}:${changeProjection(event.change)}"
        is AgentPlanEvent -> "plan:${event.sequence}:${event.entries}"
        is AgentContextUsageEvent -> "usage:${event.sequence}:${event.usedTokens}:${event.contextWindowTokens}:${event.costAmount}:${event.costCurrency}"
    }

    private data class OutcomeProjection(
        val kind: String,
        val stopReason: String?,
        val summary: String?,
        val changes: List<String>,
        val inputTokens: Long?,
        val outputTokens: Long?,
        val cachedInputTokens: Long?,
        val toolCalls: Int?,
        val session: String?,
        val failureKind: String?,
        val failureMessage: String?,
        val failureRetryable: Boolean?,
        val failureDetails: Map<String, String>,
    )

    private fun outcomeProjection(receipt: AgentExecutionReceipt): OutcomeProjection = when (val outcome = receipt.outcome) {
        is AgentExecutionOutcome.Returned -> outcome.result.let { result -> OutcomeProjection(
            "returned", result.stopReason.name, result.summary, result.changes.map(::changeProjection),
            result.usage?.inputTokens, result.usage?.outputTokens, result.usage?.cachedInputTokens, result.usage?.toolCalls,
            result.session?.toString(), null, null, null, emptyMap(),
        ) }
        is AgentExecutionOutcome.Failed -> outcome.failure.let { failure -> OutcomeProjection(
            "failed", null, null, emptyList(), null, null, null, null,
            null, failure.kind.name, failure.message, failure.retryable, failure.details.toSortedMap(),
        ) }
    }

    private fun expectedChange(text: String) = changeProjection(AgentFileChange(
        sourcePath, AgentFileChangeKind.MODIFIED, hash("old".toByteArray()), hash(text.toByteArray()), text.toByteArray().size.toLong()))

    private fun verifyOutcomeClock(receipt: AgentExecutionReceipt, request: AgentExecutionRequest) {
        val result = receipt.requireResult()
        val usage = result.usage ?: error("returned usage is missing")
        val wallClock = usage.wallClock ?: error("returned wall-clock usage is missing")
        assertTrue(!wallClock.isNegative && wallClock <= request.limits.wallClockTimeout)
    }

    private fun changeProjection(change: AgentFileChange) =
        "${change.path.rootId}:${change.path.relativePath}:${change.kind}:${change.beforeSha256}:${change.afterSha256}:${change.sizeBytes}"

    private fun projectionFixture(remaining: Long = 11, overall: Long = 12,
        previous: String = "d".repeat(64), frameHash: String = "e".repeat(64),
        contextHash: String = "a".repeat(64), requestTimeoutNanos: Long = 30) = buildJsonObject {
        put("version", 1); put("sequence", 1); put("previous", previous); put("kind", "MODEL_REQUEST")
        putJsonObject("payload") {
            put("contextSha256", contextHash)
            putJsonObject("remaining") { put("wallClockNanos", remaining); put("turns", 3) }
            putJsonObject("providerLimits") { put("overallTimeoutNanos", overall); put("requestTimeoutNanos", requestTimeoutNanos) }
        }
        put("sha256", frameHash)
    }

    private fun checkpointProjectionFixture(remaining: Long = 11, deadline: Long = 13, elapsed: Long = 14,
        contextHash: String = "a".repeat(64)) = buildJsonObject {
        val state = buildJsonObject {
            put("remainingWallClockNanos", remaining); put("deadlineEpochMillis", deadline)
            put("elapsedWallClockNanos", elapsed); put("contextSha256", contextHash)
            put("providerLimits", buildJsonObject { put("requestTimeoutNanos", 30) })
        }
        put("version", 1); put("sequence", 2); put("previous", "c".repeat(64)); put("kind", "CHECKPOINT")
        put("payload", buildJsonObject { put("resumeState", state); put("stateSha256", checkpointStateHash(state, 1024)) })
        put("sha256", "d".repeat(64))
    }

    private fun initialCheckpointFixture(remaining: Long, turns: Int = 3) = buildJsonObject {
        put("version", 1); put("sequence", 2); put("previous", "c".repeat(64)); put("kind", "CHECKPOINT")
        putJsonObject("payload") { putJsonObject("remaining") { put("wallClockNanos", remaining); put("turns", turns) } }
        put("sha256", "d".repeat(64))
    }

    private fun verifyFixtureCheckpoint(record: JsonObject) {
        val payload = record.getValue("payload").jsonObject
        val state = payload.getValue("resumeState").jsonObject
        assertEquals(JsonPrimitive(checkpointStateHash(state, 1024)), payload.getValue("stateSha256"))
        assertTrue(state.getValue("remainingWallClockNanos").jsonPrimitive.long > 0)
        assertTrue(state.getValue("deadlineEpochMillis").jsonPrimitive.long > 0)
        assertTrue(state.getValue("elapsedWallClockNanos").jsonPrimitive.long >= 0)
    }

    private fun privateDirectory(path: Path): Path {
        Files.createDirectory(path)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
        return path
    }

    private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { byte -> "%02x".format(byte) }
}
