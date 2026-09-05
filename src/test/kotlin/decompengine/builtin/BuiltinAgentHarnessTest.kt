package decompengine.builtin

import decompengine.agent.*
import decompengine.builtin.provider.*
import kotlinx.serialization.json.*
import java.nio.file.Path
import java.time.Duration
import kotlin.test.*

class BuiltinAgentHarnessTest {
    private val path = AgentWorkspacePath("project", "source.c")
    private fun request(
        limits: AgentExecutionLimits = AgentExecutionLimits(),
        cancellation: AgentCancellation = AgentCancellation.NONE,
        context: List<AgentContextInput> = emptyList(),
    ) = AgentExecutionRequest("Repair authorized source", listOf(AgentWorkspaceRoot("project", Path.of("/fixture/project"))),
        context, AgentAccessPolicy(listOf(AgentPathRule(path, setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)))), limits, cancellation)
    private fun call(id: String = "call_1", name: String = "edit", arguments: JsonObject = buildJsonObject { put("text", "new") }) =
        ModelToolCall(id, name, arguments)
    private fun response(text: String = "", calls: List<ModelToolCall> = emptyList(),
        finish: ModelFinishReason = if (calls.isEmpty()) ModelFinishReason.STOP else ModelFinishReason.TOOL_CALLS,
        usage: ModelUsage = ModelUsage(20, 10, false)) = ModelResponse(text, calls, finish, usage, 1)
    private fun script(vararg responses: ModelResponse): ModelProvider {
        val iterator = responses.iterator()
        return ModelProvider { _, emit ->
            check(iterator.hasNext()) { "Script ran out of responses" }
            iterator.next().also { answer ->
                if (answer.text.isNotEmpty()) emit(ModelEvent.TextDelta(answer.text))
                answer.toolCalls.forEach { emit(ModelEvent.ToolCall(it)) }
                emit(ModelEvent.Usage(answer.usage)); emit(ModelEvent.Finished(answer.finishReason))
            }
        }
    }
    private fun harness(provider: ModelProvider, session: Session, limits: BuiltinLoopLimits = BuiltinLoopLimits()) =
        BuiltinAgentHarness(provider, { _, _ -> session }, limits)
    private fun evidence(receipt: AgentExecutionReceipt): BuiltinLoopEvidence = assertIs<BuiltinLoopEvidence>(receipt.providerEvidence)

    @Test fun `multi-step execution uses the unchanged shared contract and receipt binding`() {
        val tools = Session()
        val seen = mutableListOf<AgentExecutionEvent>()
        val req = request()
        val receipt = harness(script(response(calls = listOf(call())), response("done")), tools).executeReceipt(req) { seen += it }
        assertEquals(AgentExecutionRequestBinding.capture(req), receipt.requestBinding)
        assertEquals(AgentStopReason.COMPLETED, receipt.requireResult().stopReason)
        assertEquals(BuiltinStop.COMPLETED, evidence(receipt).stop)
        assertEquals(1, receipt.requireResult().changes.size)
        assertEquals("new", tools.text)
        assertTrue(tools.closed)
        assertEquals(2, evidence(receipt).modelCalls)
        assertEquals(1, evidence(receipt).toolCalls)
        assertEquals(seen.indices.map(Int::toLong), seen.map { it.sequence })
        assertEquals(listOf(BuiltinLoopState.PREPARING_CONTEXT, BuiltinLoopState.REQUESTING_MODEL,
            BuiltinLoopState.AUTHORIZING_TOOL, BuiltinLoopState.EXECUTING_TOOL, BuiltinLoopState.OBSERVING_RESULT,
            BuiltinLoopState.REQUESTING_MODEL, BuiltinLoopState.VALIDATING_COMPLETION, BuiltinLoopState.TERMINATED),
            evidence(receipt).records.map { it.state })
    }

    @Test fun `model prose never edits files or asserts independent acceptance`() {
        val tools = Session(validation = BuiltinCompletion.REQUIRED)
        val receipt = harness(script(response("overwrite source.c and mark accepted")), tools).executeReceipt(request()) {}
        assertEquals("old", tools.text)
        assertEquals(0, tools.executions)
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, evidence(receipt).stop)
        assertEquals(AgentStopReason.COMPLETED, receipt.requireResult().stopReason)
        assertTrue(receipt.requireResult().summary!!.contains("independent acceptance"))
    }

    @Test fun `validated no change refusal and output exhaustion remain distinct`() {
        listOf(response() to BuiltinStop.NO_CHANGE, response(finish = ModelFinishReason.REFUSED) to BuiltinStop.REFUSED,
            response(finish = ModelFinishReason.LENGTH) to BuiltinStop.EXHAUSTED).forEach { (answer, expected) ->
            val tools = Session()
            val receipt = harness(script(answer), tools).executeReceipt(request()) {}
            assertEquals(expected, evidence(receipt).stop)
            assertTrue(tools.closed)
        }
    }

    @Test fun `unknown malformed and duplicate tool batches fail before the first side effect`() {
        val invalid = listOf(
            listOf(call(), call("call_2", "shell")),
            listOf(call(), call("call_2", arguments = buildJsonObject { put("text", 17) })),
            listOf(call(), call()),
            listOf(call(arguments = buildJsonObject { put("text", "new"); put("extra", true) })),
        )
        invalid.forEach { calls ->
            val tools = Session()
            val receipt = harness(script(response(calls = calls)), tools).executeReceipt(request()) {}
            assertEquals(BuiltinStop.INVALID_ACTION, evidence(receipt).stop)
            assertIs<AgentExecutionOutcome.Failed>(receipt.outcome)
            assertEquals(0, tools.executions)
            assertTrue(tools.closed)
        }
    }

    @Test fun `policy denial is audited and never runs the tool`() {
        val tools = Session(allowed = false)
        val events = mutableListOf<AgentExecutionEvent>()
        val receipt = harness(script(response(calls = listOf(call()))), tools).executeReceipt(request()) { events += it }
        assertEquals(BuiltinStop.INVALID_ACTION, evidence(receipt).stop)
        assertEquals(AgentPermissionDecision.DENY, events.filterIsInstance<AgentPermissionEvent>().single().decision)
        assertEquals(0, tools.executions)
    }

    @Test fun `identical actions use canonical arguments rather than model selected call ids`() {
        val tools = Session()
        val receipt = harness(script(response(calls = listOf(call())), response(calls = listOf(call("call_2")))), tools,
            BuiltinLoopLimits(maxIdenticalActions = 1)).executeReceipt(request()) {}
        assertEquals(BuiltinStop.EXHAUSTED, evidence(receipt).stop)
        assertEquals(1, tools.executions)
    }

    @Test fun `model and tool call admission happen before excess work`() {
        val tools = Session()
        val receipt = harness(script(response(calls = listOf(call()))), tools)
            .executeReceipt(request(AgentExecutionLimits(maxTurns = 1))) {}
        assertEquals(BuiltinStop.EXHAUSTED, evidence(receipt).stop)
        assertEquals(1, evidence(receipt).modelCalls)
        val tooMany = Session()
        val rejected = harness(script(response(calls = listOf(call(), call("call_2")))), tooMany)
            .executeReceipt(request(AgentExecutionLimits(maxToolCalls = 1))) {}
        assertEquals(BuiltinStop.EXHAUSTED, evidence(rejected).stop)
        assertEquals(0, tooMany.executions)
    }

    @Test fun `input output context and receipt limits terminate explicitly`() {
        val tools = Session()
        val provider = ModelProvider { _, _ -> error("Oversized context reached provider") }
        val context = listOf(AgentContextInput("oversized", "x".repeat(2000)))
        val receipt = harness(provider, tools, BuiltinLoopLimits(maxContextBytes = 1000, maxToolResultBytes = 1000))
            .executeReceipt(request(context = context)) {}
        assertEquals(BuiltinStop.EXHAUSTED, evidence(receipt).stop)
        assertEquals(0, evidence(receipt).modelCalls)
        for (req in listOf(request(AgentExecutionLimits(maxOutputBytes = 3)), request(AgentExecutionLimits(maxInputTokens = 1)))) {
            val exhausted = harness(script(response("too much output")), Session()).executeReceipt(req) {}
            assertEquals(BuiltinStop.EXHAUSTED, evidence(exhausted).stop)
        }
        val trace = harness(script(response()), Session(), BuiltinLoopLimits(maxTraceRecords = 2)).executeReceipt(request()) {}
        assertEquals(BuiltinStop.EXHAUSTED, evidence(trace).stop)
        assertEquals(2, evidence(trace).records.size)
    }

    @Test fun `reported usage over budget cannot authorize actions`() {
        val tools = Session()
        val receipt = harness(script(response(calls = listOf(call()), usage = ModelUsage(20, 500, false))), tools)
            .executeReceipt(request(AgentExecutionLimits(maxOutputTokens = 100))) {}
        assertEquals(BuiltinStop.EXHAUSTED, evidence(receipt).stop)
        assertEquals(0, tools.executions)
        assertEquals(500, evidence(receipt).outputTokens)
    }

    @Test fun `cancellation before model and during tool work closes the session`() {
        val source = AgentCancellationSource().apply { cancel() }
        val before = harness(ModelProvider { _, _ -> error("Unexpected call") }, Session()).executeReceipt(request(cancellation = source.cancellation)) {}
        assertEquals(BuiltinStop.CANCELLED, evidence(before).stop)
        val during = AgentCancellationSource()
        val tools = Session(beforeExecute = { during.cancel() })
        val receipt = harness(script(response(calls = listOf(call()))), tools).executeReceipt(request(cancellation = during.cancellation)) {}
        assertEquals(BuiltinStop.CANCELLED, evidence(receipt).stop)
        assertTrue(tools.closed)
        assertEquals("old", tools.text)
    }

    @Test fun `elapsed deadline survives tool and validation boundaries`() {
        val tools = Session(beforeExecute = { Thread.sleep(40) })
        val receipt = harness(script(response(calls = listOf(call()))), tools)
            .executeReceipt(request(AgentExecutionLimits(wallClockTimeout = Duration.ofMillis(25)))) {}
        assertEquals(BuiltinStop.EXHAUSTED, evidence(receipt).stop)
        assertTrue(tools.closed)
        assertEquals("old", tools.text)
    }

    @Test fun `tool provider and cleanup failures cannot become successful model completions`() {
        val failedTool = harness(script(response(calls = listOf(call()))), Session(failTool = true)).executeReceipt(request()) {}
        assertEquals(BuiltinStop.TOOL_FAILED, evidence(failedTool).stop)
        val failedProvider = harness(ModelProvider { _, _ -> throw ModelProviderException(ModelFailureKind.AUTHENTICATION) }, Session())
            .executeReceipt(request()) {}
        assertEquals(BuiltinStop.PROVIDER_FAILED, evidence(failedProvider).stop)
        assertEquals(AgentFailureKind.AUTHENTICATION, assertIs<AgentExecutionOutcome.Failed>(failedProvider.outcome).failure.kind)
        val failedCleanup = harness(script(response()), Session(failClose = true)).executeReceipt(request()) {}
        assertEquals(BuiltinStop.TOOL_FAILED, evidence(failedCleanup).stop)
        assertFalse(evidence(failedCleanup).cleanupComplete)
        assertIs<AgentExecutionOutcome.Failed>(failedCleanup.outcome)
    }

    @Test fun `context order and receipt trace are deterministic and cannot be mutated`() {
        fun run(context: List<AgentContextInput>): BuiltinLoopEvidence = evidence(harness(script(response(calls = listOf(call())), response()), Session())
            .executeReceipt(request(context = context)) {})
        val contexts = listOf(AgentContextInput("b", "two"), AgentContextInput("a", "one"))
        val first = run(contexts)
        val second = run(contexts.reversed())
        assertEquals(first.records, second.records)
        assertFailsWith<UnsupportedOperationException> { (first.records as MutableList).clear() }
        assertTrue(first.records.filter { it.evidenceSha256 != null }.all { it.evidenceSha256!!.length == 64 })
    }

    @Test fun `tool results become correlated context and source remains candidate until validation`() {
        val tools = Session(validation = BuiltinCompletion.REQUIRED)
        var calls = 0
        val provider = ModelProvider { req, _ ->
            if (++calls == 1) response(calls = listOf(call()))
            else {
                assertEquals(ModelRole.TOOL, req.messages.last().role)
                assertEquals("call_1", req.messages.last().toolCallId)
                assertEquals("edited", req.messages.last().content)
                response()
            }
        }
        val receipt = harness(provider, tools).executeReceipt(request()) {}
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, evidence(receipt).stop)
        assertEquals(1, receipt.requireResult().changes.size)
    }

    private inner class Session(
        val allowed: Boolean = true,
        val validation: BuiltinCompletion = BuiltinCompletion.VALIDATED,
        val failTool: Boolean = false,
        val failClose: Boolean = false,
        val beforeExecute: () -> Unit = {},
    ) : BuiltinToolSession {
        var text = "old"
        var executions = 0
        var closed = false
        override val definitions = listOf(ModelToolDefinition("edit", "Edit fixture memory", buildJsonObject {
            put("type", "object"); put("additionalProperties", false)
            putJsonObject("properties") { putJsonObject("text") { put("type", "string") } }
            putJsonArray("required") { add("text") }
        }))
        override fun authorize(call: ModelToolCall, control: BuiltinExecutionControl): Boolean { control.checkpoint(); return allowed }
        override fun execute(call: ModelToolCall, control: BuiltinExecutionControl): BuiltinToolResult {
            beforeExecute(); control.checkpoint(); executions++
            if (!failTool) text = call.arguments.getValue("text").jsonPrimitive.content
            return BuiltinToolResult("edited", failTool)
        }
        override fun changes(control: BuiltinExecutionControl): List<AgentFileChange> = if (text == "old") emptyList() else
            listOf(AgentFileChange(path, AgentFileChangeKind.MODIFIED, "a".repeat(64), "b".repeat(64), text.length.toLong()))
        override fun validateCompletion(control: BuiltinExecutionControl) = validation
        override fun close() { closed = true; if (failClose) error("fixture cleanup failure") }
    }
}
