package decompengine.agent

import decompengine.project.sha256
import java.nio.file.Files
import java.time.Duration
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class AgentExecutionContractTest {
    @Test
    fun `request snapshots absolute workspaces immutable context access and execution limits`() {
        val workspace = createTempDirectory("agent-contract-request-").toAbsolutePath().normalize()
        val roots = mutableListOf(AgentWorkspaceRoot("project", workspace))
        val context = mutableListOf(AgentContextInput("evidence", "immutable evidence"))
        val source = AgentWorkspacePath("project", "src/module.c")
        val policy = AgentAccessPolicy(
            listOf(AgentPathRule(source, setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE))),
        )
        val limits = AgentExecutionLimits(
            wallClockTimeout = Duration.ofSeconds(30),
            idleTimeout = Duration.ofSeconds(5),
            maxTurns = 3,
            maxToolCalls = 4,
            maxOutputBytes = 1_024,
            maxInputTokens = 200,
            maxOutputTokens = 100,
        )

        val request = AgentExecutionRequest("repair module", roots, context, policy, limits)
        roots.clear()
        context.clear()

        assertEquals(AGENT_EXECUTION_CONTRACT_VERSION, request.schemaVersion)
        assertEquals(listOf("project"), request.workspaceRoots.map { it.id })
        assertEquals("immutable evidence", request.contextInputs.single().content)
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (request.contextInputs as MutableList<AgentContextInput>).clear()
        }
        assertTrue(request.accessPolicy.allows(source, AgentOperation.READ_FILE))
        assertFalse(request.accessPolicy.allows(source, AgentOperation.DELETE_FILE))
        assertEquals(3, request.limits.maxTurns)
        assertFailsWith<IllegalArgumentException> { AgentWorkspacePath("project", "../outside.c") }
        assertFailsWith<IllegalArgumentException> {
            AgentWorkspaceRoot("relative", java.nio.file.Path.of("relative"))
        }
    }

    @Test
    fun `deterministic fake streams every event shape and reports workspace changes as results`() {
        val fixture = fixture("old source\n")
        val session = AgentSessionReference("scripted-fake", "session-1", "resume-1")
        val script = FakeAgentScript(
            events = listOf(
                AgentMessageEvent(0, "message-1", AgentMessageRole.ASSISTANT, "working"),
                AgentPlanEvent(1, listOf(AgentPlanEntry("edit", "Edit the module", AgentPlanStatus.IN_PROGRESS))),
                AgentToolEvent(2, "tool-1", "Read module", AgentToolStatus.SUCCEEDED, mapOf("bytes" to "11")),
                AgentPermissionEvent(3, "permission-1", AgentPermissionDecision.DENY, "deny", "command not allowed"),
            ),
            edits = listOf(FakeWorkspaceEdit(AgentWorkspacePath("project", "src/module.c"), "new source\n")),
            stopReason = AgentStopReason.COMPLETED,
            summary = "updated module",
            session = session,
            usage = AgentUsage(inputTokens = 10, outputTokens = 4, cachedInputTokens = 2, toolCalls = 1),
        )
        val harness = DeterministicFakeAgentHarness(script)
        val events = mutableListOf<AgentExecutionEvent>()

        val result = harness.execute(fixture.request, events::add)

        assertEquals(listOf(0L, 1L, 2L, 3L, 4L), events.map { it.sequence })
        assertIs<AgentMessageEvent>(events[0])
        assertIs<AgentPlanEvent>(events[1])
        assertIs<AgentToolEvent>(events[2])
        assertIs<AgentPermissionEvent>(events[3])
        assertIs<AgentFileChangeEvent>(events[4])
        assertEquals(AgentStopReason.COMPLETED, result.stopReason)
        assertEquals(session, result.session)
        assertEquals(4, result.usage?.outputTokens)
        assertEquals(AgentFileChangeKind.MODIFIED, result.changes.single().kind)
        assertEquals("new source\n", fixture.file.toFile().readText())
        assertEquals(result.changes.single(), (events.last() as AgentFileChangeEvent).change)
        assertEquals(listOf(fixture.request), harness.requests)
    }

    @Test
    fun `deterministic fake covers no-change and refusal stops without fabricating changes`() {
        val fixture = fixture("unchanged\n")
        val harness = DeterministicFakeAgentHarness(
            FakeAgentScript(stopReason = AgentStopReason.NO_CHANGES, summary = "nothing to do"),
            FakeAgentScript(stopReason = AgentStopReason.REFUSED, summary = "objective refused"),
        )

        val noChange = harness.execute(fixture.request)
        val refused = harness.execute(fixture.request)

        assertEquals(AgentStopReason.NO_CHANGES, noChange.stopReason)
        assertTrue(noChange.changes.isEmpty())
        assertEquals(AgentStopReason.REFUSED, refused.stopReason)
        assertTrue(refused.changes.isEmpty())
        assertEquals("unchanged\n", fixture.file.toFile().readText())
    }

    @Test
    fun `deterministic fake observes cancellation before executing a script`() {
        val fixture = fixture("unchanged\n")
        val source = AgentCancellationSource()
        val request = AgentExecutionRequest(
            fixture.request.objective,
            fixture.request.workspaceRoots,
            fixture.request.contextInputs,
            fixture.request.accessPolicy,
            fixture.request.limits,
            source.cancellation,
        )
        val harness = DeterministicFakeAgentHarness(
            FakeAgentScript(
                edits = listOf(FakeWorkspaceEdit(AgentWorkspacePath("project", "src/module.c"), "must not be written\n")),
                stopReason = AgentStopReason.COMPLETED,
            ),
        )
        source.cancel()

        val result = harness.execute(request)

        assertEquals(AgentStopReason.CANCELLED, result.stopReason)
        assertTrue(result.changes.isEmpty())
        assertEquals("unchanged\n", fixture.file.toFile().readText())
    }

    @Test
    fun `deterministic fake distinguishes limit exhaustion from typed execution failure`() {
        val fixture = fixture("unchanged\n")
        val harness = DeterministicFakeAgentHarness(
            FakeAgentScript(
                stopReason = AgentStopReason.LIMIT_EXHAUSTED,
                summary = "turn limit reached",
                usage = AgentUsage(inputTokens = 40, outputTokens = 20, toolCalls = 4),
            ),
            FakeAgentScript(
                failure = AgentFailure(
                    AgentFailureKind.TRANSPORT,
                    "fake transport closed",
                    retryable = true,
                    details = mapOf("phase" to "stream"),
                ),
            ),
        )

        val limited = harness.execute(fixture.request)
        val failure = assertFailsWith<AgentExecutionException> { harness.execute(fixture.request) }

        assertEquals(AgentStopReason.LIMIT_EXHAUSTED, limited.stopReason)
        assertEquals(4, limited.usage?.toolCalls)
        assertEquals(AgentFailureKind.TRANSPORT, failure.failure.kind)
        assertTrue(failure.failure.retryable)
        assertEquals("stream", failure.failure.details["phase"])
    }

    private data class Fixture(
        val request: AgentExecutionRequest,
        val file: java.nio.file.Path,
    )

    private fun fixture(content: String): Fixture {
        val workspace = createTempDirectory("agent-contract-").toAbsolutePath().normalize()
        val file = workspace.resolve("src/module.c")
        file.parent.createDirectories()
        file.writeText(content)
        val path = AgentWorkspacePath("project", "src/module.c")
        return Fixture(
            AgentExecutionRequest(
                objective = "edit the module",
                workspaceRoots = listOf(AgentWorkspaceRoot("project", workspace)),
                contextInputs = listOf(AgentContextInput("evidence", "compiler output")),
                accessPolicy = AgentAccessPolicy(
                    listOf(AgentPathRule(path, setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE))),
                ),
            ),
            file,
        )
    }
}

private data class FakeWorkspaceEdit(
    val path: AgentWorkspacePath,
    val replacement: String?,
)

private data class FakeAgentScript(
    val events: List<AgentExecutionEvent> = emptyList(),
    val edits: List<FakeWorkspaceEdit> = emptyList(),
    val stopReason: AgentStopReason = AgentStopReason.COMPLETED,
    val summary: String? = null,
    val session: AgentSessionReference? = null,
    val usage: AgentUsage? = null,
    val failure: AgentFailure? = null,
)

private class DeterministicFakeAgentHarness(vararg scripts: FakeAgentScript) : AgentHarness {
    private val scripts = ArrayDeque(scripts.toList())
    val requests = mutableListOf<AgentExecutionRequest>()

    override fun implementationIdentifier(): String = "scripted-fake"

    override fun execute(
        request: AgentExecutionRequest,
        onEvent: (AgentExecutionEvent) -> Unit,
    ): AgentExecutionResult {
        requests += request
        val script = scripts.removeFirstOrNull() ?: error("unexpected fake execution")
        if (request.cancellation.isCancellationRequested()) {
            return AgentExecutionResult(AgentStopReason.CANCELLED, "cancelled before scripted execution")
        }
        script.failure?.let { throw AgentExecutionException(it) }
        script.events.forEach(onEvent)
        var sequence = (script.events.maxOfOrNull { it.sequence } ?: -1) + 1
        val changes = script.edits.map { edit ->
            val target = edit.path.resolve(request.workspaceRoots)
            val before = target.takeIf { it.exists() }?.readBytes()
            val operation = when {
                edit.replacement == null -> AgentOperation.DELETE_FILE
                before == null -> AgentOperation.CREATE_FILE
                else -> AgentOperation.WRITE_FILE
            }
            require(request.accessPolicy.allows(edit.path, operation)) { "scripted edit is unauthorized: ${edit.path}" }
            if (edit.replacement == null) Files.delete(target)
            else {
                target.parent.createDirectories()
                target.writeText(edit.replacement)
            }
            val after = target.takeIf { it.exists() }?.readBytes()
            val change = AgentFileChange(
                path = edit.path,
                kind = when {
                    before == null -> AgentFileChangeKind.CREATED
                    after == null -> AgentFileChangeKind.DELETED
                    else -> AgentFileChangeKind.MODIFIED
                },
                beforeSha256 = before?.let(::sha256),
                afterSha256 = after?.let(::sha256),
                sizeBytes = after?.size?.toLong(),
            )
            onEvent(AgentFileChangeEvent(sequence++, change))
            change
        }
        return AgentExecutionResult(script.stopReason, script.summary, changes, script.session, script.usage)
    }
}
