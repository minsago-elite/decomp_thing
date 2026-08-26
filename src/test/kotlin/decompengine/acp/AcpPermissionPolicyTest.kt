package decompengine.acp

import com.agentclientprotocol.model.PermissionOption
import com.agentclientprotocol.model.PermissionOptionId
import com.agentclientprotocol.model.PermissionOptionKind
import com.agentclientprotocol.model.RequestPermissionOutcome
import com.agentclientprotocol.model.SessionUpdate
import com.agentclientprotocol.model.ToolCallId
import com.agentclientprotocol.model.ToolCallStatus
import com.agentclientprotocol.model.ToolKind
import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentCancellation
import decompengine.agent.AgentCancellationSource
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentOperation
import decompengine.agent.AgentWorkspaceRoot
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlinx.coroutines.runBlocking

class AcpPermissionPolicyTest {
    @Test
    fun `noninteractive default selects an offered rejection and never expands authority`() {
        runBlocking {
            val audit = AcpPermissionAuditRecorder()
            val broker = AcpPermissionBroker(
                request(allowPermission = true),
                AgentCancellation.NONE,
                AcpNonInteractivePermissionDecider.DEFAULT_DENY,
                audit,
            )

            val resolved = broker.decide(SESSION, tool(), options())

            val selected = assertIs<RequestPermissionOutcome.Selected>(resolved.response.outcome)
            assertEquals("reject", selected.optionId.value)
            val decision = audit.snapshot().single()
            assertEquals(AcpPermissionAuditOutcome.DENIED, decision.outcome)
            assertEquals(AcpPermissionAuditReason.DEFAULT_DENY, decision.reason)
            assertFalse(decision.authorityExpanded)
            assertFalse(decision.toString().contains("Run exact command"))
        }
    }

    @Test
    fun `interactive allow must select an actually offered id and allow-always stays advisory`() {
        runBlocking {
            val allowedAudit = AcpPermissionAuditRecorder()
            val allowed = AcpPermissionBroker(
                request(allowPermission = true),
                AgentCancellation.NONE,
                AcpPermissionDecider { AcpPermissionChoice.Select("always") },
                allowedAudit,
            ).decide(SESSION, tool(), options())
            assertEquals("always", assertIs<RequestPermissionOutcome.Selected>(allowed.response.outcome).optionId.value)
            assertEquals(PermissionOptionKind.ALLOW_ALWAYS, allowedAudit.snapshot().single().selectedKind)
            assertFalse(allowedAudit.snapshot().single().authorityExpanded)

            val invalidAudit = AcpPermissionAuditRecorder()
            val invalid = AcpPermissionBroker(
                request(allowPermission = true),
                AgentCancellation.NONE,
                AcpPermissionDecider { AcpPermissionChoice.Select("not-offered") },
                invalidAudit,
            ).decide(SESSION, tool(), options())
            assertIs<RequestPermissionOutcome.Cancelled>(invalid.response.outcome)
            assertEquals(AcpPermissionAuditReason.INVALID_DECIDER_SELECTION, invalidAudit.snapshot().single().reason)
        }
    }

    @Test
    fun `workflow denial overrides interactive allow and chooses only an offered reject`() {
        runBlocking {
            val audit = AcpPermissionAuditRecorder()
            val resolved = AcpPermissionBroker(
                request(allowPermission = false),
                AgentCancellation.NONE,
                AcpPermissionDecider { AcpPermissionChoice.Select("allow") },
                audit,
            ).decide(SESSION, tool(), options())

            assertEquals("reject", assertIs<RequestPermissionOutcome.Selected>(resolved.response.outcome).optionId.value)
            assertEquals(AcpPermissionAuditReason.WORKFLOW_POLICY_DENIED, audit.snapshot().single().reason)
            assertFalse(audit.snapshot().single().authorityExpanded)
        }
    }

    @Test
    fun `narrow noninteractive rules match title kind name and option kind exactly`() {
        runBlocking {
            val decider = AcpNonInteractivePermissionDecider(
                listOf(
                    AcpPermissionRule(
                        exactToolTitle = "Run exact command",
                        toolKind = ToolKind.EXECUTE,
                        exactOptionName = "Allow once",
                    ),
                ),
            )
            val matching = decider.decide(
                AcpPermissionDecisionContext(
                    SESSION,
                    "tool-1",
                    "Run exact command",
                    ToolKind.EXECUTE,
                    listOf(AcpOfferedPermissionOption("allow", "Allow once", PermissionOptionKind.ALLOW_ONCE)),
                ),
            )
            assertEquals(AcpPermissionChoice.Select("allow"), matching)

            val wrongTitle = decider.decide(
                AcpPermissionDecisionContext(
                    SESSION,
                    "tool-1",
                    "Run another command",
                    ToolKind.EXECUTE,
                    listOf(AcpOfferedPermissionOption("allow", "Allow once", PermissionOptionKind.ALLOW_ONCE)),
                ),
            )
            assertEquals(AcpPermissionChoice.Cancel, wrongTitle)
        }
    }

    @Test
    fun `invalid offers decider failures and cancellation fail closed with metadata audit`() {
        runBlocking {
            val duplicateAudit = AcpPermissionAuditRecorder()
            val duplicate = AcpPermissionBroker(
                request(true),
                AgentCancellation.NONE,
                AcpPermissionDecider { AcpPermissionChoice.Select("allow") },
                duplicateAudit,
            ).decide(
                SESSION,
                tool(),
                listOf(
                    PermissionOption(PermissionOptionId("same"), "Allow", PermissionOptionKind.ALLOW_ONCE),
                    PermissionOption(PermissionOptionId("same"), "Reject", PermissionOptionKind.REJECT_ONCE),
                ),
            )
            assertIs<RequestPermissionOutcome.Cancelled>(duplicate.response.outcome)
            assertEquals(AcpPermissionAuditReason.INVALID_OFFER, duplicateAudit.snapshot().single().reason)

            val failureAudit = AcpPermissionAuditRecorder()
            val failure = AcpPermissionBroker(
                request(true),
                AgentCancellation.NONE,
                AcpPermissionDecider { throw IllegalStateException("sensitive decider failure") },
                failureAudit,
            ).decide(SESSION, tool(), options())
            assertIs<RequestPermissionOutcome.Cancelled>(failure.response.outcome)
            assertEquals(AcpPermissionAuditReason.DECIDER_FAILED, failureAudit.snapshot().single().reason)

            val cancellation = AgentCancellationSource().also { it.cancel() }
            val cancellationAudit = AcpPermissionAuditRecorder()
            val cancelled = AcpPermissionBroker(
                request(true),
                cancellation.cancellation,
                AcpPermissionDecider { AcpPermissionChoice.Select("allow") },
                cancellationAudit,
            ).decide(SESSION, tool(), options())
            assertIs<RequestPermissionOutcome.Cancelled>(cancelled.response.outcome)
            assertEquals(AcpPermissionAuditReason.REQUEST_CANCELLED, cancellationAudit.snapshot().single().reason)
            assertFalse(cancellationAudit.snapshot().toString().contains("sensitive decider failure"))

            val boundedAudit = AcpPermissionAuditRecorder(maximumRecords = 1)
            val boundedBroker = AcpPermissionBroker(
                request(true),
                AgentCancellation.NONE,
                AcpNonInteractivePermissionDecider.DEFAULT_DENY,
                boundedAudit,
            )
            boundedBroker.decide(SESSION, tool(), options())
            assertFailsWith<AcpProtocolFailure> {
                boundedBroker.decide(SESSION, tool(), options())
            }
            assertEquals(1, boundedAudit.snapshot().size, "permission audit evidence must remain bounded")
        }
    }

    private fun options(): List<PermissionOption> = listOf(
        PermissionOption(PermissionOptionId("allow"), "Allow once", PermissionOptionKind.ALLOW_ONCE),
        PermissionOption(PermissionOptionId("always"), "Always", PermissionOptionKind.ALLOW_ALWAYS),
        PermissionOption(PermissionOptionId("reject"), "Reject once", PermissionOptionKind.REJECT_ONCE),
    )

    private fun tool(): SessionUpdate.ToolCallUpdate = SessionUpdate.ToolCallUpdate(
        toolCallId = ToolCallId("tool-1"),
        title = "Run exact command",
        kind = ToolKind.EXECUTE,
        status = ToolCallStatus.PENDING,
    )

    private fun request(allowPermission: Boolean): AgentExecutionRequest {
        val root = createTempDirectory("acp-permission-").toAbsolutePath().normalize()
        return AgentExecutionRequest(
            objective = "permission fixture",
            workspaceRoots = listOf(AgentWorkspaceRoot("fixture", root)),
            accessPolicy = AgentAccessPolicy(
                emptyList(),
                if (allowPermission) setOf(AgentOperation.REQUEST_PERMISSION) else emptySet(),
            ),
        )
    }

    private companion object {
        const val SESSION = "permission-fixture-session"
    }
}
