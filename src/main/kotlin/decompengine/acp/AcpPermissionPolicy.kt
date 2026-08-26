package decompengine.acp

import com.agentclientprotocol.model.PermissionOption
import com.agentclientprotocol.model.PermissionOptionKind
import com.agentclientprotocol.model.RequestPermissionOutcome
import com.agentclientprotocol.model.RequestPermissionResponse
import com.agentclientprotocol.model.SessionUpdate
import com.agentclientprotocol.model.ToolKind
import decompengine.agent.AgentCancellation
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentOperation
import java.security.MessageDigest
import java.util.Collections
import kotlinx.coroutines.CancellationException

data class AcpOfferedPermissionOption(
    val optionId: String,
    val name: String,
    val kind: PermissionOptionKind,
)

class AcpPermissionDecisionContext(
    val sessionId: String,
    val toolCallId: String,
    val title: String?,
    val kind: ToolKind?,
    offeredOptions: Collection<AcpOfferedPermissionOption>,
) {
    val offeredOptions: List<AcpOfferedPermissionOption> =
        Collections.unmodifiableList(ArrayList(offeredOptions))
}

sealed interface AcpPermissionChoice {
    data class Select(val optionId: String) : AcpPermissionChoice {
        init {
            require(optionId.isNotBlank()) { "selected ACP permission option id must not be blank" }
        }
    }

    data object Cancel : AcpPermissionChoice
}

/** An interactive implementation may suspend while a trusted user chooses one offered option. */
fun interface AcpPermissionDecider {
    suspend fun decide(context: AcpPermissionDecisionContext): AcpPermissionChoice
}

/** One narrow non-interactive allow rule; all non-matches continue to default denial. */
class AcpPermissionRule(
    val exactToolTitle: String,
    val toolKind: ToolKind,
    val exactOptionName: String,
    val optionKind: PermissionOptionKind = PermissionOptionKind.ALLOW_ONCE,
) {
    init {
        require(exactToolTitle.isNotBlank()) { "permission rule tool title must not be blank" }
        require(exactOptionName.isNotBlank()) { "permission rule option name must not be blank" }
        require(optionKind == PermissionOptionKind.ALLOW_ONCE || optionKind == PermissionOptionKind.ALLOW_ALWAYS) {
            "non-interactive permission rules may select only explicit allow options"
        }
    }
}

class AcpNonInteractivePermissionDecider(
    rules: Collection<AcpPermissionRule> = emptyList(),
) : AcpPermissionDecider {
    val rules: List<AcpPermissionRule> = Collections.unmodifiableList(ArrayList(rules))

    init {
        val signatures = this.rules.map { rule ->
            listOf(rule.exactToolTitle, rule.toolKind.name, rule.exactOptionName, rule.optionKind.name)
        }
        require(signatures.distinct().size == signatures.size) { "permission rules must not be duplicates" }
    }

    override suspend fun decide(context: AcpPermissionDecisionContext): AcpPermissionChoice {
        val matchingRules = rules.filter { rule ->
            rule.exactToolTitle == context.title && rule.toolKind == context.kind
        }
        if (matchingRules.size == 1) {
            val rule = matchingRules.single()
            val matchingOptions = context.offeredOptions.filter { option ->
                option.name == rule.exactOptionName && option.kind == rule.optionKind
            }
            if (matchingOptions.size == 1) return AcpPermissionChoice.Select(matchingOptions.single().optionId)
        }
        return rejectOrCancel(context.offeredOptions)
    }

    companion object {
        /** Documented production default: select an offered reject option, otherwise cancel. */
        val DEFAULT_DENY: AcpNonInteractivePermissionDecider = AcpNonInteractivePermissionDecider()
    }
}

enum class AcpPermissionAuditOutcome { ALLOWED, DENIED, CANCELLED, FAILED }

enum class AcpPermissionAuditReason {
    SELECTED,
    DEFAULT_DENY,
    WORKFLOW_POLICY_DENIED,
    REQUEST_CANCELLED,
    NO_USABLE_OPTION,
    INVALID_OFFER,
    INVALID_DECIDER_SELECTION,
    DECIDER_FAILED,
}

/** No title, raw input/output, option label, or option id is retained. */
data class AcpPermissionAuditRecord(
    val sequence: Long,
    val sessionId: String,
    val toolCallIdSha256: String,
    val offeredOptionCount: Int,
    val selectedOptionIdSha256: String?,
    val selectedKind: PermissionOptionKind?,
    val outcome: AcpPermissionAuditOutcome,
    val reason: AcpPermissionAuditReason,
    val authorityExpanded: Boolean,
)

internal class AcpPermissionAuditRecorder(
    private val maximumRecords: Int = MAXIMUM_PERMISSION_AUDIT_RECORDS,
) {
    private val records = mutableListOf<AcpPermissionAuditRecord>()
    private var sequence = 0L
    private var overflowFailure: AcpProtocolFailure? = null

    init {
        require(maximumRecords > 0) { "maximum permission audit records must be positive" }
    }

    fun record(
        sessionId: String,
        toolCallId: String,
        optionCount: Int,
        selected: AcpOfferedPermissionOption?,
        outcome: AcpPermissionAuditOutcome,
        reason: AcpPermissionAuditReason,
    ) = synchronized(records) {
        overflowFailure?.let { throw it }
        if (records.size >= maximumRecords) {
            val failure = AcpProtocolFailure(
                "ACP permission audit exceeded the $maximumRecords-record evidence limit",
            )
            overflowFailure = failure
            throw failure
        }
        records += AcpPermissionAuditRecord(
            sequence = sequence++,
            sessionId = sessionId,
            toolCallIdSha256 = permissionSha256(toolCallId),
            offeredOptionCount = optionCount,
            selectedOptionIdSha256 = selected?.let { permissionSha256(it.optionId) },
            selectedKind = selected?.kind,
            outcome = outcome,
            reason = reason,
            // Permission responses are advisory. The immutable workflow and sandbox policies are
            // never changed, including for ACP's ALLOW_ALWAYS presentation choice.
            authorityExpanded = false,
        )
    }

    fun snapshot(): List<AcpPermissionAuditRecord> = synchronized(records) {
        Collections.unmodifiableList(ArrayList(records))
    }

    fun failure(): AcpProtocolFailure? = synchronized(records) { overflowFailure }
}

internal data class AcpResolvedPermission(
    val response: RequestPermissionResponse,
    val selected: AcpOfferedPermissionOption?,
    val auditOutcome: AcpPermissionAuditOutcome,
    val auditReason: AcpPermissionAuditReason,
)

internal class AcpPermissionBroker(
    private val request: AgentExecutionRequest,
    private val cancellation: AgentCancellation,
    private val decider: AcpPermissionDecider,
    private val audit: AcpPermissionAuditRecorder,
) {
    suspend fun decide(
        sessionId: String,
        toolCall: SessionUpdate.ToolCallUpdate,
        permissions: List<PermissionOption>,
    ): AcpResolvedPermission {
        val toolCallId = toolCall.toolCallId.value
        if (toolCallId.isBlank()) throw AcpProtocolFailure("ACP permission request has an empty tool-call id")
        val offered = try {
            permissions.map { option ->
                val id = option.optionId.value
                if (id.isBlank() || option.name.isBlank()) {
                    throw IllegalArgumentException("blank permission option")
                }
                AcpOfferedPermissionOption(id, option.name, option.kind)
            }.also { values ->
                if (values.map { it.optionId }.distinct().size != values.size) {
                    throw IllegalArgumentException("duplicate permission option id")
                }
            }
        } catch (_: IllegalArgumentException) {
            return cancelled(
                sessionId,
                toolCallId,
                permissions.size,
                AcpPermissionAuditOutcome.FAILED,
                AcpPermissionAuditReason.INVALID_OFFER,
            )
        }
        if (cancellation.isCancellationRequested()) {
            return cancelled(
                sessionId,
                toolCallId,
                offered.size,
                AcpPermissionAuditOutcome.CANCELLED,
                AcpPermissionAuditReason.REQUEST_CANCELLED,
            )
        }

        val context = AcpPermissionDecisionContext(
            sessionId = sessionId,
            toolCallId = toolCallId,
            title = toolCall.title,
            kind = toolCall.kind,
            offeredOptions = offered,
        )
        val choice = try {
            decider.decide(context)
        } catch (_: CancellationException) {
            return cancelled(
                sessionId,
                toolCallId,
                offered.size,
                AcpPermissionAuditOutcome.CANCELLED,
                AcpPermissionAuditReason.REQUEST_CANCELLED,
            )
        } catch (_: Exception) {
            return cancelled(
                sessionId,
                toolCallId,
                offered.size,
                AcpPermissionAuditOutcome.FAILED,
                AcpPermissionAuditReason.DECIDER_FAILED,
            )
        }
        if (cancellation.isCancellationRequested()) {
            return cancelled(
                sessionId,
                toolCallId,
                offered.size,
                AcpPermissionAuditOutcome.CANCELLED,
                AcpPermissionAuditReason.REQUEST_CANCELLED,
            )
        }
        if (choice is AcpPermissionChoice.Cancel) {
            return cancelled(
                sessionId,
                toolCallId,
                offered.size,
                AcpPermissionAuditOutcome.CANCELLED,
                AcpPermissionAuditReason.NO_USABLE_OPTION,
            )
        }
        choice as AcpPermissionChoice.Select
        val selected = offered.singleOrNull { it.optionId == choice.optionId }
            ?: return cancelled(
                sessionId,
                toolCallId,
                offered.size,
                AcpPermissionAuditOutcome.FAILED,
                AcpPermissionAuditReason.INVALID_DECIDER_SELECTION,
            )

        val allow = selected.kind == PermissionOptionKind.ALLOW_ONCE ||
            selected.kind == PermissionOptionKind.ALLOW_ALWAYS
        if (allow && AgentOperation.REQUEST_PERMISSION !in request.accessPolicy.allowedOperations) {
            val rejection = rejectOrCancel(offered)
            if (rejection is AcpPermissionChoice.Select) {
                val rejected = offered.single { it.optionId == rejection.optionId }
                return selected(
                    sessionId,
                    toolCallId,
                    offered.size,
                    rejected,
                    AcpPermissionAuditOutcome.DENIED,
                    AcpPermissionAuditReason.WORKFLOW_POLICY_DENIED,
                )
            }
            return cancelled(
                sessionId,
                toolCallId,
                offered.size,
                AcpPermissionAuditOutcome.DENIED,
                AcpPermissionAuditReason.WORKFLOW_POLICY_DENIED,
            )
        }
        val outcome = if (allow) AcpPermissionAuditOutcome.ALLOWED else AcpPermissionAuditOutcome.DENIED
        val reason = if (
            decider === AcpNonInteractivePermissionDecider.DEFAULT_DENY && !allow
        ) AcpPermissionAuditReason.DEFAULT_DENY else AcpPermissionAuditReason.SELECTED
        return selected(sessionId, toolCallId, offered.size, selected, outcome, reason)
    }

    private fun selected(
        sessionId: String,
        toolCallId: String,
        optionCount: Int,
        selected: AcpOfferedPermissionOption,
        outcome: AcpPermissionAuditOutcome,
        reason: AcpPermissionAuditReason,
    ): AcpResolvedPermission {
        audit.record(sessionId, toolCallId, optionCount, selected, outcome, reason)
        return AcpResolvedPermission(
            RequestPermissionResponse(
                RequestPermissionOutcome.Selected(
                    com.agentclientprotocol.model.PermissionOptionId(selected.optionId),
                ),
            ),
            selected,
            outcome,
            reason,
        )
    }

    private fun cancelled(
        sessionId: String,
        toolCallId: String,
        optionCount: Int,
        outcome: AcpPermissionAuditOutcome,
        reason: AcpPermissionAuditReason,
    ): AcpResolvedPermission {
        audit.record(sessionId, toolCallId, optionCount, null, outcome, reason)
        return AcpResolvedPermission(
            RequestPermissionResponse(RequestPermissionOutcome.Cancelled),
            null,
            outcome,
            reason,
        )
    }
}

private fun rejectOrCancel(options: List<AcpOfferedPermissionOption>): AcpPermissionChoice {
    val reject = options.firstOrNull { it.kind == PermissionOptionKind.REJECT_ONCE }
        ?: options.firstOrNull { it.kind == PermissionOptionKind.REJECT_ALWAYS }
    return reject?.let { AcpPermissionChoice.Select(it.optionId) } ?: AcpPermissionChoice.Cancel
}

private fun permissionSha256(value: String): String =
    MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }

private const val MAXIMUM_PERMISSION_AUDIT_RECORDS = 4096
