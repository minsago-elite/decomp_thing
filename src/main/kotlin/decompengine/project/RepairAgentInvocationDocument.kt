package decompengine.project

import decompengine.agent.*
import decompengine.builtin.*
import decompengine.repair.TRACE_REPAIR_ACP_RECEIPT_KIND
import decompengine.repair.TRACE_REPAIR_ACP_TASK_FIELD

/** One immutable receipt document used by repair persistence regardless of the selected harness. */
internal class RepairAgentInvocationDocument private constructor(
    raw: ByteArray,
    val schemaVersion: Int,
    val requestSha256: String,
    val resultChangesSha256: String,
    val terminalOutcome: String,
    val releaseComplete: Boolean,
    val builtinArchive: BuiltinInvocationArchiveReference?,
) {
    private val raw = raw.copyOf()
    val bytes get() = raw.copyOf()
    val sha256 = sha256(raw)
    val suffix get() = if (builtinArchive == null) "acp-receipt.json" else "builtin-receipt.json"

    companion object {
        fun fromAcp(document: AcpExecutionReceiptDocument) = RepairAgentInvocationDocument(
            document.json.toByteArray(Charsets.UTF_8), document.schemaVersion, document.requestSha256,
            document.resultChangesSha256, document.terminalOutcome, document.releaseComplete, null,
        )

        fun captureOrNull(request: AgentExecutionRequest, promptSha256: String, receipt: AgentExecutionReceipt,
            events: ArchivedAgentEventSnapshot, taskId: String): RepairAgentInvocationDocument? {
            val evidence = receipt.providerEvidence
            if (evidence is BuiltinCapturedExecutionEvidence) {
                val archive = requireNotNull(evidence.invocationArchive) { "built-in repair lacks a terminal invocation archive" }
                val workflow = requireNotNull(request.workflowIdentity) { "built-in repair lacks workflow lineage" }
                require(workflow.workflow == AgentWorkflow.REPAIR && workflow.taskId == taskId && workflow.promptSha256 == promptSha256)
                archive.reference.requireWorkflow(workflow)
                require(archive.reference.identity.binding == receipt.requestBinding &&
                    receipt.requestBinding == AgentExecutionRequestBinding.capture(request)) {
                    "built-in repair archive is bound to a different request"
                }
                val verified = verifyRepairAgentInvocationDocument(archive.bytes, workflow, archive.reference)
                val outcome = when (val result = receipt.outcome) {
                    is AgentExecutionOutcome.Returned -> "returned-${result.result.stopReason.name}"
                    is AgentExecutionOutcome.Failed -> "failed-${result.failure.kind.name}"
                }.lowercase().replace('_', '-')
                require(verified.terminalOutcome == outcome && verified.resultChangesSha256 ==
                    agentFileChangeSetSha256((receipt.outcome as? AgentExecutionOutcome.Returned)?.result?.changes.orEmpty())) {
                    "built-in repair archive differs from its terminal receipt"
                }
                return fromVerified(archive.bytes, verified, archive.reference)
            }
            return AcpExecutionReceiptDocument.captureOrNull(request, promptSha256, receipt, events,
                TRACE_REPAIR_ACP_RECEIPT_KIND, TRACE_REPAIR_ACP_TASK_FIELD, taskId)?.let(::fromAcp)
        }

        /** The state store owns this immutable orphan; recovery must still match the pending graph. */
        fun recover(bytes: ByteArray, expected: AgentWorkflowIdentity, builtin: Boolean): RepairAgentInvocationDocument {
            val reference = if (builtin) recoverBuiltinInvocationArchiveReference(bytes, expected) else null
            return fromVerified(bytes, verifyRepairAgentInvocationDocument(bytes, expected, reference), reference)
        }

        private fun fromVerified(bytes: ByteArray, verified: VerifiedRepairAgentInvocationDocument,
            reference: BuiltinInvocationArchiveReference?) = RepairAgentInvocationDocument(bytes, verified.schemaVersion,
            verified.requestSha256, verified.resultChangesSha256, verified.terminalOutcome, verified.releaseComplete, reference)
    }
}

internal class VerifiedRepairAgentInvocationDocument(
    val schemaVersion: Int,
    val requestSha256: String,
    val promptSha256: String,
    val resultChangesSha256: String,
    val terminalOutcome: String,
    val releaseComplete: Boolean,
    val acp: VerifiedAcpExecutionReceiptDocument? = null,
) {
    val releaseFacts get() = acp?.releaseFacts
}

/** Pure verification against workflow-owned identities and the separately persisted journal reference. */
internal fun verifyRepairAgentInvocationDocument(bytes: ByteArray, expected: AgentWorkflowIdentity,
    builtinArchive: BuiltinInvocationArchiveReference?): VerifiedRepairAgentInvocationDocument {
    require(expected.workflow == AgentWorkflow.REPAIR)
    if (builtinArchive != null) {
        builtinArchive.requireWorkflow(expected)
        val verified = verifyBuiltinInvocationArchive(bytes, builtinArchive.identity, builtinArchive.commitment)
        return VerifiedRepairAgentInvocationDocument(1, verified.requestSha256, verified.promptSha256,
            verified.resultChangesSha256, verified.terminalOutcome.lowercase().replace('_', '-'), verified.releaseComplete)
    }
    val verified = verifyAcpExecutionReceiptDocument(bytes, TRACE_REPAIR_ACP_RECEIPT_KIND, TRACE_REPAIR_ACP_TASK_FIELD, expected.taskId)
    require(verified.promptSha256 == expected.promptSha256) { "repair ACP receipt differs from its workflow prompt" }
    return VerifiedRepairAgentInvocationDocument(2, verified.requestSha256, verified.promptSha256,
        verified.resultChangesSha256, verified.terminalOutcome, verified.releaseComplete, verified)
}
