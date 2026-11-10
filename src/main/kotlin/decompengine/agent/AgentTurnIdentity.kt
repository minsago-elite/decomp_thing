package decompengine.agent

import java.util.UUID

/**
 * Host-created identity for one attempted provider turn. It is deliberately separate from the
 * request digest: identical requests, including resumed-session requests, are distinct turns.
 *
 * This identity is correlation metadata only. It does not authorize a change or establish that
 * the provider ran, that the workspace was observed completely, or that a workflow accepted a
 * candidate.
 */
data class AgentTurnIdentity(
    val turnId: String,
    val taskId: String,
    val requestSha256: String,
    val workflowRunId: String? = null,
) {
    init {
        require(runCatching { UUID.fromString(turnId) }.isSuccess) { "agent turn id must be a UUID" }
        require(taskId.isNotBlank() && taskId.toByteArray(Charsets.UTF_8).size <= 256) {
            "agent turn task identity is invalid"
        }
        require(requestSha256.matches(Regex("[a-f0-9]{64}"))) { "agent turn request digest is invalid" }
        require(workflowRunId == null || (workflowRunId.isNotBlank() && workflowRunId.toByteArray(Charsets.UTF_8).size <= 4096)) {
            "agent turn workflow identity is invalid"
        }
    }

    fun requireBoundTo(binding: AgentExecutionRequestBinding) {
        require(requestSha256 == binding.requestSha256) { "agent turn identity belongs to another request" }
    }

    companion object {
        fun create(
            taskId: String,
            request: AgentExecutionRequest,
            workflowRunId: String? = null,
        ): AgentTurnIdentity = AgentTurnIdentity(
            turnId = UUID.randomUUID().toString(),
            taskId = taskId,
            requestSha256 = AgentExecutionRequestBinding.capture(request).requestSha256,
            workflowRunId = workflowRunId,
        )
    }
}
