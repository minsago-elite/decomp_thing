package decompengine.agent

/** Display-only workflow observations. A progress event never authorizes a revision. */
interface AgentWorkflowProgress {
    fun beginTask(taskId: String, request: AgentExecutionRequest): AgentTaskProgress
    fun beginTask(taskId: String, request: AgentExecutionRequest, workflowRunId: String): AgentTaskProgress =
        beginTask(taskId, request)
    fun phase(phase: AgentWorkflowPhase, taskId: String? = null, acceptedRevisionSha256: String? = null)
    fun runState(observation: AgentWorkflowRunObservation) =
        phase(observation.phase, observation.taskId, observation.acceptedRevisionSha256)

    companion object {
        val NONE = object : AgentWorkflowProgress {
            override fun beginTask(taskId: String, request: AgentExecutionRequest) = AgentTaskProgress.NONE
            override fun phase(phase: AgentWorkflowPhase, taskId: String?, acceptedRevisionSha256: String?) = Unit
        }
    }
}

interface AgentTaskProgress {
    fun event(event: AgentExecutionEvent)
    fun complete(receipt: AgentExecutionReceipt)

    companion object {
        val NONE = object : AgentTaskProgress {
            override fun event(event: AgentExecutionEvent) = Unit
            override fun complete(receipt: AgentExecutionReceipt) = Unit
        }
    }
}

enum class AgentWorkflowPhase {
    ANALYZING, PLANNING, AGENT_RUNNING, POLICY_CHECKING, BUILD_VALIDATING,
    BEHAVIOR_VALIDATING, ROLLED_BACK, ACCEPTED, UNRESOLVED, FAILED, COMPLETED,
    PROVISIONAL, COMPILE_VALID, REJECTED, EXHAUSTED, RESOURCE_EXHAUSTED, CANCELLED, INTERRUPTED,
}

/** Correlation with durable workflow state, distinct from the display writer's own run UUID. */
data class AgentWorkflowRunObservation(
    val workflowRunId: String,
    val phase: AgentWorkflowPhase,
    val revisionId: String? = null,
    val taskId: String? = null,
    val acceptedRevisionSha256: String? = null,
) {
    init {
        require(workflowRunId.isNotBlank() && workflowRunId.length <= 4096)
        require(listOfNotNull(revisionId, taskId).all { it.isNotBlank() && it.length <= 4096 })
        require(acceptedRevisionSha256 == null || acceptedRevisionSha256.matches(Regex("[a-f0-9]{64}")))
        require((phase == AgentWorkflowPhase.ACCEPTED) == (acceptedRevisionSha256 != null)) {
            "accepted workflow observations require an accepted source commitment; other phases cannot claim one"
        }
    }
}
