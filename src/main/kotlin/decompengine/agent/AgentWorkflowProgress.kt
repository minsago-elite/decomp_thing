package decompengine.agent

/** Display-only workflow observations. A progress event never authorizes a revision. */
interface AgentWorkflowProgress {
    fun beginTask(taskId: String, request: AgentExecutionRequest): AgentTaskProgress
    fun phase(phase: AgentWorkflowPhase, taskId: String? = null, acceptedRevisionSha256: String? = null)

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
}
