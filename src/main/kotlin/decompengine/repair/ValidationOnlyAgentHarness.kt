package decompengine.repair

import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentHarness

/**
 * The only harness a validation-only session holds. Validation runs never request repair, so any
 * invocation is a programming error and fails before contacting anything.
 */
internal object ValidationOnlyAgentHarness : AgentHarness {
    /** Stable descriptor reported by validation-only sessions; it names no agent harness. */
    const val PROVENANCE: String = "agent-harness-v1:none:validation-only"

    override fun execute(request: AgentExecutionRequest, onEvent: (AgentExecutionEvent) -> Unit): AgentExecutionResult =
        throw IllegalStateException("validation-only sessions never invoke an agent")

    override fun implementationIdentifier(): String = "validation-only"
}
