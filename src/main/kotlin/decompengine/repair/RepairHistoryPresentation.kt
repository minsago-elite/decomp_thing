package decompengine.repair

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/** Fixed labels shared by CLI and web; never infer acceptance from tool completion or succeeded. */
internal fun repairAttemptLabel(iteration: RepairIteration): String = repairAttemptLabel(
    iteration.disposition.name.lowercase(), iteration.agentInvocation?.assessmentStatus?.name?.lowercase(),
    iteration.agentInvocation?.terminalOutcome, iteration.after?.kind,
)

internal fun repairAttemptLabel(iteration: JsonObject): String {
    val invocation = iteration["agentInvocation"] as? JsonObject
    return repairAttemptLabel(iteration.historyText("disposition"), invocation?.historyText("assessmentStatus"),
        invocation?.historyText("terminalOutcome"), (iteration["after"] as? JsonObject)?.historyText("kind"))
}

private fun repairAttemptLabel(disposition: String?, assessment: String?, terminal: String?, evidence: String?): String {
    // Terminal receipt outcomes survive a generic rejected graph disposition.
    when (terminal) {
        "returned-no-changes" -> return "no-change"
        "returned-refused" -> return "refused"
        "returned-cancelled", "failed-cancelled" -> return "cancelled"
        "returned-limit-exhausted", "failed-resource-exhausted", "failed-timeout" -> return "limit-exhausted"
        "failed-process-crash" -> return "process-crashed"
    }
    when (evidence) {
        "agent-no-change", "agent-stop-no-changes" -> return "no-change"
        "agent-stop-refused" -> return "refused"
        "agent-stop-cancelled", "agent-failure-cancelled" -> return "cancelled"
        "agent-stop-limit-exhausted", "agent-failure-resource-exhausted", "agent-failure-timeout" -> return "limit-exhausted"
        "agent-failure-process-crash" -> return "process-crashed"
        "assessment-error", "validation-error" -> return "validation-failed"
    }
    return when {
        disposition == "rejected" || assessment == "rejected" -> "rejected"
        disposition == "provisional" || assessment == "provisional" -> "provisional"
        assessment == "pending" -> "pending"
        assessment == "accepted" && terminal == "returned-completed" -> "accepted"
        disposition == "fully_accepted" && assessment == null && terminal == null -> "accepted"
        else -> "unverified"
    }
}

internal fun repairRunLabel(status: String?): String = when (status) {
    "running" -> "pending"
    "fully_accepted" -> "accepted"
    "no_changes" -> "no-change"
    "iteration_exhausted", "resource_exhausted" -> "limit-exhausted"
    "validation_failed" -> "validation-failed"
    "rejected" -> "rejected"
    "cancelled" -> "cancelled"
    "interrupted" -> "interrupted"
    "compile_valid" -> "compile-valid"
    else -> "unverified"
}

internal fun JsonObject.historyText(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull
