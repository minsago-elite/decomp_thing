package decompengine.repair

import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/** Fixed labels shared by CLI and web; never infer acceptance from tool completion or succeeded. */
internal fun repairAttemptLabel(iteration: RepairIteration): String = repairAttemptLabel(
    iteration.disposition.name.lowercase(), iteration.agentInvocation?.assessmentStatus?.name?.lowercase(),
    iteration.agentInvocation?.terminalOutcome, iteration.after?.kind, iteration.publicationMode.name.lowercase(),
)

internal fun repairAttemptLabel(iteration: JsonObject): String {
    val raw = iteration["agentInvocation"]
    val invocation = if (raw == null || raw == JsonNull) null else runCatching {
        val value = raw as JsonObject
        RepairAgentInvocationBinding(
            requireNotNull(value.historyText("receiptPath")), requireNotNull(value.historyText("receiptSha256")),
            requireNotNull((value["receiptSchemaVersion"] as? JsonPrimitive)?.intOrNull),
            requireNotNull(value.historyText("requestSha256")), requireNotNull(value.historyText("resultChangesSha256")),
            requireNotNull(value.historyText("terminalOutcome")),
            requireNotNull((value["receiptReleaseComplete"] as? JsonPrimitive)?.booleanOrNull),
            RepairAgentAssessmentStatus.valueOf(requireNotNull(value.historyText("assessmentStatus")).uppercase()),
        )
    }.getOrElse { return "unverified" }
    return repairAttemptLabel(iteration.historyText("disposition"), invocation?.assessmentStatus?.name?.lowercase(),
        invocation?.terminalOutcome, (iteration["after"] as? JsonObject)?.historyText("kind"),
        iteration.historyText("publicationMode"))
}

private fun repairAttemptLabel(disposition: String?, assessment: String?, terminal: String?, evidence: String?, publicationMode: String?): String {
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
        // Migration preserves the historical ACP assessment but withdraws source acceptance.
        disposition == "fully_accepted" && assessment == "accepted" && terminal == "returned-completed" -> "accepted"
        disposition == "fully_accepted" && assessment == null && terminal == null &&
            publicationMode == "test_only_non_release" -> "accepted"
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
