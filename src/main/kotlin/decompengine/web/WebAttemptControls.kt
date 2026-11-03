package decompengine.web

import decompengine.jobs.WorkflowAttempt
import decompengine.jobs.WorkflowResumeRestoration
import kotlinx.serialization.json.*

/**
 * Current command eligibility for one attempt. Reasons are a closed public vocabulary; a null reason
 * means the command may be sent with this exact run version. It is not a reservation: each command
 * re-checks its guards, and a replay of a retained key is answered before these checks.
 */
internal data class WebAttemptControls(
    val attempt: WorkflowAttempt,
    val cancelReason: String?,
    val retryReason: String?,
    val resumeReason: String?,
    val resumeRestores: WorkflowResumeRestoration?,
    val successorRunId: String?,
) {
    init {
        require((resumeReason == null) == (resumeRestores != null)) { "resume restoration requires an available resume" }
        listOfNotNull(cancelReason).forEach { require(it in CANCEL_REASONS) { "unknown cancellation reason" } }
        listOfNotNull(retryReason).forEach { require(it in RETRY_REASONS) { "unknown retry reason" } }
        listOfNotNull(resumeReason).forEach { require(it in RETRY_REASONS + RESUME_REASONS) { "unknown resume reason" } }
    }

    fun toJson(): JsonObject = buildJsonObject {
        put("jobId", attempt.jobId); put("runId", attempt.runId); put("runVersion", attempt.version)
        put("state", attempt.state.wireName)
        put("inputRevisionId", attempt.inputRevisionId?.let(::JsonPrimitive) ?: JsonNull)
        put("cancel", control(cancelReason))
        put("retry", control(retryReason))
        put("resume", control(resumeReason))
        put("resumeRestores", resumeRestores?.wireName?.let(::JsonPrimitive) ?: JsonNull)
        put("successorRunId", successorRunId?.let(::JsonPrimitive) ?: JsonNull)
    }

    private fun control(reason: String?) = buildJsonObject {
        put("available", reason == null); put("reason", reason?.let(::JsonPrimitive) ?: JsonNull)
    }

    companion object {
        val CANCEL_REASONS = setOf("RECOVERY_REQUIRED", "ATTEMPT_TERMINAL", "CANCEL_PENDING", "SERVICE_STOPPED",
            "NO_OWNED_WORKER", "RECEIPT_CAPACITY")
        val RETRY_REASONS = setOf("RECOVERY_REQUIRED", "SERVICE_STOPPED", "ATTEMPT_ACTIVE", "ATTEMPT_COMPLETED",
            "ATTEMPT_SUPERSEDED", "ACTIVE_RUN", "WORKFLOW_UNAVAILABLE", "INPUT_UNVERIFIED", "UPLOAD_CAPACITY", "CAPACITY_UNAVAILABLE")
        val RESUME_REASONS = setOf("RESUME_UNSUPPORTED", "HARNESS_CHANGED", "CHECKPOINT_MISSING", "CHECKPOINT_MISMATCH",
            "CHECKPOINT_UNVERIFIED", "WORKSPACE_UNVERIFIED", "SESSION_QUARANTINED", "CLEANUP_UNVERIFIED")
    }
}
