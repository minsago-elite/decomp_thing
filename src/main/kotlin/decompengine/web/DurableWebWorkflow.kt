package decompengine.web

import decompengine.jobs.Job
import decompengine.jobs.WorkflowAttempt
import decompengine.jobs.WorkflowCandidate
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowJobSnapshot
import decompengine.jobs.WorkflowKind
import decompengine.jobs.WorkflowStoreDiagnostic
import decompengine.jobs.WorkflowTerminalReason
import decompengine.jobs.WorkflowUsage
import java.nio.file.Path

/** Trusted adapter contract: the implementation must enforce every declared limit and stop its children before returning. */
interface DurableWebWorkflowAdapter {
    val workflow: WorkflowKind
    val limits: WorkflowExecutionLimits
    fun execute(context: DurableWebWorkflowContext): DurableWebWorkflowOutcome
}

/** Internal execution context. Paths are never transport DTO fields. */
data class DurableWebWorkflowContext(val job: Job, val attempt: WorkflowAttempt, val reportsDirectory: Path)

sealed interface DurableWebWorkflowOutcome {
    data class Completed(val candidate: WorkflowCandidate? = null, val usage: WorkflowUsage? = null) : DurableWebWorkflowOutcome
    data class Failed(val reason: WorkflowTerminalReason = WorkflowTerminalReason.FAILED,
        val candidate: WorkflowCandidate? = null, val usage: WorkflowUsage? = null) : DurableWebWorkflowOutcome {
        init { require(reason in setOf(WorkflowTerminalReason.FAILED, WorkflowTerminalReason.REFUSED, WorkflowTerminalReason.LIMIT_EXHAUSTED)) }
    }
}

data class DurableWebWorkflowRequest(val workflow: WorkflowKind, val inputRevisionId: String? = null, val previousRunId: String? = null)

sealed interface DurableWebWorkflowAdmission {
    data class Started(val jobId: String, val runId: String) : DurableWebWorkflowAdmission
    data class Unsupported(val workflow: WorkflowKind) : DurableWebWorkflowAdmission
    data object AlreadyRunning : DurableWebWorkflowAdmission
    data class Unavailable(val reasonCode: String) : DurableWebWorkflowAdmission
}

data class WebReportContext(val reportsDirectory: Path, val artifactPrefix: String = "reports", val runId: String? = null)
data class WebJobDiagnostic(val jobId: String, val code: String, val message: String)
data class WebJobPresentation(val job: Job, val snapshot: WorkflowJobSnapshot?, val reports: WebReportContext,
    val diagnostics: List<WorkflowStoreDiagnostic> = emptyList(), val legacyInterrupted: Boolean = false)
sealed interface WebJobInspection {
    data class Available(val presentation: WebJobPresentation) : WebJobInspection
    data class Unavailable(val diagnostic: WebJobDiagnostic) : WebJobInspection
}
class WebJobServiceException(val code: String, message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/** Parse once before namespace selection; normalization must never change the selected authority. */
internal fun canonicalReportSegments(path: String): List<String> {
    require(path.length in 1..4096 && path.none { it == '\\' || it.code < 32 || it.code == 127 }) { "Invalid report artifact path" }
    val segments = path.split('/')
    require(segments.size >= 2 && segments.first() == "reports" && segments.none { it.isBlank() || it == "." || it == ".." }) {
        "Report artifact paths must be canonical and remain in the reports namespace"
    }
    if (segments[1] == "runs") require(segments.size >= 4 && segments[2].matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}"))) {
        "A workflow artifact requires an exact attempt identity and artifact name"
    }
    return segments
}
