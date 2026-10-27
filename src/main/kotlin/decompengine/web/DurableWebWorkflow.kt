package decompengine.web

import decompengine.jobs.Job
import decompengine.jobs.WorkflowAcceptanceReference
import decompengine.jobs.WorkflowAttempt
import decompengine.jobs.WorkflowCandidate
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowJobSnapshot
import decompengine.jobs.WorkflowKind
import decompengine.jobs.WorkflowResumeRestoration
import decompengine.jobs.WorkflowStoreDiagnostic
import decompengine.jobs.WorkflowTerminalReason
import decompengine.jobs.WorkflowUsage
import java.nio.file.Path

/** Trusted adapter contract: the implementation must enforce every declared limit and stop its children before returning. */
interface DurableWebWorkflowAdapter {
    val workflow: WorkflowKind
    /** Server default. With [limitsAdjustable], also the per-field ceiling a request may lower but never raise. */
    val limits: WorkflowExecutionLimits
    val harnessCapabilityId: String? get() = null
    val limitsAdjustable: Boolean get() = false
    /** Runtime prerequisites checked again at admission; inert adapters have none. */
    val requirements: Set<WebWorkflowRequirement> get() = emptySet()
    val input: DurableWebWorkflowInput get() = DurableWebWorkflowInput.ACCEPTED_OPTIONAL
    /** Public launch facts, or null for an inert registration that does not describe itself. */
    val launch: DurableWebWorkflowLaunch? get() = null
    /** Read-only acceptance attestation for a completed candidate; never executes work. */
    val publication: DurableWebWorkflowPublication? get() = null
    /** Null means checkpoint resume is unsupported; explicit retry remains a separate new attempt. */
    val checkpoints: DurableWebWorkflowCheckpointPolicy? get() = null
    fun execute(context: DurableWebWorkflowContext): DurableWebWorkflowOutcome
}

/**
 * Trusted, workflow-owned checkpoint verification. Implementations reconcile the predecessor's persisted
 * checkpoint, accepted revision and workspace identity with the shared harness recovery policy
 * (for ACP, [decompengine.agent.AgentSessionJournal]) before any admission. Inspection must be bounded and
 * read-only: it cannot start a process, load a session, quarantine or mutate evidence. The execution context
 * later carries the recorded digest; an adapter must refuse to continue if its checkpoint no longer matches.
 */
fun interface DurableWebWorkflowCheckpointPolicy {
    fun inspect(request: DurableWebWorkflowCheckpointRequest): DurableWebWorkflowCheckpoint
}

/** Internal only: the predecessor directory is workflow-owned and never a transport or caller value. */
data class DurableWebWorkflowCheckpointRequest(val job: Job, val predecessor: WorkflowAttempt, val predecessorReportsDirectory: Path)

sealed interface DurableWebWorkflowCheckpoint {
    data class Verified(val checkpointSha256: String, val restores: WorkflowResumeRestoration) : DurableWebWorkflowCheckpoint {
        init { require(checkpointSha256.matches(Regex("[0-9a-f]{64}"))) { "invalid checkpoint identity" } }
    }
    data class Refused(val reason: DurableWebWorkflowCheckpointRefusal) : DurableWebWorkflowCheckpoint
}

/** Closed public vocabulary; adapter diagnostics stay server-side. */
enum class DurableWebWorkflowCheckpointRefusal(val code: String) {
    CHECKPOINT_MISSING("CHECKPOINT_MISSING"),
    CHECKPOINT_MISMATCH("CHECKPOINT_MISMATCH"),
    WORKSPACE_UNVERIFIED("WORKSPACE_UNVERIFIED"),
    SESSION_QUARANTINED("SESSION_QUARANTINED"),
    CLEANUP_UNVERIFIED("CLEANUP_UNVERIFIED"),
}


/** What an attempt may start from. Paths are resolved by the service, never by the caller. */
enum class DurableWebWorkflowInput {
    /** Only the uploaded binary; a selected revision is refused. */
    NONE,
    /** The uploaded binary, optionally with the job's current accepted revision. */
    ACCEPTED_OPTIONAL,
    /** One revision recorded by this job: its accepted revision or a completed attempt's candidate. */
    RECORDED_REQUIRED,
}

enum class WebWorkflowRequirement(val wireName: String) {
    SANDBOX("sandbox"), GHIDRA("ghidra"), AGENT_HARNESS("agent-harness"), REPAIR_VALIDATOR("repair-validator"),
    EXPLORATION_HELPER_OWNERSHIP("exploration-helper-ownership"),
}

enum class DurableWebWorkflowMode(val wireName: String) { TOOLS("tools"), AGENT("agent"), EVIDENCE_ONLY("evidence-only") }

/**
 * One agent-execution boundary a workflow option can name. [selector] is the exact data-only value the
 * application-owned harness factory accepts; the built-in harness has none because no workflow runs it yet.
 */
enum class WebAgentHarness(val wireName: String, val capabilityId: String, val selector: String?, val deprecated: Boolean) {
    ACP("acp", "agent-acp", "acp", false),
    LEGACY_OPENAI("legacy-openai", "agent-legacy-openai", "legacy-openai", true),
    BUILTIN("builtin", "agent-builtin", null, false),
}

/** Facts the launch form shows; they describe the adapter, they never authorize admission. */
data class DurableWebWorkflowLaunch(
    val mode: DurableWebWorkflowMode,
    val executesBinary: Boolean,
    val contactsAgent: Boolean,
    val requiredTools: List<String>,
    /** The single harness an agent option uses; never another one as a fallback. */
    val harness: WebAgentHarness? = null,
) {
    init {
        require(contactsAgent == (mode == DurableWebWorkflowMode.AGENT)) { "agent contact must match the declared mode" }
        require(requiredTools.size <= 8 && requiredTools.distinct() == requiredTools && requiredTools.all { it in LAUNCH_TOOLS })
        require((harness != null) == contactsAgent && harness?.selector != null == contactsAgent) {
            "an agent option names exactly one executable harness"
        }
    }
    companion object { val LAUNCH_TOOLS = setOf("sandbox", "ghidra", "agent-harness", "c-toolchain", "angr") }
}

/** Trusted, bounded and read-only: verify retained canonical evidence for a completed candidate. */
fun interface DurableWebWorkflowPublication {
    fun verify(context: DurableWebWorkflowPublicationContext): WorkflowAcceptanceReference?
}

/** Verifiers must reserve each capture before reading and checkpoint between bounded read units. */
data class DurableWebWorkflowPublicationContext(
    val job: Job, val attempt: WorkflowAttempt, val reportsDirectory: Path,
    val checkpoint: () -> Unit = { if (Thread.currentThread().isInterrupted) throw InterruptedException("Publication interrupted") },
    val reserveCapture: (Long) -> Unit = {},
)

/**
 * Internal execution context. Paths are never transport DTO fields. A recovery attempt records its
 * mode/checkpoint in [WorkflowAttempt.recovery]; [predecessorReportsDirectory] is present only for resume.
 * [inputSourceTree] is the selected recorded revision's retained source for adapters that require one.
 */
data class DurableWebWorkflowContext(val job: Job, val attempt: WorkflowAttempt, val reportsDirectory: Path,
    val predecessorReportsDirectory: Path? = null, val inputSourceTree: Path? = null)

sealed interface DurableWebWorkflowOutcome {
    data class Completed(val candidate: WorkflowCandidate? = null, val usage: WorkflowUsage? = null,
        val reason: WorkflowTerminalReason = WorkflowTerminalReason.COMPLETED) : DurableWebWorkflowOutcome {
        init { require(reason in setOf(WorkflowTerminalReason.COMPLETED, WorkflowTerminalReason.NO_CHANGES)) }
    }
    data class Failed(val reason: WorkflowTerminalReason = WorkflowTerminalReason.FAILED,
        val candidate: WorkflowCandidate? = null, val usage: WorkflowUsage? = null) : DurableWebWorkflowOutcome {
        init { require(reason in setOf(WorkflowTerminalReason.FAILED, WorkflowTerminalReason.REFUSED, WorkflowTerminalReason.LIMIT_EXHAUSTED, WorkflowTerminalReason.TIMED_OUT)) }
    }
}

/** Attempt counts by restart disposition after startup reconciliation, and acceptances it recorded. */
data class WebStartupReconciliation(val dispositions: Map<decompengine.jobs.WorkflowRecoveryDisposition, Int>, val publishedAcceptances: Int)

data class DurableWebWorkflowRequest(val workflow: WorkflowKind, val inputRevisionId: String? = null, val previousRunId: String? = null,
    val harnessCapabilityId: String? = null)

/** A durable command result, including an explicitly refused scheduler outcome; never acceptance evidence. */
internal data class DurableWebWorkflowStartResult(val attempt: WorkflowAttempt, val replayed: Boolean)

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
