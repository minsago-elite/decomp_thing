package decompengine.web

import decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxDescriptor
import decompengine.agent.AgentWorkflowPhase
import decompengine.agent.AgentWorkflowProgress
import decompengine.exploration.AutomaticExplorer
import decompengine.exploration.CandidateInput
import decompengine.exploration.CandidateSource
import decompengine.jobs.BestEffortProgressJournal
import decompengine.jobs.WorkflowAcceptanceReference
import decompengine.jobs.WorkflowCandidate
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowKind
import decompengine.jobs.WorkflowTerminalReason
import decompengine.jobs.WorkflowUsage
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.ArchivalReconstructionService
import decompengine.project.GhidraHeadlessProgramModelAnalyzer
import decompengine.project.ReconstructionOutputWorkspace
import decompengine.repair.ModuleRevisionStatus
import decompengine.repair.RepairPublicationMode
import decompengine.repair.RepairValidationAssurance
import decompengine.repair.RepairHistoryReadStatus
import decompengine.repair.RepairHistorySnapshot
import decompengine.repair.RepairRunStatus
import decompengine.repair.RepairRunOutcome
import decompengine.repair.RepairRuntimeConfiguration
import decompengine.repair.SecureRepairRuntime
import decompengine.repair.readProjectRecordedRepairHistory
import decompengine.repair.readStableRegularFile
import decompengine.validation.ProcessInput
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.FileTime

private const val MAXIMUM_WEB_SOURCE_COPY_DEPTH = 256

/**
 * The existing CLI/legacy implementations behind each production adapter. Tests substitute inert
 * engines; production engines are the same exploration, archival reconstruction and secure repair
 * entry points the `explore`, `reconstruct` and `repair` commands use.
 */
internal interface WebWorkflowEngines {
    /** [activity] is called after each completed exploration sample. */
    fun explore(binary: Path, reportsDirectory: Path, activity: () -> Unit)
    fun reconstruct(
        binary: Path,
        reportsDirectory: Path,
        mode: WebReconstructionMode,
        progress: AgentWorkflowProgress,
        workspace: ReconstructionOutputWorkspace,
        publicationAdmission: () -> Unit,
        onCommittedPublication: () -> Unit,
    )
    fun repair(project: Path, binary: Path, reportsDirectory: Path, harness: String): RepairRunOutcome

    companion object {
        fun production(environment: Map<String, String>, sensitiveValues: Collection<String>): WebWorkflowEngines = object : WebWorkflowEngines {
            override fun explore(binary: Path, reportsDirectory: Path, activity: () -> Unit) {
                AutomaticExplorer(coverage = decompengine.exploration.OutputCoverageMeasurer(onSample = activity))
                    .explore(binary, listOf(CandidateInput("seed_default", CandidateSource.SEED)), reportsDirectory)
            }

            override fun reconstruct(
                binary: Path,
                reportsDirectory: Path,
                mode: WebReconstructionMode,
                progress: AgentWorkflowProgress,
                workspace: ReconstructionOutputWorkspace,
                publicationAdmission: () -> Unit,
                onCommittedPublication: () -> Unit,
            ) {
                // The explicit request mode replaces the legacy WEB_RECONSTRUCTION_MODE environment choice.
                val selected = environment + (WEB_RECONSTRUCTION_MODE_KEY to mode.configurationValue)
                val strategy = selectWebReconstructionStrategy(selected, progress)
                Files.createDirectories(reportsDirectory)
                Files.writeString(reportsDirectory.resolve("reconstruction_harness_selection.json"), renderWebReconstructionHarnessSelection(strategy))
                ArchivalReconstructionService(GhidraHeadlessProgramModelAnalyzer.bundled(), strategy.reconstructor,
                    profile = strategy.profile, progress = progress).reconstructWithWorkspace(
                    binary, reportsDirectory, workspace, publicationAdmission, onCommittedPublication,
                )
            }

            override fun repair(project: Path, binary: Path, reportsDirectory: Path, harness: String): RepairRunOutcome {
                val configuration = RepairRuntimeConfiguration("generated-c-make-v1", reportsDirectory.resolve("repair_history.json"),
                    harnessOverride = harness)
                return SecureRepairRuntime.open(configuration).use { runtime ->
                    runtime.runRepair(project, binary, listOf(ProcessInput("default")), reportsDirectory, REPAIR_ITERATIONS)
                }
            }
        }
    }
}

private const val WEB_RECONSTRUCTION_MODE_KEY = "WEB_RECONSTRUCTION_MODE"
private const val REPAIR_ITERATIONS = 5
/** Each repair iteration is one agent invocation bounded by the default agent limit of 256 tool calls. */
private val REPAIR_TOOL_CALLS: ULong = 1280uL

/** Deterministic identity: a revision identifier can never name a different source digest. */
internal fun webSourceRevisionId(sourceSha256: String): String {
    require(sourceSha256.matches(Regex("[0-9a-f]{64}")))
    return "source_$sourceSha256"
}

/** Builds production registrations. The configured agent selection names the agent harness option. */
internal fun productionDurableWebWorkflows(
    environment: Map<String, String> = System.getenv(),
    sensitiveValues: Collection<String> = environment.values,
    engines: WebWorkflowEngines = WebWorkflowEngines.production(environment, sensitiveValues),
    executor: BoundedWorkflowExecutor = BoundedWorkflowExecutor(),
): List<DurableWebWorkflowAdapter> {
    val agentHarness = WebHarnessReadinessProjector.agentHarnessCapabilityId(environment)
    return listOf(
        ExploreWorkflowAdapter(engines, executor),
        ReconstructWorkflowAdapter(engines, executor, WebReconstructionMode.AGENT, agentHarness, sensitiveValues),
        ReconstructWorkflowAdapter(engines, executor, WebReconstructionMode.EVIDENCE_ONLY, EVIDENCE_ONLY_CAPABILITY, sensitiveValues),
        RepairWorkflowAdapter(engines, executor, agentHarness),
    )
}

internal const val EVIDENCE_ONLY_CAPABILITY = "evidence-only"

/** Server-approved defaults; adjustable adapters accept lower values only. */
internal object WebWorkflowDefaults {
    val EXPLORE = WorkflowExecutionLimits(30uL * 60_000uL, 5uL * 60_000uL, 256uL * 1024uL * 1024uL, 0uL)
    val RECONSTRUCT_AGENT = WorkflowExecutionLimits(6uL * 3_600_000uL, 20uL * 60_000uL, 4uL * 1024uL * 1024uL * 1024uL, 10_000uL)
    val RECONSTRUCT_EVIDENCE = WorkflowExecutionLimits(2uL * 3_600_000uL, 20uL * 60_000uL, 4uL * 1024uL * 1024uL * 1024uL, 0uL)
    val REPAIR = WorkflowExecutionLimits(6uL * 3_600_000uL, 20uL * 60_000uL, 4uL * 1024uL * 1024uL * 1024uL, REPAIR_TOOL_CALLS)
}

private fun limitFailure(usage: decompengine.jobs.WorkflowUsage) =
    DurableWebWorkflowOutcome.Failed(WorkflowTerminalReason.LIMIT_EXHAUSTED, usage = usage)

/** Interruption belongs to the service: rethrow it so it records cancellation or interruption. */
private fun <T> unwrap(result: BoundedWorkflowResult<T>): BoundedWorkflowResult<T> {
    if (result is BoundedWorkflowResult.Threw) {
        val failure = result.failure
        if (failure is Error && failure !is OutOfMemoryError && failure !is StackOverflowError) throw failure
    }
    return result
}

internal class ExploreWorkflowAdapter(
    private val engines: WebWorkflowEngines,
    private val executor: BoundedWorkflowExecutor,
    // Inert executor/service controls only; production registrations never opt in (#71).
    private val allowTestOnlyExecution: Boolean = false,
) : DurableWebWorkflowAdapter {
    override val workflow = WorkflowKind.EXPLORE
    // No production checkpoint policy yet (no agent-session journal reconciliation), so POST R/recover
    // reports resume as RESUME_UNSUPPORTED; an explicit retry always starts a fresh linked attempt.
    override val checkpoints: DurableWebWorkflowCheckpointPolicy? = null
    override val limits = WebWorkflowDefaults.EXPLORE
    override val limitsAdjustable = true
    override val requirements = if (allowTestOnlyExecution) setOf(WebWorkflowRequirement.SANDBOX)
        else setOf(WebWorkflowRequirement.SANDBOX, WebWorkflowRequirement.EXPLORATION_HELPER_OWNERSHIP)
    override val input = DurableWebWorkflowInput.NONE
    override val launch = DurableWebWorkflowLaunch(DurableWebWorkflowMode.TOOLS, executesBinary = true, contactsAgent = false,
        requiredTools = listOf("sandbox", "angr"))

    override fun execute(context: DurableWebWorkflowContext): DurableWebWorkflowOutcome {
        // Also fence direct dispatch and any already-admitted attempt: readiness alone is not a gate.
        if (!allowTestOnlyExecution) return DurableWebWorkflowOutcome.Failed(WorkflowTerminalReason.REFUSED)
        val meter = WorkflowExecutionMeter(context.reportsDirectory, toolCallsMetered = false)
        // Completed samples are progress: a long healthy exploration writes its report only at the end.
        val (result, usage) = executor.run(context.attempt.limits, meter) {
            engines.explore(context.job.binaryPath, context.reportsDirectory, meter::activity)
        }
        return when (unwrap(result)) {
            is BoundedWorkflowResult.Returned -> DurableWebWorkflowOutcome.Completed(usage = usage)
            is BoundedWorkflowResult.Exhausted -> limitFailure(usage)
            is BoundedWorkflowResult.Threw -> DurableWebWorkflowOutcome.Failed(usage = usage)
        }
    }
}

internal class ReconstructWorkflowAdapter(
    private val engines: WebWorkflowEngines,
    private val executor: BoundedWorkflowExecutor,
    private val mode: WebReconstructionMode,
    override val harnessCapabilityId: String,
    private val sensitiveValues: Collection<String>,
    // Inert integration controls only. Production registration never opts into uncontained compilation.
    private val allowTestOnlyExecution: Boolean = false,
    // Injection seam for crash/durability tests; production always opens the ordinary workspace.
    private val workspaceOpener: (Path, Path) -> ReconstructionOutputWorkspace = ReconstructionOutputWorkspace::open,
) : DurableWebWorkflowAdapter {
    private val agent = mode == WebReconstructionMode.AGENT
    override val workflow = WorkflowKind.RECONSTRUCT
    // No production checkpoint policy yet (no agent-session journal reconciliation), so POST R/recover
    // reports resume as RESUME_UNSUPPORTED; an explicit retry always starts a fresh linked attempt.
    override val checkpoints: DurableWebWorkflowCheckpointPolicy? = null
    override val limits = if (agent) WebWorkflowDefaults.RECONSTRUCT_AGENT else WebWorkflowDefaults.RECONSTRUCT_EVIDENCE
    override val limitsAdjustable = true
    override val requirements = if (agent) setOf(WebWorkflowRequirement.GHIDRA, WebWorkflowRequirement.AGENT_HARNESS) +
        if (!allowTestOnlyExecution) setOf(WebWorkflowRequirement.MODULE_COMPILATION_CONTAINMENT) else emptySet()
        else setOf(WebWorkflowRequirement.GHIDRA)
    override val input = DurableWebWorkflowInput.NONE
    override val launch = if (agent) DurableWebWorkflowLaunch(DurableWebWorkflowMode.AGENT, executesBinary = false,
        contactsAgent = true, requiredTools = listOf("ghidra", "agent-harness", "c-toolchain"))
        else DurableWebWorkflowLaunch(DurableWebWorkflowMode.EVIDENCE_ONLY, executesBinary = false, contactsAgent = false,
        requiredTools = listOf("ghidra", "c-toolchain"))

    init { require(harnessCapabilityId.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}"))) }

    override fun execute(context: DurableWebWorkflowContext): DurableWebWorkflowOutcome {
        if (agent && !allowTestOnlyExecution) return DurableWebWorkflowOutcome.Failed(WorkflowTerminalReason.REFUSED)
        val meter = WorkflowExecutionMeter(context.reportsDirectory, toolCallsMetered = true)
        val (result, usage) = executor.run(context.attempt.limits, meter) {
            // Include workspace admission in the same bounded child as reconstruction. In
            // particular, acquiring the exclusive publication gate may wait behind a long-lived
            // reader; cancellation and limits must be able to interrupt that wait.
            workspaceOpener(context.reportsDirectory, context.job.binaryPath).use { workspace ->
                BestEffortProgressJournal(context.reportsDirectory, "reconstruction", sensitiveValues).use { journal ->
                    val progress = MeteredWorkflowProgress(journal, meter)
                    try {
                        engines.reconstruct(context.job.binaryPath, context.reportsDirectory, mode, progress, workspace, {
                            if (Thread.currentThread().isInterrupted) throw InterruptedException("reconstruction cancelled before publication")
                            meter.admitPublication(context.attempt.limits)
                        }, context.onReconstructionPublicationCommitted ?: {})
                    } catch (failure: Exception) {
                        progress.phase(AgentWorkflowPhase.FAILED)
                        throw failure
                    }
                }
                // Read the candidate while this adapter still owns the exclusive workspace lease.
                // Once publication admission wins, caller cancellation must not interrupt a later
                // read-lease reacquisition and turn a completed publication into a cancelled run.
                reconstructionCandidate(context.reportsDirectory.resolve("source-tree"))
            }
        }
        // Only a completed publication belongs to this attempt. On a rejected, exhausted, or
        // uncertain transaction, the live tree may be the prior accepted generation (or be
        // intentionally unavailable behind a pending journal); never report it as this attempt's
        // candidate.
        val completed = unwrap(result)
        if (completed is BoundedWorkflowResult.Threw &&
            completed.failure is decompengine.project.ReconstructionPublicationPendingException) {
            throw completed.failure
        }
        val candidate = (completed as? BoundedWorkflowResult.Returned)?.value
        return when (completed) {
            is BoundedWorkflowResult.Returned -> DurableWebWorkflowOutcome.Completed(candidate, usage)
            is BoundedWorkflowResult.Exhausted -> DurableWebWorkflowOutcome.Failed(WorkflowTerminalReason.LIMIT_EXHAUSTED, candidate, usage)
            is BoundedWorkflowResult.Threw -> DurableWebWorkflowOutcome.Failed(candidate = candidate, usage = usage)
        }
    }
}

/** The schema-3 build contract records the canonical source digest of the generated inputs. */
internal fun reconstructionCandidate(sourceTree: Path): WorkflowCandidate? {
    return try {
        val contract = readStableRegularFile(sourceTree, "reports/build_contract.json", MAXIMUM_CONTRACT_BYTES).bytes
        val document = OracleJson.parse(contract, StrictJsonLimits(MAXIMUM_CONTRACT_BYTES.toInt(),
            MAXIMUM_CONTRACT_BYTES.toInt(), 16, 100_000, 64 * 1024, MAXIMUM_CONTRACT_BYTES.toInt(), 32)) as? JsonObject ?: return null
        val sha = (document["sourceRevisionSha256"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        if (!sha.matches(Regex("[0-9a-f]{64}"))) null else WorkflowCandidate(webSourceRevisionId(sha), sha)
    } catch (_: Exception) { null }
}

private const val MAXIMUM_CONTRACT_BYTES = 16L * 1024 * 1024

internal class RepairWorkflowAdapter(
    private val engines: WebWorkflowEngines,
    private val executor: BoundedWorkflowExecutor,
    override val harnessCapabilityId: String,
    // Inert integration seam only; metadata cannot attest production acceptance (see #478).
    private val acceptTestOnlyPublication: Boolean = false,
    // Fault injection only. Production always checks the live attempt limits at the decision boundary.
    private val publicationAdmission: ((WorkflowExecutionLimits, WorkflowExecutionMeter) -> Unit)? = null,
) : DurableWebWorkflowAdapter {
    override val workflow = WorkflowKind.REPAIR
    // No production checkpoint policy yet (no agent-session journal reconciliation), so POST R/recover
    // reports resume as RESUME_UNSUPPORTED; an explicit retry always starts a fresh linked attempt.
    override val checkpoints: DurableWebWorkflowCheckpointPolicy? = null
    override val limits = WebWorkflowDefaults.REPAIR
    // The tool-call ceiling is structural (iterations times the per-invocation agent limit), so it is fixed.
    override val limitsAdjustable = false
    override val requirements = setOf(WebWorkflowRequirement.SANDBOX, WebWorkflowRequirement.AGENT_HARNESS,
        WebWorkflowRequirement.REPAIR_VALIDATOR)
    override val input = DurableWebWorkflowInput.RECORDED_REQUIRED
    override val launch = DurableWebWorkflowLaunch(DurableWebWorkflowMode.AGENT, executesBinary = true, contactsAgent = true,
        requiredTools = listOf("sandbox", "agent-harness", "c-toolchain"))
    // No production publisher until canonical evidence attestation is qualified; do not scan a
    // library's graphs merely because the repair execution adapter is registered.
    override val publication: DurableWebWorkflowPublication? = if (acceptTestOnlyPublication)
        DurableWebWorkflowPublication { context -> verifyRepairAcceptance(context, allowTestOnly = true) } else null
    private val harness = when (harnessCapabilityId) {
        "agent-legacy-openai" -> "legacy-openai"
        else -> "acp"
    }

    override fun execute(context: DurableWebWorkflowContext): DurableWebWorkflowOutcome {
        val input = checkNotNull(context.inputSourceTree) { "repair requires a recorded input revision" }
        val meter = WorkflowExecutionMeter(context.reportsDirectory, toolCallsMetered = false)
        var publishedCandidate: WorkflowCandidate? = null
        var preparedCandidate: WorkflowCandidate? = null
        var preparedState: Pair<decompengine.jobs.WorkflowRunState, WorkflowTerminalReason>? = null
        var preparedUsage: WorkflowUsage? = null
        val (result, usage) = executor.run(context.attempt.limits, meter) {
            ReconstructionOutputWorkspace.open(context.reportsDirectory, context.job.binaryPath).use { workspace ->
                var repairOutcome: RepairRunOutcome? = null
                val publication = workspace.publish(setOf("source-tree"), { stage ->
                    val project = stage.resolve("source-tree")
                    // The attempt owns a private staged copy; selected revision evidence is never modified.
                    ReconstructionOutputWorkspace.withReadLeaseIfManaged(input.parent) { copyWebSourceTree(input, project) }
                    val outcome = engines.repair(project, context.job.binaryPath, context.reportsDirectory, harness)
                    repairOutcome = outcome
                    check(outcome.recoveryComplete && outcome.runState.terminal &&
                        outcome.runState.rollbackFailureAttemptId == null && outcome.runState.rollbackResolution == null) {
                        "repair recovery is incomplete or has unresolved rollback state"
                    }
                }, {
                    val injectedAdmission = publicationAdmission
                    if (injectedAdmission != null) injectedAdmission(context.attempt.limits, meter) else {
                        if (Thread.currentThread().isInterrupted) throw InterruptedException("repair cancelled before publication")
                        meter.admitPublication(context.attempt.limits)
                    }
                }, {
                    val outcome = checkNotNull(repairOutcome) { "repair did not return before publication" }
                    val candidate = checkNotNull(repairCandidate(context.reportsDirectory.resolve("source-tree"),
                        context.attempt.startedAt?.toEpochMilli(), allowTestOnly = true)) {
                        "committed repair has no verifiable candidate identity"
                    }
                    val (state, reason) = repairWorkflowTerminal(outcome.runState.status)
                    val expectedCandidate = checkNotNull(preparedCandidate)
                    val expectedState = checkNotNull(preparedState)
                    val expectedUsage = checkNotNull(preparedUsage)
                    check(candidate == expectedCandidate && expectedState == (state to reason)) {
                        "committed repair differs from its durable pre-decision receipt"
                    }
                    context.onRepairPublicationCommitted?.invoke(candidate, state, reason, expectedUsage)
                    publishedCandidate = candidate
                }, beforeDecision = { stage ->
                    val outcome = checkNotNull(repairOutcome) { "repair did not return before publication" }
                    val candidate = checkNotNull(repairCandidate(stage.resolve("source-tree"),
                        context.attempt.startedAt?.toEpochMilli(), allowTestOnly = true)) {
                        "staged repair has no verifiable candidate identity"
                    }
                    val terminal = repairWorkflowTerminal(outcome.runState.status)
                    val usage = meter.usageSoFar()
                    context.onRepairPublicationPrepared?.invoke(candidate, terminal.first, terminal.second, usage)
                    preparedCandidate = candidate
                    preparedState = terminal
                    preparedUsage = usage
                })
                if (publication == decompengine.project.PublicationResult.PENDING)
                    throw decompengine.project.ReconstructionPublicationPendingException()
                if (publication == decompengine.project.PublicationResult.REJECTED)
                    throw InterruptedException("repair publication was rejected before its decision")
                val outcome = checkNotNull(repairOutcome) { "repair did not return an outcome" }
                outcome
            }
        }
        val completedResult = unwrap(result)
        if (completedResult is BoundedWorkflowResult.Threw &&
            completedResult.failure is decompengine.project.ReconstructionPublicationPendingException) {
            throw completedResult.failure
        }
        val completedOutcome = (completedResult as? BoundedWorkflowResult.Returned)?.value
        val publishable = completedOutcome?.let { it.recoveryComplete && it.runState.terminal &&
            it.runState.rollbackFailureAttemptId == null && it.runState.rollbackResolution == null } == true
        val candidate = if (publishable) publishedCandidate else null
        return when (completedResult) {
            is BoundedWorkflowResult.Exhausted -> DurableWebWorkflowOutcome.Failed(WorkflowTerminalReason.LIMIT_EXHAUSTED, null, usage)
            is BoundedWorkflowResult.Threw -> DurableWebWorkflowOutcome.Failed(candidate = null, usage = usage)
            is BoundedWorkflowResult.Returned -> when (completedResult.value.runState.status) {
                RepairRunStatus.FULLY_ACCEPTED, RepairRunStatus.COMPILE_VALID ->
                    if (publishable) DurableWebWorkflowOutcome.Completed(candidate, usage)
                    else DurableWebWorkflowOutcome.Failed(candidate = null, usage = usage)
                RepairRunStatus.NO_CHANGES -> DurableWebWorkflowOutcome.Completed(candidate, usage, WorkflowTerminalReason.NO_CHANGES)
                RepairRunStatus.ITERATION_EXHAUSTED, RepairRunStatus.RESOURCE_EXHAUSTED ->
                    DurableWebWorkflowOutcome.Failed(WorkflowTerminalReason.LIMIT_EXHAUSTED, candidate, usage)
                else -> DurableWebWorkflowOutcome.Failed(candidate = candidate, usage = usage)
            }
        }
    }
}

private val GRAPH_IDENTITY = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
private val DIGEST = Regex("[0-9a-f]{64}")

/** The source digest of one recorded graph node, when its identity and digest are disclosed. */
private fun nodeSource(snapshot: RepairHistorySnapshot, identity: decompengine.repair.RepairRecordedIdentity?): String? {
    if (identity == null || identity.rawIdentityWithheld || !identity.value.matches(GRAPH_IDENTITY)) return null
    val source = snapshot.attempts.singleOrNull { it.identity == identity }?.sourceRevisionSha256
        ?: snapshot.acceptedBaseline?.takeIf { it.identity == identity }?.sourceRevisionSha256
    return source?.takeIf { it.matches(DIGEST) }
}

/**
 * The repair graph's fully accepted head, bound to a fully accepted run that began within this
 * attempt (a copied input history cannot lend its earlier acceptance) and published for release.
 */
private fun acceptedHead(snapshot: RepairHistorySnapshot, attemptStartedMillis: Long?, allowTestOnly: Boolean): Pair<String, String>? {
    val head = snapshot.fullyAcceptedHead ?: return null
    val started = attemptStartedMillis ?: return null
    if (snapshot.runs.none { it.status == RepairRunStatus.FULLY_ACCEPTED && it.acceptedHead == head && it.startedEpochMillis >= started }) return null
    if (head.rawIdentityWithheld || !head.value.matches(GRAPH_IDENTITY)) return null
    // A baseline that already validated is the accepted root itself; it has no iteration entry.
    snapshot.acceptedBaseline?.takeIf { it.identity == head }?.let { baseline ->
        if (!allowTestOnly && baseline.assurance != RepairValidationAssurance.STRICT_CONTAINED) return null
        return head.value to (baseline.sourceRevisionSha256.takeIf { it.matches(DIGEST) } ?: return null)
    }
    val node = snapshot.attempts.singleOrNull { it.identity == head } ?: return null
    if (node.status != ModuleRevisionStatus.ACCEPTED) return null
    if (!allowTestOnly && node.publicationMode == RepairPublicationMode.TEST_ONLY_NON_RELEASE) return null
    return head.value to (nodeSource(snapshot, head) ?: return null)
}

private fun recordedHistory(project: Path): RepairHistorySnapshot? {
    val history = try { readProjectRecordedRepairHistory(project) } catch (_: Exception) { return null }
    return history.snapshot?.takeIf { history.status == RepairHistoryReadStatus.RECORDED }
}

private fun repairCandidate(project: Path, attemptStartedMillis: Long?, allowTestOnly: Boolean): WorkflowCandidate? {
    val snapshot = recordedHistory(project)
    // Prefer the accepted head; otherwise the published head remains an unaccepted candidate.
    val sha = snapshot?.let { acceptedHead(it, attemptStartedMillis, allowTestOnly)?.second ?: nodeSource(it, it.publishedHead) }
        ?: return reconstructionCandidate(project)
    return WorkflowCandidate(webSourceRevisionId(sha), sha)
}

internal data class CommittedRepairPublication(
    val candidate: WorkflowCandidate,
    val state: decompengine.jobs.WorkflowRunState,
    val reason: WorkflowTerminalReason,
)

private fun repairWorkflowTerminal(status: RepairRunStatus): Pair<decompengine.jobs.WorkflowRunState, WorkflowTerminalReason> =
    when (status) {
        RepairRunStatus.FULLY_ACCEPTED, RepairRunStatus.COMPILE_VALID ->
            decompengine.jobs.WorkflowRunState.COMPLETED to WorkflowTerminalReason.COMPLETED
        RepairRunStatus.NO_CHANGES ->
            decompengine.jobs.WorkflowRunState.COMPLETED to WorkflowTerminalReason.NO_CHANGES
        RepairRunStatus.ITERATION_EXHAUSTED, RepairRunStatus.RESOURCE_EXHAUSTED ->
            decompengine.jobs.WorkflowRunState.FAILED to WorkflowTerminalReason.LIMIT_EXHAUSTED
        else -> decompengine.jobs.WorkflowRunState.FAILED to WorkflowTerminalReason.FAILED
    }

/** Reconstruct the committed repair outcome from its durable graph after process death. */
internal fun committedRepairPublication(project: Path, attemptStartedMillis: Long?): CommittedRepairPublication? {
    val started = attemptStartedMillis ?: return null
    val snapshot = recordedHistory(project) ?: return null
    val run = snapshot.runs.singleOrNull { it.startedEpochMillis >= started } ?: return null
    if (run.status == RepairRunStatus.RUNNING || run.rollbackFailureAttempt != null || run.rollbackResolution != null) return null
    val candidate = repairCandidate(project, started, allowTestOnly = true) ?: return null
    val (state, reason) = repairWorkflowTerminal(run.status)
    return CommittedRepairPublication(candidate, state, reason)
}

/**
 * Inert publication control only. Recorded history is metadata, NOT acceptance authority: it does
 * not verify installed sources, blobs, receipt bodies or their binary/profile/corpus commitments.
 * Production must remain closed until a workflow-owned bounded read-only attestation is qualified
 * for that full scope (#478). Never substitute the mutating graph recovery path here.
 */
internal fun verifyRepairAcceptance(context: DurableWebWorkflowPublicationContext, allowTestOnly: Boolean = false): WorkflowAcceptanceReference? {
    if (!allowTestOnly) return null
    val candidate = context.attempt.candidate ?: return null
    context.checkpoint()
    val history = readProjectRecordedRepairHistory(context.reportsDirectory.resolve("source-tree"),
        reserveCapture = context.reserveCapture, cancel = context.checkpoint)
    // The diagnostic reader withholds a snapshot on any failure; never swallow the caller's latch.
    context.checkpoint()
    val snapshot = history.snapshot?.takeIf { history.status == RepairHistoryReadStatus.RECORDED } ?: return null
    val (node, sha) = acceptedHead(snapshot, context.attempt.startedAt?.toEpochMilli(), allowTestOnly) ?: return null
    if (candidate != WorkflowCandidate(webSourceRevisionId(sha), sha) || !snapshot.graphSha256.matches(DIGEST)) return null
    return WorkflowAcceptanceReference(context.attempt.jobId, context.attempt.runId, candidate.revisionId, sha,
        node, "repair-graph", snapshot.graphSha256)
}

/** Bounded copy of regular files and directories only; links and special files refuse the copy. */
internal fun copyWebSourceTree(source: Path, target: Path, maximumEntries: Int = 200_000, maximumBytes: Long = 4L * 1024 * 1024 * 1024) {
    require(maximumEntries > 0 && maximumBytes >= 0) { "selected source tree copy limits are invalid" }
    require(!Files.exists(target, NOFOLLOW_LINKS)) { "attempt source tree already exists" }
    val sourceRoot = LinuxFilesystemSyscalls.openAbsolutePathOrNull(source)
        ?: throw IOException("selected source tree is unavailable")
    sourceRoot.use { rootPath ->
        require(rootPath.identity.isDirectory && !rootPath.identity.isSymbolicLink) {
            "selected source tree is unavailable"
        }
        LinuxFilesystemSyscalls.openDirectoryFrom(rootPath).use { root ->
            var entries = 0
            var bytes = 0L
            copyWebDirectory(root, target, maximumEntries, maximumBytes,
                countEntry = { size ->
                    entries = Math.addExact(entries, 1)
                    check(entries <= maximumEntries) { "selected source tree exceeds its copy limits" }
                    bytes = Math.addExact(bytes, size)
                    check(bytes <= maximumBytes) { "selected source tree exceeds its copy limits" }
                })
        }
    }
}

private fun copyWebDirectory(
    source: LinuxDescriptor,
    target: Path,
    maximumEntries: Int,
    maximumBytes: Long,
    countEntry: (Long) -> Unit,
    depth: Int = 0,
) {
    check(depth <= MAXIMUM_WEB_SOURCE_COPY_DEPTH) { "selected source tree exceeds its copy depth limit" }
    check(!Thread.currentThread().isInterrupted) { "source copy interrupted" }
    val initial = LinuxFilesystemSyscalls.directoryMetadata(source)
    val names = LinuxFilesystemSyscalls.directoryEntryNamesWithoutAtime(source, maximumEntries) {
        if (Thread.currentThread().isInterrupted) throw InterruptedException("source copy interrupted")
    }.sorted()
    Files.createDirectory(target)
    for (name in names) {
        if (Thread.currentThread().isInterrupted) throw InterruptedException("source copy interrupted")
        val path = target.resolve(name)
        val entry = LinuxFilesystemSyscalls.openPathAtOrNull(source.fd, name)
            ?: throw IOException("selected source tree entry disappeared")
        entry.use { observed ->
            when {
                observed.identity.isDirectory && !observed.identity.isSymbolicLink -> {
                    countEntry(0)
                    LinuxFilesystemSyscalls.openDirectoryAt(source.fd, name).use { child ->
                        require(child.identity.key == observed.identity.key) { "selected source directory changed during copy" }
                        copyWebDirectory(child, path, maximumEntries, maximumBytes, countEntry, depth + 1)
                    }
                }
                observed.identity.isRegularFile && !observed.identity.isSymbolicLink -> {
                    LinuxFilesystemSyscalls.openRegularFileAtOrNull(source.fd, name)?.use { authorized ->
                        require(authorized.identity.key == observed.identity.key) { "selected source file changed during copy" }
                        val before = LinuxFilesystemSyscalls.fileState(authorized)
                        check(before.size <= maximumBytes) { "selected source tree exceeds its copy limits" }
                        countEntry(before.size)
                        var copiedBytes = 0L
                        Files.newOutputStream(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { output ->
                            LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(authorized).use { readable ->
                                val openedState = LinuxFilesystemSyscalls.fileState(readable)
                                require(openedState == before) { "selected source file changed before metadata-neutral copy" }
                                while (true) {
                                    if (Thread.currentThread().isInterrupted) throw InterruptedException("source copy interrupted")
                                    val remaining = before.size - copiedBytes
                                    require(remaining >= 0) { "selected source file exceeds its admitted size" }
                                    val request = if (remaining >= 64 * 1024L) 64 * 1024 else remaining.toInt() + 1
                                    val chunk = LinuxFilesystemSyscalls.readWithoutAtime(readable, request)
                                    if (chunk.isEmpty()) break
                                    require(chunk.size.toLong() <= remaining) {
                                        "selected source file grew beyond its admitted size"
                                    }
                                    output.write(chunk)
                                    copiedBytes = Math.addExact(copiedBytes, chunk.size.toLong())
                                }
                                require(LinuxFilesystemSyscalls.fileState(readable) == before) {
                                    "selected source file changed during metadata-neutral copy"
                                }
                            }
                        }
                        require(copiedBytes == before.size) { "selected source file copy was incomplete" }
                        applyWebCopyMetadata(path, before.identity.mode, before.accessTimeSeconds,
                            before.accessTimeNanoseconds, before.modificationTimeSeconds,
                            before.modificationTimeNanoseconds)
                    } ?: throw IOException("selected source file disappeared")
                }
                else -> throw IOException("selected source tree contains an unsupported entry")
            }
        }
    }
    require(LinuxFilesystemSyscalls.directoryMetadata(source) == initial) {
        "selected source directory changed during metadata-neutral copy"
    }
    val afterNames = LinuxFilesystemSyscalls.directoryEntryNamesWithoutAtime(source, maximumEntries) {
        if (Thread.currentThread().isInterrupted) throw InterruptedException("source copy interrupted")
    }.sorted()
    require(afterNames == names) { "selected source directory entries changed during copy" }
    applyWebCopyMetadata(target, initial.mode, initial.accessTimeSeconds, initial.accessTimeNanoseconds,
        initial.modificationTimeSeconds, initial.modificationTimeNanoseconds)
}

private fun applyWebCopyMetadata(
    path: Path,
    mode: Int,
    accessSeconds: Long,
    accessNanos: Int,
    modificationSeconds: Long,
    modificationNanos: Int,
) {
    Files.setAttribute(path, "unix:mode", mode and 0xfff, NOFOLLOW_LINKS)
    val view = Files.getFileAttributeView(path, java.nio.file.attribute.BasicFileAttributeView::class.java, NOFOLLOW_LINKS)
        ?: throw IOException("private source copy cannot preserve timestamps")
    view.setTimes(
        FileTime.from(java.time.Instant.ofEpochSecond(modificationSeconds, modificationNanos.toLong())),
        FileTime.from(java.time.Instant.ofEpochSecond(accessSeconds, accessNanos.toLong())),
        null,
    )
}

internal val WEB_AGENT_CONTRACT_VERSION: Int = AGENT_EXECUTION_CONTRACT_VERSION
