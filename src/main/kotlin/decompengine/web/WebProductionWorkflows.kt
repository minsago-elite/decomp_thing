package decompengine.web

import decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION
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
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.ArchivalReconstructionService
import decompengine.project.GhidraHeadlessProgramModelAnalyzer
import decompengine.repair.ModuleRevisionStatus
import decompengine.repair.RepairPublicationMode
import decompengine.repair.RepairHistoryReadStatus
import decompengine.repair.RepairHistorySnapshot
import decompengine.repair.RepairRunStatus
import decompengine.repair.RepairRuntimeConfiguration
import decompengine.repair.SecureRepairRuntime
import decompengine.repair.readProjectRecordedRepairHistory
import decompengine.validation.ProcessInput
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.BasicFileAttributes

/**
 * The existing CLI/legacy implementations behind each production adapter. Tests substitute inert
 * engines; production engines are the same exploration, archival reconstruction and secure repair
 * entry points the `explore`, `reconstruct` and `repair` commands use.
 */
internal interface WebWorkflowEngines {
    fun explore(binary: Path, reportsDirectory: Path)
    /** [harness] is the admitted selection for an agent run, null for evidence-only reconstruction. */
    fun reconstruct(binary: Path, reportsDirectory: Path, mode: WebReconstructionMode, progress: AgentWorkflowProgress,
        harness: WebAdmittedHarness? = null)
    fun repair(project: Path, binary: Path, reportsDirectory: Path, harness: WebAdmittedHarness): RepairRunStatus

    companion object {
        fun production(environment: Map<String, String>, sensitiveValues: Collection<String>): WebWorkflowEngines = object : WebWorkflowEngines {
            override fun explore(binary: Path, reportsDirectory: Path) {
                AutomaticExplorer().explore(binary, listOf(CandidateInput("seed_default", CandidateSource.SEED)), reportsDirectory)
            }

            override fun reconstruct(binary: Path, reportsDirectory: Path, mode: WebReconstructionMode, progress: AgentWorkflowProgress,
                harness: WebAdmittedHarness?) {
                // The explicit request mode and harness replace the legacy environment choices.
                var selected = environment + (WEB_RECONSTRUCTION_MODE_KEY to mode.configurationValue)
                if (harness != null) selected = selected + ("ACP_HARNESS" to harness.selector)
                val strategy = selectWebReconstructionStrategy(selected, progress)
                harness?.requireResolved(strategy.harnessProvenance?.stableDescriptor)
                Files.createDirectories(reportsDirectory)
                Files.writeString(reportsDirectory.resolve("reconstruction_harness_selection.json"), renderWebReconstructionHarnessSelection(strategy))
                ArchivalReconstructionService(GhidraHeadlessProgramModelAnalyzer.bundled(), strategy.reconstructor,
                    profile = strategy.profile, progress = progress).reconstruct(binary, reportsDirectory)
            }

            override fun repair(project: Path, binary: Path, reportsDirectory: Path, harness: WebAdmittedHarness): RepairRunStatus {
                val configuration = RepairRuntimeConfiguration("generated-c-make-v1", reportsDirectory.resolve("repair_history.json"),
                    harnessOverride = harness.selector)
                return SecureRepairRuntime.open(configuration).use { runtime ->
                    // The gate made the sole selection; refuse before any repair if it is not the admitted one.
                    harness.requireResolved(runtime.harnessProvenance)
                    runtime.runRepair(project, binary, listOf(ProcessInput("default")), reportsDirectory, REPAIR_ITERATIONS).runState.status
                }
            }
        }
    }
}

/**
 * The harness an attempt was admitted with: its exact factory selector and, when the admission snapshot
 * resolved it, the stable provenance descriptor. A run never proceeds under a different resolution.
 */
internal data class WebAdmittedHarness(val harness: WebAgentHarness, val expectedDescriptor: String?) {
    val selector: String get() = checkNotNull(harness.selector) { "the built-in harness is not executable" }

    fun requireResolved(actualDescriptor: String?) {
        if (expectedDescriptor != null && actualDescriptor != expectedDescriptor) throw WebHarnessConfigurationChanged()
    }

    companion object {
        /** Rebuilds the recorded descriptor; a record the current factory cannot reproduce never matches. */
        fun of(harness: WebAgentHarness, recorded: decompengine.jobs.WorkflowAttemptHarness?): WebAdmittedHarness {
            val descriptor = recorded?.takeIf { it.kind == harness.wireName && it.implementationId != null }?.let {
                try {
                    decompengine.acp.AcpHarnessProvenance(it.kind, checkNotNull(it.implementationId), it.agentContractVersion,
                        it.protocolVersion, it.sdkVersion, it.configurationSha256, it.deprecated).stableDescriptor
                } catch (_: IllegalArgumentException) { UNREPRODUCIBLE }
            }
            return WebAdmittedHarness(harness, descriptor)
        }
        private const val UNREPRODUCIBLE = "unreproducible-recorded-harness"
    }
}

/** The harness resolved at execution differs from the one recorded at admission; nothing ran under it. */
internal class WebHarnessConfigurationChanged : RuntimeException("the agent harness configuration changed after admission")

private const val WEB_RECONSTRUCTION_MODE_KEY = "WEB_RECONSTRUCTION_MODE"
private const val REPAIR_ITERATIONS = 5
/** Each repair iteration is one agent invocation bounded by the default agent limit of 256 tool calls. */
private val REPAIR_TOOL_CALLS: ULong = 1280uL

/** Deterministic identity: a revision identifier can never name a different source digest. */
internal fun webSourceRevisionId(sourceSha256: String): String {
    require(sourceSha256.matches(Regex("[0-9a-f]{64}")))
    return "source_$sourceSha256"
}

/**
 * Builds production registrations: one agent option per executable harness. ACP is the default and is
 * always registered; the deprecated legacy adapter only when the operator explicitly selected it. The
 * built-in harness has no registration, so it is reported as unsupported and can never be admitted.
 */
internal fun productionDurableWebWorkflows(
    environment: Map<String, String> = System.getenv(),
    sensitiveValues: Collection<String> = environment.values,
    engines: WebWorkflowEngines = WebWorkflowEngines.production(environment, sensitiveValues),
    executor: BoundedWorkflowExecutor = BoundedWorkflowExecutor(),
): List<DurableWebWorkflowAdapter> {
    val harnesses = listOfNotNull(WebAgentHarness.ACP,
        WebAgentHarness.LEGACY_OPENAI.takeIf { WebHarnessReadinessProjector.legacyHarnessConfigured(environment) })
    return listOf(ExploreWorkflowAdapter(engines, executor)) +
        harnesses.map { ReconstructWorkflowAdapter(engines, executor, WebReconstructionMode.AGENT, it, sensitiveValues) } +
        ReconstructWorkflowAdapter(engines, executor, WebReconstructionMode.EVIDENCE_ONLY, null, sensitiveValues) +
        harnesses.map { RepairWorkflowAdapter(engines, executor, it) }
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

internal class ExploreWorkflowAdapter(private val engines: WebWorkflowEngines, private val executor: BoundedWorkflowExecutor) : DurableWebWorkflowAdapter {
    override val workflow = WorkflowKind.EXPLORE
    override val limits = WebWorkflowDefaults.EXPLORE
    override val limitsAdjustable = true
    override val requirements = setOf(WebWorkflowRequirement.SANDBOX)
    override val input = DurableWebWorkflowInput.NONE
    override val launch = DurableWebWorkflowLaunch(DurableWebWorkflowMode.TOOLS, executesBinary = true, contactsAgent = false,
        requiredTools = listOf("sandbox", "angr"))

    override fun execute(context: DurableWebWorkflowContext): DurableWebWorkflowOutcome {
        val meter = WorkflowExecutionMeter(context.reportsDirectory, toolCallsMetered = false)
        val (result, usage) = executor.run(context.attempt.limits, meter) { engines.explore(context.job.binaryPath, context.reportsDirectory) }
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
    /** The agent option's single harness; null for evidence-only reconstruction. */
    private val harness: WebAgentHarness?,
    private val sensitiveValues: Collection<String>,
) : DurableWebWorkflowAdapter {
    private val agent = mode == WebReconstructionMode.AGENT
    override val harnessCapabilityId: String = harness?.capabilityId ?: EVIDENCE_ONLY_CAPABILITY
    override val workflow = WorkflowKind.RECONSTRUCT
    override val limits = if (agent) WebWorkflowDefaults.RECONSTRUCT_AGENT else WebWorkflowDefaults.RECONSTRUCT_EVIDENCE
    override val limitsAdjustable = true
    override val requirements = if (agent) setOf(WebWorkflowRequirement.GHIDRA, WebWorkflowRequirement.AGENT_HARNESS)
        else setOf(WebWorkflowRequirement.GHIDRA)
    override val input = DurableWebWorkflowInput.NONE
    override val launch = if (agent) DurableWebWorkflowLaunch(DurableWebWorkflowMode.AGENT, executesBinary = false,
        contactsAgent = true, requiredTools = listOf("ghidra", "agent-harness", "c-toolchain"), harness = harness)
        else DurableWebWorkflowLaunch(DurableWebWorkflowMode.EVIDENCE_ONLY, executesBinary = false, contactsAgent = false,
        requiredTools = listOf("ghidra", "c-toolchain"))

    init { require(agent == (harness != null)) { "only agent reconstruction names a harness" } }

    override fun execute(context: DurableWebWorkflowContext): DurableWebWorkflowOutcome {
        val admitted = harness?.let { WebAdmittedHarness.of(it, context.attempt.configuration?.harness) }
        val meter = WorkflowExecutionMeter(context.reportsDirectory, toolCallsMetered = true)
        val (result, usage) = executor.run(context.attempt.limits, meter) {
            BestEffortProgressJournal(context.reportsDirectory, "reconstruction", sensitiveValues).use { journal ->
                val progress = MeteredWorkflowProgress(journal, meter)
                try {
                    engines.reconstruct(context.job.binaryPath, context.reportsDirectory, mode, progress, admitted)
                } catch (failure: Exception) {
                    progress.phase(AgentWorkflowPhase.FAILED)
                    throw failure
                }
            }
        }
        // Candidate output is recorded whenever a canonical source revision exists; it is never acceptance.
        val candidate = reconstructionCandidate(context.reportsDirectory.resolve("source-tree"))
        return when (val completed = unwrap(result)) {
            is BoundedWorkflowResult.Returned -> DurableWebWorkflowOutcome.Completed(candidate, usage)
            is BoundedWorkflowResult.Exhausted -> DurableWebWorkflowOutcome.Failed(WorkflowTerminalReason.LIMIT_EXHAUSTED, candidate, usage)
            is BoundedWorkflowResult.Threw -> DurableWebWorkflowOutcome.Failed(refusal(completed.failure), candidate, usage)
        }
    }
}

/** A changed harness refuses the attempt; it is not a workflow failure of the selected harness. */
private fun refusal(failure: Throwable): WorkflowTerminalReason =
    if (failure is WebHarnessConfigurationChanged) WorkflowTerminalReason.REFUSED else WorkflowTerminalReason.FAILED

/** The schema-3 build contract records the canonical source digest of the generated inputs. */
internal fun reconstructionCandidate(sourceTree: Path): WorkflowCandidate? {
    val contract = sourceTree.resolve("reports").resolve("build_contract.json")
    return try {
        if (!Files.isRegularFile(contract, NOFOLLOW_LINKS) || Files.size(contract) > MAXIMUM_CONTRACT_BYTES) return null
        val document = OracleJson.parse(Files.readAllBytes(contract), StrictJsonLimits(MAXIMUM_CONTRACT_BYTES.toInt(),
            MAXIMUM_CONTRACT_BYTES.toInt(), 16, 100_000, 64 * 1024, MAXIMUM_CONTRACT_BYTES.toInt(), 32)) as? JsonObject ?: return null
        val sha = (document["sourceRevisionSha256"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        if (!sha.matches(Regex("[0-9a-f]{64}"))) null else WorkflowCandidate(webSourceRevisionId(sha), sha)
    } catch (_: Exception) { null }
}

private const val MAXIMUM_CONTRACT_BYTES = 16L * 1024 * 1024

internal class RepairWorkflowAdapter(
    private val engines: WebWorkflowEngines,
    private val executor: BoundedWorkflowExecutor,
    private val harness: WebAgentHarness,
    // Test seam only: production never accepts a test-only, release-ineligible graph publication.
    private val acceptTestOnlyPublication: Boolean = false,
) : DurableWebWorkflowAdapter {
    override val harnessCapabilityId: String = harness.capabilityId
    override val workflow = WorkflowKind.REPAIR
    override val limits = WebWorkflowDefaults.REPAIR
    // The tool-call ceiling is structural (iterations times the per-invocation agent limit), so it is fixed.
    override val limitsAdjustable = false
    override val requirements = setOf(WebWorkflowRequirement.SANDBOX, WebWorkflowRequirement.AGENT_HARNESS)
    override val input = DurableWebWorkflowInput.RECORDED_REQUIRED
    override val launch = DurableWebWorkflowLaunch(DurableWebWorkflowMode.AGENT, executesBinary = true, contactsAgent = true,
        requiredTools = listOf("sandbox", "agent-harness", "c-toolchain"), harness = harness)
    override val publication = DurableWebWorkflowPublication { context -> verifyRepairAcceptance(context, acceptTestOnlyPublication) }

    override fun execute(context: DurableWebWorkflowContext): DurableWebWorkflowOutcome {
        val input = checkNotNull(context.inputSourceTree) { "repair requires a recorded input revision" }
        val project = context.reportsDirectory.resolve("source-tree")
        val admitted = WebAdmittedHarness.of(harness, context.attempt.configuration?.harness)
        val meter = WorkflowExecutionMeter(context.reportsDirectory, toolCallsMetered = false)
        val (result, usage) = executor.run(context.attempt.limits, meter) {
            // The attempt owns a private copy; the selected revision's retained evidence is never modified.
            copyWebSourceTree(input, project)
            engines.repair(project, context.job.binaryPath, context.reportsDirectory, admitted)
        }
        val candidate = repairCandidate(project, context.attempt.startedAt?.toEpochMilli(), acceptTestOnlyPublication)
        return when (val completed = unwrap(result)) {
            is BoundedWorkflowResult.Exhausted -> DurableWebWorkflowOutcome.Failed(WorkflowTerminalReason.LIMIT_EXHAUSTED, candidate, usage)
            is BoundedWorkflowResult.Threw -> DurableWebWorkflowOutcome.Failed(refusal(completed.failure), candidate, usage)
            is BoundedWorkflowResult.Returned -> when (completed.value) {
                RepairRunStatus.FULLY_ACCEPTED, RepairRunStatus.COMPILE_VALID -> DurableWebWorkflowOutcome.Completed(candidate, usage)
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
    return snapshot.attempts.singleOrNull { it.identity == identity }?.sourceRevisionSha256?.takeIf { it.matches(DIGEST) }
}

/**
 * The repair graph's fully accepted head, bound to a fully accepted run that began within this
 * attempt (a copied input history cannot lend its earlier acceptance) and published for release.
 */
private fun acceptedHead(snapshot: RepairHistorySnapshot, attemptStartedMillis: Long?, allowTestOnly: Boolean): Pair<String, String>? {
    val head = snapshot.fullyAcceptedHead ?: return null
    val started = attemptStartedMillis ?: return null
    if (snapshot.runs.none { it.status == RepairRunStatus.FULLY_ACCEPTED && it.acceptedHead == head && it.startedEpochMillis >= started }) return null
    val node = snapshot.attempts.singleOrNull { it.identity == head } ?: return null
    if (node.status !in setOf(ModuleRevisionStatus.ACCEPTED, ModuleRevisionStatus.ROOT)) return null
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

/** Read-only attestation from the canonical repair graph; a candidate digest alone is never acceptance. */
internal fun verifyRepairAcceptance(context: DurableWebWorkflowPublicationContext, allowTestOnly: Boolean = false): WorkflowAcceptanceReference? {
    val candidate = context.attempt.candidate ?: return null
    val snapshot = recordedHistory(context.reportsDirectory.resolve("source-tree")) ?: return null
    val (node, sha) = acceptedHead(snapshot, context.attempt.startedAt?.toEpochMilli(), allowTestOnly) ?: return null
    if (candidate != WorkflowCandidate(webSourceRevisionId(sha), sha) || !snapshot.graphSha256.matches(DIGEST)) return null
    return WorkflowAcceptanceReference(context.attempt.jobId, context.attempt.runId, candidate.revisionId, sha,
        node, "repair-graph", snapshot.graphSha256)
}

/** Bounded copy of regular files and directories only; links and special files refuse the copy. */
internal fun copyWebSourceTree(source: Path, target: Path, maximumEntries: Int = 200_000, maximumBytes: Long = 4L * 1024 * 1024 * 1024) {
    require(Files.isDirectory(source, NOFOLLOW_LINKS)) { "selected source tree is unavailable" }
    require(!Files.exists(target, NOFOLLOW_LINKS)) { "attempt source tree already exists" }
    var entries = 0
    var bytes = 0L
    Files.walkFileTree(source, object : SimpleFileVisitor<Path>() {
        override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
            check(!attrs.isSymbolicLink && ++entries <= maximumEntries) { "selected source tree exceeds its copy limits" }
            if (Thread.currentThread().isInterrupted) throw InterruptedException("source copy interrupted")
            Files.createDirectory(target.resolve(source.relativize(dir).toString()))
            return FileVisitResult.CONTINUE
        }
        override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
            check(attrs.isRegularFile && ++entries <= maximumEntries) { "selected source tree contains an unsupported entry" }
            bytes += attrs.size()
            check(bytes <= maximumBytes) { "selected source tree exceeds its copy limits" }
            if (Thread.currentThread().isInterrupted) throw InterruptedException("source copy interrupted")
            Files.copy(file, target.resolve(source.relativize(file).toString()), StandardCopyOption.COPY_ATTRIBUTES, java.nio.file.LinkOption.NOFOLLOW_LINKS)
            return FileVisitResult.CONTINUE
        }
    })
}

internal val WEB_AGENT_CONTRACT_VERSION: Int = AGENT_EXECUTION_CONTRACT_VERSION
