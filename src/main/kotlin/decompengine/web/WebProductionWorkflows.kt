package decompengine.web

import decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION
import decompengine.agent.AgentWorkflowPhase
import decompengine.agent.AgentWorkflowProgress
import decompengine.exploration.AutomaticExplorer
import decompengine.exploration.CandidateInput
import decompengine.exploration.CandidateSource
import decompengine.jobs.BestEffortProgressJournal
import decompengine.jobs.Job
import decompengine.jobs.MAX_JOB_INPUT_BYTES
import decompengine.jobs.WorkflowAcceptanceReference
import decompengine.jobs.WorkflowCandidate
import decompengine.jobs.WorkflowEvidenceModel
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowRepairBinding
import decompengine.jobs.WorkflowKind
import decompengine.jobs.WorkflowTerminalReason
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.ArchivalReconstructionService
import decompengine.project.ProgramModelAnalyzer
import decompengine.project.GhidraHeadlessProgramModelAnalyzer
import decompengine.repair.ModuleRevisionStatus
import decompengine.repair.RepairPublicationCommitment
import decompengine.repair.RepairPublicationOwner
import decompengine.repair.RepairPublicationMode
import decompengine.repair.RepairValidationAssurance
import decompengine.repair.RepairHistoryReadStatus
import decompengine.repair.RepairHistorySnapshot
import decompengine.repair.RepairRunStatus
import decompengine.repair.RepairRuntimeConfiguration
import decompengine.repair.SecureRepairRuntime
import decompengine.repair.hashStableRegularFile
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
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFileAttributes
import java.nio.file.attribute.PosixFilePermissions

internal data class WebRepairResult(val status: RepairRunStatus, val publication: RepairPublicationCommitment? = null) {
    init { require(publication == null || status == RepairRunStatus.FULLY_ACCEPTED) }
}

/**
 * The existing CLI/legacy implementations behind each production adapter. Tests substitute inert
 * engines; production engines are the same exploration, archival reconstruction and secure repair
 * entry points the `explore`, `reconstruct` and `repair` commands use.
 */
internal interface WebWorkflowEngines {
    /** [activity] is called after each completed exploration sample. */
    fun explore(binary: Path, reportsDirectory: Path, activity: () -> Unit)
    /** Evidence-only reconstruction receives the owner's [WebInputSnapshot] as [binary], never the live upload path. */
    fun reconstruct(binary: Path, reportsDirectory: Path, mode: WebReconstructionMode, progress: AgentWorkflowProgress,
        published: (PublishedEvidenceModel) -> Unit)
    fun repair(project: Path, binary: Path, reportsDirectory: Path, harness: String,
        owner: RepairPublicationOwner?): WebRepairResult

    companion object {
        fun production(environment: Map<String, String>, sensitiveValues: Collection<String>): WebWorkflowEngines = object : WebWorkflowEngines {
            override fun explore(binary: Path, reportsDirectory: Path, activity: () -> Unit) {
                AutomaticExplorer(coverage = decompengine.exploration.OutputCoverageMeasurer(onSample = activity))
                    .explore(binary, listOf(CandidateInput("seed_default", CandidateSource.SEED)), reportsDirectory)
            }

            override fun reconstruct(binary: Path, reportsDirectory: Path, mode: WebReconstructionMode, progress: AgentWorkflowProgress,
                published: (PublishedEvidenceModel) -> Unit) {
                // The explicit request mode replaces the legacy WEB_RECONSTRUCTION_MODE environment choice.
                val selected = environment + (WEB_RECONSTRUCTION_MODE_KEY to mode.configurationValue)
                val strategy = selectWebReconstructionStrategy(selected, progress)
                Files.createDirectories(reportsDirectory)
                Files.writeString(reportsDirectory.resolve("reconstruction_harness_selection.json"), renderWebReconstructionHarnessSelection(strategy))
                val bundled = GhidraHeadlessProgramModelAnalyzer.bundled()
                val analyzer = if (mode == WebReconstructionMode.EVIDENCE_ONLY) {
                    val bounded = bundled.withExportBudgets(strategy.profile.budgets)
                    ProgramModelAnalyzer { input, directory ->
                        bounded.analyzeWithPublishedModel(input, directory) { digest, imported, bytes ->
                            published(PublishedEvidenceModel(digest, imported, bytes, strategy.profile.sha256))
                        }
                    }
                } else bundled
                ArchivalReconstructionService(analyzer, strategy.reconstructor,
                    profile = strategy.profile, progress = progress).reconstruct(binary, reportsDirectory)
            }

            override fun repair(project: Path, binary: Path, reportsDirectory: Path, harness: String,
                owner: RepairPublicationOwner?): WebRepairResult {
                val configuration = RepairRuntimeConfiguration("generated-c-make-v1", reportsDirectory.resolve("repair_history.json"),
                    harnessOverride = harness)
                return SecureRepairRuntime.open(configuration).use { runtime ->
                    val inputs = listOf(ProcessInput("default"))
                    val result = if (owner == null) runtime.runRepair(project, binary, inputs, reportsDirectory, REPAIR_ITERATIONS)
                        else runtime.runOwnedRepair(project, binary, inputs, reportsDirectory, REPAIR_ITERATIONS, owner)
                    WebRepairResult(result.runState.status, result.publication)
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
        var evidenceModel: WorkflowEvidenceModel? = null
        val (result, usage) = executor.run(context.attempt.limits, meter) {
            BestEffortProgressJournal(context.reportsDirectory, "reconstruction", sensitiveValues).use { journal ->
                val progress = MeteredWorkflowProgress(journal, meter)
                // Only a route that executes nothing from the upload and contacts no agent commits a model, so no
                // untrusted execution shares this attempt. It imports an owner-private snapshot, never the live upload.
                val snapshot = if (agent || launch.executesBinary || launch.contactsAgent) null
                    else WebInputSnapshot.create(context.job, context.reportsDirectory)
                try {
                    engines.reconstruct(snapshot?.path ?: context.job.binaryPath, context.reportsDirectory, mode, progress) { published ->
                        evidenceModel = evidenceModelCommitment(context.job.id, context.attempt.runId, snapshot, published)
                    }
                } catch (failure: Exception) {
                    progress.phase(AgentWorkflowPhase.FAILED)
                    throw failure
                } finally {
                    snapshot?.close()
                }
            }
        }
        // Candidate output is recorded whenever a canonical source revision exists; it is never acceptance.
        val candidate = reconstructionCandidate(context.reportsDirectory.resolve("source-tree"))
        return when (unwrap(result)) {
            is BoundedWorkflowResult.Returned -> DurableWebWorkflowOutcome.Completed(candidate, usage, evidenceModel = evidenceModel)
            is BoundedWorkflowResult.Exhausted -> DurableWebWorkflowOutcome.Failed(WorkflowTerminalReason.LIMIT_EXHAUSTED, candidate, usage, evidenceModel = evidenceModel)
            is BoundedWorkflowResult.Threw -> DurableWebWorkflowOutcome.Failed(candidate = candidate, usage = usage, evidenceModel = evidenceModel)
        }
    }
}

/**
 * A model the bundled analyzer published. [inputSha256] is the exporter's own read of the executable path;
 * [importedProgramSha256] is the isolated worker's report, over its stdout pipe, of the digest Ghidra recorded
 * for the bytes it actually imported, or null when the worker reported none or the report was not attested.
 */
internal class PublishedEvidenceModel(val inputSha256: String, val importedProgramSha256: String?,
    bytes: ByteArray, val profileSha256: String) {
    private val content = bytes.copyOf()
    val size get() = content.size
    val sha256 = decompengine.project.sha256(content)
}

/**
 * Commit a published model only to the owner's snapshot, the bytes the worker imported. The snapshot is
 * immutable while the worker runs, and the imported Program's own digest and the model's inputSha256 must
 * both equal the digest the owner computed while copying it. No commitment, and so no resume from this
 * model, results when: no snapshot exists; the snapshot changed; the worker reported no imported-Program
 * digest; either digest differs from the snapshot; or the model is outside 1..[WorkflowEvidenceModel.MAX_BYTES].
 */
internal fun evidenceModelCommitment(jobId: String, runId: String, snapshot: WebInputSnapshot?,
    published: PublishedEvidenceModel): WorkflowEvidenceModel? {
    val digest = snapshot?.sha256 ?: return null
    if (published.importedProgramSha256 == null || published.importedProgramSha256 != digest) return null
    if (published.inputSha256 != digest || published.size !in 1..WorkflowEvidenceModel.MAX_BYTES) return null
    if (!snapshot.unchanged()) return null
    return WorkflowEvidenceModel(jobId, runId, digest, published.sha256, published.size, published.profileSha256)
}

/**
 * An owner-private, read-only copy of an attempt's selected upload, written from one stable read of it and
 * hashed by the owner as it was copied. The directory is created fresh (mode 0700) for each attempt and the
 * file is read-only (0400), so a later change to the upload path cannot reach the importer. [close] removes it.
 */
internal class WebInputSnapshot private constructor(private val directory: Path, val path: Path, val sha256: String,
    private val identity: Any) : AutoCloseable {
    /** Rechecked after import: the same read-only regular file, still holding the hashed bytes. */
    fun unchanged(): Boolean = try {
        val attributes = Files.readAttributes(path, PosixFileAttributes::class.java, NOFOLLOW_LINKS)
        attributes.isRegularFile && attributes.fileKey() == identity && attributes.permissions() == READ_ONLY &&
            streamSha256(path) == sha256
    } catch (_: java.io.IOException) {
        false
    }

    override fun close() {
        try { Files.deleteIfExists(path) } catch (_: java.io.IOException) { }
        try { Files.deleteIfExists(directory) } catch (_: java.io.IOException) { }
    }

    companion object {
        private val PRIVATE_DIRECTORY = PosixFilePermissions.fromString("rwx------")
        private val PRIVATE_FILE = PosixFilePermissions.fromString("rw-------")
        private val READ_ONLY = PosixFilePermissions.fromString("r--------")

        /** Null when the selected upload has no stable, bounded identity; the attempt then commits nothing. */
        fun create(job: Job, workDirectory: Path): WebInputSnapshot? {
            val upload = job.binaryPath.parent ?: return null
            if (upload.fileName.toString() != job.id || job.binaryPath.fileName.toString() != "input.elf" ||
                job.sizeBytes !in 1..MAX_JOB_INPUT_BYTES) return null
            val storageRoot = upload.parent ?: return null
            var directory: Path? = null
            var target: Path? = null
            try {
                Files.createDirectories(workDirectory)
                val created = Files.createDirectory(workDirectory.resolve(".input-snapshot-${randomToken()}"),
                    PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY)).also { directory = it }
                val owner = Files.readAttributes(created, PosixFileAttributes::class.java, NOFOLLOW_LINKS)
                require(owner.isDirectory && owner.permissions() == PRIVATE_DIRECTORY) { "snapshot directory is not owner-private" }
                val file = created.resolve("input.elf").also { target = it }
                val written = java.security.MessageDigest.getInstance("SHA-256")
                var total = 0L
                val stable = Files.newByteChannel(file, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, NOFOLLOW_LINKS),
                    PosixFilePermissions.asFileAttribute(PRIVATE_FILE)).use { channel ->
                    hashStableRegularFile(storageRoot, "${job.id}/input.elf",
                        declaredSize = { require(it == job.sizeBytes.toLong()) },
                        readBytes = { _, read -> require(read <= job.sizeBytes.toLong()) },
                        cancellationCheck = { if (Thread.currentThread().isInterrupted) throw InterruptedException() },
                        consumeBytes = { buffer, count ->
                            val chunk = java.nio.ByteBuffer.wrap(buffer, 0, count)
                            while (chunk.hasRemaining()) channel.write(chunk)
                            written.update(buffer, 0, count)
                            total += count
                        },
                    )
                }
                // The stable read revalidates the upload after its last chunk; only then is the copy trusted.
                val digest = written.digest().joinToString("") { "%02x".format(it) }
                require(digest == stable.sha256 && total == job.sizeBytes.toLong()) { "snapshot differs from the stable read" }
                Files.setPosixFilePermissions(file, READ_ONLY)
                val identity = Files.readAttributes(file, PosixFileAttributes::class.java, NOFOLLOW_LINKS).fileKey()
                    ?: error("snapshot has no file identity")
                return WebInputSnapshot(created, file, digest, identity)
            } catch (failure: Exception) {
                target?.let { try { Files.deleteIfExists(it) } catch (_: java.io.IOException) { } }
                directory?.let { try { Files.deleteIfExists(it) } catch (_: java.io.IOException) { } }
                if (failure is InterruptedException) throw failure
                // The optional checkpoint needs a verified snapshot; evidence-only analysis still runs without one.
                return null
            }
        }

        private fun randomToken(): String {
            val bytes = ByteArray(16).also(java.security.SecureRandom()::nextBytes)
            return bytes.joinToString("") { "%02x".format(it) }
        }

        private fun streamSha256(path: Path): String {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            Files.newInputStream(path, NOFOLLOW_LINKS).use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    digest.update(buffer, 0, count)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }
    }
}

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
    override val harnessCapabilityId: String,
    // Inert integration seam only; metadata cannot attest production acceptance (see #478).
    private val acceptTestOnlyPublication: Boolean = false,
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
        val project = context.reportsDirectory.resolve("source-tree")
        val meter = WorkflowExecutionMeter(context.reportsDirectory, toolCallsMetered = false)
        val (result, usage) = executor.run(context.attempt.limits, meter) {
            // The attempt owns a private copy; the selected revision's retained evidence is never modified.
            copyWebSourceTree(input, project)
            val owner = context.attempt.repairPublicationNonce?.let {
                RepairPublicationOwner(context.job.id, context.attempt.runId, it)
            }
            engines.repair(project, context.job.binaryPath, context.reportsDirectory, harness, owner)
        }
        val completed = unwrap(result)
        val binding = (completed as? BoundedWorkflowResult.Returned)?.value?.publication?.let {
            WorkflowRepairBinding.from(context.attempt, it)
        }
        val candidate = binding?.let { WorkflowCandidate(webSourceRevisionId(it.sourceSha256), it.sourceSha256) }
            ?: repairCandidate(project, context.attempt.startedAt?.toEpochMilli(), acceptTestOnlyPublication)
        return when (completed) {
            is BoundedWorkflowResult.Exhausted -> DurableWebWorkflowOutcome.Failed(WorkflowTerminalReason.LIMIT_EXHAUSTED, candidate, usage)
            is BoundedWorkflowResult.Threw -> DurableWebWorkflowOutcome.Failed(candidate = candidate, usage = usage)
            is BoundedWorkflowResult.Returned -> when (completed.value.status) {
                RepairRunStatus.FULLY_ACCEPTED, RepairRunStatus.COMPILE_VALID -> DurableWebWorkflowOutcome.Completed(candidate, usage, binding = binding)
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
