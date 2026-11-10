package decompengine.project

import decompengine.assessment.HeuristicScoreInterpretation
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.repair.readStableRegularFile
import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentContextInput
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentSessionContinuation
import decompengine.agent.AgentSessionJournal
import decompengine.agent.AgentSessionRecoveryException
import decompengine.agent.AgentSessionResumePolicy
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentHarness
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentTurnIdentity
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import decompengine.agent.AgentWorkflowPhase
import decompengine.agent.AgentWorkflowProgress
import decompengine.agent.receiptCommitmentBytes
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.nio.file.AtomicMoveNotSupportedException
import java.io.IOException
import java.io.InterruptedIOException
import java.nio.channels.ClosedByInterruptException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.Collections
import java.util.EnumSet
import kotlin.io.path.createDirectories
import kotlin.io.path.deleteIfExists
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText

data class ModuleReconstructionRequest(
    val module: PlannedModule,
    val model: RecoveredProgramModel,
    val sharedHeader: String,
    val moduleHeader: String,
    val privateHeader: String,
    val dependencyHeaders: Map<String, String>,
    val workspaceRoot: Path,
    val observedBehavior: String? = null,
    /** Workflow-owned sink invoked before a provider receipt is interpreted or validated. */
    val persistAgentExecutionEvidence: ((ReconstructionAgentExecutionEvidence) -> Unit)? = null,
    val profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
    val sessionEvidenceFingerprint: String? = null,
    val acceptedSourceSha256: String? = null,
    /** Bounded compiler feedback is prompt context only; acceptance uses fresh compilation below. */
    val compilerDiagnostics: String? = null,
    /** Recovered ownership used to select only required cross-module interfaces. */
    val modulePlan: ModulePlan? = null,
) {
    /** Durable pre-dispatch workflow identity; evidence must be written before the harness call. */
    internal var persistAgentTurnIntent: ((AgentTurnIntent) -> Unit)? = null
        private set
    internal var workflowRunId: String? = null
        private set

    internal fun withAgentTurnContext(
        workflowRunId: String?,
        persistAgentTurnIntent: ((AgentTurnIntent) -> Unit)?,
    ): ModuleReconstructionRequest = apply {
        this.workflowRunId = workflowRunId
        this.persistAgentTurnIntent = persistAgentTurnIntent
    }
}

data class ReconstructedModule(
    val source: String,
    val generator: String,
    val promptSha256: String,
    val promptCharacters: Int? = null,
    val promptBudgetCharacters: Int? = null,
    val issues: List<ModuleReconstructionIssue> = emptyList(),
    val retryable: Boolean = true,
    val agentExecutionEvidence: ReconstructionAgentExecutionEvidence? = null,
) {
    internal var agentTurnIntent: AgentTurnIntent? = null
        private set

    internal fun withAgentTurnIntent(intent: AgentTurnIntent?): ReconstructedModule = apply {
        agentTurnIntent = intent
    }
}

data class ModuleReconstructionIssue(
    val code: String,
    val message: String,
    val entityIds: List<String>,
)

/** Cached execution belongs to the checkpoint's historical prompt identity. */
internal fun requestForCheckpointReconciliation(
    request: ModuleReconstructionRequest,
    checkpointFingerprint: String,
    checkpointReused: Boolean,
): ModuleReconstructionRequest = if (checkpointReused &&
    request.sessionEvidenceFingerprint != checkpointFingerprint) {
    request.copy(sessionEvidenceFingerprint = checkpointFingerprint).also { copied ->
        copied.withAgentTurnContext(request.workflowRunId, request.persistAgentTurnIntent)
    }
} else request

fun interface ModuleReconstructor {
    fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule

    /** Agent-backed implementations require the complete staged publication session. */
    fun publicationRequirement(): ReconstructionPublicationRequirement = ReconstructionPublicationRequirement.NONE

    /** Stable strategy identity used when resuming checkpoints. */
    fun cacheIdentity(): String = "custom"

    /** Profile-bound strategies include their effective limits in checkpoint identity. */
    fun cacheIdentity(profile: ReconstructionProfile): String = cacheIdentity()

    /** Agent-backed strategies may resume only checkpoints carrying authenticated execution evidence. */
    fun requiresExecutionEvidenceForCheckpointReuse(): Boolean = false

    /** Called only with the workflow's independently verified checkpoint/receipt identities. */
    fun reconcileSessionCheckpoint(
        request: ModuleReconstructionRequest,
        accepted: Boolean,
        sourceSha256: String,
        executionRequestSha256: String?,
        executionEvidenceSha256: String?,
    ) = Unit
}

enum class ReconstructionPublicationRequirement {
    NONE,
    TRANSACTIONAL,
}

internal enum class ReconstructionModuleDispositionKind {
    ACCEPTED,
    EVIDENCE_ONLY_UNRESOLVED,
    REJECTED,
}

internal enum class ReconstructionRejectionReason {
    ACP_REJECTED,
    AGENT_FAILURE_FALLBACK,
    ROLE_DENIED,
    POLICY_INCOMPLETE,
    COMPILER_REJECTED,
}

internal data class ReconstructionModuleDisposition(
    val moduleId: String,
    val kind: ReconstructionModuleDispositionKind,
    val rejectionReason: ReconstructionRejectionReason? = null,
)

internal class ReconstructionGenerationDisposition(
    modules: List<ReconstructionModuleDisposition>,
    val publicationRequirement: ReconstructionPublicationRequirement,
) {
    val modules: List<ReconstructionModuleDisposition> = modules.sortedBy(ReconstructionModuleDisposition::moduleId)
    val committable: Boolean = this.modules.none { it.kind == ReconstructionModuleDispositionKind.REJECTED }

    init {
        require(this.modules.map(ReconstructionModuleDisposition::moduleId).distinct().size == this.modules.size) {
            "generation disposition contains duplicate modules"
        }
        require(this.modules.all { (it.kind == ReconstructionModuleDispositionKind.REJECTED) == (it.rejectionReason != null) }) {
            "generation rejection reason does not match its disposition"
        }
        require(publicationRequirement == ReconstructionPublicationRequirement.NONE ||
            this.modules.none { it.kind == ReconstructionModuleDispositionKind.EVIDENCE_ONLY_UNRESOLVED }) {
            "transactional generation cannot classify unresolved modules as evidence-only"
        }
    }
}

internal data class ReconstructionGenerationResult(
    val manifest: SourceTreeManifest,
    val disposition: ReconstructionGenerationDisposition,
)

class BoundedLlmModuleReconstructor(
    private val harness: AgentHarness,
    private val maximumContextCharacters: Int = 120_000,
    harnessProvenanceDescriptor: String? = null,
    private val progress: AgentWorkflowProgress = AgentWorkflowProgress.NONE,
    private val sessionResumePolicy: AgentSessionResumePolicy = AgentSessionResumePolicy.LOAD_OR_NEW_WHEN_UNSUPPORTED,
) : ModuleReconstructor {
    private val harnessProvenanceSha256 = harnessProvenanceDescriptor?.let { descriptor ->
        require(descriptor.isNotBlank()) { "harness provenance descriptor must not be blank" }
        val encoded = descriptor.toByteArray(StandardCharsets.UTF_8)
        require(encoded.size <= MAXIMUM_HARNESS_PROVENANCE_BYTES) {
            "harness provenance descriptor exceeds its byte limit"
        }
        sha256(encoded)
    }

    init { require(maximumContextCharacters >= 4_096) }

    override fun cacheIdentity(): String = cacheIdentity(maximumContextCharacters)

    override fun cacheIdentity(profile: ReconstructionProfile): String = cacheIdentity(contextBudget(profile))

    // v5 additionally binds the declared-role mutation authority into the execution receipt.
    private fun cacheIdentity(contextCharacters: Int): String =
        "agent:${harness.implementationIdentifier() ?: "unspecified"}:context-$contextCharacters:" +
            "factory-${harnessProvenanceSha256 ?: "unbound"}:v5"

    private fun contextBudget(profile: ReconstructionProfile): Int =
        minOf(maximumContextCharacters, profile.budgets.reconstructionMaximumContextCharacters)

    private fun promptBudgetFailure(request: ModuleReconstructionRequest, prompt: String): ModuleContextBudgetExceededException? {
        val budget = contextBudget(request.profile)
        return if (prompt.length <= budget) null else ModuleContextBudgetExceededException(
            request.module.id, prompt.length, budget, sha256(prompt.toByteArray()), PRE_DISPATCH_BUDGET_PERMIT,
        )
    }

    internal fun requireRetainableFallbackObservation(request: ModuleReconstructionRequest) {
        if (promptBudgetFailure(request, modulePromptEvidence(request).text) != null) {
            ModuleObservationRetention.retain(request)
        }
    }

    override fun requiresExecutionEvidenceForCheckpointReuse(): Boolean = true

    override fun publicationRequirement(): ReconstructionPublicationRequirement =
        ReconstructionPublicationRequirement.TRANSACTIONAL

    private fun sessionContinuation(
        request: ModuleReconstructionRequest,
        acceptedRevision: String? = request.acceptedSourceSha256,
    ): AgentSessionContinuation? {
        val fingerprint = request.sessionEvidenceFingerprint ?: return null
        if (harnessProvenanceSha256 == null) return null
        val root = request.workspaceRoot.toAbsolutePath().normalize()
        val paths = listOf(request.module.sourcePath)
        val files = try {
            AgentSessionJournal.captureWorkspaceFiles(
                paths.map { AgentWorkspacePath("project", it) }, listOf(AgentWorkspaceRoot("project", root)),
            )
        } catch (failure: Exception) {
            throw AgentSessionRecoveryException("could not capture the bounded reconstruction session inventory", failure)
        }
        // v3 isolates journals created before minimal inline context enforcement.
        val workflowSha256 = sha256(("module-reconstruction-session-v3\n" + request.model.inputSha256 + "\n" +
            request.profile.sha256 + "\n" + fingerprint).toByteArray())
        return AgentSessionContinuation(
            directory = root.parent.resolve(".decomp-agent-sessions")
                .resolve(sha256(root.toString().toByteArray()))
                .resolve(sha256(request.module.id.toByteArray()))
                .resolve(workflowSha256),
            workflowSha256 = workflowSha256,
            taskId = request.module.id,
            workspaceFiles = files,
            acceptedRevisionSha256 = acceptedRevision,
            policy = sessionResumePolicy,
        )
    }

    override fun reconcileSessionCheckpoint(
        request: ModuleReconstructionRequest,
        accepted: Boolean,
        sourceSha256: String,
        executionRequestSha256: String?,
        executionEvidenceSha256: String?,
    ) {
        if (executionRequestSha256 == null || executionEvidenceSha256 == null) return
        val continuation = sessionContinuation(request, sourceSha256.takeIf { accepted } ?: request.acceptedSourceSha256) ?: return
        val roots = listOf(AgentWorkspaceRoot("project", request.workspaceRoot.toAbsolutePath().normalize()))
        try {
            if (accepted) AgentSessionJournal.recordAcceptance(
                continuation, roots, executionRequestSha256, executionEvidenceSha256, sourceSha256,
            ) else AgentSessionJournal.recordRejection(continuation, roots, executionRequestSha256)
        } catch (failure: Exception) {
            throw AgentSessionRecoveryException("accepted project checkpoint could not be reconciled with the durable ACP session", failure)
        }
    }

    override fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule {
        val target = request.module.sourcePath
        val prompt = modulePromptEvidence(request)
        val objective = prompt.objective
        val evidence = prompt.evidence
        val observed = prompt.observed
        val promptEvidence = prompt.text
        val contextSize = promptEvidence.length
        val contextBudget = contextBudget(request.profile)
        promptBudgetFailure(request, promptEvidence)?.let { throw it }
        val promptSha256 = sha256(promptEvidence.toByteArray())
        val workspaceRoot = request.workspaceRoot.toAbsolutePath().normalize()
        val root = AgentWorkspaceRoot("project", workspaceRoot)
        val targetPath = AgentWorkspacePath(root.id, target)
        val sourcePath = targetPath.resolve(listOf(root))
        val before = sourcePath.takeIf { it.exists() }?.readBytes()
        val targetOperations = setOf(AgentOperation.WRITE_FILE, AgentOperation.CREATE_FILE)
        var invocationEvidence: ReconstructionAgentExecutionEvidence? = null
        var turnIntent: AgentTurnIntent? = null
        try {
            val agentRequest = AgentExecutionRequest(
                objective = objective,
                workspaceRoots = listOf(root),
                contextInputs = listOf(
                    AgentContextInput("recovered-module-evidence", evidence),
                    AgentContextInput("observed-behavior", observed),
                ),
                accessPolicy = AgentAccessPolicy(
                    listOf(AgentPathRule(
                        targetPath,
                        targetOperations,
                    )),
                    mutationAuthority = DeclaredRoleMutationPolicy.forDeclaredPaths(
                        profile = request.profile,
                        rootId = root.id,
                        ownerId = "module-reconstruction:${request.profile.id}:${request.module.id}",
                        operationsByPath = mapOf(target to targetOperations),
                        requiredOwnershipRoles = setOf(
                            ProjectFileRole.MODULE_IMPLEMENTATION,
                            ProjectFileRole.ENTRYPOINT_IMPLEMENTATION,
                        ),
                        maximumBytes = request.profile.budgets.archiveMaximumFileBytes,
                        policyId = "declared-role-reconstruction-v1",
                    ),
                ),
                sessionContinuation = sessionContinuation(request),
            )
            val eventRecorder = BoundedAgentExecutionEventRecorder()
            val turnIdentity = AgentTurnIdentity.create(request.module.id, agentRequest, request.workflowRunId)
            request.persistAgentTurnIntent?.let { persistIntent ->
                val requestBinding = decompengine.agent.AgentExecutionRequestBinding.capture(agentRequest)
                val beforeSha256 = before?.let(::sha256) ?: sha256("absent-v1:$target".toByteArray(Charsets.UTF_8))
                turnIntent = AgentTurnIntent.create(
                    identity = turnIdentity,
                    workflowId = request.workflowRunId ?: "reconstruction",
                    attemptId = turnIdentity.turnId,
                    profileSha256 = request.profile.sha256,
                    policySha256 = requestBinding.accessPolicySha256,
                    beforeSha256 = beforeSha256,
                )
                persistIntent(requireNotNull(turnIntent))
            }
            val taskProgress = progress.beginTask(request.module.id, agentRequest, turnIdentity)
            val receipt = harness.executeReceipt(agentRequest, turnIdentity) { event ->
                eventRecorder.record(event)
                taskProgress.event(event)
            }
            taskProgress.complete(receipt)
            invocationEvidence = ReconstructionAgentExecutionEvidence.captureOrNull(
                request = agentRequest,
                moduleId = request.module.id,
                promptSha256 = promptSha256,
                receipt = receipt,
                events = eventRecorder.receiptSnapshot(),
            )
            invocationEvidence?.let { evidence ->
                request.persistAgentExecutionEvidence?.invoke(evidence)
            }
            invocationEvidence?.wirePromptSha256?.let { wireDigest ->
                require(wireDigest == promptSha256) { "dispatched wire prompt differs from bounded module context" }
            }
            val execution = receipt.requireResult()
            if (execution.stopReason in setOf(AgentStopReason.CANCELLED, AgentStopReason.LIMIT_EXHAUSTED)) {
                throw ModuleReconstructionInterruptedException(
                    request.module.id,
                    execution.stopReason,
                    execution.summary,
                    invocationEvidence,
                    promptSha256,
                    contextSize,
                    contextBudget,
                    turnIntent,
                )
            }
            require(execution.stopReason == AgentStopReason.COMPLETED) {
                "module reconstruction stopped with ${execution.stopReason.name.lowercase()}: ${execution.summary.orEmpty()}"
            }
            require(execution.changes.size == 1 && execution.changes.single().path == targetPath) {
                "module reconstruction must change only $target"
            }
            val change = execution.changes.single()
            require(change.kind != AgentFileChangeKind.DELETED) { "module reconstruction deleted $target" }
            require(sourcePath.exists()) { "module reconstruction reported $target without creating it" }
            val source = sourcePath.readText()
            val sourceBytes = source.toByteArray()
            val expectedKind = if (before == null) AgentFileChangeKind.CREATED else AgentFileChangeKind.MODIFIED
            require(change.kind == expectedKind && change.beforeSha256 == before?.let(::sha256)) {
                "module reconstruction before-state does not match $target"
            }
            require(change.afterSha256 == sha256(sourceBytes) && (change.sizeBytes == null || change.sizeBytes == sourceBytes.size.toLong())) {
                "module reconstruction result does not match $target"
            }
            return ReconstructedModule(
                source = source,
                generator = "agent:${harness.implementationIdentifier() ?: "unspecified"}",
                promptSha256 = promptSha256,
                promptCharacters = contextSize,
                promptBudgetCharacters = contextBudget,
                agentExecutionEvidence = invocationEvidence,
            ).withAgentTurnIntent(turnIntent)
        } catch (failure: Exception) {
            if (generateSequence<Throwable>(failure) { it.cause }.any { it is AgentSessionRecoveryException }) throw failure
            if (before == null) sourcePath.deleteIfExists() else sourcePath.writeBytes(before)
            if (failure is ModuleReconstructionInterruptedException ||
                failure is ModuleReconstructionEvidencePersistenceException ||
                invocationEvidence == null
            ) {
                throw failure
            }
            throw ModuleReconstructionAgentOutcomeException(
                moduleId = request.module.id,
                evidence = requireNotNull(invocationEvidence),
                promptSha256 = promptSha256,
                promptCharacters = contextSize,
                promptBudgetCharacters = contextBudget,
                agentTurnIntent = turnIntent,
                cause = failure,
            )
        }
    }
}

private const val MAXIMUM_HARNESS_PROVENANCE_BYTES = 4 * 1024

private object PRE_DISPATCH_BUDGET_PERMIT

class ModuleContextBudgetExceededException internal constructor(
    val moduleId: String,
    val promptCharacters: Int,
    val promptBudgetCharacters: Int,
    val promptSha256: String,
    private val originPermit: Any?,
) : IllegalArgumentException(
    "module $moduleId exceeds context budget: $promptCharacters > $promptBudgetCharacters characters",
) {
    constructor(moduleId: String, promptCharacters: Int, promptBudgetCharacters: Int, promptSha256: String) :
        this(moduleId, promptCharacters, promptBudgetCharacters, promptSha256, null)

    internal val raisedBeforeDispatch: Boolean get() = originPermit === PRE_DISPATCH_BUDGET_PERMIT
}

class ModuleReconstructionInterruptedException(
    val moduleId: String,
    val stopReason: AgentStopReason,
    val agentSummary: String?,
    internal val agentExecutionEvidence: ReconstructionAgentExecutionEvidence? = null,
    internal val promptSha256: String? = null,
    internal val promptCharacters: Int? = null,
    internal val promptBudgetCharacters: Int? = null,
    internal val agentTurnIntent: AgentTurnIntent? = null,
) : IllegalStateException(
    "module $moduleId reconstruction was interrupted with ${stopReason.name.lowercase()}",
)

class ModuleReconstructionRevisionRejectedException(
    val moduleId: String,
    val issues: List<ModuleReconstructionIssue>,
) : IllegalStateException("module $moduleId revision was rejected; the previous accepted revision was restored")

private class ModuleReconstructionAgentOutcomeException(
    val moduleId: String,
    val evidence: ReconstructionAgentExecutionEvidence,
    val promptSha256: String,
    val promptCharacters: Int,
    val promptBudgetCharacters: Int,
    val agentTurnIntent: AgentTurnIntent?,
    cause: Exception,
) : IllegalStateException(
    "module $moduleId agent invocation ended with ${evidence.terminalOutcome}",
    cause,
)

private class ModuleReconstructionEvidencePersistenceException(cause: Exception) :
    IllegalStateException("failed to persist invocation-bound agent execution evidence", cause)

class GeneratedFileEvidence(
    val path: String,
    val sha256: String,
    val generator: String,
    val promptSha256: String? = null,
    entityIds: List<String> = emptyList(),
    val acceptedImplementation: Boolean? = null,
    roles: Set<ProjectFileRole>,
    val contentKind: ProjectContentKind,
) {
    val entityIds: List<String> = Collections.unmodifiableList(entityIds.toList().sorted())
    val roles: Set<ProjectFileRole> = Collections.unmodifiableSet(
        if (roles.isEmpty()) EnumSet.noneOf(ProjectFileRole::class.java) else EnumSet.copyOf(roles),
    )

    init {
        requireNormalizedProjectPath(path, "source tree manifest path")
        require(sha256.matches(Regex("[0-9a-f]{64}"))) { "source tree manifest file hash is invalid: $path" }
        require(generator.isNotBlank() && generator.length <= 4_096 && '\n' !in generator && '\r' !in generator) {
            "source tree manifest generator is invalid: $path"
        }
        require(promptSha256 == null || promptSha256.matches(Regex("[0-9a-f]{64}"))) {
            "source tree manifest prompt hash is invalid: $path"
        }
        require(this.roles.isNotEmpty()) { "source tree manifest file roles are empty: $path" }
        require(ProjectFileRole.EDITABLE !in this.roles || contentKind == ProjectContentKind.UTF8_TEXT) {
            "editable source tree manifest files must be UTF-8 text: $path"
        }
        require(ProjectFileRole.MODULE_IMPLEMENTATION !in this.roles || acceptedImplementation != null) {
            "module implementation acceptance is not classified: $path"
        }
        require(this.entityIds.distinct().size == this.entityIds.size) {
            "source tree manifest entity IDs must be unique: $path"
        }
    }
}

class SourceTreeManifest(
    val schemaVersion: Int = 3,
    val profileId: String,
    val profileSha256: String,
    val inputSha256: String,
    files: List<GeneratedFileEvidence>,
    unresolvedEntityIds: List<String>,
    unresolvedImplementationIds: List<String> = emptyList(),
) {
    val files: List<GeneratedFileEvidence> = Collections.unmodifiableList(files.toList().sortedBy(GeneratedFileEvidence::path))
    val unresolvedEntityIds: List<String> = Collections.unmodifiableList(unresolvedEntityIds.toList().distinct().sorted())
    val unresolvedImplementationIds: List<String> =
        Collections.unmodifiableList(unresolvedImplementationIds.toList().distinct().sorted())
    val editablePaths: Set<String> = Collections.unmodifiableSet(
        this.files.filter { ProjectFileRole.EDITABLE in it.roles }.mapTo(sortedSetOf(), GeneratedFileEvidence::path),
    )

    init {
        require(schemaVersion == 3) { "unsupported source tree manifest schemaVersion: $schemaVersion" }
        require(profileId.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"))) {
            "source tree manifest profile ID is invalid"
        }
        require(profileSha256.matches(Regex("[0-9a-f]{64}"))) { "source tree manifest profile digest is invalid" }
        require(inputSha256.isNotBlank() && inputSha256.length <= 4_096 && '\n' !in inputSha256 && '\r' !in inputSha256) {
            "source tree manifest input identity is invalid"
        }
        require(this.files.isNotEmpty()) { "source tree manifest files must not be empty" }
        require(this.files.map(GeneratedFileEvidence::path).distinct().size == this.files.size) {
            "source tree manifest file paths must be unique"
        }
    }

    fun toJson(): String = buildString {
        append("{\n  \"schemaVersion\": ").append(schemaVersion)
        append(",\n  \"profileId\": \"").append(profileId.jsonEscape()).append("\",")
        append("\n  \"profileSha256\": \"").append(profileSha256).append("\",")
        append("\n  \"inputSha256\": \"").append(inputSha256.jsonEscape()).append("\",")
        append("\n  \"files\": [")
        append(files.joinToString(",") { file ->
            """
            {
              "path": "${file.path.jsonEscape()}",
              "sha256": "${file.sha256.jsonEscape()}",
              "generator": "${file.generator.jsonEscape()}",
              "promptSha256": ${file.promptSha256?.let { "\"${it.jsonEscape()}\"" } ?: "null"},
              "acceptedImplementation": ${file.acceptedImplementation ?: "null"},
              "contentKind": "${file.contentKind.wireName}",
              "roles": [${file.roles.map(ProjectFileRole::wireName).sorted().joinToString(", ") { "\"${it.jsonEscape()}\"" }}],
              "entityIds": [${file.entityIds.joinToString(", ") { "\"${it.jsonEscape()}\"" }}]
            }""".trimIndent().prependIndent("    ")
        })
        append("\n  ],\n  \"unresolvedEntityIds\": [")
        append(unresolvedEntityIds.joinToString(", ") { "\"${it.jsonEscape()}\"" })
        append("],\n  \"unresolvedImplementationIds\": [")
        append(unresolvedImplementationIds.joinToString(", ") { "\"${it.jsonEscape()}\"" })
        append("]\n}\n")
    }
}

/**
 * Hashes a cached execution-evidence artifact through a descriptor-pinned, symlink-free walk.
 *
 * Cache metadata is untrusted resumable state. Every component below [projectDir] is therefore
 * opened relative to an already-pinned directory, and the regular file is size-checked before a
 * bounded read. A concurrent pathname replacement cannot redirect the read after authorization.
 */
internal fun boundedCheckpointExecutionEvidenceSha256(
    projectDir: Path,
    relativePath: String,
): String? {
    val normalizedPath = try {
        requireNormalizedProjectPath(relativePath, "module execution evidence path")
    } catch (_: IllegalArgumentException) {
        return null
    }
    val components = normalizedPath.split('/')
    val directories = mutableListOf<LinuxDescriptor>()
    return try {
        val projectRoot = projectDir.toAbsolutePath().normalize()
        LinuxFilesystemSyscalls.requireSupported(projectRoot)
        var directory = LinuxFilesystemSyscalls.openRoot(projectRoot).also(directories::add)
        components.dropLast(1).forEach { component ->
            directory = LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, component)
                .also(directories::add)
        }
        val evidence = LinuxFilesystemSyscalls.openRegularFileAtOrNull(
            directory.fd,
            components.last(),
        ) ?: return null
        evidence.use { pinned ->
            val pinnedPath = LinuxFilesystemSyscalls.stableDescriptorPath(pinned.fd)
            if (Files.size(pinnedPath) > MAXIMUM_CHECKPOINT_EXECUTION_EVIDENCE_BYTES) return null
            LinuxFilesystemSyscalls.openReadableFrom(pinned).use { readable ->
                sha256(
                    LinuxFilesystemSyscalls.read(
                        readable,
                        MAXIMUM_CHECKPOINT_EXECUTION_EVIDENCE_BYTES,
                        cancellationCheck = {},
                    ),
                )
            }
        }
    } catch (_: Exception) {
        null
    } finally {
        directories.asReversed().forEach(LinuxDescriptor::close)
    }
}

internal const val MAXIMUM_CHECKPOINT_EXECUTION_EVIDENCE_BYTES: Int = 64 * 1024 * 1024

object SourceTreeGenerator {
    private const val INPUT_FINGERPRINT_PROVIDER = "module-reconstruction-input-v2"

    private data class ModuleGenerationBudgetObservation(
        val moduleId: String,
        val outcome: String,
        val sourceBytes: Long,
        val promptCharacters: Int?,
        val promptBudgetCharacters: Int?,
    )

    fun generate(
        model: RecoveredProgramModel,
        projectDir: Path,
        planner: DeterministicModulePlanner? = null,
        reconstructor: ModuleReconstructor? = null,
        overrides: Map<String, String> = emptyMap(),
        observedBehavior: String? = null,
        profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
        progress: AgentWorkflowProgress = AgentWorkflowProgress.NONE,
        onModuleProgress: (completed: Int, total: Int, moduleId: String) -> Unit = { _, _, _ -> },
    ): SourceTreeManifest = generateWithCompilerFeedback(
        model, projectDir, ReconstructionHostSafetyLimits.DEFAULT, planner, reconstructor, overrides,
        observedBehavior, profile, progress, { null }, {}, onModuleProgress,
    ).manifest

    /** Explicit host policy can authorize a profile without changing its recorded budgets or identity. */
    fun generate(
        model: RecoveredProgramModel,
        projectDir: Path,
        hostSafetyLimits: ReconstructionHostSafetyLimits,
        planner: DeterministicModulePlanner? = null,
        reconstructor: ModuleReconstructor? = null,
        overrides: Map<String, String> = emptyMap(),
        observedBehavior: String? = null,
        profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
        progress: AgentWorkflowProgress = AgentWorkflowProgress.NONE,
        onModuleProgress: (completed: Int, total: Int, moduleId: String) -> Unit = { _, _, _ -> },
    ): SourceTreeManifest = generateWithCompilerFeedback(
        model, projectDir, hostSafetyLimits, planner, reconstructor, overrides,
        observedBehavior, profile, progress, { null }, {}, onModuleProgress,
    ).manifest

    internal fun generateWithCompilerFeedback(
        model: RecoveredProgramModel,
        projectDir: Path,
        hostSafetyLimits: ReconstructionHostSafetyLimits,
        planner: DeterministicModulePlanner? = null,
        reconstructor: ModuleReconstructor? = null,
        overrides: Map<String, String> = emptyMap(),
        observedBehavior: String? = null,
        profile: ReconstructionProfile,
        progress: AgentWorkflowProgress = AgentWorkflowProgress.NONE,
        compilerFeedback: (moduleId: String) -> ModuleCompilerFeedback? = { null },
        onCompilerFeedback: (ModuleCompilerFeedback) -> Unit = {},
        onModuleProgress: (completed: Int, total: Int, moduleId: String) -> Unit = { _, _, _ -> },
        publicationLock: ReconstructionPublicationLock? = null,
        workflowRunId: String? = null,
    ): ReconstructionGenerationResult {
        hostSafetyLimits.requireAllows(profile.budgets)
        val adapter = ReconstructionAdapters.resolve(profile)
        requireWorkflowOwnedPathsAreReserved(profile)
        val selectedReconstructor = reconstructor ?: adapter.defaultReconstructor()
        val reconstructionWorkflowId = workflowRunId ?: java.util.UUID.randomUUID().toString()
        require(reconstructionWorkflowId.isNotBlank() && reconstructionWorkflowId.toByteArray(Charsets.UTF_8).size <= 4096)
        val publicationRequirement = selectedReconstructor.publicationRequirement()
        require(publicationRequirement != ReconstructionPublicationRequirement.TRANSACTIONAL || publicationLock != null) {
            "agent-backed reconstruction requires a lease-owned staged publication session"
        }
        if (publicationRequirement == ReconstructionPublicationRequirement.TRANSACTIONAL) {
            requireNotNull(publicationLock).requireAuthorizedGenerationTarget(projectDir, model.inputSha256)
        } else {
            publicationLock?.validate()
        }
        // Validate the lease's admitted input before binding any sidecar writer to the caller's
        // model. Besides preserving the original refusal boundary, this ensures a rejected
        // invocation cannot create even an empty evidence namespace.
        val turnEvidenceStore = publicationLock?.let { ReconstructionTurnEvidenceStore(it, model.inputSha256) }
        adapter.admitGeneration(projectDir, profile, selectedReconstructor)
        val unresolvedOutput = adapter.requiresUnresolvedOutput(profile)
        val compilationPolicy = adapter.compilation
        val selectedPlanner = planner?.withProfileBounds(profile) ?: DeterministicModulePlanner.forProfile(profile)
        val planning = selectedPlanner.planWithComplexity(model, overrides)
        val plan = planning.plan
        val rendering = adapter.rendering(model, plan, profile)
        requireProjectedArchiveEntryBudget(profile, plan.modules.size, rendering.entrypoint() != null)
        val typesHeader = rendering.sharedInterface()
        val typesHeaderPath = profile.layout.declaration("shared-interface").materialize()
        val typesHeaderFile = projectDir.resolve(typesHeaderPath)
        val headers = plan.modules.associate { module -> module.id to rendering.moduleInterface(module) }
        val moduleById = plan.modules.associateBy { it.id }
        val dependenciesByModule = moduleDependencies(model, plan)
        val headerHashes = headers.mapValues { sha256(it.value.toByteArray()) }
        val interfaceFingerprints = moduleInterfaceFingerprints(dependenciesByModule, headerHashes)
        val privateHeaders = plan.modules.associate { module -> module.id to rendering.privateInterface(module) }
        if (selectedReconstructor is BoundedLlmModuleReconstructor) {
            ModuleObservationRetention.requireRawInput(observedBehavior)
        }
        if (selectedReconstructor is BoundedLlmModuleReconstructor && observedBehavior != null &&
            observedBehavior.toByteArray(Charsets.UTF_8).size > MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES) {
            // Validate actual fallback inputs before writing any project state. Larger
            // observations that fit an authorized prompt budget need no retained copy.
            plan.modules.forEach { module ->
                val dependencyHeaders = dependenciesByModule.getValue(module.id).associate { dependency ->
                    moduleById.getValue(dependency).headerPath to headers.getValue(dependency)
                }
                selectedReconstructor.requireRetainableFallbackObservation(ModuleReconstructionRequest(
                    module, model, typesHeader, headers.getValue(module.id), privateHeaders.getValue(module.id),
                    dependencyHeaders, projectDir, observedBehavior, profile = profile, modulePlan = plan,
                ))
            }
        }
        val previousBuildDefinition = capturePreviousBuildDefinition(projectDir, profile)
        typesHeaderFile.parent.createDirectories()
        typesHeaderFile.writeText(typesHeader)
        headers.forEach { (id, content) ->
            val path = profile.layout.declaration("module-interface").materialize(mapOf("module" to id))
            val file = projectDir.resolve(path)
            file.parent.createDirectories()
            file.writeText(content)
        }
        privateHeaders.forEach { (id, content) ->
            val path = profile.layout.declaration("module-private-interface").materialize(mapOf("module" to id))
            val file = projectDir.resolve(path)
            file.parent.createDirectories()
            file.writeText(content)
        }

        val generated = mutableListOf<GeneratedFileEvidence>()
        generated += evidence(profile, typesHeaderPath, typesHeader, "planner", model.types.map { it.id })
        headers.forEach { (id, content) ->
            val module = plan.modules.single { it.id == id }
            generated += evidence(
                profile,
                module.headerPath,
                content,
                "planner",
                module.functionIds + module.globalIds + module.typeIds,
            )
        }
        privateHeaders.forEach { (id, content) ->
            val path = profile.layout.declaration("module-private-interface").materialize(mapOf("module" to id))
            generated += evidence(profile, path, content, "planner", plan.modules.single { it.id == id }.functionIds)
        }
        val unresolvedImplementations = sortedSetOf<String>()
        val moduleRevisionEvidence = mutableMapOf<String, String>()
        val generationBudgetObservations = mutableListOf<ModuleGenerationBudgetObservation>()
        val moduleDispositions = mutableListOf<ReconstructionModuleDisposition>()
        var generatedSourceBytes = 0L

        moduleDependencyOrder(dependenciesByModule).map(moduleById::getValue).forEachIndexed { index, module ->
            val dependencies = dependenciesByModule.getValue(module.id)
            val dependencyHeaders = dependencies.associate { dependency -> moduleById.getValue(dependency).headerPath to headers.getValue(dependency) }
            val basePromptRequest = ModuleReconstructionRequest(
                module, model, typesHeader, headers.getValue(module.id), privateHeaders.getValue(module.id),
                dependencyHeaders, projectDir, observedBehavior, profile = profile, modulePlan = plan,
            )
            val contextFingerprint = if (selectedReconstructor is BoundedLlmModuleReconstructor &&
                compilationPolicy.providesCompilerFeedback) {
                selectedModuleInputFingerprint(basePromptRequest)
            } else null
            val feedbackSource = projectDir.resolve(module.sourcePath)
            val recordedCompilerFeedback = contextFingerprint?.let { expectedContext ->
                runCatching { compilerFeedback(module.id) }.getOrNull()?.takeIf { it.contextSha256 == expectedContext }
            }
            val currentSourceSha256 = feedbackSource.takeIf { it.exists() }?.let { sha256(it.readBytes()) }
            val priorCompilerDiagnostics = recordedCompilerFeedback?.takeIf {
                it.sourceSha256 == currentSourceSha256
            }?.diagnostics
            // Retain the old dispatched prompt identity for cache comparison only. Diagnostics
            // tied to a failed source are never passed to a new attempt after source correction.
            val retainedFeedbackFingerprint = recordedCompilerFeedback?.takeIf {
                currentSourceSha256 != null && it.sourceSha256 != currentSourceSha256
            }?.let { feedback ->
                selectedModuleInputFingerprint(basePromptRequest.copy(compilerDiagnostics = feedback.diagnostics))
            }
            val promptRequest = basePromptRequest.copy(compilerDiagnostics = priorCompilerDiagnostics)
            val localFingerprint = moduleFingerprint(
                module,
                model,
                typesHeader,
                headers.getValue(module.id),
                privateHeaders.getValue(module.id),
                dependencyHeaders,
                observedBehavior,
                profile.sha256,
                compilationPolicy.id,
            )
            val fingerprint = if (selectedReconstructor is BoundedLlmModuleReconstructor)
                selectedModuleInputFingerprint(promptRequest)
            else sha256(("transitive-interfaces-v2\n" + localFingerprint + "\n" +
                interfaceFingerprints.getValue(module.id)).toByteArray())
            val sourcePath = projectDir.resolve(module.sourcePath)
            val checkpointPath = projectDir.resolve(profile.layout.declaration("module-evidence").materialize(mapOf("module" to module.id)))
            val executionEvidenceDeclaration = runCatching {
                profile.layout.declaration("module-agent-execution-evidence")
            }.getOrNull()
            val configuredExecutionEvidencePath = executionEvidenceDeclaration
                ?.materialize(mapOf("module" to module.id))
            val configuredExecutionEvidenceFile = configuredExecutionEvidencePath?.let(projectDir::resolve)
            val attemptPath = projectDir.resolve("reports/modules/${module.id}.attempt.json")
            var persistedExecutionEvidence: PersistedReconstructionExecutionEvidence? = null
            var persistedTurnIntent: AgentTurnIntent? = null
            var persistedTurnIntentPath: String? = null
            var persistedTurnReceiptPath: String? = null
            var persistedTurnReceiptSha256: String? = null
            var persistedChangeAssessment: AcpChangeAssessment? = null
            var persistedChangeAssessmentPath: String? = null
            fun persistExecutionEvidence(
                evidence: ReconstructionAgentExecutionEvidence,
            ): PersistedReconstructionExecutionEvidence = try {
                persistReconstructionExecutionEvidence(
                    evidence = evidence,
                    moduleId = module.id,
                    configuredPath = configuredExecutionEvidencePath,
                    configuredFile = configuredExecutionEvidenceFile,
                    previous = persistedExecutionEvidence,
                ).also { persistedExecutionEvidence = it }
            } catch (failure: ModuleReconstructionEvidencePersistenceException) {
                throw failure
            } catch (failure: Exception) {
                throw ModuleReconstructionEvidencePersistenceException(failure)
            }
            val recordedCheckpoint = readCheckpoint(checkpointPath)
            // Acceptance rules may tighten without changing model or profile bytes. A previous
            // compiler pass cannot authorize either cache reuse or rollback past the current gate.
            val currentSourcePassesAdapter by lazy {
                sourcePath.exists() && adapter.assess(module, model, recordedCheckpoint?.generator.orEmpty(),
                    sourcePath.readText()).isEmpty()
            }
            fun ModuleCheckpoint.hasCurrentModuleAcceptance(): Boolean =
                !unresolvedOutput && schemaVersion in setOf(6, 7) && inputBinarySha256 == model.inputSha256 &&
                    modelSchemaVersion == model.schemaVersion && profileSha256 == profile.sha256 &&
                    accepted && issues.isEmpty() &&
                    modulePromptAttributionIsValid(
                        moduleClaimsAgentExecution(generator, reconstructorIdentity),
                        promptCharacters?.toLong(),
                        promptBudgetCharacters?.toLong(),
                        profile,
                    ) &&
                    entityIds.size == entityIds.toSet().size &&
                    entityIds.toSet() == (module.functionIds + module.globalIds).toSet() &&
                    compilation?.passed == true &&
                    compilation.command == compilationPolicy.command(profile, module.sourcePath) &&
                    currentSourcePassesAdapter
            val verifiedPreviousAcceptance = recordedCheckpoint?.takeIf {
                it.hasCurrentModuleAcceptance() && sourcePath.exists() && sha256(sourcePath.readBytes()) == it.sourceSha256 &&
                    it.hasCurrentExecutionEvidence(
                        projectDir, configuredExecutionEvidencePath, false, turnEvidenceStore, module.id,
                        profile, module.sourcePath,
                    )
            }
            val request = ModuleReconstructionRequest(
                module,
                model,
                typesHeader,
                headers.getValue(module.id),
                privateHeaders.getValue(module.id),
                dependencyHeaders,
                projectDir,
                observedBehavior,
                persistAgentExecutionEvidence = { evidence ->
                    val persisted = persistExecutionEvidence(evidence)
                    if (turnEvidenceStore != null) {
                        val intent = requireNotNull(persistedTurnIntent) {
                            "ACP receipt arrived without a durable turn intent"
                        }
                        val receiptBytes = evidence.toReceiptJson(module.id).toByteArray(Charsets.UTF_8)
                        val receipt = try {
                            turnEvidenceStore.persistReceipt(intent, receiptBytes)
                        } catch (failure: Exception) {
                            throw ModuleReconstructionEvidencePersistenceException(failure)
                        }
                        require(receipt.second == persisted.sha256) {
                            "turn receipt sidecar differs from the checkpoint execution evidence"
                        }
                        persistedTurnReceiptPath = receipt.first
                        persistedTurnReceiptSha256 = receipt.second
                    }
                },
                profile = profile,
                sessionEvidenceFingerprint = fingerprint,
                acceptedSourceSha256 = verifiedPreviousAcceptance?.sourceSha256,
                compilerDiagnostics = priorCompilerDiagnostics,
                modulePlan = plan,
            ).withAgentTurnContext(
                workflowRunId = reconstructionWorkflowId,
                persistAgentTurnIntent = if (turnEvidenceStore == null) null else { intent ->
                    turnEvidenceStore.let { store ->
                        persistedTurnIntentPath = store.persistIntent(intent)
                        persistedTurnIntent = intent
                    }
                },
            )
            val cacheIdentity = selectedReconstructor.cacheIdentity(profile)
            val cached = recordedCheckpoint?.takeIf { checkpoint ->
                checkpoint.schemaVersion in setOf(6, 7) && checkpoint.inputBinarySha256 == model.inputSha256 &&
                    checkpoint.modelSchemaVersion == model.schemaVersion && checkpoint.profileSha256 == profile.sha256 &&
                    (checkpoint.fingerprint == fingerprint ||
                        checkpoint.accepted && checkpoint.fingerprint == retainedFeedbackFingerprint) &&
                    sourcePath.exists() &&
                    sha256(sourcePath.readBytes()) == checkpoint.sourceSha256 &&
                    checkpoint.reconstructorIdentity == cacheIdentity &&
                    checkpoint.hasCurrentExecutionEvidence(
                        projectDir = projectDir,
                        configuredEvidencePath = configuredExecutionEvidencePath,
                        evidenceRequired = selectedReconstructor.requiresExecutionEvidenceForCheckpointReuse(),
                        turnEvidenceStore = turnEvidenceStore,
                        moduleId = module.id,
                        profile = profile,
                        sourcePath = module.sourcePath,
                    ) &&
                    (if (checkpoint.accepted) checkpoint.hasCurrentModuleAcceptance() else !checkpoint.retryable)
            }
            if (cached != null) progress.checkpointReused(module.id, cached.sourceSha256)
            val checkpoint = cached ?: run {
                val previousAccepted = verifiedPreviousAcceptance
                val previousSource = previousAccepted?.let { sourcePath.readText() }
                val previousExecutionEvidence = previousAccepted?.executionEvidencePath
                    ?.let { projectDir.resolve(it).readText() }
                fun restoreAcceptedRevision(): PersistedReconstructionExecutionEvidence? {
                    if (previousAccepted == null) return persistedExecutionEvidence
                    val attemptEvidence = persistedExecutionEvidence?.let { current ->
                        val path = "reports/modules/${module.id}.attempt.execution.json"
                        writeAtomically(projectDir.resolve(path), projectDir.resolve(current.path).readText())
                        current.copy(path = path)
                    }
                    writeAtomically(sourcePath, requireNotNull(previousSource))
                    configuredExecutionEvidenceFile?.let { path ->
                        if (previousExecutionEvidence == null) path.deleteIfExists()
                        else writeAtomically(path, previousExecutionEvidence)
                    }
                    progress.phase(AgentWorkflowPhase.ROLLED_BACK, module.id, previousAccepted.sourceSha256)
                    return attemptEvidence
                }
                var workflowOrigin = "reconstructor-return"
                val attemptedRaw = try {
                    selectedReconstructor.reconstruct(request)
                } catch (interrupted: ModuleReconstructionInterruptedException) {
                    interrupted.agentExecutionEvidence?.let(::persistExecutionEvidence)
                    val turnIntent = interrupted.agentTurnIntent ?: persistedTurnIntent
                    if (turnIntent != null) {
                        persistInterruptedChangeAssessment(turnEvidenceStore, turnIntent,
                            interrupted.agentExecutionEvidence, interrupted.stopReason).also {
                            persistedChangeAssessment = it.first
                            persistedChangeAssessmentPath = it.second
                        }
                    }
                    val executionEvidence = restoreAcceptedRevision()
                    writeInterruptionReport(
                        attemptPath,
                        module,
                        fingerprint,
                        cacheIdentity,
                        sourcePath,
                        recordedCheckpoint,
                        interrupted,
                        executionEvidence,
                        persistedTurnIntentPath,
                        persistedTurnReceiptPath,
                        persistedTurnReceiptSha256,
                        persistedChangeAssessmentPath,
                        turnIntent,
                        persistedChangeAssessment,
                    )
                    throw interrupted
                } catch (failure: ModuleReconstructionEvidencePersistenceException) {
                    restoreAcceptedRevision()
                    throw failure
                } catch (failure: Exception) {
                    if (failure is InterruptedException || Thread.currentThread().isInterrupted) throw failure
                    if (unresolvedOutput) throw failure
                    if (generateSequence<Throwable>(failure) { it.cause }.any { it is AgentSessionRecoveryException }) throw failure
                    workflowOrigin = if (selectedReconstructor is BoundedLlmModuleReconstructor &&
                        failure is ModuleContextBudgetExceededException && failure.raisedBeforeDispatch)
                        "pre-dispatch-context-budget-fallback" else "exception-fallback"
                    unresolvedFallback(request, cacheIdentity, failure)
                }
                val attempted = if (attemptedRaw.agentTurnIntent == null && persistedTurnIntent != null)
                    attemptedRaw.withAgentTurnIntent(persistedTurnIntent) else attemptedRaw
                // ACP change commitments identify exact staged bytes. Host-side newline
                // normalization would otherwise make the committed after hash diverge.
                val normalizedSource = if (attempted.agentExecutionEvidence != null) attempted.source
                    else attempted.source.trimEnd() + "\n"
                adapter.validateSourceContent(profile, normalizedSource.toByteArray(), module.sourcePath)
                val executionEvidence = attempted.agentExecutionEvidence?.let(::persistExecutionEvidence)
                    ?: persistedExecutionEvidence
                progress.phase(AgentWorkflowPhase.POLICY_CHECKING, module.id)
                val issues = assessReconstruction(adapter, profile, module, model, attempted, normalizedSource, cacheIdentity).toMutableList()
                writeAtomically(sourcePath, normalizedSource)
                val compilation = if (issues.isEmpty()) {
                    progress.phase(AgentWorkflowPhase.BUILD_VALIDATING, module.id)
                    val validation = try {
                        compilationPolicy.validate(projectDir, module.sourcePath, profile)
                    } catch (failure: Exception) {
                        if (failure !is InterruptedException && !Thread.currentThread().isInterrupted) throw failure
                        // Restore durable state before reinstating cancellation, since file
                        // operations may otherwise abort immediately on the interrupted thread.
                        Thread.interrupted()
                        val interrupted = ModuleReconstructionInterruptedException(
                            module.id, AgentStopReason.CANCELLED, "module compiler validation interrupted",
                            attempted.agentExecutionEvidence, attempted.promptSha256,
                            attempted.promptCharacters, attempted.promptBudgetCharacters, attempted.agentTurnIntent,
                        ).also { it.initCause(failure) }
                        try {
                            val retainedEvidence = restoreAcceptedRevision()
                            attempted.agentTurnIntent?.let { intent ->
                                persistInterruptedChangeAssessment(
                                    turnEvidenceStore, intent, attempted.agentExecutionEvidence, AgentStopReason.CANCELLED,
                                ).also {
                                    persistedChangeAssessment = it.first
                                    persistedChangeAssessmentPath = it.second
                                }
                            }
                            writeInterruptionReport(attemptPath, module, fingerprint, cacheIdentity,
                                sourcePath, recordedCheckpoint, interrupted, retainedEvidence,
                                persistedTurnIntentPath, persistedTurnReceiptPath, persistedTurnReceiptSha256,
                                persistedChangeAssessmentPath, attempted.agentTurnIntent, persistedChangeAssessment)
                        } finally {
                            Thread.currentThread().interrupt()
                        }
                        throw interrupted
                    }
                    validation.also { validation ->
                        if (!validation.passed && contextFingerprint != null) {
                            runCatching {
                                onCompilerFeedback(retainedModuleCompilerFeedback(
                                    moduleId = module.id,
                                    sourceSha256 = validation.sourceSha256,
                                    contextSha256 = requireNotNull(contextFingerprint),
                                    diagnostics = validation.diagnosticsPrefix,
                                ))
                            }
                        }
                        if (!validation.passed) issues += ModuleReconstructionIssue(
                            "module-compilation-${validation.outcome}",
                            "module compiler gate ${validation.outcome}; diagnostics SHA-256=${validation.diagnosticsSha256}",
                            module.functionIds + module.globalIds,
                        )
                    }
                } else null
                val accepted = !unresolvedOutput && issues.isEmpty()
                val normalizedSourceSha256 = sha256(normalizedSource.toByteArray())
                val changeAssessment = attempted.agentTurnIntent?.let { intent ->
                    persistReconstructionChangeAssessment(
                        store = turnEvidenceStore,
                        intent = intent,
                        evidence = attempted.agentExecutionEvidence,
                        issues = issues,
                        compilation = compilation,
                        accepted = accepted,
                        unresolvedOutput = unresolvedOutput,
                    ).also {
                        persistedChangeAssessment = it.first
                        persistedChangeAssessmentPath = it.second
                    }.first
                }
                val candidateCheckpoint = ModuleCheckpoint(
                    schemaVersion = if (attempted.agentTurnIntent != null) 7 else 6,
                    inputBinarySha256 = model.inputSha256,
                    modelSchemaVersion = model.schemaVersion,
                    profileSha256 = profile.sha256,
                    fingerprint = fingerprint,
                    sourceSha256 = normalizedSourceSha256,
                    generator = attempted.generator,
                    workflowOrigin = workflowOrigin,
                    preDispatchObservedBehavior = if (workflowOrigin == "pre-dispatch-context-budget-fallback")
                        ModuleObservationRetention.retain(request) else null,
                    preDispatchCompilerFeedback = if (workflowOrigin == "pre-dispatch-context-budget-fallback" &&
                        priorCompilerDiagnostics != null) recordedCompilerFeedback else null,
                    reconstructorIdentity = cacheIdentity,
                    promptSha256 = attempted.promptSha256,
                    promptCharacters = attempted.promptCharacters,
                    promptBudgetCharacters = attempted.promptBudgetCharacters,
                    accepted = accepted,
                    retryable = attempted.retryable,
                    issues = issues,
                    entityIds = module.functionIds + module.globalIds,
                    executionEvidencePath = executionEvidence?.path,
                    executionEvidenceSha256 = executionEvidence?.sha256,
                    executionEvidenceSchemaVersion = executionEvidence?.schemaVersion,
                    executionRequestSha256 = executionEvidence?.requestSha256,
                    executionTerminalOutcome = executionEvidence?.terminalOutcome,
                    executionReleaseComplete = executionEvidence?.releaseComplete,
                    compilation = compilation,
                    turnIntentPath = persistedTurnIntentPath,
                    turnIntentSha256 = attempted.agentTurnIntent?.sha256,
                    turnIntent = attempted.agentTurnIntent,
                    turnReceiptPath = persistedTurnReceiptPath,
                    turnReceiptSha256 = persistedTurnReceiptSha256,
                    changeAssessmentPath = persistedChangeAssessmentPath,
                    changeAssessmentSha256 = changeAssessment?.sha256,
                    changeAssessment = changeAssessment,
                )
                if (!accepted && previousAccepted != null) {
                    val attemptEvidence = restoreAcceptedRevision()
                    val rejectedCheckpoint = candidateCheckpoint.copy(executionEvidencePath = attemptEvidence?.path)
                    writeAtomically(
                        attemptPath,
                        "{\"schemaVersion\":3,\"moduleId\":\"${module.id.jsonEscape()}\",\"status\":\"rejected\","
                            + "\"previousAcceptedSourceSha256\":\"${previousAccepted.sourceSha256}\","
                            + "\"candidate\":${rejectedCheckpoint.toJson()}}\n",
                    )
                    selectedReconstructor.reconcileSessionCheckpoint(
                        request, false, previousAccepted.sourceSha256,
                        executionEvidence?.requestSha256, executionEvidence?.sha256,
                    )
                    throw ModuleReconstructionRevisionRejectedException(module.id, issues)
                }
                if (executionEvidence == null) configuredExecutionEvidenceFile?.deleteIfExists()
                candidateCheckpoint.also { writeAtomically(checkpointPath, it.toJson()) }
            }
            moduleDispositions += moduleDisposition(module.id, checkpoint, publicationRequirement)
            require(
                checkpoint.executionEvidencePath == null ||
                    checkpoint.executionEvidencePath == configuredExecutionEvidencePath
            ) { "module checkpoint execution evidence path differs from the reconstruction profile" }
            if (checkpoint.executionEvidencePath == null) configuredExecutionEvidenceFile?.deleteIfExists()
            attemptPath.deleteIfExists()
            projectDir.resolve("reports/modules/${module.id}.attempt.execution.json").deleteIfExists()
            val reconciliationRequest = requestForCheckpointReconciliation(request, checkpoint.fingerprint, cached != null)
            selectedReconstructor.reconcileSessionCheckpoint(
                reconciliationRequest, checkpoint.accepted, checkpoint.sourceSha256,
                checkpoint.executionRequestSha256, checkpoint.executionEvidenceSha256,
            )
            val normalizedSource = sourcePath.readText()
            val sourceBytes = normalizedSource.toByteArray().size.toLong()
            require(sourceBytes <= profile.budgets.archiveMaximumFileBytes) {
                "generated source for module ${module.id} exceeds archive file byte budget"
            }
            generatedSourceBytes = Math.addExact(generatedSourceBytes, sourceBytes)
            require(generatedSourceBytes <= profile.budgets.archiveMaximumTotalBytes) {
                "generated module sources exceed aggregate archive byte budget"
            }
            val moduleEntityIds = module.functionIds + module.globalIds
            if (!checkpoint.accepted) unresolvedImplementations += moduleEntityIds
            generationBudgetObservations += ModuleGenerationBudgetObservation(
                moduleId = module.id,
                outcome = if (checkpoint.accepted) "accepted" else "unresolved",
                sourceBytes = normalizedSource.toByteArray().size.toLong(),
                promptCharacters = checkpoint.promptCharacters,
                promptBudgetCharacters = checkpoint.promptBudgetCharacters,
            )
            progress.phase(
                if (checkpoint.accepted) AgentWorkflowPhase.ACCEPTED else AgentWorkflowPhase.UNRESOLVED,
                module.id,
                checkpoint.sourceSha256.takeIf { checkpoint.accepted },
            )
            generated += evidence(
                profile,
                module.sourcePath,
                normalizedSource,
                checkpoint.generator,
                moduleEntityIds,
                checkpoint.promptSha256,
                checkpoint.accepted,
            )
            val checkpointText = checkpointPath.readText()
            val checkpointEvidencePath = profile.layout.declaration("module-evidence").materialize(mapOf("module" to module.id))
            generated += evidence(profile, checkpointEvidencePath, checkpointText, "planner", moduleEntityIds)
            moduleRevisionEvidence[module.id] = buildString {
                append("{\"sourcePath\":\"").append(module.sourcePath.jsonEscape()).append("\",")
                append("\"sourceSha256\":\"").append(checkpoint.sourceSha256).append("\",")
                append("\"inputFingerprint\":\"").append(checkpoint.fingerprint).append("\",")
                append("\"inputFingerprintProvider\":\"").append(archivedModuleInputFingerprintProvider(checkpoint.reconstructorIdentity)).append("\",")
                append("\"inputBinarySha256\":\"").append(model.inputSha256.jsonEscape()).append("\",")
                append("\"modelSchemaVersion\":").append(model.schemaVersion).append(',')
                append("\"checkpointPath\":\"").append(checkpointEvidencePath.jsonEscape()).append("\",")
                append("\"checkpointSha256\":\"").append(sha256(checkpointText.toByteArray())).append("\",")
                append("\"acceptedImplementation\":").append(checkpoint.accepted).append(',')
                append("\"compilation\":").append(checkpoint.compilation?.toJson() ?: "null").append(',')
                append("\"behavior\":{\"status\":\"unknown\",\"reason\":\"no revision-bound behavioral measurements attached\",\"coverage\":null,\"outputAgreement\":null,\"unobservedBehavior\":\"unknown\"}}")
            }
            checkpoint.executionEvidencePath?.let { evidencePath ->
                val evidenceText = projectDir.resolve(evidencePath).readText()
                generated += evidence(
                    profile,
                    evidencePath,
                    evidenceText,
                    if (checkpoint.executionEvidenceSchemaVersion == 2) {
                        "acp-execution-receipt:v2"
                    } else {
                        "acp-execution-evidence:v1"
                    },
                    moduleEntityIds,
                )
            }
            onModuleProgress(index + 1, plan.modules.size, module.id)
        }

        rendering.entrypoint()?.let { entrypoint ->
            val mainSource = entrypoint.source
            val entrypointPath = profile.layout.declaration("entrypoint-implementation").materialize()
            val entrypointFile = projectDir.resolve(entrypointPath)
            entrypointFile.parent.createDirectories()
            entrypointFile.writeText(mainSource)
            generated += evidence(profile, entrypointPath, mainSource, "planner", entrypoint.entityIds)
        }
        val sourcePaths = generated.filter { entry ->
            try {
                val declaration = profile.layout.declarationForPath(entry.path)
                ProjectFileRole.MODULE_IMPLEMENTATION in declaration.roles || ProjectFileRole.ENTRYPOINT_IMPLEMENTATION in declaration.roles
            } catch (_: IllegalArgumentException) {
                false
            }
        }.map { it.path }.sorted()
        val makefile = rendering.buildDefinition(sourcePaths, profile)
        val makefilePath = profile.layout.declaration("build-definition").materialize()
        val makefileFile = projectDir.resolve(makefilePath)
        makefileFile.parent.createDirectories()
        removeUnchangedPreviousBuildDefinition(projectDir, previousBuildDefinition)
        makefileFile.writeText(makefile)
        generated += evidence(profile, makefilePath, makefile, "planner", emptyList())

        val programModelPath = profile.layout.declaration("program-model-evidence").materialize()
        val modulePlanPath = profile.layout.declaration("module-plan-evidence").materialize()
        val confidencePath = profile.layout.declaration("confidence-evidence").materialize()
        val toolchainPath = profile.layout.declaration("toolchain-evidence").materialize()
        val unresolvedPath = profile.layout.declaration("unresolved-evidence").materialize()
        projectDir.resolve(programModelPath).also { it.parent.createDirectories() }.writeText(model.toJson())
        projectDir.resolve(modulePlanPath).also { it.parent.createDirectories() }.writeText(plan.toJson())
        generated += evidence(profile, programModelPath, model.toJson(), "analysis", model.functions.map { it.id } + model.globals.map { it.id })
        generated += evidence(profile, modulePlanPath, plan.toJson(), "planner", model.functions.map { it.id } + model.globals.map { it.id })
        val confidence = renderConfidence(
            model,
            plan,
            unresolvedImplementations,
            moduleRevisionEvidence,
            profile,
            hostSafetyLimits,
            selectedPlanner.budgetLimits,
            planning.complexity,
            generationBudgetObservations,
        )
        projectDir.resolve(confidencePath).also { it.parent.createDirectories() }.writeText(confidence)
        generated += evidence(profile, confidencePath, confidence, "evidence", model.functions.map { it.id } + model.globals.map { it.id })
        val toolchain = adapter.toolchainEvidence(profile)
        projectDir.resolve(toolchainPath).also { it.parent.createDirectories() }.writeText(toolchain)
        generated += evidence(profile, toolchainPath, toolchain, "environment", emptyList())
        val unresolvedMarkdown = renderUnresolvedMarkdown(model, plan, unresolvedImplementations, unresolvedOutput)
        projectDir.resolve(unresolvedPath).also { it.parent.createDirectories() }.writeText(unresolvedMarkdown)
        generated += evidence(profile, unresolvedPath, unresolvedMarkdown, "evidence", unresolvedImplementations.toList())
        val manifest = SourceTreeManifest(
            profileId = profile.id,
            profileSha256 = profile.sha256,
            inputSha256 = model.inputSha256,
            files = generated,
            unresolvedEntityIds = model.functions.filter { unresolvedOutput || model.isRecoveryUnresolved(it.status) }.map { it.id } +
                model.globals.filter { unresolvedOutput || model.isRecoveryUnresolved(it.status) }.map { it.id } +
                model.types.filter { unresolvedOutput || model.isRecoveryUnresolved(it.status) }.map { it.id },
            unresolvedImplementationIds = unresolvedImplementations.toList(),
        )
        projectDir.resolve("source_tree_manifest.json").writeText(manifest.toJson())
        require(moduleDispositions.size == plan.modules.size &&
            moduleDispositions.map(ReconstructionModuleDisposition::moduleId).toSet() == plan.modules.map { it.id }.toSet()) {
            "generation disposition does not cover the complete module plan"
        }
        return ReconstructionGenerationResult(
            manifest,
            ReconstructionGenerationDisposition(moduleDispositions, publicationRequirement),
        )
    }

    private fun moduleDisposition(
        moduleId: String,
        checkpoint: ModuleCheckpoint,
        publicationRequirement: ReconstructionPublicationRequirement,
    ): ReconstructionModuleDisposition {
        if (checkpoint.accepted) {
            return ReconstructionModuleDisposition(moduleId, ReconstructionModuleDispositionKind.ACCEPTED)
        }
        if (publicationRequirement == ReconstructionPublicationRequirement.NONE) {
            return ReconstructionModuleDisposition(moduleId, ReconstructionModuleDispositionKind.EVIDENCE_ONLY_UNRESOLVED)
        }
        val reason = when {
            checkpoint.workflowOrigin == "exception-fallback" ||
                checkpoint.workflowOrigin == "pre-dispatch-context-budget-fallback" ->
                ReconstructionRejectionReason.AGENT_FAILURE_FALLBACK
            checkpoint.issues.any { it.code in setOf("declared-role-denied", "role-denied", "mutation-authority-denied") } ->
                ReconstructionRejectionReason.ROLE_DENIED
            checkpoint.issues.any { it.code == "agent-execution-evidence-incomplete" ||
                it.code == "prompt-budget-unattributed" || it.code == "prompt-budget-invalid" } ->
                ReconstructionRejectionReason.POLICY_INCOMPLETE
            checkpoint.compilation?.passed == false || checkpoint.issues.any { it.code.startsWith("module-compilation-") } ->
                ReconstructionRejectionReason.COMPILER_REJECTED
            else -> ReconstructionRejectionReason.ACP_REJECTED
        }
        return ReconstructionModuleDisposition(moduleId, ReconstructionModuleDispositionKind.REJECTED, reason)
    }

    private data class PreviousBuildDefinition(
        val path: String,
        val sha256: String,
        val identity: LinuxFileIdentity,
        val maximumBytes: Long,
    )

    private fun capturePreviousBuildDefinition(
        projectDir: Path,
        currentProfile: ReconstructionProfile,
    ): PreviousBuildDefinition? = optionalBuildDefinitionEvidence {
        val builtInProfiles = ReconstructionProfiles.builtIn
        val maximumBytes = minOf(currentProfile.budgets.archiveMaximumFileBytes,
            builtInProfiles.minOf { it.budgets.archiveMaximumFileBytes }, Int.MAX_VALUE.toLong() - 1L)
        val text = readStableRegularFile(projectDir, "source_tree_manifest.json", maximumBytes,
            cancellationCheck = ::buildDefinitionCleanupCheckpoint).bytes.decodeToString(throwOnInvalidSequence = true)
        val previous = builtInProfiles.firstNotNullOfOrNull { descriptor ->
            optionalBuildDefinitionEvidence { descriptor to SourceTreeManifestReader.parse(text, descriptor) }
        } ?: return@optionalBuildDefinitionEvidence null
        val declaration = previous.first.layout.declaration("build-definition")
        val path = declaration.materialize()
        if (currentProfile.layout.declarations.any { it.matches(path) }) return@optionalBuildDefinitionEvidence null
        require(ProjectFileRole.BUILD_DEFINITION in declaration.roles &&
            ProjectFileRole.BUILD_INPUT in declaration.roles && declaration.contentKind == ProjectContentKind.UTF8_TEXT)
        val record = previous.second.files.singleOrNull { it.path == path } ?: return@optionalBuildDefinitionEvidence null
        require(record.generator == "planner" && record.promptSha256 == null &&
            record.acceptedImplementation == null && record.entityIds.isEmpty())
        val candidate = readStableRegularFile(projectDir, path, maximumBytes,
            cancellationCheck = ::buildDefinitionCleanupCheckpoint)
        require(candidate.sha256 == record.sha256) { "previous build definition no longer matches its manifest" }
        PreviousBuildDefinition(path, candidate.sha256, candidate.identity, maximumBytes)
    }

    private fun removeUnchangedPreviousBuildDefinition(projectDir: Path, previous: PreviousBuildDefinition?) {
        buildDefinitionCleanupCheckpoint()
        if (previous == null) return
        val current = optionalBuildDefinitionEvidence {
            readStableRegularFile(projectDir, previous.path, previous.maximumBytes,
                cancellationCheck = ::buildDefinitionCleanupCheckpoint)
        } ?: return
        if (current.identity != previous.identity || current.sha256 != previous.sha256) return
        // This is local manifest consistency, not authenticated producer history or an
        // atomic unlink against concurrent writers. Never infer ownership from a filename.
        buildDefinitionCleanupCheckpoint()
        projectDir.resolve(previous.path).deleteIfExists()
    }

    private inline fun <T> optionalBuildDefinitionEvidence(read: () -> T): T? {
        buildDefinitionCleanupCheckpoint()
        return try {
            read()
        } catch (failure: InterruptedIOException) {
            throw failure
        } catch (failure: ClosedByInterruptException) {
            throw failure
        } catch (_: IOException) {
            buildDefinitionCleanupCheckpoint()
            null
        } catch (_: IllegalArgumentException) {
            buildDefinitionCleanupCheckpoint()
            null
        }
    }

    private fun buildDefinitionCleanupCheckpoint() {
        if (Thread.currentThread().isInterrupted) throw InterruptedException("build definition cleanup interrupted")
    }

    private fun requireWorkflowOwnedPathsAreReserved(profile: ReconstructionProfile) {
        val buildArtifact = ReconstructionAdapters.resolve(profile).behaviorBuild.layout(profile).artifactPath
        requireNormalizedProjectPath(buildArtifact, "profile build artifact")
        val workflowOwned = listOf(
            "BUILDING.md",
            "source_tree_manifest.json",
            "reports/build.log",
            "reports/build_contract.json",
            "reports/archival_audit.json",
            buildArtifact,
        )
        profile.layout.declarations.forEach { declaration ->
            workflowOwned.forEach { path ->
                require(!declaration.canMaterializeUnder(path) && !declaration.canMaterializeAbove(path)) {
                    "profile declaration ${declaration.id} collides with workflow-owned path $path"
                }
            }
        }
    }

    private fun requireProjectedArchiveEntryBudget(
        profile: ReconstructionProfile,
        moduleCount: Int,
        hasEntrypoint: Boolean,
    ) {
        // Each module writes a public header, private header, implementation,
        // checkpoint, optional agent execution evidence, and (during the generated
        // project build) an owner diagnostic. Reserve slots for the fixed project
        // evidence files, build diagnostics, and manifest as well.
        val fixedEntries = 8 + if (hasEntrypoint) 1 else 0
        val projectedEntries = moduleCount.toLong() * 6L + fixedEntries
        require(projectedEntries <= profile.budgets.archiveMaximumEntries.toLong()) {
            "projected generated file count $projectedEntries exceeds archive entry budget " +
                "${profile.budgets.archiveMaximumEntries}"
        }
    }

    private fun evidence(
        profile: ReconstructionProfile,
        path: String,
        content: String,
        generator: String,
        ids: List<String>,
        prompt: String? = null,
        acceptedImplementation: Boolean? = null,
    ): GeneratedFileEvidence {
        val declaration = profile.layout.declarationForPath(path)
        return GeneratedFileEvidence(
            path,
            sha256(content.toByteArray()),
            generator,
            prompt,
            ids.sorted(),
            acceptedImplementation,
            declaration.roles,
            declaration.contentKind,
        )
    }

    private data class ModuleCheckpoint(
        val schemaVersion: Int = 6,
        val fingerprint: String,
        val sourceSha256: String,
        val generator: String,
        val workflowOrigin: String = "reconstructor-return",
        val preDispatchObservedBehavior: String? = null,
        val preDispatchCompilerFeedback: ModuleCompilerFeedback? = null,
        val reconstructorIdentity: String,
        val promptSha256: String,
        val promptCharacters: Int?,
        val promptBudgetCharacters: Int?,
        val accepted: Boolean,
        val retryable: Boolean,
        val issues: List<ModuleReconstructionIssue>,
        val entityIds: List<String>,
        val executionEvidencePath: String? = null,
        val executionEvidenceSha256: String? = null,
        val executionEvidenceSchemaVersion: Int? = null,
        val executionRequestSha256: String? = null,
        val executionTerminalOutcome: String? = null,
        val executionReleaseComplete: Boolean? = null,
        val compilation: ModuleCompilationEvidence? = null,
        val inputBinarySha256: String? = null,
        val modelSchemaVersion: Int? = null,
        val profileSha256: String? = null,
        val turnIntentPath: String? = null,
        val turnIntentSha256: String? = null,
        val turnIntent: AgentTurnIntent? = null,
        val turnReceiptPath: String? = null,
        val turnReceiptSha256: String? = null,
        val changeAssessmentPath: String? = null,
        val changeAssessmentSha256: String? = null,
        val changeAssessment: AcpChangeAssessment? = null,
    ) {
        init {
            require(schemaVersion < 6 || (inputBinarySha256 != null && modelSchemaVersion in setOf(1, 2, 3, 4) &&
                profileSha256?.matches(Regex("[0-9a-f]{64}")) == true)) { "module checkpoint lacks input identity" }
            require(schemaVersion in 2..7) { "unsupported module checkpoint schemaVersion: $schemaVersion" }
            val requiredTurnFields = listOf(turnIntentPath, turnIntentSha256, turnIntent,
                changeAssessmentPath, changeAssessmentSha256, changeAssessment)
            val receiptFieldsPaired = (turnReceiptPath == null) == (turnReceiptSha256 == null)
            require(if (schemaVersion == 7) requiredTurnFields.all { it != null } && receiptFieldsPaired
                else requiredTurnFields.all { it == null } && turnReceiptPath == null && turnReceiptSha256 == null) {
                "module checkpoint turn provenance binding is incomplete for schema $schemaVersion"
            }
            if (schemaVersion == 7) {
                val intent = requireNotNull(turnIntent)
                val assessment = requireNotNull(changeAssessment)
                require(intent.sha256 == turnIntentSha256 && assessment.sha256 == changeAssessmentSha256 &&
                    intent.turnId == assessment.turnId && assessment.intentSha256 == intent.sha256 &&
                    assessment.receiptSha256 == executionEvidenceSha256 &&
                    assessment.receiptSha256 == turnReceiptSha256 &&
                    (if (executionEvidenceSha256 == null) executionRequestSha256 == null
                    else intent.requestSha256 == executionRequestSha256)) {
                    "module checkpoint turn provenance does not match its execution receipt"
                }
                requireNormalizedProjectPath(requireNotNull(turnIntentPath), "module turn intent path")
                turnReceiptPath?.let { requireNormalizedProjectPath(it, "module turn receipt path") }
                requireNormalizedProjectPath(requireNotNull(changeAssessmentPath), "module change assessment path")
                require(accepted == (changeAssessment.eligibility == AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION)) {
                    "module acceptance differs from its durable change assessment"
                }
            }
            require(workflowOrigin in setOf("reconstructor-return", "exception-fallback",
                "pre-dispatch-context-budget-fallback")) { "unsupported module checkpoint workflow origin" }
            require(preDispatchObservedBehavior == null ||
                workflowOrigin == "pre-dispatch-context-budget-fallback") {
                "retained pre-dispatch prompt input requires an undispatched fallback"
            }
            require(preDispatchCompilerFeedback == null ||
                workflowOrigin == "pre-dispatch-context-budget-fallback") {
                "retained pre-dispatch compiler feedback requires an undispatched fallback"
            }
            preDispatchCompilerFeedback?.let { feedback ->
                require(feedback.moduleId.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")) &&
                    listOf(feedback.sourceSha256, feedback.contextSha256, feedback.diagnosticsSha256)
                        .all { it.matches(Regex("[0-9a-f]{64}")) } &&
                    feedback.diagnostics.toByteArray(Charsets.UTF_8).size <= 32_768 &&
                    sha256(feedback.diagnostics.toByteArray(Charsets.UTF_8)) == feedback.diagnosticsSha256) {
                    "retained pre-dispatch compiler feedback is invalid"
                }
            }
            requireRetainableModuleObservation(preDispatchObservedBehavior)
            require(schemaVersion < 5 || !accepted ||
                (compilation?.passed == true && compilation.sourceSha256 == sourceSha256)
            ) { "accepted module checkpoint lacks successful compilation of its exact source bytes" }
            val evidenceFields = listOf(
                executionEvidencePath,
                executionEvidenceSha256,
                executionEvidenceSchemaVersion,
                executionRequestSha256,
                executionTerminalOutcome,
                executionReleaseComplete,
            )
            require(
                when (schemaVersion) {
                    2 -> evidenceFields.all { it == null }
                    3 -> executionEvidenceSchemaVersion == null && executionRequestSha256 == null &&
                        executionTerminalOutcome == null && executionReleaseComplete == null &&
                        ((executionEvidencePath == null) == (executionEvidenceSha256 == null))
                    else -> evidenceFields.all { it == null } || evidenceFields.all { it != null }
                },
            ) {
                "module checkpoint execution evidence binding is incomplete for schema $schemaVersion"
            }
            executionEvidencePath?.let { requireNormalizedProjectPath(it, "module execution evidence path") }
            require(executionEvidenceSha256 == null || executionEvidenceSha256.matches(Regex("[0-9a-f]{64}"))) {
                "module checkpoint execution evidence digest is invalid"
            }
            require(executionRequestSha256 == null || executionRequestSha256.matches(Regex("[0-9a-f]{64}"))) {
                "module checkpoint execution request digest is invalid"
            }
            require(executionEvidenceSchemaVersion == null || executionEvidenceSchemaVersion == 2) {
                "module checkpoint execution evidence schema is unsupported"
            }
            require(executionTerminalOutcome == null ||
                executionTerminalOutcome.matches(Regex("(?:returned|failed)-[a-z0-9-]{1,64}"))
            ) { "module checkpoint execution terminal outcome is invalid" }
        }

        fun hasCurrentExecutionEvidence(
            projectDir: Path,
            configuredEvidencePath: String?,
            evidenceRequired: Boolean,
            turnEvidenceStore: ReconstructionTurnEvidenceStore?,
            moduleId: String,
            profile: ReconstructionProfile,
            sourcePath: String,
        ): Boolean {
            val checkpointClaimsAgentExecution =
                moduleClaimsAgentExecution(generator, reconstructorIdentity)
            val evidencePath = executionEvidencePath
                ?: return !evidenceRequired && !checkpointClaimsAgentExecution

            // Compare the untrusted checkpoint value with the profile-owned path before resolving,
            // opening, sizing, or reading anything named by the checkpoint.
            if (configuredEvidencePath == null || evidencePath != configuredEvidencePath) return false
            val expectedDigest = requireNotNull(executionEvidenceSha256)
            if (schemaVersion >= 4 && accepted && executionReleaseComplete != true) return false
            if (boundedCheckpointExecutionEvidenceSha256(projectDir, evidencePath) != expectedDigest) return false
            if (schemaVersion < 7) return true
            return turnEvidenceStore?.verifyCheckpointProvenance(
                moduleId = moduleId,
                profileSha256 = profile.sha256,
                sourcePath = sourcePath,
                sourceSha256 = sourceSha256,
                accepted = accepted,
                intentPath = turnIntentPath,
                intentSha256 = turnIntentSha256,
                intent = turnIntent,
                receiptPath = turnReceiptPath,
                receiptSha256 = turnReceiptSha256,
                executionEvidenceSha256 = executionEvidenceSha256,
                assessmentPath = changeAssessmentPath,
                assessmentSha256 = changeAssessmentSha256,
                assessment = changeAssessment,
                compilation = compilation,
                executionRequestSha256 = executionRequestSha256,
                executionTerminalOutcome = executionTerminalOutcome,
                executionReleaseComplete = executionReleaseComplete,
            ) == true
        }

        fun toJson(): String = buildString {
            append("{\n  \"schemaVersion\": ").append(schemaVersion).append(',')
            append("\n  \"fingerprint\": \"").append(fingerprint).append("\",")
            append("\n  \"sourceSha256\": \"").append(sourceSha256).append("\",")
            append("\n  \"generator\": \"").append(generator.jsonEscape()).append("\",")
            if (schemaVersion >= 6) {
                append("\n  \"workflowOrigin\": \"").append(workflowOrigin).append("\",")
            }
            if (schemaVersion >= 6 && workflowOrigin == "pre-dispatch-context-budget-fallback") {
                append("\n  \"preDispatchObservedBehavior\": ")
                append(preDispatchObservedBehavior?.let { kotlinx.serialization.json.JsonPrimitive(it) } ?: JsonNull).append(',')
                append("\n  \"preDispatchCompilerFeedback\": ")
                append(preDispatchCompilerFeedback?.let { feedback -> buildJsonObject {
                    put("moduleId", feedback.moduleId)
                    put("sourceSha256", feedback.sourceSha256)
                    put("contextSha256", feedback.contextSha256)
                    put("diagnosticsSha256", feedback.diagnosticsSha256)
                    put("diagnostics", feedback.diagnostics)
                } } ?: JsonNull).append(',')
            }
            append("\n  \"reconstructorIdentity\": \"").append(reconstructorIdentity.jsonEscape()).append("\",")
            append("\n  \"promptSha256\": \"").append(promptSha256).append("\",")
            append("\n  \"promptCharacters\": ").append(promptCharacters ?: "null").append(',')
            append("\n  \"promptBudgetCharacters\": ").append(promptBudgetCharacters ?: "null").append(',')
            append("\n  \"executionEvidencePath\": ")
            append(executionEvidencePath?.let { "\"${it.jsonEscape()}\"" } ?: "null").append(',')
            append("\n  \"executionEvidenceSha256\": ")
            append(executionEvidenceSha256?.let { "\"$it\"" } ?: "null").append(',')
            if (schemaVersion >= 4) {
                append("\n  \"executionEvidenceSchemaVersion\": ")
                append(executionEvidenceSchemaVersion ?: "null").append(',')
                append("\n  \"executionRequestSha256\": ")
                append(executionRequestSha256?.let { "\"$it\"" } ?: "null").append(',')
                append("\n  \"executionTerminalOutcome\": ")
                append(executionTerminalOutcome?.let { "\"${it.jsonEscape()}\"" } ?: "null").append(',')
                append("\n  \"executionReleaseComplete\": ")
                append(executionReleaseComplete ?: "null").append(',')
            }
            if (schemaVersion >= 6) {
                append("\n  \"inputBinarySha256\": ").append(kotlinx.serialization.json.JsonPrimitive(inputBinarySha256)).append(',')
                append("\n  \"modelSchemaVersion\": ").append(modelSchemaVersion).append(',')
                append("\n  \"profileSha256\": ").append(kotlinx.serialization.json.JsonPrimitive(profileSha256)).append(',')
            }
            if (schemaVersion >= 7) {
                append("\n  \"turnIntentPath\": \"").append(requireNotNull(turnIntentPath).jsonEscape()).append('\"').append(',')
                append("\n  \"turnIntentSha256\": \"").append(requireNotNull(turnIntentSha256)).append('\"').append(',')
                append("\n  \"turnIntent\": ").append(String(requireNotNull(turnIntent).canonicalBytes(), Charsets.UTF_8)).append(',')
                append("\n  \"turnReceiptPath\": ")
                append(turnReceiptPath?.let { "\"${it.jsonEscape()}\"" } ?: "null").append(',')
                append("\n  \"turnReceiptSha256\": ")
                append(turnReceiptSha256?.let { "\"$it\"" } ?: "null").append(',')
                append("\n  \"changeAssessmentPath\": \"").append(requireNotNull(changeAssessmentPath).jsonEscape()).append('\"').append(',')
                append("\n  \"changeAssessmentSha256\": \"").append(requireNotNull(changeAssessmentSha256)).append('\"').append(',')
                append("\n  \"changeAssessment\": ").append(String(requireNotNull(changeAssessment).canonicalBytes(), Charsets.UTF_8)).append(',')
            }
            append("\n  \"accepted\": ").append(accepted).append(',')
            if (schemaVersion >= 5) {
                append("\n  \"compilation\": ").append(compilation?.toJson() ?: "null").append(',')
            }
            append("\n  \"retryable\": ").append(retryable).append(',')
            append("\n  \"entityStatuses\": [")
            append(entityIds.sorted().joinToString(",") { id ->
                "\n    {\"id\":\"${id.jsonEscape()}\",\"status\":\"${if (accepted) "accepted" else "unresolved"}\"}"
            })
            append("\n  ],\n  \"issues\": [")
            append(issues.joinToString(",") { issue ->
                """
                {
                  "code": "${issue.code.jsonEscape()}",
                  "message": "${issue.message.jsonEscape()}",
                  "entityIds": [${issue.entityIds.sorted().joinToString(",") { "\"${it.jsonEscape()}\"" }}]
                }""".trimIndent().prependIndent("    ")
            })
            append("\n  ]\n}\n")
        }
    }

    private fun readCheckpoint(path: Path): ModuleCheckpoint? {
        if (!path.exists()) return null
        return runCatching {
            val checkpointBytes = path.readBytes()
            val initialRoot = Json.parseToJsonElement(checkpointBytes.toString(Charsets.UTF_8)).jsonObject
            val schemaVersion = initialRoot["schemaVersion"]?.jsonPrimitive?.intOrNull ?: return null
            if (schemaVersion !in setOf(2, 3, 4, 5, 6, 7)) return null
            val root = if (schemaVersion >= 6) {
                val strict = OracleJson.parse(checkpointBytes, StrictJsonLimits(
                    maximumInputBytes = MAXIMUM_AGENT_CHECKPOINT_BYTES,
                    maximumCanonicalBytes = MAXIMUM_AGENT_CHECKPOINT_BYTES,
                )) as? kotlinx.serialization.json.JsonObject
                    ?: throw IllegalArgumentException("module checkpoint must be a JSON object")
                val validFields = if (schemaVersion == 7) {
                    setOf(CHECKPOINT_V7_REQUIRED_FIELDS,
                        CHECKPOINT_V7_REQUIRED_FIELDS + CHECKPOINT_V7_OPTIONAL_FALLBACK_FIELDS)
                } else {
                    setOf(CHECKPOINT_V6_REQUIRED_FIELDS,
                        CHECKPOINT_V6_REQUIRED_FIELDS + "workflowOrigin",
                        CHECKPOINT_V6_REQUIRED_FIELDS + "workflowOrigin" + CHECKPOINT_V7_OPTIONAL_FALLBACK_FIELDS)
                }
                require(strict.keys in validFields) {
                    "schema-$schemaVersion module checkpoint has missing or unsupported fields"
                }
                strict
            } else initialRoot
            if (schemaVersion >= 6) {
                require(root.getValue("schemaVersion") == kotlinx.serialization.json.JsonPrimitive(schemaVersion))
                require(root.getValue("inputBinarySha256").jsonPrimitive.isString)
                require(root.getValue("profileSha256").jsonPrimitive.isString)
                require(!root.getValue("modelSchemaVersion").jsonPrimitive.isString)
                for (field in listOf("promptCharacters", "promptBudgetCharacters")) {
                    root[field]?.takeUnless { it is JsonNull }?.jsonPrimitive?.let { value ->
                        require(!value.isString && value.intOrNull != null) { "$field must be an integer" }
                    }
                }
            }
            fun optionalString(name: String): String? = root[name]?.let { value ->
                if (value is JsonNull) null else value.jsonPrimitive.content
            }
            ModuleCheckpoint(
                schemaVersion = schemaVersion,
                inputBinarySha256 = if (schemaVersion >= 6) optionalString("inputBinarySha256") else null,
                modelSchemaVersion = if (schemaVersion >= 6) root["modelSchemaVersion"]?.jsonPrimitive?.intOrNull else null,
                profileSha256 = if (schemaVersion >= 6) optionalString("profileSha256") else null,
                turnIntentPath = if (schemaVersion >= 7) optionalString("turnIntentPath") else null,
                turnIntentSha256 = if (schemaVersion >= 7) optionalString("turnIntentSha256") else null,
                turnIntent = if (schemaVersion >= 7) {
                    AgentTurnIntent.parse(OracleJson.canonicalBytes(root.getValue("turnIntent"), StrictJsonLimits()))
                } else null,
                turnReceiptPath = if (schemaVersion >= 7) optionalString("turnReceiptPath") else null,
                turnReceiptSha256 = if (schemaVersion >= 7) optionalString("turnReceiptSha256") else null,
                changeAssessmentPath = if (schemaVersion >= 7) optionalString("changeAssessmentPath") else null,
                changeAssessmentSha256 = if (schemaVersion >= 7) optionalString("changeAssessmentSha256") else null,
                changeAssessment = if (schemaVersion >= 7) {
                    AcpChangeAssessment.parse(OracleJson.canonicalBytes(root.getValue("changeAssessment"), StrictJsonLimits()))
                } else null,
                fingerprint = root.getValue("fingerprint").jsonPrimitive.content,
                sourceSha256 = root.getValue("sourceSha256").jsonPrimitive.content,
                generator = root.getValue("generator").jsonPrimitive.content,
                workflowOrigin = optionalString("workflowOrigin") ?: "reconstructor-return",
                preDispatchObservedBehavior = optionalString("preDispatchObservedBehavior"),
                preDispatchCompilerFeedback = root["preDispatchCompilerFeedback"]?.takeUnless { it is JsonNull }?.jsonObject?.let {
                    ModuleCompilerFeedback(
                        it.getValue("moduleId").jsonPrimitive.content,
                        it.getValue("sourceSha256").jsonPrimitive.content,
                        it.getValue("contextSha256").jsonPrimitive.content,
                        it.getValue("diagnosticsSha256").jsonPrimitive.content,
                        it.getValue("diagnostics").jsonPrimitive.content,
                    )
                },
                reconstructorIdentity = root.getValue("reconstructorIdentity").jsonPrimitive.content,
                promptSha256 = root.getValue("promptSha256").jsonPrimitive.content,
                promptCharacters = root["promptCharacters"]?.jsonPrimitive?.intOrNull,
                promptBudgetCharacters = root["promptBudgetCharacters"]?.jsonPrimitive?.intOrNull,
                accepted = root.getValue("accepted").jsonPrimitive.boolean,
                retryable = root.getValue("retryable").jsonPrimitive.boolean,
                issues = root.getValue("issues").jsonArray.map { element ->
                    val issue = element.jsonObject
                    ModuleReconstructionIssue(
                        issue.getValue("code").jsonPrimitive.content,
                        issue.getValue("message").jsonPrimitive.content,
                        issue.getValue("entityIds").jsonArray.map { it.jsonPrimitive.content },
                    )
                },
                entityIds = root.getValue("entityStatuses").jsonArray.map {
                    val status = it.jsonObject
                    require(status.keys == setOf("id", "status")) { "unsupported module entity status fields" }
                    val expected = if (root.getValue("accepted").jsonPrimitive.boolean) "accepted" else "unresolved"
                    require(status.getValue("status").jsonPrimitive.isString &&
                        status.getValue("status").jsonPrimitive.content == expected) { "contradictory module entity acceptance" }
                    require(status.getValue("id").jsonPrimitive.isString) { "module entity ID must be a string" }
                    status.getValue("id").jsonPrimitive.content
                },
                executionEvidencePath = if (schemaVersion >= 3) optionalString("executionEvidencePath") else null,
                executionEvidenceSha256 = if (schemaVersion >= 3) optionalString("executionEvidenceSha256") else null,
                executionEvidenceSchemaVersion = if (schemaVersion >= 4) {
                    root["executionEvidenceSchemaVersion"]?.jsonPrimitive?.intOrNull
                } else null,
                executionRequestSha256 = if (schemaVersion >= 4) optionalString("executionRequestSha256") else null,
                executionTerminalOutcome = if (schemaVersion >= 4) optionalString("executionTerminalOutcome") else null,
                executionReleaseComplete = if (schemaVersion >= 4) {
                    root["executionReleaseComplete"]?.jsonPrimitive?.booleanOrNull
                } else null,
                compilation = root["compilation"]?.takeUnless { it is JsonNull }?.jsonObject?.let { compilation ->
                    ModuleCompilationEvidence(
                        sourceSha256 = compilation.getValue("sourceSha256").jsonPrimitive.content,
                        command = compilation.getValue("command").jsonArray.map { it.jsonPrimitive.content },
                        outcome = compilation.getValue("outcome").jsonPrimitive.content,
                        returnCode = compilation["returnCode"]?.jsonPrimitive?.intOrNull,
                        diagnosticsSha256 = compilation.getValue("diagnosticsSha256").jsonPrimitive.content,
                        diagnosticsBytes = compilation.getValue("diagnosticsBytes").jsonPrimitive.content.toLong(),
                    )
                },
            )
        }.getOrNull()
    }

    private data class PersistedReconstructionExecutionEvidence(
        val path: String,
        val sha256: String,
        val schemaVersion: Int,
        val requestSha256: String,
        val terminalOutcome: String,
        val releaseComplete: Boolean,
    )

    private fun persistReconstructionExecutionEvidence(
        evidence: ReconstructionAgentExecutionEvidence,
        moduleId: String,
        configuredPath: String?,
        configuredFile: Path?,
        previous: PersistedReconstructionExecutionEvidence? = null,
    ): PersistedReconstructionExecutionEvidence {
        val evidencePath = requireNotNull(configuredPath) {
            "reconstruction profile does not declare module-agent-execution-evidence"
        }
        val evidenceFile = requireNotNull(configuredFile)
        val text = evidence.toReceiptJson(moduleId)
        val persisted = PersistedReconstructionExecutionEvidence(
            path = evidencePath,
            sha256 = sha256(text.toByteArray()),
            schemaVersion = 2,
            requestSha256 = evidence.requestSha256,
            terminalOutcome = evidence.terminalOutcome,
            releaseComplete = evidence.releaseComplete,
        )
        previous?.let {
            require(it == persisted) {
                "module reconstruction produced more than one invocation evidence artifact"
            }
            return it
        }
        writeAtomically(evidenceFile, text)
        return persisted
    }

    private fun persistReconstructionChangeAssessment(
        store: ReconstructionTurnEvidenceStore?,
        intent: AgentTurnIntent,
        evidence: ReconstructionAgentExecutionEvidence?,
        issues: List<ModuleReconstructionIssue>,
        compilation: ModuleCompilationEvidence?,
        accepted: Boolean,
        unresolvedOutput: Boolean,
    ): Pair<AcpChangeAssessment, String> {
        val policyRejected = evidence == null || issues.any { issue ->
            issue.code.startsWith("agent-") || issue.code.contains("policy") || issue.code.contains("role") ||
                issue.code.contains("ownership") || issue.code.contains("mutation")
        }
        val policyVerdict = if (policyRejected) AcpChangePolicyVerdict.REJECT else AcpChangePolicyVerdict.ALLOW
        val validationStatus = when {
            compilation == null -> AcpChangeValidationStatus.NOT_RUN
            compilation.passed -> AcpChangeValidationStatus.PASSED
            else -> AcpChangeValidationStatus.FAILED
        }
        val validationProofs = compilation?.let {
            listOf(sha256(OracleJson.canonicalBytes(
                Json.parseToJsonElement(it.toJson()),
                StrictJsonLimits(maximumInputBytes = 1024 * 1024, maximumCanonicalBytes = 1024 * 1024),
            )))
        }.orEmpty()
        val after = evidence?.resultAfterSha256
        val observation = when {
            evidence == null -> AcpChangeObservationStatus.UNKNOWN
            after != null -> AcpChangeObservationStatus.COMPLETE
            else -> AcpChangeObservationStatus.INCOMPLETE
        }
        val eligibility = when {
            accepted -> AcpChangePublicationEligibility.VALIDATED_FOR_PUBLICATION
            policyRejected || validationStatus == AcpChangeValidationStatus.FAILED -> AcpChangePublicationEligibility.REJECTED
            unresolvedOutput -> AcpChangePublicationEligibility.PROVISIONAL
            else -> AcpChangePublicationEligibility.REJECTED
        }
        val assessment = AcpChangeAssessment.create(
            intent = intent,
            receiptSha256 = evidence?.let { sha256(it.toReceiptJson(intent.taskId).toByteArray(Charsets.UTF_8)) },
            sessionIdSha256 = evidence?.sessionIdCommitmentSha256?.let {
                sha256("acp-session-commitment-v1:$it".toByteArray(Charsets.UTF_8))
            },
            changesSha256 = evidence?.resultChangesSha256,
            beforeSha256 = intent.beforeSha256,
            afterSha256 = after,
            observation = observation,
            protocolStopCode = null,
            normalizedStopReason = evidence?.normalizedStopReason,
            policyVerdict = policyVerdict,
            reasonCodes = buildList {
                if (policyRejected) add("mutation-policy-rejected")
                issues.forEach { issue ->
                    val code = issue.code.lowercase().replace(Regex("[^a-z0-9_-]"), "-").trim('-')
                    if (code.isNotEmpty()) add("issue-${code.take(58)}")
                }
                if (!accepted && unresolvedOutput && isEmpty()) add("unresolved-output-profile")
                if (validationStatus == AcpChangeValidationStatus.FAILED && isEmpty()) add("validation-failed")
            }.distinct().take(256),
            validationStatus = validationStatus,
            validationProofSha256 = validationProofs,
            eligibility = eligibility,
            updatesSha256 = evidence?.updatesSha256,
        )
        val path = requireNotNull(store) { "agent turn assessment requires durable turn evidence storage" }
            .persistAssessment(intent, assessment)
        return assessment to path
    }

    private fun persistInterruptedChangeAssessment(
        store: ReconstructionTurnEvidenceStore?,
        intent: AgentTurnIntent,
        evidence: ReconstructionAgentExecutionEvidence?,
        stopReason: AgentStopReason,
    ): Pair<AcpChangeAssessment, String> {
        val after = evidence?.resultAfterSha256
        val assessment = AcpChangeAssessment.create(
            intent = intent,
            receiptSha256 = evidence?.let { sha256(it.toReceiptJson(intent.taskId).toByteArray(Charsets.UTF_8)) },
            sessionIdSha256 = evidence?.sessionIdCommitmentSha256?.let {
                sha256("acp-session-commitment-v1:$it".toByteArray(Charsets.UTF_8))
            },
            changesSha256 = evidence?.resultChangesSha256,
            beforeSha256 = intent.beforeSha256,
            afterSha256 = after,
            observation = when {
                evidence == null -> AcpChangeObservationStatus.UNKNOWN
                after != null -> AcpChangeObservationStatus.COMPLETE
                else -> AcpChangeObservationStatus.INCOMPLETE
            },
            protocolStopCode = null,
            normalizedStopReason = evidence?.normalizedStopReason ?: stopReason,
            policyVerdict = AcpChangePolicyVerdict.NOT_EVALUATED,
            reasonCodes = listOf("workflow-interrupted"),
            validationStatus = if (evidence?.normalizedStopReason in setOf(AgentStopReason.COMPLETED, AgentStopReason.NO_CHANGES) &&
                stopReason in setOf(AgentStopReason.CANCELLED, AgentStopReason.LIMIT_EXHAUSTED)) {
                AcpChangeValidationStatus.INCOMPLETE
            } else AcpChangeValidationStatus.NOT_RUN,
            validationProofSha256 = emptyList(),
            eligibility = AcpChangePublicationEligibility.INTERRUPTED,
            updatesSha256 = evidence?.updatesSha256,
        )
        val path = requireNotNull(store) { "interrupted agent turn requires durable turn evidence storage" }
            .persistAssessment(intent, assessment)
        return assessment to path
    }

    private fun executionTextCommitment(value: String): Pair<String, Long> {
        val bytes = receiptCommitmentBytes(value)
        return sha256(bytes) to bytes.size.toLong()
    }

    private fun writeInterruptionReport(
        path: Path,
        module: PlannedModule,
        fingerprint: String,
        reconstructorIdentity: String,
        sourcePath: Path,
        previousCheckpoint: ModuleCheckpoint?,
        interruption: ModuleReconstructionInterruptedException,
        executionEvidence: PersistedReconstructionExecutionEvidence?,
        turnIntentPath: String?,
        turnReceiptPath: String?,
        turnReceiptSha256: String?,
        changeAssessmentPath: String?,
        turnIntent: AgentTurnIntent?,
        changeAssessment: AcpChangeAssessment?,
    ) {
        require((turnIntent == null) == (turnIntentPath == null) &&
            (turnIntent == null) == (changeAssessment == null) &&
            (turnIntent == null) == (changeAssessmentPath == null)) {
            "interruption report turn provenance is incomplete"
        }
        require((turnReceiptPath == null) == (turnReceiptSha256 == null) &&
            (turnReceiptSha256 == null || turnReceiptSha256 == changeAssessment?.receiptSha256)) {
            "interruption report receipt binding is incomplete"
        }
        val currentSourceSha256 = sourcePath.takeIf { it.exists() }?.readBytes()?.let(::sha256)
        val report = buildString {
            append("{\n  \"schemaVersion\": ").append(if (turnIntent == null) 2 else 3).append(',')
            append("\n  \"moduleId\": \"").append(module.id.jsonEscape()).append("\",")
            append("\n  \"fingerprint\": \"").append(fingerprint).append("\",")
            append("\n  \"reconstructorIdentity\": \"").append(reconstructorIdentity.jsonEscape()).append("\",")
            append("\n  \"status\": \"interrupted\",")
            append("\n  \"stopReason\": \"").append(interruption.stopReason.name.lowercase()).append("\",")
            val summaryCommitment = interruption.agentSummary?.let(::executionTextCommitment)
            append("\n  \"summarySha256\": ")
            append(summaryCommitment?.first?.let { "\"$it\"" } ?: "null").append(',')
            append("\n  \"summaryEncodedBytes\": ")
            append(summaryCommitment?.second ?: "null").append(',')
            append("\n  \"executionEvidencePath\": ")
            append(executionEvidence?.path?.let { "\"${it.jsonEscape()}\"" } ?: "null").append(',')
            append("\n  \"executionEvidenceSha256\": ")
            append(executionEvidence?.sha256?.let { "\"$it\"" } ?: "null").append(',')
            append("\n  \"executionRequestSha256\": ")
            append(executionEvidence?.requestSha256?.let { "\"$it\"" } ?: "null").append(',')
            append("\n  \"executionTerminalOutcome\": ")
            append(executionEvidence?.terminalOutcome?.let { "\"${it.jsonEscape()}\"" } ?: "null").append(',')
            if (turnIntent != null) {
                append("\n  \"turnIntentPath\": \"").append(requireNotNull(turnIntentPath).jsonEscape()).append("\",")
                append("\n  \"turnIntentSha256\": \"").append(turnIntent.sha256).append("\",")
                append("\n  \"turnReceiptPath\": ")
                append(turnReceiptPath?.let { "\"${it.jsonEscape()}\"" } ?: "null").append(',')
                append("\n  \"turnReceiptSha256\": ")
                append(turnReceiptSha256?.let { "\"$it\"" } ?: "null").append(',')
                append("\n  \"changeAssessmentPath\": \"").append(requireNotNull(changeAssessmentPath).jsonEscape()).append("\",")
                append("\n  \"changeAssessmentSha256\": \"").append(requireNotNull(changeAssessment).sha256).append("\",")
            }
            append("\n  \"currentSourceSha256\": ")
            append(currentSourceSha256?.let { "\"$it\"" } ?: "null").append(',')
            append("\n  \"previousAcceptedSourceSha256\": ")
            append(previousCheckpoint?.takeIf { it.accepted }?.sourceSha256?.let { "\"$it\"" } ?: "null").append(',')
            append("\n  \"entityIds\": [")
            append((module.functionIds + module.globalIds).sorted().joinToString(",") { "\"${it.jsonEscape()}\"" })
            append("]\n}\n")
        }
        writeAtomically(path, report)
    }

    private fun unresolvedFallback(
        request: ModuleReconstructionRequest,
        reconstructorIdentity: String,
        failure: Exception,
    ): ReconstructedModule {
        val fallback = ReconstructionAdapters.resolve(request.profile).defaultReconstructor().reconstruct(request)
        val entityIds = request.module.functionIds + request.module.globalIds
        val agentOutcome = failure as? ModuleReconstructionAgentOutcomeException
        val code = when {
            failure is ModuleContextBudgetExceededException -> "context-budget-exceeded"
            agentOutcome != null -> "agent-${agentOutcome.evidence.terminalOutcome}"
            else -> "reconstruction-failed"
        }
        val message = when {
            failure is ModuleContextBudgetExceededException ->
                "module context required ${failure.promptCharacters} characters; limit=${failure.promptBudgetCharacters}"
            agentOutcome != null -> "agent invocation ended with ${agentOutcome.evidence.terminalOutcome}"
            else -> "${failure::class.simpleName ?: "Exception"} during module reconstruction"
        }
        return fallback.copy(
            generator = "unresolved:$reconstructorIdentity",
            promptSha256 = agentOutcome?.promptSha256
                ?: (failure as? ModuleContextBudgetExceededException)?.promptSha256
                ?: fallback.promptSha256,
            promptCharacters = agentOutcome?.promptCharacters
                ?: (failure as? ModuleContextBudgetExceededException)?.promptCharacters,
            promptBudgetCharacters = agentOutcome?.promptBudgetCharacters
                ?: (failure as? ModuleContextBudgetExceededException)?.promptBudgetCharacters,
            issues = fallback.issues + ModuleReconstructionIssue(code, message, entityIds),
            retryable = true,
            agentExecutionEvidence = agentOutcome?.evidence,
        )
    }

    private fun assessReconstruction(
        adapter: ReconstructionAdapter,
        profile: ReconstructionProfile,
        module: PlannedModule,
        model: RecoveredProgramModel,
        reconstructed: ReconstructedModule,
        source: String,
        reconstructorIdentity: String,
    ): List<ModuleReconstructionIssue> {
        val entityIds = module.functionIds + module.globalIds
        val issues = reconstructed.issues.toMutableList()
        if (reconstructed.generator == "repair-revision") {
            issues += ModuleReconstructionIssue(
                "reserved-generator", "repair-revision is reserved for authenticated repair publication", entityIds,
            )
        }
        if (source.isBlank() && entityIds.isNotEmpty()) {
            issues += ModuleReconstructionIssue("empty-source", "module source is empty", entityIds)
        }
        val claimsAgentExecution = moduleClaimsAgentExecution(reconstructed.generator, reconstructorIdentity)
        if (claimsAgentExecution) {
            if (reconstructed.source != source) {
                issues += ModuleReconstructionIssue(
                    "agent-source-normalization-changed-bytes",
                    "agent candidate bytes differ from the normalized published source",
                    entityIds,
                )
            }
            if (reconstructed.agentExecutionEvidence?.releaseComplete != true) {
                issues += ModuleReconstructionIssue(
                    "agent-execution-evidence-incomplete",
                    "agent candidate lacks complete invocation-bound ACP release evidence",
                    entityIds,
                )
            }
        }
        val promptCharacters = reconstructed.promptCharacters
        val promptBudget = reconstructed.promptBudgetCharacters
        if (claimsAgentExecution || promptCharacters != null || promptBudget != null) {
            if (promptCharacters == null || promptBudget == null) {
                issues += ModuleReconstructionIssue(
                    "prompt-budget-unattributed",
                    "agent result does not record prompt size and configured budget",
                    entityIds,
                )
            } else {
                // Each violation is retained independently so recorded evidence shows both
                // a usage overrun and a budget the selected profile never authorized.
                if (promptCharacters > promptBudget) {
                    issues += ModuleReconstructionIssue(
                        "context-budget-exceeded",
                        "agent prompt used $promptCharacters characters with a $promptBudget character budget",
                        entityIds,
                    )
                }
                if (!modulePromptBudgetIsValid(promptCharacters.toLong(), promptBudget.toLong(), profile)) {
                    issues += ModuleReconstructionIssue(
                        "prompt-budget-invalid",
                        "agent prompt size or budget is outside the selected reconstruction profile",
                        entityIds,
                    )
                }
            }
        }
        issues += adapter.assess(module, model, reconstructed.generator, source, profile)
        return issues.distinctBy { Triple(it.code, it.message, it.entityIds.sorted()) }
    }

    private fun writeAtomically(path: Path, content: String) {
        path.parent?.createDirectories()
        val temporary = Files.createTempFile(path.parent ?: path.toAbsolutePath().parent, ".${path.fileName}.", ".tmp")
        try {
            temporary.writeText(content)
            try {
                Files.move(
                    temporary,
                    path,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            temporary.deleteIfExists()
        }
    }

    private const val MAXIMUM_AGENT_CHECKPOINT_BYTES = 4 * 1024 * 1024
    private val CHECKPOINT_V7_REQUIRED_FIELDS = setOf(
            "schemaVersion", "fingerprint", "sourceSha256", "generator", "workflowOrigin",
            "reconstructorIdentity", "promptSha256", "promptCharacters", "promptBudgetCharacters",
            "executionEvidencePath", "executionEvidenceSha256", "executionEvidenceSchemaVersion",
            "executionRequestSha256", "executionTerminalOutcome", "executionReleaseComplete",
            "inputBinarySha256", "modelSchemaVersion", "profileSha256", "turnIntentPath",
            "turnIntentSha256", "turnIntent", "turnReceiptPath", "turnReceiptSha256",
            "changeAssessmentPath", "changeAssessmentSha256", "changeAssessment", "accepted",
            "compilation", "retryable", "entityStatuses", "issues",
        )
    private val CHECKPOINT_V7_OPTIONAL_FALLBACK_FIELDS = setOf(
        "preDispatchObservedBehavior", "preDispatchCompilerFeedback",
    )
    private val CHECKPOINT_V6_REQUIRED_FIELDS = CHECKPOINT_V7_REQUIRED_FIELDS - setOf(
        "workflowOrigin", "turnIntentPath", "turnIntentSha256", "turnIntent", "changeAssessmentPath",
            "turnReceiptPath", "turnReceiptSha256", "changeAssessmentSha256", "changeAssessment",
    )

    internal fun moduleFingerprint(
        module: PlannedModule,
        model: RecoveredProgramModel,
        sharedHeader: String,
        moduleHeader: String,
        privateHeader: String,
        dependencyHeaders: Map<String, String>,
        observedBehavior: String?,
        profileSha256: String,
        compilerPolicyId: String,
    ): String {
        val selectedModel = model.copy(
            functions = module.functionIds.map { id -> model.functions.single { it.id == id } },
            globals = module.globalIds.map { id -> model.globals.single { it.id == id } },
            types = module.typeIds.map { id -> model.types.single { it.id == id } },
        )
        val inputs = kotlinx.serialization.json.JsonObject(linkedMapOf(
            "provider" to kotlinx.serialization.json.JsonPrimitive(INPUT_FINGERPRINT_PROVIDER),
            "model" to Json.parseToJsonElement(selectedModel.toJson()),
            "sharedHeader" to kotlinx.serialization.json.JsonPrimitive(sharedHeader),
            "moduleHeader" to kotlinx.serialization.json.JsonPrimitive(moduleHeader),
            "privateHeader" to kotlinx.serialization.json.JsonPrimitive(privateHeader),
            "dependencyHeaders" to kotlinx.serialization.json.JsonObject(dependencyHeaders.toSortedMap().mapValues {
                kotlinx.serialization.json.JsonPrimitive(it.value)
            }),
            "observedBehavior" to (observedBehavior?.let { kotlinx.serialization.json.JsonPrimitive(it) } ?: JsonNull),
            "profileSha256" to kotlinx.serialization.json.JsonPrimitive(profileSha256),
            "compilerPolicy" to kotlinx.serialization.json.JsonPrimitive(compilerPolicyId),
        ))
        return sha256(inputs.toString().toByteArray(Charsets.UTF_8))
    }

    private fun renderConfidence(
        model: RecoveredProgramModel,
        plan: ModulePlan,
        unresolvedImplementations: Set<String>,
        moduleRevisionEvidence: Map<String, String>,
        profile: ReconstructionProfile,
        hostSafetyLimits: ReconstructionHostSafetyLimits,
        plannerLimits: PlannerBudgetLimits,
        plannerComplexity: PlannerComplexity,
        generationBudgetObservations: List<ModuleGenerationBudgetObservation>,
    ): String {
        fun score(status: RecoveryStatus) = when (status) {
            RecoveryStatus.RECOVERED -> 1.0
            RecoveryStatus.PARTIAL -> 0.6
            RecoveryStatus.SYNTHETIC -> 0.25
            RecoveryStatus.FAILED -> 0.0
        }
        val functionStatuses = model.functions.associate { it.id to it.status }
        val globalStatuses = model.globals.associate { it.id to it.status }
        val typeStatuses = model.types.associate { it.id to it.status }
        val moduleScores = plan.modules.map { module ->
            val statuses = module.functionIds.map(functionStatuses::getValue) +
                module.globalIds.map(globalStatuses::getValue) + module.typeIds.map(typeStatuses::getValue)
            module.id to if (statuses.isEmpty()) 0.0 else statuses.map(::score).average()
        }
        val allStatuses = model.functions.map { it.status } + model.globals.map { it.status } + model.types.map { it.status }
        val projectScore = if (allStatuses.isEmpty()) 0.0 else allStatuses.map(::score).average()
        val unresolvedOutput = ReconstructionAdapters.resolve(profile).requiresUnresolvedOutput(profile)
        val unresolvedRecovery = model.functions.filter { unresolvedOutput || model.isRecoveryUnresolved(it.status) }.map { it.id } +
            model.globals.filter { unresolvedOutput || model.isRecoveryUnresolved(it.status) }.map { it.id } +
            model.types.filter { unresolvedOutput || model.isRecoveryUnresolved(it.status) }.map { it.id }
        fun idsJson(ids: Collection<String>) = ids.distinct().sorted().joinToString(prefix = "[", postfix = "]", separator = ",") {
            "\"${it.jsonEscape()}\""
        }
        val moduleById = plan.modules.associateBy { it.id }
        val unresolvedRecoverySet = unresolvedRecovery.toSet()
        return buildString {
            append("{\n  \"schemaVersion\": 2,")
            append("\n  \"basis\": \"recovery evidence only; behavioral equivalence is not implied\",")
            append("\n  \"scoreMeaning\": \"structural recovery heuristic; not implementation acceptance or measured behavioral confidence\",")
            append("\n  \"scoreInterpretation\": ").append(HeuristicScoreInterpretation.STRUCTURAL_RECOVERY.toJson()).append(',')
            append("\n  \"recoveryAssessment\": ").append(model.unassessedRecoveryAssessment()).append(',')
            append("\n  \"projectScore\": ").append("%.4f".format(java.util.Locale.ROOT, projectScore)).append(',')
            append("\n  \"modules\": [")
            append(moduleScores.sortedBy { it.first }.joinToString(",") { (id, value) ->
                val module = moduleById.getValue(id)
                val owned = (module.functionIds + module.globalIds + module.typeIds).toSet()
                "\n    {\"id\":\"${id.jsonEscape()}\",\"score\":${"%.4f".format(java.util.Locale.ROOT, value)}," +
                    "\"unresolvedRecoveryEntityIds\":${idsJson(owned.filter { it in unresolvedRecoverySet })}," +
                    "\"unresolvedImplementationIds\":${idsJson(owned.filter { it in unresolvedImplementations })}," +
                    "\"revisionEvidence\":${moduleRevisionEvidence.getValue(id)}}"
            })
            append("\n  ],\n  \"unresolvedRecoveryEntityIds\": ").append(idsJson(unresolvedRecovery))
            append(",\n  \"unresolvedImplementationIds\": ").append(idsJson(unresolvedImplementations))
            append(",\n  \"unresolvedEntityIds\": ").append(idsJson(unresolvedRecovery + unresolvedImplementations))
            append(",\n  \"semanticPlanningBudgetEvidence\": {")
            append("\n    \"schemaVersion\":1,")
            append("\n    \"selectedProfile\":{")
            append("\"id\":\"").append(profile.id.jsonEscape()).append("\",")
            append("\"sha256\":\"").append(profile.sha256).append("\",")
            append("\"descriptor\":").append(profile.canonicalJson()).append("},")
            append("\n    \"hostSafetyLimits\":").append(hostSafetyLimits.maximum.canonicalJson()).append(',')
            append("\n    \"effectivePlannerLimits\":{")
            append("\"maximumFunctionsPerModule\":").append(plannerLimits.maximumFunctionsPerModule).append(',')
            append("\"maximumEntities\":").append(plannerLimits.maximumEntities).append(',')
            append("\"maximumDependencyEdges\":").append(plannerLimits.maximumDependencyEdges).append(',')
            append("\"maximumWorkUnits\":").append(plannerLimits.maximumWorkUnits).append("},")
            append("\n    \"outcome\":{")
            append("\"status\":\"planned\",")
            append("\"plannedModules\":").append(plan.modules.size).append(',')
            append("\"functionCount\":").append(plannerComplexity.functionCount).append(',')
            append("\"globalCount\":").append(plannerComplexity.globalCount).append(',')
            append("\"typeCount\":").append(plannerComplexity.typeCount).append(',')
            append("\"dependencyEdges\":").append(model.functions.sumOf {
                it.calls.size.toLong() + it.referencedGlobals.size.toLong()
            }).append(',')
            append("\"sparseWorkUnits\":").append(plannerComplexity.sparseWorkUnits).append("},")
            append("\n    \"limitations\":[\"local planning evidence; no production execution authority\"]")
            append("\n  }")
            append(",\n  \"sourceGenerationBudgetEvidence\": {")
            append("\n    \"schemaVersion\": 1,")
            append("\n    \"selectedProfile\": {")
            append("\n      \"id\":\"").append(profile.id.jsonEscape()).append("\",")
            append("\n      \"sha256\":\"").append(profile.sha256).append("\",")
            append("\n      \"descriptor\":").append(profile.canonicalJson())
            append("\n    },")
            append("\n    \"hostSafetyLimits\":{")
            append("\n      \"budgets\":").append(hostSafetyLimits.maximum.canonicalJson())
            append("\n    },")
            append("\n    \"admission\":{\"profileWithinHost\":true},")
            append("\n    \"outcome\":{")
            append("\n      \"plannedModules\":").append(plan.modules.size).append(',')
            append("\n      \"completedModules\":").append(generationBudgetObservations.size).append(',')
            append("\n      \"acceptedModules\":").append(generationBudgetObservations.count { it.outcome == "accepted" }).append(',')
            append("\n      \"unresolvedModules\":").append(generationBudgetObservations.count { it.outcome == "unresolved" })
            append("\n    },")
            append("\n    \"modules\":[")
            append(generationBudgetObservations.sortedBy { it.moduleId }.joinToString(",") { observation ->
                "\n      {\"moduleId\":\"${observation.moduleId.jsonEscape()}\",\"outcome\":\"${observation.outcome}\"," +
                    "\"sourceBytes\":${observation.sourceBytes}," +
                    "\"promptCharacters\":${observation.promptCharacters ?: "null"}," +
                    "\"promptBudgetCharacters\":${observation.promptBudgetCharacters ?: "null"}}"
            })
            append("\n    ],")
            append("\n    \"limitations\":[")
            append("\"profile and host ceilings are local admission commitments; this record does not authenticate production execution\",")
            append("\"prompt usage is retained only when the selected reconstructor reports it; null is not a measured prompt\",")
            append("\"module outcomes and source byte counts are local generation observations, not behavioral equivalence evidence\"")
            append("]\n  }")
            append("\n}\n")
        }
    }

    private fun renderUnresolvedMarkdown(
        model: RecoveredProgramModel,
        plan: ModulePlan,
        unresolvedImplementationIds: Set<String>,
        unresolvedOutput: Boolean = false,
    ): String {
        val rows = buildList {
            model.functions.filter { unresolvedOutput || model.isRecoveryUnresolved(it.status) }.forEach { add("function" to Triple(it.id, it.status, "0x${it.address.toString(16)}")) }
            model.globals.filter { unresolvedOutput || model.isRecoveryUnresolved(it.status) }.forEach { add("global" to Triple(it.id, it.status, "0x${it.address.toString(16)}")) }
            model.types.filter { unresolvedOutput || model.isRecoveryUnresolved(it.status) }.forEach { add("type" to Triple(it.id, it.status, it.sourceAddress?.let { address -> "0x${address.toString(16)}" } ?: "no address")) }
        }
        return buildString {
            append("# Unresolved reconstruction evidence\n\n")
            append("This list is evidence-bounded. The generated project does not claim universal behavioral equivalence.\n\n")
            val entityCount = model.functions.size + model.globals.size + model.types.size
            append("Recovery assessment: unassessed for $entityCount entities ")
            append("(${model.functions.size} functions, ${model.globals.size} globals, ${model.types.size} types). ")
            append("Extraction labels and implementation acceptance do not establish recovery accuracy. ")
            append("The confidence report retains the complete model-bound unassessed population.\n\n")
            if (rows.isEmpty()) append("The historical extraction-status list has no unresolved entries. Recovery accuracy and untested behavior remain unassessed.\n")
            else {
                append("| Kind | Stable ID | Status | Provenance |\n|---|---|---|---|\n")
                rows.sortedBy { it.second.first }.forEach { (kind, details) ->
                    val status = details.second.name.lowercase()
                    val assessment = if (unresolvedOutput || model.schemaVersion >= 2) "unassessed (extraction: $status)" else status
                    append("| $kind | `${details.first}` | $assessment | ${details.third} |\n")
                }
            }
            append("\n## Implementation generation\n\n")
            if (unresolvedOutput) append("Evidence-only diagnostic inventory; no implementation acceptance or recovered behavior is claimed.\n\n")
            if (unresolvedImplementationIds.isEmpty()) {
                if (!unresolvedOutput) append("Every planner-owned implementation passed the acceptance checks.\n")
            } else {
                val owner = plan.modules.flatMap { module ->
                    (module.functionIds + module.globalIds).map { id -> id to module.id }
                }.toMap()
                append("These planner-owned entities are not accepted implementations. See the attributable module report for the exact evidence.\n\n")
                append("| Stable ID | Owning module | Evidence |\n|---|---|---|\n")
                unresolvedImplementationIds.sorted().forEach { id ->
                    val moduleId = owner.getValue(id)
                    append("| `$id` | `$moduleId` | `reports/modules/$moduleId.json` |\n")
                }
            }
        }
    }
}

private fun String.jsonEscape(): String = buildString {
    for (character in this@jsonEscape) {
        when (character) {
            '\\' -> append("\\\\")
            '"' -> append("\\\"")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (character.code < 0x20) append("\\u%04x".format(character.code)) else append(character)
        }
    }
}

object SourceTreeManifestReader {
    private val rootKeys = setOf(
        "schemaVersion",
        "profileId",
        "profileSha256",
        "inputSha256",
        "files",
        "unresolvedEntityIds",
        "unresolvedImplementationIds",
    )
    private val fileKeys = setOf(
        "path",
        "sha256",
        "generator",
        "promptSha256",
        "acceptedImplementation",
        "contentKind",
        "roles",
        "entityIds",
    )

    fun read(projectDir: Path, expectedProfile: ReconstructionProfile): SourceTreeManifest {
        val path = projectDir.resolve("source_tree_manifest.json")
        require(path.exists()) { "project is missing source_tree_manifest.json" }
        val ceiling = minOf(expectedProfile.budgets.archiveMaximumFileBytes, Int.MAX_VALUE.toLong() - 1L)
        require(ceiling >= 1L) { "build output ceiling is invalid" }
        val snapshot = decompengine.repair.readStableRegularFile(projectDir, "source_tree_manifest.json", ceiling)
        require(snapshot.bytes.isNotEmpty()) { "source tree manifest must not be empty" }
        return parse(snapshot.bytes.toString(Charsets.UTF_8), expectedProfile)
    }

    fun parse(text: String, expectedProfile: ReconstructionProfile): SourceTreeManifest {
        UniqueJsonObjectKeyValidator(text).validate()
        val root = Json.parseToJsonElement(text).jsonObject
        require(root.keys == rootKeys) { "source tree manifest fields do not match schema version 3" }
        val schemaPrimitive = root.getValue("schemaVersion").jsonPrimitive
        require(!schemaPrimitive.isString) { "source tree manifest schemaVersion must be an integer" }
        val schemaVersion = schemaPrimitive.intOrNull
            ?: throw IllegalArgumentException("source tree manifest schemaVersion must be an integer")
        require(schemaVersion == 3) { "unsupported source tree manifest schemaVersion: $schemaVersion" }
        val profileId = requiredManifestString(root, "profileId")
        val profileSha256 = requiredManifestString(root, "profileSha256")
        val files = root.getValue("files").jsonArray.map { element ->
            val item = element.jsonObject
            require(item.keys == fileKeys) { "source tree manifest file fields do not match schema version 3" }
            val roles = item.getValue("roles").jsonArray.map { role ->
                require(role.jsonPrimitive.isString) { "source tree manifest file roles must be strings" }
                ProjectFileRole.fromWireName(role.jsonPrimitive.content)
            }
            require(roles.map(ProjectFileRole::wireName) == roles.map(ProjectFileRole::wireName).distinct().sorted()) {
                "source tree manifest file roles must be unique and sorted"
            }
            val entityIds = item.getValue("entityIds").jsonArray.map {
                require(it.jsonPrimitive.isString) { "source tree manifest entity IDs must be strings" }
                it.jsonPrimitive.content
            }
            require(entityIds == entityIds.distinct().sorted()) {
                "source tree manifest entity IDs must be unique and sorted"
            }
            val accepted = item.getValue("acceptedImplementation").let { value ->
                if (value is JsonNull) {
                    null
                } else {
                    require(!value.jsonPrimitive.isString) {
                        "source tree manifest acceptance value must be Boolean or null"
                    }
                    value.jsonPrimitive.booleanOrNull
                        ?: throw IllegalArgumentException("source tree manifest acceptance value must be Boolean or null")
                }
            }
            GeneratedFileEvidence(
                path = requiredManifestString(item, "path"),
                sha256 = requiredManifestString(item, "sha256"),
                generator = requiredManifestString(item, "generator"),
                promptSha256 = item.getValue("promptSha256").let { value ->
                    if (value is JsonNull) null else {
                        require(value.jsonPrimitive.isString) {
                            "source tree manifest prompt hash must be a string or null"
                        }
                        value.jsonPrimitive.contentOrNull
                    }
                },
                entityIds = entityIds,
                acceptedImplementation = accepted,
                roles = roles.toSet(),
                contentKind = ProjectContentKind.fromWireName(requiredManifestString(item, "contentKind")),
            )
        }
        require(files.map(GeneratedFileEvidence::path) == files.map(GeneratedFileEvidence::path).distinct().sorted()) {
            "source tree manifest files must be unique and sorted"
        }
        fun sortedIds(name: String): List<String> = root.getValue(name).jsonArray.map {
            require(it.jsonPrimitive.isString) { "source tree manifest $name values must be strings" }
            it.jsonPrimitive.content
        }.also { ids ->
            require(ids == ids.distinct().sorted()) { "source tree manifest $name must be unique and sorted" }
        }
        val manifest = SourceTreeManifest(
            schemaVersion = schemaVersion,
            profileId = profileId,
            profileSha256 = profileSha256,
            inputSha256 = requiredManifestString(root, "inputSha256"),
            files = files,
            unresolvedEntityIds = sortedIds("unresolvedEntityIds"),
            unresolvedImplementationIds = sortedIds("unresolvedImplementationIds"),
        )
        require(manifest.profileId == expectedProfile.id && manifest.profileSha256 == expectedProfile.sha256) {
            "source tree manifest reconstruction profile does not match the expected profile"
        }
        manifest.files.forEach { file ->
            val declaration = expectedProfile.layout.declarationForPath(file.path)
            require(file.roles == declaration.roles && file.contentKind == declaration.contentKind) {
                "source tree manifest file policy does not match the reconstruction profile: ${file.path}"
            }
        }
        return manifest
    }

    fun editablePaths(
        projectDir: Path,
        expectedProfile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
    ): Set<String> {
        val path = projectDir.resolve("source_tree_manifest.json")
        if (!path.exists()) return emptySet()
        return read(projectDir, expectedProfile).editablePaths
    }

    private fun requiredManifestString(objectValue: kotlinx.serialization.json.JsonObject, name: String): String {
        val primitive = objectValue.getValue(name).jsonPrimitive
        require(primitive.isString) { "source tree manifest $name must be a string" }
        return primitive.content
    }
}

/** Reject duplicate object members before kotlinx.serialization can collapse them. */
internal class UniqueJsonObjectKeyValidator(private val source: String) {
    private var cursor = 0

    fun validate() {
        parseValue(0)
        skipWhitespace()
        require(cursor == source.length) { "source tree manifest has trailing JSON content" }
    }

    private fun parseValue(depth: Int) {
        require(depth <= MAXIMUM_MANIFEST_JSON_DEPTH) { "source tree manifest JSON nesting is too deep" }
        skipWhitespace()
        require(cursor < source.length) { "source tree manifest contains incomplete JSON" }
        when (source[cursor]) {
            '{' -> parseObject(depth + 1)
            '[' -> parseArray(depth + 1)
            '"' -> parseString()
            't' -> consumeLiteral("true")
            'f' -> consumeLiteral("false")
            'n' -> consumeLiteral("null")
            '-', in '0'..'9' -> parseNumber()
            else -> throw IllegalArgumentException("source tree manifest contains invalid JSON")
        }
    }

    private fun parseObject(depth: Int) {
        cursor++
        skipWhitespace()
        if (consumeIf('}')) return
        val keys = mutableSetOf<String>()
        while (true) {
            skipWhitespace()
            require(cursor < source.length && source[cursor] == '"') {
                "source tree manifest JSON object key must be a string"
            }
            val key = parseString()
            require(keys.add(key)) { "source tree manifest JSON object contains duplicate key: $key" }
            skipWhitespace()
            require(consumeIf(':')) { "source tree manifest JSON object is missing a colon" }
            parseValue(depth)
            skipWhitespace()
            if (consumeIf('}')) return
            require(consumeIf(',')) { "source tree manifest JSON object is missing a comma" }
        }
    }

    private fun parseArray(depth: Int) {
        cursor++
        skipWhitespace()
        if (consumeIf(']')) return
        while (true) {
            parseValue(depth)
            skipWhitespace()
            if (consumeIf(']')) return
            require(consumeIf(',')) { "source tree manifest JSON array is missing a comma" }
        }
    }

    private fun parseString(): String {
        require(consumeIf('"')) { "source tree manifest JSON string is invalid" }
        val decoded = StringBuilder()
        while (cursor < source.length) {
            val character = source[cursor++]
            when {
                character == '"' -> return decoded.toString()
                character == '\\' -> {
                    require(cursor < source.length) { "source tree manifest JSON escape is incomplete" }
                    when (val escaped = source[cursor++]) {
                        '"', '\\', '/' -> decoded.append(escaped)
                        'b' -> decoded.append('\b')
                        'f' -> decoded.append('\u000c')
                        'n' -> decoded.append('\n')
                        'r' -> decoded.append('\r')
                        't' -> decoded.append('\t')
                        'u' -> {
                            require(cursor + 4 <= source.length) {
                                "source tree manifest JSON Unicode escape is incomplete"
                            }
                            val digits = source.substring(cursor, cursor + 4)
                            require(digits.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
                                "source tree manifest JSON Unicode escape is invalid"
                            }
                            decoded.append(digits.toInt(16).toChar())
                            cursor += 4
                        }
                        else -> throw IllegalArgumentException("source tree manifest JSON escape is invalid")
                    }
                }
                character.code < 0x20 -> throw IllegalArgumentException(
                    "source tree manifest JSON string contains a control character",
                )
                else -> decoded.append(character)
            }
        }
        throw IllegalArgumentException("source tree manifest JSON string is unterminated")
    }

    private fun parseNumber() {
        consumeIf('-')
        require(cursor < source.length) { "source tree manifest JSON number is incomplete" }
        if (consumeIf('0')) {
            require(cursor >= source.length || source[cursor] !in '0'..'9') {
                "source tree manifest JSON number has a leading zero"
            }
        } else {
            require(source[cursor] in '1'..'9') { "source tree manifest JSON number is invalid" }
            while (cursor < source.length && source[cursor] in '0'..'9') cursor++
        }
        if (consumeIf('.')) {
            require(cursor < source.length && source[cursor] in '0'..'9') {
                "source tree manifest JSON fraction is incomplete"
            }
            while (cursor < source.length && source[cursor] in '0'..'9') cursor++
        }
        if (cursor < source.length && source[cursor].lowercaseChar() == 'e') {
            cursor++
            if (cursor < source.length && source[cursor] in setOf('+', '-')) cursor++
            require(cursor < source.length && source[cursor] in '0'..'9') {
                "source tree manifest JSON exponent is incomplete"
            }
            while (cursor < source.length && source[cursor] in '0'..'9') cursor++
        }
    }

    private fun consumeLiteral(value: String) {
        require(source.regionMatches(cursor, value, 0, value.length)) {
            "source tree manifest contains an invalid JSON literal"
        }
        cursor += value.length
    }

    private fun consumeIf(character: Char): Boolean {
        if (cursor >= source.length || source[cursor] != character) return false
        cursor++
        return true
    }

    private fun skipWhitespace() {
        while (cursor < source.length && source[cursor] in setOf(' ', '\t', '\n', '\r')) cursor++
    }
}

private const val MAXIMUM_MANIFEST_JSON_DEPTH = 64
