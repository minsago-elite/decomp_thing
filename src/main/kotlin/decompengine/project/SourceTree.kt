package decompengine.project

import decompengine.assessment.HeuristicScoreInterpretation
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
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
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import decompengine.agent.AgentWorkflowPhase
import decompengine.agent.AgentWorkflowProgress
import decompengine.agent.receiptCommitmentBytes
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.AtomicMoveNotSupportedException
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
)

data class ReconstructedModule(
    val source: String,
    val generator: String,
    val promptSha256: String,
    val promptCharacters: Int? = null,
    val promptBudgetCharacters: Int? = null,
    val issues: List<ModuleReconstructionIssue> = emptyList(),
    val retryable: Boolean = true,
    val agentExecutionEvidence: ReconstructionAgentExecutionEvidence? = null,
)

data class ModuleReconstructionIssue(
    val code: String,
    val message: String,
    val entityIds: List<String>,
)

fun interface ModuleReconstructor {
    fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule

    /** Stable identity used only to resume a deliberate unresolved result from the same strategy. */
    fun cacheIdentity(): String = "custom"

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

/** Emits buildable evidence stubs by default; raw recovered C remains in the program model for later refinement. */
class EvidenceModuleReconstructor(private val includeRecoveredC: Boolean = false) : ModuleReconstructor {
    override fun cacheIdentity(): String = if (includeRecoveredC) "recovered-c:v2" else "evidence-only:v1"

    override fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule {
        val functions = request.module.functionIds.map { id -> request.model.functions.single { it.id == id } }
        val globals = request.module.globalIds.map { id -> request.model.globals.single { it.id == id } }
        val source = buildString {
            append("#include <stddef.h>\n#include \"modules/${request.module.id}.h\"\n#include \"${request.module.id}_internal.h\"\n")
            request.dependencyHeaders.keys.sorted().forEach { header -> append("#include \"").append(header.removePrefix("include/")).append("\"\n") }
            append('\n')
            globals.forEach { global ->
                append("/* ${global.id}; recovered global @ 0x${global.address.toString(16)} */\n")
                append(globalDeclaration(global, external = false)).append("\n\n")
            }
            functions.forEach { function ->
                append("/* ${function.id} @ 0x${function.address.toString(16)}; status=${function.status.name.lowercase()} */\n")
                val recovered = function.decompiledC?.trim()?.takeIf(String::isNotEmpty)?.takeIf { includeRecoveredC }
                    ?.let(::markNamedParametersUsed)
                if (recovered != null) append(recovered).append("\n\n")
                else append(stub(function)).append("\n\n")
            }
        }
        val unresolved = if (includeRecoveredC) {
            functions.filter { it.decompiledC.isNullOrBlank() }.map { function ->
                ModuleReconstructionIssue(
                    "recovered-c-unavailable",
                    "normalized recovered C is unavailable for ${function.id}",
                    listOf(function.id),
                )
            }
        } else {
            listOf(
                ModuleReconstructionIssue(
                    "evidence-only-placeholder",
                    "evidence-only mode emits placeholders and does not accept implementations",
                    request.module.functionIds + request.module.globalIds,
                ),
            ).filter { it.entityIds.isNotEmpty() }
        }
        return ReconstructedModule(
            source = source,
            generator = if (includeRecoveredC) "recovered-c" else "evidence-only",
            promptSha256 = sha256(source.toByteArray()),
            issues = unresolved,
            retryable = false,
        )
    }

    private fun stub(function: RecoveredFunction): String {
        val prototype = normalizedPrototype(function)
        val body = if (prototype.trimStart().startsWith("void ")) "    return;" else "    return 0;"
        return markNamedParametersUsed("$prototype {\n$body\n}")
    }

    /** Keep strict warning builds honest without changing recovered behavior. */
    private fun markNamedParametersUsed(source: String): String {
        val bodyStart = source.indexOf('{')
        if (bodyStart < 0) return source
        val signature = source.substring(0, bodyStart)
        val parametersStart = signature.indexOf('(')
        val parametersEnd = signature.lastIndexOf(')')
        if (parametersStart < 0 || parametersEnd <= parametersStart) return source
        val cKeywords = setOf(
            "auto", "char", "const", "double", "enum", "extern", "float", "inline", "int", "long",
            "register", "restrict", "short", "signed", "static", "struct", "typedef", "union", "unsigned",
            "void", "volatile", "_Atomic", "_Bool", "_Complex",
        )
        val names = signature.substring(parametersStart + 1, parametersEnd)
            .split(',')
            .mapNotNull { parameter ->
                Regex("([A-Za-z_][A-Za-z0-9_]*)\\s*(?:\\[[^]]*])?\\s*$")
                    .find(parameter.trim())?.groupValues?.get(1)
            }
            .filterNot(cKeywords::contains)
            .distinct()
        if (names.isEmpty()) return source
        val body = source.substring(bodyStart + 1)
        val missingUses = names.filterNot { name ->
            Regex("\\(\\s*void\\s*\\)\\s*${Regex.escape(name)}\\s*;").containsMatchIn(body)
        }
        if (missingUses.isEmpty()) return source
        return buildString(source.length + missingUses.sumOf { it.length + 14 }) {
            append(source, 0, bodyStart + 1)
            missingUses.forEach { name -> append("\n    (void)").append(name).append(';') }
            append(source, bodyStart + 1, source.length)
        }
    }
}

/** Uses already-normalized recovered C, primarily for trusted fixtures and post-normalization pipelines. */
class RecoveredCModuleReconstructor : ModuleReconstructor by EvidenceModuleReconstructor(includeRecoveredC = true)

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

    override fun cacheIdentity(): String =
        "agent:${harness.implementationIdentifier() ?: "unspecified"}:context-$maximumContextCharacters:" +
            "factory-${harnessProvenanceSha256 ?: "unbound"}:v2"

    override fun requiresExecutionEvidenceForCheckpointReuse(): Boolean = true

    private fun sessionContinuation(
        request: ModuleReconstructionRequest,
        acceptedRevision: String? = request.acceptedSourceSha256,
    ): AgentSessionContinuation? {
        val fingerprint = request.sessionEvidenceFingerprint ?: return null
        if (harnessProvenanceSha256 == null) return null
        val root = request.workspaceRoot.toAbsolutePath().normalize()
        val paths = (listOf(
            request.profile.layout.declaration("shared-interface").materialize(),
            request.module.headerPath,
            request.profile.layout.declaration("module-private-interface").materialize(mapOf("module" to request.module.id)),
            request.module.sourcePath,
        ) + request.dependencyHeaders.keys).distinct()
        val files = try {
            AgentSessionJournal.captureWorkspaceFiles(
                paths.map { AgentWorkspacePath("project", it) }, listOf(AgentWorkspaceRoot("project", root)),
            )
        } catch (failure: Exception) {
            throw AgentSessionRecoveryException("could not capture the bounded reconstruction session inventory", failure)
        }
        val workflowSha256 = sha256(("module-reconstruction-session-v1\n" + request.model.inputSha256 + "\n" +
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
        val implementation = request.profile.layout.declaration("module-implementation")
        require(target == implementation.materialize(mapOf("module" to request.module.id)) &&
            ProjectFileRole.MODULE_IMPLEMENTATION in implementation.roles &&
            ProjectFileRole.EDITABLE in implementation.roles
        ) { "planned module target must match the profile-owned editable implementation" }
        val localFunctions = request.module.functionIds.map { id -> request.model.functions.single { it.id == id } }
        val localGlobals = request.module.globalIds.map { id -> request.model.globals.single { it.id == id } }
        val functionEvidence = localFunctions.joinToString("\n\n") { function ->
            "${function.id} @ 0x${function.address.toString(16)}\nprototype: ${function.prototype}\n" +
                "calls: ${function.calls.sorted()}\nglobals: ${function.referencedGlobals.sorted()}\n" +
                "strings: ${function.strings.sorted()}\ndecompilation:\n${function.decompiledC ?: "<unavailable>"}"
        }
        val globalEvidence = localGlobals.joinToString("\n") { global ->
            "${global.id} @ 0x${global.address.toString(16)}: ${global.type} ${global.name}; " +
                "initializer=${global.initializer ?: "<unavailable>"}; status=${global.status.name.lowercase()}"
        }
        val evidence = buildString {
            append("module: ").append(request.module.id).append('\n')
            append("ownership evidence: ").append(request.module.boundaryEvidence.sorted()).append("\n\n")
            append("functions:\n").append(functionEvidence.ifBlank { "<none>" })
            append("\n\nglobals:\n").append(globalEvidence.ifBlank { "<none>" })
        }
        val provenanceIds = (request.module.functionIds + request.module.globalIds).sorted()
        val acceptance = """
            The workflow validates your exact source bytes against the returned change set and owned entity IDs.
            Preserve all required function and global definitions and use only declared shared interfaces.
            Compiler gate (run by the workflow): ${GeneratedCModuleValidation.command(request.profile, target).joinToString(" ")}
            Compiler warnings are errors. A completed agent turn is accepted only after policy and compiler validation.
            Full-project build and behavioral validation remain separate release gates.
        """.trimIndent()
        val objective = """
            Reconstruct exactly one C implementation unit at $target.
            Preserve recovered behavior and suspicious operations. Do not invent file paths or edit headers.
            Edit $target in the authorized workspace and keep provenance comments containing every owned entity ID:
            ${provenanceIds.joinToString(", ")}
            Do not use generic return-value placeholders or undefined decompiler types. If evidence is insufficient,
            stop without claiming completion so the module is recorded as explicitly unresolved.
        """.trimIndent() + "\n\n" + acceptance
        val files = linkedMapOf(
            request.profile.layout.declaration("shared-interface").materialize() to request.sharedHeader,
            request.module.headerPath to request.moduleHeader,
            request.profile.layout.declaration("module-private-interface")
                .materialize(mapOf("module" to request.module.id)) to request.privateHeader,
        )
            .apply { putAll(request.dependencyHeaders) }
        val observed = request.observedBehavior ?: "<not yet available; report this limitation>"
        val promptEvidence = buildString {
            append(objective).append("\n\n").append(evidence).append("\n\n").append(observed)
            files.toSortedMap().forEach { (path, content) ->
                append("\n\n--- ").append(path).append(" ---\n").append(content)
            }
        }
        val contextSize = promptEvidence.length
        if (contextSize > maximumContextCharacters) {
            throw ModuleContextBudgetExceededException(
                request.module.id,
                contextSize,
                maximumContextCharacters,
                sha256(promptEvidence.toByteArray()),
            )
        }
        val promptSha256 = sha256(promptEvidence.toByteArray())
        val workspaceRoot = request.workspaceRoot.toAbsolutePath().normalize()
        val root = AgentWorkspaceRoot("project", workspaceRoot)
        val readRules = files.keys.map { path ->
            AgentPathRule(AgentWorkspacePath(root.id, path), setOf(AgentOperation.READ_FILE))
        }
        val targetPath = AgentWorkspacePath(root.id, target)
        val sourcePath = targetPath.resolve(listOf(root))
        val before = sourcePath.takeIf { it.exists() }?.readBytes()
        var invocationEvidence: ReconstructionAgentExecutionEvidence? = null
        try {
            val agentRequest = AgentExecutionRequest(
                objective = objective,
                workspaceRoots = listOf(root),
                contextInputs = listOf(
                    AgentContextInput("recovered-module-evidence", evidence),
                    AgentContextInput("observed-behavior", observed),
                ),
                accessPolicy = AgentAccessPolicy(
                    readRules + AgentPathRule(
                        targetPath,
                        setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE, AgentOperation.CREATE_FILE),
                    ),
                ),
                sessionContinuation = sessionContinuation(request),
            )
            val eventRecorder = BoundedAgentExecutionEventRecorder()
            val taskProgress = progress.beginTask(request.module.id, agentRequest)
            val receipt = harness.executeReceipt(agentRequest) { event ->
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
            val execution = receipt.requireResult()
            if (execution.stopReason in setOf(AgentStopReason.CANCELLED, AgentStopReason.LIMIT_EXHAUSTED)) {
                throw ModuleReconstructionInterruptedException(
                    request.module.id,
                    execution.stopReason,
                    execution.summary,
                    invocationEvidence,
                    promptSha256,
                    contextSize,
                    maximumContextCharacters,
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
                promptBudgetCharacters = maximumContextCharacters,
                agentExecutionEvidence = invocationEvidence,
            )
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
                promptBudgetCharacters = maximumContextCharacters,
                cause = failure,
            )
        }
    }
}

private const val MAXIMUM_HARNESS_PROVENANCE_BYTES = 4 * 1024

class ModuleContextBudgetExceededException(
    val moduleId: String,
    val promptCharacters: Int,
    val promptBudgetCharacters: Int,
    val promptSha256: String,
) : IllegalArgumentException(
    "module $moduleId exceeds context budget: $promptCharacters > $promptBudgetCharacters characters",
)

class ModuleReconstructionInterruptedException(
    val moduleId: String,
    val stopReason: AgentStopReason,
    val agentSummary: String?,
    internal val agentExecutionEvidence: ReconstructionAgentExecutionEvidence? = null,
    internal val promptSha256: String? = null,
    internal val promptCharacters: Int? = null,
    internal val promptBudgetCharacters: Int? = null,
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

    fun generate(
        model: RecoveredProgramModel,
        projectDir: Path,
        planner: DeterministicModulePlanner = DeterministicModulePlanner(),
        reconstructor: ModuleReconstructor = EvidenceModuleReconstructor(),
        overrides: Map<String, String> = emptyMap(),
        observedBehavior: String? = null,
        profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
        progress: AgentWorkflowProgress = AgentWorkflowProgress.NONE,
        onModuleProgress: (completed: Int, total: Int, moduleId: String) -> Unit = { _, _, _ -> },
    ): SourceTreeManifest {
        val plan = planner.plan(model, overrides)
        val rendering = GeneratedCProjectRendering(model, plan)
        val typesHeader = rendering.renderTypesHeader()
        val typesHeaderPath = profile.layout.declaration("shared-interface").materialize()
        val typesHeaderFile = projectDir.resolve(typesHeaderPath)
        typesHeaderFile.parent.createDirectories()
        typesHeaderFile.writeText(typesHeader)
        val headers = plan.modules.associate { module -> module.id to rendering.renderModuleHeader(module) }
        val moduleById = plan.modules.associateBy { it.id }
        val functionById = model.functions.associateBy { it.id }
        val functionOwners = plan.modules.flatMap { module -> module.functionIds.map { it to module.id } }.toMap()
        val globalOwners = plan.modules.flatMap { module -> module.globalIds.map { it to module.id } }.toMap()
        val dependenciesByModule = plan.modules.associate { module -> module.id to
            module.functionIds.flatMap { id ->
                val function = functionById.getValue(id)
                function.calls.mapNotNull(functionOwners::get) + function.referencedGlobals.mapNotNull(globalOwners::get)
            }.filter { it != module.id }.distinct().sorted()
        }
        val headerHashes = headers.mapValues { sha256(it.value.toByteArray()) }
        val interfaceFingerprints = moduleInterfaceFingerprints(dependenciesByModule, headerHashes)
        val privateHeaders = plan.modules.associate { module -> module.id to rendering.renderPrivateHeader(module) }
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

        moduleDependencyOrder(dependenciesByModule).map(moduleById::getValue).forEachIndexed { index, module ->
            val dependencies = dependenciesByModule.getValue(module.id)
            val dependencyHeaders = dependencies.associate { dependency -> moduleById.getValue(dependency).headerPath to headers.getValue(dependency) }
            val localFingerprint = moduleFingerprint(
                module,
                model,
                typesHeader,
                headers.getValue(module.id),
                privateHeaders.getValue(module.id),
                dependencyHeaders,
                observedBehavior,
                profile.sha256,
            )
            val fingerprint = sha256(("transitive-interfaces-v2\n" + localFingerprint + "\n" +
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
            fun ModuleCheckpoint.hasCurrentModuleAcceptance(): Boolean =
                schemaVersion == 6 && inputBinarySha256 == model.inputSha256 &&
                    modelSchemaVersion == model.schemaVersion && profileSha256 == profile.sha256 &&
                    accepted && issues.isEmpty() &&
                    entityIds.size == entityIds.toSet().size &&
                    entityIds.toSet() == (module.functionIds + module.globalIds).toSet() &&
                    compilation?.passed == true &&
                    compilation.command == GeneratedCModuleValidation.command(profile, module.sourcePath)
            val verifiedPreviousAcceptance = recordedCheckpoint?.takeIf {
                it.hasCurrentModuleAcceptance() && sourcePath.exists() && sha256(sourcePath.readBytes()) == it.sourceSha256 &&
                    it.hasCurrentExecutionEvidence(projectDir, configuredExecutionEvidencePath, false)
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
                persistAgentExecutionEvidence = { evidence -> persistExecutionEvidence(evidence) },
                profile = profile,
                sessionEvidenceFingerprint = fingerprint,
                acceptedSourceSha256 = verifiedPreviousAcceptance?.sourceSha256,
            )
            val cacheIdentity = reconstructor.cacheIdentity()
            val cached = recordedCheckpoint?.takeIf { checkpoint ->
                checkpoint.schemaVersion == 6 && checkpoint.inputBinarySha256 == model.inputSha256 &&
                    checkpoint.modelSchemaVersion == model.schemaVersion && checkpoint.profileSha256 == profile.sha256 &&
                    checkpoint.fingerprint == fingerprint &&
                    sourcePath.exists() &&
                    sha256(sourcePath.readBytes()) == checkpoint.sourceSha256 &&
                    checkpoint.reconstructorIdentity == cacheIdentity &&
                    checkpoint.hasCurrentExecutionEvidence(
                        projectDir = projectDir,
                        configuredEvidencePath = configuredExecutionEvidencePath,
                        evidenceRequired = reconstructor.requiresExecutionEvidenceForCheckpointReuse(),
                    ) &&
                    (if (checkpoint.accepted) checkpoint.hasCurrentModuleAcceptance() else !checkpoint.retryable)
            }
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
                val attempted = try {
                    reconstructor.reconstruct(request)
                } catch (interrupted: ModuleReconstructionInterruptedException) {
                    interrupted.agentExecutionEvidence?.let(::persistExecutionEvidence)
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
                    )
                    throw interrupted
                } catch (failure: ModuleReconstructionEvidencePersistenceException) {
                    restoreAcceptedRevision()
                    throw failure
                } catch (failure: Exception) {
                    if (generateSequence<Throwable>(failure) { it.cause }.any { it is AgentSessionRecoveryException }) throw failure
                    unresolvedFallback(request, cacheIdentity, failure)
                }
                val normalizedSource = attempted.source.trimEnd() + "\n"
                val executionEvidence = attempted.agentExecutionEvidence?.let(::persistExecutionEvidence)
                    ?: persistedExecutionEvidence
                progress.phase(AgentWorkflowPhase.POLICY_CHECKING, module.id)
                val issues = assessReconstruction(module, model, attempted, normalizedSource).toMutableList()
                writeAtomically(sourcePath, normalizedSource)
                val compilation = if (issues.isEmpty()) {
                    progress.phase(AgentWorkflowPhase.BUILD_VALIDATING, module.id)
                    val validation = try {
                        GeneratedCModuleValidation.validate(projectDir, module.sourcePath, profile)
                    } catch (failure: Exception) {
                        if (failure !is InterruptedException && !Thread.currentThread().isInterrupted) throw failure
                        // Restore durable state before reinstating cancellation, since file
                        // operations may otherwise abort immediately on the interrupted thread.
                        Thread.interrupted()
                        val interrupted = ModuleReconstructionInterruptedException(
                            module.id, AgentStopReason.CANCELLED, "module compiler validation interrupted",
                            attempted.agentExecutionEvidence, attempted.promptSha256,
                            attempted.promptCharacters, attempted.promptBudgetCharacters,
                        ).also { it.initCause(failure) }
                        try {
                            val retainedEvidence = restoreAcceptedRevision()
                            writeInterruptionReport(attemptPath, module, fingerprint, cacheIdentity,
                                sourcePath, recordedCheckpoint, interrupted, retainedEvidence)
                        } finally {
                            Thread.currentThread().interrupt()
                        }
                        throw interrupted
                    }
                    validation.also { validation ->
                        if (!validation.passed) issues += ModuleReconstructionIssue(
                            "module-compilation-${validation.outcome}",
                            "module compiler gate ${validation.outcome}; diagnostics SHA-256=${validation.diagnosticsSha256}",
                            module.functionIds + module.globalIds,
                        )
                    }
                } else null
                val accepted = issues.isEmpty()
                val normalizedSourceSha256 = sha256(normalizedSource.toByteArray())
                val candidateCheckpoint = ModuleCheckpoint(
                    inputBinarySha256 = model.inputSha256,
                    modelSchemaVersion = model.schemaVersion,
                    profileSha256 = profile.sha256,
                    fingerprint = fingerprint,
                    sourceSha256 = normalizedSourceSha256,
                    generator = attempted.generator,
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
                    reconstructor.reconcileSessionCheckpoint(
                        request, false, previousAccepted.sourceSha256,
                        executionEvidence?.requestSha256, executionEvidence?.sha256,
                    )
                    throw ModuleReconstructionRevisionRejectedException(module.id, issues)
                }
                if (executionEvidence == null) configuredExecutionEvidenceFile?.deleteIfExists()
                candidateCheckpoint.also { writeAtomically(checkpointPath, it.toJson()) }
            }
            require(
                checkpoint.executionEvidencePath == null ||
                    checkpoint.executionEvidencePath == configuredExecutionEvidencePath
            ) { "module checkpoint execution evidence path differs from the reconstruction profile" }
            if (checkpoint.executionEvidencePath == null) configuredExecutionEvidenceFile?.deleteIfExists()
            attemptPath.deleteIfExists()
            projectDir.resolve("reports/modules/${module.id}.attempt.execution.json").deleteIfExists()
            reconstructor.reconcileSessionCheckpoint(
                request, checkpoint.accepted, checkpoint.sourceSha256,
                checkpoint.executionRequestSha256, checkpoint.executionEvidenceSha256,
            )
            val normalizedSource = sourcePath.readText()
            val moduleEntityIds = module.functionIds + module.globalIds
            if (!checkpoint.accepted) unresolvedImplementations += moduleEntityIds
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
                append("\"inputFingerprintProvider\":\"").append(INPUT_FINGERPRINT_PROVIDER).append("\",")
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

        rendering.renderEntrypoint()?.let { entrypoint ->
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
        val makefile = rendering.renderMakefile(sourcePaths, profile)
        val makefilePath = profile.layout.declaration("build-definition").materialize()
        val makefileFile = projectDir.resolve(makefilePath)
        makefileFile.parent.createDirectories()
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
        val confidence = renderConfidence(model, plan, unresolvedImplementations, moduleRevisionEvidence)
        projectDir.resolve(confidencePath).also { it.parent.createDirectories() }.writeText(confidence)
        generated += evidence(profile, confidencePath, confidence, "evidence", model.functions.map { it.id } + model.globals.map { it.id })
        val toolchain = GeneratedCToolchainEvidence.render(profile)
        projectDir.resolve(toolchainPath).also { it.parent.createDirectories() }.writeText(toolchain)
        generated += evidence(profile, toolchainPath, toolchain, "environment", emptyList())
        val unresolvedMarkdown = renderUnresolvedMarkdown(model, plan, unresolvedImplementations)
        projectDir.resolve(unresolvedPath).also { it.parent.createDirectories() }.writeText(unresolvedMarkdown)
        generated += evidence(profile, unresolvedPath, unresolvedMarkdown, "evidence", unresolvedImplementations.toList())
        val manifest = SourceTreeManifest(
            profileId = profile.id,
            profileSha256 = profile.sha256,
            inputSha256 = model.inputSha256,
            files = generated,
            unresolvedEntityIds = model.functions.filter { model.isRecoveryUnresolved(it.status) }.map { it.id } +
                model.globals.filter { model.isRecoveryUnresolved(it.status) }.map { it.id } +
                model.types.filter { model.isRecoveryUnresolved(it.status) }.map { it.id },
            unresolvedImplementationIds = unresolvedImplementations.toList(),
        )
        projectDir.resolve("source_tree_manifest.json").writeText(manifest.toJson())
        return manifest
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
    ) {
        init {
            require(schemaVersion < 6 || (inputBinarySha256 != null && modelSchemaVersion in setOf(1, 2) &&
                profileSha256?.matches(Regex("[0-9a-f]{64}")) == true)) { "module checkpoint lacks input identity" }
            require(schemaVersion in 2..6) { "unsupported module checkpoint schemaVersion: $schemaVersion" }
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
        ): Boolean {
            val checkpointClaimsAgentExecution =
                generator.startsWith("agent:") || reconstructorIdentity.startsWith("agent:")
            val evidencePath = executionEvidencePath
                ?: return !evidenceRequired && !checkpointClaimsAgentExecution

            // Compare the untrusted checkpoint value with the profile-owned path before resolving,
            // opening, sizing, or reading anything named by the checkpoint.
            if (configuredEvidencePath == null || evidencePath != configuredEvidencePath) return false
            val expectedDigest = requireNotNull(executionEvidenceSha256)
            if (schemaVersion >= 4 && accepted && executionReleaseComplete != true) return false
            return boundedCheckpointExecutionEvidenceSha256(projectDir, evidencePath) == expectedDigest
        }

        fun toJson(): String = buildString {
            append("{\n  \"schemaVersion\": ").append(schemaVersion).append(',')
            append("\n  \"fingerprint\": \"").append(fingerprint).append("\",")
            append("\n  \"sourceSha256\": \"").append(sourceSha256).append("\",")
            append("\n  \"generator\": \"").append(generator.jsonEscape()).append("\",")
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
            val root = Json.parseToJsonElement(path.readText()).jsonObject
            val schemaVersion = root["schemaVersion"]?.jsonPrimitive?.intOrNull ?: return null
            if (schemaVersion !in setOf(2, 3, 4, 5, 6)) return null
            if (schemaVersion >= 6) {
                require(root.getValue("schemaVersion") == kotlinx.serialization.json.JsonPrimitive(6))
                require(root.getValue("inputBinarySha256").jsonPrimitive.isString)
                require(root.getValue("profileSha256").jsonPrimitive.isString)
                require(!root.getValue("modelSchemaVersion").jsonPrimitive.isString)
            }
            fun optionalString(name: String): String? = root[name]?.let { value ->
                if (value is JsonNull) null else value.jsonPrimitive.content
            }
            ModuleCheckpoint(
                schemaVersion = schemaVersion,
                inputBinarySha256 = if (schemaVersion >= 6) optionalString("inputBinarySha256") else null,
                modelSchemaVersion = if (schemaVersion >= 6) root["modelSchemaVersion"]?.jsonPrimitive?.intOrNull else null,
                profileSha256 = if (schemaVersion >= 6) optionalString("profileSha256") else null,
                fingerprint = root.getValue("fingerprint").jsonPrimitive.content,
                sourceSha256 = root.getValue("sourceSha256").jsonPrimitive.content,
                generator = root.getValue("generator").jsonPrimitive.content,
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
    ) {
        val currentSourceSha256 = sourcePath.takeIf { it.exists() }?.readBytes()?.let(::sha256)
        val report = buildString {
            append("{\n  \"schemaVersion\": 2,")
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
        val fallback = EvidenceModuleReconstructor().reconstruct(request)
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
        module: PlannedModule,
        model: RecoveredProgramModel,
        reconstructed: ReconstructedModule,
        source: String,
    ): List<ModuleReconstructionIssue> {
        val entityIds = module.functionIds + module.globalIds
        val issues = reconstructed.issues.toMutableList()
        if (source.isBlank() && entityIds.isNotEmpty()) {
            issues += ModuleReconstructionIssue("empty-source", "module source is empty", entityIds)
        }
        if (reconstructed.generator.startsWith("agent:")) {
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
            val promptCharacters = reconstructed.promptCharacters
            val promptBudget = reconstructed.promptBudgetCharacters
            when {
                promptCharacters == null || promptBudget == null -> issues += ModuleReconstructionIssue(
                    "prompt-budget-unattributed",
                    "agent result does not record prompt size and configured budget",
                    entityIds,
                )
                promptCharacters > promptBudget -> issues += ModuleReconstructionIssue(
                    "context-budget-exceeded",
                    "agent prompt used $promptCharacters characters with a $promptBudget character budget",
                    entityIds,
                )
            }
        }
        issues += GeneratedCCandidateValidation.assess(module, model, reconstructed.generator, source)
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

    private fun moduleFingerprint(
        module: PlannedModule,
        model: RecoveredProgramModel,
        sharedHeader: String,
        moduleHeader: String,
        privateHeader: String,
        dependencyHeaders: Map<String, String>,
        observedBehavior: String?,
        profileSha256: String,
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
            "compilerPolicy" to kotlinx.serialization.json.JsonPrimitive(GeneratedCModuleValidation.POLICY_ID),
        ))
        return sha256(inputs.toString().toByteArray(Charsets.UTF_8))
    }

    private fun renderConfidence(
        model: RecoveredProgramModel,
        plan: ModulePlan,
        unresolvedImplementations: Set<String>,
        moduleRevisionEvidence: Map<String, String>,
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
        val unresolvedRecovery = model.functions.filter { model.isRecoveryUnresolved(it.status) }.map { it.id } +
            model.globals.filter { model.isRecoveryUnresolved(it.status) }.map { it.id } +
            model.types.filter { model.isRecoveryUnresolved(it.status) }.map { it.id }
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
            append("\n}\n")
        }
    }

    private fun renderUnresolvedMarkdown(
        model: RecoveredProgramModel,
        plan: ModulePlan,
        unresolvedImplementationIds: Set<String>,
    ): String {
        val rows = buildList {
            model.functions.filter { model.isRecoveryUnresolved(it.status) }.forEach { add("function" to Triple(it.id, it.status, "0x${it.address.toString(16)}")) }
            model.globals.filter { model.isRecoveryUnresolved(it.status) }.forEach { add("global" to Triple(it.id, it.status, "0x${it.address.toString(16)}")) }
            model.types.filter { model.isRecoveryUnresolved(it.status) }.forEach { add("type" to Triple(it.id, it.status, it.sourceAddress?.let { address -> "0x${address.toString(16)}" } ?: "no address")) }
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
                    val assessment = if (model.schemaVersion == 2) "unassessed (extraction: $status)" else status
                    append("| $kind | `${details.first}` | $assessment | ${details.third} |\n")
                }
            }
            append("\n## Implementation generation\n\n")
            if (unresolvedImplementationIds.isEmpty()) {
                append("Every planner-owned implementation passed the acceptance checks.\n")
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
        return parse(path.readText(), expectedProfile)
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
