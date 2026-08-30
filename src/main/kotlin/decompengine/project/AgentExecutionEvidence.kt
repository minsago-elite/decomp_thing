package decompengine.project

import decompengine.acp.ACP_CLIENT_IMPLEMENTATION_NAME
import decompengine.acp.ACP_CLIENT_IMPLEMENTATION_VERSION
import decompengine.acp.AcpCgroupControllerEvidence
import decompengine.acp.AcpExecutionEvidenceSnapshot
import decompengine.acp.AcpFilesystemAuditRecord
import decompengine.acp.AcpPermissionAuditRecord
import decompengine.acp.AcpSandboxEvidence
import decompengine.acp.AcpSandboxLaunchEvidence
import decompengine.acp.AcpSandboxMountEvidence
import decompengine.acp.AcpSandboxResourceLimits
import decompengine.acp.AcpTerminalAuditRecord
import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeEvent
import decompengine.agent.AgentMessageEvent
import decompengine.agent.AgentPermissionEvent
import decompengine.agent.AgentPlanEvent
import decompengine.agent.AgentToolEvent
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Collections

/** Caller-owned validation binding appended only after the generated artifact is inspected. */
internal class AcpExecutionOutcomeBinding(
    val evidenceKind: String,
    val taskIdentityField: String,
    val taskId: String,
    val accepted: Boolean,
    val artifactDigestField: String,
    val artifactSha256: String,
    issues: Collection<AcpExecutionOutcomeIssue> = emptyList(),
) {
    val issues: List<AcpExecutionOutcomeIssue> =
        Collections.unmodifiableList(ArrayList(issues.sortedWith(compareBy(
            AcpExecutionOutcomeIssue::code,
            AcpExecutionOutcomeIssue::message,
        ))))

    init {
        require(evidenceKind.matches(Regex("[a-z0-9][a-z0-9.-]{0,127}"))) {
            "ACP execution evidence kind is invalid"
        }
        require(taskIdentityField.matches(Regex("[A-Za-z][A-Za-z0-9]{0,63}"))) {
            "ACP execution task identity field is invalid"
        }
        require(taskId.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"))) {
            "ACP execution task identity is invalid"
        }
        require(artifactDigestField.matches(Regex("[A-Za-z][A-Za-z0-9]{0,63}"))) {
            "ACP execution artifact digest field is invalid"
        }
        require(artifactSha256.isSha256()) { "ACP execution artifact digest is invalid" }
        require(this.issues.size <= MAXIMUM_ARCHIVED_OUTCOME_ISSUES) {
            "ACP execution outcome exceeds the issue-count limit"
        }
    }
}

internal class AcpExecutionOutcomeIssue(
    val code: String,
    val message: String,
    entityIds: Collection<String> = emptyList(),
) {
    val entityIds: List<String> = Collections.unmodifiableList(ArrayList(entityIds.sorted()))

    init {
        require(code.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"))) {
            "ACP execution outcome issue code is invalid"
        }
        require(message.isNotBlank()) { "ACP execution outcome issue message must not be blank" }
        require(utf8Bytes(message) <= MAXIMUM_ARCHIVED_OUTCOME_MESSAGE_BYTES) {
            "ACP execution outcome issue message exceeds the byte limit"
        }
        require(this.entityIds.size <= MAXIMUM_ARCHIVED_OUTCOME_ENTITY_IDS) {
            "ACP execution outcome issue exceeds the entity-count limit"
        }
        require(this.entityIds == this.entityIds.distinct()) {
            "ACP execution outcome entity IDs must be unique"
        }
        require(this.entityIds.all { it.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")) }) {
            "ACP execution outcome entity ID is invalid"
        }
    }
}

/**
 * Immutable, workflow-neutral ACP evidence retained until a caller binds deterministic validation
 * to the same generated artifact. Peer-authored text and opaque IDs are represented by digests.
 */
internal class BoundedAcpExecutionArtifact private constructor(
    private val request: ArchivedAgentRequest,
    private val result: AgentExecutionResult,
    events: Collection<ArchivedAgentEvent>,
    private val acp: AcpExecutionEvidenceSnapshot,
) {
    private val events: List<ArchivedAgentEvent> =
        Collections.unmodifiableList(ArrayList(events.sortedBy(ArchivedAgentEvent::sequence)))

    init {
        require(this.events.size <= MAXIMUM_ARCHIVED_AGENT_EVENTS) {
            "ACP event evidence exceeds the $MAXIMUM_ARCHIVED_AGENT_EVENTS-record limit"
        }
        require(this.events.map(ArchivedAgentEvent::sequence) == this.events.indices.map(Int::toLong)) {
            "ACP event evidence is missing or reorders an event sequence"
        }
        val session = requireNotNull(result.session) {
            "successful ACP reconstruction is missing its session reference"
        }
        require(session.harnessId == acp.factoryProvenance.implementationId) {
            "ACP session and factory implementation identities differ"
        }
        val eventChanges = this.events.filterIsInstance<ArchivedFileChangeEvent>().map { it.change }
        require(eventChanges == result.changes) {
            "ACP event evidence does not contain the complete execution change set"
        }
        require(request.maximumInputTokens == null || result.usage?.inputTokens != null) {
            "ACP execution evidence is missing input-token usage required by its ceiling"
        }
        require(request.maximumOutputTokens == null || result.usage?.outputTokens != null) {
            "ACP execution evidence is missing output-token usage required by its ceiling"
        }
    }

    fun toValidatedJson(binding: AcpExecutionOutcomeBinding): String {
        val text = buildString {
            append("{\n  \"schemaVersion\": 1,")
            append("\n  \"kind\": ").append(binding.evidenceKind.jsonString()).append(',')
            append("\n  ").append(binding.taskIdentityField.jsonString())
                .append(": ").append(binding.taskId.jsonString()).append(',')
            appendFactoryProvenance(acp)
            appendProtocolAndAgent(acp)
            appendSessionAndTurn(request, result)
            appendBounds(request, events)
            appendEvents(events)
            appendResult(result)
            appendPolicyAudits(acp)
            appendProcessDiagnostics(acp)
            appendSandboxEvidence(acp.sandboxEvidence)
            appendValidation(binding)
            append("\n}\n")
        }
        require(text.toByteArray(StandardCharsets.UTF_8).size <= MAXIMUM_ARCHIVED_EVIDENCE_BYTES) {
            "ACP execution evidence exceeds the $MAXIMUM_ARCHIVED_EVIDENCE_BYTES-byte artifact limit"
        }
        return text
    }

    companion object {
        fun capture(
            request: AgentExecutionRequest,
            promptSha256: String,
            result: AgentExecutionResult,
            events: Collection<ArchivedAgentEvent>,
            acp: AcpExecutionEvidenceSnapshot,
        ): BoundedAcpExecutionArtifact = BoundedAcpExecutionArtifact(
            ArchivedAgentRequest(
                requestSha256 = digestAgentRequest(request),
                objectiveSha256 = digest(request.objective),
                objectiveUtf8Bytes = utf8Bytes(request.objective),
                promptSha256 = promptSha256,
                wirePromptSha256 = digest(renderAcpWirePrompt(request)),
                workspaceRootsSha256 = digestWorkspaceRoots(request),
                contextInputsSha256 = digestContextInputs(request),
                accessPolicySha256 = digestAgentAccessPolicy(request),
                workspaceRootIds = request.workspaceRoots.map { it.id },
                contextInputIds = request.contextInputs.map { it.id },
                filesystemEnabled = request.accessPolicy.allowedOperations.any { it.name.endsWith("FILE") },
                terminalEnabled = request.accessPolicy.allowedOperations.any { it.name == "EXECUTE_COMMAND" },
                maximumTurns = request.limits.maxTurns,
                maximumToolCalls = request.limits.maxToolCalls,
                maximumOutputBytes = request.limits.maxOutputBytes,
                wallClockTimeoutMillis = request.limits.wallClockTimeout.toMillis(),
                idleTimeoutMillis = request.limits.idleTimeout.toMillis(),
                maximumInputTokens = request.limits.maxInputTokens,
                maximumOutputTokens = request.limits.maxOutputTokens,
            ),
            result,
            events,
            acp,
        )
    }
}

/** Reconstruction-specific adapter preserving the versioned module evidence JSON contract. */
class ReconstructionAgentExecutionEvidence private constructor(
    private val artifact: BoundedAcpExecutionArtifact,
) {
    internal fun toValidatedJson(
        moduleId: String,
        sourceSha256: String,
        accepted: Boolean,
        issues: Collection<ModuleReconstructionIssue>,
    ): String = artifact.toValidatedJson(
        AcpExecutionOutcomeBinding(
            evidenceKind = "decomp-engine.reconstruction-acp-execution",
            taskIdentityField = "moduleId",
            taskId = moduleId,
            accepted = accepted,
            artifactDigestField = "sourceSha256",
            artifactSha256 = sourceSha256,
            issues = issues.map { issue ->
                AcpExecutionOutcomeIssue(issue.code, issue.message, issue.entityIds)
            },
        ),
    )

    internal companion object {
        fun capture(
            request: AgentExecutionRequest,
            promptSha256: String,
            result: AgentExecutionResult,
            events: Collection<ArchivedAgentEvent>,
            acp: AcpExecutionEvidenceSnapshot,
        ): ReconstructionAgentExecutionEvidence = ReconstructionAgentExecutionEvidence(
            BoundedAcpExecutionArtifact.capture(request, promptSha256, result, events, acp),
        )
    }
}

/** Captures every public execution event without retaining peer-authored text. */
internal class BoundedAgentExecutionEventRecorder(
    private val maximumEvents: Int = MAXIMUM_ARCHIVED_AGENT_EVENTS,
    private val maximumComponents: Int = MAXIMUM_ARCHIVED_EVENT_COMPONENTS,
    private val maximumPeerBytes: Long = MAXIMUM_ARCHIVED_EVENT_PEER_BYTES,
) {
    private val events = mutableListOf<ArchivedAgentEvent>()
    private var components = 0
    private var peerBytes = 0L

    init {
        require(maximumEvents > 0 && maximumComponents > 0 && maximumPeerBytes > 0) {
            "agent event evidence bounds must be positive"
        }
    }

    @Synchronized
    fun record(event: AgentExecutionEvent) {
        require(events.size < maximumEvents) {
            "agent event evidence exceeds the $maximumEvents-record limit"
        }
        val archived = when (event) {
            is AgentMessageEvent -> {
                consume(1, event.messageId, event.textDelta)
                ArchivedMessageEvent(
                    event.sequence,
                    event.role.name.wireName(),
                    digest(event.messageId),
                    digest(event.textDelta),
                    utf8Bytes(event.textDelta),
                    event.completed,
                )
            }
            is AgentPlanEvent -> {
                consume(event.entries.size, *event.entries.flatMap { listOf(it.id, it.description) }.toTypedArray())
                ArchivedPlanEvent(
                    event.sequence,
                    event.entries.map { entry ->
                        ArchivedPlanEntry(
                            digest(entry.id),
                            digest(entry.description),
                            utf8Bytes(entry.description),
                            entry.status.name.wireName(),
                        )
                    },
                )
            }
            is AgentToolEvent -> {
                consume(1 + event.details.size, event.toolCallId, event.title, *event.details.flatMap {
                    listOf(it.key, it.value)
                }.toTypedArray())
                ArchivedToolEvent(
                    event.sequence,
                    digest(event.toolCallId),
                    digest(event.title),
                    event.status.name.wireName(),
                    digestCanonicalMap(event.details),
                    event.details.size,
                )
            }
            is AgentPermissionEvent -> {
                consume(1, event.requestId, event.selectedOptionId.orEmpty(), event.reason.orEmpty())
                ArchivedPermissionEvent(
                    event.sequence,
                    digest(event.requestId),
                    event.decision.name.wireName(),
                    event.selectedOptionId?.let(::digest),
                    event.reason?.let(::digest),
                )
            }
            is AgentFileChangeEvent -> {
                consume(1, event.change.path.rootId, event.change.path.relativePath)
                ArchivedFileChangeEvent(event.sequence, event.change)
            }
        }
        require(events.lastOrNull()?.sequence?.let { event.sequence > it } != false) {
            "agent execution event sequences must be strictly increasing"
        }
        events += archived
    }

    @Synchronized
    fun snapshot(): List<ArchivedAgentEvent> = Collections.unmodifiableList(ArrayList(events))

    private fun consume(componentCount: Int, vararg values: String) {
        components = Math.addExact(components, componentCount)
        require(components <= maximumComponents) {
            "agent event evidence exceeds the $maximumComponents-component limit"
        }
        values.forEach { value ->
            peerBytes = Math.addExact(peerBytes, utf8Bytes(value).toLong())
            require(peerBytes <= maximumPeerBytes) {
                "agent event evidence exceeds the $maximumPeerBytes-byte peer-input limit"
            }
        }
    }
}

internal sealed interface ArchivedAgentEvent {
    val sequence: Long
    fun appendJson(output: StringBuilder)
}

private data class ArchivedMessageEvent(
    override val sequence: Long,
    val role: String,
    val messageIdSha256: String,
    val textSha256: String,
    val textUtf8Bytes: Int,
    val completed: Boolean,
) : ArchivedAgentEvent {
    override fun appendJson(output: StringBuilder) {
        output.append("{\"sequence\":").append(sequence)
        output.append(",\"type\":\"message\",\"role\":").append(role.jsonString())
        output.append(",\"messageIdSha256\":\"").append(messageIdSha256).append('"')
        output.append(",\"textSha256\":\"").append(textSha256).append('"')
        output.append(",\"textUtf8Bytes\":").append(textUtf8Bytes)
        output.append(",\"completed\":").append(completed).append('}')
    }
}

private data class ArchivedPlanEntry(
    val idSha256: String,
    val descriptionSha256: String,
    val descriptionUtf8Bytes: Int,
    val status: String,
)

private data class ArchivedPlanEvent(
    override val sequence: Long,
    val entries: List<ArchivedPlanEntry>,
) : ArchivedAgentEvent {
    override fun appendJson(output: StringBuilder) {
        output.append("{\"sequence\":").append(sequence).append(",\"type\":\"plan\",\"entries\":[")
        entries.forEachIndexed { index, entry ->
            if (index > 0) output.append(',')
            output.append("{\"idSha256\":\"").append(entry.idSha256)
            output.append("\",\"descriptionSha256\":\"").append(entry.descriptionSha256)
            output.append("\",\"descriptionUtf8Bytes\":").append(entry.descriptionUtf8Bytes)
            output.append(",\"status\":").append(entry.status.jsonString()).append('}')
        }
        output.append("]}")
    }
}

private data class ArchivedToolEvent(
    override val sequence: Long,
    val toolCallIdSha256: String,
    val titleSha256: String,
    val status: String,
    val detailsSha256: String,
    val detailCount: Int,
) : ArchivedAgentEvent {
    override fun appendJson(output: StringBuilder) {
        output.append("{\"sequence\":").append(sequence).append(",\"type\":\"tool\"")
        output.append(",\"toolCallIdSha256\":\"").append(toolCallIdSha256)
        output.append("\",\"titleSha256\":\"").append(titleSha256)
        output.append("\",\"status\":").append(status.jsonString())
        output.append(",\"detailsSha256\":\"").append(detailsSha256)
        output.append("\",\"detailCount\":").append(detailCount).append('}')
    }
}

private data class ArchivedPermissionEvent(
    override val sequence: Long,
    val requestIdSha256: String,
    val decision: String,
    val selectedOptionIdSha256: String?,
    val reasonSha256: String?,
) : ArchivedAgentEvent {
    override fun appendJson(output: StringBuilder) {
        output.append("{\"sequence\":").append(sequence).append(",\"type\":\"permission\"")
        output.append(",\"requestIdSha256\":\"").append(requestIdSha256)
        output.append("\",\"decision\":").append(decision.jsonString())
        output.append(",\"selectedOptionIdSha256\":").append(selectedOptionIdSha256.jsonNullable())
        output.append(",\"reasonSha256\":").append(reasonSha256.jsonNullable()).append('}')
    }
}

private data class ArchivedFileChangeEvent(
    override val sequence: Long,
    val change: AgentFileChange,
) : ArchivedAgentEvent {
    override fun appendJson(output: StringBuilder) {
        output.append("{\"sequence\":").append(sequence).append(",\"type\":\"file-change\",\"change\":")
        output.appendFileChange(change).append('}')
    }
}

private data class ArchivedAgentRequest(
    val requestSha256: String,
    val objectiveSha256: String,
    val objectiveUtf8Bytes: Int,
    val promptSha256: String,
    val wirePromptSha256: String,
    val workspaceRootsSha256: String,
    val contextInputsSha256: String,
    val accessPolicySha256: String,
    val workspaceRootIds: List<String>,
    val contextInputIds: List<String>,
    val filesystemEnabled: Boolean,
    val terminalEnabled: Boolean,
    val maximumTurns: Int,
    val maximumToolCalls: Int,
    val maximumOutputBytes: Long,
    val wallClockTimeoutMillis: Long,
    val idleTimeoutMillis: Long,
    val maximumInputTokens: Long?,
    val maximumOutputTokens: Long?,
)

private fun StringBuilder.appendFactoryProvenance(acp: AcpExecutionEvidenceSnapshot) {
    val provenance = acp.factoryProvenance
    append("\n  \"factoryProvenance\": {")
    append("\n    \"descriptor\": ").append(provenance.stableDescriptor.jsonString()).append(',')
    append("\n    \"harness\": ").append(provenance.harness.jsonString()).append(',')
    append("\n    \"implementationId\": ").append(provenance.implementationId.jsonString()).append(',')
    append("\n    \"agentExecutionContractVersion\": ").append(provenance.agentExecutionContractVersion).append(',')
    append("\n    \"configurationSha256\": ").append(provenance.configurationSha256.jsonNullable()).append(',')
    append("\n    \"deprecated\": ").append(provenance.deprecated)
    append("\n  },")
}

private fun StringBuilder.appendProtocolAndAgent(acp: AcpExecutionEvidenceSnapshot) {
    val agent = acp.negotiatedAgent
    val capabilities = agent.capabilities
    append("\n  \"protocol\": {")
    append("\n    \"name\": \"acp\",")
    append("\n    \"version\": ").append(agent.protocolVersion).append(',')
    append("\n    \"sdkVersion\": ").append(acp.factoryProvenance.acpSdkVersion.jsonNullable()).append(',')
    append("\n    \"clientImplementation\": {\"name\":")
        .append(ACP_CLIENT_IMPLEMENTATION_NAME.jsonString())
        .append(",\"version\":").append(ACP_CLIENT_IMPLEMENTATION_VERSION.jsonString()).append("}")
    append("\n  },")
    append("\n  \"agent\": {")
    append("\n    \"configuredImplementationId\": ")
        .append(acp.factoryProvenance.implementationId.jsonString()).append(',')
    append("\n    \"negotiatedImplementation\": {")
    append("\"name\":").append(agent.implementationName.jsonString()).append(',')
    append("\"version\":").append(agent.implementationVersion.jsonString()).append(',')
    append("\"title\":").append(agent.implementationTitle.jsonNullable()).append("},")
    append("\n    \"negotiatedCapabilities\": {")
    append("\"loadSession\":").append(capabilities.loadSession).append(',')
    append("\"promptImage\":").append(capabilities.promptImage).append(',')
    append("\"promptAudio\":").append(capabilities.promptAudio).append(',')
    append("\"promptEmbeddedContext\":").append(capabilities.promptEmbeddedContext).append(',')
    append("\"mcpHttp\":").append(capabilities.mcpHttp).append(',')
    append("\"mcpSse\":").append(capabilities.mcpSse).append(',')
    append("\"sessionAdditionalDirectories\":").append(capabilities.sessionAdditionalDirectories).append("}")
    append("\n  },")
}

private fun StringBuilder.appendSessionAndTurn(request: ArchivedAgentRequest, result: AgentExecutionResult) {
    val session = requireNotNull(result.session)
    append("\n  \"session\": {")
    append("\n    \"harnessId\": ").append(session.harnessId.jsonString()).append(',')
    append("\n    \"sessionIdSha256\": \"").append(digest(session.sessionId)).append("\",")
    append("\n    \"resumeReferenceSha256\": ").append(session.resumeReference?.let(::digest).jsonNullable())
    append("\n  },")
    append("\n  \"turn\": {")
    append("\n    \"ordinal\": 1,")
    append("\n    \"requestSha256\": \"").append(request.requestSha256).append("\",")
    append("\n    \"objectiveSha256\": \"").append(request.objectiveSha256).append("\",")
    append("\n    \"objectiveUtf8Bytes\": ").append(request.objectiveUtf8Bytes).append(',')
    append("\n    \"promptSha256\": \"").append(request.promptSha256).append("\",")
    append("\n    \"wirePromptSha256\": \"").append(request.wirePromptSha256).append("\",")
    append("\n    \"workspaceRootsSha256\": \"").append(request.workspaceRootsSha256).append("\",")
    append("\n    \"contextInputsSha256\": \"").append(request.contextInputsSha256).append("\",")
    append("\n    \"accessPolicySha256\": \"").append(request.accessPolicySha256).append("\"")
    append("\n  },")
}

private fun StringBuilder.appendBounds(request: ArchivedAgentRequest, events: List<ArchivedAgentEvent>) {
    append("\n  \"bounds\": {")
    append("\n    \"maximumArchivedBytes\": ").append(MAXIMUM_ARCHIVED_EVIDENCE_BYTES).append(',')
    append("\n    \"maximumArchivedEvents\": ").append(MAXIMUM_ARCHIVED_AGENT_EVENTS).append(',')
    append("\n    \"archivedEventCount\": ").append(events.size).append(',')
    append("\n    \"maximumTurns\": ").append(request.maximumTurns).append(',')
    append("\n    \"maximumToolCalls\": ").append(request.maximumToolCalls).append(',')
    append("\n    \"maximumOutputBytes\": ").append(request.maximumOutputBytes).append(',')
    append("\n    \"wallClockTimeoutMillis\": ").append(request.wallClockTimeoutMillis).append(',')
    append("\n    \"idleTimeoutMillis\": ").append(request.idleTimeoutMillis).append(',')
    append("\n    \"maximumInputTokens\": ").append(request.maximumInputTokens ?: "null").append(',')
    append("\n    \"maximumOutputTokens\": ").append(request.maximumOutputTokens ?: "null").append(',')
    append("\n    \"workspaceRootIds\": ").appendJsonStrings(request.workspaceRootIds).append(',')
    append("\n    \"contextInputIds\": ").appendJsonStrings(request.contextInputIds).append(',')
    append("\n    \"filesystemCapabilityEnabled\": ").append(request.filesystemEnabled).append(',')
    append("\n    \"terminalCapabilityEnabled\": ").append(request.terminalEnabled)
    append("\n  },")
}

private fun StringBuilder.appendEvents(events: List<ArchivedAgentEvent>) {
    append("\n  \"events\": [")
    events.forEachIndexed { index, event ->
        if (index > 0) append(',')
        append("\n    ")
        event.appendJson(this)
    }
    append("\n  ],")
}

private fun StringBuilder.appendResult(result: AgentExecutionResult) {
    append("\n  \"result\": {")
    append("\n    \"stopReason\": ").append(result.stopReason.name.wireName().jsonString()).append(',')
    append("\n    \"summarySha256\": ").append(result.summary?.let(::digest).jsonNullable()).append(',')
    append("\n    \"summaryUtf8Bytes\": ").append(result.summary?.let(::utf8Bytes) ?: "null").append(',')
    append("\n    \"changes\": [")
    result.changes.forEachIndexed { index, change ->
        if (index > 0) append(',')
        append("\n      ").appendFileChange(change)
    }
    append("\n    ],")
    append("\n    \"usage\": ")
    val usage = result.usage
    if (usage == null) append("null") else {
        append('{')
        append("\"inputTokens\":").append(usage.inputTokens ?: "null").append(',')
        append("\"outputTokens\":").append(usage.outputTokens ?: "null").append(',')
        append("\"cachedInputTokens\":").append(usage.cachedInputTokens ?: "null").append(',')
        append("\"toolCalls\":").append(usage.toolCalls ?: "null").append(',')
        append("\"wallClockMillis\":").append(usage.wallClock?.toMillis() ?: "null").append('}')
    }
    append("\n  },")
}

private fun StringBuilder.appendPolicyAudits(acp: AcpExecutionEvidenceSnapshot) {
    append("\n  \"policyAudits\": {")
    append("\n    \"filesystem\": [")
    acp.filesystemAudit.forEachIndexed { index, record ->
        if (index > 0) append(',')
        append("\n      ").appendFilesystemAudit(record)
    }
    append("\n    ],")
    append("\n    \"terminal\": [")
    acp.terminalAudit.forEachIndexed { index, record ->
        if (index > 0) append(',')
        append("\n      ").appendTerminalAudit(record)
    }
    append("\n    ],")
    append("\n    \"permission\": [")
    acp.permissionAudit.forEachIndexed { index, record ->
        if (index > 0) append(',')
        append("\n      ").appendPermissionAudit(record)
    }
    append("\n    ]")
    append("\n  },")
}

private fun StringBuilder.appendFilesystemAudit(record: AcpFilesystemAuditRecord): StringBuilder {
    append("{\"sequence\":").append(record.sequence)
    append(",\"sessionIdSha256\":\"").append(digest(record.sessionId)).append('"')
    append(",\"method\":").append(record.method.jsonString())
    append(",\"requestedPathSha256\":\"").append(record.requestedPathSha256).append('"')
    append(",\"policyPath\":")
    val path = record.policyPath
    if (path == null) append("null") else {
        append("{\"rootId\":").append(path.rootId.jsonString())
        append(",\"relativePath\":").append(path.relativePath.jsonString()).append('}')
    }
    append(",\"outcome\":").append(record.outcome.name.wireName().jsonString())
    append(",\"reason\":").append(record.reason.name.wireName().jsonString()).append('}')
    return this
}

private fun StringBuilder.appendTerminalAudit(record: AcpTerminalAuditRecord): StringBuilder {
    append("{\"sequence\":").append(record.sequence)
    append(",\"sessionIdSha256\":\"").append(digest(record.sessionId)).append('"')
    append(",\"method\":").append(record.method.jsonString())
    append(",\"requestSha256\":\"").append(record.requestSha256).append('"')
    append(",\"terminalIdSha256\":").append(record.terminalIdSha256.jsonNullable())
    append(",\"toolCallIdSha256\":").append(record.toolCallIdSha256.jsonNullable())
    append(",\"outcome\":").append(record.outcome.name.wireName().jsonString())
    append(",\"reason\":").append(record.reason.name.wireName().jsonString())
    append(",\"networkIsolated\":").append(record.networkIsolated)
    append(",\"retainedOutputBytes\":").append(record.retainedOutputBytes ?: "null")
    append(",\"producedOutputBytes\":").append(record.producedOutputBytes ?: "null")
    append(",\"outputTruncated\":").append(record.outputTruncated ?: "null").append('}')
    return this
}

private fun StringBuilder.appendPermissionAudit(record: AcpPermissionAuditRecord): StringBuilder {
    append("{\"sequence\":").append(record.sequence)
    append(",\"sessionIdSha256\":\"").append(digest(record.sessionId)).append('"')
    append(",\"toolCallIdSha256\":\"").append(record.toolCallIdSha256).append('"')
    append(",\"offeredOptionCount\":").append(record.offeredOptionCount)
    append(",\"selectedOptionIdSha256\":").append(record.selectedOptionIdSha256.jsonNullable())
    append(",\"selectedKind\":").append(record.selectedKind?.name?.wireName().jsonNullable())
    append(",\"outcome\":").append(record.outcome.name.wireName().jsonString())
    append(",\"reason\":").append(record.reason.name.wireName().jsonString())
    append(",\"authorityExpanded\":").append(record.authorityExpanded).append('}')
    return this
}

private fun StringBuilder.appendProcessDiagnostics(acp: AcpExecutionEvidenceSnapshot) {
    val process = acp.diagnostics
    append("\n  \"process\": {")
    append("\n    \"exitCode\": ").append(process.exitCode ?: "null").append(',')
    append("\n    \"stderrSha256\": \"").append(digest(process.stderr)).append("\",")
    append("\n    \"stderrUtf8Bytes\": ").append(utf8Bytes(process.stderr)).append(',')
    append("\n    \"stderrTruncated\": ").append(process.stderrTruncated).append(',')
    append("\n    \"producedOutputBytes\": ").append(process.producedOutputBytes).append(',')
    append("\n    \"producedOutputLimitBytes\": ").append(process.producedOutputLimitBytes).append(',')
    append("\n    \"outputLimitExceeded\": ").append(process.outputLimitExceeded).append(',')
    append("\n    \"forcedTermination\": ").append(process.forcedTermination).append(',')
    append("\n    \"rootTerminationRequested\": ").append(process.rootTerminationRequested).append(',')
    append("\n    \"remainingProcessCount\": ").append(process.remainingProcessIds.size).append(',')
    append("\n    \"containment\": ").append(process.containment.jsonString()).append(',')
    append("\n    \"networkIsolated\": ").append(process.networkIsolated).append(',')
    append("\n    \"sandboxCleanupVerified\": ").append(process.sandboxCleanupVerified)
    append("\n  },")
}

private fun StringBuilder.appendSandboxEvidence(sandbox: AcpSandboxEvidence) {
    append("\n  \"sandbox\": {")
    append("\n    \"evidenceSha256\": \"").append(sandbox.evidenceSha256).append("\",")
    append("\n    \"provider\": ").append(sandbox.provider.jsonString()).append(',')
    append("\n    \"providerVersion\": ").append(sandbox.providerVersion.jsonString()).append(',')
    append("\n    \"providerExecutableSha256\": \"").append(sandbox.providerExecutableSha256).append("\",")
    append("\n    \"providerExecutableMode\": ").append(sandbox.providerExecutableMode).append(',')
    append("\n    \"resourceLimiterSha256\": \"").append(sandbox.resourceLimiterSha256).append("\",")
    append("\n    \"scopeSupervisorSha256\": \"").append(sandbox.scopeSupervisorSha256).append("\",")
    append("\n    \"scopeInspectorSha256\": \"").append(sandbox.scopeInspectorSha256).append("\",")
    append("\n    \"environmentFdOpenerSha256\": \"").append(sandbox.environmentFdOpenerSha256).append("\",")
    append("\n    \"policySha256\": ").append(sandbox.policySha256.jsonNullable()).append(',')
    append("\n    \"networkIsolated\": ").append(sandbox.networkIsolated).append(',')
    append("\n    \"outerAgentContained\": ").append(sandbox.outerAgentContained).append(',')
    append("\n    \"nestedUserNamespacesDisabled\": ").append(sandbox.nestedUserNamespacesDisabled).append(',')
    append("\n    \"newSession\": ").append(sandbox.newSession).append(',')
    append("\n    \"dieWithParent\": ").append(sandbox.dieWithParent).append(',')
    append("\n    \"cgroupV2PidsLimited\": ").append(sandbox.cgroupV2PidsLimited).append(',')
    append("\n    \"cgroupV2MemoryLimited\": ").append(sandbox.cgroupV2MemoryLimited).append(',')
    append("\n    \"cgroupV2CpuLimited\": ").append(sandbox.cgroupV2CpuLimited).append(',')
    append("\n    \"outerAgentLimits\": ").appendResourceLimits(sandbox.outerAgentLimits).append(',')
    append("\n    \"runtimeClosureLimits\": {")
    append("\"maximumEntries\":").append(sandbox.runtimeClosureLimits.maximumEntries).append(',')
    append("\"maximumUserOwnedFileBytes\":").append(sandbox.runtimeClosureLimits.maximumUserOwnedFileBytes).append(',')
    append("\"maximumDepth\":").append(sandbox.runtimeClosureLimits.maximumDepth).append("},")
    append("\n    \"securityExecutables\": [")
    sandbox.securityExecutables.forEachIndexed { index, executable ->
        if (index > 0) append(',')
        append("{\"role\":").append(executable.role.jsonString())
        append(",\"canonicalPathSha256\":\"").append(executable.canonicalPathSha256)
        append("\",\"contentSha256\":\"").append(executable.contentSha256)
        append("\",\"mode\":").append(executable.mode)
        append(",\"metadataSha256\":\"").append(executable.metadataSha256).append("\"}")
    }
    append("],")
    append("\n    \"authorities\": [")
    sandbox.authorities.forEachIndexed { index, authority ->
        if (index > 0) append(',')
        append("{\"rootId\":").append(authority.rootId.jsonString())
        append(",\"rootPathSha256\":\"").append(authority.rootPathSha256)
        append("\",\"mode\":").append(authority.mode.name.wireName().jsonString())
        append(",\"quota\":")
        val quota = authority.quota
        if (quota == null) append("null") else {
            append("{\"provider\":").append(quota.provider.jsonString())
            append(",\"mountId\":").append(quota.mountId)
            append(",\"maximumBytes\":").append(quota.maximumBytes)
            append(",\"maximumEntries\":").append(quota.maximumEntries)
            append(",\"mountPathSha256\":\"").append(quota.mountPathSha256).append("\"}")
        }
        append('}')
    }
    append("],")
    append("\n    \"launches\": [")
    sandbox.launches.forEachIndexed { index, launch ->
        if (index > 0) append(',')
        appendSandboxLaunch(launch)
    }
    append("],")
    append("\n    \"outerProcessOutput\": ")
    val output = sandbox.outerProcessOutput
    if (output == null) append("null") else {
        append("{\"maximumBytes\":").append(output.maximumBytes)
        append(",\"observedBytes\":").append(output.observedBytes)
        append(",\"limitExceeded\":").append(output.limitExceeded).append('}')
    }
    append("\n  },")
}

private fun StringBuilder.appendSandboxLaunch(launch: AcpSandboxLaunchEvidence) {
    append("{\"purpose\":").append(launch.purpose.name.wireName().jsonString())
    append(",\"resourceLimits\":").appendResourceLimits(launch.resourceLimits)
    append(",\"controllers\":").appendControllers(launch.controllers)
    append(",\"commandSha256\":\"").append(launch.commandSha256).append('"')
    append(",\"startGate\":{")
    append("\"descriptor\":").append(launch.startGate.descriptor)
    append(",\"waiterExecutableSha256\":\"").append(launch.startGate.waiterExecutableSha256)
    append("\",\"helperProtocolSha256\":\"").append(launch.startGate.helperProtocolSha256)
    append("\",\"positiveByteRequired\":").append(launch.startGate.positiveByteRequired).append('}')
    append(",\"environment\":{")
    append("\"sandboxPathSha256\":\"").append(launch.environment.sandboxPathSha256)
    append("\",\"bindingNamesSha256\":\"").append(launch.environment.bindingNamesSha256)
    append("\",\"bindingCount\":").append(launch.environment.bindingCount)
    append(",\"encodedBytes\":").append(launch.environment.encodedBytes)
    append(",\"device\":").append(launch.environment.device)
    append(",\"inode\":").append(launch.environment.inode)
    append(",\"mountId\":").append(launch.environment.mountId)
    append(",\"mode\":").append(launch.environment.mode)
    append(",\"linkCount\":").append(launch.environment.linkCount).append('}')
    append(",\"effectiveRlimits\":{")
    val limits = launch.effectiveRlimits
    append("\"processesSoft\":").append(limits.processesSoft).append(',')
    append("\"processesHard\":").append(limits.processesHard).append(',')
    append("\"openFilesSoft\":").append(limits.openFilesSoft).append(',')
    append("\"openFilesHard\":").append(limits.openFilesHard).append(',')
    append("\"fileBytesSoft\":").append(limits.fileBytesSoft).append(',')
    append("\"fileBytesHard\":").append(limits.fileBytesHard).append(',')
    append("\"coreBytesSoft\":").append(limits.coreBytesSoft).append(',')
    append("\"coreBytesHard\":").append(limits.coreBytesHard).append(',')
    append("\"addressSpaceSoft\":").append(limits.addressSpaceSoft).append(',')
    append("\"addressSpaceHard\":").append(limits.addressSpaceHard).append(',')
    append("\"cpuSecondsSoft\":").append(limits.cpuSecondsSoft).append(',')
    append("\"cpuSecondsHard\":").append(limits.cpuSecondsHard).append('}')
    append(",\"executableMount\":").appendMount(launch.executableMount)
    append(",\"runtimeMounts\":[")
    launch.runtimeMounts.forEachIndexed { index, mount ->
        if (index > 0) append(',')
        appendMount(mount)
    }
    append("]}")
}

private fun StringBuilder.appendResourceLimits(limits: AcpSandboxResourceLimits): StringBuilder {
    append("{\"maximumProcesses\":").append(limits.maximumProcesses)
    append(",\"maximumOpenFiles\":").append(limits.maximumOpenFiles)
    append(",\"maximumFileBytes\":").append(limits.maximumFileBytes)
    append(",\"maximumAddressSpaceBytes\":").append(limits.maximumAddressSpaceBytes)
    append(",\"maximumCpuSeconds\":").append(limits.maximumCpuSeconds).append('}')
    return this
}

private fun StringBuilder.appendControllers(controllers: AcpCgroupControllerEvidence): StringBuilder {
    append("{\"pidsMax\":").append(controllers.pidsMax)
    append(",\"memoryMaxBytes\":").append(controllers.memoryMaxBytes)
    append(",\"memorySwapMaxBytes\":").append(controllers.memorySwapMaxBytes)
    append(",\"cpuQuotaMicros\":").append(controllers.cpuQuotaMicros)
    append(",\"cpuPeriodMicros\":").append(controllers.cpuPeriodMicros)
    append(",\"memoryOomGroup\":").append(controllers.memoryOomGroup)
    append(",\"runtimeMaxMicros\":").append(controllers.runtimeMaxMicros)
    append(",\"timeoutStopMicros\":").append(controllers.timeoutStopMicros).append('}')
    return this
}

private fun StringBuilder.appendMount(mount: AcpSandboxMountEvidence): StringBuilder {
    append("{\"sourcePathSha256\":\"").append(mount.sourcePathSha256)
    append("\",\"destinationPathSha256\":\"").append(mount.destinationPathSha256)
    append("\",\"manifestSha256\":\"").append(mount.manifestSha256)
    append("\",\"device\":").append(mount.device)
    append(",\"inode\":").append(mount.inode)
    append(",\"mode\":").append(mount.mode)
    append(",\"directory\":").append(mount.directory).append('}')
    return this
}

private fun StringBuilder.appendValidation(binding: AcpExecutionOutcomeBinding) {
    append("\n  \"validation\": {")
    append("\n    \"accepted\": ").append(binding.accepted).append(',')
    append("\n    ").append(binding.artifactDigestField.jsonString())
        .append(": \"").append(binding.artifactSha256).append("\",")
    append("\n    \"issues\": [")
    binding.issues.forEachIndexed { index, issue ->
        if (index > 0) append(',')
        append("{\"code\":").append(issue.code.jsonString())
        append(",\"messageSha256\":\"").append(digest(issue.message)).append('"')
        append(",\"messageUtf8Bytes\":").append(utf8Bytes(issue.message))
        append(",\"entityIds\":").appendJsonStrings(issue.entityIds.sorted()).append('}')
    }
    append("\n    ]")
    append("\n  }")
}

private fun StringBuilder.appendFileChange(change: AgentFileChange): StringBuilder {
    append("{\"rootId\":").append(change.path.rootId.jsonString())
    append(",\"relativePath\":").append(change.path.relativePath.jsonString())
    append(",\"kind\":").append(change.kind.name.wireName().jsonString())
    append(",\"beforeSha256\":").append(change.beforeSha256.jsonNullable())
    append(",\"afterSha256\":").append(change.afterSha256.jsonNullable())
    append(",\"sizeBytes\":").append(change.sizeBytes ?: "null").append('}')
    return this
}

private fun StringBuilder.appendJsonStrings(values: Collection<String>): StringBuilder {
    append('[')
    values.forEachIndexed { index, value ->
        if (index > 0) append(',')
        append(value.jsonString())
    }
    append(']')
    return this
}

private fun digestCanonicalMap(values: Map<String, String>): String = digest(
    values.toSortedMap().entries.joinToString("\u0000") { (key, value) -> "$key\u0000$value" },
)

private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
    .digest(strictUtf8(value))
    .joinToString("") { "%02x".format(it) }

private fun utf8Bytes(value: String): Int = strictUtf8(value).size

private fun digestAgentRequest(request: AgentExecutionRequest): String = LengthDelimitedEvidenceDigest().apply {
    field("contract", request.schemaVersion.toString())
    field("objective", request.objective)
    field("workspaceRootsSha256", digestWorkspaceRoots(request))
    field("contextInputsSha256", digestContextInputs(request))
    field("accessPolicySha256", digestAgentAccessPolicy(request))
    field("wallClockTimeoutNanos", request.limits.wallClockTimeout.toNanos().toString())
    field("idleTimeoutNanos", request.limits.idleTimeout.toNanos().toString())
    field("maximumTurns", request.limits.maxTurns.toString())
    field("maximumToolCalls", request.limits.maxToolCalls.toString())
    field("maximumOutputBytes", request.limits.maxOutputBytes.toString())
    field("maximumInputTokens", request.limits.maxInputTokens?.toString())
    field("maximumOutputTokens", request.limits.maxOutputTokens?.toString())
}.finish()

private fun digestWorkspaceRoots(request: AgentExecutionRequest): String = LengthDelimitedEvidenceDigest().apply {
    field("count", request.workspaceRoots.size.toString())
    request.workspaceRoots.forEachIndexed { index, root ->
        field("root[$index].id", root.id)
        field("root[$index].path", root.path.toString())
    }
}.finish()

private fun digestContextInputs(request: AgentExecutionRequest): String = LengthDelimitedEvidenceDigest().apply {
    field("count", request.contextInputs.size.toString())
    request.contextInputs.forEachIndexed { index, context ->
        field("context[$index].id", context.id)
        field("context[$index].mediaType", context.mediaType)
        field("context[$index].description", context.description)
        field("context[$index].content", context.content)
    }
}.finish()

private fun digestAgentAccessPolicy(request: AgentExecutionRequest): String = LengthDelimitedEvidenceDigest().apply {
    val operations = request.accessPolicy.allowedOperations.map { it.name }.sorted()
    field("allowedOperationCount", operations.size.toString())
    operations.forEachIndexed { index, operation -> field("allowedOperation[$index]", operation) }
    val rules = request.accessPolicy.pathRules.sortedWith(
        compareBy(
            { it.path.rootId },
            { it.path.relativePath },
            { it.recursive },
            { it.operations.map { operation -> operation.name }.sorted().joinToString(",") },
        ),
    )
    field("pathRuleCount", rules.size.toString())
    rules.forEachIndexed { index, rule ->
        field("pathRule[$index].rootId", rule.path.rootId)
        field("pathRule[$index].relativePath", rule.path.relativePath)
        field("pathRule[$index].recursive", rule.recursive.toString())
        val ruleOperations = rule.operations.map { it.name }.sorted()
        field("pathRule[$index].operationCount", ruleOperations.size.toString())
        ruleOperations.forEachIndexed { operationIndex, operation ->
            field("pathRule[$index].operation[$operationIndex]", operation)
        }
    }
}.finish()

/** Exact ACP v1 text renderer mirrored here so its wire bytes are retained by digest. */
private fun renderAcpWirePrompt(request: AgentExecutionRequest): String = buildString {
    appendLine(request.objective)
    if (request.contextInputs.isNotEmpty()) {
        appendLine()
        appendLine("Context inputs (immutable):")
        request.contextInputs.forEach { context ->
            append("--- ").append(context.id).append(" [").append(context.mediaType).append(']')
            context.description?.let { append(" — ").append(it) }
            appendLine()
            appendLine(context.content)
        }
    }
}

private class LengthDelimitedEvidenceDigest {
    private val digest = MessageDigest.getInstance("SHA-256")

    fun field(name: String, value: String?) {
        component(strictUtf8(name))
        if (value == null) {
            digest.update(0.toByte())
        } else {
            digest.update(1.toByte())
            component(strictUtf8(value))
        }
    }

    fun finish(): String = digest.digest().joinToString("") { "%02x".format(it) }

    private fun component(bytes: ByteArray) {
        digest.update(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(bytes.size.toLong()).array())
        digest.update(bytes)
    }
}

private fun strictUtf8(value: String): ByteArray = try {
    val encoded = StandardCharsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .encode(CharBuffer.wrap(value))
    ByteArray(encoded.remaining()).also(encoded::get)
} catch (failure: CharacterCodingException) {
    throw IllegalArgumentException("ACP execution evidence text is not valid Unicode", failure)
}

private fun String.wireName(): String = lowercase().replace('_', '-')

private fun String?.jsonNullable(): String = this?.jsonString() ?: "null"

private fun String.jsonString(): String = buildString {
    append('"')
    var index = 0
    while (index < this@jsonString.length) {
        val character = this@jsonString[index]
        when (character) {
            '\\' -> append("\\\\")
            '"' -> append("\\\"")
            '\b' -> append("\\b")
            '\u000c' -> append("\\f")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> when {
                character.code < 0x20 -> append("\\u%04x".format(character.code))
                character.isHighSurrogate() -> {
                    require(index + 1 < this@jsonString.length && this@jsonString[index + 1].isLowSurrogate()) {
                        "ACP execution evidence text is not valid Unicode"
                    }
                    append(character).append(this@jsonString[++index])
                }
                character.isLowSurrogate() -> throw IllegalArgumentException(
                    "ACP execution evidence text is not valid Unicode",
                )
                else -> append(character)
            }
        }
        index++
    }
    append('"')
}

private fun String.isSha256(): Boolean = length == 64 && all { it in '0'..'9' || it in 'a'..'f' }

private const val MAXIMUM_ARCHIVED_AGENT_EVENTS = 8_192
private const val MAXIMUM_ARCHIVED_EVENT_COMPONENTS = 32_768
private const val MAXIMUM_ARCHIVED_EVENT_PEER_BYTES = 16L * 1024 * 1024
private const val MAXIMUM_ARCHIVED_EVIDENCE_BYTES = 64 * 1024 * 1024
private const val MAXIMUM_ARCHIVED_OUTCOME_ISSUES = 4_096
private const val MAXIMUM_ARCHIVED_OUTCOME_MESSAGE_BYTES = 64 * 1024
private const val MAXIMUM_ARCHIVED_OUTCOME_ENTITY_IDS = 32_768
