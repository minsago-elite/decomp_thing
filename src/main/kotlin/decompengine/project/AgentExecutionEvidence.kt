package decompengine.project

import decompengine.acp.ACP_CLIENT_IMPLEMENTATION_NAME
import decompengine.acp.ACP_CLIENT_IMPLEMENTATION_VERSION
import decompengine.acp.ACP_KOTLIN_SDK_VERSION
import decompengine.acp.ACP_STABLE_PROTOCOL_VERSION
import decompengine.acp.AcpCgroupControllerEvidence
import decompengine.acp.AcpExecutionEvidenceSnapshot
import decompengine.acp.AcpFilesystemAuditRecord
import decompengine.acp.AcpHarnessProvenance
import decompengine.acp.AcpInvocationEvidenceSnapshot
import decompengine.acp.AcpPermissionAuditRecord
import decompengine.acp.AcpSandboxEvidence
import decompengine.acp.AcpSandboxLaunchEvidence
import decompengine.acp.AcpSandboxMountEvidence
import decompengine.acp.AcpSandboxResourceLimits
import decompengine.acp.AcpTerminalAuditRecord
import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeEvent
import decompengine.agent.AgentMessageEvent
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentPermissionEvent
import decompengine.agent.AgentPlanEvent
import decompengine.agent.AgentToolEvent
import decompengine.agent.receiptCommitmentBytes
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Collections
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

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
        ): BoundedAcpExecutionArtifact {
            val requestBinding = AgentExecutionRequestBinding.capture(request)
            return BoundedAcpExecutionArtifact(
                ArchivedAgentRequest(
                requestSha256 = requestBinding.requestSha256,
                objectiveSha256 = digest(request.objective),
                objectiveUtf8Bytes = utf8Bytes(request.objective),
                promptSha256 = promptSha256,
                wirePromptSha256 = acp.wirePromptSha256,
                workspaceRootsSha256 = digestWorkspaceRoots(request),
                contextInputsSha256 = digestContextInputs(request),
                accessPolicySha256 = requestBinding.accessPolicySha256,
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
}

/** Immutable schema-v2 evidence for one ACP invocation, before workflow assessment. */
internal class BoundedAcpExecutionReceiptArtifact private constructor(
    private val request: ArchivedReceiptRequest,
    private val outcome: AgentExecutionOutcome,
    private val events: ArchivedAgentEventSnapshot,
    private val acp: AcpInvocationEvidenceSnapshot,
) {
    val requestSha256: String get() = request.requestSha256
    private val eventChanges: List<AgentFileChange> =
        events.events.filterIsInstance<ArchivedFileChangeEvent>().map { it.change }
    val terminalOutcome: String = when (outcome) {
        is AgentExecutionOutcome.Returned -> "returned-${outcome.result.stopReason.name.wireName()}"
        is AgentExecutionOutcome.Failed -> "failed-${outcome.failure.kind.name.wireName()}"
    }
    val resultChangesSha256: String = when (outcome) {
        is AgentExecutionOutcome.Returned -> agentFileChangeSetSha256(outcome.result.changes)
        is AgentExecutionOutcome.Failed -> agentFileChangeSetSha256(emptyList())
    }
    val releaseComplete: Boolean = (outcome as? AgentExecutionOutcome.Returned)?.result?.let { result ->
        val factory = acp.factoryProvenance ?: return@let false
        val negotiated = acp.negotiatedAgent ?: return@let false
        val diagnostics = acp.diagnostics ?: return@let false
        val sandbox = acp.sandboxEvidence ?: return@let false
        val session = result.session ?: return@let false
        val usage = result.usage
        result.stopReason.name == "COMPLETED" &&
            events.complete && events.observedEventCount == events.events.size.toLong() &&
            eventChanges == result.changes && result.changes.size <= MAXIMUM_ARCHIVED_RESULT_CHANGES &&
            request.workspaceRootIds.complete && request.contextInputIds.complete &&
            acp.phaseReached.name == "FINAL_WORKSPACE_SNAPSHOT" &&
            acp.cleanupDisposition.name == "VERIFIED" &&
            acp.completeness.allPolicyAuditsComplete &&
            acp.completeExecutionEvidence != null &&
            acp.wirePromptSha256 != null &&
            factory.harness == "acp" && !factory.deprecated &&
            factory.acpProtocolVersion == negotiated.protocolVersion &&
            session.harnessId == factory.implementationId &&
            diagnostics.remainingProcessIds.isEmpty() && diagnostics.sandboxCleanupVerified &&
            diagnostics.networkIsolated && diagnostics.containment.isNotBlank() &&
            !diagnostics.forcedTermination && !diagnostics.rootTerminationRequested &&
            !diagnostics.outputLimitExceeded &&
            diagnostics.producedOutputBytes <= diagnostics.producedOutputLimitBytes &&
            sandbox.networkIsolated && sandbox.outerAgentContained &&
            sandbox.nestedUserNamespacesDisabled && sandbox.newSession && sandbox.dieWithParent &&
            sandbox.cgroupV2PidsLimited && sandbox.cgroupV2MemoryLimited && sandbox.cgroupV2CpuLimited &&
            sandbox.outerProcessOutput?.let { output ->
                !output.limitExceeded && output.observedBytes <= output.maximumBytes
            } != false &&
            request.objective.encoding == "utf-8" && request.workspaceRootIds.allUtf8 &&
            request.contextInputIds.allUtf8 && events.events.all(ArchivedAgentEvent::receiptTextUtf8) &&
            releaseOutcomeTextIsUtf8(result) && releaseProviderTextIsUtf8(acp) &&
            (request.maximumInputTokens == null ||
                usage?.inputTokens?.let { it <= request.maximumInputTokens } == true) &&
            (request.maximumOutputTokens == null ||
                usage?.outputTokens?.let { it <= request.maximumOutputTokens } == true) &&
            (usage?.toolCalls == null || usage.toolCalls <= request.maximumToolCalls)
    } == true

    fun render(
        evidenceKind: String,
        taskIdentityField: String,
        taskId: String,
        maximumFullArtifactBytes: Int = MAXIMUM_ARCHIVED_EVIDENCE_BYTES,
    ): RenderedAcpReceiptArtifact {
        require(maximumFullArtifactBytes in 1..MAXIMUM_ARCHIVED_EVIDENCE_BYTES) {
            "ACP full-artifact byte limit is outside the production artifact cap"
        }
        require(evidenceKind.matches(Regex("[a-z0-9][a-z0-9.-]{0,127}"))) {
            "ACP receipt evidence kind is invalid"
        }
        require(taskIdentityField.matches(Regex("[A-Za-z][A-Za-z0-9]{0,63}"))) {
            "ACP receipt task identity field is invalid"
        }
        require(taskId.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"))) {
            "ACP receipt task identity is invalid"
        }
        val text = buildString {
            append("{\n  \"schemaVersion\": 2,")
            append("\n  \"kind\": ").append(evidenceKind.jsonString()).append(',')
            append("\n  ").append(taskIdentityField.jsonString()).append(": ")
                .append(taskId.jsonString()).append(',')
            appendReceiptRequest(request)
            appendReceiptProvider(acp)
            appendReceiptLifecycle(acp, releaseComplete)
            appendReceiptFactory(acp.factoryProvenance)
            appendReceiptProtocolAndAgent(acp)
            appendReceiptSession(outcome)
            appendReceiptEvents(events)
            appendReceiptOutcome(outcome)
            appendReceiptPolicyAudits(
                acp.filesystemAudit,
                acp.terminalAudit,
                acp.permissionAudit,
            )
            appendReceiptProcess(acp)
            appendReceiptSandbox(acp.sandboxEvidence)
            append("\n}\n")
        }
        if (text.toByteArray(StandardCharsets.UTF_8).size <= maximumFullArtifactBytes) {
            return RenderedAcpReceiptArtifact(text, releaseComplete)
        }

        // Defensive totality fallback. All caller/peer-authored strings remain commitments, while
        // the independently bounded event and audit collections collapse to whole-list digests.
        // A compact artifact can never satisfy the release-complete verifier.
        val compact = buildString {
            append("{\n  \"schemaVersion\": 2,")
            append("\n  \"kind\": ").append(evidenceKind.jsonString()).append(',')
            append("\n  ").append(taskIdentityField.jsonString()).append(": ")
                .append(taskId.jsonString()).append(',')
            appendReceiptRequest(request)
            appendReceiptProvider(acp)
            appendReceiptLifecycle(acp, releaseComplete = false)
            appendReceiptFactory(acp.factoryProvenance)
            appendReceiptProtocolAndAgent(acp)
            appendReceiptSession(outcome)
            appendCompactReceiptEvents(events)
            appendReceiptOutcome(outcome)
            appendCompactReceiptPolicyAudits(
                acp.filesystemAudit,
                acp.terminalAudit,
                acp.permissionAudit,
            )
            appendReceiptProcess(acp)
            appendReceiptSandbox(acp.sandboxEvidence)
            append("\n}\n")
        }
        check(compact.toByteArray(StandardCharsets.UTF_8).size <= MAXIMUM_ARCHIVED_EVIDENCE_BYTES) {
            "compact ACP receipt evidence violated its static artifact-size bound"
        }
        return RenderedAcpReceiptArtifact(compact, releaseComplete = false)
    }

    companion object {
        fun captureOrNull(
            request: AgentExecutionRequest,
            promptSha256: String,
            receipt: AgentExecutionReceipt,
            events: ArchivedAgentEventSnapshot,
        ): BoundedAcpExecutionReceiptArtifact? {
            val provider = receipt.providerEvidence ?: return null
            require(provider is AcpInvocationEvidenceSnapshot && provider.providerId == "acp") {
                "ACP receipt artifact requires invocation-bound ACP provider evidence"
            }
            val binding = AgentExecutionRequestBinding.capture(request)
            require(receipt.requestBinding == binding) {
                "ACP receipt artifact request differs from its invocation binding"
            }
            require(promptSha256.isSha256()) { "ACP receipt prompt digest is invalid" }
            return BoundedAcpExecutionReceiptArtifact(
                request = ArchivedReceiptRequest.capture(request, promptSha256, provider.wirePromptSha256),
                outcome = receipt.outcome,
                events = events,
                acp = provider,
            )
        }
    }
}

internal data class RenderedAcpReceiptArtifact(
    val json: String,
    val releaseComplete: Boolean,
)

/**
 * A fully rendered, immutable schema-v2 invocation document suitable for immediate persistence.
 * Workflow assessment is deliberately not part of this value: accepting or rejecting a candidate
 * must never rewrite what the provider invocation actually returned.
 */
internal class AcpExecutionReceiptDocument private constructor(
    val requestSha256: String,
    val resultChangesSha256: String,
    val terminalOutcome: String,
    val releaseComplete: Boolean,
    val json: String,
) {
    val schemaVersion: Int = 2
    val sha256: String = sha256(json.toByteArray(StandardCharsets.UTF_8))

    companion object {
        fun captureOrNull(
            request: AgentExecutionRequest,
            promptSha256: String,
            receipt: AgentExecutionReceipt,
            events: ArchivedAgentEventSnapshot,
            evidenceKind: String,
            taskIdentityField: String,
            taskId: String,
            maximumFullArtifactBytes: Int = MAXIMUM_ARCHIVED_EVIDENCE_BYTES,
        ): AcpExecutionReceiptDocument? {
            val artifact = BoundedAcpExecutionReceiptArtifact.captureOrNull(
                request,
                promptSha256,
                receipt,
                events,
            ) ?: return null
            val rendered = artifact.render(
                evidenceKind,
                taskIdentityField,
                taskId,
                maximumFullArtifactBytes,
            )
            return AcpExecutionReceiptDocument(
                artifact.requestSha256,
                artifact.resultChangesSha256,
                artifact.terminalOutcome,
                rendered.releaseComplete,
                rendered.json,
            )
        }
    }
}

internal data class VerifiedAcpExecutionReceiptDocument(
    val requestSha256: String,
    val promptSha256: String,
    val resultChangesSha256: String,
    val terminalOutcome: String,
    val releaseComplete: Boolean,
    val releaseFacts: VerifiedAcpReleaseReceiptFacts?,
)

/**
 * Strict, bounded verifier for the workflow-independent receipt binding. This deliberately does
 * not reinterpret caller-specific changes; it establishes the immutable task/request/outcome and
 * ACP lifecycle identity that a workflow assessment must compare with its own candidate state.
 */
internal fun verifyAcpExecutionReceiptDocument(
    bytes: ByteArray,
    evidenceKind: String,
    taskIdentityField: String,
    taskId: String,
): VerifiedAcpExecutionReceiptDocument {
    require(bytes.size <= MAXIMUM_ARCHIVED_EVIDENCE_BYTES) { "ACP receipt exceeds its artifact cap" }
    val root = OracleJson.parse(bytes, ACP_RECEIPT_BINDING_JSON_LIMITS).jsonObject
    val expectedRootFields = ACP_RECEIPT_BINDING_ROOT_FIELDS + taskIdentityField
    require(root.keys == expectedRootFields) { "ACP receipt has missing, extra, or duplicate binding fields" }
    require(root.receiptInt("schemaVersion") == 2) { "ACP receipt schema is unsupported" }
    require(root.receiptString("kind") == evidenceKind) { "ACP receipt kind is cross-paired" }
    require(root.receiptString(taskIdentityField) == taskId) { "ACP receipt task identity is cross-paired" }

    val request = root.receiptObject("request")
    require(request.keys == ACP_RECEIPT_BINDING_REQUEST_FIELDS) {
        "ACP receipt request has missing, extra, or duplicate fields"
    }
    val requestSha256 = request.receiptString("requestSha256")
    require(requestSha256.isSha256()) { "ACP receipt request digest is invalid" }
    val promptSha256 = request.receiptString("promptSha256")
    require(promptSha256.isSha256()) { "ACP receipt workflow prompt digest is invalid" }

    val provider = root.receiptObject("provider")
    require(provider.keys == setOf("id", "evidenceSchemaVersion") &&
        provider.receiptString("id") == "acp" && provider.receiptInt("evidenceSchemaVersion") == 2
    ) { "receipt is not invocation-bound ACP-v2 evidence" }

    val lifecycle = root.receiptObject("lifecycle")
    require(lifecycle.keys == ACP_RECEIPT_BINDING_LIFECYCLE_FIELDS) {
        "ACP receipt lifecycle has missing, extra, or duplicate fields"
    }
    val releaseComplete = lifecycle.receiptBoolean("releaseComplete")
    val outcome = root.receiptObject("outcome")
    require(outcome.keys == setOf("type", "result", "failure")) {
        "ACP receipt outcome has missing, extra, or duplicate fields"
    }
    var resultChangesSha256 = agentFileChangeSetSha256(emptyList())
    val terminalOutcome = when (outcome.receiptString("type")) {
        "returned" -> {
            require(outcome.getValue("failure") is JsonNull) { "returned ACP receipt also contains a failure" }
            val result = outcome.receiptObject("result")
            require(result.keys == setOf("stopReason", "summary", "changes", "usage")) {
                "ACP receipt result has missing, extra, or duplicate fields"
            }
            val stop = result.receiptString("stopReason")
            require(stop in ACP_RECEIPT_STOP_REASONS) { "ACP receipt stop reason is invalid" }
            val changes = result.receiptObject("changes")
            require(changes.keys == ACP_RECEIPT_BINDING_CHANGE_SET_FIELDS) {
                "ACP receipt result change set has missing, extra, or duplicate fields"
            }
            resultChangesSha256 = changes.receiptString("aggregateSha256")
            require(resultChangesSha256.isSha256()) { "ACP receipt result change digest is invalid" }
            "returned-$stop"
        }
        "failed" -> {
            require(outcome.getValue("result") is JsonNull) { "failed ACP receipt also contains a result" }
            val failure = outcome.receiptObject("failure")
            require(failure.keys == setOf("kind", "message", "retryable", "detailsSha256", "detailCount")) {
                "ACP receipt failure has missing, extra, or duplicate fields"
            }
            val kind = failure.receiptString("kind")
            require(kind in ACP_RECEIPT_FAILURE_KINDS) { "ACP receipt failure kind is invalid" }
            "failed-$kind"
        }
        else -> throw IllegalArgumentException("ACP receipt outcome type is invalid")
    }
    val releaseFacts = if (releaseComplete) {
        require(terminalOutcome == "returned-completed" &&
            lifecycle.receiptString("phaseReached") == "final-workspace-snapshot" &&
            lifecycle.receiptString("cleanupDisposition") == "verified" &&
            lifecycle.receiptBoolean("filesystemAuditComplete") &&
            lifecycle.receiptBoolean("terminalAuditComplete") &&
            lifecycle.receiptBoolean("permissionAuditComplete")
        ) { "ACP receipt release marker disagrees with its terminal lifecycle" }
        val factory = root.receiptObject("factoryProvenance")
        require(factory.keys == ACP_RECEIPT_BINDING_FACTORY_FIELDS) {
            "ACP factory provenance has missing, extra, or duplicate fields"
        }
        val implementationId = factory.receiptString("implementationId")
        val configurationSha256 = factory.receiptString("configurationSha256")
        require(factory.receiptString("harness") == "acp" && !factory.receiptBoolean("deprecated") &&
            implementationId.matches(ACP_RECEIPT_PROVENANCE_ID) && configurationSha256.isSha256() &&
            factory.receiptInt("agentExecutionContractVersion") == AGENT_EXECUTION_CONTRACT_VERSION
        ) {
            "release-complete receipt lacks supported ACP factory provenance"
        }
        val expectedDescriptor = listOf(
            "agent-harness-v1",
            "acp",
            "contract-$AGENT_EXECUTION_CONTRACT_VERSION",
            "acp-$ACP_STABLE_PROTOCOL_VERSION",
            "sdk-$ACP_KOTLIN_SDK_VERSION",
            "implementation-$implementationId",
            "configuration-$configurationSha256",
            "supported",
        ).joinToString(":")
        require(factory.receiptString("descriptor") == expectedDescriptor) {
            "ACP factory descriptor is internally inconsistent"
        }
        val protocol = root.receiptObject("protocol")
        require(protocol.keys == ACP_RECEIPT_BINDING_PROTOCOL_FIELDS &&
            protocol.receiptString("name") == "acp" &&
            protocol.receiptInt("version") == ACP_STABLE_PROTOCOL_VERSION &&
            protocol.receiptString("sdkVersion") == ACP_KOTLIN_SDK_VERSION &&
            root.getValue("agent") !is JsonNull && root.getValue("session") !is JsonNull &&
            root.getValue("process") !is JsonNull && root.getValue("sandbox") !is JsonNull
        ) { "release-complete ACP receipt lacks provider/session evidence" }
        val client = protocol.receiptObject("clientImplementation")
        require(client.keys == setOf("name", "version") &&
            client.receiptString("name") == ACP_CLIENT_IMPLEMENTATION_NAME &&
            client.receiptString("version") == ACP_CLIENT_IMPLEMENTATION_VERSION
        ) { "ACP receipt client implementation provenance is unsupported" }
        require(root.receiptObject("agent").receiptString("configuredImplementationId") == implementationId) {
            "ACP configured implementation differs from factory provenance"
        }
        val session = root.receiptObject("session")
        require(session.keys == setOf("harnessId", "sessionId", "resumeReference")) {
            "ACP receipt session has missing, extra, or duplicate fields"
        }
        session.receiptTextCommitment("harnessId", expected = implementationId, requireNonEmpty = true)
        session.receiptTextCommitment("sessionId", requireNonEmpty = true)
        ReconstructionAcpEvidenceArchiveVerifier.verifyReleaseCompleteReceipt(root)
    } else {
        null
    }
    return VerifiedAcpExecutionReceiptDocument(
        requestSha256,
        promptSha256,
        resultChangesSha256,
        terminalOutcome,
        releaseComplete,
        releaseFacts,
    )
}

private fun JsonObject.receiptString(field: String): String =
    get(field)?.jsonPrimitive?.contentOrNull ?: error("ACP receipt is missing $field")

private fun JsonObject.receiptInt(field: String): Int =
    get(field)?.jsonPrimitive?.intOrNull ?: error("ACP receipt is missing $field")

private fun JsonObject.receiptBoolean(field: String): Boolean =
    get(field)?.jsonPrimitive?.booleanOrNull ?: error("ACP receipt is missing $field")

private fun JsonObject.receiptObject(field: String): JsonObject =
    get(field)?.takeUnless { it is JsonNull }?.jsonObject ?: error("ACP receipt is missing $field")

private fun JsonObject.receiptTextCommitment(
    field: String,
    expected: String? = null,
    requireNonEmpty: Boolean = false,
) {
    val commitment = receiptObject(field)
    require(commitment.keys == setOf("sha256", "encodedBytes", "encoding")) {
        "ACP receipt text commitment has missing, extra, or duplicate fields: $field"
    }
    val digest = commitment.receiptString("sha256")
    val bytes = commitment["encodedBytes"]?.jsonPrimitive?.longOrNull
        ?: error("ACP receipt text commitment is missing encodedBytes: $field")
    require(digest.isSha256() && bytes >= 0 && commitment.receiptString("encoding") == "utf-8") {
        "ACP receipt text commitment is invalid: $field"
    }
    require(!requireNonEmpty || bytes > 0) { "ACP receipt text commitment is empty: $field" }
    expected?.let { value ->
        val encoded = value.toByteArray(StandardCharsets.UTF_8)
        require(digest == sha256(encoded) && bytes == encoded.size.toLong()) {
            "ACP receipt text commitment differs from expected identity: $field"
        }
    }
}

/** Reconstruction-specific adapter for the immutable schema-v2 invocation artifact. */
class ReconstructionAgentExecutionEvidence private constructor(
    private val moduleId: String,
    private val document: AcpExecutionReceiptDocument,
) {
    internal val requestSha256: String get() = document.requestSha256
    internal val terminalOutcome: String get() = document.terminalOutcome
    internal val releaseComplete: Boolean get() = document.releaseComplete

    internal fun toReceiptJson(moduleId: String): String {
        require(moduleId == this.moduleId) { "reconstruction receipt is bound to a different module" }
        return document.json
    }

    internal companion object {
        fun captureOrNull(
            request: AgentExecutionRequest,
            moduleId: String,
            promptSha256: String,
            receipt: AgentExecutionReceipt,
            events: ArchivedAgentEventSnapshot,
            maximumFullArtifactBytes: Int = MAXIMUM_ARCHIVED_EVIDENCE_BYTES,
        ): ReconstructionAgentExecutionEvidence? = AcpExecutionReceiptDocument.captureOrNull(
            request = request,
            promptSha256 = promptSha256,
            receipt = receipt,
            events = events,
            evidenceKind = "decomp-engine.reconstruction-acp-execution-receipt",
            taskIdentityField = "moduleId",
            taskId = moduleId,
            maximumFullArtifactBytes = maximumFullArtifactBytes,
        )?.let { document ->
            ReconstructionAgentExecutionEvidence(
                moduleId,
                document,
            )
        }
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
    private var observedEvents = 0L
    private var complete = true
    private var truncationReason: String? = null

    init {
        require(maximumEvents > 0 && maximumComponents > 0 && maximumPeerBytes > 0) {
            "agent event evidence bounds must be positive"
        }
    }

    @Synchronized
    fun record(event: AgentExecutionEvent) {
        observedEvents = Math.addExact(observedEvents, 1L)
        try {
            require(events.size < maximumEvents) {
                "agent event evidence exceeds the $maximumEvents-record limit"
            }
            val archived = when (event) {
                is AgentMessageEvent -> {
                    consume(1, event.messageId, event.textDelta)
                    ArchivedMessageEvent(
                        event.sequence,
                        event.role.name.wireName(),
                        ArchivedTextCommitment.capture(event.messageId),
                        ArchivedTextCommitment.capture(event.textDelta),
                        event.completed,
                    )
                }
                is AgentPlanEvent -> {
                    consume(
                        event.entries.size,
                        *event.entries.flatMap { listOf(it.id, it.description) }.toTypedArray(),
                    )
                    ArchivedPlanEvent(
                        event.sequence,
                        event.entries.map { entry ->
                            ArchivedPlanEntry(
                                ArchivedTextCommitment.capture(entry.id),
                                ArchivedTextCommitment.capture(entry.description),
                                entry.status.name.wireName(),
                            )
                        },
                    )
                }
                is AgentToolEvent -> {
                    consume(
                        1 + event.details.size,
                        event.toolCallId,
                        event.title,
                        *event.details.flatMap { listOf(it.key, it.value) }.toTypedArray(),
                    )
                    ArchivedToolEvent(
                        event.sequence,
                        ArchivedTextCommitment.capture(event.toolCallId),
                        ArchivedTextCommitment.capture(event.title),
                        event.status.name.wireName(),
                        digestReceiptEvidenceMap(event.details),
                        event.details.size,
                        event.toolCallId.isReceiptUtf8() && event.title.isReceiptUtf8() &&
                            event.details.all { (key, value) -> key.isReceiptUtf8() && value.isReceiptUtf8() },
                    )
                }
                is AgentPermissionEvent -> {
                    consume(1, event.requestId, event.selectedOptionId.orEmpty(), event.reason.orEmpty())
                    ArchivedPermissionEvent(
                        event.sequence,
                        ArchivedTextCommitment.capture(event.requestId),
                        event.decision.name.wireName(),
                        event.selectedOptionId?.let(ArchivedTextCommitment::capture),
                        event.reason?.let(ArchivedTextCommitment::capture),
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
        } catch (failure: RuntimeException) {
            complete = false
            if (truncationReason == null) {
                truncationReason = when {
                    events.size >= maximumEvents -> "event-count-limit"
                    components > maximumComponents -> "component-count-limit"
                    peerBytes > maximumPeerBytes -> "peer-byte-limit"
                    else -> "invalid-event-sequence"
                }
            }
            throw failure
        }
    }

    @Synchronized
    fun snapshot(): List<ArchivedAgentEvent> = Collections.unmodifiableList(ArrayList(events))

    @Synchronized
    fun receiptSnapshot(): ArchivedAgentEventSnapshot = ArchivedAgentEventSnapshot(
        events,
        observedEvents,
        complete,
        truncationReason,
    )

    private fun consume(componentCount: Int, vararg values: String) {
        components = Math.addExact(components, componentCount)
        require(components <= maximumComponents) {
            "agent event evidence exceeds the $maximumComponents-component limit"
        }
        values.forEach { value ->
            peerBytes = Math.addExact(peerBytes, receiptCommitmentBytes(value).size.toLong())
            require(peerBytes <= maximumPeerBytes) {
                "agent event evidence exceeds the $maximumPeerBytes-byte peer-input limit"
            }
        }
    }
}

internal class ArchivedAgentEventSnapshot(
    events: Collection<ArchivedAgentEvent>,
    val observedEventCount: Long,
    val complete: Boolean,
    val truncationReason: String?,
) {
    val events: List<ArchivedAgentEvent> = Collections.unmodifiableList(ArrayList(events))

    init {
        require(this.events.size <= MAXIMUM_ARCHIVED_AGENT_EVENTS) {
            "retained ACP event evidence exceeds its record bound"
        }
        require(observedEventCount >= this.events.size.toLong()) {
            "observed ACP event count is smaller than its retained prefix"
        }
        require(complete == (truncationReason == null)) {
            "ACP event completeness and truncation reason disagree"
        }
        require(truncationReason == null || truncationReason in setOf(
            "event-count-limit", "component-count-limit", "peer-byte-limit", "invalid-event-sequence",
        )) { "ACP event truncation reason is unsupported" }
        require(this.events.map(ArchivedAgentEvent::sequence) == this.events.indices.map(Int::toLong)) {
            "retained ACP event evidence is not a contiguous prefix"
        }
    }
}

internal sealed interface ArchivedAgentEvent {
    val sequence: Long
    val receiptTextUtf8: Boolean
    fun appendJson(output: StringBuilder)
    fun appendReceiptJson(output: StringBuilder)
}

private data class ArchivedMessageEvent(
    override val sequence: Long,
    val role: String,
    val messageId: ArchivedTextCommitment,
    val text: ArchivedTextCommitment,
    val completed: Boolean,
) : ArchivedAgentEvent {
    override val receiptTextUtf8: Boolean = messageId.encoding == "utf-8" && text.encoding == "utf-8"
    override fun appendJson(output: StringBuilder) {
        messageId.requireLegacyUtf8()
        text.requireLegacyUtf8()
        output.append("{\"sequence\":").append(sequence)
        output.append(",\"type\":\"message\",\"role\":").append(role.jsonString())
        output.append(",\"messageIdSha256\":\"").append(messageId.sha256).append('"')
        output.append(",\"textSha256\":\"").append(text.sha256).append('"')
        output.append(",\"textUtf8Bytes\":").append(text.encodedBytes)
        output.append(",\"completed\":").append(completed).append('}')
    }

    override fun appendReceiptJson(output: StringBuilder) {
        output.append("{\"sequence\":").append(sequence)
        output.append(",\"type\":\"message\",\"role\":").append(role.jsonString())
        output.append(",\"messageId\":").appendTextCommitment(messageId)
        output.append(",\"text\":").appendTextCommitment(text)
        output.append(",\"completed\":").append(completed).append('}')
    }
}

private data class ArchivedPlanEntry(
    val id: ArchivedTextCommitment,
    val description: ArchivedTextCommitment,
    val status: String,
)

private data class ArchivedPlanEvent(
    override val sequence: Long,
    val entries: List<ArchivedPlanEntry>,
) : ArchivedAgentEvent {
    override val receiptTextUtf8: Boolean = entries.all {
        it.id.encoding == "utf-8" && it.description.encoding == "utf-8"
    }
    override fun appendJson(output: StringBuilder) {
        entries.forEach { entry ->
            entry.id.requireLegacyUtf8()
            entry.description.requireLegacyUtf8()
        }
        output.append("{\"sequence\":").append(sequence).append(",\"type\":\"plan\",\"entries\":[")
        entries.forEachIndexed { index, entry ->
            if (index > 0) output.append(',')
            output.append("{\"idSha256\":\"").append(entry.id.sha256)
            output.append("\",\"descriptionSha256\":\"").append(entry.description.sha256)
            output.append("\",\"descriptionUtf8Bytes\":").append(entry.description.encodedBytes)
            output.append(",\"status\":").append(entry.status.jsonString()).append('}')
        }
        output.append("]}")
    }

    override fun appendReceiptJson(output: StringBuilder) {
        output.append("{\"sequence\":").append(sequence).append(",\"type\":\"plan\",\"entries\":[")
        entries.forEachIndexed { index, entry ->
            if (index > 0) output.append(',')
            output.append("{\"id\":").appendTextCommitment(entry.id)
            output.append(",\"description\":").appendTextCommitment(entry.description)
            output.append(",\"status\":").append(entry.status.jsonString()).append('}')
        }
        output.append("]}")
    }
}

private data class ArchivedToolEvent(
    override val sequence: Long,
    val toolCallId: ArchivedTextCommitment,
    val title: ArchivedTextCommitment,
    val status: String,
    val detailsSha256: String,
    val detailCount: Int,
    override val receiptTextUtf8: Boolean,
) : ArchivedAgentEvent {
    override fun appendJson(output: StringBuilder) {
        require(receiptTextUtf8) { "schema-v1 ACP tool evidence text is not valid Unicode" }
        toolCallId.requireLegacyUtf8()
        title.requireLegacyUtf8()
        output.append("{\"sequence\":").append(sequence).append(",\"type\":\"tool\"")
        output.append(",\"toolCallIdSha256\":\"").append(toolCallId.sha256)
        output.append("\",\"titleSha256\":\"").append(title.sha256)
        output.append("\",\"status\":").append(status.jsonString())
        output.append(",\"detailsSha256\":\"").append(detailsSha256)
        output.append("\",\"detailCount\":").append(detailCount).append('}')
    }

    override fun appendReceiptJson(output: StringBuilder) {
        output.append("{\"sequence\":").append(sequence).append(",\"type\":\"tool\"")
        output.append(",\"toolCallId\":").appendTextCommitment(toolCallId)
        output.append(",\"title\":").appendTextCommitment(title)
        output.append(",\"status\":").append(status.jsonString())
        output.append(",\"detailsSha256\":\"").append(detailsSha256)
        output.append("\",\"detailCount\":").append(detailCount).append('}')
    }
}

private data class ArchivedPermissionEvent(
    override val sequence: Long,
    val requestId: ArchivedTextCommitment,
    val decision: String,
    val selectedOptionId: ArchivedTextCommitment?,
    val reason: ArchivedTextCommitment?,
) : ArchivedAgentEvent {
    override val receiptTextUtf8: Boolean = requestId.encoding == "utf-8" &&
        selectedOptionId?.encoding != "jvm-utf16be" && reason?.encoding != "jvm-utf16be"
    override fun appendJson(output: StringBuilder) {
        requestId.requireLegacyUtf8()
        selectedOptionId?.requireLegacyUtf8()
        reason?.requireLegacyUtf8()
        output.append("{\"sequence\":").append(sequence).append(",\"type\":\"permission\"")
        output.append(",\"requestIdSha256\":\"").append(requestId.sha256)
        output.append("\",\"decision\":").append(decision.jsonString())
        output.append(",\"selectedOptionIdSha256\":").append(selectedOptionId?.sha256.jsonNullable())
        output.append(",\"reasonSha256\":").append(reason?.sha256.jsonNullable()).append('}')
    }

    override fun appendReceiptJson(output: StringBuilder) {
        output.append("{\"sequence\":").append(sequence).append(",\"type\":\"permission\"")
        output.append(",\"requestId\":").appendTextCommitment(requestId)
        output.append(",\"decision\":").append(decision.jsonString())
        output.append(",\"selectedOptionId\":")
        selectedOptionId?.let { output.appendTextCommitment(it) } ?: output.append("null")
        output.append(",\"reason\":")
        reason?.let { output.appendTextCommitment(it) } ?: output.append("null")
        output.append('}')
    }
}

private data class ArchivedFileChangeEvent(
    override val sequence: Long,
    val change: AgentFileChange,
) : ArchivedAgentEvent {
    override val receiptTextUtf8: Boolean = change.path.rootId.isReceiptUtf8() &&
        change.path.relativePath.isReceiptUtf8()
    override fun appendJson(output: StringBuilder) {
        output.append("{\"sequence\":").append(sequence).append(",\"type\":\"file-change\",\"change\":")
        output.appendFileChange(change).append('}')
    }

    override fun appendReceiptJson(output: StringBuilder) {
        output.append("{\"sequence\":").append(sequence).append(",\"type\":\"file-change\",\"change\":")
        output.appendReceiptFileChange(change).append('}')
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

private data class ArchivedTextCommitment(
    val sha256: String,
    val encodedBytes: Long,
    val encoding: String,
) {
    fun appendJson(output: StringBuilder) {
        output.append("{\"sha256\":\"").append(sha256)
        output.append("\",\"encodedBytes\":").append(encodedBytes)
        output.append(",\"encoding\":").append(encoding.jsonString()).append('}')
    }

    companion object {
        fun capture(value: String): ArchivedTextCommitment {
            val bytes = receiptCommitmentBytes(value)
            return ArchivedTextCommitment(
                sha256 = sha256(bytes),
                encodedBytes = bytes.size.toLong(),
                encoding = if (bytes.firstOrNull() == 0xff.toByte()) "jvm-utf16be" else "utf-8",
            )
        }
    }
}

private fun ArchivedTextCommitment.requireLegacyUtf8() {
    require(encoding == "utf-8") { "schema-v1 ACP evidence text is not valid Unicode" }
}

private data class ArchivedTextCommitmentList(
    val observedCount: Long,
    val retained: List<ArchivedTextCommitment>,
    val complete: Boolean,
    val aggregateSha256: String,
    val allUtf8: Boolean,
) {
    fun appendJson(output: StringBuilder) {
        output.append('{')
        output.append("\"observedCount\":").append(observedCount).append(',')
        output.append("\"retainedCount\":").append(retained.size).append(',')
        output.append("\"complete\":").append(complete).append(',')
        output.append("\"aggregateSha256\":\"").append(aggregateSha256).append("\",")
        output.append("\"records\":")
        output.appendTextCommitments(retained).append('}')
    }

    companion object {
        fun capture(values: Collection<String>): ArchivedTextCommitmentList {
            val digest = ReceiptEvidenceDigest().apply { field("count", values.size.toString()) }
            val retained = ArrayList<ArchivedTextCommitment>(
                minOf(values.size, MAXIMUM_ARCHIVED_REQUEST_IDENTIFIERS),
            )
            var allUtf8 = true
            values.forEachIndexed { index, value ->
                digest.field("value[$index]", value)
                allUtf8 = allUtf8 && value.isReceiptUtf8()
                if (index < MAXIMUM_ARCHIVED_REQUEST_IDENTIFIERS) {
                    retained += ArchivedTextCommitment.capture(value)
                }
            }
            return ArchivedTextCommitmentList(
                observedCount = values.size.toLong(),
                retained = Collections.unmodifiableList(retained),
                complete = values.size <= MAXIMUM_ARCHIVED_REQUEST_IDENTIFIERS,
                aggregateSha256 = digest.finish(),
                allUtf8 = allUtf8,
            )
        }
    }
}

private data class ArchivedReceiptRequest(
    val contractVersion: Int,
    val requestSha256: String,
    val accessPolicySha256: String,
    val objective: ArchivedTextCommitment,
    val promptSha256: String,
    val wirePromptSha256: String?,
    val workspaceRootIds: ArchivedTextCommitmentList,
    val contextInputIds: ArchivedTextCommitmentList,
    val filesystemEnabled: Boolean,
    val terminalEnabled: Boolean,
    val maximumTurns: Int,
    val maximumToolCalls: Int,
    val maximumOutputBytes: Long,
    val wallClockTimeoutNanos: String,
    val idleTimeoutNanos: String,
    val maximumInputTokens: Long?,
    val maximumOutputTokens: Long?,
) {
    companion object {
        fun capture(
            request: AgentExecutionRequest,
            promptSha256: String,
            wirePromptSha256: String?,
        ): ArchivedReceiptRequest {
            val binding = AgentExecutionRequestBinding.capture(request)
            return ArchivedReceiptRequest(
                contractVersion = binding.contractVersion,
                requestSha256 = binding.requestSha256,
                accessPolicySha256 = binding.accessPolicySha256,
                objective = ArchivedTextCommitment.capture(request.objective),
                promptSha256 = promptSha256,
                wirePromptSha256 = wirePromptSha256,
                workspaceRootIds = ArchivedTextCommitmentList.capture(request.workspaceRoots.map { it.id }),
                contextInputIds = ArchivedTextCommitmentList.capture(request.contextInputs.map { it.id }),
                filesystemEnabled = request.accessPolicy.allowedOperations.any { it.name.endsWith("FILE") },
                terminalEnabled = request.accessPolicy.allowedOperations.any { it.name == "EXECUTE_COMMAND" },
                maximumTurns = request.limits.maxTurns,
                maximumToolCalls = request.limits.maxToolCalls,
                maximumOutputBytes = request.limits.maxOutputBytes,
                wallClockTimeoutNanos = request.limits.wallClockTimeout.exactEvidenceNanoseconds(),
                idleTimeoutNanos = request.limits.idleTimeout.exactEvidenceNanoseconds(),
                maximumInputTokens = request.limits.maxInputTokens,
                maximumOutputTokens = request.limits.maxOutputTokens,
            )
        }
    }
}

private fun StringBuilder.appendReceiptRequest(request: ArchivedReceiptRequest) {
    append("\n  \"request\": {")
    append("\n    \"contractVersion\": ").append(request.contractVersion).append(',')
    append("\n    \"requestSha256\": \"").append(request.requestSha256).append("\",")
    append("\n    \"accessPolicySha256\": \"").append(request.accessPolicySha256).append("\",")
    append("\n    \"objective\": ").appendTextCommitment(request.objective).append(',')
    append("\n    \"promptSha256\": \"").append(request.promptSha256).append("\",")
    append("\n    \"wirePromptSha256\": ").append(request.wirePromptSha256.jsonNullable()).append(',')
    append("\n    \"workspaceRootIds\": ")
    request.workspaceRootIds.appendJson(this)
    append(',')
    append("\n    \"contextInputIds\": ")
    request.contextInputIds.appendJson(this)
    append(',')
    append("\n    \"filesystemCapabilityEnabled\": ").append(request.filesystemEnabled).append(',')
    append("\n    \"terminalCapabilityEnabled\": ").append(request.terminalEnabled).append(',')
    append("\n    \"maximumTurns\": ").append(request.maximumTurns).append(',')
    append("\n    \"maximumToolCalls\": ").append(request.maximumToolCalls).append(',')
    append("\n    \"maximumOutputBytes\": ").append(request.maximumOutputBytes).append(',')
    append("\n    \"wallClockTimeoutNanos\": ").append(request.wallClockTimeoutNanos.jsonString()).append(',')
    append("\n    \"idleTimeoutNanos\": ").append(request.idleTimeoutNanos.jsonString()).append(',')
    append("\n    \"maximumInputTokens\": ").append(request.maximumInputTokens ?: "null").append(',')
    append("\n    \"maximumOutputTokens\": ").append(request.maximumOutputTokens ?: "null")
    append("\n  },")
}

private fun StringBuilder.appendTextCommitment(value: ArchivedTextCommitment): StringBuilder {
    value.appendJson(this)
    return this
}

private fun StringBuilder.appendTextCommitments(values: List<ArchivedTextCommitment>): StringBuilder {
    append('[')
    values.forEachIndexed { index, value ->
        if (index > 0) append(',')
        value.appendJson(this)
    }
    append(']')
    return this
}

private fun StringBuilder.appendReceiptProvider(acp: AcpInvocationEvidenceSnapshot) {
    append("\n  \"provider\": {")
    append("\n    \"id\": ").append(acp.providerId.jsonString()).append(',')
    append("\n    \"evidenceSchemaVersion\": ").append(acp.schemaVersion)
    append("\n  },")
}

private fun StringBuilder.appendReceiptLifecycle(
    acp: AcpInvocationEvidenceSnapshot,
    releaseComplete: Boolean,
) {
    val completeness = acp.completeness
    append("\n  \"lifecycle\": {")
    append("\n    \"phaseReached\": ").append(acp.phaseReached.name.wireName().jsonString()).append(',')
    append("\n    \"cleanupDisposition\": ")
        .append(acp.cleanupDisposition.name.wireName().jsonString()).append(',')
    append("\n    \"filesystemAuditComplete\": ").append(completeness.filesystemAuditComplete).append(',')
    append("\n    \"terminalAuditComplete\": ").append(completeness.terminalAuditComplete).append(',')
    append("\n    \"permissionAuditComplete\": ").append(completeness.permissionAuditComplete).append(',')
    append("\n    \"releaseComplete\": ").append(releaseComplete)
    append("\n  },")
}

private fun StringBuilder.appendReceiptFactory(provenance: AcpHarnessProvenance?) {
    append("\n  \"factoryProvenance\": ")
    if (provenance == null) {
        append("null,")
        return
    }
    append('{')
    append("\n    \"descriptor\": ").append(provenance.stableDescriptor.jsonString()).append(',')
    append("\n    \"harness\": ").append(provenance.harness.jsonString()).append(',')
    append("\n    \"implementationId\": ").append(provenance.implementationId.jsonString()).append(',')
    append("\n    \"agentExecutionContractVersion\": ").append(provenance.agentExecutionContractVersion).append(',')
    append("\n    \"configurationSha256\": ").append(provenance.configurationSha256.jsonNullable()).append(',')
    append("\n    \"deprecated\": ").append(provenance.deprecated)
    append("\n  },")
}

private fun StringBuilder.appendReceiptProtocolAndAgent(acp: AcpInvocationEvidenceSnapshot) {
    val provenance = acp.factoryProvenance
    append("\n  \"protocol\": ")
    if (provenance == null) {
        append("null,")
    } else {
        append('{')
        append("\n    \"name\": \"acp\",")
        append("\n    \"version\": ").append(provenance.acpProtocolVersion ?: "null").append(',')
        append("\n    \"sdkVersion\": ").append(provenance.acpSdkVersion.jsonNullable()).append(',')
        append("\n    \"clientImplementation\": {\"name\":")
            .append(ACP_CLIENT_IMPLEMENTATION_NAME.jsonString())
            .append(",\"version\":").append(ACP_CLIENT_IMPLEMENTATION_VERSION.jsonString()).append('}')
        append("\n  },")
    }
    append("\n  \"agent\": ")
    val agent = acp.negotiatedAgent
    if (agent == null) {
        append("null,")
        return
    }
    append('{')
    append("\n    \"configuredImplementationId\": ")
        .append(provenance?.implementationId.jsonNullable()).append(',')
    append("\n    \"negotiatedImplementation\": {")
    append("\"name\":").appendTextCommitment(ArchivedTextCommitment.capture(agent.implementationName)).append(',')
    append("\"version\":").appendTextCommitment(ArchivedTextCommitment.capture(agent.implementationVersion)).append(',')
    append("\"title\":")
    agent.implementationTitle?.let { appendTextCommitment(ArchivedTextCommitment.capture(it)) } ?: append("null")
    append("},")
    val capabilities = agent.capabilities
    append("\n    \"negotiatedCapabilities\": {")
    append("\"loadSession\":").append(capabilities.loadSession).append(',')
    append("\"promptImage\":").append(capabilities.promptImage).append(',')
    append("\"promptAudio\":").append(capabilities.promptAudio).append(',')
    append("\"promptEmbeddedContext\":").append(capabilities.promptEmbeddedContext).append(',')
    append("\"mcpHttp\":").append(capabilities.mcpHttp).append(',')
    append("\"mcpSse\":").append(capabilities.mcpSse).append(',')
    append("\"sessionAdditionalDirectories\":").append(capabilities.sessionAdditionalDirectories).append('}')
    append("\n  },")
}

private fun StringBuilder.appendReceiptSession(outcome: AgentExecutionOutcome) {
    val session = when (outcome) {
        is AgentExecutionOutcome.Returned -> outcome.result.session
        is AgentExecutionOutcome.Failed -> outcome.failure.session
    }
    append("\n  \"session\": ")
    if (session == null) {
        append("null,")
        return
    }
    append('{')
    append("\n    \"harnessId\": ")
        .appendTextCommitment(ArchivedTextCommitment.capture(session.harnessId)).append(',')
    append("\n    \"sessionId\": ").appendTextCommitment(ArchivedTextCommitment.capture(session.sessionId)).append(',')
    append("\n    \"resumeReference\": ")
    session.resumeReference?.let { appendTextCommitment(ArchivedTextCommitment.capture(it)) } ?: append("null")
    append("\n  },")
}

private fun StringBuilder.appendReceiptEvents(snapshot: ArchivedAgentEventSnapshot) {
    append("\n  \"events\": {")
    append("\n    \"maximumRetainedEvents\": ").append(MAXIMUM_ARCHIVED_AGENT_EVENTS).append(',')
    append("\n    \"observedEventCount\": ").append(snapshot.observedEventCount).append(',')
    append("\n    \"retainedEventCount\": ").append(snapshot.events.size).append(',')
    append("\n    \"complete\": ").append(snapshot.complete).append(',')
    append("\n    \"truncationReason\": ").append(snapshot.truncationReason.jsonNullable()).append(',')
    append("\n    \"records\": [")
    snapshot.events.forEachIndexed { index, event ->
        if (index > 0) append(',')
        append("\n      ")
        event.appendReceiptJson(this)
    }
    append("\n    ]")
    append("\n  },")
}

private fun StringBuilder.appendCompactReceiptEvents(snapshot: ArchivedAgentEventSnapshot) {
    append("\n  \"events\": {")
    append("\n    \"maximumRetainedEvents\": ").append(MAXIMUM_ARCHIVED_AGENT_EVENTS).append(',')
    append("\n    \"observedEventCount\": ").append(snapshot.observedEventCount).append(',')
    append("\n    \"retainedEventCount\": 0,")
    append("\n    \"complete\": false,")
    append("\n    \"truncationReason\": \"artifact-byte-limit\",")
    append("\n    \"records\": []")
    append("\n  },")
}

private fun StringBuilder.appendReceiptOutcome(outcome: AgentExecutionOutcome) {
    append("\n  \"outcome\": {")
    when (outcome) {
        is AgentExecutionOutcome.Returned -> {
            append("\n    \"type\": \"returned\",")
            append("\n    \"result\": ").appendReceiptResult(outcome.result).append(',')
            append("\n    \"failure\": null")
        }
        is AgentExecutionOutcome.Failed -> {
            val failure = outcome.failure
            append("\n    \"type\": \"failed\",")
            append("\n    \"result\": null,")
            append("\n    \"failure\": {")
            append("\"kind\":").append(failure.kind.name.wireName().jsonString()).append(',')
            append("\"message\":").appendTextCommitment(ArchivedTextCommitment.capture(failure.message)).append(',')
            append("\"retryable\":").append(failure.retryable).append(',')
            append("\"detailsSha256\":\"").append(digestReceiptEvidenceMap(failure.details)).append("\",")
            append("\"detailCount\":").append(failure.details.size).append('}')
        }
    }
    append("\n  },")
}

private fun StringBuilder.appendReceiptResult(result: AgentExecutionResult): StringBuilder {
    append('{')
    append("\"stopReason\":").append(result.stopReason.name.wireName().jsonString()).append(',')
    append("\"summary\":")
    result.summary?.let { appendTextCommitment(ArchivedTextCommitment.capture(it)) } ?: append("null")
    append(",\"changes\":")
    ArchivedAgentChangeSnapshot.capture(result.changes).appendJson(this)
    append(",\"usage\":")
    val usage = result.usage
    if (usage == null) {
        append("null")
    } else {
        append('{')
        append("\"inputTokens\":").append(usage.inputTokens ?: "null").append(',')
        append("\"outputTokens\":").append(usage.outputTokens ?: "null").append(',')
        append("\"cachedInputTokens\":").append(usage.cachedInputTokens ?: "null").append(',')
        append("\"toolCalls\":").append(usage.toolCalls ?: "null").append(',')
        append("\"wallClockNanos\":")
            .append(usage.wallClock?.exactEvidenceNanoseconds()?.jsonString() ?: "null").append('}')
    }
    append('}')
    return this
}

private data class ArchivedAgentChangeSnapshot(
    val observedCount: Long,
    val retained: List<AgentFileChange>,
    val complete: Boolean,
    val aggregateSha256: String,
) {
    fun appendJson(output: StringBuilder) {
        output.append('{')
        output.append("\"observedCount\":").append(observedCount).append(',')
        output.append("\"retainedCount\":").append(retained.size).append(',')
        output.append("\"complete\":").append(complete).append(',')
        output.append("\"aggregateSha256\":\"").append(aggregateSha256).append("\",")
        output.append("\"records\":[")
        retained.forEachIndexed { index, change ->
            if (index > 0) output.append(',')
            output.appendReceiptFileChange(change)
        }
        output.append("]}")
    }

    companion object {
        fun capture(changes: Collection<AgentFileChange>): ArchivedAgentChangeSnapshot {
            val digest = ReceiptEvidenceDigest().apply { field("count", changes.size.toString()) }
            val retained = ArrayList<AgentFileChange>(
                minOf(changes.size, MAXIMUM_ARCHIVED_RESULT_CHANGES),
            )
            changes.forEachIndexed { index, change ->
                digest.field("change[$index].rootId", change.path.rootId)
                digest.field("change[$index].relativePath", change.path.relativePath)
                digest.field("change[$index].kind", change.kind.name)
                digest.field("change[$index].beforeSha256", change.beforeSha256)
                digest.field("change[$index].afterSha256", change.afterSha256)
                digest.field("change[$index].sizeBytes", change.sizeBytes?.toString())
                if (index < MAXIMUM_ARCHIVED_RESULT_CHANGES) retained += change
            }
            return ArchivedAgentChangeSnapshot(
                observedCount = changes.size.toLong(),
                retained = Collections.unmodifiableList(retained),
                complete = changes.size <= MAXIMUM_ARCHIVED_RESULT_CHANGES,
                aggregateSha256 = digest.finish(),
            )
        }
    }
}

internal fun agentFileChangeSetSha256(changes: Collection<AgentFileChange>): String =
    ArchivedAgentChangeSnapshot.capture(changes).aggregateSha256

private fun StringBuilder.appendReceiptFileChange(change: AgentFileChange): StringBuilder {
    append("{\"rootId\":")
    appendTextCommitment(ArchivedTextCommitment.capture(change.path.rootId))
    append(",\"relativePath\":")
    appendTextCommitment(ArchivedTextCommitment.capture(change.path.relativePath))
    append(",\"kind\":").append(change.kind.name.wireName().jsonString())
    append(",\"beforeSha256\":").append(change.beforeSha256.jsonNullable())
    append(",\"afterSha256\":").append(change.afterSha256.jsonNullable())
    append(",\"sizeBytes\":").append(change.sizeBytes ?: "null").append('}')
    return this
}

private fun StringBuilder.appendReceiptProcess(acp: AcpInvocationEvidenceSnapshot) {
    append("\n  \"process\": ")
    val process = acp.diagnostics
    if (process == null) {
        append("null,")
        return
    }
    append('{')
    append("\"exitCode\":").append(process.exitCode ?: "null").append(',')
    append("\"stderr\":").appendTextCommitment(ArchivedTextCommitment.capture(process.stderr)).append(',')
    append("\"stderrTruncated\":").append(process.stderrTruncated).append(',')
    append("\"producedOutputBytes\":").append(process.producedOutputBytes).append(',')
    append("\"producedOutputLimitBytes\":").append(process.producedOutputLimitBytes).append(',')
    append("\"outputLimitExceeded\":").append(process.outputLimitExceeded).append(',')
    append("\"forcedTermination\":").append(process.forcedTermination).append(',')
    append("\"rootTerminationRequested\":").append(process.rootTerminationRequested).append(',')
    append("\"remainingProcessCount\":").append(process.remainingProcessIds.size).append(',')
    append("\"containment\":")
        .appendTextCommitment(ArchivedTextCommitment.capture(process.containment)).append(',')
    append("\"networkIsolated\":").append(process.networkIsolated).append(',')
    append("\"sandboxCleanupVerified\":").append(process.sandboxCleanupVerified).append('}')
    append(',')
}

private fun StringBuilder.appendReceiptSandbox(sandbox: AcpSandboxEvidence?) {
    if (sandbox == null) {
        append("\n  \"sandbox\": null")
        return
    }
    append("\n  \"sandbox\": {")
    append("\n    \"evidenceSha256\": \"").append(sandbox.evidenceSha256).append("\",")
    append("\n    \"detailsRetained\": false,")
    append("\n    \"provider\": ")
        .appendTextCommitment(ArchivedTextCommitment.capture(sandbox.provider)).append(',')
    append("\n    \"providerVersion\": ")
        .appendTextCommitment(ArchivedTextCommitment.capture(sandbox.providerVersion)).append(',')
    append("\n    \"providerExecutableSha256\": \"")
        .append(sandbox.providerExecutableSha256).append("\",")
    append("\n    \"providerExecutableMode\": ").append(sandbox.providerExecutableMode).append(',')
    append("\n    \"resourceLimiterSha256\": \"").append(sandbox.resourceLimiterSha256).append("\",")
    append("\n    \"scopeSupervisorSha256\": \"").append(sandbox.scopeSupervisorSha256).append("\",")
    append("\n    \"scopeInspectorSha256\": \"").append(sandbox.scopeInspectorSha256).append("\",")
    append("\n    \"environmentFdOpenerSha256\": \"")
        .append(sandbox.environmentFdOpenerSha256).append("\",")
    append("\n    \"policySha256\": ").append(sandbox.policySha256.jsonNullable()).append(',')
    append("\n    \"networkIsolated\": ").append(sandbox.networkIsolated).append(',')
    append("\n    \"outerAgentContained\": ").append(sandbox.outerAgentContained).append(',')
    append("\n    \"nestedUserNamespacesDisabled\": ")
        .append(sandbox.nestedUserNamespacesDisabled).append(',')
    append("\n    \"newSession\": ").append(sandbox.newSession).append(',')
    append("\n    \"dieWithParent\": ").append(sandbox.dieWithParent).append(',')
    append("\n    \"cgroupV2PidsLimited\": ").append(sandbox.cgroupV2PidsLimited).append(',')
    append("\n    \"cgroupV2MemoryLimited\": ").append(sandbox.cgroupV2MemoryLimited).append(',')
    append("\n    \"cgroupV2CpuLimited\": ").append(sandbox.cgroupV2CpuLimited).append(',')
    append("\n    \"outerAgentLimits\": ").appendResourceLimits(sandbox.outerAgentLimits).append(',')
    append("\n    \"runtimeClosureLimits\": {")
    append("\"maximumEntries\":").append(sandbox.runtimeClosureLimits.maximumEntries).append(',')
    append("\"maximumUserOwnedFileBytes\":")
        .append(sandbox.runtimeClosureLimits.maximumUserOwnedFileBytes).append(',')
    append("\"maximumDepth\":").append(sandbox.runtimeClosureLimits.maximumDepth).append("},")
    append("\n    \"securityExecutableCount\": ").append(sandbox.securityExecutables.size).append(',')
    append("\n    \"authorityCount\": ").append(sandbox.authorities.size).append(',')
    append("\n    \"launchCount\": ").append(sandbox.launches.size).append(',')
    append("\n    \"runtimeMountCount\": ")
        .append(sandbox.launches.sumOf { it.runtimeMounts.size }).append(',')
    append("\n    \"terminalAuditCount\": ").append(sandbox.terminalAudit.size).append(',')
    append("\n    \"maximumRecordedLaunches\": ").append(sandbox.maximumRecordedLaunches).append(',')
    append("\n    \"maximumRecordedRuntimeMounts\": ")
        .append(sandbox.maximumRecordedRuntimeMounts).append(',')
    append("\n    \"maximumCanonicalMetadataBytes\": ")
        .append(sandbox.maximumCanonicalMetadataBytes).append(',')
    append("\n    \"outerProcessOutput\": ")
    val output = sandbox.outerProcessOutput
    if (output == null) {
        append("null")
    } else {
        append("{\"maximumBytes\":").append(output.maximumBytes)
        append(",\"observedBytes\":").append(output.observedBytes)
        append(",\"limitExceeded\":").append(output.limitExceeded).append('}')
    }
    append("\n  }")
}

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
    append("\"nameSha256\":\"").append(digest(agent.implementationName)).append("\",")
    append("\"nameUtf8Bytes\":").append(utf8Bytes(agent.implementationName)).append(',')
    append("\"versionSha256\":\"").append(digest(agent.implementationVersion)).append("\",")
    append("\"versionUtf8Bytes\":").append(utf8Bytes(agent.implementationVersion)).append(',')
    append("\"titleSha256\":").append(agent.implementationTitle?.let(::digest).jsonNullable()).append(',')
    append("\"titleUtf8Bytes\":").append(agent.implementationTitle?.let(::utf8Bytes) ?: "null").append("},")
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

private fun StringBuilder.appendReceiptPolicyAudits(
    filesystemAudit: List<AcpFilesystemAuditRecord>,
    terminalAudit: List<AcpTerminalAuditRecord>,
    permissionAudit: List<AcpPermissionAuditRecord>,
) {
    append("\n  \"policyAudits\": {")
    append("\n    \"filesystem\": {")
    append("\"maximumRetainedRecords\":").append(MAXIMUM_ARCHIVED_POLICY_AUDIT_RECORDS).append(',')
    append("\"recordCount\":").append(filesystemAudit.size).append(',')
    append("\"aggregateSha256\":\"").append(digestReceiptFilesystemAudit(filesystemAudit)).append("\",")
    append("\"records\":[")
    filesystemAudit.forEachIndexed { index, record ->
        if (index > 0) append(',')
        append("{\"sequence\":").append(record.sequence)
        append(",\"sessionId\":").appendTextCommitment(ArchivedTextCommitment.capture(record.sessionId))
        append(",\"method\":").appendTextCommitment(ArchivedTextCommitment.capture(record.method))
        append(",\"requestedPathSha256\":")
            .appendTextCommitment(ArchivedTextCommitment.capture(record.requestedPathSha256))
        append(",\"policyPath\":")
        val path = record.policyPath
        if (path == null) {
            append("null")
        } else {
            append("{\"rootId\":")
                .appendTextCommitment(ArchivedTextCommitment.capture(path.rootId))
            append(",\"relativePath\":")
                .appendTextCommitment(ArchivedTextCommitment.capture(path.relativePath)).append('}')
        }
        append(",\"outcome\":").append(record.outcome.name.wireName().jsonString())
        append(",\"reason\":").append(record.reason.name.wireName().jsonString()).append('}')
    }
    append("]},")
    append("\n    \"terminal\": {")
    append("\"maximumRetainedRecords\":").append(MAXIMUM_ARCHIVED_POLICY_AUDIT_RECORDS).append(',')
    append("\"recordCount\":").append(terminalAudit.size).append(',')
    append("\"aggregateSha256\":\"").append(digestReceiptTerminalAudit(terminalAudit)).append("\",")
    append("\"records\":[")
    terminalAudit.forEachIndexed { index, record ->
        if (index > 0) append(',')
        append("{\"sequence\":").append(record.sequence)
        append(",\"sessionId\":").appendTextCommitment(ArchivedTextCommitment.capture(record.sessionId))
        append(",\"method\":").appendTextCommitment(ArchivedTextCommitment.capture(record.method))
        append(",\"requestSha256\":")
            .appendTextCommitment(ArchivedTextCommitment.capture(record.requestSha256))
        append(",\"terminalIdSha256\":")
        record.terminalIdSha256?.let { appendTextCommitment(ArchivedTextCommitment.capture(it)) }
            ?: append("null")
        append(",\"toolCallIdSha256\":")
        record.toolCallIdSha256?.let { appendTextCommitment(ArchivedTextCommitment.capture(it)) }
            ?: append("null")
        append(",\"outcome\":").append(record.outcome.name.wireName().jsonString())
        append(",\"reason\":").append(record.reason.name.wireName().jsonString())
        append(",\"networkIsolated\":").append(record.networkIsolated)
        append(",\"retainedOutputBytes\":").append(record.retainedOutputBytes ?: "null")
        append(",\"producedOutputBytes\":").append(record.producedOutputBytes ?: "null")
        append(",\"outputTruncated\":").append(record.outputTruncated ?: "null").append('}')
    }
    append("]},")
    append("\n    \"permission\": {")
    append("\"maximumRetainedRecords\":").append(MAXIMUM_ARCHIVED_POLICY_AUDIT_RECORDS).append(',')
    append("\"recordCount\":").append(permissionAudit.size).append(',')
    append("\"aggregateSha256\":\"").append(digestReceiptPermissionAudit(permissionAudit)).append("\",")
    append("\"records\":[")
    permissionAudit.forEachIndexed { index, record ->
        if (index > 0) append(',')
        append("{\"sequence\":").append(record.sequence)
        append(",\"sessionId\":").appendTextCommitment(ArchivedTextCommitment.capture(record.sessionId))
        append(",\"toolCallIdSha256\":")
            .appendTextCommitment(ArchivedTextCommitment.capture(record.toolCallIdSha256))
        append(",\"offeredOptionCount\":").append(record.offeredOptionCount)
        append(",\"selectedOptionIdSha256\":")
        record.selectedOptionIdSha256?.let { appendTextCommitment(ArchivedTextCommitment.capture(it)) }
            ?: append("null")
        append(",\"selectedKind\":").append(record.selectedKind?.name?.wireName().jsonNullable())
        append(",\"outcome\":").append(record.outcome.name.wireName().jsonString())
        append(",\"reason\":").append(record.reason.name.wireName().jsonString())
        append(",\"authorityExpanded\":").append(record.authorityExpanded).append('}')
    }
    append("]}")
    append("\n  },")
}

private fun StringBuilder.appendCompactReceiptPolicyAudits(
    filesystemAudit: List<AcpFilesystemAuditRecord>,
    terminalAudit: List<AcpTerminalAuditRecord>,
    permissionAudit: List<AcpPermissionAuditRecord>,
) {
    append("\n  \"policyAudits\": {")
    appendCompactReceiptAudit("filesystem", filesystemAudit.size, digestReceiptFilesystemAudit(filesystemAudit))
    append(',')
    appendCompactReceiptAudit("terminal", terminalAudit.size, digestReceiptTerminalAudit(terminalAudit))
    append(',')
    appendCompactReceiptAudit("permission", permissionAudit.size, digestReceiptPermissionAudit(permissionAudit))
    append("\n  },")
}

private fun StringBuilder.appendCompactReceiptAudit(name: String, count: Int, aggregateSha256: String) {
    append("\n    ").append(name.jsonString()).append(": {")
    append("\"maximumRetainedRecords\":").append(MAXIMUM_ARCHIVED_POLICY_AUDIT_RECORDS).append(',')
    append("\"recordCount\":").append(count).append(',')
    append("\"aggregateSha256\":\"").append(aggregateSha256).append("\",")
    append("\"records\":[]}")
}

private fun StringBuilder.appendPolicyAudits(acp: AcpExecutionEvidenceSnapshot) {
    appendPolicyAudits(acp.filesystemAudit, acp.terminalAudit, acp.permissionAudit)
}

private fun StringBuilder.appendPolicyAudits(
    filesystemAudit: List<AcpFilesystemAuditRecord>,
    terminalAudit: List<AcpTerminalAuditRecord>,
    permissionAudit: List<AcpPermissionAuditRecord>,
) {
    append("\n  \"policyAudits\": {")
    append("\n    \"filesystem\": [")
    filesystemAudit.forEachIndexed { index, record ->
        if (index > 0) append(',')
        append("\n      ").appendFilesystemAudit(record)
    }
    append("\n    ],")
    append("\n    \"terminal\": [")
    terminalAudit.forEachIndexed { index, record ->
        if (index > 0) append(',')
        append("\n      ").appendTerminalAudit(record)
    }
    append("\n    ],")
    append("\n    \"permission\": [")
    permissionAudit.forEachIndexed { index, record ->
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
    append("\",\"contentSha256\":\"").append(launch.environment.contentSha256)
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
    append(']')
    append(",\"workingDirectorySha256\":\"").append(launch.workingDirectorySha256).append('"')
    append(",\"mergeError\":").append(launch.mergeError)
    append(",\"stagingRootsSha256\":\"").append(launch.stagingRootsSha256).append('"')
    append(",\"stagingRootCount\":").append(launch.stagingRootCount)
    append(",\"emptyDirectoriesSha256\":\"").append(launch.emptyDirectoriesSha256).append('"')
    append(",\"emptyDirectoryCount\":").append(launch.emptyDirectoryCount)
    append(",\"stdinDisposition\":").append(launch.stdinDisposition.jsonString()).append('}')
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
    append("\",\"configuredManifestSha256\":\"").append(mount.configuredManifestSha256)
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

internal fun digestCanonicalEvidenceMap(values: Map<String, String>): String = LengthDelimitedEvidenceDigest().apply {
    field("count", values.size.toString())
    values.toSortedMap().entries.forEachIndexed { index, (key, value) ->
        field("entry[$index].key", key)
        field("entry[$index].value", value)
    }
}.finish()

private fun digestReceiptEvidenceMap(values: Map<String, String>): String = ReceiptEvidenceDigest().apply {
    field("count", values.size.toString())
    values.toSortedMap().entries.forEachIndexed { index, (key, value) ->
        field("entry[$index].key", key)
        field("entry[$index].value", value)
    }
}.finish()

private fun digestReceiptFilesystemAudit(values: List<AcpFilesystemAuditRecord>): String =
    ReceiptEvidenceDigest().apply {
        field("count", values.size.toString())
        values.forEachIndexed { index, record ->
            field("record[$index].sequence", record.sequence.toString())
            field("record[$index].sessionId", record.sessionId)
            field("record[$index].method", record.method)
            field("record[$index].requestedPathSha256", record.requestedPathSha256)
            field("record[$index].policyPath.rootId", record.policyPath?.rootId)
            field("record[$index].policyPath.relativePath", record.policyPath?.relativePath)
            field("record[$index].outcome", record.outcome.name)
            field("record[$index].reason", record.reason.name)
        }
    }.finish()

private fun digestReceiptTerminalAudit(values: List<AcpTerminalAuditRecord>): String =
    ReceiptEvidenceDigest().apply {
        field("count", values.size.toString())
        values.forEachIndexed { index, record ->
            field("record[$index].sequence", record.sequence.toString())
            field("record[$index].sessionId", record.sessionId)
            field("record[$index].method", record.method)
            field("record[$index].requestSha256", record.requestSha256)
            field("record[$index].terminalIdSha256", record.terminalIdSha256)
            field("record[$index].toolCallIdSha256", record.toolCallIdSha256)
            field("record[$index].outcome", record.outcome.name)
            field("record[$index].reason", record.reason.name)
            field("record[$index].networkIsolated", record.networkIsolated.toString())
            field("record[$index].retainedOutputBytes", record.retainedOutputBytes?.toString())
            field("record[$index].producedOutputBytes", record.producedOutputBytes?.toString())
            field("record[$index].outputTruncated", record.outputTruncated?.toString())
        }
    }.finish()

private fun digestReceiptPermissionAudit(values: List<AcpPermissionAuditRecord>): String =
    ReceiptEvidenceDigest().apply {
        field("count", values.size.toString())
        values.forEachIndexed { index, record ->
            field("record[$index].sequence", record.sequence.toString())
            field("record[$index].sessionId", record.sessionId)
            field("record[$index].toolCallIdSha256", record.toolCallIdSha256)
            field("record[$index].offeredOptionCount", record.offeredOptionCount.toString())
            field("record[$index].selectedOptionIdSha256", record.selectedOptionIdSha256)
            field("record[$index].selectedKind", record.selectedKind?.name)
            field("record[$index].outcome", record.outcome.name)
            field("record[$index].reason", record.reason.name)
            field("record[$index].authorityExpanded", record.authorityExpanded.toString())
        }
    }.finish()

private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
    .digest(strictUtf8(value))
    .joinToString("") { "%02x".format(it) }

private fun utf8Bytes(value: String): Int = strictUtf8(value).size

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

private class ReceiptEvidenceDigest {
    private val digest = MessageDigest.getInstance("SHA-256")

    fun field(name: String, value: String?) {
        component(receiptCommitmentBytes(name))
        if (value == null) {
            digest.update(0.toByte())
        } else {
            digest.update(1.toByte())
            component(receiptCommitmentBytes(value))
        }
    }

    fun finish(): String = digest.digest().joinToString("") { "%02x".format(it) }

    private fun component(bytes: ByteArray) {
        digest.update(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(bytes.size.toLong()).array())
        digest.update(bytes)
    }
}

private fun java.time.Duration.exactEvidenceNanoseconds(): String =
    BigInteger.valueOf(seconds)
        .multiply(BigInteger.valueOf(1_000_000_000L))
        .add(BigInteger.valueOf(nano.toLong()))
        .toString()

private fun releaseOutcomeTextIsUtf8(result: AgentExecutionResult): Boolean {
    val session = result.session ?: return false
    return result.summary?.isReceiptUtf8() != false &&
        session.harnessId.isReceiptUtf8() && session.sessionId.isReceiptUtf8() &&
        session.resumeReference?.isReceiptUtf8() != false &&
        result.changes.all { change ->
            change.path.rootId.isReceiptUtf8() && change.path.relativePath.isReceiptUtf8()
        }
}

private fun releaseProviderTextIsUtf8(acp: AcpInvocationEvidenceSnapshot): Boolean {
    val agent = acp.negotiatedAgent ?: return false
    val diagnostics = acp.diagnostics ?: return false
    val sandbox = acp.sandboxEvidence ?: return false
    return agent.implementationName.isReceiptUtf8() &&
        agent.implementationVersion.isReceiptUtf8() &&
        agent.implementationTitle?.isReceiptUtf8() != false &&
        diagnostics.stderr.isReceiptUtf8() && diagnostics.containment.isReceiptUtf8() &&
        acp.filesystemAudit.all { record ->
            record.sessionId.isReceiptUtf8() && record.method.isReceiptUtf8() &&
                record.requestedPathSha256.isReceiptUtf8() &&
                record.policyPath?.let { it.rootId.isReceiptUtf8() && it.relativePath.isReceiptUtf8() } != false
        } &&
        acp.terminalAudit.all { record ->
            record.sessionId.isReceiptUtf8() && record.method.isReceiptUtf8() &&
                record.requestSha256.isReceiptUtf8() && record.terminalIdSha256?.isReceiptUtf8() != false &&
                record.toolCallIdSha256?.isReceiptUtf8() != false
        } &&
        acp.permissionAudit.all { record ->
            record.sessionId.isReceiptUtf8() && record.toolCallIdSha256.isReceiptUtf8() &&
                record.selectedOptionIdSha256?.isReceiptUtf8() != false
        } &&
        sandbox.provider.isReceiptUtf8() && sandbox.providerVersion.isReceiptUtf8()
}

private fun String.isReceiptUtf8(): Boolean = receiptCommitmentBytes(this).firstOrNull() != 0xff.toByte()

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

private val ACP_RECEIPT_BINDING_ROOT_FIELDS = setOf(
    "schemaVersion", "kind", "request", "provider", "lifecycle", "factoryProvenance",
    "protocol", "agent", "session", "events", "outcome", "policyAudits", "process", "sandbox",
)
private val ACP_RECEIPT_BINDING_REQUEST_FIELDS = setOf(
    "contractVersion", "requestSha256", "accessPolicySha256", "objective", "promptSha256",
    "wirePromptSha256", "workspaceRootIds", "contextInputIds", "filesystemCapabilityEnabled",
    "terminalCapabilityEnabled", "maximumTurns", "maximumToolCalls", "maximumOutputBytes",
    "wallClockTimeoutNanos", "idleTimeoutNanos", "maximumInputTokens", "maximumOutputTokens",
)
private val ACP_RECEIPT_BINDING_LIFECYCLE_FIELDS = setOf(
    "phaseReached", "cleanupDisposition", "filesystemAuditComplete", "terminalAuditComplete",
    "permissionAuditComplete", "releaseComplete",
)
private val ACP_RECEIPT_BINDING_CHANGE_SET_FIELDS = setOf(
    "observedCount", "retainedCount", "complete", "aggregateSha256", "records",
)
private val ACP_RECEIPT_BINDING_FACTORY_FIELDS = setOf(
    "descriptor", "harness", "implementationId", "agentExecutionContractVersion",
    "configurationSha256", "deprecated",
)
private val ACP_RECEIPT_BINDING_PROTOCOL_FIELDS = setOf(
    "name", "version", "sdkVersion", "clientImplementation",
)
private val ACP_RECEIPT_PROVENANCE_ID = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
private val ACP_RECEIPT_STOP_REASONS = AgentStopReason.entries.mapTo(linkedSetOf()) { it.name.wireName() }
private val ACP_RECEIPT_FAILURE_KINDS = AgentFailureKind.entries.mapTo(linkedSetOf()) { it.name.wireName() }
private val ACP_RECEIPT_BINDING_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_ARCHIVED_EVIDENCE_BYTES,
    maximumCanonicalBytes = MAXIMUM_ARCHIVED_EVIDENCE_BYTES,
    maximumDepth = 64,
    maximumNodes = 1_000_000,
    maximumStringBytes = 16 * 1024 * 1024,
    maximumTotalStringBytes = MAXIMUM_ARCHIVED_EVIDENCE_BYTES,
)

private const val MAXIMUM_ARCHIVED_AGENT_EVENTS = 8_192
private const val MAXIMUM_ARCHIVED_RESULT_CHANGES = 8_192
private const val MAXIMUM_ARCHIVED_REQUEST_IDENTIFIERS = 1_024
private const val MAXIMUM_ARCHIVED_POLICY_AUDIT_RECORDS = 4_096
private const val MAXIMUM_ARCHIVED_EVENT_COMPONENTS = 32_768
private const val MAXIMUM_ARCHIVED_EVENT_PEER_BYTES = 16L * 1024 * 1024
private const val MAXIMUM_ARCHIVED_EVIDENCE_BYTES = 64 * 1024 * 1024
private const val MAXIMUM_ARCHIVED_OUTCOME_ISSUES = 4_096
private const val MAXIMUM_ARCHIVED_OUTCOME_MESSAGE_BYTES = 64 * 1024
private const val MAXIMUM_ARCHIVED_OUTCOME_ENTITY_IDS = 32_768
