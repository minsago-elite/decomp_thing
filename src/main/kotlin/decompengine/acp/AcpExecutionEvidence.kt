package decompengine.acp

import decompengine.agent.AgentExecutionProviderEvidence
import java.nio.charset.StandardCharsets
import java.util.Collections

/** Stable ACP-v1 capabilities retained from the successful initialize negotiation. */
data class AcpNegotiatedCapabilitiesEvidence(
    val loadSession: Boolean,
    val promptImage: Boolean,
    val promptAudio: Boolean,
    val promptEmbeddedContext: Boolean,
    val mcpHttp: Boolean,
    val mcpSse: Boolean,
    val sessionAdditionalDirectories: Boolean,
)

/**
 * Bounded identity returned by the ACP agent during initialize.
 *
 * These values are peer-controlled. Keeping the exact bounded values here lets the archival
 * layer bind their digests without exposing them as trusted factory identity or retaining an
 * unbounded peer string.
 */
data class AcpNegotiatedAgentEvidence(
    val protocolVersion: Int,
    val implementationName: String,
    val implementationVersion: String,
    val implementationTitle: String?,
    val capabilities: AcpNegotiatedCapabilitiesEvidence,
) {
    init {
        require(protocolVersion == ACP_STABLE_PROTOCOL_VERSION) {
            "negotiated execution evidence must use stable ACP v1"
        }
        requireBoundedPeerIdentity("agent implementation name", implementationName, required = true)
        requireBoundedPeerIdentity("agent implementation version", implementationVersion, required = true)
        implementationTitle?.let {
            requireBoundedPeerIdentity("agent implementation title", it, required = false)
        }
    }
}

/**
 * One coherent post-execution snapshot. Collections are copied so a later turn cannot mutate the
 * audit trail being rendered for an earlier module.
 */
class AcpExecutionEvidenceSnapshot(
    val factoryProvenance: AcpHarnessProvenance,
    val negotiatedAgent: AcpNegotiatedAgentEvidence,
    /** Digest of the exact UTF-8 prompt bytes passed to the ACP SDK for this turn. */
    val wirePromptSha256: String,
    val diagnostics: AcpProcessDiagnostics,
    filesystemAudit: Collection<AcpFilesystemAuditRecord>,
    terminalAudit: Collection<AcpTerminalAuditRecord>,
    permissionAudit: Collection<AcpPermissionAuditRecord>,
    val sandboxEvidence: AcpSandboxEvidence,
) : AgentExecutionProviderEvidence {
    override val providerId: String = ACP_EXECUTION_EVIDENCE_PROVIDER_ID
    override val schemaVersion: Int = ACP_EXECUTION_EVIDENCE_SCHEMA_VERSION
    val filesystemAudit: List<AcpFilesystemAuditRecord> = immutableEvidenceList(filesystemAudit)
    val terminalAudit: List<AcpTerminalAuditRecord> = immutableEvidenceList(terminalAudit)
    val permissionAudit: List<AcpPermissionAuditRecord> = immutableEvidenceList(permissionAudit)

    init {
        require(factoryProvenance.harness == "acp" && !factoryProvenance.deprecated) {
            "ACP execution evidence requires supported ACP factory provenance"
        }
        require(factoryProvenance.acpProtocolVersion == negotiatedAgent.protocolVersion) {
            "factory and negotiated ACP protocol versions differ"
        }
        require(factoryProvenance.implementationId.isNotBlank()) {
            "ACP execution evidence is missing its configured implementation identity"
        }
        require(wirePromptSha256.isLowercaseSha256()) {
            "ACP execution evidence is missing the exact wire-prompt digest"
        }
        require(diagnostics.remainingProcessIds.isEmpty() && diagnostics.sandboxCleanupVerified) {
            "successful ACP execution evidence requires proven process and sandbox cleanup"
        }
        require(this.filesystemAudit.size <= MAXIMUM_ARCHIVED_POLICY_AUDIT_RECORDS) {
            "filesystem audit exceeds the archival evidence bound"
        }
        require(this.terminalAudit.size <= MAXIMUM_ARCHIVED_POLICY_AUDIT_RECORDS) {
            "terminal audit exceeds the archival evidence bound"
        }
        require(this.permissionAudit.size <= MAXIMUM_ARCHIVED_POLICY_AUDIT_RECORDS) {
            "permission audit exceeds the archival evidence bound"
        }
    }
}

/** Furthest lifecycle boundary reached by one ACP invocation. Values are monotonic. */
enum class AcpExecutionLifecyclePhase {
    REQUEST_BOUND,
    WORKSPACE_SNAPSHOT,
    SANDBOX_LAUNCH,
    SANDBOX_STARTED,
    INITIALIZE,
    INITIALIZED,
    SESSION_CREATED,
    PROMPT_DISPATCHED,
    PROMPT_COMPLETED,
    FINAL_WORKSPACE_SNAPSHOT,
}

/** Whether process and sandbox cleanup was necessary and, when necessary, proven. */
enum class AcpExecutionCleanupDisposition { NOT_REQUIRED, VERIFIED, UNVERIFIED }

/** Explicit completeness markers for independently bounded ACP policy recorders. */
data class AcpExecutionEvidenceCompleteness(
    val filesystemAuditComplete: Boolean,
    val terminalAuditComplete: Boolean,
    val permissionAuditComplete: Boolean,
) {
    val allPolicyAuditsComplete: Boolean
        get() = filesystemAuditComplete && terminalAuditComplete && permissionAuditComplete
}

/**
 * Provider evidence returned with every ordinary ACP terminal outcome.
 *
 * Unlike [AcpExecutionEvidenceSnapshot], this value deliberately represents partial invocations:
 * cancellation may happen before launch, negotiation may fail, and teardown itself may be
 * unverified. Optional values therefore mean "not reached or not captured", never success.
 */
class AcpInvocationEvidenceSnapshot(
    val factoryProvenance: AcpHarnessProvenance?,
    val phaseReached: AcpExecutionLifecyclePhase,
    val cleanupDisposition: AcpExecutionCleanupDisposition,
    val negotiatedAgent: AcpNegotiatedAgentEvidence?,
    /** Present only after these exact UTF-8 bytes were dispatched to the ACP SDK. */
    val wirePromptSha256: String?,
    val diagnostics: AcpProcessDiagnostics?,
    filesystemAudit: Collection<AcpFilesystemAuditRecord>,
    terminalAudit: Collection<AcpTerminalAuditRecord>,
    permissionAudit: Collection<AcpPermissionAuditRecord>,
    val sandboxEvidence: AcpSandboxEvidence?,
    val completeness: AcpExecutionEvidenceCompleteness,
    /** Existing schema-v1 archive view, available only when all of its strict invariants hold. */
    val completeExecutionEvidence: AcpExecutionEvidenceSnapshot?,
) : AgentExecutionProviderEvidence {
    override val providerId: String = ACP_EXECUTION_EVIDENCE_PROVIDER_ID
    override val schemaVersion: Int = ACP_INVOCATION_EVIDENCE_SCHEMA_VERSION
    val filesystemAudit: List<AcpFilesystemAuditRecord> = immutableEvidenceList(filesystemAudit)
    val terminalAudit: List<AcpTerminalAuditRecord> = immutableEvidenceList(terminalAudit)
    val permissionAudit: List<AcpPermissionAuditRecord> = immutableEvidenceList(permissionAudit)

    init {
        factoryProvenance?.let { provenance ->
            require(provenance.harness == "acp" && !provenance.deprecated) {
                "ACP invocation evidence has unsupported factory provenance"
            }
        }
        require(wirePromptSha256 == null || wirePromptSha256.isLowercaseSha256()) {
            "ACP invocation evidence wire-prompt digest is invalid"
        }
        require(
            phaseReached >= AcpExecutionLifecyclePhase.PROMPT_DISPATCHED || wirePromptSha256 == null,
        ) { "ACP invocation evidence claims a wire prompt before prompt dispatch" }
        require(cleanupDisposition != AcpExecutionCleanupDisposition.VERIFIED ||
            diagnostics?.let { it.remainingProcessIds.isEmpty() && it.sandboxCleanupVerified } == true
        ) { "verified ACP cleanup is missing complete process diagnostics" }
        require(cleanupDisposition != AcpExecutionCleanupDisposition.NOT_REQUIRED || diagnostics == null) {
            "ACP invocation evidence has diagnostics for a process that did not require cleanup"
        }
        require(this.filesystemAudit.size <= MAXIMUM_ARCHIVED_POLICY_AUDIT_RECORDS) {
            "filesystem audit exceeds the invocation evidence bound"
        }
        require(this.terminalAudit.size <= MAXIMUM_ARCHIVED_POLICY_AUDIT_RECORDS) {
            "terminal audit exceeds the invocation evidence bound"
        }
        require(this.permissionAudit.size <= MAXIMUM_ARCHIVED_POLICY_AUDIT_RECORDS) {
            "permission audit exceeds the invocation evidence bound"
        }
        completeExecutionEvidence?.let { complete ->
            require(cleanupDisposition == AcpExecutionCleanupDisposition.VERIFIED &&
                completeness.allPolicyAuditsComplete
            ) { "complete ACP archive evidence requires verified cleanup and complete audits" }
            require(factoryProvenance == complete.factoryProvenance &&
                negotiatedAgent == complete.negotiatedAgent &&
                wirePromptSha256 == complete.wirePromptSha256 &&
                diagnostics == complete.diagnostics &&
                sandboxEvidence == complete.sandboxEvidence &&
                this.filesystemAudit == complete.filesystemAudit &&
                this.terminalAudit == complete.terminalAudit &&
                this.permissionAudit == complete.permissionAudit
            ) { "complete ACP archive evidence differs from its invocation evidence" }
        }
    }
}

/** Implemented by ACP harnesses that can publish a coherent snapshot after a successful turn. */
@Deprecated("Use the invocation-bound AgentHarness.executeReceipt result")
interface AcpExecutionEvidenceSource {
    fun latestAcpExecutionEvidence(): AcpExecutionEvidenceSnapshot?
}

private fun requireBoundedPeerIdentity(label: String, value: String, required: Boolean) {
    require(!required || value.isNotBlank()) { "$label must not be blank" }
    require(value.toByteArray(StandardCharsets.UTF_8).size <= MAXIMUM_NEGOTIATED_IDENTITY_BYTES) {
        "$label exceeds the archival evidence byte bound"
    }
}

private fun <T> immutableEvidenceList(values: Collection<T>): List<T> =
    Collections.unmodifiableList(ArrayList(values))

private fun String.isLowercaseSha256(): Boolean =
    length == 64 && all { character -> character in '0'..'9' || character in 'a'..'f' }

private const val MAXIMUM_NEGOTIATED_IDENTITY_BYTES = 4 * 1024
private const val MAXIMUM_ARCHIVED_POLICY_AUDIT_RECORDS = 4_096
private const val ACP_EXECUTION_EVIDENCE_PROVIDER_ID = "acp"
private const val ACP_EXECUTION_EVIDENCE_SCHEMA_VERSION = 1
private const val ACP_INVOCATION_EVIDENCE_SCHEMA_VERSION = 2
