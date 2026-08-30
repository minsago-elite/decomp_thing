package decompengine.acp

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
    val diagnostics: AcpProcessDiagnostics,
    filesystemAudit: Collection<AcpFilesystemAuditRecord>,
    terminalAudit: Collection<AcpTerminalAuditRecord>,
    permissionAudit: Collection<AcpPermissionAuditRecord>,
    val sandboxEvidence: AcpSandboxEvidence,
) {
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

/** Implemented by ACP harnesses that can publish a coherent snapshot after a successful turn. */
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

private const val MAXIMUM_NEGOTIATED_IDENTITY_BYTES = 4 * 1024
private const val MAXIMUM_ARCHIVED_POLICY_AUDIT_RECORDS = 4_096
