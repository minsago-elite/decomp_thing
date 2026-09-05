package decompengine.acp

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Collections
import java.util.Locale

/**
 * Bounded production workflow profiles understood by the operator preflight.
 *
 * Current model-driven workflows all use the captured read/replace filesystem bridge and do not
 * grant the agent terminal execution. Keeping the profiles explicit prevents a future workflow
 * capability from being silently omitted from `doctor`.
 */
enum class AcpPreflightWorkflow(
    val cliName: String,
    internal val filesystemRead: Boolean,
    internal val filesystemWrite: Boolean,
    internal val terminal: Boolean,
    requiredAgentCapabilities: Collection<AcpRequiredAgentCapability> = emptySet(),
) {
    ALL("all", filesystemRead = true, filesystemWrite = true, terminal = false),
    PATCH("patch", filesystemRead = true, filesystemWrite = true, terminal = false),
    RECONSTRUCT("reconstruct", filesystemRead = true, filesystemWrite = true, terminal = false),
    REPAIR("repair", filesystemRead = true, filesystemWrite = true, terminal = false),
    WEB("web", filesystemRead = true, filesystemWrite = true, terminal = false),
    ;

    internal val requiredAgentCapabilities: Set<AcpRequiredAgentCapability> =
        Collections.unmodifiableSet(LinkedHashSet(requiredAgentCapabilities))

    companion object {
        fun parse(value: String): AcpPreflightWorkflow = entries.singleOrNull { it.cliName == value }
            ?: throw IllegalArgumentException(
                "unknown doctor workflow (expected exactly all, patch, reconstruct, repair, or web)",
            )
    }
}

/**
 * Non-secret proof returned only after initialize negotiation and complete sandbox cleanup.
 * Peer-controlled implementation text is represented by a digest in the stable descriptor.
 */
class AcpAgentPreflightResult internal constructor(
    val workflow: AcpPreflightWorkflow,
    val authentication: AcpAuthenticationInventory,
    val negotiatedAgent: AcpNegotiatedAgentEvidence,
    requiredAgentCapabilities: Collection<AcpRequiredAgentCapability>,
    val diagnostics: AcpProcessDiagnostics,
    val sandboxEvidence: AcpSandboxEvidence,
) {
    val requiredAgentCapabilities: Set<AcpRequiredAgentCapability> =
        Collections.unmodifiableSet(LinkedHashSet(requiredAgentCapabilities))

    val negotiatedIdentitySha256: String = negotiatedIdentitySha256(negotiatedAgent)

    init {
        require(negotiatedAgent.protocolVersion == ACP_STABLE_PROTOCOL_VERSION) {
            "ACP preflight must negotiate stable protocol v1"
        }
        require(diagnostics.remainingProcessIds.isEmpty() && diagnostics.sandboxCleanupVerified) {
            "ACP preflight requires proven process-tree and sandbox cleanup"
        }
        require(!diagnostics.outputLimitExceeded) {
            "ACP preflight exceeded its bounded produced-output allowance"
        }
        require(diagnostics.networkIsolated && sandboxEvidence.networkIsolated) {
            "ACP preflight requires network-isolated production containment"
        }
        require(sandboxEvidence.outerAgentContained) {
            "ACP preflight requires the production outer-agent containment boundary"
        }
    }

    /** Stable, bounded, and safe to print without exposing agent environment values or peer text. */
    val stableDescriptor: String = listOf(
        "acp-preflight-v1",
        "workflow-${workflow.cliName}",
        "protocol-${negotiatedAgent.protocolVersion}",
        "agent-identity-sha256-$negotiatedIdentitySha256",
        "required-${requiredAgentCapabilities.sortedBy { it.diagnosticName }.joinToString(",") { it.diagnosticName }.ifEmpty { "none" }}",
        "agent-capabilities-${negotiatedAgent.capabilities.stableBits()}",
        "auth-methods-${authentication.methods.size}",
        "auth-inventory-sha256-${authentication.sha256}",
        "client-fs-read-${workflow.filesystemRead}",
        "client-fs-write-${workflow.filesystemWrite}",
        "client-terminal-${workflow.terminal}",
        "containment-${diagnostics.containment.lowercase(Locale.ROOT)}",
        "network-isolated-${diagnostics.networkIsolated}",
        "cleanup-verified-${diagnostics.sandboxCleanupVerified}",
    ).joinToString(":")
}

private fun AcpNegotiatedCapabilitiesEvidence.stableBits(): String = listOf(
    loadSession,
    promptImage,
    promptAudio,
    promptEmbeddedContext,
    mcpHttp,
    mcpSse,
    sessionAdditionalDirectories,
).joinToString("") { if (it) "1" else "0" }

private fun negotiatedIdentitySha256(agent: AcpNegotiatedAgentEvidence): String {
    val digest = MessageDigest.getInstance("SHA-256")
    listOf(agent.implementationName, agent.implementationVersion, agent.implementationTitle).forEach { value ->
        if (value == null) {
            digest.update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(-1).array())
        } else {
            val encoded = value.toByteArray(StandardCharsets.UTF_8)
            digest.update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(encoded.size).array())
            digest.update(encoded)
        }
    }
    return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
}
