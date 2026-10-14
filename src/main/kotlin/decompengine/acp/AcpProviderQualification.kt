package decompengine.acp

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Duration

/**
 * Opaque, nonserializable authority. A subtype or a reflected constructor is not a permit: the
 * factory's private identity registry must own the exact instance, consumer, and purpose.
 * There is deliberately no callable fixture issuer in this checkpoint.
 */
internal sealed class AcpProviderQualificationPermit protected constructor()

internal enum class AcpProviderQualificationPurpose {
    PROCESS_CONFIGURATION,
    FIXTURE_POLICY,
    INVOCATION_EVIDENCE,
    GUARDIAN_LAUNCH_DESCRIPTOR,
}

/** Closed credential-free profile; none of its authority is selected by operator input. */
internal class AcpProviderQualificationProfile private constructor() {
    val model: String = "acp-fixture-model-v1"
    val reasoning: AcpProviderReasoning = AcpProviderReasoning.LOW
    val bounds: AcpProviderTransportBounds = AcpProviderTransportBounds(
        maximumRequestBytes = 8 * 1024,
        maximumResponseBytes = 64 * 1024,
        maximumHeaderBytes = 4 * 1024,
        maximumHeaderFields = 16,
        maximumChunkBytes = 4 * 1024,
        maximumQueuedChunks = 2,
        maximumRequests = 1,
        maximumOutputTokens = 32,
        overallTimeout = Duration.ofSeconds(10),
        idleTimeout = Duration.ofSeconds(3),
        cleanupTimeout = Duration.ofSeconds(3),
    )
    val maximumProcesses: Int = 32
    val maximumOpenFiles: Int = 128
    val maximumAddressSpaceBytes: Long = 2_147_483_648L
    val descriptorSha256: String = MessageDigest.getInstance("SHA-256").digest(
        listOf(
            "acp-provider-credential-free-profile-v1", model, reasoning.name,
            bounds.maximumRequestBytes, bounds.maximumResponseBytes, bounds.maximumHeaderBytes,
            bounds.maximumHeaderFields, bounds.maximumChunkBytes, bounds.maximumQueuedChunks,
            bounds.maximumRequests, bounds.maximumOutputTokens, bounds.overallTimeout.toMillis(),
            bounds.idleTimeout.toMillis(), bounds.cleanupTimeout.toMillis(),
            maximumProcesses, maximumOpenFiles, maximumAddressSpaceBytes,
        ).joinToString("\n", postfix = "\n").toByteArray(StandardCharsets.UTF_8),
    ).joinToString("") { "%02x".format(it) }

    internal fun requireSandboxResourceLimits(limits: AcpSandboxResourceLimits) {
        require(
            limits.maximumProcesses == maximumProcesses &&
                limits.maximumOpenFiles == maximumOpenFiles &&
                limits.maximumAddressSpaceBytes == maximumAddressSpaceBytes,
        ) { "provider qualification requires the exact 32 task, 128 FD, 2 GiB resource profile" }
    }

    companion object {
        internal val CREDENTIAL_FREE: AcpProviderQualificationProfile = AcpProviderQualificationProfile()
    }
}

/*
 * Task 5's boundary-owned guardian descriptor must bind the packaged guardian digest/manifest,
 * exact child and Codex executable mounts/manifests, ordered argv digest, configuration digest,
 * and the fixed sandbox-private state-root identity. This profile provides no executable,
 * launcher, containment, endpoint, credential, or arbitrary backend selection.
 */
