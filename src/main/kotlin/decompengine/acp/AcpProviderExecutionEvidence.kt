package decompengine.acp

import java.util.Collections
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/** Closed public classifications; no endpoint, credential reference, or capability is archived. */
enum class AcpProviderExecutionAuthority { CREDENTIAL_FREE_LOOPBACK_TLS_V1, CODEX_CHATGPT_RESPONSES_UNQUALIFIED }
enum class AcpProviderExecutionTerminal {
    COMPLETED, AUTHENTICATION, AUTHORIZATION, RESOURCE_EXHAUSTED, TIMEOUT, CANCELLED,
    UNSUPPORTED_OPERATION, UNSUPPORTED_MODEL, MALFORMED_REQUEST, MALFORMED_RESPONSE,
    TRANSPORT, REVOKED, SECRET_EXPOSURE,
}

enum class AcpProviderGuardianTeardownCause {
    NATURAL_EXIT, BOUNDED_SHUTDOWN, BOUNDED_CANCELLATION, BOUNDED_FAILURE,
    EMERGENCY, TIMED_OUT, UNKNOWN, UNOBSERVED,
}

enum class AcpProviderChildExitKind { EXITED, SIGTERM, SIGKILL, OTHER_SIGNAL, UNOBSERVED }

/** Historical schema-v3/v4 descriptor metadata; canonical digests do not prove a launch closure. */
data class AcpProviderExecutionDescriptorEvidence(
    val factoryConfigurationSha256: String,
    val qualificationIssuerSha256: String,
    val qualificationConsumerSha256: String,
    val guardianExecutableSha256: String,
    val guardianManifestSha256: String,
    val childExecutableSha256: String,
    val childManifestSha256: String,
    val codexExecutableSha256: String,
    val codexManifestSha256: String,
    val orderedArgumentsSha256: String,
    val privateStateRootSha256: String,
) {
    init {
        listOf(factoryConfigurationSha256, qualificationIssuerSha256, qualificationConsumerSha256,
            guardianExecutableSha256, guardianManifestSha256, childExecutableSha256, childManifestSha256,
            codexExecutableSha256, codexManifestSha256, orderedArgumentsSha256, privateStateRootSha256,
        ).forEach(::requireProviderEvidenceDigest)
    }
}

/** Closed schema-v5 archive owner commitments, independently checked against receipt facts.
 * Launch closure digests remain unproved archive provenance and are deliberately absent here.
 * The live launch descriptor and historical descriptor metadata above are separate contracts.
 */
data class AcpProviderExecutionOwnerEvidence(
    val factoryConfigurationSha256: String,
    val qualificationIssuerSha256: String,
    val qualificationConsumerSha256: String,
) {
    init {
        listOf(factoryConfigurationSha256, qualificationIssuerSha256, qualificationConsumerSha256)
            .forEach(::requireProviderEvidenceDigest)
    }
}

/** Declared limits and independently observed kernel limits; absent observations stay absent. */
data class AcpProviderExecutionResourceEvidence(
    val maximumProcesses: Int = 32,
    val maximumOpenFiles: Int = 128,
    val maximumAddressSpaceBytes: Long = 2_147_483_648L,
    val maximumMemoryBytes: Long = 2_147_483_648L,
    val maximumSwapBytes: Long = 0L,
    val observedMaximumProcesses: Int? = null,
    val observedMaximumOpenFiles: Int? = null,
    val observedMaximumAddressSpaceBytes: Long? = null,
    val observedMaximumMemoryBytes: Long? = null,
    val observedMaximumSwapBytes: Long? = null,
    val observedTaskPeak: Int? = null,
) {
    val observationsComplete: Boolean get() =
        observedMaximumProcesses != null && observedMaximumOpenFiles != null &&
            observedMaximumAddressSpaceBytes != null && observedMaximumMemoryBytes != null &&
            observedMaximumSwapBytes != null && observedTaskPeak != null

    val enforcementVerified: Boolean get() =
        observedMaximumProcesses == maximumProcesses && observedMaximumOpenFiles == maximumOpenFiles &&
        observedMaximumAddressSpaceBytes == maximumAddressSpaceBytes &&
        observedMaximumMemoryBytes == maximumMemoryBytes && observedMaximumSwapBytes == maximumSwapBytes
    val taskHeadroomVerified: Boolean get() = enforcementVerified &&
        observedTaskPeak?.let { it in 1 until maximumProcesses } == true

    init {
        require(maximumProcesses == 32 && maximumOpenFiles == 128 &&
            maximumAddressSpaceBytes == 2_147_483_648L && maximumMemoryBytes == 2_147_483_648L &&
            maximumSwapBytes == 0L
        ) { "ACP provider evidence resource profile is unsupported" }
        require(listOf(observedMaximumProcesses, observedMaximumOpenFiles, observedTaskPeak)
            .all { it == null || it >= 0 } &&
            listOf(observedMaximumAddressSpaceBytes, observedMaximumMemoryBytes, observedMaximumSwapBytes)
                .all { it == null || it >= 0 }
        ) { "ACP provider resource observation is invalid" }
    }
}

/** Exact child outcome and terminal cleanup observations, distinct from a successful model turn. */
data class AcpProviderGuardianCleanupEvidence(
    val disposition: AcpExecutionCleanupDisposition,
    val teardownCause: AcpProviderGuardianTeardownCause,
    val sigtermSent: Boolean,
    val sigkillSent: Boolean,
    val childExitKind: AcpProviderChildExitKind,
    val childExitStatus: Int?,
    val childTerminationSignal: Int?,
    val childReaped: Boolean,
    val finalEchildObserved: Boolean,
    val remainingDescendants: Int?,
    val cgroupRemoved: Boolean,
    val privateStateRemoved: Boolean,
    val descriptorsClosed: Boolean,
) {
    init {
        require(remainingDescendants == null || remainingDescendants in 0..32) {
            "ACP provider cleanup descendant observation is invalid"
        }
        require(childExitStatus == null || childExitStatus in 0..255) {
            "ACP provider cleanup exit status is invalid"
        }
        require(childTerminationSignal == null || childTerminationSignal in 1..64) {
            "ACP provider cleanup signal is invalid"
        }
        require(when (childExitKind) {
            AcpProviderChildExitKind.EXITED -> childExitStatus != null && childTerminationSignal == null
            AcpProviderChildExitKind.SIGTERM -> childExitStatus == null && childTerminationSignal == 15
            AcpProviderChildExitKind.SIGKILL -> childExitStatus == null && childTerminationSignal == 9
            AcpProviderChildExitKind.OTHER_SIGNAL -> childExitStatus == null &&
                childTerminationSignal != null && childTerminationSignal != 9 && childTerminationSignal != 15
            AcpProviderChildExitKind.UNOBSERVED -> childExitStatus == null && childTerminationSignal == null
        }) { "ACP provider cleanup child outcome is inconsistent" }
        require(teardownCause != AcpProviderGuardianTeardownCause.NATURAL_EXIT ||
            (childExitKind == AcpProviderChildExitKind.EXITED && !sigtermSent && !sigkillSent)
        ) { "ACP provider cleanup natural teardown has no natural child exit" }
        val expectedTeardown = teardownCause in setOf(
            AcpProviderGuardianTeardownCause.NATURAL_EXIT, AcpProviderGuardianTeardownCause.BOUNDED_SHUTDOWN,
            AcpProviderGuardianTeardownCause.BOUNDED_CANCELLATION, AcpProviderGuardianTeardownCause.BOUNDED_FAILURE,
        )
        require(disposition != AcpExecutionCleanupDisposition.VERIFIED ||
            (expectedTeardown && childExitKind != AcpProviderChildExitKind.UNOBSERVED &&
                childReaped && finalEchildObserved && remainingDescendants == 0 && cgroupRemoved &&
                privateStateRemoved && descriptorsClosed)
        ) { "ACP provider verified guardian cleanup lacks terminal observations" }
        require(disposition != AcpExecutionCleanupDisposition.NOT_REQUIRED ||
            (teardownCause == AcpProviderGuardianTeardownCause.UNOBSERVED &&
                childExitKind == AcpProviderChildExitKind.UNOBSERVED && !sigtermSent && !sigkillSent &&
                !childReaped && !finalEchildObserved && remainingDescendants == null &&
                !cgroupRemoved && !privateStateRemoved && !descriptorsClosed)
        ) { "ACP provider cleanup was observed despite not-required disposition" }
    }
}

/** All owners must finish before invocation admission can be released. */
data class AcpProviderExecutionCleanupEvidence(
    val disposition: AcpExecutionCleanupDisposition,
    val router: AcpExecutionCleanupDisposition,
    val broker: AcpExecutionCleanupDisposition,
    val guardian: AcpProviderGuardianCleanupEvidence,
    val sandbox: AcpExecutionCleanupDisposition,
) {
    val admissionSticky: Boolean get() = disposition == AcpExecutionCleanupDisposition.UNVERIFIED

    init {
        val components = listOf(router, broker, guardian.disposition, sandbox)
        require(disposition != AcpExecutionCleanupDisposition.VERIFIED ||
            (components.none { it == AcpExecutionCleanupDisposition.UNVERIFIED } &&
                components.any { it == AcpExecutionCleanupDisposition.VERIFIED })
        ) { "ACP provider aggregate cleanup contains an unverified owner" }
        require(disposition != AcpExecutionCleanupDisposition.NOT_REQUIRED ||
            components.all { it == AcpExecutionCleanupDisposition.NOT_REQUIRED }
        ) { "ACP provider aggregate cleanup incorrectly claims not-required" }
        require(components.none { it == AcpExecutionCleanupDisposition.UNVERIFIED } ||
            disposition == AcpExecutionCleanupDisposition.UNVERIFIED
        ) { "ACP provider failed owner cleanup must remain sticky" }
    }
}

/** One terminal exchange. Only commitments and bounded usage cross the host broker boundary. */
data class AcpProviderExecutionRequestEvidence(
    val sequence: Long,
    val sessionSha256: String,
    val turnSha256: String,
    val admittedBodySha256: String,
    val wireBodySha256: String,
    val wireRequestBytes: Int,
    val responseBytes: Long,
    val responseSha256: String,
    val inputTokens: Int?,
    val outputTokens: Int?,
    /** Usage admitted into the invocation budget; reported usage may exist on a denied terminal. */
    val admittedOutputTokens: Int,
    val terminal: AcpProviderExecutionTerminal,
) {
    init {
        require(sequence in 1..64) { "ACP provider request sequence is invalid" }
        listOf(sessionSha256, turnSha256, admittedBodySha256, wireBodySha256, responseSha256)
            .forEach(::requireProviderEvidenceDigest)
        require(wireRequestBytes in 1..(MAXIMUM_PROVIDER_FRAME_PAYLOAD_BYTES - PROVIDER_INVOCATION_CAPABILITY_BYTES) &&
            responseBytes in 0..(64 * 1024 * 1024L)
        ) { "ACP provider request byte observation is invalid" }
        require(inputTokens == null || inputTokens in 0..Int.MAX_VALUE) {
            "ACP provider request input usage is invalid"
        }
        require(outputTokens == null || outputTokens in 0..65_536) {
            "ACP provider request output usage is invalid"
        }
        require(admittedOutputTokens in 0..65_536 &&
            (admittedOutputTokens == 0 || admittedOutputTokens == outputTokens)
        ) { "ACP provider request admitted usage is inconsistent" }
        require(terminal != AcpProviderExecutionTerminal.COMPLETED ||
            (responseBytes > 0 && outputTokens != null && admittedOutputTokens == outputTokens)
        ) {
            "ACP provider completed request lacks output usage"
        }
    }
}

data class AcpProviderExecutionDenialEvidence(val sequence: Long, val terminal: AcpProviderExecutionTerminal) {
    init {
        require(terminal in setOf(AcpProviderExecutionTerminal.RESOURCE_EXHAUSTED,
            AcpProviderExecutionTerminal.TIMEOUT, AcpProviderExecutionTerminal.CANCELLED,
            AcpProviderExecutionTerminal.UNSUPPORTED_OPERATION, AcpProviderExecutionTerminal.UNSUPPORTED_MODEL,
            AcpProviderExecutionTerminal.MALFORMED_REQUEST, AcpProviderExecutionTerminal.TRANSPORT,
            AcpProviderExecutionTerminal.REVOKED, AcpProviderExecutionTerminal.SECRET_EXPOSURE)) {
            "ACP provider denial is not a pre-dispatch terminal"
        }
    }
}

/**
 * Immutable schema-v5 transport evidence. Live policy/authority identities are not archived:
 * their issuance cannot be reconstructed independently from these public observations.
 * Unproved launch-closure digests are also absent from the formal owner projection.
 * This checkpoint archives no provider qualification or
 * billing claim. Even complete fixture cleanup is never a release-complete execution projection.
 */
class AcpProviderInvocationEvidenceSnapshot(
    val authority: AcpProviderExecutionAuthority,
    val qualificationProfileSha256: String,
    val modelSha256: String,
    val runtimeAdapter: AcpProviderRuntimeAdapter,
    val reasoning: AcpProviderReasoning,
    val descriptors: AcpProviderExecutionOwnerEvidence,
    val invocationBindingSha256: String,
    val requestBindingSha256: String,
    val sessionSha256: String?,
    val turnSha256: String?,
    val bounds: AcpProviderTransportBounds,
    val maximumInvocationOutputTokens: Int,
    val maximumInvocationInputTokens: Long?,
    val remainingOverallTimeoutMillis: Long,
    val resources: AcpProviderExecutionResourceEvidence,
    val wireRequestBytes: Long,
    val responseBytes: Long,
    val outputTokens: Long,
    val inputTokens: Long?,
    val revoked: Boolean,
    val admissionDenial: AcpProviderExecutionDenialEvidence?,
    requests: Collection<AcpProviderExecutionRequestEvidence>,
    val cleanup: AcpProviderExecutionCleanupEvidence,
) {
    val requests: List<AcpProviderExecutionRequestEvidence> =
        immutableProviderRequestEvidence(requests, bounds.maximumRequests)
    val credentialFreeFixture: Boolean = authority == AcpProviderExecutionAuthority.CREDENTIAL_FREE_LOOPBACK_TLS_V1
    val releaseComplete: Boolean = false
    val adapterQualified: Boolean = false
    val providerCostCancellationProven: Boolean = false

    init {
        listOf(qualificationProfileSha256, modelSha256, invocationBindingSha256, requestBindingSha256)
            .forEach(::requireProviderEvidenceDigest)
        sessionSha256?.let(::requireProviderEvidenceDigest)
        turnSha256?.let(::requireProviderEvidenceDigest)
        require((sessionSha256 == null) == (turnSha256 == null)) {
            "ACP provider session and turn bindings are incomplete"
        }
        require(maximumInvocationOutputTokens in 1..bounds.maximumOutputTokens &&
            (maximumInvocationInputTokens == null || maximumInvocationInputTokens > 0) &&
            remainingOverallTimeoutMillis in 1..bounds.overallTimeout.toMillis()
        ) { "ACP provider invocation budget is invalid" }
        require(this.requests.size <= bounds.maximumRequests) { "ACP provider evidence exceeds request bound" }
        require(this.requests.isEmpty() || sessionSha256 != null) { "ACP provider requests lack session binding" }
        require(this.requests.dropLast(1).all { it.terminal == AcpProviderExecutionTerminal.COMPLETED }) {
            "ACP provider request follows revoked authority"
        }
        this.requests.forEachIndexed { index, request ->
            require(request.sequence == index + 1L && request.sessionSha256 == sessionSha256 &&
                request.turnSha256 == turnSha256
            ) { "ACP provider request binding or ordering differs" }
            require(request.wireRequestBytes <= bounds.maximumRequestBytes &&
                request.responseBytes <= bounds.maximumResponseBytes &&
                (request.outputTokens == null || request.outputTokens <= bounds.maximumOutputTokens)
            ) { "ACP provider request observations exceed policy bounds" }
        }
        require(wireRequestBytes == this.requests.sumOf { it.wireRequestBytes.toLong() } &&
            wireRequestBytes in 0..bounds.maximumRequestBytes.toLong() &&
            responseBytes == this.requests.sumOf { it.responseBytes } &&
            responseBytes in 0..bounds.maximumResponseBytes.toLong() &&
            outputTokens == this.requests.sumOf { it.admittedOutputTokens.toLong() } &&
            outputTokens in 0..maximumInvocationOutputTokens.toLong()
        ) { "ACP provider aggregate byte or output usage differs" }
        require(if (this.requests.isEmpty() || this.requests.any { it.inputTokens == null }) inputTokens == null
            else inputTokens == this.requests.sumOf { requireNotNull(it.inputTokens).toLong() }
        ) { "ACP provider aggregate input usage differs" }
        require(maximumInvocationInputTokens == null || inputTokens == null ||
            inputTokens <= maximumInvocationInputTokens
        ) { "ACP provider input usage exceeds invocation budget" }
        require(maximumInvocationInputTokens == null ||
            this.requests.none { it.terminal == AcpProviderExecutionTerminal.COMPLETED && it.inputTokens == null }
        ) { "ACP provider completed request lacks input usage under invocation cap" }
        admissionDenial?.let {
            require(revoked) { "ACP provider denial did not revoke authority" }
        }
        require(cleanup.disposition == AcpExecutionCleanupDisposition.NOT_REQUIRED || revoked) {
            "ACP provider terminal cleanup retained model authority"
        }
        require(this.requests.isEmpty() || listOf(cleanup.router, cleanup.broker,
            cleanup.guardian.disposition, cleanup.sandbox).none { it == AcpExecutionCleanupDisposition.NOT_REQUIRED }
        ) { "ACP provider exchanges require every process and transport owner" }
    }

    internal fun requireQualificationProfile(profile: AcpProviderQualificationProfile) {
        require(credentialFreeFixture && qualificationProfileSha256 == profile.descriptorSha256 &&
            bounds == profile.bounds && reasoning == profile.reasoning &&
            modelSha256 == providerExecutionEvidenceSha256(profile.model)
        ) { "ACP provider evidence differs from its closed qualification profile" }
        require(descriptors.qualificationIssuerSha256 == providerExecutionEvidenceIssuerSha256(
            descriptors.factoryConfigurationSha256, profile.descriptorSha256,
        ) && descriptors.qualificationConsumerSha256 == providerExecutionEvidenceConsumerSha256(
            requestBindingSha256, invocationBindingSha256,
        )) { "ACP provider evidence owner commitments differ" }
    }

    override fun toString(): String = "AcpProviderInvocationEvidenceSnapshot(authority=$authority, requests=${requests.size}, cleanup=${cleanup.disposition}, releaseComplete=false)"
}

private fun immutableProviderRequestEvidence(
    values: Collection<AcpProviderExecutionRequestEvidence>,
    maximumRequests: Int,
): List<AcpProviderExecutionRequestEvidence> {
    require(values.size <= maximumRequests) { "ACP provider evidence exceeds request bound" }
    val copy = ArrayList<AcpProviderExecutionRequestEvidence>()
    for (value in values) {
        require(copy.size < maximumRequests) { "ACP provider evidence exceeds request bound" }
        copy.add(value)
    }
    return Collections.unmodifiableList(copy)
}

private fun requireProviderEvidenceDigest(value: String) {
    require(value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }) {
        "ACP provider evidence digest is not canonical"
    }
}

internal fun providerExecutionEvidenceIssuerSha256(configurationSha256: String, profileSha256: String): String =
    providerExecutionEvidenceSha256("acp-provider-factory-owner-v1\n$configurationSha256\n$profileSha256\n")

internal fun providerExecutionEvidenceConsumerSha256(requestSha256: String, invocationSha256: String): String =
    providerExecutionEvidenceSha256("acp-provider-invocation-evidence-owner-v1\n$requestSha256\n$invocationSha256\n")

private fun providerExecutionEvidenceSha256(value: String): String =
    MessageDigest.getInstance("SHA-256").digest(value.toByteArray(StandardCharsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
