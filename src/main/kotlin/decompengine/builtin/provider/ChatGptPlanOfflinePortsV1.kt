package decompengine.builtin.provider

import decompengine.builtin.AccountBindingV2
import decompengine.builtin.AdmittedModelRunV2
import java.time.Instant
import java.util.Collections

/** Opaque bearer marker. There is deliberately no API that returns credential characters. */
internal interface OfflineBearerV1

internal class OfflinePlanCredentialV1(
    val binding: AccountBindingV2,
    val generation: Long,
    val expiresAt: Instant,
    scopes: Set<String>,
    val bearer: OfflineBearerV1,
) {
    val scopes: Set<String>

    init {
        if (generation < 0 || expiresAt.epochSecond !in MIN_EXPIRY_EPOCH..MAX_EXPIRY_EPOCH || scopes.size > MAX_SCOPES) malformed()
        val copy = LinkedHashSet<String>()
        for (scope in scopes) {
            if (scope.length !in 1..MAX_SCOPE_CHARS ||
                ChatGptPlanWireJsonV1.scalarUtf8Length(scope, MAX_SCOPE_CHARS) == null ||
                scope.any { it.code !in 0x21..0x7e || it == '\"' || it == '\\' } || !copy.add(scope)) malformed()
        }
        this.scopes = Collections.unmodifiableSet(copy)
    }

    fun requireFor(run: AdmittedModelRunV2) {
        if (binding.commitment() != run.bindingCommitment || binding.commitment() != run.binding.commitment()) unauthorized()
        run.deadline.remainingNanos()
    }

    fun requireReadyScopes() {
        if (!OfflineCredentialAcquisitionV1.REQUIRED_SCOPES.all(scopes::contains)) unauthorized()
    }

    override fun toString() = "OfflinePlanCredentialV1(redacted)"

    companion object {
        const val MAX_SCOPES = 32
        const val MAX_SCOPE_CHARS = 128
        private const val MIN_EXPIRY_EPOCH = -3_155_760_000L
        private const val MAX_EXPIRY_EPOCH = 3_155_760_000L
        private fun malformed(): Nothing = throw ModelProviderException(ModelFailureKind.MALFORMED_RESPONSE)
        private fun unauthorized(): Nothing = throw ModelProviderException(ModelFailureKind.AUTHORIZATION)
    }
}

internal sealed interface OfflineCredentialAcquisitionV1 {
    class Ready(val credential: OfflinePlanCredentialV1) : OfflineCredentialAcquisitionV1 {
        init {
            if (!REQUIRED_SCOPES.all(credential.scopes::contains)) {
                throw ModelProviderException(ModelFailureKind.AUTHORIZATION)
            }
        }
        override fun toString() = "Ready(redacted)"
    }
    class Expired(val bindingCommitment: String, val generation: Long) : OfflineCredentialAcquisitionV1 {
        init {
            if (!bindingCommitment.matches(Regex("[a-f0-9]{64}")) || generation < 0) {
                throw ModelProviderException(ModelFailureKind.MALFORMED_RESPONSE)
            }
        }
        override fun toString() = "Expired(redacted)"
    }
    companion object {
        val REQUIRED_SCOPES: Set<String> = Collections.unmodifiableSet(setOf("resource.invoke", "chatgpt.tokens.use.direct"))
    }
}

/**
 * Offline fake-only seam; implementations belong in test sources. They must check the admitted run's
 * deadline around any fixture operation and recheck the exact full AccountBindingV2 commitment and
 * expected generation on acquire, renewal, and recheck. Never discover an active account/model or
 * fall back to another binding. READY requires both declared scopes. This port supplies no store,
 * network adapter, identity proof, refresh rotation implementation, or hidden clock.
 */
internal interface OfflinePlanTokenSourceV1 {
    fun acquire(run: AdmittedModelRunV2): OfflineCredentialAcquisitionV1
    fun renew(run: AdmittedModelRunV2, expectedGeneration: Long): OfflinePlanCredentialV1
    fun recheck(run: AdmittedModelRunV2, credential: OfflinePlanCredentialV1)
    fun registerFixtureSecrets(credential: OfflinePlanCredentialV1, guard: ChatGptPlanSecretsV1)
}

internal class ChatGptCatalogSnapshotV1(
    val bindingCommitment: String,
    val generation: Long,
    val catalog: ChatGptCatalogV1,
) {
    init {
        if (!bindingCommitment.matches(Regex("[a-f0-9]{64}")) || generation < 0) {
            throw ModelProviderException(ModelFailureKind.MALFORMED_RESPONSE)
        }
    }
    fun requireFor(credential: OfflinePlanCredentialV1) {
        if (bindingCommitment != credential.binding.commitment() || generation != credential.generation) {
            throw ModelProviderException(ModelFailureKind.AUTHORIZATION)
        }
    }
    override fun toString() = "ChatGptCatalogSnapshotV1(redacted)"
}
