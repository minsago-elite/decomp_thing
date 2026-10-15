package decompengine.acp

import java.net.URI
import java.net.URISyntaxException
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.IdentityHashMap
import java.time.Duration

internal const val MAXIMUM_PROVIDER_FRAME_PAYLOAD_BYTES: Int = 8 * 1024 * 1024
internal const val PROVIDER_INVOCATION_CAPABILITY_BYTES: Int = 32
internal val APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT: URI = URI("https://chatgpt.com/backend-api/codex/responses")

enum class AcpProviderOperation { RESPONSES_CREATE }
enum class AcpProviderAuthMechanism { CHATGPT_CACHED_ACCESS_TOKEN }
enum class AcpProviderRuntimeAdapter { CODEX_GATEWAY_RESPONSES_V1 }
enum class AcpProviderCredentialReference { LOCAL_CODEX_CACHED_AUTH }
enum class AcpProviderReasoning(val wireValue: String) {
    MINIMAL("minimal"), LOW("low"), MEDIUM("medium"), HIGH("high"), XHIGH("xhigh"),
}

/** Finite limits for one invocation. Requests are serialized, never queued or retried. */
data class AcpProviderTransportBounds(
    val maximumRequestBytes: Int = 1024 * 1024,
    val maximumResponseBytes: Int = 8 * 1024 * 1024,
    val maximumHeaderBytes: Int = 32 * 1024,
    val maximumHeaderFields: Int = 64,
    val maximumChunkBytes: Int = 64 * 1024,
    val maximumQueuedChunks: Int = 2,
    val maximumRequests: Int = 8,
    val maximumOutputTokens: Int = 4096,
    val overallTimeout: Duration = Duration.ofMinutes(2),
    val idleTimeout: Duration = Duration.ofSeconds(30),
    val cleanupTimeout: Duration = Duration.ofSeconds(5),
) {
    val maximumRetries: Int get() = 0
    val maximumOutstandingRequests: Int get() = 1
    val maximumQueuedRequests: Int get() = 0

    init {
        require(maximumRequestBytes in 1..(MAXIMUM_PROVIDER_FRAME_PAYLOAD_BYTES - PROVIDER_INVOCATION_CAPABILITY_BYTES)) {
            "provider request byte limit is outside the frame bound"
        }
        require(maximumResponseBytes in 1..(64 * 1024 * 1024)) { "provider response byte limit is outside the bound" }
        require(maximumHeaderBytes in 1..(64 * 1024)) { "provider header byte limit is outside the bound" }
        require(maximumHeaderFields in 1..256) { "provider header field limit is outside the bound" }
        require(maximumChunkBytes in 1..minOf(64 * 1024, maximumResponseBytes)) {
            "provider response chunk byte limit is outside the bound"
        }
        require(maximumQueuedChunks in 1..16) { "provider queued chunk limit is outside the bound" }
        require(maximumRequests in 1..64) { "provider request count limit is outside the bound" }
        require(maximumOutputTokens in 1..65_536) { "provider output token limit is outside the bound" }
        requireBoundedProviderDuration(overallTimeout, "overall")
        requireBoundedProviderDuration(idleTimeout, "idle")
        requireBoundedProviderDuration(cleanupTimeout, "cleanup")
        require(idleTimeout <= overallTimeout) { "provider idle timeout exceeds the invocation timeout" }
        require(cleanupTimeout <= overallTimeout) { "provider cleanup timeout exceeds the invocation timeout" }
    }
}

/**
 * Default-disabled capability policy. Only the internal approval issuer can construct an enabled
 * policy for the one closed ChatGPT service adapter. It contains an opaque credential reference,
 * never credential bytes or a caller callback.
 * Issuance is not a production admission or a claim that the selected backend is compatible.
 */
sealed class AcpProviderTransportPolicy private constructor() {
    data object Disabled : AcpProviderTransportPolicy()

    sealed class Enabled protected constructor() : AcpProviderTransportPolicy() {
        abstract val endpoint: URI
        abstract val model: String
        abstract val reasoning: AcpProviderReasoning
        abstract val bounds: AcpProviderTransportBounds
        abstract val descriptorSha256: String
        val operation: AcpProviderOperation = AcpProviderOperation.RESPONSES_CREATE
    }

    class Approved private constructor(
        override val endpoint: URI,
        override val model: String,
        override val reasoning: AcpProviderReasoning,
        override val bounds: AcpProviderTransportBounds,
        val credentialReference: AcpProviderCredentialReference,
    ) : Enabled() {
        init {
            // Kotlin emits a callable synthetic marker constructor even for private constructors.
            // Repeat issuer validation here so that constructor cannot confer alternate authority.
            requireCanonicalProviderEndpoint(endpoint)
            require(model.matches(Regex("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"))) {
                "provider model identifier is not canonical and bounded"
            }
        }
        val authenticationMechanism: AcpProviderAuthMechanism = AcpProviderAuthMechanism.CHATGPT_CACHED_ACCESS_TOKEN
        val runtimeAdapter: AcpProviderRuntimeAdapter = AcpProviderRuntimeAdapter.CODEX_GATEWAY_RESPONSES_V1
        val allowProxy: Boolean = false
        val allowRedirect: Boolean = false
        override val descriptorSha256: String = providerSha256(canonicalDescriptor())

        private fun canonicalDescriptor(): String = listOf(
            "schema=acp-provider-transport-policy-v1",
            "endpoint=${endpoint.toASCIIString()}",
            "operation=${operation.name}",
            "model=$model",
            "reasoning=${reasoning.name}",
            "authenticationMechanism=${authenticationMechanism.name}",
            "runtimeAdapter=${runtimeAdapter.name}",
            "credentialReference=${credentialReference.name}",
            "allowProxy=false", "allowRedirect=false",
            "maximumRequestBytes=${bounds.maximumRequestBytes}",
            "maximumResponseBytes=${bounds.maximumResponseBytes}",
            "maximumHeaderBytes=${bounds.maximumHeaderBytes}",
            "maximumHeaderFields=${bounds.maximumHeaderFields}",
            "maximumChunkBytes=${bounds.maximumChunkBytes}",
            "maximumQueuedChunks=${bounds.maximumQueuedChunks}",
            "maximumRequests=${bounds.maximumRequests}",
            "maximumOutputTokens=${bounds.maximumOutputTokens}",
            "overallTimeoutMillis=${bounds.overallTimeout.toMillis()}",
            "idleTimeoutMillis=${bounds.idleTimeout.toMillis()}",
            "cleanupTimeoutMillis=${bounds.cleanupTimeout.toMillis()}",
            "maximumRetries=0", "maximumOutstandingRequests=1", "maximumQueuedRequests=0",
        ).joinToString("\n", postfix = "\n")

        companion object {
            internal fun issue(
                endpoint: URI,
                model: String,
                reasoning: AcpProviderReasoning,
                bounds: AcpProviderTransportBounds,
                credentialReference: AcpProviderCredentialReference,
            ): Approved {
                requireCanonicalProviderEndpoint(endpoint)
                require(model.matches(Regex("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"))) {
                    "provider model identifier is not canonical and bounded"
                }
                return Approved(endpoint, model, reasoning, bounds, credentialReference)
            }
        }
    }

    /**
     * An invocation-only credential-free authority. It is not a production approval. Its port
     * is host-local state and never rendered by evidence; only the complete descriptor digest is.
     * Issuance consumes a factory-private provenance permit, and broker admission consumes this
     * exact object once. A JVM synthetic constructor cannot register a forged policy.
     */
    internal class CredentialFreeFixture private constructor(
        port: Int,
        profile: AcpProviderQualificationProfile,
        private val consumer: Any,
        provenance: Any,
    ) : Enabled() {
        init {
            require(hasConstructorProvenance(provenance)) { "fixture authority provenance is unavailable" }
            require(port in 1024..65535) { "fixture listener is outside the ephemeral port bound" }
        }
        override val endpoint: URI = URI("https://127.0.0.1:$port/responses")
        override val model: String = profile.model
        override val reasoning: AcpProviderReasoning = profile.reasoning
        override val bounds: AcpProviderTransportBounds = profile.bounds
        val credentialFreeFixture: Boolean = true
        val adapterQualified: Boolean = false
        private val authorization = ByteArray(32).also(SecureRandom()::nextBytes).joinToString("") { "%02x".format(it) }
        override val descriptorSha256: String = providerSha256(listOf(
            "schema=acp-provider-credential-free-fixture-policy-v1",
            "endpoint=${endpoint.toASCIIString()}", "operation=RESPONSES_CREATE", "method=POST",
            "model=$model", "reasoning=${reasoning.name}",
            "certificateSha256=$PROVIDER_FIXTURE_CERTIFICATE_SHA256", "spkiSha256=$PROVIDER_FIXTURE_SPKI_SHA256",
            "credentialFreeFixture=true", "adapterQualified=false", "allowProxy=false", "allowRedirect=false",
            "maximumRequestBytes=${bounds.maximumRequestBytes}", "maximumResponseBytes=${bounds.maximumResponseBytes}",
            "maximumHeaderBytes=${bounds.maximumHeaderBytes}", "maximumHeaderFields=${bounds.maximumHeaderFields}",
            "maximumChunkBytes=${bounds.maximumChunkBytes}", "maximumQueuedChunks=${bounds.maximumQueuedChunks}",
            "maximumRequests=${bounds.maximumRequests}", "maximumOutputTokens=${bounds.maximumOutputTokens}",
            "overallTimeoutMillis=${bounds.overallTimeout.toMillis()}", "idleTimeoutMillis=${bounds.idleTimeout.toMillis()}",
            "cleanupTimeoutMillis=${bounds.cleanupTimeout.toMillis()}",
            "maximumRetries=0", "maximumOutstandingRequests=1", "maximumQueuedRequests=0",
        ).joinToString("\n", postfix = "\n"))

        private fun isOwnedBy(owner: Any): Boolean = consumer === owner
        internal fun syntheticAuthorization(): String = authorization
        internal fun claimForBroker(owner: Any): String = consumeIssuedPolicy(this, owner)

        override fun toString(): String = "AcpProviderTransportPolicy.CredentialFreeFixture(<fixture-only>)"

        // Instance fields in this nested issuer avoid Kotlin companion-property accessors
        // that would otherwise expose a mutable registry or the constructor provenance on JVM.
        private class Issuer {
            private val constructorProvenance = Any()
            private val issuedPolicies = IdentityHashMap<CredentialFreeFixture, Boolean>()
            fun hasConstructorProvenance(provenance: Any): Boolean = provenance === constructorProvenance
            fun consumeIssuedPolicy(policy: CredentialFreeFixture, owner: Any): String = synchronized(issuedPolicies) {
                val issued = issuedPolicies.remove(policy)
                require(policy.isOwnedBy(owner) && issued == true) { "fixture authority is forged or already consumed" }
                policy.authorization
            }
            fun issue(permit: AcpProviderQualificationPermit, consumer: Any, port: Int): CredentialFreeFixture {
                val profile = AcpHarnessFactory.consumeProviderQualificationPermit(
                    permit, consumer, AcpProviderQualificationPurpose.FIXTURE_POLICY,
                )
                return CredentialFreeFixture(port, profile, consumer, constructorProvenance).also {
                    synchronized(issuedPolicies) { issuedPolicies[it] = true }
                }
            }
        }
        companion object {
            private val issuer = Issuer()
            private fun hasConstructorProvenance(provenance: Any): Boolean = issuer.hasConstructorProvenance(provenance)
            private fun consumeIssuedPolicy(policy: CredentialFreeFixture, owner: Any): String = issuer.consumeIssuedPolicy(policy, owner)
            internal fun issue(permit: AcpProviderQualificationPermit, consumer: Any, port: Int): CredentialFreeFixture =
                issuer.issue(permit, consumer, port)
        }
    }

    companion object {
        val DISABLED: AcpProviderTransportPolicy = Disabled

        internal fun issueApproved(
            endpoint: URI,
            model: String,
            reasoning: AcpProviderReasoning,
            bounds: AcpProviderTransportBounds,
            credentialReference: AcpProviderCredentialReference = AcpProviderCredentialReference.LOCAL_CODEX_CACHED_AUTH,
        ): Approved = Approved.issue(endpoint, model, reasoning, bounds, credentialReference)

        /** Strict future operator boundary: no ignored keys, inferred defaults, or unknown enums. */
        internal fun issueApproved(configuration: Map<String, String>): Approved {
            require(configuration.size == CONFIGURATION_KEYS.size) { "provider approval configuration has missing or unknown fields" }
            val fields = HashMap(configuration)
            require(fields.keys == CONFIGURATION_KEYS) { "provider approval configuration has missing or unknown fields" }
            require(fields.getValue("operation") == AcpProviderOperation.RESPONSES_CREATE.name) {
                "unsupported provider operation"
            }
            require(fields.getValue("authenticationMechanism") == AcpProviderAuthMechanism.CHATGPT_CACHED_ACCESS_TOKEN.name) {
                "unsupported provider authentication mechanism"
            }
            require(fields.getValue("runtimeAdapter") == AcpProviderRuntimeAdapter.CODEX_GATEWAY_RESPONSES_V1.name) {
                "unsupported provider runtime adapter"
            }
            val bounds = AcpProviderTransportBounds(
                maximumRequestBytes = fields.canonicalInt("maximumRequestBytes"),
                maximumResponseBytes = fields.canonicalInt("maximumResponseBytes"),
                maximumHeaderBytes = fields.canonicalInt("maximumHeaderBytes"),
                maximumHeaderFields = fields.canonicalInt("maximumHeaderFields"),
                maximumChunkBytes = fields.canonicalInt("maximumChunkBytes"),
                maximumQueuedChunks = fields.canonicalInt("maximumQueuedChunks"),
                maximumRequests = fields.canonicalInt("maximumRequests"),
                maximumOutputTokens = fields.canonicalInt("maximumOutputTokens"),
                overallTimeout = Duration.ofMillis(fields.canonicalInt("overallTimeoutMillis").toLong()),
                idleTimeout = Duration.ofMillis(fields.canonicalInt("idleTimeoutMillis").toLong()),
                cleanupTimeout = Duration.ofMillis(fields.canonicalInt("cleanupTimeoutMillis").toLong()),
            )
            return issueApproved(
                parseProviderEndpoint(fields.getValue("endpoint")),
                fields.getValue("model"),
                AcpProviderReasoning.entries.singleOrNull { it.name == fields.getValue("reasoning") }
                    ?: throw IllegalArgumentException("unsupported provider reasoning setting"),
                bounds,
                AcpProviderCredentialReference.entries.singleOrNull { it.name == fields.getValue("credentialReference") }
                    ?: throw IllegalArgumentException("unsupported provider credential reference"),
            )
        }
    }
}

private val CONFIGURATION_KEYS = setOf(
    "endpoint", "operation", "model", "reasoning", "authenticationMechanism", "runtimeAdapter", "credentialReference",
    "maximumRequestBytes", "maximumResponseBytes", "maximumHeaderBytes", "maximumHeaderFields", "maximumChunkBytes",
    "maximumQueuedChunks", "maximumRequests", "maximumOutputTokens", "overallTimeoutMillis", "idleTimeoutMillis", "cleanupTimeoutMillis",
)

private fun Map<String, String>.canonicalInt(key: String): Int {
    val value = getValue(key)
    require(value.matches(Regex("[1-9][0-9]{0,9}"))) { "provider numeric bound is not canonical" }
    return value.toIntOrNull() ?: throw IllegalArgumentException("provider numeric bound is outside the integer range")
}

private fun requireBoundedProviderDuration(duration: Duration, label: String) {
    require(duration >= Duration.ofMillis(1) && duration <= Duration.ofMinutes(30) && duration.nano % 1_000_000 == 0) {
        "provider $label timeout must be a finite integral number of milliseconds within the bound"
    }
}

private fun requireCanonicalProviderEndpoint(endpoint: URI) {
    val raw = endpoint.toASCIIString()
    require(raw.length in 1..2048 && raw == endpoint.toString() && endpoint.scheme == "https" && !endpoint.isOpaque) {
        "provider endpoint must be bounded canonical ASCII HTTPS"
    }
    require(endpoint.rawUserInfo == null && endpoint.rawQuery == null && endpoint.rawFragment == null) {
        "provider endpoint must not contain credentials, query parameters, or fragments"
    }
    val host = endpoint.host
    require(host != null && host.matches(Regex("[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")) &&
        !host.contains("..") && endpoint.port == -1 && endpoint.rawAuthority == host) {
        "provider endpoint authority is not canonical"
    }
    val path = endpoint.rawPath
    require(path != null && path.matches(Regex("/[A-Za-z0-9._~/-]+")) && !path.contains("//") &&
        !path.endsWith('/') && path.split('/').none { it == "." || it == ".." } && endpoint.normalize() == endpoint) {
        "provider endpoint path is not canonical"
    }
    require(endpoint == APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT) {
        "provider endpoint is unsupported by the closed credential service adapter"
    }
}

private fun parseProviderEndpoint(value: String): URI {
    require(value.length in 1..2048) { "provider endpoint text is outside the bound" }
    return try {
        URI(value)
    } catch (_: URISyntaxException) {
        // URI syntax errors include the original text. Do not retain that exception as a cause.
        throw IllegalArgumentException("provider endpoint syntax is invalid")
    }
}

private fun providerSha256(value: String): String = MessageDigest.getInstance("SHA-256")
    .digest(value.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }

// Test-only identity is deliberately public repository data, never cached-auth material.
internal const val PROVIDER_FIXTURE_KEYSTORE_RESOURCE = "/acp/provider-relay-fixture-v1.p12"
internal const val PROVIDER_FIXTURE_KEYSTORE_PASSWORD = "fixture-password-v1"
internal const val PROVIDER_FIXTURE_KEYSTORE_SHA256 = "214bb9ca1da9300cf3518323a0c2e1be0564c72be306c0ef6bec79acb7b08bad"
internal const val PROVIDER_FIXTURE_CERTIFICATE_SHA256 = "cb604924d1d75aeb1986632b644193fbb39765589341c221dfd19d7c13e685a5"
internal const val PROVIDER_FIXTURE_SPKI_SHA256 = "cbb03e9d20d95d7192631080637387ff4b8f8b43a6feeedaae3f79859fc1a6c8"
