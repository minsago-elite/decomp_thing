package decompengine.acp

import java.net.URI
import java.net.URISyntaxException
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Duration

internal val APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT: URI = URI("https://chatgpt.com/backend-api/codex/responses")
internal const val MAXIMUM_PROVIDER_REQUEST_BYTES: Int = 8 * 1024 * 1024

/**
 * Closed set of provider protocol operations. [method] and [relayPath] are the only request line
 * a contained agent may send on its provider channel for this operation; the upstream destination
 * always comes from the approved policy, never from the agent's request.
 */
enum class AcpProviderOperation(val method: String, val relayPath: String) {
    RESPONSES_CREATE("POST", "/responses"),
}

/** Cached ChatGPT access token from the operator's local Codex login; there is no token refresh. */
enum class AcpProviderAuthMechanism { CHATGPT_CACHED_ACCESS_TOKEN }

/** Opaque identity of an operator-controlled secret source. It never carries credential bytes. */
enum class AcpProviderCredentialReference { LOCAL_CODEX_CACHED_AUTH }

/**
 * Closed catalog of runtime adapters. Each adapter fixes its single approved endpoint, the
 * operations it implements, its authentication mechanism and the credential sources it accepts.
 */
enum class AcpProviderRuntimeAdapter(
    val endpoint: URI,
    val operations: Set<AcpProviderOperation>,
    val authenticationMechanism: AcpProviderAuthMechanism,
    val credentialReferences: Set<AcpProviderCredentialReference>,
) {
    CODEX_GATEWAY_RESPONSES_V1(
        APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT,
        setOf(AcpProviderOperation.RESPONSES_CREATE),
        AcpProviderAuthMechanism.CHATGPT_CACHED_ACCESS_TOKEN,
        setOf(AcpProviderCredentialReference.LOCAL_CODEX_CACHED_AUTH),
    ),
}

enum class AcpProviderReasoning(val wireValue: String) {
    MINIMAL("minimal"), LOW("low"), MEDIUM("medium"), HIGH("high"), XHIGH("xhigh"),
}

/** The only upstream TLS mode: JVM platform PKIX trust plus HTTPS hostname verification. */
enum class AcpProviderTlsVerification { PLATFORM_TRUST_HOSTNAME_VERIFIED }

/**
 * Whether the approved endpoint may resolve to a private (RFC 1918, CGNAT or IPv6 ULA) address,
 * for example behind split-horizon DNS. It is explicit operator policy and is never inferred.
 * Loopback, link-local, multicast, unspecified and reserved addresses are refused either way.
 */
enum class AcpProviderPrivateDestinations { DENIED, PERMITTED }

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
        require(maximumRequestBytes in 1..MAXIMUM_PROVIDER_REQUEST_BYTES) { "provider request byte limit is outside the bound" }
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
 * Immutable model-provider transport policy. [DISABLED] is the default. An [Approved] policy is
 * issued only from explicit operator policy for one cataloged runtime adapter; it holds an opaque
 * credential reference, never credential bytes or a caller callback. Issuance is not runtime
 * admission: no production factory path issues or consumes an approved policy yet.
 */
sealed class AcpProviderTransportPolicy private constructor() {
    data object Disabled : AcpProviderTransportPolicy()

    class Approved private constructor(
        val runtimeAdapter: AcpProviderRuntimeAdapter,
        val endpoint: URI,
        val operation: AcpProviderOperation,
        val authenticationMechanism: AcpProviderAuthMechanism,
        val credentialReference: AcpProviderCredentialReference,
        val model: String,
        val reasoning: AcpProviderReasoning,
        val tlsVerification: AcpProviderTlsVerification,
        val privateDestinations: AcpProviderPrivateDestinations,
        val bounds: AcpProviderTransportBounds,
    ) : AcpProviderTransportPolicy() {
        init {
            // Validate here, not only in the issuer, because the JVM can reach a private constructor.
            requireCanonicalProviderEndpoint(endpoint)
            require(endpoint == runtimeAdapter.endpoint) { "provider endpoint is not approved for the runtime adapter" }
            require(operation in runtimeAdapter.operations) { "unsupported provider operation" }
            require(authenticationMechanism == runtimeAdapter.authenticationMechanism) {
                "unsupported provider authentication mechanism"
            }
            require(credentialReference in runtimeAdapter.credentialReferences) {
                "unsupported provider credential reference"
            }
            require(model.matches(PROVIDER_MODEL_SYNTAX)) { "provider model identifier is not canonical and bounded" }
        }

        val allowProxy: Boolean get() = false
        val allowRedirect: Boolean get() = false

        /** Credential-free SHA-256 identity of every approved field, suitable for evidence. */
        val descriptorSha256: String = providerSha256(listOf(
            "schema=$PROVIDER_POLICY_DESCRIPTOR_SCHEMA",
            "runtimeAdapter=${runtimeAdapter.name}",
            "endpoint=${endpoint.toASCIIString()}",
            "operation=${operation.name}",
            "method=${operation.method}",
            "relayPath=${operation.relayPath}",
            "authenticationMechanism=${authenticationMechanism.name}",
            "credentialReference=${credentialReference.name}",
            "model=$model",
            "reasoning=${reasoning.name}",
            "tlsVerification=${tlsVerification.name}",
            "privateDestinations=${privateDestinations.name}",
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
        ).joinToString("\n", postfix = "\n"))

        override fun toString(): String = "AcpProviderTransportPolicy.Approved(descriptorSha256=$descriptorSha256)"

        companion object {
            internal fun issue(
                runtimeAdapter: AcpProviderRuntimeAdapter,
                endpoint: URI,
                operation: AcpProviderOperation,
                authenticationMechanism: AcpProviderAuthMechanism,
                credentialReference: AcpProviderCredentialReference,
                model: String,
                reasoning: AcpProviderReasoning,
                tlsVerification: AcpProviderTlsVerification,
                privateDestinations: AcpProviderPrivateDestinations,
                bounds: AcpProviderTransportBounds,
            ): Approved = Approved(
                runtimeAdapter, endpoint, operation, authenticationMechanism, credentialReference,
                model, reasoning, tlsVerification, privateDestinations, bounds,
            )
        }
    }

    companion object {
        val DISABLED: AcpProviderTransportPolicy = Disabled

        /**
         * Strict operator policy boundary: every field is required, unknown keys and enum values are
         * refused, and nothing is defaulted or inferred. Failure messages never echo field values.
         */
        internal fun fromOperatorPolicy(fields: Map<String, String>): AcpProviderTransportPolicy {
            when (fields["mode"]) {
                "disabled" -> {
                    require(fields.keys == setOf("mode")) { "disabled provider transport accepts no other fields" }
                    return DISABLED
                }
                "approved" -> Unit
                else -> throw IllegalArgumentException("provider transport mode must be exactly disabled or approved")
            }
            require(fields.keys == APPROVED_POLICY_KEYS) { "provider transport policy has missing or unknown fields" }
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
            return Approved.issue(
                runtimeAdapter = fields.enumValue("runtimeAdapter", "provider runtime adapter"),
                endpoint = parseProviderEndpoint(fields.getValue("endpoint")),
                operation = fields.enumValue("operation", "provider operation"),
                authenticationMechanism = fields.enumValue("authenticationMechanism", "provider authentication mechanism"),
                credentialReference = fields.enumValue("credentialReference", "provider credential reference"),
                model = fields.getValue("model"),
                reasoning = fields.enumValue("reasoning", "provider reasoning setting"),
                tlsVerification = fields.enumValue("tlsVerification", "provider TLS verification mode"),
                privateDestinations = fields.enumValue("privateDestinations", "provider private destination permission"),
                bounds = bounds,
            )
        }
    }
}

private const val PROVIDER_POLICY_DESCRIPTOR_SCHEMA = "acp-provider-transport-policy-v2"
private val PROVIDER_MODEL_SYNTAX = Regex("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")

private val APPROVED_POLICY_KEYS = setOf(
    "mode", "runtimeAdapter", "endpoint", "operation", "authenticationMechanism", "credentialReference",
    "model", "reasoning", "tlsVerification", "privateDestinations",
    "maximumRequestBytes", "maximumResponseBytes", "maximumHeaderBytes", "maximumHeaderFields", "maximumChunkBytes",
    "maximumQueuedChunks", "maximumRequests", "maximumOutputTokens", "overallTimeoutMillis", "idleTimeoutMillis",
    "cleanupTimeoutMillis",
)

private inline fun <reified T : Enum<T>> Map<String, String>.enumValue(key: String, label: String): T {
    val value = getValue(key)
    return enumValues<T>().singleOrNull { it.name == value } ?: throw IllegalArgumentException("unsupported $label")
}

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
