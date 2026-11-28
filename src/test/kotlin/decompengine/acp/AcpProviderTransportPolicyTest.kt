package decompengine.acp

import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertSame

class AcpProviderTransportPolicyTest {
    @Test
    fun `default is disabled and an explicit disabled mode accepts no other fields`() {
        assertIs<AcpProviderTransportPolicy.Disabled>(AcpProviderTransportPolicy.DISABLED)
        assertSame(AcpProviderTransportPolicy.DISABLED, AcpProviderTransportPolicy.fromOperatorPolicy(mapOf("mode" to "disabled")))
        assertFailsWith<IllegalArgumentException> {
            AcpProviderTransportPolicy.fromOperatorPolicy(mapOf("mode" to "disabled", "endpoint" to APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT.toString()))
        }
        listOf(emptyMap(), mapOf("mode" to "enabled"), mapOf("mode" to "Disabled"), providerPolicyConfiguration() - "mode").forEach { fields ->
            assertFailsWith<IllegalArgumentException> { AcpProviderTransportPolicy.fromOperatorPolicy(fields) }
        }
    }

    @Test
    fun `approval identifies the cataloged service operation authentication adapter and serialized limits`() {
        val policy = approved()
        assertEquals(AcpProviderRuntimeAdapter.CODEX_GATEWAY_RESPONSES_V1, policy.runtimeAdapter)
        assertEquals(APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT, policy.endpoint)
        assertEquals(AcpProviderOperation.RESPONSES_CREATE, policy.operation)
        assertEquals("POST", policy.operation.method)
        assertEquals("/responses", policy.operation.relayPath)
        assertEquals(AcpProviderAuthMechanism.CHATGPT_CACHED_ACCESS_TOKEN, policy.authenticationMechanism)
        assertEquals(AcpProviderCredentialReference.LOCAL_CODEX_CACHED_AUTH, policy.credentialReference)
        assertEquals(AcpProviderTlsVerification.PLATFORM_TRUST_HOSTNAME_VERIFIED, policy.tlsVerification)
        assertEquals(AcpProviderPrivateDestinations.DENIED, policy.privateDestinations)
        assertFalse(policy.allowProxy)
        assertFalse(policy.allowRedirect)
        assertEquals(0, policy.bounds.maximumRetries)
        assertEquals(1, policy.bounds.maximumOutstandingRequests)
        assertEquals(0, policy.bounds.maximumQueuedRequests)
    }

    @Test
    fun `endpoint aliases credential destinations alternate schemes and other services are rejected`() {
        val endpoints = listOf(
            "http://chatgpt.com/backend-api/codex/responses",
            "wss://chatgpt.com/backend-api/codex/responses",
            "https://CHATGPT.com/backend-api/codex/responses",
            "https://chatgpt.com:443/backend-api/codex/responses",
            "https://user@chatgpt.com/backend-api/codex/responses",
            "https://chatgpt.com/backend-api/codex/responses?model=x",
            "https://chatgpt.com/backend-api/codex/responses#fragment",
            "https://chatgpt.com/backend-api/codex/%72esponses",
            "https://chatgpt.com/backend-api/codex/./responses",
            "https://chatgpt.com/backend-api/codex/../responses",
            "https://chatgpt.com/backend-api//codex/responses",
            "https://chatgpt.com/backend-api/codex/responses/",
            "https://chatgpt.com./backend-api/codex/responses",
            "https://other.example/backend-api/codex/responses",
            "https://127.0.0.1/backend-api/codex/responses",
            "https://chatgpt.com/v1/responses",
            "https://chatgpt.com/backend-api/codex/models",
            "https://chátgpt.com/backend-api/codex/responses",
            "chatgpt.com/backend-api/codex/responses",
        )
        endpoints.forEach { endpoint ->
            assertFailsWith<IllegalArgumentException>(endpoint) {
                AcpProviderTransportPolicy.fromOperatorPolicy(providerPolicyConfiguration() + ("endpoint" to endpoint))
            }
        }
    }

    @Test
    fun `approved policy requires every field and refuses unknown fields enums and capabilities`() {
        val fields = providerPolicyConfiguration()
        assertEquals(approved().descriptorSha256, (AcpProviderTransportPolicy.fromOperatorPolicy(fields) as AcpProviderTransportPolicy.Approved).descriptorSha256)
        fields.keys.forEach { key ->
            assertFailsWith<IllegalArgumentException>(key) { AcpProviderTransportPolicy.fromOperatorPolicy(fields - key) }
        }
        listOf("allowProxy", "allowRedirect", "proxy", "baseUrl", "redirectDestinations", "host").forEach { key ->
            assertFailsWith<IllegalArgumentException>(key) { AcpProviderTransportPolicy.fromOperatorPolicy(fields + (key to "true")) }
        }
        mapOf(
            "runtimeAdapter" to listOf("UNKNOWN", "codex_gateway_responses_v1"),
            "operation" to listOf("RESPONSES_WEBSOCKET", "MODELS_LIST", "RESPONSES_COMPACT", "responses_create"),
            "authenticationMechanism" to listOf("NONE", "API_KEY", ""),
            "credentialReference" to listOf("ENVIRONMENT", "INLINE"),
            "reasoning" to listOf("UNKNOWN", "medium"),
            "tlsVerification" to listOf("NONE", "INSECURE", "TRUST_ALL", "PINNED"),
            "privateDestinations" to listOf("ALLOW", "INFERRED", "permitted"),
            "addressTranslation" to listOf("NAT64", "NETWORK_SPECIFIC", "INFERRED", "well_known_nat64"),
        ).forEach { (key, values) ->
            values.forEach { value ->
                assertFailsWith<IllegalArgumentException>("$key=$value") {
                    AcpProviderTransportPolicy.fromOperatorPolicy(fields + (key to value))
                }
            }
        }
        listOf("0", "-1", "+1", "01", "1.0", " 1", "2147483648").forEach { value ->
            assertFailsWith<IllegalArgumentException>(value) {
                AcpProviderTransportPolicy.fromOperatorPolicy(fields + ("maximumRequestBytes" to value))
            }
        }
    }

    @Test
    fun `private destination permission is explicit operator policy`() {
        val permitted = AcpProviderTransportPolicy.fromOperatorPolicy(providerPolicyConfiguration() + ("privateDestinations" to "PERMITTED"))
        assertEquals(AcpProviderPrivateDestinations.PERMITTED, (permitted as AcpProviderTransportPolicy.Approved).privateDestinations)
        assertNotEquals(approved().descriptorSha256, permitted.descriptorSha256)
    }

    @Test
    fun `every configurable resource limit rejects a nonpositive or oversized value`() {
        val invalidBounds: List<() -> AcpProviderTransportBounds> = listOf(
            { AcpProviderTransportBounds(maximumRequestBytes = 0) },
            { AcpProviderTransportBounds(maximumRequestBytes = MAXIMUM_PROVIDER_REQUEST_BYTES + 1) },
            { AcpProviderTransportBounds(maximumResponseBytes = 0) },
            { AcpProviderTransportBounds(maximumResponseBytes = 64 * 1024 * 1024 + 1) },
            { AcpProviderTransportBounds(maximumHeaderBytes = 0) },
            { AcpProviderTransportBounds(maximumHeaderBytes = 64 * 1024 + 1) },
            { AcpProviderTransportBounds(maximumHeaderFields = 0) },
            { AcpProviderTransportBounds(maximumHeaderFields = 257) },
            { AcpProviderTransportBounds(maximumChunkBytes = 0) },
            { AcpProviderTransportBounds(maximumChunkBytes = 64 * 1024 + 1) },
            { AcpProviderTransportBounds(maximumResponseBytes = 4, maximumChunkBytes = 5) },
            { AcpProviderTransportBounds(maximumQueuedChunks = 0) },
            { AcpProviderTransportBounds(maximumQueuedChunks = 17) },
            { AcpProviderTransportBounds(maximumRequests = 0) },
            { AcpProviderTransportBounds(maximumRequests = 65) },
            { AcpProviderTransportBounds(maximumOutputTokens = 0) },
            { AcpProviderTransportBounds(maximumOutputTokens = 65_537) },
        )
        invalidBounds.forEach { make -> assertFailsWith<IllegalArgumentException> { make() } }
    }

    @Test
    fun `timeouts must be positive bounded integral milliseconds with finite cleanup`() {
        listOf(Duration.ZERO, Duration.ofMillis(-1), Duration.ofNanos(1), Duration.ofMinutes(30).plusMillis(1)).forEach { timeout ->
            assertFailsWith<IllegalArgumentException> { AcpProviderTransportBounds(overallTimeout = timeout) }
            assertFailsWith<IllegalArgumentException> { AcpProviderTransportBounds(idleTimeout = timeout) }
            assertFailsWith<IllegalArgumentException> { AcpProviderTransportBounds(cleanupTimeout = timeout) }
        }
        assertFailsWith<IllegalArgumentException> { AcpProviderTransportBounds(idleTimeout = Duration.ofMinutes(3)) }
        assertFailsWith<IllegalArgumentException> { AcpProviderTransportBounds(cleanupTimeout = Duration.ofMinutes(3)) }
    }

    @Test
    fun `descriptor binds every configurable field and carries no credential material`() {
        assertEquals(approved().descriptorSha256, approved().descriptorSha256)
        assertEquals(64, approved().descriptorSha256.length)
        // Keys with a single admissible value cannot vary; every other configurable field must change the digest.
        val singleValued = setOf("mode", "runtimeAdapter", "endpoint", "operation", "authenticationMechanism", "credentialReference", "tlsVerification")
        val variants = mapOf(
            "model" to "gpt-6-mini", "reasoning" to "HIGH", "privateDestinations" to "PERMITTED",
            "addressTranslation" to "WELL_KNOWN_NAT64", "maximumRequestBytes" to "1048575", "maximumResponseBytes" to "8388607",
            "maximumHeaderBytes" to "32767", "maximumHeaderFields" to "63", "maximumChunkBytes" to "65535",
            "maximumQueuedChunks" to "3", "maximumRequests" to "7", "maximumOutputTokens" to "2048",
            "overallTimeoutMillis" to "119999", "idleTimeoutMillis" to "29999", "cleanupTimeoutMillis" to "4999",
        )
        assertEquals(providerPolicyConfiguration().keys, singleValued + variants.keys)
        val digests = variants.map { (key, value) -> approved(key to value).descriptorSha256 } + approved().descriptorSha256
        assertEquals(digests.size, digests.toSet().size)
        assertEquals("AcpProviderTransportPolicy.Approved(descriptorSha256=${approved().descriptorSha256})", approved().toString())
    }

    @Test
    fun `model is a bounded plain identifier never free text`() {
        listOf("", "gpt 6", "gpt/6", "gpt-6\n", "gpt-6\u0000", "gpt=6", "Bearer abc", "x".repeat(129), "-gpt", "gpt\u00e9").forEach { model ->
            assertFailsWith<IllegalArgumentException>(model) { approved("model" to model) }
        }
        listOf("gpt-6", "gpt-6.1-sol", "org:model_v2", "A1").forEach { model -> assertEquals(model, approved("model" to model).model) }
    }

    @Test
    fun `invalid operator values do not retain sensitive input or a raw exception cause`() {
        val secretMarker = "synthetic-secret-do-not-retain"
        listOf(
            "endpoint" to "https://$secretMarker@chatgpt.com/bad path",
            "endpoint" to "https://$secretMarker@chatgpt.com/backend-api/codex/responses",
            "model" to secretMarker.repeat(8),
            "credentialReference" to secretMarker,
            "tlsVerification" to secretMarker,
            "maximumRequestBytes" to secretMarker,
        ).forEach { (key, value) ->
            val failure = assertFailsWith<IllegalArgumentException>(key) {
                AcpProviderTransportPolicy.fromOperatorPolicy(providerPolicyConfiguration() + (key to value))
            }
            assertNull(failure.cause)
            assertFalse(failure.toString().contains(secretMarker), key)
        }
        val unknownKey = assertFailsWith<IllegalArgumentException> {
            AcpProviderTransportPolicy.fromOperatorPolicy(providerPolicyConfiguration() + ("token" to secretMarker))
        }
        assertFalse(unknownKey.toString().contains(secretMarker))
    }

    private fun approved(vararg overrides: Pair<String, String>): AcpProviderTransportPolicy.Approved =
        AcpProviderTransportPolicy.fromOperatorPolicy(providerPolicyConfiguration() + overrides) as AcpProviderTransportPolicy.Approved
}

internal fun providerPolicyConfiguration(): Map<String, String> = mapOf(
    "mode" to "approved", "runtimeAdapter" to "CODEX_GATEWAY_RESPONSES_V1",
    "endpoint" to "https://chatgpt.com/backend-api/codex/responses", "operation" to "RESPONSES_CREATE",
    "authenticationMechanism" to "CHATGPT_CACHED_ACCESS_TOKEN", "credentialReference" to "LOCAL_CODEX_CACHED_AUTH",
    "model" to "gpt-6", "reasoning" to "MEDIUM", "tlsVerification" to "PLATFORM_TRUST_HOSTNAME_VERIFIED",
    "privateDestinations" to "DENIED", "addressTranslation" to "NONE",
    "maximumRequestBytes" to "1048576", "maximumResponseBytes" to "8388608", "maximumHeaderBytes" to "32768",
    "maximumHeaderFields" to "64", "maximumChunkBytes" to "65536", "maximumQueuedChunks" to "2",
    "maximumRequests" to "8", "maximumOutputTokens" to "4096", "overallTimeoutMillis" to "120000",
    "idleTimeoutMillis" to "30000", "cleanupTimeoutMillis" to "5000",
)
