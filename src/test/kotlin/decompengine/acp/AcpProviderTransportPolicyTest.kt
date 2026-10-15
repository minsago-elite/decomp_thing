package decompengine.acp

import java.net.URI
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals

class AcpProviderTransportPolicyTest {
    @Test
    fun `default is disabled and approval fixes the service authentication and zero retry authority`() {
        assertIs<AcpProviderTransportPolicy.Disabled>(AcpProviderTransportPolicy.DISABLED)
        val policy = approved()
        assertEquals(APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT, policy.endpoint)
        assertEquals(AcpProviderOperation.RESPONSES_CREATE, policy.operation)
        assertEquals(AcpProviderAuthMechanism.CHATGPT_CACHED_ACCESS_TOKEN, policy.authenticationMechanism)
        assertEquals(AcpProviderRuntimeAdapter.CODEX_GATEWAY_RESPONSES_V1, policy.runtimeAdapter)
        assertEquals(AcpProviderCredentialReference.LOCAL_CODEX_CACHED_AUTH, policy.credentialReference)
        assertFalse(policy.allowProxy)
        assertFalse(policy.allowRedirect)
        assertEquals(0, policy.bounds.maximumRetries)
        assertEquals(1, policy.bounds.maximumOutstandingRequests)
        assertEquals(0, policy.bounds.maximumQueuedRequests)
    }

    @Test
    fun `endpoint aliases credential destinations and canonical alternate services are rejected`() {
        val endpoints = listOf(
            "http://chatgpt.com/backend-api/codex/responses",
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
            "https://chatgpt.com/v1/responses",
            "https://chatgpt.com/backend-api/codex/models",
            "https://chátgpt.com/backend-api/codex/responses",
        )
        endpoints.forEach { endpoint ->
            assertFailsWith<IllegalArgumentException> {
                AcpProviderTransportPolicy.issueApproved(URI(endpoint), "gpt-6", AcpProviderReasoning.MEDIUM, AcpProviderTransportBounds())
            }
        }
    }

    @Test
    fun `configuration requires every field and rejects unknown enums or noncanonical bounds`() {
        val fields = configuration()
        assertEquals(approved().descriptorSha256, AcpProviderTransportPolicy.issueApproved(fields).descriptorSha256)
        fields.keys.forEach { key ->
            assertFailsWith<IllegalArgumentException> { AcpProviderTransportPolicy.issueApproved(fields - key) }
        }
        assertFailsWith<IllegalArgumentException> { AcpProviderTransportPolicy.issueApproved(fields + ("allowProxy" to "true")) }
        listOf("operation", "authenticationMechanism", "runtimeAdapter", "credentialReference", "reasoning").forEach { key ->
            assertFailsWith<IllegalArgumentException> { AcpProviderTransportPolicy.issueApproved(fields + (key to "UNKNOWN")) }
        }
        listOf("0", "-1", "+1", "01", "1.0", " 1", "2147483648").forEach { value ->
            assertFailsWith<IllegalArgumentException> {
                AcpProviderTransportPolicy.issueApproved(fields + ("maximumRequestBytes" to value))
            }
        }
    }

    @Test
    fun `every configurable resource limit rejects a nonpositive or oversized value`() {
        val invalidBounds: List<() -> AcpProviderTransportBounds> = listOf(
            { AcpProviderTransportBounds(maximumRequestBytes = 0) },
            { AcpProviderTransportBounds(maximumRequestBytes = MAXIMUM_PROVIDER_FRAME_PAYLOAD_BYTES - 31) },
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
    fun `descriptor binds every approved difference without credential content`() {
        assertEquals(approved().descriptorSha256, approved().descriptorSha256)
        assertEquals(64, approved().descriptorSha256.length)
        assertNotEquals(approved().descriptorSha256, approved(model = "gpt-6-mini").descriptorSha256)
        assertNotEquals(approved().descriptorSha256, approved(reasoning = AcpProviderReasoning.HIGH).descriptorSha256)
        assertNotEquals(approved().descriptorSha256, approved(bounds = AcpProviderTransportBounds(maximumOutputTokens = 2048)).descriptorSha256)
        listOf("", "gpt 6", "gpt/6", "gpt-6\n", "x".repeat(129)).forEach { model ->
            assertFailsWith<IllegalArgumentException> { approved(model = model) }
        }
    }

    @Test
    fun `invalid endpoint syntax does not retain sensitive input or a raw URI exception`() {
        val secretMarker = "synthetic-secret-do-not-retain"
        val failure = assertFailsWith<IllegalArgumentException> {
            AcpProviderTransportPolicy.issueApproved(configuration() + ("endpoint" to "https://$secretMarker@chatgpt.com/bad path"))
        }
        assertEquals("provider endpoint syntax is invalid", failure.message)
        assertEquals(null, failure.cause)
        assertFalse(failure.toString().contains(secretMarker))
    }

    private fun approved(model: String = "gpt-6", reasoning: AcpProviderReasoning = AcpProviderReasoning.MEDIUM,
        bounds: AcpProviderTransportBounds = AcpProviderTransportBounds()): AcpProviderTransportPolicy.Approved =
        AcpProviderTransportPolicy.issueApproved(APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT, model, reasoning, bounds)

    private fun configuration(): Map<String, String> = mapOf(
        "endpoint" to APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT.toString(), "operation" to "RESPONSES_CREATE",
        "model" to "gpt-6", "reasoning" to "MEDIUM", "authenticationMechanism" to "CHATGPT_CACHED_ACCESS_TOKEN",
        "runtimeAdapter" to "CODEX_GATEWAY_RESPONSES_V1", "credentialReference" to "LOCAL_CODEX_CACHED_AUTH",
        "maximumRequestBytes" to "1048576", "maximumResponseBytes" to "8388608", "maximumHeaderBytes" to "32768",
        "maximumHeaderFields" to "64", "maximumChunkBytes" to "65536", "maximumQueuedChunks" to "2",
        "maximumRequests" to "8", "maximumOutputTokens" to "4096", "overallTimeoutMillis" to "120000",
        "idleTimeoutMillis" to "30000", "cleanupTimeoutMillis" to "5000",
    )
}
