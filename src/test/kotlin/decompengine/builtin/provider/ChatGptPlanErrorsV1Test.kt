package decompengine.builtin.provider

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

internal class ChatGptPlanErrorsV1Test {
    private val now = Instant.parse("2026-11-05T00:00:00Z")
    private fun headers(vararg values: Pair<String, String>) = ChatGptHeaderMetadataV1.fromHeaders(values.toList(), now)
    private fun error(code: String? = null, param: String? = null, message: String = "private-body-sentinel", extra: String = "") =
        ("{\"error\":{" + (code?.let { "\"code\":\"$it\"," } ?: "") +
            (param?.let { "\"param\":\"$it\"," } ?: "") + "\"message\":\"$message\"}$extra}").toByteArray()
    private fun classify(status: Int, body: ByteArray = byteArrayOf(), stream: Boolean = false, metadata: ChatGptHeaderMetadataV1 = headers()) =
        ChatGptPlanErrorsV1.classify(status, metadata, body, false, stream)

    @Test fun mapsEveryOfficialCodeAndNeverUsesMessageText() {
        val cases = listOf(
            "subscription_sharing_user_not_eligible" to ModelFailureKind.AUTHORIZATION,
            "subscription_sharing_usage_limit_exceeded" to ModelFailureKind.RATE_LIMIT,
            "subscription_sharing_usage_unavailable" to ModelFailureKind.TRANSPORT,
            "subscription_sharing_unsupported_capability" to ModelFailureKind.UNSUPPORTED_FEATURE,
            "subscription_sharing_route_not_supported" to ModelFailureKind.AUTHORIZATION,
            "subscription_sharing_invalid_user" to ModelFailureKind.AUTHENTICATION,
            "chatpass_v2_scope_not_authorized" to ModelFailureKind.AUTHORIZATION,
            "chatpass_v2_invalid_authorization_context" to ModelFailureKind.AUTHORIZATION,
            "subscription_sharing_user_unavailable" to ModelFailureKind.TRANSPORT,
        )
        for ((code, kind) in cases) {
            assertEquals(kind, classify(503, error(code, message = "looks like invalid_user")).kind, code)
        }
        assertEquals(ChatGptRecoveryV1.STOP, classify(503, error("subscription_sharing_user_not_eligible")).recovery)
        assertEquals(ChatGptRecoveryV1.STOP, classify(429, error("subscription_sharing_usage_limit_exceeded")).recovery)
        assertEquals(ChatGptRecoveryV1.ONE_RENEWAL_IF_ELIGIBLE, classify(503, error("subscription_sharing_invalid_user")).recovery)
        assertEquals(ChatGptRecoveryV1.BOUNDED_RETRY, classify(503, error("subscription_sharing_usage_unavailable")).recovery)
    }

    @Test fun genericStatusPrecedenceAndStreamBoundaryAreConservative() {
        assertEquals(ChatGptRecoveryV1.ONE_RENEWAL_IF_ELIGIBLE, classify(401).recovery)
        assertEquals(ModelFailureKind.AUTHENTICATION, classify(401).kind) // not confirmed revocation
        assertEquals(ChatGptRecoveryV1.STOP, classify(429).recovery)
        assertEquals(ModelFailureKind.RATE_LIMIT, classify(429).kind)
        assertEquals(ChatGptRecoveryV1.BOUNDED_RETRY, classify(503).recovery)
        assertEquals(ChatGptRecoveryV1.STOP, classify(503, stream = true).recovery)
        assertEquals(ChatGptRecoveryV1.STOP, classify(401, error("subscription_sharing_usage_unavailable"), stream = true).recovery)
        assertEquals(ChatGptRecoveryV1.STOP, classify(503, error("subscription_sharing_user_not_eligible")).recovery)
    }

    @Test fun distinguishesErrorDetailOtherMalformedTruncatedAndAmbiguousBodies() {
        assertEquals(ChatGptBodyShapeV1.ERROR, classify(400, error("unknown_code")).diagnostic.shape)
        assertEquals(ChatGptBodyShapeV1.DETAIL, classify(403, """{"detail":"restricted"}""".toByteArray()).diagnostic.shape)
        assertEquals(ChatGptBodyShapeV1.OTHER, classify(400).diagnostic.shape)
        assertEquals(ChatGptBodyShapeV1.OTHER, classify(400, """{"error":{},"detail":"mixed"}""".toByteArray()).diagnostic.shape)
        assertEquals(ChatGptBodyShapeV1.TRUNCATED, classify(503, error().copyOf(error().size - 2)).diagnostic.shape)
        assertEquals(ChatGptBodyShapeV1.TRUNCATED, ChatGptPlanErrorsV1.classify(503, headers(), ByteArray(32 * 1024 + 1), false, false).diagnostic.shape)
        val detailPrefix = "{\"detail\":\""
        val detailSuffix = "\"}"
        val exactlyBounded = (detailPrefix + "x".repeat(32 * 1024 - detailPrefix.length - detailSuffix.length) + detailSuffix).toByteArray()
        assertEquals(32 * 1024, exactlyBounded.size)
        assertEquals(ChatGptBodyShapeV1.DETAIL, classify(503, exactlyBounded).diagnostic.shape)
        val validOverLimit = ("{\"detail\":\"" + "x".repeat(32 * 1024) + "\"}").toByteArray()
        assertEquals(ChatGptBodyShapeV1.TRUNCATED, classify(503, validOverLimit).diagnostic.shape)
        assertEquals(ChatGptBodyShapeV1.TRUNCATED, ChatGptPlanErrorsV1.classify(503, headers(), error(), true, false).diagnostic.shape)
    }

    @Test fun retryAfterUsesExactCheckedMinimumAndRejectsInvalidRepeatedOrOverDeadlineValues() {
        assertEquals(2_000_000_000L, ChatGptPlanErrorsV1.retryAfterMinimumNanos("2", now))
        assertEquals(0L, ChatGptPlanErrorsV1.retryAfterMinimumNanos("Wed, 04 Nov 2026 23:59:59 GMT", now))
        assertEquals(2_000_000_000L, ChatGptPlanErrorsV1.retryAfterMinimumNanos("Thu, 05 Nov 2026 00:00:02 GMT", now))
        assertEquals(31_000_000_000L, ChatGptPlanErrorsV1.retryAfterMinimumNanos("31", now))
        listOf("0", "-1", "1.5", "+1", "9223372036854775808", "9223372037", "18446744074", "tomorrow").forEach { bad ->
            assertThrows(IllegalArgumentException::class.java) { ChatGptPlanErrorsV1.retryAfterMinimumNanos(bad, now) }
        }
        assertThrows(IllegalArgumentException::class.java) {
            ChatGptPlanErrorsV1.retryAfterMinimumNanos("Fri, 01 Jan 9999 00:00:00 GMT", now)
        }
        assertEquals(ChatGptRecoveryV1.STOP, classify(503, metadata = headers("Retry-After" to "31")).recovery)
        assertEquals(ChatGptRecoveryV1.STOP, classify(503, metadata = headers("Retry-After" to "1", "retry-after" to "1")).recovery)
        assertEquals(ChatGptRecoveryV1.STOP, classify(503, metadata = headers("Retry-After" to "9223372036854775808")).recovery)
    }

    @Test fun diagnosticsAllowOnlySafeEnumsStatusAndSanitizedRequestId() {
        val decision = classify(400, error("wire-secret-code", "private.path.sentinel"), metadata = headers(
            "X-Request-Id" to "req_safe-123", "Authorization" to "Bearer credential-sentinel"))
        val rendered = decision.diagnostic.render()
        assertTrue(rendered.contains("code=unknown"))
        assertTrue(rendered.contains("param=OTHER"))
        assertTrue(rendered.contains("request_id=req_safe-123"))
        listOf("private-body-sentinel", "private.path.sentinel", "wire-secret-code", "credential-sentinel").forEach {
            assertFalse(rendered.contains(it))
            assertFalse(decision.toString().contains(it))
        }
        assertTrue(rendered.toByteArray().size <= 2048)
        assertNull(headers("X-Request-Id" to "req_ok", "x-request-id" to "req_second").requestId)
        assertNull(headers("X-Request-Id" to "private-id").requestId)
    }

    @Test fun headerFieldCountAndByteLimitsAreEnforced() {
        assertDoesNotThrow { headers(*Array(64) { "X-Test-$it" to "ok" }) }
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED,
            assertThrows(ModelProviderException::class.java) { headers(*Array(65) { "X-Test-$it" to "ok" }) }.kind)
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED,
            assertThrows(ModelProviderException::class.java) { headers("X-Test" to "x".repeat(4097)) }.kind)
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED,
            assertThrows(ModelProviderException::class.java) { headers("X".repeat(129) to "v") }.kind)
        assertDoesNotThrow { headers("X" to "v".repeat(4096)) }
        val exactHeaderBytes = Array(4) { "X$it" to "v".repeat(4090) }
        assertDoesNotThrow { headers(*exactHeaderBytes) }
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED,
            assertThrows(ModelProviderException::class.java) { headers(*Array(4) { "X$it" to "v".repeat(4096) }) }.kind)
    }

    @Test fun recognizesOnlyAllowlistedParamAndUnknownStatusIsFixedStop() {
        assertEquals(ChatGptSafeParamV1.MODEL, classify(400, error("subscription_sharing_unsupported_capability", "model")).diagnostic.param)
        assertEquals(ChatGptSafeParamV1.OTHER, classify(400, error("subscription_sharing_unsupported_capability", "input.secret")).diagnostic.param)
        assertEquals(ModelFailureKind.INVALID_REQUEST, classify(418).kind)
        assertEquals(ChatGptRecoveryV1.STOP, classify(418).recovery)
    }

    @Test fun malformedUnicodeEscapesCannotMintAllowlistedCodes() {
        for (escape in listOf("\\u００３２", "\\u٠٠٣٢")) {
            val diagnostic = classify(503, error("chatpass_v${escape}_scope_not_authorized")).diagnostic
            assertEquals(ChatGptSafeCodeV1.UNKNOWN, diagnostic.code)
            assertEquals(ChatGptBodyShapeV1.TRUNCATED, diagnostic.shape)
        }
        assertEquals(ChatGptSafeCodeV1.CHATPASS_V2_SCOPE_NOT_AUTHORIZED,
            classify(503, error("chatpass_v\\u0032_scope_not_authorized")).diagnostic.code)
    }

    @Test fun imfFixdateRejectsImpossibleDatesAndPreservesExactPastAndFutureMinima() {
        for (bad in listOf("Sat, 31 Feb 2026 00:00:00 GMT", "Sat, 29 Feb 2025 00:00:00 GMT",
            "Thu, 31 Apr 2025 00:00:00 GMT", "Thu, 05 Nov 2026 24:00:00 GMT",
            "Thu, 05 Nov 2026 00:00:60 GMT", "Fri, 05 Nov 2026 00:00:00 GMT",
            "Thu, 5 Nov 2026 00:00:00 GMT", "Thu, 05 Nov 2026 00:00:00 UTC")) {
            assertThrows(IllegalArgumentException::class.java) { ChatGptPlanErrorsV1.retryAfterMinimumNanos(bad, now) }
            val metadata = headers("Retry-After" to bad)
            assertTrue(metadata.retryAfterInvalid)
            assertNull(metadata.retryAfterMinimumNanos)
            assertEquals(ChatGptRecoveryV1.STOP, classify(503, metadata = metadata).recovery)
        }
        assertEquals(0L, ChatGptPlanErrorsV1.retryAfterMinimumNanos("Thu, 29 Feb 2024 00:00:00 GMT", now))
        assertEquals(0L, ChatGptPlanErrorsV1.retryAfterMinimumNanos("Thu, 05 Nov 2026 00:00:00 GMT", now))
        assertEquals(1_750_000_000L, ChatGptPlanErrorsV1.retryAfterMinimumNanos("Thu, 05 Nov 2026 00:00:02 GMT", now.plusNanos(250_000_000)))
        assertEquals(9_223_372_036_000_000_000L, ChatGptPlanErrorsV1.retryAfterMinimumNanos("9223372036", now))
    }

    @Test fun invalidRepeatedNegativeAndOverPolicyDelayStopsEveryRecoveryIncludingRenewal() {
        val bad = listOf("9223372037", "-1", "tomorrow", "31").map { headers("Retry-After" to it) } +
            listOf(headers("Retry-After" to "1", "retry-after" to "1"), ChatGptHeaderMetadataV1.validated(null, -1),
                ChatGptHeaderMetadataV1.validated(null, 30_000_000_001L), ChatGptHeaderMetadataV1.validated(null, null, true))
        for (status in listOf(401, 403, 408, 429, 500, 502, 503, 504)) {
            for (body in listOf(byteArrayOf(), error("subscription_sharing_invalid_user"), error("subscription_sharing_usage_unavailable"))) {
                val ordinary = classify(status, body)
                for (metadata in bad) {
                    val stopped = classify(status, body, metadata = metadata)
                    assertEquals(ChatGptRecoveryV1.STOP, stopped.recovery)
                    assertEquals(ordinary.kind, stopped.kind)
                    assertEquals(status, stopped.diagnostic.httpStatus)
                    assertEquals(ChatGptRecoveryV1.STOP, stopped.diagnostic.recovery)
                }
                for (metadata in listOf(headers(), headers("Retry-After" to "30"), ChatGptHeaderMetadataV1.validated(null, 0))) {
                    assertEquals(ordinary.recovery, classify(status, body, metadata = metadata).recovery)
                    assertEquals(ChatGptRecoveryV1.STOP, classify(status, body, stream = true, metadata = metadata).recovery)
                }
            }
        }
        assertEquals(ChatGptRecoveryV1.ONE_RENEWAL_IF_ELIGIBLE, classify(401, metadata = headers("Retry-After" to "30")).recovery)
    }

    @Test fun headerNamesUseAsciiTokensAndValuesRejectControlsWithoutReflection() {
        for (separator in "()<>@,;:\\\"/[]?={} \t" + "é" + '\u007f') {
            val ex = assertThrows(ModelProviderException::class.java) { headers("X${separator}Invalid" to "private-sentinel") }
            assertEquals(ModelFailureKind.MALFORMED_RESPONSE, ex.kind)
            assertFalse(ex.toString().contains("private-sentinel"))
            assertNull(ex.cause)
        }
        assertThrows(ModelProviderException::class.java) { headers("" to "v") }
        for (control in (0..31).filter { it != 9 } + (127..159)) {
            val ex = assertThrows(ModelProviderException::class.java) { headers("X-Test" to "private-sentinel${control.toChar()}value") }
            assertEquals(ModelFailureKind.MALFORMED_RESPONSE, ex.kind)
            assertFalse(ex.toString().contains("private-sentinel"))
        }
        assertDoesNotThrow { headers("!#$%&'*+-.^_`|~AZaz09" to "v\t é") }
        assertDoesNotThrow { headers("X".repeat(128) to "v") }
        assertDoesNotThrow { headers("X" to "é".repeat(2048)) }
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED, assertThrows(ModelProviderException::class.java) { headers("X" to ("é".repeat(2048) + "a")) }.kind)
    }

    @Test fun safeDiagnosticFactoryAdmitsOnlyNullOrHttpRange() {
        fun diagnostic(status: Int?) = ChatGptSafeDiagnosticV1.create(ModelFailureKind.INVALID_REQUEST, status,
            ChatGptBodyShapeV1.OTHER, ChatGptSafeCodeV1.UNKNOWN, ChatGptSafeParamV1.OTHER, ChatGptRecoveryV1.STOP, null)
        for (status in listOf(Int.MIN_VALUE, -1, 0, 99, 600, Int.MAX_VALUE)) {
            assertThrows(IllegalArgumentException::class.java) { diagnostic(status) }
        }
        for (status in listOf(null, 100, 599)) {
            assertEquals(status, diagnostic(status).httpStatus)
            assertTrue(diagnostic(status).render().contains("status=${status ?: "none"};"))
        }
    }
}
