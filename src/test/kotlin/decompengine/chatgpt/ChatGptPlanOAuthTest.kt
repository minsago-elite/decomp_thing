package decompengine.chatgpt

import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class ChatGptPlanOAuthTest {
    @Test
    fun `pkce matches RFC 7636 S256 known fixture`() {
        val attempt = ChatGptPlanOAuthAttempt.start(
            ChatGptPlanOAuthRegistration.Returning(ISSUED_CLIENT, HOST_ID),
            ChatGptPlanOAuthRedirect.of(1455),
            FakeClock(),
            QueueRandom(byteArrayOf(0, 1, 2), byteArrayOf(3, 4, 5), Base64.getUrlDecoder().decode(RFC_VERIFIER)),
        )

        val params = authorizationParams(attempt.authorizationRequest().uri)
        assertEquals(RFC_CHALLENGE, params.getValue("code_challenge"))
        assertEquals("S256", params.getValue("code_challenge_method"))
        assertEquals("http://127.0.0.1:1455/auth/callback", params.getValue("redirect_uri"))
        assertEquals("openid profile email offline_access resource.invoke chatgpt.tokens.use.direct", params.getValue("scope"))
        assertEquals(43, params.getValue("state").length)
        assertEquals(43, params.getValue("nonce").length)
    }

    @Test
    fun `new registration uses dynamic client and consistent name only initially`() {
        val attempt = newAttempt()
        val params = authorizationParams(attempt.authorizationRequest().uri)
        assertEquals("dynamic_agent_client", params.getValue("client_id"))
        assertEquals("Decomp Thing", params.getValue("agent_name_hint"))
        assertEquals(HOST_ID, params.getValue("ext_agent_host_id"))
        assertFalse("id_token_hint" in params)
        assertFalse("login_hint" in params)

        val callback = callback(attempt, "code=auth%2Bcode&client_id=$ISSUED_CLIENT&state=${params.getValue("state")}&scope=openid")
        val code = assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Code>(callback)
        assertEquals(params.getValue("nonce"), code.nonceForValidation)
        val fields = formFields(code.prepareExchange().encodedBody)
        assertEquals("authorization_code", fields.getValue("grant_type"))
        assertEquals(ISSUED_CLIENT, fields.getValue("client_id"))
        assertEquals("auth+code", fields.getValue("code"))
        assertEquals(TEST_VERIFIER, fields.getValue("code_verifier"))
        assertEquals("http://127.0.0.1:1455/auth/callback", fields.getValue("redirect_uri"))
        assertEquals("https://api.openai.com/v1", fields.getValue("resource"))
        assertFalse("client_secret" in fields)
    }

    @Test
    fun `returning uses selected issued client and paired optional hints`() {
        val attempt = returningAttempt()
        val params = authorizationParams(attempt.authorizationRequest().uri)
        assertEquals(ISSUED_CLIENT, params.getValue("client_id"))
        assertEquals("id-token-private-sentinel", params.getValue("id_token_hint"))
        assertEquals("person@example.test", params.getValue("login_hint"))
        assertFalse("agent_name_hint" in params)

        val result = callback(attempt, "code=return-code&state=${params.getValue("state")}")
        val code = assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Code>(result)
        assertEquals(ISSUED_CLIENT, formFields(code.prepareExchange().encodedBody).getValue("client_id"))
    }

    @Test
    fun `OAuth error with valid state consumes attempt and never exchanges code`() {
        val attempt = returningAttempt()
        val state = authorizationParams(attempt.authorizationRequest().uri).getValue("state")
        val result = callback(attempt, "error=access_denied&error_description=private-error-sentinel&state=$state")
        assertEquals(ChatGptPlanOAuthFailure.OAUTH_REJECTED, assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Rejected>(result).failure)
        assertEquals(ChatGptPlanOAuthFailure.ATTEMPT_USED, rejected(attempt, "code=later&state=$state"))
        assertFalse(result.toString().contains("private-error-sentinel"))
    }

    @Test
    fun `state is validated before OAuth error handling`() {
        val attempt = returningAttempt()
        val result = rejected(attempt, "error=access_denied&state=wrong")
        assertEquals(ChatGptPlanOAuthFailure.STATE_MISMATCH, result)
    }

    @Test
    fun `new callback requires issued client and returning rejects retargeting`() {
        val fresh = newAttempt()
        val state = authorizationParams(fresh.authorizationRequest().uri).getValue("state")
        assertEquals(ChatGptPlanOAuthFailure.MISSING_ISSUED_CLIENT, rejected(fresh, "code=c&state=$state"))

        val returning = returningAttempt()
        val returningState = authorizationParams(returning.authorizationRequest().uri).getValue("state")
        assertEquals(ChatGptPlanOAuthFailure.CLIENT_MISMATCH, rejected(returning, "code=c&state=$returningState&client_id=oaiapp_other"))
    }

    @Test
    fun `duplicates malformed percent UTF8 unknown and oversized query fail closed`() {
        fun run(query: String) = rejected(returningAttempt(), query)
        assertEquals(ChatGptPlanOAuthFailure.DUPLICATE_PARAMETER, run("state=x&state=y&code=c"))
        assertEquals(ChatGptPlanOAuthFailure.MALFORMED_QUERY, run("state=%"))
        assertEquals(ChatGptPlanOAuthFailure.MALFORMED_QUERY, run("state=%C3%28"))
        assertEquals(ChatGptPlanOAuthFailure.MALFORMED_QUERY, run("state=x&redirect=https%3A%2F%2Fevil"))
        assertEquals(ChatGptPlanOAuthFailure.CALLBACK_TOO_LARGE, run("state=x&code=" + "a".repeat(16 * 1024)))
    }

    @Test
    fun `method host port path and absolute redirect controls are exact`() {
        val state = authorizationParams(returningAttempt().authorizationRequest().uri).getValue("state")
        assertEquals(ChatGptPlanOAuthFailure.INVALID_CALLBACK_METHOD, rejected(returningAttempt(), "code=c&state=$state", method = "POST"))
        assertEquals(ChatGptPlanOAuthFailure.INVALID_CALLBACK_TARGET, rejected(returningAttempt(), "code=c&state=$state", host = "localhost:1455"))
        assertEquals(ChatGptPlanOAuthFailure.INVALID_CALLBACK_TARGET, rejected(returningAttempt(), "code=c&state=$state", host = "127.0.0.1:1456"))
        assertEquals(ChatGptPlanOAuthFailure.INVALID_CALLBACK_TARGET, rejected(returningAttempt(), "code=c&state=$state", target = "/callback?code=c&state=$state"))
        assertEquals(ChatGptPlanOAuthFailure.INVALID_CALLBACK_TARGET, rejected(returningAttempt(), "code=c&state=$state", target = "http://127.0.0.1:1455/auth/callback?code=c&state=$state"))
        assertEquals(ChatGptPlanOAuthFailure.INVALID_CALLBACK_TARGET, rejected(returningAttempt(), "code=c&state=$state", target = "/auth/callback?code=c&state=$state#fragment"))
    }

    @Test
    fun `attempt timeout is original and cannot be renewed`() {
        val clock = FakeClock()
        val attempt = returningAttempt(clock = clock)
        val state = authorizationParams(attempt.authorizationRequest().uri).getValue("state")
        clock.now += 5L * 60L * 1_000_000_000L
        assertEquals(ChatGptPlanOAuthFailure.TIMEOUT, rejected(attempt, "code=c&state=$state"))
    }

    @Test
    fun `cancellation and reuse are terminal`() {
        var isCancelled = false
        val attempt = attempt(cancellation = ChatGptPlanOAuthCancellation { isCancelled })
        isCancelled = true
        assertEquals(ChatGptPlanOAuthFailure.CANCELLED, rejected(attempt, "code=c&state=x"))
        assertEquals(ChatGptPlanOAuthFailure.ATTEMPT_USED, rejected(attempt, "code=c&state=x"))
    }

    @Test
    fun `valid callback result and auth artifacts redact secret sentinels`() {
        val attempt = attempt(registration = ChatGptPlanOAuthRegistration.Returning(ISSUED_CLIENT, HOST_ID, "id-token-private-sentinel"))
        val request = attempt.authorizationRequest()
        val state = authorizationParams(request.uri).getValue("state")
        val codeResult = assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Code>(callback(attempt, "code=auth-code-private-sentinel&state=$state"))
        val form = codeResult.prepareExchange()
        val rendered = listOf(attempt, request, codeResult, form, codeResult.run { toString() }).joinToString()
        assertFalse(rendered.contains("id-token-private-sentinel"))
        assertFalse(rendered.contains("auth-code-private-sentinel"))
        assertFalse(rendered.contains("access.openai.com"))
        assertTrue(form.toString().contains("redacted"))
    }

    @Test
    fun `concurrent callbacks have one single-use winner`() {
        val attempt = returningAttempt()
        val state = authorizationParams(attempt.authorizationRequest().uri).getValue("state")
        val ready = CountDownLatch(2)
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        try {
            val results = (1..2).map {
                pool.submit<Any> {
                    ready.countDown()
                    start.await()
                    callback(attempt, "code=c$it&state=$state")
                }
            }
            assertTrue(ready.await(2, TimeUnit.SECONDS))
            start.countDown()
            val values = results.map { it.get(2, TimeUnit.SECONDS) }
            assertEquals(1, values.count { it is ChatGptPlanOAuthAttempt.CallbackResult.Code })
            assertEquals(1, values.count {
                it is ChatGptPlanOAuthAttempt.CallbackResult.Rejected && it.failure == ChatGptPlanOAuthFailure.ATTEMPT_USED
            })
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun `registration and redirect constructors reject nonconforming values`() {
        assertEquals("INVALID_REDIRECT", runCatching { ChatGptPlanOAuthRedirect.of(0) }.exceptionOrNull()?.message)
        assertEquals("INVALID_REDIRECT", runCatching { ChatGptPlanOAuthRedirect.of(65536) }.exceptionOrNull()?.message)
        assertEquals("INVALID_REGISTRATION", runCatching {
            ChatGptPlanOAuthAttempt.start(ChatGptPlanOAuthRegistration.Returning("dynamic_agent_client", HOST_ID), ChatGptPlanOAuthRedirect.of(1455), FakeClock(), QueueRandom())
        }.exceptionOrNull()?.message)
    }

    @Test
    fun `percent escapes require ASCII hex and retain valid encoded UTF8`() {
        for (encoded in listOf("%４1", "%4１", "%٤1", "%4١", "%４Ａ", "%4Ａ", "%Ｃ３%Ａ９")) {
            val pending = returningAttempt()
            val state = authorizationParams(pending.authorizationRequest().uri).getValue("state")
            assertEquals(ChatGptPlanOAuthFailure.MALFORMED_QUERY, rejected(pending, "state=$state&code=$encoded"))
        }
        for ((encoded, expected) in listOf("%41" to "A", "%4a" to "J", "%C3%A9" to "é")) {
            val pending = returningAttempt()
            val state = authorizationParams(pending.authorizationRequest().uri).getValue("state")
            val result = assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Code>(callback(pending, "state=$state&code=$encoded"))
            assertEquals(expected, formFields(result.prepareExchange().encodedBody).getValue("code"))
        }
    }

    @Test
    fun `callback query preserves exact byte boundary and rejects one over`() {
        for (extra in 0..1) {
            val pending = returningAttempt()
            val state = authorizationParams(pending.authorizationRequest().uri).getValue("state")
            val prefix = "state=$state&code=c&scope="
            val query = prefix + "a".repeat(ChatGptPlanOAuthAttempt.MAX_CALLBACK_QUERY_BYTES - prefix.length + extra)
            if (extra == 0) assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Code>(callback(pending, query))
            else assertEquals(ChatGptPlanOAuthFailure.CALLBACK_TOO_LARGE, rejected(pending, query))
        }
        assertEquals(ChatGptPlanOAuthFailure.CALLBACK_TOO_LARGE,
            rejected(returningAttempt(), "scope=" + "é".repeat(8192)))
    }

    @Test
    fun `oversized callback rejection allocates independently of target length`() {
        val allocation = java.lang.management.ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
        check(allocation.isThreadAllocatedMemorySupported)
        allocation.isThreadAllocatedMemoryEnabled = true
        repeat(20) { rejected(returningAttempt(), "scope=" + "a".repeat(20_000)) }
        val pending = returningAttempt()
        val target = "/auth/callback?scope=" + "a".repeat(8 * 1024 * 1024)
        val threadId = Thread.currentThread().id
        val before = allocation.getThreadAllocatedBytes(threadId)
        val result = pending.consumeCallback("GET", "127.0.0.1:1455", target)
        val allocated = allocation.getThreadAllocatedBytes(threadId) - before
        assertEquals(ChatGptPlanOAuthFailure.CALLBACK_TOO_LARGE,
            assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Rejected>(result).failure)
        assertTrue(allocated in 0 until 128 * 1024, "rejection allocated $allocated bytes")
    }

    private fun newAttempt(clock: FakeClock = FakeClock()) = attempt(ChatGptPlanOAuthRegistration.New(HOST_ID, "Decomp Thing"), clock)
    private fun returningAttempt(clock: FakeClock = FakeClock()) = attempt(ChatGptPlanOAuthRegistration.Returning(ISSUED_CLIENT, HOST_ID, "id-token-private-sentinel", "person@example.test"), clock)

    private fun attempt(
        registration: ChatGptPlanOAuthRegistration = ChatGptPlanOAuthRegistration.Returning(ISSUED_CLIENT, HOST_ID),
        clock: FakeClock = FakeClock(),
        cancellation: ChatGptPlanOAuthCancellation = ChatGptPlanOAuthCancellation { false },
    ) = ChatGptPlanOAuthAttempt.start(registration, ChatGptPlanOAuthRedirect.of(1455), clock, QueueRandom(byteArrayOf(3, 4, 5)), cancellation)

    private fun callback(attempt: ChatGptPlanOAuthAttempt, query: String, method: String = "GET", host: String = "127.0.0.1:1455", target: String = "/auth/callback?$query") =
        attempt.consumeCallback(method, host, target)

    private fun rejected(attempt: ChatGptPlanOAuthAttempt, query: String, method: String = "GET", host: String = "127.0.0.1:1455", target: String = "/auth/callback?$query"): ChatGptPlanOAuthFailure =
        assertEqualsFailure(assertIs<ChatGptPlanOAuthAttempt.CallbackResult.Rejected>(callback(attempt, query, method, host, target)).failure)

    private fun assertEqualsFailure(failure: ChatGptPlanOAuthFailure): ChatGptPlanOAuthFailure = failure

    private fun authorizationParams(uri: String): Map<String, String> = uri.substringAfter('?').split('&').associate { part ->
        val split = part.indexOf('=')
        URLDecoder.decode(part.substring(0, split), StandardCharsets.UTF_8) to URLDecoder.decode(part.substring(split + 1), StandardCharsets.UTF_8)
    }

    private fun formFields(body: String): Map<String, String> = body.split('&').associate { part ->
        val split = part.indexOf('=')
        URLDecoder.decode(part.substring(0, split), StandardCharsets.UTF_8) to URLDecoder.decode(part.substring(split + 1), StandardCharsets.UTF_8)
    }

    private class FakeClock(var now: Long = 1234L) : ChatGptPlanOAuthClock {
        override fun monotonicNanos(): Long = now
    }

    private class QueueRandom(private vararg val values: ByteArray) : ChatGptPlanOAuthRandom {
        private var index = 0
        override fun nextBytes(destination: ByteArray) {
            val value = values.getOrNull(index++) ?: ByteArray(destination.size) { (it + 8).toByte() }
            value.copyInto(destination, endIndex = minOf(value.size, destination.size))
            if (value.size < destination.size) destination.fill(0, value.size, destination.size)
        }
    }

    companion object {
        private const val HOST_ID = "urn:uuid:123e4567-e89b-12d3-a456-426614174000"
        private const val ISSUED_CLIENT = "oaiapp_client-example"
        private const val RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        private const val RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        private const val TEST_VERIFIER = "CAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJic"
    }
}
