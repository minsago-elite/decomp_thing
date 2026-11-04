package decompengine.chatgpt

import java.net.URLEncoder
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference

/** The selected account is explicit; this helper never consults ambient selection state. */
sealed class ChatGptPlanOAuthRegistration {
    abstract val extAgentHostId: String

    class New(
        override val extAgentHostId: String,
        val agentNameHint: String,
    ) : ChatGptPlanOAuthRegistration() {
        override fun toString(): String = "New(extAgentHostId=<redacted>, agentNameHint=<redacted>)"
    }

    class Returning(
        val issuedClientId: String,
        override val extAgentHostId: String,
        /** Optional ID-token hint from this selected registration only. */
        internal val idTokenHint: String? = null,
        /** Optional email hint from this selected registration only. */
        internal val loginHint: String? = null,
    ) : ChatGptPlanOAuthRegistration() {
        override fun toString(): String = "Returning(issuedClientId=<redacted>, extAgentHostId=<redacted>, hints=<redacted>)"
    }
}

/** A fixed numeric loopback endpoint. It intentionally has no listener or socket behavior. */
class ChatGptPlanOAuthRedirect private constructor(val value: String, val port: Int) {
    internal val hostHeader: String = "127.0.0.1:$port"

    override fun toString(): String = "ChatGptPlanOAuthRedirect(<loopback-redacted>)"

    companion object {
        fun of(port: Int): ChatGptPlanOAuthRedirect {
            require(port in 1..65535) { "INVALID_REDIRECT" }
            return ChatGptPlanOAuthRedirect("http://127.0.0.1:$port/auth/callback", port)
        }
    }
}

fun interface ChatGptPlanOAuthClock {
    fun monotonicNanos(): Long
}

fun interface ChatGptPlanOAuthRandom {
    fun nextBytes(destination: ByteArray)
}

fun interface ChatGptPlanOAuthCancellation {
    fun isCancelled(): Boolean
}

object ChatGptPlanOAuthProduction {
    private val source = SecureRandom()
    val secureRandom: ChatGptPlanOAuthRandom = ChatGptPlanOAuthRandom { source.nextBytes(it) }
}

enum class ChatGptPlanOAuthFailure {
    CANCELLED,
    TIMEOUT,
    ATTEMPT_USED,
    INVALID_CALLBACK_METHOD,
    INVALID_CALLBACK_TARGET,
    CALLBACK_TOO_LARGE,
    MALFORMED_QUERY,
    DUPLICATE_PARAMETER,
    MISSING_STATE,
    STATE_MISMATCH,
    INVALID_OAUTH_ERROR,
    OAUTH_REJECTED,
    MISSING_CODE,
    INVALID_CODE,
    MISSING_ISSUED_CLIENT,
    INVALID_ISSUED_CLIENT,
    CLIENT_MISMATCH,
}

class ChatGptPlanOAuthException(val failure: ChatGptPlanOAuthFailure) : Exception(failure.name) {
    override fun toString(): String = "ChatGptPlanOAuthException(${failure.name})"
}

/** All fields are attempt-bound. URL rendering and exchange are intentionally separate operations. */
class ChatGptPlanOAuthAttempt private constructor(
    private val registration: ChatGptPlanOAuthRegistration,
    val redirect: ChatGptPlanOAuthRedirect,
    private val clock: ChatGptPlanOAuthClock,
    private val cancellation: ChatGptPlanOAuthCancellation,
    private val createdAtNanos: Long,
    private val state: String,
    private val nonce: String,
    private val verifier: String,
    private val challenge: String,
) {
    private val outcome = AtomicReference(Outcome.OPEN)

    /** Contains bearer-like hints and state. Only trusted future browser-launch code may inspect it. */
    class AuthorizationRequest internal constructor(internal val uri: String) {
        override fun toString(): String = "ChatGptPlanOAuthAuthorizationRequest(<redacted>)"
    }

    /** Authorization-code material is private to trusted host transport code and always redacted. */
    class CodeExchangeForm internal constructor(internal val encodedBody: String) {
        override fun toString(): String = "ChatGptPlanOAuthCodeExchangeForm(<redacted>)"
    }

    sealed class CallbackResult {
        class Code internal constructor(private val owner: ChatGptPlanOAuthAttempt, internal val code: String, internal val issuedClientId: String) : CallbackResult() {
            /** Attempt nonce for the later trusted ID-token validator; never public metadata. */
            internal val nonceForValidation: String = owner.nonce

            fun prepareExchange(): CodeExchangeForm {
                owner.ensureActiveDeadline()
                val fields = linkedMapOf(
                    "grant_type" to "authorization_code",
                    "client_id" to issuedClientId,
                    "code" to code,
                    "code_verifier" to owner.verifier,
                    "redirect_uri" to owner.redirect.value,
                    "resource" to RESOURCE,
                )
                return CodeExchangeForm(fields.entries.joinToString("&") { (key, value) -> "${formEncode(key)}=${formEncode(value)}" })
            }

            override fun toString(): String = "ChatGptPlanOAuthCallbackCode(<redacted>)"
        }

        class Rejected internal constructor(val failure: ChatGptPlanOAuthFailure) : CallbackResult() {
            override fun toString(): String = "ChatGptPlanOAuthCallbackRejected(${failure.name})"
        }
    }

    /**
     * Consume the attempt once. [rawTarget] must be origin-form (for example
     * `/auth/callback?code=...`); [hostHeader] must match the bound numeric loopback port.
     */
    fun consumeCallback(method: String, hostHeader: String, rawTarget: String): CallbackResult {
        if (!outcome.compareAndSet(Outcome.OPEN, Outcome.CONSUMING)) {
            return CallbackResult.Rejected(ChatGptPlanOAuthFailure.ATTEMPT_USED)
        }
        return try {
            ensureActiveDeadline()
            if (method != "GET") fail(ChatGptPlanOAuthFailure.INVALID_CALLBACK_METHOD)
            if (hostHeader != redirect.hostHeader) fail(ChatGptPlanOAuthFailure.INVALID_CALLBACK_TARGET)
            val query = rawQuery(rawTarget)
            if (query.toByteArray(StandardCharsets.UTF_8).size > MAX_CALLBACK_QUERY_BYTES) fail(ChatGptPlanOAuthFailure.CALLBACK_TOO_LARGE)
            val params = parseQuery(query)
            val returnedState = params["state"] ?: fail(ChatGptPlanOAuthFailure.MISSING_STATE)
            if (!MessageDigest.isEqual(state.toByteArray(StandardCharsets.UTF_8), returnedState.toByteArray(StandardCharsets.UTF_8))) {
                fail(ChatGptPlanOAuthFailure.STATE_MISMATCH)
            }

            val oauthError = params["error"]
            val code = params["code"]
            if (oauthError != null) {
                if (oauthError !in OAUTH_ERRORS) fail(ChatGptPlanOAuthFailure.INVALID_OAUTH_ERROR)
                if (code != null) fail(ChatGptPlanOAuthFailure.INVALID_OAUTH_ERROR)
                CallbackResult.Rejected(ChatGptPlanOAuthFailure.OAUTH_REJECTED)
            } else {
                if ("error_description" in params || "error_uri" in params) fail(ChatGptPlanOAuthFailure.MALFORMED_QUERY)
                if (code == null) fail(ChatGptPlanOAuthFailure.MISSING_CODE)
                if (code.isEmpty() || code.length > MAX_CODE_CHARS || code.any { it.isISOControl() }) fail(ChatGptPlanOAuthFailure.INVALID_CODE)
                val returnedClient = params["client_id"]
                val exchangeClient = when (registration) {
                    is ChatGptPlanOAuthRegistration.New -> {
                        val issued = returnedClient ?: fail(ChatGptPlanOAuthFailure.MISSING_ISSUED_CLIENT)
                        if (!ISSUED_CLIENT.matches(issued)) fail(ChatGptPlanOAuthFailure.INVALID_ISSUED_CLIENT)
                        issued
                    }
                    is ChatGptPlanOAuthRegistration.Returning -> {
                        if (returnedClient != null && returnedClient != registration.issuedClientId) fail(ChatGptPlanOAuthFailure.CLIENT_MISMATCH)
                        registration.issuedClientId
                    }
                }
                CallbackResult.Code(this, code, exchangeClient)
            }
        } catch (failure: ChatGptPlanOAuthException) {
            CallbackResult.Rejected(failure.failure)
        } finally {
            outcome.set(Outcome.CONSUMED)
        }
    }

    /** Returns a terminal cancellation result without exposing any attempt values. */
    fun cancel(): ChatGptPlanOAuthFailure? {
        return if (outcome.compareAndSet(Outcome.OPEN, Outcome.CONSUMED)) {
            ChatGptPlanOAuthFailure.CANCELLED
        } else {
            ChatGptPlanOAuthFailure.ATTEMPT_USED
        }
    }

    /** Fresh URL parameters for a future trusted launcher; this function does not open a browser. */
    fun authorizationRequest(): AuthorizationRequest {
        ensureActiveDeadline()
        if (outcome.get() != Outcome.OPEN) fail(ChatGptPlanOAuthFailure.ATTEMPT_USED)
        val fields = linkedMapOf(
            "client_id" to when (registration) {
                is ChatGptPlanOAuthRegistration.New -> DYNAMIC_CLIENT
                is ChatGptPlanOAuthRegistration.Returning -> registration.issuedClientId
            },
            "response_type" to "code",
            "redirect_uri" to redirect.value,
            "scope" to SCOPES,
            "resource" to RESOURCE,
            "state" to state,
            "nonce" to nonce,
            "code_challenge_method" to "S256",
            "code_challenge" to challenge,
            "ext_agent_host_id" to registration.extAgentHostId,
        )
        when (registration) {
            is ChatGptPlanOAuthRegistration.New -> fields["agent_name_hint"] = registration.agentNameHint
            is ChatGptPlanOAuthRegistration.Returning -> {
                registration.idTokenHint?.let { fields["id_token_hint"] = it }
                registration.loginHint?.let { fields["login_hint"] = it }
            }
        }
        return AuthorizationRequest(AUTHORIZATION_ENDPOINT + "?" + fields.entries.joinToString("&") { (key, value) -> "${formEncode(key)}=${formEncode(value)}" })
    }

    private fun ensureActiveDeadline() {
        if (cancellation.isCancelled()) fail(ChatGptPlanOAuthFailure.CANCELLED)
        val elapsed = clock.monotonicNanos() - createdAtNanos
        if (elapsed < 0 || elapsed >= INTERACTIVE_BUDGET_NANOS) fail(ChatGptPlanOAuthFailure.TIMEOUT)
    }

    override fun toString(): String = "ChatGptPlanOAuthAttempt(<redacted>)"

    private enum class Outcome { OPEN, CONSUMING, CONSUMED }

    companion object {
        const val MAX_CALLBACK_QUERY_BYTES = 16 * 1024
        private const val MAX_CODE_CHARS = 4096
        private const val INTERACTIVE_BUDGET_NANOS = 5L * 60L * 1_000_000_000L
        private const val DYNAMIC_CLIENT = "dynamic_agent_client"
        private const val AUTHORIZATION_ENDPOINT = "https://auth.openai.com/api/accounts/authorize"
        private const val RESOURCE = "https://api.openai.com/v1"
        private const val SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
        private val OAUTH_ERRORS = setOf("access_denied", "login_required", "interaction_required", "invalid_request", "server_error", "temporarily_unavailable")
        private val ISSUED_CLIENT = Regex("oaiapp_[A-Za-z0-9_-]{1,160}")

        fun start(
            registration: ChatGptPlanOAuthRegistration,
            redirect: ChatGptPlanOAuthRedirect,
            clock: ChatGptPlanOAuthClock,
            random: ChatGptPlanOAuthRandom,
            cancellation: ChatGptPlanOAuthCancellation = ChatGptPlanOAuthCancellation { false },
        ): ChatGptPlanOAuthAttempt {
            validateRegistration(registration)
            if (cancellation.isCancelled()) fail(ChatGptPlanOAuthFailure.CANCELLED)
            val values = Array(3) { ByteArray(32).also(random::nextBytes) }
            val state = base64Url(values[0])
            val nonce = base64Url(values[1])
            val verifier = base64Url(values[2])
            val challenge = base64Url(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(StandardCharsets.US_ASCII)))
            return ChatGptPlanOAuthAttempt(registration, redirect, clock, cancellation, clock.monotonicNanos(), state, nonce, verifier, challenge)
        }

        private fun validateRegistration(registration: ChatGptPlanOAuthRegistration) {
            if (!HOST_ID.matches(registration.extAgentHostId)) throw IllegalArgumentException("INVALID_REGISTRATION")
            when (registration) {
                is ChatGptPlanOAuthRegistration.New -> if (!validHint(registration.agentNameHint, 128)) throw IllegalArgumentException("INVALID_REGISTRATION")
                is ChatGptPlanOAuthRegistration.Returning -> {
                    if (!ISSUED_CLIENT.matches(registration.issuedClientId)) throw IllegalArgumentException("INVALID_REGISTRATION")
                    if (registration.idTokenHint != null && !validHint(registration.idTokenHint, 16 * 1024)) throw IllegalArgumentException("INVALID_REGISTRATION")
                    if (registration.loginHint != null && !validHint(registration.loginHint, 320)) throw IllegalArgumentException("INVALID_REGISTRATION")
                }
            }
        }

        private fun validHint(value: String, max: Int): Boolean = value.isNotBlank() && value.length <= max && value.none { it.isISOControl() }
        private val HOST_ID = Regex("(?:urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|urn:ietf:params:oauth:jwk-thumbprint:[A-Za-z0-9_-]{20,128}|did:key:[A-Za-z0-9._:-]{8,256})")
    }
}

private fun base64Url(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

private fun formEncode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8)

private fun rawQuery(rawTarget: String): String {
    val prefix = "/auth/callback?"
    if (!rawTarget.startsWith(prefix)) fail(ChatGptPlanOAuthFailure.INVALID_CALLBACK_TARGET)
    // Reject before scanning or copying an attacker-sized target. The byte bound
    // is still checked by the caller after this constant-space character bound.
    if (rawTarget.length - prefix.length > ChatGptPlanOAuthAttempt.MAX_CALLBACK_QUERY_BYTES) {
        fail(ChatGptPlanOAuthFailure.CALLBACK_TOO_LARGE)
    }
    if (rawTarget.contains('#')) fail(ChatGptPlanOAuthFailure.INVALID_CALLBACK_TARGET)
    val query = rawTarget.substring(prefix.length)
    if (query.isEmpty()) fail(ChatGptPlanOAuthFailure.MALFORMED_QUERY)
    return query
}

private fun parseQuery(rawQuery: String): Map<String, String> {
    val result = LinkedHashMap<String, String>()
    for (pair in rawQuery.split('&')) {
        if (pair.isEmpty()) fail(ChatGptPlanOAuthFailure.MALFORMED_QUERY)
        val equals = pair.indexOf('=')
        if (equals <= 0) fail(ChatGptPlanOAuthFailure.MALFORMED_QUERY)
        val key = strictFormDecode(pair.substring(0, equals))
        val value = strictFormDecode(pair.substring(equals + 1))
        if (key !in CALLBACK_PARAMETERS) fail(ChatGptPlanOAuthFailure.MALFORMED_QUERY)
        if (result.putIfAbsent(key, value) != null) fail(ChatGptPlanOAuthFailure.DUPLICATE_PARAMETER)
    }
    return result
}

private fun strictFormDecode(value: String): String {
    val bytes = ArrayList<Byte>(value.length)
    var index = 0
    while (index < value.length) {
        when (val ch = value[index]) {
            '+' -> { bytes.add(0x20.toByte()); index++ }
            '%' -> {
                if (index + 2 >= value.length) fail(ChatGptPlanOAuthFailure.MALFORMED_QUERY)
                val high = asciiHex(value[index + 1]) ?: fail(ChatGptPlanOAuthFailure.MALFORMED_QUERY)
                val low = asciiHex(value[index + 2]) ?: fail(ChatGptPlanOAuthFailure.MALFORMED_QUERY)
                bytes.add(((high shl 4) or low).toByte())
                index += 3
            }
            else -> {
                if (ch.code > 0x7e || ch.code < 0x21) fail(ChatGptPlanOAuthFailure.MALFORMED_QUERY)
                bytes.add(ch.code.toByte())
                index++
            }
        }
    }
    return try {
        StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes.toByteArray())).toString()
    } catch (_: CharacterCodingException) {
        fail(ChatGptPlanOAuthFailure.MALFORMED_QUERY)
    }
}

private val CALLBACK_PARAMETERS = setOf("code", "state", "scope", "client_id", "error", "error_description", "error_uri")

private fun asciiHex(value: Char): Int? = when (value) {
    in '0'..'9' -> value - '0'
    in 'a'..'f' -> value - 'a' + 10
    in 'A'..'F' -> value - 'A' + 10
    else -> null
}

private fun fail(failure: ChatGptPlanOAuthFailure): Nothing = throw ChatGptPlanOAuthException(failure)
