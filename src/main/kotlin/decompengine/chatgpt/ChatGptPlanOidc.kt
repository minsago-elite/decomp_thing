package decompengine.chatgpt

import java.math.BigInteger
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import java.time.Instant
import java.util.Base64
import java.util.concurrent.CancellationException
import java.util.concurrent.TimeoutException

/** Fixed categories only: never retain input, key IDs, provider errors or throwable chains. */
internal class ChatGptOidcFailure(val reason: Reason) :
    RuntimeException("ChatGPT identity validation failed: ${reason.name}", null, false, false) {
    enum class Reason {
        INVALID_JSON, INVALID_INPUT, INVALID_DISCOVERY, INVALID_TOKEN_RESPONSE,
        INVALID_ID_TOKEN, INVALID_KEY_SET, UNKNOWN_KEY_REFETCH_ONCE, UNKNOWN_KEY,
        INVALID_SIGNATURE, INVALID_CLAIMS,
    }
    override fun toString() = "ChatGptOidcFailure(${reason.name})"
}

/** Normalizes parser/JCA/caller callback errors without reflecting their messages or causes. */
internal inline fun <T> oidcBoundary(block: () -> T): T = try { block() }
catch (e: ChatGptOidcFailure) { throw e }
catch (e: ChatGptAuthHttpException) { throw e }
catch (_: InterruptedException) {
    Thread.currentThread().interrupt()
    throw CancellationException("ChatGPT identity validation cancelled")
} catch (_: CancellationException) { throw CancellationException("ChatGPT identity validation cancelled") }
catch (_: TimeoutException) { throw TimeoutException("ChatGPT identity validation timed out") }
catch (_: com.fasterxml.jackson.core.JsonProcessingException) { throw ChatGptOidcFailure(ChatGptOidcFailure.Reason.INVALID_JSON) }
catch (_: java.nio.charset.CharacterCodingException) { throw ChatGptOidcFailure(ChatGptOidcFailure.Reason.INVALID_JSON) }
catch (_: Exception) { throw ChatGptOidcFailure(ChatGptOidcFailure.Reason.INVALID_INPUT) }

/**
 * Offline code-exchange/reauthorization validator, not a network client or production factory.
 * The trusted coordinator supplies bytes fetched from the pinned endpoints and its original operation.
 * It must bind expectedClientId/expectedNonce/expectedSubject to the pending attempt, use a current
 * receivedAt, and fence the store authEpoch before publication. No callback scopes are accepted here.
 *
 * This is deliberately NOT a refresh validator: every call requires the fresh authorization nonce.
 * Refresh's optional nonce and retained nonce hash need a separate reviewed coordinator path.
 */
internal object ChatGptPlanOidc {
    const val ISSUER = "https://auth.openai.com"
    const val DISCOVERY = "$ISSUER/.well-known/openid-configuration"
    const val AUTHORIZATION = "$ISSUER/api/accounts/authorize"
    const val TOKEN = "$ISSUER/api/accounts/oauth/token"
    const val JWKS = "$ISSUER/.well-known/jwks.json"
    private const val MAX_TOKEN_BYTES = 16 * 1024
    private val clientPattern = Regex("oaiapp_[A-Za-z0-9_-]{1,249}")
    private val scopePattern = Regex("[\\x21\\x23-\\x5B\\x5D-\\x7E]{1,256}")
    private val base64Pattern = Regex("[A-Za-z0-9_-]+")

    /** Compatibility wrapper; endpoint authority is only exposed by Metadata's scoped wrapper. */
    fun validateDiscovery(bytes: ByteArray, operation: ChatGptStoreOperation) {
        validateDiscoveryDocument(bytes, operation)
    }

    fun validateDiscoveryDocument(bytes: ByteArray, operation: ChatGptStoreOperation): ChatGptOidcDiscovery = oidcBoundary {
        operation.check()
        val discovery = ChatGptAuthJson.parse(bytes, operation)
        for ((name, pin) in mapOf("issuer" to ISSUER, "authorization_endpoint" to AUTHORIZATION,
            "token_endpoint" to TOKEN, "jwks_uri" to JWKS)) {
            operation.check()
            check(discovery.required(name).string() == pin, ChatGptOidcFailure.Reason.INVALID_DISCOVERY)
        }
        val endpoint = discovery.member("revocation_endpoint")?.string()?.let { value ->
            check(value.length <= 2048 && value.all { it.code in 0x21..0x7e } &&
                value.none { it == '%' || it == '\\' }, ChatGptOidcFailure.Reason.INVALID_DISCOVERY)
            val uri = java.net.URI(value)
            check(uri.scheme == "https" && uri.host == "auth.openai.com" &&
                uri.rawAuthority in setOf("auth.openai.com", "auth.openai.com:443") &&
                uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null &&
                uri.rawPath.startsWith('/') && !uri.rawPath.contains("//") &&
                uri.rawPath.split('/').none { it == "." || it == ".." }, ChatGptOidcFailure.Reason.INVALID_DISCOVERY)
            OidcEndpoint(uri)
        }
        operation.check()
        OidcDiscovery(endpoint)
    }

    /**
     * UNKNOWN_KEY_REFETCH_ONCE permits a future caller one JWKS reload within the SAME operation.
     * On that retry the caller must set jwksAlreadyRefetched=true; UNKNOWN_KEY is then terminal.
     * There is no fetch/retry/cache, token exposure outside internal types, or store mutation here.
     * JDK cryptographic calls are checked before/after, not claimed to be hard-preemptible.
     */
    fun validateAuthorizationResponse(
        tokenResponse: ByteArray,
        jwksBytes: ByteArray,
        expectedClientId: String,
        expectedNonce: String,
        receivedAt: Instant,
        operation: ChatGptStoreOperation,
        expectedSubject: String? = null,
        clockSkewSeconds: Long = 5,
        jwksAlreadyRefetched: Boolean = false,
    ): ChatGptPlanValidatedRegistration = oidcBoundary {
        verifyAuthorization(tokenResponse, validateJwksDocument(jwksBytes, operation), expectedClientId,
            expectedNonce, receivedAt, receivedAt, operation, expectedSubject, clockSkewSeconds,
            jwksAlreadyRefetched).registration
    }

    fun validateAuthorizationProof(
        tokenResponse: ByteArray, keys: ChatGptOidcJwks,
        snapshot: ChatGptAuthorizationSnapshot, code: ChatGptPlanOAuthAttempt.CallbackResult.Code,
        receivedAt: Instant, validatedAt: Instant, operation: ChatGptStoreOperation,
        jwksAlreadyRefetched: Boolean = false,
    ): ChatGptAuthorizationProof = oidcBoundary {
        operation.check()
        check(isOidcJwks(keys), ChatGptOidcFailure.Reason.INVALID_KEY_SET)
        check(snapshot.expectedClientId == null || snapshot.expectedClientId == code.issuedClientId,
            ChatGptOidcFailure.Reason.INVALID_CLAIMS)
        val verified = verifyAuthorization(tokenResponse, keys, code.issuedClientId, code.nonceForValidation,
            receivedAt, validatedAt, operation, snapshot.expectedSubject, 5, jwksAlreadyRefetched)
        operation.check()
        OidcProof(snapshot.attemptId, verified.registration, verified.idExp, validatedAt, verified.nonceHash)
    }

    private class VerifiedAuthorization(
        val registration: ChatGptPlanValidatedRegistration, val idExp: Instant, val nonceHash: String,
    )

    private fun verifyAuthorization(
        tokenResponse: ByteArray, keys: ChatGptOidcJwks, expectedClientId: String, expectedNonce: String,
        receivedAt: Instant, validatedAt: Instant, operation: ChatGptStoreOperation, expectedSubject: String?,
        clockSkewSeconds: Long, jwksAlreadyRefetched: Boolean,
    ): VerifiedAuthorization {
        operation.check()
        check(isOidcJwks(keys), ChatGptOidcFailure.Reason.INVALID_KEY_SET)
        check(expectedClientId.matches(clientPattern) && clockSkewSeconds in 0..60,
            ChatGptOidcFailure.Reason.INVALID_INPUT)
        boundedText(expectedNonce, 1024, ChatGptOidcFailure.Reason.INVALID_INPUT)
        expectedSubject?.let { boundedText(it, 2048, ChatGptOidcFailure.Reason.INVALID_INPUT) }
        val response = ChatGptAuthJson.parse(tokenResponse, operation)
        check(response.member("error") == null, ChatGptOidcFailure.Reason.INVALID_TOKEN_RESPONSE)
        val accessToken = token(response.required("access_token"))
        val refreshToken = response.member("refresh_token")?.let(::token)
        val idToken = token(response.required("id_token"))
        check(response.required("token_type").string().equals("Bearer", ignoreCase = true),
            ChatGptOidcFailure.Reason.INVALID_TOKEN_RESPONSE)
        val expiresIn = response.required("expires_in").integer()
        check(expiresIn in 1..(366L * 24 * 60 * 60), ChatGptOidcFailure.Reason.INVALID_TOKEN_RESPONSE)
        val expiresAt = receivedAt.plusSeconds(expiresIn) // checked Instant arithmetic
        val scopeString = response.required("scope").string()
        check(scopeString.length <= 64 * 257, ChatGptOidcFailure.Reason.INVALID_TOKEN_RESPONSE)
        val scopes = if (scopeString.isEmpty()) emptyList() else scopeString.split(' ')
        check(scopes.size <= 64 && scopes.distinct().size == scopes.size && scopes.all { it.matches(scopePattern) },
            ChatGptOidcFailure.Reason.INVALID_TOKEN_RESPONSE)
        operation.check()
        val claims = verifiedClaims(idToken, keys, operation, jwksAlreadyRefetched)
        validateClaims(claims, expectedClientId, expectedNonce, expectedSubject, validatedAt, clockSkewSeconds, operation)
        // Access tokens are opaque. Optional at_hash binds their exact bytes, never their decoded claims.
        claims.member("at_hash")?.let {
            operation.check()
            val hash = MessageDigest.getInstance("SHA-256").digest(accessToken.toByteArray(Charsets.UTF_8)).copyOf(16)
            check(MessageDigest.isEqual(decode(it.string(), 16), hash), ChatGptOidcFailure.Reason.INVALID_CLAIMS)
        }
        val subject = claims.required("sub").string()
        val label = claims.member("name")?.string()?.also { metadata(it, 256) } ?: "ChatGPT account"
        val email = claims.member("email")?.string()?.also { metadata(it, 320) }
        operation.check()
        val nonceHash = MessageDigest.getInstance("SHA-256").digest(expectedNonce.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        operation.check()
        oidcKeys(keys, operation) // scope/expiry must still be live after signature and claims work
        return VerifiedAuthorization(ChatGptPlanValidatedRegistration(ISSUER, expectedClientId, subject, label, email,
            ChatGptPlanTokenSet(accessToken, refreshToken, idToken, "Bearer", receivedAt, expiresAt,
                scopes.toSet(), nonceHash)), numericDate(claims.required("exp")), nonceHash)
    }

    private fun verifiedClaims(
        token: String, keys: ChatGptOidcJwks, operation: ChatGptStoreOperation, refetched: Boolean,
    ): ChatGptAuthJson {
        val parts = token.split('.')
        check(parts.size == 3, ChatGptOidcFailure.Reason.INVALID_ID_TOKEN)
        val header = ChatGptAuthJson.parse(decode(parts[0], MAX_TOKEN_BYTES), operation)
        check(header.required("alg").string() == "RS256", ChatGptOidcFailure.Reason.INVALID_ID_TOKEN)
        check(listOf("jku", "x5u", "jwk", "x5c", "crit", "b64").none { header.member(it) != null },
            ChatGptOidcFailure.Reason.INVALID_ID_TOKEN)
        header.member("typ")?.let { check(it.string() == "JWT", ChatGptOidcFailure.Reason.INVALID_ID_TOKEN) }
        val kid = header.required("kid").string()
        boundedText(kid, 256, ChatGptOidcFailure.Reason.INVALID_ID_TOKEN)
        val key = oidcKeys(keys, operation)[kid] ?: throw ChatGptOidcFailure(
            if (refetched) ChatGptOidcFailure.Reason.UNKNOWN_KEY else ChatGptOidcFailure.Reason.UNKNOWN_KEY_REFETCH_ONCE)
        val signatureBytes = decode(parts[2], 1024)
        check(signatureBytes.size == (key.modulus.bitLength() + 7) / 8, ChatGptOidcFailure.Reason.INVALID_SIGNATURE)
        // Check the payload encoding before verify, but do not parse or use its claims yet.
        check(parts[1].length <= MAX_TOKEN_BYTES && parts[1].matches(base64Pattern),
            ChatGptOidcFailure.Reason.INVALID_ID_TOKEN)
        operation.check()
        val verifier = Signature.getInstance("SHA256withRSA")
        verifier.initVerify(key)
        operation.check()
        verifier.update("${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII))
        operation.check()
        val verified = verifier.verify(signatureBytes)
        operation.check()
        check(verified, ChatGptOidcFailure.Reason.INVALID_SIGNATURE)
        return ChatGptAuthJson.parse(decode(parts[1], MAX_TOKEN_BYTES), operation)
    }

    fun validateJwksDocument(bytes: ByteArray, operation: ChatGptStoreOperation): ChatGptOidcJwks = oidcBoundary {
        val keys = ChatGptAuthJson.parse(bytes, operation).required("keys").elements()
        check(keys.size in 1..32, ChatGptOidcFailure.Reason.INVALID_KEY_SET)
        val admitted = linkedMapOf<String, RSAPublicKey>()
        for (key in keys) {
            operation.check()
            val id = key.required("kid").string()
            boundedText(id, 256, ChatGptOidcFailure.Reason.INVALID_KEY_SET)
            check(id !in admitted, ChatGptOidcFailure.Reason.INVALID_KEY_SET)
            check(listOf("jku", "x5u", "jwk", "x5c").none { key.member(it) != null },
                ChatGptOidcFailure.Reason.INVALID_KEY_SET)
            admitted[id] = admitKey(key, operation)
        }
        operation.check()
        OidcKeys(java.util.Collections.unmodifiableMap(admitted))
    }

    private fun admitKey(key: ChatGptAuthJson, operation: ChatGptStoreOperation): RSAPublicKey {
        check(key.required("kty").string() == "RSA", ChatGptOidcFailure.Reason.INVALID_KEY_SET)
        key.member("use")?.let { check(it.string() == "sig", ChatGptOidcFailure.Reason.INVALID_KEY_SET) }
        key.member("alg")?.let { check(it.string() == "RS256", ChatGptOidcFailure.Reason.INVALID_KEY_SET) }
        key.member("key_ops")?.let {
            val ops = it.elements().map { entry -> entry.string() }
            check(ops == listOf("verify"), ChatGptOidcFailure.Reason.INVALID_KEY_SET)
        }
        check(listOf("d", "p", "q", "dp", "dq", "qi", "oth").none { key.member(it) != null },
            ChatGptOidcFailure.Reason.INVALID_KEY_SET)
        val n = decode(key.required("n").string(), 1024)
        val e = decode(key.required("e").string(), 4)
        check(n.size in 256..1024 && n[0] != 0.toByte() && e.isNotEmpty() && e[0] != 0.toByte(),
            ChatGptOidcFailure.Reason.INVALID_KEY_SET)
        val modulus = BigInteger(1, n)
        val exponent = BigInteger(1, e)
        check(modulus.bitLength() in 2048..8192 && modulus.testBit(0) &&
            exponent >= BigInteger.valueOf(3) && exponent.testBit(0), ChatGptOidcFailure.Reason.INVALID_KEY_SET)
        operation.check()
        val publicKey = KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, exponent)) as RSAPublicKey
        operation.check()
        return publicKey
    }

    private fun validateClaims(
        claims: ChatGptAuthJson, client: String, nonce: String, subject: String?, now: Instant, skew: Long,
        operation: ChatGptStoreOperation,
    ) {
        check(claims.required("iss").string() == ISSUER, ChatGptOidcFailure.Reason.INVALID_CLAIMS)
        val sub = claims.required("sub").string()
        boundedText(sub, 2048, ChatGptOidcFailure.Reason.INVALID_CLAIMS)
        check(subject == null || sub == subject, ChatGptOidcFailure.Reason.INVALID_CLAIMS)
        val audience = claims.required("aud")
        val audiences = if (audience.isString()) listOf(audience.string()) else audience.elements().map { it.string() }
        check(audiences.size in 1..32 && audiences.distinct().size == audiences.size &&
            audiences.all { it.isNotBlank() && it.length <= 256 } && client in audiences,
            ChatGptOidcFailure.Reason.INVALID_CLAIMS)
        val azp = claims.member("azp")?.string()
        check((audiences.size == 1 || azp != null) && (azp == null || azp == client), ChatGptOidcFailure.Reason.INVALID_CLAIMS)
        claims.member("client_id")?.let { check(it.string() == client, ChatGptOidcFailure.Reason.INVALID_CLAIMS) }
        val exp = numericDate(claims.required("exp"))
        val iat = numericDate(claims.required("iat"))
        check(exp > now.minusSeconds(skew) && iat <= now.plusSeconds(skew) && iat < exp,
            ChatGptOidcFailure.Reason.INVALID_CLAIMS)
        claims.member("nbf")?.let {
            val nbf = numericDate(it)
            check(nbf <= now.plusSeconds(skew) && nbf < exp, ChatGptOidcFailure.Reason.INVALID_CLAIMS)
        }
        val actualNonce = claims.required("nonce").string()
        boundedText(actualNonce, 1024, ChatGptOidcFailure.Reason.INVALID_CLAIMS)
        check(MessageDigest.isEqual(actualNonce.toByteArray(Charsets.UTF_8), nonce.toByteArray(Charsets.UTF_8)),
            ChatGptOidcFailure.Reason.INVALID_CLAIMS)
        operation.check()
    }

    private fun numericDate(value: ChatGptAuthJson): Instant {
        val seconds = value.integer()
        check(seconds >= 0, ChatGptOidcFailure.Reason.INVALID_CLAIMS)
        return Instant.ofEpochSecond(seconds)
    }
    private fun decode(value: String, maxBytes: Int): ByteArray {
        check(value.length <= (maxBytes * 4 + 2) / 3 && value.matches(base64Pattern), ChatGptOidcFailure.Reason.INVALID_ID_TOKEN)
        val bytes = Base64.getUrlDecoder().decode(value)
        check(bytes.size <= maxBytes && Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) == value,
            ChatGptOidcFailure.Reason.INVALID_ID_TOKEN)
        return bytes
    }
    private fun token(value: ChatGptAuthJson): String = value.string().also {
        boundedText(it, MAX_TOKEN_BYTES, ChatGptOidcFailure.Reason.INVALID_TOKEN_RESPONSE)
    }
    private fun boundedText(value: String, maxBytes: Int, reason: ChatGptOidcFailure.Reason) {
        check(value.isNotBlank() && value.length <= maxBytes && value.none { Character.isISOControl(it) }, reason)
        val encoded = Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value))
        check(encoded.remaining() <= maxBytes, reason)
    }
    private fun metadata(value: String, limit: Int) {
        check(value.length <= limit && value.none { Character.isISOControl(it) || it in '\u202a'..'\u202e' || it in '\u2066'..'\u2069' },
            ChatGptOidcFailure.Reason.INVALID_CLAIMS)
    }
    private fun check(condition: Boolean, reason: ChatGptOidcFailure.Reason) {
        if (!condition) throw ChatGptOidcFailure(reason)
    }
    override fun toString() = "ChatGptPlanOidc"
}

internal abstract class ChatGptOidcDiscovery : ChatGptAuthSafeObject() {
    abstract val revocation: ChatGptAuthRevocationEndpoint?
}
internal abstract class ChatGptOidcJwks : ChatGptAuthSafeObject()

private class OidcDiscovery(override val revocation: ChatGptAuthRevocationEndpoint?) : ChatGptOidcDiscovery()
private class OidcKeys(val keys: Map<String, RSAPublicKey>) : ChatGptOidcJwks()
private class ScopedOidcKeys(val raw: OidcKeys, val use: ChatGptAuthKeysUse) : ChatGptOidcJwks()
private class ValidationOidcKeys(val scope: ScopedOidcKeys) : ChatGptOidcJwks()
private class OidcEndpoint(private val uri: java.net.URI) : ChatGptAuthRevocationEndpoint() {
    override fun newRevocationRequest(logout: ChatGptLocalLogout, operation: ChatGptStoreOperation, httpDeadline: ChatGptDeadline): java.net.http.HttpRequest {
        authHttpCheck(operation, httpDeadline)
        val body = authRevocationPublisher(logout, operation, httpDeadline)
        return java.net.http.HttpRequest.newBuilder(uri).version(java.net.http.HttpClient.Version.HTTP_1_1)
            .timeout(java.time.Duration.ofNanos(authHttpCheck(operation, httpDeadline)))
            .header("Content-Type", "application/x-www-form-urlencoded").header("Accept", "application/json")
            .POST(body).build().also { authHttpCheck(operation, httpDeadline) }
    }
}
private class OidcProof(
    override val attemptId: java.util.UUID,
    override val registration: ChatGptPlanValidatedRegistration,
    override val idTokenExpiresAt: Instant,
    override val verifiedAt: Instant,
    override val authorizationNonceHash: String,
) : ChatGptAuthorizationProof()

internal fun isOidcDiscovery(document: ChatGptOidcDiscovery): Boolean = document is OidcDiscovery
internal fun isOidcJwks(keys: ChatGptOidcJwks): Boolean = keys is OidcKeys || keys is ScopedOidcKeys || keys is ValidationOidcKeys
internal fun isOidcRevocationEndpoint(endpoint: ChatGptAuthRevocationEndpoint): Boolean = endpoint is OidcEndpoint

// A scoped key stays scoped even when a caller retains the document after closing its use.
// Both owners check their private concrete types before calling across the boundary.
internal fun scopeOidcJwks(keys: ChatGptOidcJwks, use: ChatGptAuthKeysUse): ChatGptOidcJwks {
    if (keys !is OidcKeys || !isMetadataKeysUse(use)) throw ChatGptOidcFailure(ChatGptOidcFailure.Reason.INVALID_KEY_SET)
    return ScopedOidcKeys(keys, use)
}
// Only an active concrete reply can reserve a scope. The verifier-only wrapper never escapes
// that reply's stack, so retaining a public document cannot bypass session reservation.
internal fun reserveOidcJwks(keys: ChatGptOidcJwks, reply: ChatGptAuthTokenReply,
    operation: ChatGptStoreOperation): ChatGptOidcJwks {
    if (!isTransportReplyValidation(reply, operation)) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
    return when (keys) {
        is OidcKeys -> keys
        is ScopedOidcKeys -> {
            reserveMetadataKeysUse(keys.use, reply, operation)
            ValidationOidcKeys(keys)
        }
        else -> authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
    }
}
private fun oidcKeys(keys: ChatGptOidcJwks, operation: ChatGptStoreOperation): Map<String, RSAPublicKey> = when (keys) {
    is OidcKeys -> keys.keys
    is ScopedOidcKeys -> {
        checkMetadataKeysUse(keys.use, operation)
        authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
    }
    is ValidationOidcKeys -> {
        checkMetadataKeysUse(keys.scope.use, operation)
        keys.scope.raw.keys
    }
    else -> throw ChatGptOidcFailure(ChatGptOidcFailure.Reason.INVALID_KEY_SET)
}
