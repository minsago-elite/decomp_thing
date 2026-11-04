package decompengine.chatgpt

import kotlinx.serialization.json.*
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.concurrent.CancellationException
import java.util.concurrent.TimeoutException
import kotlin.test.*

class ChatGptPlanOidcTest {
    private val now = Instant.parse("2026-11-05T12:00:00Z")
    private val client = "oaiapp_synthetic"
    private val nonce = "synthetic-authorization-nonce-0123456789"
    private val subject = "synthetic-subject"
    private val sentinel = "SYNTHETIC_SECRET_SENTINEL_4b63589b"
    private val allScopes = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
    private fun operation() = ChatGptStoreOperation.start()
    private fun fixture(name: String): ByteArray = javaClass.getResourceAsStream("/chatgpt/oidc/" + name)!!.use { it.readBytes() }
    private fun jwks(bits: Int = 2048) = fixture("rsa" + bits + ".jwks.json")
    private fun b64(bytes: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    private fun json(text: String) = Json.parseToJsonElement(text).jsonObject
    private fun change(base: String, vararg edits: Pair<String, JsonElement?>): String {
        val values = json(base).toMutableMap()
        for ((k, v) in edits) if (v == null) values.remove(k) else values[k] = v
        return JsonObject(values).toString()
    }
    private fun claims(vararg edits: Pair<String, JsonElement?>): String = change(buildJsonObject {
        put("iss", ChatGptPlanOidc.ISSUER); put("aud", client); put("sub", subject); put("nonce", nonce)
        put("exp", now.epochSecond + 3600); put("iat", now.epochSecond); put("nbf", now.epochSecond)
        put("name", "Synthetic Person"); put("email", "synthetic@example.test")
    }.toString(), *edits)
    private fun header(bits: Int = 2048) = """{"alg":"RS256","typ":"JWT","kid":"synthetic-""" + bits + "\"}"
    private fun signed(payload: String = claims(), protected: String = header(), bits: Int = 2048): String {
        val privateKey = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(
            Base64.getDecoder().decode(fixture("rsa" + bits + ".pk8.b64").toString(Charsets.US_ASCII).trim())))
        val input = b64(protected.toByteArray()) + "." + b64(payload.toByteArray())
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(privateKey); signer.update(input.toByteArray(Charsets.US_ASCII))
        return input + "." + b64(signer.sign())
    }
    private fun response(id: String = signed(), vararg edits: Pair<String, JsonElement?>): ByteArray = change(buildJsonObject {
        put("access_token", "opaque.synthetic.access." + sentinel)
        put("refresh_token", "synthetic-renewal-" + sentinel)
        put("id_token", id); put("token_type", "Bearer"); put("expires_in", 3600); put("scope", allScopes)
    }.toString(), *edits).toByteArray()
    private fun validate(
        response: ByteArray = response(), keys: ByteArray = jwks(), expectedClient: String = client,
        expectedNonce: String = nonce, expectedSubject: String? = null, received: Instant = now,
        skew: Long = 5, refetched: Boolean = false, operation: ChatGptStoreOperation = operation(),
    ) = ChatGptPlanOidc.validateAuthorizationResponse(response, keys, expectedClient, expectedNonce,
        received, operation, expectedSubject, skew, refetched)
    private fun failure(reason: ChatGptOidcFailure.Reason? = null, block: () -> Unit): ChatGptOidcFailure {
        val failure = assertFailsWith<ChatGptOidcFailure>(block = block)
        if (reason != null) assertEquals(reason, failure.reason)
        assertNull(failure.cause); assertTrue(failure.suppressed.isEmpty())
        assertFalse(failure.toString().contains(sentinel))
        return failure
    }
    private fun modifiedKey(vararg edits: Pair<String, JsonElement?>): ByteArray {
        val key = json(jwks().toString(Charsets.UTF_8))["keys"]!!.jsonArray.single().toString()
        return ("{\"keys\":[" + change(key, *edits) + "]}").toByteArray()
    }
    private fun discovery() = buildJsonObject {
        put("issuer", ChatGptPlanOidc.ISSUER); put("authorization_endpoint", ChatGptPlanOidc.AUTHORIZATION)
        put("token_endpoint", ChatGptPlanOidc.TOKEN); put("jwks_uri", ChatGptPlanOidc.JWKS)
    }.toString()

    @Test fun validPinnedDiscoveryHasNoReturnedEndpointAuthority() {
        assertEquals(Unit, ChatGptPlanOidc.validateDiscovery(discovery().toByteArray(), operation()))
    }
    @Test fun discoveryRejectsEndpointSpellingAuthorityAndShapeSubstitutions() {
        for (field in listOf("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri")) {
            val pin = json(discovery())[field]!!.jsonPrimitive.content
            for (value in listOf(pin + "/", pin + "?next=" + sentinel, pin + "#x", pin.replace("https:", "http:"),
                pin.replace("auth.openai.com", "auth.openai.com.evil.test"), pin.replace("auth.openai.com", "auth.openai.com:443"),
                pin.replace("auth.openai.com", "user@auth.openai.com"))) {
                failure(ChatGptOidcFailure.Reason.INVALID_DISCOVERY) {
                    ChatGptPlanOidc.validateDiscovery(change(discovery(), field to JsonPrimitive(value)).toByteArray(), operation())
                }
            }
            for (value in listOf(null, JsonNull, JsonArray(emptyList()), JsonPrimitive(42))) failure {
                ChatGptPlanOidc.validateDiscovery(change(discovery(), field to value).toByteArray(), operation())
            }
        }
    }
    @Test fun verifiedRegistrationBindsIdentityTokenScopeExpiryAndStoreNonceHash() {
        val r = validate(expectedSubject = subject)
        assertEquals(client, r.clientId); assertEquals(subject, r.subject); assertEquals(ChatGptPlanOidc.ISSUER, r.issuer)
        assertEquals("Synthetic Person", r.label); assertEquals("synthetic@example.test", r.email)
        assertEquals(now, r.tokenSet.receivedAt); assertEquals(now.plusSeconds(3600), r.tokenSet.expiresAt)
        assertEquals(allScopes.split(' ').toSet(), r.tokenSet.scopes)
        val hash = MessageDigest.getInstance("SHA-256").digest(nonce.toByteArray()).joinToString("") { "%02x".format(it.toInt() and 255) }
        assertEquals(hash, r.tokenSet.authorizationNonceHash)
        assertTrue(r.tokenSet.authorizationNonceHash!!.matches(Regex("[a-f0-9]{64}")))
        assertEquals("ChatGptPlanValidatedRegistration([redacted])", r.toString())
        assertEquals("ChatGptPlanTokenSet([redacted])", r.tokenSet.toString())
    }
    @Test fun rsa8192UpperBoundAndOmittedOptionalJwkMetadataVerify() {
        assertEquals(subject, validate(response(signed(protected = header(8192), bits = 8192)), jwks(8192)).subject)
        assertEquals(subject, validate(keys = modifiedKey("use" to null, "alg" to null, "key_ops" to null)).subject)
    }
    @Test fun directScopeDenialPreservesIdentityWithoutInventingGrants() {
        for (scope in listOf("openid profile email", "resource.invoke", "chatgpt.tokens.use.direct", "")) {
            val result = validate(response(edits = arrayOf("scope" to JsonPrimitive(scope), "refresh_token" to null)))
            assertEquals(subject, result.subject)
            assertEquals(if (scope.isEmpty()) emptySet() else scope.split(' ').toSet(), result.tokenSet.scopes)
            assertFalse(setOf("resource.invoke", "chatgpt.tokens.use.direct").all(result.tokenSet.scopes::contains))
            assertNull(result.tokenSet.refreshToken)
        }
    }
    @Test fun accessTokenContentsCannotSupplyIdentityOrScopes() {
        val opaque = "not-json.not-signed." + sentinel
        val result = validate(response(edits = arrayOf("access_token" to JsonPrimitive(opaque), "scope" to JsonPrimitive("openid"))))
        assertEquals(opaque, result.tokenSet.accessToken); assertEquals(setOf("openid"), result.tokenSet.scopes)
        assertEquals(subject, result.subject)
    }
    @Test fun signatureTamperAndWrongPublicKeyFailBeforeParsingClaims() {
        val validParts = signed().split('.')
        val validSig = Base64.getUrlDecoder().decode(validParts[2]); validSig[0] = (validSig[0].toInt() xor 1).toByte()
        failure(ChatGptOidcFailure.Reason.INVALID_SIGNATURE) {
            validate(response(validParts[0] + "." + validParts[1] + "." + b64(validSig)))
        }
        val originalModulus = Base64.getUrlDecoder().decode(
            json(jwks().toString(Charsets.UTF_8))["keys"]!!.jsonArray.single().jsonObject["n"]!!.jsonPrimitive.content)
        originalModulus[originalModulus.lastIndex] = (originalModulus.last().toInt() xor 2).toByte()
        failure(ChatGptOidcFailure.Reason.INVALID_SIGNATURE) {
            validate(keys = modifiedKey("n" to JsonPrimitive(b64(originalModulus))))
        }
        val original = signed(payload = "not even JSON " + sentinel)
        val parts = original.split('.')
        val sig = Base64.getUrlDecoder().decode(parts[2]); sig[0] = (sig[0].toInt() xor 1).toByte()
        failure(ChatGptOidcFailure.Reason.INVALID_SIGNATURE) { validate(response(parts[0] + "." + parts[1] + "." + b64(sig))) }
        failure(ChatGptOidcFailure.Reason.INVALID_JSON) { validate(response(original)) }
        val foreign = json(jwks(8192).toString(Charsets.UTF_8))["keys"]!!.jsonArray.single().jsonObject["n"]!!
        failure(ChatGptOidcFailure.Reason.INVALID_SIGNATURE) { validate(keys = modifiedKey("n" to foreign)) }
    }
    @Test fun noneHs256Rs384AndCaseConfusionRejectDespiteAuthenticSignature() {
        for (alg in listOf("none", "HS256", "RS384", "rs256", sentinel)) failure(ChatGptOidcFailure.Reason.INVALID_ID_TOKEN) {
            validate(response(signed(protected = change(header(), "alg" to JsonPrimitive(alg)))))
        }
    }
    @Test fun remoteEmbeddedKeysCriticalExtensionsAndWrongTypReject() {
        for (field in listOf("jku", "x5u", "jwk", "x5c", "crit", "b64")) failure(ChatGptOidcFailure.Reason.INVALID_ID_TOKEN) {
            validate(response(signed(protected = change(header(), field to JsonPrimitive("https://evil.test/" + sentinel)))))
        }
        failure { validate(response(signed(protected = change(header(), "typ" to JsonPrimitive("at+jwt"))))) }
        assertEquals(subject, validate(response(signed(protected = change(header(), "typ" to null)))).subject)
    }
    @Test fun missingMalformedAndDuplicateKeyIdsRejectWithoutReflection() {
        for (value in listOf(null, JsonNull, JsonPrimitive(42), JsonPrimitive(""), JsonPrimitive("x".repeat(257)))) failure {
            validate(response(signed(protected = change(header(), "kid" to value))))
        }
        val key = json(jwks().toString(Charsets.UTF_8))["keys"]!!.jsonArray.single()
        failure(ChatGptOidcFailure.Reason.INVALID_KEY_SET) { validate(keys = ("{\"keys\":[" + key + "," + key + "]}").toByteArray()) }
    }
    @Test fun unknownKidOffersOneFutureRefetchThenBecomesTerminal() {
        val bytes = response(signed(protected = change(header(), "kid" to JsonPrimitive(sentinel))))
        failure(ChatGptOidcFailure.Reason.UNKNOWN_KEY_REFETCH_ONCE) { validate(bytes) }
        failure(ChatGptOidcFailure.Reason.UNKNOWN_KEY) { validate(bytes, refetched = true) }
        assertEquals(subject, validate(refetched = true).subject)
    }
    @Test fun jwksAllows32UniqueKeysRejects33AndMalformedShapes() {
        val key = json(jwks().toString(Charsets.UTF_8))["keys"]!!.jsonArray.single().toString()
        fun keys(count: Int) = ("{\"keys\":[" + (0 until count).joinToString(",") {
            if (it == 0) key else change(key, "kid" to JsonPrimitive("unused-" + it))
        } + "]}").toByteArray()
        assertEquals(subject, validate(keys = keys(32)).subject)
        failure(ChatGptOidcFailure.Reason.INVALID_KEY_SET) { validate(keys = keys(33)) }
        for (bad in listOf("{}", "[]", "{\"keys\":null}", "{\"keys\":[null]}", "{\"keys\":[]}")) failure { validate(keys = bad.toByteArray()) }
    }
    @Test fun jwkAlgorithmUseOperationsTypeAndPrivateMaterialReject() {
        for ((key, value) in listOf("alg" to JsonPrimitive("HS256"), "alg" to JsonPrimitive("RS384"),
            "kty" to JsonPrimitive("oct"), "kty" to JsonPrimitive("EC"), "use" to JsonPrimitive("enc"),
            "key_ops" to JsonArray(listOf(JsonPrimitive("sign"))), "key_ops" to JsonArray(emptyList()),
            "key_ops" to JsonArray(listOf(JsonPrimitive("verify"), JsonPrimitive("verify"))),
            "key_ops" to JsonArray(listOf(JsonPrimitive("verify"), JsonPrimitive("encrypt"))),
            "x5u" to JsonPrimitive(sentinel), "jku" to JsonPrimitive(sentinel), "d" to JsonPrimitive(sentinel))) {
            failure(ChatGptOidcFailure.Reason.INVALID_KEY_SET) { validate(keys = modifiedKey(key to value)) }
        }
    }
    @Test fun rsaModulusAndExponentAreCanonicalBoundedUnsignedIntegers() {
        for (size in listOf(255, 1025)) failure { validate(keys = modifiedKey("n" to JsonPrimitive(b64(ByteArray(size) { 0xff.toByte() })))) }
        val n = Base64.getUrlDecoder().decode(json(jwks().toString(Charsets.UTF_8))["keys"]!!.jsonArray.single().jsonObject["n"]!!.jsonPrimitive.content)
        for (bad in listOf(byteArrayOf(0) + n, n.clone().also { it[0] = 0x7f }, n.clone().also { it[it.lastIndex] = 2 })) {
            failure { validate(keys = modifiedKey("n" to JsonPrimitive(b64(bad)))) }
        }
        for (bad in listOf(byteArrayOf(0, 1, 0, 1), byteArrayOf(1), byteArrayOf(2), ByteArray(5) { 1 })) {
            failure { validate(keys = modifiedKey("e" to JsonPrimitive(b64(bad)))) }
        }
    }
    @Test fun issuerSubjectAndExactReauthorizationClientBindingAreEnforced() {
        for ((key, value) in listOf("iss" to JsonPrimitive(ChatGptPlanOidc.ISSUER + "/"), "sub" to JsonPrimitive(""),
            "sub" to JsonPrimitive("x".repeat(2049)), "sub" to JsonPrimitive("bad\nsubject"), "client_id" to JsonPrimitive("oaiapp_other"))) {
            failure { validate(response(signed(claims(key to value)))) }
        }
        failure(ChatGptOidcFailure.Reason.INVALID_CLAIMS) { validate(expectedSubject = "another-account") }
        failure(ChatGptOidcFailure.Reason.INVALID_CLAIMS) { validate(expectedClient = "oaiapp_other") }
        for (bad in listOf("dynamic_agent_client", "", "oaiapp_", "oaiapp_" + "a".repeat(250))) failure { validate(expectedClient = bad) }
    }
    @Test fun audienceArraysRequireUniqueBoundedStringsAndAzpForMultipleAudiences() {
        for (aud in listOf(JsonPrimitive(client), JsonArray(listOf(JsonPrimitive(client)))))
            assertEquals(subject, validate(response(signed(claims("aud" to aud)))).subject)
        val multi = JsonArray(listOf(JsonPrimitive(client), JsonPrimitive("oaiapp_other")))
        assertEquals(subject, validate(response(signed(claims("aud" to multi, "azp" to JsonPrimitive(client))))).subject)
        for (edits in listOf(arrayOf("aud" to multi), arrayOf("aud" to multi, "azp" to JsonPrimitive("oaiapp_other")),
            arrayOf("azp" to JsonPrimitive("oaiapp_other")), arrayOf("aud" to JsonArray(listOf(JsonPrimitive(client), JsonPrimitive(client)))),
            arrayOf("aud" to JsonArray(emptyList())), arrayOf("aud" to JsonArray(listOf(JsonPrimitive(12)))),
            arrayOf("aud" to JsonArray((0..32).map { JsonPrimitive(if (it == 0) client else "other-" + it) })))) {
            failure { validate(response(signed(claims(*edits)))) }
        }
    }
    @Test fun expiryIatNbfAndExplicitSkewBoundariesRejectStaleOrFutureIdentity() {
        assertEquals(subject, validate(response(signed(claims("exp" to JsonPrimitive(now.epochSecond - 4),
            "iat" to JsonPrimitive(now.epochSecond - 100), "nbf" to null)))).subject)
        failure { validate(response(signed(claims("exp" to JsonPrimitive(now.epochSecond - 5),
            "iat" to JsonPrimitive(now.epochSecond - 100), "nbf" to null)))) }
        for (field in listOf("iat", "nbf")) {
            assertEquals(subject, validate(response(signed(claims(field to JsonPrimitive(now.epochSecond + 5))))).subject)
            failure { validate(response(signed(claims(field to JsonPrimitive(now.epochSecond + 6))))) }
            assertEquals(subject, validate(response(signed(claims(field to JsonPrimitive(now.epochSecond + 60)))), skew = 60).subject)
            failure { validate(response(signed(claims(field to JsonPrimitive(now.epochSecond + 61)))), skew = 60) }
        }
        failure { validate(response(signed(claims("exp" to JsonPrimitive(now.epochSecond)))), skew = 0) }
        for (skew in listOf(-1L, 61L, Long.MAX_VALUE)) failure { validate(skew = skew) }
    }
    @Test fun numericDateRequiresFiniteNonnegativeIntegerAndCoherentValidityInterval() {
        for (field in listOf("iat", "exp", "nbf")) for (bad in listOf(JsonNull, JsonPrimitive("1"),
            JsonPrimitive(1.5), JsonPrimitive(-1), JsonPrimitive(Long.MAX_VALUE))) {
            failure { validate(response(signed(claims(field to bad)))) }
        }
        for (field in listOf("iat", "exp")) failure { validate(response(signed(claims(field to null)))) }
        for (field in listOf("iat", "nbf")) failure { validate(response(signed(claims(field to JsonPrimitive(now.epochSecond + 3600))))) }
        assertEquals(subject, validate(response(signed(claims("nbf" to null)))).subject)
    }
    @Test fun authorizationRequiresFreshNonceNotAbsentRefreshNonceOrStoredHash() {
        for (value in listOf(null, JsonNull, JsonPrimitive("wrong"), JsonPrimitive(""), JsonPrimitive("x".repeat(1025)),
            JsonPrimitive(validate().tokenSet.authorizationNonceHash))) failure { validate(response(signed(claims("nonce" to value)))) }
        failure { validate(expectedNonce = "") }; failure { validate(expectedNonce = "x".repeat(1025)) }
        failure { validate(expectedNonce = "\uD800") }
    }
    @Test fun optionalAccessTokenHashChecksExactOpaqueBytes() {
        val access = "opaque.synthetic.access." + sentinel
        val hash = b64(MessageDigest.getInstance("SHA-256").digest(access.toByteArray()).copyOf(16))
        assertEquals(subject, validate(response(signed(claims("at_hash" to JsonPrimitive(hash))))).subject)
        failure { validate(response(signed(claims("at_hash" to JsonPrimitive(hash))), "access_token" to JsonPrimitive("changed"))) }
        failure { validate(response(signed(claims("at_hash" to JsonPrimitive("invalid"))))) }
    }
    @Test fun tokenTypeExpiryScopesAndRefreshRejectCoercionAndMalformedShapes() {
        for (type in listOf("bearer", "BEARER", "Bearer"))
            assertEquals("Bearer", validate(response(edits = arrayOf("token_type" to JsonPrimitive(type)))).tokenSet.tokenType)
        for (field in listOf("access_token", "id_token", "token_type", "expires_in", "scope"))
            for (bad in listOf(null, JsonNull, JsonArray(emptyList()))) failure { validate(response(edits = arrayOf(field to bad))) }
        for (bad in listOf(JsonPrimitive("Basic"), JsonPrimitive("Bearer "))) failure {
            validate(response(edits = arrayOf("token_type" to bad)))
        }
        for (bad in listOf(JsonPrimitive(0), JsonPrimitive(-1), JsonPrimitive(Long.MAX_VALUE),
            JsonPrimitive(366L * 86400 + 1), JsonPrimitive("3600"), JsonPrimitive(3600.0))) {
            failure { validate(response(edits = arrayOf("expires_in" to bad))) }
        }
        assertEquals(now.plusSeconds(366L * 86400), validate(response(edits = arrayOf("expires_in" to JsonPrimitive(366L * 86400)))).tokenSet.expiresAt)
        failure { validate(received = Instant.MAX) }
        for (bad in listOf("openid openid", "openid  email", " openid", "openid ", "openid\temail", "bad\\scope",
            "bad\"scope", "x".repeat(257), (0..64).joinToString(" ") { "s" + it })) {
            failure { validate(response(edits = arrayOf("scope" to JsonPrimitive(bad)))) }
        }
        for (bad in listOf(JsonNull, JsonPrimitive(""), JsonPrimitive("\n"))) failure {
            validate(response(edits = arrayOf("refresh_token" to bad)))
        }
        failure { validate(response(edits = arrayOf("error" to JsonPrimitive(sentinel)))) }
    }
    @Test fun opaqueTokenUtf8LimitsAreIndependentOfCharacterCount() {
        for (field in listOf("access_token", "refresh_token")) {
            for (valid in listOf("x".repeat(16384), "é".repeat(8192))) assertEquals(valid,
                validate(response(edits = arrayOf(field to JsonPrimitive(valid)))).tokenSet.let {
                    if (field == "access_token") it.accessToken else it.refreshToken
                })
            for (invalid in listOf("x".repeat(16385), "é".repeat(8193), "\u0000" + sentinel, "\t", "")) failure {
                validate(response(edits = arrayOf(field to JsonPrimitive(invalid))))
            }
        }
    }
    @Test fun idTokenCompactEncodingSignatureLengthAnd16KiBBoundsReject() {
        val original = signed()
        for (bad in listOf("", original + ".extra", original.replaceFirst('.', '='), "a.b.c", "a.b.", "x".repeat(16385))) failure {
            validate(response(bad))
        }
        val parts = original.split('.')
        for (signature in listOf("AA", parts[2] + "=", "+" + parts[2].drop(1))) failure {
            validate(response(parts[0] + "." + parts[1] + "." + signature))
        }
        failure { validate(response(signed(claims("padding" to JsonPrimitive("x".repeat(16000)))))) }
    }
    @Test fun signedIdTokenAt16KiBBoundaryPassesAndNextPayloadByteRejects() {
        // One legal JSON whitespace byte makes an exact 16384-byte compact JWS representable.
        val protected = " " + header()
        val overhead = b64(protected.toByteArray()).length + 2 + b64(ByteArray(256)).length
        val size = (11000..12500).last {
            overhead + b64(claims("padding" to JsonPrimitive("x".repeat(it))).toByteArray()).length <= 16384
        }
        val bounded = signed(claims("padding" to JsonPrimitive("x".repeat(size))), protected)
        assertEquals(16384, bounded.length)
        assertEquals(subject, validate(response(bounded)).subject)
        val tooLarge = signed(claims("padding" to JsonPrimitive("x".repeat(size + 1))), protected)
        assertTrue(tooLarge.length > 16384)
        failure(ChatGptOidcFailure.Reason.INVALID_TOKEN_RESPONSE) { validate(response(tooLarge)) }
    }
    @Test fun duplicateResponseHeaderClaimsAndNestedIgnoredMembersReject() {
        val valid = response().toString(Charsets.UTF_8)
        failure { validate((valid.dropLast(1) + ",\"scope\":\"openid\"}").toByteArray()) }
        failure { validate(response(signed(protected = header().dropLast(1) + ",\"alg\":\"RS256\"}"))) }
        failure { validate(response(signed(claims().dropLast(1) + ",\"sub\":\"other\"}"))) }
        failure { validate(response(signed(claims().dropLast(1) + ",\"ignored\":{\"x\":1,\"x\":2}}"))) }
        failure { validate(keys = jwks().toString(Charsets.UTF_8).replace("\"kty\":\"RSA\"",
            "\"kty\":\"RSA\",\"kty\":\"RSA\"").toByteArray()) }
    }
    @Test fun displayMetadataRemainsBoundedAndRejectsControls() {
        assertEquals("ChatGPT account", validate(response(signed(claims("name" to null, "email" to null)))).label)
        for ((key, value) in listOf("name" to "x".repeat(257), "email" to "x".repeat(321), "name" to "bad\nname", "email" to "bad\u202ename")) {
            failure { validate(response(signed(claims(key to JsonPrimitive(value))))) }
        }
    }
    @Test fun originalOperationCancellationTimeoutAndInterruptRemainSanitized() {
        val body = response()
        assertFailsWith<CancellationException> { validate(body, operation = ChatGptStoreOperation.start(cancelled = { true })) }
        var clock = 0L
        val op = ChatGptStoreOperation.create(Duration.ofNanos(2), { false }, { clock })
        clock = 2
        assertFailsWith<TimeoutException> { validate(body, operation = op) }
        Thread.currentThread().interrupt()
        try { assertFailsWith<CancellationException> { validate(body) }; assertTrue(Thread.currentThread().isInterrupted) }
        finally { Thread.interrupted() }
        val poisoned = ChatGptStoreOperation.start(cancelled = { throw IllegalArgumentException(sentinel) })
        val e = failure { validate(body, operation = poisoned) }
        assertFalse(e.stackTraceToString().contains(sentinel))
    }
    @Test fun everyReachedCancellationCheckpointRejectsInsteadOfPublishingRegistration() {
        val body = response(); val keys = jwks()
        var checks = 0
        assertEquals(subject, validate(body, keys, operation = ChatGptStoreOperation.start(cancelled = { checks++; false })).subject)
        assertTrue(checks > 30)
        for (cutoff in 1..checks) {
            var calls = 0
            assertFailsWith<CancellationException> {
                validate(body, keys, operation = ChatGptStoreOperation.start(cancelled = { ++calls >= cutoff }))
            }
        }
    }
    @Test fun secretSentinelsNeverAppearInDiagnosticObjectsOrFailures() {
        val r = validate()
        for (text in listOf(r.toString(), r.tokenSet.toString(), ChatGptPlanOidc.toString(), ChatGptAuthJson.parse(response(), operation()).toString())) {
            assertFalse(text.contains(sentinel)); assertFalse(text.contains(nonce)); assertFalse(text.contains(r.tokenSet.idToken))
        }
        for (bad in listOf(sentinel, "{\"" + sentinel + "\":}", "{\"error\":\"" + sentinel + "\"}")) {
            val e = failure { validate(bad.toByteArray()) }
            assertFalse(e.stackTraceToString().contains(sentinel)); assertTrue(e.stackTrace.isEmpty())
        }
    }
}
