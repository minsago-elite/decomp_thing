package decompengine.chatgpt

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.awt.Desktop
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.security.KeyFactory

/** Implements the documented public-client SIWC authorization-code + PKCE flow. */
class ChatGptPlanOAuth(
    private val store: ChatGptPlanCredentialStore = ChatGptPlanCredentialStore.default(),
    private val httpClient: HttpClient = defaultHttpClient(),
) {
    fun signIn(existingProfileId: String? = null): ChatGptPlanAccount {
        val existing = existingProfileId?.let { store.account(it) }
        if (existingProfileId != null && existing == null) {
            throw ChatGptPlanAuthenticationException("The selected ChatGPT account is no longer saved.")
        }
        val hostId = store.hostId()
        val discovery = loadDiscovery()
        val verifier = randomUrlToken(48)
        val state = randomUrlToken(32)
        val nonce = randomUrlToken(32)
        val challenge = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(StandardCharsets.US_ASCII)))
        val callback = startCallbackServer(state)
        try {
            val clientId = existing?.clientId ?: DYNAMIC_REGISTRATION_CLIENT_ID
            val query = linkedMapOf(
                "client_id" to clientId,
                "ext_agent_host_id" to hostId,
                "response_type" to "code",
                "redirect_uri" to callback.redirectUri,
                "scope" to REQUESTED_SCOPES.joinToString(" "),
                "resource" to RESOURCE,
                "state" to state,
                "nonce" to nonce,
                "code_challenge_method" to "S256",
                "code_challenge" to challenge,
            )
            if (existing == null) query["agent_name_hint"] = APP_NAME
            val authorizationUrl = URI.create(
                "$AUTHORIZATION_ENDPOINT?" + query.entries.joinToString("&") { (name, value) ->
                    "${encode(name)}=${encode(value)}"
                },
            )
            openBrowserOrPrint(authorizationUrl)
            val returned = callback.result.get(CALLBACK_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
            returned.error?.let { error ->
                if (error == "access_denied") {
                    throw ChatGptPlanAuthenticationException("ChatGPT sign-in was declined. No inference will be sent.")
                }
                throw ChatGptPlanAuthenticationException("ChatGPT sign-in did not complete (OAuth error).")
            }
            val issuedClientId = returned.clientId ?: existing?.clientId
                ?: throw ChatGptPlanAuthenticationException("ChatGPT did not return an issued client id; registration is incomplete.")
            require(issuedClientId != DYNAMIC_REGISTRATION_CLIENT_ID && issuedClientId.matches(CLIENT_ID_PATTERN)) {
                "ChatGPT returned an invalid issued client id"
            }
            if (existing != null && returned.clientId != null && returned.clientId != existing.clientId) {
                throw ChatGptPlanAuthenticationException("ChatGPT returned a different client id for this account.")
            }
            val tokens = exchangeAuthorizationCode(
                clientId = issuedClientId,
                code = returned.code ?: throw ChatGptPlanAuthenticationException("ChatGPT returned no authorization code."),
                verifier = verifier,
                redirectUri = callback.redirectUri,
            )
            val identity = verifyIdToken(tokens.idToken, issuedClientId, nonce, discovery)
            if (existing != null && existing.subject != identity.subject) {
                throw ChatGptPlanAuthenticationException("The returning sign-in belongs to a different ChatGPT account.")
            }
            val account = NewChatGptPlanAccount(
                email = identity.email,
                clientId = issuedClientId,
                subject = identity.subject,
                idToken = tokens.idToken,
                accessToken = tokens.accessToken,
                refreshToken = tokens.refreshToken,
                expiresAt = tokens.expiresAt,
                scopes = tokens.scopes,
            )
            return if (existing == null) store.saveNewAccount(account) else store.replaceAccount(existing.id, account)
        } catch (failure: ChatGptPlanAuthenticationException) {
            throw failure
        } catch (failure: Exception) {
            throw ChatGptPlanAuthenticationException("ChatGPT sign-in failed. No credential values were retained in diagnostics.", failure)
        } finally {
            callback.close()
        }
    }

    fun signOut(profileId: String? = null): Boolean {
        var revocationConfirmed = false
        runCatching {
            val account = profileId?.let(store::account) ?: store.activeAccount()
                ?: throw ChatGptPlanAuthenticationException("No active ChatGPT account is selected.")
            if (account.refreshToken.isNotBlank()) {
                val discovery = loadDiscovery()
                val endpoint = discovery.revocationEndpoint
                val body = formBody(
                    "token" to account.refreshToken,
                    "token_type_hint" to "refresh_token",
                    "client_id" to account.clientId,
                )
                val result = sendForm(endpoint, body)
                revocationConfirmed = result.statusCode() == 200
            }
        }
        // Local sign-out always clears tokens, even if OpenAI cannot confirm revocation.
        store.clearTokens(profileId)
        return revocationConfirmed
    }

    fun refreshTokens(clientId: String, refreshToken: String): RefreshedChatGptPlanTokens {
        val response = sendForm(
            URI.create(TOKEN_ENDPOINT),
            formBody(
                "grant_type" to "refresh_token",
                "client_id" to clientId,
                "refresh_token" to refreshToken,
                "resource" to RESOURCE,
            ),
        )
        if (response.statusCode() !in 200..299) {
            throw ChatGptPlanAuthenticationException(
                if (response.statusCode() == 400 || response.statusCode() == 401) {
                    "ChatGPT sign-in expired or was revoked. Run llm_bin_patch chatgpt login."
                } else "ChatGPT token refresh failed (HTTP ${response.statusCode()}).",
            )
        }
        val root = parseJsonResponse(response).jsonObject
        val access = requiredToken(root, "access_token")
        val refreshed = requiredToken(root, "refresh_token")
        val expiresAt = expiry(root)
        val scopes = root.optionalSpaceSeparated("scope")
        val idToken = root.optionalString("id_token")
        return RefreshedChatGptPlanTokens(access, refreshed, expiresAt, scopes, idToken)
    }

    private fun exchangeAuthorizationCode(
        clientId: String,
        code: String,
        verifier: String,
        redirectUri: String,
    ): ExchangedTokens {
        val response = sendForm(
            URI.create(TOKEN_ENDPOINT),
            formBody(
                "grant_type" to "authorization_code",
                "client_id" to clientId,
                "code" to code,
                "code_verifier" to verifier,
                "redirect_uri" to redirectUri,
                "resource" to RESOURCE,
            ),
        )
        if (response.statusCode() !in 200..299) {
            val message = if (response.statusCode() == 400) {
                "ChatGPT rejected the authorization code. Start a fresh sign-in."
            } else "ChatGPT token exchange failed (HTTP ${response.statusCode()})."
            throw ChatGptPlanAuthenticationException(message)
        }
        val root = parseJsonResponse(response).jsonObject
        val tokenType = root.optionalString("token_type")
        require(tokenType.equals("Bearer", ignoreCase = true)) { "ChatGPT returned an unsupported token type" }
        val scopes = root.optionalSpaceSeparated("scope")
            ?: throw ChatGptPlanAuthenticationException("ChatGPT returned no granted scope inventory.")
        return ExchangedTokens(
            idToken = requiredToken(root, "id_token"),
            accessToken = requiredToken(root, "access_token"),
            refreshToken = requiredToken(root, "refresh_token"),
            expiresAt = expiry(root),
            scopes = scopes,
        )
    }

    private fun loadDiscovery(): OpenIdDiscovery {
        val response = sendGet(URI.create(DISCOVERY_ENDPOINT))
        require(response.statusCode() == 200) { "OpenAI authentication discovery was unavailable" }
        val root = parseJsonResponse(response).jsonObject
        val issuer = root.requiredString("issuer")
        require(issuer == AUTH_ISSUER) { "OpenAI authentication discovery returned an unexpected issuer" }
        val jwks = requireOpenAiAuthEndpoint(root.requiredString("jwks_uri"))
        val revocation = requireOpenAiAuthEndpoint(root.requiredString("revocation_endpoint"))
        return OpenIdDiscovery(issuer, jwks, revocation)
    }

    private fun verifyIdToken(
        compact: String,
        clientId: String,
        expectedNonce: String,
        discovery: OpenIdDiscovery,
    ): ValidatedIdentity {
        val segments = compact.split('.')
        require(segments.size == 3 && segments.all(String::isNotEmpty)) { "ChatGPT returned a malformed ID token" }
        val decoder = Base64.getUrlDecoder()
        val header = Json.parseToJsonElement(String(decoder.decode(segments[0]), StandardCharsets.UTF_8)).jsonObject
        val claims = Json.parseToJsonElement(String(decoder.decode(segments[1]), StandardCharsets.UTF_8)).jsonObject
        val algorithm = header.requiredString("alg")
        require(algorithm == "RS256") { "ChatGPT ID token uses an unsupported signing algorithm" }
        val keyId = header.requiredString("kid")
        val jwksResponse = sendGet(discovery.jwksUri)
        require(jwksResponse.statusCode() == 200) { "OpenAI signing keys could not be loaded" }
        val keys = parseJsonResponse(jwksResponse).jsonObject.getValue("keys").jsonArray
        val key = keys.firstOrNull { candidate -> candidate.jsonObject.optionalString("kid") == keyId }
            ?: throw ChatGptPlanAuthenticationException("OpenAI signing key was not found for the ID token.")
        val jwk = key.jsonObject
        require(jwk.requiredString("kty") == "RSA") { "OpenAI signing key has an unsupported type" }
        require(jwk.optionalString("use").let { it == null || it == "sig" }) { "OpenAI signing key is not a signature key" }
        require(jwk.optionalString("alg").let { it == null || it == algorithm }) { "OpenAI signing key algorithm does not match" }
        val n = java.math.BigInteger(1, decoder.decode(jwk.requiredString("n")))
        val e = java.math.BigInteger(1, decoder.decode(jwk.requiredString("e")))
        val publicKey = KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(n, e)) as RSAPublicKey
        val verifier = Signature.getInstance("SHA256withRSA")
        verifier.initVerify(publicKey)
        verifier.update("${segments[0]}.${segments[1]}".toByteArray(StandardCharsets.US_ASCII))
        require(verifier.verify(decoder.decode(segments[2]))) { "ChatGPT ID token signature is invalid" }

        require(claims.requiredString("iss") == discovery.issuer) { "ChatGPT ID token issuer is invalid" }
        val audience = claims.getValue("aud").let { value ->
            if (value is JsonArray) value.map { it.jsonPrimitive.content } else listOf(value.jsonPrimitive.content)
        }
        require(clientId in audience) { "ChatGPT ID token audience is invalid" }
        if (audience.size > 1) require(claims.optionalString("azp") == clientId) { "ChatGPT ID token authorized party is invalid" }
        val now = Instant.now().epochSecond
        val expires = claims.getValue("exp").jsonPrimitive.content.toLong()
        require(expires > now) { "ChatGPT ID token has expired" }
        claims.optionalString("nbf")?.toLong()?.let { require(it <= now + 60) { "ChatGPT ID token is not active" } }
        claims.optionalString("iat")?.toLong()?.let { require(it <= now + 60) { "ChatGPT ID token issue time is invalid" } }
        require(claims.requiredString("nonce") == expectedNonce) { "ChatGPT ID token nonce does not match this sign-in" }
        val subject = claims.requiredString("sub")
        require(subject.isNotBlank() && subject.length <= 2048) { "ChatGPT ID token subject is invalid" }
        val email = claims.optionalString("email")?.takeIf { it.length <= 320 }
        return ValidatedIdentity(subject, email)
    }

    private fun startCallbackServer(expectedState: String): CallbackListener {
        val server = try { HttpServer.create(InetSocketAddress("127.0.0.1", 0), 1) }
        catch (failure: Exception) { throw ChatGptPlanAuthenticationException("Could not start the local ChatGPT sign-in callback.", failure) }
        val result = CompletableFuture<CallbackResult>()
        server.createContext(CALLBACK_PATH) { exchange ->
            try {
                if (exchange.requestMethod != "GET" || exchange.requestURI.path != CALLBACK_PATH) {
                    respond(exchange, 404, CALLBACK_ERROR_PAGE)
                    result.completeExceptionally(ChatGptPlanAuthenticationException("ChatGPT callback path was invalid."))
                    return@createContext
                }
                val query = parseQuery(exchange.requestURI.rawQuery ?: "")
                val returnedState = query["state"] ?: throw ChatGptPlanAuthenticationException("ChatGPT callback omitted state.")
                if (!MessageDigest.isEqual(expectedState.toByteArray(StandardCharsets.US_ASCII), returnedState.toByteArray(StandardCharsets.US_ASCII))) {
                    throw ChatGptPlanAuthenticationException("ChatGPT callback state did not match this sign-in.")
                }
                val error = query["error"]
                val code = query["code"]
                require(error != null || !code.isNullOrBlank()) { "ChatGPT callback has no authorization result" }
                val returnedClientId = query["client_id"]
                respond(exchange, 200, CALLBACK_SUCCESS_PAGE)
                result.complete(CallbackResult(code, returnedClientId, error))
            } catch (failure: Exception) {
                respond(exchange, 400, CALLBACK_ERROR_PAGE)
                result.completeExceptionally(
                    if (failure is ChatGptPlanAuthenticationException) failure
                    else ChatGptPlanAuthenticationException("ChatGPT callback was invalid.", failure),
                )
            } finally {
                exchange.close()
            }
        }
        server.start()
        val port = server.address.port
        val redirectUri = "http://127.0.0.1:$port$CALLBACK_PATH"
        return CallbackListener(server, redirectUri, result)
    }

    private fun sendGet(uri: URI): AuthHttpResponse {
        val request = HttpRequest.newBuilder(uri).timeout(HTTP_TIMEOUT).GET().build()
        return send(request)
    }

    private fun sendForm(uri: URI, body: String): AuthHttpResponse {
        val request = HttpRequest.newBuilder(uri)
            .timeout(HTTP_TIMEOUT)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
            .build()
        return send(request)
    }

    private fun send(request: HttpRequest): AuthHttpResponse {
        val response = try { httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream()) }
        catch (failure: Exception) { throw ChatGptPlanAuthenticationException("OpenAI authentication request failed.", failure) }
        val body = response.body().use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(4096)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (output.size() + count > MAXIMUM_AUTH_RESPONSE_BYTES) {
                    throw ChatGptPlanAuthenticationException("OpenAI authentication response exceeded its size limit.")
                }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        return AuthHttpResponse(response.statusCode(), body)
    }

    private fun parseJsonResponse(response: AuthHttpResponse): JsonElement = try {
        Json.parseToJsonElement(String(response.body(), StandardCharsets.UTF_8))
    } catch (failure: Exception) {
        throw ChatGptPlanAuthenticationException("OpenAI authentication response was not valid JSON.", failure)
    }

    private fun requiredToken(root: JsonObject, name: String): String {
        val token = root.optionalString(name) ?: throw ChatGptPlanAuthenticationException("OpenAI token response omitted a required field.")
        require(token.length in 1..MAXIMUM_TOKEN_BYTES && token.none(Char::isWhitespace)) {
            "OpenAI token response contained an invalid token value"
        }
        return token
    }

    private fun expiry(root: JsonObject): Instant {
        val seconds = root.getValue("expires_in").jsonPrimitive.content.toLong()
        require(seconds in 1..86_400) { "OpenAI token expiry is outside the accepted range" }
        return Instant.now().plusSeconds(seconds)
    }

    private fun formBody(vararg values: Pair<String, String>): String = values.joinToString("&") { (key, value) ->
        "${encode(key)}=${encode(value)}"
    }

    private fun parseQuery(raw: String): Map<String, String> {
        require(raw.toByteArray(StandardCharsets.UTF_8).size <= MAXIMUM_CALLBACK_QUERY_BYTES) { "ChatGPT callback query is too large" }
        val values = linkedMapOf<String, String>()
        if (raw.isEmpty()) return values
        raw.split('&').forEach { segment ->
            val separator = segment.indexOf('=')
            val key = URLDecoder.decode(if (separator < 0) segment else segment.substring(0, separator), StandardCharsets.UTF_8)
            val value = URLDecoder.decode(if (separator < 0) "" else segment.substring(separator + 1), StandardCharsets.UTF_8)
            require(key.isNotBlank() && values.putIfAbsent(key, value) == null) { "ChatGPT callback has a duplicate parameter" }
        }
        return values
    }

    private fun openBrowserOrPrint(uri: URI) {
        val opened = runCatching {
            if (!Desktop.isDesktopSupported() || !Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) return@runCatching false
            Desktop.getDesktop().browse(uri)
            true
        }.getOrDefault(false)
        if (!opened) println("Open this ChatGPT sign-in URL in your browser:\n$uri")
        else println("Waiting for ChatGPT sign-in in your browser…")
    }

    private fun respond(exchange: HttpExchange, status: Int, content: String) {
        val bytes = content.toByteArray(StandardCharsets.UTF_8)
        exchange.responseHeaders.set("Content-Type", "text/html; charset=utf-8")
        exchange.responseHeaders.set("Cache-Control", "no-store")
        exchange.responseHeaders.set("Pragma", "no-cache")
        exchange.responseHeaders.set("Referrer-Policy", "no-referrer")
        exchange.responseHeaders.set("X-Content-Type-Options", "nosniff")
        exchange.sendResponseHeaders(status, bytes.size.toLong())
        exchange.responseBody.use { it.write(bytes) }
    }

    private fun requireOpenAiAuthEndpoint(value: String): URI {
        val uri = URI(value)
        require(uri.scheme == "https" && uri.host == AUTH_HOST && uri.userInfo == null && uri.query == null && uri.fragment == null) {
            "OpenAI authentication metadata included an unexpected endpoint"
        }
        return uri
    }

    private fun encode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8)

    private fun randomUrlToken(bytes: Int): String = ByteArray(bytes).also(RANDOM::nextBytes)
        .let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }

    private data class OpenIdDiscovery(val issuer: String, val jwksUri: URI, val revocationEndpoint: URI)
    private data class CallbackResult(val code: String?, val clientId: String?, val error: String?)
    private data class CallbackListener(val server: HttpServer, val redirectUri: String, val result: CompletableFuture<CallbackResult>) {
        fun close() = server.stop(0)
    }
    private data class ExchangedTokens(
        val idToken: String,
        val accessToken: String,
        val refreshToken: String,
        val expiresAt: Instant,
        val scopes: Set<String>,
    )
    private data class ValidatedIdentity(val subject: String, val email: String?)

    private data class AuthHttpResponse(private val status: Int, private val content: ByteArray) {
        fun statusCode(): Int = status
        fun body(): ByteArray = content
    }

    private fun JsonObject.requiredString(name: String): String =
        optionalString(name) ?: throw ChatGptPlanAuthenticationException("OpenAI authentication response omitted a required field.")

    private fun JsonObject.optionalString(name: String): String? = when (val value = get(name)) {
        null, JsonNull -> null
        else -> value.jsonPrimitive.content
    }

    private fun JsonObject.optionalSpaceSeparated(name: String): Set<String>? =
        optionalString(name)?.split(Regex("\\s+")).orEmpty().filter(String::isNotBlank).toSet().takeIf(Set<String>::isNotEmpty)

    companion object {
        const val RESOURCE = "https://api.openai.com/v1"
        const val AUTH_ISSUER = "https://auth.openai.com"
        const val AUTHORIZATION_ENDPOINT = "https://auth.openai.com/api/accounts/authorize"
        const val TOKEN_ENDPOINT = "https://auth.openai.com/api/accounts/oauth/token"
        private const val AUTH_HOST = "auth.openai.com"
        private const val DISCOVERY_ENDPOINT = "https://auth.openai.com/.well-known/openid-configuration"
        private const val CALLBACK_PATH = "/auth/callback"
        private const val APP_NAME = "llm_bin_patch"
        private const val DYNAMIC_REGISTRATION_CLIENT_ID = "dynamic_agent_client"
        private const val MAXIMUM_AUTH_RESPONSE_BYTES = 128 * 1024
        private const val MAXIMUM_CALLBACK_QUERY_BYTES = 16 * 1024
        private const val MAXIMUM_TOKEN_BYTES = 16 * 1024
        private val CALLBACK_TIMEOUT = Duration.ofMinutes(5)
        private val HTTP_TIMEOUT = Duration.ofSeconds(20)
        private val REQUESTED_SCOPES = listOf("openid", "profile", "email", "offline_access", "resource.invoke", "chatgpt.tokens.use.direct")
        private val CLIENT_ID_PATTERN = Regex("[A-Za-z0-9_.-]{1,256}")
        private val RANDOM = SecureRandom()
        private val CALLBACK_SUCCESS_PAGE = "<!doctype html><meta charset=utf-8><title>Sign-in complete</title><p>Sign-in complete. You can close this tab and return to llm_bin_patch.</p>"
        private val CALLBACK_ERROR_PAGE = "<!doctype html><meta charset=utf-8><title>Sign-in failed</title><p>Sign-in could not be completed. Return to llm_bin_patch.</p>"

        private fun defaultHttpClient(): HttpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build()
    }
}
