package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonException
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.ByteArrayOutputStream
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Local origins are configured by the operator, never discovered from Host or forwarding headers. */
class LocalWebAccessConfiguration(
    val canonicalOrigin: String,
    val basePath: String = "/",
    additionalLoopbackOrigins: Set<String> = emptySet(),
) {
    internal val originsByAuthority: Map<String, String>
    internal val secure: Boolean
    val cookieName: String

    init {
        require(basePath.length <= 256 && basePath.matches(Regex("/([A-Za-z0-9_-]+/)*"))) {
            "local web base path must be a normalized URL prefix of at most 256 characters"
        }
        require(additionalLoopbackOrigins.size <= 8) { "too many configured local browser origins" }
        val origins = (listOf(canonicalOrigin) + additionalLoopbackOrigins).distinct()
        val parsed = origins.map { origin ->
            require(origin.length <= 256) { "configured local browser origin is too long" }
            val uri = try { URI(origin) } catch (_: Exception) { throw IllegalArgumentException("invalid configured local browser origin") }
            require(uri.scheme in setOf("http", "https") && uri.rawUserInfo == null &&
                uri.rawPath.isNullOrEmpty() && uri.rawQuery == null && uri.rawFragment == null &&
                uri.host != null && uri.port in -1..65535 && uri.port != 0) { "local browser origin must contain only an HTTP(S) loopback authority" }
            val host = uri.host.lowercase()
            val ipv4 = host.split('.')
            val loopbackV4 = ipv4.size == 4 && ipv4.first() == "127" && ipv4.all { part ->
                part.matches(Regex("0|[1-9][0-9]{0,2}")) && part.toInt() <= 255
            }
            require(host in setOf("localhost", "[::1]", "[0:0:0:0:0:0:0:1]") || loopbackV4) {
                "remote browser access requires the separately qualified authenticated proxy profile"
            }
            val authority = host + if (uri.port == -1) "" else ":${uri.port}"
            require(origin == "${uri.scheme}://$authority") { "configured local browser origin must use its exact canonical spelling" }
            uri
        }
        require(parsed.map(URI::getScheme).distinct().size == 1) { "local browser aliases cannot downgrade the configured transport" }
        require(parsed.map(URI::getRawAuthority).distinct().size == parsed.size) { "configured local browser authorities must be unique" }
        originsByAuthority = parsed.associate { it.rawAuthority to it.toString() }
        secure = parsed.first().scheme == "https"
        cookieName = "decomp_session_" + digest((canonicalOrigin + "\n" + basePath).toByteArray()).hex().take(16)
    }
}

/** Wall time describes expiry to users; monotonic ticks enforce deadlines across wall-clock adjustments. */
interface WebAccessClock {
    fun instant(): Instant
    fun nanoTime(): Long
}

private object SystemWebAccessClock : WebAccessClock {
    override fun instant(): Instant = Instant.now()
    override fun nanoTime(): Long = System.nanoTime()
}

class WebEndpointPolicy private constructor(
    internal val methods: Set<String>,
    internal val sessionRequired: Boolean,
    internal val mutation: Boolean,
    internal val multipart: Boolean,
) {
    companion object {
        /** Routing preflight only; private handlers must still authorize their session/mutation policy. */
        internal fun transport(methods: Set<String>): WebEndpointPolicy {
            require(methods.isNotEmpty() && methods.all { it.matches(Regex("[A-Z][A-Z0-9_-]{0,31}")) }) {
                "transport policy requires explicit bounded methods"
            }
            return WebEndpointPolicy(methods.toSet(), false, false, false)
        }
        /** The router may apply this only to the public login shell and inventoried application assets. */
        fun publicRead(): WebEndpointPolicy = WebEndpointPolicy(setOf("GET", "HEAD"), false, false, false)
        fun privateRead(allowHead: Boolean = false): WebEndpointPolicy =
            WebEndpointPolicy(if (allowHead) setOf("GET", "HEAD") else setOf("GET"), true, false, false)
        fun jsonMutation(method: String): WebEndpointPolicy {
            require(method in setOf("POST", "PUT", "PATCH", "DELETE")) { "mutation policy requires an explicit mutation method" }
            return WebEndpointPolicy(setOf(method), true, true, false)
        }
        fun multipartUpload(): WebEndpointPolicy = WebEndpointPolicy(setOf("POST"), true, true, true)
    }
}

class WebAccessDenied internal constructor(
    val status: Int,
    val code: String,
    message: String,
    val allowedMethods: Set<String> = emptySet(),
    internal val clearCookie: Boolean = false,
) : RuntimeException(message)

/** These return values deliberately redact their printable representation. Never serialize them wholesale. */
class WebBootstrapToken internal constructor(val token: String, val expiresAt: Instant) {
    override fun toString(): String = "WebBootstrapToken(expiresAt=$expiresAt, token=[redacted])"
}

class AuthorizedWebSession internal constructor(val sessionId: String, val expiresAt: Instant, val idleExpiresAt: Instant)

class WebSessionCredentials internal constructor(
    val session: AuthorizedWebSession,
    val csrfToken: String,
    val setCookie: String? = null,
) {
    override fun toString(): String = "WebSessionCredentials(sessionId=${session.sessionId}, credentials=[redacted])"
}

/**
 * Reusable local browser authority; it neither registers routes nor invokes workflow services.
 * Session/bootstrap/CSRF records contain only domain-separated SHA-256 token digests.
 * A process-only HMAC key derives a stable CSRF token from each authenticated cookie, allowing
 * reload and concurrent tabs without retaining plaintext tokens or rotating another tab's token.
 * The key and all records disappear on restart. Forwarded headers confer no authority.
 */
class LocalWebAccess(
    val configuration: LocalWebAccessConfiguration,
    private val clock: WebAccessClock = SystemWebAccessClock,
    private val random: SecureRandom = SecureRandom(),
) : AutoCloseable {
    private class BootstrapRecord(val digest: ByteArray, val issuedTick: Long)
    private class SessionRecord(
        val digest: ByteArray,
        val csrfDigest: ByteArray,
        val createdAt: Instant,
        val issuedTick: Long,
        var lastSeenTick: Long,
    )

    private val csrfKey = ByteArray(TOKEN_BYTES).also(random::nextBytes)
    private val sessions = mutableListOf<SessionRecord>()
    private var bootstrap: BootstrapRecord? = null
    private var closed = false

    /** Operator-only entry. Calling it invalidates any previously unconsumed bootstrap token. */
    @Synchronized
    fun issueBootstrap(): WebBootstrapToken {
        ensureOpen()
        val token = newToken()
        bootstrap?.digest?.fill(0)
        bootstrap = BootstrapRecord(tokenDigest("bootstrap", token), clock.nanoTime())
        return WebBootstrapToken(token, clock.instant().plus(BOOTSTRAP_LIFETIME))
    }

    /** Reads bounded JSON with a single token string; JSON escaping does not alter token identity. */
    fun establishSession(exchange: HttpExchange): WebSessionCredentials {
        synchronized(this) { ensureOpen() }
        validateBoundary(exchange, WebEndpointPolicy.jsonMutation("POST"))
        val declaredLength = singleHeader(exchange, "Content-Length", 32)?.let { value ->
            value.toLongOrNull()?.takeIf { it >= 0 } ?: deny(400, "INVALID_HEADER", "Invalid request length.")
        }
        if (declaredLength != null && declaredLength > MAX_BOOTSTRAP_BODY_BYTES) {
            deny(413, "BODY_TOO_LARGE", "The session request exceeds its byte limit.")
        }
        val bytes = exchange.requestBody.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(256)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (output.size() + count > MAX_BOOTSTRAP_BODY_BYTES) deny(413, "BODY_TOO_LARGE", "The session request exceeds its byte limit.")
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        val body = try { OracleJson.parse(bytes, BOOTSTRAP_JSON_LIMITS) } catch (_: StrictJsonException) {
            deny(400, "MALFORMED_JSON", "The session request must contain a single bootstrap token.")
        }
        if (body !is JsonObject || body.keys != setOf("token")) {
            deny(400, "VALIDATION_FAILED", "The session request must contain only the token field.")
        }
        val field = body.getValue("token")
        if (field !is JsonPrimitive || !field.isString) {
            deny(400, "VALIDATION_FAILED", "The bootstrap token must be a string.")
        }
        val token = field.content
        if (!validToken(token)) deny(400, "VALIDATION_FAILED", "The bootstrap token has an invalid format.")
        // Untrusted body I/O must not hold the session lock or block independent authenticated reads.
        return synchronized(this) { establishSessionToken(token) }
    }

    private fun establishSessionToken(token: String): WebSessionCredentials {
        ensureOpen()
        val tick = clock.nanoTime()
        val record = bootstrap ?: deny(401, "BOOTSTRAP_REQUIRED", "Open a newly issued local browser link.")
        if (elapsed(record.issuedTick, tick, BOOTSTRAP_LIFETIME)) {
            record.digest.fill(0)
            bootstrap = null
            deny(401, "BOOTSTRAP_EXPIRED", "The local browser link expired. Issue a new link.")
        }
        if (!MessageDigest.isEqual(record.digest, tokenDigest("bootstrap", token))) {
            deny(401, "BOOTSTRAP_REQUIRED", "Open a newly issued local browser link.")
        }
        pruneExpired(tick)
        if (sessions.size >= MAX_SESSIONS) deny(429, "SESSION_LIMIT", "The active browser session limit has been reached.")
        val sessionToken = allocateSessionToken()
        val csrf = csrfToken(sessionToken)
        val now = clock.instant()
        val session = SessionRecord(tokenDigest("session", sessionToken), tokenDigest("csrf", csrf), now, tick, tick)
        record.digest.fill(0)
        bootstrap = null
        sessions += session
        return WebSessionCredentials(describe(session, now), csrf, sessionCookie(sessionToken))
    }

    /** Validate before reading job records or committing stream/download headers. */
    @Synchronized
    fun authorize(exchange: HttpExchange, policy: WebEndpointPolicy): AuthorizedWebSession? {
        ensureOpen()
        validateBoundary(exchange, policy)
        if (!policy.sessionRequired) return null
        return describe(authenticate(exchange, policy.mutation), clock.instant())
    }

    /** Authenticated bootstrap GET restores the same CSRF token without invalidating other tabs. */
    @Synchronized
    fun csrfForSession(exchange: HttpExchange): WebSessionCredentials {
        ensureOpen()
        validateBoundary(exchange, WebEndpointPolicy.privateRead())
        val record = authenticate(exchange, false)
        val csrf = csrfToken(sessionCookieToken(exchange))
        check(MessageDigest.isEqual(record.csrfDigest, tokenDigest("csrf", csrf))) { "local session CSRF binding is inconsistent" }
        return WebSessionCredentials(describe(record, clock.instant()), csrf)
    }

    @Synchronized
    fun logout(exchange: HttpExchange): String {
        ensureOpen()
        validateBoundary(exchange, WebEndpointPolicy.jsonMutation("DELETE"))
        val record = authenticate(exchange, true)
        sessions.remove(record)
        erase(record)
        return expiredSessionCookie()
    }

    @Synchronized
    fun revokeAll() {
        sessions.forEach(::erase)
        sessions.clear()
        bootstrap?.digest?.fill(0)
        bootstrap = null
    }

    @Synchronized
    override fun close() {
        revokeAll()
        csrfKey.fill(0)
        closed = true
    }

    /** All denial bodies are fixed safe text, including navigation, SSE and download failures. */
    fun sendDenied(exchange: HttpExchange, failure: WebAccessDenied) {
        val requestId = UUID.randomUUID().toString()
        val body = buildJsonObject {
            put("apiVersion", 1)
            put("kind", "error")
            put("requestId", requestId)
            put("error", buildJsonObject {
                put("code", failure.code)
                put("message", failure.message)
                put("retryable", failure.status == 429)
                put("details", JsonArray(emptyList()))
                put("retryAfterMs", if (failure.status == 429) JsonPrimitiveRetry else JsonNull)
            })
        }.toString().toByteArray()
        exchange.responseHeaders.set("Content-Type", "application/json; charset=utf-8")
        exchange.responseHeaders.set("Content-Length", body.size.toString())
        exchange.responseHeaders.set("Cache-Control", "no-store")
        exchange.responseHeaders.set("Referrer-Policy", "no-referrer")
        exchange.responseHeaders.set("X-Content-Type-Options", "nosniff")
        exchange.responseHeaders.set("X-Request-ID", requestId)
        deniedHeaders(exchange, failure)
        try {
            if (exchange.requestMethod == "HEAD") exchange.sendResponseHeaders(failure.status, -1)
            else {
                exchange.sendResponseHeaders(failure.status, body.size.toLong())
                exchange.responseBody.use { it.write(body) }
            }
        } finally { exchange.close() }
    }

    internal fun deniedHeaders(exchange: HttpExchange, failure: WebAccessDenied) {
        if (failure.allowedMethods.isNotEmpty()) exchange.responseHeaders.set("Allow", failure.allowedMethods.sorted().joinToString(", "))
        if (failure.clearCookie) exchange.responseHeaders.add("Set-Cookie", expiredSessionCookie())
        if (failure.status == 429) exchange.responseHeaders.set("Retry-After", "30")
    }

    private fun validateBoundary(exchange: HttpExchange, policy: WebEndpointPolicy) {
        if (exchange.requestHeaders.size > 64) deny(400, "INVALID_HEADER", "The request contains too many headers.")
        if (exchange.requestHeaders.keys.any { it.equals("Forwarded", true) || it.startsWith("X-Forwarded-", true) || it.equals("X-Real-IP", true) }) {
            deny(403, "FORWARDED_HEADERS_DENIED", "Forwarding headers are not supported by this local access profile.")
        }
        val host = singleHeader(exchange, "Host", 256) ?: deny(403, "HOST_DENIED", "The request host is not configured.")
        val originForHost = configuration.originsByAuthority[host] ?: deny(403, "HOST_DENIED", "The request host is not configured.")
        val origin = singleHeader(exchange, "Origin", 256)
        if (origin != null && origin != originForHost) deny(403, "ORIGIN_DENIED", "The request origin does not match this application.")
        val fetchSite = singleHeader(exchange, "Sec-Fetch-Site", 32)
        if (fetchSite != null && fetchSite !in setOf("same-origin", "none")) {
            deny(403, "ORIGIN_DENIED", "The browser request is not from the application origin.")
        }
        if (exchange.requestMethod !in policy.methods) {
            throw WebAccessDenied(405, "METHOD_NOT_ALLOWED", "The endpoint does not support this method.", policy.methods)
        }
        if (policy.mutation) {
            if (origin == null) deny(403, "ORIGIN_DENIED", "Mutations require the exact application origin.")
            val contentType = singleHeader(exchange, "Content-Type", 256)
            val valid = if (policy.multipart) contentType?.let(MULTIPART_TYPE::matches) == true else contentType?.let(JSON_TYPE::matches) == true
            if (!valid) deny(415, "UNSUPPORTED_MEDIA_TYPE", "The request body has an unsupported content type.")
        }
    }

    private fun authenticate(exchange: HttpExchange, mutation: Boolean): SessionRecord {
        val token = sessionCookieToken(exchange)
        val hash = tokenDigest("session", token)
        val record = sessions.firstOrNull { MessageDigest.isEqual(it.digest, hash) }
            ?: deny(401, "SESSION_REQUIRED", "Open a local browser link to start a session.")
        val tick = clock.nanoTime()
        if (expired(record, tick)) {
            sessions.remove(record)
            erase(record)
            throw WebAccessDenied(401, "SESSION_EXPIRED", "The browser session expired. Open a new local browser link.", clearCookie = true)
        }
        if (mutation) {
            val csrf = singleHeader(exchange, "X-CSRF-Token", 128)
            if (csrf == null || !validToken(csrf) || !MessageDigest.isEqual(record.csrfDigest, tokenDigest("csrf", csrf))) {
                deny(403, "CSRF_DENIED", "The mutation requires a valid session CSRF token.")
            }
        }
        // Denied requests never keep a session alive.
        record.lastSeenTick = tick
        return record
    }

    private fun sessionCookieToken(exchange: HttpExchange): String {
        val headers = exchange.requestHeaders["Cookie"] ?: deny(401, "SESSION_REQUIRED", "Open a local browser link to start a session.")
        if (headers.size > 8 || headers.sumOf(String::length) > 8192) deny(400, "INVALID_HEADER", "The cookie header exceeds its limit.")
        val pairs = headers.flatMap { it.split(';') }
        if (pairs.size > 64) deny(400, "INVALID_HEADER", "The cookie header contains too many values.")
        val selected = pairs.map(String::trim).filter { it.substringBefore('=') == configuration.cookieName }
        if (selected.size != 1) deny(401, "SESSION_REQUIRED", "A single valid browser session cookie is required.")
        val token = selected.single().substringAfter('=', "")
        if (!validToken(token)) deny(401, "SESSION_REQUIRED", "A valid browser session cookie is required.")
        return token
    }

    private fun singleHeader(exchange: HttpExchange, name: String, limit: Int): String? {
        val values = exchange.requestHeaders[name] ?: return null
        if (values.size != 1 || values.single().length > limit || values.single().any { it.code < 32 || it.code == 127 }) {
            deny(400, "INVALID_HEADER", "The request contains an invalid or repeated security header.")
        }
        return values.single()
    }

    private fun describe(record: SessionRecord, now: Instant): AuthorizedWebSession = AuthorizedWebSession(
        record.digest.hex(), record.createdAt.plus(SESSION_LIFETIME), minOf(record.createdAt.plus(SESSION_LIFETIME), now.plus(IDLE_LIFETIME)),
    )

    private fun allocateSessionToken(): String {
        repeat(8) {
            val token = newToken()
            val candidate = tokenDigest("session", token)
            if (sessions.none { MessageDigest.isEqual(it.digest, candidate) }) return token
        }
        error("Unable to allocate a unique local browser session")
    }

    private fun newToken(): String = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(TOKEN_BYTES).also(random::nextBytes))
    private fun csrfToken(sessionToken: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(csrfKey, "HmacSHA256"))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(("decomp-web-csrf-v1\u0000" + sessionToken).toByteArray()))
    }
    private fun sessionCookie(token: String): String =
        "${configuration.cookieName}=$token; Path=${configuration.basePath}; Max-Age=${SESSION_LIFETIME.seconds}; HttpOnly; SameSite=Strict" + if (configuration.secure) "; Secure" else ""
    private fun expiredSessionCookie(): String =
        "${configuration.cookieName}=; Path=${configuration.basePath}; Max-Age=0; HttpOnly; SameSite=Strict" + if (configuration.secure) "; Secure" else ""
    private fun expired(record: SessionRecord, tick: Long): Boolean =
        elapsed(record.issuedTick, tick, SESSION_LIFETIME) || elapsed(record.lastSeenTick, tick, IDLE_LIFETIME)
    private fun pruneExpired(tick: Long) {
        sessions.removeAll { record -> expired(record, tick).also { if (it) erase(record) } }
    }
    private fun erase(record: SessionRecord) { record.digest.fill(0); record.csrfDigest.fill(0) }
    private fun ensureOpen() { if (closed) deny(503, "SERVER_DRAINING", "The browser session service is closed.") }

    companion object {
        private const val TOKEN_BYTES = 32
        private const val MAX_SESSIONS = 8
        private const val MAX_BOOTSTRAP_BODY_BYTES = 1024
        private val BOOTSTRAP_LIFETIME = Duration.ofMinutes(5)
        private val SESSION_LIFETIME = Duration.ofHours(8)
        private val IDLE_LIFETIME = Duration.ofMinutes(30)
        private val TOKEN = Regex("[A-Za-z0-9_-]{43}")
        private val BOOTSTRAP_JSON_LIMITS = StrictJsonLimits(
            maximumInputBytes = MAX_BOOTSTRAP_BODY_BYTES,
            maximumCanonicalBytes = MAX_BOOTSTRAP_BODY_BYTES,
            maximumDepth = 8,
            maximumNodes = 128,
            maximumStringBytes = MAX_BOOTSTRAP_BODY_BYTES,
            maximumTotalStringBytes = MAX_BOOTSTRAP_BODY_BYTES,
            maximumNumberCharacters = 128,
        )
        private val JSON_TYPE = Regex("application/json(?:[ \\t]*;[ \\t]*charset=(?:utf-8|\"utf-8\"))?", RegexOption.IGNORE_CASE)
        private val MULTIPART_TYPE = Regex("multipart/form-data[ \\t]*;[ \\t]*boundary=(?:[A-Za-z0-9'()+_,./:=?-]{1,70}|\"[A-Za-z0-9'()+_,./:=? -]{0,69}[A-Za-z0-9'()+_,./:=?-]\")", RegexOption.IGNORE_CASE)
        private val JsonPrimitiveRetry = kotlinx.serialization.json.JsonPrimitive("30000")
        private fun validToken(value: String): Boolean = TOKEN.matches(value) && runCatching {
            val decoded = Base64.getUrlDecoder().decode(value)
            decoded.size == TOKEN_BYTES && Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) == value
        }.getOrDefault(false)
        private fun elapsed(start: Long, end: Long, lifetime: Duration): Boolean = end - start >= lifetime.toNanos()
        private fun tokenDigest(domain: String, token: String): ByteArray = digest(("decomp-web-$domain-v1\u0000" + token).toByteArray())
        private fun deny(status: Int, code: String, message: String): Nothing = throw WebAccessDenied(status, code, message)
    }
}

private fun digest(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)
private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
