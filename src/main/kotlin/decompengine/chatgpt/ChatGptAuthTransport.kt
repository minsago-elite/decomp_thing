package decompengine.chatgpt

import java.time.Duration
import java.net.URI
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.http.HttpClient
import java.nio.ByteBuffer
import java.util.Locale
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.Flow
import javax.net.ssl.*
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.net.http.HttpRequest
import java.net.http.HttpResponse
internal enum class ChatGptAuthHttpPurpose { DISCOVERY, JWKS, CODE, REFRESH, REVOCATION }
internal enum class ChatGptAuthDispatchEvidence { NOT_SUBMITTED, MAY_HAVE_BEEN_SENT }
internal enum class ChatGptAuthHttpFailure {
    CANCELLED, DEADLINE, CAPACITY, ALREADY_USED, INVALID_BINDING, INVALID_FORM,
    RUNTIME_UNQUALIFIED, TLS_OR_IO, INVALID_STATUS, INVALID_HEADERS, BODY_LIMIT,
    INVALID_BODY, DEPENDENCY_FAILED, UNSETTLED,
}
internal enum class ChatGptAuthOAuthError {
    INVALID_GRANT, INVALID_REFRESH_TOKEN, TOKEN_EXPIRED, REFRESH_TOKEN_EXPIRED,
    REFRESH_TOKEN_INVALIDATED, REFRESH_TOKEN_REUSED, INVALID_CLIENT,
}
internal class ChatGptAuthHttpException(
    val failure: ChatGptAuthHttpFailure,
    val dispatch: ChatGptAuthDispatchEvidence,
) : Exception("ChatGPT authentication HTTP failed: ${failure.name}", null, false, false) {
    override fun toString(): String = "ChatGptAuthHttpException(${failure.name},${dispatch.name})"
}

// Only a private concrete implementation minted by OIDC's validated discovery can exist
// in production. No URI/String constructor, URL getter, copy(), or data-class rendering.
// Its narrowly internal dispatch implementation is described in implementation.md.
internal abstract class ChatGptAuthRevocationEndpoint : ChatGptAuthSafeObject() {
    // Implemented by OIDC's private validated endpoint; no destination argument.
    internal abstract fun newRevocationRequest(
        logout: ChatGptLocalLogout, operation: ChatGptStoreOperation, httpDeadline: ChatGptDeadline,
    ): HttpRequest
}

// AUTH-only dispatch gate. Must be nonblocking, trusted, and invoked once on caller thread.
// Code: delegates to A2 lifetime.claimDispatch(). GET/revoke: owner-local one-shot gate.
// Refresh: request.dispatch surrounds call.start, not an asynchronous callback.
internal abstract class ChatGptAuthDispatchGate : ChatGptAuthSafeObject() {
    abstract fun claim(): Boolean
}

// One terminal outcome, delivered once. None contains a raw Throwable or diagnostic strings.
internal sealed class ChatGptAuthHttpOutcome : ChatGptAuthSafeObject() {
    class Token(val reply: ChatGptAuthTokenReply) : ChatGptAuthHttpOutcome()
    class Document(val reply: ChatGptAuthDocumentReply) : ChatGptAuthHttpOutcome()
    class Revoked : ChatGptAuthHttpOutcome()
    class Rejected(val status: Int, val error: ChatGptAuthOAuthError?) : ChatGptAuthHttpOutcome()
    class Failed(val failure: ChatGptAuthHttpFailure) : ChatGptAuthHttpOutcome()
}

// Byte arrays/headers are NEVER obtainable through these handles. Constructors private in
// implementation; purpose, binding and original operation are captured by the actual call.
internal abstract class ChatGptAuthTokenReply : ChatGptAuthSafeObject() {
    abstract val receivedAt: Instant
    abstract val purpose: ChatGptAuthHttpPurpose
    // Only CODE replies accept this operation. Uses the request's captured binding, not
    // a caller-supplied snapshot/code pair. Exactly one validation session per reply.
    internal abstract fun validateAuthorization(
        keys: ChatGptOidcJwks,
        validatedAt: Instant,
        operation: ChatGptStoreOperation,
        jwksAlreadyRefetched: Boolean,
    ): ChatGptAuthorizationProof
    abstract fun discard()
    // A4 later adds an actual validateRefresh adapter; there is deliberately none today.
}
// Immutable transport-minted result from validated response Cache-Control only.
// No public constructor, raw header getter, mutable TTL, or external policy factory.
internal abstract class ChatGptAuthDocumentCachePolicy : ChatGptAuthSafeObject() {
    abstract val reusable: Boolean
    abstract val maximumAgeNanos: Long // 0..600_000_000_000; 0 means ephemeral
}
internal abstract class ChatGptAuthDocumentReply : ChatGptAuthSafeObject() {
    internal abstract fun cachePolicy(operation: ChatGptStoreOperation): ChatGptAuthDocumentCachePolicy
    internal abstract fun discovery(operation: ChatGptStoreOperation): ChatGptOidcDiscovery
    internal abstract fun jwks(operation: ChatGptStoreOperation): ChatGptOidcJwks
    abstract fun discard()
}
internal abstract class ChatGptAuthHttpCall : ChatGptAuthSafeObject() {
    abstract val purpose: ChatGptAuthHttpPurpose
    abstract val dispatchEvidence: ChatGptAuthDispatchEvidence
    // prepare() already registered this call and all acquisition slots; no I/O yet.
    // Parent registers its lifetime resource wrapper BEFORE calling start().
    abstract fun start(gate: ChatGptAuthDispatchGate)
    // Uses the captured original operation; caller cannot supply a replacement budget.
    abstract fun await(): ChatGptAuthHttpOutcome
    abstract fun cancel()
    // maxWait is a ceiling, not a fresh business-operation budget. Sticky first cleanup
    // origin: min(maxWait, 250ms, captured original remaining), never refreshed on calls.
    abstract fun cancelAndSettle(maxWaitNanos: Long): ChatGptAuthSettlement
}
internal abstract class ChatGptAuthTransport : ChatGptAuthSafeObject() {
    abstract fun prepareDiscovery(operation: ChatGptStoreOperation): ChatGptAuthHttpCall
    abstract fun prepareJwks(operation: ChatGptStoreOperation): ChatGptAuthHttpCall
    abstract fun prepareCode(
        binding: ChatGptAuthCodeBinding,
        code: ChatGptPlanOAuthAttempt.CallbackResult.Code,
        operation: ChatGptStoreOperation,
    ): ChatGptAuthHttpCall
    // ONLY called synchronously within actual ChatGptRenewalRequest.dispatch { client, token -> }.
    // No general form/body/header constructor exists. REFRESH replies stay opaque until A4.
    abstract fun prepareRefresh(
        clientId: String, refreshToken: String, operation: ChatGptStoreOperation,
    ): ChatGptAuthHttpCall
    abstract fun prepareRevocation(
        endpoint: ChatGptAuthRevocationEndpoint,
        logout: ChatGptLocalLogout,
        operation: ChatGptStoreOperation,
    ): ChatGptAuthHttpCall
    abstract fun shutdown(maxWaitNanos: Long): ChatGptAuthSettlement
}
// Concrete object name: ChatGptAuthProduction, in ChatGptAuthTransport.kt.
// metadata() shares the same singleton transport and process-entry admission.
// No endpoint, TLS, proxy, clock, factory, client, or request argument to production().
// Admission remains DENIED unless parent startup + runtime qualification requirements pass.
internal abstract class ChatGptAuthTransportFactory : ChatGptAuthSafeObject() {
    abstract fun recordProcessEntry()
    abstract fun production(): ChatGptAuthTransport
    abstract fun metadata(): ChatGptAuthMetadata
}

// Trusted low-level adapter seam. Production selects one private JdkAuthWirePort itself.
// Scripted implementation and all arbitrary endpoint/test-CA configuration exist in src/test.
// No environment flag, service loader, public production overload, or fallback selects a fake.
// The call's pure state machine exists in main and is shared by fake and JDK executions.
internal abstract class ChatGptAuthWirePort : ChatGptAuthSafeObject() {
    // Acquire returns an inert session; owner installs it before submit can occur. If
    // cancelled during acquisition, install immediately closes it instead of submitting.
    abstract fun acquire(connectTimeoutNanos: Long): ChatGptAuthWireSession
}
internal abstract class ChatGptAuthWireSession : ChatGptAuthSafeObject() {
    abstract fun sendAsync(
        request: HttpRequest,
        handler: HttpResponse.BodyHandler<ByteArray>,
    ): CompletableFuture<HttpResponse<ByteArray>>
    abstract fun shutdownNow()
    abstract fun awaitTermination(maxWaitNanos: Long): Boolean
    // JDK adapter additionally owns/joins its explicit executor; true means BOTH settled.
}


/** No offline artifact, property repair or scripted port can admit production. */
internal object ChatGptAuthProduction : ChatGptAuthTransportFactory() {
    override fun recordProcessEntry() { /* Parent owns the future immutable entry receipt. */ }
    override fun production(): ChatGptAuthTransport = authFail(ChatGptAuthHttpFailure.RUNTIME_UNQUALIFIED)
    override fun metadata(): ChatGptAuthMetadata = authFail(ChatGptAuthHttpFailure.RUNTIME_UNQUALIFIED)
}

internal fun authFail(failure: ChatGptAuthHttpFailure): Nothing =
    throw ChatGptAuthHttpException(failure, ChatGptAuthDispatchEvidence.NOT_SUBMITTED)

internal inline fun <T> authBoundary(block: () -> T): T = try { block() }
catch (e: ChatGptAuthHttpException) { throw e }
catch (e: ChatGptOidcFailure) { throw e }
catch (_: InterruptedException) { Thread.currentThread().interrupt(); authFail(ChatGptAuthHttpFailure.CANCELLED) }
catch (_: CancellationException) { authFail(ChatGptAuthHttpFailure.CANCELLED) }
catch (_: TimeoutException) { authFail(ChatGptAuthHttpFailure.DEADLINE) }
catch (_: Exception) { authFail(ChatGptAuthHttpFailure.DEPENDENCY_FAILED) }

private const val ENTITY_LIMIT = 262144
private const val FORM_LIMIT = 131072
internal const val AUTH_CACHE_NANOS = 600_000_000_000L
private const val HTTP_NANOS = 10_000_000_000L
private const val CLEANUP_NANOS = 250_000_000L

private class DocumentPolicy(override val reusable: Boolean, override val maximumAgeNanos: Long) : ChatGptAuthDocumentCachePolicy()
internal fun isTransportCachePolicy(policy: ChatGptAuthDocumentCachePolicy): Boolean = policy is DocumentPolicy
internal fun isTransportTokenReply(reply: ChatGptAuthTokenReply): Boolean = reply is TokenReply
internal fun isTransportDocumentReply(reply: ChatGptAuthDocumentReply): Boolean = reply is DocumentReply

private class DocumentReply(
    private var bytes: ByteArray?, private val purpose: ChatGptAuthHttpPurpose,
    private val operation: ChatGptStoreOperation, private val policy: DocumentPolicy,
    private val release: () -> Unit,
) : ChatGptAuthDocumentReply() {
    private var readers = 0
    private var released = false
    private fun <T> read(op: ChatGptStoreOperation, block: (ByteArray) -> T): T {
        val value = synchronized(this) {
            if (operation !== op || bytes == null) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
            readers++; bytes!!
        }
        try {
            operation.check()
            synchronized(this) { if (bytes !== value) authFail(ChatGptAuthHttpFailure.CANCELLED) }
            val result = block(value)
            operation.check()
            synchronized(this) { if (bytes !== value) authFail(ChatGptAuthHttpFailure.CANCELLED) }
            return result
        } finally {
            synchronized(this) { readers-- }
            releaseIfAcknowledged()
        }
    }
    override fun cachePolicy(operation: ChatGptStoreOperation): ChatGptAuthDocumentCachePolicy = read(operation) { policy }
    override fun discovery(operation: ChatGptStoreOperation): ChatGptOidcDiscovery = read(operation) { value ->
        if (purpose != ChatGptAuthHttpPurpose.DISCOVERY) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
        ChatGptPlanOidc.validateDiscoveryDocument(value, operation)
    }
    override fun jwks(operation: ChatGptStoreOperation): ChatGptOidcJwks = read(operation) { value ->
        if (purpose != ChatGptAuthHttpPurpose.JWKS) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
        ChatGptPlanOidc.validateJwksDocument(value, operation)
    }
    override fun discard() {
        synchronized(this) { bytes = null }
        releaseIfAcknowledged()
    }
    private fun releaseIfAcknowledged() {
        val ready = synchronized(this) {
            if (bytes == null && readers == 0 && !released) { released = true; true } else false
        }
        if (ready) release()
    }

}

internal fun isTransportReplyValidation(reply: ChatGptAuthTokenReply, operation: ChatGptStoreOperation): Boolean =
    reply is TokenReply && reply.validating(operation)

private class TokenReply(
    private var bytes: ByteArray?, override val receivedAt: Instant, override val purpose: ChatGptAuthHttpPurpose,
    private var binding: ChatGptAuthCodeBinding?, private val operation: ChatGptStoreOperation,
    private val release: () -> Unit,
) : ChatGptAuthTokenReply() {
    private var validations = 0
    private var repair = false
    private var validator: Thread? = null
    private var discarding = false
    private var released = false
    @Synchronized fun validating(op: ChatGptStoreOperation): Boolean =
        operation === op && bytes != null && validator === Thread.currentThread()
    override fun validateAuthorization(
        keys: ChatGptOidcJwks, validatedAt: Instant, operation: ChatGptStoreOperation, jwksAlreadyRefetched: Boolean,
    ): ChatGptAuthorizationProof {
        var failure: ChatGptAuthHttpFailure? = null
        val captured = synchronized(this) {
            if (this.operation !== operation || purpose != ChatGptAuthHttpPurpose.CODE || bytes == null ||
                binding == null || !isMetadataCodeBinding(binding!!) || !isOidcJwks(keys)) {
                failure = ChatGptAuthHttpFailure.INVALID_BINDING
            } else if ((validations == 0 && jwksAlreadyRefetched) || (validations != 0 && (!repair || !jwksAlreadyRefetched))) {
                failure = ChatGptAuthHttpFailure.ALREADY_USED
            }
            if (validator != null) failure = ChatGptAuthHttpFailure.ALREADY_USED
            if (failure != null) return@synchronized null
            validations++; repair = false; validator = Thread.currentThread()
            Pair(bytes!!, binding!!)
        }
        if (captured == null) { discard(); authFail(failure!!) }
        try {
            operation.check()
            val reservedKeys = reserveOidcJwks(keys, this, operation)
            val proof = captured.second.prove(captured.first, reservedKeys, receivedAt, validatedAt, operation, jwksAlreadyRefetched)
            operation.check()
            synchronized(this) {
                if (bytes == null) authFail(ChatGptAuthHttpFailure.CANCELLED)
                bytes = null
            }
            discard()
            return proof
        } catch (e: ChatGptOidcFailure) {
            val retry = synchronized(this) {
                (bytes != null && e.reason == ChatGptOidcFailure.Reason.UNKNOWN_KEY_REFETCH_ONCE && validations == 1)
                    .also { repair = it }
            }
            if (!retry) discard()
            throw e
        } catch (e: Exception) {
            discard()
            if (e is ChatGptAuthHttpException) throw e
            authFail(ChatGptAuthHttpFailure.DEPENDENCY_FAILED)
        } finally {
            synchronized(this) { validator = null }
            releaseIfAcknowledged()
        }
    }
    override fun discard() {
        val old = synchronized(this) {
            bytes = null; repair = false
            binding.also { if (it != null) { binding = null; discarding = true } }
        }
        // Never acquire the binding monitor while holding the reply monitor.
        // Fencing drops authority now; the validator still owns its captured bytes.
        try { old?.let(::discardMetadataCodeBinding) }
        finally {
            if (old != null) synchronized(this) { discarding = false }
            releaseIfAcknowledged()
        }
    }
    private fun releaseIfAcknowledged() {
        val ready = synchronized(this) {
            if (bytes == null && validator == null && !discarding && !released) { released = true; true } else false
        }
        if (ready) release()
    }

}

private class ResponseFields(val length: Long?, val policy: DocumentPolicy)
private val headerToken = Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+")
private fun responseFields(info: HttpResponse.ResponseInfo, purpose: ChatGptAuthHttpPurpose): ResponseFields {
    if (info.version() != HttpClient.Version.HTTP_1_1) authFail(ChatGptAuthHttpFailure.INVALID_HEADERS)
    val fields = info.headers().map()
    var count = 0L
    var total = 0L
    // Inspect vendor-owned collections before making any application header copies.
    for ((name, values) in fields) {
        if (name.length > 8192 || !name.matches(headerToken) || values.isEmpty()) authFail(ChatGptAuthHttpFailure.INVALID_HEADERS)
        for (value in values) {
            count++
            if (count > 64 || value.length > 8192 || value.any { it.code !in 0x20..0x7e && it != '\t' })
                authFail(ChatGptAuthHttpFailure.INVALID_HEADERS)
            total += name.length.toLong() + value.length + 32L
            if (total > 32768) authFail(ChatGptAuthHttpFailure.INVALID_HEADERS)
        }
    }
    fun values(name: String) = fields.entries.filter { it.key.equals(name, true) }.flatMap { it.value }
    fun single(name: String): String? {
        val all = values(name)
        if (all.size > 1) authFail(ChatGptAuthHttpFailure.INVALID_HEADERS)
        return all.firstOrNull()?.trim()
    }
    val length = single("Content-Length")?.let {
        if (!it.matches(Regex("0|[1-9][0-9]*"))) authFail(ChatGptAuthHttpFailure.INVALID_HEADERS)
        it.toLongOrNull() ?: authFail(ChatGptAuthHttpFailure.INVALID_HEADERS)
    }
    if (length != null && length > ENTITY_LIMIT) authFail(ChatGptAuthHttpFailure.BODY_LIMIT)
    val encoding = single("Content-Encoding")
    if (encoding != null && !encoding.equals("identity", true)) authFail(ChatGptAuthHttpFailure.INVALID_HEADERS)
    val transfer = single("Transfer-Encoding")
    if (transfer != null && (!transfer.equals("chunked", true) || length != null)) authFail(ChatGptAuthHttpFailure.INVALID_HEADERS)
    val mime = single("Content-Type")
    if (!(purpose == ChatGptAuthHttpPurpose.REVOCATION && info.statusCode() == 200 && mime == null)) {
        if (mime == null || !mime.matches(Regex("application/json(?:\\s*;\\s*charset\\s*=\\s*(?:UTF-8|\"UTF-8\"))?", RegexOption.IGNORE_CASE)))
            authFail(ChatGptAuthHttpFailure.INVALID_HEADERS)
    }
    return ResponseFields(length, cachePolicy(values("Cache-Control"), values("Age")))
}

/** Bounded ASCII directive scanner: quoted comma/field-name lists remain one directive. */
private fun cachePolicy(controls: List<String>, ages: List<String>): DocumentPolicy {
    var maxAge = 600L
    var seenMax = false
    var ephemeral = false
    for (line in controls) {
        var start = 0
        var quoted = false
        var escape = false
        val parts = ArrayList<String>()
        for (i in line.indices) {
            val c = line[i]
            if (escape) { escape = false; continue }
            if (quoted && c == '\\') { escape = true; continue }
            if (c == '"') quoted = !quoted
            if (c == ',' && !quoted) { parts.add(line.substring(start, i)); start = i + 1 }
        }
        if (quoted || escape) ephemeral = true
        parts.add(line.substring(start))
        for (part in parts) {
            val directive = part.trim()
            val eq = directive.indexOf('=')
            val name = (if (eq < 0) directive else directive.substring(0, eq).trim()).lowercase(Locale.ROOT)
            val value = if (eq < 0) null else directive.substring(eq + 1).trim()
            val validQuoted = value != null && value.length >= 2 && value.first() == '"' && value.last() == '"' &&
                Regex("\"(?:[ !#-\\[\\]-~]|\\\\[ -~])*\"").matches(value)
            if (!name.matches(headerToken) || (value != null && !value.matches(headerToken) && !validQuoted)) ephemeral = true
            when (name) {
                "no-store", "no-cache" -> ephemeral = true
                "max-age" -> {
                    if (seenMax || value == null || !value.matches(Regex("0|[1-9][0-9]*"))) ephemeral = true
                    else {
                        // Saturate BEFORE multiplication/conversion; a large valid age cannot overflow.
                        var seconds = 0L
                        for (digit in value) seconds = minOf(600L, seconds * 10 + (digit - '0'))
                        maxAge = minOf(600L, seconds)
                    }
                    seenMax = true
                }
            }
        }
    }
    if (ages.size > 1) ephemeral = true
    ages.firstOrNull()?.trim()?.let {
        val age = if (it.matches(Regex("0|[1-9][0-9]*"))) it.toLongOrNull() else null
        if (age == null) ephemeral = true else maxAge = maxOf(0L, maxAge - minOf(age, maxAge))
    }
    return if (ephemeral || maxAge == 0L) DocumentPolicy(false, 0) else DocumentPolicy(true, maxAge * 1_000_000_000L)
}

/** Same-operation HTTP child; callbacks can veto but cannot grant time. */
internal fun authHttpCheck(operation: ChatGptStoreOperation, httpDeadline: ChatGptDeadline): Long {
    if (!httpDeadline.isWithin(operation.deadline)) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
    if (httpDeadline.remainingNanos() == 0L) authFail(ChatGptAuthHttpFailure.DEADLINE)
    operation.check()
    if (operation.fence.isCancelled()) authFail(ChatGptAuthHttpFailure.CANCELLED)
    return httpDeadline.remainingNanos().also { if (it == 0L) authFail(ChatGptAuthHttpFailure.DEADLINE) }
}

/** Counts UTF-8 and percent expansion without allocating an encoded value. */
private fun formValue(value: String, operation: ChatGptStoreOperation, httpDeadline: ChatGptDeadline, emit: (Int) -> Unit): Int {
    var bytes = 0
    var i = 0
    while (i < value.length) {
        if (i % 256 == 0) authHttpCheck(operation, httpDeadline)
        val c = value[i++]
        if (c.isISOControl()) authFail(ChatGptAuthHttpFailure.INVALID_FORM)
        val cp = when {
            Character.isHighSurrogate(c) -> {
                if (i >= value.length || !Character.isLowSurrogate(value[i])) authFail(ChatGptAuthHttpFailure.INVALID_FORM)
                Character.toCodePoint(c, value[i++])
            }
            Character.isLowSurrogate(c) -> authFail(ChatGptAuthHttpFailure.INVALID_FORM)
            else -> c.code
        }
        fun byte(b: Int) { bytes++; emit(b) }
        when {
            cp < 128 -> byte(cp)
            cp < 2048 -> { byte(0xc0 or (cp shr 6)); byte(0x80 or (cp and 63)) }
            cp < 65536 -> { byte(0xe0 or (cp shr 12)); byte(0x80 or ((cp shr 6) and 63)); byte(0x80 or (cp and 63)) }
            else -> { byte(0xf0 or (cp shr 18)); byte(0x80 or ((cp shr 12) and 63)); byte(0x80 or ((cp shr 6) and 63)); byte(0x80 or (cp and 63)) }
        }
    }
    return bytes
}
private fun unescaped(b: Int): Boolean = b in 65..90 || b in 97..122 || b in 48..57 || b in listOf(45, 46, 95, 42)
private fun encodedForm(fields: List<Pair<String, String>>, operation: ChatGptStoreOperation, httpDeadline: ChatGptDeadline): HttpRequest.BodyPublisher {
    var size = 0L
    for ((name, value) in fields) {
        size += name.length + 1L + if (size > 0) 1L else 0L
        if (value.length > 16384 || value.isBlank()) authFail(ChatGptAuthHttpFailure.INVALID_FORM)
        val bytes = formValue(value, operation, httpDeadline) { b ->
            size += if (unescaped(b) || b == 32) 1 else 3
            if (size > FORM_LIMIT) authFail(ChatGptAuthHttpFailure.INVALID_FORM)
        }
        if (bytes > 16384) authFail(ChatGptAuthHttpFailure.INVALID_FORM)
    }
    val output = ByteArray(size.toInt())
    var at = 0
    for ((index, field) in fields.withIndex()) {
        if (index != 0) output[at++] = '&'.code.toByte()
        for (c in field.first) output[at++] = c.code.toByte()
        output[at++] = '='.code.toByte()
        formValue(field.second, operation, httpDeadline) { b ->
            when {
                unescaped(b) -> output[at++] = b.toByte()
                b == 32 -> output[at++] = '+'.code.toByte()
                else -> { output[at++] = '%'.code.toByte(); output[at++] = "0123456789ABCDEF"[b shr 4].code.toByte(); output[at++] = "0123456789ABCDEF"[b and 15].code.toByte() }
            }
        }
    }
    authHttpCheck(operation, httpDeadline)
    return OneUsePublisher(output)
}
internal fun authRevocationPublisher(logout: ChatGptLocalLogout, operation: ChatGptStoreOperation, httpDeadline: ChatGptDeadline): HttpRequest.BodyPublisher {
    if (!logout.clientId.matches(Regex("oaiapp_[A-Za-z0-9_-]{1,249}"))) authFail(ChatGptAuthHttpFailure.INVALID_FORM)
    return encodedForm(listOf("token" to (logout.latestKnownRefreshToken ?: authFail(ChatGptAuthHttpFailure.INVALID_FORM)),
        "token_type_hint" to "refresh_token", "client_id" to logout.clientId), operation, httpDeadline)
}
internal fun authCodeRequest(code: ChatGptPlanOAuthAttempt.CallbackResult.Code, operation: ChatGptStoreOperation, httpDeadline: ChatGptDeadline): HttpRequest {
    authHttpCheck(operation, httpDeadline)
    // Committed OAuth bounds: <=4096 chars, <=160 client suffix, 43 verifier, numeric redirect.
    // Even 3 UTF-8 bytes/char each percent-expanded costs <=36864; fixed fields fit below 50KiB.
    if (code.code.length > 4096 || !code.issuedClientId.matches(Regex("oaiapp_[A-Za-z0-9_-]{1,160}")) ||
        ChatGptPlanOAuthAttempt.MAX_CALLBACK_QUERY_BYTES != 16384) authFail(ChatGptAuthHttpFailure.INVALID_FORM)
    val encoded = code.prepareExchange().encodedBody
    if (encoded.length > FORM_LIMIT || encoded.any { it.code > 127 }) authFail(ChatGptAuthHttpFailure.INVALID_FORM)
    authHttpCheck(operation, httpDeadline)
    return tokenRequest(OneUsePublisher(encoded.toByteArray(Charsets.US_ASCII)), operation, httpDeadline)
}
private fun tokenRequest(body: HttpRequest.BodyPublisher, operation: ChatGptStoreOperation, httpDeadline: ChatGptDeadline): HttpRequest =
    HttpRequest.newBuilder(URI(ChatGptPlanOidc.TOKEN)).version(HttpClient.Version.HTTP_1_1)
        .timeout(Duration.ofNanos(authHttpCheck(operation, httpDeadline)))
        .header("Content-Type", "application/x-www-form-urlencoded").header("Accept", "application/json").POST(body).build()

/** One subscription, one emission, and no blocking callbacks while holding the state monitor. */
private class OneUsePublisher(private var bytes: ByteArray?) : HttpRequest.BodyPublisher {
    private val length = bytes!!.size.toLong()
    private val used = AtomicBoolean()
    private val stopped = AtomicBoolean()
    private val callbacks = AtomicInteger()
    override fun contentLength(): Long = length
    fun stop() { stopped.set(true); synchronized(this) { bytes = null } }
    fun settled(): Boolean = callbacks.get() == 0
    override fun subscribe(subscriber: Flow.Subscriber<in ByteBuffer>) {
        callbacks.incrementAndGet()
        try {
            if (!used.compareAndSet(false, true) || stopped.get()) {
                subscriber.onSubscribe(object : Flow.Subscription { override fun request(n: Long) {}; override fun cancel() {} })
                subscriber.onError(ChatGptAuthHttpException(ChatGptAuthHttpFailure.ALREADY_USED, ChatGptAuthDispatchEvidence.MAY_HAVE_BEEN_SENT))
                return
            }
            val demand = AtomicBoolean()
            subscriber.onSubscribe(object : Flow.Subscription {
                override fun cancel() = stop()
                override fun request(n: Long) {
                    callbacks.incrementAndGet()
                    try {
                        if (!demand.compareAndSet(false, true) || stopped.get()) return
                        if (n <= 0) { stop(); subscriber.onError(IllegalArgumentException("invalid demand")); return }
                        val value = synchronized(this@OneUsePublisher) { bytes.also { bytes = null } } ?: return
                        if (!stopped.get()) subscriber.onNext(ByteBuffer.wrap(value).asReadOnlyBuffer())
                        if (!stopped.get()) subscriber.onComplete()
                    } finally { callbacks.decrementAndGet() }
                }
            })
        } finally { callbacks.decrementAndGet() }
    }
}

/** Trusted module/test seam; production has no injectable factory. */
internal fun newChatGptAuthTransport(
    port: ChatGptAuthWirePort, monotonicNanos: () -> Long, wallNow: () -> Instant,
): ChatGptAuthTransport = AuthTransport(port, monotonicNanos, wallNow)

private class AuthTransport(
    val port: ChatGptAuthWirePort, val clock: () -> Long, val wall: () -> Instant,
) : ChatGptAuthTransport() {
    private val lock = Any()
    private val calls = mutableSetOf<AuthCall>()
    // Logical ownership survives physical client completion until handoff/discard acknowledges.
    // The same eight permits bound this set, including unawaited completed candidates.
    private val pending = mutableSetOf<AuthCall>()
    private var permits = 0
    private val replies = mutableMapOf<AuthCall, ChatGptAuthSafeObject>()
    private var closed = false
    private var shutdownOrigin: Long? = null
    private var shutdownAllowance = 0L
    private val reaper = ScheduledThreadPoolExecutor(1, { task -> Thread(task, "chatgpt-auth-reaper").apply { isDaemon = true } })
        .apply { removeOnCancelPolicy = true; executeExistingDelayedTasksAfterShutdownPolicy = false }
    // Stop callbacks can execute arbitrary vendor code. A bounded owned worker contains a stuck
    // cancellation/termination callback; the timer and caller can still fence and quarantine it.
    private val stopper = ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, ArrayBlockingQueue(8),
        { task -> Thread(task, "chatgpt-auth-stop").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
    fun scheduleStop(call: AuthCall) {
        try { stopper.execute { call.stopAndObserve() } }
        catch (_: RejectedExecutionException) { call.stopSchedulingFailed() }
    }
    init {
        reaper.scheduleWithFixedDelay({
            val snapshot = synchronized(lock) { (calls + pending).toList() }
            snapshot.forEach { it.tick() }
        }, 25, 25, TimeUnit.MILLISECONDS)
    }
    private fun prepare(
        purpose: ChatGptAuthHttpPurpose, operation: ChatGptStoreOperation, binding: ChatGptAuthCodeBinding? = null,
        request: (ChatGptDeadline) -> HttpRequest,
    ): ChatGptAuthHttpCall = authBoundary {
        val httpDeadline = operation.deadline.cap(HTTP_NANOS)
        val call = AuthCall(this, purpose, operation, binding, httpDeadline)
        synchronized(lock) {
            if (closed || (calls + pending).any { it.quarantined }) authFail(ChatGptAuthHttpFailure.UNSETTLED)
            if (calls.size >= 8 || permits >= 8) authFail(ChatGptAuthHttpFailure.CAPACITY)
            calls.add(call); pending.add(call); permits++
        }
        try { call.initialize(request); call }
        catch (e: Exception) { call.preparationFailed(); throw e }
    }
    fun physicalRelease(call: AuthCall) { synchronized(lock) { calls.remove(call) } }
    fun replyRelease(call: AuthCall) { synchronized(lock) { permits--; replies.remove(call); pending.remove(call) } }
    fun registerReply(call: AuthCall, reply: ChatGptAuthSafeObject): Boolean = synchronized(lock) {
        if (closed || !call.ownsPermit()) false else { replies[call] = reply; true }
    }
    override fun prepareDiscovery(operation: ChatGptStoreOperation) = prepare(ChatGptAuthHttpPurpose.DISCOVERY, operation) {
        get(ChatGptPlanOidc.DISCOVERY, operation, it)
    }
    override fun prepareJwks(operation: ChatGptStoreOperation) = prepare(ChatGptAuthHttpPurpose.JWKS, operation) {
        get(ChatGptPlanOidc.JWKS, operation, it)
    }
    private fun get(uri: String, operation: ChatGptStoreOperation, httpDeadline: ChatGptDeadline): HttpRequest =
        HttpRequest.newBuilder(URI(uri)).version(HttpClient.Version.HTTP_1_1)
            .timeout(Duration.ofNanos(authHttpCheck(operation, httpDeadline)))
            .header("Accept", "application/json").GET().build()
    override fun prepareCode(binding: ChatGptAuthCodeBinding, code: ChatGptPlanOAuthAttempt.CallbackResult.Code,
        operation: ChatGptStoreOperation): ChatGptAuthHttpCall {
        if (!isMetadataCodeBinding(binding)) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
        return prepare(ChatGptAuthHttpPurpose.CODE, operation, binding) { binding.claimCode(code, operation, it) }
    }
    override fun prepareRefresh(clientId: String, refreshToken: String, operation: ChatGptStoreOperation) =
        prepare(ChatGptAuthHttpPurpose.REFRESH, operation) {
            if (!clientId.matches(Regex("oaiapp_[A-Za-z0-9_-]{1,249}"))) authFail(ChatGptAuthHttpFailure.INVALID_FORM)
            tokenRequest(encodedForm(listOf("grant_type" to "refresh_token", "client_id" to clientId,
                "refresh_token" to refreshToken, "resource" to "https://api.openai.com/v1"), operation, it), operation, it)
        }
    override fun prepareRevocation(endpoint: ChatGptAuthRevocationEndpoint, logout: ChatGptLocalLogout,
        operation: ChatGptStoreOperation): ChatGptAuthHttpCall {
        if (!isMetadataRevocationEndpoint(endpoint)) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
        return prepare(ChatGptAuthHttpPurpose.REVOCATION, operation) { endpoint.newRevocationRequest(logout, operation, it) }
    }
    override fun shutdown(maxWaitNanos: Long): ChatGptAuthSettlement {
        val start = System.nanoTime()
        val requested = maxWaitNanos.coerceIn(0, CLEANUP_NANOS)
        val limit: Long
        val snapshot = synchronized(lock) {
            if (shutdownOrigin == null) { shutdownOrigin = start; shutdownAllowance = requested }
            val elapsed = start - shutdownOrigin!!
            limit = if (elapsed < 0) 0 else minOf(requested, (shutdownAllowance - elapsed).coerceAtLeast(0))
            closed = true; (calls + pending).toList()
        }
        snapshot.forEach { it.beginCleanup(limit); it.cancel() }
        val retained = synchronized(lock) { replies.values.toList() }
        retained.forEach { when (it) { is TokenReply -> it.discard(); is DocumentReply -> it.discard() } }
        var settled = true
        snapshot.forEach { if (it.cancelAndSettle(maxOf(0, limit - (System.nanoTime() - start))) != ChatGptAuthSettlement.SETTLED) settled = false }
        if (settled) {
            reaper.shutdown(); stopper.shutdown()
            try { stopper.awaitTermination(maxOf(0, limit - (System.nanoTime() - start)), TimeUnit.NANOSECONDS) }
            catch (_: InterruptedException) { Thread.currentThread().interrupt() }
            try { reaper.awaitTermination(maxOf(0, limit - (System.nanoTime() - start)), TimeUnit.NANOSECONDS) }
            catch (_: InterruptedException) { Thread.currentThread().interrupt() }
        }
        return if (settled && reaper.isTerminated && stopper.isTerminated) ChatGptAuthSettlement.SETTLED else ChatGptAuthSettlement.UNSETTLED
    }
}

private class AuthCall(
    private val owner: AuthTransport, override val purpose: ChatGptAuthHttpPurpose,
    private val operation: ChatGptStoreOperation, private var binding: ChatGptAuthCodeBinding?,
    private val httpDeadline: ChatGptDeadline,
) : ChatGptAuthHttpCall() {
    private val lock = java.lang.Object()
    private val ownerThread = Thread.currentThread()
    private var preparing = true
    private var initialized = false
    private var cleanup: ChatGptCleanupWindow? = null
    private var acknowledgedInTime = false
    private var waitsRequested = 0L
    private var lastWaitNanos = 0L
    private var started = false
    private var acquiring = false
    private var sending = false
    private var callbacks = 0
    private var session: ChatGptAuthWireSession? = null
    private var future: CompletableFuture<HttpResponse<ByteArray>>? = null
    private var futureAcknowledged = false
    private var shutdownAcknowledged = false
    private var subscription: Flow.Subscription? = null
    private var subscriptionCancelled = false
    // A rejected subscription whose cancel throws has not acknowledged stopping.
    // Retain bounded identity-only retry ownership; overflow stays quarantined.
    private val unacknowledgedSubscriptions = java.util.IdentityHashMap<Flow.Subscription, Boolean>()
    private var subscriptionOverflow = false
    private var subscriber: BoundedSubscriber? = null
    private var handlerClaimed = false
    private var request: HttpRequest? = null
    private var publisher: OneUsePublisher? = null
    private var response: ByteArray? = null
    private var status = 0
    private var fields: ResponseFields? = null
    private var received: Instant? = null
    private var candidate = false
    private var terminal: ChatGptAuthHttpOutcome? = null
    private var returned = false
    private var handingOff = false
    private var releaseRequested = false
    private var physical = false
    private var stopping = false
    private val permitReleased = AtomicBoolean()
    @Volatile var quarantined = false
        private set
    @Volatile override var dispatchEvidence = ChatGptAuthDispatchEvidence.NOT_SUBMITTED
        private set

    fun initialize(makeRequest: (ChatGptDeadline) -> HttpRequest) {
        try {
            synchronized(lock) { initialized = true }
            sampleTime()
            authHttpCheck(operation, httpDeadline)
            val req = makeRequest(httpDeadline)
            val body = req.bodyPublisher().orElse(null) as? OneUsePublisher
            synchronized(lock) {
                if (terminal != null || remainingLocked() == 0L) { body?.stop(); authFail(ChatGptAuthHttpFailure.CANCELLED) }
                request = req; publisher = body
            }
            ownerCheck()
        } finally { synchronized(lock) { preparing = false; lock.notifyAll() } }
    }
    fun preparationFailed() { synchronized(lock) { preparing = false }; cancel(); settle() }
    // Trusted final capability and atomic fence only. No virtual/callback code under this lock.
    private fun remainingLocked(): Long =
        if (!initialized || operation.fence.isCancelled()) 0L else httpDeadline.remainingNanos()
    private fun sampleTime() {
        synchronized(lock) {
            if (physical && !handingOff && terminal != null) return
            callbacks++
        }
        try { owner.clock() /* owned probe, no time authority */ }
        finally { synchronized(lock) { callbacks--; lock.notifyAll() } }
    }
    private fun ownerCheck() {
        if (Thread.currentThread() !== ownerThread) authFail(ChatGptAuthHttpFailure.INVALID_BINDING)
        sampleTime()
        authHttpCheck(operation, httpDeadline)
        sampleTime()
        synchronized(lock) {
            if (remainingLocked() == 0L) authFail(if (operation.fence.isCancelled()) ChatGptAuthHttpFailure.CANCELLED else ChatGptAuthHttpFailure.DEADLINE)
            if (terminal != null) authFail(ChatGptAuthHttpFailure.CANCELLED)
        }
    }
    override fun start(gate: ChatGptAuthDispatchGate) {
        synchronized(lock) {
            if (started) throw ChatGptAuthHttpException(ChatGptAuthHttpFailure.ALREADY_USED, dispatchEvidence)
            started = true
            if (terminal != null) return
            callbacks++ // owner checks, dispatch gate and vendor acquisition all belong to start
        }
        try {
            ownerCheck()
            synchronized(lock) { if (terminal != null) return; acquiring = true }
            val acquired = try { owner.port.acquire(synchronized(lock) { minOf(5_000_000_000L, remainingLocked()) }) }
            catch (e: Exception) { synchronized(lock) { acquiring = false }; throw e }
            synchronized(lock) { session = acquired; acquiring = false; lock.notifyAll() }
            ownerCheck()
            if (!gate.claim()) { fail(ChatGptAuthHttpFailure.CANCELLED); return }
            ownerCheck()
            val req = synchronized(lock) {
                if (terminal != null || remainingLocked() == 0L) null else {
                    dispatchEvidence = ChatGptAuthDispatchEvidence.MAY_HAVE_BEEN_SENT
                    sending = true
                    request
                }
            } ?: run { fail(ChatGptAuthHttpFailure.DEADLINE); return }
            try {
                val sent = acquired.sendAsync(req, HttpResponse.BodyHandler { info -> callback {
                    synchronized(lock) {
                        if (handlerClaimed) authFail(ChatGptAuthHttpFailure.INVALID_HEADERS)
                        handlerClaimed = true
                    }
                    val checked = responseFields(info, purpose)
                    val checkedStatus = info.statusCode()
                    val body = BoundedSubscriber(checked.length)
                    sampleTime()
                    synchronized(lock) {
                        if (terminal != null || remainingLocked() == 0L) authFail(ChatGptAuthHttpFailure.CANCELLED)
                        fields = checked; status = checkedStatus; subscriber = body
                    }
                    body
                } })
                synchronized(lock) { future = sent }
                sent.whenComplete { result, error ->
                    // Completion hook may execute inline BEFORE sendAsync/start returns.
                    try { callback(allowFenced = true) {
                        // Vendor body access and clocks may block/reenter/throw. Their stack
                        // stays owned until callback finally, including future acknowledgement.
                        val bytes = if (error == null && result != null) result.body() else null
                        sampleTime()
                        synchronized(lock) {
                            if (terminal == null && error == null && bytes != null && subscriber?.completed == true && remainingLocked() > 0) {
                                response = bytes; candidate = true
                            } else if (terminal == null) {
                                terminal = ChatGptAuthHttpOutcome.Failed(if (remainingLocked() == 0L) ChatGptAuthHttpFailure.DEADLINE else ChatGptAuthHttpFailure.TLS_OR_IO)
                            }
                            lock.notifyAll()
                        }
                    } } catch (_: Exception) { fail(ChatGptAuthHttpFailure.TLS_OR_IO) }
                    finally { synchronized(lock) { futureAcknowledged = true; lock.notifyAll() } }
                    stopResources()
                }
                if (synchronized(lock) { terminal != null }) stopResources()
            } finally { synchronized(lock) { sending = false; request = null; lock.notifyAll() } }
        } catch (e: Exception) {
            fail(when (e) {
                is ChatGptAuthHttpException -> e.failure
                is TimeoutException -> ChatGptAuthHttpFailure.DEADLINE
                is CancellationException -> ChatGptAuthHttpFailure.CANCELLED
                else -> ChatGptAuthHttpFailure.TLS_OR_IO
            })
        } finally {
            synchronized(lock) { callbacks--; lock.notifyAll() }
            if (synchronized(lock) { terminal != null || candidate }) stopResources()
        }
    }
    private fun <T> callback(allowFenced: Boolean = false, block: () -> T): T {
        synchronized(lock) { callbacks++ }
        try {
            if (!allowFenced) sampleTime()
            if (!allowFenced && synchronized(lock) { terminal != null || remainingLocked() == 0L })
                authFail(ChatGptAuthHttpFailure.CANCELLED)
            return block()
        } catch (e: ChatGptAuthHttpException) { fail(e.failure); throw e }
        finally { synchronized(lock) { callbacks--; lock.notifyAll() } }
    }
    fun ownsPermit(): Boolean = !permitReleased.get()
    private fun releasePermit() {
        synchronized(lock) {
            releaseRequested = true
            if (callbacks != 0) return
            if (physical && !handingOff && permitReleased.compareAndSet(false, true)) owner.replyRelease(this)
            lock.notifyAll()
        }
    }
    private fun dropBinding() {
        val old = synchronized(lock) { binding.also { binding = null } }
        old?.let(::discardMetadataCodeBinding)
    }
    private fun releaseFailedOutcome() {
        val discard = synchronized(lock) { physical && !handingOff && terminal is ChatGptAuthHttpOutcome.Failed }
        if (discard) { dropBinding(); releasePermit() }
    }
    private fun fail(reason: ChatGptAuthHttpFailure) {
        synchronized(lock) {
            if (terminal == null) { terminal = ChatGptAuthHttpOutcome.Failed(reason); response = null; candidate = false }
            lock.notifyAll()
        }
        stopResources()
    }
    override fun cancel() {
        beginCleanup(CLEANUP_NANOS)
        val previous = synchronized(lock) {
            val value = terminal
            if (value == null) {
                terminal = ChatGptAuthHttpOutcome.Failed(ChatGptAuthHttpFailure.CANCELLED)
                response = null; candidate = false
            }
            lock.notifyAll()
            value
        }
        // A delivered outcome is immutable, but its secret-bearing authority is revocable.
        when (previous) {
            is ChatGptAuthHttpOutcome.Token -> previous.reply.discard()
            is ChatGptAuthHttpOutcome.Document -> previous.reply.discard()
            else -> dropBinding()
        }
        stopResources()
    }
    private fun stopResources() {
        beginCleanup(CLEANUP_NANOS) // first stop owns the original cutoff
        synchronized(lock) { publisher }?.stop() // private, constant-time; no external callback
        val enqueue = synchronized(lock) {
            if (physical || stopping) false else { stopping = true; true }
        }
        if (enqueue) owner.scheduleStop(this)
        releaseFailedOutcome()
    }
    fun stopSchedulingFailed() {
        synchronized(lock) { stopping = false; quarantined = true; lock.notifyAll() }
    }
    fun stopAndObserve() {
        val state = synchronized(lock) { Triple(subscription, future, session) }
        val rejected = synchronized(lock) { unacknowledgedSubscriptions.keys.toList() }
        var stopped = false
        try {
            rejected.forEach { value ->
                try {
                    value.cancel()
                    synchronized(lock) { unacknowledgedSubscriptions.remove(value) }
                } catch (_: Exception) { }
            }
            try {
                state.first?.cancel()
                synchronized(lock) { if (subscription === state.first) subscriptionCancelled = true }
            } catch (_: Exception) { }
            try { if (synchronized(lock) { !candidate }) state.second?.cancel(true) } catch (_: Exception) { }
            try {
                state.third?.shutdownNow()
                synchronized(lock) { if (session === state.third && state.third != null) shutdownAcknowledged = true }
            } catch (_: Exception) { }
            val observable = synchronized(lock) {
                !preparing && !acquiring && !sending && callbacks == 0 && publisher?.settled() != false &&
                    unacknowledgedSubscriptions.isEmpty() && !subscriptionOverflow &&
                    (future == null || futureAcknowledged) && (subscription == null || subscriptionCancelled) &&
                    (session == null || shutdownAcknowledged)
            }
            stopped = observable && (state.third == null || try { state.third!!.awaitTermination(0) } catch (_: Exception) { false })
        } finally {
            var release = false
            synchronized(lock) {
                if (stopped && !physical && !preparing && !acquiring && !sending && callbacks == 0 &&
                    publisher?.settled() != false && unacknowledgedSubscriptions.isEmpty() && !subscriptionOverflow &&
                    session === state.third && future === state.second && subscription === state.first) {
                    acknowledgedInTime = remainingLocked() > 0 && (cleanup?.remainingNanos() ?: 0L) > 0
                    owner.physicalRelease(this)
                    physical = true; quarantined = false
                    session = null; future = null; subscription = null; subscriber?.drop(); subscriber = null; publisher = null; request = null
                    release = true
                }
                stopping = false
                lock.notifyAll()
            }
            if (release) {
                if (synchronized(lock) { terminal is ChatGptAuthHttpOutcome.Failed }) { dropBinding(); releasePermit() }
            }
        }
    }
    private fun logicalSettledLocked(): Boolean =
        !handingOff && callbacks == 0 && ((terminal !is ChatGptAuthHttpOutcome.Token && terminal !is ChatGptAuthHttpOutcome.Document) || permitReleased.get())
    fun beginCleanup(maxWait: Long) = synchronized(lock) {
        if (cleanup == null) cleanup = ChatGptCleanupWindow(if (initialized) httpDeadline else null, maxWait)
    }
    private fun settle(includeHandoff: Boolean = false, maxWait: Long = CLEANUP_NANOS): Boolean {
        beginCleanup(maxWait)
        val invocation = ChatGptCleanupWindow(httpDeadline, maxWait)
        while (true) {
            // Independent of reaper progress, including a blocked reaper probe.
            stopResources()
            synchronized(lock) {
                if (physical && !stopping && (!includeHandoff || logicalSettledLocked())) return true
                val wait = minOf(cleanup!!.remainingNanos(), httpDeadline.remainingNanos(), invocation.remainingNanos(), 25_000_000L)
                if (wait <= 0L) return false
                waitsRequested++; lastWaitNanos = wait
                TimeUnit.NANOSECONDS.timedWait(lock, wait)
            }
        }
    }
    override fun cancelAndSettle(maxWaitNanos: Long): ChatGptAuthSettlement {
        beginCleanup(maxWaitNanos) // before cancel: a first zero stays zero
        cancel()
        if (settle(includeHandoff = true, maxWait = maxWaitNanos)) { dropBinding(); releasePermit(); return ChatGptAuthSettlement.SETTLED }
        quarantined = true
        return ChatGptAuthSettlement.UNSETTLED
    }
    fun tick() {
        try {
            if (synchronized(lock) { initialized && !preparing && (!physical || terminal == null) }) sampleTime()
            val expired = synchronized(lock) { initialized && !preparing && terminal == null && remainingLocked() == 0L }
            if (expired) fail(if (operation.fence.isCancelled()) ChatGptAuthHttpFailure.CANCELLED else ChatGptAuthHttpFailure.DEADLINE)
            val failed = synchronized(lock) { terminal is ChatGptAuthHttpOutcome.Failed }
            if (failed || synchronized(lock) { candidate }) {
                stopResources()
                if (synchronized(lock) { physical && !stopping }) {
                    if (failed) { dropBinding(); releasePermit() }
                } else if (failed) quarantined = true
            }
        } catch (_: Exception) { fail(ChatGptAuthHttpFailure.DEPENDENCY_FAILED); quarantined = true }
    }
    override fun await(): ChatGptAuthHttpOutcome {
        synchronized(lock) {
            if (returned) return ChatGptAuthHttpOutcome.Failed(ChatGptAuthHttpFailure.ALREADY_USED)
            returned = true; handingOff = true
        }
        try { return awaitOutcome() }
        finally {
            synchronized(lock) { handingOff = false; lock.notifyAll() }
            releaseFailedOutcome()
            if (synchronized(lock) { releaseRequested }) releasePermit()
        }
    }
    private fun awaitOutcome(): ChatGptAuthHttpOutcome {
        var preparedReply: ChatGptAuthSafeObject? = null
        try {
            while (true) {
                if (synchronized(lock) { terminal != null }) break
                ownerCheck()
                if (synchronized(lock) { candidate }) break
                synchronized(lock) {
                    val wait = minOf(25_000_000L, remainingLocked())
                    if (wait > 0 && terminal == null && !candidate) TimeUnit.NANOSECONDS.timedWait(lock, wait)
                }
            }
            if (!settle()) {
                quarantined = true; fail(ChatGptAuthHttpFailure.UNSETTLED)
                return synchronized(lock) { terminal!! }
            }
            synchronized(lock) { terminal }?.let { releasePermit(); return it }
            ownerCheck()
            if (synchronized(lock) { !acknowledgedInTime }) authFail(ChatGptAuthHttpFailure.UNSETTLED)
            val body = synchronized(lock) { response.also { response = null } } ?: authFail(ChatGptAuthHttpFailure.INVALID_BODY)
            val result = if (status != 200) {
                if (status in 300..399) authFail(ChatGptAuthHttpFailure.INVALID_STATUS)
                val json = ChatGptAuthJson.parse(body, operation)
                val error = if (status in listOf(400, 401) && purpose in listOf(ChatGptAuthHttpPurpose.CODE, ChatGptAuthHttpPurpose.REFRESH)) {
                    val value = json.member("error")
                    if (value?.isString() == true) ChatGptAuthOAuthError.entries.firstOrNull { it.name.lowercase(Locale.ROOT) == value.string() } else null
                } else null
                releasePermit(); ChatGptAuthHttpOutcome.Rejected(status, error)
            } else when (purpose) {
                ChatGptAuthHttpPurpose.REVOCATION -> {
                    if (body.isNotEmpty()) authFail(ChatGptAuthHttpFailure.INVALID_BODY)
                    releasePermit(); ChatGptAuthHttpOutcome.Revoked()
                }
                ChatGptAuthHttpPurpose.DISCOVERY, ChatGptAuthHttpPurpose.JWKS -> {
                    ChatGptAuthJson.parse(body, operation)
                    ChatGptAuthHttpOutcome.Document(DocumentReply(body, purpose, operation, fields!!.policy, ::releasePermit))
                }
                else -> {
                    ChatGptAuthJson.parse(body, operation)
                    ChatGptAuthHttpOutcome.Token(TokenReply(body, received!!, purpose, binding, operation, ::releasePermit))
                }
            }
            val reply = when (result) {
                is ChatGptAuthHttpOutcome.Token -> result.reply
                is ChatGptAuthHttpOutcome.Document -> result.reply
                else -> null
            }
            preparedReply = reply
            if (reply == null) dropBinding()
            if (reply != null && !owner.registerReply(this, reply)) {
                when (result) { is ChatGptAuthHttpOutcome.Token -> result.reply.discard(); is ChatGptAuthHttpOutcome.Document -> result.reply.discard(); else -> {} }
                authFail(ChatGptAuthHttpFailure.CANCELLED)
            }
            ownerCheck()
            synchronized(lock) {
                if (terminal == null && remainingLocked() > 0) { terminal = result; binding = null; preparedReply = null; return result }
            }
            when (result) { is ChatGptAuthHttpOutcome.Token -> result.reply.discard(); is ChatGptAuthHttpOutcome.Document -> result.reply.discard(); else -> {} }
        } catch (e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
            fail(when (e) {
                is ChatGptAuthHttpException -> e.failure
                is CancellationException, is InterruptedException -> ChatGptAuthHttpFailure.CANCELLED
                is TimeoutException -> ChatGptAuthHttpFailure.DEADLINE
                else -> ChatGptAuthHttpFailure.INVALID_BODY
            })
        } finally {
            // Registration and the final owner check can race shutdown/cancel. Until the
            // terminal handoff wins, this stack still owns and must discard its private reply.
            when (val reply = preparedReply) {
                is TokenReply -> reply.discard()
                is DocumentReply -> reply.discard()
            }
        }
        if (!settle()) quarantined = true else releasePermit()
        dropBinding()
        return synchronized(lock) { terminal!! }
    }
    private inner class BoundedSubscriber(private val expected: Long?) : HttpResponse.BodySubscriber<ByteArray> {
        private val body = CompletableFuture<ByteArray>()
        private var storage: ByteArray? = null
        private var size = 0
        private val copying = AtomicBoolean()
        var completed = false
            private set
        override fun getBody(): CompletionStage<ByteArray> = body
        fun drop() { storage = null }
        override fun onSubscribe(value: Flow.Subscription) {
            try { callback(allowFenced = true) {
                var cancelAttempted = false
                fun cancelIncoming() {
                    cancelAttempted = true
                    try { value.cancel() }
                    catch (e: Exception) {
                        synchronized(lock) {
                            if (subscription !== value) {
                                if (unacknowledgedSubscriptions.size < 8 || unacknowledgedSubscriptions.containsKey(value))
                                    unacknowledgedSubscriptions[value] = true
                                else subscriptionOverflow = true
                            }
                            quarantined = true
                        }
                        throw e
                    }
                }
                try {
                    // Fenced arrivals must still cancel, even if the clock cannot return.
                    // The outer callback owns observation, demand and cancellation alike.
                    if (synchronized(lock) { terminal == null && subscription == null && subscriber === this }) sampleTime()
                    val accept = synchronized(lock) {
                        if (terminal != null || remainingLocked() == 0L || subscription != null || subscriber !== this) false
                        else { subscription = value; subscriptionCancelled = false; true }
                    }
                    if (!accept) {
                        fail(if (synchronized(lock) { remainingLocked() == 0L }) ChatGptAuthHttpFailure.DEADLINE else ChatGptAuthHttpFailure.INVALID_BODY)
                        cancelIncoming()
                    } else {
                        sampleTime() // owned post-install probe; final demand uses current trusted time
                        // Demand linearizes against cancel under the call monitor; the
                        // foreign request itself runs outside it, with ownership retained.
                        val demand = synchronized(lock) {
                            terminal == null && remainingLocked() > 0 && subscriber === this &&
                                subscription === value && !subscriptionCancelled
                        }
                        if (demand) value.request(1) else cancelIncoming()
                    }
                } catch (e: Exception) {
                    // Record the first failure before cancel can throw or reenter. Do not
                    // acknowledge the callback until this late subscription has been stopped.
                    fail(if (e is ChatGptAuthHttpException) e.failure else ChatGptAuthHttpFailure.INVALID_BODY)
                    if (!cancelAttempted) try { cancelIncoming() } catch (_: Exception) { }
                }
            } } catch (_: Exception) { fail(ChatGptAuthHttpFailure.INVALID_BODY) }
        }
        override fun onNext(items: List<ByteBuffer>) {
            try { callback {
                if (!copying.compareAndSet(false, true)) authFail(ChatGptAuthHttpFailure.INVALID_BODY)
                try {
                    synchronized(lock) {
                        if (completed || terminal != null || subscription == null) authFail(ChatGptAuthHttpFailure.INVALID_BODY)
                    }
                    var batch = 0L
                    for (buffer in items) {
                        batch += buffer.remaining().toLong()
                        if (batch > ENTITY_LIMIT - size) authFail(ChatGptAuthHttpFailure.BODY_LIMIT)
                    }
                    if (expected != null && size + batch > expected) authFail(ChatGptAuthHttpFailure.INVALID_BODY)
                    fun live() {
                        sampleTime()
                        synchronized(lock) {
                            if (terminal != null || remainingLocked() == 0L) authFail(ChatGptAuthHttpFailure.CANCELLED)
                        }
                    }
                    live()
                    // Entire batch admitted before the first allocation/copy. Foreign buffer/list
                    // methods run outside the owner monitor; callback acknowledgement retains capacity.
                    if (batch > 0 && storage == null) storage = ByteArray(ENTITY_LIMIT)
                    for (buffer in items) {
                        live()
                        val n = buffer.remaining()
                        if (n > 0) buffer.get(storage!!, size, n)
                        size += n
                    }
                    live()
                } finally { copying.set(false) }
                val next = synchronized(lock) { if (terminal == null && remainingLocked() > 0 && subscriber === this) subscription else null }
                next?.request(1)
            } } catch (e: Exception) {
                fail(if (e is ChatGptAuthHttpException) e.failure else ChatGptAuthHttpFailure.INVALID_BODY)
                body.completeExceptionally(ChatGptAuthHttpException(ChatGptAuthHttpFailure.INVALID_BODY, dispatchEvidence))
            }
        }
        override fun onError(error: Throwable) {
            try { callback(allowFenced = true) { fail(ChatGptAuthHttpFailure.TLS_OR_IO); body.completeExceptionally(
                ChatGptAuthHttpException(ChatGptAuthHttpFailure.TLS_OR_IO, dispatchEvidence)) } } catch (_: Exception) { }
        }
        override fun onComplete() {
            try { callback {
                val reception = owner.wall()
                sampleTime()
                val bytes = synchronized(lock) {
                    if (completed || copying.get() || terminal != null || remainingLocked() == 0L || subscription == null || (expected != null && expected != size.toLong()))
                        authFail(ChatGptAuthHttpFailure.INVALID_BODY)
                    completed = true
                    received = reception
                    (storage?.copyOf(size) ?: ByteArray(0)).also { storage = null }
                }
                body.complete(bytes)
            } } catch (e: Exception) {
                fail(if (e is ChatGptAuthHttpException) e.failure else ChatGptAuthHttpFailure.INVALID_BODY)
                body.completeExceptionally(ChatGptAuthHttpException(ChatGptAuthHttpFailure.INVALID_BODY, dispatchEvidence))
            }
        }
    }
}

/** Compiled but never constructed by the denied factory or pure test lane. */
private class JdkAuthWirePort : ChatGptAuthWirePort() {
    override fun acquire(connectTimeoutNanos: Long): ChatGptAuthWireSession {
        val executor = ThreadPoolExecutor(0, 2, 30, TimeUnit.SECONDS, ArrayBlockingQueue(64),
            { task -> Thread(task, "chatgpt-auth-http").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
        try {
            val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(null as java.security.KeyStore?) }
            val tls = SSLContext.getInstance("TLS").apply { init(emptyArray<KeyManager>(), trust.trustManagers, null) }
            val parameters = SSLParameters().apply {
                endpointIdentificationAlgorithm = "HTTPS"; protocols = arrayOf("TLSv1.3", "TLSv1.2")
            }
            val direct = object : ProxySelector() {
                override fun select(uri: URI): List<Proxy> = listOf(Proxy.NO_PROXY)
                override fun connectFailed(uri: URI, address: SocketAddress, error: java.io.IOException) { }
            }
            val client = HttpClient.newBuilder().executor(executor).sslContext(tls).sslParameters(parameters)
                .proxy(direct).version(HttpClient.Version.HTTP_1_1).followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofNanos(connectTimeoutNanos)).build()
            return object : ChatGptAuthWireSession() {
                override fun sendAsync(request: HttpRequest, handler: HttpResponse.BodyHandler<ByteArray>) = client.sendAsync(request, handler)
                override fun shutdownNow() { client.shutdownNow() }
                override fun awaitTermination(maxWaitNanos: Long): Boolean {
                    val start = System.nanoTime()
                    val limit = maxWaitNanos.coerceAtLeast(0)
                    if (!client.awaitTermination(Duration.ofNanos(limit))) return false
                    executor.shutdownNow()
                    executor.awaitTermination(maxOf(0, limit - (System.nanoTime() - start)), TimeUnit.NANOSECONDS)
                    return client.isTerminated && executor.isTerminated
                }
            }
        } catch (_: Exception) {
            executor.shutdownNow()
            // Retain partial acquisition ownership. A throwing vendor builder gives no client
            // termination receipt, so this session stays quarantined even if its executor stops.
            return object : ChatGptAuthWireSession() {
                override fun sendAsync(request: HttpRequest, handler: HttpResponse.BodyHandler<ByteArray>): CompletableFuture<HttpResponse<ByteArray>> =
                    CompletableFuture.failedFuture(ChatGptAuthHttpException(ChatGptAuthHttpFailure.TLS_OR_IO, ChatGptAuthDispatchEvidence.NOT_SUBMITTED))
                override fun shutdownNow() { executor.shutdownNow() }
                override fun awaitTermination(maxWaitNanos: Long): Boolean {
                    executor.awaitTermination(maxWaitNanos.coerceAtLeast(0), TimeUnit.NANOSECONDS)
                    return false
                }
            }
        }
    }
}
