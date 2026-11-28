package decompengine.chatgpt

import java.net.URI
import java.net.URLDecoder
import java.net.http.*
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import java.time.Instant
import java.util.*
import java.util.concurrent.*
import java.util.concurrent.atomic.*
import javax.net.ssl.SSLSession
import kotlin.test.*

/** All runtime wire behavior in this lane is scripted; no HttpClient, TLS, socket or listener. */
internal class AuthTestClock(initial: Long = 1_000_000L) {
    val nanos = AtomicLong(initial)
    val authority = ChatGptDeadlineClock.controlled(initial)
    val now = AtomicReference(Instant.parse("2026-11-05T12:00:00Z"))
    fun operation(cancelled: () -> Boolean = { false }, seconds: Long = 30) =
        ChatGptStoreOperation.createControlled(Duration.ofSeconds(seconds), cancelled, authority, nanos::get)
    fun advance(seconds: Long) { authority.advanceNanos(seconds * 1_000_000_000L); nanos.addAndGet(seconds * 1_000_000_000L) }
}
internal fun authGate(claim: () -> Boolean = { true }) = object : ChatGptAuthDispatchGate() { override fun claim() = claim() }
internal class AuthScript(
    val bytes: ByteArray = "{}".toByteArray(), val status: Int = 200,
    val headers: Map<String, List<String>> = mapOf("Content-Type" to listOf("application/json")),
    val action: ((AuthScriptExchange) -> Unit)? = null,
)
internal class AuthScriptExchange(
    val request: HttpRequest, val subscriber: HttpResponse.BodySubscriber<ByteArray>,
    val future: CompletableFuture<HttpResponse<ByteArray>>, val script: AuthScript,
) {
    val demands = AtomicInteger()
    val cancellations = AtomicInteger()
    private val subscription = object : Flow.Subscription {
        override fun request(n: Long) { demands.incrementAndGet() }
        override fun cancel() { cancellations.incrementAndGet() }
    }
    fun subscribe() { subscriber.onSubscribe(subscription) }
    fun body(vararg buffers: ByteBuffer) { subscriber.onNext(buffers.toList()) }
    fun complete() { subscriber.onComplete() }
    fun deliver() { subscribe(); if (script.bytes.isNotEmpty()) body(ByteBuffer.wrap(script.bytes)); complete() }
}
internal class AuthScriptPort : ChatGptAuthWirePort() {
    val acquired = AtomicInteger()
    val submitted = AtomicInteger()
    val stopped = AtomicInteger()
    val scripts = LinkedBlockingQueue<AuthScript>()
    val exchanges = CopyOnWriteArrayList<AuthScriptExchange>()
    val requests = CopyOnWriteArrayList<HttpRequest>()
    val connect = CopyOnWriteArrayList<Long>()
    val settled = AtomicBoolean(true)
    var acquireHook: (() -> Unit)? = null
    var sendHook: (() -> Unit)? = null
    var shutdownHook: (() -> Unit)? = null
    override fun acquire(connectTimeoutNanos: Long): ChatGptAuthWireSession {
        acquired.incrementAndGet(); connect.add(connectTimeoutNanos); acquireHook?.invoke()
        return object : ChatGptAuthWireSession() {
            override fun sendAsync(request: HttpRequest, handler: HttpResponse.BodyHandler<ByteArray>): CompletableFuture<HttpResponse<ByteArray>> {
                submitted.incrementAndGet(); requests.add(request); sendHook?.invoke()
                val script = scripts.poll() ?: error("missing scripted response")
                val headers = HttpHeaders.of(script.headers) { _, _ -> true }
                val subscriber = handler.apply(object : HttpResponse.ResponseInfo {
                    override fun statusCode() = script.status
                    override fun headers() = headers
                    override fun version() = HttpClient.Version.HTTP_1_1
                })
                val future = CompletableFuture<HttpResponse<ByteArray>>()
                subscriber.body.whenComplete { body, error ->
                    if (error != null) future.completeExceptionally(error)
                    else future.complete(object : HttpResponse<ByteArray> {
                        override fun statusCode() = script.status
                        override fun request() = request
                        override fun previousResponse(): Optional<HttpResponse<ByteArray>> = Optional.empty()
                        override fun headers() = headers
                        override fun body() = body
                        override fun sslSession(): Optional<SSLSession> = Optional.empty()
                        override fun uri(): URI = request.uri()
                        override fun version() = HttpClient.Version.HTTP_1_1
                    })
                }
                val exchange = AuthScriptExchange(request, subscriber, future, script)
                exchanges.add(exchange)
                if (script.action != null) script.action.invoke(exchange) else exchange.deliver()
                return future
            }
            override fun shutdownNow() { stopped.incrementAndGet(); shutdownHook?.invoke() }
            override fun awaitTermination(maxWaitNanos: Long) = settled.get()
        }
    }
}
internal class AuthTestRig(val clock: AuthTestClock = AuthTestClock(), val port: AuthScriptPort = AuthScriptPort()) : AutoCloseable {
    val transport = newChatGptAuthTransport(port, clock.nanos::get, clock.now::get)
    val metadata = newChatGptAuthMetadata(transport, clock.authority, clock.nanos::get, clock.now::get)
    override fun close() {
        port.settled.set(true); port.shutdownHook = null
        assertEquals(ChatGptAuthSettlement.SETTLED, metadata.shutdown(250_000_000L), "metadata cleanup")
        authEventually { transport.shutdown(250_000_000L) == ChatGptAuthSettlement.SETTLED }
    }
    fun document(bytes: ByteArray, controls: List<String>? = null, ages: List<String>? = null): AuthScript {
        val headers = linkedMapOf("Content-Type" to listOf("application/json"))
        if (controls != null) headers["Cache-Control"] = controls
        if (ages != null) headers["Age"] = ages
        return AuthScript(bytes, headers = headers)
    }
}
internal fun authDiscovery(endpoint: String? = null): ByteArray = ("""{"issuer":"${ChatGptPlanOidc.ISSUER}","authorization_endpoint":"${ChatGptPlanOidc.AUTHORIZATION}","token_endpoint":"${ChatGptPlanOidc.TOKEN}","jwks_uri":"${ChatGptPlanOidc.JWKS}"""" +
    (endpoint?.let { ",\"revocation_endpoint\":\"$it\"" } ?: "") + "}").toByteArray()

internal fun authSnapshot(client: String? = "oaiapp_test", subject: String? = "test-subject") = object : ChatGptAuthorizationSnapshot() {
    override val attemptId = UUID.randomUUID()
    override val expectedAuthEpoch = 0L
    override val expectedSubject = subject
    override val expectedClientId = client
    override fun oauthRegistration(): ChatGptPlanOAuthRegistration = if (client == null)
        ChatGptPlanOAuthRegistration.New("urn:uuid:11111111-1111-1111-1111-111111111111", "test")
    else ChatGptPlanOAuthRegistration.Returning(client, "urn:uuid:11111111-1111-1111-1111-111111111111")
}
internal class AuthBound(val binding: ChatGptAuthCodeBinding, val code: ChatGptPlanOAuthAttempt.CallbackResult.Code)
internal fun authBound(rig: AuthTestRig, snapshot: ChatGptAuthorizationSnapshot = authSnapshot(),
    cancelled: () -> Boolean = { false }): AuthBound {
    val seed = AtomicInteger()
    val binding = rig.metadata.bindAuthorization(snapshot, ChatGptPlanOAuthRedirect.of(42321),
        ChatGptPlanOAuthClock(rig.clock.nanos::get), ChatGptPlanOAuthRandom { bytes -> bytes.fill(seed.incrementAndGet().toByte()) },
        ChatGptPlanOAuthCancellation(cancelled), rig.clock.operation())
    val fields = URI(binding.authorizationRequest().uri).rawQuery.split('&').associate {
        val pair = it.split('=', limit = 2); pair[0] to URLDecoder.decode(pair[1], Charsets.UTF_8)
    }
    val result = binding.receiveCode(object : ChatGptAuthCodeReceiver() {
        override fun await(attempt: ChatGptPlanOAuthAttempt) = attempt.consumeCallback("GET", "127.0.0.1:42321",
            "/auth/callback?state=${fields.getValue("state")}&code=synthetic-code&client_id=oaiapp_test")
    })
    assertTrue(result is ChatGptPlanOAuthAttempt.CallbackResult.Code, "real callback code")
    return AuthBound(binding, result)
}
internal class AuthSigningKey(val kid: String = "test-key") {
    private val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private fun b64(bytes: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    private fun uint(value: java.math.BigInteger) = value.toByteArray().let { if (it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
    fun keyJson(id: String = kid): String {
        val key = pair.public as RSAPublicKey
        return """{"kid":"$id","kty":"RSA","alg":"RS256","use":"sig","n":"${b64(uint(key.modulus))}","e":"${b64(uint(key.publicExponent))}"}"""
    }
    fun jwks(): ByteArray = ("{\"keys\":[${keyJson()}]}").toByteArray()
    fun response(code: ChatGptPlanOAuthAttempt.CallbackResult.Code, now: Instant, exp: Long = now.epochSecond + 3600,
        id: String = kid, nonce: String = code.nonceForValidation, subject: String = "test-subject", client: String = code.issuedClientId,
        badSignature: Boolean = false): ByteArray {
        val claims = """{"iss":"${ChatGptPlanOidc.ISSUER}","aud":"$client","sub":"$subject","nonce":"$nonce","iat":${now.epochSecond},"exp":$exp}"""
        val header = """{"alg":"RS256","kid":"$id"}"""
        val input = b64(header.toByteArray()) + "." + b64(claims.toByteArray())
        val sig = Signature.getInstance("SHA256withRSA").run { initSign(pair.private); update(input.toByteArray()); sign() }
        if (badSignature) sig[0] = (sig[0].toInt() xor 1).toByte()
        val token = input + "." + b64(sig)
        return """{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","id_token":"$token","token_type":"Bearer","expires_in":3600,"scope":"openid"}""".toByteArray()
    }
}
internal fun authToken(rig: AuthTestRig, bound: AuthBound, key: AuthSigningKey, operation: ChatGptStoreOperation,
    response: ByteArray = key.response(bound.code, rig.clock.now.get())): ChatGptAuthTokenReply {
    rig.port.scripts.add(AuthScript(response))
    val call = rig.transport.prepareCode(bound.binding, bound.code, operation)
    call.start(authGate())
    val outcome = call.await()
    assertTrue(outcome is ChatGptAuthHttpOutcome.Token, "scripted token outcome")
    return outcome.reply
}
internal fun authAwait(latch: CountDownLatch) { assertTrue(latch.await(3, TimeUnit.SECONDS), "bounded fixture barrier") }
internal fun authJoin(thread: Thread) { thread.join(3000); assertFalse(thread.isAlive, "fixture thread joined") }
internal fun authFailure(reason: ChatGptAuthHttpFailure? = null, block: () -> Unit): ChatGptAuthHttpException {
    val e = assertFailsWith<ChatGptAuthHttpException>(block = block)
    if (reason != null) assertEquals(reason, e.failure)
    assertNull(e.cause); assertTrue(e.suppressed.isEmpty())
    return e
}

// Test-only read observations for deterministic barriers. These never mint authority or alter state.
internal fun awaitMetadataWaiters(metadata: ChatGptAuthMetadata, count: Int) = observeMetadata(metadata) { slot ->
    val fetch = slot.javaClass.getDeclaredField("fetch").apply { isAccessible = true }.get(slot)
    fetch != null && fetch.javaClass.getDeclaredField("waiters").apply { isAccessible = true }.getInt(fetch) == count
}
internal fun awaitMetadataIdle(metadata: ChatGptAuthMetadata) = observeMetadata(metadata) { slot ->
    slot.javaClass.getDeclaredField("fetch").apply { isAccessible = true }.get(slot) == null
}
private fun observeMetadata(metadata: ChatGptAuthMetadata, predicate: (Any) -> Boolean) {
    val lock = metadata.javaClass.getDeclaredField("lock").apply { isAccessible = true }.get(metadata)
    val slot = metadata.javaClass.getDeclaredField("keysSlot").apply { isAccessible = true }.get(metadata)
    val start = System.nanoTime()
    while (System.nanoTime() - start < 3_000_000_000L) {
        if (synchronized(lock) { predicate(slot) }) return
        Thread.sleep(1)
    }
    fail("bounded metadata observation")
}

internal fun authEventually(predicate: () -> Boolean) {
    val start = System.nanoTime()
    while (System.nanoTime() - start < 3_000_000_000L) {
        if (predicate()) return
        Thread.sleep(2)
    }
    fail("bounded fixture reaping acknowledgement")
}

// Read-only lifecycle observations. Only counts/booleans leave these helpers, never private data.
internal fun authTransportCount(transport: ChatGptAuthTransport, field: String): Int {
    val lock = transport.javaClass.getDeclaredField("lock").apply { isAccessible = true }.get(transport)
    return synchronized(lock) {
        val value = transport.javaClass.getDeclaredField(field).apply { isAccessible = true }.get(transport)
        when (value) { is Int -> value; is Map<*, *> -> value.size; is Collection<*> -> value.size; else -> error("fixture count type") }
    }
}
internal fun authCallHasPrivateCandidate(call: ChatGptAuthHttpCall): Boolean {
    val lock = call.javaClass.getDeclaredField("lock").apply { isAccessible = true }.get(call)
    return synchronized(lock) {
        listOf("response", "binding").any { call.javaClass.getDeclaredField(it).apply { isAccessible = true }.get(call) != null }
    }
}
internal fun authMetadataClosed(metadata: ChatGptAuthMetadata): Boolean {
    val lock = metadata.javaClass.getDeclaredField("lock").apply { isAccessible = true }.get(metadata)
    return synchronized(lock) { metadata.javaClass.getDeclaredField("closed").apply { isAccessible = true }.getBoolean(metadata) }
}
internal fun authMetadataValidations(metadata: ChatGptAuthMetadata): Int {
    val lock = metadata.javaClass.getDeclaredField("lock").apply { isAccessible = true }.get(metadata)
    return synchronized(lock) { metadata.javaClass.getDeclaredField("validations").apply { isAccessible = true }.getInt(metadata) }
}

/** Explicit scripted authority for migrated A2 setup; no injected callback mints a clock. */
internal class AuthControlledTicks(initial: Long = 0L) {
    val authority = ChatGptDeadlineClock.controlled(initial)
    fun get(): Long = authority.readNanos()
    fun addAndGet(delta: Long): Long { authority.advanceNanos(delta); return get() }
    fun set(value: Long) { authority.advanceNanos(value - get()) }
}

internal fun authCallWaitCount(call: ChatGptAuthHttpCall): Long = authCallNumber(call, "waitsRequested")
internal fun authCallLastWait(call: ChatGptAuthHttpCall): Long = authCallNumber(call, "lastWaitNanos")
private fun authCallNumber(call: ChatGptAuthHttpCall, field: String): Long {
    val lock = call.javaClass.getDeclaredField("lock").apply { isAccessible = true }.get(call)
    return synchronized(lock) { call.javaClass.getDeclaredField(field).apply { isAccessible = true }.getLong(call) }
}
