package decompengine.acp

import decompengine.agent.AgentCancellation
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.builtin.provider.parseProviderObject
import decompengine.builtin.provider.boundedProviderJson
import decompengine.builtin.provider.writeProviderValue
import kotlinx.serialization.json.*
import java.io.IOException
import java.io.ByteArrayInputStream
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.Socket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLParameters
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager
import java.time.Duration
import java.util.Collections
import java.util.IdentityHashMap
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionStage
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Flow
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** Fixed diagnostics deliberately exclude upstream bodies, URLs, headers, and exception causes. */
internal class AcpProviderBrokerFailure(val kind: AcpProviderTerminalKind) : IOException("ACP provider broker: ${kind.name}")

/** Host-only material. Neither this object nor its values belong in agent configuration/evidence. */
internal class AcpProviderCredentialMaterial private constructor(
    internal val accessToken: String,
    internal val accountId: String,
) {
    override fun toString(): String = "AcpProviderCredentialMaterial(<redacted>)"

    companion object {
        /** A future operator-owned resolver supplies already-read material; this module reads no files. */
        fun cachedChatGpt(accessToken: String, accountId: String): AcpProviderCredentialMaterial {
            require(accessToken.length in 1..8192 && accessToken.all { it.code in 33..126 }) {
                "cached provider access token is missing or malformed"
            }
            require(accountId.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,255}"))) {
                "cached provider account identity is missing or malformed"
            }
            return AcpProviderCredentialMaterial(accessToken, accountId)
        }
    }
}

internal enum class AcpProviderBrokerCleanup { NOT_ATTEMPTED, VERIFIED, UNVERIFIED }
internal data class AcpProviderAdmissionDenial(val sequence: Long, val terminal: AcpProviderTerminalKind)

internal data class AcpProviderBrokerRequestEvidence(
    val sequence: Long,
    val sessionSha256: String,
    val turnSha256: String,
    val admittedBodySha256: String,
    val wireBodySha256: String,
    val wireRequestBytes: Int,
    val responseBytes: Long,
    val responseSha256: String,
    val inputTokens: Int?,
    val outputTokens: Int?,
    val terminal: AcpProviderTerminalKind,
    val admittedOutputTokens: Int = 0,
)

/** Building-block evidence, never an ACP invocation receipt or a validation/release approval. */
internal class AcpProviderBrokerSnapshot(
    val policySha256: String,
    val invocationBindingSha256: String,
    val requestBindingSha256: String,
    val revoked: Boolean,
    val cleanup: AcpProviderBrokerCleanup,
    val wireRequestBytes: Long,
    val responseBytes: Long,
    val outputTokens: Long,
    val admissionDenial: AcpProviderAdmissionDenial?,
    requests: List<AcpProviderBrokerRequestEvidence>,
    val credentialFreeFixture: Boolean = false,
) {
    val requests: List<AcpProviderBrokerRequestEvidence> = Collections.unmodifiableList(ArrayList(requests))
    val adapterQualified: Boolean = false
    val providerCostCancellationProven: Boolean = false
}

/** Bytes consumed by the private concrete backend, never rendered as a diagnostic. */
internal class AcpProviderBackendRequest(
    val endpoint: URI,
    body: ByteArray,
    internal val credentials: AcpProviderCredentialMaterial,
    val timeout: Duration,
) {
    private val content = body.copyOf()
    val body: ByteArray get() = content.copyOf()
    override fun toString(): String = "AcpProviderBackendRequest(<redacted>)"
}

/** Internal deterministic control seam; production issuance always selects the concrete JDK backend. */
internal interface AcpProviderBrokerTestBackend {
    fun start(request: AcpProviderBackendRequest, receiver: AcpProviderBackendReceiver): AcpProviderBackendRequestOwner
    fun closeWithin(timeout: Duration): Boolean
}

internal interface AcpProviderBackendRequestOwner { fun cancel() }

internal interface AcpProviderBackendReceiver {
    fun headers(status: Int, headers: Map<String, List<String>>)
    fun subscribe(subscription: Flow.Subscription)
    fun bytes(buffers: List<ByteBuffer>)
    fun complete()
    fun failed()
}

/**
 * Invocation-bound host owner for the closed, still-unqualified Responses adapter. This checkpoint
 * is deliberately not reachable from AcpHarnessFactory. No constructor accepts a public launcher,
 * network callback, client, or secret resolver. Protected qualification is a separate internal path.
 */
internal class AcpProviderBroker private constructor(
    val policy: AcpProviderTransportPolicy.Enabled,
    private val requestBinding: AgentExecutionRequestBinding,
    private val cancellation: AgentCancellation,
    private val credentials: AcpProviderCredentialMaterial,
    remaining: Duration,
    private val maximumInvocationOutputTokens: Int,
    private val maximumInvocationInputTokens: Long?,
    private val backend: AcpProviderBrokerTestBackend,
) : AutoCloseable {
    // Validate before any lifecycle executor, capability, or backend dispatch can be created.
    // Kotlin's public synthetic marker constructor must not permit a fixture backend substitute.
    private val fixtureBackendAdmission: Unit = if (policy is AcpProviderTransportPolicy.CredentialFreeFixture) {
        require(backend is JdkAcpProviderBackend && backend.ownsFixtureAuthority(policy)) {
            "fixture broker authority is unavailable"
        }
    } else Unit
    private val lock = ReentrantLock()
    private val changed = lock.newCondition()
    private val capability = ByteArray(PROVIDER_INVOCATION_CAPABILITY_BYTES).also(SecureRandom()::nextBytes)
    private val startedNanos = System.nanoTime()
    private val allowedNanos = minOf(remaining.toNanos(), policy.bounds.overallTimeout.toNanos())
    private val invocationNonce = ByteArray(32).also(SecureRandom()::nextBytes)
    val invocationBindingSha256: String = brokerDigest(
        policy.descriptorSha256.toByteArray() + requestBinding.requestSha256.toByteArray() + invocationNonce,
    )
    private var sessionSha256: String? = null
    private var turnSha256: String? = null
    private var nextSequence = 1L
    private var active: AcpProviderBrokerExchange? = null
    private var revoked = false
    private var cleanup = AcpProviderBrokerCleanup.NOT_ATTEMPTED
    private var admittedWireBytes = 0L
    private var observedResponseBytes = 0L
    private var observedOutputTokens = 0L
    private var observedInputTokens = 0L
    private val records = ArrayList<AcpProviderBrokerRequestEvidence>()
    private var admissionDenial: AcpProviderAdmissionDenial? = null
    // Exactly one periodic task; this executor is never exposed to request producers. It prevents
    // a stalled consumer from becoming the sole source of cancellation/deadline progress.
    private val lifecycle = ScheduledThreadPoolExecutor(1) { task ->
        Thread(task, "decomp-acp-provider-lifecycle").also { it.isDaemon = true }
    }.also { it.removeOnCancelPolicy = true }

    init {
        require(remaining >= Duration.ofMillis(1) && remaining <= Duration.ofDays(1)) { "provider enclosing deadline is unavailable" }
        require(maximumInvocationOutputTokens in 1..policy.bounds.maximumOutputTokens) { "provider token budget exceeds admitted request" }
        lifecycle.scheduleAtFixedRate({
            if (lock.tryLock()) {
                try { if (!revoked) try { checkActive(); active?.checkIdle() } catch (_: AcpProviderBrokerFailure) { } }
                finally { lock.unlock() }
            }
        }, 5, 5, TimeUnit.MILLISECONDS)
    }

    /** Copy for the private guardian setup frame only. Never put this value in logs or archives. */
    fun channelSetupPayload(): ByteArray = lock.withLock {
        checkActive()
        AcpProviderBrokerProtocol.channelSetupPayload(
            capability, policy, brokerHexBytes(invocationBindingSha256), remainingMillis(),
        )
    }

    /** The trusted SDK owner supplies its actual session/turn after negotiation, exactly once. */
    fun bindSession(sessionId: String, turnId: String) = lock.withLock {
        checkActive()
        val sessionBytes = validatedProviderIdentity(sessionId)
        val turnBytes = validatedProviderIdentity(turnId)
        if (sessionSha256 != null || turnSha256 != null) throw AcpProviderBrokerFailure(AcpProviderTerminalKind.REVOKED)
        sessionSha256 = brokerDigest(sessionBytes)
        turnSha256 = brokerDigest(turnBytes)
    }

    /** Only PROVIDER_REQUEST ingress reaches here; no peer-supplied URL becomes a backend URL. */
    fun beginRequest(
        sequence: Long,
        suppliedCapability: ByteArray,
        body: ByteArray,
        requestedOperation: String = AcpProviderOperation.RESPONSES_CREATE.name,
        requestedEndpoint: String = policy.endpoint.toASCIIString(),
    ): AcpProviderBrokerExchange = lock.withLock {
        try {
            checkActive()
            if (suppliedCapability.size != capability.size || !MessageDigest.isEqual(suppliedCapability, capability)) {
                throw AcpProviderBrokerFailure(AcpProviderTerminalKind.REVOKED)
            }
            if (requestedOperation != policy.operation.name || requestedEndpoint != policy.endpoint.toASCIIString()) {
                throw AcpProviderBrokerFailure(AcpProviderTerminalKind.UNSUPPORTED_OPERATION)
            }
            if (sequence != nextSequence || active != null) throw AcpProviderBrokerFailure(AcpProviderTerminalKind.REVOKED)
            if (records.size >= policy.bounds.maximumRequests) throw AcpProviderBrokerFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
            val session = sessionSha256 ?: throw AcpProviderBrokerFailure(AcpProviderTerminalKind.REVOKED)
            val turn = turnSha256 ?: throw AcpProviderBrokerFailure(AcpProviderTerminalKind.REVOKED)
            val tokenRemaining = maximumInvocationOutputTokens - observedOutputTokens.toInt()
            if (tokenRemaining <= 0) throw AcpProviderBrokerFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
            if (body.isEmpty() || body.size > policy.bounds.maximumRequestBytes) {
                throw AcpProviderBrokerFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
            }
            val admittedBody = body.copyOf()
            val wire = checkedRequestBody(admittedBody, tokenRemaining)
            if (wire.size.toLong() > policy.bounds.maximumRequestBytes - admittedWireBytes) {
                throw AcpProviderBrokerFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
            }
            checkActive()
            val exchange = AcpProviderBrokerExchange(sequence, session, turn, brokerDigest(admittedBody), wire, tokenRemaining)
            admittedWireBytes += wire.size
            active = exchange
            nextSequence++
            try {
                // The concrete backend's start is nonblocking sendAsync with a finite byte publisher.
                // Test implementations have the same nonblocking contract; no caller callback is public.
                exchange.owner = backend.start(
                    AcpProviderBackendRequest(policy.endpoint, wire, credentials, Duration.ofMillis(remainingMillis())), exchange,
                )
                if (exchange.terminal != null && exchange.terminal != AcpProviderTerminalKind.COMPLETED) exchange.owner?.cancel()
            } catch (failure: AcpProviderBrokerFailure) {
                exchange.finishFailure(failure.kind)
            } catch (_: Exception) {
                exchange.finishFailure(AcpProviderTerminalKind.TRANSPORT)
            }
            exchange
        } catch (failure: AcpProviderBrokerFailure) {
            if (admissionDenial == null) admissionDenial = AcpProviderAdmissionDenial(sequence, failure.kind)
            revoke(failure.kind)
            throw failure
        }
    }

    fun revoke(kind: AcpProviderTerminalKind = AcpProviderTerminalKind.REVOKED) = lock.withLock {
        revoked = true
        capability.fill(0)
        active?.finishFailure(kind)
        changed.signalAll()
    }

    fun snapshot(): AcpProviderBrokerSnapshot = lock.withLock {
        AcpProviderBrokerSnapshot(
            policy.descriptorSha256, invocationBindingSha256, requestBinding.requestSha256,
            revoked, cleanup, admittedWireBytes, observedResponseBytes, observedOutputTokens, admissionDenial, records,
            policy is AcpProviderTransportPolicy.CredentialFreeFixture,
        )
    }

    internal fun concreteBackendCleanupSnapshot(): AcpProviderConcreteBackendCleanupSnapshot? =
        (backend as? JdkAcpProviderBackend)?.cleanupSnapshot()

    override fun close() {
        revoke()
        // Model authority is already revoked. This distinct declared cleanup grace cannot admit
        // another request, and must not become a fresh model-execution timeout.
        val cleanupStarted = System.nanoTime()
        lifecycle.shutdownNow()
        val clean = try {
            val backendClean = backend.closeWithin(policy.bounds.cleanupTimeout)
            val left = (policy.bounds.cleanupTimeout.toNanos() - (System.nanoTime() - cleanupStarted)).coerceAtLeast(0)
            backendClean && lifecycle.awaitTermination(left, TimeUnit.NANOSECONDS) && lifecycle.isTerminated
        } catch (_: Exception) { false }
        lock.withLock { cleanup = if (clean) AcpProviderBrokerCleanup.VERIFIED else AcpProviderBrokerCleanup.UNVERIFIED }
        if (!clean) throw AcpProviderBrokerCleanupFailure()
    }

    private fun checkActive() {
        if (revoked) throw AcpProviderBrokerFailure(AcpProviderTerminalKind.REVOKED)
        if (cancellation.isCancellationRequested()) {
            revoked = true
            capability.fill(0)
            active?.finishFailure(AcpProviderTerminalKind.CANCELLED)
            throw AcpProviderBrokerFailure(AcpProviderTerminalKind.CANCELLED)
        }
        if (remainingMillisOrZero() <= 0) {
            revoked = true
            capability.fill(0)
            active?.finishFailure(AcpProviderTerminalKind.TIMEOUT)
            throw AcpProviderBrokerFailure(AcpProviderTerminalKind.TIMEOUT)
        }
    }

    private fun remainingMillisOrZero(): Long = ((allowedNanos - (System.nanoTime() - startedNanos)).coerceAtLeast(0) / 1_000_000)
    private fun remainingMillis(): Long = remainingMillisOrZero().takeIf { it > 0 }
        ?: throw AcpProviderBrokerFailure(AcpProviderTerminalKind.TIMEOUT)

    private fun checkedRequestBody(body: ByteArray, tokenRemaining: Int): ByteArray {
        if (body.isEmpty() || body.size > policy.bounds.maximumRequestBytes) {
            throw AcpProviderBrokerFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
        }
        val objectValue = try {
            val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(body)).toString()
            parseProviderObject(text, policy.bounds.maximumRequestBytes)
        } catch (_: Exception) { throw AcpProviderBrokerFailure(AcpProviderTerminalKind.MALFORMED_REQUEST) }
        if (objectValue.keys.any { it !in REQUEST_KEYS }) throw AcpProviderBrokerFailure(AcpProviderTerminalKind.UNSUPPORTED_OPERATION)
        val selectedModel = objectValue["model"] as? JsonPrimitive
        if (selectedModel?.contentOrNull != policy.model || selectedModel.isString != true) {
            throw AcpProviderBrokerFailure(AcpProviderTerminalKind.UNSUPPORTED_MODEL)
        }
        try {
            require(!objectValue.getValue("store").jsonPrimitive.isString && objectValue.getValue("store").jsonPrimitive.boolean == false)
            require(!objectValue.getValue("stream").jsonPrimitive.isString && objectValue.getValue("stream").jsonPrimitive.boolean)
            require(objectValue.getValue("input").jsonArray.isNotEmpty())
            val reasoning = objectValue.getValue("reasoning").jsonObject
            require(reasoning.keys.all { it in setOf("effort", "summary") })
            require(reasoning.getValue("effort").jsonPrimitive.isString && reasoning.getValue("effort").jsonPrimitive.content == policy.reasoning.wireValue)
            reasoning["summary"]?.let { require(it.jsonPrimitive.isString && it.jsonPrimitive.content in setOf("auto", "concise", "detailed")) }
            objectValue["include"]?.let { require(it.jsonArray.all { item -> item.jsonPrimitive.isString && item.jsonPrimitive.content == "reasoning.encrypted_content" }) }
            objectValue["tools"]?.let { tools ->
                require(tools.jsonArray.all { it.jsonObject["type"]?.jsonPrimitive?.contentOrNull == "function" })
            }
            objectValue["max_output_tokens"]?.let { require(it.jsonPrimitive.int in 1..tokenRemaining) }
            objectValue["service_tier"]?.let { require(it.jsonPrimitive.isString && it.jsonPrimitive.content == "auto") }
            objectValue["text"]?.let { text ->
                require(text.jsonObject.keys.all { it in setOf("verbosity", "format") })
                text.jsonObject["verbosity"]?.let { require(it.jsonPrimitive.isString && it.jsonPrimitive.content == "medium") }
                text.jsonObject["format"]?.let { require(it.jsonObject == buildJsonObject { put("type", "text") }) }
            }
        } catch (_: Exception) { throw AcpProviderBrokerFailure(AcpProviderTerminalKind.UNSUPPORTED_OPERATION) }
        // Explicit adapter transform. Acceptance by the ChatGPT backend remains unqualified.
        val transformed = JsonObject(objectValue + ("max_output_tokens" to JsonPrimitive(
            objectValue["max_output_tokens"]?.jsonPrimitive?.int ?: tokenRemaining,
        )))
        return try { boundedProviderJson(policy.bounds.maximumRequestBytes) { it.writeProviderValue(transformed) } }
        catch (_: Exception) { throw AcpProviderBrokerFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) }
    }

    internal inner class AcpProviderBrokerExchange internal constructor(
        val sequence: Long,
        private val session: String,
        private val turn: String,
        private val admittedDigest: String,
        private val wire: ByteArray,
        tokenRemaining: Int,
    ) : AcpProviderBackendReceiver {
        internal var owner: AcpProviderBackendRequestOwner? = null
        internal var terminal: AcpProviderTerminalKind? = null
        private var subscription: Flow.Subscription? = null
        private var demandOutstanding = false
        private var responseHeaders: AcpProviderResponseHeaders? = null
        private val queue = ArrayDeque<ByteArray>()
        private val digest = MessageDigest.getInstance("SHA-256")
        private var responseBytes = 0L
        private var lastActivityNanos = System.nanoTime()
        private var receipt: AcpProviderStreamReceipt? = null
        private var admittedOutputTokens: Int = 0
        private var recorded = false
        private val parser = AcpProviderResponseStream(
            policy.bounds,
            listOf(credentials.accessToken.toByteArray(), credentials.accountId.toByteArray(), capability.joinToString("") { "%02x".format(it) }.toByteArray()),
            tokenRemaining,
            maximumInvocationInputTokens?.let { it - observedInputTokens },
        )

        fun awaitHeaders(): AcpProviderResponseHeaders = lock.withLock {
            while (responseHeaders == null) {
                checkExchange()
                awaitChange()
            }
            requireNotNull(responseHeaders)
        }

        /** Backpressure is acknowledged only after a bounded queued chunk is taken by the owner. */
        fun nextChunk(): ByteArray? = lock.withLock {
            while (queue.isEmpty()) {
                checkExchange()
                if (terminal == AcpProviderTerminalKind.COMPLETED) { recordAndRelease(); return null }
                requestMore()
                awaitChange()
            }
            checkExchange()
            val chunk = queue.removeFirst()
            if (queue.isEmpty()) requestMore()
            chunk
        }

        fun cancel() = lock.withLock { revoke(AcpProviderTerminalKind.CANCELLED) }

        override fun headers(status: Int, headers: Map<String, List<String>>) = lock.withLock {
            if (!callbackActive()) return
            if (responseHeaders != null) { finishFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE); return }
            var fields = 0
            var bytes = 0L
            for ((name, values) in headers) {
                for (value in values) {
                    fields++
                    bytes += name.length.toLong() + value.length.toLong()
                    if (fields > policy.bounds.maximumHeaderFields || bytes > policy.bounds.maximumHeaderBytes) {
                        finishFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED); return
                    }
                    if (name.any { it.code !in 33..126 } || value.any { it.code !in 32..126 }) {
                        finishFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE); return
                    }
                }
            }
            if (policy is AcpProviderTransportPolicy.CredentialFreeFixture && status == 200 &&
                headers.keys.any { it.lowercase() !in setOf("content-type", "content-length", "date") && !(status in 300..399 && it.equals("location", true)) }) {
                finishFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE); return
            }
            if (status != 200) {
                finishFailure(when (status) {
                    401 -> AcpProviderTerminalKind.AUTHENTICATION
                    403 -> AcpProviderTerminalKind.AUTHORIZATION
                    408, 504 -> AcpProviderTerminalKind.TIMEOUT
                    429 -> AcpProviderTerminalKind.RESOURCE_EXHAUSTED
                    else -> AcpProviderTerminalKind.TRANSPORT
                }); return
            }
            val contentTypes = headers.filterKeys { it.equals("content-type", true) }.values.flatten()
            if (contentTypes.size != 1 || contentTypes.single().substringBefore(';').trim().lowercase() != "text/event-stream") {
                finishFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE); return
            }
            responseHeaders = AcpProviderResponseHeaders.decoded(200, "text/event-stream")
            lastActivityNanos = System.nanoTime()
            changed.signalAll()
        }

        override fun subscribe(subscription: Flow.Subscription) = lock.withLock {
            if (this.subscription != null || !callbackActive()) { subscription.cancel(); return }
            this.subscription = subscription
            requestMore()
        }

        override fun bytes(buffers: List<ByteBuffer>) = lock.withLock {
            if (!callbackActive()) return
            if (!demandOutstanding) { finishFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE); return }
            demandOutstanding = false
            if (responseHeaders == null) { finishFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE); return }
            var count = 0L
            for (buffer in buffers) count += buffer.remaining().toLong()
            if (count <= 0 || count > policy.bounds.maximumChunkBytes ||
                count > policy.bounds.maximumResponseBytes - observedResponseBytes) {
                finishFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED); return
            }
            val bytes = ByteArray(count.toInt())
            var offset = 0
            for (buffer in buffers) {
                val copy = buffer.asReadOnlyBuffer()
                val length = copy.remaining()
                copy.get(bytes, offset, length)
                offset += length
            }
            observedResponseBytes += count
            responseBytes += count
            digest.update(bytes)
            lastActivityNanos = System.nanoTime()
            try {
                if (!enqueueEvents(parser.accept(bytes))) return
            } catch (failure: AcpProviderStreamFailure) { finishFailure(failure.kind); return }
            catch (_: Exception) { finishFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE); return }
            changed.signalAll()
            if (queue.isEmpty()) requestMore()
        }

        override fun complete() = lock.withLock {
            if (!callbackActive()) return
            try {
                receipt = parser.finish()
                val finished = requireNotNull(receipt)
                if (finished.outputTokens.toLong() > maximumInvocationOutputTokens - observedOutputTokens ||
                    maximumInvocationInputTokens?.let { finished.inputTokens == null || finished.inputTokens.toLong() > it - observedInputTokens } == true) {
                    finishFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED); return
                }
                admittedOutputTokens = finished.outputTokens
                observedOutputTokens += finished.outputTokens
                observedInputTokens += finished.inputTokens ?: 0
                if (!enqueueEvents(parser.drainFinished())) return
                terminal = AcpProviderTerminalKind.COMPLETED
                changed.signalAll()
            } catch (failure: AcpProviderStreamFailure) { finishFailure(failure.kind) }
            catch (_: Exception) { finishFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) }
        }

        override fun failed() = lock.withLock { finishFailure(AcpProviderTerminalKind.TRANSPORT) }

        internal fun finishFailure(kind: AcpProviderTerminalKind) {
            if (terminal != null && terminal != AcpProviderTerminalKind.COMPLETED) return
            terminal = kind
            revoked = true
            capability.fill(0)
            subscription?.cancel()
            owner?.cancel()
            queue.clear()
            recordAndRelease()
            changed.signalAll()
        }

        private fun callbackActive(): Boolean {
            if (terminal != null || revoked) return false
            return try { checkActive(); checkIdle(); true }
            catch (failure: AcpProviderBrokerFailure) { finishFailure(failure.kind); false }
        }

        internal fun checkIdle() {
            if (terminal == null && System.nanoTime() - lastActivityNanos >= policy.bounds.idleTimeout.toNanos()) {
                finishFailure(AcpProviderTerminalKind.TIMEOUT)
                throw AcpProviderBrokerFailure(AcpProviderTerminalKind.TIMEOUT)
            }
        }

        private fun checkExchange() {
            if (terminal != null && terminal != AcpProviderTerminalKind.COMPLETED) throw AcpProviderBrokerFailure(requireNotNull(terminal))
            try { checkActive() } catch (failure: AcpProviderBrokerFailure) { finishFailure(failure.kind); throw failure }
            if (System.nanoTime() - lastActivityNanos >= policy.bounds.idleTimeout.toNanos()) {
                finishFailure(AcpProviderTerminalKind.TIMEOUT)
                throw AcpProviderBrokerFailure(AcpProviderTerminalKind.TIMEOUT)
            }
        }

        private fun awaitChange() {
            val millis = minOf(25L, remainingMillis(), policy.bounds.idleTimeout.toMillis())
            try { changed.await(millis, TimeUnit.MILLISECONDS) }
            catch (_: InterruptedException) { Thread.currentThread().interrupt(); finishFailure(AcpProviderTerminalKind.CANCELLED); throw AcpProviderBrokerFailure(AcpProviderTerminalKind.CANCELLED) }
        }

        private fun requestMore() {
            if (!demandOutstanding && queue.isEmpty() && terminal == null && !revoked) {
                subscription?.let { demandOutstanding = true; it.request(1) }
            }
        }

        /** Network batches may contain many tiny events; byte capacity, not event count, bounds
         * the queue. Coalescing also permits the EOF terminal event to join a partial last chunk. */
        private fun enqueueEvents(events: List<ByteArray>): Boolean {
            if (events.isEmpty()) return true
            val total = queue.sumOf { it.size.toLong() } + events.sumOf { it.size.toLong() }
            val capacity = policy.bounds.maximumChunkBytes.toLong() * policy.bounds.maximumQueuedChunks
            if (total > capacity) { finishFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED); return false }
            val inputs = queue.toList() + events
            queue.clear()
            var chunk = ByteArray(minOf(policy.bounds.maximumChunkBytes.toLong(), total).toInt())
            var written = 0
            var copied = 0L
            for (input in inputs) {
                var offset = 0
                while (offset < input.size) {
                    val count = minOf(input.size - offset, chunk.size - written)
                    input.copyInto(chunk, written, offset, offset + count)
                    offset += count; written += count; copied += count
                    if (written == chunk.size) {
                        queue.addLast(chunk)
                        if (copied < total) chunk = ByteArray(minOf(policy.bounds.maximumChunkBytes.toLong(), total - copied).toInt())
                        written = 0
                    }
                }
            }
            return true
        }

        private fun recordAndRelease() {
            if (recorded) return
            val result = terminal ?: return
            records.add(AcpProviderBrokerRequestEvidence(
                sequence, session, turn, admittedDigest, brokerDigest(wire), wire.size,
                responseBytes, digest.digest().brokerHex(), receipt?.inputTokens, receipt?.outputTokens, result, admittedOutputTokens,
            ))
            wire.fill(0)
            recorded = true
            if (active === this) active = null
        }
    }

    companion object {
        /** Still-unqualified adapter: only future explicit protected qualification may call this. */
        fun openForProtectedQualification(
            policy: AcpProviderTransportPolicy,
            admittedRequest: AgentExecutionRequest,
            enclosingRemaining: Duration,
            credentials: AcpProviderCredentialMaterial?,
        ): AcpProviderBroker {
            val approved = policy as? AcpProviderTransportPolicy.Approved
                ?: throw AcpProviderBrokerFailure(AcpProviderTerminalKind.UNSUPPORTED_OPERATION)
            val secret = credentials ?: throw AcpProviderBrokerFailure(AcpProviderTerminalKind.AUTHENTICATION)
            requireValidProviderDeadline(enclosingRemaining, admittedRequest)
            val binding = AgentExecutionRequestBinding.capture(admittedRequest)
            val backend = JdkAcpProviderBackend(ChatGptAcpProviderNetworkAuthority(approved))
            return try {
                AcpProviderBroker(
                    approved, binding, admittedRequest.cancellation, secret,
                    enclosingRemaining, minOf(approved.bounds.maximumOutputTokens.toLong(), admittedRequest.limits.maxOutputTokens ?: approved.bounds.maximumOutputTokens.toLong()).toInt(),
                    admittedRequest.limits.maxInputTokens, backend,
                )
            } catch (_: Exception) {
                if (!backend.closeWithin(approved.bounds.cleanupTimeout)) throw AcpProviderBrokerCleanupFailure()
                throw AcpProviderBrokerFailure(AcpProviderTerminalKind.TRANSPORT)
            }
        }

        /** Closed credential-free TLS building block; factory wiring is a later checkpoint. */
        internal fun openForCredentialFreeQualification(
            policy: AcpProviderTransportPolicy.CredentialFreeFixture,
            consumer: Any,
            admittedRequest: AgentExecutionRequest,
            enclosingRemaining: Duration,
        ): AcpProviderBroker {
            requireValidProviderDeadline(enclosingRemaining, admittedRequest)
            val binding = AgentExecutionRequestBinding.capture(admittedRequest)
            val authorization = policy.syntheticAuthorization()
            val credentials = AcpProviderCredentialMaterial.cachedChatGpt(authorization, "credential_free_fixture_v1")
            val backend = JdkAcpProviderBackend.openFixture(policy, consumer)
            return try {
                AcpProviderBroker(
                    policy, binding, admittedRequest.cancellation, credentials,
                    enclosingRemaining, minOf(policy.bounds.maximumOutputTokens.toLong(), admittedRequest.limits.maxOutputTokens ?: policy.bounds.maximumOutputTokens.toLong()).toInt(),
                    admittedRequest.limits.maxInputTokens, backend,
                )
            } catch (_: Exception) {
                if (!backend.closeWithin(policy.bounds.cleanupTimeout)) throw AcpProviderBrokerCleanupFailure()
                throw AcpProviderBrokerFailure(AcpProviderTerminalKind.TRANSPORT)
            }
        }

        /** Internal controls exercise owner state, not TLS, credential resolution, or the ACP factory. */
        fun openForTesting(
            policy: AcpProviderTransportPolicy,
            admittedRequest: AgentExecutionRequest,
            enclosingRemaining: Duration,
            credentials: AcpProviderCredentialMaterial?,
            backend: AcpProviderBrokerTestBackend,
        ): AcpProviderBroker {
            val approved = policy as? AcpProviderTransportPolicy.Approved
                ?: throw AcpProviderBrokerFailure(AcpProviderTerminalKind.UNSUPPORTED_OPERATION)
            val secret = credentials ?: throw AcpProviderBrokerFailure(AcpProviderTerminalKind.AUTHENTICATION)
            requireValidProviderDeadline(enclosingRemaining, admittedRequest)
            return AcpProviderBroker(
                approved, AgentExecutionRequestBinding.capture(admittedRequest), admittedRequest.cancellation, secret,
                enclosingRemaining, minOf(approved.bounds.maximumOutputTokens.toLong(), admittedRequest.limits.maxOutputTokens ?: approved.bounds.maximumOutputTokens.toLong()).toInt(),
                admittedRequest.limits.maxInputTokens, backend,
            )
        }
    }
}

internal class AcpProviderBrokerCleanupFailure : IOException("ACP provider broker cleanup was not verified")

/** No inherited proxy, authenticator, cookie jar, redirects, or body/error logging. */
internal data class AcpProviderConcreteBackendCleanupSnapshot(
    val clientTerminated: Boolean,
    val executorTerminated: Boolean,
    val requestFutureCount: Int,
    val terminalFutureCount: Int,
)

private class JdkAcpProviderBackend(private val authority: AcpProviderNetworkAuthority) : AcpProviderBrokerTestBackend {
    private val authorityAdmission = authority.admitToBackend()
    private var fixtureBrokerClaimed = false
    private val executor: ExecutorService = ThreadPoolExecutor(
        2, 2, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(32),
        { task -> Thread(task, "decomp-acp-provider-http").also { it.isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )
    private val client = authority.configure(HttpClient.newBuilder().executor(executor).followRedirects(HttpClient.Redirect.NEVER)
        .connectTimeout(Duration.ofSeconds(10)).proxy(object : ProxySelector() {
            override fun select(uri: URI): List<Proxy> = listOf(Proxy.NO_PROXY)
            override fun connectFailed(uri: URI, sa: SocketAddress, ioe: IOException) = Unit
        })).build()
    private val owners = Collections.synchronizedList(ArrayList<CompletableFuture<*>>())

    override fun start(request: AcpProviderBackendRequest, receiver: AcpProviderBackendReceiver): AcpProviderBackendRequestOwner {
        require(request.endpoint == authority.endpoint) { "provider network authority is unavailable" }
        val wire = authority.authorize(HttpRequest.newBuilder(request.endpoint).timeout(request.timeout), request.credentials)
            .header("Accept", "text/event-stream").header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofByteArray(request.body)).build()
        val future = client.sendAsync(wire) { information ->
            receiver.headers(information.statusCode(), information.headers().map())
            object : HttpResponse.BodySubscriber<Unit> {
                private val finished = CompletableFuture<Unit>()
                override fun getBody(): CompletionStage<Unit> = finished
                override fun onSubscribe(subscription: Flow.Subscription) = receiver.subscribe(object : Flow.Subscription {
                    override fun request(n: Long) = subscription.request(n)
                    override fun cancel() { subscription.cancel(); finished.complete(Unit) }
                })
                override fun onNext(item: List<ByteBuffer>) = receiver.bytes(item)
                override fun onError(throwable: Throwable) { receiver.failed(); finished.completeExceptionally(IOException("provider body failed")) }
                override fun onComplete() { receiver.complete(); finished.complete(Unit) }
            }
        }
        owners.add(future)
        future.whenComplete { _, failure -> if (failure != null) receiver.failed() }
        return object : AcpProviderBackendRequestOwner { override fun cancel() { future.cancel(true) } }
    }

    @Synchronized
    fun ownsFixtureAuthority(policy: AcpProviderTransportPolicy.CredentialFreeFixture): Boolean {
        if (fixtureBrokerClaimed || authority !is FixtureAcpProviderNetworkAuthority || authority.policy !== policy) return false
        fixtureBrokerClaimed = true
        return true
    }

    fun cleanupSnapshot(): AcpProviderConcreteBackendCleanupSnapshot = synchronized(owners) {
        AcpProviderConcreteBackendCleanupSnapshot(client.isTerminated, executor.isTerminated, owners.size, owners.count { it.isDone })
    }

    override fun closeWithin(timeout: Duration): Boolean {
        val started = System.nanoTime()
        val nanos = timeout.toNanos()
        synchronized(owners) { owners.forEach { it.cancel(true) } }
        client.shutdownNow()
        executor.shutdownNow()
        val clientClean = client.awaitTermination(Duration.ofNanos((nanos - (System.nanoTime() - started)).coerceAtLeast(0)))
        val executorClean = executor.awaitTermination((nanos - (System.nanoTime() - started)).coerceAtLeast(0), TimeUnit.NANOSECONDS)
        return clientClean && client.isTerminated && executorClean && executor.isTerminated && synchronized(owners) { owners.all { it.isDone } }
    }

    companion object {
        fun openFixture(policy: AcpProviderTransportPolicy.CredentialFreeFixture, consumer: Any): JdkAcpProviderBackend =
            JdkAcpProviderBackend(FixtureAcpProviderNetworkAuthority.issue(policy, consumer))
    }
}

/** Distinct concrete authorities: fixture TLS never changes production default trust. */
private sealed class AcpProviderNetworkAuthority protected constructor() {
    abstract val endpoint: URI
    open fun admitToBackend() = Unit
    abstract fun authorize(builder: HttpRequest.Builder, credentials: AcpProviderCredentialMaterial): HttpRequest.Builder
    open fun configure(builder: HttpClient.Builder): HttpClient.Builder = builder
}

private class ChatGptAcpProviderNetworkAuthority(policy: AcpProviderTransportPolicy.Approved) : AcpProviderNetworkAuthority() {
    override val endpoint: URI = policy.endpoint
    init { require(endpoint == APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT) { "provider network authority is unavailable" } }
    override fun authorize(builder: HttpRequest.Builder, credentials: AcpProviderCredentialMaterial): HttpRequest.Builder =
        builder.header("Authorization", "Bearer ${credentials.accessToken}").header("ChatGPT-Account-ID", credentials.accountId)
}

private class FixtureAcpProviderNetworkAuthority(
    val policy: AcpProviderTransportPolicy.CredentialFreeFixture,
    private val authorization: String,
    provenance: Any,
) : AcpProviderNetworkAuthority() {
    init { require(hasProvenance(provenance)) { "fixture network authority is unavailable" } }
    override val endpoint: URI = policy.endpoint
    // All authority state is private instance state, not companion static fields whose synthetic
    // accessors could return provenance or mutable identity registries.
    private class Issuer {
        private val provenance = Any()
        private val issuedAuthorities = IdentityHashMap<FixtureAcpProviderNetworkAuthority, Boolean>()
        fun hasProvenance(value: Any): Boolean = value === provenance
        fun issue(policy: AcpProviderTransportPolicy.CredentialFreeFixture, consumer: Any): FixtureAcpProviderNetworkAuthority {
            val authorization = policy.claimForBroker(consumer)
            return FixtureAcpProviderNetworkAuthority(policy, authorization, provenance).also {
                synchronized(issuedAuthorities) { issuedAuthorities[it] = true }
            }
        }
        fun consume(authority: FixtureAcpProviderNetworkAuthority) = synchronized(issuedAuthorities) {
            require(issuedAuthorities.remove(authority) == true) { "fixture network authority is forged or consumed" }
        }
    }
    companion object {
        private val issuer = Issuer()
        private fun hasProvenance(value: Any): Boolean = issuer.hasProvenance(value)
        fun issue(policy: AcpProviderTransportPolicy.CredentialFreeFixture, consumer: Any): FixtureAcpProviderNetworkAuthority =
            issuer.issue(policy, consumer)
    }
    override fun admitToBackend() = issuer.consume(this)
    override fun authorize(builder: HttpRequest.Builder, credentials: AcpProviderCredentialMaterial): HttpRequest.Builder {
        require(credentials.accessToken == authorization && credentials.accountId == "credential_free_fixture_v1") {
            "fixture authorization is unavailable"
        }
        return builder.header("Authorization", "Bearer $authorization")
    }
    private val tlsContext: SSLContext = createTlsContext()
    private fun createTlsContext(): SSLContext {
        val identityBytes = AcpProviderBroker::class.java.getResourceAsStream(PROVIDER_FIXTURE_KEYSTORE_RESOURCE)
            ?.use { stream -> stream.readNBytes(16 * 1024 + 1) }
            ?: throw IllegalArgumentException("fixture TLS identity is unavailable")
        require(identityBytes.size <= 16 * 1024 && brokerDigest(identityBytes) == PROVIDER_FIXTURE_KEYSTORE_SHA256) {
            "fixture TLS identity integrity failed"
        }
        val identity = KeyStore.getInstance("PKCS12").also {
            it.load(ByteArrayInputStream(identityBytes), PROVIDER_FIXTURE_KEYSTORE_PASSWORD.toCharArray())
        }
        val certificate = identity.getCertificate("fixture") as? X509Certificate
            ?: throw IllegalArgumentException("fixture TLS certificate is unavailable")
        require(brokerDigest(certificate.encoded) == PROVIDER_FIXTURE_CERTIFICATE_SHA256 &&
            brokerDigest(certificate.publicKey.encoded) == PROVIDER_FIXTURE_SPKI_SHA256) { "fixture TLS certificate integrity failed" }
        val trust = KeyStore.getInstance(KeyStore.getDefaultType()).also {
            it.load(null, null); it.setCertificateEntry("fixture", certificate)
        }
        val delegate = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).also { it.init(trust) }
            .trustManagers.filterIsInstance<X509ExtendedTrustManager>().single()
        val context = SSLContext.getInstance("TLS").also {
            it.init(null, arrayOf(PinnedFixtureTrustManager(delegate)), SecureRandom())
        }
        return context
    }
    override fun configure(builder: HttpClient.Builder): HttpClient.Builder =
        builder.version(HttpClient.Version.HTTP_1_1).sslContext(tlsContext).sslParameters(SSLParameters().also {
            it.endpointIdentificationAlgorithm = "HTTPS"
            it.protocols = arrayOf("TLSv1.3", "TLSv1.2")
        })
}

/** Extended overloads preserve the JDK's IP SAN verification as well as both exact pins. */
private class PinnedFixtureTrustManager(private val delegate: X509ExtendedTrustManager) : X509ExtendedTrustManager() {
    private fun requirePin(chain: Array<out X509Certificate>?) {
        val leaf = chain?.singleOrNull() ?: throw CertificateException("fixture TLS certificate was refused")
        if (brokerDigest(leaf.encoded) != PROVIDER_FIXTURE_CERTIFICATE_SHA256 ||
            brokerDigest(leaf.publicKey.encoded) != PROVIDER_FIXTURE_SPKI_SHA256) {
            throw CertificateException("fixture TLS certificate was refused")
        }
        leaf.checkValidity()
    }
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        requirePin(chain); delegate.checkServerTrusted(chain, authType)
    }
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {
        requirePin(chain); delegate.checkServerTrusted(chain, authType, socket)
    }
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {
        requirePin(chain); delegate.checkServerTrusted(chain, authType, engine)
    }
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) { throw CertificateException("fixture client certificates are unsupported") }
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) { throw CertificateException("fixture client certificates are unsupported") }
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) { throw CertificateException("fixture client certificates are unsupported") }
    override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers.clone()
}

private val REQUEST_KEYS = setOf(
    "model", "input", "tools", "tool_choice", "parallel_tool_calls", "reasoning", "store", "stream", "include",
    "text", "metadata", "prompt_cache_key", "service_tier", "safety_identifier", "max_output_tokens", "truncation", "instructions",
)

private fun brokerDigest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).brokerHex()
private fun ByteArray.brokerHex(): String = joinToString("") { "%02x".format(it) }
private fun brokerHexBytes(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
private fun requireValidProviderDeadline(remaining: Duration, request: AgentExecutionRequest) {
    require(remaining >= Duration.ofMillis(1) && remaining <= Duration.ofDays(1) && remaining <= request.limits.wallClockTimeout) {
        "provider enclosing deadline is missing or exceeds admitted request"
    }
}
private fun validatedProviderIdentity(value: String): ByteArray {
    require(value.isNotEmpty() && value.length <= 256 && value.none(Char::isISOControl)) { "provider session or turn identity is missing or malformed" }
    return try {
        val encoded = Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value))
        require(encoded.remaining() <= 256)
        ByteArray(encoded.remaining()).also(encoded::get)
    } catch (_: Exception) { throw IllegalArgumentException("provider session or turn identity is missing or malformed") }
}
