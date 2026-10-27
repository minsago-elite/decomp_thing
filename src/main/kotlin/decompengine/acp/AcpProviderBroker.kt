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
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URI
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
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager
import java.time.Duration
import java.util.Collections
import java.util.IdentityHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Flow
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import org.apache.hc.core5.http.ClassicHttpResponse
import org.apache.hc.core5.http.ContentLengthStrategy
import org.apache.hc.core5.http.ContentType
import org.apache.hc.core5.http.HttpVersion
import org.apache.hc.core5.http.config.Http1Config
import org.apache.hc.core5.http.impl.io.ChunkedInputStream
import org.apache.hc.core5.http.impl.io.DefaultBHttpClientConnection
import org.apache.hc.core5.http.impl.io.DefaultHttpResponseParser
import org.apache.hc.core5.http.impl.io.HttpRequestExecutor
import org.apache.hc.core5.http.io.HttpMessageParser
import org.apache.hc.core5.http.io.HttpMessageParserFactory
import org.apache.hc.core5.http.io.SessionInputBuffer
import org.apache.hc.core5.http.io.entity.ByteArrayEntity
import org.apache.hc.core5.http.message.BasicClassicHttpRequest
import org.apache.hc.core5.http.protocol.HttpCoreContext
import org.apache.hc.core5.io.CloseMode
import org.apache.hc.core5.util.CharArrayBuffer
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
    internal val deadlineNanos: Long = System.nanoTime() + timeout.toNanos(),
) {
    private val content = body.copyOf()
    val body: ByteArray get() = content.copyOf()
    override fun toString(): String = "AcpProviderBackendRequest(<redacted>)"
}

/** Internal deterministic control seam; production issuance always selects the concrete HTTP/1.1 backend. */
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
    fun timedOut() = failed()
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
    credentialMaterial: AcpProviderCredentialMaterial,
    remaining: Duration,
    private val maximumInvocationOutputTokens: Int,
    private val maximumInvocationInputTokens: Long?,
    private val backend: AcpProviderBrokerTestBackend,
    private val startedNanos: Long,
) : AutoCloseable {
    // Validate before any lifecycle executor, capability, or backend dispatch can be created.
    // Kotlin's public synthetic marker constructor must not permit a fixture backend substitute.
    private val fixtureBackendAdmission: Unit = if (policy is AcpProviderTransportPolicy.CredentialFreeFixture) {
        require(backend is CoreAcpProviderBackend && backend.ownsFixtureAuthority(policy)) {
            "fixture broker authority is unavailable"
        }
    } else Unit
    private val lock = ReentrantLock()
    // Guarded by lock. Already-admitted backend work retains its own bounded owner.
    private var credentials: AcpProviderCredentialMaterial? = credentialMaterial
    private val changed = lock.newCondition()
    private val allowedNanos = minOf(remaining.toNanos(), policy.bounds.overallTimeout.toNanos())
    private val deadlineAdmission = if (System.nanoTime() - startedNanos >= allowedNanos) {
        throw AcpProviderBrokerFailure(AcpProviderTerminalKind.TIMEOUT)
    } else Unit
    private val capability = ByteArray(PROVIDER_INVOCATION_CAPABILITY_BYTES).also(SecureRandom()::nextBytes)
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
        if (sessionSha256 != null || turnSha256 != null) {
            revoke(AcpProviderTerminalKind.REVOKED)
            throw AcpProviderBrokerFailure(AcpProviderTerminalKind.REVOKED)
        }
        val sessionBytes = validatedProviderIdentity(sessionId)
        val turnBytes = validatedProviderIdentity(turnId)
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
            if (maximumInvocationInputTokens?.let { observedInputTokens >= it } == true) {
                throw AcpProviderBrokerFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
            }
            if (body.isEmpty() || body.size > policy.bounds.maximumRequestBytes) {
                throw AcpProviderBrokerFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
            }
            val admittedBody = body.copyOf()
            val checked = checkedRequestBody(admittedBody, tokenRemaining)
            val wire = checked.wire
            if (wire.size.toLong() > policy.bounds.maximumRequestBytes - admittedWireBytes) {
                throw AcpProviderBrokerFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
            }
            checkActive()
            val dispatchCredentials = credentials ?: throw AcpProviderBrokerFailure(AcpProviderTerminalKind.REVOKED)
            val exchange = AcpProviderBrokerExchange(sequence, session, turn, brokerDigest(admittedBody), wire,
                checked.maximumOutputTokens, dispatchCredentials)
            admittedWireBytes += wire.size
            active = exchange
            nextSequence++
            try {
                // The concrete backend queues one bounded HTTP/1.1 exchange without blocking this owner.
                // Test implementations have the same nonblocking contract; no caller callback is public.
                exchange.attachOwner(backend.start(
                    AcpProviderBackendRequest(policy.endpoint, wire, dispatchCredentials, Duration.ofMillis(remainingMillis()), startedNanos + allowedNanos), exchange,
                ))
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
        revokeDispatch()
        active?.finishFailure(kind)
        changed.signalAll()
    }

    /** Called with lock held, before cancellation callbacks can reenter dispatch. */
    private fun revokeDispatch() {
        revoked = true
        credentials = null
        capability.fill(0)
    }

    fun snapshot(): AcpProviderBrokerSnapshot = lock.withLock {
        AcpProviderBrokerSnapshot(
            policy.descriptorSha256, invocationBindingSha256, requestBinding.requestSha256,
            revoked, cleanup, admittedWireBytes, observedResponseBytes, observedOutputTokens, admissionDenial, records,
            policy is AcpProviderTransportPolicy.CredentialFreeFixture,
        )
    }

    internal fun concreteBackendCleanupSnapshot(): AcpProviderConcreteBackendCleanupSnapshot? =
        (backend as? CoreAcpProviderBackend)?.cleanupSnapshot()

    @Synchronized
    override fun close() {
        // One cleanup attempt owns one grace; retries cannot erase a missed deadline.
        when (lock.withLock { cleanup }) {
            AcpProviderBrokerCleanup.VERIFIED -> return
            AcpProviderBrokerCleanup.UNVERIFIED -> throw AcpProviderBrokerCleanupFailure()
            AcpProviderBrokerCleanup.NOT_ATTEMPTED -> Unit
        }
        val cleanupStarted = System.nanoTime()
        revoke()
        // Revocation, backend teardown and lifecycle termination share this one cleanup grace.
        lifecycle.shutdownNow()
        val clean = try {
            val remaining = (policy.bounds.cleanupTimeout.toNanos() - (System.nanoTime() - cleanupStarted)).coerceAtLeast(0)
            val backendClean = backend.closeWithin(Duration.ofNanos(remaining))
            val left = (policy.bounds.cleanupTimeout.toNanos() - (System.nanoTime() - cleanupStarted)).coerceAtLeast(0)
            left > 0 && backendClean && lifecycle.awaitTermination(left, TimeUnit.NANOSECONDS) && lifecycle.isTerminated &&
                System.nanoTime() - cleanupStarted < policy.bounds.cleanupTimeout.toNanos()
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        } catch (_: Exception) { false }
        lock.withLock { cleanup = if (clean) AcpProviderBrokerCleanup.VERIFIED else AcpProviderBrokerCleanup.UNVERIFIED }
        if (!clean) throw AcpProviderBrokerCleanupFailure()
    }

    private fun checkActive() {
        if (revoked) throw AcpProviderBrokerFailure(AcpProviderTerminalKind.REVOKED)
        val cancellationRequested = try { cancellation.isCancellationRequested() }
        catch (failure: Exception) {
            // A faulty owner callback cannot silently stop the periodic lifecycle task or expose
            // its exception (which may contain host material) to the response consumer.
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            revoke(AcpProviderTerminalKind.TRANSPORT)
            throw AcpProviderBrokerFailure(AcpProviderTerminalKind.TRANSPORT)
        }
        if (cancellationRequested) {
            revokeDispatch()
            active?.finishFailure(AcpProviderTerminalKind.CANCELLED)
            throw AcpProviderBrokerFailure(AcpProviderTerminalKind.CANCELLED)
        }
        if (remainingMillisOrZero() <= 0) {
            revokeDispatch()
            active?.finishFailure(AcpProviderTerminalKind.TIMEOUT)
            throw AcpProviderBrokerFailure(AcpProviderTerminalKind.TIMEOUT)
        }
    }

    private fun remainingMillisOrZero(): Long = ((allowedNanos - (System.nanoTime() - startedNanos)).coerceAtLeast(0) / 1_000_000)
    private fun remainingMillis(): Long = remainingMillisOrZero().takeIf { it > 0 }
        ?: throw AcpProviderBrokerFailure(AcpProviderTerminalKind.TIMEOUT)

    private class CheckedProviderRequest(val wire: ByteArray, val maximumOutputTokens: Int)

    private fun checkedRequestBody(body: ByteArray, tokenRemaining: Int): CheckedProviderRequest {
        if (body.isEmpty() || body.size > policy.bounds.maximumRequestBytes) {
            throw AcpProviderBrokerFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
        }
        val objectValue = try {
            val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(body)).toString()
            parseProviderObject(text, policy.bounds.maximumRequestBytes)
        } catch (_: Exception) { throw AcpProviderBrokerFailure(AcpProviderTerminalKind.MALFORMED_REQUEST) }
        // The existing strict parser bounds document bytes, tokens and depth before this walk.
        // Inspect decoded names and scalar content so JSON escapes cannot hide the channel bearer.
        rejectCapabilityDisclosure(objectValue, capability.joinToString("") { "%02x".format(it) })
        if (objectValue.keys.any { it !in REQUEST_KEYS }) throw AcpProviderBrokerFailure(AcpProviderTerminalKind.UNSUPPORTED_OPERATION)
        val selectedModel = objectValue["model"] as? JsonPrimitive
        if (selectedModel?.contentOrNull != policy.model || selectedModel.isString != true) {
            throw AcpProviderBrokerFailure(AcpProviderTerminalKind.UNSUPPORTED_MODEL)
        }
        try {
            require(!objectValue.getValue("store").jsonPrimitive.isString && objectValue.getValue("store").jsonPrimitive.boolean == false)
            require(!objectValue.getValue("stream").jsonPrimitive.isString && objectValue.getValue("stream").jsonPrimitive.boolean)
            validateInput(objectValue.getValue("input"))
            val reasoning = objectValue.getValue("reasoning").jsonObject
            require(reasoning.keys.all { it in setOf("effort", "summary") })
            require(reasoning.getValue("effort").jsonPrimitive.isString && reasoning.getValue("effort").jsonPrimitive.content == policy.reasoning.wireValue)
            reasoning["summary"]?.let { require(it.jsonPrimitive.isString && it.jsonPrimitive.content in setOf("auto", "concise", "detailed")) }
            validateOptionalRequestFields(objectValue)
            objectValue["max_output_tokens"]?.let { require(!it.jsonPrimitive.isString && it.jsonPrimitive.int in 1..tokenRemaining) }
            objectValue["service_tier"]?.let { require(it.jsonPrimitive.isString && it.jsonPrimitive.content == "auto") }
            objectValue["text"]?.let { text ->
                require(text.jsonObject.keys.all { it in setOf("verbosity", "format") })
                text.jsonObject["verbosity"]?.let { require(it.jsonPrimitive.isString && it.jsonPrimitive.content == "medium") }
                text.jsonObject["format"]?.let { require(it.jsonObject == buildJsonObject { put("type", "text") }) }
            }
        } catch (_: Exception) { throw AcpProviderBrokerFailure(AcpProviderTerminalKind.UNSUPPORTED_OPERATION) }
        // Explicit adapter transform. Acceptance by the ChatGPT backend remains unqualified.
        val effectiveOutputTokens = objectValue["max_output_tokens"]?.jsonPrimitive?.int ?: tokenRemaining
        val transformed = JsonObject(objectValue + ("max_output_tokens" to JsonPrimitive(effectiveOutputTokens)))
        val wire = try { boundedProviderJson(policy.bounds.maximumRequestBytes) { it.writeProviderValue(transformed) } }
        catch (_: Exception) { throw AcpProviderBrokerFailure(AcpProviderTerminalKind.RESOURCE_EXHAUSTED) }
        return CheckedProviderRequest(wire, effectiveOutputTokens)
    }

    /** Two text-only component variants; native traffic and private acceptance remain unqualified. */
    private fun validateInput(value: JsonElement) {
        fun requireText(value: JsonElement) {
            val text = value.jsonPrimitive
            require(text.isString && text.content.length in 1..policy.bounds.maximumRequestBytes)
            // JSON escapes must not introduce an unpaired surrogate which changes on UTF-8 output.
            var index = 0
            while (index < text.content.length) {
                val character = text.content[index++]
                if (Character.isHighSurrogate(character)) {
                    require(index < text.content.length && Character.isLowSurrogate(text.content[index]))
                    index++
                } else require(!Character.isLowSurrogate(character))
            }
        }
        val messages = value.jsonArray
        require(messages.size in 1..MAXIMUM_INPUT_MESSAGES)
        messages.forEach { element ->
            val message = element.jsonObject
            require(message.getValue("role").jsonPrimitive.isString && message.getValue("role").jsonPrimitive.content == "user")
            if ("type" !in message) {
                require(message.keys == setOf("role", "content"))
                requireText(message.getValue("content"))
            } else {
                require(message.keys == setOf("type", "role", "content"))
                require(message.getValue("type").jsonPrimitive.isString && message.getValue("type").jsonPrimitive.content == "message")
                val parts = message.getValue("content").jsonArray
                require(parts.size in 1..MAXIMUM_INPUT_PARTS)
                parts.forEach { element ->
                    val part = element.jsonObject
                    require(part.keys == setOf("type", "text"))
                    require(part.getValue("type").jsonPrimitive.isString && part.getValue("type").jsonPrimitive.content == "input_text")
                    requireText(part.getValue("text"))
                }
            }
        }
    }

    /** Deliberately closed adapter subset; these checks do not qualify the private backend. */
    private fun validateOptionalRequestFields(request: JsonObject) {
        fun string(value: JsonElement, maximum: Int): String {
            val primitive = value.jsonPrimitive
            require(primitive.isString && primitive.content.length <= maximum)
            return primitive.content
        }
        fun boolean(value: JsonElement) { require(!value.jsonPrimitive.isString); value.jsonPrimitive.boolean }
        request["instructions"]?.let { string(it, 4096) }
        request["prompt_cache_key"]?.let { string(it, 128) }
        request["safety_identifier"]?.let { string(it, 128) }
        request["parallel_tool_calls"]?.let { boolean(it) }
        request["truncation"]?.let { require(string(it, 8) == "disabled") }
        request["include"]?.let {
            require(it.jsonArray.size <= 1)
            it.jsonArray.forEach { item -> require(string(item, 27) == "reasoning.encrypted_content") }
        }
        request["metadata"]?.let {
            val metadata = it.jsonObject
            require(metadata.size <= 16)
            metadata.forEach { (key, value) -> require(key.length in 1..64); string(value, 512) }
        }
        val toolNames = mutableSetOf<String>()
        request["tools"]?.let { value ->
            val tools = value.jsonArray
            require(tools.size <= 16)
            tools.forEach { element ->
                val tool = element.jsonObject
                require(tool.keys.all { it in setOf("type", "name", "description", "parameters", "strict") })
                require(string(tool.getValue("type"), 8) == "function")
                val name = string(tool.getValue("name"), 64)
                require(name.matches(Regex("[A-Za-z0-9_-]{1,64}")) && toolNames.add(name))
                tool["description"]?.let { string(it, 1024) }
                tool["strict"]?.let { boolean(it) }
                val schema = tool.getValue("parameters").jsonObject
                require(schema.keys == setOf("type", "properties", "required", "additionalProperties"))
                require(string(schema.getValue("type"), 6) == "object")
                require(!schema.getValue("additionalProperties").jsonPrimitive.isString && !schema.getValue("additionalProperties").jsonPrimitive.boolean)
                val properties = schema.getValue("properties").jsonObject
                require(properties.size <= 32)
                properties.forEach { (propertyName, propertyValue) ->
                    require(propertyName.matches(Regex("[A-Za-z_][A-Za-z0-9_]{0,63}")))
                    val property = propertyValue.jsonObject
                    require(property.keys.all { it in setOf("type", "description", "enum") })
                    val type = string(property.getValue("type"), 7)
                    require(type in setOf("string", "number", "integer", "boolean"))
                    property["description"]?.let { string(it, 1024) }
                    property["enum"]?.let {
                        val choices = it.jsonArray
                        require(type == "string" && choices.size in 1..16)
                        val values = choices.map { choice -> string(choice, 128) }
                        require(values.distinct().size == values.size)
                    }
                }
                val required = schema.getValue("required").jsonArray.map { string(it, 64) }
                require(required.size <= 32 && required.distinct().size == required.size && required.all { it in properties })
                if (tool["strict"]?.jsonPrimitive?.boolean == true) require(required.toSet() == properties.keys)
            }
        }
        request["tool_choice"]?.let { choice ->
            if (choice is JsonPrimitive) {
                val mode = string(choice, 8)
                require(mode in setOf("auto", "none", "required"))
                if (mode == "required") require(toolNames.isNotEmpty())
            } else {
                val function = choice.jsonObject
                require(function.keys == setOf("type", "name"))
                require(string(function.getValue("type"), 8) == "function")
                require(string(function.getValue("name"), 64) in toolNames)
            }
        }
    }

    private fun rejectCapabilityDisclosure(value: JsonElement, capabilityHex: String) {
        fun rejectIfPresent(text: String) {
            if (text.contains(capabilityHex, ignoreCase = true)) {
                throw AcpProviderBrokerFailure(AcpProviderTerminalKind.SECRET_EXPOSURE)
            }
        }
        when (value) {
            is JsonObject -> value.forEach { (name, child) ->
                rejectIfPresent(name)
                rejectCapabilityDisclosure(child, capabilityHex)
            }
            is JsonArray -> value.forEach { rejectCapabilityDisclosure(it, capabilityHex) }
            is JsonPrimitive -> rejectIfPresent(value.content)
        }
    }

    internal inner class AcpProviderBrokerExchange internal constructor(
        val sequence: Long,
        private val session: String,
        private val turn: String,
        private val admittedDigest: String,
        private val wire: ByteArray,
        maximumRequestOutputTokens: Int,
        credentials: AcpProviderCredentialMaterial,
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
            maximumRequestOutputTokens,
            maximumInvocationInputTokens?.let { it - observedInputTokens },
        )

        internal fun attachOwner(value: AcpProviderBackendRequestOwner) {
            if (recorded) {
                if (terminal != AcpProviderTerminalKind.COMPLETED) value.cancel()
                return
            }
            owner = value
            if (terminal != null && terminal != AcpProviderTerminalKind.COMPLETED) value.cancel()
        }

        fun awaitHeaders(): AcpProviderResponseHeaders = lock.withLock {
            while (responseHeaders == null) {
                checkExchange()
                awaitChange()
            }
            requireNotNull(responseHeaders)
        }

        /** Backpressure is acknowledged only after a bounded queued chunk is taken by the owner. */
        fun nextChunk(): ByteArray? = lock.withLock {
            if (recorded && terminal == AcpProviderTerminalKind.COMPLETED) return null
            while (queue.isEmpty()) {
                checkExchange()
                if (terminal == AcpProviderTerminalKind.COMPLETED) { recordAndRelease(); return null }
                requestMore()
                awaitChange()
            }
            checkExchange()
            val chunk = queue.removeFirst()
            if (queue.isEmpty()) {
                // EOF has been validated and the final bytes have now reached the consumer.
                // Freeze success here; the consumer need not make a redundant EOF read.
                if (terminal == AcpProviderTerminalKind.COMPLETED) recordAndRelease() else requestMore()
            }
            chunk
        }

        fun cancel() = lock.withLock { if (!recorded) revoke(AcpProviderTerminalKind.CANCELLED) }

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
                if (queue.isEmpty()) recordAndRelease()
                changed.signalAll()
            } catch (failure: AcpProviderStreamFailure) { finishFailure(failure.kind) }
            catch (_: Exception) { finishFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE) }
        }

        override fun failed() = lock.withLock { finishFailure(AcpProviderTerminalKind.TRANSPORT) }
        override fun timedOut() = lock.withLock { finishFailure(AcpProviderTerminalKind.TIMEOUT) }

        internal fun finishFailure(kind: AcpProviderTerminalKind) {
            if (recorded || terminal != null && terminal != AcpProviderTerminalKind.COMPLETED) return
            terminal = kind
            revokeDispatch()
            parser.abort(kind)
            runCatching { subscription?.cancel() }
            runCatching { owner?.cancel() }
            queue.forEach { it.fill(0) }
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
            // Validated EOF still owns admission until its final queued chunk is delivered.
            // Only recorded exchanges have frozen success/failure evidence and need no timer.
            if (!recorded && System.nanoTime() - lastActivityNanos >= policy.bounds.idleTimeout.toNanos()) {
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
            subscription = null
            owner = null
            recorded = true
            if (active === this) active = null
        }
    }

    companion object {
        private const val MAXIMUM_INPUT_MESSAGES = 16
        private const val MAXIMUM_INPUT_PARTS = 16

        /** Still-unqualified adapter: only future explicit protected qualification may call this. */
        fun openForProtectedQualification(
            policy: AcpProviderTransportPolicy,
            admittedRequest: AgentExecutionRequest,
            enclosingRemaining: Duration,
            credentials: AcpProviderCredentialMaterial?,
        ): AcpProviderBroker {
            val startedNanos = System.nanoTime()
            val approved = policy as? AcpProviderTransportPolicy.Approved
                ?: throw AcpProviderBrokerFailure(AcpProviderTerminalKind.UNSUPPORTED_OPERATION)
            val secret = credentials ?: throw AcpProviderBrokerFailure(AcpProviderTerminalKind.AUTHENTICATION)
            requireValidProviderDeadline(enclosingRemaining, admittedRequest)
            val binding = AgentExecutionRequestBinding.capture(admittedRequest)
            val backend = CoreAcpProviderBackend(ChatGptAcpProviderNetworkAuthority(approved))
            return try {
                AcpProviderBroker(
                    approved, binding, admittedRequest.cancellation, secret,
                    enclosingRemaining, minOf(approved.bounds.maximumOutputTokens.toLong(), admittedRequest.limits.maxOutputTokens ?: approved.bounds.maximumOutputTokens.toLong()).toInt(),
                    admittedRequest.limits.maxInputTokens, backend, startedNanos,
                )
            } catch (failure: Exception) {
                if (!backend.closeWithin(approved.bounds.cleanupTimeout)) throw AcpProviderBrokerCleanupFailure()
                throw failure as? AcpProviderBrokerFailure ?: AcpProviderBrokerFailure(AcpProviderTerminalKind.TRANSPORT)
            }
        }

        /** Closed credential-free TLS building block; factory wiring is a later checkpoint. */
        internal fun openForCredentialFreeQualification(
            policy: AcpProviderTransportPolicy.CredentialFreeFixture,
            consumer: Any,
            admittedRequest: AgentExecutionRequest,
            enclosingRemaining: Duration,
        ): AcpProviderBroker {
            val startedNanos = System.nanoTime()
            requireValidProviderDeadline(enclosingRemaining, admittedRequest)
            val binding = AgentExecutionRequestBinding.capture(admittedRequest)
            val authorization = policy.syntheticAuthorization()
            val credentials = AcpProviderCredentialMaterial.cachedChatGpt(authorization, "credential_free_fixture_v1")
            val backend = CoreAcpProviderBackend.openFixture(policy, consumer)
            return try {
                AcpProviderBroker(
                    policy, binding, admittedRequest.cancellation, credentials,
                    enclosingRemaining, minOf(policy.bounds.maximumOutputTokens.toLong(), admittedRequest.limits.maxOutputTokens ?: policy.bounds.maximumOutputTokens.toLong()).toInt(),
                    admittedRequest.limits.maxInputTokens, backend, startedNanos,
                )
            } catch (failure: Exception) {
                if (!backend.closeWithin(policy.bounds.cleanupTimeout)) throw AcpProviderBrokerCleanupFailure()
                throw failure as? AcpProviderBrokerFailure ?: AcpProviderBrokerFailure(AcpProviderTerminalKind.TRANSPORT)
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
            val startedNanos = System.nanoTime()
            val approved = policy as? AcpProviderTransportPolicy.Approved
                ?: throw AcpProviderBrokerFailure(AcpProviderTerminalKind.UNSUPPORTED_OPERATION)
            val secret = credentials ?: throw AcpProviderBrokerFailure(AcpProviderTerminalKind.AUTHENTICATION)
            requireValidProviderDeadline(enclosingRemaining, admittedRequest)
            return AcpProviderBroker(
                approved, AgentExecutionRequestBinding.capture(admittedRequest), admittedRequest.cancellation, secret,
                enclosingRemaining, minOf(approved.bounds.maximumOutputTokens.toLong(), admittedRequest.limits.maxOutputTokens ?: approved.bounds.maximumOutputTokens.toLong()).toInt(),
                admittedRequest.limits.maxInputTokens, backend, startedNanos,
            )
        }
    }
}

internal class AcpProviderBrokerCleanupFailure : IOException("ACP provider broker cleanup was not verified")

/** No inherited proxy, authenticator, cookie jar, redirects, or body/error logging. */
internal data class AcpProviderConcreteBackendCleanupSnapshot(
    val transportTerminated: Boolean,
    val executorTerminated: Boolean,
    val requestFutureCount: Int,
    val terminalFutureCount: Int,
)

/** One owned connection and one HTTP exchange per request. No HttpClient recovery layer exists. */
private class CoreAcpProviderBackend(private val authority: AcpProviderNetworkAuthority) : AcpProviderBrokerTestBackend {
    private val authorityAdmission = authority.admitToBackend()
    private var fixtureBrokerClaimed = false
    private val closed = AtomicBoolean()
    private val executor: ExecutorService = ThreadPoolExecutor(
        2, 2, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(32),
        { task -> Thread(task, "decomp-acp-provider-http").also { it.isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )
    private val owners = Collections.synchronizedList(ArrayList<ProviderHttpAttempt>())
    private var retiredOwners = 0
    private fun retireFinishedOwners() {
        val iterator = owners.iterator()
        while (iterator.hasNext()) {
            val owner = iterator.next()
            if (owner.resourcesClosed() && owner.futureTerminal() && owner.executionFinished()) {
                retiredOwners++
                iterator.remove()
            }
        }
    }

    override fun start(request: AcpProviderBackendRequest, receiver: AcpProviderBackendReceiver): AcpProviderBackendRequestOwner {
        require(request.endpoint == authority.endpoint) { "provider network authority is unavailable" }
        if (closed.get()) throw AcpProviderBrokerFailure(AcpProviderTerminalKind.TRANSPORT)
        if (request.deadlineNanos - System.nanoTime() <= 0) throw AcpProviderBrokerFailure(AcpProviderTerminalKind.TIMEOUT)
        val content = request.body
        require(content.size <= authority.bounds.maximumRequestBytes) { "provider request exceeds admitted bound" }
        val wire = BasicClassicHttpRequest("POST", request.endpoint).also {
            it.version = HttpVersion.HTTP_1_1
            it.entity = ByteArrayEntity(content, ContentType.APPLICATION_JSON)
            it.setHeader("Accept", "text/event-stream")
            it.setHeader("Content-Type", "application/json")
            it.setHeader("Content-Length", content.size.toString())
            it.setHeader("Host", request.endpoint.rawAuthority)
            it.setHeader("User-Agent", "decomp-acp-provider-http/1")
            authority.authorize(it, request.credentials)
        }
        val owner = ProviderHttpAttempt(authority, request.deadlineNanos, wire, content, receiver)
        synchronized(owners) {
            if (closed.get()) throw AcpProviderBrokerFailure(AcpProviderTerminalKind.TRANSPORT)
            retireFinishedOwners()
            owners.add(owner)
        }
        // Install cancellation before a fast header callback can precede start's return.
        receiver.subscribe(owner)
        try { owner.attach(executor.submit(owner)) }
        catch (_: Exception) { owner.cancel(); owner.notSubmitted(); receiver.failed() }
        return owner
    }

    @Synchronized
    fun ownsFixtureAuthority(policy: AcpProviderTransportPolicy.CredentialFreeFixture): Boolean {
        if (fixtureBrokerClaimed || authority !is FixtureAcpProviderNetworkAuthority || authority.policy !== policy) return false
        fixtureBrokerClaimed = true
        return true
    }

    fun cleanupSnapshot(): AcpProviderConcreteBackendCleanupSnapshot = synchronized(owners) {
        retireFinishedOwners()
        AcpProviderConcreteBackendCleanupSnapshot(closed.get() && executor.isTerminated && owners.all { it.resourcesClosed() && it.executionFinished() },
            executor.isTerminated, retiredOwners + owners.size, retiredOwners + owners.count { it.futureTerminal() })
    }

    override fun closeWithin(timeout: Duration): Boolean {
        val started = System.nanoTime()
        closed.set(true)
        synchronized(owners) { owners.forEach { it.cancel() } }
        executor.shutdownNow()
        val terminated = executor.awaitTermination((timeout.toNanos() - (System.nanoTime() - started)).coerceAtLeast(0), TimeUnit.NANOSECONDS)
        return terminated && executor.isTerminated && synchronized(owners) {
            retireFinishedOwners()
            owners.all { it.resourcesClosed() && it.futureTerminal() && it.executionFinished() }
        }
    }

    companion object {
        fun openFixture(policy: AcpProviderTransportPolicy.CredentialFreeFixture, consumer: Any): CoreAcpProviderBackend =
            CoreAcpProviderBackend(FixtureAcpProviderNetworkAuthority.issue(policy, consumer))
    }
}

/** Fixed operation labels only; never retain the thrown exception or transport inputs. */
internal enum class AcpProviderCleanupOperation {
    CANCEL_RAW_CLOSE, FINAL_RAW_CLOSE, FINAL_CONNECTION_CLOSE, FINAL_TLS_CLOSE, FINAL_RESPONSE_CLOSE,
}

/** Private owner; none of its socket, resolver, TLS or request inputs is an operator capability. */
private class ProviderHttpAttempt(
    private val authority: AcpProviderNetworkAuthority,
    private val deadline: Long,
    wire: BasicClassicHttpRequest,
    private val requestBody: ByteArray,
    receiver: AcpProviderBackendReceiver,
) : AcpProviderBackendRequestOwner, Flow.Subscription, Runnable {
    private val wire = AtomicReference<BasicClassicHttpRequest?>(wire)
    private val receiver = AtomicReference<AcpProviderBackendReceiver?>(receiver)
    private val execution = java.util.concurrent.atomic.AtomicInteger(0) // queued, running, finished
    private val cleanupFailed = AtomicBoolean()
    private val firstCleanupFailure = AtomicReference<AcpProviderCleanupOperation?>()
    private fun recordCleanupFailure(operation: AcpProviderCleanupOperation) {
        firstCleanupFailure.compareAndSet(null, operation)
        cleanupFailed.set(true)
    }
    private val cancelled = AtomicBoolean()
    private val connectAdmitted = AtomicBoolean()
    private val raw = AtomicReference<Socket?>()
    private val tls = AtomicReference<SSLSocket?>()
    private val connection = AtomicReference<ProviderHttpConnection?>()
    private val demand = Object()
    private var outstanding = 0L
    @Volatile private var future: Future<*>? = null
    @Volatile private var rejected = false

    fun attach(value: Future<*>) { future = value; if (cancelled.get()) value.cancel(true) }
    fun notSubmitted() { rejected = true; finishQueued() }
    fun executionFinished(): Boolean = execution.get() == 2
    private fun eraseRequest() {
        wire.getAndSet(null)?.let { request -> request.setHeaders(); request.entity = null }
        requestBody.fill(0)
    }
    private fun finishQueued() {
        if (execution.compareAndSet(0, 2)) { eraseRequest(); receiver.set(null) }
    }
    fun futureTerminal(): Boolean = rejected || future?.isDone == true
    fun resourcesClosed(): Boolean = !cleanupFailed.get() &&
        raw.get()?.isClosed != false && tls.get()?.isClosed != false && connection.get()?.isOpen != true

    override fun request(n: Long) {
        if (n <= 0) { cancel(); return }
        synchronized(demand) { outstanding = minOf(Long.MAX_VALUE - outstanding, n) + outstanding; demand.notifyAll() }
    }

    override fun cancel() {
        cancelled.set(true)
        synchronized(demand) { demand.notifyAll() }
        // Closing the underlying socket aborts connect/handshake/read without HTTP/TLS draining.
        runCatching { raw.get()?.close() }.onFailure { recordCleanupFailure(AcpProviderCleanupOperation.CANCEL_RAW_CLOSE) }
        future?.cancel(true)
        finishQueued()
    }

    private fun activeMillis(): Int {
        if (cancelled.get() || Thread.currentThread().isInterrupted) throw IOException("provider exchange stopped")
        val remaining = deadline - System.nanoTime()
        if (remaining <= 0) throw SocketTimeoutException("provider exchange timed out")
        return minOf(TimeUnit.NANOSECONDS.toMillis(remaining).coerceAtLeast(1), Int.MAX_VALUE.toLong()).toInt()
    }

    /** Even an accidental second call cannot start another application connection. */
    private fun connectOnce(socket: Socket, address: InetSocketAddress) {
        if (!connectAdmitted.compareAndSet(false, true)) throw IOException("provider connection attempt refused")
        socket.connect(address, minOf(10_000, activeMillis()))
    }

    override fun run() {
        if (!execution.compareAndSet(0, 1)) return
        var response: ClassicHttpResponse? = null
        var outcome = AcpProviderTerminalKind.TRANSPORT
        val callback = receiver.get()
        try {
            activeMillis()
            // No ambient JVM/NSS lookup: named-host authority is refused until an authenticated,
            // invocation-owned terminable resolver can be composed under this exact deadline.
            val address = selectProviderAddress(arrayOf(authority.resolveAddress()))
            activeMillis()
            val socket = Socket(Proxy.NO_PROXY)
            raw.set(socket)
            activeMillis()
            socket.soTimeout = minOf(authority.bounds.idleTimeout.toMillis(), activeMillis().toLong()).coerceAtLeast(1).toInt()
            socket.tcpNoDelay = true
            connectOnce(socket, InetSocketAddress(address, if (authority.endpoint.port < 0) 443 else authority.endpoint.port))
            val secure = authority.tlsContext.socketFactory.createSocket(socket, authority.endpoint.host,
                if (authority.endpoint.port < 0) 443 else authority.endpoint.port, false) as SSLSocket
            tls.set(secure)
            activeMillis()
            secure.soTimeout = minOf(authority.bounds.idleTimeout.toMillis(), activeMillis().toLong()).coerceAtLeast(1).toInt()
            secure.sslParameters = secure.sslParameters.also {
                it.endpointIdentificationAlgorithm = "HTTPS"
                it.protocols = arrayOf("TLSv1.3", "TLSv1.2")
                it.applicationProtocols = emptyArray()
            }
            secure.startHandshake()
            activeMillis()
            val http = ProviderHttpConnection(authority.bounds)
            connection.set(http)
            http.bind(secure, socket)
            activeMillis()
            // Core has no request recovery, redirect, auth challenge or decompression layer.
            response = HttpRequestExecutor().execute(requireNotNull(wire.get()), http, HttpCoreContext.create())
            activeMillis()
            val headers = LinkedHashMap<String, MutableList<String>>()
            for (header in response.headers) headers.getOrPut(header.name.lowercase()) { ArrayList() }.add(header.value)
            callback?.headers(response.code, headers)
            activeMillis()
            val input = response.entity?.content ?: throw IOException("provider body unavailable")
            val buffer = ByteArray(authority.bounds.maximumChunkBytes)
            var observed = 0L
            while (true) {
                synchronized(demand) {
                    while (outstanding == 0L) demand.wait(minOf(25, activeMillis()).toLong())
                    outstanding--
                }
                activeMillis()
                val count = input.read(buffer, 0, minOf(buffer.size.toLong(), authority.bounds.maximumResponseBytes - observed + 1).toInt())
                if (count < 0) { outcome = AcpProviderTerminalKind.COMPLETED; break }
                if (count == 0 || count > authority.bounds.maximumResponseBytes - observed) throw IOException("provider body bound exceeded")
                observed += count
                callback?.bytes(listOf(ByteBuffer.wrap(buffer, 0, count).asReadOnlyBuffer()))
            }
        } catch (_: SocketTimeoutException) { outcome = AcpProviderTerminalKind.TIMEOUT }
        catch (_: Exception) { outcome = AcpProviderTerminalKind.TRANSPORT }
        finally {
            finishTransport(response, outcome, callback)
        }
    }
    private fun finishTransport(response: ClassicHttpResponse?, outcome: AcpProviderTerminalKind,
                                callback: AcpProviderBackendReceiver?) {
            // Close all transport owners before terminal callbacks can release broker admission.
            runCatching { raw.get()?.close() }.onFailure { recordCleanupFailure(AcpProviderCleanupOperation.FINAL_RAW_CLOSE) }
            runCatching { connection.get()?.close(CloseMode.IMMEDIATE) }.onFailure { recordCleanupFailure(AcpProviderCleanupOperation.FINAL_CONNECTION_CLOSE) }
            runCatching { tls.get()?.close() }.onFailure { recordCleanupFailure(AcpProviderCleanupOperation.FINAL_TLS_CLOSE) }
            runCatching { response?.close() }.onFailure { recordCleanupFailure(AcpProviderCleanupOperation.FINAL_RESPONSE_CLOSE) }
            if (raw.get()?.isClosed == true) raw.set(null)
            if (tls.get()?.isClosed == true) tls.set(null)
            if (connection.get()?.isOpen == false) connection.set(null)
            eraseRequest()
            receiver.set(null)
            try {
                when {
                    !resourcesClosed() -> callback?.failed()
                    outcome == AcpProviderTerminalKind.COMPLETED -> callback?.complete()
                    outcome == AcpProviderTerminalKind.TIMEOUT -> callback?.timedOut()
                    else -> callback?.failed()
                }
            } finally { execution.set(2) }
    }

}

private fun selectProviderAddress(addresses: Array<InetAddress>): InetAddress =
    addresses.firstOrNull() ?: throw IOException("provider address unavailable")

private fun providerHttp1Config(bounds: AcpProviderTransportBounds): Http1Config = Http1Config.custom()
    .setVersion(HttpVersion.HTTP_1_1).setBufferSize(1024).setChunkSizeHint(bounds.maximumChunkBytes)
    .setMaxLineLength(bounds.maximumHeaderBytes + 5).setMaxHeaderCount(bounds.maximumHeaderFields + 1)
    .setMaxEmptyLineCount(1).build()

private class ProviderHttpConnection(private val bounds: AcpProviderTransportBounds) : DefaultBHttpClientConnection(
    providerHttp1Config(bounds), null, null, null, null, null,
    object : HttpMessageParserFactory<ClassicHttpResponse> {
        override fun create(config: Http1Config): HttpMessageParser<ClassicHttpResponse> = HttpMessageParser { buffer, input ->
            val parsed = DefaultHttpResponseParser(providerHttp1Config(bounds)).parse(ProviderHeaderBuffer(buffer, bounds), input)
            if (parsed.version != HttpVersion.HTTP_1_1 || parsed.code !in 200..599) throw IOException("provider response framing refused")
            parsed
        }
    },
) {
    override fun close() = close(CloseMode.IMMEDIATE)
    override fun createContentInputStream(length: Long, buffer: SessionInputBuffer, input: InputStream): InputStream =
        ProviderBodyInputView(
            if (length == ContentLengthStrategy.CHUNKED) ChunkedInputStream(ProviderChunkMetadataBuffer(buffer, bounds), input, providerHttp1Config(bounds))
            else super.createContentInputStream(length, buffer, input),
        )
}

/** Transport owns the socket. Logical entity close must neither drain framing nor close transport. */
private class ProviderBodyInputView(private val framing: InputStream) : InputStream() {
    private val closed = AtomicBoolean(false)

    private fun requireOpen() {
        if (closed.get()) throw IOException("provider response body closed")
    }

    override fun read(): Int { requireOpen(); return framing.read() }
    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
        requireOpen()
        return framing.read(bytes, offset, length)
    }
    override fun skip(count: Long): Long { requireOpen(); return framing.skip(count) }
    override fun available(): Int { requireOpen(); return framing.available() }
    override fun close() { closed.set(true) }
}

/** Scratch is bounded by policy before the parser can retain a header or grow its header list. */
private class ProviderHeaderBuffer(private val source: SessionInputBuffer, private val bounds: AcpProviderTransportBounds) : SessionInputBuffer by source {
    private val scratch = CharArrayBuffer(maxOf(128, bounds.maximumHeaderBytes + 4))
    private var status = true
    private var fields = 0
    private var bytes = 0L
    private var rawHeaderCharacters = 0L
    override fun readLine(target: CharArrayBuffer, input: InputStream): Int {
        scratch.clear()
        val count = readProviderCrlfLine(source, input, scratch, if (status) 128 else bounds.maximumHeaderBytes + 3)
        if (status) {
            status = false
            if (count !in 12..128) throw IOException("provider status refused")
        } else if (count != 0) {
            if (scratch[0] == ' ' || scratch[0] == '\t') throw IOException("provider folded header refused")
            val colon = scratch.indexOf(':')
            if (colon <= 0) throw IOException("provider header refused")
            var start = colon + 1
            var end = scratch.length
            while (start < end && scratch[start] == ' ') start++
            while (end > start && scratch[end - 1] == ' ') end--
            fields++
            bytes += colon.toLong() + end - start
            if (fields > bounds.maximumHeaderFields || bytes > bounds.maximumHeaderBytes) throw IOException("provider header bound exceeded")
            // Core retains each raw line (including OWS). Bound that storage independently of
            // normalized name/value bytes, allowing fixed colon/OWS overhead per declared field.
            // CRLF adds at most another 2*F wire bytes; status/terminator are separately fixed.
            rawHeaderCharacters += count
            if (rawHeaderCharacters > bounds.maximumHeaderBytes.toLong() + 4L * bounds.maximumHeaderFields) {
                throw IOException("provider raw header bound exceeded")
            }
        }
        target.append(scratch)
        return count
    }
}

/** The library's lenient readLine discards CRLF/EOF proof, so bound and verify each wire line here. */
private fun readProviderCrlfLine(source: SessionInputBuffer, input: InputStream, target: CharArrayBuffer, maximum: Int): Int {
    while (true) {
        val next = source.read(input)
        if (next == 13) {
            if (source.read(input) != 10) throw IOException("provider line framing refused")
            return target.length
        }
        if (next !in 32..126 || target.length >= maximum) throw IOException("provider line framing refused")
        target.append(next.toChar())
    }
}

/** Bounded framing metadata; this closed adapter does not admit trailing response headers. */
private class ProviderChunkMetadataBuffer(private val source: SessionInputBuffer, private val bounds: AcpProviderTransportBounds) : SessionInputBuffer by source {
    private val scratch = CharArrayBuffer(bounds.maximumHeaderBytes + 4)
    private var bytes = 0L
    private var trailers = false
    override fun readLine(target: CharArrayBuffer, input: InputStream): Int {
        scratch.clear()
        val count = readProviderCrlfLine(source, input, scratch, bounds.maximumHeaderBytes)
        bytes += count.toLong() + 2
        if (bytes > bounds.maximumHeaderBytes || trailers && count != 0) throw IOException("provider chunk metadata refused")
        if (scratch.toString().substringBefore(';').trim().toLongOrNull(16) == 0L) trailers = true
        target.append(scratch)
        return count
    }
}

/** Distinct concrete authorities: fixture TLS never changes production default trust. */
private sealed class AcpProviderNetworkAuthority protected constructor() {
    abstract val endpoint: URI
    abstract fun resolveAddress(): InetAddress
    open fun admitToBackend() = Unit
    abstract val bounds: AcpProviderTransportBounds
    abstract val tlsContext: SSLContext
    abstract fun authorize(request: BasicClassicHttpRequest, credentials: AcpProviderCredentialMaterial)
}

private class ChatGptAcpProviderNetworkAuthority(policy: AcpProviderTransportPolicy.Approved) : AcpProviderNetworkAuthority() {
    override val endpoint: URI = policy.endpoint
    override val bounds = policy.bounds
    override val tlsContext: SSLContext = SSLContext.getDefault()
    init { require(endpoint == APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT) { "provider network authority is unavailable" } }
    // #1510 has not qualified runtime/context issuance for deadline-owned named-host DNS.
    // Reject before Core allocates its executor or can retain an authorized request.
    override fun admitToBackend(): Nothing = throw AcpProviderBrokerFailure(AcpProviderTerminalKind.UNSUPPORTED_OPERATION)
    override fun resolveAddress(): Nothing = throw AcpProviderBrokerFailure(AcpProviderTerminalKind.UNSUPPORTED_OPERATION)
    override fun authorize(request: BasicClassicHttpRequest, credentials: AcpProviderCredentialMaterial) {
        request.setHeader("Authorization", "Bearer ${credentials.accessToken}")
        request.setHeader("ChatGPT-Account-ID", credentials.accountId)
    }
}

private class FixtureAcpProviderNetworkAuthority(
    val policy: AcpProviderTransportPolicy.CredentialFreeFixture,
    private val authorization: String,
    provenance: Any,
) : AcpProviderNetworkAuthority() {
    init { require(hasProvenance(provenance)) { "fixture network authority is unavailable" } }
    override val endpoint: URI = policy.endpoint
    override val bounds = policy.bounds
    override fun resolveAddress(): InetAddress {
        require(endpoint.host == "127.0.0.1") { "fixture address is unavailable" }
        return InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    }
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
    override fun authorize(request: BasicClassicHttpRequest, credentials: AcpProviderCredentialMaterial) {
        require(credentials.accessToken == authorization && credentials.accountId == "credential_free_fixture_v1") {
            "fixture authorization is unavailable"
        }
        request.setHeader("Authorization", "Bearer $authorization")
    }
    override val tlsContext: SSLContext = createTlsContext()
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
