package decompengine.acp

import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.builtin.provider.boundedProviderJson
import decompengine.builtin.provider.parseProviderObject
import decompengine.builtin.provider.writeProviderValue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import java.util.Locale
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

enum class AcpProviderBrokerFailureKind {
    TRANSPORT_DISABLED,
    CREDENTIAL_UNAVAILABLE,
    DESTINATION_REFUSED,
    CHANNEL_REFUSED,
    ROUTE_REFUSED,
    REQUEST_REFUSED,
    SECRET_EXPOSURE,
    CREDENTIAL_SOURCE_VISIBLE,
    TLS_REFUSED,
    REDIRECT_REFUSED,
    MALFORMED_RESPONSE,
    RESPONSE_TOO_LARGE,
    TRANSPORT,
}

/**
 * A typed broker refusal. The message is fixed text built only from enum names. It never carries a credential,
 * capability, host path, request or response byte, and it never retains a cause.
 */
internal class AcpProviderBrokerFailure(
    val kind: AcpProviderBrokerFailureKind,
    val routeRefusal: AcpProviderRouteRefusal? = null,
    val credentialFailure: AcpProviderCredentialFailure? = null,
) : IOException(
    "ACP provider broker refused: ${kind.name}" +
        (routeRefusal?.let { " ($it)" } ?: "") + (credentialFailure?.let { " ($it)" } ?: ""),
)

/**
 * Resolves the approved endpoint host to numeric addresses for one broker. The protected resolver and its
 * runtime profile are #1510 and are not on master, so production has no resolver and refuses to open.
 */
internal fun interface AcpProviderDestinationResolver {
    fun resolve(host: String): List<InetAddress>

    companion object {
        val UNAVAILABLE = AcpProviderDestinationResolver { throw IOException("provider destination resolver is unavailable") }
    }
}

/** Opens the TCP connection to the pinned numeric destination. Production connects directly, never via a proxy. */
internal fun interface AcpProviderDialer {
    fun connect(destination: InetSocketAddress, timeoutMillis: Int): Socket

    companion object {
        val DIRECT = AcpProviderDialer { destination, timeoutMillis ->
            check(!destination.isUnresolved) { "provider destination is not a pinned address" }
            val socket = Socket(Proxy.NO_PROXY)
            try {
                socket.connect(destination, timeoutMillis)
            } catch (failure: Exception) {
                socket.close()
                throw failure
            }
            socket
        }
    }
}

/**
 * Upstream TLS layered on the connected socket: PKIX trust, SNI and HTTPS hostname verification for the policy
 * host, TLS 1.3 or 1.2, and no ALPN. Production uses the platform trust store; only the trust anchors differ for
 * credential-free controls.
 */
internal class AcpProviderUpstreamTls private constructor(private val context: SSLContext) {
    fun handshake(socket: Socket, policy: AcpProviderTransportPolicy.Approved): SSLSocket {
        val tls = context.socketFactory.createSocket(socket, policy.endpoint.host, PROVIDER_HTTPS_PORT, true) as SSLSocket
        try {
            val parameters = AcpProviderRouting.upstreamSslParameters(policy, tls.sslParameters)
            AcpProviderRouting.requireMandatoryUpstreamTls(policy, parameters)
            tls.sslParameters = parameters
            tls.startHandshake()
        } catch (failure: Exception) {
            tls.close()
            throw failure
        }
        return tls
    }

    companion object {
        fun platform(): AcpProviderUpstreamTls = withTrustStore(null)

        /** Credential-free controls only: the same PKIX and hostname checks against test trust anchors. */
        internal fun withTrustAnchors(trustAnchors: KeyStore): AcpProviderUpstreamTls = withTrustStore(trustAnchors)

        private fun withTrustStore(store: KeyStore?): AcpProviderUpstreamTls {
            val trust = TrustManagerFactory.getInstance("PKIX").apply { init(store) }
            return AcpProviderUpstreamTls(SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) })
        }
    }
}

/**
 * The only provider authority a contained agent receives: a fresh random capability bound to one broker, and so
 * to one admitted invocation, one policy and one channel. It is handed over once and written only to the
 * host-owned private channel stream. It is never an environment variable, argument or file, so processes cannot
 * inherit it through ancestry or find it through filesystem visibility.
 */
internal class AcpProviderChannelGrant internal constructor(capability: ByteArray, val invocationBindingSha256: String) {
    private val content = capability.copyOf()

    /** Writes the capability to the private channel stream. Never pass a log, archive or process stream here. */
    fun writeTo(output: OutputStream) = output.write(content)

    override fun toString(): String = "AcpProviderChannelGrant(<redacted>)"
}

/**
 * One request frame received on the private channel. The capability occupies the frame's reserved field, apart
 * from the agent's HTTP head and body, and the sequence reserves the frame: each value authorizes at most one
 * upstream request. Every field is untrusted.
 */
internal class AcpProviderChannelRequest(
    val sequence: Long,
    capability: ByteArray,
    val head: AcpProviderRelayRequest,
    body: ByteArray,
) {
    private val capabilityContent = capability.copyOf()
    private val bodyContent = body.copyOf()
    internal fun capability(): ByteArray = capabilityContent.copyOf()
    internal fun body(): ByteArray = bodyContent.copyOf()

    override fun toString(): String = "AcpProviderChannelRequest(sequence=$sequence, <untrusted>)"
}

/** The bounded response returned on the channel. Error bodies and upstream headers are never forwarded. */
internal class AcpProviderExchangeResult(val sequence: Long, val status: Int, val contentType: String?, body: ByteArray) {
    private val content = body.copyOf()
    val body: ByteArray get() = content.copyOf()

    override fun toString(): String = "AcpProviderExchangeResult(sequence=$sequence, status=$status, bodyBytes=${content.size})"
}

/** Credential-free identity that evidence may retain (#962): references and digests only. */
internal data class AcpProviderBrokerIdentity(
    val policyDescriptorSha256: String,
    val invocationBindingSha256: String,
    val requestBindingSha256: String,
    val authenticationMechanism: AcpProviderAuthMechanism,
    val credentialReference: AcpProviderCredentialReference,
)

/**
 * Host-side provider broker for one admitted invocation. It alone holds the credential and the upstream
 * authority. [open] resolves the credential and pins the destination before the caller starts any ACP session
 * or prompt. Every forwarded request is rebuilt from broker-owned values and the validated body, sent to the
 * pinned numeric address over verified TLS for the policy host, and never redirected.
 *
 * Deadlines and budgets (#960), revocation and typed provider outcomes (#961) and provenance (#962) extend this
 * owner. No production path opens one yet.
 */
internal class AcpProviderBroker private constructor(
    private val policy: AcpProviderTransportPolicy.Approved,
    private val credentialSource: AcpProviderCredentialSource,
    credential: AcpProviderCredential,
    private val destination: InetSocketAddress,
    private val dialer: AcpProviderDialer,
    private val upstreamTls: AcpProviderUpstreamTls,
    requestBinding: AgentExecutionRequestBinding,
) : AutoCloseable {
    private val lock = Any()
    private val capability = ByteArray(PROVIDER_CHANNEL_CAPABILITY_BYTES).also(SecureRandom()::nextBytes)
    private var credential: AcpProviderCredential? = credential
    private var granted = false
    private var closed = false
    private var nextSequence = 1L
    private var exchangeActive = false
    private var upstream: Socket? = null

    val identity: AcpProviderBrokerIdentity = AcpProviderBrokerIdentity(
        policyDescriptorSha256 = policy.descriptorSha256,
        invocationBindingSha256 = brokerSha256(
            "acp-provider-invocation-v1\n${policy.descriptorSha256}\n${requestBinding.requestSha256}\n" +
                ByteArray(32).also(SecureRandom()::nextBytes).brokerHex() + "\n",
        ),
        requestBindingSha256 = requestBinding.requestSha256,
        authenticationMechanism = policy.authenticationMechanism,
        credentialReference = policy.credentialReference,
    )

    /** Transfers the channel capability once, for the private channel setup. */
    fun grantChannel(): AcpProviderChannelGrant = synchronized(lock) {
        if (closed || granted) refuse(AcpProviderBrokerFailureKind.CHANNEL_REFUSED)
        granted = true
        AcpProviderChannelGrant(capability, identity.invocationBindingSha256)
    }

    /** Forwards one channel request. Nothing is sent upstream unless every check before it passes. */
    fun exchange(request: AcpProviderChannelRequest): AcpProviderExchangeResult {
        val credential = synchronized(lock) {
            if (closed || !granted || !MessageDigest.isEqual(request.capability(), capability)) {
                refuse(AcpProviderBrokerFailureKind.CHANNEL_REFUSED)
            }
            // One outstanding request. The sequence is consumed here, whether or not the request is forwarded.
            if (request.sequence != nextSequence || exchangeActive) refuse(AcpProviderBrokerFailureKind.CHANNEL_REFUSED)
            nextSequence++
            exchangeActive = true
            this.credential ?: refuse(AcpProviderBrokerFailureKind.CHANNEL_REFUSED)
        }
        try {
            val routed = when (val decision = AcpProviderRouting.route(policy, request.head)) {
                is AcpProviderRouteDecision.Routed -> decision
                is AcpProviderRouteDecision.Refused ->
                    throw AcpProviderBrokerFailure(AcpProviderBrokerFailureKind.ROUTE_REFUSED, routeRefusal = decision.reason)
            }
            val body = validatedBody(request.head, request.body(), credential)
            return forward(routed, body, credential, request.sequence)
        } finally {
            synchronized(lock) {
                exchangeActive = false
                upstream = null
            }
        }
    }

    /**
     * Refuses a sandbox launch that would carry provider authority into an agent, terminal, candidate or analyzed
     * process: the channel capability or a credential value in its arguments, environment or working directory,
     * or a mount, staging root or working directory that exposes the credential source or a parent of it.
     */
    fun requireNoProviderAuthority(launch: AcpSandboxLaunch) {
        val secrets = synchronized(lock) { if (closed) emptyList() else liveSecrets(credential) }
        val texts = launch.command + launch.environment.keys + launch.environment.values + launch.workingDirectory.toString()
        if (texts.any { text -> secrets.any { text.contains(it, ignoreCase = true) } }) {
            refuse(AcpProviderBrokerFailureKind.SECRET_EXPOSURE)
        }
        val protectedPaths = credentialSource.hostPaths
        // A Path is itself Iterable<Path>, so each visible path is listed explicitly rather than added with `+`.
        val visible = (launch.readOnlyMounts.map { it.source } + launch.stagingRoots.map { it.stagingRoot.path } + listOf(launch.workingDirectory))
            .flatMap { path -> listOfNotNull(path.toAbsolutePath().normalize(), runCatching { path.toRealPath() }.getOrNull()) }
        if (visible.any { path -> protectedPaths.any { path.startsWith(it) || it.startsWith(path) } }) {
            refuse(AcpProviderBrokerFailureKind.CREDENTIAL_SOURCE_VISIBLE)
        }
    }

    /** Drops the credential, invalidates the capability and aborts an in-flight upstream connection. */
    override fun close() {
        val inflight = synchronized(lock) {
            if (closed) return
            closed = true
            credential = null
            capability.fill(0)
            upstream.also { upstream = null }
        }
        runCatching { inflight?.close() }
    }

    override fun toString(): String = "AcpProviderBroker(policyDescriptorSha256=${policy.descriptorSha256}, <redacted>)"

    private fun liveSecrets(credential: AcpProviderCredential?): List<String> =
        listOf(capability.brokerHex()) + credential?.secretValues().orEmpty()

    private fun validatedBody(head: AcpProviderRelayRequest, body: ByteArray, credential: AcpProviderCredential): ByteArray {
        // The channel frame delimits the body. Agent framing headers are checked against it and never forwarded.
        if (head.headers.any { (name, _) -> name.equals("transfer-encoding", ignoreCase = true) }) {
            refuse(AcpProviderBrokerFailureKind.REQUEST_REFUSED)
        }
        head.headers.singleOrNull { (name, _) -> name.equals("content-length", ignoreCase = true) }?.let { (_, value) ->
            val declared = value.trim()
            if (!declared.matches(CANONICAL_DECIMAL) || declared.toLongOrNull() != body.size.toLong()) {
                refuse(AcpProviderBrokerFailureKind.REQUEST_REFUSED)
            }
        }
        if (body.isEmpty() || body.size > policy.bounds.maximumRequestBytes) refuse(AcpProviderBrokerFailureKind.REQUEST_REFUSED)
        val document = try {
            parseProviderObject(brokerStrictUtf8(body), policy.bounds.maximumRequestBytes)
        } catch (_: Exception) {
            refuse(AcpProviderBrokerFailureKind.REQUEST_REFUSED)
        }
        // Decoded names and strings, so JSON escapes cannot carry the capability or a credential upstream.
        val secrets = synchronized(lock) { liveSecrets(credential) }
        if (containsSecret(document, secrets)) refuse(AcpProviderBrokerFailureKind.SECRET_EXPOSURE)
        // #960 adds the model, token and budget checks here, before the body is encoded again.
        return try {
            boundedProviderJson(policy.bounds.maximumRequestBytes) { it.writeProviderValue(document) }
        } catch (_: Exception) {
            refuse(AcpProviderBrokerFailureKind.REQUEST_REFUSED)
        }
    }

    private fun forward(
        routed: AcpProviderRouteDecision.Routed,
        body: ByteArray,
        credential: AcpProviderCredential,
        sequence: Long,
    ): AcpProviderExchangeResult {
        val timeoutMillis = minOf(policy.bounds.idleTimeout.toMillis(), Int.MAX_VALUE.toLong()).toInt()
        val raw = try {
            dialer.connect(destination, timeoutMillis)
        } catch (_: Exception) {
            refuse(AcpProviderBrokerFailureKind.TRANSPORT)
        }
        synchronized(lock) {
            if (closed) {
                runCatching { raw.close() }
                refuse(AcpProviderBrokerFailureKind.CHANNEL_REFUSED)
            }
            upstream = raw
        }
        raw.use {
            try {
                raw.soTimeout = timeoutMillis
                raw.tcpNoDelay = true
            } catch (_: Exception) {
                refuse(AcpProviderBrokerFailureKind.TRANSPORT)
            }
            val tls = try {
                upstreamTls.handshake(raw, policy)
            } catch (_: Exception) {
                refuse(AcpProviderBrokerFailureKind.TLS_REFUSED)
            }
            tls.use {
                try {
                    val output = BufferedOutputStream(tls.outputStream, 16 * 1024)
                    output.write(upstreamHead(routed, body.size, credential))
                    output.write(body)
                    output.flush()
                    return readResponse(BufferedInputStream(tls.inputStream, 16 * 1024), sequence, credential)
                } catch (failure: AcpProviderBrokerFailure) {
                    throw failure
                } catch (_: Exception) {
                    refuse(AcpProviderBrokerFailureKind.TRANSPORT)
                }
            }
        }
    }

    /** Broker-owned request line and headers. Nothing from the agent's head is copied. */
    private fun upstreamHead(routed: AcpProviderRouteDecision.Routed, contentLength: Int, credential: AcpProviderCredential): ByteArray {
        val fields = buildList {
            add("Host" to routed.endpoint.host)
            addAll(credential.authorizationHeaders())
            add("Content-Type" to "application/json")
            add("Accept" to "text/event-stream")
            add("Content-Length" to contentLength.toString())
            add("User-Agent" to PROVIDER_BROKER_USER_AGENT)
            add("Connection" to "close")
        }
        return buildString {
            append(routed.operation.method).append(' ').append(routed.endpoint.rawPath).append(" HTTP/1.1\r\n")
            fields.forEach { (name, value) -> append(name).append(": ").append(value).append("\r\n") }
            append("\r\n")
        }.toByteArray(StandardCharsets.US_ASCII)
    }

    private fun readResponse(input: InputStream, sequence: Long, credential: AcpProviderCredential): AcpProviderExchangeResult {
        val head = ResponseHeadReader(input, policy.bounds)
        val status = head.statusLine()
        // A 3xx is refused before its headers are read, so no Location value is ever parsed or followed.
        AcpProviderRouting.responseStatusRefusal(policy, status)?.let { reason ->
            val kind = if (reason == AcpProviderRouteRefusal.REDIRECT_UNDECLARED) {
                AcpProviderBrokerFailureKind.REDIRECT_REFUSED
            } else AcpProviderBrokerFailureKind.MALFORMED_RESPONSE
            throw AcpProviderBrokerFailure(kind, routeRefusal = reason)
        }
        // Interim and protocol-switching responses are never expected: the broker sends no Expect or Upgrade.
        if (status < 200) refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
        val headers = head.fields()
        // Error bodies can echo request material. They are never read or forwarded; only the status is.
        if (status != 200) return AcpProviderExchangeResult(sequence, status, null, ByteArray(0))
        val contentTypes = headers.filter { (name, _) -> name == "content-type" }
        if (contentTypes.size != 1 ||
            contentTypes.single().second.substringBefore(';').trim().lowercase(Locale.ROOT) != PROVIDER_STREAM_MEDIA_TYPE
        ) refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
        val body = readResponseBody(input, headers, policy.bounds)
        val text = String(body, StandardCharsets.ISO_8859_1)
        val secrets = synchronized(lock) { liveSecrets(credential) }
        if (secrets.any { text.contains(it, ignoreCase = true) }) {
            body.fill(0)
            refuse(AcpProviderBrokerFailureKind.SECRET_EXPOSURE)
        }
        return AcpProviderExchangeResult(sequence, status, PROVIDER_STREAM_MEDIA_TYPE, body)
    }

    companion object {
        /**
         * Opens the broker for one admitted invocation, before the caller starts any ACP session or prompt. The
         * credential is resolved first, with no network activity. The destination is then resolved once, every
         * address is checked against the policy, and the first is pinned as a numeric address for the broker's
         * lifetime. Production has no #1510 resolver yet, so this refuses with `DESTINATION_REFUSED`.
         */
        fun open(
            policy: AcpProviderTransportPolicy,
            request: AgentExecutionRequest,
            credentialSource: AcpProviderCredentialSource,
            resolver: AcpProviderDestinationResolver = AcpProviderDestinationResolver.UNAVAILABLE,
        ): AcpProviderBroker = open(
            policy, request, credentialSource, resolver, AcpProviderDialer.DIRECT, AcpProviderUpstreamTls.platform(), Clock.systemUTC(),
        )

        /** Credential-free controls only: a loopback dialer, test trust anchors and a fixed clock. */
        internal fun open(
            policy: AcpProviderTransportPolicy,
            request: AgentExecutionRequest,
            credentialSource: AcpProviderCredentialSource,
            resolver: AcpProviderDestinationResolver,
            dialer: AcpProviderDialer,
            upstreamTls: AcpProviderUpstreamTls,
            clock: Clock,
        ): AcpProviderBroker {
            val approved = policy as? AcpProviderTransportPolicy.Approved
                ?: refuse(AcpProviderBrokerFailureKind.TRANSPORT_DISABLED)
            if (credentialSource.reference != approved.credentialReference) {
                throw AcpProviderBrokerFailure(
                    AcpProviderBrokerFailureKind.CREDENTIAL_UNAVAILABLE,
                    credentialFailure = AcpProviderCredentialFailure.MECHANISM_UNSUPPORTED,
                )
            }
            val credential = try {
                credentialSource.resolve(clock.instant())
            } catch (failure: AcpProviderCredentialUnavailable) {
                throw AcpProviderBrokerFailure(AcpProviderBrokerFailureKind.CREDENTIAL_UNAVAILABLE, credentialFailure = failure.failure)
            } catch (_: Exception) {
                refuse(AcpProviderBrokerFailureKind.CREDENTIAL_UNAVAILABLE)
            }
            val destination = pinnedDestination(approved, resolver)
            return AcpProviderBroker(
                approved, credentialSource, credential, destination, dialer, upstreamTls, AgentExecutionRequestBinding.capture(request),
            )
        }

        private fun pinnedDestination(
            policy: AcpProviderTransportPolicy.Approved,
            resolver: AcpProviderDestinationResolver,
        ): InetSocketAddress {
            val resolved = try {
                resolver.resolve(policy.endpoint.host)
            } catch (_: Exception) {
                refuse(AcpProviderBrokerFailureKind.DESTINATION_REFUSED)
            }
            if (resolved.size > MAXIMUM_PROVIDER_DESTINATION_ADDRESSES) refuse(AcpProviderBrokerFailureKind.DESTINATION_REFUSED)
            // Keep only the address bytes: nothing later re-resolves a name or makes a reverse lookup.
            val numeric = resolved.map { InetAddress.getByAddress(it.address) }
            AcpProviderRouting.destinationRefusal(policy, numeric)?.let {
                throw AcpProviderBrokerFailure(AcpProviderBrokerFailureKind.DESTINATION_REFUSED, routeRefusal = it)
            }
            return InetSocketAddress(numeric.first(), PROVIDER_HTTPS_PORT)
        }
    }
}

private const val PROVIDER_CHANNEL_CAPABILITY_BYTES = 32
private const val PROVIDER_HTTPS_PORT = 443
private const val MAXIMUM_PROVIDER_DESTINATION_ADDRESSES = 64
private const val PROVIDER_STREAM_MEDIA_TYPE = "text/event-stream"
private const val PROVIDER_BROKER_USER_AGENT = "decomp-acp-provider-broker/1"
private val CANONICAL_DECIMAL = Regex("0|[1-9][0-9]{0,9}")
private val RESPONSE_STATUS_LINE = Regex("HTTP/1\\.1 ([1-5][0-9]{2})(?: [\\t -~]*)?")
private val RESPONSE_FIELD_NAME = Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+")

private fun refuse(kind: AcpProviderBrokerFailureKind): Nothing = throw AcpProviderBrokerFailure(kind)

private fun containsSecret(value: JsonElement, secrets: List<String>): Boolean = when (value) {
    is JsonObject -> value.any { (name, child) -> secrets.any { name.contains(it, ignoreCase = true) } || containsSecret(child, secrets) }
    is JsonArray -> value.any { containsSecret(it, secrets) }
    is JsonPrimitive -> secrets.any { value.content.contains(it, ignoreCase = true) }
}

/** Strict HTTP/1.1 response head: CRLF line endings, no folding, bounded fields and bytes. */
private class ResponseHeadReader(private val input: InputStream, private val bounds: AcpProviderTransportBounds) {
    private var bytes = 0L

    fun statusLine(): Int {
        val line = readLine() ?: throw AcpProviderBrokerFailure(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
        val match = RESPONSE_STATUS_LINE.matchEntire(line) ?: refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
        return match.groupValues[1].toInt()
    }

    /** Lowercase names in received order. */
    fun fields(): List<Pair<String, String>> {
        val fields = ArrayList<Pair<String, String>>()
        while (true) {
            val line = readLine() ?: refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
            if (line.isEmpty()) return fields
            if (fields.size >= bounds.maximumHeaderFields) refuse(AcpProviderBrokerFailureKind.RESPONSE_TOO_LARGE)
            val colon = line.indexOf(':')
            if (colon <= 0 || !line.substring(0, colon).matches(RESPONSE_FIELD_NAME)) {
                refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
            }
            fields += line.substring(0, colon).lowercase(Locale.ROOT) to line.substring(colon + 1).trim(' ', '\t')
        }
    }

    private fun readLine(): String? {
        val line = StringBuilder()
        while (true) {
            val next = input.read()
            if (next < 0) return if (line.isEmpty() && bytes == 0L) null else refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
            if (++bytes > bounds.maximumHeaderBytes) refuse(AcpProviderBrokerFailureKind.RESPONSE_TOO_LARGE)
            when {
                next == '\r'.code -> {
                    if (input.read() != '\n'.code) refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
                    bytes++
                    return line.toString()
                }
                next == '\t'.code || next in 0x20..0x7e -> line.append(next.toChar())
                else -> refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
            }
        }
    }
}

/** Content-Length, chunked without trailers, or close-delimited; always within the response bound. */
private fun readResponseBody(input: InputStream, headers: List<Pair<String, String>>, bounds: AcpProviderTransportBounds): ByteArray {
    val limit = bounds.maximumResponseBytes
    val transferEncodings = headers.filter { it.first == "transfer-encoding" }
    val contentLengths = headers.filter { it.first == "content-length" }
    return when {
        transferEncodings.isNotEmpty() -> {
            if (transferEncodings.size != 1 || !transferEncodings.single().second.equals("chunked", ignoreCase = true) ||
                contentLengths.isNotEmpty()
            ) refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
            readChunkedBody(input, limit)
        }
        contentLengths.isNotEmpty() -> {
            val declared = contentLengths.singleOrNull()?.second?.takeIf { it.matches(CANONICAL_DECIMAL) }?.toLongOrNull()
                ?: refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
            if (declared > limit) refuse(AcpProviderBrokerFailureKind.RESPONSE_TOO_LARGE)
            val body = input.readNBytes(declared.toInt())
            if (body.size.toLong() != declared) refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
            body
        }
        else -> input.readNBytes(limit + 1).also { if (it.size > limit) refuse(AcpProviderBrokerFailureKind.RESPONSE_TOO_LARGE) }
    }
}

private fun readChunkedBody(input: InputStream, limit: Int): ByteArray {
    val body = ByteArrayOutputStream()
    while (true) {
        val size = readChunkLine(input).takeIf { it.matches(Regex("[0-9A-Fa-f]{1,8}")) }?.toLong(16)
            ?: refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
        if (size == 0L) {
            // No trailer fields: the terminating chunk is followed directly by the final CRLF.
            if (readChunkLine(input).isNotEmpty()) refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
            return body.toByteArray()
        }
        if (size > limit - body.size()) refuse(AcpProviderBrokerFailureKind.RESPONSE_TOO_LARGE)
        val chunk = input.readNBytes(size.toInt())
        if (chunk.size.toLong() != size || readChunkLine(input).isNotEmpty()) refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
        body.write(chunk)
    }
}

private fun readChunkLine(input: InputStream): String {
    val line = StringBuilder()
    while (line.length <= 16) {
        when (val next = input.read()) {
            '\r'.code -> {
                if (input.read() != '\n'.code) refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
                return line.toString()
            }
            in 0x21..0x7e -> line.append(next.toChar())
            else -> refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
        }
    }
    refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
}

private fun brokerStrictUtf8(bytes: ByteArray): String = StandardCharsets.UTF_8.newDecoder()
    .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
    .decode(ByteBuffer.wrap(bytes)).toString()

private fun brokerSha256(value: String): String =
    MessageDigest.getInstance("SHA-256").digest(value.toByteArray(StandardCharsets.UTF_8)).brokerHex()

private fun ByteArray.brokerHex(): String = joinToString("") { "%02x".format(it) }

