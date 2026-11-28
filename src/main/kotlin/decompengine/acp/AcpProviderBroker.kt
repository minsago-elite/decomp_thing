package decompengine.acp

import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.builtin.provider.parseProviderObject
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
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import java.time.Duration
import java.util.Locale
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket

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

/**
 * Opens the verified TLS connection to the pinned numeric address. Production uses
 * [AcpProviderUpstreamTls.connect] with platform trust: a direct connection with no proxy, and the policy host,
 * never the address, as the TLS identity. Credential-free controls connect to a local server and then call
 * [AcpProviderUpstreamTls.handshake] with test trust anchors.
 */
internal fun interface AcpProviderUpstreamConnector {
    fun open(address: InetAddress, timeout: Duration): SSLSocket
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
 * from the agent's HTTP request, and the sequence reserves the frame: each value authorizes at most one upstream
 * request. [head] is the exact request-head bytes, ending with the empty line, and [body] the bytes after it.
 * Every field is untrusted.
 */
internal class AcpProviderChannelRequest(
    val sequence: Long,
    capability: ByteArray,
    head: ByteArray,
    body: ByteArray,
) {
    private val capabilityContent = capability.copyOf()
    private val headContent = head.copyOf()
    private val bodyContent = body.copyOf()
    internal fun capability(): ByteArray = capabilityContent.copyOf()
    internal fun head(): ByteArray = headContent.copyOf()
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
 * or prompt. Every forwarded request is rebuilt from policy-owned headers, the broker's credential headers and
 * the validated body, sent to the pinned numeric address over verified TLS for the policy host, and never
 * redirected.
 *
 * Deadlines and budgets (#960), revocation and typed provider outcomes (#961) and provenance (#962) extend this
 * owner. No production path opens one yet.
 */
internal class AcpProviderBroker private constructor(
    private val policy: AcpProviderTransportPolicy.Approved,
    private val credentialSource: AcpProviderCredentialSource,
    credential: AcpProviderCredential,
    private val destination: InetAddress,
    private val connector: AcpProviderUpstreamConnector,
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
            val routed = when (val decision = AcpProviderRouting.route(policy, request.head())) {
                is AcpProviderRouteDecision.Routed -> decision
                is AcpProviderRouteDecision.Refused ->
                    throw AcpProviderBrokerFailure(AcpProviderBrokerFailureKind.ROUTE_REFUSED, routeRefusal = decision.reason)
            }
            val body = validatedBody(routed, request.body(), credential)
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

    /** The exact body the routed head declared, as one strict JSON object that carries no channel secret. */
    private fun validatedBody(routed: AcpProviderRouteDecision.Routed, body: ByteArray, credential: AcpProviderCredential): ByteArray {
        // The frame's body must be exactly the length the routed head declared; the upstream framing uses it.
        if (body.size != routed.contentLength || body.isEmpty()) refuse(AcpProviderBrokerFailureKind.REQUEST_REFUSED)
        val document = try {
            parseProviderObject(brokerStrictUtf8(body), policy.bounds.maximumRequestBytes)
        } catch (_: Exception) {
            refuse(AcpProviderBrokerFailureKind.REQUEST_REFUSED)
        }
        // Decoded names and strings, so JSON escapes cannot carry the capability or a credential upstream.
        val secrets = synchronized(lock) { liveSecrets(credential) }
        if (containsSecret(document, secrets)) refuse(AcpProviderBrokerFailureKind.SECRET_EXPOSURE)
        // #960 adds the model, token and budget checks here.
        return body
    }

    private fun forward(
        routed: AcpProviderRouteDecision.Routed,
        body: ByteArray,
        credential: AcpProviderCredential,
        sequence: Long,
    ): AcpProviderExchangeResult {
        val tls = try {
            connector.open(destination, policy.bounds.idleTimeout)
        } catch (refused: AcpProviderUpstreamRefusedException) {
            throw AcpProviderBrokerFailure(AcpProviderBrokerFailureKind.DESTINATION_REFUSED, routeRefusal = refused.reason)
        } catch (_: SSLException) {
            refuse(AcpProviderBrokerFailureKind.TLS_REFUSED)
        } catch (_: IllegalStateException) {
            // The TLS client's own protocol check.
            refuse(AcpProviderBrokerFailureKind.TLS_REFUSED)
        } catch (_: Exception) {
            refuse(AcpProviderBrokerFailureKind.TRANSPORT)
        }
        synchronized(lock) {
            if (closed) {
                runCatching { tls.close() }
                refuse(AcpProviderBrokerFailureKind.CHANNEL_REFUSED)
            }
            upstream = tls
        }
        tls.use {
            try {
                val output = BufferedOutputStream(tls.outputStream, 16 * 1024)
                output.write(upstreamHead(routed, credential))
                output.write(body)
                output.flush()
                return readResponse(BufferedInputStream(tls.inputStream, 16 * 1024), routed, sequence, credential)
            } catch (failure: Exception) {
                // A close during the exchange shows up as an I/O error or an early EOF; report it as the closed channel.
                if (synchronized(lock) { closed }) refuse(AcpProviderBrokerFailureKind.CHANNEL_REFUSED)
                if (failure is AcpProviderBrokerFailure) throw failure
                refuse(AcpProviderBrokerFailureKind.TRANSPORT)
            }
        }
    }

    /**
     * The policy request line, the policy-owned header set for the validated length, then the broker's own
     * credential headers. Nothing from the agent's head is copied.
     */
    private fun upstreamHead(routed: AcpProviderRouteDecision.Routed, credential: AcpProviderCredential): ByteArray =
        buildString {
            append(routed.operation.method).append(' ').append(routed.endpoint.rawPath).append(" HTTP/1.1\r\n")
            (routed.upstreamHeaders() + credential.authorizationHeaders()).forEach { (name, value) ->
                append(name).append(": ").append(value).append("\r\n")
            }
            append("\r\n")
        }.toByteArray(StandardCharsets.US_ASCII)

    private fun readResponse(
        input: InputStream,
        routed: AcpProviderRouteDecision.Routed,
        sequence: Long,
        credential: AcpProviderCredential,
    ): AcpProviderExchangeResult {
        val head = ResponseHeadReader(input, policy.bounds)
        val status = head.statusLine()
        // A 3xx is refused before its headers are read, so no Location value is ever parsed or followed.
        AcpProviderRouting.responseStatusRefusal(policy, status)?.let { reason ->
            val kind = if (reason == AcpProviderRouteRefusal.REDIRECT_UNDECLARED) {
                AcpProviderBrokerFailureKind.REDIRECT_REFUSED
            } else AcpProviderBrokerFailureKind.MALFORMED_RESPONSE
            throw AcpProviderBrokerFailure(kind, routeRefusal = reason)
        }
        // Interim and protocol-switching responses are never expected: no Expect or Upgrade is sent.
        if (status < 200) refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
        val headers = head.fields()
        // Error bodies can echo request material. They are never read or forwarded; only the status is.
        if (status != 200) return AcpProviderExchangeResult(sequence, status, null, ByteArray(0))
        val mediaType = routed.operation.responseMediaType
        val contentTypes = headers.filter { (name, _) -> name == "content-type" }
        if (contentTypes.size != 1 || contentTypes.single().second.substringBefore(';').trim().lowercase(Locale.ROOT) != mediaType) {
            refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
        }
        val body = readResponseBody(input, headers, policy.bounds)
        val text = String(body, StandardCharsets.ISO_8859_1)
        val secrets = synchronized(lock) { liveSecrets(credential) }
        if (secrets.any { text.contains(it, ignoreCase = true) }) {
            body.fill(0)
            refuse(AcpProviderBrokerFailureKind.SECRET_EXPOSURE)
        }
        return AcpProviderExchangeResult(sequence, status, mediaType, body)
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
        ): AcpProviderBroker = open(policy, request, credentialSource, resolver, null, Clock.systemUTC())

        /**
         * Credential-free controls only: a connector that reaches a local server through the module TLS client
         * with test trust anchors, and a fixed clock. A null connector is production platform trust.
         */
        internal fun open(
            policy: AcpProviderTransportPolicy,
            request: AgentExecutionRequest,
            credentialSource: AcpProviderCredentialSource,
            resolver: AcpProviderDestinationResolver,
            connector: AcpProviderUpstreamConnector?,
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
            val upstream = connector ?: AcpProviderUpstreamTls.platform(approved).let { tls ->
                AcpProviderUpstreamConnector { address, timeout -> tls.connect(address, timeout, timeout) }
            }
            return AcpProviderBroker(
                approved, credentialSource, credential, destination, upstream, AgentExecutionRequestBinding.capture(request),
            )
        }

        private fun pinnedDestination(
            policy: AcpProviderTransportPolicy.Approved,
            resolver: AcpProviderDestinationResolver,
        ): InetAddress {
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
            return numeric.first()
        }
    }
}

private const val PROVIDER_CHANNEL_CAPABILITY_BYTES = 32
private const val MAXIMUM_PROVIDER_DESTINATION_ADDRESSES = 64
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

