package decompengine.acp

import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadConstraints
import com.fasterxml.jackson.core.exc.StreamConstraintsException
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
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import java.time.Duration
import java.util.Locale
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
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
    LAUNCH_SOURCE_UNVERIFIED,
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

    init {
        // The reserved field has a fixed width; any other length is a malformed frame, refused at decode.
        if (capabilityContent.size != PROVIDER_CHANNEL_CAPABILITY_BYTES) refuse(AcpProviderBrokerFailureKind.CHANNEL_REFUSED)
    }
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
    // Not secret: where the credential came from, which no sandbox launch may make visible. Kept after close.
    private val credentialSourceIdentity: AcpProviderCredentialSourceIdentity = credential.source
    private var privateChannel: OutputStream? = null
    private var delivered = false
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

    /**
     * The only provider authority a contained agent receives: the broker's fresh random capability, bound to this
     * broker and so to one admitted invocation, one policy and one channel. It is written once to [channel], the
     * host-owned private stream to the contained relay. The broker takes ownership of that stream and closes it on
     * [close]. The capability is never an environment variable, argument or file, and a second delivery, or one
     * after close, is refused.
     *
     * The stream is reserved under the broker lock, but written outside it, so a stream that never drains cannot
     * stop [close] from revoking. The write gets a temporary copy, never the broker's own array, and the copy is
     * zeroed afterwards. If the write does not finish within the idle bound, the stream is closed. Delivery is
     * committed only if the broker is still open when the write finishes.
     */
    fun deliverChannelCapability(channel: OutputStream) {
        val copy = synchronized(lock) {
            if (closed || privateChannel != null) refuse(AcpProviderBrokerFailureKind.CHANNEL_REFUSED)
            // Reserved before the write: a failed delivery cannot be retried on another stream.
            privateChannel = channel
            capability.copyOf()
        }
        val written = try {
            writeWithinBound(channel, copy, policy.bounds.idleTimeout)
        } finally {
            copy.fill(0)
        }
        synchronized(lock) {
            if (written && !closed) {
                delivered = true
                return
            }
        }
        runCatching { channel.close() }
        refuse(AcpProviderBrokerFailureKind.CHANNEL_REFUSED)
    }

    /** Forwards one channel request. Nothing is sent upstream unless every check before it passes. */
    fun exchange(request: AcpProviderChannelRequest): AcpProviderExchangeResult {
        val credential = synchronized(lock) {
            if (closed || !delivered || !MessageDigest.isEqual(request.capability(), capability)) {
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
     * process. Every launch input that becomes the sandbox argv, environment or mount set is scanned for the
     * capability and credential values: the command, environment names and values, the working directory, both
     * sides of every read-only mount, the staging roots and the empty directories. Every host source the launch
     * makes visible (mount sources and staging roots) is then checked by [requireEffectiveLaunchCarriesNoProviderAuthority].
     */
    fun requireNoProviderAuthority(launch: AcpSandboxLaunch) {
        // A Path is itself Iterable<Path>, so each path is listed explicitly rather than added with `+`.
        val sources = launch.readOnlyMounts.map { it.source } + launch.stagingRoots.map { it.stagingRoot.path }
        val texts = launch.command + listOf(launch.workingDirectory.toString()) +
            launch.readOnlyMounts.flatMap { listOf(it.source.toString(), it.destination.toString()) } +
            launch.stagingRoots.map { it.stagingRoot.path.toString() } + launch.emptyDirectories.map(Path::toString)
        requireEffectiveLaunchCarriesNoProviderAuthority(texts, launch.environment, sources)
        // The working directory is a sandbox path, not a host source; it still may not name the credential source.
        if (pathOverlapsCredentialSource(launch.workingDirectory)) refuse(AcpProviderBrokerFailureKind.CREDENTIAL_SOURCE_VISIBLE)
    }

    /**
     * The same check on the final effective launch inputs: the exact argv a boundary will execute (for example
     * its bubblewrap command, including every bind path), the exact environment, and every host source it makes
     * visible. A boundary calls this before the inputs reach a command observer or launch evidence.
     *
     * It fails closed. Each source must resolve to a real path, must not overlap the credential source by path,
     * and is walked without following links, within [limits]. Every entry's device and inode is compared with the
     * credential file and its directory, and the source itself with their ancestors too. So a hard link or an
     * alternate bind anywhere below a source is refused. A source that cannot be resolved, an entry that cannot
     * be read, a tree beyond the limits or a directory at the depth limit refuses the launch with
     * `LAUNCH_SOURCE_UNVERIFIED`; an error never counts as admission.
     */
    fun requireEffectiveLaunchCarriesNoProviderAuthority(
        argv: List<String>,
        environment: Map<String, String>,
        sources: List<Path>,
        limits: AcpRuntimeClosureLimits = AcpRuntimeClosureLimits(),
    ) {
        val secrets = synchronized(lock) { if (closed) emptyList() else liveSecrets(credential) }
        val texts = argv + environment.keys + environment.values
        if (texts.any { text -> secrets.any { text.contains(it, ignoreCase = true) } }) {
            refuse(AcpProviderBrokerFailureKind.SECRET_EXPOSURE)
        }
        sources.forEach { source ->
            val real = try {
                source.toRealPath()
            } catch (_: Exception) {
                refuse(AcpProviderBrokerFailureKind.LAUNCH_SOURCE_UNVERIFIED)
            }
            if (pathOverlapsCredentialSource(source) || pathOverlapsCredentialSource(real)) {
                refuse(AcpProviderBrokerFailureKind.CREDENTIAL_SOURCE_VISIBLE)
            }
            requireSourceTreeExcludesCredential(real, limits)
        }
    }

    /**
     * The check bound to the objects a boundary actually mounts: the descriptors it pinned for its sources, held
     * open across the check and the mount. Each pinned source is walked through its descriptor, so a name swapped
     * after pinning is not what is checked. The boundary must call this with the descriptors it will mount and
     * must not release them before the mount. No boundary calls it yet (see the provider credential broker doc).
     */
    fun requirePinnedSourcesExcludeCredential(
        sources: List<LinuxDescriptor>,
        limits: AcpRuntimeClosureLimits = AcpRuntimeClosureLimits(),
    ) {
        sources.forEach { source ->
            source.whileOpen { fd ->
                val current = try {
                    LinuxFilesystemSyscalls.identity(fd)
                } catch (_: Exception) {
                    refuse(AcpProviderBrokerFailureKind.LAUNCH_SOURCE_UNVERIFIED)
                }
                if (current.key != source.identity.key || current.isSymbolicLink) {
                    refuse(AcpProviderBrokerFailureKind.LAUNCH_SOURCE_UNVERIFIED)
                }
                when {
                    // The trailing "." makes the kernel resolve the descriptor link, then walk the pinned object itself.
                    current.isDirectory -> requireSourceTreeExcludesCredential(Path.of("/proc/self/fd/$fd", "."), limits)
                    current.isRegularFile -> if (current.key == credentialSourceIdentity.file) {
                        refuse(AcpProviderBrokerFailureKind.CREDENTIAL_SOURCE_VISIBLE)
                    }
                    else -> refuse(AcpProviderBrokerFailureKind.LAUNCH_SOURCE_UNVERIFIED)
                }
            }
        }
    }

    /**
     * The credential file as a forbidden runtime file, for the boundary's own pin-time source walk
     * (`PinnedReadOnlyMount.pin`). That walk refuses an entry with the same device and inode, or with the same
     * size and content digest, so a hard link or a copy of the file below any mount is refused when the boundary
     * pins the exact object it mounts. Nothing here is secret.
     */
    internal fun credentialForbiddenRuntimeFiles(): Set<ForbiddenRuntimeFile> = setOf(
        ForbiddenRuntimeFile(
            credentialSourceIdentity.file.device, credentialSourceIdentity.file.inode,
            credentialSourceIdentity.fileBytes, credentialSourceIdentity.fileSha256,
        ),
    )

    private fun pathOverlapsCredentialSource(path: Path): Boolean {
        val absolute = path.toAbsolutePath().normalize()
        return credentialSource.hostPaths.any { absolute.startsWith(it) || it.startsWith(absolute) }
    }

    /** Walks one resolved source without following links, comparing every entry's identity. Fails closed. */
    private fun requireSourceTreeExcludesCredential(root: Path, limits: AcpRuntimeClosureLimits) {
        val inside = setOf(credentialSourceIdentity.file, credentialSourceIdentity.directory)
        var entries = 0
        var exposed = false
        var unverified = false
        fun check(path: Path, isRoot: Boolean) {
            if (++entries > limits.maximumEntries) {
                unverified = true
                return
            }
            val key = sourceEntryKey(path)
            if (key == null) unverified = true
            else if (key in inside || isRoot && key in credentialSourceIdentity.ancestors) exposed = true
        }
        try {
            Files.walkFileTree(root, emptySet(), limits.maximumDepth, object : SimpleFileVisitor<Path>() {
                override fun preVisitDirectory(directory: Path, attributes: BasicFileAttributes): FileVisitResult {
                    check(directory, directory == root)
                    return if (exposed || unverified) FileVisitResult.TERMINATE else FileVisitResult.CONTINUE
                }

                override fun visitFile(file: Path, attributes: BasicFileAttributes): FileVisitResult {
                    // A directory reported here lies at the depth limit, so its children were not checked.
                    if (attributes.isDirectory) unverified = true else check(file, file == root)
                    return if (exposed || unverified) FileVisitResult.TERMINATE else FileVisitResult.CONTINUE
                }

                override fun visitFileFailed(file: Path, failure: IOException): FileVisitResult {
                    unverified = true
                    return FileVisitResult.TERMINATE
                }

                override fun postVisitDirectory(directory: Path, failure: IOException?): FileVisitResult {
                    if (failure != null) unverified = true
                    return if (unverified) FileVisitResult.TERMINATE else FileVisitResult.CONTINUE
                }
            })
        } catch (_: Exception) {
            unverified = true
        }
        if (exposed) refuse(AcpProviderBrokerFailureKind.CREDENTIAL_SOURCE_VISIBLE)
        if (unverified) refuse(AcpProviderBrokerFailureKind.LAUNCH_SOURCE_UNVERIFIED)
    }

    /**
     * Drops the credential, zeroes the capability (the only copy), closes the private channel stream and aborts an
     * in-flight upstream connection.
     */
    override fun close() {
        val (inflight, channel) = synchronized(lock) {
            if (closed) return
            closed = true
            credential = null
            capability.fill(0)
            (upstream to privateChannel).also { upstream = null }
        }
        runCatching { channel?.close() }
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
        val nested = NestedJsonBound(policy.bounds.maximumRequestBytes, AcpProviderBrokerFailureKind.REQUEST_REFUSED)
        if (exposesSecret(document, secrets, NESTED_JSON_LAYERS, nested)) refuse(AcpProviderBrokerFailureKind.SECRET_EXPOSURE)
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
        // A 3xx is refused before any header, including Location, is parsed, so none is ever followed.
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
        // Identity coding only, so the bytes checked below are the bytes the agent decodes.
        if (headers.any { (name, value) -> name == "content-encoding" && !value.equals("identity", ignoreCase = true) }) {
            refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
        }
        val mediaType = routed.operation.responseMediaType
        val contentTypes = headers.filter { (name, _) -> name == "content-type" }
        if (contentTypes.size != 1 || contentTypes.single().second.substringBefore(';').trim().lowercase(Locale.ROOT) != mediaType) {
            refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
        }
        val body = readResponseBody(input, headers, policy.bounds)
        val secrets = synchronized(lock) { liveSecrets(credential) }
        try {
            requireSafeEventStream(body, secrets, policy.bounds)
        } catch (failure: AcpProviderBrokerFailure) {
            body.fill(0)
            throw failure
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

/**
 * Whether a decoded JSON value carries a secret in any name or string. A string that is itself a JSON object or
 * array is scanned once more as a nested document ([nestedDocumentExposes]) while [nestedLayers] remain.
 */
private fun exposesSecret(value: JsonElement, secrets: List<String>, nestedLayers: Int, bound: NestedJsonBound): Boolean =
    when (value) {
        is JsonObject -> value.any { (name, child) ->
            secrets.any { name.contains(it, ignoreCase = true) } || exposesSecret(child, secrets, nestedLayers, bound)
        }
        is JsonArray -> value.any { exposesSecret(it, secrets, nestedLayers, bound) }
        is JsonPrimitive -> secrets.any { value.content.contains(it, ignoreCase = true) } ||
            value.isString && nestedLayers > 0 && nestedDocumentExposes(value.content, secrets, bound)
    }

/** A nested document's bound in UTF-8 bytes, and the refusal when it is JSON but cannot be verified. */
private class NestedJsonBound(val maximumBytes: Int, val unverifiable: AcpProviderBrokerFailureKind)

/**
 * Scans [text] as one nested JSON document when it is a JSON object or array. Every decoded field name, string and
 * number is matched as the parser streams, so a duplicate key cannot hide a value, and anything decoded before a
 * later syntax error is still matched.
 *
 * Text that does not start like a JSON object or array, or that is not well-formed JSON, is a plain string and
 * has no nested document: false. A document whose UTF-8 size exceeds the policy bound, or that exceeds a depth,
 * token, name, string or number limit, cannot be verified and refuses with [NestedJsonBound.unverifiable]; it is
 * never skipped.
 */
private fun nestedDocumentExposes(text: String, secrets: List<String>, bound: NestedJsonBound): Boolean {
    val trimmed = text.trim()
    if (trimmed.isEmpty() || trimmed[0] != '{' && trimmed[0] != '[') return false
    // Bytes, not UTF-16 characters: non-ASCII text is longer in UTF-8 than its character count.
    val document = trimmed.toByteArray(StandardCharsets.UTF_8)
    if (document.size > bound.maximumBytes) refuse(bound.unverifiable)
    val factory = JsonFactory.builder().streamReadConstraints(
        StreamReadConstraints.builder().maxNestingDepth(64).maxDocumentLength(bound.maximumBytes.toLong())
            .maxStringLength(bound.maximumBytes).maxNameLength(minOf(bound.maximumBytes, 8192)).maxNumberLength(128)
            .maxTokenCount(100_000).build(),
    ).build()
    return try {
        factory.createParser(document).use { parser ->
            var exposed = false
            while (!exposed) {
                val token = parser.nextToken() ?: break
                val value = when (token) {
                    JsonToken.FIELD_NAME -> parser.currentName()
                    JsonToken.VALUE_STRING, JsonToken.VALUE_NUMBER_INT, JsonToken.VALUE_NUMBER_FLOAT -> parser.text
                    else -> null
                }
                exposed = value != null && secrets.any { value.contains(it, ignoreCase = true) }
            }
            exposed
        }
    } catch (_: StreamConstraintsException) {
        refuse(bound.unverifiable)
    } catch (_: JsonProcessingException) {
        // Not well-formed JSON: a plain string, already matched as text by the caller.
        false
    } catch (_: Exception) {
        refuse(bound.unverifiable)
    }
}

/**
 * Validates the bounded event stream the agent will consume before any of it is released.
 *
 * Scope: this scan is defense in depth against accidental reflection of the credential, such as a provider error
 * or a model echoing a header. It does not defend against an adversarial provider, and no pattern scan can,
 * because such a provider could encode the value (in base64, for example). The approved provider is inside the
 * trust model. The primary guarantee is structural: the agent never holds the credential and never receives it
 * through the broker interface, because the credential lives only in the host broker and is written only into
 * upstream request headers.
 *
 * Framing: strict UTF-8 with LF or CRLF line ends and no byte-order mark, only `data`, `event`, `id` and `retry`
 * fields or comments, every event ended by an empty line, and one strict JSON object as each event's data. The
 * supported Responses event shapes are validated ([requireSupportedEventShape]); other event types are allowed and
 * scanned generically.
 *
 * Secrets are matched in the raw text, every field value and comment, and every decoded JSON name and string,
 * including one more decoded layer for strings that are themselves JSON (function-call and MCP arguments and
 * outputs, in deltas, `*.done` events and completed items). Deltas are joined as a consumer joins them: per event
 * type and `item_id`, and per (`item_id`, `content_index`) or (`item_id`, `summary_index`) for content deltas, in
 * arrival order when those keys are absent, plus every delta in arrival order. Each joined value is matched as
 * text and, when it is JSON, one decoded layer deeper.
 */
private fun requireSafeEventStream(body: ByteArray, secrets: List<String>, bounds: AcpProviderTransportBounds) {
    fun exposes(value: CharSequence) = secrets.any { value.contains(it, ignoreCase = true) }
    val text = try { brokerStrictUtf8(body) } catch (_: Exception) { refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE) }
    if (exposes(text)) refuse(AcpProviderBrokerFailureKind.SECRET_EXPOSURE)
    if (text.isEmpty()) return
    val normalized = text.replace("\r\n", "\n")
    if ('\r' in normalized || normalized.startsWith('\uFEFF') || !normalized.endsWith("\n\n")) {
        refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
    }
    val nested = NestedJsonBound(bounds.maximumResponseBytes, AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
    val streams = LinkedHashMap<String, StringBuilder>()
    val allDeltas = StringBuilder()
    val data = StringBuilder()
    var hasData = false
    for (line in normalized.removeSuffix("\n").split('\n')) {
        if (line.isEmpty()) {
            if (hasData) {
                val event = try {
                    parseProviderObject(data.toString(), bounds.maximumResponseBytes)
                } catch (_: Exception) {
                    refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
                }
                requireSupportedEventShape(event)
                if (exposesSecret(event, secrets, NESTED_JSON_LAYERS, nested)) refuse(AcpProviderBrokerFailureKind.SECRET_EXPOSURE)
                (event["delta"] as? JsonPrimitive)?.takeIf { it.isString }?.let { delta ->
                    streams.getOrPut(deltaStreamKey(event)) { StringBuilder() }.append(delta.content)
                    allDeltas.append(delta.content)
                }
            }
            data.setLength(0)
            hasData = false
            continue
        }
        if (exposes(line)) refuse(AcpProviderBrokerFailureKind.SECRET_EXPOSURE)
        if (line.startsWith(':')) continue
        val colon = line.indexOf(':')
        val name = if (colon < 0) line else line.substring(0, colon)
        val value = if (colon < 0) "" else line.substring(colon + 1).removePrefix(" ")
        when (name) {
            "data" -> {
                if (hasData) data.append('\n')
                data.append(value)
                hasData = true
            }
            "event", "id", "retry" -> Unit
            else -> refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
        }
    }
    (streams.values + allDeltas).forEach { joined ->
        if (exposes(joined) || NESTED_JSON_LAYERS > 0 && nestedDocumentExposes(joined.toString(), secrets, nested)) {
            refuse(AcpProviderBrokerFailureKind.SECRET_EXPOSURE)
        }
    }
}

/** One decoded layer below a JSON string field that itself carries JSON. */
private const val NESTED_JSON_LAYERS = 1

/**
 * The consumer's join key for a delta: the event type and `item_id`, plus `content_index` or `summary_index` for
 * content deltas. Absent keys are empty, so such deltas join in arrival order. Function-call and MCP argument
 * deltas join per item.
 */
private fun deltaStreamKey(event: JsonObject): String {
    val type = (event["type"] as? JsonPrimitive)?.content.orEmpty()
    val item = (event["item_id"] as? JsonPrimitive)?.content.orEmpty()
    val index = if (type in ARGUMENT_DELTA_TYPES) "" else {
        ((event["content_index"] ?: event["summary_index"]) as? JsonPrimitive)?.content.orEmpty()
    }
    return listOf(type, item, index).joinToString("\u0000")
}

private val ARGUMENT_DELTA_TYPES = setOf("response.function_call_arguments.delta", "response.mcp_call_arguments.delta")
private val CONTENT_DELTA_TYPES = setOf("response.output_text.delta", "response.refusal.delta")
private val TEXT_DONE_TYPES = setOf("response.output_text.done", "response.reasoning_text.done", "response.reasoning_summary_text.done")
private val ARGUMENT_DONE_TYPES = setOf("response.function_call_arguments.done", "response.mcp_call_arguments.done")
private val ITEM_EVENT_TYPES = setOf("response.output_item.added", "response.output_item.done")
private val RESPONSE_EVENT_TYPES = setOf(
    "response.created", "response.in_progress", "response.completed", "response.failed", "response.incomplete",
)

/**
 * The shapes of the supported Responses streaming events, checked only for the fields a consumer reads. An
 * event without a type, or with a type outside this set, is allowed and scanned generically.
 */
private fun requireSupportedEventShape(event: JsonObject) {
    val type = event["type"] ?: return
    if (type !is JsonPrimitive || !type.isString) refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
    fun string(name: String, required: Boolean) {
        val value = event[name]
        if (value == null) {
            if (required) refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
        } else if (value !is JsonPrimitive || !value.isString) refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
    }
    fun indexes() = listOf("output_index", "content_index", "summary_index").forEach { name ->
        val value = event[name] ?: return@forEach
        if (value !is JsonPrimitive || value.isString || value.content.toLongOrNull()?.let { it >= 0 } != true) {
            refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
        }
    }
    fun objectField(name: String): JsonObject =
        event[name] as? JsonObject ?: refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
    val name = type.content
    when {
        name in ARGUMENT_DELTA_TYPES || name in CONTENT_DELTA_TYPES ||
            name.startsWith("response.reasoning") && name.endsWith(".delta") -> {
            string("delta", required = true)
            string("item_id", required = false)
            indexes()
        }
        name in TEXT_DONE_TYPES -> {
            string("text", required = true)
            string("item_id", required = false)
            indexes()
        }
        name in ARGUMENT_DONE_TYPES -> {
            string("arguments", required = true)
            string("item_id", required = false)
            indexes()
        }
        name in ITEM_EVENT_TYPES -> {
            val item = objectField("item")
            if ((item["type"] as? JsonPrimitive)?.isString != true) refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE)
            item["arguments"]?.let { if (it !is JsonPrimitive || !it.isString) refuse(AcpProviderBrokerFailureKind.MALFORMED_RESPONSE) }
            indexes()
        }
        name in RESPONSE_EVENT_TYPES -> objectField("response")
    }
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
                    if (++bytes > bounds.maximumHeaderBytes) refuse(AcpProviderBrokerFailureKind.RESPONSE_TOO_LARGE)
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

/** An entry's device and inode, read without following a link; null when it cannot be read. */
private fun sourceEntryKey(path: Path): LinuxFileKey? = try {
    val attributes = Files.readAttributes(path, "unix:dev,ino", LinkOption.NOFOLLOW_LINKS)
    LinuxFileKey((attributes.getValue("dev") as Number).toLong(), (attributes.getValue("ino") as Number).toLong())
} catch (_: Exception) {
    null
}

/**
 * Writes and flushes [bytes] on the caller's thread. A watchdog closes [channel] if that does not finish within
 * [bound], which also unblocks a write stuck on a stream that never drains. True only if the write finished first.
 */
private fun writeWithinBound(channel: OutputStream, bytes: ByteArray, bound: Duration): Boolean {
    val state = AtomicInteger(DELIVERY_WRITING)
    val finished = CountDownLatch(1)
    val watchdog = Thread({
        try {
            if (!finished.await(bound.toNanos(), TimeUnit.NANOSECONDS) && state.compareAndSet(DELIVERY_WRITING, DELIVERY_TIMED_OUT)) {
                runCatching { channel.close() }
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }, "decomp-acp-provider-channel-delivery").apply { isDaemon = true }
    watchdog.start()
    return try {
        channel.write(bytes)
        channel.flush()
        state.compareAndSet(DELIVERY_WRITING, DELIVERY_FINISHED)
    } catch (_: Exception) {
        false
    } finally {
        finished.countDown()
    }
}

private const val DELIVERY_WRITING = 0
private const val DELIVERY_FINISHED = 1
private const val DELIVERY_TIMED_OUT = 2

private fun brokerStrictUtf8(bytes: ByteArray): String = StandardCharsets.UTF_8.newDecoder()
    .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
    .decode(ByteBuffer.wrap(bytes)).toString()

private fun brokerSha256(value: String): String =
    MessageDigest.getInstance("SHA-256").digest(value.toByteArray(StandardCharsets.UTF_8)).brokerHex()

private fun ByteArray.brokerHex(): String = joinToString("") { "%02x".format(it) }

