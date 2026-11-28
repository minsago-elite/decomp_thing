package decompengine.acp

import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentWorkspaceRoot
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x509.Time
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.math.BigInteger
import java.net.InetAddress
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.Collections
import java.util.Date
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.ExtendedSSLSession
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

/**
 * Opens a broker through its private entry point with substitutable parts (connector, credential clock, relay
 * channel factory and delivery clock). Production code cannot reach that entry point; only these credential-free
 * controls do, by reflection, as the #958 TLS probe reaches the private layered handshake.
 */
internal fun openBrokerForControl(
    policy: AcpProviderTransportPolicy,
    request: AgentExecutionRequest,
    credentialSource: AcpProviderCredentialSource,
    resolver: AcpProviderDestinationResolver,
    connector: AcpProviderUpstreamConnector?,
    clock: java.time.Clock,
    relayChannels: AcpProviderRelayChannelFactory = AcpProviderRelayChannelFactory.PIPE,
    deliveryNanoTime: () -> Long = System::nanoTime,
): AcpProviderBroker {
    val entry = AcpProviderBroker.Companion::class.java.getDeclaredMethod(
        "openWith", AcpProviderTransportPolicy::class.java, AgentExecutionRequest::class.java,
        AcpProviderCredentialSource::class.java, AcpProviderDestinationResolver::class.java,
        AcpProviderUpstreamConnector::class.java, java.time.Clock::class.java, AcpProviderRelayChannelFactory::class.java,
        kotlin.jvm.functions.Function0::class.java,
    ).apply { isAccessible = true }
    return try {
        entry.invoke(AcpProviderBroker.Companion, policy, request, credentialSource, resolver, connector, clock,
            relayChannels, deliveryNanoTime) as AcpProviderBroker
    } catch (invocation: InvocationTargetException) {
        throw invocation.targetException
    }
}

/** Every fixture file lives under build/, so tests never write outside the repository. */
internal fun providerFixtureDirectory(label: String): Path {
    val parent = Files.createDirectories(Path.of("build", "test-tmp", "acp-provider-broker").toAbsolutePath())
    return Files.createTempDirectory(parent, "$label-")
}

internal fun providerFixtureRequest(): AgentExecutionRequest = AgentExecutionRequest(
    "provider broker fixture",
    listOf(AgentWorkspaceRoot("project", providerFixtureDirectory("workspace"))),
    accessPolicy = AgentAccessPolicy(emptyList()),
)

internal fun approvedProviderPolicy(vararg overrides: Pair<String, String>): AcpProviderTransportPolicy.Approved =
    AcpProviderTransportPolicy.fromOperatorPolicy(providerPolicyConfiguration() + overrides) as AcpProviderTransportPolicy.Approved

/** The exact request-head bytes a contained relay would pass on, ending with the empty line. */
internal fun relayHead(method: String, target: String, fields: List<Pair<String, String>>): ByteArray =
    (listOf("$method $target HTTP/1.1") + fields.map { (name, value) -> "$name: $value" })
        .joinToString("\r\n", postfix = "\r\n\r\n").toByteArray(StandardCharsets.US_ASCII)

/** A synthetic ChatGPT-shaped access token. It authenticates nothing: the signature segment is fixed text. */
internal fun syntheticAccessToken(expiry: Instant, marker: String = randomMarker()): String {
    val encoder = Base64.getUrlEncoder().withoutPadding()
    val header = encoder.encodeToString("""{"alg":"none","typ":"JWT"}""".toByteArray())
    val claims = encoder.encodeToString("""{"exp":${expiry.epochSecond},"fixture":"$marker"}""".toByteArray())
    return "$header.$claims.c3ludGhldGljLSR$marker"
}

internal fun randomMarker(): String = ByteArray(12).also(SecureRandom()::nextBytes).joinToString("") { "%02x".format(it) }

/** Writes a private synthetic Codex login cache and returns its Codex home. */
internal fun syntheticCodexHome(
    document: String,
    permissions: String = "rw-------",
): Path {
    val home = Files.createDirectories(providerFixtureDirectory("codex-home").resolve("codex"))
    // Explicit, so the host umask cannot make the directory group-writable.
    Files.setPosixFilePermissions(home, PosixFilePermissions.fromString("rwx------"))
    val file = home.resolve("auth.json")
    Files.writeString(file, document)
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString(permissions))
    return home
}

internal fun syntheticChatGptAuth(accessToken: String, accountId: String? = "acct_fixture-1"): String =
    """{"OPENAI_API_KEY":null,"tokens":{"id_token":"synthetic-id","access_token":"$accessToken",""" +
        """"refresh_token":"synthetic-refresh"${accountId?.let { ",\"account_id\":\"$it\"" } ?: ""}},"last_refresh":"2026-11-01T00:00:00Z"}"""

/** One runtime-generated test CA and a leaf certificate for [serverName], written under build/. */
internal class ProviderTestTls(serverName: String, issuer: ProviderTestTls? = null) {
    private val authorityKeys: KeyPair = issuer?.authorityKeys ?: ecKeyPair()
    val authority: X509Certificate = issuer?.authority ?: certificate("decomp provider test CA", authorityKeys.public.encoded,
        "decomp provider test CA", authorityKeys.private, authority = true, dnsName = null)
    private val leafKeys = ecKeyPair()
    private val leaf = certificate(serverName, leafKeys.public.encoded, "decomp provider test CA", authorityKeys.private,
        authority = false, dnsName = serverName)
    val directory: Path = providerFixtureDirectory("tls")

    /** The server's key and chain, for [LocalProviderServer]. */
    val serverStore: Path = directory.resolve("server.p12")

    init {
        Files.write(directory.resolve("authority.der"), authority.encoded)
        Files.write(directory.resolve("leaf.der"), leaf.encoded)
        val identity = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry("server", leafKeys.private, PROVIDER_FIXTURE_STORE_PASSWORD.toCharArray(), arrayOf(leaf, authority))
        }
        Files.newOutputStream(serverStore).use { identity.store(it, PROVIDER_FIXTURE_STORE_PASSWORD.toCharArray()) }
    }

    /** A trust store holding only this CA, for a scenario JVM's `javax.net.ssl.trustStore` properties. */
    fun writeTrustStore(): Path {
        val path = directory.resolve("roots.p12")
        val roots = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setCertificateEntry("authority", authority)
        }
        Files.newOutputStream(path).use { roots.store(it, PROVIDER_FIXTURE_STORE_PASSWORD.toCharArray()) }
        return path
    }

    private companion object {

        fun ecKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()

        fun certificate(
            subject: String,
            subjectPublicKey: ByteArray,
            issuer: String,
            issuerKey: PrivateKey,
            authority: Boolean,
            dnsName: String?,
        ): X509Certificate {
            val now = System.currentTimeMillis()
            val algorithm = AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256)
            val extensions = ExtensionsGenerator().apply {
                addExtension(Extension.basicConstraints, true, BasicConstraints(authority))
                addExtension(Extension.keyUsage, true,
                    KeyUsage(if (authority) KeyUsage.keyCertSign or KeyUsage.cRLSign else KeyUsage.digitalSignature))
                if (!authority) addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth))
                dnsName?.let { addExtension(Extension.subjectAlternativeName, false, GeneralNames(GeneralName(GeneralName.dNSName, it))) }
            }.generate()
            val tbs = V3TBSCertificateGenerator().apply {
                setSerialNumber(ASN1Integer(BigInteger(63, SecureRandom()).add(BigInteger.ONE)))
                setSignature(algorithm)
                setIssuer(X500Name("CN=$issuer"))
                setSubject(X500Name("CN=$subject"))
                setStartDate(Time(Date(now - 60_000)))
                setEndDate(Time(Date(now + 3_600_000)))
                setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(subjectPublicKey))
                setExtensions(extensions)
            }.generateTBSCertificate()
            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(issuerKey)
                update(tbs.encoded)
                sign()
            }
            val encoded = DERSequence(arrayOf(tbs, algorithm, DERBitString(signature))).encoded
            return CertificateFactory.getInstance("X.509").generateCertificate(encoded.inputStream()) as X509Certificate
        }
    }
}

internal const val PROVIDER_FIXTURE_STORE_PASSWORD = "fixture"

internal fun providerServerContext(store: Path): SSLContext {
    val password = PROVIDER_FIXTURE_STORE_PASSWORD.toCharArray()
    val identity = KeyStore.getInstance("PKCS12").apply { Files.newInputStream(store).use { load(it, password) } }
    val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(identity, password) }
    return SSLContext.getInstance("TLS").apply { init(keys.keyManagers, null, SecureRandom()) }
}

/** What the local provider server observed on one accepted connection. */
internal class ObservedProviderRequest(val serverNames: List<String>, val head: List<String>, val body: ByteArray)

/**
 * Local TLS server on 127.0.0.1 standing in for the provider. It records each connection's SNI, request head
 * and body, then writes the scripted raw response. It is never reachable through production resolution.
 */
internal class LocalProviderServer(
    serverStore: Path,
    private val response: (ObservedProviderRequest) -> ByteArray = { sseResponse(COMPLETED_EVENT) },
) : AutoCloseable {
    private val server = providerServerContext(serverStore).serverSocketFactory
        .createServerSocket(0, 8, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))) as SSLServerSocket
    val port: Int get() = server.localPort
    val accepted = AtomicInteger()
    val handshakes = AtomicInteger()
    val requests: MutableList<ObservedProviderRequest> = Collections.synchronizedList(ArrayList())
    /** When set, each response waits for this latch, so a test can observe a live upstream connection. */
    @Volatile var holdResponse: CountDownLatch? = null
    @Volatile var requestReceived = CountDownLatch(1)

    private val thread = Thread({
        while (!server.isClosed) {
            val socket = try { server.accept() as SSLSocket } catch (_: Exception) { break }
            accepted.incrementAndGet()
            socket.use { serve(it) }
        }
    }, "local-provider-server").apply { isDaemon = true; start() }

    private fun serve(socket: SSLSocket) {
        try {
            socket.soTimeout = 10_000
            socket.startHandshake()
            handshakes.incrementAndGet()
            val names = (socket.session as? ExtendedSSLSession)?.requestedServerNames.orEmpty()
                .map { (it as SNIHostName).asciiName }
            val input = socket.inputStream
            val head = readHead(input)
            val length = head.firstNotNullOfOrNull { line ->
                line.takeIf { it.startsWith("Content-Length:", ignoreCase = true) }?.substringAfter(':')?.trim()?.toInt()
            } ?: 0
            val observed = ObservedProviderRequest(names, head, input.readNBytes(length))
            requests += observed
            requestReceived.countDown()
            holdResponse?.await(10, TimeUnit.SECONDS)
            socket.outputStream.apply { write(response(observed)); flush() }
        } catch (_: Exception) {
            // A refused handshake or an aborted client is recorded only by the counters above.
        }
    }

    override fun close() {
        server.close()
        thread.join(5_000)
    }

    private companion object {
        fun readHead(input: InputStream): List<String> {
            val bytes = ByteArrayOutputStream()
            while (!bytes.toString(StandardCharsets.ISO_8859_1).endsWith("\r\n\r\n")) {
                val next = input.read()
                if (next < 0 || bytes.size() > 64 * 1024) break
                bytes.write(next)
            }
            return bytes.toString(StandardCharsets.ISO_8859_1).removeSuffix("\r\n\r\n").split("\r\n")
        }
    }
}

/** A minimal terminal event in the Responses streaming shape. */
internal const val COMPLETED_EVENT = "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_fixture\"}}\n\n"

internal fun sseResponse(events: String, framing: String = "length"): ByteArray {
    val body = events.toByteArray(StandardCharsets.UTF_8)
    val head = when (framing) {
        "chunked" -> "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n"
        else -> "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: ${body.size}\r\n\r\n"
    }
    val payload = if (framing == "chunked") {
        "%x\r\n".format(body.size).toByteArray() + body + "\r\n0\r\n\r\n".toByteArray()
    } else body
    return head.toByteArray(StandardCharsets.US_ASCII) + payload
}

internal fun rawResponse(text: String): ByteArray = text.toByteArray(StandardCharsets.ISO_8859_1)

/**
 * Records each pinned address the broker asks for and connects to the local server instead. The loopback server
 * is not an admissible `connect` destination, so this reaches the module client's private layered handshake by
 * reflection, as the #958 TLS probe does. Only the destination socket differs from production; trust, SNI and
 * host name verification are the production code.
 */
internal class LoopbackProviderConnector(private val serverPort: Int, private val tls: AcpProviderUpstreamTls) :
    AcpProviderUpstreamConnector {
    val addresses: MutableList<InetAddress> = Collections.synchronizedList(ArrayList())

    override fun open(address: InetAddress, timeout: Duration): SSLSocket {
        addresses += address
        val socket = Socket(Proxy.NO_PROXY)
        socket.connect(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), serverPort), timeout.toMillis().toInt())
        return try {
            HANDSHAKE.invoke(tls, socket, timeout) as SSLSocket
        } catch (invocation: InvocationTargetException) {
            throw invocation.targetException
        }
    }

    private companion object {
        val HANDSHAKE: Method = AcpProviderUpstreamTls::class.java
            .getDeclaredMethod("handshake", Socket::class.java, Duration::class.java)
            .apply { isAccessible = true }
    }
}

/** A synthetic #1510 resolver: fixed numeric answers and a call count. */
internal class FixedProviderResolver(private val addresses: List<InetAddress>) : AcpProviderDestinationResolver {
    val hosts: MutableList<String> = Collections.synchronizedList(ArrayList())

    override fun resolve(host: String): List<InetAddress> {
        hosts += host
        return addresses
    }
}

internal fun numericAddress(literal: String): InetAddress = InetAddress.getByName(literal).also {
    require(it.hostAddress != null && literal.all { char -> char.isDigit() || char in ".:abcdefABCDEF" }) { "fixture address must be numeric" }
}
