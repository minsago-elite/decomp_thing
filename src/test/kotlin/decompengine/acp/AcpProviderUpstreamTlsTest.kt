package decompengine.acp

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.SecureRandom
import java.time.Duration
import java.util.concurrent.TimeUnit
import javax.net.ssl.ExtendedSSLSession
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.KeyManager
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import kotlin.concurrent.thread
import kotlin.io.path.ExperimentalPathApi
import kotlin.io.path.deleteRecursively
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Credential-free loopback handshakes. Each identity is a throwaway self-signed key pair generated
 * by the JDK keytool under build/test-tmp at runtime and deleted afterwards.
 */
class AcpProviderUpstreamTlsTest {
    private val roots = mutableListOf<Path>()
    private val policy = AcpProviderTransportPolicy.fromOperatorPolicy(providerPolicyConfiguration()) as AcpProviderTransportPolicy.Approved

    @OptIn(ExperimentalPathApi::class)
    @AfterTest
    fun cleanUp() {
        roots.forEach { it.deleteRecursively() }
        roots.clear()
    }

    @Test
    fun `platform trust rejects an untrusted chain that names the policy host`() {
        TlsServer(identity("chatgpt.com")).use { server ->
            val plain = server.connectPlain()
            val failure = assertFailsWith<SSLHandshakeException> {
                AcpProviderUpstreamTls.platform(policy).handshake(plain, Duration.ofSeconds(15))
            }
            assertTrue(failure.causes().any { "PKIX path" in it.message.orEmpty() }, failure.toString())
            assertTrue(plain.isClosed)
        }
    }

    @Test
    fun `a trusted certificate that names another host is rejected`() {
        val wrongHost = identity("wrong.example")
        TlsServer(wrongHost).use { server ->
            val plain = server.connectPlain()
            val failure = assertFailsWith<SSLHandshakeException> {
                AcpProviderUpstreamTls.withTestTrustAnchors(policy, wrongHost.anchors()).handshake(plain, Duration.ofSeconds(15))
            }
            assertTrue(failure.causes().any { "subject alternative" in it.message.orEmpty().lowercase() }, failure.toString())
            assertTrue(plain.isClosed)
        }
    }

    @Test
    fun `a trusted certificate for the policy host completes a modern handshake with policy SNI`() {
        val rightHost = identity("chatgpt.com")
        TlsServer(rightHost).use { server ->
            AcpProviderUpstreamTls.withTestTrustAnchors(policy, rightHost.anchors()).handshake(server.connectPlain(), Duration.ofSeconds(15)).use { socket ->
                assertTrue(socket.session.protocol in setOf("TLSv1.3", "TLSv1.2"), socket.session.protocol)
                assertEquals("HTTPS", socket.sslParameters.endpointIdentificationAlgorithm)
                assertEquals(1, socket.inputStream.read())
            }
            assertEquals(listOf("chatgpt.com"), server.awaitServerNames())
        }
    }

    @Test
    fun `connect refuses unadmitted destinations before opening a socket`() {
        val tls = AcpProviderUpstreamTls.platform(policy)
        mapOf(
            "127.0.0.1" to AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED,
            "::1" to AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED,
            "169.254.169.254" to AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED,
            "10.0.0.1" to AcpProviderRouteRefusal.PRIVATE_DESTINATION_NOT_PERMITTED,
        ).forEach { (literal, reason) ->
            val failure = assertFailsWith<AcpProviderUpstreamRefusedException>(literal) {
                tls.connect(InetAddress.getByName(literal), Duration.ofMillis(200), Duration.ofMillis(200))
            }
            assertEquals(reason, failure.reason, literal)
        }
    }

    @Test
    fun `the factory accepts no caller trust manager hostname verifier or TLS context`() {
        val forbidden = listOf(
            TrustManager::class.java, KeyManager::class.java, HostnameVerifier::class.java, SSLContext::class.java,
            SSLSocketFactory::class.java, SSLParameters::class.java,
        )
        val owners = listOf(AcpProviderUpstreamTls::class.java, AcpProviderUpstreamTls.Companion::class.java)
        val parameterTypes = owners.flatMap { owner ->
            owner.declaredMethods.flatMap { it.parameterTypes.toList() } + owner.declaredConstructors.flatMap { it.parameterTypes.toList() }
        }
        parameterTypes.forEach { type -> assertTrue(forbidden.none { it.isAssignableFrom(type) || type.isArray && it.isAssignableFrom(type.componentType) }, type.name) }
    }

    private class Identity(val keyStore: KeyStore, val password: CharArray) {
        fun anchors(): KeyStore = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setCertificateEntry("anchor", keyStore.getCertificate("server"))
        }
    }

    private fun identity(host: String): Identity {
        val parent = Files.createDirectories(Path.of("build", "test-tmp", "acp-provider-tls").toAbsolutePath())
        val root = Files.createTempDirectory(parent, "identity-").also(roots::add)
        val store = root.resolve("identity.p12")
        val password = ByteArray(18).also(SecureRandom()::nextBytes).joinToString("") { "%02x".format(it) }
        val keytool = Path.of(System.getProperty("java.home"), "bin", "keytool")
        val process = ProcessBuilder(
            keytool.toString(), "-genkeypair", "-alias", "server", "-keyalg", "EC", "-groupname", "secp256r1",
            "-sigalg", "SHA256withECDSA", "-dname", "CN=$host", "-ext", "SAN=dns:$host", "-validity", "2",
            "-storetype", "PKCS12", "-keystore", store.toString(), "-storepass", password, "-keypass", password, "-noprompt",
        ).redirectErrorStream(true).redirectOutput(root.resolve("keytool.log").toFile())
            .also { it.environment().clear() }
            .start()
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), "keytool did not finish")
        assertEquals(0, process.exitValue(), Files.readString(root.resolve("keytool.log")))
        val keyStore = KeyStore.getInstance("PKCS12").apply { Files.newInputStream(store).use { load(it, password.toCharArray()) } }
        return Identity(keyStore, password.toCharArray())
    }

    private class TlsServer(identity: Identity) : AutoCloseable {
        private val listener: SSLServerSocket
        @Volatile private var serverNames: List<String>? = null
        private val worker: Thread

        init {
            val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(identity.keyStore, identity.password) }
            val context = SSLContext.getInstance("TLS").apply { init(keys.keyManagers, null, null) }
            listener = context.serverSocketFactory.createServerSocket(0, 1, InetAddress.getLoopbackAddress()) as SSLServerSocket
            listener.soTimeout = 15_000
            worker = thread(isDaemon = true, name = "provider-tls-fixture") {
                runCatching {
                    (listener.accept() as SSLSocket).use { socket ->
                        socket.soTimeout = 15_000
                        socket.startHandshake()
                        serverNames = (socket.session as ExtendedSSLSession).requestedServerNames.map { (it as SNIHostName).asciiName }
                        socket.outputStream.write(1)
                        socket.outputStream.flush()
                        socket.inputStream.read()
                    }
                }
            }
        }

        fun connectPlain(): Socket = Socket(Proxy.NO_PROXY).apply {
            connect(InetSocketAddress(InetAddress.getLoopbackAddress(), listener.localPort), 5_000)
        }

        fun awaitServerNames(): List<String>? {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
            while (serverNames == null && System.nanoTime() < deadline) Thread.onSpinWait()
            return serverNames
        }

        override fun close() {
            listener.close()
            worker.join(15_000)
        }
    }

    private fun Throwable.causes(): Sequence<Throwable> = generateSequence(this) { it.cause }
}
