package decompengine.acp

import java.net.InetAddress
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
 * by the JDK keytool under build/test-tmp at runtime and deleted afterwards. The client runs in a
 * forked JVM whose only trust customization is the standard `javax.net.ssl.trustStore` properties.
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
            val result = probe(server.port, trustStore = null)
            assertTrue(result.startsWith("HANDSHAKE_FAILED type=javax.net.ssl.SSLHandshakeException closed=true "), result)
            assertTrue("PKIX path" in result, result)
        }
    }

    @Test
    fun `a configured root does not trust a different chain for the policy host`() {
        val trusted = identity("chatgpt.com")
        TlsServer(identity("chatgpt.com")).use { server ->
            val result = probe(server.port, trustStore = trustStore(trusted))
            assertTrue(result.startsWith("HANDSHAKE_FAILED type=javax.net.ssl.SSLHandshakeException closed=true "), result)
            assertTrue("PKIX path" in result, result)
        }
    }

    @Test
    fun `a certificate trusted through the configured root but naming another host is rejected`() {
        val wrongHost = identity("wrong.example")
        TlsServer(wrongHost).use { server ->
            val result = probe(server.port, trustStore = trustStore(wrongHost))
            assertTrue(result.startsWith("HANDSHAKE_FAILED type=javax.net.ssl.SSLHandshakeException closed=true "), result)
            assertTrue("subject alternative" in result.lowercase(), result)
        }
    }

    @Test
    fun `a trusted certificate for the policy host completes a modern handshake with policy SNI`() {
        val rightHost = identity("chatgpt.com")
        TlsServer(rightHost).use { server ->
            val result = probe(server.port, trustStore = trustStore(rightHost))
            assertTrue(Regex("HANDSHAKE_OK protocol=TLSv1\\.[23] identification=HTTPS byte=1").matches(result), result)
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
    fun `connect is the only entry point and no member accepts trust material or a TLS context`() {
        val forbidden = listOf(
            KeyStore::class.java, TrustManager::class.java, KeyManager::class.java, HostnameVerifier::class.java,
            SSLContext::class.java, SSLSocketFactory::class.java, SSLParameters::class.java,
        )
        val owners = listOf(AcpProviderUpstreamTls::class.java, AcpProviderUpstreamTls.Companion::class.java)
        val parameterTypes = owners.flatMap { owner ->
            owner.declaredMethods.flatMap { it.parameterTypes.toList() } + owner.declaredConstructors.flatMap { it.parameterTypes.toList() }
        }
        parameterTypes.forEach { type ->
            val element = if (type.isArray) type.componentType else type
            assertTrue(forbidden.none { it.isAssignableFrom(element) }, type.name)
        }
        val publicMembers = AcpProviderUpstreamTls::class.java.declaredMethods
            .filter { java.lang.reflect.Modifier.isPublic(it.modifiers) && !it.isSynthetic }
            .map { it.name }
        assertEquals(listOf("connect"), publicMembers)
        // Kotlin adds a synthetic accessor constructor for the companion; it takes only the policy.
        assertTrue(AcpProviderUpstreamTls::class.java.declaredConstructors.none { java.lang.reflect.Modifier.isPublic(it.modifiers) && !it.isSynthetic })
    }

    private class Identity(val keyStore: KeyStore, val password: CharArray, val root: Path)

    private fun identity(host: String): Identity {
        val parent = Files.createDirectories(Path.of("build", "test-tmp", "acp-provider-tls").toAbsolutePath())
        val root = Files.createTempDirectory(parent, "identity-").also(roots::add)
        val store = root.resolve("identity.p12")
        val password = randomPassword()
        val log = root.resolve("keytool.log")
        val process = ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "keytool").toString(), "-genkeypair", "-alias", "server",
            "-keyalg", "EC", "-groupname", "secp256r1", "-sigalg", "SHA256withECDSA", "-dname", "CN=$host",
            "-ext", "SAN=dns:$host", "-validity", "2", "-storetype", "PKCS12", "-keystore", store.toString(),
            "-storepass", password, "-keypass", password, "-noprompt",
        ).redirectErrorStream(true).redirectOutput(log.toFile()).also { it.environment().clear() }.start()
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), "keytool did not finish")
        assertEquals(0, process.exitValue(), Files.readString(log))
        val keyStore = KeyStore.getInstance("PKCS12").apply { Files.newInputStream(store).use { load(it, password.toCharArray()) } }
        return Identity(keyStore, password.toCharArray(), root)
    }

    private class TrustStoreFile(val path: Path, val password: String)

    private fun trustStore(anchor: Identity): TrustStoreFile {
        val password = randomPassword()
        val path = anchor.root.resolve("roots.p12")
        val store = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setCertificateEntry("anchor", anchor.keyStore.getCertificate("server"))
        }
        Files.newOutputStream(path).use { store.store(it, password.toCharArray()) }
        return TrustStoreFile(path, password)
    }

    /** Runs [AcpProviderUpstreamTlsProbe] in a fresh JVM and returns its single result line. */
    private fun probe(port: Int, trustStore: TrustStoreFile?): String {
        val log = Files.createTempFile(roots.first(), "probe-", ".log")
        val trustProperties = trustStore?.let {
            listOf(
                "-Djavax.net.ssl.trustStore=${it.path}", "-Djavax.net.ssl.trustStoreType=PKCS12",
                "-Djavax.net.ssl.trustStorePassword=${it.password}",
            )
        }.orEmpty()
        val process = ProcessBuilder(
            listOf(Path.of(System.getProperty("java.home"), "bin", "java").toString()) + trustProperties +
                listOf("-cp", System.getProperty("java.class.path"), AcpProviderUpstreamTlsProbe::class.java.name, port.toString()),
        ).redirectErrorStream(true).redirectOutput(log.toFile()).also { it.environment().clear() }.start()
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), "TLS probe JVM did not finish")
        val output = Files.readAllLines(log)
        assertEquals(0, process.exitValue(), output.joinToString("\n"))
        return output.single { it.startsWith("HANDSHAKE_") }
    }

    private fun randomPassword(): String = ByteArray(18).also(SecureRandom()::nextBytes).joinToString("") { "%02x".format(it) }

    private class TlsServer(identity: Identity) : AutoCloseable {
        private val listener: SSLServerSocket
        @Volatile private var serverNames: List<String>? = null
        private val worker: Thread
        val port: Int get() = listener.localPort

        init {
            val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(identity.keyStore, identity.password) }
            val context = SSLContext.getInstance("TLS").apply { init(keys.keyManagers, null, null) }
            listener = context.serverSocketFactory.createServerSocket(0, 1, InetAddress.getLoopbackAddress()) as SSLServerSocket
            listener.soTimeout = 60_000
            worker = thread(isDaemon = true, name = "provider-tls-fixture") {
                runCatching {
                    (listener.accept() as SSLSocket).use { socket ->
                        socket.soTimeout = 30_000
                        socket.startHandshake()
                        serverNames = (socket.session as ExtendedSSLSession).requestedServerNames.map { (it as SNIHostName).asciiName }
                        socket.outputStream.write(1)
                        socket.outputStream.flush()
                        socket.inputStream.read()
                    }
                }
            }
        }

        fun awaitServerNames(): List<String>? {
            worker.join(30_000)
            return serverNames
        }

        override fun close() {
            listener.close()
            worker.join(30_000)
        }
    }
}
