package decompengine.acp

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsExchange
import com.sun.net.httpserver.HttpsServer
import decompengine.agent.*
import java.io.ByteArrayInputStream
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.MessageDigest
import java.time.Duration
import java.util.Collections
import java.util.IdentityHashMap
import java.util.Properties
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Flow
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocket
import kotlin.test.*
import org.junit.jupiter.api.Timeout

/** Actual loopback TLS controls only: these are not factory, guardian, or provider qualification. */
@Timeout(value = 20, unit = TimeUnit.SECONDS)
class AcpProviderCredentialFreeTlsFixtureTest {
    @Test
    fun `exact pinned loopback TLS exchange retains fixture classification and verified cleanup`() {
        val fixture = TlsFixture()
        val owner = Any()
        val policy = issueFixture(owner, fixture)
        val broker = startAndOpen(fixture, policy, owner)
        try {
            broker.bindSession("fixture-session", "fixture-turn")
            val exchange = broker.beginRequest(1, capability(broker), body())
            assertEquals(200, exchange.awaitHeaders().status)
            val bytes = generateSequence { exchange.nextChunk() }.fold(byteArrayOf()) { all, part -> all + part }
            assertTrue(bytes.decodeToString().contains("bounded fixture answer"))
            assertTrue(bytes.decodeToString().contains("response.completed"))
            assertEquals(1, fixture.received.get())
            assertEquals(1, fixture.accepted.get())
            assertEquals("POST", fixture.method)
            assertEquals("/responses", fixture.path)
            assertEquals(setOf("accept", "authorization", "content-length", "content-type", "host", "user-agent"), fixture.requestHeaders)
            assertTrue(fixture.tlsProtocol in setOf("TLSv1.3", "TLSv1.2"))
            assertEquals(PROVIDER_FIXTURE_CERTIFICATE_SHA256, fixture.servedCertificateSha256)
            val snapshot = broker.snapshot()
            assertTrue(snapshot.credentialFreeFixture)
            assertFalse(snapshot.adapterQualified)
            assertFalse(snapshot.providerCostCancellationProven)
            assertEquals(AcpProviderTerminalKind.COMPLETED, snapshot.requests.single().terminal)
            assertEquals(2, snapshot.requests.single().admittedOutputTokens)
            assertEquals(2L, snapshot.outputTokens)
            assertFalse(bytes.decodeToString().contains(policy.syntheticAuthorization()))
        } finally { closeVerified(broker, fixture) }
    }

    @Test
    fun `reject wrong certificate pin before accepting HTTP or releasing response bytes`() {
        val fixture = TlsFixture(Mode.WRONG_PIN)
        val owner = Any(); val policy = issueFixture(owner, fixture)
        val broker = startAndOpen(fixture, policy, owner)
        try {
            val failure = beginAndFail(broker)
            assertEquals(AcpProviderTerminalKind.TRANSPORT, failure.kind)
            assertEquals(0, fixture.received.get())
            assertEquals(0, fixture.accepted.get())
            assertEquals(0L, broker.snapshot().responseBytes)
            assertNull(failure.cause)
            assertFalse(failure.message!!.contains(policy.syntheticAuthorization()))
        } finally { closeVerified(broker, fixture) }
    }

    @Test
    fun `reject plaintext listener before accepting HTTP or releasing response bytes`() {
        val fixture = TlsFixture(Mode.PLAINTEXT)
        val owner = Any(); val policy = issueFixture(owner, fixture)
        val broker = startAndOpen(fixture, policy, owner)
        try {
            assertEquals(AcpProviderTerminalKind.TIMEOUT, beginAndFail(broker).kind)
            assertEquals(0, fixture.received.get())
            assertEquals(0, fixture.accepted.get())
            assertEquals(0L, broker.snapshot().responseBytes)
        } finally { closeVerified(broker, fixture) }
    }

    @Test
    fun `reject hostname mismatch with pinned certificate and HTTPS IP SAN verification`() {
        val fixture = TlsFixture()
        val owner = Any(); val policy = issueFixture(owner, fixture)
        val broker = startAndOpen(fixture, policy, owner)
        try {
            // Test-only reflection obtains the already-fixed fixture client's context; production
            // exposes no context/host injection. The exact pinned certificate lacks localhost SAN.
            val backendField = AcpProviderBroker::class.java.getDeclaredField("backend").also { it.isAccessible = true }
            val backend = backendField.get(broker)
            val clientField = backend.javaClass.getDeclaredField("client").also { it.isAccessible = true }
            val client = clientField.get(backend) as java.net.http.HttpClient
            Socket(InetAddress.getByName("127.0.0.1"), fixture.port).use { raw ->
                (client.sslContext().socketFactory.createSocket(raw, "localhost", fixture.port, false) as SSLSocket).use { socket ->
                    socket.soTimeout = 2000
                    socket.sslParameters = socket.sslParameters.also { it.endpointIdentificationAlgorithm = "HTTPS" }
                    assertFailsWith<SSLHandshakeException> { socket.startHandshake() }
                }
            }
            assertEquals(0, fixture.received.get())
            assertEquals(0, fixture.accepted.get())
            assertEquals(0L, broker.snapshot().responseBytes)
        } finally { closeVerified(broker, fixture) }
    }

    @Test
    fun `reject alternate authority path scheme method and model before network dispatch`() {
        for (scenario in 0..6) {
            val fixture = TlsFixture()
            val owner = Any(); val policy = issueFixture(owner, fixture)
            val broker = startAndOpen(fixture, policy, owner)
            try {
                broker.bindSession("fixture-session", "fixture-turn")
                val failure = assertFailsWith<AcpProviderBrokerFailure> {
                    when (scenario) {
                        0 -> broker.beginRequest(1, capability(broker), body(), requestedEndpoint = "http://127.0.0.1:${fixture.port}/responses")
                        1 -> broker.beginRequest(1, capability(broker), body(), requestedEndpoint = "https://localhost:${fixture.port}/responses")
                        2 -> broker.beginRequest(1, capability(broker), body(), requestedEndpoint = "https://127.0.0.1:${fixture.port}/responses/other")
                        3 -> broker.beginRequest(1, capability(broker), body(), requestedEndpoint = "https://127.0.0.1:${fixture.port}/responses?alternate=1")
                        4 -> broker.beginRequest(1, capability(broker), body(), requestedOperation = "GET")
                        5 -> broker.beginRequest(1, capability(broker), body(), requestedEndpoint = "https://127.0.0.1:${fixture.port}/responsesXYZ")
                        else -> broker.beginRequest(1, capability(broker), body().decodeToString().replace("acp-fixture-model-v1", "other-model").toByteArray())
                    }
                }
                assertEquals(if (scenario == 6) AcpProviderTerminalKind.UNSUPPORTED_MODEL else AcpProviderTerminalKind.UNSUPPORTED_OPERATION, failure.kind)
                assertEquals(0, fixture.received.get())
                assertEquals(0, fixture.accepted.get())
                assertEquals(0L, broker.snapshot().responseBytes)
                assertTrue(broker.snapshot().revoked)
            } finally { closeVerified(broker, fixture) }
        }
    }

    @Test
    fun `reject redirect without following target or releasing response bytes`() {
        val fixture = TlsFixture(Mode.REDIRECT)
        val owner = Any(); val policy = issueFixture(owner, fixture)
        val broker = startAndOpen(fixture, policy, owner)
        try {
            assertEquals(AcpProviderTerminalKind.TRANSPORT, beginAndFail(broker).kind)
            assertEquals(1, fixture.received.get(), "redirect denial occurs after initial dispatch")
            assertEquals(1, fixture.accepted.get())
            assertEquals(0, fixture.redirected.get())
            assertEquals(0L, broker.snapshot().responseBytes)
        } finally { closeVerified(broker, fixture) }
    }

    @Test
    fun `reject unknown response header without releasing response bytes`() {
        val fixture = TlsFixture(Mode.UNKNOWN_HEADER)
        val owner = Any(); val policy = issueFixture(owner, fixture)
        val broker = startAndOpen(fixture, policy, owner)
        try {
            assertEquals(AcpProviderTerminalKind.MALFORMED_RESPONSE, beginAndFail(broker).kind)
            assertEquals(1, fixture.received.get())
            assertEquals(1, fixture.accepted.get())
            assertEquals(0L, broker.snapshot().responseBytes)
        } finally { closeVerified(broker, fixture) }
    }

    @Test
    fun `reject missing expected synthetic authorization without accepting request or publishing error body`() {
        val fixture = TlsFixture(Mode.WRONG_AUTHORIZATION)
        val owner = Any(); val policy = issueFixture(owner, fixture)
        val broker = startAndOpen(fixture, policy, owner)
        try {
            assertEquals(AcpProviderTerminalKind.AUTHENTICATION, beginAndFail(broker).kind)
            assertEquals(1, fixture.received.get())
            assertEquals(0, fixture.accepted.get())
            assertEquals(0L, broker.snapshot().responseBytes)
        } finally { closeVerified(broker, fixture) }
    }

    @Test
    fun `reject forged replayed wrong owner and malformed fixture permits before resource creation`() {
        val fixture = TlsFixture()
        try {
            val owner = Any()
            val forged = mintPrivatePermit(owner, register = false)
            assertFailsWith<IllegalArgumentException> { AcpProviderTransportPolicy.CredentialFreeFixture.issue(forged, owner, fixture.port) }
            val wrongOwnerPermit = mintPrivatePermit(owner)
            assertFailsWith<IllegalArgumentException> { AcpProviderTransportPolicy.CredentialFreeFixture.issue(wrongOwnerPermit, Any(), fixture.port) }
            assertFailsWith<IllegalArgumentException> { AcpProviderTransportPolicy.CredentialFreeFixture.issue(wrongOwnerPermit, owner, fixture.port) }
            val replayedPermit = mintPrivatePermit(owner)
            val issued = AcpProviderTransportPolicy.CredentialFreeFixture.issue(replayedPermit, owner, fixture.port)
            assertFailsWith<IllegalArgumentException> { AcpProviderTransportPolicy.CredentialFreeFixture.issue(replayedPermit, owner, fixture.port) }
            val broker = open(issued, owner)
            try {
                assertFailsWith<IllegalArgumentException> { open(issued, owner) }
            } finally { broker.close(); assertBackendCleanup(broker) }
            val wrongOwnerPolicy = issueFixture(owner, fixture)
            assertFailsWith<IllegalArgumentException> { open(wrongOwnerPolicy, Any()) }
            assertFailsWith<IllegalArgumentException> { open(wrongOwnerPolicy, owner) }
            for (port in listOf(-1, 0, 80, 1023, 65536)) {
                assertFailsWith<IllegalArgumentException> { issueFixture(owner, port) }
            }
            assertEquals(0, fixture.received.get())
            assertEquals(0, fixture.accepted.get())
        } finally { fixture.closeVerified() }
    }

    @Test
    fun `reject synthetic constructor alternate production authority and forged fixture backend tokens`() {
        val approvedConstructor = AcpProviderTransportPolicy.Approved::class.java.constructors.single { it.isSynthetic }
        for ((endpoint, model) in listOf(URI("https://example.invalid/responses") to "gpt-6.1-sol", APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT to "bad model")) {
            val failure = assertFailsWith<InvocationTargetException> {
                approvedConstructor.newInstance(endpoint, model, AcpProviderReasoning.LOW, AcpProviderTransportBounds(), AcpProviderCredentialReference.LOCAL_CODEX_CACHED_AUTH, null)
            }
            assertTrue(failure.cause is IllegalArgumentException)
            assertNull(failure.cause!!.cause)
            assertFalse(failure.cause!!.message!!.contains("example.invalid"))
        }
        val fixtureConstructor = AcpProviderTransportPolicy.CredentialFreeFixture::class.java.constructors.single { it.isSynthetic }
        val failure = assertFailsWith<InvocationTargetException> {
            fixtureConstructor.newInstance(49152, AcpProviderQualificationProfile.CREDENTIAL_FREE, Any(), Any(), null)
        }
        assertTrue(failure.cause is IllegalArgumentException)
        val fixture = TlsFixture()
        val owner = Any(); val policy = issueFixture(owner, fixture)
        try {
            val fake = ControlledBackend()
            val constructor = AcpProviderBroker::class.java.constructors.single { it.isSynthetic }
            val request = request()
            val beforeThreads = ownedClientThreads()
            val directFailure = assertFailsWith<InvocationTargetException> {
                constructor.newInstance(policy, AgentExecutionRequestBinding.capture(request), AgentCancellation.NONE,
                    AcpProviderCredentialMaterial.cachedChatGpt("synthetic", "fixture_account"), Duration.ofSeconds(2), 32, null, fake, null)
            }
            assertTrue(directFailure.cause is IllegalArgumentException)
            assertTrue((ownedClientThreads() - beforeThreads).isEmpty())
            assertEquals(0, fake.starts)
            assertEquals(0, fake.closes)
            val authorityClass = Class.forName("decompengine.acp.FixtureAcpProviderNetworkAuthority")
            val authorityConstructor = authorityClass.declaredConstructors.single { it.parameterCount == 3 }.also { it.isAccessible = true }
            assertTrue(assertFailsWith<InvocationTargetException> {
                authorityConstructor.newInstance(policy, "synthetic", Any())
            }.cause is IllegalArgumentException)
            assertTrue((ownedClientThreads() - beforeThreads).isEmpty())
            assertEquals(0, fixture.received.get())
        } finally { fixture.closeVerified() }
    }

    @Test
    fun `reject replay through direct JVM network issuer and backend constructor before client creation`() {
        val fixture = TlsFixture()
        val owner = Any(); val policy = issueFixture(owner, fixture)
        var concreteBackend: Any? = null
        try {
            val authorityClass = Class.forName("decompengine.acp.FixtureAcpProviderNetworkAuthority")
            val companion = authorityClass.getDeclaredField("Companion").also { it.isAccessible = true }.get(null)
            val issue = companion.javaClass.declaredMethods.single { it.name == "issue" }.also { it.isAccessible = true }
            val authority = issue.invoke(companion, policy, owner)
            val backendClass = Class.forName("decompengine.acp.JdkAcpProviderBackend")
            val constructor = backendClass.declaredConstructors.single().also { it.isAccessible = true }
            concreteBackend = constructor.newInstance(authority)
            val beforeThreads = ownedClientThreads()
            assertTrue(assertFailsWith<InvocationTargetException> { issue.invoke(companion, policy, owner) }.cause is IllegalArgumentException)
            assertTrue(assertFailsWith<InvocationTargetException> { constructor.newInstance(authority) }.cause is IllegalArgumentException)
            assertTrue((ownedClientThreads() - beforeThreads).isEmpty())
            assertEquals(0, fixture.received.get())
        } finally {
            val cleanupDeadline = System.nanoTime() + Duration.ofSeconds(3).toNanos()
            try {
                concreteBackend?.let { backend ->
                    val close = backend.javaClass.getDeclaredMethod("closeWithin", Duration::class.java).also { it.isAccessible = true }
                    assertEquals(true, close.invoke(backend, Duration.ofNanos((cleanupDeadline - System.nanoTime()).coerceAtLeast(0))))
                    val snapshotMethod = backend.javaClass.getDeclaredMethod("cleanupSnapshot").also { it.isAccessible = true }
                    val snapshot = snapshotMethod.invoke(backend) as AcpProviderConcreteBackendCleanupSnapshot
                    assertTrue(snapshot.clientTerminated && snapshot.executorTerminated)
                    assertEquals(snapshot.requestFutureCount, snapshot.terminalFutureCount)
                }
            } finally { fixture.closeVerified(cleanupDeadline) }
            assertTrue(System.nanoTime() <= cleanupDeadline, "direct backend/server cleanup grace expired")
        }
    }

    @Test
    fun `usage observed before revoked EOF creates no fabricated admitted output tokens`() {
        val backend = ControlledBackend()
        val policy = AcpProviderTransportPolicy.issueApproved(APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT, "gpt-6.1-sol", AcpProviderReasoning.LOW, AcpProviderTransportBounds())
        val broker = AcpProviderBroker.openForTesting(policy, request(), Duration.ofSeconds(2),
            AcpProviderCredentialMaterial.cachedChatGpt("synthetic", "fixture_account"), backend)
        try {
            broker.bindSession("fixture-session", "fixture-turn")
            broker.beginRequest(1, capability(broker), body().decodeToString().replace("acp-fixture-model-v1", "gpt-6.1-sol").toByteArray())
            backend.receiver!!.headers(200, mapOf("content-type" to listOf("text/event-stream")))
            backend.receiver!!.subscribe(object : Flow.Subscription { override fun request(n: Long) = Unit; override fun cancel() = Unit })
            backend.receiver!!.bytes(listOf(ByteBuffer.wrap(completed())))
            broker.revoke(AcpProviderTerminalKind.CANCELLED)
            backend.receiver!!.complete()
            val snapshot = broker.snapshot()
            assertEquals(AcpProviderTerminalKind.CANCELLED, snapshot.requests.single().terminal)
            assertNull(snapshot.requests.single().outputTokens, "EOF validation has not admitted reported usage")
            assertEquals(0, snapshot.requests.single().admittedOutputTokens)
            assertEquals(0L, snapshot.outputTokens)
        } finally { broker.close() }
    }

    @Test
    fun `production approved policy descriptor and channel setup bytes retain baseline v1 golden`() {
        val policy = AcpProviderTransportPolicy.issueApproved(APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT, "gpt-6.1-sol", AcpProviderReasoning.LOW, AcpProviderTransportBounds())
        assertEquals("36537035293cd5f5beaee0d977500891fabfb2ecd5e02da6f2b1dc2135b04ceb", policy.descriptorSha256)
        val setup = AcpProviderBrokerProtocol.channelSetupPayload(ByteArray(32) { it.toByte() }, policy, ByteArray(32) { 0xab.toByte() }, 60_000)
        assertEquals(152, setup.size)
        assertEquals("c4f95a94bad849134ae4aba9a9826ae7d7b70e89dc2f226c004d2bf58762941c", sha(setup))
    }

    @Test
    fun `usage observed before rejected input token admission creates no admitted output tokens`() {
        val backend = ControlledBackend()
        val policy = AcpProviderTransportPolicy.issueApproved(APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT, "gpt-6.1-sol", AcpProviderReasoning.LOW, AcpProviderTransportBounds())
        val broker = AcpProviderBroker.openForTesting(policy, request(inputTokens = 1), Duration.ofSeconds(2),
            AcpProviderCredentialMaterial.cachedChatGpt("synthetic", "fixture_account"), backend)
        try {
            broker.bindSession("fixture-session", "fixture-turn")
            val exchange = broker.beginRequest(1, capability(broker), body().decodeToString().replace("acp-fixture-model-v1", "gpt-6.1-sol").toByteArray())
            backend.receiver!!.headers(200, mapOf("content-type" to listOf("text/event-stream")))
            backend.receiver!!.subscribe(object : Flow.Subscription { override fun request(n: Long) = Unit; override fun cancel() = Unit })
            backend.receiver!!.bytes(listOf(ByteBuffer.wrap(completed(inputTokens = 2))))
            backend.receiver!!.complete()
            assertEquals(AcpProviderTerminalKind.RESOURCE_EXHAUSTED, assertFailsWith<AcpProviderBrokerFailure> { exchange.nextChunk() }.kind)
            val snapshot = broker.snapshot()
            assertEquals(0L, snapshot.outputTokens)
            assertEquals(0, snapshot.requests.single().admittedOutputTokens)
            assertNull(snapshot.requests.single().outputTokens, "rejected usage is not an admitted EOF receipt")
        } finally { broker.close() }
    }

    @Test
    fun `closed JVM surface exposes no arbitrary URI TLS context or backend authority issuer`() {
        val fixture = AcpProviderTransportPolicy.CredentialFreeFixture::class.java
        assertFalse(java.io.Serializable::class.java.isAssignableFrom(fixture))
        for (type in listOf(fixture, fixture.getDeclaredField("Companion").type)) {
            for (method in type.methods.filter { it.declaringClass == type }) {
                assertTrue(method.parameterTypes.none { it == URI::class.java || it == SSLContext::class.java || it == java.net.http.HttpClient::class.java || it == AcpProviderBrokerTestBackend::class.java })
            }
        }
        // Synthetic accessors may enforce checks but must never return mutable issuer registries
        // or provenance objects usable to fabricate new fixture authorities.
        for (type in listOf(fixture, fixture.getDeclaredField("Companion").type, Class.forName("decompengine.acp.AcpProviderTransportPolicyKt"), Class.forName("decompengine.acp.AcpProviderBrokerKt"), Class.forName("decompengine.acp.JdkAcpProviderBackend"), Class.forName("decompengine.acp.FixtureAcpProviderNetworkAuthority"), Class.forName("decompengine.acp.FixtureAcpProviderNetworkAuthority\$Companion"), Class.forName("decompengine.acp.FixtureAcpProviderNetworkAuthority\$Issuer"), Class.forName("decompengine.acp.JdkAcpProviderBackend\$Companion"), Class.forName("decompengine.acp.AcpProviderTransportPolicy\$CredentialFreeFixture\$Issuer"))) {
            assertTrue(type.methods.none { Modifier.isPublic(it.modifiers) && (IdentityHashMap::class.java.isAssignableFrom(it.returnType) || (it.name.startsWith("access$") && it.returnType == Any::class.java)) })
        }
        val properties = Properties().also { values -> javaClass.getResourceAsStream("/acp/provider-relay-fixture-v1.properties")!!.use(values::load) }
        assertEquals("127.0.0.1", properties.getProperty("host"))
        assertEquals("/responses", properties.getProperty("path"))
        assertEquals(PROVIDER_FIXTURE_CERTIFICATE_SHA256, properties.getProperty("certificateSha256"))
        assertEquals(PROVIDER_FIXTURE_SPKI_SHA256, properties.getProperty("spkiSha256"))
        assertEquals("true", properties.getProperty("credentialFreeFixture"))
        assertEquals("false", properties.getProperty("adapterQualified"))
    }

    private fun open(policy: AcpProviderTransportPolicy.CredentialFreeFixture, owner: Any): AcpProviderBroker =
        AcpProviderBroker.openForCredentialFreeQualification(policy, owner, request(), Duration.ofSeconds(5))

    private fun startAndOpen(fixture: TlsFixture, policy: AcpProviderTransportPolicy.CredentialFreeFixture, owner: Any): AcpProviderBroker = try {
        fixture.start(policy); open(policy, owner)
    } catch (failure: Throwable) {
        fixture.closeVerified(); throw failure
    }
    private fun issueFixture(owner: Any, fixture: TlsFixture): AcpProviderTransportPolicy.CredentialFreeFixture = try {
        issueFixture(owner, fixture.port)
    } catch (failure: Throwable) {
        fixture.closeVerified(); throw failure
    }
    private fun issueFixture(owner: Any, port: Int): AcpProviderTransportPolicy.CredentialFreeFixture =
        AcpProviderTransportPolicy.CredentialFreeFixture.issue(mintPrivatePermit(owner), owner, port)

    /** Test-local trusted composition only; there is no production reflection hook or issuer. */
    private fun mintPrivatePermit(owner: Any, register: Boolean = true): AcpProviderQualificationPermit {
        val permitClass = Class.forName("decompengine.acp.AcpHarnessFactory\$FactoryProviderPermit")
        val permit = permitClass.getDeclaredConstructor().also { it.isAccessible = true }.newInstance() as AcpProviderQualificationPermit
        if (register) {
            val recordClass = Class.forName("decompengine.acp.AcpHarnessFactory\$ProviderPermitRecord")
            val constructor = recordClass.declaredConstructors.single { it.parameterCount == 3 }.also { it.isAccessible = true }
            val record = constructor.newInstance(owner, AcpProviderQualificationPurpose.FIXTURE_POLICY, null)
            val field = AcpHarnessFactory::class.java.getDeclaredField("providerPermits").also { it.isAccessible = true }
            @Suppress("UNCHECKED_CAST")
            val registry = field.get(AcpHarnessFactory) as MutableMap<AcpProviderQualificationPermit, Any>
            synchronized(registry) { registry[permit] = record }
        }
        return permit
    }

    private fun request(inputTokens: Long? = null): AgentExecutionRequest = AgentExecutionRequest(
        "credential-free TLS fixture", listOf(AgentWorkspaceRoot("fixture", Path.of(System.getProperty("user.dir")))),
        accessPolicy = AgentAccessPolicy(emptyList()), limits = AgentExecutionLimits(wallClockTimeout = Duration.ofSeconds(10), maxInputTokens = inputTokens),
    )
    private fun body(): ByteArray = """{"model":"acp-fixture-model-v1","input":[{"role":"user","content":"synthetic fixture"}],"reasoning":{"effort":"low"},"store":false,"stream":true}""".toByteArray()
    private fun capability(broker: AcpProviderBroker): ByteArray = AcpProviderBrokerProtocol.decodeChannelSetupPayload(broker.channelSetupPayload()).capability
    private fun beginAndFail(broker: AcpProviderBroker): AcpProviderBrokerFailure {
        broker.bindSession("fixture-session", "fixture-turn")
        val exchange = broker.beginRequest(1, capability(broker), body())
        return assertFailsWith { exchange.awaitHeaders(); exchange.nextChunk() }
    }
    private fun closeVerified(broker: AcpProviderBroker, fixture: TlsFixture) {
        val cleanupDeadline = System.nanoTime() + broker.policy.bounds.cleanupTimeout.toNanos()
        try { broker.close(); assertBackendCleanup(broker) } finally { fixture.closeVerified(cleanupDeadline) }
        assertTrue(System.nanoTime() <= cleanupDeadline, "shared broker/server cleanup grace expired")
        assertEquals(AcpProviderBrokerCleanup.VERIFIED, broker.snapshot().cleanup)
    }
    private fun assertBackendCleanup(broker: AcpProviderBroker) {
        val cleanup = assertNotNull(broker.concreteBackendCleanupSnapshot())
        assertTrue(cleanup.clientTerminated)
        assertTrue(cleanup.executorTerminated)
        assertEquals(cleanup.requestFutureCount, cleanup.terminalFutureCount)
    }
    private fun completed(inputTokens: Int = 1): ByteArray = """event: response.completed
data: {"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":$inputTokens,"output_tokens":2}}}

""".toByteArray()
    private fun ownedClientThreads(): Set<Long> = Thread.getAllStackTraces().keys.filter {
        it.isAlive && (it.name.startsWith("decomp-acp-provider-") || it.name.startsWith("HttpClient-"))
    }.map { it.threadId() }.toSet()

    private enum class Mode { SUCCESS, WRONG_PIN, PLAINTEXT, REDIRECT, UNKNOWN_HEADER, WRONG_AUTHORIZATION }

    private inner class TlsFixture(private val mode: Mode = Mode.SUCCESS) {
        private val initialSockets = socketInodes()
        private val initialDispatcherThreads = Thread.getAllStackTraces().keys.filter { it.name == "HTTP-Dispatcher" }.map { it.threadId() }.toSet()
        private val executor = ThreadPoolExecutor(2, 2, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(8),
            { task -> Thread(task, "decomp-acp-fixture-server").also { it.isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
        private val exchanges = Collections.synchronizedSet(Collections.newSetFromMap(IdentityHashMap<HttpExchange, Boolean>()))
        private val serverTlsContext = if (mode == Mode.PLAINTEXT) null else serverContext(if (mode == Mode.WRONG_PIN) "wrong-pin" else "fixture")
        private val server: HttpServer = if (mode == Mode.PLAINTEXT) HttpServer.create(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 2)
            else HttpsServer.create(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 2).also { it.httpsConfigurator = HttpsConfigurator(serverTlsContext!!) }
        val port = server.address.port
        val received = AtomicInteger()
        val accepted = AtomicInteger()
        val redirected = AtomicInteger()
        @Volatile var method: String? = null
        @Volatile var path: String? = null
        @Volatile var requestHeaders: Set<String> = emptySet()
        @Volatile var tlsProtocol: String? = null
        @Volatile var servedCertificateSha256: String? = null
        private var expectedAuthorization: String? = null
        private var started = false
        init {
            server.executor = executor
            server.createContext("/") { exchange ->
                exchanges.add(exchange)
                try {
                    received.incrementAndGet()
                    if (exchange.requestURI.rawPath == "/redirected") redirected.incrementAndGet()
                    method = exchange.requestMethod; path = exchange.requestURI.rawPath
                    requestHeaders = exchange.requestHeaders.keys.map { it.lowercase() }.toSet()
                    if (exchange is HttpsExchange) {
                        tlsProtocol = exchange.sslSession.protocol
                        servedCertificateSha256 = sha(exchange.sslSession.localCertificates.single().encoded)
                    }
                    val headers = exchange.requestHeaders
                    val allowedHeaders = setOf("accept", "authorization", "content-length", "content-type", "host", "user-agent")
                    val requestBytes = exchange.requestBody.readNBytes(8193)
                    if (headers.getFirst("Authorization") != "Bearer $expectedAuthorization") {
                        exchange.responseHeaders.set("Content-Type", "text/event-stream")
                        exchange.sendResponseHeaders(401, 0)
                        exchange.responseBody.write("unreleased fixture authentication error".toByteArray())
                        return@createContext
                    }
                    if (exchange.requestMethod != "POST" || exchange.requestURI.toASCIIString() != "/responses" ||
                        headers.getFirst("Host") != "127.0.0.1:$port" || headers.getFirst("Content-Type") != "application/json" ||
                        headers.getFirst("Accept") != "text/event-stream" || requestHeaders.any { it !in allowedHeaders } ||
                        requestBytes.size > 8192 || !requestBytes.contentEquals(body().decodeToString().dropLast(1).plus(",\"max_output_tokens\":32}").toByteArray())) {
                        exchange.sendResponseHeaders(400, -1); return@createContext
                    }
                    accepted.incrementAndGet()
                    if (mode == Mode.REDIRECT) {
                        exchange.responseHeaders.set("Location", "https://127.0.0.1:$port/redirected")
                        exchange.sendResponseHeaders(302, -1); return@createContext
                    }
                    if (mode == Mode.UNKNOWN_HEADER) exchange.responseHeaders.set("X-Undeclared-Fixture", "refused")
                    val response = ("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"bounded fixture answer\"}\n\n").toByteArray() + completed()
                    exchange.responseHeaders.set("Content-Type", "text/event-stream")
                    exchange.sendResponseHeaders(200, response.size.toLong())
                    exchange.responseBody.write(response)
                } finally { exchange.close(); exchanges.remove(exchange) }
            }
        }
        fun start(policy: AcpProviderTransportPolicy.CredentialFreeFixture) {
            expectedAuthorization = if (mode == Mode.WRONG_AUTHORIZATION) "no_matching_synthetic_authorization" else policy.syntheticAuthorization()
            server.start(); started = true
        }
        fun closeVerified(stop: Long = System.nanoTime() + Duration.ofSeconds(3).toNanos()) {
            synchronized(exchanges) { exchanges.toList().forEach { it.close() } }
            // JDK HttpServer.stop ignores an unstarted server; start its already-bound listener
            // before stopping so negative pre-admission controls also close their actual socket.
            if (!started) { server.start(); started = true }
            server.stop(0)
            executor.shutdownNow()
            assertTrue(executor.awaitTermination((stop - System.nanoTime()).coerceAtLeast(0), TimeUnit.NANOSECONDS))
            assertTrue(executor.isTerminated)
            assertTrue(exchanges.isEmpty())
            while (System.nanoTime() < stop && (socketInodes() - initialSockets).isNotEmpty()) Thread.sleep(5)
            assertTrue((socketInodes() - initialSockets).isEmpty(), "fixture client/server sockets remained open")
            while (System.nanoTime() < stop && newDispatcherAlive()) Thread.sleep(5)
            assertFalse(newDispatcherAlive(), "fixture HTTP dispatcher remained alive")
        }
        private fun newDispatcherAlive(): Boolean = Thread.getAllStackTraces().keys.any {
            it.isAlive && it.name == "HTTP-Dispatcher" && it.threadId() !in initialDispatcherThreads
        }
    }

    private fun socketInodes(): Set<String> = Files.newDirectoryStream(Path.of("/proc/self/fd")).use { entries ->
        entries.mapNotNull { fd -> runCatching { Files.readSymbolicLink(fd).toString() }.getOrNull()?.takeIf { it.startsWith("socket:[") } }.toSet()
    }
    private fun serverContext(alias: String): SSLContext {
        val identityBytes = javaClass.getResourceAsStream(PROVIDER_FIXTURE_KEYSTORE_RESOURCE)!!.use { it.readAllBytes() }
        assertEquals(PROVIDER_FIXTURE_KEYSTORE_SHA256, sha(identityBytes))
        val original = KeyStore.getInstance("PKCS12").also { it.load(ByteArrayInputStream(identityBytes), PROVIDER_FIXTURE_KEYSTORE_PASSWORD.toCharArray()) }
        val identity = KeyStore.getInstance("PKCS12").also {
            it.load(null, null)
            it.setKeyEntry(alias, original.getKey(alias, PROVIDER_FIXTURE_KEYSTORE_PASSWORD.toCharArray()), PROVIDER_FIXTURE_KEYSTORE_PASSWORD.toCharArray(), original.getCertificateChain(alias))
        }
        val managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).also { it.init(identity, PROVIDER_FIXTURE_KEYSTORE_PASSWORD.toCharArray()) }
        return SSLContext.getInstance("TLS").also { it.init(managers.keyManagers, null, null) }
    }
    private fun sha(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private class ControlledBackend : AcpProviderBrokerTestBackend {
        var starts = 0
        var closes = 0
        var receiver: AcpProviderBackendReceiver? = null
        override fun start(request: AcpProviderBackendRequest, receiver: AcpProviderBackendReceiver): AcpProviderBackendRequestOwner {
            starts++; this.receiver = receiver
            return object : AcpProviderBackendRequestOwner { override fun cancel() = Unit }
        }
        override fun closeWithin(timeout: Duration): Boolean { closes++; return true }
    }
}
