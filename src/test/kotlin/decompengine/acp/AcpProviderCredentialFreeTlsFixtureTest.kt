package decompengine.acp

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsExchange
import com.sun.net.httpserver.HttpsServer
import decompengine.agent.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.ServerSocket
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
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicBoolean
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
            val authorityField = backend.javaClass.getDeclaredField("authority").also { it.isAccessible = true }
            val authority = authorityField.get(backend)
            val contextField = authority.javaClass.getDeclaredField("tlsContext").also { it.isAccessible = true }
            val context = contextField.get(authority) as SSLContext
            Socket(InetAddress.getByName("127.0.0.1"), fixture.port).use { raw ->
                (context.socketFactory.createSocket(raw, "localhost", fixture.port, false) as SSLSocket).use { socket ->
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
        var primaryFailure: Throwable? = null
        try {
            assertEquals(AcpProviderTerminalKind.MALFORMED_RESPONSE, beginAndFail(broker).kind)
            assertEquals(1, fixture.received.get())
            assertEquals(1, fixture.accepted.get())
            assertEquals(0L, broker.snapshot().responseBytes)
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally { closeVerified(broker, fixture, primaryFailure, Mode.UNKNOWN_HEADER) }
    }

    @Test
    fun `reject missing expected synthetic authorization without accepting request or publishing error body`() {
        val fixture = TlsFixture(Mode.WRONG_AUTHORIZATION)
        val owner = Any(); val policy = issueFixture(owner, fixture)
        val broker = startAndOpen(fixture, policy, owner)
        var primaryFailure: Throwable? = null
        try {
            assertEquals(AcpProviderTerminalKind.AUTHENTICATION, beginAndFail(broker).kind)
            assertEquals(1, fixture.received.get())
            assertEquals(0, fixture.accepted.get())
            assertEquals(0L, broker.snapshot().responseBytes)
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally { closeVerified(broker, fixture, primaryFailure, Mode.WRONG_AUTHORIZATION) }
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
                    AcpProviderCredentialMaterial.cachedChatGpt("synthetic", "fixture_account"), Duration.ofSeconds(2), 32, null, fake, System.nanoTime(), null)
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
            val backendClass = Class.forName("decompengine.acp.CoreAcpProviderBackend")
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
                    assertTrue(snapshot.transportTerminated && snapshot.executorTerminated)
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
        for (type in listOf(fixture, fixture.getDeclaredField("Companion").type, Class.forName("decompengine.acp.AcpProviderTransportPolicyKt"), Class.forName("decompengine.acp.AcpProviderBrokerKt"), Class.forName("decompengine.acp.CoreAcpProviderBackend"), Class.forName("decompengine.acp.FixtureAcpProviderNetworkAuthority"), Class.forName("decompengine.acp.FixtureAcpProviderNetworkAuthority\$Companion"), Class.forName("decompengine.acp.FixtureAcpProviderNetworkAuthority\$Issuer"), Class.forName("decompengine.acp.CoreAcpProviderBackend\$Companion"), Class.forName("decompengine.acp.AcpProviderTransportPolicy\$CredentialFreeFixture\$Issuer"))) {
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

    @Test
    fun `actual reset authentication challenge and redirect never replay the POST`() {
        for (mode in listOf(RawMode.RESET, RawMode.AUTH_CHALLENGE, RawMode.REDIRECT)) {
            val fixture = RawTlsFixture(mode)
            val owner = Any(); val policy = issueFixture(owner, fixture.port)
            val broker = open(policy, owner)
            val capture = CaptureReceiver()
            try {
                fixture.start()
                backend(broker).start(AcpProviderBackendRequest(policy.endpoint, body(), fixtureCredentials(policy), Duration.ofSeconds(5)), capture)
                assertTrue(capture.terminal.await(2, TimeUnit.SECONDS), mode.name)
                assertFalse(capture.completed)
                assertEquals(1, fixture.connections.get())
                assertEquals(1, fixture.posts.get())
                assertEquals("Bearer ${policy.syntheticAuthorization()}", fixture.authorization)
                assertEquals(0, capture.bytes.size(), "denied upstream bodies must remain unread")
                if (mode != RawMode.RESET) assertEquals(if (mode == RawMode.AUTH_CHALLENGE) 401 else 302, capture.status)
            } finally { closeRawVerified(broker, fixture) }
        }
    }

    @Test
    fun `actual refused connection cannot fall back or connect again to a second address`() {
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { reservation ->
            val refusedPort = reservation.localPort
            val fallback = RawTlsFixture(RawMode.RESET)
            val owner = Any(); val policy = issueFixture(owner, refusedPort)
            val broker = open(policy, owner)
            val capture = CaptureReceiver()
            try {
                // Keep the refused endpoint owned until the fallback listener has bound.
                // Otherwise its ephemeral bind may reuse the just-released target port.
                assertNotEquals(refusedPort, fallback.port, "refused target and fallback listener must be distinct")
                reservation.close()
                fallback.start()
                val requestOwner = backend(broker).start(AcpProviderBackendRequest(policy.endpoint, body(), fixtureCredentials(policy), Duration.ofSeconds(5)), capture)
                assertTrue(capture.terminal.await(2, TimeUnit.SECONDS))
                assertFalse(capture.completed)
                val method = requestOwner.javaClass.getDeclaredMethod("connectOnce", Socket::class.java, InetSocketAddress::class.java).also { it.isAccessible = true }
                Socket(Proxy.NO_PROXY).use { second ->
                    val failure = assertFailsWith<InvocationTargetException> {
                        method.invoke(requestOwner, second, InetSocketAddress(InetAddress.getByName("127.0.0.2"), fallback.port))
                    }
                    assertTrue(failure.cause is IOException)
                    assertEquals("provider connection attempt refused", failure.cause!!.message)
                    assertNull(failure.cause!!.cause)
                    assertFalse(second.isConnected)
                    assertEquals(-1, second.localPort, "second connect is refused before socket bind or network IO")
                }
                assertEquals(0, fallback.connections.get())
                assertEquals(0, capture.bytes.size())
            } finally { closeRawVerified(broker, fallback) }
        }
    }

    @Test
    fun `actual bounded chunked response completes while malformed metadata trailers and body fail closed`() {
        for (mode in listOf(RawMode.CHUNKED, RawMode.HEADER_LINE, RawMode.HEADER_COUNT, RawMode.HEADER_TOTAL, RawMode.HEADER_PADDING,
            RawMode.FOLDED, RawMode.INTERIM, RawMode.TRAILER, RawMode.TRUNCATED_CHUNK, RawMode.CHUNK_METADATA, RawMode.BODY_LIMIT)) {
            val fixture = RawTlsFixture(mode)
            val owner = Any(); val policy = issueFixture(owner, fixture.port)
            val broker = open(policy, owner)
            val capture = CaptureReceiver()
            var primaryFailure: Throwable? = null
            try {
                fixture.start()
                backend(broker).start(AcpProviderBackendRequest(policy.endpoint, body(), fixtureCredentials(policy), Duration.ofSeconds(5)), capture)
                assertTrue(capture.terminal.await(2, TimeUnit.SECONDS), mode.name)
                assertEquals(mode == RawMode.CHUNKED, capture.completed, mode.name)
                assertEquals(1, fixture.connections.get(), mode.name)
                assertEquals(1, fixture.posts.get(), mode.name)
                assertTrue(capture.bytes.size() <= policy.bounds.maximumResponseBytes, mode.name)
                if (mode == RawMode.CHUNKED) assertEquals("hello", capture.bytes.toString(Charsets.UTF_8))
                if (mode in listOf(RawMode.HEADER_LINE, RawMode.HEADER_COUNT, RawMode.HEADER_TOTAL, RawMode.HEADER_PADDING, RawMode.FOLDED, RawMode.INTERIM)) {
                    assertNull(capture.status, "header admission precedes callbacks: $mode")
                    assertEquals(0, capture.bytes.size(), mode.name)
                }
                assertFalse(capture.bytes.toString(Charsets.UTF_8).contains("unreleased_error"), mode.name)
            } catch (failure: Throwable) {
                primaryFailure = failure
                throw failure
            } finally { closeRawVerified(broker, fixture, primaryFailure, mode) }
        }
    }

    @Test
    fun `cancellation aborts actual handshake header body and demand waits within cleanup grace`() {
        for (mode in listOf(RawMode.STALL_HANDSHAKE, RawMode.STALL_HEADERS, RawMode.STALL_BODY, RawMode.STALL_DEMAND)) {
            val fixture = RawTlsFixture(mode)
            val owner = Any(); val policy = issueFixture(owner, fixture.port)
            val broker = open(policy, owner)
            val capture = CaptureReceiver(automaticDemand = mode != RawMode.STALL_DEMAND)
            var primaryFailure: Throwable? = null
            try {
                fixture.start()
                val requestOwner = backend(broker).start(AcpProviderBackendRequest(policy.endpoint, body(), fixtureCredentials(policy), Duration.ofSeconds(5)), capture)
                assertTrue(fixture.phase.await(2, TimeUnit.SECONDS), mode.name)
                if (mode == RawMode.STALL_DEMAND) assertTrue(capture.headers.await(2, TimeUnit.SECONDS))
                awaitClientWait(mode)
                val started = System.nanoTime()
                requestOwner.cancel()
                closeRawVerified(broker, fixture, scenario = mode)
                assertTrue(System.nanoTime() - started < policy.bounds.cleanupTimeout.toNanos(), mode.name)
                assertFalse(capture.completed, mode.name)
            } catch (failure: Throwable) {
                primaryFailure = failure
                throw failure
            } finally { closeRawVerified(broker, fixture, primaryFailure, mode) }
        }
    }

    @Test
    fun `unjoined owned work produces bounded unverified cleanup instead of a terminal future claim`() {
        val fixture = RawTlsFixture(RawMode.RESET)
        val owner = Any(); val policy = issueFixture(owner, fixture.port)
        val initialClientThreads = ownedClientThreads()
        val broker = open(policy, owner)
        val transport = backend(broker)
        val executor = transport.javaClass.getDeclaredField("executor").also { it.isAccessible = true }.get(transport) as ThreadPoolExecutor
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val worker = executor.submit {
            entered.countDown()
            while (release.count != 0L) try { release.await() } catch (_: InterruptedException) { }
        }
        var primaryFailure: Throwable? = null
        try {
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            val started = System.nanoTime()
            assertFalse(transport.closeWithin(Duration.ofMillis(40)))
            assertTrue(System.nanoTime() - started < Duration.ofSeconds(1).toNanos())
            val snapshot = assertNotNull(broker.concreteBackendCleanupSnapshot())
            assertFalse(snapshot.transportTerminated)
            assertFalse(snapshot.executorTerminated)
            assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
            assertEquals(AcpProviderBrokerCleanup.UNVERIFIED, broker.snapshot().cleanup)
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            // Test-owned recovery releases resources without upgrading the missed broker proof.
            val deadline = System.nanoTime() + policy.bounds.cleanupTimeout.toNanos()
            release.countDown()
            try {
                try {
                    val lifecycle = AcpProviderBroker::class.java.getDeclaredField("lifecycle").also { it.isAccessible = true }
                        .get(broker) as java.util.concurrent.ScheduledThreadPoolExecutor
                    lifecycle.shutdownNow()
                    worker.get((deadline - System.nanoTime()).coerceAtLeast(0), TimeUnit.NANOSECONDS)
                    assertTrue(transport.closeWithin(Duration.ofNanos((deadline - System.nanoTime()).coerceAtLeast(0))))
                    assertBackendCleanup(broker)
                    assertTrue(lifecycle.awaitTermination((deadline - System.nanoTime()).coerceAtLeast(0), TimeUnit.NANOSECONDS))
                    assertTrue(lifecycle.isTerminated)
                    assertFailsWith<AcpProviderBrokerCleanupFailure> { broker.close() }
                    assertEquals(AcpProviderBrokerCleanup.UNVERIFIED, broker.snapshot().cleanup)
                } finally { fixture.closeVerified(deadline) }
                assertTrue((ownedClientThreads() - initialClientThreads).isEmpty(), "test-owned client threads remained")
                assertTrue(System.nanoTime() <= deadline, "negative fixture recovery grace expired")
            } catch (cleanupFailure: Throwable) {
                if (primaryFailure != null) primaryFailure.addSuppressed(cleanupFailure) else throw cleanupFailure
            }
        }
    }

    private fun awaitClientWait(mode: RawMode) {
        val deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos()
        while (System.nanoTime() < deadline) {
            val entered = Thread.getAllStackTraces().any { (thread, frames) ->
                thread.name == "decomp-acp-provider-http" && frames.any { it.className == "decompengine.acp.ProviderHttpAttempt" && it.methodName == "run" } &&
                    when (mode) {
                        RawMode.STALL_HANDSHAKE -> frames.any { it.methodName == "startHandshake" }
                        RawMode.STALL_HEADERS -> frames.any { it.className == "decompengine.acp.ProviderHeaderBuffer" && it.methodName == "readLine" }
                        RawMode.STALL_BODY -> frames.any { it.className == "org.apache.hc.core5.http.impl.io.ContentLengthInputStream" && it.methodName == "read" }
                        RawMode.STALL_DEMAND -> frames.any { it.className == "java.lang.Object" && it.methodName.startsWith("wait") }
                        else -> false
                    }
            }
            if (entered) return
            Thread.sleep(1)
        }
        fail("owned HTTP client did not enter the intended wait: $mode")
    }

    private fun backend(broker: AcpProviderBroker): AcpProviderBrokerTestBackend =
        AcpProviderBroker::class.java.getDeclaredField("backend").also { it.isAccessible = true }.get(broker) as AcpProviderBrokerTestBackend
    private fun fixtureCredentials(policy: AcpProviderTransportPolicy.CredentialFreeFixture): AcpProviderCredentialMaterial =
        AcpProviderCredentialMaterial.cachedChatGpt(policy.syntheticAuthorization(), "credential_free_fixture_v1")
    private fun closeRawVerified(broker: AcpProviderBroker, fixture: RawTlsFixture,
                                 primaryFailure: Throwable? = null, scenario: RawMode? = null) {
        val started = System.nanoTime()
        val deadline = started + broker.policy.bounds.cleanupTimeout.toNanos()
        observeFixtureCleanup(broker, started, deadline, scenario?.name, primaryFailure,
            closeFixture = { fixture.closeVerified(deadline) }) {
            assertTrue(System.nanoTime() <= deadline, "shared raw transport/server cleanup grace expired")
        }
    }

    private class CaptureReceiver(private val automaticDemand: Boolean = true) : AcpProviderBackendReceiver {
        val terminal = CountDownLatch(1)
        val headers = CountDownLatch(1)
        val bytes = ByteArrayOutputStream()
        @Volatile var completed = false
        @Volatile var status: Int? = null
        private var subscription: Flow.Subscription? = null
        override fun subscribe(subscription: Flow.Subscription) { this.subscription = subscription; if (automaticDemand) subscription.request(Long.MAX_VALUE) }
        override fun headers(status: Int, headers: Map<String, List<String>>) {
            this.status = status
            if (status != 200) subscription!!.cancel()
            this.headers.countDown()
        }
        override fun bytes(buffers: List<ByteBuffer>) {
            for (buffer in buffers) { val copy = ByteArray(buffer.remaining()); buffer.get(copy); bytes.write(copy) }
        }
        override fun complete() { completed = true; terminal.countDown() }
        override fun failed() { terminal.countDown() }
    }

    private enum class RawMode { RESET, AUTH_CHALLENGE, REDIRECT, CHUNKED, HEADER_LINE, HEADER_COUNT, HEADER_TOTAL, HEADER_PADDING,
        FOLDED, INTERIM, TRAILER, TRUNCATED_CHUNK, CHUNK_METADATA, BODY_LIMIT, STALL_HANDSHAKE, STALL_HEADERS, STALL_BODY, STALL_DEMAND }
    private inner class RawTlsFixture(private val mode: RawMode) {
        private val initialSockets = initializedSocketRuntimeCensus()
        private val listener: ServerSocket = if (mode == RawMode.STALL_HANDSHAKE) ServerSocket(0, 2, InetAddress.getByName("127.0.0.1"))
            else serverContext("fixture").serverSocketFactory.createServerSocket(0, 2, InetAddress.getByName("127.0.0.1"))
        val port = listener.localPort
        private val closed = AtomicBoolean()
        private val executor = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(1),
            { task -> Thread(task, "decomp-acp-raw-fixture").also { it.isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
        private val sockets = Collections.synchronizedSet(Collections.newSetFromMap(IdentityHashMap<Socket, Boolean>()))
        val connections = AtomicInteger()
        val posts = AtomicInteger()
        val phase = CountDownLatch(1)
        @Volatile var authorization: String? = null
        fun start() { executor.submit {
            while (!closed.get()) {
                val socket = try { listener.accept() } catch (_: IOException) { break }
                sockets.add(socket); connections.incrementAndGet()
                try {
                    socket.soTimeout = 5000
                    if (mode == RawMode.STALL_HANDSHAKE) { phase.countDown(); while (socket.getInputStream().read() >= 0) { }; continue }
                    (socket as SSLSocket).startHandshake()
                    val input = socket.getInputStream()
                    val head = ByteArrayOutputStream()
                    while (head.size() <= 8192) {
                        val byte = input.read(); if (byte < 0) throw IOException("fixture request incomplete")
                        head.write(byte)
                        if (head.size() >= 4 && head.toString(Charsets.US_ASCII).endsWith("\r\n\r\n")) break
                    }
                    check(head.size() <= 8192)
                    val lines = head.toString(Charsets.US_ASCII).split("\r\n")
                    check(lines.first() == "POST /responses HTTP/1.1")
                    authorization = lines.single { it.startsWith("Authorization:", true) }.substringAfter(':').trim()
                    val length = lines.single { it.startsWith("Content-Length:", true) }.substringAfter(':').trim().toInt()
                    check(length in 1..8192 && input.readNBytes(length).size == length)
                    posts.incrementAndGet()
                    if (mode == RawMode.RESET) { socket.setSoLinger(true, 0); continue }
                    if (mode == RawMode.STALL_HEADERS) { phase.countDown(); while (input.read() >= 0) { }; continue }
                    val regular = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                    val content = when (mode) {
                        RawMode.AUTH_CHALLENGE -> "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=fixture\r\nContent-Length: 16\r\n\r\nunreleased_error"
                        RawMode.REDIRECT -> "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:$port/responses\r\nContent-Length: 16\r\n\r\nunreleased_error"
                        RawMode.HEADER_LINE -> regular + "X-Huge: " + "a".repeat(5000) + "\r\n\r\n"
                        RawMode.HEADER_COUNT -> regular + (1..17).joinToString("") { "X-$it: a\r\n" } + "\r\n"
                        RawMode.HEADER_TOTAL -> regular + "X-A: " + "a".repeat(2100) + "\r\nX-B: " + "a".repeat(2100) + "\r\n\r\n"
                        RawMode.HEADER_PADDING -> regular + (1..15).joinToString("") { "X-$it:" + " ".repeat(400) + "a\r\n" } + "\r\n"
                        RawMode.FOLDED -> regular + " hidden: value\r\n\r\n"
                        RawMode.INTERIM -> "HTTP/1.1 100 Continue\r\n\r\n" + regular + "Content-Length: 0\r\n\r\n"
                        RawMode.BODY_LIMIT -> regular + "Content-Length: 65537\r\n\r\n" + "a".repeat(65537)
                        RawMode.STALL_BODY -> regular + "Content-Length: 100\r\n\r\na"
                        RawMode.STALL_DEMAND -> regular + "Content-Length: 1\r\n\r\na"
                        else -> regular + "Transfer-Encoding: chunked\r\n\r\n" + when (mode) {
                            RawMode.TRAILER -> "1\r\na\r\n0\r\nX-Forbidden: unreleased_error\r\n\r\n"
                            RawMode.TRUNCATED_CHUNK -> "1\r\na\r\n0\r\n"
                            RawMode.CHUNK_METADATA -> "1;" + "a".repeat(4090) + "\r\na\r\n0\r\n\r\n"
                            else -> "5\r\nhello\r\n0\r\n\r\n"
                        }
                    }
                    socket.getOutputStream().write(content.toByteArray(Charsets.US_ASCII)); socket.getOutputStream().flush()
                    phase.countDown()
                    if (mode in listOf(RawMode.STALL_BODY, RawMode.STALL_DEMAND)) while (input.read() >= 0) { }
                } catch (_: Exception) { }
                finally { runCatching { socket.close() }; sockets.remove(socket) }
            }
        } }
        fun closeVerified(deadline: Long) {
            closed.set(true); listener.close()
            synchronized(sockets) { sockets.toList().forEach { runCatching { it.close() } } }
            executor.shutdownNow()
            assertTrue(executor.awaitTermination((deadline - System.nanoTime()).coerceAtLeast(0), TimeUnit.NANOSECONDS))
            assertTrue(executor.isTerminated && sockets.isEmpty())
            while (System.nanoTime() < deadline && (socketInodes() - initialSockets).isNotEmpty()) Thread.sleep(5)
            assertTrue((socketInodes() - initialSockets).isEmpty(), "raw fixture sockets remained: ${socketInodes() - initialSockets}")
        }
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
    private fun closeVerified(broker: AcpProviderBroker, fixture: TlsFixture,
                              primaryFailure: Throwable? = null, scenario: Mode? = null) {
        val started = System.nanoTime()
        val cleanupDeadline = started + broker.policy.bounds.cleanupTimeout.toNanos()
        observeFixtureCleanup(broker, started, cleanupDeadline, scenario?.name, primaryFailure,
            closeFixture = { fixture.closeVerified(cleanupDeadline) }) {
            assertTrue(System.nanoTime() <= cleanupDeadline, "shared broker/server cleanup grace expired")
            assertEquals(AcpProviderBrokerCleanup.VERIFIED, broker.snapshot().cleanup)
        }
    }

    private enum class CleanupObservationPhase { BROKER_CLOSE, BACKEND_ASSERTIONS, FIXTURE_CLOSE, SHARED_GRACE_ASSERTIONS }
    private class CleanupDiagnostic(message: String) : RuntimeException(message, null, false, false)

    /** Failure observations only: no extra close, wait, cancellation, or grace is introduced. */
    private fun observeFixtureCleanup(broker: AcpProviderBroker, started: Long, deadline: Long,
                                      scenario: String?, primaryFailure: Throwable?, closeFixture: () -> Unit,
                                      completionChecks: () -> Unit) {
        var cleanupFailure: Throwable? = null
        fun retain(failure: Throwable, phase: CleanupObservationPhase) {
            attachCleanupDiagnostic(failure, broker, started, deadline, scenario, phase)
            val previous = cleanupFailure
            if (previous == null) cleanupFailure = failure
            else if (previous !== failure) previous.addSuppressed(failure)
        }
        var phase = CleanupObservationPhase.BROKER_CLOSE
        try {
            broker.close()
            phase = CleanupObservationPhase.BACKEND_ASSERTIONS
            assertBackendCleanup(broker)
        } catch (failure: Throwable) {
            retain(failure, phase)
        } finally {
            try { closeFixture() }
            catch (failure: Throwable) { retain(failure, CleanupObservationPhase.FIXTURE_CLOSE) }
        }
        if (cleanupFailure == null) {
            try { completionChecks() }
            catch (failure: Throwable) { retain(failure, CleanupObservationPhase.SHARED_GRACE_ASSERTIONS) }
        }
        val failure = cleanupFailure ?: return
        if (primaryFailure == null) throw failure
        if (primaryFailure !== failure) primaryFailure.addSuppressed(failure)
    }

    private fun cleanupField(owner: Any, name: String): Any? =
        owner.javaClass.getDeclaredField(name).also { it.isAccessible = true }.get(owner)

    private fun cleanupObservation(read: () -> String): String =
        try { read() } catch (_: Throwable) { "UNAVAILABLE" }

    private fun cleanupExecutorObservation(value: Any?): String {
        val executor = value as ThreadPoolExecutor
        return "shutdown=${executor.isShutdown},terminated=${executor.isTerminated}"
    }

    private fun cleanupOwnerObservation(owner: Any): String {
        check(owner.javaClass.name == "decompengine.acp.ProviderHttpAttempt")
        fun flag(name: String) = (cleanupField(owner, name) as AtomicBoolean).get()
        fun reference(name: String) = (cleanupField(owner, name) as java.util.concurrent.atomic.AtomicReference<*>).get()
        val future = cleanupField(owner, "future") as java.util.concurrent.Future<*>?
        val execution = (cleanupField(owner, "execution") as AtomicInteger).get()
        val rejected = cleanupField(owner, "rejected") as Boolean
        val firstFailure = reference("firstCleanupFailure") as AcpProviderCleanupOperation?
        return "cleanupFailed=${flag("cleanupFailed")},firstCleanupFailure=${firstFailure?.name ?: "NONE"},cancelled=${flag("cancelled")},execution=$execution," +
            "futurePresent=${future != null},futureDone=${future?.isDone == true},futureCancelled=${future?.isCancelled == true}," +
            "futureTerminal=${rejected || future?.isDone == true},rawPresent=${reference("raw") != null}," +
            "tlsPresent=${reference("tls") != null},connectionPresent=${reference("connection") != null},closedness=UNOBSERVED"
    }

    private fun attachCleanupDiagnostic(failure: Throwable, broker: AcpProviderBroker, started: Long, deadline: Long,
                                         scenario: String?, phase: CleanupObservationPhase) {
        // Only fixed labels, enums, booleans and numbers are rendered. Never inspect a wire,
        // authority, receiver, body, header, parser, exception message, or thread stack.
        try {
            val observedAt = System.nanoTime()
            val label = scenario?.takeIf { it.length <= 32 && it.all { c -> c in 'A'..'Z' || c == '_' } } ?: "UNSPECIFIED"
            val disposition = cleanupObservation { (cleanupField(broker, "cleanup") as AcpProviderBrokerCleanup).name }
            val lifecycle = cleanupObservation { cleanupExecutorObservation(cleanupField(broker, "lifecycle")) }
            val backend = cleanupField(broker, "backend")
            val backendState = cleanupObservation {
                check(backend != null && backend.javaClass.name == "decompengine.acp.CoreAcpProviderBackend")
                "closed=${(cleanupField(backend, "closed") as AtomicBoolean).get()}," +
                    cleanupExecutorObservation(cleanupField(backend, "executor"))
            }
            val ownerStates = cleanupObservation {
                check(backend != null && backend.javaClass.name == "decompengine.acp.CoreAcpProviderBackend")
                // Inspect the list only once backend admission is closed and its workers are
                // terminated. Active socket/connection getters and executor queue locks are
                // deliberately avoided; a present reference does not claim that it is open.
                if (!(cleanupField(backend, "closed") as AtomicBoolean).get() ||
                    !(cleanupField(backend, "executor") as ThreadPoolExecutor).isTerminated) {
                    return@cleanupObservation "UNAVAILABLE_BACKEND_NOT_TERMINATED"
                }
                val owners = cleanupField(backend, "owners") as List<*>
                synchronized(owners) {
                    val count = owners.size
                    val rows = ArrayList<String>(minOf(count, 4))
                    for (index in 0 until minOf(count, 4)) {
                        rows += cleanupObservation { cleanupOwnerObservation(checkNotNull(owners[index])) }
                    }
                    "count=$count,truncated=${count > 4},retired=${cleanupField(backend, "retiredOwners") as Int},rows=[${rows.joinToString(";")}]"
                }
            }
            val message = "TLS_CLEANUP_AFTER_FAILURE scenario=$label phase=${phase.name} cleanup=$disposition " +
                "elapsedNanos=${(observedAt - started).coerceAtLeast(0)} budgetNanos=${(deadline - started).coerceAtLeast(0)} " +
                "deadlineExpired=${observedAt > deadline} interrupted=${Thread.currentThread().isInterrupted} " +
                "lifecycle=[$lifecycle] backend=[$backendState] owners=[$ownerStates]"
            failure.addSuppressed(CleanupDiagnostic(message.take(2048)))
        } catch (_: Throwable) {
            // A diagnostic reflection/formatting failure cannot replace the original failure.
            failure.addSuppressed(CleanupDiagnostic("TLS_CLEANUP_AFTER_FAILURE diagnostics=UNAVAILABLE"))
        }
    }

    private fun assertBackendCleanup(broker: AcpProviderBroker) {
        val cleanup = assertNotNull(broker.concreteBackendCleanupSnapshot())
        assertTrue(cleanup.transportTerminated)
        assertTrue(cleanup.executorTerminated)
        assertEquals(cleanup.requestFutureCount, cleanup.terminalFutureCount)
    }
    private fun completed(inputTokens: Int = 1): ByteArray = """event: response.completed
data: {"type":"response.completed","response":{"id":"resp_tls_fixture","status":"completed","usage":{"input_tokens":$inputTokens,"output_tokens":2,"total_tokens":${inputTokens.toLong() + 2L}}}}

""".toByteArray()
    private fun ownedClientThreads(): Set<Long> = Thread.getAllStackTraces().keys.filter {
        it.isAlive && (it.name.startsWith("decomp-acp-provider-") || it.name.startsWith("HttpClient-"))
    }.map { it.threadId() }.toSet()

    private enum class Mode { SUCCESS, WRONG_PIN, PLAINTEXT, REDIRECT, UNKNOWN_HEADER, WRONG_AUTHORIZATION }

    private inner class TlsFixture(private val mode: Mode = Mode.SUCCESS) {
        private val initialSockets = initializedSocketRuntimeCensus()
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
            assertTrue((socketInodes() - initialSockets).isEmpty(), "fixture client/server sockets remained open: ${socketInodes() - initialSockets}")
            while (System.nanoTime() < stop && newDispatcherAlive()) Thread.sleep(5)
            assertFalse(newDispatcherAlive(), "fixture HTTP dispatcher remained alive")
        }
        private fun newDispatcherAlive(): Boolean = Thread.getAllStackTraces().keys.any {
            it.isAlive && it.name == "HTTP-Dispatcher" && it.threadId() !in initialDispatcherThreads
        }
    }

    private fun initializedSocketRuntimeCensus(): Set<String> {
        // A first ordinary JDK Socket bind/close initializes a process-wide native close socket.
        // Establish that runtime state before the owned client/server FD baseline; every later
        // owned FD still has to disappear. See the standalone SocketRuntimeProbe evidence.
        Socket(Proxy.NO_PROXY).use { it.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0)) }
        return socketInodes()
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
