package decompengine.acp

import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The broker integration control scenarios. Each runs in a fresh JVM started by [AcpProviderBrokerTest], whose
 * only trust customization is the standard `javax.net.ssl.trustStore` properties, so the module TLS client runs
 * with its production platform-trust code. Inputs are a synthetic Codex login under build/, server identities
 * from a runtime-generated test CA under build/, a synthetic #1510 resolver, and a local TLS server. No real
 * provider or credential is used.
 */
internal class AcpProviderBrokerScenario(private val stores: ProviderScenarioStores) {
    // The production entry point uses the system clock, so the synthetic token is valid against it as well.
    private val now = Instant.now()
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val policy = approvedProviderPolicy()
    private val token = syntheticAccessToken(now.plusSeconds(3600))
    private val codexHome = syntheticCodexHome(syntheticChatGptAuth(token))
    private val pinned = numericAddress("104.18.32.47")
    private val closeables = ArrayList<AutoCloseable>()
    private val diagnostics = ArrayList<String>()
    private val capabilities = ArrayList<String>()
    private val granted = HashMap<AcpProviderBroker, ByteArray>()

    fun finish() {
        closeables.asReversed().forEach { runCatching { it.close() } }
        // No failure, result or broker rendering may carry the token, the capability or the credential path.
        diagnostics.forEach { text ->
            assertFalse(text.contains(token), "diagnostic contains the synthetic token")
            assertFalse(text.contains(codexHome.toString()), "diagnostic contains the credential source path")
            capabilities.forEach { assertFalse(text.contains(it, ignoreCase = true), "diagnostic contains the channel capability") }
        }
    }

    fun credentialCheckedBeforeAnySideEffect() {
        val server = server()
        listOf(
            providerFixtureDirectory("no-login") to AcpProviderCredentialFailure.MISSING,
            syntheticCodexHome(syntheticChatGptAuth(syntheticAccessToken(now.minusSeconds(5)))) to AcpProviderCredentialFailure.EXPIRED,
            syntheticCodexHome("""{"OPENAI_API_KEY":"sk-synthetic","tokens":null}""") to AcpProviderCredentialFailure.MECHANISM_UNSUPPORTED,
        ).forEach { (home, expected) ->
            val resolver = FixedProviderResolver(listOf(pinned))
            val connector = connector(server)
            val failure = assertRefused(AcpProviderBrokerFailureKind.CREDENTIAL_UNAVAILABLE) {
                AcpProviderBroker.open(policy, providerFixtureRequest(), AcpProviderCredentialSource.LocalCodexCachedAuth(home),
                    resolver, connector, clock)
            }
            assertEquals(expected, failure.credentialFailure)
            assertEquals(emptyList(), resolver.hosts, "no resolution before the credential is available")
            assertEquals(emptyList(), connector.addresses)
        }
        assertRefused(AcpProviderBrokerFailureKind.TRANSPORT_DISABLED) {
            AcpProviderBroker.open(AcpProviderTransportPolicy.DISABLED, providerFixtureRequest(),
                AcpProviderCredentialSource.LocalCodexCachedAuth(codexHome))
        }
        assertEquals(0, server.accepted.get())
    }

    fun pinnedNumericAddressWithoutReResolution() {
        val server = server()
        // Even an answer that carries a host name is reduced to its address bytes.
        val resolver = FixedProviderResolver(listOf(InetAddress.getByAddress("evil.example", pinned.address), numericAddress("2606:4700::6812:202f")))
        val connector = connector(server)
        val broker = broker(resolver = resolver, connector = connector)
        val capability = capability(broker)

        repeat(3) { index -> assertEquals(200, broker.exchange(channelRequest(index + 1L, capability)).status) }

        assertEquals(listOf("chatgpt.com"), resolver.hosts)
        assertEquals(3, connector.addresses.size)
        connector.addresses.forEach { address ->
            // toString shows an attached host name before the slash, and never makes a lookup.
            assertEquals("/104.18.32.47", address.toString(), "the pinned destination carries no host name")
            assertContentEquals(pinned.address, address.address)
        }
        assertEquals(3, server.requests.size)
    }

    fun refusedDestinationsFailBeforeConnecting() {
        val server = server()
        listOf(
            listOf(pinned, numericAddress("127.0.0.1")) to AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED,
            listOf(numericAddress("169.254.169.254")) to AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED,
            listOf(numericAddress("::ffff:127.0.0.1")) to AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED,
            listOf(numericAddress("64:ff9b::808:808")) to AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED,
            listOf(numericAddress("10.1.2.3")) to AcpProviderRouteRefusal.PRIVATE_DESTINATION_NOT_PERMITTED,
            emptyList<InetAddress>() to AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED,
        ).forEach { (addresses, expected) ->
            val connector = connector(server)
            val failure = assertRefused(AcpProviderBrokerFailureKind.DESTINATION_REFUSED) {
                broker(resolver = FixedProviderResolver(addresses), connector = connector)
            }
            assertEquals(expected, failure.routeRefusal)
            assertEquals(emptyList(), connector.addresses)
        }
        // Production has no #1510 resolver yet, so the production entry point cannot open a broker.
        assertRefused(AcpProviderBrokerFailureKind.DESTINATION_REFUSED) {
            AcpProviderBroker.open(policy, providerFixtureRequest(), AcpProviderCredentialSource.LocalCodexCachedAuth(codexHome))
        }
        assertEquals(0, server.accepted.get())
    }

    fun tlsUsesPolicyHostForSniAndVerification() {
        val server = server()
        val broker = broker(connector = connector(server))
        assertEquals(200, broker.exchange(channelRequest(1, capability(broker))).status)
        assertEquals(listOf("chatgpt.com"), server.requests.single().serverNames)

        // A certificate from the configured root for another name, and one for the policy host from another root.
        listOf(stores.wrongHost, stores.untrusted).forEach { presented ->
            val wrong = server(presented)
            val refusing = broker(connector = connector(wrong))
            assertRefused(AcpProviderBrokerFailureKind.TLS_REFUSED) { refusing.exchange(channelRequest(1, capability(refusing))) }
            assertEquals(emptyList(), wrong.requests, "no request byte is sent before verification succeeds")
            assertEquals(1, wrong.accepted.get())
        }
    }

    /** Run without the trust-store properties: the JVM platform store does not hold the runtime test root. */
    fun platformTrustRefusesTheTestRoot() {
        val server = server()
        val broker = broker(connector = connector(server))
        assertRefused(AcpProviderBrokerFailureKind.TLS_REFUSED) { broker.exchange(channelRequest(1, capability(broker))) }
        assertEquals(emptyList(), server.requests)
    }

    fun redirectsRefusedAndNeverFollowed() {
        listOf(301, 302, 303, 307, 308).forEach { status ->
            val server = server { rawResponse("HTTP/1.1 $status Moved\r\nLocation: https://evil.example/steal\r\nContent-Length: 0\r\n\r\n") }
            val connector = connector(server)
            val broker = broker(connector = connector)
            val failure = assertRefused(AcpProviderBrokerFailureKind.REDIRECT_REFUSED) { broker.exchange(channelRequest(1, capability(broker))) }
            assertEquals(AcpProviderRouteRefusal.REDIRECT_UNDECLARED, failure.routeRefusal)
            assertEquals(1, connector.addresses.size, "no second connection for status $status")
            assertEquals(1, server.accepted.get())
        }
    }

    fun upstreamHeadFromPolicyAndBrokerValues() {
        val server = server { sseResponse("data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\n\n", framing = "chunked") }
        val broker = broker(connector = connector(server))
        val body = """{ "model" : "gpt-6", "input" : [ {"role":"user","content":"a\/b"} ], "stream" : true, "store" : false }"""
        val agentFields = listOf(
            "Authorization" to "Bearer agent-chosen", "ChatGPT-Account-ID" to "acct_agent",
            "Cookie" to "session=agent", "User-Agent" to "agent/9", "Accept-Encoding" to "gzip", "OpenAI-Beta" to "agent",
            "Content-Type" to "text/plain", "Accept" to "*/*", "Connection" to "keep-alive",
        )
        val result = broker.exchange(channelRequest(1, capability(broker), body = body, host = "evil.example:8443", fields = agentFields))

        assertEquals(200, result.status)
        assertEquals("text/event-stream", result.contentType)
        assertEquals("data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\n\n", result.body.toString(StandardCharsets.UTF_8))
        val observed = server.requests.single()
        // The validated body goes upstream exactly as admitted, under the length the routed head declared.
        assertEquals(body, observed.body.toString(StandardCharsets.UTF_8))
        assertEquals(
            listOf(
                "POST /backend-api/codex/responses HTTP/1.1",
                "Host: chatgpt.com",
                "Content-Type: application/json",
                "Accept: text/event-stream",
                "Content-Length: ${body.toByteArray().size}",
                "Authorization: Bearer $token",
                "ChatGPT-Account-ID: acct_fixture-1",
            ),
            observed.head,
        )
        diagnostics += observed.head.filterNot { it.startsWith("Authorization:") }
    }

    fun channelBoundToCapabilityAndSequence() {
        val server = server()
        val connector = connector(server)
        val broker = broker(connector = connector)
        val other = broker(connector = connector)
        assertRefused(AcpProviderBrokerFailureKind.CHANNEL_REFUSED) { broker.exchange(channelRequest(1, ByteArray(32))) }
        val capability = capability(broker)
        val otherCapability = capability(other)
        assertRefused(AcpProviderBrokerFailureKind.CHANNEL_REFUSED) { broker.grantChannel() }

        listOf(otherCapability, ByteArray(32), capability.copyOf(31), capability + byteArrayOf(0)).forEach { wrong ->
            assertRefused(AcpProviderBrokerFailureKind.CHANNEL_REFUSED) { broker.exchange(channelRequest(1, wrong)) }
        }
        assertRefused(AcpProviderBrokerFailureKind.CHANNEL_REFUSED) { broker.exchange(channelRequest(2, capability)) }
        assertEquals(200, broker.exchange(channelRequest(1, capability)).status)
        assertRefused(AcpProviderBrokerFailureKind.CHANNEL_REFUSED) { broker.exchange(channelRequest(1, capability)) }
        assertRefused(AcpProviderBrokerFailureKind.CHANNEL_REFUSED) { other.exchange(channelRequest(1, capability)) }
        // A refused route still consumes its sequence: the frame cannot be replayed with a corrected head.
        assertRefused(AcpProviderBrokerFailureKind.ROUTE_REFUSED) { broker.exchange(channelRequest(2, capability, target = "/models")) }
        assertRefused(AcpProviderBrokerFailureKind.CHANNEL_REFUSED) { broker.exchange(channelRequest(2, capability)) }
        assertEquals(200, broker.exchange(channelRequest(3, capability)).status)

        broker.close()
        assertRefused(AcpProviderBrokerFailureKind.CHANNEL_REFUSED) { broker.exchange(channelRequest(4, capability)) }
        assertRefused(AcpProviderBrokerFailureKind.CHANNEL_REFUSED) { broker.exchange(channelRequest(4, ByteArray(32))) }
        assertEquals(2, connector.addresses.size)
        assertEquals(2, server.requests.size)
        assertFalse(broker.identity.invocationBindingSha256 == other.identity.invocationBindingSha256)
        assertEquals(broker.identity.requestBindingSha256.length, 64)
        diagnostics += broker.toString() + broker.identity.toString()
    }

    fun refusalsSendNothingUpstream() {
        val server = server()
        val connector = connector(server)
        val broker = broker(connector = connector)
        val capability = capability(broker)
        val capabilityHex = capabilityHex(capability)
        var sequence = 1L
        fun refused(kind: AcpProviderBrokerFailureKind, request: (Long) -> AcpProviderChannelRequest) =
            assertRefused(kind) { broker.exchange(request(sequence++)) }
        fun routeRefused(reason: AcpProviderRouteRefusal, request: (Long) -> AcpProviderChannelRequest) =
            assertEquals(reason, refused(AcpProviderBrokerFailureKind.ROUTE_REFUSED, request).routeRefusal)

        routeRefused(AcpProviderRouteRefusal.CONNECT_REFUSED) { channelRequest(it, capability, method = "CONNECT", target = "chatgpt.com:443") }
        routeRefused(AcpProviderRouteRefusal.PROXY_REQUEST_REFUSED) { channelRequest(it, capability, target = "https://evil.example/responses") }
        routeRefused(AcpProviderRouteRefusal.OPERATION_UNSUPPORTED) { channelRequest(it, capability, target = "/v1/responses") }
        routeRefused(AcpProviderRouteRefusal.ROUTING_OVERRIDE_REFUSED) {
            channelRequest(it, capability, fields = listOf("X-Forwarded-Host" to "evil.example"))
        }
        routeRefused(AcpProviderRouteRefusal.REQUEST_FRAMING_UNSUPPORTED) {
            channelRequest(it, capability, fields = listOf("Transfer-Encoding" to "chunked"), contentLength = null)
        }
        routeRefused(AcpProviderRouteRefusal.REQUEST_FRAMING_UNSUPPORTED) { channelRequest(it, capability, contentLength = null) }
        val oversized = "{\"model\":\"" + "x".repeat(policy.bounds.maximumRequestBytes) + "\"}"
        routeRefused(AcpProviderRouteRefusal.REQUEST_BODY_TOO_LARGE) { channelRequest(it, capability, body = oversized) }
        // The frame's body must be exactly the routed length and one strict JSON object.
        refused(AcpProviderBrokerFailureKind.REQUEST_REFUSED) { channelRequest(it, capability, contentLength = 3) }
        refused(AcpProviderBrokerFailureKind.REQUEST_REFUSED) { channelRequest(it, capability, contentLength = BODY.length + 1) }
        refused(AcpProviderBrokerFailureKind.REQUEST_REFUSED) { channelRequest(it, capability, body = "[]") }
        refused(AcpProviderBrokerFailureKind.REQUEST_REFUSED) { channelRequest(it, capability, body = """{"a":1,"a":2}""") }
        refused(AcpProviderBrokerFailureKind.REQUEST_REFUSED) { channelRequest(it, capability, body = "") }
        // The capability and the credential cannot travel upstream, even behind JSON escapes or in a name.
        val escaped = capabilityHex.map { "\\u%04x".format(it.code) }.joinToString("")
        listOf(
            """{"model":"gpt-6","input":"$capabilityHex"}""",
            """{"model":"gpt-6","input":"${capabilityHex.uppercase()}"}""",
            """{"model":"gpt-6","input":"$escaped"}""",
            """{"model":"gpt-6","$capabilityHex":1}""",
            """{"model":"gpt-6","input":["$token"]}""",
        ).forEach { body -> refused(AcpProviderBrokerFailureKind.SECRET_EXPOSURE) { channelRequest(it, capability, body = body) } }

        assertEquals(emptyList(), connector.addresses)
        assertEquals(0, server.accepted.get())
    }

    fun responsesAreRedactedAndStrict() {
        val responses = listOf(
            sseResponse("data: {\"echo\":\"$token\"}\n\n") to AcpProviderBrokerFailureKind.SECRET_EXPOSURE,
            rawResponse("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n") to AcpProviderBrokerFailureKind.MALFORMED_RESPONSE,
            rawResponse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}") to AcpProviderBrokerFailureKind.MALFORMED_RESPONSE,
            rawResponse("HTTP/1.1 200 OK\nContent-Type: text/event-stream\n\n") to AcpProviderBrokerFailureKind.MALFORMED_RESPONSE,
            rawResponse("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n folded: yes\r\n\r\n") to AcpProviderBrokerFailureKind.MALFORMED_RESPONSE,
            rawResponse("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n") to
                AcpProviderBrokerFailureKind.MALFORMED_RESPONSE,
            rawResponse("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: 1\r\n\r\n") to
                AcpProviderBrokerFailureKind.MALFORMED_RESPONSE,
            rawResponse("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 99999999\r\n\r\n") to
                AcpProviderBrokerFailureKind.RESPONSE_TOO_LARGE,
            rawResponse("HTTP/1.0 200 OK\r\nContent-Type: text/event-stream\r\n\r\n") to AcpProviderBrokerFailureKind.MALFORMED_RESPONSE,
        )
        responses.forEach { (response, expected) ->
            val server = server { response }
            val broker = broker(connector = connector(server))
            assertRefused(expected) { broker.exchange(channelRequest(1, capability(broker))) }
        }
        val failing = server { rawResponse("HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 80\r\n\r\n" +
            """{"error":"bad token $token"}""".padEnd(80)) }
        val broker = broker(connector = connector(failing))
        val result = broker.exchange(channelRequest(1, capability(broker)))
        assertEquals(401, result.status)
        assertNull(result.contentType)
        assertEquals(0, result.body.size)
        diagnostics += result.toString()
    }

    fun sandboxLaunchesCarryNoProviderAuthority() {
        val broker = broker(connector = LoopbackProviderConnector(1, AcpProviderUpstreamTls.platform(policy)))
        val capabilityHex = capabilityHex(capability(broker))
        val workspace = providerFixtureDirectory("launch")
        broker.requireNoProviderAuthority(launch(workspace))

        listOf(
            launch(workspace, command = listOf("/bin/sh", "-c", "echo $capabilityHex")),
            launch(workspace, environment = mapOf("PROVIDER" to capabilityHex.uppercase())),
            launch(workspace, environment = mapOf("OPENAI_ACCESS" to "Bearer $token")),
            launch(workspace, environment = mapOf(capabilityHex to "1")),
        ).forEach { assertRefused(AcpProviderBrokerFailureKind.SECRET_EXPOSURE) { broker.requireNoProviderAuthority(it) } }
        listOf(
            launch(workspace, mounts = listOf(AcpSandboxReadOnlyMount(codexHome))),
            launch(workspace, mounts = listOf(AcpSandboxReadOnlyMount(codexHome.parent, Path.of("/opt/provider")))),
            launch(workspace, mounts = listOf(AcpSandboxReadOnlyMount(codexHome.resolve("auth.json"), Path.of("/opt/auth.json")))),
            launch(codexHome),
        ).forEach { assertRefused(AcpProviderBrokerFailureKind.CREDENTIAL_SOURCE_VISIBLE) { broker.requireNoProviderAuthority(it) } }
        val linked = Files.createSymbolicLink(providerFixtureDirectory("link").resolve("home"), codexHome)
        assertRefused(AcpProviderBrokerFailureKind.CREDENTIAL_SOURCE_VISIBLE) {
            broker.requireNoProviderAuthority(launch(workspace, mounts = listOf(AcpSandboxReadOnlyMount(linked, Path.of("/opt/home")))))
        }
        broker.close()
        // Once closed, the source path stays protected; the dropped credential and capability are no longer held.
        assertRefused(AcpProviderBrokerFailureKind.CREDENTIAL_SOURCE_VISIBLE) { broker.requireNoProviderAuthority(launch(codexHome)) }
        broker.requireNoProviderAuthority(launch(workspace, command = listOf("/bin/sh", "-c", "echo $capabilityHex")))
    }

    fun childProcessInheritsNoAuthority() {
        if (!Files.isDirectory(Path.of("/proc/self/fd"))) return
        val held = CountDownLatch(1)
        val server = server().also { it.holdResponse = held }
        val broker = broker(connector = connector(server))
        val capabilityHex = capabilityHex(capability(broker))
        val executor = Executors.newSingleThreadExecutor()
        try {
            val exchange = executor.submit<AcpProviderExchangeResult> { broker.exchange(channelRequest(1, capability(broker, reuse = true))) }
            assertTrue(server.requestReceived.await(10, TimeUnit.SECONDS), "the upstream request is in flight")

            // The host starts a child with its inherited environment while the upstream TLS connection is open.
            val child = ProcessBuilder("/bin/sh", "-c", "tr '\\000' '\\n' < /proc/self/environ; for fd in /proc/$$/fd/*; do readlink \"\$fd\" || true; done")
                .redirectErrorStream(true).start()
            val output = child.inputStream.readAllBytes().toString(StandardCharsets.UTF_8)
            assertTrue(child.waitFor(10, TimeUnit.SECONDS))
            assertEquals(0, child.exitValue())
            assertFalse(output.contains(token))
            assertFalse(output.contains(capabilityHex, ignoreCase = true))
            assertFalse(output.contains(codexHome.toString()))
            // The listing is real: the shell's own stdout pipe appears, and no socket does.
            assertTrue(output.lines().any { it.startsWith("pipe:[") }, "descriptor listing is present")
            assertFalse(output.lines().any { it.startsWith("socket:") }, "no socket descriptor is inherited")

            held.countDown()
            assertEquals(200, exchange.get(10, TimeUnit.SECONDS).status)
        } finally {
            held.countDown()
            executor.shutdownNow()
        }
    }

    fun closeAbortsInFlightExchange() {
        val held = CountDownLatch(1)
        val server = server().also { it.holdResponse = held }
        val broker = broker(connector = connector(server))
        val capability = capability(broker)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val exchange = executor.submit<Result<AcpProviderExchangeResult>> { runCatching { broker.exchange(channelRequest(1, capability)) } }
            assertTrue(server.requestReceived.await(10, TimeUnit.SECONDS))
            broker.close()
            val failure = exchange.get(5, TimeUnit.SECONDS).exceptionOrNull() as AcpProviderBrokerFailure
            assertEquals(AcpProviderBrokerFailureKind.CHANNEL_REFUSED, failure.kind)
            diagnostics += failure.stackTraceToString()
        } finally {
            held.countDown()
            executor.shutdownNow()
        }
    }

    private fun server(store: Path = stores.trusted, response: ((ObservedProviderRequest) -> ByteArray)? = null): LocalProviderServer =
        (if (response == null) LocalProviderServer(store) else LocalProviderServer(store, response)).also(closeables::add)

    /** The production platform-trust client, reached on loopback through its private layered handshake. */
    private fun connector(server: LocalProviderServer) = LoopbackProviderConnector(server.port, AcpProviderUpstreamTls.platform(policy))

    private fun broker(
        resolver: AcpProviderDestinationResolver = FixedProviderResolver(listOf(pinned)),
        connector: AcpProviderUpstreamConnector,
    ): AcpProviderBroker = AcpProviderBroker.open(
        policy, providerFixtureRequest(), AcpProviderCredentialSource.LocalCodexCachedAuth(codexHome), resolver, connector, clock,
    ).also(closeables::add).also { diagnostics += it.toString() }

    /** The contained relay's side of the private channel setup: read the one-time grant from its stream. */
    private fun capability(broker: AcpProviderBroker, reuse: Boolean = false): ByteArray {
        if (reuse) return granted.getValue(broker).copyOf()
        val grant = broker.grantChannel()
        diagnostics += grant.toString()
        val bytes = ByteArrayOutputStream().also(grant::writeTo).toByteArray()
        assertEquals(32, bytes.size)
        capabilities += capabilityHex(bytes)
        granted[broker] = bytes
        return bytes.copyOf()
    }

    private fun capabilityHex(capability: ByteArray): String = capability.joinToString("") { "%02x".format(it) }

    /** A frame as the contained relay would pass it on: exact head bytes, then the body. */
    private fun channelRequest(
        sequence: Long,
        capability: ByteArray,
        body: String = BODY,
        method: String = "POST",
        target: String = "/responses",
        host: String = "127.0.0.1:9",
        fields: List<Pair<String, String>> = listOf("Content-Type" to "application/json"),
        contentLength: Int? = body.toByteArray().size,
    ): AcpProviderChannelRequest {
        val head = relayHead(method, target, listOf("Host" to host) + fields +
            listOfNotNull(contentLength?.let { "Content-Length" to it.toString() }))
        return AcpProviderChannelRequest(sequence, capability, head, body.toByteArray())
    }

    private fun launch(
        workingDirectory: Path,
        command: List<String> = listOf("/usr/bin/true"),
        environment: Map<String, String> = mapOf("PATH" to "/usr/bin:/bin"),
        mounts: List<AcpSandboxReadOnlyMount> = emptyList(),
    ) = AcpSandboxLaunch(
        command = command,
        environment = environment,
        workingDirectory = workingDirectory,
        resourceLimits = AcpSandboxResourceLimits(),
        maximumWallDuration = Duration.ofSeconds(5),
        readOnlyMounts = mounts,
        stagingRoots = emptyList(),
        purpose = AcpSandboxLaunchPurpose.CANDIDATE_VALIDATION,
    )

    private fun assertRefused(kind: AcpProviderBrokerFailureKind, block: () -> Unit): AcpProviderBrokerFailure {
        val failure = assertFailsWith<AcpProviderBrokerFailure> { block() }
        assertEquals(kind, failure.kind, failure.message)
        assertNull(failure.cause)
        diagnostics += failure.stackTraceToString()
        return failure
    }

    companion object {
        const val BODY = """{"model":"gpt-6","input":[{"role":"user","content":"hello"}],"stream":true,"store":false}"""
    }
}

/** Server identity stores written by the parent test under build/. */
internal class ProviderScenarioStores(val trusted: Path, val wrongHost: Path, val untrusted: Path)

/** Child-JVM entry point: runs one named scenario and prints a single result line. */
object AcpProviderBrokerScenarios {
    internal val SCENARIOS: Map<String, (AcpProviderBrokerScenario) -> Unit> = mapOf(
        "credentialCheckedBeforeAnySideEffect" to AcpProviderBrokerScenario::credentialCheckedBeforeAnySideEffect,
        "pinnedNumericAddressWithoutReResolution" to AcpProviderBrokerScenario::pinnedNumericAddressWithoutReResolution,
        "refusedDestinationsFailBeforeConnecting" to AcpProviderBrokerScenario::refusedDestinationsFailBeforeConnecting,
        "tlsUsesPolicyHostForSniAndVerification" to AcpProviderBrokerScenario::tlsUsesPolicyHostForSniAndVerification,
        "platformTrustRefusesTheTestRoot" to AcpProviderBrokerScenario::platformTrustRefusesTheTestRoot,
        "redirectsRefusedAndNeverFollowed" to AcpProviderBrokerScenario::redirectsRefusedAndNeverFollowed,
        "upstreamHeadFromPolicyAndBrokerValues" to AcpProviderBrokerScenario::upstreamHeadFromPolicyAndBrokerValues,
        "channelBoundToCapabilityAndSequence" to AcpProviderBrokerScenario::channelBoundToCapabilityAndSequence,
        "refusalsSendNothingUpstream" to AcpProviderBrokerScenario::refusalsSendNothingUpstream,
        "responsesAreRedactedAndStrict" to AcpProviderBrokerScenario::responsesAreRedactedAndStrict,
        "sandboxLaunchesCarryNoProviderAuthority" to AcpProviderBrokerScenario::sandboxLaunchesCarryNoProviderAuthority,
        "childProcessInheritsNoAuthority" to AcpProviderBrokerScenario::childProcessInheritsNoAuthority,
        "closeAbortsInFlightExchange" to AcpProviderBrokerScenario::closeAbortsInFlightExchange,
    )

    @JvmStatic
    fun main(args: Array<String>) {
        val (name, trusted, wrongHost, untrusted) = args
        val scenario = AcpProviderBrokerScenario(ProviderScenarioStores(Path.of(trusted), Path.of(wrongHost), Path.of(untrusted)))
        val status = try {
            SCENARIOS.getValue(name)(scenario)
            scenario.finish()
            "SCENARIO_OK $name"
        } catch (failure: Throwable) {
            failure.printStackTrace(System.out)
            "SCENARIO_FAILED $name"
        }
        println(status)
        System.out.flush()
        Runtime.getRuntime().halt(if (status.startsWith("SCENARIO_OK")) 0 else 1)
    }
}
