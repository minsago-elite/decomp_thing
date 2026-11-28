package decompengine.acp

import java.net.Inet6Address
import java.net.InetAddress
import java.util.Properties
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull

class AcpProviderRoutingTest {
    private val policy = AcpProviderTransportPolicy.fromOperatorPolicy(providerPolicyConfiguration()) as AcpProviderTransportPolicy.Approved

    @Test
    fun `the declared operation routes only to the approved endpoint whatever host the agent names`() {
        listOf("127.0.0.1:41000", "evil.example", "169.254.169.254", "chatgpt.com").forEach { host ->
            val decision = assertIs<AcpProviderRouteDecision.Routed>(
                AcpProviderRouting.route(policy, request(headers = listOf("Host" to host, "Content-Type" to "application/json"))),
            )
            assertEquals(AcpProviderOperation.RESPONSES_CREATE, decision.operation)
            assertEquals(APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT, decision.endpoint)
            assertEquals(policy.descriptorSha256, decision.policyDescriptorSha256)
        }
    }

    @Test
    fun `a disabled transport refuses every request response and destination before inspecting it`() {
        val disabled = AcpProviderTransportPolicy.DISABLED
        listOf(request(), request(method = "CONNECT", target = "chatgpt.com:443"), request(target = "garbage\r\n")).forEach {
            assertRefused(AcpProviderRouteRefusal.TRANSPORT_DISABLED, AcpProviderRouting.route(disabled, it))
        }
        assertEquals(AcpProviderRouteRefusal.TRANSPORT_DISABLED, AcpProviderRouting.responseStatusRefusal(disabled, 200))
        assertEquals(AcpProviderRouteRefusal.TRANSPORT_DISABLED, AcpProviderRouting.destinationRefusal(disabled, listOf(address("8.8.8.8"))))
    }

    @Test
    fun `CONNECT tunnels and proxy request forms are refused`() {
        listOf("chatgpt.com:443", "/responses", "127.0.0.1:22").forEach { target ->
            assertRefused(AcpProviderRouteRefusal.CONNECT_REFUSED, AcpProviderRouting.route(policy, request(method = "CONNECT", target = target)))
        }
        listOf(
            "https://chatgpt.com/backend-api/codex/responses",
            "http://chatgpt.com/responses",
            "HTTPS://evil.example/responses",
            "ws://chatgpt.com/responses",
            "file:///etc/passwd",
            "chatgpt.com:443",
            "*",
        ).forEach { target ->
            assertRefused(AcpProviderRouteRefusal.PROXY_REQUEST_REFUSED, AcpProviderRouting.route(policy, request(target = target)), target)
        }
    }

    @Test
    fun `agent-selected paths queries and methods cannot select another operation`() {
        listOf(
            "/responses/", "/Responses", "/v1/responses", "/backend-api/codex/responses", "/%72esponses", "/./responses",
            "//chatgpt.com/responses", "/responses/../models", "/models", "/responses/compact", "/responses;x=1", "/",
        ).forEach { target ->
            assertRefused(AcpProviderRouteRefusal.OPERATION_UNSUPPORTED, AcpProviderRouting.route(policy, request(target = target)), target)
        }
        listOf("/responses?url=https://evil.example/", "/responses?").forEach { target ->
            assertRefused(AcpProviderRouteRefusal.QUERY_REFUSED, AcpProviderRouting.route(policy, request(target = target)), target)
        }
        listOf("GET", "PUT", "post", "OPTIONS").forEach { method ->
            assertRefused(AcpProviderRouteRefusal.METHOD_UNSUPPORTED, AcpProviderRouting.route(policy, request(method = method)), method)
        }
    }

    @Test
    fun `forwarding and override headers cannot extend authority`() {
        listOf(
            "Forwarded" to "host=evil.example;proto=http", "X-Forwarded-Host" to "evil.example", "x-forwarded-proto" to "http",
            "X-Forwarded-Port" to "80", "X-Forwarded-Prefix" to "/v1", "X-Original-URL" to "/models", "X-Original-Host" to "evil.example",
            "X-Rewrite-URL" to "/models", "X-Host" to "evil.example", "X-HTTP-Method-Override" to "GET",
            "Proxy-Authorization" to "Basic Zm9vOmJhcg==", "Proxy-Connection" to "keep-alive",
        ).forEach { header ->
            assertRefused(
                AcpProviderRouteRefusal.ROUTING_OVERRIDE_REFUSED,
                AcpProviderRouting.route(policy, request(headers = listOf("Host" to "relay", header))),
                header.first,
            )
        }
        listOf(
            listOf("Upgrade" to "websocket", "Connection" to "Upgrade"),
            listOf("Connection" to "keep-alive, upgrade"),
            listOf("HTTP2-Settings" to "AAMAAABkAAQAAP__"),
        ).forEach { headers ->
            assertRefused(AcpProviderRouteRefusal.PROTOCOL_UPGRADE_REFUSED, AcpProviderRouting.route(policy, request(headers = listOf("Host" to "relay") + headers)))
        }
    }

    @Test
    fun `ambiguous or malformed request heads are refused`() {
        listOf(
            request(headers = emptyList()),
            request(headers = listOf("Host" to "relay", "host" to "evil.example")),
            request(headers = listOf("Host" to "relay\r\nHost: evil.example")),
            request(headers = listOf("Host" to "relay", "Bad Name" to "x")),
            request(headers = listOf("Host" to "relay", "Content-Length" to "5", "Transfer-Encoding" to "chunked")),
            request(headers = listOf("Host" to "relay", "Content-Length" to "5", "content-length" to "6")),
            request(target = "/responses#fragment"),
            request(target = "/respo nses"),
            request(target = ""),
            request(method = "PO ST"),
        ).forEach { assertRefused(AcpProviderRouteRefusal.MALFORMED_REQUEST, AcpProviderRouting.route(policy, it)) }
    }

    @Test
    fun `request heads above the policy header bounds are refused`() {
        val bounded = AcpProviderTransportPolicy.fromOperatorPolicy(
            providerPolicyConfiguration() + ("maximumHeaderFields" to "2") + ("maximumHeaderBytes" to "64"),
        ) as AcpProviderTransportPolicy.Approved
        assertIs<AcpProviderRouteDecision.Routed>(AcpProviderRouting.route(bounded, request(headers = listOf("Host" to "relay"))))
        assertRefused(
            AcpProviderRouteRefusal.REQUEST_HEAD_TOO_LARGE,
            AcpProviderRouting.route(bounded, request(headers = listOf("Host" to "relay", "A" to "1", "B" to "2"))),
        )
        assertRefused(
            AcpProviderRouteRefusal.REQUEST_HEAD_TOO_LARGE,
            AcpProviderRouting.route(bounded, request(headers = listOf("Host" to "relay", "A" to "x".repeat(64)))),
        )
    }

    @Test
    fun `upstream redirects are never followed because the policy declares no redirect destination`() {
        (300..399).forEach { status ->
            assertEquals(AcpProviderRouteRefusal.REDIRECT_UNDECLARED, AcpProviderRouting.responseStatusRefusal(policy, status))
        }
        listOf(200, 400, 401, 429, 500).forEach { assertNull(AcpProviderRouting.responseStatusRefusal(policy, it)) }
        listOf(0, 99, 600).forEach {
            assertEquals(AcpProviderRouteRefusal.MALFORMED_RESPONSE, AcpProviderRouting.responseStatusRefusal(policy, it))
        }
    }

    @Test
    fun `resolved destinations must be public unless the operator permits private addresses`() {
        val permitted = AcpProviderTransportPolicy.fromOperatorPolicy(
            providerPolicyConfiguration() + ("privateDestinations" to "PERMITTED"),
        ) as AcpProviderTransportPolicy.Approved
        val public = listOf("104.18.32.47", "8.8.8.8", "2606:4700::6812:202f", "2002:0808:0808::1", "64:ff9b::808:808")
        public.forEach { assertNull(AcpProviderRouting.destinationRefusal(policy, listOf(address(it))), it) }

        val private = listOf("10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "fd00::1", "2002:0a00:0001::1")
        private.forEach {
            assertEquals(AcpProviderRouteRefusal.PRIVATE_DESTINATION_NOT_PERMITTED, AcpProviderRouting.destinationRefusal(policy, listOf(address(it))), it)
            assertNull(AcpProviderRouting.destinationRefusal(permitted, listOf(address(it))), it)
        }

        val forbidden = listOf(
            "127.0.0.1", "127.1.2.3", "0.0.0.0", "169.254.169.254", "224.0.0.1", "255.255.255.255", "240.0.0.1",
            "192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1", "192.0.0.8",
            "::", "::1", "::127.0.0.1", "fe80::1", "fec0::1", "ff02::1", "2001:db8::1", "2001::1", "3fff::1", "100::1",
            "64:ff9b::7f00:1", "2002:7f00:0001::1", "64:ff9b:1::1",
        )
        forbidden.forEach {
            assertEquals(AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED, AcpProviderRouting.destinationRefusal(policy, listOf(address(it))), it)
            assertEquals(AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED, AcpProviderRouting.destinationRefusal(permitted, listOf(address(it))), it)
        }
        val mappedLoopback = Inet6Address.getByAddress(null, ByteArray(16).also { it[10] = -1; it[11] = -1; it[12] = 127; it[15] = 1 }, null)
        assertEquals(AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED, AcpProviderRouting.destinationRefusal(policy, listOf(mappedLoopback)))

        assertEquals(AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED, AcpProviderRouting.destinationRefusal(policy, emptyList()))
        assertEquals(
            AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED,
            AcpProviderRouting.destinationRefusal(permitted, listOf(address("8.8.8.8"), address("10.0.0.1"), address("127.0.0.1"))),
        )
    }

    @Test
    fun `upstream TLS requires hostname verification policy SNI and modern protocols`() {
        val defaults = SSLContext.getDefault().defaultSSLParameters
        val parameters = AcpProviderRouting.upstreamSslParameters(policy, defaults)
        assertEquals("HTTPS", parameters.endpointIdentificationAlgorithm)
        assertEquals(listOf("chatgpt.com"), parameters.serverNames.map { (it as SNIHostName).asciiName })
        AcpProviderRouting.requireMandatoryUpstreamTls(policy, parameters, Properties())

        val weakened = listOf<SSLParameters.() -> Unit>(
            { endpointIdentificationAlgorithm = null },
            { endpointIdentificationAlgorithm = "LDAPS" },
            { protocols = arrayOf("TLSv1.3", "TLSv1.1") },
            { protocols = arrayOf() },
            { serverNames = listOf(SNIHostName("evil.example")) },
            { serverNames = emptyList() },
            { protocols = null },
        )
        val unset = SSLParameters().apply { endpointIdentificationAlgorithm = "HTTPS" }
        assertFailsWith<IllegalStateException> { AcpProviderRouting.requireMandatoryUpstreamTls(policy, unset, Properties()) }
        weakened.forEach { weaken ->
            val copy = AcpProviderRouting.upstreamSslParameters(policy, defaults).apply(weaken)
            assertFailsWith<IllegalStateException> { AcpProviderRouting.requireMandatoryUpstreamTls(policy, copy, Properties()) }
        }
        listOf("", "true", "false").forEach { value ->
            val properties = Properties().apply { setProperty("jdk.internal.httpclient.disableHostnameVerification", value) }
            assertFailsWith<IllegalStateException>(value) { AcpProviderRouting.requireMandatoryUpstreamTls(policy, parameters, properties) }
        }
        assertFailsWith<IllegalArgumentException> {
            AcpProviderRouting.upstreamSslParameters(policy, SSLParameters(defaults.cipherSuites, arrayOf("TLSv1.1")))
        }
    }

    private fun request(
        method: String = "POST",
        target: String = "/responses",
        headers: List<Pair<String, String>> = listOf("Host" to "127.0.0.1:41000"),
    ) = AcpProviderRelayRequest(method, target, headers)

    private fun assertRefused(expected: AcpProviderRouteRefusal, decision: AcpProviderRouteDecision, message: String? = null) {
        assertEquals(AcpProviderRouteDecision.Refused(expected), decision, message)
    }

    // Literal parsing only: InetAddress.getByName performs no DNS lookup for numeric addresses.
    private fun address(literal: String): InetAddress = InetAddress.getByName(literal)
}
