package decompengine.acp

import java.net.Inet6Address
import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

class AcpProviderRoutingTest {
    private val policy = approved()

    @Test
    fun `the declared operation routes only to the approved endpoint whatever host the agent names`() {
        listOf("127.0.0.1:41000", "evil.example", "169.254.169.254", "chatgpt.com").forEach { host ->
            val decision = assertIs<AcpProviderRouteDecision.Routed>(
                AcpProviderRouting.route(policy, head(fields = listOf("Host" to host, "Content-Type" to "text/plain", "Content-Length" to "17"))),
            )
            assertEquals(AcpProviderOperation.RESPONSES_CREATE, decision.operation)
            assertEquals(APPROVED_CODEX_CHATGPT_RESPONSES_ENDPOINT, decision.endpoint)
            assertEquals(policy.descriptorSha256, decision.policyDescriptorSha256)
            assertEquals(17, decision.contentLength)
        }
    }

    @Test
    fun `upstream headers are rebuilt from policy values and the validated length only`() {
        val routed = assertIs<AcpProviderRouteDecision.Routed>(AcpProviderRouting.route(policy, head(fields = listOf(
            "Host" to "evil.example", "Content-Length" to "42", "Content-Type" to "text/x-evil", "Accept" to "*/*",
            "Authorization" to "Bearer agent-chosen", "Cookie" to "a=b", "User-Agent" to "agent",
        ))))
        assertEquals(
            listOf(
                "Host" to "chatgpt.com", "Content-Type" to "application/json", "Accept" to "text/event-stream",
                "Content-Length" to "42",
            ),
            routed.upstreamHeaders(),
        )
    }

    @Test
    fun `a disabled transport refuses every request response and destination before inspecting it`() {
        val disabled = AcpProviderTransportPolicy.DISABLED
        listOf(head(), head(method = "CONNECT", target = "chatgpt.com:443"), "garbage".toByteArray()).forEach {
            assertRefused(AcpProviderRouteRefusal.TRANSPORT_DISABLED, AcpProviderRouting.route(disabled, it))
        }
        assertEquals(AcpProviderRouteRefusal.TRANSPORT_DISABLED, AcpProviderRouting.responseStatusRefusal(disabled, 200))
        assertEquals(AcpProviderRouteRefusal.TRANSPORT_DISABLED, AcpProviderRouting.destinationRefusal(disabled, listOf(address("8.8.8.8"))))
    }

    @Test
    fun `CONNECT tunnels and proxy request forms are refused`() {
        listOf("chatgpt.com:443", "/responses", "127.0.0.1:22").forEach { target ->
            assertRefused(AcpProviderRouteRefusal.CONNECT_REFUSED, AcpProviderRouting.route(policy, head(method = "CONNECT", target = target)))
        }
        listOf(
            "https://chatgpt.com/backend-api/codex/responses", "http://chatgpt.com/responses", "HTTPS://evil.example/responses",
            "ws://chatgpt.com/responses", "file:///etc/passwd", "chatgpt.com:443", "*",
        ).forEach { target ->
            assertRefused(AcpProviderRouteRefusal.PROXY_REQUEST_REFUSED, AcpProviderRouting.route(policy, head(target = target)), target)
        }
    }

    @Test
    fun `agent-selected paths queries and methods cannot select another operation`() {
        listOf(
            "/responses/", "/Responses", "/v1/responses", "/backend-api/codex/responses", "/%72esponses", "/./responses",
            "//chatgpt.com/responses", "/responses/../models", "/models", "/responses/compact", "/responses;x=1", "/",
        ).forEach { target ->
            assertRefused(AcpProviderRouteRefusal.OPERATION_UNSUPPORTED, AcpProviderRouting.route(policy, head(target = target)), target)
        }
        listOf("/responses?url=https://evil.example/", "/responses?").forEach { target ->
            assertRefused(AcpProviderRouteRefusal.QUERY_REFUSED, AcpProviderRouting.route(policy, head(target = target)), target)
        }
        listOf("GET", "PUT", "post", "OPTIONS").forEach { method ->
            assertRefused(AcpProviderRouteRefusal.METHOD_UNSUPPORTED, AcpProviderRouting.route(policy, head(method = method)), method)
        }
    }

    @Test
    fun `forwarding and override headers cannot extend authority`() {
        listOf(
            "Forwarded" to "host=evil.example;proto=http", "X-Forwarded-Host" to "evil.example", "x-forwarded-proto" to "http",
            "X-Forwarded-Port" to "80", "X-Forwarded-Prefix" to "/v1", "X-Original-URL" to "/models", "X-Original-Host" to "evil.example",
            "X-Rewrite-URL" to "/models", "X-Host" to "evil.example", "X-HTTP-Method-Override" to "GET",
            "Proxy-Authorization" to "Basic Zm9vOmJhcg==", "Proxy-Connection" to "keep-alive",
        ).forEach { field ->
            assertRefused(AcpProviderRouteRefusal.ROUTING_OVERRIDE_REFUSED, AcpProviderRouting.route(policy, head(extra = listOf(field))), field.first)
        }
        listOf(
            listOf("Upgrade" to "websocket", "Connection" to "Upgrade"),
            listOf("Connection" to "keep-alive,\tupgrade"),
            listOf("HTTP2-Settings" to "AAMAAABkAAQAAP__"),
        ).forEach { fields ->
            assertRefused(AcpProviderRouteRefusal.PROTOCOL_UPGRADE_REFUSED, AcpProviderRouting.route(policy, head(extra = fields)))
        }
    }

    @Test
    fun `only one canonical Content-Length delimits a request body`() {
        listOf("0", "1", "1048576").forEach { length ->
            assertEquals(length.toInt(), assertIs<AcpProviderRouteDecision.Routed>(AcpProviderRouting.route(policy, head(length = length))).contentLength)
        }
        listOf("01", "+5", "-1", "5, 5", "5,5", "0x10", "1e3", "5 5", "", "12345678901", "١").forEach { length ->
            assertRefused(AcpProviderRouteRefusal.MALFORMED_REQUEST, AcpProviderRouting.route(policy, head(length = length)), length)
        }
        assertRefused(AcpProviderRouteRefusal.REQUEST_BODY_TOO_LARGE, AcpProviderRouting.route(policy, head(length = "1048577")))
        assertRefused(AcpProviderRouteRefusal.REQUEST_FRAMING_UNSUPPORTED, AcpProviderRouting.route(policy, head(length = null)))
        assertRefused(
            AcpProviderRouteRefusal.MALFORMED_REQUEST,
            AcpProviderRouting.route(policy, head(extra = listOf("content-length" to "5"))),
        )
        listOf(
            "Transfer-Encoding" to "chunked", "Transfer-Encoding" to "gzip, chunked", "Transfer-Encoding" to "identity",
            "transfer-encoding" to "chunked, chunked", "TE" to "trailers", "Expect" to "100-continue",
            "Content-Encoding" to "zstd", "Content-Encoding" to "identity", "Trailer" to "X-Checksum",
        ).forEach { field ->
            assertRefused(AcpProviderRouteRefusal.REQUEST_FRAMING_UNSUPPORTED, AcpProviderRouting.route(policy, head(extra = listOf(field))), field.toString())
            assertRefused(
                AcpProviderRouteRefusal.REQUEST_FRAMING_UNSUPPORTED,
                AcpProviderRouting.route(policy, head(length = null, extra = listOf(field))),
                field.toString(),
            )
        }
    }

    @Test
    fun `malformed request heads and prohibited field characters are refused`() {
        val valid = "POST /responses HTTP/1.1\r\nHost: relay\r\nContent-Length: 2\r\n\r\n"
        assertIs<AcpProviderRouteDecision.Routed>(AcpProviderRouting.route(policy, valid.toByteArray()))
        assertIs<AcpProviderRouteDecision.Routed>(
            AcpProviderRouting.route(policy, "POST /responses HTTP/1.1\r\nHost:\t relay \t\r\nContent-Length:2\r\nX-Note: a\tb\r\n\r\n".toByteArray()),
        )
        listOf(
            "POST /responses HTTP/1.1\r\nContent-Length: 2\r\n\r\n",
            "POST /responses HTTP/1.1\r\nHost: relay\r\nhost: evil.example\r\nContent-Length: 2\r\n\r\n",
            "POST /responses HTTP/1.1\r\nHost: relay\r\nContent-Length: 2\r\n",
            "POST /responses HTTP/1.1\r\nHost: relay\r\nContent-Length: 2\r\n\r\nGET /models HTTP/1.1\r\n\r\n",
            "\r\nPOST /responses HTTP/1.1\r\nHost: relay\r\nContent-Length: 2\r\n\r\n",
            "POST /responses HTTP/1.1\nHost: relay\nContent-Length: 2\n\n",
            "POST /responses HTTP/1.1\r\nHost: relay\nX: y\r\nContent-Length: 2\r\n\r\n",
            "POST /responses HTTP/1.1\r\nHost: relay\rX: y\r\nContent-Length: 2\r\n\r\n",
            "POST /responses HTTP/1.1\r\nHost : relay\r\nContent-Length: 2\r\n\r\n",
            "POST /responses HTTP/1.1\r\nHost: relay\r\n folded\r\nContent-Length: 2\r\n\r\n",
            "POST /responses HTTP/1.1\r\n\tHost: relay\r\nContent-Length: 2\r\n\r\n",
            "POST /responses HTTP/1.1\r\nHost: relay\r\nBad Name: x\r\nContent-Length: 2\r\n\r\n",
            "POST /responses HTTP/1.1\r\nHost: relay\r\n: x\r\nContent-Length: 2\r\n\r\n",
            "POST /responses HTTP/1.1\r\nHost: relay\r\nNoColon\r\nContent-Length: 2\r\n\r\n",
            "POST  /responses HTTP/1.1\r\nHost: relay\r\nContent-Length: 2\r\n\r\n",
            "POST /responses  HTTP/1.1\r\nHost: relay\r\nContent-Length: 2\r\n\r\n",
            "POST /responses\r\nHost: relay\r\nContent-Length: 2\r\n\r\n",
            "POST /responses HTTP/1.0\r\nHost: relay\r\nContent-Length: 2\r\n\r\n",
            "POST /responses HTTP/2\r\nHost: relay\r\nContent-Length: 2\r\n\r\n",
            "POST /responses http/1.1\r\nHost: relay\r\nContent-Length: 2\r\n\r\n",
            "PO\tST /responses HTTP/1.1\r\nHost: relay\r\nContent-Length: 2\r\n\r\n",
            "POST /responses#fragment HTTP/1.1\r\nHost: relay\r\nContent-Length: 2\r\n\r\n",
            "POST /respo\u0001nses HTTP/1.1\r\nHost: relay\r\nContent-Length: 2\r\n\r\n",
        ).forEach { text -> assertRefused(AcpProviderRouteRefusal.MALFORMED_REQUEST, AcpProviderRouting.route(policy, text.toByteArray()), text) }

        // Every C0 control other than HTAB, plus DEL and any non-ASCII byte, is refused inside a field value.
        ((0x00..0x1f).filter { it != 0x09 && it != 0x0a && it != 0x0d } + 0x7f + 0x80 + 0xff).forEach { byte ->
            val bytes = head(extra = listOf("X-Note" to "a#b")).also { raw -> raw[raw.indexOf('#'.code.toByte())] = byte.toByte() }
            assertRefused(AcpProviderRouteRefusal.MALFORMED_REQUEST, AcpProviderRouting.route(policy, bytes), "byte $byte")
        }
    }

    @Test
    fun `the Host field must follow the uri-host and port grammar before it is discarded`() {
        listOf(
            "relay", "127.0.0.1:41000", "[::1]:41000", "[2001:db8::1]", "[::ffff:127.0.0.1]:1", "[1:2:3:4:5:6:7:8]",
            "a-b.example", "x%41y", "host:65535", "host:0", "sub!$&'()*+,;=delims", "1.2.3.256", "under_score~",
        ).forEach { host ->
            val routed = assertIs<AcpProviderRouteDecision.Routed>(AcpProviderRouting.route(policy, head(fields = listOf("Host" to host, "Content-Length" to "2"))), host)
            assertEquals("chatgpt.com", routed.upstreamHeaders().first { it.first == "Host" }.second)
        }
        listOf(
            "", "relay:", "relay:65536", "relay:123456", "relay:-1", "relay:1:2", "relay: 1", ":41000", "[::1", "::1", "[::1]x",
            "[::1]:", "[::1]:99999", "[]", "[v1.x]", "[fe80::1%eth0]", "[fe80::1%25eth0]", "[1::2::3]", "[12345::]",
            "[1:2:3:4:5:6:7:8:9]", "[1:2:3:4:5:6:7]", "[::1.2.3.256]", "[::01.2.3.4]", "[1.2.3.4]", "[:1::]", "[1:::2]",
            "re lay", "re\tlay", "relay/path", "user@relay", "relay?x", "relay#x", "%zz", "%4", "relay%", "\"relay\"", "<relay>",
        ).forEach { host ->
            assertRefused(AcpProviderRouteRefusal.MALFORMED_REQUEST, AcpProviderRouting.route(policy, head(fields = listOf("Host" to host, "Content-Length" to "2"))), host)
        }
    }

    @Test
    fun `the head byte bound counts the request line field lines and terminator exactly`() {
        val exact = head(fields = listOf("Host" to "r", "Content-Length" to "1"))
        val bounded = approved("maximumHeaderBytes" to exact.size.toString(), "maximumHeaderFields" to "2")
        assertIs<AcpProviderRouteDecision.Routed>(AcpProviderRouting.route(bounded, exact))
        assertRefused(AcpProviderRouteRefusal.REQUEST_HEAD_TOO_LARGE, AcpProviderRouting.route(approved("maximumHeaderBytes" to (exact.size - 1).toString()), exact))
        val twoFields = approved("maximumHeaderFields" to "2")
        assertRefused(
            AcpProviderRouteRefusal.REQUEST_HEAD_TOO_LARGE,
            AcpProviderRouting.route(twoFields, head(fields = listOf("Host" to "r", "Content-Length" to "1", "A" to "1"))),
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
    fun `public IPv4 and allocated IPv6 global unicast destinations are admitted`() {
        listOf(
            "104.18.32.47", "8.8.8.8", "1.1.1.1", "2606:4700::6812:202f", "2001:4860:4860::8888", "2a00:1450:4001::200e",
            "2400:cb00::1", "2800:3f0::1", "2c0f:fb50::1", "2003:de::1", "2610:a1::1", "2620:fe::fe", "2630::1", "2a10::1",
        ).forEach { assertNull(AcpProviderRouting.destinationRefusal(policy, listOf(address(it))), it) }
    }

    @Test
    fun `registry block boundaries admit allocated space and refuse its unallocated and special neighbours`() {
        val six = ":ffff".repeat(6)
        val seven = ":ffff".repeat(7)
        val admitted = listOf(
            "2410::", "241f$seven", "2c00::", "2c0f$seven", "2001:200::", "2001:e00::", "2001:fff$six",
            "2001:1200::", "2001:4dff$six", "2001:5000::", "2001:5fff$six", "2001:8000::", "2001:bfff$six",
            "2003::", "2003:3fff$six", "2610::", "2610:1ff$six", "2620::", "2620:1ff$six", "2630::",
            "2001:db7$six", "2001:db9::", "2620:4f:7fff:ffff:ffff:ffff:ffff:ffff", "2620:4f:8001::",
        )
        admitted.forEach { assertNull(AcpProviderRouting.destinationRefusal(policy, listOf(address(it))), it) }
        val refused = listOf(
            "2420::", "2c10::", "2bff$seven", "2001:1000::", "2001:11ff$six", "2001:4e00::", "2001:4fff$six",
            "2001:6000::", "2001:7fff$six", "2001:c000::", "2001:ffff$six", "2001:1ff$six", "2003:4000::",
            "2610:200::", "2611$seven", "2612::", "2620:200::", "2621$seven", "2622::", "262f$seven", "2d00::", "3fff::", "2001:db8::", "2001:db8$six",
            "2620:4f:8000::", "2620:4f:8000:ffff:ffff:ffff:ffff:ffff", "2002::", "2002$seven",
        )
        refused.forEach {
            assertEquals(AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED, AcpProviderRouting.destinationRefusal(policy, listOf(address(it))), it)
        }
    }

    @Test
    fun `private destinations require explicit operator permission`() {
        val permitted = approved("privateDestinations" to "PERMITTED")
        listOf("10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "fd00::1", "fc00::1").forEach {
            assertEquals(AcpProviderRouteRefusal.PRIVATE_DESTINATION_NOT_PERMITTED, AcpProviderRouting.destinationRefusal(policy, listOf(address(it))), it)
            assertNull(AcpProviderRouting.destinationRefusal(permitted, listOf(address(it))), it)
        }
    }

    @Test
    fun `special-purpose transition and reserved destinations are refused even when private is permitted`() {
        val permissive = approved("privateDestinations" to "PERMITTED", "addressTranslation" to "WELL_KNOWN_NAT64")
        val refused = mapOf(
            "IPv4 this-network" to "0.0.0.1", "IPv4 loopback" to "127.1.2.3", "IPv4 link-local metadata" to "169.254.169.254",
            "IPv4 multicast" to "224.0.0.1", "IPv4 reserved" to "240.0.0.1", "IPv4 broadcast" to "255.255.255.255",
            "IPv4 IETF assignments" to "192.0.0.8", "TEST-NET-1" to "192.0.2.1", "TEST-NET-2" to "198.51.100.1",
            "TEST-NET-3" to "203.0.113.1", "IPv4 benchmarking" to "198.19.0.1", "6to4 relay anycast" to "192.88.99.1",
            "AS112-v4" to "192.31.196.1", "AMT" to "192.52.193.1", "AS112 direct delegation v4" to "192.175.48.1",
            "IPv6 unspecified" to "::", "IPv6 loopback" to "::1", "IPv4-compatible" to "::127.0.0.1",
            "IPv4-mapped loopback" to "::ffff:127.0.0.1", "IPv6 link-local" to "fe80::1", "IPv6 site-local" to "fec0::1",
            "IPv6 multicast" to "ff02::1", "discard-only" to "100::1", "dummy prefix" to "100:0:0:1::1",
            "local-use NAT64" to "64:ff9b:1::808:808", "Teredo" to "2001::1", "PCP anycast" to "2001:1::1",
            "benchmarking" to "2001:2::1", "AMT v6" to "2001:3::1", "AS112-v6" to "2001:4:112::1",
            "ORCHID" to "2001:10::1", "ORCHIDv2" to "2001:20::1", "drone remote ID" to "2001:30::1",
            "documentation 2001:db8::/32" to "2001:db8::1", "documentation 3fff::/20" to "3fff::1",
            "6to4 public embedded" to "2002:808:808::1", "6to4 private embedded" to "2002:a00:1::1",
            "AS112 direct delegation v6" to "2620:4f:8000::1", "segment routing" to "5f00::1",
            "unallocated in 2000::/3" to "2004::1", "IANA reserved 2d00::/8" to "2d00::1", "IANA reserved 2e00::/7" to "2f00::1",
            "IANA reserved 3000::/4" to "3000::1", "returned 6bone" to "3ffe::1", "RIR-unallocated 2003 tail" to "2003:4000::1",
        )
        refused.forEach { (label, literal) ->
            assertEquals(AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED, AcpProviderRouting.destinationRefusal(policy, listOf(address(literal))), label)
            assertEquals(AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED, AcpProviderRouting.destinationRefusal(permissive, listOf(address(literal))), label)
        }
        val mappedLoopback = Inet6Address.getByAddress(null, ByteArray(16).also { it[10] = -1; it[11] = -1; it[12] = 127; it[15] = 1 }, null)
        assertEquals(AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED, AcpProviderRouting.destinationRefusal(permissive, listOf(mappedLoopback)))
        assertEquals(AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED, AcpProviderRouting.destinationRefusal(permissive, emptyList()))
        assertEquals(
            AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED,
            AcpProviderRouting.destinationRefusal(permissive, listOf(address("8.8.8.8"), address("10.0.0.1"), address("127.0.0.1"))),
        )
    }

    @Test
    fun `well-known NAT64 is an explicit deployment decision admitting only global embedded IPv4`() {
        val nat64 = approved("addressTranslation" to "WELL_KNOWN_NAT64")
        val nat64Private = approved("addressTranslation" to "WELL_KNOWN_NAT64", "privateDestinations" to "PERMITTED")
        assertEquals(AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED, AcpProviderRouting.destinationRefusal(policy, listOf(address("64:ff9b::808:808"))))
        assertNull(AcpProviderRouting.destinationRefusal(nat64, listOf(address("64:ff9b::808:808"))))
        listOf("64:ff9b::a00:1", "64:ff9b::c0a8:101", "64:ff9b::6440:1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::c000:201").forEach {
            assertEquals(AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED, AcpProviderRouting.destinationRefusal(nat64, listOf(address(it))), it)
            assertEquals(AcpProviderRouteRefusal.DESTINATION_ADDRESS_REFUSED, AcpProviderRouting.destinationRefusal(nat64Private, listOf(address(it))), it)
        }
    }

    private fun head(
        method: String = "POST",
        target: String = "/responses",
        length: String? = "2",
        fields: List<Pair<String, String>>? = null,
        extra: List<Pair<String, String>> = emptyList(),
    ): ByteArray {
        val lines = (fields ?: (listOf("Host" to "127.0.0.1:41000") + listOfNotNull(length?.let { "Content-Length" to it }))) + extra
        return ("$method $target HTTP/1.1\r\n" + lines.joinToString("") { (name, value) -> "$name: $value\r\n" } + "\r\n")
            .toByteArray(Charsets.UTF_8)
    }

    private fun approved(vararg overrides: Pair<String, String>): AcpProviderTransportPolicy.Approved =
        AcpProviderTransportPolicy.fromOperatorPolicy(providerPolicyConfiguration() + overrides) as AcpProviderTransportPolicy.Approved

    private fun assertRefused(expected: AcpProviderRouteRefusal, decision: AcpProviderRouteDecision, message: String? = null) {
        assertEquals(AcpProviderRouteDecision.Refused(expected), decision, message)
    }

    // Literal parsing only: InetAddress.getByName performs no DNS lookup for numeric addresses.
    private fun address(literal: String): InetAddress = InetAddress.getByName(literal)
}
