package decompengine.web

import decompengine.jobs.AgentProgressJournal
import decompengine.jobs.JobStore
import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowJobInspection
import decompengine.jobs.WorkflowKind
import decompengine.jobs.elfFixture
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.BufferedInputStream
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The optional reverse-proxy profile (#216/#613/#614/#480) on a real listener. The JVM stays on
 * 127.0.0.1; the trusted proxy peer is 127.0.0.2, with a separate private upstream credential.
 * Direct clients can select that same source address and must still be refused without the secret.
 * A test-owned nginx-like hop exercises login, streams, uploads, downloads and subpath assets.
 */
class WebReverseProxyProfileTest {
    private val root: Path = Files.createTempDirectory(Path.of("build"), "reverse-proxy-profile")
    private val http: HttpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build()
    private val public = "https://decomp.example"
    private val profile get() = WebReverseProxyProfile(public, setOf(TRUSTED_PEER), PROXY_SECRET)

    @AfterTest fun cleanup() { http.close(); root.toFile().deleteRecursively() }

    private fun server(profile: WebReverseProxyProfile? = this.profile, basePath: String = BASE): UploadServer =
        UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("unexpected analysis") },
            JobReconstructor { _, _ -> error("unexpected reconstruction") }, uiMode = WebUiMode.SPA, basePath = basePath,
            reverseProxy = profile).also { it.start() }

    private class RawResponse(val status: Int, val headers: List<Pair<String, String>>, val body: String) {
        fun header(name: String): String? = headers.firstOrNull { it.first.equals(name, true) }?.second
        fun headers(name: String): List<String> = headers.filter { it.first.equals(name, true) }.map { it.second }
        val code: String? get() = Regex("\"code\":\"([A-Z_]+)\"").find(body)?.groupValues?.get(1)
    }

    /** One HTTP/1.1 exchange from an explicit loopback source address, as a proxy hop or a direct client would send it. */
    private fun raw(port: Int, peer: String, method: String, path: String, headers: List<Pair<String, String>>, body: String? = null): RawResponse {
        Socket().use { socket ->
            socket.bind(InetSocketAddress(peer, 0))
            socket.connect(InetSocketAddress("127.0.0.1", port), 5_000)
            socket.soTimeout = 10_000
            val bytes = body?.toByteArray() ?: ByteArray(0)
            val head = buildString {
                append("$method $path HTTP/1.1\r\n")
                headers.forEach { (name, value) -> append("$name: $value\r\n") }
                if (body != null) append("Content-Length: ${bytes.size}\r\n")
                append("Connection: close\r\n\r\n")
            }
            socket.getOutputStream().apply { write(head.toByteArray()); write(bytes); flush() }
            val response = socket.getInputStream().readBytes().decodeToString()
            val lines = response.substringBefore("\r\n\r\n").split("\r\n")
            val parsed = lines.drop(1).map { it.substringBefore(':') to it.substringAfter(':').trim() }
            var content = response.substringAfter("\r\n\r\n", "")
            if (parsed.any { it.first.equals("Transfer-Encoding", true) && it.second.equals("chunked", true) }) content = dechunk(content)
            return RawResponse(lines.first().split(' ')[1].toInt(), parsed, content)
        }
    }

    private fun dechunk(value: String): String {
        val out = StringBuilder()
        var rest = value
        while (true) {
            val size = rest.substringBefore("\r\n").substringBefore(';').trim().toIntOrNull(16) ?: return out.toString()
            if (size == 0) return out.toString()
            rest = rest.substringAfter("\r\n")
            out.append(rest, 0, size)
            rest = rest.substring(size).removePrefix("\r\n")
        }
    }

    // Unit-level hop requests explicitly carry the upstream credential; end-to-end tests use the proxy.
    private val forwarding = listOf(WebReverseProxyProfile.SECRET_HEADER to PROXY_SECRET,
        "Host" to "decomp.example", "X-Forwarded-Proto" to "https",
        "X-Forwarded-Host" to "decomp.example", "X-Forwarded-For" to "198.51.100.7")

    private fun exchangeToken(server: UploadServer, peer: String = TRUSTED_PEER, headers: List<Pair<String, String>> = forwarding,
                              origin: String? = public, token: String = server.issueBrowserBootstrap().token): RawResponse =
        raw(server.serverPort, peer, "POST", "${BASE}api/v1/session", headers + listOfNotNull(origin?.let { "Origin" to it }) +
            listOf("Content-Type" to "application/json", "Accept" to "application/json"), "{\"token\":\"$token\"}")

    private fun signIn(server: UploadServer): Pair<String, String> = credentials(exchangeToken(server))

    private fun signInVia(server: UploadServer, proxy: FakeReverseProxy, token: String = server.issueBrowserBootstrap().token): Pair<String, String> =
        credentials(raw(URI(proxy.origin).port, "127.0.0.1", "POST", "${BASE}api/v1/session",
            listOf("Host" to "decomp.example", "Origin" to public, "Content-Type" to "application/json",
                "Accept" to "application/json", "Authorization" to OPERATOR_CREDENTIAL,
                WebReverseProxyProfile.SECRET_HEADER to "client-forged-secret"), "{\"token\":\"$token\"}"))

    private fun credentials(response: RawResponse): Pair<String, String> {
        assertEquals(200, response.status, response.body)
        val csrf = Json.parseToJsonElement(response.body).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
        return response.header("Set-Cookie")!!.substringBefore(';') to csrf
    }

    private fun assertNoCors(response: RawResponse) =
        assertFalse(response.headers.any { it.first.startsWith("Access-Control-", true) }, "CORS header in ${response.headers}")

    @Test
    fun `profile configuration accepts only an exact public HTTPS origin and loopback literal proxy peers`() {
        for (origin in listOf("https://decomp.example", "https://decomp.example:8443", "https://a.b-c.example", "https://192.0.2.10", "https://[2001:db8::1]")) {
            WebReverseProxyProfile(origin, setOf("127.0.0.1"), PROXY_SECRET)
        }
        for (origin in listOf("http://decomp.example", "https://decomp.example:443", "https://Decomp.example", "https://decomp.example/",
                "https://decomp.example/base", "https://user@decomp.example", "https://decomp.example?x=1", "https://decomp.example#f",
                "https://*.example", "https://decomp.example:0", "https://decomp_example", "decomp.example", "")) {
            assertFailsWith<IllegalArgumentException>(origin) { WebReverseProxyProfile(origin, setOf("127.0.0.1"), PROXY_SECRET) }
        }
        WebReverseProxyProfile(public, setOf("127.0.0.1", "127.0.0.2", "::1"), PROXY_SECRET)
        for (secret in listOf("", "a".repeat(63), "a".repeat(65), "A".repeat(64), "z".repeat(64), "$PROXY_SECRET\n")) {
            assertFailsWith<IllegalArgumentException> { WebReverseProxyProfile(public, setOf(TRUSTED_PEER), secret) }
        }
        val secretFile = root.resolve("proxy-secret")
        Files.writeString(secretFile, "$PROXY_SECRET\n")
        assertTrue(WebReverseProxyProfile.fromSecretFile(public, setOf(TRUSTED_PEER), secretFile).authenticates(PROXY_SECRET))
        val link = Files.createSymbolicLink(root.resolve("secret-link"), secretFile.toAbsolutePath())
        for (path in listOf(root.resolve("missing-secret"), root, link)) {
            assertFailsWith<IllegalArgumentException> { WebReverseProxyProfile.fromSecretFile(public, setOf(TRUSTED_PEER), path) }
        }
        for (secret in listOf("", "invalid", PROXY_SECRET + "\n\n", "a".repeat(1024))) {
            Files.writeString(secretFile, secret)
            assertFailsWith<IllegalArgumentException> { WebReverseProxyProfile.fromSecretFile(public, setOf(TRUSTED_PEER), secretFile) }
        }
        for (proxies in listOf(emptySet(), setOf("192.0.2.1"), setOf("10.0.0.1"), setOf("0.0.0.0"), setOf("localhost"), setOf("[::1]"),
                setOf("127.0.0.1/8"), setOf("::"), setOf("2001:db8::1"), (1..9).map { "127.0.0.$it" }.toSet())) {
            assertFailsWith<IllegalArgumentException>(proxies.toString()) { WebReverseProxyProfile(public, proxies, PROXY_SECRET) }
        }
        val configuration = LocalWebAccessConfiguration("http://127.0.0.1:8000", "/decomp/", reverseProxy = profile)
        assertEquals(public, configuration.browserOrigin)
        assertTrue(configuration.cookieName.startsWith("__Secure-decomp_session_"))
        // The default configuration is unchanged: same cookie name and no proxy authority.
        assertEquals("decomp_session_", LocalWebAccessConfiguration("http://127.0.0.1:8000", "/decomp/").cookieName.take(15))
        assertFailsWith<IllegalArgumentException> {
            LocalWebAccessConfiguration("http://127.0.0.1:8000", "/", setOf("http://localhost:5173"), profile)
        }
        // Incomplete or unsupported topologies fail before storage or a listener exists.
        val absent = root.resolve("absent")
        assertTrue(assertFailsWith<IllegalArgumentException> { UploadServer("127.0.0.1", 0, absent, uiMode = WebUiMode.LEGACY, reverseProxy = profile) }
            .message.orEmpty().contains("--ui spa"))
        assertFailsWith<IllegalArgumentException> {
            UploadServer("127.0.0.1", 0, absent, uiMode = WebUiMode.SPA, devFrontendOrigin = "http://localhost:5173", reverseProxy = profile)
        }
        for (host in listOf("0.0.0.0", "192.0.2.1")) {
            val failure = assertFailsWith<IllegalArgumentException> { UploadServer(host, 0, absent, uiMode = WebUiMode.SPA, reverseProxy = profile) }
            assertTrue(failure.message.orEmpty().contains("loopback"), failure.message)
        }
        assertFalse(Files.exists(absent))
    }

    @Test
    fun `only the trusted proxy peer is admitted and it receives a Secure SameSite base-path session cookie`() {
        val server = server()
        try {
            assertEquals(public, server.browserOrigin)
            val token = server.issueBrowserBootstrap().token
            // Spoofed forwarding headers from an untrusted loopback peer are refused before the body or token is consumed.
            val spoofed = exchangeToken(server, peer = "127.0.0.1", token = token)
            assertEquals(403, spoofed.status); assertEquals("PROXY_PEER_DENIED", spoofed.code)
            assertNull(spoofed.header("Set-Cookie")); assertNoCors(spoofed)
            // A direct local browser request without any forwarding is refused too: there is no second authority.
            val direct = raw(server.serverPort, "127.0.0.1", "GET", "${BASE}api/v1/bootstrap", listOf("Host" to "127.0.0.1:${server.serverPort}", "Accept" to "application/json"))
            assertEquals("PROXY_PEER_DENIED", direct.code)
            val shell = raw(server.serverPort, "127.0.0.3", "GET", BASE, forwarding + ("Accept" to "text/html"))
            assertEquals(403, shell.status); assertEquals("PROXY_PEER_DENIED", shell.code)

            val admitted = exchangeToken(server, token = token)
            assertEquals(200, admitted.status, admitted.body); assertNoCors(admitted)
            val cookie = admitted.header("Set-Cookie")!!
            val attributes = cookie.split(';').map(String::trim)
            assertTrue(attributes.first().startsWith("__Secure-decomp_session_"), cookie)
            assertTrue("Secure" in attributes && "HttpOnly" in attributes && "SameSite=Strict" in attributes && "Path=$BASE" in attributes, cookie)
            assertFalse(attributes.any { it.startsWith("Domain", true) }, cookie)
            val session = cookie.substringBefore(';')
            val csrf = Json.parseToJsonElement(admitted.body).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content

            val bootstrap = raw(server.serverPort, TRUSTED_PEER, "GET", "${BASE}api/v1/bootstrap", forwarding + listOf("Cookie" to session, "Accept" to "application/json"))
            assertEquals(200, bootstrap.status, bootstrap.body)
            assertEquals(BASE, Json.parseToJsonElement(bootstrap.body).jsonObject.getValue("data").jsonObject.getValue("basePath").jsonPrimitive.content)
            // The same valid cookie and headers from a direct peer remain refused: a stolen cookie needs the proxy too.
            val replay = raw(server.serverPort, "127.0.0.1", "GET", "${BASE}api/v1/bootstrap", forwarding + listOf("Cookie" to session, "Accept" to "application/json"))
            assertEquals("PROXY_PEER_DENIED", replay.code)
            // Mutations keep CSRF through the proxy.
            val logoutHeaders = forwarding + listOf("Cookie" to session, "Origin" to public, "Content-Type" to "application/json", "Accept" to "application/json")
            assertEquals("CSRF_DENIED", raw(server.serverPort, TRUSTED_PEER, "DELETE", "${BASE}api/v1/session", logoutHeaders, "{}").code)
            val logout = raw(server.serverPort, TRUSTED_PEER, "DELETE", "${BASE}api/v1/session", logoutHeaders + ("X-CSRF-Token" to csrf), "{}")
            assertEquals(204, logout.status)
            assertTrue(logout.headers("Set-Cookie").single().let { it.contains("Max-Age=0") && it.contains("; Secure") && it.contains("Path=$BASE") })
        } finally { server.stop() }
    }

    @Test
    fun `direct clients using the proxy source address cannot exchange a token or replay a session without the upstream credential`() {
        val server = server()
        try {
            FakeReverseProxy(server.serverPort, "decomp.example").use { proxy ->
                val token = server.issueBrowserBootstrap().token
                val directHeaders = forwarding.filterNot { it.first == WebReverseProxyProfile.SECRET_HEADER }
                val attempts = listOf(directHeaders, directHeaders + (WebReverseProxyProfile.SECRET_HEADER to "0".repeat(64)),
                    forwarding + (WebReverseProxyProfile.SECRET_HEADER to PROXY_SECRET))
                for (headers in attempts) {
                    val denied = exchangeToken(server, peer = TRUSTED_PEER, headers = headers, token = token)
                    assertEquals(403, denied.status); assertEquals("PROXY_PEER_DENIED", denied.code)
                    assertNull(denied.header("Set-Cookie")); assertFalse(denied.body.contains(PROXY_SECRET))
                }
                // Edge authentication is required even with a valid bootstrap and a forged upstream header.
                val noEdgeAuth = raw(URI(proxy.origin).port, "127.0.0.1", "POST", "${BASE}api/v1/session",
                    forwarding + listOf("Origin" to public, "Content-Type" to "application/json"), "{\"token\":\"$token\"}")
                assertEquals(401, noEdgeAuth.status); assertEquals(0, proxy.forwardedRequests.get())
                // None of the denied exchanges consumed the token. The hop overwrites the forged secret.
                val (session, _) = signInVia(server, proxy, token)
                assertEquals(1, proxy.forwardedRequests.get())
                val unauthenticatedReplay = raw(URI(proxy.origin).port, "127.0.0.1", "GET", "${BASE}api/v1/bootstrap",
                    forwarding + listOf("Cookie" to session, "Accept" to "application/json"))
                assertEquals(401, unauthenticatedReplay.status); assertEquals(1, proxy.forwardedRequests.get())
                for (headers in attempts) {
                    val replay = raw(server.serverPort, TRUSTED_PEER, "GET", "${BASE}api/v1/bootstrap",
                        headers + listOf("Cookie" to session, "Accept" to "application/json"))
                    assertEquals(403, replay.status); assertEquals("PROXY_PEER_DENIED", replay.code)
                }
                val admitted = raw(URI(proxy.origin).port, "127.0.0.1", "GET", "${BASE}api/v1/bootstrap",
                    listOf("Host" to "decomp.example", "Cookie" to session, "Accept" to "application/json", "Authorization" to OPERATOR_CREDENTIAL))
                assertEquals(200, admitted.status, admitted.body)
                assertNull(admitted.header(WebReverseProxyProfile.SECRET_HEADER))
                assertFalse(admitted.body.contains(PROXY_SECRET))
            }
        } finally { server.stop() }
    }

    @Test
    fun `trusted proxy forwarding and Host or Origin values must agree with the configured public origin and base path`() {
        val server = server()
        try {
            val (session, _) = signIn(server)
            fun read(headers: List<Pair<String, String>>, path: String = "${BASE}api/v1/bootstrap") =
                raw(server.serverPort, TRUSTED_PEER, "GET", path, headers + listOf("Cookie" to session, "Accept" to "application/json"))
            fun without(vararg names: String) = forwarding.filterNot { (name, _) -> names.any { it.equals(name, true) } }
            assertEquals(200, read(forwarding).status)
            // RFC 7239 alone is sufficient; only its last element (the trusted hop's own) is consulted.
            assertEquals(200, read(without("X-Forwarded-Proto", "X-Forwarded-Host") + ("Forwarded" to "for=198.51.100.7;proto=https;host=decomp.example")).status)
            assertEquals(200, read(without("X-Forwarded-Proto") + ("Forwarded" to "proto=http, for=\"[2001:db8::7]\";proto=https")).status)
            assertEquals(200, read(forwarding + ("X-Forwarded-Port" to "443") + ("X-Real-IP" to "198.51.100.7")).status)
            val refused = listOf(
                without("X-Forwarded-Proto") to "PROXY_FORWARDING_INVALID", // TLS termination must be declared
                (without("X-Forwarded-Proto") + ("X-Forwarded-Proto" to "http")) to "PROXY_FORWARDING_INVALID",
                (without("X-Forwarded-Host") + ("X-Forwarded-Host" to "evil.example")) to "PROXY_FORWARDING_INVALID",
                (forwarding + ("X-Forwarded-Port" to "80")) to "PROXY_FORWARDING_INVALID",
                (forwarding + ("Forwarded" to "proto=https, proto=http")) to "PROXY_FORWARDING_INVALID",
                (forwarding + ("Forwarded" to "proto=https;host=\"evil.example\"")) to "PROXY_FORWARDING_INVALID",
                (forwarding + ("Forwarded" to "proto=\"https")) to "PROXY_FORWARDING_INVALID",
                (forwarding + ("Forwarded" to "proto=https;proto=https")) to "PROXY_FORWARDING_INVALID",
                // Identity headers and unlisted forwarding headers confer nothing and are refused rather than ignored.
                (forwarding + ("X-Forwarded-User" to "admin")) to "FORWARDED_HEADERS_DENIED",
                (forwarding + ("Remote-User" to "admin")) to "FORWARDED_HEADERS_DENIED",
                (forwarding + ("X-Auth-Request-Email" to "admin@example.invalid")) to "FORWARDED_HEADERS_DENIED",
                (forwarding + ("X-Forwarded-Prefix" to "/decomp")) to "FORWARDED_HEADERS_DENIED",
                (forwarding + ("X-Forwarded-Server" to "proxy")) to "FORWARDED_HEADERS_DENIED",
                // Exact Host/Origin allowlist: the loopback listener authority and every alias are not browser origins here.
                (without("Host") + ("Host" to "127.0.0.1:${server.serverPort}")) to "HOST_DENIED",
                (without("Host") + ("Host" to "localhost:${server.serverPort}")) to "HOST_DENIED",
                (without("Host") + ("Host" to "decomp.example:443")) to "HOST_DENIED",
                (without("Host") + ("Host" to "evil.example")) to "HOST_DENIED",
                (forwarding + ("Origin" to "http://decomp.example")) to "ORIGIN_DENIED",
                (forwarding + ("Origin" to "https://evil.example")) to "ORIGIN_DENIED",
                (forwarding + ("Origin" to "http://127.0.0.1:${server.serverPort}")) to "ORIGIN_DENIED",
                (forwarding + ("Origin" to "null")) to "ORIGIN_DENIED",
                (forwarding + ("Sec-Fetch-Site" to "cross-site")) to "ORIGIN_DENIED",
            )
            for ((headers, code) in refused) {
                val response = read(headers)
                assertEquals(code, response.code, "$headers -> ${response.status} ${response.body.take(200)}")
                assertTrue(response.status in 400..499); assertNoCors(response)
            }
            // A proxy that strips the configured prefix gets explicit guidance instead of a generic miss.
            val stripped = read(forwarding, "/api/v1/bootstrap")
            assertEquals(404, stripped.status); assertEquals("PROXY_BASE_PATH_MISMATCH", stripped.code)
            // Session exchange through the proxy still requires the exact public Origin.
            for (origin in listOf(null, "http://decomp.example", "https://decomp.example:8443", "http://127.0.0.1:${server.serverPort}")) {
                assertEquals("ORIGIN_DENIED", exchangeToken(server, origin = origin).code, "Origin $origin")
            }
        } finally { server.stop() }
    }

    @Test
    fun `without the profile every peer, including 127_0_0_2, keeps the default loopback no-forwarding policy`() {
        val server = server(profile = null)
        try {
            val own = "127.0.0.1:${server.serverPort}"
            assertEquals("http://$own", server.browserOrigin)
            val headers = listOf("Host" to own, "Accept" to "application/json")
            for (peer in listOf("127.0.0.1", TRUSTED_PEER)) {
                val forwarded = raw(server.serverPort, peer, "GET", "${BASE}api/v1/bootstrap", headers + ("X-Forwarded-Proto" to "https"))
                assertEquals("FORWARDED_HEADERS_DENIED", forwarded.code)
                assertEquals("HOST_DENIED", raw(server.serverPort, peer, "GET", "${BASE}api/v1/bootstrap",
                    listOf("Host" to "decomp.example", "Accept" to "application/json")).code)
            }
            // Localhost aliases of the listener are not implied: only explicitly configured authorities pair with an Origin.
            for (alias in listOf("localhost", "127.0.0.2", "[::1]", "127.1", "LOCALHOST")) {
                val host = "$alias:${server.serverPort}"
                val response = raw(server.serverPort, "127.0.0.1", "GET", BASE, listOf("Host" to host, "Origin" to "http://$host", "Accept" to "text/html"))
                assertEquals("HOST_DENIED", response.code, host)
            }
            val token = server.issueBrowserBootstrap().token
            val session = raw(server.serverPort, "127.0.0.1", "POST", "${BASE}api/v1/session", headers + listOf("Origin" to "http://$own",
                "Content-Type" to "application/json"), "{\"token\":\"$token\"}")
            assertEquals(200, session.status)
            val cookie = session.header("Set-Cookie")!!
            assertTrue(cookie.startsWith("decomp_session_") && !cookie.contains("Secure"), cookie)
        } finally { server.stop() }
    }

    /**
     * A minimal authenticating nginx-like hop. It answers 401 itself unless the single operator's basic
     * credential is present (and strips it), overwrites Host and all client forwarding headers, connects from the
     * trusted source address, overwrites the private upstream credential, enforces the documented
     * declared Content-Length edge ceiling and, like nginx's default `proxy_buffering on`, holds a response until the
     * upstream finishes unless the upstream sends `X-Accel-Buffering: no` (or [alwaysBuffer] is set).
     */
    private class FakeReverseProxy(private val upstreamPort: Int, private val authority: String, private val alwaysBuffer: Boolean = false) : AutoCloseable {
        private val listener = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
        private val sockets = ConcurrentLinkedQueue<Socket>()
        val origin: String get() = "http://127.0.0.1:${listener.localPort}"
        /** Requests that passed authentication and were forwarded to the JVM. */
        val forwardedRequests = java.util.concurrent.atomic.AtomicInteger()

        init {
            Thread({
                while (!listener.isClosed) {
                    val client = try { listener.accept() } catch (_: IOException) { break }
                    sockets += client
                    Thread({ try { relay(client) } catch (_: IOException) { } finally { client.close() } }, "fake-proxy-relay").apply { isDaemon = true; start() }
                }
            }, "fake-proxy-accept").apply { isDaemon = true; start() }
        }

        private fun head(input: InputStream): ByteArray? {
            val out = ByteArrayOutputStream()
            while (true) {
                val next = input.read()
                if (next < 0) return null
                out.write(next)
                val bytes = out.toByteArray()
                if (bytes.size >= 4 && bytes.takeLast(4) == listOf<Byte>(13, 10, 13, 10)) return bytes
                if (bytes.size > 65_536) throw IOException("oversized head")
            }
        }

        private fun relay(client: Socket) {
            val upstream = Socket().also { sockets += it }
            try { relay(client, upstream) } finally { upstream.close() }
        }

        private fun relay(client: Socket, upstream: Socket) {
            val clientIn = BufferedInputStream(client.getInputStream())
            val lines = head(clientIn)?.decodeToString()?.split("\r\n")?.filter(String::isNotEmpty) ?: return
            val headers = lines.drop(1).map { it.substringBefore(':') to it.substringAfter(':').trim() }
            if (headers.none { it.first.equals("Authorization", true) && it.second == OPERATOR_CREDENTIAL }) {
                client.getOutputStream().write(("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"decomp\"\r\n" +
                    "Content-Length: 0\r\nConnection: close\r\n\r\n").toByteArray())
                return
            }
            val length = headers.firstOrNull { it.first.equals("Content-Length", true) }?.second?.toLong() ?: 0L
            if (length > EDGE_MAX_REQUEST_BYTES) {
                client.getOutputStream().write(("HTTP/1.1 413 Content Too Large\r\nContent-Type: text/html\r\n" +
                    "Content-Length: 0\r\nConnection: close\r\n\r\n").toByteArray())
                return
            }
            forwardedRequests.incrementAndGet()
            val hopByHop = setOf("authorization", "host", "connection", "keep-alive", "upgrade", "http2-settings", "te", "forwarded", "x-real-ip",
                WebReverseProxyProfile.SECRET_HEADER.lowercase())
            val kept = headers.filterNot { (name, _) -> name.lowercase() in hopByHop || name.lowercase().startsWith("x-forwarded-") }
            upstream.bind(InetSocketAddress(TRUSTED_PEER, 0))
            upstream.connect(InetSocketAddress("127.0.0.1", upstreamPort), 5_000)
            val forwarded = buildString {
                append(lines.first()).append("\r\nHost: $authority\r\n")
                kept.forEach { (name, value) -> append("$name: $value\r\n") }
                append("${WebReverseProxyProfile.SECRET_HEADER}: $PROXY_SECRET\r\n")
                append("X-Forwarded-Proto: https\r\nX-Forwarded-Host: $authority\r\nX-Forwarded-For: ${client.inetAddress.hostAddress}\r\nConnection: close\r\n\r\n")
            }
            val upstreamOut = upstream.getOutputStream()
            upstreamOut.write(forwarded.toByteArray()); upstreamOut.flush()
            Thread({ try { copy(clientIn, upstreamOut, length) } catch (_: IOException) { } }, "fake-proxy-body").apply { isDaemon = true; start() }
            val upstreamIn = BufferedInputStream(upstream.getInputStream())
            val responseHead = head(upstreamIn) ?: return
            val streaming = !alwaysBuffer && responseHead.decodeToString().split("\r\n").any { it.equals("X-Accel-Buffering: no", true) }
            val out = client.getOutputStream()
            if (streaming) {
                out.write(responseHead); out.flush()
                val buffer = ByteArray(8192)
                while (true) { val count = upstreamIn.read(buffer); if (count < 0) break; out.write(buffer, 0, count); out.flush() }
            } else {
                val rest = upstreamIn.readBytes()
                out.write(responseHead); out.write(rest); out.flush()
            }
        }

        private fun copy(input: InputStream, output: OutputStream, length: Long) {
            var remaining = length
            val buffer = ByteArray(64 * 1024)
            while (remaining > 0) {
                val count = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                if (count < 0) break
                output.write(buffer, 0, count); remaining -= count
            }
            output.flush()
        }

        override fun close() { listener.close(); sockets.forEach { runCatching { it.close() } } }
    }

    private class Run(val jobId: String, val runId: String, val artifact: String)

    private fun runFixture(): Run {
        val job = JobStore(root).createFromUpload("inert.elf", elfFixture())
        val run = WorkflowAttemptStore.open(root).use { owner ->
            val original = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            owner.create(job.id, original.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
        }
        val reports = Files.createDirectories(root.resolve(job.id).resolve("reports/runs/${run.runId}"))
        AgentProgressJournal(reports, "reconstruct").use { it.phase(decompengine.agent.AgentWorkflowPhase.PLANNING) }
        val raw = "{\"fixture\":\"inert proxied download\"}"
        Files.writeString(reports.resolve("exploration.json"), raw)
        return Run(job.id, run.runId, raw)
    }

    @Test
    fun `streams, reconnects, uploads, downloads and subpath assets keep their bounded semantics through a buffering proxy`() {
        val run = runFixture()
        val server = server()
        val proxy = FakeReverseProxy(server.serverPort, "decomp.example")
        val buffering = FakeReverseProxy(server.serverPort, "decomp.example", alwaysBuffer = true)
        try {
            // Denied access: without the operator credential the proxy answers 401 and nothing reaches the JVM.
            for (path in listOf(BASE, "${BASE}api/v1/bootstrap", "${BASE}jobs/${run.jobId}")) {
                val denied = http.send(HttpRequest.newBuilder(URI(proxy.origin + path)).build(), HttpResponse.BodyHandlers.ofString())
                assertEquals(401, denied.statusCode()); assertTrue(denied.headers().firstValue("WWW-Authenticate").isPresent)
            }
            assertEquals(0, proxy.forwardedRequests.get())
            val (session, csrf) = signInVia(server, proxy)
            fun call(path: String, accept: String = "application/json", via: FakeReverseProxy = proxy, method: String = "GET",
                     headers: Map<String, String> = emptyMap(), body: HttpRequest.BodyPublisher = HttpRequest.BodyPublishers.noBody(),
                     cookie: String = session): HttpResponse<String> {
                val builder = HttpRequest.newBuilder(URI(via.origin + path)).timeout(Duration.ofSeconds(30)).header("Accept", accept).header("Cookie", cookie)
                    .header("Authorization", OPERATOR_CREDENTIAL)
                headers.forEach { (name, value) -> builder.header(name, value) }
                return http.send(builder.method(method, body).build(), HttpResponse.BodyHandlers.ofString())
            }
            // The login shell and its manifest-owned assets are served under the declared base path.
            val shell = call(BASE, "text/html")
            assertEquals(200, shell.statusCode(), shell.body().take(200))
            assertTrue(shell.body().contains("name=\"decomp-base-path\" content=\"$BASE\""))
            val assets = Regex("(?:src|href)=\"(/[^\"]*assets/ui/[^\"]+)\"").findAll(shell.body()).map { it.groupValues[1] }.toList()
            assertTrue(assets.isNotEmpty() && assets.all { it.startsWith("${BASE}assets/ui/") }, assets.toString())
            assertEquals(200, call(assets.first(), "*/*").statusCode())
            // A deep link is answered by the shell; the bare prefix redirects with a relative, proxy-safe Location.
            assertEquals(200, call("${BASE}jobs/${run.jobId}", "text/html").statusCode())
            val bare = call(BASE.dropLast(1), "text/html")
            assertEquals(308, bare.statusCode()); assertEquals(BASE, bare.headers().firstValue("Location").orElseThrow())

            val runPath = "${BASE}api/v1/jobs/${run.jobId}/runs/${run.runId}"
            // Cursors are bound to the session that read them.
            fun oldest(cookie: String) = Json.parseToJsonElement(call("$runPath/snapshot", cookie = cookie).body()).jsonObject
                .getValue("data").jsonObject.getValue("oldestCursor").jsonPrimitive.content
            /** Headers and the first SSE data frame (with its id) must arrive while the stream stays open; the server lease is 30 s. */
            fun firstFrame(via: FakeReverseProxy, cookie: String, query: String, within: Long = 5): Pair<HttpResponse<InputStream>, String?> =
                CompletableFuture.supplyAsync {
                    val response = http.send(HttpRequest.newBuilder(URI("${via.origin}$runPath/events$query")).header("Cookie", cookie)
                        .header("Accept", "text/event-stream").header("Authorization", OPERATOR_CREDENTIAL).build(), HttpResponse.BodyHandlers.ofInputStream())
                    val reader = BufferedReader(InputStreamReader(response.body()))
                    var id: String? = null
                    var line = reader.readLine()
                    while (line != null && !line.startsWith("data: ")) { if (line.startsWith("id: ")) id = line.removePrefix("id: "); line = reader.readLine() }
                    checkNotNull(line) { "the stream ended before an event" }
                    response to id
                }.get(within, TimeUnit.SECONDS)
            // Positive control: a proxy that buffers regardless delivers nothing promptly. It uses its own session so
            // its held upstream stream does not count against the two-stream quota of the session under test.
            val (control, _) = signInVia(server, proxy)
            assertFailsWith<TimeoutException> { firstFrame(buffering, control, "?after=${oldest(control)}&limit=1", within = 2) }
            val (stream, eventIdOrNull) = firstFrame(proxy, session, "?after=${oldest(session)}&limit=1")
            assertEquals(200, stream.statusCode())
            assertEquals("no", stream.headers().firstValue("X-Accel-Buffering").orElseThrow())
            assertEquals("no-store, no-transform", stream.headers().firstValue("Cache-Control").orElseThrow())
            assertTrue(stream.headers().firstValue("Content-Type").orElseThrow().startsWith("text/event-stream"))
            stream.body().close()
            val eventId = assertNotNull(eventIdOrNull, "the proxied stream delivered no event id")
            // Reconnect with Last-Event-ID under the same session through the same proxy.
            val resumed = http.send(HttpRequest.newBuilder(URI("${proxy.origin}$runPath/events")).header("Cookie", session)
                .header("Accept", "text/event-stream").header("Last-Event-ID", eventId).header("Authorization", OPERATOR_CREDENTIAL).build(), HttpResponse.BodyHandlers.ofInputStream())
            assertEquals(200, resumed.statusCode())
            assertEquals(": connected", CompletableFuture.supplyAsync { BufferedReader(InputStreamReader(resumed.body())).readLine() }.get(5, TimeUnit.SECONDS))
            resumed.body().close()

            // Downloads keep attachment semantics and exact bytes.
            val href = Json.parseToJsonElement(call("$runPath/reports/exploration").body()).jsonObject.getValue("data").jsonObject
                .getValue("sourceArtifact").jsonObject.getValue("contentHref").jsonPrimitive.content
            assertTrue(href.startsWith(BASE), href)
            val download = call(href, "application/octet-stream")
            assertEquals(200, download.statusCode()); assertEquals(run.artifact, download.body())
            assertTrue(download.headers().firstValue("Content-Disposition").orElseThrow().startsWith("attachment"))

            // Uploads stream through with session, exact public Origin and CSRF; the server keeps its own byte ceiling.
            val boundary = "proxy_upload_fixture"
            fun multipart(content: ByteArray) = "--$boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"inert.elf\"\r\n\r\n".toByteArray() +
                content + "\r\n--$boundary--\r\n".toByteArray()
            val mutation = mapOf("Origin" to public, "X-CSRF-Token" to csrf, "Content-Type" to "multipart/form-data; boundary=$boundary")
            val created = call("${BASE}api/v1/jobs", method = "POST", headers = mutation + ("Idempotency-Key" to "proxy-upload-000001"),
                body = HttpRequest.BodyPublishers.ofByteArray(multipart(elfFixture())))
            assertEquals(201, created.statusCode(), created.body())
            assertTrue(created.headers().firstValue("Location").orElseThrow().startsWith("${BASE}api/v1/jobs/"))
            val oversized = call("${BASE}api/v1/jobs", method = "POST", headers = mutation + ("Idempotency-Key" to "proxy-upload-000002"),
                body = HttpRequest.BodyPublishers.ofByteArray(multipart(ByteArray(StreamingMultipartUpload.MAX_REQUEST_BYTES.toInt()))))
            assertEquals(413, oversized.statusCode())
            val requestId = oversized.headers().firstValue("X-Request-ID").orElseThrow()
            assertEquals(requestId, java.util.UUID.fromString(requestId).toString())
            assertTrue(oversized.headers().firstValue("Content-Type").orElseThrow().startsWith("application/json"))
            val envelope = Json.parseToJsonElement(oversized.body()).jsonObject
            assertEquals(setOf("apiVersion", "kind", "requestId", "error"), envelope.keys)
            assertEquals("1", envelope.getValue("apiVersion").jsonPrimitive.content)
            assertEquals("error", envelope.getValue("kind").jsonPrimitive.content)
            assertEquals(requestId, envelope.getValue("requestId").jsonPrimitive.content)
            val error = envelope.getValue("error").jsonObject
            assertEquals(setOf("code", "message", "retryable", "details", "retryAfterMs"), error.keys)
            assertEquals("UPLOAD_TOO_LARGE", error.getValue("code").jsonPrimitive.content)
            assertTrue(error.getValue("message").jsonPrimitive.content.isNotBlank())
            assertEquals("false", error.getValue("retryable").jsonPrimitive.content)
            assertEquals("[]", error.getValue("details").toString())
            assertEquals("null", error.getValue("retryAfterMs").toString())
            // Above the independent finite edge ceiling the proxy refuses before forwarding or reading a body.
            val beforeEdgeRefusal = proxy.forwardedRequests.get()
            val edgeRefused = raw(URI(proxy.origin).port, "127.0.0.1", "POST", "${BASE}api/v1/jobs",
                listOf("Host" to "decomp.example", "Authorization" to OPERATOR_CREDENTIAL,
                    "Content-Length" to (EDGE_MAX_REQUEST_BYTES + 1).toString()))
            assertEquals(413, edgeRefused.status); assertNull(edgeRefused.code); assertNull(edgeRefused.header("X-Request-ID"))
            assertEquals(beforeEdgeRefusal, proxy.forwardedRequests.get())
            // A client-supplied forwarding header is overwritten by the proxy, and a forged Origin still fails.
            assertEquals(403, call("${BASE}api/v1/jobs", method = "POST", headers = mutation + mapOf("Idempotency-Key" to "proxy-upload-000003",
                "Origin" to "https://evil.example"), body = HttpRequest.BodyPublishers.ofByteArray(multipart(elfFixture()))).statusCode())
        } finally { proxy.close(); buffering.close(); server.stop() }
    }

    @Test
    fun `documented proxy examples match the server's bounded limits`() {
        val guide = Files.readString(Path.of("docs/web-reverse-proxy.md"))
        assertEquals(32L * 1024 * 1024, StreamingMultipartUpload.MAX_REQUEST_BYTES)
        assertEquals(64L * 1024 * 1024, EDGE_MAX_REQUEST_BYTES)
        assertTrue(EDGE_MAX_REQUEST_BYTES > StreamingMultipartUpload.MAX_REQUEST_BYTES)
        for (required in listOf("client_max_body_size 64m;", "max_size 64MiB", "--proxy-secret-file", "X-Decomp-Proxy-Secret", "proxy_buffering off;", "proxy_request_buffering off;",
                "X-Accel-Buffering", "proxy_set_header X-Forwarded-Proto \$scheme;", "proxy_set_header Forwarded \"\";",
                "--trusted-proxy 127.0.0.1", "--public-origin https://", "flush_interval -1")) {
            assertTrue(guide.contains(required), "the reverse-proxy guide no longer states: $required")
        }
        // Proxy read timeouts must outlast the 15 s SSE heartbeat and the 30 s ordinary request deadline.
        val timeouts = Regex("proxy_read_timeout (\\d+)s;").findAll(guide).map { it.groupValues[1].toInt() }.toList()
        assertTrue(timeouts.isNotEmpty() && timeouts.all { it > 30 }, timeouts.toString())
    }

    private fun runCli(vararg arguments: String): Process = ProcessBuilder(
        Path.of(System.getProperty("java.home"), "bin", "java").toString(),
        "-Djava.io.tmpdir=${System.getProperty("java.io.tmpdir")}", "-cp", System.getProperty("java.class.path"),
        "decompengine.MainKt", "web", *arguments,
    ).apply { environment().clear() }.start()

    @Test
    fun `the web command refuses an incomplete profile and prints the public handoff for a complete one`() {
        val storage = root.resolve("cli-incomplete")
        val secretFile = root.resolve("cli-secret")
        Files.writeString(secretFile, "$PROXY_SECRET\n")
        val fullProfile = listOf("--public-origin", public, "--trusted-proxy", "127.0.0.1", "--proxy-secret-file", secretFile.toString())
        for (arguments in listOf(listOf("--public-origin", public), listOf("--trusted-proxy", "127.0.0.1"),
                listOf("--proxy-secret-file", secretFile.toString()),
                listOf("--ui", "spa", "--public-origin", public, "--trusted-proxy", "127.0.0.1"),
                listOf("--ui", "spa", "--public-origin", public, "--proxy-secret-file", secretFile.toString()),
                listOf("--ui", "spa", "--trusted-proxy", "127.0.0.1", "--proxy-secret-file", secretFile.toString()),
                listOf("--ui", "spa") + fullProfile.dropLast(1) + root.resolve("missing-secret").toString(),
                fullProfile)) { // the last one omits --ui spa
            val process = runCli("--port", "0", "--data-dir", storage.toString(), *arguments.toTypedArray())
            try {
                assertTrue(process.waitFor(60, TimeUnit.SECONDS), "$arguments did not exit")
                assertTrue(process.exitValue() != 0, "$arguments started")
                assertFalse(process.inputStream.readNBytes(16 * 1024).decodeToString().contains("bootstrap="))
            } finally { if (process.isAlive) process.destroyForcibly().waitFor(10, TimeUnit.SECONDS) }
        }
        assertFalse(Files.exists(storage))
        val process = runCli("--port", "0", "--ui", "spa", "--base-path", BASE, "--data-dir", root.resolve("cli-complete").toString(),
            *fullProfile.toTypedArray())
        try {
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val lines = CompletableFuture.supplyAsync { listOf(reader.readLine(), reader.readLine(), reader.readLine()) }.get(60, TimeUnit.SECONDS)
            assertTrue(lines[0].startsWith("Serving decomp_engine spa UI on http://127.0.0.1:"), lines.toString())
            assertTrue(lines[1].startsWith("Reverse-proxy profile:") && lines[1].contains("127.0.0.1"), lines.toString())
            assertTrue(lines[2].contains(": $public$BASE#bootstrap="), lines.toString())
            assertFalse(lines.any { it.contains(PROXY_SECRET) }, "the upstream credential must never be printed")
        } finally { process.destroyForcibly().waitFor(10, TimeUnit.SECONDS) }
    }

    private companion object {
        const val PROXY_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        const val EDGE_MAX_REQUEST_BYTES = 64L * 1024 * 1024
        const val TRUSTED_PEER = "127.0.0.2"
        const val BASE = "/decomp/"
        const val OPERATOR_CREDENTIAL = "Basic b3BlcmF0b3I6c3ludGhldGljLWZpeHR1cmU=" // operator:synthetic-fixture
    }
}
