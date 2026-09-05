package decompengine.web

import com.sun.net.httpserver.Headers
import com.sun.net.httpserver.HttpContext
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpPrincipal
import com.sun.net.httpserver.HttpServer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LocalWebAccessTest {
    @Test
    fun `configuration admits only explicitly canonical loopback origins`() {
        listOf("http://127.0.0.1:8000", "http://127.0.0.2:8000", "http://localhost:8000", "https://[::1]:8443", "http://[0:0:0:0:0:0:0:1]:8000").forEach {
            LocalWebAccessConfiguration(it, "/workbench/")
        }
        listOf("http://example.invalid:8000", "http://0.0.0.0:8000", "http://127.0.0.1:0", "http://user@127.0.0.1:8000",
            "http://127.0.0.1:8000/path", "http://127.0.0.1:8000?token=synthetic", "http://127.0.0.1:8000#fragment", "http://LOCALHOST:8000").forEach {
            assertFailsWith<IllegalArgumentException> { LocalWebAccessConfiguration(it) }
        }
        assertFailsWith<IllegalArgumentException> { LocalWebAccessConfiguration(ORIGIN, additionalLoopbackOrigins = setOf("https://localhost:8443")) }
        assertFailsWith<IllegalArgumentException> { LocalWebAccessConfiguration(ORIGIN, "/../") }
        assertEquals(256, LocalWebAccessConfiguration(ORIGIN, "/" + "a".repeat(254) + "/").basePath.length)
        assertFailsWith<IllegalArgumentException> { LocalWebAccessConfiguration(ORIGIN, "/" + "a".repeat(255) + "/") }
        assertFailsWith<IllegalArgumentException> { WebEndpointPolicy.jsonMutation("GET") }
        assertNotEquals(LocalWebAccessConfiguration(ORIGIN).cookieName, LocalWebAccessConfiguration("http://127.0.0.1:8001").cookieName)
    }

    @Test
    fun `transport preflight enforces boundary before methods without granting session authority`() {
        val access = access()
        val methods = mutableSetOf("POST", "DELETE")
        val policy = WebEndpointPolicy.transport(methods)
        methods.clear()
        val request = MemoryExchange("POST", "/api/v1/session").apply {
            requestHeaders.set("Host", "127.0.0.1:8000")
        }
        assertNull(access.authorize(request, policy))
        assertDenied(403, "ORIGIN_DENIED") { access.authorize(request, WebEndpointPolicy.jsonMutation("POST")) }
        request.requestHeaders.set("Origin", ORIGIN)
        request.requestHeaders.set("Content-Type", "application/json")
        assertDenied(401, "SESSION_REQUIRED") { access.authorize(request, WebEndpointPolicy.jsonMutation("POST")) }

        val unsupported = MemoryExchange("GET", "/api/v1/session").apply {
            requestHeaders.set("Host", "127.0.0.1:8000")
        }
        val denied = assertDenied(405, "METHOD_NOT_ALLOWED") { access.authorize(unsupported, policy) }
        assertEquals(setOf("POST", "DELETE"), denied.allowedMethods)
        unsupported.requestHeaders.set("Host", "example.invalid:8000")
        assertDenied(403, "HOST_DENIED") { access.authorize(unsupported, policy) }
        unsupported.requestHeaders.set("Host", "127.0.0.1:8000")
        unsupported.requestHeaders.set("Origin", "http://localhost:8000")
        assertDenied(403, "ORIGIN_DENIED") { access.authorize(unsupported, policy) }
        unsupported.requestHeaders.remove("Origin")
        unsupported.requestHeaders.set("Forwarded", "host=127.0.0.1:8000")
        assertDenied(403, "FORWARDED_HEADERS_DENIED") { access.authorize(unsupported, policy) }
        assertFailsWith<IllegalArgumentException> { WebEndpointPolicy.transport(emptySet()) }
        assertFailsWith<IllegalArgumentException> { WebEndpointPolicy.transport(setOf("GET\n")) }
    }

    @Test
    fun `bootstrap is single use and wrong origin cannot consume it`() {
        val access = access()
        val bootstrap = access.issueBootstrap()
        val wrong = bootstrapRequest(bootstrap.token).apply { requestHeaders.set("Origin", "http://localhost:8000") }
        assertDenied(403, "ORIGIN_DENIED") { access.establishSession(wrong) }
        val credentials = access.establishSession(bootstrapRequest(bootstrap.token))
        assertNotNull(credentials.setCookie)
        assertEquals(43, bootstrap.token.length)
        assertEquals(43, credentials.csrfToken.length)
        assertDenied(401, "BOOTSTRAP_REQUIRED") { access.establishSession(bootstrapRequest(bootstrap.token)) }
        assertFalse(bootstrap.toString().contains(bootstrap.token))
        assertFalse(credentials.toString().contains(credentials.csrfToken))
        assertFalse(credentials.toString().contains(credentials.setCookie))
    }

    @Test
    fun `reissuing bootstrap revokes old link and deadline is enforced at five minutes`() {
        val clock = TestClock()
        val access = access(clock)
        val old = access.issueBootstrap()
        val replacement = access.issueBootstrap()
        assertDenied(401, "BOOTSTRAP_REQUIRED") { access.establishSession(bootstrapRequest(old.token)) }
        clock.advance(Duration.ofMinutes(5))
        assertDenied(401, "BOOTSTRAP_EXPIRED") { access.establishSession(bootstrapRequest(replacement.token)) }
        assertNotNull(login(access).setCookie)
    }

    @Test
    fun `concurrent bootstrap exchange admits exactly one session`() {
        val access = access()
        val bootstrap = access.issueBootstrap()
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(8)
        try {
            val futures = (1..16).map {
                executor.submit<Int> {
                    start.await()
                    try { access.establishSession(bootstrapRequest(bootstrap.token)); 200 } catch (denial: WebAccessDenied) { denial.status }
                }
            }
            start.countDown()
            val statuses = futures.map { it.get(5, TimeUnit.SECONDS) }
            assertEquals(1, statuses.count { it == 200 })
            assertEquals(15, statuses.count { it == 401 })
        } finally { executor.shutdownNow() }
    }

    @Test
    fun `session quota is bounded and failed admission preserves bootstrap for explicit retry`() {
        val access = access()
        val sessions = (1..8).map { login(access) }
        val bootstrap = access.issueBootstrap()
        assertDenied(429, "SESSION_LIMIT") { access.establishSession(bootstrapRequest(bootstrap.token)) }
        access.logout(authenticated("DELETE", sessions.first()))
        assertNotNull(access.establishSession(bootstrapRequest(bootstrap.token)).setCookie)
    }

    @Test
    fun `cookie flags scope and secure transport are explicit`() {
        val plain = login(access()).setCookie!!
        assertTrue(plain.contains("; Path=/;"))
        assertTrue(plain.contains("HttpOnly"))
        assertTrue(plain.contains("SameSite=Strict"))
        assertFalse(plain.contains("Secure"))
        assertFalse(plain.contains("Domain="))
        val origin = "https://localhost:8443"
        val access = LocalWebAccess(LocalWebAccessConfiguration(origin, "/workbench/"), TestClock(), TestRandom())
        val token = access.issueBootstrap()
        val credentials = access.establishSession(bootstrapRequest(token.token, origin))
        assertTrue(credentials.setCookie!!.contains("; Path=/workbench/;"))
        assertTrue(credentials.setCookie.endsWith("; Secure"))
        assertEquals(Duration.ofHours(8).seconds.toString(), credentials.setCookie.substringAfter("Max-Age=").substringBefore(';'))
    }

    @Test
    fun `reload recovers stable per-session CSRF without accepting another session token`() {
        val access = access()
        val first = login(access)
        val second = login(access)
        val reloaded = access.csrfForSession(authenticated("GET", first))
        assertEquals(first.csrfToken, reloaded.csrfToken)
        assertEquals(first.session.sessionId, reloaded.session.sessionId)
        assertNull(reloaded.setCookie)
        assertNotEquals(first.csrfToken, second.csrfToken)
        val wrong = authenticated("POST", first).apply { requestHeaders.set("X-CSRF-Token", second.csrfToken) }
        assertDenied(403, "CSRF_DENIED") { access.authorize(wrong, WebEndpointPolicy.jsonMutation("POST")) }
        assertNotNull(access.authorize(authenticated("POST", first), WebEndpointPolicy.jsonMutation("POST")))
    }

    @Test
    fun `idle and absolute expiry use monotonic time and denied requests do not renew session`() {
        val clock = TestClock()
        val access = access(clock)
        val session = login(access)
        clock.advance(Duration.ofMinutes(29))
        val denied = authenticated("POST", session).apply { requestHeaders.remove("X-CSRF-Token") }
        assertDenied(403, "CSRF_DENIED") { access.authorize(denied, WebEndpointPolicy.jsonMutation("POST")) }
        clock.jumpWall(Duration.ofDays(-1))
        clock.advance(Duration.ofMinutes(1))
        assertDenied(401, "SESSION_EXPIRED") { access.authorize(authenticated("GET", session), WebEndpointPolicy.privateRead()) }

        val keptAlive = login(access)
        repeat(16) {
            clock.advance(Duration.ofMinutes(29))
            assertNotNull(access.authorize(authenticated("GET", keptAlive), WebEndpointPolicy.privateRead()))
        }
        clock.advance(Duration.ofMinutes(16))
        assertDenied(401, "SESSION_EXPIRED") { access.authorize(authenticated("GET", keptAlive), WebEndpointPolicy.privateRead()) }
    }

    @Test
    fun `logout explicit revocation and a new server all invalidate prior cookies`() {
        val access = access()
        val session = login(access)
        val clearCookie = access.logout(authenticated("DELETE", session))
        assertTrue(clearCookie.contains("Max-Age=0"))
        assertDenied(401, "SESSION_REQUIRED") { access.authorize(authenticated("GET", session), WebEndpointPolicy.privateRead()) }
        val second = login(access)
        val bootstrap = access.issueBootstrap()
        access.revokeAll()
        assertDenied(401, "SESSION_REQUIRED") { access.authorize(authenticated("GET", second), WebEndpointPolicy.privateRead()) }
        assertDenied(401, "BOOTSTRAP_REQUIRED") { access.establishSession(bootstrapRequest(bootstrap.token)) }
        val restarted = access()
        assertDenied(401, "SESSION_REQUIRED") { restarted.authorize(authenticated("GET", second), WebEndpointPolicy.privateRead()) }
        access.close()
        assertDenied(503, "SERVER_DRAINING") { access.issueBootstrap() }
    }

    @Test
    fun `host origin aliases fetch metadata and forwarding combinations fail closed`() {
        val access = LocalWebAccess(LocalWebAccessConfiguration(ORIGIN, additionalLoopbackOrigins = setOf("http://localhost:8000", "http://[::1]:8000")), TestClock(), TestRandom())
        val session = login(access)
        listOf("http://localhost:8000", "http://[::1]:8000").forEach { origin ->
            val allowed = authenticated("GET", session).apply {
                requestHeaders.set("Host", URI(origin).rawAuthority)
                requestHeaders.set("Origin", origin)
            }
            assertNotNull(access.authorize(allowed, WebEndpointPolicy.privateRead()))
        }
        val mutations: List<(MemoryExchange) -> Unit> = listOf(
            { it.requestHeaders.remove("Host") },
            { it.requestHeaders.set("Host", "example.invalid:8000") },
            { it.requestHeaders.set("Host", "127.0.0.1:8000, localhost:8000") },
            { it.requestHeaders.add("Host", "127.0.0.1:8000") },
            { it.requestHeaders.set("Origin", "null") },
            { it.requestHeaders.set("Origin", "http://localhost:8000") },
            { it.requestHeaders.set("Origin", "http://127.0.0.1:8000/") },
            { it.requestHeaders.add("Origin", ORIGIN) },
            { it.requestHeaders.set("Sec-Fetch-Site", "cross-site") },
            { it.requestHeaders.set("Sec-Fetch-Site", "same-site") },
            { it.requestHeaders.set("Forwarded", "host=127.0.0.1:8000") },
            { it.requestHeaders.set("X-Forwarded-Host", "127.0.0.1:8000") },
            { it.requestHeaders.set("X-Forwarded-Proto", "http") },
        )
        mutations.forEach { change ->
            val request = authenticated("GET", session).also(change)
            assertFailsWith<WebAccessDenied> { access.authorize(request, WebEndpointPolicy.privateRead()) }
        }
    }

    @Test
    fun `private read mutation method and content type policies are distinct`() {
        val access = access()
        val session = login(access)
        val read = authenticated("GET", session).apply { requestHeaders.remove("Origin"); requestHeaders.remove("X-CSRF-Token"); requestHeaders.remove("Content-Type") }
        assertNotNull(access.authorize(read, WebEndpointPolicy.privateRead()))
        assertNotNull(access.authorize(authenticated("HEAD", session), WebEndpointPolicy.privateRead(allowHead = true)))
        assertDenied(405, "METHOD_NOT_ALLOWED") { access.authorize(authenticated("HEAD", session), WebEndpointPolicy.privateRead()) }
        assertDenied(405, "METHOD_NOT_ALLOWED") { access.authorize(authenticated("GET", session), WebEndpointPolicy.jsonMutation("POST")) }
        assertDenied(405, "METHOD_NOT_ALLOWED") { access.authorize(authenticated("OPTIONS", session), WebEndpointPolicy.privateRead()) }
        val absentOrigin = authenticated("POST", session).apply { requestHeaders.remove("Origin") }
        assertDenied(403, "ORIGIN_DENIED") { access.authorize(absentOrigin, WebEndpointPolicy.jsonMutation("POST")) }
        listOf("text/plain", "application/x-www-form-urlencoded", "application/json; charset=iso-8859-1", "application/json, text/plain").forEach { type ->
            val request = authenticated("POST", session).apply { requestHeaders.set("Content-Type", type) }
            assertDenied(415, "UNSUPPORTED_MEDIA_TYPE") { access.authorize(request, WebEndpointPolicy.jsonMutation("POST")) }
        }
        listOf("application/json", "application/json; charset=UTF-8", "application/json; charset=\"utf-8\"").forEach { type ->
            val request = authenticated("POST", session).apply { requestHeaders.set("Content-Type", type) }
            assertNotNull(access.authorize(request, WebEndpointPolicy.jsonMutation("POST")))
        }
        val multipart = authenticated("POST", session).apply { requestHeaders.set("Content-Type", "multipart/form-data; boundary=synthetic-boundary") }
        assertNotNull(access.authorize(multipart, WebEndpointPolicy.multipartUpload()))
        assertDenied(415, "UNSUPPORTED_MEDIA_TYPE") { access.authorize(multipart, WebEndpointPolicy.jsonMutation("POST")) }
        multipart.requestHeaders.set("Content-Type", "multipart/form-data")
        assertDenied(415, "UNSUPPORTED_MEDIA_TYPE") { access.authorize(multipart, WebEndpointPolicy.multipartUpload()) }
    }

    @Test
    fun `ambiguous cookies and noncanonical or missing tokens do not authorize`() {
        val access = access()
        val session = login(access)
        val cookie = session.setCookie!!.substringBefore(';')
        listOf("", "$cookie; $cookie", "${access.configuration.cookieName}=not-a-token", "unrelated=synthetic").forEach { value ->
            val request = authenticated("GET", session).apply { requestHeaders.set("Cookie", value) }
            assertDenied(401, "SESSION_REQUIRED") { access.authorize(request, WebEndpointPolicy.privateRead()) }
        }
        val request = MemoryExchange("GET", "/private?token=${cookie.substringAfter('=')}").apply {
            requestHeaders.set("Host", "127.0.0.1:8000")
            requestHeaders.set("Authorization", "Bearer ${cookie.substringAfter('=')}")
        }
        assertDenied(401, "SESSION_REQUIRED") { access.authorize(request, WebEndpointPolicy.privateRead()) }
    }

    @Test
    fun `bootstrap body is bounded and duplicate unknown and malformed JSON are rejected`() {
        val access = access()
        val token = access.issueBootstrap().token
        listOf("{\"token\":\"$token\",\"token\":\"$token\"}", "{\"token\":\"$token\",\"to\\u006ben\":\"$token\"}", "{", "[] trailing").forEach { body ->
            assertDenied(400, "MALFORMED_JSON") { access.establishSession(bootstrapRequest(token, body = body)) }
        }
        listOf("{\"token\":\"$token\",\"extra\":true}", "[]", "{}", "{\"token\":123}", "{\"token\":null}",
            "{\"token\":true}", "{\"token\":[]}", "{\"token\":{}}").forEach { body ->
            assertDenied(400, "VALIDATION_FAILED") { access.establishSession(bootstrapRequest(token, body = body)) }
        }
        assertDenied(413, "BODY_TOO_LARGE") { access.establishSession(bootstrapRequest(token, body = " ".repeat(1025))) }
        val largeDeclared = bootstrapRequest(token).apply { requestHeaders.set("Content-Length", "1025") }
        assertDenied(413, "BODY_TOO_LARGE") { access.establishSession(largeDeclared) }
        assertNotNull(access.establishSession(bootstrapRequest(token, body = "{\"token\":\"$token\"}".padEnd(1024))).setCookie)
    }

    @Test
    fun `session JSON escaping preserves decoded token identity`() {
        val access = access()
        val token = access.issueBootstrap().token
        val escaped = token.map { "\\u" + it.code.toString(16).padStart(4, '0') }.joinToString("")
        val body = " \n{\"\\u0074oken\":\"$escaped\"}\t\r\n"
        assertNotNull(access.establishSession(bootstrapRequest(token, body = body)).setCookie)
        assertDenied(401, "BOOTSTRAP_REQUIRED") { access.establishSession(bootstrapRequest(token)) }
    }

    @Test
    fun `valid JSON with invalid or incorrect token receives value or authentication denial`() {
        val access = access()
        val token = access.issueBootstrap().token
        for (incorrect in listOf("a".repeat(32), "synthetic_non_secret_bootstrap_fixture_1234567890", "a".repeat(256))) {
            assertDenied(400, "VALIDATION_FAILED") { access.establishSession(bootstrapRequest(incorrect)) }
        }
        assertDenied(401, "BOOTSTRAP_REQUIRED") { access.establishSession(bootstrapRequest("A".repeat(43))) }
        assertNotNull(access.establishSession(bootstrapRequest(token)).setCookie)
    }

    @Test
    fun `session parser rejects invalid Unicode and excessive nesting without consuming token`() {
        val access = access()
        val token = access.issueBootstrap().token
        val malformedUtf8 = bootstrapRequest(token).apply { customInput = ByteArrayInputStream(byteArrayOf(0xc3.toByte(), 0x28)) }
        assertDenied(400, "MALFORMED_JSON") { access.establishSession(malformedUtf8) }
        listOf("{\"token\":\"\\ud800\"}", "[".repeat(9) + "0" + "]".repeat(9)).forEach { body ->
            assertDenied(400, "MALFORMED_JSON") { access.establishSession(bootstrapRequest(token, body = body)) }
        }
        assertNotNull(access.establishSession(bootstrapRequest(token)).setCookie)
    }

    @Test
    fun `slow session body never holds the authorization lock`() {
        val access = access()
        val session = login(access)
        val token = access.issueBootstrap().token
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val source = object : ByteArrayInputStream("{\"token\":\"$token\"}".toByteArray()) {
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS))
                return super.read(buffer, offset, length)
            }
        }
        val request = bootstrapRequest(token).apply { customInput = source }
        val executor = Executors.newFixedThreadPool(2)
        try {
            val establishing = executor.submit<WebSessionCredentials> { access.establishSession(request) }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            val unrelated = executor.submit<AuthorizedWebSession?> { access.authorize(authenticated("GET", session), WebEndpointPolicy.privateRead()) }
            assertNotNull(unrelated.get(1, TimeUnit.SECONDS))
            release.countDown()
            assertNotNull(establishing.get(5, TimeUnit.SECONDS))
        } finally { release.countDown(); executor.shutdownNow() }
    }

    @Test
    fun `real HTTP fetch reload SSE download and logout share one session boundary`() {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val origin = "http://127.0.0.1:${server.address.port}"
        val access = LocalWebAccess(LocalWebAccessConfiguration(origin), TestClock(), TestRandom())
        val mutations = AtomicInteger()
        server.createContext("/") { exchange ->
            try {
                when (exchange.requestURI.path) {
                    "/session" -> {
                        val grant = access.establishSession(exchange)
                        exchange.responseHeaders.set("Set-Cookie", grant.setCookie!!)
                        respond(exchange, buildJsonObject { put("csrfToken", grant.csrfToken) }.toString())
                    }
                    "/bootstrap" -> respond(exchange, buildJsonObject { put("csrfToken", access.csrfForSession(exchange).csrfToken) }.toString())
                    "/logout" -> {
                        exchange.responseHeaders.set("Set-Cookie", access.logout(exchange))
                        respond(exchange, "logged out")
                    }
                    "/mutation" -> {
                        access.authorize(exchange, WebEndpointPolicy.jsonMutation("POST"))
                        mutations.incrementAndGet()
                        respond(exchange, "accepted synthetic intent")
                    }
                    else -> {
                        access.authorize(exchange, WebEndpointPolicy.privateRead(allowHead = true))
                        if (exchange.requestURI.path == "/events") exchange.responseHeaders.set("Content-Type", "text/event-stream")
                        respond(exchange, if (exchange.requestURI.path == "/events") "event: snapshot\ndata: synthetic\n\n" else "synthetic private bytes")
                    }
                }
            } catch (failure: WebAccessDenied) { access.sendDenied(exchange, failure) }
        }
        server.start()
        try {
            assertEquals(401, http(origin, "GET", "/download").status)
            val bootstrap = access.issueBootstrap()
            val issued = http(origin, "POST", "/session", mapOf("Origin" to origin, "Content-Type" to "application/json"), "{\"token\":\"${bootstrap.token}\"}")
            assertEquals(200, issued.status)
            val cookie = issued.header("Set-Cookie")!!.substringBefore(';')
            val csrf = (Json.parseToJsonElement(issued.body).jsonObject.getValue("csrfToken") as JsonPrimitive).content
            val cookieHeader = mapOf("Cookie" to cookie)
            assertEquals(200, http(origin, "GET", "/bootstrap", cookieHeader).status)
            assertEquals(csrf, (Json.parseToJsonElement(http(origin, "GET", "/bootstrap", cookieHeader).body).jsonObject.getValue("csrfToken") as JsonPrimitive).content)
            assertTrue(http(origin, "GET", "/events", cookieHeader).body.contains("event: snapshot"))
            assertEquals("synthetic private bytes", http(origin, "GET", "/download", cookieHeader).body)
            assertEquals("", http(origin, "HEAD", "/download", cookieHeader).body)
            val denied = http(origin, "POST", "/mutation", cookieHeader + mapOf("Origin" to origin, "Content-Type" to "application/json"), "{}")
            assertEquals(403, denied.status)
            assertEquals("no-store", denied.header("Cache-Control"))
            assertEquals("no-referrer", denied.header("Referrer-Policy"))
            assertEquals("nosniff", denied.header("X-Content-Type-Options"))
            assertFalse(denied.headers.keys.any { it?.startsWith("Access-Control-", true) == true })
            assertFalse(denied.body.contains(cookie.substringAfter('=')))
            assertFalse(denied.body.contains(csrf))
            assertEquals(0, mutations.get())
            val auth = cookieHeader + mapOf("Origin" to origin, "Content-Type" to "application/json", "X-CSRF-Token" to csrf)
            assertEquals(200, http(origin, "POST", "/mutation", auth, "{}").status)
            assertEquals(1, mutations.get())
            assertEquals(200, http(origin, "DELETE", "/logout", auth, "{}").status)
            assertEquals(401, http(origin, "GET", "/events", cookieHeader).status)
            val deniedHead = http(origin, "HEAD", "/download", cookieHeader)
            assertEquals(401, deniedHead.status)
            assertEquals("", deniedHead.body)
        } finally { server.stop(0); access.close() }
    }

    private fun access(clock: TestClock = TestClock()): LocalWebAccess = LocalWebAccess(LocalWebAccessConfiguration(ORIGIN), clock, TestRandom())
    private fun login(access: LocalWebAccess): WebSessionCredentials = access.establishSession(bootstrapRequest(access.issueBootstrap().token))
    private fun bootstrapRequest(token: String, origin: String = ORIGIN, body: String = "{\"token\":\"$token\"}"): MemoryExchange =
        MemoryExchange("POST", "/session", body).apply {
            requestHeaders.set("Host", URI(origin).rawAuthority)
            requestHeaders.set("Origin", origin)
            requestHeaders.set("Content-Type", "application/json")
        }
    private fun authenticated(method: String, session: WebSessionCredentials): MemoryExchange = MemoryExchange(method, "/private").apply {
        requestHeaders.set("Host", "127.0.0.1:8000")
        requestHeaders.set("Origin", ORIGIN)
        requestHeaders.set("Cookie", session.setCookie!!.substringBefore(';'))
        requestHeaders.set("X-CSRF-Token", session.csrfToken)
        requestHeaders.set("Content-Type", "application/json")
    }
    private fun assertDenied(status: Int, code: String, action: () -> Unit): WebAccessDenied = assertFailsWith<WebAccessDenied>(block = action).also {
        assertEquals(status, it.status)
        assertEquals(code, it.code)
    }
    private fun respond(exchange: HttpExchange, body: String) {
        val bytes = body.toByteArray()
        exchange.responseHeaders.set("Content-Length", bytes.size.toString())
        if (exchange.requestMethod == "HEAD") exchange.sendResponseHeaders(200, -1)
        else { exchange.sendResponseHeaders(200, bytes.size.toLong()); exchange.responseBody.use { it.write(bytes) } }
        exchange.close()
    }
    private data class Response(val status: Int, val body: String, val headers: Map<String?, List<String>>) {
        fun header(name: String): String? = headers.entries.firstOrNull { it.key.equals(name, true) }?.value?.firstOrNull()
    }
    private fun http(origin: String, method: String, path: String, headers: Map<String, String> = emptyMap(), body: String? = null): Response {
        val request = HttpRequest.newBuilder(URI.create(origin + path)).timeout(Duration.ofSeconds(3))
        headers.forEach(request::header)
        request.method(method, body?.let(HttpRequest.BodyPublishers::ofString) ?: HttpRequest.BodyPublishers.noBody())
        val response = HTTP_CLIENT.send(request.build(), HttpResponse.BodyHandlers.ofString())
        return Response(response.statusCode(), response.body(), response.headers().map())
    }
    private class TestClock : WebAccessClock {
        private var now = Instant.parse("2026-09-05T00:00:00Z")
        private var ticks = 0L
        override fun instant(): Instant = now
        override fun nanoTime(): Long = ticks
        fun advance(duration: Duration) { now = now.plus(duration); ticks += duration.toNanos() }
        fun jumpWall(duration: Duration) { now = now.plus(duration) }
    }
    private class TestRandom : SecureRandom() {
        private val invocation = AtomicInteger()
        override fun nextBytes(bytes: ByteArray) {
            val count = invocation.incrementAndGet()
            bytes.indices.forEach { bytes[it] = (count + it).toByte() }
        }
    }
    private class MemoryExchange(private val method: String, path: String, body: String = "") : HttpExchange() {
        private val uri = URI.create(path)
        private val incoming = Headers()
        private val outgoing = Headers()
        private val input = body.byteInputStream()
        private val output = ByteArrayOutputStream()
        var customInput: InputStream? = null
        private var status = -1
        override fun getRequestHeaders(): Headers = incoming
        override fun getResponseHeaders(): Headers = outgoing
        override fun getRequestURI(): URI = uri
        override fun getRequestMethod(): String = method
        override fun getHttpContext(): HttpContext = throw UnsupportedOperationException()
        override fun close() = Unit
        override fun getRequestBody(): InputStream = customInput ?: input
        override fun getResponseBody(): OutputStream = output
        override fun sendResponseHeaders(code: Int, length: Long) { status = code }
        override fun getRemoteAddress(): InetSocketAddress = InetSocketAddress("127.0.0.1", 1)
        override fun getResponseCode(): Int = status
        override fun getLocalAddress(): InetSocketAddress = InetSocketAddress("127.0.0.1", 8000)
        override fun getProtocol(): String = "HTTP/1.1"
        override fun getAttribute(name: String): Any? = null
        override fun setAttribute(name: String, value: Any?) = Unit
        override fun setStreams(input: InputStream?, output: OutputStream?) = Unit
        override fun getPrincipal(): HttpPrincipal? = null
    }
    private companion object {
        const val ORIGIN = "http://127.0.0.1:8000"
        val HTTP_CLIENT: HttpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(3)).build()
    }
}
