package decompengine.web

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.io.TempDir
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Path
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Real HTTP session lifecycle with captured server diagnostics. The only places a credential may
 * legitimately travel are the one-time bootstrap request body, the session cookie (in Set-Cookie
 * only) and the CSRF token delivered to its own authenticated session by the session exchange and
 * authenticated bootstrap reads; no URL, diagnostic line or other response may carry any of them.
 */
class WebSessionCredentialDisclosureTest {
    @TempDir lateinit var directory: Path

    private class TestClock : WebAccessClock {
        private val wallBase = Instant.now()
        private val elapsedNanos = AtomicLong()
        override fun instant(): Instant = wallBase.plusNanos(elapsedNanos.get())
        override fun nanoTime(): Long = elapsedNanos.get()
        fun advance(duration: Duration) { elapsedNanos.addAndGet(duration.toNanos()) }
    }

    private class Observed(val method: String, val path: String, val cookie: String?, val response: HttpResponse<String>)

    @Test
    fun `sign-in, denial, expiry, reauthentication and logout never put credentials in urls, diagnostics or other responses`() {
        val clock = TestClock()
        val diagnostics = CopyOnWriteArrayList<String>()
        val server = UploadServer("127.0.0.1", 0, directory.resolve("jobs"), uiMode = WebUiMode.SPA, basePath = "/nested/",
            webAccessClock = clock, requestDiagnosticOutput = { diagnostics += it })
        val client = HttpClient.newHttpClient()
        val requested = mutableListOf<String>()
        val observed = mutableListOf<Observed>()
        fun send(path: String, method: String = "GET", body: String? = null, headers: Map<String, String> = emptyMap(),
                 origin: String = server.browserOrigin): HttpResponse<String> {
            requested += path
            val builder = HttpRequest.newBuilder(URI("${server.browserOrigin}$path")).header("Accept", "application/json")
            headers.forEach { (k, v) -> builder.header(k, v) }
            if (method != "GET") builder.header("Origin", origin).header("Content-Type", "application/json")
                .method(method, HttpRequest.BodyPublishers.ofString(body ?: "{}"))
            return client.send(builder.build(), HttpResponse.BodyHandlers.ofString()).also { observed += Observed(method, path, headers["Cookie"], it) }
        }
        fun exchange(token: String, origin: String = server.browserOrigin) = send("/nested/api/v1/session", "POST", "{\"token\":\"$token\"}", origin = origin)
        fun cookieOf(response: HttpResponse<String>) = response.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
        fun csrfOf(response: HttpResponse<String>) =
            Json.parseToJsonElement(response.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
        server.start()
        try {
            val first = server.issueBrowserBootstrap().token
            val wrongToken = "w".repeat(first.length)
            assertTrue(exchange(wrongToken).statusCode() in 400..499)
            assertTrue(exchange(first, origin = "http://evil.invalid").statusCode() in 400..499)
            val signedIn = exchange(first)
            assertEquals(200, signedIn.statusCode())
            val cookie = cookieOf(signedIn); val csrf = csrfOf(signedIn)
            assertTrue(signedIn.headers().firstValue("Set-Cookie").orElseThrow().contains("HttpOnly"))
            assertEquals(200, send("/nested/api/v1/bootstrap", headers = mapOf("Cookie" to cookie)).statusCode())
            assertTrue(send("/nested/api/v1/bootstrap").statusCode() == 401)
            // Rejected mutations that carry the real CSRF token: wrong origin with the cookie, and no cookie at all.
            assertTrue(send("/nested/api/v1/session", "DELETE", headers = mapOf("Cookie" to cookie, "X-CSRF-Token" to csrf), origin = "http://evil.invalid").statusCode() in 400..499)
            assertTrue(send("/nested/api/v1/session", "DELETE", headers = mapOf("X-CSRF-Token" to csrf)).statusCode() in 400..499)
            assertTrue(send("/nested/api/v1/jobs", "POST", headers = mapOf("X-CSRF-Token" to csrf)).statusCode() in 400..499)
            // A replay of the consumed one-time token is refused.
            assertTrue(exchange(first).statusCode() in 400..499)
            clock.advance(Duration.ofHours(8))
            val expired = send("/nested/api/v1/bootstrap", headers = mapOf("Cookie" to cookie, "X-CSRF-Token" to csrf))
            assertEquals(401, expired.statusCode())
            val fresh = server.issueBrowserBootstrap().token
            val reauthenticated = exchange(fresh)
            assertEquals(200, reauthenticated.statusCode())
            val newCookie = cookieOf(reauthenticated); val newCsrf = csrfOf(reauthenticated)
            assertTrue(send("/nested/api/v1/session", "DELETE", headers = mapOf("Cookie" to newCookie, "X-CSRF-Token" to newCsrf), origin = "http://evil.invalid").statusCode() in 400..499)
            val logout = send("/nested/api/v1/session", "DELETE", headers = mapOf("Cookie" to newCookie, "X-CSRF-Token" to newCsrf))
            assertTrue(logout.statusCode() in 200..299, "logout status ${logout.statusCode()}")
            assertEquals(401, send("/nested/api/v1/bootstrap", headers = mapOf("Cookie" to newCookie, "X-CSRF-Token" to newCsrf)).statusCode())

            val bootstrapTokens = listOf(first, fresh, wrongToken)
            val cookieValues = listOf(cookie.substringAfter('='), newCookie.substringAfter('='))
            val csrfTokens = mapOf(cookie to csrf, newCookie to newCsrf)
            val credentials = bootstrapTokens + cookieValues + csrfTokens.values
            // No credential appears in any URL the client was asked to use, so none can enter history or server access logs.
            for (credential in credentials) for (url in requested) assertFalse(url.contains(credential), "credential in request URL $url")
            // No credential appears in server diagnostics, including those from rejected requests that carried the real CSRF token.
            assertTrue(diagnostics.isNotEmpty() || observed.any { it.response.statusCode() >= 400 })
            for (credential in credentials) for (line in diagnostics) assertFalse(line.contains(credential), "credential in diagnostic: $line")
            for (item in observed) {
                val body = item.response.body()
                // One-time bootstrap tokens and cookie values are never echoed in a body.
                for (secret in bootstrapTokens + cookieValues) assertFalse(body.contains(secret), "secret echoed in a ${item.method} ${item.path} body")
                // A CSRF token is delivered only by the successful session exchange that created it, or by a successful
                // authenticated bootstrap read made with that session's cookie.
                for ((owner, token) in csrfTokens) {
                    val creating = (item.response === signedIn && owner == cookie) || (item.response === reauthenticated && owner == newCookie)
                    val ownRead = item.method == "GET" && item.path == "/nested/api/v1/bootstrap" && item.cookie == owner && item.response.statusCode() == 200
                    if (!creating && !ownRead) assertFalse(body.contains(token), "CSRF token echoed in a ${item.method} ${item.path} (${item.response.statusCode()}) body")
                }
                for ((name, values) in item.response.headers().map()) {
                    if (name.equals("Set-Cookie", true)) {
                        // Set-Cookie may carry only a session cookie value, never a bootstrap or CSRF credential.
                        for (secret in bootstrapTokens + csrfTokens.values) assertFalse(values.any { it.contains(secret) }, "non-cookie credential in Set-Cookie")
                    } else for (credential in credentials) assertFalse(values.any { it.contains(credential) }, "credential in response header $name")
                }
            }
        } finally { server.stop() }
    }
}
