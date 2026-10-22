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
 * legitimately travel are the one-time bootstrap request body, the session cookie and the CSRF
 * token delivered to the authenticated client; no URL, diagnostic line or unrelated response may
 * carry any of them.
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

    @Test
    fun `sign-in, denial, expiry, reauthentication and logout never put credentials in urls, diagnostics or other responses`() {
        val clock = TestClock()
        val diagnostics = CopyOnWriteArrayList<String>()
        val server = UploadServer("127.0.0.1", 0, directory.resolve("jobs"), uiMode = WebUiMode.SPA, basePath = "/nested/",
            webAccessClock = clock, requestDiagnosticOutput = { diagnostics += it })
        val client = HttpClient.newHttpClient()
        val requested = mutableListOf<String>()
        val observed = mutableListOf<Pair<HttpResponse<String>, String?>>()
        fun send(path: String, method: String = "GET", body: String? = null, headers: Map<String, String> = emptyMap(),
                 origin: String = server.browserOrigin): HttpResponse<String> {
            requested += path
            val builder = HttpRequest.newBuilder(URI("${server.browserOrigin}$path")).header("Accept", "application/json")
            headers.forEach { (k, v) -> builder.header(k, v) }
            if (method != "GET") builder.header("Origin", origin).header("Content-Type", "application/json")
                .method(method, HttpRequest.BodyPublishers.ofString(body ?: "{}"))
            return client.send(builder.build(), HttpResponse.BodyHandlers.ofString()).also { observed += it to headers["Cookie"] }
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
            val cookieValue = cookie.substringAfter('=')
            assertTrue(signedIn.headers().firstValue("Set-Cookie").orElseThrow().contains("HttpOnly"))
            assertEquals(200, send("/nested/api/v1/bootstrap", headers = mapOf("Cookie" to cookie)).statusCode())
            assertTrue(send("/nested/api/v1/bootstrap").statusCode() == 401)
            // A replay of the consumed one-time token is refused.
            assertTrue(exchange(first).statusCode() in 400..499)
            clock.advance(Duration.ofHours(8))
            val expired = send("/nested/api/v1/bootstrap", headers = mapOf("Cookie" to cookie))
            assertEquals(401, expired.statusCode())
            val fresh = server.issueBrowserBootstrap().token
            val reauthenticated = exchange(fresh)
            assertEquals(200, reauthenticated.statusCode())
            val newCookie = cookieOf(reauthenticated); val newCsrf = csrfOf(reauthenticated)
            val logout = send("/nested/api/v1/session", "DELETE", headers = mapOf("Cookie" to newCookie, "X-CSRF-Token" to newCsrf))
            assertTrue(logout.statusCode() in 200..299, "logout status ${logout.statusCode()}")
            assertEquals(401, send("/nested/api/v1/bootstrap", headers = mapOf("Cookie" to newCookie)).statusCode())

            val bootstrapTokens = listOf(first, fresh, wrongToken)
            val cookieValues = listOf(cookieValue, newCookie.substringAfter('='))
            val csrfTokens = mapOf(cookie to csrf, newCookie to newCsrf)
            val credentials = bootstrapTokens + cookieValues + csrfTokens.values
            // No credential appears in any URL the client was asked to use, so none can enter history or server access logs.
            for (credential in credentials) for (url in requested) assertFalse(url.contains(credential), "credential in request URL $url")
            // No credential appears in server diagnostics.
            for (credential in credentials) for (line in diagnostics) assertFalse(line.contains(credential), "credential in diagnostic: $line")
            for ((response, usedCookie) in observed) {
                val body = response.body()
                // One-time bootstrap tokens and cookie values are never echoed in a body.
                for (secret in bootstrapTokens + cookieValues) assertFalse(body.contains(secret), "secret echoed in a response body")
                // A CSRF token reaches only its own session: in the session body that created it or in that session's reads.
                for ((owner, token) in csrfTokens) {
                    val ownSession = usedCookie == owner || (response === signedIn && owner == cookie) || (response === reauthenticated && owner == newCookie)
                    if (!ownSession) assertFalse(body.contains(token), "CSRF token disclosed to a request without its session")
                }
                // Only Set-Cookie may carry a cookie; no other header carries any credential.
                for ((name, values) in response.headers().map()) {
                    if (name.equals("Set-Cookie", true)) continue
                    for (credential in credentials) assertFalse(values.any { it.contains(credential) }, "credential in response header $name")
                }
            }
        } finally { server.stop() }
    }
}
