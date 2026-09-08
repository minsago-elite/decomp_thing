package decompengine.web

import com.sun.net.httpserver.HttpServer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WebSessionControllerTest {
    @Test
    fun `asset independent session handler shares authority and rejects requests before consuming credentials`() {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val origin = "http://127.0.0.1:${server.address.port}"
        val access = LocalWebAccess(LocalWebAccessConfiguration(origin))
        val sessions = WebSessionController(access)
        server.createContext("/") { exchange ->
            try {
                if (exchange.requestURI.path == "/api/v1/session") sessions.handle(exchange)
                else {
                    val credentials = access.csrfForSession(exchange)
                    exchange.sendResponseHeaders(200, credentials.csrfToken.length.toLong())
                    exchange.responseBody.use { it.write(credentials.csrfToken.toByteArray()) }
                    exchange.close()
                }
            } catch (failure: WebAccessDenied) { access.sendDenied(exchange, failure) }
        }
        server.start()
        val client = HttpClient.newHttpClient()
        fun request(method: String, path: String = "/api/v1/session", body: String = "", headers: Map<String, String> = emptyMap()): HttpResponse<String> {
            val builder = HttpRequest.newBuilder(URI.create(origin + path)).timeout(Duration.ofSeconds(5))
                .method(method, HttpRequest.BodyPublishers.ofString(body))
            (mapOf("Origin" to origin, "Content-Type" to "application/json", "Accept" to "application/json") + headers)
                .forEach { (name, value) -> builder.header(name, value) }
            return client.send(builder.build(), HttpResponse.BodyHandlers.ofString())
        }
        try {
            val token = access.issueBootstrap().token
            val body = "{\"token\":\"$token\"}"
            assertEquals(405, request("GET").statusCode())
            assertEquals(403, request("POST", body = body, headers = mapOf("Origin" to "http://example.invalid")).statusCode())
            assertEquals(400, request("POST", "/api/v1/session?extra=1", body).statusCode())
            assertEquals(406, request("POST", body = body, headers = mapOf("Accept" to "text/html")).statusCode())
            val response = request("POST", body = body)
            assertEquals(200, response.statusCode())
            val envelope = Json.parseToJsonElement(response.body()).jsonObject
            assertEquals("session", envelope.getValue("kind").jsonPrimitive.content)
            assertEquals(response.headers().firstValue("X-Request-ID").orElseThrow(), envelope.getValue("requestId").jsonPrimitive.content)
            assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow())
            assertFalse(response.body().contains(token))
            val cookieHeader = response.headers().firstValue("Set-Cookie").orElseThrow()
            assertTrue(cookieHeader.contains("HttpOnly"))
            assertTrue(cookieHeader.contains("SameSite=Strict"))
            val cookie = cookieHeader.substringBefore(';')
            val csrf = envelope.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
            assertEquals(csrf, request("GET", "/private", headers = mapOf("Cookie" to cookie)).body())
            assertEquals(403, request("DELETE", headers = mapOf("Cookie" to cookie)).statusCode())
            assertEquals(csrf, request("GET", "/private", headers = mapOf("Cookie" to cookie)).body())
            val logout = request("DELETE", headers = mapOf("Cookie" to cookie, "X-CSRF-Token" to csrf))
            assertEquals(204, logout.statusCode())
            assertTrue(logout.body().isEmpty())
            assertTrue(logout.headers().firstValue("Set-Cookie").orElseThrow().contains("Max-Age=0"))
            assertEquals(401, request("GET", "/private", headers = mapOf("Cookie" to cookie)).statusCode())
            assertEquals(401, request("POST", body = body).statusCode())
        } finally {
            server.stop(0)
            access.close()
        }
    }
}
