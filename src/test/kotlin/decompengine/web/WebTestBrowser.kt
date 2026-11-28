package decompengine.web

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import kotlin.test.assertEquals

/** One signed-in local browser over the real listener: exact Origin, session cookie and CSRF token. */
internal class WebTestBrowser(private val server: UploadServer) : AutoCloseable {
    val origin = "http://127.0.0.1:${server.serverPort}"
    private val http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
    val cookie: String
    val csrf: String

    init {
        val response = send("POST", "/w/api/v1/session", "{\"token\":\"${server.issueBrowserBootstrap().token}\"}".toByteArray(), signedIn = false)
        assertEquals(200, response.statusCode(), response.text())
        cookie = response.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
        csrf = response.json().getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
    }

    fun get(path: String, headers: Map<String, String> = emptyMap()): HttpResponse<ByteArray> = send("GET", path, null, headers)

    fun send(method: String, path: String, body: ByteArray?, headers: Map<String, String> = emptyMap(),
             signedIn: Boolean = true): HttpResponse<ByteArray> {
        val builder = HttpRequest.newBuilder(URI(origin + path)).timeout(Duration.ofSeconds(60))
            .method(method, body?.let(HttpRequest.BodyPublishers::ofByteArray) ?: HttpRequest.BodyPublishers.noBody())
        val defaults = buildMap {
            put("Accept", "application/json")
            if (method != "GET" && method != "HEAD") { put("Origin", origin); put("Content-Type", "application/json") }
            if (signedIn) { put("Cookie", cookie); put("X-CSRF-Token", csrf) }
        }
        (defaults + headers).forEach { (name, value) -> builder.header(name, value) }
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray()).also(::assertNoWebCors)
    }

    /** A multipart upload body with exactly one `binary` part. */
    fun upload(filename: String, bytes: ByteArray, key: String, headers: Map<String, String> = emptyMap()): HttpResponse<ByteArray> {
        val body = "--fixture_boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"$filename\"\r\n\r\n".toByteArray() +
            bytes + "\r\n--fixture_boundary--\r\n".toByteArray()
        return send("POST", "/w/api/v1/jobs", body, mapOf("Content-Type" to "multipart/form-data; boundary=fixture_boundary",
            "Idempotency-Key" to key) + headers)
    }

    override fun close() = http.close()
}

internal fun HttpResponse<ByteArray>.text(): String = body().decodeToString()
internal fun HttpResponse<ByteArray>.json(): JsonObject = Json.parseToJsonElement(text()).jsonObject
internal fun HttpResponse<ByteArray>.data(): JsonObject = json().getValue("data").jsonObject
internal fun HttpResponse<ByteArray>.errorCode(): String = json().getValue("error").jsonObject.getValue("code").jsonPrimitive.content
