package decompengine.web

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/** Explicit operator bootstrap for test clients; production has no session-issuing HTTP route. */
internal fun legacySessionHeaders(server: UploadServer): Map<String, String> {
    val origin = "http://127.0.0.1:${server.serverPort}"
    val token = server.issueBrowserBootstrap().token
    val response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI("$origin/api/v1/session"))
        .timeout(Duration.ofSeconds(5)).header("Origin", origin).header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"$token\"}")).build(), HttpResponse.BodyHandlers.ofString())
    check(response.statusCode() == 200) { "Test session exchange failed: ${response.statusCode()}" }
    return mapOf("Cookie" to response.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';'),
        "X-CSRF-Token" to Json.parseToJsonElement(response.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content)
}
