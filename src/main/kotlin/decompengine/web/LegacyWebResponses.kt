package decompengine.web

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Retain the legacy upload Accept switch; API paths always return JSON errors. */
internal fun com.sun.net.httpserver.HttpExchange.requestsLegacyJson(): Boolean =
    (requestHeaders.getFirst("Accept") ?: "").contains("application/json")

internal fun legacyError(
    exchange: com.sun.net.httpserver.HttpExchange,
    status: Int,
    code: String,
    message: String,
    html: () -> String,
) {
    val segments = exchange.requestURI.path.split('/').filter(String::isNotBlank)
    val json = segments.firstOrNull() == "api" ||
        (exchange.requestMethod == "POST" && segments == listOf("jobs") && exchange.requestsLegacyJson())
    if (!json) {
        exchange.sendHtml(status, html())
        return
    }
    val requestId = java.util.UUID.randomUUID().toString()
    exchange.responseHeaders.set("X-Request-ID", requestId)
    exchange.sendJson(status, buildJsonObject {
        put("requestId", requestId)
        put("error", buildJsonObject {
            put("code", code)
            put("message", message)
        })
    }.toString())
}
