package decompengine.web

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Prefer explicit JSON on the dual-format legacy upload, retaining HTML for absent or wildcard Accept. */
internal fun com.sun.net.httpserver.HttpExchange.requestsLegacyJson(): Boolean {
    val json = acceptsWebMediaType(this, "application/json")
    val html = acceptsWebMediaType(this, "text/html")
    if (!json && !html) throw WebAccessDenied(406, "NOT_ACCEPTABLE", "This endpoint returns text/html or application/json.")
    return json && (acceptsWebMediaType(this, "application/json", explicit = true) || !html)
}

internal fun legacyError(
    exchange: com.sun.net.httpserver.HttpExchange,
    status: Int,
    code: String,
    message: String,
    html: () -> String,
) {
    val segments = exchange.requestURI.path.split('/').filter(String::isNotBlank)
    val json = segments.firstOrNull() == "api" ||
        (exchange.requestMethod == "POST" && segments == listOf("jobs") &&
            try { exchange.requestsLegacyJson() } catch (_: WebAccessDenied) { false })
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
