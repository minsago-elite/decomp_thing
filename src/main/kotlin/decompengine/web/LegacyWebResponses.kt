package decompengine.web

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
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
    requestDiagnosticOutput: (String) -> Unit = System.err::println,
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
    recordWebRequestFailure(requestId, status, code, requestDiagnosticOutput)
    exchange.sendJson(status, buildJsonObject {
        put("requestId", requestId)
        put("error", buildJsonObject {
            put("code", code)
            put("message", message)
        })
    }.toString())
}

/** Preserve older JSON fields while giving direct legacy API failures the same safe correlation boundary. */
internal fun sendCorrelatedLegacyJsonProblem(
    exchange: com.sun.net.httpserver.HttpExchange,
    status: Int,
    code: String,
    payload: String,
    requestDiagnosticOutput: (String) -> Unit = System.err::println,
) {
    require(status in 400..599)
    val fields = Json.parseToJsonElement(payload) as? JsonObject
        ?: error("Legacy JSON error payload must be an object")
    val requestId = java.util.UUID.randomUUID().toString()
    val correlated = buildJsonObject {
        fields.forEach { (key, value) -> put(key, value) }
        put("requestId", requestId)
    }
    exchange.responseHeaders.set("X-Request-ID", requestId)
    recordWebRequestFailure(requestId, status, code, requestDiagnosticOutput)
    exchange.sendJson(status, correlated.toString())
}
