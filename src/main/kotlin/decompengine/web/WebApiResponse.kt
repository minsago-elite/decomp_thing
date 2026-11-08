package decompengine.web

import com.sun.net.httpserver.HttpExchange
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.UUID

/** Shared versioned response contract for browser controllers. */
internal fun requireNoWebApiQuery(exchange: HttpExchange) {
    if (!exchange.requestURI.rawQuery.isNullOrEmpty()) {
        throw WebAccessDenied(400, "VALIDATION_FAILED", "This endpoint does not accept query parameters.")
    }
}

internal fun sendWebApiResponse(exchange: HttpExchange, status: Int, kind: String, data: JsonElement) {
    val requestId = UUID.randomUUID().toString()
    val response = buildJsonObject {
        put("apiVersion", 1)
        put("kind", kind)
        put("requestId", requestId)
        put("data", data)
    }
    // Finish bounded encoding before setting headers: an oversized document must not leave a partial response.
    val body = try { WebJsonUtf8.encode(response, MAXIMUM_WEB_API_RESPONSE_BYTES) }
        catch (failure: WebJsonByteLimitException) {
            throw IllegalStateException("The API response exceeds its byte ceiling", failure)
        }
    webApiHeaders(exchange, requestId)
    exchange.responseHeaders.set("Content-Type", "application/json; charset=utf-8")
    exchange.responseHeaders.set("Content-Length", body.size.toString())
    try {
        if (exchange.requestMethod == "HEAD") exchange.sendResponseHeaders(status, -1)
        else {
            exchange.sendResponseHeaders(status, body.size.toLong())
            exchange.responseBody.use { it.write(body) }
        }
    } finally { exchange.close() }
}

private const val MAXIMUM_WEB_API_RESPONSE_BYTES = 1024 * 1024

internal fun webApiHeaders(exchange: HttpExchange, requestId: String) {
    exchange.responseHeaders.set("X-Request-ID", requestId)
    exchange.responseHeaders.set("Cache-Control", "no-store")
    exchange.applyWebSecurityHeaders()
}

/** HEAD has no JSON body; retain only the two trusted session-invalidating denial codes. */
internal fun headWebSessionErrorCode(method: String, status: Int, code: String): String? =
    code.takeIf { method == "HEAD" && status == 401 && it in setOf("SESSION_REQUIRED", "SESSION_EXPIRED") }
