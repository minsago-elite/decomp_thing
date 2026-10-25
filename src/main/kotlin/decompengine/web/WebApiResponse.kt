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

/**
 * Kinds whose payload is committed job content rather than server-produced text: source bytes and the
 * committed source tree's own names, whose contract requires exact, unique and ordered spellings.
 */
private val committedContentKinds = setOf("sourceChunk", "revisionDirectory", "revisionSources", "revisionFile", "sourceCatalog")

/** The public projection of one response payload under [policy]. */
internal fun publicWebApiData(kind: String, data: JsonElement, policy: WebRedactionPolicy): JsonElement =
    if (kind in committedContentKinds) data else policy.json(data)

internal fun sendWebApiResponse(exchange: HttpExchange, status: Int, kind: String, data: JsonElement) {
    val requestId = UUID.randomUUID().toString()
    val public = publicWebApiData(kind, data, WebRedactionPolicy.of(exchange))
    val body = buildJsonObject {
        put("apiVersion", 1)
        put("kind", kind)
        put("requestId", requestId)
        put("data", public)
    }.toString().toByteArray(Charsets.UTF_8)
    check(body.size <= 1024 * 1024) { "The API response exceeds its byte ceiling" }
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

internal fun webApiHeaders(exchange: HttpExchange, requestId: String) {
    exchange.responseHeaders.set("X-Request-ID", requestId)
    exchange.responseHeaders.set("Cache-Control", "no-store")
    exchange.applyWebSecurityHeaders()
}

/** HEAD has no JSON body; retain only the two trusted session-invalidating denial codes. */
internal fun headWebSessionErrorCode(method: String, status: Int, code: String): String? =
    code.takeIf { method == "HEAD" && status == 401 && it in setOf("SESSION_REQUIRED", "SESSION_EXPIRED") }
