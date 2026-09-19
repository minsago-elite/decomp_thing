package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.jobs.WorkflowPinActor
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*

/** One selected progress-journal policy. Attribution comes exclusively from authorization. */
internal class WebProgressPinController(private val access: LocalWebAccess, private val jobs: WebJobService) {
    fun handle(exchange: HttpExchange, jobId: String, runId: String) {
        val read = exchange.requestMethod == "GET"
        val session = checkNotNull(access.authorize(exchange,
            if (read) WebEndpointPolicy.privateRead() else WebEndpointPolicy.jsonMutation("PUT")))
        requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
        if (!jobId.matches(Regex("[0-9a-f]{32}")) || !runId.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}"))) {
            throw WebAccessDenied(404, "NOT_FOUND", "The requested attempt is unavailable.")
        }
        val version: String
        val pinned: Boolean
        if (read) {
            if (exchange.requestHeaders.keys.any { it.startsWith("If-", true) }) {
                throw WebAccessDenied(400, "UNSUPPORTED_HEADER", "Read the current pin policy without conditional headers.")
            }
            val attempt = jobs.getAttempt(jobId, runId)
            version = attempt.version; pinned = attempt.progressRetentionPinned
        } else {
            val match = header(exchange, "If-Match")
                ?: throw WebAccessDenied(428, "PRECONDITION_REQUIRED", "A pin change requires the current run version in If-Match.")
            if (!match.matches(Regex("\"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\""))) {
                throw WebAccessDenied(400, "INVALID_HEADER", "If-Match must contain one strong run version.")
            }
            val key = header(exchange, "Idempotency-Key")
            if (key == null || !key.matches(Regex("[A-Za-z0-9_-]{16,128}"))) {
                throw WebAccessDenied(400, "INVALID_IDEMPOTENCY_KEY", "A pin change requires one bounded idempotency key.")
            }
            if (exchange.requestHeaders.keys.any { it.startsWith("If-", true) && !it.equals("If-Match", true) }) {
                throw WebAccessDenied(400, "UNSUPPORTED_HEADER", "Only If-Match is supported for pin changes.")
            }
            val desired = readPin(exchange)
            val result = try {
                jobs.requestProgressRetentionPinned(jobId, runId, match.removeSurrounding("\""), desired,
                    WorkflowPinActor.browserSession(session.sessionId), key)
            } catch (failure: WebJobServiceException) {
                when (failure.code) {
                    "VERSION_CONFLICT" -> throw WebAccessDenied(412, failure.code, "The run version changed. Read its current pin policy.")
                    "IDEMPOTENCY_CONFLICT" -> throw WebAccessDenied(409, failure.code, "The request key was used for a different pin change.")
                    "PIN_RECEIPT_CAPACITY" -> throw WebAccessDenied(429, failure.code, "Pin request history is at capacity. Reconcile the policy before a later explicit request.")
                    else -> throw failure
                }
            }
            version = result.receipt.appliedVersion; pinned = result.receipt.pinned
            if (result.replayed) exchange.responseHeaders.set("Idempotency-Replayed", "true")
        }
        exchange.responseHeaders.set("ETag", "\"$version\"")
        sendWebApiResponse(exchange, 200, "progressPin", buildJsonObject {
            put("jobId", jobId); put("runId", runId); put("version", version); put("pinned", pinned)
        })
    }

    private fun header(exchange: HttpExchange, name: String): String? {
        val values = exchange.requestHeaders[name] ?: return null
        if (values.size != 1 || values.single().length > 256 || values.single().any { it.code < 32 || it.code == 127 }) {
            throw WebAccessDenied(400, "INVALID_HEADER", "The request contains an invalid or repeated header.")
        }
        return values.single()
    }
    private fun readPin(exchange: HttpExchange): Boolean {
        val length = header(exchange, "Content-Length")
        if (length != null && (!length.matches(Regex("0|[1-9][0-9]{0,18}")) || length.toLongOrNull() == null)) {
            throw WebAccessDenied(400, "INVALID_HEADER", "The request length is invalid.")
        }
        if (length != null && length.toLong() > 1024) throw WebAccessDenied(413, "BODY_TOO_LARGE", "The pin request exceeds its byte limit.")
        val bytes = exchange.requestBody.use { it.readNBytes(1025) }
        if (bytes.size > 1024) throw WebAccessDenied(413, "BODY_TOO_LARGE", "The pin request exceeds its byte limit.")
        val value = try { OracleJson.parse(bytes, StrictJsonLimits(1024, 1024, 4, 16, 128, 512, 32)) }
            catch (_: Exception) { throw WebAccessDenied(400, "MALFORMED_JSON", "The pin request must be a bounded JSON object.") }
        val pin = (value as? JsonObject)?.takeIf { it.keys == setOf("pinned") }?.get("pinned") as? JsonPrimitive
        return pin?.takeUnless { it.isString }?.booleanOrNull
            ?: throw WebAccessDenied(400, "VALIDATION_FAILED", "The pin request must contain only a boolean pinned field.")
    }
}
