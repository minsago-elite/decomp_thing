package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.jobs.WorkflowCancellationActor
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*

/** Cancellation authority and actor attribution come only from the authenticated request. */
internal class WebCancellationController(private val access: LocalWebAccess, private val jobs: WebJobService) {
    fun handle(exchange: HttpExchange, jobId: String, runId: String) {
        val read = exchange.requestMethod == "GET"
        val session = checkNotNull(access.authorize(exchange, if (read) WebEndpointPolicy.privateRead() else WebEndpointPolicy.jsonMutation("PUT")))
        requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
        if (!jobId.matches(Regex("[0-9a-f]{32}")) || !runId.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")))
            throw WebAccessDenied(404, "NOT_FOUND", "The requested attempt is unavailable.")
        if (read) {
            if (exchange.requestHeaders.keys.any { it.startsWith("If-", true) })
                throw WebAccessDenied(400, "UNSUPPORTED_HEADER", "Read current cancellation eligibility without conditional headers.")
            val policy = jobs.cancellationEligibility(jobId, runId)
            exchange.responseHeaders.set("ETag", "\"${policy.attempt.version}\"")
            sendWebApiResponse(exchange, 200, "cancellationPolicy", buildJsonObject {
                put("current", webRun(policy.attempt)); put("eligible", policy.eligible)
                put("reasonCode", policy.reasonCode?.let(::JsonPrimitive) ?: JsonNull)
            })
            return
        }
        val match = header(exchange, "If-Match")
            ?: throw WebAccessDenied(428, "PRECONDITION_REQUIRED", "Cancellation requires the current run version in If-Match.")
        if (!match.matches(Regex("\"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\"")))
            throw WebAccessDenied(400, "INVALID_HEADER", "If-Match must contain one strong run version.")
        val key = header(exchange, "Idempotency-Key")
        if (key == null || !key.matches(Regex("[A-Za-z0-9_-]{16,128}")))
            throw WebAccessDenied(400, "INVALID_IDEMPOTENCY_KEY", "Cancellation requires one bounded idempotency key.")
        if (exchange.requestHeaders.keys.any { it.startsWith("If-", true) && !it.equals("If-Match", true) })
            throw WebAccessDenied(400, "UNSUPPORTED_HEADER", "Only If-Match is supported for cancellation.")
        readRequest(exchange)
        val result = try {
            jobs.requestDurableCancellation(jobId, runId, match.removeSurrounding("\""),
                WorkflowCancellationActor.browserSession(session.sessionId), key)
        } catch (failure: WebJobServiceException) {
            when (failure.code) {
                "VERSION_CONFLICT" -> throw WebAccessDenied(412, failure.code, "The attempt changed. Read its current state before a new command.")
                "IDEMPOTENCY_CONFLICT" -> throw WebAccessDenied(409, failure.code, "The request key was used for different cancellation intent.")
                "CANCELLATION_RECEIPT_CAPACITY" -> throw WebAccessDenied(429, failure.code, "Cancellation receipt storage is at capacity. Reconcile the attempt; no new command was applied.")
                else -> throw failure
            }
        }
        exchange.responseHeaders.set("ETag", "\"${result.attempt.version}\"")
        if (result.replayed) exchange.responseHeaders.set("Idempotency-Replayed", "true")
        sendWebApiResponse(exchange, 200, "cancellation", buildJsonObject {
            put("current", webRun(result.attempt)); put("replayed", result.replayed)
            put("acknowledgement", buildJsonObject {
                put("expectedVersion", result.receipt.expectedVersion); put("appliedVersion", result.receipt.appliedVersion)
                put("state", result.receipt.acknowledgedState.wireName); put("recordedAt", result.receipt.at.toString())
            })
        })
    }

    private fun header(exchange: HttpExchange, name: String): String? {
        val values = exchange.requestHeaders[name] ?: return null
        if (values.size != 1 || values.single().length > 256 || values.single().any { it.code < 32 || it.code == 127 }) {
            throw WebAccessDenied(400, "INVALID_HEADER", "The request contains an invalid or repeated header.")
        }
        return values.single()
    }
    private fun readRequest(exchange: HttpExchange) {
        val length = header(exchange, "Content-Length")
        if (length != null && (!length.matches(Regex("0|[1-9][0-9]{0,18}")) || length.toLongOrNull() == null)) {
            throw WebAccessDenied(400, "INVALID_HEADER", "The request length is invalid.")
        }
        if (length != null && length.toLong() > 1024) throw WebAccessDenied(413, "BODY_TOO_LARGE", "The cancellation request exceeds its byte limit.")
        val bytes = exchange.requestBody.use { it.readNBytes(1025) }
        if (bytes.size > 1024) throw WebAccessDenied(413, "BODY_TOO_LARGE", "The cancellation request exceeds its byte limit.")
        val value = try { OracleJson.parse(bytes, StrictJsonLimits(1024, 1024, 4, 16, 128, 512, 32)) }
            catch (_: Exception) { throw WebAccessDenied(400, "MALFORMED_JSON", "The cancellation request must be a bounded JSON object.") }
        if (value !is JsonObject || value.keys != setOf("action") || value["action"] != JsonPrimitive("cancel"))
            throw WebAccessDenied(400, "VALIDATION_FAILED", "The cancellation request must contain only action: cancel.")
    }
}
