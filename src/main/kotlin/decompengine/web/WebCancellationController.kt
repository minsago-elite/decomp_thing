package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*

/** Cancellation authority and actor attribution come only from the authenticated request. */
internal class WebCancellationController(
    private val jobMutations: WebJobMutationBoundary,
    private val basePath: String,
) {
    fun handle(exchange: HttpExchange, jobId: String, runId: String) {
        val mutation = jobMutations.authorizeCancellation(exchange)
        requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
        if (!jobId.matches(Regex("[0-9a-f]{32}")) || !runId.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")))
            throw WebAccessDenied(404, "NOT_FOUND", "The requested attempt is unavailable.")
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
            mutation.request(jobId, runId, match.removeSurrounding("\""), key)
        } catch (failure: WebJobServiceException) {
            when (failure.code) {
                "VERSION_CONFLICT" -> throw WebAccessDenied(412, failure.code, "The attempt changed. Read its current state before a new command.")
                "IDEMPOTENCY_CONFLICT" -> throw WebAccessDenied(409, failure.code, "The request key was used for different cancellation intent.")
                "CANCELLATION_RECEIPT_CAPACITY" -> throw WebAccessDenied(429, failure.code, "Cancellation receipt storage is at capacity. Reconcile the attempt; no new command was applied.")
                else -> throw failure
            }
        }
        val attempt = result.attempt
        exchange.responseHeaders.set("ETag", "\"${attempt.version}\"")
        exchange.responseHeaders.set("Location", "${basePath}api/v1/jobs/${attempt.jobId}/runs/${attempt.runId}")
        if (result.replayed) exchange.responseHeaders.set("Idempotency-Replayed", "true")
        // The receipt retains the original acknowledgement; the response contains current run state.
        val status = if (result.receipt.acknowledgedState.terminal) 200 else 202
        sendWebApiResponse(exchange, status, "run", webRun(attempt))
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
            throw WebAccessDenied(422, "VALIDATION_FAILED", "The cancellation request must contain only action: cancel.")
    }
}
