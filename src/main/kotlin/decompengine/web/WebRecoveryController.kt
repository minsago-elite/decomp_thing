package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.jobs.WorkflowRecoveryMode
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*

/**
 * Closed recovery command for one identified predecessor attempt. Authorization precedes body
 * consumption and every service read. The body names only the mode and the expected input revision;
 * the workflow, limits, harness, checkpoint and paths come from the trusted server registration.
 */
internal class WebRecoveryController(
    private val jobs: WebJobService,
    private val jobMutations: WebJobMutationBoundary,
    private val basePath: String,
    // Fresh readiness for the predecessor's option, read before the service monitor like a start's.
    private val prerequisites: (decompengine.jobs.WorkflowKind, String?) -> WebWorkflowPrerequisites? = { _, _ -> WebWorkflowPrerequisites.UNCHECKED },
) {
    fun handle(exchange: HttpExchange, jobId: String, runId: String) {
        val mutation = jobMutations.authorizeRecovery(exchange)
        requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
        if (!jobId.matches(Regex("[0-9a-f]{32}")) || !runId.matches(ID))
            throw WebAccessDenied(404, "NOT_FOUND", "The requested attempt is unavailable.")
        // Without registered workflows or retained keyed receipts, no recovery can be admitted or replayed.
        if (!jobs.durableStartRouteAvailable(jobId))
            throw WebAccessDenied(503, "CAPABILITY_UNAVAILABLE", "Workflow recovery is unavailable.")
        val match = header(exchange, "If-Match")
            ?: throw WebAccessDenied(428, "PRECONDITION_REQUIRED", "Recovery requires the current run version in If-Match.")
        if (!match.matches(Regex("\"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\"")))
            throw WebAccessDenied(400, "INVALID_HEADER", "If-Match must contain one strong run version.")
        val key = header(exchange, "Idempotency-Key")
        if (key == null || !key.matches(Regex("[A-Za-z0-9_-]{16,128}")))
            throw WebAccessDenied(400, "INVALID_IDEMPOTENCY_KEY", "Recovery requires one bounded idempotency key.")
        if (exchange.requestHeaders.keys.any { it.startsWith("If-", true) && !it.equals("If-Match", true) })
            throw WebAccessDenied(400, "UNSUPPORTED_HEADER", "Only If-Match is supported for recovery.")
        val (mode, expectedInput) = readRequest(exchange)
        // The predecessor's workflow and harness are immutable, so its option's readiness can be read first.
        val predecessor = jobs.getAttempt(jobId, runId)
        val readiness = prerequisites(predecessor.workflow, predecessor.harnessCapabilityId)
        val result = try {
            mutation.request(jobId, runId, match.removeSurrounding("\""), mode, expectedInput, key, readiness)
        } catch (failure: WebJobServiceException) {
            throw when (failure.code) {
                "VERSION_CONFLICT" -> WebAccessDenied(412, failure.code, "The attempt changed. Read its current state before a new command.")
                "IDEMPOTENCY_CONFLICT" -> WebAccessDenied(409, failure.code, "The request key was used for different workflow intent.")
                "INPUT_REVISION_CONFLICT" -> WebAccessDenied(409, failure.code, "The attempt's recorded input differs from the expected input revision.")
                "INVALID_PREVIOUS_RUN" -> WebAccessDenied(409, "ATTEMPT_SUPERSEDED", "Only the latest unsuccessful attempt can be recovered.")
                "STORE_LIMIT" -> WebAccessDenied(409, failure.code, "This job reached its retained attempt limit.")
                "WORKFLOW_UNAVAILABLE" -> WebAccessDenied(503, "CAPABILITY_UNAVAILABLE", "The attempt's workflow is unavailable.")
                "WORKFLOW_PREREQUISITE_UNAVAILABLE" -> WebAccessDenied(503, "CAPABILITY_UNAVAILABLE",
                    "A runtime prerequisite for this workflow is unavailable. ${failure.message}")
                "WORKFLOW_LIMITS_UNAVAILABLE", "RECONSTRUCTION_SCOPE_UNAVAILABLE" ->
                    WebAccessDenied(503, "CAPABILITY_UNAVAILABLE", "The attempt's recorded limits or reconstruction scope are no longer server-approved.")
                "CAPACITY_UNAVAILABLE", "UPLOAD_CAPACITY" ->
                    WebAccessDenied(429, "QUOTA_EXCEEDED", "Workflow admission is at capacity. Inspect current work before a new request.")
                "SCHEDULING_FAILED" -> WebAccessDenied(503, failure.code, "Scheduling did not finish. Inspect the retained run before retrying.")
                in WebAttemptControls.RETRY_REASONS + WebAttemptControls.RESUME_REASONS - setOf("RECOVERY_REQUIRED", "SERVICE_STOPPED") ->
                    WebAccessDenied(409, failure.code, refusal(failure.code))
                else -> failure
            }
        }
        val attempt = result.attempt
        exchange.responseHeaders.set("Location", "${basePath}api/v1/jobs/${attempt.jobId}/runs/${attempt.runId}")
        exchange.responseHeaders.set("ETag", "\"${attempt.version}\"")
        if (result.replayed) exchange.responseHeaders.set("Idempotency-Replayed", "true")
        sendWebApiResponse(exchange, 202, "run", webRun(attempt))
    }

    private fun refusal(code: String): String = when (code) {
        "ATTEMPT_ACTIVE" -> "The attempt has not finished; it cannot be recovered yet."
        "ATTEMPT_COMPLETED" -> "A completed attempt is not recovered; start a new workflow instead."
        "ATTEMPT_SUPERSEDED" -> "A newer attempt exists. Only the latest unsuccessful attempt can be recovered."
        "ACTIVE_RUN" -> "This job already has active work."
        "INPUT_UNVERIFIED" -> "The attempt's input revision is no longer verified project evidence."
        "RESUME_UNSUPPORTED" -> "This workflow does not support checkpoint resume. Retry creates a new attempt instead."
        "HARNESS_CHANGED" -> "The registered harness differs from the attempt's recorded harness; resume is unsafe."
        else -> "The attempt's checkpoint could not be verified for resume."
    }

    private fun header(exchange: HttpExchange, name: String): String? {
        val values = exchange.requestHeaders[name] ?: return null
        if (values.size != 1 || values.single().length > 256 || values.single().any { it.code < 32 || it.code == 127 }) {
            throw WebAccessDenied(400, "INVALID_HEADER", "The request contains an invalid or repeated header.")
        }
        return values.single()
    }

    private fun readRequest(exchange: HttpExchange): Pair<WorkflowRecoveryMode, String?> {
        val length = header(exchange, "Content-Length")
        if (length != null && (!length.matches(Regex("0|[1-9][0-9]{0,18}")) || length.toLongOrNull() == null)) {
            throw WebAccessDenied(400, "INVALID_HEADER", "The request length is invalid.")
        }
        if (length != null && length.toLong() > MAX_BODY) tooLarge()
        val bytes = exchange.requestBody.use { it.readNBytes(MAX_BODY + 1) }
        if (bytes.size > MAX_BODY) tooLarge()
        val value = try { OracleJson.parse(bytes, StrictJsonLimits(MAX_BODY, MAX_BODY, 4, 16, 128, 512, 32)) }
            catch (_: Exception) { throw WebAccessDenied(400, "MALFORMED_JSON", "The recovery request must be a bounded JSON object.") }
        val body = value as? JsonObject ?: invalid()
        if (body.keys != setOf("mode", "expectedInputRevisionId")) invalid()
        val mode = (body["mode"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?.let { name -> WorkflowRecoveryMode.entries.singleOrNull { it.wireName == name } } ?: invalid()
        val input = when (val field = body["expectedInputRevisionId"]) {
            JsonNull -> null
            is JsonPrimitive -> field.takeIf { it.isString }?.content?.takeIf { it.matches(ID) } ?: invalid()
            else -> invalid()
        }
        return mode to input
    }

    private fun tooLarge(): Nothing = throw WebAccessDenied(413, "BODY_TOO_LARGE", "The recovery request exceeds its byte limit.")
    private fun invalid(): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED",
        "The recovery request must contain only mode (retry or resume) and expectedInputRevisionId.")
    private companion object {
        const val MAX_BODY = 1024
        val ID = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
    }
}
