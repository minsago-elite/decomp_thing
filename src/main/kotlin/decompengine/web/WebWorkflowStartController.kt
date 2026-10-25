package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowKind
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*

/** Closed HTTP command. Authorization precedes body consumption and every service read/write. */
internal class WebWorkflowStartController(
    private val jobs: WebJobService,
    private val jobMutations: WebJobMutationBoundary,
    private val basePath: String,
    // Fresh readiness for admission; read before the service monitor so a slow probe never holds it.
    private val prerequisites: (NewWorkflowAttempt) -> WebWorkflowPrerequisites? = { WebWorkflowPrerequisites.UNCHECKED },
) {
    fun handle(exchange: HttpExchange, jobId: String) {
        val mutation = jobMutations.authorizeDurableStart(exchange)
        requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
        if (!jobId.matches(Regex("[0-9a-f]{32}"))) {
            throw WebAccessDenied(404, "NOT_FOUND", "The requested job is unavailable.")
        }
        // Keep unavailable production routes truthful, without reading an unneeded body.
        // A retained keyed attempt keeps this transport open for read-only replay after restart.
        if (!jobs.durableStartRouteAvailable(jobId)) {
            throw WebAccessDenied(405, "METHOD_NOT_ALLOWED", "Workflow start is unavailable.", setOf("GET"))
        }
        val match = header(exchange, "If-Match")
            ?: throw WebAccessDenied(428, "PRECONDITION_REQUIRED", "Starting a workflow requires the current job version in If-Match.")
        if (!match.matches(Regex("\"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\""))) {
            throw WebAccessDenied(400, "INVALID_HEADER", "If-Match must contain one strong job version.")
        }
        val key = header(exchange, "Idempotency-Key")
        if (key == null || !key.matches(Regex("[A-Za-z0-9_-]{16,128}"))) {
            throw WebAccessDenied(400, "INVALID_IDEMPOTENCY_KEY", "Starting a workflow requires one bounded idempotency key.")
        }
        if (exchange.requestHeaders.keys.any { it.startsWith("If-", true) && !it.equals("If-Match", true) }) {
            throw WebAccessDenied(400, "UNSUPPORTED_HEADER", "Only If-Match is supported for workflow starts.")
        }
        val request = readStart(exchange)
        val readiness = prerequisites(request)
        val result = try { mutation.request(jobId, match.removeSurrounding("\""), request, key, readiness) }
        catch (failure: WebJobServiceException) {
            when (failure.code) {
                "VERSION_CONFLICT" -> throw WebAccessDenied(412, failure.code, "The job version changed. Refresh before starting new work.")
                "IDEMPOTENCY_CONFLICT" -> throw WebAccessDenied(409, failure.code, "The request key was used for a different workflow start.")
                "ACTIVE_RUN" -> throw WebAccessDenied(409, failure.code, "This job already has an active workflow attempt.")
                "CAPACITY_UNAVAILABLE", "UPLOAD_CAPACITY" -> throw WebAccessDenied(429, "QUOTA_EXCEEDED", "Workflow admission is at capacity. Inspect current work before a new request.")
                "WORKFLOW_UNAVAILABLE", "WORKFLOW_LIMITS_UNAVAILABLE", "HARNESS_UNAVAILABLE" ->
                    throw WebAccessDenied(503, "CAPABILITY_UNAVAILABLE", "The requested workflow, harness or limits are unavailable.")
                // Prerequisite messages are fixed server vocabulary, never probe or exception text.
                "WORKFLOW_PREREQUISITE_UNAVAILABLE" -> throw WebAccessDenied(503, "CAPABILITY_UNAVAILABLE",
                    "A runtime prerequisite for this workflow is unavailable. ${failure.message}")
                "INPUT_REVISION_UNAVAILABLE" -> throw WebAccessDenied(422, failure.code, "The selected input revision is unavailable for this job.")
                "INPUT_REVISION_REQUIRED" -> throw WebAccessDenied(422, failure.code, "This workflow starts from a revision recorded by this job. Select one before starting.")
                "RECONSTRUCTION_SCOPE_UNAVAILABLE" -> throw WebAccessDenied(422, failure.code, "The requested reconstruction scope is outside the server-approved range for this option.")
                "SCHEDULING_FAILED" -> throw WebAccessDenied(503, failure.code, "Scheduling did not finish. Inspect the retained run before retrying.")
                else -> throw failure
            }
        }
        val attempt = result.attempt
        exchange.responseHeaders.set("Location", "${basePath}api/v1/jobs/${attempt.jobId}/runs/${attempt.runId}")
        exchange.responseHeaders.set("ETag", "\"${attempt.version}\"")
        if (result.replayed) exchange.responseHeaders.set("Idempotency-Replayed", "true")
        sendWebApiResponse(exchange, 202, "run", webRun(attempt))
    }

    private fun header(exchange: HttpExchange, name: String): String? {
        val values = exchange.requestHeaders[name] ?: return null
        if (values.size != 1 || values.single().length > 256 || values.single().any { it.code < 32 || it.code == 127 }) {
            throw WebAccessDenied(400, "INVALID_HEADER", "The request contains an invalid or repeated header.")
        }
        return values.single()
    }

    private fun readStart(exchange: HttpExchange): NewWorkflowAttempt {
        val length = header(exchange, "Content-Length")
        if (length != null && (!length.matches(Regex("0|[1-9][0-9]{0,18}")) || length.toLongOrNull() == null)) {
            throw WebAccessDenied(400, "INVALID_HEADER", "The request length is invalid.")
        }
        if (length != null && length.toLong() > MAX_BODY) tooLarge()
        val bytes = exchange.requestBody.use { it.readNBytes(MAX_BODY + 1) }
        if (bytes.size > MAX_BODY) tooLarge()
        val value = try { OracleJson.parse(bytes, StrictJsonLimits(MAX_BODY, MAX_BODY, 4, 32, 128, 2048, 32)) }
        catch (_: Exception) { throw WebAccessDenied(400, "MALFORMED_JSON", "The workflow start must be bounded strict JSON.") }
        val body = value as? JsonObject ?: invalid()
        val declared = setOf("workflow", "inputRevisionId", "harnessCapabilityId", "limits")
        if (body.keys != declared && body.keys != declared + "scope") invalid()
        val workflow = WorkflowKind.entries.singleOrNull { it.wireName == text(body["workflow"]) } ?: invalid()
        val limits = body["limits"] as? JsonObject ?: invalid()
        if (limits.keys != setOf("wallClockMs", "idleMs", "maxOutputBytes", "maxToolCalls")) invalid()
        val scope = body["scope"]?.takeUnless { it == JsonNull }?.let { value ->
            val fields = value as? JsonObject ?: invalid()
            if (fields.keys != setOf("maxContextCharacters")) invalid()
            fields["maxContextCharacters"]
        }
        return try {
            NewWorkflowAttempt(workflow, WorkflowExecutionLimits(number(limits["wallClockMs"]), number(limits["idleMs"]),
                number(limits["maxOutputBytes"]), number(limits["maxToolCalls"])),
                nullableId(body["inputRevisionId"]), nullableId(body["harnessCapabilityId"]),
                scope = scope?.let { decompengine.jobs.WorkflowReconstructionScope(number(it)) })
        } catch (_: IllegalArgumentException) { invalid() }
    }

    private fun text(value: JsonElement?): String = (value as? JsonPrimitive)?.takeIf { it.isString }?.content ?: invalid()
    private fun nullableId(value: JsonElement?): String? {
        if (value == JsonNull) return null
        return text(value).takeIf { it.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")) } ?: invalid()
    }
    private fun number(value: JsonElement?): ULong {
        val text = text(value)
        if (!text.matches(Regex("0|[1-9][0-9]{0,19}"))) invalid()
        return text.toULongOrNull() ?: invalid()
    }
    private fun tooLarge(): Nothing = throw WebAccessDenied(413, "BODY_TOO_LARGE", "The workflow start exceeds its 4096-byte limit.")
    private fun invalid(): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED", "The workflow start must contain only the declared workflow, optional identities and unsigned limits.")
    private companion object { const val MAX_BODY = 4096 }
}
