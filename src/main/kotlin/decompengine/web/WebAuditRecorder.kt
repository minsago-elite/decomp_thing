package decompengine.web

import com.sun.net.httpserver.HttpExchange

/**
 * Records one audit entry around each sensitive HTTP action, including refused and failed
 * requests. Attribution, target identity and outcome come only from the authorization-owned
 * session, the canonical route and the response the server actually sent: request bodies,
 * filenames and header values other than strong versions are never inspected.
 */
internal class WebAuditRecorder(
    private val access: LocalWebAccess,
    private val log: WebAuditLog?,
) {
    /** Run [handle] and record its outcome when [action] names a sensitive action. */
    fun <T> around(exchange: HttpExchange, action: WebAuditAction?, target: WebAuditTarget, handle: () -> T): T {
        if (action == null || log == null) return handle()
        val before = try { access.auditSessionId(exchange) } catch (_: Exception) { null }
        WebDeniedResponseTrace.begin()
        var thrown = false
        try {
            return handle()
        } catch (failure: Throwable) {
            thrown = true
            throw failure
        } finally {
            // Auditing never changes the response or turns a handled request into a failure.
            try { record(exchange, action, target, before, thrown) } catch (_: Exception) { }
        }
    }

    private fun record(exchange: HttpExchange, action: WebAuditAction, target: WebAuditTarget, before: String?, thrown: Boolean) {
        val log = log ?: return
        run {
            val reason = WebDeniedResponseTrace.end()
            val sessionId = before ?: access.auditIssuedSessionId(exchange)
            val status = exchange.responseCode.takeIf { it in 100..599 } ?: 500
            val headers = exchange.responseHeaders
            val replayed = headers.getFirst("Idempotency-Replayed") == "true"
            val location = headers.getFirst("Location")?.let(::locationTarget)
            val outcome = if (thrown && status < 400) WebAuditOutcome.FAILED else WebAuditOutcome.of(status, replayed)
            log.record(
                actor = sessionId?.let(WebAuditActor::browserSession) ?: WebAuditActor.UNAUTHENTICATED,
                action = action,
                target = WebAuditTarget(
                    jobId = target.jobId ?: location?.first,
                    runId = target.runId ?: location?.second,
                    expectedVersion = strongVersion(exchange.requestHeaders["If-Match"]),
                    resultVersion = if (status < 400) strongVersion(headers["ETag"]) else null,
                ),
                outcome = outcome,
                status = status,
                reasonCode = reason ?: if (outcome == WebAuditOutcome.FAILED) "INTERNAL_ERROR" else null,
                requestId = headers.getFirst("X-Request-ID"),
            )
        }
    }

    private fun strongVersion(values: List<String>?): String? =
        values?.singleOrNull()?.takeIf { it.length in 3..130 && it.startsWith('"') && it.endsWith('"') }?.removeSurrounding("\"")

    private fun locationTarget(location: String): Pair<String?, String?>? {
        val match = LOCATION.find(location) ?: return null
        return match.groupValues[1] to match.groupValues[2].takeIf(String::isNotEmpty)
    }

    companion object {
        private val LOCATION = Regex("/(?:api/v1/)?jobs/([a-f0-9]{32})(?:/runs/([A-Za-z0-9][A-Za-z0-9_-]{0,127}))?$")
        private val JOB = Regex("[a-f0-9]{32}")
        private val RUN = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")

        /** Versioned routes relative to `api/v1/`. Unknown and read-only routes are not audited. */
        fun versionedAction(method: String, resource: String): Pair<WebAuditAction, WebAuditTarget>? {
            val parts = resource.split('/')
            fun job() = parts.getOrNull(1)?.takeIf(JOB::matches)
            fun run() = parts.getOrNull(3)?.takeIf(RUN::matches)
            val action = when {
                resource == "session" && method == "POST" -> WebAuditAction.SESSION_START
                resource == "session" && method == "DELETE" -> WebAuditAction.SESSION_END
                resource == "jobs" && method == "POST" -> WebAuditAction.JOB_UPLOAD
                resource == "agent/preflight" && method == "POST" -> WebAuditAction.AGENT_PREFLIGHT
                resource == "support-export" && method == "GET" -> WebAuditAction.SUPPORT_EXPORT
                parts.size == 2 && parts[0] == "jobs" && method == "PATCH" -> WebAuditAction.JOB_UPDATE
                parts.size == 2 && parts[0] == "jobs" && method == "DELETE" -> WebAuditAction.JOB_DELETE
                parts.size == 3 && parts[0] == "jobs" && parts[2] == "runs" && method == "POST" -> WebAuditAction.RUN_START
                parts.size == 5 && parts[0] == "jobs" && parts[2] == "runs" -> when {
                    parts[4] == "cancel" && method == "POST" -> WebAuditAction.RUN_CANCEL
                    parts[4] == "recover" && method == "POST" -> WebAuditAction.RUN_RECOVER
                    parts[4] == "progress-pin" && method == "PUT" -> WebAuditAction.PROGRESS_PIN
                    else -> null
                }
                else -> null
            } ?: return null
            return action to WebAuditTarget(jobId = job(), runId = if (parts.size >= 4) run() else null)
        }

        /** Legacy presentation mutations, by path segment. */
        fun legacyAction(method: String, segments: List<String>): Pair<WebAuditAction, WebAuditTarget>? {
            if (segments == listOf("api", "v1", "session")) return when (method) {
                "POST" -> WebAuditAction.SESSION_START to WebAuditTarget()
                "DELETE" -> WebAuditAction.SESSION_END to WebAuditTarget()
                else -> null
            }
            if (method != "POST") return null
            return when {
                segments == listOf("jobs") -> WebAuditAction.JOB_UPLOAD to WebAuditTarget()
                segments.size == 3 && segments[0] == "jobs" && segments[2] in setOf("explore", "reconstruct") ->
                    WebAuditAction.RUN_START to WebAuditTarget(jobId = segments[1].takeIf(JOB::matches))
                segments == listOf("api", "operator", "auth-methods") ->
                    WebAuditAction.OPERATOR_INSPECTION to WebAuditTarget()
                else -> null
            }
        }
    }
}

/** The public error code of the denial sent on this request thread, for audit outcome only. */
internal object WebDeniedResponseTrace {
    private val code = ThreadLocal<String?>()
    private val active = ThreadLocal<Boolean>()
    fun begin() { active.set(true); code.remove() }
    fun note(value: String) { if (active.get() == true) code.set(value) }
    fun end(): String? = code.get().also { code.remove(); active.remove() }
}
