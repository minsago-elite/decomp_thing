package decompengine.agent

/** Only application-owned classifications may cross into logs; peer/exception messages are omitted. */
internal fun safeAgentFailureDiagnostic(failure: AgentFailure): String = buildString {
    append(failure.kind.name.lowercase()).append(" retryable=").append(failure.retryable)
    failure.details["diagnosticCode"]?.takeIf { it in SAFE_AGENT_DIAGNOSTIC_CODES }?.let {
        append(" cause=").append(it)
    }
    for (key in listOf("httpStatus", "attempts")) {
        failure.details[key]?.takeIf { it.matches(Regex("[0-9]{1,3}")) }?.let {
            append(' ').append(key).append('=').append(it)
        }
    }
}

internal val SAFE_AGENT_DIAGNOSTIC_CODES = setOf(
    "connection-timeout", "connection-failed", "dns-failed", "tls-failed", "io-failed", "transport-failed",
    "interrupted", "rate-limited", "http-client-error", "http-server-error", "stream-incomplete",
    "stream-failed", "incompatible-media-type", "invalid-patch-json", "invalid-patch-set", "no-source-changes", "wall-deadline",
)
