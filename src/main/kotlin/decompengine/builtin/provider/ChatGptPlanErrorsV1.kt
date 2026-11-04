package decompengine.builtin.provider

import java.time.Instant
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.time.format.ResolverStyle
import java.util.Locale

internal enum class ChatGptRecoveryV1 { STOP, ONE_RENEWAL_IF_ELIGIBLE, BOUNDED_RETRY }
internal enum class ChatGptBodyShapeV1 { ERROR, DETAIL, OTHER, TRUNCATED }
internal enum class ChatGptSafeParamV1 { MODEL, INPUT, TOOLS, INCLUDE, STORE, STREAM, OTHER }
internal enum class ChatGptSafeCodeV1 {
    SUBSCRIPTION_SHARING_USER_NOT_ELIGIBLE,
    SUBSCRIPTION_SHARING_USAGE_LIMIT_EXCEEDED,
    SUBSCRIPTION_SHARING_USAGE_UNAVAILABLE,
    SUBSCRIPTION_SHARING_UNSUPPORTED_CAPABILITY,
    SUBSCRIPTION_SHARING_ROUTE_NOT_SUPPORTED,
    SUBSCRIPTION_SHARING_INVALID_USER,
    CHATPASS_V2_SCOPE_NOT_AUTHORIZED,
    CHATPASS_V2_INVALID_AUTHORIZATION_CONTEXT,
    SUBSCRIPTION_SHARING_USER_UNAVAILABLE,
    UNKNOWN,
}

internal class ChatGptSafeDiagnosticV1 private constructor(
    val kind: ModelFailureKind,
    val httpStatus: Int?,
    val shape: ChatGptBodyShapeV1,
    val code: ChatGptSafeCodeV1,
    val param: ChatGptSafeParamV1,
    val recovery: ChatGptRecoveryV1,
    val requestId: String?,
) {
    /** A fixed-field projection. Values are enums, bounded status, and a sanitized request ID only. */
    fun render(): String {
        val result = "kind=${kind.name};status=${httpStatus ?: "none"};shape=${shape.name};code=${code.wire()};param=${param.name};recovery=${recovery.name};request_id=${requestId ?: "none"}"
        check(result.toByteArray(Charsets.UTF_8).size <= 2048)
        return result
    }
    override fun toString() = "ChatGptSafeDiagnosticV1(redacted)"
    companion object {
        internal fun create(kind: ModelFailureKind, status: Int?, shape: ChatGptBodyShapeV1,
                            code: ChatGptSafeCodeV1, param: ChatGptSafeParamV1,
                            recovery: ChatGptRecoveryV1, requestId: String?): ChatGptSafeDiagnosticV1 {
            require(status == null || status in 100..599)
            return ChatGptSafeDiagnosticV1(kind, status, shape, code, param, recovery,
                requestId?.takeIf { it.matches(Regex("req_[A-Za-z0-9_-]{1,96}")) })
        }
    }
}

internal class ChatGptFailureDecisionV1(
    val kind: ModelFailureKind,
    val recovery: ChatGptRecoveryV1,
    val diagnostic: ChatGptSafeDiagnosticV1,
) { override fun toString() = "ChatGptFailureDecisionV1(redacted)" }

/** Validated metadata from an already bounded header block. Relevant duplicate headers fail closed. */
internal class ChatGptHeaderMetadataV1 private constructor(
    val requestId: String?,
    val retryAfterMinimumNanos: Long?,
    internal val retryAfterInvalid: Boolean,
) {
    override fun toString() = "ChatGptHeaderMetadataV1(redacted)"
    companion object {
        const val MAX_HEADER_BYTES = 16 * 1024
        const val MAX_FIELDS = 64
        const val MAX_NAME_BYTES = 128
        const val MAX_VALUE_BYTES = 4096
        private val REQUEST_ID = Regex("req_[A-Za-z0-9_-]{1,96}")
        private val IMF_FIXDATE = Regex("(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), [0-9]{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT")

        fun fromHeaders(fields: List<Pair<String, String>>, now: Instant): ChatGptHeaderMetadataV1 {
            if (fields.size > MAX_FIELDS) throw ModelProviderException(ModelFailureKind.RESOURCE_EXHAUSTED)
            var total = 0L
            val ids = ArrayList<String>()
            val retries = ArrayList<String>()
            for ((name, value) in fields) {
                if (name.length > MAX_NAME_BYTES || value.length > MAX_VALUE_BYTES) {
                    throw ModelProviderException(ModelFailureKind.RESOURCE_EXHAUSTED)
                }
                val nameBytes = name.toByteArray(Charsets.UTF_8).size
                val valueBytes = value.toByteArray(Charsets.UTF_8).size
                if (nameBytes > MAX_NAME_BYTES || valueBytes > MAX_VALUE_BYTES) throw ModelProviderException(ModelFailureKind.RESOURCE_EXHAUSTED)
                if (nameBytes == 0 || name.any { !isFieldToken(it) } ||
                    value.any { it.isISOControl() && it != '\t' }) {
                    throw ModelProviderException(ModelFailureKind.MALFORMED_RESPONSE)
                }
                total = try { Math.addExact(total, (nameBytes + valueBytes + 4).toLong()) }
                catch (_: ArithmeticException) { throw ModelProviderException(ModelFailureKind.RESOURCE_EXHAUSTED) }
                if (total > MAX_HEADER_BYTES) throw ModelProviderException(ModelFailureKind.RESOURCE_EXHAUSTED)
                when (name.lowercase(Locale.ROOT)) {
                    "x-request-id" -> ids.add(value.trim())
                    "retry-after" -> retries.add(value.trim())
                }
            }
            val id = ids.singleOrNull()?.takeIf { REQUEST_ID.matches(it) }
            if (retries.size > 1) return validated(id, null, retryAfterInvalid = true)
            if (retries.isEmpty()) return validated(id, null)
            val delay = parseRetryAfter(retries.single(), now)
            return validated(id, delay, retryAfterInvalid = delay == null)
        }

        fun validated(requestId: String?, retryAfterMinimumNanos: Long?, retryAfterInvalid: Boolean = false): ChatGptHeaderMetadataV1 {
            val delayInvalid = retryAfterMinimumNanos != null && retryAfterMinimumNanos < 0
            return ChatGptHeaderMetadataV1(
                requestId?.takeIf { REQUEST_ID.matches(it) },
                retryAfterMinimumNanos?.takeIf { it >= 0 },
                retryAfterInvalid || delayInvalid,
            )
        }

        private fun isFieldToken(c: Char): Boolean =
            c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c in "!#$%&'*+-.^_`|~"

        private fun parseRetryAfter(value: String, now: Instant): Long? {
            if (value.matches(Regex("[1-9][0-9]*"))) {
                val seconds = value.toLongOrNull() ?: return null
                return try { Math.multiplyExact(seconds, 1_000_000_000L) } catch (_: ArithmeticException) { null }
            }
            if (!IMF_FIXDATE.matches(value)) return null
            return try {
                val then = DateTimeFormatter.RFC_1123_DATE_TIME.withLocale(Locale.US).withResolverStyle(ResolverStyle.STRICT).parse(value, Instant::from)
                val nanos = java.time.Duration.between(now, then).toNanos()
                maxOf(0L, nanos)
            } catch (_: DateTimeParseException) { null }
            catch (_: ArithmeticException) { null }
        }
    }
}

internal object ChatGptPlanErrorsV1 {
    const val MAX_BODY_BYTES = 32 * 1024
    const val MAX_RETRY_DELAY_NANOS = 30_000_000_000L
    private val codes = mapOf(
        "subscription_sharing_user_not_eligible" to ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_USER_NOT_ELIGIBLE,
        "subscription_sharing_usage_limit_exceeded" to ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_USAGE_LIMIT_EXCEEDED,
        "subscription_sharing_usage_unavailable" to ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_USAGE_UNAVAILABLE,
        "subscription_sharing_unsupported_capability" to ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_UNSUPPORTED_CAPABILITY,
        "subscription_sharing_route_not_supported" to ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_ROUTE_NOT_SUPPORTED,
        "subscription_sharing_invalid_user" to ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_INVALID_USER,
        "chatpass_v2_scope_not_authorized" to ChatGptSafeCodeV1.CHATPASS_V2_SCOPE_NOT_AUTHORIZED,
        "chatpass_v2_invalid_authorization_context" to ChatGptSafeCodeV1.CHATPASS_V2_INVALID_AUTHORIZATION_CONTEXT,
        "subscription_sharing_user_unavailable" to ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_USER_UNAVAILABLE,
    )

    fun classify(status: Int, metadata: ChatGptHeaderMetadataV1, body: ByteArray,
                 truncated: Boolean, streamStarted: Boolean): ChatGptFailureDecisionV1 {
        require(status in 100..599)
        val parsed = if (truncated || body.size > MAX_BODY_BYTES) null else try {
            ChatGptPlanWireJsonV1.parse(body, MAX_BODY_BYTES)
        } catch (_: ChatGptWireJsonException) { null }
        val shape = when {
            truncated || body.size > MAX_BODY_BYTES || (body.isNotEmpty() && parsed == null) -> ChatGptBodyShapeV1.TRUNCATED
            parsed is ChatGptWireValueV1.Obj && parsed.fields.containsKey("error") && parsed.fields.containsKey("detail") -> ChatGptBodyShapeV1.OTHER
            parsed is ChatGptWireValueV1.Obj && parsed.fields["error"] is ChatGptWireValueV1.Obj -> ChatGptBodyShapeV1.ERROR
            parsed is ChatGptWireValueV1.Obj && parsed.fields.containsKey("detail") -> ChatGptBodyShapeV1.DETAIL
            else -> ChatGptBodyShapeV1.OTHER
        }
        val error = if (shape == ChatGptBodyShapeV1.ERROR) ((parsed as ChatGptWireValueV1.Obj).fields["error"] as ChatGptWireValueV1.Obj).fields else emptyMap()
        val rawCode = (error["code"] as? ChatGptWireValueV1.Str)?.value
        val code = rawCode?.let { codes[it] } ?: ChatGptSafeCodeV1.UNKNOWN
        val paramText = (error["param"] as? ChatGptWireValueV1.Str)?.value
        val param = when (paramText) {
            "model" -> ChatGptSafeParamV1.MODEL
            "input" -> ChatGptSafeParamV1.INPUT
            "tools" -> ChatGptSafeParamV1.TOOLS
            "include" -> ChatGptSafeParamV1.INCLUDE
            "store" -> ChatGptSafeParamV1.STORE
            "stream" -> ChatGptSafeParamV1.STREAM
            null -> ChatGptSafeParamV1.OTHER
            else -> ChatGptSafeParamV1.OTHER
        }

        var kind = statusKind(status)
        var recovery = statusRecovery(status)
        if (shape == ChatGptBodyShapeV1.ERROR && code != ChatGptSafeCodeV1.UNKNOWN) {
            when (code) {
                ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_USER_NOT_ELIGIBLE,
                ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_ROUTE_NOT_SUPPORTED,
                ChatGptSafeCodeV1.CHATPASS_V2_SCOPE_NOT_AUTHORIZED,
                ChatGptSafeCodeV1.CHATPASS_V2_INVALID_AUTHORIZATION_CONTEXT -> { kind = ModelFailureKind.AUTHORIZATION; recovery = ChatGptRecoveryV1.STOP }
                ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_USAGE_LIMIT_EXCEEDED -> { kind = ModelFailureKind.RATE_LIMIT; recovery = ChatGptRecoveryV1.STOP }
                ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_UNSUPPORTED_CAPABILITY -> { kind = ModelFailureKind.UNSUPPORTED_FEATURE; recovery = ChatGptRecoveryV1.STOP }
                ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_INVALID_USER -> { kind = ModelFailureKind.AUTHENTICATION; recovery = ChatGptRecoveryV1.ONE_RENEWAL_IF_ELIGIBLE }
                ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_USAGE_UNAVAILABLE,
                ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_USER_UNAVAILABLE -> {
                    kind = ModelFailureKind.TRANSPORT
                    recovery = if (status in setOf(408, 500, 502, 503, 504)) ChatGptRecoveryV1.BOUNDED_RETRY else statusRecovery(status)
                }
                ChatGptSafeCodeV1.UNKNOWN -> Unit
            }
        }
        if (metadata.retryAfterInvalid || (metadata.retryAfterMinimumNanos ?: 0L) > MAX_RETRY_DELAY_NANOS) {
            recovery = ChatGptRecoveryV1.STOP
        }
        if (streamStarted) recovery = ChatGptRecoveryV1.STOP
        val diagnostic = ChatGptSafeDiagnosticV1.create(kind, status, shape, code, param, recovery, metadata.requestId)
        return ChatGptFailureDecisionV1(kind, recovery, diagnostic)
    }

    fun retryAfterMinimumNanos(value: String, now: Instant): Long =
        ChatGptHeaderMetadataV1.fromHeaders(listOf("Retry-After" to value), now).retryAfterMinimumNanos
            ?: throw IllegalArgumentException("Invalid Retry-After")

    private fun statusKind(status: Int) = when (status) {
        401 -> ModelFailureKind.AUTHENTICATION
        403 -> ModelFailureKind.AUTHORIZATION
        429 -> ModelFailureKind.RATE_LIMIT
        408, 500, 502, 503, 504 -> ModelFailureKind.TRANSPORT
        else -> ModelFailureKind.INVALID_REQUEST
    }

    private fun statusRecovery(status: Int) = when (status) {
        401 -> ChatGptRecoveryV1.ONE_RENEWAL_IF_ELIGIBLE
        408, 500, 502, 503, 504 -> ChatGptRecoveryV1.BOUNDED_RETRY
        else -> ChatGptRecoveryV1.STOP
    }
}

private fun ChatGptSafeCodeV1.wire(): String = when (this) {
    ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_USER_NOT_ELIGIBLE -> "subscription_sharing_user_not_eligible"
    ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_USAGE_LIMIT_EXCEEDED -> "subscription_sharing_usage_limit_exceeded"
    ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_USAGE_UNAVAILABLE -> "subscription_sharing_usage_unavailable"
    ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_UNSUPPORTED_CAPABILITY -> "subscription_sharing_unsupported_capability"
    ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_ROUTE_NOT_SUPPORTED -> "subscription_sharing_route_not_supported"
    ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_INVALID_USER -> "subscription_sharing_invalid_user"
    ChatGptSafeCodeV1.CHATPASS_V2_SCOPE_NOT_AUTHORIZED -> "chatpass_v2_scope_not_authorized"
    ChatGptSafeCodeV1.CHATPASS_V2_INVALID_AUTHORIZATION_CONTEXT -> "chatpass_v2_invalid_authorization_context"
    ChatGptSafeCodeV1.SUBSCRIPTION_SHARING_USER_UNAVAILABLE -> "subscription_sharing_user_unavailable"
    ChatGptSafeCodeV1.UNKNOWN -> "unknown"
}
