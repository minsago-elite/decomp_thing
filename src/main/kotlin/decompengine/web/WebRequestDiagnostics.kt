package decompengine.web

/** A request ID is the only connection between public failures and server diagnostics.
 * Never put a request target, header, rejected value, exception, or persisted message on this line.
 */
private val canonicalRequestId = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

private val publicErrorCodes = setOf(
    "ARTIFACT_CHANGED", "BODY_TOO_LARGE", "BOOTSTRAP_EXPIRED", "BOOTSTRAP_REQUIRED", "CSRF_DENIED",
    "CURSOR_EXPIRED", "EVENT_GAP", "FORWARDED_HEADERS_DENIED", "HOST_DENIED", "IDEMPOTENCY_CONFLICT",
    "INTERNAL_ERROR", "INVALID_CURSOR", "INVALID_ELF", "INVALID_HEADER", "INVALID_IDEMPOTENCY_KEY",
    "INVALID_REQUEST", "INVALID_STORAGE_ENTRY", "INVALID_UPLOAD", "INVALID_UPLOAD_ID", "JOB_NOT_FOUND",
    "JOB_RECORD_UNAVAILABLE", "JOB_STORAGE_UNAVAILABLE", "LISTING_BUSY", "LISTING_LIMIT", "MALFORMED_JSON",
    "METHOD_NOT_ALLOWED", "NOT_FOUND", "ORIGIN_DENIED", "PIN_RECEIPT_CAPACITY", "PRECONDITION_REQUIRED",
    "OPERATOR_INSPECTION_REJECTED", "OPERATOR_INSPECTION_UNAVAILABLE",
    "PROGRESS_UNAVAILABLE", "RECOVERY_REQUIRED", "REPORT_CHANGED", "RUN_NOT_FOUND", "SERVER_DRAINING",
    "SESSION_EXPIRED", "SESSION_LIMIT", "SESSION_REQUIRED", "STREAM_LIMIT", "UNSUPPORTED_HEADER",
    "UNSUPPORTED_MEDIA_TYPE", "UPLOAD_CAPACITY", "UPLOAD_ID_REUSED", "UPLOAD_RECEIPT_UNAVAILABLE",
    "UPLOAD_STORAGE", "UPLOAD_TOO_LARGE", "VALIDATION_FAILED", "VERSION_CONFLICT",
    "UI_ASSET_NOT_FOUND", "UI_ASSET_UNAVAILABLE",
)

internal fun recordWebRequestFailure(
    requestId: String,
    status: Int,
    code: String,
    output: (String) -> Unit,
) {
    if (!canonicalRequestId.matches(requestId)) return
    val safeStatus = status.takeIf { it in 400..599 } ?: 500
    val safeCode = code.takeIf(publicErrorCodes::contains) ?: "UNCLASSIFIED"
    // An output failure cannot replace or delay the fixed public HTTP response.
    try { output("web-http-failure request_id=$requestId status=$safeStatus code=$safeCode") }
    catch (_: Exception) { }
}
