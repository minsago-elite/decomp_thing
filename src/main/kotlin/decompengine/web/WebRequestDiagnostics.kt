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
    "UI_ASSET_NOT_FOUND", "UI_ASSET_UNAVAILABLE", "NOT_ACCEPTABLE", "STREAMS_DRAINING",
    "UPLOAD_PROGRESS_CAPACITY", "LISTING_UNAVAILABLE", "CORRUPT_WORKFLOW_STATE",
    // Storage/public projection codes are emitted by WebJobService and UploadServer too.
    "LEGACY_INTERRUPTED", "LEGACY_RECOVERY_REQUIRED", "PUBLICATION_PENDING", "RECOVERY_REQUIRED",
    "UPLOAD_STAGING_RECOVERY_REQUIRED", "STORE_LIMIT", "PERSISTENCE_FAILED", "SERVICE_NOT_INITIALIZED",
    "SERVICE_STOPPED", "PROGRESS_RETENTION_FAILED", "VERSION_CONFLICT", "PROGRESS_UNAVAILABLE",
    "STORAGE_ACCOUNTING_UNAVAILABLE", "INPUT_REVISION_UNAVAILABLE", "SHUTDOWN_INCOMPLETE",
)

private val diagnosticExecutor = java.util.concurrent.ThreadPoolExecutor(
    1, 1, 0L, java.util.concurrent.TimeUnit.MILLISECONDS,
    java.util.concurrent.ArrayBlockingQueue<Runnable>(256),
    { task -> Thread(task, "decomp-web-diagnostics").apply { isDaemon = true } },
    java.util.concurrent.ThreadPoolExecutor.DiscardPolicy(),
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
    val line = "web-http-failure request_id=$requestId status=$safeStatus code=$safeCode"
    // Queueing is bounded and nonblocking, so a stalled sink cannot delay the response.
    diagnosticExecutor.execute { try { output(line) } catch (_: Exception) { } }
}
