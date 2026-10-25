package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.jobs.JobDeletionOperation
import decompengine.jobs.JobDeletionState
import decompengine.jobs.JobOrganization
import decompengine.jobs.JobOrganizationChange
import decompengine.jobs.StorageBreakdown
import decompengine.jobs.StorageCategory
import decompengine.jobs.StorageScan
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.MessageDigest
import java.time.Instant

/**
 * A read-only reason a job must be retained, contributed by another subsystem. Git workspaces
 * are not implemented yet; when they are, a repository/worktree adapter registers a hold that
 * reports uncommitted, unpushed or in-progress Git work so deletion and maintenance refuse to
 * discard it (#509). An implementation must be fast and side-effect free; throwing fails closed.
 */
fun interface JobRetentionHold {
    fun holds(jobId: String): List<JobRetentionHoldReason>
}

data class JobRetentionHoldReason(val source: String, val code: String, val message: String) {
    init {
        require(source.matches(Regex("[a-z][a-z0-9-]{0,47}"))) { "invalid retention hold source" }
        require(code.matches(Regex("[A-Z][A-Z0-9_]{0,63}"))) { "invalid retention hold code" }
        require(message.length in 1..200 && message.none { it.code < 32 || it.code == 127 }) { "invalid retention hold message" }
    }
}

/** One explicit protection. Each carries recovery guidance shown verbatim by clients. */
internal data class WebRetentionProtection(val code: String, val source: String, val message: String) {
    companion object {
        val ACTIVE_ATTEMPT = WebRetentionProtection("ACTIVE_ATTEMPT", "workflow",
            "A workflow attempt is queued, running or cancelling. Cancel it and wait until it reaches a final state.")
        val OWNED_WORKER = WebRetentionProtection("OWNED_WORKER", "workflow",
            "A worker still owns this job's files. Wait until it exits, then review the job again.")
        val PUBLICATION_PENDING = WebRetentionProtection("PUBLICATION_PENDING", "workflow",
            "Completed candidate output still awaits canonical publication review.")
        val PINNED_EVIDENCE = WebRetentionProtection("PINNED_EVIDENCE", "retention-pin",
            "At least one attempt's progress history is pinned. Unpin it on the attempt page before deleting.")
        val DOWNLOAD_IN_PROGRESS = WebRetentionProtection("DOWNLOAD_IN_PROGRESS", "download",
            "A download from this job is still being delivered. Wait for it to finish.")
        val STORAGE_BUSY = WebRetentionProtection("STORAGE_BUSY", "storage",
            "An upload is measuring or writing storage. Retry when it finishes.")
        val RECOVERY_REQUIRED = WebRetentionProtection("RECOVERY_REQUIRED", "storage",
            "Storage recovery is required. Restart the server to reconcile storage before deleting.")
        val HOLD_UNAVAILABLE = WebRetentionProtection("RETENTION_HOLD_UNAVAILABLE", "retention-hold",
            "A registered retention hold could not be checked, so the job is retained.")
        fun hold(reason: JobRetentionHoldReason) = WebRetentionProtection(reason.code, reason.source, reason.message)
    }
}

internal class WebJobRetentionConflict(val protections: List<WebRetentionProtection>) :
    RuntimeException("The job is protected by its retention policy.")

internal data class WebJobDeletionAdmission(val operation: JobDeletionOperation, val replayed: Boolean)

internal data class WebJobDeletionPreview(
    val presentation: WebJobPresentation, val version: String, val storage: StorageBreakdown,
    val storageComplete: Boolean, val protections: List<WebRetentionProtection>,
)

internal data class WebStorageSummary(val scan: StorageScan, val pendingDeletions: Int, val sampledAt: Instant)
internal data class WebMaintenanceAction(val action: String, val jobId: String?, val runId: String?, val bytes: Long, val schedule: String)
internal data class WebMaintenancePreview(
    val sampledAt: Instant, val complete: Boolean, val periodic: Boolean,
    val actions: List<WebMaintenanceAction>, val protectedJobs: List<Pair<String, List<WebRetentionProtection>>>,
)

internal fun lifecycleDigest(value: String): String = MessageDigest.getInstance("SHA-256")
    .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

internal const val JOB_DELETION_TOMBSTONE_MS = "86400000"

internal fun webStorageCategories(storage: StorageBreakdown): JsonObject = buildJsonObject {
    for (category in StorageCategory.entries) put(category.wireName, buildJsonObject {
        val tally = storage.categories[category] ?: decompengine.jobs.StorageTally()
        put("bytes", tally.bytes.toString()); put("entries", tally.entries.toString())
    })
}

private fun webProtections(protections: List<WebRetentionProtection>) = JsonArray(protections.map { protection ->
    buildJsonObject { put("code", protection.code); put("source", protection.source); put("message", protection.message) }
})

internal fun webOperation(operation: JobDeletionOperation): JsonObject = buildJsonObject {
    put("operationId", operation.operationId)
    put("jobId", operation.jobId)
    put("repositoryId", JsonNull); put("worktreeId", JsonNull)
    put("action", "job.delete")
    put("state", operation.state.wireName)
    put("version", "opv${operation.revision}_${operation.operationId.removePrefix("jobdel_")}")
    put("createdAt", operation.createdAt.toString())
    put("endedAt", operation.endedAt?.toString()?.let(::JsonPrimitive) ?: JsonNull)
    put("resultObjectId", JsonNull)
    put("recoveryRequired", operation.failureCode == "CLEANUP_CONTAINMENT")
    put("message", when (operation.state) {
        JobDeletionState.ACCEPTED -> "Deletion is recorded and waiting to remove the job."
        JobDeletionState.RUNNING -> "The job is removed from the library. Its stored files are being purged; cleanup resumes after a restart."
        JobDeletionState.COMPLETED -> "The job and its stored files were permanently deleted (${operation.removedBytes} bytes in " +
            "${operation.removedEntries} entries). This cannot be undone; only this deletion record is retained."
        JobDeletionState.FAILED -> when (operation.failureCode) {
            "INTERRUPTED_BEFORE_REMOVAL" -> "Deletion was interrupted before the job was removed. The job is retained unchanged; review it and delete again if needed."
            "CLEANUP_CONTAINMENT" -> "The job was removed from the library, but cleanup stopped at an entry outside its owned storage (a mount, link target or foreign file). Remaining bytes were preserved; inspect storage."
            else -> "Storage is full, read-only or unavailable. The job was not removed and is retained unchanged."
        }
    })
}

internal fun webDeletionPreview(preview: WebJobDeletionPreview): JsonObject {
    val job = webJob(preview.presentation)
    val attempts = preview.presentation.snapshot?.attempts.orEmpty()
    return buildJsonObject {
        put("jobId", preview.presentation.job.id)
        put("version", preview.version)
        put("displayFilename", job.getValue("displayFilename"))
        put("label", job.getValue("label"))
        put("attemptCount", attempts.size.toString())
        put("pinnedAttemptCount", attempts.count { it.progressRetentionPinned }.toString())
        put("storage", webStorageCategories(preview.storage))
        put("totalBytes", preview.storage.total.bytes.toString())
        put("storageComplete", preview.storageComplete)
        put("protections", webProtections(preview.protections))
        put("deletable", preview.protections.isEmpty())
        put("finality", "permanent")
        put("undoAvailable", false)
        put("tombstoneRetentionMs", JOB_DELETION_TOMBSTONE_MS)
    }
}

internal fun webStorageSummary(summary: WebStorageSummary): JsonObject = buildJsonObject {
    val scan = summary.scan
    put("sampledAt", summary.sampledAt.toString())
    put("accounting", "logical-bytes")
    put("complete", scan.complete)
    put("scannedEntries", scan.scannedEntries.toString())
    put("uninspectedEntries", scan.uninspectedEntries.toString())
    put("jobCount", scan.jobs.size.toString())
    put("categories", webStorageCategories(scan.library))
    put("totalBytes", scan.library.total.bytes.toString())
    put("pendingDeletions", summary.pendingDeletions.toString())
    put("pendingDeletionBytes", scan.pendingDeletions.values.sumOf { it.bytes }.toString())
}

internal fun webMaintenancePreview(preview: WebMaintenancePreview): JsonObject = buildJsonObject {
    val actions = preview.actions.take(200)
    val protectedJobs = preview.protectedJobs.take(200)
    put("sampledAt", preview.sampledAt.toString())
    put("dryRun", true)
    put("complete", preview.complete)
    put("policy", buildJsonObject {
        put("automaticJobDeletion", false)
        put("periodicMaintenance", preview.periodic)
        put("terminalProgressRetentionMs", decompengine.jobs.AgentProgressJournalRetention.DEFAULT_TERMINAL_RETENTION.toMillis().toString())
        put("deletionTombstoneRetentionMs", JOB_DELETION_TOMBSTONE_MS)
    })
    put("actions", JsonArray(actions.map { action -> buildJsonObject {
        put("action", action.action)
        put("jobId", action.jobId?.let(::JsonPrimitive) ?: JsonNull)
        put("runId", action.runId?.let(::JsonPrimitive) ?: JsonNull)
        put("bytes", action.bytes.toString())
        put("schedule", action.schedule)
    } }))
    put("omittedActions", (preview.actions.size - actions.size).toString())
    put("affectedJobs", preview.actions.mapNotNull { it.jobId }.toSet().size.toString())
    put("reclaimableBytes", preview.actions.sumOf { it.bytes }.toString())
    put("protectedJobs", JsonArray(protectedJobs.map { (jobId, protections) -> buildJsonObject {
        put("jobId", jobId); put("protections", webProtections(protections))
    } }))
    put("omittedProtectedJobs", (preview.protectedJobs.size - protectedJobs.size).toString())
}

/**
 * PATCH/DELETE J, deletion preview, deletion operations and storage reads. Every mutation uses the
 * shared session/Origin/JSON/CSRF boundary before reading a body, requires one strong If-Match and
 * one idempotency key, and derives its actor only from the authorized session.
 */
internal class WebJobLifecycleController(
    private val access: LocalWebAccess,
    private val jobs: WebJobService,
    private val jobMutations: WebJobMutationBoundary,
    private val basePath: String,
    private val invalidateCollections: () -> Unit,
) {
    fun patch(exchange: HttpExchange, jobId: String) {
        val mutation = jobMutations.authorizeJobOrganization(exchange)
        requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
        requireJobIdentity(jobId)
        val (match, key) = guards(exchange, "An organization change")
        val change = readOrganizationChange(exchange)
        val (presentation, replayed) = try { mutation.request(jobId, match, change, key) } catch (failure: WebJobServiceException) {
            throw lifecycleFailure(failure)
        }
        val value = webJob(presentation)
        exchange.responseHeaders.set("ETag", "\"${(value.getValue("version") as JsonPrimitive).content}\"")
        if (replayed) exchange.responseHeaders.set("Idempotency-Replayed", "true")
        sendWebApiResponse(exchange, 200, "job", value)
    }

    fun delete(exchange: HttpExchange, jobId: String) {
        val mutation = jobMutations.authorizeJobDeletion(exchange)
        requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
        requireJobIdentity(jobId)
        val (match, key) = guards(exchange, "Deleting a job")
        val confirmed = readDeletion(exchange)
        if (confirmed != jobId) throw WebAccessDenied(422, "VALIDATION_FAILED", "Confirm deletion with this job's exact identity.",
            details = listOf(WebErrorDetail("/confirmJobId", "CONFIRMATION_MISMATCH", "The confirmation does not name this job.")))
        val admission = try { mutation.request(jobId, match, key) } catch (failure: WebJobServiceException) {
            throw lifecycleFailure(failure)
        } catch (conflict: WebJobRetentionConflict) {
            throw WebAccessDenied(409, "RETENTION_PROTECTED", "This job is protected by its retention policy. Resolve each listed reason, then review it again.",
                details = conflict.protections.mapIndexed { index, protection ->
                    WebErrorDetail("/protections/$index", protection.code, protection.message)
                })
        }
        invalidateCollections()
        // The purge is bounded; an unfinished pass stays running and resumes during maintenance or restart.
        val operation = if (admission.replayed) admission.operation else jobs.continueJobDeletion(admission.operation)
        exchange.responseHeaders.set("Location", "${basePath}api/v1/jobs/$jobId/operations/${operation.operationId}")
        if (admission.replayed) exchange.responseHeaders.set("Idempotency-Replayed", "true")
        sendWebApiResponse(exchange, 202, "operation", webOperation(if (admission.replayed) jobs.jobDeletionOperation(jobId, operation.operationId) else operation))
    }

    fun operation(exchange: HttpExchange, jobId: String, operationId: String) {
        access.authorize(exchange, WebEndpointPolicy.privateRead())
        requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
        requireJobIdentity(jobId)
        if (!JobDeletionOperation.OPERATION_ID.matches(operationId)) throw WebAccessDenied(404, "NOT_FOUND", "The requested operation is unavailable.")
        val operation = jobs.jobDeletionOperation(jobId, operationId)
        sendWebApiResponse(exchange, 200, "operation", webOperation(operation))
    }

    fun deletionPreview(exchange: HttpExchange, jobId: String) {
        access.authorize(exchange, WebEndpointPolicy.privateRead())
        requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
        requireJobIdentity(jobId)
        val preview = try { jobs.jobDeletionPreview(jobId) } catch (failure: WebJobServiceException) { throw lifecycleFailure(failure) }
        sendWebApiResponse(exchange, 200, "jobDeletionPreview", webDeletionPreview(preview))
    }

    fun storage(exchange: HttpExchange, maintenance: Boolean) {
        access.authorize(exchange, WebEndpointPolicy.privateRead())
        requireNoWebApiQuery(exchange); requireJsonAccept(exchange)
        if (maintenance) sendWebApiResponse(exchange, 200, "maintenancePreview", webMaintenancePreview(jobs.maintenancePreview()))
        else sendWebApiResponse(exchange, 200, "storageSummary", webStorageSummary(jobs.storageSummary()))
    }

    private fun requireJobIdentity(jobId: String) {
        if (!jobId.matches(Regex("[0-9a-f]{32}"))) throw WebAccessDenied(404, "NOT_FOUND", "The requested job is unavailable.")
    }

    private fun lifecycleFailure(failure: WebJobServiceException): Exception = when (failure.code) {
        "VERSION_CONFLICT" -> WebAccessDenied(412, failure.code, "The job changed. Read it again before choosing another change.")
        "IDEMPOTENCY_CONFLICT" -> WebAccessDenied(409, failure.code, "The request key was used for a different change.")
        "JOB_DELETED" -> WebAccessDenied(410, "RESOURCE_GONE", "This job was deleted. Only its deletion record is retained.")
        "ORGANIZATION_RECEIPT_CAPACITY", "DELETION_CAPACITY" -> WebAccessDenied(429, failure.code, failure.message ?: "Request history is at capacity.")
        "STORAGE_UNAVAILABLE" -> WebAccessDenied(503, failure.code, failure.message ?: "Storage is unavailable.")
        "STORAGE_UNCONFIRMED" -> WebAccessDenied(503, failure.code, failure.message ?: "The change could not be confirmed.")
        else -> failure
    }

    private fun guards(exchange: HttpExchange, action: String): Pair<String, String> {
        val match = header(exchange, "If-Match")
            ?: throw WebAccessDenied(428, "PRECONDITION_REQUIRED", "$action requires the current job version in If-Match.")
        if (!match.matches(Regex("\"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\""))) {
            throw WebAccessDenied(400, "INVALID_HEADER", "If-Match must contain one strong job version.")
        }
        val key = header(exchange, "Idempotency-Key")
        if (key == null || !key.matches(Regex("[A-Za-z0-9_-]{16,128}"))) {
            throw WebAccessDenied(400, "INVALID_IDEMPOTENCY_KEY", "$action requires one bounded idempotency key.")
        }
        if (exchange.requestHeaders.keys.any { it.startsWith("If-", true) && !it.equals("If-Match", true) }) {
            throw WebAccessDenied(400, "UNSUPPORTED_HEADER", "Only If-Match is supported for this change.")
        }
        return match.removeSurrounding("\"") to key
    }

    private fun header(exchange: HttpExchange, name: String): String? {
        val values = exchange.requestHeaders[name] ?: return null
        if (values.size != 1 || values.single().length > 256 || values.single().any { it.code < 32 || it.code == 127 }) {
            throw WebAccessDenied(400, "INVALID_HEADER", "The request contains an invalid or repeated header.")
        }
        return values.single()
    }

    private fun readObject(exchange: HttpExchange): JsonObject {
        val length = header(exchange, "Content-Length")
        if (length != null && (!length.matches(Regex("0|[1-9][0-9]{0,18}")) || length.toLongOrNull() == null)) {
            throw WebAccessDenied(400, "INVALID_HEADER", "The request length is invalid.")
        }
        if (length != null && length.toLong() > MAX_BODY) throw WebAccessDenied(413, "BODY_TOO_LARGE", "The request exceeds its byte limit.")
        val bytes = exchange.requestBody.use { it.readNBytes(MAX_BODY + 1) }
        if (bytes.size > MAX_BODY) throw WebAccessDenied(413, "BODY_TOO_LARGE", "The request exceeds its byte limit.")
        val value = try { OracleJson.parse(bytes, StrictJsonLimits(MAX_BODY, MAX_BODY, 4, 16, 1024, MAX_BODY, 32)) }
            catch (_: Exception) { throw WebAccessDenied(400, "MALFORMED_JSON", "The request must be a bounded strict JSON object.") }
        return value as? JsonObject ?: throw WebAccessDenied(400, "VALIDATION_FAILED", "The request must be a JSON object.")
    }

    private fun readOrganizationChange(exchange: HttpExchange): JobOrganizationChange {
        val body = readObject(exchange)
        fun invalid(pointer: String, message: String): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED", message,
            details = listOf(WebErrorDetail(pointer, "INVALID_FIELD", message)))
        if (body.isEmpty() || !setOf("label", "archived").containsAll(body.keys)) {
            throw WebAccessDenied(400, "VALIDATION_FAILED", "An organization change may contain only label and archived.")
        }
        val setLabel = "label" in body
        val label = body["label"]?.let { value ->
            if (value == JsonNull) null else (value as? JsonPrimitive)?.takeIf { it.isString }?.content
                ?: invalid("/label", "The label must be a string or null.")
        }
        if (label != null) try { decompengine.jobs.requireJobLabel(label) } catch (_: IllegalArgumentException) {
            invalid("/label", "Use 1–${JobOrganization.MAX_LABEL_CHARACTERS} printable characters without surrounding spaces.")
        }
        val archived = body["archived"]?.let { value ->
            (value as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull ?: invalid("/archived", "archived must be a boolean.")
        }
        return JobOrganizationChange(setLabel, label, archived)
    }

    private fun readDeletion(exchange: HttpExchange): String {
        val body = readObject(exchange)
        val confirm = (body.takeIf { it.keys == setOf("confirmJobId") }?.get("confirmJobId") as? JsonPrimitive)?.takeIf { it.isString }?.content
        return confirm ?: throw WebAccessDenied(400, "VALIDATION_FAILED", "A deletion request contains only confirmJobId.")
    }

    private companion object { const val MAX_BODY = 4096 }
}
