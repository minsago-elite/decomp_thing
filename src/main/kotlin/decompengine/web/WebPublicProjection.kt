package decompengine.web

import decompengine.binary.ElfMetadata
import decompengine.jobs.Job
import decompengine.jobs.WorkflowStoreDiagnostic
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.MessageDigest

/**
 * The public job boundary is deliberately independent of the persistence serializer.
 * In particular, neither the response nor its opaque version depends on binary_path or
 * status_message. Those fields can contain host layout, environment values, and historical
 * exception text.
 */
private data class WebPublicJobProjection(
    val id: String,
    val filename: String,
    val status: String,
    val createdAt: String,
    val updatedAt: String,
    val sizeBytes: Int,
    val format: String,
    val endianness: String,
    val elfVersion: Long,
    val osAbi: String,
    val objectType: String,
    val machine: String,
    val entryPoint: ULong,
    val elfHeaderSize: Int,
    val programHeaderCount: Int,
    val sectionHeaderCount: Int,
    val sectionNameTableIndex: Int,
) {
    fun legacy(): JsonObject = buildJsonObject {
        put("id", id)
        put("filename", filename)
        put("status", status)
        put("created_at", createdAt)
        put("updated_at", updatedAt)
        put("size_bytes", sizeBytes)
        put("metadata", buildJsonObject {
            put("format", format)
            put("endianness", endianness)
            put("elf_version", elfVersion)
            put("os_abi", osAbi)
            put("object_type", objectType)
            put("machine", machine)
            put("entry_point", entryPoint.toLong())
            put("elf_header_size", elfHeaderSize)
            put("program_header_count", programHeaderCount)
            put("section_header_count", sectionHeaderCount)
            put("section_name_table_index", sectionNameTableIndex)
        })
    }

    fun versioned(): JsonObject {
        val publicFields = buildJsonObject {
            require(sizeBytes >= 0) { "Invalid stored job size" }
            put("jobId", id)
            put("displayFilename", filename.take(255))
            put("status", when (status) {
                "uploaded", "queued", "failed" -> status
                "analyzing" -> "running"
                "complete" -> "completed"
                else -> "unknown"
            })
            put("createdAt", createdAt)
            put("updatedAt", updatedAt)
            put("sizeBytes", sizeBytes.toString())
            put("binary", buildJsonObject {
                put("format", format)
                put("endianness", endianness)
                put("objectType", objectType)
                put("machine", machine)
                put("osAbi", osAbi)
                put("entryPoint", "0x${entryPoint.toString(16)}")
            })
            put("latestRunId", JsonNull)
            put("acceptedRevisionId", JsonNull)
        }
        return publicVersionedJob(publicFields)
    }

    companion object {
        fun from(job: Job): WebPublicJobProjection {
            val metadata = job.metadata
            requirePublicElfCategories(metadata)
            return WebPublicJobProjection(
                id = job.id,
                filename = job.filename,
                status = job.status,
                createdAt = job.createdAt,
                updatedAt = job.updatedAt,
                sizeBytes = job.sizeBytes,
                format = metadata.format,
                endianness = metadata.endianness,
                elfVersion = metadata.elfVersion.toLong(),
                osAbi = metadata.osAbi,
                objectType = metadata.objectType,
                machine = metadata.machine,
                entryPoint = metadata.entryPoint,
                elfHeaderSize = metadata.elfHeaderSize.toInt(),
                programHeaderCount = metadata.programHeaderCount.toInt(),
                sectionHeaderCount = metadata.sectionHeaderCount.toInt(),
                sectionNameTableIndex = metadata.sectionNameTableIndex.toInt(),
            )
        }
    }
}

/** Legacy names/types are compatibility only; the selected source fields are shared with v1. */
internal fun legacyJobPresentation(job: Job): JsonObject = WebPublicJobProjection.from(job).legacy()

internal fun webJob(job: Job): JsonObject = WebPublicJobProjection.from(job).versioned()

internal fun webJob(presentation: WebJobPresentation): JsonObject {
    val base = webJob(presentation.job)
    val snapshot = presentation.snapshot ?: return base
    val fields = base.toMutableMap()
    fields.remove("version")
    val latest = snapshot.latestRun
    if (latest != null) {
        fields["status"] = JsonPrimitive(if (latest.state == decompengine.jobs.WorkflowRunState.CANCELLING) "running" else latest.state.wireName)
        fields["latestRunId"] = JsonPrimitive(latest.runId)
        fields["acceptedRevisionId"] = snapshot.acceptedRevision?.revisionId?.let(::JsonPrimitive) ?: JsonNull
    } else if (presentation.legacyInterrupted) {
        fields["status"] = JsonPrimitive("interrupted")
    }
    val versioned = publicVersionedJob(JsonObject(fields))
    if (snapshot.attempts.isEmpty()) return versioned
    require(snapshot.version.matches(Regex("version_[a-f0-9]{32}"))) { "Invalid stored workflow version" }
    return JsonObject(versioned + ("version" to JsonPrimitive(snapshot.version)))
}

/** Only exact ElfMetadataReader output categories may cross the public job boundary. */
internal fun requirePublicElfCategories(metadata: ElfMetadata) {
    fun unknown(value: String, maximum: Int, known: Set<Int>): Boolean {
        val number = value.removePrefix("unknown(").removeSuffix(")")
        if (value != "unknown($number)" || !number.matches(Regex("0|[1-9][0-9]*"))) return false
        val parsed = number.toIntOrNull() ?: return false
        return parsed in 0..maximum && parsed !in known
    }
    require(metadata.format in setOf("ELF32", "ELF64") &&
        metadata.endianness in setOf("little", "big") &&
        (metadata.osAbi in setOf("System V", "Linux") || unknown(metadata.osAbi, 255, setOf(0, 3))) &&
        (metadata.objectType in setOf("relocatable", "executable", "shared", "core") ||
            unknown(metadata.objectType, 65535, setOf(1, 2, 3, 4))) &&
        (metadata.machine in setOf("x86", "ARM", "x86-64", "AArch64", "RISC-V") ||
            unknown(metadata.machine, 65535, setOf(3, 40, 62, 183, 243)))) {
        "Invalid stored ELF metadata"
    }
}

private fun publicVersionedJob(fields: JsonObject): JsonObject {
    val publicFields = JsonObject(fields - "version")
    val version = MessageDigest.getInstance("SHA-256")
        .digest(publicFields.toString().toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
    return JsonObject(publicFields + ("version" to JsonPrimitive(version)))
}

/**
 * Storage/service codes remain truthful and machine-readable when they are part of the public
 * vocabulary. An unrecognised persisted code is producer-controlled text, so it is collapsed to
 * the fixed storage-unavailable classification along with its message.
 */
internal fun publicWebDiagnosticCode(code: String): String = when (code) {
    "JOB_NOT_FOUND", "RUN_NOT_FOUND", "LEGACY_INTERRUPTED", "LEGACY_RECOVERY_REQUIRED",
    "PUBLICATION_PENDING", "RECOVERY_REQUIRED", "UPLOAD_STAGING_RECOVERY_REQUIRED",
    "CORRUPT_LEGACY_JOB", "CORRUPT_WORKFLOW_STATE", "INVALID_STORAGE_ENTRY",
    "JOB_RECORD_UNAVAILABLE", "STORE_LIMIT", "LISTING_UNAVAILABLE", "PERSISTENCE_FAILED",
    "SERVICE_NOT_INITIALIZED", "SERVICE_STOPPED", "PROGRESS_UNAVAILABLE",
    "PROGRESS_RETENTION_FAILED", "VERSION_CONFLICT", "IDEMPOTENCY_CONFLICT",
    "PIN_RECEIPT_CAPACITY", "UPLOAD_CAPACITY", "UPLOAD_STORAGE",
    "STORAGE_ACCOUNTING_UNAVAILABLE", "INPUT_REVISION_UNAVAILABLE", "SHUTDOWN_INCOMPLETE",
    "REPORT_CHANGED", "ARTIFACT_CHANGED", "JOB_STORAGE_UNAVAILABLE" -> code
    else -> "JOB_STORAGE_UNAVAILABLE"
}

internal fun publicWebDiagnosticMessage(code: String): String = when (publicWebDiagnosticCode(code)) {
    "JOB_NOT_FOUND" -> "The requested job is unavailable."
    "RUN_NOT_FOUND" -> "The requested attempt does not belong to this job."
    "LEGACY_INTERRUPTED" -> "Historical legacy work was interrupted; its workflow identity is unknown."
    "LEGACY_RECOVERY_REQUIRED" -> "The historical operation has no workflow identity. Run startup recovery before requesting new work."
    "PUBLICATION_PENDING" -> "Completed candidate output awaits canonical publication review; it is not accepted evidence."
    "RECOVERY_REQUIRED", "UPLOAD_STAGING_RECOVERY_REQUIRED" ->
        "Storage recovery is required. Preserve the job and reopen storage before retrying."
    "CORRUPT_LEGACY_JOB", "CORRUPT_WORKFLOW_STATE", "INVALID_STORAGE_ENTRY", "JOB_RECORD_UNAVAILABLE" ->
        "The job record is unavailable or invalid. Preserve its storage and restore a verified backup before retrying."
    "STORE_LIMIT", "LISTING_UNAVAILABLE" ->
        "Job storage exceeds a configured inspection limit. Inspect storage before retrying."
    "PERSISTENCE_FAILED" -> "The requested state change could not be published. Refresh before retrying."
    "SERVICE_NOT_INITIALIZED" -> "Job storage is not initialized for reads."
    "SERVICE_STOPPED" -> "The job service is stopping or stopped."
    "PROGRESS_UNAVAILABLE" ->
        "The retained progress journal is unavailable. Missing data does not establish an empty history."
    "PROGRESS_RETENTION_FAILED" -> "Progress retention did not finish. Preserve the journal before retrying maintenance."
    "VERSION_CONFLICT" -> "The selected resource version changed. Refresh before retrying."
    "IDEMPOTENCY_CONFLICT" -> "The request key was already used for different input."
    "PIN_RECEIPT_CAPACITY" -> "Pin request history is at capacity. Reconcile the current policy before retrying."
    "UPLOAD_CAPACITY" -> "Upload capacity is temporarily unavailable. Retry shortly."
    "UPLOAD_STORAGE", "STORAGE_ACCOUNTING_UNAVAILABLE" ->
        "Upload storage cannot be measured or reserved safely. Inspect storage before retrying."
    "INPUT_REVISION_UNAVAILABLE" -> "The selected input revision is unavailable for this job."
    "SHUTDOWN_INCOMPLETE" -> "Owned work has not stopped; storage remains unavailable until it exits."
    "REPORT_CHANGED" -> "The attempt changed during this read. Refresh its evidence."
    "ARTIFACT_CHANGED" -> "The report changed during this read. Refresh its evidence before downloading."
    else -> "Job storage is unavailable. Inspect storage before retrying."
}

internal fun publicWebDiagnostic(jobId: String, code: String): WebJobDiagnostic =
    WebJobDiagnostic(jobId, publicWebDiagnosticCode(code), publicWebDiagnosticMessage(code))

internal fun publicWorkflowDiagnostic(code: String): WorkflowStoreDiagnostic =
    WorkflowStoreDiagnostic(publicWebDiagnosticCode(code), publicWebDiagnosticMessage(code))
