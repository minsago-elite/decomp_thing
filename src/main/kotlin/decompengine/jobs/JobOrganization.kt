package decompengine.jobs

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant

/**
 * Display-only organization of one job: an optional label and an archive flag. It is stored in
 * its own `organization.json`, never in `job.json`, so the original input, its metadata record,
 * workflow state and every report keep their exact bytes and hashes. Archiving hides a job from
 * the default library view; it is unrelated to source-archive export and removes nothing.
 */
data class JobOrganization(
    val label: String?,
    val archived: Boolean,
    internal val receipts: List<JobOrganizationReceipt> = emptyList(),
) {
    init {
        label?.let(::requireJobLabel)
        require(receipts.size <= MAX_RECEIPTS) { "too many organization receipts" }
    }
    val isDefault: Boolean get() = label == null && !archived

    /** Version contribution of the visible fields; receipts never affect a resource version. */
    fun digest(): String = organizationSha256("decomp-job-organization-v1\u0000${label ?: "\u0001"}\u0000$archived")

    internal fun toJson(): JsonObject = buildJsonObject {
        put("schemaVersion", 1)
        put("label", label?.let(::JsonPrimitive) ?: JsonNull)
        put("archived", archived)
        put("receipts", JsonArray(receipts.map { receipt -> buildJsonObject {
            put("keyDigest", receipt.keyDigest); put("requestDigest", receipt.requestDigest); put("at", receipt.at.toString())
        } }))
    }

    companion object {
        val DEFAULT = JobOrganization(null, false)
        const val FILE_NAME = "organization.json"
        const val MAX_LABEL_CHARACTERS = 120
        internal const val MAX_RECEIPTS = 64
        internal const val MAX_BYTES = 64 * 1024
        internal val RECEIPT_RETENTION: Duration = Duration.ofHours(24)
        internal val LIMITS = StrictJsonLimits(MAX_BYTES, MAX_BYTES, 4, 512, 4096, MAX_BYTES, 32)

        internal fun decode(bytes: ByteArray): JobOrganization {
            val value = OracleJson.parse(bytes, LIMITS).jsonObject
            require(value.keys == setOf("schemaVersion", "label", "archived", "receipts")) { "organization fields are invalid" }
            require(value.getValue("schemaVersion").jsonPrimitive.let { !it.isString && it.content == "1" }) { "unsupported organization schema" }
            val label = value.getValue("label").let { if (it == JsonNull) null else it.jsonPrimitive.also { p -> require(p.isString) }.content }
            val archived = value.getValue("archived").jsonPrimitive.let { require(!it.isString); requireNotNull(it.booleanOrNull) }
            val receipts = value.getValue("receipts").jsonArray.map { element ->
                val receipt = element.jsonObject
                require(receipt.keys == setOf("keyDigest", "requestDigest", "at"))
                fun text(name: String) = receipt.getValue(name).jsonPrimitive.also { require(it.isString) }.content
                JobOrganizationReceipt(text("keyDigest"), text("requestDigest"), Instant.parse(text("at")))
            }
            require(receipts.map { it.keyDigest }.toSet().size == receipts.size) { "duplicate organization receipt" }
            return JobOrganization(label, archived, receipts)
        }
    }
}

data class JobOrganizationReceipt internal constructor(val keyDigest: String, val requestDigest: String, val at: Instant) {
    init { require(keyDigest.matches(SHA256) && requestDigest.matches(SHA256)) { "invalid organization receipt digest" } }
}

/** One allowlisted change. Absent fields keep their current value; `label = null` clears it. */
data class JobOrganizationChange(val setLabel: Boolean, val label: String?, val archived: Boolean?) {
    init {
        require(setLabel || archived != null) { "an organization change needs at least one field" }
        require(setLabel || label == null)
        label?.let(::requireJobLabel)
    }
    fun applyTo(current: JobOrganization): JobOrganization =
        current.copy(label = if (setLabel) label else current.label, archived = archived ?: current.archived)
    fun canonical(): String = buildJsonObject {
        if (setLabel) put("label", label?.let(::JsonPrimitive) ?: JsonNull)
        archived?.let { put("archived", it) }
    }.toString()
}

/** A refusal that never changed storage, or a write whose durability could not be confirmed. */
class JobStorageWriteException(val applied: Boolean, cause: Throwable) : IOException(
    if (applied) "Job storage accepted a change but could not confirm durability" else "Job storage refused a change", cause)

internal class JobOrganizationReceiptCapacityException : IllegalStateException("organization receipt capacity")
internal class JobOrganizationKeyConflictException : IllegalStateException("organization key conflict")

/** Seam for disk-full and read-only fixtures; production writes use the atomic default. */
internal fun interface JobOrganizationWriter {
    @Throws(IOException::class)
    fun replace(jobDirectory: Path, bytes: ByteArray)
}

internal object AtomicJobOrganizationWriter : JobOrganizationWriter {
    override fun replace(jobDirectory: Path, bytes: ByteArray) {
        var renamed = false
        val temporary = try { Files.createTempFile(jobDirectory, ".job-metadata-", ".tmp") }
            catch (failure: IOException) { throw JobStorageWriteException(false, failure) }
        try {
            FileChannel.open(temporary, WRITE).use { channel ->
                val buffer = java.nio.ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) channel.write(buffer)
                channel.force(true)
            }
            Files.move(temporary, jobDirectory.resolve(JobOrganization.FILE_NAME), ATOMIC_MOVE, REPLACE_EXISTING)
            renamed = true
            FileChannel.open(jobDirectory, READ).use { it.force(true) }
        } catch (failure: IOException) {
            throw JobStorageWriteException(renamed, failure)
        } finally {
            try { Files.deleteIfExists(temporary) } catch (_: IOException) { }
        }
    }
}

/** Caller (the web service) serializes every call under its storage monitor. */
internal class JobOrganizationStore(
    private val root: Path,
    private val writer: JobOrganizationWriter = AtomicJobOrganizationWriter,
) {
    fun exists(jobId: String): Boolean = Files.exists(root.resolve(jobId).resolve(JobOrganization.FILE_NAME), NOFOLLOW_LINKS)

    /** A missing file is the default organization; an invalid one is surfaced, never silently reset. */
    fun read(jobId: String, read: (String, Int) -> ByteArray = { relative, maximum ->
        decompengine.repair.readStableRegularFile(root, relative, maximum.toLong()).bytes
    }): JobOrganization {
        requireJobIdentity(jobId)
        if (!exists(jobId)) return JobOrganization.DEFAULT
        val bytes = read("$jobId/${JobOrganization.FILE_NAME}", JobOrganization.MAX_BYTES)
        return try { JobOrganization.decode(bytes) } catch (failure: Exception) {
            throw WorkflowStoreException("JOB_RECORD_UNAVAILABLE", "The job organization record is invalid; preserve it before editing.", cause = failure)
        }
    }

    sealed interface Result {
        val organization: JobOrganization
        data class Applied(override val organization: JobOrganization) : Result
        data class Replayed(override val organization: JobOrganization) : Result
    }

    fun replay(jobId: String, keyDigest: String, requestDigest: String): Result.Replayed? {
        val current = read(jobId)
        val receipt = current.receipts.firstOrNull { it.keyDigest == keyDigest } ?: return null
        if (receipt.requestDigest != requestDigest) throw JobOrganizationKeyConflictException()
        return Result.Replayed(current)
    }

    /** Caller has already compared the public job version; this records the receipt atomically. */
    fun apply(jobId: String, change: JobOrganizationChange, keyDigest: String, requestDigest: String, now: Instant): Result {
        replay(jobId, keyDigest, requestDigest)?.let { return it }
        val current = read(jobId)
        var receipts = current.receipts
        if (receipts.size >= JobOrganization.MAX_RECEIPTS) {
            val oldest = receipts.minBy { it.at }
            if (Duration.between(oldest.at, now) < JobOrganization.RECEIPT_RETENTION) throw JobOrganizationReceiptCapacityException()
            receipts = receipts - oldest
        }
        val next = change.applyTo(current).copy(receipts = receipts + JobOrganizationReceipt(keyDigest, requestDigest, now))
        val bytes = OracleJson.canonicalBytes(next.toJson(), JobOrganization.LIMITS)
        val directory = root.resolve(jobId)
        if (!Files.isDirectory(directory, NOFOLLOW_LINKS)) throw WorkflowStoreException("JOB_NOT_FOUND", "The job storage directory is missing.")
        writer.replace(directory, bytes)
        return Result.Applied(next)
    }
}

internal fun requireJobLabel(label: String) {
    val points = label.codePointCount(0, label.length)
    require(points in 1..JobOrganization.MAX_LABEL_CHARACTERS) { "job label length is invalid" }
    require(label.isNotBlank() && label.trim() == label) { "job label must not be blank or padded" }
    require(label.none { it.code < 32 || it.code == 127 || it == ' ' || it == ' ' || it == '�' }) { "job label contains control characters" }
    require(label.indices.none { index -> label[index].isSurrogate() && !(label[index].isHighSurrogate() && index + 1 < label.length && label[index + 1].isLowSurrogate()) &&
        !(label[index].isLowSurrogate() && index > 0 && label[index - 1].isHighSurrogate()) }) { "job label is not valid Unicode" }
}

internal fun organizationSha256(value: String): String = MessageDigest.getInstance("SHA-256")
    .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

private val SHA256 = Regex("[0-9a-f]{64}")
private fun requireJobIdentity(jobId: String) { require(jobId.matches(Regex("[0-9a-f]{32}"))) { "invalid job identity" } }
