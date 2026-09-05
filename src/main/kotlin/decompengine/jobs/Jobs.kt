package decompengine.jobs

import decompengine.binary.ElfMetadata
import decompengine.binary.ElfMetadataReader
import decompengine.binary.InvalidElfException
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.core.StrictJsonException
import decompengine.repair.StableRegularFile
import decompengine.repair.readStableRegularFile
import java.io.IOException
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.nio.file.Path
import java.nio.file.Files
import java.time.Instant
import java.util.UUID
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.name
import kotlin.io.path.isRegularFile

class JobStoreException(message: String) : RuntimeException(message)
internal class JobRecoveryCancelledException(val statusUpdatesStarted: Boolean) : IllegalStateException(
    if (statusUpdatesStarted) "Job recovery cancelled after status publication began; some statuses may have changed"
    else "Job recovery cancelled before status publication; no recovery statuses were changed",
)
class InvalidUploadException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

data class Job(
    val id: String,
    val filename: String,
    val status: String,
    val createdAt: String,
    val updatedAt: String = createdAt,
    val statusMessage: String? = null,
    val sizeBytes: Int,
    val binaryPath: Path,
    val metadata: ElfMetadata,
) {
    fun toJson(): JsonObject = buildJsonObject {
        put("id", id)
        put("filename", filename)
        put("status", status)
        put("created_at", createdAt)
        put("updated_at", updatedAt)
        statusMessage?.let { put("status_message", it) }
        put("size_bytes", sizeBytes)
        put("binary_path", binaryPath.toString())
        put("metadata", metadata.toJson())
    }
}

class JobStore internal constructor(
    root: Path,
    private val uploadPublisher: UploadPublisher,
    private val metadataPublisher: JobMetadataPublisher = AtomicJobMetadataPublisher,
    private val storeDirectories: JobStoreDirectories = ForcedJobStoreDirectories,
) {
    constructor(root: Path) : this(root, AtomicUploadPublisher)
    private val root = root.toAbsolutePath().normalize()
    internal val storageRoot: Path get() = root

    /** Bounded identities only; malformed records are inspected separately instead of disappearing. */
    internal fun jobIds(): List<String> {
        if (!Files.exists(root, java.nio.file.LinkOption.NOFOLLOW_LINKS)) return emptyList()
        if (!Files.isDirectory(root, java.nio.file.LinkOption.NOFOLLOW_LINKS)) throw JobStoreException("job storage is not a directory")
        val ids = mutableListOf<String>()
        Files.newDirectoryStream(root).use { entries ->
            for (entry in entries) if (entry.fileName.toString().matches(Regex("[a-f0-9]{32}"))) {
                if (ids.size >= 10_000) throw JobStoreException("job storage exceeds its listing limit")
                ids += entry.fileName.toString()
            }
        }
        return ids.sorted()
    }

    @Synchronized
    fun createFromUpload(filename: String, content: ByteArray): Job {
        require(content.size <= MAX_INPUT_BYTES) { "upload exceeds the 32 MiB input limit" }
        val input = content.copyOf()
        val metadata = try {
            ElfMetadataReader.read(input)
        } catch (exception: InvalidElfException) {
            throw InvalidUploadException(exception.message ?: "uploaded file is not an ELF binary", exception)
        }

        storeDirectories.prepare(root)
        val jobId = UUID.randomUUID().toString().replace("-", "")
        val jobDir = root.resolve(jobId)
        val binaryPath = jobDir.resolve("input.elf")
        val job = Job(
            id = jobId,
            filename = Path.of(filename).name.ifBlank { "input.elf" },
            status = "uploaded",
            createdAt = Instant.now().toString(),
            sizeBytes = input.size,
            binaryPath = binaryPath,
            metadata = metadata,
        )
        requireStatusUpdateHeadroom(job)
        val staging = Files.createTempDirectory(root, ".upload-")
        var publicationAttempted = false
        try {
            val stagedInput = staging.resolve("input.elf")
            uploadPublisher.writeAndForceInput(stagedInput, input)
            persist(job, staging)
            publicationAttempted = true
            uploadPublisher.publish(staging, jobDir)
            uploadPublisher.confirmDirectory(root)
            return job
        } catch (failure: Exception) {
            try {
                Files.deleteIfExists(staging.resolve("input.elf"))
                Files.deleteIfExists(staging.resolve("job.json"))
                Files.deleteIfExists(staging)
            } catch (cleanup: Exception) {
                failure.addSuppressed(cleanup)
            }
            if (publicationAttempted) throw UploadPublicationUncertainException(job.id, failure)
            throw failure
        }
    }

    @Synchronized
    fun get(jobId: String): Job {
        jobDirectory(jobId)
        val payload = try {
            OracleJson.parse(readStableRegularFile(root, "$jobId/job.json", MAX_METADATA_BYTES.toLong()).bytes).jsonObject
        } catch (_: IOException) {
            throw JobStoreException("job metadata is unavailable or its path changed")
        }
        return decodeJobRecord(jobId, payload)
    }

    private fun decodeJob(jobId: String, bytes: ByteArray): Job = decodeJobRecord(jobId, OracleJson.parse(bytes).jsonObject)

    internal fun decodeJobRecord(jobId: String, payload: JsonObject): Job {
        val jobDir = jobDirectory(jobId)
        require(payload.keys.all { it in setOf("id", "filename", "status", "created_at", "updated_at",
            "status_message", "size_bytes", "binary_path", "metadata") }) { "job metadata has unsupported fields" }
        require(payload.string("status") in VALID_STATUSES) { "job metadata has an invalid status" }
        require(payload.int("size_bytes") in 0..MAX_INPUT_BYTES) { "job metadata has an invalid input size" }
        require(payload.string("id") == jobId &&
            Path.of(payload.string("binary_path")) == jobDir.resolve("input.elf")
        ) { "job metadata identity does not match its store location" }
        return Job(
            id = payload.string("id"),
            filename = payload.string("filename"),
            status = payload.string("status"),
            createdAt = payload.string("created_at"),
            updatedAt = if ("updated_at" in payload) payload.string("updated_at") else payload.string("created_at"),
            statusMessage = payload.optionalString("status_message"),
            sizeBytes = payload.int("size_bytes"),
            binaryPath = Path.of(payload.string("binary_path")),
            metadata = payload.jsonObject("metadata").toElfMetadata(),
        )
    }

    @Synchronized
    fun recoveryInventory(): JobRecoveryInventory = inspectJobRecoveryInventory(root)

    @Synchronized
    fun list(): List<Job> {
        if (!root.exists()) return emptyList()
        return Files.list(root).use { paths ->
            paths.iterator().asSequence()
                .filter { Files.isDirectory(it) && it.resolve("job.json").isRegularFile() }
                .toList()
                .mapNotNull { directory -> runCatching { get(directory.fileName.toString()) }.getOrNull() }
                .sortedByDescending { it.createdAt }
        }
    }

    @Synchronized
    fun updateStatus(jobId: String, status: String, message: String? = null): Job {
        require(status in VALID_STATUSES) { "invalid job status: $status" }
        val updated = get(jobId).copy(
            status = status,
            updatedAt = Instant.now().toString(),
            statusMessage = message?.replace(Regex("[\\r\\n]+"), " ")?.take(MAX_STATUS_MESSAGE_CHARACTERS),
        )
        persist(updated)
        return updated
    }

    fun reportsDirectory(jobId: String): Path = jobDirectory(jobId).resolve("reports").createDirectories()

    /** The caller first verifies run ownership through the durable attempt store. Reads never create directories. */
    internal fun runReportsDirectory(jobId: String, runId: String, create: Boolean = false): Path {
        require(runId.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}"))) { "invalid workflow report identity" }
        val job = jobDirectory(jobId)
        if (!Files.isDirectory(job, java.nio.file.LinkOption.NOFOLLOW_LINKS)) throw JobStoreException("job storage is unavailable")
        var current = job
        for (segment in listOf("reports", "runs", runId)) {
            current = current.resolve(segment)
            if (Files.exists(current, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                if (!Files.isDirectory(current, java.nio.file.LinkOption.NOFOLLOW_LINKS)) throw JobStoreException("workflow report storage is invalid")
            } else if (create) Files.createDirectory(current)
        }
        return current
    }

    internal fun resolveRunArtifact(jobId: String, runId: String, relativePath: String): Path {
        require(relativePath.isNotBlank() && !relativePath.contains('\\')) { "invalid workflow artifact path" }
        val segments = relativePath.split('/')
        require(segments.none { it.isBlank() || it == "." || it == ".." }) { "invalid workflow artifact path" }
        var current = runReportsDirectory(jobId, runId)
        for ((index, segment) in segments.withIndex()) {
            current = current.resolve(segment)
            val valid = if (index == segments.lastIndex) Files.isRegularFile(current, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                else Files.isDirectory(current, java.nio.file.LinkOption.NOFOLLOW_LINKS)
            if (!valid) throw JobStoreException("workflow artifact is unavailable")
        }
        return current
    }

    fun resolveArtifact(jobId: String, relativePath: String): Path {
        require(relativePath.isNotBlank()) { "artifact path must not be blank" }
        require(relativePath.replace('\\', '/').startsWith("reports/")) { "only report artifacts may be downloaded" }
        val jobDir = jobDirectory(jobId).toAbsolutePath().normalize()
        val artifact = jobDir.resolve(relativePath).normalize()
        if (!artifact.startsWith(jobDir) || !artifact.isRegularFile()) {
            throw JobStoreException("artifact not found: $relativePath")
        }
        return artifact
    }

    internal fun readArtifact(
        jobId: String,
        relativePath: String,
        maximumBytes: Long,
    ): StableRegularFile {
        jobDirectory(jobId)
        require(relativePath.startsWith("reports/") && relativePath.length <= 4096 &&
            relativePath.none { it == '\\' || it.code < 32 || it.code == 127 } &&
            relativePath.split('/').let { parts ->
                parts.size <= 32 && parts.none { it.isBlank() || it == "." || it == ".." }
            }
        ) { "artifact path must be a canonical report path" }
        return try {
            readStableRegularFile(root, "$jobId/$relativePath", maximumBytes)
        } catch (_: IOException) {
            throw JobStoreException("artifact is unavailable or its path changed")
        }
    }

    internal fun readInput(jobId: String): StableRegularFile {
        jobDirectory(jobId)
        return try {
            readStableRegularFile(root, "$jobId/input.elf", MAX_INPUT_BYTES.toLong())
        } catch (_: IOException) {
            throw JobStoreException("job input is unavailable or its path changed")
        }
    }

    internal fun sourceArchiveInventory(jobId: String, reportPrefix: String = "reports"): Map<String, LinuxFileIdentity> {
        jobDirectory(jobId)
        require(reportPrefix == "reports" || reportPrefix.matches(Regex("reports/runs/[A-Za-z0-9][A-Za-z0-9_-]{0,127}"))) { "archive report prefix is invalid" }
        val inventory = sortedMapOf<String, LinuxFileIdentity>()
        var entries = 1
        var regularFiles = 0
        fun visit(directory: LinuxDescriptor, prefix: String, depth: Int) {
            require(depth <= 30) { "archive source inventory exceeds its depth bound" }
            inventory[prefix] = directory.identity
            val names = LinuxFilesystemSyscalls.directoryEntryNames(directory, 100_001 - entries).sorted()
            for (name in names) {
                require(++entries <= 100_000) { "archive source inventory exceeds its entry bound" }
                val relative = if (prefix.isEmpty()) name else "$prefix/$name"
                val selected = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, name)) {
                    "archive source entry disappeared"
                }
                selected.use { entry ->
                    require(!entry.identity.isSymbolicLink) { "archive source inventory contains a linked entry" }
                    if (relative == "build") {
                        require(entry.identity.isDirectory) { "archive build root is not a directory" }
                    } else if (entry.identity.isDirectory) {
                        LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, name).use { child ->
                            require(child.identity == entry.identity) { "archive source directory changed" }
                            visit(child, relative, depth + 1)
                        }
                    } else {
                        require(entry.identity.isRegularFile) { "archive source inventory contains a nonregular entry" }
                        inventory[relative] = entry.identity
                        require(++regularFiles <= 2048) {
                            "archive source inventory exceeds its file-count bound"
                        }
                    }
                }
            }
            require(names == LinuxFilesystemSyscalls.directoryEntryNames(directory, 100_000).sorted() &&
                directory.identity == LinuxFilesystemSyscalls.identity(directory.fd)
            ) { "archive source inventory changed during enumeration" }
        }
        try {
            LinuxFilesystemSyscalls.openRoot(root).use { storeRoot ->
                LinuxFilesystemSyscalls.openDirectoryAt(storeRoot.fd, jobId).use { job ->
                    fun openSelected(parent: LinuxDescriptor, segments: List<String>) {
                        LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, segments.first()).use { child ->
                            if (segments.size == 1) visit(child, "", 0) else openSelected(child, segments.drop(1))
                        }
                    }
                    openSelected(job, reportPrefix.split('/') + "source-tree")
                }
            }
        } catch (_: IOException) {
            throw JobStoreException("archive source inventory is unavailable or changed")
        }
        return inventory
    }

    @Synchronized
    fun recoverInterruptedJobs() = recoverInterruptedJobs { false }

    internal fun recoverInterruptedJobs(cancellation: () -> Boolean) =
        recoverInterruptedJobs(4096, 64L * 1024 * 1024, cancellation)

    /** Complete bounded inspection precedes every recovery write; errors never imply rollback. */
    @Synchronized
    internal fun recoverInterruptedJobs(
        maximumEntries: Int, maximumMetadataBytes: Long, cancellation: () -> Boolean = { false },
    ) {
        require(maximumEntries in 1..4096 && maximumMetadataBytes in 1..64L * 1024 * 1024)
        var statusUpdatesStarted = false
        fun checkCancellation() {
            if (Thread.currentThread().isInterrupted || cancellation()) {
                throw JobRecoveryCancelledException(statusUpdatesStarted)
            }
        }
        checkCancellation()
        if (!root.exists()) return
        val pending = ArrayList<Job>()
        try {
            var scanned = 0
            var remaining = maximumMetadataBytes
            Files.newDirectoryStream(root).use { entries ->
                for (entry in entries) {
                    checkCancellation()
                    check(++scanned <= maximumEntries)
                    val id = entry.fileName.toString()
                    if (!id.matches(Regex("[a-f0-9]{32}"))) continue
                    check(remaining > 0)
                    val bytes = readStableRegularFile(root, "$id/job.json",
                        minOf(MAX_METADATA_BYTES.toLong(), remaining)).bytes
                    remaining -= bytes.size
                    val job = decodeJob(id, bytes)
                    check(job.status in VALID_STATUSES)
                    if (job.status == "queued" || job.status == "analyzing") {
                        val recovered = job.copy(
                            status = "failed",
                            updatedAt = Instant.now().toString(),
                            statusMessage = "Analysis was interrupted before the server restarted",
                        )
                        // Legacy records may parse within the read limit but exceed the rewrite limit.
                        // Freeze the entire replacement, including its timestamp, before validating it.
                        encodeMetadata(recovered)
                        pending.add(recovered)
                    }
                }
            }
        } catch (cancelled: JobRecoveryCancelledException) {
            throw cancelled
        } catch (_: Exception) {
            throw JobStoreException("Job recovery inspection is incomplete; no recovery statuses were changed")
        }
        checkCancellation()
        pending.forEach { job ->
            checkCancellation()
            statusUpdatesStarted = true
            // Reuse the bounded inspection: updateStatus would read this metadata a second time.
            persist(job)
        }
        // A cancellation racing the final write begins after its admission check; report the
        // publication through the cancelled-after-status-updates failure instead of success.
        checkCancellation()
    }

    private fun jobDirectory(jobId: String): Path {
        if (jobId.isBlank() || !jobId.matches(Regex("[a-f0-9]{32}"))) {
            throw JobStoreException("invalid job id: $jobId")
        }
        return root.resolve(jobId)
    }

    // Admissions must also fit every later record shape updateStatus can publish.
    private fun requireStatusUpdateHeadroom(job: Job) {
        val reserved = job.copy(
            status = "analyzing",
            updatedAt = MAXIMUM_UPDATE_TIMESTAMP,
            statusMessage = STATUS_MESSAGE_RESERVE,
        )
        try {
            OracleJson.canonicalBytes(reserved.toJson(), METADATA_LIMITS)
        } catch (_: StrictJsonException) {
            throw InvalidUploadException("job metadata exceeds the 256 KiB limit once later status updates are reserved")
        }
    }

    private fun persist(job: Job, jobDir: Path = jobDirectory(job.id).createDirectories()) {
        val bytes = encodeMetadata(job)
        val temporary = Files.createTempFile(jobDir, ".job-metadata-", ".tmp")
        try {
            metadataPublisher.writeAndForce(temporary, bytes)
            metadataPublisher.replace(temporary, jobDir.resolve("job.json"))
            metadataPublisher.confirmDirectory(jobDir)
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    private fun encodeMetadata(job: Job): ByteArray {
        // Bound the encoder's string-byte accounting allocation before it sees caller-provided text.
        require(job.filename.length <= MAX_METADATA_BYTES) { "job metadata exceeds the 256 KiB limit" }
        return try {
            OracleJson.canonicalBytes(job.toJson(), METADATA_LIMITS)
        } catch (_: StrictJsonException) {
            throw IllegalArgumentException("job metadata exceeds the 256 KiB limit or contains invalid JSON text")
        }
    }

    private companion object {
        const val MAX_STATUS_MESSAGE_CHARACTERS = 500
        const val MAX_INPUT_BYTES = 32 * 1024 * 1024
        const val MAX_METADATA_BYTES = 256 * 1024
        val METADATA_LIMITS = StrictJsonLimits(
            maximumCanonicalBytes = MAX_METADATA_BYTES,
            maximumStringBytes = MAX_METADATA_BYTES,
            maximumTotalStringBytes = MAX_METADATA_BYTES,
            maximumDepth = 8,
            maximumNodes = 128,
        )
        val VALID_STATUSES = setOf("uploaded", "queued", "analyzing", "complete", "failed")
        val STATUS_MESSAGE_RESERVE = "\u0001".repeat(500)
        const val MAXIMUM_UPDATE_TIMESTAMP = "9999-12-31T23:59:59.999999999Z"
    }
}

fun ElfMetadata.toJson(): JsonObject = buildJsonObject {
    put("format", format)
    put("endianness", endianness)
    put("elf_version", elfVersion.toLong())
    put("os_abi", osAbi)
    put("object_type", objectType)
    put("machine", machine)
    put("entry_point", entryPoint.toLong())
    put("elf_header_size", elfHeaderSize.toInt())
    put("program_header_count", programHeaderCount.toInt())
    put("section_header_count", sectionHeaderCount.toInt())
    put("section_name_table_index", sectionNameTableIndex.toInt())
}

private fun JsonObject.toElfMetadata(): ElfMetadata {
    require(keys == setOf("format", "endianness", "elf_version", "os_abi", "object_type", "machine",
        "entry_point", "elf_header_size", "program_header_count", "section_header_count", "section_name_table_index")) {
        "job ELF metadata has missing or unsupported fields"
    }
    fun unsignedShort(name: String): UShort = long(name).also {
        require(it in 0..65535) { "job ELF metadata integer is out of range" }
    }.toUShort()
    return ElfMetadata(
        format = string("format"),
        endianness = string("endianness"),
        elfVersion = long("elf_version").also {
            require(it in 0..UInt.MAX_VALUE.toLong()) { "job ELF metadata version is out of range" }
        }.toUInt(),
        osAbi = string("os_abi"),
        objectType = string("object_type"),
        machine = string("machine"),
        // Existing metadata encodes this ULong using its signed Long bit representation.
        entryPoint = long("entry_point").toULong(),
        elfHeaderSize = unsignedShort("elf_header_size"),
        programHeaderCount = unsignedShort("program_header_count"),
        sectionHeaderCount = unsignedShort("section_header_count"),
        sectionNameTableIndex = unsignedShort("section_name_table_index"),
    )
}

private fun JsonObject.string(name: String): String = getValue(name).jsonPrimitive.let {
    require(it.isString) { "job metadata requires a JSON string" }
    it.content
}
private fun JsonObject.optionalString(name: String): String? =
    if (get(name) == null || get(name) == JsonNull) null else string(name)
private fun JsonObject.int(name: String): Int = long(name).also {
    require(it in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong()) { "job metadata integer is out of range" }
}.toInt()
private fun JsonObject.long(name: String): Long = getValue(name).jsonPrimitive.let {
    require(!it.isString) { "job metadata requires a JSON integer" }
    requireNotNull(it.longOrNull) { "job metadata requires a JSON integer" }
}
private fun JsonObject.jsonObject(name: String): JsonObject = getValue(name).jsonObject
