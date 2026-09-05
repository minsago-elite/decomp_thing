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
import kotlinx.serialization.json.int
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
        jobDirectory(jobId) // Validate the identifier before any metadata read.
        val bytes = try {
            readStableRegularFile(root, "$jobId/job.json", MAX_METADATA_BYTES.toLong()).bytes
        } catch (_: IOException) {
            throw JobStoreException("job metadata is unavailable or its path changed")
        }
        return decodeJob(jobId, bytes)
    }

    private fun decodeJob(jobId: String, bytes: ByteArray): Job {
        val jobDir = jobDirectory(jobId)
        val payload = OracleJson.parse(bytes).jsonObject
        require(payload.string("id") == jobId &&
            Path.of(payload.string("binary_path")) == jobDir.resolve("input.elf")
        ) { "job metadata identity does not match its store location" }
        return Job(
            id = payload.string("id"),
            filename = payload.string("filename"),
            status = payload.string("status"),
            createdAt = payload.string("created_at"),
            updatedAt = payload.optionalString("updated_at") ?: payload.string("created_at"),
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
            statusMessage = message?.replace(Regex("[\\r\\n]+"), " ")?.take(500),
        )
        persist(updated)
        return updated
    }

    fun reportsDirectory(jobId: String): Path = jobDirectory(jobId).resolve("reports").createDirectories()

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

    internal fun sourceArchiveInventory(jobId: String): Map<String, LinuxFileIdentity> {
        jobDirectory(jobId)
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
                    LinuxFilesystemSyscalls.openDirectoryAt(job.fd, "reports").use { reports ->
                        LinuxFilesystemSyscalls.openDirectoryAt(reports.fd, "source-tree").use { source -> visit(source, "", 0) }
                    }
                }
            }
        } catch (_: IOException) {
            throw JobStoreException("archive source inventory is unavailable or changed")
        }
        return inventory
    }

    @Synchronized
    fun recoverInterruptedJobs() = recoverInterruptedJobs(4096, 64L * 1024 * 1024)

    /** Complete bounded inspection precedes every recovery write; errors never imply rollback. */
    @Synchronized
    internal fun recoverInterruptedJobs(maximumEntries: Int, maximumMetadataBytes: Long) {
        require(maximumEntries in 1..4096 && maximumMetadataBytes in 1..64L * 1024 * 1024)
        if (!root.exists()) return
        val pending = ArrayList<String>()
        try {
            var scanned = 0
            var remaining = maximumMetadataBytes
            Files.newDirectoryStream(root).use { entries ->
                for (entry in entries) {
                    check(++scanned <= maximumEntries)
                    val id = entry.fileName.toString()
                    if (!id.matches(Regex("[a-f0-9]{32}"))) continue
                    check(remaining > 0)
                    val bytes = readStableRegularFile(root, "$id/job.json",
                        minOf(MAX_METADATA_BYTES.toLong(), remaining)).bytes
                    remaining -= bytes.size
                    val job = decodeJob(id, bytes)
                    check(job.status in VALID_STATUSES)
                    if (job.status == "queued" || job.status == "analyzing") pending.add(id)
                }
            }
        } catch (_: Exception) {
            throw JobStoreException("Job recovery inspection is incomplete; no recovery statuses were changed")
        }
        pending.forEach { id ->
            updateStatus(id, "failed", "Analysis was interrupted before the server restarted")
        }
    }

    private fun jobDirectory(jobId: String): Path {
        if (jobId.isBlank() || !jobId.matches(Regex("[a-f0-9]{32}"))) {
            throw JobStoreException("invalid job id: $jobId")
        }
        return root.resolve(jobId)
    }

    private fun persist(job: Job, jobDir: Path = jobDirectory(job.id).createDirectories()) {
        // Bound the encoder's string-byte accounting allocation before it sees caller-provided text.
        require(job.filename.length <= MAX_METADATA_BYTES) { "job metadata exceeds the 256 KiB limit" }
        val bytes = try {
            OracleJson.canonicalBytes(job.toJson(), METADATA_LIMITS)
        } catch (_: StrictJsonException) {
            throw IllegalArgumentException("job metadata exceeds the 256 KiB limit or contains invalid JSON text")
        }
        val temporary = Files.createTempFile(jobDir, ".job-metadata-", ".tmp")
        try {
            metadataPublisher.writeAndForce(temporary, bytes)
            metadataPublisher.replace(temporary, jobDir.resolve("job.json"))
            metadataPublisher.confirmDirectory(jobDir)
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    private companion object {
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

private fun JsonObject.toElfMetadata(): ElfMetadata = ElfMetadata(
    format = string("format"),
    endianness = string("endianness"),
    elfVersion = long("elf_version").toUInt(),
    osAbi = string("os_abi"),
    objectType = string("object_type"),
    machine = string("machine"),
    entryPoint = long("entry_point").toULong(),
    elfHeaderSize = int("elf_header_size").toUShort(),
    programHeaderCount = int("program_header_count").toUShort(),
    sectionHeaderCount = int("section_header_count").toUShort(),
    sectionNameTableIndex = int("section_name_table_index").toUShort(),
)

private fun JsonObject.string(name: String): String = getValue(name).jsonPrimitive.content
private fun JsonObject.optionalString(name: String): String? = get(name)?.jsonPrimitive?.content
private fun JsonObject.int(name: String): Int = getValue(name).jsonPrimitive.int
private fun JsonObject.long(name: String): Long = getValue(name).jsonPrimitive.content.toLong()
private fun JsonObject.jsonObject(name: String): JsonObject = getValue(name).jsonObject
