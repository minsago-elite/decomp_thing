package decompengine.jobs

import decompengine.binary.ElfMetadata
import decompengine.binary.ElfMetadataReader
import decompengine.binary.InvalidElfException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
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
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.isRegularFile
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText

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

class JobStore(root: Path) {
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
        val metadata = try {
            ElfMetadataReader.read(content)
        } catch (exception: InvalidElfException) {
            throw InvalidUploadException(exception.message ?: "uploaded file is not an ELF binary", exception)
        }

        root.createDirectories()
        val jobId = UUID.randomUUID().toString().replace("-", "")
        val jobDir = root.resolve(jobId).createDirectories()
        val binaryPath = jobDir.resolve("input.elf")
        binaryPath.writeBytes(content)
        check(binaryPath.toFile().setExecutable(true, true) || Files.isExecutable(binaryPath)) {
            "could not mark uploaded ELF executable"
        }
        val job = Job(
            id = jobId,
            filename = Path.of(filename).name.ifBlank { "input.elf" },
            status = "uploaded",
            createdAt = Instant.now().toString(),
            sizeBytes = content.size,
            binaryPath = binaryPath,
            metadata = metadata,
        )
        persist(job)
        return job
    }

    @Synchronized
    fun get(jobId: String): Job {
        val metadataPath = jobDirectory(jobId).resolve("job.json")
        if (!metadataPath.exists()) {
            throw JobStoreException("job not found: $jobId")
        }
        val payload = Json.parseToJsonElement(metadataPath.readText()).jsonObject
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

    @Synchronized
    fun recoverInterruptedJobs() {
        list().filter { it.status in setOf("queued", "analyzing") }.forEach { job ->
            updateStatus(job.id, "failed", "Analysis was interrupted before the server restarted")
        }
    }

    private fun jobDirectory(jobId: String): Path {
        if (jobId.isBlank() || !jobId.matches(Regex("[a-f0-9]{32}"))) {
            throw JobStoreException("invalid job id: $jobId")
        }
        return root.resolve(jobId)
    }

    private fun persist(job: Job) {
        val jobDir = jobDirectory(job.id).createDirectories()
        jobDir.resolve("job.json").writeText(
            Json { prettyPrint = true }.encodeToString(JsonElement.serializer(), job.toJson()) + "\n",
        )
    }

    private companion object {
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
