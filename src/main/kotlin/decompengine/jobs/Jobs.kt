package decompengine.jobs

import decompengine.binary.ElfMetadata
import decompengine.binary.ElfMetadataReader
import decompengine.binary.InvalidElfException
import decompengine.oracle.core.OracleJson
import decompengine.repair.StableRegularFile
import decompengine.repair.readStableRegularFile
import java.io.IOException
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
        val jobDir = jobDirectory(jobId)
        val payload = try {
            OracleJson.parse(readStableRegularFile(root, "$jobId/job.json", 256L * 1024).bytes).jsonObject
        } catch (_: IOException) {
            throw JobStoreException("job metadata is unavailable or its path changed")
        }
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
