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
import java.time.Instant
import java.util.UUID
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.name
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText

class JobStoreException(message: String) : RuntimeException(message)
class InvalidUploadException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

data class Job(
    val id: String,
    val filename: String,
    val status: String,
    val createdAt: String,
    val sizeBytes: Int,
    val binaryPath: Path,
    val metadata: ElfMetadata,
) {
    fun toJson(): JsonObject = buildJsonObject {
        put("id", id)
        put("filename", filename)
        put("status", status)
        put("created_at", createdAt)
        put("size_bytes", sizeBytes)
        put("binary_path", binaryPath.toString())
        put("metadata", metadata.toJson())
    }
}

class JobStore(private val root: Path) {
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
        val job = Job(
            id = jobId,
            filename = Path.of(filename).name.ifBlank { "input.elf" },
            status = "uploaded",
            createdAt = Instant.now().toString(),
            sizeBytes = content.size,
            binaryPath = binaryPath,
            metadata = metadata,
        )
        jobDir.resolve("job.json").writeText(Json { prettyPrint = true }.encodeToString(JsonElement.serializer(), job.toJson()) + "\n")
        return job
    }

    fun get(jobId: String): Job {
        if (jobId.isBlank() || listOf("/", "\\", "..").any { jobId.contains(it) }) {
            throw JobStoreException("invalid job id: $jobId")
        }
        val metadataPath = root.resolve(jobId).resolve("job.json")
        if (!metadataPath.exists()) {
            throw JobStoreException("job not found: $jobId")
        }
        val payload = Json.parseToJsonElement(metadataPath.readText()).jsonObject
        return Job(
            id = payload.string("id"),
            filename = payload.string("filename"),
            status = payload.string("status"),
            createdAt = payload.string("created_at"),
            sizeBytes = payload.int("size_bytes"),
            binaryPath = Path.of(payload.string("binary_path")),
            metadata = payload.jsonObject("metadata").toElfMetadata(),
        )
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
private fun JsonObject.int(name: String): Int = getValue(name).jsonPrimitive.int
private fun JsonObject.long(name: String): Long = getValue(name).jsonPrimitive.content.toLong()
private fun JsonObject.jsonObject(name: String): JsonObject = getValue(name).jsonObject
