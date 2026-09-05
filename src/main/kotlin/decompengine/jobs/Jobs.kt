package decompengine.jobs

import decompengine.binary.ElfMetadata
import decompengine.binary.ElfMetadataReader
import decompengine.binary.InvalidElfException
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
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
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.StandardOpenOption.CREATE_NEW
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
        val jobDir = root.resolve(jobId)
        val binaryPath = jobDir.resolve("input.elf")
        val job = Job(
            id = jobId,
            filename = Path.of(filename).name.ifBlank { "input.elf" },
            status = "uploaded",
            createdAt = Instant.now().toString(),
            sizeBytes = content.size,
            binaryPath = binaryPath,
            metadata = metadata,
        )
        val staging = Files.createTempDirectory(root, ".upload-")
        try {
            val stagedInput = staging.resolve("input.elf")
            FileChannel.open(stagedInput, CREATE_NEW, WRITE, NOFOLLOW_LINKS).use { channel ->
                val buffer = ByteBuffer.wrap(content)
                while (buffer.hasRemaining()) channel.write(buffer)
                check(stagedInput.toFile().setExecutable(true, true) || Files.isExecutable(stagedInput)) {
                    "could not mark uploaded ELF executable"
                }
                channel.force(true)
            }
            persist(job, staging)
            Files.move(staging, jobDir, ATOMIC_MOVE)
            FileChannel.open(root, READ).use { it.force(true) }
            return job
        } catch (failure: Exception) {
            try {
                Files.deleteIfExists(staging.resolve("input.elf"))
                Files.deleteIfExists(staging.resolve("job.json"))
                Files.deleteIfExists(staging)
            } catch (cleanup: Exception) {
                failure.addSuppressed(cleanup)
            }
            throw failure
        }
    }

    @Synchronized
    fun get(jobId: String): Job {
        val jobDir = jobDirectory(jobId)
        val payload = try {
            OracleJson.parse(readStableRegularFile(root, "$jobId/job.json", MAX_METADATA_BYTES.toLong()).bytes).jsonObject
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

    internal fun readInput(jobId: String): StableRegularFile {
        jobDirectory(jobId)
        return try {
            readStableRegularFile(root, "$jobId/input.elf", 32L * 1024 * 1024)
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

    private fun persist(job: Job, jobDir: Path = jobDirectory(job.id).createDirectories()) {
        val bytes = (Json { prettyPrint = true }.encodeToString(JsonElement.serializer(), job.toJson()) + "\n")
            .toByteArray(Charsets.UTF_8)
        require(bytes.size <= MAX_METADATA_BYTES) { "job metadata exceeds the 256 KiB limit" }
        val temporary = Files.createTempFile(jobDir, ".job-metadata-", ".tmp")
        try {
            FileChannel.open(temporary, WRITE, NOFOLLOW_LINKS).use { channel ->
                val buffer = ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) channel.write(buffer)
                channel.force(true)
            }
            Files.move(temporary, jobDir.resolve("job.json"), ATOMIC_MOVE, REPLACE_EXISTING)
            FileChannel.open(jobDir, READ).use { it.force(true) }
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    private companion object {
        const val MAX_METADATA_BYTES = 256 * 1024
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
