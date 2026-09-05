package decompengine.jobs

import decompengine.oracle.core.OracleJson
import decompengine.repair.readStableRegularFile
import kotlinx.serialization.json.*
import decompengine.binary.ElfMetadataReader
import decompengine.binary.InvalidElfException
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID

internal data class PublishedJobUpload(val job: Job, val inputSha256: String, val replayed: Boolean = false)
internal class UploadPublicationUncertain(val jobId: String, cause: Throwable) : RuntimeException("Upload publication requires storage recovery", cause)
internal class UploadIdempotencyConflict : RuntimeException("The idempotency key was already used for different upload content or filename")
internal class UploadReceiptUnavailable : RuntimeException("The retained upload receipt is unavailable or invalid; inspect storage before retrying")
internal enum class UploadPublishPoint { AFTER_BINARY_SYNC, AFTER_METADATA_SYNC, BEFORE_RENAME, AFTER_RENAME }

/** Caller holds the job-root ownership lease. Only the final atomic rename makes a complete job visible. */
internal class StagedJobUpload(
    private val root: Path,
    private val fault: (UploadPublishPoint) -> Unit = {},
) {
    private val publicationLock = Any()

    fun publish(idempotencyKey: String? = null, writeBinary: (OutputStream) -> String): PublishedJobUpload {
        require(idempotencyKey == null || idempotencyKey.matches(Regex("[A-Za-z0-9_-]{16,128}"))) { "Invalid upload idempotency key" }
        val keyHash = idempotencyKey?.let { hash("local-owner\u0000POST\u0000/api/v1/jobs\u0000$it".toByteArray()) }
        require(Files.isDirectory(root, java.nio.file.LinkOption.NOFOLLOW_LINKS)) { "Upload storage must already be owned and initialized" }
        val stage = Files.createTempDirectory(root, ".upload-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val id = keyHash?.take(32) ?: UUID.randomUUID().toString().replace("-", "")
        val destination = root.resolve(id)
        val binary = stage.resolve("input.elf")
        val metadataFile = stage.resolve("job.json")
        val receiptFile = stage.resolve("upload-receipt.json")
        var renamed = false
        var primary: Throwable? = null
        try {
            val header = ByteArrayOutputStream(64)
            val digest = MessageDigest.getInstance("SHA-256")
            var size = 0L
            val filename: String
            FileChannel.open(binary, CREATE_NEW, WRITE).use { channel ->
                val sink = object : OutputStream() {
                    override fun write(value: Int) { write(byteArrayOf(value.toByte()), 0, 1) }
                    override fun write(bytes: ByteArray, offset: Int, length: Int) {
                        java.util.Objects.checkFromIndexSize(offset, length, bytes.size)
                        if (Thread.currentThread().isInterrupted) throw java.io.InterruptedIOException("Upload interrupted")
                        require(size + length <= 32L * 1024 * 1024) { "Upload binary exceeds its byte limit" }
                        val buffer = ByteBuffer.wrap(bytes, offset, length)
                        while (buffer.hasRemaining()) channel.write(buffer)
                        digest.update(bytes, offset, length)
                        if (header.size() < 64) header.write(bytes, offset, minOf(length, 64 - header.size()))
                        size += length
                    }
                }
                filename = writeBinary(sink)
                channel.force(true)
            }
            fault(UploadPublishPoint.AFTER_BINARY_SYNC)
            require(filename.length in 1..255 && filename !in setOf(".", "..") && filename.none { it == '/' || it == '\\' || it.code < 32 || it.code == 127 }) { "Invalid display filename" }
            val inputSha = digest.digest().joinToString("") { "%02x".format(it) }
            val intent = hash(buildJsonObject {
                put("version", 1); put("filename", filename); put("inputSha256", inputSha); put("sizeBytes", size.toString())
            }.toString().toByteArray())
            return synchronized(publicationLock) {
                if (keyHash != null && Files.exists(destination, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                    return@synchronized replay(id, keyHash, intent)
                }
                val metadata = try { ElfMetadataReader.read(header.toByteArray()) }
                    catch (failure: InvalidElfException) { throw InvalidUploadException(failure.message ?: "Invalid ELF header", failure) }
                Files.setPosixFilePermissions(binary, PosixFilePermissions.fromString("rwx------"))
                FileChannel.open(binary, WRITE).use { it.force(true) }
                val job = Job(id, filename, "uploaded", Instant.now().toString(), sizeBytes = size.toInt(), binaryPath = destination.resolve("input.elf"), metadata = metadata)
                writeSynced(metadataFile, job.toJson())
                if (keyHash != null) writeSynced(receiptFile, buildJsonObject {
                    put("schemaVersion", 1); put("keySha256", keyHash); put("intentSha256", intent)
                    put("inputSha256", inputSha); put("job", job.toJson())
                })
                fault(UploadPublishPoint.AFTER_METADATA_SYNC)
                syncDirectory(stage)
                if (Thread.currentThread().isInterrupted) throw java.io.InterruptedIOException("Upload interrupted before publication")
                fault(UploadPublishPoint.BEFORE_RENAME)
                Files.move(stage, destination, ATOMIC_MOVE)
                renamed = true
                fault(UploadPublishPoint.AFTER_RENAME)
                syncDirectory(root)
                PublishedJobUpload(job, inputSha)
            }
        } catch (failure: Throwable) {
            val selected = if (renamed) UploadPublicationUncertain(id, failure) else failure
            primary = selected
            throw selected
        } finally {
            if (!renamed) {
                try {
                    Files.deleteIfExists(receiptFile)
                    Files.deleteIfExists(metadataFile)
                    Files.deleteIfExists(binary)
                    Files.deleteIfExists(stage)
                } catch (cleanup: Throwable) { if (primary != null) primary.addSuppressed(cleanup) else throw cleanup }
            }
        }
    }

    private fun replay(id: String, keyHash: String, intent: String): PublishedJobUpload {
        val receipt = try {
            val bytes = readStableRegularFile(root, "$id/upload-receipt.json", 16384).bytes
            val document = OracleJson.parse(bytes).jsonObject
            require(document.keys == setOf("schemaVersion", "keySha256", "intentSha256", "inputSha256", "job"))
            require(document.getValue("schemaVersion").jsonPrimitive.int == 1)
            require(document.getValue("keySha256").jsonPrimitive.content == keyHash)
            require(document.getValue("intentSha256").jsonPrimitive.content.matches(Regex("[0-9a-f]{64}")))
            require(document.getValue("inputSha256").jsonPrimitive.content.matches(Regex("[0-9a-f]{64}")))
            document
        } catch (_: Exception) { throw UploadReceiptUnavailable() }
        if (receipt.getValue("intentSha256").jsonPrimitive.content != intent) throw UploadIdempotencyConflict()
        return try {
            val store = JobStore(root)
            store.get(id) // A missing/corrupt live job is unavailable; do not silently recreate it.
            val job = store.decodeJobRecord(id, receipt.getValue("job").jsonObject)
            require(job.status == "uploaded" && job.updatedAt == job.createdAt && job.statusMessage == null)
            val recordedIntent = hash(buildJsonObject {
                put("version", 1); put("filename", job.filename)
                put("inputSha256", receipt.getValue("inputSha256").jsonPrimitive.content); put("sizeBytes", job.sizeBytes.toString())
            }.toString().toByteArray())
            require(recordedIntent == intent)
            PublishedJobUpload(job, receipt.getValue("inputSha256").jsonPrimitive.content, replayed = true)
        } catch (_: Exception) { throw UploadReceiptUnavailable() }
    }

    private fun writeSynced(path: Path, document: JsonObject) {
        val bytes = (document.toString() + "\n").toByteArray()
        require(bytes.size <= 16384) { "Upload receipt exceeds its byte limit" }
        FileChannel.open(path, CREATE_NEW, WRITE).use { channel ->
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer)
            channel.force(true)
        }
    }
    private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun syncDirectory(path: Path) { FileChannel.open(path, READ).use { it.force(true) } }
}
