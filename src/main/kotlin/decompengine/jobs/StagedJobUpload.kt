package decompengine.jobs

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

internal data class PublishedJobUpload(val job: Job, val inputSha256: String)
internal class UploadPublicationUncertain(val jobId: String, cause: Throwable) : RuntimeException("Upload publication requires storage recovery", cause)
internal enum class UploadPublishPoint { AFTER_BINARY_SYNC, AFTER_METADATA_SYNC, BEFORE_RENAME, AFTER_RENAME }

/** Caller holds the job-root ownership lease. Only the final atomic rename makes a complete job visible. */
internal class StagedJobUpload(
    private val root: Path,
    private val fault: (UploadPublishPoint) -> Unit = {},
) {
    fun publish(writeBinary: (OutputStream) -> String): PublishedJobUpload {
        require(Files.isDirectory(root, java.nio.file.LinkOption.NOFOLLOW_LINKS)) { "Upload storage must already be owned and initialized" }
        val stage = Files.createTempDirectory(root, ".upload-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val id = UUID.randomUUID().toString().replace("-", "")
        val destination = root.resolve(id)
        val binary = stage.resolve("input.elf")
        val metadataFile = stage.resolve("job.json")
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
            val metadata = try { ElfMetadataReader.read(header.toByteArray()) }
                catch (failure: InvalidElfException) { throw InvalidUploadException(failure.message ?: "Invalid ELF header", failure) }
            Files.setPosixFilePermissions(binary, PosixFilePermissions.fromString("rwx------"))
            FileChannel.open(binary, WRITE).use { it.force(true) }
            val job = Job(id, filename, "uploaded", Instant.now().toString(), sizeBytes = size.toInt(), binaryPath = destination.resolve("input.elf"), metadata = metadata)
            FileChannel.open(metadataFile, CREATE_NEW, WRITE).use { channel ->
                val buffer = ByteBuffer.wrap((job.toJson().toString() + "\n").toByteArray())
                while (buffer.hasRemaining()) channel.write(buffer)
                channel.force(true)
            }
            fault(UploadPublishPoint.AFTER_METADATA_SYNC)
            syncDirectory(stage)
            if (Thread.currentThread().isInterrupted) throw java.io.InterruptedIOException("Upload interrupted before publication")
            fault(UploadPublishPoint.BEFORE_RENAME)
            Files.move(stage, destination, ATOMIC_MOVE)
            renamed = true
            fault(UploadPublishPoint.AFTER_RENAME)
            syncDirectory(root)
            return PublishedJobUpload(job, digest.digest().joinToString("") { "%02x".format(it) })
        } catch (failure: Throwable) {
            val selected = if (renamed) UploadPublicationUncertain(id, failure) else failure
            primary = selected
            throw selected
        } finally {
            if (!renamed) {
                try {
                    Files.deleteIfExists(metadataFile)
                    Files.deleteIfExists(binary)
                    Files.deleteIfExists(stage)
                } catch (cleanup: Throwable) { if (primary != null) primary.addSuppressed(cleanup) else throw cleanup }
            }
        }
    }

    private fun syncDirectory(path: Path) { FileChannel.open(path, READ).use { it.force(true) } }
}
