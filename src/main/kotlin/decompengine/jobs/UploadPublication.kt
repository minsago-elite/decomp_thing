package decompengine.jobs

import java.nio.channels.FileChannel
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.StandardOpenOption.CREATE_NEW

class UploadPublicationUncertainException internal constructor(val jobId: String, cause: Exception) :
    RuntimeException("Upload publication is uncertain for job $jobId; inspect that job before uploading again", cause)

/** Publication I/O boundary, allowing failures before and after rename to be qualified independently. */
internal interface UploadPublisher {
    fun writeAndForceInput(input: Path, bytes: ByteArray)
    fun publish(staging: Path, destination: Path)
    fun confirmDirectory(root: Path)
}

internal object AtomicUploadPublisher : UploadPublisher {
    override fun writeAndForceInput(input: Path, bytes: ByteArray) {
        FileChannel.open(input, CREATE_NEW, WRITE, NOFOLLOW_LINKS).use { channel ->
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer)
            check(input.toFile().setExecutable(true, true) || Files.isExecutable(input)) {
                "could not mark uploaded ELF executable"
            }
            channel.force(true)
        }
    }

    override fun publish(staging: Path, destination: Path) {
        Files.move(staging, destination, ATOMIC_MOVE)
    }

    override fun confirmDirectory(root: Path) {
        FileChannel.open(root, READ).use { it.force(true) }
    }
}
