package decompengine.jobs

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE

internal interface JobMetadataPublisher {
    fun writeAndForce(temporary: Path, bytes: ByteArray)
    fun replace(temporary: Path, destination: Path)
    fun confirmDirectory(directory: Path)
}

internal object AtomicJobMetadataPublisher : JobMetadataPublisher {
    override fun writeAndForce(temporary: Path, bytes: ByteArray) {
        FileChannel.open(temporary, WRITE, NOFOLLOW_LINKS).use { channel ->
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer)
            channel.force(true)
        }
    }

    override fun replace(temporary: Path, destination: Path) {
        Files.move(temporary, destination, ATOMIC_MOVE, REPLACE_EXISTING)
    }

    override fun confirmDirectory(directory: Path) {
        FileChannel.open(directory, READ).use { it.force(true) }
    }
}
