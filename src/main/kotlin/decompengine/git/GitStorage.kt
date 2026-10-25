package decompengine.git

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest

/** Small durable-file primitives shared by the managed repository registry. */
internal object GitStorage {
    fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).hex()
    fun sha256(text: String): String = sha256(text.toByteArray(Charsets.UTF_8))
    fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

    /** Create each missing segment without following links; existing segments must be real directories. */
    fun directories(base: Path, vararg segments: String): Path {
        var current = base
        for (segment in segments) {
            current = current.resolve(segment)
            if (!Files.exists(current, NOFOLLOW_LINKS)) {
                Files.createDirectory(current, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            }
            if (!Files.isDirectory(current, NOFOLLOW_LINKS)) throw IOException("Git storage directory is invalid")
        }
        return current
    }

    /** Write, force and rename into place; the directory entry is forced afterwards. */
    fun replaceAtomically(destination: Path, bytes: ByteArray) {
        val temporary = destination.resolveSibling(".${destination.fileName}.${java.util.UUID.randomUUID()}.tmp")
        try {
            FileChannel.open(temporary, CREATE_NEW, WRITE, NOFOLLOW_LINKS).use { channel ->
                val buffer = ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) channel.write(buffer)
                channel.force(true)
            }
            Files.move(temporary, destination, ATOMIC_MOVE, REPLACE_EXISTING)
            forceDirectory(destination.parent)
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    fun forceDirectory(directory: Path) { FileChannel.open(directory, READ).use { it.force(true) } }

    /** Bounded read of a regular, unlinked file. */
    fun read(file: Path, maximum: Int): ByteArray {
        if (!Files.isRegularFile(file, NOFOLLOW_LINKS)) throw IOException("Git storage record is unavailable")
        Files.newInputStream(file, NOFOLLOW_LINKS).use { input ->
            val bytes = input.readNBytes(maximum + 1)
            if (bytes.size > maximum) throw IOException("Git storage record exceeds its bound")
            return bytes
        }
    }

    /** Delete a private tree without following links. Missing trees are already removed. */
    fun deleteTree(root: Path) {
        if (!Files.exists(root, NOFOLLOW_LINKS)) return
        Files.walkFileTree(root, object : SimpleFileVisitor<Path>() {
            override fun visitFile(file: Path, attributes: BasicFileAttributes): FileVisitResult {
                Files.delete(file); return FileVisitResult.CONTINUE
            }
            override fun postVisitDirectory(directory: Path, failure: IOException?): FileVisitResult {
                if (failure != null) throw failure
                Files.delete(directory); return FileVisitResult.CONTINUE
            }
        })
    }
}
