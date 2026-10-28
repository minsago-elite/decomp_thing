package decompengine.git

import decompengine.acp.LinuxFilesystemSyscalls
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InterruptedIOException
import java.nio.file.Path

/** Data-only metadata reads from mutable admitted repositories, never blocking pathname opens. */
internal object GitImportMetadata {
    /** [beforeOpen] exercises replacement after admission but before the actual descriptor open. */
    fun read(file: Path, maximum: Int, beforeOpen: (Path) -> Unit = {}): ByteArray {
        require(maximum >= 0)
        try {
            GitStorage.checkInterrupted()
            LinuxFilesystemSyscalls.requireSupported(file)
            val absolute = file.toAbsolutePath().normalize()
            var parent = LinuxFilesystemSyscalls.openRoot(absolute.root)
            try {
                // Pin every ancestor, refusing links at open, not just during prior admission.
                for (component in absolute.parent) {
                    GitStorage.checkInterrupted()
                    val next = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, component.toString())
                    parent.close()
                    parent = next
                }
                beforeOpen(file)
                GitStorage.checkInterrupted()
                // O_PATH authenticates regular type before a readable O_NONBLOCK reopen of this inode.
                val pinned = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, absolute.fileName.toString())
                    ?: throw IOException("Repository metadata is unavailable")
                pinned.use { input ->
                    val output = ByteArrayOutputStream(minOf(maximum, 4096))
                    LinuxFilesystemSyscalls.copyReadableTo(input, output, maximum.toLong(),
                        cancellationCheck = GitStorage::checkInterrupted)
                    return output.toByteArray()
                }
            } finally { parent.close() }
        } catch (failure: InterruptedIOException) {
            throw failure
        } catch (_: IOException) {
            unsupported()
        } catch (_: LinkageError) {
            unsupported()
        }
    }

    private fun unsupported(): Nothing = throw GitOperationFailure("REPOSITORY_UNSUPPORTED",
        "The repository metadata is not safely readable as bounded ordinary files.")
}
