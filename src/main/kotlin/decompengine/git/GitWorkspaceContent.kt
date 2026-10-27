package decompengine.git

import decompengine.git.GitStorage.hex
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.WRITE
import java.security.MessageDigest

/** Bounded content commitments, shared by reviewed status and the bytes captured for staging. */
internal object GitWorkspaceContent {
    class Budget(var remaining: Long = GitSourceCopy.MAX_BYTES)

    /** Never follow a leaf link. The optional destination receives exactly the hashed bytes. */
    fun fingerprint(root: Path, file: Path, budget: Budget, destination: Path? = null): String {
        val stat = GitRepositoryInspector.worktreeStat(root, file) ?: return "absent"
        if (stat.isDirectory) return "directory"
        if (!stat.isRegularFile && !stat.isSymbolicLink) unavailable()
        var ancestor = file.parent
        while (ancestor != root) {
            if (ancestor == null || !Files.isDirectory(ancestor, NOFOLLOW_LINKS)) unavailable()
            ancestor = ancestor.parent
        }
        val digest = MessageDigest.getInstance("SHA-256")
        val mode = if (stat.isSymbolicLink) "120000" else if (Files.isExecutable(file)) "100755" else "100644"
        val output = destination?.let { Files.newOutputStream(it, CREATE_NEW, WRITE) }
        try {
            if (stat.isSymbolicLink) {
                val target = Files.readSymbolicLink(file).toString()
                // Do not silently authorize a lossy native filename conversion.
                if ('\uFFFD' in target) unavailable()
                val bytes = target.toByteArray(Charsets.UTF_8)
                consume(bytes, bytes.size, budget, digest, output)
            } else {
                if (stat.size() > budget.remaining) unavailable()
                Files.newInputStream(file, NOFOLLOW_LINKS).use { input ->
                    val buffer = ByteArray(64 * 1024)
                    var size = 0L
                    while (true) {
                        GitStorage.checkInterrupted()
                        val count = input.read(buffer)
                        if (count < 0) break
                        size += count
                        if (size > stat.size()) unavailable()
                        consume(buffer, count, budget, digest, output)
                    }
                    if (size != stat.size()) unavailable()
                }
            }
        } finally { output?.close() }
        return "$mode:${digest.digest().hex()}"
    }

    private fun consume(bytes: ByteArray, count: Int, budget: Budget, digest: MessageDigest, output: OutputStream?) {
        if (count > budget.remaining) unavailable()
        budget.remaining -= count
        digest.update(bytes, 0, count)
        output?.write(bytes, 0, count)
    }

    private fun unavailable(): Nothing = throw GitRepositoryException("REPOSITORY_UNAVAILABLE",
        "Work-tree content could not be captured exactly within its bounds. Read the current status before trying again.")
}
