package decompengine.testing

import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom

/**
 * Owner-only fixture directories for Unix domain sockets.
 *
 * Linux limits `sun_path` to 108 bytes, so `Files.createTempDirectory` names (prefix plus up to 20 digits)
 * under a repository-local `java.io.tmpdir` can push socket paths over the limit in nested worktrees.
 * This creates a six-character directory directly under `java.io.tmpdir` instead.
 */
object ShortSocketDirectory {
    private const val ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
    private val random = SecureRandom()

    fun create(): Path {
        val parent = Path.of(System.getProperty("java.io.tmpdir")).toAbsolutePath().normalize()
        repeat(64) {
            val name = String(CharArray(6) { ALPHABET[random.nextInt(ALPHABET.length)] })
            try {
                return Files.createDirectory(parent.resolve(name),
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            } catch (_: FileAlreadyExistsException) {
                // Try another name.
            }
        }
        error("no unused short socket directory under $parent")
    }
}
