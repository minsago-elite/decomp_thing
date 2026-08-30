package decompengine.oracle.gcc

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

class AuthenticatedGhidraInstallation internal constructor(
    val home: Path,
    val archivePath: Path,
    val archiveSha256: String,
    val fileCount: Int,
)

/** Proves that the runnable Ghidra tree contains exactly the bytes in the authenticated release archive. */
fun GccCompilerEngineAnalysisToolchain.authenticateGhidraInstallation(
    archivePath: Path,
    homePath: Path,
): AuthenticatedGhidraInstallation {
    val archiveBefore = authenticateGhidraArchive(archivePath)
    val home = requireGhidraHome(homePath)
    val expectedRootName = "ghidra_${ghidraVersion}_${ghidraRelease}"
    if (home.fileName.toString() != expectedRootName) {
        installationFailure("Ghidra home name differs from its authenticated archive root")
    }
    val homeBefore = stableDirectory(home, "Ghidra installation")
    val fileCount = authenticateArchiveTree(archiveBefore.path, home, expectedRootName)
    val archiveAfter = authenticateGhidraArchive(archiveBefore.path)
    val homeAfter = stableDirectory(home, "Ghidra installation")
    if (
        archiveBefore.path != archiveAfter.path || archiveBefore.bytes != archiveAfter.bytes ||
        archiveBefore.sha256 != archiveAfter.sha256 || !sameVersion(homeBefore, homeAfter)
    ) {
        installationFailure("Ghidra archive or installation changed while it was authenticated")
    }
    return AuthenticatedGhidraInstallation(home, archiveBefore.path, archiveBefore.sha256, fileCount)
}

private fun authenticateArchiveTree(archivePath: Path, home: Path, rootName: String): Int {
    val expectedFiles = linkedSetOf<Path>()
    val expectedDirectories = linkedSetOf<Path>()
    var uncompressedBytes = 0L
    try {
        ZipFile(archivePath.toFile()).use { archive ->
            if (archive.size() !in 1..MAXIMUM_GHIDRA_ARCHIVE_ENTRIES) {
                installationFailure("Ghidra archive entry count is outside the supported bound")
            }
            val entries = archive.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                val relative = authenticatedRelativePath(entry, rootName)
                if (relative == null) continue
                val target = home.resolve(relative).normalize()
                if (!target.startsWith(home)) installationFailure("Ghidra archive entry escapes its installation root")
                if (entry.isDirectory) {
                    if (!expectedDirectories.add(relative)) installationFailure("Ghidra archive repeats a directory entry")
                    continue
                }
                if (!expectedFiles.add(relative)) installationFailure("Ghidra archive repeats a file entry")
                if (entry.size !in 0..MAXIMUM_GHIDRA_ARCHIVE_FILE_BYTES) {
                    installationFailure("Ghidra archive file size is outside the supported bound")
                }
                uncompressedBytes = try {
                    Math.addExact(uncompressedBytes, entry.size)
                } catch (_: ArithmeticException) {
                    installationFailure("Ghidra archive uncompressed size overflows the supported range")
                }
                if (uncompressedBytes > MAXIMUM_GHIDRA_ARCHIVE_UNCOMPRESSED_BYTES) {
                    installationFailure("Ghidra archive uncompressed size exceeds the supported bound")
                }
                authenticateEntryBytes(archive, entry, target)
            }
        }
        authenticateExactTree(home, expectedFiles, expectedDirectories)
    } catch (failure: GccCompilerEngineProfileException) {
        throw failure
    } catch (failure: Exception) {
        throw GccCompilerEngineProfileException("cannot authenticate the Ghidra installation tree", failure)
    }
    if (expectedFiles.isEmpty()) installationFailure("Ghidra archive contains no installation files")
    return expectedFiles.size
}

private fun authenticatedRelativePath(entry: ZipEntry, rootName: String): Path? {
    val name = entry.name
    if (
        name.isBlank() || name.length > MAXIMUM_GHIDRA_ARCHIVE_PATH_CHARACTERS || '\\' in name ||
        name.startsWith('/') || name.any { it.code < 0x20 || it.code == 0x7f }
    ) {
        installationFailure("Ghidra archive contains an invalid path")
    }
    val prefix = "$rootName/"
    if (!name.startsWith(prefix)) installationFailure("Ghidra archive contains more than one installation root")
    if (name == prefix) {
        if (!entry.isDirectory) installationFailure("Ghidra archive root is not a directory")
        return null
    }
    if (entry.isDirectory != name.endsWith('/')) {
        installationFailure("Ghidra archive entry kind and path disagree")
    }
    val relativeText = name.removePrefix(prefix).removeSuffix("/")
    val components = relativeText.split('/')
    if (components.any { it.isBlank() || it == "." || it == ".." || it.length > 255 }) {
        installationFailure("Ghidra archive contains a non-normalized path")
    }
    val relative = Path.of(relativeText).normalize()
    if (relative.isAbsolute || relative.toString() != relativeText) {
        installationFailure("Ghidra archive contains a non-normalized path")
    }
    return relative
}

private fun authenticateEntryBytes(archive: ZipFile, entry: ZipEntry, target: Path) {
    val parent = target.parent ?: installationFailure("Ghidra archive file has no installation parent")
    val parentBefore = stableDirectory(parent, "Ghidra installation directory")
    val before = stableFile(target, "Ghidra installation file")
    val permissions = trustedPermissions(target, "Ghidra installation file")
    if (before.size() != entry.size) installationFailure("Ghidra installation file size differs from its archive")
    archive.getInputStream(entry).use { expected ->
        Files.newInputStream(target, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { actual ->
            val expectedBuffer = ByteArray(COPY_BUFFER_BYTES)
            val actualBuffer = ByteArray(COPY_BUFFER_BYTES)
            var observed = 0L
            while (true) {
                val count = expected.read(expectedBuffer)
                if (count < 0) break
                if (count == 0) continue
                val actualCount = actual.readNBytes(actualBuffer, 0, count)
                if (actualCount != count) installationFailure("Ghidra installation file ended before its archive entry")
                for (index in 0 until count) {
                    if (expectedBuffer[index] != actualBuffer[index]) {
                        installationFailure("Ghidra installation file bytes differ from its archive entry")
                    }
                }
                observed = Math.addExact(observed, count.toLong())
            }
            if (observed != entry.size || actual.read() >= 0) {
                installationFailure("Ghidra installation file length differs from its archive entry")
            }
        }
    }
    val after = stableFile(target, "Ghidra installation file")
    val parentAfter = stableDirectory(parent, "Ghidra installation directory")
    if (
        !sameVersion(before, after) || parentBefore.fileKey() != parentAfter.fileKey() ||
        permissions != trustedPermissions(target, "Ghidra installation file")
    ) {
        installationFailure("Ghidra installation file changed while it was authenticated")
    }
}

private fun authenticateExactTree(home: Path, expectedFiles: Set<Path>, expectedDirectories: Set<Path>) {
    val actualFiles = linkedSetOf<Path>()
    val actualDirectories = linkedSetOf<Path>()
    Files.walk(home).use { paths ->
        paths.forEach { candidate ->
            if (candidate == home) return@forEach
            val attributes = Files.readAttributes(
                candidate,
                BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
            if (attributes.isSymbolicLink || candidate.toRealPath() != candidate) {
                installationFailure("Ghidra installation contains a symbolic link")
            }
            trustedPermissions(candidate, "Ghidra installation entry")
            val relative = home.relativize(candidate)
            when {
                attributes.isRegularFile -> actualFiles.add(relative)
                attributes.isDirectory -> actualDirectories.add(relative)
                else -> installationFailure("Ghidra installation contains an unsupported filesystem entry")
            }
        }
    }
    if (actualFiles != expectedFiles || actualDirectories != expectedDirectories) {
        installationFailure("Ghidra installation membership differs from its authenticated archive")
    }
}

private fun installationFailure(message: String): Nothing = throw GccCompilerEngineProfileException(message)

private const val MAXIMUM_GHIDRA_ARCHIVE_ENTRIES = 20_000
private const val MAXIMUM_GHIDRA_ARCHIVE_PATH_CHARACTERS = 4_096
private const val MAXIMUM_GHIDRA_ARCHIVE_FILE_BYTES = 128L * 1024 * 1024
private const val MAXIMUM_GHIDRA_ARCHIVE_UNCOMPRESSED_BYTES = 2L * 1024 * 1024 * 1024
private const val COPY_BUFFER_BYTES = 1024 * 1024
