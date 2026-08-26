package decompengine.project

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile
import kotlin.io.path.pathString
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.relativeTo
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText

data class ArchivalBundle(
    val archivePath: Path,
    val archiveSha256: String,
    val payloadFiles: List<String>,
)

object ArchivalPackager {
    private const val HASH_MANIFEST = "ARCHIVE_MANIFEST.sha256"

    fun create(projectDir: Path, archivePath: Path): ArchivalBundle {
        require(projectDir.resolve("source_tree_manifest.json").isRegularFile()) { "project is missing source_tree_manifest.json" }
        ArchivalProjectAuditor.audit(projectDir)
        val readme = projectDir.resolve("ARCHIVE_README.md")
        readme.writeText(
            """
            # Reconstructed archival source tree

            This project was reconstructed from a binary using evidence-backed analysis and may not be universally equivalent to the original.

            Build with the exact parallel warnings-as-errors command in `BUILDING.md`. The recovered program model, module plan, confidence, unresolved entities, build logs, and per-module provenance are under `reports/`.
            Verify payload hashes with `ARCHIVE_MANIFEST.sha256` before use.
            """.trimIndent() + "\n",
        )
        val archiveAbsolute = archivePath.toAbsolutePath().normalize()
        val payload = Files.walk(projectDir).use { paths ->
            paths.filter { it.isRegularFile() }
                .filter { it.toAbsolutePath().normalize() != archiveAbsolute }
                .filter { !it.relativeTo(projectDir).pathString.replace('\\', '/').startsWith("build/") }
                .filter { it.fileName.toString() != HASH_MANIFEST }
                .map { it.relativeTo(projectDir).pathString.replace('\\', '/') to it.readBytes() }
                .toList().sortedBy { it.first }
        }
        val hashManifest = payload.joinToString("", postfix = "") { (path, bytes) -> "${sha256(bytes)}  $path\n" }.toByteArray()
        projectDir.resolve(HASH_MANIFEST).writeBytes(hashManifest)
        archivePath.parent?.createDirectories()
        ZipOutputStream(Files.newOutputStream(archivePath, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)).use { zip ->
            (payload + (HASH_MANIFEST to hashManifest)).sortedBy { it.first }.forEach { (path, bytes) ->
                val crc = CRC32().apply { update(bytes) }
                val entry = ZipEntry(path).apply {
                    method = ZipEntry.STORED
                    size = bytes.size.toLong()
                    compressedSize = bytes.size.toLong()
                    this.crc = crc.value
                    time = 0L
                    creationTime = java.nio.file.attribute.FileTime.fromMillis(0)
                    lastAccessTime = java.nio.file.attribute.FileTime.fromMillis(0)
                    lastModifiedTime = java.nio.file.attribute.FileTime.fromMillis(0)
                }
                zip.putNextEntry(entry)
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return ArchivalBundle(archivePath, sha256(archivePath.readBytes()), payload.map { it.first })
    }
}

object ArchivalBundleVerifier {
    private const val HASH_MANIFEST = "ARCHIVE_MANIFEST.sha256"

    fun extractAndVerify(archivePath: Path, targetDir: Path): List<Path> {
        targetDir.createDirectories()
        val targetBase = targetDir.toAbsolutePath().normalize()
        val extracted = mutableListOf<Path>()
        val seen = mutableSetOf<String>()
        ZipFile(archivePath.toFile()).use { zip ->
            val entries = zip.entries().asSequence().toList()
            require(entries.none { it.isDirectory }) { "archive contains directory entries" }
            entries.forEach { entry ->
                val normalizedName = entry.name.replace('\\', '/')
                require(normalizedName.isNotBlank() && normalizedName !in seen) { "archive contains a duplicate or blank path" }
                require(!normalizedName.startsWith('/') && normalizedName.split('/').none { it == ".." || it.isBlank() }) {
                    "archive entry escapes extraction target: ${entry.name}"
                }
                seen += normalizedName
                val target = targetBase.resolve(normalizedName).normalize()
                require(target.startsWith(targetBase)) { "archive entry escapes extraction target: ${entry.name}" }
                target.parent.createDirectories()
                target.writeBytes(zip.getInputStream(entry).use { it.readBytes() })
                extracted.add(target)
            }
        }
        val manifestPath = targetDir.resolve(HASH_MANIFEST)
        require(manifestPath.exists()) { "archive is missing $HASH_MANIFEST" }
        val expected = manifestPath.readText().lineSequence().filter(String::isNotBlank).associate { line ->
            val hash = line.substringBefore("  ")
            val relative = line.substringAfter("  ", "")
            require(hash.matches(Regex("[a-f0-9]{64}")) && relative.isNotBlank()) { "invalid archive hash manifest line" }
            relative to hash
        }
        require(seen == expected.keys + HASH_MANIFEST) { "archive entries do not match the hash manifest" }
        expected.forEach { (relative, hash) ->
            require(sha256(targetDir.resolve(relative).readBytes()) == hash) { "archive payload hash mismatch: $relative" }
        }
        return extracted
    }
}
