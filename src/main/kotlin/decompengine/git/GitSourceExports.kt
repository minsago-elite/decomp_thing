package decompengine.git

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import java.time.LocalDateTime
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

/**
 * Deterministic source export of one commit tree (#582). The payload holds only the tree's
 * regular files, never `.git`, reflogs, configuration, or commit metadata. Entries are stored
 * uncompressed in byte order of their paths, with a fixed timestamp and no extra fields, so equal
 * trees produce identical bytes regardless of commit time, author or work-tree state. Provenance
 * (object ID, refs, mapping) travels in a separate envelope, never inside the payload.
 */
data class GitSourceExport(
    val bytes: ByteArray,
    val sha256: String,
    /** `path -> Git blob ID` of every exported file, for independent verification. */
    val blobs: Map<String, String>,
    /** Tree entries that are not regular files (submodule links and symbolic links), omitted. */
    val skippedEntries: Int,
)

/** One commit's provenance; [refNames] are display labels and never part of any identity. */
data class GitProvenanceView(
    val record: GitRepositoryRecord,
    val commit: GitHistoryEntry,
    val refNames: List<String>,
    val mapping: GitMappingView?,
    val export: GitSourceExport,
    val verified: Boolean,
)

object GitSourceExports {
    const val MAX_BYTES = 64 * 1024 * 1024
    const val MAX_FILES = 20_000
    private val FIXED_TIME: LocalDateTime = LocalDateTime.of(1980, 1, 1, 0, 0)

    fun build(runner: GitCommandRunner, gitDir: Path, format: GitObjectFormat, commit: String): GitSourceExport {
        val listing = runner.run(GitInvocation("ls-tree", listOf("-r", "-z", "-l", "--full-tree", format.requireObjectId(commit)), gitDir = gitDir,
            truncateStdout = true, limits = GitExecutionLimits(Duration.ofMinutes(1), 32 * 1024 * 1024, 16 * 1024)))
        if (listing.stdoutTruncated) tooLarge()
        data class Entry(val path: ByteArray, val text: String, val objectId: String, val size: Long)
        val entries = mutableListOf<Entry>()
        var skipped = 0
        var total = 0L
        for (record in GitReads.records(listing.stdout)) {
            if (record.isEmpty()) continue
            val tab = record.indexOf('\t'.code.toByte())
            val fields = String(record, 0, maxOf(tab, 0), Charsets.US_ASCII).split(' ').filter { it.isNotEmpty() }
            if (tab < 0 || fields.size != 4) throw GitRepositoryException("REPOSITORY_CORRUPT", "The commit tree listing is malformed.")
            if (fields[1] != "blob" || fields[0] !in setOf("100644", "100755")) { skipped++; continue }
            val path = record.copyOfRange(tab + 1, record.size)
            val text = GitPath.of(path).exact ?: throw GitRepositoryException("REPOSITORY_UNSUPPORTED", "A file name is not valid UTF-8 and cannot be exported.")
            val size = fields[3].toLongOrNull() ?: throw GitRepositoryException("REPOSITORY_CORRUPT", "The commit tree listing is malformed.")
            total += size
            if (entries.size >= MAX_FILES || total > MAX_BYTES) tooLarge()
            entries += Entry(path, text, format.requireObjectId(fields[2]), size)
        }
        entries.sortWith { left, right -> java.util.Arrays.compareUnsigned(left.path, right.path) }
        val contents = readBlobs(runner, gitDir, entries.map { it.objectId }.distinct(), total)
        val output = ByteArrayOutputStream()
        ZipOutputStream(output).use { zip ->
            zip.setMethod(ZipOutputStream.STORED)
            for (entry in entries) {
                val bytes = contents.getValue(entry.objectId)
                val zipEntry = ZipEntry(entry.text).apply {
                    method = ZipEntry.STORED
                    size = bytes.size.toLong(); compressedSize = bytes.size.toLong()
                    crc = CRC32().apply { update(bytes) }.value
                    timeLocal = FIXED_TIME
                }
                zip.putNextEntry(zipEntry); zip.write(bytes); zip.closeEntry()
            }
        }
        val bytes = output.toByteArray()
        return GitSourceExport(bytes, GitStorage.sha256(bytes), entries.associate { it.text to it.objectId }, skipped)
    }

    /** Blob contents through `cat-file --batch`, parsed length-first so any byte content is exact. */
    private fun readBlobs(runner: GitCommandRunner, gitDir: Path, objectIds: List<String>, total: Long): Map<String, ByteArray> {
        if (objectIds.isEmpty()) return emptyMap()
        val bound = (total + objectIds.size * 200L + 4096).coerceAtMost(MAX_BYTES + 8L * 1024 * 1024).toInt()
        val result = runner.run(GitInvocation("cat-file", listOf("--batch"), gitDir = gitDir,
            input = objectIds.joinToString("") { "$it\n" }.toByteArray(), limits = GitExecutionLimits(Duration.ofMinutes(2), bound, 16 * 1024)))
        val output = result.stdout
        val blobs = HashMap<String, ByteArray>()
        var offset = 0
        while (offset < output.size) {
            val newline = (offset until output.size).firstOrNull { output[it] == '\n'.code.toByte() }
                ?: throw GitRepositoryException("REPOSITORY_CORRUPT", "Blob output is malformed.")
            val header = String(output, offset, newline - offset, Charsets.US_ASCII).split(' ')
            if (header.size != 3 || header[1] != "blob") throw GitRepositoryException("REPOSITORY_CORRUPT", "A tree entry is not a readable blob.")
            val size = header[2].toInt()
            val start = newline + 1
            if (start + size + 1 > output.size) throw GitRepositoryException("REPOSITORY_CORRUPT", "Blob output is truncated.")
            blobs[header[0]] = output.copyOfRange(start, start + size)
            offset = start + size + 1
        }
        if (!objectIds.all { it in blobs }) throw GitRepositoryException("REPOSITORY_CORRUPT", "A tree blob is missing.")
        return blobs
    }

    /**
     * Independent check of an export: every entry's Git blob ID, recomputed from the archive bytes,
     * must equal the commit tree's, with nothing extra. It needs no remote and trusts no ref name.
     */
    fun verify(bytes: ByteArray, format: GitObjectFormat, expected: Map<String, String>): Boolean = try {
        verifyEntries(bytes, format, expected)
    } catch (_: java.io.IOException) { false }

    private fun verifyEntries(bytes: ByteArray, format: GitObjectFormat, expected: Map<String, String>): Boolean {
        val seen = HashMap<String, String>()
        ZipInputStream(ByteArrayInputStream(bytes)).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                if (entry.isDirectory || entry.name in seen || entry.name.split('/').any { it == ".git" || it == ".." }) return false
                val content = zip.readAllBytes()
                val digest = MessageDigest.getInstance(if (format == GitObjectFormat.SHA256) "SHA-256" else "SHA-1")
                digest.update("blob ${content.size}\u0000".toByteArray(Charsets.US_ASCII)); digest.update(content)
                seen[entry.name] = digest.digest().joinToString("") { "%02x".format(it) }
            }
        }
        return seen == expected
    }

    private fun tooLarge(): Nothing = throw GitRepositoryException("REPOSITORY_UNSUPPORTED", "The commit tree exceeds the export limits.")
}
