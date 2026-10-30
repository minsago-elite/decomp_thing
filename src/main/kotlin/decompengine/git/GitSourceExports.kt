package decompengine.git

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
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
    /** Total payload bound; blob reads are batched so every capture stays within the runner's 64 MiB limit. */
    const val MAX_BYTES = 48 * 1024 * 1024
    private const val BATCH_BYTES = 32L * 1024 * 1024
    const val MAX_FILES = 20_000
    // 1980-01-01 00:00 is the JDK's "before 1980" sentinel and would add a time-zone-dependent extended
    // timestamp; one day later is an ordinary DOS time with no extra field in every zone.
    private val FIXED_TIME: LocalDateTime = LocalDateTime.of(1980, 1, 2, 0, 0)

    fun build(runner: GitCommandRunner, gitDir: Path, format: GitObjectFormat, commit: String): GitSourceExport {
        val listing = runner.run(GitInvocation("ls-tree", listOf("-r", "-z", "-l", "--full-tree", format.requireObjectId(commit)), gitDir = gitDir,
            truncateStdout = true, limits = GitExecutionLimits(Duration.ofMinutes(1), 32 * 1024 * 1024, 16 * 1024)))
        if (listing.stdoutTruncated) tooLarge()
        data class Entry(val path: ByteArray, val text: String, val objectId: String, val size: Long)
        val entries = mutableListOf<Entry>()
        val paths = GitExportPaths()
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
            if (!paths.add(text)) throw GitRepositoryException("REPOSITORY_UNSUPPORTED",
                "The tree contains an unsafe or colliding portable archive path and cannot be exported.")
            val size = fields[3].toLongOrNull() ?: throw GitRepositoryException("REPOSITORY_CORRUPT", "The commit tree listing is malformed.")
            total += size
            if (entries.size >= MAX_FILES || total > MAX_BYTES) tooLarge()
            entries += Entry(path, text, format.requireObjectId(fields[2]), size)
        }
        entries.sortWith { left, right -> java.util.Arrays.compareUnsigned(left.path, right.path) }
        val sizes = entries.associate { it.objectId to it.size }
        val batches = mutableListOf<Pair<List<String>, Long>>()
        var batch = mutableListOf<String>(); var batchBytes = 0L
        for (objectId in sizes.keys) {
            val size = sizes.getValue(objectId)
            if (batch.isNotEmpty() && batchBytes + size > BATCH_BYTES) { batches += batch to batchBytes; batch = mutableListOf(); batchBytes = 0 }
            batch += objectId; batchBytes += size
        }
        if (batch.isNotEmpty()) batches += batch to batchBytes
        val contents = readBlobs(runner, gitDir, sizes.keys.toList(), total, batches)
        val output = ByteArrayOutputStream()
        ZipOutputStream(output).use { zip ->
            zip.setMethod(ZipOutputStream.STORED)
            for (entry in entries) {
                val bytes = contents.getValue(entry.objectId)
                writeEntry(zip, entry.text, bytes)
            }
        }
        val bytes = output.toByteArray()
        return GitSourceExport(bytes, GitStorage.sha256(bytes), entries.associate { it.text to it.objectId }, skipped)
    }

    private fun writeEntry(zip: ZipOutputStream, name: String, bytes: ByteArray) {
        val entry = ZipEntry(name).apply {
            method = ZipEntry.STORED
            size = bytes.size.toLong(); compressedSize = bytes.size.toLong()
            crc = CRC32().apply { update(bytes) }.value
            timeLocal = FIXED_TIME
        }
        zip.putNextEntry(entry); zip.write(bytes); zip.closeEntry()
    }

    /** Blob contents through `cat-file --batch`, parsed length-first so any byte content is exact. */
    private fun readBlobs(runner: GitCommandRunner, gitDir: Path, objectIds: List<String>, total: Long,
        batches: List<Pair<List<String>, Long>>): Map<String, ByteArray> {
        if (objectIds.isEmpty()) return emptyMap()
        check(total <= MAX_BYTES)
        val blobs = HashMap<String, ByteArray>()
        for ((batch, bytes) in batches) readBatch(runner, gitDir, batch, bytes, blobs)
        if (!objectIds.all { it in blobs }) throw GitRepositoryException("REPOSITORY_CORRUPT", "A tree blob is missing.")
        return blobs
    }

    private fun readBatch(runner: GitCommandRunner, gitDir: Path, objectIds: List<String>, contentBytes: Long, blobs: MutableMap<String, ByteArray>) {
        // Content plus one header line (at most ~100 bytes) and newline per blob, well under 64 MiB.
        val bound = (contentBytes + objectIds.size * 200L + 4096).toInt()
        val result = runner.run(GitInvocation("cat-file", listOf("--batch"), gitDir = gitDir,
            input = objectIds.joinToString("") { "$it\n" }.toByteArray(), limits = GitExecutionLimits(Duration.ofMinutes(2), bound, 16 * 1024)))
        val output = result.stdout
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
    }

    /**
     * Independent check of an export: every entry's Git blob ID, recomputed from the archive bytes,
     * must equal the commit tree's, with nothing extra. It needs no remote and trusts no ref name.
     * This verifies our deterministic STORED export profile, not arbitrary ZIP variants. Re-encoding
     * into a byte comparator checks every local header, central record and end record too: a local-
     * entry stream alone would silently accept missing/truncated directories or even non-ZIP bytes.
     */
    fun verify(bytes: ByteArray, format: GitObjectFormat, expected: Map<String, String>): Boolean = try {
        verifyEntries(bytes, format, expected)
    } catch (_: IOException) { false }
      catch (_: IllegalArgumentException) { false }

    private fun verifyEntries(bytes: ByteArray, format: GitObjectFormat, expected: Map<String, String>): Boolean {
        val seen = HashMap<String, String>()
        val paths = GitExportPaths()
        var total = 0
        val comparison = ExportByteComparison(bytes)
        ZipOutputStream(comparison).use { canonical ->
            ZipInputStream(ByteArrayInputStream(bytes)).use { zip ->
                while (true) {
                    val entry = zip.nextEntry ?: break
                    if (entry.isDirectory || seen.size >= MAX_FILES || !paths.add(entry.name)) return false
                    val content = zip.readNBytes(MAX_BYTES - total + 1)
                    total += content.size
                    if (total > MAX_BYTES) return false
                    val digest = MessageDigest.getInstance(if (format == GitObjectFormat.SHA256) "SHA-256" else "SHA-1")
                    digest.update("blob ${content.size}\u0000".toByteArray(Charsets.US_ASCII)); digest.update(content)
                    seen[entry.name] = digest.digest().joinToString("") { "%02x".format(it) }
                    writeEntry(canonical, entry.name, content)
                }
            }
        }
        return comparison.complete && seen == expected
    }

    /** Compare as we encode, without retaining a second archive-sized buffer or any temp files. */
    private class ExportByteComparison(private val expected: ByteArray) : OutputStream() {
        private var offset = 0
        val complete get() = offset == expected.size
        override fun write(value: Int) {
            if (offset >= expected.size || expected[offset] != value.toByte()) throw IOException("Noncanonical export ZIP")
            offset++
        }
        override fun write(bytes: ByteArray, start: Int, length: Int) {
            if (length > expected.size - offset || java.util.Arrays.mismatch(expected, offset, offset + length, bytes, start, start + length) != -1)
                throw IOException("Noncanonical export ZIP")
            offset += length
        }
    }

    private fun tooLarge(): Nothing = throw GitRepositoryException("REPOSITORY_UNSUPPORTED", "The commit tree exceeds the export limits.")
}
