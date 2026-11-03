package decompengine.jobs

import java.io.IOException
import java.nio.file.DirectoryIteratorException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.SecureDirectoryStream
import java.nio.file.attribute.BasicFileAttributeView

/** Display categories for retained bytes. Classification uses fixed store layout names only. */
enum class StorageCategory(val wireName: String) {
    ORIGINAL_INPUTS("originalInputs"), REPORTS("reports"), SOURCE_SNAPSHOTS("sourceSnapshots"), LOGS("logs"),
    ARCHIVES("archives"), METADATA("metadata"), TEMPORARY("temporary"), OTHER("other"),
}

data class StorageTally(val bytes: Long = 0, val entries: Long = 0) {
    operator fun plus(other: StorageTally) = StorageTally(saturating(bytes, other.bytes), saturating(entries, other.entries))
    private fun saturating(left: Long, right: Long) = if (Long.MAX_VALUE - left < right) Long.MAX_VALUE else left + right
}

data class StorageBreakdown(val categories: Map<StorageCategory, StorageTally>) {
    val total: StorageTally get() = categories.values.fold(StorageTally()) { sum, tally -> sum + tally }
    fun bytes(category: StorageCategory): Long = categories[category]?.bytes ?: 0
    companion object {
        val EMPTY = StorageBreakdown(StorageCategory.entries.associateWith { StorageTally() })
    }
}

/** A complete or explicitly partial read-only scan; partial totals are lower bounds only. */
data class StorageScan(
    val library: StorageBreakdown,
    val jobs: Map<String, StorageBreakdown>,
    val pendingDeletions: Map<String, StorageTally>,
    val scannedEntries: Long,
    val uninspectedEntries: Long,
    val complete: Boolean,
)

/**
 * Bounded, read-only, tolerant accounting of the owned job root. It uses no-follow secure
 * directory streams: symbolic links are charged as zero-byte entries and never traversed, and
 * nothing is opened for writing. Concurrent changes can make a scan partial, never invalid.
 * Logical regular-file lengths only; directory entries count but carry no bytes.
 */
internal object JobStorageAccounting {
    private val jobName = Regex("[0-9a-f]{32}")
    private val removingName = Regex("jobdel_[0-9a-f]{32}\\.removing")

    fun scan(
        root: Path,
        onlyJob: String? = null,
        maximumEntries: Long = 200_000,
        maximumNanos: Long = 5_000_000_000L,
        nanoTime: () -> Long = System::nanoTime,
    ): StorageScan {
        require(onlyJob == null || jobName.matches(onlyJob))
        val started = nanoTime()
        val library = StorageCategory.entries.associateWith { StorageTally() }.toMutableMap()
        val jobs = linkedMapOf<String, MutableMap<StorageCategory, StorageTally>>()
        val pending = linkedMapOf<String, StorageTally>()
        var scanned = 0L
        var uninspected = 0L
        var complete = true
        fun exhausted(): Boolean {
            if (scanned >= maximumEntries || nanoTime() - started > maximumNanos || Thread.currentThread().isInterrupted) {
                complete = false
                return true
            }
            return false
        }
        fun charge(category: StorageCategory, bytes: Long, job: String?, removing: String?) {
            val tally = StorageTally(bytes, 1)
            library[category] = library.getValue(category) + tally
            if (job != null) jobs.getOrPut(job) { StorageCategory.entries.associateWith { StorageTally() }.toMutableMap() }
                .let { it[category] = it.getValue(category) + tally }
            if (removing != null) pending[removing] = (pending[removing] ?: StorageTally()) + tally
        }
        fun visit(directory: SecureDirectoryStream<Path>, segments: List<String>, depth: Int) {
            if (depth > 64) { uninspected++; complete = false; return }
            try {
                for (entry in directory) {
                    if (exhausted()) return
                    val name = entry.fileName.toString()
                    val path = segments + name
                    if (onlyJob != null && segments.isEmpty() && name != onlyJob) continue
                    scanned++
                    try {
                        val attributes = directory.getFileAttributeView(entry.fileName, BasicFileAttributeView::class.java, NOFOLLOW_LINKS).readAttributes()
                        val job = path.first().takeIf { jobName.matches(it) }
                        val removing = if (path.size >= 2 && path[0] == JobDeletionStore.DIRECTORY && removingName.matches(path[1]))
                            path[1].removeSuffix(".removing") else null
                        when {
                            attributes.isDirectory && !attributes.isSymbolicLink -> {
                                if (removing != null && path.size == 2) pending.putIfAbsent(removing, StorageTally())
                                // Every directory below the scan root is an entry with no bytes, including empty ones.
                                charge(classifyDirectory(path), 0, job, removing)
                                directory.newDirectoryStream(entry.fileName, NOFOLLOW_LINKS).use { child ->
                                    visit(child as SecureDirectoryStream<Path>, path, depth + 1)
                                }
                            }
                            attributes.isRegularFile -> charge(classify(path), attributes.size(), job, removing)
                            else -> charge(if (removing != null) StorageCategory.TEMPORARY else StorageCategory.OTHER, 0, job, removing)
                        }
                    } catch (_: IOException) { uninspected++; complete = false }
                    catch (_: ClassCastException) { uninspected++; complete = false }
                }
            } catch (_: DirectoryIteratorException) { uninspected++; complete = false }
        }
        if (!Files.notExists(root, NOFOLLOW_LINKS)) {
            try {
                Files.newDirectoryStream(root).use { stream ->
                    if (stream is SecureDirectoryStream<Path>) visit(stream, emptyList(), 0) else { uninspected++; complete = false }
                }
            } catch (_: IOException) { uninspected++; complete = false }
        }
        return StorageScan(StorageBreakdown(library.toMap()), jobs.mapValues { StorageBreakdown(it.value.toMap()) },
            pending.toMap(), scanned, uninspected, complete)
    }

    /** Segments are relative to the job root; the first selects a job, upload stage or journal. */
    internal fun classify(path: List<String>): StorageCategory {
        val first = path.first()
        val name = path.last()
        return when {
            jobName.matches(first) -> classifyJob(path.drop(1))
            first.startsWith(".upload-") -> StorageCategory.TEMPORARY
            first == JobDeletionStore.DIRECTORY -> if (path.size == 2 && name.endsWith(".json")) StorageCategory.METADATA else StorageCategory.TEMPORARY
            first == ".workflow-owner.lock" && path.size == 1 -> StorageCategory.METADATA
            else -> StorageCategory.OTHER
        }
    }

    /** Directories take the category of the content their fixed layout position holds. */
    internal fun classifyDirectory(path: List<String>): StorageCategory {
        val first = path.first()
        return when {
            jobName.matches(first) -> when {
                path.size == 1 -> StorageCategory.METADATA
                path[1] != "reports" -> StorageCategory.OTHER
                "source-tree" in path -> StorageCategory.SOURCE_SNAPSHOTS
                "logs" in path -> StorageCategory.LOGS
                else -> StorageCategory.REPORTS
            }
            first.startsWith(".upload-") -> StorageCategory.TEMPORARY
            first == JobDeletionStore.DIRECTORY -> if (path.size == 1) StorageCategory.METADATA else StorageCategory.TEMPORARY
            else -> StorageCategory.OTHER
        }
    }

    private fun classifyJob(path: List<String>): StorageCategory {
        if (path.isEmpty()) return StorageCategory.OTHER
        val name = path.last()
        if (path.size == 1) return when {
            name == "input.elf" -> StorageCategory.ORIGINAL_INPUTS
            name in setOf("job.json", "workflow-state.json", JobOrganization.FILE_NAME, "upload-receipt.json") -> StorageCategory.METADATA
            name.startsWith(".job-metadata-") || name.endsWith(".tmp") || name.endsWith(".pending.json") -> StorageCategory.TEMPORARY
            else -> StorageCategory.OTHER
        }
        if (path.first() != "reports") return StorageCategory.OTHER
        return when {
            "source-tree" in path.dropLast(1) || name == "source-tree" -> StorageCategory.SOURCE_SNAPSHOTS
            name.endsWith(".tmp") || name.endsWith(".pending.json") || name.startsWith(".") && name.contains("tmp") -> StorageCategory.TEMPORARY
            name.startsWith("agent-progress") || name.endsWith(".log") || name.endsWith(".jsonl") || name.endsWith(".ndjson") ||
                "logs" in path.dropLast(1) -> StorageCategory.LOGS
            listOf(".zip", ".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.zst").any(name::endsWith) -> StorageCategory.ARCHIVES
            else -> StorageCategory.REPORTS
        }
    }
}
