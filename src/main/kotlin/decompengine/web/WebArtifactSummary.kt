package decompengine.web

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.FileVisitResult
import decompengine.repair.RepairHistoryReadResult
import decompengine.repair.RepairRecordedHistoryPage
import decompengine.repair.RepairRecordedHistorySelection

/** Display metadata only; download authorization still validates the selected artifact. */
data class WebArtifactSummary(val relativePath: String, val displayName: String, val sizeBytes: Long)

internal fun listLegacyArtifactSummaries(context: WebReportContext): List<WebArtifactSummary> =
    listLegacyArtifactSummaries(context, null)

internal fun listLegacyArtifactSummaries(context: WebReportContext, recordedRepair: RepairHistoryReadResult?): List<WebArtifactSummary> =
    listLegacyArtifactSummaries(context, recordedRepair, recordedRepair?.snapshot?.let {
        RepairRecordedHistoryPage.select(it, RepairRecordedHistorySelection(), MAXIMUM_VISIBLE_RECORDED_REPAIR_ATTEMPTS) })

internal fun listLegacyArtifactSummaries(context: WebReportContext, recordedRepair: RepairHistoryReadResult?,
    page: RepairRecordedHistoryPage?): List<WebArtifactSummary> {
    val snapshot = recordedRepair?.snapshot
    require(if (snapshot == null) page == null else page?.snapshot === snapshot) {
        "Recorded history page does not match its capture."
    }
    val root = context.reportsDirectory
    val attributes = try { Files.readAttributes(root, BasicFileAttributes::class.java, NOFOLLOW_LINKS) }
        catch (_: java.nio.file.NoSuchFileException) { return emptyList() }
    require(attributes.isDirectory) { "report listing root is not a directory" }
    val summaries = mutableListOf<WebArtifactSummary>()
    var entries = 0
    val sourceTree = root.resolve("source-tree")
    // One listing observation only; these metadata hints never authorize a download.
    val selectedMetadata = mutableMapOf<Path, BasicFileAttributes?>()
    Files.walkFileTree(root, object : java.nio.file.SimpleFileVisitor<Path>() {
        override fun preVisitDirectory(directory: Path, attributes: BasicFileAttributes): FileVisitResult {
            require(++entries <= 10_000 && root.relativize(directory).nameCount <= 32) { "report listing exceeds its traversal bound" }
            if (directory == sourceTree) {
                selectedMetadata[directory] = attributes
                return FileVisitResult.SKIP_SUBTREE
            }
            return if (directory == root.resolve("runs")) FileVisitResult.SKIP_SUBTREE else FileVisitResult.CONTINUE
        }
        override fun visitFile(file: Path, attributes: BasicFileAttributes): FileVisitResult {
            require(++entries <= 10_000) { "report listing exceeds its entry bound" }
            if (attributes.isRegularFile) {
                val relative = root.relativize(file).toString().replace('\\', '/')
                summaries += WebArtifactSummary("${context.artifactPrefix}/$relative", file.fileName.toString(), attributes.size())
            }
            return FileVisitResult.CONTINUE
        }
    })
    if (snapshot != null) {
        requireNotNull(recordedRepair).selectedArtifactPaths(requireNotNull(page)).forEach { logical ->
            val target = "${context.artifactPrefix}/source-tree/$logical"
            // Validate the same closed namespace before any metadata query.
            if (recordedRepairLogicalArtifactPath(target, context) != logical) return@forEach
            val parts = listOf("source-tree") + logical.split('/')
            var candidate = root
            parts.forEachIndexed { index, part ->
                candidate = candidate.resolve(part)
                if (index != parts.lastIndex) require(root.relativize(candidate).nameCount <= 32) {
                    "report listing exceeds its traversal bound"
                }
                val current = if (selectedMetadata.containsKey(candidate)) selectedMetadata[candidate] else {
                    require(++entries <= 10_000) { "report listing exceeds its entry bound" }
                    val observed = try { Files.readAttributes(candidate, BasicFileAttributes::class.java, NOFOLLOW_LINKS) }
                        catch (_: java.nio.file.NoSuchFileException) { null }
                    selectedMetadata[candidate] = observed
                    observed
                }
                if (index != parts.lastIndex) {
                    if (current?.isDirectory != true) return@forEach
                } else if (current?.isRegularFile == true) {
                    summaries += WebArtifactSummary(target, "Repair evidence", current.size())
                }
            }
        }
    }
    return summaries.sortedBy { it.relativePath }
}
