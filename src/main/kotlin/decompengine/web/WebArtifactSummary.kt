package decompengine.web

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.FileVisitResult
import decompengine.repair.RepairHistorySnapshot
import decompengine.repair.recordedRepairArtifactReference
import decompengine.repair.RepairRecordedHistoryPage
import decompengine.repair.RepairRecordedHistorySelection

/** Display metadata only; download authorization still validates the selected artifact. */
data class WebArtifactSummary(val relativePath: String, val displayName: String, val sizeBytes: Long)

internal fun listLegacyArtifactSummaries(context: WebReportContext): List<WebArtifactSummary> =
    listLegacyArtifactSummaries(context, null)

internal fun listLegacyArtifactSummaries(context: WebReportContext, recordedRepair: RepairHistorySnapshot?): List<WebArtifactSummary> =
    listLegacyArtifactSummaries(context, recordedRepair, recordedRepair?.let {
        RepairRecordedHistoryPage.select(it, RepairRecordedHistorySelection(), MAXIMUM_VISIBLE_RECORDED_REPAIR_ATTEMPTS) })

internal fun listLegacyArtifactSummaries(context: WebReportContext, recordedRepair: RepairHistorySnapshot?,
    page: RepairRecordedHistoryPage?): List<WebArtifactSummary> {
    require(if (recordedRepair == null) page == null else page?.snapshot === recordedRepair) {
        "Recorded history page does not match its capture."
    }
    val root = context.reportsDirectory
    val attributes = try { Files.readAttributes(root, BasicFileAttributes::class.java, NOFOLLOW_LINKS) }
        catch (_: java.nio.file.NoSuchFileException) { return emptyList() }
    require(attributes.isDirectory) { "report listing root is not a directory" }
    val summaries = mutableListOf<WebArtifactSummary>()
    var entries = 0
    val sourceTree = root.resolve("source-tree")
    val sourceReports = sourceTree.resolve("reports")
    val references = recordedRepair?.let { recordedRepairArtifactReferences(it, requireNotNull(page)) }.orEmpty()
    Files.walkFileTree(root, object : java.nio.file.SimpleFileVisitor<Path>() {
        override fun preVisitDirectory(directory: Path, attributes: BasicFileAttributes): FileVisitResult {
            require(++entries <= 10_000 && root.relativize(directory).nameCount <= 32) { "report listing exceeds its traversal bound" }
            if (directory == sourceTree) {
                // Visit only the fixed report namespace: unrelated source entries are not artifacts.
                if (recordedRepair != null) {
                    val reportAttributes = try {
                        Files.readAttributes(sourceReports, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
                    } catch (_: java.nio.file.NoSuchFileException) { null }
                    if (reportAttributes?.isDirectory == true) Files.walkFileTree(sourceReports, this)
                }
                return FileVisitResult.SKIP_SUBTREE
            }
            if (directory == sourceReports.resolve("repair-revisions")) {
                // Canonical receipts have graph-derived names. Do not walk every historical file
                // merely to discard references outside this selected page. No raw path enters the DTO.
                if (recordedRepair != null) {
                    (recordedRepair.attempts.asSequence() + listOfNotNull(recordedRepair.pending).asSequence()).forEach { attempt ->
                        val identity = attempt.identity
                        if (identity.rawIdentityWithheld ||
                            !Regex("revision_[0-9]{8}_[0-9a-f]{16}").matches(identity.value)) return@forEach
                        val name = "${identity.value}.acp-receipt.json"
                        val logical = "reports/repair-revisions/$name"
                        if (recordedRepairArtifactReference(recordedRepair.corpusSha256, logical) !in references) return@forEach
                        require(++entries <= 10_000) { "report listing exceeds its entry bound" }
                        val receipt = try {
                            Files.readAttributes(directory.resolve(name), BasicFileAttributes::class.java, NOFOLLOW_LINKS)
                        } catch (_: java.nio.file.NoSuchFileException) { null }
                        if (receipt?.isRegularFile == true) {
                            val relative = "source-tree/reports/repair-revisions/$name"
                            summaries += WebArtifactSummary("${context.artifactPrefix}/$relative", "Repair evidence", receipt.size())
                        }
                    }
                }
                return FileVisitResult.SKIP_SUBTREE
            }
            return if (directory == root.resolve("runs") ||
                directory == sourceReports.resolve("repair-revisions/blobs"))
                FileVisitResult.SKIP_SUBTREE else FileVisitResult.CONTINUE
        }
        override fun visitFile(file: Path, attributes: BasicFileAttributes): FileVisitResult {
            require(++entries <= 10_000) { "report listing exceeds its entry bound" }
            if (attributes.isRegularFile) {
                val relative = root.relativize(file).toString().replace('\\', '/')
                val target = "${context.artifactPrefix}/$relative"
                if (file.startsWith(sourceTree)) {
                    val logical = recordedRepairLogicalArtifactPath(target, context)
                    if (recordedRepair != null && file.startsWith(sourceReports) && logical != null &&
                        recordedRepairArtifactReference(recordedRepair.corpusSha256, logical) in references)
                        summaries += WebArtifactSummary(target, "Repair evidence", attributes.size())
                } else summaries += WebArtifactSummary(target, file.fileName.toString(), attributes.size())
            }
            return FileVisitResult.CONTINUE
        }
    })
    return summaries.sortedBy { it.relativePath }
}
