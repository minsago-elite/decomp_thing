package decompengine.web

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.FileVisitResult

/** Display metadata only; download authorization still validates the selected artifact. */
data class WebArtifactSummary(val relativePath: String, val displayName: String, val sizeBytes: Long)

internal fun listLegacyArtifactSummaries(context: WebReportContext): List<WebArtifactSummary> {
    val root = context.reportsDirectory
    val attributes = try { Files.readAttributes(root, BasicFileAttributes::class.java, NOFOLLOW_LINKS) }
        catch (_: java.nio.file.NoSuchFileException) { return emptyList() }
    require(attributes.isDirectory) { "report listing root is not a directory" }
    val summaries = mutableListOf<WebArtifactSummary>()
    var entries = 0
    Files.walkFileTree(root, object : java.nio.file.SimpleFileVisitor<Path>() {
        override fun preVisitDirectory(directory: Path, attributes: BasicFileAttributes): FileVisitResult {
            require(++entries <= 10_000 && root.relativize(directory).nameCount <= 32) { "report listing exceeds its traversal bound" }
            return if (directory == root.resolve("source-tree") || directory == root.resolve("runs"))
                FileVisitResult.SKIP_SUBTREE else FileVisitResult.CONTINUE
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
    return summaries.sortedBy { it.relativePath }
}
