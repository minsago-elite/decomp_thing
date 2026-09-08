package decompengine.jobs

import java.io.IOException
import java.nio.file.DirectoryIteratorException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.SecureDirectoryStream
import java.nio.file.attribute.BasicFileAttributeView
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

data class JobRecoveryInventory(
    val scannedEntries: Int,
    val retainedUploadStages: Int,
    val retainedMetadataFiles: Int,
    val observedBytes: Long,
    val uninspectedEntries: Int,
    val inventoryComplete: Boolean,
) {
    fun toJson() = buildJsonObject {
        put("schemaVersion", 1)
        put("displayOnly", true)
        put("scannedEntries", scannedEntries)
        put("retainedUploadStages", retainedUploadStages)
        put("retainedMetadataFiles", retainedMetadataFiles)
        put("observedBytes", observedBytes.toString())
        put("uninspectedEntries", uninspectedEntries)
        put("inventoryComplete", inventoryComplete)
    }
}

/** Read-only bounded inspection. A candidate name is never evidence that deletion is safe. */
internal fun inspectJobRecoveryInventory(
    root: Path,
    maximumEntries: Int = 4096,
    maximumCandidates: Int = 128,
    maximumBytes: Long = 64L * 1024 * 1024,
): JobRecoveryInventory {
    require(maximumEntries in 1..4096 && maximumCandidates in 1..128)
    require(maximumBytes in 1..64L * 1024 * 1024)
    var scanned = 0
    var candidates = 0
    var stages = 0
    var metadata = 0
    var bytes = 0L
    var uninspected = 0
    var incomplete = false
    var exhausted = false
    val jobName = Regex("[a-f0-9]{32}")

    fun reserveCandidate(): Boolean {
        if (candidates == maximumCandidates) {
            incomplete = true
            exhausted = true
            return false
        }
        candidates++
        return true
    }

    fun addBytes(size: Long) {
        if (size < 0 || size > maximumBytes - bytes) {
            incomplete = true
            exhausted = true
        } else bytes += size
    }

    fun inspect(directory: SecureDirectoryStream<Path>, kind: String) {
        try {
            for (entry in directory) {
                if (exhausted || scanned == maximumEntries) {
                    incomplete = true
                    exhausted = true
                    break
                }
                scanned++
                val name = entry.fileName
                val text = name.toString()
                val stage = kind == "root" && text.startsWith(".upload-")
                val job = kind == "root" && jobName.matches(text)
                val temporary = kind == "job" && text.startsWith(".job-metadata-")
                if (!stage && !job && !temporary && kind != "stage") continue
                try {
                    val attributes = directory.getFileAttributeView(name, BasicFileAttributeView::class.java, NOFOLLOW_LINKS)
                        .readAttributes()
                    when {
                        attributes.isSymbolicLink -> { uninspected++; incomplete = true }
                        (stage || job) && attributes.isDirectory -> {
                            if (stage && !reserveCandidate()) break
                            if (stage) stages++
                            directory.newDirectoryStream(name, NOFOLLOW_LINKS).use { child ->
                                inspect(child, if (stage) "stage" else "job")
                            }
                        }
                        temporary && attributes.isRegularFile -> {
                            if (!reserveCandidate()) break
                            metadata++
                            addBytes(attributes.size())
                        }
                        kind == "stage" && attributes.isRegularFile -> addBytes(attributes.size())
                        else -> { uninspected++; incomplete = true }
                    }
                } catch (_: IOException) {
                    uninspected++
                    incomplete = true
                }
            }
        } catch (_: DirectoryIteratorException) {
            uninspected++
            incomplete = true
        }
    }

    if (!Files.notExists(root, NOFOLLOW_LINKS)) {
        try {
            Files.newDirectoryStream(root).use { directory ->
                if (directory is SecureDirectoryStream<Path>) inspect(directory, "root")
                else { uninspected++; incomplete = true }
            }
        } catch (_: IOException) {
            uninspected++
            incomplete = true
        }
    }
    return JobRecoveryInventory(scanned, stages, metadata, bytes, uninspected, !incomplete)
}
