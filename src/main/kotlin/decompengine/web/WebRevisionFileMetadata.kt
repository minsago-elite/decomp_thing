package decompengine.web

import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileRole
import kotlinx.serialization.json.*

/** One recorded input declaration. This operation never requests the selected file's body. */
internal class WebRevisionFileMetadata(private val source: (String, String, String) -> WebRevisionSourceSnapshot) {
    fun read(jobId: String, runId: String, revisionId: String, fileId: String): JsonObject {
        revisionSourceFileIndex(fileId)
        val snapshot = source(jobId, runId, revisionId)
        val ref = snapshot.reference
        check(ref.jobId == jobId && ref.runId == runId && ref.revisionId == revisionId)
        val file = resolveRevisionSourceFile(snapshot, fileId)
        val entry = file.evidence
        val parent = entry.path.substringBeforeLast('/', "")
        return buildJsonObject {
            put("binding", buildJsonObject { put("jobId", jobId); put("runId", runId); put("revisionId", revisionId) })
            put("authority", "source-input-commitments"); put("contentVerification", "not-performed")
            put("sourceSha256", ref.sourceSha256); put("metadataVersion", snapshot.metadataVersion)
            put("parentDirectoryId", if (parent.isEmpty()) "root" else revisionSourceDirectoryId(snapshot, parent))
            // Preserve the manifest claim without promoting it to content or revision acceptance evidence.
            put("implementationDeclaration", when (entry.acceptedImplementation) {
                true -> "accepted"
                false -> "unaccepted"
                null -> "not-classified"
            })
            put("item", buildJsonObject {
                put("fileId", fileId); put("displayName", entry.path); put("sizeBytes", file.sizeBytes.toString())
                put("sha256", entry.sha256); put("declaredUtf8Text", entry.contentKind == ProjectContentKind.UTF8_TEXT)
                put("declaredViewable", ProjectFileRole.VIEWABLE in entry.roles)
                put("declaredArchivable", ProjectFileRole.ARCHIVE_PAYLOAD in entry.roles)
            })
        }
    }
}
