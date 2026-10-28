package decompengine.web

import kotlinx.serialization.json.*
import java.security.MessageDigest

/** Descriptor for the fixed exploration report family. Content is served by the digest-bound artifact reader. */
internal object WebExplorationArtifact {
    fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    fun descriptor(jobId: String, runId: String, bytes: ByteArray, basePath: String): JsonObject = buildJsonObject {
        val digest = sha256(bytes)
        val id = webArtifactId(jobId, runId, WebArtifactFamily.EXPLORATION, digest)
        put("artifactId", id)
        put("binding", buildJsonObject { put("jobId", jobId); put("runId", runId); put("revisionId", JsonNull) })
        put("displayName", "exploration.json"); put("mediaType", "application/json")
        put("sizeBytes", bytes.size.toString()); put("sha256", digest)
        put("contentHref", "${basePath}api/v1/jobs/$jobId/artifacts/$id/content")
        put("role", "raw-evidence"); put("derivedFromArtifactId", JsonNull)
    }
}
