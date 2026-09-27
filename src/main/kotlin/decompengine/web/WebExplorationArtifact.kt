package decompengine.web

import decompengine.jobs.WorkflowJobInspection
import kotlinx.serialization.json.*
import java.security.MessageDigest

/** Resolver for one fixed, bounded report family. No browser-supplied path is ever opened. */
internal object WebExplorationArtifact {
    private val idPattern = Regex("exploration_([a-f0-9]{32})_([a-f0-9]{64})")
    fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun binding(jobId: String, runId: String) = sha256("$jobId\u0000$runId".toByteArray()).take(32)
    fun descriptor(jobId: String, runId: String, bytes: ByteArray, basePath: String): JsonObject = buildJsonObject {
        val digest = sha256(bytes)
        val id = "exploration_${binding(jobId, runId)}_$digest"
        put("artifactId", id)
        put("binding", buildJsonObject { put("jobId", jobId); put("runId", runId); put("revisionId", JsonNull) })
        put("displayName", "exploration.json"); put("mediaType", "application/json")
        put("sizeBytes", bytes.size.toString()); put("sha256", digest)
        put("contentHref", "${basePath}api/v1/jobs/$jobId/artifacts/$id/content")
        put("role", "raw-evidence"); put("derivedFromArtifactId", JsonNull)
    }

    fun read(jobs: WebJobService, jobId: String, artifactId: String): ByteArray {
        val match = idPattern.matchEntire(artifactId) ?: unavailable()
        val snapshot = when (val inspection = jobs.inspectDurableJob(jobId)) {
            is WorkflowJobInspection.Available -> inspection.snapshot
            is WorkflowJobInspection.Unavailable -> unavailable()
        }
        val run = snapshot.attempts.singleOrNull { binding(jobId, it.runId) == match.groupValues[1] } ?: unavailable()
        val bytes = jobs.readArtifact(jobId, "reports/runs/${run.runId}/exploration.json", 1_048_576).bytes
        if (sha256(bytes) != match.groupValues[2]) throw WebJobServiceException("ARTIFACT_CHANGED", "These report bytes differ from the displayed artifact. Refresh its evidence before downloading.")
        return bytes
    }

    private fun unavailable(): Nothing = throw WebAccessDenied(404, "NOT_FOUND", "The requested artifact is unavailable for this job.")
}
