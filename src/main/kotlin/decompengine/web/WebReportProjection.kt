package decompengine.web

import decompengine.jobs.AgentProgressJournal

/**
 * Server-produced reports (exploration reports and progress journals) may carry host paths, environment values or
 * credential prose, so they leave the server only through this one projection, shared by the legacy report route and
 * the v1 artifact content route. Committed source, manifests, build contracts and archives are job content and never
 * pass through it. The stored-artifact digest stays the artifact identity; the projection is a separate representation.
 */
internal object WebReportProjection {
    /** Wire name of the projection, repeated in `X-Decomp-Content-Projection`. */
    const val REDACTED = "redacted"
    const val VERBATIM = "verbatim"
    const val UNAVAILABLE = "unavailable"

    /** Same ceiling as the legacy report route; progress journals keep their stricter journal read limit. */
    const val MAXIMUM_REPORT_BYTES = 64L * 1024 * 1024

    fun limit(progress: Boolean): Long = if (progress) AgentProgressJournal.MAXIMUM_READ_BYTES.toLong() else MAXIMUM_REPORT_BYTES

    /** Progress journals are replayed to their display snapshot first; every report then passes [WebRedactionPolicy.document]. */
    fun project(progress: Boolean, bytes: ByteArray, policy: WebRedactionPolicy): ByteArray {
        require(bytes.size <= limit(progress)) { "report exceeds its projection limit" }
        return policy.document(if (progress) progressJournalProjection(bytes) else bytes)
    }

    /** Descriptor state for a stored file of [size] bytes in [family]. */
    fun state(family: WebArtifactFamily, size: Long): String = when {
        !family.redactedContent -> VERBATIM
        size > limit(family == WebArtifactFamily.PROGRESS) -> UNAVAILABLE
        else -> REDACTED
    }
}

internal fun webArtifactProjectionUnavailable(): Nothing = throw WebAccessDenied(409, "ARTIFACT_PROJECTION_UNAVAILABLE",
    "This report cannot be served through the redacted report projection, so its stored bytes are withheld. " +
        "Use the report views in the workbench instead.")
