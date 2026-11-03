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

    /** Progress journals are replayed to their display snapshot first; every report then passes the strict, bounded JSON redaction boundary. */
    fun project(progress: Boolean, bytes: ByteArray, policy: WebRedactionPolicy): ByteArray {
        return try {
            val maximumBytes = limit(progress).toInt()
            require(bytes.size <= maximumBytes) { "report exceeds its projection limit" }
            val limits = decompengine.oracle.core.StrictJsonLimits(
                maximumInputBytes = maximumBytes,
                maximumCanonicalBytes = maximumBytes,
                maximumDepth = 32,
                maximumNodes = 100_000,
                maximumStringBytes = minOf(1024 * 1024, maximumBytes),
                maximumTotalStringBytes = maximumBytes,
            )
            policy.reportDocument(if (progress) progressJournalProjection(bytes) else bytes, limits)
        } catch (failure: Exception) {
            if (failure is java.util.concurrent.CancellationException || failure is InterruptedException) throw failure
            webArtifactProjectionUnavailable()
        }
    }

    /** Legacy non-JSON report attachments are text, never a binary pass-through or a JSON interpretation. */
    fun legacyText(bytes: ByteArray, policy: WebRedactionPolicy): ByteArray {
        return try {
            require(bytes.size <= MAXIMUM_REPORT_BYTES)
            val text = Charsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(bytes)).toString()
            val safe = policy.text(text)
            if (safe == text) bytes else safe.toByteArray(Charsets.UTF_8).also {
                require(it.size <= MAXIMUM_REPORT_BYTES)
            }
        } catch (failure: Exception) {
            if (failure is java.util.concurrent.CancellationException || failure is InterruptedException) throw failure
            webArtifactProjectionUnavailable()
        }
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
        "Use the numeric report summary when available; retained case details are withheld too.")
