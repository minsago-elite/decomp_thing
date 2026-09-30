package decompengine.web

private val SAFE_REPAIR_ARTIFACT_SEGMENT = Regex("[A-Za-z0-9._-]{1,160}")

enum class RepairEvidenceArtifactState { AVAILABLE, UNAVAILABLE, CORRUPT }

/** Resolve a persisted portable reports path only to an artifact the current checked listing exposes. */
internal fun safeRepairEvidenceTarget(
    value: String?,
    reports: WebReportContext,
    artifacts: List<WebArtifactSummary>?,
): String? {
    if (value == null || artifacts == null || !value.startsWith("reports/")) return null
    val parts = value.split('/')
    if (parts.size !in 2..6 || parts.any { it.isBlank() || it == "." || it == ".." || !SAFE_REPAIR_ARTIFACT_SEGMENT.matches(it) }) return null
    val candidates = setOf(value, "${reports.artifactPrefix}/${parts.drop(1).joinToString("/")}")
    return artifacts.asSequence().map { it.relativePath }.firstOrNull { it in candidates &&
        it.startsWith("reports/") && it.split('/').all(SAFE_REPAIR_ARTIFACT_SEGMENT::matches)
    }
}
