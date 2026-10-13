package decompengine.web

import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull

private val SAFE_REPAIR_ARTIFACT_SEGMENT = Regex("[A-Za-z0-9._-]{1,160}")

enum class RepairEvidenceArtifactState { AVAILABLE, UNAVAILABLE, CORRUPT }

/** Receipt integrity is per persisted invocation, even if several records name the same path. */
data class RepairReceiptBindingIdentity(
    val receiptPath: String,
    val revisionId: String?,
    val receiptSha256: String?,
    val receiptSchemaVersion: Int?,
    val requestSha256: String?,
    val resultChangesSha256: String?,
    val terminalOutcome: String?,
    val receiptReleaseComplete: Boolean?,
    val assessmentStatus: String?,
)

internal fun repairReceiptBindingIdentity(iteration: kotlinx.serialization.json.JsonObject): RepairReceiptBindingIdentity? {
    val binding = iteration["agentInvocation"] as? kotlinx.serialization.json.JsonObject ?: return null
    val path = (binding["receiptPath"] as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull ?: return null
    return RepairReceiptBindingIdentity(
        receiptPath = path,
        revisionId = (iteration["revisionId"] as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull,
        receiptSha256 = (binding["receiptSha256"] as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull,
        receiptSchemaVersion = (binding["receiptSchemaVersion"] as? kotlinx.serialization.json.JsonPrimitive)?.intOrNull,
        requestSha256 = (binding["requestSha256"] as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull,
        resultChangesSha256 = (binding["resultChangesSha256"] as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull,
        terminalOutcome = (binding["terminalOutcome"] as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull,
        receiptReleaseComplete = (binding["receiptReleaseComplete"] as? kotlinx.serialization.json.JsonPrimitive)?.booleanOrNull,
        assessmentStatus = (binding["assessmentStatus"] as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull,
    )
}

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
