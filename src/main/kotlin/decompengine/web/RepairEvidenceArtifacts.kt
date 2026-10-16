package decompengine.web

import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import decompengine.repair.*

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

internal const val MAXIMUM_VISIBLE_RECORDED_REPAIR_ATTEMPTS = 100
internal fun visibleRecordedRepairAttempts(snapshot: RepairHistorySnapshot): List<RepairRecordedAttempt> =
    RepairRecordedHistoryPage.select(snapshot, RepairRecordedHistorySelection(), MAXIMUM_VISIBLE_RECORDED_REPAIR_ATTEMPTS).attempts

internal data class RecordedRepairHistoryQuery(val runId: String?, val selection: RepairRecordedHistorySelection)
internal fun parseRecordedRepairHistoryQuery(raw: String?): RecordedRepairHistoryQuery {
    if (raw == null) return RecordedRepairHistoryQuery(null, RepairRecordedHistorySelection())
    require(raw.isNotEmpty() && raw.length <= 512) { "Recorded history query is invalid." }
    val values = linkedMapOf<String, String>()
    for (part in raw.split('&')) {
        val pair = part.split('=', limit = 2)
        require(pair.size == 2 && pair[0] in setOf("runId", "historyPage", "historyCasesPage", "historyGraph", "historyEvidence") &&
            values.put(pair[0], pair[1]) == null) { "Recorded history query is invalid." }
    }
    val run = values["runId"]
    require(run == null || run.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}"))) { "Recorded history query is invalid." }
    return RecordedRepairHistoryQuery(run, parseRecordedRepairSelection(
        values["historyPage"], values["historyCasesPage"], values["historyGraph"], values["historyEvidence"]))
}

internal data class RecordedRepairHistoryView(
    val recorded: RepairHistoryReadResult,
    val targets: Map<RepairRecordedArtifactReference, String> = emptyMap(),
    val evidenceStates: Map<RepairRecordedArtifactReference, RepairEvidenceArtifactState> = emptyMap(),
    val receiptStates: Map<RepairRecordedIdentity, RepairEvidenceArtifactState> = emptyMap(),
    val page: RepairRecordedHistoryPage? = null,
    val runId: String? = null,
)

internal fun recordedRepairArtifactReferences(snapshot: RepairHistorySnapshot): Set<RepairRecordedArtifactReference> =
    recordedRepairArtifactReferences(snapshot, RepairRecordedHistoryPage.select(snapshot,
        RepairRecordedHistorySelection(), MAXIMUM_VISIBLE_RECORDED_REPAIR_ATTEMPTS))

internal fun recordedRepairArtifactReferences(snapshot: RepairHistorySnapshot,
    page: RepairRecordedHistoryPage): Set<RepairRecordedArtifactReference> {
    require(page.snapshot === snapshot) { "Recorded history page does not match its capture." }
    return buildSet {
        page.evidenceAttempts.forEach { attempt ->
            attempt.before?.artifact?.let(::add)
            attempt.after?.artifact?.let(::add)
            attempt.invocation?.artifact?.let(::add)
        }
    }
}

/** Fixed selected report namespace only; canonical H/G/binding/blobs are never evidence reads. */
internal fun recordedRepairLogicalArtifactPath(target: String, reports: WebReportContext): String? {
    val prefix = "${reports.artifactPrefix}/"
    if (!target.startsWith(prefix)) return null
    val suffix = target.removePrefix(prefix)
    val relative = if (suffix.startsWith("source-tree/reports/")) suffix.removePrefix("source-tree/reports/") else suffix
    if (relative.startsWith("source-tree/") || relative.startsWith("runs/")) return null
    val logical = "reports/$relative"
    val parts = logical.split('/')
    if (logical.length > 4096 || parts.size !in 2..32 ||
        parts.any { it == "." || it == ".." || !SAFE_REPAIR_ARTIFACT_SEGMENT.matches(it) }) return null
    if (logical == "reports/repair_history.json") return null
    if (parts[1] == "repair-revisions" &&
        (parts.size != 3 || !Regex("revision_[0-9]{8}_[0-9a-f]{16}\\.acp-receipt\\.json").matches(parts[2]))) return null
    return logical
}

/** No first-match shortcut: duplicate or ambiguous checked targets withhold the link. */
internal fun recordedRepairEvidenceTarget(reference: RepairRecordedArtifactReference, snapshot: RepairHistorySnapshot,
    reports: WebReportContext, artifacts: List<WebArtifactSummary>?): String? {
    val matches = artifacts.orEmpty().filter { artifact ->
        recordedRepairLogicalArtifactPath(artifact.relativePath, reports)?.let {
            recordedRepairArtifactReference(snapshot.corpusSha256, it) == reference
        } == true
    }
    return matches.singleOrNull()?.relativePath
}
