package decompengine.web

import decompengine.project.sha256
import decompengine.repair.*
import kotlinx.serialization.json.*

/** Metadata discovery never reads a receipt, invocation, output or source body. */
internal data class WebValidationHistoryCapture(val recorded: RepairHistoryReadResult, val page: RepairRecordedHistoryPage?)

internal fun parseWebValidationHistoryQuery(raw: String?): RepairRecordedHistorySelection = try {
    if (raw == null) RepairRecordedHistorySelection() else {
        require(raw.isNotEmpty() && raw.length <= 256)
        val names = raw.split('&').map { it.substringBefore('=') }
        require(names.all { it in setOf("historyGraph", "historyPage") })
        parseRecordedRepairHistoryQuery(raw).selection
    }
} catch (_: IllegalArgumentException) {
    throw WebAccessDenied(400, "VALIDATION_FAILED", "Select a canonical recorded history page and snapshot.")
}

internal fun WebJobService.readValidationHistory(jobId: String, runId: String,
    selection: RepairRecordedHistorySelection): WebValidationHistoryCapture = captureValidationHistory(selection,
    version = { getAttempt(jobId, runId).version }, history = { readRecordedRepairHistory(jobId, runId) })

internal fun captureValidationHistory(selection: RepairRecordedHistorySelection, version: () -> String,
    history: () -> RepairHistoryReadResult): WebValidationHistoryCapture {
    val before = version()
    val recorded = history()
    val page = try { recordedRepairHistoryPage(recorded, selection, 20) }
    catch (failure: RepairRecordedSelectionFailure) {
        throw WebAccessDenied(if (failure.problem == RepairRecordedSelectionProblem.OUT_OF_RANGE) 400 else 409,
            "REPORT_CHANGED", "Recorded history is unavailable or changed. Read its latest metadata.")
    }
    val after = history()
    if (version() != before || after.status != recorded.status || after.snapshot?.graphSha256 != recorded.snapshot?.graphSha256)
        throw WebAccessDenied(409, "REPORT_CHANGED", "Recorded history or the selected attempt changed during this read.")
    return WebValidationHistoryCapture(recorded, page)
}

internal fun webValidationHistory(jobId: String, runId: String, value: WebValidationHistoryCapture): JsonObject {
    val snapshot = value.recorded.snapshot
    val page = value.page
    require(value.recorded.status != RepairHistoryReadStatus.RECORDED || snapshot != null)
    require((page == null) == (value.recorded.status != RepairHistoryReadStatus.RECORDED || snapshot == null))
    if (page != null) require(page.snapshot === snapshot)
    fun owner(kind: String, identity: RepairRecordedIdentity, binding: RepairRecordedValidationObservation?): JsonObject = buildJsonObject {
        val withheld = identity.rawIdentityWithheld || binding?.candidate?.rawIdentityWithheld == true
        put("ownerKind", kind)
        put("ownerId", if (identity.rawIdentityWithheld) "withheld_" + sha256(identity.value.toByteArray(Charsets.UTF_8)).take(32) else identity.value)
        put("identityWithheld", withheld); put("hasReceipt", binding != null); put("canInspect", binding != null && !withheld)
        put("candidateId", binding?.takeUnless { withheld }?.candidate?.let { JsonPrimitive(it.value) } ?: JsonNull)
        put("sourceSha256", binding?.takeUnless { withheld }?.proof?.sourceRevisionSha256?.let(::JsonPrimitive) ?: JsonNull)
        put("corpusSha256", binding?.takeUnless { withheld }?.proof?.regressionCorpusSha256?.let(::JsonPrimitive) ?: JsonNull)
        put("normalOutcome", binding?.outcome?.name?.lowercase()?.replace('_', '-')?.let(::JsonPrimitive) ?: JsonNull)
    }
    val items = buildList {
        page?.attempts?.forEach { add(owner("attempt", it.identity, it.validationObservation)) }
        page?.runs?.forEach { add(owner("run-baseline", it.identity, it.baselineValidationObservation)) }
    }
    require(items.size <= 41 && items.map { it.getValue("ownerKind") to it.getValue("ownerId") }.distinct().size == items.size)
    return buildJsonObject {
        put("binding", buildJsonObject { put("jobId", jobId); put("runId", runId); put("revisionId", JsonNull) })
        put("authority", "recorded-metadata")
        put("state", when (value.recorded.status) {
            RepairHistoryReadStatus.RECORDED -> "recorded"
            RepairHistoryReadStatus.NOT_RECORDED -> "not-recorded"
            RepairHistoryReadStatus.UNAVAILABLE -> "unavailable"
        })
        put("graphSha256", snapshot?.graphSha256?.let(::JsonPrimitive) ?: JsonNull)
        put("corpusSha256", snapshot?.corpusSha256?.let(::JsonPrimitive) ?: JsonNull)
        put("page", page?.selection?.pageNumber?.let(::JsonPrimitive) ?: JsonNull); put("pageSize", 20)
        put("totalPages", page?.totalPages?.let(::JsonPrimitive) ?: JsonNull)
        put("previousPage", page?.selection?.pageNumber?.takeIf { it > 1 }?.let { JsonPrimitive(it - 1) } ?: JsonNull)
        put("nextPage", page?.takeIf { it.selection.pageNumber < it.totalPages }?.let { JsonPrimitive(it.selection.pageNumber + 1) } ?: JsonNull)
        put("items", JsonArray(items))
        put("limitations", JsonArray(listOf(JsonPrimitive(
            "Recorded operation metadata only. Inspecting a selected receipt checks available case evidence; it does not run validation or accept a repair."))))
    }
}
