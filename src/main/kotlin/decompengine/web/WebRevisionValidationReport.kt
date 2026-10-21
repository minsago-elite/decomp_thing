package decompengine.web

import decompengine.project.sha256
import decompengine.repair.*
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.serialization.json.*

/** A selected recorded operation, not the latest workflow result or an acceptance decision. */
internal class WebRevisionValidationQuery private constructor(val selection: RepairRecordedHistorySelection,
    val casePageNumber: Int) {
    companion object {
        fun parse(raw: String?): WebRevisionValidationQuery = try {
            require(!raw.isNullOrEmpty() && raw.length <= 512)
            val names = raw.split('&').map { it.substringBefore('=') }
            require(names.all { it in setOf("historyGraph", "historyPage", "historyEvidence", "historyRunEvidence", "historyValidationPage") })
            val query = parseRecordedRepairHistoryQuery(raw)
            require(query.selection.expectedGraphSha256 != null)
            require((query.selection.evidenceAttempt != null) != (query.selection.evidenceRun != null))
            WebRevisionValidationQuery(query.selection, query.validationCasePageNumber)
        } catch (_: IllegalArgumentException) {
            throw WebAccessDenied(400, "VALIDATION_FAILED", "Select one recorded graph and validation evidence owner.")
        }
    }
}

internal data class WebRevisionValidationCapture(
    val page: RepairRecordedHistoryPage,
    val primary: ByteArray?,
    val diff: ByteArray?,
)

private fun selectedValidationBinding(page: RepairRecordedHistoryPage): RepairRecordedValidationObservation? =
    if (page.selection.evidenceRun != null) page.evidenceRuns.single().baselineValidationObservation
    else page.evidenceAttempts.single().validationObservation

/** One capture/projection at a time; callbacks also permit authored in-memory boundary controls. */
internal class WebRevisionValidationReports(
    private val capture: (String, String, RepairRecordedHistorySelection) -> WebRevisionValidationCapture,
) {
    private val reading = AtomicBoolean(false)

    fun read(jobId: String, runId: String, rawQuery: String?): JsonObject {
        requireIdentity(jobId, runId)
        val query = WebRevisionValidationQuery.parse(rawQuery)
        return oneRead {
            val value = capture(jobId, runId, query.selection)
            if (value.page.selection != query.selection || value.page.snapshot.graphSha256 != query.selection.expectedGraphSha256)
                throw WebAccessDenied(409, "REPORT_CHANGED", "The selected recorded history changed. Reload its evidence.")
            recordedValidationReport(jobId, runId, value, query.casePageNumber)
        }
    }

    fun history(jobId: String, runId: String, rawQuery: String?,
        captureHistory: (String, String, RepairRecordedHistorySelection) -> WebValidationHistoryCapture): JsonObject {
        requireIdentity(jobId, runId)
        val selection = parseWebValidationHistoryQuery(rawQuery)
        return oneRead {
            val value = captureHistory(jobId, runId, selection)
            if (value.page?.selection != selection && (value.page != null || !selection.isDefault))
                throw WebAccessDenied(409, "REPORT_CHANGED", "The selected history metadata changed. Read its latest snapshot.")
            webValidationHistory(jobId, runId, value)
        }
    }

    fun failure(jobId: String, runId: String, rawQuery: String?,
        captureFailure: (String, String, RepairRecordedHistorySelection) -> WebRevisionValidationFailureCapture): JsonObject {
        requireIdentity(jobId, runId)
        val selection = parseWebValidationFailureQuery(rawQuery)
        return oneRead {
            val value = captureFailure(jobId, runId, selection)
            if (value.page.selection != selection || value.page.snapshot.graphSha256 != selection.expectedGraphSha256)
                throw WebAccessDenied(409, "REPORT_CHANGED", "The selected recorded failure changed. Reload its evidence.")
            recordedValidationFailureReport(jobId, runId, value)
        }
    }

    private fun requireIdentity(jobId: String, runId: String) {
        if (!jobId.matches(Regex("[a-f0-9]{32}")) || !runId.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")))
            throw WebAccessDenied(404, "NOT_FOUND", "The selected report is unavailable.")
    }

    private fun <T> oneRead(read: () -> T): T {
        if (!reading.compareAndSet(false, true))
            throw WebAccessDenied(429, "VALIDATION_REPORT_BUSY", "Another validation evidence read is in progress. Try this read again later.")
        return try { read() } finally { reading.set(false) }
    }
}

internal fun WebJobService.readRecordedValidationReport(jobId: String, runId: String,
    selection: RepairRecordedHistorySelection): WebRevisionValidationCapture = captureRecordedValidationReport(
    selection, reportContext(jobId, runId),
    version = { getAttempt(jobId, runId).version },
    history = { readRecordedRepairHistory(jobId, runId) },
    artifacts = { recorded, page -> listArtifactSummaries(jobId, runId, recorded, page) },
    read = { target, maximum -> readArtifact(jobId, target, maximum).bytes },
)

/** Graph selection precedes payload reads; both graph and durable attempt versions bracket the capture. */
internal fun captureRecordedValidationReport(
    selection: RepairRecordedHistorySelection,
    context: WebReportContext,
    version: () -> String,
    history: () -> RepairHistoryReadResult,
    artifacts: (RepairHistoryReadResult, RepairRecordedHistoryPage) -> List<WebArtifactSummary>?,
    read: (String, Long) -> ByteArray?,
): WebRevisionValidationCapture {
    val value = captureSelectedValidationEvidence(selection, context, version, history, artifacts, read) { page ->
        selectedValidationBinding(page)?.let { listOf(it.primary) + listOfNotNull(it.diff) }.orEmpty()
    }
    return WebRevisionValidationCapture(value.page, value.payloads.getOrNull(0), value.payloads.getOrNull(1))
}

internal data class WebSelectedValidationEvidence(val page: RepairRecordedHistoryPage, val payloads: List<ByteArray?>)

/** Both normal and failed-operation receipts use the same selected, version-bracketed byte allowance. */
internal fun captureSelectedValidationEvidence(
    selection: RepairRecordedHistorySelection,
    context: WebReportContext,
    version: () -> String,
    history: () -> RepairHistoryReadResult,
    artifacts: (RepairHistoryReadResult, RepairRecordedHistoryPage) -> List<WebArtifactSummary>?,
    read: (String, Long) -> ByteArray?,
    selectArtifacts: (RepairRecordedHistoryPage) -> List<RepairRecordedValidationObservedArtifact>,
): WebSelectedValidationEvidence {
    val before = version()
    val recorded = history()
    val page = try { requireNotNull(recordedRepairHistoryPage(recorded, selection, 20)) }
    catch (failure: RepairRecordedSelectionFailure) {
        val status = if (failure.problem == RepairRecordedSelectionProblem.OUT_OF_RANGE) 400 else 409
        throw WebAccessDenied(status, "REPORT_CHANGED", "The selected recorded history is unavailable or changed. Reload its evidence.")
    }
    val selected = selectArtifacts(page)
    require(selected.size <= 2)
    val listed = if (selected.isEmpty()) null else runCatching { artifacts(recorded, page) }.getOrNull()
    var remaining = MAXIMUM_RECORDED_REPAIR_EVIDENCE_REQUEST_BYTES
    val captured = mutableMapOf<String, ByteArray?>()
    fun bytes(artifact: RepairRecordedValidationObservedArtifact): ByteArray? {
        val target = recordedRepairEvidenceTarget(artifact.artifact, page.snapshot, context, listed) ?: return null
        if (captured.containsKey(target)) return captured[target]
        val reserved = runCatching { recordedRepairEvidenceReadReservation(artifact.bytes, remaining) }.getOrDefault(0)
        if (reserved == 0L) return null
        remaining -= reserved // Failed reads consume their reservation, as on the existing recorded view.
        val value = runCatching { read(target, reserved) }.getOrNull()?.takeIf { it.size.toLong() <= reserved }
        if (value != null) remaining += reserved - value.size
        captured[target] = value
        return value
    }
    val payloads = selected.map(::bytes)
    val after = history()
    if (version() != before || after.status != RepairHistoryReadStatus.RECORDED ||
        after.snapshot?.graphSha256 != page.snapshot.graphSha256)
        throw WebAccessDenied(409, "REPORT_CHANGED", "The selected recorded history or attempt changed during this read.")
    return WebSelectedValidationEvidence(page, payloads)
}

/** Existing report contract with optional bounded normal case detail; fatal outcomes are not inferred. */
internal fun recordedValidationReport(jobId: String, runId: String, capture: WebRevisionValidationCapture,
    casePageNumber: Int = 1): JsonObject {
    require(casePageNumber > 0)
    val page = capture.page
    val owner = if (page.selection.evidenceRun != null) page.evidenceRuns.single().identity
        else page.evidenceAttempts.single().identity
    val binding = selectedValidationBinding(page)
    var state = "unknown"
    var producerVersion: Int? = null
    var summary: JsonObject? = null
    var caseDetail: JsonObject? = null
    var casePageOutOfRange = false
    var limitation = "No normal validation receipt is recorded for this owner. Fatal case outcomes are not inferred."
    if (binding != null) {
        if (capture.primary == null || capture.primary.isEmpty()) {
            state = "unknown"; limitation = "The selected receipt bytes are missing, inaccessible or changed during the bounded read."
        } else try {
            val bytes = capture.primary
            require(bytes.size.toLong() == binding.primary.bytes && sha256(bytes) == binding.primary.sha256 &&
                binding.primary.sha256 == binding.proof.evidenceSha256)
            val root = parseNormalValidationJson(bytes)
            val declared = root["schemaVersion"] as? JsonPrimitive
            require(declared != null && !declared.isString)
            producerVersion = declared.intOrNull?.takeIf { it in 1..65535 }
            require(producerVersion != null)
            if (producerVersion != 2) {
                state = "unsupported"; limitation = "This adapter does not support the declared validation producer schema."
            } else {
                val detail = checkedRecordedRepairValidationObservation(binding, bytes, capture.diff, casePageNumber)
                val cases = detail.casePage
                require(detail.primaryState != RepairEvidenceArtifactState.CORRUPT &&
                    detail.diffState != RepairEvidenceArtifactState.CORRUPT && cases?.state != RecordedRepairValidationCaseState.CORRUPT)
                if (cases?.state == RecordedRepairValidationCaseState.OUT_OF_RANGE) casePageOutOfRange = true
                if (detail.primaryState != RepairEvidenceArtifactState.AVAILABLE ||
                    binding.diff != null && detail.diffState != RepairEvidenceArtifactState.AVAILABLE ||
                    cases?.state != RecordedRepairValidationCaseState.AVAILABLE || binding.candidate.rawIdentityWithheld || owner.rawIdentityWithheld) {
                    state = "partial"; limitation = "Required recorded scope, diff or identity evidence is unavailable; no result is inferred."
                } else {
                    val result = when (binding.outcome) {
                        RepairValidationObservedOutcome.COMPILE_FAILED -> "failed"
                        RepairValidationObservedOutcome.COMPILE_VALID -> "unknown"
                        RepairValidationObservedOutcome.BEHAVIOR_CHECKED ->
                            if (cases.matchedCount == cases.inputCount) "passed" else "failed"
                    }
                    summary = buildJsonObject {
                        put("result", result); put("casesCompared", requireNotNull(detail.completedCasePairs).toString())
                        put("sourceSha256", binding.proof.sourceRevisionSha256)
                    }
                    caseDetail = recordedValidationCaseDetail(page, owner, binding, cases)
                    state = "available"
                    limitation = if (binding.outcome == RepairValidationObservedOutcome.COMPILE_VALID)
                        "Recorded compilation only; behavior cases were not compared and no validation success is inferred."
                    else "Recorded operation observations bound to this source and corpus; not an acceptance or equivalence decision."
                }
            }
        } catch (_: Exception) {
            state = "invalid"; summary = null; caseDetail = null
            limitation = "The selected receipt or derived diff is corrupt, inconsistent or exceeds adapter limits."
        }
    }
    if (casePageOutOfRange)
        throw WebAccessDenied(400, "VALIDATION_FAILED", "The selected validation case page is out of range.")
    val identity = listOf(jobId, runId, page.snapshot.graphSha256, if (page.selection.evidenceRun != null) "run" else "attempt",
        owner.value, binding?.primary?.sha256.orEmpty()).joinToString("") { "${it.length}:$it;" }
    return buildJsonObject {
        put("reportId", "validation_" + sha256(identity.toByteArray(Charsets.UTF_8)))
        put("binding", buildJsonObject {
            put("jobId", jobId); put("runId", runId)
            put("revisionId", binding?.candidate?.takeUnless { it.rawIdentityWithheld }?.let { JsonPrimitive(it.value) } ?: JsonNull)
        })
        put("reportType", "revision-validation"); put("adapterVersion", 1)
        put("producerSchemaVersion", producerVersion?.let(::JsonPrimitive) ?: JsonNull)
        put("state", state); put("authority", "observations"); put("sourceArtifact", JsonNull)
        put("acceptance", "not-evaluated"); put("acceptanceArtifactId", JsonNull)
        put("limitations", JsonArray(listOf(JsonPrimitive(limitation), JsonPrimitive(
            "Integrity checks do not qualify independent containment, physical resource bounds, authentication or ACP decompilation effectiveness."))))
        put("summary", summary ?: JsonNull)
        put("validationCases", caseDetail ?: JsonNull)
        put("validationFailure", JsonNull)
    }
}

private fun recordedValidationCaseDetail(page: RepairRecordedHistoryPage, owner: RepairRecordedIdentity,
    binding: RepairRecordedValidationObservation, cases: RecordedRepairValidationCasePage): JsonObject = buildJsonObject {
    fun count(value: Long?): JsonElement = value?.let { JsonPrimitive(it.toString()) } ?: JsonNull
    fun flag(value: Boolean?): JsonElement = value?.let(::JsonPrimitive) ?: JsonNull
    fun preview(value: RecordedRepairValidationPreview?): JsonElement = value?.let {
        buildJsonObject {
            put("totalBytes", it.totalBytes.toString()); put("prefixBytes", it.prefixBytes)
            put("hex", it.hex); put("text", it.text?.let(::JsonPrimitive) ?: JsonNull)
            put("textBytes", it.textBytes?.let(::JsonPrimitive) ?: JsonNull); put("truncated", it.truncated)
        }
    } ?: JsonNull
    put("authority", "observations"); put("comparisonPolicy", "exact-bytes-v1")
    put("graphSha256", page.snapshot.graphSha256); put("corpusSha256", binding.proof.regressionCorpusSha256)
    put("sourceSha256", binding.proof.sourceRevisionSha256)
    put("ownerKind", if (page.selection.evidenceRun != null) "run-baseline" else "attempt"); put("ownerId", owner.value)
    put("normalOutcome", binding.outcome.name.lowercase().replace('_', '-'))
    put("page", cases.pageNumber); put("pageSize", 20); put("totalPages", cases.totalPages)
    put("totalInputs", cases.inputCount.toString()); put("matchedInputs", cases.matchedCount?.let { JsonPrimitive(it.toString()) } ?: JsonNull)
    put("previousPage", (cases.pageNumber - 1).takeIf { it > 0 }?.let(::JsonPrimitive) ?: JsonNull)
    put("nextPage", if (cases.pageNumber < cases.totalPages) JsonPrimitive(cases.pageNumber + 1) else JsonNull)
    put("firstMismatchPage", cases.firstMismatchPage?.let(::JsonPrimitive) ?: JsonNull)
    put("previousMismatchPage", cases.previousMismatchPage?.let(::JsonPrimitive) ?: JsonNull)
    put("nextMismatchPage", cases.nextMismatchPage?.let(::JsonPrimitive) ?: JsonNull)
    put("comparisonIndex", cases.comparisonIndex?.let { index -> buildJsonObject {
        put("referenceObservationsSha256", index.referenceObservationsSha256)
        put("mismatchBitmapHex", index.mismatchBitmapHex)
    } } ?: JsonNull)
    put("items", JsonArray(cases.cases.map { value -> buildJsonObject {
        put("caseId", value.identity.value); put("ordinal", value.ordinal.toString())
        put("outcome", value.outcome.name.lowercase().replace('_', '-'))
        put("exitCodeMatches", flag(value.exitCodeMatches)); put("stdoutMatches", flag(value.stdoutMatches)); put("stderrMatches", flag(value.stderrMatches))
        put("originalStdoutBytes", count(value.originalStdoutBytes)); put("rebuiltStdoutBytes", count(value.rebuiltStdoutBytes))
        put("originalStderrBytes", count(value.originalStderrBytes)); put("rebuiltStderrBytes", count(value.rebuiltStderrBytes))
        put("originalStdoutPreview", preview(value.originalStdoutPreview)); put("rebuiltStdoutPreview", preview(value.rebuiltStdoutPreview))
        put("originalStderrPreview", preview(value.originalStderrPreview)); put("rebuiltStderrPreview", preview(value.rebuiltStderrPreview))
    } }))
}
