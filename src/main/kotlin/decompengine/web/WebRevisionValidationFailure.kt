package decompengine.web

import decompengine.project.sha256
import decompengine.project.parseGeneratedCValidationFailureRecord
import decompengine.repair.*
import kotlinx.serialization.json.*

/** Explicit failure selection cannot silently substitute a run's baseline validation. */
internal fun parseWebValidationFailureQuery(raw: String?): RepairRecordedHistorySelection = try {
    require(!raw.isNullOrEmpty() && raw.length <= 512)
    val parts = raw.split('&')
    require(parts.count { it.substringBefore('=') == "historyFailureRun" } == 1)
    require(parts.none { it.substringBefore('=') in setOf("historyEvidence", "historyRunEvidence") })
    val normalQuery = parts.joinToString("&") {
        if (it.substringBefore('=') == "historyFailureRun") "historyRunEvidence=" + it.substringAfter('=', "") else it
    }
    val query = WebRevisionValidationQuery.parse(normalQuery)
    require(query.casePageNumber == 1 && query.selection.evidenceRun != null)
    query.selection
} catch (_: IllegalArgumentException) {
    throw WebAccessDenied(400, "VALIDATION_FAILED", "Select one recorded graph and failed-operation run.")
}

internal data class WebRevisionValidationFailureCapture(val page: RepairRecordedHistoryPage,
    val primary: ByteArray?, val diagnostic: ByteArray?)

internal fun WebJobService.readRecordedValidationFailureReport(jobId: String, runId: String,
    selection: RepairRecordedHistorySelection): WebRevisionValidationFailureCapture = captureRecordedValidationFailureReport(
    selection, reportContext(jobId, runId), version = { getAttempt(jobId, runId).version },
    history = { readRecordedRepairHistory(jobId, runId) },
    artifacts = { recorded, page -> listArtifactSummaries(jobId, runId, recorded, page) },
    read = { target, maximum -> readArtifact(jobId, target, maximum).bytes })

internal fun captureRecordedValidationFailureReport(selection: RepairRecordedHistorySelection,
    context: WebReportContext, version: () -> String, history: () -> RepairHistoryReadResult,
    artifacts: (RepairHistoryReadResult, RepairRecordedHistoryPage) -> List<WebArtifactSummary>?,
    read: (String, Long) -> ByteArray?): WebRevisionValidationFailureCapture {
    require(selection.evidenceRun != null && selection.evidenceAttempt == null)
    val value = captureSelectedValidationEvidence(selection, context, version, history, artifacts, read) { page ->
        page.evidenceRuns.single().validationDiagnostic?.let {
            listOf(RepairRecordedValidationObservedArtifact(it.receipt, it.receiptSha256, it.receiptBytes),
                RepairRecordedValidationObservedArtifact(it.diagnostic, it.diagnosticSha256, it.diagnosticBytes.toLong()))
        }.orEmpty()
    }
    return WebRevisionValidationFailureCapture(value.page, value.payloads.getOrNull(0), value.payloads.getOrNull(1))
}

/** Producer diagnostics identify the enclosing operation; they do not classify an unseen child process. */
internal fun recordedValidationFailureReport(jobId: String, runId: String, capture: WebRevisionValidationFailureCapture): JsonObject {
    val page = capture.page
    require(page.selection.evidenceRun != null && page.selection.evidenceAttempt == null)
    val run = page.evidenceRuns.single()
    val binding = run.validationDiagnostic
    var state = "unknown"
    var version: Int? = null
    var detail: JsonObject? = null
    var limitation = "No failed-operation diagnostic is recorded for this run. No case outcome is inferred."
    if (binding != null) {
        if (capture.primary == null || capture.primary.isEmpty()) limitation = "The selected failed-operation receipt bytes are unavailable."
        else try {
            val bytes = requireNotNull(capture.primary)
            require(bytes.size.toLong() == binding.receiptBytes && sha256(bytes) == binding.receiptSha256)
            val root = parseNormalValidationJson(bytes)
            val schema = root["schemaVersion"] as? JsonPrimitive
            require(schema != null && !schema.isString)
            version = schema.intOrNull?.takeIf { it in 1..65535 }
            require(version != null)
            if (version != 2) {
                state = "unsupported"; limitation = "This adapter does not support the declared failed-operation receipt schema."
            } else {
                val checked = checkedRecordedRepairValidationDiagnostic(binding, bytes, capture.diagnostic)
                when (checked.state) {
                    RepairEvidenceArtifactState.CORRUPT -> error("failed-operation diagnostic integrity")
                    RepairEvidenceArtifactState.UNAVAILABLE -> {
                        state = "partial"; limitation = "The required bound failure diagnostic is unavailable; no failure labels are inferred."
                    }
                    RepairEvidenceArtifactState.AVAILABLE -> {
                        val invocation = requireNotNull(parseGeneratedCValidationFailureRecord(requireNotNull(capture.diagnostic)).invocation)
                        require(binding.regressionCorpusSha256 == run.corpusSha256)
                        if (!run.identity.rawIdentityWithheld) require(invocation.runId == run.identity.value)
                        val inputs = root.getValue("inputs").jsonArray
                        require(recordedNormalValidationCorpusSha256(inputs) == binding.regressionCorpusSha256)
                        require(binding.cleanupVerified == (binding.failureKind != RepairValidationFailureKind.CLEANUP_UNVERIFIED))
                        val completed = root.getValue("caseCount").jsonPrimitive.int
                        val phase = requireNotNull(checked.phase)
                        val casePhase = phase in setOf("before-case", "original-operation", "rebuilt-operation")
                        require(casePhase == (checked.inputIndex != null))
                        if (phase in setOf("source-preparation", "build", "build-finalization", "capture-rebuilt")) require(completed == 0)
                        if (run.identity.rawIdentityWithheld || binding.candidate.rawIdentityWithheld) {
                            state = "partial"; limitation = "The selected failure identity is withheld; no diagnostic detail is exposed."
                        } else {
                            detail = buildJsonObject {
                                put("authority", "producer-diagnostic"); put("ownerKind", "run-failure"); put("ownerId", run.identity.value)
                                put("graphSha256", page.snapshot.graphSha256); put("sourceSha256", binding.sourceRevisionSha256)
                                put("corpusSha256", binding.regressionCorpusSha256)
                                put("classification", binding.failureKind.name.lowercase().replace('_', '-'))
                                put("reason", requireNotNull(checked.reason)); put("phase", phase)
                                put("inputCount", requireNotNull(checked.inputCount).toString())
                                put("inputOrdinal", checked.inputIndex?.let { JsonPrimitive((it.toLong() + 1).toString()) } ?: JsonNull)
                                put("reportedCompletedPairs", completed.toString()); put("reportedCleanupVerified", binding.cleanupVerified)
                            }
                            state = "available"
                            limitation = "Bound producer diagnostic for an enclosing failed operation. Completed-pair counts are producer reports, not verified case comparisons or child-process failure classifications."
                        }
                    }
                }
            }
        } catch (_: Exception) {
            state = "invalid"; detail = null
            limitation = "The failed-operation receipt and diagnostic are corrupt, inconsistent or exceed adapter limits."
        }
    }
    val identity = listOf(jobId, runId, page.snapshot.graphSha256, "run-failure", run.identity.value,
        binding?.receiptSha256.orEmpty(), binding?.diagnosticSha256.orEmpty()).joinToString("") { "${it.length}:$it;" }
    return buildJsonObject {
        put("reportId", "validation_" + sha256(identity.toByteArray(Charsets.UTF_8)))
        put("binding", buildJsonObject { put("jobId", jobId); put("runId", runId)
            put("revisionId", binding?.candidate?.takeUnless { it.rawIdentityWithheld }?.let { JsonPrimitive(it.value) } ?: JsonNull) })
        put("reportType", "revision-validation"); put("adapterVersion", 1)
        put("producerSchemaVersion", version?.let(::JsonPrimitive) ?: JsonNull); put("state", state)
        put("authority", "observations"); put("sourceArtifact", JsonNull)
        put("acceptance", "not-evaluated"); put("acceptanceArtifactId", JsonNull); put("summary", JsonNull)
        put("validationCases", JsonNull); put("validationFailure", detail ?: JsonNull)
        put("limitations", JsonArray(listOf(JsonPrimitive(limitation), JsonPrimitive(
            "Reading diagnostics does not execute validation, establish process absence or cleanup, accept a repair, or qualify ACP decompilation effectiveness."))))
    }
}
