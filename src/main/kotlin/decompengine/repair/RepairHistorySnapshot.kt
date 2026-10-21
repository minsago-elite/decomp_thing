package decompengine.repair

import decompengine.project.sha256
import java.util.Collections

/** Recorded metadata only. This value is never repair, execution or release authority. */
internal class RepairHistorySnapshot internal constructor(
    val graphSha256: String,
    val graphSchemaVersion: Int,
    val graphWire: RepairRecordedGraphWire,
    val corpusSha256: String,
    val publishedHead: RepairRecordedIdentity,
    val provisionalHead: RepairRecordedIdentity?,
    val fullyAcceptedHead: RepairRecordedIdentity?,
    runs: List<RepairRecordedRun>,
    attempts: List<RepairRecordedAttempt>,
    val pending: RepairRecordedAttempt?,
    retainedCases: List<RepairRecordedIdentity>,
) {
    val viewSchemaVersion: Int get() = 5
    val qualification: RepairRecordedQualification get() = RepairRecordedQualification.RECORDED_METADATA_ONLY
    val runs: List<RepairRecordedRun> = immutableRecordedList(runs)
    val attempts: List<RepairRecordedAttempt> = immutableRecordedList(attempts)
    val retainedCases: List<RepairRecordedIdentity> = immutableRecordedList(retainedCases)
}

/** Continuations name the same captured graph; no selection grants filesystem authority. */
internal data class RepairRecordedHistorySelection(
    val pageNumber: Int = 1,
    val casePageNumber: Int = 1,
    val expectedGraphSha256: String? = null,
    val evidenceAttempt: String? = null,
    val evidenceRun: String? = null,
) {
    init {
        require(pageNumber > 0 && casePageNumber > 0) { "Recorded history page is invalid." }
        require(expectedGraphSha256 == null || GRAPH_DIGEST.matches(expectedGraphSha256)) {
            "Recorded history graph identity is invalid."
        }
        require(evidenceAttempt == null || ATTEMPT_REFERENCE.matches(evidenceAttempt)) {
            "Recorded evidence selection is invalid."
        }
        require(evidenceRun == null || ATTEMPT_REFERENCE.matches(evidenceRun)) { "Recorded run selection is invalid." }
        require(evidenceRun == null || evidenceAttempt == null) { "Select one recorded evidence owner." }
        require((pageNumber == 1 && casePageNumber == 1 && evidenceAttempt == null && evidenceRun == null) || expectedGraphSha256 != null) {
            "Continued history selection requires the recorded graph identity."
        }
    }

    val isDefault: Boolean get() = pageNumber == 1 && casePageNumber == 1 && expectedGraphSha256 == null && evidenceAttempt == null && evidenceRun == null

    private companion object {
        val GRAPH_DIGEST = Regex("[0-9a-f]{64}")
        val ATTEMPT_REFERENCE = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
    }
}

internal fun parseRecordedRepairSelection(page: String?, cases: String?, graph: String?, evidence: String? = null,
    runEvidence: String? = null): RepairRecordedHistorySelection {
    fun number(value: String?): Int {
        if (value == null) return 1
        require(value.isNotEmpty() && value.length <= 10 && value[0] in '1'..'9' && value.all { it in '0'..'9' }) {
            "Recorded history page is invalid."
        }
        return requireNotNull(value.toIntOrNull()) { "Recorded history page is invalid." }
    }
    return RepairRecordedHistorySelection(number(page), number(cases), graph, evidence, runEvidence)
}

internal enum class RepairRecordedSelectionProblem { UNAVAILABLE, CHANGED, OUT_OF_RANGE }
internal class RepairRecordedSelectionFailure(val problem: RepairRecordedSelectionProblem) : RuntimeException(
    when (problem) {
        RepairRecordedSelectionProblem.UNAVAILABLE -> "Recorded history selection is unavailable. Reload the latest history."
        RepairRecordedSelectionProblem.CHANGED -> "Recorded history changed. Reload the latest history before continuing."
        RepairRecordedSelectionProblem.OUT_OF_RANGE -> "Recorded history page is out of range."
    }, null, false, false,
)

/** Fixed-size windows over one immutable capture, including pending only on the latest page. */
internal class RepairRecordedHistoryPage private constructor(
    val snapshot: RepairHistorySnapshot,
    val selection: RepairRecordedHistorySelection,
    val pageSize: Int,
    val totalPages: Int,
    val attemptStart: Int,
    val attemptEnd: Int,
    val runStart: Int,
    val runEnd: Int,
    val casePages: Int,
) {
    val attempts: List<RepairRecordedAttempt> = immutableRecordedList(
        snapshot.attempts.subList(attemptStart, attemptEnd) +
            listOfNotNull(snapshot.pending.takeIf { selection.pageNumber == 1 }))
    val runs: List<RepairRecordedRun> = immutableRecordedList(snapshot.runs.subList(runStart, runEnd))
    val evidenceAttempts: List<RepairRecordedAttempt> = if (selection.evidenceRun != null) emptyList() else selection.evidenceAttempt?.let { reference ->
        val attempt = attempts.singleOrNull { it.identity.value == reference }
            ?: throw RepairRecordedSelectionFailure(RepairRecordedSelectionProblem.OUT_OF_RANGE)
        immutableRecordedList(listOf(attempt))
    } ?: attempts
    val evidenceRuns: List<RepairRecordedRun> = selection.evidenceRun?.let { reference ->
        val run = runs.singleOrNull { it.identity.value == reference }
            ?: throw RepairRecordedSelectionFailure(RepairRecordedSelectionProblem.OUT_OF_RANGE)
        immutableRecordedList(listOf(run))
    } ?: emptyList()
    val earlierAttempts: Int get() = attemptStart
    val newerAttempts: Int get() = snapshot.attempts.size - attemptEnd
    val earlierRuns: Int get() = runStart
    val newerRuns: Int get() = snapshot.runs.size - runEnd

    fun caseReferences(attempt: RepairRecordedAttempt): List<RepairRecordedIdentity> {
        require(attempts.any { it === attempt }) { "Recorded attempt is outside the selected history page." }
        if (attempt.corpusSha256 == null) return emptyList()
        val start = minOf(attempt.retainedCases.size.toLong(),
            (selection.casePageNumber - 1).toLong() * CASE_PAGE_SIZE).toInt()
        return immutableRecordedList(attempt.retainedCases.subList(start,
            minOf(attempt.retainedCases.size.toLong(), start.toLong() + CASE_PAGE_SIZE).toInt()))
    }

    companion object {
        const val CASE_PAGE_SIZE = 20
        fun select(snapshot: RepairHistorySnapshot, selection: RepairRecordedHistorySelection,
            pageSize: Int): RepairRecordedHistoryPage {
            require(pageSize in 1..100) { "Recorded history window exceeds its bound." }
            if (selection.expectedGraphSha256 != null && selection.expectedGraphSha256 != snapshot.graphSha256)
                throw RepairRecordedSelectionFailure(RepairRecordedSelectionProblem.CHANGED)
            fun pages(count: Int, size: Int): Int = maxOf(1L, (count.toLong() + size - 1) / size).toInt()
            val total = maxOf(pages(snapshot.attempts.size, pageSize), pages(snapshot.runs.size, pageSize))
            if (selection.pageNumber > total)
                throw RepairRecordedSelectionFailure(RepairRecordedSelectionProblem.OUT_OF_RANGE)
            fun bounds(count: Int): Pair<Int, Int> {
                val end = (count.toLong() - (selection.pageNumber - 1).toLong() * pageSize)
                    .coerceIn(0L, count.toLong()).toInt()
                return maxOf(0, end - pageSize) to end
            }
            val (first, end) = bounds(snapshot.attempts.size)
            val (runFirst, runEnd) = bounds(snapshot.runs.size)
            val visible = snapshot.attempts.subList(first, end) +
                listOfNotNull(snapshot.pending.takeIf { selection.pageNumber == 1 })
            val maximumCases = visible.maxOfOrNull { if (it.corpusSha256 == null) 0 else it.retainedCases.size } ?: 0
            val casePages = pages(maximumCases, CASE_PAGE_SIZE)
            if (selection.casePageNumber > casePages)
                throw RepairRecordedSelectionFailure(RepairRecordedSelectionProblem.OUT_OF_RANGE)
            return RepairRecordedHistoryPage(snapshot, selection, pageSize, total, first, end, runFirst, runEnd, casePages)
        }
    }
}

internal fun recordedRepairHistoryPage(result: RepairHistoryReadResult, selection: RepairRecordedHistorySelection,
    pageSize: Int): RepairRecordedHistoryPage? {
    val snapshot = result.snapshot
    if (result.status != RepairHistoryReadStatus.RECORDED || snapshot == null) {
        if (!selection.isDefault) throw RepairRecordedSelectionFailure(RepairRecordedSelectionProblem.UNAVAILABLE)
        return null
    }
    return RepairRecordedHistoryPage.select(snapshot, selection, pageSize)
}

internal enum class RepairRecordedQualification { RECORDED_METADATA_ONLY }
internal enum class RepairRecordedGraphWire { COMPACT, EXPLICIT_NULL }
internal enum class RepairRecordedAttemptKind { FINALIZED, PENDING }
internal enum class RepairRecordedReceiptStatus { NOT_READ }
internal enum class RepairRecordedFailureKind { COMPILE, BEHAVIOR, OTHER }
internal enum class RepairRecordedEvidenceKind {
    BUILD, BEHAVIOR, REGRESSION, RECOVERY, VALIDATION, NO_CHANGE, REFUSED, CANCELLED,
    LIMIT_EXHAUSTED, PROCESS_CRASHED, VALIDATION_FAILED, OTHER,
}
internal enum class RepairRecordedTerminal {
    COMPLETED, NO_CHANGES, REFUSED, CANCELLED, LIMIT_EXHAUSTED, PROCESS_CRASHED, OTHER,
}

/** Correlation only; the consumer must separately authorize and validate any matching artifact. */
internal data class RepairRecordedArtifactReference internal constructor(val value: String)
internal data class RepairRecordedEvidence internal constructor(
    val kind: RepairRecordedEvidenceKind,
    val artifact: RepairRecordedArtifactReference?,
)

/** An opaque identity is a checked reference, not a mathematically lossless encoding. */
internal data class RepairRecordedIdentity internal constructor(val value: String, val rawIdentityWithheld: Boolean)

internal data class RepairRecordedRollback internal constructor(
    val schemaVersion: Int,
    val attempt: RepairRecordedIdentity,
    val run: RepairRecordedIdentity?,
    val target: RepairRecordedIdentity,
    val expectedSourceRevisionSha256: String,
    val state: RepairRollbackState,
    val failureStage: RepairRollbackStage?,
    val failureCode: RepairRollbackFailureCode?,
    val observedSourceRevisionSha256: String?,
    val legacyPendingStateUnknown: Boolean,
    val candidateSourceInstallStarted: Boolean?,
)

/** Pure association was checked; receipt content/authorization has deliberately NOT been read. */
internal data class RepairRecordedInvocation internal constructor(
    val receiptSha256: String,
    val requestSha256: String,
    val resultChangesSha256: String,
    val assessment: RepairAgentAssessmentStatus,
    val artifact: RepairRecordedArtifactReference,
    val receiptSchemaVersion: Int,
    val terminal: RepairRecordedTerminal,
    val terminalSha256: String,
    val receiptReleaseComplete: Boolean,
) {
    val receiptStatus: RepairRecordedReceiptStatus get() = RepairRecordedReceiptStatus.NOT_READ
}

internal class RepairRecordedAttempt internal constructor(
    val kind: RepairRecordedAttemptKind,
    val identity: RepairRecordedIdentity,
    val parent: RepairRecordedIdentity?,
    val ordinal: Int,
    val status: ModuleRevisionStatus?,
    val sourceRevisionSha256: String?,
    val run: RepairRecordedIdentity?,
    val publicationMode: RepairPublicationMode?,
    val rollback: RepairRecordedRollback?,
    val invocation: RepairRecordedInvocation?,
    retainedCases: List<RepairRecordedIdentity>,
    val iterationIndex: Int?,
    val failureKind: RepairRecordedFailureKind,
    val before: RepairRecordedEvidence?,
    val after: RepairRecordedEvidence?,
    val corpusSha256: String? = null,
    val validationObservation: RepairRecordedValidationObservation? = null,
) {
    val retainedCases: List<RepairRecordedIdentity> = immutableRecordedList(retainedCases)
}

internal data class RepairRecordedRun internal constructor(
    val schemaVersion: Int,
    val identity: RepairRecordedIdentity,
    val status: RepairRunStatus,
    val baseline: RepairRecordedIdentity,
    val acceptedHead: RepairRecordedIdentity?,
    val provisionalHead: RepairRecordedIdentity?,
    val corpusSha256: String,
    val maximumAttempts: Int,
    val attemptedCount: Int,
    val startedEpochMillis: Long,
    val deadlineEpochMillis: Long,
    val rollbackFailureAttempt: RepairRecordedIdentity?,
    val rollbackResolution: RepairRollbackState?,
    val validationDiagnostic: RepairRecordedValidationDiagnostic? = null,
    val baselineValidationObservation: RepairRecordedValidationObservation? = null,
) {
    val remainingAttempts: Int get() = maximumAttempts - attemptedCount
}

/** Opaque references and commitments only; this capture does not read either artifact. */
internal data class RepairRecordedValidationDiagnostic internal constructor(
    val invocationSha256: String,
    val candidate: RepairRecordedIdentity,
    val sourceRevisionSha256: String,
    val profileSha256: String,
    val indexSha256: String,
    val regressionCorpusSha256: String,
    val runtimeSha256: String,
    val receipt: RepairRecordedArtifactReference,
    val receiptSha256: String,
    val receiptBytes: Long,
    val diagnostic: RepairRecordedArtifactReference,
    val diagnosticSha256: String,
    val diagnosticBytes: Int,
    val failureKind: RepairValidationFailureKind,
    val cleanupVerified: Boolean,
)

internal data class RepairRecordedValidationObservedArtifact internal constructor(
    val artifact: RepairRecordedArtifactReference,
    val sha256: String,
    val bytes: Long,
)

/** The canonical run checked the invocation relation; private report paths are withheld. */
internal data class RepairRecordedValidationObservation internal constructor(
    val invocationSha256: String,
    val candidate: RepairRecordedIdentity,
    val proof: RepairValidationProof,
    val outcome: RepairValidationObservedOutcome,
    val primary: RepairRecordedValidationObservedArtifact,
    val diff: RepairRecordedValidationObservedArtifact?,
) {
    val comparisonPolicy: String get() = "exact-bytes-v1"
}

/** Input only; the byte facade copies each admitted payload before parsing it. */
internal class RepairHistoryDeclaredGraph(val name: String, val bytes: ByteArray)

/** Closed, stackless and cause-free: rejected private input never becomes a diagnostic graph. */
internal class RepairHistorySnapshotRefusal internal constructor() :
    RuntimeException("Recorded repair metadata is invalid or exceeds its bound.", null, false, false)

private fun <T> immutableRecordedList(values: Collection<T>): List<T> =
    Collections.unmodifiableList(ArrayList(values))

/** Construction-local table; no caller callback, global cache or public hash override. */
internal class RepairHistoryIdentityReferences internal constructor(private val corpusSha256: String) {
    private val originals = HashMap<String, String>()

    fun revision(value: String): RepairRecordedIdentity {
        val public = PUBLIC_RECORDED_ID.matches(value)
        val reference = if (public) value else "opaque_" + referenceDigest("decompengine.repair.public-identity.v1", value)
        register(reference, value)
        return RepairRecordedIdentity(reference, !public)
    }

    fun case(value: String): RepairRecordedIdentity = case(value, corpusSha256)

    fun case(value: String, boundCorpusSha256: String): RepairRecordedIdentity {
        require(CORPUS_DIGEST.matches(boundCorpusSha256)) { "Recorded case corpus is invalid." }
        val bytes = value.toByteArray(Charsets.UTF_8)
        val prefix = "decompengine.repair.public-case.v1\n$boundCorpusSha256\n${bytes.size}:".toByteArray(Charsets.UTF_8)
        val reference = "case_" + sha256(prefix + bytes)
        register(reference, value)
        return RepairRecordedIdentity(reference, true)
    }

    fun artifact(value: String): RepairRecordedArtifactReference {
        val reference = recordedRepairArtifactReference(corpusSha256, value)
        register(reference.value, value)
        return reference
    }

    private fun referenceDigest(domain: String, value: String): String {
        val bytes = value.toByteArray(Charsets.UTF_8)
        return sha256((domain + "\n" + bytes.size + ":").toByteArray(Charsets.UTF_8) + bytes)
    }

    private fun register(reference: String, original: String) {
        val previous = originals.putIfAbsent(reference, original)
        require(previous == null || previous == original) { "Recorded identity reference collision." }
    }

    private companion object {
        val CORPUS_DIGEST = Regex("[0-9a-f]{64}")
        val PUBLIC_RECORDED_ID = Regex("(?:root_[0-9a-f]{24}|revision_[0-9]{8}_[0-9a-f]{16}|run_[0-9]{8})")
    }
}

/** Length framing and the captured corpus bind this opaque reference without retaining its path. */
internal fun recordedRepairArtifactReference(corpusSha256: String, value: String): RepairRecordedArtifactReference {
    val bytes = value.toByteArray(Charsets.UTF_8)
    val prefix = "decompengine.repair.public-artifact.v1\n$corpusSha256\n${bytes.size}:".toByteArray(Charsets.UTF_8)
    return RepairRecordedArtifactReference("artifact_" + sha256(prefix + bytes))
}

/** Unknown valid terminal strings can contain private text; retain only a domain-bound digest. */
internal fun recordedRepairTerminalSha256(value: String): String {
    val bytes = value.toByteArray(Charsets.UTF_8)
    return sha256(("decompengine.repair.public-terminal.v1\n${bytes.size}:").toByteArray(Charsets.UTF_8) + bytes)
}

internal fun recordedRepairTerminal(value: String): RepairRecordedTerminal = when (value) {
    "returned-completed" -> RepairRecordedTerminal.COMPLETED
    "returned-no-changes" -> RepairRecordedTerminal.NO_CHANGES
    "returned-refused" -> RepairRecordedTerminal.REFUSED
    "returned-cancelled", "failed-cancelled" -> RepairRecordedTerminal.CANCELLED
    "returned-limit-exhausted", "failed-resource-exhausted", "failed-timeout" -> RepairRecordedTerminal.LIMIT_EXHAUSTED
    "failed-process-crash" -> RepairRecordedTerminal.PROCESS_CRASHED
    else -> RepairRecordedTerminal.OTHER
}

internal fun recordedRepairEvidenceKind(value: String?): RepairRecordedEvidenceKind = when (value) {
    "compile", "compile-valid" -> RepairRecordedEvidenceKind.BUILD
    "behavior", "valid" -> RepairRecordedEvidenceKind.BEHAVIOR
    "retained-regression" -> RepairRecordedEvidenceKind.REGRESSION
    "crash-recovery" -> RepairRecordedEvidenceKind.RECOVERY
    "no-validated-improvement" -> RepairRecordedEvidenceKind.VALIDATION
    "agent-no-change", "agent-stop-no-changes" -> RepairRecordedEvidenceKind.NO_CHANGE
    "agent-stop-refused" -> RepairRecordedEvidenceKind.REFUSED
    "agent-stop-cancelled", "agent-failure-cancelled" -> RepairRecordedEvidenceKind.CANCELLED
    "agent-stop-limit-exhausted", "agent-failure-resource-exhausted", "agent-failure-timeout" -> RepairRecordedEvidenceKind.LIMIT_EXHAUSTED
    "agent-failure-process-crash" -> RepairRecordedEvidenceKind.PROCESS_CRASHED
    "assessment-error", "validation-error" -> RepairRecordedEvidenceKind.VALIDATION_FAILED
    else -> RepairRecordedEvidenceKind.OTHER
}

/** Correlation of a captured derived projection only; never canonical or execution authority. */
internal enum class RepairHistoryProjectionStatus {
    NOT_INSPECTED, MISSING, EMPTY, UNAVAILABLE, CHANGED_DURING_CAPTURE, INVALID,
    UNVERIFIABLE_ENCODING, DOES_NOT_MATCH_CAPTURED_GRAPH, MATCHED_CAPTURED_PROJECTION,
}
internal enum class RepairHistoryProjectionReason { NONE, CAPTURE, ENCODING, VERSION, CORPUS, ITERATIONS, METADATA, PATCH, RUNS, CANONICAL }
internal enum class RepairHistoryProjectionCoverage { NOT_INSPECTED, LEGACY_FINALIZED_AND_CORPUS, FINALIZED_CORPUS_AND_RUNS }
internal data class RepairHistoryProjectionDiagnostic(
    val status: RepairHistoryProjectionStatus,
    val reason: RepairHistoryProjectionReason = RepairHistoryProjectionReason.NONE,
    val schemaVersion: Int? = null,
    val admittedBytes: Long? = null,
    val capturedSha256: String? = null,
) {
    val coverage: RepairHistoryProjectionCoverage get() = when (schemaVersion) {
        1, 2 -> RepairHistoryProjectionCoverage.LEGACY_FINALIZED_AND_CORPUS
        3 -> RepairHistoryProjectionCoverage.FINALIZED_CORPUS_AND_RUNS
        else -> RepairHistoryProjectionCoverage.NOT_INSPECTED
    }
    init {
        require(schemaVersion == null || schemaVersion in 1..3)
        require(admittedBytes == null || admittedBytes in 0..MAXIMUM_REPAIR_PROJECTION_BYTES)
        require(capturedSha256 == null || capturedSha256.matches(Regex("[0-9a-f]{64}")))
    }
}
