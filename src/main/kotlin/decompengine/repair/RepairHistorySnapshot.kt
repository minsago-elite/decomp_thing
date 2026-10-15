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
    val viewSchemaVersion: Int get() = 1
    val qualification: RepairRecordedQualification get() = RepairRecordedQualification.RECORDED_METADATA_ONLY
    val runs: List<RepairRecordedRun> = immutableRecordedList(runs)
    val attempts: List<RepairRecordedAttempt> = immutableRecordedList(attempts)
    val retainedCases: List<RepairRecordedIdentity> = immutableRecordedList(retainedCases)
}

internal enum class RepairRecordedQualification { RECORDED_METADATA_ONLY }
internal enum class RepairRecordedGraphWire { COMPACT, EXPLICIT_NULL }
internal enum class RepairRecordedAttemptKind { FINALIZED, PENDING }
internal enum class RepairRecordedReceiptStatus { NOT_READ }

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
) {
    val remainingAttempts: Int get() = maximumAttempts - attemptedCount
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

    fun case(value: String): RepairRecordedIdentity {
        val bytes = value.toByteArray(Charsets.UTF_8)
        val prefix = "decompengine.repair.public-case.v1\n$corpusSha256\n${bytes.size}:".toByteArray(Charsets.UTF_8)
        val reference = "case_" + sha256(prefix + bytes)
        register(reference, value)
        return RepairRecordedIdentity(reference, true)
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
        val PUBLIC_RECORDED_ID = Regex("(?:root_[0-9a-f]{24}|revision_[0-9]{8}_[0-9a-f]{16}|run_[0-9]{8})")
    }
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
