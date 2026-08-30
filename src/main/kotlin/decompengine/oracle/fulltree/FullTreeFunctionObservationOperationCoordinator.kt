package decompengine.oracle.fulltree

import decompengine.oracle.core.DescriptorBoundStateFaultInjector
import java.nio.file.Path
import java.security.MessageDigest

internal class FullTreeFunctionObservationOperationCoordinationException(
    message: String,
) : IllegalArgumentException(message)

/**
 * Fresh-operation composition substrate with the mandatory lock order:
 * journal root, operation journal, then disk-mount flock.
 *
 * This coordinator does not launch a worker, mutate recovery residue, publish output, or authorize
 * release. Its only state transition is PREPARING to an exactly evidenced LEASED operation; cold
 * composition accepts only an already fully published LEASED history and observes disk read-only.
 */
internal object FullTreeFunctionObservationOperationCoordinator {
    fun prepareNew(
        authority: FullTreeFunctionObservationJournalAuthority,
        binding: FullTreeFunctionObservationOperationBinding,
        provisionedMount: Path,
        initializationFaultInjector: DescriptorBoundStateFaultInjector? = null,
        evidenceFaultInjector: DescriptorBoundStateFaultInjector? = null,
        transitionFaultInjector: DescriptorBoundStateFaultInjector? = null,
    ): FullTreeFunctionObservationLeasedOperation {
        var journal: FullTreeFunctionObservationOperationJournal? = null
        var lease: FullTreeDiskScratchLease? = null
        try {
            val ownedJournal = authority.createNew(binding)
            journal = ownedJournal
            ownedJournal.initialize(initializationFaultInjector)

            val ownedLease = FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(
                provisionedMount,
                binding.diskOperation(),
                binding.diskPolicy(),
            )
            lease = ownedLease
            ownedLease.requireCurrent(FullTreeDiskScratchStage.AUTHORIZED)
            val leasedHistory = ownedJournal.recordLeased(
                ownedLease.evidence,
                evidenceFaultInjector,
                transitionFaultInjector,
            )
            val acceptedEvidence = leasedHistory.requireDiskEvidenceIntroducedAt(
                FullTreeFunctionObservationOperationPhase.LEASED,
            )
            requireExactEvidence(ownedLease.evidence, acceptedEvidence)
            ownedLease.requireCurrent(FullTreeDiskScratchStage.AUTHORIZED)

            val prepared = FullTreeFunctionObservationLeasedOperation(
                leasedHistory,
                acceptedEvidence,
                ownedJournal,
                ownedLease,
            )
            journal = null
            lease = null
            return prepared
        } catch (failure: Throwable) {
            lease?.let { opened ->
                runCatching { opened.abandonForRecovery() }.exceptionOrNull()?.let(failure::addSuppressed)
            }
            journal?.let { opened ->
                runCatching { opened.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            }
            throw failure
        }
    }

    /**
     * Reopens one fully published LEASED operation in journal-first lock order and reconciles its
     * journal-derived evidence against the residual disk lease without completing or appending any
     * journal publication. Pending, staged-only, post-LEASED, and terminal histories fail closed.
     */
    fun openExistingLeasedReadOnly(
        authority: FullTreeFunctionObservationJournalAuthority,
        binding: FullTreeFunctionObservationOperationBinding,
        provisionedMount: Path,
    ): FullTreeFunctionObservationColdLeasedOperation {
        var journal: FullTreeFunctionObservationOperationJournal? = null
        var coldLease: FullTreeDiskScratchColdLease? = null
        try {
            val ownedJournal = authority.openExisting(binding)
                ?: coordinationFail("function-observation LEASED operation journal is absent")
            journal = ownedJournal
            val leasedHistory = ownedJournal.loadOrNull()
                ?: coordinationFail("function-observation LEASED operation journal is empty")
            val diskEvidence = requireExactlyLeasedHistory(leasedHistory)

            val ownedColdLease = FullTreeDiskScratchAuthority.openExistingReadOnly(
                provisionedMount,
                binding.diskOperation(),
                binding.diskPolicy(),
            )
            coldLease = ownedColdLease
            val snapshot = requireCurrentColdLeasedOperation(
                expectedHistory = leasedHistory,
                expectedEvidence = diskEvidence,
                expectedSnapshot = null,
                journal = ownedJournal,
                coldLease = ownedColdLease,
            )
            val opened = FullTreeFunctionObservationColdLeasedOperation.create(
                leasedHistory = leasedHistory,
                diskEvidence = diskEvidence,
                initialSnapshot = snapshot,
                journal = ownedJournal,
                coldLease = ownedColdLease,
                constructionPermit = COLD_LEASED_OPERATION_CONSTRUCTION_PERMIT,
            )
            journal = null
            coldLease = null
            return opened
        } catch (failure: Throwable) {
            coldLease?.let { opened ->
                runCatching { opened.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            }
            journal?.let { opened ->
                runCatching { opened.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            }
            throw failure
        }
    }
}

/**
 * Lock-retaining fresh LEASED operation. Closing releases the mount flock before the operation
 * journal lock and preserves all journal and disk residue for cold reconciliation.
 */
internal class FullTreeFunctionObservationLeasedOperation internal constructor(
    val leasedHistory: FullTreeFunctionObservationOperationHistory,
    val diskEvidence: FullTreeDiskScratchEvidence,
    private val journal: FullTreeFunctionObservationOperationJournal,
    private val lease: FullTreeDiskScratchLease,
) : AutoCloseable {
    val scratchParent: Path = lease.scratchParent
    private var closed = false

    init {
        if (
            leasedHistory.latest?.phase != FullTreeFunctionObservationOperationPhase.LEASED ||
            leasedHistory.diskEvidence !== diskEvidence
        ) {
            coordinationFail("leased operation did not retain its journal-parsed disk evidence")
        }
        leasedHistory.requireDiskEvidenceIntroducedAt(
            FullTreeFunctionObservationOperationPhase.LEASED,
        )
    }

    /** Revalidates the unchanged LEASED journal and record-only lease while all locks remain held. */
    @Synchronized
    fun requireCurrentAuthorized() {
        check(!closed) { "function-observation leased operation is closed" }
        requireCurrent(FullTreeDiskScratchStage.AUTHORIZED)
    }

    /**
     * Creates the deterministic empty run root and transfers ownership into the typed pre-launch
     * state. A failure closes locks/descriptors without removing any run, lease, or journal member.
     */
    @Synchronized
    fun prepareRunRoot(
        faultInjector: FullTreeDiskScratchRunRootFaultInjector? = null,
    ): FullTreeFunctionObservationPreparedRun {
        check(!closed) { "function-observation leased operation is closed" }
        return try {
            requireCurrent(FullTreeDiskScratchStage.AUTHORIZED)
            val runRoot = lease.createEmptyOperationRunRoot(faultInjector)
            requireCurrent(FullTreeDiskScratchStage.BEFORE_LAUNCH)
            val prepared = FullTreeFunctionObservationPreparedRun.create(
                leasedHistory = leasedHistory,
                diskEvidence = diskEvidence,
                runRoot = runRoot,
                journal = journal,
                lease = lease,
                constructionPermit = PREPARED_RUN_CONSTRUCTION_PERMIT,
            )
            closed = true
            prepared
        } catch (failure: Throwable) {
            runCatching { close() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
    }

    private fun requireCurrent(stage: FullTreeDiskScratchStage) {
        requireCurrentHistory(leasedHistory, diskEvidence, journal)
        lease.requireCurrent(stage)
        requireCurrentHistory(leasedHistory, diskEvidence, journal)
        lease.requireCurrent(stage)
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        closeOperationResources(lease, journal)?.let { throw it }
    }
}

/**
 * Typed LEASED operation with one pinned deterministic run root and no worker/cgroup claim.
 * Closing preserves the active-run residue and releases run, mount, then journal authorities.
 */
private object PREPARED_RUN_CONSTRUCTION_PERMIT

internal class FullTreeFunctionObservationPreparedRun private constructor(
    val leasedHistory: FullTreeFunctionObservationOperationHistory,
    val diskEvidence: FullTreeDiskScratchEvidence,
    private val runRoot: FullTreeDiskScratchRunRoot,
    private val journal: FullTreeFunctionObservationOperationJournal,
    private val lease: FullTreeDiskScratchLease,
) : AutoCloseable {
    private var closed = false

    init {
        if (
            leasedHistory.latest?.phase != FullTreeFunctionObservationOperationPhase.LEASED ||
            leasedHistory.diskEvidence !== diskEvidence
        ) coordinationFail("prepared run is not bound to one fresh leased operation")
        leasedHistory.requireDiskEvidenceIntroducedAt(
            FullTreeFunctionObservationOperationPhase.LEASED,
        )
        lease.requireCurrentOperationRunRoot(
            runRoot,
            FullTreeDiskScratchStage.BEFORE_LAUNCH,
        )
    }

    /** Revalidates the unchanged LEASED journal and exact active run before any worker launch. */
    @Synchronized
    fun requireCurrentBeforeLaunch() {
        check(!closed) { "function-observation prepared run is closed" }
        requireCurrentHistory(leasedHistory, diskEvidence, journal)
        lease.requireCurrentOperationRunRoot(
            runRoot,
            FullTreeDiskScratchStage.BEFORE_LAUNCH,
        )
        requireCurrentHistory(leasedHistory, diskEvidence, journal)
        lease.requireCurrentOperationRunRoot(
            runRoot,
            FullTreeDiskScratchStage.BEFORE_LAUNCH,
        )
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        closeOperationResources(lease, journal)?.let { throw it }
    }

    companion object {
        internal fun create(
            leasedHistory: FullTreeFunctionObservationOperationHistory,
            diskEvidence: FullTreeDiskScratchEvidence,
            runRoot: FullTreeDiskScratchRunRoot,
            journal: FullTreeFunctionObservationOperationJournal,
            lease: FullTreeDiskScratchLease,
            constructionPermit: Any,
        ): FullTreeFunctionObservationPreparedRun {
            check(constructionPermit === PREPARED_RUN_CONSTRUCTION_PERMIT) {
                "prepared-run capabilities can only be issued by the operation coordinator"
            }
            return FullTreeFunctionObservationPreparedRun(
                leasedHistory,
                diskEvidence,
                runRoot,
                journal,
                lease,
            )
        }
    }
}

private object COLD_LEASED_OPERATION_CONSTRUCTION_PERMIT

/**
 * Lock-retaining observation of one exact, fully published LEASED history and its residual disk
 * population. The captured population is historical inspection data, not launch or mutation
 * authority. Closing releases only descriptors and locks, disk first and journal second.
 */
internal class FullTreeFunctionObservationColdLeasedOperation private constructor(
    val leasedHistory: FullTreeFunctionObservationOperationHistory,
    val diskEvidence: FullTreeDiskScratchEvidence,
    val observedPopulation: FullTreeDiskScratchColdPopulation,
    private val initialSnapshot: FullTreeDiskScratchColdSnapshot,
    private val journal: FullTreeFunctionObservationOperationJournal,
    private val coldLease: FullTreeDiskScratchColdLease,
) : AutoCloseable {
    private var closed = false

    init {
        val acceptedEvidence = requireExactlyLeasedHistory(leasedHistory)
        if (acceptedEvidence !== diskEvidence || observedPopulation != initialSnapshot.population) {
            coordinationFail("cold LEASED operation did not retain its exact initial observation")
        }
        requireCurrentColdLeasedOperation(
            expectedHistory = leasedHistory,
            expectedEvidence = diskEvidence,
            expectedSnapshot = initialSnapshot,
            journal = journal,
            coldLease = coldLease,
        )
    }

    /**
     * Repeats exact journal/evidence reconciliation around coarse disk-population inspections; the
     * active run tree remains deliberately opaque and untraversed.
     */
    @Synchronized
    fun requireCurrentReadOnly() {
        check(!closed) { "function-observation cold LEASED operation is closed" }
        requireCurrentColdLeasedOperation(
            expectedHistory = leasedHistory,
            expectedEvidence = diskEvidence,
            expectedSnapshot = initialSnapshot,
            journal = journal,
            coldLease = coldLease,
        )
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        closeColdOperationResources(coldLease, journal)?.let { throw it }
    }

    companion object {
        internal fun create(
            leasedHistory: FullTreeFunctionObservationOperationHistory,
            diskEvidence: FullTreeDiskScratchEvidence,
            initialSnapshot: FullTreeDiskScratchColdSnapshot,
            journal: FullTreeFunctionObservationOperationJournal,
            coldLease: FullTreeDiskScratchColdLease,
            constructionPermit: Any,
        ): FullTreeFunctionObservationColdLeasedOperation {
            check(constructionPermit === COLD_LEASED_OPERATION_CONSTRUCTION_PERMIT) {
                "cold LEASED capabilities can only be issued by the operation coordinator"
            }
            return FullTreeFunctionObservationColdLeasedOperation(
                leasedHistory,
                diskEvidence,
                initialSnapshot.population,
                initialSnapshot,
                journal,
                coldLease,
            )
        }
    }
}

private fun requireExactlyLeasedHistory(
    history: FullTreeFunctionObservationOperationHistory,
): FullTreeDiskScratchEvidence {
    if (
        history.transitions.map { it.phase } != listOf(
            FullTreeFunctionObservationOperationPhase.PREPARING,
            FullTreeFunctionObservationOperationPhase.LEASED,
        )
    ) coordinationFail("cold composition requires one fully published LEASED operation")
    return history.requireDiskEvidenceIntroducedAt(
        FullTreeFunctionObservationOperationPhase.LEASED,
    ).also { evidence ->
        if (history.diskEvidence !== evidence) {
            coordinationFail("cold LEASED history did not retain its parsed disk evidence")
        }
    }
}

private fun requireCurrentColdLeasedOperation(
    expectedHistory: FullTreeFunctionObservationOperationHistory,
    expectedEvidence: FullTreeDiskScratchEvidence,
    expectedSnapshot: FullTreeDiskScratchColdSnapshot?,
    journal: FullTreeFunctionObservationOperationJournal,
    coldLease: FullTreeDiskScratchColdLease,
): FullTreeDiskScratchColdSnapshot {
    requireCurrentHistory(expectedHistory, expectedEvidence, journal)
    val first = coldLease.requireCurrent(expectedEvidence)
    requireCurrentHistory(expectedHistory, expectedEvidence, journal)
    val second = coldLease.requireCurrent(expectedEvidence)
    if (first != second || (expectedSnapshot != null && second != expectedSnapshot)) {
        coordinationFail("cold LEASED disk population changed during exact reconciliation")
    }
    return second
}

private fun requireCurrentHistory(
    expectedHistory: FullTreeFunctionObservationOperationHistory,
    expectedEvidence: FullTreeDiskScratchEvidence,
    journal: FullTreeFunctionObservationOperationJournal,
) {
    val current = journal.loadOrNull()
        ?: coordinationFail("function-observation leased operation journal disappeared")
    val currentEvidence = current.requireDiskEvidenceIntroducedAt(
        FullTreeFunctionObservationOperationPhase.LEASED,
    )
    requireExactEvidence(expectedEvidence, currentEvidence)
    requireExactHistory(expectedHistory, current)
}

private fun closeOperationResources(
    lease: FullTreeDiskScratchLease,
    journal: FullTreeFunctionObservationOperationJournal,
): Throwable? {
    var failure: Throwable? = null
    runCatching { lease.abandonForRecovery() }.exceptionOrNull()?.let { failure = it }
    runCatching { journal.close() }.exceptionOrNull()?.let { closeFailure ->
        if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
    }
    return failure
}

private fun closeColdOperationResources(
    coldLease: FullTreeDiskScratchColdLease,
    journal: FullTreeFunctionObservationOperationJournal,
): Throwable? {
    var failure: Throwable? = null
    runCatching { coldLease.close() }.exceptionOrNull()?.let { failure = it }
    runCatching { journal.close() }.exceptionOrNull()?.let { closeFailure ->
        if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
    }
    return failure
}

private fun requireExactEvidence(
    expected: FullTreeDiskScratchEvidence,
    actual: FullTreeDiskScratchEvidence,
) {
    if (!MessageDigest.isEqual(expected.canonicalBytes(), actual.canonicalBytes())) {
        coordinationFail("function-observation leased operation has different exact disk evidence")
    }
}

private fun requireExactHistory(
    expected: FullTreeFunctionObservationOperationHistory,
    actual: FullTreeFunctionObservationOperationHistory,
) {
    if (
        !MessageDigest.isEqual(expected.binding.canonicalBytes(), actual.binding.canonicalBytes()) ||
        expected.transitions.size != actual.transitions.size ||
        expected.transitions.zip(actual.transitions).any { (left, right) ->
            !MessageDigest.isEqual(left.canonicalBytes(), right.canonicalBytes())
        }
    ) coordinationFail("function-observation leased operation journal changed")
}

private fun coordinationFail(message: String): Nothing =
    throw FullTreeFunctionObservationOperationCoordinationException(message)
