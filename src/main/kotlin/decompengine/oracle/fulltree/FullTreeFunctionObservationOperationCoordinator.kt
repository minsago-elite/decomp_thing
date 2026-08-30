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
 * release. Its only state transition is PREPARING to an exactly evidenced LEASED operation.
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

    /** Revalidates the unchanged LEASED journal and live lease twice while all locks remain held. */
    @Synchronized
    fun requireCurrent(stage: FullTreeDiskScratchStage) {
        check(!closed) { "function-observation leased operation is closed" }
        requireCurrentHistory()
        lease.requireCurrent(stage)
        requireCurrentHistory()
        lease.requireCurrent(stage)
    }

    private fun requireCurrentHistory() {
        val current = journal.loadOrNull()
            ?: coordinationFail("function-observation leased operation journal disappeared")
        val currentEvidence = current.requireDiskEvidenceIntroducedAt(
            FullTreeFunctionObservationOperationPhase.LEASED,
        )
        requireExactEvidence(diskEvidence, currentEvidence)
        requireExactHistory(leasedHistory, current)
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        runCatching { lease.abandonForRecovery() }.exceptionOrNull()?.let { failure = it }
        runCatching { journal.close() }.exceptionOrNull()?.let { closeFailure ->
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        failure?.let { throw it }
    }
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
