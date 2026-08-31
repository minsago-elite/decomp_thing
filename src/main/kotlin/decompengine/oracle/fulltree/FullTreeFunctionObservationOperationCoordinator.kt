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
    private var runRootBorrowActive = false

    init {
        if (
            leasedHistory.latest?.phase != FullTreeFunctionObservationOperationPhase.LEASED ||
            leasedHistory.diskEvidence !== diskEvidence
        ) coordinationFail("prepared run is not bound to one fresh leased operation")
        leasedHistory.requireDiskEvidenceIntroducedAt(
            FullTreeFunctionObservationOperationPhase.LEASED,
        )
        requireCurrentPreparedRun(leasedHistory, diskEvidence, runRoot, journal, lease)
    }

    /** Revalidates the unchanged LEASED journal and exact active run before any worker launch. */
    @Synchronized
    fun requireCurrentBeforeLaunch() {
        check(!closed) { "function-observation prepared run is closed" }
        requireCurrentPreparedRun(leasedHistory, diskEvidence, runRoot, journal, lease)
    }

    /**
     * Retains the journal lock, mount flock, opaque run-root token, and this handle's monitor while
     * granting one revocable descriptor-backed run-root borrow. Both authorities are revalidated
     * around the callback; callback failure remains primary and never closes either authority.
     */
    @Synchronized
    fun <T> withCurrentRunRootBeforeLaunch(
        action: (FullTreeDiskScratchBorrowedRunRoot) -> T,
    ): T {
        check(!closed) { "function-observation prepared run is closed" }
        if (runRootBorrowActive) {
            coordinationFail("function-observation prepared run root is already borrowed")
        }
        runRootBorrowActive = true
        try {
            requireCurrentBeforeLaunch()
            return try {
                lease.withCurrentOperationRunRootBeforeLaunch(runRoot) { borrowed ->
                    requireCurrentHistory(leasedHistory, diskEvidence, journal)
                    try {
                        action(borrowed).also {
                            requireCurrentHistory(leasedHistory, diskEvidence, journal)
                        }
                    } catch (failure: Throwable) {
                        runCatching {
                            requireCurrentHistory(leasedHistory, diskEvidence, journal)
                        }.exceptionOrNull()?.let { validationFailure ->
                            if (validationFailure !== failure) failure.addSuppressed(validationFailure)
                        }
                        throw failure
                    }
                }.also { requireCurrentBeforeLaunch() }
            } catch (failure: Throwable) {
                runCatching { requireCurrentBeforeLaunch() }.exceptionOrNull()?.let { validationFailure ->
                    if (validationFailure !== failure) failure.addSuppressed(validationFailure)
                }
                throw failure
            }
        } finally {
            runRootBorrowActive = false
        }
    }

    /**
     * Moves the still-LEASED journal, lease, and opaque run root into the isolation-preparation
     * owner before the isolation layer establishes an exact interior-layout claim. The old handle
     * becomes inert only after the replacement has independently revalidated every authority; no
     * descriptor, lock, or filesystem member is closed or changed by the transfer itself. This
     * low-level transfer proves no prior-content history for the otherwise opaque run root.
     */
    @Synchronized
    internal fun transferToPreparedIsolationAuthority():
        FullTreeFunctionObservationPreparedIsolationAuthority {
        check(!closed) { "function-observation prepared run is closed" }
        if (runRootBorrowActive) {
            coordinationFail("function-observation prepared run cannot transfer while its root is borrowed")
        }
        requireCurrentBeforeLaunch()
        val transferred = FullTreeFunctionObservationPreparedIsolationAuthority.create(
            leasedHistory = leasedHistory,
            diskEvidence = diskEvidence,
            runRoot = runRoot,
            journal = journal,
            lease = lease,
            constructionPermit = PREPARED_ISOLATION_AUTHORITY_CONSTRUCTION_PERMIT,
        )
        closed = true
        return transferred
    }

    @Synchronized
    override fun close() {
        if (closed) return
        if (runRootBorrowActive) {
            coordinationFail("function-observation prepared run cannot close while its root is borrowed")
        }
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

private object PREPARED_ISOLATION_AUTHORITY_CONSTRUCTION_PERMIT
private object ATTACHED_ISOLATION_AUTHORITY_CONSTRUCTION_PERMIT

private enum class PreparedIsolationRunRootBorrowStage {
    BEFORE_LAUNCH,
    SCOPE_ATTACHMENT,
    AFTER_SCOPE_ATTACHMENT,
}

/**
 * Content-opaque lock-retaining owner used while the isolation layer authenticates and materializes
 * the deterministic run tree. Only the outer typed isolation handle proves interior layout. This
 * history is still LEASED: no durable worker or unit claim exists, and failed preparation preserves
 * residue. Crossing the scope-attachment borrow consumes pre-launch authority even though a later
 * live-unit proof remains mandatory before any journal phase may advance.
 */
internal class FullTreeFunctionObservationPreparedIsolationAuthority private constructor(
    val leasedHistory: FullTreeFunctionObservationOperationHistory,
    val diskEvidence: FullTreeDiskScratchEvidence,
    private val runRoot: FullTreeDiskScratchRunRoot,
    private val journal: FullTreeFunctionObservationOperationJournal,
    private val lease: FullTreeDiskScratchLease,
) : AutoCloseable {
    private var closed = false
    private var runRootBorrowActive = false
    private var scopeAttachmentAttempted = false
    private var launchBoundaryAbsenceAccepted = false
    private var attachmentPublicationAttempted = false

    init {
        if (
            leasedHistory.latest?.phase != FullTreeFunctionObservationOperationPhase.LEASED ||
            leasedHistory.diskEvidence !== diskEvidence
        ) coordinationFail("prepared isolation is not bound to one fresh leased operation")
        leasedHistory.requireDiskEvidenceIntroducedAt(
            FullTreeFunctionObservationOperationPhase.LEASED,
        )
        requireCurrentPreparedRun(leasedHistory, diskEvidence, runRoot, journal, lease)
    }

    /** Revalidates the unchanged LEASED journal and exact opaque active run before launch. */
    @Synchronized
    fun requireCurrentBeforeLaunch() {
        check(!closed) { "function-observation prepared isolation is closed" }
        if (scopeAttachmentAttempted) {
            coordinationFail("function-observation prepared isolation already attempted scope attachment")
        }
        requireCurrentPreparedRun(
            leasedHistory,
            diskEvidence,
            runRoot,
            journal,
            lease,
            FullTreeDiskScratchStage.BEFORE_LAUNCH,
        )
    }

    /** Revalidates the still-LEASED journal and run root after a caller-owned attachment attempt. */
    @Synchronized
    fun requireCurrentAfterScopeAttachment() {
        check(!closed) { "function-observation prepared isolation is closed" }
        if (attachmentPublicationAttempted) {
            coordinationFail("function-observation attachment publication was already attempted")
        }
        if (!scopeAttachmentAttempted) {
            coordinationFail("function-observation prepared isolation has not attempted scope attachment")
        }
        if (launchBoundaryAbsenceAccepted) {
            coordinationFail("function-observation launch boundary absence was already accepted")
        }
        requireCurrentPreparedRun(
            leasedHistory,
            diskEvidence,
            runRoot,
            journal,
            lease,
            FullTreeDiskScratchStage.AFTER_SCOPE_ATTACHMENT,
        )
    }

    /**
     * Revalidates the still-LEASED journal and active run after the caller independently proves
     * cgroup absence. It does not itself inspect, kill, or certify any unit or cgroup.
     */
    @Synchronized
    fun requireCurrentAfterCgroupAbsence() {
        check(!closed) { "function-observation prepared isolation is closed" }
        if (attachmentPublicationAttempted) {
            coordinationFail("function-observation attachment publication was already attempted")
        }
        if (!scopeAttachmentAttempted) {
            coordinationFail("function-observation prepared isolation has not attempted scope attachment")
        }
        requireCurrentPreparedRun(
            leasedHistory,
            diskEvidence,
            runRoot,
            journal,
            lease,
            FullTreeDiskScratchStage.AFTER_CGROUP_ABSENCE,
        )
        launchBoundaryAbsenceAccepted = true
    }

    /**
     * Selects the only honest close-side disk stage after the caller has proved that its launch
     * boundary is absent. A callback that was never entered remains pre-launch; entering the
     * callback, even if it later failed, permanently requires AFTER_CGROUP_ABSENCE validation.
     * This method does not inspect or certify process, unit, or cgroup absence itself.
     */
    @Synchronized
    fun requireCurrentAfterProvedLaunchBoundaryAbsence() {
        if (scopeAttachmentAttempted) {
            requireCurrentAfterCgroupAbsence()
        } else {
            requireCurrentBeforeLaunch()
        }
    }

    /** Grants one revocable pinned borrow while retaining the transferred lock hierarchy. */
    @Synchronized
    fun <T> withCurrentRunRootBeforeLaunch(
        action: (FullTreeDiskScratchBorrowedRunRoot) -> T,
    ): T = withCurrentRunRoot(PreparedIsolationRunRootBorrowStage.BEFORE_LAUNCH, action)

    /**
     * Retains the journal/mount lock hierarchy across one external scope-attachment attempt. The
     * callback is entered only after pre-launch disk validation; entering it irrevocably consumes
     * this authority's pre-launch state because an exception cannot prove that no process started.
     * The callback result is not by itself live-unit or UNIT_ATTACHED evidence.
     */
    @Synchronized
    fun <T> withCurrentRunRootForScopeAttachment(
        action: (FullTreeDiskScratchBorrowedRunRoot) -> T,
    ): T = withCurrentRunRoot(PreparedIsolationRunRootBorrowStage.SCOPE_ATTACHMENT, action)

    /** Grants a non-owning run-root borrow after attachment while history honestly remains LEASED. */
    @Synchronized
    fun <T> withCurrentRunRootAfterScopeAttachment(
        action: (FullTreeDiskScratchBorrowedRunRoot) -> T,
    ): T = withCurrentRunRoot(PreparedIsolationRunRootBorrowStage.AFTER_SCOPE_ATTACHMENT, action)

    /**
     * Linearly advances the journal from LEASED to UNIT_ATTACHED while retaining the journal,
     * mount, and run-root authorities. The receipt is a forgeable byte assertion at this layer;
     * only the outer live BOOT typestate may call this method, and it must use [requireLiveReceipt]
     * to revalidate the same opaque live attachment before and after publication.
     *
     * Once transaction validation begins, any failure permanently makes this owner cleanup-only;
     * the flag is set before the first journal operation because that operation may poison its
     * handle. A poisoned journal cannot be reopened without violating the journal-before-mount lock
     * order; after the caller proves its locally owned launch boundary absent,
     * [closeAfterFailedAttachmentPublication] performs disk-only validation and releases the locks
     * for cold journal completion.
     */
    @Synchronized
    internal fun transferToUnitAttachedIsolationAuthority(
        receipt: FullTreeFunctionObservationUnitAttachmentReceipt,
        requireLiveReceipt: () -> Unit,
        receiptFaultInjector: DescriptorBoundStateFaultInjector? = null,
        transitionFaultInjector: DescriptorBoundStateFaultInjector? = null,
    ): FullTreeFunctionObservationUnitAttachedIsolationAuthority {
        check(!closed) { "function-observation prepared isolation is closed" }
        if (runRootBorrowActive) {
            coordinationFail("function-observation prepared isolation cannot transfer while its root is borrowed")
        }
        if (!scopeAttachmentAttempted || launchBoundaryAbsenceAccepted || attachmentPublicationAttempted) {
            coordinationFail("function-observation prepared isolation is not at one live attachment boundary")
        }
        requireLiveReceipt()
        attachmentPublicationAttempted = true
        try {
            requireCurrentPreparedRun(
                leasedHistory,
                diskEvidence,
                runRoot,
                journal,
                lease,
                FullTreeDiskScratchStage.AFTER_SCOPE_ATTACHMENT,
            )
            val attachedHistory = journal.recordUnitAttached(
                receipt,
                receiptFaultInjector,
                transitionFaultInjector,
            )
            val acceptedEvidence = attachedHistory.requireDiskEvidenceIntroducedAt(
                FullTreeFunctionObservationOperationPhase.LEASED,
            )
            val acceptedReceipt = attachedHistory.requireUnitAttachmentReceiptIntroducedAt(
                FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
            )
            requireExactEvidence(diskEvidence, acceptedEvidence)
            requireExactReceipt(receipt, acceptedReceipt)
            requireCurrentPreparedRun(
                attachedHistory,
                diskEvidence,
                runRoot,
                journal,
                lease,
                FullTreeDiskScratchStage.AFTER_SCOPE_ATTACHMENT,
            )
            requireLiveReceipt()
            requireCurrentPreparedRun(
                attachedHistory,
                diskEvidence,
                runRoot,
                journal,
                lease,
                FullTreeDiskScratchStage.AFTER_SCOPE_ATTACHMENT,
            )
            val transferred = FullTreeFunctionObservationUnitAttachedIsolationAuthority.create(
                attachedHistory,
                diskEvidence,
                acceptedReceipt,
                runRoot,
                journal,
                lease,
                ATTACHED_ISOLATION_AUTHORITY_CONSTRUCTION_PERMIT,
            )
            closed = true
            return transferred
        } catch (failure: Throwable) {
            runCatching {
                lease.requireCurrentOperationRunRoot(
                    runRoot,
                    FullTreeDiskScratchStage.AFTER_SCOPE_ATTACHMENT,
                )
            }.exceptionOrNull()?.let { validationFailure ->
                if (validationFailure !== failure) failure.addSuppressed(validationFailure)
            }
            throw failure
        }
    }

    /** Query-only cleanup routing after a transfer call threw; it never consults the journal. */
    @Synchronized
    internal fun attachmentPublicationWasAttempted(): Boolean = attachmentPublicationAttempted

    /**
     * Cleanup-only terminal path after a failed receipt/transition transaction. The caller must
     * first prove its locally owned unit, cgroup, and pidfds absent. This method never completes a
     * journal temporary, appends a phase, mutates scratch, or releases a lease record.
     */
    @Synchronized
    internal fun closeAfterFailedAttachmentPublication() {
        check(!closed) { "function-observation prepared isolation is closed" }
        if (!scopeAttachmentAttempted || !attachmentPublicationAttempted) {
            coordinationFail("function-observation attachment publication has not failed in flight")
        }
        if (runRootBorrowActive) {
            coordinationFail("function-observation prepared isolation cannot close while its root is borrowed")
        }
        val validationFailure = runCatching {
            lease.requireCurrentOperationRunRoot(
                runRoot,
                FullTreeDiskScratchStage.AFTER_CGROUP_ABSENCE,
            )
            lease.requireCurrentOperationRunRoot(
                runRoot,
                FullTreeDiskScratchStage.AFTER_CGROUP_ABSENCE,
            )
        }.exceptionOrNull()
        launchBoundaryAbsenceAccepted = true
        closed = true
        val closeFailure = closeOperationResources(lease, journal)
        if (validationFailure != null) {
            if (closeFailure != null && closeFailure !== validationFailure) {
                validationFailure.addSuppressed(closeFailure)
            }
            throw validationFailure
        }
        closeFailure?.let { throw it }
    }

    private fun <T> withCurrentRunRoot(
        stage: PreparedIsolationRunRootBorrowStage,
        action: (FullTreeDiskScratchBorrowedRunRoot) -> T,
    ): T {
        check(!closed) { "function-observation prepared isolation is closed" }
        if (runRootBorrowActive) {
            coordinationFail("function-observation prepared isolation run root is already borrowed")
        }
        runRootBorrowActive = true
        try {
            requireCurrentForBorrow(stage)
            return try {
                val invoke: (FullTreeDiskScratchBorrowedRunRoot) -> T = { borrowed ->
                    requireCurrentHistory(leasedHistory, diskEvidence, journal)
                    if (stage == PreparedIsolationRunRootBorrowStage.SCOPE_ATTACHMENT) {
                        scopeAttachmentAttempted = true
                    }
                    try {
                        action(borrowed).also {
                            requireCurrentHistory(leasedHistory, diskEvidence, journal)
                        }
                    } catch (failure: Throwable) {
                        runCatching {
                            requireCurrentHistory(leasedHistory, diskEvidence, journal)
                        }.exceptionOrNull()?.let { validationFailure ->
                            if (validationFailure !== failure) failure.addSuppressed(validationFailure)
                        }
                        throw failure
                    }
                }
                val result = when (stage) {
                    PreparedIsolationRunRootBorrowStage.BEFORE_LAUNCH ->
                        lease.withCurrentOperationRunRootBeforeLaunch(runRoot, invoke)

                    PreparedIsolationRunRootBorrowStage.SCOPE_ATTACHMENT ->
                        lease.withCurrentOperationRunRootForScopeAttachment(runRoot, invoke)

                    PreparedIsolationRunRootBorrowStage.AFTER_SCOPE_ATTACHMENT ->
                        lease.withCurrentOperationRunRootAfterScopeAttachment(runRoot, invoke)
                }
                result.also { requireCurrentAfterBorrow(stage) }
            } catch (failure: Throwable) {
                runCatching { requireCurrentAfterBorrow(stage) }.exceptionOrNull()?.let { validationFailure ->
                    if (validationFailure !== failure) failure.addSuppressed(validationFailure)
                }
                throw failure
            }
        } finally {
            runRootBorrowActive = false
        }
    }

    private fun requireCurrentForBorrow(stage: PreparedIsolationRunRootBorrowStage) {
        when (stage) {
            PreparedIsolationRunRootBorrowStage.BEFORE_LAUNCH,
            PreparedIsolationRunRootBorrowStage.SCOPE_ATTACHMENT,
            -> requireCurrentBeforeLaunch()

            PreparedIsolationRunRootBorrowStage.AFTER_SCOPE_ATTACHMENT ->
                requireCurrentAfterScopeAttachment()
        }
    }

    private fun requireCurrentAfterBorrow(stage: PreparedIsolationRunRootBorrowStage) {
        if (
            stage == PreparedIsolationRunRootBorrowStage.AFTER_SCOPE_ATTACHMENT ||
            scopeAttachmentAttempted
        ) {
            requireCurrentAfterScopeAttachment()
        } else {
            requireCurrentBeforeLaunch()
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        if (runRootBorrowActive) {
            coordinationFail("function-observation prepared isolation cannot close while its root is borrowed")
        }
        if (scopeAttachmentAttempted && !launchBoundaryAbsenceAccepted) {
            coordinationFail(
                "function-observation prepared isolation cannot close before proved launch-boundary absence",
            )
        }
        val validationFailure = runCatching {
            requireCurrentPreparedRun(
                leasedHistory,
                diskEvidence,
                runRoot,
                journal,
                lease,
                if (scopeAttachmentAttempted) {
                    FullTreeDiskScratchStage.AFTER_CGROUP_ABSENCE
                } else {
                    FullTreeDiskScratchStage.BEFORE_LAUNCH
                },
            )
        }.exceptionOrNull()
        closed = true
        val closeFailure = closeOperationResources(lease, journal)
        if (validationFailure != null) {
            if (closeFailure != null && closeFailure !== validationFailure) {
                validationFailure.addSuppressed(closeFailure)
            }
            throw validationFailure
        }
        closeFailure?.let { throw it }
    }

    companion object {
        internal fun create(
            leasedHistory: FullTreeFunctionObservationOperationHistory,
            diskEvidence: FullTreeDiskScratchEvidence,
            runRoot: FullTreeDiskScratchRunRoot,
            journal: FullTreeFunctionObservationOperationJournal,
            lease: FullTreeDiskScratchLease,
            constructionPermit: Any,
        ): FullTreeFunctionObservationPreparedIsolationAuthority {
            check(constructionPermit === PREPARED_ISOLATION_AUTHORITY_CONSTRUCTION_PERMIT) {
                "prepared-isolation authorities can only be issued by a prepared run"
            }
            return FullTreeFunctionObservationPreparedIsolationAuthority(
                leasedHistory,
                diskEvidence,
                runRoot,
                journal,
                lease,
            )
        }
    }
}

/**
 * Lock-retaining UNIT_ATTACHED authority for one worker still blocked before START. The attached
 * receipt is historical evidence only; the outer isolation owner must independently match its
 * live pidfds, InvocationID, cgroup descriptor, BOOT layout, inputs, and runtime on every use.
 */
internal class FullTreeFunctionObservationUnitAttachedIsolationAuthority private constructor(
    val attachedHistory: FullTreeFunctionObservationOperationHistory,
    val diskEvidence: FullTreeDiskScratchEvidence,
    val unitAttachmentReceipt: FullTreeFunctionObservationUnitAttachmentReceipt,
    private val runRoot: FullTreeDiskScratchRunRoot,
    private val journal: FullTreeFunctionObservationOperationJournal,
    private val lease: FullTreeDiskScratchLease,
) : AutoCloseable {
    private var closed = false
    private var runRootBorrowActive = false
    private var launchBoundaryAbsenceAccepted = false

    init {
        requireExactlyAttachedHistory(attachedHistory, diskEvidence, unitAttachmentReceipt)
        requireCurrentPreparedRun(
            attachedHistory,
            diskEvidence,
            runRoot,
            journal,
            lease,
            FullTreeDiskScratchStage.AFTER_SCOPE_ATTACHMENT,
        )
    }

    @Synchronized
    fun requireCurrentAtBoot() {
        check(!closed) { "function-observation attached isolation is closed" }
        if (launchBoundaryAbsenceAccepted) {
            coordinationFail("function-observation attached launch boundary is already absent")
        }
        requireCurrentPreparedRun(
            attachedHistory,
            diskEvidence,
            runRoot,
            journal,
            lease,
            FullTreeDiskScratchStage.AFTER_SCOPE_ATTACHMENT,
        )
    }

    @Synchronized
    fun <T> withCurrentRunRootAtBoot(
        action: (FullTreeDiskScratchBorrowedRunRoot) -> T,
    ): T {
        check(!closed) { "function-observation attached isolation is closed" }
        if (runRootBorrowActive) {
            coordinationFail("function-observation attached run root is already borrowed")
        }
        runRootBorrowActive = true
        try {
            requireCurrentAtBoot()
            return try {
                lease.withCurrentOperationRunRootAfterScopeAttachment(runRoot) { borrowed ->
                    requireCurrentHistory(attachedHistory, diskEvidence, journal)
                    try {
                        action(borrowed).also {
                            requireCurrentHistory(attachedHistory, diskEvidence, journal)
                        }
                    } catch (failure: Throwable) {
                        runCatching {
                            requireCurrentHistory(attachedHistory, diskEvidence, journal)
                        }.exceptionOrNull()?.let { validationFailure ->
                            if (validationFailure !== failure) failure.addSuppressed(validationFailure)
                        }
                        throw failure
                    }
                }.also { requireCurrentAtBoot() }
            } catch (failure: Throwable) {
                runCatching {
                    requireCurrentAtBoot()
                }.exceptionOrNull()?.let { validationFailure ->
                    if (validationFailure !== failure) failure.addSuppressed(validationFailure)
                }
                throw failure
            }
        } finally {
            runRootBorrowActive = false
        }
    }

    /** Caller-owned live cleanup must prove cgroup absence before this disk-stage transition. */
    @Synchronized
    fun requireCurrentAfterCgroupAbsence() {
        check(!closed) { "function-observation attached isolation is closed" }
        if (runRootBorrowActive) {
            coordinationFail("function-observation attached run root is borrowed")
        }
        requireCurrentPreparedRun(
            attachedHistory,
            diskEvidence,
            runRoot,
            journal,
            lease,
            FullTreeDiskScratchStage.AFTER_CGROUP_ABSENCE,
        )
        launchBoundaryAbsenceAccepted = true
    }

    /**
     * Terminal path after the caller has independently proved live cgroup absence. Validation may
     * poison the journal, so this method always releases the disk and journal locks before
     * propagating that validation failure.
     */
    @Synchronized
    internal fun closeAfterProvedCgroupAbsence() {
        check(!closed) { "function-observation attached isolation is closed" }
        if (runRootBorrowActive) {
            coordinationFail("function-observation attached isolation cannot close while its root is borrowed")
        }
        val validationFailure = runCatching {
            requireCurrentPreparedRun(
                attachedHistory,
                diskEvidence,
                runRoot,
                journal,
                lease,
                FullTreeDiskScratchStage.AFTER_CGROUP_ABSENCE,
            )
        }.exceptionOrNull()
        launchBoundaryAbsenceAccepted = true
        closed = true
        val closeFailure = closeOperationResources(lease, journal)
        if (validationFailure != null) {
            if (closeFailure != null && closeFailure !== validationFailure) {
                validationFailure.addSuppressed(closeFailure)
            }
            throw validationFailure
        }
        closeFailure?.let { throw it }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        if (runRootBorrowActive) {
            coordinationFail("function-observation attached isolation cannot close while its root is borrowed")
        }
        if (!launchBoundaryAbsenceAccepted) {
            coordinationFail("function-observation attached isolation cannot close before cgroup absence")
        }
        closeAfterProvedCgroupAbsence()
    }

    companion object {
        internal fun create(
            attachedHistory: FullTreeFunctionObservationOperationHistory,
            diskEvidence: FullTreeDiskScratchEvidence,
            unitAttachmentReceipt: FullTreeFunctionObservationUnitAttachmentReceipt,
            runRoot: FullTreeDiskScratchRunRoot,
            journal: FullTreeFunctionObservationOperationJournal,
            lease: FullTreeDiskScratchLease,
            constructionPermit: Any,
        ): FullTreeFunctionObservationUnitAttachedIsolationAuthority {
            check(constructionPermit === ATTACHED_ISOLATION_AUTHORITY_CONSTRUCTION_PERMIT) {
                "attached-isolation authorities can only follow durable live attachment"
            }
            return FullTreeFunctionObservationUnitAttachedIsolationAuthority(
                attachedHistory,
                diskEvidence,
                unitAttachmentReceipt,
                runRoot,
                journal,
                lease,
            )
        }
    }
}

private object COLD_LEASED_OPERATION_CONSTRUCTION_PERMIT

internal enum class FullTreeFunctionObservationColdTransferFaultPoint {
    BEFORE_FINAL_SYSTEMD_SWEEP,
    AFTER_FINAL_SYSTEMD_SWEEP,
}

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

    /**
     * Transfers the same journal and disk locks into an observation-only exact-unit-absent state.
     *
     * The ordering is H/D/H/D, systemd, H/D/H/D, systemd. The unit name is derived only from the
     * durable binding, and the complete isolation-configuration digest must match that binding.
     * Any failure leaves this source live. Success appends nothing and grants no launch, recovery,
     * adoption, publication, cleanup, or release authority.
     */
    @Synchronized
    fun transferToDeterministicUnitAbsent(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
    ): FullTreeFunctionObservationColdLeasedUnitAbsent =
        transferToDeterministicUnitAbsent(configuration, null)

    /** Internally interpreted fail-only seam; it cannot issue or retain an authority. */
    @Synchronized
    internal fun transferToDeterministicUnitAbsentForTesting(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        faultPoint: FullTreeFunctionObservationColdTransferFaultPoint,
    ): Nothing {
        transferToDeterministicUnitAbsent(configuration, faultPoint)
        error("cold LEASED fail-only transfer issued an authority")
    }

    private fun transferToDeterministicUnitAbsent(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        faultPoint: FullTreeFunctionObservationColdTransferFaultPoint?,
    ): FullTreeFunctionObservationColdLeasedUnitAbsent {
        check(!closed) { "function-observation cold LEASED operation is closed" }
        val binding = leasedHistory.binding
        if (configuration.canonicalSha256 != binding.isolationConfigurationSha256) {
            coordinationFail("cold LEASED systemd configuration differs from its operation binding")
        }
        requireCurrentColdLeasedOperation(
            expectedHistory = leasedHistory,
            expectedEvidence = diskEvidence,
            expectedSnapshot = initialSnapshot,
            journal = journal,
            coldLease = coldLease,
        )
        val observer = FullTreeFunctionObservationColdUnitAbsenceObserver.open(binding, configuration)
        observer.requireAbsent()
        requireCurrentColdLeasedOperation(
            expectedHistory = leasedHistory,
            expectedEvidence = diskEvidence,
            expectedSnapshot = initialSnapshot,
            journal = journal,
            coldLease = coldLease,
        )
        injectColdTransferFaultIfReached(
            faultPoint,
            FullTreeFunctionObservationColdTransferFaultPoint.BEFORE_FINAL_SYSTEMD_SWEEP,
        )
        observer.requireAbsent()
        injectColdTransferFaultIfReached(
            faultPoint,
            FullTreeFunctionObservationColdTransferFaultPoint.AFTER_FINAL_SYSTEMD_SWEEP,
        )
        if (faultPoint != null) coordinationFail("cold LEASED fail-only transfer missed its fault point")
        val transferred = FullTreeFunctionObservationColdLeasedUnitAbsent.create(
            leasedHistory = leasedHistory,
            diskEvidence = diskEvidence,
            initialSnapshot = initialSnapshot,
            journal = journal,
            coldLease = coldLease,
            observer = observer,
            constructionPermit = COLD_LEASED_UNIT_ABSENT_CONSTRUCTION_PERMIT,
        )
        closed = true
        return transferred
    }

    private fun injectColdTransferFaultIfReached(
        requested: FullTreeFunctionObservationColdTransferFaultPoint?,
        reached: FullTreeFunctionObservationColdTransferFaultPoint,
    ) {
        when (requested) {
            null -> Unit
            FullTreeFunctionObservationColdTransferFaultPoint.BEFORE_FINAL_SYSTEMD_SWEEP -> {
                if (reached == requested) coordinationFail("injected failure before the final cold systemd sweep")
            }

            FullTreeFunctionObservationColdTransferFaultPoint.AFTER_FINAL_SYSTEMD_SWEEP -> {
                if (reached == requested) coordinationFail("injected failure after the final cold systemd sweep")
            }
        }
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

private object COLD_LEASED_UNIT_ABSENT_CONSTRUCTION_PERMIT

/**
 * Lock-retaining, revalidatable observation that the deterministic unit name was absent.
 *
 * This state is a bounded point-in-time observation, not a reservation or same-UID exclusion.
 * A later unit remains foreign. Closing releases only the cold disk lease and journal descriptors;
 * it never queries, stops, kills, cancels, resets, adopts, or otherwise touches systemd state.
 */
internal class FullTreeFunctionObservationColdLeasedUnitAbsent private constructor(
    val leasedHistory: FullTreeFunctionObservationOperationHistory,
    val diskEvidence: FullTreeDiskScratchEvidence,
    val observedPopulation: FullTreeDiskScratchColdPopulation,
    val unitName: String,
    private val initialSnapshot: FullTreeDiskScratchColdSnapshot,
    private val journal: FullTreeFunctionObservationOperationJournal,
    private val coldLease: FullTreeDiskScratchColdLease,
    private val observer: FullTreeFunctionObservationColdUnitAbsenceObserver,
) : AutoCloseable {
    private var closed = false

    init {
        val acceptedEvidence = requireExactlyLeasedHistory(leasedHistory)
        if (
            acceptedEvidence !== diskEvidence ||
            observedPopulation != initialSnapshot.population ||
            unitName != leasedHistory.binding.unitName ||
            observer.unitName != unitName ||
            observer.isolationConfigurationSha256 != leasedHistory.binding.isolationConfigurationSha256
        ) coordinationFail("cold deterministic-unit absence owner retained different authority")
    }

    /** Repeats H/D/H/D -> systemd -> H/D/H/D -> systemd without mutation. */
    @Synchronized
    fun requireCurrentUnitAbsentReadOnly() {
        check(!closed) { "function-observation cold unit-absent operation is closed" }
        requireCurrentColdLeasedOperation(
            expectedHistory = leasedHistory,
            expectedEvidence = diskEvidence,
            expectedSnapshot = initialSnapshot,
            journal = journal,
            coldLease = coldLease,
        )
        observer.requireAbsent()
        requireCurrentColdLeasedOperation(
            expectedHistory = leasedHistory,
            expectedEvidence = diskEvidence,
            expectedSnapshot = initialSnapshot,
            journal = journal,
            coldLease = coldLease,
        )
        observer.requireAbsent()
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
            observer: FullTreeFunctionObservationColdUnitAbsenceObserver,
            constructionPermit: Any,
        ): FullTreeFunctionObservationColdLeasedUnitAbsent {
            check(constructionPermit === COLD_LEASED_UNIT_ABSENT_CONSTRUCTION_PERMIT) {
                "cold unit-absent capabilities can only be issued by a cold LEASED transfer"
            }
            return FullTreeFunctionObservationColdLeasedUnitAbsent(
                leasedHistory,
                diskEvidence,
                initialSnapshot.population,
                leasedHistory.binding.unitName,
                initialSnapshot,
                journal,
                coldLease,
                observer,
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
    if (history.unitAttachmentReceipt != null) {
        coordinationFail("cold LEASED composition rejects a staged unit-attachment receipt")
    }
    return history.requireDiskEvidenceIntroducedAt(
        FullTreeFunctionObservationOperationPhase.LEASED,
    ).also { evidence ->
        if (history.diskEvidence !== evidence) {
            coordinationFail("cold LEASED history did not retain its parsed disk evidence")
        }
    }
}

private fun requireExactlyAttachedHistory(
    history: FullTreeFunctionObservationOperationHistory,
    expectedEvidence: FullTreeDiskScratchEvidence,
    expectedReceipt: FullTreeFunctionObservationUnitAttachmentReceipt,
) {
    if (
        history.transitions.map { it.phase } != listOf(
            FullTreeFunctionObservationOperationPhase.PREPARING,
            FullTreeFunctionObservationOperationPhase.LEASED,
            FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
        )
    ) coordinationFail("attached composition requires one fully published UNIT_ATTACHED operation")
    val actualEvidence = history.requireDiskEvidenceIntroducedAt(
        FullTreeFunctionObservationOperationPhase.LEASED,
    )
    val actualReceipt = history.requireUnitAttachmentReceiptIntroducedAt(
        FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
    )
    requireExactEvidence(expectedEvidence, actualEvidence)
    requireExactReceipt(expectedReceipt, actualReceipt)
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

private fun requireCurrentPreparedRun(
    expectedHistory: FullTreeFunctionObservationOperationHistory,
    expectedEvidence: FullTreeDiskScratchEvidence,
    runRoot: FullTreeDiskScratchRunRoot,
    journal: FullTreeFunctionObservationOperationJournal,
    lease: FullTreeDiskScratchLease,
    stage: FullTreeDiskScratchStage = FullTreeDiskScratchStage.BEFORE_LAUNCH,
) {
    requireCurrentHistory(expectedHistory, expectedEvidence, journal)
    lease.requireCurrentOperationRunRoot(runRoot, stage)
    requireCurrentHistory(expectedHistory, expectedEvidence, journal)
    lease.requireCurrentOperationRunRoot(runRoot, stage)
}

private fun closeOperationResources(
    lease: FullTreeDiskScratchLease,
    journal: FullTreeFunctionObservationOperationJournal,
): Throwable? {
    var failure: Throwable? = null
    runCatching { lease.abandonForRecovery() }.exceptionOrNull()?.let { failure = it }
    runCatching { journal.close() }.exceptionOrNull()?.let { closeFailure ->
        if (failure == null) failure = closeFailure else if (closeFailure !== failure) {
            failure.addSuppressed(closeFailure)
        }
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
        if (failure == null) failure = closeFailure else if (closeFailure !== failure) {
            failure.addSuppressed(closeFailure)
        }
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

private fun requireExactReceipt(
    expected: FullTreeFunctionObservationUnitAttachmentReceipt,
    actual: FullTreeFunctionObservationUnitAttachmentReceipt,
) {
    if (!MessageDigest.isEqual(expected.canonicalBytes(), actual.canonicalBytes())) {
        coordinationFail("function-observation operation has a different exact attachment receipt")
    }
}

private fun requireExactHistory(
    expected: FullTreeFunctionObservationOperationHistory,
    actual: FullTreeFunctionObservationOperationHistory,
) {
    val expectedReceipt = expected.unitAttachmentReceipt
    val actualReceipt = actual.unitAttachmentReceipt
    if (
        !MessageDigest.isEqual(expected.binding.canonicalBytes(), actual.binding.canonicalBytes()) ||
        expected.transitions.size != actual.transitions.size ||
        expected.transitions.zip(actual.transitions).any { (left, right) ->
            !MessageDigest.isEqual(left.canonicalBytes(), right.canonicalBytes())
        } ||
        (expectedReceipt == null) != (actualReceipt == null) ||
        expectedReceipt != null && actualReceipt != null &&
        !MessageDigest.isEqual(expectedReceipt.canonicalBytes(), actualReceipt.canonicalBytes())
    ) coordinationFail("function-observation operation journal changed")
}

private fun coordinationFail(message: String): Nothing =
    throw FullTreeFunctionObservationOperationCoordinationException(message)
