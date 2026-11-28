package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.DescriptorBoundCommitGate
import decompengine.oracle.core.DescriptorBoundStateFaultInjector
import decompengine.oracle.core.DescriptorBoundStateSnapshot
import decompengine.oracle.fulltree.ContainedCommandOperationDeadline

/**
 * Single-commit admission under the operation deadline. The rename may start only while at least
 * [commitReserveMillis] remain, and it counts only if the deadline is still current when it
 * returns. Success is reported only after [accept] also sees a current deadline. Abandonment from
 * any earlier state means the result must not remain published.
 */
internal class GccBundledDeadlineCommitGate(
    private val deadline: ContainedCommandOperationDeadline,
    private val commitReserveMillis: Long = COMMIT_RESERVE_MILLIS,
) : DescriptorBoundCommitGate {
    enum class State { STAGING, COMMITTING, COMMITTED, FINISHED, ACCEPTED, ABANDONED }

    var state = State.STAGING
        @Synchronized get
        private set
    var finishedIdentity: LinuxFileIdentity? = null
        @Synchronized get
        private set

    @Synchronized
    override fun requireStaging(stage: String) {
        check(state == State.STAGING) { "GCC result publication stopped $stage" }
        abandonOnFailure { deadline.requireCurrent() }
    }

    @Synchronized
    override fun beginCommit() {
        check(state == State.STAGING) { "GCC result publication cannot begin its commit" }
        abandonOnFailure {
            check(deadline.remainingMillis(Long.MAX_VALUE) >= commitReserveMillis) {
                "GCC result commit requires $commitReserveMillis ms of its operation deadline"
            }
        }
        state = State.COMMITTING
    }

    @Synchronized
    override fun completeCommit(): Boolean {
        if (state != State.COMMITTING) return false
        if (runCatching { deadline.requireCurrent() }.isFailure) {
            state = State.ABANDONED
            return false
        }
        state = State.COMMITTED
        return true
    }

    @Synchronized
    fun finish(identity: LinuxFileIdentity): Boolean {
        if (state != State.COMMITTED) return false
        finishedIdentity = identity
        state = State.FINISHED
        return true
    }

    @Synchronized
    fun accept() {
        check(state == State.FINISHED) { "GCC result publication was abandoned before acceptance" }
        abandonOnFailure { deadline.requireCurrent() }
        state = State.ACCEPTED
    }

    /** Returns the state that was abandoned; after [accept] nothing changes. */
    @Synchronized
    fun abandon(): State = state.also { if (it != State.ACCEPTED) state = State.ABANDONED }

    private inline fun abandonOnFailure(action: () -> Unit) {
        try {
            action()
        } catch (failure: Throwable) {
            state = State.ABANDONED
            throw failure
        }
    }

    companion object {
        const val COMMIT_RESERVE_MILLIS = 1_000L
    }
}

/**
 * Publishes one new result file so that an expired or failed operation leaves no result behind.
 *
 * Staging and the gated rename run as owned host work bounded by the operation deadline. After the
 * step returns, [afterCommit] runs the caller's post-publication checks and the gate must still
 * accept. Every failure revokes the committed name: the in-flight step revokes it if the caller
 * stopped waiting first, otherwise a bounded cleanup step does. A cleanup step that is itself
 * blocked remains owned, and the operation must not release ownership while it is in flight.
 */
internal object GccBundledDeadlineBoundPublication {
    const val CLEANUP_ALLOWANCE_MILLIS = 5_000L

    fun publish(
        work: GccBundledHostWorkTracker,
        parent: LinuxDescriptor,
        name: String,
        bytes: ByteArray,
        maximumBytes: Int,
        deadline: ContainedCommandOperationDeadline,
        faultInjector: DescriptorBoundStateFaultInjector? = null,
        afterCommit: () -> Unit,
    ): DescriptorBoundStateSnapshot {
        val gate = GccBundledDeadlineCommitGate(deadline)
        val published = try {
            val allowance = deadline.remainingMillis(Long.MAX_VALUE)
            val owned = duplicateOwnedDirectory(parent)
            work.run("result publication", allowance, owned) {
                val snapshot = DescriptorBoundAtomicStateFile.commitNoReplace(owned, name, bytes, maximumBytes, gate, faultInjector)
                if (!gate.finish(snapshot.identity)) {
                    DescriptorBoundAtomicStateFile.revokeCommitted(owned, name, snapshot.identity)
                    error("GCC result publication was abandoned after its commit and was revoked")
                }
                snapshot
            }
        } catch (failure: Throwable) {
            if (gate.abandon() == GccBundledDeadlineCommitGate.State.FINISHED) {
                revoke(work, parent, name, checkNotNull(gate.finishedIdentity), failure)
            }
            throw failure
        }
        try {
            afterCommit()
            gate.accept()
            return published
        } catch (failure: Throwable) {
            gate.abandon()
            revoke(work, parent, name, published.identity, failure)
            throw failure
        }
    }

    private fun revoke(work: GccBundledHostWorkTracker, parent: LinuxDescriptor, name: String,
        identity: LinuxFileIdentity, failure: Throwable) {
        runCatching {
            val owned = duplicateOwnedDirectory(parent)
            work.run("result revocation", CLEANUP_ALLOWANCE_MILLIS, owned) {
                DescriptorBoundAtomicStateFile.revokeCommitted(owned, name, identity)
            }
        }.exceptionOrNull()?.let(failure::addSuppressed)
    }
}

/** A separately owned descriptor for the same pinned directory, handed to exactly one step. */
internal fun duplicateOwnedDirectory(directory: LinuxDescriptor): LinuxDescriptor {
    val duplicate = directory.whileOpen { fd -> LinuxFilesystemSyscalls.openDirectoryAt(fd, ".") }
    val expected = directory.identity
    if (duplicate.identity.key != expected.key || duplicate.identity.mountId != expected.mountId ||
        !duplicate.identity.isDirectory || duplicate.identity.isSymbolicLink) {
        duplicate.close()
        throw IllegalStateException("GCC owned directory descriptor differs from its pinned directory")
    }
    return duplicate
}
