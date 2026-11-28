package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.DescriptorBoundCommitFaultInjector
import decompengine.oracle.core.DescriptorBoundCommitGate
import decompengine.oracle.core.DescriptorBoundPreparedCommit
import decompengine.oracle.core.DescriptorBoundStateSnapshot
import decompengine.oracle.fulltree.ContainedCommandOperationDeadline
import java.nio.file.Path

/**
 * Single-commit admission under the operation deadline. The link may start only while at least
 * [commitReserveMillis] remain, and it counts only if the deadline is still current both when it
 * returns and after its durability sync. Abandonment from any earlier state means the result must
 * not remain published.
 */
internal class GccBundledDeadlineCommitGate(
    private val deadline: ContainedCommandOperationDeadline,
    private val commitReserveMillis: Long = COMMIT_RESERVE_MILLIS,
) : DescriptorBoundCommitGate {
    enum class State { STAGING, COMMITTING, COMMITTED, FINISHED, ABANDONED }

    var state = State.STAGING
        @Synchronized get
        private set
    var finished: DescriptorBoundPreparedCommit? = null
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

    /**
     * The owned step's last transition, after the commit's durability sync: it succeeds only while
     * the deadline is current, matching the owner's real-time wait. Afterwards only the caller may
     * revoke [commit].
     */
    @Synchronized
    fun finish(commit: DescriptorBoundPreparedCommit): Boolean {
        if (state != State.COMMITTED) return false
        if (runCatching { deadline.requireCurrent() }.isFailure) {
            state = State.ABANDONED
            return false
        }
        finished = commit
        state = State.FINISHED
        return true
    }

    /** Returns the state that was abandoned. */
    @Synchronized
    fun abandon(): State = state.also { state = State.ABANDONED }

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
 * Publishes one new result file so that a failed or expired operation reports no result.
 *
 * The caller completes every fallible verification first. Preparation and the gated link then
 * run as owned host work bounded by the operation deadline; the link is the last fallible step
 * apart from the directory sync it needs for durability. If that step fails, outlasts the owner's
 * wait or completes after expiry, the result is revoked: by the in-flight step when its syscall
 * returns, or by a bounded cleanup step when the owned step had already finished. A process that
 * exits while such a step is still blocked can leave an unaccepted result.json behind; consumers
 * must keep requiring a successful CLI exit before opening it.
 */
internal object GccBundledDeadlineBoundPublication {
    const val CLEANUP_ALLOWANCE_MILLIS = 5_000L

    /**
     * [parentPath] is the authenticated pathname of [parent]; the owned step requires it to reach
     * the committed inode after the durability sync, then runs [requireBindings] before [finish].
     */
    fun publish(
        work: GccBundledHostWorkTracker,
        parent: LinuxDescriptor,
        parentPath: Path,
        name: String,
        bytes: ByteArray,
        maximumBytes: Int,
        deadline: ContainedCommandOperationDeadline,
        faultInjector: DescriptorBoundCommitFaultInjector? = null,
        requireBindings: () -> Unit = {},
    ): DescriptorBoundStateSnapshot {
        val gate = GccBundledDeadlineCommitGate(deadline)
        val owned = LinuxFilesystemSyscalls.duplicate(parent)
        val commit = try {
            work.run("result publication", { deadline.remainingMillis(Long.MAX_VALUE) }, owned) {
                val prepared = DescriptorBoundAtomicStateFile.commitNoReplace(owned, parentPath, name, bytes, maximumBytes,
                    gate, faultInjector)
                try {
                    requireBindings()
                    check(gate.finish(prepared)) { "GCC result publication was abandoned or expired after its commit and is revoked" }
                } catch (failure: Throwable) {
                    runCatching { DescriptorBoundAtomicStateFile.revokeCommitted(owned, prepared, faultInjector) }
                        .exceptionOrNull()?.let(failure::addSuppressed)
                    prepared.close()
                    throw failure
                }
                prepared
            }
        } catch (failure: Throwable) {
            if (gate.abandon() == GccBundledDeadlineCommitGate.State.FINISHED) {
                revoke(work, parent, checkNotNull(gate.finished), failure)
            }
            throw failure
        }
        return commit.use { it.snapshot }
    }

    private fun revoke(work: GccBundledHostWorkTracker, parent: LinuxDescriptor, commit: DescriptorBoundPreparedCommit,
        failure: Throwable) {
        runCatching {
            val owned = try {
                LinuxFilesystemSyscalls.duplicate(parent)
            } catch (notDuplicated: Throwable) {
                commit.close()
                throw notDuplicated
            }
            work.run("result revocation", CLEANUP_ALLOWANCE_MILLIS, AutoCloseable { owned.close(); commit.close() }) {
                DescriptorBoundAtomicStateFile.revokeCommitted(owned, commit)
            }
        }.exceptionOrNull()?.let(failure::addSuppressed)
    }
}
