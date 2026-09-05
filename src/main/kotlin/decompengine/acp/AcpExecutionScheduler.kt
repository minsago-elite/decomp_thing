package decompengine.acp

import decompengine.agent.AgentCancellation
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** Process-wide admission limits; each admitted ACP invocation owns at most one outer agent/session/prompt. */
internal data class AcpSchedulingLimits(
    val maximumActive: Int = 4,
    val maximumActivePerWorkspace: Int = 1,
    val maximumQueued: Int = 64,
    val maximumQueuedPerWorkspace: Int = 8,
    val maximumQueueWait: Duration = Duration.ofSeconds(30),
) {
    init {
        require(maximumActive in 1..64)
        require(maximumActivePerWorkspace in 1..maximumActive)
        require(maximumQueued in 1..4096)
        require(maximumQueuedPerWorkspace in 1..maximumQueued)
        require(!maximumQueueWait.isNegative && !maximumQueueWait.isZero)
        require(maximumQueueWait <= Duration.ofMinutes(5))
    }
}

internal data class AcpSchedulingSnapshot(
    val active: Int,
    val queued: Int,
    val activeWorkspaceGroups: Int,
    val quarantined: Int,
)

/**
 * Bounded FIFO admission among eligible workspace groups. A busy group's queued calls cannot
 * block another group from using spare global capacity. Waiters run on caller threads, so there
 * is no executor or hidden work queue. Cancellation and the original request deadline are polled
 * while queued; no workspace snapshot, agent process, or permission authority exists yet.
 *
 * The group is the immutable primary workspace path from the provider-neutral request, not a
 * caller-supplied priority or agent name. Captured repair's shared synthetic workspace therefore
 * conservatively serializes repairs across projects. This is workspace admission, not a claim
 * that independent application processes share one scheduler or that project IDs are modeled.
 */
internal class AcpExecutionScheduler(
    private val limits: AcpSchedulingLimits = AcpSchedulingLimits(),
) {
    private class Waiter(val group: String)

    private val lock = ReentrantLock(true)
    private val changed = lock.newCondition()
    private val queue = ArrayList<Waiter>()
    private val activeByGroup = HashMap<String, Int>()
    private val quarantinedByGroup = HashMap<String, Int>()
    private var active = 0

    /** Returns null for cancellation before admission, preserving an interrupted caller's flag. */
    fun acquire(
        workspaceGroup: String,
        cancellation: AgentCancellation,
        requestExpired: () -> Boolean,
    ): Permit? {
        require(workspaceGroup.isNotEmpty())
        val queueStartedAt = System.nanoTime()
        val queueTimeoutNanos = limits.maximumQueueWait.toNanos()
        val waiter = Waiter(workspaceGroup)
        try {
            lock.lockInterruptibly()
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return null
        }
        try {
            if (cancellation.isCancellationRequested()) return null
            if (requestExpired()) throw schedulingFailure("requestDeadline", AgentFailureKind.TIMEOUT)
            if (quarantinedByGroup.containsKey(workspaceGroup) || quarantinedCount() == limits.maximumActive) {
                throw schedulingFailure("cleanupUnverified", AgentFailureKind.UNAVAILABLE, retryable = false)
            }
            // Queue bounds charge waiting work only. If every older waiter is blocked by its
            // workspace, immediate admission to spare capacity does not enlarge the queue.
            if (active < limits.maximumActive && eligible(workspaceGroup) && queue.none { eligible(it.group) }) {
                return admit(workspaceGroup)
            }
            if (queue.size >= limits.maximumQueued ||
                queue.count { it.group == workspaceGroup } >= limits.maximumQueuedPerWorkspace
            ) {
                throw schedulingFailure("queueCapacity", AgentFailureKind.RESOURCE_EXHAUSTED)
            }
            queue.add(waiter)
            while (true) {
                if (Thread.currentThread().isInterrupted || cancellation.isCancellationRequested()) return null
                if (requestExpired()) throw schedulingFailure("requestDeadline", AgentFailureKind.TIMEOUT)
                if (quarantinedByGroup.containsKey(workspaceGroup) || quarantinedCount() == limits.maximumActive) {
                    throw schedulingFailure("cleanupUnverified", AgentFailureKind.UNAVAILABLE, retryable = false)
                }
                val elapsed = (System.nanoTime() - queueStartedAt).coerceAtLeast(0)
                if (elapsed >= queueTimeoutNanos) throw schedulingFailure("queueDeadline", AgentFailureKind.TIMEOUT)
                if (active < limits.maximumActive && queue.firstOrNull { eligible(it.group) } === waiter) {
                    queue.remove(waiter)
                    return admit(workspaceGroup)
                }
                try {
                    changed.awaitNanos(minOf(POLL_NANOS, queueTimeoutNanos - elapsed))
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return null
                }
            }
        } finally {
            queue.remove(waiter)
            changed.signalAll()
            lock.unlock()
        }
    }

    fun snapshot(): AcpSchedulingSnapshot = lock.withLock {
        AcpSchedulingSnapshot(active, queue.size, activeByGroup.size, quarantinedCount())
    }

    private fun eligible(group: String): Boolean =
        !quarantinedByGroup.containsKey(group) &&
            activeByGroup.getOrDefault(group, 0) < limits.maximumActivePerWorkspace

    private fun quarantinedCount(): Int = quarantinedByGroup.values.sum()

    private fun admit(group: String): Permit {
        active += 1
        activeByGroup[group] = activeByGroup.getOrDefault(group, 0) + 1
        changed.signalAll()
        return Permit(this, group)
    }

    private fun finish(group: String, cleanupUnverified: Boolean) = lock.withLock {
        if (cleanupUnverified) {
            // A failed cleanup proof cannot create spare capacity for another agent. Keep the
            // slot and group reserved for the lifetime of this application process.
            quarantinedByGroup[group] = quarantinedByGroup.getOrDefault(group, 0) + 1
        } else {
            active -= 1
            val remaining = activeByGroup.getValue(group) - 1
            if (remaining == 0) activeByGroup.remove(group) else activeByGroup[group] = remaining
        }
        changed.signalAll()
    }

    class Permit internal constructor(
        private val scheduler: AcpExecutionScheduler,
        private val group: String,
    ) {
        private val finished = AtomicBoolean(false)

        fun finish(cleanupUnverified: Boolean = false) {
            if (finished.compareAndSet(false, true)) scheduler.finish(group, cleanupUnverified)
        }
    }

    private companion object {
        const val POLL_NANOS: Long = 25_000_000
    }
}

/** Shared by factory-created and directly constructed production harnesses, including doctor. */
internal val productionAcpExecutionScheduler = AcpExecutionScheduler()

private fun schedulingFailure(
    reason: String,
    kind: AgentFailureKind,
    retryable: Boolean = true,
): AgentExecutionException = AgentExecutionException(
    AgentFailure(
        kind,
        "ACP execution was not admitted before any agent process started",
        retryable = retryable,
        details = mapOf("phase" to "scheduler", "reason" to reason),
    ),
)
