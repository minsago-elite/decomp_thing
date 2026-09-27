package decompengine.acp

import decompengine.agent.AgentCancellation
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import java.time.Duration
import java.util.concurrent.TimeUnit
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
        var queued = false
        try {
            // The queue position is reserved before the caller's first observer runs, so a
            // slow observer can neither be overtaken by later callers nor wait outside the
            // queue bounds.
            lock.withLock {
                if (quarantinedByGroup.containsKey(workspaceGroup) || quarantinedCount() == limits.maximumActive) {
                    throw schedulingFailure("cleanupUnverified", AgentFailureKind.UNAVAILABLE, retryable = false)
                }
                val immediatelyAdmissible = active < limits.maximumActive &&
                    eligible(workspaceGroup) &&
                    queue.none { eligible(it.group) }
                if (!immediatelyAdmissible) {
                    if (queue.size >= limits.maximumQueued ||
                        queue.count { it.group == workspaceGroup } >= limits.maximumQueuedPerWorkspace
                    ) {
                        throw schedulingFailure("queueCapacity", AgentFailureKind.RESOURCE_EXHAUSTED)
                    }
                    queue.add(waiter)
                    queued = true
                }
            }
            while (true) {
                // Caller-provided observers must never hold the process-wide scheduler lock.
                // A slow observer must not prevent permit release or observation of scheduler state.
                if (Thread.currentThread().isInterrupted || cancellation.isCancellationRequested()) return null
                if (requestExpired()) throw schedulingFailure("requestDeadline", AgentFailureKind.TIMEOUT)
                val elapsed = (System.nanoTime() - queueStartedAt).coerceAtLeast(0)
                if (elapsed >= queueTimeoutNanos) throw schedulingFailure("queueDeadline", AgentFailureKind.TIMEOUT)
                // The observations above are current. Admission may only commit while they
                // stay current: waiting for the lock invalidates them, so that pass gives up
                // its admission decisions and the state is re-observed before the next one.
                var current = true
                try {
                    if (!lock.tryLock()) {
                        if (!lock.tryLock(minOf(POLL_NANOS, queueTimeoutNanos - elapsed), TimeUnit.NANOSECONDS)) continue
                        current = false
                    }
                    try {
                        val remaining = queueTimeoutNanos - (System.nanoTime() - queueStartedAt).coerceAtLeast(0)
                        if (remaining <= 0) throw schedulingFailure("queueDeadline", AgentFailureKind.TIMEOUT)
                        if (quarantinedByGroup.containsKey(workspaceGroup) || quarantinedCount() == limits.maximumActive) {
                            throw schedulingFailure("cleanupUnverified", AgentFailureKind.UNAVAILABLE, retryable = false)
                        }
                        if (!queued) {
                            // Queue bounds charge waiting work only. A blocked workspace cannot
                            // prevent immediate admission to spare capacity for an eligible group.
                            if (active < limits.maximumActive && eligible(workspaceGroup) && queue.none { eligible(it.group) }) {
                                if (current) return admit(workspaceGroup)
                                continue
                            }
                            if (queue.size >= limits.maximumQueued ||
                                queue.count { it.group == workspaceGroup } >= limits.maximumQueuedPerWorkspace
                            ) {
                                throw schedulingFailure("queueCapacity", AgentFailureKind.RESOURCE_EXHAUSTED)
                            }
                            queue.add(waiter)
                            queued = true
                        }
                        if (active < limits.maximumActive && queue.firstOrNull { eligible(it.group) } === waiter) {
                            if (current) {
                                queue.remove(waiter)
                                return admit(workspaceGroup)
                            }
                            continue
                        }
                        changed.awaitNanos(minOf(POLL_NANOS, remaining))
                    } finally {
                        lock.unlock()
                    }
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return null
                }
            }
        } finally {
            if (queued) lock.withLock {
                queue.remove(waiter)
                changed.signalAll()
            }
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
