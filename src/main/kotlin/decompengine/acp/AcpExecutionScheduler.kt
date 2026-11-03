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
    private val lock: ReentrantLock = ReentrantLock(true),
    private val nanoTime: () -> Long = System::nanoTime,
) {
    private class Waiter(val group: String)
    private enum class ReservationState { RESERVED, GRANTED, INVALIDATED }
    private class Reservation(val group: String) {
        val state = java.util.concurrent.atomic.AtomicReference(ReservationState.RESERVED)
    }

    init { require(lock.isFair) { "ACP admission requires a fair scheduler lock" } }

    private val changed = lock.newCondition()
    // Includes active/quarantined slots, queued callers and initial mutex contenders.
    private val ingress = java.util.concurrent.Semaphore(limits.maximumActive + limits.maximumQueued, true)
    private val queue = ArrayList<Waiter>()
    private val reservations = ArrayList<Reservation>()
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
        val queueStartedAt = nanoTime()
        val queueTimeoutNanos = limits.maximumQueueWait.toNanos()
        fun remaining(): Long = queueTimeoutNanos - (nanoTime() - queueStartedAt).coerceAtLeast(0)
        fun observe(): Boolean {
            if (Thread.currentThread().isInterrupted || cancellation.isCancellationRequested()) return false
            if (requestExpired()) throw schedulingFailure("requestDeadline", AgentFailureKind.TIMEOUT)
            if (remaining() <= 0) throw schedulingFailure("queueDeadline", AgentFailureKind.TIMEOUT)
            return true
        }
        val entered = try {
            ingress.tryAcquire(0L, TimeUnit.NANOSECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return null
        }
        if (!entered) {
            // This caller cannot enter or wait. Observe cancellation/deadlines before refusal.
            if (!observe()) return null
            throw schedulingFailure("queueCapacity", AgentFailureKind.RESOURCE_EXHAUSTED)
        }

        val waiter = Waiter(workspaceGroup)
        var ownsIngress = true
        var queued = false
        var reservation: Reservation? = null
        var granted = false
        var refusal: AgentExecutionException? = null
        try {
            if (!enterBeforeDeadline(queueStartedAt, queueTimeoutNanos, ::observe)) return null
            try {
                when {
                    quarantinedByGroup.containsKey(workspaceGroup) || quarantinedCount() == limits.maximumActive ->
                        refusal = schedulingFailure("cleanupUnverified", AgentFailureKind.UNAVAILABLE, retryable = false)
                    active < limits.maximumActive && eligible(workspaceGroup) && queue.none { eligible(it.group) } ->
                        reservation = reserve(workspaceGroup)
                    queue.size >= limits.maximumQueued ||
                        queue.count { it.group == workspaceGroup } >= limits.maximumQueuedPerWorkspace ->
                        refusal = schedulingFailure("queueCapacity", AgentFailureKind.RESOURCE_EXHAUSTED)
                    else -> {
                        queue.add(waiter)
                        queued = true
                    }
                }
            } finally {
                lock.unlock()
            }
            if (refusal != null) {
                // No work was reserved: a rejected observer owns neither a queue nor ingress slot.
                ingress.release()
                ownsIngress = false
            }
            while (true) {
                // Every accepted observer has a bounded FIFO place or a reserved active slot.
                // Observers run without either scheduler or executor locks.
                if (!observe()) return null
                refusal?.let { throw it }
                val held = reservation
                if (held != null) {
                    val permit = Permit { cleanupUnverified -> finish(held, cleanupUnverified) }
                    // Quarantine invalidates pending same-group reservations before publication.
                    // The CAS orders grant against that invalidation without another mutex wait.
                    if (!held.state.compareAndSet(ReservationState.RESERVED, ReservationState.GRANTED)) {
                        throw schedulingFailure("cleanupUnverified", AgentFailureKind.UNAVAILABLE, retryable = false)
                    }
                    granted = true
                    ownsIngress = false // The permit retains this slot through verified cleanup.
                    return permit
                }
                if (!enterBeforeDeadline(queueStartedAt, queueTimeoutNanos, ::observe)) return null
                try {
                    val left = remaining()
                    if (left <= 0) continue
                    if (quarantinedByGroup.containsKey(workspaceGroup) || quarantinedCount() == limits.maximumActive) {
                        refusal = schedulingFailure("cleanupUnverified", AgentFailureKind.UNAVAILABLE, retryable = false)
                    } else if (active < limits.maximumActive && queue.firstOrNull { eligible(it.group) } === waiter) {
                        queue.remove(waiter)
                        queued = false
                        reservation = reserve(workspaceGroup)
                    } else {
                        try {
                            changed.awaitNanos(minOf(POLL_NANOS, left))
                        } catch (_: InterruptedException) {
                            Thread.currentThread().interrupt()
                            return null
                        }
                    }
                } finally {
                    lock.unlock()
                }
                // A fair-lock wait reserves capacity, then refreshes observations outside the
                // mutex. It never discards that place just because another caller was queued.
            }
        } finally {
            try {
                if (!granted && (queued || reservation != null)) lock.withLock {
                    if (queued) queue.remove(waiter)
                    reservation?.let { releaseReservation(it) }
                    changed.signalAll()
                }
            } finally {
                if (ownsIngress) ingress.release()
            }
        }
    }

    private fun enterBeforeDeadline(startedAt: Long, timeoutNanos: Long, observe: () -> Boolean): Boolean {
        while (true) {
            if (Thread.currentThread().isInterrupted) return false
            val remaining = timeoutNanos - (nanoTime() - startedAt).coerceAtLeast(0)
            if (remaining <= 0) {
                if (!observe()) return false
                throw schedulingFailure("queueDeadline", AgentFailureKind.TIMEOUT)
            }
            try {
                if (lock.tryLock(minOf(POLL_NANOS, remaining), TimeUnit.NANOSECONDS)) return true
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return false
            }
            // A missed timed slice owns no mutex; explicit cancellation and the request
            // deadline must remain observable before another fair-lock wait starts.
            if (!observe()) return false
        }
    }

    fun snapshot(): AcpSchedulingSnapshot = lock.withLock {
        AcpSchedulingSnapshot(active, queue.size, activeByGroup.size, quarantinedCount())
    }

    private fun eligible(group: String): Boolean =
        !quarantinedByGroup.containsKey(group) &&
            activeByGroup.getOrDefault(group, 0) < limits.maximumActivePerWorkspace

    private fun quarantinedCount(): Int = quarantinedByGroup.values.sum()

    private fun reserve(group: String): Reservation {
        val reservation = Reservation(group)
        active += 1
        activeByGroup[group] = activeByGroup.getOrDefault(group, 0) + 1
        reservations.add(reservation)
        changed.signalAll()
        return reservation
    }

    private fun releaseReservation(reservation: Reservation) {
        check(reservations.remove(reservation))
        active -= 1
        val group = reservation.group
        val remaining = activeByGroup.getValue(group) - 1
        if (remaining == 0) activeByGroup.remove(group) else activeByGroup[group] = remaining
    }

    private fun finish(reservation: Reservation, cleanupUnverified: Boolean) = lock.withLock {
        if (cleanupUnverified) {
            // Invalidate before publishing quarantine: a racing CAS either grants before
            // quarantine, or observes invalidation and releases its unused reservation.
            reservations.filter { it.group == reservation.group }.forEach {
                it.state.compareAndSet(ReservationState.RESERVED, ReservationState.INVALIDATED)
            }
            quarantinedByGroup[reservation.group] = quarantinedByGroup.getOrDefault(reservation.group, 0) + 1
        } else {
            releaseReservation(reservation)
            ingress.release()
        }
        changed.signalAll()
    }

    class Permit internal constructor(private val finishReservation: (Boolean) -> Unit) {
        private val finished = AtomicBoolean(false)

        fun finish(cleanupUnverified: Boolean = false) {
            if (finished.compareAndSet(false, true)) finishReservation(cleanupUnverified)
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
    retryable: Boolean = reason == "queueDeadline" || reason == "queueCapacity",
): AgentExecutionException = AgentExecutionException(
    AgentFailure(
        kind,
        "ACP execution was not admitted before any agent process started",
        retryable = retryable,
        details = mapOf("phase" to "scheduler", "reason" to reason),
    ),
)
