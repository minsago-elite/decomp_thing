package decompengine.chatgpt

import java.time.Duration
import java.util.EnumMap
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

internal abstract class ChatGptAuthParent : ChatGptAuthSafeObject() {
    /** Trusted bounded host callback; zero means expired or cancelled. */
    abstract fun remainingNanos(): Long
}

internal abstract class ChatGptAuthCancellation : ChatGptAuthSafeObject() {
    abstract fun isCancelled(): Boolean
}

internal enum class ChatGptAuthFailure {
    CANCELLED, TIMEOUT, DEPENDENCY_FAILED, RESOURCE_LIMIT, CALLBACK_INPUT_LIMIT,
    LISTENER_FAILED, ATTEMPT_USED, INVALID_OWNER, UNSETTLED,
}

internal class ChatGptAuthException(val failure: ChatGptAuthFailure) :
    Exception(failure.name, null, false, false) {
    override fun toString(): String = "ChatGptAuthException(${failure.name})"
}

/** Register BEFORE acquisition/submission. A true return acknowledges physical cleanup, not cancellation. */
internal abstract class ChatGptAuthResource : ChatGptAuthSafeObject() {
    abstract fun stopAndAwait(): Boolean
}

/**
 * One original admission clock. The host creates this before any initialization/random/store work.
 * Arbitrary completion callbacks must recheck check(); submission additionally uses claimDispatch().
 * A permit is not proof that the peer received nothing: after submission ambiguity belongs to A3.
 */
internal class ChatGptAuthLifetime private constructor(
    private val origin: Long,
    private val allowance: Long,
    private val clock: () -> Long,
    private val parent: ChatGptAuthParent?,
    private val cancellation: ChatGptAuthCancellation?,
) : ChatGptAuthSafeObject() {
    private enum class Authority { OPEN, DISPATCHED, FENCED, COMMITTING, COMPLETE }
    private val authority = AtomicReference(Authority.OPEN)
    private val result = AtomicReference<ChatGptAuthCommit?>()
    private val publicationPhase = AtomicReference<ChatGptStoreOperation?>()
    private val monitor = Any()
    private val phases = EnumMap<ChatGptAuthPhase, ChatGptStoreOperation>(ChatGptAuthPhase::class.java)
    private val resources = ArrayList<Cleanup>()
    @Volatile private var fenced = false
    private var listenerAdmitted = false
    private var slotHeld = false
    private var cleanupOrigin: Long? = null
    private var cleanupAllowance = 0L

    private class Cleanup(val resource: ChatGptAuthResource) {
        @Volatile var acknowledged = false
        var thread: Thread? = null
    }

    private val gate = object : ChatGptAuthPublication() {
        override fun enterCommit(): Boolean {
            try { check(); publicationPhase.get()?.check() } catch (_: Exception) { cancel(); return false }
            while (true) {
                val old = authority.get()
                if (old != Authority.OPEN && old != Authority.DISPATCHED) return false
                if (authority.compareAndSet(old, Authority.COMMITTING)) return true
            }
        }
        override fun complete(result: ChatGptAuthCommit) {
            // Only the store owning the successful gate may call this port, once.
            synchronized(monitor) {
                if (authority.get() != Authority.COMMITTING) throw ChatGptAuthException(ChatGptAuthFailure.ATTEMPT_USED)
                this@ChatGptAuthLifetime.result.set(result)
                authority.set(Authority.COMPLETE)
            }
        }
    }

    fun publication(): ChatGptAuthPublication = gate
    /** Durable/unknown store outcome remains observable even if cancellation raced publication. */
    fun commitOutcome(): ChatGptAuthCommit? = result.get()

    fun check() { remainingNanos() }

    fun remainingNanos(): Long {
        if (fenced || authority.get() in setOf(Authority.FENCED, Authority.COMPLETE) || Thread.currentThread().isInterrupted) {
            cancel()
            throw ChatGptAuthException(ChatGptAuthFailure.CANCELLED)
        }
        val remaining = try {
            if (cancellation?.isCancelled() == true) {
                cancel()
                throw ChatGptAuthException(ChatGptAuthFailure.CANCELLED)
            }
            originalRemaining {
                // Parent evaluation may consume time or observe cancellation. Recheck after it,
                // then sample the clock after this cancellation callback too.
                if (cancellation?.isCancelled() == true || fenced ||
                    authority.get() in setOf(Authority.FENCED, Authority.COMPLETE) ||
                    Thread.currentThread().isInterrupted) {
                    cancel()
                    throw ChatGptAuthException(ChatGptAuthFailure.CANCELLED)
                }
            }
        } catch (e: ChatGptAuthException) { throw e }
        catch (_: Exception) {
            cancel()
            throw ChatGptAuthException(ChatGptAuthFailure.DEPENDENCY_FAILED)
        }
        if (remaining <= 0) {
            cancel()
            throw ChatGptAuthException(ChatGptAuthFailure.TIMEOUT)
        }
        return remaining
    }

    private fun originalRemaining(afterParent: () -> Unit = {}): Long {
        val parentRemaining = parent?.remainingNanos() ?: Long.MAX_VALUE
        afterParent()
        val elapsed = clock() - origin // nanoTime wrap is valid for these short intervals.
        if (elapsed < 0 || elapsed >= allowance) return 0
        return minOf(allowance - elapsed, parentRemaining).coerceAtLeast(0)
    }

    fun cancel(): ChatGptAuthCancelResult {
        while (true) {
            val old = authority.get()
            val answer = when (old) {
                Authority.COMMITTING -> ChatGptAuthCancelResult.COMMIT_IN_PROGRESS
                Authority.COMPLETE -> ChatGptAuthCancelResult.ALREADY_SETTLED
                Authority.FENCED -> ChatGptAuthCancelResult.CANCELLED
                else -> if (authority.compareAndSet(old, Authority.FENCED)) ChatGptAuthCancelResult.CANCELLED else continue
            }
            fenced = true
            startCleanup()
            return answer
        }
    }

    /** Single dispatch owner even when Code.prepareExchange is called repeatedly. Never resets. */
    fun claimDispatch(): Boolean {
        try { check(); publicationPhase.get()?.check() } catch (_: Exception) { cancel(); return false }
        return authority.compareAndSet(Authority.OPEN, Authority.DISPATCHED)
    }

    fun phaseOperation(phase: ChatGptAuthPhase): ChatGptStoreOperation = synchronized(monitor) {
        check()
        phases.getOrPut(phase) {
            val phaseOrigin = clock()
            val budget = minOf(30_000_000_000L, remainingNanos())
            val elapsedFloor = AtomicLong()
            var initializing = true
            ChatGptStoreOperation.create(Duration.ofNanos(budget), {
                try { check(); false } catch (_: ChatGptAuthException) { true }
            }, {
                // StoreOperation exposes a clock and cancellation port, not a dynamic parent port.
                // Its virtual clock charges initialization and parent shrinkage without restoring time.
                if (initializing) { initializing = false; 0L } else {
                    val remaining = remainingNanos()
                    val elapsed = clock() - phaseOrigin
                    val charged = if (elapsed < 0) budget else maxOf(elapsed, budget - remaining)
                    elapsedFloor.accumulateAndGet(charged, ::maxOf)
                }
            }).also { publicationPhase.set(it) }
        }
    }

    /** Ownership is bounded and cannot be registered after the result fence. */
    fun own(resource: ChatGptAuthResource) = synchronized(monitor) {
        check()
        if (resources.size == MAX_RESOURCES) throw ChatGptAuthException(ChatGptAuthFailure.RESOURCE_LIMIT)
        if (resources.any { it.resource === resource }) throw ChatGptAuthException(ChatGptAuthFailure.INVALID_OWNER)
        resources.add(Cleanup(resource))
        Unit
    }

    internal fun admitListener() = synchronized(monitor) {
        check()
        if (listenerAdmitted) throw ChatGptAuthException(ChatGptAuthFailure.ATTEMPT_USED)
        while (true) {
            val count = liveAttempts.get()
            if (count >= 4) throw ChatGptAuthException(ChatGptAuthFailure.RESOURCE_LIMIT)
            if (liveAttempts.compareAndSet(count, count + 1)) break
        }
        listenerAdmitted = true
        slotHeld = true
    }

    private fun startCleanup() = synchronized(monitor) {
        if (cleanupOrigin == null) {
            cleanupOrigin = System.nanoTime()
            cleanupAllowance = try { minOf(CLEANUP_NANOS, originalRemaining()) } catch (_: Exception) { 0 }
        }
        for (entry in resources) if (entry.thread == null) {
            val worker = Thread({
                try { entry.acknowledged = entry.resource.stopAndAwait() }
                catch (_: Throwable) { /* fixed UNSETTLED, no raw diagnostics */ }
            }, "chatgpt-auth-cleanup")
            // A stuck trusted adapter is quarantined, never force-stopped. Capacity stays occupied.
            worker.isDaemon = true
            entry.thread = worker
            try { worker.start() } catch (_: Throwable) { /* retained unacknowledged */ }
        }
    }

    fun settle(): ChatGptAuthSettlement {
        // Revoke ordinary result/submission authority BEFORE invoking any cleanup callback.
        cancel()
        val entries = synchronized(monitor) { resources.toList() }
        for (entry in entries) {
            val wait = synchronized(monitor) {
                (cleanupAllowance - (System.nanoTime() - cleanupOrigin!!)).coerceAtLeast(0)
            }
            if (wait > 0) try {
                entry.thread?.join(wait / 1_000_000, (wait % 1_000_000).toInt())
            } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
        }
        return synchronized(monitor) {
            if (authority.get() == Authority.COMMITTING || resources.any { !it.acknowledged || it.thread?.isAlive == true }) {
                ChatGptAuthSettlement.UNSETTLED
            } else {
                if (slotHeld) { slotHeld = false; liveAttempts.decrementAndGet() }
                ChatGptAuthSettlement.SETTLED
            }
        }
    }

    companion object {
        internal const val POLL_NANOS = 25_000_000L
        private const val CLEANUP_NANOS = 250_000_000L
        private const val MAX_RESOURCES = 16
        private val liveAttempts = AtomicInteger()

        fun start(
            timeout: Duration = Duration.ofMinutes(5),
            parent: ChatGptAuthParent? = null,
            cancellation: ChatGptAuthCancellation? = null,
            clock: () -> Long = System::nanoTime,
        ): ChatGptAuthLifetime {
            val origin = clock() // first action, before validation or trusted parent initialization
            require(!timeout.isNegative && !timeout.isZero && timeout <= Duration.ofMinutes(5)) { "INVALID_AUTH_BUDGET" }
            return ChatGptAuthLifetime(origin, timeout.toNanos(), clock, parent, cancellation)
        }
    }
}
