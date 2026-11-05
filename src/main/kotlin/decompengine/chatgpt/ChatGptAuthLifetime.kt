package decompengine.chatgpt

import java.time.Duration
import java.util.EnumMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

internal abstract class ChatGptAuthParent : ChatGptAuthSafeObject() {
    internal abstract val deadline: ChatGptDeadline
    /** Owner-only veto/tightening callback; never cleanup authority. */
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
    internal val deadline: ChatGptDeadline,
    internal val fence: ChatGptOperationFence,
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
    private var cleanup: ChatGptCleanupWindow? = null
    private var initializations = 0

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
                synchronized(monitor) {
                    try { trustedRemaining(); publicationPhase.get()?.let {
                        if (it.fence.isCancelled() || it.deadline.remainingNanos() == 0L) return false
                    } } catch (_: Exception) { return false }
                    if (authority.compareAndSet(old, Authority.COMMITTING)) return true
                }
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

    private fun trustedRemaining(): Long {
        if (fence.isCancelled() || fenced || authority.get() in setOf(Authority.FENCED, Authority.COMPLETE) ||
            Thread.currentThread().isInterrupted) throw ChatGptAuthException(ChatGptAuthFailure.CANCELLED)
        return deadline.remainingNanos().also { if (it == 0L) throw ChatGptAuthException(ChatGptAuthFailure.TIMEOUT) }
    }
    fun remainingNanos(): Long {
        synchronized(monitor) { initializations++ }
        try {
            trustedRemaining()
            if (cancellation?.isCancelled() == true) throw ChatGptAuthException(ChatGptAuthFailure.CANCELLED)
            val before = deadline.clock.readNanos()
            parent?.let { deadline.tightenFrom(before, it.remainingNanos()) }
            clock() // owned non-authoritative probe
            if (cancellation?.isCancelled() == true) throw ChatGptAuthException(ChatGptAuthFailure.CANCELLED)
            return trustedRemaining()
        } catch (e: ChatGptAuthException) { cancel(); throw e }
        catch (_: Exception) { cancel(); throw ChatGptAuthException(ChatGptAuthFailure.DEPENDENCY_FAILED) }
        finally { synchronized(monitor) { initializations-- } }
    }

    fun cancel(): ChatGptAuthCancelResult {
      synchronized(monitor) {
        while (true) {
            val old = authority.get()
            val answer = when (old) {
                Authority.COMMITTING -> ChatGptAuthCancelResult.COMMIT_IN_PROGRESS
                Authority.COMPLETE -> ChatGptAuthCancelResult.ALREADY_SETTLED
                Authority.FENCED -> ChatGptAuthCancelResult.CANCELLED
                else -> if (authority.compareAndSet(old, Authority.FENCED)) ChatGptAuthCancelResult.CANCELLED else continue
            }
            fence.cancel()
            fenced = true
            startCleanup()
            return answer
        }
      }
    }

    /** Single dispatch owner even when Code.prepareExchange is called repeatedly. Never resets. */
    fun claimDispatch(): Boolean {
        try { check(); publicationPhase.get()?.check() } catch (_: Exception) { cancel(); return false }
        return synchronized(monitor) {
            try { trustedRemaining(); publicationPhase.get()?.let {
                if (it.fence.isCancelled() || it.deadline.remainingNanos() == 0L) return false
            } } catch (_: Exception) { return false }
            authority.compareAndSet(Authority.OPEN, Authority.DISPATCHED)
        }
    }

    fun phaseOperation(phase: ChatGptAuthPhase): ChatGptStoreOperation {
        val child = synchronized(monitor) {
            trustedRemaining()
            initializations++
            deadline.cap(30_000_000_000L)
        }
        try {
            check()
            val existing = synchronized(monitor) { phases[phase] }
            if (existing != null) return existing
            val operation = ChatGptStoreOperation.fromDeadline(child, fence) {
                try { check(); false } catch (e: ChatGptAuthException) {
                    when (e.failure) {
                        ChatGptAuthFailure.TIMEOUT -> throw java.util.concurrent.TimeoutException("ChatGPT auth phase timed out")
                        ChatGptAuthFailure.CANCELLED -> throw java.util.concurrent.CancellationException("ChatGPT auth phase cancelled")
                        else -> throw IllegalStateException("ChatGPT auth phase dependency failed")
                    }
                }
            }
            operation.check()
            return synchronized(monitor) {
                trustedRemaining()
                if (child.remainingNanos() == 0L) throw ChatGptAuthException(ChatGptAuthFailure.TIMEOUT)
                phases.getOrPut(phase) { operation.also { publicationPhase.set(it) } }
            }
        } finally { synchronized(monitor) { initializations-- } }
    }

    /** Reserve ownership before a helper can block; cleanup retains the entire initialization. */
    fun own(resource: ChatGptAuthResource) {
        synchronized(monitor) {
            trustedRemaining()
            if (resources.size == MAX_RESOURCES) throw ChatGptAuthException(ChatGptAuthFailure.RESOURCE_LIMIT)
            if (resources.any { it.resource === resource }) throw ChatGptAuthException(ChatGptAuthFailure.INVALID_OWNER)
            resources.add(Cleanup(resource)); initializations++
        }
        try { check(); synchronized(monitor) { trustedRemaining() } }
        catch (e: Exception) { cancel(); throw e }
        finally { synchronized(monitor) { initializations-- } }
    }

    internal fun admitListener() {
        synchronized(monitor) {
            trustedRemaining()
            if (listenerAdmitted) throw ChatGptAuthException(ChatGptAuthFailure.ATTEMPT_USED)
            while (true) {
                val count = liveAttempts.get()
                if (count >= 4) throw ChatGptAuthException(ChatGptAuthFailure.RESOURCE_LIMIT)
                if (liveAttempts.compareAndSet(count, count + 1)) break
            }
            listenerAdmitted = true; slotHeld = true; initializations++
        }
        try { check(); synchronized(monitor) { trustedRemaining() } }
        catch (e: Exception) { cancel(); throw e }
        finally { synchronized(monitor) { initializations-- } }
    }

    private fun startCleanup() = synchronized(monitor) {
        if (cleanup == null) cleanup = ChatGptCleanupWindow(deadline, CLEANUP_NANOS)
        for (entry in resources) if (entry.thread == null) {
            val worker = Thread({
                try { entry.acknowledged = entry.resource.stopAndAwait() }
                catch (_: Throwable) { /* sticky failed acknowledgement */ }
            }, "chatgpt-auth-cleanup")
            worker.isDaemon = true; entry.thread = worker
            try { worker.start() } catch (_: Throwable) { /* retained unacknowledged */ }
        }
    }

    fun settle(): ChatGptAuthSettlement {
        cancel()
        val entries = synchronized(monitor) { resources.toList() }
        for (entry in entries) {
            while (entry.thread?.isAlive == true) {
                val wait = synchronized(monitor) { minOf(POLL_NANOS, cleanup!!.remainingNanos(), deadline.remainingNanos()) }
                if (wait <= 0) break
                try { entry.thread?.join(wait / 1_000_000, (wait % 1_000_000).toInt()) }
                catch (_: InterruptedException) { Thread.currentThread().interrupt(); break }
            }
        }
        return synchronized(monitor) {
            if (initializations != 0 || authority.get() == Authority.COMMITTING ||
                resources.any { !it.acknowledged || it.thread?.isAlive == true }) ChatGptAuthSettlement.UNSETTLED
            else {
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
            return startControlled(timeout, parent, cancellation, ChatGptDeadlineClock.SYSTEM, clock)
        }
        internal fun startControlled(
            timeout: Duration = Duration.ofMinutes(5), parent: ChatGptAuthParent? = null,
            cancellation: ChatGptAuthCancellation? = null, deadlineClock: ChatGptDeadlineClock,
            clockProbe: () -> Long = { 0L },
        ): ChatGptAuthLifetime {
            val root = ChatGptDeadline.start(deadlineClock, 300_000_000_000L)
            val entry = deadlineClock.readNanos()
            require(!timeout.isNegative && !timeout.isZero && timeout <= Duration.ofMinutes(5)) { "INVALID_AUTH_BUDGET" }
            // Fresh roots must also be minted before the potentially blocking parent getter.
            val own = root.capAt(entry, timeout.toNanos())
            val parentDeadline = try { parent?.deadline } catch (_: Exception) {
                throw ChatGptAuthException(ChatGptAuthFailure.DEPENDENCY_FAILED)
            }
            if (parentDeadline != null && parentDeadline.clock !== deadlineClock)
                throw ChatGptAuthException(ChatGptAuthFailure.INVALID_OWNER)
            val deadline = parentDeadline?.capAt(entry, timeout.toNanos()) ?: own
            return ChatGptAuthLifetime(deadline, ChatGptOperationFence(), clockProbe, parent, cancellation)
        }
    }
}
