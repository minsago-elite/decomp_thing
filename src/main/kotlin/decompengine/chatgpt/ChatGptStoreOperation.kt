package decompengine.chatgpt

import java.time.Duration
import java.util.concurrent.CancellationException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicReference

/** Original trusted time and sticky cancellation, with owner-only cooperative probes. */
class ChatGptStoreOperation private constructor(
    internal val deadline: ChatGptDeadline,
    internal val fence: ChatGptOperationFence,
    private val cancelled: () -> Boolean,
    private val probe: () -> Long,
    private val failure: AtomicReference<Failure?> = AtomicReference(),
) {
    private enum class Failure { CANCELLED, TIMEOUT, DEPENDENCY }
    private fun reject(reason: Failure): Nothing {
        failure.compareAndSet(null, reason)
        fence.cancel()
        when (failure.get()!!) {
            Failure.CANCELLED -> throw CancellationException("ChatGPT store operation cancelled")
            Failure.TIMEOUT -> throw TimeoutException("ChatGPT store operation timed out")
            Failure.DEPENDENCY -> throw IllegalStateException("ChatGPT store operation dependency failed")
        }
    }
    private fun trustedRemaining(): Long {
        failure.get()?.let { reject(it) }
        if (Thread.currentThread().isInterrupted || fence.isCancelled()) reject(Failure.CANCELLED)
        return deadline.remainingNanos().also { if (it == 0L) reject(Failure.TIMEOUT) }
    }
    fun check() { remainingNanos() }
    internal fun remainingNanos(): Long {
        trustedRemaining()
        try {
            if (cancelled()) reject(Failure.CANCELLED)
            probe() // arbitrary return values never supply time authority
        } catch (_: CancellationException) { reject(Failure.CANCELLED) }
        catch (_: TimeoutException) { reject(Failure.TIMEOUT) }
        catch (_: InterruptedException) { Thread.currentThread().interrupt(); reject(Failure.CANCELLED) }
        catch (_: Exception) { reject(Failure.DEPENDENCY) }
        return trustedRemaining()
    }
    internal fun capped(timeout: Duration): ChatGptStoreOperation {
        validateDuration(timeout)
        val child = deadline.cap(timeout.toNanos()) // before any cooperative callback
        check()
        return ChatGptStoreOperation(child, fence, cancelled, probe, failure).also { it.trustedRemaining() }
    }
    internal fun pause() {
        try { TimeUnit.NANOSECONDS.sleep(minOf(remainingNanos(), POLL_NANOS)) }
        catch (_: InterruptedException) { Thread.currentThread().interrupt(); reject(Failure.CANCELLED) }
    }
    override fun toString() = "ChatGptStoreOperation"
    companion object {
        internal const val POLL_NANOS = 25_000_000L
        fun start(timeout: Duration = Duration.ofSeconds(30), cancelled: () -> Boolean = { false }): ChatGptStoreOperation =
            create(timeout, cancelled, System::nanoTime)
        internal fun create(timeout: Duration, cancelled: () -> Boolean, clock: () -> Long): ChatGptStoreOperation =
            createControlled(timeout, cancelled, ChatGptDeadlineClock.SYSTEM, clock)
        internal fun createControlled(timeout: Duration, cancelled: () -> Boolean,
            clock: ChatGptDeadlineClock, probe: () -> Long): ChatGptStoreOperation {
            validateDuration(timeout)
            return ChatGptStoreOperation(ChatGptDeadline.start(clock, timeout.toNanos()), ChatGptOperationFence(), cancelled, probe)
        }
        internal fun fromDeadline(deadline: ChatGptDeadline, fence: ChatGptOperationFence,
            cancelled: () -> Boolean): ChatGptStoreOperation = ChatGptStoreOperation(deadline, fence, cancelled, { 0L })
        private fun validateDuration(timeout: Duration) {
            require(!timeout.isNegative && !timeout.isZero && timeout <= Duration.ofSeconds(30)) {
                "invalid ChatGPT store operation duration"
            }
        }
    }
}

/** No raw causes or suppressed exceptions cross the private store boundary. */
internal inline fun <T> storeBoundary(block: () -> T): T = try { block() }
catch (_: InterruptedException) {
    Thread.currentThread().interrupt()
    throw CancellationException("ChatGPT store operation cancelled")
} catch (_: CancellationException) { throw CancellationException("ChatGPT store operation cancelled") }
catch (_: TimeoutException) { throw TimeoutException("ChatGPT store operation timed out") }
catch (e: StoreInputFailure) { throw IllegalArgumentException(e.safeMessage) }
catch (e: StoreFailure) { throw IllegalStateException(e.safeMessage) }
catch (_: NoSuchElementException) { throw NoSuchElementException("unknown ChatGPT account id") }
catch (_: IllegalArgumentException) { throw IllegalArgumentException("invalid or unsafe ChatGPT store input") }
catch (_: Exception) { throw IllegalStateException("ChatGPT credential operation failed") }
catch (_: LinkageError) { throw IllegalStateException("ChatGPT private filesystem is unsupported") }

internal class StoreFailure(val safeMessage: String) : RuntimeException(safeMessage)

internal class StoreInputFailure(val safeMessage: String) : RuntimeException(safeMessage)
