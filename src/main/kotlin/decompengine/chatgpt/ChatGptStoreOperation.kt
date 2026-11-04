package decompengine.chatgpt

import java.time.Duration
import java.util.concurrent.CancellationException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** One original monotonic budget, including admission, disk work, transport and validation. */
class ChatGptStoreOperation private constructor(
    private val allowance: Long,
    private val cancelled: () -> Boolean,
    private val clock: () -> Long,
    private val parent: ChatGptStoreOperation? = null,
) {
    private val start = clock()

    fun check() { remainingNanos() }

    internal fun remainingNanos(): Long {
        if (Thread.currentThread().isInterrupted || cancelled())
            throw CancellationException("ChatGPT store operation cancelled")
        // Subtraction is valid across nanoTime's signed wrap for intervals shorter than 2^63 ns.
        val elapsed = clock() - start
        if (elapsed < 0 || elapsed >= allowance) throw TimeoutException("ChatGPT store operation timed out")
        return minOf(allowance - elapsed, parent?.remainingNanos() ?: Long.MAX_VALUE)
    }

    /** An attempt may tighten its bound, but cannot renew the caller's original budget. */
    internal fun capped(timeout: Duration): ChatGptStoreOperation {
        validateDuration(timeout)
        check()
        return ChatGptStoreOperation(timeout.toNanos(), { false }, clock, this)
    }

    internal fun pause() {
        try { TimeUnit.NANOSECONDS.sleep(minOf(remainingNanos(), POLL_NANOS)) }
        catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            throw CancellationException("ChatGPT store operation cancelled")
        }
    }

    override fun toString() = "ChatGptStoreOperation"

    companion object {
        internal const val POLL_NANOS = 25_000_000L
        fun start(timeout: Duration = Duration.ofSeconds(30), cancelled: () -> Boolean = { false }): ChatGptStoreOperation =
            create(timeout, cancelled, System::nanoTime)

        internal fun create(timeout: Duration, cancelled: () -> Boolean, clock: () -> Long): ChatGptStoreOperation {
            validateDuration(timeout)
            return ChatGptStoreOperation(timeout.toNanos(), cancelled, clock)
        }
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
