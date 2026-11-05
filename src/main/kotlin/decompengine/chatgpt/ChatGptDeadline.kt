package decompengine.chatgpt

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

private const val MAX_SPAN = 600_000_000_000L

internal class ChatGptDeadlineClock private constructor(private val ticks: AtomicLong?) {
    private val failed = AtomicBoolean()
    internal fun readNanos(): Long = ticks?.get() ?: System.nanoTime()
    internal fun valid(): Boolean = !failed.get()
    internal fun advanceNanos(delta: Long) {
        check(ticks != null)
        if (delta !in 0..MAX_SPAN) { failed.set(true); return }
        ticks.addAndGet(delta) // signed wrap is intentional
    }
    internal fun invalidate() { check(ticks != null); failed.set(true) }
    companion object {
        internal val SYSTEM = ChatGptDeadlineClock(null)
        internal fun controlled(initial: Long = 0L) = ChatGptDeadlineClock(AtomicLong(initial))
    }
}

internal class ChatGptDeadline private constructor(private val root: Root, private val localCutoff: Long) {
    private class Root(val clock: ChatGptDeadlineClock, val origin: Long, cutoff: Long) {
        val cutoff = AtomicLong(cutoff)
        val floor = AtomicLong()
        fun sample(): Long {
            val elapsed = clock.readNanos() - origin
            if (!clock.valid() || elapsed < 0 || elapsed > MAX_SPAN) {
                cutoff.set(0L)
                return MAX_SPAN
            }
            return floor.accumulateAndGet(elapsed) { old, next -> maxOf(old, next) }
        }
    }
    internal val clock: ChatGptDeadlineClock get() = root.clock
    internal fun remainingNanos(): Long {
        val elapsed = root.sample()
        return (minOf(root.cutoff.get(), localCutoff) - elapsed).coerceAtLeast(0L)
    }
    internal fun cap(maxNanos: Long): ChatGptDeadline = capAt(clock.readNanos(), maxNanos)
    internal fun capAt(entryNanos: Long, maxNanos: Long): ChatGptDeadline {
        require(maxNanos in 0..MAX_SPAN)
        root.sample()
        val entryElapsed = entryNanos - root.origin
        val cutoff = if (entryElapsed !in 0..MAX_SPAN) 0L else
            minOf(localCutoff, root.cutoff.get(), entryElapsed + maxNanos)
        return ChatGptDeadline(root, cutoff)
    }
    internal fun detach(): ChatGptDeadline {
        root.sample()
        val cutoff = minOf(localCutoff, root.cutoff.get())
        return ChatGptDeadline(Root(clock, root.origin, cutoff).also { it.floor.set(root.floor.get()) }, cutoff)
    }
    internal fun tightenFrom(beforeNanos: Long, remainingNanos: Long) {
        root.sample() // charge time spent in the helper, including reentry/preemption
        val before = beforeNanos - root.origin
        val ceiling = root.cutoff.get()
        val next = if (before !in 0..MAX_SPAN) 0L else {
            val amount = remainingNanos.coerceIn(0L, MAX_SPAN)
            minOf(ceiling, before + amount)
        }
        root.cutoff.accumulateAndGet(next) { old, value -> minOf(old, value) }
    }
    internal fun isWithin(parent: ChatGptDeadline): Boolean = root === parent.root && localCutoff <= parent.localCutoff
    companion object {
        internal fun start(clock: ChatGptDeadlineClock, span: Long): ChatGptDeadline {
            require(span in 1..MAX_SPAN)
            return ChatGptDeadline(Root(clock, clock.readNanos(), span), span)
        }
    }
}

internal class ChatGptOperationFence {
    private val cancelled = AtomicBoolean()
    internal fun cancel() { cancelled.set(true) }
    internal fun isCancelled(): Boolean = cancelled.get()
}

/** First-stop window; SYSTEM only shortens the original capability's allowance. */
internal class ChatGptCleanupWindow(deadline: ChatGptDeadline?, requested: Long) {
    private val guardOrigin = System.nanoTime()
    private val maximum = requested.coerceIn(0L, 250_000_000L)
    private val cutoff = deadline?.cap(maximum)
    internal fun remainingNanos(): Long {
        val elapsed = System.nanoTime() - guardOrigin
        val guard = if (elapsed < 0) 0L else (maximum - elapsed).coerceAtLeast(0L)
        return minOf(cutoff?.remainingNanos() ?: 0L, guard)
    }
}
