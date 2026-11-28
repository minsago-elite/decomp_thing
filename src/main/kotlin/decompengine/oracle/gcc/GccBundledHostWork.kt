package decompengine.oracle.gcc

import java.lang.management.ManagementFactory
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** The caller stopped waiting; the named step still owns its descriptors until its thread retires. */
internal class GccBundledHostWorkTimeoutException(stage: String) :
    IllegalStateException("GCC host $stage exceeded its operation allowance; in-flight work retains its own descriptors")

internal class GccBundledHostMemoryBudgetException(message: String) : IllegalStateException(message)

/** Visible to one owned step: abandonment is checked at the step's cooperative checkpoints. */
internal class GccBundledHostWorkContext internal constructor(private val stage: String) {
    @Volatile
    internal var abandoned = false
        private set

    fun requireCurrent(label: String) {
        if (abandoned) throw IllegalStateException("GCC host $stage was abandoned by its operation at $label")
    }

    internal fun abandon() { abandoned = true }
}

/**
 * Runs host-side steps on dedicated owned threads so that a native read, fsync or rename that
 * ignores interrupts, or one nonpreemptible library call, cannot hold the operation past its
 * allowance. The step alone closes [owned]; a timed-out caller never closes a descriptor that a
 * blocked syscall may still use. Unretired steps keep the operation from releasing ownership.
 */
internal class GccBundledHostWorkTracker {
    private class Step(val stage: String, val thread: Thread, val retired: CountDownLatch)

    private val steps = mutableListOf<Step>()

    @Synchronized
    private fun register(step: Step) { steps.removeAll { it.retired.count == 0L }; steps += step }

    val inFlightStages: List<String>
        @Synchronized get() = steps.filter { it.retired.count != 0L }.map { it.stage }

    fun <T> run(stage: String, allowanceMillis: Long, owned: AutoCloseable?, work: (GccBundledHostWorkContext) -> T): T {
        val context = GccBundledHostWorkContext(stage)
        val retired = CountDownLatch(1)
        val outcome = arrayOfNulls<Any>(1)
        var failure: Throwable? = null
        val done = CountDownLatch(1)
        val thread = Thread({
            try {
                try {
                    outcome[0] = work(context)
                } finally {
                    owned?.close()
                }
            } catch (thrown: Throwable) {
                failure = thrown
            } finally {
                done.countDown()
                retired.countDown()
            }
        }, "gcc-host-work").apply { isDaemon = true }
        try {
            require(allowanceMillis > 0) { "GCC host $stage has no remaining allowance" }
            register(Step(stage, thread, retired))
            thread.start()
        } catch (notStarted: Throwable) {
            runCatching { owned?.close() }.exceptionOrNull()?.let(notStarted::addSuppressed)
            retired.countDown()
            throw notStarted
        }
        val completed = try {
            done.await(allowanceMillis, TimeUnit.MILLISECONDS)
        } catch (interrupted: InterruptedException) {
            context.abandon()
            thread.interrupt()
            throw interrupted
        }
        if (!completed) {
            context.abandon()
            thread.interrupt()
            throw GccBundledHostWorkTimeoutException(stage)
        }
        failure?.let { throw it }
        @Suppress("UNCHECKED_CAST")
        return outcome[0] as T
    }

    /** Waits at most [graceMillis] in total; any step still in flight retains operation ownership. */
    fun requireRetired(graceMillis: Long) {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(graceMillis)
        val pending = synchronized(this) { steps.toList() }
        for (step in pending) {
            val remaining = deadline - System.nanoTime()
            if (remaining > 0) runCatching { step.retired.await(remaining, TimeUnit.NANOSECONDS) }
        }
        val stages = inFlightStages
        check(stages.isEmpty()) { "GCC host work remains in flight ($stages); retaining disk and input ownership" }
    }
}

/**
 * Admitted host allocation for one owned phase, bound to the thread that performs it.
 *
 * A fixed working reservation is admitted at binding, every retained buffer and every
 * nonpreemptible assessment step is admitted before allocation, and at each cooperative checkpoint
 * the thread's measured heap allocation must remain within what was admitted. Allocation includes
 * collected garbage, so it bounds the heap this phase can retain. Allocation within one library
 * call is observed at the next checkpoint; the JVM heap limit remains the backstop.
 */
internal class GccBundledHostMemoryBudget(
    val maximumBytes: Long,
    private val allocatedBytes: () -> Long = ::currentThreadAllocatedBytes,
) {
    private val owner = Thread.currentThread()
    private val started = allocatedBytes()
    var admittedBytes: Long = WORKING_RESERVATION_BYTES
        private set

    init {
        if (maximumBytes < WORKING_RESERVATION_BYTES) {
            throw GccBundledHostMemoryBudgetException("GCC host memory budget is below its fixed working reservation")
        }
    }

    val measuredBytes: Long get() = allocatedBytes() - started

    fun admit(stage: String, bytes: Long) {
        require(bytes >= 0)
        requireWithinAdmission(stage)
        if (bytes > maximumBytes - admittedBytes) {
            throw GccBundledHostMemoryBudgetException(
                "GCC host $stage needs $bytes bytes beyond $admittedBytes admitted of its $maximumBytes-byte host memory budget")
        }
        admittedBytes += bytes
    }

    fun requireWithinAdmission(stage: String) {
        check(Thread.currentThread() === owner) { "GCC host memory budget is bound to its owned thread" }
        val measured = measuredBytes
        if (measured < 0 || measured > admittedBytes) {
            throw GccBundledHostMemoryBudgetException(
                "GCC host allocation reached $measured bytes at $stage, beyond its $admittedBytes admitted bytes")
        }
    }

    companion object {
        const val WORKING_RESERVATION_BYTES = 16L * 1024 * 1024
    }
}

private val THREADS = ManagementFactory.getThreadMXBean() as? com.sun.management.ThreadMXBean

internal fun currentThreadAllocatedBytes(): Long {
    val threads = THREADS
    if (threads == null || !threads.isThreadAllocatedMemorySupported || !threads.isThreadAllocatedMemoryEnabled) {
        throw GccBundledHostMemoryBudgetException("GCC host memory accounting requires per-thread allocation measurement")
    }
    return threads.currentThreadAllocatedBytes.also { check(it >= 0) { "GCC host allocation measurement is unavailable" } }
}
