package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.spi.AbstractInterruptibleChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GccBundledHostWorkTest {
    @Test
    fun `abandoning a blocked NIO channel read bounds the caller and never closes the step's channel`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val root = Files.createTempDirectory(scratch, "gcc-host-work-").toRealPath()
        val fifo = root.resolve("blocked.fifo")
        try {
            assertEquals(0, ProcessBuilder("mkfifo", "-m", "600", fifo.toString()).start().waitFor())
            // O_RDWR never waits for a peer, and its own writer keeps read(2) blocked without EOF.
            FileChannel.open(fifo, StandardOpenOption.READ, StandardOpenOption.WRITE).use { channel ->
                // A separate writer: FileChannelImpl holds its position lock for the whole blocked read.
                FileChannel.open(fifo, StandardOpenOption.WRITE).use { writer ->
                    val tracker = GccBundledHostWorkTracker()
                    val closed = AtomicBoolean(false)
                    val outcome = callBounded {
                        tracker.run("blocked channel read", 300, AutoCloseable { closed.set(true) }) {
                            channel.read(ByteBuffer.allocate(1))
                        }
                    }
                    try {
                        assertTrue(outcome.returned, "the caller must return while the channel read remains blocked")
                        assertTrue(outcome.failure is GccBundledHostWorkTimeoutException, outcome.failure.toString())
                        assertTrue(outcome.elapsedMillis in 300..10_000, "elapsed ${outcome.elapsedMillis} ms")
                        assertTrue(channel.isOpen, "abandonment must not run the channel's interruptor on the caller")
                        assertEquals(listOf("blocked channel read"), tracker.inFlightStages)
                        assertFalse(closed.get(), "a timed-out caller must not close descriptors owned by the blocked step")
                        assertFailsWith<IllegalStateException> { tracker.requireRetired(50) }
                    } finally {
                        writer.write(ByteBuffer.wrap(byteArrayOf(1)))
                    }
                    tracker.requireRetired(10_000)
                    assertTrue(closed.get(), "the step closes its own descriptor when its read returns")
                    assertEquals(emptyList(), tracker.inFlightStages)
                }
            }
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    @Test
    fun `abandonment cannot be held by a channel close that waits for its blocked native operation`() {
        val release = CountDownLatch(1)
        val closeEntered = CountDownLatch(1)
        // JDK 21 Thread.interrupt() runs this close on the interrupting thread; FileChannelImpl's close
        // likewise waits for a native read that its wakeup signal cannot end.
        val channel = object : AbstractInterruptibleChannel() {
            override fun implCloseChannel() { closeEntered.countDown(); awaitIgnoringInterrupts(release) }
            fun blockedOperation() { begin(); try { awaitIgnoringInterrupts(release) } finally { end(true) } }
        }
        val tracker = GccBundledHostWorkTracker()
        val outcome = callBounded { tracker.run("blocked uninterruptible channel", 300, null) { channel.blockedOperation() } }
        try {
            assertTrue(outcome.returned && outcome.failure is GccBundledHostWorkTimeoutException, outcome.failure.toString())
            assertTrue(outcome.elapsedMillis in 300..10_000, "elapsed ${outcome.elapsedMillis} ms")
            assertEquals(1L, closeEntered.count, "the caller must not enter the blocked channel's close")
        } finally {
            release.countDown()
        }
        tracker.requireRetired(10_000)
    }

    private class Outcome(val returned: Boolean, val failure: Throwable?, val elapsedMillis: Long)

    /** A separate caller thread lets a mutation that waits unboundedly fail instead of hanging the suite. */
    private fun callBounded(action: () -> Unit): Outcome {
        val failure = arrayOfNulls<Throwable>(1)
        val started = System.nanoTime()
        val caller = Thread { failure[0] = runCatching(action).exceptionOrNull() }.apply { isDaemon = true; start() }
        caller.join(15_000)
        return Outcome(!caller.isAlive, failure[0], TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started))
    }

    private fun awaitIgnoringInterrupts(latch: CountDownLatch) {
        while (true) {
            try { if (latch.await(10, TimeUnit.SECONDS)) return } catch (_: InterruptedException) { }
        }
    }

    @Test
    fun `owned work returns results and propagates failures after closing its descriptor`() {
        val tracker = GccBundledHostWorkTracker()
        var closes = 0
        assertEquals(7, tracker.run("value", 5_000, AutoCloseable { closes++ }) { 7 })
        val failure = assertFailsWith<IllegalArgumentException> {
            tracker.run("failure", 5_000, AutoCloseable { closes++ }) { throw IllegalArgumentException("refused") }
        }
        assertEquals("refused", failure.message)
        assertFailsWith<GccBundledHostWorkTimeoutException> { tracker.run("no allowance", 0, AutoCloseable { closes++ }) { 1 } }
        tracker.requireRetired(5_000)
        assertEquals(3, closes)
    }

    @Test
    fun `a pinned-scope exit failure after duplication closes the handed-off duplicate`() {
        val scratch = Files.createDirectories(Path.of("build/test-tmp").toAbsolutePath().normalize())
        val path = Files.createTempDirectory(scratch, "gcc-host-duplicate-").toRealPath()
        fun descriptorsOnPath() = Files.list(Path.of("/proc/self/fd")).use { fds -> fds.toList() }
            .count { fd -> runCatching { Files.readSymbolicLink(fd) == path }.getOrDefault(false) }
        try {
            LinuxFilesystemSyscalls.openRoot(path).use { pinned ->
                val before = descriptorsOnPath()
                val failure = assertFailsWith<IllegalStateException> {
                    duplicateWithinPinnedScope { action -> action(pinned); throw IllegalStateException("exit check failed") }
                }
                assertEquals("exit check failed", failure.message)
                assertEquals(before, descriptorsOnPath(), "the duplicate must be closed when the scope's exit check fails")
                duplicateWithinPinnedScope { action -> action(pinned) }.use { assertEquals(before + 1, descriptorsOnPath()) }
                assertEquals(before, descriptorsOnPath())
            }
        } finally {
            Files.delete(path)
        }
    }

    @Test
    fun `the caller samples its wait from the deadline only after handing the step off`() {
        val tracker = GccBundledHostWorkTracker()
        val started = CountDownLatch(1)
        val value = tracker.run("handoff", {
            check(started.await(5, TimeUnit.SECONDS)) { "the wait was sampled before the step was handed off" }
            5_000L
        }, null) { started.countDown(); 7 }
        assertEquals(7, value)
        tracker.requireRetired(5_000)
    }

    @Test
    fun `host memory budget refuses admission and measured allocation beyond its admitted bytes`() {
        var allocated = 1_000L
        val reservation = GccBundledHostMemoryBudget.WORKING_RESERVATION_BYTES
        assertFailsWith<GccBundledHostMemoryBudgetException> { GccBundledHostMemoryBudget(reservation - 1) { allocated } }
        val budget = GccBundledHostMemoryBudget(reservation + 1_000) { allocated }
        budget.admit("first read", 600)
        val admission = assertFailsWith<GccBundledHostMemoryBudgetException> { budget.admit("second read", 401) }
        assertTrue(admission.message.orEmpty().contains("second read"))
        assertEquals(reservation + 600, budget.admittedBytes)
        allocated += reservation + 600
        budget.requireWithinAdmission("at the admitted limit")
        allocated += 1
        val measured = assertFailsWith<GccBundledHostMemoryBudgetException> { budget.requireWithinAdmission("after one more byte") }
        assertTrue(measured.message.orEmpty().contains("after one more byte"))
        assertFailsWith<GccBundledHostMemoryBudgetException> { budget.admit("any further read", 0) }
        val observed = arrayOfNulls<Throwable>(2)
        Thread {
            observed[0] = runCatching { GccBundledHostMemoryBudget(reservation).requireWithinAdmission("own") }.exceptionOrNull()
            observed[1] = runCatching { budget.requireWithinAdmission("foreign thread") }.exceptionOrNull()
        }.apply { start(); join() }
        assertEquals(null, observed[0], "the production counter measures the binding thread")
        assertTrue(observed[1]?.message.orEmpty().contains("bound to its owned thread"), observed[1].toString())
    }
}
