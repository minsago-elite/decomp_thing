package decompengine.oracle.gcc

import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GccBundledHostWorkTest {
    @Test
    fun `blocked native read that ignores interrupts returns a bounded failure and keeps ownership until it retires`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val root = Files.createTempDirectory(scratch, "gcc-host-work-").toRealPath()
        val fifo = root.resolve("blocked.fifo")
        try {
            assertEquals(0, ProcessBuilder("mkfifo", "-m", "600", fifo.toString()).start().waitFor())
            // O_RDWR never waits for a peer, and its own writer keeps read(2) blocked without EOF.
            RandomAccessFile(fifo.toFile(), "rw").use { pipe ->
                val tracker = GccBundledHostWorkTracker()
                val closed = AtomicBoolean(false)
                val closedOnOwner = AtomicBoolean(false)
                val outcome = arrayOfNulls<Throwable>(1)
                val started = System.nanoTime()
                // A watchdog-free caller thread lets a mutation that waits unboundedly fail instead of hanging the suite.
                val caller = Thread {
                    outcome[0] = runCatching {
                        tracker.run("blocked read", 300, AutoCloseable {
                            closedOnOwner.set(Thread.currentThread().name == "gcc-host-work")
                            closed.set(true)
                        }) { pipe.read() }
                    }.exceptionOrNull()
                }.apply { isDaemon = true; start() }
                caller.join(15_000)
                val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
                val bounded = !caller.isAlive
                try {
                    assertTrue(bounded, "the caller must return while the native read remains blocked")
                    assertTrue(outcome[0] is GccBundledHostWorkTimeoutException, outcome[0].toString())
                    assertTrue(elapsedMillis in 300..10_000, "elapsed $elapsedMillis ms")
                    assertEquals(listOf("blocked read"), tracker.inFlightStages)
                    assertFalse(closed.get(), "a timed-out caller must not close descriptors owned by the blocked step")
                    assertFailsWith<IllegalStateException> { tracker.requireRetired(50) }
                } finally {
                    pipe.write(1)
                }
                tracker.requireRetired(10_000)
                assertTrue(closed.get() && closedOnOwner.get(), "the step closes its own descriptor when its syscall returns")
                assertEquals(emptyList(), tracker.inFlightStages)
            }
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
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
        assertFailsWith<IllegalArgumentException> { tracker.run("no allowance", 0, AutoCloseable { closes++ }) { 1 } }
        assertEquals(3, closes)
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
