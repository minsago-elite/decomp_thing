package decompengine.project

import decompengine.analysis.BoundedAnalysisProcessLaunch
import decompengine.analysis.GhidraAnalysisException
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.lang.reflect.InvocationTargetException
import java.time.Duration
import java.util.Optional
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.stream.Stream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Portable policy controls; the real OpenJDK ordering reproduction is retained at 32ba8503. */
class GhidraLateExportCleanupWaitTest {
    @Test
    fun `owned acknowledgement wait settles cleanup before next isolated admission`() {
        val process = AcknowledgementProcess()
        val owner = owner()
        assertTrue(abandon(owner, process).suppressed.isEmpty())
        assertEquals(1, process.waits.size)
        assertTrue(process.waits.single() in 1..FORCED_ALLOWANCE)
        assertFalse(process.isAlive)
        process.assertStreamsClosed()
        val admitted = AtomicBoolean()
        assertSame(process, owner.start({}, { admitted.set(true); process }, ::cleanup))
        assertTrue(admitted.get())
    }

    @Test
    fun `already acknowledged process needs no additional wait`() {
        val process = AcknowledgementProcess(acknowledged = true)
        cleanup(process)
        assertTrue(process.waits.isEmpty())
        process.assertStreamsClosed()
    }

    @Test
    fun `false bounded wait preserves alive refusal and permanent same-owner latch`() {
        val process = AcknowledgementProcess(outcome = WaitOutcome.TIMEOUT)
        val owner = owner()
        val caller = abandon(owner, process)
        val failure = caller.suppressed.single()
        assertTrue(failure is GhidraAnalysisException)
        assertTrue(failure.message?.startsWith("late Ghidra export cleanup could not prove absence") == true)
        assertTrue(process.waits.isNotEmpty())
        assertTrue(process.waits.all { it in 1..TimeUnit.MILLISECONDS.toNanos(50) })
        assertTrue(process.waits.sum() <= FORCED_ALLOWANCE)
        assertTrue(process.isAlive)
        process.assertStreamsClosed()
        process.acknowledged = true
        assertStillRefused(owner, process, failure)
    }

    @Test
    fun `wait interruption is restored after bounded cleanup and caller failure stays primary`() {
        val process = AcknowledgementProcess(outcome = WaitOutcome.INTERRUPTED)
        val owner = owner()
        try {
            val caller = abandon(owner, process)
            assertTrue(caller.suppressed.isEmpty())
            assertEquals(2, process.waits.size)
            assertTrue(Thread.currentThread().isInterrupted)
            process.assertStreamsClosed()
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `entry interruption is cleared for owned cleanup and restored afterward`() {
        val process = AcknowledgementProcess()
        Thread.currentThread().interrupt()
        try {
            cleanup(process)
            assertEquals(1, process.waits.size)
            assertTrue(Thread.currentThread().isInterrupted)
            process.assertStreamsClosed()
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `stream failure after acknowledged exit retains failure and closes remaining streams`() {
        val process = AcknowledgementProcess(outputFailure = IOException("authored stream close refusal"))
        val owner = owner()
        val caller = abandon(owner, process)
        assertSame(process.outputFailure, caller.suppressed.single())
        assertFalse(process.isAlive)
        process.assertStreamsClosed()
        assertStillRefused(owner, process, checkNotNull(process.outputFailure))
    }

    @Test
    fun `owned wait receives the remaining aggregate allowance instead of a fresh five seconds`() {
        val process = AcknowledgementProcess(beforeEnumeration = {
            // A bounded authored enumeration stage consumes part of the existing tree allowance.
            // No race, real process, changed production timer or independent cleanup window is used.
            assertFalse(CountDownLatch(1).await(100, TimeUnit.MILLISECONDS))
        })
        cleanup(process)
        assertEquals(1, process.waits.size)
        assertTrue(process.waits.single() in 1 until FORCED_ALLOWANCE - TimeUnit.MILLISECONDS.toNanos(50))
        process.assertStreamsClosed()
    }

    private fun owner() = BoundedAnalysisProcessLaunch(Executor(Runnable::run))

    private fun abandon(owner: BoundedAnalysisProcessLaunch, process: Process): AuthoredAbandonment {
        val expected = AuthoredAbandonment()
        val actual = assertFailsWith<AuthoredAbandonment> {
            owner.start({ phase -> if (phase == "while starting export process") throw expected }, { process }) {
                cleanup(it, owner)
            }
        }
        assertSame(expected, actual)
        return actual
    }

    private fun assertStillRefused(owner: BoundedAnalysisProcessLaunch, process: Process, cause: Throwable) {
        val invoked = AtomicBoolean()
        val refusal = assertFailsWith<GhidraAnalysisException> {
            owner.start({}, { invoked.set(true); process }, ::cleanup)
        }
        assertFalse(invoked.get())
        assertSame(cause, refusal.cause)
        assertEquals("analysis launch is unavailable after an unconfirmed worker cleanup", refusal.message)
    }

    private class AuthoredAbandonment : RuntimeException("authored caller abandonment")
    private enum class WaitOutcome { ACKNOWLEDGED, TIMEOUT, INTERRUPTED }

    /** Distinct observations are authored explicitly; no host PID or process authority is represented. */
    private class AcknowledgementProcess(
        var acknowledged: Boolean = false,
        val outcome: WaitOutcome = WaitOutcome.ACKNOWLEDGED,
        val outputFailure: IOException? = null,
        beforeEnumeration: () -> Unit = {},
    ) : Process() {
        val waits = mutableListOf<Long>()
        val interruption = InterruptedException("authored owned-process acknowledgement interruption")
        private var interruptionDelivered = false
        private val closed = mutableListOf<String>()
        private val output = object : ByteArrayOutputStream() {
            override fun close() { closed += "output"; outputFailure?.let { throw it }; super.close() }
        }
        private fun input(name: String) = object : ByteArrayInputStream(byteArrayOf()) {
            override fun close() { closed += name; super.close() }
        }
        private val input = input("input")
        private val errorInput = input("error")
        private val handle = object : ProcessHandle {
            override fun pid() = 9_000_000_001L
            override fun parent(): Optional<ProcessHandle> = Optional.empty()
            override fun children(): Stream<ProcessHandle> = Stream.empty()
            override fun descendants(): Stream<ProcessHandle> { beforeEnumeration(); return Stream.empty() }
            override fun info(): ProcessHandle.Info = error("no host process metadata")
            override fun onExit(): CompletableFuture<ProcessHandle> = error("already absent native handle needs no wait")
            override fun supportsNormalTermination() = true
            override fun destroy(): Boolean = error("already absent native handle needs no signal")
            override fun destroyForcibly(): Boolean = error("already absent native handle needs no signal")
            override fun isAlive() = false
            override fun compareTo(other: ProcessHandle) = pid().compareTo(other.pid())
        }
        override fun getOutputStream() = output
        override fun getInputStream() = input
        override fun getErrorStream() = errorInput
        override fun toHandle() = handle
        override fun isAlive() = !acknowledged
        override fun exitValue(): Int = if (acknowledged) 0 else throw IllegalThreadStateException("acknowledgement pending")
        override fun waitFor(): Int = error("unbounded Process wait is forbidden")
        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
            assertEquals(TimeUnit.NANOSECONDS, unit)
            assertTrue(timeout in 1..FORCED_ALLOWANCE)
            assertFalse(Thread.currentThread().isInterrupted, "entry interruption must be cleared for cleanup")
            waits += timeout
            return when (outcome) {
                WaitOutcome.ACKNOWLEDGED -> { acknowledged = true; true }
                WaitOutcome.TIMEOUT -> false
                WaitOutcome.INTERRUPTED -> if (!interruptionDelivered) {
                    interruptionDelivered = true
                    throw interruption
                } else {
                    acknowledged = true
                    true
                }
            }
        }
        override fun destroy(): Unit = error("already absent native handle needs no signal")
        fun assertStreamsClosed() { assertEquals(listOf("output", "input", "error"), closed) }
    }

    companion object {
        private val FORCED_ALLOWANCE = TimeUnit.SECONDS.toNanos(5)
        private val stopLate = Class.forName("decompengine.project.ArchivalReconstructionKt")
            .getDeclaredMethod(
                "stopLateExportProcess", Process::class.java, Duration::class.java,
                BoundedAnalysisProcessLaunch::class.java, List::class.java,
            ).apply { isAccessible = true }
        private fun cleanup(process: Process) =
            cleanup(process, BoundedAnalysisProcessLaunch(Executor(Runnable::run)))
        private fun cleanup(process: Process, owner: BoundedAnalysisProcessLaunch) {
            try { stopLate.invoke(null, process, Duration.ZERO, owner, emptyList<java.nio.file.Path>()) }
            catch (failure: InvocationTargetException) { throw failure.targetException }
        }
    }
}
