package decompengine.analysis

import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.*

class AnalysisDeadlineTest {
    @Test fun `callback reaching dispatch after normal return cannot interrupt the reused caller`() {
        val timer = ControlledWatchdog()
        val result = deadline().enforceDuring("normal phase", timer::schedule) { 42 }
        assertEquals(42, result)
        assertTrue(timer.cancellationRequested.get())
        assertTrue(timer.allowanceNanos in 1..TimeUnit.SECONDS.toNanos(10))
        timer.fire()
        assertFalse(Thread.currentThread().isInterrupted)
    }

    @Test fun `claimed watchdog delivery retires before timeout handling and caller reuse`() {
        val timer = ControlledWatchdog()
        val operationReturned = CountDownLatch(1)
        val deliveryEntered = CountDownLatch(1)
        val allowDelivery = CountDownLatch(1)
        val scopeExited = CountDownLatch(1)
        val nextWorkEntered = CountDownLatch(1)
        val allowNextWork = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>()
        val nextFailure = AtomicReference<Throwable?>()
        val leakedFlag = AtomicBoolean(false)
        val caller = object : Thread("deadline-retirement-caller") {
            override fun interrupt() {
                deliveryEntered.countDown()
                check(allowDelivery.await(5, TimeUnit.SECONDS)) { "controlled interrupt delivery was not released" }
                super.interrupt()
            }
            override fun run() {
                try {
                    deadline().enforceDuring("claimed phase", timer::schedule) {
                        assertTrue(deliveryEntered.await(5, TimeUnit.SECONDS))
                        operationReturned.countDown()
                    }
                } catch (caught: Throwable) { failure.set(caught) }
                finally { scopeExited.countDown() }
                leakedFlag.set(isInterrupted)
                nextWorkEntered.countDown()
                try { assertTrue(allowNextWork.await(5, TimeUnit.SECONDS)) }
                catch (caught: Throwable) { nextFailure.set(caught) }
            }
        }
        caller.isDaemon = true
        val watchdog = Thread({ timer.fire() }, "deadline-retirement-watchdog").apply { isDaemon = true }
        try {
            caller.start()
            assertTrue(timer.scheduled.await(5, TimeUnit.SECONDS))
            watchdog.start()
            assertTrue(deliveryEntered.await(5, TimeUnit.SECONDS))
            assertTrue(operationReturned.await(5, TimeUnit.SECONDS))
            // Pure JVM thread state distinguishes dispatch retirement from a caller already reused.
            val waitingStarted = System.nanoTime()
            while (scopeExited.count != 0L && caller.state != Thread.State.BLOCKED &&
                System.nanoTime() - waitingStarted < TimeUnit.SECONDS.toNanos(5)) {
                Thread.sleep(1)
            }
            assertEquals(Thread.State.BLOCKED, caller.state, "caller must retire the in-progress delivery")
            assertEquals(1L, scopeExited.count, "scope returned before interrupt dispatch completed")
            assertFalse(timer.cancellationRequested.get(), "timer cancellation cannot substitute for delivery retirement")
            allowDelivery.countDown()
            assertTrue(nextWorkEntered.await(5, TimeUnit.SECONDS))
            assertIs<GhidraAnalysisException>(failure.get())
            assertFalse(leakedFlag.get(), "owned watchdog signal escaped into subsequent work")
            // Even a callback that survives timer cancellation cannot dispatch after retirement.
            timer.fire()
            allowNextWork.countDown()
            caller.join(5_000); watchdog.join(5_000)
            assertFalse(caller.isAlive); assertFalse(watchdog.isAlive)
            assertNull(nextFailure.get())
        } finally {
            allowDelivery.countDown(); allowNextWork.countDown()
            caller.join(5_000)
            if (watchdog.state != Thread.State.NEW) watchdog.join(5_000)
        }
    }

    @Test fun `exceptional return retires callback and preserves the original failure`() {
        val timer = ControlledWatchdog()
        val expected = IOException("authored operation failure")
        val actual = assertFailsWith<IOException> {
            deadline().enforceDuring("failed phase", timer::schedule) { throw expected }
        }
        assertSame(expected, actual)
        assertTrue(timer.cancellationRequested.get())
        timer.fire()
        assertFalse(Thread.currentThread().isInterrupted)
    }

    @Test fun `external cancellation without watchdog delivery preserves failure and interrupt state`() {
        for (consumeFlag in listOf(false, true)) {
            val timer = ControlledWatchdog()
            val expected = InterruptedException("independent caller cancellation")
            try {
                val actual = assertFailsWith<InterruptedException> {
                    deadline().enforceDuring("externally cancelled phase", timer::schedule) {
                        Thread.currentThread().interrupt()
                        if (consumeFlag) Thread.interrupted()
                        throw expected
                    }
                }
                assertSame(expected, actual)
                assertEquals(!consumeFlag, Thread.currentThread().isInterrupted)
                timer.fire()
                assertEquals(!consumeFlag, Thread.currentThread().isInterrupted)
                assertTrue(timer.cancellationRequested.get())
            } finally { Thread.interrupted() }
        }
    }

    @Test fun `fatal operation still retires delivery without replacing the original error`() {
        val timer = ControlledWatchdog()
        val expected = AssertionError("authored fatal failure")
        val actual = assertFailsWith<AssertionError> {
            deadline().enforceDuring("fatal phase", timer::schedule) { throw expected }
        }
        assertSame(expected, actual)
        assertTrue(timer.cancellationRequested.get())
        timer.fire()
        assertFalse(Thread.currentThread().isInterrupted)
    }

    @Test fun `nested deadline passes only the tighter inherited allowance to its watchdog`() {
        val parent = AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(5), "parent allowance")
        val child = AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(10), "child allowance", parent)
        val before = parent.remainingNanos("before child fixture")
        val timer = ControlledWatchdog()
        assertEquals(17, child.enforceDuring("child phase", timer::schedule) { 17 })
        assertTrue(timer.allowanceNanos in 1..before)
        assertEquals(10_000L, child.maximumMillis)
        assertEquals(5_000L, child.parentMaximumMillis)
        timer.fire()
        assertFalse(Thread.currentThread().isInterrupted)
    }

    @Test fun `real watchdog interrupts a blocked synchronous phase and leaves the caller reusable`() {
        val admitted = AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(1), "real fixture allowance")
        val entered = AtomicBoolean(false)
        val failure = assertFailsWith<GhidraAnalysisException> {
            admitted.enforceDuring("blocked phase") {
                entered.set(true)
                CountDownLatch(1).await()
            }
        }
        assertTrue(entered.get())
        assertTrue(failure.message.orEmpty().contains("real fixture allowance exceeded 1000 milliseconds"))
        assertFalse(Thread.currentThread().isInterrupted)
        assertEquals(73, deadline().enforceDuring("subsequent phase") { 73 })
    }

    private class ControlledWatchdog {
        val scheduled = CountDownLatch(1)
        val cancellationRequested = AtomicBoolean(false)
        private val action = AtomicReference<Runnable?>()
        @Volatile var allowanceNanos: Long = 0
            private set
        fun schedule(action: Runnable, allowance: Long): AutoCloseable {
            check(this.action.compareAndSet(null, action))
            allowanceNanos = allowance
            scheduled.countDown()
            // Simulate cancellation that cannot stop an already-entered scheduled callback.
            return AutoCloseable { cancellationRequested.set(true) }
        }
        fun fire() { checkNotNull(action.get()).run() }
    }

    private fun deadline() = AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(10), "controlled fixture allowance")
}
