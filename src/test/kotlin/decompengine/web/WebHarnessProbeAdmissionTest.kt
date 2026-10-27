package decompengine.web

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class WebHarnessProbeAdmissionTest {
    @Test
    fun `expiry before callback entry refuses every late invocation`() {
        val admission = WebHarnessProbeAdmission()
        var calls = 0
        admission.abandon()
        admission.abandon()
        repeat(2) { assertNull(admission.tryRun { calls++; "late" }) }
        assertEquals(0, calls)
        assertFalse(admission.isRunning)
    }

    @Test
    fun `expiry after admission fences the probe until callback exit`() {
        val admission = WebHarnessProbeAdmission()
        val result = admission.tryRun {
            assertTrue(admission.isRunning)
            admission.abandon()
            assertTrue(admission.isRunning)
            assertNull(admission.tryRun { error("a second callback must not enter") })
            "complete"
        }
        assertEquals("complete", result)
        assertFalse(admission.isRunning)
        assertNull(admission.tryRun { error("a completed admission must not be reused") })
    }

    @Test
    fun `throwing admitted callbacks release ownership without permitting reuse`() {
        val admission = WebHarnessProbeAdmission()
        assertFailsWith<IllegalStateException> {
            admission.tryRun<String> { error("authored failure") }
        }
        assertFalse(admission.isRunning)
        admission.abandon()
        assertNull(admission.tryRun { error("a failed admission must not be reused") })
    }

    @Test
    fun `interrupted wait retains the abandoned probe and restores caller interruption`() {
        val calls = AtomicInteger()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val now = AtomicLong()
        val result = AtomicReference<String?>()
        val interrupted = AtomicBoolean()
        val projector = WebHarnessReadinessProjector(
            probe = {
                calls.incrementAndGet()
                entered.countDown()
                try {
                    while (release.count > 0) {
                        try { release.await() } catch (_: InterruptedException) { /* authored noncooperative callback */ }
                    }
                    WebHarnessReadiness("supported", null, "authored")
                } finally { finished.countDown() }
            },
            timeoutMillis = 5_000, ttlNanos = 1_000, nanoTime = now::get,
        )
        val caller = Thread({
            result.set(projector.current().reasonCode)
            interrupted.set(Thread.currentThread().isInterrupted)
        }, "readiness-interrupted-wait-control")
        try {
            caller.start()
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            caller.interrupt()
            caller.join(5_000)
            assertFalse(caller.isAlive)
            assertEquals("PROBE_FAILED", result.get())
            assertTrue(interrupted.get())
            repeat(2) {
                now.addAndGet(1_000)
                assertEquals("PROBE_TIMEOUT", projector.current().reasonCode)
            }
            assertEquals(1, calls.get(), "no replacement probe may enter while the abandoned callback remains active")
        } finally {
            release.countDown()
            caller.interrupt()
            caller.join(5_000)
            assertTrue(finished.await(5, TimeUnit.SECONDS))
            projector.close()
        }
    }
}
