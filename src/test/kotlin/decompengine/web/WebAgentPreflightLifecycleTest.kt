package decompengine.web

import decompengine.agent.AgentCancellation
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Callback/latch data only: no HTTP server, ACP harness, provider, process or host fixture. */
class WebAgentPreflightLifecycleTest {
    @Test
    fun `shutdown signals cancellation and waits for callback cleanup before returning`() {
        exerciseClose(interruptedCaller = false)
    }

    @Test
    fun `interrupted shutdown drains callback cleanup and restores caller interruption`() {
        exerciseClose(interruptedCaller = true)
    }

    private fun exerciseClose(interruptedCaller: Boolean) {
        val entered = CountDownLatch(1)
        val cleanup = CountDownLatch(1)
        val closerStarted = CountDownLatch(1)
        val returned = CountDownLatch(1)
        val cancellation = AtomicReference<AgentCancellation>()
        val restoredInterrupt = AtomicBoolean(false)
        val closeFailure = AtomicReference<Throwable?>()
        val preflight = WebAgentPreflight { signal ->
            cancellation.set(signal)
            entered.countDown()
            cleanup.await()
        }
        val closer = Thread({
            try {
                if (interruptedCaller) Thread.currentThread().interrupt()
                closerStarted.countDown()
                preflight.close()
                restoredInterrupt.set(Thread.currentThread().isInterrupted)
            } catch (failure: Throwable) {
                closeFailure.set(failure)
            } finally { returned.countDown() }
        }, "preflight-callback-close-control")
        try {
            assertTrue(preflight.start() is WebAgentPreflight.Start.Started)
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            preflight.requestStop()
            assertTrue(cancellation.get().isCancellationRequested())
            assertEquals(WebAgentPreflight.Start.Closed, preflight.start())
            closer.start()
            assertTrue(closerStarted.await(5, TimeUnit.SECONDS))
            assertFalse(returned.await(100, TimeUnit.MILLISECONDS), "close must await callback cleanup")
            assertEquals("inspecting", preflight.snapshot().status)
            cleanup.countDown()
            assertTrue(returned.await(5, TimeUnit.SECONDS))
            assertEquals(null, closeFailure.get())
            assertEquals(interruptedCaller, restoredInterrupt.get())
            assertEquals("cancelled", preflight.snapshot().status)
            assertEquals(WebAgentPreflight.Start.Closed, preflight.start())
        } finally {
            cleanup.countDown()
            preflight.close()
            if (closer.state != Thread.State.NEW) closer.join(5000)
        }
    }
}
