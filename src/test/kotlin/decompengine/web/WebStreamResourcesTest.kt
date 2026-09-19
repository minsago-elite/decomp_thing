package decompengine.web

import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WebStreamResourcesTest {
    private fun session(id: String) = AuthorizedWebSession(id, Instant.MAX, Instant.MAX)
    private fun await(latch: CountDownLatch) = assertTrue(latch.await(5, TimeUnit.SECONDS), "Fixture deadline exceeded")
    private fun released(resources: WebStreamResources, expected: Int = 0) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (resources.snapshot().active != expected && System.nanoTime() < deadline) Thread.sleep(5)
        assertEquals(expected, resources.snapshot().active)
    }
    private fun deny(code: String, operation: () -> Unit) = assertEquals(code, assertFailsWith<WebAccessDenied>(block = operation).code)
    private fun uninterruptible(latch: CountDownLatch) {
        while (latch.count > 0) try { latch.await() } catch (_: InterruptedException) { }
    }

    @Test fun `global and session admission limits leave rejected connections with the caller`() {
        val resources = WebStreamResources(maximumConnections = 3)
        val finish = CountDownLatch(1)
        val started = CountDownLatch(3)
        val closed = AtomicInteger()
        val rejected = AtomicInteger()
        try {
            for (owner in listOf("a", "a", "b")) resources.submit(session(owner), AutoCloseable { closed.incrementAndGet() }) {
                started.countDown(); finish.await()
            }
            await(started)
            deny("STREAM_LIMIT") { resources.submit(session("a"), AutoCloseable { rejected.incrementAndGet() }) { rejected.incrementAndGet() } }
            deny("STREAM_LIMIT") { resources.submit(session("c"), AutoCloseable { rejected.incrementAndGet() }) { rejected.incrementAndGet() } }
            assertEquals(3, resources.snapshot().active)
            assertEquals(0, rejected.get())
            finish.countDown(); released(resources)
            assertEquals(3, closed.get())
        } finally { finish.countDown(); assertTrue(resources.shutdown()) }
    }

    @Test fun `simultaneous sessions cannot overbook the global connection budget`() {
        val resources = WebStreamResources()
        val callers = java.util.concurrent.Executors.newFixedThreadPool(8)
        val finish = CountDownLatch(1)
        try {
            val admissions = (0 until 32).map { owner -> callers.submit<Boolean> {
                try {
                    resources.submit(session("owner-$owner"), AutoCloseable {}) { finish.await() }
                    true
                } catch (failure: WebAccessDenied) {
                    assertEquals("STREAM_LIMIT", failure.code)
                    false
                }
            } }
            assertEquals(16, admissions.count { it.get(5, TimeUnit.SECONDS) })
            assertEquals(16, resources.snapshot().active)
        } finally { finish.countDown(); callers.shutdownNow(); assertTrue(resources.shutdown()) }
    }

    @Test fun `per session limit applies before global capacity is exhausted`() {
        val resources = WebStreamResources(maximumConnections = 4)
        val finish = CountDownLatch(1)
        try {
            repeat(2) { resources.submit(session("same"), AutoCloseable {}) { finish.await() } }
            deny("STREAM_LIMIT") { resources.submit(session("same"), AutoCloseable {}) {} }
            resources.submit(session("different"), AutoCloseable {}) { finish.await() }
            assertEquals(3, resources.snapshot().active)
        } finally { finish.countDown(); assertTrue(resources.shutdown()) }
    }

    @Test fun `cancellation keeps reservation until an uncooperative writer actually exits`() {
        val resources = WebStreamResources(maximumConnections = 1)
        val started = CountDownLatch(1); val finish = CountDownLatch(1); val closed = CountDownLatch(1)
        try {
            val lease = resources.submit(session("a"), AutoCloseable { closed.countDown() }) {
                started.countDown(); uninterruptible(finish)
            }
            await(started); lease.close(); await(closed)
            deny("STREAM_LIMIT") { resources.submit(session("b"), AutoCloseable {}) {} }
            assertEquals(1, resources.snapshot().active)
            finish.countDown(); released(resources)
            resources.submit(session("b"), AutoCloseable {}) {}
            released(resources)
        } finally { finish.countDown(); assertTrue(resources.shutdown()) }
    }

    @Test fun `blocked cleanup retains its reservation without blocking another connection cleanup`() {
        val resources = WebStreamResources(maximumConnections = 2)
        val closing = CountDownLatch(1); val finish = CountDownLatch(1); val otherClosed = CountDownLatch(1)
        try {
            resources.submit(session("a"), AutoCloseable { closing.countDown(); uninterruptible(finish) }) {}
            await(closing)
            resources.submit(session("b"), AutoCloseable { otherClosed.countDown() }) {}
            await(otherClosed); released(resources, 1)
            finish.countDown(); released(resources)
        } finally { finish.countDown(); assertTrue(resources.shutdown()) }
    }

    @Test fun `deadline interrupts work and closes the connection exactly once`() {
        val resources = WebStreamResources(lifetimeMs = 1000)
        val started = CountDownLatch(1); val interrupted = CountDownLatch(1); val closed = AtomicInteger()
        try {
            val lease = resources.submit(session("a"), AutoCloseable { closed.incrementAndGet() }) {
                started.countDown()
                try { CountDownLatch(1).await() } catch (_: InterruptedException) { interrupted.countDown() }
            }
            await(started); await(interrupted); released(resources)
            repeat(5) { lease.close() }
            assertEquals(1, closed.get())
        } finally { assertTrue(resources.shutdown()) }
    }

    @Test fun `work failure closes once and permits replacement without exposing diagnostics`() {
        val resources = WebStreamResources(maximumConnections = 1)
        val closed = AtomicInteger()
        try {
            resources.submit(session("a"), AutoCloseable { closed.incrementAndGet() }) { error("PRIVATE_STREAM_FIXTURE") }
            released(resources)
            resources.submit(session("b"), AutoCloseable { closed.incrementAndGet() }) {}
            released(resources)
            assertEquals(2, closed.get())
            assertEquals(0, resources.snapshot().cleanupFailures)
        } finally { assertTrue(resources.shutdown()) }
    }

    @Test fun `cleanup failure retains capacity and cannot report a clean shutdown`() {
        val resources = WebStreamResources(maximumConnections = 1)
        val attempted = CountDownLatch(1)
        resources.submit(session("a"), AutoCloseable { attempted.countDown(); error("PRIVATE_CLOSE_FIXTURE") }) {}
        await(attempted)
        assertFalse(resources.shutdown())
        assertEquals(1, resources.snapshot().active)
        assertEquals(1, resources.snapshot().cleanupFailures)
        deny("STREAMS_DRAINING") { resources.submit(session("b"), AutoCloseable {}) {} }
    }

    @Test fun `shutdown deadline is bounded and late completion can be observed without restarting work`() {
        val resources = WebStreamResources(shutdownTimeoutMs = 20)
        val started = CountDownLatch(1); val finish = CountDownLatch(1); val closed = CountDownLatch(1)
        try {
            resources.submit(session("a"), AutoCloseable { closed.countDown() }) {
                started.countDown(); uninterruptible(finish)
            }
            await(started)
            val before = System.nanoTime()
            assertFalse(resources.shutdown())
            assertTrue(System.nanoTime() - before < TimeUnit.SECONDS.toNanos(2))
            await(closed)
            assertEquals(1, resources.snapshot().active)
            deny("STREAMS_DRAINING") { resources.submit(session("b"), AutoCloseable {}) {} }
            finish.countDown(); released(resources)
            assertTrue(resources.shutdown())
        } finally { finish.countDown(); resources.shutdown() }
    }
}
