package decompengine.chatgpt

import java.time.Duration
import java.util.concurrent.CancellationException
import java.util.concurrent.TimeoutException
import kotlin.test.*

class ChatGptStoreOperationTest {
    @Test fun probesCannotExtendOrExpireTrustedTime() {
        val c = ChatGptDeadlineClock.controlled(); var probe = Long.MAX_VALUE
        val op = ChatGptStoreOperation.createControlled(Duration.ofNanos(100), { false }, c) { probe }
        assertEquals(100, op.remainingNanos()); probe = Long.MIN_VALUE
        assertEquals(100, op.remainingNanos()); c.advanceNanos(100)
        assertFailsWith<TimeoutException> { op.check() }
    }
    @Test fun childCapturePrecedesCallbacksAndSharesFence() {
        val c = ChatGptDeadlineClock.controlled(); var armed = false
        val op = ChatGptStoreOperation.createControlled(Duration.ofNanos(1_000), { if (armed) c.advanceNanos(90); false }, c) { 0 }
        armed = true
        val child = op.capped(Duration.ofNanos(100))
        assertSame(op.fence, child.fence); assertTrue(child.deadline.isWithin(op.deadline))
        assertEquals(10, child.deadline.remainingNanos())
        armed = false; c.advanceNanos(10)
        assertFailsWith<TimeoutException> { child.check() }
        assertFailsWith<TimeoutException> { op.check() }
    }
    @Test fun vetoAndFailureLatchWithFixedDiagnostics() {
        val c = ChatGptDeadlineClock.controlled(); var veto = true
        val op = ChatGptStoreOperation.createControlled(Duration.ofSeconds(1), { veto }, c) { 0 }
        assertFailsWith<CancellationException> { op.check() }; veto = false
        assertFailsWith<CancellationException> { op.check() }
        val bad = ChatGptStoreOperation.createControlled(Duration.ofSeconds(1), { false }, c) { error("private probe detail") }
        val e = assertFailsWith<IllegalStateException> { bad.check() }
        assertNull(e.cause); assertTrue(e.suppressed.isEmpty()); assertFalse(e.message!!.contains("private"))
        assertTrue(bad.fence.isCancelled())
    }
    @Test fun callbackTimeIsChargedAndLegacyProbeIsNotAuthority() {
        val c = ChatGptDeadlineClock.controlled()
        val op = ChatGptStoreOperation.createControlled(Duration.ofNanos(100), { c.advanceNanos(100); false }, c) { 0 }
        assertFailsWith<TimeoutException> { op.check() }
        val legacy = ChatGptStoreOperation.create(Duration.ofSeconds(1), { false }) { Long.MIN_VALUE }
        assertSame(ChatGptDeadlineClock.SYSTEM, legacy.deadline.clock); legacy.check()
    }
    @Test fun fromDeadlineKeepsExactCapabilityAndCancellation() {
        val c = ChatGptDeadlineClock.controlled(); val d = ChatGptDeadline.start(c, 100); val f = ChatGptOperationFence()
        val op = ChatGptStoreOperation.fromDeadline(d, f) { false }
        assertSame(d, op.deadline); assertEquals(100, op.remainingNanos())
        f.cancel(); assertFailsWith<CancellationException> { op.check() }
    }
}
