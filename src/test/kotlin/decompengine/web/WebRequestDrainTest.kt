package decompengine.web

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** Deterministic drain decisions under a test clock; the server calls these under its lifecycle lock. */
class WebRequestDrainTest {
    private var now = 0L
    private fun drain() = WebRequestDrain { now }.apply { admit() }

    @Test fun `an ordinary request reaching its append after an unobserved request deadline does not earn the audit bound`() {
        val drain = drain()
        drain.begin(requestTimeoutNanos = 100, auditTimeoutNanos = 1000)
        assertNull(drain.decide())
        // The stop thread's timed wait expired, but the request transitions before stop observes the deadline.
        now = 150
        drain.enterAudit()
        assertEquals(WebRequestDrain.Outcome.ACTIVE, drain.decide())
    }

    @Test fun `a request in its append at the request deadline keeps the audit bound while it unwinds`() {
        val drain = drain()
        drain.begin(requestTimeoutNanos = 100, auditTimeoutNanos = 1000)
        now = 50
        drain.enterAudit()
        now = 150
        assertNull(drain.decide())
        assertEquals(850, drain.waitNanos())
        // The append finishes; the request is still unwinding toward its exit.
        now = 200
        drain.exitAudit()
        assertNull(drain.decide())
        now = 1000
        assertEquals(WebRequestDrain.Outcome.AUDIT_PENDING, drain.decide())
    }

    @Test fun `the audit decision is frozen by the first transition past the deadline, not by stop observing it`() {
        val drain = drain()
        drain.begin(requestTimeoutNanos = 100, auditTimeoutNanos = 1000)
        now = 50
        drain.enterAudit()
        // The append ends after the deadline but before stop reacquires its monitor.
        now = 120
        drain.exitAudit()
        now = 130
        assertNull(drain.decide(), "the request was in its append at the deadline")
        drain.exitRequest()
        assertEquals(WebRequestDrain.Outcome.DRAINED, drain.decide())
    }

    @Test fun `the audit deadline is never earlier than the request deadline`() {
        val drain = drain()
        drain.begin(requestTimeoutNanos = 100, auditTimeoutNanos = 40)
        drain.enterAudit()
        now = 100
        assertEquals(WebRequestDrain.Outcome.AUDIT_PENDING, drain.decide())
    }

    @Test fun `deadlines start when the drain begins, so transitions before a stalled start cannot be misjudged`() {
        val drain = drain()
        // stop sampled nothing early: it stalls before taking the lock while the request still works normally.
        now = 300
        drain.begin(requestTimeoutNanos = 100, auditTimeoutNanos = 1000)
        assertNull(drain.decide())
        assertEquals(100, drain.waitNanos(), "the request bound is measured from the drain start")
        // Reaching the append before the real deadline earns the audit bound.
        now = 350
        drain.enterAudit()
        now = 400
        assertNull(drain.decide())
        assertEquals(900, drain.waitNanos())
        now = 1300
        assertEquals(WebRequestDrain.Outcome.AUDIT_PENDING, drain.decide())
    }

    @Test fun `overlapping and later drains share one deadline and decision`() {
        val drain = drain()
        drain.begin(requestTimeoutNanos = 100, auditTimeoutNanos = 1000)
        now = 50
        drain.enterAudit()
        now = 150
        assertNull(drain.decide())
        // The append ends while the request is still active (unwinding); a reset decision would now be ACTIVE.
        now = 200
        drain.exitAudit()
        // An overlapping stop call begins while the first waits: neither the deadline nor the decision is reset.
        now = 600
        drain.begin(requestTimeoutNanos = 100, auditTimeoutNanos = 1000)
        assertNull(drain.decide())
        assertEquals(400, drain.waitNanos())
        now = 1000
        assertEquals(WebRequestDrain.Outcome.AUDIT_PENDING, drain.decide())
        // A later stop call shares the same outcome.
        now = 1500
        drain.begin(requestTimeoutNanos = 100, auditTimeoutNanos = 1000)
        assertEquals(WebRequestDrain.Outcome.AUDIT_PENDING, drain.decide())
    }
}
