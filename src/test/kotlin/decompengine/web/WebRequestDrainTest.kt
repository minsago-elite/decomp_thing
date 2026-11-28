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
        drain.begin(requestDeadline = 100, auditDeadline = 1000)
        assertNull(drain.decide())
        // The stop thread's timed wait expired, but the request transitions before stop observes the deadline.
        now = 150
        drain.enterAudit()
        assertEquals(WebRequestDrain.Outcome.ACTIVE, drain.decide())
    }

    @Test fun `a request in its append at the request deadline keeps the audit bound while it unwinds`() {
        val drain = drain()
        drain.begin(requestDeadline = 100, auditDeadline = 1000)
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
        drain.begin(requestDeadline = 100, auditDeadline = 1000)
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
        drain.begin(requestDeadline = 100, auditDeadline = 40)
        drain.enterAudit()
        now = 100
        assertEquals(WebRequestDrain.Outcome.AUDIT_PENDING, drain.decide())
    }
}
