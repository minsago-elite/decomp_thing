package decompengine.web

/**
 * Admitted-request accounting for a bounded shutdown drain. Not synchronized: every call must hold the owning
 * server's lifecycle lock. Admission is closed while draining, so the active set only shrinks.
 *
 * Requests get the request deadline. If at that deadline every remaining request was inside its post-response
 * audit append, the drain extends once to the audit deadline. That decision is frozen at the first observation
 * past the request deadline, and every transition observes before applying itself, so the frozen value is the
 * state at the deadline: an ordinary request that reaches its append later never earns the audit bound, and an
 * audit request that left its append and is unwinding keeps it.
 */
internal class WebRequestDrain(private val clock: () -> Long = System::nanoTime) {
    enum class Outcome { DRAINED, AUDIT_PENDING, ACTIVE }

    /** Admitted requests, including those inside their post-response audit append. */
    var active = 0
        private set
    private var audits = 0
    private var draining = false
    private var requestDeadline = 0L
    private var auditDeadline = 0L
    private var auditExtension: Boolean? = null

    fun admit() { active++ }
    fun exitRequest() { observe(); active-- }
    fun enterAudit() { observe(); audits++ }
    fun exitAudit() { observe(); audits-- }

    /**
     * Starts the drain once. Its deadlines are measured from this call, made under the caller's lock, so
     * observation is enabled atomically with them; no transition can slip past an earlier sampled start.
     * Overlapping and later callers share the same deadlines and decision: it is never reset. The audit
     * timeout is at least the request timeout.
     */
    fun begin(requestTimeoutNanos: Long, auditTimeoutNanos: Long) {
        if (draining) return
        val now = clock()
        requestDeadline = now + requestTimeoutNanos
        auditDeadline = now + maxOf(requestTimeoutNanos, auditTimeoutNanos)
        auditExtension = null
        draining = true
    }

    private fun observe() {
        if (draining && auditExtension == null && clock() - requestDeadline >= 0) auditExtension = active > 0 && audits == active
    }

    /** The outcome once decided, or null with [waitNanos] to wait before deciding again. */
    fun decide(): Outcome? {
        if (active == 0) return Outcome.DRAINED
        observe()
        return when (auditExtension) {
            null -> null
            false -> Outcome.ACTIVE
            true -> if (clock() - auditDeadline >= 0) Outcome.AUDIT_PENDING else null
        }
    }

    /** Whether the drain extended to the audit deadline: only audit appends remained at the request deadline. */
    val auditExtended: Boolean get() = auditExtension == true

    /** Nanoseconds until the next deadline that can change [decide]. */
    fun waitNanos(): Long = (if (auditExtension == true) auditDeadline else requestDeadline) - clock()
}
