package decompengine.builtin.provider

import decompengine.chatgpt.ChatGptDeadline
import decompengine.chatgpt.ChatGptOperationFence
import java.io.Closeable

/** Independent TEST authority only. No A run export, credential authority, or production factory. */
internal class PlanHttpTestContextV1(val deadline: ChatGptDeadline, val fence: ChatGptOperationFence,
    val entityLimit: Long, val requestLimit: Int, val idleNanos: Long = 10_000_000_000L) {
    init {
        planHttpRequire(entityLimit in 0..Int.MAX_VALUE.toLong() && requestLimit >= 0)
        planHttpRequire(idleNanos in 1..600_000_000_000L)
    }
}
internal enum class PlanHttpActionV1 { ACQUIRE, HEADER_WRITE, BODY_WRITE, READ }
/** Synthetic hook, always outside the process monitor. Production final owned-action gate is C4b. */
internal fun interface PlanHttpTestGateV1 { fun before(action: PlanHttpActionV1) }
internal data class PlanHttpTransferV1(val headerPossiblySent: Boolean, val bodyBytesOffered: Long,
    val bodyBytesReturned: Long, val entityBytesObserved: Long, val entityBytesCopiedToOwner: Long,
    val framingBytesObserved: Long, val ioTasksExited: Long, val stopTasksExited: Long,
    val retained: Boolean, val failure: Boolean, val closeFailure: Boolean)
internal enum class PlanHttpCloseV1 { RETAINED, ACKNOWLEDGED, SUCCEEDED, FAILED }
internal sealed interface PlanHttpHeaderStepV1 {
    data object Pending : PlanHttpHeaderStepV1
    class Ready(val headers: PlanHttpHeadersV1) : PlanHttpHeaderStepV1
}

/** All mutable predicates below use one trusted private monitor; no socket/gate/owner callbacks do. */
internal class ChatGptPlanTransportLifetimeV1 private constructor(
    private val context: PlanHttpTestContextV1, private val gate: PlanHttpTestGateV1,
    private val slot: Int,
) {
    private enum class Job { ACQUIRE, HEADERS, READ }
    private var job: Job? = null
    private var ioActive = true // reserves initialization before ANY helper/allocation
    private var stopActive = false
    private var stopQueued = false
    private var startReady = false
    private var stopped = false
    private var failed = false
    private var closeFailed = false
    private var acknowledged = false
    private var ackInTime = false
    private var candidate = false
    private var consumer = false
    private var stopWindow: Window? = null
    private var ioExited = 0L
    private var stopExited = 0L
    private var arrivals = 0L
    private var copies = 0L
    private var framing = 0L
    private var offered = 0L
    private var returned = 0L
    private var headerSent = false
    private var lastArrival = context.deadline.clock.readNanos()
    private var headersStarted = false
    private var headerValue: PlanHttpHeadersV1? = null
    private var readDemand = 0
    private var readResult: Int? = null
    private val handles = arrayOfNulls<Closeable>(2)
    private val closeDone = BooleanArray(2)
    private var arena: PlanHttpArenasV1? = null
    private var parser: ChatGptPlanHttp1FramingV1? = null
    private var acquisition: (() -> Unit)? = null
    private var finalArenaFacts: List<Int> = emptyList()
    private var maxRequestedWait = 0L
    private var waitAdmissions = 0L
    private val waitAudit = LongArray(8 * 6) // bounded diagnostic ring; no callback/queue per wait

    private class Window(val deadline: ChatGptDeadline, requested: Long, private val origin: Long = System.nanoTime()) {
        private val maximum = requested.coerceIn(0, 250_000_000L)
        private val clockEntry = deadline.clock.readNanos()
        private var allowance = maximum
        private var cutoff = deadline.capAt(clockEntry, maximum)
        fun intersect(other: Window) {
            // Preserve the original root identity and BOTH method-entry clock domains.
            cutoff = cutoff.capAt(other.clockEntry, other.maximum)
            val offset = other.origin - origin // signed monotonic wrap is intentional
            if (offset in -250_000_000L..250_000_000L)
                allowance = minOf(allowance, (offset + other.allowance).coerceAtLeast(0))
            else if (offset < 0) allowance = 0
        }
        fun remaining(): Long {
            val elapsed = System.nanoTime() - origin
            return if (elapsed < 0) 0 else minOf(cutoff.remainingNanos(), (allowance - elapsed).coerceAtLeast(0))
        }
    }
    private fun authorityLive(): Boolean = !failed && !context.fence.isCancelled() && context.deadline.remainingNanos() > 0
    private fun live(): Boolean {
        val idle = context.deadline.clock.readNanos() - lastArrival
        return authorityLive() && idle in 0 until context.idleNanos
    }
    private fun failLocked() { failed = true; stopLocked() }
    private fun checkLocked() { if (stopped || !live()) { failLocked(); throw PlanHttpBoundaryV1() } }
    private fun stopLocked(entry: Window? = null) {
        if (!stopped) {
            // Capture the first cutoff BEFORE signaling. A first zero allowance is permanent.
            stopWindow = entry ?: Window(context.deadline, 250_000_000L)
            stopped = true
        } else if (entry != null) stopWindow!!.intersect(entry)
        stopQueued = true
        MON.notifyAll()
    }
    fun requestClose() {
        val entry = Window(context.deadline, 250_000_000L)
        synchronized(MON) { stopLocked(entry) }
    }
    fun cancel() = synchronized(MON) { context.fence.cancel(); failLocked() }
    fun transfer(): PlanHttpTransferV1 = synchronized(MON) {
        PlanHttpTransferV1(headerSent, offered, returned, arrivals, copies, framing, ioExited, stopExited,
            !acknowledged, failed, closeFailed)
    }
    internal fun waitFacts(): Pair<Long, Long> = synchronized(MON) { waitAdmissions to maxRequestedWait }
    internal fun waitSamples(): List<List<Long>> = synchronized(MON) {
        (0 until minOf(waitAdmissions, 8).toInt()).map { row -> (0 until 6).map { col -> waitAudit[row * 6 + col] } }
    }
    internal fun arenaFacts(): List<Int> = synchronized(MON) {
        val a = arena
        if (a == null) finalArenaFacts else listOf(PlanHttpArenasV1.FIXED_BYTES, a.headerHighWater, a.fieldHighWater, a.materializedAscii, a.maximumDemand)
    }
    /** Before every foreign helper. The same reservation remains live until its actual finally exit. */
    internal fun action(action: PlanHttpActionV1) {
        timeoutMillis() // floor check also applies to DNS/wrap/write, not only timed reads
        gate.before(action)
        timeoutMillis() // callback may have consumed all but a sub-millisecond remainder
    }
    internal fun timeoutMillis(): Int = synchronized(MON) {
        checkLocked()
        val idleLeft = context.idleNanos - (context.deadline.clock.readNanos() - lastArrival)
        val millis = minOf(context.deadline.remainingNanos(), idleLeft) / 1_000_000
        if (millis < 1) { failLocked(); throw PlanHttpBoundaryV1() }
        minOf(millis, Int.MAX_VALUE.toLong()).toInt()
    }
    /** Called immediately on helper return, even after stop; late handles join the SAME mailbox. */
    internal fun own(index: Int, handle: Closeable) = synchronized(MON) {
        planHttpRequire(index in 0..1 && handles[index] == null)
        handles[index] = handle
        if (stopped) { stopQueued = true; MON.notifyAll() }
        checkLocked()
    }
    internal fun headerOffered() = synchronized(MON) { timeoutMillis(); headerSent = true }
    internal fun bodyOffered(n: Int) = synchronized(MON) { timeoutMillis(); offered = Math.addExact(offered, n.toLong()) }
    internal fun bodyReturned(n: Int) = synchronized(MON) { returned = Math.addExact(returned, n.toLong()) }
    internal fun observed(n: Int) = synchronized(MON) {
        arrivals = Math.addExact(arrivals, n.toLong())
        lastArrival = context.deadline.clock.readNanos() // arrival before veto, including late/cap+1
    }
    internal fun framed(n: Int) = synchronized(MON) { framing = Math.addExact(framing, n.toLong()) }
    internal fun install(value: ChatGptPlanHttp1FramingV1) = synchronized(MON) { parser = value; checkLocked() }

    fun headers(maxWaitNanos: Long): PlanHttpHeaderStepV1 {
        val entry = Window(context.deadline, maxWaitNanos)
        return step {
            synchronized(MON) {
                checkLocked()
                if (!headersStarted) { headersStarted = true }
                scheduleHeadersLocked()
                waitLocked(entry) { (headerValue != null && !ioActive) || failed || stopped }
                checkLocked()
                if (ioActive) PlanHttpHeaderStepV1.Pending else headerValue?.let { PlanHttpHeaderStepV1.Ready(it) } ?: PlanHttpHeaderStepV1.Pending
            }
        }
    }
    private fun scheduleHeadersLocked() {
        if (startReady && headersStarted && headerValue == null && !ioActive && job == null && !stopped) {
            job = Job.HEADERS; MON.notifyAll()
        }
    }
    fun read(into: ByteArray, demand: Int, maxWaitNanos: Long): Int {
        val entry = Window(context.deadline, maxWaitNanos)
        return step {
            synchronized(MON) {
                if (demand !in 1..8192 || demand > into.size || headerValue == null) { failLocked(); throw PlanHttpBoundaryV1() }
                checkLocked()
                if (readDemand == 0) {
                    planHttpRequire(!ioActive && job == null)
                    readDemand = demand; job = Job.READ; MON.notifyAll()
                } else if (readDemand != demand) { failLocked(); throw PlanHttpBoundaryV1() }
                waitLocked(entry) { (readResult != null && !ioActive) || failed || stopped }
                checkLocked()
                if (ioActive) return@synchronized 0
                val n = readResult ?: return@synchronized 0
                if (n > 0) {
                    // No caller array is captured by a worker or retained across pending.
                    arena!!.io.copyInto(into, 0, 0, n)
                    copies = Math.addExact(copies, n.toLong())
                }
                readResult = null; readDemand = 0
                n
            }
        }
    }
    /** Lower candidate only: complete framing for catalog/error, or length check for validated SSE.
     * Caller-supplied terminal truth is NOT a C2/host/production response authority.
     */
    fun finish(validatedSseTerminal: Boolean = false) = step {
        synchronized(MON) {
            checkLocked()
            if (ioActive || job != null || readDemand != 0 || arrivals != copies) { failLocked(); throw PlanHttpBoundaryV1() }
            val p = parser ?: throw PlanHttpBoundaryV1()
            if (!p.completeFraming() && !(validatedSseTerminal && p.allowsEarlyTerminal() && headerValue!!.status == 200 && p.terminalLengthMatches())) {
                failLocked(); throw PlanHttpBoundaryV1()
            }
            candidate = true; stopLocked()
        }
    }
    fun closeStep(maxWaitNanos: Long): PlanHttpCloseV1 {
        val entry = Window(context.deadline, maxWaitNanos)
        return step {
            synchronized(MON) {
                stopLocked(entry)
                waitLocked(entry, true) { acknowledged }
                if (!acknowledged) PlanHttpCloseV1.RETAINED
                else if (failed || closeFailed || !authorityLive() || !ackInTime || stopWindow!!.remaining() == 0L) PlanHttpCloseV1.FAILED
                else if (candidate) PlanHttpCloseV1.SUCCEEDED else PlanHttpCloseV1.ACKNOWLEDGED
            }
        }
    }
    private inline fun <T> step(block: () -> T): T {
        synchronized(MON) {
            if (consumer) { failLocked(); throw PlanHttpBoundaryV1() }
            consumer = true
        }
        try { return block() } catch (_: Throwable) {
            synchronized(MON) { failLocked() }; throw PlanHttpBoundaryV1()
        } finally { synchronized(MON) { consumer = false; MON.notifyAll() } }
    }
    private fun waitLocked(call: Window, closing: Boolean = false, done: () -> Boolean) {
        while (!done()) {
            val callLeft = call.remaining()
            val originalLeft = context.deadline.remainingNanos()
            val authorityLeft = if (closing) stopWindow?.remaining() ?: 0 else if (live()) Long.MAX_VALUE else 0
            val remaining = minOf(callLeft, originalLeft, authorityLeft, 25_000_000L)
            if (remaining <= 0) return
            val row = (waitAdmissions % 8).toInt() * 6
            waitAudit[row] = System.nanoTime(); waitAudit[row + 1] = remaining
            waitAudit[row + 2] = originalLeft; waitAudit[row + 3] = callLeft
            waitAudit[row + 4] = authorityLeft; waitAudit[row + 5] = if (closing) 1 else 0
            waitAdmissions = Math.addExact(waitAdmissions, 1); maxRequestedWait = maxOf(maxRequestedWait, remaining)
            MON.wait(remaining / 1_000_000L, (remaining % 1_000_000L).toInt())
        }
    }
    private fun execute(job: Job) {
        synchronized(MON) { checkLocked() }
        when (job) {
            Job.ACQUIRE -> acquisition!!()
            Job.HEADERS -> {
                val h = parser!!.headers()
                synchronized(MON) { checkLocked(); headerValue = h }
            }
            Job.READ -> {
                val n = parser!!.read(readDemand)
                synchronized(MON) { checkLocked(); readResult = n }
            }
        }
    }
    private fun stopResources() {
        for (i in handles.indices) {
            val handle = synchronized(MON) { if (closeDone[i]) null else handles[i] }
            if (handle != null) {
                try {
                    handle.close() // only independent stopper lane, NEVER consumer/reaper
                    synchronized(MON) { closeDone[i] = true }
                } catch (_: Throwable) { synchronized(MON) { closeFailed = true; failed = true } }
            }
        }
    }
    private fun ackLocked() {
        if (!stopped || ioActive || stopActive || job != null || handles.indices.any { handles[it] != null && !closeDone[it] }) return
        // Actual runner has returned from task + finally. Current result consumer is not I/O.
        finalArenaFacts = arenaFacts()
        acquisition = null; parser = null; arena = null; headerValue = null
        readDemand = 0; readResult = null
        handles.fill(null); stopQueued = false
        acknowledged = true; ackInTime = stopWindow!!.remaining() > 0 && authorityLive()
        if (!ackInTime) failed = true
        SLOTS[slot] = null
        MON.notifyAll()
    }
    companion object {
        private val MON = Object()
        private val SLOTS = arrayOfNulls<ChatGptPlanTransportLifetimeV1>(8)
        private val LANES = arrayOfNulls<Thread>(17)
        private var highWater = 0
        private var shuttingDown = false
        private var shutdownWindow: Window? = null
        private var lanesStarted = false
        private fun lanesLocked() {
            if (lanesStarted) return
            lanesStarted = true
            try {
                for (i in SLOTS.indices) {
                    Thread({ ioLane(i) }, "plan-http-io-$i").apply { isDaemon = true; LANES[i * 2] = this; start() }
                    Thread({ stopLane(i) }, "plan-http-stop-$i").apply { isDaemon = true; LANES[i * 2 + 1] = this; start() }
                }
                Thread({ reap() }, "plan-http-reaper").apply { isDaemon = true; LANES[16] = this; start() }
            } catch (_: Throwable) {
                // Partial native thread initialization cannot authorize a smaller/unpaired service.
                shuttingDown = true
                throw PlanHttpBoundaryV1()
            }
        }
        internal fun reserve(context: PlanHttpTestContextV1, gate: PlanHttpTestGateV1,
            initialize: (ChatGptPlanTransportLifetimeV1, PlanHttpArenasV1) -> (() -> Unit)): ChatGptPlanTransportLifetimeV1 {
            val op = synchronized(MON) {
                planHttpRequire(!shuttingDown && !context.fence.isCancelled() && context.deadline.remainingNanos() > 0)
                val i = SLOTS.indexOfFirst { it == null }; planHttpRequire(i >= 0)
                lanesLocked()
                ChatGptPlanTransportLifetimeV1(context, gate, i).also { SLOTS[i] = it; highWater = maxOf(highWater, SLOTS.count { s -> s != null }) }
            }
            try {
                val a = PlanHttpArenasV1()
                val init = initialize(op, a) // bounded copies, outside monitor, reserved BEFORE invocation
                synchronized(MON) { op.arena = a; op.acquisition = init; op.ioActive = false; op.job = Job.ACQUIRE; MON.notifyAll() }
            } catch (_: Throwable) {
                synchronized(MON) { op.ioActive = false; op.failLocked(); op.ackLocked() }
                throw PlanHttpBoundaryV1()
            }
            return op
        }
        private fun ioLane(i: Int) {
            while (true) {
                val pair = synchronized(MON) {
                    while (SLOTS[i]?.job == null) MON.wait()
                    val op = SLOTS[i]!!; val j = op.job!!
                    op.job = null; op.ioActive = true
                    op to j
                }
                val (op, j) = pair
                try { op.execute(j) } catch (_: Throwable) { synchronized(MON) { op.failLocked() } }
                // Acknowledgment outside task and its finally; this persistent runner is now idle.
                synchronized(MON) {
                    op.ioActive = false; op.ioExited++
                    if (j == Job.ACQUIRE) { op.startReady = true; op.acquisition = null }
                    if (op.stopped) op.stopQueued = true else op.scheduleHeadersLocked()
                    op.ackLocked(); MON.notifyAll()
                }
            }
        }
        private fun stopLane(i: Int) {
            while (true) {
                val op = synchronized(MON) {
                    while (SLOTS[i]?.stopQueued != true) MON.wait()
                    SLOTS[i]!!.also { it.stopQueued = false; it.stopActive = true }
                }
                op.stopResources()
                synchronized(MON) { op.stopActive = false; op.stopExited++; op.ackLocked(); MON.notifyAll() }
            }
        }
        private fun reap() {
            synchronized(MON) {
                while (true) {
                    for (op in SLOTS) if (op != null && !op.stopped && !op.live()) op.failLocked()
                    MON.wait(5)
                }
            }
        }
        internal fun processFacts(): List<Int> = synchronized(MON) {
            listOf(SLOTS.count { it != null }, highWater, LANES.count { it?.isAlive == true },
                SLOTS.count { it?.ioActive == true }, SLOTS.count { it?.stopActive == true },
                SLOTS.count { it?.job != null }, SLOTS.count { it?.stopQueued == true })
        }
        /** One service allowance across all children and repeated shutdowns. Never replaces lanes. */
        internal fun shutdown() {
            val entry = System.nanoTime()
            synchronized(MON) {
                shuttingDown = true
                if (shutdownWindow == null) SLOTS.firstOrNull { it != null }?.let { shutdownWindow = Window(it.context.deadline, 250_000_000L, entry) }
                for (op in SLOTS) op?.stopLocked()
                while (SLOTS.any { it != null }) {
                    val n = minOf(shutdownWindow?.remaining() ?: 0, 25_000_000L)
                    if (n <= 0) return
                    MON.wait(n / 1_000_000, (n % 1_000_000).toInt())
                }
            }
        }
    }
}
