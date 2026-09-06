package decompengine.web

import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** Owns bounded stream work independently of HTTP and workflow executors.
 * The router must authenticate before admission. Rejection leaves connection ownership with it.
 * Accepted slots remain charged until both work and successful connection cleanup finish.
 */
internal class WebStreamResources(
    private val maximumConnections: Int = 16,
    private val maximumPerSession: Int = 2,
    private val lifetimeMs: Long = 30_000,
    private val shutdownTimeoutMs: Long = 1000,
) : AutoCloseable {
    init {
        require(maximumConnections in 1..16 && maximumPerSession in 1..2)
        require(lifetimeMs in 1..30_000 && shutdownTimeoutMs in 0..5000)
    }
    private val gate = Any()
    private var stopped = false
    private val leases = mutableSetOf<Lease>()
    // Virtual-thread executors are only entered after bounded admission. Cleanup has a
    // separate executor so an uncooperative writer cannot prevent its socket being closed.
    private val workers = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().name("decomp-web-stream-", 0).factory())
    private val cleanup = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().name("decomp-web-stream-close-", 0).factory())
    private val deadlines = ScheduledThreadPoolExecutor(1) { task ->
        Thread(task, "decomp-web-stream-deadline").apply { isDaemon = true }
    }.apply { removeOnCancelPolicy = true }

    internal data class Snapshot(val active: Int, val cleanupFailures: Int, val stopped: Boolean)
    fun snapshot(): Snapshot = synchronized(gate) {
        Snapshot(leases.size, leases.count { it.cleanupFailed }, stopped)
    }

    fun submit(session: AuthorizedWebSession, connection: AutoCloseable, work: () -> Unit): Lease = synchronized(gate) {
        if (stopped) throw WebAccessDenied(503, "STREAMS_DRAINING", "Event streams are shutting down.")
        if (leases.size >= maximumConnections || leases.count { it.owner == session.sessionId } >= maximumPerSession) {
            throw WebAccessDenied(429, "STREAM_LIMIT", "Event stream capacity is unavailable. Use bounded polling or retry later.")
        }
        val lease = Lease(session.sessionId, connection)
        leases += lease
        try {
            lease.deadline = deadlines.schedule({ lease.close() }, lifetimeMs, TimeUnit.MILLISECONDS)
            workers.execute {
                val run = synchronized(gate) {
                    lease.worker = Thread.currentThread()
                    !lease.cancelled
                }
                try { if (run) work() }
                catch (_: Exception) { /* Transport failure is not a workflow failure or a public diagnostic. */ }
                finally {
                    synchronized(gate) { lease.workDone = true; lease.worker = null }
                    lease.requestCleanup()
                    release(lease)
                }
            }
        } catch (failure: Exception) {
            // No router/body callback has run; keep ownership with the caller on failed admission.
            lease.deadline?.cancel(false)
            leases.remove(lease)
            throw WebAccessDenied(503, "STREAMS_DRAINING", "Event stream admission is unavailable.")
        }
        lease
    }

    internal inner class Lease internal constructor(internal val owner: String, private val connection: AutoCloseable) : AutoCloseable {
        internal var worker: Thread? = null
        internal var deadline: ScheduledFuture<*>? = null
        internal var cancelled = false
        internal var workDone = false
        private var cleanupStarted = false
        internal var cleanupDone = false
        internal var cleanupFailed = false

        override fun close() {
            synchronized(gate) {
                if (this !in leases) return
                cancelled = true
                worker?.interrupt()
            }
            requestCleanup()
        }

        internal fun requestCleanup() = synchronized(gate) {
            if (cleanupStarted) return@synchronized
            cleanupStarted = true
            deadline?.cancel(false)
            try {
                cleanup.execute {
                    var succeeded = false
                    try { connection.close(); succeeded = true }
                    catch (_: Exception) { /* Retain the reservation if closure could not be established. */ }
                    finally {
                        synchronized(gate) { cleanupDone = succeeded; cleanupFailed = !succeeded }
                        release(this)
                    }
                }
            } catch (_: Exception) { cleanupFailed = true }
        }
    }

    private fun release(lease: Lease) = synchronized(gate) {
        if (lease.workDone && lease.cleanupDone) leases.remove(lease)
    }

    /** A false result preserves outstanding reservations; it must not be reported as clean shutdown. */
    fun shutdown(): Boolean {
        val active = synchronized(gate) { stopped = true; leases.toList() }
        active.forEach { it.close() }
        deadlines.shutdownNow()
        workers.shutdown()
        cleanup.shutdown()
        val until = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(shutdownTimeoutMs)
        fun await(executor: java.util.concurrent.ExecutorService): Boolean {
            val remaining = (until - System.nanoTime()).coerceAtLeast(0)
            return try { executor.awaitTermination(remaining, TimeUnit.NANOSECONDS) }
            catch (_: InterruptedException) { Thread.currentThread().interrupt(); false }
        }
        val workersStopped = await(workers)
        val cleanupStopped = await(cleanup)
        val deadlinesStopped = await(deadlines)
        return workersStopped && cleanupStopped && deadlinesStopped && snapshot().active == 0
    }

    override fun close() { shutdown() }
}
