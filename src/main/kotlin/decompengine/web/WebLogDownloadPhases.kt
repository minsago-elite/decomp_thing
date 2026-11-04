package decompengine.web

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * One listener-local, fixed-size diagnostic for the first generated build-log content request.
 *
 * A valid record gives server-local order and floored elapsed time between reached controller
 * boundaries for the first content-branch entrant only. validated→readReturned lumps together both
 * service-monitor acquisitions, both inspections, store locks, the stable read and the digest. It is
 * not split. The record says nothing about arrival, queueing, client delivery, CPU, GC or locks.
 * The server epoch and the host observer epoch cannot be aligned. Unique attribution needs entries=1,
 * invalid=0, incomplete=0, availability available, and frozen qualifier evidence of exactly one
 * download. The record proves no cause and does not satisfy issue acceptance.
 */
internal class WebLogDownloadPhases(private val nanoClock: () -> Long = System::nanoTime) {
    internal enum class Phase { VALIDATED, READ_RETURNED, CAPTURE_RETURNED, BYTES_READY, HEADERS_RETURNED, BODY_CLOSED, EXCHANGE_CLOSED }

    private val claimed = AtomicBoolean(false)
    private val later = AtomicBoolean(false)
    private val freezeClaimed = AtomicBoolean(false)
    private val faulted = AtomicBoolean(false)
    private val published = AtomicReference<State?>(null)
    private val frozen = AtomicReference<String?>(null)

    /** Claims the diagnostic before any product statement. Every non-owner performs no clock read. */
    fun enter(): Owner? {
        return try {
            when {
                freezeClaimed.get() -> null
                !claimed.compareAndSet(false, true) -> {
                    if (!freezeClaimed.get()) later.set(true)
                    null
                }
                else -> Owner().also { it.start() }
            }
        } catch (_: Throwable) {
            faulted.set(true)
            null
        }
    }

    /** Freeze once, before sampling. A competing caller never waits or samples. */
    fun summarySuffix(): String {
        try {
            frozen.get()?.let { return it }
            if (!freezeClaimed.compareAndSet(false, true)) return frozen.get() ?: ""
            val state = published.get()
            val entrantClaimed = claimed.get()
            // A claimed but not yet published request is unknown; do not manufacture entries=0.
            if (entrantClaimed && state == null) return cache("")
            if (faulted.get() && (!entrantClaimed || state == null)) return cache("")
            val snapshot = if (state == null || state.invalid || faulted.get()) null else sampleSnapshot(state)
            val entryCount = if (!entrantClaimed) 0 else if (later.get()) 2 else 1
            val effectiveState = when {
                state == null -> State.zero()
                snapshot?.invalid == true || faulted.get() -> state.asInvalid()
                else -> state
            }
            var line = format(effectiveState, entryCount, snapshot)
            // A publication fault racing formatting invalidates all sampled fields before caching.
            if (faulted.get() && entrantClaimed && !effectiveState.invalid) {
                line = format(effectiveState.asInvalid(), entryCount, null)
            }
            return cache(line)
        } catch (_: Throwable) {
            faulted.set(true)
            return cache("")
        }
    }

    private fun cache(value: String): String {
        frozen.compareAndSet(null, value)
        return frozen.get() ?: ""
    }

    private fun sampleSnapshot(state: State): Snapshot = try {
        val now = nanoClock()
        val delta = Math.subtractExact(now, state.lastSampleNs)
        val elapsed = Math.subtractExact(now, state.epochNs)
        if (delta < 0L || elapsed < 0L) Snapshot.invalid()
        else Snapshot.fromElapsed(elapsed)
    } catch (_: Throwable) {
        Snapshot.invalid()
    }

    private fun format(state: State, entries: Int, snapshot: Snapshot?): String {
        val invalid = state.invalid || faulted.get() || snapshot?.invalid == true
        val values = LongArray(SLOT_COUNT)
        var present = 0
        var saturated = 0
        var terminal = state.terminal
        if (!invalid && entries > 0) {
            for (i in 0 until WORKER_SLOT_COUNT) {
                if (state.presentBits and (1 shl i) != 0) {
                    present = present or (1 shl i)
                    values[i] = state.elapsedMs[i]
                    if (state.saturatedBits and (1 shl i) != 0) saturated = saturated or (1 shl i)
                }
            }
            if (snapshot != null) {
                present = present or SNAPSHOT_BIT
                values[SNAPSHOT_SLOT] = snapshot.elapsedMs
                if (snapshot.saturated) saturated = saturated or SNAPSHOT_BIT
            }
        } else if (invalid) {
            present = 0
            saturated = 0
        }
        if (entries == 0) terminal = 0
        val incomplete = entries > 0 && terminal == 0
        val out = StringBuilder(304)
        out.append(" lp_v=1 lp_entries=").append(entries)
            .append(" lp_present=").append(present)
            .append(" lp_saturated=").append(saturated)
            .append(" lp_invalid=").append(if (invalid) 1 else 0)
            .append(" lp_incomplete=").append(if (incomplete) 1 else 0)
            .append(" lp_terminal=").append(terminal)
            .append(" lp_cap_ms=").append(CAP_MS)
        for (i in 0 until SLOT_COUNT) {
            out.append(' ').append(KEYS[i]).append('=').append(values[i])
        }
        val result = out.toString()
        return if (result.toByteArray(Charsets.US_ASCII).size <= MAX_SUFFIX_BYTES) result else ""
    }

    internal inner class Owner internal constructor() {
        private var epochNs = 0L
        private var lastSampleNs = 0L
        private var elapsedMs = LongArray(WORKER_SLOT_COUNT)
        private var presentBits = 0
        private var saturatedBits = 0
        private var terminal = 0
        private var invalid = false
        private var started = false
        private var exited = false

        internal fun start() {
            try {
                if (started) return
                started = true
                if (freezeClaimed.get()) return
                val sample = nanoClock()
                epochNs = sample
                lastSampleNs = sample
                elapsedMs[0] = 0L
                presentBits = 1
                publish()
            } catch (_: Throwable) {
                fail()
            }
        }

        internal fun mark(phase: Phase) {
            try {
                if (exited || freezeClaimed.get() || invalid) return
                val slot = phase.ordinal + 1
                if (presentBits and (1 shl slot) != 0) return
                stamp(slot)
            } catch (_: Throwable) {
                fail()
            }
        }

        /** Records the owner exit for normal and unwound branches without affecting product errors. */
        internal fun exit(normal: Boolean) {
            try {
                if (exited) return
                exited = true
                // Publish the exit stamp together with its terminal state, never a torn pair.
                terminal = if (normal) 1 else 2
                if (!freezeClaimed.get() && !invalid) stamp(EXIT_SLOT)
                publish()
            } catch (_: Throwable) {
                fail()
                terminal = if (normal) 1 else 2
                publishInvalidBestEffort()
            }
        }

        private fun stamp(slot: Int) {
            if (freezeClaimed.get() || invalid) return
            val sample = nanoClock()
            val delta = Math.subtractExact(sample, lastSampleNs)
            val elapsed = Math.subtractExact(sample, epochNs)
            if (delta < 0L || elapsed < 0L) {
                fail()
                return
            }
            lastSampleNs = sample
            val millis = elapsed / NANOS_PER_MILLI
            elapsedMs[slot] = if (millis > CAP_MS) CAP_MS else millis
            presentBits = presentBits or (1 shl slot)
            if (millis > CAP_MS) saturatedBits = saturatedBits or (1 shl slot)
            publish()
        }

        private fun publish() {
            if (freezeClaimed.get()) return
            published.set(State(elapsedMs.copyOf(), presentBits, saturatedBits, terminal, invalid, epochNs, lastSampleNs))
        }

        private fun fail() {
            try {
                // Latch first: freezing may suppress the invalid-state publication below.
                faulted.set(true)
                invalid = true
                presentBits = 0
                saturatedBits = 0
                elapsedMs = LongArray(WORKER_SLOT_COUNT)
                publishInvalidBestEffort()
            } catch (_: Throwable) {
                faulted.set(true)
            }
        }

        private fun publishInvalidBestEffort() {
            try {
                if (!freezeClaimed.get()) published.set(State(LongArray(WORKER_SLOT_COUNT), 0, 0, terminal, true, epochNs, lastSampleNs))
            } catch (_: Throwable) {
                faulted.set(true)
            }
        }
    }

    private data class Snapshot(val elapsedMs: Long, val saturated: Boolean, val invalid: Boolean) {
        companion object {
            fun invalid() = Snapshot(0L, false, true)
            fun fromElapsed(nanos: Long): Snapshot {
                val millis = nanos / NANOS_PER_MILLI
                return Snapshot(if (millis > CAP_MS) CAP_MS else millis, millis > CAP_MS, false)
            }
        }
    }

    private class State(
        slots: LongArray,
        val presentBits: Int,
        val saturatedBits: Int,
        val terminal: Int,
        val invalid: Boolean,
        val epochNs: Long,
        val lastSampleNs: Long,
    ) {
        val elapsedMs: LongArray = slots.copyOf()
        fun asInvalid() = State(LongArray(WORKER_SLOT_COUNT), 0, 0, terminal, true, epochNs, lastSampleNs)
        companion object { fun zero() = State(LongArray(WORKER_SLOT_COUNT), 0, 0, 0, false, 0L, 0L) }
    }

    companion object {
        const val CAP_MS = 60_000L
        const val MAX_SUFFIX_BYTES = 768
        const val MAX_LINE_BYTES = 1024
        private const val NANOS_PER_MILLI = 1_000_000L
        private const val WORKER_SLOT_COUNT = 9
        private const val SLOT_COUNT = 10
        private const val EXIT_SLOT = 8
        private const val SNAPSHOT_SLOT = 9
        private const val SNAPSHOT_BIT = 1 shl SNAPSHOT_SLOT
        private val KEYS = arrayOf(
            "lp_enter_ms", "lp_validated_ms", "lp_read_ms", "lp_capture_ms", "lp_bytes_ms",
            "lp_headers_ms", "lp_body_ms", "lp_exchange_ms", "lp_exit_ms", "lp_snapshot_ms",
        )
    }
}
