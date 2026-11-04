package decompengine.oracle.fulltree.repair

import java.util.Collections

/** Immutable ceilings; callers may only lower them. Allocation is cumulative, never refunded. */
internal data class ShardDiagnosticLimits(
    val failedActions: Int = 4096,
    val observations: Int = 16384,
    val actionBytes: Long = 8L * 1024 * 1024,
    val batchBytes: Long = 64L * 1024 * 1024,
    val diagnosticPayloadBytes: Long = 64L * 1024 * 1024,
    val spansPerObservation: Int = 4096,
    val spansPerAction: Int = 16384,
    val workUnits: Long = 128_000_000,
    val spansPerBatch: Long = 4096L * 16384,
    val allocationBytes: Long = 256L * 1024 * 1024,
    val stringBytes: Int = 4096,
    val totalStringBytes: Long = 8L * 1024 * 1024,
) {
    init {
        diagnosticCapacity(failedActions in 0..HARD_MAX_ACTIONS)
        diagnosticCapacity(observations in 0..HARD_MAX_OBSERVATIONS)
        diagnosticCapacity(actionBytes in 0..HARD_MAX_ACTION_BYTES)
        diagnosticCapacity(batchBytes in 0..HARD_MAX_BATCH_BYTES)
        diagnosticCapacity(diagnosticPayloadBytes in 0..HARD_MAX_BATCH_BYTES)
        diagnosticCapacity(spansPerObservation in 0..HARD_MAX_SPANS_PER_OBSERVATION)
        diagnosticCapacity(spansPerAction in 0..HARD_MAX_SPANS_PER_ACTION)
        diagnosticCapacity(workUnits in 0..HARD_MAX_WORK_UNITS)
        diagnosticCapacity(spansPerBatch in 0..4096L * 16384)
        diagnosticCapacity(allocationBytes in 0..256L * 1024 * 1024)
        diagnosticCapacity(stringBytes in 0..4096)
        diagnosticCapacity(totalStringBytes in 0..8L * 1024 * 1024)
    }

    /** Additional restriction of an already admitted batch; uses its original operation meter. */
    internal fun admit(batch: RecordedCompileLinkBatch) = batch.checkLimits(this)

    companion object {
        const val HARD_MAX_ACTIONS = 4096
        const val HARD_MAX_OBSERVATIONS = 16384
        const val HARD_MAX_ACTION_BYTES = 8L * 1024 * 1024
        const val HARD_MAX_BATCH_BYTES = 64L * 1024 * 1024
        const val HARD_MAX_SPANS_PER_OBSERVATION = 4096
        const val HARD_MAX_SPANS_PER_ACTION = 16384
        const val HARD_MAX_WORK_UNITS = 128_000_000L
        const val CHECKPOINT_INTERVAL = 256L
    }
}

/** Work executes BEFORE the boundary callback, in slices ending at the next global checkpoint. */
internal class DiagnosticWorkMeter(
    private val limits: ShardDiagnosticLimits,
    private val checkpoint: (String) -> Unit,
) {
    private val owner = Thread.currentThread()
    private var inCheckpoint = false
    private var inWorkSlice = false
    var used: Long = 0
        private set

    fun checkAccess() {
        diagnosticCapacity(Thread.currentThread() === owner && !inCheckpoint && !inWorkSlice)
    }

    fun begin(label: String) {
        checkAccess()
        inCheckpoint = true
        try {
            checkpoint(label) // Never wrap caller exceptions, including cancellation and Errors.
        } finally {
            inCheckpoint = false
        }
        if (Thread.currentThread().isInterrupted) throw InterruptedException("diagnostic work cancelled")
    }

    fun ensure(units: Long) {
        checkAccess()
        diagnosticCapacity(units >= 0)
        if (units > limits.workUnits - used) throw DiagnosticInputException(DiagnosticInputFailure.WORK_EXHAUSTED)
    }

    fun work(units: Long, label: String, action: (offset: Int, count: Int) -> Unit) {
        ensure(units)
        diagnosticCapacity(units <= Int.MAX_VALUE)
        var offset = 0
        while (offset.toLong() < units) {
            val count = minOf(units - offset, ShardDiagnosticLimits.CHECKPOINT_INTERVAL - used %
                ShardDiagnosticLimits.CHECKPOINT_INTERVAL).toInt()
            used += count // Reserve this slice even if the caller or input rejects partway through.
            inWorkSlice = true
            try {
                action(offset, count)
            } finally {
                inWorkSlice = false
            }
            offset += count
            if (used % ShardDiagnosticLimits.CHECKPOINT_INTERVAL == 0L) begin(label)
        }
    }

    /** Accounting-only work; byte operations must use work so callbacks interrupt actual traversal. */
    fun charge(units: Long, label: String) = work(units, label) { _, _ -> }
    fun end(label: String) = begin(label)
}

/** One caller-owned, thread-confined operation, from input admission through stable keys.
 * All byte-bearing constructors require it; combining records from different contexts is rejected.
 * Counters include failed attempts and defensive getters. This is a resource boundary, not authority.
 */
internal class DiagnosticComputationContext(
    val limits: ShardDiagnosticLimits = ShardDiagnosticLimits(),
    checkpoint: (String) -> Unit = {},
) {
    val meter = DiagnosticWorkMeter(limits, checkpoint)
    var allocatedBytes: Long = 0
        private set
    private var stringBytes = 0L

    fun reserve(bytes: Long, label: String) {
        meter.checkAccess()
        diagnosticCapacity(bytes >= 0 && bytes <= limits.allocationBytes - allocatedBytes)
        meter.begin(label)
        allocatedBytes += bytes
    }

    fun copy(bytes: ByteArray, label: String): ByteArray {
        meter.ensure(bytes.size.toLong())
        reserve(bytes.size.toLong(), "before $label allocation")
        val result = ByteArray(bytes.size)
        meter.work(bytes.size.toLong(), label) { offset, count -> bytes.copyInto(result, offset, offset, offset + count) }
        meter.end("after $label")
        return result
    }

    fun <T> snapshot(values: List<T>, maximum: Int, label: String): List<T> {
        meter.checkAccess()
        val count = values.size
        diagnosticCapacity(count in 0..maximum)
        meter.ensure(count.toLong())
        reserve(diagnosticMultiply(count.toLong(), 8), "before $label allocation")
        val result = ArrayList<T>(count)
        val iterator = values.iterator()
        meter.work(count.toLong(), label) { _, size ->
            repeat(size) { result.add(iterator.next()) }
        }
        meter.end("after $label")
        return Collections.unmodifiableList(result)
    }

    /** No encoding, substring, regex or copy before UTF-8 length and surrogate admission. */
    fun text(value: String, nonempty: Boolean = false, controls: Boolean = true) {
        meter.checkAccess()
        diagnosticCapacity(value.length <= limits.stringBytes && (!nonempty || value.isNotEmpty()))
        meter.begin("before diagnostic text admission")
        var bytes = 0L
        var high = false
        meter.work(value.length.toLong(), "while admitting diagnostic text") { offset, count ->
            for (i in offset until offset + count) {
                val c = value[i]
                diagnosticCapacity(controls || !Character.isISOControl(c))
                when {
                    high -> { diagnosticCapacity(Character.isLowSurrogate(c)); bytes += 1; high = false }
                    Character.isHighSurrogate(c) -> { bytes += 3; high = true }
                    Character.isLowSurrogate(c) -> diagnosticCapacity(false)
                    c.code <= 0x7f -> bytes++
                    c.code <= 0x7ff -> bytes += 2
                    else -> bytes += 3
                }
                diagnosticCapacity(bytes <= limits.stringBytes)
            }
        }
        diagnosticCapacity(!high)
        val total = diagnosticAdd(stringBytes, bytes)
        diagnosticCapacity(total <= limits.totalStringBytes)
        reserve(bytes, "before retaining diagnostic text")
        stringBytes = total
    }

    fun digest(value: String) {
        meter.checkAccess()
        diagnosticCapacity(value.length == 64)
        text(value)
        meter.work(64, "while checking diagnostic digest") { offset, count ->
            for (i in offset until offset + count) diagnosticCapacity(value[i] in '0'..'9' || value[i] in 'a'..'f')
        }
    }

    fun equal(left: String, right: String): Boolean {
        meter.checkAccess()
        if (left.length != right.length) return false
        var equal = true
        meter.work(left.length.toLong(), "while comparing diagnostic text") { offset, count ->
            for (i in offset until offset + count) if (left[i] != right[i]) equal = false
        }
        return equal
    }

    fun moduleId(value: String) {
        meter.checkAccess()
        diagnosticCapacity(value.length == 35)
        text(value)
        meter.work(35, "while checking module identity") { offset, count ->
            for (i in offset until offset + count) diagnosticCapacity(
                if (i < 3) value[i] == "cu-"[i] else value[i] in '0'..'9' || value[i] in 'a'..'f')
        }
    }

    fun shardId(value: String) {
        text(value, nonempty = true)
        var segment = false
        meter.work(value.length.toLong(), "while checking shard identity") { offset, count ->
            for (i in offset until offset + count) {
                val c = value[i]
                if (c == '-') { diagnosticCapacity(segment); segment = false }
                else { diagnosticCapacity(c in 'a'..'z' || c in '0'..'9'); segment = true }
            }
        }
        diagnosticCapacity(segment)
    }

    fun <T> each(values: List<T>, maximum: Int = Int.MAX_VALUE, action: (T) -> Unit) {
        meter.checkAccess()
        val count = values.size
        // Admit the exact traversal count, after any entry checkpoint and before iterator access.
        diagnosticCapacity(count in 0..maximum)
        val iterator = values.iterator()
        repeat(count) {
            meter.ensure(1)
            val value = iterator.next()
            meter.charge(1, "while visiting diagnostic records")
            action(value)
        }
    }

    fun strings(values: List<String>, modules: Boolean = false): List<String> {
        meter.checkAccess()
        diagnosticCapacity(values.size in 0..limits.observations)
        // Snapshot bounded references once; validate those exact immutable strings before returning.
        // No UTF-8 encoding/string materialization occurs in this admission path.
        val retained = snapshot(values, limits.observations, "diagnostic strings")
        each(retained) { value ->
            if (modules) moduleId(value) else text(value)
        }
        return retained
    }
}
