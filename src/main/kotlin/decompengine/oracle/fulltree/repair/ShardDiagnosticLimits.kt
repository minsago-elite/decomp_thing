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
    val failedInvocations: Int = 4096,
    val moduleMappings: Int = 4096,
    val headerNodes: Int = 8192,
    val graphNodes: Int = 16384,
    val directEdges: Int = 65536,
    val condensationEdges: Int = 65536,
    val retainedCases: Int = 4096,
    val diagnosticKeys: Int = 4096,
    val rootMemberships: Int = 1000000,
    val impactMemberships: Int = 1000000,
    val canonicalBytes: Int = 16777216,
    val jsonDepth: Int = 24,
    val jsonNodes: Int = 1000000,
    val jsonNumberCharacters: Int = 19,
    val sourceOnlyUnits: Int = 16384,
    val headerObservations: Int = 65536,
    val graphBlockers: Int = 65536,
    val ownershipMemberships: Int = 65536,
) {
    init {
        diagnosticCapacity(failedInvocations in 0..4096)
        diagnosticCapacity(moduleMappings in 0..4096)
        diagnosticCapacity(headerNodes in 0..8192)
        diagnosticCapacity(graphNodes in 0..16384)
        diagnosticCapacity(directEdges in 0..65536)
        diagnosticCapacity(condensationEdges in 0..65536)
        diagnosticCapacity(retainedCases in 0..4096)
        diagnosticCapacity(diagnosticKeys in 0..4096)
        diagnosticCapacity(rootMemberships in 0..1000000)
        diagnosticCapacity(impactMemberships in 0..1000000)
        diagnosticCapacity(canonicalBytes in 0..16777216)
        diagnosticCapacity(jsonDepth in 0..24)
        diagnosticCapacity(jsonNodes in 0..1000000)
        diagnosticCapacity(jsonNumberCharacters in 0..19)
        diagnosticCapacity(sourceOnlyUnits in 0..16384)
        diagnosticCapacity(headerObservations in 0..65536)
        diagnosticCapacity(graphBlockers in 0..65536)
        diagnosticCapacity(ownershipMemberships in 0..65536)
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
    private var inInput = false
    var used: Long = 0
        private set

    fun checkAccess() {
        diagnosticCapacity(Thread.currentThread() === owner && !inCheckpoint && !inWorkSlice && !inInput)
    }

    /** Guard caller-controlled access; restore on every exception without wrapping it. */
    fun <T> guardedInput(read: () -> T): T {
        checkAccess()
        inInput = true
        try { return read() } finally { inInput = false }
    }

    // Actual new-code units for cadence controls. Accounting-only precharges do not advance these.
    internal var graphCompletedUnits: Long = 0
        private set
    internal var graphLastPhase: String = ""
        private set

    fun graphStep(label: String, action: () -> Unit) {
        work(1, label) { _, _ ->
            action()
            graphCompletedUnits++
            graphLastPhase = label
        }
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

    /** Final admission follows the allocation callback and precedes iterator acquisition. */
    fun <T> graphSnapshot(values: List<T>, maximum: Int, label: String): List<T> {
        meter.checkAccess()
        val count = meter.guardedInput { values.size }
        diagnosticCapacity(count in 0..maximum)
        meter.ensure(count.toLong())
        reserve(diagnosticAdd(64, diagnosticMultiply(count.toLong(), 8)), "before $label allocation")
        val iterator = meter.guardedInput {
            val finalCount = values.size
            diagnosticCapacity(finalCount in 0..maximum && finalCount == count)
            values.iterator()
        }
        val result = ArrayList<T>(count)
        repeat(count) {
            meter.graphStep(label) {
                // work guards caller size/next reentry; never recursively call the meter here.
                diagnosticCapacity(values.size == count)
                result.add(iterator.next())
            }
        }
        meter.guardedInput { diagnosticCapacity(values.size == count) }
        meter.end("after $label")
        return Collections.unmodifiableList(result)
    }

    fun compareCodePoints(left: String, right: String): Int {
        meter.checkAccess()
        var l = 0
        var r = 0
        var result = 0
        while (l < left.length && r < right.length && result == 0) {
            var a = 0
            var b = 0
            meter.graphStep("graph comparator") { a = left.codePointAt(l); diagnosticCapacity(a !in 0xD800..0xDFFF); l += Character.charCount(a) }
            meter.graphStep("graph comparator") { b = right.codePointAt(r); diagnosticCapacity(b !in 0xD800..0xDFFF); r += Character.charCount(b) }
            result = a.compareTo(b)
        }
        return if (result != 0) result else (left.length - l).compareTo(right.length - r)
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

/** Stable, cancellable bottom-up mergesort; no library sort or caller indexed access. */
internal fun <T> diagnosticMergeSort(
    context: DiagnosticComputationContext, values: List<T>, maximum: Int, compare: (T, T) -> Int,
): List<T> {
    val meter = context.meter
    meter.checkAccess()
    val retained = context.graphSnapshot(values, maximum, "graph sort snapshot")
    meter.begin("before graph sort")
    val count = retained.size
    context.reserve(diagnosticMultiply(count.toLong(), 16), "before graph sort scratch")
    var source = arrayOfNulls<Any?>(count)
    var target = arrayOfNulls<Any?>(count)
    for (i in 0 until count) meter.graphStep("graph sort copy") { source[i] = retained[i] }
    var width = 1
    while (width < count) {
        var base = 0
        while (base < count) {
            val middle = minOf(base + width, count)
            val end = minOf(middle + width, count)
            var left = base
            var right = middle
            var out = base
            while (out < end) {
                @Suppress("UNCHECKED_CAST")
                val fromLeft = left < middle && (right == end || compare(source[left] as T, source[right] as T) <= 0)
                meter.graphStep("graph sort merge") {
                    target[out++] = if (fromLeft) source[left++] else source[right++]
                }
            }
            base = end
        }
        val swap = source; source = target; target = swap
        width = minOf(count.toLong(), diagnosticMultiply(width.toLong(), 2)).toInt()
    }
    context.reserve(diagnosticAdd(64, diagnosticMultiply(count.toLong(), 8)), "before graph sorted output")
    val result = ArrayList<T>(count)
    for (i in 0 until count) meter.graphStep("graph sorted output") {
        @Suppress("UNCHECKED_CAST")
        result.add(source[i] as T)
    }
    meter.end("after graph sort")
    return Collections.unmodifiableList(result)
}
