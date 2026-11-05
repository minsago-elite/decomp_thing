package decompengine.oracle.fulltree.repair

import decompengine.repair.RepairValidationInvocation
import decompengine.repair.RepairValidationObservedArtifact
import java.util.concurrent.atomic.AtomicReference
import org.junit.jupiter.api.Test
import kotlin.test.*

/** Resource-boundary regression controls promoted from the independent review. */
class ShardDiagnosticCallbackControlsTest {
    @Test fun callback_cannot_remove_required_spans_before_snapshot() {
        val spans = mutableListOf(DiagnosticSpan(DiagnosticStream.STDOUT, 0, 1))
        val c = DiagnosticComputationContext(checkpoint = {
            if (it == "before diagnostic payload copy allocation") spans.clear()
        })
        val result = runCatching { RecordedDiagnosticObservation(c, DiagnosticStage.COMPILE, "a".repeat(64),
            byteArrayOf(7), spans, null, null, FailureClass.OTHER) }
        println("span mutation witness: success=${result.isSuccess}, retainedSpans=${result.getOrNull()?.spans?.size}")
        assertTrue(result.exceptionOrNull() is DiagnosticInputException, "retained snapshot must still require at least one span")
    }

    @Test fun default_ceiling_accepts_a_nontrivial_construction_to_key_operation() {
        val c = DiagnosticComputationContext()
        val raw = ByteArray(1024 * 1024) { 7 }
        val o = RecordedDiagnosticObservation(c, DiagnosticStage.COMPILE, "a".repeat(64), raw,
            listOf(DiagnosticSpan(DiagnosticStream.STDOUT, 0, raw.size.toLong())), null, null, FailureClass.OTHER)
        val normalized = ShardDiagnosticNormalizerV1.normalize(o)
        assertTrue(ShardDiagnosticNormalizerV1.stableKey(o, normalized).startsWith("diagnostic-"))
        assertContentEquals(raw, o.payload)
        println("usable ceiling witness: payload=${raw.size}, used=${c.meter.used}, reserved=${c.allocatedBytes}")
        assertTrue(c.meter.used < c.limits.workUnits)
        assertTrue(c.allocatedBytes < c.limits.allocationBytes)
    }

    @Test fun reentrant_callback_cannot_overrun_allocation_ceiling() {
        lateinit var c: DiagnosticComputationContext
        var nested = false
        c = DiagnosticComputationContext(ShardDiagnosticLimits(allocationBytes = 8), checkpoint = {
            if (it == "before outer allocation" && !nested) {
                nested = true
                c.copy(ByteArray(8), "inner")
            }
        })
        val result = runCatching { c.copy(ByteArray(8), "outer") }
        println("allocation witness: success=${result.isSuccess}, reserved=${c.allocatedBytes}, cap=8")
        assertEquals(DiagnosticInputFailure.INVALID_OR_OVER_LIMIT, assertIs<DiagnosticInputException>(result.exceptionOrNull()).failure)
        assertTrue(c.allocatedBytes <= 8, "nested allocation must be counted before outer reservation")
    }

    @Test fun reentrant_real_copy_cannot_overrun_work_ceiling() {
        lateinit var c: DiagnosticComputationContext
        var nested = false
        c = DiagnosticComputationContext(ShardDiagnosticLimits(workUnits = 512), checkpoint = {
            if (it == "outer" && !nested) {
                nested = true
                c.copy(ByteArray(256), "inner")
            }
        })
        val result = runCatching { c.copy(ByteArray(512), "outer") }
        println("work witness: success=${result.isSuccess}, used=${c.meter.used}, cap=512")
        assertEquals(DiagnosticInputFailure.INVALID_OR_OVER_LIMIT, assertIs<DiagnosticInputException>(result.exceptionOrNull()).failure)
        assertTrue(c.meter.used <= 512, "outer work must not proceed with stale remaining budget")
    }

    @Test fun reentrant_text_cannot_lose_aggregate_retention_charge() {
        lateinit var c: DiagnosticComputationContext
        var nested = false
        c = DiagnosticComputationContext(ShardDiagnosticLimits(totalStringBytes = 1), checkpoint = {
            if (it == "before retaining diagnostic text" && !nested) {
                nested = true
                DiagnosticOwner.Unknown(c, "y")
            }
        })
        val result = runCatching { DiagnosticOwner.Unknown(c, "x") }
        println("text witness: two one-byte owners admitted=${result.isSuccess}, reserved=${c.allocatedBytes}, text cap=1")
        assertTrue(result.exceptionOrNull() is DiagnosticInputException, "two retained bytes exceed totalStringBytes=1")
    }

    @Test fun callback_spent_work_is_rechecked_before_copy_allocation() {
        lateinit var c: DiagnosticComputationContext
        c = DiagnosticComputationContext(ShardDiagnosticLimits(workUnits = 8), checkpoint = {
            if (it == "before outer allocation") c.meter.charge(8, "callback work")
        })
        val error = assertFailsWith<DiagnosticInputException> { c.copy(ByteArray(8), "outer") }
        assertEquals(DiagnosticInputFailure.INVALID_OR_OVER_LIMIT, error.failure)
        println("copy preflight witness: used=${c.meter.used}, reserved=${c.allocatedBytes} before exhaustion")
        assertEquals(0L, c.allocatedBytes, "insufficient work must reject before allocation reservation/materialization")
    }

    @Test fun context_operations_remain_on_the_original_caller_thread() {
        val c = DiagnosticComputationContext()
        val result = AtomicReference<Result<ByteArray>>()
        val thread = Thread { result.set(runCatching { c.copy(byteArrayOf(7), "foreign thread") }) }
        thread.isDaemon = true
        thread.start()
        thread.join(2000)
        assertFalse(thread.isAlive)
        println("thread witness: foreign thread copy accepted=${result.get().isSuccess}, used=${c.meter.used}")
        assertTrue(result.get().isFailure, "thread-confinement must be enforced at the resource boundary")
    }

    @Test fun exception_and_interrupt_identity_positive_control() {
        val sentinel = AssertionError("original")
        val c = DiagnosticComputationContext(checkpoint = { throw sentinel })
        assertSame(sentinel, assertFails { c.copy(byteArrayOf(7), "sentinel") })
        Thread.currentThread().interrupt()
        try {
            assertFailsWith<InterruptedException> { DiagnosticComputationContext().copy(byteArrayOf(7), "interrupt") }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    @Test fun foreign_thread_is_rejected_before_empty_fast_paths_or_list_access() {
        var callbacks = 0
        val c = DiagnosticComputationContext(checkpoint = { callbacks++ })
        val unreadable = object : AbstractList<String>() {
            override val size: Int get() = error("foreign list was read")
            override fun get(index: Int): String = error("foreign element was read")
        }
        val actions = listOf<() -> Unit>(
            { c.equal("a", "bb") }, { c.each(emptyList<String>()) {} },
            { c.snapshot(unreadable, 0, "foreign") }, { c.strings(unreadable) },
            { c.text("") }, { c.reserve(0, "foreign") }, { c.meter.charge(0, "foreign") },
            { DiagnosticOwner.Shared(c, "header", unreadable) },
        )
        val results = AtomicReference<List<Throwable?>>()
        val thread = Thread { results.set(actions.map { runCatching(it).exceptionOrNull() }) }
        thread.isDaemon = true
        thread.start()
        thread.join(2000)
        assertFalse(thread.isAlive)
        results.get().forEach { assertIs<DiagnosticInputException>(it) }
        assertEquals(0, callbacks)
        assertEquals(0L, c.meter.used)
        assertEquals(0L, c.allocatedBytes)
    }

    @Test fun rejected_nested_operation_does_not_disable_future_checkpoints() {
        lateinit var c: DiagnosticComputationContext
        var callbacks = 0
        c = DiagnosticComputationContext(checkpoint = {
            callbacks++
            assertFailsWith<DiagnosticInputException> { c.copy(byteArrayOf(8), "nested") }
        })
        assertContentEquals(byteArrayOf(7), c.copy(byteArrayOf(7), "outer"))
        assertContentEquals(byteArrayOf(6), c.copy(byteArrayOf(6), "next"))
        assertEquals(4, callbacks)
        assertEquals(2L, c.meter.used)
        assertEquals(2L, c.allocatedBytes)
    }

    @Test fun caller_list_iterator_cannot_reenter_the_active_copy_slice() {
        val c = DiagnosticComputationContext(ShardDiagnosticLimits(workUnits = 2))
        val values = object : AbstractList<String>() {
            override val size = 2
            override fun get(index: Int): String {
                c.meter.charge(2, "nested input")
                return "value"
            }
        }
        val error = assertFailsWith<DiagnosticInputException> { c.snapshot(values, 2, "copy references") }
        assertEquals(DiagnosticInputFailure.INVALID_OR_OVER_LIMIT, error.failure)
        assertEquals(2L, c.meter.used)
        // Failed work stays charged; the guard is released even when the input getter throws.
        assertFailsWith<DiagnosticInputException> { c.meter.charge(1, "after failure") }.also {
            assertEquals(DiagnosticInputFailure.WORK_EXHAUSTED, it.failure)
        }
    }

    private val invocation = RepairValidationInvocation("validation_" + "1".padStart(32, '0'),
        "run_00000001", "root_" + "0".repeat(24), "c".repeat(64), "d".repeat(64), "e".repeat(64), "f".repeat(64))
    private val receipt = RepairValidationObservedArtifact(
        "reports/repair-revisions/validation-receipts/${invocation.id}_${"b".repeat(64)}.json", "b".repeat(64), 1)
    private fun failure(c: DiagnosticComputationContext, observations: List<RecordedDiagnosticObservation> = emptyList()) =
        RecordedBuildFailure(c, "action", "9".repeat(64), DiagnosticStage.COMPILE, "a".repeat(64),
            invocation, receipt, 1, byteArrayOf(7), byteArrayOf(), observations, true)

    @Test fun action_callback_growth_is_rejected_before_first_element() {
        val values = mutableListOf<RecordedDiagnosticObservation>()
        var grow = false
        var reads = 0
        val c = DiagnosticComputationContext(ShardDiagnosticLimits(observations = 1), checkpoint = {
            if (grow && it == "before action aggregate admission") values += values.single()
        })
        values += RecordedDiagnosticObservation(c, DiagnosticStage.COMPILE, "a".repeat(64), byteArrayOf(7),
            listOf(DiagnosticSpan(DiagnosticStream.STDOUT, 0, 1)), null, null, FailureClass.OTHER)
        val wrapper = object : AbstractList<RecordedDiagnosticObservation>() {
            override val size get() = values.size
            override fun get(index: Int): RecordedDiagnosticObservation { reads++; return values[index] }
        }
        grow = true
        val result = runCatching { failure(c, wrapper) }
        println("action list count=${values.size}, cap=1, elementReads=$reads, error=${result.exceptionOrNull()}")
        assertIs<DiagnosticInputException>(result.exceptionOrNull())
        assertEquals(0, reads, "over-cap callback-mutated action list must reject before traversal")
    }

    @Test fun batch_callback_growth_is_rejected_before_first_element() {
        val values = mutableListOf<RecordedBuildFailure>()
        var grow = false
        var reads = 0
        val c = DiagnosticComputationContext(ShardDiagnosticLimits(failedActions = 1), checkpoint = {
            if (grow && it == "before batch aggregate admission") values += values.single()
        })
        values += failure(c)
        val wrapper = object : AbstractList<RecordedBuildFailure>() {
            override val size get() = values.size
            override fun get(index: Int): RecordedBuildFailure { reads++; return values[index] }
        }
        grow = true
        val result = runCatching { RecordedCompileLinkBatch(c, wrapper) }
        println("batch list count=${values.size}, cap=1, elementReads=$reads, error=${result.exceptionOrNull()}")
        assertIs<DiagnosticInputException>(result.exceptionOrNull())
        assertEquals(0, reads, "over-cap callback-mutated batch list must reject before traversal")
    }
}
