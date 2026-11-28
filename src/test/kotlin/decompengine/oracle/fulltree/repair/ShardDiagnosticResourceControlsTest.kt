package decompengine.oracle.fulltree.repair

import decompengine.repair.RepairValidationInvocation
import decompengine.repair.RepairValidationObservedArtifact
import java.util.concurrent.CancellationException
import org.junit.jupiter.api.Test
import kotlin.test.*

class ShardDiagnosticResourceControlsTest {
    private val tool = "a".repeat(64)
    private val invocation = RepairValidationInvocation("validation_" + "1".repeat(32), "run_00000001",
        "root_" + "0".repeat(24), tool, tool, tool, tool)
    private val receipt = RepairValidationObservedArtifact(
        "reports/repair-revisions/validation-receipts/${invocation.id}_${tool}.json", tool, 1)
    private fun observation(c: DiagnosticComputationContext, bytes: ByteArray = byteArrayOf(7),
        spans: List<DiagnosticSpan> = listOf(DiagnosticSpan(DiagnosticStream.STDOUT, 0, bytes.size.toLong())),
        path: String? = null, entity: String? = null) = RecordedDiagnosticObservation(c,
        DiagnosticStage.COMPILE, tool, bytes, spans, path, entity, FailureClass.OTHER)
    private fun failure(c: DiagnosticComputationContext, bytes: ByteArray = byteArrayOf(7),
        observations: List<RecordedDiagnosticObservation> = emptyList(), id: String = "action") =
        RecordedBuildFailure(c, id, tool, DiagnosticStage.COMPILE, tool, invocation, receipt,
            1, bytes, byteArrayOf(), observations, true)
    private fun invalid(block: () -> Unit) {
        assertEquals(DiagnosticInputFailure.INVALID_OR_OVER_LIMIT, assertFailsWith<DiagnosticInputException>(block = block).failure)
    }
    private fun exhausted(block: () -> Unit) {
        assertEquals(DiagnosticInputFailure.WORK_EXHAUSTED, assertFailsWith<DiagnosticInputException>(block = block).failure)
    }
    private fun <T> untouchable(size: Int) = object : AbstractList<T>() {
        override val size = size
        override fun get(index: Int): T = error("element traversal before count admission")
    }

    @Test fun real_work_stops_at_next_global_boundary_before_remaining_bytes() {
        val result = ByteArray(1024)
        val stop = CancellationException("at next boundary")
        lateinit var c: DiagnosticComputationContext
        c = DiagnosticComputationContext(checkpoint = { if (c.meter.used == 256L) throw stop })
        c.meter.charge(250, "prefix")
        assertSame(stop, assertFails {
            c.meter.work(1024, "copy") { offset, count -> result.fill(7, offset, offset + count) }
        })
        assertEquals(256, c.meter.used)
        assertTrue(result.take(6).all { it == 7.toByte() })
        assertTrue(result.drop(6).all { it == 0.toByte() })
    }

    @Test fun actual_copy_hash_and_compare_slices_end_on_global_boundaries() {
        val boundaries = mutableListOf<Long>()
        lateinit var c: DiagnosticComputationContext
        c = DiagnosticComputationContext(checkpoint = { if (it.startsWith("while ")) boundaries += c.meter.used })
        c.meter.charge(251, "prefix")
        val raw = ByteArray(1024) { (it % 256).toByte() }
        val copied = c.copy(raw, "while copying")
        assertContentEquals(raw, copied)
        val o = observation(c, raw)
        assertTrue(o.matchesSingleSpan(raw, o.spans.single()))
        invalid { o.matchesSingleSpan(raw, DiagnosticSpan(DiagnosticStream.STDOUT, Long.MAX_VALUE - 1024, Long.MAX_VALUE)) }
        assertEquals("785b0751fc2c53dc14a4ce3d800e69ef9ce1009eb327ccf458afe09c242c26c9", o.payloadHash())
        assertTrue(boundaries.isNotEmpty())
        assertTrue(boundaries.all { it % 256 == 0L })
    }

    @Test fun whole_operation_exact_work_and_one_less_cover_construction_through_stable_key() {
        fun operation(c: DiagnosticComputationContext): String {
            val o = observation(c, "error: bad\n".encodeToByteArray())
            val f = failure(c, "error: bad\n".encodeToByteArray(), listOf(o))
            RecordedCompileLinkBatch(c, listOf(f))
            return ShardDiagnosticNormalizerV1.stableKey(o, ShardDiagnosticNormalizerV1.normalize(o))
        }
        val measured = DiagnosticComputationContext()
        val key = operation(measured)
        val used = measured.meter.used
        assertTrue(used > 529)
        val exact = DiagnosticComputationContext(ShardDiagnosticLimits(workUnits = used))
        assertEquals(key, operation(exact))
        assertEquals(used, exact.meter.used)
        exhausted { operation(DiagnosticComputationContext(ShardDiagnosticLimits(workUnits = used - 1))) }
    }

    @Test fun normalization_and_stable_key_never_hide_work_in_a_fresh_meter() {
        val c = DiagnosticComputationContext()
        val o = observation(c, ByteArray(513))
        val before = c.meter.used
        val normalized = ShardDiagnosticNormalizerV1.normalize(o)
        val normalizationCost = c.meter.used - before
        assertTrue(normalizationCost >= 136 + 513)
        val beforeKey = c.meter.used
        ShardDiagnosticNormalizerV1.stableKey(o, normalized)
        assertTrue(c.meter.used - beforeKey >= normalizationCost + 382)
    }

    @Test fun insufficient_copy_work_rejects_before_any_allocation_or_hash_entry() {
        val labels = mutableListOf<String>()
        val c = DiagnosticComputationContext(ShardDiagnosticLimits(workUnits = 136), checkpoint = { labels += it })
        exhausted { observation(c, ByteArray(1024 * 1024)) }
        assertEquals(0, c.allocatedBytes)
        assertTrue(labels.none { "allocation" in it || "hashing" in it })
        exhausted { c.copy(ByteArray(137), "copy") }
        assertEquals(0, c.allocatedBytes)
    }

    @Test fun allocation_reservations_are_checked_before_materialization_and_never_refunded() {
        val labels = mutableListOf<String>()
        val c = DiagnosticComputationContext(ShardDiagnosticLimits(allocationBytes = 1024), checkpoint = { labels += it })
        assertEquals(1024, c.copy(ByteArray(1024), "first").size)
        assertEquals(1024, c.allocatedBytes)
        val before = labels.size
        invalid { c.copy(byteArrayOf(1), "over") }
        assertEquals(before, labels.size)
        assertEquals(1024, c.allocatedBytes)
        invalid { DiagnosticComputationContext(ShardDiagnosticLimits(allocationBytes = 7)).snapshot(listOf(1), 1, "list") }
        invalid { diagnosticMultiply(Long.MAX_VALUE, 2) }
    }

    @Test fun zero_allocation_and_zero_work_prevent_record_retention() {
        val zero = DiagnosticComputationContext(ShardDiagnosticLimits(allocationBytes = 0))
        invalid { observation(zero) }
        assertEquals(0, zero.allocatedBytes)
        exhausted { observation(DiagnosticComputationContext(ShardDiagnosticLimits(workUnits = 0))) }
    }

    @Test fun sequential_lists_use_iterators_and_never_quadratic_indexed_traversal() {
        val c = DiagnosticComputationContext()
        val sequential = object : java.util.AbstractSequentialList<String>() {
            private val data = java.util.LinkedList(listOf("one", "two", "three"))
            override val size get() = data.size
            override fun listIterator(index: Int): MutableListIterator<String> {
                assertEquals(0, index, "must use one iterator instead of indexed retrieval")
                return data.listIterator(index)
            }
        }
        assertEquals(listOf("one", "two", "three"), DiagnosticOwner.Conflict(c, sequential).evidenceIds)
    }

    @Test fun failed_work_slice_remains_charged() {
        val c = DiagnosticComputationContext()
        val failure = AssertionError("in work")
        assertSame(failure, assertFails { c.meter.work(300, "work") { _, _ -> throw failure } })
        assertEquals(256, c.meter.used)
    }

    @Test fun getters_consume_original_context_work_and_allocation() {
        val c = DiagnosticComputationContext()
        val o = observation(c, ByteArray(513))
        val work = c.meter.used
        val allocation = c.allocatedBytes
        o.payload
        assertEquals(work + 513, c.meter.used)
        assertEquals(allocation + 513, c.allocatedBytes)
        val f = failure(c, ByteArray(513))
        val before = c.meter.used
        f.stdout
        assertEquals(before + 513, c.meter.used)
    }

    @Test fun contexts_cannot_be_swapped_to_reset_admission_cost() {
        val a = DiagnosticComputationContext()
        val b = DiagnosticComputationContext()
        val o = observation(a)
        invalid { failure(b, observations = listOf(o)) }
        val f = failure(a, observations = listOf(o))
        invalid { RecordedCompileLinkBatch(b, listOf(f)) }
    }

    @Test fun all_collection_counts_are_checked_before_the_first_element() {
        val c = DiagnosticComputationContext(ShardDiagnosticLimits(observations = 1, failedActions = 1, spansPerObservation = 1))
        invalid { DiagnosticOwner.Shared(c, "header", untouchable(2)) }
        invalid { DiagnosticOwner.Conflict(c, untouchable(2)) }
        invalid { DiagnosticBlocker(c, DiagnosticBlockerCode.CONFLICT, untouchable(2)) }
        invalid { observation(c, spans = untouchable(2)) }
        invalid { failure(c, observations = untouchable(2)) }
        invalid { RecordedCompileLinkBatch(c, untouchable(2)) }
        assertEquals(0, c.meter.used)
        assertEquals(0, c.allocatedBytes)
    }

    @Test fun action_summaries_reject_before_span_traversal_and_stream_retention() {
        val labels = mutableListOf<String>()
        val c = DiagnosticComputationContext(ShardDiagnosticLimits(diagnosticPayloadBytes = 1), checkpoint = { labels += it })
        val o = observation(c)
        labels.clear()
        val before = c.allocatedBytes
        invalid { failure(c, observations = listOf(o, o)) }
        assertEquals(before, c.allocatedBytes)
        assertEquals(listOf("before action aggregate admission"), labels)
    }

    @Test fun repeated_action_references_count_toward_all_aggregate_caps_before_batch_copy() {
        for (limits in listOf(ShardDiagnosticLimits(observations = 1), ShardDiagnosticLimits(batchBytes = 1),
            ShardDiagnosticLimits(diagnosticPayloadBytes = 1), ShardDiagnosticLimits(spansPerBatch = 1))) {
            val labels = mutableListOf<String>()
            val c = DiagnosticComputationContext(limits, checkpoint = { labels += it })
            val f = failure(c, observations = listOf(observation(c)))
            labels.clear()
            val allocated = c.allocatedBytes
            invalid { RecordedCompileLinkBatch(c, listOf(f, f)) }
            assertEquals(allocated, c.allocatedBytes)
            assertEquals(listOf("before batch aggregate admission"), labels)
        }
    }

    @Test fun callbacks_cannot_replace_admitted_records_with_stale_aggregate_summaries() {
        var mutate: (String) -> Unit = {}
        val c = DiagnosticComputationContext(ShardDiagnosticLimits(diagnosticPayloadBytes = 3), checkpoint = { mutate(it) })
        val small = observation(c)
        val large = observation(c, byteArrayOf(7, 7))
        val records = mutableListOf(small)
        mutate = { if (it == "before action observations allocation") records[0] = large }
        invalid { failure(c, byteArrayOf(7, 7), records) }
        mutate = {}
        val a = failure(c, observations = listOf(small))
        val b = failure(c, byteArrayOf(7, 7), listOf(large))
        val actions = mutableListOf(a, a)
        mutate = { if (it == "before batch failures allocation") { actions[0] = b; actions[1] = b } }
        invalid { RecordedCompileLinkBatch(c, actions) }
    }

    @Test fun lowerable_limits_apply_during_construction_not_optional_admission() {
        invalid { observation(DiagnosticComputationContext(ShardDiagnosticLimits(diagnosticPayloadBytes = 0))) }
        invalid { observation(DiagnosticComputationContext(ShardDiagnosticLimits(spansPerObservation = 0))) }
        invalid { failure(DiagnosticComputationContext(ShardDiagnosticLimits(actionBytes = 0))) }
        invalid { failure(DiagnosticComputationContext(ShardDiagnosticLimits(batchBytes = 0))) }
        val c = DiagnosticComputationContext(ShardDiagnosticLimits(failedActions = 0))
        invalid { RecordedCompileLinkBatch(c, listOf(failure(c))) }
        val d = DiagnosticComputationContext(ShardDiagnosticLimits(spansPerAction = 0))
        invalid { failure(d, observations = listOf(observation(d))) }
        val e = DiagnosticComputationContext(ShardDiagnosticLimits(observations = 0))
        invalid { failure(e, observations = listOf(observation(e))) }
    }

    @Test fun utf8_limits_are_bytes_and_surrogates_are_admitted_without_encoding() {
        for (exact in listOf("x".repeat(4096), "é".repeat(2048), "😀".repeat(1024))) {
            DiagnosticOwner.Unknown(DiagnosticComputationContext(), exact)
            invalid { DiagnosticOwner.Unknown(DiagnosticComputationContext(), exact + "x") }
        }
        for (bad in listOf("\ud800", "\udfff", "a\ud800b", "\udfff\ud800")) {
            invalid { DiagnosticOwner.Unknown(DiagnosticComputationContext(), bad) }
        }
        val c = DiagnosticComputationContext(ShardDiagnosticLimits(stringBytes = 4, totalStringBytes = 4))
        DiagnosticOwner.Unknown(c, "😀")
        invalid { DiagnosticOwner.Unknown(c, "x") }
        invalid { DiagnosticOwner.Unknown(DiagnosticComputationContext(ShardDiagnosticLimits(stringBytes = 3)), "😀") }
    }

    @Test fun every_owner_action_evidence_path_entity_and_reason_text_is_bounded() {
        val badStrings = listOf("a".repeat(4097), "\ud800", "é".repeat(2049))
        for (bad in badStrings) {
            val factories: List<(DiagnosticComputationContext) -> Unit> = listOf(
                { DiagnosticOwner.Module(it, "cu-" + "a".repeat(32), bad) },
                { DiagnosticOwner.Module(it, bad, "shard") },
                { DiagnosticOwner.Shared(it, bad, emptyList()) },
                { DiagnosticOwner.Shared(it, "header", listOf(bad)) },
                { DiagnosticOwner.External(it, bad) },
                { DiagnosticOwner.Unknown(it, bad) },
                { DiagnosticOwner.Unclassified(it, bad) },
                { DiagnosticOwner.Conflict(it, listOf(bad)) },
                { DiagnosticBlocker(it, DiagnosticBlockerCode.CONFLICT, listOf(bad)) },
                { observation(it, path = bad) }, { observation(it, entity = bad) },
                { failure(it, id = bad) },
            )
            factories.forEach { factory -> invalid { factory(DiagnosticComputationContext()) } }
        }
    }

    @Test fun shard_identifiers_are_iterative_and_accept_the_exact_bound() {
        val module = "cu-" + "a".repeat(32)
        DiagnosticOwner.Module(DiagnosticComputationContext(), module, "a-".repeat(2047) + "ab")
        for (bad in listOf("", "-a", "a-", "a--b", "A", "a_b", "a b", "a-".repeat(5000) + "a")) {
            invalid { DiagnosticOwner.Module(DiagnosticComputationContext(), module, bad) }
        }
    }

    @Test fun arbitrary_raw_path_claims_do_not_become_ownership_or_identity_authority() {
        val a = observation(DiagnosticComputationContext())
        val b = observation(DiagnosticComputationContext(), path = "../\\not-a-portable-path", entity = "unverified")
        fun key(o: RecordedDiagnosticObservation) = ShardDiagnosticNormalizerV1.stableKey(o, ShardDiagnosticNormalizerV1.normalize(o))
        assertEquals(key(a), key(b))
        assertEquals("../\\not-a-portable-path", b.sourcePath)
    }

    @Test fun exceptions_keep_identity_at_every_construction_codec_hash_and_getter_checkpoint() {
        fun operation(checkpoint: (String) -> Unit) {
            val c = DiagnosticComputationContext(checkpoint = checkpoint)
            DiagnosticOwner.Shared(c, "header", listOf("cu-" + "a".repeat(32)))
            val raw = ByteArray(513) { 7 }
            val o = observation(c, raw)
            val f = failure(c, raw, listOf(o))
            RecordedCompileLinkBatch(c, listOf(f))
            ShardDiagnosticNormalizerV1.stableKey(o, ShardDiagnosticNormalizerV1.normalize(o))
            o.payload; f.stdout; f.stderr
        }
        val labels = mutableListOf<String>()
        operation { labels += it }
        assertTrue(labels.any { "sorting canonical JSON" in it })
        for (position in 1..labels.size) for (sentinel in listOf(CancellationException("cancel"), IllegalStateException("caller"), AssertionError("caller"))) {
            var visited = 0
            assertSame(sentinel, assertFails { operation { if (++visited == position) throw sentinel } }, "position $position: ${labels[position-1]}")
        }
    }
}
