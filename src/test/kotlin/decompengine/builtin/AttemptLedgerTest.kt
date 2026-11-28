package decompengine.builtin

import decompengine.agent.AgentCancellationSource
import decompengine.builtin.provider.*
import java.util.UUID
import kotlin.test.*

internal class FakeDurabilityV2 : DurableIntentPortV2 {
    val records = mutableListOf<DurableLedgerRecordV2>()
    var failState: AttemptStateV2? = null
    var publishBeforeFailure = false
    override fun publish(record: DurableLedgerRecordV2) {
        if (record.attemptState != failState || publishBeforeFailure) records += record
        if (record.attemptState == failState) error("synthetic persistence failure")
    }
    override fun currentHead(runId: UUID) = records.lastOrNull { it.runId == runId }
}

class AttemptLedgerTest {
    @Test fun `durable terminal publication preserves already known budget exhaustion`() {
        val f = V2Fixture(local = LocalBudgetV1(responseBytes = 100, eventBytes = 50, receivedBytesTotal = 150))
        val sink = FakeDurabilityV2()
        val ledger = AttemptLedgerV2(f.bind(), LedgerModeV2.INJECTED_DURABILITY, sink)
        val lease = reserve(ledger); val call = dispatch(ledger, lease)
        val seen = ObservedLocalCountersV2(wireBytes = 101)
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED,
            assertFailsWith<ModelProviderException> { call.meter.beforeDelivery(seen) }.kind)
        ledger.settle(lease, seen, null, AttemptOutcomeV2.FAILED, ModelFailureKind.RESOURCE_EXHAUSTED)
        assertEquals(AttemptStateV2.SETTLED, sink.records.last().attemptState)
        assertEquals(ledger.counters(), sink.records.last().counters)
        assertEquals(LedgerStateV2.EXHAUSTED, ledger.state())
        assertFalse(ledger.checkpointEligible())
    }
    @Test fun `durable publication rejects all nested mutators without clearing outer ownership`() {
        for (operation in listOf("not-sent", "settle", "ambiguous", "observe", "session", "fail-batch", "finally")) {
            lateinit var ledger: AttemptLedgerV2
            lateinit var lease: ReservedLease
            var bodyCalls = 0
            var denied = 0
            val records = mutableListOf<DurableLedgerRecordV2>()
            val sink = object : DurableIntentPortV2 {
                override fun publish(record: DurableLedgerRecordV2) {
                    records += record
                    if (record.attemptState != AttemptStateV2.DISPATCH_INTENT) return
                    val before = ledger.counters()
                    assertFailsWith<ModelProviderException> {
                        when (operation) {
                            "not-sent" -> ledger.markDefinitelyNotSent(lease, DefinitelyNotSentProofV2(lease))
                            "settle" -> ledger.settle(lease, ObservedLocalCountersV2(), null, AttemptOutcomeV2.COMPLETED)
                            "ambiguous" -> ledger.markAmbiguous(lease)
                            "observe" -> ledger.observe(lease, ObservedLocalCountersV2(wireBytes = 1), 1)
                            "session" -> ledger.registerToolSession(Any(), BatchCapacityV2())
                            "fail-batch" -> ledger.failBatch()
                            "finally" -> ledger.withSettlement(lease, { AttemptOutcomeV2.COMPLETED }, { null }) { bodyCalls++ }
                        }
                    }
                    denied++
                    assertEquals(before, ledger.counters())
                    assertEquals(LedgerStateV2.ACTIVE, ledger.state())
                    assertFailsWith<ModelProviderException> { reserve(ledger, 2) }
                    assertFailsWith<ModelProviderException> { ledger.call(lease, ByteArray(100)) }
                }
                override fun currentHead(runId: UUID) = records.lastOrNull()
            }
            ledger = AttemptLedgerV2(V2Fixture().bind(), LedgerModeV2.INJECTED_DURABILITY, sink)
            lease = reserve(ledger)
            val call = dispatch(ledger, lease)
            assertNotNull(call)
            assertEquals(1, denied)
            assertEquals(0, bodyCalls)
            assertEquals(listOf(AttemptStateV2.RESERVED, AttemptStateV2.DISPATCH_INTENT), records.map { it.attemptState })
            ledger.settle(lease, ObservedLocalCountersV2(), null, AttemptOutcomeV2.COMPLETED)
            assertEquals(LedgerStateV2.READY, ledger.state())
        }
    }
    @Test fun `failed outer publication cannot leak nested lease or call authority`() {
        lateinit var ledger: AttemptLedgerV2
        lateinit var lease: ReservedLease
        var nestedLeases = 0
        var nestedCalls = 0
        var denials = 0
        val sink = object : DurableIntentPortV2 {
            override fun publish(record: DurableLedgerRecordV2) {
                if (record.attemptState != AttemptStateV2.DISPATCH_INTENT) return
                for (mutate in listOf<() -> Unit>(
                    { ledger.markDefinitelyNotSent(lease, DefinitelyNotSentProofV2(lease)) },
                    { ledger.settle(lease, ObservedLocalCountersV2(), null, AttemptOutcomeV2.COMPLETED) },
                    { ledger.markAmbiguous(lease) },
                )) {
                    assertFailsWith<ModelProviderException> { mutate() }
                    assertFailsWith<ModelProviderException> { reserve(ledger, 2); nestedLeases++ }
                    assertFailsWith<ModelProviderException> { ledger.call(lease, ByteArray(100)); nestedCalls++ }
                    denials++
                }
                error("outer publication uncertain")
            }
            override fun currentHead(runId: UUID): DurableLedgerRecordV2? = null
        }
        ledger = AttemptLedgerV2(V2Fixture().bind(), LedgerModeV2.INJECTED_DURABILITY, sink)
        lease = reserve(ledger)
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED, assertFailsWith<ModelProviderException> { dispatch(ledger, lease) }.kind)
        assertEquals(3, denials); assertEquals(0, nestedLeases); assertEquals(0, nestedCalls)
        assertEquals(LedgerStateV2.INDETERMINATE, ledger.state())
        assertEquals(LedgerCountersV2(1, 100, 0, 0, 0), ledger.counters())
        assertFalse(ledger.checkpointEligible())
    }
    @Test fun `durable head callback cannot mutate the ready ledger being verified`() {
        lateinit var ledger: AttemptLedgerV2
        var latest: DurableLedgerRecordV2? = null
        var denied = false
        val sink = object : DurableIntentPortV2 {
            override fun publish(record: DurableLedgerRecordV2) { latest = record }
            override fun currentHead(runId: UUID): DurableLedgerRecordV2? {
                assertFailsWith<ModelProviderException> { reserve(ledger, 2) }
                denied = true
                return latest
            }
        }
        ledger = AttemptLedgerV2(V2Fixture().bind(), LedgerModeV2.INJECTED_DURABILITY, sink)
        val lease = reserve(ledger); dispatch(ledger, lease)
        ledger.settle(lease, ObservedLocalCountersV2(), null, AttemptOutcomeV2.COMPLETED)
        val head = assertNotNull(latest)
        ledger.verifyInjectedHead(head.sequence, head.commitment)
        assertTrue(denied)
        assertTrue(ledger.checkpointEligible())
        assertEquals(head.sequence, ledger.durableSequence())
    }
    private fun reserve(ledger: AttemptLedgerV2, id: Long = 1, ordinal: Int = 1, input: Long = 100, output: Long = 64) =
        ledger.reserve(UUID(0, id), ordinal, input, output)
    private fun dispatch(ledger: AttemptLedgerV2, lease: ReservedLease): AdmittedModelCallV2 {
        ledger.markDispatchIntent(lease, ledger.durableSequence() + 1)
        return ledger.call(lease, ByteArray(lease.exactEncodedInputBytes.toInt()))
    }
    @Test fun `retry and admission 401 each debit repeated input and one dispatch slot`() {
        val ledger = AttemptLedgerV2(V2Fixture().bind())
        val first = reserve(ledger); val a = dispatch(ledger, first)
        val seen = ObservedLocalCountersV2(wireBytes = 13, decodedOutputBytes = 7, displayedBytes = 4)
        a.meter.beforeDelivery(seen)
        ledger.settle(first, seen, null, AttemptOutcomeV2.FAILED, ModelFailureKind.AUTHENTICATION)
        val second = reserve(ledger, 2); dispatch(ledger, second)
        ledger.settle(second, ObservedLocalCountersV2(), ReportedModelUsageV1(0, 0, 0), AttemptOutcomeV2.COMPLETED)
        assertEquals(LedgerCountersV2(2, 200, 7, 13, 4), ledger.counters())
        assertEquals(listOf(1, 2), ledger.observations().map { it.attempt })
        val usage = ledger.aggregate()
        assertEquals(UsageCoverageV1.PARTIAL, usage.coverage); assertEquals(1L, usage.unknown)
        assertNull(usage.input); assertEquals(0L, usage.knownInput)
    }
    @Test fun `known zero is complete and absent detail does not become zero`() {
        val ledger = AttemptLedgerV2(V2Fixture().bind()); val lease = reserve(ledger); dispatch(ledger, lease)
        ledger.settle(lease, ObservedLocalCountersV2(), ReportedModelUsageV1(0, 0, 0), AttemptOutcomeV2.COMPLETED)
        val usage = ledger.aggregate()
        assertEquals(UsageCoverageV1.COMPLETE, usage.coverage); assertEquals(0L, usage.total)
        assertNull(usage.cachedInput); assertNull(usage.reasoningOutput)
        assertTrue(ledger.observations().single().estimated)
        assertEquals(100L, ledger.counters().input)
    }
    @Test fun `failed and incomplete terminal telemetry participates in detail coverage independently`() {
        val ledger = AttemptLedgerV2(V2Fixture().bind())
        val a = reserve(ledger); dispatch(ledger, a)
        ledger.settle(a, ObservedLocalCountersV2(), ReportedModelUsageV1(5, 2, 7, cachedInput = 5, cacheWriteInput = 5, reasoningOutput = 1), AttemptOutcomeV2.INCOMPLETE)
        val b = reserve(ledger, 2); dispatch(ledger, b)
        ledger.settle(b, ObservedLocalCountersV2(), ReportedModelUsageV1(3, 4, 7, cachedInput = 2, reasoningOutput = 2), AttemptOutcomeV2.FAILED)
        val aggregate = ledger.aggregate()
        assertEquals(14L, aggregate.total); assertEquals(7L, aggregate.cachedInput)
        assertNull(aggregate.cacheWriteInput); assertEquals(3L, aggregate.reasoningOutput)
    }
    @Test fun `reported usage rejects negative inconsistent overflow and out of parent details`() {
        listOf<() -> ReportedModelUsageV1>({ ReportedModelUsageV1(-1, 0, 0) }, { ReportedModelUsageV1(1, 2, 4) },
            { ReportedModelUsageV1(Long.MAX_VALUE, 1, Long.MAX_VALUE) }, { ReportedModelUsageV1(2, 1, 3, cachedInput = 3) },
            { ReportedModelUsageV1(2, 1, 3, reasoningOutput = 2) }, { ReportedModelUsageV1(2, 1, 3, cacheWriteInput = -1) })
            .forEach { assertFailsWith<ModelProviderException> { it() } }
        assertEquals(Long.MAX_VALUE, ReportedModelUsageV1(Long.MAX_VALUE, 0, Long.MAX_VALUE).total)
        // No invented sum constraint between cache read/write details.
        assertNotNull(ReportedModelUsageV1(5, 0, 5, cachedInput = 5, cacheWriteInput = 5))
    }
    @Test fun `settlement is idempotent but conflicting telemetry poisons run`() {
        val ledger = AttemptLedgerV2(V2Fixture().bind()); val lease = reserve(ledger); dispatch(ledger, lease)
        val first = ledger.settle(lease, ObservedLocalCountersV2(), null, AttemptOutcomeV2.COMPLETED)
        assertSame(first, ledger.settle(lease, ObservedLocalCountersV2(), null, AttemptOutcomeV2.COMPLETED))
        assertEquals(100L, ledger.counters().input)
        assertFailsWith<ModelProviderException> { ledger.settle(lease, ObservedLocalCountersV2(), ReportedModelUsageV1(0, 0, 0), AttemptOutcomeV2.COMPLETED) }
        assertEquals(LedgerStateV2.INDETERMINATE, ledger.state())
    }
    @Test fun `overdraw retains true report and blocks future reserve and tools`() {
        val ledger = AttemptLedgerV2(V2Fixture().bind()); val lease = reserve(ledger); dispatch(ledger, lease)
        ledger.settle(lease, ObservedLocalCountersV2(), ReportedModelUsageV1(101, 65, 166), AttemptOutcomeV2.COMPLETED)
        assertEquals(101L, ledger.counters().input); assertEquals(65L, ledger.counters().output)
        assertEquals(166L, ledger.aggregate().total); assertEquals(LedgerStateV2.EXHAUSTED, ledger.state())
        assertFailsWith<ModelProviderException> { reserve(ledger, 2) }
        assertFalse(ledger.checkpointEligible())
    }
    @Test fun `wire output and continuation ceilings reject before delivery and retain observed charges`() {
        val f = V2Fixture(local = LocalBudgetV1(responseBytes = 100, eventBytes = 50, receivedBytesTotal = 150))
        val ledger = AttemptLedgerV2(f.bind()); val lease = reserve(ledger); val call = dispatch(ledger, lease)
        val atLimit = ObservedLocalCountersV2(wireBytes = 100, decodedOutputBytes = 64)
        call.meter.beforeDelivery(atLimit, 50); call.meter.beforeDelivery(atLimit, 50) // final projection: no duplicate debit
        var delivered = false
        val tooLarge = atLimit.copy(wireBytes = 101)
        assertFailsWith<ModelProviderException> { call.meter.beforeDelivery(tooLarge); delivered = true }
        assertFalse(delivered)
        ledger.settle(lease, tooLarge, null, AttemptOutcomeV2.FAILED, ModelFailureKind.RESOURCE_EXHAUSTED)
        assertEquals(101L, ledger.counters().wire); assertEquals(64L, ledger.counters().output)
        assertEquals(LedgerStateV2.EXHAUSTED, ledger.state())
    }
    @Test fun `aggregate raw wire is not refunded by retry or displayed byte headroom`() {
        val f = V2Fixture(local = LocalBudgetV1(responseBytes = 100, eventBytes = 50, receivedBytesTotal = 150))
        val ledger = AttemptLedgerV2(f.bind()); val a = reserve(ledger); val ca = dispatch(ledger, a)
        ca.meter.beforeDelivery(ObservedLocalCountersV2(wireBytes = 100))
        ledger.settle(a, ObservedLocalCountersV2(wireBytes = 100), null, AttemptOutcomeV2.FAILED)
        val b = reserve(ledger, 2); val cb = dispatch(ledger, b)
        assertFailsWith<ModelProviderException> { cb.meter.beforeDelivery(ObservedLocalCountersV2(wireBytes = 51)) }
        assertEquals(151L, ledger.counters().wire); assertEquals(0L, ledger.counters().displayed)
    }
    @Test fun `closed and foreign leases cannot be mutated`() {
        val ledger = AttemptLedgerV2(V2Fixture().bind()); val other = AttemptLedgerV2(V2Fixture().bind())
        val lease = reserve(ledger); val call = dispatch(ledger, lease)
        assertFailsWith<ModelProviderException> { other.markDispatchIntent(lease, 1) }
        ledger.settle(lease, ObservedLocalCountersV2(), null, AttemptOutcomeV2.COMPLETED)
        assertFailsWith<ModelProviderException> { call.meter.beforeDelivery(ObservedLocalCountersV2(wireBytes = 1)) }
        assertFailsWith<ModelProviderException> { ledger.markDefinitelyNotSent(lease, DefinitelyNotSentProofV2(lease)) }
    }
    @Test fun `proven not sent releases reservations but ambiguous dispatch never does`() {
        val ledger = AttemptLedgerV2(V2Fixture().bind()); val before = reserve(ledger)
        ledger.markDefinitelyNotSent(before, DefinitelyNotSentProofV2(before))
        assertEquals(0L, ledger.counters().requests)
        val notSent = reserve(ledger, 2); dispatch(ledger, notSent)
        ledger.markDefinitelyNotSent(notSent, DefinitelyNotSentProofV2(notSent))
        assertEquals(0L, ledger.counters().requests)
        val ambiguous = reserve(ledger, 3); dispatch(ledger, ambiguous)
        val observation = ledger.markAmbiguous(ambiguous)
        assertSame(observation, ledger.markAmbiguous(ambiguous))
        assertEquals(LedgerCountersV2(1, 100, 64, 0, 0), ledger.counters())
        assertEquals(LedgerStateV2.INDETERMINATE, ledger.state()); assertNull(ledger.aggregate().total)
        assertFailsWith<ModelProviderException> { reserve(ledger, 4) }
    }
    @Test fun `required durable intent failure means no provider dispatch`() {
        assertFailsWith<ModelProviderException> { AttemptLedgerV2(V2Fixture().bind(), LedgerModeV2.INJECTED_DURABILITY) }
        val sink = FakeDurabilityV2(); val ledger = AttemptLedgerV2(V2Fixture().bind(), LedgerModeV2.INJECTED_DURABILITY, sink)
        val lease = reserve(ledger); sink.failState = AttemptStateV2.DISPATCH_INTENT
        var sends = 0
        assertFailsWith<ModelProviderException> { dispatch(ledger, lease); sends++ }
        assertEquals(0, sends); assertFalse(ledger.checkpointEligible())
        assertFailsWith<ModelProviderException> { reserve(ledger, 2) }
    }
    @Test fun `settlement persistence failure preserves the original typed failure and full charge`() {
        val sink = FakeDurabilityV2(); val ledger = AttemptLedgerV2(V2Fixture().bind(), LedgerModeV2.INJECTED_DURABILITY, sink)
        val lease = reserve(ledger); val call = dispatch(ledger, lease)
        call.meter.beforeDelivery(ObservedLocalCountersV2(wireBytes = 12, decodedOutputBytes = 7))
        sink.failState = AttemptStateV2.SETTLED
        val original = ModelProviderException(ModelFailureKind.TRANSPORT)
        val caught = assertFailsWith<ModelProviderException> {
            ledger.withSettlement(lease, { AttemptOutcomeV2.COMPLETED }, { null }) { throw original }
        }
        assertSame(original, caught); assertEquals(7L, ledger.counters().output)
        assertEquals(ModelFailureKind.TRANSPORT, ledger.observations().single().failureKind)
        assertEquals(LedgerStateV2.INDETERMINATE, ledger.state()); assertFalse(ledger.checkpointEligible())
    }
    @Test fun `pending or newer injected head never validates an older ready reference`() {
        val sink = FakeDurabilityV2(); val ledger = AttemptLedgerV2(V2Fixture().bind(), LedgerModeV2.INJECTED_DURABILITY, sink)
        val lease = reserve(ledger); dispatch(ledger, lease)
        ledger.settle(lease, ObservedLocalCountersV2(), null, AttemptOutcomeV2.COMPLETED)
        val old = sink.records.last()
        assertTrue(ledger.checkpointEligible()); ledger.verifyInjectedHead(old.sequence, old.commitment)
        val second = reserve(ledger, 2)
        assertFailsWith<ModelProviderException> { ledger.verifyInjectedHead(old.sequence, old.commitment) } // crash after reserve
        dispatch(ledger, second)
        assertFailsWith<ModelProviderException> { ledger.verifyInjectedHead(old.sequence, old.commitment) } // intent/send/response before settle
        ledger.settle(second, ObservedLocalCountersV2(), null, AttemptOutcomeV2.COMPLETED)
        assertFailsWith<ModelProviderException> { ledger.verifyInjectedHead(old.sequence, old.commitment) } // newer settled head
        val latest = sink.records.last(); ledger.verifyInjectedHead(latest.sequence, latest.commitment)
    }
    @Test fun `cancellation before reserve before intent and during response preserves accounting`() {
        val cancellation = AgentCancellationSource(); val f = V2Fixture(cancellation = cancellation.cancellation)
        val ledger = AttemptLedgerV2(f.bind()); val lease = reserve(ledger)
        cancellation.cancel()
        assertEquals(ModelFailureKind.CANCELLED, assertFailsWith<ModelProviderException> { dispatch(ledger, lease) }.kind)
        assertEquals(0L, ledger.counters().requests)
        ledger.markDefinitelyNotSent(lease, DefinitelyNotSentProofV2(lease))
        assertFailsWith<ModelProviderException> { reserve(ledger, 2) }
        val source = AgentCancellationSource(); val active = AttemptLedgerV2(V2Fixture(cancellation = source.cancellation).bind())
        val a = reserve(active); val call = dispatch(active, a); source.cancel()
        assertFailsWith<ModelProviderException> {
            active.withSettlement(a, { AttemptOutcomeV2.COMPLETED }, { null }) { call.meter.beforeDelivery(ObservedLocalCountersV2(wireBytes = 1)) }
        }
        assertEquals(1L, active.counters().requests); assertEquals(1L, active.counters().wire); assertEquals(AttemptOutcomeV2.CANCELLED, active.observations().single().outcome)
    }
    @Test fun `maxTurns clips all inference attempts including retries`() {
        val ledger = AttemptLedgerV2(V2Fixture(legacy = decompengine.agent.AgentExecutionLimits(maxTurns = 1)).bind())
        val lease = reserve(ledger); dispatch(ledger, lease)
        ledger.settle(lease, ObservedLocalCountersV2(), null, AttemptOutcomeV2.FAILED)
        assertFailsWith<ModelProviderException> { reserve(ledger, 2) }
        assertEquals(1L, ledger.counters().requests)
    }
    @Test fun `one admitted run cannot mint a second ledger`() {
        val run = V2Fixture().bind(); AttemptLedgerV2(run)
        assertFailsWith<ModelProviderException> { AttemptLedgerV2(run) }
    }
    @Test fun `reentrant durable callback cannot obtain dispatch authority before publication returns`() {
        lateinit var ledger: AttemptLedgerV2
        lateinit var lease: ReservedLease
        var prematureCalls = 0
        val sink = object : DurableIntentPortV2 {
            override fun publish(record: DurableLedgerRecordV2) {
                if (record.attemptState == AttemptStateV2.DISPATCH_INTENT) {
                    assertFailsWith<ModelProviderException> { ledger.call(lease, ByteArray(100)); prematureCalls++ }
                }
            }
            override fun currentHead(runId: UUID): DurableLedgerRecordV2? = null
        }
        ledger = AttemptLedgerV2(V2Fixture().bind(), LedgerModeV2.INJECTED_DURABILITY, sink)
        lease = reserve(ledger); dispatch(ledger, lease)
        assertEquals(0, prematureCalls)
    }
    @Test fun `finally retains full reservation when host classifies the send ambiguous`() {
        val ledger = AttemptLedgerV2(V2Fixture().bind()); val lease = reserve(ledger); dispatch(ledger, lease)
        val failure = ModelProviderException(ModelFailureKind.TRANSPORT)
        assertSame(failure, assertFailsWith<ModelProviderException> {
            ledger.withSettlement(lease, { AttemptOutcomeV2.AMBIGUOUS }, { null }) { throw failure }
        })
        assertEquals(64L, ledger.counters().output); assertEquals(LedgerStateV2.INDETERMINATE, ledger.state())
        assertEquals(AttemptOutcomeV2.AMBIGUOUS, ledger.observations().single().outcome)
        assertEquals(ModelFailureKind.TRANSPORT, ledger.observations().single().failureKind)
    }

}
