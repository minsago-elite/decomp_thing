package decompengine.builtin

import decompengine.agent.AgentCancellationSource
import decompengine.builtin.provider.*
import kotlinx.serialization.json.jsonPrimitive
import java.util.UUID
import kotlin.test.*

internal class BatchFixtureV2(
    val fixture: V2Fixture = V2Fixture(),
    var layout: EncodedLayoutV2 = EncodedLayoutV2(100, 32),
    var resultCeiling: Long = 16,
    initialCapacity: BatchCapacityV2 = BatchCapacityV2(),
) {
    val run = fixture.bind()
    val ledger = AttemptLedgerV2(run)
    var previews = 0; var effects = 0; var rechecks = 0
    var epochMatches = true; var allowRecheck = true
    var onRecheck: (() -> Unit)? = null
    var bindingReads = 0
    var onBindingRead: (() -> Unit)? = null
    var auditBytes = 1L; var sourceBytes = 1L; var traceRecords = 1L
    val authority = object : ToolAuthorityV2 {
        override fun preview(proposal: ToolProposalV2, arguments: kotlinx.serialization.json.JsonObject,
            policy: ToolRequestPolicyV2, inventory: ToolInventoryV2): EffectPreviewV2? {
            previews++
            val path = ToolPathV2("project", arguments.getValue("path").jsonPrimitive.content)
            if (!policy.allows(path, ToolOperationV2.WRITE) || !inventory.contains(path)) return null
            return EffectPreviewV2(path, ToolOperationV2.WRITE, resultCeiling, auditBytes, 1, sourceBytes, 1, traceRecords)
        }
        override fun currentBindingCommitment(): String {
            bindingReads++; onBindingRead?.invoke()
            return if (epochMatches) run.bindingCommitment else "0".repeat(64)
        }
        override fun recheck(effect: EffectPreviewV2, policy: ToolRequestPolicyV2, inventory: ToolInventoryV2): Boolean {
            rechecks++; onRecheck?.invoke(); return allowRecheck
        }
    }
    val batch = BuiltinToolBatchV2(ledger, fixture.policy, fixture.inventory, authority, EncodedSpaceV2 { _, _ -> layout }, initialCapacity)
    fun response(calls: List<ToolProposalV2> = listOf(proposal()), settle: Boolean = true,
        outcome: AttemptOutcomeV2 = AttemptOutcomeV2.COMPLETED, usage: ReportedModelUsageV1? = null,
        finish: ModelFinishReason = if (calls.isEmpty()) ModelFinishReason.STOP else ModelFinishReason.TOOL_CALLS): ModelResponseV2 {
        val ordinal = ledger.counters().requests.toInt() + 1
        val lease = ledger.reserve(UUID(0, ordinal.toLong()), ordinal, 100, 64)
        ledger.markDispatchIntent(lease, ledger.durableSequence() + 1)
        val call = ledger.call(lease, ByteArray(100))
        val observed = ObservedLocalCountersV2(20, 2, 2, 2)
        call.meter.beforeDelivery(observed)
        val turn = ValidatedResponsesTurnV1(call, "response_$ordinal", listOf("{}".toByteArray()), calls, "f".repeat(64))
        val response = ModelResponseV2("ok", finish, turn, usage)
        if (settle) ledger.settle(lease, observed, usage, outcome)
        return response
    }
    fun execute(admitted: AdmittedBatchV2, text: String = "ok"): List<ToolResultV2> = batch.execute(admitted) { _, _, collector -> effects++; collector.append(text) }
    companion object {
        fun proposal(id: String = "call_1", path: String = "source.c", namespace: String? = "decomp", name: String = "write",
            args: String = """{"path":"$path","text":"new"}""", caller: String? = null, async: Boolean = false) =
            ToolProposalV2(namespace, name, id, "item_$id", args, caller, async)
    }
}

class BuiltinToolBatchV2Test {
    @Test fun `remaining invocation input is reserved before any tool effect at exact fit and one over`() {
        // Initial request consumes 100; the complete next request upper bound is 100 + 32 + 6*16.
        val exact = BatchFixtureV2(V2Fixture(local = LocalBudgetV1(inputUnits = 328)))
        val permit = exact.batch.previewBatch(exact.response())
        assertEquals(228L, permit.reservation.nextRequestBytes)
        exact.execute(permit)
        val next = exact.ledger.reserve(UUID(0, 2), 2, 228, 64)
        exact.ledger.markDispatchIntent(next, exact.ledger.durableSequence() + 1)
        assertEquals(328L, exact.ledger.counters().input)
        assertEquals(1, exact.effects)
        for (limit in listOf(327L, 200L)) {
            val over = BatchFixtureV2(V2Fixture(local = LocalBudgetV1(inputUnits = limit)))
            val failure = assertFailsWith<ModelProviderException> { over.execute(over.batch.previewBatch(over.response())) }
            assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED, failure.kind)
            assertEquals(0, over.effects)
            assertEquals(100L, over.ledger.counters().input)
        }
    }
    @Test fun `next input reservation stays owned through the batch and bounds its consuming request`() {
        val f = BatchFixtureV2(V2Fixture(local = LocalBudgetV1(inputUnits = 1000)))
        val permit = f.batch.previewBatch(f.response())
        assertFailsWith<ModelProviderException> { f.ledger.reserve(UUID(0, 2), 2, 100, 64) }
        f.execute(permit)
        // There is general budget headroom, but no authority to exceed this batch's reserved framing.
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED,
            assertFailsWith<ModelProviderException> { f.ledger.reserve(UUID(0, 2), 2, 229, 64) }.kind)
        assertEquals(1, f.effects)
    }
    @Test fun `consuming a smaller next request releases only unused input reservation`() {
        val f = BatchFixtureV2(V2Fixture(local = LocalBudgetV1(inputUnits = 1000)))
        f.execute(f.batch.previewBatch(f.response()))
        val next = f.ledger.reserve(UUID(0, 2), 2, 200, 64)
        assertEquals(100L, f.ledger.counters().input) // Reservation is not observed usage.
        f.ledger.markDispatchIntent(next, f.ledger.durableSequence() + 1)
        assertEquals(300L, f.ledger.counters().input)
        f.ledger.settle(next, ObservedLocalCountersV2(), null, AttemptOutcomeV2.COMPLETED)
        val later = f.ledger.reserve(UUID(0, 3), 3, 400, 64)
        f.ledger.markDispatchIntent(later, f.ledger.durableSequence() + 1)
        assertEquals(700L, f.ledger.counters().input)
    }
    @Test fun `deadline and cancellation during final binding read prevent the effect`() {
        for (cancel in listOf(false, true)) {
            val source = AgentCancellationSource()
            val f = BatchFixtureV2(V2Fixture(cancellation = source.cancellation))
            val permit = f.batch.previewBatch(f.response())
            f.onBindingRead = {
                if (f.bindingReads == 2) {
                    if (cancel) source.cancel() else f.fixture.now = java.time.Duration.ofMinutes(20).toNanos()
                }
            }
            val failure = assertFailsWith<ModelProviderException> { f.execute(permit) }
            assertEquals(if (cancel) ModelFailureKind.CANCELLED else ModelFailureKind.TIMEOUT, failure.kind)
            assertEquals(2, f.bindingReads)
            assertEquals(0, f.effects)
        }
    }
    @Test fun `later forbidden path schema namespace ID or caller executes zero tools`() {
        val invalid = listOf(
            BatchFixtureV2.proposal("call_2", path = "header.h"), BatchFixtureV2.proposal("call_2", path = "../source.c"),
            BatchFixtureV2.proposal("call_2", args = """{"path":"source.c","text":17}"""),
            BatchFixtureV2.proposal("call_2", args = """{"path":"source.c","text":"ok","extra":true}"""),
            BatchFixtureV2.proposal("call_2", namespace = null), BatchFixtureV2.proposal("call_2", namespace = "foreign"),
            BatchFixtureV2.proposal("call_2", name = "decomp.write"), BatchFixtureV2.proposal("call_2", name = "shell"),
            BatchFixtureV2.proposal("call_2", caller = "programmatic"), BatchFixtureV2.proposal("call_2", async = true),
            BatchFixtureV2.proposal("call_1"), BatchFixtureV2.proposal("bad.id"),
        )
        invalid.forEach { bad ->
            val f = BatchFixtureV2(); val response = f.response(listOf(BatchFixtureV2.proposal(), bad))
            assertFailsWith<ModelProviderException> { f.execute(f.batch.previewBatch(response)) }
            assertEquals(0, f.effects); assertEquals(0, f.rechecks)
        }
    }
    @Test fun `strict parser rejects duplicate keys depth malformed Unicode and nonintegral integer fields`() {
        listOf("""{"path":"source.c","text":"a","text":"b"}""", "{}{}", "{", """{"path":"source.c","text":"\uD800"}""")
            .forEach { raw ->
                val f = BatchFixtureV2()
                assertFailsWith<ModelProviderException> { f.batch.previewBatch(f.response(listOf(BatchFixtureV2.proposal(args = raw)))) }
                assertEquals(0, f.effects)
            }
        val schema = ToolSchemaV2.compile("""{"type":"object","properties":{"n":{"type":"integer","minimum":0,"maximum":10}},"required":["n"],"additionalProperties":false}""")
        listOf("1.5", "1.0", "1e0", "\"1\"", "9223372036854775808", "-1", "11").forEach { n -> assertFalse(schema.accepts(parseToolObjectV2("{\"n\":$n}", 1024))) }
        assertTrue(schema.accepts(parseToolObjectV2("{\"n\":10}", 1024)))
        val deep = "{\"a\":".repeat(33) + "0" + "}".repeat(33)
        assertFailsWith<ModelProviderException> { parseToolObjectV2(deep, 4096) }
    }
    @Test fun `batch simulates repetitions and remaining tool count before effects`() {
        val f = BatchFixtureV2()
        val repeated = (1..4).map { BatchFixtureV2.proposal("call_$it") }
        assertFailsWith<ModelProviderException> { f.execute(f.batch.previewBatch(f.response(repeated))) }
        assertEquals(0, f.effects)
        val capped = BatchFixtureV2(V2Fixture(legacy = decompengine.agent.AgentExecutionLimits(maxToolCalls = 1)))
        assertFailsWith<ModelProviderException> { capped.batch.previewBatch(capped.response(repeated.take(2))) }
        assertEquals(0, capped.effects)
    }
    @Test fun `canonical repetition treats object member order equally`() {
        val f = BatchFixtureV2(V2Fixture(local = LocalBudgetV1(maxIdenticalAction = 1)))
        val reordered = BatchFixtureV2.proposal("call_2", args = """{"text":"new","path":"source.c"}""")
        assertFailsWith<ModelProviderException> { f.batch.previewBatch(f.response(listOf(BatchFixtureV2.proposal(), reordered))) }
        assertEquals(0, f.effects)
    }
    @Test fun `checked sixfold encoded reservation accepts exact capacity and rejects one over`() {
        val budget = LocalBudgetV1(contextBytes = 1024, historyReserveBytes = 256, continuationBytes = 1024,
            requestBytes = 768, toolResultBytes = 64)
        val calls = listOf(BatchFixtureV2.proposal(), BatchFixtureV2.proposal("call_2"))
        val exact = BatchFixtureV2(V2Fixture(local = budget), EncodedLayoutV2(512, 64), 16)
        val admitted = exact.batch.previewBatch(exact.response(calls))
        assertEquals(768L, admitted.reservation.nextRequestBytes)
        val text = "\u0001".repeat(16) // every byte needs six JSON bytes
        val results = exact.execute(admitted, text)
        assertEquals(listOf("call_1", "call_2"), results.map { it.callId }); assertEquals(2, exact.effects)
        val over = BatchFixtureV2(V2Fixture(local = budget), EncodedLayoutV2(513, 64), 16)
        assertFailsWith<ModelProviderException> { over.batch.previewBatch(over.response(calls)) }; assertEquals(0, over.effects)
    }
    @Test fun `quotes controls and multibyte result accounting is bounded before retention`() {
        val f = BatchFixtureV2(resultCeiling = 4)
        val results = f.execute(f.batch.previewBatch(f.response()), "\"\n\r\t")
        assertEquals(1, results.size); assertEquals(6L, f.ledger.counters().displayed) // two assistant bytes plus four result bytes
        val over = BatchFixtureV2(resultCeiling = 3)
        assertFailsWith<ModelProviderException> { over.execute(over.batch.previewBatch(over.response()), "😀") }
        assertEquals(LedgerStateV2.INDETERMINATE, over.ledger.state())
        assertFailsWith<ModelProviderException> { over.response() }
    }
    @Test fun `audit disk trace and long overflow reservation failures precede effects`() {
        val fixtures = listOf(
            BatchFixtureV2(V2Fixture(local = LocalBudgetV1(evidenceBytes = 12_304))),
            BatchFixtureV2(V2Fixture(local = LocalBudgetV1(privateDiskBytes = 12_304))),
            BatchFixtureV2(V2Fixture(local = LocalBudgetV1(traceRecords = 4)), initialCapacity = BatchCapacityV2(usedTraceRecords = 1)),
            BatchFixtureV2(layout = EncodedLayoutV2(Long.MAX_VALUE, 1)),
            BatchFixtureV2().also { it.sourceBytes = Long.MAX_VALUE },
        )
        fixtures.forEach { f -> assertFailsWith<ModelProviderException> { f.batch.previewBatch(f.response()) }; assertEquals(0, f.effects) }
    }
    @Test fun `epoch cancellation and dynamic broker denial recheck before each effect`() {
        val stale = BatchFixtureV2(); val permit = stale.batch.previewBatch(stale.response()); stale.epochMatches = false
        assertFailsWith<ModelProviderException> { stale.execute(permit) }; assertEquals(0, stale.effects)
        val race = BatchFixtureV2(); val racePermit = race.batch.previewBatch(race.response()); race.onRecheck = { race.epochMatches = false }
        assertFailsWith<ModelProviderException> { race.execute(racePermit) }; assertEquals(0, race.effects)
        val source = AgentCancellationSource(); val cancelled = BatchFixtureV2(V2Fixture(cancellation = source.cancellation))
        val cancelPermit = cancelled.batch.previewBatch(cancelled.response()); source.cancel()
        assertFailsWith<ModelProviderException> { cancelled.execute(cancelPermit) }; assertEquals(0, cancelled.effects)
        val dynamic = BatchFixtureV2(); val two = dynamic.batch.previewBatch(dynamic.response(listOf(BatchFixtureV2.proposal(), BatchFixtureV2.proposal("call_2"))))
        assertFailsWith<ModelProviderException> { dynamic.batch.execute(two) { _, _, collector -> dynamic.effects++; collector.append("ok"); dynamic.allowRecheck = false } }
        assertEquals(1, dynamic.effects); assertEquals(4L, dynamic.ledger.counters().displayed)
        assertEquals(LedgerStateV2.INDETERMINATE, dynamic.ledger.state())
        assertFailsWith<ModelProviderException> { dynamic.response() } // candidate remains unaccepted, no claimed rollback
    }
    @Test fun `historical foreign unfinished failed refused and overdrawn responses authorize nothing`() {
        val current = BatchFixtureV2(); val historic = current.response(); current.response(listOf(BatchFixtureV2.proposal("call_2")))
        assertFailsWith<ModelProviderException> { current.batch.previewBatch(historic) }
        val foreign = BatchFixtureV2(); val target = BatchFixtureV2()
        assertFailsWith<ModelProviderException> { target.batch.previewBatch(foreign.response()) }
        listOf(AttemptOutcomeV2.FAILED, AttemptOutcomeV2.INCOMPLETE).forEach { outcome ->
            val f = BatchFixtureV2(); assertFailsWith<ModelProviderException> { f.batch.previewBatch(f.response(outcome = outcome)) }; assertEquals(0, f.effects)
        }
        val unfinished = BatchFixtureV2(); assertFailsWith<ModelProviderException> { unfinished.batch.previewBatch(unfinished.response(settle = false)) }
        val refused = BatchFixtureV2(); assertFailsWith<ModelProviderException> { refused.batch.previewBatch(refused.response(finish = ModelFinishReason.REFUSED)) }
        val overdraw = BatchFixtureV2(); assertFailsWith<ModelProviderException> { overdraw.batch.previewBatch(overdraw.response(usage = ReportedModelUsageV1(101, 0, 101))) }
    }
    @Test fun `batch is exact once and call IDs cannot be reused in a later response`() {
        val f = BatchFixtureV2(); val permit = f.batch.previewBatch(f.response()); f.execute(permit)
        assertFailsWith<ModelProviderException> { f.execute(permit) }; assertEquals(1, f.effects)
        assertFailsWith<ModelProviderException> { f.batch.previewBatch(f.response()) }; assertEquals(1, f.effects)
        assertFailsWith<ModelProviderException> { BuiltinToolBatchV2(f.ledger, f.fixture.policy, f.fixture.inventory, f.authority, EncodedSpaceV2 { _, _ -> f.layout }) }
    }
    @Test fun `bounded collector cannot be reused after executor returns`() {
        val f = BatchFixtureV2(); var retained: BoundedToolResultV2? = null
        f.batch.execute(f.batch.previewBatch(f.response())) { _, _, out -> retained = out; out.append("ok") }
        assertFailsWith<ModelProviderException> { retained!!.append("late") }
    }
    @Test fun `copied batch fields and forged run do not mint host permits`() {
        val f = BatchFixtureV2(); val real = f.batch.previewBatch(f.response())
        val forged = AdmittedBatchV2.mint(f.batch, real.response, real.proposals, real.effects, real.reservation)
        assertFailsWith<ModelProviderException> { f.execute(forged) }; assertEquals(0, f.effects)
        f.execute(real); assertEquals(1, f.effects)
        val unissuedRun = AdmittedModelRunV2.mint(f.run.checked, f.run.binding)
        assertFailsWith<ModelProviderException> { AttemptLedgerV2(unissuedRun) }
    }

}
