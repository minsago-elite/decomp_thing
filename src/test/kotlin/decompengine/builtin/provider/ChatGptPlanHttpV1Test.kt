package decompengine.builtin.provider

import decompengine.agent.*
import decompengine.builtin.*
import decompengine.project.GeneratedCValidationHostSafetyLimits
import decompengine.repair.RepairResourceBudget
import kotlinx.serialization.json.JsonObject
import java.time.Duration
import java.time.Instant
import java.util.UUID
import kotlin.test.*

/** Exact controlled state shared by A's callbacks, C0, and the callback-free C3 fence. */
internal class C3State : OfflineInvocationFenceV1 {
    var now = 0L
    var end = Duration.ofMinutes(20).toNanos()
    var cancelled = false
    var commitment = "0".repeat(64)
    var generation = 0L
    var revision = 0L
    override fun snapshot() = OfflineInvocationStateV1(maxOf(0, end - now), cancelled, commitment, generation, revision)
}
internal class C3Reply(val status: Int = 200, val body: ByteArray = C3Wire.text(),
    val fields: List<Pair<String, String>> = emptyList(), var chunk: Int = 8192) {
    var headersPending = 0
    var readPending = 0
    var retains = 0
    var forever = false
    var throwClose = 0
    var closeFailure = false
    var throwDispatch = false
    var throwRead = false
    var throwAllocate = false
    var overrideCount: Int? = null
    var factsOffset = 0L
    var send = OfflineSendFactV1.SENT
    var closed = false
    var dispatches = 0
    var closes = 0
    var reads = 0
    var delivered = 0
    val demands = ArrayList<Int>()
    val waits = ArrayList<Long>()
    var sent: ByteArray? = null
    var timeouts: CallTimeoutsV2? = null
    var endpoint: OfflineEndpointV1? = null
    companion object {
        fun catalog(slug: String = "fixture-model") = C3Reply(body = """{"models":[{"slug":"$slug","display_name":"Fixture","visibility":"list"}]}""".toByteArray(), fields = listOf("Content-Type" to "application/json"))
    }
}
internal object C3Wire {
    fun stream(items: List<String>, usage: String? = null, terminal: String = "completed", ending: String = "\n"): ByteArray {
        var sequence = 0
        fun event(type: String, fields: String) = "data: {\"type\":\"$type\",\"sequence_number\":${sequence++},$fields}$ending$ending"
        val out = StringBuilder(event("response.created", "\"response\":${C2Fixture.envelope("in_progress")}"))
        items.forEachIndexed { i, raw ->
            out.append(event("response.output_item.added", "\"output_index\":$i,\"item\":$raw"))
            out.append(event("response.output_item.done", "\"output_index\":$i,\"item\":$raw"))
        }
        out.append(event("response.$terminal", "\"response\":${C2Fixture.envelope(terminal, items, usage)}"))
        return out.toString().toByteArray()
    }
    fun text(text: String = "hello", usage: String? = null) = stream(listOf(C2Fixture.message(text)), usage)
}
internal class C3Fixture(val budget: LocalBudgetV1 = LocalBudgetV1(), val durabilityAt: Int = 0,
    val legacy: AgentExecutionLimits = AgentExecutionLimits(), val requirement: GenerationRequirementV2 = GenerationRequirementV2.ElectLocalAcceptance()) {
    val state = C3State()
    var hook: (String) -> Unit = {}
    val trace = ArrayList<String>()
    fun edge(name: String) { trace.add(name); hook(name) }
    val vf = V2Fixture()
    val secrets = ChatGptPlanSecretsV1()
    val factory = ModelRunAdmissionV2({ listOf(V2Fixture.tool()) }, RunCommitmentsV2("c".repeat(64), "d".repeat(64),
        "e".repeat(64), vf.inventory.commitment, vf.policy.commitment), NanoClockV2 { edge("clock"); state.now }, state.end,
        AgentCancellation { edge("cancellation"); state.cancelled })
    lateinit var run: AdmittedModelRunV2
    lateinit var ledger: AttemptLedgerV2
    lateinit var harness: ChatGptPlanOfflineHarness
    val codec = ChatGptPlanRequestV1(secrets)
    val replies = ArrayDeque<C3Reply>()
    val allocated = ArrayList<C3Reply>()
    var allocations = 0
    var acquire = 0
    var renew = 0
    var expired = false
    var missingScopes = false
    var wrongBinding = false
    var publication = 0
    val events = ArrayList<ModelEventV2>()
    val prior = listOf(ModelMessageV2(ModelRole.USER, "fixture task"))
    var previews = 0
    var effects = 0
    private fun credential(): OfflinePlanCredentialV1 = OfflinePlanCredentialV1(if (wrongBinding)
        AccountBindingV2(UUID(7, 8), vf.binding.issuer, vf.binding.hostId, vf.binding.issuedClient, vf.binding.verifiedSubjectCommitment, 1, "fixture-model") else vf.binding,
        state.generation, Instant.ofEpochSecond(2_000_000_000), if (missingScopes) emptySet() else OfflineCredentialAcquisitionV1.REQUIRED_SCOPES,
        object : OfflineBearerV1 {})
    val tokens = object : OfflinePlanTokenSourceV1 {
        override fun acquire(run: AdmittedModelRunV2): OfflineCredentialAcquisitionV1 {
            acquire++; edge("acquire")
            return if (expired) OfflineCredentialAcquisitionV1.Expired(state.commitment, state.generation) else OfflineCredentialAcquisitionV1.Ready(credential())
        }
        override fun renew(run: AdmittedModelRunV2, expectedGeneration: Long): OfflinePlanCredentialV1 {
            assertEquals(state.generation, expectedGeneration); renew++; state.generation++; edge("renew"); return credential()
        }
        override fun recheck(run: AdmittedModelRunV2, credential: OfflinePlanCredentialV1) {
            edge("recheck"); credential.requireFor(run)
            if (state.generation != credential.generation || state.commitment != run.bindingCommitment) v2Fail(ModelFailureKind.AUTHORIZATION)
        }
        override fun registerFixtureSecrets(credential: OfflinePlanCredentialV1, guard: ChatGptPlanSecretsV1) {
            guard.registerSynthetic("fixture-secret-${credential.generation}"); edge("register")
        }
    }
    val port = object : OfflineHttpPortV1 {
        override fun allocate(): OfflineHttpExchangeV1 {
            allocations++
            val r = replies.removeFirst(); allocated.add(r)
            if (r.throwAllocate) throw IllegalStateException("private fixture text")
            return object : OfflineHttpExchangeV1 {
                var offset = 0
                override fun dispatch(endpoint: OfflineEndpointV1, bearer: OfflineBearerV1, entity: ByteArray?, timeouts: CallTimeoutsV2) {
                    check(!r.closed && r.dispatches++ == 0); r.endpoint = endpoint; r.sent = entity?.copyOf(); r.timeouts = timeouts
                    edge("dispatch:$endpoint")
                    if (r.throwDispatch) throw IllegalStateException("private fixture text")
                }
                override fun headers(maxWaitNanos: Long): OfflineHeadersV1? {
                    check(!r.closed); r.waits.add(maxWaitNanos); edge("headers:${r.endpoint}")
                    if (r.headersPending-- > 0) return null
                    return OfflineHeadersV1(r.status, r.fields)
                }
                override fun read(into: ByteArray, demand: Int, maxWaitNanos: Long): Int {
                    check(!r.closed); assertEquals(8192, into.size); assertTrue(demand in 1..8192)
                    r.demands.add(demand); r.waits.add(maxWaitNanos); r.reads++
                    if (r.throwRead) { edge("read:${r.endpoint}"); throw IllegalStateException("private fixture text") }
                    val n = if (r.readPending-- > 0) 0 else if (offset == r.body.size) -1 else minOf(demand, r.chunk, r.body.size - offset)
                    if (n > 0) { r.body.copyInto(into, 0, offset, offset + n); offset += n; r.delivered = offset }
                    edge("read:${r.endpoint}"); return r.overrideCount ?: n
                }
                override fun delivery() = OfflineDeliveryFactsV1(r.send,
                    if (r.send in setOf(OfflineSendFactV1.SCRIPTED_ZERO_SEND, OfflineSendFactV1.NEVER_DISPATCHED)) 0 else r.sent?.size?.toLong() ?: 0,
                    offset.toLong() + r.factsOffset)
                override fun closeStep(maxWaitNanos: Long): OfflineCloseV1 {
                    check(!r.closed); r.closes++; r.waits.add(maxWaitNanos); edge("close:${r.endpoint}")
                    if (r.throwClose-- > 0) throw IllegalStateException("private close")
                    val retained = r.forever || r.retains-- > 0
                    if (!retained) r.closed = true
                    return OfflineCloseV1(if (retained) OfflineCloseFactV1.RETAINED else OfflineCloseFactV1.CLOSED,
                        if (r.closeFailure) ModelFailureKind.TRANSPORT else null)
                }
            }
        }
    }
    val http = BoundedChatGptPlanHttpV1(port, tokens, secrets, state) { edge("wall"); Instant.ofEpochSecond(1_800_000_000) }
    fun admit() {
        val checked = factory.checkCapabilities(vf.selection, requirement, ProviderCapabilitiesV2.siwc(), CallerRequirementsV2(legacy, budget),
            HostAdmissionLimitsV2(budget, GeneratedCValidationHostSafetyLimits()), ProfileAdmissionLimitsV2(budget, RepairResourceBudget()))
        run = factory.bind(checked, vf.binding); state.commitment = run.bindingCommitment
        state.end = minOf(state.end, state.now + run.budget.wallClock.toNanos())
        ledger = if (durabilityAt == 0) AttemptLedgerV2(run) else AttemptLedgerV2(run, LedgerModeV2.INJECTED_DURABILITY, object : DurableIntentPortV2 {
            override fun publish(record: DurableLedgerRecordV2) { publication++; edge("settlement:${record.attemptState}"); if (publication == durabilityAt) throw IllegalStateException("private publication") }
            override fun currentHead(runId: UUID): DurableLedgerRecordV2? = null
        })
        harness = ChatGptPlanOfflineHarness(ledger, tokens, http, codec, secrets, state)
    }
    fun start(ordinal: Int = 1, messages: List<ModelMessageV2> = prior, results: Map<ValidatedResponsesTurnV1, List<ToolResultV2>> = emptyMap()): OfflineTurnV1 =
        harness.start(ordinal, messages, results, ModelEventV2Sink {
            assertFalse(Thread.holdsLock(secrets)); events.add(it); edge(if (it is ModelEventV2.Finished) "Finished" else "sink")
        })
    fun drive(turn: OfflineTurnV1, steps: Int = 20000, advance: Long = 1_000_000): OfflineHttpValueV1 {
        repeat(steps) {
            val p = turn.step()
            if (p is OfflineHttpProgressV1.Closed) return p.value
            state.now += advance // explicit deterministic driver tick, never sleep or wall polling
        }
        error("bounded fixture driver exhausted")
    }
    fun batch(): BuiltinToolBatchV2 = BuiltinToolBatchV2(ledger, vf.policy, vf.inventory, object : ToolAuthorityV2 {
        override fun preview(proposal: ToolProposalV2, arguments: JsonObject, policy: ToolRequestPolicyV2, inventory: ToolInventoryV2): EffectPreviewV2 {
            previews++; edge("preview"); return EffectPreviewV2(vf.path, ToolOperationV2.WRITE, 16, 1, 1, 1, 1, 1)
        }
        override fun currentBindingCommitment(): String { edge("authority"); return run.bindingCommitment }
        override fun recheck(effect: EffectPreviewV2, policy: ToolRequestPolicyV2, inventory: ToolInventoryV2): Boolean { edge("authority-recheck"); return true }
    }, codec.encodedSpace(run, prior, emptyMap()))
    fun execute(r: ModelResponseV2, batch: BuiltinToolBatchV2 = batch()) = harness.executeCompleted(r, batch) { _, _, out -> effects++; out.append("ok") }
    fun completed(value: OfflineHttpValueV1) = assertIs<ChatGptAttemptResultV1.Completed>(assertIs<OfflineHttpValueV1.Attempt>(value).value)
    fun stopped(value: OfflineHttpValueV1) = assertIs<ChatGptAttemptResultV1.Stopped>(assertIs<OfflineHttpValueV1.Attempt>(value).value)
    fun script(vararg rs: C3Reply) { replies.addAll(rs) }
}

class ChatGptPlanHttpV1Test {
    @Test fun textClosesBeforeFinalSinkAndSettlesBeforeFinished() {
        val f = C3Fixture(); f.admit(); val r = C3Reply(body = C3Wire.text("fixture-")); f.script(C3Reply.catalog(), r)
        f.hook = { if (it == "Finished") { assertTrue(r.closed); assertEquals(LedgerStateV2.READY, f.ledger.state()); assertEquals(1, f.ledger.observations().size) } }
        val done = f.completed(f.drive(f.start())); assertEquals("fixture-", done.response.text)
        assertEquals(r.body.size.toLong(), f.ledger.counters().wire); assertEquals(8, f.ledger.counters().displayed)
        assertTrue(f.trace.indexOf("close:RESPONSES") < f.trace.indexOf("sink")); assertEquals(1, r.closes)
        assertTrue(r.demands.all { it in 1..8192 }); assertTrue(r.waits.all { it in 0..25_000_000 })
    }
    @Test fun absentAndUtf8MimeAcceptOnlyStrictSse() {
        for (fields in listOf(emptyList(), listOf("Content-Type" to "text/event-stream"), listOf("content-type" to "text/event-stream; charset=UTF-8"))) {
            val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply(fields = fields)); f.completed(f.drive(f.start()))
        }
        for (mime in listOf("", "application/json", "text/event-stream; charset=latin1", "text/event-stream; extra=x")) {
            val f = C3Fixture(); f.admit(); val r = C3Reply(fields = listOf("Content-Type" to mime)); f.script(C3Reply.catalog(), r)
            f.stopped(f.drive(f.start())); assertEquals(0, r.reads); assertTrue(r.closed); assertEquals(1, f.ledger.counters().requests)
        }
    }
    @Test fun malformedHeadersRejectBeforeBodyAndNeverRetry() {
        for (fields in listOf(listOf("Content-Type" to "text/event-stream", "Content-Type" to "text/event-stream"),
            listOf("Content-Encoding" to "gzip"), listOf("Content-Length" to "1", "Content-Length" to "1"),
            listOf("Content-Length" to "-1"), listOf("Content-Length" to "99999999999999999999"), listOf("Content-Length" to "4194305"))) {
            val f = C3Fixture(); f.admit(); val r = C3Reply(fields = fields); f.script(C3Reply.catalog(), r)
            f.stopped(f.drive(f.start())); assertTrue(r.closed); assertEquals(0, r.reads); assertEquals(1, r.dispatches)
        }
    }
    @Test fun headerCapsValidateBeforeCopy() {
        OfflineHeadersV1(200, listOf("a".repeat(128) to "b".repeat(4096)))
        for (fields in listOf(listOf("a".repeat(129) to "b"), listOf("a" to "b".repeat(4097)), List(65) { "a" to "b" }, List(4) { "a" to "b".repeat(4096) }))
            assertFailsWith<ModelProviderException> { OfflineHeadersV1(200, fields) }
        val exact = List(4) { "a" to "b".repeat(4091) }; OfflineHeadersV1(200, exact)
        assertFailsWith<ModelProviderException> { OfflineHeadersV1(200, exact.dropLast(1) + ("a" to "b".repeat(4092))) }
        val mutable = mutableListOf("a" to "b"); val h = OfflineHeadersV1(200, mutable); mutable.clear(); assertEquals(1, h.fields.size)
    }
    @Test fun everyUtf8AndCrlfBoundaryUsesBoundedReads() {
        val bytes = C3Wire.stream(listOf(C2Fixture.message("é😀")), ending = "\r\n")
        // A one-byte read splits every byte and every CR/LF, including both multibyte scalars.
        val f = C3Fixture(); f.admit(); val r = C3Reply(body = bytes, chunk = 1); f.script(C3Reply.catalog(), r)
        assertEquals("é😀", f.completed(f.drive(f.start())).response.text); assertEquals(r.delivered.toLong(), f.ledger.counters().wire); assertTrue(r.delivered >= bytes.size - 1)
    }
    @Test fun arrivalIsDebitedBeforeReadCancellationAndNeverTwice() {
        val f = C3Fixture(); f.admit(); val r = C3Reply(); f.script(C3Reply.catalog(), r)
        f.hook = { if (it == "read:RESPONSES") f.state.cancelled = true }
        val stopped = f.stopped(f.drive(f.start())); assertEquals(AttemptOutcomeV2.AMBIGUOUS, stopped.outcome)
        assertEquals(r.body.size.toLong(), f.ledger.counters().wire); assertEquals(r.body.size.toLong(), f.ledger.observations().single().local.wireBytes)
        assertEquals(f.run.budget.outputUnits, f.ledger.counters().output); assertTrue(r.closed); assertTrue(f.events.isEmpty())
    }
    @Test fun pendingHeadersAndReadsDoNotRefreshIdleDeadline() {
        val f = C3Fixture(LocalBudgetV1(idleTimeout = Duration.ofMillis(8))); f.admit(); val r = C3Reply().also { it.readPending = 20 }
        f.script(C3Reply.catalog(), r); f.stopped(f.drive(f.start())); assertTrue(r.closed); assertTrue(f.events.isEmpty()); assertEquals(0, f.ledger.counters().wire)
    }
    @Test fun badReadCountsAndContradictoryDeliveryNeverMintObservedBytesOrRefund() {
        for (count in listOf(-2, 8193)) {
            val f = C3Fixture(); f.admit(); val r = C3Reply().also { it.overrideCount = count }; f.script(C3Reply.catalog(), r)
            f.stopped(f.drive(f.start())); assertEquals(0, f.ledger.counters().wire); assertEquals(LedgerStateV2.INDETERMINATE, f.ledger.state()); assertTrue(r.closed)
        }
        val f = C3Fixture(); f.admit(); val r = C3Reply().also { it.factsOffset = 1 }; f.script(C3Reply.catalog(), r)
        f.stopped(f.drive(f.start())); assertEquals(0, r.reads); assertTrue(r.closed)
    }
    @Test fun retainedCloseNeverPublishesRetriesOrFinishedEvenAfterDeadline() {
        val f = C3Fixture(); f.admit(); val r = C3Reply().also { it.forever = true }; f.script(C3Reply.catalog(), r)
        val turn = f.start(); repeat(20) { assertIs<OfflineHttpProgressV1.Pending>(turn.step()); f.state.now += 1_000_000 }
        val reads = r.reads; turn.cancel(); f.state.now = f.state.end
        repeat(4) { assertTrue(assertIs<OfflineHttpProgressV1.Pending>(turn.step()).closing) }
        assertFalse(r.closed); assertEquals(reads, r.reads); assertEquals(1, r.dispatches); assertEquals(LedgerStateV2.ACTIVE, f.ledger.state())
        assertTrue(f.events.none { it is ModelEventV2.Finished }); assertTrue(f.ledger.observations().isEmpty()); assertEquals(0, r.waits.last())
        r.forever = false; f.stopped(f.drive(turn)); assertTrue(r.closed)
    }
    @Test fun closeThrowThenRetentionThenClosedNeverRestoresSuccess() {
        val f = C3Fixture(); f.admit(); val r = C3Reply().also { it.throwClose = 1; it.retains = 2 }; f.script(C3Reply.catalog(), r)
        val value = assertIs<OfflineHttpValueV1.Attempt>(f.drive(f.start())); assertEquals(ModelFailureKind.TRANSPORT, value.closeFailure)
        assertIs<ChatGptAttemptResultV1.Stopped>(value.value); assertEquals(4, r.closes); assertTrue(r.closed)
        assertTrue(f.events.none { it is ModelEventV2.Finished }); assertEquals(1, f.ledger.observations().size)
    }
    @Test fun closedFailureAndCancelInsideCloseRetainValidatedUsage() {
        val f = C3Fixture(); f.admit(); val r = C3Reply(body = C3Wire.text(usage = C2Fixture.usage())).also { it.closeFailure = true }
        f.script(C3Reply.catalog(), r); f.hook = { if (it == "close:RESPONSES") f.state.cancelled = true }
        val value = assertIs<OfflineHttpValueV1.Attempt>(f.drive(f.start())); assertEquals(ModelFailureKind.TRANSPORT, value.closeFailure)
        assertNotNull(value.value.reported); assertTrue(r.closed); assertTrue(f.events.none { it is ModelEventV2.Finished })
    }
    @Test fun contentLengthTerminalAndEofMismatchNeverSucceed() {
        for (delta in listOf(-1, 1)) {
            val body = C3Wire.text(); val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply(body = body, fields = listOf("Content-Length" to "${body.size + delta}")))
            f.stopped(f.drive(f.start())); assertTrue(f.events.none { it is ModelEventV2.Finished })
        }
    }
    @Test fun catalogAndErrorCapPlusOneProbeIsBounded() {
        for (error in listOf(false, true)) {
            val cap = if (error) 32768 else 1048576
            val f = C3Fixture(); f.admit()
            val r = C3Reply(status = if (error) 503 else 200, body = ByteArray(cap + 100) { ' '.code.toByte() }, fields = listOf("Content-Type" to "application/json"))
            if (error) f.script(C3Reply.catalog(), r) else f.script(r)
            f.drive(f.start()); assertEquals(cap + 1L, if (error) f.ledger.counters().wire else r.demands.dropLast(1).sum().toLong() + 1)
            assertEquals(1, r.demands.last()); assertTrue(r.closed)
        }
    }
    @Test fun catalogExactCapAndSlugFilterAndMissingMime() {
        val small = C3Reply.catalog().body
        val f = C3Fixture(); f.admit(); val body = small + ByteArray(1048576 - small.size) { ' '.code.toByte() }
        f.script(C3Reply(body = body, fields = listOf("Content-Type" to "application/json")), C3Reply()); f.completed(f.drive(f.start()))
        val g = C3Fixture(); g.admit(); g.script(C3Reply(body = small)); assertIs<OfflineHttpValueV1.CatalogFailure>(g.drive(g.start())); assertEquals(0, g.ledger.counters().requests)
    }
    @Test fun directHttpNestedStepAndStartLatchRevocationWithoutC3Monitors() {
        for (stage in listOf("dispatch:RESPONSES", "headers:RESPONSES", "read:RESPONSES", "close:RESPONSES", "sink")) {
            for (start in listOf(true, false)) {
                val f = C3Fixture(); f.admit()
                val credential = (f.tokens.acquire(f.run) as OfflineCredentialAcquisitionV1.Ready).credential
                f.tokens.registerFixtureSecrets(credential, f.secrets)
                val body = f.codec.encode(f.run, f.prior, emptyMap()).encoded()
                val lease = f.ledger.reserve(UUID.randomUUID(), 1, body.size.toLong(), 100)
                f.ledger.markDispatchIntent(lease, 1); val call = f.ledger.call(lease, body)
                val reply = C3Reply(); f.script(reply); var hit = false
                val op = f.http.exchange(call, credential, ModelEventV2Sink { assertFalse(Thread.holdsLock(f.secrets)); f.edge("sink") })
                f.hook = { if (it == stage && !hit) { hit = true; try {
                    if (start) f.http.exchange(call, credential, ModelEventV2Sink {}) else op.step()
                } catch (_: ModelProviderException) { } } }
                var closed: OfflineHttpProgressV1.Closed? = null
                repeat(20) { if (closed == null) closed = op.step() as? OfflineHttpProgressV1.Closed }
                assertTrue(hit, stage); val value = assertIs<OfflineHttpValueV1.Attempt>(assertNotNull(closed).value)
                assertIs<ChatGptAttemptResultV1.Stopped>(value.value); assertTrue(reply.closed); assertEquals(1, reply.dispatches)
            }
        }
    }
    @Test fun errorExactCapAndCatalogEntryLimitHavePositiveAndNegativeControls() {
        val f = C3Fixture(); f.admit()
        f.script(C3Reply.catalog(), C3Reply(429, "{}".toByteArray() + ByteArray(32766) { ' '.code.toByte() }))
        assertEquals(ModelFailureKind.RATE_LIMIT, f.stopped(f.drive(f.start())).kind); assertEquals(32768, f.ledger.counters().wire)
        for (n in listOf(1024, 1025)) {
            val g = C3Fixture(); g.admit()
            val rows = (0 until n).joinToString(",") { """{"slug":"${if (it == 0) "fixture-model" else "model-$it"}","display_name":"Fixture","visibility":"list"}""" }
            g.script(C3Reply(body = """{"models":[$rows]}""".toByteArray(), fields = listOf("Content-Type" to "application/json")), C3Reply())
            val value = g.drive(g.start()); if (n == 1024) g.completed(value) else { assertIs<OfflineHttpValueV1.CatalogFailure>(value); assertEquals(0, g.ledger.counters().requests) }
        }
    }
    @Test fun sidebandCapIsSharedAcrossOrdinalsAndNeverInferenceWire() {
        val f = C3Fixture(); f.admit(); val small = C3Reply.catalog().body
        fun catalog() = C3Reply(body = small + ByteArray(1048576 - small.size) { ' '.code.toByte() }, fields = listOf("Content-Type" to "application/json"))
        val first = C3Reply(); val second = C3Reply(); val third = catalog()
        f.script(catalog(), first, catalog(), second, third)
        f.completed(f.drive(f.start())); f.completed(f.drive(f.start(2)))
        assertIs<OfflineHttpValueV1.CatalogFailure>(f.drive(f.start(3))); assertEquals(1, third.delivered)
        assertEquals(first.delivered.toLong() + second.delivered, f.ledger.counters().wire); assertEquals(2, f.ledger.counters().requests)
    }
    @Test fun completedPrivateTextCannotEscapeRegistrationDuringPhysicalClose() {
        val f = C3Fixture(); f.admit(); f.script(C3Reply.catalog(), C3Reply())
        f.hook = { if (it == "close:RESPONSES") f.secrets.registerSynthetic("hello") }
        assertEquals(ModelFailureKind.SECRET_EXPOSURE, f.stopped(f.drive(f.start())).kind)
        assertTrue(f.events.isEmpty()); assertEquals(0, f.previews)
    }
    @Test fun decodedOverdrawAndDisplayAreAbsoluteObservations() {
        val f = C3Fixture(LocalBudgetV1(outputUnits = 4)); f.admit(); val r = C3Reply(); f.script(C3Reply.catalog(), r)
        f.stopped(f.drive(f.start())); assertEquals(5, f.ledger.counters().output); assertEquals(5, f.ledger.observations().single().local.decodedOutputBytes)
        assertEquals(r.delivered.toLong(), f.ledger.counters().wire); assertTrue(f.events.isEmpty()); assertTrue(r.closed)
    }

    @Test fun contradictoryArrivalFactsNeverPublishCountersAheadOfActualLedger() {
        val f = C3Fixture(); f.admit(); val r = C3Reply(); f.script(C3Reply.catalog(), r)
        f.hook = { if (it == "read:RESPONSES") r.factsOffset = 1 }
        val stopped = f.stopped(f.drive(f.start()))
        assertEquals(ModelFailureKind.MALFORMED_RESPONSE, stopped.kind)
        assertEquals(f.ledger.observations().single().local, stopped.local)
        assertEquals(0, f.ledger.counters().wire); assertTrue(r.closed); assertEquals(1, f.ledger.counters().requests)
    }

}
