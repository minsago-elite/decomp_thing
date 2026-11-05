package decompengine.builtin.provider

import decompengine.agent.AgentCancellationSource
import decompengine.builtin.*
import kotlinx.serialization.json.*
import java.time.Duration
import java.util.UUID
import kotlin.test.*

internal class C2Fixture(val fixture: V2Fixture = V2Fixture(), reserve: Long = 4096, callback: ((ModelEventV2) -> Unit)? = null) {
    val run = fixture.bind()
    val ledger = AttemptLedgerV2(run)
    val secrets = ChatGptPlanSecretsV1().also { it.registerSynthetic("fixture-original-secret"); it.registerSynthetic("fixture-rotated-secret") }
    val codec = ChatGptPlanRequestV1(secrets)
    val prior = listOf(ModelMessageV2(ModelRole.USER, "fixture task"))
    val body = codec.encode(run, prior, emptyMap()).encoded()
    val lease = ledger.reserve(UUID(11, 12), 1, body.size.toLong(), reserve)
    val call = run { ledger.markDispatchIntent(lease, ledger.durableSequence() + 1); ledger.call(lease, body) }
    val events = ArrayList<ModelEventV2>()
    var effects = 0
    var previews = 0
    val session = ChatGptPlanResponsesV1.start(call, secrets, ModelEventV2Sink { events.add(it); callback?.invoke(it) })
    var sequence = 0
    fun event(type: String, fields: String, number: Int = sequence++): String = """{"type":"$type","sequence_number":$number,$fields}"""
    fun send(json: String) = sendBytes("data: $json\n\n".toByteArray())
    fun sendBytes(bytes: ByteArray, chunk: Int = 8192) {
        var i = 0
        while (i < bytes.size && session.readDemand() != 0) {
            val n = minOf(bytes.size - i, chunk, session.readDemand()); session.feed(bytes, i, n); i += n
        }
    }
    fun created() = send(event("response.created", "\"response\":${envelope("in_progress")}"))
    fun added(raw: String, index: Int = 0) = send(event("response.output_item.added", "\"output_index\":$index,\"item\":$raw"))
    fun done(raw: String, index: Int = 0) = send(event("response.output_item.done", "\"output_index\":$index,\"item\":$raw"))
    fun terminal(items: List<String>, usage: String? = null, type: String = "completed") = send(event("response.$type", "\"response\":${envelope(type, items, usage)}"))
    fun complete(text: String = "hello", usage: String? = null): ChatGptAttemptResultV1.Completed {
        created(); added(message("", status = "in_progress")); done(message(text)); terminal(listOf(message(text)), usage)
        return session.terminalResult() as ChatGptAttemptResultV1.Completed
    }
    fun text() = events.filterIsInstance<ModelEventV2.TextDelta>().joinToString("") { it.text }
    fun settle(r: ChatGptAttemptResultV1) = ledger.settle(lease, r.local, r.reported, r.outcome, (r as? ChatGptAttemptResultV1.Stopped)?.kind)
    private val ownedBatch by lazy { BuiltinToolBatchV2(ledger, fixture.policy, fixture.inventory, object : ToolAuthorityV2 {
        override fun preview(proposal: ToolProposalV2, arguments: JsonObject, policy: ToolRequestPolicyV2, inventory: ToolInventoryV2): EffectPreviewV2 {
            previews++; return EffectPreviewV2(fixture.path, ToolOperationV2.WRITE, 16, 1, 1, 1, 1, 1)
        }
        override fun currentBindingCommitment() = run.bindingCommitment
        override fun recheck(effect: EffectPreviewV2, policy: ToolRequestPolicyV2, inventory: ToolInventoryV2) = true
    }, codec.encodedSpace(run, prior, emptyMap())) }
    fun batch() = ownedBatch
    fun execute(r: ModelResponseV2) = batch().let { b -> b.execute(b.previewBatch(r)) { _, _, out -> effects++; out.append("ok") } }
    companion object {
        fun q(s: String) = JsonPrimitive(s).toString()
        fun part(s: String, type: String = "output_text") = """{"type":"$type","${if (type == "refusal") "refusal" else "text"}":${q(s)}}"""
        fun message(s: String, id: String = "msg_1", status: String = "completed", type: String = "output_text") = """{ "id":"$id", "type":"message", "role":"assistant", "status":"$status", "phase":"final_answer", "content":[${part(s, type)}] }"""
        fun reasoning(encrypted: String = "opaque-final", summary: String = "private summary", content: String = "private thought", status: String = "completed") = """{ "type":"reasoning","id":"rs_1","summary":[${part(summary, "summary_text")}],"content":[${part(content, "reasoning_text")}],"encrypted_content":${q(encrypted)},"status":"$status" }"""
        fun function(args: String = """{"path":"source.c","text":"new"}""", status: String = "completed") = """{ "id":"fc_1", "type":"function_call", "call_id":"call_1", "namespace":"decomp", "name":"write", "arguments":${q(args)}, "caller":{"type":"direct"}, "async":false, "status":"$status" }"""
        fun envelope(status: String, items: List<String>? = null, usage: String? = null) = """{"id":"resp_1","model":"fixture-model","status":"$status"${items?.let { ",\"output\":[${it.joinToString(",")}]" } ?: ""}${usage?.let { ",\"usage\":$it" } ?: ""}}"""
        fun usage(input: String = "0", output: String = "0", total: String = "0", extra: String = "") = """{"input_tokens":$input,"output_tokens":$output,"total_tokens":$total$extra}"""
        fun failure(kind: ModelFailureKind? = null, block: () -> Unit): ModelProviderException {
            val e = assertFailsWith<ModelProviderException>(block = block)
            if (kind != null) assertEquals(kind, e.kind)
            assertNull(e.cause); assertTrue(e.suppressed.isEmpty()); assertFalse(e.message.orEmpty().contains("fixture-original-secret")); return e
        }
    }
}

class ChatGptPlanResponsesV1Test {
    private fun reject(block: () -> Unit): ModelProviderException {
        val e = assertFailsWith<ModelProviderException>(block = block)
        assertNull(e.cause); assertTrue(e.suppressed.isEmpty())
        return e
    }
    private fun message(parts: List<String>, id: String = "msg_1") =
        """{"id":"$id","type":"message","role":"assistant","status":"completed","content":[${parts.joinToString(",") { C2Fixture.part(it) }}]}"""

    @Test fun swallowedFinalCallbackReentryMustRevokeCompletion() {
        lateinit var f: C2Fixture
        var caught = false
        f = C2Fixture(callback = {
            try { f.session.feed(byteArrayOf()) } catch (e: ModelProviderException) {
                assertNull(e.cause); caught = true
            }
        })
        // A prefix of a registered synthetic secret remains held until terminal flush.
        f.created(); f.added(C2Fixture.message("", status = "in_progress")); f.done(C2Fixture.message("fixture-"))
        assertTrue(f.events.isEmpty())
        reject { f.terminal(listOf(C2Fixture.message("fixture-"))) }
        assertTrue(caught); assertNull(f.session.terminalResult()); assertEquals(0, f.effects)
    }
    @Test fun finalCallbackDiscardMustRevokeCompletion() {
        lateinit var f: C2Fixture
        f = C2Fixture(callback = { f.session.discard() })
        f.created(); f.added(C2Fixture.message("", status = "in_progress")); f.done(C2Fixture.message("fixture-"))
        reject { f.terminal(listOf(C2Fixture.message("fixture-"))) }
        assertNull(f.session.terminalResult()); assertEquals(0, f.effects)
    }
    @Test fun rotationInFinalCallbackMustRescanPrivateResult() {
        lateinit var f: C2Fixture
        f = C2Fixture(callback = { f.secrets.registerSynthetic("fixture-") })
        f.created(); f.added(C2Fixture.message("", status = "in_progress")); f.done(C2Fixture.message("fixture-"))
        val e = reject { f.terminal(listOf(C2Fixture.message("fixture-"))) }
        assertEquals(ModelFailureKind.SECRET_EXPOSURE, e.kind); assertNull(f.session.terminalResult())
    }
    @Test fun concatenatedCredentialMarkerAcrossPartsMustNotReachSink() {
        val f = C2Fixture(); val raw = message(listOf("access_", "token"))
        f.created(); f.added(message(emptyList()))
        val e = reject { f.done(raw); f.terminal(listOf(raw)) }
        assertEquals(ModelFailureKind.SECRET_EXPOSURE, e.kind)
        assertFalse(f.text().contains("access_token")); assertNull(f.session.terminalResult())
    }
    @Test fun concatenatedCredentialMarkerAcrossItemsMustNotReachSink() {
        val f = C2Fixture(); val first = message(listOf("access_")); val second = message(listOf("token"), "msg_2")
        f.created(); f.added(message(emptyList())); f.added(message(emptyList(), "msg_2"), 1)
        val e = reject { f.done(first); f.done(second, 1); f.terminal(listOf(first, second)) }
        assertEquals(ModelFailureKind.SECRET_EXPOSURE, e.kind); assertFalse(f.text().contains("access_token"))
    }
    @Test fun registeredSecretAcrossPartsMustNotEnterCompletedNeutralText() {
        val f = C2Fixture(); val raw = message(listOf("fixture-original-", "secret"))
        f.created(); f.added(message(emptyList()))
        val e = reject { f.done(raw); f.terminal(listOf(raw)) }
        assertEquals(ModelFailureKind.SECRET_EXPOSURE, e.kind); assertNull(f.session.terminalResult())
        assertFalse(f.text().contains("fixture-original-secret"))
    }

    @Test fun `done only completion meters exactly once and never finishes or settles`() {
        val f = C2Fixture(); val r = f.complete("hello é😀")
        assertEquals("hello é😀", r.response.text); assertEquals(r.response.text, f.text())
        assertEquals(r.response.text.toByteArray().size.toLong(), r.local.decodedOutputBytes)
        assertEquals(r.local.decodedOutputBytes, r.local.displayedBytes)
        assertEquals(r.response.continuation.rawBytes, r.local.continuationBytes)
        assertEquals(f.ledger.counters().wire, r.local.wireBytes)
        assertEquals(LedgerStateV2.ACTIVE, f.ledger.state()); assertEquals(0, f.effects)
        assertTrue(f.events.none { it is ModelEventV2.Finished }); assertEquals(0, f.session.readDemand())
        assertSame(r, f.session.endOfInput()); assertSame(r, f.session.terminalResult())
    }
    @Test fun `all lifecycle events with private reasoning preserve final slices through actual C1`() {
        val f = C2Fixture(); f.created()
        f.send(f.event("response.in_progress", "\"response\":${C2Fixture.envelope("in_progress")}"))
        f.added(C2Fixture.reasoning("provisional", "", "", "in_progress"), 0)
        fun aux(type: String, fields: String) = f.send(f.event("response.$type", "\"output_index\":0,\"item_id\":\"rs_1\",$fields"))
        aux("reasoning_summary_part.added", "\"summary_index\":0,\"part\":${C2Fixture.part("", "summary_text")}")
        aux("reasoning_summary_text.delta", "\"summary_index\":0,\"delta\":\"private summary\"")
        aux("reasoning_summary_text.done", "\"summary_index\":0,\"text\":\"private summary\"")
        aux("reasoning_summary_part.done", "\"summary_index\":0,\"part\":${C2Fixture.part("private summary", "summary_text")}")
        aux("reasoning_text.delta", "\"content_index\":0,\"delta\":\"private thought\"")
        aux("reasoning_text.done", "\"content_index\":0,\"text\":\"private thought\"")
        f.done(C2Fixture.reasoning(), 0)
        f.added(C2Fixture.message("", status = "in_progress"), 1)
        fun msg(type: String, field: String) = f.send(f.event("response.$type", "\"output_index\":1,\"item_id\":\"msg_1\",\"content_index\":0,$field"))
        msg("content_part.added", "\"part\":${C2Fixture.part("")}")
        msg("output_text.delta", "\"delta\":\"hello\",\"logprobs\":[]")
        msg("output_text.done", "\"text\":\"hello\"")
        msg("content_part.done", "\"part\":${C2Fixture.part("hello")}")
        f.done(C2Fixture.message("hello"), 1)
        f.added(C2Fixture.function("", "in_progress"), 2)
        val args = """{"path":"source.c","text":"new"}"""
        f.send(f.event("response.function_call_arguments.delta", "\"output_index\":2,\"item_id\":\"fc_1\",\"delta\":${C2Fixture.q(args)}"))
        f.send(f.event("response.function_call_arguments.done", "\"output_index\":2,\"item_id\":\"fc_1\",\"arguments\":${C2Fixture.q(args)}"))
        f.done(C2Fixture.function(), 2)
        val raw = listOf(C2Fixture.reasoning(), C2Fixture.message("hello"), C2Fixture.function()); f.terminal(raw)
        val r = f.session.terminalResult() as ChatGptAttemptResultV1.Completed
        assertEquals("hello", f.text()); assertEquals((5 + args.toByteArray().size).toLong(), r.local.decodedOutputBytes)
        assertEquals(raw, r.response.continuation.orderedItems().map { it.toString(Charsets.UTF_8) })
        assertEquals(LedgerStateV2.ACTIVE, f.ledger.state()); assertEquals(0, f.effects); assertEquals(0, f.previews)
        f.settle(r); val results = f.execute(r.response); assertEquals(1, f.effects)
        val replay = f.codec.encode(f.run, f.prior + ModelMessageV2(ModelRole.ASSISTANT, r.response.text, r.response.continuation), mapOf(r.response.continuation to results)).encoded().toString(Charsets.UTF_8)
        raw.forEach { assertTrue(replay.contains(it)) }; assertFalse(replay.contains("provisional")); assertTrue(replay.indexOf(raw[0]) < replay.indexOf(raw[2]))
    }
    @Test fun `refusal lifecycle is public but never executable`() {
        val f = C2Fixture(); f.created(); f.added(C2Fixture.message("", status = "in_progress", type = "refusal"))
        for ((suffix, key) in listOf("delta" to "delta", "done" to "refusal")) f.send(f.event("response.refusal.$suffix", "\"output_index\":0,\"item_id\":\"msg_1\",\"content_index\":0,\"$key\":\"no\""))
        val raw = C2Fixture.message("no", type = "refusal"); f.done(raw); f.terminal(listOf(raw))
        val r = f.session.terminalResult() as ChatGptAttemptResultV1.Completed
        assertEquals(ModelFinishReason.REFUSED, r.response.finishReason); assertEquals("no", f.text()); assertEquals(2, r.local.decodedOutputBytes)
    }
    @Test fun `absent and null usage remain unknown explicit zero stays zero`() {
        for (u in listOf(null, "null")) assertNull(C2Fixture().complete(usage = u).reported)
        val zero = C2Fixture().complete(usage = C2Fixture.usage()).reported!!
        assertEquals(0, zero.input); assertNull(zero.cachedInput); assertNull(zero.reasoningOutput)
        val detail = C2Fixture().complete(usage = C2Fixture.usage(extra = ",\"input_tokens_details\":{\"cached_tokens\":0,\"cache_write_tokens\":null},\"output_tokens_details\":null")).reported!!
        assertEquals(0, detail.cachedInput); assertNull(detail.cacheWriteInput)
    }
    @Test fun `usage canonical syntax arithmetic bounds and detail parent limits`() {
        for (u in listOf(C2Fixture.usage("-0"), C2Fixture.usage("0.0"), C2Fixture.usage("0e0"), C2Fixture.usage("\"0\""), C2Fixture.usage("null"),
            C2Fixture.usage("9223372036854775808"), C2Fixture.usage("9223372036854775807", "1", "0"), C2Fixture.usage("1", "2", "4"), "{}",
            C2Fixture.usage(extra = ",\"input_tokens_details\":{\"cached_tokens\":1}"), C2Fixture.usage(extra = ",\"output_tokens_details\":{\"reasoning_tokens\":1}"))) {
            C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { C2Fixture().complete(usage = u) }
        }
        assertEquals(Long.MAX_VALUE, C2Fixture().complete(usage = C2Fixture.usage("9223372036854775807", "0", "9223372036854775807")).reported!!.total)
    }
    @Test fun `terminal usage overdraw is host recorded truthfully and blocks actual batch`() {
        val f = C2Fixture(); f.created(); f.added(C2Fixture.function("", "in_progress")); f.done(C2Fixture.function()); f.terminal(listOf(C2Fixture.function()), C2Fixture.usage("999999", "10000", "1009999"))
        val r = f.session.terminalResult() as ChatGptAttemptResultV1.Completed
        assertEquals(LedgerStateV2.ACTIVE, f.ledger.state()); C2Fixture.failure { f.execute(r.response) }
        val obs = f.settle(r); assertEquals(999999, obs.inputCharge); assertEquals(10000, obs.outputCharge)
        assertEquals(LedgerStateV2.EXHAUSTED, f.ledger.state()); C2Fixture.failure { f.execute(r.response) }; assertEquals(0, f.effects)
    }
    @Test fun `failed incomplete and error without created are immutable safe stops`() {
        for (type in listOf("failed", "incomplete", "error")) {
            val f = C2Fixture()
            if (type == "error") f.send(f.event(type, "\"code\":null,\"message\":\"safe fixture error\",\"param\":null"))
            else f.terminal(emptyList(), C2Fixture.usage(), type)
            val r = f.session.terminalResult() as ChatGptAttemptResultV1.Stopped
            assertTrue(r.validatedTerminal); assertEquals(ChatGptRecoveryV1.STOP, r.diagnostic.recovery)
            assertEquals(if (type == "incomplete") AttemptOutcomeV2.INCOMPLETE else AttemptOutcomeV2.FAILED, r.outcome)
            assertEquals(0, f.effects); assertTrue(f.events.isEmpty()); assertEquals(0, f.session.readDemand()); f.settle(r)
        }
    }
    @Test fun `failure after partial charges terminal suffix without replay or double debit`() {
        for (type in listOf("failed", "incomplete")) {
            val f = C2Fixture(); f.created(); f.added(C2Fixture.message("", status = "in_progress"))
            f.send(f.event("response.output_text.delta", "\"output_index\":0,\"item_id\":\"msg_1\",\"content_index\":0,\"delta\":\"a\""))
            f.terminal(listOf(C2Fixture.message("abc", status = "in_progress")), C2Fixture.usage("2", "3", "5"), type)
            val r = f.session.terminalResult() as ChatGptAttemptResultV1.Stopped
            assertEquals(3, r.local.decodedOutputBytes); assertEquals(0, r.local.continuationBytes); assertEquals(5, r.reported!!.total)
            assertEquals("a", f.text()); assertEquals(0, f.effects); assertEquals(3, f.settle(r).outputCharge)
        }
        val f = C2Fixture()
        f.send(f.event("response.incomplete", "\"response\":${C2Fixture.envelope("incomplete").dropLast(1)},\"incomplete_details\":{\"reason\":\"max_output_tokens\"}}"))
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED, (f.session.terminalResult() as ChatGptAttemptResultV1.Stopped).kind)
    }
    @Test fun `invalid lifecycle ordering identity and sequence fail closed`() {
        val invalid: List<(C2Fixture) -> Unit> = listOf(
            { it.added(C2Fixture.message("")) },
            { it.created(); it.created() },
            { it.created(); it.added(C2Fixture.message(""), 1) },
            { it.created(); it.added(C2Fixture.message("")); it.added(C2Fixture.message(""), 1) },
            { it.created(); it.added(C2Fixture.message("")); it.done(C2Fixture.message("x")); it.done(C2Fixture.message("x")) },
            { it.created(); it.send(it.event("response.output_text.delta", "\"output_index\":0,\"item_id\":\"msg_1\",\"content_index\":0,\"delta\":\"x\"")) },
            { it.created(); it.added(C2Fixture.message("")); it.send(it.event("response.output_text.delta", "\"output_index\":0,\"item_id\":\"wrong\",\"content_index\":0,\"delta\":\"x\"")) },
            { it.created(); it.added(C2Fixture.message("")); it.send(it.event("response.output_text.delta", "\"output_index\":0,\"item_id\":\"msg_1\",\"content_index\":1,\"delta\":\"x\"")); it.done(C2Fixture.message("")) },
            { it.created(); it.send(it.event("response.in_progress", "\"response\":${C2Fixture.envelope("in_progress")}", 0)) },
            { it.created(); it.terminal(emptyList()) }
        )
        invalid.forEach { fn -> val f = C2Fixture(); C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { fn(f) }; assertNull(f.session.terminalResult()); assertEquals(0, f.effects) }
        val f = C2Fixture(); f.sequence = 100; f.complete(); assertNotNull(f.session.terminalResult())
    }
    @Test fun `delta done part final and full terminal output must agree`() {
        for (mode in 0..4) {
            val f = C2Fixture(); f.created(); f.added(C2Fixture.message("", status = "in_progress"))
            f.send(f.event("response.output_text.delta", "\"output_index\":0,\"item_id\":\"msg_1\",\"content_index\":0,\"delta\":\"x\""))
            C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) {
                if (mode == 0) f.done(C2Fixture.message("x"))
                else {
                    f.send(f.event("response.output_text.done", "\"output_index\":0,\"item_id\":\"msg_1\",\"content_index\":0,\"text\":\"${if (mode == 1) "bad" else "x"}\""))
                    f.done(C2Fixture.message(if (mode == 2) "bad" else "x"))
                    f.terminal(listOf(C2Fixture.message("x").let { if (mode == 3) it.replace("final_answer", "commentary") else it.replace("\"x\"", "\"bad\"") }))
                }
            }
        }
    }
    @Test fun `namespace direct caller async schema and private context reject before effects`() {
        val base = C2Fixture.function()
        for (bad in listOf(base.replace("decomp", "foreign"), base.replace("\"direct\"", "\"program\""), base.replace("{\"type\":\"direct\"}", "\"direct\""),
            base.replace("\"async\":false", "\"async\":true"), base.replace("\"write\"", "\"unknown\""), C2Fixture.function("{\"extra\":1}"),
            base.replace("call_1", "x".repeat(65)), C2Fixture.reasoning(""), C2Fixture.reasoning().replace("opaque-final", "fixture-original-secret"))) {
            val f = C2Fixture(); C2Fixture.failure { f.created(); f.added(bad); f.done(bad) }; assertEquals(0, f.effects); assertNull(f.session.terminalResult())
        }
    }
    @Test fun `unknown events executable types and unqualified fields reject`() {
        for (type in listOf("response.web_search_call.completed", "response.output_text.unknown")) C2Fixture.failure(ModelFailureKind.UNSUPPORTED_FEATURE) { val f = C2Fixture(); f.send(f.event(type, "\"x\":0")) }
        for (raw in listOf("""{"id":"x","type":"computer_call"}""", C2Fixture.message("x").replace("\"phase\"", "\"unknown\""), C2Fixture.message("x").replace("\"text\":\"x\"", "\"text\":\"x\",\"annotations\":[{}]"))) {
            C2Fixture.failure { val f = C2Fixture(); f.created(); f.added(raw) }
        }
    }
    @Test fun `secret keys escaped scalar args raw replay and rotated private data reject`() {
        for (text in listOf("fixture-original-secret", "fixture-rotated-secret", "Bearer fixture", "access_token")) {
            val f = C2Fixture(); C2Fixture.failure(ModelFailureKind.SECRET_EXPOSURE) { f.complete(text) }; assertFalse(f.text().contains(text)); assertEquals(0, f.effects)
        }
        val f = C2Fixture(); f.created(); f.added(C2Fixture.reasoning()); f.done(C2Fixture.reasoning()); f.secrets.registerSynthetic("opaque-final")
        C2Fixture.failure(ModelFailureKind.SECRET_EXPOSURE) { f.terminal(listOf(C2Fixture.reasoning())) }
        val escaped = """{"path":"source.c","text":"fixture-original-\u0073ecret"}"""
        val g = C2Fixture(); g.created(); g.added(C2Fixture.function("", "in_progress")); C2Fixture.failure(ModelFailureKind.SECRET_EXPOSURE) { g.done(C2Fixture.function(escaped)) }
    }
    @Test fun `split public secret and overlapping guards never expose raw values`() {
        val f = C2Fixture(); f.created(); f.added(C2Fixture.message("", status = "in_progress"))
        f.send(f.event("response.output_text.delta", "\"output_index\":0,\"item_id\":\"msg_1\",\"content_index\":0,\"delta\":\"fixture-original-\""))
        C2Fixture.failure(ModelFailureKind.SECRET_EXPOSURE) { f.send(f.event("response.output_text.delta", "\"output_index\":0,\"item_id\":\"msg_1\",\"content_index\":0,\"delta\":\"secret\"")) }
        assertFalse(f.text().contains("fixture-original-secret")); assertEquals(23, f.session.observed().decodedOutputBytes)
    }
    @Test fun `sink throw and cancellation inside callback retain charges without success`() {
        val f = C2Fixture(callback = { throw IllegalStateException("fixture-original-secret") })
        C2Fixture.failure(ModelFailureKind.TRANSPORT) { f.complete() }; assertEquals(5, f.session.observed().decodedOutputBytes); assertEquals(5, f.session.observed().displayedBytes); assertNull(f.session.terminalResult())
        val source = AgentCancellationSource(); val g = C2Fixture(V2Fixture(cancellation = source.cancellation), callback = { source.cancel() })
        C2Fixture.failure(ModelFailureKind.CANCELLED) { g.complete() }; assertEquals(5, g.session.observed().displayedBytes); assertNull(g.session.terminalResult())
    }
    @Test fun `preallocation cancelled expired and reentrant feeds are rejected`() {
        val source = AgentCancellationSource(); val f = C2Fixture(V2Fixture(cancellation = source.cancellation)); source.cancel()
        C2Fixture.failure(ModelFailureKind.CANCELLED) { f.session.feed(ByteArray(8192)) }; assertEquals(8192, f.session.observed().wireBytes)
        val g = C2Fixture(); g.fixture.now = Duration.ofMinutes(20).toNanos(); C2Fixture.failure(ModelFailureKind.TIMEOUT) { g.session.feed(ByteArray(8192)) }; assertEquals(8192, g.session.observed().wireBytes)
        lateinit var h: C2Fixture; h = C2Fixture(callback = { h.session.feed(byteArrayOf()) })
        C2Fixture.failure { h.complete() }; assertNull(h.session.terminalResult()); assertEquals(0, h.effects)
    }
    @Test fun `meter precedes sink and failed local ceiling retains overdraw`() {
        val f = C2Fixture(reserve = 4)
        C2Fixture.failure(ModelFailureKind.RESOURCE_EXHAUSTED) { f.complete("12345") }
        assertEquals(5, f.session.observed().decodedOutputBytes); assertEquals("", f.text()); assertEquals(0, f.effects)
        val obs = f.ledger.markAmbiguous(f.lease); assertEquals(5, obs.outputCharge)
    }
    @Test fun `terminal equality ignores key order but preserves optional fields`() {
        val f = C2Fixture(); f.created(); val raw = C2Fixture.message("x"); f.added(raw); f.done(raw)
        val reordered = JsonObject(Json.parseToJsonElement(raw).jsonObject.entries.reversed().associate { it.key to it.value }).toString()
        f.terminal(listOf(reordered)); val r = f.session.terminalResult() as ChatGptAttemptResultV1.Completed
        assertEquals(raw, r.response.continuation.orderedItems().single().toString(Charsets.UTF_8))
    }
    @Test fun `unsettled valid codec result fails actual A batch with zero previews and effects`() {
        val f = C2Fixture(); f.created(); f.added(C2Fixture.function("", "in_progress")); f.done(C2Fixture.function()); f.terminal(listOf(C2Fixture.function()))
        val r = f.session.terminalResult() as ChatGptAttemptResultV1.Completed
        C2Fixture.failure { f.execute(r.response) }; assertEquals(0, f.effects); assertEquals(0, f.previews)
        assertEquals(LedgerStateV2.INDETERMINATE, f.ledger.state()) // actual A seals a failed batch
    }
    @Test fun `part lifecycle optional absence seed duplicate and incomplete reasoning prevent success`() {
        val f = C2Fixture(); f.created(); f.added(C2Fixture.message("seed", status = "in_progress"))
        f.send(f.event("response.content_part.added", "\"output_index\":0,\"item_id\":\"msg_1\",\"content_index\":0,\"part\":${C2Fixture.part("seed")}"))
        f.send(f.event("response.content_part.done", "\"output_index\":0,\"item_id\":\"msg_1\",\"content_index\":0,\"part\":${C2Fixture.part("seed")}"))
        f.done(C2Fixture.message("seed")); f.terminal(listOf(C2Fixture.message("seed"))); assertEquals(4, f.session.observed().decodedOutputBytes)
        val g = C2Fixture(); g.created(); g.added(C2Fixture.reasoning("provisional", "", "", "in_progress"))
        for (s in listOf("added", "done")) g.send(g.event("response.reasoning_summary_part.$s", "\"output_index\":0,\"item_id\":\"rs_1\",\"summary_index\":0,\"part\":${C2Fixture.part("", "summary_text")}${if(s == "done") ",\"status\":\"incomplete\"" else ""}"))
        g.done(C2Fixture.reasoning(summary = "", content = ""))
        C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { g.terminal(listOf(C2Fixture.reasoning(summary = "", content = ""))) }
    }
    @Test fun `refusal plus function and swapped terminal arrays reject`() {
        val f = C2Fixture(); f.created(); val r = C2Fixture.message("no", type = "refusal"); val fn = C2Fixture.function()
        f.added(r); f.done(r); f.added(fn, 1); f.done(fn, 1)
        C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { f.terminal(listOf(r, fn)) }; assertEquals(0, f.effects)
        val g = C2Fixture(); g.created(); g.added(C2Fixture.reasoning()); g.done(C2Fixture.reasoning()); g.added(C2Fixture.message("x"), 1); g.done(C2Fixture.message("x"), 1)
        C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { g.terminal(listOf(C2Fixture.message("x"), C2Fixture.reasoning())) }
    }
    @Test fun `function count exact ceiling and one over`() {
        fun fn(i: Int) = C2Fixture.function().replace("fc_1", "fc_$i").replace("call_1", "call_$i")
        val f = C2Fixture(V2Fixture(local = LocalBudgetV1(callsPerResponse = 2))); f.created()
        for (i in 0..1) { f.added(fn(i), i); f.done(fn(i), i) }; f.terminal(listOf(fn(0), fn(1)))
        assertEquals(2, (f.session.terminalResult() as ChatGptAttemptResultV1.Completed).response.continuation.proposals.size)
        val g = C2Fixture(V2Fixture(local = LocalBudgetV1(callsPerResponse = 2))); g.created(); for (i in 0..1) g.added(fn(i), i)
        C2Fixture.failure(ModelFailureKind.RESOURCE_EXHAUSTED) { g.added(fn(2), 2) }
    }
    @Test fun `partial failed terminal must also enforce call and total private part ceilings`() {
        val f = C2Fixture(V2Fixture(local = LocalBudgetV1(callsPerResponse = 1)))
        C2Fixture.failure(ModelFailureKind.RESOURCE_EXHAUSTED) { f.terminal(listOf(C2Fixture.function(), C2Fixture.function().replace("fc_1", "fc_2").replace("call_1", "call_2")), type = "failed") }
        val g = C2Fixture()
        val p = C2Fixture.part("", "summary_text")
        val a = "{\"type\":\"reasoning\",\"id\":\"rs_1\",\"summary\":[${List(1024) { p }.joinToString(",")}] }"
        val b = "{\"type\":\"reasoning\",\"id\":\"rs_2\",\"summary\":[$p]}"
        C2Fixture.failure(ModelFailureKind.RESOURCE_EXHAUSTED) { g.terminal(listOf(a, b), type = "failed") }
    }
    @Test fun `cancel during parser scan retains wire and no public or executable effect`() {
        var armed = false; var checks = 0
        val fixture = V2Fixture(cancellation = decompengine.agent.AgentCancellation { armed && ++checks >= 50 })
        val f = C2Fixture(fixture); armed = true
        val bytes = ("data: " + f.event("response.created", "\"response\":${C2Fixture.envelope("in_progress")}") + "\n\n").toByteArray()
        C2Fixture.failure(ModelFailureKind.CANCELLED) { f.session.feed(bytes) }
        assertEquals(bytes.size.toLong(), f.session.observed().wireBytes); assertEquals(0, f.effects); assertEquals("", f.text())
    }

    @Test fun `1024 items exact and one over with contiguous indices`() {
        val b = LocalBudgetV1(responseBytes = 32L * 1024 * 1024, eventBytes = 2L * 1024 * 1024)
        fun fixture() = C2Fixture(V2Fixture(local = b, hostLocal = b, profileLocal = b))
        val raw = (0 until 1024).map { C2Fixture.message("", id = "m_$it") }
        val f = fixture(); f.created()
        raw.forEachIndexed { n, item ->
            try { f.added(item, n); f.done(item, n) } catch (e: ModelProviderException) { fail("item=$n budget=${f.run.budget.responseBytes} wire=${f.session.observed().wireBytes} kind=${e.kind}") }
        }; f.terminal(raw)
        assertEquals(1024, (f.session.terminalResult() as ChatGptAttemptResultV1.Completed).response.continuation.orderedItems().size)
        val g = fixture(); g.created(); raw.forEachIndexed { n, item -> g.added(item, n) }
        C2Fixture.failure(ModelFailureKind.RESOURCE_EXHAUSTED) { g.added(C2Fixture.message("", id = "m_last"), 1024) }
    }
    @Test fun `1024 total parts exact and one over includes private arrays`() {
        val b = LocalBudgetV1(responseBytes = 32L * 1024 * 1024, eventBytes = 2L * 1024 * 1024)
        fun raw(n: Int) = "{\"id\":\"rs_1\",\"type\":\"reasoning\",\"encrypted_content\":\"opaque\",\"summary\":[${List(n) { C2Fixture.part("", "summary_text") }.joinToString(",")}] }"
        val f = C2Fixture(V2Fixture(local = b, hostLocal = b, profileLocal = b)); f.created(); f.added("{\"id\":\"rs_1\",\"type\":\"reasoning\"}"); f.done(raw(1024)); f.terminal(listOf(raw(1024)))
        assertNotNull(f.session.terminalResult()); assertEquals(0, f.session.observed().decodedOutputBytes)
        val g = C2Fixture(V2Fixture(local = b, hostLocal = b, profileLocal = b)); g.created(); g.added("{\"id\":\"rs_1\",\"type\":\"reasoning\"}")
        C2Fixture.failure(ModelFailureKind.RESOURCE_EXHAUSTED) { g.done(raw(1025)) }
    }
    @Test fun `interleaved items keep final array order and supported optional fields exact`() {
        val f = C2Fixture(); f.created()
        val first = C2Fixture.message("one").replace("\"text\":\"one\"", "\"text\":\"one\",\"annotations\":[],\"logprobs\":[]")
        val second = C2Fixture.message("two", id = "msg_2").replace("\"final_answer\"", "null")
        f.added(first); f.added(second, 1); f.done(second, 1); f.done(first); f.terminal(listOf(first, second))
        val r = f.session.terminalResult() as ChatGptAttemptResultV1.Completed
        assertEquals("onetwo", r.response.text); assertEquals(listOf(first, second), r.response.continuation.orderedItems().map { it.toString(Charsets.UTF_8) })
    }
    @Test fun `cancelled entry checks before allocation of supplied large bytes`() {
        val bean = java.lang.management.ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
        bean.isThreadAllocatedMemoryEnabled = true
        var armed = false; var observed = 0L
        val tid = Thread.currentThread().threadId()
        val f = C2Fixture(V2Fixture(cancellation = decompengine.agent.AgentCancellation { if (armed) { observed = bean.getThreadAllocatedBytes(tid); true } else false }))
        val bytes = ByteArray(8192); armed = true
        val before = bean.getThreadAllocatedBytes(tid)
        C2Fixture.failure(ModelFailureKind.CANCELLED) { f.session.feed(bytes) }
        val allocation = observed - before
        println("C2_CANCEL_BEFORE_BUFFER allocated=$allocation")
        assertTrue(allocation < 100000); assertEquals(8192, f.session.observed().wireBytes)
    }

    @Test fun `incomplete item snapshots in stopped terminals preserve validated usage`() {
        for (type in listOf("failed", "incomplete")) {
            val f = C2Fixture()
            f.terminal(listOf(C2Fixture.message("partial", status = "incomplete")), C2Fixture.usage("1", "2", "3"), type)
            val r = f.session.terminalResult() as ChatGptAttemptResultV1.Stopped
            assertEquals(3, r.reported!!.total); assertEquals(7, r.local.decodedOutputBytes)
            assertEquals(0, r.local.continuationBytes); assertEquals(0, f.effects)
        }
        val f = C2Fixture(); f.created(); f.added(C2Fixture.message("", status = "in_progress"))
        C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { f.done(C2Fixture.message("partial", status = "incomplete")) }
    }

    @Test fun `nonempty seeds cannot silently grow in a done only snapshot`() {
        val f = C2Fixture(); f.created(); f.added(C2Fixture.message("seed", status = "in_progress"))
        C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { f.done(C2Fixture.message("seed extra")) }
        val g = C2Fixture(); g.created(); g.added(C2Fixture.function("{", "in_progress"))
        C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { g.done(C2Fixture.function()) }
        assertEquals(0, f.effects); assertEquals(0, g.effects)
    }

    @Test fun `joined credential marker rejects before the last public fragment`() {
        val f = C2Fixture(); f.created(); f.added(C2Fixture.message("", status = "in_progress"))
        fun delta(s: String) = f.send(f.event("response.output_text.delta", "\"output_index\":0,\"item_id\":\"msg_1\",\"content_index\":0,\"delta\":${C2Fixture.q(s)}"))
        delta("bear")
        C2Fixture.failure(ModelFailureKind.SECRET_EXPOSURE) { delta("er ") }
        assertEquals("bear", f.text()); assertEquals(7, f.session.observed().decodedOutputBytes); assertEquals(0, f.effects)
    }

    @Test fun `revoked final callbacks cannot reach actual host settled batch effects`() {
        for (action in 0..3) {
            lateinit var f: C2Fixture
            var entered = false
            f = C2Fixture(callback = {
                entered = true
                assertNull(f.session.terminalResult())
                when (action) {
                    0 -> try { f.session.feed(byteArrayOf()) } catch (_: ModelProviderException) { }
                    1 -> f.session.discard()
                    2 -> try { f.session.endOfInput() } catch (_: ModelProviderException) { }
                    else -> try { f.session.readDemand() } catch (_: ModelProviderException) { }
                }
            })
            val raw = listOf(C2Fixture.message("fixture-"), C2Fixture.function())
            f.created(); f.added(C2Fixture.message("", status = "in_progress")); f.done(raw[0])
            f.added(C2Fixture.function("", "in_progress"), 1); f.done(raw[1], 1)
            var failure: ModelProviderException? = null
            try { f.terminal(raw) } catch (e: ModelProviderException) { failure = e }
            // Run the ordinary host success path if the codec accidentally publishes authority.
            val published = f.session.terminalResult() as? ChatGptAttemptResultV1.Completed
            if (published != null) { f.settle(published); f.execute(published.response) }
            assertEquals(0, f.effects); assertEquals(0, f.previews)
            assertTrue(entered); assertNotNull(failure); assertNull(published)
            val stopped = f.ledger.settle(f.lease, f.session.observed(), null, AttemptOutcomeV2.FAILED, failure.kind)
            assertEquals(AttemptOutcomeV2.FAILED, stopped.outcome)
            // Even a test-constructed candidate with this exact call cannot bypass actual A
            // after failed settlement. No codec result is fabricated on the production path.
            val proposal = ToolProposalV2("decomp", "write", "call_1", "fc_1", """{"path":"source.c","text":"new"}""", "direct", false)
            val digest = v2Digest(listOf("responses-neutral-v1", "fixture-", "decomp", "write", "call_1", "fc_1", proposal.argumentsJson, "direct", "false"))
            val candidate = ModelResponseV2("fixture-", ModelFinishReason.TOOL_CALLS,
                ValidatedResponsesTurnV1(f.call, "resp_1", raw.map { it.toByteArray() }, listOf(proposal), digest), null)
            C2Fixture.failure { f.execute(candidate) }
            assertEquals(0, f.effects); assertEquals(0, f.previews)
            assertEquals(0, f.session.readDemand()); assertNull(f.session.terminalResult())
            f.session.discard(); f.session.discard()
            assertEquals(f.text().toByteArray().size.toLong(), f.session.observed().displayedBytes)
        }
    }

    @Test fun `final callback cancellation timeout meter and thrown errors keep original safe kinds`() {
        for (action in 0..3) {
            val cancel = AgentCancellationSource()
            lateinit var f: C2Fixture
            f = C2Fixture(V2Fixture(cancellation = cancel.cancellation), callback = {
                when (action) {
                    0 -> { f.session.discard(); cancel.cancel() }
                    1 -> { f.session.discard(); f.fixture.now = Duration.ofMinutes(21).toNanos() }
                    2 -> { f.session.discard(); throw IllegalStateException("synthetic callback failure") }
                    else -> cancel.cancel()
                }
            })
            val expected = when (action) { 0, 3 -> ModelFailureKind.CANCELLED; 1 -> ModelFailureKind.TIMEOUT; else -> ModelFailureKind.TRANSPORT }
            C2Fixture.failure(expected) { f.complete("fixture-") }
            assertNull(f.session.terminalResult()); assertEquals(8, f.session.observed().displayedBytes)
            assertEquals(0, f.session.readDemand()); assertEquals(0, f.effects)
        }
        val b = LocalBudgetV1(displayedBytesTotal = 8)
        val g = C2Fixture(V2Fixture(local = b, hostLocal = b, profileLocal = b))
        C2Fixture.failure(ModelFailureKind.RESOURCE_EXHAUSTED) { g.complete("zzfixture-") }
        assertEquals("zz", g.text()); assertNull(g.session.terminalResult())
        assertEquals(10, g.session.observed().displayedBytes) // attempted debit retained before rejected delivery
    }

    @Test fun `nonfinal callback revocation clears held state and cannot resume`() {
        lateinit var f: C2Fixture
        f = C2Fixture(callback = { f.session.discard() })
        C2Fixture.failure(ModelFailureKind.MALFORMED_RESPONSE) { f.complete("visible") }
        assertNull(f.session.terminalResult()); assertEquals(0, f.session.readDemand())
        val before = f.session.observed()
        C2Fixture.failure { f.session.feed(byteArrayOf()) }
        assertEquals(before, f.session.observed())
        // The discarded C0 guard must be unregistered; registry rotation cannot re-emit.
        val count = f.events.size; f.secrets.registerSynthetic("visible")
        assertEquals(count, f.events.size); assertEquals("visible", f.text())
    }

    @Test fun `interleaved public arrival join is scanned independently of canonical projection`() {
        val f = C2Fixture(); f.created()
        f.added(message(emptyList())); f.added(message(emptyList(), "msg_2"), 1)
        f.done(message(listOf("access_"), "msg_2"), 1)
        C2Fixture.failure(ModelFailureKind.SECRET_EXPOSURE) { f.done(message(listOf("token"))) }
        assertEquals("access_", f.text()); assertNull(f.session.terminalResult())
        assertEquals(7, f.session.observed().displayedBytes)
    }

    @Test fun `canonical projection secret and marker join rejects despite safe arrival order`() {
        for (parts in listOf(listOf("access_", "token"), listOf("fixture-original-", "secret"), listOf("fixture-rotated-", "secret"))) {
            val f = C2Fixture(); f.created()
            f.added(message(emptyList())); f.added(message(emptyList(), "msg_2"), 1)
            val raw = listOf(message(listOf(parts[0])), message(listOf(parts[1]), "msg_2"))
            f.done(raw[1], 1); f.done(raw[0])
            C2Fixture.failure(ModelFailureKind.SECRET_EXPOSURE) { f.terminal(raw) }
            assertNull(f.session.terminalResult()); assertFalse(f.text().contains(parts.joinToString("")))
            assertEquals(f.text().toByteArray().size.toLong(), f.session.observed().displayedBytes)
        }
    }

    @Test fun `max C0 overlap and multibyte cross item secrets never complete or display raw join`() {
        for (secret in listOf("x".repeat(ChatGptPlanSecretsV1.MAX_SECRET_BYTES - 1) + "y", "😀".repeat(4095) + "éé")) {
            val f = C2Fixture(reserve = 50000); f.secrets.registerSynthetic(secret)
            val split = secret.length / 2 - (secret.length / 2 % 2)
            val a = secret.substring(0, split); val b = secret.substring(split)
            f.created(); f.added(message(emptyList())); f.added(message(emptyList(), "msg_2"), 1)
            f.done(message(listOf("前" + a)))
            C2Fixture.failure(ModelFailureKind.SECRET_EXPOSURE) { f.done(message(listOf(b), "msg_2"), 1) }
            assertFalse(f.text().contains(secret)); assertNull(f.session.terminalResult())
            assertEquals(f.text().toByteArray().size.toLong(), f.session.observed().displayedBytes)
        }
    }

    @Test fun `bounded public window handles benign multibyte and exact raw replay through actual C1`() {
        val f = C2Fixture(reserve = 80000)
        val raw = listOf(message(listOf("中".repeat(9000))), message(listOf("😀".repeat(5000), "é"), "msg_2"))
        f.created(); f.added(message(emptyList())); f.added(message(emptyList(), "msg_2"), 1)
        f.done(raw[1], 1); f.done(raw[0]); f.terminal(raw)
        val r = f.session.terminalResult() as ChatGptAttemptResultV1.Completed
        assertEquals(47002, r.local.decodedOutputBytes); assertEquals(47002, r.local.displayedBytes)
        assertEquals("中".repeat(9000) + "😀".repeat(5000) + "é", r.response.text)
        assertEquals("😀".repeat(5000) + "é" + "中".repeat(9000), f.text())
        val replay = f.codec.encode(f.run, f.prior + ModelMessageV2(ModelRole.ASSISTANT, r.response.text, r.response.continuation), emptyMap()).encoded().toString(Charsets.UTF_8)
        raw.forEach { assertTrue(replay.contains(it)) }
        assertEquals(raw, r.response.continuation.orderedItems().map { it.toString(Charsets.UTF_8) })
    }

    @Test fun `final registry rotation rescans decoded arguments raw slices private trees and neutral joins`() {
        for (mode in 0..3) {
            lateinit var f: C2Fixture
            val rotated = when (mode) { 0 -> "latevalue"; 1 -> "\"type\":\"reasoning\",\"id\""; 2 -> "opaque-final"; else -> "leftright" }
            f = C2Fixture(callback = { if ((it as ModelEventV2.TextDelta).text == "fixture-") f.secrets.registerSynthetic(rotated) })
            f.created()
            val raw = when (mode) {
                0 -> listOf(C2Fixture.function("""{"path":"source.c","text":"\u006catevalue"}"""), C2Fixture.message("fixture-"))
                1, 2 -> listOf(if (mode == 1) C2Fixture.reasoning() else C2Fixture.reasoning().replace("opaque-final", "opaque-\\u0066inal"), C2Fixture.message("fixture-"))
                else -> listOf(message(listOf("left")), message(listOf("right"), "msg_2"), message(listOf("fixture-"), "msg_3"))
            }
            raw.forEachIndexed { index, item ->
                val seed = if (mode == 0 && index == 0) C2Fixture.function("", "in_progress") else if (mode in 1..2 && index == 0) """{"id":"rs_1","type":"reasoning"}""" else message(emptyList(), if (mode == 3) "msg_${index + 1}" else "msg_1")
                f.added(seed, index)
            }
            // Safe display order differs from canonical neutral order in the join case.
            if (mode == 3) { f.done(raw[1], 1); f.done(raw[0]); f.done(raw[2], 2) }
            else raw.forEachIndexed { index, item -> f.done(item, index) }
            C2Fixture.failure(ModelFailureKind.SECRET_EXPOSURE) { f.terminal(raw) }
            assertNull(f.session.terminalResult()); assertEquals(0, f.effects)
            assertEquals(f.text().toByteArray().size.toLong(), f.session.observed().displayedBytes)
        }
    }

    @Test fun `benign final registry rotation preserves exact replay and already delivered observation`() {
        lateinit var f: C2Fixture
        f = C2Fixture(callback = { f.secrets.registerSynthetic("unrelated-synthetic-value") })
        val r = f.complete("fixture-")
        assertEquals("fixture-", f.text()); assertEquals(8, r.local.displayedBytes)
        val replay = f.codec.encode(f.run, f.prior + ModelMessageV2(ModelRole.ASSISTANT, r.response.text, r.response.continuation), emptyMap()).encoded().toString(Charsets.UTF_8)
        assertTrue(replay.contains(C2Fixture.message("fixture-")))
        f.session.discard(); assertSame(r, f.session.terminalResult())
    }

    @Test fun `actual A and C1 classes share freshly compiled C2 origin`() {
        val origin = ChatGptPlanResponsesV1::class.java.protectionDomain.codeSource.location
        for (klass in listOf(AttemptLedgerV2::class.java, AttemptMeterV2::class.java, BuiltinToolBatchV2::class.java,
            ModelRunAdmissionV2::class.java, ValidatedResponsesTurnV1::class.java, ChatGptPlanRequestV1::class.java, ChatGptPlanSecretsV1::class.java)) {
            assertEquals(origin, klass.protectionDomain.codeSource.location)
            println("C2_CLASS ${klass.name}=$origin")
        }
    }


    /** Test-only callback trace: no production hooks, reflection writes, or substitute A/C1. */
    private class PublicationProbe(val stopped: Boolean = false, val suffix: String = "",
        private val target: Pair<String, Int>? = null,
        private val action: (C2Fixture) -> Boolean = { false }) {
        var armed = false
        var entered = false
        var monitorHeld = false
        val checks = linkedMapOf<String, Int>()
        val captured = ArrayList<ChatGptAttemptResultV1>()
        val f: C2Fixture
        var failure: ModelProviderException? = null
        init {
            var owner: C2Fixture? = null
            f = C2Fixture(V2Fixture(cancellation = decompengine.agent.AgentCancellation {
                val current = owner
                if (!armed || current == null) false else {
                    current.session.terminalResult()?.let { captured.add(it) }
                    val stack = Thread.currentThread().stackTrace
                    fun session(method: String) = stack.any {
                        it.className.endsWith("ChatGptPlanResponsesV1\$Session") && it.methodName == method
                    }
                    val stage = when {
                        session("complete") && Thread.holdsLock(current.secrets) -> "private"
                        session("complete") || session("stop") -> "build"
                        session("event") -> "event"
                        stack.any { it.className.endsWith("ChatGptPlanSseV1") && it.methodName == "feed" } -> "framer"
                        else -> "feed"
                    }
                    val n = checks.getOrDefault(stage, 0) + 1
                    checks[stage] = n
                    if (!entered && target == stage to n) {
                        entered = true
                        monitorHeld = Thread.holdsLock(current.secrets)
                        action(current)
                    } else false
                }
            }))
            owner = f
        }
        fun run(): PublicationProbe {
            val raw = listOf(C2Fixture.message("fixture-"), C2Fixture.function())
            f.created(); f.added(C2Fixture.message("", status = "in_progress")); f.done(raw[0])
            f.added(C2Fixture.function("", "in_progress"), 1); f.done(raw[1], 1)
            val json = if (stopped) f.event("error", "\"code\":null,\"message\":\"synthetic failure\",\"param\":null")
                else f.event("response.completed", "\"response\":${C2Fixture.envelope("completed", raw)}")
            val bytes = ("data: $json\n\n" + suffix).toByteArray()
            armed = true
            try { f.session.feed(bytes) } catch (e: ModelProviderException) { failure = e }
            finally { armed = false }
            return this
        }
        fun assertRejected(kind: ModelFailureKind) {
            // Exercise actual A if anything escaped, including a transient parent capture.
            val escaped = captured.firstOrNull() ?: f.session.terminalResult()
            if (escaped is ChatGptAttemptResultV1.Completed) { f.settle(escaped); f.execute(escaped.response) }
            assertEquals(0, f.previews); assertEquals(0, f.effects)
            assertTrue(entered); assertNotNull(failure); assertEquals(kind, failure!!.kind)
            assertNull(failure!!.cause); assertTrue(failure!!.suppressed.isEmpty())
            assertTrue(captured.isEmpty()); assertNull(f.session.terminalResult()); assertEquals(0, f.session.readDemand())
        }
    }

    @Test fun terminalCandidatesStayPrivateAcrossEveryParentCallbackForCompletionAndStop() {
        for (stopped in listOf(false, true)) {
            val p = PublicationProbe(stopped, "unread suffix").run()
            assertNull(p.failure); assertTrue(p.checks.values.sum() > 0); assertTrue(p.captured.isEmpty())
            val ready = p.f.session.terminalResult()!!
            assertEquals(if (stopped) AttemptOutcomeV2.FAILED else AttemptOutcomeV2.COMPLETED, ready.outcome)
            assertSame(ready, p.f.session.endOfInput())
            if (ready is ChatGptAttemptResultV1.Completed) {
                p.f.settle(ready); p.f.execute(ready.response)
                assertEquals(1, p.f.previews); assertEquals(1, p.f.effects)
            }
            p.f.session.discard(); assertSame(ready, p.f.session.terminalResult())
        }
    }

    @Test fun revokedFinalParentCallbacksCannotCaptureExecutableCompletionOrStop() {
        for (stopped in listOf(false, true)) {
            val trace = PublicationProbe(stopped, "suffix").run()
            // Final check inside complete's reentrant monitor, enclosing event, SSE suffix,
            // and outer feed. Target the last real callback in each stage, not a line number.
            for (stage in listOf(if (stopped) "build" else "private", "event", "framer", "feed")) {
                val last = trace.checks.getValue(stage)
                for (action in 0..3) {
                    val probe = PublicationProbe(stopped, "suffix", stage to last) { f ->
                        when (action) {
                            0 -> f.session.discard()
                            1 -> try { f.session.feed(byteArrayOf()) } catch (_: ModelProviderException) {}
                            2 -> try { f.session.endOfInput() } catch (_: ModelProviderException) {}
                            else -> try { f.session.readDemand() } catch (_: ModelProviderException) {}
                        }
                        false
                    }.run()
                    probe.assertRejected(ModelFailureKind.MALFORMED_RESPONSE)
                }
            }
        }
    }

    @Test fun finalParentRegistryChangesFenceCompletionAndStopBeforePublication() {
        for (stopped in listOf(false, true)) {
            val trace = PublicationProbe(stopped, "suffix").run()
            val collision = if (stopped) (trace.f.session.terminalResult() as ChatGptAttemptResultV1.Stopped).diagnostic.render() else "fixture-"
            for (stage in listOf(if (stopped) "build" else "private", "event", "framer", "feed")) {
                val probe = PublicationProbe(stopped, "suffix", stage to trace.checks.getValue(stage)) { f ->
                    f.secrets.registerSynthetic(collision); false
                }.run()
                probe.assertRejected(ModelFailureKind.SECRET_EXPOSURE)
                if (stage == "private") assertTrue(probe.monitorHeld, "Same-thread registration must be fenced even under the registry monitor")
            }
        }
    }

    @Test fun boundedRevisionFenceRejectsEvenBenignChangesButAcceptsDuplicateRegistrations() {
        for (stopped in listOf(false, true)) {
            val trace = PublicationProbe(stopped).run()
            for (duplicate in listOf(false, true)) {
                val p = PublicationProbe(stopped, target = "feed" to trace.checks.getValue("feed")) { f ->
                    f.secrets.registerSynthetic(if (duplicate) "fixture-original-secret" else "new-benign-synthetic-value")
                    false
                }.run()
                if (!duplicate) p.assertRejected(ModelFailureKind.SECRET_EXPOSURE)
                else {
                    assertTrue(p.entered); assertNull(p.failure); assertTrue(p.captured.isEmpty())
                    val result = p.f.session.terminalResult()!!
                    if (result is ChatGptAttemptResultV1.Completed) {
                        assertEquals(listOf(C2Fixture.message("fixture-"), C2Fixture.function()),
                            result.response.continuation.orderedItems().map { it.toString(Charsets.UTF_8) })
                        p.f.settle(result); p.f.execute(result.response)
                        assertEquals(1, p.f.effects)
                    }
                }
            }
        }
    }

    @Test fun finalParentCancellationAndTimeoutKeepOriginalPriorityOverRevocationAndRegistryChange() {
        for (stopped in listOf(false, true)) {
            val trace = PublicationProbe(stopped).run()
            for (kind in listOf(ModelFailureKind.CANCELLED, ModelFailureKind.TIMEOUT)) {
                val p = PublicationProbe(stopped, target = "feed" to trace.checks.getValue("feed")) { f ->
                    f.session.discard(); f.secrets.registerSynthetic("late-benign-value")
                    if (kind == ModelFailureKind.TIMEOUT) f.fixture.now = Duration.ofHours(1).toNanos()
                    kind == ModelFailureKind.CANCELLED
                }.run()
                p.assertRejected(kind)
            }
        }
    }

}
