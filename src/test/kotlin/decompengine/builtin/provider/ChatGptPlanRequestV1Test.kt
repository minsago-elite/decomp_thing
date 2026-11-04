package decompengine.builtin.provider

import com.sun.management.ThreadMXBean
import java.lang.management.ManagementFactory
import decompengine.agent.AgentCancellation
import decompengine.agent.AgentCancellationSource
import decompengine.builtin.*
import kotlinx.serialization.json.*
import java.time.Duration
import java.util.UUID
import kotlin.test.*

/** Actual A admission/ledger/batch objects; all identities and effects are synthetic. */
private class RequestFixture(val fixture: V2Fixture = V2Fixture()) {
    val run = fixture.bind()
    val ledger = AttemptLedgerV2(run)
    val secrets = ChatGptPlanSecretsV1()
    val codec = ChatGptPlanRequestV1(secrets)
    val prior = listOf(ModelMessageV2(ModelRole.SYSTEM, "rules"), ModelMessageV2(ModelRole.USER, "task"))
    var effects = 0
    var previews = 0
    var resultCeiling = 16L
    fun call(body: ByteArray = codec.encode(run, prior, emptyMap()).encoded(), ordinal: Int = ledger.counters().requests.toInt() + 1): Pair<ReservedLease, AdmittedModelCallV2> {
        val lease = ledger.reserve(UUID.randomUUID(), ordinal, body.size.toLong(), 4096)
        ledger.markDispatchIntent(lease, ledger.durableSequence() + 1)
        return lease to ledger.call(lease, body)
    }
    fun response(items: List<String> = listOf(reasoning(), message(), function()),
        proposals: List<ToolProposalV2> = listOf(proposal()), text: String = "hello", responseId: String? = null,
        settle: Boolean = true, outcome: AttemptOutcomeV2 = AttemptOutcomeV2.COMPLETED,
        digest: String = neutral(text, proposals), finish: ModelFinishReason = if (proposals.isEmpty()) ModelFinishReason.STOP else ModelFinishReason.TOOL_CALLS): ModelResponseV2 {
        val (lease, call) = call()
        val turn = ValidatedResponsesTurnV1(call, responseId ?: "resp_${call.ordinal}", items.map { it.toByteArray() }, proposals, digest)
        if (settle) ledger.settle(lease, ObservedLocalCountersV2(), null, outcome)
        return ModelResponseV2(text, finish, turn, null)
    }
    fun messages(r: ModelResponseV2) = prior + ModelMessageV2(ModelRole.ASSISTANT, r.text, r.continuation)
    fun results(r: ModelResponseV2, text: String = "ok") = mapOf(r.continuation to r.continuation.proposals.map { ToolResultV2(it.callId, text) })
    fun batch(space: EncodedSpaceV2 = codec.encodedSpace(run, prior, emptyMap())) = BuiltinToolBatchV2(ledger, fixture.policy, fixture.inventory,
        object : ToolAuthorityV2 {
            override fun preview(proposal: ToolProposalV2, arguments: JsonObject, policy: ToolRequestPolicyV2, inventory: ToolInventoryV2): EffectPreviewV2 {
                previews++
                return EffectPreviewV2(fixture.path, ToolOperationV2.WRITE, resultCeiling, 1, 1, 1, 1, 1)
            }
            override fun currentBindingCommitment() = run.bindingCommitment
            override fun recheck(effect: EffectPreviewV2, policy: ToolRequestPolicyV2, inventory: ToolInventoryV2) = true
        }, space)
    fun execute(batch: BuiltinToolBatchV2, response: ModelResponseV2, text: String = "ok"): List<ToolResultV2> =
        batch.execute(batch.previewBatch(response)) { _, _, out -> effects++; out.append(text) }
    companion object {
        fun proposal(id: String = "call_1", item: String = "fc_1", arguments: String = """{"path":"source.c","text":"new"}""", caller: String? = "direct") =
            ToolProposalV2("decomp", "write", id, item, arguments, caller)
        fun function(p: ToolProposalV2 = proposal()) = """{ "type":"function_call", "id":${q(p.outputItemId)},"call_id":${q(p.callId)},"namespace":"decomp","name":"write","arguments":${q(p.argumentsJson)},"status":"completed","caller":${if (p.caller == null) "null" else """{"type":"${p.caller}"}"""},"async":false }"""
        fun message(id: String = "msg_1", text: String = "hello") = """{ "id":"$id", "type":"message","role":"assistant","status":"completed","phase":"commentary","content":[{"type":"output_text","text":${q(text)},"annotations":[],"logprobs":[]}] }"""
        fun reasoning(id: String = "rs_1") = """{ "type":"reasoning", "id":"$id", "summary":[{"type":"summary_text","text":"private summary"}], "content":[{"type":"reasoning_text","text":"private reasoning"}], "encrypted_content":"opaque-final-encrypted", "status":"completed" }"""
        fun q(s: String) = JsonPrimitive(s).toString()
        fun neutral(text: String, proposals: List<ToolProposalV2>) = v2Digest(listOf("responses-neutral-v1", text) + proposals.flatMap {
            listOf(it.namespace ?: "", it.name, it.callId, it.outputItemId, it.argumentsJson, it.caller ?: "", it.asynchronous.toString())
        })
    }
}

class ChatGptPlanRequestV1Test {
    @Test fun cancelledFactoryChecksBeforeBodyClone() {
        val bean = ManagementFactory.getThreadMXBean() as ThreadMXBean
        assertTrue(bean.isThreadAllocatedMemorySupported)
        bean.isThreadAllocatedMemoryEnabled = true
        val tid = Thread.currentThread().threadId()
        var armed = false; var seen = -1L
        val fixture = V2Fixture(definitions = mutableListOf(), cancellation = AgentCancellation {
            if (armed) { seen = bean.getThreadAllocatedBytes(tid); true } else false
        })
        val f = RequestFixture(fixture)
        val body = f.codec.encode(f.run, listOf(ModelMessageV2(ModelRole.USER, "x".repeat(700000))), emptyMap()).encoded()
        val call = f.call(body).second
        armed = true
        // Warm the exact failure path, excluding class-loading noise from the measured sample.
        repeat(10) { failure(ModelFailureKind.CANCELLED) { PreparedChatGptRequestV1.fromAdmittedCall(call, f.secrets) } }
        val before = bean.getThreadAllocatedBytes(tid)
        failure(ModelFailureKind.CANCELLED) { PreparedChatGptRequestV1.fromAdmittedCall(call, f.secrets) }
        val allocatedBeforeFirstCheck = seen - before
        println("CANCEL_COPY bodyBytes=${body.size} allocatedBeforeFirstCheck=$allocatedBeforeFirstCheck")
        assertTrue(allocatedBeforeFirstCheck < 100000, "cancelled call copied ${body.size} body bytes before first cancellation check ($allocatedBeforeFirstCheck allocated)")
    }

    @Test fun expiredFactoryChecksBeforeBodyClone() {
        val bean = ManagementFactory.getThreadMXBean() as ThreadMXBean
        bean.isThreadAllocatedMemoryEnabled = true
        val f = RequestFixture(V2Fixture(definitions = mutableListOf()))
        val body = f.codec.encode(f.run, listOf(ModelMessageV2(ModelRole.USER, "x".repeat(700000))), emptyMap()).encoded()
        val call = f.call(body).second
        f.fixture.now = Duration.ofMinutes(20).toNanos()
        val tid = Thread.currentThread().threadId()
        repeat(10) { failure(ModelFailureKind.TIMEOUT) { PreparedChatGptRequestV1.fromAdmittedCall(call, f.secrets) } }
        val before = bean.getThreadAllocatedBytes(tid)
        failure(ModelFailureKind.TIMEOUT) { PreparedChatGptRequestV1.fromAdmittedCall(call, f.secrets) }
        val allocated = bean.getThreadAllocatedBytes(tid) - before
        println("TIMEOUT_COPY bodyBytes=${body.size} allocated=$allocated")
        assertTrue(allocated < 100000, "expired call allocated $allocated bytes")
    }


    private fun failure(kind: ModelFailureKind? = null, action: () -> Unit): ModelProviderException {
        val e = assertFailsWith<ModelProviderException>(block = action)
        if (kind != null) assertEquals(kind, e.kind)
        assertNull(e.cause); assertTrue(e.suppressed.isEmpty()); assertFalse(e.message.orEmpty().contains("opaque-final"))
        return e
    }
    private fun body(f: RequestFixture, r: ModelResponseV2) = f.codec.encode(f.run, f.messages(r), f.results(r)).encoded().toString(Charsets.UTF_8)

    @Test fun `complete body omits empty tools and preserves all plain context`() {
        val f = V2Fixture(definitions = mutableListOf())
        val messages = listOf(ModelMessageV2(ModelRole.SYSTEM, "rules"), ModelMessageV2(ModelRole.USER, "hello"), ModelMessageV2(ModelRole.ASSISTANT, "answer"))
        val prepared = ChatGptPlanRequestV1(ChatGptPlanSecretsV1()).encode(f.bind(), messages, emptyMap())
        assertEquals("""{"model":"fixture-model","input":[{"role":"developer","content":"rules"},{"role":"user","content":"hello"},{"role":"assistant","content":"answer"}],"store":false,"stream":true,"include":["reasoning.encrypted_content"]}""", prepared.encoded().toString(Charsets.UTF_8))
        assertEquals(prepared.encoded().size.toLong(), prepared.bytes)
        val copy = prepared.encoded(); copy.fill(0)
        assertEquals('{'.code.toByte(), prepared.encoded()[0])
        assertEquals("PreparedChatGptRequestV1(redacted)", prepared.toString())
    }
    @Test fun `frozen namespace optional schema exact definitions and strict false`() {
        val schema = """{ "type":"object", "properties":{"path":{"type":"string"},"text":{"type":"string"}},"required":["path"],"additionalProperties":false }"""
        val defs = mutableListOf(ToolDefinitionV2("write", "original description", schema))
        val f = RequestFixture(V2Fixture(definitions = defs)); defs.clear()
        val encoded = f.codec.encode(f.run, f.prior, emptyMap()).encoded().toString(Charsets.UTF_8)
        assertTrue(encoded.contains("\"parameters\":$schema"))
        val json = Json.parseToJsonElement(encoded).jsonObject
        assertEquals(setOf("model", "input", "store", "stream", "include", "tools"), json.keys)
        val ns = json.getValue("tools").jsonArray.single().jsonObject
        assertEquals("decomp", ns.getValue("name").jsonPrimitive.content)
        val tool = ns.getValue("tools").jsonArray.single().jsonObject
        assertEquals(JsonPrimitive(false), tool["strict"])
        assertEquals(Json.parseToJsonElement(schema), tool["parameters"])
        val p = RequestFixture.proposal(arguments = """{"path":"source.c"}""")
        val r = f.response(items = listOf(RequestFixture.function(p)), proposals = listOf(p), text = "")
        assertTrue(body(f, r).contains("function_call_output"))
    }
    @Test fun `escaping controls astral scalars and malformed UTF16`() {
        val f = RequestFixture(V2Fixture(definitions = mutableListOf()))
        val text = "\"\\\u0000\n\r\t\b\u000c é中😀"
        val encoded = f.codec.encode(f.run, listOf(ModelMessageV2(ModelRole.USER, text)), emptyMap())
        val string = encoded.encoded().toString(Charsets.UTF_8)
        assertTrue(string.contains("\\\"\\\\\\u0000\\u000a\\u000d\\u0009\\u0008\\u000c é中😀"))
        assertEquals(text, Json.parseToJsonElement(string).jsonObject.getValue("input").jsonArray[0].jsonObject.getValue("content").jsonPrimitive.content)
        assertEquals(string.toByteArray().size.toLong(), encoded.bytes)
        for (s in listOf("\uD800", "\uDC00", "a\uD800b")) failure(ModelFailureKind.INVALID_REQUEST) { f.codec.encode(f.run, listOf(ModelMessageV2(ModelRole.USER, s)), emptyMap()) }
    }
    @Test fun `request and context exact fits reject one byte over before allocation`() {
        fun run(budget: LocalBudgetV1, text: String): Long {
            val f = RequestFixture(V2Fixture(local = budget, definitions = mutableListOf()))
            return f.codec.encode(f.run, listOf(ModelMessageV2(ModelRole.USER, text)), emptyMap()).bytes
        }
        val text = "x".repeat(200)
        val bytes = run(LocalBudgetV1(), text)
        assertEquals(bytes, run(LocalBudgetV1(requestBytes = bytes), text))
        failure(ModelFailureKind.RESOURCE_EXHAUSTED) { run(LocalBudgetV1(requestBytes = bytes - 1), text) }
        val context = 4 * ((bytes + 2) / 3)
        val available = context * 3 / 4
        val adjusted = text + "x".repeat((available - bytes).toInt())
        val exact = LocalBudgetV1(contextBytes = context, continuationBytes = context, historyReserveBytes = context / 4, toolResultBytes = 32)
        assertEquals(available, run(exact, adjusted))
        failure(ModelFailureKind.RESOURCE_EXHAUSTED) { run(exact, adjusted + "x") }
    }
    @Test fun `raw complete continuation slices once in order with later context positions`() {
        val f = RequestFixture(); val r = f.response()
        val later = ModelMessageV2(ModelRole.USER, "later")
        val bytes = f.codec.encode(f.run, f.messages(r) + later, f.results(r)).encoded().toString(Charsets.UTF_8)
        val exact = listOf(RequestFixture.reasoning(), RequestFixture.message(), RequestFixture.function()).joinToString(",")
        assertTrue(bytes.contains(exact + ","))
        for (raw in listOf(RequestFixture.reasoning(), RequestFixture.message(), RequestFixture.function())) assertEquals(1, bytes.windowed(raw.length).count { it == raw })
        val input = Json.parseToJsonElement(bytes).jsonObject.getValue("input").jsonArray
        assertEquals(7, input.size)
        assertEquals("reasoning", input[2].jsonObject.getValue("type").jsonPrimitive.content)
        assertEquals("function_call_output", input[5].jsonObject.getValue("type").jsonPrimitive.content)
        assertEquals("later", input[6].jsonObject.getValue("content").jsonPrimitive.content)
        assertEquals("private reasoning", input[2].jsonObject.getValue("content").jsonArray[0].jsonObject.getValue("text").jsonPrimitive.content)
    }
    @Test fun `multiple host results require exact ordered identity mapping`() {
        val p1 = RequestFixture.proposal(); val p2 = RequestFixture.proposal("call_2", "fc_2")
        val f = RequestFixture(); val r = f.response(listOf(RequestFixture.function(p1), RequestFixture.function(p2)), listOf(p1, p2), "")
        val good = f.results(r)
        assertTrue(body(f, r).contains("call_2"))
        val a = good.getValue(r.continuation)
        for (bad in listOf(emptyList(), a.take(1), a.reversed(), listOf(a[0], a[0]), a + a[0], listOf(a[0], ToolResultV2("unknown", "ok")))) {
            failure { f.codec.encode(f.run, f.messages(r), mapOf(r.continuation to bad)) }
        }
        failure { f.codec.encode(f.run, f.messages(r), emptyMap()) }
        failure { f.codec.encode(f.run, f.prior, good) }
        val other = RequestFixture(); val foreign = other.response()
        failure { f.codec.encode(f.run, f.messages(r), good + other.results(foreign)) }
    }
    @Test fun `generic TOOL and duplicated turn handles are rejected`() {
        val f = RequestFixture(); val r = f.response()
        failure(ModelFailureKind.UNSUPPORTED_FEATURE) { f.codec.encode(f.run, listOf(ModelMessageV2(ModelRole.TOOL, "fake")), emptyMap()) }
        failure { f.codec.encode(f.run, f.messages(r) + ModelMessageV2(ModelRole.ASSISTANT, r.text, r.continuation), f.results(r)) }
    }
    @Test fun `same binding foreign run and changed registry cannot replay`() {
        val a = RequestFixture(); val r = a.response()
        val sameBindingDifferentRun = RequestFixture()
        assertEquals(a.run.bindingCommitment, sameBindingDifferentRun.run.bindingCommitment)
        failure { sameBindingDifferentRun.codec.encode(sameBindingDifferentRun.run, a.messages(r), a.results(r)) }
        val drift = RequestFixture(V2Fixture(definitions = mutableListOf(V2Fixture.tool("other"))))
        failure { drift.codec.encode(drift.run, a.messages(r), a.results(r)) }
        val changedBinding = AccountBindingV2(a.run.binding.accountId, a.run.binding.issuer, a.run.binding.hostId, a.run.binding.issuedClient, "d".repeat(64), 2, a.run.binding.modelSlug)
        val forged = AdmittedModelRunV2.mint(a.run.checked, changedBinding)
        failure { a.codec.encode(forged, a.messages(r), a.results(r)) }
    }
    @Test fun `neutral digest text and proposal projections are recomputed`() {
        val scenarios = listOf(
            Triple("wrong", listOf(RequestFixture.proposal()), "0".repeat(64)),
            Triple("hello", listOf(RequestFixture.proposal(arguments = "{}")), RequestFixture.neutral("hello", listOf(RequestFixture.proposal(arguments = "{}")))),
            Triple("hello", listOf(RequestFixture.proposal(caller = null)), RequestFixture.neutral("hello", listOf(RequestFixture.proposal(caller = null))))
        )
        for ((text, proposals, digest) in scenarios) {
            val f = RequestFixture(); val r = f.response(text = text, proposals = proposals, digest = digest)
            failure { body(f, r) }
        }
        val f = RequestFixture(); val r = f.response(digest = "a".repeat(64)); failure { body(f, r) }
        val valid = RequestFixture(); val rv = valid.response()
        failure { valid.codec.encode(valid.run, valid.prior + ModelMessageV2(ModelRole.ASSISTANT, "changed", rv.continuation), valid.results(rv)) }
    }
    @Test fun `history rejects response item call ID reuse and nonmonotonic ordinals`() {
        for (reuse in listOf("response", "item", "call", "ordinal")) {
            val f = RequestFixture(); val first = f.response()
            val p = RequestFixture.proposal(if (reuse == "call") "call_1" else "call_2", if (reuse == "item") "fc_1" else "fc_2")
            val second = f.response(listOf(RequestFixture.function(p)), listOf(p), "", if (reuse == "response") first.continuation.responseId else null)
            val ms = if (reuse == "ordinal") f.prior + listOf(second, first).map { ModelMessageV2(ModelRole.ASSISTANT, it.text, it.continuation) }
                else f.messages(first) + ModelMessageV2(ModelRole.ASSISTANT, second.text, second.continuation)
            failure { f.codec.encode(f.run, ms, f.results(first) + f.results(second)) }
        }
    }
    @Test fun `strict raw malformed duplicate key caller async unsupported item shapes fail`() {
        val raw = RequestFixture.function()
        val invalid = listOf(
            raw.replace("\"type\":\"function_call\"", "\"type\":\"function_call\",\"type\":\"function_call\""),
            raw.replace("\"async\":false", "\"async\":true"),
            raw.replace("{\"type\":\"direct\"}", "\"direct\""),
            raw.replace("{\"type\":\"direct\"}", "{\"type\":\"program\"}"),
            raw.replace("\"namespace\":\"decomp\"", "\"namespace\":\"foreign\""),
            raw.replace("\"status\":\"completed\"", "\"status\":\"in_progress\""),
            raw.replace("\"async\":false", "\"async\":false,\"executable\":true"),
            raw.replace("\"type\":\"function_call\"", "\"type\":\"custom_tool_call\""),
            raw + "{}", "{", raw.replace("\"fc_1\"", "\"bad.id\""),
            raw.replace("\"fc_1\"", "\"" + "x".repeat(129) + "\""),
            raw.replace("\"call_1\"", "\"" + "x".repeat(65) + "\""),
            raw.replace("\"write\"", "\"unknown\""),
        )
        for (item in invalid) {
            val f = RequestFixture(); val r = f.response(listOf(item), text = "")
            failure { body(f, r) }
        }
    }
    @Test fun `strict reasoning message parts and refusal profile`() {
        val invalid = listOf(
            RequestFixture.reasoning().replace("\"opaque-final-encrypted\"", "\"\""),
            RequestFixture.reasoning().replace("\"opaque-final-encrypted\"", "null"),
            RequestFixture.reasoning().replace("summary_text", "output_text"),
            RequestFixture.reasoning().replace("\"status\":\"completed\"", "\"status\":\"in_progress\""),
            RequestFixture.message().replace("\"annotations\":[]", "\"annotations\":[{}]"),
            RequestFixture.message().replace("\"logprobs\":[]", "\"logprobs\":[0]"),
            RequestFixture.message().replace("commentary", "unknown"),
            RequestFixture.message().replace("assistant", "system"),
            RequestFixture.message().replace("output_text", "image"),
            RequestFixture.message().replace("\"text\":\"hello\"", "\"text\":\"\\uD800\""),
        )
        for (item in invalid) { val f = RequestFixture(); val r = f.response(listOf(item), emptyList()); failure { body(f, r) } }
        val refusal = """{"id":"ref_1","type":"message","role":"assistant","status":"completed","phase":null,"content":[{"type":"refusal","refusal":"no"}]}"""
        val f = RequestFixture(); val r = f.response(listOf(refusal), emptyList(), "no", finish = ModelFinishReason.REFUSED)
        assertTrue(body(f, r).contains(refusal))
        val mixed = RequestFixture(); val m = mixed.response(listOf(refusal, RequestFixture.function()), text = "no")
        failure { body(mixed, m) }
    }
    @Test fun `argument schemas duplicate keys numbers and Unicode fail before effects`() {
        for (args in listOf("{}", """{"path":"source.c","text":1}""", """{"path":"source.c","text":"x","text":"y"}""", """{"path":"source.c","text":"\uD800"}""", """{"path":"source.c","text":"x","extra":0}""")) {
            val f = RequestFixture(); val p = RequestFixture.proposal(arguments = args); val r = f.response(listOf(RequestFixture.function(p)), listOf(p), "")
            failure { body(f, r) }
            assertEquals(0, f.effects)
        }
    }
    @Test fun `secret rejection covers raw private data nested arguments and all primitives`() {
        for (item in listOf(RequestFixture.reasoning(), RequestFixture.message(), RequestFixture.function())) {
            val f = RequestFixture(); f.secrets.registerSynthetic(when { item.contains("reasoning_text") -> "private reasoning"; item.contains("output_text") -> "hello"; else -> "source.c" })
            val r = f.response(listOf(item), if (item.contains("function_call")) listOf(RequestFixture.proposal()) else emptyList(), if (item.contains("output_text")) "hello" else "")
            failure(ModelFailureKind.SECRET_EXPOSURE) { body(f, r) }
        }
        for (value in listOf("true", "false", "null", "123")) {
            val f = RequestFixture()
            val raw = RequestFixture.function().replace("\"async\":false", "\"async\":$value")
            val r = f.response(listOf(raw), text = "")
            f.secrets.registerSynthetic(value)
            failure(ModelFailureKind.SECRET_EXPOSURE) { body(f, r) }
        }
        val f = RequestFixture(); val p = RequestFixture.proposal(arguments = """{"path":"source.c","text":"ok","access_token":"not-a-real-token"}""")
        val r = f.response(listOf(RequestFixture.function(p)), listOf(p), "")
        failure(ModelFailureKind.SECRET_EXPOSURE) { body(f, r) }
    }
    @Test fun `long split secrets reject without rewriting and scanner scalar ceiling holds`() {
        val f = RequestFixture(V2Fixture(definitions = mutableListOf()))
        val secret = "s".repeat(ChatGptPlanSecretsV1.MAX_SECRET_BYTES)
        f.secrets.registerSynthetic(secret)
        for (offset in listOf(8191, 16383, 24575, 32767)) {
            val text = "x".repeat(offset) + secret + "y".repeat(33000)
            failure(ModelFailureKind.SECRET_EXPOSURE) { f.codec.encode(f.run, listOf(ModelMessageV2(ModelRole.USER, text)), emptyMap()) }
        }
        failure(ModelFailureKind.RESOURCE_EXHAUSTED) { f.codec.encode(f.run, listOf(ModelMessageV2(ModelRole.USER, "x".repeat((1 shl 20) + 1))), emptyMap()) }
        val text = "x".repeat(1 shl 20)
        assertTrue(f.codec.encode(f.run, listOf(ModelMessageV2(ModelRole.USER, text)), emptyMap()).bytes > text.length)
    }
    @Test fun `layout is same full body with exact empty result framing no sixfold charge`() {
        val f = RequestFixture(); val r = f.response()
        val layout = f.codec.encodedSpace(f.run, f.prior, emptyMap()).layout(r, r.continuation.proposals)
        val emptyBody = f.codec.encode(f.run, f.messages(r), f.results(r, "")).encoded().toString(Charsets.UTF_8)
        val envelope = """,{"type":"function_call_output","call_id":"call_1","output":""}"""
        assertEquals(emptyBody.toByteArray().size.toLong(), layout.exactCurrentHistoryBytes + layout.exactResultFramingBytes)
        assertEquals(envelope.toByteArray().size.toLong(), layout.exactResultFramingBytes)
        assertEquals(emptyBody.replace(envelope, "").toByteArray().size.toLong(), layout.exactCurrentHistoryBytes)
        val p = RequestFixture(); val plain = p.response(listOf(RequestFixture.message()), emptyList())
        assertEquals(0, p.codec.encodedSpace(p.run, p.prior, emptyMap()).layout(plain, emptyList()).exactResultFramingBytes)
    }
    @Test fun `layout snapshots caller lists maps and previous results`() {
        val f = RequestFixture(); val first = f.response()
        val messages = f.messages(first).toMutableList()
        val priorResults = f.results(first).mapValues { it.value.toMutableList() }.toMutableMap()
        val adapter = f.codec.encodedSpace(f.run, messages, priorResults)
        messages.clear(); priorResults.getValue(first.continuation).clear(); priorResults.clear()
        val p = RequestFixture.proposal("call_2", "fc_2")
        val second = f.response(listOf(RequestFixture.function(p)), listOf(p), "")
        val layout = adapter.layout(second, listOf(p))
        val exact = f.codec.encode(f.run, f.messages(first) + ModelMessageV2(ModelRole.ASSISTANT, "", second.continuation), f.results(first) + f.results(second, ""))
        assertEquals(exact.bytes, layout.exactCurrentHistoryBytes + layout.exactResultFramingBytes)
    }
    @Test fun `layout verifies supplied proposals response text and finish reason`() {
        val f = RequestFixture(); val r = f.response(); val space = f.codec.encodedSpace(f.run, f.prior, emptyMap())
        failure { space.layout(r, emptyList()) }
        failure { space.layout(r, listOf(RequestFixture.proposal("different"))) }
        failure { space.layout(ModelResponseV2("other", r.finishReason, r.continuation, null), r.continuation.proposals) }
        failure { space.layout(ModelResponseV2(r.text, ModelFinishReason.STOP, r.continuation, null), r.continuation.proposals) }
    }
    @Test fun `actual ledger batch adds sixfold once exact reserved sent compatible lengths`() {
        val f = RequestFixture(); val r = f.response(); val batch = f.batch()
        val empty = f.codec.encode(f.run, f.messages(r), f.results(r, ""))
        val permit = batch.previewBatch(r)
        assertEquals(empty.bytes + 6 * f.resultCeiling, permit.reservation.nextRequestBytes)
        val result = batch.execute(permit) { _, _, out -> f.effects++; out.append("\u0001".repeat(16)) }
        val prepared = f.codec.encode(f.run, f.messages(r), mapOf(r.continuation to result))
        assertEquals(permit.reservation.nextRequestBytes, prepared.bytes)
        val (_, call) = f.call(prepared.encoded())
        val send = PreparedChatGptRequestV1.fromAdmittedCall(call, f.secrets)
        assertEquals(prepared.bytes, call.encodedInputBytes)
        assertContentEquals(prepared.encoded(), send.encoded())
        assertEquals(1, f.effects)
    }
    @Test fun `actual batch rejects call id 65 and remaining budget exhaustion with zero effects`() {
        val f = RequestFixture(); val p = RequestFixture.proposal("a".repeat(65)); val r = f.response(listOf(RequestFixture.function(p)), listOf(p), "")
        val batch = f.batch(); failure { f.execute(batch, r) }; assertEquals(0, f.effects)
        val probe = RequestFixture(); val pr = probe.response(); val next = probe.codec.encodedSpace(probe.run, probe.prior, emptyMap()).layout(pr, pr.continuation.proposals)
        val reservation = next.exactCurrentHistoryBytes + next.exactResultFramingBytes + 96
        val firstBytes = probe.ledger.counters().input
        for (delta in listOf(0L, -1L)) {
            val bounded = RequestFixture(V2Fixture(local = LocalBudgetV1(inputUnits = firstBytes + reservation + delta)))
            val response = bounded.response(); val b = bounded.batch()
            if (delta == 0L) { bounded.execute(b, response); assertEquals(1, bounded.effects) }
            else { failure(ModelFailureKind.RESOURCE_EXHAUSTED) { bounded.execute(b, response) }; assertEquals(0, bounded.effects) }
        }
    }
    @Test fun `codec validation confers no current successful settlement authority`() {
        for (settled in listOf(false, true)) {
            val f = RequestFixture(); val r = f.response(settle = settled, outcome = AttemptOutcomeV2.FAILED)
            assertTrue(body(f, r).isNotEmpty()) // Same-run DTO validation deliberately cannot certify settlement.
            val batch = f.batch(); failure { f.execute(batch, r) }; assertEquals(0, f.effects); assertEquals(0, f.previews)
        }
        val f = RequestFixture(); val old = f.response(); val p = RequestFixture.proposal("call_2", "fc_2")
        f.response(listOf(RequestFixture.function(p)), listOf(p), "")
        val b = f.batch(); failure { f.execute(b, old) }; assertEquals(0, f.effects)
    }
    @Test fun `original cancellation deadline and post collection callbacks preserved`() {
        for (cancel in listOf(false, true)) {
            val source = AgentCancellationSource(); val f = RequestFixture(V2Fixture(cancellation = source.cancellation))
            val messages = object : AbstractList<ModelMessageV2>() {
                override val size = 1
                override fun get(index: Int): ModelMessageV2 {
                    if (cancel) source.cancel() else f.fixture.now = Duration.ofMinutes(20).toNanos()
                    return ModelMessageV2(ModelRole.USER, "hello")
                }
            }
            failure(if (cancel) ModelFailureKind.CANCELLED else ModelFailureKind.TIMEOUT) { f.codec.encode(f.run, messages, emptyMap()) }
        }
        var armed = false; var scans = 0
        val f = RequestFixture(V2Fixture(definitions = mutableListOf(), cancellation = AgentCancellation { armed && ++scans >= 200 }))
        armed = true
        failure(ModelFailureKind.CANCELLED) { f.codec.encode(f.run, listOf(ModelMessageV2(ModelRole.USER, "x".repeat(800000))), emptyMap()) }
        assertEquals(200, scans)
    }
    @Test fun `admitted factory preserves whitespace and rejects altered model tools and forbidden fields`() {
        val seed = RequestFixture()
        val original = seed.codec.encode(seed.run, seed.prior, emptyMap()).encoded().toString(Charsets.UTF_8)
        val valid = RequestFixture(); val (_, call) = valid.call((" \n" + original + " \t").toByteArray())
        val prepared = PreparedChatGptRequestV1.fromAdmittedCall(call, valid.secrets)
        assertContentEquals(call.encodedInput(), prepared.encoded())
        for (bad in listOf(original.replace("fixture-model", "other-model"), original.replace("offline fixture", "changed"), original.replace("\"strict\":false", "\"strict\":true"), original.replace("\"store\":false", "\"store\":true"), original.dropLast(1) + ",\"temperature\":0}", original.dropLast(1) + ",\"model\":\"fixture-model\"}", "{}", "[]")) {
            val f = RequestFixture(); val (_, altered) = f.call(bad.toByteArray())
            failure { PreparedChatGptRequestV1.fromAdmittedCall(altered, f.secrets) }
        }
    }
    @Test fun `admitted factory rejects orphan missing reordered results and unsupported inputs`() {
        val seed = RequestFixture(); val r = seed.response()
        val original = body(seed, r)
        val root = Json.parseToJsonElement(original).jsonObject
        val input = root.getValue("input").jsonArray
        val variants = listOf(input.dropLast(1), input + input.last(), listOf(input.last()) + input.dropLast(1), listOf(Json.parseToJsonElement("""{"role":"tool","content":"fake"}""")))
        for (items in variants) {
            val f = RequestFixture(); val bad = JsonObject(root + ("input" to JsonArray(items))).toString().toByteArray()
            val (_, call) = f.call(bad)
            failure { PreparedChatGptRequestV1.fromAdmittedCall(call, f.secrets) }
        }
    }
    @Test fun `malformed UTF8 duplicate nested fields and parser depth are rejected`() {
        for (bad in listOf(byteArrayOf(123, 34, 120, 34, 58, 34, 0xc0.toByte(), 0xaf.toByte(), 34, 125), "{\"x\":{\"y\":0,\"y\":1}}".toByteArray(), ("[".repeat(34) + "0" + "]".repeat(34)).toByteArray())) {
            val f = RequestFixture(); val (_, call) = f.call(bad)
            failure { PreparedChatGptRequestV1.fromAdmittedCall(call, f.secrets) }
        }
    }
    @Test fun `empty context envelope and generated primitives are validated`() {
        val f = RequestFixture(V2Fixture(definitions = mutableListOf()))
        val prepared = f.codec.encode(f.run, emptyList(), emptyMap())
        assertEquals("""{"model":"fixture-model","input":[],"store":false,"stream":true,"include":["reasoning.encrypted_content"]}""", prepared.encoded().toString(Charsets.UTF_8))
        for (secret in listOf("false", "true", "reasoning.encrypted_content", "input", "decomp", "Invocation-owned tools")) {
            val guarded = RequestFixture(); guarded.secrets.registerSynthetic(secret)
            failure(ModelFailureKind.SECRET_EXPOSURE) { guarded.codec.encode(guarded.run, guarded.prior, emptyMap()) }
        }
    }
    @Test fun `maximum call and item IDs plus absent optional fields replay successfully`() {
        val f = RequestFixture()
        val p = RequestFixture.proposal("c".repeat(64), "i".repeat(128), caller = null)
        val raw = """{"type":"function_call","id":${RequestFixture.q(p.outputItemId)},"call_id":${RequestFixture.q(p.callId)},"name":"write","namespace":"decomp","arguments":${RequestFixture.q(p.argumentsJson)}}"""
        val reason = """{"type":"reasoning","id":"reason","summary":[],"encrypted_content":"opaque"}"""
        val r = f.response(listOf(reason, raw), listOf(p), "", "r".repeat(128))
        assertTrue(body(f, r).contains(raw))
        val result = f.execute(f.batch(), r)
        assertEquals(p.callId, result.single().callId)
        assertEquals(1, f.effects)
    }
    @Test fun `multiple messages concatenate neutral projection without synthesized separators`() {
        val f = RequestFixture()
        val one = RequestFixture.message("m1", "one")
        val two = RequestFixture.message("m2", "two").replace("commentary", "final_answer")
        val r = f.response(listOf(one, RequestFixture.reasoning(), two), emptyList(), "onetwo")
        val b = body(f, r)
        assertTrue(b.contains(listOf(one, RequestFixture.reasoning(), two).joinToString(",")))
        assertFalse(b.contains("onetwo"))
        val (_, call) = f.call(b.toByteArray())
        assertContentEquals(call.encodedInput(), PreparedChatGptRequestV1.fromAdmittedCall(call, f.secrets).encoded())
    }
    @Test fun `full empty envelopes and sixfold expansion hit context cap before effects`() {
        val probe = RequestFixture(); val pr = probe.response()
        val empty = probe.codec.encode(probe.run, probe.messages(pr), probe.results(pr, "")).bytes
        val requestCap = empty + 96
        for (limit in listOf(requestCap, requestCap - 1, empty - 1)) {
            val f = RequestFixture(V2Fixture(local = LocalBudgetV1(requestBytes = limit)))
            val r = f.response(); val batch = f.batch()
            if (limit == requestCap) assertEquals(1, f.execute(batch, r).size)
            else { failure(ModelFailureKind.RESOURCE_EXHAUSTED) { f.execute(batch, r) }; assertEquals(0, f.effects) }
        }
    }
    @Test fun `raw parser retains original cancellation during large JSON and after completion`() {
        var armed = false; var reads = 0
        val f = RequestFixture(V2Fixture(definitions = mutableListOf(), cancellation = AgentCancellation { armed && ++reads >= 50 }))
        val long = "x".repeat(180000)
        val r = f.response(listOf(RequestFixture.message(text = long)), emptyList(), long)
        val (_, call) = f.call(body(f, r).toByteArray())
        armed = true
        failure(ModelFailureKind.CANCELLED) { PreparedChatGptRequestV1.fromAdmittedCall(call, f.secrets) }
        assertEquals(50, reads)
        val g = RequestFixture(); val response = g.response(); val adapter = g.codec.encodedSpace(g.run, g.prior, emptyMap())
        g.fixture.now = Duration.ofMinutes(20).toNanos()
        failure(ModelFailureKind.TIMEOUT) { adapter.layout(response, response.continuation.proposals) }
    }

    @Test fun `tool result byte ceiling is UTF8 exact and independent of escape expansion`() {
        val f = RequestFixture(V2Fixture(local = LocalBudgetV1(toolResultBytes = 4)))
        val r = f.response()
        for (value in listOf("😀", "\u0001".repeat(4))) {
            val encoded = f.codec.encode(f.run, f.messages(r), f.results(r, value))
            val result = Json.parseToJsonElement(encoded.encoded().toString(Charsets.UTF_8)).jsonObject.getValue("input").jsonArray.last().jsonObject
            assertEquals(value, result.getValue("output").jsonPrimitive.content)
        }
        failure(ModelFailureKind.RESOURCE_EXHAUSTED) { f.codec.encode(f.run, f.messages(r), f.results(r, "😀x")) }
        failure(ModelFailureKind.INVALID_REQUEST) { f.codec.encode(f.run, f.messages(r), f.results(r, "\uD800")) }
    }

    @Test fun `codec allocation headroom rejection precedes fake tool effects`() {
        val f = RequestFixture(V2Fixture(local = LocalBudgetV1(responseBytes = 65536, eventBytes = 16384)))
        val r = f.response()
        val batch = f.batch()
        failure(ModelFailureKind.RESOURCE_EXHAUSTED) { f.execute(batch, r) }
        assertEquals(0, f.effects)
    }

}
