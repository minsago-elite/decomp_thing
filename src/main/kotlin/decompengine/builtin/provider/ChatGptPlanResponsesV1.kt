package decompengine.builtin.provider

import decompengine.builtin.*
import kotlinx.serialization.json.*

/** Observation only. None of these values settles a lease or grants execution/replay authority. */
internal sealed interface ChatGptAttemptResultV1 {
    val call: AdmittedModelCallV2
    val local: ObservedLocalCountersV2
    val reported: ReportedModelUsageV1?
    val outcome: AttemptOutcomeV2
    class Completed(override val call: AdmittedModelCallV2, override val local: ObservedLocalCountersV2,
        override val reported: ReportedModelUsageV1?, val response: ModelResponseV2) : ChatGptAttemptResultV1 {
        override val outcome = AttemptOutcomeV2.COMPLETED
        override fun toString() = "ChatGptAttemptCompletedV1(redacted)"
    }
    class Stopped(override val call: AdmittedModelCallV2, override val local: ObservedLocalCountersV2,
        override val reported: ReportedModelUsageV1?, override val outcome: AttemptOutcomeV2,
        val kind: ModelFailureKind, val validatedTerminal: Boolean, val diagnostic: ChatGptSafeDiagnosticV1) : ChatGptAttemptResultV1 {
        override fun toString() = "ChatGptAttemptStoppedV1(redacted)"
    }
}

internal interface ChatGptResponsesSessionV1 {
    fun feed(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset)
    /** Zero after a terminal or rejection, otherwise <=8192 and <=remaining+1. */
    fun readDemand(): Int
    fun terminalResult(): ChatGptAttemptResultV1?
    fun endOfInput(): ChatGptAttemptResultV1
    fun observed(): ObservedLocalCountersV2
    /** C3 calls on disconnect/close failure/cancellation; never emits Finished. */
    fun discard()
}

internal object ChatGptPlanResponsesV1 {
    fun start(call: AdmittedModelCallV2, secrets: ChatGptPlanSecretsV1, sink: ModelEventV2Sink): ChatGptResponsesSessionV1 {
        call.run.deadline.remainingNanos()
        return Session(call, secrets, sink)
    }

    private class Part(val type: String) {
        var value = ""
        var initialized = false
        var deltaSeen = false
        var textDone = false
        var partAdded = false
        var partDone: JsonObject? = null
    }
    private class Item(val seed: JsonObject, val id: String, val type: String) {
        val content = ArrayList<Part>()
        val summary = ArrayList<Part>()
        val args = Part("arguments")
        var final: JsonObject? = null
        var raw: ByteArray? = null
        var proposal: ToolProposalV2? = null
    }

    private class TerminalCandidate(val value: ChatGptAttemptResultV1, val registryRevision: Int)

    private class Session(val call: AdmittedModelCallV2, val secrets: ChatGptPlanSecretsV1, val sink: ModelEventV2Sink) : ChatGptResponsesSessionV1 {
        val w = ChatGptResponseWorkV1(call, secrets) { c2Require(!dead) }
        private var totals = ObservedLocalCountersV2()
        private var result: ChatGptAttemptResultV1? = null
        // Framing may stop on this private candidate; callers must not observe it until
        // every enclosing event/feed check (including parent callbacks) has succeeded.
        private var candidate: TerminalCandidate? = null
        private var dead = false
        private var busy = false
        private var sequence = -1L
        private var responseId: String? = null
        private var progress = false
        private var parts = 0
        private var calls = 0
        private var incompletePart = false
        private val items = ArrayList<Item>()
        private val ids = HashSet<String>()
        private val callIds = HashSet<String>()
        // One public stream, including interleaved items/parts. C0 secrets are <=16384 UTF8
        // bytes (hence <=16384 UTF16 units); every credential marker is shorter. Retain
        // that overlap plus a possible scalar boundary, independently of C0's display tail.
        private var publicTail = ""
        private var publicTailAllowance = 0L
        // C0 normalizes callback failures to TRANSPORT; preserve this session's typed meter/deadline failure.
        private var callbackFailure: ModelFailureKind? = null
        private val guard = secrets.displayGuard { text ->
            try {
                w.check()
                val n = w.utf8(text, call.run.budget.displayedBytesTotal)
                totals = totals.copy(displayedBytes = v2Add(totals.displayedBytes, n))
                meter(); w.check()
                try { sink.emit(ModelEventV2.TextDelta(text)) } catch (_: Throwable) { throw ModelProviderException(ModelFailureKind.TRANSPORT) }
                w.check()
            } catch (e: ModelProviderException) { callbackFailure = e.kind; discard(); throw e }
        }
        private val framer = ChatGptPlanSseV1(call.run.budget.eventBytes.toInt(), w, ::event)

        override fun observed() = totals
        override fun terminalResult() = result
        override fun readDemand(): Int {
            if (dead || result != null) return 0
            return protect { w.check(); minOf(8192L, maxOf(1L, call.run.budget.responseBytes - totals.wireBytes + 1)).toInt() }
        }
        override fun feed(bytes: ByteArray, offset: Int, length: Int) = protect {
            c2Require(!dead && result == null && offset >= 0 && length >= 0 && offset <= bytes.size && length <= bytes.size - offset)
            c2Require(length <= readDemandInternal())
            // These bytes have already arrived. Observe before the meter checks cancellation/deadline,
            // then check again before any buffer allocation or decoding.
            totals = totals.copy(wireBytes = v2Add(totals.wireBytes, length.toLong()))
            meter(); v2Capacity(totals.wireBytes <= call.run.budget.responseBytes); w.check()
            framer.feed(bytes, offset, length)
            w.check()
        }
        private fun readDemandInternal() = minOf(8192L, maxOf(1L, call.run.budget.responseBytes - totals.wireBytes + 1)).toInt()
        override fun endOfInput(): ChatGptAttemptResultV1 = protect {
            c2Require(!dead); w.check()
            framer.endOfInput()
            result ?: candidate?.value ?: c2Malformed()
        }
        override fun discard() {
            candidate = null
            dead = true; guard.discardOnFailure(); framer.discard(); items.clear(); ids.clear(); callIds.clear(); publicTail = ""
        }
        private inline fun <T> protect(block: () -> T): T {
            if (busy) { discard(); c2Malformed() }
            busy = true
            try {
                val value = block()
                publishTerminal()
                return value
            }
            catch (e: ModelProviderException) {
                val kind = callbackFailure ?: e.kind
                result = null; discard(); throw ModelProviderException(kind)
            } catch (_: Throwable) {
                result = null; discard(); throw ModelProviderException(ModelFailureKind.MALFORMED_RESPONSE)
            } finally { busy = false }
        }
        private fun publishTerminal() {
            // No deadline, meter, sink, collection or other external callbacks here or
            // after publication. A monitor alone cannot fence same-thread registration.
            synchronized(secrets) {
                c2Require(!dead)
                val ready = candidate ?: return
                if (secrets.registryRevision() != ready.registryRevision)
                    throw ModelProviderException(ModelFailureKind.SECRET_EXPOSURE)
                result = ready.value
                candidate = null
            }
        }
        private fun meter(eventBytes: Long = 0) { call.meter.beforeDelivery(totals, eventBytes); w.check() }
        private fun decoded(s: String, public: Boolean) {
            val n = w.utf8(s)
            totals = totals.copy(decodedOutputBytes = v2Add(totals.decodedOutputBytes, n))
            meter(); w.check()
            if (public) display(s)
        }
        private fun display(s: String) {
            var i = 0
            while (i < s.length) {
                w.check(); var end = minOf(s.length, i + 8192)
                if (end < s.length && s[end].isLowSurrogate()) end--
                w.retain((publicTail.length.toLong() + end - i) * 2 + (end - i).toLong() * 2 + 128)
                val fragment = s.substring(i, end)
                val joined = publicTail + fragment
                w.scan(joined, call.run.budget.responseBytes)
                var start = maxOf(0, joined.length - ChatGptPlanSecretsV1.MAX_SECRET_BYTES)
                if (start > 0 && joined[start].isLowSurrogate()) start--
                val allowance = (joined.length - start).toLong() * 10 + 128
                if (allowance > publicTailAllowance) { w.keep(allowance - publicTailAllowance); publicTailAllowance = allowance }
                w.retain(allowance); publicTail = joined.substring(start)
                // C0's temporary coverage/output arrays include its retained lookbehind.
                w.retain(joined.length.toLong() * 16 + 128)
                guard.append(fragment); w.check(); i = end
            }
        }
        private fun seed(p: Part, value: String, public: Boolean, charged: Boolean) {
            c2Require(!p.textDone && p.partDone == null)
            if (p.initialized) { c2Require(p.value == value); return }
            if (charged) decoded(value, public)
            w.keep(value.length.toLong() * 2 + 64); w.check()
            p.value = value; p.initialized = true
        }
        private fun finalText(p: Part, value: String, public: Boolean, charged: Boolean) {
            if (p.initialized && (p.value.isNotEmpty() || p.deltaSeen || p.textDone || p.partDone != null)) c2Require(p.value == value)
            else {
                c2Require(value.startsWith(p.value))
                val suffix = value.substring(p.value.length)
                if (charged) decoded(suffix, public)
                w.keep(value.length.toLong() * 2 + 64); p.value = value; p.initialized = true
            }
        }
        private fun event(eventName: String?, bytes: ByteArray): Boolean {
            meter(bytes.size.toLong()); w.check()
            val doc = w.parse(bytes)
            val e = doc.value.obj()
            val type = e.str("type")
            if (type !in EVENT_FIELDS) c2Unsupported()
            e.shape(setOf("type", "sequence_number") + EVENT_FIELDS.getValue(type),
                setOf("obfuscation") + if (type.startsWith("response.output_text.")) setOf("logprobs") else if (type == "response.reasoning_summary_part.done") setOf("status") else emptySet())
            c2Require(eventName == null || eventName == type)
            e["obfuscation"]?.let { it.string() }
            e["logprobs"]?.let { c2Require(it is JsonArray && it.isEmpty()) }
            val next = e.getValue("sequence_number").integer(); c2Require(next > sequence); sequence = next
            when (type) {
                "error" -> {
                    e.getValue("code").nullableString(); e.str("message"); e.getValue("param").nullableString()
                    stop(AttemptOutcomeV2.FAILED, ModelFailureKind.TRANSPORT, null)
                }
                "response.created", "response.in_progress", "response.completed", "response.failed", "response.incomplete" -> envelope(type, e.getValue("response").obj())
                else -> {
                    c2Require(responseId != null)
                    when (type) {
                        "response.output_item.added" -> add(e)
                        "response.output_item.done" -> done(e, doc)
                        else -> auxiliary(type, e)
                    }
                }
            }
            w.check()
            return candidate != null
        }
        private fun envelope(type: String, r: JsonObject) {
            val id = r.str("id"); c2Require(validId(id, 128))
            c2Require(r.str("model") == call.run.binding.modelSlug)
            if (responseId != null) c2Require(responseId == id)
            val status = type.removePrefix("response.")
            c2Require(r.str("status") == if (status in setOf("created", "in_progress")) "in_progress" else status)
            when (status) {
                "created" -> {
                    c2Require(responseId == null && items.isEmpty())
                    r["output"]?.let { c2Require(it is JsonArray && it.isEmpty()) }; responseId = id
                }
                "in_progress" -> { c2Require(responseId != null && !progress && items.isEmpty()); progress = true; r["output"]?.let { c2Require(it is JsonArray && it.isEmpty()) } }
                "completed" -> {
                    c2Require(responseId != null && items.isNotEmpty() && !incompletePart)
                    c2Require(r["error"].isNull() && r["incomplete_details"].isNull())
                    val usage = usage(r["usage"])
                    val output = r.array("output"); c2Require(output.size == items.size)
                    for (i in items.indices) { w.check(); c2Require(items[i].final != null && items[i].final == output[i]) }
                    complete(id, usage)
                }
                else -> {
                    val usage = usage(r["usage"])
                    r["output"]?.let { partial(it as? JsonArray ?: c2Malformed()) }
                    if (status == "incomplete") {
                        val reason = r["incomplete_details"]?.takeUnless { it == JsonNull }?.obj()?.str("reason")
                        stop(AttemptOutcomeV2.INCOMPLETE, if (reason == "max_output_tokens") ModelFailureKind.RESOURCE_EXHAUSTED else ModelFailureKind.UNSUPPORTED_FEATURE, usage)
                    } else stop(AttemptOutcomeV2.FAILED, ModelFailureKind.TRANSPORT, usage)
                }
            }
        }
        private fun add(e: JsonObject) {
            c2Require(e.index("output_index") == items.size); v2Capacity(items.size < 1024)
            val obj = e.getValue("item").obj(); val id = obj.str("id"); val type = obj.str("type")
            c2Require(validId(id, 128) && ids.add(id)); validateItem(obj, false)
            if (type == "function_call") { v2Capacity(++calls <= call.run.budget.callsPerResponse); c2Require(callIds.add(obj.str("call_id"))) }
            w.keep(256)
            w.keepTree(obj)
            val item = Item(obj, id, type); items.add(item)
            if (type == "function_call") obj["arguments"]?.let { seed(item.args, it.string(), false, true) }
            for (key in listOf("content", "summary")) obj[key]?.let { array ->
                (array as? JsonArray ?: c2Malformed()).forEachIndexed { i, p ->
                    val part = p.obj(); val state = part(item, key, i, part.str("type"))
                    seed(state, partText(part), type == "message", type == "message")
                }
            }
        }
        private fun item(e: JsonObject, auxiliary: Boolean): Item {
            val i = e.index("output_index"); c2Require(i < items.size)
            val item = items[i]; c2Require(item.final == null)
            if (auxiliary) c2Require(e.str("item_id") == item.id)
            return item
        }
        private fun part(item: Item, key: String, index: Int, type: String): Part {
            val list = if (key == "summary") item.summary else item.content
            c2Require(index <= list.size)
            if (index == list.size) { v2Capacity(++parts <= 1024); w.keep(160); list.add(Part(type)) }
            return list[index].also { c2Require(it.type == type) }
        }
        private fun auxiliary(type: String, e: JsonObject) {
            val item = item(e, true)
            val group = type.removePrefix("response.").substringBefore('.')
            val action = type.substringAfterLast('.')
            val partEvent = group in setOf("content_part", "reasoning_summary_part")
            val public = group in setOf("content_part", "output_text", "refusal")
            val charged = public || group == "function_call_arguments"
            val expected = when (group) {
                "content_part", "output_text", "refusal" -> "message"
                "function_call_arguments" -> "function_call"
                else -> "reasoning"
            }
            c2Require(item.type == expected)
            val p = if (group == "function_call_arguments") item.args else {
                val key = if (group.startsWith("reasoning_summary")) "summary" else "content"
                val index = e.index(if (key == "summary") "summary_index" else "content_index")
                val pt = if (partEvent) e.getValue("part").obj().str("type") else when (group) {
                    "output_text" -> "output_text"; "refusal" -> "refusal"; "reasoning_summary_text" -> "summary_text"; else -> "reasoning_text"
                }
                part(item, key, index, pt)
            }
            if (partEvent) {
                val obj = e.getValue("part").obj(); validatePart(obj, if (public) "message" else "summary")
                if (action == "added") {
                    c2Require(!p.partAdded && p.partDone == null && !p.deltaSeen && !p.textDone)
                    seed(p, partText(obj), public, charged); p.partAdded = true
                } else {
                    c2Require(p.partAdded && p.partDone == null && (!p.deltaSeen || p.textDone))
                    finalText(p, partText(obj), public, charged); w.keepTree(obj); p.partDone = obj
                    e["status"]?.let { c2Require(it == JsonPrimitive("incomplete")); incompletePart = true }
                }
            } else {
                c2Require(!p.textDone && p.partDone == null)
                if (action == "delta") {
                    val value = e.str("delta")
                    if (charged) decoded(value, false)
                    v2Capacity(p.value.length.toLong() + value.length <= call.run.budget.responseBytes)
                    w.keep((p.value.length.toLong() + value.length) * 2 + 64); w.check()
                    p.value += value; p.initialized = true; p.deltaSeen = true
                    w.scan(p.value)
                    if (public) display(value)
                } else {
                    val key = when (group) { "refusal" -> "refusal"; "function_call_arguments" -> "arguments"; else -> "text" }
                    finalText(p, e.str(key), public, charged); p.textDone = true
                }
            }
        }
        private fun done(e: JsonObject, doc: ChatGptResponseJsonV1) {
            val item = item(e, false); val obj = e.getValue("item").obj()
            c2Require(obj.str("id") == item.id && obj.str("type") == item.type)
            validateItem(obj, true)
            for (key in when (item.type) { "message" -> listOf("role", "phase"); "function_call" -> listOf("call_id", "name", "namespace", "caller", "async"); else -> emptyList() }) {
                item.seed[key]?.let { c2Require(it == obj[key]) }
            }
            if (item.type == "function_call") {
                c2Require(!item.args.deltaSeen || item.args.textDone)
                finalText(item.args, obj.str("arguments"), false, true)
                val args = w.parseText(obj.str("arguments")).obj()
                val schema = call.run.tools.schema(obj.str("name")) ?: c2Unsupported()
                c2Require(schema.accepts(args)); w.check()
                w.keep(128)
                item.proposal = ToolProposalV2("decomp", obj.str("name"), obj.str("call_id"), item.id, obj.str("arguments"),
                    if (obj["caller"].isNull()) null else "direct", false)
            }
            for (key in listOf("content", "summary")) {
                val list = if (key == "summary") item.summary else item.content
                val array = obj[key]?.let { it as? JsonArray ?: c2Malformed() } ?: JsonArray(emptyList())
                c2Require(list.size <= array.size)
                array.forEachIndexed { i, value ->
                    val p = value.obj(); val state = part(item, key, i, p.str("type"))
                    c2Require(!state.deltaSeen || state.textDone)
                    c2Require(!state.partAdded || state.partDone != null)
                    state.partDone?.let { c2Require(it == p) }
                    finalText(state, partText(p), item.type == "message", item.type == "message")
                }
            }
            val raw = doc.rawItem()
            // Private raw bytes are scanned but never redacted/reencoded for replay.
            w.scan(w.decode(raw)); w.check()
            w.keepTree(obj); w.keep(raw.size.toLong() + 64)
            item.raw = raw; item.final = obj
        }
        private fun validateItem(o: JsonObject, final: Boolean) {
            val type = o.str("type")
            when (type) {
                "message" -> {
                    o.shape(setOf("id", "type", "role") + if (final) setOf("status", "content") else emptySet(), setOf("status", "content", "phase"))
                    c2Require(o.str("role") == "assistant")
                    o["phase"]?.let { c2Require(it == JsonNull || it == JsonPrimitive("commentary") || it == JsonPrimitive("final_answer")) }
                }
                "function_call" -> {
                    o.shape(setOf("id", "type", "call_id", "name", "namespace") + if (final) setOf("arguments") else emptySet(), setOf("status", "arguments", "caller", "async"))
                    c2Require(validId(o.str("call_id"), 64) && o.str("namespace") == "decomp")
                    if (call.run.tools.schema(o.str("name")) == null) c2Unsupported()
                    o["arguments"]?.string()
                    o["async"]?.let { c2Require(it == JsonPrimitive(false)) }
                    o["caller"]?.takeUnless { it == JsonNull }?.obj()?.let { it.shape(setOf("type")); c2Require(it.str("type") == "direct") }
                }
                "reasoning" -> {
                    o.shape(setOf("id", "type") + if (final) setOf("summary", "encrypted_content") else emptySet(), setOf("summary", "content", "encrypted_content", "status"))
                    o["encrypted_content"]?.let { if (it != JsonNull || final) c2Require(it.string().isNotEmpty() || !final) }
                }
                else -> c2Unsupported()
            }
            o["status"]?.let { c2Require(it == JsonPrimitive("completed") || (!final && it in setOf(JsonPrimitive("in_progress"), JsonPrimitive("incomplete")))) }
            for (key in listOf("content", "summary")) o[key]?.let { a ->
                c2Require(type != "function_call" && (key != "summary" || type == "reasoning"))
                val list = a as? JsonArray ?: c2Malformed(); v2Capacity(list.size <= 1024)
                for (p in list) validatePart(p.obj(), if (type == "message") "message" else key)
            }
        }
        private fun validatePart(p: JsonObject, kind: String) {
            val type = p.str("type")
            when (kind) {
                "message" -> when (type) {
                    "output_text" -> { p.shape(setOf("type", "text"), setOf("annotations", "logprobs")); for (key in listOf("annotations", "logprobs")) p[key]?.let { c2Require(it is JsonArray && it.isEmpty()) } }
                    "refusal" -> p.shape(setOf("type", "refusal"))
                    else -> c2Unsupported()
                }
                else -> { c2Require(type == if (kind == "summary") "summary_text" else "reasoning_text"); p.shape(setOf("type", "text")) }
            }
            partText(p)
        }
        private fun partial(output: JsonArray) {
            v2Capacity(output.size <= 1024)
            var extraParts = 0
            var extraCalls = 0
            val seenCalls = HashSet<String>()
            val seen = HashSet<String>()
            output.forEachIndexed { index, value ->
                val o = value.obj(); val id = o.str("id"); c2Require(validId(id, 128) && seen.add(id)); validateItem(o, false)
                val existing = items.getOrNull(index)
                if (existing != null) c2Require(existing.id == id && existing.type == o.str("type"))
                for (key in listOf("content", "summary")) o[key]?.let { array ->
                    val oldSize = if (key == "content") existing?.content?.size ?: 0 else existing?.summary?.size ?: 0
                    extraParts += maxOf(0, (array as JsonArray).size - oldSize)
                    v2Capacity(parts + extraParts <= 1024)
                }
                if (o.str("type") == "function_call") {
                    c2Require(seenCalls.add(o.str("call_id")))
                    if (existing == null) { extraCalls++; v2Capacity(calls + extraCalls <= call.run.budget.callsPerResponse) }
                    else for (key in listOf("call_id", "name", "namespace")) c2Require(o[key] == existing.seed[key])
                }
                if (o.str("type") == "message") o["content"]?.let { a ->
                    (a as JsonArray).forEachIndexed { i, part ->
                        val p = part.obj(); val text = partText(p)
                        val old = existing?.content?.getOrNull(i)
                        if (old != null) c2Require(old.type == p.str("type"))
                        chargeRemainder(old?.value ?: "", text)
                    }
                }
                if (o.str("type") == "function_call") o["arguments"]?.let { chargeRemainder(existing?.args?.value ?: "", it.string()) }
            }
        }
        private fun chargeRemainder(prior: String, current: String) {
            c2Require(current.startsWith(prior)); w.retain((current.length - prior.length).toLong() * 2)
            decoded(current.substring(prior.length), false)
        }
        private fun complete(id: String, usage: ReportedModelUsageV1?) {
            val text = StringBuilder(); val proposals = ArrayList<ToolProposalV2>(); val raw = ArrayList<ByteArray>()
            var refusal = false; var continuation = 0L
            for (item in items) {
                w.check(); val bytes = item.raw ?: c2Malformed()
                // Scan again with the current C0 registry snapshot, including any rotated fixture secret.
                w.scanTree(item.final ?: c2Malformed()); w.scan(w.decode(bytes))
                continuation = v2Add(continuation, bytes.size.toLong())
                if (item.type == "message") for (p in item.content) {
                    refusal = refusal || p.type == "refusal"
                    w.retain(p.value.length.toLong() * 4 + 32); text.append(p.value)
                }
                item.proposal?.let { proposals.add(it) }; raw.add(bytes)
            }
            c2Require(!refusal || proposals.isEmpty())
            totals = totals.copy(continuationBytes = continuation); meter()
            v2Capacity(continuation <= call.run.budget.continuationBytes)
            w.retain(continuation + text.length.toLong() * 6 + 256); w.check()
            val value = text.toString()
            // Arrival order can differ from canonical item/part order.
            w.scan(value, call.run.budget.responseBytes)
            val fields = listOf("responses-neutral-v1", value) + proposals.flatMap {
                listOf(it.namespace ?: "", it.name, it.callId, it.outputItemId, it.argumentsJson, it.caller ?: "", it.asynchronous.toString())
            }
            w.retain(fields.sumOf { it.length.toLong() * 4 + 64 }); w.check()
            val digest = v2Digest(fields); w.check()
            val finish = if (refusal) ModelFinishReason.REFUSED else if (proposals.isEmpty()) ModelFinishReason.STOP else ModelFinishReason.TOOL_CALLS
            w.retain(publicTail.length.toLong() * 16 + 128)
            guard.finishValidatedCompletion(); w.check()
            // The final sink may rotate the registry. Rescan all private views after it;
            // capture a revision before scanning so callbacks within the scans and all
            // enclosing parent checks cannot silently invalidate this private candidate.
            synchronized(secrets) {
                val revision = secrets.registryRevision()
                for (item in items) {
                    w.scanTree(item.final ?: c2Malformed())
                    item.proposal?.let { w.parseText(it.argumentsJson) }
                    w.scan(w.decode(item.raw ?: c2Malformed()))
                }
                w.scan(value, call.run.budget.responseBytes)
                w.check()
                val turn = ValidatedResponsesTurnV1(call, id, raw, proposals, digest)
                w.check()
                val response = ModelResponseV2(value, finish, turn, usage)
                candidate = TerminalCandidate(ChatGptAttemptResultV1.Completed(call, totals, usage, response), revision)
            }
            // Finished belongs to C3, after physical close. No sink terminal here.
        }
        private fun stop(outcome: AttemptOutcomeV2, kind: ModelFailureKind, usage: ReportedModelUsageV1?) {
            guard.discardOnFailure(); w.check()
            val diagnostic = ChatGptSafeDiagnosticV1.create(kind, null, ChatGptBodyShapeV1.ERROR, ChatGptSafeCodeV1.UNKNOWN,
                ChatGptSafeParamV1.OTHER, ChatGptRecoveryV1.STOP, null)
            // Even fixed diagnostic literals may collide with registered fixture secrets.
            val revision = secrets.registryRevision()
            w.scan(diagnostic.render()); w.check()
            candidate = TerminalCandidate(ChatGptAttemptResultV1.Stopped(call, totals, usage, outcome, kind, true, diagnostic), revision)
        }
        override fun toString() = "ChatGptResponsesSessionV1(redacted)"
    }

    private fun usage(value: JsonElement?): ReportedModelUsageV1? {
        if (value.isNull()) return null
        val o = value!!.obj()
        val input = o.getValueOrFail("input_tokens").integer()
        val output = o.getValueOrFail("output_tokens").integer()
        val total = o.getValueOrFail("total_tokens").integer()
        c2Require(input <= Long.MAX_VALUE - output && input + output == total)
        fun detail(block: String, name: String, parent: Long): Long? {
            val v = o[block]; if (v.isNull()) return null
            val n = v!!.obj()[name]; if (n.isNull()) return null
            return n!!.integer().also { c2Require(it <= parent) }
        }
        return ReportedModelUsageV1(input, output, total, detail("input_tokens_details", "cached_tokens", input),
            detail("input_tokens_details", "cache_write_tokens", input), detail("output_tokens_details", "reasoning_tokens", output))
    }
    private fun JsonElement?.isNull() = this == null || this == JsonNull
    private fun JsonElement.obj() = this as? JsonObject ?: c2Malformed()
    private fun JsonElement.string() = (this as? JsonPrimitive)?.takeIf { it.isString }?.content ?: c2Malformed()
    private fun JsonElement.nullableString() { if (this != JsonNull) string() }
    private fun JsonObject.str(key: String) = getValueOrFail(key).string()
    private fun JsonObject.getValueOrFail(key: String) = get(key) ?: c2Malformed()
    private fun JsonObject.array(key: String) = get(key) as? JsonArray ?: c2Malformed()
    private fun JsonObject.index(key: String): Int = getValueOrFail(key).integer().also { c2Require(it <= Int.MAX_VALUE) }.toInt()
    private fun JsonElement.integer(): Long {
        val p = this as? JsonPrimitive ?: c2Malformed(); c2Require(!p.isString)
        val s = p.content; c2Require(s.isNotEmpty() && (s == "0" || s[0] in '1'..'9') && s.all { it in '0'..'9' })
        return s.toLongOrNull() ?: c2Malformed()
    }
    private fun JsonObject.shape(required: Set<String>, optional: Set<String> = emptySet()) {
        c2Require(keys.containsAll(required)); if (keys.any { it !in required && it !in optional }) c2Unsupported()
    }
    private fun validId(s: String, max: Int) = s.length in 1..max && s.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '_' || it == '-' }
    private fun partText(p: JsonObject) = p.str(if (p.str("type") == "refusal") "refusal" else "text")
    private val EVENT_FIELDS = buildMap<String, Set<String>> {
        for (s in listOf("created", "in_progress", "completed", "failed", "incomplete")) put("response.$s", setOf("response"))
        for (s in listOf("added", "done")) put("response.output_item.$s", setOf("output_index", "item"))
        for (g in listOf("content_part", "reasoning_summary_part")) for (s in listOf("added", "done"))
            put("response.$g.$s", setOf("output_index", "item_id", if (g == "content_part") "content_index" else "summary_index", "part"))
        for (g in listOf("output_text", "refusal", "function_call_arguments", "reasoning_summary_text", "reasoning_text")) for (s in listOf("delta", "done")) {
            val fields = mutableSetOf("output_index", "item_id", if (s == "delta") "delta" else when (g) { "refusal" -> "refusal"; "function_call_arguments" -> "arguments"; else -> "text" })
            if (g != "function_call_arguments") fields.add(if (g == "reasoning_summary_text") "summary_index" else "content_index")
            put("response.$g.$s", fields)
        }
        put("error", setOf("code", "message", "param"))
    }
}
