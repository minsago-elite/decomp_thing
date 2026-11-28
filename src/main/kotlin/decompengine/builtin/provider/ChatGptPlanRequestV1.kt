package decompengine.builtin.provider

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadConstraints
import com.fasterxml.jackson.core.StreamReadFeature
import decompengine.builtin.*
import kotlinx.serialization.json.*
import java.io.ByteArrayInputStream
import java.io.FilterReader
import java.io.InputStreamReader
import java.nio.charset.CodingErrorAction
import java.util.IdentityHashMap

/** Complete HTTP entity. Construction always validates; neither bytes nor diagnostics carry authority. */
internal class PreparedChatGptRequestV1 private constructor(private val body: ByteArray) {
    val bytes: Long get() = body.size.toLong()
    fun encoded(): ByteArray = body.copyOf()
    override fun toString() = "PreparedChatGptRequestV1(redacted)"

    companion object {
        internal fun prepare(codec: ChatGptPlanRequestV1, run: AdmittedModelRunV2,
            messages: List<ModelMessageV2>, results: Map<ValidatedResponsesTurnV1, List<ToolResultV2>>) =
            PreparedChatGptRequestV1(codec.encodeBytes(run, messages, results))

        /** Pure shape/commitment validation, NOT a successful-call or prior-settlement proof. */
        internal fun fromAdmittedCall(call: AdmittedModelCallV2, secrets: ChatGptPlanSecretsV1) =
            PreparedChatGptRequestV1(ChatGptPlanRequestV1(secrets).validatedAdmittedBytes(call))
    }
}

/** Offline codec only. No ledger, credential source, sink, registration, or transport. */
internal class ChatGptPlanRequestV1(private val secrets: ChatGptPlanSecretsV1) {
    fun encode(run: AdmittedModelRunV2, messages: List<ModelMessageV2>,
        resultsByTurn: Map<ValidatedResponsesTurnV1, List<ToolResultV2>>): PreparedChatGptRequestV1 =
        PreparedChatGptRequestV1.prepare(this, run, messages, resultsByTurn)

    fun encodedSpace(run: AdmittedModelRunV2, priorMessages: List<ModelMessageV2>,
        priorResults: Map<ValidatedResponsesTurnV1, List<ToolResultV2>>): EncodedSpaceV2 {
        val w = Work(run)
        val (messages, results) = snapshot(w, priorMessages, priorResults)
        // Validate before retaining a snapshot in the adapter. No complete body allocation is needed.
        measure(w, plan(w, messages, results))
        w.check()
        return EncodedSpaceV2 { response, proposals ->
            val next = Work(run)
            sameProposals(response.continuation.proposals, proposals)
            next.check()
            val appended = messages + ModelMessageV2(ModelRole.ASSISTANT, response.text, response.continuation)
            val withResults = IdentityHashMap(results)
            requireInput(!withResults.containsKey(response.continuation))
            withResults[response.continuation] = proposals.map { ToolResultV2(it.callId, "") }
            val (ownedMessages, ownedResults) = snapshot(next, appended, withResults)
            val fullPlan = plan(next, ownedMessages, ownedResults)
            val projection = fullPlan.lastProjection ?: malformed()
            requireInput(response.finishReason == projection.finish)
            val full = measure(next, fullPlan)
            // SAME writer, removing only this turn's result elements; commas are measured too.
            val base = measure(next, fullPlan.copy(inputs = fullPlan.inputs.filterNot {
                it is Result && it.turn === response.continuation
            }))
            // Result strings already belong to the host. Future encode retains the same raw
            // items/trees and one final byte array; reserve its maximum admitted size here.
            // This is codec allocation headroom, not extra wire framing or A's 6x charge.
            next.retain(minOf(run.budget.requestBytes, v2Subtract(run.budget.contextBytes, run.budget.historyReserveBytes)))
            next.check()
            EncodedLayoutV2(base, v2Subtract(full, base)) // A alone adds 6 * raw result ceilings.
        }
    }

    internal fun encodeBytes(run: AdmittedModelRunV2, messages: List<ModelMessageV2>,
        results: Map<ValidatedResponsesTurnV1, List<ToolResultV2>>): ByteArray {
        val w = Work(run)
        val (ownedMessages, ownedResults) = snapshot(w, messages, results)
        val p = plan(w, ownedMessages, ownedResults)
        val length = measure(w, p)
        w.retain(length)
        w.check()
        val bytes = ByteArray(length.toInt())
        val writer = Writer(w, bytes)
        emit(writer, p)
        requireInput(writer.size == length)
        w.check()
        return bytes
    }

    private sealed interface Input
    private class Plain(val role: String, val content: String) : Input
    private class Raw(val bytes: ByteArray) : Input
    private class Result(val turn: ValidatedResponsesTurnV1, val value: ToolResultV2) : Input
    private data class Plan(val model: String, val tools: List<ToolDefinitionV2>, val inputs: List<Input>,
        val lastProjection: Projection?) { override fun toString() = "ChatGptRequestPlanV1(redacted)" }
    private class Projection(val text: String, val proposals: List<ToolProposalV2>, val refused: Boolean) {
        val finish get() = if (refused) ModelFinishReason.REFUSED else if (proposals.isEmpty()) ModelFinishReason.STOP else ModelFinishReason.TOOL_CALLS
        fun digest() = v2Digest(listOf("responses-neutral-v1", text) + proposals.flatMap(::fields))
    }
    private class Ids {
        val responses = HashSet<String>()
        val items = HashSet<String>()
        val calls = HashSet<String>()
    }

    private fun snapshot(w: Work, messages: List<ModelMessageV2>, results: Map<ValidatedResponsesTurnV1, List<ToolResultV2>>):
        Pair<List<ModelMessageV2>, IdentityHashMap<ValidatedResponsesTurnV1, List<ToolResultV2>>> {
        w.check()
        v2Capacity(messages.size <= MAX_NODES && results.size <= w.run.budget.maxRequests)
        val ms = ArrayList<ModelMessageV2>()
        for (m in messages) { w.check(); w.retain(32); ms.add(m) }
        val rs = IdentityHashMap<ValidatedResponsesTurnV1, List<ToolResultV2>>()
        for ((turn, values) in results) {
            w.check()
            requireInput(!rs.containsKey(turn))
            v2Capacity(values.size <= w.run.budget.callsPerResponse)
            val owned = ArrayList<ToolResultV2>()
            for (value in values) { w.check(); w.retain(32); owned.add(value) }
            rs[turn] = owned
        }
        w.check() // Includes collection callbacks, even the last iterator operation.
        return ms to rs
    }

    private fun plan(w: Work, messages: List<ModelMessageV2>, results: Map<ValidatedResponsesTurnV1, List<ToolResultV2>>): Plan {
        requireInput(w.run.checked.capabilities.commitment() == ProviderCapabilitiesV2.siwc().commitment())
        w.generated("model", "input", "store", "false", "stream", "true", "include", "reasoning.encrypted_content")
        w.scalar(w.run.binding.modelSlug)
        if (w.run.tools.definitions.isNotEmpty()) w.generated("tools", "type", "namespace", "name", "decomp", "description", "Invocation-owned tools", "tools")
        for (tool in w.run.tools.definitions) {
            w.generated("type", "function", "name", "description", "parameters", "strict", "false")
            w.scalar(tool.name); w.scalar(tool.description)
            val schema = w.parseText(tool.parametersJson, 256L * 1024).obj()
            w.retain(v2Multiply(12, tool.parametersJson.length.toLong()))
            requireInput(w.run.tools.schema(tool.name)?.commitment == v2Digest(listOf(canonicalToolJsonV2(schema))))
            w.check()
        }
        val inputs = ArrayList<Input>()
        val used = IdentityHashMap<ValidatedResponsesTurnV1, Boolean>()
        val ids = Ids()
        var ordinal = 0
        var rawBytes = 0L
        var last: Projection? = null
        for (m in messages) {
            w.check()
            if (m.role == ModelRole.TOOL) unsupported()
            w.scalar(m.content)
            val turn = m.continuation
            if (turn == null) {
                w.generated("role", "content", when (m.role) { ModelRole.SYSTEM -> "developer"; ModelRole.USER -> "user"; else -> "assistant" })
                w.retain(32)
                inputs.add(Plain(when (m.role) { ModelRole.SYSTEM -> "developer"; ModelRole.USER -> "user"; ModelRole.ASSISTANT -> "assistant" }, m.content))
            } else {
                requireInput(m.role == ModelRole.ASSISTANT && turn.call.run === w.run &&
                    turn.bindingSha256 == w.run.bindingCommitment && turn.toolsSha256 == w.run.tools.commitment)
                requireInput(used.put(turn, true) == null && turn.call.ordinal > ordinal && turn.call.ordinal <= w.run.budget.maxRequests)
                requireInput(turn.call.attempt in 1..w.run.budget.maxRetries + 1)
                ordinal = turn.call.ordinal
                requireInput(validId(turn.responseId, 128) && ids.responses.add(turn.responseId))
                rawBytes = v2Add(rawBytes, turn.rawBytes)
                w.capacity(rawBytes)
                w.retain(turn.rawBytes)
                val items = turn.orderedItems()
                w.check()
                val digestParts = ArrayList<String>()
                val parsed = ArrayList<JsonObject>()
                for (raw in items) {
                    w.check()
                    v2Capacity(raw.size.toLong() <= w.run.budget.eventBytes)
                    w.retain(256) // Digest text and per-item list references.
                    digestParts.add(v2BytesDigest(raw))
                    parsed.add(w.parse(raw, w.run.budget.eventBytes).obj())
                }
                requireInput(v2Digest(digestParts) == turn.sha256)
                last = project(w, parsed, ids)
                w.check()
                requireInput(last.text == m.content && last.digest() == turn.neutralTextCallsSha256)
                sameProposals(last.proposals, turn.proposals)
                w.check()
                for (raw in items) { w.retain(32); inputs.add(Raw(raw)) }
                val values = results[turn]
                requireInput(values != null || turn.proposals.isEmpty())
                requireInput((values?.size ?: 0) == turn.proposals.size)
                values.orEmpty().forEachIndexed { i, value ->
                    w.check()
                    requireInput(value.callId == turn.proposals[i].callId)
                    w.generated("type", "function_call_output", "call_id", "output")
                    w.scalar(value.callId)
                    w.scalar(value.text, w.run.budget.toolResultBytes)
                    w.retain(32)
                    inputs.add(Result(turn, value))
                }
            }
        }
        requireInput(results.keys.all { used.containsKey(it) })
        w.check()
        return Plan(w.run.binding.modelSlug, w.run.tools.definitions, inputs, last)
    }

    private fun project(w: Work, items: List<JsonObject>, ids: Ids): Projection {
        v2Capacity(items.size in 1..1024)
        val text = StringBuilder()
        val calls = ArrayList<ToolProposalV2>()
        var parts = 0
        var refused = false
        for (item in items) {
            w.check()
            val id = item.string("id")
            requireWire(validId(id, 128) && ids.items.add(id))
            when (item.string("type")) {
                "message" -> {
                    item.shape(setOf("id", "type", "role", "status", "content"), setOf("phase"))
                    requireWire(item.string("role") == "assistant" && item.string("status") == "completed")
                    item["phase"]?.let { requireWire(it == JsonNull || it == JsonPrimitive("commentary") || it == JsonPrimitive("final_answer")) }
                    for (part in item.array("content")) {
                        w.check(); v2Capacity(++parts <= 1024)
                        val p = part.obj()
                        val s = when (p.string("type")) {
                            "output_text" -> {
                                p.shape(setOf("type", "text"), setOf("annotations", "logprobs"))
                                for (key in listOf("annotations", "logprobs")) p[key]?.let { requireWire(it is JsonArray && it.isEmpty()) }
                                p.string("text")
                            }
                            "refusal" -> { p.shape(setOf("type", "refusal")); refused = true; p.string("refusal") }
                            else -> unsupported()
                        }
                        w.retain(v2Multiply(4, s.length.toLong())) // Includes bounded builder growth.
                        v2Capacity(text.length.toLong() + s.length <= w.run.budget.responseBytes)
                        text.append(s)
                    }
                }
                "reasoning" -> {
                    item.shape(setOf("id", "type", "summary", "encrypted_content"), setOf("content", "status"))
                    requireWire(item.string("encrypted_content").isNotEmpty())
                    item["status"]?.let { requireWire(it == JsonPrimitive("completed")) }
                    for ((key, type) in listOf("summary" to "summary_text", "content" to "reasoning_text")) {
                        if (key == "content" && key !in item) continue
                        for (part in item.array(key)) {
                            w.check(); v2Capacity(++parts <= 1024)
                            part.obj().also { it.shape(setOf("type", "text")); requireWire(it.string("type") == type); it.string("text") }
                        }
                    }
                }
                "function_call" -> {
                    item.shape(setOf("id", "type", "call_id", "name", "namespace", "arguments"), setOf("status", "caller", "async"))
                    item["status"]?.let { requireWire(it == JsonPrimitive("completed")) }
                    item["async"]?.let { requireWire(it == JsonPrimitive(false)) }
                    val caller = item["caller"]?.takeUnless { it == JsonNull }?.let {
                        it.obj().shape(setOf("type")); requireWire(it.obj().string("type") == "direct"); "direct"
                    }
                    val callId = item.string("call_id")
                    requireWire(validId(callId, 64) && ids.calls.add(callId))
                    requireWire(item.string("namespace") == "decomp")
                    val name = item.string("name")
                    val schema = w.run.tools.schema(name) ?: unsupported()
                    val arguments = item.string("arguments")
                    val obj = w.parseText(arguments, w.run.budget.eventBytes).obj()
                    requireWire(schema.accepts(obj)); w.check()
                    v2Capacity(calls.size < w.run.budget.callsPerResponse)
                    w.retain(64)
                    calls.add(ToolProposalV2("decomp", name, callId, id, arguments, caller, false))
                }
                else -> unsupported()
            }
        }
        requireWire(!refused || calls.isEmpty())
        w.retain(v2Multiply(2, text.length.toLong()))
        w.check()
        return Projection(text.toString(), calls, refused)
    }

    private fun measure(w: Work, p: Plan): Long = Writer(w).also { emit(it, p); w.capacity(it.size); w.check() }.size

    private fun emit(out: Writer, p: Plan) {
        out.ascii("{\"model\":"); out.string(p.model); out.ascii(",\"input\":[")
        p.inputs.forEachIndexed { i, input ->
            out.w.check()
            if (i > 0) out.ascii(",")
            when (input) {
                is Plain -> { out.ascii("{\"role\":"); out.string(input.role); out.ascii(",\"content\":"); out.string(input.content); out.ascii("}") }
                is Raw -> out.raw(input.bytes)
                is Result -> { out.ascii("{\"type\":\"function_call_output\",\"call_id\":"); out.string(input.value.callId); out.ascii(",\"output\":"); out.string(input.value.text); out.ascii("}") }
            }
        }
        out.ascii("],\"store\":false,\"stream\":true,\"include\":[\"reasoning.encrypted_content\"]")
        if (p.tools.isNotEmpty()) {
            out.ascii(",\"tools\":[{\"type\":\"namespace\",\"name\":\"decomp\",\"description\":\"Invocation-owned tools\",\"tools\":[")
            p.tools.forEachIndexed { i, tool ->
                out.w.check()
                if (i > 0) out.ascii(",")
                out.ascii("{\"type\":\"function\",\"name\":"); out.string(tool.name)
                out.ascii(",\"description\":"); out.string(tool.description)
                out.ascii(",\"parameters\":"); out.utf8(tool.parametersJson)
                out.ascii(",\"strict\":false}")
            }
            out.ascii("]}]")
        }
        out.ascii("}")
    }

    /** Validate an admitted entity without canonicalizing, replacing, or re-encoding its bytes.
     * The call is the host's carrier. JSON cannot prove private turn provenance/settlement.
     */
    internal fun validatedAdmittedBytes(call: AdmittedModelCallV2): ByteArray {
        val w = Work(call.run)
        w.check()
        w.capacity(call.encodedInputBytes)
        requireInput(call.ordinal in 1..call.run.budget.maxRequests && call.attempt in 1..call.run.budget.maxRetries + 1)
        requireInput(call.run.checked.capabilities.commitment() == ProviderCapabilitiesV2.siwc().commitment())
        w.retain(call.encodedInputBytes)
        val bytes = call.encodedInput()
        val body = w.parse(bytes, call.run.budget.requestBytes).obj()
        body.shape(setOf("model", "input", "store", "stream", "include"), setOf("tools"))
        requireInput(body.string("model") == call.run.binding.modelSlug && body["store"] == JsonPrimitive(false) && body["stream"] == JsonPrimitive(true))
        requireInput(body["include"] == JsonArray(listOf(JsonPrimitive("reasoning.encrypted_content"))))
        val definitions = call.run.tools.definitions
        if (definitions.isEmpty()) requireInput("tools" !in body) else {
            val spaces = body.array("tools"); requireInput(spaces.size == 1)
            val space = spaces[0].obj(); space.shape(setOf("type", "name", "description", "tools"))
            requireInput(space.string("type") == "namespace" && space.string("name") == "decomp" && space.string("description") == "Invocation-owned tools")
            val tools = space.array("tools"); requireInput(tools.size == definitions.size)
            tools.forEachIndexed { i, element ->
                w.check()
                val tool = element.obj(); tool.shape(setOf("type", "name", "description", "parameters", "strict"))
                val expected = definitions[i]
                requireInput(tool.string("type") == "function" && tool.string("name") == expected.name && tool.string("description") == expected.description && tool["strict"] == JsonPrimitive(false))
                requireInput(tool["parameters"] == w.parseText(expected.parametersJson, 256L * 1024))
            }
        }
        val ids = Ids()
        val pending = ArrayList<JsonObject>()
        var calls: List<ToolProposalV2> = emptyList()
        var resultIndex = 0
        fun flush() {
            if (pending.isNotEmpty()) { calls = project(w, pending, ids).proposals; pending.clear(); resultIndex = 0 }
        }
        for (value in body.array("input")) {
            w.check()
            val item = value.obj()
            if ("type" !in item || item["type"] == JsonPrimitive("message") && "id" !in item) {
                flush(); requireInput(resultIndex == calls.size)
                item.shape(setOf("role", "content"), setOf("type"))
                item["type"]?.let { requireWire(it == JsonPrimitive("message")) }
                requireInput(item.string("role") in setOf("developer", "user", "assistant")); item.string("content")
            } else if (item.string("type") == "function_call_output") {
                flush()
                item.shape(setOf("type", "call_id", "output"))
                requireInput(resultIndex < calls.size && item.string("call_id") == calls[resultIndex++].callId)
                w.utf8Length(item.string("output"), call.run.budget.toolResultBytes)
            } else {
                requireInput(resultIndex == calls.size)
                v2Capacity(pending.size < 1024)
                pending.add(item)
            }
        }
        flush(); requireInput(resultIndex == calls.size)
        w.check()
        return bytes
    }

    /** Conservative codec-owned allocation charges, not a bound on total JVM heap.
     * Caller-owned strings/turns preexist; retained references, raw copies, parser trees, bridge
     * scalars, projections and final body are charged. Jackson has separate bounded token buffers.
     * Charges are cumulative (no credit for freed trees), deliberately stricter than live retention.
     */
    private inner class Work(val run: AdmittedModelRunV2) {
        private var retained = 0L
        private var nodes = 0
        private var chars = 0L
        fun check() { run.deadline.remainingNanos() }
        fun retain(bytes: Long) { retained = v2Add(retained, bytes); v2Capacity(retained <= v2Multiply(4, run.budget.responseBytes)) }
        fun capacity(bytes: Long) { v2Capacity(bytes <= run.budget.requestBytes && v2Add(bytes, run.budget.historyReserveBytes) <= run.budget.contextBytes) }
        fun utf8Length(s: String, max: Long): Long {
            val counter = Writer(this, maximum = max)
            counter.utf8(s)
            return counter.size
        }
        fun generated(vararg scalars: String) {
            val tokens = 4 + 2 * scalars.size // Conservative framing plus supplied and associated scalars.
            v2Capacity(tokens <= MAX_NODES - nodes)
            nodes += tokens
            for (s in scalars) scalar(s)
        }
        fun scalar(s: String, maximum: Long = MAX_SCALAR.toLong()) {
            check(); v2Capacity(s.length <= MAX_SCALAR)
            utf8Length(s, minOf(maximum, MAX_SCALAR.toLong()))
            chars = v2Add(chars, s.length.toLong()); v2Capacity(chars <= ChatGptPlanSecretsV1.MAX_JSON_TOTAL_CHARS)
            // Overlap exceeds every possible C0 secret (16 KiB); split on scalar boundaries.
            // This keeps original cancellation/deadline checks during large private scans.
            var start = 0
            do {
                var end = minOf(s.length, start + 32768)
                if (end < s.length && s[end].isLowSurrogate()) end--
                secrets.rejectCredentialsInPrivateJson(JsonPrimitive(if (start == 0 && end == s.length) s else s.substring(start, end)))
                check()
                if (end == s.length) break
                start += 8192
                if (s[start].isLowSurrogate()) start--
            } while (true)
        }
        fun parseText(s: String, max: Long): JsonElement {
            val length = utf8Length(s, max)
            retain(length); check()
            return parse(s.toByteArray(Charsets.UTF_8), max)
        }
        fun parse(bytes: ByteArray, maximum: Long): JsonElement {
            check(); v2Capacity(bytes.size.toLong() <= maximum)
            val factory = JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(32).maxDocumentLength(maximum)
                    .maxStringLength(minOf(maximum, MAX_SCALAR.toLong()).toInt()).maxNameLength(8192)
                    .maxNumberLength(32).maxTokenCount(MAX_NODES.toLong()).build()).build()
            val decoder = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            val reader = object : FilterReader(InputStreamReader(ByteArrayInputStream(bytes), decoder)) {
                override fun read(cbuf: CharArray, off: Int, len: Int): Int { check(); return super.read(cbuf, off, minOf(len, 1024)).also { check() } }
            }
            try {
                factory.createParser(reader).use { parser ->
                    parser.nextToken() ?: malformed()
                    val value = readValue(parser, 0)
                    requireWire(parser.nextToken() == null)
                    check()
                    return value
                }
            } catch (failure: ModelProviderException) {
                if (failure.kind == ModelFailureKind.INVALID_REQUEST) malformed()
                throw failure
            } catch (_: com.fasterxml.jackson.core.exc.StreamConstraintsException) {
                v2Fail(ModelFailureKind.RESOURCE_EXHAUSTED)
            } catch (_: Exception) { malformed() }
        }
        private fun readValue(p: JsonParser, depth: Int): JsonElement {
            check(); v2Capacity(++nodes <= MAX_NODES); requireWire(depth <= 32); retain(64)
            return when (p.currentToken()) {
                JsonToken.START_OBJECT -> {
                    val fields = LinkedHashMap<String, JsonElement>()
                    while (p.nextToken() != JsonToken.END_OBJECT) {
                        requireWire(p.currentToken() == JsonToken.FIELD_NAME)
                        v2Capacity(++nodes <= MAX_NODES)
                        val key = p.currentName() ?: malformed()
                        scalar(key, 8192); retain(v2Add(64, v2Multiply(2, key.length.toLong())))
                        requireWire(key !in fields)
                        p.nextToken() ?: malformed()
                        fields[key] = readValue(p, depth + 1)
                    }
                    JsonObject(fields)
                }
                JsonToken.START_ARRAY -> {
                    val values = ArrayList<JsonElement>()
                    while (p.nextToken() != JsonToken.END_ARRAY) { requireWire(p.currentToken() != null); values.add(readValue(p, depth + 1)) }
                    JsonArray(values)
                }
                JsonToken.VALUE_STRING -> { retain(v2Multiply(2, p.textLength.toLong())); p.text.let { scalar(it); JsonPrimitive(it) } }
                JsonToken.VALUE_NUMBER_INT, JsonToken.VALUE_NUMBER_FLOAT -> p.text.let {
                    requireWire(it.length <= 32 && NUMBER.matches(it)); scalar(it); Json.parseToJsonElement(it)
                }
                JsonToken.VALUE_TRUE -> { scalar("true"); JsonPrimitive(true) }
                JsonToken.VALUE_FALSE -> { scalar("false"); JsonPrimitive(false) }
                JsonToken.VALUE_NULL -> { scalar("null"); JsonNull }
                else -> malformed()
            }
        }
    }

    /** Identical counting/writing path, with no whole-string UTF-8 or escaped-string intermediates. */
    private class Writer(val w: Work, private val bytes: ByteArray? = null, private val maximum: Long = w.run.budget.requestBytes) {
        var size = 0L; private set
        private fun byte(value: Int) {
            size = v2Add(size, 1); v2Capacity(size <= maximum)
            bytes?.set((size - 1).toInt(), value.toByte())
        }
        fun ascii(s: String) { for (c in s) byte(c.code) }
        fun raw(raw: ByteArray) { for (i in raw.indices) { if (i % 1024 == 0) w.check(); byte(raw[i].toInt()) } }
        fun string(s: String) { byte(34); write(s, true); byte(34) }
        fun utf8(s: String) = write(s, false)
        private fun write(s: String, quoted: Boolean) {
            var i = 0
            var nextCheck = 0
            while (i < s.length) {
                if (i >= nextCheck) { w.check(); nextCheck = i + 1024 }
                val c = s[i++]; var cp = c.code
                if (quoted && (cp < 32 || c == '"' || c == '\\')) {
                    if (c == '"' || c == '\\') { byte(92); byte(cp) }
                    else { ascii("\\u00"); byte(HEX[cp shr 4].code); byte(HEX[cp and 15].code) }
                    continue
                }
                if (c.isHighSurrogate()) { requireInput(i < s.length && s[i].isLowSurrogate()); cp = Character.toCodePoint(c, s[i++]) }
                else requireInput(!c.isLowSurrogate())
                when {
                    cp < 0x80 -> byte(cp)
                    cp < 0x800 -> { byte(0xc0 or (cp shr 6)); byte(0x80 or (cp and 63)) }
                    cp < 0x10000 -> { byte(0xe0 or (cp shr 12)); byte(0x80 or ((cp shr 6) and 63)); byte(0x80 or (cp and 63)) }
                    else -> { byte(0xf0 or (cp shr 18)); byte(0x80 or ((cp shr 12) and 63)); byte(0x80 or ((cp shr 6) and 63)); byte(0x80 or (cp and 63)) }
                }
            }
            w.check()
        }
    }

    override fun toString() = "ChatGptPlanRequestV1(redacted)"
    private companion object {
        const val MAX_NODES = 100_000
        const val MAX_SCALAR = 1 shl 20
        const val HEX = "0123456789abcdef"
        val NUMBER = Regex("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
        fun validId(s: String, max: Int) = s.length in 1..max && s.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '_' || it == '-' }
        fun fields(p: ToolProposalV2) = listOf(p.namespace ?: "", p.name, p.callId, p.outputItemId, p.argumentsJson, p.caller ?: "", p.asynchronous.toString())
        fun sameProposals(a: List<ToolProposalV2>, b: List<ToolProposalV2>) { requireInput(a.size == b.size && a.indices.all { fields(a[it]) == fields(b[it]) }) }
        fun requireInput(ok: Boolean) { if (!ok) v2Fail() }
        fun requireWire(ok: Boolean) { if (!ok) malformed() }
        fun malformed(): Nothing = v2Fail(ModelFailureKind.MALFORMED_RESPONSE)
        fun unsupported(): Nothing = v2Fail(ModelFailureKind.UNSUPPORTED_FEATURE)
        fun JsonElement.obj() = this as? JsonObject ?: malformed()
        fun JsonObject.string(key: String) = (get(key) as? JsonPrimitive)?.takeIf { it.isString }?.content ?: malformed()
        fun JsonObject.array(key: String) = get(key) as? JsonArray ?: malformed()
        fun JsonObject.shape(required: Set<String>, optional: Set<String> = emptySet()) {
            requireWire(keys.containsAll(required))
            if (keys.any { it !in required && it !in optional }) unsupported()
        }
    }
}
