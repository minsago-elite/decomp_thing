package decompengine.acp

import decompengine.builtin.provider.parseProviderObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** The exception deliberately contains neither provider data nor credential material. */
internal class AcpProviderStreamFailure(val kind: AcpProviderTerminalKind) :
    IOException("provider response rejected: ${kind.name}")

internal data class AcpProviderStreamReceipt(
    val responseBytes: Long,
    val eventCount: Int,
    val inputTokens: Int?,
    val outputTokens: Int,
)

/**
 * Bounded quarantine for one unqualified Responses adapter exchange. Network chunks are charged
 * before parsing. Only complete, strictly validated SSE events leave the quarantine. Credential
 * matches are checked in original/normalized wire bytes, decoded JSON names/strings, and all
 * accepted text/tool argument deltas using bounded logical and aggregate continuation matchers. A trailing
 * credential prefix holds whole events until it is disproved or the stream
 * completes; that hold uses the same finite queue byte bound as the transport.
 *
 * This class starts no tasks, performs no I/O, and makes no provider/backend compatibility claim.
 */
internal class AcpProviderResponseStream(
    private val bounds: AcpProviderTransportBounds,
    secrets: List<ByteArray>,
    private val maximumRemainingOutputTokens: Int,
    private val maximumRemainingInputTokens: Long? = null,
) {
    private val secretPatterns: List<ProviderSecretPattern>
    private val rawMatcher: ProviderSecretMatcher
    private val emittedMatcher: ProviderSecretMatcher
    private val forbiddenPatterns = FORBIDDEN_RENDERED_MARKERS.map { ProviderSecretPattern(it.toByteArray(Charsets.UTF_8)) }
    private val deltaMatcher: ProviderSemanticMatcher
    private val logicalDeltaMatchers = LinkedHashMap<String, ProviderSemanticMatcher>()
    private val event = ErasableProviderEventBuffer(minOf(bounds.maximumChunkBytes, 8192))
    private val pending = ArrayDeque<ByteArray>()
    private var pendingBytes = 0L
    private var observedBytes = 0L
    private var events = 0
    private var jsonTokens = 0L
    private var decodedBytes = 0L
    private var semanticBytes = 0L
    private var semanticWork = 0L
    private var identityWorkBytes = 0L
    private var storedIdentityBytes = 0L
    private var lineBytes = 0
    private var priorByte = -1
    private var completed = false
    private var finished = false
    private var drained = false
    private var failure: AcpProviderTerminalKind? = null
    private var inputTokens: Int? = null
    private var outputTokens: Int? = null

    init {
        require(maximumRemainingOutputTokens in 0..bounds.maximumOutputTokens) {
            "provider remaining token budget is outside the invocation bound"
        }
        require(maximumRemainingInputTokens == null || maximumRemainingInputTokens >= 0) {
            "provider remaining input token budget is negative"
        }
        require(secrets.size <= 16 && secrets.all { it.size in 1..8192 } &&
            secrets.sumOf { it.size.toLong() } <= 64 * 1024) { "provider secret scan material exceeds the static bound" }
        secretPatterns = secrets.map { ProviderSecretPattern(it.copyOf()) }
        rawMatcher = ProviderSecretMatcher(secretPatterns)
        emittedMatcher = ProviderSecretMatcher(secretPatterns)
        deltaMatcher = ProviderSemanticMatcher(secretPatterns, forbiddenPatterns)
    }

    @Synchronized
    fun accept(bytes: ByteArray): List<ByteArray> {
        requireActive()
        if (bytes.size > bounds.maximumChunkBytes ||
            bytes.size.toLong() > bounds.maximumResponseBytes.toLong() - observedBytes) {
            reject(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
        }
        observedBytes += bytes.size
        val released = ArrayList<ByteArray>()
        try {
        for (byte in bytes) {
            if (completed) reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
            if (rawMatcher.accept(byte)) reject(AcpProviderTerminalKind.SECRET_EXPOSURE)
            if (event.size() == bounds.maximumChunkBytes) reject(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
            event.write(byte.toInt())
            val unsigned = byte.toInt() and 0xff
            if (unsigned == '\n'.code) {
                val effectiveLineBytes = lineBytes - if (priorByte == '\r'.code) 1 else 0
                lineBytes = 0
                if (effectiveLineBytes == 0) completeEvent(released)
            } else {
                lineBytes++
            }
            priorByte = unsigned
        }
        return released
        } catch (failure: Exception) {
            released.forEach { it.fill(0) }
            abort((failure as? AcpProviderStreamFailure)?.kind ?: AcpProviderTerminalKind.MALFORMED_RESPONSE)
            throw failure
        }
    }

    @Synchronized
    fun finish(): AcpProviderStreamReceipt {
        requireActive()
        if (!completed || event.size() != 0) reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        finished = true
        val receipt = AcpProviderStreamReceipt(observedBytes, events, inputTokens, outputTokens!!)
        eraseSecrets()
        return receipt
    }

    /** Called only after the upstream owner has supplied actual EOF and finish has succeeded. */
    @Synchronized
    fun drainFinished(): List<ByteArray> {
        if (!finished || drained || failure != null) reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        drained = true
        val result = pending.map(ByteArray::copyOf)
        pending.forEach { it.fill(0) }
        pending.clear()
        pendingBytes = 0L
        return result
    }

    private fun completeEvent(released: MutableList<ByteArray>) {
        if (++events > MAXIMUM_EVENTS) reject(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
        val raw = event.toByteArray()
        event.erase()
        val text = try {
            raw.decodeToString(throwOnInvalidSequence = true)
        } catch (_: Exception) {
            reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        }
        val normalized = text.replace("\r\n", "\n")
        if ('\r' in normalized || !normalized.endsWith("\n\n")) reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        val lines = normalized.dropLast(2).split('\n')
        var declaredType: String? = null
        val data = StringBuilder()
        var dataLines = 0
        for (line in lines) {
            when {
                line.startsWith("event:") -> {
                    if (declaredType != null) reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
                    declaredType = line.substring(6).removePrefix(" ")
                    if (!declaredType.matches(EVENT_TYPE)) reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
                }
                line.startsWith("data:") -> {
                    if (dataLines++ > 0) data.append('\n')
                    data.append(line.substring(5).removePrefix(" "))
                }
                else -> reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
            }
        }
        if (dataLines == 0) reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        val value = try {
            parseProviderObject(data.toString(), bounds.maximumChunkBytes)
        } catch (_: Exception) {
            reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        }
        chargeJsonTokens(value)
        val type = stringValue(value["type"]) ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        if (!type.matches(EVENT_TYPE) || (declaredType != null && declaredType != type)) {
            reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        }
        if (type == "error" || type in ERROR_EVENTS) reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        if (type !in SUPPORTED_EVENTS) reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        validateWireFields(value)
        val matchers = if (type in DELTA_EVENTS) {
            val direct = matchersForDelta(type, value)
            if (type == "response.output_text.delta") direct + matchersForDelta(RENDERED_MESSAGE_STREAM, value) else direct
        } else emptyList()
        val rendered = renderedMessage(type, value)
        scanStrings(value)
        if (type in DELTA_EVENTS) {
            val delta = stringValue(value["delta"]) ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
            scanSemanticText(delta, matchers)
        }
        rendered?.let { message -> message.parts.forEach { part ->
            scanSemanticText(part.text, if (part.output) message.allMatchers + message.outputMatchers else message.allMatchers)
        } }
        if (type == "response.completed") {
            val response = value["response"] as? JsonObject ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
            if (stringValue(response["status"]) != "completed") reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
            val usage = completedUsage(response)
            outputTokens = boundedTokenCount(usage["output_tokens"])
            if (outputTokens!! > maximumRemainingOutputTokens) reject(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
            inputTokens = boundedTokenCount(usage["input_tokens"])
            maximumRemainingInputTokens?.let { limit ->
                val count = inputTokens ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
                if (count.toLong() > limit) reject(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
            }
            completed = true
        }
        val emitted = normalized.toByteArray(Charsets.UTF_8)
        for (byte in emitted) {
            if (emittedMatcher.accept(byte)) reject(AcpProviderTerminalKind.SECRET_EXPOSURE)
        }
        val capacity = bounds.maximumChunkBytes.toLong() * bounds.maximumQueuedChunks
        if (emitted.size.toLong() > capacity - pendingBytes) reject(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
        pending.addLast(emitted)
        pendingBytes += emitted.size
        if (!completed && !rawMatcher.hasPrefix() && !emittedMatcher.hasPrefix() && !deltaMatcher.hasPrefix() &&
            logicalDeltaMatchers.values.none { it.hasPrefix() }) {
            val releasedBytes = released.sumOf { it.size.toLong() }
            if (pendingBytes > capacity - releasedBytes) reject(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
            while (pending.isNotEmpty()) released.add(pending.removeFirst())
            pendingBytes = 0L
        }
    }

    /** Exact optional wire types in pinned Codex 0.162.1 ResponsesStreamEvent, not a newer API schema. */
    private fun validateWireFields(value: JsonObject) {
        for (field in listOf("item_id", "call_id", "delta", "text")) {
            optionalValue(value[field])?.let { if (stringValue(it) == null) reject(AcpProviderTerminalKind.MALFORMED_RESPONSE) }
        }
        for (field in listOf("summary_index", "content_index")) {
            optionalValue(value[field])?.let(::wireInteger)
        }
    }

    /** Only completed uses fatal typed response decoding in the pinned consumer. */
    private fun completedUsage(response: JsonObject): JsonObject {
        if (stringValue(response["id"]) == null) reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        optionalValue(response["end_turn"])?.let {
            val primitive = it as? JsonPrimitive ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
            if (primitive.isString || primitive.content !in setOf("true", "false")) reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        }
        optionalValue(response["usage_metadata"])?.let {
            val metadata = it as? JsonObject ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
            optionalValue(metadata["amount"])?.let { amount ->
                if (stringValue(amount) == null) reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
            }
        }
        // Usage is optional upstream, but this adapter's existing token-budget policy requires it.
        val usage = response["usage"] as? JsonObject ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        wireInteger(usage["total_tokens"])
        optionalValue(usage["input_tokens_details"])?.let {
            val details = it as? JsonObject ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
            wireInteger(details["cached_tokens"])
            details["cache_write_tokens"]?.let(::wireInteger)
        }
        optionalValue(usage["output_tokens_details"])?.let {
            val details = it as? JsonObject ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
            wireInteger(details["reasoning_tokens"])
        }
        optionalValue(usage["codex_rollout_budget_units"])?.let {
            val number = it as? JsonPrimitive ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
            if (number.isString || number.content.toDoubleOrNull()?.isFinite() != true) {
                reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
            }
        }
        return usage
    }

    private fun optionalValue(value: JsonElement?): JsonElement? = value?.takeUnless { it == JsonNull }

    private fun wireInteger(value: JsonElement?): Long {
        val primitive = value as? JsonPrimitive ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        if (primitive.isString || !primitive.content.matches(WIRE_INTEGER)) reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        return primitive.content.toLongOrNull() ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
    }

    private fun matchersForDelta(type: String, value: JsonObject): List<ProviderSemanticMatcher> {
        val components = ArrayList<String>()
        var effectiveItem: String? = null
        for (field in STRING_IDENTITY_FIELDS) {
            value[field]?.let { encoded ->
                val identity = stringValue(encoded) ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
                if (identity.length !in 1..128 || !identity.matches(IDENTITY_STRING)) reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
                if (effectiveItem == null) effectiveItem = identity
                components.add("$field=$identity")
            }
        }
        for (field in INDEX_IDENTITY_FIELDS) {
            value[field]?.let { encoded ->
                val identity = boundedTokenCount(encoded)
                components.add("$field=$identity")
            }
        }
        // Type aggregate and stable projections prevent optional identity changes from creating
        // aliases for a downstream stream. They intentionally permit conservative false positives.
        val keys = linkedSetOf("$type|default")
        if (components.isNotEmpty()) {
            keys.add("$type|tuple|${components.joinToString("|")}")
            components.forEach { keys.add("$type|projection|$it") }
            // The pinned custom tool consumer selects item_id.or(call_id). Field-labelled
            // projections alone cannot join an item_id to a later call_id fallback alias.
            effectiveItem?.let { keys.add("$type|effectiveItem|$it") }
        }
        val work = keys.sumOf { it.length.toLong() }
        if (work > bounds.maximumResponseBytes.toLong() - identityWorkBytes) reject(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
        identityWorkBytes += work
        val missing = keys.filter { it !in logicalDeltaMatchers }
        if (missing.size > MAXIMUM_LOGICAL_MATCHERS - logicalDeltaMatchers.size) reject(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
        val retained = missing.sumOf { it.length.toLong() }
        if (retained > MAXIMUM_IDENTITY_BYTES - storedIdentityBytes) reject(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
        storedIdentityBytes += retained
        return keys.map { key -> logicalDeltaMatchers.getOrPut(key) { ProviderSemanticMatcher(secretPatterns, forbiddenPatterns) } }
    }

    private class RenderedPart(val text: String, val output: Boolean)
    private class RenderedMessage(val parts: List<RenderedPart>, val allMatchers: List<ProviderSemanticMatcher>,
        val outputMatchers: List<ProviderSemanticMatcher>)

    private fun renderedMessage(type: String, value: JsonObject): RenderedMessage? {
        if (type != "response.output_item.added" && type != "response.output_item.done") return null
        val item = value["item"] as? JsonObject ?: return null
        if (stringValue(item["type"]) != "message" || stringValue(item["role"]) != "assistant") return null
        val content = item["content"] as? JsonArray ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        val parts = ArrayList<RenderedPart>()
        for (element in content) {
            val part = element as? JsonObject ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
            val partType = stringValue(part["type"])
            if (partType == "output_text" || partType == "input_text") {
                parts.add(RenderedPart(stringValue(part["text"]) ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE),
                    partType == "output_text"))
            }
        }
        val identity = LinkedHashMap<String, JsonElement>()
        item["id"]?.let { identity["item_id"] = it }
        value["output_index"]?.let { identity["output_index"] = it }
        // The pinned assistant renderer concatenates these parts without a separator. Keeping
        // KMP state across parts proves the exact join without constructing a joined string.
        // raw_assistant_output_text_from_item separately concatenates only output_text parts;
        // input_text therefore must not reset that projection's credential continuation state.
        val identityValue = JsonObject(identity)
        return RenderedMessage(parts, matchersForDelta(RENDERED_MESSAGE_STREAM, identityValue),
            matchersForDelta("response.output_text.delta", identityValue))
    }

    private fun scanSemanticText(value: String, matchers: List<ProviderSemanticMatcher>) {
        val byteCount = utf8Length(value)
        if (byteCount > bounds.maximumResponseBytes.toLong() - semanticBytes) reject(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
        val work = byteCount * (matchers.size + 1L)
        val workLimit = bounds.maximumResponseBytes.toLong() * (MAXIMUM_LOGICAL_MATCHERS + 1L)
        if (work > workLimit - semanticWork) reject(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
        semanticBytes += byteCount
        semanticWork += work
        for (byte in value.toByteArray(Charsets.UTF_8)) {
            deltaMatcher.accept(byte)?.let(::reject)
            for (matcher in matchers) matcher.accept(byte)?.let(::reject)
        }
    }

    private fun chargeJsonTokens(value: JsonElement) {
        val charge = when (value) {
            is JsonObject -> 2L + value.size
            is JsonArray -> 2L
            is JsonPrimitive -> 1L
        }
        val limit = minOf(bounds.maximumResponseBytes.toLong(), MAXIMUM_JSON_TOKENS)
        if (charge > limit - jsonTokens) reject(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
        jsonTokens += charge
        when (value) {
            is JsonObject -> value.values.forEach(::chargeJsonTokens)
            is JsonArray -> value.forEach(::chargeJsonTokens)
            is JsonPrimitive -> Unit
        }
    }

    private fun scanStrings(value: JsonElement) {
        when (value) {
            is JsonObject -> value.forEach { (key, child) -> scanString(key); scanStrings(child) }
            is JsonArray -> value.forEach(::scanStrings)
            is JsonPrimitive -> if (value.isString) scanString(value.content)
        }
    }

    private fun scanString(value: String) {
        val byteCount = utf8Length(value)
        if (byteCount > bounds.maximumResponseBytes.toLong() - decodedBytes) reject(AcpProviderTerminalKind.RESOURCE_EXHAUSTED)
        decodedBytes += byteCount
        val matcher = ProviderSemanticMatcher(secretPatterns, forbiddenPatterns)
        for (byte in value.toByteArray(Charsets.UTF_8)) matcher.accept(byte)?.let(::reject)
    }

    private fun utf8Length(value: String): Long {
        var index = 0
        var byteCount = 0L
        while (index < value.length) {
            val character = value[index++]
            if (character.isHighSurrogate()) {
                if (index >= value.length || !value[index++].isLowSurrogate()) {
                    reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
                }
                byteCount += 4
            } else if (character.isLowSurrogate()) {
                reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
            } else {
                byteCount += when {
                    character.code <= 0x7f -> 1
                    character.code <= 0x7ff -> 2
                    else -> 3
                }
            }
        }
        return byteCount
    }

    private fun boundedTokenCount(value: JsonElement?): Int {
        val primitive = value as? JsonPrimitive ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        if (primitive.isString || !primitive.content.matches(TOKEN_COUNT)) reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
        return primitive.content.toIntOrNull() ?: reject(AcpProviderTerminalKind.MALFORMED_RESPONSE)
    }

    private fun requireActive() {
        failure?.let { throw AcpProviderStreamFailure(it) }
        if (finished) throw AcpProviderStreamFailure(AcpProviderTerminalKind.MALFORMED_RESPONSE)
    }

    private fun reject(kind: AcpProviderTerminalKind): Nothing {
        abort(kind)
        throw AcpProviderStreamFailure(kind)
    }

    /** External owner failures must erase the same quarantine as parser-originated rejection. */
    @Synchronized
    fun abort(kind: AcpProviderTerminalKind) {
        if (failure == null) failure = kind
        pending.forEach { it.fill(0) }
        pending.clear()
        pendingBytes = 0L
        event.erase()
        eraseSecrets()
    }

    private fun eraseSecrets() {
        rawMatcher.clear(); emittedMatcher.clear(); deltaMatcher.clear()
        logicalDeltaMatchers.values.forEach { it.clear() }
        logicalDeltaMatchers.clear()
        secretPatterns.forEach { it.bytes.fill(0); it.prefixes.fill(0) }
    }

    companion object {
        internal const val MAXIMUM_EVENTS: Int = 4096
        internal const val MAXIMUM_JSON_TOKENS: Long = 1_000_000
        internal const val MAXIMUM_LOGICAL_MATCHERS: Int = 64
        private const val MAXIMUM_IDENTITY_BYTES: Long = 64 * 1024
        private val EVENT_TYPE = Regex("(?:response\\.[a-z][a-z0-9_.]{0,127}|error)")
        private val TOKEN_COUNT = Regex("(?:0|[1-9][0-9]{0,9})")
        private val WIRE_INTEGER = Regex("(?:0|-?[1-9][0-9]{0,18})")
        private val ERROR_EVENTS = setOf("response.error", "response.failed", "response.incomplete")
        private val STRING_IDENTITY_FIELDS = listOf("item_id", "call_id")
        private val INDEX_IDENTITY_FIELDS = listOf("output_index", "content_index", "summary_index")
        private val IDENTITY_STRING = Regex("[A-Za-z0-9._:-]+")
        private const val RENDERED_MESSAGE_STREAM = "rendered.message"
        // This checkpoint cannot reproduce the native renderer's hidden citation removal. Reject
        // exact decoded markers (including continuations) instead of forwarding a transformed join.
        private val FORBIDDEN_RENDERED_MARKERS = listOf("<oai-mem-citation>", "</oai-mem-citation>")
        // Closed subset of process_responses_event match arms in Codex 0.162.1, commit
        // 092d3acd6bec3e3a14bdc7e7a2810ab628ab759d, codex-api/src/sse/responses.rs.
        // Metadata extensions and websocket events are deliberately unsupported in this checkpoint.
        private val DELTA_EVENTS = setOf(
            "response.output_text.delta", "response.custom_tool_call_input.delta",
            "response.function_call_arguments.delta", "response.reasoning_summary_text.delta", "response.reasoning_text.delta",
        )
        private val SUPPORTED_EVENTS = DELTA_EVENTS + setOf(
            "response.created", "response.in_progress", "response.completed",
            "response.output_item.added", "response.output_item.done", "response.content_part.added", "response.content_part.done",
            "response.output_text.done", "response.custom_tool_call_input.done", "response.function_call_arguments.done",
            "response.reasoning_summary_text.done", "response.reasoning_summary_part.added", "response.reasoning_summary_part.done",
        )
    }
}

private class ProviderSemanticMatcher(secrets: List<ProviderSecretPattern>, forbidden: List<ProviderSecretPattern>) {
    private val credentials = ProviderSecretMatcher(secrets)
    private val markup = ProviderSecretMatcher(forbidden)

    fun accept(byte: Byte): AcpProviderTerminalKind? = when {
        credentials.accept(byte) -> AcpProviderTerminalKind.SECRET_EXPOSURE
        markup.accept(byte) -> AcpProviderTerminalKind.MALFORMED_RESPONSE
        else -> null
    }

    fun hasPrefix(): Boolean = credentials.hasPrefix() || markup.hasPrefix()
    fun clear() { credentials.clear(); markup.clear() }
}

/** Knuth–Morris–Pratt state is finite even for overlapping, adversarial credential prefixes. */
private class ProviderSecretPattern(val bytes: ByteArray) {
    val prefixes = IntArray(bytes.size).also { table ->
        var matched = 0
        for (index in 1 until bytes.size) {
            while (matched > 0 && bytes[index] != bytes[matched]) matched = table[matched - 1]
            if (bytes[index] == bytes[matched]) matched++
            table[index] = matched
        }
    }
}

private class ProviderSecretMatcher(private val patterns: List<ProviderSecretPattern>) {
    private val positions = IntArray(patterns.size)

    fun accept(byte: Byte): Boolean {
        for (index in patterns.indices) {
            val pattern = patterns[index].bytes
            val table = patterns[index].prefixes
            var matched = positions[index]
            while (matched > 0 && byte != pattern[matched]) matched = table[matched - 1]
            if (byte == pattern[matched]) matched++
            if (matched == pattern.size) return true
            positions[index] = matched
        }
        return false
    }

    fun hasPrefix(): Boolean = positions.any { it != 0 }
    fun clear() { positions.fill(0) }
}

private fun stringValue(value: JsonElement?): String? = (value as? JsonPrimitive)?.takeIf { it.isString }?.content

/** reset() alone leaves the previous event bytes in ByteArrayOutputStream's retained backing array. */
private class ErasableProviderEventBuffer(capacity: Int) : ByteArrayOutputStream(capacity) {
    fun erase() { buf.fill(0); reset() }
}
