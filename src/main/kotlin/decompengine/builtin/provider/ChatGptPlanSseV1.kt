package decompengine.builtin.provider

import decompengine.builtin.*
import kotlinx.serialization.json.*
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

/** Entity framing only. Bytes are borrowed during feed; only bounded line/data buffers survive it. */
internal class ChatGptPlanSseV1(
    private val maximum: Int,
    private val work: ChatGptResponseWorkV1,
    private val event: (String?, ByteArray) -> Boolean,
) {
    private var line = ByteArray(0)
    private var length = 0
    private var data = ByteArray(0)
    private var dataLength = 0
    private var dataLines = 0
    private var name: String? = null
    private var frame = 0
    private var frames = 0
    private var closedFrame = 0
    private var afterCr = false
    private var initial = true
    private var stopped = false

    fun feed(bytes: ByteArray, offset: Int, count: Int) {
        for (i in offset until offset + count) {
            work.check()
            if (stopped) return // completed is the read boundary; no assertion about unread suffix
            val b = bytes[i].toInt() and 255
            if (afterCr && b == 10) {
                afterCr = false
                // The CR has already ended the line; its LF still counts toward the frame cap.
                if (frame != 0) chargeFrame() else v2Capacity(closedFrame < maximum)
                continue
            }
            afterCr = false
            chargeFrame()
            if (b == 0) c2Malformed()
            if (b == 13 || b == 10) {
                endLine()
                afterCr = b == 13
            } else {
                v2Capacity(length < maximum)
                if (length == line.size) line = grow(line, length + 1)
                line[length++] = b.toByte()
            }
        }
    }

    private fun chargeFrame() { v2Capacity(frame < maximum); frame++ }
    private fun grow(old: ByteArray, need: Int): ByteArray {
        work.check()
        val size = minOf(maximum.toLong(), maxOf(need.toLong(), maxOf(32L, old.size.toLong() * 2))).toInt()
        work.keep(size.toLong())
        return old.copyOf(size)
    }
    private fun endLine() {
        work.check()
        work.retain(length.toLong() * 4 + 32)
        var text = c2Decode(line, length)
        if (initial) { initial = false; if (text.startsWith('\uFEFF')) { work.retain(text.length.toLong() * 2); text = text.substring(1) } }
        if ('\uFEFF' in text || '\u0000' in text) c2Malformed()
        length = 0
        if (text.isEmpty()) {
            v2Capacity(++frames <= 4096)
            if (dataLines > 0) {
                c2Require(dataLength > 0)
                work.retain(dataLength.toLong()); work.check()
                stopped = event(name, data.copyOf(dataLength))
            } else c2Require(name == null)
            closedFrame = frame
            name = null; dataLength = 0; dataLines = 0; frame = 0; work.nextFrame()
            return
        }
        if (text[0] == ':') return
        val colon = text.indexOf(':')
        c2Require(colon >= 0)
        work.retain(text.length.toLong() * 2 + 64)
        val field = text.substring(0, colon)
        var start = colon + 1
        if (start < text.length && text[start] == ' ') start++
        when (field) {
            "event" -> { c2Require(name == null); name = text.substring(start); c2Require(name!!.isNotEmpty()) }
            "data" -> {
                val value = text.substring(start)
                val n = work.utf8(value)
                val extra = if (dataLines == 0) 0 else 1
                v2Capacity(n + extra <= maximum.toLong() - dataLength)
                val need = dataLength + n.toInt() + extra
                if (need > data.size) data = grow(data, need)
                if (extra != 0) data[dataLength++] = 10
                work.retain(n); work.check()
                val encoded = value.toByteArray(Charsets.UTF_8)
                encoded.copyInto(data, dataLength); dataLength += encoded.size; dataLines++
            }
            else -> c2Malformed()
        }
    }
    fun endOfInput() { c2Require(stopped); /* terminal-less EOF always fails, including heartbeat-only */ }
    fun discard() { line = ByteArray(0); data = ByteArray(0); length = 0; dataLength = 0; stopped = true }
}

internal fun c2Malformed(): Nothing = throw ModelProviderException(ModelFailureKind.MALFORMED_RESPONSE)
internal fun c2Unsupported(): Nothing = throw ModelProviderException(ModelFailureKind.UNSUPPORTED_FEATURE)
internal fun c2Require(ok: Boolean) { if (!ok) c2Malformed() }
internal fun c2Decode(bytes: ByteArray, length: Int = bytes.size): String = try {
    Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes, 0, length)).toString()
} catch (_: Exception) { c2Malformed() }

/** Conservative live allowance; frame temporaries expire only after dispatch. State charges never refund. */
internal class ChatGptResponseWorkV1(val call: AdmittedModelCallV2, private val secrets: ChatGptPlanSecretsV1,
    private val checkLive: () -> Unit = {}) {
    private var retained = 0L
    private var persistent = 0L
    fun keep(bytes: Long) { retain(bytes); persistent = v2Add(persistent, bytes) }
    fun nextFrame() { retained = persistent }
    fun scanTree(value: JsonElement) {
        check()
        when (value) {
            is JsonObject -> for ((key, child) in value) { scan(key); scanTree(child) }
            is JsonArray -> for (child in value) scanTree(child)
            is JsonPrimitive -> scan(value.content)
        }
    }
    fun keepTree(value: JsonElement) {
        fun size(v: JsonElement): Long {
            check()
            return when (v) {
                is JsonObject -> v.entries.fold(96L) { n, entry -> v2Add(n, v2Add(128 + entry.key.length.toLong() * 2, size(entry.value))) }
                is JsonArray -> v.fold(64L) { n, child -> v2Add(n, v2Add(16, size(child))) }
                is JsonPrimitive -> 64 + v.content.length.toLong() * 2
            }
        }
        keep(size(value))
    }
    fun check() { call.run.deadline.remainingNanos(); checkLive() }
    fun retain(bytes: Long) { check(); retained = v2Add(retained, bytes); v2Capacity(retained <= v2Multiply(4, call.run.budget.responseBytes)) }
    fun utf8(s: String, max: Long = call.run.budget.eventBytes): Long {
        check()
        var n = 0L; var i = 0
        while (i < s.length) {
            if (i % 1024 == 0) check()
            val c = s[i++]
            n += when {
                c.code < 128 -> 1
                c.code < 2048 -> 2
                c.isHighSurrogate() -> { c2Require(i < s.length && s[i++].isLowSurrogate()); 4 }
                c.isLowSurrogate() -> c2Malformed()
                else -> 3
            }
            v2Capacity(n <= max)
        }
        check(); return n
    }
    fun scan(s: String, maximum: Long = call.run.budget.eventBytes) {
        utf8(s, maximum)
        var start = 0
        do {
            check()
            var end = minOf(s.length, start + 32768)
            if (end < s.length && s[end].isLowSurrogate()) end--
            retain(64 + (end - start).toLong() * 2)
            secrets.rejectCredentialsInPrivateJson(JsonPrimitive(if (start == 0 && end == s.length) s else s.substring(start, end)))
            check()
            if (end == s.length) break
            start += 8192
            if (s[start].isLowSurrogate()) start--
        } while (true)
    }
    fun decode(bytes: ByteArray): String {
        retain(bytes.size.toLong() * 4 + 32); check()
        return c2Decode(bytes)
    }
    fun parse(bytes: ByteArray): ChatGptResponseJsonV1 {
        check(); v2Capacity(bytes.size.toLong() <= call.run.budget.eventBytes)
        retain(bytes.size.toLong() * 4 + 64)
        return ChatGptResponseJsonV1(c2Decode(bytes), this)
    }
    fun parseText(s: String): JsonElement {
        val n = utf8(s); retain(n); check()
        return parse(s.toByteArray(Charsets.UTF_8)).value
    }
}

/** Strict scalar parser with decoded-key duplicate detection and exact top-level item span. */
internal class ChatGptResponseJsonV1(private val source: String, private val w: ChatGptResponseWorkV1) {
    private var i = 0
    private var tokens = 0
    private var itemStart = -1
    private var itemEnd = -1
    val value: JsonElement
    init { ws(); value = read(0); ws(); c2Require(i == source.length) }
    fun rawItem(): ByteArray {
        c2Require(itemStart >= 0 && itemEnd > itemStart)
        w.retain((itemEnd - itemStart).toLong() * 5); w.check()
        val s = source.substring(itemStart, itemEnd); w.utf8(s); w.check()
        return s.toByteArray(Charsets.UTF_8)
    }
    private fun token() { w.check(); v2Capacity(++tokens <= 100000); w.retain(64) }
    private fun read(depth: Int): JsonElement {
        token(); c2Require(i < source.length)
        return when (source[i]) {
            '{' -> {
                c2Require(depth < 32); i++; ws(); w.retain(64)
                val fields = LinkedHashMap<String, JsonElement>()
                if (!take('}')) while (true) {
                    token(); val key = string(8192); c2Require(key !in fields); ws(); expect(':'); ws()
                    val start = i; val child = read(depth + 1)
                    if (depth == 0 && key == "item") { itemStart = start; itemEnd = i }
                    w.retain(64); fields[key] = child; ws()
                    if (take('}')) break
                    expect(','); ws()
                }
                JsonObject(fields)
            }
            '[' -> {
                c2Require(depth < 32); i++; ws(); w.retain(32)
                val values = ArrayList<JsonElement>()
                if (!take(']')) while (true) {
                    w.retain(16); values.add(read(depth + 1)); ws()
                    if (take(']')) break
                    expect(','); ws()
                }
                JsonArray(values)
            }
            '"' -> JsonPrimitive(string())
            't' -> { literal("true"); JsonPrimitive(true) }
            'f' -> { literal("false"); JsonPrimitive(false) }
            'n' -> { literal("null"); JsonNull }
            else -> number()
        }
    }
    private fun string(max: Int = Int.MAX_VALUE): String {
        expect('"'); w.retain(64)
        val out = StringBuilder(); var bytes = 0L
        fun unit(): Char {
            c2Require(i < source.length)
            val c = source[i++]
            if (c != '\\') { c2Require(c.code >= 32 && c != '"'); return c }
            c2Require(i < source.length)
            return when (source[i++]) {
                '"' -> '"'; '\\' -> '\\'; '/' -> '/'; 'b' -> '\b'; 'f' -> '\u000c'; 'n' -> '\n'; 'r' -> '\r'; 't' -> '\t'
                'u' -> {
                    c2Require(i + 4 <= source.length); var n = 0
                    repeat(4) { val d = source[i++]; n = n * 16 + when (d) { in '0'..'9' -> d - '0'; in 'a'..'f' -> d - 'a' + 10; in 'A'..'F' -> d - 'A' + 10; else -> c2Malformed() } }
                    n.toChar()
                }
                else -> c2Malformed()
            }
        }
        while (true) {
            w.check(); c2Require(i < source.length)
            if (take('"')) { w.retain(out.length.toLong() * 2); val s = out.toString(); w.scan(s); return s }
            val c = unit()
            val second = if (c.isHighSurrogate()) unit().also { c2Require(it.isLowSurrogate()) } else null
            c2Require(!c.isLowSurrogate())
            bytes += if (second != null) 4 else if (c.code < 128) 1 else if (c.code < 2048) 2 else 3
            v2Capacity(bytes <= max && bytes <= w.call.run.budget.eventBytes)
            w.retain(if (second == null) 8 else 16); out.append(c); if (second != null) out.append(second)
        }
    }
    private fun number(): JsonElement {
        val start = i
        fun advance() { c2Require(i - start < 32); i++ }
        if (i < source.length && source[i] == '-') advance()
        c2Require(i < source.length)
        if (source[i] == '0') { advance(); c2Require(i == source.length || source[i] !in '0'..'9') }
        else { c2Require(source[i] in '1'..'9'); while (i < source.length && source[i] in '0'..'9') advance() }
        if (i < source.length && source[i] == '.') {
            advance(); c2Require(i < source.length && source[i] in '0'..'9'); while (i < source.length && source[i] in '0'..'9') advance()
        }
        if (i < source.length && source[i] in "eE") {
            advance(); if (i < source.length && source[i] in "+-") advance()
            c2Require(i < source.length && source[i] in '0'..'9'); while (i < source.length && source[i] in '0'..'9') advance()
        }
        val s = source.substring(start, i); w.scan(s)
        return Json.parseToJsonElement(s)
    }
    private fun literal(s: String) { c2Require(source.startsWith(s, i)); i += s.length; w.scan(s) }
    private fun ws() { while (i < source.length && source[i] in " \t\r\n") { if (i % 1024 == 0) w.check(); i++ } }
    private fun take(c: Char): Boolean = if (i < source.length && source[i] == c) { i++; true } else false
    private fun expect(c: Char) { c2Require(take(c)) }
}
