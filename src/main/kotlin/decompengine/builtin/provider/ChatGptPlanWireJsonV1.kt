package decompengine.builtin.provider

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.Collections

/** Small, duplicate-aware JSON reader for untrusted ChatGPT wire metadata. */
internal sealed interface ChatGptWireValueV1 {
    // Cached structural sizes let constructors validate shared subtrees without recursion.
    val tokenCount: Int get() = 1
    val containerDepth: Int get() = 0

    class Obj(fields: Map<String, ChatGptWireValueV1>) : ChatGptWireValueV1 {
        val fields: Map<String, ChatGptWireValueV1>
        override val tokenCount: Int
        override val containerDepth: Int
        init {
            if (fields.size > (ChatGptPlanWireJsonV1.MAX_TOKENS - 1) / 2) throw ChatGptWireJsonException()
            val copy = LinkedHashMap<String, ChatGptWireValueV1>()
            var tokens = 1
            var depth = 1
            for ((key, value) in fields) {
                if (ChatGptPlanWireJsonV1.scalarUtf8Length(key, ChatGptPlanWireJsonV1.MAX_NAME_BYTES) == null ||
                    value.tokenCount > ChatGptPlanWireJsonV1.MAX_TOKENS - tokens - 1 ||
                    value.containerDepth >= ChatGptPlanWireJsonV1.MAX_DEPTH || copy.containsKey(key)) throw ChatGptWireJsonException()
                tokens += 1 + value.tokenCount
                depth = maxOf(depth, 1 + value.containerDepth)
                copy[key] = value
            }
            this.fields = Collections.unmodifiableMap(copy)
            tokenCount = tokens
            containerDepth = depth
        }
    }
    class Arr(values: List<ChatGptWireValueV1>) : ChatGptWireValueV1 {
        val values: List<ChatGptWireValueV1>
        override val tokenCount: Int
        override val containerDepth: Int
        init {
            if (values.size > ChatGptPlanWireJsonV1.MAX_TOKENS - 1) throw ChatGptWireJsonException()
            val copy = ArrayList<ChatGptWireValueV1>()
            var tokens = 1
            var depth = 1
            for (value in values) {
                if (value.tokenCount > ChatGptPlanWireJsonV1.MAX_TOKENS - tokens ||
                    value.containerDepth >= ChatGptPlanWireJsonV1.MAX_DEPTH) throw ChatGptWireJsonException()
                tokens += value.tokenCount
                depth = maxOf(depth, 1 + value.containerDepth)
                copy.add(value)
            }
            this.values = Collections.unmodifiableList(copy)
            tokenCount = tokens
            containerDepth = depth
        }
    }
    class Str(val value: String) : ChatGptWireValueV1 {
        init { if (ChatGptPlanWireJsonV1.scalarUtf8Length(value, Int.MAX_VALUE) == null) throw ChatGptWireJsonException() }
    }
    class Num(val lexeme: String) : ChatGptWireValueV1 {
        init {
            if (lexeme.length > ChatGptPlanWireJsonV1.MAX_NUMBER_BYTES ||
                !NUMBER.matches(lexeme)) throw ChatGptWireJsonException()
        }
        private companion object { val NUMBER = Regex("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?") }
    }
    class Bool(val value: Boolean) : ChatGptWireValueV1
    data object Null : ChatGptWireValueV1
}

internal class ChatGptWireJsonException : RuntimeException()

internal object ChatGptPlanWireJsonV1 {
    internal const val MAX_DEPTH = 32
    internal const val MAX_TOKENS = 100_000
    internal const val MAX_NAME_BYTES = 8192
    internal const val MAX_NUMBER_BYTES = 32

    fun parse(bytes: ByteArray, maxBytes: Int): ChatGptWireValueV1 {
        if (bytes.size > maxBytes) throw ChatGptWireJsonException()
        val text = try {
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: Exception) { throw ChatGptWireJsonException() }
        return Parser(text).parse()
    }

    private class Parser(private val s: String) {
        private var i = 0
        private var tokens = 0

        fun parse(): ChatGptWireValueV1 {
            ws()
            val result = value(0)
            ws()
            if (i != s.length) fail()
            return result
        }

        private fun value(depth: Int): ChatGptWireValueV1 {
            if (++tokens > MAX_TOKENS) fail()
            if (depth > MAX_DEPTH || i >= s.length) fail()
            return when (s[i]) {
                '{' -> obj(depth + 1)
                '[' -> array(depth + 1)
                '"' -> ChatGptWireValueV1.Str(string())
                't' -> { literal("true"); ChatGptWireValueV1.Bool(true) }
                'f' -> { literal("false"); ChatGptWireValueV1.Bool(false) }
                'n' -> { literal("null"); ChatGptWireValueV1.Null }
                '-', in '0'..'9' -> number()
                else -> fail()
            }
        }

        private fun obj(depth: Int): ChatGptWireValueV1.Obj {
            if (depth > MAX_DEPTH) fail()
            i++
            ws()
            val map = LinkedHashMap<String, ChatGptWireValueV1>()
            if (take('}')) return ChatGptWireValueV1.Obj(map)
            while (true) {
                if (i >= s.length || s[i] != '"') fail()
                if (++tokens > MAX_TOKENS) fail()
                val key = string(MAX_NAME_BYTES)
                if (map.containsKey(key)) fail()
                ws(); expect(':'); ws()
                map[key] = value(depth)
                ws()
                if (take('}')) break
                expect(','); ws()
            }
            return ChatGptWireValueV1.Obj(map)
        }

        private fun array(depth: Int): ChatGptWireValueV1.Arr {
            if (depth > MAX_DEPTH) fail()
            i++
            ws()
            val values = ArrayList<ChatGptWireValueV1>()
            if (take(']')) return ChatGptWireValueV1.Arr(values)
            while (true) {
                values.add(value(depth))
                ws()
                if (take(']')) break
                expect(','); ws()
            }
            return ChatGptWireValueV1.Arr(values)
        }

        private fun string(maxBytes: Int = Int.MAX_VALUE): String {
            expect('"')
            val out = StringBuilder()
            var bytes = 0
            fun appendScalar(first: Char, second: Char? = null) {
                val width = if (second != null) 4 else when {
                    first.code < 0x80 -> 1
                    first.code < 0x800 -> 2
                    else -> 3
                }
                if (width > maxBytes - bytes) fail()
                bytes += width
                out.append(first)
                if (second != null) out.append(second)
            }
            while (i < s.length) {
                val c = s[i++]
                when {
                    c == '"' -> return out.toString()
                    c == '\\' -> {
                        if (i >= s.length) fail()
                        when (val e = s[i++]) {
                            '"', '\\', '/' -> appendScalar(e)
                            'b' -> appendScalar('\b')
                            'f' -> appendScalar('\u000c')
                            'n' -> appendScalar('\n')
                            'r' -> appendScalar('\r')
                            't' -> appendScalar('\t')
                            'u' -> {
                                val first = hex4()
                                when {
                                    first in 0xD800..0xDBFF -> {
                                        if (i + 2 > s.length || s[i] != '\\' || s[i + 1] != 'u') fail()
                                        i += 2
                                        val second = hex4()
                                        if (second !in 0xDC00..0xDFFF) fail()
                                        appendScalar(first.toChar(), second.toChar())
                                    }
                                    first in 0xDC00..0xDFFF -> fail()
                                    else -> appendScalar(first.toChar())
                                }
                            }
                            else -> fail()
                        }
                    }
                    c.code < 0x20 -> fail()
                    c.isHighSurrogate() -> {
                        if (i >= s.length || !s[i].isLowSurrogate()) fail()
                        appendScalar(c, s[i++])
                    }
                    c.isLowSurrogate() -> fail()
                    else -> appendScalar(c)
                }
            }
            fail()
        }

        private fun hex4(): Int {
            if (i + 4 > s.length) fail()
            var n = 0
            repeat(4) {
                val d = when (val c = s[i++]) {
                    in '0'..'9' -> c - '0'
                    in 'a'..'f' -> c - 'a' + 10
                    in 'A'..'F' -> c - 'A' + 10
                    else -> fail()
                }
                n = n * 16 + d
            }
            return n
        }

        private fun number(): ChatGptWireValueV1.Num {
            val start = i
            take('-')
            if (take('0')) {
                if (i < s.length && s[i] in '0'..'9') fail()
            } else {
                if (i >= s.length || s[i] !in '1'..'9') fail()
                while (i < s.length && s[i] in '0'..'9') i++
            }
            if (take('.')) { if (i >= s.length || s[i] !in '0'..'9') fail(); while (i < s.length && s[i] in '0'..'9') i++ }
            if (i < s.length && s[i] in "eE") {
                i++; if (i < s.length && s[i] in "+-") i++
                if (i >= s.length || s[i] !in '0'..'9') fail()
                while (i < s.length && s[i] in '0'..'9') i++
            }
            if (i - start > MAX_NUMBER_BYTES) fail()
            return ChatGptWireValueV1.Num(s.substring(start, i))
        }

        private fun literal(value: String) { if (!s.startsWith(value, i)) fail(); i += value.length }
        private fun ws() { while (i < s.length && s[i] in " \t\r\n") i++ }
        private fun take(c: Char): Boolean = if (i < s.length && s[i] == c) { i++; true } else false
        private fun expect(c: Char) { if (!take(c)) fail() }
        private fun fail(): Nothing = throw ChatGptWireJsonException()
    }

    /** Checks Unicode scalars and a UTF-8 ceiling without allocating an encoded copy. */
    internal fun scalarUtf8Length(value: String, maxBytes: Int): Int? {
        if (value.length > maxBytes) return null
        var bytes = 0
        var i = 0
        while (i < value.length) {
            val c = value[i++]
            val width = when {
                c.code < 0x80 -> 1
                c.code < 0x800 -> 2
                c.isHighSurrogate() -> {
                    if (i >= value.length || !value[i++].isLowSurrogate()) return null
                    4
                }
                c.isLowSurrogate() -> return null
                else -> 3
            }
            if (width > maxBytes - bytes) return null
            bytes += width
        }
        return bytes
    }
}
