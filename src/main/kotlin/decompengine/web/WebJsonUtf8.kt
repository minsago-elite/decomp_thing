package decompengine.web

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.ByteArrayOutputStream
import java.io.OutputStream

/** Bounded JSON UTF-8 output that avoids materializing intermediate JSON strings. */
internal object WebJsonUtf8 {
    fun encodedByteCount(element: JsonElement, maximumBytes: Int): Int {
        val writer = Writer(maximumBytes, null)
        writer.element(element)
        writer.finish()
        return writer.size
    }

    fun encode(element: JsonElement, maximumBytes: Int): ByteArray {
        val output = ByteArrayOutputStream(minOf(maximumBytes, 8 * 1024))
        val writer = Writer(maximumBytes, output)
        writer.element(element)
        writer.finish()
        return output.toByteArray()
    }

    private class Writer(private val maximumBytes: Int, private val output: OutputStream?) {
        private val pending = if (output == null) null else ByteArray(8 * 1024)
        private var pendingSize = 0
        var size: Int = 0
            private set

        init { require(maximumBytes >= 0) { "JSON byte limit is invalid" } }

        fun element(value: JsonElement) {
            when (value) {
                JsonNull -> ascii("null")
                is JsonObject -> {
                    ascii("{")
                    value.entries.forEachIndexed { index, (key, child) ->
                        if (index != 0) ascii(",")
                        string(key)
                        ascii(":")
                        element(child)
                    }
                    ascii("}")
                }
                is JsonArray -> {
                    ascii("[")
                    value.forEachIndexed { index, child ->
                        if (index != 0) ascii(",")
                        element(child)
                    }
                    ascii("]")
                }
                is JsonPrimitive -> if (value.isString) string(value.content) else ascii(value.toString())
            }
        }

        fun finish() {
            if (pendingSize > 0) {
                output?.write(checkNotNull(pending), 0, pendingSize)
                pendingSize = 0
            }
        }

        private fun string(value: String) {
            byte('"'.code)
            var index = 0
            while (index < value.length) {
                val character = value[index]
                when (character) {
                    '"' -> ascii("\\\"")
                    '\\' -> ascii("\\\\")
                    '\b' -> ascii("\\b")
                    '\t' -> ascii("\\t")
                    '\n' -> ascii("\\n")
                    '\u000c' -> ascii("\\f")
                    '\r' -> ascii("\\r")
                    else -> when {
                        character.code < 0x20 -> unicodeEscape(character.code)
                        character.isHighSurrogate() -> {
                            val low = value.getOrNull(index + 1)
                            if (low != null && low.isLowSurrogate()) {
                                utf8(Character.toCodePoint(character, low))
                                index++
                            } else byte('?'.code)
                        }
                        character.isLowSurrogate() -> byte('?'.code)
                        else -> utf8(character.code)
                    }
                }
                index++
            }
            byte('"'.code)
        }

        private fun unicodeEscape(code: Int) {
            ascii("\\u")
            val digits = "0123456789abcdef"
            byte(digits[(code ushr 12) and 0xf].code)
            byte(digits[(code ushr 8) and 0xf].code)
            byte(digits[(code ushr 4) and 0xf].code)
            byte(digits[code and 0xf].code)
        }

        private fun ascii(value: String) {
            value.forEach { character ->
                check(character.code < 0x80) { "non-ASCII character in JSON syntax" }
                byte(character.code)
            }
        }

        private fun utf8(codePoint: Int) {
            when {
                codePoint <= 0x7f -> byte(codePoint)
                codePoint <= 0x7ff -> {
                    byte(0xc0 or (codePoint ushr 6))
                    byte(0x80 or (codePoint and 0x3f))
                }
                codePoint <= 0xffff -> {
                    byte(0xe0 or (codePoint ushr 12))
                    byte(0x80 or ((codePoint ushr 6) and 0x3f))
                    byte(0x80 or (codePoint and 0x3f))
                }
                else -> {
                    byte(0xf0 or (codePoint ushr 18))
                    byte(0x80 or ((codePoint ushr 12) and 0x3f))
                    byte(0x80 or ((codePoint ushr 6) and 0x3f))
                    byte(0x80 or (codePoint and 0x3f))
                }
            }
        }

        private fun byte(value: Int) {
            if (size >= maximumBytes) throw WebJsonByteLimitException(maximumBytes)
            size++
            val target = pending
            if (target == null) return
            target[pendingSize++] = value.toByte()
            if (pendingSize == target.size) finish()
        }
    }
}

internal class WebJsonByteLimitException(maximumBytes: Int) : IllegalArgumentException(
    "The JSON document exceeds its $maximumBytes-byte ceiling",
)
