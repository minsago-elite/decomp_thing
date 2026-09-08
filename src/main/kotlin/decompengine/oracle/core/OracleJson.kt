package decompengine.oracle.core

import java.io.ByteArrayOutputStream
import java.math.BigDecimal
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import kotlin.math.abs
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Resource limits applied both while parsing and while rendering oracle artifacts. */
data class StrictJsonLimits(
    val maximumInputBytes: Int = 4 * 1024 * 1024,
    val maximumCanonicalBytes: Int = 4 * 1024 * 1024,
    val maximumDepth: Int = 64,
    val maximumNodes: Int = 100_000,
    val maximumStringBytes: Int = 1024 * 1024,
    val maximumTotalStringBytes: Int = 2 * 1024 * 1024,
    val maximumNumberCharacters: Int = 256,
) {
    init {
        require(maximumInputBytes in 1..HARD_MAXIMUM_BYTES) { "maximumInputBytes is outside the supported range" }
        require(maximumCanonicalBytes in 1..HARD_MAXIMUM_BYTES) {
            "maximumCanonicalBytes is outside the supported range"
        }
        require(maximumDepth in 1..HARD_MAXIMUM_DEPTH) { "maximumDepth is outside the supported range" }
        require(maximumNodes in 1..HARD_MAXIMUM_NODES) { "maximumNodes is outside the supported range" }
        require(maximumStringBytes in 1..HARD_MAXIMUM_BYTES) {
            "maximumStringBytes is outside the supported range"
        }
        require(maximumTotalStringBytes in 1..HARD_MAXIMUM_BYTES) {
            "maximumTotalStringBytes is outside the supported range"
        }
        require(maximumNumberCharacters in 1..HARD_MAXIMUM_NUMBER_CHARACTERS) {
            "maximumNumberCharacters is outside the supported range"
        }
    }

    private companion object {
        const val HARD_MAXIMUM_BYTES = 64 * 1024 * 1024
        const val HARD_MAXIMUM_DEPTH = 256
        const val HARD_MAXIMUM_NODES = 1_000_000
        const val HARD_MAXIMUM_NUMBER_CHARACTERS = 4096
    }
}

class StrictJsonException(message: String, cause: Throwable? = null) : IllegalArgumentException(message, cause)

/** Strict, bounded JSON support for authenticated oracle artifacts. */
object OracleJson {
    fun parse(bytes: ByteArray, limits: StrictJsonLimits = StrictJsonLimits()): JsonElement {
        if (bytes.size > limits.maximumInputBytes) {
            throw StrictJsonException("JSON input exceeds the configured byte limit")
        }
        val input = bytes.copyOf()
        val text = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(input))
                .toString()
        } catch (failure: Exception) {
            throw StrictJsonException("JSON input is not valid UTF-8", failure)
        }
        return StrictParser(text, limits).parse()
    }

    fun canonicalBytes(element: JsonElement, limits: StrictJsonLimits = StrictJsonLimits()): ByteArray =
        CanonicalEncoder(limits).encode(element)

    fun parseAndCanonicalize(bytes: ByteArray, limits: StrictJsonLimits = StrictJsonLimits()): ByteArray =
        canonicalBytes(parse(bytes, limits), limits)

    fun parseCanonical(bytes: ByteArray, limits: StrictJsonLimits = StrictJsonLimits()): JsonElement {
        val input = bytes.copyOf()
        val element = parse(input, limits)
        val canonical = canonicalBytes(element, limits)
        if (!MessageDigest.isEqual(input, canonical)) {
            throw StrictJsonException("JSON artifact is not in canonical byte form")
        }
        return element
    }
}

private class StrictParser(
    private val source: String,
    private val limits: StrictJsonLimits,
) {
    private var offset = 0
    private var nodes = 0
    private var totalStringBytes = 0

    fun parse(): JsonElement {
        skipWhitespace()
        if (offset == source.length) fail("JSON input is empty")
        val result = parseValue(depth = 1)
        skipWhitespace()
        if (offset != source.length) fail("unexpected trailing JSON content")
        return result
    }

    private fun parseValue(depth: Int): JsonElement {
        chargeNode()
        if (offset >= source.length) fail("expected a JSON value")
        return when (source[offset]) {
            '{' -> parseObject(depth)
            '[' -> parseArray(depth)
            '"' -> JsonPrimitive(parseStringAndCharge())
            't' -> parseLiteral("true", JsonPrimitive(true))
            'f' -> parseLiteral("false", JsonPrimitive(false))
            'n' -> parseLiteral("null", JsonNull)
            '-', in '0'..'9' -> parseNumber()
            else -> fail("invalid JSON value")
        }
    }

    private fun parseObject(depth: Int): JsonObject {
        checkDepth(depth)
        offset++
        skipWhitespace()
        if (consume('}')) return JsonObject(emptyMap())
        val entries = LinkedHashMap<String, JsonElement>()
        while (true) {
            if (offset >= source.length || source[offset] != '"') fail("object key must be a string")
            val key = parseStringAndCharge()
            if (entries.containsKey(key)) fail("duplicate object key")
            skipWhitespace()
            expect(':')
            skipWhitespace()
            entries[key] = parseValue(depth + 1)
            skipWhitespace()
            if (consume('}')) return JsonObject(entries)
            expect(',')
            skipWhitespace()
        }
    }

    private fun parseArray(depth: Int): JsonArray {
        checkDepth(depth)
        offset++
        skipWhitespace()
        if (consume(']')) return JsonArray(emptyList())
        val entries = ArrayList<JsonElement>()
        while (true) {
            entries += parseValue(depth + 1)
            skipWhitespace()
            if (consume(']')) return JsonArray(entries)
            expect(',')
            skipWhitespace()
        }
    }

    private fun parseNumber(): JsonPrimitive {
        val start = offset
        consume('-')
        if (offset >= source.length) fail("incomplete JSON number")
        when (source[offset]) {
            '0' -> {
                offset++
                if (offset < source.length && source[offset] in '0'..'9') fail("JSON number has a leading zero")
            }
            in '1'..'9' -> while (offset < source.length && source[offset] in '0'..'9') offset++
            else -> fail("invalid JSON number")
        }
        var floating = false
        if (consume('.')) {
            floating = true
            val fractionStart = offset
            while (offset < source.length && source[offset] in '0'..'9') offset++
            if (offset == fractionStart) fail("JSON number has an incomplete fraction")
        }
        if (offset < source.length && (source[offset] == 'e' || source[offset] == 'E')) {
            floating = true
            offset++
            if (offset < source.length && (source[offset] == '+' || source[offset] == '-')) offset++
            val exponentStart = offset
            while (offset < source.length && source[offset] in '0'..'9') offset++
            if (offset == exponentStart) fail("JSON number has an incomplete exponent")
        }
        val tokenLength = offset - start
        if (tokenLength > limits.maximumNumberCharacters) fail("JSON number exceeds the configured character limit")
        val token = source.substring(start, offset)
        if (floating) {
            val value = token.toDoubleOrNull() ?: fail("invalid JSON number")
            if (!value.isFinite()) fail("JSON number is not finite")
        }
        return try {
            Json.parseToJsonElement(token) as JsonPrimitive
        } catch (failure: Exception) {
            throw StrictJsonException("invalid JSON number at character $start", failure)
        }
    }

    private fun parseStringAndCharge(): String {
        expect('"')
        val result = StringBuilder()
        while (offset < source.length) {
            val current = source[offset++]
            when {
                current == '"' -> {
                    val value = result.toString()
                    chargeString(value)
                    return value
                }
                current == '\\' -> parseEscape(result)
                current.code < 0x20 -> fail("unescaped control character in JSON string")
                Character.isHighSurrogate(current) -> {
                    if (offset >= source.length || !Character.isLowSurrogate(source[offset])) {
                        fail("unpaired high surrogate in JSON string")
                    }
                    result.append(current).append(source[offset++])
                }
                Character.isLowSurrogate(current) -> fail("unpaired low surrogate in JSON string")
                else -> result.append(current)
            }
        }
        fail("unterminated JSON string")
    }

    private fun parseEscape(result: StringBuilder) {
        if (offset >= source.length) fail("unterminated JSON escape")
        when (val escaped = source[offset++]) {
            '"', '\\', '/' -> result.append(escaped)
            'b' -> result.append('\b')
            'f' -> result.append('\u000c')
            'n' -> result.append('\n')
            'r' -> result.append('\r')
            't' -> result.append('\t')
            'u' -> {
                val first = parseHexCodeUnit()
                when {
                    Character.isHighSurrogate(first) -> {
                        if (offset + 2 > source.length || source[offset] != '\\' || source[offset + 1] != 'u') {
                            fail("high surrogate is not followed by an escaped low surrogate")
                        }
                        offset += 2
                        val second = parseHexCodeUnit()
                        if (!Character.isLowSurrogate(second)) fail("invalid low surrogate in JSON string")
                        result.append(first).append(second)
                    }
                    Character.isLowSurrogate(first) -> fail("unpaired low surrogate in JSON string")
                    else -> result.append(first)
                }
            }
            else -> fail("invalid JSON escape")
        }
    }

    private fun parseHexCodeUnit(): Char {
        if (offset + 4 > source.length) fail("incomplete Unicode escape")
        var value = 0
        repeat(4) {
            val digit = when (val character = source[offset++]) {
                in '0'..'9' -> character.code - '0'.code
                in 'a'..'f' -> character.code - 'a'.code + 10
                in 'A'..'F' -> character.code - 'A'.code + 10
                else -> fail("invalid Unicode escape")
            }
            value = value * 16 + digit
        }
        return value.toChar()
    }

    private fun chargeNode() {
        nodes++
        if (nodes > limits.maximumNodes) fail("JSON value exceeds the configured node limit")
    }

    private fun chargeString(value: String) {
        val byteCount = value.toByteArray(StandardCharsets.UTF_8).size
        if (byteCount > limits.maximumStringBytes) fail("JSON string exceeds the configured byte limit")
        if (totalStringBytes > limits.maximumTotalStringBytes - byteCount) {
            fail("JSON strings exceed the configured aggregate byte limit")
        }
        totalStringBytes += byteCount
    }

    private fun checkDepth(depth: Int) {
        if (depth > limits.maximumDepth) fail("JSON value exceeds the configured nesting-depth limit")
    }

    private fun parseLiteral(expected: String, value: JsonElement): JsonElement {
        if (!source.regionMatches(offset, expected, 0, expected.length)) fail("invalid JSON literal")
        offset += expected.length
        return value
    }

    private fun skipWhitespace() {
        while (offset < source.length && source[offset] in JSON_WHITESPACE) offset++
    }

    private fun expect(expected: Char) {
        if (!consume(expected)) fail("expected '$expected'")
    }

    private fun consume(expected: Char): Boolean {
        if (offset >= source.length || source[offset] != expected) return false
        offset++
        return true
    }

    private fun fail(message: String): Nothing = throw StrictJsonException("$message at character $offset")

    private companion object {
        val JSON_WHITESPACE = charArrayOf(' ', '\t', '\n', '\r')
    }
}

private class CanonicalEncoder(private val limits: StrictJsonLimits) {
    private val output = BoundedByteWriter(limits.maximumCanonicalBytes)
    private var nodes = 0
    private var totalStringBytes = 0

    fun encode(element: JsonElement): ByteArray {
        writeElement(element, indentation = 0, structuralDepth = 1)
        output.writeAscii("\n")
        return output.toByteArray()
    }

    private fun writeElement(element: JsonElement, indentation: Int, structuralDepth: Int) {
        chargeNode()
        when (element) {
            JsonNull -> output.writeAscii("null")
            is JsonObject -> writeObject(element, indentation, structuralDepth)
            is JsonArray -> writeArray(element, indentation, structuralDepth)
            is JsonPrimitive -> writePrimitive(element)
        }
    }

    private fun writeObject(value: JsonObject, indentation: Int, structuralDepth: Int) {
        checkDepth(structuralDepth)
        if (value.isEmpty()) {
            output.writeAscii("{}")
            return
        }
        if (nodes > limits.maximumNodes - value.size) {
            throw StrictJsonException("JSON value exceeds the configured node limit")
        }
        output.writeAscii("{\n")
        val entries = value.entries.sortedWith { left, right -> compareByCodePoint(left.key, right.key) }
        entries.forEachIndexed { index, entry ->
            output.writeSpaces((indentation + 1) * INDENT_WIDTH)
            chargeString(entry.key)
            writeString(entry.key)
            output.writeAscii(": ")
            writeElement(entry.value, indentation + 1, structuralDepth + 1)
            if (index != entries.lastIndex) output.writeAscii(",")
            output.writeAscii("\n")
        }
        output.writeSpaces(indentation * INDENT_WIDTH)
        output.writeAscii("}")
    }

    private fun writeArray(value: JsonArray, indentation: Int, structuralDepth: Int) {
        checkDepth(structuralDepth)
        if (value.isEmpty()) {
            output.writeAscii("[]")
            return
        }
        output.writeAscii("[\n")
        value.forEachIndexed { index, element ->
            output.writeSpaces((indentation + 1) * INDENT_WIDTH)
            writeElement(element, indentation + 1, structuralDepth + 1)
            if (index != value.lastIndex) output.writeAscii(",")
            output.writeAscii("\n")
        }
        output.writeSpaces(indentation * INDENT_WIDTH)
        output.writeAscii("]")
    }

    private fun writePrimitive(value: JsonPrimitive) {
        if (value.isString) {
            chargeString(value.content)
            writeString(value.content)
            return
        }
        when (value.content) {
            "true", "false" -> output.writeAscii(value.content)
            else -> output.writeAscii(canonicalNumber(value.content, limits.maximumNumberCharacters))
        }
    }

    private fun writeString(value: String) {
        output.writeAscii("\"")
        var index = 0
        while (index < value.length) {
            val current = value[index]
            when (current) {
                '"' -> output.writeAscii("\\\"")
                '\\' -> output.writeAscii("\\\\")
                '\b' -> output.writeAscii("\\b")
                '\u000c' -> output.writeAscii("\\f")
                '\n' -> output.writeAscii("\\n")
                '\r' -> output.writeAscii("\\r")
                '\t' -> output.writeAscii("\\t")
                else -> when {
                    current.code < 0x20 -> output.writeAscii("\\u${current.code.toString(16).padStart(4, '0')}")
                    Character.isHighSurrogate(current) -> {
                        if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) {
                            throw StrictJsonException("cannot encode an unpaired high surrogate")
                        }
                        output.writeUtf8(value.substring(index, index + 2))
                        index++
                    }
                    Character.isLowSurrogate(current) -> throw StrictJsonException("cannot encode an unpaired low surrogate")
                    else -> output.writeUtf8(current.toString())
                }
            }
            index++
        }
        output.writeAscii("\"")
    }

    private fun chargeNode() {
        nodes++
        if (nodes > limits.maximumNodes) throw StrictJsonException("JSON value exceeds the configured node limit")
    }

    private fun chargeString(value: String) {
        validateSurrogates(value)
        val byteCount = value.toByteArray(StandardCharsets.UTF_8).size
        if (byteCount > limits.maximumStringBytes) {
            throw StrictJsonException("JSON string exceeds the configured byte limit")
        }
        if (totalStringBytes > limits.maximumTotalStringBytes - byteCount) {
            throw StrictJsonException("JSON strings exceed the configured aggregate byte limit")
        }
        totalStringBytes += byteCount
    }

    private fun checkDepth(depth: Int) {
        if (depth > limits.maximumDepth) {
            throw StrictJsonException("JSON value exceeds the configured nesting-depth limit")
        }
    }

    private companion object {
        const val INDENT_WIDTH = 2
    }
}

private class BoundedByteWriter(private val maximumBytes: Int) {
    private val output = ByteArrayOutputStream(minOf(maximumBytes, 8192))

    fun writeAscii(value: String) = write(value.toByteArray(StandardCharsets.US_ASCII))

    fun writeUtf8(value: String) = write(value.toByteArray(StandardCharsets.UTF_8))

    fun writeSpaces(count: Int) {
        repeat(count) { write(SPACE) }
    }

    fun toByteArray(): ByteArray = output.toByteArray()

    private fun write(value: ByteArray) {
        if (output.size() > maximumBytes - value.size) {
            throw StrictJsonException("canonical JSON exceeds the configured byte limit")
        }
        output.write(value)
    }

    private companion object {
        val SPACE = byteArrayOf(' '.code.toByte())
    }
}

private fun canonicalNumber(token: String, maximumCharacters: Int): String {
    if (token.length > maximumCharacters) throw StrictJsonException("JSON number exceeds the configured character limit")
    if (!STRICT_NUMBER.matches(token)) throw StrictJsonException("invalid JSON number")
    val floating = token.indexOf('.') >= 0 || token.indexOf('e', ignoreCase = true) >= 0
    if (!floating) {
        return try {
            BigInteger(token).toString()
        } catch (failure: NumberFormatException) {
            throw StrictJsonException("invalid JSON integer", failure)
        }
    }

    val value = token.toDoubleOrNull() ?: throw StrictJsonException("invalid JSON number")
    if (!value.isFinite()) throw StrictJsonException("JSON number is not finite")
    if (value != 0.0 && abs(value) < java.lang.Double.MIN_NORMAL) {
        throw StrictJsonException("subnormal floating-point values cannot be rendered portably")
    }
    val negative = java.lang.Double.doubleToRawLongBits(value) < 0
    if (value == 0.0) return if (negative) "-0.0" else "0.0"

    val decimal = BigDecimal.valueOf(abs(value)).stripTrailingZeros()
    val adjustedExponent = decimal.precision() - decimal.scale() - 1
    val magnitude = if (adjustedExponent < -4 || adjustedExponent >= 16) {
        val digits = decimal.unscaledValue().abs().toString()
        val significand = if (digits.length == 1) digits else "${digits[0]}.${digits.substring(1)}"
        val exponentSign = if (adjustedExponent >= 0) '+' else '-'
        "$significand" + "e$exponentSign${abs(adjustedExponent).toString().padStart(2, '0')}"
    } else {
        decimal.toPlainString().let { if ('.' in it) it else "$it.0" }
    }
    return if (negative) "-$magnitude" else magnitude
}

private fun compareByCodePoint(left: String, right: String): Int {
    var leftOffset = 0
    var rightOffset = 0
    while (leftOffset < left.length && rightOffset < right.length) {
        val leftCodePoint = Character.codePointAt(left, leftOffset)
        val rightCodePoint = Character.codePointAt(right, rightOffset)
        if (leftCodePoint != rightCodePoint) return leftCodePoint.compareTo(rightCodePoint)
        leftOffset += Character.charCount(leftCodePoint)
        rightOffset += Character.charCount(rightCodePoint)
    }
    return (left.length - leftOffset).compareTo(right.length - rightOffset)
}

private fun validateSurrogates(value: String) {
    var index = 0
    while (index < value.length) {
        when {
            Character.isHighSurrogate(value[index]) -> {
                if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) {
                    throw StrictJsonException("JSON string contains an unpaired high surrogate")
                }
                index += 2
            }
            Character.isLowSurrogate(value[index]) -> throw StrictJsonException("JSON string contains an unpaired low surrogate")
            else -> index++
        }
    }
}

private val STRICT_NUMBER = Regex("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
