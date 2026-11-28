package decompengine.builtin

import decompengine.builtin.provider.boundedProviderJson
import decompengine.builtin.provider.writeProviderValue
import kotlinx.serialization.json.*

internal const val BUILTIN_REDACTION_MARKER = "[REDACTED]"
internal const val BUILTIN_EVIDENCE_MASK = '*'
internal const val MINIMUM_BUILTIN_SECRET_LENGTH = 8
internal const val MAXIMUM_BUILTIN_SECRET_LENGTH = 4096

/** Bounded nested JSON-string escaping depth; deeper or transformed spellings are not classified. */
private const val MAXIMUM_JSON_ESCAPE_DEPTH = 3

/**
 * Declared secrets must be distinguishable from evidence vocabulary and from redaction output.
 * Refused shapes would otherwise rewrite schema-owned values (versions, booleans, counts), or let the
 * marker or evidence mask itself spell a declared secret. Refusal messages never contain the value.
 */
internal fun admitBuiltinSecrets(secrets: Collection<String>): List<String> {
    val admitted = secrets.distinct()
    admitted.forEach { secret ->
        require(secret.length in MINIMUM_BUILTIN_SECRET_LENGTH..MAXIMUM_BUILTIN_SECRET_LENGTH) {
            "Declared built-in secrets must contain $MINIMUM_BUILTIN_SECRET_LENGTH to $MAXIMUM_BUILTIN_SECRET_LENGTH characters"
        }
        require(secret !in setOf("true", "false", "null") && !secret.all { it in '0'..'9' }) {
            "Declared built-in secrets must not be a JSON literal or contain only digits"
        }
        require(!BUILTIN_REDACTION_MARKER.contains(secret) && !secret.contains(BUILTIN_REDACTION_MARKER)) {
            "Declared built-in secrets must not contain or be contained in the redaction marker"
        }
        require(!secret.all { it == BUILTIN_EVIDENCE_MASK }) { "Declared built-in secrets must not consist only of the evidence mask" }
        require(secret.indices.all { index ->
            val character = secret[index]
            when {
                character.isHighSurrogate() -> index + 1 < secret.length && secret[index + 1].isLowSurrogate()
                character.isLowSurrogate() -> index > 0 && secret[index - 1].isHighSurrogate()
                else -> true
            }
        }) { "Declared built-in secrets must be valid Unicode text" }
    }
    return admitted.sortedByDescending { it.length }
}

/**
 * Raw secrets plus each nested JSON-string spelling produced by either serializer this harness uses:
 * kotlinx (lowercase `\u001b`) and the built-in Jackson writer used for tool pages and provider bodies
 * (uppercase `\u001B`). Every layer applies both encoders, so the pattern set stays bounded.
 */
internal fun builtinRedactionPatterns(secrets: List<String>): List<String> = secrets.flatMap { secret ->
    val spellings = linkedSetOf(secret)
    var layer = setOf(secret)
    repeat(MAXIMUM_JSON_ESCAPE_DEPTH) {
        layer = layer.flatMap { listOf(kotlinxEscaped(it), builtinWriterEscaped(it)) }.toSet()
        spellings += layer
    }
    spellings
}.distinct().sortedByDescending { it.length }

private fun kotlinxEscaped(value: String) = JsonPrimitive(value).toString().drop(1).dropLast(1)
private fun builtinWriterEscaped(value: String) =
    boundedProviderJson(Int.MAX_VALUE) { it.writeProviderValue(JsonPrimitive(value)) }.decodeToString().drop(1).dropLast(1)

/**
 * Journal records are schema-owned: keys, record kinds, envelopes, versions, booleans, counts,
 * enum names and hashes are never rewritten. Only values the harness designates as content
 * (provider, tool and caller text) pass through [redactContent]; everything else is checked by
 * [compliant] and fails closed when a declared spelling remains.
 */
internal class BuiltinRedactor(secrets: Collection<String>) {
    private val patterns = builtinRedactionPatterns(admitBuiltinSecrets(secrets))
    private val longest = patterns.firstOrNull()?.length ?: 0

    /**
     * Coverage of [start, end) by any declared spelling. Only occurrences that can intersect the
     * range are searched (a window extended by the longest spelling on each side), and coverage is
     * merged in a difference array, so cost is bounded by the range and no object is kept per match.
     */
    fun coverage(value: String, start: Int = 0, end: Int = value.length, checkpoint: () -> Unit = {}): BooleanArray? {
        if (patterns.isEmpty() || start >= end) return null
        val windowStart = maxOf(0, start - longest + 1)
        val windowEnd = minOf(value.length, end + longest - 1)
        val window = if (windowStart == 0 && windowEnd == value.length) value else value.substring(windowStart, windowEnd)
        var difference: IntArray? = null
        var matches = 0
        patterns.forEach { pattern ->
            checkpoint()
            var index = window.indexOf(pattern)
            while (index >= 0) {
                val first = maxOf(windowStart + index, start)
                val last = minOf(windowStart + index + pattern.length, end)
                if (first < last) {
                    val counts = difference ?: IntArray(end - start + 1).also { difference = it }
                    counts[first - start]++; counts[last - start]--
                }
                if (++matches and 0x3ff == 0) checkpoint()
                index = window.indexOf(pattern, index + 1)
            }
        }
        val counts = difference ?: return null
        var active = 0
        return BooleanArray(end - start) { offset -> active += counts[offset]; active > 0 }
    }

    fun matches(value: String) = coverage(value) != null

    fun redactString(value: String): String {
        val covered = coverage(value) ?: return value
        val result = StringBuilder(value.length)
        covered.forEachIndexed { index, masked ->
            if (!masked) result.append(value[index])
            else if (index == 0 || !covered[index - 1]) result.append(BUILTIN_REDACTION_MARKER)
        }
        return result.toString().also { check(!matches(it)) } // Redaction must never spell a declared secret.
    }

    /** Harness-designated content only: keys, strings and literals are rewritten; collisions fail closed. */
    fun redactContent(value: JsonElement): JsonElement = when (value) {
        is JsonObject -> {
            val pairs = value.entries.map { redactString(it.key) to redactContent(it.value) }
            check(pairs.map { it.first }.distinct().size == pairs.size)
            JsonObject(pairs.toMap())
        }
        is JsonArray -> JsonArray(value.map(::redactContent))
        is JsonPrimitive -> when {
            value.isString -> JsonPrimitive(redactString(value.content))
            value is JsonNull -> value
            // A numeric or boolean literal cannot hold a placeholder, so it becomes the marker string.
            matches(value.content) -> JsonPrimitive(BUILTIN_REDACTION_MARKER)
            else -> value
        }
    }

    /** True when no key, value or literal anywhere in the value contains a declared spelling. */
    fun compliant(value: JsonElement): Boolean = when (value) {
        is JsonObject -> value.all { (key, child) -> !matches(key) && compliant(child) }
        is JsonArray -> value.all(::compliant)
        is JsonPrimitive -> value is JsonNull || !matches(value.content)
    }

    /**
     * Mask every character of [start, end) that a declared spelling in the original text covers.
     * Returns null when the masked page would itself spell a declared secret, so the page fails closed.
     */
    fun maskSlice(value: String, start: Int, end: Int, checkpoint: () -> Unit = {}): String? {
        val covered = coverage(value, start, end, checkpoint) ?: return value.substring(start, end)
        val masked = String(CharArray(end - start) { offset -> if (covered[offset]) BUILTIN_EVIDENCE_MASK else value[start + offset] })
        return masked.takeIf { coverage(it, checkpoint = checkpoint) == null }
    }
}
