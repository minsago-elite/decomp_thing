package decompengine.builtin

import decompengine.builtin.provider.boundedProviderJson
import decompengine.builtin.provider.writeProviderValue
import kotlinx.serialization.json.*

internal const val BUILTIN_REDACTION_MARKER = "[REDACTED]"
internal const val MINIMUM_BUILTIN_SECRET_LENGTH = 8

/** Bounded nested JSON-string escaping depth; deeper or transformed spellings are not classified. */
private const val MAXIMUM_JSON_ESCAPE_DEPTH = 3
private const val MAXIMUM_SECRET_CHARACTERS = 64 * 1024

/**
 * Declared secrets must be distinguishable from evidence vocabulary. A secret shorter than eight
 * characters, a JSON literal, a digits-only value or a substring of the redaction marker would
 * otherwise rewrite schema-owned metadata (booleans, versions, counts, hashes) or the marker itself.
 * No credential has these shapes, so configuration that declares one is refused rather than guessed.
 */
internal fun admitBuiltinSecrets(secrets: Collection<String>): List<String> {
    val admitted = secrets.distinct()
    admitted.forEach { secret ->
        require(secret.length in MINIMUM_BUILTIN_SECRET_LENGTH..MAXIMUM_SECRET_CHARACTERS) {
            "Declared built-in secrets must contain $MINIMUM_BUILTIN_SECRET_LENGTH to $MAXIMUM_SECRET_CHARACTERS characters"
        }
        require(secret !in setOf("true", "false", "null") && !secret.all { it in '0'..'9' }) {
            "Declared built-in secrets must not be a JSON literal or contain only digits"
        }
        require(!BUILTIN_REDACTION_MARKER.contains(secret)) { "Declared built-in secrets must not overlap the redaction marker" }
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

internal class BuiltinRedactor(secrets: Collection<String>) {
    private val patterns = builtinRedactionPatterns(admitBuiltinSecrets(secrets))
    val active get() = patterns.isNotEmpty()

    /** Disjoint covering spans of every declared spelling, merged when occurrences overlap. */
    fun spans(value: String, checkpoint: () -> Unit = {}): List<IntRange> {
        if (patterns.isEmpty() || value.isEmpty()) return emptyList()
        val occurrences = mutableListOf<IntRange>()
        patterns.forEach { pattern ->
            checkpoint()
            var index = value.indexOf(pattern)
            while (index >= 0) {
                occurrences += index until index + pattern.length
                index = value.indexOf(pattern, index + 1)
            }
        }
        occurrences.sortWith(compareBy<IntRange> { it.first }.thenByDescending { it.last })
        val merged = mutableListOf<IntRange>()
        occurrences.forEach { range ->
            val last = merged.lastOrNull()
            if (last != null && range.first <= last.last) merged[merged.lastIndex] = last.first..maxOf(last.last, range.last)
            else merged += range
        }
        return merged
    }

    fun redactString(value: String): String {
        val spans = spans(value)
        if (spans.isEmpty()) return value
        val result = StringBuilder()
        var index = 0
        spans.forEach { span ->
            result.append(value, index, span.first).append(BUILTIN_REDACTION_MARKER)
            index = span.last + 1
        }
        return result.append(value, index, value.length).toString()
    }

    /**
     * Strings and keys are redacted everywhere. Schema-owned literals (versions, booleans, counts,
     * offsets) keep their type: a declared spelling inside one fails closed instead of being rewritten.
     */
    fun redact(value: JsonElement): JsonElement = when (value) {
        is JsonObject -> {
            val pairs = value.entries.map { redactString(it.key) to redact(it.value) }
            check(pairs.map { it.first }.distinct().size == pairs.size)
            JsonObject(pairs.toMap())
        }
        is JsonArray -> JsonArray(value.map(::redact))
        is JsonPrimitive -> when {
            value.isString -> JsonPrimitive(redactString(value.content))
            value is JsonNull -> value
            else -> value.also { check(spans(it.content).isEmpty()) }
        }
    }

    /**
     * Provider-originated values only (tool-call arguments): a numeric or boolean literal containing
     * a declared spelling cannot hold a placeholder, so it becomes the redaction marker string.
     */
    fun redactProviderLiterals(value: JsonElement): JsonElement = when (value) {
        is JsonObject -> JsonObject(value.mapValues { redactProviderLiterals(it.value) })
        is JsonArray -> JsonArray(value.map(::redactProviderLiterals))
        is JsonPrimitive -> if (!value.isString && value !is JsonNull && spans(value.content).isNotEmpty())
            JsonPrimitive(BUILTIN_REDACTION_MARKER) else value
    }

    /** True when the value already satisfies this policy, so persisted evidence can be admitted unchanged. */
    fun compliant(value: JsonElement): Boolean = when (value) {
        is JsonObject -> value.all { (key, child) -> spans(key).isEmpty() && compliant(child) }
        is JsonArray -> value.all(::compliant)
        is JsonPrimitive -> value is JsonNull || spans(value.content).isEmpty()
    }

    /** Mask every character of a declared spelling that intersects [start, end) of the original text. */
    fun maskSlice(spans: List<IntRange>, value: String, start: Int, end: Int): String {
        val slice = value.substring(start, end)
        if (spans.isEmpty()) return slice
        val masked = StringBuilder(slice)
        spans.forEach { span ->
            val first = maxOf(span.first, start)
            val last = minOf(span.last, end - 1)
            for (index in first..last) masked.setCharAt(index - start, '*')
        }
        return masked.toString()
    }
}
