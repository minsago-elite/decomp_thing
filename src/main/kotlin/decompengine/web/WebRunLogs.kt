package decompengine.web

import decompengine.jobs.WorkflowAttempt
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.time.Instant
import kotlinx.serialization.json.*

/**
 * Bounded, redacted line ranges of an attempt's recorded build log. The same policy produces the
 * live ranges and the download, so neither can reveal what the other withholds. Bytes are decoded
 * as UTF-8 with replacement; control characters other than tab become visible escapes, so a log
 * cannot carry terminal sequences or markup into a consumer.
 */
internal class WebRunLogs(private val redaction: WebLogRedaction) {
    /** [beforeLine] selects a byte-bounded range ending just before that line, so backward pages stay adjacent. */
    data class Query(val fromLine: Long?, val tail: Boolean, val limit: Int, val search: String?, val beforeLine: Long? = null)

    data class Line(val number: Long, val text: String, val truncated: Boolean, val replaced: Boolean, val redacted: Boolean,
        // Search the complete bounded, redacted visible text, not just its display prefix.
        val searchText: String = text)

    /** One parsed, redacted capture of the bounded source; range serialization has its own byte budget. */
    class Capture(val sha256: String, val totalBytes: Long, private val lines: List<Line>) {
        val totalLines: Long get() = lines.size.toLong()
        fun line(index: Int): Line = lines[index]
        val redactedLines: Int get() = lines.count { it.redacted }
        fun allLines(): List<Line> = lines
    }

    fun parseQuery(raw: String?): Query {
        fun invalid(): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED",
            "Log ranges accept one of fromLine, beforeLine or tail=true, limit (1-$MAXIMUM_PAGE_LINES) and an optional literal search of at most $MAXIMUM_SEARCH_CHARACTERS characters.")
        if (raw.isNullOrEmpty()) return Query(1, false, DEFAULT_PAGE_LINES, null)
        // Room for a maximal percent-encoded search (128 characters, up to 12 encoded bytes each) and the other fields.
        if (raw.length > 2048) invalid()
        val values = mutableMapOf<String, String>()
        for (part in raw.split('&')) {
            val split = part.indexOf('=')
            if (split < 1) invalid()
            val key = part.substring(0, split)
            if (key !in setOf("fromLine", "beforeLine", "tail", "limit", "search") || key in values) invalid()
            values[key] = try { URLDecoder.decode(part.substring(split + 1), StandardCharsets.UTF_8) } catch (_: Exception) { invalid() }
        }
        val tail = when (values["tail"]) { null -> false; "true" -> true; else -> invalid() }
        val from = values["fromLine"]?.let { value ->
            if (!value.matches(Regex("[1-9][0-9]{0,8}"))) invalid()
            value.toLong()
        }
        val before = values["beforeLine"]?.let { value ->
            if (!value.matches(Regex("[1-9][0-9]{0,8}"))) invalid()
            value.toLong()
        }
        if (listOf(tail, from != null, before != null).count { it } > 1) invalid()
        val limit = values["limit"]?.let { value ->
            if (!value.matches(Regex("[1-9][0-9]{0,2}"))) invalid()
            value.toInt().takeIf { it <= MAXIMUM_PAGE_LINES } ?: invalid()
        } ?: DEFAULT_PAGE_LINES
        val search = values["search"]?.also { value ->
            // Literal text only: no pattern language can make a search expensive.
            if (value.isEmpty() || value.length > MAXIMUM_SEARCH_CHARACTERS || value.any { it.code < 32 || it.code == 127 }) invalid()
        }
        return Query(if (tail || before != null) null else from ?: 1, tail, limit, search, before)
    }

    /** Null when the log exceeds the line budget; callers report it as oversized, never as a failure. */
    fun capture(bytes: ByteArray, sha256: String): Capture? {
        require(bytes.size <= MAXIMUM_LOG_BYTES)
        var newlines = 0
        for (byte in bytes) if (byte == '\n'.code.toByte()) newlines += 1
        val lineCount = newlines + if (bytes.isNotEmpty() && bytes.last() != '\n'.code.toByte()) 1 else 0
        if (lineCount > MAXIMUM_LOG_LINES) return null
        val lines = mutableListOf<Line>()
        var start = 0
        var number = 1L
        fun add(end: Int) {
            require(lines.size < MAXIMUM_LOG_LINES) { "log line budget exceeded" }
            var raw = bytes.copyOfRange(start, end)
            if (raw.isNotEmpty() && raw.last() == '\r'.code.toByte()) raw = raw.copyOf(raw.size - 1)
            val (decoded, replaced) = decode(raw)
            val (redacted, changed) = redaction.apply(decoded)
            val visible = visibleControls(redacted)
            val truncated = visible.length > MAXIMUM_LINE_CHARACTERS
            // Never cut a surrogate pair in half.
            var cut = if (truncated) MAXIMUM_LINE_CHARACTERS else visible.length
            if (truncated && Character.isHighSurrogate(visible[cut - 1])) cut -= 1
            lines += Line(number++, visible.substring(0, cut), truncated, replaced, changed, visible)
        }
        for (index in bytes.indices) if (bytes[index] == '\n'.code.toByte()) { add(index); start = index + 1 }
        if (start < bytes.size) add(bytes.size)
        return Capture(sha256, bytes.size.toLong(), lines)
    }

    fun range(jobId: String, attempt: WorkflowAttempt, capture: Capture?, oversized: Boolean, query: Query, readAt: Instant): JsonObject = buildJsonObject {
        put("jobId", jobId); put("runId", attempt.runId); put("logId", "build"); put("source", "generated-build-log")
        put("attempt", buildJsonObject {
            put("state", attempt.state.wireName)
            put("startedAt", attempt.startedAt?.toString()?.let(::JsonPrimitive) ?: JsonNull)
            put("endedAt", attempt.endedAt?.toString()?.let(::JsonPrimitive) ?: JsonNull)
        })
        put("readAt", readAt.toString())
        put("redactionPolicy", REDACTION_POLICY)
        if (capture == null) {
            put("state", if (oversized) "oversized" else "missing")
            put("maximumBytes", MAXIMUM_LOG_BYTES.toString())
            return@buildJsonObject
        }
        put("state", "available")
        put("sourceSha256", capture.sha256); put("totalBytes", capture.totalBytes.toString()); put("totalLines", capture.totalLines.toString())
        put("redactedLines", capture.redactedLines.toString())
        val total = capture.totalLines
        fun size(line: Line) = line.text.toByteArray(Charsets.UTF_8).size + 64
        var bytes = 0
        val selected = ArrayDeque<Line>()
        val first: Long
        val backward = query.tail || query.beforeLine != null
        if (backward) {
            // Spend the byte budget backward from the final (or requested) line, so the range always ends there.
            var index = if (query.beforeLine != null) minOf(query.beforeLine - 1, total) else total
            while (index >= 1 && selected.size < query.limit) {
                val line = capture.line((index - 1).toInt())
                if (selected.isNotEmpty() && bytes + size(line) > MAXIMUM_RESPONSE_TEXT_BYTES) break
                bytes += size(line); selected.addFirst(line); index -= 1
            }
            first = index + 1
        } else {
            // A position just past the end is an empty, current range: callers can follow without repeating lines.
            first = minOf(requireNotNull(query.fromLine), total + 1)
            var index = first
            while (index <= total && selected.size < query.limit) {
                val line = capture.line((index - 1).toInt())
                if (selected.isNotEmpty() && bytes + size(line) > MAXIMUM_RESPONSE_TEXT_BYTES) break
                bytes += size(line); selected.addLast(line); index += 1
            }
        }
        val budgetStopped = selected.size < query.limit && if (backward) first > 1 else first + selected.size - 1 < total
        put("range", buildJsonObject {
            put("firstLine", first.toString()); put("lineCount", selected.size.toString())
            put("truncatedBefore", first > 1); put("truncatedAfter", first + selected.size - 1 < total)
            put("byteLimited", budgetStopped)
        })
        put("lines", buildJsonArray { selected.forEach { add(lineJson(it)) } })
        put("search", query.search?.let { search(capture, it) } ?: JsonNull)
    }

    /** Download text: a provenance header, then every redacted line exactly as ranges present it. */
    fun download(jobId: String, attempt: WorkflowAttempt, capture: Capture, exportedAt: Instant): ByteArray = buildString {
        append("# decomp-workbench log export v1\n")
        append("# job ").append(jobId).append(" attempt ").append(attempt.runId).append(" log build (generated-build-log)\n")
        append("# attempt state ").append(attempt.state.wireName).append(" started ").append(attempt.startedAt ?: "not recorded")
            .append(" ended ").append(attempt.endedAt ?: "not recorded").append('\n')
        append("# source sha256 ").append(capture.sha256).append(" bytes ").append(capture.totalBytes)
            .append(" lines ").append(capture.totalLines).append('\n')
        append("# redaction ").append(REDACTION_POLICY).append(" redacted lines ").append(capture.redactedLines)
            .append("; long lines are cut at ").append(MAXIMUM_LINE_CHARACTERS).append(" characters and marked\n")
        append("# exported ").append(exportedAt).append('\n')
        for (line in capture.allLines()) {
            append(line.text)
            if (line.truncated) append(" [line truncated]")
            append('\n')
        }
    }.toByteArray(Charsets.UTF_8)

    private fun search(capture: Capture, query: String): JsonObject {
        val matches = mutableListOf<Long>()
        var count = 0L
        for (line in capture.allLines()) if (line.searchText.contains(query)) {
            count += 1
            if (matches.size < MAXIMUM_SEARCH_MATCHES) matches += line.number
        }
        return buildJsonObject {
            put("query", query); put("scope", "whole-log"); put("matchCount", count.toString())
            put("matches", buildJsonArray { matches.forEach { add(JsonPrimitive(it.toString())) } })
            put("matchesTruncated", count > matches.size)
        }
    }

    private fun lineJson(line: Line) = buildJsonObject {
        put("number", line.number.toString()); put("text", line.text)
        put("truncated", line.truncated); put("replacedInvalidText", line.replaced); put("redacted", line.redacted)
    }

    private fun decode(raw: ByteArray): Pair<String, Boolean> {
        val strict = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
        return try { strict.decode(ByteBuffer.wrap(raw)).toString() to false }
        catch (_: CharacterCodingException) { String(raw, StandardCharsets.UTF_8) to true }
    }

    companion object {
        const val REDACTION_POLICY = "web-log-v1"
        const val MAXIMUM_LOG_BYTES = 8 * 1024 * 1024
        const val MAXIMUM_LOG_LINES = 1_000_000
        const val MAXIMUM_LINE_CHARACTERS = 4096
        const val MAXIMUM_PAGE_LINES = 500
        const val DEFAULT_PAGE_LINES = 200
        const val MAXIMUM_RESPONSE_TEXT_BYTES = 256 * 1024
        const val MAXIMUM_SEARCH_CHARACTERS = 128
        const val MAXIMUM_SEARCH_MATCHES = 200

        /** Visible escapes for C0/C1 controls (except tab) and bidirectional overrides. */
        fun visibleControls(text: String): String {
            if (text.none { (it.code < 32 && it != '\t') || it.code in 127..159 || it.code in 0x202a..0x202e || it.code in 0x2066..0x2069 }) return text
            return buildString(text.length + 16) {
                for (character in text) when {
                    character == '\t' -> append(character)
                    character.code == 27 -> append("\\e")
                    character.code < 32 || character.code in 127..159 || character.code in 0x202a..0x202e || character.code in 0x2066..0x2069 ->
                        append("\\u").append("%04x".format(character.code))
                    else -> append(character)
                }
            }
        }
    }
}

/** Host roots are replaced by fixed labels; literal configured values are never echoed. */
internal class WebLogRedaction(roots: Map<String, Path>) {
    private val literals = roots.mapNotNull { (label, path) ->
        path.toAbsolutePath().normalize().toString().takeIf { it.length >= 2 && it != "/" }?.let { it to "[$label]" }
    }.sortedByDescending { it.first.length }

    fun apply(text: String): Pair<String, Boolean> {
        var value = text
        for ((literal, label) in literals) value = value.replace(literal, label)
        return value to (value != text)
    }

    companion object {
        fun forHost(storageRoot: Path) = WebLogRedaction(buildMap {
            put("job-store", storageRoot)
            System.getProperty("user.home")?.let { put("home", Path.of(it)) }
            System.getProperty("java.io.tmpdir")?.let { put("temporary", Path.of(it)) }
            System.getProperty("user.dir")?.let { put("working-directory", Path.of(it)) }
        })
    }
}
