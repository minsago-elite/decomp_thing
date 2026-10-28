package decompengine.web

import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileRole
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.*

internal enum class WebSourceSearchMatch(val wire: String) { TEXT("text"), SYMBOL("symbol") }

/** One closed, canonical search request. Neither the query nor the path filter ever selects a filesystem path. */
internal data class WebSourceSearchQuery(
    val text: String,
    val match: WebSourceSearchMatch,
    val caseSensitive: Boolean,
    val directoryId: String,
    val path: String?,
    val limit: Int,
    val cursor: String?,
) {
    /** A continuation can be replayed only under exactly these normalized parameters. */
    val identity: String get() = listOf("revision-source-search-v1", text, match.wire, caseSensitive.toString(), directoryId,
        path ?: "", (path != null).toString(), limit.toString()).joinToString("\u0000")

    companion object {
        const val MAXIMUM_QUERY_CODE_POINTS = 128
        const val MAXIMUM_PATH_CODE_POINTS = 256
        const val DEFAULT_LIMIT = 50
        const val MAXIMUM_LIMIT = 100
        private val SYMBOL = Regex("[A-Za-z_][A-Za-z0-9_]*")
        private val HEX_ESCAPE = Regex("[0-9A-Fa-f]{2}")
        // Version, file index, byte offset, then the coverage gaps observed by earlier pages and the signature.
        internal val CURSOR = Regex("([a-f0-9]{64})_(0|[1-9][0-9]{0,4})_(0|[1-9][0-9]{0,7})_(0|[1-9][0-9]{0,4})_(0|[1-9][0-9]{0,4})_([a-f0-9]{32})")

        fun parse(rawQuery: String?): WebSourceSearchQuery {
            if (rawQuery.isNullOrEmpty() || rawQuery.length > 4096) invalid()
            val fields = linkedMapOf<String, String>()
            for (part in rawQuery.split('&')) {
                val split = part.indexOf('=')
                if (split < 1) invalid()
                val key = part.substring(0, split)
                if (key !in setOf("q", "match", "case", "directory", "path", "limit", "cursor") || key in fields) invalid()
                fields[key] = decode(part.substring(split + 1))
            }
            val text = fields["q"] ?: invalid()
            val match = when (fields["match"] ?: "text") { "text" -> WebSourceSearchMatch.TEXT; "symbol" -> WebSourceSearchMatch.SYMBOL; else -> invalid() }
            val caseSensitive = when (fields["case"] ?: "sensitive") { "sensitive" -> true; "insensitive" -> false; else -> invalid() }
            if (!literal(text, MAXIMUM_QUERY_CODE_POINTS) || (match == WebSourceSearchMatch.SYMBOL && !text.matches(SYMBOL))) invalid()
            val path = fields["path"]?.also { if (!literal(it, MAXIMUM_PATH_CODE_POINTS)) invalid() }
            val directoryId = fields["directory"] ?: "root"
            if (directoryId.length > 128) invalid()
            requireRevisionSourceDirectoryId(directoryId)
            val limit = fields["limit"]?.let { if (!it.matches(Regex("[1-9][0-9]{0,2}"))) invalid(); it.toInt() } ?: DEFAULT_LIMIT
            if (limit !in 1..MAXIMUM_LIMIT) invalid()
            val cursor = fields["cursor"]?.also { if (!it.matches(CURSOR)) invalidCursor() }
            return WebSourceSearchQuery(text, match, caseSensitive, directoryId, path, limit, cursor)
        }

        /** Nonblank single-line text without controls; whitespace inside the literal is significant. */
        private fun literal(value: String, maximum: Int): Boolean {
            val count = value.codePointCount(0, value.length)
            return count in 1..maximum && value.isNotBlank() && value.codePoints().noneMatch { it < 0x20 || it in 0x7f..0x9f }
        }

        /** Strict percent decoding: malformed escapes or UTF-8 are refused instead of being replaced. */
        private fun decode(raw: String): String {
            val bytes = ByteArrayOutputStream(raw.length)
            var index = 0
            while (index < raw.length) {
                val character = raw[index]
                when {
                    character == '+' -> { bytes.write(0x20); index++ }
                    character == '%' -> {
                        if (index + 3 > raw.length || !raw.substring(index + 1, index + 3).matches(HEX_ESCAPE)) invalid()
                        bytes.write(raw.substring(index + 1, index + 3).toInt(16)); index += 3
                    }
                    character.code in 0x21..0x7e -> { bytes.write(character.code); index++ }
                    else -> invalid()
                }
            }
            val decoder = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            return try { decoder.decode(ByteBuffer.wrap(bytes.toByteArray())).toString() } catch (_: CharacterCodingException) { invalid() }
        }

        private fun invalid(): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED",
            "Source search accepts one q literal (1–128 characters; symbol searches use one C identifier), match=text|symbol, " +
                "case=sensitive|insensitive, an optional opaque directory, an optional path substring of at most 256 characters, " +
                "limit from 1 to 100 and a cursor from the previous page.")
    }
}

internal fun invalidSourceSearchCursor(): Nothing = throw WebAccessDenied(400, "INVALID_CURSOR",
    "Use a search cursor from this session, revision and exact query, or start the search again.")

private fun invalidCursor(): Nothing = invalidSourceSearchCursor()

/** The pinned reader requires a positive limit and may read one extra byte to detect growth. */
internal fun sourceSearchReadReservation(file: WebRevisionSourceFile): Long {
    require(file.sizeBytes in 0..WebRevisionSourceContent.MAXIMUM_FILE_BYTES)
    return maxOf(1L, file.sizeBytes) + 1
}

/**
 * Bounded literal search over the canonical input set of one persisted candidate. There is no retained index:
 * every scanned body is a fresh digest-checked capture, so offsets always describe the committed file bytes.
 */
internal class WebRevisionSourceSearch(
    private val source: (String, String, String, (WebRevisionSourceSnapshot, (WebRevisionSourceFile) -> ByteArray?) -> JsonObject) -> JsonObject,
    private val nanoTime: () -> Long = System::nanoTime,
    private val deadlineNanos: Long = DEFAULT_DEADLINE_MS * 1_000_000,
    private val maximumScannedBytes: Long = MAXIMUM_SCANNED_BYTES,
) {
    private val secret = ByteArray(32).also(SecureRandom()::nextBytes)

    init { require(deadlineNanos > 0 && maximumScannedBytes >= WebRevisionSourceContent.MAXIMUM_FILE_BYTES + 1) }

    fun search(owner: String, jobId: String, runId: String, revisionId: String, rawQuery: String?): JsonObject {
        val query = WebSourceSearchQuery.parse(rawQuery)
        // Verify the signature before any capture; the position is trusted only after its version matches the snapshot.
        val continuation = query.cursor?.let { cursor ->
            val parts = WebSourceSearchQuery.CURSOR.matchEntire(cursor)!!.groupValues
            if (!MessageDigest.isEqual(signature(owner, jobId, runId, revisionId, query.identity, parts[1], parts[2], parts[3], parts[4], parts[5]).toByteArray(),
                    parts[6].toByteArray())) invalidCursor()
            Continuation(parts[1], parts[2].toInt(), parts[3].toInt(), parts[4].toInt(), parts[5].toInt())
        }
        val started = nanoTime()
        return source(jobId, runId, revisionId) { snapshot, read ->
            val ref = snapshot.reference
            check(ref.jobId == jobId && ref.runId == runId && ref.revisionId == revisionId)
            scan(owner, snapshot, query, continuation, started, read)
        }
    }

    private class Stop(val reason: String, val fileIndex: Int, val offset: Int)
    private class MatchDeadline(val nextStart: Int) : RuntimeException(null, null, false, false)
    private data class Continuation(val version: String, val fileIndex: Int, val offset: Int, val unsearchableText: Int, val unavailable: Int)

    private fun scan(owner: String, snapshot: WebRevisionSourceSnapshot, query: WebSourceSearchQuery,
        continuation: Continuation?, started: Long, read: (WebRevisionSourceFile) -> ByteArray?): JsonObject {
        val ref = snapshot.reference
        val directory = resolveRevisionSourceDirectory(snapshot, query.directoryId)
        val prefix = directory.path?.let { "$it/" }.orEmpty()
        val folded = if (query.caseSensitive) null else fold(query.text)
        val width = query.text.codePointCount(0, query.text.length)
        val pathFilter = query.path?.let { if (query.caseSensitive) it else fold(it) }
        var inScope = 0; var notViewable = 0; var declaredBinary = 0; var tooLarge = 0
        val searchable = ArrayList<Int>()
        for (index in directory.first until snapshot.files.size) {
            val file = snapshot.files[index]
            val path = file.evidence.path
            if (!path.startsWith(prefix)) break
            if (pathFilter != null && !(if (query.caseSensitive) path else fold(path)).contains(pathFilter)) continue
            inScope++
            when {
                ProjectFileRole.VIEWABLE !in file.evidence.roles -> notViewable++
                file.evidence.contentKind != ProjectContentKind.UTF8_TEXT -> declaredBinary++
                file.sizeBytes > WebRevisionSourceContent.MAXIMUM_FILE_BYTES -> tooLarge++
                else -> searchable += index
            }
        }
        var position = 0; var resumeOffset = 0
        continuation?.let { (version, fileIndex, offset) ->
            if (continuation.unsearchableText + continuation.unavailable > searchable.size) invalidCursor()
            if (version != snapshot.metadataVersion) throw WebAccessDenied(410, "CURSOR_EXPIRED",
                "Source metadata changed since this search page. Start the search again.")
            position = searchable.binarySearch(fileIndex).also { if (it < 0) invalidCursor() }
            if (offset.toLong() > snapshot.files[fileIndex].sizeBytes) invalidCursor()
            resumeOffset = offset
        }
        val items = ArrayList<JsonObject>(query.limit)
        var itemBytes = 0; var scannedFiles = 0; var scannedBytes = 0L; var unsearchableText = 0; var unavailable = 0
        var progressed = false
        var stop: Stop? = null
        fun expired() = progressed && (Thread.currentThread().isInterrupted || nanoTime() - started >= deadlineNanos)
        files@ while (position < searchable.size) {
            val fileIndex = searchable[position]
            val file = snapshot.files[fileIndex]
            val from = resumeOffset
            if (expired()) { stop = Stop("deadline", fileIndex, from); break }
            val reservation = sourceSearchReadReservation(file)
            if (scannedBytes + reservation > maximumScannedBytes) { stop = Stop("byte-limit", fileIndex, from); break }
            // Reserve the full authorized work before IO; failed revalidation and the overflow probe count too.
            scannedBytes += reservation
            val bytes = read(file)
            progressed = true; resumeOffset = 0; position++
            if (bytes == null) { unavailable++; continue }
            check(bytes.size.toLong() == file.sizeBytes)
            scannedFiles++
            if (WebRevisionSourceContent.textFallback(bytes) != null) { unsearchableText++; continue }
            if (from > 0 && from < bytes.size && (bytes[from].toInt() and 0xc0) == 0x80) invalidCursor()
            var lineStart = from
            while (lineStart > 0 && bytes[lineStart - 1] != 10.toByte()) lineStart--
            var line = 1L + (0 until lineStart).count { bytes[it] == 10.toByte() }
            var linesSinceCheck = 0; var bytesSinceCheck = 0L
            while (lineStart < bytes.size) {
                // Bound inter-line work too; the matcher below checkpoints within long lines.
                if (++linesSinceCheck >= 256 || bytesSinceCheck >= DEADLINE_CHECK_BYTES) {
                    linesSinceCheck = 0; bytesSinceCheck = 0
                    if (expired()) { stop = Stop("deadline", fileIndex, lineStart); position--; break@files }
                }
                var lineEnd = lineStart
                while (lineEnd < bytes.size && bytes[lineEnd] != 10.toByte()) lineEnd++
                val text = String(bytes, lineStart, lineEnd - lineStart, Charsets.UTF_8)
                val content = if (text.endsWith('\r')) text.dropLast(1) else text
                // Resume at the first untested candidate, not the start of this line: restarting a
                // repetitive long line would time out forever or repeat matches from earlier pages.
                var searchFrom = if (lineStart < from) String(bytes, lineStart, from - lineStart, Charsets.UTF_8).length else 0
                var bytePosition = maxOf(lineStart, from); var charPosition = searchFrom
                while (true) {
                    val start = try {
                        find(content, query, folded, searchFrom) { nextStart ->
                            if (expired()) throw MatchDeadline(nextStart)
                        }
                    } catch (deadline: MatchDeadline) {
                        val offset = bytePosition + utf8Length(content, charPosition, deadline.nextStart)
                        stop = Stop("deadline", fileIndex, offset); position--; break@files
                    }
                    if (start < 0) break
                    val end = content.offsetByCodePoints(start, width)
                    bytePosition += utf8Length(content, charPosition, start); charPosition = start
                    searchFrom = end
                    if (bytePosition < from) continue
                    val item = item(ref, fileIndex, file, content, start, end, line, lineStart, bytePosition)
                    val size = item.toString().toByteArray(Charsets.UTF_8).size + 1
                    if (items.size >= query.limit || itemBytes + size > MAXIMUM_ITEM_BYTES) {
                        stop = Stop("result-limit", fileIndex, bytePosition); position--; break@files
                    }
                    items += item; itemBytes += size
                    // find's candidate counter restarts after a match. Check between calls too,
                    // continuing after this emitted match so even dense results make progress.
                    if (expired()) {
                        val offset = bytePosition + utf8Length(content, charPosition, end)
                        stop = Stop("deadline", fileIndex, offset); position--; break@files
                    }
                }
                bytesSinceCheck += lineEnd + 1 - lineStart
                lineStart = lineEnd + 1; line++
            }
        }
        // Gaps are cumulative from the first page, so a continued page never reports more coverage than the search had.
        val gapText = (continuation?.unsearchableText ?: 0) + unsearchableText
        val gapUnavailable = (continuation?.unavailable ?: 0) + unavailable
        val next = stop?.let { "${snapshot.metadataVersion}_${it.fileIndex}_${it.offset}_${gapText}_${gapUnavailable}_" +
            signature(owner, ref.jobId, ref.runId, ref.revisionId, query.identity, snapshot.metadataVersion, it.fileIndex, it.offset,
                gapText, gapUnavailable) }
        return buildJsonObject {
            put("binding", buildJsonObject { put("jobId", ref.jobId); put("runId", ref.runId); put("revisionId", ref.revisionId) })
            put("authority", "source-input-commitments"); put("sourceSha256", ref.sourceSha256)
            put("metadataVersion", snapshot.metadataVersion)
            put("query", buildJsonObject {
                put("text", query.text); put("match", query.match.wire); put("caseSensitive", query.caseSensitive)
                put("directoryId", query.directoryId); put("path", query.path?.let(::JsonPrimitive) ?: JsonNull)
            })
            put("index", "none")
            put("status", if (stop == null) "complete" else "partial")
            put("stopReason", stop?.reason?.let(::JsonPrimitive) ?: JsonNull)
            put("scope", buildJsonObject {
                put("filesInScope", inScope); put("searchableFiles", searchable.size)
                put("notViewable", notViewable); put("declaredBinary", declaredBinary); put("tooLarge", tooLarge)
            })
            put("progress", buildJsonObject {
                put("scannedFiles", scannedFiles); put("scannedBytes", scannedBytes.toString())
                put("unsearchableText", unsearchableText); put("unavailableFiles", unavailable)
                put("remainingFiles", searchable.size - position)
            })
            put("coverageGaps", buildJsonObject { put("unsearchableText", gapText); put("unavailableFiles", gapUnavailable) })
            put("limits", buildJsonObject {
                put("maxResults", query.limit); put("maxScannedBytes", maximumScannedBytes.toString())
                put("deadlineMs", (deadlineNanos / 1_000_000).toString())
            })
            put("items", JsonArray(items))
            put("page", buildJsonObject {
                put("limit", query.limit); put("snapshotVersion", snapshot.metadataVersion)
                put("nextCursor", next?.let(::JsonPrimitive) ?: JsonNull)
            })
        }
    }

    private fun item(ref: WebRevisionSourceReference, fileIndex: Int, file: WebRevisionSourceFile, line: String,
        start: Int, end: Int, lineNumber: Long, lineStart: Int, offset: Int): JsonObject {
        val before = line.codePointCount(0, start)
        val beforeStart = if (before > CONTEXT_CODE_POINTS) line.offsetByCodePoints(start, -CONTEXT_CODE_POINTS) else 0
        val after = line.codePointCount(end, line.length)
        val afterEnd = if (after > CONTEXT_CODE_POINTS) line.offsetByCodePoints(end, CONTEXT_CODE_POINTS) else line.length
        return buildJsonObject {
            put("fileId", revisionSourceFileId(ref, fileIndex, file.evidence.path)); put("displayName", file.evidence.path)
            put("sha256", file.evidence.sha256)
            put("line", lineNumber.toString()); put("column", (before + 1).toString())
            put("offsetBytes", offset.toString()); put("lineOffsetBytes", lineStart.toString())
            put("before", line.substring(beforeStart, start)); put("match", line.substring(start, end))
            put("after", line.substring(end, afterEnd))
            put("truncatedBefore", beforeStart > 0); put("truncatedAfter", afterEnd < line.length)
        }
    }

    private fun signature(vararg fields: Any): String {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }
        val bytes = mac.doFinal(fields.joinToString("\u0000").toByteArray(Charsets.UTF_8))
        return buildString(32) {
            val hex = "0123456789abcdef"
            for (index in 0 until 16) { val n = bytes[index].toInt() and 255; append(hex[n ushr 4]); append(hex[n and 15]) }
        }
    }

    companion object {
        const val DEFAULT_DEADLINE_MS = 2_000L
        const val MAXIMUM_SCANNED_BYTES = 32L * 1024 * 1024
        const val CONTEXT_CODE_POINTS = 80
        private const val DEADLINE_CHECK_BYTES = 64L * 1024
        private const val MAXIMUM_ITEM_BYTES = 900_000

        /** Per-code-point simple case folding; it never changes the code point count of the matched text. */
        internal fun fold(value: String): String = buildString(value.length) {
            value.codePoints().forEach { appendCodePoint(Character.toLowerCase(Character.toUpperCase(it))) }
        }

        private fun identifier(character: Char) = character == '_' || character in 'a'..'z' || character in 'A'..'Z' || character in '0'..'9'

        /**
         * Next match in original-line coordinates. At most 256 candidate starts (each comparing at
         * most 128 code points) separate deadline/interruption checks, including rejected symbols
         * and case-sensitive searches. [checkpoint] receives the first untested code-point boundary.
         */
        internal fun find(line: String, query: WebSourceSearchQuery, folded: String?, from: Int,
            checkpoint: (Int) -> Unit = {}): Int {
            val needle = folded?.codePoints()?.toArray()
            var start = from
            var candidates = 0
            while (start < line.length) {
                if (candidates++ == 256) { checkpoint(start); candidates = 1 }
                var end = start
                val matched = if (needle == null) {
                    line.startsWith(query.text, start).also { if (it) end = start + query.text.length }
                } else {
                    var matches = true
                    for (expected in needle) {
                        if (end >= line.length) return -1
                        val actual = line.codePointAt(end)
                        if (Character.toLowerCase(Character.toUpperCase(actual)) != expected) { matches = false; break }
                        end += Character.charCount(actual)
                    }
                    matches
                }
                if (matched && (query.match == WebSourceSearchMatch.TEXT ||
                    ((start == 0 || !identifier(line[start - 1])) && (end == line.length || !identifier(line[end]))))) return start
                start += Character.charCount(line.codePointAt(start))
            }
            return -1
        }

        private fun utf8Length(text: String, from: Int, to: Int): Int {
            var bytes = 0; var index = from
            while (index < to) {
                val code = text.codePointAt(index)
                bytes += when { code < 0x80 -> 1; code < 0x800 -> 2; code < 0x10000 -> 3; else -> 4 }
                index += Character.charCount(code)
            }
            return bytes
        }
    }
}
