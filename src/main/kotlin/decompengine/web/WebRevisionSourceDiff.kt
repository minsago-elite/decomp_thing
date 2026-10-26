package decompengine.web

import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileRole
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.*

internal enum class WebSourceDiffStatus(val wire: String) {
    ADDED("added"), REMOVED("removed"), MODIFIED("modified"), RENAMED("renamed"), UNCHANGED("unchanged"),
}

/** One classified pair of indices into the base and head snapshots; at least one side is present. */
internal class WebSourceDiffEntry(val status: WebSourceDiffStatus, val base: Int?, val head: Int?) {
    init { require(base != null || head != null) }
}

/**
 * Classify two exact recorded file sets by path and recorded digest only. Renames are detected only between a
 * removed and an added path with the same digest and content kind; a renamed file whose bytes also changed stays a
 * removal plus an addition. Ordering is deterministic: by the head path, or the base path when no head exists.
 */
internal fun classifyRevisionSourceDiff(base: WebRevisionSourceSnapshot, head: WebRevisionSourceSnapshot): List<WebSourceDiffEntry> {
    val baseByPath = base.files.withIndex().associate { it.value.evidence.path to it.index }
    val headByPath = head.files.withIndex().associate { it.value.evidence.path to it.index }
    val entries = ArrayList<WebSourceDiffEntry>(maxOf(base.files.size, head.files.size))
    val removed = ArrayList<Int>(); val added = ArrayList<Int>()
    for ((index, file) in base.files.withIndex()) {
        val other = headByPath[file.evidence.path]
        if (other == null) { removed += index; continue }
        val match = head.files[other]
        val same = match.evidence.sha256 == file.evidence.sha256 && match.evidence.contentKind == file.evidence.contentKind
        entries += WebSourceDiffEntry(if (same) WebSourceDiffStatus.UNCHANGED else WebSourceDiffStatus.MODIFIED, index, other)
    }
    for ((index, file) in head.files.withIndex()) if (file.evidence.path !in baseByPath) added += index
    fun key(file: WebRevisionSourceFile) = file.evidence.sha256 + "\u0000" + file.evidence.contentKind.name
    val addedByContent = added.groupBy { key(head.files[it]) }.mapValues { (_, list) -> ArrayDeque(list) }
    val paired = HashSet<Int>()
    // Both lists are already in path order, so pairing is deterministic.
    for (index in removed) {
        val match = addedByContent[key(base.files[index])]?.removeFirstOrNull()
        if (match == null) entries += WebSourceDiffEntry(WebSourceDiffStatus.REMOVED, index, null)
        else { paired += match; entries += WebSourceDiffEntry(WebSourceDiffStatus.RENAMED, index, match) }
    }
    for (index in added) if (index !in paired) entries += WebSourceDiffEntry(WebSourceDiffStatus.ADDED, null, index)
    fun path(entry: WebSourceDiffEntry) = entry.head?.let { head.files[it].evidence.path } ?: base.files[entry.base!!].evidence.path
    entries.sortWith(compareBy<WebSourceDiffEntry> { path(it) }.thenBy { it.status.ordinal })
    return entries
}

/** Parsed closed query shared by the summary, file and patch routes. */
internal data class WebSourceDiffQuery(
    val baseRunId: String, val baseRevisionId: String, val baseFileId: String?, val headFileId: String?,
    val limit: Int, val cursor: String?, val hunk: Int,
    /** Optional pin of both observed metadata versions; continued hunk pages and patches must match it. */
    val metadataVersion: String? = null, val baseMetadataVersion: String? = null,
) {
    companion object {
        private val ID = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")

        fun parse(rawQuery: String?, keys: Set<String>): WebSourceDiffQuery {
            val fields = linkedMapOf<String, String>()
            if (rawQuery.isNullOrEmpty() || rawQuery.length > 1024) invalid()
            for (part in rawQuery.split('&')) {
                val split = part.indexOf('=')
                if (split < 1) invalid()
                val key = part.substring(0, split)
                val value = part.substring(split + 1)
                if (key !in keys || key in fields || !value.matches(ID)) invalid()
                fields[key] = value
            }
            val baseRun = fields["baseRunId"] ?: invalid()
            val baseRevision = fields["baseRevisionId"] ?: invalid()
            fields["baseFileId"]?.let(::revisionSourceFileIndex)
            fields["headFileId"]?.let(::revisionSourceFileIndex)
            if ("baseFileId" in keys && fields["baseFileId"] == null && fields["headFileId"] == null) invalid()
            val limit = fields["limit"]?.let { if (!it.matches(Regex("[1-9][0-9]{0,2}"))) invalid(); it.toInt() } ?: 50
            if (limit !in 1..200) invalid()
            val hunk = fields["hunk"]?.let { if (!it.matches(Regex("0|[1-9][0-9]{0,5}"))) invalid(); it.toInt() } ?: 0
            val pinned = listOf(fields["metadataVersion"], fields["baseMetadataVersion"])
            if (pinned.count { it != null } == 1 || pinned.any { it != null && !it.matches(Regex("[a-f0-9]{64}")) }) invalid()
            return WebSourceDiffQuery(baseRun, baseRevision, fields["baseFileId"], fields["headFileId"], limit, fields["cursor"], hunk,
                pinned[0], pinned[1])
        }

        private fun invalid(): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED",
            "Source diffs accept baseRunId and baseRevisionId, with limit (1–200) and cursor for the file list, " +
                "or baseFileId and/or headFileId with an optional hunk offset and an optional pair of metadata versions for one file.")
    }
}

/** A text side of a comparison: LF-separated lines; the final line may lack its terminator. */
internal class WebDiffText(bytes: ByteArray) {
    val lines: List<String>
    val missingFinalNewline: Boolean

    init {
        val text = String(bytes, Charsets.UTF_8)
        val parts = if (text.isEmpty()) emptyList() else text.split('\n')
        missingFinalNewline = text.isNotEmpty() && !text.endsWith('\n')
        lines = if (parts.isNotEmpty() && !missingFinalNewline) parts.dropLast(1) else parts
    }
}

internal enum class WebDiffOp { EQUAL, DELETE, INSERT }

/**
 * Greedy Myers line diff after trimming the common prefix and suffix. Returns one operation per output row, or
 * null when the edit distance exceeds [maximumEdits] or [expired] reports the deadline. Memory is bounded by
 * the retained frontier windows, at most (maximumEdits + 2)^2 integers.
 */
internal fun revisionLineEdits(base: IntArray, head: IntArray, maximumEdits: Int, expired: () -> Boolean): List<WebDiffOp>? {
    var prefix = 0
    while (prefix < base.size && prefix < head.size && base[prefix] == head[prefix]) prefix++
    var suffix = 0
    while (suffix < base.size - prefix && suffix < head.size - prefix &&
        base[base.size - 1 - suffix] == head[head.size - 1 - suffix]) suffix++
    val n = base.size - prefix - suffix; val m = head.size - prefix - suffix
    val middle = ArrayList<WebDiffOp>(n + m)
    if (n == 0 || m == 0) {
        if (n + m > maximumEdits || expired()) return null
        repeat(n) { middle += WebDiffOp.DELETE }; repeat(m) { middle += WebDiffOp.INSERT }
    } else {
        val limit = minOf(n + m, maximumEdits)
        val offset = limit + 1
        val v = IntArray(2 * limit + 3)
        val trace = ArrayList<IntArray>()
        var found = false
        search@ for (d in 0..limit) {
            if (d % 32 == 0 && expired()) return null
            trace += v.copyOfRange(offset - d - 1, offset + d + 2)
            for (k in -d..d step 2) {
                var x = if (k == -d || (k != d && v[offset + k - 1] < v[offset + k + 1])) v[offset + k + 1] else v[offset + k - 1] + 1
                var y = x - k
                while (x < n && y < m && base[prefix + x] == head[prefix + y]) { x++; y++ }
                v[offset + k] = x
                if (x >= n && y >= m) { found = true; break@search }
            }
        }
        if (!found) return null
        var x = n; var y = m
        for (d in trace.indices.reversed()) {
            val window = trace[d]
            fun at(k: Int) = window[k + d + 1]
            val k = x - y
            val previous = if (k == -d || (k != d && at(k - 1) < at(k + 1))) k + 1 else k - 1
            val previousX = if (d == 0) 0 else at(previous)
            val previousY = previousX - previous
            while (x > previousX && y > previousY) { middle += WebDiffOp.EQUAL; x--; y-- }
            if (d > 0) { if (x == previousX) middle += WebDiffOp.INSERT else middle += WebDiffOp.DELETE }
            x = previousX; y = previousY
        }
        while (x > 0 && y > 0) { middle += WebDiffOp.EQUAL; x--; y-- }
        middle.reverse()
    }
    return List(prefix) { WebDiffOp.EQUAL } + middle + List(suffix) { WebDiffOp.EQUAL }
}

/** One diff row with 1-based line numbers on the sides it belongs to. */
internal class WebDiffRow(val op: WebDiffOp, val baseLine: Int?, val headLine: Int?)

/** Contiguous output range with explicit counts of unchanged lines omitted before it. */
internal class WebDiffHunk(val start: Int, val end: Int, val unchangedBefore: Int)

internal fun revisionDiffRows(ops: List<WebDiffOp>): List<WebDiffRow> {
    var baseLine = 0; var headLine = 0
    return ops.map { op ->
        when (op) {
            WebDiffOp.EQUAL -> WebDiffRow(op, ++baseLine, ++headLine)
            WebDiffOp.DELETE -> WebDiffRow(op, ++baseLine, null)
            WebDiffOp.INSERT -> WebDiffRow(op, null, ++headLine)
        }
    }
}

/** Group changes with [context] unchanged rows around each, then split long groups so every row stays reachable. */
internal fun revisionDiffHunks(rows: List<WebDiffRow>, context: Int, maximumRows: Int): List<WebDiffHunk> {
    val groups = ArrayList<Pair<Int, Int>>()
    var index = 0; var previousEnd = 0
    while (index < rows.size) {
        if (rows[index].op == WebDiffOp.EQUAL) { index++; continue }
        val start = maxOf(previousEnd, index - context)
        var last = index; var cursor = index
        while (cursor < rows.size) {
            if (rows[cursor].op != WebDiffOp.EQUAL) last = cursor
            else if (cursor - last > 2 * context) break
            cursor++
        }
        val end = minOf(rows.size, last + context + 1)
        groups += start to end
        previousEnd = end; index = end
    }
    val hunks = ArrayList<WebDiffHunk>()
    var covered = 0
    for ((start, end) in groups) {
        var from = start
        while (from < end) {
            val to = minOf(end, from + maximumRows)
            hunks += WebDiffHunk(from, to, from - covered)
            covered = to; from = to
        }
    }
    return hunks
}

/**
 * Bounded comparisons between two exact persisted candidates of one job. Classification uses recorded digests only;
 * per-file hunks read both bodies through the same digest-checked source reader and are paged by hunk.
 */
internal class WebRevisionSourceDiffs(
    private val snapshot: (String, String, String) -> WebRevisionSourceSnapshot,
    /** Body reader bound to the compared snapshot: the last argument is its expected metadata version. */
    private val content: (String, String, String, String, String) -> WebRevisionSourceContent,
    private val nanoTime: () -> Long = System::nanoTime,
    private val deadlineNanos: Long = DEADLINE_MS * 1_000_000,
    private val maximumEdits: Int = MAXIMUM_EDITS,
) {
    private val secret = ByteArray(32).also(SecureRandom()::nextBytes)
    private val comparing = AtomicBoolean(false)

    private class RevisionPair(val base: WebRevisionSourceSnapshot, val head: WebRevisionSourceSnapshot)

    private fun capture(jobId: String, runId: String, revisionId: String, query: WebSourceDiffQuery): RevisionPair {
        val head = snapshot(jobId, runId, revisionId)
        val base = snapshot(jobId, query.baseRunId, query.baseRevisionId)
        check(head.reference.jobId == jobId && head.reference.runId == runId && head.reference.revisionId == revisionId)
        check(base.reference.jobId == jobId && base.reference.runId == query.baseRunId && base.reference.revisionId == query.baseRevisionId)
        return RevisionPair(base, head)
    }

    private fun JsonObjectBuilder.identities(pair: RevisionPair) {
        val head = pair.head.reference; val base = pair.base.reference
        put("binding", buildJsonObject { put("jobId", head.jobId); put("runId", head.runId); put("revisionId", head.revisionId) })
        put("base", buildJsonObject { put("runId", base.runId); put("revisionId", base.revisionId) })
        put("authority", "recorded-digests")
        put("sourceSha256", head.sourceSha256); put("metadataVersion", pair.head.metadataVersion)
        put("baseSourceSha256", base.sourceSha256); put("baseMetadataVersion", pair.base.metadataVersion)
    }

    private fun fileReference(snapshot: WebRevisionSourceSnapshot, index: Int?): JsonElement = index?.let {
        val file = snapshot.files[it]
        buildJsonObject {
            put("fileId", revisionSourceFileId(snapshot.reference, it, file.evidence.path))
            put("displayName", file.evidence.path); putRevisionSourceFileFacts(file)
        }
    } ?: JsonNull

    fun summary(owner: String, jobId: String, runId: String, revisionId: String, rawQuery: String?): JsonObject {
        val query = WebSourceDiffQuery.parse(rawQuery, setOf("baseRunId", "baseRevisionId", "limit", "cursor"))
        val continuation = query.cursor?.split('_')?.also { parts ->
            if (parts.size != 3 || !parts[0].matches(SHA256) || !parts[1].matches(Regex("[1-9][0-9]{0,5}")) ||
                !parts[2].matches(Regex("[a-f0-9]{32}")) ||
                !MessageDigest.isEqual(signature(owner, jobId, runId, revisionId, query.baseRunId, query.baseRevisionId,
                    query.limit, parts[0], parts[1]).toByteArray(), parts[2].toByteArray())) invalidCursor()
        }
        val pair = capture(jobId, runId, revisionId, query)
        val entries = classifyRevisionSourceDiff(pair.base, pair.head)
        val changed = entries.filter { it.status != WebSourceDiffStatus.UNCHANGED }
        val version = revisionSourceDigest("revision-source-diff-v1\n${pair.base.metadataVersion}\n${pair.head.metadataVersion}\n")
        val offset = continuation?.let { parts ->
            if (parts[0] != version) throw WebAccessDenied(410, "CURSOR_EXPIRED", "A compared revision changed. Refresh the comparison.")
            parts[1].toInt().also { if (it >= changed.size) invalidCursor() }
        } ?: 0
        val items = ArrayList<JsonObject>(query.limit)
        var bytes = 0
        for (entry in changed.subList(offset, minOf(changed.size, offset + query.limit))) {
            val item = buildJsonObject {
                put("status", entry.status.wire)
                put("baseFile", fileReference(pair.base, entry.base)); put("headFile", fileReference(pair.head, entry.head))
            }
            val size = item.toString().toByteArray(Charsets.UTF_8).size + 1
            if (items.isNotEmpty() && bytes + size > 900_000) break
            bytes += size; items += item
        }
        val next = offset + items.size
        return buildJsonObject {
            identities(pair)
            put("renameDetection", "identical-digest")
            put("counts", buildJsonObject {
                for (status in WebSourceDiffStatus.entries) put(status.wire, entries.count { it.status == status })
            })
            put("totalChanged", changed.size); put("items", JsonArray(items))
            put("page", buildJsonObject {
                put("limit", query.limit); put("snapshotVersion", version)
                put("nextCursor", if (next < changed.size) JsonPrimitive("${version}_${next}_" +
                    signature(owner, jobId, runId, revisionId, query.baseRunId, query.baseRevisionId, query.limit, version, next)) else JsonNull)
            })
        }
    }

    /** A hunk offset or patch is meaningful only for the comparison it was observed in; a changed side expires it. */
    private fun requirePinned(pair: RevisionPair, query: WebSourceDiffQuery) {
        if (query.metadataVersion == null) return
        if (query.metadataVersion != pair.head.metadataVersion || query.baseMetadataVersion != pair.base.metadataVersion) {
            throw WebAccessDenied(410, "CURSOR_EXPIRED", "A compared revision changed. Reopen this file comparison from its first change group.")
        }
    }

    /** The classified entry named by both file identities; a pair outside the classification is unavailable. */
    private fun select(pair: RevisionPair, query: WebSourceDiffQuery): WebSourceDiffEntry {
        val base = query.baseFileId?.let { id -> pair.base.files.indices.firstOrNull {
            revisionSourceFileIndex(id) == it && MessageDigest.isEqual(
                revisionSourceFileId(pair.base.reference, it, pair.base.files[it].evidence.path).toByteArray(), id.toByteArray())
        } ?: entryNotFound() }
        val head = query.headFileId?.let { id -> pair.head.files.indices.firstOrNull {
            revisionSourceFileIndex(id) == it && MessageDigest.isEqual(
                revisionSourceFileId(pair.head.reference, it, pair.head.files[it].evidence.path).toByteArray(), id.toByteArray())
        } ?: entryNotFound() }
        return classifyRevisionSourceDiff(pair.base, pair.head).singleOrNull { it.base == base && it.head == head } ?: entryNotFound()
    }

    private class Comparison(val representation: String, val reason: String?, val baseText: WebDiffText?, val headText: WebDiffText?,
        val rows: List<WebDiffRow>, val hunks: List<WebDiffHunk>) {
        /** Rows before index i that belong to each side, so hunk starts cost O(1). */
        val basePrefix = IntArray(rows.size + 1).also { for (i in rows.indices) it[i + 1] = it[i] + if (rows[i].baseLine != null) 1 else 0 }
        val headPrefix = IntArray(rows.size + 1).also { for (i in rows.indices) it[i + 1] = it[i] + if (rows[i].headLine != null) 1 else 0 }
    }

    private fun compare(pair: RevisionPair, entry: WebSourceDiffEntry): Comparison {
        fun none(representation: String, reason: String? = null) = Comparison(representation, reason, null, null, emptyList(), emptyList())
        val files = listOfNotNull(entry.base?.let { pair.base.files[it] }, entry.head?.let { pair.head.files[it] })
        if (entry.status == WebSourceDiffStatus.UNCHANGED || entry.status == WebSourceDiffStatus.RENAMED) return none("identical")
        if (files.any { ProjectFileRole.VIEWABLE !in it.evidence.roles }) return none("not-viewable")
        if (files.any { it.evidence.contentKind != ProjectContentKind.UTF8_TEXT }) return none("binary", "declared-binary")
        if (files.any { (it.sizeBytes ?: 0) > MAXIMUM_FILE_BYTES }) return none("too-large")
        if (!comparing.compareAndSet(false, true)) {
            throw WebAccessDenied(429, "SOURCE_DIFF_BUSY", "Another source comparison is in progress. Try this comparison again later.")
        }
        try {
            fun read(snapshot: WebRevisionSourceSnapshot, index: Int?): ByteArray? = index?.let {
                val ref = snapshot.reference
                // A changed manifest between capture and read is refused rather than mixing two observations.
                val captured = content(ref.jobId, ref.runId, ref.revisionId, revisionSourceFileId(ref, it, snapshot.files[it].evidence.path),
                    snapshot.metadataVersion)
                captured.fallbackReason?.let { reason -> throw Fallback(reason) }
                captured.previewBytes()
            }
            val baseBytes: ByteArray?; val headBytes: ByteArray?
            try {
                baseBytes = read(pair.base, entry.base); headBytes = read(pair.head, entry.head)
            } catch (fallback: Fallback) { return none("binary", fallback.reason) }
            catch (denied: WebAccessDenied) {
                // Manifest-only entries record no size; the reader's own ceiling is reported as an explicit state.
                if (denied.code == "SOURCE_FILE_TOO_LARGE") return none("too-large") else throw denied
            }
            if ((baseBytes?.size ?: 0) > MAXIMUM_FILE_BYTES || (headBytes?.size ?: 0) > MAXIMUM_FILE_BYTES) return none("too-large")
            val baseText = WebDiffText(baseBytes ?: ByteArray(0)); val headText = WebDiffText(headBytes ?: ByteArray(0))
            if (baseText.lines.size > MAXIMUM_LINES || headText.lines.size > MAXIMUM_LINES) return none("too-large")
            val interned = HashMap<String, Int>()
            fun ids(text: WebDiffText) = IntArray(text.lines.size) { index ->
                val terminated = index < text.lines.size - 1 || !text.missingFinalNewline
                interned.getOrPut(text.lines[index] + if (terminated) "\n" else "") { interned.size }
            }
            val started = nanoTime()
            val ops = revisionLineEdits(ids(baseText), ids(headText), maximumEdits) { nanoTime() - started >= deadlineNanos }
                ?: return none("budget-exceeded")
            val rows = revisionDiffRows(ops)
            return Comparison("text", null, baseText, headText, rows, revisionDiffHunks(rows, CONTEXT_LINES, MAXIMUM_HUNK_ROWS))
        } finally { comparing.set(false) }
    }

    private class Fallback(val reason: String) : RuntimeException(null, null, false, false)

    fun file(jobId: String, runId: String, revisionId: String, rawQuery: String?): JsonObject {
        val query = WebSourceDiffQuery.parse(rawQuery, setOf("baseRunId", "baseRevisionId", "baseFileId", "headFileId", "hunk",
            "metadataVersion", "baseMetadataVersion"))
        val pair = capture(jobId, runId, revisionId, query)
        requirePinned(pair, query)
        val entry = select(pair, query)
        val comparison = compare(pair, entry)
        if (comparison.hunks.isNotEmpty() && query.hunk >= comparison.hunks.size || comparison.hunks.isEmpty() && query.hunk != 0) {
            throw WebAccessDenied(416, "SOURCE_DIFF_RANGE_INVALID", "The hunk offset is outside this comparison.")
        }
        val pageHunks = ArrayList<JsonObject>()
        var rows = 0; var bytes = 0
        var position = query.hunk
        while (position < comparison.hunks.size && pageHunks.size < HUNKS_PER_PAGE) {
            val hunk = comparison.hunks[position]
            val size = hunk.end - hunk.start
            if (pageHunks.isNotEmpty() && rows + size > ROWS_PER_PAGE) break
            val lines = ArrayList<JsonObject>(size)
            var hunkBytes = 0
            for (row in comparison.rows.subList(hunk.start, hunk.end)) {
                val text = if (row.baseLine != null) comparison.baseText!!.lines[row.baseLine - 1] else comparison.headText!!.lines[row.headLine!! - 1]
                val shown = displayPrefix(text)
                val missing = if (row.headLine != null) row.headLine == comparison.headText!!.lines.size && comparison.headText.missingFinalNewline
                    else row.baseLine == comparison.baseText!!.lines.size && comparison.baseText.missingFinalNewline
                val line = buildJsonObject {
                    put("kind", when (row.op) { WebDiffOp.EQUAL -> "context"; WebDiffOp.DELETE -> "removed"; WebDiffOp.INSERT -> "added" })
                    put("baseLine", row.baseLine?.let(::JsonPrimitive) ?: JsonNull)
                    put("headLine", row.headLine?.let(::JsonPrimitive) ?: JsonNull)
                    put("text", shown); put("truncated", shown.length < text.length)
                    put("characters", text.length); put("missingFinalNewline", missing)
                }
                // Serialized UTF-8 size, including escapes: multibyte text cannot exceed the response ceiling.
                hunkBytes += line.toString().toByteArray(Charsets.UTF_8).size + 1
                lines += line
            }
            if (pageHunks.isNotEmpty() && bytes + hunkBytes > PAGE_BYTES) break
            val base = comparison.basePrefix; val head = comparison.headPrefix
            pageHunks += buildJsonObject {
                put("baseStart", 1 + base[hunk.start]); put("baseCount", base[hunk.end] - base[hunk.start])
                put("headStart", 1 + head[hunk.start]); put("headCount", head[hunk.end] - head[hunk.start])
                put("unchangedBefore", hunk.unchangedBefore); put("lines", JsonArray(lines))
            }
            rows += size; bytes += hunkBytes; position++
        }
        val unchangedAfter = comparison.hunks.lastOrNull()?.let { comparison.rows.size - it.end } ?: comparison.rows.size
        return buildJsonObject {
            identities(pair)
            put("status", entry.status.wire)
            put("baseFile", fileReference(pair.base, entry.base)); put("headFile", fileReference(pair.head, entry.head))
            put("representation", comparison.representation)
            put("fallbackReason", comparison.reason?.let(::JsonPrimitive) ?: JsonNull)
            put("baseLines", comparison.baseText?.let { JsonPrimitive(it.lines.size) } ?: JsonNull)
            put("headLines", comparison.headText?.let { JsonPrimitive(it.lines.size) } ?: JsonNull)
            put("totalHunks", comparison.hunks.size); put("hunkOffset", query.hunk)
            put("nextHunk", if (position < comparison.hunks.size) JsonPrimitive(position) else JsonNull)
            put("unchangedAfter", if (comparison.representation == "text") JsonPrimitive(unchangedAfter) else JsonNull)
            put("hunks", JsonArray(pageHunks))
            put("patchAvailable", patchAvailable(comparison))
            put("limits", buildJsonObject {
                put("maximumFileBytes", MAXIMUM_FILE_BYTES.toString()); put("maximumLines", MAXIMUM_LINES)
                put("maximumEdits", maximumEdits); put("contextLines", CONTEXT_LINES); put("hunksPerPage", HUNKS_PER_PAGE)
                put("rowsPerPage", ROWS_PER_PAGE); put("lineCharacters", LINE_CHARACTERS)
            })
        }
    }

    /** Complete unified diff of one text comparison; the bounded JSON pages remain the display path. */
    class Patch(val fileName: String, val bytes: ByteArray, val headers: Map<String, String>)

    fun patch(jobId: String, runId: String, revisionId: String, rawQuery: String?): Patch {
        val query = WebSourceDiffQuery.parse(rawQuery, setOf("baseRunId", "baseRevisionId", "baseFileId", "headFileId",
            "metadataVersion", "baseMetadataVersion"))
        val pair = capture(jobId, runId, revisionId, query)
        requirePinned(pair, query)
        val entry = select(pair, query)
        val comparison = compare(pair, entry)
        if (!patchAvailable(comparison)) throw WebAccessDenied(409, "SOURCE_DIFF_NOT_TEXT",
            "This comparison has no text patch. Download both complete files instead.")
        val basePath = entry.base?.let { "a/" + pair.base.files[it].evidence.path } ?: "/dev/null"
        val headPath = entry.head?.let { "b/" + pair.head.files[it].evidence.path } ?: "/dev/null"
        val text = StringBuilder()
        text.append("--- ").append(basePath).append('\n').append("+++ ").append(headPath).append('\n')
        // Display pages split long change groups at 128 rows; a downloaded patch keeps each group whole so it applies
        // with ordinary context rules.
        val groups = ArrayList<WebDiffHunk>()
        for (hunk in comparison.hunks) {
            val previous = groups.lastOrNull()
            if (previous != null && previous.end == hunk.start && hunk.unchangedBefore == 0) groups[groups.size - 1] = WebDiffHunk(previous.start, hunk.end, previous.unchangedBefore)
            else groups += hunk
        }
        for (hunk in groups) {
            val inside = comparison.rows.subList(hunk.start, hunk.end)
            val baseCount = comparison.basePrefix[hunk.end] - comparison.basePrefix[hunk.start]
            val headCount = comparison.headPrefix[hunk.end] - comparison.headPrefix[hunk.start]
            // Unified diff convention: an empty side names the line before the change.
            val baseStart = comparison.basePrefix[hunk.start] + if (baseCount == 0) 0 else 1
            val headStart = comparison.headPrefix[hunk.start] + if (headCount == 0) 0 else 1
            text.append("@@ -").append(baseStart).append(',').append(baseCount).append(" +").append(headStart).append(',').append(headCount).append(" @@\n")
            for (row in inside) {
                val (marker, line, side) = when (row.op) {
                    WebDiffOp.EQUAL -> Triple(' ', row.headLine!!, comparison.headText!!)
                    WebDiffOp.DELETE -> Triple('-', row.baseLine!!, comparison.baseText!!)
                    WebDiffOp.INSERT -> Triple('+', row.headLine!!, comparison.headText!!)
                }
                text.append(marker).append(side.lines[line - 1]).append('\n')
                if (line == side.lines.size && side.missingFinalNewline) text.append("\\ No newline at end of file\n")
            }
        }
        val name = (entry.head?.let { pair.head.files[it] } ?: pair.base.files[entry.base!!]).evidence.path.substringAfterLast('/') + ".diff"
        return Patch(name, text.toString().toByteArray(Charsets.UTF_8), mapOf(
            "X-Decomp-Diff-Authority" to "recorded-digests",
            "X-Decomp-Source-SHA256" to pair.head.reference.sourceSha256,
            "X-Decomp-Base-Source-SHA256" to pair.base.reference.sourceSha256,
            "X-Decomp-Metadata-Version" to pair.head.metadataVersion,
            "X-Decomp-Base-Metadata-Version" to pair.base.metadataVersion,
        ))
    }

    /**
     * A unified patch is offered only when it reproduces the head side: adding or removing an empty file changes
     * existence without any line, which a plain unified diff cannot express.
     */
    private fun patchAvailable(comparison: Comparison) = comparison.representation == "text" && comparison.hunks.isNotEmpty()

    /** Display prefix that never splits a surrogate pair. */
    private fun displayPrefix(text: String): String {
        if (text.length <= LINE_CHARACTERS) return text
        var end = LINE_CHARACTERS
        if (Character.isHighSurrogate(text[end - 1])) end--
        return text.substring(0, end)
    }

    private fun signature(vararg fields: Any): String {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }
        val bytes = mac.doFinal(fields.joinToString("\u0000").toByteArray(Charsets.UTF_8))
        return buildString(32) {
            val hex = "0123456789abcdef"
            for (index in 0 until 16) { val n = bytes[index].toInt() and 255; append(hex[n ushr 4]); append(hex[n and 15]) }
        }
    }

    private fun invalidCursor(): Nothing = throw WebAccessDenied(400, "INVALID_CURSOR",
        "Use a comparison cursor from this session, revision pair and page size, or refresh the first page.")

    private fun entryNotFound(): Nothing = throw WebAccessDenied(404, "SOURCE_DIFF_ENTRY_NOT_FOUND",
        "These files are not a classified change between the selected revisions.")

    companion object {
        const val MAXIMUM_FILE_BYTES = 1L * 1024 * 1024
        const val MAXIMUM_LINES = 50_000
        const val MAXIMUM_EDITS = 2_000
        const val CONTEXT_LINES = 3
        // 128 rows of 1,000 UTF-16 units stay below the 1 MiB response ceiling even when every unit escapes to 6 bytes.
        const val MAXIMUM_HUNK_ROWS = 128
        const val HUNKS_PER_PAGE = 20
        const val ROWS_PER_PAGE = 2_000
        const val PAGE_BYTES = 768 * 1024
        const val LINE_CHARACTERS = 1_000
        const val DEADLINE_MS = 2_000L
        private val SHA256 = Regex("[a-f0-9]{64}")
    }
}
