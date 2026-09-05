package decompengine.web

import kotlinx.serialization.json.*
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.util.Base64
import java.util.Locale
import java.util.UUID
import java.util.concurrent.Semaphore
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal data class WebJobQuery(
    val search: String = "", val status: String? = null,
    val after: Instant? = null, val before: Instant? = null, val limit: Int = 50,
) {
    companion object {
        fun parse(raw: String?): Pair<WebJobQuery, String?> {
            fun invalid(): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED", "Use known job filters, valid dates and a page limit between 1 and 200.")
            if (raw == null) return WebJobQuery() to null
            if (raw.isEmpty() || raw.length > 4096) invalid()
            val fields = linkedMapOf<String, String>()
            for (part in raw.split('&')) {
                val split = part.indexOf('=')
                if (split < 1) invalid()
                val key = part.substring(0, split)
                if (key !in setOf("search", "status", "createdAfter", "createdBefore", "limit", "cursor") || key in fields) invalid()
                val value = try { URLDecoder.decode(part.substring(split + 1), StandardCharsets.UTF_8) } catch (_: Exception) { invalid() }
                if (value.any { it.code < 32 || it.code == 127 || it == '\uFFFD' }) invalid()
                fields[key] = value
            }
            val limit = fields["limit"]?.let { if (!it.matches(Regex("[1-9][0-9]{0,2}"))) invalid(); it.toInt() } ?: 50
            if (limit !in 1..200) invalid()
            val search = fields["search"].orEmpty()
            if (search.length > 256) invalid()
            val status = fields["status"]
            if (status != null && status !in setOf("uploaded", "queued", "running", "completed", "failed", "cancelled", "interrupted", "unknown")) invalid()
            fun date(key: String): Instant? = fields[key]?.let { value ->
                if (value.length !in 1..40) invalid()
                try { Instant.parse(value) } catch (_: Exception) { invalid() }
            }
            val after = date("createdAfter")
            val before = date("createdBefore")
            if (after != null && before != null && after >= before) invalid()
            val cursor = fields["cursor"]
            if (cursor != null && !cursor.matches(Regex("[A-Za-z0-9_-]{1,128}"))) throw WebAccessDenied(400, "INVALID_CURSOR", "Use a cursor returned by this job collection.")
            return WebJobQuery(search.lowercase(Locale.ROOT), status, after, before, limit) to cursor
        }
    }
}

/** Bounded, process-local collection snapshots. Continuations never scan storage or execute workflows. */
internal class WebJobPages(
    private val source: () -> Sequence<JsonObject>,
    private val now: () -> Long = System::nanoTime,
) {
    private data class Snapshot(val id: String, val owner: String, val query: WebJobQuery,
        val items: List<JsonObject>, val expires: Long, val bytes: Long)
    private val snapshots = linkedMapOf<String, Snapshot>()
    private val admission = Semaphore(1)
    private val secret = ByteArray(32).also(SecureRandom()::nextBytes)
    private val ttl = 120_000_000_000L

    fun page(owner: String, query: WebJobQuery, cursor: String?): JsonObject {
        if (cursor != null) return synchronized(snapshots) {
            val parts = cursor.split('_', limit = 3)
            if (parts.size != 3 || !parts[0].matches(Regex("[a-f0-9]{32}")) || !parts[1].matches(Regex("[1-9][0-9]{0,4}")) ||
                !MessageDigest.isEqual(signature(parts[0], parts[1]).toByteArray(), parts[2].toByteArray())) invalidCursor()
            expire()
            val snapshot = snapshots[parts[0]] ?: throw WebAccessDenied(410, "CURSOR_EXPIRED", "The job snapshot expired. Refresh the collection.")
            if (snapshot.owner != owner || snapshot.query != query) invalidCursor()
            val offset = parts[1].toInt()
            if (offset >= snapshot.items.size || offset % query.limit != 0) invalidCursor()
            response(snapshot, offset)
        }
        if (!admission.tryAcquire()) throw WebAccessDenied(503, "LISTING_BUSY", "Another job snapshot is being collected. Retry this read shortly.")
        try {
            val start = now()
            var bytes = 0L
            var visited = 0
            val items = mutableListOf<JsonObject>()
            for (item in source()) {
                if (++visited > 10_000 || now() - start > 5_000_000_000L) throw WebAccessDenied(503, "LISTING_LIMIT", "The job library exceeds this listing scan budget.")
                val created = try { Instant.parse(item.getValue("createdAt").jsonPrimitive.content) }
                    catch (_: Exception) { throw WebAccessDenied(503, "JOB_RECORD_UNAVAILABLE", "A job has an invalid creation date. Repair its metadata before listing.") }
                if (!item.getValue("displayFilename").jsonPrimitive.content.lowercase(Locale.ROOT).contains(query.search) ||
                    (query.status != null && item.getValue("status").jsonPrimitive.content != query.status) ||
                    (query.after != null && created < query.after) || (query.before != null && created >= query.before)) continue
                val rowBytes = item.toString().toByteArray(StandardCharsets.UTF_8).size
                if (rowBytes > 4096) throw WebAccessDenied(503, "JOB_RECORD_UNAVAILABLE", "A job presentation exceeds its row budget. Repair its metadata before listing.")
                bytes += rowBytes
                if (bytes > 16L * 1024 * 1024) throw WebAccessDenied(503, "LISTING_LIMIT", "The job snapshot exceeds its byte budget. Narrow the filters.")
                items += item
            }
            items.sortWith(compareByDescending<JsonObject> { Instant.parse(it.getValue("createdAt").jsonPrimitive.content) }
                .thenByDescending { it.getValue("jobId").jsonPrimitive.content })
            val snapshot = Snapshot(UUID.randomUUID().toString().replace("-", ""), owner, query, items.toList(), now() + ttl, bytes)
            return synchronized(snapshots) {
                expire()
                if (items.size > query.limit) {
                    while (snapshots.isNotEmpty() && (snapshots.size >= 8 || snapshots.values.sumOf { it.bytes } + bytes > 32L * 1024 * 1024)) {
                        snapshots.remove(snapshots.keys.first())
                    }
                    snapshots[snapshot.id] = snapshot
                }
                response(snapshot, 0)
            }
        } finally { admission.release() }
    }

    private fun expire() { val time = now(); snapshots.entries.removeIf { time - it.value.expires >= 0 } }
    private fun invalidCursor(): Nothing = throw WebAccessDenied(400, "INVALID_CURSOR", "The cursor does not match this session and job query.")
    private fun signature(id: String, offset: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret, "HmacSHA256"))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal("jobs-v1:$id:$offset".toByteArray()))
    }
    private fun response(snapshot: Snapshot, offset: Int): JsonObject {
        val end = minOf(offset + snapshot.query.limit, snapshot.items.size)
        return buildJsonObject {
            put("items", JsonArray(snapshot.items.subList(offset, end)))
            put("page", buildJsonObject {
                put("limit", snapshot.query.limit)
                put("snapshotVersion", snapshot.id)
                put("nextCursor", if (end < snapshot.items.size) JsonPrimitive("${snapshot.id}_${end}_${signature(snapshot.id, end.toString())}") else JsonNull)
            })
        }
    }
}
