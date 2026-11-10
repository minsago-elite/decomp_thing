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
    val after: Instant? = null, val before: Instant? = null, val limit: Int = 50, val sort: String = "newest",
    /** Archived jobs are organization only: hidden by default, never removed or changed. */
    val archived: String = "exclude",
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
                if (key !in setOf("search", "status", "createdAfter", "createdBefore", "limit", "cursor", "sort", "archived") || key in fields) invalid()
                val value = try { URLDecoder.decode(part.substring(split + 1), StandardCharsets.UTF_8) } catch (_: Exception) { invalid() }
                if (value.any { it.code < 32 || it.code == 127 || it == '\uFFFD' }) invalid()
                fields[key] = value
            }
            val limit = fields["limit"]?.let { if (!it.matches(Regex("[1-9][0-9]{0,2}"))) invalid(); it.toInt() } ?: 50
            if (limit !in 1..200) invalid()
            val sort = fields["sort"] ?: "newest"
            if (sort !in setOf("newest", "oldest")) invalid()
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
            val archived = fields["archived"] ?: "exclude"
            if (archived !in setOf("exclude", "all", "only")) invalid()
            val cursor = fields["cursor"]
            if (cursor != null && (cursor.length !in 1..128 || !cursor.matches(Regex("[A-Za-z0-9_-]+")))) {
                throw WebAccessDenied(400, "INVALID_CURSOR", "Use a cursor returned by this job collection.")
            }
            return WebJobQuery(search.lowercase(Locale.ROOT), status, after, before, limit, sort, archived) to cursor
        }
    }
}

/** Stable metadata-only identity for the persisted inputs used to build a collection image. */
internal data class WebJobCollectionStamp(
    val digest: String,
    val jobIdsDigest: String,
    val cacheable: Boolean,
    val retainedBytes: Long = 512,
)

/** Compact validated row retained after startup recovery or one complete collection scan. */
internal data class WebJobCollectionRow(
    val item: JsonObject,
    val createdAt: Instant,
    val jobId: String,
    val bytes: Int,
)

/** One-shot startup observation; every request still revalidates its storage stamp before use. */
internal data class WebJobCollectionSeed(
    val version: Long,
    val stamp: WebJobCollectionStamp,
    val rows: List<WebJobCollectionRow>,
    val bytes: Long,
)

private const val DIAGNOSTIC_JOB_COLLECTION_DEADLINE_PROPERTY = "decomp.web.diagnosticJobCollectionDeadlineMillis"
private const val DASHBOARD_SEED_DISABLED_PROPERTY = "decomp.web.dashboardSeedDisabled"
private const val DEFAULT_JOB_COLLECTION_DEADLINE_MILLIS = 5_000L

/** Qualification-only override: available only to the unseeded diagnostic profile, and only shorter than production. */
private fun configuredJobCollectionDeadlineNanos(): Long {
    val raw = System.getProperty(DIAGNOSTIC_JOB_COLLECTION_DEADLINE_PROPERTY)
        ?: return WebJobCollectionDeadline.DEFAULT_BUDGET_NANOS
    require(System.getProperty(DASHBOARD_SEED_DISABLED_PROPERTY) == "true") {
        "$DIAGNOSTIC_JOB_COLLECTION_DEADLINE_PROPERTY requires $DASHBOARD_SEED_DISABLED_PROPERTY=true"
    }
    require(raw.matches(Regex("[1-9][0-9]{0,3}"))) {
        "$DIAGNOSTIC_JOB_COLLECTION_DEADLINE_PROPERTY must be a canonical decimal from 1 through 4999"
    }
    val millis = raw.toLong()
    require(millis in 1 until DEFAULT_JOB_COLLECTION_DEADLINE_MILLIS) {
        "$DIAGNOSTIC_JOB_COLLECTION_DEADLINE_PROPERTY must be less than the 5000 ms production default"
    }
    System.err.println("Web diagnostic job collection deadline: $millis ms (default 5000 ms, dashboard seed disabled)")
    return millis * 1_000_000L
}

/** One admitted scan deadline, also checked by the production source between bounded read units. */
internal class WebJobCollectionDeadline(
    private val started: Long,
    private val budgetNanos: Long = DEFAULT_BUDGET_NANOS,
    private val now: () -> Long,
) {
    init {
        require(budgetNanos in 1..DEFAULT_BUDGET_NANOS) { "Job collection deadline must be between 1 ns and 5 s." }
    }

    companion object {
        const val DEFAULT_BUDGET_NANOS = 5_000_000_000L
    }

    private var expired = false
    fun checkpoint() {
        if (expired || now() - started > budgetNanos) {
            expired = true
            throw WebAccessDenied(503, "LISTING_LIMIT", "The job library exceeds this listing scan budget.")
        }
    }
}

/** Bounded, process-local collection snapshots. Continuations never scan storage or execute workflows. */
internal class WebJobPages(
    private val source: () -> Sequence<JsonObject>,
    private val now: () -> Long = System::nanoTime,
    private val checkpointedSource: ((() -> Unit) -> Sequence<JsonObject>)? = null,
    private val collectionVersion: (() -> Long?)? = null,
    private val collectionStamp: ((Long, () -> Unit) -> WebJobCollectionStamp)? = null,
    private val collectionSeed: (() -> WebJobCollectionSeed?)? = null,
) {
    private val deadlineBudgetNanos = configuredJobCollectionDeadlineNanos()
    private data class CollectionImage(val version: Long, val stamp: WebJobCollectionStamp, val rows: List<WebJobCollectionRow>, val bytes: Long)
    private data class Snapshot(val id: String, val owner: String, val query: WebJobQuery,
        val items: List<JsonObject>, val expires: Long, val bytes: Long)
    private val snapshots = linkedMapOf<String, Snapshot>()
    private val imageLock = Any()
    private var image: CollectionImage? = null
    private val admission = Semaphore(1)
    private val secret = ByteArray(32).also(SecureRandom()::nextBytes)
    private val ttl = 120_000_000_000L
    private val maximumImageBytes = 16L * 1024 * 1024
    private val maximumRetainedBytes = 32L * 1024 * 1024
    /** Retires in-flight first-page publication when an owned mutation invalidates the collection. */
    @Volatile private var generation = 0L

    fun page(owner: String, query: WebJobQuery, cursor: String?): JsonObject =
        pageFirst(owner, query, cursor, 0, WebJobCollectionDeadline(now(), deadlineBudgetNanos, now))

    private fun pageFirst(owner: String, query: WebJobQuery, cursor: String?, retry: Int,
        deadline: WebJobCollectionDeadline): JsonObject {
        if (cursor != null) return synchronized(snapshots) {
            val parts = cursor.split('_', limit = 3)
            if (parts.size != 3 || !parts[0].matches(Regex("[a-f0-9]{32}")) || !parts[1].matches(Regex("0|[1-9][0-9]{0,4}")) ||
                !MessageDigest.isEqual(signature(parts[0], parts[1]).toByteArray(), parts[2].toByteArray())) invalidCursor()
            expire()
            val snapshot = snapshots[parts[0]] ?: throw WebAccessDenied(410, "CURSOR_EXPIRED", "The job snapshot expired. Refresh the collection.")
            if (snapshot.owner != owner || snapshot.query != query) invalidCursor()
            val offset = parts[1].toInt()
            if ((offset != 0 && offset >= snapshot.items.size) || offset % query.limit != 0) invalidCursor()
            response(snapshot, offset)
        }
        // Invalidation retries are still the same HTTP request and share its original allowance.
        deadline.checkpoint()
        val collectedGeneration = generation
        if (!admission.tryAcquire()) {
            if (generation != collectedGeneration && retry < 2) return pageFirst(owner, query, cursor, retry + 1, deadline)
            throw WebAccessDenied(503, "LISTING_BUSY", "Another job snapshot is being collected. Retry this read shortly.")
        }
        var admissionReleasedForRetry = false
        try {
            adoptStartupSeed()
            val scanStartedAtMillis = System.currentTimeMillis()
            val admittedVersion = collectionVersion?.invoke()
            val admittedImage = admittedVersion?.let(::imageForVersion)
            if (admittedImage != null && collectionStamp != null) {
                val stamp = collectionStamp.invoke(scanStartedAtMillis, deadline::checkpoint)
                val finalVersion = collectionVersion.invoke()
                if (admittedVersion == finalVersion && stamp.cacheable && stamp == admittedImage.stamp) {
                    val selected = select(admittedImage, query, deadline)
                    deadline.checkpoint()
                    return createSnapshot(owner, query, selected, deadline, expectedGeneration = collectedGeneration)
                }
                discardImage(admittedImage)
            } else if (admittedVersion == null) {
                synchronized(imageLock) { image = null }
            }
            val beforeScanStamp = if (admittedVersion != null && collectionStamp != null)
                collectionStamp.invoke(scanStartedAtMillis, deadline::checkpoint) else null
            var visited = 0
            var selectedBytes = 0L
            val selectedRows = mutableListOf<WebJobCollectionRow>()
            var imageBytes = 0L
            var imageCacheable = admittedVersion != null && beforeScanStamp?.cacheable == true
            val imageRows = if (imageCacheable) mutableListOf<WebJobCollectionRow>() else null
            for (item in checkpointedSource?.invoke(deadline::checkpoint) ?: source()) {
                if (++visited > 10_000) throw WebAccessDenied(503, "LISTING_LIMIT", "The job library exceeds this listing scan budget.")
                deadline.checkpoint()
                val created = try { Instant.parse(item.getValue("createdAt").jsonPrimitive.content) }
                    catch (_: Exception) { throw WebAccessDenied(503, "JOB_RECORD_UNAVAILABLE", "A job has an invalid creation date. Repair its metadata before listing.") }
                val id = item.getValue("jobId").jsonPrimitive.content
                val rowBytes = item.toString().toByteArray(StandardCharsets.UTF_8).size
                if (rowBytes > 4096) throw WebAccessDenied(503, "JOB_RECORD_UNAVAILABLE", "A job presentation exceeds its row budget. Repair its metadata before listing.")
                val row = WebJobCollectionRow(item, created, id, rowBytes)
                imageRows?.let { rows ->
                    imageBytes += rowBytes
                    if (imageBytes <= maximumImageBytes) rows += row
                    else { rows.clear(); imageCacheable = false }
                }
                if (matches(row, query)) {
                    selectedBytes += row.bytes
                    if (selectedBytes > 16L * 1024 * 1024) throw WebAccessDenied(503, "LISTING_LIMIT", "The job snapshot exceeds its byte budget. Narrow the filters.")
                    selectedRows += row
                }
            }
            deadline.checkpoint() // Empty and fully filtered sources still consume the admitted deadline.
            val order = compareBy<WebJobCollectionRow> { it.createdAt }.thenBy { it.jobId }
            selectedRows.sortWith(if (query.sort == "oldest") order else order.reversed())
            deadline.checkpoint()
            val afterVersion = collectionVersion?.invoke()
            val stamp = if (imageCacheable && admittedVersion != null && afterVersion == admittedVersion && collectionStamp != null)
                collectionStamp.invoke(scanStartedAtMillis, deadline::checkpoint) else null
            val captured = imageRows.orEmpty().sortedWith(order).toList()
            val capturedIdsDigest = jobIdsDigest(captured)
            val pendingImage = if (stamp != null && beforeScanStamp != null && stamp == beforeScanStamp && stamp.cacheable &&
                stamp.jobIdsDigest == capturedIdsDigest &&
                imageBytes + stamp.retainedBytes <= maximumImageBytes) {
                CollectionImage(admittedVersion!!, stamp, captured, imageBytes + stamp.retainedBytes)
            } else null
            return createSnapshot(owner, query, selectedRows to selectedBytes, deadline, pendingImage, updateImage = true, expectedGeneration = collectedGeneration)
        } catch (failure: WebAccessDenied) {
            if (failure.code == "LISTING_BUSY" && generation != collectedGeneration && retry < 2) {
                admissionReleasedForRetry = true
                admission.release()
                return pageFirst(owner, query, cursor, retry + 1, deadline)
            }
            throw failure
        } finally { if (!admissionReleasedForRetry) admission.release() }
    }

    private fun imageForVersion(version: Long): CollectionImage? = synchronized(imageLock) {
        image?.takeIf { it.version == version } ?: run { image = null; null }
    }

    private fun adoptStartupSeed() {
        val provider = collectionSeed ?: return
        val shouldTake = synchronized(imageLock) { image == null }
        if (!shouldTake) return
        val seed = provider() ?: return
        synchronized(imageLock) {
            if (image == null) image = CollectionImage(seed.version, seed.stamp, seed.rows, seed.bytes)
        }
    }

    private fun discardImage(candidate: CollectionImage) = synchronized(imageLock) {
        if (image === candidate) image = null
    }

    private fun jobIdsDigest(rows: List<WebJobCollectionRow>): String = sha256(rows.asSequence().map { it.jobId }.sorted())

    private fun sha256(values: Sequence<String>): String {
        val digest = MessageDigest.getInstance("SHA-256")
        for (value in values) {
            digest.update(value.toByteArray(StandardCharsets.UTF_8))
            digest.update(0.toByte())
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun matches(row: WebJobCollectionRow, query: WebJobQuery): Boolean =
        ((row.item.getValue("displayFilename").jsonPrimitive.content.lowercase(Locale.ROOT).contains(query.search) ||
            (row.item["label"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.lowercase(Locale.ROOT)?.contains(query.search) == true) &&
            run { val archived = (row.item["archived"] as? JsonPrimitive)?.booleanOrNull == true;
                (query.archived == "all" || query.archived == "only" && archived || query.archived == "exclude" && !archived) }) &&
            (query.status == null || row.item.getValue("status").jsonPrimitive.content == query.status) &&
            (query.after == null || row.createdAt >= query.after) && (query.before == null || row.createdAt < query.before)

    private fun select(image: CollectionImage, query: WebJobQuery, deadline: WebJobCollectionDeadline): Pair<List<WebJobCollectionRow>, Long> {
        val rows = mutableListOf<WebJobCollectionRow>()
        var bytes = 0L
        val ordered = if (query.sort == "oldest") image.rows else image.rows.asReversed()
        for (row in ordered) {
            deadline.checkpoint()
            if (!matches(row, query)) continue
            bytes += row.bytes
            if (bytes > 16L * 1024 * 1024) throw WebAccessDenied(503, "LISTING_LIMIT", "The job snapshot exceeds its byte budget. Narrow the filters.")
            rows += row
        }
        return rows to bytes
    }

    private fun createSnapshot(owner: String, query: WebJobQuery, selected: Pair<List<WebJobCollectionRow>, Long>, deadline: WebJobCollectionDeadline,
        pendingImage: CollectionImage? = null, updateImage: Boolean = false, expectedGeneration: Long): JsonObject {
        val (rows, bytes) = selected
        val snapshot = Snapshot(UUID.randomUUID().toString().replace("-", ""), owner, query,
            rows.map(WebJobCollectionRow::item), now() + ttl, bytes)
        return synchronized(snapshots) {
            deadline.checkpoint()
            if (generation != expectedGeneration) throw WebAccessDenied(503, "LISTING_BUSY", "The job library changed during this listing. Retry this read shortly.")
            expire()
            // First pages, including empty results, also need an authenticated return token.
            // Retained query snapshots and the shared image use one byte envelope.
            var retainedImageBytes = synchronized(imageLock) { if (updateImage) pendingImage?.bytes ?: 0L else image?.bytes ?: 0L }
            while (snapshots.isNotEmpty() && (snapshots.size >= 8 || snapshots.values.sumOf { it.bytes } + bytes + retainedImageBytes > maximumRetainedBytes)) {
                snapshots.remove(snapshots.keys.first())
            }
            val dropImage = bytes + retainedImageBytes > maximumRetainedBytes
            if (dropImage) retainedImageBytes = 0
            deadline.checkpoint()
            snapshots[snapshot.id] = snapshot
            if (updateImage) synchronized(imageLock) { image = pendingImage.takeIf { !dropImage } }
            response(snapshot, 0)
        }
    }

    /** A mutation retires retained cursors and prevents a mixed first page from being published. */
    fun invalidate() = synchronized(snapshots) { generation++; snapshots.clear(); synchronized(imageLock) { image = null } }

    private fun expire() { val time = now(); snapshots.entries.removeIf { time - it.value.expires >= 0 } }
    private fun invalidCursor(): Nothing = throw WebAccessDenied(400, "INVALID_CURSOR", "The cursor does not match this session and job query.")
    private fun signature(id: String, offset: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret, "HmacSHA256"))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal("jobs-v1:$id:$offset".toByteArray()))
    }
    private fun pageCursor(snapshot: Snapshot, offset: Int) =
        JsonPrimitive("${snapshot.id}_${offset}_${signature(snapshot.id, offset.toString())}")

    private fun response(snapshot: Snapshot, offset: Int): JsonObject {
        val end = minOf(offset + snapshot.query.limit, snapshot.items.size)
        return buildJsonObject {
            put("items", JsonArray(snapshot.items.subList(offset, end)))
            put("page", buildJsonObject {
                put("limit", snapshot.query.limit)
                put("snapshotVersion", snapshot.id)
                put("nextCursor", if (end < snapshot.items.size) pageCursor(snapshot, end) else JsonNull)
                put("currentCursor", pageCursor(snapshot, offset))
                put("previousCursor", if (offset > 0) pageCursor(snapshot, offset - snapshot.query.limit) else JsonNull)
                put("pageNumber", offset / snapshot.query.limit + 1)
            })
        }
    }
}
