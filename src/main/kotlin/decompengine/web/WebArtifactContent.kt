package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.jobs.WorkflowJobInspection
import java.util.UUID
import java.util.concurrent.CancellationException

/** The job service as an artifact store; every call authorizes the job and attempt before touching storage. */
internal class WebJobArtifactStore(private val jobs: WebJobService) : WebArtifactStore {
    override fun attempts(jobId: String) = when (val inspection = jobs.inspectDurableJob(jobId)) {
        is WorkflowJobInspection.Available -> inspection.snapshot.attempts
        is WorkflowJobInspection.Unavailable -> throw WebAccessDenied(404, "NOT_FOUND", "The requested job is unavailable.")
    }
    override fun present(jobId: String, runId: String, path: String) = jobs.runArtifactPresent(jobId, runId, path)
    override fun stream(jobId: String, runId: String, path: String, declaredSize: (Long) -> Unit,
        consume: (ByteArray, Int) -> Unit, cancellationCheck: () -> Unit) =
        jobs.streamRunArtifact(jobId, runId, path, declaredSize, consume, cancellationCheck)
    override fun revisionCommitments(jobId: String, runId: String, revisionId: String): Pair<String, String>? = try {
        jobs.readRevisionSources(jobId, runId, revisionId).let { it.manifestSha256 to it.descriptorSha256 }
    } catch (failure: Exception) {
        if (failure is InterruptedException || failure is CancellationException) throw failure
        null // Unavailable or inconsistent metadata is reported as not verified, never as verified.
    }
}

/** One satisfiable byte range (inclusive end) of a representation of [size] bytes. */
internal data class WebByteRange(val start: Long, val endInclusive: Long) {
    val length: Long get() = endInclusive - start + 1
}

/**
 * Parse one `bytes` range. Unsupported or malformed syntax returns null so the complete representation is sent
 * (RFC 9110 permits ignoring Range); an unsatisfiable range throws 416.
 */
internal fun parseWebByteRange(header: String, size: Long): WebByteRange? {
    val match = Regex("bytes=(?:(0|[1-9][0-9]{0,18})-(0|[1-9][0-9]{0,18})?|-(0|[1-9][0-9]{0,18}))").matchEntire(header.trim()) ?: return null
    val (first, last, suffix) = match.destructured
    val range = if (suffix.isNotEmpty()) {
        val count = suffix.toLongOrNull() ?: return null
        if (count == 0L || size == 0L) null else WebByteRange(maxOf(0, size - count), size - 1)
    } else {
        val start = first.toLongOrNull() ?: return null
        val end = if (last.isEmpty()) size - 1 else (last.toLongOrNull() ?: return null).coerceAtMost(size - 1)
        if (last.isNotEmpty() && (last.toLongOrNull() ?: return null) < start) return null
        if (start >= size) null else WebByteRange(start, end)
    }
    return range ?: throw WebRangeNotSatisfiable()
}

internal class WebRangeNotSatisfiable : RuntimeException("range is not satisfiable")

/** Bounded concurrent downloads, released after the exchange finishes or fails. */
internal class WebArtifactDownloads(private val maximum: Int = 4, private val perSession: Int = 2) {
    private val active = HashMap<String, Int>()
    private var total = 0

    fun <T> admit(sessionId: String, work: () -> T): T {
        synchronized(this) {
            if (total >= maximum || (active[sessionId] ?: 0) >= perSession) {
                throw WebAccessDenied(429, "DOWNLOAD_LIMIT", "Artifact download capacity is in use. Finish or cancel another download, then retry.")
            }
            total++; active[sessionId] = (active[sessionId] ?: 0) + 1
        }
        try { return work() } finally {
            synchronized(this) {
                total--
                val remaining = (active[sessionId] ?: 1) - 1
                if (remaining == 0) active.remove(sessionId) else active[sessionId] = remaining
            }
        }
    }

    fun activeCount(): Int = synchronized(this) { total }
}

/**
 * Digest-bound artifact delivery. A first pinned pass confirms the listed digest before any header is sent;
 * the second pass streams with a held-back final chunk that is written only after that pass also reproduces the
 * digest and unchanged file identity. A changed or interrupted stream is closed short of its declared length.
 */
internal class WebArtifactContent(private val store: WebArtifactStore,
    private val maximumBytes: Long = WebArtifactCatalog.MAXIMUM_ARTIFACT_BYTES) {

    fun send(exchange: HttpExchange, jobId: String, artifactId: String) {
        val headers = exchange.requestHeaders
        if (headers.keys.any { it.equals("If-Modified-Since", true) || it.equals("If-Unmodified-Since", true) }) {
            throw WebAccessDenied(400, "UNSUPPORTED_HEADER", "Artifact downloads use strong ETag preconditions; date preconditions are unsupported.")
        }
        for (name in listOf("Range", "If-Range", "If-Match", "If-None-Match")) {
            val values = headers[name] ?: continue
            if (values.size != 1 || values.single().length > 1024) throw WebAccessDenied(400, "INVALID_HEADER", "A conditional or range header is repeated or too long.")
        }
        val selection = resolveWebArtifact(store, jobId, artifactId)
        if (!store.present(jobId, selection.attempt.runId, selection.family.path)) webArtifactUnavailable()
        val cancellation = cancellationCheck(exchange)
        val deadline = exchange.getAttribute(WebRequestDeadline.ATTRIBUTE) as? WebRequestDeadline
        var size = -1L
        val observed = try {
            store.stream(jobId, selection.attempt.runId, selection.family.path, {
                if (it > maximumBytes) throw WebArtifactTooLarge()
                size = it
            }, { _, _ -> deadline?.renew() }, cancellation)
        } catch (failure: Exception) {
            if (failure is WebAccessDenied || failure is CancellationException || failure is InterruptedException) throw failure
            if (failure is WebArtifactTooLarge) throw WebAccessDenied(413, "ARTIFACT_TOO_LARGE", "The artifact exceeds the download byte ceiling.")
            throw WebAccessDenied(503, "ARTIFACT_UNAVAILABLE", "The artifact could not be read consistently. Refresh the artifact catalog.")
        }
        if (observed.sha256 != selection.sha256 || observed.size != size) webArtifactChanged()
        val etag = "\"${selection.sha256}\""
        fun matches(value: String) = value.split(',').any { it.trim() == "*" || it.trim() == etag }
        headers.getFirst("If-Match")?.let { if (!matches(it)) throw WebAccessDenied(412, "PRECONDITION_FAILED", "The artifact representation does not match If-Match.") }
        val notModified = headers.getFirst("If-None-Match")?.let(::matches) == true
        val ifRange = headers.getFirst("If-Range")
        val range = if (notModified || exchange.requestMethod == "HEAD" || (ifRange != null && ifRange.trim() != etag)) null else try {
            headers.getFirst("Range")?.let { parseWebByteRange(it, size) }
        } catch (_: WebRangeNotSatisfiable) {
            webApiHeaders(exchange, UUID.randomUUID().toString())
            exchange.responseHeaders.set("Content-Range", "bytes */$size")
            throw WebAccessDenied(416, "RANGE_NOT_SATISFIABLE", "The requested byte range is outside this artifact.")
        }
        val name = java.net.URLEncoder.encode(selection.family.displayName, Charsets.UTF_8).replace("+", "%20").replace("*", "%2A")
        webApiHeaders(exchange, UUID.randomUUID().toString())
        exchange.responseHeaders.set("ETag", etag)
        exchange.responseHeaders.set("Accept-Ranges", "bytes")
        exchange.responseHeaders.set("X-Decomp-Artifact-ID", selection.artifactId)
        exchange.responseHeaders.set("X-Decomp-Content-SHA256", selection.sha256)
        // The listed media type stays metadata; the transport is always an inert attachment.
        exchange.responseHeaders.set("Content-Type", "application/octet-stream")
        exchange.responseHeaders.set("Content-Disposition", "attachment; filename=\"${selection.family.displayName}\"; filename*=UTF-8''$name")
        try {
            if (notModified) { exchange.responseHeaders.remove("Content-Type"); exchange.sendResponseHeaders(304, -1); return }
            val length = range?.length ?: size
            exchange.responseHeaders.set("Content-Length", length.toString())
            range?.let { exchange.responseHeaders.set("Content-Range", "bytes ${it.start}-${it.endInclusive}/$size") }
            val status = if (range == null) 200 else 206
            if (exchange.requestMethod == "HEAD" || length == 0L) { exchange.sendResponseHeaders(status, -1); return }
            exchange.sendResponseHeaders(status, length)
            stream(exchange, selection, size, range ?: WebByteRange(0, size - 1), cancellation)
        } finally { exchange.close() }
    }

    private fun stream(exchange: HttpExchange, selection: WebArtifactSelection, size: Long, range: WebByteRange, cancellation: () -> Unit) {
        val output = exchange.responseBody
        val deadline = exchange.getAttribute(WebRequestDeadline.ATTRIBUTE) as? WebRequestDeadline
        var pending: ByteArray? = null
        var position = 0L
        var written = 0L
        val digest = store.stream(selection.jobId, selection.attempt.runId, selection.family.path, {
            if (it != size) webArtifactChanged()
        }, { buffer, count ->
            val chunkStart = position; val chunkEnd = position + count - 1
            position += count
            val from = maxOf(chunkStart, range.start); val to = minOf(chunkEnd, range.endInclusive)
            if (from <= to) {
                pending?.let { output.write(it); written += it.size; deadline?.renew() }
                pending = buffer.copyOfRange((from - chunkStart).toInt(), (to - chunkStart + 1).toInt())
            }
        }, cancellation)
        // The final bytes are released only after the complete pass reproduced the listed digest and identity.
        if (digest.sha256 != selection.sha256 || digest.size != size) throw IllegalStateException("artifact changed while streaming")
        pending?.let { output.write(it); written += it.size }
        check(written == range.length)
        output.flush()
    }

    private fun cancellationCheck(exchange: HttpExchange): () -> Unit {
        val deadline = exchange.getAttribute(WebRequestDeadline.ATTRIBUTE) as? WebRequestDeadline
        return {
            if (Thread.currentThread().isInterrupted) throw CancellationException("download interrupted")
            if (deadline?.expired == true) throw CancellationException("download deadline expired")
        }
    }
}
