package decompengine.web

/** Ephemeral per-session transfer observations. They never authorize admission or replace upload receipts. */
internal class WebUploadProgress(
    private val capacity: Int = 256,
    private val now: () -> Long = System::nanoTime,
) {
    internal data class Snapshot(val uploadId: String, val receivedBytes: Long, val totalBytes: Long?, val state: String, val jobId: String?)
    private data class Entry(var snapshot: Snapshot, var endedAt: Long? = null)
    private val entries = linkedMapOf<Pair<String, String>, Entry>()
    init { require(capacity in 1..256) }

    @Synchronized fun begin(sessionId: String, uploadId: String, totalBytes: Long?): Transfer {
        require(uploadId.matches(Regex("[a-f0-9]{32}")))
        require(totalBytes == null || totalBytes in 0..StreamingMultipartUpload.MAX_REQUEST_BYTES)
        purge()
        val key = sessionId to uploadId
        if (key in entries) throw WebAccessDenied(409, "UPLOAD_ID_REUSED", "Use a fresh progress identity for each transfer.")
        if (entries.size >= capacity) entries.entries.firstOrNull { it.value.endedAt != null }?.let { entries.remove(it.key) }
        if (entries.size >= capacity) throw WebAccessDenied(503, "UPLOAD_PROGRESS_CAPACITY", "Upload progress capacity is unavailable.")
        val entry = Entry(Snapshot(uploadId, 0, totalBytes, "receiving", null))
        entries[key] = entry
        return Transfer(key)
    }
    @Synchronized fun read(sessionId: String, uploadId: String): Snapshot? { purge(); return entries[sessionId to uploadId]?.snapshot }
    private fun purge() { val current = now(); entries.entries.removeIf { it.value.endedAt?.let { end -> current - end >= 120_000_000_000L } == true } }

    inner class Transfer internal constructor(private val key: Pair<String, String>) {
        fun received(bytes: Long) = synchronized(this@WebUploadProgress) {
            val entry = entries[key] ?: return@synchronized
            if (entry.endedAt != null) return@synchronized
            require(bytes in entry.snapshot.receivedBytes..(StreamingMultipartUpload.MAX_REQUEST_BYTES + 1))
            entry.snapshot = entry.snapshot.copy(receivedBytes = bytes)
        }
        fun validating() = synchronized(this@WebUploadProgress) {
            val entry = entries[key] ?: return@synchronized
            if (entry.endedAt == null) entry.snapshot = entry.snapshot.copy(state = "validating")
        }
        fun finish(jobId: String? = null) = synchronized(this@WebUploadProgress) {
            val entry = entries[key] ?: return@synchronized
            if (entry.endedAt != null) return@synchronized
            entry.snapshot = entry.snapshot.copy(state = if (jobId == null) "unconfirmed" else "published", jobId = jobId)
            entry.endedAt = now()
        }
    }
}
