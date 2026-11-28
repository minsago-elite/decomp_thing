package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.StableFileDigest
import java.util.concurrent.CancellationException

/** Reads one attempt artifact through pinned descriptors without retaining it, as [WebJobService.streamRunArtifact] does. */
internal typealias WebRunArtifactStream = (jobId: String, runId: String, path: String, declaredSize: (Long) -> Unit,
    consume: (ByteArray, Int) -> Unit, cancellationCheck: () -> Unit) -> StableFileDigest

/**
 * Bounded delivery of one manifest-committed structure record. A first pinned pass reproduces the committed digest
 * before any header is sent. The second pass streams through a held-back final chunk that is written only after that
 * pass also reproduces the digest, so a record that changes mid-response is closed short of its declared length.
 * Memory stays at one read chunk; the caller holds the job lease and download admission for the whole delivery.
 */
internal class WebStructureRecordDelivery(private val stream: WebRunArtifactStream) {
    fun send(exchange: HttpExchange, jobId: String, record: WebProgramStructurePages.RecordDownload) {
        val cancellation = webExchangeCancellation(exchange)
        val deadline = WebRequestDeadline.of(exchange)
        var size = -1L
        val verified = try {
            read(jobId, record, { size = it }, { _, _ -> deadline?.renew() }, cancellation)
        } catch (failure: Exception) {
            if (failure is CancellationException || failure is InterruptedException || failure is WebAccessDenied) throw failure
            if (failure is RepairBudgetExceededException) throw WebAccessDenied(413, "RECORD_TOO_LARGE",
                "The structure record exceeds this reader's byte ceiling.")
            recordChanged()
        }
        if (verified.sha256 != record.sha256 || verified.size != size) recordChanged()
        val headers = mapOf("X-Decomp-Content-Verification" to "committed-digest", "X-Decomp-Content-SHA256" to record.sha256)
        sendWebAttachment(exchange, size, record.name, headers) { output ->
            if (size == 0L) return@sendWebAttachment
            val forwarder = WebRangeForwarder(WebByteRange(0, size - 1), { output.write(it) }, { deadline?.renew() })
            val streamed = read(jobId, record, { if (it != size) throw IllegalStateException("structure record changed") },
                forwarder::accept, cancellation)
            // The final bytes are released only after the complete pass reproduced the committed digest.
            if (streamed.sha256 != record.sha256 || streamed.size != size) throw IllegalStateException("structure record changed while streaming")
            check(forwarder.finish() == size)
        }
    }

    private fun read(jobId: String, record: WebProgramStructurePages.RecordDownload, declaredSize: (Long) -> Unit,
        consume: (ByteArray, Int) -> Unit, cancellation: () -> Unit): StableFileDigest =
        stream(jobId, record.runId, record.path, { declared ->
            if (declared > record.maximumBytes) throw RepairBudgetExceededException("structure record exceeds its byte ceiling")
            declaredSize(declared)
        }, consume, cancellation)

    private fun recordChanged(): Nothing = throw WebAccessDenied(409, "STRUCTURE_CHANGED",
        "The selected revision structure records changed. Return to the inventory and read its current records.")
}
