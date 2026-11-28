package decompengine.web

import com.sun.net.httpserver.HttpExchange
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.StableFileDigest
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.async.ByteArrayFeeder
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.util.concurrent.CancellationException

/** Reads one attempt artifact through pinned descriptors without retaining it, as [WebJobService.streamRunArtifact] does. */
internal typealias WebRunArtifactStream = (jobId: String, runId: String, path: String, declaredSize: (Long) -> Unit,
    consume: (ByteArray, Int) -> Unit, cancellationCheck: () -> Unit) -> StableFileDigest

/**
 * Bounded delivery of one manifest-committed structure record. A first pinned pass reproduces the committed digest
 * before any header is sent. The second pass streams through a held-back final chunk that is written only after that
 * pass also reproduces the digest, so a record that changes mid-response is closed short of its declared length.
 * Memory stays at one read chunk; the caller holds the job lease and download admission for the whole delivery.
 * The first pass also reads the record's decoded content: a record that contains a value the listener's policy
 * conceals is withheld before any header, so a download never bypasses the aliases of the JSON views.
 */
internal class WebStructureRecordDelivery(private val stream: WebRunArtifactStream) {
    fun send(exchange: HttpExchange, jobId: String, record: WebProgramStructurePages.RecordDownload) {
        val cancellation = webExchangeCancellation(exchange)
        val deadline = WebRequestDeadline.of(exchange)
        val scan = ConfiguredValueScan(WebRedactionPolicy.of(exchange))
        var size = -1L
        val verified = try {
            read(jobId, record, { size = it }, { bytes, count -> deadline?.renew(); scan.accept(bytes, count) }, cancellation)
        } catch (failure: Exception) {
            if (failure is CancellationException || failure is InterruptedException || failure is WebAccessDenied) throw failure
            if (failure is RepairBudgetExceededException) throw WebAccessDenied(413, "RECORD_TOO_LARGE",
                "The structure record exceeds this reader's byte ceiling.")
            recordChanged()
        }
        if (verified.sha256 != record.sha256 || verified.size != size) recordChanged()
        if (scan.finish()) throw WebAccessDenied(409, "RECORD_WITHHELD",
            "This record is withheld from this listener because its content includes a concealed value.")
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

/**
 * Streams a record's content past the listener's configured values: its decoded UTF-8 text, keeping the overlap a value
 * can straddle between chunks, and while the content parses as JSON every name and scalar token, so an escaped value is
 * found too. Without configured values nothing is decoded or parsed.
 */
private class ConfiguredValueScan(private val policy: WebRedactionPolicy) {
    private val active = policy.longestConfiguredValue > 0
    private val overlap = maxOf(0, policy.longestConfiguredValue - 1)
    private val decoder = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPLACE).onUnmappableCharacter(CodingErrorAction.REPLACE)
    private var pending = ByteArray(0)
    private var tail = ""
    private val parser = if (active) WebProgramStructureBuilder.JSON.createNonBlockingByteArrayParser() else null
    private var parsing = active
    private var found = false

    fun accept(bytes: ByteArray, count: Int) {
        if (!active || found) return
        text(decode(bytes, count, end = false))
        if (parsing) tokens { (checkNotNull(parser).nonBlockingInputFeeder as ByteArrayFeeder).feedInput(bytes, 0, count) }
    }

    /** True when a configured value occurred anywhere in the content. */
    fun finish(): Boolean {
        if (!active || found) return found
        text(decode(ByteArray(0), 0, end = true))
        if (parsing) tokens { (checkNotNull(parser).nonBlockingInputFeeder as ByteArrayFeeder).endOfInput() }
        return found
    }

    private fun decode(bytes: ByteArray, count: Int, end: Boolean): String {
        val input = ByteBuffer.allocate(pending.size + count).put(pending).put(bytes, 0, count).flip()
        val output = CharBuffer.allocate(input.remaining() + 2)
        decoder.decode(input, output, end)
        if (end) decoder.flush(output)
        pending = ByteArray(input.remaining()).also { input.get(it) }
        return output.flip().toString()
    }

    private fun text(decoded: String) {
        val window = tail + decoded
        if (policy.containsConfiguredValue(window)) found = true
        tail = window.takeLast(overlap)
    }

    /** Feed the parser, then check every complete token; content that is not JSON leaves the text scan alone. */
    private fun tokens(feed: () -> Unit) {
        val parser = checkNotNull(parser)
        try {
            feed()
            while (!found) {
                val token = parser.nextToken() ?: break
                if (token == JsonToken.NOT_AVAILABLE) break
                val value = when (token) {
                    JsonToken.FIELD_NAME -> parser.currentName()
                    JsonToken.VALUE_STRING, JsonToken.VALUE_NUMBER_INT, JsonToken.VALUE_NUMBER_FLOAT -> parser.text
                    else -> null
                }
                if (value != null && policy.containsConfiguredValue(value)) found = true
            }
        } catch (failure: Exception) {
            if (failure is CancellationException || failure is InterruptedException) throw failure
            parsing = false
        }
    }
}

