package decompengine.web

import decompengine.jobs.AgentProgressJournal
import kotlinx.serialization.json.*
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Stateless bounded polling over bytes read through the caller's authenticated artifact boundary. */
internal class WebProgressPages {
    private val secret = ByteArray(32).also(SecureRandom()::nextBytes)
    private val epoch = ByteArray(8).also(SecureRandom()::nextBytes).hex()
    internal data class Boundary(val throughCursor: String?, val throughSequence: String?, val oldestCursor: String?,
        val nextSequence: String, val queueDropped: String, val historyDropped: String)

    fun boundary(owner: String, jobId: String, runId: String, bytes: ByteArray): Boundary {
        val journal = decode(bytes)
        val records = journal.getValue("events").jsonArray.map { it.jsonObject }
        return Boundary(records.lastOrNull()?.let { token(owner, jobId, runId, it, "s", journal.getValue("nextSequence").jsonPrimitive.long - 1) },
            records.lastOrNull()?.let { (journal.getValue("nextSequence").jsonPrimitive.long - 1).toString() },
            records.firstOrNull()?.let { token(owner, jobId, runId, it, "b") },
            journal.getValue("nextSequence").jsonPrimitive.content, journal.getValue("queueDropped").jsonPrimitive.content,
            journal.getValue("historyDropped").jsonPrimitive.content)
    }

    fun page(owner: String, jobId: String, runId: String, bytes: ByteArray, rawQuery: String?): JsonObject {
        if (rawQuery != null && rawQuery.split('&').any { it.substringBefore('=') !in setOf("limit", "cursor") }) {
            throw WebAccessDenied(422, "VALIDATION_FAILED", "Progress pages accept only limit and cursor.")
        }
        val (query, cursor) = WebJobQuery.parse(rawQuery)
        val journal = decode(bytes)
        val records = journal.getValue("events").jsonArray.map { it.jsonObject }
        var expected = 0L
        val start = if (cursor == null) 0 else {
            val parts = cursor.split('_')
            if (parts.size != 7 || parts[0] != "p1" || !parts[1].matches(Regex("[a-f0-9]{16}")) ||
                parts[2] !in setOf("a", "b", "s") || !parts[3].matches(Regex("0|[1-9][0-9]{0,18}")) ||
                !parts[4].matches(Regex("0|[1-9][0-9]{0,18}")) ||
                !parts[5].matches(Regex("[a-f0-9]{32}")) || !parts[6].matches(Regex("[a-f0-9]{32}"))) invalid()
            if (parts[1] != epoch) gap()
            val signed = parts.take(6).joinToString("_")
            if (!MessageDigest.isEqual(signature(owner, jobId, runId, signed).toByteArray(), parts[6].toByteArray())) invalid()
            val sequence = parts[3].toLongOrNull() ?: invalid()
            val index = records.indexOfFirst { it.getValue("sequence").jsonPrimitive.long == sequence }
            if (index < 0 || digest(records[index]) != parts[5]) gap()
            val position = parts[4].toLongOrNull() ?: invalid()
            if (position < sequence || (parts[2] != "s" && position != sequence) || position == Long.MAX_VALUE) invalid()
            expected = position + if (parts[2] == "b") 0 else 1
            if (parts[2] == "s") records.indexOfFirst { it.getValue("sequence").jsonPrimitive.long >= expected }
                .let { if (it < 0) records.size else it }
            else index + if (parts[2] == "a") 1 else 0
        }
        val items = mutableListOf<JsonObject>()
        var nextCursor = cursor
        var offset = start
        var bytesUsed = 512 // Reserve envelope/cursor overhead below the one-MiB response ceiling.
        while (offset < records.size && items.size < query.limit) {
            val record = records[offset]
            if (record.getValue("sequence").jsonPrimitive.long != expected) gap()
            val eventCursor = token(owner, jobId, runId, record, "a")
            val event = try { webProgressObservation(jobId, runId, eventCursor, record) }
                catch (_: Exception) { unavailable() }
            val size = event.toString().toByteArray(Charsets.UTF_8).size + 1
            if (bytesUsed + size > 1_048_000) break
            items += event; bytesUsed += size; nextCursor = eventCursor; expected++; offset++
        }
        if (offset == records.size && expected != journal.getValue("nextSequence").jsonPrimitive.long) gap()
        return buildJsonObject {
            put("items", JsonArray(items)); put("nextCursor", nextCursor?.let(::JsonPrimitive) ?: JsonNull)
            put("hasMore", offset < records.size)
        }
    }

    private fun decode(bytes: ByteArray): JsonObject = try { AgentProgressJournal.decode(bytes) }
        catch (_: Exception) { unavailable() }
    private fun token(owner: String, jobId: String, runId: String, record: JsonObject, mode: String, position: Long = record.getValue("sequence").jsonPrimitive.long): String {
        val prefix = "p1_${epoch}_${mode}_${record.getValue("sequence").jsonPrimitive.content}_${position}_${digest(record)}"
        return "${prefix}_${signature(owner, jobId, runId, prefix)}"
    }
    private fun signature(owner: String, jobId: String, runId: String, prefix: String): String {
        require(listOf(owner, jobId, runId).all { it.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")) })
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }
        return mac.doFinal(listOf(owner, jobId, runId, prefix).joinToString("\u0000").toByteArray(Charsets.UTF_8)).take(16).toByteArray().hex()
    }
    private fun digest(record: JsonObject) = MessageDigest.getInstance("SHA-256")
        .digest(record.toString().toByteArray(Charsets.UTF_8)).take(16).toByteArray().hex()
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
    private fun invalid(): Nothing = throw WebAccessDenied(400, "INVALID_CURSOR", "Use a progress cursor from this session, job and attempt.")
    private fun gap(): Nothing = throw WebAccessDenied(410, "PROGRESS_GAP", "Progress history changed or contains omitted events. Read a fresh snapshot before resuming.")
    private fun unavailable(): Nothing = throw WebAccessDenied(503, "PROGRESS_UNAVAILABLE", "The retained progress journal could not be read completely.")
}
