package decompengine.web

import decompengine.jobs.WorkflowJobSnapshot
import kotlinx.serialization.json.*
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** No retained page cache: continuations require the same bounded durable job snapshot version. */
internal class WebRunPages(private val source: (String) -> WorkflowJobSnapshot) {
    private val secret = ByteArray(32).also(SecureRandom()::nextBytes)

    fun page(owner: String, jobId: String, rawQuery: String?): JsonObject {
        if (rawQuery != null && rawQuery.split('&').any { it.substringBefore('=') !in setOf("limit", "cursor") }) {
            throw WebAccessDenied(422, "VALIDATION_FAILED", "Attempt pages accept only limit and cursor.")
        }
        val (query, cursor) = WebJobQuery.parse(rawQuery)
        val snapshot = source(jobId)
        check(snapshot.jobId == jobId && snapshot.attempts.size <= 1024)
        val version = digest(snapshot.version)
        val offset = if (cursor == null) 0 else {
            val parts = cursor.split('_')
            if (parts.size != 3 || !parts[0].matches(Regex("[a-f0-9]{32}")) || !parts[1].matches(Regex("[1-9][0-9]{0,3}")) ||
                !MessageDigest.isEqual(signature(owner, jobId, query.limit, parts[0], parts[1]).toByteArray(), parts[2].toByteArray())) invalid()
            if (parts[0] != version) throw WebAccessDenied(410, "CURSOR_EXPIRED", "Attempt history changed. Refresh its first page.")
            parts[1].toInt().also { if (it >= snapshot.attempts.size || it % query.limit != 0) invalid() }
        }
        val items = snapshot.attempts.asReversed().drop(offset).take(query.limit).map(::webRun)
        val next = offset + items.size
        val value = buildJsonObject {
            put("jobId", jobId); put("items", JsonArray(items))
            put("page", buildJsonObject {
                put("limit", query.limit); put("snapshotVersion", snapshot.version)
                put("nextCursor", if (next < snapshot.attempts.size) JsonPrimitive("${version}_${next}_${signature(owner, jobId, query.limit, version, next.toString())}") else JsonNull)
            })
        }
        if (value.toString().toByteArray(Charsets.UTF_8).size > 1_048_000) {
            throw WebAccessDenied(503, "LISTING_LIMIT", "The attempt page exceeds its response budget. Request fewer rows.")
        }
        return value
    }

    private fun digest(value: String) = MessageDigest.getInstance("SHA-256").digest(value.toByteArray()).take(16).joinToString("") { "%02x".format(it) }
    private fun signature(owner: String, jobId: String, limit: Int, version: String, offset: String): String {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }
        // Hex keeps the cursor delimiter unambiguous.
        return mac.doFinal(listOf(owner, jobId, limit.toString(), version, offset).joinToString("\u0000").toByteArray())
            .take(16).joinToString("") { "%02x".format(it) }
    }
    private fun invalid(): Nothing = throw WebAccessDenied(400, "INVALID_CURSOR", "Use an attempt cursor from this session, job and page size, or refresh the first page.")
}
