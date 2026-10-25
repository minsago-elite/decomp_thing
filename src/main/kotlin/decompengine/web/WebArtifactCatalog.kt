package decompengine.web

import decompengine.jobs.WorkflowAttempt
import decompengine.repair.StableFileDigest
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.*

/** Fixed attempt artifact families. No request supplies a path; each family names exactly one retained file. */
internal enum class WebArtifactFamily(
    val code: String, val wire: String, val path: String, val displayName: String,
    val mediaType: String, val role: String, val revisionBound: Boolean,
) {
    EXPLORATION("exploration", "exploration-report", "exploration.json", "exploration.json", "application/json", "raw-evidence", false),
    PROGRESS("progress", "progress-journal", decompengine.jobs.AgentProgressJournal.FILE_NAME,
        decompengine.jobs.AgentProgressJournal.FILE_NAME, "application/json", "raw-evidence", false),
    MANIFEST("manifest", "source-manifest", "source-tree/source_tree_manifest.json", "source_tree_manifest.json", "application/json", "source", true),
    CONTRACT("contract", "build-contract", "source-tree/reports/build_contract.json", "build_contract.json", "application/json", "source", true),
    ARCHIVE("archive", "source-archive", "source-tree.zip", "source-tree.zip", "application/zip", "archive", true);

    companion object {
        fun forCode(code: String): WebArtifactFamily? = entries.singleOrNull { it.code == code }
    }
}

/** Store access used by the catalog and content reader; implementations authorize the job/attempt first. */
internal interface WebArtifactStore {
    fun attempts(jobId: String): List<WorkflowAttempt>
    fun present(jobId: String, runId: String, path: String): Boolean
    fun stream(jobId: String, runId: String, path: String, declaredSize: (Long) -> Unit,
        consume: (ByteArray, Int) -> Unit, cancellationCheck: () -> Unit): StableFileDigest
    /** Manifest and build-contract digests that were cross-checked against the persisted candidate, or null. */
    fun revisionCommitments(jobId: String, runId: String, revisionId: String): Pair<String, String>?
}

internal class WebArtifactTooLarge : RuntimeException("artifact exceeds the catalog byte ceiling")

/** One resolved artifact identity: the attempt, its fixed family and the digest bound into the opaque ID. */
internal data class WebArtifactSelection(val jobId: String, val attempt: WorkflowAttempt, val family: WebArtifactFamily, val sha256: String) {
    val artifactId: String get() = webArtifactId(jobId, attempt.runId, family, sha256)
    val revisionId: String? get() = if (family.revisionBound) attempt.candidate?.revisionId else null
}

internal fun webArtifactBinding(jobId: String, runId: String): String =
    WebExplorationArtifact.sha256("$jobId\u0000$runId".toByteArray()).take(32)

internal fun webArtifactId(jobId: String, runId: String, family: WebArtifactFamily, sha256: String): String =
    "${family.code}_${webArtifactBinding(jobId, runId)}_$sha256"

private val ARTIFACT_ID = Regex("([a-z]{1,16})_([a-f0-9]{32})_([a-f0-9]{64})")

internal fun webArtifactUnavailable(): Nothing = throw WebAccessDenied(404, "NOT_FOUND", "The requested artifact is unavailable for this job.")

internal fun webArtifactChanged(): Nothing = throw WebAccessDenied(409, "ARTIFACT_CHANGED",
    "These artifact bytes differ from the listed artifact. Refresh the artifact catalog before downloading.")

/** Resolve an opaque ID against the job's current attempts; it never names a path or another job. */
internal fun resolveWebArtifact(store: WebArtifactStore, jobId: String, artifactId: String): WebArtifactSelection {
    val match = ARTIFACT_ID.matchEntire(artifactId) ?: webArtifactUnavailable()
    val family = WebArtifactFamily.forCode(match.groupValues[1]) ?: webArtifactUnavailable()
    val attempt = store.attempts(jobId).singleOrNull { webArtifactBinding(jobId, it.runId) == match.groupValues[2] } ?: webArtifactUnavailable()
    return WebArtifactSelection(jobId, attempt, family, match.groupValues[3])
}

/** Bounded, paged catalog of the fixed families retained for a job, optionally filtered by attempt and revision. */
internal class WebArtifactCatalog(
    private val store: WebArtifactStore,
    private val maximumArtifactBytes: Long = MAXIMUM_ARTIFACT_BYTES,
    private val maximumPageHashBytes: Long = MAXIMUM_PAGE_HASH_BYTES,
) {
    private val secret = ByteArray(32).also(SecureRandom()::nextBytes)

    private data class Filter(val runId: String?, val revisionId: String?, val limit: Int, val cursor: String?)

    private fun parse(rawQuery: String?): Filter {
        fun invalid(): Nothing = throw WebAccessDenied(422, "VALIDATION_FAILED",
            "Artifact catalogs accept an optional runId, a revisionId only together with runId, limit from 1 to 200 and a cursor.")
        val fields = linkedMapOf<String, String>()
        if (!rawQuery.isNullOrEmpty()) {
            if (rawQuery.length > 1024) invalid()
            for (part in rawQuery.split('&')) {
                val split = part.indexOf('=')
                if (split < 1) invalid()
                val key = part.substring(0, split)
                if (key !in setOf("runId", "revisionId", "limit", "cursor") || key in fields) invalid()
                val value = part.substring(split + 1)
                if (!value.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}"))) invalid()
                fields[key] = value
            }
        }
        if (fields.containsKey("revisionId") && !fields.containsKey("runId")) invalid()
        val limit = fields["limit"]?.let { if (!it.matches(Regex("[1-9][0-9]{0,2}"))) invalid(); it.toInt() } ?: 50
        if (limit !in 1..200) invalid()
        return Filter(fields["runId"], fields["revisionId"], limit, fields["cursor"])
    }

    fun page(owner: String, jobId: String, rawQuery: String?, basePath: String): JsonObject {
        val filter = parse(rawQuery)
        val attempts = store.attempts(jobId).sortedWith(compareBy<WorkflowAttempt> { it.createdAt }.thenBy { it.runId })
        val selected = if (filter.runId == null) attempts else listOf(attempts.singleOrNull { it.runId == filter.runId }
            ?: throw WebAccessDenied(404, "RUN_NOT_FOUND", "The requested attempt is unavailable."))
        if (filter.revisionId != null && selected.single().candidate?.revisionId != filter.revisionId) {
            throw WebAccessDenied(404, "REVISION_NOT_FOUND", "The requested revision is not registered for this attempt.")
        }
        val families = WebArtifactFamily.entries.filter { filter.revisionId == null || it.revisionBound }
        val candidates = selected.flatMap { attempt -> families.map { attempt to it } }
        // Changes to the attempt set or a candidate revision expire continuations explicitly.
        val version = WebExplorationArtifact.sha256(("artifact-catalog-v1\u0000" + selected.joinToString("\u0000") {
            "${it.runId}\u0001${it.candidate?.revisionId.orEmpty()}" }).toByteArray())
        val offset = filter.cursor?.let { cursor ->
            val parts = cursor.split('_')
            if (parts.size != 3 || !parts[0].matches(Regex("[a-f0-9]{64}")) || !parts[1].matches(Regex("[1-9][0-9]{0,5}")) ||
                !parts[2].matches(Regex("[a-f0-9]{32}")) ||
                !MessageDigest.isEqual(signature(owner, jobId, filter.runId.orEmpty(), filter.revisionId.orEmpty(), filter.limit, parts[0], parts[1]).toByteArray(),
                    parts[2].toByteArray())) invalidCursor()
            if (parts[0] != version) throw WebAccessDenied(410, "CURSOR_EXPIRED", "The attempt set changed. Refresh the artifact catalog.")
            parts[1].toInt().also { if (it >= candidates.size) invalidCursor() }
        } ?: 0
        val items = ArrayList<JsonObject>(filter.limit)
        val commitments = HashMap<String, Pair<String, String>?>()
        var position = offset; var hashed = 0L; var unavailable = 0
        // Each page inspects at most 200 candidates, so unavailable counts and work stay bounded too.
        while (position < candidates.size && items.size < filter.limit && position - offset < MAXIMUM_PAGE_CANDIDATES) {
            val (attempt, family) = candidates[position]
            if (!store.present(jobId, attempt.runId, family.path)) { position++; continue }
            var size = -1L
            var consumed = 0L
            val digest = try {
                store.stream(jobId, attempt.runId, family.path, { declared ->
                    if (declared > maximumArtifactBytes) throw WebArtifactTooLarge()
                    // Keep at least one hash per page so every continuation advances.
                    if (hashed > 0 && hashed + declared > maximumPageHashBytes) throw PageBudget()
                    size = declared
                }, { _, count -> consumed += count }, {})
            } catch (_: PageBudget) { break }
            catch (failure: Exception) {
                if (failure is WebAccessDenied) throw failure
                // A read that fails late still did its hashing work; charge it so unstable files cannot bypass the budget.
                hashed += consumed; unavailable++; position++; continue
            }
            check(digest.size == size)
            hashed += consumed; position++
            val selection = WebArtifactSelection(jobId, attempt, family, digest.sha256)
            val verified = selection.revisionId?.let { revision ->
                val recorded = commitments.getOrPut(attempt.runId) { store.revisionCommitments(jobId, attempt.runId, revision) }
                when (family) {
                    WebArtifactFamily.MANIFEST -> recorded?.first == digest.sha256
                    WebArtifactFamily.CONTRACT -> recorded?.second == digest.sha256
                    else -> false
                }
            } ?: false
            items += webArtifactDescriptor(selection, digest.size, verified, basePath)
        }
        val next = if (position < candidates.size) "${version}_${position}_" +
            signature(owner, jobId, filter.runId.orEmpty(), filter.revisionId.orEmpty(), filter.limit, version, position) else null
        return buildJsonObject {
            put("binding", buildJsonObject {
                put("jobId", jobId); put("runId", filter.runId?.let(::JsonPrimitive) ?: JsonNull)
                put("revisionId", filter.revisionId?.let(::JsonPrimitive) ?: JsonNull)
            })
            put("catalogedFamilies", JsonArray(families.map { JsonPrimitive(it.wire) }))
            put("unavailableFiles", unavailable)
            put("items", JsonArray(items))
            put("page", buildJsonObject {
                put("limit", filter.limit); put("snapshotVersion", version)
                put("nextCursor", next?.let(::JsonPrimitive) ?: JsonNull)
            })
        }
    }

    /** Detail re-hashes current bytes; the ID's digest must still describe them. */
    fun detail(jobId: String, artifactId: String, basePath: String): JsonObject {
        val selection = resolveWebArtifact(store, jobId, artifactId)
        if (!store.present(jobId, selection.attempt.runId, selection.family.path)) webArtifactUnavailable()
        val digest = try {
            store.stream(jobId, selection.attempt.runId, selection.family.path,
                { if (it > maximumArtifactBytes) throw WebArtifactTooLarge() }, { _, _ -> }, {})
        } catch (failure: Exception) {
            if (failure is WebAccessDenied) throw failure
            throw WebAccessDenied(503, "ARTIFACT_UNAVAILABLE", "The artifact could not be read within its limits.")
        }
        if (digest.sha256 != selection.sha256) webArtifactChanged()
        val verified = selection.revisionId?.let { revision ->
            val recorded = store.revisionCommitments(jobId, selection.attempt.runId, revision)
            (selection.family == WebArtifactFamily.MANIFEST && recorded?.first == digest.sha256) ||
                (selection.family == WebArtifactFamily.CONTRACT && recorded?.second == digest.sha256)
        } ?: false
        return webArtifactDescriptor(selection, digest.size, verified, basePath)
    }

    private class PageBudget : RuntimeException()

    private fun signature(vararg fields: Any): String {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }
        val bytes = mac.doFinal(fields.joinToString("\u0000").toByteArray(Charsets.UTF_8))
        return buildString(32) {
            val hex = "0123456789abcdef"
            for (index in 0 until 16) { val n = bytes[index].toInt() and 255; append(hex[n ushr 4]); append(hex[n and 15]) }
        }
    }

    private fun invalidCursor(): Nothing = throw WebAccessDenied(400, "INVALID_CURSOR",
        "Use an artifact catalog cursor from this session, job, filter and page size, or refresh its first page.")

    companion object {
        const val MAXIMUM_ARTIFACT_BYTES = 4L * 1024 * 1024 * 1024
        const val MAXIMUM_PAGE_HASH_BYTES = 512L * 1024 * 1024
        const val MAXIMUM_PAGE_CANDIDATES = 200
    }
}

internal fun webArtifactDescriptor(selection: WebArtifactSelection, size: Long, revisionVerified: Boolean, basePath: String): JsonObject = buildJsonObject {
    val family = selection.family
    put("artifactId", selection.artifactId)
    put("binding", buildJsonObject {
        put("jobId", selection.jobId); put("runId", selection.attempt.runId)
        put("revisionId", selection.revisionId?.let(::JsonPrimitive) ?: JsonNull)
    })
    put("displayName", family.displayName); put("mediaType", family.mediaType)
    put("sizeBytes", size.toString()); put("sha256", selection.sha256)
    put("contentHref", "${basePath}api/v1/jobs/${selection.jobId}/artifacts/${selection.artifactId}/content")
    put("role", family.role); put("derivedFromArtifactId", JsonNull)
    put("family", family.wire)
    // An observed digest identifies current bytes; only a persisted candidate commitment makes it verified.
    put("verification", if (revisionVerified) "revision-commitment" else "not-verified")
}
