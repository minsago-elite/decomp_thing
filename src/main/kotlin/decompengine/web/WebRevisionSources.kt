package decompengine.web

import decompengine.jobs.WorkflowJobSnapshot
import decompengine.jobs.WorkflowRunState
import decompengine.project.GeneratedFileEvidence
import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileRole
import decompengine.project.SourceTreeManifest
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Collections
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.*

/** A persisted candidate reference, never an attestation of execution or accepted publication. */
internal data class WebRevisionSourceReference(
    val jobId: String, val runId: String, val revisionId: String, val sourceSha256: String, val attemptVersion: String,
)

internal fun selectWebRevisionSource(
    snapshot: WorkflowJobSnapshot, jobId: String, runId: String, revisionId: String,
): WebRevisionSourceReference {
    check(snapshot.jobId == jobId && snapshot.attempts.size <= 1024 && snapshot.attempts.all { it.jobId == jobId } &&
        snapshot.attempts.map { it.runId }.distinct().size == snapshot.attempts.size)
    val attempt = snapshot.attempts.singleOrNull { it.runId == runId && it.jobId == jobId }
        ?: throw WebAccessDenied(404, "RUN_NOT_FOUND", "The requested attempt is unavailable.")
    val candidate = attempt.candidate?.takeIf { it.revisionId == revisionId }
        ?: throw WebAccessDenied(404, "REVISION_NOT_FOUND", "The requested revision is not registered for this attempt.")
    check(attempt.state in setOf(WorkflowRunState.COMPLETED, WorkflowRunState.FAILED,
        WorkflowRunState.CANCELLED, WorkflowRunState.INTERRUPTED) && attempt.startedAt != null && attempt.endedAt != null)
    // An identifier cannot acquire a different source identity through another retained attempt.
    if (snapshot.attempts.any { other ->
        (other.candidate?.let { it.revisionId == revisionId && it.sourceSha256 != candidate.sourceSha256 } == true) ||
            (other.acceptedRevision?.let { it.revisionId == revisionId && it.sourceSha256 != candidate.sourceSha256 } == true)
    }) revisionSourceChanged()
    return WebRevisionSourceReference(jobId, runId, revisionId, candidate.sourceSha256, attempt.version)
}

/**
 * One recorded file of the selected candidate. Canonical build inputs carry the descriptor's committed size and
 * belong to the source revision digest. Other manifest entries (reports, notes) are bound only by the manifest
 * digest; their size is not recorded, so it stays null rather than being observed from the filesystem.
 */
internal class WebRevisionSourceFile(val evidence: GeneratedFileEvidence, val sizeBytes: Long?) {
    val committedInput: Boolean get() = ProjectFileRole.BUILD_INPUT in evidence.roles

    init { require((sizeBytes != null) == committedInput && (sizeBytes == null || sizeBytes >= 0)) }

    /** Wire name of the commitment that binds this entry's digest. */
    val commitment: String get() = if (committedInput) "source-input" else "manifest-digest"
}

/** Shared item projection; size is a decimal string for committed inputs and null for manifest-only entries. */
internal fun JsonObjectBuilder.putRevisionSourceFileFacts(file: WebRevisionSourceFile) {
    put("sizeBytes", file.sizeBytes?.let { JsonPrimitive(it.toString()) } ?: JsonNull)
    put("sha256", file.evidence.sha256)
    put("declaredUtf8Text", file.evidence.contentKind == ProjectContentKind.UTF8_TEXT)
    put("declaredViewable", ProjectFileRole.VIEWABLE in file.evidence.roles)
    put("commitment", file.commitment)
}

/** Canonical source input commitments plus the other manifest entries. Bodies, compiler results and acceptance remain separate. */
internal class WebRevisionSourceSnapshot(
    val reference: WebRevisionSourceReference,
    val manifestSha256: String,
    val descriptorSha256: String,
    files: List<WebRevisionSourceFile>,
) {
    val files: List<WebRevisionSourceFile>
    /** Selector order preserves the original canonical-input indices, independently of display ordering. */
    val identityFiles: List<WebRevisionSourceFile>
    val inputFiles: List<WebRevisionSourceFile>
    private val identityIndices: Map<String, Int>
    val metadataVersion: String

    init {
        require(manifestSha256.matches(SHA256) && descriptorSha256.matches(SHA256) && reference.sourceSha256.matches(SHA256))
        require(files.size in 1..WebSourceCatalogSnapshot.MAXIMUM_FILES && files.any { it.committedInput })
        require(files.map { it.evidence.path }.distinct().size == files.size)
        this.files = Collections.unmodifiableList(files.sortedBy { it.evidence.path })
        inputFiles = Collections.unmodifiableList(this.files.filter { it.committedInput })
        identityFiles = Collections.unmodifiableList(inputFiles + this.files.filterNot { it.committedInput })
        identityIndices = identityFiles.withIndex().associate { it.value.evidence.path to it.index }
        metadataVersion = revisionSourceDigest("revision-source-metadata-v1\n$manifestSha256\n$descriptorSha256\n${reference.sourceSha256}\n")
    }

    /** Unnegotiated v1 responses retain the original canonical-input inventory and non-null size type. */
    fun inventory(includeManifest: Boolean): WebRevisionSourceSnapshot =
        if (includeManifest || files.size == inputFiles.size) this
        else WebRevisionSourceSnapshot(reference, manifestSha256, descriptorSha256, inputFiles)

    fun identityIndex(file: WebRevisionSourceFile): Int = identityIndices.getValue(file.evidence.path)
    fun fileId(file: WebRevisionSourceFile): String = revisionSourceFileId(reference, identityIndex(file), file.evidence.path)

    private companion object { val SHA256 = Regex("[a-f0-9]{64}") }
}

/** Project only schema-supported commitments; no compiler/graph API is invoked by this read. */
internal fun parseWebRevisionSourceInputs(
    reference: WebRevisionSourceReference,
    manifest: SourceTreeManifest,
    manifestSha256: String,
    descriptor: JsonObject,
    descriptorSha256: String,
): WebRevisionSourceSnapshot {
    val schema = descriptor["schemaVersion"] as? JsonPrimitive
    require(schema != null && !schema.isString && schema.intOrNull == 3) // Explicitly reviewed descriptor format.
    val recordedRevision = descriptor["sourceRevisionSha256"] as? JsonPrimitive ?: error("Source input descriptor is invalid.")
    require(recordedRevision.isString)
    if (recordedRevision.content != reference.sourceSha256) revisionSourceChanged()
    val records = descriptor["sourceInputs"] as? JsonArray ?: error("Source input descriptor is invalid.")
    require(records.size in 1..WebSourceCatalogSnapshot.MAXIMUM_FILES)
    val expected = manifest.files.filter { ProjectFileRole.BUILD_INPUT in it.roles }.associateBy { it.path }
    require(expected.isNotEmpty() && expected.values.any { ProjectFileRole.BUILD_DEFINITION in it.roles })
    val paths = ArrayList<String>(records.size)
    val files = records.map { value ->
        val item = value as? JsonObject ?: error("Source input descriptor is invalid.")
        require(item.keys == setOf("path", "bytes", "sha256"))
        fun text(key: String): String = (item[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: error("Source input descriptor is invalid.")
        val path = text("path")
        val evidence = expected[path] ?: revisionSourceChanged()
        if (text("sha256") != evidence.sha256) revisionSourceChanged()
        val size = item["bytes"] as? JsonPrimitive ?: error("Source input descriptor is invalid.")
        require(!size.isString && size.content.matches(Regex("0|[1-9][0-9]{0,18}")))
        val bytes = requireNotNull(size.longOrNull)
        paths += path
        WebRevisionSourceFile(evidence, bytes)
    }
    require(paths == paths.sorted() && paths.distinct().size == paths.size)
    if (paths.toSet() != expected.keys) revisionSourceChanged()
    // Identical to the existing build/repair source preimage, including UTF-16 path length and exact decimal sizes.
    val canonical = files.joinToString("") { "${it.evidence.path.length}:${it.evidence.path}:${it.sizeBytes}:${it.evidence.sha256}\n" }
    if (revisionSourceDigest(canonical) != reference.sourceSha256) revisionSourceChanged()
    // Remaining manifest entries are reachable for inspection; they never enter the source revision digest.
    val recorded = manifest.files.filter { ProjectFileRole.BUILD_INPUT !in it.roles }.map { WebRevisionSourceFile(it, null) }
    return WebRevisionSourceSnapshot(reference, manifestSha256, descriptorSha256, files + recorded)
}

internal fun revisionSourceChanged(): Nothing = throw WebAccessDenied(409, "SOURCE_REVISION_CHANGED",
    "The selected revision could not be captured consistently. Refresh its source listing.")

private fun revisionSourceHex(bytes: ByteArray, length: Int = bytes.size): String = buildString(length * 2) {
    val hex = "0123456789abcdef"
    for (index in 0 until length) {
        val value = bytes[index].toInt() and 255
        append(hex[value ushr 4]); append(hex[value and 15])
    }
}

internal fun revisionSourceDigest(text: String): String = revisionSourceHex(
    MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)))

/**
 * Raw identity construction for one identity-order index. Producers must call [WebRevisionSourceSnapshot.fileId]
 * so every listing, reader, search, diff, structure and archive link uses the same input-first identity order.
 */
internal fun revisionSourceFileId(reference: WebRevisionSourceReference, index: Int, path: String): String =
    "file_${index}_${revisionSourceDigest(listOf("revision-source-file-v1", reference.jobId, reference.runId,
        reference.revisionId, reference.sourceSha256, path).joinToString("\u0000"))}"

/** Explicit opt-in; older clients and servers retain the original v1 inventory. */
internal fun sourceInventoryIncludesManifest(values: List<String>?): Boolean {
    if (values == null) return false
    if (values != listOf("manifest")) throw WebAccessDenied(422, "VALIDATION_FAILED",
        "X-Decomp-Source-Inventory accepts only one manifest value.")
    return true
}

/** Bounded pages over the canonical input set of one actual persisted candidate. */
internal class WebRevisionSourcePages(private val source: (String, String, String) -> WebRevisionSourceSnapshot) {
    private val secret = ByteArray(32).also(SecureRandom()::nextBytes)

    fun page(owner: String, jobId: String, runId: String, revisionId: String, rawQuery: String?, includeManifest: Boolean = false): JsonObject {
        if (rawQuery != null && rawQuery.split('&').any { it.substringBefore('=') !in setOf("limit", "cursor") }) {
            throw WebAccessDenied(422, "VALIDATION_FAILED", "Revision source pages accept only limit and cursor.")
        }
        val (query, cursor) = WebJobQuery.parse(rawQuery)
        val continuation = cursor?.split('_')?.also { parts ->
            if (parts.size != 3 || !parts[0].matches(Regex("[a-f0-9]{64}")) ||
                !parts[1].matches(Regex("[1-9][0-9]{0,4}")) || !parts[2].matches(Regex("[a-f0-9]{32}")) ||
                !MessageDigest.isEqual(signature(owner, jobId, runId, revisionId, includeManifest, query.limit, parts[0], parts[1]).toByteArray(),
                    parts[2].toByteArray())) invalidCursor()
        }
        val snapshot = source(jobId, runId, revisionId).inventory(includeManifest)
        val ref = snapshot.reference
        check(ref.jobId == jobId && ref.runId == runId && ref.revisionId == revisionId)
        val offset = continuation?.let { parts ->
            if (parts[0] != snapshot.metadataVersion) {
                throw WebAccessDenied(410, "CURSOR_EXPIRED", "Revision source metadata changed. Refresh its first page.")
            }
            parts[1].toInt().also { if (it >= snapshot.files.size) invalidCursor() }
        } ?: 0
        val items = ArrayList<JsonObject>(query.limit)
        var bytes = 0
        for (index in offset until minOf(snapshot.files.size, offset + query.limit)) {
            val file = snapshot.files[index]
            val entry = file.evidence
            // Stable across sessions/restarts. Authentication remains separate; the index is never a path selector.
            val fileId = snapshot.fileId(file)
            val item = buildJsonObject {
                put("fileId", fileId); put("displayName", entry.path)
                putRevisionSourceFileFacts(file)
            }
            val itemBytes = item.toString().toByteArray(Charsets.UTF_8).size + 1
            if (bytes + itemBytes > 1_000_000) break
            bytes += itemBytes; items += item
        }
        check(items.isNotEmpty())
        val next = offset + items.size
        return buildJsonObject {
            put("binding", buildJsonObject { put("jobId", jobId); put("runId", runId); put("revisionId", revisionId) })
            put("authority", "source-input-commitments")
            put("sourceSha256", ref.sourceSha256); put("manifestSha256", snapshot.manifestSha256)
            put("descriptorSha256", snapshot.descriptorSha256); put("metadataVersion", snapshot.metadataVersion)
            put("totalFiles", snapshot.files.size); put("items", JsonArray(items))
            put("page", buildJsonObject {
                put("limit", query.limit); put("snapshotVersion", snapshot.metadataVersion)
                put("nextCursor", if (next < snapshot.files.size) JsonPrimitive(
                    "${snapshot.metadataVersion}_${next}_${signature(owner, jobId, runId, revisionId, includeManifest, query.limit, snapshot.metadataVersion, next)}"
                ) else JsonNull)
            })
        }
    }

    private fun signature(vararg fields: Any): String {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }
        return revisionSourceHex(mac.doFinal(fields.joinToString("\u0000").toByteArray(Charsets.UTF_8)), 16)
    }

    private fun invalidCursor(): Nothing = throw WebAccessDenied(400, "INVALID_CURSOR",
        "Use a revision source cursor from this session, job, run, revision and page size, or refresh the first page.")
}
