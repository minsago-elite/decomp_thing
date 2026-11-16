package decompengine.web

import decompengine.jobs.ArtifactChangedException
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.GeneratedFileEvidence
import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileRole
import decompengine.project.ReconstructionProfile
import decompengine.project.SourceTreeManifestReader
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.StableFileDigest
import decompengine.repair.StableRegularFile
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Collections
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.*

/** Manifest metadata only: neither captured source bytes nor a registered project revision. */
internal class WebSourceCatalogSnapshot(val manifestSha256: String, files: List<GeneratedFileEvidence>) {
    val files: List<GeneratedFileEvidence>

    init {
        require(manifestSha256.matches(Regex("[a-f0-9]{64}")))
        require(files.size <= MAXIMUM_FILES)
        require(files.map { it.path }.distinct().size == files.size)
        this.files = Collections.unmodifiableList(files.sortedBy { it.path })
    }

    companion object { const val MAXIMUM_FILES = 25_000 }
}

/** Shared bounded capture; file bodies are read only for an explicitly selected committed input. */
internal class WebSourceCatalogEvidence(
    profiles: List<ReconstructionProfile>,
    private val readInput: (String) -> StableRegularFile,
    private val readArtifact: (String, String, Long) -> StableRegularFile,
    private val readInputDigest: ((String) -> StableFileDigest)? = null,
    private val readArtifactDigest: ((String, String, Long) -> StableFileDigest)? = null,
) {
    private val profiles = profiles.associateBy { it.id to it.sha256 }
    private val capturing = AtomicBoolean(false)
    private val searching = AtomicBoolean(false)
    @Volatile private var metadataMemo: MetadataMemo? = null

    private data class MetadataMemo(
        val jobId: String,
        val runId: String,
        val input: StableFileDigest,
        val manifest: StableFileDigest,
        val parsed: decompengine.project.SourceTreeManifest,
        val catalog: WebSourceCatalogSnapshot?,
        val revision: RevisionMemo?,
    )
    private data class RevisionMemo(val reference: WebRevisionSourceReference, val descriptor: StableFileDigest,
        val snapshot: WebRevisionSourceSnapshot)
    private class CaptureContext(val prior: MetadataMemo?, val input: StableFileDigest, val manifest: StableFileDigest) {
        var catalog: WebSourceCatalogSnapshot? = null
        var revision: RevisionMemo? = null
    }

    init { require(profiles.size in 1..16 && this.profiles.size == profiles.size) }

    fun read(jobId: String, runId: String): WebSourceCatalogSnapshot = capture(jobId, runId) { manifest, captured, context ->
        context.prior?.catalog ?: WebSourceCatalogSnapshot(captured.sha256, manifest.files).also { context.catalog = it }
    }

    fun readRevision(reference: WebRevisionSourceReference): WebRevisionSourceSnapshot = capture(reference.jobId, reference.runId) { manifest, captured, context ->
        revision(reference, manifest, captured, context) { it }
    }

    /** Selected metadata only; the source body, private checkpoints and execution receipts are never read. */
    fun readFileMetadata(reference: WebRevisionSourceReference, fileId: String): WebRevisionFileMetadataSnapshot {
        revisionSourceFileIndex(fileId)
        return capture(reference.jobId, reference.runId) { manifest, captured, context ->
            revision(reference, manifest, captured, context) { snapshot ->
                val selected = resolveRevisionSourceFile(snapshot, fileId)
                val profile = profiles.getValue(manifest.profileId to manifest.profileSha256)
                val files = WebRecordedModuleProvenance.evidenceFiles(profile, manifest, selected)
                val recorded = try { files?.let { declarations ->
                    fun read(entry: GeneratedFileEvidence): StableRegularFile {
                        val path = "reports/runs/${reference.runId}/source-tree/${entry.path}"
                        val record = readArtifact(reference.jobId, path, WebRecordedModuleProvenance.MAXIMUM_BYTES.toLong())
                        if (record.bytes.size > WebRecordedModuleProvenance.MAXIMUM_BYTES) {
                            throw RepairBudgetExceededException("Optional generation record exceeds its metadata byte limit.")
                        }
                        val detached = record.copy(bytes = record.bytes.copyOf())
                        if (detached.sha256 != entry.sha256 || WebExplorationArtifact.sha256(detached.bytes) != entry.sha256) revisionSourceChanged()
                        return detached
                    }
                    val plan = read(declarations.plan)
                    val generation = read(declarations.generation)
                    val result = WebRecordedModuleProvenance.project(profile, manifest, selected, plan.bytes, generation.bytes)
                    requireSame(plan, read(declarations.plan))
                    requireSame(generation, read(declarations.generation))
                    result
                } } catch (_: RepairBudgetExceededException) { null }
                WebRevisionFileMetadataSnapshot(snapshot, recorded)
            }
        }
    }

    fun readFile(reference: WebRevisionSourceReference, fileId: String, purpose: WebSourceReadPurpose,
        expectedMetadataVersion: String?, readSource: (String, String, String, Long) -> StableRegularFile): WebRevisionSourceContent =
        capture(reference.jobId, reference.runId) { manifest, captured, context ->
            revision(reference, manifest, captured, context) { snapshot ->
                if (expectedMetadataVersion != null && expectedMetadataVersion != snapshot.metadataVersion) expiredSourceMetadata()
                val file = selectRevisionSourceFile(snapshot, fileId, purpose)
                val content = WebRevisionSourceContent(snapshot, fileId, file,
                    readSource(reference.jobId, reference.runId, file.evidence.path, WebRevisionSourceContent.MAXIMUM_FILE_BYTES))
                content.requireSame(readSource(reference.jobId, reference.runId, file.evidence.path, WebRevisionSourceContent.MAXIMUM_FILE_BYTES))
                content
            }
        }

    /**
     * One bounded search admission. Metadata is captured before and after the scan; each body is selected only from
     * that snapshot's canonical inputs and must match its committed size and SHA-256. Missing bodies are reported as
     * unavailable to the scan; changed bodies or metadata refuse the whole page.
     */
    fun search(reference: WebRevisionSourceReference, readSource: (String, String, String, Long) -> StableRegularFile,
        scan: (WebRevisionSourceSnapshot, (WebRevisionSourceFile) -> ByteArray?) -> JsonObject): JsonObject {
        if (!searching.compareAndSet(false, true)) {
            throw WebAccessDenied(429, "SOURCE_SEARCH_BUSY", "Another source search is in progress. Try this search again later.")
        }
        try {
            val before = readRevision(reference)
            val members = Collections.newSetFromMap(java.util.IdentityHashMap<WebRevisionSourceFile, Boolean>()).apply { addAll(before.files) }
            val result = scan(before) { file ->
                check(file in members)
                val captured = try {
                    readSource(reference.jobId, reference.runId, file.evidence.path, WebRevisionSourceContent.MAXIMUM_FILE_BYTES)
                } catch (failure: Exception) {
                    if (failure is ArtifactChangedException) revisionSourceChanged()
                    if (failure is WebAccessDenied || failure is java.util.concurrent.CancellationException || failure is InterruptedException) throw failure
                    null
                }
                captured?.let { stable ->
                    // The descriptor-bound reader already hashes exactly these captured bytes and
                    // revalidates the file and its path before returning. The search scanner only
                    // reads this array synchronously, so copying and hashing it again adds request-
                    // time allocation without adding a freshness check.
                    if (stable.bytes.size.toLong() != file.sizeBytes || stable.sha256 != file.evidence.sha256) {
                        revisionSourceChanged()
                    }
                    stable.bytes
                }
            }
            if (readRevision(reference).metadataVersion != before.metadataVersion) revisionSourceChanged()
            return result
        } finally { searching.set(false) }
    }

    private fun <T> revision(reference: WebRevisionSourceReference, manifest: decompengine.project.SourceTreeManifest,
        captured: StableRegularFile, context: CaptureContext, project: (WebRevisionSourceSnapshot) -> T): T {
        val path = "reports/runs/${reference.runId}/source-tree/reports/build_contract.json"
        val descriptorStart = artifactDigest(reference.jobId, path, MAXIMUM_MANIFEST_BYTES)
        val prior = context.prior?.takeIf {
            it.jobId == reference.jobId && it.runId == reference.runId && it.input == context.input &&
                it.manifest == context.manifest && it.revision?.reference == reference &&
                it.revision.descriptor == descriptorStart
        }?.revision
        val snapshot = prior?.snapshot ?: run {
            val descriptor = readArtifact(reference.jobId, path, MAXIMUM_MANIFEST_BYTES)
            if (descriptorStart != digestOf(descriptor)) revisionSourceChanged()
            require(descriptor.bytes.size.toLong() <= MAXIMUM_MANIFEST_BYTES)
            val document = OracleJson.parse(descriptor.bytes, JSON_LIMITS) as? JsonObject
                ?: throw IllegalArgumentException("Source input descriptor is invalid.")
            parseWebRevisionSourceInputs(reference, manifest, captured.sha256, document, descriptor.sha256)
        }
        val result = project(snapshot)
        if (descriptorStart != artifactDigest(reference.jobId, path, MAXIMUM_MANIFEST_BYTES)) revisionSourceChanged()
        context.revision = RevisionMemo(reference, descriptorStart, snapshot)
        return result
    }

    private fun <T> capture(jobId: String, runId: String,
        project: (decompengine.project.SourceTreeManifest, StableRegularFile, CaptureContext) -> T): T {
        if (!capturing.compareAndSet(false, true)) {
            throw WebAccessDenied(429, "SOURCE_CATALOG_BUSY", "Another source metadata capture is in progress. Try this read again later.")
        }
        return try { captured(jobId, runId, project) } finally { capturing.set(false) }
    }

    private fun <T> captured(jobId: String, runId: String,
        project: (decompengine.project.SourceTreeManifest, StableRegularFile, CaptureContext) -> T): T {
        val path = "reports/runs/$runId/source-tree/source_tree_manifest.json"
        canonicalReportSegments(path)
        val input = inputDigest(jobId)
        val manifestStart = artifactDigest(jobId, path, MAXIMUM_MANIFEST_BYTES)
        val prior = metadataMemo?.takeIf {
            it.jobId == jobId && it.runId == runId && it.input == input && it.manifest == manifestStart
        }
        val manifest = prior?.parsed ?: run {
            val captured = readArtifact(jobId, path, MAXIMUM_MANIFEST_BYTES)
            if (manifestStart != digestOf(captured)) sourceCatalogChanged()
            require(captured.bytes.size.toLong() <= MAXIMUM_MANIFEST_BYTES)
            val document = OracleJson.parse(captured.bytes, JSON_LIMITS) as? JsonObject
                ?: throw IllegalArgumentException("Source catalog manifest is invalid.")
            val profileId = (document["profileId"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            val profileSha256 = (document["profileSha256"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            val profile = profiles[profileId to profileSha256]
                ?: throw IllegalArgumentException("Source catalog profile is unavailable.")
            val declaredFiles = document["files"] as? JsonArray
                ?: throw IllegalArgumentException("Source catalog files are invalid.")
            require(declaredFiles.size <= WebSourceCatalogSnapshot.MAXIMUM_FILES)
            SourceTreeManifestReader.parse(document, profile).also {
                require(it.inputSha256 == input.sha256)
            }
        }
        val context = CaptureContext(prior, input, manifestStart)
        val captured = StableRegularFile(ByteArray(0), manifestStart.sha256, manifestStart.identity)
        val result = project(manifest, captured, context)
        val manifestEnd = artifactDigest(jobId, path, MAXIMUM_MANIFEST_BYTES)
        val inputEnd = inputDigest(jobId)
        if (manifestStart != manifestEnd || input != inputEnd) sourceCatalogChanged()
        metadataMemo = MetadataMemo(jobId, runId, input, manifestStart, manifest,
            context.catalog ?: prior?.catalog, context.revision ?: prior?.revision)
        return result
    }

    private fun inputDigest(jobId: String): StableFileDigest = readInputDigest?.invoke(jobId) ?: digestOf(readInput(jobId))
    private fun artifactDigest(jobId: String, path: String, maximum: Long): StableFileDigest =
        readArtifactDigest?.invoke(jobId, path, maximum) ?: digestOf(readArtifact(jobId, path, maximum))

    private fun digestOf(file: StableRegularFile) = StableFileDigest(file.sha256, file.bytes.size.toLong(), file.identity)

    private fun sourceCatalogChanged(): Nothing = throw WebAccessDenied(409, "SOURCE_CATALOG_CHANGED",
        "Source catalog changed during capture. Refresh its first page.")

    private fun requireSame(expected: StableRegularFile, current: StableRegularFile) {
        if (expected.identity != current.identity || expected.sha256 != current.sha256 ||
            !expected.bytes.contentEquals(current.bytes)) {
            throw WebAccessDenied(409, "SOURCE_CATALOG_CHANGED", "Source catalog changed during capture. Refresh its first page.")
        }
    }

    companion object {
        // Separate metadata budget; legacy whole-tree capture retains its existing 1 MiB/4096-file limits.
        const val MAXIMUM_MANIFEST_BYTES = 16L * 1024 * 1024
        private val JSON_LIMITS = StrictJsonLimits(
            maximumInputBytes = MAXIMUM_MANIFEST_BYTES.toInt(),
            maximumCanonicalBytes = MAXIMUM_MANIFEST_BYTES.toInt(),
            maximumDepth = 32,
            maximumNodes = 1_000_000,
            maximumStringBytes = 16 * 1024,
            maximumTotalStringBytes = MAXIMUM_MANIFEST_BYTES.toInt(),
        )
    }
}

/** Stateless flat metadata pages. No source body, full-tree JSON response or retained page cache. */
internal class WebSourceCatalogPages(private val source: (String, String) -> WebSourceCatalogSnapshot) {
    private val secret = ByteArray(32).also(SecureRandom()::nextBytes)
    private val capturing = AtomicBoolean(false)

    fun page(owner: String, jobId: String, runId: String, rawQuery: String?): JsonObject {
        if (!capturing.compareAndSet(false, true)) {
            throw WebAccessDenied(429, "SOURCE_CATALOG_BUSY", "Another source catalog read is in progress. Try this read again later.")
        }
        return try { capturedPage(owner, jobId, runId, rawQuery) } finally { capturing.set(false) }
    }

    private fun capturedPage(owner: String, jobId: String, runId: String, rawQuery: String?): JsonObject {
        if (rawQuery != null && rawQuery.split('&').any { it.substringBefore('=') !in setOf("limit", "cursor") }) {
            throw WebAccessDenied(422, "VALIDATION_FAILED", "Source catalog pages accept only limit and cursor.")
        }
        val (query, cursor) = WebJobQuery.parse(rawQuery)
        val continuation = cursor?.split('_')?.also { parts ->
            if (parts.size != 3 || !parts[0].matches(Regex("[a-f0-9]{64}")) ||
                !parts[1].matches(Regex("[1-9][0-9]{0,4}")) || !parts[2].matches(Regex("[a-f0-9]{32}")) ||
                !MessageDigest.isEqual(signature(owner, jobId, runId, query.limit, parts[0], parts[1]).toByteArray(),
                    parts[2].toByteArray())) invalidCursor()
        }
        val snapshot = source(jobId, runId)
        val offset = continuation?.let { parts ->
            if (parts[0] != snapshot.manifestSha256) {
                throw WebAccessDenied(410, "CURSOR_EXPIRED", "Source catalog changed. Refresh its first page.")
            }
            parts[1].toInt().also { if (it >= snapshot.files.size) invalidCursor() }
        } ?: 0
        val items = ArrayList<JsonObject>(query.limit)
        var bytes = 0
        for (file in snapshot.files.subList(offset, minOf(snapshot.files.size, offset + query.limit))) {
            val item = buildJsonObject {
                put("fileId", signature(owner, jobId, runId, "file", snapshot.manifestSha256, file.path))
                // Display text only. No request accepts this label as a path or resource identity.
                put("displayName", file.path)
                put("sha256", file.sha256)
                put("declaredUtf8Text", file.contentKind == ProjectContentKind.UTF8_TEXT)
                put("declaredViewable", ProjectFileRole.VIEWABLE in file.roles)
            }
            val itemBytes = item.toString().toByteArray(Charsets.UTF_8).size + 1
            if (bytes + itemBytes > MAXIMUM_ITEM_BYTES) break
            items += item
            bytes += itemBytes
        }
        check(items.isNotEmpty() || snapshot.files.isEmpty())
        val next = offset + items.size
        return buildJsonObject {
            put("binding", buildJsonObject { put("jobId", jobId); put("runId", runId); put("revisionId", JsonNull) })
            put("authority", "manifest-metadata")
            put("manifestSha256", snapshot.manifestSha256)
            put("totalFiles", snapshot.files.size)
            put("items", JsonArray(items))
            put("page", buildJsonObject {
                put("limit", query.limit)
                put("snapshotVersion", snapshot.manifestSha256)
                put("nextCursor", if (next < snapshot.files.size) JsonPrimitive(
                    "${snapshot.manifestSha256}_${next}_${signature(owner, jobId, runId, query.limit, snapshot.manifestSha256, next)}"
                ) else JsonNull)
            })
        }
    }

    private fun signature(vararg fields: Any): String {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }
        val bytes = mac.doFinal(fields.joinToString("\u0000").toByteArray(Charsets.UTF_8))
        return buildString(32) {
            for (index in 0 until 16) {
                val value = bytes[index].toInt() and 255
                append(HEX[value ushr 4]); append(HEX[value and 15])
            }
        }
    }

    private fun invalidCursor(): Nothing = throw WebAccessDenied(400, "INVALID_CURSOR",
        "Use a source catalog cursor from this session, job, run and page size, or refresh its first page.")

    companion object {
        private const val MAXIMUM_ITEM_BYTES = 1_000_000
        private const val HEX = "0123456789abcdef"
    }
}
