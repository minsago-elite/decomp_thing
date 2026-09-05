package decompengine.web

import decompengine.jobs.JobStore
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.GeneratedFileEvidence
import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileRole
import decompengine.project.ReconstructionProfile
import decompengine.project.SourceTreeManifest
import decompengine.project.SourceTreeManifestReader
import decompengine.repair.StableRegularFile
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

data class SourceTreeView(
    val files: List<GeneratedFileEvidence>,
    val confidence: JsonObject?,
)

internal class WebSourceEvidence(
    private val store: JobStore,
    profiles: List<ReconstructionProfile>,
) {
    private val profiles = profiles.associateBy(ReconstructionProfile::id)

    init {
        require(profiles.size in 1..16 && this.profiles.size == profiles.size) {
            "web source profiles must be a bounded unique host allowlist"
        }
    }

    fun read(jobId: String): WebSourceSnapshot {
        val input = store.readInput(jobId)
        val manifestSnapshot = store.readArtifact(jobId, MANIFEST_PATH, MAXIMUM_MANIFEST_BYTES)
        val manifestDocument = OracleJson.parse(manifestSnapshot.bytes, JSON_LIMITS) as? JsonObject
            ?: throw IllegalArgumentException("source manifest must be an object")
        val profileId = manifestDocument["profileId"]?.jsonPrimitive?.content
        val profile = profiles[profileId] ?: throw IllegalArgumentException("source profile is not admitted by this host")
        val manifest = SourceTreeManifestReader.parse(manifestDocument.toString(), profile)
        require(manifest.inputSha256 == input.sha256) { "source manifest belongs to a different uploaded input" }
        require(manifest.files.size <= 4096) { "source manifest exceeds the file-count bound" }
        var total = manifestSnapshot.bytes.size.toLong()
        val files = manifest.files.associate { entry ->
            val remaining = MAXIMUM_TOTAL_BYTES - total
            require(remaining > 0L) { "source tree exceeds its aggregate read bound" }
            val snapshot = store.readArtifact(jobId, "reports/source-tree/${entry.path}", minOf(MAXIMUM_SOURCE_BYTES, remaining))
            require(snapshot.sha256 == entry.sha256) { "source file differs from its manifest: ${entry.path}" }
            total += snapshot.bytes.size
            entry.path to snapshot
        }
        fun requireSame(expected: StableRegularFile, current: StableRegularFile) {
            require(expected.sha256 == current.sha256 && expected.identity == current.identity) {
                "source evidence changed during observation"
            }
        }
        manifest.files.forEach { entry ->
            requireSame(files.getValue(entry.path), store.readArtifact(jobId, "reports/source-tree/${entry.path}", MAXIMUM_SOURCE_BYTES))
        }
        requireSame(manifestSnapshot, store.readArtifact(jobId, MANIFEST_PATH, MAXIMUM_MANIFEST_BYTES))
        requireSame(input, store.readInput(jobId))
        return WebSourceSnapshot(manifest, manifestDocument, files)
    }

    companion object {
        private const val MANIFEST_PATH = "reports/source-tree/source_tree_manifest.json"
        private const val MAXIMUM_MANIFEST_BYTES = 1024L * 1024
        private const val MAXIMUM_SOURCE_BYTES = 4L * 1024 * 1024
        private const val MAXIMUM_TOTAL_BYTES = 64L * 1024 * 1024
        internal val JSON_LIMITS = StrictJsonLimits(
            maximumInputBytes = MAXIMUM_MANIFEST_BYTES.toInt(),
            maximumCanonicalBytes = MAXIMUM_MANIFEST_BYTES.toInt(),
            maximumDepth = 32,
            maximumNodes = 100_000,
            maximumStringBytes = 64 * 1024,
            maximumTotalStringBytes = MAXIMUM_MANIFEST_BYTES.toInt(),
        )
    }
}

internal class WebSourceSnapshot(
    private val manifest: SourceTreeManifest,
    val manifestDocument: JsonObject,
    private val files: Map<String, StableRegularFile>,
) {
    private val viewable = manifest.files.filter {
        ProjectFileRole.VIEWABLE in it.roles && it.contentKind == ProjectContentKind.UTF8_TEXT
    }

    val confidence: JsonObject? = viewable.singleOrNull { it.path == "reports/confidence.json" }?.let {
        runCatching { OracleJson.parse(files.getValue(it.path).bytes, WebSourceEvidence.JSON_LIMITS) as? JsonObject }.getOrNull()
    }

    fun view(): SourceTreeView = SourceTreeView(viewable, confidence)

    fun text(relative: String): String {
        require(viewable.any { it.path == relative }) { "source file is not declared as viewable UTF-8 text" }
        return try {
            StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(files.getValue(relative).bytes)).toString()
        } catch (_: java.nio.charset.CharacterCodingException) {
            throw IllegalArgumentException("source file is not valid UTF-8 text")
        }
    }
}
