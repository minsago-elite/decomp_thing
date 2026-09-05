package decompengine.web

import decompengine.acp.AcpRuntimeClosureLimits
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.deletePrivateTreeContents
import decompengine.jobs.JobStore
import decompengine.oracle.core.OracleJson
import decompengine.project.ArchivalBundleLimits
import decompengine.project.ArchivalBundleVerifier
import decompengine.repair.StableRegularFile
import decompengine.repair.readStableRegularFile
import java.nio.file.Files
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

internal data class WebArchiveSnapshot(
    val bytes: ByteArray,
    val sha256: String,
    val source: SourceTreeView,
    val manifestDocument: JsonObject,
)

internal class WebArchiveEvidence(private val store: JobStore, private val sources: WebSourceEvidence,
    private val readArtifact: (String, String, Long) -> StableRegularFile = store::readArtifact,
) {
    private data class ReadIdentity(val sha256: String, val identity: LinuxFileIdentity)

    fun read(jobId: String, expectedSha256: String? = null, reportPrefix: String = "reports"): WebArchiveSnapshot {
        canonicalReportSegments("$reportPrefix/source-tree.zip")
        require(expectedSha256 == null || expectedSha256.matches(Regex("[a-f0-9]{64}"))) { "archive digest is not canonical" }
        val archive = readArtifact(jobId, "$reportPrefix/source-tree.zip", MAXIMUM_BYTES)
        require(expectedSha256 == null || archive.sha256 == expectedSha256) { "archive differs from the displayed verified digest" }
        val input = identity(store.readInput(jobId))
        val source = sources.read(jobId, reportPrefix).revision()
        val inventory = store.sourceArchiveInventory(jobId, reportPrefix)
        val temporary = Files.createTempDirectory("decomp-web-archive-")
        try {
            val extractedRoot = temporary.resolve("payload")
            val paths = try {
                ArchivalBundleVerifier.extractAndVerifySnapshot(
                    archive.bytes,
                    extractedRoot,
                    ArchivalBundleLimits(maximumEntries = 2048, maximumFileBytes = MAXIMUM_FILE_BYTES, maximumTotalBytes = MAXIMUM_BYTES),
                    source.profile,
                    maximumPathDepth = 30,
                )
            } catch (failure: java.util.zip.ZipException) {
                throw IllegalArgumentException("source archive ZIP is invalid", failure)
            } catch (failure: java.io.EOFException) {
                throw IllegalArgumentException("source archive ZIP is truncated", failure)
            }
            val relatives = paths.map { extractedRoot.relativize(it).toString().replace('\\', '/') }.toSet()
            require(relatives == inventory.filterValues { it.isRegularFile }.keys) {
                "archive payload does not match the complete current source-tree inventory"
            }
            val current = relatives.associateWith { relative ->
                val expected = readStableRegularFile(extractedRoot, relative, MAXIMUM_FILE_BYTES)
                val observed = readArtifact(jobId, "$reportPrefix/source-tree/$relative", MAXIMUM_FILE_BYTES)
                require(expected.sha256 == observed.sha256 && expected.bytes.size == observed.bytes.size &&
                    observed.identity == inventory.getValue(relative)
                ) { "archive payload differs from the current source tree: $relative" }
                identity(observed)
            }
            val contractSnapshot = readArtifact(jobId, "$reportPrefix/source-tree/reports/build_contract.json", MAXIMUM_FILE_BYTES)
            requireSame(current.getValue("reports/build_contract.json"), contractSnapshot)
            val contract = OracleJson.parse(contractSnapshot.bytes).jsonObject
            val artifact = contract.getValue("artifact").jsonObject
            require(artifact.getValue("path").jsonPrimitive.content == "build/reconstructed") { "archive build artifact path is invalid" }
            val executable = readArtifact(jobId, "$reportPrefix/source-tree/build/reconstructed", MAXIMUM_BYTES).let { snapshot ->
                require(artifact.getValue("sha256").jsonPrimitive.content == snapshot.sha256 &&
                    artifact.getValue("bytes").jsonPrimitive.longOrNull == snapshot.bytes.size.toLong()
                ) { "archive build contract differs from the current rebuilt executable" }
                identity(snapshot)
            }
            current.forEach { (relative, snapshot) ->
                requireSame(snapshot, readArtifact(jobId, "$reportPrefix/source-tree/$relative", MAXIMUM_FILE_BYTES))
            }
            require(inventory == store.sourceArchiveInventory(jobId, reportPrefix)) { "archive source inventory changed during verification" }
            require(source.manifestDocument == sources.read(jobId, reportPrefix).manifestDocument) { "archive source revision changed during verification" }
            requireSame(executable, readArtifact(jobId, "$reportPrefix/source-tree/build/reconstructed", MAXIMUM_BYTES))
            requireSame(input, store.readInput(jobId))
            requireSame(identity(archive), readArtifact(jobId, "$reportPrefix/source-tree.zip", MAXIMUM_BYTES))
            return WebArchiveSnapshot(archive.bytes, archive.sha256, source.view.copy(archiveSha256 = archive.sha256), source.manifestDocument)
        } finally {
            LinuxFilesystemSyscalls.openRoot(temporary).use { directory ->
                deletePrivateTreeContents(directory, AcpRuntimeClosureLimits(maximumUserOwnedFileBytes = MAXIMUM_CLEANUP_BYTES, maximumDepth = 64))
            }
            Files.delete(temporary)
        }
    }

    private fun identity(snapshot: StableRegularFile): ReadIdentity = ReadIdentity(snapshot.sha256, snapshot.identity)

    private fun requireSame(expected: ReadIdentity, current: StableRegularFile) {
        require(expected.sha256 == current.sha256 && expected.identity == current.identity) { "archive input changed during verification" }
    }

    companion object {
        const val ARCHIVE_PATH = "reports/source-tree.zip"
        private const val MAXIMUM_BYTES = 64L * 1024 * 1024
        private const val MAXIMUM_FILE_BYTES = 4L * 1024 * 1024
        private const val MAXIMUM_CLEANUP_BYTES = MAXIMUM_BYTES + 2048L * 4096 * 4 + 4096
    }
}
