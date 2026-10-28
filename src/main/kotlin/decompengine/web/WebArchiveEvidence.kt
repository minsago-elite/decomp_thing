package decompengine.web

import decompengine.acp.AcpRuntimeClosureLimits
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.deletePrivateTreeContents
import decompengine.jobs.ArtifactChangedException
import decompengine.jobs.JobStore
import decompengine.jobs.JobStoreException
import decompengine.oracle.core.OracleJson
import decompengine.project.ArchivalBundleLimits
import decompengine.project.ArchivalBundleVerifier
import decompengine.project.ReconstructionAdapters
import decompengine.project.checkedTransportLayout
import decompengine.project.requireNormalizedProjectPath
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
    /** Digest of the payload's own build contract, the descriptor that binds the candidate's source digest. */
    val contractSha256: String,
    /** Raw manifest digest checked by the authoritative source observation. */
    val manifestSha256: String,
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
        val sourceSnapshot = sources.read(jobId, reportPrefix)
        val source = sourceSnapshot.revision()
        val adapter = ReconstructionAdapters.resolve(source.profile)
        val buildPolicy = adapter.archiveBuild
        val transport = adapter.archiveBuild.checkedTransportLayout(source.profile)
        val layout = buildPolicy.contractPaths(source.profile)
        requireNormalizedProjectPath(layout.contractPath, "archive build contract path")
        requireNormalizedProjectPath(layout.artifactPath, "archive build artifact path")
        require(layout.contractPath != layout.artifactPath) { "archive build evidence paths are duplicated" }
        // One streamed size/digest receipt per inventoried file, admitted as an unchanged snapshot.
        val receipts = store.sourceArchiveReceipts(jobId, transport, reportPrefix, MAXIMUM_FILE_BYTES, MAXIMUM_BYTES)
        val inventory = receipts.inventory
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
            // Repository metadata never belongs to the deterministic source payload.
            require(relatives.none { relative -> relative.split('/').any { it == ".git" } }) { "archive payload contains repository metadata" }
            require(relatives == inventory.filterValues { it.isRegularFile }.keys) {
                "archive payload does not match the complete current source-tree inventory"
            }
            val current = relatives.associateWith { relative ->
                val expected = readStableRegularFile(extractedRoot, relative, MAXIMUM_FILE_BYTES)
                val observed = receipts.files.getValue(relative)
                require(expected.sha256 == observed.sha256 && expected.bytes.size.toLong() == observed.sizeBytes &&
                    observed.identity == inventory.getValue(relative)
                ) { "archive payload differs from the current source tree: $relative" }
                ReadIdentity(observed.sha256, observed.identity)
            }
            require(current.getValue("source_tree_manifest.json").sha256 == sourceSnapshot.manifestSha256) {
                "archive manifest differs from the checked source manifest"
            }
            val contractSnapshot = revalidate { readArtifact(jobId, "$reportPrefix/source-tree/${layout.contractPath}", MAXIMUM_FILE_BYTES) }
            requireSame(current.getValue(layout.contractPath), contractSnapshot)
            val parsedContract = OracleJson.parse(contractSnapshot.bytes).jsonObject
            val contract = buildPolicy.parseContract(parsedContract, source.profile)
            val artifact = contract.artifact
            require(artifact.getValue("path").jsonPrimitive.content == layout.artifactPath) { "archive build artifact path is invalid" }
            val executable = readArtifact(jobId, "$reportPrefix/source-tree/${layout.artifactPath}", MAXIMUM_BYTES).let { snapshot ->
                require(artifact.getValue("sha256").jsonPrimitive.content == snapshot.sha256 &&
                    artifact.getValue("bytes").jsonPrimitive.longOrNull == snapshot.bytes.size.toLong()
                ) { "archive build contract differs from the current rebuilt executable" }
                identity(snapshot)
            }
            // The first pass already admitted this tree. Unavailability or an inventory/budget
            // refusal on revalidation is a concurrent change, not an initially missing artifact.
            val revalidated = revalidate {
                store.sourceArchiveReceipts(jobId, transport, reportPrefix, MAXIMUM_FILE_BYTES, MAXIMUM_BYTES)
            }
            if (revalidated != receipts) {
                throw ArtifactChangedException("archive source tree changed during verification")
            }
            val manifest = revalidate { sources.read(jobId, reportPrefix) }
            if (sourceSnapshot.manifestSha256 != manifest.manifestSha256 || source.manifestDocument != manifest.manifestDocument) {
                throw ArtifactChangedException("archive source revision changed during verification")
            }
            requireSame(executable, revalidate { readArtifact(jobId, "$reportPrefix/source-tree/${layout.artifactPath}", MAXIMUM_BYTES) })
            requireSame(input, revalidate { store.readInput(jobId) })
            requireSame(identity(archive), revalidate { readArtifact(jobId, "$reportPrefix/source-tree.zip", MAXIMUM_BYTES) })
            return WebArchiveSnapshot(archive.bytes, archive.sha256, source.view.copy(archiveSha256 = archive.sha256), source.manifestDocument,
                contractSnapshot.sha256, sourceSnapshot.manifestSha256)
        } finally {
            LinuxFilesystemSyscalls.openRoot(temporary).use { directory ->
                deletePrivateTreeContents(directory, AcpRuntimeClosureLimits(maximumUserOwnedFileBytes = MAXIMUM_CLEANUP_BYTES, maximumDepth = 64))
            }
            Files.delete(temporary)
        }
    }

    private fun identity(snapshot: StableRegularFile): ReadIdentity = ReadIdentity(snapshot.sha256, snapshot.identity)

    /** Only for objects already admitted above; initial missing/invalid input retains its refusal. */
    private inline fun <T> revalidate(read: () -> T): T = try {
        read()
    } catch (failure: ArtifactChangedException) {
        throw failure
    } catch (_: JobStoreException) {
        throw ArtifactChangedException("archive input changed during verification")
    } catch (_: IllegalArgumentException) {
        // Includes budget growth and a manifest/source validation that no longer matches admission.
        throw ArtifactChangedException("archive input changed during verification")
    }

    private fun requireSame(expected: ReadIdentity, current: StableRegularFile) {
        if (expected.sha256 != current.sha256 || expected.identity != current.identity) {
            throw ArtifactChangedException("archive input changed during verification")
        }
    }

    companion object {
        const val ARCHIVE_PATH = "reports/source-tree.zip"
        private const val MAXIMUM_BYTES = 64L * 1024 * 1024
        private const val MAXIMUM_FILE_BYTES = 4L * 1024 * 1024
        private const val MAXIMUM_CLEANUP_BYTES = MAXIMUM_BYTES + 2048L * 4096 * 4 + 4096
    }
}
