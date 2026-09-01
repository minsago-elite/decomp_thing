package decompengine.oracle.behavior

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import decompengine.project.ArchivalBundleVerifier
import decompengine.project.VerifiedAcpTextCommitment
import decompengine.project.VerifiedCandidateAcpChange
import decompengine.project.VerifiedCandidateAcpContribution
import decompengine.project.VerifiedCandidateArchiveLineage
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.util.Comparator
import java.util.Locale
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class LlvmBehaviorCandidateAcpLineageIndexV2Exception(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * Constant-size semantic commitment to all accepted ACP contributions in one verified candidate
 * archive. Detailed receipts remain in the archive; this value grants no hosted-build, executable,
 * PREPARED, START, oracle, reference, scoring, certification, or release authority.
 */
sealed interface LlvmBehaviorCandidateAcpLineageIndexV2 {
    val schemaVersion: Int
    val authority: String
    val archiveBytes: Long
    val archiveSha256: String
    val sourceRevisionSha256: String
    val sourceInputCount: Int
    val acceptedAcpCount: Int
    val reconstructionCount: Int
    val repairCount: Int
    val receiptSetSha256: String
    val sessionSetSha256: String
    val changeSetSha256: String
    val lineageSetSha256: String
    val candidateSourceLineageSha256: String
    val indexBytes: Long
    val indexSha256: String
    val schemaSha256: String
    val candidateLineageBound: Boolean
    val hostedBuildBound: Boolean
    val admittedArtifactBound: Boolean
    val prepared: Boolean
    val candidateStarted: Boolean
    val scoringAuthority: Boolean
    val certificationAuthority: Boolean
    val releaseEligible: Boolean
}

object LlvmBehaviorCandidateAcpLineageIndexV2Publisher {
    /** The only production inputs are the raw reconstruction archive and immutable index output. */
    fun publish(archivePath: Path, outputPath: Path): LlvmBehaviorCandidateAcpLineageIndexV2 {
        val paths = normalizePublisherPaths(archivePath, outputPath)
        requireDistinctArchiveAndIndex(paths.archive, paths.index)
        requireDedicatedIndexParent(paths.index)
        try {
            StableControlFile.open(
                paths.archive,
                LLVM_BEHAVIOR_CANDIDATE_ACP_LINEAGE_MAXIMUM_ARCHIVE_BYTES,
                "candidate reconstruction archive",
            ).use {
                    archiveGuard ->
                requireSingleLink(paths.archive, "candidate reconstruction archive")
                val derivation = deriveArchiveLineage(archiveGuard)
                val rendered = renderIndex(derivation)

                val terminalArchiveSha256 = archiveGuard.sha256(label = "candidate reconstruction archive")
                archiveGuard.verifyUnchanged("candidate reconstruction archive")
                requireSingleLink(paths.archive, "candidate reconstruction archive")
                if (terminalArchiveSha256 != derivation.archiveSha256) {
                    lineageFail("candidate reconstruction archive changed before lineage publication")
                }

                LinuxFilesystemSyscalls.openRoot(paths.index.parent).use { parent ->
                    val published = DescriptorBoundAtomicStateFile.publishNoReplace(
                        parent,
                        paths.index.fileName.toString(),
                        rendered.bytes,
                        MAXIMUM_INDEX_BYTES,
                    )
                    if (!MessageDigest.isEqual(published.bytes, rendered.bytes)) {
                        lineageFail("published candidate ACP lineage index differs from derived bytes")
                    }
                }
            }
            return LlvmBehaviorCandidateAcpLineageIndexV2Verifier.verify(paths.archive, paths.index)
        } catch (failure: LlvmBehaviorCandidateAcpLineageIndexV2Exception) {
            throw failure
        } catch (failure: Exception) {
            lineageFail(
                "candidate ACP lineage publication failed: ${failure.message ?: failure.javaClass.simpleName}",
                failure,
            )
        }
    }
}

object LlvmBehaviorCandidateAcpLineageIndexV2Verifier {
    /** Re-derives the expected index from the raw archive; no claimed digest or parsed fact enters. */
    fun verify(archivePath: Path, indexPath: Path): LlvmBehaviorCandidateAcpLineageIndexV2 {
        val paths = normalizeVerifierPaths(archivePath, indexPath)
        requireDistinctArchiveAndIndex(paths.archive, paths.index)
        requireDedicatedIndexParent(paths.index)
        try {
            StableControlFile.open(
                paths.archive,
                LLVM_BEHAVIOR_CANDIDATE_ACP_LINEAGE_MAXIMUM_ARCHIVE_BYTES,
                "candidate reconstruction archive",
            ).use {
                    archiveGuard ->
                requireSingleLink(paths.archive, "candidate reconstruction archive")
                StableControlFile.open(paths.index, MAXIMUM_INDEX_BYTES.toLong(), "candidate ACP lineage index").use {
                        indexGuard ->
                    requireSingleLink(paths.index, "candidate ACP lineage index")
                    val indexBytes = indexGuard.readExactly(
                        0L,
                        indexGuard.size.toInt(),
                        "candidate ACP lineage index",
                    )
                    rejectForbiddenIndexText(indexBytes.toString(Charsets.UTF_8), "candidate ACP lineage index")
                    val parsed = parseCanonicalIndex(indexBytes)
                    OracleSchemas.validate(INDEX_SCHEMA_NAME, parsed)

                    val derivation = deriveArchiveLineage(archiveGuard)
                    val expected = renderIndex(derivation)
                    if (!MessageDigest.isEqual(indexBytes, expected.bytes)) {
                        lineageFail("candidate ACP lineage index differs from the archive-derived Kotlin value")
                    }
                    val indexSha256 = OracleArtifacts.sha256(indexBytes)
                    val terminalArchiveSha256 = archiveGuard.sha256(label = "candidate reconstruction archive")
                    val terminalIndexSha256 = indexGuard.sha256(label = "candidate ACP lineage index")
                    archiveGuard.verifyUnchanged("candidate reconstruction archive")
                    indexGuard.verifyUnchanged("candidate ACP lineage index")
                    requireSingleLink(paths.archive, "candidate reconstruction archive")
                    requireSingleLink(paths.index, "candidate ACP lineage index")
                    if (terminalArchiveSha256 != derivation.archiveSha256 || terminalIndexSha256 != indexSha256) {
                        lineageFail("candidate archive or ACP lineage index changed during terminal authentication")
                    }
                    return VerifiedLineageIndex(
                        archiveBytes = derivation.archiveBytes,
                        archiveSha256 = derivation.archiveSha256,
                        sourceRevisionSha256 = derivation.lineage.source.sourceRevision.sha256,
                        sourceInputCount = derivation.lineage.source.sourceRevision.inputs.size,
                        acceptedAcpCount = expected.acceptedAcpCount,
                        reconstructionCount = expected.reconstructionCount,
                        repairCount = expected.repairCount,
                        receiptSetSha256 = expected.receiptSetSha256,
                        sessionSetSha256 = expected.sessionSetSha256,
                        changeSetSha256 = expected.changeSetSha256,
                        lineageSetSha256 = expected.lineageSetSha256,
                        candidateSourceLineageSha256 = expected.candidateSourceLineageSha256,
                        indexBytes = indexBytes.size.toLong(),
                        indexSha256 = indexSha256,
                        schemaSha256 = expected.schemaSha256,
                    )
                }
            }
        } catch (failure: LlvmBehaviorCandidateAcpLineageIndexV2Exception) {
            throw failure
        } catch (failure: Exception) {
            lineageFail(
                "candidate ACP lineage verification failed: ${failure.message ?: failure.javaClass.simpleName}",
                failure,
            )
        }
    }
}

object LlvmBehaviorCandidateAcpLineageIndexV2Cli {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 2) { "usage: <absolute-candidate-archive> <absolute-lineage-index-output>" }
        val verified = LlvmBehaviorCandidateAcpLineageIndexV2Publisher.publish(
            Path.of(arguments[0]),
            Path.of(arguments[1]),
        )
        println("${verified.indexSha256}  ${verified.candidateSourceLineageSha256}")
    }
}

private data class CandidateLineagePaths(val archive: Path, val index: Path)

private data class DerivedArchiveLineage(
    val archiveBytes: Long,
    val archiveSha256: String,
    val lineage: VerifiedCandidateArchiveLineage,
)

private data class RenderedLineageIndex(
    val bytes: ByteArray,
    val schemaSha256: String,
    val acceptedAcpCount: Int,
    val reconstructionCount: Int,
    val repairCount: Int,
    val receiptSetSha256: String,
    val sessionSetSha256: String,
    val changeSetSha256: String,
    val lineageSetSha256: String,
    val candidateSourceLineageSha256: String,
)

private data class VerifiedLineageIndex(
    override val archiveBytes: Long,
    override val archiveSha256: String,
    override val sourceRevisionSha256: String,
    override val sourceInputCount: Int,
    override val acceptedAcpCount: Int,
    override val reconstructionCount: Int,
    override val repairCount: Int,
    override val receiptSetSha256: String,
    override val sessionSetSha256: String,
    override val changeSetSha256: String,
    override val lineageSetSha256: String,
    override val candidateSourceLineageSha256: String,
    override val indexBytes: Long,
    override val indexSha256: String,
    override val schemaSha256: String,
) : LlvmBehaviorCandidateAcpLineageIndexV2 {
    override val schemaVersion = 2
    override val authority = INDEX_AUTHORITY
    override val candidateLineageBound = true
    override val hostedBuildBound = false
    override val admittedArtifactBound = false
    override val prepared = false
    override val candidateStarted = false
    override val scoringAuthority = false
    override val certificationAuthority = false
    override val releaseEligible = false
}

private fun normalizePublisherPaths(archivePath: Path, outputPath: Path): CandidateLineagePaths {
    val archive = requireExactPath(archivePath, "candidate reconstruction archive")
    val output = requireExactPath(outputPath, "candidate ACP lineage index output")
    requireIndexFileName(output)
    rejectForbiddenIndexText(output.toString(), "candidate ACP lineage index output path")
    return CandidateLineagePaths(archive, output)
}

private fun normalizeVerifierPaths(archivePath: Path, indexPath: Path): CandidateLineagePaths {
    val archive = requireExactPath(archivePath, "candidate reconstruction archive")
    val index = requireExactPath(indexPath, "candidate ACP lineage index")
    requireIndexFileName(index)
    rejectForbiddenIndexText(index.toString(), "candidate ACP lineage index path")
    return CandidateLineagePaths(archive, index)
}

private fun requireExactPath(path: Path, label: String): Path {
    if (!path.isAbsolute || path.normalize() != path || path.fileName == null || path.parent == null) {
        lineageFail("$label path must be exact, absolute, normalized, and name a file")
    }
    return path
}

private fun requireIndexFileName(path: Path) {
    if (path.fileName.toString() != INDEX_FILE_NAME) {
        lineageFail("candidate ACP lineage index must use the fixed file name $INDEX_FILE_NAME")
    }
}

private fun requireDistinctArchiveAndIndex(archive: Path, index: Path) {
    if (archive == index || sameExistingFile(archive, index)) {
        lineageFail("candidate archive and ACP lineage index must not alias")
    }
    if (archive.parent == index.parent) {
        lineageFail("dedicated candidate ACP lineage index parent must not contain the archive")
    }
    val temporary = index.parent.resolve(DescriptorBoundAtomicStateFile.temporaryName(INDEX_FILE_NAME))
    if (sameExistingFile(archive, temporary)) {
        lineageFail("candidate archive must not alias the lineage publication temporary")
    }
}

private fun sameExistingFile(left: Path, right: Path): Boolean =
    Files.exists(left, LinkOption.NOFOLLOW_LINKS) && Files.exists(right, LinkOption.NOFOLLOW_LINKS) &&
        try {
            Files.isSameFile(left, right)
        } catch (failure: Exception) {
            lineageFail("cannot establish candidate lineage path alias identity", failure)
        }

private fun requireDedicatedIndexParent(index: Path) {
    val parent = index.parent
    val attributes = try {
        Files.readAttributes(parent, java.nio.file.attribute.BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    } catch (failure: Exception) {
        lineageFail("candidate ACP lineage index parent is unavailable", failure)
    }
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null ||
        parent.toRealPath() != parent
    ) {
        lineageFail("candidate ACP lineage index parent must be an identified real directory")
    }
    val permissions = try {
        Files.getPosixFilePermissions(parent, LinkOption.NOFOLLOW_LINKS)
    } catch (failure: Exception) {
        lineageFail("candidate ACP lineage index parent POSIX permissions are unavailable", failure)
    }
    if (permissions != OWNER_DIRECTORY_PERMISSIONS) {
        lineageFail("candidate ACP lineage index parent must be dedicated mode 0700")
    }
    val allowed = setOf(INDEX_FILE_NAME, DescriptorBoundAtomicStateFile.temporaryName(INDEX_FILE_NAME))
    val entries = try {
        Files.newDirectoryStream(parent).use { stream -> stream.map { it.fileName.toString() }.toList() }
    } catch (failure: Exception) {
        lineageFail("candidate ACP lineage index parent cannot be enumerated", failure)
    }
    if (entries.any { it !in allowed } || entries.size > 1) {
        lineageFail("candidate ACP lineage index parent is not dedicated to one immutable index")
    }
}

private fun requireSingleLink(path: Path, label: String) {
    val links = try {
        (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toLong()
    } catch (failure: Exception) {
        lineageFail("$label link identity is unavailable", failure)
    }
    if (links != 1L) lineageFail("$label must not be hard-linked")
}

private fun deriveArchiveLineage(archiveGuard: StableControlFile): DerivedArchiveLineage {
    val scratch = Files.createTempDirectory("llvm-candidate-acp-lineage-v2-").toAbsolutePath().normalize()
    try {
        Files.setPosixFilePermissions(scratch, OWNER_DIRECTORY_PERMISSIONS)
        if (scratch.toRealPath() != scratch) lineageFail("candidate lineage scratch path contains a symbolic link")
        val snapshot = scratch.resolve("candidate-archive.zip")
        val digest = MessageDigest.getInstance("SHA-256")
        var copied = 0L
        archiveGuard.slice().use { input ->
            Files.newOutputStream(snapshot, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    copied = Math.addExact(copied, count.toLong())
                    if (copied > archiveGuard.size) lineageFail("candidate archive grew during snapshotting")
                    digest.update(buffer, 0, count)
                    output.write(buffer, 0, count)
                }
            }
        }
        if (copied != archiveGuard.size) lineageFail("candidate archive ended during snapshotting")
        FileChannel.open(snapshot, StandardOpenOption.WRITE).use { it.force(true) }
        Files.setPosixFilePermissions(snapshot, OWNER_READ_ONLY_PERMISSIONS)
        val archiveSha256 = digest.digest().hex()

        StableControlFile.open(
            snapshot,
            LLVM_BEHAVIOR_CANDIDATE_ACP_LINEAGE_MAXIMUM_ARCHIVE_BYTES,
            "private candidate archive snapshot",
        ).use {
                snapshotGuard ->
            requireSingleLink(snapshot, "private candidate archive snapshot")
            val initialSnapshotSha256 = snapshotGuard.sha256(label = "private candidate archive snapshot")
            if (snapshotGuard.size != archiveGuard.size || initialSnapshotSha256 != archiveSha256) {
                lineageFail("private candidate archive snapshot differs from its descriptor-pinned input")
            }
            val lineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(
                snapshot,
                scratch.resolve("extracted-candidate"),
            )
            val terminalSnapshotSha256 = snapshotGuard.sha256(label = "private candidate archive snapshot")
            snapshotGuard.verifyUnchanged("private candidate archive snapshot")
            requireSingleLink(snapshot, "private candidate archive snapshot")
            if (terminalSnapshotSha256 != archiveSha256) {
                lineageFail("private candidate archive snapshot changed during archive verification")
            }
            return DerivedArchiveLineage(archiveGuard.size, archiveSha256, lineage)
        }
    } finally {
        deletePrivateScratch(scratch)
    }
}

private fun deletePrivateScratch(root: Path) {
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
    Files.walk(root).use { paths ->
        paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
    }
}

private fun renderIndex(derivation: DerivedArchiveLineage): RenderedLineageIndex {
    val source = derivation.lineage.source
    val contributions = source.acceptedAcpContributions
    if (contributions.isEmpty()) {
        lineageFail("candidate archive contains no accepted first-class ACP contribution")
    }
    if (contributions.size > MAXIMUM_ACCEPTED_ACP_CONTRIBUTIONS) {
        lineageFail("candidate archive exceeds the accepted ACP contribution bound")
    }
    val reconstructionCount = contributions.count { it.workflow == "reconstruction" }
    val repairCount = contributions.count { it.workflow == "repair" }
    if (reconstructionCount + repairCount != contributions.size) {
        lineageFail("candidate archive contains an unsupported ACP workflow contribution")
    }

    val receiptLeaves = contributions.map(::receiptLeafSha256)
    val sessionLeaves = contributions.map(::sessionLeafSha256)
    val changeLeaves = contributions.map(::changeLeafSha256)
    val lineageLeaves = contributions.indices.map { index ->
        domainDigest("candidate-acp-contribution-lineage-leaf-v2") {
            field("receiptLeafSha256", receiptLeaves[index])
            field("sessionLeafSha256", sessionLeaves[index])
            field("changeLeafSha256", changeLeaves[index])
        }
    }
    val receiptSetSha256 = aggregateLeaves("candidate-acp-receipt-set-v2", receiptLeaves)
    val sessionSetSha256 = aggregateLeaves("candidate-acp-session-set-v2", sessionLeaves)
    val changeSetSha256 = aggregateLeaves("candidate-acp-change-set-v2", changeLeaves)
    val lineageSetSha256 = aggregateLeaves("candidate-acp-lineage-set-v2", lineageLeaves)
    val schemaIdentity = OracleSchemas.identity(INDEX_SCHEMA_NAME)
    val candidateSourceLineageSha256 = domainDigest("candidate-source-lineage-v2") {
        field("schemaSha256", schemaIdentity.sha256)
        field("archiveBytes", derivation.archiveBytes)
        field("archiveSha256", derivation.archiveSha256)
        field("archiveManifestBytes", derivation.lineage.archiveManifestBytes)
        field("archiveManifestSha256", derivation.lineage.archiveManifestSha256)
        field("sourceTreeManifestBytes", source.sourceTreeManifestBytes)
        field("sourceTreeManifestSha256", source.sourceTreeManifestSha256)
        field("profileId", source.profileId)
        field("profileSha256", source.profileSha256)
        field("sourceInputCount", source.sourceRevision.inputs.size.toLong())
        field("sourceRevisionSha256", source.sourceRevision.sha256)
        field("repairGraphHeadId", source.repairGraphHeadId)
        field("repairGraphHeadRevisionSha256", source.repairGraphHeadRevisionSha256)
        field("acceptedAcpCount", contributions.size.toLong())
        field("reconstructionCount", reconstructionCount.toLong())
        field("repairCount", repairCount.toLong())
        field("receiptSetSha256", receiptSetSha256)
        field("sessionSetSha256", sessionSetSha256)
        field("changeSetSha256", changeSetSha256)
        field("lineageSetSha256", lineageSetSha256)
    }

    val document = jsonObject(
        "schemaVersion" to JsonPrimitive(2),
        "kind" to JsonPrimitive(INDEX_KIND),
        "authority" to JsonPrimitive(INDEX_AUTHORITY),
        "schema" to jsonObject(
            "name" to JsonPrimitive(INDEX_SCHEMA_NAME),
            "sha256" to JsonPrimitive(schemaIdentity.sha256),
        ),
        "archive" to jsonObject(
            "bytes" to JsonPrimitive(derivation.archiveBytes),
            "sha256" to JsonPrimitive(derivation.archiveSha256),
            "archiveManifestBytes" to JsonPrimitive(derivation.lineage.archiveManifestBytes),
            "archiveManifestSha256" to JsonPrimitive(derivation.lineage.archiveManifestSha256),
            "sourceTreeManifestBytes" to JsonPrimitive(source.sourceTreeManifestBytes),
            "sourceTreeManifestSha256" to JsonPrimitive(source.sourceTreeManifestSha256),
        ),
        "source" to jsonObject(
            "profileId" to JsonPrimitive(source.profileId),
            "profileSha256" to JsonPrimitive(source.profileSha256),
            "revisionAlgorithm" to JsonPrimitive("length-prefixed-path-bytes-sha256-v1"),
            "inputCount" to JsonPrimitive(source.sourceRevision.inputs.size),
            "revisionSha256" to JsonPrimitive(source.sourceRevision.sha256),
            "repairGraphHeadId" to nullableString(source.repairGraphHeadId),
            "repairGraphHeadRevisionSha256" to nullableString(source.repairGraphHeadRevisionSha256),
        ),
        "acceptedAcp" to jsonObject(
            "receiptSchemaVersion" to JsonPrimitive(2),
            "count" to JsonPrimitive(contributions.size),
            "reconstructionCount" to JsonPrimitive(reconstructionCount),
            "repairCount" to JsonPrimitive(repairCount),
            "aggregateAlgorithm" to JsonPrimitive("domain-separated-length-prefixed-sorted-leaves-v2"),
            "receiptSetSha256" to JsonPrimitive(receiptSetSha256),
            "sessionSetSha256" to JsonPrimitive(sessionSetSha256),
            "changeSetSha256" to JsonPrimitive(changeSetSha256),
            "lineageSetSha256" to JsonPrimitive(lineageSetSha256),
        ),
        "candidateSourceLineageSha256" to JsonPrimitive(candidateSourceLineageSha256),
        "acpBoundary" to acpBoundaryDocument(),
        "claims" to claimsDocument(),
    )
    OracleSchemas.validate(INDEX_SCHEMA_NAME, document)
    val bytes = try {
        OracleJson.canonicalBytes(document, INDEX_JSON_LIMITS)
    } catch (failure: Exception) {
        lineageFail("candidate ACP lineage index exceeds canonical JSON limits", failure)
    }
    if (bytes.isEmpty() || bytes.size > MAXIMUM_INDEX_BYTES) {
        lineageFail("candidate ACP lineage index exceeds its immutable publication bound")
    }
    rejectForbiddenIndexText(bytes.toString(Charsets.UTF_8), "candidate ACP lineage index")
    return RenderedLineageIndex(
        bytes,
        schemaIdentity.sha256,
        contributions.size,
        reconstructionCount,
        repairCount,
        receiptSetSha256,
        sessionSetSha256,
        changeSetSha256,
        lineageSetSha256,
        candidateSourceLineageSha256,
    )
}

private fun receiptLeafSha256(contribution: VerifiedCandidateAcpContribution): String =
    domainDigest("candidate-acp-receipt-leaf-v2") {
        contributionIdentity(contribution)
        field("receiptBytes", contribution.receiptBytes)
        field("receiptSha256", contribution.receiptSha256)
        field("receiptSchemaVersion", 2L)
        field("requestSha256", contribution.requestSha256)
        field("promptSha256", contribution.promptSha256)
        field("resultChangesSha256", contribution.resultChangesSha256)
        field("terminalOutcome", "returned-completed")
        field("releaseComplete", true)
    }

private fun sessionLeafSha256(contribution: VerifiedCandidateAcpContribution): String =
    domainDigest("candidate-acp-session-leaf-v2") {
        contributionIdentity(contribution)
        val session = contribution.session
        field("factoryImplementationId", session.factoryImplementationId)
        field("factoryConfigurationSha256", session.factoryConfigurationSha256)
        field("factoryDescriptor", session.factoryDescriptor)
        textCommitment("negotiatedName", session.negotiatedName)
        textCommitment("negotiatedVersion", session.negotiatedVersion)
        optionalTextCommitment("negotiatedTitle", session.negotiatedTitle)
        field("capabilityCount", session.negotiatedCapabilities.size.toLong())
        session.negotiatedCapabilities.entries.sortedBy(Map.Entry<String, Boolean>::key)
            .forEachIndexed { index, (name, enabled) ->
                field("capability[$index].name", name)
                field("capability[$index].enabled", enabled)
            }
        textCommitment("sessionId", session.sessionId)
        optionalTextCommitment("resumeReference", session.resumeReference)
    }

private fun changeLeafSha256(contribution: VerifiedCandidateAcpContribution): String =
    domainDigest("candidate-acp-change-leaf-v2") {
        contributionIdentity(contribution)
        field("resultChangesSha256", contribution.resultChangesSha256)
        field("parentSourceRevisionSha256", contribution.parentSourceRevisionSha256)
        field("resultSourceRevisionSha256", contribution.resultSourceRevisionSha256)
        field("changeCount", contribution.changes.size.toLong())
        contribution.changes.forEachIndexed { index, change -> change("change[$index]", change) }
    }

private fun LineageDigest.contributionIdentity(contribution: VerifiedCandidateAcpContribution) {
    field("workflow", contribution.workflow)
    field("taskId", contribution.taskId)
    field("receiptPath", contribution.receiptPath)
}

private fun LineageDigest.textCommitment(label: String, value: VerifiedAcpTextCommitment) {
    field("$label.sha256", value.sha256)
    field("$label.encodedBytes", value.encodedBytes)
    field("$label.encoding", value.encoding)
}

private fun LineageDigest.optionalTextCommitment(label: String, value: VerifiedAcpTextCommitment?) {
    field("$label.present", value != null)
    if (value != null) textCommitment(label, value)
}

private fun LineageDigest.change(label: String, value: VerifiedCandidateAcpChange) {
    field("$label.path", value.path)
    field("$label.kind", value.kind)
    field("$label.beforeSha256", value.beforeSha256)
    field("$label.afterSha256", value.afterSha256)
    field("$label.bytes", value.bytes)
}

private fun aggregateLeaves(domain: String, leaves: List<String>): String = domainDigest(domain) {
    field("count", leaves.size.toLong())
    leaves.sorted().forEachIndexed { index, leaf -> field("leaf[$index]", leaf) }
}

private inline fun domainDigest(domain: String, populate: LineageDigest.() -> Unit): String =
    LineageDigest(domain).apply(populate).finish()

private class LineageDigest(domain: String) {
    private val digest = MessageDigest.getInstance("SHA-256")

    init {
        token("decomp-engine-candidate-acp-lineage-index-v2".toByteArray(Charsets.UTF_8))
        token(domain.toByteArray(Charsets.UTF_8))
    }

    fun field(name: String, value: String?) {
        token(name.toByteArray(Charsets.UTF_8))
        digest.update(if (value == null) 0 else 1)
        if (value != null) token(value.toByteArray(Charsets.UTF_8))
    }

    fun field(name: String, value: Long?) = field(name, value?.toString())

    fun field(name: String, value: Boolean) = field(name, if (value) "true" else "false")

    fun finish(): String = digest.digest().hex()

    private fun token(bytes: ByteArray) {
        digest.update(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(bytes.size.toLong()).array())
        digest.update(bytes)
    }
}

private fun acpBoundaryDocument(): JsonObject = jsonObject(
    "role" to JsonPrimitive("first-class-candidate-producer-operator"),
    "candidateContribution" to JsonPrimitive("authenticated-session-change-provenance"),
    "candidateProvenanceAccess" to JsonPrimitive("read-only-oracle-input"),
    "candidateAdmissionOwner" to JsonPrimitive("kotlin-jvm-host"),
    "candidateLiveExecutionOwner" to JsonPrimitive("separately-reviewed-kotlin-jvm-host"),
    "referenceSubjectAdmission" to JsonPrimitive("kotlin-jvm-host-only"),
    "oracleAuthority" to JsonPrimitive(false),
    "referenceAuthoringAuthority" to JsonPrimitive(false),
    "policyAuthoringAuthority" to JsonPrimitive(false),
    "validationAuthority" to JsonPrimitive(false),
    "observationAuthoringAuthority" to JsonPrimitive(false),
    "startAuthority" to JsonPrimitive(false),
    "containmentAuthority" to JsonPrimitive(false),
    "terminalAbsenceAuthority" to JsonPrimitive(false),
    "scoringAuthority" to JsonPrimitive(false),
    "certificationAuthority" to JsonPrimitive(false),
    "releaseAuthority" to JsonPrimitive(false),
)

private fun claimsDocument(): JsonObject = jsonObject(
    "candidateLineageBound" to JsonPrimitive(true),
    "hostedBuildBound" to JsonPrimitive(false),
    "admittedArtifactBound" to JsonPrimitive(false),
    "prepared" to JsonPrimitive(false),
    "runtimeIdentityVerified" to JsonPrimitive(false),
    "liveContainmentVerified" to JsonPrimitive(false),
    "terminalAbsenceVerified" to JsonPrimitive(false),
    "observationsCaptured" to JsonPrimitive(false),
    "candidateStarted" to JsonPrimitive(false),
    "startAuthorized" to JsonPrimitive(false),
    "referenceTruthEstablished" to JsonPrimitive(false),
    "scoringAuthority" to JsonPrimitive(false),
    "certificationAuthority" to JsonPrimitive(false),
    "releaseEligible" to JsonPrimitive(false),
)

private fun parseCanonicalIndex(bytes: ByteArray): JsonObject {
    val parsed = try {
        OracleJson.parseCanonical(bytes, INDEX_JSON_LIMITS)
    } catch (failure: Exception) {
        lineageFail("candidate ACP lineage index is not strict canonical bounded JSON", failure)
    }
    return parsed as? JsonObject ?: lineageFail("candidate ACP lineage index root must be an object")
}

private fun rejectForbiddenIndexText(value: String, label: String) {
    val lower = value.lowercase(Locale.ROOT)
    FORBIDDEN_INDEX_MARKERS.forEach { marker ->
        if (marker in lower) lineageFail("$label contains forbidden Python or legacy behavior material")
    }
}

private fun nullableString(value: String?): JsonElement = value?.let(::JsonPrimitive) ?: JsonNull

private fun jsonObject(vararg fields: Pair<String, JsonElement>): JsonObject = JsonObject(linkedMapOf(*fields))

private fun ByteArray.hex(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private fun lineageFail(message: String, cause: Throwable? = null): Nothing =
    throw LlvmBehaviorCandidateAcpLineageIndexV2Exception(message, cause)

private const val INDEX_SCHEMA_NAME = "llvm-behavior-candidate-acp-lineage-index-v2"
private const val INDEX_FILE_NAME = "candidate-acp-lineage-index-v2.json"
private const val INDEX_KIND = "llvm-behavior-candidate-acp-lineage-index-v2"
private const val INDEX_AUTHORITY = "kotlin-jvm-verified-candidate-acp-lineage-v2"
private const val MAXIMUM_INDEX_BYTES = 64 * 1024
private const val MAXIMUM_ACCEPTED_ACP_CONTRIBUTIONS = 100_000
// The archive verifier admits 1 GiB of stored payload. Packager-produced ZIP headers repeat every
// manifest path, so the whole-file cap also reserves twice the 128 MiB manifest-file bound plus
// fixed per-entry overhead while remaining finite before descriptor-pinned snapshotting.
internal const val LLVM_BEHAVIOR_CANDIDATE_ACP_LINEAGE_MAXIMUM_ARCHIVE_BYTES = 1536L * 1024 * 1024
private val OWNER_DIRECTORY_PERMISSIONS = setOf(
    PosixFilePermission.OWNER_READ,
    PosixFilePermission.OWNER_WRITE,
    PosixFilePermission.OWNER_EXECUTE,
)
private val OWNER_READ_ONLY_PERMISSIONS = setOf(PosixFilePermission.OWNER_READ)
private val INDEX_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_INDEX_BYTES,
    maximumCanonicalBytes = MAXIMUM_INDEX_BYTES,
    maximumDepth = 16,
    maximumNodes = 512,
    maximumStringBytes = 4096,
    maximumTotalStringBytes = 32 * 1024,
)
private val FORBIDDEN_INDEX_MARKERS = listOf(
    "python",
    "behavior-preexec-v1",
    "oci-container-v1",
    "llvm-behavior-candidate-execution-admission-v1",
    "llvm-behavior-runtime-preflight-v1",
)
