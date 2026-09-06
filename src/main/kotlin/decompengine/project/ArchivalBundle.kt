package decompengine.project

import decompengine.oracle.fulltree.StableControlFile
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.io.BufferedInputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.text.Normalizer
import java.util.Locale
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile
import kotlin.io.path.readText
import kotlin.io.path.relativeTo

data class ArchivalBundle(
    val archivePath: Path,
    val archiveSha256: String,
    val payloadFiles: List<String>,
)

data class ArchivalBundleLimits(
    val maximumEntries: Int = 100_000,
    val maximumFileBytes: Long = 128L * 1024 * 1024,
    val maximumTotalBytes: Long = 1024L * 1024 * 1024,
) {
    init {
        require(maximumEntries in 1..1_000_000) { "archive entry limit must be between 1 and 1000000" }
        require(maximumFileBytes in 1 until Int.MAX_VALUE.toLong()) {
            "archive file limit must be positive and smaller than 2 GiB"
        }
        require(maximumTotalBytes >= maximumFileBytes) { "archive total limit must be at least the file limit" }
    }
}

private data class ArchivePayload(
    val relativePath: String,
    val sourcePath: Path,
    val size: Long,
    val sha256: String,
    val crc32: Long,
)

object ArchivalPackager {
    private const val HASH_MANIFEST = "ARCHIVE_MANIFEST.sha256"

    @JvmOverloads
    fun create(
        projectDir: Path,
        archivePath: Path,
        limits: ArchivalBundleLimits = ArchivalBundleLimits(),
        profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
        requiredCorpusSha256: Set<String> = emptySet(),
    ): ArchivalBundle {
        val requiredCorpora = snapshotRequiredBehaviorCorpora(requiredCorpusSha256)
        require(!Files.isSymbolicLink(projectDir)) { "archive project root must not be a symbolic link" }
        require(projectDir.resolve("source_tree_manifest.json").isRegularFile(LinkOption.NOFOLLOW_LINKS)) {
            "project is missing source_tree_manifest.json"
        }
        preflightProjectTree(projectDir, limits)
        val projectBase = projectDir.toRealPath()
        val archiveAbsolute = archivePath.toAbsolutePath().normalize()
        val archiveLexicalParent = archiveAbsolute.parent
        val prospectiveArchiveParent = prospectiveRealPath(archiveLexicalParent)
        val prospectiveDestination = prospectiveArchiveParent.resolve(archiveAbsolute.fileName).normalize()
        require(!prospectiveDestination.startsWith(projectBase)) {
            "archive output must be outside the archived project"
        }
        Files.createDirectories(archiveLexicalParent)
        val archiveParent = archiveLexicalParent.toRealPath()
        val archiveDestination = archiveParent.resolve(archiveAbsolute.fileName).normalize()
        require(archiveParent == prospectiveArchiveParent) { "archive output parent changed while it was prepared" }
        require(!archiveDestination.startsWith(projectBase)) { "archive output must be outside the archived project" }
        require(!Files.isSymbolicLink(archivePath) && !Files.isSymbolicLink(archiveDestination)) {
            "archive output must not be a symbolic link: $archivePath"
        }
        validateSuccessfulBuild(projectDir)
        val audit = ArchivalProjectAuditor.audit(projectDir, profile, requiredCorpora)
        require(audit.provenanceComplete) { "archive project has incomplete model or source provenance" }
        require(requiredCorpora.isEmpty() || audit.behaviorMatched == true) {
            "archive project does not satisfy the required behavior corpora"
        }
        val readme = projectDir.resolve("ARCHIVE_README.md")
        writeProjectEvidenceAtomically(
            readme,
            """
            # Reconstructed archival source tree

            This project was reconstructed from a binary using evidence-backed analysis and may not be universally equivalent to the original.

            Build with the exact parallel warnings-as-errors command in `BUILDING.md`. The recovered program model, module plan, confidence, unresolved entities, build logs, and per-module provenance are under `reports/`.
            Verify payload hashes with `ARCHIVE_MANIFEST.sha256` before use.
            """.trimIndent() + "\n",
        )
        val payload = collectPayload(projectDir, archiveDestination, limits)
        validateSourceManifest(projectDir, payload.associateBy { it.relativePath }, profile)
        val payloadBytes = payload.fold(0L) { total, item -> Math.addExact(total, item.size) }
        val hashManifestBytes = payload.fold(0L) { total, item ->
            Math.addExact(total, 67L + item.relativePath.toByteArray(Charsets.UTF_8).size)
        }
        require(hashManifestBytes <= limits.maximumFileBytes) {
            "$HASH_MANIFEST exceeds the ${limits.maximumFileBytes}-byte file limit"
        }
        require(Math.addExact(payloadBytes, hashManifestBytes) <= limits.maximumTotalBytes) {
            "archive exceeds ${limits.maximumTotalBytes} payload bytes"
        }
        val hashManifestPath = projectDir.resolve(HASH_MANIFEST)
        require(!Files.isSymbolicLink(hashManifestPath)) { "$HASH_MANIFEST must not be a symbolic link" }
        writeProjectEvidenceAtomically(hashManifestPath) { output ->
            payload.forEach { item ->
                output.write("${item.sha256}  ${item.relativePath}\n".toByteArray(Charsets.UTF_8))
            }
        }
        val manifestPayload = inspectPayload(HASH_MANIFEST, hashManifestPath, limits)
        require(payload.size + 1 <= limits.maximumEntries) { "archive exceeds ${limits.maximumEntries} entries" }
        check(manifestPayload.size == hashManifestBytes) { "$HASH_MANIFEST changed while it was prepared" }
        val temporaryArchive = Files.createTempFile(archiveParent, ".${archivePath.fileName}.", ".tmp")
        try {
            ZipOutputStream(Files.newOutputStream(temporaryArchive, StandardOpenOption.TRUNCATE_EXISTING)).use { zip ->
                (payload + manifestPayload).sortedBy { it.relativePath }.forEach { item ->
                    val entry = ZipEntry(item.relativePath).apply {
                        method = ZipEntry.STORED
                        size = item.size
                        compressedSize = item.size
                        crc = item.crc32
                        time = 0L
                        creationTime = java.nio.file.attribute.FileTime.fromMillis(0)
                        lastAccessTime = java.nio.file.attribute.FileTime.fromMillis(0)
                        lastModifiedTime = java.nio.file.attribute.FileTime.fromMillis(0)
                    }
                    zip.putNextEntry(entry)
                    copyAndVerify(item, zip)
                    zip.closeEntry()
                }
            }
            try {
                Files.move(
                    temporaryArchive,
                    archiveDestination,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
                Files.move(temporaryArchive, archiveDestination, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(temporaryArchive)
        }
        return ArchivalBundle(archivePath, digestFile(archiveDestination), payload.map { it.relativePath })
    }

    private fun collectPayload(
        projectDir: Path,
        archiveAbsolute: Path,
        limits: ArchivalBundleLimits,
    ): List<ArchivePayload> {
        val files = mutableListOf<ArchivePayload>()
        val portablePaths = mutableSetOf(portablePathKey(HASH_MANIFEST))
        var totalBytes = 0L
        Files.walk(projectDir).use { paths ->
            paths.forEach { path ->
                if (path == projectDir) return@forEach
                val relative = archiveRelativePath(projectDir, path)
                if (relative == "build" || relative.startsWith("build/")) return@forEach
                if (path.toAbsolutePath().normalize() == archiveAbsolute || relative == HASH_MANIFEST) {
                    return@forEach
                }
                validateRelativePath(relative)
                require(portablePaths.add(portablePathKey(relative))) {
                    "archive project contains a non-portable colliding path: $relative"
                }
                require(!Files.isSymbolicLink(path)) { "archive project contains a symbolic link: $relative" }
                if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) return@forEach
                require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                    "archive project contains a non-regular file: $relative"
                }
                rejectPrivateOrCachedPath(relative)
                val item = inspectPayload(relative, path, limits)
                totalBytes = Math.addExact(totalBytes, item.size)
                require(totalBytes <= limits.maximumTotalBytes) {
                    "archive exceeds ${limits.maximumTotalBytes} payload bytes"
                }
                files += item
                require(files.size < limits.maximumEntries) {
                    "archive leaves no entry available for $HASH_MANIFEST under the ${limits.maximumEntries} entry limit"
                }
            }
        }
        return files.sortedBy { it.relativePath }
    }
}

object ArchivalBundleVerifier {
    private const val HASH_MANIFEST = "ARCHIVE_MANIFEST.sha256"

    internal fun extractAndVerifySnapshot(
        archiveBytes: ByteArray,
        targetDir: Path,
        limits: ArchivalBundleLimits,
        profile: ReconstructionProfile,
        maximumPathDepth: Int,
    ): List<Path> = archiveBytes.inputStream().use { input ->
        extractAndVerifyInternal(input, targetDir, limits, profile, maximumPathDepth, strictControlJson = true).paths
    }

    @JvmOverloads
    fun extractAndVerify(
        archivePath: Path,
        targetDir: Path,
        limits: ArchivalBundleLimits = ArchivalBundleLimits(),
        profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
    ): List<Path> = extractAndVerifyInternal(archivePath, targetDir, limits, profile).paths

    internal fun extractAndVerifyCandidateLineage(
        archivePath: Path,
        targetDir: Path,
    ): VerifiedCandidateArchiveLineage = extractAndVerifyInternal(
        archivePath,
        targetDir,
        ArchivalBundleLimits(),
        GeneratedCMakeReconstructionProfile.descriptor,
    ).lineage

    @JvmSynthetic
    internal fun extractAndVerifyCandidateLineage(
        archive: StableControlFile,
        targetDir: Path,
    ): VerifiedCandidateArchiveLineage = archive.slice().use { archiveInput ->
        extractAndVerifyInternal(
            archiveInput,
            targetDir,
            ArchivalBundleLimits(),
            GeneratedCMakeReconstructionProfile.descriptor,
        ).lineage
    }

    private fun extractAndVerifyInternal(
        archivePath: Path,
        targetDir: Path,
        limits: ArchivalBundleLimits,
        profile: ReconstructionProfile,
    ): VerifiedArchiveExtraction {
        require(Files.isRegularFile(archivePath, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(archivePath)) {
            "archive must be a regular non-symbolic-link file"
        }
        return Files.newInputStream(archivePath).use { archiveInput ->
            extractAndVerifyInternal(archiveInput, targetDir, limits, profile)
        }
    }

    private fun extractAndVerifyInternal(
        archiveInput: InputStream,
        targetDir: Path,
        limits: ArchivalBundleLimits,
        profile: ReconstructionProfile,
        maximumPathDepth: Int = 2048,
        strictControlJson: Boolean = false,
    ): VerifiedArchiveExtraction {
        require(maximumPathDepth in 1..2048) { "archive path depth bound is invalid" }
        val targetBase = targetDir.toAbsolutePath().normalize()
        val targetExisted = Files.exists(targetBase, LinkOption.NOFOLLOW_LINKS)
        require(!Files.isSymbolicLink(targetBase)) { "archive target must not be a symbolic link" }
        val existingTargetIdentity = if (targetExisted) {
            require(Files.isDirectory(targetBase, LinkOption.NOFOLLOW_LINKS)) { "archive target is not a directory" }
            Files.list(targetBase).use { require(it.findAny().isEmpty) { "archive target must be empty" } }
            captureDirectoryIdentity(targetBase)
        } else {
            null
        }
        val targetParent = targetBase.parent.also(Files::createDirectories)
        val staging = if (targetExisted) {
            Files.createTempDirectory(targetBase, ".archive-extract-")
        } else {
            Files.createTempDirectory(targetParent, ".${targetBase.fileName}.extract-")
        }
        try {
            val extractedRelative = mutableListOf<String>()
            val seen = mutableSetOf<String>()
            val seenPortable = mutableSetOf<String>()
            var totalBytes = 0L
            ZipInputStream(BufferedInputStream(archiveInput)).use { zip ->
                var entryCount = 0
                while (true) {
                    val entry = zip.nextEntry ?: break
                    entryCount++
                    require(entryCount <= limits.maximumEntries) { "archive exceeds ${limits.maximumEntries} entries" }
                    require(!entry.isDirectory) { "archive contains directory entries" }
                    val normalizedName = entry.name
                    validateRelativePath(normalizedName)
                    require(normalizedName.split('/').size <= maximumPathDepth) { "archive path exceeds its depth bound" }
                    if (normalizedName != HASH_MANIFEST) rejectPrivateOrCachedPath(normalizedName)
                    require(normalizedName !in seen && seenPortable.add(portablePathKey(normalizedName))) {
                        "archive contains a duplicate or non-portable colliding path: ${entry.name}"
                    }
                    require(entry.method == ZipEntry.STORED) { "archive entry must use the bounded stored format: ${entry.name}" }
                    require(entry.size in 0..limits.maximumFileBytes) { "archive entry exceeds the file limit: ${entry.name}" }
                    totalBytes = Math.addExact(totalBytes, entry.size)
                    require(totalBytes <= limits.maximumTotalBytes) { "archive exceeds ${limits.maximumTotalBytes} payload bytes" }
                    seen += normalizedName
                    val target = staging.resolve(normalizedName).normalize()
                    require(target.startsWith(staging)) { "archive entry escapes extraction target: ${entry.name}" }
                    createSafeParents(staging, target.parent)
                    var observed = 0L
                    Files.newOutputStream(target, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { output ->
                        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                        while (true) {
                            val count = zip.read(buffer)
                            if (count < 0) break
                            observed = Math.addExact(observed, count.toLong())
                            require(observed <= entry.size && observed <= limits.maximumFileBytes) {
                                "archive entry exceeds its declared or configured size: ${entry.name}"
                            }
                            output.write(buffer, 0, count)
                        }
                    }
                    require(observed == entry.size) { "archive entry size mismatch: ${entry.name}" }
                    extractedRelative += normalizedName
                    zip.closeEntry()
                }
            }
            val manifestPath = staging.resolve(HASH_MANIFEST)
            require(manifestPath.exists()) { "archive is missing $HASH_MANIFEST" }
            val expected = linkedMapOf<String, String>()
            Files.newBufferedReader(manifestPath).useLines { lines ->
                lines.filter(String::isNotBlank).forEach { line ->
                    val hash = line.substringBefore("  ")
                    val relative = line.substringAfter("  ", "")
                    require(hash.matches(Regex("[a-f0-9]{64}")) && relative.isNotBlank()) {
                        "invalid archive hash manifest line"
                    }
                    validateRelativePath(relative)
                    require(relative != HASH_MANIFEST && expected.put(relative, hash) == null) {
                        "archive hash manifest contains a duplicate or self reference: $relative"
                    }
                }
            }
            require(seen == expected.keys + HASH_MANIFEST) { "archive entries do not match the hash manifest" }
            expected.forEach { (relative, hash) ->
                require(digestFile(staging.resolve(relative)) == hash) { "archive payload hash mismatch: $relative" }
            }
            if (strictControlJson) {
                for (relative in listOf("source_tree_manifest.json", "reports/build_contract.json", "reports/program_model.json")) {
                    val snapshot = decompengine.repair.readStableRegularFile(staging, relative, 4L * 1024 * 1024)
                    decompengine.oracle.core.OracleJson.parse(snapshot.bytes)
                }
            }
            validateSuccessfulBuild(staging, requireArtifact = false)
            val payload = expected.map { (relative, hash) ->
                val path = staging.resolve(relative)
                ArchivePayload(relative, path, Files.size(path), hash, 0)
            }.associateBy { it.relativePath }
            val sourceLineage = validateSourceManifest(staging, payload, profile)
            val candidateLineage = VerifiedCandidateArchiveLineage(
                archiveManifestBytes = Files.size(manifestPath),
                archiveManifestSha256 = digestFile(manifestPath),
                source = sourceLineage,
            )
            if (existingTargetIdentity != null) {
                finalizeIntoExistingTarget(staging, targetBase, existingTargetIdentity, extractedRelative.toSet())
            } else {
                try {
                    Files.move(staging, targetBase, StandardCopyOption.ATOMIC_MOVE)
                } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
                    Files.move(staging, targetBase)
                }
            }
            return VerifiedArchiveExtraction(
                paths = extractedRelative.map(targetBase::resolve),
                lineage = candidateLineage,
            )
        } finally {
            deleteTreeIfExists(staging)
        }
    }

    private data class VerifiedArchiveExtraction(
        val paths: List<Path>,
        val lineage: VerifiedCandidateArchiveLineage,
    )
}

private val requiredArchivePaths = setOf(
    "ARCHIVE_README.md",
    "BUILDING.md",
    "Makefile",
    "UNRESOLVED.md",
    "reports/archival_audit.json",
    "reports/build.log",
    "reports/build_contract.json",
    "reports/confidence.json",
    "reports/module_plan.json",
    "reports/program_model.json",
    "reports/toolchain.json",
    "source_tree_manifest.json",
)

private fun validateSuccessfulBuild(projectDir: Path, requireArtifact: Boolean = true) {
    requiredArchivePaths.filterNot { it == "ARCHIVE_README.md" || it == "reports/archival_audit.json" }
        .forEach { relative ->
            require(projectDir.resolve(relative).isRegularFile(LinkOption.NOFOLLOW_LINKS)) {
                "archive project is missing required evidence: $relative"
            }
    }
    val contract = Json.parseToJsonElement(projectDir.resolve("reports/build_contract.json").readText()).jsonObject
    require(contract["schemaVersion"]?.jsonPrimitive?.intOrNull == 2) {
        "archive build contract must use source-bound schema version 2"
    }
    require(contract["returnCode"]?.jsonPrimitive?.intOrNull == 0) { "archive build contract is not successful" }
    require(contract["sourceStableDuringBuild"]?.jsonPrimitive?.booleanOrNull == true) {
        "archive build contract does not prove stable source inputs"
    }
    require(contract["warningsAsErrors"]?.jsonPrimitive?.booleanOrNull == true) {
        "archive build contract does not enforce warnings-as-errors"
    }
    require(contract["reproduciblePathMapping"]?.jsonPrimitive?.booleanOrNull == true) {
        "archive build contract does not map workstation paths reproducibly"
    }
    require(contract["apiCredentialsRequired"]?.jsonPrimitive?.booleanOrNull == false) {
        "archive build contract requires API credentials"
    }
    require(contract["analysisCachesRequired"]?.jsonPrimitive?.booleanOrNull == false) {
        "archive build contract requires analysis caches"
    }
    val recordedInputs = contract["sourceInputs"]?.jsonArray?.map { element ->
        val item = element.jsonObject
        val relative = item["path"]?.jsonPrimitive?.content ?: error("archive build source input is missing path")
        validateRelativePath(relative)
        val bytes = item["bytes"]?.jsonPrimitive?.longOrNull
            ?: error("archive build source input is missing byte length: $relative")
        val hash = item["sha256"]?.jsonPrimitive?.content
            ?: error("archive build source input is missing SHA-256: $relative")
        require(bytes >= 0 && hash.matches(Regex("[a-f0-9]{64}"))) {
            "archive build source input is invalid: $relative"
        }
        BuildSourceInput(relative, bytes, hash)
    } ?: error("archive build contract is missing source inputs")
    require(recordedInputs == recordedInputs.sortedBy { it.path } && recordedInputs.map { it.path }.distinct().size == recordedInputs.size) {
        "archive build source inputs must be unique and sorted"
    }
    val observedRevision = captureBuildSourceRevision(projectDir)
    require(recordedInputs == observedRevision.inputs) { "archive build contract does not match the current source inputs" }
    val recordedRevision = contract["sourceRevisionSha256"]?.jsonPrimitive?.content
    require(recordedRevision == observedRevision.sha256) {
        "archive build contract does not match the current source revision"
    }
    val artifactElement = contract["artifact"]
    require(artifactElement != null && artifactElement !is JsonNull) {
        "successful archive build contract is missing its artifact identity"
    }
    val artifact = artifactElement.jsonObject
    val artifactPath = artifact["path"]?.jsonPrimitive?.content
        ?: error("archive build artifact is missing path")
    validateRelativePath(artifactPath)
    require(artifactPath == "build/reconstructed") { "archive build artifact path is unexpected: $artifactPath" }
    val artifactBytes = artifact["bytes"]?.jsonPrimitive?.longOrNull
        ?: error("archive build artifact is missing byte length")
    val artifactSha256 = artifact["sha256"]?.jsonPrimitive?.contentOrNull
        ?: error("archive build artifact is missing SHA-256")
    require(artifactBytes > 0 && artifactSha256.matches(Regex("[a-f0-9]{64}"))) {
        "archive build artifact identity is invalid"
    }
    if (requireArtifact) {
        val artifactFile = projectDir.resolve(artifactPath)
        require(Files.isRegularFile(artifactFile, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(artifactFile)) {
            "archive build artifact is missing or unsafe: $artifactPath"
        }
        require(Files.size(artifactFile) == artifactBytes && digestFile(artifactFile) == artifactSha256) {
            "archive build artifact does not match its build contract"
        }
    }
    contract["modules"]?.jsonArray.orEmpty().forEach { element ->
        val diagnostics = element.jsonObject["diagnostics"]?.jsonPrimitive?.content
            ?: error("archive build contract module is missing diagnostics")
        validateRelativePath(diagnostics)
        require(projectDir.resolve(diagnostics).isRegularFile(LinkOption.NOFOLLOW_LINKS)) {
            "archive build contract diagnostics are missing: $diagnostics"
        }
    }
}

private fun validateSourceManifest(
    projectDir: Path,
    payload: Map<String, ArchivePayload>,
    expectedProfile: ReconstructionProfile,
): VerifiedCandidateArchiveSourceLineage {
    requiredArchivePaths.forEach { relative ->
        require(relative in payload) {
            "archive payload is missing required evidence: $relative"
        }
    }
    val manifest = SourceTreeManifestReader.read(projectDir, expectedProfile)
    val oracleSha256 = manifest.inputSha256
    require(oracleSha256.matches(Regex("[a-f0-9]{64}"))) {
        "source tree manifest has an invalid oracle SHA-256"
    }
    val modelOracleSha256 = Json.parseToJsonElement(projectDir.resolve("reports/program_model.json").readText())
        .jsonObject["inputSha256"]?.jsonPrimitive?.contentOrNull
        ?: error("program model is missing its oracle identity")
    require(modelOracleSha256 == oracleSha256) {
        "program model and source tree manifest identify different oracle binaries"
    }
    manifest.files.forEach { file ->
        validateRelativePath(file.path)
        val archived = payload[file.path] ?: error("source tree manifest path is missing from archive: ${file.path}")
        require(archived.sha256 == file.sha256) { "source tree manifest hash mismatch: ${file.path}" }
        require(ProjectFileRole.MODULE_IMPLEMENTATION !in file.roles || file.acceptedImplementation != null) {
            "source tree manifest does not classify module implementation: ${file.path}"
        }
    }
    val repairLineage = RepairAcpEvidenceArchiveVerifier.verifyIfPresent(
        projectDir = projectDir,
        payloadSha256 = payload.mapValues { (_, item) -> item.sha256 },
        payloadSizes = payload.mapValues { (_, item) -> item.size },
        manifest = manifest,
        reconstructionProfile = expectedProfile,
    )
    val reconstructionContributions = ReconstructionAcpEvidenceArchiveVerifier.verify(
        projectDir = projectDir,
        payloadSha256 = payload.mapValues { (_, item) -> item.sha256 },
        payloadSizes = payload.mapValues { (_, item) -> item.size },
        manifest = manifest,
        profile = expectedProfile,
        repairLineage = repairLineage,
    )
    val sourceManifestPayload = requireNotNull(payload["source_tree_manifest.json"])
    val sourceRevision = captureBuildSourceRevision(projectDir)
    val archivedBuildInputs = payload.values.asSequence()
        .filter { item ->
            item.relativePath == "Makefile" || item.relativePath.startsWith("src/") ||
                item.relativePath.startsWith("include/")
        }
        .map { item -> BuildSourceInput(item.relativePath, item.size, item.sha256) }
        .sortedBy(BuildSourceInput::path)
        .toList()
    require(sourceRevision.inputs == archivedBuildInputs) {
        "candidate source revision differs from the authenticated archive payload"
    }
    return VerifiedCandidateArchiveSourceLineage(
        profileId = manifest.profileId,
        profileSha256 = manifest.profileSha256,
        inputSha256 = manifest.inputSha256,
        sourceTreeManifestBytes = sourceManifestPayload.size,
        sourceTreeManifestSha256 = sourceManifestPayload.sha256,
        sourceRevision = sourceRevision,
        repairGraphHeadId = repairLineage.graphHeadId,
        repairGraphHeadRevisionSha256 = repairLineage.graphHeadRevisionSha256,
        acceptedAcpContributions = reconstructionContributions + repairLineage.acceptedAcpContributions,
    )
}

private fun inspectPayload(relative: String, path: Path, limits: ArchivalBundleLimits): ArchivePayload {
    val size = Files.size(path)
    require(size in 0..limits.maximumFileBytes) { "archive payload exceeds the file limit: $relative" }
    val digest = MessageDigest.getInstance("SHA-256")
    val crc = CRC32()
    var observed = 0L
    BufferedInputStream(Files.newInputStream(path)).use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            observed += count
            digest.update(buffer, 0, count)
            crc.update(buffer, 0, count)
        }
    }
    require(observed == size) { "archive payload changed while hashing: $relative" }
    return ArchivePayload(relative, path, size, digest.digest().toHex(), crc.value)
}

private fun copyAndVerify(item: ArchivePayload, zip: ZipOutputStream) {
    val digest = MessageDigest.getInstance("SHA-256")
    var observed = 0L
    BufferedInputStream(Files.newInputStream(item.sourcePath)).use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            observed += count
            require(observed <= item.size) { "archive payload grew while packaging: ${item.relativePath}" }
            digest.update(buffer, 0, count)
            zip.write(buffer, 0, count)
        }
    }
    require(observed == item.size && digest.digest().toHex() == item.sha256) {
        "archive payload changed while packaging: ${item.relativePath}"
    }
}

private fun digestFile(path: Path): String {
    val digest = MessageDigest.getInstance("SHA-256")
    BufferedInputStream(Files.newInputStream(path)).use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
    }
    return digest.digest().toHex()
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun validateRelativePath(relative: String) {
    require(
        relative.isNotBlank() && !relative.startsWith('/') &&
            relative.length <= 4_096 &&
            relative.none { it.code < 0x20 || it.code == 0x7f || it == '\\' || it == ':' },
    ) {
        "archive path is not a safe relative path: $relative"
    }
    val segments = relative.split('/')
    require(segments.none { it.isBlank() || it == "." || it == ".." || it.length > 255 }) {
        "archive path escapes or aliases its root: $relative"
    }
    val windowsReserved = Regex("(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\\..*)?$")
    require(segments.none { it.endsWith(' ') || it.endsWith('.') || windowsReserved.matches(it) }) {
        "archive path is not portable: $relative"
    }
}

private fun portablePathKey(relative: String): String =
    Normalizer.normalize(relative, Normalizer.Form.NFC).lowercase(Locale.ROOT)

private fun archiveRelativePath(root: Path, path: Path): String =
    path.relativeTo(root).joinToString("/") { it.toString() }

private fun preflightProjectTree(projectDir: Path, limits: ArchivalBundleLimits) {
    val portablePaths = mutableSetOf<String>()
    var entryCount = 0
    Files.walk(projectDir).use { paths ->
        paths.forEach { path ->
            if (path == projectDir) return@forEach
            entryCount = Math.addExact(entryCount, 1)
            require(entryCount <= limits.maximumEntries) {
                "archive project preflight exceeds ${limits.maximumEntries} filesystem entries"
            }
            val relative = archiveRelativePath(projectDir, path)
            validateRelativePath(relative)
            require(portablePaths.add(portablePathKey(relative))) {
                "archive project contains a non-portable colliding path: $relative"
            }
            require(!Files.isSymbolicLink(path)) { "archive project contains a symbolic link: $relative" }
            if (relative == "build" || relative.startsWith("build/")) return@forEach
            if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) return@forEach
            require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                "archive project contains a non-regular file: $relative"
            }
            rejectPrivateOrCachedPath(relative)
        }
    }
}

private fun prospectiveRealPath(path: Path): Path {
    var existing = path
    val missingSegments = mutableListOf<Path>()
    while (!Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
        missingSegments.add(requireNotNull(existing.fileName))
        existing = existing.parent ?: error("archive output path has no existing ancestor: $path")
    }
    var resolved = existing.toRealPath()
    missingSegments.asReversed().forEach { segment -> resolved = resolved.resolve(segment.toString()) }
    return resolved.normalize()
}

internal fun writeProjectEvidenceAtomically(path: Path, content: String) =
    writeProjectEvidenceAtomically(path, content.toByteArray(Charsets.UTF_8))

internal fun writeProjectEvidenceAtomically(path: Path, content: ByteArray) =
    writeProjectEvidenceAtomically(path) { output -> output.write(content) }

private fun writeProjectEvidenceAtomically(path: Path, writer: (OutputStream) -> Unit) {
    val parent = requireNotNull(path.parent) { "project evidence path has no parent: $path" }
    val temporary = Files.createTempFile(parent, ".${path.fileName}.", ".tmp")
    try {
        Files.newOutputStream(temporary, StandardOpenOption.TRUNCATE_EXISTING).use(writer)
        try {
            Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
            Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING)
        }
    } finally {
        Files.deleteIfExists(temporary)
    }
}

private fun rejectPrivateOrCachedPath(relative: String) {
    val segments = relative.split('/')
    val cacheSegments = setOf(".git", ".gradle", ".ghidra", ".idea", ".codex", "__pycache__")
    require(segments.none { it in cacheSegments }) { "archive project contains cache or workstation state: $relative" }
    val name = segments.last().lowercase(Locale.ROOT)
    val credentialName = name == ".env" || name.startsWith(".env.") ||
        name in setOf(".netrc", ".npmrc", ".pypirc", "id_rsa", "id_ed25519") ||
        name.endsWith(".pem") || name.endsWith(".p12") || name.endsWith(".pfx") || name.endsWith(".key")
    require(!credentialName) { "archive project contains a credential-shaped file: $relative" }
}

private fun createSafeParents(targetBase: Path, parent: Path) {
    var current = targetBase
    targetBase.relativize(parent).forEach { segment ->
        current = current.resolve(segment)
        if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
            require(Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(current)) {
                "archive extraction parent is not a real directory: $current"
            }
        } else {
            Files.createDirectory(current)
        }
    }
}

private data class DirectoryIdentity(
    val realPath: Path,
    val fileKey: Any?,
)

private fun captureDirectoryIdentity(path: Path): DirectoryIdentity {
    val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    require(attributes.isDirectory) { "archive target is no longer a directory: $path" }
    return DirectoryIdentity(path.toRealPath(), attributes.fileKey())
}

private fun finalizeIntoExistingTarget(
    staging: Path,
    target: Path,
    expectedIdentity: DirectoryIdentity,
    expectedFiles: Set<String>,
) {
    val observedIdentity = captureDirectoryIdentity(target)
    require(
        observedIdentity.realPath == expectedIdentity.realPath &&
            (expectedIdentity.fileKey == null || observedIdentity.fileKey == expectedIdentity.fileKey),
    ) {
        "archive target changed while the bundle was being verified"
    }
    val targetEntries = Files.list(target).use { it.toList() }
    require(targetEntries.size == 1 && targetEntries.single() == staging) {
        "archive target changed while the bundle was being verified"
    }
    Files.list(staging).use { children ->
        children.sorted().toList().forEach { child ->
            val destination = target.resolve(child.fileName)
            try {
                Files.move(child, destination, StandardCopyOption.ATOMIC_MOVE)
            } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
                Files.move(child, destination)
            }
        }
    }
    Files.delete(staging)

    val expectedDirectories = buildSet {
        expectedFiles.forEach { relative ->
            val segments = relative.split('/')
            for (length in 1 until segments.size) add(segments.take(length).joinToString("/"))
        }
    }
    val observedFiles = mutableSetOf<String>()
    val observedDirectories = mutableSetOf<String>()
    Files.walk(target).use { paths ->
        paths.forEach { path ->
            if (path == target) return@forEach
            val relative = archiveRelativePath(target, path)
            require(!Files.isSymbolicLink(path)) { "archive target changed during finalization: $relative" }
            when {
                Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) -> observedDirectories += relative
                Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) -> observedFiles += relative
                else -> error("archive target contains a non-regular entry after finalization: $relative")
            }
        }
    }
    require(observedFiles == expectedFiles && observedDirectories == expectedDirectories) {
        "archive target changed during finalization"
    }
}

private fun deleteTreeIfExists(root: Path) {
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
    Files.walk(root).use { paths ->
        paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
    }
}
