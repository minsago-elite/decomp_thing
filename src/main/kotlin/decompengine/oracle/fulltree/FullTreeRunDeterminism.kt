package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileTime
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.EnumSet
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

class FullTreeRunDeterminismException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

data class FullTreeRunDeterminismLimits(
    val runLimits: BoundedShardRunLimits = BoundedShardRunLimits(),
    val maximumReportBytes: Int = 16 * 1024 * 1024,
    val maximumWallClockSeconds: Long = 3600L,
    val maximumCpuSeconds: Long = 3600L,
) {
    init {
        require(maximumReportBytes in 1..64 * 1024 * 1024)
        require(maximumWallClockSeconds in 1L..86_400L)
        require(maximumCpuSeconds in 1L..86_400L)
    }
}

data class FullTreeRunDeterminismGeneration(
    val reportSha256: String,
    val artifactSha256: String,
    val contentContractSha256: String,
    val differingShards: List<String>,
    val outputBytes: Long,
)

data class FullTreeRunDeterminismBinding(
    val reportSha256: String,
    val artifactSha256: String,
    val contentContractSha256: String,
    val firstIndexSha256: String,
    val secondIndexSha256: String,
    val differingShards: List<String>,
    val identical: Boolean,
    val shards: Long,
    val bytes: Long,
)

internal data class FullTreeRunDeterminismRuntimeSample(val wallNanos: Long, val processCpuNanos: Long)

internal fun interface FullTreeRunDeterminismRuntime {
    fun sample(stage: String): FullTreeRunDeterminismRuntimeSample
}

/**
 * Exact Kotlin/JVM implementation of the historical full-tree determinism report v2.
 *
 * Both input indexes are explicit external trust anchors. The content contract removes only
 * `bounds.maximumWorkers`; every other canonical run byte remains authoritative. Authenticated
 * output byte identities determine the differing-shard list. No worker execution occurs here.
 * Report publication is a same-filesystem atomic directory move followed by exact membership,
 * identity, permission, byte, and digest validation. Wall/CPU checks are cooperative rather than
 * operating-system hard limits, and same-owner NIO pathname swaps remain outside the trust model.
 */
object FullTreeRunDeterminism {
    fun compareAndPublish(
        firstRoot: Path,
        expectedFirstIndexSha256: String,
        secondRoot: Path,
        expectedSecondIndexSha256: String,
        outputRoot: Path,
        limits: FullTreeRunDeterminismLimits = FullTreeRunDeterminismLimits(),
    ): FullTreeRunDeterminismGeneration = exceptionBoundary {
        compareAndPublishInternal(
            firstRoot,
            expectedFirstIndexSha256,
            secondRoot,
            expectedSecondIndexSha256,
            outputRoot,
            limits,
            SYSTEM_RUNTIME,
        )
    }

    internal fun compareAndPublishForTesting(
        firstRoot: Path,
        expectedFirstIndexSha256: String,
        secondRoot: Path,
        expectedSecondIndexSha256: String,
        outputRoot: Path,
        limits: FullTreeRunDeterminismLimits = FullTreeRunDeterminismLimits(),
        runtime: FullTreeRunDeterminismRuntime,
    ): FullTreeRunDeterminismGeneration = exceptionBoundary {
        compareAndPublishInternal(
            firstRoot,
            expectedFirstIndexSha256,
            secondRoot,
            expectedSecondIndexSha256,
            outputRoot,
            limits,
            runtime,
        )
    }

    fun validate(
        outputRoot: Path,
        expectedArtifactSha256: String,
        limits: FullTreeRunDeterminismLimits = FullTreeRunDeterminismLimits(),
    ): FullTreeRunDeterminismBinding = exceptionBoundary {
        requireDigest(expectedArtifactSha256, "determinism report artifact")
        val root = requireTrustedDirectory(outputRoot, "determinism report root")
        val parentVersion = trustedDirectoryVersion(root.parent, "determinism report parent")
        val rootVersion = trustedDirectoryVersion(root, "determinism report root")
        requireReportMembership(root)
        val reportPath = root.resolve(REPORT_FILE)
        val reportVersion = trustedFileVersion(reportPath, "determinism report")
        val bytes = try {
            OracleArtifacts.read(reportPath, OracleArtifactLimits(limits.maximumReportBytes)).bytes
        } catch (failure: Exception) {
            throw FullTreeRunDeterminismException("cannot read determinism report", failure)
        }
        val artifactSha256 = sha256(bytes)
        if (artifactSha256 != expectedArtifactSha256) {
            throw FullTreeRunDeterminismException("determinism report artifact SHA-256 differs")
        }
        val report = parseAndValidateReport(bytes, limits.maximumReportBytes)
        requireReportMembership(root)
        ensureVersion(root.parent, parentVersion, "determinism report parent")
        ensureVersion(root, rootVersion, "determinism report root")
        ensureVersion(reportPath, reportVersion, "determinism report")
        binding(report, artifactSha256, bytes.size.toLong())
    }

    private fun compareAndPublishInternal(
        firstRootPath: Path,
        expectedFirstIndexSha256: String,
        secondRootPath: Path,
        expectedSecondIndexSha256: String,
        outputRoot: Path,
        limits: FullTreeRunDeterminismLimits,
        runtime: FullTreeRunDeterminismRuntime,
    ): FullTreeRunDeterminismGeneration {
        val budget = ReportBudget(limits, runtime, runtime.sample("at determinism comparison entry"))
        budget.checkpoint("before first bounded-shard run verification")
        requireDistinctOutput(outputRoot, firstRootPath, secondRootPath)
        val first = verifyRun(firstRootPath, expectedFirstIndexSha256, limits)
        budget.checkpoint("after first bounded-shard run verification")
        val second = verifyRun(secondRootPath, expectedSecondIndexSha256, limits)
        budget.checkpoint("after second bounded-shard run verification")

        val firstContract = contentContract(first.run, limits.maximumReportBytes)
        val secondContract = contentContract(second.run, limits.maximumReportBytes)
        if (!MessageDigest.isEqual(firstContract.bytes, secondContract.bytes)) {
            throw FullTreeRunDeterminismException(
                "bounded runs have different authenticated content contracts",
            )
        }
        if (first.outputs.map { it.shardId } != second.outputs.map { it.shardId }) {
            throw FullTreeRunDeterminismException("bounded runs have different shard populations")
        }
        val differing = ArrayList<String>()
        first.outputs.indices.forEach { index ->
            budget.periodicCheckpoint("while comparing authenticated shard outputs")
            val left = first.outputs[index]
            val right = second.outputs[index]
            if (left.outputBytes != right.outputBytes || left.outputSha256 != right.outputSha256) {
                differing += left.shardId
            }
        }

        val withoutHash = JsonObject(
            mapOf(
                "contentContractSha256" to JsonPrimitive(firstContract.sha256),
                "differingShards" to JsonArray(differing.map(::JsonPrimitive)),
                "firstIndexSha256" to JsonPrimitive(first.indexArtifactSha256),
                "firstRun" to runIdentity(first),
                "identical" to JsonPrimitive(differing.isEmpty()),
                "schemaVersion" to JsonPrimitive(2),
                "secondIndexSha256" to JsonPrimitive(second.indexArtifactSha256),
                "secondRun" to runIdentity(second),
                "shards" to JsonPrimitive(first.outputs.size),
            ),
        )
        val withoutHashBytes = canonicalBytes(withoutHash, limits.maximumReportBytes)
        val reportSha256 = sha256(withoutHashBytes)
        val report = JsonObject(withoutHash + ("reportSha256" to JsonPrimitive(reportSha256)))
        validateReport(report, limits.maximumReportBytes)
        val reportBytes = canonicalBytes(report, limits.maximumReportBytes)
        val artifactSha256 = sha256(reportBytes)
        budget.checkpoint("before determinism report publication")

        ReportPublication.create(outputRoot).use { publication ->
            publication.write(reportBytes)
            publication.commit(artifactSha256, reportBytes.size.toLong(), limits.maximumReportBytes, budget)
        }
        return FullTreeRunDeterminismGeneration(
            reportSha256 = reportSha256,
            artifactSha256 = artifactSha256,
            contentContractSha256 = firstContract.sha256,
            differingShards = differing.toList(),
            outputBytes = reportBytes.size.toLong(),
        )
    }

    private fun verifyRun(
        root: Path,
        expectedIndexSha256: String,
        limits: FullTreeRunDeterminismLimits,
    ): BoundedShardRunBinding = try {
        BoundedShardRunVerifier.verify(root, expectedIndexSha256, limits.runLimits)
    } catch (failure: Exception) {
        throw FullTreeRunDeterminismException("cannot authenticate bounded-shard run", failure)
    }

    private fun contentContract(run: JsonObject, maximumBytes: Int): ContentContract {
        val bounds = run.requiredObject("bounds")
        if ("maximumWorkers" !in bounds) {
            throw FullTreeRunDeterminismException("bounded-shard run omits maximumWorkers")
        }
        val contractBounds = JsonObject(bounds.filterKeys { it != "maximumWorkers" })
        val contract = JsonObject(run + ("bounds" to contractBounds))
        val bytes = canonicalBytes(contract, maximumBytes)
        return ContentContract(bytes, sha256(bytes))
    }

    private fun runIdentity(run: BoundedShardRunBinding): JsonObject = JsonObject(
        mapOf(
            "maximumWorkers" to JsonPrimitive(run.maximumWorkers),
            "runSha256" to JsonPrimitive(run.runSha256),
        ),
    )

    private fun parseAndValidateReport(bytes: ByteArray, maximumBytes: Int): JsonObject {
        if (bytes.isEmpty()) throw FullTreeRunDeterminismException("determinism report is empty")
        val report = try {
            OracleJson.parseCanonical(bytes, jsonLimits(maximumBytes)) as? JsonObject
                ?: throw FullTreeRunDeterminismException("determinism report root is not an object")
        } catch (failure: FullTreeRunDeterminismException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeRunDeterminismException("determinism report is not strict canonical JSON", failure)
        }
        validateReport(report, maximumBytes)
        return report
    }

    private fun validateReport(report: JsonObject, maximumBytes: Int) {
        try {
            OracleSchemas.validate("full-tree-determinism-report", report)
        } catch (failure: Exception) {
            throw FullTreeRunDeterminismException("determinism report fails its bundled schema", failure)
        }
        if (report.keys != REPORT_FIELDS || report.requiredLong("schemaVersion") != 2L) {
            throw FullTreeRunDeterminismException("determinism report fields or version differ")
        }
        requireDigest(report.requiredString("contentContractSha256"), "determinism content contract")
        requireDigest(report.requiredString("firstIndexSha256"), "first bounded-shard index")
        requireDigest(report.requiredString("secondIndexSha256"), "second bounded-shard index")
        validateRunIdentity(report.requiredObject("firstRun"), "first")
        validateRunIdentity(report.requiredObject("secondRun"), "second")
        val shards = report.requiredLong("shards")
        if (shards <= 0L) throw FullTreeRunDeterminismException("determinism shard count must be positive")
        val differingValues = report.requiredArray("differingShards")
        if (differingValues.size.toLong() > shards) {
            throw FullTreeRunDeterminismException("determinism differing-shard count exceeds population")
        }
        var previous: String? = null
        differingValues.forEach { value ->
            val identifier = value.requiredString("determinism differing shard")
            if (!IDENTIFIER.matches(identifier) ||
                (previous != null && FULL_TREE_CODE_POINT_ORDER.compare(previous, identifier) >= 0)
            ) {
                throw FullTreeRunDeterminismException("determinism differing shards are invalid or unordered")
            }
            previous = identifier
        }
        val identical = report.requiredBoolean("identical")
        if (identical != differingValues.isEmpty()) {
            throw FullTreeRunDeterminismException("determinism identical flag does not reconcile")
        }
        val reportSha256 = report.requiredString("reportSha256")
        requireDigest(reportSha256, "determinism report")
        val withoutHash = JsonObject(report.filterKeys { it != "reportSha256" })
        if (sha256(canonicalBytes(withoutHash, maximumBytes)) != reportSha256) {
            throw FullTreeRunDeterminismException("determinism report self-hash does not reconcile")
        }
    }

    private fun validateRunIdentity(identity: JsonObject, label: String) {
        if (identity.keys != RUN_IDENTITY_FIELDS) {
            throw FullTreeRunDeterminismException("$label determinism run identity fields differ")
        }
        val workers = identity.requiredLong("maximumWorkers")
        if (workers !in 1L..32L) {
            throw FullTreeRunDeterminismException("$label determinism worker count is invalid")
        }
        requireDigest(identity.requiredString("runSha256"), "$label determinism run")
    }

    private fun binding(report: JsonObject, artifactSha256: String, bytes: Long): FullTreeRunDeterminismBinding {
        val differing = report.requiredArray("differingShards").map {
            it.requiredString("determinism differing shard")
        }
        return FullTreeRunDeterminismBinding(
            reportSha256 = report.requiredString("reportSha256"),
            artifactSha256 = artifactSha256,
            contentContractSha256 = report.requiredString("contentContractSha256"),
            firstIndexSha256 = report.requiredString("firstIndexSha256"),
            secondIndexSha256 = report.requiredString("secondIndexSha256"),
            differingShards = differing,
            identical = report.requiredBoolean("identical"),
            shards = report.requiredLong("shards"),
            bytes = bytes,
        )
    }

    private class ReportPublication private constructor(
        private val target: Path,
        private val staging: Path,
        private val parentIdentity: Any,
        private val stagingIdentity: Any,
    ) : AutoCloseable {
        private var committed = false
        private var writtenReportIdentity: Any? = null

        fun write(bytes: ByteArray) {
            val report = staging.resolve(REPORT_FILE)
            try {
                FileChannel.open(
                    report,
                    setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
                    PosixFilePermissions.asFileAttribute(PRIVATE_FILE_PERMISSIONS),
                ).use { channel ->
                    val buffer = ByteBuffer.wrap(bytes)
                    while (buffer.hasRemaining()) channel.write(buffer)
                    channel.force(true)
                }
                writtenReportIdentity = fileIdentity(report, "staged determinism report")
            } catch (failure: Exception) {
                throw FullTreeRunDeterminismException("cannot write staged determinism report", failure)
            }
        }

        fun commit(
            expectedSha256: String,
            expectedBytes: Long,
            maximumBytes: Int,
            budget: ReportBudget,
        ) {
            val report = staging.resolve(REPORT_FILE)
            verifyPublicationTree(staging, expectedSha256, expectedBytes, maximumBytes)
            val reportIdentity = writtenReportIdentity
                ?: throw FullTreeRunDeterminismException("staged determinism report identity is unavailable")
            ensureDirectoryIdentity(staging, stagingIdentity, "determinism report staging directory")
            Files.setPosixFilePermissions(report, READ_ONLY_FILE_PERMISSIONS)
            Files.setPosixFilePermissions(staging, READ_ONLY_DIRECTORY_PERMISSIONS)
            forceDirectory(staging)
            ensureDirectoryIdentity(target.parent, parentIdentity, "determinism report output parent")
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                throw FullTreeRunDeterminismException("determinism report output already exists")
            }
            var published = false
            try {
                try {
                    Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE)
                } catch (failure: AtomicMoveNotSupportedException) {
                    throw FullTreeRunDeterminismException(
                        "filesystem cannot atomically publish determinism report directory",
                        failure,
                    )
                }
                published = true
                forceDirectory(target.parent)
                ensureDirectoryIdentity(target.parent, parentIdentity, "determinism report output parent")
                ensureDirectoryIdentity(target, stagingIdentity, "published determinism report directory")
                ensureFileIdentity(target.resolve(REPORT_FILE), reportIdentity, "published determinism report")
                if (Files.getPosixFilePermissions(target, LinkOption.NOFOLLOW_LINKS) !=
                    READ_ONLY_DIRECTORY_PERMISSIONS
                ) {
                    throw FullTreeRunDeterminismException("published determinism report permissions differ")
                }
                if (Files.getPosixFilePermissions(target.resolve(REPORT_FILE), LinkOption.NOFOLLOW_LINKS) !=
                    READ_ONLY_FILE_PERMISSIONS
                ) {
                    throw FullTreeRunDeterminismException("published determinism report file permissions differ")
                }
                verifyPublicationTree(target, expectedSha256, expectedBytes, maximumBytes)
                budget.checkpoint("after atomic determinism report publication")
                committed = true
            } catch (failure: Throwable) {
                if (published) {
                    try {
                        revokePublished(target, stagingIdentity, reportIdentity)
                    } catch (revocationFailure: Throwable) {
                        failure.addSuppressed(revocationFailure)
                    }
                }
                throw failure
            }
        }

        override fun close() {
            if (committed) return
            if (!Files.exists(staging, LinkOption.NOFOLLOW_LINKS)) return
            ensureDirectoryIdentity(staging, stagingIdentity, "determinism report staging directory")
            Files.setPosixFilePermissions(staging, PRIVATE_DIRECTORY_PERMISSIONS)
            deleteStagingTree(staging, writtenReportIdentity)
            forceDirectory(staging.parent)
        }

        companion object {
            fun create(path: Path): ReportPublication {
                val target = path.toAbsolutePath().normalize()
                if (target.fileName == null || target.parent == null) {
                    throw FullTreeRunDeterminismException("determinism report output must name a directory")
                }
                val parent = requireTrustedDirectory(target.parent, "determinism report output parent")
                if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                    throw FullTreeRunDeterminismException("determinism report output already exists")
                }
                val parentIdentity = directoryIdentity(parent, "determinism report output parent")
                forceDirectory(parent)
                var staging: Path? = null
                var stagingIdentity: Any? = null
                try {
                    val created = Files.createTempDirectory(
                        parent,
                        ".${target.fileName}.determinism-stage-",
                        PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS),
                    )
                    staging = created
                    Files.setPosixFilePermissions(created, PRIVATE_DIRECTORY_PERMISSIONS)
                    val identity = directoryIdentity(created, "determinism report staging directory")
                    stagingIdentity = identity
                    forceDirectory(parent)
                    ensureDirectoryIdentity(parent, parentIdentity, "determinism report output parent")
                    return ReportPublication(target, created, parentIdentity, identity)
                } catch (failure: Throwable) {
                    if (staging != null) {
                        try {
                            if (stagingIdentity != null) {
                                ensureDirectoryIdentity(staging, stagingIdentity, "determinism report partial staging")
                            }
                            Files.delete(staging)
                            forceDirectory(parent)
                        } catch (cleanupFailure: Throwable) {
                            failure.addSuppressed(cleanupFailure)
                        }
                    }
                    if (failure is FullTreeRunDeterminismException) throw failure
                    throw FullTreeRunDeterminismException("cannot create determinism report staging", failure)
                }
            }
        }
    }

    private class ReportBudget(
        limits: FullTreeRunDeterminismLimits,
        private val runtime: FullTreeRunDeterminismRuntime,
        private val started: FullTreeRunDeterminismRuntimeSample,
    ) {
        private val maximumWallNanos = TimeUnit.SECONDS.toNanos(limits.maximumWallClockSeconds)
        private val maximumCpuNanos = TimeUnit.SECONDS.toNanos(limits.maximumCpuSeconds)
        private var units = 0L

        fun checkpoint(stage: String) {
            if (Thread.currentThread().isInterrupted) {
                throw FullTreeRunDeterminismException("determinism comparison interrupted $stage")
            }
            val current = runtime.sample(stage)
            val wall = current.wallNanos - started.wallNanos
            val cpu = current.processCpuNanos - started.processCpuNanos
            if (wall < 0L || wall > maximumWallNanos) {
                throw FullTreeRunDeterminismException("determinism comparison exceeds wall-clock bound $stage")
            }
            if (cpu < 0L || cpu > maximumCpuNanos) {
                throw FullTreeRunDeterminismException("determinism comparison exceeds process-CPU bound $stage")
            }
        }

        fun periodicCheckpoint(stage: String) {
            units++
            if ((units and 255L) == 0L) checkpoint(stage)
        }
    }

    private data class ContentContract(val bytes: ByteArray, val sha256: String)

    private data class TrustedVersion(
        val identity: Any,
        val size: Long,
        val modified: FileTime,
        val permissions: Set<PosixFilePermission>,
        val directory: Boolean,
    )

    private fun requireDistinctOutput(output: Path, first: Path, second: Path) {
        val target = output.toAbsolutePath().normalize()
        listOf(first, second).forEach { input ->
            val normalized = input.toAbsolutePath().normalize()
            if (target == normalized || target.startsWith(normalized)) {
                throw FullTreeRunDeterminismException("determinism output must be outside both input run trees")
            }
        }
    }

    private fun requireTrustedDirectory(path: Path, label: String): Path {
        val normalized = path.toAbsolutePath().normalize()
        if (normalized.fileName == null || normalized.parent == null) {
            throw FullTreeRunDeterminismException("$label must name a directory")
        }
        val real = try {
            normalized.toRealPath()
        } catch (failure: Exception) {
            throw FullTreeRunDeterminismException("$label is unavailable", failure)
        }
        if (real != normalized) throw FullTreeRunDeterminismException("$label path contains a symbolic link")
        trustedDirectoryVersion(normalized.parent, "$label parent")
        trustedDirectoryVersion(normalized, label)
        return normalized
    }

    private fun trustedDirectoryVersion(path: Path, label: String): TrustedVersion = trustedVersion(path, label, true)

    private fun trustedFileVersion(path: Path, label: String): TrustedVersion = trustedVersion(path, label, false)

    private fun trustedVersion(path: Path, label: String, directory: Boolean): TrustedVersion {
        val attributes = try {
            Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw FullTreeRunDeterminismException("$label attributes are unavailable", failure)
        }
        if (attributes.isSymbolicLink || attributes.fileKey() == null ||
            (directory && !attributes.isDirectory) || (!directory && !attributes.isRegularFile)
        ) {
            throw FullTreeRunDeterminismException("$label has an invalid type or no stable identity")
        }
        val permissions = try {
            Files.getFileAttributeView(path, PosixFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS)
                ?.readAttributes()?.permissions()?.toSet()
                ?: throw FullTreeRunDeterminismException("$label requires POSIX permissions")
        } catch (failure: FullTreeRunDeterminismException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeRunDeterminismException("$label permissions are unavailable", failure)
        }
        if (permissions.any { it in UNTRUSTED_WRITE_PERMISSIONS }) {
            throw FullTreeRunDeterminismException("$label is writable by group or other principals")
        }
        return TrustedVersion(
            identity = attributes.fileKey(),
            size = attributes.size(),
            modified = attributes.lastModifiedTime(),
            permissions = permissions,
            directory = directory,
        )
    }

    private fun ensureVersion(path: Path, expected: TrustedVersion, label: String) {
        if (trustedVersion(path, label, expected.directory) != expected) {
            throw FullTreeRunDeterminismException("$label identity, metadata, or permissions changed")
        }
    }

    private fun requireReportMembership(root: Path) {
        val actual = Files.newDirectoryStream(root).use { entries -> entries.mapTo(linkedSetOf()) { it.fileName.toString() } }
        if (actual != setOf(REPORT_FILE)) {
            throw FullTreeRunDeterminismException("determinism report tree membership is missing or extra")
        }
        val report = root.resolve(REPORT_FILE)
        val attributes = Files.readAttributes(report, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!attributes.isRegularFile || attributes.isSymbolicLink) {
            throw FullTreeRunDeterminismException("determinism report tree contains an invalid path")
        }
    }

    private fun verifyPublicationTree(
        root: Path,
        expectedSha256: String,
        expectedBytes: Long,
        maximumBytes: Int,
    ) {
        requireReportMembership(root)
        val report = root.resolve(REPORT_FILE)
        val snapshot = try {
            OracleArtifacts.read(report, OracleArtifactLimits(maximumBytes))
        } catch (failure: Exception) {
            throw FullTreeRunDeterminismException("cannot authenticate published determinism report", failure)
        }
        if (snapshot.size.toLong() != expectedBytes || snapshot.sha256 != expectedSha256) {
            throw FullTreeRunDeterminismException("published determinism report binding differs")
        }
    }

    private fun revokePublished(path: Path, expectedIdentity: Any, expectedReportIdentity: Any) {
        ensureDirectoryIdentity(path, expectedIdentity, "unverified determinism report publication")
        ensureFileIdentity(
            path.resolve(REPORT_FILE),
            expectedReportIdentity,
            "unverified determinism report artifact",
        )
        Files.setPosixFilePermissions(path, PRIVATE_DIRECTORY_PERMISSIONS)
        deleteKnownTree(path, expectedReportIdentity)
        forceDirectory(path.parent)
    }

    private fun deleteKnownTree(path: Path, expectedReportIdentity: Any) {
        val entries = Files.newDirectoryStream(path).use { it.toList() }
        if (entries.map { it.fileName.toString() }.toSet() != setOf(REPORT_FILE)) {
            throw FullTreeRunDeterminismException("cannot safely revoke determinism tree with unexpected membership")
        }
        val report = path.resolve(REPORT_FILE)
        val attributes = Files.readAttributes(report, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!attributes.isRegularFile || attributes.isSymbolicLink) {
            throw FullTreeRunDeterminismException("cannot safely revoke determinism tree with invalid report")
        }
        ensureFileIdentity(report, expectedReportIdentity, "unverified determinism report artifact")
        Files.delete(report)
        Files.delete(path)
    }

    private fun deleteStagingTree(path: Path, expectedReportIdentity: Any?) {
        val entries = Files.newDirectoryStream(path).use { it.toList() }
        val names = entries.map { it.fileName.toString() }.toSet()
        if (names.isNotEmpty() && names != setOf(REPORT_FILE)) {
            throw FullTreeRunDeterminismException("cannot safely clean determinism staging with unexpected membership")
        }
        if (names.isNotEmpty()) {
            val report = path.resolve(REPORT_FILE)
            val attributes = Files.readAttributes(report, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            if (!attributes.isRegularFile || attributes.isSymbolicLink) {
                throw FullTreeRunDeterminismException("cannot safely clean determinism staging with invalid report")
            }
            if (expectedReportIdentity != null) {
                ensureFileIdentity(report, expectedReportIdentity, "determinism staging report")
            }
            Files.delete(report)
        }
        Files.delete(path)
    }

    private fun directoryIdentity(path: Path, label: String): Any {
        val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
            throw FullTreeRunDeterminismException("$label has no stable directory identity")
        }
        return attributes.fileKey()
    }

    private fun ensureDirectoryIdentity(path: Path, expected: Any, label: String) {
        if (directoryIdentity(path, label) != expected) {
            throw FullTreeRunDeterminismException("$label identity changed")
        }
    }

    private fun fileIdentity(path: Path, label: String): Any {
        val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
            throw FullTreeRunDeterminismException("$label has no stable regular-file identity")
        }
        return attributes.fileKey()
    }

    private fun ensureFileIdentity(path: Path, expected: Any, label: String) {
        if (fileIdentity(path, label) != expected) {
            throw FullTreeRunDeterminismException("$label identity changed")
        }
    }

    private fun forceDirectory(path: Path) {
        try {
            FileChannel.open(path, StandardOpenOption.READ).use { it.force(true) }
        } catch (failure: Exception) {
            throw FullTreeRunDeterminismException("cannot force determinism publication directory", failure)
        }
    }

    private fun canonicalBytes(document: JsonObject, maximumBytes: Int): ByteArray = try {
        OracleJson.canonicalBytes(document, jsonLimits(maximumBytes))
    } catch (failure: Exception) {
        throw FullTreeRunDeterminismException("determinism report exceeds strict JSON limits", failure)
    }

    private fun jsonLimits(maximumBytes: Int) = StrictJsonLimits(
        maximumInputBytes = maximumBytes,
        maximumCanonicalBytes = maximumBytes,
        maximumDepth = 128,
        maximumNodes = 1_000_000,
        maximumStringBytes = minOf(maximumBytes, 1024 * 1024),
        maximumTotalStringBytes = maximumBytes,
        maximumNumberCharacters = 4096,
    )

    private fun JsonObject.requiredBoolean(name: String): Boolean {
        val value = this[name] as? JsonPrimitive
            ?: throw FullTreeRunDeterminismException("determinism report field $name is not boolean")
        return value.booleanOrNull
            ?: throw FullTreeRunDeterminismException("determinism report field $name is not boolean")
    }

    private fun requireDigest(value: String, label: String) {
        if (!SHA256.matches(value)) throw FullTreeRunDeterminismException("$label SHA-256 is invalid")
    }

    private inline fun <T> exceptionBoundary(block: () -> T): T = try {
        block()
    } catch (failure: FullTreeRunDeterminismException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeRunDeterminismException("full-tree determinism operation failed: ${failure.message}", failure)
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).hex()

    private fun ByteArray.hex(): String = joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }

    private val SYSTEM_RUNTIME = FullTreeRunDeterminismRuntime {
        FullTreeRunDeterminismRuntimeSample(
            wallNanos = System.nanoTime(),
            processCpuNanos = ProcessHandle.current().info().totalCpuDuration()
                .orElseThrow { FullTreeRunDeterminismException("process CPU duration is unavailable") }
                .toNanos(),
        )
    }
    private val REPORT_FIELDS = setOf(
        "contentContractSha256",
        "differingShards",
        "firstIndexSha256",
        "firstRun",
        "identical",
        "reportSha256",
        "schemaVersion",
        "secondIndexSha256",
        "secondRun",
        "shards",
    )
    private val RUN_IDENTITY_FIELDS = setOf("maximumWorkers", "runSha256")
    private val IDENTIFIER = Regex("[a-z0-9]+(?:-[a-z0-9]+)*")
    private val SHA256 = Regex("[0-9a-f]{64}")
    private val PRIVATE_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
    private val READ_ONLY_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("r-x------")
    private val PRIVATE_FILE_PERMISSIONS: Set<PosixFilePermission> = EnumSet.of(
        PosixFilePermission.OWNER_READ,
        PosixFilePermission.OWNER_WRITE,
    )
    private val READ_ONLY_FILE_PERMISSIONS = PosixFilePermissions.fromString("r--------")
    private val UNTRUSTED_WRITE_PERMISSIONS = setOf(
        PosixFilePermission.GROUP_WRITE,
        PosixFilePermission.OTHERS_WRITE,
    )
    private const val REPORT_FILE = "report.json"
}
