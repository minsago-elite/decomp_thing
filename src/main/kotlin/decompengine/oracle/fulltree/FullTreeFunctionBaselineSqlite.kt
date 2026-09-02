package decompengine.oracle.fulltree

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxSyscallException
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.io.BufferedOutputStream
import java.io.FilterOutputStream
import java.io.OutputStream
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.DigestOutputStream
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager
import java.sql.PreparedStatement
import java.util.EnumSet
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

internal class FullTreeFunctionBaselineException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

internal data class FullTreeFunctionBaselineLimits(
    val truth: FullTreeFunctionTruthLimits = FullTreeFunctionTruthLimits(),
    val maximumBaselineBytes: Long = 4L * 1024L * 1024L * 1024L,
    val maximumDatabaseBytes: Long = 8L * 1024L * 1024L * 1024L,
    val maximumScratchBytes: Long = 16L * 1024L * 1024L * 1024L,
    val maximumEntities: Long = 50_000_000L,
    val maximumTokens: Long = 1_000_000_000L,
    val maximumEntityBytes: Int = 64 * 1024 * 1024,
    val maximumEntityNodes: Int = 1_000_000,
    val maximumStringBytes: Int = 1024 * 1024,
    val maximumTotalStringBytes: Long = 4L * 1024L * 1024L * 1024L,
    val maximumSqliteCacheBytes: Int = 16 * 1024 * 1024,
    val databaseCheckpointRows: Int = 4096,
) {
    init {
        require(maximumBaselineBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumDatabaseBytes in BASELINE_SQLITE_PAGE_BYTES..8L * 1024L * 1024L * 1024L)
        require(maximumScratchBytes in maximumDatabaseBytes..16L * 1024L * 1024L * 1024L)
        require(maximumEntities in 1L..50_000_000L)
        require(maximumTokens in 1L..1_000_000_000L)
        require(maximumEntityBytes in 1..64 * 1024 * 1024)
        require(maximumEntityNodes in 1..1_000_000)
        require(maximumStringBytes in 1..maximumEntityBytes)
        require(maximumTotalStringBytes in 1L..maximumBaselineBytes)
        require(maximumSqliteCacheBytes in 1024..64 * 1024 * 1024)
        require(databaseCheckpointRows in 1..1_000_000)
    }
}

internal data class FullTreeFunctionBaselineMetric(
    val denominator: Long,
    val recovered: Long,
    val missing: Long,
    val fabricated: Long,
    val excluded: Long,
) {
    init {
        require(denominator >= 0L && recovered >= 0L && missing >= 0L)
        require(fabricated >= 0L && excluded >= 0L)
        require(denominator == Math.addExact(recovered, missing))
    }

    fun toJson(): JsonObject = JsonObject(
        mapOf(
            "denominator" to JsonPrimitive(denominator),
            "excluded" to JsonPrimitive(excluded),
            "fabricated" to JsonPrimitive(fabricated),
            "missing" to JsonPrimitive(missing),
            "recallDenominator" to JsonPrimitive(denominator),
            "recallNumerator" to JsonPrimitive(recovered),
            "recovered" to JsonPrimitive(recovered),
        ),
    )
}

/**
 * Result of composing baseline publication with a live raw-input truth validation.
 *
 * The candidate was exact at the named boundary, but no candidate descriptor lease survives this
 * call. The result therefore cannot authorize later scoring or release.
 */
internal class FullTreeFunctionBaselineGeneration internal constructor(
    val reportSha256: String,
    val artifactSha256: String,
    val truthIndexArtifactSha256: String,
    val outputBytes: Long,
    /** Observed derivation-tree/SQLite checkpoints, not an aggregate scratch lease (#138). */
    val derivationScratchHighWaterBytes: Long,
    val aggregate: FullTreeFunctionBaselineMetric,
) {
    val candidateLeaseRetained: Boolean = false
    val downstreamScoringAuthorized: Boolean = false
    val authoritativeReleaseEvidence: Boolean = false
}

internal class FullTreeFunctionBaselineValidation internal constructor(
    val reportSha256: String,
    val artifactSha256: String,
    val truthIndexArtifactSha256: String,
    val bytes: Long,
    val shardCount: Long,
    val mismatchCount: Long,
    val aggregate: FullTreeFunctionBaselineMetric,
) {
    val authoritativeReleaseEvidence: Boolean = false
}

/** A synchronous, module-private view of the raw-derived projection held by function truth. */
internal class FullTreeFunctionBaselineRawProjection internal constructor(
    val root: Path,
    val index: JsonObject,
    val indexArtifactSha256: String,
    val counts: FullTreeFunctionTruthCounts,
    val scratchParent: Path,
    val limits: FullTreeFunctionBaselineLimits,
    private val scratchCheckpoint: (String) -> Long,
    private val runtimeCheckpoint: (String) -> Unit,
) {
    fun checkpoint(label: String): Long {
        runtimeCheckpoint(label)
        return scratchCheckpoint(label).also { observed ->
            if (observed > limits.maximumScratchBytes) {
                baselineFail("function-baseline derivation exceeds its lowered scratch bound $label")
            }
        }
    }
}

/**
 * Bounded Kotlin/JVM function-baseline generation, strict validation, and regression comparison.
 *
 * Production generation is intentionally available only through the fixed raw-projection
 * composition in [FullTreeFunctionTruthSqlite]. This object never accepts candidate truth as a
 * source of expectations and never invokes Python or ACP.
 */
internal object FullTreeFunctionBaselineSqlite {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256("full-tree-function-baseline", BASELINE_POLICY).also {
            if (it != FROZEN_BASELINE_CONFIGURATION_SHA256) {
                baselineFail("bundled function-baseline schema differs from the frozen v1 contract")
            }
        }
    }

    /**
     * The only production generation entry point. Raw inputs and the candidate are independently
     * reconciled by function truth before the private publisher can observe a projection.
     */
    internal fun generateAndPublishFromRawInputs(
        candidateRoot: Path,
        richArtifact: Path,
        strippedArtifact: Path,
        inventoryPath: Path,
        elfFunctionIndex: Path,
        observationRoot: Path,
        expectedObservationIndexArtifactSha256: String,
        scope: AuthenticatedFullTreeScope,
        scratchParent: Path,
        outputRoot: Path,
        maximumWorkers: Int,
        limits: FullTreeFunctionBaselineLimits,
    ): FullTreeFunctionBaselineGeneration = FullTreeFunctionTruthSqlite.withValidatedBaselineProjection(
        candidateRoot = candidateRoot,
        richArtifact = richArtifact,
        strippedArtifact = strippedArtifact,
        inventoryPath = inventoryPath,
        elfFunctionIndex = elfFunctionIndex,
        observationRoot = observationRoot,
        expectedObservationIndexArtifactSha256 = expectedObservationIndexArtifactSha256,
        scope = scope,
        scratchParent = scratchParent,
        outputRoot = outputRoot,
        maximumWorkers = maximumWorkers,
        limits = limits,
    ) { projection, recheck, release ->
        publishNonAuthoritativeProjection(
            projection = projection,
            outputRoot = outputRoot,
            verifyStagedBoundary = recheck,
            verifyMovedBoundary = recheck,
            finalizeBoundary = { release() },
        )
    }

    private fun publishNonAuthoritativeProjection(
        projection: FullTreeFunctionBaselineRawProjection,
        outputRoot: Path,
        verifyStagedBoundary: (String) -> Unit,
        verifyMovedBoundary: (String) -> Unit,
        finalizeBoundary: (String) -> Unit,
    ): FullTreeFunctionBaselineGeneration = translateBaselineFailures {
        val publication = FunctionBaselinePublication.create(outputRoot, projection.limits)
        var committed = false
        try {
            val generated = generateReport(projection, publication.report)
            publication.freezeAndCommit(
                generated = generated,
                scratchParent = projection.scratchParent,
                verifyStagedBoundary = verifyStagedBoundary,
                verifyMovedBoundary = verifyMovedBoundary,
                finalizeBoundary = finalizeBoundary,
            )
            committed = true
            FullTreeFunctionBaselineGeneration(
                reportSha256 = generated.reportSha256,
                artifactSha256 = generated.artifactSha256,
                truthIndexArtifactSha256 = generated.truthIndexArtifactSha256,
                outputBytes = generated.outputBytes,
                derivationScratchHighWaterBytes = generated.derivationScratchHighWaterBytes,
                aggregate = generated.aggregate,
            )
        } finally {
            if (!committed) publication.close()
        }
    }

    fun loadAndValidate(
        report: Path,
        expectedArtifactSha256: String,
        expectedTruthIndexArtifactSha256: String,
        scratchParent: Path,
        limits: FullTreeFunctionBaselineLimits = FullTreeFunctionBaselineLimits(),
    ): FullTreeFunctionBaselineValidation = translateBaselineFailures {
        requireBaselineDigest(expectedArtifactSha256, "function baseline artifact")
        requireBaselineDigest(expectedTruthIndexArtifactSha256, "function truth index artifact")
        requireDisjointBaselinePaths(report, scratchParent)
        FunctionBaselineComparisonScratch.create(scratchParent, limits).use { scratch ->
            DriverManager.getConnection(SqliteJdbcPaths.create(scratch.database)).use { connection ->
                configureBaselineDatabase(connection, limits)
                connection.autoCommit = false
                try {
                    val validation = BaselineStreamValidation(connection, "validated", limits, scratch)
                    val binding = validation.use {
                        streamBaseline(
                            report = report,
                            expectedArtifactSha256 = expectedArtifactSha256,
                            expectedTruthIndexArtifactSha256 = expectedTruthIndexArtifactSha256,
                            limits = limits,
                            validation = it,
                        )
                    }
                    connection.commit()
                    scratch.requireBound("after committing function-baseline validation")
                    binding
                } catch (failure: Throwable) {
                    runCatching { connection.rollback() }.exceptionOrNull()?.let(failure::addSuppressed)
                    throw failure
                }
            }
        }
    }

    fun requireNoRegression(
        current: Path,
        currentArtifactSha256: String,
        currentTruthIndexArtifactSha256: String,
        accepted: Path,
        acceptedArtifactSha256: String,
        acceptedTruthIndexArtifactSha256: String,
        scratchParent: Path,
        limits: FullTreeFunctionBaselineLimits = FullTreeFunctionBaselineLimits(),
    ): Unit = translateBaselineFailures {
        requireBaselineDigest(currentArtifactSha256, "current function baseline artifact")
        requireBaselineDigest(acceptedArtifactSha256, "accepted function baseline artifact")
        requireBaselineDigest(currentTruthIndexArtifactSha256, "current function truth index artifact")
        requireBaselineDigest(acceptedTruthIndexArtifactSha256, "accepted function truth index artifact")
        if (currentTruthIndexArtifactSha256 != acceptedTruthIndexArtifactSha256) {
            baselineFail("function baseline truth population differs from the accepted baseline")
        }
        requireDisjointBaselinePaths(current, scratchParent)
        requireDisjointBaselinePaths(accepted, scratchParent)
        FunctionBaselineComparisonScratch.create(scratchParent, limits).use { scratch ->
            DriverManager.getConnection(SqliteJdbcPaths.create(scratch.database)).use { connection ->
                configureBaselineDatabase(connection, limits)
                connection.autoCommit = false
                try {
                    BaselineStreamValidation(connection, "current", limits, scratch).use { validation ->
                        streamBaseline(
                            current,
                            currentArtifactSha256,
                            currentTruthIndexArtifactSha256,
                            limits,
                            validation,
                        )
                    }
                    BaselineStreamValidation(connection, "accepted", limits, scratch).use { validation ->
                        streamBaseline(
                            accepted,
                            acceptedArtifactSha256,
                            acceptedTruthIndexArtifactSha256,
                            limits,
                            validation,
                        )
                    }
                    requireSameShardPopulation(connection)
                    requireStableDenominators(connection)
                    requireStableExcludedPopulation(connection)
                    requireNoNewMismatchIdentities(connection)
                    requireNonRegressingMetrics(connection)
                    connection.commit()
                    scratch.requireBound("after committing function-baseline comparison")
                } catch (failure: Throwable) {
                    runCatching { connection.rollback() }.exceptionOrNull()?.let(failure::addSuppressed)
                    throw failure
                }
            }
        }
    }

    private fun generateReport(
        projection: FullTreeFunctionBaselineRawProjection,
        output: Path,
    ): GeneratedFunctionBaseline {
        requireBaselineDigest(projection.indexArtifactSha256, "raw-derived function truth index")
        val database = projection.scratchParent.resolve("function-baseline.sqlite")
        if (Files.exists(database, LinkOption.NOFOLLOW_LINKS)) {
            baselineFail("function-baseline scratch database already exists")
        }
        var scratchHighWater = projection.checkpoint("before creating function-baseline SQLite scratch")
        val written = try {
            DriverManager.getConnection(SqliteJdbcPaths.create(database)).use { connection ->
                configureBaselineDatabase(connection, projection.limits)
                connection.autoCommit = false
                try {
                    createBaselineTables(connection, "generated")
                    ingestRawProjection(connection, projection, scratchHighWater) { observed ->
                        scratchHighWater = maxOf(scratchHighWater, observed)
                    }
                    val aggregate = aggregateMetrics(connection, "generated")
                    val reportSha256 = digestReport(
                        connection,
                        "generated",
                        projection.indexArtifactSha256,
                        aggregate,
                        projection.limits,
                        projection::checkpoint,
                    )
                    val scratchBeforeReport = projection.checkpoint(
                        "before serializing the function-baseline report",
                    )
                    val reportScratchAllowance = projection.limits.maximumScratchBytes - scratchBeforeReport
                    val artifact = writeReport(
                        connection,
                        "generated",
                        output,
                        projection.indexArtifactSha256,
                        aggregate,
                        reportSha256,
                        projection.limits,
                        minOf(projection.limits.maximumBaselineBytes, reportScratchAllowance),
                        projection::checkpoint,
                    )
                    val scratchWithReport = checkedBaselineAdd(
                        projection.checkpoint("after writing the function-baseline report"),
                        artifact.bytes,
                        "function-baseline derivation scratch",
                    )
                    if (scratchWithReport > projection.limits.maximumScratchBytes) {
                        baselineFail("function-baseline derivation exceeds its aggregate checkpoint bound")
                    }
                    scratchHighWater = maxOf(scratchHighWater, scratchWithReport)
                    connection.commit()
                    val committedScratchWithReport = checkedBaselineAdd(
                        projection.checkpoint("after committing function-baseline report state"),
                        artifact.bytes,
                        "committed function-baseline derivation scratch",
                    )
                    if (committedScratchWithReport > projection.limits.maximumScratchBytes) {
                        baselineFail("function-baseline derivation exceeds its aggregate checkpoint bound")
                    }
                    scratchHighWater = maxOf(scratchHighWater, committedScratchWithReport)
                    GeneratedFunctionBaseline(
                        reportSha256 = reportSha256,
                        artifactSha256 = artifact.sha256,
                        truthIndexArtifactSha256 = projection.indexArtifactSha256,
                        outputBytes = artifact.bytes,
                        derivationScratchHighWaterBytes = scratchHighWater,
                        aggregate = aggregate,
                    )
                } catch (failure: Throwable) {
                    runCatching { connection.rollback() }.exceptionOrNull()?.let(failure::addSuppressed)
                    throw failure
                }
            }
        } finally {
            if (Files.exists(database, LinkOption.NOFOLLOW_LINKS)) {
                Files.delete(database)
                forceBaselineDirectory(projection.scratchParent)
            }
        }
        projection.checkpoint("after removing function-baseline SQLite scratch")
        return written
    }

    private fun ingestRawProjection(
        connection: Connection,
        projection: FullTreeFunctionBaselineRawProjection,
        initialScratchHighWater: Long,
        updateScratchHighWater: (Long) -> Unit,
    ) {
        val limits = projection.limits
        val shardRecords = projection.index.baselineArray("shards", "function truth index")
        if (shardRecords.isEmpty() || shardRecords.size.toLong() > limits.maximumEntities) {
            baselineFail("function truth shard population exceeds the baseline bound")
        }
        var totalEntities = 0L
        fun chargeEntities(count: Long, label: String) {
            totalEntities = checkedBaselineAdd(totalEntities, count, label)
            if (totalEntities > limits.maximumEntities) {
                baselineFail("function-baseline derivation exceeds its whole-run entity bound")
            }
        }
        val insertMetric = connection.prepareStatement(
            "INSERT INTO generated_metrics(" +
                "shard_id, denominator, recovered, missing, fabricated, excluded) VALUES (?, 0, 0, 0, 0, 0)",
        )
        try {
            shardRecords.forEachIndexed { index, value ->
                chargeEntities(1L, "function truth shard entity")
                val record = value as? JsonObject
                    ?: baselineFail("function truth shard record $index is not an object")
                val shardId = record.baselineString("id", "function truth shard")
                if (shardId == ELF_ONLY_BASELINE_SHARD) {
                    baselineFail("function truth shard identity is reserved")
                }
                insertMetric.setString(1, shardId)
                insertBaselineExactlyOnce(insertMetric, "generated function-baseline shard")
                if ((index + 1) % limits.databaseCheckpointRows == 0) {
                    connection.commit()
                    requireBaselineDatabaseBound(connection, limits.maximumDatabaseBytes)
                    updateScratchHighWater(
                        projection.checkpoint("while indexing function-baseline shards"),
                    )
                }
            }
            chargeEntities(1L, "ELF-only baseline shard entity")
            insertMetric.setString(1, ELF_ONLY_BASELINE_SHARD)
            insertBaselineExactlyOnce(insertMetric, "generated ELF-only function-baseline shard")
        } finally {
            insertMetric.close()
        }

        val insertMismatch = connection.prepareStatement(
            "INSERT INTO generated_mismatches(id, kind, shard_id, truth_id) VALUES (?, 'missing', ?, ?)",
        )
        val updateMetric = connection.prepareStatement(
            "UPDATE generated_metrics SET denominator=?, recovered=?, missing=?, excluded=? WHERE shard_id=?",
        )
        var rowsSinceCheckpoint = 0
        fun checkpointEntity() {
            rowsSinceCheckpoint++
            if (rowsSinceCheckpoint >= limits.databaseCheckpointRows) {
                connection.commit()
                requireBaselineDatabaseBound(connection, limits.maximumDatabaseBytes)
                updateScratchHighWater(
                    projection.checkpoint("while deriving function-baseline metrics"),
                )
                rowsSinceCheckpoint = 0
            }
        }
        try {
            shardRecords.forEachIndexed { shardIndex, rawRecord ->
                val record = rawRecord as? JsonObject
                    ?: baselineFail("function truth shard record $shardIndex is not an object")
                val shardId = record.baselineString("id", "function truth shard")
                val relative = record.baselineString("path", "function truth shard")
                if (relative != "shards/$shardId.json") {
                    baselineFail("function truth shard path is not canonical")
                }
                val path = projection.root.resolve(relative).normalize()
                if (!path.startsWith(projection.root.resolve("shards").normalize())) {
                    baselineFail("function truth shard path escapes its root")
                }
                val expectedFunctions = record.baselineLong("functions", "function truth shard")
                val expectedNonEmitted = record.baselineLong("nonEmitted", "function truth shard")
                val expectedEntities = checkedBaselineAdd(
                    expectedFunctions,
                    expectedNonEmitted,
                    "truth shard entity",
                )
                if (expectedEntities > limits.maximumEntities - totalEntities) {
                    baselineFail("function-baseline derivation exceeds its whole-run entity bound")
                }
                var functions = 0L
                var nonEmitted = 0L
                var recovered = 0L
                var missing = 0L
                var excluded = 0L
                val streamed = FullTreeCanonicalStreaming.readObject(
                    path = path,
                    label = "raw-derived function truth shard $shardId",
                    expectedSourceSha256 = record.baselineString("sha256", "function truth shard"),
                    fieldOrder = FUNCTION_TRUTH_SHARD_FIELDS,
                    arrayFields = setOf("functions", "nonEmitted"),
                    omittedDigestField = null,
                    limits = rawProjectionStreamingLimits(
                        record.baselineLong("bytes", "function truth shard"),
                        expectedEntities,
                        limits,
                    ),
                ) { field, _, entity, _ ->
                    chargeEntities(1L, "raw function truth entity")
                    when (field) {
                        "functions" -> {
                            functions = checkedBaselineAdd(functions, 1L, "truth function")
                            when (entity.baselineString("population", "truth function")) {
                                "excluded" -> excluded = checkedBaselineAdd(excluded, 1L, "excluded function")
                                "scored" -> {
                                    val surviving = entity.baselineArray("aliases", "truth function").any { aliasRaw ->
                                        val alias = aliasRaw as? JsonObject
                                            ?: baselineFail("truth function alias is not an object")
                                        alias.baselineArray("evidence", "truth function alias").any { evidenceRaw ->
                                            val evidence = evidenceRaw as? JsonObject
                                                ?: baselineFail("truth function evidence is not an object")
                                            evidence.baselineString("kind", "truth function evidence") == "elf-symbol" &&
                                                evidence.baselineString(
                                                    "locator",
                                                    "truth function evidence",
                                                ).startsWith("stripped:")
                                        }
                                    }
                                    if (surviving) {
                                        recovered = checkedBaselineAdd(recovered, 1L, "recovered function")
                                    } else {
                                        missing = checkedBaselineAdd(missing, 1L, "missing function")
                                        val truthId = entity.baselineString("id", "truth function")
                                        val mismatchId = baselineMismatchId("missing", truthId)
                                        insertMismatch.setString(1, mismatchId)
                                        insertMismatch.setString(2, shardId)
                                        insertMismatch.setString(3, truthId)
                                        insertBaselineExactlyOnce(insertMismatch, "generated function mismatch")
                                    }
                                }
                                else -> baselineFail("truth function population is invalid")
                            }
                            checkpointEntity()
                        }
                        "nonEmitted" -> {
                            nonEmitted = checkedBaselineAdd(
                                nonEmitted,
                                1L,
                                "truth non-emitted function",
                            )
                            checkpointEntity()
                        }
                        else -> baselineFail("unexpected function truth array")
                    }
                }
                if (streamed.sourceBytes != record.baselineLong("bytes", "function truth shard")) {
                    baselineFail("function truth shard byte binding differs")
                }
                if (functions != expectedFunctions || nonEmitted != expectedNonEmitted) {
                    baselineFail("function truth shard counts differ during baseline derivation")
                }
                val metric = FullTreeFunctionBaselineMetric(
                    denominator = checkedBaselineAdd(recovered, missing, "function denominator"),
                    recovered = recovered,
                    missing = missing,
                    fabricated = 0L,
                    excluded = excluded,
                )
                updateMetric.setLong(1, metric.denominator)
                updateMetric.setLong(2, metric.recovered)
                updateMetric.setLong(3, metric.missing)
                updateMetric.setLong(4, metric.excluded)
                updateMetric.setString(5, shardId)
                if (updateMetric.executeUpdate() != 1) {
                    baselineFail("generated function-baseline shard is absent")
                }
                if ((shardIndex + 1) % limits.databaseCheckpointRows == 0) {
                    projection.checkpoint("while finishing function-baseline shards")
                }
            }
        } finally {
            insertMismatch.close()
            updateMetric.close()
        }
        connection.prepareStatement(
            "UPDATE generated_metrics SET excluded=? WHERE shard_id=?",
        ).use { update ->
            update.setLong(1, projection.counts.elfOnlyRvas)
            update.setString(2, ELF_ONLY_BASELINE_SHARD)
            if (update.executeUpdate() != 1) baselineFail("ELF-only baseline shard is absent")
        }
        requireBaselineDatabaseBound(connection, limits.maximumDatabaseBytes)
        updateScratchHighWater(maxOf(initialScratchHighWater, projection.checkpoint("after deriving baseline metrics")))
    }

    private fun digestReport(
        connection: Connection,
        prefix: String,
        truthIndexSha256: String,
        aggregate: FullTreeFunctionBaselineMetric,
        limits: FullTreeFunctionBaselineLimits,
        checkpoint: (String) -> Long,
    ): String {
        val digest = MessageDigest.getInstance("SHA-256")
        DigestOutputStream(OutputStream.nullOutputStream(), digest).use { output ->
            writeReportDocument(
                connection,
                prefix,
                output,
                truthIndexSha256,
                aggregate,
                null,
                limits,
                checkpoint,
            )
        }
        return digest.digest().baselineHex()
    }

    private fun writeReport(
        connection: Connection,
        prefix: String,
        output: Path,
        truthIndexSha256: String,
        aggregate: FullTreeFunctionBaselineMetric,
        reportSha256: String,
        limits: FullTreeFunctionBaselineLimits,
        maximumOutputBytes: Long,
        checkpoint: (String) -> Long,
    ): BaselineFileDigest {
        val artifactDigest = MessageDigest.getInstance("SHA-256")
        val bounded = BaselineBoundedOutputStream(
            Files.newOutputStream(
                output,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS,
            ),
            maximumOutputBytes,
        )
        DigestOutputStream(BufferedOutputStream(bounded), artifactDigest).use { stream ->
            writeReportDocument(
                connection,
                prefix,
                stream,
                truthIndexSha256,
                aggregate,
                reportSha256,
                limits,
                checkpoint,
            )
        }
        FileChannel.open(output, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { it.force(true) }
        return BaselineFileDigest(artifactDigest.digest().baselineHex(), bounded.count)
    }

    private fun writeReportDocument(
        connection: Connection,
        prefix: String,
        output: OutputStream,
        truthIndexSha256: String,
        aggregate: FullTreeFunctionBaselineMetric,
        reportSha256: String?,
        limits: FullTreeFunctionBaselineLimits,
        checkpoint: (String) -> Long,
    ) {
        requireBaselinePrefix(prefix)
        val writer = FunctionBaselineCanonicalWriter(output)
        writer.startObject()
        writer.field("aggregate")
        writer.value(canonicalBaselineBytes(aggregate.toJson(), limits))
        writer.field("configurationSha256")
        writer.value(canonicalBaselineBytes(JsonPrimitive(configurationSha256), limits))
        writer.field("mismatches")
        writer.startArray()
        var emitted = 0
        connection.createStatement().use { statement ->
            statement.executeQuery(
                "SELECT id, kind, shard_id, truth_id FROM ${prefix}_mismatches ORDER BY id COLLATE BINARY",
            ).use { rows ->
                while (rows.next()) {
                    writer.arrayValue(
                        canonicalBaselineBytes(
                            baselineMismatch(
                                id = rows.getString(1),
                                kind = rows.getString(2),
                                shardId = rows.getString(3),
                                truthId = rows.getString(4),
                            ),
                            limits,
                        ),
                    )
                    emitted++
                    if (emitted >= limits.databaseCheckpointRows) {
                        checkpoint("while emitting function-baseline mismatches")
                        emitted = 0
                    }
                }
            }
        }
        writer.endArray()
        if (reportSha256 != null) {
            writer.field("reportSha256")
            writer.value(canonicalBaselineBytes(JsonPrimitive(reportSha256), limits))
        }
        writer.field("schemaVersion")
        writer.value(canonicalBaselineBytes(JsonPrimitive(1), limits))
        writer.field("shards")
        writer.startArray()
        connection.createStatement().use { statement ->
            statement.executeQuery(
                "SELECT shard_id, denominator, recovered, missing, fabricated, excluded " +
                    "FROM ${prefix}_metrics ORDER BY shard_id COLLATE BINARY",
            ).use { rows ->
                while (rows.next()) {
                    writer.arrayValue(
                        canonicalBaselineBytes(
                            JsonObject(
                                mapOf(
                                    "id" to JsonPrimitive(rows.getString(1)),
                                    "metric" to FullTreeFunctionBaselineMetric(
                                        denominator = rows.getLong(2),
                                        recovered = rows.getLong(3),
                                        missing = rows.getLong(4),
                                        fabricated = rows.getLong(5),
                                        excluded = rows.getLong(6),
                                    ).toJson(),
                                ),
                            ),
                            limits,
                        ),
                    )
                    emitted++
                    if (emitted >= limits.databaseCheckpointRows) {
                        checkpoint("while emitting function-baseline shard metrics")
                        emitted = 0
                    }
                }
            }
        }
        writer.endArray()
        writer.field("truthIndexSha256")
        writer.value(canonicalBaselineBytes(JsonPrimitive(truthIndexSha256), limits))
        writer.endObject()
    }

    private fun streamBaseline(
        report: Path,
        expectedArtifactSha256: String,
        expectedTruthIndexArtifactSha256: String,
        limits: FullTreeFunctionBaselineLimits,
        validation: BaselineStreamValidation,
    ): FullTreeFunctionBaselineValidation {
        var previousMismatch: String? = null
        var previousShard: String? = null
        var mismatchCount = 0L
        var shardCount = 0L
        val aggregate = MutableBaselineMetric()
        val streamed = try {
            FullTreeCanonicalStreaming.readObject(
                path = report,
                label = "function baseline",
                expectedSourceSha256 = expectedArtifactSha256,
                fieldOrder = FUNCTION_BASELINE_FIELDS,
                arrayFields = setOf("mismatches", "shards"),
                omittedDigestField = "reportSha256",
                limits = baselineStreamingLimits(limits),
            ) { field, _, entity, _ ->
                when (field) {
                    "mismatches" -> {
                        validateBaselineMismatch(entity)
                        val id = entity.baselineString("id", "function baseline mismatch")
                        previousMismatch = requireBaselineIncreasing(
                            id,
                            previousMismatch,
                            "function baseline mismatches",
                        )
                        validation.recordMismatch(entity)
                        mismatchCount = checkedBaselineAdd(mismatchCount, 1L, "baseline mismatch")
                    }
                    "shards" -> {
                        val metric = validateBaselineShard(entity)
                        val id = entity.baselineString("id", "function baseline shard")
                        previousShard = requireBaselineIncreasing(id, previousShard, "function baseline shards")
                        validation.recordMetric(id, metric)
                        aggregate.add(metric)
                        shardCount = checkedBaselineAdd(shardCount, 1L, "baseline shard")
                    }
                    else -> baselineFail("unexpected function baseline array")
                }
            }
        } catch (failure: FullTreeFunctionBaselineException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeFunctionBaselineException("cannot stream authenticated function baseline", failure)
        }
        val envelope = streamed.envelope
        try {
            OracleSchemas.validate("full-tree-function-baseline", envelope)
        } catch (failure: Exception) {
            throw FullTreeFunctionBaselineException("function baseline fails schema validation", failure)
        }
        if (envelope.baselineLong("schemaVersion", "function baseline") != 1L) {
            baselineFail("function baseline schema version differs")
        }
        if (envelope.baselineString("configurationSha256", "function baseline") != configurationSha256) {
            baselineFail("function baseline configuration binding differs")
        }
        val truthIndex = envelope.baselineString("truthIndexSha256", "function baseline")
        if (truthIndex != expectedTruthIndexArtifactSha256) {
            baselineFail("function baseline truth-index binding differs")
        }
        val reportSha256 = envelope.baselineString("reportSha256", "function baseline")
        if (streamed.canonicalWithoutOmittedFieldSha256 != reportSha256) {
            baselineFail("function baseline report hash does not reconcile")
        }
        val computed = aggregate.freeze()
        if (envelope.baselineObject("aggregate", "function baseline") != computed.toJson()) {
            baselineFail("function baseline aggregate does not reconcile")
        }
        validation.requireClosure()
        return FullTreeFunctionBaselineValidation(
            reportSha256 = reportSha256,
            artifactSha256 = streamed.sourceSha256,
            truthIndexArtifactSha256 = truthIndex,
            bytes = streamed.sourceBytes,
            shardCount = shardCount,
            mismatchCount = mismatchCount,
            aggregate = computed,
        )
    }

    private fun validateBaselineMismatch(entity: JsonObject) {
        if (entity.keys != setOf("id", "kind", "shardId", "truthId")) {
            baselineFail("function baseline mismatch fields differ")
        }
        val kind = entity.baselineString("kind", "function baseline mismatch")
        if (kind !in setOf("missing", "fabricated")) {
            baselineFail("function baseline mismatch kind is invalid")
        }
        val truthId = entity.baselineString("truthId", "function baseline mismatch")
        if (truthId.isEmpty() || truthId.codePointCount(0, truthId.length) > 256) {
            baselineFail("function baseline mismatch truth identity is invalid")
        }
        val shard = entity["shardId"]
        if (kind == "missing" && (shard !is JsonPrimitive || !shard.isString || shard.content.isEmpty())) {
            baselineFail("missing function-baseline mismatch has no shard identity")
        }
        if (
            kind == "fabricated" && shard !is JsonNull &&
            (shard !is JsonPrimitive || !shard.isString || shard.content.isEmpty())
        ) {
            baselineFail("fabricated function-baseline mismatch shard identity is invalid")
        }
        if (entity.baselineString("id", "function baseline mismatch") != baselineMismatchId(kind, truthId)) {
            baselineFail("function baseline mismatch identity does not reconcile")
        }
    }

    private fun validateBaselineShard(entity: JsonObject): FullTreeFunctionBaselineMetric {
        if (entity.keys != setOf("id", "metric")) baselineFail("function baseline shard fields differ")
        val id = entity.baselineString("id", "function baseline shard")
        if (id.isEmpty() || id.codePointCount(0, id.length) > 256) {
            baselineFail("function baseline shard identity is invalid")
        }
        return baselineMetric(entity.baselineObject("metric", "function baseline shard"))
    }

    private fun baselineMetric(value: JsonObject): FullTreeFunctionBaselineMetric {
        if (value.keys != BASELINE_METRIC_FIELDS) baselineFail("function baseline metric fields differ")
        val recovered = value.baselineLong("recovered", "function baseline metric")
        val missing = value.baselineLong("missing", "function baseline metric")
        val fabricated = value.baselineLong("fabricated", "function baseline metric")
        val excluded = value.baselineLong("excluded", "function baseline metric")
        val denominator = value.baselineLong("denominator", "function baseline metric")
        if (
            denominator != checkedBaselineAdd(recovered, missing, "function metric denominator") ||
            value.baselineLong("recallDenominator", "function baseline metric") != denominator ||
            value.baselineLong("recallNumerator", "function baseline metric") != recovered
        ) {
            baselineFail("function baseline metric equations do not reconcile")
        }
        return try {
            FullTreeFunctionBaselineMetric(denominator, recovered, missing, fabricated, excluded)
        } catch (failure: IllegalArgumentException) {
            throw FullTreeFunctionBaselineException("function baseline metric is invalid", failure)
        }
    }

    private fun requireSameShardPopulation(connection: Connection) {
        val missing = baselineScalar(
            connection,
            "SELECT COUNT(*) FROM current_metrics c LEFT JOIN accepted_metrics a " +
                "ON a.shard_id=c.shard_id WHERE a.shard_id IS NULL",
        )
        val extra = baselineScalar(
            connection,
            "SELECT COUNT(*) FROM accepted_metrics a LEFT JOIN current_metrics c " +
                "ON c.shard_id=a.shard_id WHERE c.shard_id IS NULL",
        )
        if (missing != 0L || extra != 0L) baselineFail("function baseline shard population drifted")
    }

    private fun requireStableDenominators(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.executeQuery(
                "SELECT c.shard_id FROM current_metrics c JOIN accepted_metrics a " +
                    "ON a.shard_id=c.shard_id WHERE c.denominator<>a.denominator " +
                    "ORDER BY c.shard_id COLLATE BINARY LIMIT 1",
            ).use { rows ->
                if (rows.next()) {
                    baselineFail("function denominator drifted for ${rows.getString(1)}")
                }
            }
        }
    }

    private fun requireStableExcludedPopulation(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.executeQuery(
                "SELECT c.shard_id FROM current_metrics c JOIN accepted_metrics a " +
                    "ON a.shard_id=c.shard_id WHERE c.excluded<>a.excluded " +
                    "ORDER BY c.shard_id COLLATE BINARY LIMIT 1",
            ).use { rows ->
                if (rows.next()) {
                    baselineFail("function excluded population drifted for ${rows.getString(1)}")
                }
            }
        }
    }

    private fun requireNoNewMismatchIdentities(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.executeQuery(
                "SELECT c.id FROM current_mismatches c LEFT JOIN accepted_mismatches a " +
                    "ON a.id=c.id AND a.kind=c.kind AND a.truth_id=c.truth_id " +
                    "AND ((a.shard_id IS NULL AND c.shard_id IS NULL) OR a.shard_id=c.shard_id) " +
                    "WHERE a.id IS NULL ORDER BY c.id COLLATE BINARY LIMIT 1",
            ).use { rows ->
                if (rows.next()) {
                    baselineFail("function baseline introduced mismatch identity ${rows.getString(1)}")
                }
            }
        }
    }

    private fun requireNonRegressingMetrics(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.executeQuery(
                "SELECT c.shard_id FROM current_metrics c JOIN accepted_metrics a " +
                    "ON a.shard_id=c.shard_id " +
                    "WHERE c.recovered<a.recovered OR c.fabricated>a.fabricated " +
                    "ORDER BY c.shard_id COLLATE BINARY LIMIT 1",
            ).use { rows ->
                if (rows.next()) baselineFail("function baseline regressed for ${rows.getString(1)}")
            }
        }
    }
}

private class BaselineStreamValidation(
    private val connection: Connection,
    prefix: String,
    private val limits: FullTreeFunctionBaselineLimits,
    private val scratch: FunctionBaselineComparisonScratch,
) : AutoCloseable {
    private val prefix = requireBaselinePrefix(prefix)
    private val insertMismatch: PreparedStatement
    private val insertMetric: PreparedStatement
    private var rowsSinceCheckpoint = 0

    init {
        createBaselineTables(connection, prefix)
        insertMismatch = connection.prepareStatement(
            "INSERT INTO ${prefix}_mismatches(id, kind, shard_id, truth_id) VALUES (?, ?, ?, ?)",
        )
        insertMetric = connection.prepareStatement(
            "INSERT INTO ${prefix}_metrics(" +
                "shard_id, denominator, recovered, missing, fabricated, excluded) VALUES (?, ?, ?, ?, ?, ?)",
        )
    }

    fun recordMismatch(entity: JsonObject) {
        insertMismatch.setString(1, entity.baselineString("id", "function baseline mismatch"))
        insertMismatch.setString(2, entity.baselineString("kind", "function baseline mismatch"))
        val shard = entity["shardId"]
        if (shard is JsonNull) {
            insertMismatch.setNull(3, java.sql.Types.VARCHAR)
        } else {
            insertMismatch.setString(3, entity.baselineString("shardId", "function baseline mismatch"))
        }
        insertMismatch.setString(4, entity.baselineString("truthId", "function baseline mismatch"))
        insertBaselineExactlyOnce(insertMismatch, "function baseline mismatch")
        checkpoint()
    }

    fun recordMetric(shardId: String, metric: FullTreeFunctionBaselineMetric) {
        insertMetric.setString(1, shardId)
        insertMetric.setLong(2, metric.denominator)
        insertMetric.setLong(3, metric.recovered)
        insertMetric.setLong(4, metric.missing)
        insertMetric.setLong(5, metric.fabricated)
        insertMetric.setLong(6, metric.excluded)
        insertBaselineExactlyOnce(insertMetric, "function baseline shard metric")
        checkpoint()
    }

    fun requireClosure() {
        if (baselineScalar(connection, "SELECT COUNT(*) FROM ${prefix}_metrics") == 0L) {
            baselineFail("function baseline has no shard metrics")
        }
        val elfOnly = connection.prepareStatement(
            "SELECT denominator, recovered, missing, fabricated FROM ${prefix}_metrics WHERE shard_id=?",
        )
        elfOnly.use { statement ->
            statement.setString(1, ELF_ONLY_BASELINE_SHARD)
            statement.executeQuery().use { rows ->
                if (!rows.next() || rows.getLong(1) != 0L || rows.getLong(2) != 0L ||
                    rows.getLong(3) != 0L || rows.getLong(4) != 0L || rows.next()
                ) {
                    baselineFail("ELF-only function baseline shard is absent or invalid")
                }
            }
        }
        val missingOwner = baselineScalar(
            connection,
            "SELECT COUNT(*) FROM ${prefix}_mismatches m LEFT JOIN ${prefix}_metrics s " +
                "ON s.shard_id=m.shard_id WHERE m.shard_id IS NOT NULL AND s.shard_id IS NULL",
        )
        if (missingOwner != 0L) baselineFail("function baseline mismatch owner is absent")
        val count = connection.prepareStatement(
            "SELECT COUNT(*) FROM ${prefix}_mismatches WHERE shard_id=? AND kind=?",
        )
        try {
            connection.createStatement().use { statement ->
                statement.executeQuery(
                    "SELECT shard_id, missing, fabricated FROM ${prefix}_metrics ORDER BY shard_id COLLATE BINARY",
                ).use { rows ->
                    while (rows.next()) {
                        fun mismatchCount(kind: String): Long {
                            count.setString(1, rows.getString(1))
                            count.setString(2, kind)
                            count.executeQuery().use { matches ->
                                if (!matches.next()) baselineFail("function mismatch count returned no row")
                                val result = matches.getLong(1)
                                if (matches.next()) baselineFail("function mismatch count returned extra rows")
                                return result
                            }
                        }
                        if (mismatchCount("missing") != rows.getLong(2)) {
                            baselineFail("function baseline missing mismatches do not cover shard metrics")
                        }
                    }
                }
            }
        } finally {
            count.close()
        }
        val fabricatedMetrics = baselineScalar(
            connection,
            "SELECT COALESCE(SUM(fabricated),0) FROM ${prefix}_metrics",
        )
        val fabricatedMismatches = baselineScalar(
            connection,
            "SELECT COUNT(*) FROM ${prefix}_mismatches WHERE kind='fabricated'",
        )
        if (fabricatedMetrics != fabricatedMismatches) {
            baselineFail("function baseline fabricated mismatches do not cover shard metrics")
        }
        val ownerlessFabricated = baselineScalar(
            connection,
            "SELECT COUNT(*) FROM ${prefix}_mismatches " +
                "WHERE kind='fabricated' AND shard_id IS NULL",
        )
        val ownedFabricated = fabricatedMismatches - ownerlessFabricated
        if (ownerlessFabricated == 0L) {
            val incorrectlyAssigned = baselineScalar(
                connection,
                "SELECT COUNT(*) FROM ${prefix}_metrics s WHERE s.fabricated <> " +
                    "(SELECT COUNT(*) FROM ${prefix}_mismatches m " +
                    "WHERE m.kind='fabricated' AND m.shard_id=s.shard_id)",
            )
            if (incorrectlyAssigned != 0L) {
                baselineFail("function baseline fabricated mismatches do not cover their shard metrics")
            }
        } else {
            val possibleOwnerShards = baselineScalar(
                connection,
                "SELECT COUNT(*) FROM ${prefix}_metrics WHERE fabricated>0",
            )
            if (ownedFabricated != 0L || possibleOwnerShards != 1L || ownerlessFabricated != fabricatedMetrics) {
                baselineFail("ownerless fabricated function mismatches have ambiguous shard ownership")
            }
        }
        scratch.requireBound("after closing function-baseline mismatch population")
    }

    private fun checkpoint() {
        rowsSinceCheckpoint++
        if (rowsSinceCheckpoint >= limits.databaseCheckpointRows) {
            connection.commit()
            requireBaselineDatabaseBound(connection, limits.maximumDatabaseBytes)
            scratch.requireBound("while streaming function baseline")
            rowsSinceCheckpoint = 0
        }
    }

    override fun close() {
        var failure: Throwable? = null
        runCatching { insertMismatch.close() }.exceptionOrNull()?.let { failure = it }
        runCatching { insertMetric.close() }.exceptionOrNull()?.let {
            val primary = failure
            if (primary == null) failure = it else primary.addSuppressed(it)
        }
        failure?.let { throw it }
    }
}

private class FunctionBaselineComparisonScratch private constructor(
    private val root: Path,
    private val identity: Any,
    private val maximumBytes: Long,
) : AutoCloseable {
    val database: Path = root.resolve("comparison.sqlite")

    fun requireBound(label: String): Long = baselineTreeBytes(root, maximumBytes, label)

    override fun close() {
        deleteBaselineOwnedTree(root, identity, "function-baseline comparison scratch")
    }

    companion object {
        fun create(parentPath: Path, limits: FullTreeFunctionBaselineLimits): FunctionBaselineComparisonScratch {
            val parent = requireBaselineDirectory(parentPath, "function-baseline comparison scratch parent")
            val parentIdentity = baselineDirectoryIdentity(parent, "function-baseline comparison scratch parent")
            val root = Files.createTempDirectory(
                parent,
                ".function-baseline-comparison-",
                PosixFilePermissions.asFileAttribute(BASELINE_PRIVATE_DIRECTORY_PERMISSIONS),
            )
            try {
                forceBaselineDirectory(parent)
                requireBaselineDirectoryIdentity(parent, parentIdentity, "function-baseline comparison scratch parent")
                return FunctionBaselineComparisonScratch(
                    root,
                    baselineDirectoryIdentity(root, "function-baseline comparison scratch"),
                    limits.maximumScratchBytes,
                )
            } catch (failure: Throwable) {
                runCatching {
                    if (Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
                        Files.delete(root)
                        forceBaselineDirectory(parent)
                    }
                }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

private class FunctionBaselinePublication private constructor(
    private val target: Path,
    private val staging: Path,
    val report: Path,
    private val parentIdentity: Any,
    private val stagingIdentity: Any,
    private val limits: FullTreeFunctionBaselineLimits,
) : AutoCloseable {
    private var published = false
    private var committed = false

    fun freezeAndCommit(
        generated: GeneratedFunctionBaseline,
        scratchParent: Path,
        verifyStagedBoundary: (String) -> Unit,
        verifyMovedBoundary: (String) -> Unit,
        finalizeBoundary: (String) -> Unit,
    ) {
        Files.setPosixFilePermissions(report, BASELINE_READ_ONLY_FILE_PERMISSIONS)
        Files.setPosixFilePermissions(staging, BASELINE_READ_ONLY_DIRECTORY_PERMISSIONS)
        forceBaselineDirectory(staging)
        verifyBaselineTree(staging, generated, limits)
        val staged = FullTreeFunctionBaselineSqlite.loadAndValidate(
            report,
            generated.artifactSha256,
            generated.truthIndexArtifactSha256,
            scratchParent,
            limits,
        )
        requireGeneratedBinding(staged, generated)
        verifyStagedBoundary("at the function-baseline staged publication boundary")
        verifyBaselineTree(staging, generated, limits)
        requireBaselineDirectoryIdentity(target.parent, parentIdentity, "function-baseline output parent")
        requireBaselineDirectoryIdentity(staging, stagingIdentity, "function-baseline staging root")
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) baselineFail("function-baseline output already exists")
        try {
            LinuxFilesystemSyscalls.requireSupported(target.parent)
            LinuxFilesystemSyscalls.openRoot(target.parent).use { parent ->
                parent.whileOpen { parentFd ->
                    if (!Files.isSameFile(target.parent, LinuxFilesystemSyscalls.stableDescriptorPath(parentFd))) {
                        baselineFail("function-baseline output parent changed before publication")
                    }
                    LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, target.fileName.toString())?.use {
                        baselineFail("function-baseline output already exists")
                    }
                    LinuxFilesystemSyscalls.synchronize(parent)
                    try {
                        LinuxFilesystemSyscalls.renameNoReplace(
                            parentFd,
                            staging.fileName.toString(),
                            target.fileName.toString(),
                        )
                    } catch (failure: LinuxSyscallException) {
                        if (failure.errno == LinuxFilesystemSyscalls.EEXIST) {
                            throw FullTreeFunctionBaselineException("function-baseline output already exists", failure)
                        }
                        throw failure
                    }
                    published = true
                }
                LinuxFilesystemSyscalls.synchronize(parent)
            }
            requireBaselineDirectoryIdentity(target, stagingIdentity, "published function-baseline root")
            verifyBaselineTree(target, generated, limits)
            val moved = FullTreeFunctionBaselineSqlite.loadAndValidate(
                target.resolve(BASELINE_REPORT_FILE),
                generated.artifactSha256,
                generated.truthIndexArtifactSha256,
                scratchParent,
                limits,
            )
            requireGeneratedBinding(moved, generated)
            verifyMovedBoundary("at the function-baseline moved publication boundary")
            verifyBaselineTree(target, generated, limits)
            finalizeBoundary("before finalizing the function-baseline publication boundary")
            verifyBaselineTree(target, generated, limits)
            requireBaselineDirectoryIdentity(target, stagingIdentity, "published function-baseline root")
            requireBaselineDirectoryIdentity(target.parent, parentIdentity, "function-baseline output parent")
            committed = true
        } catch (failure: Throwable) {
            if (published) runCatching { revokePublished() }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
    }

    override fun close() {
        if (committed) return
        val root = if (published) target else staging
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
        if (published) baselineFail("unverified published function baseline remains at its target")
        deleteBaselineOwnedTree(root, stagingIdentity, "function-baseline staging root")
        forceBaselineDirectory(target.parent)
    }

    private fun revokePublished() {
        requireBaselineDirectoryIdentity(target, stagingIdentity, "unverified function-baseline root")
        requireBaselineDirectoryIdentity(target.parent, parentIdentity, "function-baseline output parent")
        deleteBaselineOwnedTree(target, stagingIdentity, "unverified published function-baseline root")
        published = false
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            baselineFail("unverified function-baseline target survived revocation")
        }
        forceBaselineDirectory(target.parent)
    }

    companion object {
        fun create(path: Path, limits: FullTreeFunctionBaselineLimits): FunctionBaselinePublication {
            val target = path.toAbsolutePath().normalize()
            if (target.parent == null || target.fileName == null) baselineFail("function-baseline output must name a directory")
            val parent = requireBaselineDirectory(target.parent, "function-baseline output parent")
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) baselineFail("function-baseline output already exists")
            val parentIdentity = baselineDirectoryIdentity(parent, "function-baseline output parent")
            val staging = Files.createTempDirectory(
                parent,
                ".${target.fileName}.function-baseline-",
                PosixFilePermissions.asFileAttribute(BASELINE_PRIVATE_DIRECTORY_PERMISSIONS),
            )
            try {
                forceBaselineDirectory(parent)
                return FunctionBaselinePublication(
                    target,
                    staging,
                    staging.resolve(BASELINE_REPORT_FILE),
                    parentIdentity,
                    baselineDirectoryIdentity(staging, "function-baseline staging root"),
                    limits,
                )
            } catch (failure: Throwable) {
                runCatching {
                    if (Files.exists(staging, LinkOption.NOFOLLOW_LINKS)) Files.delete(staging)
                    forceBaselineDirectory(parent)
                }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

private data class GeneratedFunctionBaseline(
    val reportSha256: String,
    val artifactSha256: String,
    val truthIndexArtifactSha256: String,
    val outputBytes: Long,
    val derivationScratchHighWaterBytes: Long,
    val aggregate: FullTreeFunctionBaselineMetric,
)

private data class BaselineFileDigest(val sha256: String, val bytes: Long)

private class MutableBaselineMetric {
    private var recovered = 0L
    private var missing = 0L
    private var fabricated = 0L
    private var excluded = 0L

    fun add(metric: FullTreeFunctionBaselineMetric) {
        recovered = checkedBaselineAdd(recovered, metric.recovered, "aggregate recovered function")
        missing = checkedBaselineAdd(missing, metric.missing, "aggregate missing function")
        fabricated = checkedBaselineAdd(fabricated, metric.fabricated, "aggregate fabricated function")
        excluded = checkedBaselineAdd(excluded, metric.excluded, "aggregate excluded function")
    }

    fun freeze(): FullTreeFunctionBaselineMetric = FullTreeFunctionBaselineMetric(
        denominator = checkedBaselineAdd(recovered, missing, "aggregate function denominator"),
        recovered = recovered,
        missing = missing,
        fabricated = fabricated,
        excluded = excluded,
    )
}

private class FunctionBaselineCanonicalWriter(private val output: OutputStream) {
    private var fields = 0
    private var arrayValues = 0
    private var finished = false

    fun startObject() = writeAscii("{\n")

    fun field(name: String) {
        if (fields++ > 0) writeAscii(",\n")
        writeAscii("  \"$name\": ")
    }

    fun value(canonicalBytes: ByteArray) = writeCanonicalValue(canonicalBytes, 2, false)

    fun startArray() {
        arrayValues = 0
    }

    fun arrayValue(canonicalBytes: ByteArray) {
        if (arrayValues++ == 0) writeAscii("[\n") else writeAscii(",\n")
        writeCanonicalValue(canonicalBytes, 4, true)
    }

    fun endArray() {
        if (arrayValues == 0) writeAscii("[]") else writeAscii("\n  ]")
    }

    fun endObject() {
        if (finished) baselineFail("canonical function-baseline writer already finished")
        writeAscii("\n}\n")
        finished = true
    }

    private fun writeCanonicalValue(bytes: ByteArray, indentation: Int, indentFirst: Boolean) {
        if (bytes.isEmpty() || bytes.last() != '\n'.code.toByte()) {
            baselineFail("canonical function-baseline value is malformed")
        }
        if (indentFirst) writeSpaces(indentation)
        var start = 0
        for (index in 0 until bytes.lastIndex) {
            if (bytes[index] == '\n'.code.toByte()) {
                output.write(bytes, start, index - start)
                writeAscii("\n")
                writeSpaces(indentation)
                start = index + 1
            }
        }
        output.write(bytes, start, bytes.lastIndex - start)
    }

    private fun writeAscii(value: String) = output.write(value.toByteArray(StandardCharsets.US_ASCII))
    private fun writeSpaces(count: Int) = repeat(count) { output.write(' '.code) }
}

private class BaselineBoundedOutputStream(
    output: OutputStream,
    private val maximumBytes: Long,
) : FilterOutputStream(output) {
    var count: Long = 0L
        private set

    override fun write(value: Int) {
        charge(1L)
        out.write(value)
    }

    override fun write(bytes: ByteArray, offset: Int, length: Int) {
        if (length < 0) baselineFail("function-baseline output length is invalid")
        charge(length.toLong())
        out.write(bytes, offset, length)
    }

    private fun charge(bytes: Long) {
        count = checkedBaselineAdd(count, bytes, "serialized baseline byte")
        if (count > maximumBytes) baselineFail("function-baseline report exceeds its byte bound")
    }
}

private fun configureBaselineDatabase(connection: Connection, limits: FullTreeFunctionBaselineLimits) {
    connection.createStatement().use { statement ->
        // Every database is private, revocable scratch. Disabling the rollback journal makes the
        // max-page bound cover the complete on-disk SQLite footprint instead of missing a
        // transaction-sized transient sidecar; any failure discards the owned tree.
        statement.execute("PRAGMA journal_mode=OFF")
        statement.execute("PRAGMA synchronous=OFF")
        statement.execute("PRAGMA foreign_keys=ON")
        statement.execute("PRAGMA temp_store=MEMORY")
        statement.execute("PRAGMA page_size=$BASELINE_SQLITE_PAGE_BYTES")
        statement.execute("PRAGMA cache_size=-${limits.maximumSqliteCacheBytes / 1024}")
        statement.execute("PRAGMA application_id=$BASELINE_SQLITE_APPLICATION_ID")
        statement.execute("PRAGMA user_version=$BASELINE_SQLITE_SCHEMA_VERSION")
        statement.execute("PRAGMA max_page_count=${limits.maximumDatabaseBytes / BASELINE_SQLITE_PAGE_BYTES}")
    }
}

private fun createBaselineTables(connection: Connection, rawPrefix: String) {
    val prefix = requireBaselinePrefix(rawPrefix)
    connection.createStatement().use { statement ->
        statement.execute(
            "CREATE TABLE ${prefix}_metrics(" +
                "shard_id TEXT PRIMARY KEY COLLATE BINARY, denominator INTEGER NOT NULL CHECK(denominator>=0), " +
                "recovered INTEGER NOT NULL CHECK(recovered>=0), missing INTEGER NOT NULL CHECK(missing>=0), " +
                "fabricated INTEGER NOT NULL CHECK(fabricated>=0), excluded INTEGER NOT NULL CHECK(excluded>=0), " +
                "CHECK(denominator=recovered+missing)) WITHOUT ROWID",
        )
        statement.execute(
            "CREATE TABLE ${prefix}_mismatches(" +
                "id TEXT PRIMARY KEY COLLATE BINARY, kind TEXT NOT NULL COLLATE BINARY, " +
                "shard_id TEXT COLLATE BINARY, truth_id TEXT NOT NULL COLLATE BINARY, " +
                "UNIQUE(kind, truth_id), CHECK(kind IN ('missing','fabricated'))) WITHOUT ROWID",
        )
        statement.execute(
            "CREATE INDEX ${prefix}_mismatch_owner ON ${prefix}_mismatches(" +
                "shard_id COLLATE BINARY, kind COLLATE BINARY, id COLLATE BINARY)",
        )
    }
}

private fun aggregateMetrics(connection: Connection, rawPrefix: String): FullTreeFunctionBaselineMetric {
    val prefix = requireBaselinePrefix(rawPrefix)
    connection.createStatement().use { statement ->
        statement.executeQuery(
            "SELECT COALESCE(SUM(recovered),0), COALESCE(SUM(missing),0), " +
                "COALESCE(SUM(fabricated),0), COALESCE(SUM(excluded),0) FROM ${prefix}_metrics",
        ).use { rows ->
            if (!rows.next()) baselineFail("function-baseline aggregate query returned no row")
            val recovered = rows.getLong(1)
            val missing = rows.getLong(2)
            val fabricated = rows.getLong(3)
            val excluded = rows.getLong(4)
            if (rows.next()) baselineFail("function-baseline aggregate query returned extra rows")
            return FullTreeFunctionBaselineMetric(
                checkedBaselineAdd(recovered, missing, "aggregate denominator"),
                recovered,
                missing,
                fabricated,
                excluded,
            )
        }
    }
}

private fun requireBaselineDatabaseBound(connection: Connection, maximumBytes: Long) {
    connection.createStatement().use { statement ->
        val pages = statement.executeQuery("PRAGMA page_count").use { rows ->
            if (!rows.next()) baselineFail("function-baseline SQLite page count is unavailable")
            rows.getLong(1).also { if (rows.next()) baselineFail("function-baseline SQLite page count repeats") }
        }
        val pageSize = statement.executeQuery("PRAGMA page_size").use { rows ->
            if (!rows.next()) baselineFail("function-baseline SQLite page size is unavailable")
            rows.getLong(1).also { if (rows.next()) baselineFail("function-baseline SQLite page size repeats") }
        }
        if (Math.multiplyExact(pages, pageSize) > maximumBytes) {
            baselineFail("function-baseline SQLite database exceeds its byte bound")
        }
    }
}

private fun verifyBaselineTree(
    root: Path,
    generated: GeneratedFunctionBaseline,
    limits: FullTreeFunctionBaselineLimits,
) {
    requireBaselineDirectoryIdentity(root, baselineDirectoryIdentity(root, "function-baseline root"), "function-baseline root")
    var member: String? = null
    Files.newDirectoryStream(root).use { entries ->
        entries.forEach { entry ->
            if (member != null) baselineFail("function-baseline root membership differs")
            member = entry.fileName.toString()
        }
    }
    if (member != BASELINE_REPORT_FILE) baselineFail("function-baseline root membership differs")
    if (Files.getPosixFilePermissions(root, LinkOption.NOFOLLOW_LINKS) != BASELINE_READ_ONLY_DIRECTORY_PERMISSIONS) {
        baselineFail("function-baseline root permissions differ")
    }
    val report = root.resolve(BASELINE_REPORT_FILE)
    val attributes = Files.readAttributes(report, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    val links = (Files.getAttribute(report, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as? Number)?.toLong()
    if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null || links != 1L) {
        baselineFail("function-baseline report is not a singly linked regular file")
    }
    if (Files.getPosixFilePermissions(report, LinkOption.NOFOLLOW_LINKS) != BASELINE_READ_ONLY_FILE_PERMISSIONS) {
        baselineFail("function-baseline report permissions differ")
    }
    if (attributes.size() != generated.outputBytes || attributes.size() > limits.maximumBaselineBytes) {
        baselineFail("function-baseline report byte binding differs")
    }
    val initialIdentity = attributes.fileKey()
    val digest = MessageDigest.getInstance("SHA-256")
    var bytes = 0L
    Files.newInputStream(report, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { input ->
        val buffer = ByteArray(BASELINE_STREAM_BUFFER_BYTES)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            if (read == 0) continue
            bytes = checkedBaselineAdd(bytes, read.toLong(), "verified function-baseline report byte")
            if (bytes > limits.maximumBaselineBytes || bytes > generated.outputBytes) {
                baselineFail("function-baseline report byte binding differs")
            }
            digest.update(buffer, 0, read)
        }
    }
    val finalAttributes = Files.readAttributes(report, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    val finalLinks = (Files.getAttribute(report, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as? Number)?.toLong()
    if (
        !finalAttributes.isRegularFile || finalAttributes.isSymbolicLink ||
        finalAttributes.fileKey() != initialIdentity || finalLinks != 1L ||
        finalAttributes.size() != bytes || bytes != generated.outputBytes ||
        digest.digest().baselineHex() != generated.artifactSha256 ||
        Files.getPosixFilePermissions(report, LinkOption.NOFOLLOW_LINKS) != BASELINE_READ_ONLY_FILE_PERMISSIONS
    ) {
        baselineFail("function-baseline report content changed at its publication boundary")
    }
}

private fun requireGeneratedBinding(
    validation: FullTreeFunctionBaselineValidation,
    generated: GeneratedFunctionBaseline,
) {
    if (
        validation.reportSha256 != generated.reportSha256 ||
        validation.artifactSha256 != generated.artifactSha256 ||
        validation.truthIndexArtifactSha256 != generated.truthIndexArtifactSha256 ||
        validation.bytes != generated.outputBytes ||
        validation.aggregate != generated.aggregate
    ) {
        baselineFail("validated function-baseline report differs from its generated binding")
    }
}

private fun baselineMismatch(kind: String, id: String, shardId: String?, truthId: String): JsonObject = JsonObject(
    mapOf(
        "id" to JsonPrimitive(id),
        "kind" to JsonPrimitive(kind),
        "shardId" to (shardId?.let(::JsonPrimitive) ?: JsonNull),
        "truthId" to JsonPrimitive(truthId),
    ),
)

private fun baselineMismatchId(kind: String, truthId: String): String {
    val preimage = JsonObject(mapOf("kind" to JsonPrimitive(kind), "truthId" to JsonPrimitive(truthId)))
    return "$kind-function-${OracleArtifacts.sha256(OracleJson.canonicalBytes(preimage)).take(32)}"
}

private fun canonicalBaselineBytes(value: JsonElement, limits: FullTreeFunctionBaselineLimits): ByteArray = try {
    OracleJson.canonicalBytes(
        value,
        StrictJsonLimits(
            maximumInputBytes = limits.maximumEntityBytes,
            maximumCanonicalBytes = limits.maximumEntityBytes,
            maximumDepth = 128,
            maximumNodes = limits.maximumEntityNodes,
            maximumStringBytes = limits.maximumStringBytes,
            maximumTotalStringBytes = limits.maximumEntityBytes,
        ),
    )
} catch (failure: Exception) {
    throw FullTreeFunctionBaselineException("function-baseline value exceeds canonical bounds", failure)
}

private fun rawProjectionStreamingLimits(
    maximumBytes: Long,
    maximumEntities: Long,
    limits: FullTreeFunctionBaselineLimits,
): FullTreeCanonicalStreamingLimits = FullTreeCanonicalStreamingLimits(
    maximumInputBytes = maximumBytes,
    maximumTokens = limits.maximumTokens,
    maximumEntities = maxOf(1L, maximumEntities),
    maximumEntityBytes = limits.maximumEntityBytes,
    maximumEntityNodes = limits.maximumEntityNodes,
    maximumDepth = 128,
    maximumStringBytes = limits.maximumStringBytes,
    maximumTotalStringBytes = minOf(maximumBytes, limits.maximumTotalStringBytes),
    maximumNumberCharacters = 256,
)

private fun baselineStreamingLimits(limits: FullTreeFunctionBaselineLimits): FullTreeCanonicalStreamingLimits =
    FullTreeCanonicalStreamingLimits(
        maximumInputBytes = limits.maximumBaselineBytes,
        maximumTokens = limits.maximumTokens,
        maximumEntities = limits.maximumEntities,
        maximumEntityBytes = limits.maximumEntityBytes,
        maximumEntityNodes = limits.maximumEntityNodes,
        maximumDepth = 128,
        maximumStringBytes = limits.maximumStringBytes,
        maximumTotalStringBytes = minOf(limits.maximumBaselineBytes, limits.maximumTotalStringBytes),
        maximumNumberCharacters = 256,
    )

private fun requireDisjointBaselinePaths(reportPath: Path, scratchPath: Path) {
    val report = reportPath.toAbsolutePath().normalize()
    val scratch = scratchPath.toAbsolutePath().normalize()
    if (report.startsWith(scratch) || scratch.startsWith(report)) {
        baselineFail("function-baseline report and scratch paths overlap")
    }
}

private fun requireBaselineDirectory(path: Path, label: String): Path {
    val normalized = path.toAbsolutePath().normalize()
    val attributes = Files.readAttributes(normalized, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
        baselineFail("$label must be an identified real directory")
    }
    val permissions = Files.getPosixFilePermissions(normalized, LinkOption.NOFOLLOW_LINKS)
    if (PosixFilePermission.GROUP_WRITE in permissions || PosixFilePermission.OTHERS_WRITE in permissions) {
        baselineFail("$label must not be group- or other-writable")
    }
    return normalized
}

private fun baselineDirectoryIdentity(path: Path, label: String): Any {
    val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
        baselineFail("$label is not an identified real directory")
    }
    return attributes.fileKey()
}

private fun requireBaselineDirectoryIdentity(path: Path, expected: Any, label: String) {
    if (baselineDirectoryIdentity(path, label) != expected) baselineFail("$label changed identity")
}

private fun baselineTreeBytes(root: Path, maximumBytes: Long, label: String): Long {
    var bytes = 0L
    Files.walk(root).use { paths ->
        paths.forEach { path ->
            val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            if (attributes.isSymbolicLink || (!attributes.isDirectory && !attributes.isRegularFile)) {
                baselineFail("$label contains an invalid path type")
            }
            if (attributes.isRegularFile) {
                bytes = checkedBaselineAdd(bytes, attributes.size(), "$label byte")
                if (bytes > maximumBytes) baselineFail("$label exceeds its byte bound")
            }
        }
    }
    return bytes
}

private fun deleteBaselineOwnedTree(root: Path, identity: Any, label: String) {
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
    requireBaselineDirectoryIdentity(root, identity, label)
    Files.walk(root).use { paths ->
        paths.sorted(Comparator.reverseOrder()).forEach { path ->
            if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                Files.setPosixFilePermissions(path, BASELINE_PRIVATE_DIRECTORY_PERMISSIONS)
            } else if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                Files.setPosixFilePermissions(path, BASELINE_PRIVATE_FILE_PERMISSIONS)
            }
            Files.delete(path)
        }
    }
    forceBaselineDirectory(root.parent)
}

private fun forceBaselineDirectory(path: Path) {
    FileChannel.open(path, StandardOpenOption.READ).use { it.force(true) }
}

private fun requireBaselineIncreasing(value: String, previous: String?, label: String): String {
    if (previous != null && BASELINE_CODE_POINT_ORDER.compare(previous, value) >= 0) {
        baselineFail("$label are not strictly ordered")
    }
    return value
}

private fun requireBaselinePrefix(value: String): String = value.also {
    if (it !in BASELINE_TABLE_PREFIXES) baselineFail("function-baseline SQLite prefix is invalid")
}

private fun requireBaselineDigest(value: String, label: String) {
    if (!value.matches(BASELINE_SHA256)) baselineFail("$label SHA-256 is invalid")
}

private fun baselineScalar(connection: Connection, sql: String): Long =
    connection.createStatement().use { statement ->
        statement.executeQuery(sql).use { rows ->
            if (!rows.next()) baselineFail("function-baseline scalar query returned no row")
            rows.getLong(1).also { if (rows.next()) baselineFail("function-baseline scalar query returned extra rows") }
        }
    }

private fun insertBaselineExactlyOnce(statement: PreparedStatement, label: String) {
    try {
        if (statement.executeUpdate() != 1) baselineFail("$label was not inserted exactly once")
    } catch (failure: FullTreeFunctionBaselineException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeFunctionBaselineException("$label is duplicated or invalid", failure)
    }
}

private fun checkedBaselineAdd(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeFunctionBaselineException("function-baseline $label exceeds the supported range", failure)
}

private fun JsonObject.baselineString(name: String, label: String): String {
    val value = this[name] as? JsonPrimitive
    if (value == null || !value.isString) baselineFail("$label field $name must be a string")
    return value.content
}

private fun JsonObject.baselineLong(name: String, label: String): Long {
    val value = (this[name] as? JsonPrimitive)?.longOrNull
        ?: baselineFail("$label field $name must be an integer")
    if (value < 0L) baselineFail("$label field $name must be nonnegative")
    return value
}

private fun JsonObject.baselineObject(name: String, label: String): JsonObject =
    this[name] as? JsonObject ?: baselineFail("$label field $name must be an object")

private fun JsonObject.baselineArray(name: String, label: String): JsonArray =
    this[name] as? JsonArray ?: baselineFail("$label field $name must be an array")

private fun ByteArray.baselineHex(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private inline fun <T> translateBaselineFailures(action: () -> T): T = try {
    action()
} catch (failure: FullTreeFunctionBaselineException) {
    throw failure
} catch (failure: Exception) {
    throw FullTreeFunctionBaselineException("cannot process full-tree function baseline", failure)
}

private fun baselineFail(message: String): Nothing = throw FullTreeFunctionBaselineException(message)

private const val BASELINE_REPORT_FILE = "report.json"
private const val ELF_ONLY_BASELINE_SHARD = "elf-only-exclusions"
private const val BASELINE_SQLITE_PAGE_BYTES = 4096L
private const val BASELINE_SQLITE_APPLICATION_ID = 0x44434642
private const val BASELINE_SQLITE_SCHEMA_VERSION = 1
private const val BASELINE_STREAM_BUFFER_BYTES = 64 * 1024
private const val FROZEN_BASELINE_CONFIGURATION_SHA256 =
    "c29ef7047ba26e9165e78faffd5781711923f75c1fb265e5f615bfd1ffd21951"
private val BASELINE_SHA256 = Regex("[0-9a-f]{64}")
private val BASELINE_TABLE_PREFIXES = setOf("generated", "validated", "current", "accepted")
private val BASELINE_METRIC_FIELDS = setOf(
    "denominator",
    "excluded",
    "fabricated",
    "missing",
    "recallDenominator",
    "recallNumerator",
    "recovered",
)
private val FUNCTION_TRUTH_SHARD_FIELDS = listOf(
    "counts",
    "functions",
    "nonEmitted",
    "oracle",
    "schemaVersion",
    "shard",
)
private val FUNCTION_BASELINE_FIELDS = listOf(
    "aggregate",
    "configurationSha256",
    "mismatches",
    "reportSha256",
    "schemaVersion",
    "shards",
    "truthIndexSha256",
)
private val BASELINE_PRIVATE_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
private val BASELINE_READ_ONLY_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("r-x------")
private val BASELINE_PRIVATE_FILE_PERMISSIONS: Set<PosixFilePermission> = EnumSet.of(
    PosixFilePermission.OWNER_READ,
    PosixFilePermission.OWNER_WRITE,
)
private val BASELINE_READ_ONLY_FILE_PERMISSIONS: Set<PosixFilePermission> =
    EnumSet.of(PosixFilePermission.OWNER_READ)
private val BASELINE_CODE_POINT_ORDER = Comparator<String> { left, right ->
    val leftPoints = left.codePoints().iterator()
    val rightPoints = right.codePoints().iterator()
    while (leftPoints.hasNext() && rightPoints.hasNext()) {
        val compared = leftPoints.nextInt().compareTo(rightPoints.nextInt())
        if (compared != 0) return@Comparator compared
    }
    left.codePointCount(0, left.length).compareTo(right.codePointCount(0, right.length))
}
private val BASELINE_POLICY = JsonObject(
    mapOf(
        "denominator" to JsonPrimitive("scored-function-rvas"),
        "excluded" to JsonPrimitive("dwarf-only-owned-plus-elf-only-unowned-rvas"),
        "id" to JsonPrimitive("full-tree-function-baseline"),
        "recovered" to JsonPrimitive("truth-alias-has-authenticated-stripped-elf-symbol-evidence"),
        "version" to JsonPrimitive(1),
    ),
)
