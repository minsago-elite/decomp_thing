package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.io.BufferedOutputStream
import java.io.FilterOutputStream
import java.io.OutputStream
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.DigestOutputStream
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeDataBaselineException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

data class FullTreeDataBaselineLimits(
    val maximumControlArtifactBytes: Int = 16 * 1024 * 1024,
    val maximumTruthPartitionBytes: Long = 1024L * 1024L * 1024L,
    val maximumTruthBytes: Long = 16L * 1024L * 1024L * 1024L,
    val maximumReconciliationBytes: Long = 4L * 1024L * 1024L * 1024L,
    val maximumBaselineBytes: Long = 4L * 1024L * 1024L * 1024L,
    val maximumDatabaseBytes: Long = 8L * 1024L * 1024L * 1024L,
    val maximumScratchBytes: Long = 12L * 1024L * 1024L * 1024L,
    val maximumEntities: Long = 20_000_000L,
    val maximumTruthPartitionEntities: Long = 5_000_000L,
    val maximumTokens: Long = 500_000_000L,
    val maximumEntityBytes: Int = 16 * 1024 * 1024,
    val maximumEntityNodes: Int = 1_000_000,
    val maximumModeledSqliteTempBytes: Long = 64L * 1024L * 1024L,
    val maximumModeledResidentBytes: Long = 512L * 1024L * 1024L,
    val maximumWallClockSeconds: Long = 3600L,
    val maximumCpuSeconds: Long = 3600L,
    val maximumWorkers: Int = 32,
) {
    init {
        require(maximumControlArtifactBytes in 1..64 * 1024 * 1024)
        require(maximumTruthPartitionBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumTruthBytes in maximumTruthPartitionBytes..64L * 1024L * 1024L * 1024L)
        require(maximumReconciliationBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumBaselineBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumDatabaseBytes in 4L * 1024L..8L * 1024L * 1024L * 1024L)
        require(maximumScratchBytes in maximumDatabaseBytes..32L * 1024L * 1024L * 1024L)
        require(maximumEntities in 1L..50_000_000L)
        require(maximumTruthPartitionEntities in 1L..maximumEntities)
        require(maximumTokens in 1L..1_000_000_000L)
        require(maximumEntityBytes in 1..64 * 1024 * 1024)
        require(maximumEntityNodes in 1..1_000_000)
        require(maximumModeledSqliteTempBytes in 1L..1024L * 1024L * 1024L)
        require(maximumModeledResidentBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumWallClockSeconds in 1L..86_400L)
        require(maximumCpuSeconds in 1L..86_400L)
        require(maximumWorkers in 1..32)
    }
}

data class FullTreeDataBaselineGeneration(
    val reportSha256: String,
    val artifactSha256: String,
    val dataTruthIndexSha256: String,
    val reconciliationReportSha256: String,
    val outputBytes: Long,
    val aggregate: JsonObject,
)

data class FullTreeDataBaselineBinding(
    val reportSha256: String,
    val artifactSha256: String,
    val dataTruthIndexSha256: String,
    val reconciliationReportSha256: String,
    val bytes: Long,
    val shardCount: Long,
    val mismatchCount: Long,
    val aggregate: JsonObject,
)

internal data class FullTreeDataBaselineRuntimeSample(val wallNanos: Long, val processCpuNanos: Long)

internal fun interface FullTreeDataBaselineRuntime {
    fun sample(stage: String): FullTreeDataBaselineRuntimeSample
}

/**
 * Authoritative bounded Kotlin/JVM full-tree data baseline generation and comparison.
 *
 * Truth and reconciliation arrays are canonical-streamed into wholly revocable private SQLite
 * scratch. SQLite journals are disabled and temp storage is forced to memory; query plans used for
 * publication are rejected if they request a temp B-tree. Wall/CPU deadlines and resident bytes are
 * cooperative/modelled limits, not operating-system hard caps. Java NIO cannot descriptor-bind a
 * pathname across an entire read, so the regular-file and non-group-writable directory owners are
 * cooperating trust principals, as in the other Kotlin oracle stages.
 */
object FullTreeDataBaselineSqlite {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256("full-tree-data-baseline", BASELINE_POLICY)
    }

    fun generate(
        dataTruthRoot: Path,
        dataTruthIndexSha256: String,
        reconciliationReport: Path,
        reconciliationReportSha256: String,
        inventory: JsonObject,
        scopeSha256: String,
        outputRoot: Path,
        maximumWorkers: Int,
        limits: FullTreeDataBaselineLimits = FullTreeDataBaselineLimits(),
    ): FullTreeDataBaselineGeneration = generateInternal(
        dataTruthRoot,
        dataTruthIndexSha256,
        reconciliationReport,
        reconciliationReportSha256,
        inventory,
        scopeSha256,
        outputRoot,
        maximumWorkers,
        limits,
        SYSTEM_RUNTIME,
    )

    internal fun generateForTesting(
        dataTruthRoot: Path,
        dataTruthIndexSha256: String,
        reconciliationReport: Path,
        reconciliationReportSha256: String,
        inventory: JsonObject,
        scopeSha256: String,
        outputRoot: Path,
        maximumWorkers: Int,
        limits: FullTreeDataBaselineLimits = FullTreeDataBaselineLimits(),
        runtime: FullTreeDataBaselineRuntime,
    ): FullTreeDataBaselineGeneration = generateInternal(
        dataTruthRoot,
        dataTruthIndexSha256,
        reconciliationReport,
        reconciliationReportSha256,
        inventory,
        scopeSha256,
        outputRoot,
        maximumWorkers,
        limits,
        runtime,
    )

    fun validate(
        report: Path,
        expectedArtifactSha256: String,
        scratchRoot: Path,
        limits: FullTreeDataBaselineLimits = FullTreeDataBaselineLimits(),
    ): FullTreeDataBaselineBinding {
        val started = SYSTEM_RUNTIME.sample("start")
        val budget = Budget(limits, SYSTEM_RUNTIME, started)
        ComparisonScratch.create(scratchRoot, limits, budget).use { scratch ->
            return DriverManager.getConnection(SqliteJdbcPaths.create(scratch.database)).use { connection ->
                configureDatabase(connection, limits)
                connection.autoCommit = false
                try {
                    val validation = StreamValidation(connection, "baseline")
                    val binding = validation.use {
                        streamBaseline(
                            report,
                            expectedArtifactSha256,
                            limits,
                            budget,
                            validation = it,
                        )
                    }
                    requireDatabaseBound(connection, limits.maximumDatabaseBytes)
                    connection.commit()
                    binding
                } catch (failure: Throwable) {
                    try {
                        connection.rollback()
                    } catch (rollbackFailure: Throwable) {
                        failure.addSuppressed(rollbackFailure)
                    }
                    throw baselineFailure("cannot validate authenticated data baseline", failure)
                }
            }.also { scratch.requireBound() }
        }
    }

    fun requireNoRegression(
        current: Path,
        currentArtifactSha256: String,
        accepted: Path,
        acceptedArtifactSha256: String,
        scratchRoot: Path,
        limits: FullTreeDataBaselineLimits = FullTreeDataBaselineLimits(),
    ) {
        requireDigest(currentArtifactSha256, "current data baseline")
        requireDigest(acceptedArtifactSha256, "accepted data baseline")
        val started = SYSTEM_RUNTIME.sample("start")
        val budget = Budget(limits, SYSTEM_RUNTIME, started)
        ComparisonScratch.create(scratchRoot, limits, budget).use { scratch ->
            DriverManager.getConnection(SqliteJdbcPaths.create(scratch.database)).use { connection ->
                configureDatabase(connection, limits)
                connection.autoCommit = false
                try {
                    createComparisonSchema(connection)
                    val insert = connection.prepareStatement(
                        "INSERT INTO current_metrics(shard_id, dimension, denominator, exact, fabricated) " +
                            "VALUES (?, ?, ?, ?, ?)",
                    )
                    insert.use { currentInsert ->
                        val validation = StreamValidation(connection, "current")
                        validation.use { currentValidation ->
                            streamBaseline(
                                current,
                                currentArtifactSha256,
                                limits,
                                budget,
                                validation = currentValidation,
                            ) { shard ->
                                DIMENSIONS.forEach { dimension ->
                                    val metric = shard.requiredObject(dimension)
                                    currentInsert.setString(1, shard.requiredString("id"))
                                    currentInsert.setString(2, dimension)
                                    currentInsert.setLong(3, metric.requiredLong("denominator"))
                                    currentInsert.setLong(4, metric.requiredLong("exact"))
                                    currentInsert.setLong(5, metric.requiredLong("fabricated"))
                                    insertExactlyOnce(currentInsert, "current baseline shard metric")
                                }
                            }
                        }
                    }
                    val lookup = connection.prepareStatement(
                        "SELECT denominator, exact, fabricated FROM current_metrics " +
                            "WHERE shard_id = ? AND dimension = ?",
                    )
                    val mark = connection.prepareStatement(
                        "UPDATE current_metrics SET seen = 1 WHERE shard_id = ? AND dimension = ?",
                    )
                    try {
                        val validation = StreamValidation(connection, "accepted")
                        validation.use { acceptedValidation ->
                            streamBaseline(
                                accepted,
                                acceptedArtifactSha256,
                                limits,
                                budget,
                                validation = acceptedValidation,
                            ) { shard ->
                                DIMENSIONS.forEach { dimension ->
                                    val prior = shard.requiredObject(dimension)
                                    lookup.setString(1, shard.requiredString("id"))
                                    lookup.setString(2, dimension)
                                    lookup.executeQuery().use { rows ->
                                        if (!rows.next()) {
                                            throw FullTreeDataBaselineException(
                                                "data baseline shard population drifted",
                                            )
                                        }
                                        val denominator = rows.getLong(1)
                                        val exact = rows.getLong(2)
                                        val fabricated = rows.getLong(3)
                                        if (rows.next()) {
                                            throw FullTreeDataBaselineException(
                                                "data baseline metric identity is duplicated",
                                            )
                                        }
                                        if (denominator != prior.requiredLong("denominator")) {
                                            throw FullTreeDataBaselineException(
                                                "$dimension denominator drifted for ${shard.requiredString("id")}",
                                            )
                                        }
                                        if (exact < prior.requiredLong("exact") ||
                                            fabricated > prior.requiredLong("fabricated")
                                        ) {
                                            throw FullTreeDataBaselineException(
                                                "$dimension baseline regressed for ${shard.requiredString("id")}",
                                            )
                                        }
                                    }
                                    mark.setString(1, shard.requiredString("id"))
                                    mark.setString(2, dimension)
                                    if (mark.executeUpdate() != 1) {
                                        throw FullTreeDataBaselineException("data baseline shard population drifted")
                                    }
                                }
                            }
                        }
                    } finally {
                        lookup.close()
                        mark.close()
                    }
                    connection.createStatement().use { statement ->
                        statement.executeQuery("SELECT COUNT(*) FROM current_metrics WHERE seen = 0").use { rows ->
                            if (!rows.next() || rows.getLong(1) != 0L || rows.next()) {
                                throw FullTreeDataBaselineException("data baseline shard population drifted")
                            }
                        }
                    }
                    connection.commit()
                    requireDatabaseBound(connection, limits.maximumDatabaseBytes)
                } catch (failure: Throwable) {
                    try {
                        connection.rollback()
                    } catch (rollbackFailure: Throwable) {
                        failure.addSuppressed(rollbackFailure)
                    }
                    throw baselineFailure("cannot compare authenticated data baselines", failure)
                }
            }
            scratch.requireBound()
        }
    }

    private fun generateInternal(
        dataTruthRoot: Path,
        dataTruthIndexSha256: String,
        reconciliationReport: Path,
        reconciliationReportSha256: String,
        inventory: JsonObject,
        scopeSha256: String,
        outputRoot: Path,
        maximumWorkers: Int,
        limits: FullTreeDataBaselineLimits,
        runtime: FullTreeDataBaselineRuntime,
    ): FullTreeDataBaselineGeneration {
        val started = runtime.sample("start")
        requireDigest(dataTruthIndexSha256, "data truth index")
        requireDigest(reconciliationReportSha256, "data reconciliation report")
        requireDigest(scopeSha256, "scope")
        if (maximumWorkers !in 1..limits.maximumWorkers) {
            throw FullTreeDataBaselineException("data baseline worker count exceeds its configured bound")
        }
        val authenticatedInventory = canonicalControlSnapshot(inventory, "inventory", limits)
        val budget = Budget(limits, runtime, started)
        budget.checkpoint("after baseline control snapshot")
        val inventoryBinding = authenticateInventory(authenticatedInventory, scopeSha256, limits, budget)
        requireModeledResidentBound(maximumWorkers, limits)
        val truth = authenticateTruthIndex(
            dataTruthRoot,
            dataTruthIndexSha256,
            inventoryBinding,
            scopeSha256,
            limits,
            budget,
        )
        val publication = BaselinePublication.create(outputRoot, budget)
        var complete = false
        var primaryFailure: Throwable? = null
        try {
            val database = publication.scratch.resolve("baseline.sqlite")
            val written = DriverManager.getConnection(SqliteJdbcPaths.create(database)).use { connection ->
                configureDatabase(connection, limits)
                connection.autoCommit = false
                try {
                    createGenerationSchema(connection)
                    initializeMetrics(connection, inventoryBinding.shardIds)
                    val truthCounts = ingestTruth(
                        connection,
                        truth,
                        inventoryBinding,
                        limits,
                        budget,
                    )
                    requireDatabaseBound(connection, limits.maximumDatabaseBytes)
                    publication.requireBound(limits.maximumScratchBytes)
                    val reconciliationCounts = ingestReconciliation(
                        connection,
                        reconciliationReport,
                        reconciliationReportSha256,
                        dataTruthIndexSha256,
                        inventoryBinding,
                        scopeSha256,
                        truthCounts,
                        limits,
                        budget,
                    )
                    finalizeGlobalMetrics(connection, budget)
                    requireCompletePopulation(connection, truthCounts, reconciliationCounts, budget)
                    requireNoTempBTreePlans(connection)
                    val aggregate = aggregateMetrics(connection, budget)
                    validateGeneratedMetricEquations(connection, aggregate, budget)
                    connection.commit()
                    requireDatabaseBound(connection, limits.maximumDatabaseBytes)
                    publication.requireBound(limits.maximumScratchBytes)
                    writeReport(
                        connection,
                        publication.staging.resolve("report.json"),
                        dataTruthIndexSha256,
                        reconciliationReportSha256,
                        aggregate,
                        limits,
                        budget,
                    ).also {
                        requireDatabaseBound(connection, limits.maximumDatabaseBytes)
                        publication.requireBound(limits.maximumScratchBytes)
                        budget.checkpoint("after bounded data baseline report validation")
                    }
                } catch (failure: Throwable) {
                    try {
                        connection.rollback()
                    } catch (rollbackFailure: Throwable) {
                        failure.addSuppressed(rollbackFailure)
                    }
                    throw baselineFailure("cannot generate authenticated data baseline", failure)
                }
            }
            publication.requireBound(limits.maximumScratchBytes)
            budget.checkpoint("before removing data baseline SQLite scratch")
            Files.delete(database)
            budget.checkpoint("before atomic data baseline publication")
            publication.commit(written.artifactSha256, written.bytes, limits.maximumBaselineBytes, budget)
            complete = true
            return FullTreeDataBaselineGeneration(
                reportSha256 = written.reportSha256,
                artifactSha256 = written.artifactSha256,
                dataTruthIndexSha256 = dataTruthIndexSha256,
                reconciliationReportSha256 = reconciliationReportSha256,
                outputBytes = written.bytes,
                aggregate = written.aggregate,
            )
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            if (!complete) {
                try {
                    publication.close()
                } catch (cleanupFailure: Throwable) {
                    primaryFailure?.addSuppressed(cleanupFailure) ?: throw cleanupFailure
                }
            }
        }
    }

    private fun authenticateInventory(
        inventory: JsonObject,
        scopeSha256: String,
        limits: FullTreeDataBaselineLimits,
        budget: Budget,
    ): InventoryBinding {
        try {
            OracleSchemas.validate("full-tree-inventory", inventory)
        } catch (failure: Exception) {
            throw FullTreeDataBaselineException("data baseline inventory fails schema validation", failure)
        }
        if (inventory.requiredObject("oracle").requiredString("scopeSha256") != scopeSha256) {
            throw FullTreeDataBaselineException("data baseline inventory scope binding differs")
        }
        val units = inventory.requiredArray("units").objects("inventory unit")
        if (units.size.toLong() > limits.maximumEntities) {
            throw FullTreeDataBaselineException("data baseline inventory exceeds its entity limit")
        }
        if (units != units.sortedWith(INVENTORY_UNIT_COMPARATOR)) {
            throw FullTreeDataBaselineException("data baseline inventory units are not canonically ordered")
        }
        val ids = units.map { it.requiredString("id") }
        val paths = units.map { it.requiredString("sourcePath") }
        if (ids.distinct().size != ids.size || paths.distinct().size != paths.size) {
            throw FullTreeDataBaselineException("data baseline inventory unit identities are duplicated")
        }
        val indexDigest = MessageDigest.getInstance("SHA-256")
        indexDigest.update(INVENTORY_INDEX_DOMAIN)
        units.forEach { unit ->
            budget.periodicCheckpoint("while authenticating baseline inventory")
            indexDigest.update(MessageDigest.getInstance("SHA-256").digest(canonicalEntity(unit, limits)))
        }
        val indexSha256 = indexDigest.digest().hex()
        if (inventory.requiredString("indexSha256") != indexSha256) {
            throw FullTreeDataBaselineException("data baseline inventory index hash does not reconcile")
        }
        val grouped = units.groupBy { it.requiredString("shardId") }
        val orderedGroups = java.util.TreeMap<String, List<JsonObject>>(CODE_POINT_STRING_COMPARATOR).apply {
            putAll(grouped)
        }
        if (orderedGroups.containsKey(ELF_ONLY_SHARD)) {
            throw FullTreeDataBaselineException("inventory collides with the reserved elf-only baseline shard")
        }
        val expectedShards = orderedGroups.map { (id, owned) ->
            JsonObject(
                mapOf(
                    "id" to JsonPrimitive(id),
                    "unitIds" to JsonArray(
                        owned.map { it.requiredString("id") }.sortedWith(CODE_POINT_STRING_COMPARATOR)
                            .map(::JsonPrimitive),
                    ),
                ),
            )
        }
        if (inventory.requiredArray("shards") != JsonArray(expectedShards)) {
            throw FullTreeDataBaselineException("data baseline inventory shard ownership does not reconcile")
        }
        val counts = inventory.requiredObject("counts")
        val generated = units.count { it.requiredString("sourceKind") == "generated" }.toLong()
        if (counts.requiredLong("compilationUnits") != units.size.toLong() ||
            counts.requiredLong("generatedUnits") != generated ||
            counts.requiredLong("handwrittenUnits") != units.size.toLong() - generated ||
            counts.requiredLong("shards") != expectedShards.size.toLong()
        ) {
            throw FullTreeDataBaselineException("data baseline inventory counts do not reconcile")
        }
        return InventoryBinding(
            indexSha256 = indexSha256,
            shardIds = expectedShards.map { it.requiredString("id") },
            shardUnits = expectedShards.associate { shard ->
                shard.requiredString("id") to shard.requiredArray("unitIds").map {
                    it.requiredString("inventory shard unit")
                }
            },
            unitToShard = units.associate { it.requiredString("id") to it.requiredString("shardId") },
        ).also { budget.checkpoint("after authenticating baseline inventory") }
    }

    private fun authenticateTruthIndex(
        rootPath: Path,
        expectedSha256: String,
        inventory: InventoryBinding,
        scopeSha256: String,
        limits: FullTreeDataBaselineLimits,
        budget: Budget,
    ): TruthInputs {
        val root = requireRealTrustedDirectory(rootPath, "data baseline truth root")
        val snapshot = try {
            OracleArtifacts.read(
                root.resolve("index.json"),
                OracleArtifactLimits(limits.maximumControlArtifactBytes),
            )
        } catch (failure: Exception) {
            throw FullTreeDataBaselineException("cannot read authenticated data truth index", failure)
        }
        if (snapshot.sha256 != expectedSha256) {
            throw FullTreeDataBaselineException("data truth index artifact SHA-256 differs")
        }
        val index = try {
            OracleJson.parseCanonical(snapshot.bytes, controlJsonLimits(limits)) as? JsonObject
                ?: throw FullTreeDataBaselineException("data truth index must be an object")
        } catch (failure: FullTreeDataBaselineException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeDataBaselineException("data truth index is not strict canonical JSON", failure)
        }
        try {
            OracleSchemas.validate("full-tree-data-truth-index", index)
        } catch (failure: Exception) {
            throw FullTreeDataBaselineException("data truth index fails schema validation", failure)
        }
        budget.checkpoint("after data truth index snapshot")
        val withoutHash = JsonObject(index.filterKeys { it != "indexSha256" })
        if (index.requiredString("indexSha256") != OracleArtifacts.sha256(canonicalControlBytes(withoutHash, limits))) {
            throw FullTreeDataBaselineException("data truth index self hash does not reconcile")
        }
        val oracle = index.requiredObject("oracle")
        if (oracle.requiredString("configurationSha256") != FullTreeDataTruthSqlite.configurationSha256 ||
            oracle.requiredString("inventoryIndexSha256") != inventory.indexSha256 ||
            oracle.requiredString("scopeSha256") != scopeSha256
        ) {
            throw FullTreeDataBaselineException("data truth index bindings differ")
        }
        requireDigest(oracle.requiredString("dataObservationIndexSha256"), "data observation index")
        val records = index.requiredArray("shards").objects("data truth index shard")
        if (records.isEmpty() || records.size.toLong() > limits.maximumEntities) {
            throw FullTreeDataBaselineException("data truth index partition count exceeds its limit")
        }
        val grouped = records.groupBy { it.requiredString("id") }
        if (grouped.keys != inventory.shardIds.toSet()) {
            throw FullTreeDataBaselineException("data truth partition ownership is missing or extra")
        }
        val expectedOrder = inventory.shardIds.flatMap { id -> List(grouped.getValue(id).size) { id } }
        if (records.map { it.requiredString("id") } != expectedOrder) {
            throw FullTreeDataBaselineException("data truth partitions are not in inventory order")
        }
        val seenPaths = hashSetOf<Path>()
        var totalBytes = 0L
        val aggregate = BaselineTruthCounts()
        val partitions = records.mapIndexed { recordIndex, record ->
            budget.periodicCheckpoint("while authenticating data truth index records")
            val id = record.requiredString("id")
            val owned = grouped.getValue(id)
            val ordinal = owned.indexOfFirst { it === record }
            if (ordinal < 0) throw FullTreeDataBaselineException("data truth partition identity is contradictory")
            val relativeText = if (owned.size == 1) {
                "shards/$id.json"
            } else {
                "shards/$id.part-${ordinal.toString().padStart(3, '0')}.json"
            }
            if (record.requiredString("path") != relativeText) {
                throw FullTreeDataBaselineException("data truth partition path is not canonical")
            }
            val path = root.resolve(Path.of(relativeText)).normalize()
            if (!path.startsWith(root.resolve("shards").normalize()) || !seenPaths.add(path)) {
                throw FullTreeDataBaselineException("data truth partition path is duplicated or escapes its root")
            }
            val bytes = record.requiredLong("bytes")
            if (bytes !in 1L..limits.maximumTruthPartitionBytes) {
                throw FullTreeDataBaselineException("data truth partition byte binding exceeds its limit")
            }
            totalBytes = addExact(totalBytes, bytes, "data truth partition byte")
            val counts = BaselineTruthCounts.from(record)
            if (counts.entities > limits.maximumTruthPartitionEntities) {
                throw FullTreeDataBaselineException("data truth partition entity binding exceeds its limit")
            }
            aggregate.add(counts)
            TruthPartition(
                index = recordIndex,
                shardId = id,
                ordinal = ordinal,
                total = owned.size,
                path = path,
                bytes = bytes,
                sha256 = record.requiredString("sha256").also { requireDigest(it, "data truth partition") },
                counts = counts,
            )
        }
        if (totalBytes > limits.maximumTruthBytes || aggregate.entities > limits.maximumEntities) {
            throw FullTreeDataBaselineException("data truth index aggregate exceeds its configured bound")
        }
        if (aggregate.toJson() != index.requiredObject("counts")) {
            throw FullTreeDataBaselineException("data truth partition counts do not reconcile with the index")
        }
        verifyTruthTreeMembership(root, partitions, budget)
        return TruthInputs(root, index, partitions, aggregate)
    }

    private fun ingestTruth(
        connection: Connection,
        inputs: TruthInputs,
        inventory: InventoryBinding,
        limits: FullTreeDataBaselineLimits,
        budget: Budget,
    ): BaselineTruthCounts {
        val total = BaselineTruthCounts()
        val previousGlobals = hashMapOf<String, String>()
        val previousTypes = hashMapOf<String, String>()
        val insertGlobal = connection.prepareStatement(
            "INSERT INTO truth_globals(id, shard_id, population) VALUES (?, ?, ?)",
        )
        val insertType = connection.prepareStatement(
            "INSERT INTO truth_types(id, shard_id, population) VALUES (?, ?, ?)",
        )
        val increment = connection.prepareStatement(
            "UPDATE metrics SET exact = exact + ?, excluded = excluded + ? " +
                "WHERE shard_id = ? AND dimension = 'types'",
        )
        try {
            inputs.partitions.forEach { partition ->
                budget.checkpoint("before baseline data truth partition ${partition.index}")
                val computed = BaselineTruthCounts()
                val expectedShard = truthShardBinding(
                    partition,
                    inventory.shardUnits.getValue(partition.shardId),
                )
                val streamed = FullTreeCanonicalStreaming.readObject(
                    path = partition.path,
                    label = "baseline data truth partition ${partition.shardId}/${partition.ordinal}",
                    expectedSourceSha256 = partition.sha256,
                    fieldOrder = TRUTH_FIELDS,
                    arrayFields = setOf("globals", "types"),
                    omittedDigestField = null,
                    limits = streamingLimits(
                        maximumInputBytes = minOf(limits.maximumTruthPartitionBytes, partition.bytes),
                        maximumEntities = maxOf(
                            1L,
                            minOf(limits.maximumTruthPartitionEntities, partition.counts.entities),
                        ),
                        limits = limits,
                    ),
                ) { field, index, entity, _ ->
                    if ((index and 1023L) == 0L) budget.checkpoint("while streaming baseline data truth")
                    when (field) {
                        "globals" -> {
                            validateTruthEntity("global", entity, inputs.index.requiredObject("oracle"), expectedShard)
                            val id = entity.requiredString("id")
                            previousGlobals[partition.shardId] = requireIncreasing(
                                id,
                                previousGlobals[partition.shardId],
                                "data truth globals",
                            )
                            val ownerShard = inventory.unitToShard[entity.requiredString("ownerUnitId")]
                                ?: throw FullTreeDataBaselineException("truth global owner is outside inventory")
                            if (ownerShard != partition.shardId) {
                                throw FullTreeDataBaselineException("truth global owner differs from partition")
                            }
                            validateTruthGlobalSemantics(entity)
                            val names = entity.requiredArray("names").map {
                                it.requiredString("truth global name")
                            }
                            requireSortedUnique(names, "truth global names")
                            computed.add(BaselineTruthCounts.forEntity("global", entity, ownerShard))
                            insertGlobal.setString(1, id)
                            insertGlobal.setString(2, ownerShard)
                            insertGlobal.setString(3, entity.requiredString("population"))
                            insertExactlyOnce(insertGlobal, "truth global identity")
                        }
                        "types" -> {
                            validateTruthEntity("type", entity, inputs.index.requiredObject("oracle"), expectedShard)
                            val id = entity.requiredString("id")
                            previousTypes[partition.shardId] = requireIncreasing(
                                id,
                                previousTypes[partition.shardId],
                                "data truth types",
                            )
                            val ownerShard = inventory.unitToShard[entity.requiredString("ownerUnitId")]
                                ?: throw FullTreeDataBaselineException("truth type owner is outside inventory")
                            if (ownerShard != partition.shardId) {
                                throw FullTreeDataBaselineException("truth type owner differs from partition")
                            }
                            validateTruthTypeSemantics(entity)
                            computed.add(BaselineTruthCounts.forEntity("type", entity, ownerShard))
                            insertType.setString(1, id)
                            insertType.setString(2, ownerShard)
                            insertType.setString(3, entity.requiredString("population"))
                            insertExactlyOnce(insertType, "truth type identity")
                            val scored = entity.requiredString("population") == "scored"
                            increment.setLong(1, if (scored) 1L else 0L)
                            increment.setLong(2, if (scored) 0L else 1L)
                            increment.setString(3, ownerShard)
                            if (increment.executeUpdate() != 1) {
                                throw FullTreeDataBaselineException("truth type baseline owner is absent")
                            }
                        }
                        else -> throw FullTreeDataBaselineException("unexpected streamed data truth field")
                    }
                    if (computed.entities > limits.maximumTruthPartitionEntities) {
                        throw FullTreeDataBaselineException("data truth partition exceeds its streamed entity limit")
                    }
                }
                if (streamed.sourceBytes != partition.bytes) {
                    throw FullTreeDataBaselineException("data truth partition byte count differs from index")
                }
                val envelope = streamed.envelope
                validateTruthEnvelope(envelope)
                if (envelope.requiredObject("oracle") != inputs.index.requiredObject("oracle") ||
                    envelope.requiredObject("shard") != expectedShard
                ) {
                    throw FullTreeDataBaselineException("data truth partition bindings differ")
                }
                if (envelope.requiredObject("counts") != computed.toJson() || computed != partition.counts) {
                    throw FullTreeDataBaselineException("data truth partition counts are stale or contradictory")
                }
                total.add(computed)
            }
        } finally {
            insertGlobal.close()
            insertType.close()
            increment.close()
        }
        if (total != inputs.counts || total.toJson() != inputs.index.requiredObject("counts")) {
            throw FullTreeDataBaselineException("streamed data truth counts differ from index")
        }
        verifyTruthTreeMembership(inputs.root, inputs.partitions, budget)
        return total
    }

    private fun ingestReconciliation(
        connection: Connection,
        path: Path,
        expectedSha256: String,
        dataTruthIndexSha256: String,
        inventory: InventoryBinding,
        scopeSha256: String,
        truth: BaselineTruthCounts,
        limits: FullTreeDataBaselineLimits,
        budget: Budget,
    ): BaselineReconciliationCounts {
        val counts = BaselineReconciliationCounts()
        var previousAbi: Pair<String, String>? = null
        var previousDwarf: String? = null
        var previousGlobal: String? = null
        val insertAbi = connection.prepareStatement(
            "INSERT INTO abi_objects(elf_id, alias_name, owner_shard, owners_sha256, slots, resolved_slots) " +
                "VALUES (?, ?, ?, ?, ?, ?)",
        )
        val insertDwarf = connection.prepareStatement(
            "INSERT INTO dwarf_only(truth_id, shard_id) VALUES (?, ?)",
        )
        val insertGlobal = connection.prepareStatement(
            "INSERT INTO reconciliation_globals(elf_id, owner_shard, owners_sha256, reconciliation) " +
                "VALUES (?, ?, ?, ?)",
        )
        val insertAlias = connection.prepareStatement(
            "INSERT INTO reconciliation_aliases(elf_id, alias_name) VALUES (?, ?)",
        )
        val insertMatched = connection.prepareStatement(
            "INSERT INTO matched_truth(truth_id, elf_id) VALUES (?, ?)",
        )
        val truthOwner = connection.prepareStatement(
            "SELECT shard_id, population FROM truth_globals WHERE id = ?",
        )
        val overlap = connection.prepareStatement("SELECT 1 FROM dwarf_only WHERE truth_id = ?")
        val increment = connection.prepareStatement(
            "UPDATE metrics SET exact = exact + ?, partial = partial + ?, missing = missing + ? " +
                "WHERE shard_id = ? AND dimension = ?",
        )
        val insertMismatchRow = connection.prepareStatement(
            "INSERT INTO mismatches(id, dimension, kind, truth_id, shard_id, reason_code) " +
                "VALUES (?, ?, ?, ?, ?, ?)",
        )
        try {
            val streamed = FullTreeCanonicalStreaming.readObject(
                path = path,
                label = "data reconciliation report for baseline",
                expectedSourceSha256 = expectedSha256,
                fieldOrder = RECONCILIATION_FIELDS,
                arrayFields = setOf("abiObjects", "dwarfOnlyScoredGlobals", "globals"),
                omittedDigestField = "reportSha256",
                limits = streamingLimits(limits.maximumReconciliationBytes, limits.maximumEntities, limits),
            ) { field, index, entity, _ ->
                if ((index and 1023L) == 0L) budget.checkpoint("while streaming data reconciliation baseline input")
                when (field) {
                    "abiObjects" -> {
                        validateReconciliationEntity("abi", entity, EMPTY_RECONCILIATION_ORACLE)
                        val key = entity.requiredString("elfGlobalId") to entity.requiredString("aliasName")
                        if (previousAbi != null && compareAbiKeys(previousAbi!!, key) >= 0) {
                            throw FullTreeDataBaselineException("ABI reconciliation objects are not strictly ordered")
                        }
                        previousAbi = key
                        val owners = entity.requiredArray("ownerShardIds").map {
                            it.requiredString("ABI owner shard")
                        }
                        requireSortedUnique(owners, "ABI owner shards")
                        requireKnownOwners(owners, inventory)
                        val slots = entity.requiredLong("slots")
                        val resolved = entity.requiredLong("resolvedSlots")
                        if (resolved > slots) {
                            throw FullTreeDataBaselineException("ABI resolved slots exceed total slots")
                        }
                        counts.abiObjects = increment(counts.abiObjects, "ABI object")
                        counts.abiSlots = addExact(counts.abiSlots, slots, "ABI slot")
                        counts.abiResolvedSlots = addExact(counts.abiResolvedSlots, resolved, "resolved ABI slot")
                        insertAbi.setString(1, key.first)
                        insertAbi.setString(2, key.second)
                        insertAbi.setString(3, owners.first())
                        insertAbi.setString(4, ownerListSha256(owners, limits))
                        insertAbi.setLong(5, slots)
                        insertAbi.setLong(6, resolved)
                        insertExactlyOnce(insertAbi, "ABI object identity")
                        val exact = resolved == slots
                        incrementMetric(increment, owners.first(), "abiObjects", exact = exact, partial = !exact)
                        if (!exact) {
                            insertMismatch(
                                insertMismatchRow,
                                dimension = "abiObjects",
                                kind = "partial",
                                truthId = "${key.first}:${key.second}",
                                shardId = owners.first(),
                                reasonCode = "abi-object-has-unresolved-slot-words",
                                limits = limits,
                            )
                        }
                    }
                    "dwarfOnlyScoredGlobals" -> {
                        validateReconciliationEntity("dwarf", entity, EMPTY_RECONCILIATION_ORACLE)
                        val truthId = entity.requiredString("truthId")
                        previousDwarf = requireIncreasing(
                            truthId,
                            previousDwarf,
                            "DWARF-only reconciliation globals",
                        )
                        val shardId = entity.requiredString("shardId")
                        if (shardId !in inventory.shardIds) {
                            throw FullTreeDataBaselineException("DWARF-only global owner is outside inventory")
                        }
                        truthOwner.setString(1, truthId)
                        truthOwner.executeQuery().use { rows ->
                            if (!rows.next() || rows.getString(1) != shardId || rows.getString(2) != "scored" || rows.next()) {
                                throw FullTreeDataBaselineException("DWARF-only global does not bind scored truth")
                            }
                        }
                        insertDwarf.setString(1, truthId)
                        insertDwarf.setString(2, shardId)
                        insertExactlyOnce(insertDwarf, "DWARF-only truth identity")
                        counts.dwarfOnlyScoredGlobals = increment(
                            counts.dwarfOnlyScoredGlobals,
                            "DWARF-only scored global",
                        )
                        incrementMetric(increment, shardId, "globals", missing = true)
                        insertMismatch(
                            insertMismatchRow,
                            dimension = "globals",
                            kind = "missing",
                            truthId = truthId,
                            shardId = shardId,
                            reasonCode = "dwarf-address-without-elf-object",
                            limits = limits,
                        )
                    }
                    "globals" -> {
                        validateReconciliationEntity("global", entity, EMPTY_RECONCILIATION_ORACLE)
                        val elfId = entity.requiredString("elfGlobalId")
                        previousGlobal = requireIncreasing(elfId, previousGlobal, "ELF reconciliation globals")
                        val aliases = entity.requiredArray("aliasNames").map {
                            it.requiredString("ELF reconciliation alias")
                        }
                        val dwarfTruthIds = entity.requiredArray("dwarfTruthIds").map {
                            it.requiredString("reconciled DWARF truth identity")
                        }
                        val owners = entity.requiredArray("ownerShardIds").map {
                            it.requiredString("reconciled owner shard")
                        }
                        requireSortedUnique(aliases, "ELF reconciliation aliases")
                        requireSortedUnique(dwarfTruthIds, "reconciled DWARF truth identities")
                        requireSortedUnique(owners, "ELF reconciliation owners")
                        requireKnownOwners(owners, inventory)
                        val outcome = entity.requiredString("reconciliation")
                        val derivedOwners = java.util.TreeSet<String>(CODE_POINT_STRING_COMPARATOR)
                        if (outcome == "elf-only") {
                            if (dwarfTruthIds.isNotEmpty() || owners != listOf(ELF_ONLY_SHARD)) {
                                throw FullTreeDataBaselineException("ELF-only reconciliation ownership is contradictory")
                            }
                        } else {
                            if (dwarfTruthIds.isEmpty() || ELF_ONLY_SHARD in owners) {
                                throw FullTreeDataBaselineException("matched reconciliation ownership is contradictory")
                            }
                            dwarfTruthIds.forEach { truthId ->
                                truthOwner.setString(1, truthId)
                                truthOwner.executeQuery().use { rows ->
                                    if (!rows.next()) {
                                        throw FullTreeDataBaselineException("matched reconciliation truth is absent")
                                    }
                                    derivedOwners += rows.getString(1)
                                    if (rows.next()) {
                                        throw FullTreeDataBaselineException("matched reconciliation truth is duplicated")
                                    }
                                }
                                overlap.setString(1, truthId)
                                overlap.executeQuery().use { rows ->
                                    if (rows.next()) {
                                        throw FullTreeDataBaselineException("truth global is both matched and DWARF-only")
                                    }
                                }
                            }
                            if (derivedOwners.toList() != owners) {
                                throw FullTreeDataBaselineException("matched reconciliation owner set differs from truth")
                            }
                        }
                        insertGlobal.setString(1, elfId)
                        insertGlobal.setString(2, owners.first())
                        insertGlobal.setString(3, ownerListSha256(owners, limits))
                        insertGlobal.setString(4, outcome)
                        insertExactlyOnce(insertGlobal, "ELF reconciliation identity")
                        dwarfTruthIds.forEach { truthId ->
                            insertMatched.setString(1, truthId)
                            insertMatched.setString(2, elfId)
                            insertExactlyOnce(insertMatched, "matched truth identity")
                        }
                        aliases.forEach { alias ->
                            insertAlias.setString(1, elfId)
                            insertAlias.setString(2, alias)
                            insertExactlyOnce(insertAlias, "ELF reconciliation alias")
                        }
                        counts.elfGlobals = increment(counts.elfGlobals, "ELF reconciliation global")
                        if (outcome == "elf-only") {
                            counts.elfOnlyGlobals = increment(counts.elfOnlyGlobals, "ELF-only global")
                            incrementMetric(increment, owners.first(), "globals", partial = true)
                            insertMismatch(
                                insertMismatchRow,
                                dimension = "globals",
                                kind = "partial",
                                truthId = elfId,
                                shardId = owners.first(),
                                reasonCode = "elf-object-without-dwarf-owner",
                                limits = limits,
                            )
                        } else {
                            counts.matchedElfGlobals = increment(counts.matchedElfGlobals, "matched ELF global")
                            incrementMetric(increment, owners.first(), "globals", exact = true)
                        }
                    }
                    else -> throw FullTreeDataBaselineException("unexpected streamed reconciliation field")
                }
                if (counts.entities > limits.maximumEntities) {
                    throw FullTreeDataBaselineException("data reconciliation exceeds baseline entity limit")
                }
            }
            val envelope = streamed.envelope
            val oracle = envelope.requiredObject("oracle")
            validateReconciliationEnvelope(envelope)
            if (oracle.requiredString("configurationSha256") !=
                FullTreeDataReconciliationSqlite.configurationSha256 ||
                oracle.requiredString("dataTruthIndexSha256") != dataTruthIndexSha256 ||
                oracle.requiredString("inventoryIndexSha256") != inventory.indexSha256 ||
                oracle.requiredString("scopeSha256") != scopeSha256
            ) {
                throw FullTreeDataBaselineException("data reconciliation bindings differ")
            }
            requireDigest(oracle.requiredString("elfDataIndexSha256"), "ELF data index")
            val reportSha256 = envelope.requiredString("reportSha256")
            if (streamed.canonicalWithoutOmittedFieldSha256 != reportSha256) {
                throw FullTreeDataBaselineException("data reconciliation report self hash does not reconcile")
            }
            counts.requireEnvelope(envelope.requiredObject("counts"), truth)
        } finally {
            insertAbi.close()
            insertDwarf.close()
            insertGlobal.close()
            insertAlias.close()
            insertMatched.close()
            truthOwner.close()
            overlap.close()
            increment.close()
            insertMismatchRow.close()
        }
        requireAbiBindings(connection, budget)
        return counts
    }

    private fun finalizeGlobalMetrics(connection: Connection, budget: Budget) {
        val select = connection.prepareStatement(
            "SELECT t.shard_id FROM truth_globals t " +
                "WHERE t.population = 'unobservable' " +
                "AND NOT EXISTS (SELECT 1 FROM matched_truth m WHERE m.truth_id = t.id)",
        )
        val increment = connection.prepareStatement(
            "UPDATE metrics SET excluded = excluded + 1 WHERE shard_id = ? AND dimension = 'globals'",
        )
        try {
            select.executeQuery().use { rows ->
                while (rows.next()) {
                    budget.periodicCheckpoint("while finalizing unobservable global baseline population")
                    increment.setString(1, rows.getString(1))
                    if (increment.executeUpdate() != 1) {
                        throw FullTreeDataBaselineException("unobservable truth global owner is absent")
                    }
                }
            }
        } finally {
            select.close()
            increment.close()
        }
    }

    private fun requireCompletePopulation(
        connection: Connection,
        truth: BaselineTruthCounts,
        reconciliation: BaselineReconciliationCounts,
        budget: Budget,
    ) {
        budget.checkpoint("before baseline population closure queries")
        scalar(
            connection,
            "SELECT COUNT(*) FROM truth_globals t WHERE t.population = 'scored' AND " +
                "((CASE WHEN EXISTS (SELECT 1 FROM matched_truth m WHERE m.truth_id = t.id) THEN 1 ELSE 0 END) + " +
                "(CASE WHEN EXISTS (SELECT 1 FROM dwarf_only d WHERE d.truth_id = t.id) THEN 1 ELSE 0 END)) <> 1",
        ).also { uncovered ->
            if (uncovered != 0L) {
                throw FullTreeDataBaselineException("scored truth global population is missing or duplicated")
            }
        }
        if (scalar(connection, "SELECT COUNT(*) FROM matched_truth") +
            scalar(connection, "SELECT COUNT(*) FROM dwarf_only") !=
            truth.globals - truth.unobservableGlobals +
            scalar(
                connection,
                "SELECT COUNT(*) FROM matched_truth m JOIN truth_globals t ON t.id = m.truth_id " +
                    "WHERE t.population = 'unobservable'",
            )
        ) {
            throw FullTreeDataBaselineException("reconciled truth global population does not close")
        }
        if (scalar(connection, "SELECT COUNT(*) FROM dwarf_only") != reconciliation.dwarfOnlyScoredGlobals) {
            throw FullTreeDataBaselineException("DWARF-only reconciliation population differs")
        }
        budget.checkpoint("after baseline population closure queries")
    }

    private fun requireAbiBindings(connection: Connection, budget: Budget) {
        budget.checkpoint("before ABI baseline binding query")
        val unbound = scalar(
            connection,
            "SELECT COUNT(*) FROM abi_objects a WHERE " +
                "NOT EXISTS (SELECT 1 FROM reconciliation_globals g " +
                "WHERE g.elf_id = a.elf_id AND g.owners_sha256 = a.owners_sha256) OR " +
                "NOT EXISTS (SELECT 1 FROM reconciliation_aliases n " +
                "WHERE n.elf_id = a.elf_id AND n.alias_name = a.alias_name)",
        )
        if (unbound != 0L) {
            throw FullTreeDataBaselineException("ABI baseline objects do not bind reconciliation globals")
        }
        budget.checkpoint("after ABI baseline binding query")
    }

    private fun configureDatabase(connection: Connection, limits: FullTreeDataBaselineLimits) {
        connection.createStatement().use { statement ->
            statement.execute("PRAGMA page_size = $SQLITE_PAGE_BYTES")
            statement.execute("PRAGMA journal_mode = OFF")
            statement.execute("PRAGMA synchronous = FULL")
            statement.execute("PRAGMA temp_store = MEMORY")
            statement.execute("PRAGMA automatic_index = OFF")
            statement.execute("PRAGMA foreign_keys = ON")
            statement.execute("PRAGMA mmap_size = 0")
            statement.execute("PRAGMA cache_size = -${SQLITE_CACHE_BYTES / 1024L}")
            statement.execute("PRAGMA trusted_schema = OFF")
            statement.execute("PRAGMA application_id = $SQLITE_APPLICATION_ID")
            statement.execute("PRAGMA user_version = $SQLITE_SCHEMA_VERSION")
            val maximumPages = limits.maximumDatabaseBytes / SQLITE_PAGE_BYTES
            statement.execute("PRAGMA max_page_count = $maximumPages")
        }
        if (pragmaLong(connection, "page_size") != SQLITE_PAGE_BYTES ||
            pragmaLong(connection, "temp_store") != SQLITE_TEMP_STORE_MEMORY.toLong() ||
            pragmaText(connection, "journal_mode") != "off" ||
            pragmaLong(connection, "automatic_index") != 0L ||
            pragmaLong(connection, "foreign_keys") != 1L ||
            pragmaLong(connection, "mmap_size") != 0L ||
            pragmaLong(connection, "application_id") != SQLITE_APPLICATION_ID.toLong() ||
            pragmaLong(connection, "user_version") != SQLITE_SCHEMA_VERSION.toLong()
        ) {
            throw FullTreeDataBaselineException("SQLite baseline safety configuration differs")
        }
    }

    private fun createGenerationSchema(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.execute(
                "CREATE TABLE truth_globals(" +
                    "id TEXT PRIMARY KEY COLLATE BINARY, " +
                    "shard_id TEXT NOT NULL COLLATE BINARY, " +
                    "population TEXT NOT NULL CHECK(population IN ('scored','unobservable'))) WITHOUT ROWID",
            )
            statement.execute(
                "CREATE TABLE truth_types(" +
                    "id TEXT PRIMARY KEY COLLATE BINARY, " +
                    "shard_id TEXT NOT NULL COLLATE BINARY, " +
                    "population TEXT NOT NULL CHECK(population IN ('scored','unobservable'))) WITHOUT ROWID",
            )
            statement.execute(
                "CREATE TABLE dwarf_only(" +
                    "truth_id TEXT PRIMARY KEY COLLATE BINARY, " +
                    "shard_id TEXT NOT NULL COLLATE BINARY, " +
                    "FOREIGN KEY(truth_id) REFERENCES truth_globals(id)) WITHOUT ROWID",
            )
            statement.execute(
                "CREATE TABLE reconciliation_globals(" +
                    "elf_id TEXT PRIMARY KEY COLLATE BINARY, " +
                    "owner_shard TEXT NOT NULL COLLATE BINARY, " +
                    "owners_sha256 TEXT NOT NULL, " +
                    "reconciliation TEXT NOT NULL) WITHOUT ROWID",
            )
            statement.execute(
                "CREATE TABLE reconciliation_aliases(" +
                    "elf_id TEXT NOT NULL COLLATE BINARY, alias_name TEXT NOT NULL COLLATE BINARY, " +
                    "PRIMARY KEY(elf_id, alias_name), " +
                    "FOREIGN KEY(elf_id) REFERENCES reconciliation_globals(elf_id)) WITHOUT ROWID",
            )
            statement.execute(
                "CREATE TABLE matched_truth(" +
                    "truth_id TEXT PRIMARY KEY COLLATE BINARY, elf_id TEXT NOT NULL COLLATE BINARY, " +
                    "FOREIGN KEY(truth_id) REFERENCES truth_globals(id), " +
                    "FOREIGN KEY(elf_id) REFERENCES reconciliation_globals(elf_id)) WITHOUT ROWID",
            )
            statement.execute(
                "CREATE TABLE abi_objects(" +
                    "elf_id TEXT NOT NULL COLLATE BINARY, alias_name TEXT NOT NULL COLLATE BINARY, " +
                    "owner_shard TEXT NOT NULL COLLATE BINARY, owners_sha256 TEXT NOT NULL, " +
                    "slots INTEGER NOT NULL CHECK(slots >= 0), " +
                    "resolved_slots INTEGER NOT NULL CHECK(resolved_slots BETWEEN 0 AND slots), " +
                    "PRIMARY KEY(elf_id, alias_name)) WITHOUT ROWID",
            )
            statement.execute(
                "CREATE TABLE metrics(" +
                    "shard_id TEXT NOT NULL COLLATE BINARY, dimension TEXT NOT NULL COLLATE BINARY, " +
                    "exact INTEGER NOT NULL DEFAULT 0 CHECK(exact >= 0), " +
                    "partial INTEGER NOT NULL DEFAULT 0 CHECK(partial >= 0), " +
                    "missing INTEGER NOT NULL DEFAULT 0 CHECK(missing >= 0), " +
                    "fabricated INTEGER NOT NULL DEFAULT 0 CHECK(fabricated >= 0), " +
                    "excluded INTEGER NOT NULL DEFAULT 0 CHECK(excluded >= 0), " +
                    "PRIMARY KEY(shard_id, dimension)) WITHOUT ROWID",
            )
            statement.execute(
                "CREATE TABLE mismatches(" +
                    "id TEXT PRIMARY KEY COLLATE BINARY, dimension TEXT NOT NULL, kind TEXT NOT NULL, " +
                    "truth_id TEXT NOT NULL, shard_id TEXT NOT NULL COLLATE BINARY, reason_code TEXT NOT NULL) " +
                    "WITHOUT ROWID",
            )
        }
    }

    private fun createComparisonSchema(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.execute(
                "CREATE TABLE current_metrics(" +
                    "shard_id TEXT NOT NULL COLLATE BINARY, dimension TEXT NOT NULL COLLATE BINARY, " +
                    "denominator INTEGER NOT NULL CHECK(denominator >= 0), " +
                    "exact INTEGER NOT NULL CHECK(exact >= 0), " +
                    "fabricated INTEGER NOT NULL CHECK(fabricated >= 0), " +
                    "seen INTEGER NOT NULL DEFAULT 0 CHECK(seen IN (0,1)), " +
                    "PRIMARY KEY(shard_id, dimension)) WITHOUT ROWID",
            )
        }
    }

    private fun initializeMetrics(connection: Connection, inventoryShardIds: List<String>) {
        val insert = connection.prepareStatement(
            "INSERT INTO metrics(shard_id, dimension) VALUES (?, ?)",
        )
        try {
            (inventoryShardIds + ELF_ONLY_SHARD).sortedWith(CODE_POINT_STRING_COMPARATOR).forEach { shardId ->
                DIMENSIONS.forEach { dimension ->
                    insert.setString(1, shardId)
                    insert.setString(2, dimension)
                    insertExactlyOnce(insert, "baseline shard metric identity")
                }
            }
        } finally {
            insert.close()
        }
    }

    private fun aggregateMetrics(connection: Connection, budget: Budget): JsonObject {
        val aggregate = DIMENSIONS.associateWith { MetricCounts() }.toMutableMap()
        connection.createStatement().use { statement ->
            statement.executeQuery(
                "SELECT shard_id, dimension, exact, partial, missing, fabricated, excluded " +
                    "FROM metrics ORDER BY shard_id COLLATE BINARY, dimension COLLATE BINARY",
            ).use { rows ->
                while (rows.next()) {
                    budget.periodicCheckpoint("while aggregating baseline metrics")
                    aggregate.getValue(rows.getString(2)).add(
                        MetricCounts(
                            exact = rows.getLong(3),
                            partial = rows.getLong(4),
                            missing = rows.getLong(5),
                            fabricated = rows.getLong(6),
                            excluded = rows.getLong(7),
                        ),
                    )
                }
            }
        }
        return dimensionsJson(aggregate)
    }

    private fun validateGeneratedMetricEquations(
        connection: Connection,
        aggregate: JsonObject,
        budget: Budget,
    ) {
        val mismatchCounts = mutableMapOf<Pair<String, String>, Long>()
        connection.createStatement().use { statement ->
            statement.executeQuery(
                "SELECT id, dimension, kind FROM mismatches ORDER BY id COLLATE BINARY",
            ).use { rows ->
                var previous: String? = null
                while (rows.next()) {
                    budget.periodicCheckpoint("while validating generated baseline mismatches")
                    previous = requireIncreasing(rows.getString(1), previous, "baseline mismatch identities")
                    val key = rows.getString(2) to rows.getString(3)
                    mismatchCounts[key] = increment(mismatchCounts[key] ?: 0L, "baseline mismatch")
                }
            }
        }
        val globals = aggregate.requiredObject("globals")
        val abi = aggregate.requiredObject("abiObjects")
        val types = aggregate.requiredObject("types")
        if ((mismatchCounts["globals" to "partial"] ?: 0L) != globals.requiredLong("partial") ||
            (mismatchCounts["globals" to "missing"] ?: 0L) != globals.requiredLong("missing") ||
            (mismatchCounts["abiObjects" to "partial"] ?: 0L) != abi.requiredLong("partial") ||
            mismatchCounts.keys.any { it !in EXPECTED_MISMATCH_KINDS }
        ) {
            throw FullTreeDataBaselineException("baseline mismatch population does not reconcile with metrics")
        }
        if (abi.requiredLong("missing") != 0L || abi.requiredLong("fabricated") != 0L ||
            globals.requiredLong("fabricated") != 0L ||
            types.requiredLong("partial") != 0L || types.requiredLong("missing") != 0L ||
            types.requiredLong("fabricated") != 0L
        ) {
            throw FullTreeDataBaselineException("baseline dimension outcomes contradict v1 scoring policy")
        }
    }

    private fun requireNoTempBTreePlans(connection: Connection) {
        val statements = listOf(
            "SELECT shard_id, dimension, exact, partial, missing, fabricated, excluded " +
                "FROM metrics ORDER BY shard_id COLLATE BINARY, dimension COLLATE BINARY",
            "SELECT id, dimension, kind, truth_id, shard_id, reason_code " +
                "FROM mismatches ORDER BY id COLLATE BINARY",
        )
        statements.forEach { sql ->
            connection.createStatement().use { statement ->
                statement.executeQuery("EXPLAIN QUERY PLAN $sql").use { rows ->
                    while (rows.next()) {
                        val detail = rows.getString(4).uppercase()
                        if ("TEMP B-TREE" in detail || "AUTOMATIC" in detail) {
                            throw FullTreeDataBaselineException("baseline SQLite plan requests unmanaged temporary state")
                        }
                    }
                }
            }
        }
    }

    private fun writeReport(
        connection: Connection,
        target: Path,
        dataTruthIndexSha256: String,
        reconciliationReportSha256: String,
        aggregate: JsonObject,
        limits: FullTreeDataBaselineLimits,
        budget: Budget,
    ): WrittenReport {
        budget.checkpoint("before data baseline report hash pass")
        val selfDigest = MessageDigest.getInstance("SHA-256")
        val selfBound = BoundedOutputStream(OutputStream.nullOutputStream(), limits.maximumBaselineBytes, budget)
        DigestOutputStream(selfBound, selfDigest).use { output ->
            writeReportDocument(
                connection,
                output,
                dataTruthIndexSha256,
                reconciliationReportSha256,
                aggregate,
                reportSha256 = null,
                limits,
                budget,
            )
        }
        val reportSha256 = selfDigest.digest().hex()
        budget.checkpoint("after data baseline report hash pass")
        val temporaryFile = createTrackedTemporaryFile(
            target.parent,
            ".baseline-report-",
            ".tmp",
            "temporary data baseline report",
        )
        val temporary = temporaryFile.path
        val temporaryIdentity = temporaryFile.identity
        var moved = false
        try {
            Files.setPosixFilePermissions(temporary, PRIVATE_FILE_PERMISSIONS)
            budget.checkpoint("before data baseline report artifact pass")
            val artifactDigest = MessageDigest.getInstance("SHA-256")
            val bound = BoundedOutputStream(
                BufferedOutputStream(
                    Files.newOutputStream(
                        temporary,
                        StandardOpenOption.WRITE,
                        StandardOpenOption.TRUNCATE_EXISTING,
                        LinkOption.NOFOLLOW_LINKS,
                    ),
                ),
                limits.maximumBaselineBytes,
                budget,
            )
            DigestOutputStream(bound, artifactDigest).use { output ->
                writeReportDocument(
                    connection,
                    output,
                    dataTruthIndexSha256,
                    reconciliationReportSha256,
                    aggregate,
                    reportSha256,
                    limits,
                    budget,
                )
            }
            budget.checkpoint("after data baseline report artifact pass")
            FileChannel.open(temporary, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS).use { it.force(true) }
            requireFileIdentity(temporary, temporaryIdentity, "temporary data baseline report")
            Files.setPosixFilePermissions(temporary, READ_ONLY_FILE_PERMISSIONS)
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                throw FullTreeDataBaselineException("data baseline staging report already exists")
            }
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE)
            } catch (failure: AtomicMoveNotSupportedException) {
                throw FullTreeDataBaselineException("filesystem cannot atomically stage data baseline report", failure)
            }
            moved = true
            forceDirectory(target.parent)
            requireFileIdentity(target, temporaryIdentity, "staged data baseline report")
            val artifactSha256 = artifactDigest.digest().hex()
            val digest = digestFile(target, limits.maximumBaselineBytes, "staged data baseline report", budget)
            if (digest.sha256 != artifactSha256 || digest.bytes != bound.count) {
                throw FullTreeDataBaselineException("staged data baseline report digest differs")
            }
            val validation = StreamValidation(connection, "generated")
            val binding = validation.use {
                streamBaseline(
                    target,
                    artifactSha256,
                    limits,
                    budget,
                    validation = it,
                )
            }
            if (binding.reportSha256 != reportSha256 || binding.aggregate != aggregate ||
                binding.dataTruthIndexSha256 != dataTruthIndexSha256 ||
                binding.reconciliationReportSha256 != reconciliationReportSha256
            ) {
                throw FullTreeDataBaselineException("staged data baseline report semantics differ")
            }
            return WrittenReport(reportSha256, artifactSha256, bound.count, aggregate)
        } finally {
            if (!moved && Files.exists(temporary, LinkOption.NOFOLLOW_LINKS)) {
                requireFileIdentity(temporary, temporaryIdentity, "temporary data baseline report")
                Files.delete(temporary)
            }
        }
    }

    private fun writeReportDocument(
        connection: Connection,
        output: OutputStream,
        dataTruthIndexSha256: String,
        reconciliationReportSha256: String,
        aggregate: JsonObject,
        reportSha256: String?,
        limits: FullTreeDataBaselineLimits,
        budget: Budget,
    ) {
        val writer = CanonicalReportWriter(output)
        writer.startObject()
        writer.field("aggregate")
        writer.value(canonicalEntity(aggregate, limits))
        writer.field("configurationSha256")
        writer.value(canonicalEntity(JsonPrimitive(configurationSha256), limits))
        writer.field("dataTruthIndexSha256")
        writer.value(canonicalEntity(JsonPrimitive(dataTruthIndexSha256), limits))
        writer.field("mismatches")
        writer.startArray()
        connection.createStatement().use { statement ->
            statement.executeQuery(
                "SELECT id, dimension, kind, truth_id, shard_id, reason_code " +
                    "FROM mismatches ORDER BY id COLLATE BINARY",
            ).use { rows ->
                while (rows.next()) {
                    budget.periodicCheckpoint("while emitting data baseline mismatches")
                    writer.arrayValue(
                        canonicalEntity(
                            mismatchJson(
                                id = rows.getString(1),
                                dimension = rows.getString(2),
                                kind = rows.getString(3),
                                truthId = rows.getString(4),
                                shardId = rows.getString(5),
                                reasonCode = rows.getString(6),
                            ),
                            limits,
                        ),
                    )
                }
            }
        }
        writer.endArray()
        writer.field("reconciliationReportSha256")
        writer.value(canonicalEntity(JsonPrimitive(reconciliationReportSha256), limits))
        if (reportSha256 != null) {
            writer.field("reportSha256")
            writer.value(canonicalEntity(JsonPrimitive(reportSha256), limits))
        }
        writer.field("schemaVersion")
        writer.value(canonicalEntity(JsonPrimitive(1), limits))
        writer.field("shards")
        writer.startArray()
        forEachShardMetric(connection, budget) { shard ->
            writer.arrayValue(canonicalEntity(shard, limits))
        }
        writer.endArray()
        writer.endObject()
    }

    private fun forEachShardMetric(
        connection: Connection,
        budget: Budget,
        consume: (JsonObject) -> Unit,
    ) {
        connection.createStatement().use { statement ->
            statement.executeQuery(
                "SELECT shard_id, dimension, exact, partial, missing, fabricated, excluded " +
                    "FROM metrics ORDER BY shard_id COLLATE BINARY, dimension COLLATE BINARY",
            ).use { rows ->
                var shardId: String? = null
                val metrics = linkedMapOf<String, JsonElement>()
                fun flush() {
                    val current = shardId ?: return
                    if (metrics.keys != DIMENSIONS.toSet()) {
                        throw FullTreeDataBaselineException("baseline shard metric dimensions are incomplete")
                    }
                    consume(
                        JsonObject(
                            linkedMapOf<String, JsonElement>("id" to JsonPrimitive(current)).apply {
                                putAll(metrics)
                            },
                        ),
                    )
                    metrics.clear()
                }
                while (rows.next()) {
                    budget.periodicCheckpoint("while emitting data baseline shards")
                    val current = rows.getString(1)
                    if (shardId != current) {
                        flush()
                        shardId = current
                    }
                    val dimension = rows.getString(2)
                    if (metrics.put(
                            dimension,
                            MetricCounts(
                                exact = rows.getLong(3),
                                partial = rows.getLong(4),
                                missing = rows.getLong(5),
                                fabricated = rows.getLong(6),
                                excluded = rows.getLong(7),
                            ).toJson(),
                        ) != null
                    ) {
                        throw FullTreeDataBaselineException("baseline shard metric dimension is duplicated")
                    }
                }
                flush()
            }
        }
    }

    private fun streamBaseline(
        path: Path,
        expectedArtifactSha256: String,
        limits: FullTreeDataBaselineLimits,
        budget: Budget,
        validation: StreamValidation? = null,
        consumeShard: (JsonObject) -> Unit = {},
    ): FullTreeDataBaselineBinding {
        requireDigest(expectedArtifactSha256, "data baseline artifact")
        var previousMismatch: String? = null
        var previousShard: String? = null
        var mismatchCount = 0L
        var shardCount = 0L
        val computedAggregate = DIMENSIONS.associateWith { MetricCounts() }.toMutableMap()
        val mismatchCounts = mutableMapOf<Pair<String, String>, Long>()
        val streamed = try {
            FullTreeCanonicalStreaming.readObject(
                path = path,
                label = "full-tree data baseline",
                expectedSourceSha256 = expectedArtifactSha256,
                fieldOrder = BASELINE_FIELDS,
                arrayFields = setOf("mismatches", "shards"),
                omittedDigestField = "reportSha256",
                limits = streamingLimits(limits.maximumBaselineBytes, limits.maximumEntities, limits),
            ) { field, index, entity, _ ->
                if ((index and 1023L) == 0L) budget.checkpoint("while streaming data baseline")
                when (field) {
                    "mismatches" -> {
                        validateBaselineEntity("mismatch", entity)
                        val expected = mismatch(
                            dimension = entity.requiredString("dimension"),
                            kind = entity.requiredString("kind"),
                            truthId = entity.requiredString("truthId"),
                            shardId = entity.requiredString("shardId"),
                            reasonCode = entity.requiredString("reasonCode"),
                            limits = limits,
                        )
                        if (entity != expected) {
                            throw FullTreeDataBaselineException("data baseline mismatch identity or reason differs")
                        }
                        val id = entity.requiredString("id")
                        previousMismatch = requireIncreasing(id, previousMismatch, "data baseline mismatches")
                        mismatchCount = increment(mismatchCount, "data baseline mismatch")
                        val key = entity.requiredString("dimension") to entity.requiredString("kind")
                        mismatchCounts[key] = increment(mismatchCounts[key] ?: 0L, "data baseline mismatch")
                        validation?.recordMismatch(entity)
                    }
                    "shards" -> {
                        validateBaselineEntity("shard", entity)
                        val id = entity.requiredString("id")
                        previousShard = requireIncreasing(id, previousShard, "data baseline shards")
                        DIMENSIONS.forEach { dimension ->
                            val metric = MetricCounts.from(entity.requiredObject(dimension))
                            computedAggregate.getValue(dimension).add(metric)
                        }
                        shardCount = increment(shardCount, "data baseline shard")
                        validation?.recordShard(entity)
                        consumeShard(entity)
                    }
                    else -> throw FullTreeDataBaselineException("unexpected streamed data baseline field")
                }
            }
        } catch (failure: Throwable) {
            throw baselineFailure("cannot stream authenticated data baseline", failure)
        }
        val envelope = streamed.envelope
        validateBaselineEnvelope(envelope)
        if (envelope.requiredString("configurationSha256") != configurationSha256) {
            throw FullTreeDataBaselineException("data baseline configuration binding differs")
        }
        requireDigest(envelope.requiredString("dataTruthIndexSha256"), "baseline data truth index")
        requireDigest(
            envelope.requiredString("reconciliationReportSha256"),
            "baseline reconciliation report",
        )
        val reportSha256 = envelope.requiredString("reportSha256")
        if (streamed.canonicalWithoutOmittedFieldSha256 != reportSha256) {
            throw FullTreeDataBaselineException("data baseline report hash does not reconcile")
        }
        val aggregate = dimensionsJson(computedAggregate)
        if (envelope.requiredObject("aggregate") != aggregate) {
            throw FullTreeDataBaselineException("data baseline aggregate does not reconcile")
        }
        val globals = aggregate.requiredObject("globals")
        val abi = aggregate.requiredObject("abiObjects")
        if ((mismatchCounts["globals" to "partial"] ?: 0L) != globals.requiredLong("partial") ||
            (mismatchCounts["globals" to "missing"] ?: 0L) != globals.requiredLong("missing") ||
            (mismatchCounts["abiObjects" to "partial"] ?: 0L) != abi.requiredLong("partial") ||
            mismatchCounts.keys.any { it !in EXPECTED_MISMATCH_KINDS }
        ) {
            throw FullTreeDataBaselineException("data baseline mismatches do not cover every non-exact outcome")
        }
        validation?.requireClosure()
        return FullTreeDataBaselineBinding(
            reportSha256 = reportSha256,
            artifactSha256 = streamed.sourceSha256,
            dataTruthIndexSha256 = envelope.requiredString("dataTruthIndexSha256"),
            reconciliationReportSha256 = envelope.requiredString("reconciliationReportSha256"),
            bytes = streamed.sourceBytes,
            shardCount = shardCount,
            mismatchCount = mismatchCount,
            aggregate = aggregate,
        )
    }

    private fun validateBaselineEnvelope(envelope: JsonObject) {
        try {
            OracleSchemas.validate("full-tree-data-baseline", envelope)
        } catch (failure: Exception) {
            throw FullTreeDataBaselineException("data baseline envelope fails schema validation", failure)
        }
    }

    private fun validateBaselineEntity(kind: String, entity: JsonObject) {
        val document = JsonObject(
            mapOf(
                "aggregate" to EMPTY_DIMENSIONS,
                "configurationSha256" to JsonPrimitive(configurationSha256),
                "dataTruthIndexSha256" to JsonPrimitive("0".repeat(64)),
                "mismatches" to if (kind == "mismatch") {
                    JsonArray(listOf(entity))
                } else {
                    JsonArray(emptyList())
                },
                "reconciliationReportSha256" to JsonPrimitive("0".repeat(64)),
                "reportSha256" to JsonPrimitive("0".repeat(64)),
                "schemaVersion" to JsonPrimitive(1),
                "shards" to if (kind == "shard") JsonArray(listOf(entity)) else JsonArray(emptyList()),
            ),
        )
        try {
            OracleSchemas.validate("full-tree-data-baseline", document)
        } catch (failure: Exception) {
            throw FullTreeDataBaselineException("data baseline $kind fails schema validation", failure)
        }
    }

    private fun validateTruthEnvelope(envelope: JsonObject) {
        try {
            OracleSchemas.validate("full-tree-data-truth", envelope)
        } catch (failure: Exception) {
            throw FullTreeDataBaselineException("data truth partition envelope fails schema validation", failure)
        }
    }

    private fun validateTruthEntity(kind: String, entity: JsonObject, oracle: JsonObject, shard: JsonObject) {
        val document = JsonObject(
            mapOf(
                "counts" to BaselineTruthCounts().toJson(),
                "globals" to if (kind == "global") JsonArray(listOf(entity)) else JsonArray(emptyList()),
                "oracle" to oracle,
                "schemaVersion" to JsonPrimitive(1),
                "shard" to shard,
                "types" to if (kind == "type") JsonArray(listOf(entity)) else JsonArray(emptyList()),
            ),
        )
        try {
            OracleSchemas.validate("full-tree-data-truth", document)
        } catch (failure: Exception) {
            throw FullTreeDataBaselineException("data truth $kind fails schema validation", failure)
        }
    }

    private fun validateTruthGlobalSemantics(entity: JsonObject) {
        val scored = entity.requiredString("population") == "scored"
        val address = entity.requiredElement("addressRva").nullableString("truth global address")
        val reasonAbsent = entity.requiredElement("reasonCode") is JsonNull
        if (scored != (address != null) || scored != reasonAbsent) {
            throw FullTreeDataBaselineException("truth global population, address, and reason differ")
        }
        address?.let { value ->
            if (!HEX_ADDRESS.matches(value)) {
                throw FullTreeDataBaselineException("truth global address is not canonical hexadecimal")
            }
        }
    }

    private fun validateTruthTypeSemantics(entity: JsonObject) {
        val scored = entity.requiredString("population") == "scored"
        val sized = entity.requiredElement("byteSize") !is JsonNull
        val reasonAbsent = entity.requiredElement("reasonCode") is JsonNull
        if (scored != sized || scored != reasonAbsent) {
            throw FullTreeDataBaselineException("truth type population, size, and reason differ")
        }
    }

    private fun validateReconciliationEnvelope(envelope: JsonObject) {
        try {
            OracleSchemas.validate("full-tree-data-reconciliation", envelope)
        } catch (failure: Exception) {
            throw FullTreeDataBaselineException("data reconciliation envelope fails schema validation", failure)
        }
    }

    private fun validateReconciliationEntity(kind: String, entity: JsonObject, oracle: JsonObject) {
        val document = JsonObject(
            mapOf(
                "abiObjects" to if (kind == "abi") JsonArray(listOf(entity)) else JsonArray(emptyList()),
                "counts" to EMPTY_RECONCILIATION_COUNTS,
                "dwarfOnlyScoredGlobals" to if (kind == "dwarf") {
                    JsonArray(listOf(entity))
                } else {
                    JsonArray(emptyList())
                },
                "globals" to if (kind == "global") JsonArray(listOf(entity)) else JsonArray(emptyList()),
                "oracle" to oracle,
                "reportSha256" to JsonPrimitive("0".repeat(64)),
                "schemaVersion" to JsonPrimitive(1),
            ),
        )
        try {
            OracleSchemas.validate("full-tree-data-reconciliation", document)
        } catch (failure: Exception) {
            throw FullTreeDataBaselineException("data reconciliation $kind fails schema validation", failure)
        }
    }

    private fun mismatch(
        dimension: String,
        kind: String,
        truthId: String,
        shardId: String,
        reasonCode: String,
        limits: FullTreeDataBaselineLimits,
    ): JsonObject {
        val expectedReason = when (dimension to kind) {
            "globals" to "partial" -> "elf-object-without-dwarf-owner"
            "globals" to "missing" -> "dwarf-address-without-elf-object"
            "abiObjects" to "partial" -> "abi-object-has-unresolved-slot-words"
            else -> throw FullTreeDataBaselineException("data baseline mismatch kind is outside v1 policy")
        }
        if (reasonCode != expectedReason) {
            throw FullTreeDataBaselineException("data baseline mismatch reason differs from v1 policy")
        }
        val identity = JsonObject(
            mapOf(
                "dimension" to JsonPrimitive(dimension),
                "kind" to JsonPrimitive(kind),
                "truthId" to JsonPrimitive(truthId),
            ),
        )
        val singular = if (dimension == "abiObjects") "abi-object" else "global"
        val id = "$kind-$singular-${OracleArtifacts.sha256(canonicalEntity(identity, limits)).take(32)}"
        return mismatchJson(id, dimension, kind, truthId, shardId, reasonCode)
    }

    private fun mismatchJson(
        id: String,
        dimension: String,
        kind: String,
        truthId: String,
        shardId: String,
        reasonCode: String,
    ): JsonObject = JsonObject(
        mapOf(
            "dimension" to JsonPrimitive(dimension),
            "id" to JsonPrimitive(id),
            "kind" to JsonPrimitive(kind),
            "reasonCode" to JsonPrimitive(reasonCode),
            "shardId" to JsonPrimitive(shardId),
            "truthId" to JsonPrimitive(truthId),
        ),
    )

    private fun insertMismatch(
        insert: java.sql.PreparedStatement,
        dimension: String,
        kind: String,
        truthId: String,
        shardId: String,
        reasonCode: String,
        limits: FullTreeDataBaselineLimits,
    ) {
        val mismatch = mismatch(dimension, kind, truthId, shardId, reasonCode, limits)
        insert.setString(1, mismatch.requiredString("id"))
        insert.setString(2, dimension)
        insert.setString(3, kind)
        insert.setString(4, truthId)
        insert.setString(5, shardId)
        insert.setString(6, reasonCode)
        insertExactlyOnce(insert, "baseline mismatch identity")
    }

    private fun incrementMetric(
        statement: java.sql.PreparedStatement,
        shardId: String,
        dimension: String,
        exact: Boolean = false,
        partial: Boolean = false,
        missing: Boolean = false,
    ) {
        statement.setLong(1, if (exact) 1L else 0L)
        statement.setLong(2, if (partial) 1L else 0L)
        statement.setLong(3, if (missing) 1L else 0L)
        statement.setString(4, shardId)
        statement.setString(5, dimension)
        if (statement.executeUpdate() != 1) {
            throw FullTreeDataBaselineException("baseline metric owner or dimension is absent")
        }
    }

    private fun requireKnownOwners(owners: List<String>, inventory: InventoryBinding) {
        if (owners.isEmpty() || owners.any { it != ELF_ONLY_SHARD && it !in inventory.shardIds }) {
            throw FullTreeDataBaselineException("data reconciliation owner is outside baseline shards")
        }
    }

    private fun ownerListSha256(owners: List<String>, limits: FullTreeDataBaselineLimits): String =
        OracleArtifacts.sha256(canonicalEntity(JsonArray(owners.map(::JsonPrimitive)), limits))

    private fun truthShardBinding(partition: TruthPartition, unitIds: List<String>): JsonObject {
        val values = linkedMapOf<String, JsonElement>(
            "id" to JsonPrimitive(partition.shardId),
            "unitIds" to JsonArray(unitIds.map(::JsonPrimitive)),
        )
        if (partition.total > 1) {
            values["partition"] = JsonObject(
                mapOf(
                    "index" to JsonPrimitive(partition.ordinal),
                    "total" to JsonPrimitive(partition.total),
                ),
            )
        }
        return JsonObject(values)
    }

    private fun verifyTruthTreeMembership(root: Path, partitions: List<TruthPartition>, budget: Budget) {
        budget.checkpoint("before verifying data truth tree membership for baseline")
        val shards = root.resolve("shards")
        val expected = hashSetOf(root, root.resolve("index.json"), shards)
        expected += partitions.map { it.path }
        val actual = hashSetOf<Path>()
        Files.walk(root).use { paths ->
            paths.forEach { candidate ->
                budget.periodicCheckpoint("while verifying data truth tree membership for baseline")
                val normalized = candidate.toAbsolutePath().normalize()
                if (!actual.add(normalized) || normalized !in expected) {
                    throw FullTreeDataBaselineException("data truth tree contains an extra path")
                }
                val attributes = Files.readAttributes(
                    normalized,
                    BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                )
                if (attributes.isSymbolicLink ||
                    (normalized in setOf(root, shards) && !attributes.isDirectory) ||
                    (normalized !in setOf(root, shards) && !attributes.isRegularFile)
                ) {
                    throw FullTreeDataBaselineException("data truth tree contains an invalid path type")
                }
            }
        }
        if (actual != expected) throw FullTreeDataBaselineException("data truth tree is incomplete")
        budget.checkpoint("after verifying data truth tree membership for baseline")
    }

    private fun requireModeledResidentBound(maximumWorkers: Int, limits: FullTreeDataBaselineLimits) {
        val entityBytes = multiplyExact(
            limits.maximumEntityBytes.toLong(),
            maximumWorkers.toLong(),
            "baseline worker entity bytes",
        )
        val modeled = addExact(
            addExact(
                limits.maximumControlArtifactBytes.toLong(),
                entityBytes,
                "baseline modeled resident byte",
            ),
            addExact(
                SQLITE_CACHE_BYTES,
                limits.maximumModeledSqliteTempBytes,
                "baseline SQLite modeled resident byte",
            ),
            "baseline modeled resident byte",
        )
        if (modeled > limits.maximumModeledResidentBytes) {
            throw FullTreeDataBaselineException("data baseline modeled resident bytes exceed their limit")
        }
    }

    private fun streamingLimits(
        maximumInputBytes: Long,
        maximumEntities: Long,
        limits: FullTreeDataBaselineLimits,
    ): FullTreeCanonicalStreamingLimits = FullTreeCanonicalStreamingLimits(
        maximumInputBytes = maximumInputBytes,
        maximumTokens = limits.maximumTokens,
        maximumEntities = maximumEntities,
        maximumEntityBytes = limits.maximumEntityBytes,
        maximumEntityNodes = limits.maximumEntityNodes,
        maximumTotalStringBytes = maximumInputBytes,
    )

    private fun controlJsonLimits(limits: FullTreeDataBaselineLimits): StrictJsonLimits = StrictJsonLimits(
        maximumInputBytes = limits.maximumControlArtifactBytes,
        maximumCanonicalBytes = limits.maximumControlArtifactBytes,
        maximumDepth = 128,
        maximumNodes = 1_000_000,
        maximumStringBytes = minOf(limits.maximumControlArtifactBytes, 1024 * 1024),
        maximumTotalStringBytes = limits.maximumControlArtifactBytes,
    )

    private fun canonicalControlBytes(
        value: JsonElement,
        limits: FullTreeDataBaselineLimits,
    ): ByteArray = try {
        OracleJson.canonicalBytes(value, controlJsonLimits(limits))
    } catch (failure: Exception) {
        throw FullTreeDataBaselineException("data baseline control JSON exceeds its strict limits", failure)
    }

    private fun canonicalControlSnapshot(
        value: JsonObject,
        label: String,
        limits: FullTreeDataBaselineLimits,
    ): JsonObject {
        val bytes = canonicalControlBytes(value, limits)
        return try {
            OracleJson.parseCanonical(bytes, controlJsonLimits(limits)) as? JsonObject
                ?: throw FullTreeDataBaselineException("data baseline $label must be an object")
        } catch (failure: FullTreeDataBaselineException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeDataBaselineException("data baseline $label cannot be bounded and snapshotted", failure)
        }
    }

    private fun canonicalEntity(value: JsonElement, limits: FullTreeDataBaselineLimits): ByteArray = try {
        OracleJson.canonicalBytes(
            value,
            StrictJsonLimits(
                maximumInputBytes = limits.maximumEntityBytes,
                maximumCanonicalBytes = limits.maximumEntityBytes,
                maximumDepth = 128,
                maximumNodes = limits.maximumEntityNodes,
                maximumStringBytes = minOf(limits.maximumEntityBytes, 1024 * 1024),
                maximumTotalStringBytes = limits.maximumEntityBytes,
            ),
        )
    } catch (failure: Exception) {
        throw FullTreeDataBaselineException("data baseline entity exceeds its strict JSON limits", failure)
    }

    private fun dimensionsJson(metrics: Map<String, MetricCounts>): JsonObject = JsonObject(
        DIMENSIONS.associateWith { dimension -> metrics.getValue(dimension).toJson() },
    )

    private fun requireDatabaseBound(connection: Connection, maximumBytes: Long) {
        val bytes = multiplyExact(
            pragmaLong(connection, "page_count"),
            pragmaLong(connection, "page_size"),
            "baseline SQLite byte",
        )
        if (bytes > maximumBytes) throw FullTreeDataBaselineException("data baseline SQLite exceeds its byte limit")
    }

    private fun pragmaLong(connection: Connection, name: String): Long =
        connection.createStatement().use { statement ->
            statement.executeQuery("PRAGMA $name").use { rows ->
                if (!rows.next()) throw FullTreeDataBaselineException("SQLite PRAGMA $name returned no row")
                rows.getLong(1).also {
                    if (rows.next()) throw FullTreeDataBaselineException("SQLite PRAGMA $name returned extra rows")
                }
            }
        }

    private fun pragmaText(connection: Connection, name: String): String =
        connection.createStatement().use { statement ->
            statement.executeQuery("PRAGMA $name").use { rows ->
                if (!rows.next()) throw FullTreeDataBaselineException("SQLite PRAGMA $name returned no row")
                rows.getString(1).also {
                    if (rows.next()) throw FullTreeDataBaselineException("SQLite PRAGMA $name returned extra rows")
                }
            }
        }

    private fun scalar(connection: Connection, sql: String): Long =
        connection.createStatement().use { statement ->
            statement.executeQuery(sql).use { rows ->
                if (!rows.next()) throw FullTreeDataBaselineException("baseline scalar query returned no row")
                rows.getLong(1).also {
                    if (rows.next()) throw FullTreeDataBaselineException("baseline scalar query returned extra rows")
                }
            }
        }

    private fun insertExactlyOnce(statement: java.sql.PreparedStatement, label: String) {
        try {
            if (statement.executeUpdate() != 1) {
                throw FullTreeDataBaselineException("$label was not stored exactly once")
            }
        } catch (failure: FullTreeDataBaselineException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeDataBaselineException("$label is duplicated or invalid", failure)
        }
    }

    private fun requireDigest(value: String, label: String) {
        if (!SHA256.matches(value)) throw FullTreeDataBaselineException("$label SHA-256 is invalid")
    }

    private fun requireIncreasing(current: String, previous: String?, label: String): String {
        if (previous != null && CODE_POINT_STRING_COMPARATOR.compare(previous, current) >= 0) {
            throw FullTreeDataBaselineException("$label are duplicated or not canonically ordered")
        }
        return current
    }

    private fun requireSortedUnique(values: List<String>, label: String) {
        values.zipWithNext().forEach { (left, right) ->
            if (CODE_POINT_STRING_COMPARATOR.compare(left, right) >= 0) {
                throw FullTreeDataBaselineException("$label are duplicated or not canonically ordered")
            }
        }
    }

    private fun compareAbiKeys(left: Pair<String, String>, right: Pair<String, String>): Int {
        val elf = CODE_POINT_STRING_COMPARATOR.compare(left.first, right.first)
        return if (elf != 0) elf else CODE_POINT_STRING_COMPARATOR.compare(left.second, right.second)
    }

    private fun addExact(left: Long, right: Long, label: String): Long = try {
        Math.addExact(left, right)
    } catch (failure: ArithmeticException) {
        throw FullTreeDataBaselineException("$label count exceeds the supported range", failure)
    }

    private fun multiplyExact(left: Long, right: Long, label: String): Long = try {
        Math.multiplyExact(left, right)
    } catch (failure: ArithmeticException) {
        throw FullTreeDataBaselineException("$label count exceeds the supported range", failure)
    }

    private fun increment(value: Long, label: String): Long = addExact(value, 1L, label)

    private fun baselineFailure(message: String, failure: Throwable): FullTreeDataBaselineException =
        if (failure is FullTreeDataBaselineException) failure else FullTreeDataBaselineException(message, failure)

    private fun JsonElement.nullableString(label: String): String? = when (this) {
        JsonNull -> null
        else -> requiredString(label)
    }

    private data class InventoryBinding(
        val indexSha256: String,
        val shardIds: List<String>,
        val shardUnits: Map<String, List<String>>,
        val unitToShard: Map<String, String>,
    )

    private data class TruthInputs(
        val root: Path,
        val index: JsonObject,
        val partitions: List<TruthPartition>,
        val counts: BaselineTruthCounts,
    )

    private data class TruthPartition(
        val index: Int,
        val shardId: String,
        val ordinal: Int,
        val total: Int,
        val path: Path,
        val bytes: Long,
        val sha256: String,
        val counts: BaselineTruthCounts,
    )

    private data class BaselineTruthCounts(
        var globals: Long = 0L,
        var types: Long = 0L,
        var unobservableGlobals: Long = 0L,
        var unobservableTypes: Long = 0L,
        var fields: Long = 0L,
        var bases: Long = 0L,
        var enumerators: Long = 0L,
        var resolvedTypeReferences: Long = 0L,
        var unresolvedTypeReferences: Long = 0L,
        var ambiguousTypeReferences: Long = 0L,
        var crossShardTypeReferences: Long = 0L,
    ) {
        val entities: Long
            get() = safeAdd(globals, types, "truth entity")

        fun add(other: BaselineTruthCounts) {
            globals = safeAdd(globals, other.globals, "truth global")
            types = safeAdd(types, other.types, "truth type")
            unobservableGlobals = safeAdd(
                unobservableGlobals,
                other.unobservableGlobals,
                "unobservable truth global",
            )
            unobservableTypes = safeAdd(unobservableTypes, other.unobservableTypes, "unobservable truth type")
            fields = safeAdd(fields, other.fields, "truth field")
            bases = safeAdd(bases, other.bases, "truth base")
            enumerators = safeAdd(enumerators, other.enumerators, "truth enumerator")
            resolvedTypeReferences = safeAdd(
                resolvedTypeReferences,
                other.resolvedTypeReferences,
                "resolved truth reference",
            )
            unresolvedTypeReferences = safeAdd(
                unresolvedTypeReferences,
                other.unresolvedTypeReferences,
                "unresolved truth reference",
            )
            ambiguousTypeReferences = safeAdd(
                ambiguousTypeReferences,
                other.ambiguousTypeReferences,
                "ambiguous truth reference",
            )
            crossShardTypeReferences = safeAdd(
                crossShardTypeReferences,
                other.crossShardTypeReferences,
                "cross-shard truth reference",
            )
        }

        fun toJson(): JsonObject = JsonObject(
            mapOf(
                "ambiguousTypeReferences" to JsonPrimitive(ambiguousTypeReferences),
                "bases" to JsonPrimitive(bases),
                "crossShardTypeReferences" to JsonPrimitive(crossShardTypeReferences),
                "enumerators" to JsonPrimitive(enumerators),
                "fields" to JsonPrimitive(fields),
                "globals" to JsonPrimitive(globals),
                "resolvedTypeReferences" to JsonPrimitive(resolvedTypeReferences),
                "types" to JsonPrimitive(types),
                "unobservableGlobals" to JsonPrimitive(unobservableGlobals),
                "unobservableTypes" to JsonPrimitive(unobservableTypes),
                "unresolvedTypeReferences" to JsonPrimitive(unresolvedTypeReferences),
            ),
        )

        companion object {
            fun from(record: JsonObject): BaselineTruthCounts = BaselineTruthCounts(
                globals = record.requiredLong("globals"),
                types = record.requiredLong("types"),
                unobservableGlobals = record.requiredLong("unobservableGlobals"),
                unobservableTypes = record.requiredLong("unobservableTypes"),
                fields = record.requiredLong("fields"),
                bases = record.requiredLong("bases"),
                enumerators = record.requiredLong("enumerators"),
                resolvedTypeReferences = record.requiredLong("resolvedTypeReferences"),
                unresolvedTypeReferences = record.requiredLong("unresolvedTypeReferences"),
                ambiguousTypeReferences = record.requiredLong("ambiguousTypeReferences"),
                crossShardTypeReferences = record.requiredLong("crossShardTypeReferences"),
            )

            fun forEntity(kind: String, entity: JsonObject, ownerShard: String): BaselineTruthCounts {
                val result = BaselineTruthCounts()
                when (kind) {
                    "global" -> {
                        result.globals = 1L
                        if (entity.requiredString("population") == "unobservable") {
                            result.unobservableGlobals = 1L
                        }
                    }
                    "type" -> {
                        result.types = 1L
                        if (entity.requiredString("population") == "unobservable") {
                            result.unobservableTypes = 1L
                        }
                        entity.requiredArray("members").objects("truth member").forEach { member ->
                            when (member.requiredString("kind")) {
                                "field" -> result.fields = safeAdd(result.fields, 1L, "truth field")
                                "base" -> result.bases = safeAdd(result.bases, 1L, "truth base")
                                "enumerator" -> result.enumerators = safeAdd(
                                    result.enumerators,
                                    1L,
                                    "truth enumerator",
                                )
                                else -> throw FullTreeDataBaselineException("truth member kind is invalid")
                            }
                        }
                    }
                    else -> throw FullTreeDataBaselineException("truth entity kind is invalid")
                }
                truthReferences(kind, entity).forEach { reference ->
                    if (reference.requiredElement("targetTypeId") is JsonNull) {
                        result.unresolvedTypeReferences = safeAdd(
                            result.unresolvedTypeReferences,
                            1L,
                            "unresolved truth reference",
                        )
                    } else {
                        result.resolvedTypeReferences = safeAdd(
                            result.resolvedTypeReferences,
                            1L,
                            "resolved truth reference",
                        )
                    }
                    if (reference.requiredString("resolutionCode") == "unresolved-authenticated-target-set") {
                        result.ambiguousTypeReferences = safeAdd(
                            result.ambiguousTypeReferences,
                            1L,
                            "ambiguous truth reference",
                        )
                    }
                    val targetOwner = when (val owner = reference.requiredElement("targetOwnerShardId")) {
                        JsonNull -> null
                        else -> owner.requiredString("targetOwnerShardId")
                    }
                    if (targetOwner != null && targetOwner != ownerShard) {
                        result.crossShardTypeReferences = safeAdd(
                            result.crossShardTypeReferences,
                            1L,
                            "cross-shard truth reference",
                        )
                    }
                }
                return result
            }

            private fun truthReferences(kind: String, entity: JsonObject): List<JsonObject> = when (kind) {
                "global" -> listOf(entity.requiredObject("typeReference"))
                "type" -> entity.requiredArray("members").objects("truth member")
                    .map { it.requiredObject("typeReference") }
                else -> throw FullTreeDataBaselineException("truth entity kind is invalid")
            }

            private fun safeAdd(left: Long, right: Long, label: String): Long = try {
                Math.addExact(left, right)
            } catch (failure: ArithmeticException) {
                throw FullTreeDataBaselineException("$label count exceeds the supported range", failure)
            }
        }
    }

    private data class BaselineReconciliationCounts(
        var abiObjects: Long = 0L,
        var abiResolvedSlots: Long = 0L,
        var abiSlots: Long = 0L,
        var dwarfOnlyScoredGlobals: Long = 0L,
        var elfGlobals: Long = 0L,
        var elfOnlyGlobals: Long = 0L,
        var matchedElfGlobals: Long = 0L,
    ) {
        val entities: Long
            get() = listOf(abiObjects, dwarfOnlyScoredGlobals, elfGlobals).fold(0L) { total, value ->
                try {
                    Math.addExact(total, value)
                } catch (failure: ArithmeticException) {
                    throw FullTreeDataBaselineException(
                        "data reconciliation entity count exceeds the supported range",
                        failure,
                    )
                }
            }

        fun requireEnvelope(counts: JsonObject, truth: BaselineTruthCounts) {
            val expected = JsonObject(
                mapOf(
                    "abiObjects" to JsonPrimitive(abiObjects),
                    "abiResolvedSlots" to JsonPrimitive(abiResolvedSlots),
                    "abiSlots" to JsonPrimitive(abiSlots),
                    "dwarfGlobals" to JsonPrimitive(truth.globals),
                    "dwarfOnlyScoredGlobals" to JsonPrimitive(dwarfOnlyScoredGlobals),
                    "dwarfScoredGlobals" to JsonPrimitive(truth.globals - truth.unobservableGlobals),
                    "dwarfTypes" to JsonPrimitive(truth.types),
                    "dwarfUnobservableGlobals" to JsonPrimitive(truth.unobservableGlobals),
                    "elfGlobals" to JsonPrimitive(elfGlobals),
                    "elfOnlyGlobals" to JsonPrimitive(elfOnlyGlobals),
                    "matchedElfGlobals" to JsonPrimitive(matchedElfGlobals),
                    "unexplainedEntities" to JsonPrimitive(0),
                ),
            )
            if (counts != expected) {
                throw FullTreeDataBaselineException("data reconciliation counts differ from streamed truth")
            }
        }
    }

    private data class MetricCounts(
        var exact: Long = 0L,
        var partial: Long = 0L,
        var missing: Long = 0L,
        var fabricated: Long = 0L,
        var excluded: Long = 0L,
    ) {
        val denominator: Long
            get() = safeAdd(safeAdd(exact, partial, "baseline denominator"), missing, "baseline denominator")

        fun add(other: MetricCounts) {
            exact = safeAdd(exact, other.exact, "baseline exact")
            partial = safeAdd(partial, other.partial, "baseline partial")
            missing = safeAdd(missing, other.missing, "baseline missing")
            fabricated = safeAdd(fabricated, other.fabricated, "baseline fabricated")
            excluded = safeAdd(excluded, other.excluded, "baseline excluded")
        }

        fun toJson(): JsonObject = JsonObject(
            mapOf(
                "denominator" to JsonPrimitive(denominator),
                "exact" to JsonPrimitive(exact),
                "excluded" to JsonPrimitive(excluded),
                "fabricated" to JsonPrimitive(fabricated),
                "missing" to JsonPrimitive(missing),
                "partial" to JsonPrimitive(partial),
            ),
        )

        companion object {
            fun from(metric: JsonObject): MetricCounts {
                val result = MetricCounts(
                    exact = metric.requiredLong("exact"),
                    partial = metric.requiredLong("partial"),
                    missing = metric.requiredLong("missing"),
                    fabricated = metric.requiredLong("fabricated"),
                    excluded = metric.requiredLong("excluded"),
                )
                if (metric.requiredLong("denominator") != result.denominator) {
                    throw FullTreeDataBaselineException("data baseline metric denominator does not reconcile")
                }
                return result
            }

            private fun safeAdd(left: Long, right: Long, label: String): Long = try {
                Math.addExact(left, right)
            } catch (failure: ArithmeticException) {
                throw FullTreeDataBaselineException("$label count exceeds the supported range", failure)
            }
        }
    }

    private data class WrittenReport(
        val reportSha256: String,
        val artifactSha256: String,
        val bytes: Long,
        val aggregate: JsonObject,
    )

    private data class FileDigest(val bytes: Long, val sha256: String, val identity: Any)

    private data class TrackedFile(val path: Path, val identity: Any)

    private class Budget(
        limits: FullTreeDataBaselineLimits,
        private val runtime: FullTreeDataBaselineRuntime,
        private val started: FullTreeDataBaselineRuntimeSample,
    ) {
        private val maximumWallNanos = TimeUnit.SECONDS.toNanos(limits.maximumWallClockSeconds)
        private val maximumCpuNanos = TimeUnit.SECONDS.toNanos(limits.maximumCpuSeconds)
        private var periodicUnits = 0

        fun checkpoint(stage: String) {
            if (Thread.currentThread().isInterrupted) {
                throw FullTreeDataBaselineException("data baseline was interrupted $stage")
            }
            val current = runtime.sample(stage)
            val wall = current.wallNanos - started.wallNanos
            val cpu = current.processCpuNanos - started.processCpuNanos
            if (wall < 0L || wall > maximumWallNanos) {
                throw FullTreeDataBaselineException("data baseline exceeds wall-clock bound $stage")
            }
            if (cpu < 0L || cpu > maximumCpuNanos) {
                throw FullTreeDataBaselineException("data baseline exceeds process-CPU bound $stage")
            }
        }

        fun periodicCheckpoint(stage: String) {
            periodicUnits++
            if ((periodicUnits and 255) == 0) checkpoint(stage)
        }
    }

    private class BoundedOutputStream(
        output: OutputStream,
        private val maximumBytes: Long,
        private val budget: Budget,
    ) : FilterOutputStream(output) {
        var count: Long = 0L
            private set
        private var bytesSinceCheckpoint = 0L

        override fun write(value: Int) {
            requireCapacity(1L)
            out.write(value)
            count++
            chargeCheckpointBytes(1L)
        }

        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            if (offset < 0 || length < 0 || offset > bytes.size - length) throw IndexOutOfBoundsException()
            requireCapacity(length.toLong())
            out.write(bytes, offset, length)
            count += length.toLong()
            chargeCheckpointBytes(length.toLong())
        }

        private fun requireCapacity(additional: Long) {
            if (count > maximumBytes - additional) {
                throw FullTreeDataBaselineException("data baseline report exceeds its byte limit")
            }
        }

        private fun chargeCheckpointBytes(bytes: Long) {
            bytesSinceCheckpoint = addExact(bytesSinceCheckpoint, bytes, "baseline report checkpoint byte")
            if (bytesSinceCheckpoint >= REPORT_CHECKPOINT_BYTES) {
                budget.checkpoint("while emitting data baseline report")
                bytesSinceCheckpoint %= REPORT_CHECKPOINT_BYTES
            }
        }
    }

    private class CanonicalReportWriter(private val output: OutputStream) {
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
            if (finished) throw FullTreeDataBaselineException("canonical baseline writer already finished")
            writeAscii("\n}\n")
            finished = true
        }

        private fun writeCanonicalValue(bytes: ByteArray, indentation: Int, indentFirst: Boolean) {
            if (bytes.isEmpty() || bytes.last() != '\n'.code.toByte()) {
                throw FullTreeDataBaselineException("canonical baseline value is malformed")
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

    /** All writes precede final stream authentication and therefore stay in revocable scratch. */
    private class StreamValidation(
        private val connection: Connection,
        prefix: String,
    ) : AutoCloseable {
        private val tablePrefix = if (prefix in STREAM_VALIDATION_PREFIXES) {
            "${prefix}_validation"
        } else {
            throw FullTreeDataBaselineException("data baseline validation table prefix is invalid")
        }
        private val mismatchTable = "${tablePrefix}_mismatches"
        private val metricTable = "${tablePrefix}_metrics"
        private val insertMismatch: java.sql.PreparedStatement
        private val insertMetric: java.sql.PreparedStatement

        init {
            connection.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE $mismatchTable(" +
                        "id TEXT PRIMARY KEY COLLATE BINARY, shard_id TEXT NOT NULL COLLATE BINARY, " +
                        "dimension TEXT NOT NULL COLLATE BINARY, kind TEXT NOT NULL COLLATE BINARY) WITHOUT ROWID",
                )
                statement.execute(
                    "CREATE INDEX ${mismatchTable}_owner ON $mismatchTable(" +
                        "shard_id COLLATE BINARY, dimension COLLATE BINARY, kind COLLATE BINARY, id COLLATE BINARY)",
                )
                statement.execute(
                    "CREATE TABLE $metricTable(" +
                        "shard_id TEXT NOT NULL COLLATE BINARY, dimension TEXT NOT NULL COLLATE BINARY, " +
                        "partial INTEGER NOT NULL, missing INTEGER NOT NULL, " +
                        "PRIMARY KEY(shard_id, dimension)) WITHOUT ROWID",
                )
            }
            insertMismatch = connection.prepareStatement(
                "INSERT INTO $mismatchTable(id, shard_id, dimension, kind) VALUES (?, ?, ?, ?)",
            )
            insertMetric = connection.prepareStatement(
                "INSERT INTO $metricTable(shard_id, dimension, partial, missing) VALUES (?, ?, ?, ?)",
            )
        }

        fun recordMismatch(entity: JsonObject) {
            insertMismatch.setString(1, entity.requiredString("id"))
            insertMismatch.setString(2, entity.requiredString("shardId"))
            insertMismatch.setString(3, entity.requiredString("dimension"))
            insertMismatch.setString(4, entity.requiredString("kind"))
            insertExactlyOnce(insertMismatch, "streamed baseline mismatch identity")
        }

        fun recordShard(entity: JsonObject) {
            DIMENSIONS.forEach { dimension ->
                val metric = entity.requiredObject(dimension)
                insertMetric.setString(1, entity.requiredString("id"))
                insertMetric.setString(2, dimension)
                insertMetric.setLong(3, metric.requiredLong("partial"))
                insertMetric.setLong(4, metric.requiredLong("missing"))
                insertExactlyOnce(insertMetric, "streamed baseline shard metric identity")
            }
        }

        fun requireClosure() {
            val missingOwners = scalar(
                connection,
                "SELECT COUNT(*) FROM $mismatchTable m WHERE NOT EXISTS (" +
                    "SELECT 1 FROM $metricTable s WHERE s.shard_id = m.shard_id AND s.dimension = m.dimension)",
            )
            if (missingOwners != 0L) {
                throw FullTreeDataBaselineException("data baseline mismatch owner is absent from shard metrics")
            }
            val mismatchCount = connection.prepareStatement(
                "SELECT COUNT(*) FROM $mismatchTable WHERE shard_id = ? AND dimension = ? AND kind = ?",
            )
            try {
                connection.createStatement().use { statement ->
                    statement.executeQuery(
                        "SELECT shard_id, dimension, partial, missing FROM $metricTable " +
                            "ORDER BY shard_id COLLATE BINARY, dimension COLLATE BINARY",
                    ).use { rows ->
                        while (rows.next()) {
                            val shardId = rows.getString(1)
                            val dimension = rows.getString(2)
                            fun count(kind: String): Long {
                                mismatchCount.setString(1, shardId)
                                mismatchCount.setString(2, dimension)
                                mismatchCount.setString(3, kind)
                                mismatchCount.executeQuery().use { matches ->
                                    if (!matches.next()) {
                                        throw FullTreeDataBaselineException("baseline mismatch count returned no row")
                                    }
                                    return matches.getLong(1).also {
                                        if (matches.next()) {
                                            throw FullTreeDataBaselineException(
                                                "baseline mismatch count returned extra rows",
                                            )
                                        }
                                    }
                                }
                            }
                            val partial = count("partial")
                            val missing = count("missing")
                            val expectedPartial = if (dimension in setOf("globals", "abiObjects")) {
                                rows.getLong(3)
                            } else {
                                0L
                            }
                            val expectedMissing = if (dimension == "globals") rows.getLong(4) else 0L
                            if (partial != expectedPartial || missing != expectedMissing) {
                                throw FullTreeDataBaselineException(
                                    "data baseline shard mismatch population does not reconcile",
                                )
                            }
                        }
                    }
                }
            } finally {
                mismatchCount.close()
            }
        }

        override fun close() {
            var failure: Throwable? = null
            try {
                insertMismatch.close()
            } catch (closeFailure: Throwable) {
                failure = closeFailure
            }
            try {
                insertMetric.close()
            } catch (closeFailure: Throwable) {
                if (failure == null) failure = closeFailure else failure?.addSuppressed(closeFailure)
            }
            failure?.let { throw it }
        }
    }

    private class ComparisonScratch private constructor(
        private val root: Path,
        private val identity: Any,
        private val maximumBytes: Long,
    ) : AutoCloseable {
        val database: Path = root.resolve("comparison.sqlite")

        fun requireBound() = requireTreeBound(root, maximumBytes, "data baseline comparison scratch")

        override fun close() {
            deleteOwnedTreeIfPresent(root, identity, "data baseline comparison scratch")
        }

        companion object {
            fun create(
                parentPath: Path,
                limits: FullTreeDataBaselineLimits,
                budget: Budget,
            ): ComparisonScratch {
                val parent = requireRealTrustedDirectory(parentPath, "data baseline comparison scratch parent")
                val parentIdentity = directoryAttributes(parent, "data baseline comparison scratch parent").fileKey()
                    ?: throw FullTreeDataBaselineException("data baseline comparison scratch parent has no identity")
                var root: Path? = null
                var identity: Any? = null
                try {
                    val createdRoot = Files.createTempDirectory(parent, ".data-baseline-comparison-")
                    root = createdRoot
                    val createdIdentity = directoryAttributes(createdRoot, "data baseline comparison scratch").fileKey()
                        ?: throw FullTreeDataBaselineException("data baseline comparison scratch has no identity")
                    identity = createdIdentity
                    Files.setPosixFilePermissions(createdRoot, PRIVATE_DIRECTORY_PERMISSIONS)
                    budget.checkpoint("after data baseline comparison scratch creation")
                    forceDirectory(parent)
                    requireDirectoryIdentity(parent, parentIdentity, "data baseline comparison scratch parent")
                    return ComparisonScratch(createdRoot, createdIdentity, limits.maximumScratchBytes)
                } catch (failure: Throwable) {
                    cleanupPartialDirectory(root, identity, "data baseline comparison scratch", failure)
                    throw baselineFailure("cannot create data baseline comparison scratch", failure)
                }
            }
        }
    }

    private class BaselinePublication private constructor(
        val target: Path,
        val staging: Path,
        val scratch: Path,
        private val parentIdentity: Any,
        private val stagingIdentity: Any,
        private val scratchIdentity: Any,
    ) : AutoCloseable {
        private var committed = false

        fun requireBound(maximumBytes: Long) {
            val stagingBytes = treeBytes(staging, "data baseline staging directory")
            val scratchBytes = treeBytes(scratch, "data baseline scratch directory")
            if (addExact(stagingBytes, scratchBytes, "data baseline publication byte") > maximumBytes) {
                throw FullTreeDataBaselineException("data baseline publication scratch exceeds its byte limit")
            }
        }

        fun commit(
            expectedSha256: String,
            expectedBytes: Long,
            maximumBytes: Long,
            budget: Budget,
        ) {
            val report = staging.resolve("report.json")
            verifyTree(staging, report, expectedSha256, expectedBytes, maximumBytes, budget)
            requireDirectoryIdentity(staging, stagingIdentity, "data baseline staging directory")
            requireDirectoryIdentity(scratch, scratchIdentity, "data baseline scratch directory")
            deleteEmptyDirectory(scratch, scratchIdentity, "data baseline scratch directory")
            Files.setPosixFilePermissions(staging, READ_ONLY_DIRECTORY_PERMISSIONS)
            if (Files.getPosixFilePermissions(staging, LinkOption.NOFOLLOW_LINKS) !=
                READ_ONLY_DIRECTORY_PERMISSIONS
            ) {
                throw FullTreeDataBaselineException("data baseline staging directory permissions differ")
            }
            forceDirectory(staging)
            requireDirectoryIdentity(target.parent, parentIdentity, "data baseline output parent")
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                throw FullTreeDataBaselineException("data baseline output target already exists")
            }
            var published = false
            try {
                try {
                    Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE)
                } catch (failure: AtomicMoveNotSupportedException) {
                    throw FullTreeDataBaselineException(
                        "filesystem cannot atomically publish data baseline directory",
                        failure,
                    )
                }
                published = true
                forceDirectory(target.parent)
                requireDirectoryIdentity(target.parent, parentIdentity, "data baseline output parent")
                requireDirectoryIdentity(target, stagingIdentity, "published data baseline directory")
                if (Files.getPosixFilePermissions(target, LinkOption.NOFOLLOW_LINKS) !=
                    READ_ONLY_DIRECTORY_PERMISSIONS
                ) {
                    throw FullTreeDataBaselineException("published data baseline directory permissions differ")
                }
                verifyTree(
                    target,
                    target.resolve("report.json"),
                    expectedSha256,
                    expectedBytes,
                    maximumBytes,
                    budget,
                )
                budget.checkpoint("after atomic data baseline publication")
                committed = true
            } catch (failure: Throwable) {
                if (published) {
                    try {
                        revokePublished(target, stagingIdentity)
                    } catch (revocationFailure: Throwable) {
                        failure.addSuppressed(revocationFailure)
                    }
                }
                throw failure
            }
        }

        override fun close() {
            if (committed) return
            var cleanupFailure: Throwable? = null
            try {
                deleteOwnedTreeIfPresent(staging, stagingIdentity, "data baseline staging directory")
            } catch (failure: Throwable) {
                cleanupFailure = failure
            }
            try {
                deleteOwnedTreeIfPresent(scratch, scratchIdentity, "data baseline scratch directory")
            } catch (failure: Throwable) {
                if (cleanupFailure == null) cleanupFailure = failure else cleanupFailure?.addSuppressed(failure)
            }
            cleanupFailure?.let { throw it }
        }

        companion object {
            fun create(path: Path, budget: Budget): BaselinePublication {
                val target = path.toAbsolutePath().normalize()
                if (target.fileName == null || target.parent == null) {
                    throw FullTreeDataBaselineException("data baseline output must name a directory")
                }
                val parent = requireRealTrustedDirectory(target.parent, "data baseline output parent")
                if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                    throw FullTreeDataBaselineException("data baseline output already exists")
                }
                val parentIdentity = directoryAttributes(parent, "data baseline output parent").fileKey()
                    ?: throw FullTreeDataBaselineException("data baseline output parent has no identity")
                forceDirectory(parent)
                var staging: Path? = null
                var stagingIdentity: Any? = null
                var scratch: Path? = null
                var scratchIdentity: Any? = null
                try {
                    val createdStaging = Files.createTempDirectory(parent, ".${target.fileName}.data-baseline-stage-")
                    staging = createdStaging
                    val createdStagingIdentity = directoryAttributes(
                        createdStaging,
                        "data baseline staging directory",
                    ).fileKey()
                        ?: throw FullTreeDataBaselineException("data baseline staging directory has no identity")
                    stagingIdentity = createdStagingIdentity
                    Files.setPosixFilePermissions(createdStaging, PRIVATE_DIRECTORY_PERMISSIONS)
                    budget.checkpoint("after data baseline staging creation")

                    val createdScratch = Files.createTempDirectory(parent, ".${target.fileName}.data-baseline-scratch-")
                    scratch = createdScratch
                    val createdScratchIdentity = directoryAttributes(
                        createdScratch,
                        "data baseline scratch directory",
                    ).fileKey()
                        ?: throw FullTreeDataBaselineException("data baseline scratch directory has no identity")
                    scratchIdentity = createdScratchIdentity
                    Files.setPosixFilePermissions(createdScratch, PRIVATE_DIRECTORY_PERMISSIONS)
                    budget.checkpoint("after data baseline scratch creation")
                    forceDirectory(parent)
                    requireDirectoryIdentity(parent, parentIdentity, "data baseline output parent")
                    return BaselinePublication(
                        target,
                        createdStaging,
                        createdScratch,
                        parentIdentity,
                        createdStagingIdentity,
                        createdScratchIdentity,
                    )
                } catch (failure: Throwable) {
                    cleanupPartialDirectory(scratch, scratchIdentity, "data baseline scratch directory", failure)
                    cleanupPartialDirectory(staging, stagingIdentity, "data baseline staging directory", failure)
                    try {
                        forceDirectory(parent)
                    } catch (cleanupFailure: Throwable) {
                        failure.addSuppressed(cleanupFailure)
                    }
                    throw baselineFailure("cannot create data baseline publication", failure)
                }
            }
        }

        private fun verifyTree(
            root: Path,
            report: Path,
            expectedSha256: String,
            expectedBytes: Long,
            maximumBytes: Long,
            budget: Budget,
        ) {
            val expected = setOf(root, report)
            val actual = hashSetOf<Path>()
            Files.walk(root).use { paths ->
                paths.forEach { path ->
                    budget.periodicCheckpoint("while verifying data baseline publication membership")
                    val normalized = path.toAbsolutePath().normalize()
                    if (!actual.add(normalized) || normalized !in expected) {
                        throw FullTreeDataBaselineException("data baseline publication contains an extra path")
                    }
                    val attributes = Files.readAttributes(
                        normalized,
                        BasicFileAttributes::class.java,
                        LinkOption.NOFOLLOW_LINKS,
                    )
                    if (attributes.isSymbolicLink || (normalized == root && !attributes.isDirectory) ||
                        (normalized == report && !attributes.isRegularFile)
                    ) {
                        throw FullTreeDataBaselineException("data baseline publication contains an invalid path type")
                    }
                }
            }
            if (actual != expected) throw FullTreeDataBaselineException("data baseline publication is incomplete")
            val digest = digestFile(report, maximumBytes, "data baseline publication report", budget)
            if (digest.bytes != expectedBytes || digest.sha256 != expectedSha256) {
                throw FullTreeDataBaselineException("data baseline publication report binding differs")
            }
            if (Files.getPosixFilePermissions(report, LinkOption.NOFOLLOW_LINKS) != READ_ONLY_FILE_PERMISSIONS) {
                throw FullTreeDataBaselineException("data baseline publication report permissions differ")
            }
        }

        private fun revokePublished(path: Path, expectedIdentity: Any) {
            requireDirectoryIdentity(path, expectedIdentity, "unverified data baseline publication")
            Files.setPosixFilePermissions(path, PRIVATE_DIRECTORY_PERMISSIONS)
            val report = path.resolve("report.json")
            val paths = Files.walk(path).use { it.toList() }
            if (paths.toSet() != setOf(path, report)) {
                throw FullTreeDataBaselineException("cannot safely revoke data baseline publication with extra paths")
            }
            Files.delete(report)
            Files.delete(path)
            forceDirectory(path.parent)
        }

        private fun deleteEmptyDirectory(path: Path, expectedIdentity: Any, label: String) {
            requireDirectoryIdentity(path, expectedIdentity, label)
            Files.newDirectoryStream(path).use { entries ->
                if (entries.iterator().hasNext()) throw FullTreeDataBaselineException("$label is not empty")
            }
            Files.delete(path)
            forceDirectory(path.parent)
        }
    }

    private fun cleanupPartialDirectory(path: Path?, identity: Any?, label: String, failure: Throwable) {
        if (path == null) return
        try {
            if (identity != null) {
                deleteOwnedTreeIfPresent(path, identity, label)
            } else if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                val attributes = Files.readAttributes(
                    path,
                    BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                )
                if (!attributes.isDirectory || attributes.isSymbolicLink) {
                    throw FullTreeDataBaselineException("$label has an unsafe partial identity")
                }
                Files.delete(path)
            }
        } catch (cleanupFailure: Throwable) {
            failure.addSuppressed(cleanupFailure)
        }
    }

    private fun createTrackedTemporaryFile(
        parent: Path,
        prefix: String,
        suffix: String,
        label: String,
    ): TrackedFile {
        val parentIdentity = directoryAttributes(parent, "$label parent").fileKey()
            ?: throw FullTreeDataBaselineException("$label parent has no identity")
        var path: Path? = null
        var identity: Any? = null
        try {
            val created = Files.createTempFile(parent, prefix, suffix)
            path = created
            val createdIdentity = regularFileAttributes(created, label).fileKey()
                ?: throw FullTreeDataBaselineException("$label has no identity")
            identity = createdIdentity
            requireDirectoryIdentity(parent, parentIdentity, "$label parent")
            return TrackedFile(created, createdIdentity)
        } catch (failure: Throwable) {
            val created = path
            if (created != null) {
                try {
                    val attributes = Files.readAttributes(
                        created,
                        BasicFileAttributes::class.java,
                        LinkOption.NOFOLLOW_LINKS,
                    )
                    if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.size() != 0L) {
                        throw FullTreeDataBaselineException("$label has an unsafe partial identity")
                    }
                    identity?.let { expected -> requireFileIdentity(created, expected, label) }
                    Files.delete(created)
                } catch (cleanupFailure: Throwable) {
                    failure.addSuppressed(cleanupFailure)
                }
            }
            throw baselineFailure("cannot create $label", failure)
        }
    }

    private fun deleteOwnedTreeIfPresent(path: Path, expectedIdentity: Any, label: String) {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return
        requireDirectoryIdentity(path, expectedIdentity, label)
        Files.setPosixFilePermissions(path, PRIVATE_DIRECTORY_PERMISSIONS)
        val paths = Files.walk(path).use { it.toList() }
        paths.filter { Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) }.forEach {
            Files.setPosixFilePermissions(it, PRIVATE_DIRECTORY_PERMISSIONS)
        }
        paths.sortedWith(Comparator.reverseOrder()).forEach { candidate ->
            val attributes = Files.readAttributes(
                candidate,
                BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
            if (attributes.isSymbolicLink || (!attributes.isDirectory && !attributes.isRegularFile)) {
                throw FullTreeDataBaselineException("$label contains an unsafe path during cleanup")
            }
            Files.delete(candidate)
        }
        forceDirectory(path.parent)
    }

    private fun requireTreeBound(root: Path, maximumBytes: Long, label: String) {
        if (treeBytes(root, label) > maximumBytes) {
            throw FullTreeDataBaselineException("$label exceeds its byte limit")
        }
    }

    private fun treeBytes(root: Path, label: String): Long {
        var bytes = 0L
        Files.walk(root).use { paths ->
            paths.forEach { path ->
                val attributes = Files.readAttributes(
                    path,
                    BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                )
                if (attributes.isSymbolicLink || (!attributes.isDirectory && !attributes.isRegularFile)) {
                    throw FullTreeDataBaselineException("$label contains an unsafe path")
                }
                if (attributes.isRegularFile) bytes = addExact(bytes, attributes.size(), "$label byte")
            }
        }
        return bytes
    }

    private fun digestFile(
        path: Path,
        maximumBytes: Long,
        label: String,
        budget: Budget? = null,
    ): FileDigest {
        val before = regularFileAttributes(path, label)
        val beforePermissions = readTrustedFilePermissions(path, label)
        if (before.size() !in 1L..maximumBytes) throw FullTreeDataBaselineException("$label exceeds its byte limit")
        val digest = MessageDigest.getInstance("SHA-256")
        var bytes = 0L
        Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                bytes = addExact(bytes, read.toLong(), "$label byte")
                if (bytes > maximumBytes) throw FullTreeDataBaselineException("$label exceeds its byte limit")
                digest.update(buffer, 0, read)
                budget?.periodicCheckpoint("while hashing $label")
            }
        }
        val after = regularFileAttributes(path, label)
        val afterPermissions = readTrustedFilePermissions(path, label)
        if (before.fileKey() != after.fileKey() || before.size() != after.size() ||
            before.lastModifiedTime() != after.lastModifiedTime() || beforePermissions != afterPermissions
        ) {
            throw FullTreeDataBaselineException("$label changed while hashing")
        }
        return FileDigest(bytes, digest.digest().hex(), after.fileKey()!!)
    }

    private fun requireRealTrustedDirectory(path: Path, label: String): Path {
        val normalized = path.toAbsolutePath().normalize()
        val attributes = directoryAttributes(normalized, label)
        if (normalized.toRealPath() != normalized || attributes.fileKey() == null) {
            throw FullTreeDataBaselineException("$label path contains a symbolic link or lacks identity")
        }
        val permissions = Files.getFileAttributeView(
            normalized,
            PosixFileAttributeView::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )?.readAttributes()?.permissions()
            ?: throw FullTreeDataBaselineException("$label requires POSIX permissions")
        if (permissions.any { it in UNTRUSTED_WRITE_PERMISSIONS }) {
            throw FullTreeDataBaselineException("$label is writable by an untrusted principal")
        }
        return normalized
    }

    private fun directoryAttributes(path: Path, label: String): BasicFileAttributes {
        val attributes = try {
            Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw FullTreeDataBaselineException("$label is unavailable", failure)
        }
        if (!attributes.isDirectory || attributes.isSymbolicLink) {
            throw FullTreeDataBaselineException("$label must be a real directory")
        }
        return attributes
    }

    private fun regularFileAttributes(path: Path, label: String): BasicFileAttributes {
        val attributes = try {
            Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw FullTreeDataBaselineException("$label is unavailable", failure)
        }
        if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
            throw FullTreeDataBaselineException("$label must be an identity-bearing regular file")
        }
        return attributes
    }

    private fun readTrustedFilePermissions(path: Path, label: String): Set<PosixFilePermission> {
        val permissions = Files.getFileAttributeView(
            path,
            PosixFileAttributeView::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )?.readAttributes()?.permissions()
            ?: throw FullTreeDataBaselineException("$label requires POSIX permissions")
        if (permissions.any { it in UNTRUSTED_WRITE_PERMISSIONS }) {
            throw FullTreeDataBaselineException("$label is writable by an untrusted principal")
        }
        return permissions.toSet()
    }

    private fun requireDirectoryIdentity(path: Path, expected: Any, label: String) {
        if (directoryAttributes(path, label).fileKey() != expected) {
            throw FullTreeDataBaselineException("$label changed identity")
        }
    }

    private fun requireFileIdentity(path: Path, expected: Any, label: String) {
        if (regularFileAttributes(path, label).fileKey() != expected) {
            throw FullTreeDataBaselineException("$label changed identity")
        }
    }

    private fun forceDirectory(path: Path) {
        FileChannel.open(path, StandardOpenOption.READ).use { it.force(true) }
    }

    private fun ByteArray.hex(): String = joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }

    private const val ELF_ONLY_SHARD = "elf-only"
    private const val SQLITE_PAGE_BYTES = 4096L
    private const val SQLITE_CACHE_BYTES = 16L * 1024L * 1024L
    private const val SQLITE_APPLICATION_ID = 0x4443424c
    private const val SQLITE_SCHEMA_VERSION = 1
    private const val SQLITE_TEMP_STORE_MEMORY = 2
    private const val REPORT_CHECKPOINT_BYTES = 1024L * 1024L
    private val DIMENSIONS = listOf("abiObjects", "globals", "types")
    private val EXPECTED_MISMATCH_KINDS = setOf(
        "globals" to "partial",
        "globals" to "missing",
        "abiObjects" to "partial",
    )
    private val STREAM_VALIDATION_PREFIXES = setOf("accepted", "baseline", "current", "generated")
    private val SHA256 = Regex("[0-9a-f]{64}")
    private val HEX_ADDRESS = Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})")
    private val TRUTH_FIELDS = listOf("counts", "globals", "oracle", "schemaVersion", "shard", "types")
    private val RECONCILIATION_FIELDS = listOf(
        "abiObjects",
        "counts",
        "dwarfOnlyScoredGlobals",
        "globals",
        "oracle",
        "reportSha256",
        "schemaVersion",
    )
    private val BASELINE_FIELDS = listOf(
        "aggregate",
        "configurationSha256",
        "dataTruthIndexSha256",
        "mismatches",
        "reconciliationReportSha256",
        "reportSha256",
        "schemaVersion",
        "shards",
    )
    private val INVENTORY_INDEX_DOMAIN = "full-tree-index-v1\u0000".toByteArray(StandardCharsets.UTF_8)
    private val SYSTEM_RUNTIME = FullTreeDataBaselineRuntime {
        FullTreeDataBaselineRuntimeSample(
            wallNanos = System.nanoTime(),
            processCpuNanos = ProcessHandle.current().info().totalCpuDuration()
                .orElseThrow { FullTreeDataBaselineException("process CPU duration is unavailable") }
                .toNanos(),
        )
    }
    private val PRIVATE_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
    private val READ_ONLY_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("r-x------")
    private val PRIVATE_FILE_PERMISSIONS: Set<PosixFilePermission> = setOf(
        PosixFilePermission.OWNER_READ,
        PosixFilePermission.OWNER_WRITE,
    )
    private val READ_ONLY_FILE_PERMISSIONS = PosixFilePermissions.fromString("r--------")
    private val UNTRUSTED_WRITE_PERMISSIONS: Set<PosixFilePermission> = setOf(
        PosixFilePermission.GROUP_WRITE,
        PosixFilePermission.OTHERS_WRITE,
    )
    private val CODE_POINT_STRING_COMPARATOR = Comparator<String> { left, right ->
        var leftOffset = 0
        var rightOffset = 0
        while (leftOffset < left.length && rightOffset < right.length) {
            val leftCodePoint = Character.codePointAt(left, leftOffset)
            val rightCodePoint = Character.codePointAt(right, rightOffset)
            if (leftCodePoint != rightCodePoint) return@Comparator leftCodePoint.compareTo(rightCodePoint)
            leftOffset += Character.charCount(leftCodePoint)
            rightOffset += Character.charCount(rightCodePoint)
        }
        (left.length - leftOffset).compareTo(right.length - rightOffset)
    }
    private val INVENTORY_UNIT_COMPARATOR = Comparator<JsonObject> { left, right ->
        val path = CODE_POINT_STRING_COMPARATOR.compare(
            left.requiredString("sourcePath"),
            right.requiredString("sourcePath"),
        )
        if (path != 0) path else CODE_POINT_STRING_COMPARATOR.compare(
            left.requiredString("id"),
            right.requiredString("id"),
        )
    }
    private val EMPTY_RECONCILIATION_ORACLE = JsonObject(emptyMap())
    private val EMPTY_RECONCILIATION_COUNTS = JsonObject(
        mapOf(
            "abiObjects" to JsonPrimitive(0),
            "abiResolvedSlots" to JsonPrimitive(0),
            "abiSlots" to JsonPrimitive(0),
            "dwarfGlobals" to JsonPrimitive(0),
            "dwarfOnlyScoredGlobals" to JsonPrimitive(0),
            "dwarfScoredGlobals" to JsonPrimitive(0),
            "dwarfTypes" to JsonPrimitive(0),
            "dwarfUnobservableGlobals" to JsonPrimitive(0),
            "elfGlobals" to JsonPrimitive(0),
            "elfOnlyGlobals" to JsonPrimitive(0),
            "matchedElfGlobals" to JsonPrimitive(0),
            "unexplainedEntities" to JsonPrimitive(0),
        ),
    )
    private val EMPTY_DIMENSIONS = dimensionsJson(DIMENSIONS.associateWith { MetricCounts() })
    private val BASELINE_POLICY = JsonObject(
        mapOf(
            "abiExact" to JsonPrimitive("all-authenticated-slots-resolved-or-no-pointer-slots"),
            "globalExact" to JsonPrimitive("dwarf-elf-reconciled"),
            "globalPartial" to JsonPrimitive("authenticated-elf-only"),
            "id" to JsonPrimitive("full-tree-data-baseline"),
            "typeExact" to JsonPrimitive("complete-dwarf-layout"),
            "version" to JsonPrimitive(1),
        ),
    )
}
