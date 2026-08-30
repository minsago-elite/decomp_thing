package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.io.BufferedOutputStream
import java.io.FilterOutputStream
import java.io.OutputStream
import java.math.BigInteger
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
import java.util.EnumSet
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

data class FullTreeDataReconciliationLimits(
    val maximumControlArtifactBytes: Int = 16 * 1024 * 1024,
    val maximumTruthPartitionBytes: Long = 1024L * 1024L * 1024L,
    val maximumElfIndexBytes: Long = 4L * 1024L * 1024L * 1024L,
    val maximumReportBytes: Long = 4L * 1024L * 1024L * 1024L,
    val maximumDatabaseBytes: Long = 8L * 1024L * 1024L * 1024L,
    val maximumScratchBytes: Long = 12L * 1024L * 1024L * 1024L,
    val maximumEntities: Long = 20_000_000L,
    val maximumTokens: Long = 500_000_000L,
    val maximumEntityBytes: Int = 16 * 1024 * 1024,
    val maximumEntityNodes: Int = 1_000_000,
    val maximumMatchesPerElfGlobal: Int = 1_000_000,
    val maximumElfScannedSymbolsPerArtifact: Long = 2_000_000L,
    val maximumAbiObjectBytes: Long = 1024L * 1024L,
    val maximumAbiSlots: Long = 2_000_000L,
    val maximumModeledSqliteTempBytes: Long = 64L * 1024L * 1024L,
    val maximumWorkers: Int = 32,
) {
    init {
        require(maximumControlArtifactBytes in 1..64 * 1024 * 1024)
        require(maximumTruthPartitionBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumElfIndexBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumReportBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumDatabaseBytes in 1L..8L * 1024L * 1024L * 1024L)
        require(maximumScratchBytes in maximumDatabaseBytes..32L * 1024L * 1024L * 1024L)
        require(maximumEntities in 1L..50_000_000L)
        require(maximumTokens in 1L..1_000_000_000L)
        require(maximumEntityBytes in 1..64 * 1024 * 1024)
        require(maximumEntityNodes in 1..1_000_000)
        require(maximumMatchesPerElfGlobal in 1..1_000_000)
        require(maximumElfScannedSymbolsPerArtifact in 1L..20_000_000L)
        require(maximumAbiObjectBytes in 1L..64L * 1024L * 1024L)
        require(maximumAbiSlots in 1L..20_000_000L)
        require(maximumModeledSqliteTempBytes in 1L..1024L * 1024L * 1024L)
        require(maximumWorkers in 1..32)
    }
}

data class FullTreeDataReconciliationGeneration(
    val reportSha256: String,
    val dataTruthIndexSha256: String,
    val elfDataIndexSha256: String,
    val outputBytes: Long,
    val counts: JsonObject,
)

internal data class FullTreeReconciliationRuntimeSample(val wallNanos: Long, val processCpuNanos: Long)

internal fun interface FullTreeReconciliationRuntime {
    fun sample(stage: String): FullTreeReconciliationRuntimeSample
}

/**
 * Authoritative Kotlin/JVM reconciliation of authenticated DWARF truth and ELF data evidence.
 *
 * Large truth partitions and the ELF index are canonical-streamed one entity at a time into a
 * bounded scratch SQLite database. The elapsed wall and process-CPU checks are cooperative
 * monotonic checkpoints, not operating-system hard limits. SQLite temp storage is forced to memory
 * so it cannot escape the owned scratch directory; plans are also rejected if they request a temp
 * B-tree. Disk, input, token, entity, and SQLite page limits fail synchronously. The resident-byte
 * calculation includes configured SQLite temp and match-map allowances, but remains a modeled
 * working-set check and is deliberately not described as an OS-enforced cap.
 */
object FullTreeDataReconciliationSqlite {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256("full-tree-data-reconciliation", RECONCILIATION_POLICY)
    }

    val elfDataConfigurationSha256: String by lazy {
        OracleSchemas.configurationSha256("full-tree-elf-data", ELF_DATA_POLICY)
    }

    fun generate(
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        sourceLockSha256: String,
        artifactManifestSha256: String,
        dataTruthRoot: Path,
        dataTruthIndexSha256: String,
        elfDataIndex: Path,
        elfDataIndexSha256: String,
        outputRoot: Path,
        maximumWorkers: Int,
        limits: FullTreeDataReconciliationLimits = FullTreeDataReconciliationLimits(),
    ): FullTreeDataReconciliationGeneration = generateInternal(
        scope,
        scopeSha256,
        inventory,
        sourceLockSha256,
        artifactManifestSha256,
        dataTruthRoot,
        dataTruthIndexSha256,
        elfDataIndex,
        elfDataIndexSha256,
        outputRoot,
        maximumWorkers,
        limits,
        SYSTEM_RUNTIME,
    )

    internal fun generateForTesting(
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        sourceLockSha256: String,
        artifactManifestSha256: String,
        dataTruthRoot: Path,
        dataTruthIndexSha256: String,
        elfDataIndex: Path,
        elfDataIndexSha256: String,
        outputRoot: Path,
        maximumWorkers: Int,
        limits: FullTreeDataReconciliationLimits = FullTreeDataReconciliationLimits(),
        runtime: FullTreeReconciliationRuntime,
    ): FullTreeDataReconciliationGeneration = generateInternal(
        scope,
        scopeSha256,
        inventory,
        sourceLockSha256,
        artifactManifestSha256,
        dataTruthRoot,
        dataTruthIndexSha256,
        elfDataIndex,
        elfDataIndexSha256,
        outputRoot,
        maximumWorkers,
        limits,
        runtime,
    )

    private fun generateInternal(
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        sourceLockSha256: String,
        artifactManifestSha256: String,
        dataTruthRoot: Path,
        dataTruthIndexSha256: String,
        elfDataIndex: Path,
        elfDataIndexSha256: String,
        outputRoot: Path,
        maximumWorkers: Int,
        limits: FullTreeDataReconciliationLimits,
        runtime: FullTreeReconciliationRuntime,
    ): FullTreeDataReconciliationGeneration {
        val runtimeStart = runtime.sample("start")
        requireDigest(scopeSha256, "scope")
        requireDigest(sourceLockSha256, "source lock")
        requireDigest(artifactManifestSha256, "artifact manifest")
        requireDigest(dataTruthIndexSha256, "data truth index")
        requireDigest(elfDataIndexSha256, "ELF data index")
        if (maximumWorkers !in 1..limits.maximumWorkers) {
            throw FullTreeDataTruthException("data reconciliation worker count exceeds its configured bound")
        }
        // Bound and snapshot hostile caller trees before schema traversal, sorting, grouping, or hashing.
        val authenticatedScope = canonicalControlSnapshot(scope, "scope", limits)
        val authenticatedInventory = canonicalControlSnapshot(inventory, "inventory", limits)
        val canonicalScopeSha256 = OracleArtifacts.sha256(canonicalControlBytes(authenticatedScope, limits))
        if (canonicalScopeSha256 != scopeSha256) {
            throw FullTreeDataTruthException("scope SHA-256 does not authenticate its canonical document")
        }
        val budget = CooperativeBudget(authenticatedScope, runtime, runtimeStart)
        budget.checkpoint("after control snapshots")
        val inputs = authenticateControlInputs(
            authenticatedScope,
            scopeSha256,
            authenticatedInventory,
            sourceLockSha256,
            artifactManifestSha256,
            dataTruthRoot,
            dataTruthIndexSha256,
            limits,
            budget,
        )
        requireModeledResidentBound(authenticatedScope, maximumWorkers, limits)
        val maximumReportBytes = minOf(
            limits.maximumReportBytes,
            authenticatedScope.requiredObject("bounds").requiredObject("wholeRun")
                .requiredLong("serializedBytes"),
        )
        val publication = ReconciliationPublication.create(outputRoot, budget)
        var complete = false
        try {
            val database = publication.scratch.resolve("reconciliation.sqlite")
            val oracle = JsonObject(
                mapOf(
                    "configurationSha256" to JsonPrimitive(configurationSha256),
                    "dataTruthIndexSha256" to JsonPrimitive(dataTruthIndexSha256),
                    "elfDataIndexSha256" to JsonPrimitive(elfDataIndexSha256),
                    "inventoryIndexSha256" to JsonPrimitive(authenticatedInventory.requiredString("indexSha256")),
                    "scopeSha256" to JsonPrimitive(scopeSha256),
                ),
            )
            val result = DriverManager.getConnection(SqliteJdbcPaths.create(database)).use { connection ->
                configureDatabase(connection, limits)
                connection.autoCommit = false
                try {
                    createSchema(connection)
                    requireNoTempBTreePlans(connection)
                    val truthCounts = ingestTruth(
                        connection,
                        inputs,
                        authenticatedScope,
                        authenticatedInventory,
                        budget,
                        limits,
                    )
                    requireDatabaseBound(connection, limits.maximumDatabaseBytes)
                    requireScratchBound(publication.scratch, limits.maximumScratchBytes)
                    val elfCounts = ingestElfAndReconcile(
                        connection,
                        elfDataIndex,
                        elfDataIndexSha256,
                        authenticatedScope,
                        scopeSha256,
                        authenticatedInventory,
                        oracle,
                        truthCounts,
                        budget,
                        limits,
                    )
                    requireNoTempBTreePlans(connection)
                    val counts = reconciliationCounts(connection, truthCounts, elfCounts, budget)
                    val reportEntities = listOf(
                        counts.requiredLong("abiObjects"),
                        counts.requiredLong("dwarfOnlyScoredGlobals"),
                        counts.requiredLong("elfGlobals"),
                    ).fold(0L) { total, count -> addExact(total, count, "reconciliation report entity") }
                    if (reportEntities > limits.maximumEntities ||
                        reportEntities > authenticatedScope.requiredObject("bounds").requiredObject("wholeRun")
                            .requiredLong("entities")
                    ) {
                        throw FullTreeDataTruthException("data reconciliation report exceeds its entity bound")
                    }
                    validateReportEnvelope(oracle, counts)
                    connection.commit()
                    requireDatabaseBound(connection, limits.maximumDatabaseBytes)
                    requireScratchBound(publication.scratch, limits.maximumScratchBytes)
                    budget.checkpoint("before reconciliation report publication")
                    writeReport(
                        connection,
                        publication.staging.resolve("report.json"),
                        oracle,
                        counts,
                        maximumReportBytes,
                        limits,
                        budget,
                    ).let {
                        ReportResult(it.reportSha256, it.artifactSha256, it.bytes, counts)
                    }
                } catch (failure: Throwable) {
                    try {
                        connection.rollback()
                    } catch (rollbackFailure: Throwable) {
                        failure.addSuppressed(rollbackFailure)
                    }
                    if (failure is FullTreeDataTruthException) throw failure
                    throw FullTreeDataTruthException("cannot reconcile authenticated full-tree data", failure)
                }
            }
            Files.delete(database)
            budget.checkpoint("before atomic reconciliation publication")
            publication.commit(result.artifactSha256, result.outputBytes, maximumReportBytes, budget)
            complete = true
            return FullTreeDataReconciliationGeneration(
                reportSha256 = result.reportSha256,
                dataTruthIndexSha256 = dataTruthIndexSha256,
                elfDataIndexSha256 = elfDataIndexSha256,
                outputBytes = result.outputBytes,
                counts = result.counts,
            )
        } finally {
            if (!complete) publication.close()
        }
    }

    private fun authenticateControlInputs(
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        sourceLockSha256: String,
        artifactManifestSha256: String,
        dataTruthRoot: Path,
        dataTruthIndexSha256: String,
        limits: FullTreeDataReconciliationLimits,
        budget: CooperativeBudget,
    ): AuthenticatedInputs {
        try {
            OracleSchemas.validate("full-tree-scope", scope)
            OracleSchemas.validate("full-tree-inventory", inventory)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data reconciliation control input fails schema validation", failure)
        }
        validateScopeSemantics(scope)
        budget.checkpoint("after scope authentication")
        val scopeOracle = scope.requiredObject("oracle")
        if (
            scopeOracle.requiredString("sourceLockSha256") != sourceLockSha256 ||
            scopeOracle.requiredString("artifactManifestSha256") != artifactManifestSha256
        ) {
            throw FullTreeDataTruthException("source-lock or artifact-manifest identity differs from scope")
        }
        validateInventory(scope, scopeSha256, inventory, budget)

        val root = requireRealTrustedDirectory(dataTruthRoot, "data truth root")
        val indexPath = root.resolve("index.json")
        val snapshot = try {
            OracleArtifacts.read(indexPath, OracleArtifactLimits(limits.maximumControlArtifactBytes))
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("cannot read authenticated data truth index", failure)
        }
        if (snapshot.sha256 != dataTruthIndexSha256) {
            throw FullTreeDataTruthException("data truth index SHA-256 differs from its expected identity")
        }
        val index = try {
            OracleJson.parseCanonical(snapshot.bytes, controlJsonLimits(limits)) as? JsonObject
                ?: throw FullTreeDataTruthException("data truth index must be an object")
        } catch (failure: FullTreeDataTruthException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data truth index is not strict canonical JSON", failure)
        }
        try {
            OracleSchemas.validate("full-tree-data-truth-index", index)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data truth index fails schema validation", failure)
        }
        val withoutHash = JsonObject(index.filterKeys { it != "indexSha256" })
        if (index.requiredString("indexSha256") != OracleArtifacts.sha256(canonicalControlBytes(withoutHash, limits))) {
            throw FullTreeDataTruthException("data truth index self-hash does not reconcile")
        }
        val truthOracle = index.requiredObject("oracle")
        if (
            truthOracle.keys != setOf(
                "configurationSha256",
                "dataObservationIndexSha256",
                "inventoryIndexSha256",
                "scopeSha256",
            ) ||
            truthOracle.requiredString("configurationSha256") != FullTreeDataTruthSqlite.configurationSha256 ||
            truthOracle.requiredString("inventoryIndexSha256") != inventory.requiredString("indexSha256") ||
            truthOracle.requiredString("scopeSha256") != scopeSha256
        ) {
            throw FullTreeDataTruthException("data truth index bindings differ from authenticated controls")
        }
        requireDigest(truthOracle.requiredString("dataObservationIndexSha256"), "data observation index")
        val records = authenticateTruthRecords(root, index, inventory, scope, limits, budget)
        verifyTruthTreeMembership(root, records, budget)
        return AuthenticatedInputs(root, index, records)
    }

    private fun validateScopeSemantics(scope: JsonObject) {
        val prefixMaps = scope.requiredObject("pathPolicy").requiredArray("prefixMaps")
            .objects("scope prefix map")
        val sources = prefixMaps.map { it.requiredString("from") }
        val targets = prefixMaps.map { it.requiredString("to") }
        if (sources.distinct().size != sources.size) {
            throw FullTreeDataTruthException("scope prefix-map sources are duplicated")
        }
        sources.forEach { left ->
            sources.forEach { right ->
                if (left != right && right.startsWith(left)) {
                    throw FullTreeDataTruthException("scope prefix-map sources overlap")
                }
            }
        }
        val rules = scope.requiredObject("sharding").requiredArray("rules").objects("scope shard rule")
        val rulePrefixes = rules.map { it.requiredString("pathPrefix") }
        if (rulePrefixes.distinct().size != rulePrefixes.size) {
            throw FullTreeDataTruthException("scope shard-rule prefixes are duplicated")
        }
        rules.forEach { rule ->
            if (targets.none { rule.requiredString("pathPrefix").startsWith(it) }) {
                throw FullTreeDataTruthException("scope shard rule is outside normalized prefix-map targets")
            }
        }
        val perShard = scope.requiredObject("bounds").requiredObject("perShard")
        val wholeRun = scope.requiredObject("bounds").requiredObject("wholeRun")
        BOUND_NAMES.forEach { name ->
            if (perShard.requiredLong(name) > wholeRun.requiredLong(name)) {
                throw FullTreeDataTruthException("scope per-shard $name exceeds its whole-run bound")
            }
        }
    }

    private fun validateInventory(
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        budget: CooperativeBudget,
    ) {
        val scopeOracle = scope.requiredObject("oracle")
        val expectedOracle = JsonObject(
            mapOf(
                "artifactManifestSha256" to scopeOracle.requiredElement("artifactManifestSha256"),
                "id" to scopeOracle.requiredElement("id"),
                "richArtifactSha256" to scopeOracle.requiredElement("richArtifactSha256"),
                "scopeSha256" to JsonPrimitive(scopeSha256),
                "sourceLockSha256" to scopeOracle.requiredElement("sourceLockSha256"),
            ),
        )
        if (inventory.requiredObject("oracle") != expectedOracle) {
            throw FullTreeDataTruthException("inventory bindings differ from authenticated scope")
        }
        val units = inventory.requiredArray("units").objects("inventory unit")
        if (units != units.sortedWith(INVENTORY_UNIT_COMPARATOR)) {
            throw FullTreeDataTruthException("inventory units are not canonically ordered")
        }
        val ids = units.map { it.requiredString("id") }
        val paths = units.map { it.requiredString("sourcePath") }
        if (ids.distinct().size != ids.size || paths.distinct().size != paths.size) {
            throw FullTreeDataTruthException("inventory unit source identities are duplicated")
        }
        val indexDigest = MessageDigest.getInstance("SHA-256")
        indexDigest.update(INVENTORY_INDEX_DOMAIN)
        units.forEach { unit ->
            budget.periodicCheckpoint("while authenticating inventory")
            indexDigest.update(MessageDigest.getInstance("SHA-256").digest(OracleJson.canonicalBytes(unit)))
        }
        if (inventory.requiredString("indexSha256") != indexDigest.digest().hex()) {
            throw FullTreeDataTruthException("inventory index hash does not reconcile")
        }
        val grouped = units.groupBy { it.requiredString("shardId") }
        val orderedGroups = java.util.TreeMap<String, List<JsonObject>>(CODE_POINT_STRING_COMPARATOR).apply {
            putAll(grouped)
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
            throw FullTreeDataTruthException("inventory shard ownership does not reconcile")
        }
        val counts = inventory.requiredObject("counts")
        val generated = units.count { it.requiredString("sourceKind") == "generated" }.toLong()
        if (
            counts.requiredLong("compilationUnits") != units.size.toLong() ||
            counts.requiredLong("generatedUnits") != generated ||
            counts.requiredLong("handwrittenUnits") != units.size.toLong() - generated ||
            counts.requiredLong("shards") != expectedShards.size.toLong()
        ) {
            throw FullTreeDataTruthException("inventory counts do not reconcile")
        }
        val perShardUnits = scope.requiredObject("bounds").requiredObject("perShard")
            .requiredLong("compilationUnits")
        if (grouped.values.any { it.size.toLong() > perShardUnits }) {
            throw FullTreeDataTruthException("inventory shard exceeds its compilation-unit bound")
        }
        if (units.size.toLong() > scope.requiredObject("bounds").requiredObject("wholeRun")
                .requiredLong("compilationUnits")
        ) {
            throw FullTreeDataTruthException("inventory exceeds its whole-run compilation-unit bound")
        }
    }

    private fun authenticateTruthRecords(
        root: Path,
        index: JsonObject,
        inventory: JsonObject,
        scope: JsonObject,
        limits: FullTreeDataReconciliationLimits,
        budget: CooperativeBudget,
    ): List<TruthPartition> {
        val records = index.requiredArray("shards").objects("data truth index shard")
        if (records.isEmpty()) throw FullTreeDataTruthException("data truth index has no partitions")
        if (records.size.toLong() > limits.maximumEntities) {
            throw FullTreeDataTruthException("data truth index exceeds its partition-count limit")
        }
        val inventoryShards = inventory.requiredArray("shards").objects("inventory shard")
        val grouped = records.groupBy { it.requiredString("id") }
        if (grouped.keys != inventoryShards.map { it.requiredString("id") }.toSet()) {
            throw FullTreeDataTruthException("data truth partition ownership is missing or extra")
        }
        val expectedIdOrder = inventoryShards.flatMap { shard ->
            List(grouped.getValue(shard.requiredString("id")).size) { shard.requiredString("id") }
        }
        if (records.map { it.requiredString("id") } != expectedIdOrder) {
            throw FullTreeDataTruthException("data truth partitions are not in inventory order")
        }
        val maximumPartitionBytes = minOf(
            limits.maximumTruthPartitionBytes,
            scope.requiredObject("bounds").requiredObject("perShard").requiredLong("serializedBytes"),
        )
        val seenPaths = hashSetOf<Path>()
        return records.mapIndexed { recordIndex, record ->
            budget.periodicCheckpoint("while authenticating data truth index records")
            val id = record.requiredString("id")
            val owned = grouped.getValue(id)
            val ordinal = owned.indexOfFirst { it === record }
            if (ordinal < 0) throw FullTreeDataTruthException("data truth partition identity is contradictory")
            val expectedRelative = if (owned.size == 1) {
                "shards/$id.json"
            } else {
                "shards/$id.part-${ordinal.toString().padStart(3, '0')}.json"
            }
            if (record.requiredString("path") != expectedRelative) {
                throw FullTreeDataTruthException("data truth partition path is not canonical")
            }
            val relative = Path.of(expectedRelative)
            val path = root.resolve(relative).normalize()
            if (!path.startsWith(root.resolve("shards").normalize()) || !seenPaths.add(path)) {
                throw FullTreeDataTruthException("data truth partition path is duplicated or escapes its root")
            }
            val bytes = record.requiredLong("bytes")
            if (bytes !in 1L..maximumPartitionBytes) {
                throw FullTreeDataTruthException("data truth partition byte binding exceeds its authenticated bound")
            }
            requireDigest(record.requiredString("sha256"), "data truth partition")
            TruthPartition(
                index = recordIndex,
                shardId = id,
                ordinal = ordinal,
                total = owned.size,
                path = path,
                bytes = bytes,
                sha256 = record.requiredString("sha256"),
                counts = truthCounts(record),
            ).also { partition ->
                if (partition.counts.entities > scope.requiredObject("bounds").requiredObject("perShard")
                        .requiredLong("entities")
                ) {
                    throw FullTreeDataTruthException("data truth partition exceeds authenticated entity bound")
                }
            }
        }.also { partitions ->
            val aggregate = TruthCounts()
            partitions.forEach { aggregate.add(it.counts) }
            if (aggregate.toJson() != index.requiredObject("counts")) {
                throw FullTreeDataTruthException("data truth partition counts do not reconcile with the index")
            }
            val whole = scope.requiredObject("bounds").requiredObject("wholeRun")
            val partitionBytes = partitions.fold(0L) { total, partition ->
                addExact(total, partition.bytes, "data truth partition byte")
            }
            if (aggregate.entities > whole.requiredLong("entities") ||
                partitionBytes > whole.requiredLong("serializedBytes")
            ) {
                throw FullTreeDataTruthException("data truth index exceeds authenticated whole-run bounds")
            }
        }
    }

    private fun verifyTruthTreeMembership(
        root: Path,
        partitions: List<TruthPartition>,
        budget: CooperativeBudget,
    ) {
        val shardRoot = root.resolve("shards")
        val expected = hashSetOf(root, root.resolve("index.json"), shardRoot)
        expected.addAll(partitions.map { it.path })
        val actual = hashSetOf<Path>()
        Files.walk(root).use { paths ->
            paths.forEach { path ->
                budget.periodicCheckpoint("while authenticating data truth tree membership")
                val normalized = path.toAbsolutePath().normalize()
                if (!actual.add(normalized) || normalized !in expected) {
                    throw FullTreeDataTruthException("data truth tree contains an unindexed path")
                }
                val attributes = Files.readAttributes(
                    normalized,
                    BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                )
                val directory = normalized == root || normalized == shardRoot
                if (attributes.isSymbolicLink || (directory && !attributes.isDirectory) ||
                    (!directory && !attributes.isRegularFile)
                ) {
                    throw FullTreeDataTruthException("data truth tree contains an invalid path type")
                }
            }
        }
        if (actual != expected) throw FullTreeDataTruthException("data truth tree membership is incomplete")
    }

    private fun ingestTruth(
        connection: Connection,
        inputs: AuthenticatedInputs,
        scope: JsonObject,
        inventory: JsonObject,
        budget: CooperativeBudget,
        limits: FullTreeDataReconciliationLimits,
    ): TruthCounts {
        val unitToShard = inventory.requiredArray("units").objects("inventory unit")
            .associate { it.requiredString("id") to it.requiredString("shardId") }
        val shardUnits = inventory.requiredArray("shards").objects("inventory shard")
            .associate { shard ->
                shard.requiredString("id") to shard.requiredArray("unitIds").map {
                    it.requiredString("inventory shard unit")
                }
            }
        val total = TruthCounts()
        val insertGlobal = connection.prepareStatement(
            "INSERT INTO truth_globals(id, owner_shard, population, address_rva, tls) VALUES (?, ?, ?, ?, ?)",
        )
        val insertName = connection.prepareStatement(
            "INSERT INTO truth_names(name, truth_id) VALUES (?, ?)",
        )
        val insertType = connection.prepareStatement("INSERT INTO truth_types(id, owner_shard) VALUES (?, ?)")
        val insertReference = connection.prepareStatement(
            "INSERT INTO truth_reference_targets(reference_key, target_id, target_owner) VALUES (?, ?, ?)",
        )
        try {
            inputs.partitions.forEach { partition ->
                budget.checkpoint("before data truth partition ${partition.index}")
                val computed = TruthCounts()
                var previousGlobal: String? = null
                var previousType: String? = null
                val expectedShard = truthShardBinding(partition, shardUnits.getValue(partition.shardId))
                val streamed = FullTreeCanonicalStreaming.readObject(
                    path = partition.path,
                    label = "data truth partition ${partition.shardId}/${partition.ordinal}",
                    expectedSourceSha256 = partition.sha256,
                    fieldOrder = TRUTH_FIELDS,
                    arrayFields = setOf("globals", "types"),
                    omittedDigestField = null,
                    limits = streamingLimits(
                        minOf(limits.maximumTruthPartitionBytes, partition.bytes),
                        limits,
                        scope,
                        scope.requiredObject("bounds").requiredObject("perShard").requiredLong("entities"),
                    ),
                ) { field, index, entity, _ ->
                    if ((index and 1023L) == 0L) budget.checkpoint("while streaming data truth")
                    when (field) {
                        "globals" -> {
                            validateTruthEntity("global", entity, inputs.index.requiredObject("oracle"), expectedShard)
                            previousGlobal = requireIncreasing(
                                entity.requiredString("id"),
                                previousGlobal,
                                "data truth globals",
                            )
                            val ownerUnit = entity.requiredString("ownerUnitId")
                            val ownerShard = unitToShard[ownerUnit]
                                ?: throw FullTreeDataTruthException("truth global owner is outside inventory")
                            if (ownerShard != partition.shardId) {
                                throw FullTreeDataTruthException("truth global owner differs from partition")
                            }
                            validateTruthGlobalSemantics(entity)
                            val entityCounts = TruthCounts.forEntity("global", entity, ownerShard)
                            computed.add(entityCounts)
                            storeTruthReferences(
                                insertReference,
                                "global",
                                entity,
                                ownerShard,
                                limits,
                            )
                            insertGlobal.setString(1, entity.requiredString("id"))
                            insertGlobal.setString(2, ownerShard)
                            insertGlobal.setString(3, entity.requiredString("population"))
                            insertGlobal.setString(4, entity.requiredElement("addressRva").nullableString("addressRva"))
                            insertGlobal.setInt(5, if (entity.requiredElement("tls").strictBoolean("tls")) 1 else 0)
                            insertExactlyOnce(insertGlobal, "truth global identity")
                            val names = entity.requiredArray("names").map {
                                it.requiredString("truth global name")
                            }
                            requireSortedUnique(names, "truth global names")
                            names.forEach { name ->
                                insertName.setString(1, name)
                                insertName.setString(2, entity.requiredString("id"))
                                insertExactlyOnce(insertName, "truth global name")
                            }
                        }
                        "types" -> {
                            validateTruthEntity("type", entity, inputs.index.requiredObject("oracle"), expectedShard)
                            validateTruthTypeSemantics(entity)
                            previousType = requireIncreasing(
                                entity.requiredString("id"),
                                previousType,
                                "data truth types",
                            )
                            val ownerUnit = entity.requiredString("ownerUnitId")
                            val ownerShard = unitToShard[ownerUnit]
                                ?: throw FullTreeDataTruthException("truth type owner is outside inventory")
                            if (ownerShard != partition.shardId) {
                                throw FullTreeDataTruthException("truth type owner differs from partition")
                            }
                            computed.add(TruthCounts.forEntity("type", entity, ownerShard))
                            storeTruthReferences(insertReference, "type", entity, ownerShard, limits)
                            insertType.setString(1, entity.requiredString("id"))
                            insertType.setString(2, ownerShard)
                            insertExactlyOnce(insertType, "truth type identity")
                        }
                        else -> throw FullTreeDataTruthException("unexpected streamed truth field")
                    }
                    if (computed.entities > limits.maximumEntities ||
                        computed.entities > scope.requiredObject("bounds").requiredObject("perShard")
                            .requiredLong("entities")
                    ) {
                        throw FullTreeDataTruthException("data truth partition exceeds its entity limit")
                    }
                }
                if (streamed.sourceBytes != partition.bytes) {
                    throw FullTreeDataTruthException("data truth partition byte count differs from index")
                }
                val envelope = streamed.envelope
                validateTruthEnvelope(envelope)
                if (envelope.requiredObject("oracle") != inputs.index.requiredObject("oracle") ||
                    envelope.requiredObject("shard") != expectedShard
                ) {
                    throw FullTreeDataTruthException("data truth partition bindings differ")
                }
                if (envelope.requiredObject("counts") != computed.toJson() || computed != partition.counts) {
                    throw FullTreeDataTruthException("data truth partition counts are stale or contradictory")
                }
                total.add(computed)
            }
        } finally {
            insertGlobal.close()
            insertName.close()
            insertType.close()
            insertReference.close()
        }
        if (total.toJson() != inputs.index.requiredObject("counts")) {
            throw FullTreeDataTruthException("streamed data truth counts differ from index")
        }
        requireClosedTruthReferences(connection)
        verifyTruthTreeMembership(inputs.root, inputs.partitions, budget)
        return total
    }

    private fun storeTruthReferences(
        insert: java.sql.PreparedStatement,
        kind: String,
        entity: JsonObject,
        ownerShard: String,
        limits: FullTreeDataReconciliationLimits,
    ) {
        truthReferences(kind, entity).forEachIndexed { referenceIndex, reference ->
            val targets = validateTruthReferenceCommitments(reference, ownerShard, limits)
            targets.forEachIndexed { targetIndex, (targetId, targetOwner) ->
                insert.setString(1, "${entity.requiredString("id")}:$referenceIndex:$targetIndex")
                insert.setString(2, targetId)
                insert.setString(3, targetOwner)
                insertExactlyOnce(insert, "truth reference target")
            }
        }
    }

    private fun validateTruthReferenceCommitments(
        reference: JsonObject,
        ownerShard: String,
        limits: FullTreeDataReconciliationLimits,
    ): List<Pair<String, String>> {
        val candidateFields = listOf("candidateTargetCount", "candidateTargets", "candidateTargetsSha256")
        val evidenceFields = listOf("evidenceDieOffsetCount", "evidenceDieOffsetsSha256")
        if (candidateFields.map(reference::containsKey).distinct().size != 1) {
            throw FullTreeDataTruthException("truth reference candidate commitment is incomplete")
        }
        if (evidenceFields.map(reference::containsKey).distinct().size != 1) {
            throw FullTreeDataTruthException("truth reference evidence commitment is incomplete")
        }
        val candidates = (reference["candidateTargets"] as? JsonArray ?: JsonArray(emptyList()))
            .objects("truth reference candidate")
        val candidateCount = reference["candidateTargetCount"]?.let {
            JsonObject(mapOf("value" to it)).requiredLong("value")
        } ?: candidates.size.toLong()
        val evidence = reference.requiredArray("evidenceDieOffsets")
        val evidenceCount = reference["evidenceDieOffsetCount"]?.let {
            JsonObject(mapOf("value" to it)).requiredLong("value")
        } ?: evidence.size.toLong()
        if (candidateCount < candidates.size.toLong() || evidenceCount < evidence.size.toLong()) {
            throw FullTreeDataTruthException("truth reference sample exceeds its committed count")
        }
        reference["candidateTargetsSha256"]?.requiredString("candidate commitment")?.let { expected ->
            if (candidateCount == candidates.size.toLong() &&
                expected != OracleArtifacts.sha256(canonicalRecord(JsonArray(candidates), limits))
            ) {
                throw FullTreeDataTruthException("truth reference candidate commitment differs")
            }
        }
        reference["evidenceDieOffsetsSha256"]?.requiredString("evidence commitment")?.let { expected ->
            if (evidenceCount == evidence.size.toLong() &&
                expected != OracleArtifacts.sha256(canonicalRecord(evidence, limits))
            ) {
                throw FullTreeDataTruthException("truth reference evidence commitment differs")
            }
        }
        val pairs = candidates.map {
            it.requiredString("targetTypeId") to it.requiredString("targetOwnerShardId")
        }
        if (pairs.distinct().size != pairs.size) {
            throw FullTreeDataTruthException("truth reference candidate targets are duplicated")
        }
        val target = reference.requiredElement("targetTypeId").nullableString("targetTypeId")
        val targetOwner = reference.requiredElement("targetOwnerShardId").nullableString("targetOwnerShardId")
        val reason = reference.requiredElement("reasonCode")
        if (target == null) {
            if (targetOwner != null || reason is JsonNull) {
                throw FullTreeDataTruthException("unresolved truth reference has contradictory evidence")
            }
            if (reference.requiredString("resolutionCode") == "unresolved-authenticated-target-set" &&
                (candidateCount < 2L || !candidateFields.all(reference::containsKey))
            ) {
                throw FullTreeDataTruthException("ambiguous truth reference has incomplete candidates")
            }
        } else {
            if (targetOwner == null || reason !is JsonNull) {
                throw FullTreeDataTruthException("resolved truth reference has contradictory evidence")
            }
            if (pairs.isNotEmpty() && (target to targetOwner) !in pairs) {
                throw FullTreeDataTruthException("resolved truth reference is absent from candidate evidence")
            }
        }
        if (targetOwner != null && targetOwner != ownerShard) {
            // The count logic records this cross-shard edge; the SQL lookup below authenticates it.
        }
        return buildList {
            target?.let { add(it to targetOwner!!) }
            addAll(pairs)
        }.distinct()
    }

    private fun requireClosedTruthReferences(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.executeQuery(
                "SELECT r.reference_key FROM truth_reference_targets r " +
                    "LEFT JOIN truth_types t ON t.id=r.target_id " +
                    "WHERE t.id IS NULL OR t.owner_shard != r.target_owner LIMIT 1",
            ).use { rows ->
                if (rows.next()) {
                    throw FullTreeDataTruthException("truth reference has a dangling or substituted target owner")
                }
            }
        }
    }

    private fun truthReferences(kind: String, entity: JsonObject): List<JsonObject> = when (kind) {
        "global" -> listOf(entity.requiredObject("typeReference"))
        "type" -> entity.requiredArray("members").objects("truth member")
            .map { it.requiredObject("typeReference") }
        else -> throw FullTreeDataTruthException("truth entity kind is invalid")
    }

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

    private fun validateTruthGlobalSemantics(entity: JsonObject) {
        val population = entity.requiredString("population")
        val address = entity.requiredElement("addressRva").nullableString("addressRva")
        if ((population == "scored") != (address != null)) {
            throw FullTreeDataTruthException("truth global population and address observability differ")
        }
        val reason = entity.requiredElement("reasonCode")
        if ((population == "scored") != (reason is JsonNull)) {
            throw FullTreeDataTruthException("truth global population and reason evidence differ")
        }
        address?.let { requireHexAddress(it, "truth global address") }
    }

    private fun validateTruthTypeSemantics(entity: JsonObject) {
        val scored = entity.requiredString("population") == "scored"
        val sized = entity.requiredElement("byteSize") !is JsonNull
        val reasonAbsent = entity.requiredElement("reasonCode") is JsonNull
        if (scored != sized || scored != reasonAbsent) {
            throw FullTreeDataTruthException("truth type population, size, and reason evidence differ")
        }
    }

    private fun validateTruthEnvelope(envelope: JsonObject) {
        try {
            OracleSchemas.validate("full-tree-data-truth", envelope)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data truth partition envelope fails schema validation", failure)
        }
    }

    private fun validateTruthEntity(kind: String, entity: JsonObject, oracle: JsonObject, shard: JsonObject) {
        val zero = TruthCounts().toJson()
        val document = JsonObject(
            mapOf(
                "counts" to zero,
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
            throw FullTreeDataTruthException("data truth $kind fails schema validation", failure)
        }
    }

    private fun ingestElfAndReconcile(
        connection: Connection,
        elfPath: Path,
        expectedSha256: String,
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        reportOracle: JsonObject,
        truthCounts: TruthCounts,
        budget: CooperativeBudget,
        limits: FullTreeDataReconciliationLimits,
    ): ElfCounts {
        val expectedOracle = JsonObject(
            mapOf(
                "configurationSha256" to JsonPrimitive(elfDataConfigurationSha256),
                "inventoryIndexSha256" to inventory.requiredElement("indexSha256"),
                "scopeSha256" to JsonPrimitive(scopeSha256),
            ),
        )
        val expectedArtifacts = JsonObject(
            mapOf(
                "rich" to JsonObject(
                    mapOf(
                        "inputSha256" to scope.requiredObject("oracle").requiredElement("richArtifactSha256"),
                        "scannedSymbols" to JsonPrimitive(0),
                        "sizeBytes" to JsonPrimitive(0),
                    ),
                ),
                "stripped" to JsonObject(
                    mapOf(
                        "inputSha256" to scope.requiredObject("oracle").requiredElement("strippedArtifactSha256"),
                        "scannedSymbols" to JsonPrimitive(0),
                        "sizeBytes" to JsonPrimitive(0),
                    ),
                ),
            ),
        )
        val counts = ElfCounts()
        var previousAddressKind: String? = null
        var previousAddress: BigInteger? = null
        var previousExternalName: String? = null
        val insertGlobal = connection.prepareStatement(
            "INSERT INTO report_globals(elf_id, reconciliation, payload) VALUES (?, ?, ?)",
        )
        val insertAbi = connection.prepareStatement(
            "INSERT INTO report_abi(elf_id, alias_name, slots, resolved_slots, payload) VALUES (?, ?, ?, ?, ?)",
        )
        val insertMatched = connection.prepareStatement("INSERT OR IGNORE INTO matched_truth(truth_id) VALUES (?)")
        try {
            val streamed = FullTreeCanonicalStreaming.readObject(
                path = elfPath,
                label = "ELF data index",
                expectedSourceSha256 = expectedSha256,
                fieldOrder = ELF_FIELDS,
                arrayFields = setOf("externalGlobals", "globals"),
                omittedDigestField = "indexSha256",
                limits = streamingLimits(
                    minOf(
                        limits.maximumElfIndexBytes,
                        scope.requiredObject("bounds").requiredObject("wholeRun").requiredLong("serializedBytes"),
                    ),
                    limits,
                    scope,
                    scope.requiredObject("bounds").requiredObject("wholeRun").requiredLong("entities"),
                ),
            ) { field, index, entity, _ ->
                if ((index and 1023L) == 0L) budget.checkpoint("while streaming ELF data")
                when (field) {
                    "externalGlobals" -> {
                        validateElfEntity("external", entity, expectedArtifacts, expectedOracle)
                        val name = entity.requiredString("name")
                        previousExternalName = requireIncreasing(name, previousExternalName, "ELF external globals")
                        val evidence = entity.requiredArray("evidence").map {
                            it.requiredString("ELF external evidence")
                        }
                        requireSortedUnique(evidence, "ELF external evidence")
                        counts.externalGlobals = increment(counts.externalGlobals, "ELF external global")
                    }
                    "globals" -> {
                        validateElfEntity("global", entity, expectedArtifacts, expectedOracle)
                        val addressKind = entity.requiredString("addressKind")
                        val addressText = entity.requiredString("address")
                        val address = requireHexAddress(addressText, "ELF global address")
                        if (previousAddressKind != null) {
                            val comparison = addressKind.compareTo(previousAddressKind!!)
                            if (comparison < 0 || (comparison == 0 && address <= previousAddress!!)) {
                                throw FullTreeDataTruthException(
                                    "ELF global addresses are duplicated or not canonically ordered",
                                )
                            }
                        }
                        previousAddressKind = addressKind
                        previousAddress = address
                        val expectedId = "global-${if (addressKind == "image-rva") "rva" else "tls"}-$addressText"
                        if (entity.requiredString("id") != expectedId) {
                            throw FullTreeDataTruthException("ELF global ID differs from its address identity")
                        }
                        val aliases = entity.requiredArray("aliases").objects("ELF alias")
                        val aliasNames = aliases.map { it.requiredString("name") }
                        requireSortedUnique(aliasNames, "ELF aliases")
                        counts.globalRvas = increment(counts.globalRvas, "ELF global")
                        counts.aliases = addExact(counts.aliases, aliases.size.toLong(), "ELF alias")
                        if (counts.globalRvas > limits.maximumEntities || counts.aliases > limits.maximumEntities) {
                            throw FullTreeDataTruthException("ELF data exceeds its entity limit")
                        }
                        val matches = resolveTruthMatches(connection, entity, limits.maximumMatchesPerElfGlobal)
                        matches.keys.forEach { truthId ->
                            insertMatched.setString(1, truthId)
                            if (insertMatched.executeUpdate() !in 0..1) {
                                throw FullTreeDataTruthException("matched truth identity was not stored deterministically")
                            }
                        }
                        val ownerSet = java.util.TreeSet<String>(CODE_POINT_STRING_COMPARATOR).apply {
                            addAll(matches.values)
                        }
                        if (ownerSet.isEmpty()) ownerSet.add("elf-only")
                        val owners = ownerSet.toList()
                        val reconciliation = when {
                            matches.isEmpty() -> "elf-only"
                            addressKind == "image-rva" -> "matched-by-rva"
                            else -> "matched-tls-by-linkage-name"
                        }
                        val globalRecord = JsonObject(
                            mapOf(
                                "address" to JsonPrimitive(addressText),
                                "addressKind" to JsonPrimitive(addressKind),
                                "aliasNames" to JsonArray(aliasNames.map(::JsonPrimitive)),
                                "dwarfTruthIds" to JsonArray(matches.keys.map(::JsonPrimitive)),
                                "elfGlobalId" to entity.requiredElement("id"),
                                "ownerShardIds" to JsonArray(owners.map(::JsonPrimitive)),
                                "reconciliation" to JsonPrimitive(reconciliation),
                            ),
                        )
                        validateReconciliationEntity("global", globalRecord, reportOracle)
                        insertGlobal.setString(1, entity.requiredString("id"))
                        insertGlobal.setString(2, reconciliation)
                        insertGlobal.setBytes(3, canonicalRecord(globalRecord, limits))
                        insertExactlyOnce(insertGlobal, "ELF reconciliation global")

                        aliases.forEach { alias ->
                            validateElfAliasSemantics(alias)
                            val expectedAliasKind = if (addressKind == "tls-offset") "tls" else "object"
                            if (alias.requiredString("kind") != expectedAliasKind) {
                                throw FullTreeDataTruthException("ELF alias kind differs from its address kind")
                            }
                            val abi = alias.requiredElement("abi")
                            if (abi !is JsonNull) {
                                val abiObject = abi as? JsonObject
                                    ?: throw FullTreeDataTruthException("ELF ABI evidence must be an object or null")
                                val slots = abiObject.requiredArray("slots").objects("ELF ABI slot")
                                validateAbiSlots(slots)
                                if (alias.requiredLong("size") > limits.maximumAbiObjectBytes ||
                                    slots.size.toLong() > limits.maximumAbiSlots
                                ) {
                                    throw FullTreeDataTruthException("ELF ABI object exceeds its byte or slot bound")
                                }
                                val resolved = slots.count {
                                    it.requiredElement("targetRva") !is JsonNull
                                }.toLong()
                                counts.abiObjects = increment(counts.abiObjects, "ELF ABI object")
                                counts.abiSlots = addExact(counts.abiSlots, slots.size.toLong(), "ELF ABI slot")
                                counts.abiResolvedSlots = addExact(
                                    counts.abiResolvedSlots,
                                    resolved,
                                    "ELF resolved ABI slot",
                                )
                                if (counts.abiSlots > limits.maximumAbiSlots ||
                                    counts.abiSlots > limits.maximumEntities
                                ) {
                                    throw FullTreeDataTruthException("ELF ABI evidence exceeds its slot limit")
                                }
                                val abiRecord = JsonObject(
                                    mapOf(
                                        "aliasName" to alias.requiredElement("name"),
                                        "elfGlobalId" to entity.requiredElement("id"),
                                        "kind" to abiObject.requiredElement("kind"),
                                        "ownerMangledName" to abiObject.requiredElement("ownerMangledName"),
                                        "ownerShardIds" to JsonArray(owners.map(::JsonPrimitive)),
                                        "resolvedSlots" to JsonPrimitive(resolved),
                                        "slots" to JsonPrimitive(slots.size),
                                    ),
                                )
                                validateReconciliationEntity("abi", abiRecord, reportOracle)
                                insertAbi.setString(1, entity.requiredString("id"))
                                insertAbi.setString(2, alias.requiredString("name"))
                                insertAbi.setLong(3, slots.size.toLong())
                                insertAbi.setLong(4, resolved)
                                insertAbi.setBytes(5, canonicalRecord(abiRecord, limits))
                                insertExactlyOnce(insertAbi, "ELF reconciliation ABI object")
                            }
                        }
                    }
                    else -> throw FullTreeDataTruthException("unexpected streamed ELF field")
                }
            }
            val envelope = streamed.envelope
            validateElfEnvelope(envelope)
            if (envelope.requiredObject("oracle") != expectedOracle) {
                throw FullTreeDataTruthException("ELF data index bindings differ from authenticated controls")
            }
            validateElfArtifacts(envelope.requiredObject("artifacts"), scope, limits)
            if (envelope.requiredObject("counts") != counts.toJson()) {
                throw FullTreeDataTruthException("ELF data index counts are stale or contradictory")
            }
            if (envelope.requiredString("indexSha256") != streamed.canonicalWithoutOmittedFieldSha256) {
                throw FullTreeDataTruthException("ELF data index self-hash does not reconcile")
            }
        } finally {
            insertGlobal.close()
            insertAbi.close()
            insertMatched.close()
        }
        if (truthCounts.entities > limits.maximumEntities || counts.globalRvas > limits.maximumEntities) {
            throw FullTreeDataTruthException("reconciliation input population exceeds its entity limit")
        }
        return counts
    }

    private fun resolveTruthMatches(
        connection: Connection,
        elfGlobal: JsonObject,
        maximumMatches: Int,
    ): java.util.SortedMap<String, String> {
        val matches = java.util.TreeMap<String, String>(CODE_POINT_STRING_COMPARATOR)
        if (elfGlobal.requiredString("addressKind") == "image-rva") {
            connection.prepareStatement(
                "SELECT id, owner_shard FROM truth_globals WHERE address_rva=? AND tls=0",
            ).use { query ->
                query.setString(1, elfGlobal.requiredString("address"))
                query.executeQuery().use { rows ->
                    while (rows.next()) {
                        matches[rows.getString(1)] = rows.getString(2)
                        if (matches.size > maximumMatches) {
                            throw FullTreeDataTruthException("ELF global exceeds its truth-match limit")
                        }
                    }
                }
            }
        } else {
            connection.prepareStatement(
                "SELECT g.id, g.owner_shard FROM truth_names n " +
                    "JOIN truth_globals g ON g.id=n.truth_id WHERE n.name=? AND g.tls=1",
            ).use { query ->
                elfGlobal.requiredArray("aliases").objects("ELF alias").forEach { alias ->
                    query.setString(1, alias.requiredString("name"))
                    query.executeQuery().use { rows ->
                        while (rows.next()) {
                            val id = rows.getString(1)
                            val owner = rows.getString(2)
                            val previous = matches.put(id, owner)
                            if (previous != null && previous != owner) {
                                throw FullTreeDataTruthException("truth global has contradictory shard ownership")
                            }
                            if (matches.size > maximumMatches) {
                                throw FullTreeDataTruthException("ELF global exceeds its truth-match limit")
                            }
                        }
                    }
                }
            }
        }
        return matches
    }

    private fun validateElfArtifacts(
        artifacts: JsonObject,
        scope: JsonObject,
        limits: FullTreeDataReconciliationLimits,
    ) {
        if (artifacts.keys != setOf("rich", "stripped")) {
            throw FullTreeDataTruthException("ELF data artifact population is missing or extra")
        }
        mapOf(
            "rich" to scope.requiredObject("oracle").requiredString("richArtifactSha256"),
            "stripped" to scope.requiredObject("oracle").requiredString("strippedArtifactSha256"),
        ).forEach { (label, expectedSha256) ->
            val record = artifacts.requiredObject(label)
            if (record.keys != setOf("inputSha256", "scannedSymbols", "sizeBytes") ||
                record.requiredString("inputSha256") != expectedSha256 ||
                record.requiredLong("scannedSymbols") !in 0L..limits.maximumElfScannedSymbolsPerArtifact ||
                record.requiredLong("sizeBytes") < 1L
            ) {
                throw FullTreeDataTruthException("ELF data $label artifact binding is invalid")
            }
        }
    }

    private fun validateElfAliasSemantics(alias: JsonObject) {
        val evidence = alias.requiredArray("evidence").map { it.requiredString("ELF alias evidence") }
        requireSortedUnique(evidence, "ELF alias evidence")
        val availability = alias.requiredObject("availability")
        if (availability.keys != setOf("rich", "stripped") ||
            availability.requiredString("rich") != "surviving" ||
            availability.requiredString("stripped") !in setOf("surviving", "removed")
        ) {
            throw FullTreeDataTruthException("ELF alias availability is invalid")
        }
        if (alias.requiredLong("size") < 0L || alias.requiredLong("alignment") < 0L) {
            throw FullTreeDataTruthException("ELF alias size or alignment is negative")
        }
    }

    private fun validateAbiSlots(slots: List<JsonObject>) {
        slots.forEachIndexed { index, slot ->
            if (slot.requiredLong("index") != index.toLong()) {
                throw FullTreeDataTruthException("ELF ABI slots are not consecutively ordered")
            }
            requireHexAddress(slot.requiredString("rva"), "ELF ABI slot RVA")
            val targetRva = slot.requiredElement("targetRva").nullableString("targetRva")
            val targetKind = slot.requiredElement("targetKind").nullableString("targetKind")
            if ((targetRva == null) != (targetKind == null)) {
                throw FullTreeDataTruthException("ELF ABI slot target kind and RVA differ in presence")
            }
            targetRva?.let { requireHexAddress(it, "ELF ABI target RVA") }
        }
    }

    private fun validateElfEnvelope(envelope: JsonObject) {
        try {
            OracleSchemas.validate("full-tree-elf-data", envelope)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("ELF data index envelope fails schema validation", failure)
        }
    }

    private fun validateElfEntity(
        kind: String,
        entity: JsonObject,
        artifacts: JsonObject,
        oracle: JsonObject,
    ) {
        val document = JsonObject(
            mapOf(
                "artifacts" to artifacts,
                "counts" to ElfCounts().toJson(),
                "externalGlobals" to if (kind == "external") JsonArray(listOf(entity)) else JsonArray(emptyList()),
                "globals" to if (kind == "global") JsonArray(listOf(entity)) else JsonArray(emptyList()),
                "indexSha256" to JsonPrimitive("0".repeat(64)),
                "oracle" to oracle,
                "schemaVersion" to JsonPrimitive(1),
            ),
        )
        try {
            OracleSchemas.validate("full-tree-elf-data", document)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("ELF data $kind fails schema validation", failure)
        }
    }

    private fun reconciliationCounts(
        connection: Connection,
        truth: TruthCounts,
        elf: ElfCounts,
        budget: CooperativeBudget,
    ): JsonObject {
        fun scalar(sql: String): Long = connection.createStatement().use { statement ->
            statement.executeQuery(sql).use { rows ->
                if (!rows.next()) throw FullTreeDataTruthException("reconciliation count query returned no row")
                rows.getLong(1).also {
                    if (rows.next()) throw FullTreeDataTruthException("reconciliation count query returned extra rows")
                }
            }
        }
        budget.checkpoint("before reconciliation count queries")
        val globals = scalar("SELECT COUNT(*) FROM report_globals")
        val matched = scalar("SELECT COUNT(*) FROM report_globals WHERE reconciliation != 'elf-only'")
        val elfOnly = scalar("SELECT COUNT(*) FROM report_globals WHERE reconciliation = 'elf-only'")
        val dwarfOnly = scalar(
            "SELECT COUNT(*) FROM truth_globals g LEFT JOIN matched_truth m ON m.truth_id=g.id " +
                "WHERE g.population='scored' AND m.truth_id IS NULL",
        )
        val abiObjects = scalar("SELECT COUNT(*) FROM report_abi")
        val abiSlots = scalar("SELECT COALESCE(SUM(slots), 0) FROM report_abi")
        val resolvedSlots = scalar("SELECT COALESCE(SUM(resolved_slots), 0) FROM report_abi")
        if (
            globals != elf.globalRvas || matched + elfOnly != globals || abiObjects != elf.abiObjects ||
            abiSlots != elf.abiSlots || resolvedSlots != elf.abiResolvedSlots
        ) {
            throw FullTreeDataTruthException("SQLite reconciliation counts differ from streamed ELF counts")
        }
        return JsonObject(
            mapOf(
                "abiObjects" to JsonPrimitive(abiObjects),
                "abiResolvedSlots" to JsonPrimitive(resolvedSlots),
                "abiSlots" to JsonPrimitive(abiSlots),
                "dwarfGlobals" to JsonPrimitive(truth.globals),
                "dwarfOnlyScoredGlobals" to JsonPrimitive(dwarfOnly),
                "dwarfScoredGlobals" to JsonPrimitive(truth.globals - truth.unobservableGlobals),
                "dwarfTypes" to JsonPrimitive(truth.types),
                "dwarfUnobservableGlobals" to JsonPrimitive(truth.unobservableGlobals),
                "elfGlobals" to JsonPrimitive(globals),
                "elfOnlyGlobals" to JsonPrimitive(elfOnly),
                "matchedElfGlobals" to JsonPrimitive(matched),
                "unexplainedEntities" to JsonPrimitive(0),
            ),
        ).also { budget.checkpoint("after reconciliation count queries") }
    }

    private fun validateReportEnvelope(oracle: JsonObject, counts: JsonObject) {
        val document = JsonObject(
            mapOf(
                "abiObjects" to JsonArray(emptyList()),
                "counts" to counts,
                "dwarfOnlyScoredGlobals" to JsonArray(emptyList()),
                "globals" to JsonArray(emptyList()),
                "oracle" to oracle,
                "reportSha256" to JsonPrimitive("0".repeat(64)),
                "schemaVersion" to JsonPrimitive(1),
            ),
        )
        try {
            OracleSchemas.validate("full-tree-data-reconciliation", document)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data reconciliation envelope fails schema validation", failure)
        }
    }

    private fun validateReconciliationEntity(kind: String, entity: JsonObject, oracle: JsonObject) {
        val globals = if (kind == "global") JsonArray(listOf(entity)) else JsonArray(emptyList())
        val abi = if (kind == "abi") JsonArray(listOf(entity)) else JsonArray(emptyList())
        val dwarf = if (kind == "dwarf") JsonArray(listOf(entity)) else JsonArray(emptyList())
        val document = JsonObject(
            mapOf(
                "abiObjects" to abi,
                "counts" to EMPTY_REPORT_COUNTS,
                "dwarfOnlyScoredGlobals" to dwarf,
                "globals" to globals,
                "oracle" to oracle,
                "reportSha256" to JsonPrimitive("0".repeat(64)),
                "schemaVersion" to JsonPrimitive(1),
            ),
        )
        try {
            OracleSchemas.validate("full-tree-data-reconciliation", document)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data reconciliation $kind record fails schema validation", failure)
        }
    }

    private fun writeReport(
        connection: Connection,
        target: Path,
        oracle: JsonObject,
        counts: JsonObject,
        maximumReportBytes: Long,
        limits: FullTreeDataReconciliationLimits,
        budget: CooperativeBudget,
    ): WrittenReport {
        val digest = MessageDigest.getInstance("SHA-256")
        val digestBound = BoundedOutputStream(OutputStream.nullOutputStream(), maximumReportBytes, budget)
        DigestOutputStream(digestBound, digest).use { output ->
            writeReportDocument(connection, output, oracle, counts, reportSha256 = null, limits, budget)
        }
        val reportSha256 = digest.digest().hex()
        budget.checkpoint("after reconciliation report hash pass")
        val temporary = Files.createTempFile(target.parent, ".report-", ".tmp")
        var committed = false
        try {
            Files.setPosixFilePermissions(temporary, PRIVATE_FILE_PERMISSIONS)
            val outputBound = Files.newOutputStream(
                temporary,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING,
                LinkOption.NOFOLLOW_LINKS,
            ).use { file ->
                val bounded = BoundedOutputStream(BufferedOutputStream(file), maximumReportBytes, budget)
                bounded.use { output ->
                    writeReportDocument(connection, output, oracle, counts, reportSha256, limits, budget)
                }
                bounded.count
            }
            forceFile(temporary)
            val expected = digestFile(
                temporary,
                maximumReportBytes,
                "staged reconciliation report",
                budget,
            )
            if (expected.bytes != outputBound) {
                throw FullTreeDataTruthException("staged reconciliation report byte count changed")
            }
            Files.setPosixFilePermissions(temporary, READ_ONLY_FILE_PERMISSIONS)
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE)
            } catch (failure: AtomicMoveNotSupportedException) {
                throw FullTreeDataTruthException("filesystem cannot atomically publish reconciliation report", failure)
            }
            committed = true
            forceDirectory(target.parent)
            val published = digestFile(target, maximumReportBytes, "published reconciliation report", budget)
            if (published.bytes != expected.bytes || published.sha256 != expected.sha256) {
                throw FullTreeDataTruthException("published reconciliation report binding changed")
            }
            return WrittenReport(reportSha256, expected.sha256, expected.bytes)
        } finally {
            if (!committed) Files.deleteIfExists(temporary)
        }
    }

    private fun writeReportDocument(
        connection: Connection,
        output: OutputStream,
        oracle: JsonObject,
        counts: JsonObject,
        reportSha256: String?,
        limits: FullTreeDataReconciliationLimits,
        budget: CooperativeBudget,
    ) {
        budget.checkpoint("before emitting reconciliation report pass")
        val writer = CanonicalReportWriter(output)
        writer.startObject()
        writer.field("abiObjects")
        writer.startArray()
        streamPayloads(connection, "SELECT payload FROM report_abi ORDER BY elf_id, alias_name", budget) {
            writer.arrayValue(it)
        }
        writer.endArray()
        budget.checkpoint("while emitting reconciliation report pass")
        writer.field("counts")
        writer.value(canonicalRecord(counts, limits))
        writer.field("dwarfOnlyScoredGlobals")
        writer.startArray()
        connection.createStatement().use { statement ->
            statement.executeQuery(
                "SELECT g.id, g.owner_shard, g.address_rva FROM truth_globals g " +
                    "LEFT JOIN matched_truth m ON m.truth_id=g.id " +
                    "WHERE g.population='scored' AND m.truth_id IS NULL ORDER BY g.id",
            ).use { rows ->
                while (rows.next()) {
                    budget.periodicCheckpoint("while writing dwarf-only reconciliation records")
                    val address = rows.getString(3)
                        ?: throw FullTreeDataTruthException("scored dwarf-only global has no address")
                    val record = JsonObject(
                        mapOf(
                            "addressRva" to JsonPrimitive(address),
                            "shardId" to JsonPrimitive(rows.getString(2)),
                            "truthId" to JsonPrimitive(rows.getString(1)),
                        ),
                    )
                    validateReconciliationEntity("dwarf", record, oracle)
                    writer.arrayValue(canonicalRecord(record, limits))
                }
            }
        }
        writer.endArray()
        budget.checkpoint("while emitting reconciliation report pass")
        writer.field("globals")
        writer.startArray()
        streamPayloads(connection, "SELECT payload FROM report_globals ORDER BY elf_id", budget) {
            writer.arrayValue(it)
        }
        writer.endArray()
        budget.checkpoint("while emitting reconciliation report pass")
        writer.field("oracle")
        writer.value(canonicalRecord(oracle, limits))
        if (reportSha256 != null) {
            writer.field("reportSha256")
            writer.value(canonicalRecord(JsonPrimitive(reportSha256), limits))
        }
        writer.field("schemaVersion")
        writer.value(canonicalRecord(JsonPrimitive(1), limits))
        writer.endObject()
    }

    private fun streamPayloads(
        connection: Connection,
        sql: String,
        budget: CooperativeBudget,
        consume: (ByteArray) -> Unit,
    ) {
        connection.createStatement().use { statement ->
            statement.executeQuery(sql).use { rows ->
                while (rows.next()) {
                    budget.periodicCheckpoint("while writing reconciliation records")
                    consume(rows.getBytes(1))
                }
            }
        }
    }

    private fun configureDatabase(connection: Connection, limits: FullTreeDataReconciliationLimits) {
        connection.createStatement().use { statement ->
            statement.execute("PRAGMA journal_mode=OFF")
            statement.execute("PRAGMA synchronous=OFF")
            statement.execute("PRAGMA temp_store=MEMORY")
            statement.execute("PRAGMA automatic_index=OFF")
            statement.execute("PRAGMA foreign_keys=ON")
            statement.execute("PRAGMA cache_size=-16384")
            statement.execute("PRAGMA mmap_size=0")
            statement.execute("PRAGMA trusted_schema=OFF")
            statement.execute("PRAGMA page_size=$SQLITE_PAGE_BYTES")
            val pages = limits.maximumDatabaseBytes / SQLITE_PAGE_BYTES +
                if (limits.maximumDatabaseBytes % SQLITE_PAGE_BYTES == 0L) 0L else 1L
            statement.execute("PRAGMA max_page_count=$pages")
            statement.execute("PRAGMA application_id=$SQLITE_APPLICATION_ID")
            statement.execute("PRAGMA user_version=$SQLITE_SCHEMA_VERSION")
            statement.executeQuery("PRAGMA temp_store").use { rows ->
                if (!rows.next() || rows.getInt(1) != SQLITE_TEMP_STORE_MEMORY || rows.next()) {
                    throw FullTreeDataTruthException("SQLite temp storage is not confined to memory")
                }
            }
            statement.executeQuery("PRAGMA journal_mode").use { rows ->
                if (!rows.next() || rows.getString(1).lowercase() != "off" || rows.next()) {
                    throw FullTreeDataTruthException("SQLite journal storage is not disabled for scratch state")
                }
            }
        }
    }

    private fun createSchema(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.execute(
                "CREATE TABLE truth_globals(" +
                    "id TEXT PRIMARY KEY, owner_shard TEXT NOT NULL, population TEXT NOT NULL, " +
                    "address_rva TEXT, tls INTEGER NOT NULL CHECK(tls IN (0,1))) WITHOUT ROWID",
            )
            statement.execute(
                "CREATE INDEX truth_globals_address ON truth_globals(address_rva, tls, id, owner_shard)",
            )
            statement.execute(
                "CREATE TABLE truth_names(" +
                    "name TEXT NOT NULL, truth_id TEXT NOT NULL, PRIMARY KEY(name, truth_id), " +
                    "FOREIGN KEY(truth_id) REFERENCES truth_globals(id)) WITHOUT ROWID",
            )
            statement.execute(
                "CREATE TABLE truth_types(id TEXT PRIMARY KEY, owner_shard TEXT NOT NULL) WITHOUT ROWID",
            )
            statement.execute(
                "CREATE TABLE truth_reference_targets(" +
                    "reference_key TEXT NOT NULL, target_id TEXT NOT NULL, target_owner TEXT NOT NULL, " +
                    "PRIMARY KEY(reference_key, target_id, target_owner)) WITHOUT ROWID",
            )
            statement.execute(
                "CREATE TABLE matched_truth(" +
                    "truth_id TEXT PRIMARY KEY, FOREIGN KEY(truth_id) REFERENCES truth_globals(id)) WITHOUT ROWID",
            )
            statement.execute(
                "CREATE TABLE report_globals(" +
                    "elf_id TEXT PRIMARY KEY, reconciliation TEXT NOT NULL, payload BLOB NOT NULL) WITHOUT ROWID",
            )
            statement.execute(
                "CREATE TABLE report_abi(" +
                    "elf_id TEXT NOT NULL, alias_name TEXT NOT NULL, slots INTEGER NOT NULL, " +
                    "resolved_slots INTEGER NOT NULL, payload BLOB NOT NULL, " +
                    "PRIMARY KEY(elf_id, alias_name)) WITHOUT ROWID",
            )
        }
    }

    /** Proves every population-sized ordered query is index-backed and cannot request a temp B-tree. */
    private fun requireNoTempBTreePlans(connection: Connection) {
        val queries = listOf(
            "SELECT id, owner_shard FROM truth_globals WHERE address_rva='0x0' AND tls=0",
            "SELECT g.id, g.owner_shard FROM truth_names n JOIN truth_globals g ON g.id=n.truth_id " +
                "WHERE n.name='' AND g.tls=1",
            "SELECT payload FROM report_abi ORDER BY elf_id, alias_name",
            "SELECT payload FROM report_globals ORDER BY elf_id",
            "SELECT g.id, g.owner_shard, g.address_rva FROM truth_globals g " +
                "LEFT JOIN matched_truth m ON m.truth_id=g.id " +
                "WHERE g.population='scored' AND m.truth_id IS NULL ORDER BY g.id",
        )
        queries.forEach { sql ->
            connection.createStatement().use { statement ->
                statement.executeQuery("EXPLAIN QUERY PLAN $sql").use { rows ->
                    while (rows.next()) {
                        val detail = rows.getString(4).uppercase()
                        if ("TEMP B-TREE" in detail || "AUTOMATIC" in detail) {
                            throw FullTreeDataTruthException(
                                "SQLite reconciliation query would escape the explicit scratch model: $detail",
                            )
                        }
                    }
                }
            }
        }
    }

    private fun requireDatabaseBound(connection: Connection, maximumBytes: Long) {
        val pageCount = pragmaLong(connection, "page_count")
        val pageSize = pragmaLong(connection, "page_size")
        if (pageCount < 0L || pageSize <= 0L || pageCount > maximumBytes / pageSize) {
            throw FullTreeDataTruthException("data reconciliation SQLite database exceeds its byte limit")
        }
    }

    private fun pragmaLong(connection: Connection, name: String): Long = connection.createStatement().use { statement ->
        statement.executeQuery("PRAGMA $name").use { rows ->
            if (!rows.next()) throw FullTreeDataTruthException("SQLite $name is unavailable")
            rows.getLong(1)
        }
    }

    private fun requireModeledResidentBound(
        scope: JsonObject,
        maximumWorkers: Int,
        limits: FullTreeDataReconciliationLimits,
    ) {
        val entityBuffers = multiplyExact(
            limits.maximumEntityBytes.toLong(),
            multiplyExact(maximumWorkers.toLong(), 2L, "modeled worker buffer"),
            "modeled entity buffer",
        )
        val controls = multiplyExact(
            limits.maximumControlArtifactBytes.toLong(),
            4L,
            "modeled control buffer",
        )
        val required = addExact(
            addExact(
                addExact(entityBuffers, controls, "modeled resident byte"),
                limits.maximumModeledSqliteTempBytes,
                "modeled SQLite temp byte",
            ),
            addExact(
                SQLITE_CACHE_BYTES,
                multiplyExact(
                    limits.maximumMatchesPerElfGlobal.toLong(),
                    MODELED_MATCH_BYTES,
                    "modeled match-map byte",
                ),
                "modeled resident byte",
            ),
            "modeled resident byte",
        )
        val authenticated = scope.requiredObject("bounds").requiredObject("wholeRun")
            .requiredLong("maximumResidentBytes")
        if (required > authenticated) {
            throw FullTreeDataTruthException(
                "data reconciliation modeled working set $required exceeds authenticated resident bound $authenticated",
            )
        }
    }

    private fun streamingLimits(
        maximumInputBytes: Long,
        limits: FullTreeDataReconciliationLimits,
        scope: JsonObject,
        authenticatedMaximumEntities: Long,
    ): FullTreeCanonicalStreamingLimits {
        val whole = scope.requiredObject("bounds").requiredObject("wholeRun")
        return FullTreeCanonicalStreamingLimits(
            maximumInputBytes = maximumInputBytes,
            maximumTokens = limits.maximumTokens,
            maximumEntities = minOf(
                limits.maximumEntities,
                whole.requiredLong("entities"),
                authenticatedMaximumEntities,
            ),
            maximumEntityBytes = limits.maximumEntityBytes,
            maximumEntityNodes = limits.maximumEntityNodes,
            maximumTotalStringBytes = maximumInputBytes,
        )
    }

    private fun controlJsonLimits(limits: FullTreeDataReconciliationLimits): StrictJsonLimits = StrictJsonLimits(
        maximumInputBytes = limits.maximumControlArtifactBytes,
        maximumCanonicalBytes = limits.maximumControlArtifactBytes,
        maximumDepth = 128,
        maximumNodes = 1_000_000,
        maximumStringBytes = minOf(limits.maximumControlArtifactBytes, 1024 * 1024),
        maximumTotalStringBytes = limits.maximumControlArtifactBytes,
    )

    private fun canonicalControlBytes(
        value: JsonElement,
        limits: FullTreeDataReconciliationLimits,
    ): ByteArray = try {
        OracleJson.canonicalBytes(value, controlJsonLimits(limits))
    } catch (failure: Exception) {
        throw FullTreeDataTruthException("data reconciliation control JSON exceeds its strict limits", failure)
    }

    private fun canonicalControlSnapshot(
        value: JsonObject,
        label: String,
        limits: FullTreeDataReconciliationLimits,
    ): JsonObject {
        val bytes = canonicalControlBytes(value, limits)
        return try {
            OracleJson.parseCanonical(bytes, controlJsonLimits(limits)) as? JsonObject
                ?: throw FullTreeDataTruthException("data reconciliation $label must be an object")
        } catch (failure: FullTreeDataTruthException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeDataTruthException(
                "data reconciliation $label cannot be snapshotted as strict bounded JSON",
                failure,
            )
        }
    }

    private fun canonicalRecord(
        value: JsonElement,
        limits: FullTreeDataReconciliationLimits,
    ): ByteArray = try {
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
        throw FullTreeDataTruthException("data reconciliation record exceeds its strict JSON limits", failure)
    }

    private fun truthCounts(record: JsonObject): TruthCounts = TruthCounts(
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

    private fun requireIncreasing(current: String, previous: String?, label: String): String {
        if (previous != null && CODE_POINT_STRING_COMPARATOR.compare(previous, current) >= 0) {
            throw FullTreeDataTruthException("$label are duplicated or not canonically ordered")
        }
        return current
    }

    private fun requireSortedUnique(values: List<String>, label: String) {
        values.zipWithNext().forEach { (left, right) ->
            if (CODE_POINT_STRING_COMPARATOR.compare(left, right) >= 0) {
                throw FullTreeDataTruthException("$label are duplicated or not canonically ordered")
            }
        }
    }

    private fun requireHexAddress(value: String, label: String): BigInteger {
        if (!HEX_ADDRESS.matches(value)) throw FullTreeDataTruthException("$label is not canonical hexadecimal")
        return BigInteger(value.removePrefix("0x"), 16)
    }

    private fun insertExactlyOnce(statement: java.sql.PreparedStatement, label: String) {
        try {
            if (statement.executeUpdate() != 1) {
                throw FullTreeDataTruthException("$label was not stored exactly once")
            }
        } catch (failure: FullTreeDataTruthException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("$label is duplicated or invalid", failure)
        }
    }

    private fun digestFile(
        path: Path,
        maximumBytes: Long,
        label: String,
        budget: CooperativeBudget? = null,
    ): FileDigest {
        val before = regularFileAttributes(path, label)
        if (before.size() !in 1L..maximumBytes) throw FullTreeDataTruthException("$label exceeds its byte limit")
        val digest = MessageDigest.getInstance("SHA-256")
        var bytes = 0L
        Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                bytes = addExact(bytes, read.toLong(), "$label byte")
                if (bytes > maximumBytes) throw FullTreeDataTruthException("$label exceeds its byte limit")
                digest.update(buffer, 0, read)
                budget?.checkpoint("while hashing $label")
            }
        }
        val after = regularFileAttributes(path, label)
        if (before.fileKey() != after.fileKey() || before.size() != after.size() ||
            before.lastModifiedTime() != after.lastModifiedTime()
        ) {
            throw FullTreeDataTruthException("$label changed while hashing")
        }
        return FileDigest(bytes, digest.digest().hex(), after.fileKey())
    }

    private fun requireRealTrustedDirectory(path: Path, label: String): Path {
        val normalized = path.toAbsolutePath().normalize()
        val attributes = directoryAttributes(normalized, label)
        if (normalized.toRealPath() != normalized || attributes.fileKey() == null) {
            throw FullTreeDataTruthException("$label path contains a symbolic link")
        }
        val permissions = Files.getFileAttributeView(
            normalized,
            PosixFileAttributeView::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )?.readAttributes()?.permissions()
            ?: throw FullTreeDataTruthException("$label requires POSIX permissions")
        if (permissions.any { it in UNTRUSTED_WRITE_PERMISSIONS }) {
            throw FullTreeDataTruthException("$label is writable by an untrusted principal")
        }
        return normalized
    }

    private fun directoryAttributes(path: Path, label: String): BasicFileAttributes {
        val attributes = try {
            Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("$label is unavailable", failure)
        }
        if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
            throw FullTreeDataTruthException("$label must be an identified real directory")
        }
        return attributes
    }

    private fun regularFileAttributes(path: Path, label: String): BasicFileAttributes {
        val attributes = try {
            Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("$label is unavailable", failure)
        }
        if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
            throw FullTreeDataTruthException("$label must be an identified regular file")
        }
        return attributes
    }

    private fun requireScratchBound(root: Path, maximumBytes: Long) {
        var total = 0L
        Files.walk(root).use { paths ->
            paths.forEach { path ->
                val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                if (attributes.isSymbolicLink) throw FullTreeDataTruthException("scratch contains a symbolic link")
                if (attributes.isRegularFile) {
                    total = addExact(total, attributes.size(), "scratch byte")
                    if (total > maximumBytes) {
                        throw FullTreeDataTruthException("data reconciliation scratch exceeds its byte limit")
                    }
                } else if (!attributes.isDirectory) {
                    throw FullTreeDataTruthException("scratch contains an unsupported path type")
                }
            }
        }
    }

    private fun forceFile(path: Path) {
        FileChannel.open(path, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS).use { it.force(true) }
    }

    private fun forceDirectory(path: Path) {
        try {
            FileChannel.open(path, StandardOpenOption.READ).use { it.force(true) }
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("directory durability is unavailable", failure)
        }
    }

    private fun requireDigest(value: String, label: String) {
        if (!SHA256.matches(value)) throw FullTreeDataTruthException("$label digest is invalid")
    }

    private fun increment(value: Long, label: String): Long = addExact(value, 1L, label)

    private fun addExact(left: Long, right: Long, label: String): Long = try {
        Math.addExact(left, right)
    } catch (failure: ArithmeticException) {
        throw FullTreeDataTruthException("$label count exceeds the supported range", failure)
    }

    private fun multiplyExact(left: Long, right: Long, label: String): Long = try {
        Math.multiplyExact(left, right)
    } catch (failure: ArithmeticException) {
        throw FullTreeDataTruthException("$label count exceeds the supported range", failure)
    }

    private fun JsonElement.nullableString(label: String): String? = when (this) {
        JsonNull -> null
        else -> requiredString(label)
    }

    private fun JsonElement.strictBoolean(label: String): Boolean {
        val primitive = this as? JsonPrimitive
            ?: throw FullTreeDataTruthException("$label is not a Boolean")
        return primitive.booleanOrNull ?: throw FullTreeDataTruthException("$label is not a Boolean")
    }

    private fun ByteArray.hex(): String = joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }

    private data class AuthenticatedInputs(
        val root: Path,
        val index: JsonObject,
        val partitions: List<TruthPartition>,
    )

    private data class TruthPartition(
        val index: Int,
        val shardId: String,
        val ordinal: Int,
        val total: Int,
        val path: Path,
        val bytes: Long,
        val sha256: String,
        val counts: TruthCounts,
    )

    private data class ReportResult(
        val reportSha256: String,
        val artifactSha256: String,
        val outputBytes: Long,
        val counts: JsonObject,
    )
    private data class WrittenReport(val reportSha256: String, val artifactSha256: String, val bytes: Long)
    private data class FileDigest(val bytes: Long, val sha256: String, val identity: Any?)

    private data class ElfCounts(
        var globalRvas: Long = 0L,
        var aliases: Long = 0L,
        var externalGlobals: Long = 0L,
        var abiObjects: Long = 0L,
        var abiSlots: Long = 0L,
        var abiResolvedSlots: Long = 0L,
    ) {
        fun toJson(): JsonObject = JsonObject(
            mapOf(
                "abiObjects" to JsonPrimitive(abiObjects),
                "abiResolvedSlots" to JsonPrimitive(abiResolvedSlots),
                "abiSlots" to JsonPrimitive(abiSlots),
                "aliases" to JsonPrimitive(aliases),
                "externalGlobals" to JsonPrimitive(externalGlobals),
                "globalRvas" to JsonPrimitive(globalRvas),
            ),
        )
    }

    private data class TruthCounts(
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
            get() = addExact(globals, types, "truth entity")

        fun add(other: TruthCounts) {
            globals = addExact(globals, other.globals, "truth global")
            types = addExact(types, other.types, "truth type")
            unobservableGlobals = addExact(
                unobservableGlobals,
                other.unobservableGlobals,
                "unobservable truth global",
            )
            unobservableTypes = addExact(unobservableTypes, other.unobservableTypes, "unobservable truth type")
            fields = addExact(fields, other.fields, "truth field")
            bases = addExact(bases, other.bases, "truth base")
            enumerators = addExact(enumerators, other.enumerators, "truth enumerator")
            resolvedTypeReferences = addExact(
                resolvedTypeReferences,
                other.resolvedTypeReferences,
                "resolved truth reference",
            )
            unresolvedTypeReferences = addExact(
                unresolvedTypeReferences,
                other.unresolvedTypeReferences,
                "unresolved truth reference",
            )
            ambiguousTypeReferences = addExact(
                ambiguousTypeReferences,
                other.ambiguousTypeReferences,
                "ambiguous truth reference",
            )
            crossShardTypeReferences = addExact(
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
            fun forEntity(kind: String, entity: JsonObject, ownerShard: String): TruthCounts {
                val result = TruthCounts()
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
                                "field" -> result.fields++
                                "base" -> result.bases++
                                "enumerator" -> result.enumerators++
                                else -> throw FullTreeDataTruthException("truth member kind is invalid")
                            }
                        }
                    }
                    else -> throw FullTreeDataTruthException("truth entity kind is invalid")
                }
                truthReferences(kind, entity).forEach { reference ->
                    if (reference.requiredElement("targetTypeId") is JsonNull) {
                        result.unresolvedTypeReferences++
                    } else {
                        result.resolvedTypeReferences++
                    }
                    if (reference.requiredString("resolutionCode") == "unresolved-authenticated-target-set") {
                        result.ambiguousTypeReferences++
                    }
                    val targetOwner = reference.requiredElement("targetOwnerShardId")
                        .nullableString("targetOwnerShardId")
                    if (targetOwner != null && targetOwner != ownerShard) result.crossShardTypeReferences++
                }
                return result
            }

            private fun truthReferences(kind: String, entity: JsonObject): List<JsonObject> = when (kind) {
                "global" -> listOf(entity.requiredObject("typeReference"))
                "type" -> entity.requiredArray("members").objects("truth member")
                    .map { it.requiredObject("typeReference") }
                else -> throw FullTreeDataTruthException("truth entity kind is invalid")
            }
        }
    }

    private class CooperativeBudget(
        scope: JsonObject,
        private val runtime: FullTreeReconciliationRuntime,
        private val started: FullTreeReconciliationRuntimeSample,
    ) {
        private val maximumWallNanos = TimeUnit.SECONDS.toNanos(
            scope.requiredObject("bounds").requiredObject("wholeRun").requiredLong("wallClockSeconds"),
        )
        private val maximumCpuNanos = TimeUnit.SECONDS.toNanos(
            scope.requiredObject("bounds").requiredObject("wholeRun").requiredLong("cpuSeconds"),
        )
        private var periodicUnits = 0

        fun checkpoint(stage: String) {
            val current = runtime.sample(stage)
            val wall = current.wallNanos - started.wallNanos
            val cpu = current.processCpuNanos - started.processCpuNanos
            if (wall < 0L || wall > maximumWallNanos) {
                throw FullTreeDataTruthException("data reconciliation exceeds wall-clock bound $stage")
            }
            if (cpu < 0L || cpu > maximumCpuNanos) {
                throw FullTreeDataTruthException("data reconciliation exceeds process-CPU bound $stage")
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
        private val budget: CooperativeBudget,
    ) :
        FilterOutputStream(output) {
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
                throw FullTreeDataTruthException("data reconciliation report exceeds its byte limit")
            }
        }

        private fun chargeCheckpointBytes(bytes: Long) {
            bytesSinceCheckpoint = addExact(bytesSinceCheckpoint, bytes, "report checkpoint byte")
            if (bytesSinceCheckpoint >= REPORT_CHECKPOINT_BYTES) {
                budget.checkpoint("while emitting reconciliation report")
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
            writeSpaces(2)
            writeAscii("\"$name\": ")
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
            if (finished) throw FullTreeDataTruthException("canonical report writer already finished")
            writeAscii("\n}\n")
            finished = true
        }

        private fun writeCanonicalValue(bytes: ByteArray, indentation: Int, indentFirst: Boolean) {
            if (bytes.isEmpty() || bytes.last() != '\n'.code.toByte()) {
                throw FullTreeDataTruthException("canonical report value is malformed")
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

    private class ReconciliationPublication private constructor(
        val target: Path,
        val staging: Path,
        val scratch: Path,
        private val parentIdentity: Any,
        private val stagingIdentity: Any,
        private val scratchIdentity: Any,
    ) : AutoCloseable {
        private var committed = false

        fun commit(
            expectedSha256: String,
            expectedBytes: Long,
            maximumBytes: Long,
            budget: CooperativeBudget,
        ) {
            val report = staging.resolve("report.json")
            verifyTree(staging, report, expectedSha256, expectedBytes, maximumBytes, budget)
            requireDirectoryIdentity(staging, stagingIdentity, "reconciliation staging directory")
            requireDirectoryIdentity(scratch, scratchIdentity, "reconciliation scratch directory")
            deleteEmptyDirectory(scratch, scratchIdentity, "reconciliation scratch directory")
            Files.setPosixFilePermissions(staging, READ_ONLY_DIRECTORY_PERMISSIONS)
            if (Files.getPosixFilePermissions(staging, LinkOption.NOFOLLOW_LINKS) !=
                READ_ONLY_DIRECTORY_PERMISSIONS
            ) {
                throw FullTreeDataTruthException("reconciliation staging directory permissions differ")
            }
            forceDirectory(staging)
            requireDirectoryIdentity(target.parent, parentIdentity, "reconciliation output parent")
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                throw FullTreeDataTruthException("data reconciliation output target already exists")
            }
            var published = false
            try {
                try {
                    Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE)
                } catch (failure: AtomicMoveNotSupportedException) {
                    throw FullTreeDataTruthException(
                        "filesystem cannot atomically publish reconciliation directory",
                        failure,
                    )
                }
                published = true
                forceDirectory(target.parent)
                requireDirectoryIdentity(target.parent, parentIdentity, "reconciliation output parent")
                requireDirectoryIdentity(target, stagingIdentity, "published reconciliation directory")
                if (Files.getPosixFilePermissions(target, LinkOption.NOFOLLOW_LINKS) !=
                    READ_ONLY_DIRECTORY_PERMISSIONS
                ) {
                    throw FullTreeDataTruthException("published reconciliation directory permissions differ")
                }
                verifyTree(
                    target,
                    target.resolve("report.json"),
                    expectedSha256,
                    expectedBytes,
                    maximumBytes,
                    budget,
                )
                budget.checkpoint("after atomic reconciliation publication")
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
                deleteOwnedTreeIfPresent(staging, stagingIdentity, "reconciliation staging directory")
            } catch (failure: Throwable) {
                cleanupFailure = failure
            }
            try {
                deleteOwnedTreeIfPresent(scratch, scratchIdentity, "reconciliation scratch directory")
            } catch (failure: Throwable) {
                if (cleanupFailure == null) cleanupFailure = failure else cleanupFailure.addSuppressed(failure)
            }
            cleanupFailure?.let { throw it }
        }

        companion object {
            fun create(path: Path, budget: CooperativeBudget): ReconciliationPublication {
                val target = path.toAbsolutePath().normalize()
                if (target.fileName == null || target.parent == null) {
                    throw FullTreeDataTruthException("data reconciliation output must name a directory")
                }
                val parent = requireRealTrustedDirectory(target.parent, "data reconciliation output parent")
                if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                    throw FullTreeDataTruthException("data reconciliation output already exists")
                }
                val parentIdentity = directoryAttributes(parent, "data reconciliation output parent").fileKey()
                    ?: throw FullTreeDataTruthException("data reconciliation output parent has no identity")
                forceDirectory(parent)
                var staging: Path? = null
                var stagingIdentity: Any? = null
                var scratch: Path? = null
                var scratchIdentity: Any? = null
                try {
                    staging = Files.createTempDirectory(parent, ".${target.fileName}.reconciliation-stage-")
                    stagingIdentity = directoryAttributes(staging, "reconciliation staging directory").fileKey()
                        ?: throw FullTreeDataTruthException("reconciliation staging directory has no identity")
                    Files.setPosixFilePermissions(staging, PRIVATE_DIRECTORY_PERMISSIONS)
                    budget.checkpoint("after reconciliation staging creation")

                    scratch = Files.createTempDirectory(parent, ".${target.fileName}.reconciliation-scratch-")
                    scratchIdentity = directoryAttributes(scratch, "reconciliation scratch directory").fileKey()
                        ?: throw FullTreeDataTruthException("reconciliation scratch directory has no identity")
                    Files.setPosixFilePermissions(scratch, PRIVATE_DIRECTORY_PERMISSIONS)
                    budget.checkpoint("after reconciliation scratch creation")
                    forceDirectory(parent)
                    requireDirectoryIdentity(parent, parentIdentity, "data reconciliation output parent")
                    return ReconciliationPublication(
                        target,
                        staging,
                        scratch,
                        parentIdentity,
                        stagingIdentity,
                        scratchIdentity,
                    )
                } catch (failure: Throwable) {
                    cleanupPartiallyConstructedDirectory(
                        scratch,
                        scratchIdentity,
                        "reconciliation scratch directory",
                        failure,
                    )
                    cleanupPartiallyConstructedDirectory(
                        staging,
                        stagingIdentity,
                        "reconciliation staging directory",
                        failure,
                    )
                    try {
                        forceDirectory(parent)
                    } catch (cleanupFailure: Throwable) {
                        failure.addSuppressed(cleanupFailure)
                    }
                    if (failure is FullTreeDataTruthException) throw failure
                    throw FullTreeDataTruthException("cannot create reconciliation publication", failure)
                }
            }

            private fun cleanupPartiallyConstructedDirectory(
                path: Path?,
                expectedIdentity: Any?,
                label: String,
                failure: Throwable,
            ) {
                if (path == null) return
                try {
                    if (expectedIdentity != null) {
                        deleteOwnedTreeIfPresent(path, expectedIdentity, label)
                    } else if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                        val attributes = Files.readAttributes(
                            path,
                            BasicFileAttributes::class.java,
                            LinkOption.NOFOLLOW_LINKS,
                        )
                        if (!attributes.isDirectory || attributes.isSymbolicLink) {
                            throw FullTreeDataTruthException("$label has an unsafe partial identity")
                        }
                        // No recursive deletion is allowed without a captured identity. The freshly
                        // created directory must still be empty or cleanup fails closed.
                        Files.delete(path)
                    }
                } catch (cleanupFailure: Throwable) {
                    failure.addSuppressed(cleanupFailure)
                }
            }
        }

        private fun verifyTree(
            root: Path,
            report: Path,
            expectedSha256: String,
            expectedBytes: Long,
            maximumBytes: Long,
            budget: CooperativeBudget,
        ) {
            val expected = setOf(root, report)
            val actual = hashSetOf<Path>()
            Files.walk(root).use { paths ->
                paths.forEach { path ->
                    budget.periodicCheckpoint("while verifying reconciliation publication membership")
                    val normalized = path.toAbsolutePath().normalize()
                    if (!actual.add(normalized) || normalized !in expected) {
                        throw FullTreeDataTruthException("reconciliation publication contains an extra path")
                    }
                    val attributes = Files.readAttributes(
                        normalized,
                        BasicFileAttributes::class.java,
                        LinkOption.NOFOLLOW_LINKS,
                    )
                    if (attributes.isSymbolicLink || (normalized == root && !attributes.isDirectory) ||
                        (normalized == report && !attributes.isRegularFile)
                    ) {
                        throw FullTreeDataTruthException("reconciliation publication contains an invalid path type")
                    }
                }
            }
            if (actual != expected) throw FullTreeDataTruthException("reconciliation publication is incomplete")
            val digest = digestFile(report, maximumBytes, "reconciliation publication report", budget)
            if (digest.bytes != expectedBytes || digest.sha256 != expectedSha256) {
                throw FullTreeDataTruthException("reconciliation publication report binding differs")
            }
            val permissions = Files.getPosixFilePermissions(report, LinkOption.NOFOLLOW_LINKS)
            if (permissions != READ_ONLY_FILE_PERMISSIONS) {
                throw FullTreeDataTruthException("reconciliation publication report permissions differ")
            }
        }

        private fun revokePublished(path: Path, expectedIdentity: Any) {
            requireDirectoryIdentity(path, expectedIdentity, "unverified reconciliation publication")
            Files.setPosixFilePermissions(path, PRIVATE_DIRECTORY_PERMISSIONS)
            val report = path.resolve("report.json")
            val paths = Files.walk(path).use { stream -> stream.toList() }
            if (paths.toSet() != setOf(path, report)) {
                throw FullTreeDataTruthException("cannot safely revoke reconciliation publication with extra paths")
            }
            Files.delete(report)
            Files.delete(path)
            forceDirectory(path.parent)
        }

        private fun deleteEmptyDirectory(path: Path, expectedIdentity: Any, label: String) {
            requireDirectoryIdentity(path, expectedIdentity, label)
            Files.newDirectoryStream(path).use { entries ->
                if (entries.iterator().hasNext()) throw FullTreeDataTruthException("$label is not empty")
            }
            Files.delete(path)
            forceDirectory(path.parent)
        }

    }

    private fun deleteOwnedTreeIfPresent(path: Path, expectedIdentity: Any, label: String) {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return
        requireDirectoryIdentity(path, expectedIdentity, label)
        Files.setPosixFilePermissions(path, PRIVATE_DIRECTORY_PERMISSIONS)
        val paths = Files.walk(path).use { stream -> stream.toList() }
        paths.sortedWith(Comparator.reverseOrder()).forEach { candidate ->
            val attributes = Files.readAttributes(
                candidate,
                BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
            if (attributes.isSymbolicLink || (!attributes.isDirectory && !attributes.isRegularFile)) {
                throw FullTreeDataTruthException("$label contains an unsafe path during cleanup")
            }
            Files.delete(candidate)
        }
        forceDirectory(path.parent)
    }

    private fun requireDirectoryIdentity(path: Path, expected: Any, label: String) {
        if (directoryAttributes(path, label).fileKey() != expected) {
            throw FullTreeDataTruthException("$label changed identity")
        }
    }

    private const val SQLITE_PAGE_BYTES = 4096L
    private const val SQLITE_CACHE_BYTES = 16L * 1024L * 1024L
    private const val SQLITE_APPLICATION_ID = 0x44435243
    private const val SQLITE_SCHEMA_VERSION = 1
    private const val SQLITE_TEMP_STORE_MEMORY = 2
    private const val MODELED_MATCH_BYTES = 256L
    private const val REPORT_CHECKPOINT_BYTES = 1024L * 1024L
    private val SHA256 = Regex("[0-9a-f]{64}")
    private val HEX_ADDRESS = Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})")
    private val TRUTH_FIELDS = listOf("counts", "globals", "oracle", "schemaVersion", "shard", "types")
    private val ELF_FIELDS = listOf(
        "artifacts",
        "counts",
        "externalGlobals",
        "globals",
        "indexSha256",
        "oracle",
        "schemaVersion",
    )
    private val BOUND_NAMES = listOf(
        "compilationUnits",
        "cpuSeconds",
        "entities",
        "serializedBytes",
        "wallClockSeconds",
        "maximumResidentBytes",
    )
    private val INVENTORY_INDEX_DOMAIN = "full-tree-index-v1\u0000".toByteArray(StandardCharsets.UTF_8)
    private val SYSTEM_RUNTIME = FullTreeReconciliationRuntime {
        FullTreeReconciliationRuntimeSample(
            wallNanos = System.nanoTime(),
            processCpuNanos = ProcessHandle.current().info().totalCpuDuration()
                .orElseThrow { FullTreeDataTruthException("process CPU duration is unavailable") }
                .toNanos(),
        )
    }
    private val PRIVATE_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
    private val READ_ONLY_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("r-x------")
    private val PRIVATE_FILE_PERMISSIONS: Set<PosixFilePermission> = EnumSet.of(
        PosixFilePermission.OWNER_READ,
        PosixFilePermission.OWNER_WRITE,
    )
    private val READ_ONLY_FILE_PERMISSIONS = PosixFilePermissions.fromString("r--------")
    private val UNTRUSTED_WRITE_PERMISSIONS: Set<PosixFilePermission> = EnumSet.of(
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
    private val EMPTY_REPORT_COUNTS = JsonObject(
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
    private val RECONCILIATION_POLICY = JsonObject(
        mapOf(
            "id" to JsonPrimitive("full-tree-data-reconciliation"),
            "version" to JsonPrimitive(1),
            "imageObjects" to JsonPrimitive("exact-image-rva"),
            "tlsObjects" to JsonPrimitive("exact-authenticated-linkage-name"),
            "elfOnlyOwnership" to JsonPrimitive("explicit-elf-only-shard"),
        ),
    )
    private val ELF_DATA_POLICY = JsonObject(
        mapOf(
            "id" to JsonPrimitive("full-tree-elf-data"),
            "version" to JsonPrimitive(2),
            "identity" to JsonPrimitive("one-record-per-defined-object-rva"),
            "abiSlots" to JsonPrimitive(
                "authenticated-eight-byte-little-endian-object-words-with-loaded-image-pointer-resolution",
            ),
        ),
    )
}
