package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.io.BufferedOutputStream
import java.io.FilterOutputStream
import java.io.OutputStream
import java.nio.ByteBuffer
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
import java.sql.PreparedStatement
import java.sql.ResultSet
import java.util.Collections
import java.util.EnumSet
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

data class FullTreeDataTruthGenerationLimits(
    val maximumControlArtifactBytes: Int = 16 * 1024 * 1024,
    val maximumObservationInputBytes: Long = 1024L * 1024L * 1024L,
    val maximumObservationDatabaseBytes: Long = 2L * 1024L * 1024L * 1024L,
    val maximumScratchDatabaseBytes: Long = 8L * 1024L * 1024L * 1024L,
    val maximumScratchBytes: Long = 16L * 1024L * 1024L * 1024L,
    val maximumEntityBytes: Int = 16 * 1024 * 1024,
    val maximumEntityNodes: Int = 1_000_000,
    val maximumMergePopulationEntities: Int = 100_000,
    val maximumMergePopulationBytes: Long = 32L * 1024L * 1024L,
    val maximumPartitions: Int = 10_000,
) {
    init {
        require(maximumControlArtifactBytes in 1..64 * 1024 * 1024) {
            "maximumControlArtifactBytes is outside the supported range"
        }
        require(maximumObservationInputBytes in 1L..16L * 1024L * 1024L * 1024L) {
            "maximumObservationInputBytes is outside the supported range"
        }
        require(maximumObservationDatabaseBytes in 1L..32L * 1024L * 1024L * 1024L) {
            "maximumObservationDatabaseBytes is outside the supported range"
        }
        require(maximumScratchDatabaseBytes in 1L..8L * 1024L * 1024L * 1024L) {
            "maximumScratchDatabaseBytes is outside the supported range"
        }
        require(maximumScratchBytes in maximumScratchDatabaseBytes..64L * 1024L * 1024L * 1024L) {
            "maximumScratchBytes is outside the supported range"
        }
        require(maximumEntityBytes in 1..64 * 1024 * 1024) {
            "maximumEntityBytes is outside the supported range"
        }
        require(maximumEntityNodes in 1..1_000_000) {
            "maximumEntityNodes is outside the supported range"
        }
        require(maximumMergePopulationEntities in 1..1_000_000) {
            "maximumMergePopulationEntities is outside the supported range"
        }
        require(maximumMergePopulationBytes in maximumEntityBytes.toLong()..1024L * 1024L * 1024L) {
            "maximumMergePopulationBytes is outside the supported range"
        }
        require(maximumPartitions in 1..1_000_000) { "maximumPartitions is outside the supported range" }
    }
}

data class FullTreeDataTruthGeneration(
    val index: JsonObject,
    val indexSha256: String,
    val observationIndexSha256: String,
    val partitionCount: Int,
    val outputBytes: Long,
)

/** Kotlin-owned authenticated orchestration and bounded SQLite data-truth publication. */
object FullTreeDataTruthSqlite {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256("full-tree-data-truth", POLICY)
    }

    fun generate(
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        observationRoot: Path,
        outputRoot: Path,
        maximumWorkers: Int,
        limits: FullTreeDataTruthGenerationLimits = FullTreeDataTruthGenerationLimits(),
    ): FullTreeDataTruthGeneration {
        requireSha256(scopeSha256, "scope")
        require(maximumWorkers in 1..32) { "data truth worker count is outside 1..32" }
        validateInputs(scope, scopeSha256, inventory)
        val authenticated = authenticateObservationRun(
            scope,
            scopeSha256,
            inventory,
            observationRoot,
            limits,
        )
        if (maximumWorkers > authenticated.maximumWorkers) {
            throw FullTreeDataTruthException("data truth worker count exceeds the authenticated run bound")
        }
        requireResidentMemoryBound(scope, maximumWorkers, limits)
        val publication = OutputPublication.create(outputRoot)
        var completed = false
        try {
            val scratch = publication.staging.resolve(".scratch")
            val observationDatabases = scratch.resolve("observations")
            val shardDirectory = publication.staging.resolve("shards")
            Files.createDirectories(observationDatabases)
            Files.createDirectories(shardDirectory)
            Files.setPosixFilePermissions(scratch, PRIVATE_DIRECTORY_PERMISSIONS)
            Files.setPosixFilePermissions(observationDatabases, PRIVATE_DIRECTORY_PERMISSIONS)
            Files.setPosixFilePermissions(shardDirectory, PRIVATE_DIRECTORY_PERMISSIONS)

            val databases = ingestObservationShards(
                authenticated,
                scope,
                scopeSha256,
                inventory,
                authenticated.root,
                observationDatabases,
                maximumWorkers,
                limits,
            )
            requireScratchBound(scratch, limits.maximumScratchBytes)

            val truthDatabase = scratch.resolve("truth.sqlite")
            val result = buildTruthDatabaseAndPartitions(
                truthDatabase,
                databases,
                authenticated,
                scope,
                scopeSha256,
                inventory,
                shardDirectory,
                limits,
            )
            requireScratchBound(scratch, limits.maximumScratchBytes)
            databases.forEach { Files.delete(it.path) }
            Files.delete(observationDatabases)
            Files.delete(truthDatabase)
            Files.delete(scratch)

            val indexBytes = canonicalBytes(result.index, limits.maximumControlArtifactBytes)
            OracleArtifacts.publishAtomically(
                publication.staging.resolve("index.json"),
                indexBytes,
                OracleArtifactLimits(limits.maximumControlArtifactBytes),
            )
            Files.setPosixFilePermissions(
                publication.staging.resolve("index.json"),
                READ_ONLY_FILE_PERMISSIONS,
            )
            publication.commit { publishedRoot ->
                verifyTruthPublication(publishedRoot, result.index, indexBytes, scope, limits)
            }
            completed = true
            return FullTreeDataTruthGeneration(
                index = result.index,
                indexSha256 = result.index.requiredString("indexSha256"),
                observationIndexSha256 = authenticated.indexSha256,
                partitionCount = result.partitionCount,
                outputBytes = result.outputBytes,
            )
        } finally {
            if (!completed) publication.close()
        }
    }

    private fun validateInputs(scope: JsonObject, scopeSha256: String, inventory: JsonObject) {
        try {
            OracleSchemas.validate("full-tree-scope", scope)
            OracleSchemas.validate("full-tree-inventory", inventory)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data truth inputs fail schema validation: ${failure.message}", failure)
        }
        val scopeOracle = scope.requiredObject("oracle")
        val inventoryOracle = inventory.requiredObject("oracle")
        if (
            inventoryOracle.requiredString("scopeSha256") != scopeSha256 ||
            inventoryOracle.requiredString("richArtifactSha256") != scopeOracle.requiredString("richArtifactSha256") ||
            inventoryOracle.requiredString("sourceLockSha256") != scopeOracle.requiredString("sourceLockSha256") ||
            inventoryOracle.requiredString("artifactManifestSha256") !=
            scopeOracle.requiredString("artifactManifestSha256")
        ) {
            throw FullTreeDataTruthException("data truth inventory bindings do not match the authenticated scope")
        }
        val units = inventory.requiredArray("units").objects("inventory unit")
        val shards = inventory.requiredArray("shards").objects("inventory shard")
        if (units.size.toLong() > scope.requiredObject("bounds").requiredObject("wholeRun").requiredLong("compilationUnits")) {
            throw FullTreeDataTruthException("data truth inventory exceeds the whole-run compilation-unit bound")
        }
        if (inventory.requiredObject("counts").requiredLong("compilationUnits") != units.size.toLong() ||
            inventory.requiredObject("counts").requiredLong("shards") != shards.size.toLong()
        ) {
            throw FullTreeDataTruthException("data truth inventory counts do not reconcile")
        }
        val unitById = units.associateBy { it.requiredString("id") }
        if (unitById.size != units.size) throw FullTreeDataTruthException("inventory unit identifiers are not unique")
        val seenUnits = hashSetOf<String>()
        val shardIds = hashSetOf<String>()
        shards.forEach { shard ->
            val shardId = shard.requiredString("id")
            if (!shardIds.add(shardId)) throw FullTreeDataTruthException("inventory shard identifiers are not unique")
            shard.requiredArray("unitIds").forEach { element ->
                val unitId = element.requiredString("inventory shard unit")
                val unit = unitById[unitId]
                    ?: throw FullTreeDataTruthException("inventory shard references an unknown unit")
                if (unit.requiredString("shardId") != shardId || !seenUnits.add(unitId)) {
                    throw FullTreeDataTruthException("inventory unit ownership is duplicated or contradictory")
                }
            }
        }
        if (seenUnits != unitById.keys) throw FullTreeDataTruthException("inventory unit ownership is incomplete")
    }

    private fun authenticateObservationRun(
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        observationRoot: Path,
        limits: FullTreeDataTruthGenerationLimits,
    ): AuthenticatedObservationRun {
        val root = requireRealDirectory(observationRoot, "data observation root")
        val runArtifact = readCanonicalObject(root.resolve("run.json"), limits.maximumControlArtifactBytes)
        val indexArtifact = readCanonicalObject(root.resolve("index.json"), limits.maximumControlArtifactBytes)
        val run = runArtifact.document
        val index = indexArtifact.document
        try {
            OracleSchemas.validate("bounded-shard-index", index)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data observation index fails schema validation: ${failure.message}", failure)
        }

        val expectedInputs = FullTreeDataObservations.shardInputs(
            inventory,
            scopeSha256,
            scope.requiredObject("oracle").requiredString("richArtifactSha256"),
        ).sortedBy { it.identifier }
        val runWorkers = run.requiredObject("bounds").requiredLong("maximumWorkers")
        if (runWorkers !in 1L..minOf(32, expectedInputs.size).toLong()) {
            throw FullTreeDataTruthException("data observation run worker bound is invalid")
        }
        val expectedRun = observationRunContract(scope, scopeSha256, expectedInputs, runWorkers)
        if (run != expectedRun) throw FullTreeDataTruthException("data observation run contract differs")
        val runSha256 = OracleArtifacts.sha256(runArtifact.bytes)

        val records = index.requiredArray("shards").objects("data observation index shard")
        if (records.size != expectedInputs.size) {
            throw FullTreeDataTruthException("data observation index shard population is incomplete")
        }
        val expectedById = expectedInputs.associateBy { it.identifier }
        val identifiers = records.map { it.requiredString("shardId") }
        if (identifiers != expectedInputs.map { it.identifier }) {
            throw FullTreeDataTruthException("data observation index membership or ordering differs")
        }
        val perShard = scope.requiredObject("bounds").requiredObject("perShard")
        val wholeRun = scope.requiredObject("bounds").requiredObject("wholeRun")
        var totalEntities = 0L
        var totalBytes = 0L
        val leaves = MessageDigest.getInstance("SHA-256").apply {
            update("bounded-shards-v1\u0000".toByteArray(StandardCharsets.UTF_8))
        }
        val authenticatedShards = records.map { record ->
            val identifier = record.requiredString("shardId")
            val expected = expectedById.getValue(identifier)
            val checkpoint = readCanonicalObject(
                root.resolve("checkpoints").resolve("$identifier.json"),
                limits.maximumControlArtifactBytes,
            ).document
            if (checkpoint != record) {
                throw FullTreeDataTruthException("data observation checkpoint differs for $identifier")
            }
            if (
                record.requiredLong("schemaVersion") != 1L ||
                record.requiredString("status") != "complete" ||
                record.requiredString("inputSha256") != expected.inputSha256 ||
                record.requiredString("runSha256") != runSha256
            ) {
                throw FullTreeDataTruthException("data observation checkpoint identity differs for $identifier")
            }
            val entities = record.requiredLong("entities")
            val outputBytes = record.requiredLong("outputBytes")
            if (entities > perShard.requiredLong("entities") || outputBytes > perShard.requiredLong("serializedBytes")) {
                throw FullTreeDataTruthException("data observation checkpoint exceeds per-shard bounds")
            }
            totalEntities = addExact(totalEntities, entities, "observation entity")
            totalBytes = addExact(totalBytes, outputBytes, "observation byte")
            leaves.update(MessageDigest.getInstance("SHA-256").digest(canonicalBytes(record, limits.maximumControlArtifactBytes)))
            AuthenticatedObservationShard(
                identifier = identifier,
                input = expected,
                artifact = FullTreeDataObservationArtifactBinding(
                    record.requiredString("outputSha256"),
                    outputBytes,
                    entities,
                ),
            )
        }
        if (totalEntities > wholeRun.requiredLong("entities") || totalBytes > wholeRun.requiredLong("serializedBytes")) {
            throw FullTreeDataTruthException("data observation index exceeds whole-run bounds")
        }
        val expectedCounts = JsonObject(
            mapOf(
                "entities" to JsonPrimitive(totalEntities),
                "serializedBytes" to JsonPrimitive(totalBytes),
                "shards" to JsonPrimitive(records.size),
            ),
        )
        val expectedIndex = JsonObject(
            mapOf(
                "complete" to JsonPrimitive(true),
                "counts" to expectedCounts,
                "indexSha256" to JsonPrimitive(leaves.digest().hex()),
                "runSha256" to JsonPrimitive(runSha256),
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(records),
            ),
        )
        if (index != expectedIndex) throw FullTreeDataTruthException("data observation index commitment differs")
        return AuthenticatedObservationRun(
            root = root,
            maximumWorkers = runWorkers.toInt(),
            indexSha256 = OracleArtifacts.sha256(indexArtifact.bytes),
            shards = Collections.unmodifiableList(authenticatedShards),
        )
    }

    private fun observationRunContract(
        scope: JsonObject,
        scopeSha256: String,
        inputs: List<FullTreeDataObservationShardInput>,
        maximumWorkers: Long,
    ): JsonObject {
        val perShard = scope.requiredObject("bounds").requiredObject("perShard")
        val wholeRun = scope.requiredObject("bounds").requiredObject("wholeRun")
        return JsonObject(
            mapOf(
                "bounds" to JsonObject(
                    mapOf(
                        "maximumResidentBytes" to wholeRun.requiredElement("maximumResidentBytes"),
                        "maximumShards" to JsonPrimitive(inputs.size),
                        "maximumWorkers" to JsonPrimitive(maximumWorkers),
                        "perShardBytes" to perShard.requiredElement("serializedBytes"),
                        "perShardCpuSeconds" to perShard.requiredElement("cpuSeconds"),
                        "perShardEntities" to perShard.requiredElement("entities"),
                        "perShardSeconds" to perShard.requiredElement("wallClockSeconds"),
                        "wholeRunBytes" to wholeRun.requiredElement("serializedBytes"),
                        "wholeRunCpuSeconds" to wholeRun.requiredElement("cpuSeconds"),
                        "wholeRunEntities" to wholeRun.requiredElement("entities"),
                        "wholeRunSeconds" to wholeRun.requiredElement("wallClockSeconds"),
                    ),
                ),
                "id" to JsonPrimitive("full-tree-data-${scopeSha256.take(16)}"),
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(
                    inputs.map { input ->
                        JsonObject(
                            mapOf(
                                "id" to JsonPrimitive(input.identifier),
                                "inputSha256" to JsonPrimitive(input.inputSha256),
                            ),
                        )
                    },
                ),
            ),
        )
    }

    private fun ingestObservationShards(
        authenticated: AuthenticatedObservationRun,
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        observationRoot: Path,
        databaseRoot: Path,
        maximumWorkers: Int,
        limits: FullTreeDataTruthGenerationLimits,
    ): List<ObservationDatabase> {
        val workers = minOf(maximumWorkers, authenticated.shards.size)
        val executor = Executors.newFixedThreadPool(workers)
        try {
            val tasks = authenticated.shards.map { shard ->
                Callable {
                        val database = databaseRoot.resolve("${shard.identifier}.sqlite")
                        val result = FullTreeDataObservationSqlite.ingest(
                            source = observationRoot.resolve("outputs").resolve("${shard.identifier}.json"),
                            database = database,
                            scope = scope,
                            scopeSha256 = scopeSha256,
                            inventory = inventory,
                            shard = shard.input,
                            artifact = shard.artifact,
                            limits = observationIngestionLimits(limits, authenticated.shards.size),
                        )
                        ObservationDatabase(shard.identifier, database, result)
                    }
            }
            val futures = executor.invokeAll(tasks)
            return futures.mapIndexed { index, future ->
                try {
                    future.get()
                } catch (failure: ExecutionException) {
                    val cause = failure.cause ?: failure
                    if (cause is FullTreeDataTruthException) throw cause
                    throw FullTreeDataTruthException(
                        "data observation shard ${authenticated.shards[index].identifier} ingestion failed",
                        cause,
                    )
                }
            }
        } finally {
            executor.shutdownNow()
        }
    }

    private fun observationIngestionLimits(
        limits: FullTreeDataTruthGenerationLimits,
        shardCount: Int,
    ): FullTreeDataObservationIngestionLimits = FullTreeDataObservationIngestionLimits(
        maximumInputBytes = limits.maximumObservationInputBytes,
        maximumDatabaseBytes = observationDatabaseBudget(limits, shardCount),
        maximumEntities = 50_000_000L,
        maximumTokens = 1_000_000_000L,
        maximumEntityBytes = limits.maximumEntityBytes,
        maximumEntityNodes = limits.maximumEntityNodes,
        maximumDepth = 128,
        maximumStringBytes = minOf(limits.maximumEntityBytes, 1024 * 1024),
        maximumTotalStringBytes = minOf(limits.maximumObservationInputBytes, 768L * 1024L * 1024L),
        maximumNumberCharacters = 256,
    )

    private fun observationDatabaseBudget(
        limits: FullTreeDataTruthGenerationLimits,
        shardCount: Int,
    ): Long {
        if (shardCount < 1) throw FullTreeDataTruthException("data observation shard population is empty")
        val available = limits.maximumScratchBytes - limits.maximumScratchDatabaseBytes
        val perShard = available / shardCount.toLong()
        if (perShard < SQLITE_PAGE_BYTES) {
            throw FullTreeDataTruthException("data observation SQLite population cannot fit the scratch bound")
        }
        return minOf(limits.maximumObservationDatabaseBytes, perShard)
    }

    private fun requireResidentMemoryBound(
        scope: JsonObject,
        workers: Int,
        limits: FullTreeDataTruthGenerationLimits,
    ) {
        val entityWorkingBytes = addExact(
            multiplyExact(limits.maximumEntityBytes.toLong(), 8L, "entity working byte"),
            multiplyExact(limits.maximumEntityNodes.toLong(), 128L, "entity-node working byte"),
            "entity working byte",
        )
        val ingestionBytes = multiplyExact(
            workers.toLong(),
            addExact(entityWorkingBytes, OBSERVATION_SQLITE_CACHE_BYTES, "ingestion working byte"),
            "parallel ingestion working byte",
        )
        val mergeBytes = listOf(
            multiplyExact(limits.maximumMergePopulationBytes, 8L, "merge population working byte"),
            multiplyExact(entityWorkingBytes, 2L, "merge entity working byte"),
            multiplyExact(limits.maximumControlArtifactBytes.toLong(), 4L, "control working byte"),
            multiplyExact(limits.maximumPartitions.toLong(), 512L, "partition-plan working byte"),
            TRUTH_SQLITE_CACHE_BYTES,
        ).fold(0L) { total, value -> addExact(total, value, "resident working byte") }
        val required = maxOf(ingestionBytes, mergeBytes)
        val authenticated = scope.requiredObject("bounds").requiredObject("wholeRun")
            .requiredLong("maximumResidentBytes")
        if (required > authenticated) {
            throw FullTreeDataTruthException(
                "data truth configured working set $required exceeds authenticated resident bound $authenticated",
            )
        }
    }

    private fun buildTruthDatabaseAndPartitions(
        database: Path,
        observations: List<ObservationDatabase>,
        authenticated: AuthenticatedObservationRun,
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        shardDirectory: Path,
        limits: FullTreeDataTruthGenerationLimits,
    ): TruthBuildResult {
        val unitToShard = inventory.requiredArray("units").objects("inventory unit")
            .associate { it.requiredString("id") to it.requiredString("shardId") }
        val oracle = JsonObject(
            mapOf(
                "configurationSha256" to JsonPrimitive(configurationSha256),
                "dataObservationIndexSha256" to JsonPrimitive(authenticated.indexSha256),
                "inventoryIndexSha256" to JsonPrimitive(inventory.requiredString("indexSha256")),
                "scopeSha256" to JsonPrimitive(scopeSha256),
            ),
        )
        DriverManager.getConnection(SqliteJdbcPaths.create(database)).use { connection ->
            configureTruthDatabase(connection, limits)
            connection.autoCommit = false
            try {
                createTruthSchema(connection)
                copyObservations(connection, observations, limits)
                requireDatabaseBound(connection, limits.maximumScratchDatabaseBytes)
                mergeObservations(connection, unitToShard, oracle, limits)
                validateMergedReferences(connection, limits)
                val plans = assignPartitions(connection, inventory, scope, limits)
                connection.commit()
                requireDatabaseBound(connection, limits.maximumScratchDatabaseBytes)
                val result = writeTruthPartitions(
                    connection,
                    plans,
                    oracle,
                    inventory,
                    scope,
                    shardDirectory,
                    limits,
                )
                requireTruthIndex(result.index, limits)
                return result
            } catch (failure: Throwable) {
                try {
                    connection.rollback()
                } catch (rollbackFailure: Throwable) {
                    failure.addSuppressed(rollbackFailure)
                }
                if (failure is FullTreeDataTruthException) throw failure
                throw FullTreeDataTruthException("cannot generate SQLite-backed data truth", failure)
            }
        }
    }

    private fun configureTruthDatabase(connection: Connection, limits: FullTreeDataTruthGenerationLimits) {
        connection.createStatement().use { statement ->
            statement.execute("PRAGMA journal_mode=OFF")
            statement.execute("PRAGMA synchronous=OFF")
            statement.execute("PRAGMA temp_store=MEMORY")
            statement.execute("PRAGMA cache_size=-16384")
            statement.execute("PRAGMA mmap_size=0")
            statement.execute("PRAGMA trusted_schema=OFF")
            statement.execute("PRAGMA page_size=$SQLITE_PAGE_BYTES")
            val pages = limits.maximumScratchDatabaseBytes / SQLITE_PAGE_BYTES +
                if (limits.maximumScratchDatabaseBytes % SQLITE_PAGE_BYTES == 0L) 0L else 1L
            statement.execute("PRAGMA max_page_count=$pages")
            statement.execute("PRAGMA application_id=$SQLITE_APPLICATION_ID")
            statement.execute("PRAGMA user_version=$SQLITE_SCHEMA_VERSION")
        }
    }

    private fun createTruthSchema(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.execute(
                """
                CREATE TABLE observations (
                    kind TEXT NOT NULL CHECK (kind IN ('global', 'type')),
                    identity TEXT NOT NULL,
                    observation_id TEXT PRIMARY KEY NOT NULL,
                    payload BLOB NOT NULL
                ) WITHOUT ROWID
                """.trimIndent(),
            )
            statement.execute("CREATE INDEX observations_identity ON observations(kind, identity, observation_id)")
            statement.execute(
                """
                CREATE TABLE type_targets (
                    die_offset TEXT PRIMARY KEY NOT NULL,
                    identity TEXT NOT NULL,
                    unit_id TEXT NOT NULL,
                    quality TEXT NOT NULL CHECK (
                        quality IN ('source-aligned', 'producer-declaration', 'producer-definition')
                    )
                ) WITHOUT ROWID
                """.trimIndent(),
            )
            statement.execute("CREATE INDEX type_targets_identity ON type_targets(identity, unit_id)")
            statement.execute(
                """
                CREATE TABLE merged (
                    kind TEXT NOT NULL CHECK (kind IN ('global', 'type')),
                    owner_shard TEXT NOT NULL,
                    identity TEXT NOT NULL,
                    canonical_id TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    partition_index INTEGER,
                    globals INTEGER NOT NULL,
                    types INTEGER NOT NULL,
                    unobservable_globals INTEGER NOT NULL,
                    unobservable_types INTEGER NOT NULL,
                    fields INTEGER NOT NULL,
                    bases INTEGER NOT NULL,
                    enumerators INTEGER NOT NULL,
                    resolved_type_references INTEGER NOT NULL,
                    unresolved_type_references INTEGER NOT NULL,
                    ambiguous_type_references INTEGER NOT NULL,
                    cross_shard_type_references INTEGER NOT NULL,
                    PRIMARY KEY (kind, identity),
                    UNIQUE (kind, canonical_id)
                ) WITHOUT ROWID
                """.trimIndent(),
            )
            statement.execute("CREATE INDEX merged_owner ON merged(owner_shard, kind, identity)")
        }
    }

    private fun copyObservations(
        connection: Connection,
        databases: List<ObservationDatabase>,
        limits: FullTreeDataTruthGenerationLimits,
    ) {
        val maximumDatabaseBytes = observationDatabaseBudget(limits, databases.size)
        connection.prepareStatement(
            "INSERT INTO observations(kind, identity, observation_id, payload) VALUES (?, ?, ?, ?)",
        ).use { insertObservation ->
            connection.prepareStatement(
                "INSERT INTO type_targets(die_offset, identity, unit_id, quality) VALUES (?, ?, ?, ?)",
            ).use { insertTarget ->
                databases.sortedBy { it.shardId }.forEach { database ->
                    requireObservationDatabaseFile(database, maximumDatabaseBytes)
                    val stateDigest = MessageDigest.getInstance("SHA-256")
                    DriverManager.getConnection(SqliteJdbcPaths.readOnly(database.path)).use { source ->
                        source.createStatement().use { statement ->
                            statement.execute("PRAGMA query_only=ON")
                            statement.execute("PRAGMA trusted_schema=OFF")
                            if (pragmaLong(statement, "application_id") != OBSERVATION_SQLITE_APPLICATION_ID.toLong() ||
                                pragmaLong(statement, "user_version") != OBSERVATION_SQLITE_SCHEMA_VERSION.toLong()
                            ) {
                                throw FullTreeDataTruthException("ingested data observation database identity differs")
                            }
                            statement.executeQuery("PRAGMA integrity_check").use { rows ->
                                if (!rows.next() || rows.getString(1) != "ok" || rows.next()) {
                                    throw FullTreeDataTruthException("ingested data observation database integrity failed")
                                }
                            }
                            statement.executeQuery("SELECT key, value FROM metadata ORDER BY key").use { rows ->
                                while (rows.next()) {
                                    digestField(stateDigest, "metadata".toByteArray(StandardCharsets.UTF_8))
                                    digestField(stateDigest, rows.getString(1).toByteArray(StandardCharsets.UTF_8))
                                    digestField(stateDigest, rows.getString(2).toByteArray(StandardCharsets.UTF_8))
                                }
                            }
                        }
                        source.createStatement().use { statement ->
                            statement.executeQuery(
                                "SELECT kind, id, unit_id, canonical_json FROM observations ORDER BY kind, id",
                            ).use { rows ->
                                var copied = 0L
                                while (rows.next()) {
                                    val kind = rows.getString(1)
                                    val observationId = rows.getString(2)
                                    val unitId = rows.getString(3)
                                    val payload = rows.getBytes(4)
                                    digestField(stateDigest, "observation".toByteArray(StandardCharsets.UTF_8))
                                    digestField(stateDigest, kind.toByteArray(StandardCharsets.UTF_8))
                                    digestField(stateDigest, observationId.toByteArray(StandardCharsets.UTF_8))
                                    digestField(stateDigest, unitId.toByteArray(StandardCharsets.UTF_8))
                                    digestField(stateDigest, payload)
                                    val item = parseCanonicalEntity(payload, limits)
                                    if (item.requiredString("id") != observationId || item.requiredString("unitId") != unitId) {
                                        throw FullTreeDataTruthException(
                                            "ingested data observation database identity is contradictory",
                                        )
                                    }
                                    val identity = when (kind) {
                                        "global" -> FullTreeDataTruthSemantics.globalIdentity(item, entityJsonLimits(limits))
                                        "type" -> FullTreeDataTruthSemantics.typeIdentity(item, entityJsonLimits(limits))
                                        else -> throw FullTreeDataTruthException("ingested observation kind is invalid")
                                    }
                                    insertObservation.setString(1, kind)
                                    insertObservation.setString(2, identity)
                                    insertObservation.setString(3, observationId)
                                    insertObservation.setBytes(4, payload)
                                    insertObservation.executeUpdate()
                                    if (kind == "type") {
                                        insertTarget.setString(1, item.requiredString("dieOffset"))
                                        insertTarget.setString(2, identity)
                                        insertTarget.setString(3, unitId)
                                        insertTarget.setString(4, typeTargetQuality(item))
                                        insertTarget.executeUpdate()
                                    }
                                    copied = addExact(copied, 1L, "copied observation")
                                }
                                if (copied != database.ingestion.globals + database.ingestion.types) {
                                    throw FullTreeDataTruthException(
                                        "ingested data observation database count is contradictory",
                                    )
                                }
                            }
                        }
                    }
                    if (stateDigest.digest().hex() != database.ingestion.stateSha256) {
                        throw FullTreeDataTruthException("ingested data observation logical state changed")
                    }
                    requireObservationDatabaseFile(database, maximumDatabaseBytes)
                    connection.commit()
                }
            }
        }
    }

    private fun pragmaLong(statement: java.sql.Statement, name: String): Long =
        statement.executeQuery("PRAGMA $name").use { rows ->
            if (!rows.next()) throw FullTreeDataTruthException("SQLite $name is unavailable")
            rows.getLong(1).also {
                if (rows.next()) throw FullTreeDataTruthException("SQLite $name is contradictory")
            }
        }

    private fun requireObservationDatabaseFile(database: ObservationDatabase, maximumBytes: Long) {
        val snapshot = readBoundedFileDigest(
            database.path,
            maximumBytes,
            READ_ONLY_FILE_PERMISSIONS,
            "ingested data observation database",
        )
        if (snapshot.sha256 != database.ingestion.databaseSha256) {
            throw FullTreeDataTruthException("ingested data observation database bytes changed")
        }
    }

    private fun readBoundedFileDigest(
        path: Path,
        maximumBytes: Long,
        expectedPermissions: Set<PosixFilePermission>,
        label: String,
    ): BoundedFileDigest {
        val before = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!before.isRegularFile || before.isSymbolicLink || before.fileKey() == null ||
            before.size() !in 1L..maximumBytes
        ) {
            throw FullTreeDataTruthException("$label is not a bounded identified file")
        }
        if (Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS) != expectedPermissions) {
            throw FullTreeDataTruthException("$label permissions differ")
        }
        val digest = MessageDigest.getInstance("SHA-256")
        var bytes = 0L
        FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
            val buffer = ByteBuffer.allocate(1024 * 1024)
            while (true) {
                buffer.clear()
                val read = channel.read(buffer)
                if (read < 0) break
                if (read == 0) continue
                bytes = addExact(bytes, read.toLong(), "bounded file byte")
                if (bytes > maximumBytes) {
                    throw FullTreeDataTruthException("$label exceeds its byte bound")
                }
                digest.update(buffer.array(), 0, read)
            }
            if (channel.size() != bytes) {
                throw FullTreeDataTruthException("$label changed size while read")
            }
        }
        val after = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (before.fileKey() != after.fileKey() || before.size() != after.size() ||
            before.lastModifiedTime() != after.lastModifiedTime()
        ) {
            throw FullTreeDataTruthException("$label changed identity while read")
        }
        if (bytes != before.size()) {
            throw FullTreeDataTruthException("$label byte count changed")
        }
        return BoundedFileDigest(bytes, digest.digest().hex(), before.fileKey())
    }

    private fun digestField(digest: MessageDigest, bytes: ByteArray) {
        digest.update(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(bytes.size.toLong()).array())
        digest.update(bytes)
    }

    private fun revokeCommittedFile(path: Path, expectedIdentity: Any, label: String) {
        val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() != expectedIdentity) {
            throw FullTreeDataTruthException("$label changed identity and was not deleted")
        }
        Files.delete(path)
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            throw FullTreeDataTruthException("$label could not be revoked")
        }
        forceDirectory(path.parent)
    }

    private fun typeTargetQuality(item: JsonObject): String {
        val declaration = item.requiredObject("declaration")
        return when {
            declaration.requiredElement("sourcePath") !is JsonNull ||
                declaration.requiredElement("externalPathSha256") !is JsonNull -> "source-aligned"
            item.requiredElement("declarationOnly").strictBoolean("declarationOnly") -> "producer-declaration"
            else -> "producer-definition"
        }
    }

    private fun mergeObservations(
        connection: Connection,
        unitToShard: Map<String, String>,
        oracle: JsonObject,
        limits: FullTreeDataTruthGenerationLimits,
    ) {
        var afterKind = ""
        var afterIdentity = ""
        connection.prepareStatement(
            """
            SELECT candidate.kind, candidate.identity FROM observations candidate
            WHERE (candidate.kind > ? OR (candidate.kind = ? AND candidate.identity > ?))
              AND candidate.observation_id = (
                  SELECT MIN(population.observation_id) FROM observations population
                  WHERE population.kind=candidate.kind AND population.identity=candidate.identity
              )
            ORDER BY candidate.kind, candidate.identity LIMIT 512
            """.trimIndent(),
        ).use { keys ->
            connection.prepareStatement(
                "SELECT payload FROM observations WHERE kind=? AND identity=? ORDER BY observation_id",
            ).use { population ->
                connection.prepareStatement(
                    """
                    SELECT target.identity,
                           (SELECT MIN(owner.unit_id) FROM type_targets owner
                            WHERE owner.identity=target.identity),
                           target.quality
                    FROM type_targets target WHERE target.die_offset=?
                    """.trimIndent(),
                ).use { targetLookup ->
                    connection.prepareStatement(INSERT_MERGED_SQL).use { insert ->
                        while (true) {
                            keys.setString(1, afterKind)
                            keys.setString(2, afterKind)
                            keys.setString(3, afterIdentity)
                            val batch = keys.executeQuery().use { rows ->
                                buildList {
                                    while (rows.next()) add(rows.getString(1) to rows.getString(2))
                                }
                            }
                            if (batch.isEmpty()) break
                            batch.forEach { (kind, identity) ->
                                val records = loadPopulation(population, kind, identity, limits)
                                val target: (String) -> FullTreeTypeTarget? = { offset ->
                                    targetLookup.setString(1, offset)
                                    targetLookup.executeQuery().use { rows ->
                                        if (!rows.next()) null else FullTreeTypeTarget(
                                            rows.getString(1),
                                            rows.getString(2),
                                            rows.getString(3),
                                        ).also {
                                            if (rows.next()) throw FullTreeDataTruthException(
                                                "DWARF target offset resolves to multiple canonical identities",
                                            )
                                        }
                                    }
                                }
                                val merged = when (kind) {
                                    "global" -> FullTreeDataTruthSemantics.mergeGlobalObservations(
                                        identity,
                                        records,
                                        target,
                                        unitToShard,
                                        entityJsonLimits(limits),
                                    )
                                    "type" -> FullTreeDataTruthSemantics.mergeTypeObservations(
                                        identity,
                                        records,
                                        target,
                                        unitToShard,
                                        entityJsonLimits(limits),
                                    )
                                    else -> throw FullTreeDataTruthException("observation merge kind is invalid")
                                }
                                val ownerUnit = merged.requiredString("ownerUnitId")
                                val ownerShard = unitToShard[ownerUnit]
                                    ?: throw FullTreeDataTruthException("merged observation owner is outside inventory")
                                val counts = TruthCounts.forEntity(kind, merged, ownerShard)
                                validateTruthEntitySchema(kind, merged, counts, oracle, ownerShard)
                                insertMerged(insert, kind, ownerShard, identity, merged, counts, limits)
                                afterKind = kind
                                afterIdentity = identity
                            }
                        }
                    }
                }
            }
        }
        connection.commit()
    }

    private fun loadPopulation(
        statement: PreparedStatement,
        kind: String,
        identity: String,
        limits: FullTreeDataTruthGenerationLimits,
    ): List<JsonObject> {
        statement.setString(1, kind)
        statement.setString(2, identity)
        return statement.executeQuery().use { rows ->
            val records = arrayListOf<JsonObject>()
            var bytes = 0L
            while (rows.next()) {
                if (records.size >= limits.maximumMergePopulationEntities) {
                    throw FullTreeDataTruthException("data truth merge population exceeds its entity bound")
                }
                val payload = rows.getBytes(1)
                bytes = addExact(bytes, payload.size.toLong(), "merge population byte")
                if (bytes > limits.maximumMergePopulationBytes) {
                    throw FullTreeDataTruthException("data truth merge population exceeds its byte bound")
                }
                records += parseCanonicalEntity(payload, limits)
            }
            records.ifEmpty { throw FullTreeDataTruthException("data truth merge population is empty") }
        }
    }

    private fun insertMerged(
        insert: PreparedStatement,
        kind: String,
        ownerShard: String,
        identity: String,
        merged: JsonObject,
        counts: TruthCounts,
        limits: FullTreeDataTruthGenerationLimits,
    ) {
        val payload = canonicalBytes(merged, limits.maximumEntityBytes)
        insert.setString(1, kind)
        insert.setString(2, ownerShard)
        insert.setString(3, identity)
        insert.setString(4, merged.requiredString("id"))
        insert.setBytes(5, payload)
        counts.bind(insert, 6)
        insert.executeUpdate()
    }

    private fun validateTruthEntitySchema(
        kind: String,
        entity: JsonObject,
        counts: TruthCounts,
        oracle: JsonObject,
        ownerShard: String,
    ) {
        val document = JsonObject(
            mapOf(
                "counts" to counts.toJson(),
                "globals" to if (kind == "global") JsonArray(listOf(entity)) else JsonArray(emptyList()),
                "oracle" to oracle,
                "schemaVersion" to JsonPrimitive(1),
                "shard" to JsonObject(mapOf("id" to JsonPrimitive(ownerShard), "unitIds" to JsonArray(emptyList()))),
                "types" to if (kind == "type") JsonArray(listOf(entity)) else JsonArray(emptyList()),
            ),
        )
        try {
            OracleSchemas.validate("full-tree-data-truth", document)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("merged data truth entity fails schema validation: ${failure.message}", failure)
        }
    }

    private fun validateMergedReferences(connection: Connection, limits: FullTreeDataTruthGenerationLimits) {
        connection.prepareStatement(
            "SELECT kind, owner_shard, payload FROM merged ORDER BY kind, identity",
        ).use { entities ->
            connection.prepareStatement(
                "SELECT owner_shard FROM merged WHERE kind='type' AND canonical_id=?",
            ).use { ownerLookup ->
                entities.executeQuery().use { rows ->
                    while (rows.next()) {
                        val kind = rows.getString(1)
                        val ownerShard = rows.getString(2)
                        val item = parseCanonicalEntity(rows.getBytes(3), limits)
                        truthReferences(kind, item).forEach { reference ->
                            validateTruthReference(reference, ownerShard, ownerLookup, limits)
                        }
                    }
                }
            }
        }
    }

    private fun validateTruthReference(
        reference: JsonObject,
        ownerShard: String,
        ownerLookup: PreparedStatement,
        limits: FullTreeDataTruthGenerationLimits,
    ) {
        val candidateFields = listOf("candidateTargetCount", "candidateTargets", "candidateTargetsSha256")
        val evidenceFields = listOf("evidenceDieOffsetCount", "evidenceDieOffsetsSha256")
        if (candidateFields.map(reference::containsKey).distinct().size != 1) {
            throw FullTreeDataTruthException("type reference candidate commitment is incomplete")
        }
        if (evidenceFields.map(reference::containsKey).distinct().size != 1) {
            throw FullTreeDataTruthException("type reference evidence commitment is incomplete")
        }
        val candidates = (reference["candidateTargets"] as? JsonArray ?: JsonArray(emptyList()))
            .objects("type reference candidate")
        val candidateCount = reference["candidateTargetCount"]?.let { element ->
            JsonObject(mapOf("value" to element)).requiredLong("value")
        } ?: candidates.size.toLong()
        val evidence = reference.requiredArray("evidenceDieOffsets")
        val evidenceCount = reference["evidenceDieOffsetCount"]?.let { element ->
            JsonObject(mapOf("value" to element)).requiredLong("value")
        } ?: evidence.size.toLong()
        if (candidateCount < candidates.size || evidenceCount < evidence.size) {
            throw FullTreeDataTruthException("type reference sample exceeds its committed count")
        }
        reference["candidateTargetsSha256"]?.requiredString("candidate commitment")?.let { commitment ->
            if (candidateCount == candidates.size.toLong() &&
                commitment != FullTreeDataTruthSemantics.canonicalSha256(
                    JsonArray(candidates),
                    entityJsonLimits(limits),
                )
            ) {
                throw FullTreeDataTruthException("type reference candidate commitment differs")
            }
        }
        reference["evidenceDieOffsetsSha256"]?.requiredString("evidence commitment")?.let { commitment ->
            if (evidenceCount == evidence.size.toLong() &&
                commitment != FullTreeDataTruthSemantics.canonicalSha256(evidence, entityJsonLimits(limits))
            ) {
                throw FullTreeDataTruthException("type reference evidence commitment differs")
            }
        }
        candidates.forEach { candidate ->
            val targetId = candidate.requiredString("targetTypeId")
            val targetOwner = candidate.requiredString("targetOwnerShardId")
            if (lookupTypeOwner(ownerLookup, targetId) != targetOwner) {
                throw FullTreeDataTruthException("type reference candidate has a dangling or substituted owner")
            }
        }
        val target = reference.requiredElement("targetTypeId").nullableStrictString("targetTypeId")
        val targetOwner = reference.requiredElement("targetOwnerShardId").nullableStrictString("targetOwnerShardId")
        val reason = reference.requiredElement("reasonCode")
        if (target == null) {
            if (targetOwner != null || reason is JsonNull) {
                throw FullTreeDataTruthException("unresolved type reference has contradictory evidence")
            }
            if (reference.requiredString("resolutionCode") == "unresolved-authenticated-target-set" &&
                (candidateCount < 2L || !candidateFields.all(reference::containsKey))
            ) {
                throw FullTreeDataTruthException("ambiguous type reference has incomplete candidate evidence")
            }
        } else {
            if (reason !is JsonNull || lookupTypeOwner(ownerLookup, target) != targetOwner) {
                throw FullTreeDataTruthException("type reference has a dangling or substituted owner")
            }
            if (candidates.isNotEmpty() && candidates.none {
                    it.requiredString("targetTypeId") == target &&
                        it.requiredString("targetOwnerShardId") == targetOwner
                }
            ) {
                throw FullTreeDataTruthException("resolved type reference is absent from candidate evidence")
            }
        }
        if (targetOwner != null && targetOwner != ownerShard) {
            // Counted as cross-shard by [TruthCounts]; lookup above proves this is a real owner.
        }
    }

    private fun lookupTypeOwner(statement: PreparedStatement, targetId: String): String? {
        statement.setString(1, targetId)
        return statement.executeQuery().use { rows ->
            if (!rows.next()) null else rows.getString(1).also {
                if (rows.next()) throw FullTreeDataTruthException("canonical type identity is duplicated")
            }
        }
    }

    private fun assignPartitions(
        connection: Connection,
        inventory: JsonObject,
        scope: JsonObject,
        limits: FullTreeDataTruthGenerationLimits,
    ): List<PartitionPlan> {
        val perShard = scope.requiredObject("bounds").requiredObject("perShard")
        val entityLimit = perShard.requiredLong("entities")
        val serializedLimit = perShard.requiredLong("serializedBytes")
        val partitionBudget = serializedLimit -
            (serializedLimit / 3L + if (serializedLimit % 3L == 0L) 0L else 1L)
        if (partitionBudget < 1L) throw FullTreeDataTruthException("data truth partition budget is invalid")
        val plans = arrayListOf<PartitionPlan>()
        connection.prepareStatement(
            """
            SELECT kind, identity, length(payload), globals, types, unobservable_globals,
                   unobservable_types, fields, bases, enumerators, resolved_type_references,
                   unresolved_type_references, ambiguous_type_references, cross_shard_type_references
            FROM merged WHERE owner_shard=? ORDER BY kind, identity
            """.trimIndent(),
        ).use { select ->
            connection.prepareStatement(
                "UPDATE merged SET partition_index=? WHERE kind=? AND identity=?",
            ).use { update ->
                inventory.requiredArray("shards").objects("inventory shard").forEach { shard ->
                    val shardId = shard.requiredString("id")
                    select.setString(1, shardId)
                    select.executeQuery().use { rows ->
                        var current = PartitionPlan(shardId, 0, TruthCounts(), 0L)
                        var hasRows = false
                        while (rows.next()) {
                            hasRows = true
                            val itemBytes = addExact(rows.getLong(3), 1L, "partition entity byte")
                            val counts = TruthCounts.fromResultSet(rows, 4)
                            val exceedsBytes = addExact(
                                current.estimatedEntityBytes,
                                itemBytes,
                                "partition estimate",
                            ) > partitionBudget
                            val exceedsEntities = addExact(
                                current.counts.entities,
                                counts.entities,
                                "partition entity",
                            ) > entityLimit
                            if (current.counts.entities > 0L && (exceedsBytes || exceedsEntities)) {
                                requirePartitionBound(current, entityLimit)
                                plans += current
                                if (plans.size >= limits.maximumPartitions) {
                                    throw FullTreeDataTruthException("data truth exceeds its partition-count bound")
                                }
                                current = PartitionPlan(shardId, current.index + 1, TruthCounts(), 0L)
                            }
                            current.counts.add(counts)
                            current.estimatedEntityBytes = addExact(
                                current.estimatedEntityBytes,
                                itemBytes,
                                "partition estimate",
                            )
                            update.setInt(1, current.index)
                            update.setString(2, rows.getString(1))
                            update.setString(3, rows.getString(2))
                            update.executeUpdate()
                        }
                        if (!hasRows) current = PartitionPlan(shardId, 0, TruthCounts(), 0L)
                        requirePartitionBound(current, entityLimit)
                        plans += current
                        if (plans.size > limits.maximumPartitions) {
                            throw FullTreeDataTruthException("data truth exceeds its partition-count bound")
                        }
                    }
                }
            }
        }
        return Collections.unmodifiableList(plans)
    }

    private fun requirePartitionBound(plan: PartitionPlan, maximumEntities: Long) {
        if (plan.counts.entities > maximumEntities) {
            throw FullTreeDataTruthException(
                "data truth shard ${plan.shardId} partition ${plan.index} exceeds its entity bound",
            )
        }
    }

    private fun writeTruthPartitions(
        connection: Connection,
        plans: List<PartitionPlan>,
        oracle: JsonObject,
        inventory: JsonObject,
        scope: JsonObject,
        shardDirectory: Path,
        limits: FullTreeDataTruthGenerationLimits,
    ): TruthBuildResult {
        val perShardBytes = scope.requiredObject("bounds").requiredObject("perShard").requiredLong("serializedBytes")
        val wholeRun = scope.requiredObject("bounds").requiredObject("wholeRun")
        val wholeRunBytes = wholeRun.requiredLong("serializedBytes")
        val inventoryById = inventory.requiredArray("shards").objects("inventory shard")
            .associateBy { it.requiredString("id") }
        val totals = plans.groupingBy { it.shardId }.eachCount()
        val positions = hashMapOf<String, Int>()
        val records = arrayListOf<JsonObject>()
        val aggregate = TruthCounts()
        var outputBytes = 0L
        connection.prepareStatement(
            "SELECT payload FROM merged WHERE owner_shard=? AND partition_index=? AND kind=? ORDER BY identity",
        ).use { entities ->
            plans.forEach { plan ->
                val position = positions.getOrDefault(plan.shardId, 0)
                positions[plan.shardId] = position + 1
                if (position != plan.index) throw FullTreeDataTruthException("data truth partition order is contradictory")
                val total = totals.getValue(plan.shardId)
                val relative = if (total == 1) {
                    "${plan.shardId}.json"
                } else {
                    "${plan.shardId}.part-${position.toString().padStart(3, '0')}.json"
                }
                val inventoryShard = inventoryById.getValue(plan.shardId)
                val shardBinding = linkedMapOf<String, JsonElement>(
                    "id" to JsonPrimitive(plan.shardId),
                    "unitIds" to inventoryShard.requiredArray("unitIds"),
                )
                if (total > 1) {
                    shardBinding["partition"] = JsonObject(
                        mapOf("index" to JsonPrimitive(position), "total" to JsonPrimitive(total)),
                    )
                }
                val shard = JsonObject(shardBinding)
                validateTruthEnvelope(plan.counts, oracle, shard)
                val remainingOutputBytes = wholeRunBytes - outputBytes
                if (remainingOutputBytes < 1L) {
                    throw FullTreeDataTruthException("data truth exceeds its whole-run output bound")
                }
                val written = writeTruthDocument(
                    connection,
                    entities,
                    shardDirectory.resolve(relative),
                    plan,
                    oracle,
                    shard,
                    minOf(perShardBytes, remainingOutputBytes),
                    limits,
                )
                outputBytes = addExact(outputBytes, written.bytes, "truth output byte")
                aggregate.add(plan.counts)
                records += JsonObject(
                    linkedMapOf<String, JsonElement>(
                        "id" to JsonPrimitive(plan.shardId),
                        "path" to JsonPrimitive("shards/$relative"),
                        "bytes" to JsonPrimitive(written.bytes),
                        "sha256" to JsonPrimitive(written.sha256),
                    ).apply { putAll(plan.counts.toJson()) },
                )
            }
        }
        if (aggregate.entities > wholeRun.requiredLong("entities")) {
            throw FullTreeDataTruthException("data truth exceeds its whole-run entity bound")
        }
        if (outputBytes > wholeRunBytes) {
            throw FullTreeDataTruthException("data truth exceeds its whole-run output bound")
        }
        val withoutHash = JsonObject(
            mapOf(
                "complete" to JsonPrimitive(true),
                "counts" to aggregate.toJson(),
                "oracle" to oracle,
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(records),
            ),
        )
        val indexSha256 = FullTreeDataTruthSemantics.canonicalSha256(
            withoutHash,
            controlJsonLimits(limits),
        )
        return TruthBuildResult(
            index = JsonObject(withoutHash.toMutableMap().apply {
                this["indexSha256"] = JsonPrimitive(indexSha256)
            }),
            partitionCount = plans.size,
            outputBytes = outputBytes,
        )
    }

    private fun validateTruthEnvelope(counts: TruthCounts, oracle: JsonObject, shard: JsonObject) {
        val document = JsonObject(
            mapOf(
                "counts" to counts.toJson(),
                "globals" to JsonArray(emptyList()),
                "oracle" to oracle,
                "schemaVersion" to JsonPrimitive(1),
                "shard" to shard,
                "types" to JsonArray(emptyList()),
            ),
        )
        try {
            OracleSchemas.validate("full-tree-data-truth", document)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data truth partition envelope fails schema validation", failure)
        }
    }

    private fun writeTruthDocument(
        connection: Connection,
        entities: PreparedStatement,
        target: Path,
        plan: PartitionPlan,
        oracle: JsonObject,
        shard: JsonObject,
        maximumBytes: Long,
        limits: FullTreeDataTruthGenerationLimits,
    ): WrittenArtifact {
        val temporary = Files.createTempFile(target.parent, ".${target.fileName}.", ".partial")
        var committed = false
        try {
            Files.setPosixFilePermissions(temporary, PRIVATE_FILE_PERMISSIONS)
            val digest = MessageDigest.getInstance("SHA-256")
            val bounded = BoundedOutputStream(
                BufferedOutputStream(
                    DigestOutputStream(
                        Files.newOutputStream(
                            temporary,
                            StandardOpenOption.WRITE,
                            StandardOpenOption.TRUNCATE_EXISTING,
                            LinkOption.NOFOLLOW_LINKS,
                        ),
                        digest,
                    ),
                ),
                maximumBytes,
            )
            bounded.use { output ->
                val writer = CanonicalTruthWriter(output)
                writer.startObject()
                writer.field("counts")
                writer.value(canonicalBytes(plan.counts.toJson(), limits.maximumControlArtifactBytes), 2, false)
                writer.field("globals")
                writer.startArray()
                streamPartitionEntities(entities, plan, "global") { writer.arrayValue(it) }
                writer.endArray()
                writer.field("oracle")
                writer.value(canonicalBytes(oracle, limits.maximumControlArtifactBytes), 2, false)
                writer.field("schemaVersion")
                writer.value(canonicalBytes(JsonPrimitive(1), limits.maximumControlArtifactBytes), 2, false)
                writer.field("shard")
                writer.value(canonicalBytes(shard, limits.maximumControlArtifactBytes), 2, false)
                writer.field("types")
                writer.startArray()
                streamPartitionEntities(entities, plan, "type") { writer.arrayValue(it) }
                writer.endArray()
                writer.endObject()
            }
            FileChannel.open(temporary, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS).use { it.force(true) }
            Files.setPosixFilePermissions(temporary, READ_ONLY_FILE_PERMISSIONS)
            val expected = readBoundedFileDigest(
                temporary,
                maximumBytes,
                READ_ONLY_FILE_PERMISSIONS,
                "temporary data truth partition",
            )
            val streamedSha256 = digest.digest().hex()
            if (expected.bytes != bounded.count || expected.sha256 != streamedSha256) {
                throw FullTreeDataTruthException("temporary data truth partition stream binding differs")
            }
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                throw FullTreeDataTruthException("data truth partition target already exists")
            }
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE)
            } catch (failure: AtomicMoveNotSupportedException) {
                throw FullTreeDataTruthException("atomic truth partition publication is unavailable", failure)
            }
            try {
                val published = readBoundedFileDigest(
                    target,
                    maximumBytes,
                    READ_ONLY_FILE_PERMISSIONS,
                    "published data truth partition",
                )
                if (published.identity != expected.identity || published.bytes != expected.bytes ||
                    published.sha256 != expected.sha256
                ) {
                    throw FullTreeDataTruthException("published data truth partition binding differs")
                }
                forceDirectory(target.parent)
            } catch (failure: Throwable) {
                try {
                    revokeCommittedFile(target, expected.identity, "unverified data truth partition")
                } catch (revocationFailure: Throwable) {
                    failure.addSuppressed(revocationFailure)
                }
                throw FullTreeDataTruthException("data truth partition publication failed and was revoked", failure)
            }
            committed = true
            return WrittenArtifact(expected.bytes, expected.sha256)
        } finally {
            if (!committed) Files.deleteIfExists(temporary)
        }
    }

    private fun streamPartitionEntities(
        statement: PreparedStatement,
        plan: PartitionPlan,
        kind: String,
        consume: (ByteArray) -> Unit,
    ) {
        statement.setString(1, plan.shardId)
        statement.setInt(2, plan.index)
        statement.setString(3, kind)
        statement.executeQuery().use { rows ->
            var count = 0L
            while (rows.next()) {
                consume(rows.getBytes(1))
                count++
            }
            val expected = if (kind == "global") plan.counts.globals else plan.counts.types
            if (count != expected) throw FullTreeDataTruthException("data truth partition entity count changed")
        }
    }

    private fun requireTruthIndex(index: JsonObject, limits: FullTreeDataTruthGenerationLimits) {
        try {
            OracleSchemas.validate("full-tree-data-truth-index", index)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data truth index fails schema validation: ${failure.message}", failure)
        }
        val withoutHash = JsonObject(index.filterKeys { it != "indexSha256" })
        if (index.requiredString("indexSha256") !=
            FullTreeDataTruthSemantics.canonicalSha256(withoutHash, controlJsonLimits(limits))
        ) {
            throw FullTreeDataTruthException("data truth index hash does not reconcile")
        }
    }

    private fun verifyTruthPublication(
        root: Path,
        index: JsonObject,
        indexBytes: ByteArray,
        scope: JsonObject,
        limits: FullTreeDataTruthGenerationLimits,
    ) {
        val expectedIndexSha256 = OracleArtifacts.sha256(indexBytes)
        val indexFile = readBoundedFileDigest(
            root.resolve("index.json"),
            limits.maximumControlArtifactBytes.toLong(),
            READ_ONLY_FILE_PERMISSIONS,
            "published data truth index",
        )
        if (indexFile.bytes != indexBytes.size.toLong() || indexFile.sha256 != expectedIndexSha256) {
            throw FullTreeDataTruthException("published data truth index binding differs")
        }
        val shardRoot = root.resolve("shards").normalize()
        val maximumShardBytes = scope.requiredObject("bounds").requiredObject("perShard")
            .requiredLong("serializedBytes")
        val maximumRunBytes = scope.requiredObject("bounds").requiredObject("wholeRun")
            .requiredLong("serializedBytes")
        val seenPaths = hashSetOf<Path>()
        val expectedPaths = hashSetOf(root, root.resolve("index.json"), shardRoot)
        var totalBytes = 0L
        index.requiredArray("shards").objects("published truth shard").forEach { record ->
            val relative = Path.of(record.requiredString("path"))
            if (relative.isAbsolute || relative.normalize() != relative || relative.nameCount != 2 ||
                relative.getName(0).toString() != "shards"
            ) {
                throw FullTreeDataTruthException("published data truth partition path is unsafe")
            }
            val path = root.resolve(relative).normalize()
            if (!path.startsWith(shardRoot) || !seenPaths.add(path)) {
                throw FullTreeDataTruthException("published data truth partition path is duplicated or escapes")
            }
            expectedPaths.add(path)
            val expectedBytes = record.requiredLong("bytes")
            if (expectedBytes !in 1L..maximumShardBytes) {
                throw FullTreeDataTruthException("published data truth partition byte binding is invalid")
            }
            val file = readBoundedFileDigest(
                path,
                maximumShardBytes,
                READ_ONLY_FILE_PERMISSIONS,
                "published data truth partition",
            )
            if (file.bytes != expectedBytes || file.sha256 != record.requiredString("sha256")) {
                throw FullTreeDataTruthException("published data truth partition binding differs")
            }
            totalBytes = addExact(totalBytes, file.bytes, "published truth byte")
            if (totalBytes > maximumRunBytes) {
                throw FullTreeDataTruthException("published data truth exceeds its whole-run byte bound")
            }
        }
        val actualPaths = hashSetOf<Path>()
        Files.walk(root).use { paths ->
            paths.forEach { path ->
                val normalized = path.toAbsolutePath().normalize()
                if (!actualPaths.add(normalized) || normalized !in expectedPaths) {
                    throw FullTreeDataTruthException("published data truth tree contains an unindexed path")
                }
                val attributes = Files.readAttributes(
                    normalized,
                    BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                )
                if (attributes.isSymbolicLink ||
                    (normalized in setOf(root, shardRoot) && !attributes.isDirectory) ||
                    (normalized !in setOf(root, shardRoot) && !attributes.isRegularFile)
                ) {
                    throw FullTreeDataTruthException("published data truth tree has an invalid path type")
                }
            }
        }
        if (actualPaths != expectedPaths) {
            throw FullTreeDataTruthException("published data truth tree membership is incomplete")
        }
    }

    private fun requireDatabaseBound(connection: Connection, maximumBytes: Long) {
        val pageCount = connection.createStatement().use { statement ->
            statement.executeQuery("PRAGMA page_count").use { rows ->
                if (!rows.next()) throw FullTreeDataTruthException("SQLite page count is unavailable")
                rows.getLong(1)
            }
        }
        val pageSize = connection.createStatement().use { statement ->
            statement.executeQuery("PRAGMA page_size").use { rows ->
                if (!rows.next()) throw FullTreeDataTruthException("SQLite page size is unavailable")
                rows.getLong(1)
            }
        }
        if (pageCount < 0L || pageSize <= 0L || pageCount > maximumBytes / pageSize) {
            throw FullTreeDataTruthException("data truth SQLite database exceeds its byte bound")
        }
    }

    private fun parseCanonicalEntity(
        bytes: ByteArray,
        limits: FullTreeDataTruthGenerationLimits,
    ): JsonObject {
        if (bytes.size > limits.maximumEntityBytes) {
            throw FullTreeDataTruthException("data truth entity exceeds its byte bound")
        }
        return try {
            OracleJson.parseCanonical(bytes, entityJsonLimits(limits)) as? JsonObject
                ?: throw FullTreeDataTruthException("data truth entity must be an object")
        } catch (failure: FullTreeDataTruthException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data truth entity is not strict canonical JSON", failure)
        }
    }

    private fun entityJsonLimits(limits: FullTreeDataTruthGenerationLimits): StrictJsonLimits = StrictJsonLimits(
        maximumInputBytes = limits.maximumEntityBytes,
        maximumCanonicalBytes = limits.maximumEntityBytes,
        maximumDepth = 128,
        maximumNodes = limits.maximumEntityNodes,
        maximumStringBytes = minOf(limits.maximumEntityBytes, 1024 * 1024),
        maximumTotalStringBytes = limits.maximumEntityBytes,
        maximumNumberCharacters = 256,
    )

    private fun controlJsonLimits(limits: FullTreeDataTruthGenerationLimits): StrictJsonLimits = StrictJsonLimits(
        maximumInputBytes = limits.maximumControlArtifactBytes,
        maximumCanonicalBytes = limits.maximumControlArtifactBytes,
        maximumDepth = 128,
        maximumNodes = 1_000_000,
        maximumStringBytes = minOf(limits.maximumControlArtifactBytes, 1024 * 1024),
        maximumTotalStringBytes = limits.maximumControlArtifactBytes,
        maximumNumberCharacters = 256,
    )

    private fun truthReferences(kind: String, entity: JsonObject): List<JsonObject> = when (kind) {
        "global" -> listOf(entity.requiredObject("typeReference"))
        "type" -> entity.requiredArray("members").objects("truth member").map { it.requiredObject("typeReference") }
        else -> throw FullTreeDataTruthException("truth entity kind is invalid")
    }

    private fun readCanonicalObject(path: Path, maximumBytes: Int): CanonicalObject {
        val snapshot = try {
            OracleArtifacts.read(path, OracleArtifactLimits(maximumBytes))
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("cannot read bounded oracle control artifact: $path", failure)
        }
        val document = try {
            OracleJson.parseCanonical(
                snapshot.bytes,
                StrictJsonLimits(
                    maximumInputBytes = maximumBytes,
                    maximumCanonicalBytes = maximumBytes,
                    maximumDepth = 128,
                    maximumNodes = 1_000_000,
                    maximumStringBytes = minOf(maximumBytes, 1024 * 1024),
                    maximumTotalStringBytes = maximumBytes,
                    maximumNumberCharacters = 256,
                ),
            ) as? JsonObject
                ?: throw FullTreeDataTruthException("oracle control artifact must be a JSON object")
        } catch (failure: FullTreeDataTruthException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("oracle control artifact is not strict canonical JSON: $path", failure)
        }
        return CanonicalObject(document, snapshot.bytes)
    }

    private fun canonicalBytes(element: JsonElement, maximumBytes: Int): ByteArray = OracleJson.canonicalBytes(
        element,
        StrictJsonLimits(
            maximumInputBytes = maximumBytes,
            maximumCanonicalBytes = maximumBytes,
            maximumDepth = 128,
            maximumNodes = 1_000_000,
            maximumStringBytes = minOf(maximumBytes, 1024 * 1024),
            maximumTotalStringBytes = maximumBytes,
            maximumNumberCharacters = 256,
        ),
    )

    private fun requireRealDirectory(path: Path, label: String): Path {
        val absolute = path.toAbsolutePath().normalize()
        val real = try {
            absolute.toRealPath()
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("$label is unavailable", failure)
        }
        if (real != absolute) throw FullTreeDataTruthException("$label path contains a symbolic link")
        val attributes = Files.readAttributes(real, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
            throw FullTreeDataTruthException("$label must be an identified real directory")
        }
        requireTrustedDirectory(real, label)
        return real
    }

    private fun requireTrustedDirectory(path: Path, label: String) {
        val permissions = Files.getFileAttributeView(
            path,
            PosixFileAttributeView::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )?.readAttributes()?.permissions()
            ?: throw FullTreeDataTruthException("$label requires POSIX permissions")
        if (PosixFilePermission.GROUP_WRITE in permissions || PosixFilePermission.OTHERS_WRITE in permissions) {
            throw FullTreeDataTruthException("$label is writable by an untrusted principal")
        }
    }

    private fun requireScratchBound(root: Path, maximumBytes: Long) {
        var total = 0L
        Files.walk(root).use { paths ->
            paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }.forEach { path ->
                total = addExact(total, Files.size(path), "scratch byte")
                if (total > maximumBytes) throw FullTreeDataTruthException("data truth scratch exceeds its byte bound")
            }
        }
    }

    private fun requireSha256(value: String, label: String) {
        if (!value.matches(Regex("[0-9a-f]{64}"))) throw FullTreeDataTruthException("$label digest is invalid")
    }

    private fun addExact(left: Long, right: Long, label: String): Long = try {
        Math.addExact(left, right)
    } catch (failure: ArithmeticException) {
        throw FullTreeDataTruthException("data truth $label count exceeds the supported range", failure)
    }

    private fun multiplyExact(left: Long, right: Long, label: String): Long = try {
        Math.multiplyExact(left, right)
    } catch (failure: ArithmeticException) {
        throw FullTreeDataTruthException("data truth $label count exceeds the supported range", failure)
    }

    private fun ByteArray.hex(): String = joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }

    private fun JsonElement.strictBoolean(label: String): Boolean {
        val primitive = this as? JsonPrimitive
            ?: throw FullTreeDataTruthException("$label is not a Boolean")
        return primitive.booleanOrNull
            ?: throw FullTreeDataTruthException("$label is not a Boolean")
    }

    private fun JsonElement.nullableStrictString(label: String): String? = when (this) {
        JsonNull -> null
        else -> requiredString(label)
    }

    private data class CanonicalObject(val document: JsonObject, val bytes: ByteArray)

    private data class AuthenticatedObservationShard(
        val identifier: String,
        val input: FullTreeDataObservationShardInput,
        val artifact: FullTreeDataObservationArtifactBinding,
    )

    private data class AuthenticatedObservationRun(
        val root: Path,
        val maximumWorkers: Int,
        val indexSha256: String,
        val shards: List<AuthenticatedObservationShard>,
    )

    private data class ObservationDatabase(
        val shardId: String,
        val path: Path,
        val ingestion: FullTreeDataObservationIngestion,
    )

    private data class TruthBuildResult(
        val index: JsonObject,
        val partitionCount: Int,
        val outputBytes: Long,
    )

    private data class WrittenArtifact(val bytes: Long, val sha256: String)

    private data class BoundedFileDigest(val bytes: Long, val sha256: String, val identity: Any)

    private data class PartitionPlan(
        val shardId: String,
        val index: Int,
        val counts: TruthCounts,
        var estimatedEntityBytes: Long,
    )

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
            get() = checkedAdd(globals, types, "entity")

        fun add(other: TruthCounts) {
            globals = checkedAdd(globals, other.globals, "global")
            types = checkedAdd(types, other.types, "type")
            unobservableGlobals = checkedAdd(
                unobservableGlobals,
                other.unobservableGlobals,
                "unobservable global",
            )
            unobservableTypes = checkedAdd(unobservableTypes, other.unobservableTypes, "unobservable type")
            fields = checkedAdd(fields, other.fields, "field")
            bases = checkedAdd(bases, other.bases, "base")
            enumerators = checkedAdd(enumerators, other.enumerators, "enumerator")
            resolvedTypeReferences = checkedAdd(
                resolvedTypeReferences,
                other.resolvedTypeReferences,
                "resolved type reference",
            )
            unresolvedTypeReferences = checkedAdd(
                unresolvedTypeReferences,
                other.unresolvedTypeReferences,
                "unresolved type reference",
            )
            ambiguousTypeReferences = checkedAdd(
                ambiguousTypeReferences,
                other.ambiguousTypeReferences,
                "ambiguous type reference",
            )
            crossShardTypeReferences = checkedAdd(
                crossShardTypeReferences,
                other.crossShardTypeReferences,
                "cross-shard type reference",
            )
        }

        fun bind(statement: PreparedStatement, start: Int) {
            values().forEachIndexed { offset, value -> statement.setLong(start + offset, value) }
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

        private fun values(): List<Long> = listOf(
            globals,
            types,
            unobservableGlobals,
            unobservableTypes,
            fields,
            bases,
            enumerators,
            resolvedTypeReferences,
            unresolvedTypeReferences,
            ambiguousTypeReferences,
            crossShardTypeReferences,
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
                                "field" -> result.fields = checkedAdd(result.fields, 1L, "field")
                                "base" -> result.bases = checkedAdd(result.bases, 1L, "base")
                                "enumerator" -> result.enumerators = checkedAdd(result.enumerators, 1L, "enumerator")
                                else -> throw FullTreeDataTruthException("truth entity member kind is invalid")
                            }
                        }
                    }
                    else -> throw FullTreeDataTruthException("truth entity kind is invalid")
                }
                truthReferences(kind, entity).forEach { reference ->
                    if (reference.requiredElement("targetTypeId") is JsonNull) {
                        result.unresolvedTypeReferences = checkedAdd(
                            result.unresolvedTypeReferences,
                            1L,
                            "unresolved type reference",
                        )
                    } else {
                        result.resolvedTypeReferences = checkedAdd(
                            result.resolvedTypeReferences,
                            1L,
                            "resolved type reference",
                        )
                    }
                    if (reference.requiredString("resolutionCode") == "unresolved-authenticated-target-set") {
                        result.ambiguousTypeReferences = checkedAdd(
                            result.ambiguousTypeReferences,
                            1L,
                            "ambiguous type reference",
                        )
                    }
                    val targetOwner = reference.requiredElement("targetOwnerShardId")
                        .nullableStrictString("targetOwnerShardId")
                    if (targetOwner != null && targetOwner != ownerShard) {
                        result.crossShardTypeReferences = checkedAdd(
                            result.crossShardTypeReferences,
                            1L,
                            "cross-shard type reference",
                        )
                    }
                }
                return result
            }

            fun fromResultSet(rows: ResultSet, start: Int): TruthCounts = TruthCounts(
                globals = rows.getLong(start),
                types = rows.getLong(start + 1),
                unobservableGlobals = rows.getLong(start + 2),
                unobservableTypes = rows.getLong(start + 3),
                fields = rows.getLong(start + 4),
                bases = rows.getLong(start + 5),
                enumerators = rows.getLong(start + 6),
                resolvedTypeReferences = rows.getLong(start + 7),
                unresolvedTypeReferences = rows.getLong(start + 8),
                ambiguousTypeReferences = rows.getLong(start + 9),
                crossShardTypeReferences = rows.getLong(start + 10),
            )

            private fun checkedAdd(left: Long, right: Long, label: String): Long = try {
                Math.addExact(left, right)
            } catch (failure: ArithmeticException) {
                throw FullTreeDataTruthException("data truth $label count exceeds the supported range", failure)
            }
        }
    }

    private class BoundedOutputStream(output: OutputStream, private val maximumBytes: Long) :
        FilterOutputStream(output) {
        var count: Long = 0L
            private set

        override fun write(value: Int) {
            requireCapacity(1L)
            out.write(value)
            count++
        }

        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            if (offset < 0 || length < 0 || offset > bytes.size - length) {
                throw IndexOutOfBoundsException()
            }
            requireCapacity(length.toLong())
            out.write(bytes, offset, length)
            count += length.toLong()
        }

        private fun requireCapacity(additional: Long) {
            if (count > maximumBytes - additional) {
                throw FullTreeDataTruthException("canonical data truth JSON exceeds its byte limit")
            }
        }
    }

    private class CanonicalTruthWriter(private val output: OutputStream) {
        private var fields = 0
        private var arrayValues = 0
        private var finished = false

        fun startObject() = writeAscii("{\n")

        fun field(name: String) {
            if (finished) throw FullTreeDataTruthException("canonical data truth writer is already finished")
            if (fields++ > 0) writeAscii(",\n")
            writeSpaces(2)
            writeAscii("\"$name\": ")
        }

        fun value(canonicalBytes: ByteArray, indentation: Int, indentFirst: Boolean) =
            writeCanonicalValue(canonicalBytes, indentation, indentFirst)

        fun startArray() {
            arrayValues = 0
        }

        fun arrayValue(canonicalBytes: ByteArray) {
            if (arrayValues++ == 0) writeAscii("[\n") else writeAscii(",\n")
            writeCanonicalValue(canonicalBytes, indentation = 4, indentFirst = true)
        }

        fun endArray() {
            if (arrayValues == 0) writeAscii("[]") else writeAscii("\n  ]")
        }

        fun endObject() {
            writeAscii("\n}\n")
            finished = true
        }

        private fun writeCanonicalValue(bytes: ByteArray, indentation: Int, indentFirst: Boolean) {
            if (bytes.isEmpty() || bytes.last() != '\n'.code.toByte()) {
                throw FullTreeDataTruthException("canonical data truth value is malformed")
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

        private fun writeAscii(value: String) {
            val bytes = value.toByteArray(StandardCharsets.US_ASCII)
            output.write(bytes, 0, bytes.size)
        }

        private fun writeSpaces(count: Int) = repeat(count) { output.write(' '.code) }
    }

    private class OutputPublication private constructor(
        val target: Path,
        val staging: Path,
        private val parentIdentity: Any,
        private val stagingIdentity: Any,
    ) {
        private var committed = false

        fun commit(verify: (Path) -> Unit) {
            ensureDirectoryIdentity(target.parent, parentIdentity, "data truth publication parent")
            ensureDirectoryIdentity(staging, stagingIdentity, "data truth staging directory")
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                throw FullTreeDataTruthException("data truth output root already exists")
            }
            forceDirectory(target.parent)
            try {
                Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE)
            } catch (failure: AtomicMoveNotSupportedException) {
                throw FullTreeDataTruthException("atomic data truth directory publication is unavailable", failure)
            }
            try {
                ensureDirectoryIdentity(target, stagingIdentity, "published data truth directory")
                forceDirectory(target.parent)
                ensureDirectoryIdentity(target.parent, parentIdentity, "data truth publication parent")
                ensureDirectoryIdentity(target, stagingIdentity, "published data truth directory")
                verify(target)
                ensureDirectoryIdentity(target.parent, parentIdentity, "data truth publication parent")
                ensureDirectoryIdentity(target, stagingIdentity, "published data truth directory")
            } catch (failure: Throwable) {
                try {
                    revokePublishedDirectory(target, stagingIdentity)
                } catch (revocationFailure: Throwable) {
                    failure.addSuppressed(revocationFailure)
                }
                throw FullTreeDataTruthException(
                    "data truth publication could not be verified and was revoked",
                    failure,
                )
            }
            committed = true
        }

        fun close() {
            if (committed || !Files.exists(staging, LinkOption.NOFOLLOW_LINKS)) return
            ensureDirectoryIdentity(staging, stagingIdentity, "data truth staging directory")
            Files.walk(staging).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::delete)
            }
            forceDirectory(target.parent)
        }

        private fun revokePublishedDirectory(path: Path, expectedIdentity: Any) {
            ensureDirectoryIdentity(path, expectedIdentity, "unverified published data truth directory")
            Files.walk(path).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach { candidate ->
                    if (candidate == path) {
                        ensureDirectoryIdentity(candidate, expectedIdentity, "unverified published data truth directory")
                    }
                    Files.delete(candidate)
                }
            }
            if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                throw FullTreeDataTruthException("unverified data truth directory could not be revoked")
            }
            forceDirectory(path.parent)
        }

        companion object {
            fun create(path: Path): OutputPublication {
                val target = path.toAbsolutePath().normalize()
                if (target.parent == null || target.fileName == null) {
                    throw FullTreeDataTruthException("data truth output root must name a directory")
                }
                if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                    throw FullTreeDataTruthException("data truth output root already exists")
                }
                val parent = requireRealDirectoryStatic(target.parent, "data truth publication parent")
                val parentIdentity = directoryIdentity(parent, "data truth publication parent")
                val staging = Files.createTempDirectory(
                    parent,
                    ".${target.fileName}.data-truth-",
                    PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS),
                )
                val stagingIdentity = directoryIdentity(staging, "data truth staging directory")
                return OutputPublication(target, staging, parentIdentity, stagingIdentity)
            }

            private fun requireRealDirectoryStatic(path: Path, label: String): Path {
                val absolute = path.toAbsolutePath().normalize()
                val real = absolute.toRealPath()
                if (real != absolute) throw FullTreeDataTruthException("$label path contains a symbolic link")
                requireTrustedDirectoryStatic(real, label)
                return real
            }

            private fun requireTrustedDirectoryStatic(path: Path, label: String) {
                val permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS)
                if (PosixFilePermission.GROUP_WRITE in permissions || PosixFilePermission.OTHERS_WRITE in permissions) {
                    throw FullTreeDataTruthException("$label is writable by an untrusted principal")
                }
            }
        }
    }

    private const val SQLITE_PAGE_BYTES = 4096L
    private const val SQLITE_APPLICATION_ID = 0x44435452
    private const val SQLITE_SCHEMA_VERSION = 1
    private const val OBSERVATION_SQLITE_APPLICATION_ID = 0x44434f42
    private const val OBSERVATION_SQLITE_SCHEMA_VERSION = 1
    private const val OBSERVATION_SQLITE_CACHE_BYTES = 4L * 1024L * 1024L
    private const val TRUTH_SQLITE_CACHE_BYTES = 16L * 1024L * 1024L
    private const val INSERT_MERGED_SQL =
        "INSERT INTO merged(kind, owner_shard, identity, canonical_id, payload, globals, types, " +
            "unobservable_globals, unobservable_types, fields, bases, enumerators, " +
            "resolved_type_references, unresolved_type_references, ambiguous_type_references, " +
            "cross_shard_type_references) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    private val PRIVATE_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
    private val PRIVATE_FILE_PERMISSIONS: Set<PosixFilePermission> = EnumSet.of(
        PosixFilePermission.OWNER_READ,
        PosixFilePermission.OWNER_WRITE,
    )
    private val READ_ONLY_FILE_PERMISSIONS = PosixFilePermissions.fromString("r--------")
    private val POLICY = JsonObject(
        mapOf(
            "id" to JsonPrimitive("full-tree-data-truth"),
            "version" to JsonPrimitive(16),
            "typeIdentity" to JsonPrimitive(
                "tag-qualified-lexical-context-name-or-anonymous-declaration-with-observation-owned-lambda-and-lossy-local-contexts",
            ),
            "globalIdentity" to JsonPrimitive(
                "rva-or-source-aligned-name-declaration-or-producer-observation",
            ),
            "owner" to JsonPrimitive("lowest-unit-id"),
            "typeReferences" to JsonPrimitive(
                "exact-dwarf-offset-chain-with-conditional-bounded-authenticated-candidate-commitments-and-no-ambiguous-target-substitution",
            ),
            "truthSharding" to JsonPrimitive(
                "inventory-owner-with-deterministic-two-thirds-byte-budget-entity-partitions",
            ),
            "maximumDatabaseBytes" to JsonPrimitive(8L * 1024L * 1024L * 1024L),
        ),
    )
}

private fun directoryIdentity(path: Path, label: String): Any {
    val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
        throw FullTreeDataTruthException("$label must be an identified real directory")
    }
    return attributes.fileKey()
}

private fun ensureDirectoryIdentity(path: Path, expected: Any, label: String) {
    if (directoryIdentity(path, label) != expected) throw FullTreeDataTruthException("$label changed identity")
}

private fun forceDirectory(path: Path) {
    FileChannel.open(path, StandardOpenOption.READ).use { it.force(true) }
}
