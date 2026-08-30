package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import java.io.FilterOutputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager
import java.sql.PreparedStatement
import java.sql.SQLException
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class FullTreeFunctionObservationSqliteException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** Caller-supplied authenticated wall/CPU budget checkpoint. */
internal fun interface FullTreeFunctionObservationSqliteCheckpoint {
    fun checkpoint(label: String)
}

/** File-backed bounds for one already-authenticated function-observation shard. */
internal data class FullTreeFunctionObservationSqliteLimits(
    val maximumDatabaseBytes: Long,
    val maximumOutputBytes: Long,
    val observations: FullTreeFunctionObservationAccumulatorLimits =
        FullTreeFunctionObservationAccumulatorLimits(),
    val maximumCacheBytes: Int = 8 * 1024 * 1024,
    val databaseCheckpointRows: Int = 4096,
    val checkpoint: FullTreeFunctionObservationSqliteCheckpoint,
) {
    init {
        require(maximumDatabaseBytes in SQLITE_PAGE_BYTES.toLong()..16L * 1024L * 1024L * 1024L)
        require(maximumOutputBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumCacheBytes in 1024..64 * 1024 * 1024)
        require(databaseCheckpointRows in 1..1_000_000)
    }
}

/** Externally authenticated envelope values that are not properties of the shard work item. */
internal data class FullTreeFunctionObservationBindings(
    val inventoryIndexSha256: String,
    val richArtifactSha256: String,
    val scopeSha256: String,
)

/** Metadata returned after projection; the complete observation tree never enters JVM memory. */
internal data class FullTreeFunctionObservationStreamResult(
    val outputSha256: String,
    val outputBytes: Long,
    val emitted: Long,
    val nonEmitted: Long,
    val nonEmittedDies: Long,
    val entities: Long,
    val scannedDies: Long,
    val databaseHighWaterBytes: Long,
)

/** Common scanner boundary shared by the in-progress SQLite-backed producer path. */
internal interface FullTreeFunctionObservationSink : AutoCloseable {
    fun recordScannedDies(count: Long)

    fun accept(observation: FullTreeObservedSubprogram)

    fun finishTo(
        output: OutputStream,
        bindings: FullTreeFunctionObservationBindings,
    ): FullTreeFunctionObservationStreamResult
}

/** Opens wholly revocable private SQLite state for one derived shard input. */
internal object FullTreeFunctionObservationSqlite {
    fun open(
        scratchParent: Path,
        shard: FullTreeFunctionObservationShardInput,
        limits: FullTreeFunctionObservationSqliteLimits,
    ): FullTreeFunctionObservationSink {
        requireStableDirectory(scratchParent, "function-observation SQLite scratch parent")
        val workspace = FunctionObservationSqliteWorkspace.create(scratchParent, limits.maximumDatabaseBytes)
        return try {
            FunctionObservationSqliteSink.open(workspace, shard, limits)
        } catch (failure: Throwable) {
            try {
                workspace.close()
            } catch (cleanupFailure: Throwable) {
                failure.addSuppressed(cleanupFailure)
            }
            throw translateFunctionObservationSqliteFailure("cannot open function-observation SQLite state", failure)
        }
    }
}

private class FunctionObservationSqliteSink private constructor(
    private val workspace: FunctionObservationSqliteWorkspace,
    private val shard: FullTreeFunctionObservationShardInput,
    private val limits: FullTreeFunctionObservationSqliteLimits,
    private val connection: Connection,
    private val statements: FunctionObservationSqliteStatements,
) : FullTreeFunctionObservationSink {
    private val unitsById: Map<String, JsonObject> = Collections.unmodifiableMap(
        shard.units.associateBy { it.controlString("id") },
    )
    private var scannedDies = 0L
    private var subprograms = 0L
    private var emitted = 0L
    private var nonEmitted = 0L
    private var nonEmittedDies = 0L
    private var insertedRows = 0L
    private var nextCheckpoint = limits.databaseCheckpointRows.toLong()
    private var state = SinkState.OPEN

    init {
        if (unitsById.size != shard.units.size) {
            sqliteFail("function-observation shard contains duplicate compilation-unit IDs")
        }
    }

    override fun recordScannedDies(count: Long) = mutate("record scanned DIEs") {
        if (count <= 0L) sqliteFail("function-observation scanned-DIE increment is invalid")
        scannedDies = addCount(scannedDies, count, "scanned DIE")
        if (scannedDies > limits.observations.maximumScannedDies) {
            sqliteFail("function-observation scan exceeds its DIE bound")
        }
    }

    override fun accept(observation: FullTreeObservedSubprogram) = mutate("accept a subprogram") {
        limits.checkpoint.checkpoint("before accepting a function observation")
        subprograms = addCount(subprograms, 1L, "subprogram")
        if (subprograms > limits.observations.maximumSubprograms) {
            sqliteFail("function-observation scan exceeds its subprogram bound")
        }
        val owner = unitsById[observation.unitId]
            ?: sqliteFail("observed subprogram owner is outside its authenticated shard")
        if (!insertObservedDie(observation.dieOffset)) {
            sqliteFail("artifact scan emitted the same subprogram DIE more than once")
        }
        if (
            observation.aliases.isEmpty() ||
            observation.aliases.size > limits.observations.maximumAliasesPerSubprogram
        ) {
            sqliteFail("observed subprogram alias population is outside its bound")
        }
        if (observation.rvas.size > 1) {
            sqliteFail("observed subprogram has more than one historical-v3 start RVA")
        }
        val canonicalBudget = SqliteCanonicalObservationBudget(
            limits.observations.maximumCanonicalBytesPerSubprogram,
        )
        val aliases = authenticateAliases(observation.aliases, observation.unitId, canonicalBudget)
        limits.checkpoint.checkpoint("after authenticating function aliases")
        val declaration = snapshotDeclaration(observation.declaration, owner, canonicalBudget)
        limits.checkpoint.checkpoint("after authenticating a function declaration")
        val rvas = observation.rvas.toSortedSet()
        if (rvas.size != observation.rvas.size) {
            sqliteFail("observed subprogram contains duplicate emitted RVAs")
        }
        if (rvas.isEmpty()) {
            acceptNonEmitted(observation, aliases, declaration, canonicalBudget)
        } else {
            rvas.forEach { rva -> acceptEmitted(rva, observation.unitId, aliases, declaration.bytes) }
        }
        limits.checkpoint.checkpoint("after accepting a function observation")
    }

    override fun finishTo(
        output: OutputStream,
        bindings: FullTreeFunctionObservationBindings,
    ): FullTreeFunctionObservationStreamResult {
        requireOpen()
        state = SinkState.FINISHING
        try {
            requireSha256(bindings.inventoryIndexSha256, "inventory index")
            requireSha256(bindings.richArtifactSha256, "rich artifact")
            requireSha256(bindings.scopeSha256, "scope")
            val minimumScannedDies = addCount(shard.units.size.toLong(), subprograms, "minimum scanned DIE")
            if (scannedDies < minimumScannedDies) {
                sqliteFail("function-observation scan cannot cover its compilation units and evidence")
            }
            limits.checkpoint.checkpoint("before committing function-observation SQLite state")
            connection.commit()
            val committedDatabaseBytes =
                workspace.checkDatabaseBound("before function-observation projection")
            requireCommittedDatabaseLayout(committedDatabaseBytes)
            limits.checkpoint.checkpoint("before checking function-observation projection plans")
            assertIndexedProjectionPlans()
            limits.checkpoint.checkpoint("after checking function-observation projection plans")
            state = SinkState.PROJECTING
            val bounded = FunctionObservationDigestingOutputStream(
                output,
                limits.maximumOutputBytes,
                limits.checkpoint,
            )
            FunctionObservationCanonicalWriter(connection, bounded).use { writer ->
                writer.write(
                    shard = shard,
                    bindings = bindings,
                    emitted = emitted,
                    nonEmitted = nonEmitted,
                    nonEmittedDies = nonEmittedDies,
                    scannedDies = scannedDies,
                )
            }
            val digest = bounded.finish()
            limits.checkpoint.checkpoint("after projecting function-observation output")
            state = SinkState.FINISHED
            return FullTreeFunctionObservationStreamResult(
                outputSha256 = digest.sha256,
                outputBytes = digest.bytes,
                emitted = emitted,
                nonEmitted = nonEmitted,
                nonEmittedDies = nonEmittedDies,
                entities = addCount(emitted, nonEmitted, "function-observation entity"),
                scannedDies = scannedDies,
                databaseHighWaterBytes = workspace.databaseHighWaterBytes(),
            )
        } catch (failure: Throwable) {
            state = SinkState.FAILED
            throw translateFunctionObservationSqliteFailure("cannot project function-observation SQLite state", failure)
        }
    }

    private fun acceptEmitted(
        rva: ULong,
        unitId: String,
        aliases: List<SqliteFunctionAlias>,
        declaration: ByteArray,
    ) {
        val rvaKey = unsignedKey(rva)
        statements.insertEmittedRva.setBytes(1, rvaKey)
        if (statements.insertEmittedRva.executeUpdate() == 1) {
            rowInserted()
            emitted = addCount(emitted, 1L, "emitted observation")
            requireEntityCapacity()
            if (emitted > limits.observations.maximumEmittedRvas.toLong()) {
                sqliteFail("function-observation emitted-RVA population exceeds its bound")
            }
        }

        statements.insertEmittedOwner.setBytes(1, rvaKey)
        statements.insertEmittedOwner.setString(2, unitId)
        if (statements.insertEmittedOwner.executeUpdate() == 1) {
            incrementBoundedCount(
                statements.incrementEmittedOwners,
                rvaKey,
                limits.observations.maximumOwnersPerEntity,
                "emitted observation owner population exceeds its bound",
            )
            rowInserted()
        }

        statements.insertEmittedDeclaration.setBytes(1, rvaKey)
        statements.insertEmittedDeclaration.setBytes(2, declaration)
        if (statements.insertEmittedDeclaration.executeUpdate() == 1) {
            incrementBoundedCount(
                statements.incrementEmittedDeclarations,
                rvaKey,
                limits.observations.maximumDeclarationsPerRva,
                "emitted observation declaration population exceeds its bound",
            )
            rowInserted()
        }

        aliases.forEach { alias ->
            statements.insertEmittedAlias.setBytes(1, rvaKey)
            statements.insertEmittedAlias.setString(2, alias.name)
            if (statements.insertEmittedAlias.executeUpdate() == 1) {
                incrementBoundedCount(
                    statements.incrementEmittedAliases,
                    rvaKey,
                    limits.observations.maximumAliasesPerEntity,
                    "emitted observation alias population exceeds its bound",
                )
                rowInserted()
            }
            alias.evidence.forEach { evidence ->
                statements.insertEmittedEvidence.setBytes(1, rvaKey)
                statements.insertEmittedEvidence.setString(2, alias.name)
                statements.insertEmittedEvidence.setBytes(3, evidence)
                if (statements.insertEmittedEvidence.executeUpdate() == 1) {
                    incrementBoundedEvidenceCount(
                        statements.incrementEmittedEvidence,
                        rvaKey,
                        alias.name,
                        limits.observations.maximumEvidencePerAliasPerEntity,
                        "emitted alias evidence population exceeds its bound",
                    )
                    rowInserted()
                }
            }
        }
    }

    private fun acceptNonEmitted(
        observation: FullTreeObservedSubprogram,
        aliases: List<SqliteFunctionAlias>,
        declaration: SqliteDeclaration,
        canonicalBudget: SqliteCanonicalObservationBudget,
    ) {
        val identityDocument = JsonObject(
            mapOf(
                "aliasNames" to JsonArray(
                    aliases.map { it.name }.sortedWith(FULL_TREE_CODE_POINT_ORDER).map(::JsonPrimitive),
                ),
                "declaration" to JsonObject(declaration.document.filterKeys { it != "unitSourcePath" }),
            ),
        )
        limits.checkpoint.checkpoint("before canonicalizing a non-emitted observation identity")
        val identityBytes = canonicalBytes(identityDocument, "non-emitted observation identity")
        canonicalBudget.charge(identityBytes.size, "non-emitted observation identity")
        limits.checkpoint.checkpoint("after canonicalizing a non-emitted observation identity")
        val digest = MessageDigest.getInstance("SHA-256").digest(identityBytes)
        val groupKey = digest.copyOf(16)
        val identity = groupKey.hex()
        val identifier = "non-emitted-observation-" + sha256(
            "${shard.identifier}:$identity".toByteArray(StandardCharsets.UTF_8),
        ).take(32)

        statements.insertNonEmittedGroup.setBytes(1, groupKey)
        statements.insertNonEmittedGroup.setBytes(2, identityBytes)
        statements.insertNonEmittedGroup.setString(3, identifier)
        statements.insertNonEmittedGroup.setBytes(4, declaration.bytes)
        if (statements.insertNonEmittedGroup.executeUpdate() == 1) {
            rowInserted()
            nonEmitted = addCount(nonEmitted, 1L, "non-emitted observation")
            requireEntityCapacity()
            if (nonEmitted > limits.observations.maximumNonEmittedGroups.toLong()) {
                sqliteFail("function-observation non-emitted population exceeds its bound")
            }
        } else {
            statements.selectNonEmittedIdentity.setBytes(1, groupKey)
            statements.selectNonEmittedIdentity.executeQuery().use { rows ->
                if (!rows.next() || !rows.getBytes(1).contentEquals(identityBytes) || rows.next()) {
                    sqliteFail("non-emitted observation identity digest collision")
                }
            }
        }

        statements.selectNonEmittedIdentifier.setString(1, identifier)
        statements.selectNonEmittedIdentifier.executeQuery().use { rows ->
            if (!rows.next() || !rows.getBytes(1).contentEquals(groupKey) || rows.next()) {
                sqliteFail("non-emitted observation identifier digest collision")
            }
        }
        statements.updateNonEmittedDeclaration.setBytes(1, declaration.bytes)
        statements.updateNonEmittedDeclaration.setBytes(2, groupKey)
        statements.updateNonEmittedDeclaration.setBytes(3, declaration.bytes)
        statements.updateNonEmittedDeclaration.executeUpdate()

        aliases.forEach { alias ->
            statements.insertNonEmittedAlias.setBytes(1, groupKey)
            statements.insertNonEmittedAlias.setString(2, alias.name)
            if (statements.insertNonEmittedAlias.executeUpdate() == 1) {
                incrementBoundedCount(
                    statements.incrementNonEmittedAliases,
                    groupKey,
                    limits.observations.maximumAliasesPerEntity,
                    "non-emitted observation alias population exceeds its bound",
                )
                rowInserted()
            }
            alias.evidence.forEach { evidence ->
                statements.insertNonEmittedEvidence.setBytes(1, groupKey)
                statements.insertNonEmittedEvidence.setString(2, alias.name)
                statements.insertNonEmittedEvidence.setBytes(3, evidence)
                if (statements.insertNonEmittedEvidence.executeUpdate() == 1) {
                    incrementBoundedEvidenceCount(
                        statements.incrementNonEmittedEvidence,
                        groupKey,
                        alias.name,
                        limits.observations.maximumEvidencePerAliasPerEntity,
                        "non-emitted alias evidence population exceeds its bound",
                    )
                    rowInserted()
                }
            }
        }

        statements.insertNonEmittedDie.setBytes(1, groupKey)
        statements.insertNonEmittedDie.setString(2, observation.unitId)
        statements.insertNonEmittedDie.setBytes(3, unsignedKey(observation.dieOffset))
        if (statements.insertNonEmittedDie.executeUpdate() != 1) {
            sqliteFail("non-emitted observation repeats a DIE identity")
        }
        rowInserted()
        nonEmittedDies = addCount(nonEmittedDies, 1L, "non-emitted DIE")

        statements.insertNonEmittedOwner.setBytes(1, groupKey)
        statements.insertNonEmittedOwner.setString(2, observation.unitId)
        if (statements.insertNonEmittedOwner.executeUpdate() == 1) {
            incrementBoundedCount(
                statements.incrementNonEmittedOwners,
                groupKey,
                limits.observations.maximumOwnersPerEntity,
                "non-emitted observation owner population exceeds its bound",
            )
            rowInserted()
        }

        statements.insertNonEmittedReason.setBytes(1, groupKey)
        statements.insertNonEmittedReason.setString(
            2,
            if (observation.inlineWithoutEmittedRange) {
                "inline-no-emitted-range"
            } else {
                "definition-no-emitted-range"
            },
        )
        if (statements.insertNonEmittedReason.executeUpdate() == 1) rowInserted()
    }

    private fun authenticateAliases(
        aliases: List<FullTreeObservedFunctionAlias>,
        unitId: String,
        canonicalBudget: SqliteCanonicalObservationBudget,
    ): List<SqliteFunctionAlias> {
        val names = HashSet<String>()
        var evidenceItems = 0L
        return aliases.map { alias ->
            limits.checkpoint.checkpoint("while authenticating function aliases")
            requireScalar(alias.name, limits.observations.maximumNameCodePoints, "DWARF function name")
            if (!names.add(alias.name)) sqliteFail("observed subprogram repeats an alias name")
            if (
                alias.evidence.isEmpty() ||
                alias.evidence.size > limits.observations.maximumEvidencePerAliasPerSubprogram
            ) {
                sqliteFail("observed function alias evidence population is outside its bound")
            }
            evidenceItems = addCount(
                evidenceItems,
                alias.evidence.size.toLong(),
                "subprogram alias evidence",
            )
            if (evidenceItems > limits.observations.maximumEvidencePerSubprogram.toLong()) {
                sqliteFail("observed subprogram aggregate evidence population exceeds its bound")
            }
            val evidence = LinkedHashMap<CanonicalBytesKey, ByteArray>()
            alias.evidence.forEach { item ->
                limits.checkpoint.checkpoint("while authenticating function alias evidence")
                requireScalar(
                    item.locator,
                    limits.observations.maximumLocatorCodePoints,
                    "DWARF function locator",
                )
                if (item.unitId != unitId) {
                    sqliteFail("observed function evidence owner differs from its DIE owner")
                }
                val bytes = canonicalBytes(
                    JsonObject(
                        mapOf(
                            "kind" to JsonPrimitive("dwarf-subprogram"),
                            "locator" to JsonPrimitive(item.locator),
                            "unitId" to JsonPrimitive(item.unitId),
                        ),
                    ),
                    "function alias evidence",
                )
                canonicalBudget.charge(bytes.size, "function alias evidence")
                evidence[CanonicalBytesKey(bytes)] = bytes
            }
            SqliteFunctionAlias(alias.name, Collections.unmodifiableList(evidence.values.toList()))
        }
    }

    private fun snapshotDeclaration(
        declaration: JsonObject,
        unit: JsonObject,
        canonicalBudget: SqliteCanonicalObservationBudget,
    ): SqliteDeclaration {
        val bytes = canonicalBytes(declaration, "function declaration")
        canonicalBudget.charge(bytes.size, "function declaration")
        val snapshot = try {
            OracleJson.parseCanonical(bytes, FULL_TREE_FUNCTION_OBSERVATION_JSON_LIMITS) as? JsonObject
                ?: sqliteFail("function declaration root is not an object")
        } catch (failure: FullTreeFunctionObservationSqliteException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeFunctionObservationSqliteException("function declaration is not canonicalizable", failure)
        }
        if (snapshot.controlString("unitSourcePath") != unit.controlString("sourcePath")) {
            sqliteFail("function declaration owner path differs from its compilation unit")
        }
        return SqliteDeclaration(snapshot, bytes)
    }

    private fun insertObservedDie(offset: ULong): Boolean {
        statements.insertObservedDie.setBytes(1, unsignedKey(offset))
        val inserted = statements.insertObservedDie.executeUpdate() == 1
        if (inserted) rowInserted()
        return inserted
    }

    private fun requireEntityCapacity() {
        if (addCount(emitted, nonEmitted, "function-observation entity") > limits.observations.maximumEntities) {
            sqliteFail("function-observation entity population exceeds its bound")
        }
    }

    private fun incrementBoundedCount(
        statement: PreparedStatement,
        key: ByteArray,
        maximum: Int,
        message: String,
    ) {
        statement.setBytes(1, key)
        statement.setInt(2, maximum)
        if (statement.executeUpdate() != 1) sqliteFail(message)
    }

    private fun incrementBoundedEvidenceCount(
        statement: PreparedStatement,
        key: ByteArray,
        name: String,
        maximum: Int,
        message: String,
    ) {
        statement.setBytes(1, key)
        statement.setString(2, name)
        statement.setInt(3, maximum)
        if (statement.executeUpdate() != 1) sqliteFail(message)
    }

    private fun rowInserted() {
        insertedRows = addCount(insertedRows, 1L, "function-observation SQLite row")
        if (insertedRows >= nextCheckpoint) {
            connection.commit()
            workspace.checkDatabaseBound("while accumulating function observations")
            limits.checkpoint.checkpoint("while accumulating function observations")
            val completedIntervals = insertedRows / limits.databaseCheckpointRows.toLong()
            nextCheckpoint = Math.multiplyExact(
                addCount(completedIntervals, 1L, "function-observation SQLite checkpoint"),
                limits.databaseCheckpointRows.toLong(),
            )
        }
    }

    private fun assertIndexedProjectionPlans() {
        PROJECTION_QUERIES.forEach { sql ->
            connection.createStatement().use { statement ->
                statement.executeQuery("EXPLAIN QUERY PLAN $sql").use { rows ->
                    while (rows.next()) {
                        if ("USE TEMP B-TREE" in rows.getString(4).uppercase()) {
                            sqliteFail("function-observation projection requests unmanaged temporary sorting")
                        }
                    }
                }
            }
        }
    }

    private fun requireCommittedDatabaseLayout(databaseBytes: Long) {
        val pageSize = pragmaLong(connection, "page_size")
        val pageCount = pragmaLong(connection, "page_count")
        val allocatedBytes = try {
            Math.multiplyExact(pageSize, pageCount)
        } catch (failure: ArithmeticException) {
            throw FullTreeFunctionObservationSqliteException(
                "function-observation SQLite allocation overflows",
                failure,
            )
        }
        if (
            pageSize != SQLITE_PAGE_BYTES.toLong() || pageCount <= 0L ||
            allocatedBytes != databaseBytes || workspace.databaseHighWaterBytes() != databaseBytes
        ) {
            sqliteFail("function-observation SQLite allocation differs from its pinned file size")
        }
    }

    private inline fun mutate(operation: String, block: () -> Unit) {
        requireOpen()
        state = SinkState.MUTATING
        try {
            block()
            state = SinkState.OPEN
        } catch (failure: Throwable) {
            state = SinkState.FAILED
            throw translateFunctionObservationSqliteFailure("cannot $operation", failure)
        }
    }

    private fun requireOpen() {
        if (state != SinkState.OPEN) sqliteFail("function-observation SQLite sink is not open")
    }

    override fun close() {
        if (state == SinkState.CLOSED) return
        if (state == SinkState.MUTATING || state == SinkState.FINISHING || state == SinkState.PROJECTING) {
            sqliteFail("function-observation SQLite sink operation is in progress")
        }
        var failure: Throwable? = null
        if (state == SinkState.OPEN || state == SinkState.FAILED) {
            try {
                connection.rollback()
            } catch (rollbackFailure: Throwable) {
                failure = rollbackFailure
            }
        }
        try {
            statements.close()
        } catch (closeFailure: Throwable) {
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        try {
            connection.close()
        } catch (closeFailure: Throwable) {
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        try {
            workspace.close()
        } catch (closeFailure: Throwable) {
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        state = SinkState.CLOSED
        failure?.let {
            throw translateFunctionObservationSqliteFailure("cannot close function-observation SQLite state", it)
        }
    }

    companion object {
        fun open(
            workspace: FunctionObservationSqliteWorkspace,
            shard: FullTreeFunctionObservationShardInput,
            limits: FullTreeFunctionObservationSqliteLimits,
        ): FunctionObservationSqliteSink {
            val connection = DriverManager.getConnection(SqliteJdbcPaths.create(workspace.database))
            try {
                configure(connection, workspace, limits)
                val statements = FunctionObservationSqliteStatements(connection)
                connection.autoCommit = false
                return FunctionObservationSqliteSink(workspace, shard, limits, connection, statements)
            } catch (failure: Throwable) {
                try {
                    connection.close()
                } catch (closeFailure: Throwable) {
                    failure.addSuppressed(closeFailure)
                }
                throw failure
            }
        }

        private fun configure(
            connection: Connection,
            workspace: FunctionObservationSqliteWorkspace,
            limits: FullTreeFunctionObservationSqliteLimits,
        ) {
            val maximumPages = limits.maximumDatabaseBytes / SQLITE_PAGE_BYTES
            connection.createStatement().use { statement ->
                statement.execute("PRAGMA page_size=$SQLITE_PAGE_BYTES")
                statement.execute("PRAGMA journal_mode=OFF")
                statement.execute("PRAGMA synchronous=OFF")
                statement.execute("PRAGMA temp_store=FILE")
                statement.execute("PRAGMA cache_size=-${limits.maximumCacheBytes / 1024}")
                statement.execute("PRAGMA mmap_size=0")
                statement.execute("PRAGMA locking_mode=EXCLUSIVE")
                statement.execute("PRAGMA foreign_keys=ON")
                statement.execute("PRAGMA automatic_index=OFF")
                statement.execute("PRAGMA auto_vacuum=NONE")
                statement.execute("PRAGMA threads=1")
                statement.execute("PRAGMA application_id=$SQLITE_APPLICATION_ID")
                statement.execute("PRAGMA user_version=$SQLITE_SCHEMA_VERSION")
                statement.execute("PRAGMA max_page_count=$maximumPages")
                SCHEMA.forEach(statement::execute)
            }
            Files.setPosixFilePermissions(workspace.database, SQLITE_PRIVATE_FILE_PERMISSIONS)
            workspace.verifyDatabaseIdentity()
            if (
                pragmaLong(connection, "page_size") != SQLITE_PAGE_BYTES.toLong() ||
                pragmaLong(connection, "max_page_count") > maximumPages ||
                pragmaLong(connection, "temp_store") != SQLITE_TEMP_STORE_FILE.toLong() ||
                pragmaLong(connection, "mmap_size") != 0L ||
                pragmaLong(connection, "foreign_keys") != 1L ||
                pragmaLong(connection, "automatic_index") != 0L ||
                pragmaLong(connection, "auto_vacuum") != 0L ||
                pragmaLong(connection, "application_id") != SQLITE_APPLICATION_ID.toLong() ||
                pragmaLong(connection, "user_version") != SQLITE_SCHEMA_VERSION.toLong()
            ) {
                sqliteFail("function-observation SQLite safety configuration differs")
            }
            connection.createStatement().use { statement ->
                statement.executeQuery("PRAGMA encoding").use { rows ->
                    if (!rows.next() || rows.getString(1).uppercase() != "UTF-8" || rows.next()) {
                        sqliteFail("function-observation SQLite encoding differs")
                    }
                }
            }
            workspace.checkDatabaseBound("after creating function-observation schema")
            limits.checkpoint.checkpoint("after creating function-observation SQLite schema")
        }
    }
}

private class FunctionObservationSqliteStatements(connection: Connection) : AutoCloseable {
    val insertObservedDie = connection.prepareStatement("INSERT OR IGNORE INTO observed_die(die_offset) VALUES(?)")
    val insertEmittedRva = connection.prepareStatement("INSERT OR IGNORE INTO emitted_rva(rva) VALUES(?)")
    val insertEmittedOwner = connection.prepareStatement(
        "INSERT OR IGNORE INTO emitted_owner(rva,unit_id) VALUES(?,?)",
    )
    val insertEmittedDeclaration =
        connection.prepareStatement("INSERT OR IGNORE INTO emitted_declaration(rva,canonical) VALUES(?,?)")
    val insertEmittedAlias =
        connection.prepareStatement("INSERT OR IGNORE INTO emitted_alias(rva,name) VALUES(?,?)")
    val insertEmittedEvidence = connection.prepareStatement(
        "INSERT OR IGNORE INTO emitted_evidence(rva,name,canonical) VALUES(?,?,?)",
    )
    val incrementEmittedOwners = connection.prepareStatement(
        "UPDATE emitted_rva SET owner_count=owner_count+1 WHERE rva=? AND owner_count<?",
    )
    val incrementEmittedDeclarations = connection.prepareStatement(
        "UPDATE emitted_rva SET declaration_count=declaration_count+1 " +
            "WHERE rva=? AND declaration_count<?",
    )
    val incrementEmittedAliases = connection.prepareStatement(
        "UPDATE emitted_rva SET alias_count=alias_count+1 WHERE rva=? AND alias_count<?",
    )
    val incrementEmittedEvidence = connection.prepareStatement(
        "UPDATE emitted_alias SET evidence_count=evidence_count+1 " +
            "WHERE rva=? AND name=? AND evidence_count<?",
    )
    val insertNonEmittedGroup =
        connection.prepareStatement(
            "INSERT OR IGNORE INTO non_emitted_group(group_key,identity,identifier,declaration) " +
                "VALUES(?,?,?,?)",
        )
    val selectNonEmittedIdentity =
        connection.prepareStatement("SELECT identity FROM non_emitted_group WHERE group_key=?")
    val selectNonEmittedIdentifier =
        connection.prepareStatement("SELECT group_key FROM non_emitted_group WHERE identifier=?")
    val updateNonEmittedDeclaration = connection.prepareStatement(
        "UPDATE non_emitted_group SET declaration=? WHERE group_key=? AND declaration>?",
    )
    val insertNonEmittedAlias = connection.prepareStatement(
        "INSERT OR IGNORE INTO non_emitted_alias(group_key,name) VALUES(?,?)",
    )
    val insertNonEmittedEvidence = connection.prepareStatement(
        "INSERT OR IGNORE INTO non_emitted_evidence(group_key,name,canonical) VALUES(?,?,?)",
    )
    val insertNonEmittedDie = connection.prepareStatement(
        "INSERT OR IGNORE INTO non_emitted_die(group_key,unit_id,die_offset) VALUES(?,?,?)",
    )
    val insertNonEmittedOwner = connection.prepareStatement(
        "INSERT OR IGNORE INTO non_emitted_owner(group_key,unit_id) VALUES(?,?)",
    )
    val insertNonEmittedReason = connection.prepareStatement(
        "INSERT OR IGNORE INTO non_emitted_reason(group_key,reason) VALUES(?,?)",
    )
    val incrementNonEmittedAliases = connection.prepareStatement(
        "UPDATE non_emitted_group SET alias_count=alias_count+1 " +
            "WHERE group_key=? AND alias_count<?",
    )
    val incrementNonEmittedEvidence = connection.prepareStatement(
        "UPDATE non_emitted_alias SET evidence_count=evidence_count+1 " +
            "WHERE group_key=? AND name=? AND evidence_count<?",
    )
    val incrementNonEmittedOwners = connection.prepareStatement(
        "UPDATE non_emitted_group SET owner_count=owner_count+1 " +
            "WHERE group_key=? AND owner_count<?",
    )

    override fun close() {
        var failure: Throwable? = null
        listOf(
            insertObservedDie,
            insertEmittedRva,
            insertEmittedOwner,
            insertEmittedDeclaration,
            insertEmittedAlias,
            insertEmittedEvidence,
            incrementEmittedOwners,
            incrementEmittedDeclarations,
            incrementEmittedAliases,
            incrementEmittedEvidence,
            insertNonEmittedGroup,
            selectNonEmittedIdentity,
            selectNonEmittedIdentifier,
            updateNonEmittedDeclaration,
            insertNonEmittedAlias,
            insertNonEmittedEvidence,
            insertNonEmittedDie,
            insertNonEmittedOwner,
            insertNonEmittedReason,
            incrementNonEmittedAliases,
            incrementNonEmittedEvidence,
            incrementNonEmittedOwners,
        ).forEach { statement ->
            try {
                statement.close()
            } catch (closeFailure: Throwable) {
                if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
            }
        }
        failure?.let { throw it }
    }
}

private class FunctionObservationCanonicalWriter(
    private val connection: Connection,
    private val output: OutputStream,
) : AutoCloseable {
    private val emittedRows = connection.prepareStatement("SELECT rva FROM emitted_rva ORDER BY rva")
    private val emittedAliases =
        connection.prepareStatement("SELECT name FROM emitted_alias WHERE rva=? ORDER BY name")
    private val emittedEvidence = connection.prepareStatement(
        "SELECT canonical FROM emitted_evidence WHERE rva=? AND name=? ORDER BY canonical",
    )
    private val emittedDeclarations = connection.prepareStatement(
        "SELECT canonical FROM emitted_declaration WHERE rva=? ORDER BY canonical",
    )
    private val emittedOwners = connection.prepareStatement("SELECT unit_id FROM emitted_owner WHERE rva=? ORDER BY unit_id")
    private val nonEmittedRows = connection.prepareStatement(
        "SELECT group_key,identifier,declaration FROM non_emitted_group ORDER BY identifier",
    )
    private val nonEmittedAliases =
        connection.prepareStatement("SELECT name FROM non_emitted_alias WHERE group_key=? ORDER BY name")
    private val nonEmittedEvidence = connection.prepareStatement(
        "SELECT canonical FROM non_emitted_evidence WHERE group_key=? AND name=? ORDER BY canonical",
    )
    private val nonEmittedDies = connection.prepareStatement(
        "SELECT unit_id,die_offset FROM non_emitted_die WHERE group_key=? ORDER BY unit_id,die_offset",
    )
    private val nonEmittedReasons = connection.prepareStatement(
        "SELECT reason FROM non_emitted_reason WHERE group_key=? ORDER BY reason",
    )
    private val nonEmittedOwners = connection.prepareStatement(
        "SELECT unit_id FROM non_emitted_owner WHERE group_key=? ORDER BY unit_id",
    )

    fun write(
        shard: FullTreeFunctionObservationShardInput,
        bindings: FullTreeFunctionObservationBindings,
        emitted: Long,
        nonEmitted: Long,
        nonEmittedDies: Long,
        scannedDies: Long,
    ) {
        ascii("{\n")
        ascii("  \"counts\": {\n")
        ascii("    \"emittedRvas\": $emitted,\n")
        ascii("    \"nonEmitted\": $nonEmitted,\n")
        ascii("    \"nonEmittedDies\": $nonEmittedDies,\n")
        ascii("    \"scannedDies\": $scannedDies,\n")
        ascii("    \"units\": ${shard.units.size}\n")
        ascii("  },\n")
        val projectedEmitted = writeEmitted()
        ascii(",\n")
        val projectedNonEmitted = writeNonEmitted()
        ascii(",\n")
        ascii("  \"oracle\": {\n")
        ascii("    \"configurationSha256\": ")
        string(FullTreeFunctionObservations.configurationSha256)
        ascii(",\n")
        ascii("    \"inventoryIndexSha256\": ")
        string(bindings.inventoryIndexSha256)
        ascii(",\n")
        ascii("    \"richArtifactSha256\": ")
        string(bindings.richArtifactSha256)
        ascii(",\n")
        ascii("    \"scopeSha256\": ")
        string(bindings.scopeSha256)
        ascii("\n  },\n")
        ascii("  \"schemaVersion\": 1,\n")
        ascii("  \"shard\": {\n")
        ascii("    \"id\": ")
        string(shard.identifier)
        ascii(",\n")
        ascii("    \"inputSha256\": ")
        string(shard.inputSha256)
        ascii("\n  }\n")
        ascii("}\n")
        if (
            projectedEmitted != emitted || projectedNonEmitted.entities != nonEmitted ||
            projectedNonEmitted.dies != nonEmittedDies
        ) {
            sqliteFail("function-observation SQLite projection counts do not reconcile")
        }
    }

    private fun writeEmitted(): Long {
        var index = 0L
        ascii("  \"emitted\": ")
        emittedRows.executeQuery().use { rows ->
            while (rows.next()) {
                if (index++ == 0L) ascii("[\n") else ascii(",\n")
                writeEmittedEntity(rows.getBytes(1))
            }
        }
        ascii(if (index == 0L) "[]" else "\n  ]")
        return index
    }

    private fun writeEmittedEntity(rva: ByteArray) {
        val address = canonicalAddress(rva)
        ascii("    {\n")
        ascii("      \"aliases\": [\n")
        bind(emittedAliases, rva)
        var aliasIndex = 0L
        emittedAliases.executeQuery().use { aliases ->
            while (aliases.next()) {
                if (aliasIndex++ > 0L) ascii(",\n")
                val name = aliases.getString(1)
                ascii("        {\n")
                ascii("          \"evidence\": [\n")
                emittedEvidence.setBytes(1, rva)
                emittedEvidence.setString(2, name)
                writeCanonicalRows(emittedEvidence, 12, "emitted alias has no evidence")
                ascii("\n          ],\n")
                ascii("          \"name\": ")
                string(name)
                ascii("\n        }")
            }
        }
        if (aliasIndex == 0L) sqliteFail("emitted observation has no aliases")
        ascii("\n      ],\n")
        ascii("      \"declarations\": [\n")
        bind(emittedDeclarations, rva)
        writeCanonicalRows(emittedDeclarations, 8, "emitted observation has no declarations")
        ascii("\n      ],\n")
        ascii("      \"id\": ")
        string("function-rva-$address")
        ascii(",\n")
        ascii("      \"ownerUnitIds\": [\n")
        bind(emittedOwners, rva)
        writeStringRows(emittedOwners, 8, "emitted observation has no owners")
        ascii("\n      ],\n")
        ascii("      \"rva\": ")
        string(address)
        ascii("\n    }")
    }

    private fun writeNonEmitted(): FunctionObservationNonEmittedProjectionCounts {
        var index = 0L
        var dies = 0L
        ascii("  \"nonEmitted\": ")
        nonEmittedRows.executeQuery().use { rows ->
            while (rows.next()) {
                if (index++ == 0L) ascii("[\n") else ascii(",\n")
                dies = addCount(
                    dies,
                    writeNonEmittedEntity(rows.getBytes(1), rows.getString(2), rows.getBytes(3)),
                    "projected non-emitted DIE",
                )
            }
        }
        ascii(if (index == 0L) "[]" else "\n  ]")
        return FunctionObservationNonEmittedProjectionCounts(index, dies)
    }

    private fun writeNonEmittedEntity(group: ByteArray, identifier: String, declaration: ByteArray): Long {
        ascii("    {\n")
        ascii("      \"aliases\": [\n")
        bind(nonEmittedAliases, group)
        var aliasIndex = 0L
        nonEmittedAliases.executeQuery().use { aliases ->
            while (aliases.next()) {
                if (aliasIndex++ > 0L) ascii(",\n")
                val name = aliases.getString(1)
                ascii("        {\n")
                ascii("          \"evidence\": [\n")
                nonEmittedEvidence.setBytes(1, group)
                nonEmittedEvidence.setString(2, name)
                writeCanonicalRows(nonEmittedEvidence, 12, "non-emitted alias has no evidence")
                ascii("\n          ],\n")
                ascii("          \"name\": ")
                string(name)
                ascii("\n        }")
            }
        }
        if (aliasIndex == 0L) sqliteFail("non-emitted observation has no aliases")
        ascii("\n      ],\n")
        ascii("      \"declaration\": ")
        writeIndentedCanonical(declaration, 6, prefixAlreadyWritten = true)
        ascii(",\n")
        ascii("      \"dieOffsets\": [\n")
        bind(nonEmittedDies, group)
        var dieIndex = 0L
        nonEmittedDies.executeQuery().use { dies ->
            while (dies.next()) {
                if (dieIndex++ > 0L) ascii(",\n")
                ascii("        {\n")
                ascii("          \"dieOffset\": ")
                string(canonicalAddress(dies.getBytes(2)))
                ascii(",\n")
                ascii("          \"unitId\": ")
                string(dies.getString(1))
                ascii("\n        }")
            }
        }
        if (dieIndex == 0L) sqliteFail("non-emitted observation has no DIE evidence")
        ascii("\n      ],\n")
        ascii("      \"id\": ")
        string(identifier)
        ascii(",\n")
        ascii("      \"reasonCodes\": [\n")
        bind(nonEmittedReasons, group)
        writeStringRows(nonEmittedReasons, 8, "non-emitted observation has no reason")
        ascii("\n      ],\n")
        ascii("      \"unitIds\": [\n")
        bind(nonEmittedOwners, group)
        writeStringRows(nonEmittedOwners, 8, "non-emitted observation has no owners")
        ascii("\n      ]\n")
        ascii("    }")
        return dieIndex
    }

    private fun writeCanonicalRows(statement: PreparedStatement, indent: Int, emptyMessage: String) {
        var index = 0L
        statement.executeQuery().use { rows ->
            while (rows.next()) {
                if (index++ > 0L) ascii(",\n")
                writeIndentedCanonical(rows.getBytes(1), indent)
            }
        }
        if (index == 0L) sqliteFail(emptyMessage)
    }

    private fun writeStringRows(statement: PreparedStatement, indent: Int, emptyMessage: String) {
        var index = 0L
        statement.executeQuery().use { rows ->
            while (rows.next()) {
                if (index++ > 0L) ascii(",\n")
                spaces(indent)
                string(rows.getString(1))
            }
        }
        if (index == 0L) sqliteFail(emptyMessage)
    }

    private fun writeIndentedCanonical(bytes: ByteArray, indent: Int, prefixAlreadyWritten: Boolean = false) {
        if (bytes.isEmpty() || bytes.last() != '\n'.code.toByte()) {
            sqliteFail("stored canonical JSON is malformed")
        }
        val end = bytes.lastIndex
        var lineStart = 0
        var first = true
        while (lineStart < end) {
            var lineEnd = lineStart
            while (lineEnd < end && bytes[lineEnd] != '\n'.code.toByte()) lineEnd++
            if (!(first && prefixAlreadyWritten)) spaces(indent)
            output.write(bytes, lineStart, lineEnd - lineStart)
            if (lineEnd < end) ascii("\n")
            lineStart = lineEnd + 1
            first = false
        }
    }

    private fun string(value: String) {
        val bytes = try {
            OracleJson.canonicalBytes(JsonPrimitive(value))
        } catch (failure: Exception) {
            throw FullTreeFunctionObservationSqliteException("cannot encode function-observation string", failure)
        }
        if (bytes.isEmpty() || bytes.last() != '\n'.code.toByte()) {
            sqliteFail("canonical function-observation string is malformed")
        }
        output.write(bytes, 0, bytes.size - 1)
    }

    private fun bind(statement: PreparedStatement, key: ByteArray) {
        statement.setBytes(1, key)
    }

    private fun spaces(count: Int) {
        output.write(ByteArray(count) { ' '.code.toByte() })
    }

    private fun ascii(value: String) {
        output.write(value.toByteArray(StandardCharsets.US_ASCII))
    }

    override fun close() {
        var failure: Throwable? = null
        listOf(
            emittedRows,
            emittedAliases,
            emittedEvidence,
            emittedDeclarations,
            emittedOwners,
            nonEmittedRows,
            nonEmittedAliases,
            nonEmittedEvidence,
            nonEmittedDies,
            nonEmittedReasons,
            nonEmittedOwners,
        ).forEach { statement ->
            try {
                statement.close()
            } catch (closeFailure: Throwable) {
                if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
            }
        }
        failure?.let { throw it }
    }
}

private class FunctionObservationSqliteWorkspace private constructor(
    private val parent: Path,
    private val parentIdentity: Any,
    private val root: Path,
    private val rootIdentity: Any,
    val database: Path,
    private val databaseIdentity: Any,
    private val maximumDatabaseBytes: Long,
) : AutoCloseable {
    private var maximumObservedDatabaseBytes = 0L

    fun verifyDatabaseIdentity() {
        checkParentAndRootIdentity("after opening function-observation SQLite state")
        val attributes = Files.readAttributes(
            database,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        if (
            !attributes.isRegularFile || attributes.isSymbolicLink ||
            attributes.fileKey() != databaseIdentity ||
            Files.getPosixFilePermissions(database, LinkOption.NOFOLLOW_LINKS) !=
            SQLITE_PRIVATE_FILE_PERMISSIONS
        ) {
            sqliteFail("function-observation SQLite database identity changed")
        }
    }

    fun checkDatabaseBound(checkpoint: String): Long {
        checkParentAndRootIdentity(checkpoint)
        val attributes = Files.readAttributes(
            database,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        if (
            !attributes.isRegularFile || attributes.isSymbolicLink ||
            attributes.fileKey() != databaseIdentity || attributes.size() > maximumDatabaseBytes ||
            Files.getPosixFilePermissions(database, LinkOption.NOFOLLOW_LINKS) !=
            SQLITE_PRIVATE_FILE_PERMISSIONS
        ) {
            sqliteFail("function-observation SQLite database changed or exceeds its byte bound $checkpoint")
        }
        maximumObservedDatabaseBytes = maxOf(maximumObservedDatabaseBytes, attributes.size())
        requireSoleDatabaseChild(checkpoint)
        return attributes.size()
    }

    fun databaseHighWaterBytes(): Long {
        if (maximumObservedDatabaseBytes <= 0L) {
            sqliteFail("function-observation SQLite database high-water mark is unavailable")
        }
        return maximumObservedDatabaseBytes
    }

    override fun close() {
        checkParentAndRootIdentity("before revoking function-observation SQLite state")
        requireSoleDatabaseChild("before revoking function-observation SQLite state")
        verifyDatabaseIdentity()
        Files.delete(database)
        Files.delete(root)
        val (_, currentParentIdentity) = requireStableDirectory(
            parent,
            "function-observation SQLite scratch parent after cleanup",
        )
        if (currentParentIdentity != parentIdentity) {
            sqliteFail("function-observation SQLite scratch parent identity changed after cleanup")
        }
    }

    private fun checkParentAndRootIdentity(checkpoint: String) {
        val (_, currentParentIdentity) = requireStableDirectory(
            parent,
            "function-observation SQLite scratch parent $checkpoint",
        )
        if (currentParentIdentity != parentIdentity) {
            sqliteFail("function-observation SQLite scratch parent identity changed $checkpoint")
        }
        val current = Files.readAttributes(root, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (
            !current.isDirectory || current.isSymbolicLink || current.fileKey() != rootIdentity ||
            Files.getPosixFilePermissions(root, LinkOption.NOFOLLOW_LINKS) !=
            SQLITE_PRIVATE_DIRECTORY_PERMISSIONS
        ) {
            sqliteFail("function-observation SQLite scratch identity changed $checkpoint")
        }
    }

    private fun requireSoleDatabaseChild(checkpoint: String) {
        var seenDatabase = false
        Files.newDirectoryStream(root).use { children ->
            children.forEach { child ->
                if (child != database || seenDatabase) {
                    sqliteFail("function-observation SQLite scratch contains an unexpected path $checkpoint")
                }
                seenDatabase = true
            }
        }
        if (!seenDatabase) sqliteFail("function-observation SQLite database disappeared $checkpoint")
    }

    companion object {
        fun create(parent: Path, maximumDatabaseBytes: Long): FunctionObservationSqliteWorkspace {
            val (trustedParent, parentIdentity) = requireStableDirectory(
                parent,
                "function-observation SQLite scratch parent",
            )
            val root = Files.createTempDirectory(
                trustedParent,
                ".function-observation-sqlite-",
                PosixFilePermissions.asFileAttribute(SQLITE_PRIVATE_DIRECTORY_PERMISSIONS),
            )
            var database: Path? = null
            try {
                val attributes = Files.readAttributes(
                    root,
                    BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                )
                if (
                    !attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null ||
                    Files.getPosixFilePermissions(root, LinkOption.NOFOLLOW_LINKS) !=
                    SQLITE_PRIVATE_DIRECTORY_PERMISSIONS
                ) {
                    sqliteFail("function-observation SQLite scratch has no stable identity")
                }
                database = Files.createFile(
                    root.resolve("observations.sqlite"),
                    PosixFilePermissions.asFileAttribute(SQLITE_PRIVATE_FILE_PERMISSIONS),
                )
                val databaseAttributes = Files.readAttributes(
                    database,
                    BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                )
                if (
                    !databaseAttributes.isRegularFile || databaseAttributes.isSymbolicLink ||
                    databaseAttributes.fileKey() == null ||
                    Files.getPosixFilePermissions(database, LinkOption.NOFOLLOW_LINKS) !=
                    SQLITE_PRIVATE_FILE_PERMISSIONS
                ) {
                    sqliteFail("function-observation SQLite database has no stable identity")
                }
                val (_, currentParentIdentity) = requireStableDirectory(
                    trustedParent,
                    "function-observation SQLite scratch parent after creation",
                )
                if (currentParentIdentity != parentIdentity) {
                    sqliteFail("function-observation SQLite scratch parent identity changed during creation")
                }
                return FunctionObservationSqliteWorkspace(
                    trustedParent,
                    parentIdentity,
                    root,
                    checkNotNull(attributes.fileKey()),
                    database,
                    checkNotNull(databaseAttributes.fileKey()),
                    maximumDatabaseBytes,
                )
            } catch (failure: Throwable) {
                try {
                    database?.let(Files::deleteIfExists)
                    Files.deleteIfExists(root)
                } catch (cleanupFailure: Throwable) {
                    failure.addSuppressed(cleanupFailure)
                }
                throw failure
            }
        }
    }
}

private class FunctionObservationDigestingOutputStream(
    output: OutputStream,
    private val maximumBytes: Long,
    private val checkpoint: FullTreeFunctionObservationSqliteCheckpoint,
) : FilterOutputStream(output) {
    private val digest = MessageDigest.getInstance("SHA-256")
    private var count = 0L
    private var nextCheckpoint = OUTPUT_CHECKPOINT_BYTES
    private var finished = false

    override fun write(value: Int) {
        write(byteArrayOf(value.toByte()), 0, 1)
    }

    override fun write(bytes: ByteArray, offset: Int, length: Int) {
        if (finished) sqliteFail("function-observation output digest is already complete")
        if (offset < 0 || length < 0 || offset > bytes.size - length) throw IndexOutOfBoundsException()
        if (count > maximumBytes - length.toLong()) {
            sqliteFail("function-observation output exceeds its byte bound")
        }
        var cursor = offset
        var remaining = length
        while (remaining > 0) {
            val untilCheckpoint = nextCheckpoint - count
            val chunk = minOf(remaining.toLong(), untilCheckpoint).toInt()
            out.write(bytes, cursor, chunk)
            digest.update(bytes, cursor, chunk)
            count += chunk.toLong()
            cursor += chunk
            remaining -= chunk
            if (count == nextCheckpoint) {
                checkpoint.checkpoint("while projecting function-observation output")
                nextCheckpoint = Math.addExact(nextCheckpoint, OUTPUT_CHECKPOINT_BYTES)
            }
        }
    }

    fun finish(): FunctionObservationStreamDigest {
        if (finished) sqliteFail("function-observation output digest is already complete")
        finished = true
        return FunctionObservationStreamDigest(digest.digest().hex(), count)
    }
}

private data class SqliteFunctionAlias(val name: String, val evidence: List<ByteArray>)
private data class SqliteDeclaration(val document: JsonObject, val bytes: ByteArray)
private data class FunctionObservationStreamDigest(val sha256: String, val bytes: Long)
private data class FunctionObservationNonEmittedProjectionCounts(val entities: Long, val dies: Long)

private class SqliteCanonicalObservationBudget(private val maximumBytes: Int) {
    private var bytes = 0L

    fun charge(count: Int, label: String) {
        bytes = addCount(bytes, count.toLong(), "canonical observation byte")
        if (bytes > maximumBytes.toLong()) {
            sqliteFail("$label exceeds the per-subprogram canonical byte bound")
        }
    }
}

private class CanonicalBytesKey(bytes: ByteArray) {
    private val value = bytes.copyOf()

    override fun equals(other: Any?): Boolean = other is CanonicalBytesKey && value.contentEquals(other.value)
    override fun hashCode(): Int = value.contentHashCode()
}

private enum class SinkState {
    OPEN,
    MUTATING,
    FINISHING,
    PROJECTING,
    FINISHED,
    FAILED,
    CLOSED,
}

private fun canonicalBytes(value: JsonElement, label: String): ByteArray = try {
    OracleJson.canonicalBytes(value, FULL_TREE_FUNCTION_OBSERVATION_JSON_LIMITS)
} catch (failure: Exception) {
    throw FullTreeFunctionObservationSqliteException("$label is not bounded canonical JSON", failure)
}

private fun requireScalar(value: String, maximumCodePoints: Int, label: String) {
    if (value.isEmpty() || '\u0000' in value || value.codePointCount(0, value.length) > maximumCodePoints) {
        sqliteFail("$label is empty, contains NUL, or exceeds its code-point bound")
    }
    var index = 0
    while (index < value.length) {
        val current = value[index]
        when {
            Character.isHighSurrogate(current) -> {
                if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) {
                    sqliteFail("$label contains an unpaired surrogate")
                }
                index += 2
            }
            Character.isLowSurrogate(current) -> sqliteFail("$label contains an unpaired surrogate")
            else -> index++
        }
    }
}

private fun unsignedKey(value: ULong): ByteArray =
    ByteArray(8) { index -> ((value shr ((7 - index) * 8)) and 0xffUL).toByte() }

private fun canonicalAddress(key: ByteArray): String {
    if (key.size != 8) sqliteFail("stored unsigned function-observation key has the wrong width")
    var value = 0UL
    key.forEach { byte -> value = (value shl 8) or (byte.toInt() and 0xff).toULong() }
    return "0x${value.toString(16)}"
}

private fun requireSha256(value: String, label: String) {
    if (!value.matches(SHA256)) sqliteFail("$label SHA-256 is invalid")
}

private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).hex()

private fun addCount(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeFunctionObservationSqliteException("$label count overflows", failure)
}

private fun pragmaLong(connection: Connection, name: String): Long =
    connection.createStatement().use { statement ->
        statement.executeQuery("PRAGMA $name").use { rows ->
            if (!rows.next()) sqliteFail("function-observation SQLite PRAGMA $name is absent")
            val value = rows.getLong(1)
            if (rows.next()) sqliteFail("function-observation SQLite PRAGMA $name is contradictory")
            value
        }
    }

private fun translateFunctionObservationSqliteFailure(message: String, failure: Throwable): Throwable =
    when (failure) {
        is FullTreeFunctionObservationSqliteException -> failure
        is SQLException -> FullTreeFunctionObservationSqliteException(message, failure)
        else -> failure
    }

private fun sqliteFail(message: String): Nothing = throw FullTreeFunctionObservationSqliteException(message)

private const val SQLITE_PAGE_BYTES = 4096
private const val SQLITE_TEMP_STORE_FILE = 1
private const val SQLITE_APPLICATION_ID = 0x46544f46
private const val SQLITE_SCHEMA_VERSION = 1
private const val OUTPUT_CHECKPOINT_BYTES = 1024L * 1024L
private val SHA256 = Regex("[0-9a-f]{64}")
private val SQLITE_PRIVATE_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
private val SQLITE_PRIVATE_FILE_PERMISSIONS = PosixFilePermissions.fromString("rw-------")

private val SCHEMA = listOf(
    "CREATE TABLE observed_die(" +
        "die_offset BLOB PRIMARY KEY CHECK(typeof(die_offset)='blob' AND length(die_offset)=8)) WITHOUT ROWID",
    "CREATE TABLE emitted_rva(" +
        "rva BLOB PRIMARY KEY CHECK(typeof(rva)='blob' AND length(rva)=8)," +
        "owner_count INTEGER NOT NULL DEFAULT 0 CHECK(owner_count>=0)," +
        "declaration_count INTEGER NOT NULL DEFAULT 0 CHECK(declaration_count>=0)," +
        "alias_count INTEGER NOT NULL DEFAULT 0 CHECK(alias_count>=0)) WITHOUT ROWID",
    "CREATE TABLE emitted_owner(" +
        "rva BLOB NOT NULL,unit_id TEXT NOT NULL COLLATE BINARY," +
        "PRIMARY KEY(rva,unit_id),FOREIGN KEY(rva) REFERENCES emitted_rva(rva)) WITHOUT ROWID",
    "CREATE TABLE emitted_declaration(" +
        "rva BLOB NOT NULL,canonical BLOB NOT NULL," +
        "PRIMARY KEY(rva,canonical),FOREIGN KEY(rva) REFERENCES emitted_rva(rva)) WITHOUT ROWID",
    "CREATE TABLE emitted_alias(" +
        "rva BLOB NOT NULL,name TEXT NOT NULL COLLATE BINARY," +
        "evidence_count INTEGER NOT NULL DEFAULT 0 CHECK(evidence_count>=0)," +
        "PRIMARY KEY(rva,name),FOREIGN KEY(rva) REFERENCES emitted_rva(rva)) WITHOUT ROWID",
    "CREATE TABLE emitted_evidence(" +
        "rva BLOB NOT NULL,name TEXT NOT NULL COLLATE BINARY,canonical BLOB NOT NULL," +
        "PRIMARY KEY(rva,name,canonical)," +
        "FOREIGN KEY(rva,name) REFERENCES emitted_alias(rva,name)) WITHOUT ROWID",
    "CREATE TABLE non_emitted_group(" +
        "group_key BLOB PRIMARY KEY CHECK(typeof(group_key)='blob' AND length(group_key)=16)," +
        "identity BLOB NOT NULL,identifier TEXT NOT NULL COLLATE BINARY,declaration BLOB NOT NULL," +
        "alias_count INTEGER NOT NULL DEFAULT 0 CHECK(alias_count>=0)," +
        "owner_count INTEGER NOT NULL DEFAULT 0 CHECK(owner_count>=0)) WITHOUT ROWID",
    "CREATE UNIQUE INDEX non_emitted_group_identifier ON non_emitted_group(identifier)",
    "CREATE TABLE non_emitted_alias(" +
        "group_key BLOB NOT NULL,name TEXT NOT NULL COLLATE BINARY," +
        "evidence_count INTEGER NOT NULL DEFAULT 0 CHECK(evidence_count>=0)," +
        "PRIMARY KEY(group_key,name)," +
        "FOREIGN KEY(group_key) REFERENCES non_emitted_group(group_key)) WITHOUT ROWID",
    "CREATE TABLE non_emitted_evidence(" +
        "group_key BLOB NOT NULL,name TEXT NOT NULL COLLATE BINARY,canonical BLOB NOT NULL," +
        "PRIMARY KEY(group_key,name,canonical)," +
        "FOREIGN KEY(group_key,name) REFERENCES non_emitted_alias(group_key,name)) WITHOUT ROWID",
    "CREATE TABLE non_emitted_die(" +
        "group_key BLOB NOT NULL,unit_id TEXT NOT NULL COLLATE BINARY,die_offset BLOB NOT NULL," +
        "PRIMARY KEY(group_key,unit_id,die_offset)," +
        "FOREIGN KEY(group_key) REFERENCES non_emitted_group(group_key)) WITHOUT ROWID",
    "CREATE TABLE non_emitted_owner(" +
        "group_key BLOB NOT NULL,unit_id TEXT NOT NULL COLLATE BINARY," +
        "PRIMARY KEY(group_key,unit_id)," +
        "FOREIGN KEY(group_key) REFERENCES non_emitted_group(group_key)) WITHOUT ROWID",
    "CREATE TABLE non_emitted_reason(" +
        "group_key BLOB NOT NULL,reason TEXT NOT NULL COLLATE BINARY," +
        "PRIMARY KEY(group_key,reason)," +
        "FOREIGN KEY(group_key) REFERENCES non_emitted_group(group_key)) WITHOUT ROWID",
)

private val PROJECTION_QUERIES = listOf(
    "SELECT rva FROM emitted_rva ORDER BY rva",
    "SELECT name FROM emitted_alias WHERE rva=x'0000000000000000' ORDER BY name",
    "SELECT canonical FROM emitted_evidence " +
        "WHERE rva=x'0000000000000000' AND name='' ORDER BY canonical",
    "SELECT canonical FROM emitted_declaration WHERE rva=x'0000000000000000' ORDER BY canonical",
    "SELECT unit_id FROM emitted_owner WHERE rva=x'0000000000000000' ORDER BY unit_id",
    "SELECT group_key,identifier,declaration FROM non_emitted_group ORDER BY identifier",
    "SELECT name FROM non_emitted_alias WHERE group_key=x'00000000000000000000000000000000' ORDER BY name",
    "SELECT canonical FROM non_emitted_evidence " +
        "WHERE group_key=x'00000000000000000000000000000000' AND name='' ORDER BY canonical",
    "SELECT unit_id,die_offset FROM non_emitted_die " +
        "WHERE group_key=x'00000000000000000000000000000000' ORDER BY unit_id,die_offset",
    "SELECT reason FROM non_emitted_reason " +
        "WHERE group_key=x'00000000000000000000000000000000' ORDER BY reason",
    "SELECT unit_id FROM non_emitted_owner " +
        "WHERE group_key=x'00000000000000000000000000000000' ORDER BY unit_id",
)
