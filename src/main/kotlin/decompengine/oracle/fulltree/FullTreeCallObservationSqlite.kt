package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager
import kotlinx.serialization.json.JsonObject

internal data class FullTreeCallObservationSqliteLimits(
    val maximumDatabaseBytes: Long = 2L * 1024L * 1024L * 1024L,
    val maximumOutputBytes: Long = 512L * 1024L * 1024L,
    val maximumCalls: Int = 1_000_000,
    val maximumScannedDies: Long = 50_000_000L,
    val maximumRecordBytes: Int = 1024 * 1024,
    val maximumCacheBytes: Int = 8 * 1024 * 1024,
    val databaseCheckpointRows: Int = 4096,
) {
    init {
        require(maximumDatabaseBytes in CALL_SQLITE_PAGE_BYTES..16L * 1024L * 1024L * 1024L)
        require(maximumOutputBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumCalls in 1..10_000_000)
        require(maximumScannedDies in 1L..1_000_000_000L)
        require(maximumRecordBytes in 1..4 * 1024 * 1024)
        require(maximumCacheBytes in 1024..64 * 1024 * 1024)
        require(databaseCheckpointRows in 1..1_000_000)
    }
}

internal data class FullTreeCallObservationStreamResult(
    val outputSha256: String,
    val outputBytes: Long,
    val entities: Long,
    val scored: Long,
    val scannedDies: Long,
    val databaseHighWaterBytes: Long,
) {
    val authoritativeReleaseEvidence: Boolean get() = false
}

internal class FullTreeCallObservationSqlite private constructor(
    private val workspace: CallSqliteWorkspace,
    private val connection: Connection,
    private val shard: FullTreeCallObservationShardInput,
    private val inventoryIndexSha256: String,
    private val richArtifactSha256: String,
    private val scopeSha256: String,
    private val limits: FullTreeCallObservationSqliteLimits,
    private val validateRecord: (JsonObject) -> String,
    private val checkpoint: (String) -> Unit,
) : AutoCloseable {
    private val insert = connection.prepareStatement("INSERT INTO calls(id,die,canonical) VALUES(?,?,?)")
    private val jsonLimits = StrictJsonLimits(
        maximumInputBytes = limits.maximumRecordBytes,
        maximumCanonicalBytes = limits.maximumRecordBytes,
        maximumTotalStringBytes = limits.maximumRecordBytes,
    )
    private var state = CallSqliteState.OPEN
    private var calls = 0L
    private var scored = 0L
    private var scannedDies = 0L

    fun recordScannedDies(count: Long) = mutate {
        require(count > 0L) { "call-observation DIE increment is invalid" }
        scannedDies = Math.addExact(scannedDies, count)
        require(scannedDies <= limits.maximumScannedDies) { "call-observation scan exceeds its DIE bound" }
        checkpoint("after counting call-observation DIEs")
    }

    fun accept(observation: FullTreeObservedCallSite) = mutate {
        checkpoint("before accepting a SQLite call observation")
        require(calls < limits.maximumCalls) { "call-observation population exceeds its bound" }
        require(observation.target.aliases.size <= 256 && observation.target.provenFunctionIds.size <= 1) {
            "call-observation target population exceeds its bound"
        }
        val document = callObservationDocument(observation)
        val bytes = OracleJson.canonicalBytes(document, jsonLimits)
        OracleSchemas.validate(
            "full-tree-call-observations",
            envelope(listOf(document), 1L, if (observation.population == "scored") 1L else 0L, shard.units.size + 1L),
        )
        val identifier = validateRecord(document)
        insert.setString(1, identifier)
        insert.setBytes(2, ByteArray(8) { index ->
            ((observation.dieOffset shr ((7 - index) * 8)) and 0xffUL).toByte()
        })
        insert.setBytes(3, bytes)
        require(insert.executeUpdate() == 1) { "call-observation insert did not retain exactly one call" }
        calls++
        if (observation.population == "scored") scored++
        if (calls % limits.databaseCheckpointRows == 0L) {
            connection.commit()
            workspace.verify("while accumulating calls")
            checkpoint("after committing SQLite call observations")
        }
    }

    fun finishTo(output: OutputStream): FullTreeCallObservationStreamResult {
        require(state == CallSqliteState.OPEN) { "call-observation SQLite sink is not open" }
        state = CallSqliteState.ACTIVE
        try {
            require(scannedDies >= shard.units.size.toLong() + calls) {
                "call-observation scan cannot cover its evidence"
            }
            checkpoint("before projecting SQLite call observations")
            connection.commit()
            workspace.verify("before call projection")
            val allocated = Math.multiplyExact(pragma(connection, "page_count"), CALL_SQLITE_PAGE_BYTES)
            require(allocated == workspace.highWaterBytes) { "call-observation SQLite allocation differs" }
            connection.createStatement().use { statement ->
                statement.executeQuery("EXPLAIN QUERY PLAN $CALL_PROJECTION").use { rows ->
                    while (rows.next()) {
                        require("USE TEMP B-TREE" !in rows.getString(4).uppercase()) {
                            "call-observation projection requires unmanaged temporary sorting"
                        }
                    }
                }
            }
            val writer = CallDigestingOutput(output, limits.maximumOutputBytes, checkpoint)
            writer.ascii("{\n  \"calls\": [")
            var emitted = 0L
            connection.createStatement().use { statement ->
                statement.executeQuery(CALL_PROJECTION).use { rows ->
                    while (rows.next()) {
                        checkpoint("while projecting a SQLite call observation")
                        writer.ascii(if (emitted == 0L) "\n" else ",\n")
                        val bytes = rows.getBytes(1)
                        require(bytes.size <= limits.maximumRecordBytes) { "stored call exceeds its record bound" }
                        writer.indentedRecord(bytes)
                        emitted++
                    }
                }
            }
            require(emitted == calls) { "call-observation projection population differs" }
            writer.ascii(if (calls == 0L) "],\n" else "\n  ],\n")
            val trailer = OracleJson.canonicalBytes(envelope(emptyList(), calls, scored, scannedDies))
            val emptyCallsPrefix = "{\n  \"calls\": [],\n".toByteArray(Charsets.US_ASCII)
            require(trailer.take(emptyCallsPrefix.size).toByteArray().contentEquals(emptyCallsPrefix)) {
                "call-observation envelope canonical ordering changed"
            }
            writer.write(trailer, emptyCallsPrefix.size, trailer.size - emptyCallsPrefix.size)
            checkpoint("after projecting SQLite call observations")
            workspace.verify("after call projection")
            state = CallSqliteState.FINISHED
            return FullTreeCallObservationStreamResult(
                writer.sha256(), writer.bytes, calls, scored, scannedDies, workspace.highWaterBytes,
            )
        } catch (failure: Throwable) {
            state = CallSqliteState.FAILED
            throw failure
        }
    }

    private fun envelope(documents: List<JsonObject>, count: Long, scoredCount: Long, dies: Long) =
        callObservationEnvelope(
            shard, inventoryIndexSha256, richArtifactSha256, scopeSha256, documents, count, scoredCount, dies,
        )

    private inline fun mutate(action: () -> Unit) {
        require(state == CallSqliteState.OPEN) { "call-observation SQLite sink is not open" }
        state = CallSqliteState.ACTIVE
        try {
            action()
            state = CallSqliteState.OPEN
        } catch (failure: Throwable) {
            state = CallSqliteState.FAILED
            throw failure
        }
    }

    override fun close() {
        if (state == CallSqliteState.CLOSED) return
        require(state != CallSqliteState.ACTIVE) { "call-observation SQLite operation is in progress" }
        state = CallSqliteState.CLOSED
        var failure: Throwable? = null
        listOf<() -> Unit>(insert::close, connection::close, workspace::close).forEach { cleanup ->
            try {
                cleanup()
            } catch (caught: Throwable) {
                if (failure == null) failure = caught else failure.addSuppressed(caught)
            }
        }
        failure?.let { throw it }
    }

    companion object {
        fun open(
            scratchParent: Path,
            inputs: FullTreeCallObservationAuthenticatedInputs,
            scope: AuthenticatedFullTreeScope,
            limits: FullTreeCallObservationSqliteLimits,
            checkpoint: (String) -> Unit,
        ): FullTreeCallObservationSqlite {
            val expected = FullTreeCallObservations.shardInputs(
                inputs.inventory, inputs.inventoryArtifactSha256, scope.document, scope.sha256,
            ).singleOrNull { it.identifier == inputs.shard.identifier }
            require(expected != null && expected.inputSha256 == inputs.shard.inputSha256 && expected.units == inputs.shard.units) {
                "call-observation SQLite input is not authenticated"
            }
            val bounds = scope.document.controlObject("bounds").controlObject("perShard")
            require(limits.maximumCalls.toLong() <= bounds.controlLong("entities")) {
                "call-observation SQLite entity limit exceeds its authenticated bound"
            }
            require(limits.maximumOutputBytes <= bounds.controlLong("serializedBytes")) {
                "call-observation SQLite output limit exceeds its authenticated bound"
            }
            val workspace = CallSqliteWorkspace.create(scratchParent, limits.maximumDatabaseBytes)
            var connection: Connection? = null
            try {
                connection = DriverManager.getConnection(SqliteJdbcPaths.create(workspace.database))
                configure(connection, limits)
                workspace.verify("after opening call-observation SQLite state")
                checkpoint("after opening call-observation SQLite state")
                connection.autoCommit = false
                return FullTreeCallObservationSqlite(
                    workspace, connection, inputs.shard, inputs.inventory.controlString("indexSha256"),
                    scope.document.controlObject("oracle").controlString("richArtifactSha256"), scope.sha256,
                    limits, FullTreeCallObservations.recordValidator(inputs.inventory, inputs.shard), checkpoint,
                )
            } catch (failure: Throwable) {
                listOf<() -> Unit>({ connection?.close() }, workspace::close).forEach { cleanup ->
                    try {
                        cleanup()
                    } catch (caught: Throwable) {
                        failure.addSuppressed(caught)
                    }
                }
                throw failure
            }
        }

        private fun configure(connection: Connection, limits: FullTreeCallObservationSqliteLimits) {
            val maximumPages = limits.maximumDatabaseBytes / CALL_SQLITE_PAGE_BYTES
            connection.createStatement().use { statement ->
                listOf(
                    "page_size=$CALL_SQLITE_PAGE_BYTES", "journal_mode=OFF", "synchronous=OFF",
                    "temp_store=FILE", "cache_size=-${limits.maximumCacheBytes / 1024}", "mmap_size=0",
                    "locking_mode=EXCLUSIVE", "automatic_index=OFF", "auto_vacuum=NONE", "threads=1",
                    "max_page_count=$maximumPages",
                ).forEach { statement.execute("PRAGMA $it") }
                statement.execute(
                    "CREATE TABLE calls(id TEXT PRIMARY KEY COLLATE BINARY,die BLOB NOT NULL UNIQUE " +
                        "CHECK(typeof(die)='blob' AND length(die)=8),canonical BLOB NOT NULL) WITHOUT ROWID",
                )
                statement.executeQuery("PRAGMA journal_mode").use { rows ->
                    require(rows.next() && rows.getString(1) == "off" && !rows.next()) {
                        "call-observation SQLite journal mode differs"
                    }
                }
            }
            require(
                pragma(connection, "page_size") == CALL_SQLITE_PAGE_BYTES &&
                    pragma(connection, "max_page_count") == maximumPages &&
                    pragma(connection, "temp_store") == 1L && pragma(connection, "mmap_size") == 0L &&
                    pragma(connection, "automatic_index") == 0L && pragma(connection, "auto_vacuum") == 0L &&
                    pragma(connection, "cache_size") == -(limits.maximumCacheBytes / 1024).toLong(),
            ) { "call-observation SQLite resource configuration differs" }
        }
    }
}

private class CallSqliteWorkspace private constructor(
    private val parent: Path,
    private val parentIdentity: Any,
    private val root: Path,
    private val rootIdentity: Any,
    val database: Path,
    private val databaseIdentity: Any,
    private val maximumBytes: Long,
) : AutoCloseable {
    var highWaterBytes: Long = 0L
        private set

    fun verify(label: String) {
        require(requireStableDirectory(parent, "call-observation scratch parent").second == parentIdentity) {
            "call-observation scratch parent changed $label"
        }
        require(attributes(root).let { it.isDirectory && it.fileKey() == rootIdentity }) {
            "call-observation SQLite root changed $label"
        }
        require(Files.getPosixFilePermissions(root, LinkOption.NOFOLLOW_LINKS) == CALL_DIRECTORY_PERMISSIONS) {
            "call-observation SQLite root permissions changed $label"
        }
        Files.newDirectoryStream(root).use { children ->
            var count = 0
            children.forEach { child ->
                require(child == database && count++ == 0) { "unexpected call-observation scratch member $label" }
            }
            require(count == 1) { "call-observation SQLite database disappeared $label" }
        }
        val current = attributes(database)
        require(current.isRegularFile && current.fileKey() == databaseIdentity && current.size() <= maximumBytes) {
            "call-observation SQLite database changed or exceeds its bound $label"
        }
        require(
            Files.getPosixFilePermissions(database, LinkOption.NOFOLLOW_LINKS) == CALL_FILE_PERMISSIONS &&
                (Files.getAttribute(database, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toLong() == 1L,
        ) { "call-observation SQLite database permissions or link count changed $label" }
        highWaterBytes = maxOf(highWaterBytes, current.size())
    }

    override fun close() {
        verify("before cleanup")
        Files.delete(database)
        Files.delete(root)
    }

    companion object {
        fun create(parent: Path, maximumBytes: Long): CallSqliteWorkspace {
            val (trustedParent, parentIdentity) = requireStableDirectory(parent, "call-observation scratch parent")
            val root = Files.createTempDirectory(
                trustedParent, ".call-observation-sqlite-",
                PosixFilePermissions.asFileAttribute(CALL_DIRECTORY_PERMISSIONS),
            )
            var database: Path? = null
            try {
                val rootIdentity = requireNotNull(attributes(root).fileKey())
                database = Files.createFile(
                    root.resolve("calls.sqlite"), PosixFilePermissions.asFileAttribute(CALL_FILE_PERMISSIONS),
                )
                return CallSqliteWorkspace(
                    trustedParent, parentIdentity, root, rootIdentity, database,
                    requireNotNull(attributes(database).fileKey()), maximumBytes,
                ).also { it.verify("after creation") }
            } catch (failure: Throwable) {
                try {
                    database?.let(Files::deleteIfExists)
                    Files.delete(root)
                } catch (caught: Throwable) {
                    failure.addSuppressed(caught)
                }
                throw failure
            }
        }

        private fun attributes(path: Path): BasicFileAttributes =
            Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    }
}

private class CallDigestingOutput(
    private val output: OutputStream,
    private val maximumBytes: Long,
    private val checkpoint: (String) -> Unit,
) {
    private val digest = MessageDigest.getInstance("SHA-256")
    var bytes = 0L
        private set

    fun ascii(value: String) = write(value.toByteArray(Charsets.US_ASCII))

    fun write(value: ByteArray, offset: Int = 0, length: Int = value.size) {
        require(bytes <= maximumBytes - length.toLong()) { "call-observation output exceeds its byte bound" }
        var cursor = offset
        val end = offset + length
        while (cursor < end) {
            val count = minOf(end - cursor, 64 * 1024)
            checkpoint("while writing call-observation canonical bytes")
            output.write(value, cursor, count)
            digest.update(value, cursor, count)
            bytes += count
            cursor += count
        }
    }

    fun indentedRecord(record: ByteArray) {
        require(record.lastOrNull() == '\n'.code.toByte()) { "stored call lacks its canonical newline" }
        var start = 0
        for (offset in record.indices) {
            if (record[offset] == '\n'.code.toByte()) {
                ascii("    ")
                write(record, start, offset - start)
                if (offset < record.lastIndex) ascii("\n")
                start = offset + 1
            }
        }
    }

    fun sha256(): String = digest.digest().joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
}

private fun pragma(connection: Connection, name: String): Long = connection.createStatement().use { statement ->
    statement.executeQuery("PRAGMA $name").use { rows ->
        require(rows.next()) { "call-observation SQLite PRAGMA $name is absent" }
        val value = rows.getLong(1)
        require(!rows.next()) { "call-observation SQLite PRAGMA $name is ambiguous" }
        value
    }
}

private enum class CallSqliteState { OPEN, ACTIVE, FINISHED, FAILED, CLOSED }
private const val CALL_SQLITE_PAGE_BYTES = 4096L
private const val CALL_PROJECTION = "SELECT canonical FROM calls ORDER BY id"
private val CALL_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
private val CALL_FILE_PERMISSIONS = PosixFilePermissions.fromString("rw-------")
