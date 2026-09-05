package decompengine.oracle.fulltree

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.io.BufferedOutputStream
import java.io.FilterOutputStream
import java.io.OutputStream
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.sqlite.ProgressHandler

internal class FullTreeCallBaselineException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

internal data class FullTreeCallBaselineLimits(
    val truth: FullTreeCallTruthLimits = FullTreeCallTruthLimits(),
    val maximumBaselineBytes: Long = 4L * CALL_BASELINE_GIB,
    val maximumDatabaseBytes: Long = CALL_BASELINE_GIB,
    val maximumScratchBytes: Long = 16L * CALL_BASELINE_GIB,
    val maximumEntities: Long = 50_000_000L,
    val maximumEntityBytes: Int = 64 * 1024 * 1024,
    val maximumEntityNodes: Int = 1_000_000,
    val maximumStringBytes: Int = 1024 * 1024,
    val maximumTokensPerInput: Long = 1_000_000_000L,
    val maximumSqliteCacheBytes: Int = 4 * 1024 * 1024,
    val databaseCheckpointRows: Int = 4096,
    val modeledResidentBytes: Long = CALL_BASELINE_GIB,
) {
    init {
        require(maximumBaselineBytes in 1L..8L * CALL_BASELINE_GIB)
        require(maximumDatabaseBytes in 4096L..8L * CALL_BASELINE_GIB)
        require(maximumScratchBytes in maximumDatabaseBytes..16L * CALL_BASELINE_GIB)
        require(maximumEntities in 1L..50_000_000L)
        require(maximumEntityBytes in 1..64 * 1024 * 1024)
        require(maximumEntityNodes in 1..1_000_000)
        require(maximumStringBytes in 1..maximumEntityBytes)
        require(maximumTokensPerInput in 1L..1_000_000_000L)
        require(maximumSqliteCacheBytes in 1024..64 * 1024 * 1024)
        require(databaseCheckpointRows in 1..1_000_000)
        require(modeledResidentBytes in 1L..2L * CALL_BASELINE_GIB)
        require(modeledResidentBytes >= truth.modeledResidentBytes + maximumSqliteCacheBytes +
            maximumEntityBytes.toLong() * 4L + 32L * 1024 * 1024)
    }
}

internal data class FullTreeCallBaselineMetric(val exact: Long, val partial: Long, val excluded: Long) {
    val denominator: Long = Math.addExact(exact, partial)
    val missing: Long = 0L
    val fabricated: Long = 0L

    init {
        require(exact >= 0L && partial >= 0L && excluded >= 0L)
    }

    fun toJson(): JsonObject = JsonObject(mapOf(
        "denominator" to JsonPrimitive(denominator), "exact" to JsonPrimitive(exact),
        "excluded" to JsonPrimitive(excluded), "fabricated" to JsonPrimitive(fabricated),
        "missing" to JsonPrimitive(missing), "partial" to JsonPrimitive(partial),
    ))
}

internal class FullTreeCallBaselinePublication internal constructor(
    val root: Path,
    val reportSha256: String,
    val artifactSha256: String,
    val truthIndexArtifactSha256: String,
    val outputBytes: Long,
    val databaseHighWaterBytes: Long,
    val aggregate: FullTreeCallBaselineMetric,
    val candidateBytesMatchedAtValidationBoundary: Boolean,
) {
    val rawInputsRederived: Boolean = true
    val candidateLeaseRetained: Boolean = false
    val downstreamScoringAuthorized: Boolean = false
    val authoritativeReleaseEvidence: Boolean = false
    val recoveredModelScored: Boolean = false
}

internal object FullTreeCallBaselineSqlite {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256("full-tree-call-baseline", CALL_BASELINE_POLICY)
    }

    fun generateAndPublishFromRawInputs(
        callTruthRoot: Path,
        richArtifact: Path,
        strippedArtifact: Path,
        inventoryPath: Path,
        elfFunctionIndex: Path,
        functionObservationRoot: Path,
        expectedFunctionObservationIndexArtifactSha256: String,
        functionTruthRoot: Path,
        callObservationRoot: Path,
        expectedCallObservationIndexArtifactSha256: String,
        scope: AuthenticatedFullTreeScope,
        scratchParent: Path,
        outputRoot: Path,
        maximumWorkers: Int,
        limits: FullTreeCallBaselineLimits = FullTreeCallBaselineLimits(),
    ): FullTreeCallBaselinePublication = deriveCallBaseline(
        callTruthRoot, richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex,
        functionObservationRoot, expectedFunctionObservationIndexArtifactSha256, functionTruthRoot,
        callObservationRoot, expectedCallObservationIndexArtifactSha256, scope, scratchParent,
        outputRoot, maximumWorkers, limits, false,
    )

    fun loadAndValidateFromRawInputs(
        candidateRoot: Path,
        callTruthRoot: Path,
        richArtifact: Path,
        strippedArtifact: Path,
        inventoryPath: Path,
        elfFunctionIndex: Path,
        functionObservationRoot: Path,
        expectedFunctionObservationIndexArtifactSha256: String,
        functionTruthRoot: Path,
        callObservationRoot: Path,
        expectedCallObservationIndexArtifactSha256: String,
        scope: AuthenticatedFullTreeScope,
        scratchParent: Path,
        maximumWorkers: Int,
        limits: FullTreeCallBaselineLimits = FullTreeCallBaselineLimits(),
    ): FullTreeCallBaselinePublication = deriveCallBaseline(
        callTruthRoot, richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex,
        functionObservationRoot, expectedFunctionObservationIndexArtifactSha256, functionTruthRoot,
        callObservationRoot, expectedCallObservationIndexArtifactSha256, scope, scratchParent,
        candidateRoot, maximumWorkers, limits, true,
    )
}

private fun deriveCallBaseline(
    callTruthRoot: Path,
    richArtifact: Path,
    strippedArtifact: Path,
    inventoryPath: Path,
    elfFunctionIndex: Path,
    functionObservationRoot: Path,
    expectedFunctionObservationIndexArtifactSha256: String,
    functionTruthRoot: Path,
    callObservationRoot: Path,
    expectedCallObservationIndexArtifactSha256: String,
    scope: AuthenticatedFullTreeScope,
    scratchParent: Path,
    resultRoot: Path,
    maximumWorkers: Int,
    limits: FullTreeCallBaselineLimits,
    validating: Boolean,
): FullTreeCallBaselinePublication = translateCallBaselineFailure {
    if (limits.maximumScratchBytes < limits.truth.maximumScratchBytes) {
        callBaselineFail("call-baseline scratch ceiling does not admit its nested raw derivation")
    }
    FullTreeScopeControl.validate(scope, limits.truth.truth.control)
    if (limits.modeledResidentBytes > scope.document.controlObject("bounds").controlObject("wholeRun")
            .controlLong("maximumResidentBytes")
    ) callBaselineFail("call-baseline modeled resident bound exceeds the scope")
    val target = resultRoot.toAbsolutePath().normalize()
    if (!validating && Files.exists(target, LinkOption.NOFOLLOW_LINKS)) callBaselineFail("call-baseline target already exists")
    FullTreeCallTruthSqlite.withValidatedBaselineProjection(
        callTruthRoot, richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex,
        functionObservationRoot, expectedFunctionObservationIndexArtifactSha256, functionTruthRoot,
        callObservationRoot, expectedCallObservationIndexArtifactSha256, scope, scratchParent,
        target, maximumWorkers, limits.truth,
    ) { raw ->
        val context = CallBaselineContext(raw, limits)
        context.reserveDatabase()
        CallBaselineScratch.create(raw.scratchParent).use { scratch ->
            CallBaselineStage.create(if (validating) scratch.root else target.parent).use { stage ->
                val generated = CallBaselineDatabase.open(scratch.database, context).use { database ->
                    database.ingest()
                    database.writeReport(stage.report)
                }
                scratch.releaseDatabase()
                stage.freeze(generated, raw::terminalCheckpoint)
                raw.recheck("after deriving the call observability baseline")
                if (validating) {
                    compareCallBaseline(target, stage.root, generated, raw::terminalCheckpoint)
                    raw.recheck("at raw call-baseline candidate comparison")
                    compareCallBaseline(target, stage.root, generated, raw::terminalCheckpoint)
                    stage.close()
                    scratch.close()
                    raw.release()
                    verifyCallBaselineTree(target, generated, raw::terminalCheckpoint)
                } else {
                    scratch.close()
                    stage.publish(target, generated, raw)
                }
                FullTreeCallBaselinePublication(
                    target, generated.reportSha256, generated.sha256, raw.indexArtifactSha256,
                    generated.bytes, context.databaseHighWaterBytes, generated.aggregate, validating,
                )
            }
        }
    }
}

private class CallBaselineContext(val raw: FullTreeCallBaselineRawProjection, val limits: FullTreeCallBaselineLimits) {
    private val whole = raw.scope.document.controlObject("bounds").controlObject("wholeRun")
    val maximumEntities = minOf(limits.maximumEntities, whole.controlLong("entities"))
    val maximumBytes = minOf(limits.maximumBaselineBytes, whole.controlLong("serializedBytes"))
    var databaseHighWaterBytes = 0L
        private set
    private var reservation = 0L

    fun reserveDatabase() {
        reservation = Math.addExact(checkpoint("before reserving call-baseline scratch"), limits.maximumDatabaseBytes)
        if (reservation > limits.maximumScratchBytes) callBaselineFail("call-baseline database reservation exceeds scratch bound")
    }

    fun checkpoint(label: String): Long = raw.checkpoint(label).also {
        if (it > limits.maximumScratchBytes) callBaselineFail("call-baseline scratch bound exceeded $label")
    }

    fun checkDatabase(path: Path) {
        val bytes = Files.size(path)
        if (bytes > limits.maximumDatabaseBytes) callBaselineFail("call-baseline database bound exceeded")
        databaseHighWaterBytes = maxOf(databaseHighWaterBytes, bytes)
        checkpoint("while checking call-baseline database")
    }

    fun chargeOutput(bytes: Long) {
        if (bytes > maximumBytes || Math.addExact(reservation, bytes) > limits.maximumScratchBytes) {
            callBaselineFail("call-baseline output or aggregate scratch bound exceeded")
        }
        raw.terminalCheckpoint("while serializing the bounded call baseline")
    }

    fun canonical(value: JsonElement): ByteArray = OracleJson.canonicalBytes(value, StrictJsonLimits(
        maximumInputBytes = limits.maximumEntityBytes, maximumCanonicalBytes = limits.maximumEntityBytes,
        maximumDepth = 128, maximumNodes = limits.maximumEntityNodes,
        maximumStringBytes = limits.maximumStringBytes, maximumTotalStringBytes = limits.maximumEntityBytes,
    ))
}

private class CallBaselineDatabase private constructor(
    private val connection: Connection,
    private val path: Path,
    private val context: CallBaselineContext,
) : AutoCloseable {
    private val limits = context.limits

    fun ingest() {
        val records = context.raw.index.controlArray("shards").controlObjects("raw call-truth shards")
        var edges = 0L
        var pending = 0
        connection.prepareStatement("INSERT INTO metrics VALUES(?,?,?,?)").use { metric ->
            connection.prepareStatement("INSERT INTO mismatches VALUES(?,?,?,?)").use { mismatch ->
                for (record in records) {
                    val owner = record.controlString("id")
                    val relative = record.controlString("path")
                    if (relative != "shards/$owner.json") callBaselineFail("raw call-truth shard path is not canonical")
                    var exact = 0L
                    var partial = 0L
                    var excluded = 0L
                    var shardEdges = 0L
                    val expectedEdges = record.controlLong("edges")
                    val stream = FullTreeCanonicalStreaming.readObject(
                        context.raw.root.resolve(relative), "raw call-baseline shard", record.controlString("sha256"),
                        CALL_BASELINE_TRUTH_FIELDS, setOf("calls"), null,
                        FullTreeCanonicalStreamingLimits(
                            maximumInputBytes = record.controlLong("bytes"), maximumTokens = limits.maximumTokensPerInput,
                            maximumEntities = maxOf(1L, minOf(context.maximumEntities, expectedEdges)),
                            maximumEntityBytes = limits.maximumEntityBytes, maximumEntityNodes = limits.maximumEntityNodes,
                            maximumStringBytes = limits.maximumStringBytes, maximumTotalStringBytes = record.controlLong("bytes"),
                        ),
                    ) { _, _, call, _ ->
                        edges = Math.addExact(edges, 1L)
                        shardEdges = Math.addExact(shardEdges, 1L)
                        if (edges > context.maximumEntities) callBaselineFail("call-baseline entity bound exceeded")
                        when (call.controlString("population")) {
                            "unobservable" -> excluded = Math.addExact(excluded, 1L)
                            "scored" -> {
                                val resolved = when (call.controlString("targetKind")) {
                                    "direct-internal" -> call.getValue("semanticTargetId") != JsonNull
                                    "external" -> call.controlArray("externalTargetIds").isNotEmpty()
                                    "indirect-proven" -> call.controlArray("provenTargetIds").isNotEmpty()
                                    "indirect-unresolved" -> false
                                    else -> callBaselineFail("scored call has an unsupported target kind")
                                }
                                if (resolved) exact = Math.addExact(exact, 1L) else {
                                    partial = Math.addExact(partial, 1L)
                                    val identifier = call.controlString("id")
                                    val mismatchId = "partial-call-" + OracleArtifacts.sha256(context.canonical(JsonObject(mapOf(
                                        "kind" to JsonPrimitive("partial"), "truthId" to JsonPrimitive(identifier),
                                    )))).take(32)
                                    mismatch.setString(1, mismatchId)
                                    mismatch.setString(2, identifier)
                                    mismatch.setString(3, owner)
                                    mismatch.setString(4, call.getValue("reasonCode").let {
                                        if (it == JsonNull) null else call.controlString("reasonCode")
                                    })
                                    if (mismatch.executeUpdate() != 1) callBaselineFail("call-baseline mismatch was not inserted exactly once")
                                }
                            }
                            else -> callBaselineFail("raw call population is unsupported")
                        }
                        pending++
                        if (pending >= limits.databaseCheckpointRows) {
                            connection.commit()
                            context.checkDatabase(path)
                            pending = 0
                        }
                        context.raw.terminalCheckpoint("while classifying a raw call for its baseline")
                    }
                    if (shardEdges != expectedEdges || stream.sourceBytes != record.controlLong("bytes") ||
                        stream.envelope.controlObject("shard").controlString("id") != owner ||
                        stream.envelope.controlObject("counts").controlLong("edges") != expectedEdges ||
                        excluded != record.controlLong("unobservable")
                    ) callBaselineFail("call-baseline raw shard population changed")
                    metric.setString(1, owner)
                    metric.setLong(2, exact)
                    metric.setLong(3, partial)
                    metric.setLong(4, excluded)
                    if (metric.executeUpdate() != 1) callBaselineFail("call-baseline shard was not inserted exactly once")
                    context.checkpoint("after ingesting one raw call-baseline shard")
                }
            }
        }
        if (edges != context.raw.index.controlObject("counts").controlLong("edges")) {
            callBaselineFail("call-baseline complete edge population changed")
        }
        connection.commit()
        context.checkDatabase(path)
    }

    fun writeReport(output: Path): CallBaselineGenerated {
        val aggregate = connection.createStatement().use { statement ->
            statement.executeQuery("SELECT COALESCE(SUM(exact),0),COALESCE(SUM(partial),0),COALESCE(SUM(excluded),0) FROM metrics").use { rows ->
                check(rows.next())
                FullTreeCallBaselineMetric(rows.getLong(1), rows.getLong(2), rows.getLong(3))
            }
        }
        val unsigned = writeDocument(OutputStream.nullOutputStream(), aggregate, null)
        val complete = FileChannel.open(output, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
            PosixFilePermissions.asFileAttribute(CALL_BASELINE_FILE)).use { channel ->
            val result = writeDocument(Channels.newOutputStream(channel), aggregate, unsigned.first)
            channel.force(true)
            result
        }
        context.checkpoint("after writing the complete call baseline")
        return CallBaselineGenerated(unsigned.first, complete.first, complete.second, aggregate)
    }

    private fun writeDocument(output: OutputStream, aggregate: FullTreeCallBaselineMetric, reportSha256: String?): Pair<String, Long> {
        val digest = MessageDigest.getInstance("SHA-256")
        var bytes = 0L
        val bounded = object : FilterOutputStream(output) {
            override fun write(value: Int) = write(byteArrayOf(value.toByte()), 0, 1)
            override fun write(buffer: ByteArray, offset: Int, length: Int) {
                bytes = Math.addExact(bytes, length.toLong())
                context.chargeOutput(bytes)
                out.write(buffer, offset, length)
                digest.update(buffer, offset, length)
            }
        }
        val buffered = BufferedOutputStream(bounded, 64 * 1024)
        val writer = CallBaselineWriter(buffered)
        writer.startObject()
        writer.field("aggregate"); writer.value(context.canonical(aggregate.toJson()))
        writer.field("configurationSha256"); writer.value(context.canonical(JsonPrimitive(FullTreeCallBaselineSqlite.configurationSha256)))
        writer.field("mismatches"); writer.startArray()
        connection.createStatement().use { statement ->
            statement.executeQuery("SELECT id,truth_id,shard_id,reason FROM mismatches ORDER BY id COLLATE BINARY").use { rows ->
                while (rows.next()) {
                    writer.arrayValue(context.canonical(JsonObject(mapOf(
                        "id" to JsonPrimitive(rows.getString(1)), "kind" to JsonPrimitive("partial"),
                        "truthId" to JsonPrimitive(rows.getString(2)), "shardId" to JsonPrimitive(rows.getString(3)),
                        "reasonCode" to (rows.getString(4)?.let(::JsonPrimitive) ?: JsonNull),
                    ))))
                    context.raw.terminalCheckpoint("while emitting call-baseline mismatches")
                }
            }
        }
        writer.endArray()
        if (reportSha256 != null) {
            writer.field("reportSha256"); writer.value(context.canonical(JsonPrimitive(reportSha256)))
        }
        writer.field("schemaVersion"); writer.value(context.canonical(JsonPrimitive(1)))
        writer.field("shards"); writer.startArray()
        connection.createStatement().use { statement ->
            statement.executeQuery("SELECT shard_id,exact,partial,excluded FROM metrics ORDER BY shard_id COLLATE BINARY").use { rows ->
                while (rows.next()) {
                    writer.arrayValue(context.canonical(JsonObject(mapOf(
                        "id" to JsonPrimitive(rows.getString(1)),
                        "metric" to FullTreeCallBaselineMetric(rows.getLong(2), rows.getLong(3), rows.getLong(4)).toJson(),
                    ))))
                    context.raw.terminalCheckpoint("while emitting call-baseline shard metrics")
                }
            }
        }
        writer.endArray()
        writer.field("truthIndexSha256"); writer.value(context.canonical(JsonPrimitive(context.raw.indexArtifactSha256)))
        writer.endObject()
        buffered.flush()
        return digest.digest().callBaselineHex() to bytes
    }

    override fun close() {
        try {
            ProgressHandler.clearHandler(connection)
        } finally {
            connection.close()
        }
    }

    companion object {
        fun open(path: Path, context: CallBaselineContext): CallBaselineDatabase {
            val connection = DriverManager.getConnection(SqliteJdbcPaths.create(path))
            try {
                connection.createStatement().use { statement ->
                    listOf("journal_mode=OFF", "synchronous=OFF", "temp_store=MEMORY", "mmap_size=0", "page_size=4096",
                        "cache_size=-${context.limits.maximumSqliteCacheBytes / 1024}",
                        "max_page_count=${context.limits.maximumDatabaseBytes / 4096}").forEach { statement.execute("PRAGMA $it") }
                    connection.autoCommit = false
                    statement.execute("CREATE TABLE metrics(shard_id TEXT COLLATE BINARY PRIMARY KEY,exact INTEGER NOT NULL,partial INTEGER NOT NULL,excluded INTEGER NOT NULL) WITHOUT ROWID")
                    statement.execute("CREATE TABLE mismatches(id TEXT COLLATE BINARY PRIMARY KEY,truth_id TEXT NOT NULL UNIQUE,shard_id TEXT NOT NULL,reason TEXT) WITHOUT ROWID")
                    for (query in listOf(
                        "SELECT id,truth_id,shard_id,reason FROM mismatches ORDER BY id COLLATE BINARY",
                        "SELECT shard_id,exact,partial,excluded FROM metrics ORDER BY shard_id COLLATE BINARY",
                    )) {
                        statement.executeQuery("EXPLAIN QUERY PLAN $query").use { rows ->
                            while (rows.next()) {
                                val detail = rows.getString("detail").uppercase()
                                if ("TEMP B-TREE" in detail || "AUTOMATIC" in detail) callBaselineFail("call-baseline SQL requires temporary sorting")
                            }
                        }
                    }
                }
                ProgressHandler.setHandler(connection, 10_000, object : ProgressHandler() {
                    override fun progress(): Int {
                        context.raw.terminalCheckpoint("during call-baseline SQLite execution")
                        return 0
                    }
                })
                connection.commit()
                context.checkDatabase(path)
                return CallBaselineDatabase(connection, path, context)
            } catch (failure: Throwable) {
                runCatching { connection.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

private data class CallBaselineGenerated(
    val reportSha256: String,
    val sha256: String,
    val bytes: Long,
    val aggregate: FullTreeCallBaselineMetric,
)

private class CallBaselineScratch private constructor(
    val root: Path,
    val database: Path,
    private val identity: Any,
    private val databaseIdentity: Any,
) : AutoCloseable {
    private var databaseReleased = false
    private var closed = false

    fun releaseDatabase() {
        if (databaseReleased) return
        requireCallBaselineIdentity(root, identity, true)
        requireCallBaselineIdentity(database, databaseIdentity, false)
        Files.delete(database)
        databaseReleased = true
        forceCallBaselineDirectory(root)
    }

    override fun close() {
        if (closed) return
        requireCallBaselineIdentity(root, identity, true)
        if (callBaselineMembers(root).any { it != "baseline.sqlite" }) {
            callBaselineFail("call-baseline scratch retained unexpected members")
        }
        releaseDatabase()
        if (callBaselineMembers(root).isNotEmpty()) callBaselineFail("call-baseline scratch is not empty")
        Files.delete(root)
        forceCallBaselineDirectory(root.parent)
        closed = true
    }

    companion object {
        fun create(parent: Path): CallBaselineScratch {
            requireStableDirectory(parent, "call-baseline scratch parent")
            val root = Files.createTempDirectory(parent, ".call-baseline-scratch-", PosixFilePermissions.asFileAttribute(CALL_BASELINE_DIRECTORY))
            try {
                val database = Files.createFile(root.resolve("baseline.sqlite"), PosixFilePermissions.asFileAttribute(CALL_BASELINE_FILE))
                return CallBaselineScratch(root, database, checkNotNull(callBaselineAttributes(root).fileKey()),
                    checkNotNull(callBaselineAttributes(database).fileKey()))
            } catch (failure: Throwable) {
                runCatching { Files.deleteIfExists(root.resolve("baseline.sqlite")); Files.delete(root) }
                    .exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

private class CallBaselineStage private constructor(
    private val staging: Path,
    private val identity: Any,
    private val parentIdentity: Any,
) : AutoCloseable {
    var root: Path = staging
        private set
    val report: Path get() = root.resolve("report.json")
    private var committed = false
    private var closed = false

    fun freeze(generated: CallBaselineGenerated, checkpoint: (String) -> Unit) {
        requireCallBaselineIdentity(root, identity, true)
        if (callBaselineMembers(root) != setOf("report.json")) callBaselineFail("call-baseline staging membership differs")
        requireCallBaselineRegular(report)
        Files.setPosixFilePermissions(report, CALL_BASELINE_READ_ONLY_FILE)
        FileChannel.open(report, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { it.force(true) }
        Files.setPosixFilePermissions(root, CALL_BASELINE_READ_ONLY_DIRECTORY)
        forceCallBaselineDirectory(root)
        verifyCallBaselineTree(root, generated, checkpoint)
    }

    fun publish(target: Path, generated: CallBaselineGenerated, raw: FullTreeCallBaselineRawProjection) {
        require(target.parent == staging.parent)
        requireCallBaselineIdentity(target.parent, parentIdentity, true)
        requireCallBaselineIdentity(staging, identity, true)
        verifyCallBaselineTree(staging, generated, raw::terminalCheckpoint)
        raw.recheck("immediately before call-baseline publication")
        raw.terminalCheckpoint("at call-baseline publication")
        LinuxFilesystemSyscalls.openRoot(target.parent).use { parent ->
            requireCallBaselineIdentity(target.parent, parentIdentity, true)
            parent.whileOpen { descriptor ->
                LinuxFilesystemSyscalls.renameNoReplace(descriptor, staging.fileName.toString(), target.fileName.toString())
            }
            root = target
            LinuxFilesystemSyscalls.synchronize(parent)
        }
        requireCallBaselineIdentity(target, identity, true)
        verifyCallBaselineTree(target, generated, raw::terminalCheckpoint)
        raw.recheck("after call-baseline publication")
        raw.release()
        verifyCallBaselineTree(target, generated, raw::terminalCheckpoint)
        raw.terminalCheckpoint("after call-baseline terminal rechecks and cleanup")
        requireCallBaselineIdentity(target.parent, parentIdentity, true)
        requireCallBaselineIdentity(target, identity, true)
        committed = true
    }

    override fun close() {
        if (closed || committed) return
        requireCallBaselineIdentity(root, identity, true)
        if (callBaselineMembers(root).any { it != "report.json" }) callBaselineFail("call-baseline staging retained unknown residue")
        Files.setPosixFilePermissions(root, CALL_BASELINE_DIRECTORY)
        if (Files.exists(report, LinkOption.NOFOLLOW_LINKS)) {
            requireCallBaselineRegular(report)
            Files.delete(report)
        }
        Files.delete(root)
        forceCallBaselineDirectory(root.parent)
        closed = true
    }

    companion object {
        fun create(parent: Path): CallBaselineStage {
            val (_, parentIdentity) = requireStableDirectory(parent, "call-baseline publication parent")
            val root = Files.createTempDirectory(parent, ".call-baseline-stage-", PosixFilePermissions.asFileAttribute(CALL_BASELINE_DIRECTORY))
            return CallBaselineStage(root, checkNotNull(callBaselineAttributes(root).fileKey()), parentIdentity)
        }
    }
}

private fun verifyCallBaselineTree(root: Path, generated: CallBaselineGenerated, checkpoint: (String) -> Unit) {
    val (_, parentIdentity) = requireStableDirectory(root.parent, "call-baseline tree parent")
    val (_, identity) = requireStableDirectory(root, "call-baseline tree root")
    if (callBaselineMembers(root) != setOf("report.json") ||
        Files.getPosixFilePermissions(root, LinkOption.NOFOLLOW_LINKS) != CALL_BASELINE_READ_ONLY_DIRECTORY
    ) callBaselineFail("call-baseline directory membership or permissions differ")
    val report = root.resolve("report.json")
    val before = requireCallBaselineRegular(report)
    if (before.size() != generated.bytes ||
        Files.getPosixFilePermissions(report, LinkOption.NOFOLLOW_LINKS) != CALL_BASELINE_READ_ONLY_FILE
    ) callBaselineFail("call-baseline report size or permissions differ")
    val digest = MessageDigest.getInstance("SHA-256")
    var bytes = 0L
    Files.newInputStream(report, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { input ->
        val buffer = ByteArray(64 * 1024)
        while (true) {
            checkpoint("while hashing the bounded call-baseline report")
            val count = input.read(buffer)
            if (count < 0) break
            if (count == 0) callBaselineFail("call-baseline report made no read progress")
            bytes = Math.addExact(bytes, count.toLong())
            if (bytes > generated.bytes) callBaselineFail("call-baseline report grew during hashing")
            digest.update(buffer, 0, count)
        }
    }
    if (bytes != generated.bytes || digest.digest().callBaselineHex() != generated.sha256 ||
        !sameCallBaselineFile(before, requireCallBaselineRegular(report))
    ) callBaselineFail("call-baseline report differs from raw derivation")
    if (callBaselineMembers(root) != setOf("report.json") ||
        Files.getPosixFilePermissions(report, LinkOption.NOFOLLOW_LINKS) != CALL_BASELINE_READ_ONLY_FILE ||
        Files.getPosixFilePermissions(root, LinkOption.NOFOLLOW_LINKS) != CALL_BASELINE_READ_ONLY_DIRECTORY
    ) callBaselineFail("call-baseline tree changed while hashing")
    requireCallBaselineIdentity(root, identity, true)
    requireCallBaselineIdentity(root.parent, parentIdentity, true)
}

private fun compareCallBaseline(candidate: Path, derived: Path, generated: CallBaselineGenerated, checkpoint: (String) -> Unit) {
    val (_, identity) = requireStableDirectory(candidate, "call-baseline candidate root")
    val (_, parentIdentity) = requireStableDirectory(candidate.parent, "call-baseline candidate parent")
    verifyCallBaselineTree(derived, generated, checkpoint)
    verifyCallBaselineTree(candidate, generated, checkpoint)
    val expected = derived.resolve("report.json")
    val actual = candidate.resolve("report.json")
    val expectedBefore = requireCallBaselineRegular(expected)
    val actualBefore = requireCallBaselineRegular(actual)
    Files.newInputStream(expected, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { expectedInput ->
        Files.newInputStream(actual, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { actualInput ->
            var bytes = 0L
            while (true) {
                checkpoint("during byte-exact raw call-baseline comparison")
                val expectedChunk = expectedInput.readNBytes(64 * 1024)
                val actualChunk = actualInput.readNBytes(64 * 1024)
                if (!expectedChunk.contentEquals(actualChunk)) callBaselineFail("call-baseline candidate is not byte-exact raw baseline")
                if (expectedChunk.isEmpty()) break
                bytes = Math.addExact(bytes, expectedChunk.size.toLong())
                if (bytes > generated.bytes) callBaselineFail("call-baseline comparison exceeded its bound")
            }
            if (bytes != generated.bytes) callBaselineFail("call-baseline candidate was truncated during comparison")
        }
    }
    if (!sameCallBaselineFile(expectedBefore, requireCallBaselineRegular(expected)) ||
        !sameCallBaselineFile(actualBefore, requireCallBaselineRegular(actual))
    ) callBaselineFail("call-baseline report changed identity during comparison")
    verifyCallBaselineTree(candidate, generated, checkpoint)
    requireCallBaselineIdentity(candidate, identity, true)
    requireCallBaselineIdentity(candidate.parent, parentIdentity, true)
}

private class CallBaselineWriter(private val output: OutputStream) {
    private var fields = 0
    private var values = 0L
    fun startObject() = ascii("{\n")
    fun field(name: String) {
        if (fields++ > 0) ascii(",\n")
        ascii("  \"$name\": ")
    }
    fun value(bytes: ByteArray) = canonical(bytes, 2, false)
    fun startArray() { values = 0L }
    fun arrayValue(bytes: ByteArray) {
        if (values++ == 0L) ascii("[\n") else ascii(",\n")
        canonical(bytes, 4, true)
    }
    fun endArray() = ascii(if (values == 0L) "[]" else "\n  ]")
    fun endObject() = ascii("\n}\n")
    private fun canonical(bytes: ByteArray, indentation: Int, indentFirst: Boolean) {
        if (bytes.isEmpty() || bytes.last() != '\n'.code.toByte()) callBaselineFail("call-baseline canonical value is invalid")
        if (indentFirst) repeat(indentation) { output.write(' '.code) }
        var start = 0
        for (offset in 0 until bytes.lastIndex) {
            if (bytes[offset] == '\n'.code.toByte()) {
                output.write(bytes, start, offset - start)
                ascii("\n")
                repeat(indentation) { output.write(' '.code) }
                start = offset + 1
            }
        }
        output.write(bytes, start, bytes.lastIndex - start)
    }
    private fun ascii(value: String) = output.write(value.toByteArray(Charsets.US_ASCII))
}

private fun callBaselineMembers(path: Path): Set<String> = Files.newDirectoryStream(path).use { entries ->
    val names = linkedSetOf<String>()
    for (entry in entries) {
        if (names.isNotEmpty()) callBaselineFail("call-baseline directory membership exceeds its bound")
        names += entry.fileName.toString()
    }
    names
}

private fun callBaselineAttributes(path: Path): BasicFileAttributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)

private fun requireCallBaselineRegular(path: Path): BasicFileAttributes = callBaselineAttributes(path).also {
    if (!it.isRegularFile || it.isSymbolicLink || it.fileKey() == null ||
        (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toLong() != 1L
    ) callBaselineFail("call-baseline file is not a single-link regular file")
}

private fun requireCallBaselineIdentity(path: Path, identity: Any, directory: Boolean) {
    val attributes = if (directory) callBaselineAttributes(path) else requireCallBaselineRegular(path)
    if (attributes.fileKey() != identity || attributes.isSymbolicLink || attributes.isDirectory != directory) {
        callBaselineFail("call-baseline path changed identity")
    }
}

private fun sameCallBaselineFile(expected: BasicFileAttributes, actual: BasicFileAttributes): Boolean =
    expected.fileKey() == actual.fileKey() && expected.size() == actual.size() && expected.lastModifiedTime() == actual.lastModifiedTime()

private fun forceCallBaselineDirectory(path: Path) = LinuxFilesystemSyscalls.openRoot(path).use(LinuxFilesystemSyscalls::synchronize)
private fun ByteArray.callBaselineHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
private fun callBaselineFail(message: String): Nothing = throw FullTreeCallBaselineException(message)
private inline fun <Result> translateCallBaselineFailure(action: () -> Result): Result = try {
    action()
} catch (failure: FullTreeCallBaselineException) {
    throw failure
} catch (failure: Exception) {
    throw FullTreeCallBaselineException("raw call-baseline derivation failed: ${failure.message}", failure)
}

private const val CALL_BASELINE_GIB = 1024L * 1024L * 1024L
private val CALL_BASELINE_DIRECTORY = PosixFilePermissions.fromString("rwx------")
private val CALL_BASELINE_READ_ONLY_DIRECTORY = PosixFilePermissions.fromString("r-x------")
private val CALL_BASELINE_FILE = PosixFilePermissions.fromString("rw-------")
private val CALL_BASELINE_READ_ONLY_FILE = PosixFilePermissions.fromString("r--------")
private val CALL_BASELINE_TRUTH_FIELDS = listOf("calls", "counts", "oracle", "schemaVersion", "shard")
private val CALL_BASELINE_POLICY = JsonObject(mapOf(
    "id" to JsonPrimitive("full-tree-call-baseline"),
    "version" to JsonPrimitive(4),
    "exact" to JsonPrimitive("resolved-direct-semantic-external-or-independently-proven-target-set"),
    "partial" to JsonPrimitive("observed-site-with-unresolved-indirect-or-thunk-semantic-target"),
    "excluded" to JsonPrimitive("unobservable-call-site"),
    "inputAuthority" to JsonPrimitive("kotlin-live-raw-rederived-call-truth-v4"),
    "measurement" to JsonPrimitive("observability-only-not-recovered-model-scoring"),
))
