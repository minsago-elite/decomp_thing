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
import java.nio.file.OpenOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager
import java.sql.PreparedStatement
import java.util.TreeSet
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import org.sqlite.ProgressHandler

internal class FullTreeCallTruthException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

internal data class FullTreeCallTruthCounts(
    val edges: Long = 0,
    val observations: Long = 0,
    val directInternal: Long = 0,
    val external: Long = 0,
    val indirectProven: Long = 0,
    val indirectUnresolved: Long = 0,
    val virtualUnresolved: Long = 0,
    val tailCalls: Long = 0,
    val unobservable: Long = 0,
) {
    fun toJson(): JsonObject = JsonObject(mapOf(
        "directInternal" to JsonPrimitive(directInternal), "edges" to JsonPrimitive(edges),
        "external" to JsonPrimitive(external), "indirectProven" to JsonPrimitive(indirectProven),
        "indirectUnresolved" to JsonPrimitive(indirectUnresolved), "observations" to JsonPrimitive(observations),
        "tailCalls" to JsonPrimitive(tailCalls), "unobservable" to JsonPrimitive(unobservable),
        "virtualUnresolved" to JsonPrimitive(virtualUnresolved),
    ))
}

internal data class FullTreeCallTruthLimits(
    val truth: FullTreeFunctionTruthLimits = FullTreeFunctionTruthLimits(),
    val callRun: FullTreeCallObservationRunLimits = FullTreeCallObservationRunLimits(),
    val maximumDatabaseBytes: Long = 8L * CALL_TRUTH_GIB,
    val maximumScratchBytes: Long = 16L * CALL_TRUTH_GIB,
    val maximumOutputBytes: Long = 4L * CALL_TRUTH_GIB,
    val maximumEntityBytes: Int = 64 * 1024 * 1024,
    val maximumEntityNodes: Int = 1_000_000,
    val maximumGroupRows: Int = 1_000_000,
    val maximumGroupBytes: Int = 64 * 1024 * 1024,
    val maximumAliasTargets: Int = 1024,
    val maximumTokensPerInput: Long = 1_000_000_000L,
    val maximumStringBytes: Int = 1024 * 1024,
    val maximumSqliteCacheBytes: Int = 16 * 1024 * 1024,
    val databaseCheckpointRows: Int = 4096,
    val modeledResidentBytes: Long = 512L * 1024L * 1024L,
    val maximumWorkers: Int = 32,
) {
    init {
        require(maximumDatabaseBytes in 4096L..8L * CALL_TRUTH_GIB)
        require(maximumScratchBytes in maximumDatabaseBytes..16L * CALL_TRUTH_GIB)
        require(maximumOutputBytes in 1L..8L * CALL_TRUTH_GIB)
        require(maximumEntityBytes in 1..64 * 1024 * 1024)
        require(maximumEntityNodes in 1..1_000_000)
        require(maximumGroupRows in 1..1_000_000)
        require(maximumGroupBytes in 1..64 * 1024 * 1024)
        require(maximumAliasTargets in 1..1_000_000)
        require(maximumTokensPerInput in 1L..1_000_000_000L)
        require(maximumStringBytes in 1..maximumEntityBytes)
        require(maximumSqliteCacheBytes in 1024..64 * 1024 * 1024)
        require(databaseCheckpointRows in 1..1_000_000)
        require(maximumWorkers in 1..32)
        require(modeledResidentBytes in 1L..2L * CALL_TRUTH_GIB)
        require(modeledResidentBytes >= 32L * 1024L * 1024L + maximumSqliteCacheBytes +
            maximumEntityBytes.toLong() * 4L + maximumGroupBytes.toLong() * 2L)
    }
}

internal class FullTreeCallTruthPublication internal constructor(
    val root: Path,
    val index: JsonObject,
    val indexArtifactSha256: String,
    val indexSha256: String,
    val functionTruthIndexArtifactSha256: String,
    val elfIndexArtifactSha256: String,
    val callObservationIndexArtifactSha256: String,
    val outputBytes: Long,
    val databaseHighWaterBytes: Long,
    val counts: FullTreeCallTruthCounts,
    val candidateBytesMatchedAtValidationBoundary: Boolean,
) {
    val rawInputsRederived: Boolean = true
    val candidateLeaseRetained: Boolean = false
    val downstreamScoringAuthorized: Boolean = false
    val authoritativeReleaseEvidence: Boolean = false
}

internal class FullTreeCallTruthFunctionProjection internal constructor(
    val root: Path,
    val index: JsonObject,
    val indexArtifactSha256: String,
    val scratchParent: Path,
    private val scratchCheckpoint: (String) -> Long,
    private val runtimeCheckpoint: (String) -> Unit,
) {
    fun checkpoint(label: String): Long {
        runtimeCheckpoint(label)
        return scratchCheckpoint(label)
    }
}

/**
 * Raw Kotlin policy-v3 reconciliation. Candidate artifacts supply no expected oracle facts.
 * Indexed scratch and bounded groups replace historical whole-tree maps. Filesystem owners
 * must cooperate; receipts do not grant a retained candidate lease or release/scoring authority.
 */
internal object FullTreeCallTruthSqlite {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256(listOf("full-tree-call-truth", "full-tree-call-truth-index"), CALL_TRUTH_POLICY)
    }

    fun generateAndPublish(
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
        limits: FullTreeCallTruthLimits = FullTreeCallTruthLimits(),
    ): FullTreeCallTruthPublication = reconcileCalls(
        richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex, functionObservationRoot,
        expectedFunctionObservationIndexArtifactSha256, functionTruthRoot, callObservationRoot,
        expectedCallObservationIndexArtifactSha256, scope, scratchParent, outputRoot, maximumWorkers, limits, false,
    ) { it.publish() }

    fun loadAndValidate(
        candidateRoot: Path,
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
        limits: FullTreeCallTruthLimits = FullTreeCallTruthLimits(),
    ): FullTreeCallTruthPublication = reconcileCalls(
        richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex, functionObservationRoot,
        expectedFunctionObservationIndexArtifactSha256, functionTruthRoot, callObservationRoot,
        expectedCallObservationIndexArtifactSha256, scope, scratchParent, candidateRoot, maximumWorkers, limits, true,
    ) { it.validate() }

    internal fun <Result> withValidatedBaselineProjection(
        candidateRoot: Path,
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
        baselineRoot: Path,
        maximumWorkers: Int,
        limits: FullTreeCallTruthLimits,
        consume: (FullTreeCallBaselineRawProjection) -> Result,
    ): Result {
        requireCallTruthDisjoint(baselineRoot, listOf(
            candidateRoot, richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex,
            functionObservationRoot, functionTruthRoot, callObservationRoot, scratchParent,
        ))
        return reconcileCalls(
            richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex, functionObservationRoot,
            expectedFunctionObservationIndexArtifactSha256, functionTruthRoot, callObservationRoot,
            expectedCallObservationIndexArtifactSha256, scope, scratchParent, candidateRoot, maximumWorkers, limits, true,
        ) { it.withBaseline(consume) }
    }
}

internal class FullTreeCallBaselineRawProjection internal constructor(
    val root: Path,
    val index: JsonObject,
    val indexArtifactSha256: String,
    val scope: AuthenticatedFullTreeScope,
    val scratchParent: Path,
    private val scratchCheckpoint: (String) -> Long,
    private val runtimeCheckpoint: (String) -> Unit,
    private val rawRecheck: (String) -> Unit,
    private val releaseInputs: () -> Unit,
) : AutoCloseable {
    private var released = false

    fun checkpoint(label: String): Long {
        check(!released) { "call-baseline raw projection has been released" }
        return scratchCheckpoint(label)
    }

    fun recheck(label: String) {
        check(!released) { "call-baseline raw projection has been released" }
        rawRecheck(label)
    }

    fun release() {
        if (released) return
        releaseInputs()
        released = true
    }

    fun terminalCheckpoint(label: String) = runtimeCheckpoint(label)

    override fun close() = release()
}

private fun <Result> reconcileCalls(
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
    limits: FullTreeCallTruthLimits,
    validating: Boolean,
    finish: (CallTruthReconciliation) -> Result,
): Result = translateCallTruthFailure {
    if (limits.maximumScratchBytes < maxOf(limits.truth.maximumScratchBytes,
            limits.truth.elfFunctions.maximumScratchBytes, limits.callRun.maximumScratchBytes)
    ) callTruthFail("call-truth scratch ceiling does not admit its configured nested raw derivations")
    val budget = CallTruthBudget(scope, limits)
    val result = resultRoot.toAbsolutePath().normalize()
    val calls = callObservationRoot.toAbsolutePath().normalize()
    requireCallTruthDigest(expectedCallObservationIndexArtifactSha256)
    if (maximumWorkers !in 1..limits.maximumWorkers) callTruthFail("call-truth worker bound exceeds its implementation ceiling")
    requireCallTruthDisjoint(result, listOf(
        richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex, functionObservationRoot,
        functionTruthRoot, calls, scratchParent,
    ))
    requireCallTruthDisjoint(calls, listOf(
        richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex, functionObservationRoot,
        functionTruthRoot, scratchParent,
    ))
    if (!validating && Files.exists(result, LinkOption.NOFOLLOW_LINKS)) callTruthFail("call-truth target already exists")
    FullTreeFunctionTruthSqlite.withValidatedCallProjection(
        candidateRoot = functionTruthRoot, richArtifact = richArtifact, strippedArtifact = strippedArtifact,
        inventoryPath = inventoryPath, elfFunctionIndex = elfFunctionIndex, observationRoot = functionObservationRoot,
        expectedObservationIndexArtifactSha256 = expectedFunctionObservationIndexArtifactSha256,
        scope = scope, scratchParent = scratchParent, outputRoot = result, maximumWorkers = maximumWorkers,
        limits = limits.truth, checkpoint = budget::checkpoint,
    ) { functions, recheckFunctions, releaseFunctions ->
        budget.checkpoint("after raw function-truth reconciliation")
        val inventory = FullTreeInventoryControl.loadAndValidate(inventoryPath, scope, limits.truth.control)
        val shards = inventory.controlArray("shards").controlObjects("call-truth inventory shards")
            .map { it.controlString("id") }
        if (shards.isEmpty() || shards.size > limits.callRun.run.maximumShards) callTruthFail("call-truth shard bound exceeded")
        val context = CallTruthContext(scope, limits, budget, functions, !validating)
        val perShardBytes = scope.document.controlObject("bounds").controlObject("perShard").controlLong("serializedBytes")
        val workerReservation = Math.addExact(
            limits.callRun.shard.control.maximumDwarfScratchBytes,
            minOf(limits.callRun.shard.sqlite.maximumDatabaseBytes,
                maxOf(4096L, minOf(perShardBytes, limits.callRun.shard.sqlite.maximumDatabaseBytes) * 4L)),
        )
        context.checkpoint("before rederiving the complete call-observation run", workerReservation)
        val callRun = FullTreeCallObservationRunPublisher.loadAndValidateWithinDeadline(
            calls, expectedCallObservationIndexArtifactSha256, richArtifact, inventoryPath,
            scope, functions.scratchParent, maximumWorkers, limits.callRun, budget.deadline,
        )
        context.checkpoint("after rederiving the complete call-observation run")
        if (callRun.outputs.map { it.shardId } != shards) callTruthFail("call-truth inputs have incomplete shard membership")
        StableControlFile.open(elfFunctionIndex, limits.truth.maximumElfIndexBytes, "call-truth ELF index").use { elfGuard ->
            val expectedElfSha = functions.index.controlObject("oracle").controlString("elfIndexSha256")
            if (elfGuard.authenticatedSha256 != expectedElfSha) callTruthFail("call-truth ELF index differs from raw function truth")
            val oracle = JsonObject(mapOf(
                "authority" to JsonPrimitive("non-authoritative-kotlin-raw-call-truth-v3"),
                "callObservationConfigurationSha256" to JsonPrimitive(FullTreeCallObservations.configurationSha256),
                "callObservationIndexSha256" to JsonPrimitive(callRun.indexArtifactSha256),
                "configurationSha256" to JsonPrimitive(FullTreeCallTruthSqlite.configurationSha256),
                "elfIndexSha256" to JsonPrimitive(expectedElfSha),
                "functionTruthIndexSha256" to JsonPrimitive(functions.indexArtifactSha256),
                "inventoryIndexSha256" to JsonPrimitive(inventory.controlString("indexSha256")),
                "richArtifactSha256" to JsonPrimitive(callRun.richArtifactSha256),
                "scopeSha256" to JsonPrimitive(scope.sha256),
                "strippedArtifactSha256" to scope.document.controlObject("oracle").getValue("strippedArtifactSha256"),
            ))
            fun recheck(label: String) {
                context.checkpoint("before $label")
                recheckFunctions(label)
                elfGuard.verifyUnchanged(label)
                val current = BoundedShardRunVerifier.verifyWithCheckpoint(
                    calls, callRun.indexArtifactSha256, limits.callRun.run, budget::checkpoint,
                )
                if (current.runSha256 != callRun.runSha256 || current.outputs.map { Triple(it.shardId, it.outputSha256, it.outputBytes) } !=
                    callRun.outputs.map { Triple(it.shardId, it.outputSha256, it.outputBytes) }
                ) callTruthFail("call-observation run changed during call-truth composition")
                requireCallRunPermissions(calls, shards)
                context.checkpoint("after $label")
            }
            context.reserveDatabase()
            CallTruthScratch.create(functions.scratchParent, context).use { scratch ->
                CallTruthStage.create(if (validating) scratch.root else result.parent, shards).use { stage ->
                    val projection = CallTruthDatabase.open(scratch.database, context).use { database ->
                        database.ingestFunctions(functions)
                        database.ingestExternal(elfFunctionIndex, elfGuard.authenticatedSha256, elfGuard.size)
                        database.ingestCalls(calls, callRun)
                        recheck("after ingesting raw-derived call-truth inputs")
                        database.compose()
                        database.writeProjection(stage.root, shards, oracle)
                    }
                    scratch.releaseDatabase()
                    recheck("before terminal call-truth comparison")
                    stage.freeze(projection, budget)
                    finish(CallTruthReconciliation(
                        result, projection, stage, scratch, context, functions.indexArtifactSha256,
                        expectedElfSha, callRun.indexArtifactSha256, ::recheck, releaseFunctions,
                    ))
                }
            }
        }
    }
}

private class CallTruthReconciliation(
    private val result: Path,
    private val projection: CallTruthProjection,
    private val stage: CallTruthStage,
    private val scratch: CallTruthScratch,
    private val context: CallTruthContext,
    private val functionTruthIndexSha256: String,
    private val elfIndexSha256: String,
    private val callIndexSha256: String,
    private val recheckInputs: (String) -> Unit,
    private val releaseFunctions: () -> Unit,
) {
    private var released = false

    fun publish(): FullTreeCallTruthPublication {
        scratch.close()
        stage.publish(result, projection, context.budget, { recheckInputs("at call-truth publication") }) {
            releaseFunctions()
            context.budget.checkpoint("after releasing call-truth publication scratch")
        }
        return receipt(false)
    }

    fun validate(): FullTreeCallTruthPublication {
        recheckCandidate("after comparing the raw-derived call-truth candidate")
        release()
        return receipt(true)
    }

    fun <Result> withBaseline(consume: (FullTreeCallBaselineRawProjection) -> Result): Result {
        recheckCandidate("before consuming the raw call-baseline projection")
        val live = FullTreeCallBaselineRawProjection(
            stage.root, projection.index, projection.indexArtifactSha256, context.scope, scratch.root,
            context::scratchBytes, context.budget::checkpoint, ::recheckCandidate, ::release,
        )
        return live.use(consume)
    }

    private fun recheckCandidate(label: String) {
        check(!released) { "call-truth candidate projection has been released" }
        compareCallTruthTree(result, stage.root, projection, context.budget)
        recheckInputs(label)
        compareCallTruthTree(result, stage.root, projection, context.budget)
    }

    private fun release() {
        if (released) return
        stage.close()
        scratch.close()
        releaseFunctions()
        released = true
        context.budget.checkpoint("after releasing call-truth validation scratch")
    }

    private fun receipt(validating: Boolean): FullTreeCallTruthPublication = FullTreeCallTruthPublication(
        result, projection.index, projection.indexArtifactSha256, projection.index.controlString("indexSha256"),
        functionTruthIndexSha256, elfIndexSha256, callIndexSha256, projection.outputBytes,
        context.databaseHighWaterBytes, projection.counts, validating,
    )
}

private class CallTruthContext(
    val scope: AuthenticatedFullTreeScope,
    val limits: FullTreeCallTruthLimits,
    val budget: CallTruthBudget,
    private val functions: FullTreeCallTruthFunctionProjection,
    private val detachedOutput: Boolean,
) {
    var databaseHighWaterBytes: Long = 0L
        private set
    var outputBytes: Long = 0L
        private set
    private var reservedScratchBeforeOutput: Long = 0L
    val whole: JsonObject = scope.document.controlObject("bounds").controlObject("wholeRun")
    val perShard: JsonObject = scope.document.controlObject("bounds").controlObject("perShard")

    fun checkpoint(label: String, transientReservation: Long = 0L) {
        budget.checkpoint(label)
        val residentScratch = functions.checkpoint(label)
        val total = Math.addExact(Math.addExact(residentScratch, transientReservation), if (detachedOutput) outputBytes else 0L)
        if (total > limits.maximumScratchBytes) callTruthFail("call-truth aggregate scratch bound exceeded $label")
    }

    fun scratchBytes(label: String): Long {
        budget.checkpoint(label)
        val bytes = functions.checkpoint(label)
        if (bytes > limits.maximumScratchBytes) callTruthFail("call-truth aggregate scratch bound exceeded $label")
        return bytes
    }

    fun chargeOutput(bytes: Long) {
        outputBytes = Math.addExact(outputBytes, bytes)
        if (outputBytes > limits.maximumOutputBytes || outputBytes > whole.controlLong("serializedBytes")) {
            callTruthFail("call-truth whole-run output bound exceeded")
        }
        if (Math.addExact(reservedScratchBeforeOutput, outputBytes) > limits.maximumScratchBytes) {
            callTruthFail("call-truth output exceeds its conservative aggregate scratch reservation")
        }
    }

    fun reserveDatabase() {
        reservedScratchBeforeOutput = Math.addExact(functions.checkpoint("before reserving call-truth SQLite"), limits.maximumDatabaseBytes)
        if (reservedScratchBeforeOutput > limits.maximumScratchBytes) callTruthFail("call-truth SQLite reservation exceeds aggregate scratch")
    }

    fun checkDatabase(path: Path) {
        val bytes = Files.size(path)
        if (bytes > limits.maximumDatabaseBytes) callTruthFail("call-truth SQLite bound exceeded")
        databaseHighWaterBytes = maxOf(databaseHighWaterBytes, bytes)
        checkpoint("while checking call-truth SQLite scratch")
    }

    fun entityBytes(value: JsonElement): ByteArray = OracleJson.canonicalBytes(value, jsonLimits())

    fun jsonLimits(): StrictJsonLimits = StrictJsonLimits(
        maximumInputBytes = limits.maximumEntityBytes, maximumCanonicalBytes = limits.maximumEntityBytes,
        maximumDepth = 128, maximumNodes = limits.maximumEntityNodes,
        maximumStringBytes = limits.maximumStringBytes, maximumTotalStringBytes = limits.maximumEntityBytes,
    )

    fun streamingLimits(bytes: Long): FullTreeCanonicalStreamingLimits = FullTreeCanonicalStreamingLimits(
        maximumInputBytes = bytes, maximumTokens = limits.maximumTokensPerInput,
        maximumEntities = maxOf(1L, minOf(25_000_000L, whole.controlLong("entities")) * 2L),
        maximumEntityBytes = limits.maximumEntityBytes, maximumEntityNodes = limits.maximumEntityNodes,
        maximumStringBytes = limits.maximumStringBytes, maximumTotalStringBytes = bytes,
    )
}

private class CallTruthBudget(scope: AuthenticatedFullTreeScope, limits: FullTreeCallTruthLimits) {
    val deadline: FullTreeCallObservationDeadline = FullTreeCallObservationDeadline.startWholeRun(scope, limits.truth.control)
    private val started = System.nanoTime()
    private val cpuStarted = callTruthCpuNanos()
    private val whole = scope.document.controlObject("bounds").controlObject("wholeRun")
    private val wallLimit = Math.multiplyExact(whole.controlLong("wallClockSeconds"), 1_000_000_000L)
    private val cpuLimit = Math.multiplyExact(whole.controlLong("cpuSeconds"), 1_000_000_000L)
    private val residentLimit = whole.controlLong("maximumResidentBytes")

    init {
        FullTreeScopeControl.validate(scope, limits.truth.control)
        if (limits.modeledResidentBytes > residentLimit) callTruthFail("call-truth modeled resident bound exceeds the scope")
        checkpoint("before authenticating call-truth inputs")
    }

    fun checkpoint(label: String) {
        deadline.checkpoint(label)
        if (Thread.currentThread().isInterrupted) callTruthFail("call-truth reconciliation interrupted $label")
        val wall = System.nanoTime() - started
        val cpu = callTruthCpuNanos() - cpuStarted
        if (wall < 0L || wall > wallLimit || cpu < 0L || cpu > cpuLimit) {
            callTruthFail("call-truth operation exceeded its shared wall-clock or CPU bound $label")
        }
        val resident = LinuxResidentMemory.sampleSelf()
        if (resident.currentBytes > residentLimit || resident.highWaterBytes > residentLimit) {
            callTruthFail("call-truth resident bound exceeded $label")
        }
    }
}

private class CallTruthDatabase private constructor(
    private val connection: Connection,
    private val path: Path,
    private val context: CallTruthContext,
) : AutoCloseable {
    private val statements = linkedMapOf<String, PreparedStatement>()
    private var rowsSinceCheckpoint = 0
    private var observations = 0L
    private var closed = false
    private val limits: FullTreeCallTruthLimits get() = context.limits

    private fun prepared(sql: String): PreparedStatement = statements.getOrPut(sql) { connection.prepareStatement(sql) }

    private fun update(sql: String, vararg values: Any): Int {
        val statement = prepared(sql)
        values.forEachIndexed { index, value ->
            when (value) {
                is String -> statement.setString(index + 1, value)
                is ByteArray -> statement.setBytes(index + 1, value)
                is Long -> statement.setLong(index + 1, value)
                is Int -> statement.setInt(index + 1, value)
                else -> callTruthFail("unsupported internal call-truth SQLite value")
            }
        }
        return statement.executeUpdate()
    }

    private fun rowAccepted() {
        rowsSinceCheckpoint++
        if (rowsSinceCheckpoint >= limits.databaseCheckpointRows) flush()
    }

    private fun flush() {
        context.budget.checkpoint("before committing call-truth SQLite scratch")
        connection.commit()
        context.checkDatabase(path)
        rowsSinceCheckpoint = 0
    }

    fun ingestFunctions(projection: FullTreeCallTruthFunctionProjection) {
        for (shard in projection.index.controlArray("shards").controlObjects("raw-derived function-truth shards")) {
            val owner = shard.controlString("id")
            val relative = shard.controlString("path")
            if (relative != "shards/$owner.json") callTruthFail("raw-derived function shard has an unexpected path")
            val streamed = FullTreeCanonicalStreaming.readObject(
                projection.root.resolve(relative), "raw-derived call function namespace", shard.controlString("sha256"),
                CALL_FUNCTION_FIELDS, setOf("functions", "nonEmitted"), null,
                context.streamingLimits(shard.controlLong("bytes")),
            ) { field, _, function, _ ->
                if (field == "functions") {
                    val identifier = function.controlString("id")
                    if (identifier != "function-rva-${function.controlString("rva")}") callTruthFail("call function identity differs from its RVA")
                    update("INSERT INTO functions VALUES(?,?,?)", identifier, owner, function.controlString("entityKind"))
                    for (alias in function.controlArray("aliases").controlObjects("call function aliases")) {
                        update("INSERT OR IGNORE INTO aliases VALUES(?,?)", alias.controlString("name"), identifier)
                        rowAccepted()
                    }
                    rowAccepted()
                }
                context.budget.checkpoint("while streaming the raw function namespace")
            }
            if (streamed.sourceBytes != shard.controlLong("bytes") ||
                streamed.envelope.controlObject("oracle") != projection.index.controlObject("oracle") ||
                streamed.envelope.controlObject("shard").controlString("id") != owner
            ) callTruthFail("raw-derived function namespace binding changed")
        }
        flush()
    }

    fun ingestExternal(elf: Path, expectedSha256: String, bytes: Long) {
        FullTreeCanonicalStreaming.readObject(
            elf, "raw-derived ELF call namespace", expectedSha256, CALL_ELF_FIELDS,
            setOf("functions", "externalFunctions"), null, context.streamingLimits(bytes),
        ) { field, _, record, _ ->
            if (field == "externalFunctions") {
                val name = record.controlString("name")
                update("INSERT INTO external_names VALUES(?,?)", name, callExternalId(name))
                rowAccepted()
            }
            context.budget.checkpoint("while streaming the raw ELF call namespace")
        }
        flush()
    }

    fun ingestCalls(root: Path, run: FullTreeCallObservationRunPublication) {
        for (shard in run.outputs) {
            var observed = 0L
            val streamed = FullTreeCanonicalStreaming.readObject(
                root.resolve("outputs/${shard.shardId}.json"), "raw-derived call observations", shard.outputSha256,
                CALL_OBSERVATION_FIELDS, setOf("calls"), null, context.streamingLimits(shard.outputBytes),
            ) { _, _, observation, _ ->
                ingestCall(shard.shardId, observation)
                observed = Math.addExact(observed, 1L)
            }
            if (observed != shard.entities || streamed.sourceBytes != shard.outputBytes ||
                streamed.envelope.controlObject("shard").controlString("id") != shard.shardId ||
                streamed.envelope.controlObject("shard").controlString("inputSha256") != shard.inputSha256 ||
                streamed.envelope.controlObject("oracle").controlString("configurationSha256") != FullTreeCallObservations.configurationSha256
            ) callTruthFail("raw call-observation shard binding changed")
        }
        if (observations != run.entities) callTruthFail("raw call-observation denominator changed")
        flush()
    }

    private fun ingestCall(shard: String, observation: JsonObject) {
        observations = Math.addExact(observations, 1L)
        if (observations > context.whole.controlLong("entities")) callTruthFail("call observation whole-run entity bound exceeded")
        val identifier = observation.controlString("id")
        val identity = if (observation.controlString("population") == "scored") {
            JsonObject(mapOf("callerId" to observation.getValue("callerId"), "returnPcRva" to observation.getValue("returnPcRva")))
        } else {
            JsonObject(mapOf("observationId" to JsonPrimitive(identifier)))
        }
        val preimage = context.entityBytes(identity)
        val key = OracleArtifacts.sha256(preimage)
        val signature = context.entityBytes(JsonObject(
            observation.filterKeys { it !in setOf("id", "dieOffset", "unitId", "target") } +
                ("target" to JsonObject(observation.controlObject("target").filterKeys { it != "originDieOffset" })),
        ))
        update("INSERT OR IGNORE INTO edge_groups VALUES(?,?,?,0,0)", key, preimage, signature)
        val selected = prepared("SELECT identity_payload,signature,rows,bytes FROM edge_groups WHERE edge_key=?")
        selected.setString(1, key)
        selected.executeQuery().use { rows ->
            if (!rows.next() || !rows.getBytes(1).contentEquals(preimage) || !rows.getBytes(2).contentEquals(signature)) {
                callTruthFail("incompatible duplicate call observations or edge identity collision")
            }
            val nextRows = Math.addExact(rows.getLong(3), 1L)
            val increment = identifier.toByteArray(Charsets.UTF_8).size.toLong() + shard.toByteArray(Charsets.UTF_8).size + 64L
            val nextBytes = Math.addExact(rows.getLong(4), increment)
            if (nextRows > limits.maximumGroupRows || Math.addExact(nextBytes, signature.size.toLong()) > limits.maximumGroupBytes) {
                callTruthFail("call-truth observation group exceeds its row or byte bound")
            }
            update("UPDATE edge_groups SET rows=?,bytes=? WHERE edge_key=?", nextRows, nextBytes, key)
        }
        update("INSERT INTO observations VALUES(?,?,?)", key, identifier, shard)
        rowAccepted()
    }

    fun compose() {
        connection.createStatement().use { statement ->
            statement.executeQuery("SELECT edge_key,signature FROM edge_groups ORDER BY edge_key COLLATE BINARY").use { groups ->
                while (groups.next()) {
                    val key = groups.getString(1)
                    val signature = OracleJson.parseCanonical(groups.getBytes(2), context.jsonLimits()) as? JsonObject
                        ?: callTruthFail("call-truth internal signature is invalid")
                    val identifiers = ArrayList<String>()
                    var ownerFallback: String? = null
                    val selected = prepared("SELECT observation_id,source_shard FROM observations WHERE edge_key=? ORDER BY observation_id COLLATE BINARY")
                    selected.setString(1, key)
                    selected.executeQuery().use { rows ->
                        while (rows.next()) {
                            if (identifiers.size >= limits.maximumGroupRows) callTruthFail("call-truth observation group row overflow")
                            identifiers += rows.getString(1)
                            val shard = rows.getString(2)
                            if (ownerFallback == null || FULL_TREE_CODE_POINT_ORDER.compare(shard, ownerFallback) < 0) ownerFallback = shard
                            context.budget.checkpoint("while composing one bounded call group")
                        }
                    }
                    val caller = signature.nullableCallString("callerId")
                    val callerRow = caller?.let(::function)
                    if (caller != null && callerRow == null) callTruthFail("call has a dangling caller identity")
                    if (signature.controlString("population") == "scored" && callerRow == null) callTruthFail("scored call lacks an authenticated caller")
                    val owner = callerRow?.first ?: checkNotNull(ownerFallback)
                    val edge = composeEdge(key, signature, identifiers)
                    val payload = context.entityBytes(edge)
                    if (payload.size > limits.maximumGroupBytes) callTruthFail("composed call group exceeds its byte bound")
                    update("INSERT INTO merged VALUES(?,?,?,?,?,?,?)", edge.controlString("id"), owner, payload,
                        edge.controlString("targetKind"), if (edge.callBoolean("tailCall")) 1 else 0,
                        if (edge.controlString("population") == "unobservable") 1 else 0, identifiers.size)
                    rowAccepted()
                }
            }
        }
        flush()
    }

    private fun function(identifier: String): Pair<String, String>? {
        val selected = prepared("SELECT owner_shard,kind FROM functions WHERE function_id=?")
        selected.setString(1, identifier)
        return selected.executeQuery().use { rows -> if (rows.next()) rows.getString(1) to rows.getString(2) else null }
    }

    private fun composeEdge(key: String, signature: JsonObject, identifiers: List<String>): JsonObject {
        val target = signature.controlObject("target")
        var kind = target.controlString("kind")
        var population = signature.controlString("population")
        var reason = signature.nullableCallString("reasonCode")
        var physical: String? = null
        var semantic: String? = null
        var external = emptyList<String>()
        var proven = emptyList<String>()
        fun direct(identifier: String) {
            val selected = function(identifier) ?: callTruthFail("call has a dangling direct target")
            physical = identifier
            if (selected.second == "thunk") {
                reason = "thunk-semantic-target-unresolved"
            } else {
                semantic = identifier
            }
        }
        when (kind) {
            "direct-internal" -> direct(target.controlString("functionId"))
            "external-unresolved" -> {
                val names = target.callStrings("aliases")
                val internal = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
                var aliasesVisited = 0L
                var aliasBytes = 0L
                for (name in names) {
                    val selected = prepared("SELECT function_id FROM aliases WHERE name=? ORDER BY function_id COLLATE BINARY")
                    selected.setString(1, name)
                    selected.executeQuery().use { rows ->
                        while (rows.next()) {
                            aliasesVisited++
                            val identifier = rows.getString(1)
                            aliasBytes = Math.addExact(aliasBytes, identifier.toByteArray(Charsets.UTF_8).size.toLong())
                            if (aliasesVisited > limits.maximumAliasTargets || aliasBytes > limits.maximumGroupBytes) {
                                callTruthFail("call-truth alias target fanout exceeds its bound")
                            }
                            internal += identifier
                        }
                    }
                }
                when {
                    internal.size == 1 -> {
                        kind = "direct-internal"
                        direct(internal.single())
                    }
                    internal.size > 1 -> {
                        kind = "indirect-unresolved"
                        population = "unobservable"
                        reason = "ambiguous-authenticated-internal-aliases"
                    }
                    else -> {
                        kind = "external"
                        val selectedIds = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
                        for (name in names) {
                            val selected = prepared("SELECT external_id FROM external_names WHERE name=?")
                            selected.setString(1, name)
                            selected.executeQuery().use { rows ->
                                if (rows.next()) selectedIds += rows.getString(1)
                            }
                            if (selectedIds.size > limits.maximumAliasTargets) callTruthFail("external call target fanout exceeds its bound")
                        }
                        external = selectedIds.toList()
                        if (external.isEmpty()) {
                            population = "unobservable"
                            reason = "external-without-elf-evidence"
                        }
                    }
                }
            }
            "indirect-proven" -> {
                proven = target.callStrings("provenFunctionIds")
                if (proven.isEmpty() || proven.size > 16 || proven != proven.distinct().sortedWith(FULL_TREE_CODE_POINT_ORDER)) {
                    callTruthFail("call proven-target set exceeds its bound or is noncanonical")
                }
                proven.forEach { if (function(it) == null) callTruthFail("call has a dangling proven target") }
            }
            "virtual-unresolved" -> {
                population = "unobservable"
                reason = "virtual-target-set-unproven"
            }
            "indirect-unresolved" -> Unit
            else -> callTruthFail("call target classification is unsupported")
        }
        return JsonObject(mapOf(
            "callerId" to signature.getValue("callerId"), "callerLocalReturnOffset" to signature.getValue("callerLocalReturnOffset"),
            "dispatchKind" to target.getValue("dispatchKind"), "externalTargetIds" to JsonArray(external.map(::JsonPrimitive)),
            "id" to JsonPrimitive("call-edge-${key.take(32)}"), "observationIds" to JsonArray(identifiers.map(::JsonPrimitive)),
            "physicalTargetId" to physical.callJson(), "population" to JsonPrimitive(population),
            "provenTargetIds" to JsonArray(proven.map(::JsonPrimitive)), "reasonCode" to reason.callJson(),
            "returnPcRva" to signature.getValue("returnPcRva"), "semanticTargetId" to semantic.callJson(),
            "tailCall" to signature.getValue("tailCall"), "targetEvidence" to target.getValue("targetEvidence"),
            "targetKind" to JsonPrimitive(kind),
        ))
    }

    private fun counts(owner: String?): FullTreeCallTruthCounts {
        val where = if (owner == null) "" else " WHERE owner_shard=?"
        val selected = prepared("SELECT COUNT(*),COALESCE(SUM(target_kind='direct-internal'),0),COALESCE(SUM(target_kind='external'),0)," +
            "COALESCE(SUM(target_kind='indirect-proven'),0),COALESCE(SUM(target_kind='indirect-unresolved'),0)," +
            "COALESCE(SUM(target_kind='virtual-unresolved'),0),COALESCE(SUM(tail_call),0),COALESCE(SUM(unobservable),0) FROM merged$where")
        if (owner != null) selected.setString(1, owner)
        val totalObservations = if (owner == null) observations else {
            val membership = prepared("SELECT COALESCE(SUM(observation_count),0) FROM merged WHERE owner_shard=?")
            membership.setString(1, owner)
            membership.executeQuery().use { rows -> check(rows.next()); rows.getLong(1) }
        }
        return selected.executeQuery().use { rows ->
            check(rows.next())
            FullTreeCallTruthCounts(rows.getLong(1), totalObservations, rows.getLong(2), rows.getLong(3), rows.getLong(4),
                rows.getLong(5), rows.getLong(6), rows.getLong(7), rows.getLong(8))
        }
    }

    fun writeProjection(root: Path, shards: List<String>, oracle: JsonObject): CallTruthProjection {
        val aggregate = counts(null)
        if (aggregate.edges > context.whole.controlLong("entities")) callTruthFail("call-truth edge population exceeds its whole-run bound")
        val files = shards.map { owner ->
            val counts = counts(owner)
            if (counts.edges > context.perShard.controlLong("entities")) callTruthFail("call-truth shard edge population exceeds its bound")
            val relative = "shards/$owner.json"
            val digest = writeCallTruthFile(root.resolve(relative), minOf(limits.maximumOutputBytes, context.perShard.controlLong("serializedBytes")), context) { writer ->
                writer.startObject()
                writer.field("calls")
                writer.startArray()
                val selected = prepared("SELECT payload FROM merged WHERE owner_shard=? ORDER BY edge_id COLLATE BINARY")
                selected.setString(1, owner)
                selected.executeQuery().use { rows ->
                    var emitted = 0L
                    while (rows.next()) {
                        writer.arrayValue(rows.getBytes(1))
                        emitted++
                        if (emitted % limits.databaseCheckpointRows == 0L) context.checkpoint("while emitting call truth")
                    }
                    if (emitted != counts.edges) callTruthFail("call-truth emitted count changed")
                }
                writer.endArray()
                writer.field("counts"); writer.value(context.entityBytes(counts.toJson()))
                writer.field("oracle"); writer.value(context.entityBytes(oracle))
                writer.field("schemaVersion"); writer.value(context.entityBytes(JsonPrimitive(1)))
                writer.field("shard"); writer.value(context.entityBytes(JsonObject(mapOf("id" to JsonPrimitive(owner)))))
                writer.endObject()
            }
            CallTruthFile(owner, relative, digest.first, digest.second, counts)
        }
        val summed = files.sumOf { it.counts.observations }
        if (summed != observations || files.sumOf { it.counts.edges } != aggregate.edges) callTruthFail("call-truth shard population does not reconcile")
        val unsigned = JsonObject(mapOf(
            "complete" to JsonPrimitive(true), "counts" to aggregate.toJson(), "oracle" to oracle,
            "schemaVersion" to JsonPrimitive(1), "shards" to JsonArray(files.map { it.toJson() }),
        ))
        val indexLimits = controlJsonLimits(limits.truth.control.maximumInventoryBytes)
        val index = JsonObject(unsigned + ("indexSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned, indexLimits)))))
        OracleSchemas.validate("full-tree-call-truth-index", index)
        val bytes = OracleJson.canonicalBytes(index, indexLimits)
        val indexDigest = writeCallTruthFile(root.resolve("index.json"), limits.maximumOutputBytes, context) { writer ->
            writer.completeValue(bytes)
        }
        context.checkpoint("after projecting the complete call-truth tree")
        return CallTruthProjection(index, indexDigest.first, indexDigest.second, files, aggregate, context.outputBytes)
    }

    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        fun record(caught: Throwable) {
            val prior = failure
            if (prior == null) failure = caught else if (caught !== prior) prior.addSuppressed(caught)
        }
        statements.values.forEach { runCatching { it.close() }.exceptionOrNull()?.let(::record) }
        runCatching { ProgressHandler.clearHandler(connection) }.exceptionOrNull()?.let(::record)
        runCatching { connection.close() }.exceptionOrNull()?.let(::record)
        failure?.let { throw it }
    }

    companion object {
        fun open(path: Path, context: CallTruthContext): CallTruthDatabase {
            val connection = DriverManager.getConnection(SqliteJdbcPaths.create(path))
            try {
                connection.createStatement().use { statement ->
                    listOf("journal_mode=OFF", "synchronous=OFF", "foreign_keys=ON", "temp_store=MEMORY", "mmap_size=0",
                        "page_size=4096", "cache_size=-${context.limits.maximumSqliteCacheBytes / 1024}",
                        "max_page_count=${context.limits.maximumDatabaseBytes / 4096L}").forEach { statement.execute("PRAGMA $it") }
                    connection.autoCommit = false
                    statement.execute("CREATE TABLE functions(function_id TEXT COLLATE BINARY PRIMARY KEY,owner_shard TEXT NOT NULL,kind TEXT NOT NULL) WITHOUT ROWID")
                    statement.execute("CREATE TABLE aliases(name TEXT COLLATE BINARY NOT NULL,function_id TEXT COLLATE BINARY NOT NULL REFERENCES functions(function_id),PRIMARY KEY(name,function_id)) WITHOUT ROWID")
                    statement.execute("CREATE TABLE external_names(name TEXT COLLATE BINARY PRIMARY KEY,external_id TEXT NOT NULL UNIQUE) WITHOUT ROWID")
                    statement.execute("CREATE TABLE edge_groups(edge_key TEXT COLLATE BINARY PRIMARY KEY,identity_payload BLOB NOT NULL,signature BLOB NOT NULL,rows INTEGER NOT NULL,bytes INTEGER NOT NULL) WITHOUT ROWID")
                    statement.execute("CREATE TABLE observations(edge_key TEXT COLLATE BINARY NOT NULL REFERENCES edge_groups(edge_key),observation_id TEXT COLLATE BINARY NOT NULL UNIQUE,source_shard TEXT NOT NULL,PRIMARY KEY(edge_key,observation_id)) WITHOUT ROWID")
                    statement.execute("CREATE TABLE merged(edge_id TEXT COLLATE BINARY PRIMARY KEY,owner_shard TEXT COLLATE BINARY NOT NULL,payload BLOB NOT NULL,target_kind TEXT NOT NULL,tail_call INTEGER NOT NULL,unobservable INTEGER NOT NULL,observation_count INTEGER NOT NULL) WITHOUT ROWID")
                    statement.execute("CREATE INDEX merged_owner ON merged(owner_shard,edge_id)")
                }
                for (query in CALL_TRUTH_INDEXED_QUERIES) {
                    connection.prepareStatement("EXPLAIN QUERY PLAN $query").use { plan ->
                        if ('?' in query) plan.setString(1, "")
                        plan.executeQuery().use { rows ->
                            while (rows.next()) {
                                val detail = rows.getString("detail").uppercase()
                                if ("TEMP B-TREE" in detail || "AUTOMATIC" in detail) {
                                    callTruthFail("call-truth SQL query requires unbounded temporary sorting")
                                }
                            }
                        }
                    }
                }
                ProgressHandler.setHandler(connection, 10_000, object : ProgressHandler() {
                    override fun progress(): Int {
                        context.budget.checkpoint("during call-truth SQLite execution")
                        return 0
                    }
                })
                return CallTruthDatabase(connection, path, context).also { it.flush() }
            } catch (failure: Throwable) {
                runCatching { connection.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

private data class CallTruthFile(
    val id: String,
    val path: String,
    val sha256: String,
    val bytes: Long,
    val counts: FullTreeCallTruthCounts,
) {
    fun toJson(): JsonObject = JsonObject(counts.toJson() + mapOf(
        "id" to JsonPrimitive(id), "path" to JsonPrimitive(path),
        "sha256" to JsonPrimitive(sha256), "bytes" to JsonPrimitive(bytes),
    ))
}

private data class CallTruthProjection(
    val index: JsonObject,
    val indexArtifactSha256: String,
    val indexBytes: Long,
    val files: List<CallTruthFile>,
    val counts: FullTreeCallTruthCounts,
    val outputBytes: Long,
) {
    fun expectedFiles(): List<Triple<String, String, Long>> =
        listOf(Triple("index.json", indexArtifactSha256, indexBytes)) + files.map { Triple(it.path, it.sha256, it.bytes) }
}

private class CallTruthScratch private constructor(
    val root: Path,
    val database: Path,
    private val rootIdentity: Any,
    private val databaseIdentity: Any,
    private val context: CallTruthContext,
) : AutoCloseable {
    private var databaseReleased = false
    private var closed = false

    fun releaseDatabase(checkBudget: Boolean = true) {
        if (databaseReleased) return
        requireCallTruthIdentity(database, databaseIdentity, false)
        if (checkBudget) context.checkDatabase(database)
        Files.delete(database)
        databaseReleased = true
        forceCallTruthDirectory(root)
    }

    override fun close() {
        if (closed) return
        requireCallTruthIdentity(root, rootIdentity, true)
        val members = callTruthMembers(root, 1)
        if (members.any { it != "calls.sqlite" }) callTruthFail("call-truth scratch retained unexpected members")
        if (!databaseReleased) releaseDatabase(checkBudget = false)
        if (callTruthMembers(root, 1).isNotEmpty()) callTruthFail("call-truth scratch is not empty")
        Files.delete(root)
        forceCallTruthDirectory(root.parent)
        closed = true
    }

    companion object {
        fun create(parent: Path, context: CallTruthContext): CallTruthScratch {
            requireStableDirectory(parent, "call-truth scratch parent")
            val root = Files.createTempDirectory(parent, ".call-truth-scratch-", PosixFilePermissions.asFileAttribute(CALL_TRUTH_DIRECTORY))
            try {
                val database = Files.createFile(root.resolve("calls.sqlite"), PosixFilePermissions.asFileAttribute(CALL_TRUTH_FILE))
                return CallTruthScratch(root, database, checkNotNull(callTruthAttributes(root).fileKey()),
                    checkNotNull(callTruthAttributes(database).fileKey()), context)
            } catch (failure: Throwable) {
                runCatching { Files.deleteIfExists(root.resolve("calls.sqlite")); Files.delete(root) }
                    .exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

private class CallTruthStage private constructor(
    private val staging: Path,
    private val identity: Any,
    private val parentIdentity: Any,
    private val shards: List<String>,
) : AutoCloseable {
    var root: Path = staging
        private set
    private var committed = false
    private var closed = false

    fun freeze(projection: CallTruthProjection, budget: CallTruthBudget) {
        requireMembership(projection)
        for ((relative, _, _) in projection.expectedFiles()) {
            val path = root.resolve(relative)
            requireCallTruthRegular(path)
            Files.setPosixFilePermissions(path, CALL_TRUTH_READ_ONLY_FILE)
            FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { it.force(true) }
            budget.checkpoint("while freezing call-truth output")
        }
        Files.setPosixFilePermissions(root.resolve("shards"), CALL_TRUTH_READ_ONLY_DIRECTORY)
        Files.setPosixFilePermissions(root, CALL_TRUTH_READ_ONLY_DIRECTORY)
        forceCallTruthDirectory(root.resolve("shards"))
        forceCallTruthDirectory(root)
        verifyCallTruthTree(root, projection, budget)
    }

    fun publish(
        target: Path,
        projection: CallTruthProjection,
        budget: CallTruthBudget,
        verifyInputs: () -> Unit,
        finalizeInputs: () -> Unit,
    ) {
        require(target.parent == staging.parent)
        requireCallTruthIdentity(target.parent, parentIdentity, true)
        requireCallTruthIdentity(staging, identity, true)
        verifyCallTruthTree(staging, projection, budget)
        verifyInputs()
        budget.checkpoint("immediately before call-truth publication")
        LinuxFilesystemSyscalls.openRoot(target.parent).use { parent ->
            requireCallTruthIdentity(target.parent, parentIdentity, true)
            parent.whileOpen { descriptor ->
                LinuxFilesystemSyscalls.renameNoReplace(descriptor, staging.fileName.toString(), target.fileName.toString())
            }
            root = target
            LinuxFilesystemSyscalls.synchronize(parent)
        }
        requireCallTruthIdentity(target, identity, true)
        verifyCallTruthTree(target, projection, budget)
        verifyInputs()
        finalizeInputs()
        budget.checkpoint("after terminal call-truth source rechecks and cleanup")
        requireCallTruthIdentity(target.parent, parentIdentity, true)
        requireCallTruthIdentity(target, identity, true)
        committed = true
    }

    private fun requireMembership(projection: CallTruthProjection) {
        requireCallTruthIdentity(root, identity, true)
        if (projection.files.map { it.id } != shards) callTruthFail("call-truth staging shard membership changed")
        requireCallTruthMembership(root, shards)
    }

    override fun close() {
        if (committed || closed) return
        requireCallTruthIdentity(root, identity, true)
        if (callTruthMembers(root, 2).any { it !in setOf("index.json", "shards") }) {
            callTruthFail("call-truth staging contains unknown residue")
        }
        val directory = root.resolve("shards")
        val allowed = shards.mapTo(hashSetOf()) { "$it.json" }
        if (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
            requireStableDirectory(directory, "call-truth staging shard directory")
            val members = callTruthMembers(directory, shards.size)
            if (!allowed.containsAll(members)) callTruthFail("call-truth staging contains unknown shards")
            Files.setPosixFilePermissions(directory, CALL_TRUTH_DIRECTORY)
            for (name in members) {
                val path = directory.resolve(name)
                requireCallTruthRegular(path)
                Files.delete(path)
            }
        }
        Files.setPosixFilePermissions(root, CALL_TRUTH_DIRECTORY)
        val index = root.resolve("index.json")
        if (Files.exists(index, LinkOption.NOFOLLOW_LINKS)) {
            requireCallTruthRegular(index)
            Files.delete(index)
        }
        Files.deleteIfExists(directory)
        Files.delete(root)
        forceCallTruthDirectory(root.parent)
        closed = true
    }

    companion object {
        fun create(parent: Path, shards: List<String>): CallTruthStage {
            val (_, parentIdentity) = requireStableDirectory(parent, "call-truth publication parent")
            if (shards.any { !it.matches(Regex("[a-z0-9][a-z0-9-]{0,249}")) } || shards.distinct().size != shards.size) {
                callTruthFail("call-truth shard names are unsafe or repeated")
            }
            val staging = Files.createTempDirectory(parent, ".call-truth-stage-", PosixFilePermissions.asFileAttribute(CALL_TRUTH_DIRECTORY))
            try {
                Files.createDirectory(staging.resolve("shards"), PosixFilePermissions.asFileAttribute(CALL_TRUTH_DIRECTORY))
                return CallTruthStage(staging, checkNotNull(callTruthAttributes(staging).fileKey()), parentIdentity, shards.toList())
            } catch (failure: Throwable) {
                runCatching { Files.deleteIfExists(staging.resolve("shards")); Files.delete(staging) }
                    .exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

private fun requireCallTruthMembership(root: Path, shards: List<String>) {
    requireStableDirectory(root, "call-truth tree root")
    val directory = root.resolve("shards")
    requireStableDirectory(directory, "call-truth shards directory")
    if (callTruthMembers(root, 2) != setOf("index.json", "shards") ||
        callTruthMembers(directory, shards.size) != shards.mapTo(hashSetOf()) { "$it.json" }
    ) callTruthFail("call-truth tree has incomplete or extra membership")
}

private fun verifyCallTruthTree(root: Path, projection: CallTruthProjection, budget: CallTruthBudget) {
    val (_, parentIdentity) = requireStableDirectory(root.parent, "call-truth tree parent")
    val (_, identity) = requireStableDirectory(root, "call-truth tree root")
    requireCallTruthMembership(root, projection.files.map { it.id })
    for (directory in listOf(root, root.resolve("shards"))) {
        if (Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS) != CALL_TRUTH_READ_ONLY_DIRECTORY) {
            callTruthFail("call-truth directories must have mode 0500")
        }
    }
    for ((relative, expectedSha256, bytes) in projection.expectedFiles()) {
        val path = root.resolve(relative)
        val before = requireCallTruthRegular(path)
        if (before.size() != bytes || Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS) != CALL_TRUTH_READ_ONLY_FILE) {
            callTruthFail("call-truth member size or mode changed")
        }
        val digest = MessageDigest.getInstance("SHA-256")
        var read = 0L
        Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                budget.checkpoint("while hashing bounded call-truth members")
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) callTruthFail("call-truth member made no read progress")
                read = Math.addExact(read, count.toLong())
                if (read > bytes) callTruthFail("call-truth member grew while hashing")
                digest.update(buffer, 0, count)
            }
        }
        if (read != bytes || digest.digest().callHex() != expectedSha256 || !sameCallTruthFile(before, requireCallTruthRegular(path))) {
            callTruthFail("call-truth member differs from its raw derivation")
        }
    }
    requireCallTruthMembership(root, projection.files.map { it.id })
    requireCallTruthIdentity(root, identity, true)
    requireCallTruthIdentity(root.parent, parentIdentity, true)
}

private fun compareCallTruthTree(candidate: Path, derived: Path, projection: CallTruthProjection, budget: CallTruthBudget) {
    val (_, identity) = requireStableDirectory(candidate, "call-truth candidate root")
    val (_, parentIdentity) = requireStableDirectory(candidate.parent, "call-truth candidate parent")
    verifyCallTruthTree(derived, projection, budget)
    verifyCallTruthTree(candidate, projection, budget)
    for ((relative, _, bytes) in projection.expectedFiles()) {
        val expected = derived.resolve(relative)
        val actual = candidate.resolve(relative)
        val expectedBefore = requireCallTruthRegular(expected)
        val actualBefore = requireCallTruthRegular(actual)
        Files.newInputStream(expected, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { left ->
            Files.newInputStream(actual, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { right ->
                var compared = 0L
                while (true) {
                    budget.checkpoint("during byte-exact raw call-truth comparison")
                    val expectedChunk = left.readNBytes(64 * 1024)
                    val actualChunk = right.readNBytes(64 * 1024)
                    if (!expectedChunk.contentEquals(actualChunk)) callTruthFail("candidate call truth is not byte-exact raw truth")
                    if (expectedChunk.isEmpty()) break
                    compared = Math.addExact(compared, expectedChunk.size.toLong())
                    if (compared > bytes) callTruthFail("call-truth comparison exceeded its byte bound")
                }
                if (compared != bytes) callTruthFail("call-truth candidate was truncated during comparison")
            }
        }
        if (!sameCallTruthFile(expectedBefore, requireCallTruthRegular(expected)) ||
            !sameCallTruthFile(actualBefore, requireCallTruthRegular(actual))
        ) callTruthFail("call-truth candidate changed identity during comparison")
    }
    requireCallTruthMembership(candidate, projection.files.map { it.id })
    requireCallTruthIdentity(candidate, identity, true)
    requireCallTruthIdentity(candidate.parent, parentIdentity, true)
}

private fun requireCallRunPermissions(root: Path, shards: List<String>) {
    for (directory in listOf(root, root.resolve("outputs"), root.resolve("checkpoints"))) {
        if (Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS) != CALL_TRUTH_READ_ONLY_DIRECTORY) {
            callTruthFail("call-observation run directory mode changed")
        }
    }
    val files = listOf(root.resolve("run.json"), root.resolve("index.json")) + shards.flatMap {
        listOf(root.resolve("outputs/$it.json"), root.resolve("checkpoints/$it.json"))
    }
    for (file in files) {
        requireCallTruthRegular(file)
        if (Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS) != CALL_TRUTH_READ_ONLY_FILE) {
            callTruthFail("call-observation run file mode changed")
        }
    }
}

private fun writeCallTruthFile(
    path: Path,
    maximumBytes: Long,
    context: CallTruthContext,
    write: (CallTruthCanonicalWriter) -> Unit,
): Pair<String, Long> {
    FileChannel.open(path, setOf<OpenOption>(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
        PosixFilePermissions.asFileAttribute(CALL_TRUTH_FILE)).use { channel ->
        val digest = MessageDigest.getInstance("SHA-256")
        var count = 0L
        val bounded = object : FilterOutputStream(Channels.newOutputStream(channel)) {
            override fun write(value: Int) {
                write(byteArrayOf(value.toByte()), 0, 1)
            }
            override fun write(bytes: ByteArray, offset: Int, length: Int) {
                count = Math.addExact(count, length.toLong())
                if (count > maximumBytes) callTruthFail("call-truth shard output byte bound exceeded")
                context.chargeOutput(length.toLong())
                context.budget.checkpoint("while writing bounded call truth")
                out.write(bytes, offset, length)
                digest.update(bytes, offset, length)
            }
        }
        BufferedOutputStream(bounded, 64 * 1024).use { output ->
            val writer = CallTruthCanonicalWriter(output)
            write(writer)
            writer.requireFinished()
            output.flush()
            channel.force(true)
        }
        return digest.digest().callHex() to count
    }
}

private class CallTruthCanonicalWriter(private val output: OutputStream) {
    private var fields = 0
    private var values = 0L
    private var finished = false
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
    fun endObject() { ascii("\n}\n"); finished = true }
    fun completeValue(bytes: ByteArray) { output.write(bytes); finished = true }
    fun requireFinished() { if (!finished) callTruthFail("call-truth canonical writer did not finish") }
    private fun canonical(bytes: ByteArray, indentation: Int, indentFirst: Boolean) {
        if (bytes.isEmpty() || bytes.last() != '\n'.code.toByte()) callTruthFail("call-truth canonical value is invalid")
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

private fun callTruthMembers(path: Path, maximum: Int): Set<String> = Files.newDirectoryStream(path).use { entries ->
    val names = linkedSetOf<String>()
    for (entry in entries) {
        if (names.size >= maximum) callTruthFail("call-truth directory membership exceeds its bound")
        names += entry.fileName.toString()
    }
    names
}

private fun callTruthAttributes(path: Path): BasicFileAttributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)

private fun requireCallTruthRegular(path: Path): BasicFileAttributes = callTruthAttributes(path).also {
    if (!it.isRegularFile || it.isSymbolicLink || it.fileKey() == null ||
        (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toLong() != 1L
    ) callTruthFail("call-truth file is not a single-link regular file")
}

private fun requireCallTruthIdentity(path: Path, identity: Any, directory: Boolean) {
    val attributes = if (directory) callTruthAttributes(path) else requireCallTruthRegular(path)
    if (attributes.fileKey() != identity || attributes.isSymbolicLink || attributes.isDirectory != directory) {
        callTruthFail("call-truth path changed identity")
    }
}

private fun sameCallTruthFile(left: BasicFileAttributes, right: BasicFileAttributes): Boolean =
    left.fileKey() == right.fileKey() && left.size() == right.size() && left.lastModifiedTime() == right.lastModifiedTime()

private fun forceCallTruthDirectory(path: Path) = LinuxFilesystemSyscalls.openRoot(path).use(LinuxFilesystemSyscalls::synchronize)

private fun requireCallTruthDisjoint(path: Path, protected: List<Path>) {
    val normalized = path.toAbsolutePath().normalize()
    if (normalized.parent == null || normalized.fileName == null) callTruthFail("call-truth path must name a directory")
    requireStableDirectory(normalized.parent, "call-truth path parent")
    protected.forEach {
        val other = it.toAbsolutePath().normalize()
        if (normalized.startsWith(other) || other.startsWith(normalized)) callTruthFail("call-truth paths overlap protected inputs or scratch")
    }
}

private fun JsonObject.nullableCallString(name: String): String? = when (val value = getValue(name)) {
    JsonNull -> null
    is JsonPrimitive -> if (value.isString) value.content else callTruthFail("call-truth nullable string is invalid")
    else -> callTruthFail("call-truth nullable string is invalid")
}

private fun JsonObject.callStrings(name: String): List<String> = controlArray(name).map {
    val value = it as? JsonPrimitive ?: callTruthFail("call-truth string array is invalid")
    if (!value.isString) callTruthFail("call-truth string array is invalid")
    value.content
}

private fun JsonObject.callBoolean(name: String): Boolean = (getValue(name) as? JsonPrimitive)?.booleanOrNull
    ?: callTruthFail("call-truth boolean is invalid")

private fun String?.callJson(): JsonElement = this?.let(::JsonPrimitive) ?: JsonNull
private fun callExternalId(name: String): String = "external-function-${OracleArtifacts.sha256(name.toByteArray(Charsets.UTF_8)).take(32)}"
private fun ByteArray.callHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
private fun requireCallTruthDigest(value: String) { if (!value.matches(Regex("[0-9a-f]{64}"))) callTruthFail("call-truth digest is invalid") }
private fun callTruthCpuNanos(): Long = ProcessHandle.current().info().totalCpuDuration()
    .orElseThrow { FullTreeCallTruthException("call-truth process CPU duration is unavailable") }.toNanos()
private fun callTruthFail(message: String): Nothing = throw FullTreeCallTruthException(message)
private inline fun <Result> translateCallTruthFailure(action: () -> Result): Result = try {
    action()
} catch (failure: FullTreeCallTruthException) {
    throw failure
} catch (failure: Exception) {
    throw FullTreeCallTruthException("raw call-truth reconciliation failed: ${failure.message}", failure)
}

private const val CALL_TRUTH_GIB = 1024L * 1024L * 1024L
private val CALL_TRUTH_DIRECTORY = PosixFilePermissions.fromString("rwx------")
private val CALL_TRUTH_READ_ONLY_DIRECTORY = PosixFilePermissions.fromString("r-x------")
private val CALL_TRUTH_FILE = PosixFilePermissions.fromString("rw-------")
private val CALL_TRUTH_READ_ONLY_FILE = PosixFilePermissions.fromString("r--------")
private val CALL_FUNCTION_FIELDS = listOf("counts", "functions", "nonEmitted", "oracle", "schemaVersion", "shard")
private val CALL_ELF_FIELDS = listOf("artifacts", "counts", "externalFunctions", "functions", "image", "oracle", "schemaVersion")
private val CALL_OBSERVATION_FIELDS = listOf("calls", "counts", "oracle", "schemaVersion", "shard")
private val CALL_TRUTH_INDEXED_QUERIES = listOf(
    "SELECT edge_key,signature FROM edge_groups ORDER BY edge_key COLLATE BINARY",
    "SELECT observation_id,source_shard FROM observations WHERE edge_key=? ORDER BY observation_id COLLATE BINARY",
    "SELECT function_id FROM aliases WHERE name=? ORDER BY function_id COLLATE BINARY",
    "SELECT payload FROM merged WHERE owner_shard=? ORDER BY edge_id COLLATE BINARY",
    "SELECT COALESCE(SUM(observation_count),0) FROM merged WHERE owner_shard=?",
)
private val CALL_TRUTH_POLICY = JsonObject(mapOf(
    "dispatchPolicy" to JsonPrimitive("direct-virtual-indirect-preserved-without-name-inference"),
    "externalNamespace" to JsonPrimitive("exact-undefined-elf-function-name"),
    "id" to JsonPrimitive("full-tree-call-truth"),
    "identity" to JsonPrimitive("caller-id-and-return-pc-rva"),
    "inputAuthority" to JsonPrimitive("kotlin-raw-rederived-function-truth-and-call-observation-v3"),
    "thunkPolicy" to JsonPrimitive("physical-target-retained-semantic-target-explicitly-unresolved"),
    "version" to JsonPrimitive(3),
))
