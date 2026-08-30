package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.io.BufferedOutputStream
import java.io.FilterOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager
import java.util.EnumSet
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeElfFunctionException(message: String, cause: Throwable? = null) : IllegalArgumentException(message, cause)

/** Explicit JVM/parser/scratch bounds layered beneath the authenticated full-tree scope. */
data class FullTreeElfFunctionLimits(
    val control: FullTreeControlLimits = FullTreeControlLimits(),
    val layout: FullTreeElfLayoutLimits = FullTreeElfLayoutLimits(),
    val maximumAliasesPerRva: Int = 512,
    val maximumOutputBytes: Long = 4L * 1024L * 1024L * 1024L,
    val maximumDatabaseBytes: Long = 8L * 1024L * 1024L * 1024L,
    val maximumScratchBytes: Long = 12L * 1024L * 1024L * 1024L,
    val modeledResidentBytes: Long = 128L * 1024L * 1024L,
    val maximumWorkers: Int = 32,
) {
    init {
        require(maximumAliasesPerRva in 1..512)
        require(maximumOutputBytes in 1L..8L * 1024L * 1024L * 1024L)
        require(maximumDatabaseBytes in 1L..8L * 1024L * 1024L * 1024L)
        require(maximumScratchBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(modeledResidentBytes in 1L..1024L * 1024L * 1024L)
        require(maximumWorkers in 1..32)
        require(
            modeledResidentBytes >= Math.addExact(
                layout.modeledResidentBytes(),
                ELF_FUNCTION_RESIDENT_OVERHEAD_BYTES,
            ),
        ) { "modeled resident bound understates the configured ELF parser and SQLite working set" }
    }
}

data class FullTreeElfFunctionCounts(
    val aliases: Long,
    val externalFunctions: Long,
    val functionRvas: Long,
    val strippedFunctionRvas: Long,
)

class AuthenticatedFullTreeElfFunctionIndex internal constructor(
    val sha256: String,
    val bytes: Long,
    val configurationSha256: String,
    val scopeSha256: String,
    val inventoryIndexSha256: String,
    val richInputSha256: String,
    val strippedInputSha256: String,
    val counts: FullTreeElfFunctionCounts,
    val imageBase: String,
    val elfType: String,
)

internal data class FullTreeElfRuntimeSample(
    val wallNanos: Long,
    val processCpuNanos: Long,
)

internal fun interface FullTreeElfRuntime {
    fun sample(checkpoint: String): FullTreeElfRuntimeSample
}

/** Authoritative Kotlin/JVM producer and byte-exact validator for full-tree-elf-functions v1. */
object FullTreeElfFunctionsSqlite {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256("full-tree-elf-functions", POLICY)
    }

    fun generateAndPublish(
        richArtifact: Path,
        strippedArtifact: Path,
        scope: AuthenticatedFullTreeScope,
        inventory: JsonObject,
        output: Path,
        maximumWorkers: Int,
        limits: FullTreeElfFunctionLimits = FullTreeElfFunctionLimits(),
    ): AuthenticatedFullTreeElfFunctionIndex = generateAndPublishInternal(
        richArtifact,
        strippedArtifact,
        scope,
        inventory,
        output,
        maximumWorkers,
        limits,
        SYSTEM_RUNTIME,
    )

    fun loadAndValidate(
        index: Path,
        richArtifact: Path,
        strippedArtifact: Path,
        scope: AuthenticatedFullTreeScope,
        inventory: JsonObject,
        maximumWorkers: Int,
        limits: FullTreeElfFunctionLimits = FullTreeElfFunctionLimits(),
    ): AuthenticatedFullTreeElfFunctionIndex = loadAndValidateInternal(
        index,
        richArtifact,
        strippedArtifact,
        scope,
        inventory,
        maximumWorkers,
        limits,
        SYSTEM_RUNTIME,
    )

    internal fun generateAndPublishInternal(
        richArtifact: Path,
        strippedArtifact: Path,
        scope: AuthenticatedFullTreeScope,
        inventory: JsonObject,
        output: Path,
        maximumWorkers: Int,
        limits: FullTreeElfFunctionLimits,
        runtime: FullTreeElfRuntime,
    ): AuthenticatedFullTreeElfFunctionIndex = translateFailures {
        val started = runtime.sample("at ELF function operation entry")
        val controls = authenticateControls(scope, inventory, maximumWorkers, limits, runtime, started)
        val target = output.toAbsolutePath().normalize()
        requireDistinctControlOutput(
            target,
            "rich artifact" to richArtifact,
            "stripped artifact" to strippedArtifact,
        )
        ElfFunctionWorkspace.create(target, limits).use { workspace ->
            openInputs(richArtifact, strippedArtifact, scope, limits).use { inputs ->
                val budget = controls.budget
                budget.checkpoint("before hashing ELF twins")
                val richSha = inputs.rich.sha256()
                budget.checkpoint("after hashing rich ELF")
                val strippedSha = inputs.stripped.sha256()
                budget.checkpoint("after hashing stripped ELF")
                requireArtifactBindings(scope, richSha, strippedSha)
                val projection = buildProjection(
                    workspace,
                    inputs,
                    controls,
                    richSha,
                    strippedSha,
                    limits,
                )
                val staged = projection.use { authenticatedProjection ->
                    workspace.openStagingOutput().use { channel ->
                        val outputStream = BufferedOutputStream(Channels.newOutputStream(channel), OUTPUT_BUFFER_BYTES)
                        val digest = authenticatedProjection.writeTo(outputStream, controls.outputLimit, budget)
                        outputStream.flush()
                        channel.force(true)
                        digest
                    }
                }
                workspace.checkScratchBound("after writing ELF function index")
                workspace.markDatabaseClosed()
                workspace.commit(staged, controls.outputLimit, budget, inputs::verifyUnchanged)
                projection.authenticated(staged)
            }
        }
    }

    internal fun loadAndValidateInternal(
        index: Path,
        richArtifact: Path,
        strippedArtifact: Path,
        scope: AuthenticatedFullTreeScope,
        inventory: JsonObject,
        maximumWorkers: Int,
        limits: FullTreeElfFunctionLimits,
        runtime: FullTreeElfRuntime,
    ): AuthenticatedFullTreeElfFunctionIndex = translateFailures {
        val started = runtime.sample("at ELF function operation entry")
        val controls = authenticateControls(scope, inventory, maximumWorkers, limits, runtime, started)
        requireDistinctControlOutput(
            index.toAbsolutePath().normalize(),
            "rich artifact" to richArtifact,
            "stripped artifact" to strippedArtifact,
        )
        ElfFunctionWorkspace.createValidation(index, limits).use { workspace ->
            openInputs(richArtifact, strippedArtifact, scope, limits).use { inputs ->
                val source = StableControlFile.open(index, controls.outputLimit, "full-tree ELF function index")
                source.use {
                    val budget = controls.budget
                    budget.checkpoint("before hashing ELF function inputs")
                    val indexSha = source.sha256()
                    val richSha = inputs.rich.sha256()
                    val strippedSha = inputs.stripped.sha256()
                    budget.checkpoint("after hashing ELF function inputs")
                    requireArtifactBindings(scope, richSha, strippedSha)
                    val projection = buildProjection(
                        workspace,
                        inputs,
                        controls,
                        richSha,
                        strippedSha,
                        limits,
                    )
                    val comparison = ComparingOutputStream(
                        source.slice(),
                        source.size,
                        "full-tree ELF function index",
                    )
                    val observed = projection.use { authenticatedProjection ->
                        comparison.use { sink ->
                            authenticatedProjection.writeTo(sink, controls.outputLimit, budget)
                                .also { sink.requireComplete() }
                        }
                    }
                    if (observed.sha256 != indexSha || observed.bytes != source.size) {
                        fail("full-tree ELF function index digest differs from its re-derived bytes")
                    }
                    source.verifyUnchanged("full-tree ELF function index")
                    inputs.verifyUnchanged()
                    workspace.markDatabaseClosed()
                    budget.checkpoint("after validating ELF function index")
                    projection.authenticated(observed)
                }
            }
        }
    }

    private fun authenticateControls(
        scope: AuthenticatedFullTreeScope,
        inventory: JsonObject,
        maximumWorkers: Int,
        limits: FullTreeElfFunctionLimits,
        runtime: FullTreeElfRuntime,
        started: FullTreeElfRuntimeSample,
    ): AuthenticatedControls {
        if (maximumWorkers !in 1..minOf(limits.maximumWorkers, limits.control.maximumWorkers)) {
            fail("ELF function worker count exceeds its configured bound")
        }
        FullTreeScopeControl.validate(scope, limits.control)
        val whole = scope.document.controlObject("bounds").controlObject("wholeRun")
        val budget = CooperativeElfBudget(
            started,
            runtime,
            whole.controlLong("wallClockSeconds"),
            whole.controlLong("cpuSeconds"),
        )
        budget.checkpoint("after authenticating full-tree scope")
        val snapshot = snapshotControlObject(
            inventory,
            limits.control.maximumInventoryBytes,
            "full-tree inventory",
            "full-tree-inventory",
        ).first
        FullTreeInventoryControl.validate(snapshot, scope, limits.control)
        budget.checkpoint("after authenticating full-tree inventory")
        if (limits.modeledResidentBytes > whole.controlLong("maximumResidentBytes")) {
            fail("modeled ELF function resident working set exceeds the authenticated bound")
        }
        val outputLimit = minOf(limits.maximumOutputBytes, whole.controlLong("serializedBytes"))
        if (outputLimit <= 0L) fail("authenticated ELF function output bound is empty")
        return AuthenticatedControls(
            snapshot,
            scope.sha256,
            outputLimit,
            whole.controlLong("entities"),
            budget,
        )
    }

    private fun openInputs(
        richArtifact: Path,
        strippedArtifact: Path,
        scope: AuthenticatedFullTreeScope,
        limits: FullTreeElfFunctionLimits,
    ): ElfTwinInputs {
        val maximum = minOf(limits.control.maximumRichArtifactBytes, 1024L * 1024L * 1024L)
        val rich = StableControlFile.open(richArtifact, maximum, "rich ELF artifact")
        try {
            val stripped = StableControlFile.open(strippedArtifact, maximum, "stripped ELF artifact")
            return ElfTwinInputs(rich, stripped)
        } catch (failure: Throwable) {
            try {
                rich.close()
            } catch (closeFailure: Throwable) {
                failure.addSuppressed(closeFailure)
            }
            throw failure
        }
    }

    private fun requireArtifactBindings(scope: AuthenticatedFullTreeScope, rich: String, stripped: String) {
        val oracle = scope.document.controlObject("oracle")
        if (rich != oracle.controlString("richArtifactSha256")) fail("rich ELF SHA-256 differs from scope")
        if (stripped != oracle.controlString("strippedArtifactSha256")) fail("stripped ELF SHA-256 differs from scope")
    }

    private fun buildProjection(
        workspace: ElfFunctionWorkspace,
        inputs: ElfTwinInputs,
        controls: AuthenticatedControls,
        richSha: String,
        strippedSha: String,
        limits: FullTreeElfFunctionLimits,
    ): ElfFunctionProjection {
        val database = ElfFunctionDatabase.open(workspace.database, limits, workspace, controls.budget)
        try {
            workspace.trackDatabase()
            val rich = FullTreeElfLayout.scanFunctions(
                inputs.rich,
                "rich",
                limits.layout,
                controls.budget::checkpoint,
                database::acceptRich,
            )
            database.flush("after rich ELF scan")
            val stripped = FullTreeElfLayout.scanFunctions(
                inputs.stripped,
                "stripped",
                limits.layout,
                controls.budget::checkpoint,
                database::acceptStripped,
            )
            database.flush("after stripped ELF scan")
            requireTwinLayout(rich, stripped)
            val counts = database.validateAndCount(controls.maximumEntities)
            workspace.checkScratchBound("after indexing ELF twins")
            inputs.verifyUnchanged()
            return ElfFunctionProjection(
                database,
                controls,
                rich,
                stripped,
                inputs.rich.size,
                inputs.stripped.size,
                richSha,
                strippedSha,
                counts,
            )
        } catch (failure: Throwable) {
            try {
                database.close()
                workspace.markDatabaseClosed()
            } catch (closeFailure: Throwable) {
                failure.addSuppressed(closeFailure)
            }
            throw failure
        }
    }

    private fun requireTwinLayout(rich: FullTreeElfLayoutObservation, stripped: FullTreeElfLayoutObservation) {
        if (rich.elfClass != stripped.elfClass) fail("ELF twins disagree on class")
        if (rich.byteOrder != stripped.byteOrder) fail("ELF twins disagree on byte order")
        if (rich.elfType != stripped.elfType) fail("ELF twins disagree on elfType")
        if (rich.machine != stripped.machine) fail("ELF twins disagree on machine")
        if (rich.osAbi != stripped.osAbi) fail("ELF twins disagree on OS ABI")
        if (rich.abiVersion != stripped.abiVersion) fail("ELF twins disagree on ABI version")
        if (rich.imageBase != stripped.imageBase) fail("ELF twins disagree on imageBase")
        if (rich.executableRanges != stripped.executableRanges) fail("ELF twins disagree on executableRanges")
    }

    private inline fun <T> translateFailures(action: () -> T): T = try {
        action()
    } catch (failure: FullTreeElfFunctionException) {
        throw failure
    } catch (failure: Throwable) {
        throw FullTreeElfFunctionException("full-tree ELF function operation failed: ${failure.message}", failure)
    }

    private val POLICY = JsonObject(
        mapOf(
            "id" to JsonPrimitive("full-tree-elf-functions"),
            "version" to JsonPrimitive(1),
            "identity" to JsonPrimitive("one-record-per-image-relative-function-symbol-rva"),
            "aliasPolicy" to JsonPrimitive("all-defined-stt-func-names-with-rich-stripped-availability"),
        ),
    )
    private val SYSTEM_RUNTIME = FullTreeElfRuntime { _ ->
        FullTreeElfRuntimeSample(
            System.nanoTime(),
            ProcessHandle.current().info().totalCpuDuration()
                .orElseThrow { FullTreeElfFunctionException("process CPU duration is unavailable") }
                .toNanos(),
        )
    }
}

private data class AuthenticatedControls(
    val inventory: JsonObject,
    val scopeSha256: String,
    val outputLimit: Long,
    val maximumEntities: Long,
    val budget: CooperativeElfBudget,
)

private class CooperativeElfBudget(
    private val started: FullTreeElfRuntimeSample,
    private val runtime: FullTreeElfRuntime,
    wallSeconds: Long,
    cpuSeconds: Long,
) {
    private val wallLimit = secondsToNanos(wallSeconds, "wall-clock")
    private val cpuLimit = secondsToNanos(cpuSeconds, "CPU")

    fun checkpoint(label: String) {
        val sample = runtime.sample(label)
        val wall = elapsed(started.wallNanos, sample.wallNanos, "wall-clock")
        val cpu = elapsed(started.processCpuNanos, sample.processCpuNanos, "CPU")
        if (wall > wallLimit) fail("ELF function operation exceeded wall-clock bound $label")
        if (cpu > cpuLimit) fail("ELF function operation exceeded CPU bound $label")
    }

    private fun secondsToNanos(seconds: Long, label: String): Long = try {
        Math.multiplyExact(seconds, 1_000_000_000L)
    } catch (failure: ArithmeticException) {
        throw FullTreeElfFunctionException("authenticated $label bound overflows", failure)
    }

    private fun elapsed(start: Long, end: Long, label: String): Long {
        if (end < start) fail("$label runtime sample moved backwards")
        return end - start
    }
}

private class ElfTwinInputs(
    val rich: StableControlFile,
    val stripped: StableControlFile,
) : AutoCloseable {
    fun verifyUnchanged() {
        rich.verifyUnchanged("rich ELF artifact")
        stripped.verifyUnchanged("stripped ELF artifact")
    }

    override fun close() {
        var failure: Throwable? = null
        try {
            stripped.close()
        } catch (closeFailure: Throwable) {
            failure = closeFailure
        }
        try {
            rich.close()
        } catch (closeFailure: Throwable) {
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        failure?.let { throw it }
    }
}

private data class IndexDigest(val sha256: String, val bytes: Long)

private class ElfFunctionDatabase private constructor(
    private val connection: Connection,
    private val limits: FullTreeElfFunctionLimits,
    private val workspace: ElfFunctionWorkspace,
    private val budget: CooperativeElfBudget,
) : AutoCloseable {
    private val insertRva = connection.prepareStatement(
        "INSERT OR IGNORE INTO function_rva(rva, stripped) VALUES (?, 0)",
    )
    private val insertAlias = connection.prepareStatement(
        "INSERT OR IGNORE INTO function_alias(rva, name, stripped) VALUES (?, ?, 0)",
    )
    private val insertEvidence = connection.prepareStatement(
        "INSERT INTO function_evidence(rva, name, locator) VALUES (?, ?, ?)",
    )
    private val insertExternal = connection.prepareStatement(
        "INSERT OR IGNORE INTO external_function(name, stripped) VALUES (?, 0)",
    )
    private val insertExternalEvidence = connection.prepareStatement(
        "INSERT INTO external_evidence(name, locator) VALUES (?, ?)",
    )
    private val markStrippedRva = connection.prepareStatement(
        "UPDATE function_rva SET stripped=1 WHERE rva=?",
    )
    private val markStrippedAlias = connection.prepareStatement(
        "UPDATE function_alias SET stripped=1 WHERE rva=? AND name=?",
    )
    private val markStrippedExternal = connection.prepareStatement(
        "UPDATE external_function SET stripped=1 WHERE name=?",
    )
    private var accepted = 0L
    private var closed = false

    fun acceptRich(symbol: FullTreeElfFunctionSymbol) {
        if (symbol.rva == null) {
            insertExternal.setString(1, symbol.name)
            insertExternal.executeUpdate()
            insertExternalEvidence.setString(1, symbol.name)
            insertExternalEvidence.setString(2, symbol.locator)
            insertExternalEvidence.executeUpdate()
        } else {
            val rva = rvaKey(symbol.rva)
            insertRva.setString(1, rva)
            insertRva.executeUpdate()
            insertAlias.setString(1, rva)
            insertAlias.setString(2, symbol.name)
            insertAlias.executeUpdate()
            insertEvidence.setString(1, rva)
            insertEvidence.setString(2, symbol.name)
            insertEvidence.setString(3, symbol.locator)
            insertEvidence.executeUpdate()
        }
        acceptedSymbol("rich")
    }

    fun acceptStripped(symbol: FullTreeElfFunctionSymbol) {
        if (symbol.rva == null) {
            markStrippedExternal.setString(1, symbol.name)
            if (markStrippedExternal.executeUpdate() != 1) {
                fail("stripped ELF introduces external function ${symbol.name}")
            }
            insertExternalEvidence.setString(1, symbol.name)
            insertExternalEvidence.setString(2, symbol.locator)
            insertExternalEvidence.executeUpdate()
        } else {
            val rva = rvaKey(symbol.rva)
            markStrippedAlias.setString(1, rva)
            markStrippedAlias.setString(2, symbol.name)
            if (markStrippedAlias.executeUpdate() != 1) {
                fail("stripped ELF introduces alias ${symbol.name} at ${canonicalAddress(rva)}")
            }
            markStrippedRva.setString(1, rva)
            if (markStrippedRva.executeUpdate() != 1) {
                fail("stripped ELF introduces function RVA ${canonicalAddress(rva)}")
            }
            insertEvidence.setString(1, rva)
            insertEvidence.setString(2, symbol.name)
            insertEvidence.setString(3, symbol.locator)
            insertEvidence.executeUpdate()
        }
        acceptedSymbol("stripped")
    }

    fun flush(label: String) {
        connection.commit()
        budget.checkpoint(label)
        workspace.checkDatabaseBound(label)
    }

    fun validateAndCount(maximumEntities: Long): FullTreeElfFunctionCounts {
        flush("before validating ELF function database")
        connection.prepareStatement(
            "SELECT rva FROM function_alias GROUP BY rva HAVING COUNT(*) > ? LIMIT 1",
        ).use { statement ->
            statement.setInt(1, limits.maximumAliasesPerRva)
            statement.executeQuery().use { result ->
                if (result.next()) {
                    fail(
                        "rich ELF RVA ${canonicalAddress(result.getString(1))} exceeds " +
                            "its ${limits.maximumAliasesPerRva}-alias bound",
                    )
                }
            }
        }
        assertIndexedPlans()
        val counts = FullTreeElfFunctionCounts(
            aliases = scalar("SELECT COUNT(*) FROM function_alias"),
            externalFunctions = scalar("SELECT COUNT(*) FROM external_function"),
            functionRvas = scalar("SELECT COUNT(*) FROM function_rva"),
            strippedFunctionRvas = scalar("SELECT COUNT(*) FROM function_rva WHERE stripped=1"),
        )
        if (counts.functionRvas !in 1L..maximumEntities) {
            fail("ELF function count is outside the full-tree entity bound")
        }
        if (counts.aliases < counts.functionRvas) fail("ELF function aliases do not cover every RVA")
        return counts
    }

    fun forEachFunction(action: (rva: String, stripped: Boolean) -> Unit) {
        connection.prepareStatement("SELECT rva, stripped FROM function_rva ORDER BY rva").use { statement ->
            statement.executeQuery().use { result ->
                while (result.next()) action(result.getString(1), result.getInt(2) == 1)
            }
        }
    }

    fun forEachAlias(rva: String, action: (name: String, stripped: Boolean) -> Unit) {
        connection.prepareStatement(
            "SELECT name, stripped FROM function_alias WHERE rva=? ORDER BY name",
        ).use { statement ->
            statement.setString(1, rva)
            statement.executeQuery().use { result ->
                while (result.next()) action(result.getString(1), result.getInt(2) == 1)
            }
        }
    }

    fun forEachFunctionEvidence(rva: String, name: String, action: (String) -> Unit) {
        connection.prepareStatement(
            "SELECT locator FROM function_evidence WHERE rva=? AND name=? ORDER BY locator",
        ).use { statement ->
            statement.setString(1, rva)
            statement.setString(2, name)
            statement.executeQuery().use { result ->
                while (result.next()) action(result.getString(1))
            }
        }
    }

    fun forEachExternal(action: (name: String, stripped: Boolean) -> Unit) {
        connection.prepareStatement("SELECT name, stripped FROM external_function ORDER BY name").use { statement ->
            statement.executeQuery().use { result ->
                while (result.next()) action(result.getString(1), result.getInt(2) == 1)
            }
        }
    }

    fun forEachExternalEvidence(name: String, action: (String) -> Unit) {
        connection.prepareStatement(
            "SELECT locator FROM external_evidence WHERE name=? ORDER BY locator",
        ).use { statement ->
            statement.setString(1, name)
            statement.executeQuery().use { result ->
                while (result.next()) action(result.getString(1))
            }
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        listOf(
            insertRva,
            insertAlias,
            insertEvidence,
            insertExternal,
            insertExternalEvidence,
            markStrippedRva,
            markStrippedAlias,
            markStrippedExternal,
        ).forEach { statement ->
            try {
                statement.close()
            } catch (closeFailure: Throwable) {
                if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
            }
        }
        try {
            connection.close()
        } catch (closeFailure: Throwable) {
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        failure?.let { throw it }
    }

    private fun acceptedSymbol(twin: String) {
        accepted = checkedAdd(accepted, 1L, "accepted ELF function symbol count")
        if (accepted % DATABASE_CHECKPOINT_ROWS == 0L) {
            connection.commit()
            budget.checkpoint("while indexing $twin ELF functions")
            workspace.checkDatabaseBound("while indexing $twin ELF functions")
        }
    }

    private fun scalar(sql: String): Long = connection.createStatement().use { statement ->
        statement.executeQuery(sql).use { result ->
            if (!result.next()) fail("ELF function database count is absent")
            result.getLong(1)
        }
    }

    private fun assertIndexedPlans() {
        listOf(
            "SELECT rva, stripped FROM function_rva ORDER BY rva",
            "SELECT name, stripped FROM function_alias WHERE rva='0000000000000000' ORDER BY name",
            "SELECT locator FROM function_evidence WHERE rva='0000000000000000' AND name='' ORDER BY locator",
            "SELECT name, stripped FROM external_function ORDER BY name",
            "SELECT locator FROM external_evidence WHERE name='' ORDER BY locator",
            "SELECT rva FROM function_alias GROUP BY rva HAVING COUNT(*) > 512 LIMIT 1",
        ).forEach { sql ->
            connection.createStatement().use { statement ->
                statement.executeQuery("EXPLAIN QUERY PLAN $sql").use { result ->
                    while (result.next()) {
                        if ("USE TEMP B-TREE" in result.getString(4).uppercase()) {
                            fail("ELF function database query escapes its indexed resource model")
                        }
                    }
                }
            }
        }
    }

    companion object {
        fun open(
            path: Path,
            limits: FullTreeElfFunctionLimits,
            workspace: ElfFunctionWorkspace,
            budget: CooperativeElfBudget,
        ): ElfFunctionDatabase {
            val connection = DriverManager.getConnection(SqliteJdbcPaths.create(path))
            try {
                connection.createStatement().use { statement ->
                    statement.execute("PRAGMA page_size=$SQLITE_PAGE_BYTES")
                    statement.execute("PRAGMA journal_mode=OFF")
                    statement.execute("PRAGMA synchronous=OFF")
                    statement.execute("PRAGMA temp_store=MEMORY")
                    statement.execute("PRAGMA cache_size=-${SQLITE_CACHE_BYTES / 1024}")
                    statement.execute("PRAGMA locking_mode=EXCLUSIVE")
                    statement.execute("PRAGMA foreign_keys=ON")
                    statement.execute("PRAGMA application_id=$SQLITE_APPLICATION_ID")
                    statement.execute("PRAGMA user_version=$SQLITE_SCHEMA_VERSION")
                    statement.execute(
                        "CREATE TABLE function_rva(" +
                            "rva TEXT PRIMARY KEY COLLATE BINARY CHECK(length(rva)=16)," +
                            "stripped INTEGER NOT NULL CHECK(stripped IN (0,1))) WITHOUT ROWID",
                    )
                    statement.execute(
                        "CREATE TABLE function_alias(" +
                            "rva TEXT NOT NULL COLLATE BINARY," +
                            "name TEXT NOT NULL COLLATE BINARY," +
                            "stripped INTEGER NOT NULL CHECK(stripped IN (0,1))," +
                            "PRIMARY KEY(rva,name)," +
                            "FOREIGN KEY(rva) REFERENCES function_rva(rva)) WITHOUT ROWID",
                    )
                    statement.execute(
                        "CREATE TABLE function_evidence(" +
                            "rva TEXT NOT NULL COLLATE BINARY," +
                            "name TEXT NOT NULL COLLATE BINARY," +
                            "locator TEXT NOT NULL COLLATE BINARY," +
                            "PRIMARY KEY(rva,name,locator)," +
                            "FOREIGN KEY(rva,name) REFERENCES function_alias(rva,name)) WITHOUT ROWID",
                    )
                    statement.execute(
                        "CREATE TABLE external_function(" +
                            "name TEXT PRIMARY KEY COLLATE BINARY," +
                            "stripped INTEGER NOT NULL CHECK(stripped IN (0,1))) WITHOUT ROWID",
                    )
                    statement.execute(
                        "CREATE TABLE external_evidence(" +
                            "name TEXT NOT NULL COLLATE BINARY," +
                            "locator TEXT NOT NULL COLLATE BINARY," +
                            "PRIMARY KEY(name,locator)," +
                            "FOREIGN KEY(name) REFERENCES external_function(name)) WITHOUT ROWID",
                    )
                }
                connection.createStatement().use { statement ->
                    statement.executeQuery("PRAGMA encoding").use { result ->
                        if (!result.next() || result.getString(1).uppercase() != "UTF-8") {
                            fail("ELF function database is not UTF-8")
                        }
                    }
                }
                connection.autoCommit = false
                budget.checkpoint("after creating ELF function database")
                workspace.checkDatabaseBound("after creating ELF function database")
                return ElfFunctionDatabase(connection, limits, workspace, budget)
            } catch (failure: Throwable) {
                try {
                    connection.close()
                } catch (closeFailure: Throwable) {
                    failure.addSuppressed(closeFailure)
                }
                throw failure
            }
        }
    }
}

private fun rvaKey(value: ULong): String = value.toString(16).padStart(16, '0')

private fun canonicalAddress(key: String): String {
    val digits = key.trimStart('0').ifEmpty { "0" }
    return "0x$digits"
}

private class ElfFunctionProjection(
    val database: ElfFunctionDatabase,
    private val controls: AuthenticatedControls,
    private val rich: FullTreeElfLayoutObservation,
    private val stripped: FullTreeElfLayoutObservation,
    private val richSize: Long,
    private val strippedSize: Long,
    private val richSha256: String,
    private val strippedSha256: String,
    private val counts: FullTreeElfFunctionCounts,
) : AutoCloseable {
    init {
        if (rich.scannedSymbols < 1L || stripped.scannedSymbols < 1L) {
            fail("each ELF twin must contain at least one scanned symbol")
        }
    }

    fun writeTo(
        output: OutputStream,
        maximumBytes: Long,
        budget: CooperativeElfBudget,
    ): IndexDigest {
        val bounded = DigestingBoundedOutputStream(output, maximumBytes, budget)
        val writer = ElfFunctionCanonicalWriter(bounded, database)
            .bindArtifactSizes(richSize, strippedSize)
        writer.write(
            rich,
            stripped,
            richSha256,
            strippedSha256,
            controls.scopeSha256,
            controls.inventory.controlString("indexSha256"),
            counts,
        )
        return bounded.finish()
    }

    fun authenticated(digest: IndexDigest): AuthenticatedFullTreeElfFunctionIndex =
        AuthenticatedFullTreeElfFunctionIndex(
            sha256 = digest.sha256,
            bytes = digest.bytes,
            configurationSha256 = FullTreeElfFunctionsSqlite.configurationSha256,
            scopeSha256 = controls.scopeSha256,
            inventoryIndexSha256 = controls.inventory.controlString("indexSha256"),
            richInputSha256 = richSha256,
            strippedInputSha256 = strippedSha256,
            counts = counts,
            imageBase = canonicalAddress(rvaKey(rich.imageBase)),
            elfType = rich.elfType,
        )

    override fun close() = database.close()
}

private class ElfFunctionCanonicalWriter(
    private val output: OutputStream,
    private val database: ElfFunctionDatabase,
) {
    fun write(
        rich: FullTreeElfLayoutObservation,
        stripped: FullTreeElfLayoutObservation,
        richSha256: String,
        strippedSha256: String,
        scopeSha256: String,
        inventoryIndexSha256: String,
        counts: FullTreeElfFunctionCounts,
    ) {
        ascii("{\n")
        ascii("  \"artifacts\": {\n")
        writeArtifact("rich", richSha256, rich.scannedSymbols, richSize = true, comma = true)
        writeArtifact("stripped", strippedSha256, stripped.scannedSymbols, richSize = false, comma = false)
        ascii("  },\n")
        ascii("  \"counts\": {\n")
        ascii("    \"aliases\": ${counts.aliases},\n")
        ascii("    \"externalFunctions\": ${counts.externalFunctions},\n")
        ascii("    \"functionRvas\": ${counts.functionRvas},\n")
        ascii("    \"strippedFunctionRvas\": ${counts.strippedFunctionRvas}\n")
        ascii("  },\n")
        writeExternalFunctions()
        ascii(",\n")
        writeFunctions()
        ascii(",\n")
        ascii("  \"image\": {\n")
        ascii("    \"elfType\": ")
        string(rich.elfType)
        ascii(",\n")
        ascii("    \"executableRanges\": [\n")
        rich.executableRanges.forEachIndexed { index, range ->
            ascii("      {\n")
            ascii("        \"endExclusive\": ")
            string(canonicalAddress(rvaKey(range.endExclusive)))
            ascii(",\n")
            ascii("        \"start\": ")
            string(canonicalAddress(rvaKey(range.start)))
            ascii("\n      }")
            ascii(if (index == rich.executableRanges.lastIndex) "\n" else ",\n")
        }
        ascii("    ],\n")
        ascii("    \"imageBase\": ")
        string(canonicalAddress(rvaKey(rich.imageBase)))
        ascii("\n  },\n")
        ascii("  \"oracle\": {\n")
        ascii("    \"configurationSha256\": ")
        string(FullTreeElfFunctionsSqlite.configurationSha256)
        ascii(",\n")
        ascii("    \"inventoryIndexSha256\": ")
        string(inventoryIndexSha256)
        ascii(",\n")
        ascii("    \"scopeSha256\": ")
        string(scopeSha256)
        ascii("\n  },\n")
        ascii("  \"schemaVersion\": 1\n")
        ascii("}\n")
    }

    private var richArtifactSize = -1L
    private var strippedArtifactSize = -1L

    fun bindArtifactSizes(rich: Long, stripped: Long): ElfFunctionCanonicalWriter {
        richArtifactSize = rich
        strippedArtifactSize = stripped
        return this
    }

    private fun writeArtifact(
        twin: String,
        sha256: String,
        scannedSymbols: Long,
        richSize: Boolean,
        comma: Boolean,
    ) {
        val size = if (richSize) richArtifactSize else strippedArtifactSize
        if (size <= 0L) fail("ELF artifact size is absent while writing its index")
        ascii("    \"$twin\": {\n")
        ascii("      \"inputSha256\": ")
        string(sha256)
        ascii(",\n")
        ascii("      \"scannedSymbols\": $scannedSymbols,\n")
        ascii("      \"sizeBytes\": $size\n")
        ascii("    }")
        ascii(if (comma) ",\n" else "\n")
    }

    private fun writeExternalFunctions() {
        var index = 0L
        ascii("  \"externalFunctions\": ")
        database.forEachExternal { name, stripped ->
            if (index++ == 0L) ascii("[\n") else ascii(",\n")
            ascii("    {\n")
            ascii("      \"availability\": {\n")
            ascii("        \"rich\": \"surviving\",\n")
            ascii("        \"stripped\": \"${if (stripped) "surviving" else "removed"}\"\n")
            ascii("      },\n")
            ascii("      \"evidence\": [\n")
            var evidenceIndex = 0L
            database.forEachExternalEvidence(name) { locator ->
                if (evidenceIndex++ > 0L) ascii(",\n")
                ascii("        {\n")
                ascii("          \"kind\": \"elf-symbol\",\n")
                ascii("          \"locator\": ")
                string(locator)
                ascii("\n        }")
            }
            if (evidenceIndex == 0L) fail("external ELF alias has no evidence")
            ascii("\n      ],\n")
            ascii("      \"name\": ")
            string(name)
            ascii("\n    }")
        }
        ascii(if (index == 0L) "[]" else "\n  ]")
    }

    private fun writeFunctions() {
        var functionIndex = 0L
        ascii("  \"functions\": ")
        database.forEachFunction { rva, _ ->
            if (functionIndex++ == 0L) ascii("[\n") else ascii(",\n")
            ascii("    {\n")
            ascii("      \"aliases\": [\n")
            var aliasIndex = 0L
            database.forEachAlias(rva) { name, stripped ->
                if (aliasIndex++ > 0L) ascii(",\n")
                ascii("        {\n")
                ascii("          \"availability\": {\n")
                ascii("            \"rich\": \"surviving\",\n")
                ascii("            \"stripped\": \"${if (stripped) "surviving" else "removed"}\"\n")
                ascii("          },\n")
                ascii("          \"evidence\": [\n")
                var evidenceIndex = 0L
                database.forEachFunctionEvidence(rva, name) { locator ->
                    if (evidenceIndex++ > 0L) ascii(",\n")
                    ascii("            {\n")
                    ascii("              \"kind\": \"elf-symbol\",\n")
                    ascii("              \"locator\": ")
                    string(locator)
                    ascii("\n            }")
                }
                if (evidenceIndex == 0L) fail("defined ELF alias has no evidence")
                ascii("\n          ],\n")
                ascii("          \"name\": ")
                string(name)
                ascii("\n        }")
            }
            if (aliasIndex == 0L) fail("ELF function RVA has no alias")
            val address = canonicalAddress(rva)
            ascii("\n      ],\n")
            ascii("      \"id\": ")
            string("function-rva-$address")
            ascii(",\n")
            ascii("      \"rva\": ")
            string(address)
            ascii("\n    }")
        }
        if (functionIndex == 0L) fail("ELF function index is empty")
        ascii("\n  ]")
    }

    private fun string(value: String) {
        val canonical = try {
            OracleJson.canonicalBytes(
                JsonPrimitive(value),
                StrictJsonLimits(
                    maximumInputBytes = 1024 * 1024,
                    maximumCanonicalBytes = 1024 * 1024,
                    maximumDepth = 2,
                    maximumNodes = 2,
                    maximumStringBytes = 1024 * 1024,
                    maximumTotalStringBytes = 1024 * 1024,
                ),
            )
        } catch (failure: Exception) {
            throw FullTreeElfFunctionException("cannot encode ELF function string", failure)
        }
        if (canonical.isEmpty() || canonical.last() != '\n'.code.toByte()) {
            fail("canonical ELF function string is malformed")
        }
        output.write(canonical, 0, canonical.size - 1)
    }

    private fun ascii(value: String) {
        output.write(value.toByteArray(StandardCharsets.US_ASCII))
    }
}

private class DigestingBoundedOutputStream(
    output: OutputStream,
    private val maximumBytes: Long,
    private val budget: CooperativeElfBudget,
) : FilterOutputStream(output) {
    private val digest = MessageDigest.getInstance("SHA-256")
    private var count = 0L
    private var nextCheckpoint = OUTPUT_CHECKPOINT_BYTES
    private var finished = false

    override fun write(value: Int) {
        val byte = byteArrayOf(value.toByte())
        write(byte, 0, 1)
    }

    override fun write(bytes: ByteArray, offset: Int, length: Int) {
        if (finished) fail("ELF function output digest is already complete")
        if (offset < 0 || length < 0 || offset > bytes.size - length) throw IndexOutOfBoundsException()
        if (count > maximumBytes - length.toLong()) fail("ELF function index exceeds its byte bound")
        out.write(bytes, offset, length)
        digest.update(bytes, offset, length)
        count += length.toLong()
        if (count >= nextCheckpoint) {
            budget.checkpoint("while writing ELF function index")
            nextCheckpoint = checkedAdd(nextCheckpoint, OUTPUT_CHECKPOINT_BYTES, "output checkpoint")
        }
    }

    fun finish(): IndexDigest {
        if (finished) fail("ELF function output digest is already complete")
        finished = true
        budget.checkpoint("after writing ELF function index")
        return IndexDigest(digest.digest().hex(), count)
    }
}

private class ComparingOutputStream(
    private val source: InputStream,
    private val expectedBytes: Long,
    private val label: String,
) : OutputStream() {
    private var compared = 0L
    private var complete = false

    override fun write(value: Int) {
        val observed = source.read()
        if (observed < 0 || observed != (value and 0xff)) fail("$label differs from re-derived canonical bytes")
        compared++
    }

    override fun write(bytes: ByteArray, offset: Int, length: Int) {
        if (offset < 0 || length < 0 || offset > bytes.size - length) throw IndexOutOfBoundsException()
        var consumed = 0
        val observed = ByteArray(minOf(length, OUTPUT_BUFFER_BYTES))
        while (consumed < length) {
            val requested = minOf(observed.size, length - consumed)
            var readTotal = 0
            while (readTotal < requested) {
                val read = source.read(observed, readTotal, requested - readTotal)
                if (read < 0) fail("$label is truncated relative to re-derived canonical bytes")
                readTotal += read
            }
            if (!MessageDigest.isEqual(
                    bytes.copyOfRange(offset + consumed, offset + consumed + requested),
                    observed.copyOf(requested),
                )
            ) fail("$label differs from re-derived canonical bytes")
            consumed += requested
            compared = checkedAdd(compared, requested.toLong(), "validated ELF function byte count")
        }
    }

    fun requireComplete() {
        if (compared != expectedBytes || source.read() >= 0) fail("$label has extra or missing canonical bytes")
        complete = true
    }

    override fun close() {
        try {
            source.close()
        } finally {
            super.close()
        }
    }
}

private class ElfFunctionWorkspace private constructor(
    private val target: Path,
    private val root: Path,
    val database: Path,
    private val staging: Path?,
    private val parentIdentity: Any,
    private val rootIdentity: Any,
    private val databaseIdentity: Any,
    private val stagingIdentity: Any?,
    private val limits: FullTreeElfFunctionLimits,
) : AutoCloseable {
    private var databaseClosed = false
    private var databaseDeleted = false
    private var stagingMoved = false
    private var committed = false

    fun trackDatabase() {
        requireFileIdentity(database, databaseIdentity, "ELF function database")
        Files.setPosixFilePermissions(database, PRIVATE_FILE_PERMISSIONS)
    }

    fun markDatabaseClosed() {
        databaseClosed = true
    }

    fun openStagingOutput(): FileChannel {
        val path = staging ?: fail("validation workspace has no publication staging file")
        requireFileIdentity(path, stagingIdentity ?: fail("ELF function staging identity is absent"), "ELF function staging file")
        return FileChannel.open(
            path,
            StandardOpenOption.WRITE,
            StandardOpenOption.TRUNCATE_EXISTING,
            LinkOption.NOFOLLOW_LINKS,
        )
    }

    fun checkDatabaseBound(label: String) {
        val size = Files.size(database)
        if (size > limits.maximumDatabaseBytes) fail("ELF function database exceeds its byte bound $label")
        checkScratchBound(label)
    }

    fun checkScratchBound(label: String) {
        requireDirectoryIdentity(root, rootIdentity, "ELF function scratch directory")
        val expected = mutableSetOf(root, database)
        staging?.let(expected::add)
        var bytes = 0L
        val actual = hashSetOf<Path>()
        Files.walk(root).use { paths ->
            paths.forEach { raw ->
                val path = raw.toAbsolutePath().normalize()
                if (!actual.add(path) || path !in expected) fail("ELF function scratch contains an unexpected path $label")
                val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                if (attributes.isSymbolicLink || (path == root && !attributes.isDirectory) ||
                    (path != root && !attributes.isRegularFile)
                ) fail("ELF function scratch contains an invalid path type $label")
                if (attributes.isRegularFile) bytes = checkedAdd(bytes, attributes.size(), "scratch byte count")
            }
        }
        if (actual != expected) fail("ELF function scratch is incomplete $label")
        if (bytes > limits.maximumScratchBytes) fail("ELF function scratch exceeds its aggregate byte bound $label")
    }

    fun commit(
        expected: IndexDigest,
        maximumBytes: Long,
        budget: CooperativeElfBudget,
        verifyInputs: () -> Unit,
    ) {
        val stage = staging ?: fail("validation workspace cannot publish")
        val stageIdentity = stagingIdentity ?: fail("ELF function staging identity is absent")
        if (!databaseClosed) fail("ELF function database must be closed before publication")
        checkScratchBound("before ELF function publication")
        StableControlFile.open(stage, maximumBytes, "staged ELF function index").use { source ->
            if (source.size != expected.bytes || source.sha256() != expected.sha256) {
                fail("staged ELF function index differs from generated bytes")
            }
            source.verifyUnchanged("staged ELF function index")
        }
        deleteTrackedFile(database, databaseIdentity, "ELF function database")
        databaseDeleted = true
        requireExactMembership(setOf(root, stage), "ELF function publication staging")
        Files.setPosixFilePermissions(stage, READ_ONLY_FILE_PERMISSIONS)
        if (Files.getPosixFilePermissions(stage, LinkOption.NOFOLLOW_LINKS) != READ_ONLY_FILE_PERMISSIONS) {
            fail("staged ELF function index permissions differ")
        }
        forceDirectory(root)
        requireDirectoryIdentity(target.parent, parentIdentity, "ELF function output parent")
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) fail("ELF function output target already exists")
        forceDirectory(target.parent)
        var published = false
        try {
            try {
                Files.move(stage, target, StandardCopyOption.ATOMIC_MOVE)
            } catch (failure: AtomicMoveNotSupportedException) {
                throw FullTreeElfFunctionException("atomic ELF function publication is unavailable", failure)
            }
            published = true
            stagingMoved = true
            forceDirectory(target.parent)
            requireDirectoryIdentity(target.parent, parentIdentity, "ELF function output parent")
            requireFileIdentity(target, stageIdentity, "published ELF function index")
            if (Files.getPosixFilePermissions(target, LinkOption.NOFOLLOW_LINKS) != READ_ONLY_FILE_PERMISSIONS) {
                fail("published ELF function index permissions differ")
            }
            StableControlFile.open(target, maximumBytes, "published ELF function index").use { source ->
                if (source.size != expected.bytes || source.sha256() != expected.sha256) {
                    fail("published ELF function index differs from staged bytes")
                }
                source.verifyUnchanged("published ELF function index")
            }
            verifyInputs()
            budget.checkpoint("after verifying atomic ELF function publication")
            requireDirectoryIdentity(root, rootIdentity, "ELF function scratch directory")
            requireExactMembership(setOf(root), "ELF function scratch after publication")
            Files.delete(root)
            forceDirectory(target.parent)
            committed = true
        } catch (failure: Throwable) {
            if (published) {
                try {
                    revokePublished(stageIdentity)
                } catch (revokeFailure: Throwable) {
                    failure.addSuppressed(revokeFailure)
                }
            }
            throw failure
        }
    }

    override fun close() {
        if (committed || !Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
        requireDirectoryIdentity(root, rootIdentity, "ELF function scratch directory")
        val expected = mutableMapOf<Path, Any>()
        if (!databaseDeleted) expected[database] = databaseIdentity
        if (!stagingMoved && staging != null && stagingIdentity != null) expected[staging] = stagingIdentity
        val actual = Files.walk(root).use { it.toList().toSet() }
        val expectedPaths = expected.keys.toMutableSet().apply { add(root) }
        if (actual != expectedPaths) fail("ELF function scratch changed membership during cleanup")
        var failure: Throwable? = null
        expected.forEach { (path, identity) ->
            try {
                deleteTrackedFile(path, identity, "ELF function scratch file")
            } catch (cleanupFailure: Throwable) {
                if (failure == null) failure = cleanupFailure else failure.addSuppressed(cleanupFailure)
            }
        }
        try {
            requireDirectoryIdentity(root, rootIdentity, "ELF function scratch directory")
            Files.delete(root)
            forceDirectory(target.parent)
        } catch (cleanupFailure: Throwable) {
            if (failure == null) failure = cleanupFailure else failure.addSuppressed(cleanupFailure)
        }
        failure?.let { throw it }
    }

    private fun revokePublished(expectedIdentity: Any) {
        requireFileIdentity(target, expectedIdentity, "unverified ELF function publication")
        Files.setPosixFilePermissions(target, PRIVATE_FILE_PERMISSIONS)
        requireFileIdentity(target, expectedIdentity, "unverified ELF function publication")
        Files.delete(target)
        forceDirectory(target.parent)
    }

    private fun requireExactMembership(expected: Set<Path>, label: String) {
        val actual = Files.walk(root).use { it.toList().toSet() }
        if (actual != expected) fail("$label has unexpected membership")
        actual.forEach { path ->
            val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            if (attributes.isSymbolicLink || (path == root && !attributes.isDirectory) ||
                (path != root && !attributes.isRegularFile)
            ) fail("$label has an invalid path type")
        }
    }

    companion object {
        fun create(targetPath: Path, limits: FullTreeElfFunctionLimits): ElfFunctionWorkspace =
            createInternal(targetPath, limits, publication = true)

        fun createValidation(indexPath: Path, limits: FullTreeElfFunctionLimits): ElfFunctionWorkspace =
            createInternal(indexPath, limits, publication = false)

        private fun createInternal(
            targetPath: Path,
            limits: FullTreeElfFunctionLimits,
            publication: Boolean,
        ): ElfFunctionWorkspace {
            val target = targetPath.toAbsolutePath().normalize()
            if (target.fileName == null || target.parent == null) fail("ELF function index path must name a file")
            val (parent, parentIdentity) = requireStableDirectory(target.parent, "ELF function index parent")
            if (publication && Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                fail("ELF function output target already exists")
            }
            var root: Path? = null
            var rootIdentity: Any? = null
            var database: Path? = null
            var databaseIdentity: Any? = null
            var staging: Path? = null
            var stagingIdentity: Any? = null
            try {
                root = Files.createTempDirectory(
                    parent,
                    ".${target.fileName}.elf-functions-scratch-",
                    PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS),
                )
                rootIdentity = directoryIdentity(root, "ELF function scratch directory")
                database = Files.createFile(
                    root.resolve("state.sqlite"),
                    PosixFilePermissions.asFileAttribute(PRIVATE_FILE_PERMISSIONS),
                )
                databaseIdentity = fileIdentity(database, "ELF function database")
                if (publication) {
                    staging = Files.createFile(
                        root.resolve("index.json"),
                        PosixFilePermissions.asFileAttribute(PRIVATE_FILE_PERMISSIONS),
                    )
                    stagingIdentity = fileIdentity(staging, "ELF function staging file")
                }
                forceDirectory(root)
                forceDirectory(parent)
                requireDirectoryIdentity(parent, parentIdentity, "ELF function index parent")
                return ElfFunctionWorkspace(
                    target,
                    root,
                    database,
                    staging,
                    parentIdentity,
                    rootIdentity,
                    databaseIdentity,
                    stagingIdentity,
                    limits,
                )
            } catch (failure: Throwable) {
                cleanupPartial(staging, stagingIdentity, failure)
                cleanupPartial(database, databaseIdentity, failure)
                if (root != null) {
                    try {
                        if (rootIdentity != null) requireDirectoryIdentity(root, rootIdentity, "partial ELF function scratch")
                        Files.deleteIfExists(root)
                    } catch (cleanupFailure: Throwable) {
                        failure.addSuppressed(cleanupFailure)
                    }
                }
                throw failure
            }
        }

        private fun cleanupPartial(path: Path?, identity: Any?, failure: Throwable) {
            if (path == null) return
            try {
                if (identity != null) requireFileIdentity(path, identity, "partial ELF function scratch file")
                Files.deleteIfExists(path)
            } catch (cleanupFailure: Throwable) {
                failure.addSuppressed(cleanupFailure)
            }
        }
    }
}

private fun directoryIdentity(path: Path, label: String): Any {
    val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
        fail("$label must be an identified real directory")
    }
    return attributes.fileKey()
}

private fun fileIdentity(path: Path, label: String): Any {
    val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
        fail("$label must be an identified regular file")
    }
    return attributes.fileKey()
}

private fun requireDirectoryIdentity(path: Path, expected: Any, label: String) {
    if (directoryIdentity(path, label) != expected) fail("$label changed identity")
}

private fun requireFileIdentity(path: Path, expected: Any, label: String) {
    if (fileIdentity(path, label) != expected) fail("$label changed identity")
}

private fun deleteTrackedFile(path: Path, expected: Any, label: String) {
    requireFileIdentity(path, expected, label)
    Files.delete(path)
}

private fun forceDirectory(path: Path) {
    FileChannel.open(path, StandardOpenOption.READ).use { channel -> channel.force(true) }
}

private fun checkedAdd(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeElfFunctionException("$label overflows", failure)
}

private const val DATABASE_CHECKPOINT_ROWS = 4096L
private const val OUTPUT_CHECKPOINT_BYTES = 1024L * 1024L
private const val SQLITE_PAGE_BYTES = 4096
private const val SQLITE_CACHE_BYTES = 16L * 1024L * 1024L
private const val ELF_FUNCTION_RESIDENT_OVERHEAD_BYTES = 32L * 1024L * 1024L
private const val SQLITE_APPLICATION_ID = 0x44434546
private const val SQLITE_SCHEMA_VERSION = 1
private val PRIVATE_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
private val PRIVATE_FILE_PERMISSIONS: Set<PosixFilePermission> = EnumSet.of(
    PosixFilePermission.OWNER_READ,
    PosixFilePermission.OWNER_WRITE,
)
private val READ_ONLY_FILE_PERMISSIONS: Set<PosixFilePermission> = EnumSet.of(PosixFilePermission.OWNER_READ)

private fun fail(message: String): Nothing = throw FullTreeElfFunctionException(message)

private const val OUTPUT_BUFFER_BYTES = 1024 * 1024
