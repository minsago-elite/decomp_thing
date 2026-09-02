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
import java.math.BigDecimal
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.OpenOption
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
import java.sql.ResultSet
import java.util.EnumSet
import java.util.TreeMap
import kotlin.math.min
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

internal class FullTreeFunctionTruthException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** Exact aggregate populations published by the current function-truth v2 policy. */
internal data class FullTreeFunctionTruthCounts(
    val elfRvas: Long,
    val dwarfRvas: Long,
    val scoredRvas: Long,
    val elfOnlyRvas: Long,
    val dwarfOnlyRvas: Long,
    val nonEmittedObservations: Long,
    val nonEmittedUnique: Long,
    val inlineOnlyUnique: Long,
    val selectedElsewhereUnique: Long,
    val definitionNoRangeUnique: Long,
    val coalescedEmittedRvas: Long,
) {
    internal fun toJson(): JsonObject = JsonObject(
        mapOf(
            "coalescedEmittedRvas" to JsonPrimitive(coalescedEmittedRvas),
            "definitionNoRangeUnique" to JsonPrimitive(definitionNoRangeUnique),
            "dwarfOnlyRvas" to JsonPrimitive(dwarfOnlyRvas),
            "dwarfRvas" to JsonPrimitive(dwarfRvas),
            "elfOnlyRvas" to JsonPrimitive(elfOnlyRvas),
            "elfRvas" to JsonPrimitive(elfRvas),
            "inlineOnlyUnique" to JsonPrimitive(inlineOnlyUnique),
            "nonEmittedObservations" to JsonPrimitive(nonEmittedObservations),
            "nonEmittedUnique" to JsonPrimitive(nonEmittedUnique),
            "scoredRvas" to JsonPrimitive(scoredRvas),
            "selectedElsewhereUnique" to JsonPrimitive(selectedElsewhereUnique),
        ),
    )
}

/**
 * Authenticated bytes from one deterministic Kotlin reconciliation.
 *
 * This receipt is deliberately not authoritative release evidence. The current entry point uses
 * a caller-supplied scratch parent and consumes an already-published bounded-shard tree; it does
 * not prove the missing all-shard isolated lifecycle and aggregate lease accounting tracked by
 * issue #138. ACP may consume the published truth read-only, but neither ACP nor Python belongs to
 * this derivation or validation boundary.
 */
internal class FullTreeFunctionTruthGeneration internal constructor(
    val root: Path,
    val index: JsonObject,
    val indexArtifactSha256: String,
    val indexSha256: String,
    val observationIndexArtifactSha256: String,
    val elfIndexArtifactSha256: String,
    val outputBytes: Long,
    val databaseHighWaterBytes: Long,
    val counts: FullTreeFunctionTruthCounts,
) {
    /** Always false until the isolated all-shard authority and lease lifecycle are complete. */
    val authoritativeReleaseEvidence: Boolean = false
}

/**
 * Exact comparison of an existing tree with a fresh Kotlin reconciliation from raw inputs.
 *
 * Candidate bytes never supply oracle facts: the validator independently rederives the ELF index,
 * every function-observation shard, and the complete truth projection before comparing the closed
 * tree. This receipt remains non-authoritative until issue #138 supplies the aggregate isolated
 * lifecycle and a later release owner composes that authority.
 */
internal sealed interface FullTreeFunctionTruthValidation {
    val indexArtifactSha256: String
    val indexSha256: String
    val observationIndexArtifactSha256: String
    val elfIndexArtifactSha256: String
    val outputBytes: Long
    val databaseHighWaterBytes: Long
    val counts: FullTreeFunctionTruthCounts
    val rawInputsRederived: Boolean
    val candidateBytesMatchedAtValidationBoundary: Boolean
    val candidateLeaseRetained: Boolean
    val downstreamScoringAuthorized: Boolean
    val authoritativeReleaseEvidence: Boolean
}

/** Independent implementation ceilings beneath the authenticated full-tree scope. */
internal data class FullTreeFunctionTruthLimits(
    val control: FullTreeControlLimits = FullTreeControlLimits(),
    val elfFunctions: FullTreeElfFunctionLimits = FullTreeElfFunctionLimits(),
    val observationRun: BoundedShardRunLimits = BoundedShardRunLimits(),
    val observationShard: FullTreeFunctionObservationShardPublisherLimits =
        FullTreeFunctionObservationShardPublisherLimits(),
    val maximumElfIndexBytes: Long = 4L * 1024L * 1024L * 1024L,
    val maximumObservationInputBytes: Long = 512L * 1024L * 1024L,
    val maximumDatabaseBytes: Long = 8L * 1024L * 1024L * 1024L,
    val maximumScratchBytes: Long = 16L * 1024L * 1024L * 1024L,
    val maximumOutputBytes: Long = 4L * 1024L * 1024L * 1024L,
    val maximumEntityBytes: Int = 64 * 1024 * 1024,
    val maximumEntityNodes: Int = 1_000_000,
    val maximumGroupRows: Int = 1_000_000,
    val maximumTokensPerInput: Long = 1_000_000_000L,
    val maximumStringBytes: Int = 1024 * 1024,
    val maximumTotalStringBytesPerInput: Long = 512L * 1024L * 1024L,
    val maximumSqliteCacheBytes: Int = 16 * 1024 * 1024,
    val databaseCheckpointRows: Int = 4096,
    val modeledResidentBytes: Long = 256L * 1024L * 1024L,
    val maximumWorkers: Int = 32,
) {
    init {
        require(maximumElfIndexBytes in 1L..8L * 1024L * 1024L * 1024L)
        require(maximumObservationInputBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumDatabaseBytes in SQLITE_PAGE_BYTES..8L * 1024L * 1024L * 1024L)
        require(maximumScratchBytes in maximumDatabaseBytes..16L * 1024L * 1024L * 1024L)
        require(maximumOutputBytes in 1L..8L * 1024L * 1024L * 1024L)
        require(maximumEntityBytes in 1..64 * 1024 * 1024)
        require(maximumEntityNodes in 1..1_000_000)
        require(maximumGroupRows in 1..1_000_000)
        require(maximumTokensPerInput in 1L..1_000_000_000L)
        require(maximumStringBytes in 1..maximumEntityBytes)
        require(maximumTotalStringBytesPerInput in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumSqliteCacheBytes in 1024..64 * 1024 * 1024)
        require(databaseCheckpointRows in 1..1_000_000)
        require(modeledResidentBytes in 1L..2L * 1024L * 1024L * 1024L)
        val minimumModeledResidentBytes = Math.addExact(
            MODELED_FIXED_RESIDENT_BYTES,
            Math.addExact(
                maximumSqliteCacheBytes.toLong(),
                Math.multiplyExact(maximumEntityBytes.toLong(), MODELED_ENTITY_RESIDENT_COPIES),
            ),
        )
        require(modeledResidentBytes >= minimumModeledResidentBytes)
        require(maximumWorkers in 1..32)
    }
}

/**
 * Kotlin-only raw-path function-truth v2 producer.
 *
 * The accepted observation root is exactly the generic four-member bounded-shard tree. Historical
 * migration roots that also carry `control`, `usage`, or `execution-evidence.json` are rejected;
 * accepting those members requires a separate validator that authenticates every extra artifact.
 * This object remains internal until issue #138 supplies an opaque all-shard execution/scratch
 * authority rather than a caller-selected directory. Like the existing bounded-run publisher,
 * this pathname slice requires cooperation from the filesystem owner and same-eUID processes;
 * it is not a mutation boundary against its own Unix principal.
 */
internal object FullTreeFunctionTruthSqlite {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256(
            listOf(
                "full-tree-function-exclusions",
                "full-tree-function-truth",
                "full-tree-function-truth-index",
            ),
            POLICY,
        ).also { digest ->
            if (digest != FROZEN_CONFIGURATION_SHA256) {
                truthFail("bundled function-truth schemas differ from the frozen v2 contract")
            }
        }
    }

    fun generateAndPublish(
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
        limits: FullTreeFunctionTruthLimits = FullTreeFunctionTruthLimits(),
    ): FullTreeFunctionTruthGeneration = reconcile(
        richArtifact = richArtifact,
        strippedArtifact = strippedArtifact,
        inventoryPath = inventoryPath,
        elfFunctionIndex = elfFunctionIndex,
        observationRoot = observationRoot,
        expectedObservationIndexArtifactSha256 = expectedObservationIndexArtifactSha256,
        scope = scope,
        scratchParent = scratchParent,
        resultRoot = outputRoot,
        maximumWorkers = maximumWorkers,
        limits = limits,
        finish = ::publishReconciliation,
    )

    /**
     * Validates a candidate tree only by exact comparison with a fresh raw-input reconciliation.
     * The candidate is read-only input and is never repaired, copied, renamed, or republished.
     */
    fun loadAndValidate(
        candidateRoot: Path,
        richArtifact: Path,
        strippedArtifact: Path,
        inventoryPath: Path,
        elfFunctionIndex: Path,
        observationRoot: Path,
        expectedObservationIndexArtifactSha256: String,
        scope: AuthenticatedFullTreeScope,
        scratchParent: Path,
        maximumWorkers: Int,
        limits: FullTreeFunctionTruthLimits = FullTreeFunctionTruthLimits(),
    ): FullTreeFunctionTruthValidation = reconcile(
        richArtifact = richArtifact,
        strippedArtifact = strippedArtifact,
        inventoryPath = inventoryPath,
        elfFunctionIndex = elfFunctionIndex,
        observationRoot = observationRoot,
        expectedObservationIndexArtifactSha256 = expectedObservationIndexArtifactSha256,
        scope = scope,
        scratchParent = scratchParent,
        resultRoot = candidateRoot,
        maximumWorkers = maximumWorkers,
        limits = limits,
        finish = ::validateReconciliation,
    )

    /**
     * Derives a function baseline only from the private raw-reconciled projection while the exact
     * candidate, raw inputs, and observation run remain live and recheckable.
     */
    fun generateBaselineAndPublish(
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
        limits: FullTreeFunctionBaselineLimits = FullTreeFunctionBaselineLimits(),
    ): FullTreeFunctionBaselineGeneration = FullTreeFunctionBaselineSqlite.generateAndPublishFromRawInputs(
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
    )

    /**
     * Supplies only a live, raw-rederived projection. Callers cannot substitute candidate bytes;
     * the private reconciliation owns construction, rechecks, and terminal cleanup.
     */
    internal fun <T> withValidatedBaselineProjection(
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
        consume: (
            FullTreeFunctionBaselineRawProjection,
            (String) -> Unit,
            () -> Unit,
        ) -> T,
    ): T {
        requireFunctionBaselineOutputDisjoint(
            outputRoot,
            listOf(
                candidateRoot,
                richArtifact,
                strippedArtifact,
                inventoryPath,
                elfFunctionIndex,
                observationRoot,
                scratchParent,
            ),
        )
        return reconcile(
            richArtifact = richArtifact,
            strippedArtifact = strippedArtifact,
            inventoryPath = inventoryPath,
            elfFunctionIndex = elfFunctionIndex,
            observationRoot = observationRoot,
            expectedObservationIndexArtifactSha256 = expectedObservationIndexArtifactSha256,
            scope = scope,
            scratchParent = scratchParent,
            resultRoot = candidateRoot,
            maximumWorkers = maximumWorkers,
            limits = limits.truth,
            finish = { reconciliation ->
                withValidatedFunctionTruthCandidate(reconciliation) { validation ->
                    consume(
                        validation.baselineProjection(limits),
                        validation::recheck,
                        validation::release,
                    )
                }
            },
        )
    }

    private fun <T> reconcile(
        richArtifact: Path,
        strippedArtifact: Path,
        inventoryPath: Path,
        elfFunctionIndex: Path,
        observationRoot: Path,
        expectedObservationIndexArtifactSha256: String,
        scope: AuthenticatedFullTreeScope,
        scratchParent: Path,
        resultRoot: Path,
        maximumWorkers: Int,
        limits: FullTreeFunctionTruthLimits,
        finish: (FunctionTruthReconciliation) -> T,
    ): T = translateTruthFailures {
        requireSha256(expectedObservationIndexArtifactSha256, "function-observation index artifact")
        if (maximumWorkers !in 1..min(limits.maximumWorkers, limits.control.maximumWorkers)) {
            truthFail("function-truth worker count exceeds its implementation bound")
        }
        FullTreeScopeControl.validate(scope, limits.control)
        val wholeRun = scope.document.truthObject("bounds").truthObject("wholeRun")
        if (limits.modeledResidentBytes > wholeRun.truthLong("maximumResidentBytes")) {
            truthFail("function-truth modeled resident set exceeds the authenticated whole-run bound")
        }
        val budget = FunctionTruthBudget(scope)
        budget.checkpoint("after authenticating function-truth scope")

        val paths = FunctionTruthPaths.authenticate(
            richArtifact,
            strippedArtifact,
            inventoryPath,
            elfFunctionIndex,
            observationRoot,
            scratchParent,
            resultRoot,
        )
        FunctionTruthInputGuards.open(paths, limits).use { guards ->
            val inventory = FullTreeInventoryControl.loadAndValidate(
                paths.inventory,
                scope,
                limits.control,
            )
            if (guards.inventory.authenticatedSha256 != guards.inventory.sha256()) {
                truthFail("full-tree inventory changed while it was validated")
            }
            val inventoryArtifactSha256 = guards.inventory.authenticatedSha256
            val expectedInputs = FullTreeFunctionObservations.shardInputs(
                inventory,
                inventoryArtifactSha256,
                scope.document,
                scope.sha256,
            )
            if (expectedInputs.isEmpty()) truthFail("function truth requires at least one inventory shard")
            if (maximumWorkers > expectedInputs.size) {
                // The historical run contract records min(caller workers, shard population). The
                // caller value remains accepted; exact comparison below uses that deterministic cap.
                budget.checkpoint("after capping function-truth worker declaration")
            }

            val elf = FullTreeElfFunctionsSqlite.loadAndValidate(
                index = paths.elfIndex,
                richArtifact = paths.rich,
                strippedArtifact = paths.stripped,
                scope = scope,
                inventory = inventory,
                maximumWorkers = maximumWorkers,
                limits = limits.elfFunctions,
            )
            if (
                elf.sha256 != guards.elfIndex.authenticatedSha256 ||
                elf.bytes != guards.elfIndex.size ||
                elf.scopeSha256 != scope.sha256 ||
                elf.inventoryIndexSha256 != inventory.truthString("indexSha256") ||
                elf.richInputSha256 != guards.rich.authenticatedSha256 ||
                elf.strippedInputSha256 != guards.stripped.authenticatedSha256
            ) {
                truthFail("ELF function index authentication differs from the pinned raw inputs")
            }
            budget.checkpoint("after re-deriving the ELF function index")

            val observation = authenticateObservationRun(
                paths.observations,
                expectedObservationIndexArtifactSha256,
                expectedInputs,
                scope,
                maximumWorkers,
                limits,
            )
            budget.checkpoint("after authenticating the bounded function-observation run")

            FunctionTruthScratch.create(paths.scratchParent, limits).use { scratch ->
                val oracle = truthOracle(
                    scope = scope,
                    inventory = inventory,
                    observationIndexArtifactSha256 = observation.indexArtifactSha256,
                    elfIndexArtifactSha256 = elf.sha256,
                )
                val database = FunctionTruthDatabase.open(scratch.database, limits, budget, scratch)
                try {
                    database.ingestElf(
                        paths.elfIndex,
                        elf,
                        scope,
                        inventory,
                        limits,
                    )
                    database.flush("after ingesting the ELF function index")

                    observation.outputs.forEachIndexed { index, binding ->
                        budget.checkpoint("before re-deriving function-observation shard ${binding.shardId}")
                        val candidate = observation.root.resolve(OUTPUTS_DIRECTORY).resolve("${binding.shardId}.json")
                        val receipt = FullTreeFunctionObservationShardPublisher.loadAndValidate(
                            candidate = candidate,
                            richArtifact = paths.rich,
                            inventoryPath = paths.inventory,
                            scope = scope,
                            shardId = binding.shardId,
                            scratchParent = scratch.validation,
                            limits = limits.observationShard,
                        )
                        requireObservationReceipt(
                            receipt,
                            binding,
                            inventoryArtifactSha256,
                            guards.rich.authenticatedSha256,
                            scope.sha256,
                        )
                        scratch.chargeTransientValidation(
                            receipt.databaseHighWaterBytes,
                            "while validating function-observation shard ${binding.shardId}",
                        )
                        database.ingestObservation(
                            candidate,
                            receipt,
                            binding,
                            inventory,
                            scope,
                            limits,
                        )
                        database.flush("after ingesting function-observation shard ${binding.shardId}")
                        if ((index + 1) % limits.databaseCheckpointRows == 0) {
                            budget.checkpoint("while ingesting function-observation shards")
                        }
                    }
                    requireObservationRunUnchanged(
                        observation,
                        expectedInputs,
                        scope,
                        maximumWorkers,
                        limits,
                    )
                    guards.verifyUnchanged("after function-truth input ingestion")
                    database.reconcile(inventory, scope, limits)
                    database.flush("after reconciling function truth")
                    finish(
                        FunctionTruthReconciliation(
                            paths = paths,
                            inventory = inventory,
                            oracle = oracle,
                            observation = observation,
                            elf = elf,
                            expectedInputs = expectedInputs,
                            scope = scope,
                            maximumWorkers = maximumWorkers,
                            limits = limits,
                            budget = budget,
                            guards = guards,
                            scratch = scratch,
                            database = database,
                        ),
                    )
                } finally {
                    database.close()
                }
            }
        }
    }

}

private class FunctionTruthReconciliation(
    val paths: FunctionTruthPaths,
    val inventory: JsonObject,
    val oracle: JsonObject,
    val observation: AuthenticatedFunctionObservationRun,
    val elf: AuthenticatedFullTreeElfFunctionIndex,
    val expectedInputs: List<FullTreeFunctionObservationShardInput>,
    val scope: AuthenticatedFullTreeScope,
    val maximumWorkers: Int,
    val limits: FullTreeFunctionTruthLimits,
    val budget: FunctionTruthBudget,
    val guards: FunctionTruthInputGuards,
    val scratch: FunctionTruthScratch,
    val database: FunctionTruthDatabase,
)

private fun publishReconciliation(
    reconciliation: FunctionTruthReconciliation,
): FullTreeFunctionTruthGeneration = with(reconciliation) {
    val publication = FunctionTruthPublication.create(paths.output, limits)
    var published = false
    try {
        val completed = database.writeProjection(
            publication.staging,
            inventory,
            oracle,
            observation,
            elf,
            scope,
            limits,
        )
        database.close()
        scratch.releaseDatabase()
        scratch.requireEmptyValidationDirectory()
        scratch.release()

        publication.commit(
            completed,
            inventory,
            oracle,
            scope,
            limits,
            budget,
        ) {
            reauthenticateFunctionTruthInputs(reconciliation, "at the function-truth publication boundary")
        }
        published = true
        FunctionTruthGenerationFactory.create(
            root = paths.output,
            projection = completed,
            observation = observation,
            elf = elf,
        )
    } finally {
        if (!published) publication.close()
    }
}

private fun validateReconciliation(
    reconciliation: FunctionTruthReconciliation,
): FullTreeFunctionTruthValidation = withValidatedFunctionTruthCandidate(reconciliation) { validation ->
    validation.recheck("at the function-truth validation boundary")
    FunctionTruthValidationFactory.create(
        validation.projection,
        reconciliation.observation,
        reconciliation.elf,
    )
}

private fun <T> withValidatedFunctionTruthCandidate(
    reconciliation: FunctionTruthReconciliation,
    consume: (FunctionTruthCandidateValidation) -> T,
): T = with(reconciliation) {
    val candidate = paths.output
    val candidateParent = candidate.parent
        ?: truthFail("function-truth candidate root must name a directory")
    val (_, candidateParentIdentity) = requireStableDirectory(
        candidateParent,
        "function-truth candidate parent",
    )
    val (_, candidateIdentity) = requireStableDirectory(candidate, "function-truth candidate root")
    scratch.requireEmptyValidationDirectory()
    val derived = Files.createDirectory(
        scratch.validation.resolve("raw-rederived-truth"),
        PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS),
    )
    Files.createDirectory(
        derived.resolve(SHARDS_DIRECTORY),
        PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS),
    )
    forceDirectory(derived)

    var validation: FunctionTruthCandidateValidation? = null
    try {
        val completed = database.writeProjection(
            derived,
            inventory,
            oracle,
            observation,
            elf,
            scope,
            limits,
        )
        database.close()
        scratch.releaseDatabase()

        freezePublicationTree(derived, completed, budget)
        val active = FunctionTruthCandidateValidation(
            reconciliation = reconciliation,
            candidate = candidate,
            candidateParent = candidateParent,
            candidateIdentity = candidateIdentity,
            candidateParentIdentity = candidateParentIdentity,
            derived = derived,
            projection = completed,
        )
        validation = active
        active.recheck("after deriving the candidate comparison tree")
        consume(active)
    } finally {
        validation?.release() ?: cleanupDerivedFunctionTruth(derived)
    }
}

private class FunctionTruthCandidateValidation(
    private val reconciliation: FunctionTruthReconciliation,
    private val candidate: Path,
    private val candidateParent: Path,
    private val candidateIdentity: Any,
    private val candidateParentIdentity: Any,
    private val derived: Path,
    val projection: FunctionTruthProjection,
) {
    private var released = false

    fun recheck(label: String) = with(reconciliation) {
        if (released) truthFail("function-truth candidate validation was already released")
        verifyFunctionTruthPublication(
            derived,
            projection,
            inventory,
            oracle,
            scope,
            limits,
            budget,
        )
        reauthenticateFunctionTruthInputs(reconciliation, label)
        requireDirectoryIdentity(
            candidateParent,
            candidateParentIdentity,
            "function-truth candidate parent",
        )
        requireDirectoryIdentity(candidate, candidateIdentity, "function-truth candidate root")
        verifyFunctionTruthPublication(
            candidate,
            projection,
            inventory,
            oracle,
            scope,
            limits,
            budget,
        )
        budget.checkpoint(label)
        requireDirectoryIdentity(
            candidateParent,
            candidateParentIdentity,
            "function-truth candidate parent",
        )
        requireDirectoryIdentity(candidate, candidateIdentity, "function-truth candidate root")
    }

    fun baselineProjection(limits: FullTreeFunctionBaselineLimits): FullTreeFunctionBaselineRawProjection =
        with(reconciliation) {
            if (released) truthFail("function-truth candidate validation was already released")
            if (limits.truth != this.limits) {
                truthFail("function-baseline truth limits differ from the live reconciliation")
            }
            FullTreeFunctionBaselineRawProjection(
                root = derived,
                index = projection.index,
                indexArtifactSha256 = projection.indexArtifactSha256,
                counts = projection.counts,
                scratchParent = scratch.validation,
                limits = limits,
                scratchCheckpoint = scratch::checkBound,
                runtimeCheckpoint = budget::checkpoint,
            )
        }

    fun release() = with(reconciliation) {
        if (released) return@with
        cleanupDerivedFunctionTruth(derived)
        scratch.requireEmptyValidationDirectory()
        scratch.release()
        released = true
    }
}

private fun requireFunctionBaselineOutputDisjoint(outputPath: Path, protectedPaths: List<Path>) {
    val output = outputPath.toAbsolutePath().normalize()
    if (output.parent == null || output.fileName == null) {
        truthFail("function-baseline output root must name a directory")
    }
    requireStableDirectory(output.parent, "function-baseline output parent")
    protectedPaths.forEach { protected ->
        val normalized = protected.toAbsolutePath().normalize()
        if (pathsOverlap(output, normalized)) {
            truthFail("function-baseline output overlaps a truth input or candidate path")
        }
    }
}

private fun reauthenticateFunctionTruthInputs(
    reconciliation: FunctionTruthReconciliation,
    label: String,
) = with(reconciliation) {
    FullTreeScopeControl.validate(scope, limits.control)
    guards.verifyUnchanged(label)
    requireObservationRunUnchanged(
        observation,
        expectedInputs,
        scope,
        maximumWorkers,
        limits,
    )
}

private fun cleanupDerivedFunctionTruth(root: Path) {
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
    makeOwnedTreeWritable(root)
    Files.walk(root).use { paths ->
        paths.sorted(Comparator.reverseOrder()).forEach(Files::delete)
    }
    forceDirectory(root.parent)
}

private data class AuthenticatedFunctionObservationRun(
    val root: Path,
    val run: JsonObject,
    val index: JsonObject,
    val runSha256: String,
    val indexArtifactSha256: String,
    val logicalIndexSha256: String,
    val maximumWorkers: Int,
    val outputs: List<BoundedShardOutputBinding>,
)

private fun authenticateObservationRun(
    root: Path,
    expectedIndexArtifactSha256: String,
    expectedInputs: List<FullTreeFunctionObservationShardInput>,
    scope: AuthenticatedFullTreeScope,
    maximumWorkers: Int,
    limits: FullTreeFunctionTruthLimits,
): AuthenticatedFunctionObservationRun {
    val binding = try {
        BoundedShardRunVerifier.verify(root, expectedIndexArtifactSha256, limits.observationRun)
    } catch (failure: Exception) {
        throw FullTreeFunctionTruthException(
            "cannot authenticate the exact generic function-observation run; embedded historical " +
                "control/usage/evidence roots are not accepted by this production slice",
            failure,
        )
    }
    requireObservationContract(binding, expectedInputs, scope, maximumWorkers)
    val logicalIndexSha256 = binding.index.truthString("indexSha256")
    requireSha256(logicalIndexSha256, "function-observation logical index")
    return AuthenticatedFunctionObservationRun(
        root = binding.root,
        run = binding.run,
        index = binding.index,
        runSha256 = binding.runSha256,
        indexArtifactSha256 = binding.indexArtifactSha256,
        logicalIndexSha256 = logicalIndexSha256,
        maximumWorkers = binding.maximumWorkers,
        outputs = binding.outputs.toList(),
    )
}

private fun requireObservationRunUnchanged(
    authenticated: AuthenticatedFunctionObservationRun,
    expectedInputs: List<FullTreeFunctionObservationShardInput>,
    scope: AuthenticatedFullTreeScope,
    maximumWorkers: Int,
    limits: FullTreeFunctionTruthLimits,
) {
    val observed = try {
        BoundedShardRunVerifier.verify(
            authenticated.root,
            authenticated.indexArtifactSha256,
            limits.observationRun,
        )
    } catch (failure: Exception) {
        throw FullTreeFunctionTruthException("function-observation run changed after authentication", failure)
    }
    requireObservationContract(observed, expectedInputs, scope, maximumWorkers)
    if (
        observed.root != authenticated.root ||
        observed.run != authenticated.run ||
        observed.index != authenticated.index ||
        observed.runSha256 != authenticated.runSha256 ||
        observed.indexArtifactSha256 != authenticated.indexArtifactSha256 ||
        observed.maximumWorkers != authenticated.maximumWorkers ||
        observed.outputs != authenticated.outputs
    ) {
        truthFail("function-observation run binding changed after authentication")
    }
}

private fun requireObservationContract(
    binding: BoundedShardRunBinding,
    expectedInputs: List<FullTreeFunctionObservationShardInput>,
    scope: AuthenticatedFullTreeScope,
    maximumWorkers: Int,
) {
    val run = binding.run
    if (run.keys != setOf("bounds", "id", "schemaVersion", "shards")) {
        truthFail("function-observation run fields differ from the current bounded-shard contract")
    }
    if (run.truthLong("schemaVersion") != 1L) truthFail("function-observation run schema version differs")
    val expectedRunId = "full-tree-functions-${scope.sha256.take(16)}"
    if (run.truthString("id") != expectedRunId) {
        truthFail("function-observation run ID differs from the authenticated scope")
    }
    val bounds = run.truthObject("bounds")
    val expectedBoundNames = setOf(
        "maximumResidentBytes",
        "maximumShards",
        "maximumWorkers",
        "perShardBytes",
        "perShardCpuSeconds",
        "perShardEntities",
        "perShardSeconds",
        "wholeRunBytes",
        "wholeRunCpuSeconds",
        "wholeRunEntities",
        "wholeRunSeconds",
    )
    if (bounds.keys != expectedBoundNames) truthFail("function-observation run bound fields differ")
    val perShard = scope.document.truthObject("bounds").truthObject("perShard")
    val wholeRun = scope.document.truthObject("bounds").truthObject("wholeRun")
    requireExactNumber(bounds, "maximumResidentBytes", wholeRun.truthLong("maximumResidentBytes"))
    requireExactNumber(bounds, "maximumShards", expectedInputs.size.toLong())
    requireExactNumber(bounds, "maximumWorkers", min(maximumWorkers, expectedInputs.size).toLong())
    requireExactNumber(bounds, "perShardBytes", perShard.truthLong("serializedBytes"))
    requireExactNumber(bounds, "perShardCpuSeconds", perShard.truthLong("cpuSeconds"))
    requireExactNumber(bounds, "perShardEntities", perShard.truthLong("entities"))
    requireExactNumber(bounds, "perShardSeconds", perShard.truthLong("wallClockSeconds"))
    requireExactNumber(bounds, "wholeRunBytes", wholeRun.truthLong("serializedBytes"))
    requireExactNumber(bounds, "wholeRunCpuSeconds", wholeRun.truthLong("cpuSeconds"))
    requireExactNumber(bounds, "wholeRunEntities", wholeRun.truthLong("entities"))
    requireExactNumber(bounds, "wholeRunSeconds", wholeRun.truthLong("wallClockSeconds"))

    val expected = expectedInputs.map { input -> input.identifier to input.inputSha256 }
    val runInputs = run.truthArray("shards").mapIndexed { index, raw ->
        val shard = raw as? JsonObject
            ?: truthFail("function-observation run shard $index is not an object")
        if (shard.keys != setOf("id", "inputSha256")) {
            truthFail("function-observation run shard fields differ")
        }
        shard.truthString("id") to shard.truthString("inputSha256")
    }
    if (runInputs != expected) {
        truthFail("function-observation run inputs differ from the current scope/inventory contract")
    }
    val outputInputs = binding.outputs.map { it.shardId to it.inputSha256 }
    if (outputInputs != expected) {
        truthFail("function-observation output membership differs from the current scope/inventory contract")
    }
    if (binding.maximumWorkers != min(maximumWorkers, expectedInputs.size)) {
        truthFail("function-observation worker binding differs from the requested deterministic bound")
    }
}

private fun requireExactNumber(parent: JsonObject, name: String, expected: Long) {
    val primitive = parent[name] as? JsonPrimitive
        ?: truthFail("function-observation run bound $name is absent")
    if (primitive.isString || primitive.booleanOrNull != null) {
        truthFail("function-observation run bound $name is not numeric")
    }
    val actual = try {
        BigDecimal(primitive.content)
    } catch (failure: NumberFormatException) {
        throw FullTreeFunctionTruthException("function-observation run bound $name is invalid", failure)
    }
    if (actual.compareTo(BigDecimal.valueOf(expected)) != 0) {
        truthFail("function-observation run bound $name differs from the authenticated scope")
    }
}

private fun requireObservationReceipt(
    receipt: FullTreeFunctionObservationPublishedShard,
    binding: BoundedShardOutputBinding,
    inventoryArtifactSha256: String,
    richArtifactSha256: String,
    scopeSha256: String,
) {
    if (
        receipt.shardId != binding.shardId ||
        receipt.inputSha256 != binding.inputSha256 ||
        receipt.outputSha256 != binding.outputSha256 ||
        receipt.outputBytes != binding.outputBytes ||
        receipt.entities != binding.entities ||
        receipt.inventoryArtifactSha256 != inventoryArtifactSha256 ||
        receipt.richArtifactSha256 != richArtifactSha256 ||
        receipt.scopeSha256 != scopeSha256 ||
        receipt.entities != checkedAdd(receipt.emittedRvas, receipt.nonEmitted, "observation entity")
    ) {
        truthFail("artifact-backed function-observation receipt differs from its bounded-run binding")
    }
}

private fun truthOracle(
    scope: AuthenticatedFullTreeScope,
    inventory: JsonObject,
    observationIndexArtifactSha256: String,
    elfIndexArtifactSha256: String,
): JsonObject = JsonObject(
    mapOf(
        "configurationSha256" to JsonPrimitive(FullTreeFunctionTruthSqlite.configurationSha256),
        "elfIndexSha256" to JsonPrimitive(elfIndexArtifactSha256),
        "inventoryIndexSha256" to JsonPrimitive(inventory.truthString("indexSha256")),
        "observationIndexSha256" to JsonPrimitive(observationIndexArtifactSha256),
        "scopeSha256" to JsonPrimitive(scope.sha256),
    ),
)

private data class FunctionTruthPaths(
    val rich: Path,
    val stripped: Path,
    val inventory: Path,
    val elfIndex: Path,
    val observations: Path,
    val scratchParent: Path,
    val output: Path,
) {
    companion object {
        fun authenticate(
            rich: Path,
            stripped: Path,
            inventory: Path,
            elfIndex: Path,
            observations: Path,
            scratchParent: Path,
            output: Path,
        ): FunctionTruthPaths {
            val normalized = FunctionTruthPaths(
                rich.toAbsolutePath().normalize(),
                stripped.toAbsolutePath().normalize(),
                inventory.toAbsolutePath().normalize(),
                elfIndex.toAbsolutePath().normalize(),
                observations.toAbsolutePath().normalize(),
                scratchParent.toAbsolutePath().normalize(),
                output.toAbsolutePath().normalize(),
            )
            requireStableDirectory(normalized.scratchParent, "function-truth scratch parent")
            requireStableDirectory(
                normalized.output.parent
                    ?: truthFail("function-truth output root must name a directory"),
                "function-truth output parent",
            )
            val inputs = listOf(
                "rich artifact" to normalized.rich,
                "stripped artifact" to normalized.stripped,
                "inventory" to normalized.inventory,
                "ELF function index" to normalized.elfIndex,
                "function-observation root" to normalized.observations,
                "scratch parent" to normalized.scratchParent,
            )
            inputs.forEach { (label, input) ->
                if (pathsOverlap(normalized.output, input)) {
                    truthFail("function-truth output root overlaps its $label input")
                }
            }
            inputs.filterNot { it.second == normalized.scratchParent }.forEach { (label, input) ->
                if (pathsOverlap(normalized.scratchParent, input)) {
                    truthFail("function-truth scratch parent overlaps its $label input")
                }
            }
            if (pathsOverlap(normalized.scratchParent, normalized.output)) {
                truthFail("function-truth scratch and output roots overlap")
            }
            return normalized
        }
    }
}

private class FunctionTruthInputGuards private constructor(
    val rich: StableControlFile,
    val stripped: StableControlFile,
    val inventory: StableControlFile,
    val elfIndex: StableControlFile,
) : AutoCloseable {
    fun verifyUnchanged(label: String) {
        rich.verifyUnchanged("rich artifact $label")
        stripped.verifyUnchanged("stripped artifact $label")
        inventory.verifyUnchanged("full-tree inventory $label")
        elfIndex.verifyUnchanged("ELF function index $label")
    }

    override fun close() {
        var failure: Throwable? = null
        listOf(elfIndex, inventory, stripped, rich).forEach { guard ->
            try {
                guard.close()
            } catch (closeFailure: Throwable) {
                if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
            }
        }
        failure?.let { throw it }
    }

    companion object {
        fun open(paths: FunctionTruthPaths, limits: FullTreeFunctionTruthLimits): FunctionTruthInputGuards {
            val opened = ArrayList<StableControlFile>(4)
            try {
                val rich = StableControlFile.open(
                    paths.rich,
                    limits.control.maximumRichArtifactBytes,
                    "function-truth rich artifact",
                ).also(opened::add)
                val stripped = StableControlFile.open(
                    paths.stripped,
                    limits.control.maximumRichArtifactBytes,
                    "function-truth stripped artifact",
                ).also(opened::add)
                val inventory = StableControlFile.open(
                    paths.inventory,
                    limits.control.maximumInventoryBytes.toLong(),
                    "function-truth inventory",
                ).also(opened::add)
                val elf = StableControlFile.open(
                    paths.elfIndex,
                    limits.maximumElfIndexBytes,
                    "function-truth ELF index",
                ).also(opened::add)
                return FunctionTruthInputGuards(rich, stripped, inventory, elf)
            } catch (failure: Throwable) {
                opened.asReversed().forEach { runCatching { it.close() } }
                throw failure
            }
        }
    }
}

private class FunctionTruthScratch private constructor(
    val root: Path,
    val validation: Path,
    val database: Path,
    private val rootIdentity: Any,
    private val validationIdentity: Any,
    private val databaseIdentity: Any,
    private val limits: FullTreeFunctionTruthLimits,
) : AutoCloseable {
    private var databaseReleased = false
    private var released = false
    private var highWaterBytes = 0L

    fun checkBound(label: String): Long {
        requireDirectoryIdentity(root, rootIdentity, "function-truth scratch root")
        var bytes = 0L
        Files.walk(root).use { paths ->
            paths.forEach { path ->
                val attributes = Files.readAttributes(
                    path,
                    BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                )
                if (attributes.isSymbolicLink || (!attributes.isDirectory && !attributes.isRegularFile)) {
                    truthFail("function-truth scratch contains an invalid path type $label")
                }
                if (attributes.isRegularFile) {
                    bytes = checkedAdd(bytes, attributes.size(), "scratch byte")
                }
            }
        }
        if (bytes > limits.maximumScratchBytes) {
            truthFail("function-truth scratch exceeds its aggregate byte bound $label")
        }
        highWaterBytes = maxOf(highWaterBytes, bytes)
        return bytes
    }

    fun databaseHighWaterBytes(): Long = highWaterBytes

    /**
     * Conservatively combines a completed validator's reported database peak with the truth
     * scratch that remained live during that validation. The validator currently cannot expose
     * an opaque aggregate lease, so this is a ceiling check rather than release authority (#138).
     */
    fun chargeTransientValidation(databaseHighWaterBytes: Long, label: String) {
        if (databaseHighWaterBytes <= 0L) {
            truthFail("function-observation validator reported an invalid database high-water mark")
        }
        val liveBytes = checkBound(label)
        val modeledPeak = checkedAdd(liveBytes, databaseHighWaterBytes, "validation scratch byte")
        if (modeledPeak > limits.maximumScratchBytes) {
            truthFail("function-truth scratch exceeds its aggregate byte bound $label")
        }
        highWaterBytes = maxOf(highWaterBytes, modeledPeak)
    }

    fun releaseDatabase() {
        if (databaseReleased) return
        requireFileIdentity(database, databaseIdentity, "function-truth SQLite database")
        Files.delete(database)
        databaseReleased = true
        forceDirectory(root)
    }

    fun requireEmptyValidationDirectory() {
        requireDirectoryIdentity(validation, validationIdentity, "function-truth validation scratch")
        Files.list(validation).use { entries ->
            if (entries.findAny().isPresent) {
                truthFail("function-observation validator left residual truth scratch state")
            }
        }
    }

    fun release() {
        if (released) return
        if (!databaseReleased) truthFail("function-truth database must be released before scratch")
        requireEmptyValidationDirectory()
        requireDirectoryIdentity(root, rootIdentity, "function-truth scratch root")
        Files.delete(validation)
        Files.delete(root)
        forceDirectory(root.parent)
        released = true
    }

    override fun close() {
        if (released || !Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
        requireDirectoryIdentity(root, rootIdentity, "function-truth scratch root during cleanup")
        Files.walk(root).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach { candidate ->
                if (candidate == database && !databaseReleased) {
                    requireFileIdentity(candidate, databaseIdentity, "function-truth database cleanup")
                }
                if (candidate == validation) {
                    requireDirectoryIdentity(candidate, validationIdentity, "function-truth validation cleanup")
                }
                Files.delete(candidate)
            }
        }
        forceDirectory(root.parent)
        released = true
    }

    companion object {
        fun create(parentPath: Path, limits: FullTreeFunctionTruthLimits): FunctionTruthScratch {
            val (parent, _) = requireStableDirectory(parentPath, "function-truth scratch parent")
            var root: Path? = null
            try {
                val createdRoot = Files.createTempDirectory(
                    parent,
                    ".function-truth-",
                    PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS),
                )
                root = createdRoot
                val validation = Files.createDirectory(
                    createdRoot.resolve("validation"),
                    PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS),
                )
                val database = Files.createFile(
                    createdRoot.resolve("truth.sqlite"),
                    PosixFilePermissions.asFileAttribute(PRIVATE_FILE_PERMISSIONS),
                )
                forceDirectory(createdRoot)
                forceDirectory(parent)
                return FunctionTruthScratch(
                    root = createdRoot,
                    validation = validation,
                    database = database,
                    rootIdentity = directoryIdentity(createdRoot, "function-truth scratch root"),
                    validationIdentity = directoryIdentity(validation, "function-truth validation scratch"),
                    databaseIdentity = fileIdentity(database, "function-truth database"),
                    limits = limits,
                )
            } catch (failure: Throwable) {
                if (root != null && Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
                    runCatching {
                        Files.walk(root).use { paths ->
                            paths.sorted(Comparator.reverseOrder()).forEach(Files::delete)
                        }
                        forceDirectory(parent)
                    }.exceptionOrNull()?.let(failure::addSuppressed)
                }
                throw failure
            }
        }
    }
}

private class FunctionTruthBudget(scope: AuthenticatedFullTreeScope) {
    private val startedWallNanos = System.nanoTime()
    private val startedCpuNanos = processCpuNanos()
    private val whole = scope.document.truthObject("bounds").truthObject("wholeRun")
    private val maximumWallNanos = secondsToNanos(whole.truthLong("wallClockSeconds"), "wall-clock")
    private val maximumCpuNanos = secondsToNanos(whole.truthLong("cpuSeconds"), "CPU")
    private val maximumResidentBytes = whole.truthLong("maximumResidentBytes")

    fun checkpoint(label: String) {
        val wall = System.nanoTime() - startedWallNanos
        val cpu = processCpuNanos() - startedCpuNanos
        if (wall < 0L || wall > maximumWallNanos) {
            truthFail("function-truth reconciliation exceeded its wall-clock bound $label")
        }
        if (cpu < 0L || cpu > maximumCpuNanos) {
            truthFail("function-truth reconciliation exceeded its CPU-time bound $label")
        }
        val resident = LinuxResidentMemory.sampleSelf()
        if (resident.currentBytes > maximumResidentBytes || resident.highWaterBytes > maximumResidentBytes) {
            truthFail("function-truth reconciliation exceeded its resident-byte bound $label")
        }
    }

    private fun processCpuNanos(): Long = ProcessHandle.current().info().totalCpuDuration()
        .orElseThrow { FullTreeFunctionTruthException("process CPU duration is unavailable") }
        .toNanos()

    private fun secondsToNanos(seconds: Long, label: String): Long = try {
        Math.multiplyExact(seconds, 1_000_000_000L)
    } catch (failure: ArithmeticException) {
        throw FullTreeFunctionTruthException("function-truth $label bound exceeds the supported range", failure)
    }
}

private data class FunctionTruthFile(
    val id: String,
    val path: String,
    val sha256: String,
    val bytes: Long,
    val functions: Long,
    val nonEmitted: Long,
) {
    fun toJson(): JsonObject = JsonObject(
        mapOf(
            "bytes" to JsonPrimitive(bytes),
            "functions" to JsonPrimitive(functions),
            "id" to JsonPrimitive(id),
            "nonEmitted" to JsonPrimitive(nonEmitted),
            "path" to JsonPrimitive(path),
            "sha256" to JsonPrimitive(sha256),
        ),
    )
}

private data class FunctionTruthProjection(
    val index: JsonObject,
    val indexBytes: ByteArray,
    val indexArtifactSha256: String,
    val logicalIndexSha256: String,
    val counts: FullTreeFunctionTruthCounts,
    val shards: List<FunctionTruthFile>,
    val exclusions: FunctionTruthFile,
    val contentBytes: Long,
    val publishedBytes: Long,
    val databaseHighWaterBytes: Long,
)

private object FunctionTruthGenerationFactory {
    fun create(
        root: Path,
        projection: FunctionTruthProjection,
        observation: AuthenticatedFunctionObservationRun,
        elf: AuthenticatedFullTreeElfFunctionIndex,
    ): FullTreeFunctionTruthGeneration = FullTreeFunctionTruthGeneration(
        root = root,
        index = projection.index,
        indexArtifactSha256 = projection.indexArtifactSha256,
        indexSha256 = projection.logicalIndexSha256,
        observationIndexArtifactSha256 = observation.indexArtifactSha256,
        elfIndexArtifactSha256 = elf.sha256,
        outputBytes = projection.publishedBytes,
        databaseHighWaterBytes = projection.databaseHighWaterBytes,
        counts = projection.counts,
    )
}

private object FunctionTruthValidationFactory {
    fun create(
        projection: FunctionTruthProjection,
        observation: AuthenticatedFunctionObservationRun,
        elf: AuthenticatedFullTreeElfFunctionIndex,
    ): FullTreeFunctionTruthValidation = VerifiedFunctionTruthValidation(
        indexArtifactSha256 = projection.indexArtifactSha256,
        indexSha256 = projection.logicalIndexSha256,
        observationIndexArtifactSha256 = observation.indexArtifactSha256,
        elfIndexArtifactSha256 = elf.sha256,
        outputBytes = projection.publishedBytes,
        databaseHighWaterBytes = projection.databaseHighWaterBytes,
        counts = projection.counts,
    )
}

private class VerifiedFunctionTruthValidation(
    override val indexArtifactSha256: String,
    override val indexSha256: String,
    override val observationIndexArtifactSha256: String,
    override val elfIndexArtifactSha256: String,
    override val outputBytes: Long,
    override val databaseHighWaterBytes: Long,
    override val counts: FullTreeFunctionTruthCounts,
) : FullTreeFunctionTruthValidation {
    override val rawInputsRederived: Boolean = true
    override val candidateBytesMatchedAtValidationBoundary: Boolean = true
    override val candidateLeaseRetained: Boolean = false
    override val downstreamScoringAuthorized: Boolean = false
    override val authoritativeReleaseEvidence: Boolean = false
}

private class FunctionTruthDatabase private constructor(
    private val connection: Connection,
    private val limits: FullTreeFunctionTruthLimits,
    private val budget: FunctionTruthBudget,
    private val scratch: FunctionTruthScratch,
) : AutoCloseable {
    private var acceptedRows = 0L
    private var nextCheckpoint = limits.databaseCheckpointRows.toLong()
    private var closed = false
    private var reconciledCounts: FullTreeFunctionTruthCounts? = null

    fun ingestElf(
        path: Path,
        authenticated: AuthenticatedFullTreeElfFunctionIndex,
        scope: AuthenticatedFullTreeScope,
        inventory: JsonObject,
        limits: FullTreeFunctionTruthLimits,
    ) {
        var functions = 0L
        var externalFunctions = 0L
        val insertElf = connection.prepareStatement("INSERT INTO elf(rva, payload) VALUES (?, ?)")
        val insertRva = connection.prepareStatement("INSERT OR IGNORE INTO all_rva(rva) VALUES (?)")
        try {
            val streamed = FullTreeCanonicalStreaming.readObject(
                path = path,
                label = "full-tree ELF function index",
                expectedSourceSha256 = authenticated.sha256,
                fieldOrder = ELF_INDEX_FIELDS,
                arrayFields = setOf("externalFunctions", "functions"),
                omittedDigestField = null,
                limits = streamingLimits(
                    maximumBytes = min(authenticated.bytes, limits.maximumElfIndexBytes),
                    maximumEntities = limits.observationRun.maximumWholeRunEntities,
                    limits = limits,
                ),
            ) { field, _, value, canonical ->
                when (field) {
                    "functions" -> {
                        val rva = parseCanonicalAddress(value.truthString("rva"), "ELF function RVA")
                        val key = unsignedKey(rva)
                        if (value.truthString("id") != "function-rva-${canonicalAddress(rva)}") {
                            truthFail("ELF function identity differs from its RVA")
                        }
                        insertRva.setBytes(1, key)
                        insertRva.executeUpdate()
                        insertElf.setBytes(1, key)
                        insertElf.setBytes(2, canonical)
                        if (insertElf.executeUpdate() != 1) truthFail("ELF function index repeats an RVA")
                        functions = checkedAdd(functions, 1L, "ELF function")
                        rowAccepted("while ingesting ELF functions")
                    }
                    "externalFunctions" -> {
                        externalFunctions = checkedAdd(externalFunctions, 1L, "external ELF function")
                        rowAccepted("while streaming external ELF functions")
                    }
                    else -> truthFail("ELF function stream exposed an unexpected array")
                }
            }
            if (streamed.sourceBytes != authenticated.bytes) {
                truthFail("ELF function index byte binding differs during truth ingestion")
            }
            val envelope = streamed.envelope
            if (envelope.truthLong("schemaVersion") != 1L) truthFail("ELF function schema version differs")
            val oracle = envelope.truthObject("oracle")
            if (
                oracle.truthString("configurationSha256") != FullTreeElfFunctionsSqlite.configurationSha256 ||
                oracle.truthString("inventoryIndexSha256") != inventory.truthString("indexSha256") ||
                oracle.truthString("scopeSha256") != scope.sha256
            ) {
                truthFail("ELF function envelope bindings differ during truth ingestion")
            }
            val counts = envelope.truthObject("counts")
            if (
                functions != authenticated.counts.functionRvas ||
                externalFunctions != authenticated.counts.externalFunctions ||
                counts.truthLong("functionRvas") != functions ||
                counts.truthLong("externalFunctions") != externalFunctions ||
                counts.truthLong("aliases") != authenticated.counts.aliases ||
                counts.truthLong("strippedFunctionRvas") != authenticated.counts.strippedFunctionRvas
            ) {
                truthFail("ELF function counts differ during truth ingestion")
            }
        } finally {
            insertElf.close()
            insertRva.close()
        }
    }

    fun ingestObservation(
        path: Path,
        receipt: FullTreeFunctionObservationPublishedShard,
        binding: BoundedShardOutputBinding,
        inventory: JsonObject,
        scope: AuthenticatedFullTreeScope,
        limits: FullTreeFunctionTruthLimits,
    ) {
        var emitted = 0L
        var nonEmitted = 0L
        val insertEmitted = connection.prepareStatement(
            "INSERT INTO emitted(rva, shard_id, payload) VALUES (?, ?, ?)",
        )
        val insertRva = connection.prepareStatement("INSERT OR IGNORE INTO all_rva(rva) VALUES (?)")
        val insertIdentity = connection.prepareStatement(
            "INSERT OR IGNORE INTO non_emitted_identity(prefix, full_digest, identity_payload) VALUES (?, ?, ?)",
        )
        val readIdentity = connection.prepareStatement(
            "SELECT full_digest, identity_payload FROM non_emitted_identity WHERE prefix=?",
        )
        val insertNonEmitted = connection.prepareStatement(
            "INSERT INTO non_emitted_observation(prefix, observation_id, shard_id, payload) VALUES (?, ?, ?, ?)",
        )
        try {
            val maximumInputBytes = minOf(
                receipt.outputBytes,
                limits.maximumObservationInputBytes,
                scope.document.truthObject("bounds").truthObject("perShard").truthLong("serializedBytes"),
            )
            if (receipt.outputBytes > maximumInputBytes) {
                truthFail("function-observation shard exceeds the truth ingestion byte bound")
            }
            val streamed = FullTreeCanonicalStreaming.readObject(
                path = path,
                label = "function-observation shard ${binding.shardId}",
                expectedSourceSha256 = binding.outputSha256,
                fieldOrder = OBSERVATION_FIELDS,
                arrayFields = setOf("emitted", "nonEmitted"),
                omittedDigestField = null,
                limits = streamingLimits(
                    maximumBytes = maximumInputBytes,
                    maximumEntities = scope.document.truthObject("bounds")
                        .truthObject("perShard").truthLong("entities"),
                    limits = limits,
                ),
            ) { field, _, value, canonical ->
                when (field) {
                    "emitted" -> {
                        val rva = parseCanonicalAddress(value.truthString("rva"), "DWARF emitted RVA")
                        val key = unsignedKey(rva)
                        insertRva.setBytes(1, key)
                        insertRva.executeUpdate()
                        insertEmitted.setBytes(1, key)
                        insertEmitted.setString(2, binding.shardId)
                        insertEmitted.setBytes(3, canonical)
                        if (insertEmitted.executeUpdate() != 1) {
                            truthFail("function-observation shard repeats an emitted RVA")
                        }
                        emitted = checkedAdd(emitted, 1L, "emitted observation")
                        rowAccepted("while ingesting emitted function observations")
                    }
                    "nonEmitted" -> {
                        val identity = nonEmittedIdentity(value, limits)
                        insertIdentity.setBytes(1, identity.prefix)
                        insertIdentity.setBytes(2, identity.fullDigest)
                        insertIdentity.setBytes(3, identity.preimage)
                        insertIdentity.executeUpdate()
                        readIdentity.setBytes(1, identity.prefix)
                        readIdentity.executeQuery().use { rows ->
                            if (!rows.next()) truthFail("non-emitted identity was not persisted")
                            val storedDigest = rows.getBytes(1)
                            val storedPreimage = rows.getBytes(2)
                            if (
                                !MessageDigest.isEqual(storedDigest, identity.fullDigest) ||
                                !MessageDigest.isEqual(storedPreimage, identity.preimage)
                            ) {
                                truthFail(
                                    "non-emitted 128-bit identity prefix collision: ${identity.identifier}",
                                )
                            }
                        }
                        insertNonEmitted.setBytes(1, identity.prefix)
                        insertNonEmitted.setString(2, value.truthString("id"))
                        insertNonEmitted.setString(3, binding.shardId)
                        insertNonEmitted.setBytes(4, canonical)
                        if (insertNonEmitted.executeUpdate() != 1) {
                            truthFail("function-observation run repeats a non-emitted observation identity")
                        }
                        nonEmitted = checkedAdd(nonEmitted, 1L, "non-emitted observation")
                        rowAccepted("while ingesting non-emitted function observations")
                    }
                    else -> truthFail("function-observation stream exposed an unexpected array")
                }
            }
            if (streamed.sourceBytes != receipt.outputBytes) {
                truthFail("function-observation byte binding differs during truth ingestion")
            }
            val envelope = streamed.envelope
            val expectedOracle = JsonObject(
                mapOf(
                    "configurationSha256" to JsonPrimitive(FullTreeFunctionObservations.configurationSha256),
                    "inventoryIndexSha256" to JsonPrimitive(inventory.truthString("indexSha256")),
                    "richArtifactSha256" to JsonPrimitive(receipt.richArtifactSha256),
                    "scopeSha256" to JsonPrimitive(scope.sha256),
                ),
            )
            val expectedShard = JsonObject(
                mapOf(
                    "id" to JsonPrimitive(binding.shardId),
                    "inputSha256" to JsonPrimitive(binding.inputSha256),
                ),
            )
            val counts = envelope.truthObject("counts")
            if (
                envelope.truthLong("schemaVersion") != 1L ||
                envelope.truthObject("oracle") != expectedOracle ||
                envelope.truthObject("shard") != expectedShard ||
                emitted != receipt.emittedRvas ||
                nonEmitted != receipt.nonEmitted ||
                counts.truthLong("emittedRvas") != receipt.emittedRvas ||
                counts.truthLong("nonEmitted") != receipt.nonEmitted ||
                counts.truthLong("nonEmittedDies") != receipt.nonEmittedDies ||
                counts.truthLong("scannedDies") != receipt.scannedDies ||
                counts.truthLong("units") != receipt.units
            ) {
                truthFail("function-observation envelope differs from its artifact-backed receipt")
            }
        } finally {
            insertEmitted.close()
            insertRva.close()
            insertIdentity.close()
            readIdentity.close()
            insertNonEmitted.close()
        }
    }

    fun flush(label: String) {
        budget.checkpoint("before committing $label")
        scratch.checkBound("before committing $label")
        connection.commit()
        budget.checkpoint(label)
        val databaseBytes = Files.size(scratch.database)
        if (databaseBytes > limits.maximumDatabaseBytes) {
            truthFail("function-truth SQLite database exceeds its byte bound $label")
        }
        scratch.checkBound(label)
    }

    private fun rowAccepted(label: String) {
        acceptedRows = checkedAdd(acceptedRows, 1L, "SQLite row")
        if (acceptedRows >= nextCheckpoint) {
            flush(label)
            nextCheckpoint = checkedAdd(nextCheckpoint, limits.databaseCheckpointRows.toLong(), "checkpoint row")
        }
    }

    fun reconcile(
        inventory: JsonObject,
        scope: AuthenticatedFullTreeScope,
        limits: FullTreeFunctionTruthLimits,
    ) {
        if (reconciledCounts != null) truthFail("function-truth database was already reconciled")
        assertIndexedPlans()
        val unitToShard = inventory.truthArray("units").associate { raw ->
            val unit = raw as? JsonObject ?: truthFail("inventory unit is not an object")
            unit.truthString("id") to unit.truthString("shardId")
        }
        if (unitToShard.size != inventory.truthArray("units").size) {
            truthFail("inventory repeats a compilation-unit identity")
        }

        var dwarfRvas = 0L
        var scoredRvas = 0L
        var dwarfOnlyRvas = 0L
        var elfOnlyRvas = 0L
        var coalescedEmittedRvas = 0L
        val insertFunction = connection.prepareStatement(
            "INSERT INTO truth_function(owner_shard, rva, payload) VALUES (?, ?, ?)",
        )
        val insertAlias = connection.prepareStatement(
            "INSERT INTO emitted_alias(name, rva) VALUES (?, ?)",
        )
        val insertExclusion = connection.prepareStatement(
            "INSERT INTO exclusion(rva, payload) VALUES (?, ?)",
        )
        try {
            connection.prepareStatement(EMITTED_MERGE_SQL).use { statement ->
                statement.executeQuery().use { rows ->
                    var group: EmittedTruthGroup? = null
                    while (rows.next()) {
                        val key = rows.getBytes(1)
                        if (group == null || !group.rvaKey.contentEquals(key)) {
                            group?.let { completed ->
                                val result = completeEmittedGroup(
                                    completed,
                                    unitToShard,
                                    insertFunction,
                                    insertAlias,
                                    insertExclusion,
                                    limits,
                                )
                                dwarfRvas = checkedAdd(dwarfRvas, result.dwarfRvas, "DWARF RVA")
                                scoredRvas = checkedAdd(scoredRvas, result.scoredRvas, "scored RVA")
                                dwarfOnlyRvas = checkedAdd(dwarfOnlyRvas, result.dwarfOnlyRvas, "DWARF-only RVA")
                                elfOnlyRvas = checkedAdd(elfOnlyRvas, result.elfOnlyRvas, "ELF-only RVA")
                                coalescedEmittedRvas = checkedAdd(
                                    coalescedEmittedRvas,
                                    result.coalescedEmittedRvas,
                                    "coalesced emitted RVA",
                                )
                            }
                            group = EmittedTruthGroup(key, limits, budget)
                        }
                        val current = group
                        rows.getBytes(2)?.let(current::acceptElf)
                        rows.getBytes(3)?.let(current::acceptDwarf)
                    }
                    group?.let { completed ->
                        val result = completeEmittedGroup(
                            completed,
                            unitToShard,
                            insertFunction,
                            insertAlias,
                            insertExclusion,
                            limits,
                        )
                        dwarfRvas = checkedAdd(dwarfRvas, result.dwarfRvas, "DWARF RVA")
                        scoredRvas = checkedAdd(scoredRvas, result.scoredRvas, "scored RVA")
                        dwarfOnlyRvas = checkedAdd(dwarfOnlyRvas, result.dwarfOnlyRvas, "DWARF-only RVA")
                        elfOnlyRvas = checkedAdd(elfOnlyRvas, result.elfOnlyRvas, "ELF-only RVA")
                        coalescedEmittedRvas = checkedAdd(
                            coalescedEmittedRvas,
                            result.coalescedEmittedRvas,
                            "coalesced emitted RVA",
                        )
                    }
                }
            }
        } finally {
            insertFunction.close()
            insertAlias.close()
            insertExclusion.close()
        }
        flush("after reconciling emitted function truth")

        var nonEmittedObservations = 0L
        var nonEmittedUnique = 0L
        var inlineOnlyUnique = 0L
        var selectedElsewhereUnique = 0L
        var definitionNoRangeUnique = 0L
        val selectedAlias = connection.prepareStatement(
            "SELECT 1 FROM emitted_alias WHERE name=? LIMIT 1",
        )
        val insertNonEmitted = connection.prepareStatement(
            "INSERT INTO truth_non_emitted(owner_shard, prefix, identifier, payload) VALUES (?, ?, ?, ?)",
        )
        try {
            connection.prepareStatement(NON_EMITTED_MERGE_SQL).use { statement ->
                statement.executeQuery().use { rows ->
                    var group: NonEmittedTruthGroup? = null
                    while (rows.next()) {
                        val prefix = rows.getBytes(1)
                        if (group == null || !group.prefix.contentEquals(prefix)) {
                            group?.let { completed ->
                                val result = completeNonEmittedGroup(
                                    completed,
                                    unitToShard,
                                    selectedAlias,
                                    insertNonEmitted,
                                    limits,
                                )
                                nonEmittedObservations = checkedAdd(
                                    nonEmittedObservations,
                                    result.observations,
                                    "non-emitted observation",
                                )
                                nonEmittedUnique = checkedAdd(nonEmittedUnique, 1L, "non-emitted identity")
                                when (result.reasonCode) {
                                    INLINE_REASON -> inlineOnlyUnique = checkedAdd(
                                        inlineOnlyUnique,
                                        1L,
                                        "inline-only identity",
                                    )
                                    SELECTED_REASON -> selectedElsewhereUnique = checkedAdd(
                                        selectedElsewhereUnique,
                                        1L,
                                        "selected-elsewhere identity",
                                    )
                                    DEFINITION_REASON -> definitionNoRangeUnique = checkedAdd(
                                        definitionNoRangeUnique,
                                        1L,
                                        "definition-without-range identity",
                                    )
                                }
                            }
                            group = NonEmittedTruthGroup(
                                prefix,
                                rows.getBytes(2),
                                rows.getBytes(3),
                                limits,
                                budget,
                            )
                        } else {
                            group.requireIdentity(rows.getBytes(2), rows.getBytes(3))
                        }
                        group.accept(rows.getBytes(5))
                    }
                    group?.let { completed ->
                        val result = completeNonEmittedGroup(
                            completed,
                            unitToShard,
                            selectedAlias,
                            insertNonEmitted,
                            limits,
                        )
                        nonEmittedObservations = checkedAdd(
                            nonEmittedObservations,
                            result.observations,
                            "non-emitted observation",
                        )
                        nonEmittedUnique = checkedAdd(nonEmittedUnique, 1L, "non-emitted identity")
                        when (result.reasonCode) {
                            INLINE_REASON -> inlineOnlyUnique = checkedAdd(
                                inlineOnlyUnique,
                                1L,
                                "inline-only identity",
                            )
                            SELECTED_REASON -> selectedElsewhereUnique = checkedAdd(
                                selectedElsewhereUnique,
                                1L,
                                "selected-elsewhere identity",
                            )
                            DEFINITION_REASON -> definitionNoRangeUnique = checkedAdd(
                                definitionNoRangeUnique,
                                1L,
                                "definition-without-range identity",
                            )
                        }
                    }
                }
            }
        } finally {
            selectedAlias.close()
            insertNonEmitted.close()
        }

        val elfRvas = scalar("SELECT COUNT(*) FROM elf")
        val counts = FullTreeFunctionTruthCounts(
            elfRvas = elfRvas,
            dwarfRvas = dwarfRvas,
            scoredRvas = scoredRvas,
            elfOnlyRvas = elfOnlyRvas,
            dwarfOnlyRvas = dwarfOnlyRvas,
            nonEmittedObservations = nonEmittedObservations,
            nonEmittedUnique = nonEmittedUnique,
            inlineOnlyUnique = inlineOnlyUnique,
            selectedElsewhereUnique = selectedElsewhereUnique,
            definitionNoRangeUnique = definitionNoRangeUnique,
            coalescedEmittedRvas = coalescedEmittedRvas,
        )
        if (counts.elfRvas != checkedAdd(counts.scoredRvas, counts.elfOnlyRvas, "ELF denominator")) {
            truthFail("ELF function denominator does not reconcile")
        }
        if (counts.dwarfRvas != checkedAdd(counts.scoredRvas, counts.dwarfOnlyRvas, "DWARF denominator")) {
            truthFail("DWARF function denominator does not reconcile")
        }
        if (
            counts.nonEmittedUnique != checkedAdd(
                checkedAdd(counts.inlineOnlyUnique, counts.selectedElsewhereUnique, "non-emitted reason"),
                counts.definitionNoRangeUnique,
                "non-emitted reason",
            )
        ) {
            truthFail("non-emitted function reasons do not reconcile")
        }
        val totalEntities = checkedAdd(
            checkedAdd(counts.elfRvas, counts.dwarfOnlyRvas, "truth entity"),
            counts.nonEmittedUnique,
            "truth entity",
        )
        if (totalEntities > scope.document.truthObject("bounds").truthObject("wholeRun").truthLong("entities")) {
            truthFail("function truth exceeds its authenticated whole-run entity bound")
        }
        reconciledCounts = counts
    }

    private fun completeEmittedGroup(
        group: EmittedTruthGroup,
        unitToShard: Map<String, String>,
        insertFunction: PreparedStatement,
        insertAlias: PreparedStatement,
        insertExclusion: PreparedStatement,
        limits: FullTreeFunctionTruthLimits,
    ): EmittedGroupCounts {
        val result = group.finish(unitToShard, limits)
        if (result.exclusion != null) {
            insertExclusion.setBytes(1, group.rvaKey)
            insertExclusion.setBytes(2, result.exclusion)
            if (insertExclusion.executeUpdate() != 1) truthFail("ELF-only exclusion repeats an RVA")
        } else {
            val ownerShard = result.ownerShard ?: truthFail("reconciled function has no owner shard")
            val payload = result.function ?: truthFail("reconciled function has no canonical payload")
            insertFunction.setString(1, ownerShard)
            insertFunction.setBytes(2, group.rvaKey)
            insertFunction.setBytes(3, payload)
            if (insertFunction.executeUpdate() != 1) truthFail("reconciled function repeats an RVA")
            result.aliasNames.forEach { name ->
                insertAlias.setString(1, name)
                insertAlias.setBytes(2, group.rvaKey)
                if (insertAlias.executeUpdate() != 1) truthFail("reconciled function repeats an alias")
            }
        }
        rowAccepted("while reconciling emitted function groups")
        return result.counts
    }

    private fun completeNonEmittedGroup(
        group: NonEmittedTruthGroup,
        unitToShard: Map<String, String>,
        selectedAlias: PreparedStatement,
        insert: PreparedStatement,
        limits: FullTreeFunctionTruthLimits,
    ): CompletedNonEmitted {
        val completed = group.finish(unitToShard, selectedAlias, limits)
        insert.setString(1, completed.ownerShard)
        insert.setBytes(2, group.prefix)
        insert.setString(3, completed.identifier)
        insert.setBytes(4, completed.payload)
        if (insert.executeUpdate() != 1) truthFail("non-emitted truth repeats an identity")
        rowAccepted("while reconciling non-emitted function groups")
        return completed
    }

    private fun scalar(sql: String): Long = connection.prepareStatement(sql).use { statement ->
        statement.executeQuery().use { rows ->
            if (!rows.next()) truthFail("function-truth SQLite scalar query returned no row")
            rows.getLong(1).also {
                if (rows.wasNull() || rows.next()) truthFail("function-truth SQLite scalar query is invalid")
            }
        }
    }

    private fun assertIndexedPlans() {
        listOf(EMITTED_MERGE_SQL, NON_EMITTED_MERGE_SQL).forEach { sql ->
            connection.prepareStatement("EXPLAIN QUERY PLAN $sql").use { statement ->
                statement.executeQuery().use { rows ->
                    while (rows.next()) {
                        if ("USE TEMP B-TREE" in rows.getString(4).uppercase()) {
                            truthFail("function-truth SQLite query plan requires an unbounded temporary sort")
                        }
                    }
                }
            }
        }
    }

    fun writeProjection(
        staging: Path,
        inventory: JsonObject,
        oracle: JsonObject,
        observation: AuthenticatedFunctionObservationRun,
        elf: AuthenticatedFullTreeElfFunctionIndex,
        scope: AuthenticatedFullTreeScope,
        limits: FullTreeFunctionTruthLimits,
    ): FunctionTruthProjection {
        val counts = reconciledCounts ?: truthFail("function-truth database has not been reconciled")
        if (counts.elfRvas != elf.counts.functionRvas) {
            truthFail("reconciled ELF denominator differs from the authenticated ELF index")
        }
        if (oracle.truthString("observationIndexSha256") != observation.indexArtifactSha256) {
            truthFail("function-truth projection has the wrong observation index binding")
        }
        flush("before projecting function-truth output")
        val shardDirectory = staging.resolve(SHARDS_DIRECTORY)
        val perShard = scope.document.truthObject("bounds").truthObject("perShard")
        val shardFiles = inventory.truthArray("shards").mapIndexed { index, raw ->
            val shard = raw as? JsonObject ?: truthFail("inventory shard $index is not an object")
            val shardId = shard.truthString("id")
            val functionCount = scalarForShard("truth_function", shardId)
            val nonEmittedCount = scalarForShard("truth_non_emitted", shardId)
            if (checkedAdd(functionCount, nonEmittedCount, "truth shard entity") > perShard.truthLong("entities")) {
                truthFail("function-truth shard $shardId exceeds its authenticated entity bound")
            }
            val relative = "$SHARDS_DIRECTORY/$shardId.json"
            val digest = writeTruthShard(
                path = staging.resolve(relative),
                shard = shard,
                oracle = oracle,
                functionCount = functionCount,
                nonEmittedCount = nonEmittedCount,
                maximumBytes = minOf(
                    perShard.truthLong("serializedBytes"),
                    limits.maximumOutputBytes,
                ),
            )
            FunctionTruthFile(
                id = shardId,
                path = relative,
                sha256 = digest.sha256,
                bytes = digest.bytes,
                functions = functionCount,
                nonEmitted = nonEmittedCount,
            )
        }
        val exclusionCount = scalar("SELECT COUNT(*) FROM exclusion")
        if (exclusionCount != counts.elfOnlyRvas) {
            truthFail("ELF-only exclusion projection count does not reconcile")
        }
        val exclusionDigest = writeExclusions(
            staging.resolve(EXCLUSIONS_FILE),
            oracle,
            exclusionCount,
            minOf(
                scope.document.truthObject("bounds").truthObject("wholeRun").truthLong("serializedBytes"),
                limits.maximumOutputBytes,
            ),
        )
        val exclusions = FunctionTruthFile(
            id = "elf-only-exclusions",
            path = EXCLUSIONS_FILE,
            sha256 = exclusionDigest.sha256,
            bytes = exclusionDigest.bytes,
            functions = exclusionCount,
            nonEmitted = 0L,
        )
        val contentBytes = (shardFiles + exclusions).fold(0L) { total, file ->
            checkedAdd(total, file.bytes, "truth output byte")
        }
        val wholeOutputBound = scope.document.truthObject("bounds").truthObject("wholeRun")
            .truthLong("serializedBytes")
        if (contentBytes > wholeOutputBound || contentBytes > limits.maximumOutputBytes) {
            truthFail("function truth exceeds its whole-run output byte bound")
        }
        val indexWithoutHash = JsonObject(
            mapOf(
                "complete" to JsonPrimitive(true),
                "counts" to counts.toJson(),
                "exclusions" to exclusions.toJson(),
                "oracle" to oracle,
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(shardFiles.map(FunctionTruthFile::toJson)),
            ),
        )
        val logicalIndexSha256 = sha256(canonicalControlBytes(indexWithoutHash, limits))
        val index = JsonObject(indexWithoutHash + ("indexSha256" to JsonPrimitive(logicalIndexSha256)))
        try {
            OracleSchemas.validate("full-tree-function-truth-index", index)
        } catch (failure: Exception) {
            throw FullTreeFunctionTruthException("generated function-truth index fails its bundled schema", failure)
        }
        val indexBytes = canonicalControlBytes(index, limits)
        val indexArtifactSha256 = sha256(indexBytes)
        writeMaterializedFile(staging.resolve(INDEX_FILE), indexBytes)
        val publishedBytes = checkedAdd(contentBytes, indexBytes.size.toLong(), "published truth byte")
        if (publishedBytes > limits.maximumOutputBytes || publishedBytes > wholeOutputBound) {
            truthFail("function-truth publication exceeds its whole-tree output bound")
        }
        budget.checkpoint("after projecting function-truth output")
        scratch.checkBound("after projecting function-truth output")
        return FunctionTruthProjection(
            index = index,
            indexBytes = indexBytes,
            indexArtifactSha256 = indexArtifactSha256,
            logicalIndexSha256 = logicalIndexSha256,
            counts = counts,
            shards = shardFiles,
            exclusions = exclusions,
            contentBytes = contentBytes,
            publishedBytes = publishedBytes,
            databaseHighWaterBytes = scratch.databaseHighWaterBytes(),
        )
    }

    private fun writeTruthShard(
        path: Path,
        shard: JsonObject,
        oracle: JsonObject,
        functionCount: Long,
        nonEmittedCount: Long,
        maximumBytes: Long,
    ): FileDigest = writeCanonicalFile(path, maximumBytes) { writer ->
        writer.startObject()
        writer.field("counts")
        writer.value(
            canonicalEntityBytes(
                JsonObject(
                    mapOf(
                        "functions" to JsonPrimitive(functionCount),
                        "nonEmitted" to JsonPrimitive(nonEmittedCount),
                    ),
                ),
                limits,
            ),
        )
        writer.field("functions")
        writer.startArray()
        connection.prepareStatement(
            "SELECT payload FROM truth_function WHERE owner_shard=? ORDER BY rva",
        ).use { statement ->
            statement.setString(1, shard.truthString("id"))
            statement.executeQuery().use { rows ->
                var observed = 0L
                while (rows.next()) {
                    writer.arrayValue(rows.getBytes(1))
                    observed = checkedAdd(observed, 1L, "truth shard function")
                }
                if (observed != functionCount) truthFail("function-truth shard function count changed")
            }
        }
        writer.endArray()
        writer.field("nonEmitted")
        writer.startArray()
        connection.prepareStatement(
            "SELECT payload FROM truth_non_emitted WHERE owner_shard=? ORDER BY prefix",
        ).use { statement ->
            statement.setString(1, shard.truthString("id"))
            statement.executeQuery().use { rows ->
                var observed = 0L
                while (rows.next()) {
                    writer.arrayValue(rows.getBytes(1))
                    observed = checkedAdd(observed, 1L, "truth shard non-emitted function")
                }
                if (observed != nonEmittedCount) truthFail("function-truth shard non-emitted count changed")
            }
        }
        writer.endArray()
        writer.field("oracle")
        writer.value(canonicalEntityBytes(oracle, limits))
        writer.field("schemaVersion")
        writer.value(canonicalEntityBytes(JsonPrimitive(1), limits))
        writer.field("shard")
        writer.value(canonicalEntityBytes(shard, limits))
        writer.endObject()
    }

    private fun writeExclusions(
        path: Path,
        oracle: JsonObject,
        exclusionCount: Long,
        maximumBytes: Long,
    ): FileDigest = writeCanonicalFile(path, maximumBytes) { writer ->
        writer.startObject()
        writer.field("functions")
        writer.startArray()
        connection.prepareStatement("SELECT payload FROM exclusion ORDER BY rva").use { statement ->
            statement.executeQuery().use { rows ->
                var observed = 0L
                while (rows.next()) {
                    writer.arrayValue(rows.getBytes(1))
                    observed = checkedAdd(observed, 1L, "ELF-only exclusion")
                }
                if (observed != exclusionCount) truthFail("ELF-only exclusion count changed")
            }
        }
        writer.endArray()
        writer.field("oracle")
        writer.value(canonicalEntityBytes(oracle, limits))
        writer.field("reasonCode")
        writer.value(canonicalEntityBytes(JsonPrimitive(ELF_ONLY_REASON), limits))
        writer.field("schemaVersion")
        writer.value(canonicalEntityBytes(JsonPrimitive(1), limits))
        writer.endObject()
    }

    private fun scalarForShard(table: String, shardId: String): Long {
        if (table !in setOf("truth_function", "truth_non_emitted")) {
            truthFail("function-truth scalar table is not implementation-owned")
        }
        return connection.prepareStatement("SELECT COUNT(*) FROM $table WHERE owner_shard=?").use { statement ->
            statement.setString(1, shardId)
            statement.executeQuery().use { rows ->
                if (!rows.next()) truthFail("function-truth shard count returned no row")
                rows.getLong(1).also {
                    if (rows.wasNull() || rows.next()) truthFail("function-truth shard count is invalid")
                }
            }
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        connection.close()
    }

    companion object {
        fun open(
            path: Path,
            limits: FullTreeFunctionTruthLimits,
            budget: FunctionTruthBudget,
            scratch: FunctionTruthScratch,
        ): FunctionTruthDatabase {
            val connection = DriverManager.getConnection(SqliteJdbcPaths.create(path))
            try {
                connection.createStatement().use { statement ->
                    statement.execute("PRAGMA journal_mode=DELETE")
                    statement.execute("PRAGMA synchronous=FULL")
                    statement.execute("PRAGMA foreign_keys=ON")
                    statement.execute("PRAGMA temp_store=MEMORY")
                    statement.execute("PRAGMA page_size=$SQLITE_PAGE_BYTES")
                    statement.execute("PRAGMA cache_size=-${limits.maximumSqliteCacheBytes / 1024}")
                    statement.execute("PRAGMA application_id=$SQLITE_APPLICATION_ID")
                    statement.execute("PRAGMA user_version=$SQLITE_SCHEMA_VERSION")
                    statement.execute("PRAGMA max_page_count=${limits.maximumDatabaseBytes / SQLITE_PAGE_BYTES}")
                    connection.autoCommit = false
                    statement.executeUpdate(
                        "CREATE TABLE all_rva(" +
                            "rva BLOB PRIMARY KEY NOT NULL CHECK(length(rva)=8)) WITHOUT ROWID",
                    )
                    statement.executeUpdate(
                        "CREATE TABLE elf(" +
                            "rva BLOB PRIMARY KEY NOT NULL CHECK(length(rva)=8), " +
                            "payload BLOB NOT NULL, " +
                            "FOREIGN KEY(rva) REFERENCES all_rva(rva)) WITHOUT ROWID",
                    )
                    statement.executeUpdate(
                        "CREATE TABLE emitted(" +
                            "rva BLOB NOT NULL CHECK(length(rva)=8), " +
                            "shard_id TEXT COLLATE BINARY NOT NULL, payload BLOB NOT NULL, " +
                            "PRIMARY KEY(rva, shard_id), " +
                            "FOREIGN KEY(rva) REFERENCES all_rva(rva)) WITHOUT ROWID",
                    )
                    statement.executeUpdate(
                        "CREATE TABLE non_emitted_identity(" +
                            "prefix BLOB PRIMARY KEY NOT NULL CHECK(length(prefix)=16), " +
                            "full_digest BLOB NOT NULL CHECK(length(full_digest)=32), " +
                            "identity_payload BLOB NOT NULL) WITHOUT ROWID",
                    )
                    statement.executeUpdate(
                        "CREATE TABLE non_emitted_observation(" +
                            "prefix BLOB NOT NULL CHECK(length(prefix)=16), " +
                            "observation_id TEXT COLLATE BINARY NOT NULL UNIQUE, " +
                            "shard_id TEXT COLLATE BINARY NOT NULL, payload BLOB NOT NULL, " +
                            "PRIMARY KEY(prefix, observation_id), " +
                            "FOREIGN KEY(prefix) REFERENCES non_emitted_identity(prefix)) WITHOUT ROWID",
                    )
                    statement.executeUpdate(
                        "CREATE TABLE truth_function(" +
                            "owner_shard TEXT COLLATE BINARY NOT NULL, " +
                            "rva BLOB NOT NULL UNIQUE CHECK(length(rva)=8), payload BLOB NOT NULL, " +
                            "PRIMARY KEY(owner_shard, rva)) WITHOUT ROWID",
                    )
                    statement.executeUpdate(
                        "CREATE TABLE emitted_alias(" +
                            "name TEXT COLLATE BINARY NOT NULL, rva BLOB NOT NULL CHECK(length(rva)=8), " +
                            "PRIMARY KEY(name, rva)) WITHOUT ROWID",
                    )
                    statement.executeUpdate(
                        "CREATE TABLE truth_non_emitted(" +
                            "owner_shard TEXT COLLATE BINARY NOT NULL, " +
                            "prefix BLOB NOT NULL UNIQUE CHECK(length(prefix)=16), " +
                            "identifier TEXT COLLATE BINARY NOT NULL UNIQUE, payload BLOB NOT NULL, " +
                            "PRIMARY KEY(owner_shard, prefix)) WITHOUT ROWID",
                    )
                    statement.executeUpdate(
                        "CREATE TABLE exclusion(" +
                            "rva BLOB PRIMARY KEY NOT NULL CHECK(length(rva)=8), payload BLOB NOT NULL) WITHOUT ROWID",
                    )
                }
                scratch.checkBound("before committing function-truth SQLite schema")
                connection.commit()
                scratch.checkBound("after creating function-truth SQLite schema")
                return FunctionTruthDatabase(connection, limits, budget, scratch)
            } catch (failure: Throwable) {
                runCatching { connection.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

private data class EmittedGroupCounts(
    val dwarfRvas: Long,
    val scoredRvas: Long,
    val dwarfOnlyRvas: Long,
    val elfOnlyRvas: Long,
    val coalescedEmittedRvas: Long,
)

private data class CompletedEmitted(
    val function: ByteArray?,
    val exclusion: ByteArray?,
    val ownerShard: String?,
    val aliasNames: List<String>,
    val counts: EmittedGroupCounts,
)

private class EmittedTruthGroup(
    rvaKey: ByteArray,
    private val limits: FullTreeFunctionTruthLimits,
    runtimeBudget: FunctionTruthBudget,
) {
    val rvaKey: ByteArray = rvaKey.copyOf()
    private val rva = unsignedValue(this.rvaKey)
    private val budget = FunctionTruthGroupBudget(
        limits,
        "emitted RVA ${canonicalAddress(rva)}",
        runtimeBudget,
    )
    private val aliases = FunctionTruthAliases(budget, limits)
    private val declarations = CanonicalObjectSet(budget)
    private val owners = sortedSetOf(FULL_TREE_CODE_POINT_ORDER)
    private var elfPayload: ByteArray? = null
    private var dwarfRows = 0

    fun acceptElf(payload: ByteArray) {
        val existing = elfPayload
        if (existing != null) {
            if (!MessageDigest.isEqual(existing, payload)) truthFail("ELF record changed within one RVA group")
            return
        }
        budget.chargeRow(payload)
        val record = parseCanonicalEntity(payload, limits, "ELF function record")
        if (parseCanonicalAddress(record.truthString("rva"), "ELF function RVA") != rva) {
            truthFail("ELF function payload differs from its SQLite RVA")
        }
        aliases.accept(record.truthArray("aliases"), "ELF function alias")
        elfPayload = payload.copyOf()
    }

    fun acceptDwarf(payload: ByteArray) {
        dwarfRows++
        budget.chargeRow(payload)
        val record = parseCanonicalEntity(payload, limits, "emitted function observation")
        if (parseCanonicalAddress(record.truthString("rva"), "DWARF emitted RVA") != rva) {
            truthFail("DWARF function payload differs from its SQLite RVA")
        }
        aliases.accept(record.truthArray("aliases"), "DWARF function alias")
        record.truthArray("declarations").forEachIndexed { index, raw ->
            declarations.add(raw as? JsonObject
                ?: truthFail("DWARF function declaration $index is not an object"))
        }
        record.truthArray("ownerUnitIds").forEach { raw ->
            val owner = (raw as? JsonPrimitive)?.takeIf { it.isString }?.content
                ?: truthFail("DWARF function owner is not a string")
            owners += owner
        }
    }

    fun finish(
        unitToShard: Map<String, String>,
        limits: FullTreeFunctionTruthLimits,
    ): CompletedEmitted {
        val aliasValues = aliases.toJson()
        val aliasNames = aliases.names()
        if (dwarfRows == 0) {
            if (elfPayload == null) truthFail("RVA group has neither ELF nor DWARF evidence")
            val exclusion = JsonObject(
                mapOf(
                    "aliases" to aliasValues,
                    "id" to JsonPrimitive("function-rva-${canonicalAddress(rva)}"),
                    "reasonCode" to JsonPrimitive(ELF_ONLY_REASON),
                    "rva" to JsonPrimitive(canonicalAddress(rva)),
                ),
            )
            return CompletedEmitted(
                function = null,
                exclusion = canonicalEntityBytes(exclusion, limits),
                ownerShard = null,
                aliasNames = emptyList(),
                counts = EmittedGroupCounts(0L, 0L, 0L, 1L, 0L),
            )
        }
        if (owners.isEmpty() || declarations.isEmpty()) {
            truthFail("DWARF emitted RVA lacks ownership or declaration evidence")
        }
        val hasElf = elfPayload != null
        if (!hasElf && owners.size > 1) {
            truthFail(
                "coalesced DWARF-only contradiction at ${canonicalAddress(rva)}: " +
                    "multiple owners require emitted ELF evidence",
            )
        }
        val owner = owners.first()
        val ownerShard = unitToShard[owner]
            ?: truthFail("reconciled function owner is outside the authenticated inventory")
        val isThunk = aliasNames.any(::isThunkName)
        val coalesced = owners.size > 1
        val function = JsonObject(
            mapOf(
                "aliases" to aliasValues,
                "declarations" to declarations.toJson(),
                "emissionKind" to JsonPrimitive(
                    if (coalesced) COALESCED_EMISSION else SINGLE_EMISSION,
                ),
                "entityKind" to JsonPrimitive(if (isThunk) "thunk" else "function"),
                "id" to JsonPrimitive("function-rva-${canonicalAddress(rva)}"),
                "ownerUnitId" to JsonPrimitive(owner),
                "ownershipCandidates" to JsonArray(owners.map(::JsonPrimitive)),
                "population" to JsonPrimitive(if (hasElf) "scored" else "excluded"),
                "reasonCode" to if (hasElf) JsonNull else JsonPrimitive(DWARF_ONLY_REASON),
                "rva" to JsonPrimitive(canonicalAddress(rva)),
            ),
        )
        return CompletedEmitted(
            function = canonicalEntityBytes(function, limits),
            exclusion = null,
            ownerShard = ownerShard,
            aliasNames = aliasNames,
            counts = EmittedGroupCounts(
                dwarfRvas = 1L,
                scoredRvas = if (hasElf) 1L else 0L,
                dwarfOnlyRvas = if (hasElf) 0L else 1L,
                elfOnlyRvas = 0L,
                coalescedEmittedRvas = if (hasElf && coalesced) 1L else 0L,
            ),
        )
    }
}

private data class CompletedNonEmitted(
    val identifier: String,
    val ownerShard: String,
    val payload: ByteArray,
    val observations: Long,
    val reasonCode: String,
)

private class NonEmittedTruthGroup(
    prefix: ByteArray,
    fullDigest: ByteArray,
    preimage: ByteArray,
    private val limits: FullTreeFunctionTruthLimits,
    runtimeBudget: FunctionTruthBudget,
) {
    val prefix: ByteArray = prefix.copyOf()
    private val fullDigest = fullDigest.copyOf()
    private val preimage = preimage.copyOf()
    private val identifier = "non-emitted-function-${this.prefix.truthHex()}"
    private val budget = FunctionTruthGroupBudget(limits, identifier, runtimeBudget)
    private val aliases = FunctionTruthAliases(budget, limits)
    private val declarations = CanonicalObjectSet(budget)
    private val observationIds = sortedSetOf(FULL_TREE_CODE_POINT_ORDER)
    private val dieOffsets = TreeMap<FunctionTruthDieKey, JsonObject>()
    private val owners = sortedSetOf(FULL_TREE_CODE_POINT_ORDER)
    private val reasons = sortedSetOf(FULL_TREE_CODE_POINT_ORDER)

    init {
        if (this.prefix.size != 16 || this.fullDigest.size != 32) {
            truthFail("non-emitted identity has an invalid digest width")
        }
        val observed = MessageDigest.getInstance("SHA-256").digest(this.preimage)
        if (
            !MessageDigest.isEqual(observed, this.fullDigest) ||
            !MessageDigest.isEqual(observed.copyOf(16), this.prefix)
        ) {
            truthFail("non-emitted identity digest does not reconcile")
        }
    }

    fun requireIdentity(fullDigest: ByteArray, preimage: ByteArray) {
        if (
            !MessageDigest.isEqual(this.fullDigest, fullDigest) ||
            !MessageDigest.isEqual(this.preimage, preimage)
        ) {
            truthFail("non-emitted 128-bit identity prefix collision: $identifier")
        }
    }

    fun accept(payload: ByteArray) {
        budget.chargeRow(payload)
        val record = parseCanonicalEntity(payload, limits, "non-emitted function observation")
        aliases.accept(record.truthArray("aliases"), "non-emitted function alias")
        declarations.add(record.truthObject("declaration"))
        observationIds += record.truthString("id")
        record.truthArray("unitIds").forEach { raw ->
            val owner = (raw as? JsonPrimitive)?.takeIf { it.isString }?.content
                ?: truthFail("non-emitted function owner is not a string")
            owners += owner
        }
        record.truthArray("reasonCodes").forEach { raw ->
            val reason = (raw as? JsonPrimitive)?.takeIf { it.isString }?.content
                ?: truthFail("non-emitted function reason is not a string")
            reasons += reason
        }
        record.truthArray("dieOffsets").forEachIndexed { index, raw ->
            val locator = raw as? JsonObject
                ?: truthFail("non-emitted DIE locator $index is not an object")
            val key = FunctionTruthDieKey(
                locator.truthString("unitId"),
                parseCanonicalAddress(locator.truthString("dieOffset"), "non-emitted DIE offset"),
            )
            dieOffsets.putIfAbsent(key, locator)
        }
    }

    fun finish(
        unitToShard: Map<String, String>,
        selectedAlias: PreparedStatement,
        limits: FullTreeFunctionTruthLimits,
    ): CompletedNonEmitted {
        if (
            aliases.isEmpty() || declarations.isEmpty() || observationIds.isEmpty() ||
            dieOffsets.isEmpty() || owners.isEmpty() || reasons.isEmpty()
        ) {
            truthFail("non-emitted function identity lacks required evidence")
        }
        val selectedElsewhere = if (DEFINITION_REASON in reasons) {
            aliases.names().any { name ->
                selectedAlias.setString(1, name)
                selectedAlias.executeQuery().use(ResultSet::next)
            }
        } else {
            false
        }
        val reason = when {
            DEFINITION_REASON in reasons && selectedElsewhere -> SELECTED_REASON
            DEFINITION_REASON in reasons -> DEFINITION_REASON
            else -> INLINE_REASON
        }
        val owner = owners.first()
        val ownerShard = unitToShard[owner]
            ?: truthFail("non-emitted function owner is outside the authenticated inventory")
        val document = JsonObject(
            mapOf(
                "aliases" to aliases.toJson(),
                "declarations" to declarations.toJson(),
                "id" to JsonPrimitive(identifier),
                "observationDieOffsets" to JsonArray(dieOffsets.values.toList()),
                "observationIds" to JsonArray(observationIds.map(::JsonPrimitive)),
                "ownerUnitId" to JsonPrimitive(owner),
                "population" to JsonPrimitive("unobservable"),
                "reasonCode" to JsonPrimitive(reason),
            ),
        )
        return CompletedNonEmitted(
            identifier = identifier,
            ownerShard = ownerShard,
            payload = canonicalEntityBytes(document, limits),
            observations = dieOffsets.size.toLong(),
            reasonCode = reason,
        )
    }
}

private class FunctionTruthAliases(
    private val budget: FunctionTruthGroupBudget,
    private val limits: FullTreeFunctionTruthLimits,
) {
    private val byName = TreeMap<String, TreeMap<ByteKey, JsonObject>>(FULL_TREE_CODE_POINT_ORDER)

    fun accept(values: JsonArray, label: String) {
        values.forEachIndexed { index, raw ->
            val alias = raw as? JsonObject ?: truthFail("$label $index is not an object")
            val name = alias.truthString("name")
            val evidence = byName.getOrPut(name) { TreeMap(BYTE_KEY_ORDER) }
            alias.truthArray("evidence").forEachIndexed { evidenceIndex, evidenceRaw ->
                val input = evidenceRaw as? JsonObject
                    ?: truthFail("$label $index evidence $evidenceIndex is not an object")
                val normalized = JsonObject(
                    mapOf(
                        "kind" to JsonPrimitive(input.truthString("kind")),
                        "locator" to JsonPrimitive(input.truthString("locator")),
                        "unitId" to (input["unitId"] ?: JsonNull),
                    ),
                )
                val canonical = canonicalEntityBytes(normalized, limits)
                val key = ByteKey(canonical)
                if (evidence.putIfAbsent(key, normalized) == null) budget.chargeUnique(canonical.size)
            }
        }
    }

    fun names(): List<String> = byName.keys.toList()

    fun isEmpty(): Boolean = byName.isEmpty()

    fun toJson(): JsonArray = JsonArray(
        byName.map { (name, evidence) ->
            JsonObject(
                mapOf(
                    "evidence" to JsonArray(evidence.values.toList()),
                    "name" to JsonPrimitive(name),
                ),
            )
        },
    )
}

private class CanonicalObjectSet(private val budget: FunctionTruthGroupBudget) {
    private val values = TreeMap<ByteKey, JsonObject>(BYTE_KEY_ORDER)

    fun add(value: JsonObject) {
        val canonical = canonicalEntityBytes(value, budget.limits)
        if (values.putIfAbsent(ByteKey(canonical), value) == null) budget.chargeUnique(canonical.size)
    }

    fun isEmpty(): Boolean = values.isEmpty()

    fun toJson(): JsonArray = JsonArray(values.values.toList())
}

private class FunctionTruthGroupBudget(
    val limits: FullTreeFunctionTruthLimits,
    private val label: String,
    private val runtimeBudget: FunctionTruthBudget,
) {
    private var rows = 0
    private var bytes = 0L

    fun chargeRow(payload: ByteArray) {
        rows++
        if (rows > limits.maximumGroupRows) truthFail("$label exceeds its grouped-row bound")
        charge(payload.size)
        if (rows % limits.databaseCheckpointRows == 0) {
            runtimeBudget.checkpoint("while reconciling $label")
        }
    }

    fun chargeUnique(size: Int) = charge(size)

    private fun charge(size: Int) {
        bytes = checkedAdd(bytes, size.toLong(), "$label grouped byte")
        if (bytes > limits.maximumEntityBytes.toLong()) {
            truthFail("$label exceeds its bounded in-memory merge budget")
        }
    }
}

private data class FunctionTruthDieKey(val unitId: String, val dieOffset: ULong) :
    Comparable<FunctionTruthDieKey> {
    override fun compareTo(other: FunctionTruthDieKey): Int {
        val unit = FULL_TREE_CODE_POINT_ORDER.compare(unitId, other.unitId)
        return if (unit != 0) unit else dieOffset.compareTo(other.dieOffset)
    }
}

private class ByteKey(bytes: ByteArray) {
    val bytes: ByteArray = bytes.copyOf()

    override fun equals(other: Any?): Boolean = other is ByteKey && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()
}

private val BYTE_KEY_ORDER = Comparator<ByteKey> { left, right ->
    compareUnsignedBytes(left.bytes, right.bytes)
}

private class FunctionTruthPublication private constructor(
    val target: Path,
    val staging: Path,
    private val parentIdentity: Any,
    private val stagingIdentity: Any,
    private val limits: FullTreeFunctionTruthLimits,
) : AutoCloseable {
    private var published = false
    private var committed = false

    fun commit(
        projection: FunctionTruthProjection,
        inventory: JsonObject,
        oracle: JsonObject,
        scope: AuthenticatedFullTreeScope,
        limits: FullTreeFunctionTruthLimits,
        budget: FunctionTruthBudget,
        verifyInputs: () -> Unit,
    ) {
        budget.checkpoint("before staging function-truth publication")
        requireDirectoryIdentity(target.parent, parentIdentity, "function-truth publication parent")
        requireDirectoryIdentity(staging, stagingIdentity, "function-truth staging root")
        requirePublicationMembership(staging, projection)
        freezePublicationTree(staging, projection, budget)
        verifyFunctionTruthPublication(staging, projection, inventory, oracle, scope, limits, budget)
        budget.checkpoint("after verifying staged function-truth publication")
        verifyInputs()
        budget.checkpoint("after rechecking staged function-truth inputs")
        requireDirectoryIdentity(target.parent, parentIdentity, "function-truth publication parent")
        requireDirectoryIdentity(staging, stagingIdentity, "function-truth staging root")
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            truthFail("function-truth output root already exists")
        }
        forceDirectory(staging.resolve(SHARDS_DIRECTORY))
        forceDirectory(staging)
        forceDirectory(target.parent)
        try {
            LinuxFilesystemSyscalls.requireSupported(target.parent)
            LinuxFilesystemSyscalls.openRoot(target.parent).use { parent ->
                parent.whileOpen { parentFd ->
                    if (!Files.isSameFile(target.parent, LinuxFilesystemSyscalls.stableDescriptorPath(parentFd))) {
                        truthFail("function-truth output parent changed before publication")
                    }
                    LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, target.fileName.toString())?.use {
                        truthFail("function-truth output root already exists")
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
                            throw FullTreeFunctionTruthException(
                                "function-truth output root already exists",
                                failure,
                            )
                        }
                        throw failure
                    }
                    published = true
                }
                LinuxFilesystemSyscalls.synchronize(parent)
            }
            budget.checkpoint("after moving function-truth publication")
            requireDirectoryIdentity(target, stagingIdentity, "published function-truth root")
            forceDirectory(target.parent)
            requireDirectoryIdentity(target.parent, parentIdentity, "function-truth publication parent")
            verifyFunctionTruthPublication(target, projection, inventory, oracle, scope, limits, budget)
            budget.checkpoint("after verifying moved function-truth publication")
            verifyInputs()
            budget.checkpoint("after rechecking moved function-truth inputs")
            requireDirectoryIdentity(target, stagingIdentity, "published function-truth root")
            requireDirectoryIdentity(target.parent, parentIdentity, "function-truth publication parent")
            committed = true
        } catch (failure: Throwable) {
            if (published) {
                try {
                    revokePublished(projection)
                } catch (revokeFailure: Throwable) {
                    failure.addSuppressed(revokeFailure)
                }
            }
            if (failure is FullTreeFunctionTruthException) throw failure
            throw FullTreeFunctionTruthException("function-truth publication failed closed", failure)
        }
    }

    override fun close() {
        if (committed) return
        val root = if (published) target else staging
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
        if (published) {
            truthFail("unverified published function-truth tree remains at its target")
        }
        requireDirectoryIdentity(root, stagingIdentity, "function-truth staging cleanup")
        makeOwnedTreeWritable(root)
        Files.walk(root).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach { candidate -> Files.delete(candidate) }
        }
        forceDirectory(target.parent)
    }

    private fun revokePublished(projection: FunctionTruthProjection) {
        requireDirectoryIdentity(target, stagingIdentity, "unverified published function-truth root")
        requireDirectoryIdentity(target.parent, parentIdentity, "function-truth publication parent")
        LinuxFilesystemSyscalls.requireSupported(target.parent)
        LinuxFilesystemSyscalls.openRoot(target.parent).use { parent ->
            parent.whileOpen { parentFd ->
                if (!Files.isSameFile(target.parent, LinuxFilesystemSyscalls.stableDescriptorPath(parentFd))) {
                    truthFail("function-truth output parent changed before quarantine")
                }
                LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, staging.fileName.toString())?.use {
                    truthFail("function-truth quarantine name unexpectedly exists")
                }
                LinuxFilesystemSyscalls.renameNoReplace(
                    parentFd,
                    target.fileName.toString(),
                    staging.fileName.toString(),
                )
                LinuxFilesystemSyscalls.synchronize(parent)
            }
        }
        published = false
        requireDirectoryIdentity(staging, stagingIdentity, "quarantined function-truth root")
        requirePublicationMembership(staging, projection)
        makeOwnedTreeWritable(staging)
        Files.walk(staging).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach { candidate -> Files.delete(candidate) }
        }
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            truthFail("unverified function-truth publication could not be revoked")
        }
        forceDirectory(target.parent)
    }

    companion object {
        fun create(path: Path, limits: FullTreeFunctionTruthLimits): FunctionTruthPublication {
            val target = path.toAbsolutePath().normalize()
            if (target.parent == null || target.fileName == null) {
                truthFail("function-truth output root must name a directory")
            }
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                truthFail("function-truth output root already exists")
            }
            val (parent, parentIdentity) = requireStableDirectory(
                target.parent,
                "function-truth publication parent",
            )
            val staging = Files.createTempDirectory(
                parent,
                ".${target.fileName}.function-truth-",
                PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS),
            )
            try {
                Files.createDirectory(
                    staging.resolve(SHARDS_DIRECTORY),
                    PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS),
                )
                forceDirectory(staging)
                forceDirectory(parent)
                return FunctionTruthPublication(
                    target,
                    staging,
                    parentIdentity,
                    directoryIdentity(staging, "function-truth staging root"),
                    limits,
                )
            } catch (failure: Throwable) {
                runCatching {
                    if (Files.exists(staging, LinkOption.NOFOLLOW_LINKS)) {
                        Files.walk(staging).use { paths ->
                            paths.sorted(Comparator.reverseOrder()).forEach { Files.delete(it) }
                        }
                    }
                }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

private fun freezePublicationTree(
    root: Path,
    projection: FunctionTruthProjection,
    budget: FunctionTruthBudget,
) {
    requirePublicationMembership(root, projection)
    expectedPublicationFiles(root, projection).forEachIndexed { index, file ->
        Files.setPosixFilePermissions(file, READ_ONLY_FILE_PERMISSIONS)
        FileChannel.open(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { it.force(true) }
        if (Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS) != READ_ONLY_FILE_PERMISSIONS) {
            truthFail("function-truth staged file permissions differ")
        }
        if ((index + 1) % PUBLICATION_CHECKPOINT_FILES == 0) {
            budget.checkpoint("while freezing function-truth publication files")
        }
    }
    Files.setPosixFilePermissions(root.resolve(SHARDS_DIRECTORY), READ_ONLY_DIRECTORY_PERMISSIONS)
    Files.setPosixFilePermissions(root, READ_ONLY_DIRECTORY_PERMISSIONS)
    forceDirectory(root.resolve(SHARDS_DIRECTORY))
    forceDirectory(root)
    budget.checkpoint("after freezing function-truth publication tree")
}

private fun makeOwnedTreeWritable(root: Path) {
    Files.setPosixFilePermissions(root, PRIVATE_DIRECTORY_PERMISSIONS)
    val shards = root.resolve(SHARDS_DIRECTORY)
    if (Files.exists(shards, LinkOption.NOFOLLOW_LINKS)) {
        Files.setPosixFilePermissions(shards, PRIVATE_DIRECTORY_PERMISSIONS)
    }
    Files.walk(root).use { paths ->
        paths.filter { candidate ->
            Files.isRegularFile(candidate, LinkOption.NOFOLLOW_LINKS)
        }.forEach { file -> Files.setPosixFilePermissions(file, PRIVATE_FILE_PERMISSIONS) }
    }
}

private fun requirePublicationMembership(root: Path, projection: FunctionTruthProjection) {
    val expectedRoot = setOf(INDEX_FILE, EXCLUSIONS_FILE, SHARDS_DIRECTORY)
    val shardDirectory = root.resolve(SHARDS_DIRECTORY)
    listOf(root, shardDirectory).forEach { directory ->
        val attributes = Files.readAttributes(
            directory,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
            truthFail("function-truth publication directory is invalid")
        }
    }
    val actualRoot = boundedDirectoryMembers(root, expectedRoot.size, "function-truth root")
    if (actualRoot != expectedRoot) truthFail("function-truth root membership is incomplete or extra")
    val expectedShards = projection.shards.mapTo(linkedSetOf()) { Path.of(it.path).fileName.toString() }
    val actualShards = boundedDirectoryMembers(
        shardDirectory,
        expectedShards.size,
        "function-truth shard directory",
    )
    if (actualShards != expectedShards) truthFail("function-truth shard membership is incomplete or extra")
    val fileIdentities = HashSet<Any>()
    expectedPublicationFiles(root, projection).forEach { file ->
        val attributes = Files.readAttributes(
            file,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        val identity = attributes.fileKey()
        val linkCount = (Files.getAttribute(file, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as? Number)
            ?.toLong()
            ?: truthFail("function-truth publication member link count is unavailable")
        if (
            !attributes.isRegularFile || attributes.isSymbolicLink || identity == null ||
            linkCount != 1L || !fileIdentities.add(identity)
        ) {
            truthFail("function-truth publication member is not an identified regular file")
        }
    }
}

private fun boundedDirectoryMembers(directory: Path, maximumMembers: Int, label: String): Set<String> {
    if (maximumMembers < 0) truthFail("$label has an invalid member bound")
    val members = linkedSetOf<String>()
    Files.newDirectoryStream(directory).use { entries ->
        entries.forEach { entry ->
            if (members.size >= maximumMembers) truthFail("$label contains extra members")
            if (!members.add(entry.fileName.toString())) truthFail("$label repeats a member name")
        }
    }
    return members
}

private fun expectedPublicationFiles(root: Path, projection: FunctionTruthProjection): List<Path> =
    buildList {
        add(root.resolve(INDEX_FILE))
        add(root.resolve(EXCLUSIONS_FILE))
        projection.shards.forEach { add(root.resolve(it.path)) }
    }

private fun verifyFunctionTruthPublication(
    root: Path,
    projection: FunctionTruthProjection,
    inventory: JsonObject,
    oracle: JsonObject,
    scope: AuthenticatedFullTreeScope,
    limits: FullTreeFunctionTruthLimits,
    budget: FunctionTruthBudget,
) {
    budget.checkpoint("before streaming function-truth publication")
    requirePublicationMembership(root, projection)
    if (
        Files.getPosixFilePermissions(root, LinkOption.NOFOLLOW_LINKS) != READ_ONLY_DIRECTORY_PERMISSIONS ||
        Files.getPosixFilePermissions(root.resolve(SHARDS_DIRECTORY), LinkOption.NOFOLLOW_LINKS) !=
        READ_ONLY_DIRECTORY_PERMISSIONS
    ) {
        truthFail("function-truth publication directory permissions differ")
    }
    expectedPublicationFiles(root, projection).forEach { file ->
        if (Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS) != READ_ONLY_FILE_PERMISSIONS) {
            truthFail("function-truth publication file permissions differ")
        }
    }
    val inventoryShards = inventory.truthArray("shards").associate { raw ->
        val shard = raw as? JsonObject ?: truthFail("inventory shard is not an object")
        shard.truthString("id") to shard
    }
    val unitToShard = inventory.truthArray("units").associate { raw ->
        val unit = raw as? JsonObject ?: truthFail("inventory unit is not an object")
        unit.truthString("id") to unit.truthString("shardId")
    }
    if (unitToShard.size != inventory.truthArray("units").size) {
        truthFail("inventory repeats a compilation-unit identity during publication verification")
    }
    var contentBytes = 0L
    var totalFunctions = 0L
    var totalNonEmitted = 0L
    var totalNonEmittedObservations = 0L
    projection.shards.forEachIndexed { shardIndex, file ->
        val expectedShard = inventoryShards[file.id]
            ?: truthFail("function-truth projection references an unknown shard")
        var functions = 0L
        var nonEmitted = 0L
        var previousRva: ULong? = null
        var previousIdentity: String? = null
        val streamed = FullTreeCanonicalStreaming.readObject(
            path = root.resolve(file.path),
            label = "published function-truth shard ${file.id}",
            expectedSourceSha256 = file.sha256,
            fieldOrder = TRUTH_SHARD_FIELDS,
            arrayFields = setOf("functions", "nonEmitted"),
            omittedDigestField = null,
            limits = streamingLimits(
                maximumBytes = file.bytes,
                maximumEntities = maxOf(1L, checkedAdd(file.functions, file.nonEmitted, "truth shard entity")),
                limits = limits,
            ),
        ) { field, _, value, _ ->
            when (field) {
                "functions" -> {
                    val rva = parseCanonicalAddress(value.truthString("rva"), "truth function RVA")
                    if (previousRva != null && previousRva!! >= rva) {
                        truthFail("function-truth shard functions are not strictly RVA ordered")
                    }
                    previousRva = rva
                    validatePublishedTruthFunction(value, rva, file.id, unitToShard, limits)
                    val expectedKind = if (
                        value.truthArray("aliases").any { raw ->
                            isThunkName((raw as JsonObject).truthString("name"))
                        }
                    ) "thunk" else "function"
                    if (value.truthString("entityKind") != expectedKind) {
                        truthFail("function-truth entity kind contradicts its aliases")
                    }
                    functions = checkedAdd(functions, 1L, "published truth function")
                    if ((functions + nonEmitted) % limits.databaseCheckpointRows == 0L) {
                        budget.checkpoint("while streaming published truth functions")
                    }
                }
                "nonEmitted" -> {
                    val identity = value.truthString("id")
                    if (
                        previousIdentity != null &&
                        FULL_TREE_CODE_POINT_ORDER.compare(previousIdentity, identity) >= 0
                    ) {
                        truthFail("function-truth non-emitted identities are not strictly ordered")
                    }
                    previousIdentity = identity
                    totalNonEmittedObservations = checkedAdd(
                        totalNonEmittedObservations,
                        validatePublishedNonEmitted(value, file.id, unitToShard, limits),
                        "published non-emitted observation",
                    )
                    nonEmitted = checkedAdd(nonEmitted, 1L, "published non-emitted function")
                    if ((functions + nonEmitted) % limits.databaseCheckpointRows == 0L) {
                        budget.checkpoint("while streaming published non-emitted functions")
                    }
                }
                else -> truthFail("function-truth shard exposed an unexpected streamed field")
            }
        }
        val envelope = streamed.envelope
        val expectedCounts = JsonObject(
            mapOf(
                "functions" to JsonPrimitive(file.functions),
                "nonEmitted" to JsonPrimitive(file.nonEmitted),
            ),
        )
        if (
            streamed.sourceBytes != file.bytes ||
            functions != file.functions ||
            nonEmitted != file.nonEmitted ||
            envelope.truthObject("counts") != expectedCounts ||
            envelope.truthObject("oracle") != oracle ||
            envelope.truthLong("schemaVersion") != 1L ||
            envelope.truthObject("shard") != expectedShard
        ) {
            truthFail("published function-truth shard ${file.id} differs from its index binding")
        }
        totalFunctions = checkedAdd(totalFunctions, functions, "published truth function")
        totalNonEmitted = checkedAdd(totalNonEmitted, nonEmitted, "published non-emitted function")
        contentBytes = checkedAdd(contentBytes, file.bytes, "published function-truth content byte")
        if ((shardIndex + 1) % PUBLICATION_CHECKPOINT_FILES == 0) {
            budget.checkpoint("while verifying published function-truth shards")
        }
    }
    var exclusionFunctions = 0L
    var previousExclusion: ULong? = null
    val exclusions = FullTreeCanonicalStreaming.readObject(
        path = root.resolve(EXCLUSIONS_FILE),
        label = "published function-truth exclusions",
        expectedSourceSha256 = projection.exclusions.sha256,
        fieldOrder = EXCLUSION_FIELDS,
        arrayFields = setOf("functions"),
        omittedDigestField = null,
        limits = streamingLimits(
            maximumBytes = projection.exclusions.bytes,
            maximumEntities = maxOf(1L, projection.exclusions.functions),
            limits = limits,
        ),
    ) { field, _, value, _ ->
        if (field != "functions") truthFail("function-truth exclusions exposed an unexpected field")
        val rva = parseCanonicalAddress(value.truthString("rva"), "ELF-only exclusion RVA")
        if (previousExclusion != null && previousExclusion!! >= rva) {
            truthFail("ELF-only exclusions are not strictly RVA ordered")
        }
        previousExclusion = rva
        if (value.truthString("reasonCode") != ELF_ONLY_REASON) {
            truthFail("ELF-only exclusion has the wrong reason")
        }
        if (
            value.keys != setOf("aliases", "id", "reasonCode", "rva") ||
            value.truthString("id") != "function-rva-${canonicalAddress(rva)}"
        ) {
            truthFail("ELF-only exclusion identity or fields differ from its RVA")
        }
        validateTruthAliases(value.truthArray("aliases"), limits)
        exclusionFunctions = checkedAdd(exclusionFunctions, 1L, "published ELF-only exclusion")
        if (exclusionFunctions % limits.databaseCheckpointRows == 0L) {
            budget.checkpoint("while streaming published function-truth exclusions")
        }
    }
    if (
        exclusions.sourceBytes != projection.exclusions.bytes ||
        exclusionFunctions != projection.exclusions.functions ||
        exclusions.envelope.truthObject("oracle") != oracle ||
        exclusions.envelope.truthString("reasonCode") != ELF_ONLY_REASON ||
        exclusions.envelope.truthLong("schemaVersion") != 1L
    ) {
        truthFail("published function-truth exclusions differ from their index binding")
    }
    contentBytes = checkedAdd(
        contentBytes,
        projection.exclusions.bytes,
        "published function-truth content byte",
    )
    if (contentBytes != projection.contentBytes) {
        truthFail("published function-truth content byte count does not reconcile")
    }
    val (index, indexBytes) = try {
        readCanonicalControlObject(
            root.resolve(INDEX_FILE),
            limits.observationRun.maximumControlArtifactBytes,
            "published function-truth index",
            "full-tree-function-truth-index",
        )
    } catch (failure: Exception) {
        throw FullTreeFunctionTruthException("cannot authenticate the published function-truth index", failure)
    }
    if (
        index != projection.index ||
        !MessageDigest.isEqual(indexBytes, projection.indexBytes) ||
        sha256(indexBytes) != projection.indexArtifactSha256 ||
        index.truthString("indexSha256") != projection.logicalIndexSha256 ||
        checkedAdd(contentBytes, indexBytes.size.toLong(), "published function-truth byte") !=
        projection.publishedBytes
    ) {
        truthFail("published function-truth index bytes differ from the completed projection")
    }
    val withoutSelf = JsonObject(index.filterKeys { it != "indexSha256" })
    if (sha256(canonicalControlBytes(withoutSelf, limits)) != projection.logicalIndexSha256) {
        truthFail("published function-truth logical index hash does not reconcile")
    }
    val totalEntities = checkedAdd(
        checkedAdd(projection.counts.elfRvas, projection.counts.dwarfOnlyRvas, "truth entity"),
        projection.counts.nonEmittedUnique,
        "truth entity",
    )
    if (totalEntities > scope.document.truthObject("bounds").truthObject("wholeRun").truthLong("entities")) {
        truthFail("published function truth exceeds its authenticated entity bound")
    }
    if (
        totalFunctions != projection.counts.dwarfRvas ||
        totalNonEmitted != projection.counts.nonEmittedUnique ||
        totalNonEmittedObservations != projection.counts.nonEmittedObservations ||
        exclusionFunctions != projection.counts.elfOnlyRvas
    ) {
        truthFail("published function-truth aggregate populations do not reconcile")
    }
    requirePublicationMembership(root, projection)
    budget.checkpoint("after streaming function-truth publication")
}

private fun validatePublishedTruthFunction(
    value: JsonObject,
    rva: ULong,
    shardId: String,
    unitToShard: Map<String, String>,
    limits: FullTreeFunctionTruthLimits,
) {
    if (
        value.keys != setOf(
            "aliases",
            "declarations",
            "emissionKind",
            "entityKind",
            "id",
            "ownerUnitId",
            "ownershipCandidates",
            "population",
            "reasonCode",
            "rva",
        ) ||
        value.truthString("id") != "function-rva-${canonicalAddress(rva)}"
    ) {
        truthFail("published function identity or fields differ from its RVA")
    }
    validateTruthAliases(value.truthArray("aliases"), limits)
    validateTruthDeclarations(value.truthArray("declarations"), limits)
    val owners = value.truthArray("ownershipCandidates").mapIndexed { index, raw ->
        (raw as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: truthFail("published function ownership candidate $index is not a string")
    }
    if (owners.isEmpty()) truthFail("published function has no ownership candidates")
    owners.zipWithNext().forEach { (left, right) ->
        if (FULL_TREE_CODE_POINT_ORDER.compare(left, right) >= 0) {
            truthFail("published function ownership candidates are not strictly ordered")
        }
    }
    if (owners.any { it !in unitToShard }) {
        truthFail("published function ownership candidate is outside the authenticated inventory")
    }
    val owner = value.truthString("ownerUnitId")
    if (owner != owners.first() || unitToShard[owner] != shardId) {
        truthFail("published function owner differs from its lowest candidate or shard")
    }
    val coalesced = owners.size > 1
    if (
        value.truthString("emissionKind") !=
        if (coalesced) COALESCED_EMISSION else SINGLE_EMISSION
    ) {
        truthFail("published function emission kind contradicts its ownership candidates")
    }
    val population = value.truthString("population")
    val reason = value.truthElement("reasonCode")
    when (population) {
        "scored" -> if (reason !is JsonNull) {
            truthFail("scored published function has an exclusion reason")
        }
        "excluded" -> {
            if (reason !is JsonPrimitive || !reason.isString || reason.content != DWARF_ONLY_REASON) {
                truthFail("excluded published function has the wrong reason")
            }
            if (coalesced) truthFail("published function contains the coalesced DWARF-only contradiction")
        }
        else -> truthFail("published function has an invalid population")
    }
}

private fun validatePublishedNonEmitted(
    value: JsonObject,
    shardId: String,
    unitToShard: Map<String, String>,
    limits: FullTreeFunctionTruthLimits,
): Long {
    if (
        value.keys != setOf(
            "aliases",
            "declarations",
            "id",
            "observationDieOffsets",
            "observationIds",
            "ownerUnitId",
            "population",
            "reasonCode",
        ) ||
        value.truthString("population") != "unobservable" ||
        value.truthString("reasonCode") !in setOf(INLINE_REASON, DEFINITION_REASON, SELECTED_REASON)
    ) {
        truthFail("published non-emitted function fields or policy classification differ")
    }
    val aliases = value.truthArray("aliases")
    validateTruthAliases(aliases, limits)
    val declarations = value.truthArray("declarations")
    validateTruthDeclarations(declarations, limits)
    val owner = value.truthString("ownerUnitId")
    if (unitToShard[owner] != shardId) {
        truthFail("published non-emitted function owner differs from its shard")
    }
    val observationIds = value.truthArray("observationIds").mapIndexed { index, raw ->
        (raw as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: truthFail("published non-emitted observation identity $index is not a string")
    }
    if (observationIds.isEmpty()) truthFail("published non-emitted function has no observations")
    observationIds.zipWithNext().forEach { (left, right) ->
        if (FULL_TREE_CODE_POINT_ORDER.compare(left, right) >= 0) {
            truthFail("published non-emitted observation identities are not strictly ordered")
        }
    }
    var previousDie: FunctionTruthDieKey? = null
    val dieOffsets = value.truthArray("observationDieOffsets")
    if (dieOffsets.isEmpty()) truthFail("published non-emitted function has no DIE observations")
    dieOffsets.forEachIndexed { index, raw ->
        val locator = raw as? JsonObject
            ?: truthFail("published non-emitted DIE locator $index is not an object")
        if (locator.keys != setOf("dieOffset", "unitId")) {
            truthFail("published non-emitted DIE locator fields differ")
        }
        val unitId = locator.truthString("unitId")
        if (unitId !in unitToShard) {
            truthFail("published non-emitted DIE locator is outside the authenticated inventory")
        }
        val current = FunctionTruthDieKey(
            unitId,
            parseCanonicalAddress(locator.truthString("dieOffset"), "published non-emitted DIE offset"),
        )
        val priorDie = previousDie
        if (priorDie != null && priorDie >= current) {
            truthFail("published non-emitted DIE locators are not strictly ordered")
        }
        previousDie = current
    }
    val aliasNames = aliases.map { raw -> (raw as JsonObject).truthString("name") }
    val expectedIdentifier = value.truthString("id")
    declarations.forEach { raw ->
        val declaration = raw as JsonObject
        val preimage = canonicalEntityBytes(
            JsonObject(
                mapOf(
                    "aliasNames" to JsonArray(aliasNames.map(::JsonPrimitive)),
                    "declaration" to JsonObject(declaration.filterKeys { it != "unitSourcePath" }),
                ),
            ),
            limits,
        )
        val prefix = MessageDigest.getInstance("SHA-256").digest(preimage).copyOf(16).truthHex()
        if (expectedIdentifier != "non-emitted-function-$prefix") {
            truthFail("published non-emitted identity differs from its declaration and aliases")
        }
    }
    return dieOffsets.size.toLong()
}

private fun validateTruthDeclarations(values: JsonArray, limits: FullTreeFunctionTruthLimits) {
    if (values.isEmpty()) truthFail("published function has no declarations")
    var previous: ByteArray? = null
    values.forEachIndexed { index, raw ->
        val declaration = raw as? JsonObject
            ?: truthFail("published function declaration $index is not an object")
        if (
            !declaration.keys.containsAll(
                setOf("sourcePath", "externalPathSha256", "line", "column", "fileIndex", "unitSourcePath"),
            )
        ) {
            truthFail("published function declaration fields are incomplete")
        }
        val canonical = canonicalEntityBytes(declaration, limits)
        val prior = previous
        if (prior != null && compareUnsignedBytes(prior, canonical) >= 0) {
            truthFail("published function declarations are not strictly canonical-byte ordered")
        }
        previous = canonical
    }
}

private fun validateTruthAliases(values: JsonArray, limits: FullTreeFunctionTruthLimits) {
    if (values.isEmpty()) truthFail("published function has no aliases")
    var previousName: String? = null
    values.forEachIndexed { index, raw ->
        val alias = raw as? JsonObject ?: truthFail("truth alias $index is not an object")
        if (alias.keys != setOf("evidence", "name")) truthFail("truth alias fields differ")
        val name = alias.truthString("name")
        if (previousName != null && FULL_TREE_CODE_POINT_ORDER.compare(previousName, name) >= 0) {
            truthFail("truth aliases are not strictly name ordered")
        }
        previousName = name
        var previousEvidence: ByteArray? = null
        val evidenceValues = alias.truthArray("evidence")
        if (evidenceValues.isEmpty()) truthFail("truth alias has no evidence")
        evidenceValues.forEach { evidence ->
            val objectValue = evidence as? JsonObject ?: truthFail("truth alias evidence is not an object")
            if (objectValue.keys != setOf("kind", "locator", "unitId")) {
                truthFail("truth alias evidence fields differ")
            }
            val kind = objectValue.truthString("kind")
            if (kind !in setOf("dwarf-subprogram", "elf-symbol")) {
                truthFail("truth alias evidence kind differs")
            }
            if (objectValue.truthString("locator").isEmpty()) truthFail("truth alias evidence locator is empty")
            val unitId = objectValue.truthElement("unitId")
            if (
                (kind == "elf-symbol" && unitId !is JsonNull) ||
                (kind == "dwarf-subprogram" &&
                    (unitId !is JsonPrimitive || !unitId.isString || unitId.content.isEmpty()))
            ) {
                truthFail("truth alias evidence unit binding contradicts its kind")
            }
            val canonical = canonicalEntityBytes(
                objectValue,
                limits,
            )
            val previous = previousEvidence
            if (previous != null && compareUnsignedBytes(previous, canonical) >= 0) {
                truthFail("truth alias evidence is not strictly canonical-byte ordered")
            }
            previousEvidence = canonical
        }
    }
}

private data class FileDigest(val sha256: String, val bytes: Long)

private fun writeCanonicalFile(
    path: Path,
    maximumBytes: Long,
    write: (FunctionTruthCanonicalWriter) -> Unit,
): FileDigest {
    if (maximumBytes <= 0L) truthFail("function-truth file byte bound is invalid")
    return try {
        FileChannel.open(
            path,
            setOf<OpenOption>(
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS,
            ),
            PosixFilePermissions.asFileAttribute(PRIVATE_FILE_PERMISSIONS),
        ).use { channel ->
            val bounded = FunctionTruthDigestingOutputStream(
                Channels.newOutputStream(channel),
                maximumBytes,
            )
            val buffered = BufferedOutputStream(bounded, OUTPUT_BUFFER_BYTES)
            try {
                val writer = FunctionTruthCanonicalWriter(buffered)
                write(writer)
                writer.requireFinished()
                buffered.flush()
                channel.force(true)
                bounded.finish()
            } finally {
                buffered.close()
            }
        }
    } catch (failure: Throwable) {
        runCatching { Files.deleteIfExists(path) }.exceptionOrNull()?.let(failure::addSuppressed)
        throw failure
    }
}

private fun writeMaterializedFile(path: Path, bytes: ByteArray) {
    try {
        FileChannel.open(
            path,
            setOf<OpenOption>(
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS,
            ),
            PosixFilePermissions.asFileAttribute(PRIVATE_FILE_PERMISSIONS),
        ).use { channel ->
            var offset = 0
            while (offset < bytes.size) {
                val buffer = java.nio.ByteBuffer.wrap(bytes, offset, bytes.size - offset)
                while (buffer.hasRemaining()) {
                    val written = channel.write(buffer)
                    if (written <= 0) truthFail("function-truth index write made no progress")
                    offset += written
                }
            }
            channel.force(true)
        }
    } catch (failure: Throwable) {
        runCatching { Files.deleteIfExists(path) }.exceptionOrNull()?.let(failure::addSuppressed)
        throw failure
    }
}

private class FunctionTruthDigestingOutputStream(
    output: OutputStream,
    private val maximumBytes: Long,
) : FilterOutputStream(output) {
    private val digest = MessageDigest.getInstance("SHA-256")
    private var count = 0L
    private var finished = false

    override fun write(value: Int) {
        requireCapacity(1L)
        out.write(value)
        digest.update(value.toByte())
        count++
    }

    override fun write(bytes: ByteArray, offset: Int, length: Int) {
        if (offset < 0 || length < 0 || offset > bytes.size - length) throw IndexOutOfBoundsException()
        requireCapacity(length.toLong())
        out.write(bytes, offset, length)
        digest.update(bytes, offset, length)
        count += length.toLong()
    }

    fun finish(): FileDigest {
        if (finished) truthFail("function-truth output digest was already finalized")
        finished = true
        if (count <= 0L) truthFail("function-truth output file is empty")
        return FileDigest(digest.digest().truthHex(), count)
    }

    private fun requireCapacity(additional: Long) {
        if (additional < 0L || count > maximumBytes - additional) {
            truthFail("canonical function-truth JSON exceeds its byte bound")
        }
    }
}

private class FunctionTruthCanonicalWriter(private val output: OutputStream) {
    private var fields = 0
    private var arrayValues = 0
    private var finished = false

    fun startObject() = writeAscii("{\n")

    fun field(name: String) {
        if (finished) truthFail("canonical function-truth writer is already finished")
        if (fields++ > 0) writeAscii(",\n")
        writeSpaces(2)
        writeAscii("\"$name\": ")
    }

    fun value(canonical: ByteArray) = writeCanonicalValue(canonical, 2, false)

    fun startArray() {
        arrayValues = 0
    }

    fun arrayValue(canonical: ByteArray) {
        if (arrayValues++ == 0) writeAscii("[\n") else writeAscii(",\n")
        writeCanonicalValue(canonical, 4, true)
    }

    fun endArray() {
        if (arrayValues == 0) writeAscii("[]") else writeAscii("\n  ]")
    }

    fun endObject() {
        writeAscii("\n}\n")
        finished = true
    }

    fun requireFinished() {
        if (!finished) truthFail("canonical function-truth writer did not finish its object")
    }

    private fun writeCanonicalValue(bytes: ByteArray, indentation: Int, indentFirst: Boolean) {
        if (bytes.isEmpty() || bytes.last() != '\n'.code.toByte()) {
            truthFail("canonical function-truth value is malformed")
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

private data class NonEmittedIdentity(
    val prefix: ByteArray,
    val fullDigest: ByteArray,
    val preimage: ByteArray,
    val identifier: String,
)

private fun nonEmittedIdentity(
    record: JsonObject,
    limits: FullTreeFunctionTruthLimits,
): NonEmittedIdentity {
    val declaration = record.truthObject("declaration")
    val normalizedDeclaration = JsonObject(declaration.filterKeys { it != "unitSourcePath" })
    val aliasNames = record.truthArray("aliases").mapIndexed { index, raw ->
        val alias = raw as? JsonObject ?: truthFail("non-emitted identity alias $index is not an object")
        alias.truthString("name")
    }.sortedWith(FULL_TREE_CODE_POINT_ORDER)
    val preimage = canonicalEntityBytes(
        JsonObject(
            mapOf(
                "aliasNames" to JsonArray(aliasNames.map(::JsonPrimitive)),
                "declaration" to normalizedDeclaration,
            ),
        ),
        limits,
    )
    val full = MessageDigest.getInstance("SHA-256").digest(preimage)
    val prefix = full.copyOf(16)
    return NonEmittedIdentity(
        prefix,
        full,
        preimage,
        "non-emitted-function-${prefix.truthHex()}",
    )
}

private fun streamingLimits(
    maximumBytes: Long,
    maximumEntities: Long,
    limits: FullTreeFunctionTruthLimits,
): FullTreeCanonicalStreamingLimits {
    if (maximumBytes <= 0L) truthFail("streamed function-truth input is empty")
    return FullTreeCanonicalStreamingLimits(
        maximumInputBytes = maximumBytes,
        maximumTokens = limits.maximumTokensPerInput,
        maximumEntities = maxOf(1L, maximumEntities),
        maximumEntityBytes = limits.maximumEntityBytes,
        maximumEntityNodes = limits.maximumEntityNodes,
        maximumDepth = 128,
        maximumStringBytes = limits.maximumStringBytes,
        maximumTotalStringBytes = min(maximumBytes, limits.maximumTotalStringBytesPerInput),
        maximumNumberCharacters = 256,
    )
}

private fun parseCanonicalEntity(
    bytes: ByteArray,
    limits: FullTreeFunctionTruthLimits,
    label: String,
): JsonObject = try {
    OracleJson.parseCanonical(bytes, entityJsonLimits(limits)) as? JsonObject
        ?: truthFail("$label is not an object")
} catch (failure: FullTreeFunctionTruthException) {
    throw failure
} catch (failure: Exception) {
    throw FullTreeFunctionTruthException("$label is not bounded canonical JSON", failure)
}

private fun canonicalEntityBytes(
    value: JsonElement,
    limits: FullTreeFunctionTruthLimits,
): ByteArray = try {
    OracleJson.canonicalBytes(value, entityJsonLimits(limits))
} catch (failure: Exception) {
    throw FullTreeFunctionTruthException("function-truth entity exceeds strict JSON bounds", failure)
}

private fun entityJsonLimits(limits: FullTreeFunctionTruthLimits): StrictJsonLimits = StrictJsonLimits(
    maximumInputBytes = limits.maximumEntityBytes,
    maximumCanonicalBytes = limits.maximumEntityBytes,
    maximumDepth = 128,
    maximumNodes = limits.maximumEntityNodes,
    maximumStringBytes = limits.maximumStringBytes,
    maximumTotalStringBytes = limits.maximumEntityBytes,
    maximumNumberCharacters = 256,
)

private fun canonicalControlBytes(
    value: JsonElement,
    limits: FullTreeFunctionTruthLimits,
): ByteArray = try {
    val maximum = limits.observationRun.maximumControlArtifactBytes
    OracleJson.canonicalBytes(
        value,
        StrictJsonLimits(
            maximumInputBytes = maximum,
            maximumCanonicalBytes = maximum,
            maximumDepth = 128,
            maximumNodes = 1_000_000,
            maximumStringBytes = min(maximum, 1024 * 1024),
            maximumTotalStringBytes = maximum,
            maximumNumberCharacters = 256,
        ),
    )
} catch (failure: Exception) {
    throw FullTreeFunctionTruthException("function-truth index exceeds strict JSON bounds", failure)
}

private fun JsonObject.truthElement(name: String): JsonElement = this[name]
    ?: truthFail("function-truth JSON field $name is absent")

private fun JsonObject.truthObject(name: String): JsonObject = truthElement(name) as? JsonObject
    ?: truthFail("function-truth JSON field $name is not an object")

private fun JsonObject.truthArray(name: String): JsonArray = truthElement(name) as? JsonArray
    ?: truthFail("function-truth JSON field $name is not an array")

private fun JsonObject.truthString(name: String): String {
    val value = truthElement(name) as? JsonPrimitive
        ?: truthFail("function-truth JSON field $name is not a string")
    if (!value.isString) truthFail("function-truth JSON field $name is not a string")
    return value.content
}

private fun JsonObject.truthLong(name: String): Long {
    val value = truthElement(name) as? JsonPrimitive
        ?: truthFail("function-truth JSON field $name is not an integer")
    if (value.isString || value.booleanOrNull != null) {
        truthFail("function-truth JSON field $name is not an integer")
    }
    return value.longOrNull ?: truthFail("function-truth JSON field $name is outside the Long range")
}

private fun parseCanonicalAddress(value: String, label: String): ULong {
    if (!value.matches(CANONICAL_ADDRESS)) truthFail("$label is not canonical")
    return try {
        value.substring(2).toULong(16)
    } catch (failure: NumberFormatException) {
        throw FullTreeFunctionTruthException("$label is outside the unsigned 64-bit range", failure)
    }
}

private fun canonicalAddress(value: ULong): String = "0x${value.toString(16)}"

private fun unsignedKey(value: ULong): ByteArray = ByteArray(8) { index ->
    ((value shr ((7 - index) * 8)) and 0xffuL).toByte()
}

private fun unsignedValue(bytes: ByteArray): ULong {
    if (bytes.size != 8) truthFail("SQLite RVA key does not have unsigned 64-bit width")
    var result = 0uL
    bytes.forEach { byte -> result = (result shl 8) or (byte.toInt() and 0xff).toULong() }
    return result
}

private fun compareUnsignedBytes(left: ByteArray, right: ByteArray): Int {
    val length = min(left.size, right.size)
    for (index in 0 until length) {
        val difference = (left[index].toInt() and 0xff) - (right[index].toInt() and 0xff)
        if (difference != 0) return difference
    }
    return left.size.compareTo(right.size)
}

private fun isThunkName(name: String): Boolean =
    name.startsWith("_ZTh") || name.startsWith("_ZTv") || name.startsWith("_ZTc")

private fun requireSha256(value: String, label: String) {
    if (!value.matches(SHA256)) truthFail("$label SHA-256 is invalid")
}

private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).truthHex()

private fun ByteArray.truthHex(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private fun checkedAdd(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeFunctionTruthException("function-truth $label count exceeds the supported range", failure)
}

private fun pathsOverlap(left: Path, right: Path): Boolean = left.startsWith(right) || right.startsWith(left)

private fun directoryIdentity(path: Path, label: String): Any {
    val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
        truthFail("$label must be an identified real directory")
    }
    return attributes.fileKey()
}

private fun fileIdentity(path: Path, label: String): Any {
    val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
        truthFail("$label must be an identified regular file")
    }
    return attributes.fileKey()
}

private fun requireDirectoryIdentity(path: Path, expected: Any, label: String) {
    if (directoryIdentity(path, label) != expected) truthFail("$label changed identity")
}

private fun requireFileIdentity(path: Path, expected: Any, label: String) {
    if (fileIdentity(path, label) != expected) truthFail("$label changed identity")
}

private fun forceDirectory(path: Path) {
    FileChannel.open(path, StandardOpenOption.READ).use { it.force(true) }
}

private inline fun <T> translateTruthFailures(action: () -> T): T = try {
    action()
} catch (failure: FullTreeFunctionTruthException) {
    throw failure
} catch (failure: Exception) {
    throw FullTreeFunctionTruthException("cannot reconcile full-tree function truth", failure)
}

private fun truthFail(message: String): Nothing = throw FullTreeFunctionTruthException(message)

private const val SQLITE_PAGE_BYTES = 4096L
private const val SQLITE_APPLICATION_ID = 0x44434654
private const val SQLITE_SCHEMA_VERSION = 1
private const val OUTPUT_BUFFER_BYTES = 1024 * 1024
private const val PUBLICATION_CHECKPOINT_FILES = 64
private const val MODELED_ENTITY_RESIDENT_COPIES = 2L
private const val MODELED_FIXED_RESIDENT_BYTES = 96L * 1024L * 1024L
private const val OUTPUTS_DIRECTORY = "outputs"
private const val SHARDS_DIRECTORY = "shards"
private const val INDEX_FILE = "index.json"
private const val EXCLUSIONS_FILE = "exclusions.json"
private const val ELF_ONLY_REASON = "elf-no-source-aligned-dwarf"
private const val DWARF_ONLY_REASON = "dwarf-rva-without-elf-function"
private const val INLINE_REASON = "inline-no-emitted-range"
private const val DEFINITION_REASON = "definition-no-emitted-range"
private const val SELECTED_REASON = "comdat-or-odr-selected-elsewhere"
private const val SINGLE_EMISSION = "single-definition"
private const val COALESCED_EMISSION = "coalesced-odr-or-comdat"
private const val FROZEN_CONFIGURATION_SHA256 =
    "17c61e43524b98a215075b82fa50732d6d8f50d883dce235e511731612da04e5"
private val SHA256 = Regex("[0-9a-f]{64}")
private val CANONICAL_ADDRESS = Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})")
private val PRIVATE_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
private val READ_ONLY_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("r-x------")
private val PRIVATE_FILE_PERMISSIONS: Set<PosixFilePermission> = EnumSet.of(
    PosixFilePermission.OWNER_READ,
    PosixFilePermission.OWNER_WRITE,
)
private val READ_ONLY_FILE_PERMISSIONS: Set<PosixFilePermission> =
    EnumSet.of(PosixFilePermission.OWNER_READ)
private val ELF_INDEX_FIELDS = listOf(
    "artifacts",
    "counts",
    "externalFunctions",
    "functions",
    "image",
    "oracle",
    "schemaVersion",
)
private val OBSERVATION_FIELDS = listOf(
    "counts",
    "emitted",
    "nonEmitted",
    "oracle",
    "schemaVersion",
    "shard",
)
private val TRUTH_SHARD_FIELDS = listOf(
    "counts",
    "functions",
    "nonEmitted",
    "oracle",
    "schemaVersion",
    "shard",
)
private val EXCLUSION_FIELDS = listOf("functions", "oracle", "reasonCode", "schemaVersion")
private const val EMITTED_MERGE_SQL =
    "SELECT u.rva, e.payload, d.payload " +
        "FROM all_rva u " +
        "LEFT JOIN elf e ON e.rva=u.rva " +
        "LEFT JOIN emitted d ON d.rva=u.rva " +
        "ORDER BY u.rva, d.shard_id"
private const val NON_EMITTED_MERGE_SQL =
    "SELECT i.prefix, i.full_digest, i.identity_payload, o.observation_id, o.payload " +
        "FROM non_emitted_identity i " +
        "JOIN non_emitted_observation o ON o.prefix=i.prefix " +
        "ORDER BY i.prefix, o.observation_id"
private val POLICY = JsonObject(
    mapOf(
        "emittedIdentity" to JsonPrimitive("one-record-per-rva"),
        "id" to JsonPrimitive("full-tree-function-truth"),
        "nonEmissionPolicy" to JsonPrimitive(
            "inline-or-definition-without-range-and-emitted-alias-reconciliation",
        ),
        "nonEmittedIdentity" to JsonPrimitive("declaration-and-alias-name-sha256-prefix-128"),
        "ownerSelection" to JsonPrimitive("lowest-source-aligned-unit-id"),
        "elfOnlyPopulation" to JsonPrimitive("excluded-elf-no-source-aligned-dwarf"),
        "version" to JsonPrimitive(2),
    ),
)
