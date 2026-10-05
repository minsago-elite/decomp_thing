package decompengine.oracle.fulltree

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxSyscallException
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.Comparator
import java.util.EnumMap
import java.util.TreeMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

internal class FullTreeFunctionTruthV3Exception(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

internal data class FullTreeFunctionTruthV3NestedScratchPlan(
    val maximumScratchBytes: Long,
    val maximumOutputBytes: Long,
)

/**
 * Estimate simultaneously live allocations before decoding a shard: four observation-sized copies
 * cover canonical input plus decoded maps/arrays and reconciliation views; three truth-sized copies
 * cover decoded function rows and row projection; three projected-output copies cover the new JSON
 * graph, canonical encoder and digest/write buffers. Two control copies cover retained run/index
 * snapshots and per-shard index records; the full-run emitted-RVA set is charged once separately.
 * Persistent workspace files are charged to the disk bound.
 */
internal fun fullTreeFunctionTruthV3ModeledWorkingSetBytes(
    observationBytes: Long,
    legacyTruthBytes: Long,
    projectedShardBytes: Long,
    retainedControlBytes: Long,
    retainedSingleCopyBytes: Long = 0L,
): Long {
    require(observationBytes > 0L && legacyTruthBytes >= 0L && projectedShardBytes > 0L &&
        retainedControlBytes >= 0L && retainedSingleCopyBytes >= 0L)
    return Math.addExact(
        96L * 1024L * 1024L,
        Math.addExact(
            Math.addExact(Math.multiplyExact(observationBytes, 4L), Math.multiplyExact(legacyTruthBytes, 3L)),
            Math.addExact(
                Math.addExact(Math.multiplyExact(projectedShardBytes, 3L), Math.multiplyExact(retainedControlBytes, 2L)),
                retainedSingleCopyBytes,
            ),
        ),
    )
}

internal fun fullTreeFunctionTruthV3AdmitWorkingSet(
    observationBytes: Long,
    legacyTruthBytes: Long,
    projectedShardBytes: Long,
    retainedControlBytes: Long,
    maximumRetainedBytes: Long,
    retainedSingleCopyBytes: Long = 0L,
): Long {
    require(maximumRetainedBytes > 0L)
    val modeled = fullTreeFunctionTruthV3ModeledWorkingSetBytes(
        observationBytes,
        legacyTruthBytes,
        projectedShardBytes,
        retainedControlBytes,
        retainedSingleCopyBytes,
    )
    require(modeled <= maximumRetainedBytes) { "truth-v3 combined retained-working-set bound exceeded" }
    return modeled
}

/** Divide one shared V3 allowance between the legacy truth engine's live scratch and staged output. */
internal fun fullTreeFunctionTruthV3NestedScratchPlan(
    remainingBytes: Long,
    databaseMinimumBytes: Long,
    maximumScratchBytes: Long,
    maximumOutputBytes: Long,
): FullTreeFunctionTruthV3NestedScratchPlan {
    require(remainingBytes > 0L && databaseMinimumBytes > 0L && maximumScratchBytes >= databaseMinimumBytes && maximumOutputBytes > 0L)
    require(databaseMinimumBytes < remainingBytes) { "truth-v3 shared scratch cannot reserve a database and nonempty output" }
    val output = minOf(maximumOutputBytes, remainingBytes - databaseMinimumBytes)
    val scratch = minOf(maximumScratchBytes, remainingBytes - output)
    require(output > 0L && scratch >= databaseMinimumBytes && scratch + output <= remainingBytes)
    return FullTreeFunctionTruthV3NestedScratchPlan(scratch, output)
}

/** Reserve real SQLite capacity when a V3 rederivation narrows the nested V2 scratch ceiling. */
internal fun fullTreeFunctionTruthV3NestedObservationDwarfScratchBytes(
    availableScratchBytes: Long,
    preparedOutputBytes: Long,
    configuredOutputBytes: Long,
    configuredDatabaseBytes: Long,
    configuredDwarfScratchBytes: Long,
): Long {
    require(availableScratchBytes > 0L && preparedOutputBytes >= 0L && configuredOutputBytes > 0L &&
        configuredDatabaseBytes > 0L && configuredDwarfScratchBytes > 0L)
    val sqlitePageBytes = FULL_TREE_FUNCTION_OBSERVATION_SQLITE_PAGE_BYTES
    val outputReservation = minOf(configuredOutputBytes, FullTreeFunctionObservationsV2.MAXIMUM_CANONICAL_BYTES)
    val desiredDatabaseReservation = minOf(
        configuredDatabaseBytes,
        maxOf(sqlitePageBytes * 64L, availableScratchBytes / 4L),
    )
    val availableForDwarf = availableScratchBytes - preparedOutputBytes - outputReservation - desiredDatabaseReservation
    require(availableForDwarf > sqlitePageBytes) {
        "truth-v3 shared scratch cannot reserve observation output, decompression space, and SQLite pages"
    }
    return minOf(configuredDwarfScratchBytes, availableForDwarf)
}

internal fun fullTreeFunctionTruthV3AccumulateShardBudget(
    previousWallNanos: Long,
    previousCpuNanos: Long,
    phaseWallNanos: Long,
    phaseCpuNanos: Long,
    maximumWallNanos: Long,
    maximumCpuNanos: Long,
): Pair<Long, Long> {
    require(previousWallNanos >= 0L && previousCpuNanos >= 0L && phaseWallNanos >= 0L && phaseCpuNanos >= 0L)
    require(maximumWallNanos > 0L && maximumCpuNanos > 0L)
    val wall = Math.addExact(previousWallNanos, phaseWallNanos)
    val cpu = Math.addExact(previousCpuNanos, phaseCpuNanos)
    require(wall <= maximumWallNanos && cpu <= maximumCpuNanos) {
        "truth-v3 cumulative per-shard wall-clock or CPU bound exceeded"
    }
    return wall to cpu
}

/** Shares one cumulative wall/CPU interval across nested shard callbacks. */
internal class FullTreeFunctionTruthV3ShardPhaseLedger(
    private val maximumWallNanos: Long,
    private val maximumCpuNanos: Long,
    private val wallClock: () -> Long = System::nanoTime,
    private val cpuClock: () -> Long = ::truthV3ProcessCpuNanos,
) : FullTreeOracleShardPhaseObserver {
    private data class ActivePhase(val wallStart: Long, val cpuStart: Long, var depth: Int)

    private val active = HashMap<String, ActivePhase>()
    private val completed = HashMap<String, Pair<Long, Long>>()

    init {
        require(maximumWallNanos > 0L && maximumCpuNanos > 0L)
    }

    @Synchronized
    override fun beginShardPhase(shardId: String) {
        val phase = active[shardId]
        if (phase == null) active[shardId] = ActivePhase(wallClock(), cpuClock(), 1)
        else phase.depth = Math.addExact(phase.depth, 1)
    }

    @Synchronized
    override fun endShardPhase(shardId: String) {
        val phase = active[shardId] ?: throw IllegalStateException("truth-v3 shard phase was not started for $shardId")
        if (phase.depth > 1) {
            phase.depth -= 1
            return
        }
        active.remove(shardId)
        val wall = Math.subtractExact(wallClock(), phase.wallStart)
        val cpu = Math.subtractExact(cpuClock(), phase.cpuStart)
        val prior = completed[shardId] ?: (0L to 0L)
        val total = fullTreeFunctionTruthV3AccumulateShardBudget(
            prior.first,
            prior.second,
            wall,
            cpu,
            maximumWallNanos,
            maximumCpuNanos,
        )
        completed[shardId] = total
    }

    @Synchronized
    fun activeShardCount(): Int = active.size
}

internal fun fullTreeFunctionTruthV3CombinedEntityCount(
    emittedTruthEntities: Long,
    sourceCensusEntities: Long,
    maximumEntities: Long,
): Long {
    require(emittedTruthEntities >= 0L && sourceCensusEntities >= 0L && maximumEntities > 0L)
    val combined = Math.addExact(emittedTruthEntities, sourceCensusEntities)
    require(combined <= maximumEntities) { "truth-v3 combined entity bound exceeded" }
    return combined
}

internal fun fullTreeFunctionTruthV3WorkingSetCeiling(
    configuredWorkingSetBytes: Long,
    authenticatedPerShardResidentBytes: Long,
): Long {
    require(configuredWorkingSetBytes > 0L && authenticatedPerShardResidentBytes > 0L)
    return minOf(configuredWorkingSetBytes, authenticatedPerShardResidentBytes)
}

internal fun fullTreeFunctionTruthV3AdmitShardWorkingSet(
    observationBytes: Long,
    truthBytes: Long,
    projectedBytes: Long,
    retainedControlBytes: Long,
    configuredWorkingSetBytes: Long,
    authenticatedPerShardResidentBytes: Long,
    retainedSingleCopyBytes: Long = 0L,
): Long = fullTreeFunctionTruthV3AdmitWorkingSet(
    observationBytes,
    truthBytes,
    projectedBytes,
    retainedControlBytes,
    fullTreeFunctionTruthV3WorkingSetCeiling(configuredWorkingSetBytes, authenticatedPerShardResidentBytes),
    retainedSingleCopyBytes,
)

internal fun fullTreeFunctionTruthV3CheckResidentBytes(
    currentBytes: Long,
    highWaterBytes: Long,
    wholeRunMaximumBytes: Long,
    activeShardMaximumBytes: Long? = null,
) {
    require(currentBytes >= 0L && highWaterBytes >= 0L && wholeRunMaximumBytes > 0L)
    if (currentBytes > wholeRunMaximumBytes || highWaterBytes > wholeRunMaximumBytes) {
        throw IllegalArgumentException("truth-v3 operation exceeded its authenticated whole-run resident-memory bound")
    }
    if (activeShardMaximumBytes != null) {
        require(activeShardMaximumBytes > 0L)
        if (currentBytes > activeShardMaximumBytes) {
            throw IllegalArgumentException("truth-v3 shard phase exceeded its authenticated per-shard resident-memory bound")
        }
    }
}

internal fun fullTreeFunctionTruthV3HasOnlyEmittedRvaLinks(
    linkedRvas: Iterable<String>,
    fullRunEmittedRvas: Set<String>,
): Boolean = linkedRvas.all(fullRunEmittedRvas::contains)

/** V3 adds a source census without changing the v2 emitted-RVA score population. */
internal data class FullTreeFunctionTruthV3Limits(
    val truth: FullTreeFunctionTruthLimits = FullTreeFunctionTruthLimits(),
    val observationV2: FullTreeFunctionObservationV2RunLimits = FullTreeFunctionObservationV2RunLimits(),
    val maximumOutputBytes: Long = 4L * 1024L * 1024L * 1024L,
    val maximumScratchBytes: Long = 16L * 1024L * 1024L * 1024L,
    val maximumRetainedWorkingSetBytes: Long = 1024L * 1024L * 1024L,
) {
    init {
        require(maximumOutputBytes in 1L..8L * 1024L * 1024L * 1024L)
        require(maximumScratchBytes in 1L..32L * 1024L * 1024L * 1024L)
        require(maximumRetainedWorkingSetBytes in 128L * 1024L * 1024L..2L * 1024L * 1024L * 1024L)
    }
}

internal fun fullTreeFunctionTruthV3SharedScratchBound(limits: FullTreeFunctionTruthV3Limits): Long =
    limits.maximumScratchBytes

internal fun fullTreeFunctionTruthV3HasDatabaseScratchCapacity(limits: FullTreeFunctionTruthV3Limits): Boolean =
    fullTreeFunctionTruthV3SharedScratchBound(limits) >= limits.truth.maximumDatabaseBytes

/**
 * Peak scratch while publishing the private observation adapter. `currentScratchBytes` already
 * includes the prepared adapter payloads; publication makes one additional staged payload copy
 * and bounded control artifacts. Keep the model explicit so callers reserve only live files.
 */
internal fun fullTreeFunctionTruthV3AdapterPublishScratchPeakBytes(
    currentScratchBytes: Long,
    preparedPayloadBytes: Long,
    maximumControlArtifactBytes: Long,
    shardCount: Int,
    maximumScratchBytes: Long,
): Long {
    require(currentScratchBytes >= 0L && preparedPayloadBytes >= 0L && maximumControlArtifactBytes > 0L && shardCount > 0)
    require(maximumScratchBytes > 0L && currentScratchBytes >= preparedPayloadBytes) {
        "truth-v3 prepared adapter bytes are missing from scratch accounting"
    }
    val stagedPayloadAndControls = Math.addExact(
        preparedPayloadBytes,
        Math.multiplyExact(Math.addExact(shardCount.toLong(), 2L), maximumControlArtifactBytes),
    )
    val peak = Math.addExact(currentScratchBytes, stagedPayloadAndControls)
    require(peak <= maximumScratchBytes) { "truth-v3 observation adapter publication exceeds its remaining scratch bound" }
    return peak
}

internal fun fullTreeFunctionTruthV3AdmitEmittedRvaCollectionWorkingSet(
    truthShardBytes: Long,
    retainedControlBytes: Long,
    retainedEmittedRvaBytes: Long,
    configuredWorkingSetBytes: Long,
    authenticatedPerShardResidentBytes: Long,
): Long = fullTreeFunctionTruthV3AdmitShardWorkingSet(
    observationBytes = 1L,
    truthBytes = truthShardBytes,
    projectedBytes = 1L,
    retainedControlBytes = retainedControlBytes,
    configuredWorkingSetBytes = configuredWorkingSetBytes,
    authenticatedPerShardResidentBytes = authenticatedPerShardResidentBytes,
    retainedSingleCopyBytes = retainedEmittedRvaBytes,
)

internal data class FullTreeFunctionTruthV3Counts(
    val functions: FullTreeFunctionTruthCounts,
    val sourceEntities: Long,
    val sourceEntitiesByKind: Map<FullTreeSourceEntityKind, Long>,
    val sourceEntitiesByObservability: Map<FullTreeIdentityObservability, Long>,
    val sourceEntitiesByDisposition: Map<FullTreeDenominatorDisposition, Long>,
) {
    fun toJson(): JsonObject = JsonObject(buildMap {
        putAll(functions.toJson())
        put("sourceEntities", JsonPrimitive(sourceEntities))
        put("sourceEntitiesByKind", countObject(sourceEntitiesByKind.mapKeys { it.key.wireValue }))
        put("sourceEntitiesByObservability", countObject(sourceEntitiesByObservability.mapKeys { it.key.wireValue }))
        put("sourceEntitiesByDenominatorDisposition", countObject(sourceEntitiesByDisposition.mapKeys { it.key.wireValue }))
    })
}

internal class FullTreeFunctionTruthV3Generation internal constructor(
    val root: Path,
    val index: JsonObject,
    val indexArtifactSha256: String,
    val indexSha256: String,
    val observationV2IndexArtifactSha256: String,
    val elfIndexArtifactSha256: String,
    val outputBytes: Long,
    val databaseHighWaterBytes: Long,
    val counts: FullTreeFunctionTruthV3Counts,
) {
    val authoritativeReleaseEvidence: Boolean = false
    val productionQualification: Boolean = false
    val downstreamScoringAuthorized: Boolean = false
}

internal data class FullTreeFunctionTruthV3Validation(
    val indexArtifactSha256: String,
    val indexSha256: String,
    val observationV2IndexArtifactSha256: String,
    val elfIndexArtifactSha256: String,
    val outputBytes: Long,
    val databaseHighWaterBytes: Long,
    val counts: FullTreeFunctionTruthV3Counts,
    val rawInputsRederived: Boolean = true,
    val candidateBytesMatchedAtValidationBoundary: Boolean = true,
    val candidateLeaseRetained: Boolean = false,
    val downstreamScoringAuthorized: Boolean = false,
    val authoritativeReleaseEvidence: Boolean = false,
    val productionQualification: Boolean = false,
)

/**
 * Additive function-truth v3 API. Both entrypoints rederive observation-v2 from the rich artifact,
 * including the complete collision population, and rederive ELF/emitted-RVA truth through the
 * frozen v2 truth engine. The adapter below only projects already authenticated v2 emitted fields
 * into that engine's unchanged input contract; census rows never enter its score population.
 */
internal object FullTreeFunctionTruthSqliteV3 {
    const val SHARD_SCHEMA_NAME = "full-tree-function-truth-v3"
    const val INDEX_SCHEMA_NAME = "full-tree-function-truth-index-v3"
    const val POLICY_ID = "full-tree-function-truth"
    const val POLICY_VERSION = 3
    private const val V3_SHARD_ENVELOPE_BYTES = 64L * 1024L
    private const val V3_CONTROL_BASE_BYTES = 8L * 1024L
    private const val V3_SHARD_RECORD_CONTROL_BYTES = 512L
    private const val V3_FIXED_RETAINED_BYTES = 96L * 1024L * 1024L
    private const val V3_EMITTED_RVA_SET_ENTRY_BYTES = 96L

    val producerPolicy: JsonObject = JsonObject(
        mapOf(
            "candidateHashesProveIdentity" to JsonPrimitive(false),
            "identityReconciliation" to JsonPrimitive("full-run-anchor-claims-v1"),
            "maximumIdentityEdgesPerEntity" to JsonPrimitive(MAXIMUM_IDENTITY_EDGES_PER_ENTITY),
            "maximumReferenceChainEntries" to JsonPrimitive(
                FullTreeFunctionObservationProducerLimits().maximumReferenceChainEntries,
            ),
            "patternRelationsWithoutProof" to JsonPrimitive("unknown-null"),
            "emittedPopulation" to JsonPrimitive("one-function-row-per-emitted-rva"),
            "id" to JsonPrimitive(POLICY_ID),
            "inputObservationSchema" to JsonPrimitive(FullTreeFunctionObservationsV2.SCHEMA_NAME),
            "maximumCanonicalDocumentBytes" to JsonPrimitive(FullTreeFunctionObservationsV2.MAXIMUM_CANONICAL_BYTES),
            "maximumJsonNodes" to JsonPrimitive(FullTreeFunctionObservationsV2.MAXIMUM_JSON_NODES),
            "maximumOutputBytesCeiling" to JsonPrimitive(8L * 1024L * 1024L * 1024L),
            "maximumRetainedWorkingSetBytesCeiling" to JsonPrimitive(2L * 1024L * 1024L * 1024L),
            "maximumScratchBytesCeiling" to JsonPrimitive(32L * 1024L * 1024L * 1024L),
            "semanticAnchorCandidate" to JsonPrimitive("typed-source-tuple-v2-column-excluded"),
            "sourceEntityRowsAreScoreable" to JsonPrimitive(false),
            "sourceEntityId" to JsonPrimitive("artifact-unit-section-cu-die-kind-v1"),
            "sourceEntityRowsArePhysical" to JsonPrimitive(true),
            "version" to JsonPrimitive(POLICY_VERSION),
        ),
    )

    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256(
            listOf(
                "full-tree-function-exclusions",
                SHARD_SCHEMA_NAME,
                INDEX_SCHEMA_NAME,
            ),
            producerPolicy,
        )
    }

    fun generateAndPublish(
        richArtifact: Path,
        strippedArtifact: Path,
        inventoryPath: Path,
        elfFunctionIndex: Path,
        observationV2Root: Path,
        expectedObservationV2IndexArtifactSha256: String,
        scope: AuthenticatedFullTreeScope,
        scratchParent: Path,
        outputRoot: Path,
        limits: FullTreeFunctionTruthV3Limits = FullTreeFunctionTruthV3Limits(),
    ): FullTreeFunctionTruthV3Generation = runV3 {
        val deadline = V3RunDeadline.start(scope, limits)
        FullTreeOracleOperationCheckpoint.withCheckpoint(deadline::checkpoint, deadline) {
        deadline.checkpoint("truth-v3 generation entry")
        requireV3Sha(expectedObservationV2IndexArtifactSha256, "observation-v2 index artifact")
        validateV3ScopeAndLimits(scope, limits)
        val target = outputRoot.toAbsolutePath().normalize()
        requireV3OutputDisjoint(
            target,
            listOf(richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex, observationV2Root, scratchParent),
        )
        requireStableDirectory(scratchParent, "truth-v3 scratch parent")
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) v3Fail("truth-v3 output root already exists")

        val parent = target.parent ?: v3Fail("truth-v3 output root must name a parent directory")
        requireStableDirectory(parent, "truth-v3 output parent")
        V3RawInputGuards.open(richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex, limits).use { rawInputs ->
        V3Workspace.create(scratchParent).use { workspace ->
            val observationIdentity = V3StableTreeSnapshot.captureIdentity(
                observationV2Root,
                setOf("outputs", "checkpoints"),
                Math.addExact(Math.multiplyExact(limits.observationV2.run.maximumShards.toLong(), 2L), 2L),
                maximumScratchBound(limits),
                deadline::checkpoint,
                setOf("run.json", "index.json"),
            )
            val initialRun = authenticateObservationV2(
                observationV2Root, expectedObservationV2IndexArtifactSha256, richArtifact, inventoryPath,
                scope, workspace.root, limits, deadline,
            )
            observationIdentity.verifyIdentity(deadline::checkpoint)
            val observationSnapshot = snapshotObservationV2(
                observationV2Root, initialRun.binding, observationIdentity, workspace.root, limits, deadline,
            )
            val (legacyTruth, legacySnapshot, v2Run) = deriveLegacyAndCensus(
                richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex, observationSnapshot.root,
                expectedObservationV2IndexArtifactSha256, scope, workspace, initialRun, limits, deadline,
            )
            requireV3WorkspaceBound(workspace.root, limits)
            val publication = V3Publication.create(target, limits.maximumOutputBytes)
            try {
                val projection = composeV3Tree(
                    publication.staging,
                    legacySnapshot.root,
                    observationSnapshot.root,
                    v2Run,
                    legacyTruth,
                    scope,
                    workspace.root,
                    limits,
                    deadline,
                )
                requireV3WorkspaceBound(workspace.root, limits)
                legacySnapshot.verifyPrivateSnapshotUnchanged(deadline::checkpoint)
                revalidateLegacyTruth(
                    legacyTruth, legacySnapshot.root, richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex,
                    scope, workspace, v2Run.maximumWorkers, limits, deadline,
                )
                legacySnapshot.verifyPrivateSnapshotUnchanged(deadline::checkpoint)
                requireSameV2Reconciliation(
                    initialRun,
                    authenticateObservationV2(
                        observationSnapshot.root, expectedObservationV2IndexArtifactSha256, richArtifact, inventoryPath,
                        scope,
                        newObservationRevalidationScratch(workspace.root, observationSnapshot.root),
                        limits,
                        deadline,
                        aggregateScratchRoot = workspace.root,
                    ),
                )
                deadline.checkpoint("before committing truth-v3 publication")
                publication.commit(projection, deadline::checkpoint) {
                    rawInputs.verifyUnchanged("at truth-v3 publication boundary")
                    observationSnapshot.verifyOriginalUnchanged(deadline::checkpoint)
                    legacySnapshot.verifyOriginalUnchanged(deadline::checkpoint)
                }
                FullTreeFunctionTruthV3Generation(
                    root = target,
                    index = projection.index,
                    indexArtifactSha256 = projection.indexArtifactSha256,
                    indexSha256 = projection.indexSha256,
                    observationV2IndexArtifactSha256 = v2Run.binding.indexArtifactSha256,
                    elfIndexArtifactSha256 = legacyTruth.elfIndexArtifactSha256,
                    outputBytes = projection.outputBytes,
                    databaseHighWaterBytes = legacyTruth.databaseHighWaterBytes,
                    counts = projection.counts,
                )
            } finally {
                publication.close()
            }
        }
        }
        }
    }

    fun loadAndValidate(
        candidateRoot: Path,
        richArtifact: Path,
        strippedArtifact: Path,
        inventoryPath: Path,
        elfFunctionIndex: Path,
        observationV2Root: Path,
        expectedObservationV2IndexArtifactSha256: String,
        scope: AuthenticatedFullTreeScope,
        scratchParent: Path,
        limits: FullTreeFunctionTruthV3Limits = FullTreeFunctionTruthV3Limits(),
    ): FullTreeFunctionTruthV3Validation = runV3 {
        val deadline = V3RunDeadline.start(scope, limits)
        FullTreeOracleOperationCheckpoint.withCheckpoint(deadline::checkpoint, deadline) {
        deadline.checkpoint("truth-v3 validation entry")
        requireV3Sha(expectedObservationV2IndexArtifactSha256, "observation-v2 index artifact")
        validateV3ScopeAndLimits(scope, limits)
        val candidate = candidateRoot.toAbsolutePath().normalize()
        val candidateParent = candidate.parent
            ?: v3Fail("truth-v3 candidate root must name a parent directory")
        val (_, candidateParentIdentity) = requireStableDirectory(candidateParent, "truth-v3 candidate parent")
        requireV3OutputDisjoint(
            candidate,
            listOf(richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex, observationV2Root, scratchParent),
        )
        requireStableDirectory(scratchParent, "truth-v3 validation scratch parent")
        requireStableDirectory(candidate, "truth-v3 candidate root")
        V3RawInputGuards.open(richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex, limits).use { rawInputs ->
        V3Workspace.create(scratchParent).use { workspace ->
            val observationIdentity = V3StableTreeSnapshot.captureIdentity(
                observationV2Root,
                setOf("outputs", "checkpoints"),
                Math.addExact(Math.multiplyExact(limits.observationV2.run.maximumShards.toLong(), 2L), 2L),
                maximumScratchBound(limits),
                deadline::checkpoint,
                setOf("run.json", "index.json"),
            )
            val initialRun = authenticateObservationV2(
                observationV2Root, expectedObservationV2IndexArtifactSha256, richArtifact, inventoryPath,
                scope, workspace.root, limits, deadline,
            )
            observationIdentity.verifyIdentity(deadline::checkpoint)
            val observationSnapshot = snapshotObservationV2(
                observationV2Root, initialRun.binding, observationIdentity, workspace.root, limits, deadline,
            )
            val (legacyTruth, legacySnapshot, v2Run) = deriveLegacyAndCensus(
                richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex, observationSnapshot.root,
                expectedObservationV2IndexArtifactSha256, scope, workspace, initialRun, limits, deadline,
            )
            requireV3WorkspaceBound(workspace.root, limits)
            val derivedRoot = workspace.root.resolve("derived-truth-v3")
            Files.createDirectory(derivedRoot, PosixFilePermissions.asFileAttribute(V3_WRITABLE_DIRECTORY))
            val projection = composeV3Tree(
                derivedRoot, legacySnapshot.root, observationSnapshot.root, v2Run, legacyTruth, scope, workspace.root, limits,
                deadline,
            )
            requireV3WorkspaceBound(workspace.root, limits)
            legacySnapshot.verifyPrivateSnapshotUnchanged(deadline::checkpoint)
            val candidateSnapshot = snapshotCandidate(
                candidate, projection, workspace.root, scope, limits, deadline,
            )
            verifyV3Candidate(candidateSnapshot, projection, candidateParent, candidateParentIdentity)
            revalidateLegacyTruth(
                legacyTruth, legacySnapshot.root, richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex,
                    scope, workspace, v2Run.maximumWorkers, limits, deadline,
            )
            legacySnapshot.verifyPrivateSnapshotUnchanged(deadline::checkpoint)
            requireSameV2Reconciliation(
                initialRun,
                authenticateObservationV2(
                    observationSnapshot.root, expectedObservationV2IndexArtifactSha256, richArtifact, inventoryPath,
                    scope,
                    newObservationRevalidationScratch(workspace.root, observationSnapshot.root),
                    limits,
                    deadline,
                    aggregateScratchRoot = workspace.root,
                ),
            )
            verifyV3Candidate(candidateSnapshot, projection, candidateParent, candidateParentIdentity)
            candidateSnapshot.verifyOriginalUnchanged(deadline::checkpoint)
            rawInputs.verifyUnchanged("at truth-v3 candidate comparison boundary")
            observationSnapshot.verifyOriginalUnchanged(deadline::checkpoint)
            legacySnapshot.verifyOriginalUnchanged(deadline::checkpoint)
            FullTreeFunctionTruthV3Validation(
                indexArtifactSha256 = projection.indexArtifactSha256,
                indexSha256 = projection.indexSha256,
                observationV2IndexArtifactSha256 = v2Run.binding.indexArtifactSha256,
                elfIndexArtifactSha256 = legacyTruth.elfIndexArtifactSha256,
                outputBytes = projection.outputBytes,
                databaseHighWaterBytes = legacyTruth.databaseHighWaterBytes,
                counts = projection.counts,
            )
        }
        }
        }
    }

    private fun deriveLegacyAndCensus(
        richArtifact: Path,
        strippedArtifact: Path,
        inventoryPath: Path,
        elfFunctionIndex: Path,
        observationV2Root: Path,
        expectedObservationV2IndexArtifactSha256: String,
        scope: AuthenticatedFullTreeScope,
        workspace: V3Workspace,
        v2Run: FullTreeFunctionObservationV2RunPublication,
        limits: FullTreeFunctionTruthV3Limits,
        deadline: V3RunDeadline,
    ): Triple<FullTreeFunctionTruthGeneration, V3StableTreeSnapshot, FullTreeFunctionObservationV2RunPublication> {
        deadline.checkpoint("before projecting authenticated observation-v2 into the frozen truth input")
        val adapter = publishLegacyObservationAdapter(observationV2Root, v2Run, scope, workspace, limits, deadline)
        val truthLimits = effectiveTruthLimits(limits, workspace.root, reservePublishedOutput = true)
        val truthScratch = workspace.root.resolve("legacy-truth-scratch")
        Files.createDirectory(truthScratch, PosixFilePermissions.asFileAttribute(V3_WRITABLE_DIRECTORY))
        val truthRoot = workspace.root.resolve("legacy-truth")
        val legacyTruth = FullTreeFunctionTruthSqlite.generateAndPublish(
            richArtifact = richArtifact,
            strippedArtifact = strippedArtifact,
            inventoryPath = inventoryPath,
            elfFunctionIndex = elfFunctionIndex,
            observationRoot = adapter.root,
            expectedObservationIndexArtifactSha256 = adapter.indexArtifactSha256,
            scope = scope,
            scratchParent = truthScratch,
            outputRoot = truthRoot,
            maximumWorkers = v2Run.maximumWorkers,
            limits = truthLimits,
        )
        if (legacyTruth.observationIndexArtifactSha256 != adapter.indexArtifactSha256) {
            v3Fail("v3 emitted-RVA projection does not bind its authenticated observation adapter")
        }
        // Keep the caller-provided v2 index as the v3 provenance digest, never the adapter digest.
        if (v2Run.binding.indexArtifactSha256 != expectedObservationV2IndexArtifactSha256) {
            v3Fail("observation-v2 run changed during v3 derivation")
        }
        val pinnedLegacyTruth = snapshotLegacyTruthV3(legacyTruth, workspace.root, limits, deadline::checkpoint)
        return Triple(legacyTruth, pinnedLegacyTruth, v2Run)
    }

    /** Pin the exact frozen-v2 generation receipt bytes before any V3 projection reads them. */
    internal fun snapshotLegacyTruthV3(
        truth: FullTreeFunctionTruthGeneration,
        workspaceRoot: Path,
        limits: FullTreeFunctionTruthV3Limits,
        checkpoint: (String) -> Unit = {},
    ): V3StableTreeSnapshot {
        OracleSchemas.validate("full-tree-function-truth-index", truth.index)
        val indexBytes = canonicalV3Bytes(truth.index)
        val logicalIndex = JsonObject(truth.index.filterKeys { it != "indexSha256" })
        if (truth.indexSha256 != truth.index.v3String("indexSha256") ||
            OracleArtifacts.sha256(canonicalV3Bytes(logicalIndex)) != truth.indexSha256 ||
            OracleArtifacts.sha256(indexBytes) != truth.indexArtifactSha256
        ) {
            v3Fail("legacy truth generation receipt does not authenticate its frozen-v2 index")
        }
        val expected = TreeMap<String, V3ExpectedTreeMember>()
        expected["index.json"] = V3ExpectedTreeMember(indexBytes.size.toLong(), truth.indexArtifactSha256)
        fun addFile(record: JsonObject, expectedPath: String) {
            val path = record.v3String("path")
            if (path != expectedPath) v3Fail("legacy truth generation receipt has an unexpected member path")
            val member = V3ExpectedTreeMember(record.v3Long("bytes"), record.v3String("sha256"))
            requireV3Sha(member.sha256, "legacy truth member digest")
            if (member.bytes <= 0L || expected.put(path, member) != null) {
                v3Fail("legacy truth generation receipt repeats or empties a member")
            }
        }
        val shardRecords = truth.index.v3Array("shards")
        shardRecords.forEach { raw ->
            val record = raw as? JsonObject ?: v3Fail("legacy truth index shard receipt is not an object")
            val id = record.v3String("id")
            if (id.isBlank() || id.contains('/') || id.contains('\\') || id == "." || id == "..") {
                v3Fail("legacy truth index shard id is not a single safe path component")
            }
            addFile(record, "shards/$id.json")
        }
        val exclusion = truth.index.v3Object("exclusions")
        if (exclusion.v3String("id") != "elf-only-exclusions") {
            v3Fail("legacy truth index has an unexpected exclusions identity")
        }
        addFile(exclusion, "exclusions.json")
        val expectedBytes = expected.values.fold(0L) { total, member -> Math.addExact(total, member.bytes) }
        if (expectedBytes != truth.outputBytes) v3Fail("legacy truth generation receipt byte count does not reconcile")
        val maximumFiles = Math.addExact(shardRecords.size.toLong(), 2L)
        val identity = V3StableTreeSnapshot.captureIdentity(
            truth.root,
            setOf("shards"),
            maximumFiles,
            truth.outputBytes,
            checkpoint,
            setOf("index.json", "exclusions.json"),
        )
        if (identity.totalBytes != truth.outputBytes) {
            v3Fail("legacy truth tree size differs from its generation receipt")
        }
        reserveV3ScratchCapacity(workspaceRoot, identity.totalBytes, limits)
        val snapshot = identity.createSnapshot(
            truth.root,
            workspaceRoot.resolve("legacy-truth-pinned"),
            setOf("shards"),
            expected,
            checkpoint,
            truth.outputBytes,
        )
        checkV3Scratch(workspaceRoot, maximumScratchBound(limits))
        return snapshot
    }

    private fun authenticateObservationV2(
        observationV2Root: Path,
        expectedIndexSha256: String,
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        scratchParent: Path,
        limits: FullTreeFunctionTruthV3Limits,
        deadline: V3RunDeadline,
        aggregateScratchRoot: Path = scratchParent,
    ): FullTreeFunctionObservationV2RunPublication = try {
        deadline.checkpoint("before independently rederiving observation-v2")
        val availableScratchBytes = remainingV3Scratch(limits, aggregateScratchRoot)
        val perShardOutputBound = scope.document.controlObject("bounds").controlObject("perShard")
            .controlLong("serializedBytes")
        val outputReservation = minOf(
            perShardOutputBound,
            limits.observationV2.shard.maximumOutputBytes,
            FullTreeFunctionObservationsV2.MAXIMUM_CANONICAL_BYTES,
        )
        val nestedDwarfScratch = try {
            fullTreeFunctionTruthV3NestedObservationDwarfScratchBytes(
                availableScratchBytes,
                0L,
                outputReservation,
                limits.observationV2.shard.maximumDatabaseBytes,
                limits.observationV2.shard.control.maximumDwarfScratchBytes,
            )
        } catch (failure: IllegalArgumentException) {
            throw FullTreeFunctionTruthV3Exception(
                "truth-v3 shared scratch cannot reserve bounded observation-v2 database capacity",
                failure,
            )
        }
        val nestedLimits = limits.observationV2.copy(
            maximumScratchBytes = minOf(limits.observationV2.maximumScratchBytes, availableScratchBytes),
            shard = limits.observationV2.shard.copy(
                control = limits.observationV2.shard.control.copy(
                    maximumDwarfScratchBytes = nestedDwarfScratch,
                ),
            ),
        )
        FullTreeFunctionObservationV2RunPublisher.loadAndValidate(
            candidateRoot = observationV2Root,
            expectedIndexArtifactSha256 = expectedIndexSha256,
            richArtifact = richArtifact,
            inventoryPath = inventoryPath,
            scope = scope,
            scratchParent = scratchParent,
            limits = nestedLimits,
        )
            .also {
                requireV3WorkspaceBound(aggregateScratchRoot, limits)
                deadline.checkpoint("after independently rederiving observation-v2")
            }
    } catch (failure: Exception) {
        throw FullTreeFunctionTruthV3Exception(
            "observation-v2 run failed independent raw-input rederivation for truth v3",
            failure,
        )
    }

    /**
     * The V2 validator forbids scratch that overlaps its candidate tree. Final V3 rederivation
     * consumes the pinned observation snapshot, so give it a private sibling scratch directory
     * while measuring both trees against the enclosing V3 workspace ceiling.
     */
    private fun newObservationRevalidationScratch(workspaceRoot: Path, candidateRoot: Path): Path {
        val workspace = workspaceRoot.toAbsolutePath().normalize()
        val candidate = candidateRoot.toAbsolutePath().normalize()
        val scratch = workspace.resolve("observation-v2-final-revalidation-scratch")
        if (!candidate.startsWith(workspace) || scratch.startsWith(candidate) || candidate.startsWith(scratch)) {
            v3Fail("final observation-v2 revalidation scratch must be disjoint from its pinned candidate tree")
        }
        return try {
            Files.createDirectory(scratch, PosixFilePermissions.asFileAttribute(V3_WRITABLE_DIRECTORY))
        } catch (failure: Exception) {
            throw FullTreeFunctionTruthV3Exception("cannot create disjoint final observation-v2 revalidation scratch", failure)
        }
    }

    private fun snapshotObservationV2(
        originalRoot: Path,
        binding: BoundedShardRunBinding,
        identity: V3StableTreeSnapshot,
        workspaceRoot: Path,
        limits: FullTreeFunctionTruthV3Limits,
        deadline: V3RunDeadline,
    ): V3StableTreeSnapshot {
        val expected = TreeMap<String, V3ExpectedTreeMember>()
        val runBytes = canonicalV3Bytes(binding.run)
        val indexBytes = canonicalV3Bytes(binding.index)
        expected["run.json"] = V3ExpectedTreeMember(runBytes.size.toLong(), binding.runSha256)
        expected["index.json"] = V3ExpectedTreeMember(indexBytes.size.toLong(), binding.indexArtifactSha256)
        val indexRecords = binding.index.v3Array("shards").associate { raw ->
            val record = raw as? JsonObject ?: v3Fail("observation-v2 index record is not an object")
            record.v3String("shardId") to record
        }
        binding.outputs.forEach { output ->
            expected["outputs/${output.shardId}.json"] = V3ExpectedTreeMember(output.outputBytes, output.outputSha256)
            val record = indexRecords[output.shardId]
                ?: v3Fail("observation-v2 checkpoint record is missing for ${output.shardId}")
            val checkpoint = JsonObject(record.toMutableMap().apply {
                put("runSha256", JsonPrimitive(binding.runSha256))
                put("schemaVersion", JsonPrimitive(1))
                put("status", JsonPrimitive("complete"))
            })
            val checkpointBytes = canonicalV3Bytes(checkpoint)
            expected["checkpoints/${output.shardId}.json"] = V3ExpectedTreeMember(
                checkpointBytes.size.toLong(), OracleArtifacts.sha256(checkpointBytes),
            )
        }
        val memberBytes = expected.values.fold(0L) { total, member -> Math.addExact(total, member.bytes) }
        reserveV3ScratchCapacity(workspaceRoot, memberBytes, limits)
        val snapshot = identity.createSnapshot(
            originalRoot,
            workspaceRoot.resolve("observation-v2-pinned"),
            setOf("outputs", "checkpoints"),
            expected,
            deadline::checkpoint,
        )
        checkV3Scratch(workspaceRoot, maximumScratchBound(limits))
        return snapshot
    }

    private fun snapshotCandidate(
        candidateRoot: Path,
        projection: V3Projection,
        workspaceRoot: Path,
        scope: AuthenticatedFullTreeScope,
        limits: FullTreeFunctionTruthV3Limits,
        deadline: V3RunDeadline,
    ): V3StableTreeSnapshot {
        val maxFiles = Math.addExact(projection.index.v3Array("shards").size.toLong(), 2L)
        val identity = V3StableTreeSnapshot.captureIdentity(
            candidateRoot,
            setOf("shards"),
            maxFiles,
            projection.outputBytes,
            deadline::checkpoint,
            setOf("index.json", "exclusions.json"),
        )
        val wholeRunBytes = scope.document.controlObject("bounds").controlObject("wholeRun").controlLong("serializedBytes")
        val acceptedBytes = minOf(projection.outputBytes, wholeRunBytes, limits.maximumOutputBytes)
        reserveV3ScratchCapacity(workspaceRoot, identity.totalBytes, limits)
        val snapshot = identity.createSnapshot(
            candidateRoot,
            workspaceRoot.resolve("candidate-truth-v3-pinned"),
            setOf("shards"),
            null,
            deadline::checkpoint,
            acceptedBytes,
        )
        checkV3Scratch(workspaceRoot, maximumScratchBound(limits))
        return snapshot
    }

    private fun revalidateLegacyTruth(
        truth: FullTreeFunctionTruthGeneration,
        candidateRoot: Path,
        richArtifact: Path,
        strippedArtifact: Path,
        inventoryPath: Path,
        elfFunctionIndex: Path,
        scope: AuthenticatedFullTreeScope,
        workspace: V3Workspace,
        maximumWorkers: Int,
        limits: FullTreeFunctionTruthV3Limits,
        deadline: V3RunDeadline,
    ) {
        deadline.checkpoint("before independently rederiving frozen emitted-RVA truth")
        val truthLimits = effectiveTruthLimits(limits, workspace.root, reservePublishedOutput = false)
        val scratch = workspace.root.resolve("legacy-truth-validation-scratch")
        Files.createDirectory(scratch, PosixFilePermissions.asFileAttribute(V3_WRITABLE_DIRECTORY))
        val validation = FullTreeFunctionTruthSqlite.loadAndValidate(
            candidateRoot = candidateRoot,
            richArtifact = richArtifact,
            strippedArtifact = strippedArtifact,
            inventoryPath = inventoryPath,
            elfFunctionIndex = elfFunctionIndex,
            observationRoot = workspace.root.resolve("legacy-observation-run"),
            expectedObservationIndexArtifactSha256 = truth.observationIndexArtifactSha256,
            scope = scope,
            scratchParent = scratch,
            maximumWorkers = maximumWorkers,
            limits = truthLimits,
        )
        deadline.checkpoint("after independently rederiving frozen emitted-RVA truth")
        if (!validation.rawInputsRederived || !validation.candidateBytesMatchedAtValidationBoundary ||
            validation.indexArtifactSha256 != truth.indexArtifactSha256 ||
            validation.indexSha256 != truth.indexSha256
        ) {
            v3Fail("legacy emitted-RVA truth did not survive final raw-input rederivation")
        }
    }

    private fun publishLegacyObservationAdapter(
        observationV2Root: Path,
        run: FullTreeFunctionObservationV2RunPublication,
        scope: AuthenticatedFullTreeScope,
        workspace: V3Workspace,
        limits: FullTreeFunctionTruthV3Limits,
        deadline: V3RunDeadline,
    ): BoundedShardRunBinding {
        val preparedDirectory = workspace.root.resolve("legacy-observation-prepared")
        Files.createDirectory(preparedDirectory, PosixFilePermissions.asFileAttribute(V3_WRITABLE_DIRECTORY))
        val (_, preparedDirectoryIdentity) = requireStableDirectory(preparedDirectory, "truth-v3 prepared adapter directory")
        val prepared = ArrayList<BoundedShardPreparedOutput>(run.binding.outputs.size)
        var totalBytes = 0L
        run.binding.outputs.forEachIndexed { index, binding ->
            val shardStart = deadline.beginShard(binding.shardId)
            deadline.checkpoint("before adapting observation-v2 shard ${binding.shardId}")
            val path = observationV2Root.resolve("outputs/${binding.shardId}.json")
            val observationBytes = Files.size(path)
            val adapterProjectionBytes = projectedV3ShardBytes(observationBytes, 0L)
            admitV3ShardWorkingSet(
                observationBytes,
                0L,
                adapterProjectionBytes,
                projectedV3ControlBytes(
                    run.binding.outputs.size,
                    Files.size(observationV2Root.resolve("run.json")) + Files.size(observationV2Root.resolve("index.json")),
                ),
                scope.document.controlObject("bounds").controlObject("perShard").controlLong("maximumResidentBytes"),
                limits,
            )
            val document = readAuthenticatedObservationV2(path, binding, scope, limits)
            val countsV2 = document.v3Object("counts")
            val legacyCounts = JsonObject(
                listOf("emittedRvas", "nonEmitted", "nonEmittedDies", "scannedDies", "units")
                    .associateWith { name -> countsV2.getValue(name) },
            )
            val oracle = JsonObject(document.v3Object("oracle").toMutableMap().apply {
                put("configurationSha256", JsonPrimitive(FullTreeFunctionObservations.configurationSha256))
            })
            val legacy = JsonObject(
                mapOf(
                    "counts" to legacyCounts,
                    "emitted" to document.v3Array("emitted"),
                    "nonEmitted" to document.v3Array("nonEmitted"),
                    "oracle" to oracle,
                    "schemaVersion" to JsonPrimitive(1),
                    "shard" to document.v3Object("shard"),
                ),
            )
            OracleSchemas.validate("full-tree-function-observations", legacy)
            val bytes = canonicalV3Bytes(legacy)
            totalBytes = Math.addExact(totalBytes, bytes.size.toLong())
            if (totalBytes > maximumScratchBound(limits)) v3Fail("v3 observation adapter exceeds its scratch bound")
            val output = preparedDirectory.resolve("${binding.shardId}.json")
            reserveV3ScratchCapacity(workspace.root, bytes.size.toLong(), limits)
            writePrivateFile(output, bytes)
            val emitted = legacy.v3Array("emitted").size.toLong()
            val nonEmitted = legacy.v3Array("nonEmitted").size.toLong()
            prepared += BoundedShardPreparedOutput(
                shardId = binding.shardId,
                inputSha256 = binding.inputSha256,
                output = output,
                outputSha256 = OracleArtifacts.sha256(bytes),
                outputBytes = bytes.size.toLong(),
                entities = Math.addExact(emitted, nonEmitted),
            )
            checkV3Scratch(workspace.root, maximumScratchBound(limits))
            deadline.finishShard(shardStart, binding.shardId)
            if ((index + 1) % 128 == 0) deadline.checkpoint("after adapting observation-v2 shards ${index + 1}")
        }
        val perShard = scope.document.controlObject("bounds").controlObject("perShard")
        val wholeRun = scope.document.controlObject("bounds").controlObject("wholeRun")
        val maxWorkers = minOf(run.maximumWorkers, run.binding.outputs.size)
        val bounds = BoundedShardRunPublicationBounds(
            maximumShards = run.binding.outputs.size,
            perShardEntities = perShard.controlLong("entities"),
            wholeRunEntities = wholeRun.controlLong("entities"),
            perShardBytes = perShard.controlLong("serializedBytes"),
            wholeRunBytes = wholeRun.controlLong("serializedBytes"),
            perShardSeconds = perShard.controlLong("wallClockSeconds").toDouble(),
            wholeRunSeconds = wholeRun.controlLong("wallClockSeconds").toDouble(),
            perShardCpuSeconds = perShard.controlLong("cpuSeconds").toDouble(),
            wholeRunCpuSeconds = wholeRun.controlLong("cpuSeconds").toDouble(),
            maximumResidentBytes = wholeRun.controlLong("maximumResidentBytes"),
            maximumWorkers = maxWorkers,
        )
        val currentScratchBytes = checkV3Scratch(workspace.root, maximumScratchBound(limits))
        try {
            fullTreeFunctionTruthV3AdapterPublishScratchPeakBytes(
                currentScratchBytes = currentScratchBytes,
                preparedPayloadBytes = totalBytes,
                maximumControlArtifactBytes = limits.truth.observationRun.maximumControlArtifactBytes.toLong(),
                shardCount = run.binding.outputs.size,
                maximumScratchBytes = maximumScratchBound(limits),
            )
        } catch (failure: ArithmeticException) {
            throw FullTreeFunctionTruthV3Exception("truth-v3 observation adapter scratch model overflows", failure)
        } catch (failure: IllegalArgumentException) {
            throw FullTreeFunctionTruthV3Exception(
                "truth-v3 observation adapter publication exceeds its remaining scratch bound",
                failure,
            )
        }
        val target = workspace.root.resolve("legacy-observation-run")
        val adapter = BoundedShardRunPublisher.publish(
            target = target,
            runId = "full-tree-functions-${scope.sha256.take(16)}",
            preparedOutputs = prepared,
            bounds = bounds,
            semanticValidator = BoundedShardOutputSemanticValidator { staged ->
                deadline.checkpoint("before validating staged legacy observation ${staged.shardId}")
                val bytes = Files.readAllBytes(staged.output)
                val document = parseV3Object(bytes, staged.outputBytes, "staged legacy observation")
                OracleSchemas.validate("full-tree-function-observations", document)
                if (OracleArtifacts.sha256(bytes) != staged.outputSha256) {
                    v3Fail("legacy adapter bytes changed during publication")
                }
                deadline.checkpoint("after validating staged legacy observation ${staged.shardId}")
            },
            limits = limits.truth.observationRun,
        )
        deletePreparedAdapterFiles(preparedDirectory, preparedDirectoryIdentity, prepared)
        checkV3Scratch(workspace.root, maximumScratchBound(limits))
        return adapter
    }

    private fun deletePreparedAdapterFiles(
        directory: Path,
        expectedDirectoryIdentity: Any,
        prepared: List<BoundedShardPreparedOutput>,
    ) {
        requireDirectoryIdentity(directory, expectedDirectoryIdentity, "truth-v3 prepared adapter directory")
        val expectedNames = prepared.map { it.output.fileName.toString() }.toSet()
        if (expectedNames.size != prepared.size) v3Fail("truth-v3 prepared adapter member names are not unique")
        val entries = Files.list(directory).use { paths -> paths.toList() }
        if (entries.map { it.fileName.toString() }.toSet() != expectedNames || entries.size != expectedNames.size) {
            v3Fail("truth-v3 prepared adapter directory membership changed after publication")
        }
        entries.forEach { path ->
            if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                v3Fail("truth-v3 prepared adapter member is not a regular file")
            }
            Files.delete(path)
        }
        requireDirectoryIdentity(directory, expectedDirectoryIdentity, "truth-v3 prepared adapter directory")
        if (Files.list(directory).use { it.findAny().isPresent }) {
            v3Fail("truth-v3 prepared adapter directory did not empty after publication")
        }
        Files.delete(directory)
    }

    private fun composeV3Tree(
        target: Path,
        legacyRoot: Path,
        observationV2Root: Path,
        v2Run: FullTreeFunctionObservationV2RunPublication,
        legacyTruth: FullTreeFunctionTruthGeneration,
        scope: AuthenticatedFullTreeScope,
        scratchRoot: Path,
        limits: FullTreeFunctionTruthV3Limits,
        deadline: V3RunDeadline,
    ): V3Projection {
        val targetNormalized = target.toAbsolutePath().normalize()
        if (!Files.isDirectory(targetNormalized, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(targetNormalized)) {
            v3Fail("truth-v3 staging root must be a regular directory")
        }
        if (Files.list(targetNormalized).use { it.findAny().isPresent }) {
            v3Fail("truth-v3 staging root is not empty")
        }
        checkV3Scratch(scratchRoot, maximumScratchBound(limits))
        val targetInsideScratch = targetNormalized.startsWith(scratchRoot.toAbsolutePath().normalize())
        val shardsDirectory = targetNormalized.resolve("shards")
        Files.createDirectory(shardsDirectory, PosixFilePermissions.asFileAttribute(V3_WRITABLE_DIRECTORY))

        val legacyIndex = readCanonicalObject(legacyRoot.resolve("index.json"), limits.truth.maximumOutputBytes)
        val legacyOracle = legacyIndex.v3Object("oracle")
        val v3Oracle = JsonObject(legacyOracle.toMutableMap().apply {
            put("configurationSha256", JsonPrimitive(configurationSha256))
            put("observationIndexSha256", JsonPrimitive(v2Run.binding.indexArtifactSha256))
        })
        val sourcesByShard = v2Run.binding.outputs.associateBy { it.shardId }
        val allKindCounts = zeroKindCounts()
        val allObservabilityCounts = zeroObservabilityCounts()
        val allDispositionCounts = zeroDispositionCounts()
        val wholeRunOutputBound = minOf(
            limits.maximumOutputBytes,
            v2Run.binding.run.v3Object("bounds").v3Long("wholeRunBytes"),
        )
        preflightV3RunWorkingSet(
            legacyRoot,
            observationV2Root,
            legacyIndex,
            v2Run,
            limits,
            deadline,
        )
        val truthEntities = Math.addExact(
            Math.addExact(legacyTruth.counts.elfRvas, legacyTruth.counts.dwarfOnlyRvas),
            legacyTruth.counts.nonEmittedUnique,
        )
        val wholeRunEntityBound = scope.document.controlObject("bounds").controlObject("wholeRun").controlLong("entities")
        val perShardEntityBound = scope.document.controlObject("bounds").controlObject("perShard").controlLong("entities")
        val fullRunEmittedRvas = collectFullRunEmittedRvas(
            legacyRoot,
            observationV2Root,
            legacyIndex,
            v2Run,
            truthEntities,
            scope.document.controlObject("bounds").controlObject("perShard").controlLong("maximumResidentBytes"),
            limits,
            deadline,
        )
        var allSourceEntities = 0L
        var outputBytes = 0L
        val v3ShardRecords = ArrayList<JsonObject>(v2Run.binding.outputs.size)

        v2Run.binding.outputs.forEachIndexed { shardIndex, observation ->
            val shardStart = deadline.beginShard(observation.shardId)
            val shardSourceEntities = v2Run.outputs.getOrNull(shardIndex)?.sourceEntities
                ?: v3Fail("observation-v2 source census receipt is missing for ${observation.shardId}")
            val nextSourceEntityTotal = Math.addExact(allSourceEntities, shardSourceEntities)
            try {
                fullTreeFunctionTruthV3CombinedEntityCount(truthEntities, nextSourceEntityTotal, wholeRunEntityBound)
            } catch (failure: IllegalArgumentException) {
                throw FullTreeFunctionTruthV3Exception(
                    "truth-v3 combined emitted, non-emitted, and source-census populations exceed the authenticated entity bound",
                    failure,
                )
            }
            val truthRecord = legacyIndex.v3Array("shards").getOrNull(shardIndex) as? JsonObject
                ?: v3Fail("legacy truth shard membership differs from authenticated observation-v2")
            val shardId = truthRecord.v3String("id")
            if (shardId != observation.shardId || sourcesByShard[shardId] !== observation) {
                v3Fail("legacy truth and observation-v2 shard orders differ")
            }
            val truthPath = legacyRoot.resolve("shards/$shardId.json")
            val truthFileBytes = Files.size(truthPath)
            val sourcePath = observationV2Root.resolve("outputs/$shardId.json")
            val sourceFileBytes = Files.size(sourcePath)
            val estimatedProjectionBytes = projectedV3ShardBytes(sourceFileBytes, truthFileBytes)
            admitV3ShardWorkingSet(
                sourceFileBytes,
                truthFileBytes,
                estimatedProjectionBytes,
                projectedV3ControlBytes(
                    v2Run.binding.outputs.size,
                    Files.size(legacyRoot.resolve("index.json")) + Files.size(legacyRoot.resolve("exclusions.json")) +
                        Files.size(observationV2Root.resolve("run.json")) + Files.size(observationV2Root.resolve("index.json")),
                ),
                scope.document.controlObject("bounds").controlObject("perShard").controlLong("maximumResidentBytes"),
                limits,
                retainedSingleCopyBytes = fullRunEmittedRvas.retainedBytes,
            )
            val truthBytes = readBoundedFile(truthPath, limits.truth.maximumOutputBytes, "legacy truth shard")
            val truthDocument = parseV3Object(truthBytes, truthBytes.size.toLong(), "legacy truth shard")
            val truthShardCounts = truthDocument.v3Object("counts")
            val truthShardEntities = Math.addExact(
                truthShardCounts.v3Long("functions"),
                truthShardCounts.v3Long("nonEmitted"),
            )
            try {
                fullTreeFunctionTruthV3CombinedEntityCount(
                    truthShardEntities,
                    shardSourceEntities,
                    perShardEntityBound,
                )
            } catch (failure: IllegalArgumentException) {
                throw FullTreeFunctionTruthV3Exception(
                    "truth-v3 combined emitted, non-emitted, and source-census shard population exceeds the authenticated per-shard entity bound",
                    failure,
                )
            }
            val sourceDocument = readAuthenticatedObservationV2(sourcePath, observation, scope, limits)
            val sourceRows = sourceDocument.v3Array("sourceEntities")
            val census = countSourceRows(sourceRows)
            val v2ShardCounts = sourceDocument.v3Object("counts")
            if (census.sourceEntities != shardSourceEntities ||
                census.sourceEntities != v2ShardCounts.v3Long("sourceEntities") ||
                countObject(census.sourceEntitiesByKind.mapKeys { it.key.wireValue }) !=
                v2ShardCounts.v3Object("sourceEntitiesByKind") ||
                countObject(census.sourceEntitiesByObservability.mapKeys { it.key.wireValue }) !=
                v2ShardCounts.v3Object("sourceEntitiesByObservability") ||
                countObject(census.sourceEntitiesByDisposition.mapKeys { it.key.wireValue }) !=
                v2ShardCounts.v3Object("sourceEntitiesByDenominatorDisposition") ||
                sourceDocument.v3Object("identityReconciliation") != v2Run.reconciliation.canonicalJson()
            ) {
                v3Fail("observation-v2 source census count differs from its authenticated facts")
            }
            census.sourceEntitiesByKind.forEach { (key, count) -> allKindCounts[key] = Math.addExact(allKindCounts.getValue(key), count) }
            census.sourceEntitiesByObservability.forEach { (key, count) ->
                allObservabilityCounts[key] = Math.addExact(allObservabilityCounts.getValue(key), count)
            }
            census.sourceEntitiesByDisposition.forEach { (key, count) ->
                allDispositionCounts[key] = Math.addExact(allDispositionCounts.getValue(key), count)
            }
            allSourceEntities = nextSourceEntityTotal

            val linkedRvas = ArrayList<String>()
            sourceRows.forEachIndexed { sourceIndex, raw ->
                if ((sourceIndex and 255) == 0) deadline.checkpoint("while reconciling source links for $shardId")
                val source = raw as? JsonObject ?: v3Fail("source entity $sourceIndex is not an object")
                if (source.v3String("denominatorDisposition") == FullTreeDenominatorDisposition.EMITTED_RVA_LINK.wireValue) {
                    val linkedRva = source["linkedEmittedRva"]?.let { (it as? JsonPrimitive)?.content }
                        ?: v3Fail("emitted source entity has no linked RVA")
                    linkedRvas += linkedRva
                }
            }
            if (!fullTreeFunctionTruthV3HasOnlyEmittedRvaLinks(linkedRvas, fullRunEmittedRvas.rvas)) {
                v3Fail("source census link does not name an emitted truth row in the authenticated full run")
            }
            val oldCounts = truthDocument.v3Object("counts")
            val newCounts = JsonObject(oldCounts.toMutableMap().apply {
                put("sourceEntities", JsonPrimitive(census.sourceEntities))
                put("sourceEntitiesByKind", countObject(census.sourceEntitiesByKind.mapKeys { it.key.wireValue }))
                put("sourceEntitiesByObservability", countObject(census.sourceEntitiesByObservability.mapKeys { it.key.wireValue }))
                put("sourceEntitiesByDenominatorDisposition", countObject(census.sourceEntitiesByDisposition.mapKeys { it.key.wireValue }))
            })
            val newShard = JsonObject(truthDocument.toMutableMap().apply {
                put("counts", newCounts)
                put("oracle", v3Oracle)
                put("schemaVersion", JsonPrimitive(2))
                put("sourceEntities", sourceRows)
            })
            OracleSchemas.validate(SHARD_SCHEMA_NAME, newShard)
            val bytes = canonicalV3Bytes(newShard)
            val maxShardBytes = minOf(
                wholeRunOutputBound,
                v2Run.binding.run.v3Object("bounds").v3Long("perShardBytes"),
            )
            if (bytes.size.toLong() > maxShardBytes) v3Fail("truth-v3 shard exceeds its authenticated output-byte bound")
            val output = shardsDirectory.resolve("$shardId.json")
            outputBytes = reserveV3OutputBytes(outputBytes, bytes.size.toLong(), wholeRunOutputBound)
            if (targetInsideScratch) reserveV3ScratchCapacity(scratchRoot, bytes.size.toLong(), limits)
            writePrivateFile(output, bytes)
            v3ShardRecords += JsonObject(
                truthRecord.toMutableMap().apply {
                    put("bytes", JsonPrimitive(bytes.size))
                    put("sha256", JsonPrimitive(OracleArtifacts.sha256(bytes)))
                    put("sourceEntities", JsonPrimitive(census.sourceEntities))
                },
            )
            deadline.finishShard(shardStart, observation.shardId)
            checkV3Scratch(scratchRoot, maximumScratchBound(limits))
        }

        if (allSourceEntities != v2Run.sourceEntities) v3Fail("v3 full-run census total differs from raw observation-v2")
        try {
            fullTreeFunctionTruthV3CombinedEntityCount(truthEntities, allSourceEntities, wholeRunEntityBound)
        } catch (failure: IllegalArgumentException) {
            throw FullTreeFunctionTruthV3Exception(
                "truth-v3 combined emitted, non-emitted, and source-census populations exceed the authenticated entity bound",
                failure,
            )
        }
        val exclusionsPath = legacyRoot.resolve("exclusions.json")
        val exclusions = readCanonicalObject(exclusionsPath, limits.truth.maximumOutputBytes)
        val v3Exclusions = JsonObject(exclusions.toMutableMap().apply {
            put("oracle", v3Oracle)
        })
        OracleSchemas.validate("full-tree-function-exclusions", v3Exclusions)
        val exclusionBytes = canonicalV3Bytes(v3Exclusions)
        outputBytes = reserveV3OutputBytes(outputBytes, exclusionBytes.size.toLong(), wholeRunOutputBound)
        if (targetInsideScratch) reserveV3ScratchCapacity(scratchRoot, exclusionBytes.size.toLong(), limits)
        writePrivateFile(targetNormalized.resolve("exclusions.json"), exclusionBytes)

        val legacyCounts = legacyIndex.v3Object("counts")
        val newIndexCounts = JsonObject(legacyCounts.toMutableMap().apply {
            put("sourceEntities", JsonPrimitive(allSourceEntities))
            put("sourceEntitiesByKind", countObject(allKindCounts.mapKeys { it.key.wireValue }))
            put("sourceEntitiesByObservability", countObject(allObservabilityCounts.mapKeys { it.key.wireValue }))
            put("sourceEntitiesByDenominatorDisposition", countObject(allDispositionCounts.mapKeys { it.key.wireValue }))
        })
        val exclusionsRecord = JsonObject(
            legacyIndex.v3Object("exclusions").toMutableMap().apply {
                put("bytes", JsonPrimitive(exclusionBytes.size))
                put("sha256", JsonPrimitive(OracleArtifacts.sha256(exclusionBytes)))
            },
        )
        val indexWithoutSelf = JsonObject(
            mapOf(
                "complete" to JsonPrimitive(true),
                "counts" to newIndexCounts,
                "exclusions" to exclusionsRecord,
                "identityReconciliation" to v2Run.reconciliation.canonicalJson(),
                "oracle" to v3Oracle,
                "schemaVersion" to JsonPrimitive(2),
                "shards" to JsonArray(v3ShardRecords),
            ),
        )
        val logicalIndexSha256 = OracleArtifacts.sha256(canonicalV3Bytes(indexWithoutSelf))
        val index = JsonObject(indexWithoutSelf + ("indexSha256" to JsonPrimitive(logicalIndexSha256)))
        OracleSchemas.validate(INDEX_SCHEMA_NAME, index)
        val indexBytes = canonicalV3Bytes(index)
        outputBytes = reserveV3OutputBytes(outputBytes, indexBytes.size.toLong(), wholeRunOutputBound)
        if (targetInsideScratch) reserveV3ScratchCapacity(scratchRoot, indexBytes.size.toLong(), limits)
        writePrivateFile(targetNormalized.resolve("index.json"), indexBytes)
        val totalContent = v3ShardRecords.fold(exclusionBytes.size.toLong()) { total, record ->
            addV3Bounded(total, record.v3Long("bytes"), limits.maximumOutputBytes)
        }
        if (totalContent != outputBytes - indexBytes.size || outputBytes > limits.maximumOutputBytes) {
            v3Fail("truth-v3 output byte total does not reconcile")
        }
        verifyV3IndexTree(targetNormalized, index, indexBytes, outputBytes)
        val finalCounts = FullTreeFunctionTruthV3Counts(
            functions = legacyTruth.counts,
            sourceEntities = allSourceEntities,
            sourceEntitiesByKind = allKindCounts.toMap(),
            sourceEntitiesByObservability = allObservabilityCounts.toMap(),
            sourceEntitiesByDisposition = allDispositionCounts.toMap(),
        )
        return V3Projection(
            root = targetNormalized,
            index = index,
            indexBytes = indexBytes,
            indexArtifactSha256 = OracleArtifacts.sha256(indexBytes),
            indexSha256 = logicalIndexSha256,
            outputBytes = outputBytes,
            counts = finalCounts,
            elfIndexArtifactSha256 = legacyTruth.elfIndexArtifactSha256,
        )
    }

    private fun readAuthenticatedObservationV2(
        path: Path,
        binding: BoundedShardOutputBinding,
        scope: AuthenticatedFullTreeScope?,
        limits: FullTreeFunctionTruthV3Limits,
    ): JsonObject {
        val perShardLimit = scope?.document?.controlObject("bounds")?.controlObject("perShard")
            ?.controlLong("serializedBytes") ?: limits.observationV2.run.maximumPerShardOutputBytes
        val cap = minOf(FullTreeFunctionObservationsV2.MAXIMUM_CANONICAL_BYTES, perShardLimit)
        val bytes = readBoundedFile(path, cap, "observation-v2 shard ${binding.shardId}")
        if (bytes.size.toLong() != binding.outputBytes || OracleArtifacts.sha256(bytes) != binding.outputSha256) {
            v3Fail("observation-v2 shard changed after raw-input validation")
        }
        val document = parseV3Object(bytes, cap, "observation-v2 shard")
        if (document.v3Object("shard").v3String("id") != binding.shardId ||
            document.v3Object("shard").v3String("inputSha256") != binding.inputSha256
        ) {
            v3Fail("observation-v2 shard binding differs from the authenticated run")
        }
        return document
    }

    private fun countSourceRows(rows: JsonArray): FullTreeFunctionTruthV3Counts {
        val kinds = zeroKindCounts()
        val observability = zeroObservabilityCounts()
        val dispositions = zeroDispositionCounts()
        rows.forEachIndexed { index, raw ->
            if ((index and 255) == 0) FullTreeOracleOperationCheckpoint.checkpoint("while counting source-census rows")
            val row = raw as? JsonObject ?: v3Fail("source entity $index is not an object")
            val kind = FullTreeSourceEntityKind.entries.singleOrNull { it.wireValue == row.v3String("entityKind") }
                ?: v3Fail("source entity has an unsupported kind")
            val identity = FullTreeIdentityObservability.entries.singleOrNull {
                it.wireValue == row.v3String("identityObservability")
            } ?: v3Fail("source entity has an unsupported observability disposition")
            val disposition = FullTreeDenominatorDisposition.entries.singleOrNull {
                it.wireValue == row.v3String("denominatorDisposition")
            } ?: v3Fail("source entity has an unsupported denominator disposition")
            kinds[kind] = Math.addExact(kinds.getValue(kind), 1L)
            observability[identity] = Math.addExact(observability.getValue(identity), 1L)
            dispositions[disposition] = Math.addExact(dispositions.getValue(disposition), 1L)
        }
        return FullTreeFunctionTruthV3Counts(
            functions = emptyFunctionCounts(),
            sourceEntities = rows.size.toLong(),
            sourceEntitiesByKind = kinds,
            sourceEntitiesByObservability = observability,
            sourceEntitiesByDisposition = dispositions,
        )
    }

    private fun emptyFunctionCounts() = FullTreeFunctionTruthCounts(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    private fun zeroKindCounts() = EnumMap<FullTreeSourceEntityKind, Long>(FullTreeSourceEntityKind::class.java).apply {
        FullTreeSourceEntityKind.entries.forEach { put(it, 0L) }
    }

    private fun zeroObservabilityCounts() = EnumMap<FullTreeIdentityObservability, Long>(FullTreeIdentityObservability::class.java).apply {
        FullTreeIdentityObservability.entries.forEach { put(it, 0L) }
    }

    private fun zeroDispositionCounts() = EnumMap<FullTreeDenominatorDisposition, Long>(FullTreeDenominatorDisposition::class.java).apply {
        FullTreeDenominatorDisposition.entries.forEach { put(it, 0L) }
    }

    private fun validateV3ScopeAndLimits(scope: AuthenticatedFullTreeScope, limits: FullTreeFunctionTruthV3Limits) {
        FullTreeScopeControl.validate(scope, limits.truth.control)
        val whole = scope.document.controlObject("bounds").controlObject("wholeRun")
        if (limits.maximumRetainedWorkingSetBytes > whole.controlLong("maximumResidentBytes") ||
            limits.truth.modeledResidentBytes > whole.controlLong("maximumResidentBytes")
        ) {
            v3Fail("truth-v3 working-set limits exceed the authenticated whole-run resident bound")
        }
        if (!fullTreeFunctionTruthV3HasDatabaseScratchCapacity(limits)) {
            v3Fail("truth-v3 scratch bound is smaller than the frozen emitted-RVA database minimum")
        }
    }

    private fun remainingV3Scratch(limits: FullTreeFunctionTruthV3Limits, scratchRoot: Path): Long {
        val bound = maximumScratchBound(limits)
        val used = checkV3Scratch(scratchRoot, bound)
        val remaining = bound - used
        if (remaining <= 0L) v3Fail("truth-v3 has no scratch remaining for nested raw-input rederivation")
        return remaining
    }

    private fun effectiveTruthLimits(
        limits: FullTreeFunctionTruthV3Limits,
        scratchRoot: Path,
        reservePublishedOutput: Boolean,
    ): FullTreeFunctionTruthLimits {
        val remaining = remainingV3Scratch(limits, scratchRoot)
        if (remaining < limits.truth.maximumDatabaseBytes) {
            v3Fail("truth-v3 remaining scratch is below the frozen emitted-RVA database minimum")
        }
        if (!reservePublishedOutput) {
            return limits.truth.copy(maximumScratchBytes = minOf(limits.truth.maximumScratchBytes, remaining))
        }
        val plan = try {
            fullTreeFunctionTruthV3NestedScratchPlan(
                remainingBytes = remaining,
                databaseMinimumBytes = limits.truth.maximumDatabaseBytes,
                maximumScratchBytes = limits.truth.maximumScratchBytes,
                maximumOutputBytes = limits.truth.maximumOutputBytes,
            )
        } catch (failure: IllegalArgumentException) {
            throw FullTreeFunctionTruthV3Exception(
                "truth-v3 shared scratch cannot reserve nested emitted-RVA database, scratch, and staged output",
                failure,
            )
        }
        return limits.truth.copy(
            maximumScratchBytes = plan.maximumScratchBytes,
            maximumOutputBytes = plan.maximumOutputBytes,
        )
    }

    private fun requireSameV2Reconciliation(
        initial: FullTreeFunctionObservationV2RunPublication,
        final: FullTreeFunctionObservationV2RunPublication,
    ) {
        if (initial.binding.run != final.binding.run || initial.binding.index != final.binding.index ||
            initial.binding.runSha256 != final.binding.runSha256 ||
            initial.binding.indexArtifactSha256 != final.binding.indexArtifactSha256 ||
            initial.reconciliation != final.reconciliation || initial.outputs != final.outputs
        ) {
            v3Fail("observation-v2 raw rederivation changed before truth-v3 publication or validation")
        }
    }

    /** Freeze a complete staged tree, then reauthenticate its members and retain path identities. */
    internal fun freezeAndVerifyV3Staging(
        root: Path,
        index: JsonObject,
        indexBytes: ByteArray,
        outputBytes: Long,
        checkpoint: (String) -> Unit = {},
    ): V3StableTreeSnapshot {
        makeV3ReadOnly(root, checkpoint)
        checkpoint("after freezing truth-v3 publication staging")
        verifyV3IndexTree(root, index, indexBytes, outputBytes)
        return V3StableTreeSnapshot.captureIdentity(
            root,
            setOf("shards"),
            Math.addExact(index.v3Array("shards").size.toLong(), 2L),
            outputBytes,
            checkpoint,
            setOf("index.json", "exclusions.json"),
        )
    }

    /** Rehash the frozen tree at the final rename boundary; same-UID writers are not permanently excluded. */
    internal fun reauthenticateV3Staging(
        snapshot: V3StableTreeSnapshot,
        index: JsonObject,
        indexBytes: ByteArray,
        outputBytes: Long,
        checkpoint: (String) -> Unit = {},
    ) {
        snapshot.verifyIdentity(checkpoint)
        verifyV3IndexTree(snapshot.root, index, indexBytes, outputBytes)
    }

    private fun verifyV3IndexTree(root: Path, index: JsonObject, indexBytes: ByteArray, expectedOutputBytes: Long) {
        OracleSchemas.validate(INDEX_SCHEMA_NAME, index)
        if (OracleArtifacts.sha256(indexBytes) != index.v3String("indexSha256")) {
            // indexSha256 is the logical hash, so compare its declared preimage separately below.
            val withoutSelf = JsonObject(index.filterKeys { it != "indexSha256" })
            if (OracleArtifacts.sha256(canonicalV3Bytes(withoutSelf)) != index.v3String("indexSha256")) {
                v3Fail("truth-v3 logical index digest does not reconcile")
            }
        }
        val maximumFiles = Math.addExact(index.v3Array("shards").size.toLong(), 2L)
        val outputFiles = v3TreeFiles(root, maximumFiles, expectedOutputBytes)
        val expectedPaths = linkedSetOf("index.json", "exclusions.json")
        index.v3Array("shards").forEachIndexed { indexPosition, raw ->
            if ((indexPosition and 255) == 0) FullTreeOracleOperationCheckpoint.checkpoint("while matching truth-v3 index members")
            expectedPaths += (raw as JsonObject).v3String("path")
        }
        if (outputFiles.keys != expectedPaths) v3Fail("truth-v3 output tree membership differs from its index")
        var total = 0L
        index.v3Array("shards").forEachIndexed { indexPosition, raw ->
            if ((indexPosition and 255) == 0) FullTreeOracleOperationCheckpoint.checkpoint("while hashing truth-v3 indexed shards")
            val record = raw as JsonObject
            val path = record.v3String("path")
            withV3TreeMemberPhase(path) {
            val actual = hashV3File(outputFiles.getValue(path))
            if (actual.first != record.v3String("sha256") || actual.second != record.v3Long("bytes")) {
                v3Fail("truth-v3 shard digest differs from its index")
            }
            total = addV3Bounded(total, actual.second, expectedOutputBytes)
            }
        }
        val exclusion = index.v3Object("exclusions")
        val exclusionDigest = hashV3File(outputFiles.getValue(exclusion.v3String("path")))
        if (exclusionDigest.first != exclusion.v3String("sha256") || exclusionDigest.second != exclusion.v3Long("bytes")) {
            v3Fail("truth-v3 exclusion digest differs from its index")
        }
        total = addV3Bounded(total, exclusionDigest.second, expectedOutputBytes)
        val indexDigest = hashV3File(root.resolve("index.json"))
        if (indexDigest.first != OracleArtifacts.sha256(indexBytes) || indexDigest.second != indexBytes.size.toLong()) {
            v3Fail("truth-v3 index file changed during derivation")
        }
        total = addV3Bounded(total, indexDigest.second, expectedOutputBytes)
        if (total != expectedOutputBytes) v3Fail("truth-v3 byte count differs from its members")
    }

    private fun verifyV3Candidate(
        candidate: V3StableTreeSnapshot,
        expected: V3Projection,
        candidateParent: Path,
        candidateParentIdentity: Any,
    ) {
        requireDirectoryIdentity(candidateParent, candidateParentIdentity, "truth-v3 candidate parent")
        compareV3CandidateTreeBytes(
            candidate.root,
            expected.root,
            Math.addExact(expected.index.v3Array("shards").size.toLong(), 2L),
            expected.outputBytes,
        )
        requireDirectoryIdentity(candidateParent, candidateParentIdentity, "truth-v3 candidate parent")
    }

    internal fun compareV3CandidateTreeBytes(
        candidate: Path,
        independentlyDerivedRoot: Path,
        maximumFiles: Long,
        expectedOutputBytes: Long,
        afterComparedMember: ((String) -> Unit)? = null,
    ) {
        val candidateParent = candidate.parent ?: v3Fail("truth-v3 candidate root must have a parent")
        val (_, candidateParentIdentity) = requireStableDirectory(candidateParent, "truth-v3 candidate parent")
        val (_, identity) = requireStableDirectory(candidate, "truth-v3 candidate tree")
        val candidateShards = candidate.resolve("shards")
        val (_, candidateShardsIdentity) = requireStableDirectory(candidateShards, "truth-v3 candidate shard directory")
        val candidateFiles = v3TreeFiles(candidate, maximumFiles, expectedOutputBytes)
        val expectedFiles = v3TreeFiles(independentlyDerivedRoot, maximumFiles, expectedOutputBytes)
        if (candidateFiles.keys != expectedFiles.keys) v3Fail("truth-v3 candidate tree membership differs from raw rederivation")
        candidateFiles.forEach { (relative, file) ->
            withV3TreeMemberPhase(relative) {
            FullTreeOracleOperationCheckpoint.checkpoint("while comparing truth-v3 candidate member $relative")
            val derived = expectedFiles.getValue(relative)
            if (Files.mismatch(file, derived) != -1L) v3Fail("truth-v3 candidate bytes differ from raw rederivation at $relative")
            afterComparedMember?.invoke(relative)
            }
        }
        requireDirectoryIdentity(candidate, identity, "truth-v3 candidate root")
        requireDirectoryIdentity(candidateShards, candidateShardsIdentity, "truth-v3 candidate shard directory")
        requireDirectoryIdentity(candidateParent, candidateParentIdentity, "truth-v3 candidate parent")
    }

    private fun v3TreeFiles(root: Path, maximumFiles: Long, maximumBytes: Long): Map<String, Path> {
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(root)) {
            v3Fail("truth-v3 tree root is not a regular directory")
        }
        if (maximumFiles < 2L || maximumBytes <= 0L) v3Fail("truth-v3 tree bounds are invalid")
        val (_, rootIdentity) = requireStableDirectory(root, "truth-v3 tree root")
        val top = Files.list(root).use { stream ->
            val members = linkedSetOf<String>()
            stream.forEach { path ->
                if (members.size >= 3 || !members.add(path.fileName.toString())) {
                    v3Fail("truth-v3 tree root exceeds its member-count bound")
                }
            }
            members
        }
        if (top != setOf("index.json", "exclusions.json", "shards")) v3Fail("truth-v3 tree root members differ")
        val shards = root.resolve("shards")
        if (!Files.isDirectory(shards, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(shards)) {
            v3Fail("truth-v3 shard member is not a directory")
        }
        val (_, shardsIdentity) = requireStableDirectory(shards, "truth-v3 shard directory")
        val result = TreeMap<String, Path>()
        var fileCount = 0L
        var fileBytes = 0L
        Files.walk(root).use { paths ->
            paths.filter { it != root }.forEach { path ->
                FullTreeOracleOperationCheckpoint.checkpoint("while enumerating truth-v3 tree members")
                if (Files.isSymbolicLink(path)) v3Fail("truth-v3 tree contains a symbolic link")
                val relative = root.relativize(path).toString().replace('\\', '/')
                if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                    if (relative != "shards") v3Fail("truth-v3 tree contains an unexpected directory")
                } else if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                    fileCount = Math.addExact(fileCount, 1L)
                    if (fileCount > maximumFiles) v3Fail("truth-v3 tree exceeds its member-count bound")
                    val size = Files.size(path)
                    if (size <= 0L) v3Fail("truth-v3 tree contains an empty member")
                    fileBytes = addV3Bounded(fileBytes, size, maximumBytes)
                    requireV3StableTreeFile(path)
                    result[relative] = path
                } else {
                    v3Fail("truth-v3 tree contains a non-regular member")
                }
            }
        }
        requireDirectoryIdentity(root, rootIdentity, "truth-v3 tree root")
        requireDirectoryIdentity(shards, shardsIdentity, "truth-v3 shard directory")
        return result
    }

    private fun requireV3StableTreeFile(path: Path) {
        try {
            val attributes = Files.readAttributes(path, "unix:mode,nlink", LinkOption.NOFOLLOW_LINKS)
            val mode = (attributes["mode"] as? Number)?.toInt()
                ?: v3Fail("truth-v3 member mode is unavailable")
            val links = (attributes["nlink"] as? Number)?.toLong()
                ?: v3Fail("truth-v3 member link count is unavailable")
            if (links != 1L || mode and 0x12 != 0) {
                v3Fail("truth-v3 member must be privately linked and not group/other writable")
            }
        } catch (failure: FullTreeFunctionTruthV3Exception) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeFunctionTruthV3Exception("truth-v3 member identity is unavailable", failure)
        }
    }

    private fun readCanonicalObject(path: Path, maximumBytes: Long): JsonObject =
        parseV3Object(readBoundedFile(path, maximumBytes, path.fileName.toString()), maximumBytes, path.fileName.toString())

    private fun canonicalV3Bytes(document: JsonElement): ByteArray = OracleJson.canonicalBytes(
        document,
        StrictJsonLimits(
            maximumInputBytes = FullTreeFunctionObservationsV2.MAXIMUM_CANONICAL_BYTES.toInt(),
            maximumCanonicalBytes = FullTreeFunctionObservationsV2.MAXIMUM_CANONICAL_BYTES.toInt(),
            maximumDepth = 128,
            maximumNodes = FullTreeFunctionObservationsV2.MAXIMUM_JSON_NODES,
            maximumStringBytes = MAXIMUM_SOURCE_IDENTITY_ROW_BYTES.toInt(),
            maximumTotalStringBytes = FullTreeFunctionObservationsV2.MAXIMUM_CANONICAL_BYTES.toInt(),
        ),
        FullTreeOracleOperationCheckpoint::checkpoint,
    )

    private fun parseV3Object(bytes: ByteArray, maximumBytes: Long, label: String): JsonObject {
        if (bytes.isEmpty() || bytes.size.toLong() > maximumBytes || bytes.last() != '\n'.code.toByte()) {
            v3Fail("$label is empty, oversized, or not canonical JSON")
        }
        return try {
            OracleJson.parseCanonical(
                bytes,
                StrictJsonLimits(
                    maximumInputBytes = bytes.size,
                    maximumCanonicalBytes = bytes.size,
                    maximumDepth = 128,
                    maximumNodes = FullTreeFunctionObservationsV2.MAXIMUM_JSON_NODES,
                    maximumStringBytes = MAXIMUM_SOURCE_IDENTITY_ROW_BYTES.toInt(),
                    maximumTotalStringBytes = bytes.size,
                ),
                FullTreeOracleOperationCheckpoint::checkpoint,
            ) as? JsonObject ?: v3Fail("$label root is not an object")
        } catch (failure: FullTreeFunctionTruthV3Exception) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeFunctionTruthV3Exception("$label is not strict canonical JSON", failure)
        }
    }

    private fun readBoundedFile(path: Path, maximumBytes: Long, label: String): ByteArray {
        FullTreeOracleOperationCheckpoint.checkpoint("before reading truth-v3 $label")
        if (maximumBytes <= 0L || Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            v3Fail("$label is not a regular non-symlink file")
        }
        val size = Files.size(path)
        if (size <= 0L || size > maximumBytes || size > Int.MAX_VALUE) v3Fail("$label exceeds its byte bound")
        val bytes = Files.readAllBytes(path)
        if (bytes.size.toLong() != size) v3Fail("$label changed while it was read")
        FullTreeOracleOperationCheckpoint.checkpoint("after reading truth-v3 $label")
        return bytes
    }

    private fun writePrivateFile(path: Path, bytes: ByteArray) {
        FullTreeOracleOperationCheckpoint.checkpoint("before writing truth-v3 ${path.fileName}")
        FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { channel ->
            var buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) {
                FullTreeOracleOperationCheckpoint.checkpoint("while writing truth-v3 ${path.fileName}")
                channel.write(buffer)
            }
            channel.force(true)
        }
        Files.setPosixFilePermissions(path, V3_PRIVATE_FILE)
        FullTreeOracleOperationCheckpoint.checkpoint("after writing truth-v3 ${path.fileName}")
    }

    private fun checkV3Scratch(path: Path, maximumBytes: Long): Long {
        var used = 0L
        Files.walk(path).use { paths ->
            paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }.forEach { file ->
                FullTreeOracleOperationCheckpoint.checkpoint("while accounting truth-v3 scratch")
                used = addV3Bounded(used, Files.size(file), maximumBytes)
            }
        }
        if (used > maximumBytes) v3Fail("truth-v3 scratch exceeds its byte bound")
        return used
    }

    internal fun reserveV3OutputBytes(
        currentOutputBytes: Long,
        nextMemberBytes: Long,
        outputBound: Long,
    ): Long {
        return addV3Bounded(currentOutputBytes, nextMemberBytes, outputBound)
    }

    private fun <T> withV3TreeMemberPhase(relative: String, operation: () -> T): T {
        if ('/' !in relative) return operation()
        val directory = relative.substringBefore('/', "")
        if (directory !in setOf("shards", "outputs", "checkpoints")) return operation()
        val fileName = relative.substringAfter('/')
        val shardId = fileName.removeSuffix(".json")
        if (shardId == fileName || shardId.isBlank()) v3Fail("truth-v3 shard member path is invalid")
        return FullTreeOracleOperationCheckpoint.withShardPhase(shardId, operation)
    }

    private fun requireV3WorkspaceBound(root: Path, limits: FullTreeFunctionTruthV3Limits) {
        checkV3Scratch(root, maximumScratchBound(limits))
    }

    private fun reserveV3ScratchCapacity(root: Path, additionalBytes: Long, limits: FullTreeFunctionTruthV3Limits) {
        if (additionalBytes < 0L) v3Fail("truth-v3 scratch reservation is negative")
        val bound = maximumScratchBound(limits)
        val used = checkV3Scratch(root, bound)
        if (additionalBytes > bound - used) {
            v3Fail("truth-v3 derived files exceed the remaining shared scratch bound")
        }
    }

    private fun maximumScratchBound(limits: FullTreeFunctionTruthV3Limits): Long =
        fullTreeFunctionTruthV3SharedScratchBound(limits)

    private fun projectedV3ShardBytes(observationBytes: Long, truthBytes: Long): Long {
        if (observationBytes <= 0L || truthBytes < 0L) v3Fail("truth-v3 shard has invalid preflight input sizes")
        return try {
            Math.addExact(Math.addExact(observationBytes, truthBytes), V3_SHARD_ENVELOPE_BYTES)
        } catch (failure: ArithmeticException) {
            throw FullTreeFunctionTruthV3Exception("truth-v3 projected shard size overflows", failure)
        }
    }

    private fun projectedV3ControlBytes(shardCount: Int, additionalBytes: Long = 0L): Long = try {
        Math.addExact(
            Math.addExact(V3_CONTROL_BASE_BYTES, Math.multiplyExact(shardCount.toLong(), V3_SHARD_RECORD_CONTROL_BYTES)),
            additionalBytes,
        )
    } catch (failure: ArithmeticException) {
        throw FullTreeFunctionTruthV3Exception("truth-v3 retained control model overflows", failure)
    }

    private fun preflightV3RunWorkingSet(
        legacyRoot: Path,
        observationV2Root: Path,
        legacyIndex: JsonObject,
        v2Run: FullTreeFunctionObservationV2RunPublication,
        limits: FullTreeFunctionTruthV3Limits,
        deadline: V3RunDeadline,
    ) {
        if (legacyIndex.v3Array("shards").size != v2Run.binding.outputs.size) {
            v3Fail("truth-v3 preflight shard populations differ")
        }
        v2Run.binding.outputs.forEachIndexed { index, observation ->
            val truthRecord = legacyIndex.v3Array("shards")[index] as? JsonObject
                ?: v3Fail("truth-v3 preflight has a non-object truth shard record")
            val shardId = truthRecord.v3String("id")
            if (shardId != observation.shardId) v3Fail("truth-v3 preflight shard order differs")
            withV3TreeMemberPhase("shards/$shardId.json") {
                deadline.checkpoint("preflighting truth-v3 shard working set $shardId")
                val observationBytes = Files.size(observationV2Root.resolve("outputs/$shardId.json"))
                val truthBytes = Files.size(legacyRoot.resolve("shards/$shardId.json"))
                if (observationBytes > limits.observationV2.run.maximumPerShardOutputBytes ||
                    truthBytes > limits.truth.maximumOutputBytes
                ) {
                    v3Fail("truth-v3 preflight input shard exceeds its authenticated file-size bounds")
                }
            }
        }
    }

    private data class V3EmittedRvaPopulation(val rvas: Set<String>, val retainedBytes: Long)

    private fun collectFullRunEmittedRvas(
        legacyRoot: Path,
        observationV2Root: Path,
        legacyIndex: JsonObject,
        v2Run: FullTreeFunctionObservationV2RunPublication,
        maximumTruthEntities: Long,
        authenticatedPerShardResidentBytes: Long,
        limits: FullTreeFunctionTruthV3Limits,
        deadline: V3RunDeadline,
    ): V3EmittedRvaPopulation {
        val records = legacyIndex.v3Array("shards")
        if (records.size != v2Run.binding.outputs.size) v3Fail("truth-v3 emitted-RVA shard populations differ")
        val maximumSetBytes = limits.maximumRetainedWorkingSetBytes - V3_FIXED_RETAINED_BYTES
        if (maximumSetBytes < 0L) v3Fail("truth-v3 emitted-RVA population has no retained-memory allowance")
        val rvas = HashSet<String>()
        val retainedControlBytes = projectedV3ControlBytes(
            records.size,
            Files.size(legacyRoot.resolve("index.json")) + Files.size(legacyRoot.resolve("exclusions.json")) +
                Files.size(observationV2Root.resolve("run.json")) + Files.size(observationV2Root.resolve("index.json")),
        )
        records.forEachIndexed { index, raw ->
            val record = raw as? JsonObject ?: v3Fail("truth-v3 emitted-RVA record is not an object")
            val shardId = record.v3String("id")
            if (v2Run.binding.outputs[index].shardId != shardId) {
                v3Fail("truth-v3 emitted-RVA shard order differs from authenticated observation-v2")
            }
            withV3TreeMemberPhase("shards/$shardId.json") {
            deadline.checkpoint("collecting full-run emitted RVA population")
            val truthPath = legacyRoot.resolve("shards/$shardId.json")
            val truthFileBytes = Files.size(truthPath)
            if (truthFileBytes !in 1L..limits.truth.maximumOutputBytes) {
                v3Fail("truth-v3 emitted-RVA shard exceeds its authenticated file-size bound")
            }
            val retainedRvaBytes = Math.multiplyExact(rvas.size.toLong(), V3_EMITTED_RVA_SET_ENTRY_BYTES)
            try {
                fullTreeFunctionTruthV3AdmitEmittedRvaCollectionWorkingSet(
                    truthShardBytes = truthFileBytes,
                    retainedControlBytes = retainedControlBytes,
                    retainedEmittedRvaBytes = retainedRvaBytes,
                    configuredWorkingSetBytes = limits.maximumRetainedWorkingSetBytes,
                    authenticatedPerShardResidentBytes = authenticatedPerShardResidentBytes,
                )
            } catch (failure: ArithmeticException) {
                throw FullTreeFunctionTruthV3Exception("truth-v3 emitted-RVA collection working-set model overflows", failure)
            } catch (failure: IllegalArgumentException) {
                throw FullTreeFunctionTruthV3Exception(
                    "truth-v3 emitted-RVA collection exceeds its admitted retained-working-set budget",
                    failure,
                )
            }
            val bytes = readBoundedFile(truthPath, limits.truth.maximumOutputBytes, "legacy truth shard")
            val truth = parseV3Object(bytes, bytes.size.toLong(), "legacy truth shard")
            val functions = truth.v3Array("functions")
            functions.forEachIndexed { functionIndex, rawFunction ->
                if ((functionIndex and 255) == 0) deadline.checkpoint("while collecting emitted RVAs for $shardId")
                val function = rawFunction as? JsonObject ?: v3Fail("truth function row is not an object")
                val rva = function.v3String("rva")
                if (rvas.contains(rva)) v3Fail("truth-v3 full run repeats an emitted RVA score row")
                val nextCount = Math.addExact(rvas.size.toLong(), 1L)
                if (nextCount > maximumTruthEntities) v3Fail("truth-v3 emitted RVA population exceeds its authenticated entity bound")
                val nextRetainedBytes = Math.multiplyExact(nextCount, V3_EMITTED_RVA_SET_ENTRY_BYTES)
                if (nextRetainedBytes > maximumSetBytes) {
                    v3Fail("truth-v3 full-run emitted-RVA set exceeds its retained-working-set allowance")
                }
                rvas += rva
            }
            }
        }
        val retainedBytes = Math.multiplyExact(rvas.size.toLong(), V3_EMITTED_RVA_SET_ENTRY_BYTES)
        return V3EmittedRvaPopulation(rvas, retainedBytes)
    }

    /** Admit concurrently live JSON graphs; serialized-output ceilings are checked against exact bytes later. */
    private fun admitV3ShardWorkingSet(
        authenticatedObservationBytes: Long,
        emittedTruthBytes: Long,
        projectedShardBytes: Long,
        retainedControlBytes: Long,
        authenticatedPerShardResidentBytes: Long,
        limits: FullTreeFunctionTruthV3Limits,
        retainedSingleCopyBytes: Long = 0L,
    ) {
        if (authenticatedObservationBytes <= 0L || emittedTruthBytes < 0L || projectedShardBytes <= 0L ||
            retainedControlBytes < 0L || retainedSingleCopyBytes < 0L
        ) {
            v3Fail("truth-v3 shard has invalid pre-admission byte sizes")
        }
        val modeled = try {
            fullTreeFunctionTruthV3AdmitShardWorkingSet(
                authenticatedObservationBytes,
                emittedTruthBytes,
                projectedShardBytes,
                retainedControlBytes,
                limits.maximumRetainedWorkingSetBytes,
                authenticatedPerShardResidentBytes,
                retainedSingleCopyBytes,
            )
        } catch (failure: ArithmeticException) {
            throw FullTreeFunctionTruthV3Exception("truth-v3 shard working-set model overflows", failure)
        } catch (failure: IllegalArgumentException) {
            throw FullTreeFunctionTruthV3Exception("truth-v3 shard exceeds its admitted retained-working-set budget", failure)
        }
        if (modeled <= 0L) v3Fail("truth-v3 shard working-set estimate is not positive")
    }

    private fun addV3Bounded(total: Long, amount: Long, bound: Long): Long {
        val next = try { Math.addExact(total, amount) } catch (failure: ArithmeticException) {
            throw FullTreeFunctionTruthV3Exception("truth-v3 byte accounting overflows", failure)
        }
        if (next > bound) v3Fail("truth-v3 artifact exceeds its output-byte bound")
        return next
    }

    private fun hashV3File(path: Path): Pair<String, Long> {
        val digest = MessageDigest.getInstance("SHA-256")
        var size = 0L
        Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                FullTreeOracleOperationCheckpoint.checkpoint("while hashing truth-v3 member ${path.fileName}")
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
                size = Math.addExact(size, read.toLong())
            }
        }
        return digest.digest().joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') } to size
    }

    private fun requireV3OutputDisjoint(output: Path, protected: List<Path>) {
        if (output.parent == null || output.fileName == null) v3Fail("truth-v3 output root must name a directory")
        val normalized = output.toAbsolutePath().normalize()
        protected.forEach { path ->
            val input = path.toAbsolutePath().normalize()
            if (normalized == input || normalized.startsWith(input) || input.startsWith(normalized)) {
                v3Fail("truth-v3 output overlaps an authenticated input or scratch path")
            }
        }
    }

    private fun countObject(values: Map<String, Long>): JsonObject = JsonObject(
        values.toSortedMap().mapValues { JsonPrimitive(it.value) },
    )

    private fun requireV3Sha(value: String, label: String) {
        if (!value.matches(Regex("[0-9a-f]{64}"))) v3Fail("$label must be a lowercase SHA-256 digest")
    }

    private inline fun <T> runV3(action: () -> T): T = try {
        action()
    } catch (failure: FullTreeFunctionTruthV3Exception) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeFunctionTruthV3Exception("cannot derive or validate function truth v3", failure)
    }

    private fun v3Fail(message: String): Nothing = throw FullTreeFunctionTruthV3Exception(message)

    private class V3RunDeadline private constructor(
        private val startedWallNanos: Long,
        private val startedCpuNanos: Long,
        private val maximumWallNanos: Long,
        private val maximumCpuNanos: Long,
        private val maximumResidentBytes: Long,
        private val maximumShardResidentBytes: Long,
        private val maximumShardWallNanos: Long,
        private val maximumShardCpuNanos: Long,
    ) : FullTreeOracleShardPhaseObserver {
        private val shardLedger = FullTreeFunctionTruthV3ShardPhaseLedger(maximumShardWallNanos, maximumShardCpuNanos)

        fun checkpoint(stage: String) {
            if (Thread.currentThread().isInterrupted) {
                v3Fail("truth-v3 operation was interrupted $stage")
            }
            val wall = System.nanoTime() - startedWallNanos
            val cpu = truthV3ProcessCpuNanos() - startedCpuNanos
            if (wall < 0L || wall > maximumWallNanos) {
                v3Fail("truth-v3 operation exceeded its authenticated whole-run wall-clock bound $stage")
            }
            if (cpu < 0L || cpu > maximumCpuNanos) {
                v3Fail("truth-v3 operation exceeded its authenticated whole-run CPU bound $stage")
            }
            val resident = try {
                LinuxResidentMemory.sampleSelf()
            } catch (failure: Exception) {
                throw FullTreeFunctionTruthV3Exception("truth-v3 resident-memory sample is unavailable $stage", failure)
            }
            try {
                fullTreeFunctionTruthV3CheckResidentBytes(
                    resident.currentBytes,
                    resident.highWaterBytes,
                    maximumResidentBytes,
                    maximumShardResidentBytes.takeIf { shardLedger.activeShardCount() > 0 },
                )
            } catch (failure: IllegalArgumentException) {
                throw FullTreeFunctionTruthV3Exception("${failure.message} $stage", failure)
            }
        }

        fun beginShard(shardId: String): String {
            checkpoint("before shard $shardId")
            beginShardPhase(shardId)
            return shardId
        }

        @Synchronized
        override fun beginShardPhase(shardId: String) {
            checkpoint("before shard phase $shardId")
            shardLedger.beginShardPhase(shardId)
            checkpoint("after starting shard phase $shardId")
        }

        @Synchronized
        override fun endShardPhase(shardId: String) {
            checkpoint("before ending shard phase $shardId")
            shardLedger.endShardPhase(shardId)
            checkpoint("after ending shard phase $shardId")
        }

        fun finishShard(start: String, shardId: String) {
            if (start != shardId) v3Fail("truth-v3 shard timer identity changed")
            checkpoint("after shard $shardId")
            endShardPhase(shardId)
        }

        companion object {
            fun start(scope: AuthenticatedFullTreeScope, limits: FullTreeFunctionTruthV3Limits): V3RunDeadline {
                val wholeRun = scope.document.controlObject("bounds").controlObject("wholeRun")
                val perShard = scope.document.controlObject("bounds").controlObject("perShard")
                return V3RunDeadline(
                    startedWallNanos = System.nanoTime(),
                    startedCpuNanos = truthV3ProcessCpuNanos(),
                    maximumWallNanos = Math.multiplyExact(wholeRun.controlLong("wallClockSeconds"), 1_000_000_000L),
                    maximumCpuNanos = Math.multiplyExact(wholeRun.controlLong("cpuSeconds"), 1_000_000_000L),
                    maximumResidentBytes = minOf(
                        wholeRun.controlLong("maximumResidentBytes"),
                        limits.maximumRetainedWorkingSetBytes,
                    ),
                    maximumShardResidentBytes = fullTreeFunctionTruthV3WorkingSetCeiling(
                        minOf(wholeRun.controlLong("maximumResidentBytes"), limits.maximumRetainedWorkingSetBytes),
                        perShard.controlLong("maximumResidentBytes"),
                    ),
                    maximumShardWallNanos = Math.multiplyExact(perShard.controlLong("wallClockSeconds"), 1_000_000_000L),
                    maximumShardCpuNanos = Math.multiplyExact(perShard.controlLong("cpuSeconds"), 1_000_000_000L),
                )
            }
        }
    }

    private data class V3Projection(
        val root: Path,
        val index: JsonObject,
        val indexBytes: ByteArray,
        val indexArtifactSha256: String,
        val indexSha256: String,
        val outputBytes: Long,
        val counts: FullTreeFunctionTruthV3Counts,
        val elfIndexArtifactSha256: String,
    )

    internal data class V3ExpectedTreeMember(val bytes: Long, val sha256: String)

    /**
     * Pins every path identity and byte digest in an authenticated run or candidate tree. The
     * private copy is the only tree read during projection/comparison; the caller's original tree
     * is re-enumerated and rehashed at the final publication/return boundary.
     */
    internal class V3StableTreeSnapshot private constructor(
        private val sourceRoot: Path,
        val root: Path,
        private val rootIdentity: Any,
        private val directoryIdentities: Map<String, Any>,
        private val files: Map<String, V3TreeFileIdentity>,
        private val allowedDirectories: Set<String>,
        private val allowedRootFiles: Set<String>,
        private val maximumFiles: Long,
        private val maximumBytes: Long,
        val totalBytes: Long,
        private val privateSnapshotIdentity: V3PrivateSnapshotIdentity? = null,
    ) {
        fun verifyIdentity(checkpoint: (String) -> Unit = {}) {
            val current = enumerate(
                sourceRoot, allowedDirectories, allowedRootFiles, maximumFiles, maximumBytes, checkpoint,
            )
            if (current.rootIdentity != rootIdentity || current.directoryIdentities != directoryIdentities ||
                current.files.mapValues { (_, file) -> file.fileIdentity to file.bytes } !=
                files.mapValues { (_, file) -> file.fileIdentity to file.bytes }
            ) {
                FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 authenticated input tree identities or membership changed")
            }
        }

        fun verifyOriginalUnchanged(checkpoint: (String) -> Unit = {}) {
            verifyPrivateSnapshotUnchanged(checkpoint)
            verifyIdentity(checkpoint)
            files.forEach { (relative, expected) ->
                FullTreeFunctionTruthSqliteV3.withV3TreeMemberPhase(relative) {
                checkpoint("while rechecking pinned truth-v3 input member $relative")
                val path = sourceRoot.resolve(relative)
                StableControlFile.open(path, maximumBytes, "truth-v3 pinned member $relative").use { guard ->
                    if (guard.size != expected.bytes || guard.authenticatedSha256 != expected.sha256) {
                        FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 pinned input member changed bytes at $relative")
                    }
                    guard.verifyUnchanged("truth-v3 pinned input member $relative")
                }
                }
            }
            verifyIdentity(checkpoint)
            verifyPrivateSnapshotUnchanged(checkpoint)
        }

        fun verifyPrivateSnapshotUnchanged(checkpoint: (String) -> Unit = {}) {
            val pinned = privateSnapshotIdentity
                ?: FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 private snapshot has not been created")
            val current = enumerate(root, allowedDirectories, allowedRootFiles, maximumFiles, maximumBytes, checkpoint)
            if (current.rootIdentity != pinned.rootIdentity || current.directoryIdentities != pinned.directoryIdentities ||
                current.files.mapValues { (_, file) -> file.fileIdentity to file.bytes } !=
                pinned.files.mapValues { (_, file) -> file.fileIdentity to file.bytes }
            ) {
                FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 private snapshot identities or membership changed")
            }
            files.forEach { (relative, expected) ->
                FullTreeFunctionTruthSqliteV3.withV3TreeMemberPhase(relative) {
                checkpoint("while rechecking private truth-v3 snapshot member $relative")
                StableControlFile.open(root.resolve(relative), maximumBytes, "truth-v3 private snapshot member $relative").use { guard ->
                    if (guard.size != expected.bytes || guard.authenticatedSha256 != expected.sha256) {
                        FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 private snapshot changed bytes at $relative")
                    }
                    guard.verifyUnchanged("truth-v3 private snapshot member $relative")
                }
                }
            }
        }

        fun createSnapshot(
            originalRoot: Path,
            destination: Path,
            expectedDirectories: Set<String>,
            expectedFiles: Map<String, V3ExpectedTreeMember>?,
            checkpoint: (String) -> Unit,
            maximumSnapshotBytes: Long = maximumBytes,
        ): V3StableTreeSnapshot {
            if (originalRoot.toAbsolutePath().normalize() != sourceRoot) {
                FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 snapshot source differs from its authenticated tree")
            }
            if (expectedDirectories != allowedDirectories || maximumSnapshotBytes <= 0L || maximumSnapshotBytes > maximumBytes) {
                FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 snapshot directory or byte bound differs from its authenticated tree")
            }
            verifyIdentity(checkpoint)
            if (expectedFiles != null && expectedFiles.keys != files.keys) {
                FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 snapshot member set differs from authenticated evidence")
            }
            if (totalBytes > maximumSnapshotBytes) FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 snapshot exceeds its byte bound")
            Files.createDirectory(destination, PosixFilePermissions.asFileAttribute(V3_WRITABLE_DIRECTORY))
            expectedDirectories.sorted().forEach { directory ->
                Files.createDirectory(destination.resolve(directory), PosixFilePermissions.asFileAttribute(V3_WRITABLE_DIRECTORY))
            }
            val copied = TreeMap<String, V3TreeFileIdentity>()
            files.forEach { (relative, source) ->
                FullTreeFunctionTruthSqliteV3.withV3TreeMemberPhase(relative) {
                checkpoint("before pinning truth-v3 tree member $relative")
                val expected = expectedFiles?.get(relative)
                if (expected != null && expected.bytes != source.bytes) {
                    FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 authenticated member byte count differs at $relative")
                }
                StableControlFile.open(source.path, maximumBytes, "truth-v3 snapshot source $relative").use { guard ->
                    if (guard.size != source.bytes || source.fileIdentity != identityOf(source.path)) {
                        FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 source member identity changed before snapshot at $relative")
                    }
                    val digest = MessageDigest.getInstance("SHA-256")
                    val target = destination.resolve(relative)
                    FileChannel.open(target, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { channel ->
                        val buffer = ByteArray(64 * 1024)
                        var position = 0L
                        while (position < guard.size) {
                            val amount = guard.readAt(position, buffer, 0, minOf(buffer.size.toLong(), guard.size - position).toInt())
                            if (amount <= 0) FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 source member ended while pinning $relative")
                            digest.update(buffer, 0, amount)
                            var pending = ByteBuffer.wrap(buffer, 0, amount)
                            while (pending.hasRemaining()) channel.write(pending)
                            position = Math.addExact(position, amount.toLong())
                            checkpoint("while pinning truth-v3 tree member $relative")
                        }
                        channel.force(true)
                    }
                    val sha256 = digest.digest().joinToString("") { "%02x".format(it) }
                    if (guard.authenticatedSha256 != sha256 || expected?.sha256?.let { it != sha256 } == true) {
                        FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 snapshot member digest differs from authenticated evidence at $relative")
                    }
                    guard.verifyUnchanged("truth-v3 snapshot source $relative")
                    if (identityOf(source.path) != source.fileIdentity) {
                        FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 source member path changed while pinning $relative")
                    }
                    Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("r--------"))
                    copied[relative] = V3TreeFileIdentity(target, source.fileIdentity, source.bytes, sha256)
                }
                }
            }
            verifyIdentity(checkpoint)
            val snapshotDirectoryPermissions = PosixFilePermissions.fromString("r-x------")
            expectedDirectories.sortedDescending().forEach { directory ->
                Files.setPosixFilePermissions(destination.resolve(directory), snapshotDirectoryPermissions)
            }
            Files.setPosixFilePermissions(destination, snapshotDirectoryPermissions)
            val snapshotAttributes = enumerate(
                destination, expectedDirectories, allowedRootFiles, maximumFiles, maximumSnapshotBytes, checkpoint,
            )
            if (snapshotAttributes.files.keys != copied.keys || snapshotAttributes.totalBytes != totalBytes) {
                FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 private snapshot membership differs after pinning")
            }
            val stableSnapshotFiles = TreeMap<String, V3TreeFileIdentity>().apply {
                snapshotAttributes.files.forEach { (relative, member) ->
                    put(relative, member.copy(sha256 = copied.getValue(relative).sha256))
                }
            }
            return V3StableTreeSnapshot(
                sourceRoot,
                destination.toAbsolutePath().normalize(),
                rootIdentity,
                directoryIdentities,
                copied,
                allowedDirectories,
                allowedRootFiles,
                maximumFiles,
                maximumSnapshotBytes,
                totalBytes,
                V3PrivateSnapshotIdentity(
                    snapshotAttributes.rootIdentity,
                    snapshotAttributes.directoryIdentities,
                    stableSnapshotFiles,
                ),
            )
        }

        companion object {
            fun captureIdentity(
                root: Path,
                allowedDirectories: Set<String>,
                maximumFiles: Long,
                maximumBytes: Long,
                checkpoint: (String) -> Unit,
                allowedRootFiles: Set<String>,
            ): V3StableTreeSnapshot {
                if (maximumFiles < 1L || maximumBytes <= 0L) FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 tree identity bound is invalid")
                val metadata = enumerate(root, allowedDirectories, allowedRootFiles, maximumFiles, maximumBytes, checkpoint)
                return V3StableTreeSnapshot(
                    root.toAbsolutePath().normalize(), root.toAbsolutePath().normalize(), metadata.rootIdentity,
                    metadata.directoryIdentities, metadata.files, allowedDirectories, allowedRootFiles,
                    maximumFiles, maximumBytes, metadata.totalBytes,
                )
            }

            private fun enumerate(
                root: Path,
                allowedDirectories: Set<String>,
                allowedRootFiles: Set<String>,
                maximumFiles: Long,
                maximumBytes: Long,
                checkpoint: (String) -> Unit,
            ): V3TreeMetadata {
                val (normalizedRoot, rootIdentity) = try {
                    requireStableDirectory(root, "truth-v3 pinned tree root")
                } catch (failure: Exception) {
                    throw FullTreeFunctionTruthV3Exception("truth-v3 pinned tree root is not stable", failure)
                }
                val directories = TreeMap<String, Any>()
                val files = TreeMap<String, V3TreeFileIdentity>()
                var bytes = 0L
                Files.walk(normalizedRoot).use { paths ->
                    paths.filter { it != normalizedRoot }.forEach { path ->
                        checkpoint("while enumerating truth-v3 pinned tree")
                        val relative = normalizedRoot.relativize(path).toString().replace('\\', '/')
                        FullTreeFunctionTruthSqliteV3.withV3TreeMemberPhase(relative) {
                        if (Files.isSymbolicLink(path)) FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 pinned tree contains a symbolic link")
                        val depth = relative.count { it == '/' }
                        val attrs = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                        if (attrs.isDirectory) {
                            if (depth != 0 || relative !in allowedDirectories) {
                                FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 pinned tree has an unexpected directory")
                            }
                            val identity = attrs.fileKey() ?: FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 pinned directory identity is unavailable")
                            directories[relative] = identity
                        } else if (attrs.isRegularFile) {
                            if (depth > 1 || (depth == 0 && relative !in allowedRootFiles) ||
                                (depth == 1 && relative.substringBefore('/') !in allowedDirectories)
                            ) {
                                FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 pinned tree has an unexpected file path")
                            }
                            if (files.size >= maximumFiles) FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 pinned tree exceeds its member-count bound")
                            if (attrs.size() <= 0L) FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 pinned tree contains an empty member")
                            bytes = FullTreeFunctionTruthSqliteV3.addV3Bounded(bytes, attrs.size(), maximumBytes)
                            FullTreeFunctionTruthSqliteV3.requireV3StableTreeFile(path)
                            val identity = attrs.fileKey() ?: FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 pinned file identity is unavailable")
                            files[relative] = V3TreeFileIdentity(path, identity, attrs.size(), "")
                        } else {
                            FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 pinned tree contains a non-regular member")
                        }
                        }
                    }
                }
                if (directories.keys != allowedDirectories || files.keys.any { it.substringBefore('/') !in allowedDirectories && '/' in it } ||
                    files.keys.filter { '/' !in it }.toSet() != allowedRootFiles
                ) {
                    FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 pinned tree membership differs from its permitted layout")
                }
                requireDirectoryIdentity(normalizedRoot, rootIdentity, "truth-v3 pinned tree root")
                directories.forEach { (relative, identity) ->
                    requireDirectoryIdentity(normalizedRoot.resolve(relative), identity, "truth-v3 pinned directory $relative")
                }
                return V3TreeMetadata(rootIdentity, directories, files, bytes)
            }

            private fun identityOf(path: Path): Any {
                val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
                    FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 file identity is unavailable")
                }
                return checkNotNull(attributes.fileKey())
            }
        }
    }

    private data class V3TreeFileIdentity(val path: Path, val fileIdentity: Any, val bytes: Long, val sha256: String)

    private data class V3TreeMetadata(
        val rootIdentity: Any,
        val directoryIdentities: Map<String, Any>,
        val files: Map<String, V3TreeFileIdentity>,
        val totalBytes: Long,
    )

    private data class V3PrivateSnapshotIdentity(
        val rootIdentity: Any,
        val directoryIdentities: Map<String, Any>,
        val files: Map<String, V3TreeFileIdentity>,
    )

    internal class V3RawInputGuards private constructor(
        private val inputs: List<Pair<String, StableControlFile>>,
    ) : AutoCloseable {
        fun verifyUnchanged(label: String) {
            inputs.forEach { (name, guard) -> guard.verifyUnchanged("truth-v3 $name $label") }
        }

        override fun close() {
            var failure: Throwable? = null
            inputs.asReversed().forEach { (_, guard) ->
                try {
                    guard.close()
                } catch (closeFailure: Throwable) {
                    if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
                }
            }
            failure?.let { throw it }
        }

        companion object {
            fun open(
                richArtifact: Path,
                strippedArtifact: Path,
                inventoryPath: Path,
                elfFunctionIndex: Path,
                limits: FullTreeFunctionTruthV3Limits,
            ): V3RawInputGuards {
                val specs = listOf(
                    Triple("rich artifact", richArtifact, limits.truth.control.maximumRichArtifactBytes),
                    Triple("stripped artifact", strippedArtifact, limits.truth.control.maximumRichArtifactBytes),
                    Triple("inventory", inventoryPath, limits.truth.control.maximumInventoryBytes.toLong()),
                    Triple("ELF function index", elfFunctionIndex, limits.truth.maximumElfIndexBytes),
                )
                val opened = ArrayList<Pair<String, StableControlFile>>(specs.size)
                try {
                    specs.forEach { (label, path, maximumBytes) ->
                        opened += label to StableControlFile.openWithCheckpoint(
                            path,
                            maximumBytes,
                            "truth-v3 $label",
                            FullTreeOracleOperationCheckpoint::checkpoint,
                        )
                    }
                    return V3RawInputGuards(opened)
                } catch (failure: Throwable) {
                    opened.asReversed().forEach { (_, guard) -> runCatching { guard.close() } }
                    throw failure
                }
            }
        }
    }

    private class V3Workspace private constructor(val root: Path) : AutoCloseable {
        override fun close() {
            if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
            makeV3Writable(root)
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }

        companion object {
            fun create(parent: Path): V3Workspace {
                val root = Files.createTempDirectory(parent, ".function-truth-v3-", PosixFilePermissions.asFileAttribute(V3_WRITABLE_DIRECTORY))
                return V3Workspace(root)
            }
        }
    }

    private class V3Publication private constructor(
        private val target: Path,
        val staging: Path,
        private val parent: Path,
        private val parentIdentity: Any,
        private val stagingIdentity: Any,
        private val maximumBytes: Long,
    ) : AutoCloseable {
        private var committed = false
        private var published = false

        fun commit(
            projection: V3Projection,
            checkpoint: (String) -> Unit,
            verifyInputs: () -> Unit,
        ) {
            checkpoint("before committing truth-v3 publication")
            verifyInputs()
            if (projection.root != staging) FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 projection is outside its publication staging tree")
            if (projection.outputBytes > maximumBytes) FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 output exceeds its publication bound")
            val stagedSnapshot = FullTreeFunctionTruthSqliteV3.freezeAndVerifyV3Staging(
                staging, projection.index, projection.indexBytes, projection.outputBytes, checkpoint,
            )
            requireDirectoryIdentity(parent, parentIdentity, "truth-v3 publication parent")
            requireDirectoryIdentity(staging, stagingIdentity, "truth-v3 staging root")
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) v3Fail("truth-v3 output root already exists")
            FileChannel.open(staging, StandardOpenOption.READ).use { it.force(true) }
            FileChannel.open(staging.resolve("shards"), StandardOpenOption.READ).use { it.force(true) }
            FileChannel.open(parent, StandardOpenOption.READ).use { it.force(true) }
            LinuxFilesystemSyscalls.requireSupported(parent)
            LinuxFilesystemSyscalls.openRoot(parent).use { descriptor ->
                descriptor.whileOpen { parentFd ->
                    if (!Files.isSameFile(parent, LinuxFilesystemSyscalls.stableDescriptorPath(parentFd))) {
                        FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 output parent changed before publication")
                    }
                    LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, target.fileName.toString())?.use {
                        FullTreeFunctionTruthSqliteV3.v3Fail("truth-v3 output root already exists")
                    }
                    LinuxFilesystemSyscalls.synchronize(descriptor)
                    FullTreeFunctionTruthSqliteV3.reauthenticateV3Staging(
                        stagedSnapshot, projection.index, projection.indexBytes, projection.outputBytes, checkpoint,
                    )
                    try {
                        LinuxFilesystemSyscalls.renameNoReplace(parentFd, staging.fileName.toString(), target.fileName.toString())
                    } catch (failure: LinuxSyscallException) {
                        if (failure.errno == LinuxFilesystemSyscalls.EEXIST) {
                            throw FullTreeFunctionTruthV3Exception("truth-v3 output root already exists", failure)
                        }
                        throw failure
                    }
                    published = true
                }
                LinuxFilesystemSyscalls.synchronize(descriptor)
            }
            requireDirectoryIdentity(target, stagingIdentity, "truth-v3 published root")
            checkpoint("after truth-v3 publication rename")
            verifyInputs()
            committed = true
        }

        override fun close() {
            if (committed) return
            val root = if (published) target else staging
            if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
            requireDirectoryIdentity(root, stagingIdentity, "truth-v3 publication cleanup root")
            makeV3Writable(root)
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
            if (published) FullTreeFunctionTruthSqliteV3.v3Fail("unverified truth-v3 publication was revoked")
        }

        companion object {
            fun create(target: Path, maximumBytes: Long): V3Publication {
                val parent = target.parent ?: throw FullTreeFunctionTruthV3Exception("truth-v3 output must have a parent")
                val (_, parentIdentity) = requireStableDirectory(parent, "truth-v3 publication parent")
                if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                    throw FullTreeFunctionTruthV3Exception("truth-v3 output root already exists")
                }
                val staging = Files.createTempDirectory(
                    parent,
                    ".${target.fileName}.function-truth-v3-",
                    PosixFilePermissions.asFileAttribute(V3_WRITABLE_DIRECTORY),
                )
                val (_, stagingIdentity) = requireStableDirectory(staging, "truth-v3 staging root")
                return V3Publication(target, staging, parent, parentIdentity, stagingIdentity, maximumBytes)
            }
        }
    }
}

private fun truthV3ProcessCpuNanos(): Long = ProcessHandle.current().info().totalCpuDuration()
    .orElseThrow { FullTreeFunctionTruthV3Exception("truth-v3 process CPU duration is unavailable") }
    .toNanos()

private fun countObject(values: Map<String, Long>): JsonObject = JsonObject(values.toSortedMap().mapValues { JsonPrimitive(it.value) })

private fun makeV3Writable(root: Path) {
    Files.walk(root).use { paths ->
        paths.sorted(Comparator.reverseOrder()).forEach { path ->
            if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                Files.setPosixFilePermissions(path, V3_WRITABLE_DIRECTORY)
            } else {
                Files.setPosixFilePermissions(path, V3_WRITABLE_FILE)
            }
        }
    }
}

private fun makeV3ReadOnly(root: Path, checkpoint: (String) -> Unit = {}) {
    Files.walk(root).use { paths ->
        paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }
            .forEach { path ->
                checkpoint("while freezing truth-v3 member ${path.fileName}")
                Files.setPosixFilePermissions(path, V3_READ_ONLY_FILE)
            }
    }
    Files.walk(root).use { paths ->
        paths.filter { Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) }
            .sorted(Comparator.reverseOrder())
            .forEach { path ->
                checkpoint("while freezing truth-v3 directory ${path.fileName}")
                Files.setPosixFilePermissions(path, V3_READ_ONLY_DIRECTORY)
            }
    }
}

private fun requireDirectoryIdentity(path: Path, expected: Any, label: String) {
    val (_, actual) = requireStableDirectory(path, label)
    if (actual != expected) throw FullTreeFunctionTruthV3Exception("$label changed identity")
}

private val V3_WRITABLE_DIRECTORY = PosixFilePermissions.fromString("rwx------")
private val V3_WRITABLE_FILE = PosixFilePermissions.fromString("rw-------")
private val V3_PRIVATE_FILE = PosixFilePermissions.fromString("r--------")
private val V3_READ_ONLY_FILE = PosixFilePermissions.fromString("r--------")
private val V3_READ_ONLY_DIRECTORY = PosixFilePermissions.fromString("r-x------")

private fun JsonObject.v3Object(name: String): JsonObject =
    this[name] as? JsonObject ?: throw FullTreeFunctionTruthV3Exception("$name is not an object")

private fun JsonObject.v3Array(name: String): JsonArray =
    this[name] as? JsonArray ?: throw FullTreeFunctionTruthV3Exception("$name is not an array")

private fun JsonObject.v3String(name: String): String =
    (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
        ?: throw FullTreeFunctionTruthV3Exception("$name is not a string")

private fun JsonObject.v3Long(name: String): Long =
    (this[name] as? JsonPrimitive)?.longOrNull
        ?: throw FullTreeFunctionTruthV3Exception("$name is not an integer")
