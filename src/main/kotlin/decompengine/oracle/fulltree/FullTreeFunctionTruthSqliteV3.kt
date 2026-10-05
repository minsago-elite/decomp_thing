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
 * snapshots and per-shard index records. Persistent workspace files are charged to the disk bound.
 */
internal fun fullTreeFunctionTruthV3ModeledWorkingSetBytes(
    observationBytes: Long,
    legacyTruthBytes: Long,
    projectedShardBytes: Long,
    retainedControlBytes: Long,
): Long {
    require(observationBytes > 0L && legacyTruthBytes >= 0L && projectedShardBytes > 0L && retainedControlBytes >= 0L)
    return Math.addExact(
        96L * 1024L * 1024L,
        Math.addExact(
            Math.addExact(Math.multiplyExact(observationBytes, 4L), Math.multiplyExact(legacyTruthBytes, 3L)),
            Math.addExact(Math.multiplyExact(projectedShardBytes, 3L), Math.multiplyExact(retainedControlBytes, 2L)),
        ),
    )
}

internal fun fullTreeFunctionTruthV3AdmitWorkingSet(
    observationBytes: Long,
    legacyTruthBytes: Long,
    projectedShardBytes: Long,
    retainedControlBytes: Long,
    maximumRetainedBytes: Long,
): Long {
    require(maximumRetainedBytes > 0L)
    val modeled = fullTreeFunctionTruthV3ModeledWorkingSetBytes(
        observationBytes,
        legacyTruthBytes,
        projectedShardBytes,
        retainedControlBytes,
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
        FullTreeOracleOperationCheckpoint.withCheckpoint(deadline::checkpoint) {
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
            val initialRun = authenticateObservationV2(
                observationV2Root, expectedObservationV2IndexArtifactSha256, richArtifact, inventoryPath,
                scope, workspace.root, limits, deadline,
            )
            val (legacyTruth, v2Run) = deriveLegacyAndCensus(
                richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex, observationV2Root,
                expectedObservationV2IndexArtifactSha256, scope, workspace, initialRun, limits, deadline,
            )
            requireV3WorkspaceBound(workspace.root, limits)
            val publication = V3Publication.create(target, limits.maximumOutputBytes)
            try {
                val projection = composeV3Tree(
                    publication.staging,
                    legacyTruth.root,
                    observationV2Root,
                    v2Run,
                    legacyTruth,
                    scope,
                    workspace.root,
                    limits,
                    deadline,
                )
                requireV3WorkspaceBound(workspace.root, limits)
                revalidateLegacyTruth(
                    legacyTruth, richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex,
                    scope, workspace, v2Run.maximumWorkers, limits, deadline,
                )
                requireSameV2Reconciliation(
                    initialRun,
                    authenticateObservationV2(
                        observationV2Root, expectedObservationV2IndexArtifactSha256, richArtifact, inventoryPath,
                        scope, workspace.root, limits, deadline,
                    ),
                )
                deadline.checkpoint("before committing truth-v3 publication")
                publication.commit(projection, deadline::checkpoint) {
                    rawInputs.verifyUnchanged("at truth-v3 publication boundary")
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
        FullTreeOracleOperationCheckpoint.withCheckpoint(deadline::checkpoint) {
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
            val initialRun = authenticateObservationV2(
                observationV2Root, expectedObservationV2IndexArtifactSha256, richArtifact, inventoryPath,
                scope, workspace.root, limits, deadline,
            )
            val (legacyTruth, v2Run) = deriveLegacyAndCensus(
                richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex, observationV2Root,
                expectedObservationV2IndexArtifactSha256, scope, workspace, initialRun, limits, deadline,
            )
            requireV3WorkspaceBound(workspace.root, limits)
            val derivedRoot = workspace.root.resolve("derived-truth-v3")
            Files.createDirectory(derivedRoot, PosixFilePermissions.asFileAttribute(V3_WRITABLE_DIRECTORY))
            val projection = composeV3Tree(
                derivedRoot, legacyTruth.root, observationV2Root, v2Run, legacyTruth, scope, workspace.root, limits,
                deadline,
            )
            requireV3WorkspaceBound(workspace.root, limits)
            verifyV3Candidate(candidate, projection, candidateParent, candidateParentIdentity)
            revalidateLegacyTruth(
                legacyTruth, richArtifact, strippedArtifact, inventoryPath, elfFunctionIndex,
                    scope, workspace, v2Run.maximumWorkers, limits, deadline,
            )
            requireSameV2Reconciliation(
                initialRun,
                authenticateObservationV2(
                    observationV2Root, expectedObservationV2IndexArtifactSha256, richArtifact, inventoryPath,
                    scope, workspace.root, limits, deadline,
                ),
            )
            verifyV3Candidate(candidate, projection, candidateParent, candidateParentIdentity)
            rawInputs.verifyUnchanged("at truth-v3 candidate comparison boundary")
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
    ): Pair<FullTreeFunctionTruthGeneration, FullTreeFunctionObservationV2RunPublication> {
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
        return legacyTruth to v2Run
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
    ): FullTreeFunctionObservationV2RunPublication = try {
        deadline.checkpoint("before independently rederiving observation-v2")
        val availableScratchBytes = remainingV3Scratch(limits, scratchParent)
        val nestedLimits = limits.observationV2.copy(
            maximumScratchBytes = minOf(limits.observationV2.maximumScratchBytes, availableScratchBytes),
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
            .also { deadline.checkpoint("after independently rederiving observation-v2") }
    } catch (failure: Exception) {
        throw FullTreeFunctionTruthV3Exception(
            "observation-v2 run failed independent raw-input rederivation for truth v3",
            failure,
        )
    }

    private fun revalidateLegacyTruth(
        truth: FullTreeFunctionTruthGeneration,
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
            candidateRoot = truth.root,
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
        val prepared = ArrayList<BoundedShardPreparedOutput>(run.binding.outputs.size)
        var totalBytes = 0L
        run.binding.outputs.forEachIndexed { index, binding ->
            val shardStart = deadline.beginShard(binding.shardId, scope)
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
                    Files.size(run.binding.root.resolve("run.json")) + Files.size(run.binding.root.resolve("index.json")),
                ),
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
        val modeledAdapterPublishBytes = try {
            Math.addExact(Math.multiplyExact(totalBytes, 2L), 3L * limits.truth.observationRun.maximumControlArtifactBytes)
        } catch (failure: ArithmeticException) {
            throw FullTreeFunctionTruthV3Exception("truth-v3 observation adapter scratch model overflows", failure)
        }
        if (modeledAdapterPublishBytes > maximumScratchBound(limits) - currentScratchBytes) {
            v3Fail("truth-v3 observation adapter publication exceeds its remaining scratch bound")
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
        checkV3Scratch(workspace.root, maximumScratchBound(limits))
        return adapter
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
            limits.truth.maximumOutputBytes,
            v2Run.binding.run.v3Object("bounds").v3Long("wholeRunBytes"),
        )
        val projectedTotalOutputBytes = preflightV3RunOutputBytes(
            legacyRoot,
            observationV2Root,
            legacyIndex,
            v2Run,
            wholeRunOutputBound,
            deadline,
        )
        val truthEntities = Math.addExact(
            Math.addExact(legacyTruth.counts.elfRvas, legacyTruth.counts.dwarfOnlyRvas),
            legacyTruth.counts.nonEmittedUnique,
        )
        val wholeRunEntityBound = scope.document.controlObject("bounds").controlObject("wholeRun").controlLong("entities")
        var allSourceEntities = 0L
        var outputBytes = 0L
        val v3ShardRecords = ArrayList<JsonObject>(v2Run.binding.outputs.size)

        v2Run.binding.outputs.forEachIndexed { shardIndex, observation ->
            val shardStart = deadline.beginShard(observation.shardId, scope)
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
            val sourcePath = observationV2Root.resolve("outputs/$shardId.json")
            val truthPath = legacyRoot.resolve("shards/$shardId.json")
            val sourceFileBytes = Files.size(sourcePath)
            val truthFileBytes = Files.size(truthPath)
            val projectedShardBytes = projectedV3ShardBytes(sourceFileBytes, truthFileBytes)
            preflightV3ShardOutput(projectedShardBytes, minOf(
                wholeRunOutputBound,
                v2Run.binding.run.v3Object("bounds").v3Long("perShardBytes"),
            ))
            admitV3ShardWorkingSet(
                sourceFileBytes,
                truthFileBytes,
                projectedShardBytes,
                projectedV3ControlBytes(
                    v2Run.binding.outputs.size,
                    Files.size(legacyRoot.resolve("index.json")) + Files.size(legacyRoot.resolve("exclusions.json")) +
                        Files.size(observationV2Root.resolve("run.json")) + Files.size(observationV2Root.resolve("index.json")),
                ),
                limits,
            )
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

            val truthBytes = readBoundedFile(truthPath, limits.truth.maximumOutputBytes, "legacy truth shard")
            val truthDocument = parseV3Object(truthBytes, truthBytes.size.toLong(), "legacy truth shard")
            val emittedTruthFunctions = truthDocument.v3Array("functions").map { raw ->
                (raw as? JsonObject ?: v3Fail("truth function row is not an object")).v3String("rva")
            }
            val emittedTruthRvas = emittedTruthFunctions.toHashSet()
            if (emittedTruthRvas.size != emittedTruthFunctions.size) {
                v3Fail("v3 truth projection repeats an emitted RVA score row")
            }
            sourceRows.forEachIndexed { sourceIndex, raw ->
                if ((sourceIndex and 255) == 0) deadline.checkpoint("while reconciling source links for $shardId")
                val source = raw as? JsonObject ?: v3Fail("source entity $sourceIndex is not an object")
                if (source.v3String("denominatorDisposition") == FullTreeDenominatorDisposition.EMITTED_RVA_LINK.wireValue) {
                    val linkedRva = source["linkedEmittedRva"]?.let { (it as? JsonPrimitive)?.content }
                        ?: v3Fail("emitted source entity has no linked RVA")
                    if (linkedRva !in emittedTruthRvas) {
                        v3Fail("source census link does not name its one emitted truth row")
                    }
                }
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
        if (outputBytes > projectedTotalOutputBytes) {
            v3Fail("truth-v3 serialized output exceeds its preflighted whole-run projection")
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
        if (maximumScratchBound(limits) < limits.truth.maximumDatabaseBytes) {
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
            val actual = hashV3File(outputFiles.getValue(path))
            if (actual.first != record.v3String("sha256") || actual.second != record.v3Long("bytes")) {
                v3Fail("truth-v3 shard digest differs from its index")
            }
            total = addV3Bounded(total, actual.second, expectedOutputBytes)
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
        candidate: Path,
        expected: V3Projection,
        candidateParent: Path,
        candidateParentIdentity: Any,
    ) {
        requireDirectoryIdentity(candidateParent, candidateParentIdentity, "truth-v3 candidate parent")
        compareV3CandidateTreeBytes(
            candidate,
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
            FullTreeOracleOperationCheckpoint.checkpoint("while comparing truth-v3 candidate member $relative")
            val derived = expectedFiles.getValue(relative)
            if (Files.mismatch(file, derived) != -1L) v3Fail("truth-v3 candidate bytes differ from raw rederivation at $relative")
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

    private fun reserveV3OutputBytes(
        currentOutputBytes: Long,
        nextMemberBytes: Long,
        outputBound: Long,
    ): Long {
        return addV3Bounded(currentOutputBytes, nextMemberBytes, outputBound)
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

    private fun maximumScratchBound(limits: FullTreeFunctionTruthV3Limits): Long = minOf(
        limits.maximumScratchBytes,
        limits.truth.maximumScratchBytes,
        limits.observationV2.maximumScratchBytes,
    )

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

    private fun preflightV3RunOutputBytes(
        legacyRoot: Path,
        observationV2Root: Path,
        legacyIndex: JsonObject,
        v2Run: FullTreeFunctionObservationV2RunPublication,
        outputBound: Long,
        deadline: V3RunDeadline,
    ): Long {
        if (legacyIndex.v3Array("shards").size != v2Run.binding.outputs.size) {
            v3Fail("truth-v3 preflight shard populations differ")
        }
        var total = 0L
        val wholePerShardBound = v2Run.binding.run.v3Object("bounds").v3Long("perShardBytes")
        v2Run.binding.outputs.forEachIndexed { index, observation ->
            deadline.checkpoint("preflighting serialized truth-v3 shard ${observation.shardId}")
            val truthRecord = legacyIndex.v3Array("shards")[index] as? JsonObject
                ?: v3Fail("truth-v3 preflight has a non-object truth shard record")
            val shardId = truthRecord.v3String("id")
            if (shardId != observation.shardId) v3Fail("truth-v3 preflight shard order differs")
            val observationBytes = Files.size(observationV2Root.resolve("outputs/$shardId.json"))
            val truthBytes = Files.size(legacyRoot.resolve("shards/$shardId.json"))
            val projectedShard = projectedV3ShardBytes(observationBytes, truthBytes)
            preflightV3ShardOutput(projectedShard, minOf(outputBound, wholePerShardBound))
            total = addV3Bounded(total, projectedShard, outputBound)
        }
        val projectedExclusions = Math.addExact(Files.size(legacyRoot.resolve("exclusions.json")), V3_SHARD_ENVELOPE_BYTES)
        val projectedIndex = try {
            Math.addExact(
                Math.addExact(Files.size(legacyRoot.resolve("index.json")), Files.size(observationV2Root.resolve("index.json"))),
                projectedV3ControlBytes(v2Run.binding.outputs.size),
            )
        } catch (failure: ArithmeticException) {
            throw FullTreeFunctionTruthV3Exception("truth-v3 projected control artifact size overflows", failure)
        }
        total = addV3Bounded(total, projectedExclusions, outputBound)
        return addV3Bounded(total, projectedIndex, outputBound)
    }

    private fun preflightV3ShardOutput(projectedBytes: Long, outputBound: Long) {
        if (projectedBytes <= 0L || projectedBytes > outputBound) {
            v3Fail("truth-v3 projected serialized shard exceeds its authenticated output-byte bound")
        }
    }

    /** Admit copied JSON graphs and overlap scratch from file sizes before either input is retained. */
    private fun admitV3ShardWorkingSet(
        authenticatedObservationBytes: Long,
        emittedTruthBytes: Long,
        projectedShardBytes: Long,
        retainedControlBytes: Long,
        limits: FullTreeFunctionTruthV3Limits,
    ) {
        if (authenticatedObservationBytes <= 0L || emittedTruthBytes < 0L || projectedShardBytes <= 0L || retainedControlBytes < 0L) {
            v3Fail("truth-v3 shard has invalid pre-admission byte sizes")
        }
        val modeled = try {
            fullTreeFunctionTruthV3AdmitWorkingSet(
                authenticatedObservationBytes,
                emittedTruthBytes,
                projectedShardBytes,
                retainedControlBytes,
                limits.maximumRetainedWorkingSetBytes,
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
    ) {
        private val shardUsageNanos = HashMap<String, Pair<Long, Long>>()

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
            if (resident.currentBytes > maximumResidentBytes || resident.highWaterBytes > maximumResidentBytes) {
                v3Fail("truth-v3 operation exceeded its authenticated whole-run resident-memory bound $stage")
            }
        }

        fun beginShard(shardId: String, scope: AuthenticatedFullTreeScope): V3ShardStart {
            checkpoint("before shard $shardId")
            val perShard = scope.document.controlObject("bounds").controlObject("perShard")
            return V3ShardStart(
                shardId = shardId,
                wallNanos = System.nanoTime(),
                cpuNanos = truthV3ProcessCpuNanos(),
                maximumWallNanos = Math.multiplyExact(perShard.controlLong("wallClockSeconds"), 1_000_000_000L),
                maximumCpuNanos = Math.multiplyExact(perShard.controlLong("cpuSeconds"), 1_000_000_000L),
            )
        }

        fun finishShard(start: V3ShardStart, shardId: String) {
            checkpoint("after shard $shardId")
            if (start.shardId != shardId) v3Fail("truth-v3 shard timer identity changed")
            val wall = System.nanoTime() - start.wallNanos
            val cpu = truthV3ProcessCpuNanos() - start.cpuNanos
            val prior = shardUsageNanos[shardId] ?: (0L to 0L)
            val accumulated = try {
                fullTreeFunctionTruthV3AccumulateShardBudget(
                    prior.first,
                    prior.second,
                    wall,
                    cpu,
                    start.maximumWallNanos,
                    start.maximumCpuNanos,
                )
            } catch (failure: IllegalArgumentException) {
                throw FullTreeFunctionTruthV3Exception(
                    "truth-v3 shard $shardId exceeded its cumulative authenticated wall-clock or CPU bound",
                    failure,
                )
            }
            shardUsageNanos[shardId] = accumulated
        }

        data class V3ShardStart(
            val shardId: String,
            val wallNanos: Long,
            val cpuNanos: Long,
            val maximumWallNanos: Long,
            val maximumCpuNanos: Long,
        )

        companion object {
            fun start(scope: AuthenticatedFullTreeScope, limits: FullTreeFunctionTruthV3Limits): V3RunDeadline {
                val wholeRun = scope.document.controlObject("bounds").controlObject("wholeRun")
                return V3RunDeadline(
                    startedWallNanos = System.nanoTime(),
                    startedCpuNanos = truthV3ProcessCpuNanos(),
                    maximumWallNanos = Math.multiplyExact(wholeRun.controlLong("wallClockSeconds"), 1_000_000_000L),
                    maximumCpuNanos = Math.multiplyExact(wholeRun.controlLong("cpuSeconds"), 1_000_000_000L),
                    maximumResidentBytes = minOf(
                        wholeRun.controlLong("maximumResidentBytes"),
                        limits.maximumRetainedWorkingSetBytes,
                    ),
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
            FullTreeFunctionTruthSqliteV3.verifyV3IndexTree(staging, projection.index, projection.indexBytes, projection.outputBytes)
            makeV3ReadOnly(staging, checkpoint)
            checkpoint("after freezing truth-v3 publication staging")
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
