package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.Collections
import kotlinx.serialization.json.JsonObject

internal class FullTreeFunctionObservationV2RunException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

internal data class FullTreeFunctionObservationV2RunLimits(
    val shard: FullTreeFunctionObservationShardPublisherLimits = FullTreeFunctionObservationShardPublisherLimits(),
    val run: BoundedShardRunLimits = BoundedShardRunLimits(),
    val maximumScratchBytes: Long = 16L * 1024L * 1024L * 1024L,
    val maximumRunRetainedBytes: Long = 512L * 1024L * 1024L,
    val maximumAnchorClaims: Long = 4_000_000L,
) {
    init {
        require(maximumScratchBytes in 1L..64L * 1024L * 1024L * 1024L)
        require(maximumRunRetainedBytes in 1L..8L * 1024L * 1024L * 1024L)
        require(maximumAnchorClaims in 1L..50_000_000L)
    }
}

internal data class FullTreeFunctionObservationV2RetainedBudget(
    val anchorIndexBytes: Long,
    val sourceFactsBytes: Long,
)

internal data class FullTreeFunctionObservationV2ShardScratchBudget(
    val dwarfScratchBytes: Long,
    val outputBytes: Long,
    val databaseBytes: Long,
    val additionalScratchBytes: Long,
)

internal fun fullTreeFunctionObservationV2RetainedBudget(
    maximumRunRetainedBytes: Long,
    maximumResidentBytes: Long,
): FullTreeFunctionObservationV2RetainedBudget {
    require(maximumRunRetainedBytes > 0L && maximumResidentBytes > 0L)
    val anchorIndexBytes = minOf(maximumRunRetainedBytes / 2L, maximumResidentBytes / 8L).coerceAtLeast(1L)
    return FullTreeFunctionObservationV2RetainedBudget(
        anchorIndexBytes = anchorIndexBytes,
        sourceFactsBytes = minOf(maximumRunRetainedBytes - anchorIndexBytes, maximumResidentBytes / 4L),
    )
}

internal fun fullTreeFunctionObservationV2ShardScratchBudget(
    maximumScratchBytes: Long,
    preparedOutputBytes: Long,
    configuredDwarfScratchBytes: Long,
    configuredOutputBytes: Long,
    configuredDatabaseBytes: Long,
    sqlitePageBytes: Long = FULL_TREE_FUNCTION_OBSERVATION_SQLITE_PAGE_BYTES,
): FullTreeFunctionObservationV2ShardScratchBudget {
    require(
        maximumScratchBytes > 0L && preparedOutputBytes >= 0L && configuredDwarfScratchBytes > 0L &&
            configuredOutputBytes > 0L && configuredDatabaseBytes > 0L && sqlitePageBytes > 0L,
    )
    val outputBytes = minOf(configuredOutputBytes, FullTreeFunctionObservationsV2.MAXIMUM_CANONICAL_BYTES)
    val dwarfAllowance = maximumScratchBytes - preparedOutputBytes - outputBytes - sqlitePageBytes
    if (dwarfAllowance <= 0L) {
        v2RunFail("prepared observation-v2 outputs leave no decompression scratch and SQLite page budget")
    }
    val dwarfScratchBytes = minOf(configuredDwarfScratchBytes, dwarfAllowance)
    val databaseAllowance = maximumScratchBytes - preparedOutputBytes - dwarfScratchBytes - outputBytes
    val databaseBytes = minOf(configuredDatabaseBytes, databaseAllowance)
    if (databaseBytes < sqlitePageBytes) {
        v2RunFail("observation-v2 concurrent scratch leaves no SQLite database page")
    }
    return FullTreeFunctionObservationV2ShardScratchBudget(
        dwarfScratchBytes = dwarfScratchBytes,
        outputBytes = outputBytes,
        databaseBytes = databaseBytes,
        additionalScratchBytes = Math.addExact(preparedOutputBytes, dwarfScratchBytes),
    )
}

internal fun fullTreeFunctionObservationV2EffectiveWorkers(requestedWorkers: Int, shardCount: Int): Int {
    require(requestedWorkers > 0 && shardCount > 0)
    return minOf(requestedWorkers, shardCount)
}

internal data class FullTreeFunctionObservationV2ShardReceipt(
    val shardId: String,
    val inputSha256: String,
    val outputSha256: String,
    val outputBytes: Long,
    val emittedRvas: Long,
    val nonEmitted: Long,
    val sourceEntities: Long,
    val scannedDies: Long,
    val subprograms: Long,
    val databaseHighWaterBytes: Long,
)

/** Authenticated run receipt; all production/scoring authorities remain false for fixture evidence. */
internal class FullTreeFunctionObservationV2RunPublication internal constructor(
    val binding: BoundedShardRunBinding,
    val scopeSha256: String,
    val inventoryArtifactSha256: String,
    val richArtifactSha256: String,
    val reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
    outputs: List<FullTreeFunctionObservationV2ShardReceipt>,
    val maximumWorkers: Int,
) {
    val outputs: List<FullTreeFunctionObservationV2ShardReceipt> = Collections.unmodifiableList(outputs.toList())
    val sourceEntities: Long = outputs.fold(0L) { total, output -> Math.addExact(total, output.sourceEntities) }
    val emittedRvas: Long = outputs.fold(0L) { total, output -> Math.addExact(total, output.emittedRvas) }
    val nonEmitted: Long = outputs.fold(0L) { total, output -> Math.addExact(total, output.nonEmitted) }
    val outputBytes: Long = outputs.fold(0L) { total, output -> Math.addExact(total, output.outputBytes) }
    val fixtureOnly: Boolean = true
    val productionQualification: Boolean = false
    val authoritativeReleaseEvidence: Boolean = false
    val downstreamScoringAuthorized: Boolean = false
}

/**
 * Authenticated full-run observation-v2 producer. It first scans every shard's complete source
 * anchor population (including ordinary emitted definitions), reconciles collisions, and only
 * then publishes any observation-v2 shard.
 */
internal object FullTreeFunctionObservationV2RunPublisher {
    fun generateAndPublish(
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        scratchParent: Path,
        outputRoot: Path,
        maximumWorkers: Int = 1,
        limits: FullTreeFunctionObservationV2RunLimits = FullTreeFunctionObservationV2RunLimits(),
    ): FullTreeFunctionObservationV2RunPublication = translateV2RunFailure {
        require(maximumWorkers in 1..minOf(32, limits.shard.control.maximumWorkers, limits.run.maximumWorkers))
        FullTreeScopeControl.validate(scope, limits.shard.control)
        val target = outputRoot.toAbsolutePath().normalize()
        requireDistinctControlOutput(target, "rich artifact" to richArtifact, "inventory" to inventoryPath)
        requireStableDirectory(scratchParent, "observation-v2 scratch parent")
        val wholeRun = scope.document.controlObject("bounds").controlObject("wholeRun")
        val perShard = scope.document.controlObject("bounds").controlObject("perShard")
        val deadline = V2RunDeadline.start(scope, limits)

        StableControlFile.open(inventoryPath, limits.shard.control.maximumInventoryBytes.toLong(), "full-tree inventory").use { inventoryGuard ->
            StableControlFile.open(richArtifact, limits.shard.control.maximumRichArtifactBytes, "rich artifact").use { richGuard ->
                val inventoryBytes = inventoryGuard.readExactly(0L, inventoryGuard.size.toInt(), "full-tree inventory")
                val inventory = try {
                    OracleJson.parseCanonical(inventoryBytes, controlJsonLimits(limits.shard.control.maximumInventoryBytes)) as? JsonObject
                        ?: v2RunFail("full-tree inventory root is not an object")
                } catch (failure: FullTreeFunctionObservationV2RunException) {
                    throw failure
                } catch (failure: Exception) {
                    throw FullTreeFunctionObservationV2RunException("full-tree inventory is not strict canonical JSON", failure)
                }
                val inventorySha256 = OracleArtifacts.sha256(inventoryBytes)
                FullTreeInventoryControl.validate(inventory, scope, limits.shard.control)
                val richSha256 = richGuard.sha256(deadline::checkpoint, "rich artifact")
                if (richSha256 != scope.document.controlObject("oracle").controlString("richArtifactSha256")) {
                    v2RunFail("rich artifact does not match the authenticated scope")
                }
                val shards = FullTreeFunctionObservations.shardInputs(
                    inventory,
                    inventorySha256,
                    scope.document,
                    scope.sha256,
                )
                if (shards.size > limits.run.maximumShards) v2RunFail("observation-v2 shard count exceeds its bound")
                if (shards.isEmpty()) v2RunFail("observation-v2 run has no authenticated shards")
                val effectiveWorkers = fullTreeFunctionObservationV2EffectiveWorkers(maximumWorkers, shards.size)
                val retainedBudget = fullTreeFunctionObservationV2RetainedBudget(
                    limits.maximumRunRetainedBytes,
                    wholeRun.controlLong("maximumResidentBytes"),
                )

                val anchorIndex = FullTreeFunctionObservationV2AnchorIndex(
                    maximumClaims = minOf(
                        limits.maximumAnchorClaims,
                        minOf(wholeRun.controlLong("entities") * 64L, limits.maximumRunRetainedBytes / 256L),
                    ).coerceAtLeast(1L),
                    maximumRetainedBytes = retainedBudget.anchorIndexBytes,
                )
                val sourceFactsByShard = LinkedHashMap<String, List<FullTreeSourceEntityFact>>()
                val shardDeadlines = shards.associate { shard ->
                    shard.identifier to deadline.newShardBudget(scope)
                }
                var sourceFactCount = 0L
                var sourceFactAdmissionBytes = 0L
                var sourceFactCanonicalBytes = 0L
                var modeledRetainedBytes = 0L
                val retainedAdmission = retainedBudget.sourceFactsBytes
                val sourcePassControlLimits = limits.shard.control.copy(
                    maximumDwarfScratchBytes = minOf(
                        limits.shard.control.maximumDwarfScratchBytes,
                        limits.maximumScratchBytes,
                    ),
                )
                shards.forEach { shard ->
                    deadline.checkpoint("before extracting observation-v2 source entities")
                    val shardDeadline = shardDeadlines.getValue(shard.identifier)
                    val shardCheckpoint = shardDeadline.beginPhase()
                    val sourceCountBeforeShard = sourceFactCount
                    val scan = FullTreeSourceEntityIdentityProducer.scanShard(
                        richArtifact = richArtifact,
                        inventoryPath = inventoryPath,
                        scope = scope,
                        shardId = shard.identifier,
                        scratchParent = scratchParent,
                        controlLimits = sourcePassControlLimits,
                        producerLimits = limits.shard.producer,
                        checkpoint = shardCheckpoint,
                        anchorClaim = anchorIndex::accept,
                        factAdmission = { _, canonicalRowBytes ->
                            val nextCount = Math.addExact(sourceFactCount, 1L)
                            val nextAdmissionBytes = Math.addExact(sourceFactAdmissionBytes, canonicalRowBytes)
                            val modeledRowBytes = sourceIdentityModeledRetainedChargeBytes(
                                Math.addExact(canonicalRowBytes, 64L),
                            )
                            val nextRetained = Math.addExact(modeledRetainedBytes, modeledRowBytes)
                            if (nextCount > wholeRun.controlLong("entities") ||
                                nextAdmissionBytes > wholeRun.controlLong("serializedBytes")
                            ) {
                                v2RunFail("full-run source census exceeds its authenticated entity or byte bound")
                            }
                            if (nextRetained > retainedAdmission) {
                                v2RunFail("full-run source census exceeds its authenticated retained-working-set budget")
                            }
                            sourceFactCount = nextCount
                            sourceFactAdmissionBytes = nextAdmissionBytes
                            modeledRetainedBytes = nextRetained
                        },
                    )
                    if (scan.inventoryArtifactSha256 != inventorySha256 || scan.richArtifactSha256 != richSha256) {
                        v2RunFail("source-identity scan inputs differ from the authenticated run")
                    }
                    if (Math.subtractExact(sourceFactCount, sourceCountBeforeShard) != scan.facts.size.toLong()) {
                        v2RunFail("source-identity run admission count differs from the accepted shard facts")
                    }
                    sourceFactCanonicalBytes = Math.addExact(sourceFactCanonicalBytes, scan.canonicalBytes)
                    if (sourceFactCanonicalBytes > wholeRun.controlLong("serializedBytes")) {
                        v2RunFail("full-run source census exceeds its authenticated entity or byte bound")
                    }
                    sourceFactsByShard[shard.identifier] = scan.facts
                    deadline.sampleWholeRun("after extracting source entities for ${shard.identifier}")
                    inventoryGuard.verifyUnchanged("full-tree inventory after source-identity extraction")
                    richGuard.verifyUnchanged("rich artifact after source-identity extraction")
                    shardDeadline.endPhase("after source-identity extraction for ${shard.identifier}")
                }
                val reconciliation = anchorIndex.reconciliation()
                shards.forEach { shard ->
                    val original = sourceFactsByShard.getValue(shard.identifier)
                    val perShardBytes = minOf(perShard.controlLong("serializedBytes"), MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES)
                    val expansion = sourceIdentityCollisionExpansionUpperBound(original, reconciliation.collisionIdsByCandidate, perShardBytes)
                    if (expansion > perShardBytes - canonicalSourceEntityFactsByteLength(original, perShardBytes)) {
                        v2RunFail("full-run collision evidence exceeds the authenticated per-shard output bound")
                    }
                    val copyCharge = sourceIdentityCollisionAdjustedFactCopyUpperBound(
                        original,
                        reconciliation.collisionIdsByCandidate,
                        perShardBytes,
                    )
                    val copiedRetainedUpperBound = Math.addExact(copyCharge, expansion)
                    val copyModeled = sourceIdentityModeledRetainedChargeBytes(copiedRetainedUpperBound)
                    val peakRetained = Math.addExact(modeledRetainedBytes, copyModeled)
                    if (peakRetained > retainedAdmission) {
                        v2RunFail("full-run collision reconciliation exceeds the retained-working-set budget")
                    }
                    modeledRetainedBytes = peakRetained
                    val adjusted = reconcileObservationV2Facts(original, reconciliation)
                    val adjustedBytes = canonicalSourceEntityFactsByteLength(adjusted, perShardBytes)
                    if (adjustedBytes > perShardBytes) {
                        v2RunFail("reconciled source entities exceed the authenticated per-shard byte bound")
                    }
                    sourceFactsByShard[shard.identifier] = adjusted
                }
                inventoryGuard.verifyUnchanged("full-tree inventory before observation-v2 production")
                richGuard.verifyUnchanged("rich artifact before observation-v2 production")

                val prepared = V2PreparedWorkspace.create(scratchParent)
                try {
                    val receipts = ArrayList<FullTreeFunctionObservationV2ShardReceipt>(shards.size)
                    val boundedOutputs = ArrayList<BoundedShardPreparedOutput>(shards.size)
                    var preparedBytes = 0L
                    var preparedEntities = 0L
                    for (shard in shards) {
                        deadline.checkpoint("before producing observation-v2 shard ${shard.identifier}")
                        val shardDeadline = shardDeadlines.getValue(shard.identifier)
                        val shardCheckpoint = shardDeadline.beginPhase()
                        val inputs = FullTreeFunctionObservationAuthenticatedInputs(
                            inventory,
                            inventorySha256,
                            shard,
                        )
                        val effective = deriveAuthenticatedLimits(scope, inputs, limits.shard)
                        val scratchBudget = fullTreeFunctionObservationV2ShardScratchBudget(
                            maximumScratchBytes = limits.maximumScratchBytes,
                            preparedOutputBytes = preparedBytes,
                            configuredDwarfScratchBytes = limits.shard.control.maximumDwarfScratchBytes,
                            configuredOutputBytes = effective.maximumOutputBytes,
                            configuredDatabaseBytes = effective.maximumDatabaseBytes,
                        )
                        val perShardLimits = authenticatedV2SqliteLimits(
                            limits,
                            effective,
                            shardCheckpoint,
                            scratchBudget,
                        )
                        val producerControlLimits = limits.shard.control.copy(
                            maximumDwarfScratchBytes = scratchBudget.dwarfScratchBytes,
                        )
                        val shardFile = prepared.output(shard.identifier)
                        val streamResult: FullTreeFunctionObservationV2StreamResult
                        var scanResult: FullTreeFunctionObservationArtifactScan? = null
                        var result: FullTreeFunctionObservationV2StreamResult? = null
                        FileChannel.open(shardFile, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { channel ->
                            Files.setPosixFilePermissions(shardFile, PRIVATE_OUTPUT_PERMISSIONS)
                            val output = Channels.newOutputStream(channel)
                            FullTreeFunctionObservationSqliteV2.open(scratchParent, shard, perShardLimits).use { sink ->
                                val pair = FullTreeFunctionObservationProducer.scanAuthenticatedShardV2(
                                    richArtifact = richArtifact,
                                    scope = scope,
                                    inputs = inputs,
                                    scratchParent = scratchParent,
                                    controlLimits = producerControlLimits,
                                    producerLimits = effective.producer,
                                    sink = sink,
                                    sourceFacts = sourceFactsByShard.getValue(shard.identifier),
                                    reconciliation = reconciliation,
                                    output = output,
                                    checkpoint = shardCheckpoint,
                                )
                                scanResult = pair.first
                                result = pair.second
                            }
                            output.flush()
                            channel.force(true)
                            streamResult = result ?: v2RunFail("observation-v2 sink returned no receipt")
                        }
                        val scan = scanResult ?: v2RunFail("observation-v2 producer returned no scan receipt")
                        Files.setPosixFilePermissions(shardFile, READ_ONLY_OUTPUT_PERMISSIONS)
                        val observed = hashAndSize(shardFile)
                        if (observed.first != streamResult.outputSha256 || observed.second != streamResult.outputBytes) {
                            v2RunFail("prepared observation-v2 bytes differ from the streaming receipt")
                        }
                        preparedBytes = Math.addExact(preparedBytes, streamResult.outputBytes)
                        val entityCount = Math.addExact(
                            Math.addExact(streamResult.emitted, streamResult.nonEmitted),
                            streamResult.sourceEntities,
                        )
                        preparedEntities = Math.addExact(preparedEntities, entityCount)
                        if (preparedBytes > wholeRun.controlLong("serializedBytes") ||
                            preparedEntities > wholeRun.controlLong("entities")
                        ) {
                            v2RunFail("observation-v2 run exceeds its authenticated whole-run bounds")
                        }
                        val scratchUse = Math.addExact(
                            Math.addExact(preparedBytes, streamResult.databaseHighWaterBytes),
                            scratchBudget.dwarfScratchBytes,
                        )
                        if (scratchUse > limits.maximumScratchBytes) {
                            v2RunFail("observation-v2 outputs, database, and decompression scratch exceed the scratch bound")
                        }
                        val receipt = FullTreeFunctionObservationV2ShardReceipt(
                            shardId = shard.identifier,
                            inputSha256 = shard.inputSha256,
                            outputSha256 = streamResult.outputSha256,
                            outputBytes = streamResult.outputBytes,
                            emittedRvas = streamResult.emitted,
                            nonEmitted = streamResult.nonEmitted,
                            sourceEntities = streamResult.sourceEntities,
                            scannedDies = streamResult.scannedDies,
                            subprograms = scan.subprograms,
                            databaseHighWaterBytes = streamResult.databaseHighWaterBytes,
                        )
                        receipts += receipt
                        boundedOutputs += BoundedShardPreparedOutput(
                            shardId = shard.identifier,
                            inputSha256 = shard.inputSha256,
                            output = shardFile,
                            outputSha256 = streamResult.outputSha256,
                            outputBytes = streamResult.outputBytes,
                            entities = entityCount,
                        )
                        deadline.sampleWholeRun("after producing observation-v2 shard ${shard.identifier}")
                        inventoryGuard.verifyUnchanged("full-tree inventory after observation-v2 shard")
                        richGuard.verifyUnchanged("rich artifact after observation-v2 shard")
                        shardDeadline.endPhase("after observation-v2 shard ${shard.identifier}")
                    }

                    val runBounds = BoundedShardRunPublicationBounds(
                        maximumShards = shards.size,
                        perShardEntities = perShard.controlLong("entities"),
                        wholeRunEntities = wholeRun.controlLong("entities"),
                        perShardBytes = perShard.controlLong("serializedBytes"),
                        wholeRunBytes = wholeRun.controlLong("serializedBytes"),
                        perShardSeconds = perShard.controlLong("wallClockSeconds").toDouble(),
                        wholeRunSeconds = wholeRun.controlLong("wallClockSeconds").toDouble(),
                        perShardCpuSeconds = perShard.controlLong("cpuSeconds").toDouble(),
                        wholeRunCpuSeconds = wholeRun.controlLong("cpuSeconds").toDouble(),
                        maximumResidentBytes = wholeRun.controlLong("maximumResidentBytes"),
                        maximumWorkers = effectiveWorkers,
                    )
                    val receiptsByShard = receipts.associateBy { it.shardId }
                    val runId = "observation-v2-${OracleArtifacts.sha256("${scope.sha256}:$richSha256".toByteArray()).take(32)}"
                    val publicationCheckpoint: (String) -> Unit = { stage ->
                        deadline.checkpoint(stage)
                        if (stage.endsWith("BEFORE_ATOMIC_MOVE") ||
                            stage.endsWith("AFTER_ATOMIC_MOVE") ||
                            stage.endsWith("AFTER_FINAL_VERIFICATION")
                        ) {
                            inventoryGuard.verifyUnchanged("full-tree inventory at observation-v2 publication $stage")
                            richGuard.verifyUnchanged("rich artifact at observation-v2 publication $stage")
                        }
                        if (stage.endsWith("AFTER_FINAL_VERIFICATION")) {
                            deadline.sampleWholeRun("before returning authenticated observation-v2 run")
                        }
                    }
                    val binding = BoundedShardRunPublisher.publishWithCheckpoint(
                        target = target,
                        runId = runId,
                        preparedOutputs = boundedOutputs,
                        bounds = runBounds,
                        limits = limits.run,
                        semanticValidator = BoundedShardOutputSemanticValidator { staged ->
                            val receipt = receiptsByShard[staged.shardId]
                                ?: v2RunFail("published observation-v2 shard is outside the authenticated inventory")
                            if (staged.inputSha256 != receipt.inputSha256 ||
                                staged.outputSha256 != receipt.outputSha256 || staged.outputBytes != receipt.outputBytes
                            ) {
                                v2RunFail("staged observation-v2 metadata differs from its authenticated receipt")
                            }
                            val actual = hashAndSize(staged.output)
                            if (actual.first != receipt.outputSha256 || actual.second != receipt.outputBytes) {
                                v2RunFail("staged observation-v2 bytes differ from their authenticated receipt")
                            }
                        },
                        checkpoint = publicationCheckpoint,
                    )
                    return@translateV2RunFailure FullTreeFunctionObservationV2RunPublication(
                        binding = binding,
                        scopeSha256 = scope.sha256,
                        inventoryArtifactSha256 = inventorySha256,
                        richArtifactSha256 = richSha256,
                        reconciliation = reconciliation,
                        outputs = receipts,
                        maximumWorkers = effectiveWorkers,
                    )
                } finally {
                    prepared.close()
                }
            }
        }
    }

    /** Re-derives the complete run into private scratch and matches every authenticated shard receipt. */
    fun loadAndValidate(
        candidateRoot: Path,
        expectedIndexArtifactSha256: String,
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        scratchParent: Path,
        limits: FullTreeFunctionObservationV2RunLimits = FullTreeFunctionObservationV2RunLimits(),
    ): FullTreeFunctionObservationV2RunPublication = translateV2RunFailure {
        requireStableDirectory(scratchParent, "observation-v2 rederivation scratch parent")
        val candidate = BoundedShardRunVerifier.verify(candidateRoot, expectedIndexArtifactSha256, limits.run)
        val workers = candidate.maximumWorkers
        val expected = V2PreparedWorkspace.create(scratchParent)
        try {
            val regeneratedRoot = expected.directory.resolve("rederived-run")
            val regenerated = generateAndPublish(
                richArtifact,
                inventoryPath,
                scope,
                expected.directory,
                regeneratedRoot,
                workers,
                limits,
            )
            if (
                candidate.runSha256 != regenerated.binding.runSha256 ||
                candidate.indexArtifactSha256 != regenerated.binding.indexArtifactSha256 ||
                candidate.outputs != regenerated.binding.outputs ||
                candidate.run != regenerated.binding.run || candidate.index != regenerated.binding.index
            ) {
                v2RunFail("observation-v2 run differs from independent raw-input rederivation")
            }
            return@translateV2RunFailure FullTreeFunctionObservationV2RunPublication(
                binding = candidate,
                scopeSha256 = regenerated.scopeSha256,
                inventoryArtifactSha256 = regenerated.inventoryArtifactSha256,
                richArtifactSha256 = regenerated.richArtifactSha256,
                reconciliation = regenerated.reconciliation,
                outputs = regenerated.outputs,
                maximumWorkers = workers,
            )
        } finally {
            expected.close()
        }
    }
}

private fun authenticatedV2SqliteLimits(
    limits: FullTreeFunctionObservationV2RunLimits,
    effective: AuthenticatedFunctionObservationLimits,
    checkpoint: (String) -> Unit,
    scratchBudget: FullTreeFunctionObservationV2ShardScratchBudget,
): FullTreeFunctionObservationSqliteLimits {
    return FullTreeFunctionObservationSqliteLimits(
        maximumDatabaseBytes = minOf(effective.maximumDatabaseBytes, scratchBudget.databaseBytes),
        maximumOutputBytes = scratchBudget.outputBytes,
        observations = effective.producer.accumulatorLimits,
        maximumCacheBytes = limits.shard.maximumSqliteCacheBytes,
        databaseCheckpointRows = limits.shard.databaseCheckpointRows,
        checkpoint = FullTreeFunctionObservationSqliteCheckpoint(checkpoint::invoke),
        maximumScratchBytes = limits.maximumScratchBytes,
        additionalScratchBytes = scratchBudget.additionalScratchBytes,
    )
}

private class V2RunDeadline private constructor(
    private val startedWall: Long,
    private val startedCpu: Long,
    private val maximumWholeWall: Long,
    private val maximumWholeCpu: Long,
    private val maximumResidentBytes: Long,
) {
    fun checkpoint(label: String) {
        val wall = elapsed(startedWall, System.nanoTime(), "wall-clock")
        val cpu = elapsed(startedCpu, processCpuNanos(), "CPU")
        if (wall > maximumWholeWall || cpu > maximumWholeCpu) {
            v2RunFail("observation-v2 run exceeded its authenticated whole-run time budget at $label")
        }
    }

    fun sampleWholeRun(label: String) {
        checkpoint(label)
        val resident = try {
            LinuxResidentMemory.sampleSelf().highWaterBytes
        } catch (failure: Exception) {
            throw FullTreeFunctionObservationV2RunException("observation-v2 resident-memory sample is unavailable", failure)
        }
        if (resident > maximumResidentBytes) v2RunFail("observation-v2 run exceeded its authenticated resident-memory bound at $label")
    }

    fun newShardBudget(scope: AuthenticatedFullTreeScope): V2ShardDeadline {
        val perShard = scope.document.controlObject("bounds").controlObject("perShard")
        val maximumWall = Math.multiplyExact(perShard.controlLong("wallClockSeconds"), 1_000_000_000L)
        val maximumCpu = Math.multiplyExact(perShard.controlLong("cpuSeconds"), 1_000_000_000L)
        return V2ShardDeadline(::checkpoint, maximumWall, maximumCpu)
    }

    companion object {
        fun start(scope: AuthenticatedFullTreeScope, limits: FullTreeFunctionObservationV2RunLimits): V2RunDeadline {
            val wholeRun = scope.document.controlObject("bounds").controlObject("wholeRun")
            val wallSeconds = wholeRun.controlLong("wallClockSeconds")
            val cpuSeconds = wholeRun.controlLong("cpuSeconds")
            return V2RunDeadline(
                System.nanoTime(),
                processCpuNanos(),
                Math.multiplyExact(wallSeconds, 1_000_000_000L),
                Math.multiplyExact(cpuSeconds, 1_000_000_000L),
                wholeRun.controlLong("maximumResidentBytes"),
            )
        }
    }
}

/** Cumulative budget across this shard's census and observation-production phases. */
internal class V2ShardDeadline internal constructor(
    private val runCheckpoint: (String) -> Unit,
    private val maximumWall: Long,
    private val maximumCpu: Long,
    private val wallClock: () -> Long = System::nanoTime,
    private val cpuClock: () -> Long = ::processCpuNanos,
) {
    private var activeWallStart: Long? = null
    private var activeCpuStart: Long? = null
    private var accumulatedWall = 0L
    private var accumulatedCpu = 0L

    fun beginPhase(): (String) -> Unit {
        check(activeWallStart == null && activeCpuStart == null)
        activeWallStart = wallClock()
        activeCpuStart = cpuClock()
        return ::checkpoint
    }

    fun endPhase(label: String) {
        checkpoint(label)
        val wallStart = activeWallStart ?: v2RunFail("observation-v2 shard deadline has no active phase")
        val cpuStart = activeCpuStart ?: v2RunFail("observation-v2 shard deadline has no active phase")
        accumulatedWall = Math.addExact(accumulatedWall, elapsed(wallStart, wallClock(), "per-shard wall-clock"))
        accumulatedCpu = Math.addExact(accumulatedCpu, elapsed(cpuStart, cpuClock(), "per-shard CPU"))
        activeWallStart = null
        activeCpuStart = null
        if (accumulatedWall > maximumWall || accumulatedCpu > maximumCpu) {
            v2RunFail("observation-v2 shard exceeded its authenticated cumulative time budget at $label")
        }
    }

    private fun checkpoint(label: String) {
        runCheckpoint(label)
        val wallStart = activeWallStart ?: v2RunFail("observation-v2 shard deadline has no active phase")
        val cpuStart = activeCpuStart ?: v2RunFail("observation-v2 shard deadline has no active phase")
        if (Math.addExact(accumulatedWall, elapsed(wallStart, wallClock(), "per-shard wall-clock")) > maximumWall ||
            Math.addExact(accumulatedCpu, elapsed(cpuStart, cpuClock(), "per-shard CPU")) > maximumCpu
        ) {
            v2RunFail("observation-v2 shard exceeded its authenticated cumulative time budget at $label")
        }
    }
}

private class V2PreparedWorkspace private constructor(val directory: Path, private val key: Any) : AutoCloseable {
    fun output(shardId: String): Path = directory.resolve("$shardId.json")

    override fun close() {
        val current = Files.readAttributes(directory, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!current.isDirectory || current.isSymbolicLink || current.fileKey() != key) {
            v2RunFail("observation-v2 prepared workspace changed identity")
        }
        deleteV2Tree(directory)
    }

    companion object {
        fun create(parent: Path): V2PreparedWorkspace {
            val directory = Files.createTempDirectory(parent, ".function-observation-v2-")
            Files.setPosixFilePermissions(directory, PRIVATE_DIRECTORY_PERMISSIONS)
            val attrs = Files.readAttributes(directory, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            if (!attrs.isDirectory || attrs.isSymbolicLink || attrs.fileKey() == null) {
                v2RunFail("observation-v2 prepared workspace is not a stable directory")
            }
            return V2PreparedWorkspace(directory, attrs.fileKey())
        }
    }
}

private fun deleteV2Tree(root: Path) {
    Files.walkFileTree(root, object : SimpleFileVisitor<Path>() {
        override fun preVisitDirectory(directory: Path, attrs: BasicFileAttributes): FileVisitResult {
            if (attrs.isSymbolicLink || !attrs.isDirectory) {
                v2RunFail("unsafe directory in observation-v2 prepared workspace")
            }
            // Published subtrees are made read-only before the rederivation workspace is
            // removed. Restore owner-only write/search permission before descending so their
            // verified regular files can be unlinked safely.
            Files.setPosixFilePermissions(directory, PRIVATE_DIRECTORY_PERMISSIONS)
            return FileVisitResult.CONTINUE
        }

        override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
            if (attrs.isSymbolicLink || !attrs.isRegularFile) v2RunFail("unsafe entry in observation-v2 prepared workspace")
            Files.delete(file)
            return FileVisitResult.CONTINUE
        }

        override fun postVisitDirectory(directory: Path, exc: java.io.IOException?): FileVisitResult {
            if (exc != null) throw exc
            Files.setPosixFilePermissions(directory, PRIVATE_DIRECTORY_PERMISSIONS)
            Files.delete(directory)
            return FileVisitResult.CONTINUE
        }
    })
}

private fun hashAndSize(path: Path): Pair<String, Long> {
    val digest = MessageDigest.getInstance("SHA-256")
    var bytes = 0L
    Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { input ->
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            if (count == 0) continue
            digest.update(buffer, 0, count)
            bytes = Math.addExact(bytes, count.toLong())
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) } to bytes
}

private fun processCpuNanos(): Long = ProcessHandle.current().info().totalCpuDuration()
    .orElseThrow { FullTreeFunctionObservationV2RunException("process CPU duration is unavailable") }
    .toNanos()

private fun elapsed(start: Long, end: Long, label: String): Long {
    if (end < start) v2RunFail("observation-v2 $label runtime moved backwards")
    return Math.subtractExact(end, start)
}

private fun translateV2RunFailure(block: () -> FullTreeFunctionObservationV2RunPublication): FullTreeFunctionObservationV2RunPublication =
    try {
        block()
    } catch (failure: FullTreeFunctionObservationV2RunException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeFunctionObservationV2RunException("cannot produce authenticated observation-v2 run", failure)
    }

private fun v2RunFail(message: String): Nothing = throw FullTreeFunctionObservationV2RunException(message)

private val PRIVATE_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
private val PRIVATE_OUTPUT_PERMISSIONS = PosixFilePermissions.fromString("rw-------")
private val READ_ONLY_OUTPUT_PERMISSIONS = PosixFilePermissions.fromString("r--------")
