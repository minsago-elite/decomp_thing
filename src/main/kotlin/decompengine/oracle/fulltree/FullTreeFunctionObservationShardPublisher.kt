package decompengine.oracle.fulltree

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxSyscallException
import decompengine.acp.permissions
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.security.SecureRandom

internal class FullTreeFunctionObservationShardPublicationException(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

/**
 * Independent production ceilings layered beneath the authenticated per-shard scope.
 *
 * SQLite scratch is allowed at most four times the authenticated serialized-output bound. That
 * factor models normalized indexes and canonical child rows; it is private, revocable disk space
 * and never relaxes the exact authenticated output limit. [maximumDatabaseBytes] is a second,
 * implementation-owned ceiling on that expansion.
 *
 * [modeledSqliteOverheadBytes] covers the JDBC connection, two copies of one bounded canonical
 * subprogram projection, and the streaming output buffer. It is added to the configured SQLite
 * page cache and scanner's independently modeled working set before artifact traversal begins.
 */
internal data class FullTreeFunctionObservationShardPublisherLimits(
    val control: FullTreeControlLimits = FullTreeControlLimits(),
    val producer: FullTreeFunctionObservationProducerLimits =
        FullTreeFunctionObservationProducerLimits(),
    val maximumOutputBytes: Long = 512L * 1024L * 1024L,
    val maximumDatabaseBytes: Long = 8L * 1024L * 1024L * 1024L,
    val maximumSqliteCacheBytes: Int = 8 * 1024 * 1024,
    val modeledSqliteOverheadBytes: Long = 128L * 1024L * 1024L,
    val databaseCheckpointRows: Int = 4096,
) {
    init {
        require(maximumOutputBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumDatabaseBytes in SQLITE_PAGE_BYTES..16L * 1024L * 1024L * 1024L)
        require(maximumSqliteCacheBytes in 1024..64 * 1024 * 1024)
        require(
            modeledSqliteOverheadBytes in
                MINIMUM_MODELED_SQLITE_OVERHEAD_BYTES..1024L * 1024L * 1024L,
        )
        require(databaseCheckpointRows in 1..1_000_000)
    }
}

/** Primitive-only publication receipt; the potentially large v3 JSON tree is never materialized. */
internal data class FullTreeFunctionObservationPublishedShard(
    val shardId: String,
    val inputSha256: String,
    val inventoryArtifactSha256: String,
    val richArtifactSha256: String,
    val scopeSha256: String,
    val outputSha256: String,
    val outputBytes: Long,
    val units: Long,
    val emittedRvas: Long,
    val nonEmitted: Long,
    val nonEmittedDies: Long,
    val entities: Long,
    val scannedDies: Long,
    val subprograms: Long,
    val databaseHighWaterBytes: Long,
    val peakResidentBytes: Long,
)

internal data class FullTreeFunctionObservationRuntimeSample(
    val wallNanos: Long,
    val processCpuNanos: Long,
    val currentResidentBytes: Long,
    val peakResidentBytes: Long,
) {
    init {
        require(currentResidentBytes > 0L)
        require(peakResidentBytes >= currentResidentBytes)
    }
}

internal fun interface FullTreeFunctionObservationRuntime {
    fun sample(checkpoint: String): FullTreeFunctionObservationRuntimeSample
}

/**
 * Trusted file-backed derivation and validation engine for one authenticated v3 shard.
 *
 * Its direct entry point provides pinned no-replace publication and cooperative process checks for
 * fixtures and inner-worker use. An authoritative release must invoke it through the isolated
 * cgroup runner so process-wide resource accounting is outside this worker's control.
 */
internal object FullTreeFunctionObservationShardPublisher {
    fun generateAndPublish(
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        scratchParent: Path,
        output: Path,
        limits: FullTreeFunctionObservationShardPublisherLimits =
            FullTreeFunctionObservationShardPublisherLimits(),
    ): FullTreeFunctionObservationPublishedShard = generateAndPublishInternal(
        richArtifact = richArtifact,
        inventoryPath = inventoryPath,
        scope = scope,
        shardId = shardId,
        scratchParent = scratchParent,
        output = output,
        limits = limits,
        runtime = SYSTEM_RUNTIME,
    )

    /** Re-derives one existing candidate without modifying or replacing it. */
    fun loadAndValidate(
        candidate: Path,
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        scratchParent: Path,
        limits: FullTreeFunctionObservationShardPublisherLimits =
            FullTreeFunctionObservationShardPublisherLimits(),
    ): FullTreeFunctionObservationPublishedShard = loadAndValidateInternal(
        candidate = candidate,
        richArtifact = richArtifact,
        inventoryPath = inventoryPath,
        scope = scope,
        shardId = shardId,
        scratchParent = scratchParent,
        limits = limits,
        runtime = SYSTEM_RUNTIME,
    )

    internal fun generateAndPublishInternal(
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        scratchParent: Path,
        output: Path,
        limits: FullTreeFunctionObservationShardPublisherLimits,
        runtime: FullTreeFunctionObservationRuntime,
    ): FullTreeFunctionObservationPublishedShard = translatePublicationFailures {
        val started = runtime.sample("at function-observation shard operation entry")
        FullTreeScopeControl.validate(scope, limits.control)
        val perShard = scope.document.controlObject("bounds").controlObject("perShard")
        val budget = CooperativeFunctionObservationBudget(
            started = started,
            runtime = runtime,
            wallSeconds = perShard.controlLong("wallClockSeconds"),
            cpuSeconds = perShard.controlLong("cpuSeconds"),
            maximumResidentBytes = perShard.controlLong("maximumResidentBytes"),
        )
        budget.checkpoint("after authenticating function-observation scope")

        val target = output.toAbsolutePath().normalize()
        requireDistinctControlOutput(
            target,
            "rich artifact" to richArtifact,
            "inventory" to inventoryPath,
        )
        requireStableDirectory(scratchParent, "function-observation scratch parent")

        StableControlFile.open(
            inventoryPath,
            limits.control.maximumInventoryBytes.toLong(),
            "full-tree inventory",
        ).use { inventoryGuard ->
            StableControlFile.open(
                richArtifact,
                limits.control.maximumRichArtifactBytes,
                "rich artifact",
            ).use { richGuard ->
                val guardedInventorySha = digestStableFile(
                    inventoryGuard,
                    budget,
                    "full-tree inventory",
                )
                val guardedRichSha = digestStableFile(richGuard, budget, "rich artifact")
                val expectedRichSha = scope.document.controlObject("oracle")
                    .controlString("richArtifactSha256")
                if (guardedRichSha != expectedRichSha) {
                    publicationFail("rich artifact does not match the authenticated full-tree scope")
                }

                val inputs = FullTreeFunctionObservationProducer.authenticateShardInputs(
                    inventoryPath = inventoryPath,
                    scope = scope,
                    shardId = shardId,
                    controlLimits = limits.control,
                    checkpoint = budget::checkpoint,
                )
                if (inputs.inventoryArtifactSha256 != guardedInventorySha) {
                    publicationFail("inventory changed while function-observation inputs were authenticated")
                }
                inventoryGuard.verifyUnchanged("full-tree inventory after authentication")
                richGuard.verifyUnchanged("rich artifact after authentication")

                val effective = deriveAuthenticatedLimits(scope, inputs, limits)
                FunctionObservationOutputStage.create(target).use { stage ->
                    val (scan, streamResult) = FullTreeFunctionObservationSqlite.open(
                        scratchParent = scratchParent,
                        shard = inputs.shard,
                        limits = FullTreeFunctionObservationSqliteLimits(
                            maximumDatabaseBytes = effective.maximumDatabaseBytes,
                            maximumOutputBytes = effective.maximumOutputBytes,
                            observations = effective.producer.accumulatorLimits,
                            maximumCacheBytes = limits.maximumSqliteCacheBytes,
                            databaseCheckpointRows = limits.databaseCheckpointRows,
                            checkpoint = FullTreeFunctionObservationSqliteCheckpoint(budget::checkpoint),
                        ),
                    ).use { sink ->
                        val observedScan = FullTreeFunctionObservationProducer.scanAuthenticatedShardWithLimits(
                            richArtifact = richArtifact,
                            scope = scope,
                            inputs = inputs,
                            scratchParent = scratchParent,
                            controlLimits = limits.control,
                            producerLimits = effective.producer,
                            checkpoint = budget::checkpoint,
                            recordScannedDies = sink::recordScannedDies,
                            accept = sink::accept,
                        )
                        budget.checkpoint("after scanning function-observation shard")
                        if (observedScan.richArtifactSha256 != guardedRichSha) {
                            publicationFail("rich artifact changed during function-observation traversal")
                        }
                        val projected = stage.write { stream ->
                            sink.finishTo(
                                stream,
                                FullTreeFunctionObservationBindings(
                                    inventoryIndexSha256 = inputs.inventory.controlString("indexSha256"),
                                    richArtifactSha256 = observedScan.richArtifactSha256,
                                    scopeSha256 = scope.sha256,
                                ),
                            )
                        }
                        observedScan to projected
                    }
                    budget.checkpoint("after closing function-observation SQLite state")
                    requireProjectionConsistency(scan, streamResult, effective, "initially derived")

                    budget.checkpoint("before re-deriving staged function-observation output")
                    val rederived = rederiveAgainstCandidate(
                        candidateBytes = streamResult.outputBytes,
                        openCandidate = stage::openComparisonInput,
                        richArtifact = richArtifact,
                        inventoryPath = inventoryPath,
                        scope = scope,
                        shardId = shardId,
                        scratchParent = scratchParent,
                        limits = limits,
                        budget = budget,
                        inventoryGuard = inventoryGuard,
                        richGuard = richGuard,
                    )
                    stage.verifyLinkedCandidate()
                    requireEquivalentDerivation(
                        initialInputs = inputs,
                        initialLimits = effective,
                        initialScan = scan,
                        initialResult = streamResult,
                        rederived = rederived,
                    )
                    budget.checkpoint("after re-deriving staged function-observation output")

                    val verifyInputs = {
                        FullTreeScopeControl.validate(scope, limits.control)
                        if (
                            digestStableFile(inventoryGuard, budget, "full-tree inventory") !=
                            inputs.inventoryArtifactSha256
                        ) {
                            publicationFail("full-tree inventory changed before publication completed")
                        }
                        if (digestStableFile(richGuard, budget, "rich artifact") != scan.richArtifactSha256) {
                            publicationFail("rich artifact changed before publication completed")
                        }
                        inventoryGuard.verifyUnchanged("full-tree inventory during publication")
                        richGuard.verifyUnchanged("rich artifact during publication")
                    }
                    stage.publish(
                        expected = FunctionObservationOutputDigest(
                            streamResult.outputSha256,
                            streamResult.outputBytes,
                        ),
                        maximumBytes = effective.maximumOutputBytes,
                        budget = budget,
                        verifyInputs = verifyInputs,
                    )

                    publicationReceipt(scope, inputs, scan, streamResult, budget.peakResidentBytes)
                }
            }
        }
    }

    internal fun loadAndValidateInternal(
        candidate: Path,
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        scratchParent: Path,
        limits: FullTreeFunctionObservationShardPublisherLimits,
        runtime: FullTreeFunctionObservationRuntime,
    ): FullTreeFunctionObservationPublishedShard = translatePublicationFailures {
        val started = runtime.sample("at function-observation validation entry")
        FullTreeScopeControl.validate(scope, limits.control)
        val perShard = scope.document.controlObject("bounds").controlObject("perShard")
        val budget = CooperativeFunctionObservationBudget(
            started = started,
            runtime = runtime,
            wallSeconds = perShard.controlLong("wallClockSeconds"),
            cpuSeconds = perShard.controlLong("cpuSeconds"),
            maximumResidentBytes = perShard.controlLong("maximumResidentBytes"),
        )
        budget.checkpoint("after authenticating function-observation validation scope")
        val normalizedCandidate = candidate.toAbsolutePath().normalize()
        requireDistinctControlOutput(
            normalizedCandidate,
            "rich artifact" to richArtifact,
            "inventory" to inventoryPath,
        )
        requireStableDirectory(scratchParent, "function-observation validation scratch parent")
        val maximumCandidateBytes = minOf(
            perShard.controlLong("serializedBytes"),
            limits.maximumOutputBytes,
        )
        StableControlFile.open(
            inventoryPath,
            limits.control.maximumInventoryBytes.toLong(),
            "full-tree inventory",
        ).use { inventoryGuard ->
            StableControlFile.open(
                richArtifact,
                limits.control.maximumRichArtifactBytes,
                "rich artifact",
            ).use { richGuard ->
                StableControlFile.open(
                    normalizedCandidate,
                    maximumCandidateBytes,
                    "function-observation candidate",
                ).use { candidateGuard ->
                    val rederived = rederiveAgainstCandidate(
                        candidateBytes = candidateGuard.size,
                        openCandidate = { candidateGuard.slice() },
                        richArtifact = richArtifact,
                        inventoryPath = inventoryPath,
                        scope = scope,
                        shardId = shardId,
                        scratchParent = scratchParent,
                        limits = limits,
                        budget = budget,
                        inventoryGuard = inventoryGuard,
                        richGuard = richGuard,
                    )
                    candidateGuard.verifyUnchanged("function-observation candidate after validation")
                    budget.checkpoint("after validating existing function-observation candidate")
                    publicationReceipt(
                        scope,
                        rederived.inputs,
                        rederived.scan,
                        rederived.result,
                        budget.peakResidentBytes,
                    )
                }
            }
        }
    }

    private val SYSTEM_RUNTIME = FullTreeFunctionObservationRuntime { _ ->
        val resident = LinuxResidentMemory.sampleSelf()
        FullTreeFunctionObservationRuntimeSample(
            wallNanos = System.nanoTime(),
            processCpuNanos = ProcessHandle.current().info().totalCpuDuration()
                .orElseThrow {
                    FullTreeFunctionObservationShardPublicationException(
                        "process CPU duration is unavailable",
                    )
                }
                .toNanos(),
            currentResidentBytes = resident.currentBytes,
            peakResidentBytes = resident.highWaterBytes,
        )
    }
}

private data class AuthenticatedFunctionObservationLimits(
    val producer: FullTreeFunctionObservationProducerLimits,
    val maximumEntities: Int,
    val maximumOutputBytes: Long,
    val maximumDatabaseBytes: Long,
)

private data class ReDerivedFunctionObservation(
    val inputs: FullTreeFunctionObservationAuthenticatedInputs,
    val limits: AuthenticatedFunctionObservationLimits,
    val scan: FullTreeFunctionObservationArtifactScan,
    val result: FullTreeFunctionObservationStreamResult,
)

private fun rederiveAgainstCandidate(
    candidateBytes: Long,
    openCandidate: () -> InputStream,
    richArtifact: Path,
    inventoryPath: Path,
    scope: AuthenticatedFullTreeScope,
    shardId: String,
    scratchParent: Path,
    limits: FullTreeFunctionObservationShardPublisherLimits,
    budget: CooperativeFunctionObservationBudget,
    inventoryGuard: StableControlFile,
    richGuard: StableControlFile,
): ReDerivedFunctionObservation {
    FullTreeScopeControl.validate(scope, limits.control)
    budget.checkpoint("after independently authenticating function-observation scope")
    val guardedInventorySha = digestStableFile(
        inventoryGuard,
        budget,
        "full-tree inventory for independent derivation",
    )
    val guardedRichSha = digestStableFile(
        richGuard,
        budget,
        "rich artifact for independent derivation",
    )
    if (
        guardedRichSha != scope.document.controlObject("oracle")
            .controlString("richArtifactSha256")
    ) {
        publicationFail("rich artifact differs from scope during independent derivation")
    }
    val inputs = FullTreeFunctionObservationProducer.authenticateShardInputs(
        inventoryPath = inventoryPath,
        scope = scope,
        shardId = shardId,
        controlLimits = limits.control,
        checkpoint = budget::checkpoint,
    )
    if (inputs.inventoryArtifactSha256 != guardedInventorySha) {
        publicationFail("inventory changed during independent function-observation authentication")
    }
    val effective = deriveAuthenticatedLimits(scope, inputs, limits)
    if (candidateBytes !in 1L..effective.maximumOutputBytes) {
        publicationFail("function-observation candidate exceeds its authenticated byte bound")
    }

    val (scan, result) = FullTreeFunctionObservationSqlite.open(
        scratchParent = scratchParent,
        shard = inputs.shard,
        limits = FullTreeFunctionObservationSqliteLimits(
            maximumDatabaseBytes = effective.maximumDatabaseBytes,
            maximumOutputBytes = effective.maximumOutputBytes,
            observations = effective.producer.accumulatorLimits,
            maximumCacheBytes = limits.maximumSqliteCacheBytes,
            databaseCheckpointRows = limits.databaseCheckpointRows,
            checkpoint = FullTreeFunctionObservationSqliteCheckpoint(budget::checkpoint),
        ),
    ).use { sink ->
        val observedScan = FullTreeFunctionObservationProducer.scanAuthenticatedShardWithLimits(
            richArtifact = richArtifact,
            scope = scope,
            inputs = inputs,
            scratchParent = scratchParent,
            controlLimits = limits.control,
            producerLimits = effective.producer,
            checkpoint = budget::checkpoint,
            recordScannedDies = sink::recordScannedDies,
            accept = sink::accept,
        )
        budget.checkpoint("after independently rescanning function-observation shard")
        if (observedScan.richArtifactSha256 != guardedRichSha) {
            publicationFail("rich artifact changed during independent function-observation traversal")
        }
        val projected = FunctionObservationComparingOutputStream(
            source = openCandidate(),
            expectedBytes = candidateBytes,
            budget = budget,
        ).use { comparison ->
            val observed = sink.finishTo(
                comparison,
                FullTreeFunctionObservationBindings(
                    inventoryIndexSha256 = inputs.inventory.controlString("indexSha256"),
                    richArtifactSha256 = observedScan.richArtifactSha256,
                    scopeSha256 = scope.sha256,
                ),
            )
            val compared = comparison.finish()
            if (observed.outputBytes != compared.bytes || observed.outputSha256 != compared.sha256) {
                publicationFail("independently derived function-observation digest differs from candidate")
            }
            observed
        }
        observedScan to projected
    }
    requireProjectionConsistency(scan, result, effective, "independently derived")
    FullTreeScopeControl.validate(scope, limits.control)
    if (
        digestStableFile(
            inventoryGuard,
            budget,
            "full-tree inventory after independent derivation",
        ) != inputs.inventoryArtifactSha256
    ) {
        publicationFail("full-tree inventory changed during independent derivation")
    }
    if (
        digestStableFile(richGuard, budget, "rich artifact after independent derivation") !=
        scan.richArtifactSha256
    ) {
        publicationFail("rich artifact changed during independent derivation")
    }
    inventoryGuard.verifyUnchanged("full-tree inventory after independent derivation")
    richGuard.verifyUnchanged("rich artifact after independent derivation")
    budget.checkpoint("after reverifying independent function-observation inputs")
    return ReDerivedFunctionObservation(inputs, effective, scan, result)
}

private fun requireEquivalentDerivation(
    initialInputs: FullTreeFunctionObservationAuthenticatedInputs,
    initialLimits: AuthenticatedFunctionObservationLimits,
    initialScan: FullTreeFunctionObservationArtifactScan,
    initialResult: FullTreeFunctionObservationStreamResult,
    rederived: ReDerivedFunctionObservation,
) {
    if (
        initialInputs.inventoryArtifactSha256 != rederived.inputs.inventoryArtifactSha256 ||
        initialInputs.inventory != rederived.inputs.inventory ||
        initialInputs.shard.identifier != rederived.inputs.shard.identifier ||
        initialInputs.shard.inputSha256 != rederived.inputs.shard.inputSha256 ||
        initialInputs.shard.units != rederived.inputs.shard.units
    ) {
        publicationFail("independent function-observation authentication differs from the initial pass")
    }
    if (
        initialLimits != rederived.limits || initialScan != rederived.scan ||
        initialResult != rederived.result
    ) {
        publicationFail("independent function-observation scan, counts, or high-water metadata differ")
    }
}

private fun requireProjectionConsistency(
    scan: FullTreeFunctionObservationArtifactScan,
    result: FullTreeFunctionObservationStreamResult,
    limits: AuthenticatedFunctionObservationLimits,
    label: String,
) {
    if (result.scannedDies != scan.scannedDies) {
        publicationFail("$label scanner and SQLite scanned-DIE counts differ")
    }
    if (result.entities > limits.maximumEntities.toLong()) {
        publicationFail("$label function-observation entity count exceeds its authenticated bound")
    }
    if (result.outputBytes !in 1L..limits.maximumOutputBytes) {
        publicationFail("$label function-observation output exceeds its authenticated byte bound")
    }
    if (result.databaseHighWaterBytes !in 1L..limits.maximumDatabaseBytes) {
        publicationFail("$label function-observation database high-water mark exceeds its scratch bound")
    }
}

private fun publicationReceipt(
    scope: AuthenticatedFullTreeScope,
    inputs: FullTreeFunctionObservationAuthenticatedInputs,
    scan: FullTreeFunctionObservationArtifactScan,
    result: FullTreeFunctionObservationStreamResult,
    peakResidentBytes: Long,
): FullTreeFunctionObservationPublishedShard = FullTreeFunctionObservationPublishedShard(
    shardId = inputs.shard.identifier,
    inputSha256 = inputs.shard.inputSha256,
    inventoryArtifactSha256 = inputs.inventoryArtifactSha256,
    richArtifactSha256 = scan.richArtifactSha256,
    scopeSha256 = scope.sha256,
    outputSha256 = result.outputSha256,
    outputBytes = result.outputBytes,
    units = inputs.shard.units.size.toLong(),
    emittedRvas = result.emitted,
    nonEmitted = result.nonEmitted,
    nonEmittedDies = result.nonEmittedDies,
    entities = result.entities,
    scannedDies = result.scannedDies,
    subprograms = scan.subprograms,
    databaseHighWaterBytes = result.databaseHighWaterBytes,
    peakResidentBytes = peakResidentBytes,
)

private fun deriveAuthenticatedLimits(
    scope: AuthenticatedFullTreeScope,
    inputs: FullTreeFunctionObservationAuthenticatedInputs,
    limits: FullTreeFunctionObservationShardPublisherLimits,
): AuthenticatedFunctionObservationLimits {
    val perShard = scope.document.controlObject("bounds").controlObject("perShard")
    val authenticatedUnits = perShard.controlLong("compilationUnits")
    val unitCount = inputs.shard.units.size.toLong()
    if (unitCount !in 1L..authenticatedUnits) {
        publicationFail("function-observation shard exceeds its authenticated compilation-unit bound")
    }

    val configured = limits.producer.accumulatorLimits
    val physicalScanBound = checkedMultiply(
        limits.producer.dieLimits.maximumPhysicalRecords,
        unitCount,
        "function-observation physical-DIE bound",
    )
    val nonNullScanBound = checkedMultiply(
        limits.producer.dieLimits.maximumNonNullRecords.toLong(),
        unitCount,
        "function-observation non-null DIE bound",
    )
    val maximumScannedDies = minOf(configured.maximumScannedDies, physicalScanBound)
    // Subprogram DIEs may coalesce by RVA/identity, so this scan bound is intentionally independent
    // of the final perShard.entities bound.
    val maximumSubprograms = minOf(
        configured.maximumSubprograms,
        nonNullScanBound,
        maximumScannedDies,
    )
    val authenticatedEntities = perShard.controlLong("entities")
    if (authenticatedEntities <= 0L) publicationFail("authenticated function-observation entity bound is empty")
    val maximumEntities = minOf(
        authenticatedEntities,
        configured.maximumEntities.toLong(),
        Int.MAX_VALUE.toLong(),
    ).toInt()
    val scannerFactBound = checkedMultiply(
        limits.producer.maximumReferenceChainEntries.toLong(),
        FUNCTION_NAME_ATTRIBUTES_PER_REFERENCE,
        "function-observation per-subprogram name fact bound",
    ).toInt()
    val residentCompatibleCanonicalBytes = minOf(
        MAXIMUM_CANONICAL_BYTES_PER_SUBPROGRAM.toLong(),
        limits.modeledSqliteOverheadBytes / CANONICAL_RESIDENT_COPY_FACTOR,
    ).toInt()
    val observations = configured.copy(
        maximumScannedDies = maximumScannedDies,
        maximumSubprograms = maximumSubprograms,
        maximumEntities = maximumEntities,
        maximumEmittedRvas = minOf(configured.maximumEmittedRvas, maximumEntities),
        maximumNonEmittedGroups = minOf(configured.maximumNonEmittedGroups, maximumEntities),
        maximumAliasesPerSubprogram = minOf(configured.maximumAliasesPerSubprogram, scannerFactBound),
        maximumEvidencePerAliasPerSubprogram = minOf(
            configured.maximumEvidencePerAliasPerSubprogram,
            scannerFactBound,
        ),
        maximumEvidencePerSubprogram = minOf(configured.maximumEvidencePerSubprogram, scannerFactBound),
        maximumCanonicalBytesPerSubprogram = minOf(
            configured.maximumCanonicalBytesPerSubprogram,
            residentCompatibleCanonicalBytes,
        ),
    )
    val producer = limits.producer.copy(accumulatorLimits = observations)

    val scannerResidentBytes = modeledScannerResidentBytes(producer)
    val sqliteResidentBytes = checkedAdd(
        limits.maximumSqliteCacheBytes.toLong(),
        limits.modeledSqliteOverheadBytes,
        "function-observation SQLite resident model",
    )
    val modeledResidentBytes = checkedAdd(
        scannerResidentBytes,
        sqliteResidentBytes,
        "function-observation total resident model",
    )
    if (modeledResidentBytes > perShard.controlLong("maximumResidentBytes")) {
        publicationFail("modeled function-observation working set exceeds its authenticated resident-byte bound")
    }

    val authenticatedOutputBytes = perShard.controlLong("serializedBytes")
    val maximumOutputBytes = minOf(authenticatedOutputBytes, limits.maximumOutputBytes)
    if (maximumOutputBytes <= 0L) publicationFail("authenticated function-observation output bound is empty")
    val expandedDatabaseBytes = checkedMultiply(
        authenticatedOutputBytes,
        SQLITE_DATABASE_EXPANSION_FACTOR,
        "function-observation SQLite scratch expansion",
    )
    val maximumDatabaseBytes = minOf(expandedDatabaseBytes, limits.maximumDatabaseBytes)
    if (maximumDatabaseBytes < SQLITE_PAGE_BYTES) {
        publicationFail("authenticated function-observation SQLite scratch bound is smaller than one page")
    }
    return AuthenticatedFunctionObservationLimits(
        producer = producer,
        maximumEntities = maximumEntities,
        maximumOutputBytes = maximumOutputBytes,
        maximumDatabaseBytes = maximumDatabaseBytes,
    )
}

private fun modeledScannerResidentBytes(limits: FullTreeFunctionObservationProducerLimits): Long {
    val cachedUnits = limits.maximumCachedCompilationUnits.toLong()
    val residentDieCopies = checkedAdd(
        limits.maximumReferenceChainEntries.toLong(),
        cachedUnits,
        "function-observation resident DIE-copy count",
    )
    val dies = checkedMultiply(
        limits.dieLimits.maximumRetainedBytes,
        residentDieCopies,
        "function-observation resident DIE bytes",
    )
    val paths = checkedMultiply(
        limits.lineTableLimits.maximumAggregatePathBytes,
        2L,
        "function-observation decoded line-table path bytes",
    )
    val lineEntries = checkedAdd(
        limits.lineTableLimits.maximumDirectories.toLong(),
        limits.lineTableLimits.maximumFiles.toLong(),
        "function-observation line-table entry count",
    )
    val entryObjects = checkedMultiply(
        lineEntries,
        MODELED_LINE_TABLE_ENTRY_BYTES,
        "function-observation line-table entry bytes",
    )
    val oneLineTable = checkedAdd(
        checkedAdd(paths, entryObjects, "function-observation line-table retained bytes"),
        MODELED_LINE_TABLE_BYTES,
        "function-observation line-table retained bytes",
    )
    return checkedAdd(
        dies,
        checkedMultiply(
            oneLineTable,
            cachedUnits,
            "function-observation cached line-table bytes",
        ),
        "function-observation scanner resident bytes",
    )
}

private class CooperativeFunctionObservationBudget(
    private val started: FullTreeFunctionObservationRuntimeSample,
    private val runtime: FullTreeFunctionObservationRuntime,
    wallSeconds: Long,
    cpuSeconds: Long,
    private val maximumResidentBytes: Long,
) {
    private val wallLimit = secondsToNanos(wallSeconds, "wall-clock")
    private val cpuLimit = secondsToNanos(cpuSeconds, "CPU")
    var peakResidentBytes: Long = started.peakResidentBytes
        private set

    init {
        requireResidentBound(started, "at function-observation operation entry")
    }

    fun checkpoint(label: String) {
        val sample = runtime.sample(label)
        val wall = elapsed(started.wallNanos, sample.wallNanos, "wall-clock")
        val cpu = elapsed(started.processCpuNanos, sample.processCpuNanos, "CPU")
        if (wall > wallLimit) {
            publicationFail("function-observation operation exceeded wall-clock bound $label")
        }
        if (cpu > cpuLimit) publicationFail("function-observation operation exceeded CPU bound $label")
        requireResidentBound(sample, label)
    }

    private fun requireResidentBound(sample: FullTreeFunctionObservationRuntimeSample, label: String) {
        if (sample.peakResidentBytes > maximumResidentBytes) {
            publicationFail("function-observation operation exceeded resident-memory bound $label")
        }
        peakResidentBytes = maxOf(peakResidentBytes, sample.peakResidentBytes)
        if (peakResidentBytes > maximumResidentBytes) {
            publicationFail("function-observation retained resident peak exceeds its bound $label")
        }
    }

    private fun secondsToNanos(seconds: Long, label: String): Long = try {
        Math.multiplyExact(seconds, NANOS_PER_SECOND)
    } catch (failure: ArithmeticException) {
        throw FullTreeFunctionObservationShardPublicationException(
            "authenticated function-observation $label bound overflows",
            failure,
        )
    }

    private fun elapsed(start: Long, end: Long, label: String): Long {
        if (end < start) publicationFail("function-observation $label runtime sample moved backwards")
        return try {
            Math.subtractExact(end, start)
        } catch (failure: ArithmeticException) {
            throw FullTreeFunctionObservationShardPublicationException(
                "function-observation $label elapsed time overflows",
                failure,
            )
        }
    }
}

private data class FunctionObservationOutputDigest(val sha256: String, val bytes: Long)

/** Streams re-derived bytes against a bounded pinned candidate without retaining either tree. */
private class FunctionObservationComparingOutputStream(
    private val source: InputStream,
    private val expectedBytes: Long,
    private val budget: CooperativeFunctionObservationBudget,
) : OutputStream() {
    private val digest = MessageDigest.getInstance("SHA-256")
    private val observed = ByteArray(OUTPUT_BUFFER_BYTES)
    private var compared = 0L
    private var nextCheckpoint = COMPARISON_CHECKPOINT_BYTES
    private var finished = false

    init {
        if (expectedBytes <= 0L) publicationFail("function-observation comparison byte bound is empty")
    }

    override fun write(value: Int) {
        write(byteArrayOf(value.toByte()), 0, 1)
    }

    override fun write(bytes: ByteArray, offset: Int, length: Int) {
        if (finished) publicationFail("function-observation comparison is already complete")
        if (offset < 0 || length < 0 || offset > bytes.size - length) throw IndexOutOfBoundsException()
        if (compared > expectedBytes - length.toLong()) {
            publicationFail("independently derived function-observation output exceeds the candidate")
        }
        var consumed = 0
        while (consumed < length) {
            val untilCheckpoint = nextCheckpoint - compared
            val requested = minOf(
                observed.size.toLong(),
                (length - consumed).toLong(),
                untilCheckpoint,
            ).toInt()
            var readTotal = 0
            while (readTotal < requested) {
                val read = source.read(observed, readTotal, requested - readTotal)
                if (read <= 0) {
                    publicationFail("function-observation candidate ended before the independent derivation")
                }
                readTotal += read
            }
            var index = 0
            while (index < requested) {
                if (observed[index] != bytes[offset + consumed + index]) {
                    publicationFail("function-observation candidate differs from the independent derivation")
                }
                index++
            }
            digest.update(bytes, offset + consumed, requested)
            consumed += requested
            compared = checkedAdd(
                compared,
                requested.toLong(),
                "independently compared function-observation byte count",
            )
            if (compared == nextCheckpoint) {
                budget.checkpoint("while comparing independently derived function-observation output")
                nextCheckpoint = checkedAdd(
                    nextCheckpoint,
                    COMPARISON_CHECKPOINT_BYTES,
                    "function-observation comparison checkpoint",
                )
            }
        }
    }

    fun finish(): FunctionObservationOutputDigest {
        if (finished) publicationFail("function-observation comparison is already complete")
        if (compared != expectedBytes) {
            publicationFail("independently derived function-observation output is shorter than the candidate")
        }
        if (source.read() >= 0) {
            publicationFail("function-observation candidate has bytes beyond the independent derivation")
        }
        budget.checkpoint("after comparing independently derived function-observation output")
        finished = true
        return FunctionObservationOutputDigest(digest.digest().hex(), compared)
    }

    override fun close() = source.close()
}

/** A pinned direct sibling whose only successful terminal transition is a no-replace rename. */
private class FunctionObservationOutputStage private constructor(
    private val target: Path,
    private val parent: Path,
    private val parentIdentity: Any,
    private val parentDescriptor: LinuxDescriptor,
    private val stageName: String,
    private val stageDescriptor: LinuxDescriptor,
) : AutoCloseable {
    private var published = false
    private var committed = false

    fun <T> write(action: (OutputStream) -> T): T {
        requireNamedIdentity(stageName, "function-observation staging output")
        val pinned = LinuxFilesystemSyscalls.stableDescriptorPath(stageDescriptor.fd)
        return FileChannel.open(
            pinned,
            StandardOpenOption.WRITE,
            StandardOpenOption.TRUNCATE_EXISTING,
        ).use { channel ->
            val stream = BufferedOutputStream(Channels.newOutputStream(channel), OUTPUT_BUFFER_BYTES)
            val result = action(stream)
            stream.flush()
            channel.force(true)
            result
        }.also {
            LinuxFilesystemSyscalls.synchronize(stageDescriptor)
            requireNamedIdentity(stageName, "function-observation staging output")
        }
    }

    fun openComparisonInput(): InputStream {
        requireNamedIdentity(stageName, "function-observation staging output before re-derivation")
        val channel = FileChannel.open(
            LinuxFilesystemSyscalls.stableDescriptorPath(stageDescriptor.fd),
            StandardOpenOption.READ,
        )
        return try {
            Channels.newInputStream(channel)
        } catch (failure: Throwable) {
            channel.close()
            throw failure
        }
    }

    fun verifyLinkedCandidate() {
        requireParentIdentity("after re-deriving staged function-observation output")
        requireNamedIdentity(stageName, "re-derived function-observation staging output")
        requireStageMode(OWNER_READ_WRITE_MODE, "re-derived function-observation staging output")
    }

    fun publish(
        expected: FunctionObservationOutputDigest,
        maximumBytes: Long,
        budget: CooperativeFunctionObservationBudget,
        verifyInputs: () -> Unit,
    ) {
        budget.checkpoint("before verifying staged function-observation output")
        requireParentIdentity("before function-observation publication")
        requireNamedIdentity(stageName, "function-observation staging output")
        val actual = digestPinnedStage(maximumBytes, budget)
        if (actual != expected) publicationFail("staged function-observation output differs from generated bytes")

        LinuxFilesystemSyscalls.chmodPinned(stageDescriptor, OWNER_READ_ONLY_MODE)
        LinuxFilesystemSyscalls.synchronize(stageDescriptor)
        requireStageMode(OWNER_READ_ONLY_MODE, "staged function-observation output")
        requireNamedIdentity(stageName, "function-observation staging output")
        verifyInputs()
        budget.checkpoint("before atomic function-observation publication")
        requireParentIdentity("before atomic function-observation publication")
        parentDescriptor.whileOpen { parentFd ->
            LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, target.fileName.toString())?.use {
                publicationFail("function-observation publication target already exists")
            }
            LinuxFilesystemSyscalls.synchronize(parentDescriptor)
            try {
                LinuxFilesystemSyscalls.renameNoReplace(
                    parentFd,
                    stageName,
                    target.fileName.toString(),
                )
            } catch (failure: LinuxSyscallException) {
                if (failure.errno == LinuxFilesystemSyscalls.EEXIST) {
                    throw FullTreeFunctionObservationShardPublicationException(
                        "function-observation publication target already exists",
                        failure,
                    )
                }
                throw failure
            }
            published = true
        }
        LinuxFilesystemSyscalls.synchronize(parentDescriptor)
        requireParentIdentity("after atomic function-observation publication")
        requireNamedIdentity(target.fileName.toString(), "published function-observation output")
        requireStageMode(OWNER_READ_ONLY_MODE, "published function-observation output")
        if (digestPinnedStage(maximumBytes, budget) != expected) {
            publicationFail("published function-observation output differs from staged bytes")
        }
        verifyInputs()
        budget.checkpoint("after verifying atomic function-observation publication")
        committed = true
    }

    private fun digestPinnedStage(
        maximumBytes: Long,
        budget: CooperativeFunctionObservationBudget,
    ): FunctionObservationOutputDigest {
        val digest = MessageDigest.getInstance("SHA-256")
        val pinned = LinuxFilesystemSyscalls.stableDescriptorPath(stageDescriptor.fd)
        return FileChannel.open(pinned, StandardOpenOption.READ).use { channel ->
            val size = channel.size()
            if (size !in 1L..maximumBytes) {
                publicationFail("function-observation staging output exceeds its byte bound")
            }
            val buffer = ByteBuffer.allocate(OUTPUT_BUFFER_BYTES)
            var total = 0L
            while (total < size) {
                buffer.clear()
                buffer.limit(minOf(buffer.capacity().toLong(), size - total).toInt())
                val read = channel.read(buffer)
                if (read <= 0) publicationFail("function-observation staging output ended while hashing")
                digest.update(buffer.array(), 0, read)
                total = checkedAdd(total, read.toLong(), "function-observation staging byte count")
                budget.checkpoint("while hashing function-observation staging output")
            }
            if (channel.read(ByteBuffer.allocate(1)) >= 0) {
                publicationFail("function-observation staging output grew while hashing")
            }
            FunctionObservationOutputDigest(digest.digest().hex(), total)
        }
    }

    private fun requireParentIdentity(label: String) {
        val (_, current) = requireStableDirectory(parent, "function-observation output parent")
        if (current != parentIdentity) publicationFail("function-observation output parent changed $label")
        parentDescriptor.whileOpen { fd ->
            if (!Files.isSameFile(parent, LinuxFilesystemSyscalls.stableDescriptorPath(fd))) {
                publicationFail("function-observation output parent changed $label")
            }
        }
    }

    private fun requireNamedIdentity(name: String, label: String) {
        parentDescriptor.whileOpen { parentFd ->
            val named = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parentFd, name)
                ?: publicationFail("$label disappeared")
            named.use {
                val pinned = LinuxFilesystemSyscalls.identity(stageDescriptor.fd)
                val observed = LinuxFilesystemSyscalls.identity(named.fd)
                if (!sameRegularFile(pinned, observed)) publicationFail("$label changed identity")
            }
        }
    }

    private fun requireStageMode(mode: Int, label: String) {
        val identity = LinuxFilesystemSyscalls.identity(stageDescriptor.fd)
        if (!identity.isRegularFile || identity.isSymbolicLink || identity.linkCount != 1 ||
            identity.mode.permissions != mode
        ) {
            publicationFail("$label permissions or link count differ")
        }
    }

    override fun close() {
        var failure: Throwable? = null
        if (!committed) {
            try {
                revoke()
            } catch (cleanupFailure: Throwable) {
                failure = cleanupFailure
            }
        }
        try {
            stageDescriptor.close()
        } catch (closeFailure: Throwable) {
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        try {
            parentDescriptor.close()
        } catch (closeFailure: Throwable) {
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        failure?.let { throw it }
    }

    private fun revoke() {
        val linkedName = if (published) target.fileName.toString() else stageName
        parentDescriptor.whileOpen { parentFd ->
            val named = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parentFd, linkedName)
            if (named == null) {
                if (published) publicationFail("unverified function-observation publication disappeared")
                return@whileOpen
            }
            named.use {
                val pinned = LinuxFilesystemSyscalls.identity(stageDescriptor.fd)
                val observed = LinuxFilesystemSyscalls.identity(named.fd)
                if (!sameRegularFile(pinned, observed)) {
                    publicationFail("refusing to revoke a changed function-observation output")
                }
            }
            LinuxFilesystemSyscalls.unlink(parentFd, linkedName)
            LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, linkedName)?.use {
                publicationFail("revoked function-observation output remains linked")
            }
        }
        LinuxFilesystemSyscalls.synchronize(parentDescriptor)
    }

    companion object {
        fun create(targetPath: Path): FunctionObservationOutputStage {
            val target = targetPath.toAbsolutePath().normalize()
            if (target.parent == null || target.fileName == null) {
                publicationFail("function-observation output must name a file")
            }
            LinuxFilesystemSyscalls.requireSupported(target.parent)
            val (parent, parentIdentity) = requireStableDirectory(
                target.parent,
                "function-observation output parent",
            )
            val parentDescriptor = LinuxFilesystemSyscalls.openRoot(parent)
            try {
                parentDescriptor.whileOpen { parentFd ->
                    if (!Files.isSameFile(parent, LinuxFilesystemSyscalls.stableDescriptorPath(parentFd))) {
                        publicationFail("function-observation output parent changed during authorization")
                    }
                    LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, target.fileName.toString())?.use {
                        publicationFail("function-observation publication target already exists")
                    }
                }
                val (stageName, stageDescriptor) = createPrivateStage(parentDescriptor)
                return FunctionObservationOutputStage(
                    target = target,
                    parent = parent,
                    parentIdentity = parentIdentity,
                    parentDescriptor = parentDescriptor,
                    stageName = stageName,
                    stageDescriptor = stageDescriptor,
                )
            } catch (failure: Throwable) {
                parentDescriptor.close()
                throw failure
            }
        }

        private fun createPrivateStage(parent: LinuxDescriptor): Pair<String, LinuxDescriptor> {
            repeat(MAXIMUM_STAGE_NAME_ATTEMPTS) {
                val random = ByteArray(STAGE_RANDOM_BYTES).also(SECURE_RANDOM::nextBytes).hex()
                val name = ".function-observation-$random.tmp"
                val stage = try {
                    parent.whileOpen { parentFd ->
                        LinuxFilesystemSyscalls.createRegularFile(
                            parentFd,
                            name,
                            OWNER_READ_WRITE_MODE,
                        )
                    }
                } catch (failure: LinuxSyscallException) {
                    if (failure.errno == LinuxFilesystemSyscalls.EEXIST) return@repeat
                    throw failure
                }
                try {
                    LinuxFilesystemSyscalls.chmod(stage, OWNER_READ_WRITE_MODE)
                    LinuxFilesystemSyscalls.synchronize(stage)
                    val identity = LinuxFilesystemSyscalls.identity(stage.fd)
                    if (!identity.isRegularFile || identity.isSymbolicLink || identity.linkCount != 1 ||
                        identity.mode.permissions != OWNER_READ_WRITE_MODE
                    ) {
                        publicationFail("function-observation staging output is not private")
                    }
                    LinuxFilesystemSyscalls.synchronize(parent)
                    return name to stage
                } catch (failure: Throwable) {
                    try {
                        parent.whileOpen { LinuxFilesystemSyscalls.unlinkIfPresent(it, name) }
                    } catch (cleanupFailure: Throwable) {
                        failure.addSuppressed(cleanupFailure)
                    }
                    stage.close()
                    throw failure
                }
            }
            publicationFail("cannot allocate a unique function-observation staging output")
        }
    }
}

private fun digestStableFile(
    file: StableControlFile,
    budget: CooperativeFunctionObservationBudget,
    label: String,
): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(OUTPUT_BUFFER_BYTES)
    var total = 0L
    file.slice().use { source ->
        while (true) {
            val read = source.read(buffer)
            if (read < 0) break
            if (read == 0) publicationFail("$label made no progress while hashing")
            digest.update(buffer, 0, read)
            total = checkedAdd(total, read.toLong(), "$label byte count")
            budget.checkpoint("while hashing $label")
        }
    }
    if (total != file.size) publicationFail("$label size changed while hashing")
    budget.checkpoint("after hashing $label")
    return digest.digest().hex()
}

private fun sameRegularFile(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
    first.key == second.key && first.mountId == second.mountId &&
        first.isRegularFile && second.isRegularFile &&
        !first.isDirectory && !second.isDirectory &&
        !first.isSymbolicLink && !second.isSymbolicLink

private inline fun <T> translatePublicationFailures(action: () -> T): T = try {
    action()
} catch (failure: FullTreeFunctionObservationShardPublicationException) {
    throw failure
} catch (failure: Throwable) {
    throw FullTreeFunctionObservationShardPublicationException(
        "function-observation shard publication failed: ${failure.message}",
        failure,
    )
}

private fun checkedAdd(left: Long, right: Long, label: String): Long = try {
    Math.addExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeFunctionObservationShardPublicationException("$label overflows", failure)
}

private fun checkedMultiply(left: Long, right: Long, label: String): Long = try {
    Math.multiplyExact(left, right)
} catch (failure: ArithmeticException) {
    throw FullTreeFunctionObservationShardPublicationException("$label overflows", failure)
}

private fun publicationFail(message: String): Nothing =
    throw FullTreeFunctionObservationShardPublicationException(message)

private const val SQLITE_PAGE_BYTES = 4096L
private const val SQLITE_DATABASE_EXPANSION_FACTOR = 4L
private const val FUNCTION_NAME_ATTRIBUTES_PER_REFERENCE = 3L
private const val MAXIMUM_CANONICAL_BYTES_PER_SUBPROGRAM = 64 * 1024 * 1024
private const val CANONICAL_RESIDENT_COPY_FACTOR = 2L
private const val MINIMUM_MODELED_SQLITE_OVERHEAD_BYTES =
    CANONICAL_RESIDENT_COPY_FACTOR * MAXIMUM_CANONICAL_BYTES_PER_SUBPROGRAM
private const val MODELED_LINE_TABLE_ENTRY_BYTES = 128L
private const val MODELED_LINE_TABLE_BYTES = 1024L
private const val NANOS_PER_SECOND = 1_000_000_000L
private const val OUTPUT_BUFFER_BYTES = 1024 * 1024
private const val COMPARISON_CHECKPOINT_BYTES = 1024L * 1024L
private const val OWNER_READ_ONLY_MODE = 0x100 // 0400
private const val OWNER_READ_WRITE_MODE = 0x180 // 0600
private const val MAXIMUM_STAGE_NAME_ATTEMPTS = 32
private const val STAGE_RANDOM_BYTES = 16
private val SECURE_RANDOM = SecureRandom()
