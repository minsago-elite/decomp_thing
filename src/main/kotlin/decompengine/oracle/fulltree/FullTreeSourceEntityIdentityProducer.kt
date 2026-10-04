package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.Collections
import java.util.LinkedHashSet
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.JsonObject

/** Result of one complete, authenticated source-entity pass. No partial fact list escapes a failed pass. */
internal data class FullTreeSourceEntityIdentityScan(
    val richArtifactSha256: String,
    val inventoryArtifactSha256: String,
    val shardId: String,
    val scannedDies: Long,
    val facts: List<FullTreeSourceEntityFact>,
    val canonicalSha256: String,
    val canonicalBytes: Long,
    val peakRetainedLineTableBytes: Long,
    val peakRetainedLineTableUnits: Int,
)

internal fun requireSourceIdentityScannedDiesWithinBound(scannedDies: Long, maximumScannedDies: Long) {
    if (scannedDies < 0L || maximumScannedDies <= 0L || scannedDies > maximumScannedDies) {
        throw FullTreeControlException("source-identity shard exceeds its aggregate physical-DIE bound")
    }
}

/** Additive extractor for source identities; it does not write or alter either frozen observation schema. */
internal object FullTreeSourceEntityIdentityProducer {
    fun scanShard(
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        scratchParent: Path,
        controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
        producerLimits: FullTreeFunctionObservationProducerLimits = FullTreeFunctionObservationProducerLimits(),
        checkpoint: (String) -> Unit = {},
        /** Receives bounded candidate-to-physical claims, including ordinary emitted definitions. */
        anchorClaim: ((kind: FullTreeSourceAnchorKind, candidateId: String, physicalClaimId: String) -> Unit)? = null,
        /** Admits each canonical census row against the caller's aggregate run budget before retention. */
        factAdmission: ((fact: FullTreeSourceEntityFact, canonicalRowBytes: Long) -> Unit)? = null,
        /** Optional run-level resident allowance after reserving co-resident full-run state. */
        residentBudgetBytes: Long? = null,
        /** Admits shard-local collision copies before the source rows are copied and retained. */
        factAdjustmentAdmission: ((collisionCopyBytes: Long, collisionExpansionBytes: Long) -> Unit)? = null,
    ): FullTreeSourceEntityIdentityScan {
        FullTreeScopeControl.validate(scope, controlLimits)
        requireStableDirectory(scratchParent, "source-identity scratch parent")
        val perShard = scope.document.controlObject("bounds").controlObject("perShard")
        // The authenticated per-shard entity ceiling applies to this census. The separate
        // 20,000-function limit belongs to function projection and is not a census cap.
        val maximumFacts = perShard.controlLong("entities")
        val maximumResidentBytes = minOf(
            perShard.controlLong("maximumResidentBytes"),
            residentBudgetBytes ?: Long.MAX_VALUE,
        )
        if (maximumResidentBytes <= 0L) {
            throw FullTreeControlException("source-identity run resident-byte allowance is empty")
        }
        val maximumSerializedBytes = minOf(
            perShard.controlLong("serializedBytes"),
            MAXIMUM_SOURCE_IDENTITY_BYTES,
        )
        val memoryBounds = sourceIdentityMemoryBounds(
            maximumResidentBytes,
            maximumSerializedBytes,
        )
        val maximumCanonicalRowBytes = memoryBounds.maximumCanonicalRowBytes
        val maximumRowScratchBytes = memoryBounds.maximumRowScratchBytes
        val maximumModeledRetainedBytes = memoryBounds.maximumModeledRetainedBytes
        val maximumReferencedUnits = scope.document.controlObject("bounds").controlObject("wholeRun")
            .controlLong("compilationUnits")
        var admittedLineTableBudget: SourceIdentityLineTableBudget? = null

        // The parsed inventory tree coexists with source rows, output, and DWARF state. Reserve its
        // serialized-input expansion before parsing it; later use the admitted inventory's exact
        // CU count to divide the remaining line-table share before any line tables are retained.
        // The file-size cap is rechecked by the stable canonical-control reader, so a replaced
        // larger file cannot evade this preflight.
        val inventoryBytes = try {
            Files.size(inventoryPath)
        } catch (failure: Exception) {
            throw FullTreeControlException("source-identity inventory size is unavailable", failure)
        }
        if (inventoryBytes <= 0L || inventoryBytes > controlLimits.maximumInventoryBytes.toLong()) {
            throw FullTreeControlException("source-identity inventory exceeds its authenticated input bound")
        }
        if (maximumFacts <= 0L || maximumModeledRetainedBytes <= 0L) {
            throw FullTreeControlException("authenticated source-identity bounds are empty")
        }
        val maximumInventoryJsonNodes = minOf(inventoryBytes, MAXIMUM_SOURCE_IDENTITY_CONTROL_JSON_NODES)
        val inventoryOnlyReserve = sourceIdentityFixedStructureResidentBytes(
            authenticatedInventoryBytes = inventoryBytes,
            modeledInventoryJsonNodes = maximumInventoryJsonNodes,
            compilationUnitCount = 0L,
            modeledElfLayoutBytes = 0L,
            modeledObservedUnitMetadataBytes = 0L,
        )
        sourceIdentityAvailableRepositoryWorkingSetBytes(
            authenticatedMaximumResidentBytes = maximumResidentBytes,
            modeledLineTableBytes = 0L,
            modeledRetainedFactBytes = maximumModeledRetainedBytes,
            maximumSerializedOutputBytes = maximumSerializedBytes,
            maximumRowScratchBytes = maximumRowScratchBytes,
            modeledFixedStructureBytes = inventoryOnlyReserve,
        )
        val inventoryReadLimits = controlLimits.copy(maximumInventoryBytes = inventoryBytes.toInt())
        val modeledElfLayoutBytes = producerLimits.elfLayoutLimits.modeledResidentBytes()
        var admission: SourceIdentityInventoryAdmission? = null
        val inputs = FullTreeFunctionObservationProducer.authenticateShardInputs(
            inventoryPath,
            scope,
            shardId,
            inventoryReadLimits,
            checkpoint,
            beforeInventoryValidation = { inventory ->
                val unitCount = inventory.controlArray("units").size
                val lineTableBudget = sourceIdentityLineTableBudget(
                    configured = producerLimits.lineTableLimits,
                    maximumResidentBytes = maximumResidentBytes,
                    admittedCompilationUnitCount = unitCount.toLong(),
                    maximumAuthenticatedCompilationUnitCount = maximumReferencedUnits,
                )
                admittedLineTableBudget = lineTableBudget
                val fixedStructureBytes = sourceIdentityFixedStructureResidentBytes(
                    authenticatedInventoryBytes = inventoryBytes,
                    modeledInventoryJsonNodes = maximumInventoryJsonNodes,
                    compilationUnitCount = unitCount.toLong(),
                    modeledElfLayoutBytes = modeledElfLayoutBytes,
                    modeledObservedUnitMetadataBytes = 0L,
                )
                val availableForUnitMetadata = sourceIdentityAvailableRepositoryWorkingSetBytes(
                    authenticatedMaximumResidentBytes = maximumResidentBytes,
                    modeledLineTableBytes = lineTableBudget.modeledRetainedBytes,
                    modeledRetainedFactBytes = maximumModeledRetainedBytes,
                    maximumSerializedOutputBytes = maximumSerializedBytes,
                    maximumRowScratchBytes = maximumRowScratchBytes,
                    modeledFixedStructureBytes = fixedStructureBytes,
                )
                val boundedUnitMetadataBytes = minOf(
                    controlLimits.maximumDwarfMetadataBytes,
                    availableForUnitMetadata / SOURCE_IDENTITY_UNIT_METADATA_EXPANSION_FACTOR,
                )
                if (boundedUnitMetadataBytes <= 0L) {
                    throw FullTreeControlException("source-identity CU metadata has no authenticated resident-byte budget")
                }
                val modeledUnitMetadataBytes = Math.multiplyExact(
                    boundedUnitMetadataBytes,
                    SOURCE_IDENTITY_UNIT_METADATA_EXPANSION_FACTOR,
                )
                val fixedStructureBytesWithMetadata = sourceIdentityFixedStructureResidentBytes(
                    authenticatedInventoryBytes = inventoryBytes,
                    modeledInventoryJsonNodes = maximumInventoryJsonNodes,
                    compilationUnitCount = unitCount.toLong(),
                    modeledElfLayoutBytes = modeledElfLayoutBytes,
                    modeledObservedUnitMetadataBytes = modeledUnitMetadataBytes,
                )
                val maximumRepositoryBytes = sourceIdentityAvailableRepositoryWorkingSetBytes(
                    authenticatedMaximumResidentBytes = maximumResidentBytes,
                    modeledLineTableBytes = lineTableBudget.modeledRetainedBytes,
                    modeledRetainedFactBytes = maximumModeledRetainedBytes,
                    maximumSerializedOutputBytes = maximumSerializedBytes,
                    maximumRowScratchBytes = maximumRowScratchBytes,
                    modeledFixedStructureBytes = fixedStructureBytesWithMetadata,
                )
                admission = SourceIdentityInventoryAdmission(
                    compilationUnitCount = unitCount,
                    boundedUnitMetadataBytes = boundedUnitMetadataBytes,
                    maximumRepositoryBytes = maximumRepositoryBytes,
                )
            },
        )
        val maximumScannedDies = fullTreeFunctionObservationScannedDiesBound(
            maximumPhysicalRecordsPerUnit = producerLimits.dieLimits.maximumPhysicalRecords,
            unitCount = inputs.shard.units.size.toLong(),
            configuredMaximumScannedDies = producerLimits.accumulatorLimits.maximumScannedDies,
        )
        val inventoryUnitArray = inputs.inventory.controlArray("units")
        val admitted = admission ?: throw FullTreeControlException("source-identity inventory was not admitted")
        val lineTableBudget = admittedLineTableBudget
            ?: throw FullTreeControlException("source-identity line-table budget was not admitted")
        val lineLimits = lineTableBudget.limits
        val modeledLineBytes = lineTableBudget.modeledRetainedBytes
        if (inventoryUnitArray.size != admitted.compilationUnitCount) {
            throw FullTreeControlException("source-identity inventory unit count changed after admission")
        }
        val inventoryUnitDocuments = inventoryUnitArray.controlObjects("inventory units")
        val unitByOffset = inventoryUnitDocuments.associateBy {
            parseDwarfOffset(it.controlString("dwarfOffset"), "inventory DWARF offset")
        }
        if (unitByOffset.size != inventoryUnitDocuments.size) {
            throw FullTreeControlException("authenticated inventory repeats a DWARF compilation-unit offset")
        }
        val identityDwarfLimits = controlLimits.copy(
            maximumCompilationUnits = inventoryUnitDocuments.size,
            maximumDwarfMetadataBytes = admitted.boundedUnitMetadataBytes,
        )

        StableControlFile.open(
            richArtifact,
            controlLimits.maximumRichArtifactBytes,
            "source-identity rich artifact",
        ).use { artifact ->
            val artifactSha256 = artifact.sha256(checkpoint, "source-identity rich artifact")
            if (artifactSha256 != scope.document.controlObject("oracle").controlString("richArtifactSha256")) {
                throw FullTreeControlException("source-identity rich artifact does not match the authenticated scope")
            }
            val observedUnits = FullTreeDwarfCompilationUnits.read(
                artifact,
                scratchParent,
                scope.document,
                identityDwarfLimits,
                checkpoint,
            )
            FullTreeFunctionObservationProducer.authenticateInventoryAgainstArtifact(
                inputs.inventory,
                observedUnits,
                scope.document,
            )
            val headerParseBudget = FullTreeDwarfParseBudget(controlLimits.maximumDwarfParseSteps, checkpoint)
            var scannedDies = 0L
            var peakRetainedLineTableBytes = 0L
            var peakRetainedLineTableUnits = 0
            val budget = SourceIdentityRetentionBudget(
                maximumFacts,
                maximumModeledRetainedBytes,
                maximumCanonicalRowBytes,
                maximumRowScratchBytes,
                factAdmission,
            )
            val anchorClaims = SourceIdentityAnchorClaims(budget, anchorClaim)
            val facts = ArrayList<FullTreeSourceEntityFact>()
            val layout = FullTreeElfLayout.scanLayout(artifact, "rich artifact", producerLimits.elfLayoutLimits, checkpoint)
            val executable = FullTreeElfExecutableMembership.fromSorted(layout.executableRanges)

            FullTreeDwarfSections.open(
                artifact,
                scratchParent,
                controlLimits,
                FullTreeDwarfSections.FUNCTION_OBSERVATION_SECTION_NAMES,
            ).use { sections ->
                val info = sections.required(".debug_info")
                val headers = FullTreeFunctionObservationProducer.readAllHeaders(
                    info,
                    inventoryUnitDocuments.size,
                    headerParseBudget,
                )
                val headersByOffset = headers.associateBy { it.offset }
                val retainedTags = sourceIdentityRetainedTags()
                val maximumRetainedBytes = minOf(
                    producerLimits.dieLimits.maximumRetainedBytes,
                    admitted.maximumRepositoryBytes / (2L * producerLimits.maximumCachedCompilationUnits),
                )
                if (maximumRetainedBytes <= 0L) {
                    throw FullTreeControlException("source-identity retained-unit budget is empty")
                }
                val boundedProducerLimits = producerLimits.copy(
                    lineTableLimits = lineLimits,
                    dieLimits = producerLimits.dieLimits.copy(maximumRetainedBytes = maximumRetainedBytes),
                )
                val repository = FunctionDwarfUnitRepository(
                    sections,
                    headers,
                    controlLimits,
                    boundedProducerLimits,
                    headerParseBudget,
                    retainedTags = retainedTags,
                    contextForAttribute = ::sourceIdentityAttributeContext,
                    maximumRetainedWorkingSetBytes = admitted.maximumRepositoryBytes,
                    maximumRetainedLineTableWorkingSetBytes = modeledLineBytes,
                )
                val sourceRevision = scope.sourceLock.controlObject("revision").controlString("commit")

                inputs.shard.units.forEach { unitDocument ->
                    val unitOffset = parseDwarfOffset(
                        unitDocument.controlString("dwarfOffset"),
                        "source-identity inventory DWARF offset",
                    )
                    val header = headersByOffset[unitOffset]
                        ?: throw FullTreeControlException("source-identity unit is absent from the rich artifact")
                    val inventoryUnit = unitByOffset[unitOffset]
                        ?: throw FullTreeControlException("source-identity unit is absent from the inventory")
                    val owner = repository.load(header)
                    scannedDies = Math.addExact(scannedDies, owner.index.physicalRecordCount)
                    requireSourceIdentityScannedDiesWithinBound(scannedDies, maximumScannedDies)

                    repository.withRetainedUnits(owner) {
                        val ids = SourceEntityIdentityReader(
                            owner = owner,
                            inventoryUnit = inventoryUnit,
                            repository = repository,
                            info = info,
                            allHeaders = headers,
                            unitByOffset = unitByOffset,
                            scope = scope.document,
                            richArtifactSha256 = artifactSha256,
                            sourceRevision = sourceRevision,
                            executable = executable,
                            layout = layout,
                            controlLimits = controlLimits,
                            producerLimits = boundedProducerLimits,
                            budget = budget,
                            anchorClaims = anchorClaims,
                        )
                        owner.index.recordsInPhysicalOrder.forEach { record ->
                            if (record.tag in SOURCE_ENTITY_TAGS) {
                                val fact = ids.fact(record)
                                if (fact != null) {
                                    budget.retain(fact)
                                    facts += fact
                                }
                            }
                        }
                    }
                }
                peakRetainedLineTableBytes = repository.peakRetainedLineTableBytes
                peakRetainedLineTableUnits = repository.peakRetainedLineTableUnits
            }
            artifact.verifyUnchanged("source-identity scan")
            val ordered = FullTreeSourceEntityFact.deterministicOrder(facts)
            val maximumBaselineBytes = canonicalSourceEntityFactsByteLength(ordered, maximumSerializedBytes)
            if (maximumBaselineBytes > maximumSerializedBytes) {
                throw FullTreeControlException("canonical source-identity output exceeds its authenticated byte bound")
            }
            val collisionReport = anchorClaims.collisionReport()
            val collisionExpansionBytes = sourceIdentityCollisionExpansionUpperBound(
                ordered,
                collisionReport.byCandidateId,
                maximumSerializedBytes,
            )
            budget.charge(collisionExpansionBytes, "source-identity collision evidence")
            if (collisionExpansionBytes > maximumSerializedBytes - maximumBaselineBytes) {
                throw FullTreeControlException("source-identity collision evidence exceeds its authenticated output bound")
            }
            val collisionCopyBytes = sourceIdentityCollisionAdjustedFactCopyUpperBound(
                ordered,
                collisionReport.byCandidateId,
                maximumSerializedBytes,
            )
            factAdjustmentAdmission?.invoke(collisionCopyBytes, collisionExpansionBytes)
            budget.charge(collisionCopyBytes, "source-identity collision-adjusted fact copies")
            val collisionAdjusted = markUnprovedAnchorCollisions(ordered, collisionReport)
            val finalBytes = canonicalSourceEntityFacts(collisionAdjusted, maximumSerializedBytes)
            if (finalBytes.size.toLong() > maximumSerializedBytes) {
                throw FullTreeControlException("canonical source-identity output exceeds its authenticated byte bound")
            }
            artifact.verifyUnchanged("source-identity canonicalization")
            return FullTreeSourceEntityIdentityScan(
                richArtifactSha256 = artifactSha256,
                inventoryArtifactSha256 = inputs.inventoryArtifactSha256,
                shardId = inputs.shard.identifier,
                scannedDies = scannedDies,
                facts = Collections.unmodifiableList(collisionAdjusted),
                canonicalSha256 = OracleArtifacts.sha256(finalBytes),
                canonicalBytes = finalBytes.size.toLong(),
                peakRetainedLineTableBytes = peakRetainedLineTableBytes,
                peakRetainedLineTableUnits = peakRetainedLineTableUnits,
            )
        }
    }

    internal fun markUnprovedAnchorCollisions(
        ordered: List<FullTreeSourceEntityFact>,
        report: SourceIdentityAnchorCollisionReport,
    ): List<FullTreeSourceEntityFact> {
        if (report.byCandidateId.isEmpty()) return ordered
        return ordered.map { fact ->
            val fields = fact.semanticAnchorFields
            val relatedCandidateIds = listOfNotNull(
                fields?.inlineCalleeAnchorCandidateId,
                fields?.inlineOwnerAnchorCandidateId,
                fields?.templatePatternAnchorCandidateId,
            ) + fields?.inlinePathAnchorCandidateIds.orEmpty()
            val directCollisionIds = fact.semanticAnchorCandidateId?.let(report.byCandidateId::get).orEmpty()
            val relatedCollisionIds = relatedCandidateIds.flatMap { report.byCandidateId[it].orEmpty() }
            val collisionIds = (directCollisionIds + relatedCollisionIds).distinct().sorted()
            if (collisionIds.isEmpty()) fact else fact.copy(
                identityObservability = FullTreeIdentityObservability.AMBIGUOUS,
                candidateCollisionSourceEntityIds = collisionIds,
                reasonCodes = (fact.reasonCodes + if (directCollisionIds.isNotEmpty()) {
                    "duplicate-source-anchor-unproven"
                } else {
                    "ambiguous-related-source-anchor"
                }).distinct().sorted(),
            )
        }
    }
}

internal data class SourceIdentityAnchorCollisionReport(
    val byCandidateId: Map<String, List<String>>,
)

internal data class SourceIdentityMemoryBounds(
    val maximumCanonicalRowBytes: Long,
    val maximumRowScratchBytes: Long,
    val maximumModeledRetainedBytes: Long,
)

private data class SourceIdentityInventoryAdmission(
    val compilationUnitCount: Int,
    val boundedUnitMetadataBytes: Long,
    val maximumRepositoryBytes: Long,
)

/**
 * Modeled co-resident control and index structures, separate from retained source facts and the
 * repository's decoded DIE cache. Inventory payload expansion covers raw/canonical buffers and
 * decoded strings, and a per-JSON-node charge covers the parser's bounded object graph. The per-CU
 * allowance covers inventory entries, header/list/map nodes, and temporary validation indexes.
 * Observed CU strings/records and ELF layout use their own models. These deterministic charges
 * are an admission model; they do not claim to be measured JVM RSS.
 */
internal fun sourceIdentityFixedStructureResidentBytes(
    authenticatedInventoryBytes: Long,
    modeledInventoryJsonNodes: Long,
    compilationUnitCount: Long,
    modeledElfLayoutBytes: Long,
    modeledObservedUnitMetadataBytes: Long,
): Long {
    require(
        authenticatedInventoryBytes >= 0L && modeledInventoryJsonNodes >= 0L && compilationUnitCount >= 0L &&
            modeledElfLayoutBytes >= 0L && modeledObservedUnitMetadataBytes >= 0L,
    )
    return try {
        Math.addExact(
            Math.addExact(
                Math.addExact(
                    Math.multiplyExact(authenticatedInventoryBytes, SOURCE_IDENTITY_INVENTORY_EXPANSION_FACTOR),
                    Math.addExact(
                        Math.multiplyExact(modeledInventoryJsonNodes, SOURCE_IDENTITY_CONTROL_JSON_NODE_BYTES),
                        Math.multiplyExact(compilationUnitCount, SOURCE_IDENTITY_COMPILATION_UNIT_INDEX_BYTES),
                    ),
                ),
                modeledElfLayoutBytes,
            ),
            modeledObservedUnitMetadataBytes,
        )
    } catch (failure: ArithmeticException) {
        throw FullTreeControlException("source-identity fixed-structure model overflows", failure)
    }
}

/** Keep row, transient row scratch, retained-model, and shard-output ceilings distinct. */
internal fun sourceIdentityMemoryBounds(
    authenticatedMaximumResidentBytes: Long,
    authenticatedMaximumSerializedBytes: Long,
): SourceIdentityMemoryBounds {
    require(authenticatedMaximumResidentBytes > 0L && authenticatedMaximumSerializedBytes > 0L)
    val rowBytes = minOf(authenticatedMaximumSerializedBytes, MAXIMUM_SOURCE_IDENTITY_ROW_BYTES)
    // Serialized output is a payload bound, not a heap bound. Allow three modeled retained bytes
    // per output byte while keeping the aggregate cap distinct and fixed at 64 MiB.
    val modeledOutputAllowance = if (
        authenticatedMaximumSerializedBytes >
        MAXIMUM_SOURCE_IDENTITY_RETAINED_BYTES / SOURCE_IDENTITY_RETAINED_CONTENT_EXPANSION_FACTOR
    ) {
        MAXIMUM_SOURCE_IDENTITY_RETAINED_BYTES
    } else {
        authenticatedMaximumSerializedBytes * SOURCE_IDENTITY_RETAINED_CONTENT_EXPANSION_FACTOR
    }
    val retainedBytes = minOf(
        authenticatedMaximumResidentBytes / 4L,
        modeledOutputAllowance,
        MAXIMUM_SOURCE_IDENTITY_RETAINED_BYTES,
    )
    if (rowBytes <= 0L || retainedBytes <= 0L) {
        throw FullTreeControlException("authenticated source-identity retention bounds are empty")
    }
    val rowScratchBytes = try {
        Math.multiplyExact(rowBytes, MAXIMUM_SOURCE_IDENTITY_ROW_SCRATCH_FACTOR)
    } catch (failure: ArithmeticException) {
        throw FullTreeControlException("source-identity row-scratch model overflows", failure)
    }
    return SourceIdentityMemoryBounds(rowBytes, rowScratchBytes, retainedBytes)
}

/** Preflight modeled resident space after line tables, source facts, fixed indexes, output, and row scratch. */
internal fun sourceIdentityAvailableRepositoryWorkingSetBytes(
    authenticatedMaximumResidentBytes: Long,
    modeledLineTableBytes: Long,
    modeledRetainedFactBytes: Long,
    maximumSerializedOutputBytes: Long,
    maximumRowScratchBytes: Long,
    modeledFixedStructureBytes: Long = 0L,
): Long {
    val available = try {
        Math.subtractExact(
            Math.subtractExact(
                Math.subtractExact(
                    Math.subtractExact(
                        Math.subtractExact(authenticatedMaximumResidentBytes, modeledLineTableBytes),
                        modeledRetainedFactBytes,
                    ),
                    modeledFixedStructureBytes,
                ),
                maximumSerializedOutputBytes,
            ),
            maximumRowScratchBytes,
        )
    } catch (failure: ArithmeticException) {
        throw FullTreeControlException("source-identity peak resident model overflows", failure)
    }
    if (available <= 0L) {
        throw FullTreeControlException("source-identity peak resident model exceeds its authenticated bound")
    }
    return available
}

/** Deterministic retained-object admission charge for one canonical payload contribution. */
internal fun sourceIdentityModeledRetainedChargeBytes(canonicalPayloadBytes: Long): Long {
    require(canonicalPayloadBytes >= 0L)
    return try {
        Math.addExact(
            Math.multiplyExact(canonicalPayloadBytes, SOURCE_IDENTITY_RETAINED_CONTENT_EXPANSION_FACTOR),
            SOURCE_IDENTITY_RETAINED_CHARGE_OVERHEAD_BYTES,
        )
    } catch (failure: ArithmeticException) {
        throw FullTreeControlException("source-identity modeled retained size overflows", failure)
    }
}

internal fun sourceIdentityCompilationUnitAt(
    offset: Long,
    headers: List<FullTreeDwarfCompilationUnitHeader>,
): FullTreeDwarfCompilationUnitHeader {
    var low = 0
    var high = headers.lastIndex
    while (low <= high) {
        val middle = low + (high - low) / 2
        val header = headers[middle]
        when {
            offset < header.offset -> high = middle - 1
            offset >= header.endOffset -> low = middle + 1
            else -> return header
        }
    }
    throw FullTreeControlException("source-identity reference is outside every validated CU")
}

internal fun sourceIdentityTargetDie(
    index: FullTreeDwarfDieIndex,
    offset: Long,
    label: String,
): FullTreeDwarfDieRecord = index.required(offset, label)

/**
 * Decode a typed integer only when the form's signedness/width and the declared type support one
 * interpretation. Fixed-width unsigned forms narrower than a signed target cannot be sign-extended
 * when their own top bit is set: that encoding is ambiguous, so it remains unknown.
 */
internal fun sourceIdentityIntegralValueDescriptor(
    value: FullTreeDwarfFormValue,
    signed: Boolean,
    bits: Int,
): String? {
    if (bits !in 8..64 || bits % 8 != 0) return null
    val mask = if (bits == 64) ULong.MAX_VALUE else (1UL shl bits) - 1UL
    val signedMaximum = if (bits == 64) Long.MAX_VALUE.toULong() else (1UL shl (bits - 1)) - 1UL
    return when (value) {
        is FullTreeDwarfUnsignedConstantValue -> {
            val raw = value.rawValue
            if (raw > mask) return null
            if (!signed) raw.toString() else {
                val encodedBits = when (value.resolvedForm) {
                    FULL_TREE_DW_FORM_DATA1 -> 8
                    FULL_TREE_DW_FORM_DATA2 -> 16
                    FULL_TREE_DW_FORM_DATA4 -> 32
                    FULL_TREE_DW_FORM_DATA8 -> 64
                    FULL_TREE_DW_FORM_DATA16 -> 128
                    else -> null
                }
                when {
                    encodedBits == bits -> {
                        val signBit = 1UL shl (bits - 1)
                        val normalized = if (raw and signBit != 0UL) {
                            if (bits == 64) raw.toLong() else (raw or mask.inv()).toLong()
                        } else raw.toLong()
                        normalized.toString()
                    }
                    encodedBits != null && encodedBits < bits -> {
                        val encodedSignBit = 1UL shl (encodedBits - 1)
                        if (raw and encodedSignBit != 0UL) null else raw.toString()
                    }
                    raw <= signedMaximum -> raw.toString()
                    else -> null
                }
            }
        }
        is FullTreeDwarfSignedConstantValue -> {
            if (signed) {
                val minimum = if (bits == 64) Long.MIN_VALUE else -(1L shl (bits - 1))
                val maximum = if (bits == 64) Long.MAX_VALUE else (1L shl (bits - 1)) - 1L
                value.rawValue.takeIf { it in minimum..maximum }?.toString()
            } else {
                value.rawValue.takeIf { it >= 0L && value.rawValue.toULong() <= mask }?.toString()
            }
        }
        is FullTreeDwarfNumericValue -> {
            if (signed) {
                val minimum = if (bits == 64) Long.MIN_VALUE else -(1L shl (bits - 1))
                val maximum = if (bits == 64) Long.MAX_VALUE else (1L shl (bits - 1)) - 1L
                value.value.takeIf { it in minimum..maximum }?.toString()
            } else {
                value.value.takeIf { it >= 0L && it.toULong() <= mask }?.toString()
            }
        }
        else -> null
    }
}

/** Boolean non-type template arguments have only the source-language values zero and one. */
internal fun sourceIdentityBooleanValueDescriptor(value: FullTreeDwarfFormValue): String? {
    val numeric = when (value) {
        is FullTreeDwarfUnsignedConstantValue -> value.rawValue
        is FullTreeDwarfSignedConstantValue -> value.rawValue.takeIf { it >= 0L }?.toULong()
        is FullTreeDwarfNumericValue -> value.value.takeIf { it >= 0L }?.toULong()
        else -> null
    } ?: return null
    return numeric.takeIf { it <= 1UL }?.toString()
}

/** One independently decoded value from a validated specification/origin branch. */
internal data class SourceAnchorBranchValue<T>(
    val score: Int,
    val value: T?,
)

internal data class SourceAnchorBranchResolution<T>(
    val value: T?,
    val ambiguous: Boolean,
)

/** Merge evidence without letting a high aggregate score hide a conflicting lower-scored branch. */
internal fun <T> mergeValidatedSourceAnchorBranches(
    branches: List<SourceAnchorBranchValue<T>>,
): SourceAnchorBranchResolution<T> {
    val candidates = branches.mapNotNull(SourceAnchorBranchValue<T>::value).distinct()
    return when (candidates.size) {
        0 -> SourceAnchorBranchResolution(null, ambiguous = false)
        1 -> SourceAnchorBranchResolution(candidates.single(), ambiguous = false)
        else -> SourceAnchorBranchResolution(null, ambiguous = true)
    }
}

/** Caps each lazy line table so even every authenticated CU being pinned fits its resident share. */
internal fun boundedSourceIdentityLineTableLimits(
    configured: FullTreeDwarfLineTableLimits,
    maximumRetainedBytesPerUnit: Long,
): FullTreeDwarfLineTableLimits {
    val available = maximumRetainedBytesPerUnit - 1_024L
    val maximumEntries = available / 256L
    if (available < 512L || maximumEntries < 2L) {
        throw FullTreeControlException("source-identity line-table bound cannot fit a minimal retained table")
    }
    val maximumDirectories = minOf(configured.maximumDirectories.toLong(), maxOf(1L, maximumEntries / 2L)).toInt()
    val maximumFiles = minOf(
        configured.maximumFiles.toLong(),
        maxOf(1L, maximumEntries - maximumDirectories.toLong()),
    ).toInt()
    val maximumAggregatePathBytes = minOf(configured.maximumAggregatePathBytes, available / 4L)
    if (maximumAggregatePathBytes <= 0L) {
        throw FullTreeControlException("source-identity line-table path bound is empty")
    }
    return configured.copy(
        maximumDirectories = maximumDirectories,
        maximumFiles = maximumFiles,
        maximumAggregatePathBytes = maximumAggregatePathBytes,
    )
}

internal data class SourceIdentityLineTableBudget(
    val limits: FullTreeDwarfLineTableLimits,
    val perUnitRetainedBytes: Long,
    val modeledRetainedBytes: Long,
)

/** Divides the reserved resident share by the actual, authenticated CU population. */
internal fun sourceIdentityLineTableBudget(
    configured: FullTreeDwarfLineTableLimits,
    maximumResidentBytes: Long,
    admittedCompilationUnitCount: Long,
    maximumAuthenticatedCompilationUnitCount: Long,
): SourceIdentityLineTableBudget {
    if (maximumResidentBytes <= 0L || admittedCompilationUnitCount <= 0L ||
        maximumAuthenticatedCompilationUnitCount <= 0L
    ) {
        throw FullTreeControlException("source-identity line-table budget has no resident space or admitted CUs")
    }
    if (admittedCompilationUnitCount > maximumAuthenticatedCompilationUnitCount) {
        throw FullTreeControlException("source-identity inventory compilation-unit count exceeds its authenticated bound")
    }
    val lineWorkingSetBudget = maximumResidentBytes / 4L
    val perUnitRetainedBytes = lineWorkingSetBudget / admittedCompilationUnitCount
    val limits = boundedSourceIdentityLineTableLimits(configured, perUnitRetainedBytes)
    val modeledPerUnitBytes = try {
        Math.addExact(
            Math.addExact(
                Math.multiplyExact(limits.maximumAggregatePathBytes, 2L),
                Math.multiplyExact(
                    Math.addExact(limits.maximumDirectories.toLong(), limits.maximumFiles.toLong()),
                    128L,
                ),
            ),
            1_024L,
        )
    } catch (failure: ArithmeticException) {
        throw FullTreeControlException("source-identity line-table working-set model overflows", failure)
    }
    val modeledRetainedBytes = try {
        Math.multiplyExact(modeledPerUnitBytes, admittedCompilationUnitCount)
    } catch (failure: ArithmeticException) {
        throw FullTreeControlException("source-identity line-table working-set model overflows", failure)
    }
    if (modeledRetainedBytes > lineWorkingSetBudget) {
        throw FullTreeControlException("source-identity line-table model exceeds its authenticated working-set share")
    }
    return SourceIdentityLineTableBudget(limits, perUnitRetainedBytes, modeledRetainedBytes)
}

/** Includes anchors used only as inline callees/owners, not just census rows. */
private class SourceIdentityAnchorClaims(
    private val budget: SourceIdentityRetentionBudget,
    private val externalClaim: ((kind: FullTreeSourceAnchorKind, candidateId: String, physicalClaimId: String) -> Unit)?,
) {
    private val claims = HashMap<String, MutableSet<String>>()

    fun claim(kind: FullTreeSourceAnchorKind, candidateId: String, physical: FullTreeSourcePhysicalDie) {
        val sourceEntityId = physical.sourceEntityId(kind)
        val prior = claims[candidateId]
        if (prior?.contains(sourceEntityId) == true) return
        budget.charge(candidateId.length.toLong() + sourceEntityId.length.toLong() + 128L, "source-anchor collision index")
        // The additive run publisher admits this claim in its own bounded index before the
        // shard-local index retains it. Failed scans never publish a partial observation.
        externalClaim?.invoke(kind, candidateId, sourceEntityId)
        claims.getOrPut(candidateId) { sortedSetOf() } += sourceEntityId
    }

    fun collisionReport(): SourceIdentityAnchorCollisionReport {
        val collisions = claims.filterValues { it.size > 1 }
        collisions.values.forEach { sourceEntityIds ->
            budget.charge(sourceEntityIds.size.toLong() * 16L + 64L, "source-anchor collision report")
        }
        return SourceIdentityAnchorCollisionReport(
            byCandidateId = collisions.mapValues { (_, sourceEntityIds) -> sourceEntityIds.toList() },
        )
    }
}

/** Conservative preflight for per-row copies of collision IDs and their ambiguity reason. */
internal fun sourceIdentityCollisionExpansionUpperBound(
    facts: List<FullTreeSourceEntityFact>,
    collisionSourceEntityIdsByCandidate: Map<String, List<String>>,
    maximumCanonicalBytes: Long = MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES,
): Long {
    canonicalSourceEntityFactsByteLength(facts, maximumCanonicalBytes)
    var total = 0L
    try {
        facts.forEach { fact ->
            val fields = fact.semanticAnchorFields
            val candidateIds = listOfNotNull(
                fact.semanticAnchorCandidateId,
                fields?.inlineCalleeAnchorCandidateId,
                fields?.inlineOwnerAnchorCandidateId,
                fields?.templatePatternAnchorCandidateId,
            ) + fields?.inlinePathAnchorCandidateIds.orEmpty()
            val distinctCandidateIds = candidateIds.distinct()
            var copiedIds = 0L
            distinctCandidateIds.forEach { candidateId ->
                copiedIds = Math.addExact(
                    copiedIds,
                    collisionSourceEntityIdsByCandidate[candidateId]?.size?.toLong() ?: 0L,
                )
            }
            if (copiedIds > 0L) {
                // A JSON ID costs 66 bytes plus a possible comma. An extra 128 bytes per affected
                // row bounds the state and reason-code replacement too. Duplicate related IDs are
                // deliberately over-counted so this estimate is safe before list materialization.
                total = Math.addExact(total, Math.addExact(Math.multiplyExact(copiedIds, 67L), 128L))
            }
        }
    } catch (failure: ArithmeticException) {
        throw FullTreeControlException("source-identity collision evidence size overflows", failure)
    }
    return total
}

/** Bounds the copied nested evidence arrays and result-list references before collision copies are made. */
internal fun sourceIdentityCollisionAdjustedFactCopyUpperBound(
    facts: List<FullTreeSourceEntityFact>,
    collisionSourceEntityIdsByCandidate: Map<String, List<String>>,
    maximumCanonicalBytes: Long = MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES,
): Long {
    if (collisionSourceEntityIdsByCandidate.isEmpty()) return 0L
    var total = 0L
    try {
        // markUnprovedAnchorCollisions returns a new list when a collision exists, even when a
        // particular row is reused. Model those references separately from changed fact objects.
        total = Math.addExact(64L, Math.multiplyExact(facts.size.toLong(), 8L))
        facts.forEach { fact ->
            val fields = fact.semanticAnchorFields
            val candidateIds = listOfNotNull(
                fact.semanticAnchorCandidateId,
                fields?.inlineCalleeAnchorCandidateId,
                fields?.inlineOwnerAnchorCandidateId,
                fields?.templatePatternAnchorCandidateId,
            ) + fields?.inlinePathAnchorCandidateIds.orEmpty()
            if (candidateIds.any { collisionSourceEntityIdsByCandidate[it].orEmpty().isNotEmpty() }) {
                val factBytes = canonicalSourceEntityFacts(listOf(fact), maximumCanonicalBytes).size.toLong()
                total = Math.addExact(total, Math.addExact(factBytes, SOURCE_IDENTITY_RETAINED_CHARGE_OVERHEAD_BYTES))
            }
        }
    } catch (failure: ArithmeticException) {
        throw FullTreeControlException("source-identity collision-adjusted fact copy size overflows", failure)
    }
    return total
}

/** Admission for transient and accumulating text built while one source row is being derived. */
private class SourceIdentityRowScratchBudget(
    private val maximumBytes: Long,
) {
    private var chargedBytes = 0L

    fun charge(bytesToAdd: Long, label: String) {
        if (bytesToAdd < 0L) throw FullTreeControlException("$label scratch size is negative")
        chargedBytes = try {
            Math.addExact(chargedBytes, bytesToAdd)
        } catch (failure: ArithmeticException) {
            throw FullTreeControlException("$label row-scratch size overflows", failure)
        }
        if (chargedBytes > maximumBytes) {
            throw FullTreeControlException(
                "source-identity row scratch exceeds its authenticated bound while building $label " +
                    "($chargedBytes > $maximumBytes)",
            )
        }
    }
}

/** Memoizes one DIE's range-derived start for the duration of its row classification. */
internal class FullTreeSourceIdentityFunctionStartResolution(
    private val resolve: () -> ULong?,
) {
    private var resolved = false
    private var value: ULong? = null

    fun get(): ULong? {
        if (!resolved) {
            value = resolve()
            resolved = true
        }
        return value
    }
}

private class SourceIdentityRetentionBudget(
    private val maximumFacts: Long,
    private val maximumBytes: Long,
    private val maximumCanonicalRowBytes: Long,
    val maximumRowScratchBytes: Long,
    private val factAdmission: ((fact: FullTreeSourceEntityFact, canonicalRowBytes: Long) -> Unit)?,
) {
    private var facts = 0L
    private var bytes = 0L

    fun charge(bytesToAdd: Long, label: String) {
        if (bytesToAdd < 0L) throw FullTreeControlException("$label size is negative")
        // Model UTF-16 strings, object/list references, and retained copies conservatively as
        // three times canonical payload plus fixed per-allocation overhead. This is a deterministic
        // admission model, not an observed JVM RSS guarantee.
        val modeledBytes = try {
            sourceIdentityModeledRetainedChargeBytes(bytesToAdd)
        } catch (failure: FullTreeControlException) {
            throw FullTreeControlException("$label modeled resident size overflows", failure)
        }
        bytes = try {
            Math.addExact(bytes, modeledBytes)
        } catch (failure: ArithmeticException) {
            throw FullTreeControlException("$label size overflows", failure)
        }
        if (bytes > maximumBytes) {
            throw FullTreeControlException(
                "source-identity modeled retained facts exceed their byte bound ($bytes > $maximumBytes)",
            )
        }
    }

    fun retain(fact: FullTreeSourceEntityFact) {
        if (facts >= maximumFacts) throw FullTreeControlException("source-identity census exceeds its entity bound")
        val serialized = canonicalSourceEntityFacts(listOf(fact), maximumCanonicalRowBytes).size.toLong()
        factAdmission?.invoke(fact, serialized)
        charge(serialized, "source-identity fact")
        facts++
    }
}

private class SourceEntityIdentityReader(
    private val owner: FunctionDwarfUnit,
    private val inventoryUnit: JsonObject,
    private val repository: FunctionDwarfUnitRepository,
    private val info: FullTreeDwarfSection,
    private val allHeaders: List<FullTreeDwarfCompilationUnitHeader>,
    private val unitByOffset: Map<Long, JsonObject>,
    private val scope: JsonObject,
    private val richArtifactSha256: String,
    private val sourceRevision: String,
    private val executable: FullTreeElfExecutableMembership,
    private val layout: FullTreeElfCoreLayout,
    private val controlLimits: FullTreeControlLimits,
    private val producerLimits: FullTreeFunctionObservationProducerLimits,
    private val budget: SourceIdentityRetentionBudget,
    private val anchorClaims: SourceIdentityAnchorClaims,
) {
    private val anchorCache = HashMap<String, CachedAnchorEvidence>()
    private val anchorStack = LinkedHashSet<String>()
    private val anchorEdgeCaptures = ArrayDeque<MutableList<FullTreeSourceIdentityEdge>>()
    private var activeRowScratchBudget: SourceIdentityRowScratchBudget? = null

    private data class CachedAnchorEvidence(
        val fields: FullTreeSourceAnchorFields?,
        val edges: List<FullTreeSourceIdentityEdge>,
        val reasonCodes: List<String>,
    )

    private data class SourceAnchorProvider(
        val unit: FunctionDwarfUnit,
        val record: FullTreeDwarfDieRecord,
        val score: Int,
        val records: List<SourceAnchorRecord>,
    )

    private data class SourceAnchorRecord(
        val unit: FunctionDwarfUnit,
        val record: FullTreeDwarfDieRecord,
        val score: Int,
    )

    private data class PackedSubprogramChild(
        val record: FullTreeDwarfDieRecord,
        val packPath: String?,
    )

    fun fact(record: FullTreeDwarfDieRecord): FullTreeSourceEntityFact? {
        val prior = activeRowScratchBudget
        if (prior != null) return factWithRowScratch(record)
        activeRowScratchBudget = SourceIdentityRowScratchBudget(budget.maximumRowScratchBytes)
        return try {
            factWithRowScratch(record)
        } finally {
            activeRowScratchBudget = null
        }
    }

    private fun factWithRowScratch(record: FullTreeDwarfDieRecord): FullTreeSourceEntityFact? {
        val physical = physical(owner, record)
        val edgeList = ArrayList<FullTreeSourceIdentityEdge>()
        val reasonCodes = sortedSetOf<String>()
        collectReferenceGraph(owner, record, physical, edgeList, reasonCodes)
        if (edgeList.any { it.state == FullTreeSourceIdentityEdgeState.CYCLIC }) reasonCodes += "ambiguous-reference-cycle"
        if (edgeList.any { it.state in setOf(FullTreeSourceIdentityEdgeState.MISSING_TARGET, FullTreeSourceIdentityEdgeState.MALFORMED, FullTreeSourceIdentityEdgeState.UNSUPPORTED) }) {
            reasonCodes += "unknown-reference-edge"
        }
        val isInline = record.tag == DW_TAG_INLINED_SUBROUTINE
        val templateFormals = packedSubprogramChildren(
            owner,
            record,
            setOf(DW_TAG_TEMPLATE_TYPE_PARAMETER, DW_TAG_TEMPLATE_VALUE_PARAMETER),
            FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT,
            edgeList,
        ).map(PackedSubprogramChild::record)
        val templateState = templateState(owner, templateFormals, edgeList, reasonCodes)
        val functionStartResolution = FullTreeSourceIdentityFunctionStartResolution { owner.functionStart(record) }
        val kind = when {
            isInline -> FullTreeSourceEntityKind.INLINE_INSTANCE
            templateState == TemplateParameterState.PATTERN -> FullTreeSourceEntityKind.TEMPLATE_PATTERN
            templateState == TemplateParameterState.INSTANCE -> FullTreeSourceEntityKind.TEMPLATE_INSTANCE
            templateState == TemplateParameterState.UNKNOWN -> FullTreeSourceEntityKind.UNRESOLVED
            record.truthy(DW_AT_DECLARATION, "DW_AT_declaration") -> FullTreeSourceEntityKind.DECLARATION_ONLY
            functionStartResolution.get() == null -> FullTreeSourceEntityKind.NO_RANGE_DEFINITION
            else -> FullTreeSourceEntityKind.UNRESOLVED
        }
        // Ordinary emitted functions are already represented by the emitted-RVA observation. The
        // census adds only source identities that otherwise disappear or need an explicit relation.
        if (!isInline && kind == FullTreeSourceEntityKind.UNRESOLVED && templateFormals.isEmpty()) {
            // Emitted definitions remain represented by the existing RVA observation, but their
            // source anchor still participates in unproved-collision detection when another row
            // relates to that definition.
            if (relatedSubprogramKind(owner, record, edgeList, reasonCodes, functionStartResolution) ==
                FullTreeSourceAnchorKind.SOURCE_DEFINITION
            ) {
                anchorFields(owner, record, FullTreeSourceAnchorKind.SOURCE_DEFINITION, edgeList, reasonCodes, physical)
            }
            return null
        }
        if (edgeList.any { it.state == FullTreeSourceIdentityEdgeState.CYCLIC }) reasonCodes += "ambiguous-reference-cycle"
        if (edgeList.any { it.state in setOf(FullTreeSourceIdentityEdgeState.MISSING_TARGET, FullTreeSourceIdentityEdgeState.MALFORMED, FullTreeSourceIdentityEdgeState.UNSUPPORTED) }) {
            reasonCodes += "unknown-reference-edge"
        }
        val fields = kind.anchorKind()?.let { anchorFields(owner, record, it, edgeList, reasonCodes, physical) }
        val anchorId = kind.anchorKind()?.let { anchorKind -> fields?.candidateId(anchorKind) }
        val completeAnchor = anchorId != null
        if (!completeAnchor) reasonCodes += "source-anchor-incomplete"
        val declaration = record.truthy(DW_AT_DECLARATION, "DW_AT_declaration")
        if (declaration) reasonCodes += "declaration-only-no-definition"
        val observability = when {
            reasonCodes.any { it.startsWith("ambiguous-") } -> FullTreeIdentityObservability.AMBIGUOUS
            declaration -> FullTreeIdentityObservability.UNOBSERVABLE
            reasonCodes.any { it.startsWith("unknown-") } -> FullTreeIdentityObservability.UNKNOWN
            completeAnchor -> FullTreeIdentityObservability.OBSERVABLE
            else -> FullTreeIdentityObservability.UNKNOWN
        }
        val (disposition, emittedRva) = when {
            isInline || kind == FullTreeSourceEntityKind.DECLARATION_ONLY || kind == FullTreeSourceEntityKind.TEMPLATE_PATTERN ->
                FullTreeDenominatorDisposition.NON_SCOREABLE to null
            kind == FullTreeSourceEntityKind.TEMPLATE_INSTANCE || kind == FullTreeSourceEntityKind.NO_RANGE_DEFINITION ->
                emittedLink(owner, record)
            else -> FullTreeDenominatorDisposition.UNKNOWN to null
        }
        return FullTreeSourceEntityFact(
            sourceEntityId = physical.sourceEntityId(kind),
            physicalDie = physical,
            kind = kind,
            identityObservability = observability,
            denominatorDisposition = disposition,
            semanticAnchorFields = fields,
            semanticAnchorCandidateId = anchorId,
            resolvedSemanticIdentityId = null,
            candidateCollisionSourceEntityIds = emptyList(),
            linkedEmittedRva = emittedRva,
            reasonCodes = reasonCodes.toList(),
            edges = edgeList.sortedWith(compareBy({ it.kind.wireValue }, { it.source.locator() }, { it.target?.locator() ?: "~" }, { it.state.wireValue }, { it.rawReference ?: "~" })),
        )
    }

    /** Flattens only the standard GNU parameter-pack wrapper while preserving its ordered group path. */
    private fun packedSubprogramChildren(
        unit: FunctionDwarfUnit,
        subprogram: FullTreeDwarfDieRecord,
        acceptedTags: Set<Long>,
        structuralEdgeKind: FullTreeSourceIdentityEdgeKind,
        edges: MutableList<FullTreeSourceIdentityEdge>,
    ): List<PackedSubprogramChild> {
        val result = ArrayList<PackedSubprogramChild>()
        val pending = ArrayDeque<Triple<FullTreeDwarfDieRecord, FullTreeDwarfDieRecord, String?>>()
        unit.directChildren(subprogram).asReversed().forEach { pending.addFirst(Triple(subprogram, it, null)) }
        var nextPackOrdinal = 0
        while (pending.isNotEmpty()) {
            val (parent, child, parentPackPath) = pending.removeFirst()
            if (child.tag == DW_TAG_GNU_TEMPLATE_PARAMETER_PACK || child.tag == DW_TAG_GNU_FORMAL_PARAMETER_PACK) {
                val packPath = parentPackPath?.let { "$it.$nextPackOrdinal" } ?: nextPackOrdinal.toString()
                nextPackOrdinal++
                addStructuralEdge(physical(unit, parent), physical(unit, child), structuralEdgeKind, edges)
                val nested = unit.directChildren(child)
                if (nested.isEmpty()) result += PackedSubprogramChild(child, packPath)
                else nested.asReversed().forEach { pending.addFirst(Triple(child, it, packPath)) }
            } else if (child.tag in acceptedTags) {
                // Typed evidence starts at the actual parameter/formal DIE. Preserve its bounded
                // parent-child path so the v2 envelope can check graph connectivity without
                // inferring ancestry from DIE offset ordering.
                if (parentPackPath != null || child.attributesNamed(DW_AT_TYPE).isNotEmpty()) {
                    addStructuralEdge(physical(unit, parent), physical(unit, child), structuralEdgeKind, edges)
                }
                result += PackedSubprogramChild(child, parentPackPath)
            }
        }
        return result
    }

    private fun anchorFields(
        dieUnit: FunctionDwarfUnit,
        record: FullTreeDwarfDieRecord,
        kind: FullTreeSourceAnchorKind,
        edges: MutableList<FullTreeSourceIdentityEdge>,
        reasons: MutableSet<String>,
        physical: FullTreeSourcePhysicalDie,
    ): FullTreeSourceAnchorFields? {
        val key = physical.locator() + ":" + kind.wireValue
        anchorCache[key]?.let { cached ->
            cached.edges.forEach { retainEdge(edges, it) }
            reasons.addAll(cached.reasonCodes)
            return cached.fields
        }
        if (!anchorStack.add(key)) {
            reasons += "ambiguous-reference-cycle"
            return null
        }
        val edgeCapture = ArrayList<FullTreeSourceIdentityEdge>()
        anchorEdgeCaptures.addLast(edgeCapture)
        val originalReasons = reasons.toSet()
        var result: FullTreeSourceAnchorFields? = null
        try {
            val originRecord: FullTreeDwarfDieRecord? = if (record.tag == DW_TAG_INLINED_SUBROUTINE) {
                val originAttr = sourceReferenceAttribute(
                    dieUnit, record, DW_AT_ABSTRACT_ORIGIN,
                    FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN, edges, reasons,
                )
                if (originAttr == null) {
                    reasons += "unknown-inline-origin"
                    null
                } else {
                    referenceEdge(dieUnit, record, originAttr, FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN, physical, edges)
                        ?.let { (unit, target) ->
                            if (target.tag != DW_TAG_SUBPROGRAM) {
                                reasons += "ambiguous-inline-origin-kind"
                                null
                            } else {
                                target
                            }
                        }
                }
            } else {
                record
            }
            if (originRecord == null) return null
            val originUnit = if (originRecord === record) dieUnit else unitForRecord(originRecord)
            val provider = sourceAnchorProvider(originUnit, originRecord, edges, reasons)
            val baseUnit = provider.unit
            val baseRecord = provider.record
            val templateSourceUnit = if (kind == FullTreeSourceAnchorKind.TEMPLATE_INSTANCE) originUnit else baseUnit
            val templateSourceRecord = if (kind == FullTreeSourceAnchorKind.TEMPLATE_INSTANCE) originRecord else baseRecord
            val sourceRecords = provider.records
            val sourcePath = uniqueInheritedSourceValue(sourceRecords, "source-path", reasons) {
                declarationPath(it.unit, it.record, DW_AT_DECL_FILE, "DW_AT_decl_file")
            }
            if (sourcePath == null && sourceRecords.none { it.record.attributesNamed(DW_AT_DECL_FILE).isNotEmpty() }) {
                reasons += "unknown-source-declaration-file"
            }
            val declarationLines = sourceRecords.mapNotNull { source ->
                source.record.optionalNonNegativeLong(DW_AT_DECL_LINE, "DW_AT_decl_line")?.takeIf { it > 0L }
            }.distinct()
            if (declarationLines.size > 1) reasons += "ambiguous-inherited-declaration-line"
            val declLine = declarationLines.singleOrNull()
            if (sourceRecords.any { it.record.attributesNamed(DW_AT_DECL_LINE).isNotEmpty() } && declLine == null) {
                reasons += "unknown-source-declaration-line"
            }
            val sourcePathRecord = sourcePath?.let { path ->
                sourceRecords.firstOrNull { source ->
                    declarationPath(source.unit, source.record, DW_AT_DECL_FILE, "DW_AT_decl_file") == path
                }
            }
            val declFile = sourcePathRecord?.record?.optionalNonNegativeLong(DW_AT_DECL_FILE, "DW_AT_decl_file")
                ?: baseRecord.optionalNonNegativeLong(DW_AT_DECL_FILE, "DW_AT_decl_file")
            // The optional compiler-local column is excluded from the semantic hash, but every
            // validated branch still participates in conflict detection before retaining it.
            val declColumn = uniqueInheritedSourceValue(sourceRecords, "declaration-column", reasons) { source ->
                source.record.optionalNonNegativeLong(DW_AT_DECL_COLUMN, "DW_AT_decl_column")
            }
            val sourceName = uniqueInheritedSourceValue(sourceRecords, "source-name", reasons) { source ->
                source.record.optionalUniqueAttribute(DW_AT_NAME, "DW_AT_name")?.let { attr ->
                    FullTreeDwarfForms.decodeString(
                        attr.value,
                        source.unit.sections,
                        source.unit.stringOffsetsBase,
                        source.unit.header.offsetSize,
                        controlLimits,
                        "source identity DW_AT_name",
                        16_384,
                    )
                }
            }
            if (sourceName == null) reasons += "unknown-source-name"
            val lexicalCandidates = sourceRecords.map { lexicalContext(it.unit, it.record) }.filter { it.isNotEmpty() }.distinct()
            if (lexicalCandidates.size > 1) reasons += "ambiguous-inherited-lexical-context"
            val lexical = lexicalCandidates.singleOrNull().orEmpty()
            val languageCandidates = sourceRecords.mapNotNull { source ->
                val inventory = unitByOffset[source.unit.header.offset] ?: inventoryUnit
                inventory["language"]?.takeUnless { it == kotlinx.serialization.json.JsonNull }
                    ?.let { (it as kotlinx.serialization.json.JsonPrimitive).longOrNull }
            }.distinct()
            if (languageCandidates.size > 1) reasons += "ambiguous-inherited-language"
            val language = languageCandidates.singleOrNull()
            val signature = signature(sourceRecords, edges, reasons)
            var templateFormalDescriptors: List<String>? = null
            var patternAnchorId: String? = null
            var actualArguments: List<String>? = null
            if (kind == FullTreeSourceAnchorKind.TEMPLATE_PATTERN || kind == FullTreeSourceAnchorKind.TEMPLATE_INSTANCE) {
                if (kind == FullTreeSourceAnchorKind.TEMPLATE_PATTERN) {
                    val formalBranches = arrayListOf<SourceAnchorBranchValue<List<String>>>()
                    var unknownFormalBranch = false
                    var conflictingFormalKind = false
                    sourceRecords.distinctBy { physical(it.unit, it.record).locator() }.forEach { source ->
                        val sourceFormals = packedSubprogramChildren(
                            source.unit,
                            source.record,
                            setOf(DW_TAG_TEMPLATE_TYPE_PARAMETER, DW_TAG_TEMPLATE_VALUE_PARAMETER),
                            FullTreeSourceIdentityEdgeKind.TEMPLATE_FORMAL,
                            edges,
                        )
                        if (sourceFormals.isEmpty()) return@forEach
                        val sourceRecordsForFormals = sourceFormals.map(PackedSubprogramChild::record)
                        if (sourceRecordsForFormals.size > MAXIMUM_DWARF_TEMPLATE_PARAMETERS) {
                            throw FullTreeControlException("source-identity template parameters exceed their 1,024-entry bound")
                        }
                        when (templateState(source.unit, sourceRecordsForFormals, edges, reasons)) {
                            TemplateParameterState.PATTERN -> {
                                val values = arrayListOf<String>()
                                var complete = true
                                sourceFormals.forEach { packedFormal ->
                                    val formal = packedFormal.record
                                    addStructuralEdge(
                                        physical(source.unit, source.record),
                                        physical(source.unit, formal),
                                        FullTreeSourceIdentityEdgeKind.TEMPLATE_FORMAL,
                                        edges,
                                    )
                                    val name = formal.optionalUniqueAttribute(DW_AT_NAME, "DW_AT_name")?.let {
                                        FullTreeDwarfForms.decodeString(
                                            it.value,
                                            source.unit.sections,
                                            source.unit.stringOffsetsBase,
                                            source.unit.header.offsetSize,
                                            controlLimits,
                                            "template formal name",
                                            16_384,
                                        )
                                    }
                                    val descriptor = if (formal.tag == DW_TAG_TEMPLATE_TYPE_PARAMETER) {
                                        "type-formal:${name ?: "unnamed"}"
                                    } else {
                                        val declaredType = sourceReferenceAttribute(
                                            source.unit,
                                            formal,
                                            DW_AT_TYPE,
                                            FullTreeSourceIdentityEdgeKind.TEMPLATE_FORMAL,
                                            edges,
                                            reasons,
                                        )?.let {
                                            typeDescriptor(
                                                source.unit,
                                                formal,
                                                it,
                                                edges,
                                                FullTreeSourceIdentityEdgeKind.TEMPLATE_FORMAL,
                                                reasons,
                                            )
                                        }
                                        if (declaredType == null) null else "value-formal:$declaredType:${name ?: "unnamed"}"
                                    }
                                    if (descriptor == null) {
                                        reasons += "unknown-template-formal-type"
                                        complete = false
                                    } else {
                                        budget.charge(
                                            descriptor.toByteArray(StandardCharsets.UTF_8).size.toLong(),
                                            "template formal descriptor",
                                        )
                                        val rendered = packedFormal.packPath?.let { "pack[$it]:$descriptor" } ?: descriptor
                                        chargeRowScratch(
                                            sourceIdentityUtf8ByteLength(rendered),
                                            "template formal descriptor",
                                        )
                                        values += rendered
                                    }
                                }
                                if (complete) formalBranches += SourceAnchorBranchValue(source.score, values)
                                else unknownFormalBranch = true
                            }
                            TemplateParameterState.UNKNOWN -> {
                                reasons += "unknown-template-pattern-formals"
                                unknownFormalBranch = true
                            }
                            TemplateParameterState.INSTANCE, TemplateParameterState.NONE -> {
                                reasons += "ambiguous-inherited-template-formals"
                                conflictingFormalKind = true
                            }
                        }
                    }
                    val mergedFormals = mergeValidatedSourceAnchorBranches(formalBranches)
                    if (mergedFormals.ambiguous) {
                        reasons += "ambiguous-inherited-template-formals"
                    }
                    templateFormalDescriptors = mergedFormals.value.takeUnless {
                        unknownFormalBranch || conflictingFormalKind || mergedFormals.ambiguous
                    }
                    if (templateFormalDescriptors == null) reasons += "unknown-template-pattern-formals"
                } else {
                    val formalChildren = packedSubprogramChildren(
                        templateSourceUnit,
                        templateSourceRecord,
                        setOf(DW_TAG_TEMPLATE_TYPE_PARAMETER, DW_TAG_TEMPLATE_VALUE_PARAMETER),
                        FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT,
                        edges,
                    )
                    val formals = formalChildren.map(PackedSubprogramChild::record)
                    if (formals.size > MAXIMUM_DWARF_TEMPLATE_PARAMETERS) {
                        throw FullTreeControlException("source-identity template parameters exceed their 1,024-entry bound")
                    }
                    val args = arrayListOf<String>()
                    formalChildren.forEach { packedFormal ->
                        val formal = packedFormal.record
                        val descriptor = when (formal.tag) {
                            DW_TAG_TEMPLATE_TYPE_PARAMETER -> sourceReferenceAttribute(
                                templateSourceUnit, formal, DW_AT_TYPE,
                                FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT, edges, reasons,
                            )
                                ?.let { typeDescriptor(templateSourceUnit, formal, it, edges, FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT, reasons) }
                                ?.let { type ->
                                    chargeRowScratchText("template type argument", "type-argument:", type)
                                    "type-argument:$type"
                                }
                            DW_TAG_TEMPLATE_VALUE_PARAMETER -> {
                                val typeAttribute = sourceReferenceAttribute(
                                    templateSourceUnit, formal, DW_AT_TYPE,
                                    FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT, edges, reasons,
                                )
                                val typeTarget = typeAttribute?.let {
                                    referenceEdge(
                                        templateSourceUnit, formal, it,
                                        FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT,
                                        physical(templateSourceUnit, formal), edges,
                                    )
                                }
                                val type = typeTarget?.let { describeType(it.first, it.second, HashSet(), 0, reasons, edges) }
                                val constValues = formal.attributesNamed(DW_AT_CONST_VALUE)
                                val value = if (constValues.size == 1 && typeTarget != null) {
                                    typedIntegralDescriptor(constValues.single().value, typeTarget.first, typeTarget.second, edges, reasons)
                                } else {
                                    if (constValues.size > 1) reasons += "ambiguous-template-argument-value"
                                    null
                                }
                                if (type == null || value == null) {
                                    null
                                } else {
                                    chargeRowScratchText("template value argument", "value-argument:type=", type, ":value=", value)
                                    "value-argument:type=$type:value=$value"
                                }
                            }
                            else -> null
                        }
                        if (descriptor == null) reasons += "unknown-template-argument" else {
                            budget.charge(descriptor.toByteArray(StandardCharsets.UTF_8).size.toLong(), "template actual argument")
                            // Actual template arguments are an ordered semantic tuple. GNU's
                            // wrapper-group path is artifact/compiler structure, retained by the
                            // typed TEMPLATE_ARGUMENT structural edges above rather than hashed
                            // into the cross-compiler candidate.
                            args += descriptor
                        }
                    }
                    actualArguments = args.takeIf { it.size == formals.size }
                    val patternAttr = listOf(DW_AT_SPECIFICATION, DW_AT_ABSTRACT_ORIGIN).mapNotNull { attrName ->
                        sourceReferenceAttribute(
                            templateSourceUnit, templateSourceRecord, attrName,
                            if (attrName == DW_AT_SPECIFICATION) FullTreeSourceIdentityEdgeKind.SPECIFICATION
                            else FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN,
                            edges, reasons,
                        )
                    }
                    if (patternAttr.size == 1) {
                        val target = referenceEdge(templateSourceUnit, templateSourceRecord, patternAttr.single(),
                            if (patternAttr.single().name == DW_AT_SPECIFICATION) FullTreeSourceIdentityEdgeKind.SPECIFICATION else FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN,
                            physical(templateSourceUnit, templateSourceRecord), edges)
                        if (target != null && target.second.tag == DW_TAG_SUBPROGRAM) {
                            val patternFormals = packedSubprogramChildren(
                                target.first,
                                target.second,
                                setOf(DW_TAG_TEMPLATE_TYPE_PARAMETER, DW_TAG_TEMPLATE_VALUE_PARAMETER),
                                FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT,
                                edges,
                            ).map(PackedSubprogramChild::record)
                            val verifiedPattern = templateState(target.first, patternFormals, edges, reasons) ==
                                TemplateParameterState.PATTERN
                            if (verifiedPattern) {
                                val patternFields = anchorFields(
                                    target.first,
                                    target.second,
                                    FullTreeSourceAnchorKind.TEMPLATE_PATTERN,
                                    edges,
                                    reasons,
                                    physical(target.first, target.second),
                                )
                                patternAnchorId = patternFields?.candidateId(FullTreeSourceAnchorKind.TEMPLATE_PATTERN)
                            } else reasons += "unknown-template-pattern-reference"
                        } else reasons += "unknown-template-pattern-reference"
                    } else {
                        reasons += if (patternAttr.isEmpty()) "unknown-template-pattern-reference" else "ambiguous-template-pattern-reference"
                    }
                }
            }
            var inlineCallee: String? = null
            var inlineOwner: String? = null
            var callFile: String? = null
            var callLine: Long? = null
            var callColumn: Long? = null
            var inlinePath: List<String>? = null
            if (kind == FullTreeSourceAnchorKind.INLINE_INSTANCE) {
                inlineCallee = baseRecord.takeIf { baseRecord !== record }
                    ?.let { callee ->
                        val calleeKind = relatedSubprogramKind(baseUnit, callee, edges, reasons)
                        calleeKind?.let {
                            anchorFields(baseUnit, callee, it, edges, reasons, physical(baseUnit, callee))
                                ?.candidateId(it)
                        }
                    }
                if (inlineCallee == null) reasons += "unknown-inline-callee-anchor"
                val parent = record.nearestRetainedParentOffset?.let(owner.index::find)
                val containing = parent?.let { nearestContainingSubprogram(owner, it) }
                if (containing == null) {
                    reasons += "unknown-inline-owner"
                } else {
                    val containingPhysical = physical(owner, containing)
                    addStructuralEdge(physical, containingPhysical, FullTreeSourceIdentityEdgeKind.INLINE_OWNER, edges)
                    val ownerKind = relatedSubprogramKind(owner, containing, edges, reasons)
                    inlineOwner = ownerKind?.let {
                        anchorFields(owner, containing, it, edges, reasons, containingPhysical)?.candidateId(it)
                    }
                    if (inlineOwner == null) reasons += "unknown-inline-owner-anchor"
                }
                val callFileIndex = record.optionalNonNegativeLong(DW_AT_CALL_FILE, "DW_AT_call_file")
                callFile = callFileIndex?.let { resolvePath(owner, it) }
                callLine = record.optionalNonNegativeLong(DW_AT_CALL_LINE, "DW_AT_call_line")?.takeIf { it > 0L }
                callColumn = record.optionalNonNegativeLong(DW_AT_CALL_COLUMN, "DW_AT_call_column")
                if (callFile == null || callLine == null) reasons += "unknown-inline-callsite"
                inlinePath = enclosingInlinePath(owner, record, reasons, edges)
            }
            if (sourcePath == null || declLine == null || language == null || signature == null) {
                reasons += "source-anchor-incomplete"
            }
            if (kind == FullTreeSourceAnchorKind.TEMPLATE_INSTANCE && sourceName != null && actualArguments != null &&
                canonicalSourceIdentityTemplateInstanceBaseName(sourceName, actualArguments.size) == null
            ) {
                reasons += "unknown-template-instance-name-rendering"
            }
            val fields = FullTreeSourceAnchorFields(
                sourcePath = sourcePath,
                declarationFileIndex = declFile,
                declarationLine = declLine,
                declarationColumn = declColumn,
                language = language,
                lexicalContext = lexical,
                sourceName = sourceName,
                signature = signature,
                templateFormalParameters = templateFormalDescriptors,
                templatePatternAnchorCandidateId = patternAnchorId,
                templateActualArguments = actualArguments,
                inlineCalleeAnchorCandidateId = inlineCallee,
                inlineOwnerAnchorCandidateId = inlineOwner,
                inlineCallFile = callFile,
                inlineCallLine = callLine,
                inlineCallColumn = callColumn,
                inlinePathAnchorCandidateIds = inlinePath,
                authenticatedSourceRevision = sourceRevision,
            )
            result = fields
            budget.charge(
                OracleJson.canonicalBytes(fields.canonicalJson(), sourceIdentityRowJsonLimits(MAXIMUM_SOURCE_IDENTITY_ROW_BYTES)).size.toLong(),
                "source-anchor fields",
            )
            fields.candidateId(kind)?.let { anchorClaims.claim(kind, it, physical) }
            return fields
        } finally {
            val reasonTranscript = reasons.filterNot(originalReasons::contains)
            val transcriptBytes = try {
                Math.addExact(
                    Math.addExact(Math.multiplyExact(edgeCapture.size.toLong(), 24L), key.length.toLong() + 96L),
                    reasonTranscript.sumOf { it.toByteArray(StandardCharsets.UTF_8).size.toLong() + 8L },
                )
            } catch (failure: ArithmeticException) {
                throw FullTreeControlException("source-identity anchor transcript size overflows", failure)
            }
            budget.charge(transcriptBytes, "source-anchor evidence cache")
            anchorCache[key] = CachedAnchorEvidence(
                fields = result,
                edges = Collections.unmodifiableList(ArrayList(edgeCapture)),
                reasonCodes = Collections.unmodifiableList(ArrayList(reasonTranscript)),
            )
            anchorEdgeCaptures.removeLast()
            anchorStack.remove(key)
        }
    }

    /** Selects only an explicitly related specification/origin DIE when it supplies more source facts. */
    private fun sourceAnchorProvider(
        rootUnit: FunctionDwarfUnit,
        root: FullTreeDwarfDieRecord,
        edges: MutableList<FullTreeSourceIdentityEdge>,
        reasons: MutableSet<String>,
    ): SourceAnchorProvider {
        fun score(unit: FunctionDwarfUnit, record: FullTreeDwarfDieRecord): Int {
            val identityAttributes = listOf(DW_AT_NAME, DW_AT_DECL_FILE, DW_AT_DECL_LINE, DW_AT_DECL_COLUMN)
            var result = identityAttributes.count { record.attributesNamed(it).isNotEmpty() }
            if (record.attributesNamed(DW_AT_TYPE).isNotEmpty()) result++
            val children = unit.directChildren(record)
            if (children.any { it.tag in setOf(DW_TAG_FORMAL_PARAMETER, DW_TAG_UNSPECIFIED_PARAMETERS, DW_TAG_GNU_FORMAL_PARAMETER_PACK) }) result++
            if (children.any { it.tag in setOf(DW_TAG_TEMPLATE_TYPE_PARAMETER, DW_TAG_TEMPLATE_VALUE_PARAMETER, DW_TAG_GNU_TEMPLATE_PARAMETER_PACK) }) result++
            return result
        }

        val rootScore = score(rootUnit, root)
        val providers = LinkedHashMap<String, SourceAnchorProvider>()
        val pending = ArrayDeque<Triple<FunctionDwarfUnit, FullTreeDwarfDieRecord, Int>>()
        pending += Triple(rootUnit, root, 1)
        val visited = HashSet<String>()
        while (pending.isNotEmpty()) {
            val (unit, record, depth) = pending.removeFirst()
            val source = physical(unit, record)
            val sourceKey = source.locator()
            if (!visited.add(sourceKey)) continue
            providers[sourceKey] = SourceAnchorProvider(unit, record, score(unit, record), emptyList())
            for ((attributeName, edgeKind) in listOf(
                DW_AT_SPECIFICATION to FullTreeSourceIdentityEdgeKind.SPECIFICATION,
                DW_AT_ABSTRACT_ORIGIN to FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN,
            )) {
                val attribute = sourceReferenceAttribute(unit, record, attributeName, edgeKind, edges, reasons) ?: continue
                val target = referenceEdge(unit, record, attribute, edgeKind, source, edges) ?: continue
                if (target.second.tag != DW_TAG_SUBPROGRAM) {
                    reasons += "ambiguous-source-anchor-reference-kind"
                    continue
                }
                val targetPhysical = physical(target.first, target.second)
                if (targetPhysical.locator() in visited) continue
                if (depth >= producerLimits.maximumReferenceChainEntries) {
                    throw FullTreeControlException(
                        "source-identity source-anchor reference walk exceeds ${producerLimits.maximumReferenceChainEntries} DIE entries",
                    )
                }
                pending += Triple(target.first, target.second, depth + 1)
            }
        }
        val bestScore = providers.values.maxOfOrNull(SourceAnchorProvider::score) ?: rootScore
        val chain = providers.values.map { SourceAnchorRecord(it.unit, it.record, it.score) }
        if (bestScore <= rootScore) return providers.values.first { it.record === root }.copy(records = chain)
        val best = providers.values.filter { it.score == bestScore }
        if (best.size != 1) {
            reasons += "ambiguous-source-anchor-reference"
            return providers.values.first { it.record === root }.copy(records = chain)
        }
        return best.single().copy(records = chain)
    }

    private data class IntegralTypeShape(val signed: Boolean, val bits: Int, val boolean: Boolean = false)

    private fun typedIntegralDescriptor(
        value: FullTreeDwarfFormValue,
        typeUnit: FunctionDwarfUnit,
        typeRecord: FullTreeDwarfDieRecord,
        edges: MutableList<FullTreeSourceIdentityEdge>,
        reasons: MutableSet<String>,
    ): String? {
        val shape = integralTypeShape(typeUnit, typeRecord, edges, reasons, HashSet(), 0) ?: return null
        return if (shape.boolean) {
            sourceIdentityBooleanValueDescriptor(value)
        } else {
            sourceIdentityIntegralValueDescriptor(value, shape.signed, shape.bits)
        }
            .also { if (it == null) reasons += "unknown-template-argument-value" }
    }

    private fun integralTypeShape(
        unit: FunctionDwarfUnit,
        record: FullTreeDwarfDieRecord,
        edges: MutableList<FullTreeSourceIdentityEdge>,
        reasons: MutableSet<String>,
        visited: MutableSet<String>,
        depth: Int,
    ): IntegralTypeShape? {
        if (depth >= producerLimits.maximumReferenceChainEntries || !visited.add(physical(unit, record).locator())) {
            reasons += "unknown-template-argument-type"
            return null
        }
        if (record.tag == DW_TAG_BASE_TYPE) {
            val encoding = record.optionalNonNegativeLong(DW_AT_ENCODING, "DW_AT_encoding")
            val bytes = record.optionalNonNegativeLong(DW_AT_BYTE_SIZE, "DW_AT_byte_size")
            if (bytes == null || bytes !in 1L..8L) {
                reasons += "unknown-template-argument-type"
                return null
            }
            val signed = when (encoding) {
                DW_ATE_SIGNED, DW_ATE_SIGNED_CHAR -> true
                DW_ATE_UNSIGNED, DW_ATE_UNSIGNED_CHAR -> false
                DW_ATE_BOOLEAN -> {
                    if (bytes != 1L) {
                        reasons += "unknown-template-argument-type"
                        return null
                    }
                    return IntegralTypeShape(signed = false, bits = 8, boolean = true)
                }
                else -> {
                    reasons += "unsupported-template-argument-type-encoding"
                    return null
                }
            }
            return IntegralTypeShape(signed, (bytes * 8L).toInt())
        }
        if (record.tag == DW_TAG_ENUMERATION_TYPE) {
            val attribute = sourceReferenceAttribute(
                unit,
                record,
                DW_AT_TYPE,
                FullTreeSourceIdentityEdgeKind.TYPE,
                edges,
                reasons,
            ) ?: run {
                reasons += "unknown-template-argument-type"
                return null
            }
            val target = referenceEdge(
                unit,
                record,
                attribute,
                FullTreeSourceIdentityEdgeKind.TYPE,
                physical(unit, record),
                edges,
            ) ?: run {
                reasons += "unknown-template-argument-type"
                return null
            }
            return integralTypeShape(target.first, target.second, edges, reasons, visited, depth + 1)
        }
        if (record.tag !in setOf(DW_TAG_TYPEDEF, DW_TAG_CONST_TYPE, DW_TAG_VOLATILE_TYPE, DW_TAG_RESTRICT_TYPE)) {
            reasons += "unsupported-template-argument-type"
            return null
        }
        val attribute = sourceReferenceAttribute(unit, record, DW_AT_TYPE, FullTreeSourceIdentityEdgeKind.TYPE, edges, reasons)
            ?: run {
                reasons += "unknown-template-argument-type"
                return null
            }
        val target = referenceEdge(unit, record, attribute, FullTreeSourceIdentityEdgeKind.TYPE, physical(unit, record), edges)
            ?: run {
                reasons += "unknown-template-argument-type"
                return null
            }
        return integralTypeShape(target.first, target.second, edges, reasons, visited, depth + 1)
    }

    private fun signature(
        sources: List<SourceAnchorRecord>,
        edges: MutableList<FullTreeSourceIdentityEdge>,
        reasons: MutableSet<String>,
    ): List<String>? {
        val returnTypeDescriptors = linkedSetOf<String>()
        var returnTypeUnknown = false
        sources.forEach { source ->
            if (source.record.attributesNamed(DW_AT_TYPE).isEmpty()) return@forEach
            val returnType = sourceReferenceAttribute(
                source.unit, source.record, DW_AT_TYPE, FullTreeSourceIdentityEdgeKind.TYPE, edges, reasons,
            )
            if (returnType == null) {
                returnTypeUnknown = true
                return@forEach
            }
            val value = typeDescriptor(source.unit, source.record, returnType, edges, FullTreeSourceIdentityEdgeKind.TYPE, reasons)
            if (value == null) returnTypeUnknown = true else returnTypeDescriptors += value
        }
        val returnType = mergeValidatedSourceAnchorBranches(
            returnTypeDescriptors.map { SourceAnchorBranchValue(score = 0, value = it) },
        )
        if (returnType.ambiguous) {
            reasons += "ambiguous-inherited-return-type"
            return null
        }
        if (returnTypeUnknown) {
            reasons += "unknown-return-type"
            return null
        }
        val returnDescriptor = returnType.value?.let {
            chargeRowScratchText("function signature return descriptor", "return:", it)
            "return:$it"
        } ?: "return:void"
        if (returnType.value == null) chargeRowScratch(sourceIdentityUtf8ByteLength(returnDescriptor), "function signature return descriptor")
        val result = arrayListOf(returnDescriptor)
        val parameterSets = arrayListOf<List<String>>()
        var parameterSetUnknown = false
        sources.forEach { source ->
            val parameterChildren = packedSubprogramChildren(
                source.unit,
                source.record,
                setOf(DW_TAG_FORMAL_PARAMETER, DW_TAG_UNSPECIFIED_PARAMETERS),
                FullTreeSourceIdentityEdgeKind.TYPE,
                edges,
            )
            if (parameterChildren.isEmpty()) return@forEach
            if (parameterChildren.size > MAXIMUM_DWARF_PARAMETERS) {
                throw FullTreeControlException("source-identity function parameters exceed their 1,024-entry bound")
            }
            val values = arrayListOf<String>()
            parameterChildren.forEach { packedParameter ->
                val parameter = packedParameter.record
                if (parameter.tag == DW_TAG_UNSPECIFIED_PARAMETERS) {
                    values += "varargs"
                } else {
                    val type = sourceReferenceAttribute(
                        source.unit, parameter, DW_AT_TYPE, FullTreeSourceIdentityEdgeKind.TYPE, edges, reasons,
                    )
                    if (type == null) {
                        reasons += "unknown-parameter-type"
                        parameterSetUnknown = true
                    } else {
                        val descriptor = typeDescriptor(
                            source.unit, parameter, type, edges, FullTreeSourceIdentityEdgeKind.TYPE, reasons,
                        )
                        if (descriptor == null) {
                            parameterSetUnknown = true
                        } else {
                            chargeRowScratchText("function signature parameter descriptor", "parameter:", descriptor)
                            values += "parameter:$descriptor"
                        }
                    }
                }
            }
            if (!parameterSetUnknown) parameterSets += values
        }
        if (parameterSetUnknown) return null
        val parameters = mergeValidatedSourceAnchorBranches(
            parameterSets.map { SourceAnchorBranchValue(score = 0, value = it) },
        )
        if (parameters.ambiguous) {
            reasons += "ambiguous-inherited-parameter-set"
            return null
        }
        result += parameters.value.orEmpty()
        return result
    }

    private fun <T> uniqueInheritedSourceValue(
        sources: List<SourceAnchorRecord>,
        label: String,
        reasons: MutableSet<String>,
        read: (SourceAnchorRecord) -> T?,
    ): T? {
        val resolution = mergeValidatedSourceAnchorBranches(
            sources.map { source -> SourceAnchorBranchValue(source.score, read(source)) },
        )
        if (resolution.ambiguous) {
            reasons += "ambiguous-inherited-$label"
            return null
        }
        return resolution.value
    }

    private fun typeDescriptor(
        unit: FunctionDwarfUnit,
        sourceRecord: FullTreeDwarfDieRecord,
        attribute: FullTreeDwarfDieAttribute,
        edges: MutableList<FullTreeSourceIdentityEdge>,
        edgeKind: FullTreeSourceIdentityEdgeKind,
        reasons: MutableSet<String>,
    ): String? {
        val target = referenceEdge(unit, sourceRecord, attribute, edgeKind, physical(unit, sourceRecord), edges) ?: return null
        return describeType(target.first, target.second, HashSet(), 0, reasons, edges)
    }

    private fun templateState(
        unit: FunctionDwarfUnit,
        formals: List<FullTreeDwarfDieRecord>,
        edges: MutableList<FullTreeSourceIdentityEdge>,
        reasons: MutableSet<String>,
    ): TemplateParameterState {
        if (formals.isEmpty()) return TemplateParameterState.NONE
        var concrete = false
        var unknown = false
        formals.forEach { formal ->
            val parameterState = when (formal.tag) {
                DW_TAG_TEMPLATE_TYPE_PARAMETER -> {
                    val typeAttributes = formal.attributesNamed(DW_AT_TYPE)
                    val type = sourceReferenceAttribute(
                        unit, formal, DW_AT_TYPE,
                        FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT, edges, reasons,
                    )
                    if (typeAttributes.isEmpty()) {
                        TemplateParameterState.PATTERN
                    } else if (type == null) {
                        TemplateParameterState.UNKNOWN
                    } else {
                        val target = referenceEdge(
                            unit,
                            formal,
                            type,
                            FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT,
                            physical(unit, formal),
                            edges,
                        )
                        when {
                            target == null -> TemplateParameterState.UNKNOWN
                            target.second.tag == DW_TAG_TEMPLATE_TYPE_PARAMETER -> TemplateParameterState.PATTERN
                            else -> TemplateParameterState.INSTANCE
                        }
                    }
                }
                DW_TAG_TEMPLATE_VALUE_PARAMETER -> {
                    val constValues = formal.attributesNamed(DW_AT_CONST_VALUE)
                    if (constValues.size > 1) {
                        reasons += "ambiguous-template-argument-value"
                        TemplateParameterState.UNKNOWN
                    } else if (constValues.isNotEmpty()) {
                        TemplateParameterState.INSTANCE
                    } else {
                        val declaredType = sourceReferenceAttribute(
                            unit, formal, DW_AT_TYPE,
                            FullTreeSourceIdentityEdgeKind.TEMPLATE_FORMAL, edges, reasons,
                        )
                        val target = declaredType?.let {
                            referenceEdge(
                                unit,
                                formal,
                                it,
                                FullTreeSourceIdentityEdgeKind.TEMPLATE_FORMAL,
                                physical(unit, formal),
                                edges,
                            )
                        }
                        if (target == null) TemplateParameterState.UNKNOWN else TemplateParameterState.PATTERN
                    }
                }
                else -> TemplateParameterState.UNKNOWN
            }
            when (parameterState) {
                TemplateParameterState.INSTANCE -> concrete = true
                TemplateParameterState.UNKNOWN -> {
                    unknown = true
                    reasons += "unknown-template-parameter-shape"
                }
                TemplateParameterState.NONE, TemplateParameterState.PATTERN -> Unit
            }
        }
        return when {
            concrete -> TemplateParameterState.INSTANCE
            unknown -> TemplateParameterState.UNKNOWN
            else -> TemplateParameterState.PATTERN
        }
    }

    private fun relatedSubprogramKind(
        unit: FunctionDwarfUnit,
        record: FullTreeDwarfDieRecord,
        edges: MutableList<FullTreeSourceIdentityEdge>,
        reasons: MutableSet<String>,
        functionStartResolution: FullTreeSourceIdentityFunctionStartResolution =
            FullTreeSourceIdentityFunctionStartResolution { unit.functionStart(record) },
    ): FullTreeSourceAnchorKind? {
        if (record.tag != DW_TAG_SUBPROGRAM) return null
        val formals = packedSubprogramChildren(
            unit,
            record,
            setOf(DW_TAG_TEMPLATE_TYPE_PARAMETER, DW_TAG_TEMPLATE_VALUE_PARAMETER),
            FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT,
            edges,
        ).map(PackedSubprogramChild::record)
        return when (templateState(unit, formals, edges, reasons)) {
            TemplateParameterState.INSTANCE -> FullTreeSourceAnchorKind.TEMPLATE_INSTANCE
            TemplateParameterState.PATTERN -> FullTreeSourceAnchorKind.TEMPLATE_PATTERN
            TemplateParameterState.UNKNOWN -> null
            TemplateParameterState.NONE -> when {
                record.truthy(DW_AT_DECLARATION, "DW_AT_declaration") -> FullTreeSourceAnchorKind.DECLARATION_ONLY
                functionStartResolution.get() == null -> FullTreeSourceAnchorKind.NO_RANGE_DEFINITION
                else -> FullTreeSourceAnchorKind.SOURCE_DEFINITION
            }
        }
    }

    private fun describeType(
        unit: FunctionDwarfUnit,
        record: FullTreeDwarfDieRecord,
        seen: MutableSet<String>,
        depth: Int,
        reasons: MutableSet<String>,
        edges: MutableList<FullTreeSourceIdentityEdge>,
    ): String? {
        val physical = physical(unit, record)
        val locator = physical.locator()
        if (!seen.add(locator)) {
            reasons += "ambiguous-type-cycle"
            return null
        }
        if (depth >= producerLimits.maximumReferenceChainEntries) {
            reasons += "unknown-type-depth"
            return null
        }
        val name = record.optionalUniqueAttribute(DW_AT_NAME, "DW_AT_name")?.let {
            FullTreeDwarfForms.decodeString(it.value, unit.sections, unit.stringOffsetsBase, unit.header.offsetSize, controlLimits, "DWARF type name", 16_384)
        }
        fun nested(label: String): String? {
            val attr = sourceReferenceAttribute(
                unit, record, DW_AT_TYPE, FullTreeSourceIdentityEdgeKind.TYPE, edges, reasons,
            ) ?: return null
            val ref = referenceEdge(unit, record, attr, FullTreeSourceIdentityEdgeKind.TYPE, physical, edges) ?: return null
            val nestedDescriptor = describeType(ref.first, ref.second, HashSet(seen), depth + 1, reasons, edges)
                ?: return null
            chargeRowScratch(
                sourceIdentityUtf8ByteLength(label) + sourceIdentityUtf8ByteLength(nestedDescriptor) + 2L,
                "nested type descriptor",
            )
            return "$label<$nestedDescriptor>"
        }
        return when (record.tag) {
            DW_TAG_BASE_TYPE -> {
                val encoding = record.optionalNonNegativeLong(DW_AT_ENCODING, "DW_AT_encoding") ?: return null
                val bytes = record.optionalNonNegativeLong(DW_AT_BYTE_SIZE, "DW_AT_byte_size") ?: return null
                name?.let {
                    val canonical = canonicalSourceIdentityBuiltinName(it)
                    val descriptorBytes = sourceIdentityUtf8ByteLength("base:") +
                        sourceIdentityUtf8ByteLength(canonical) +
                        sourceIdentityUtf8ByteLength(":encoding=$encoding:bytes=$bytes")
                    chargeRowScratch(descriptorBytes, "base type descriptor")
                    "base:$canonical:encoding=$encoding:bytes=$bytes"
                }
            }
            DW_TAG_POINTER_TYPE -> if (record.attributesNamed(DW_AT_TYPE).isEmpty()) "pointer<void>" else nested("pointer")
            DW_TAG_LVALUE_REFERENCE_TYPE -> nested("lvalue-reference")
            DW_TAG_RVALUE_REFERENCE_TYPE -> nested("rvalue-reference")
            DW_TAG_CONST_TYPE -> nested("const")
            DW_TAG_VOLATILE_TYPE -> nested("volatile")
            DW_TAG_RESTRICT_TYPE -> nested("restrict")
            DW_TAG_TYPEDEF -> name?.let { typedef -> nested("typedef:$typedef") }
            DW_TAG_SUBROUTINE_TYPE -> {
                val parts = arrayListOf<String>()
                fun appendPart(part: String) {
                    chargeRowScratch(sourceIdentityUtf8ByteLength(part), "subroutine type component")
                    budget.charge(
                        part.toByteArray(StandardCharsets.UTF_8).size.toLong() + 8L,
                        "subroutine type component",
                    )
                    parts += part
                }
                fun appendPart(prefix: String, value: String) {
                    chargeRowScratchText("subroutine type component", prefix, value)
                    val part = prefix + value
                    budget.charge(
                        sourceIdentityUtf8ByteLength(part) + 8L,
                        "subroutine type component",
                    )
                    parts += part
                }
                if (record.attributesNamed(DW_AT_TYPE).isEmpty()) {
                    appendPart("return:void")
                } else {
                    val returnAttribute = sourceReferenceAttribute(
                        unit, record, DW_AT_TYPE, FullTreeSourceIdentityEdgeKind.TYPE, edges, reasons,
                    ) ?: return null
                    val returnTarget = referenceEdge(
                        unit, record, returnAttribute, FullTreeSourceIdentityEdgeKind.TYPE, physical, edges,
                    ) ?: return null
                    val returnType = describeType(
                        returnTarget.first, returnTarget.second, HashSet(seen), depth + 1, reasons, edges,
                    ) ?: return null
                    appendPart("return:", returnType)
                }
                val parameters = packedSubprogramChildren(
                    unit,
                    record,
                    setOf(DW_TAG_FORMAL_PARAMETER, DW_TAG_UNSPECIFIED_PARAMETERS),
                    FullTreeSourceIdentityEdgeKind.TYPE,
                    edges,
                )
                if (parameters.size > MAXIMUM_DWARF_PARAMETERS) {
                    throw FullTreeControlException("source-identity callback parameters exceed their 1,024-entry bound")
                }
                parameters.forEach { packedParameter ->
                    val parameter = packedParameter.record
                    if (parameter.tag == DW_TAG_UNSPECIFIED_PARAMETERS) {
                        appendPart("varargs")
                    } else {
                        val attribute = sourceReferenceAttribute(
                            unit, parameter, DW_AT_TYPE, FullTreeSourceIdentityEdgeKind.TYPE, edges, reasons,
                        ) ?: run {
                            reasons += "unknown-callback-parameter-type"
                            return null
                        }
                        val target = referenceEdge(
                            unit, parameter, attribute, FullTreeSourceIdentityEdgeKind.TYPE, physical(unit, parameter), edges,
                        ) ?: return null
                        val descriptor = describeType(
                            target.first, target.second, HashSet(seen), depth + 1, reasons, edges,
                        ) ?: return null
                        appendPart("parameter:", descriptor)
                    }
                }
                var descriptorBytes = sourceIdentityUtf8ByteLength("subroutine[") + 1L
                parts.forEach { part ->
                    val partBytes = sourceIdentityUtf8ByteLength(part)
                    descriptorBytes = Math.addExact(
                        descriptorBytes,
                        sourceIdentityUtf8ByteLength(partBytes.toString()) + 1L + partBytes,
                    )
                }
                chargeRowScratch(descriptorBytes, "subroutine type descriptor")
                val descriptor = "subroutine[" + parts.joinToString(separator = "") { part ->
                    "${part.toByteArray(StandardCharsets.UTF_8).size}:$part"
                } + "]"
                chargeRowScratch(sourceIdentityUtf8ByteLength(descriptor), "subroutine type descriptor")
                budget.charge(descriptor.toByteArray(StandardCharsets.UTF_8).size.toLong(), "subroutine type descriptor")
                descriptor
            }
            DW_TAG_CLASS_TYPE, DW_TAG_STRUCTURE_TYPE, DW_TAG_UNION_TYPE, DW_TAG_ENUMERATION_TYPE -> {
                val tag = when (record.tag) {
                    DW_TAG_CLASS_TYPE -> "class"
                    DW_TAG_STRUCTURE_TYPE -> "struct"
                    DW_TAG_UNION_TYPE -> "union"
                    else -> "enum"
                }
                val sourcePath = typeDeclPath(unit, record)
                val declarationLine = record.optionalNonNegativeLong(DW_AT_DECL_LINE, "DW_AT_decl_line")?.takeIf { it > 0L }
                if (name == null || sourcePath == null || declarationLine == null) {
                    reasons += "unknown-named-type-declaration-identity"
                    null
                } else {
                    val scope = lexicalContext(unit, record)
                    var encodedScopeBytes = 0L
                    scope.forEach { component ->
                        encodedScopeBytes = Math.addExact(
                            encodedScopeBytes,
                            sourceIdentityUtf8ByteLength(component.length.toString()) + 1L +
                                sourceIdentityUtf8ByteLength(component),
                        )
                    }
                    chargeRowScratch(encodedScopeBytes, "named type lexical-scope encoding")
                    val encodedScope = scope.joinToString(separator = "") { component -> "${component.length}:$component" }
                    val descriptorBytes = sourceIdentityUtf8ByteLength(tag + ":") +
                        sourceIdentityUtf8ByteLength(name.length.toString()) + 1L +
                        sourceIdentityUtf8ByteLength(name) + 1L +
                        sourceIdentityUtf8ByteLength(sourcePath.length.toString()) + 1L +
                        sourceIdentityUtf8ByteLength(sourcePath) + 1L +
                        sourceIdentityUtf8ByteLength(declarationLine.toString()) +
                        sourceIdentityUtf8ByteLength(":scope[") +
                        sourceIdentityUtf8ByteLength(scope.size.toString()) + 1L +
                        sourceIdentityUtf8ByteLength(encodedScope) + 1L
                    chargeRowScratch(descriptorBytes, "named type descriptor")
                    "$tag:${name.length}:$name:${sourcePath.length}:$sourcePath:$declarationLine:scope[${scope.size}:$encodedScope]"
                }
            }
            DW_TAG_UNSPECIFIED_TYPE -> "void"
            DW_TAG_TEMPLATE_TYPE_PARAMETER -> name?.let { "template-type-parameter:$it" }
            else -> {
                reasons += "unsupported-type-shape"
                null
            }
        }
    }

    private fun referenceEdge(
        unit: FunctionDwarfUnit,
        record: FullTreeDwarfDieRecord,
        attribute: FullTreeDwarfDieAttribute,
        kind: FullTreeSourceIdentityEdgeKind,
        source: FullTreeSourcePhysicalDie,
        edges: MutableList<FullTreeSourceIdentityEdge>,
    ): Pair<FunctionDwarfUnit, FullTreeDwarfDieRecord>? {
        val reference = attribute.value as? FullTreeDwarfReferenceValue
        if (reference == null) {
            val unsupportedForm = (attribute.value as? FullTreeDwarfUnsignedFormValue)?.resolvedForm ?: attribute.declaredForm
            val state = if (attribute.value is FullTreeDwarfUnsupportedReferenceValue) {
                FullTreeSourceIdentityEdgeState.UNSUPPORTED
            } else {
                FullTreeSourceIdentityEdgeState.MALFORMED
            }
            val raw = (attribute.value as? FullTreeDwarfUnsignedFormValue)?.rawValue
            val edge = FullTreeSourceIdentityEdge(
                kind, source, null, canonicalHex(unsupportedForm), raw?.let(::canonicalUnsignedHex), state,
                if (state == FullTreeSourceIdentityEdgeState.UNSUPPORTED) "unsupported-reference-form" else "malformed-reference-value",
            )
            retainEdge(edges, edge)
            return null
        }
        val raw = canonicalUnsignedHex(reference.rawValue)
        val previous = edges.lastOrNull {
            it.kind == kind && it.source == source && it.rawReference == raw && it.referenceForm == canonicalHex(reference.resolvedForm)
        }
        if (previous != null && previous.state != FullTreeSourceIdentityEdgeState.RESOLVED) return null
        val targetOffset = try {
            unit.header.resolveReference(info, reference)
        } catch (_: FullTreeControlException) {
            val edge = FullTreeSourceIdentityEdge(
                kind, source, null, canonicalHex(reference.resolvedForm), raw,
                FullTreeSourceIdentityEdgeState.MALFORMED, "reference-outside-validated-dwarf-boundary",
            )
            retainEdge(edges, edge)
            return null
        }
        val targetHeader = try {
            findHeader(targetOffset)
        } catch (_: FullTreeControlException) {
            val edge = FullTreeSourceIdentityEdge(
                kind, source, null, canonicalHex(reference.resolvedForm), raw,
                FullTreeSourceIdentityEdgeState.MALFORMED, "reference-not-in-a-compilation-unit",
            )
            retainEdge(edges, edge)
            return null
        }
        val targetUnitAndRecord = try {
            val targetUnit = if (targetHeader.offset == unit.header.offset) unit else repository.load(targetHeader)
            targetUnit to sourceIdentityTargetDie(
                targetUnit.index,
                targetOffset,
                "source identity ${dwarfAttributeLabel(attribute.name)} target",
            )
        } catch (failure: FullTreeControlException) {
            if (failure.message?.contains("does not identify a retained non-null DIE boundary") != true) throw failure
            val edge = FullTreeSourceIdentityEdge(
                kind, source, null, canonicalHex(reference.resolvedForm), raw,
                FullTreeSourceIdentityEdgeState.MISSING_TARGET, "target-not-retained-or-not-a-die-boundary",
            )
            retainEdge(edges, edge)
            return null
        }
        val edge = FullTreeSourceIdentityEdge(
            kind,
            source,
            physical(targetUnitAndRecord.first, targetUnitAndRecord.second),
            canonicalHex(reference.resolvedForm),
            raw,
            FullTreeSourceIdentityEdgeState.RESOLVED,
            null,
        )
        retainEdge(edges, edge)
        return targetUnitAndRecord
    }

    private fun retainEdge(edges: MutableList<FullTreeSourceIdentityEdge>, edge: FullTreeSourceIdentityEdge) {
        anchorEdgeCaptures.forEach { capture ->
            if (edge !in capture) capture += edge
        }
        if (edge in edges) return
        if (edges.size >= MAXIMUM_IDENTITY_EDGES_PER_ENTITY) {
            throw FullTreeControlException("source identity has more than 32 edges")
        }
        budget.charge(OracleJson.canonicalBytes(edge.canonicalJson()).size.toLong(), "source-identity edge")
        edges += edge
    }

    /** Duplicate typed references are retained as conflicting evidence instead of a last-wins guess. */
    private fun sourceReferenceAttribute(
        unit: FunctionDwarfUnit,
        record: FullTreeDwarfDieRecord,
        attributeName: Long,
        edgeKind: FullTreeSourceIdentityEdgeKind,
        edges: MutableList<FullTreeSourceIdentityEdge>,
        reasons: MutableSet<String>,
    ): FullTreeDwarfDieAttribute? {
        val attributes = record.attributesNamed(attributeName)
        if (attributes.size <= 1) return attributes.singleOrNull()
        reasons += "ambiguous-conflicting-reference"
        val source = physical(unit, record)
        attributes.forEach { attribute ->
            val reference = attribute.value as? FullTreeDwarfReferenceValue
            val unsigned = attribute.value as? FullTreeDwarfUnsignedFormValue
            val form = reference?.resolvedForm ?: unsigned?.resolvedForm ?: attribute.declaredForm
            val raw = reference?.rawValue?.let(::canonicalUnsignedHex)
                ?: unsigned?.rawValue?.let(::canonicalUnsignedHex)
            retainEdge(
                edges,
                FullTreeSourceIdentityEdge(
                    kind = edgeKind,
                    source = source,
                    target = null,
                    referenceForm = canonicalHex(form),
                    rawReference = raw,
                    state = FullTreeSourceIdentityEdgeState.MALFORMED,
                    reasonCode = "conflicting-duplicate-reference-attribute",
                ),
            )
        }
        return null
    }

    /** Walk raw origin/specification branches; the 32-DIE ceiling counts the source DIE. */
    private fun collectReferenceGraph(
        rootUnit: FunctionDwarfUnit,
        root: FullTreeDwarfDieRecord,
        rootPhysical: FullTreeSourcePhysicalDie,
        edges: MutableList<FullTreeSourceIdentityEdge>,
        reasons: MutableSet<String>,
    ) {
        val states = HashMap<String, Int>() // 1 = active DFS path, 2 = fully visited
        fun visit(unit: FunctionDwarfUnit, record: FullTreeDwarfDieRecord, depth: Int) {
            val source = physical(unit, record)
            val sourceKey = source.locator()
            states[sourceKey] = 1
            val relations = listOf(
                DW_AT_ABSTRACT_ORIGIN to FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN,
                DW_AT_SPECIFICATION to FullTreeSourceIdentityEdgeKind.SPECIFICATION,
            )
            for ((attributeName, edgeKind) in relations) {
                val attribute = sourceReferenceAttribute(
                    unit, record, attributeName, edgeKind, edges, reasons,
                ) ?: continue
                val target = referenceEdge(unit, record, attribute, edgeKind, source, edges) ?: continue
                val targetPhysical = physical(target.first, target.second)
                val targetKey = targetPhysical.locator()
                if (depth >= producerLimits.maximumReferenceChainEntries) {
                    throw FullTreeControlException(
                        "source-identity origin/specification walk exceeds ${producerLimits.maximumReferenceChainEntries} DIE entries",
                    )
                }
                if (states[targetKey] == 1) {
                    val matchingIndex = edges.indexOfLast {
                        it.kind == edgeKind && it.source == source && it.target == targetPhysical &&
                            it.state == FullTreeSourceIdentityEdgeState.RESOLVED
                    }
                    if (matchingIndex >= 0) {
                        val prior = edges.removeAt(matchingIndex)
                        val cyclic = prior.copy(
                            target = null,
                            state = FullTreeSourceIdentityEdgeState.CYCLIC,
                            reasonCode = "reference-cycle",
                        )
                        anchorEdgeCaptures.forEach { capture -> capture.remove(prior) }
                        anchorCache.replaceAll { _, cached ->
                            if (prior in cached.edges) {
                                budget.charge(cached.edges.size.toLong() * 8L + 64L, "source-anchor cycle cache update")
                                cached.copy(
                                    edges = Collections.unmodifiableList(cached.edges.map { if (it == prior) cyclic else it }),
                                )
                            } else cached
                        }
                        retainEdge(edges, cyclic)
                    }
                    reasons += "ambiguous-reference-cycle"
                    continue
                }
                if (states[targetKey] != 2) {
                    visit(target.first, target.second, depth + 1)
                }
            }
            states[sourceKey] = 2
        }
        visit(rootUnit, root, 1)
    }

    private fun addStructuralEdge(
        source: FullTreeSourcePhysicalDie,
        target: FullTreeSourcePhysicalDie,
        kind: FullTreeSourceIdentityEdgeKind,
        edges: MutableList<FullTreeSourceIdentityEdge>,
    ) {
        retainEdge(edges, FullTreeSourceIdentityEdge(kind, source, target, null, null, FullTreeSourceIdentityEdgeState.RESOLVED, null))
    }

    private fun emittedLink(
        unit: FunctionDwarfUnit,
        record: FullTreeDwarfDieRecord,
    ): Pair<FullTreeDenominatorDisposition, String?> {
        val start = unit.functionStart(record)
            ?: return FullTreeDenominatorDisposition.NON_SCOREABLE to null
        if (start < layout.imageBase) return FullTreeDenominatorDisposition.UNKNOWN to null
        val rva = start - layout.imageBase
        if (!executable.contains(rva)) return FullTreeDenominatorDisposition.UNKNOWN to null
        return FullTreeDenominatorDisposition.EMITTED_RVA_LINK to canonicalUnsignedHex(rva)
    }

    private fun declarationPath(unit: FunctionDwarfUnit, record: FullTreeDwarfDieRecord, attribute: Long, label: String): String? {
        val file = record.optionalNonNegativeLong(attribute, label) ?: return null
        return resolvePath(unit, file)
    }

    private fun resolvePath(unit: FunctionDwarfUnit, fileIndex: Long): String? {
        val raw = unit.lineTable(producerLimits.lineTableLimits)?.resolveDeclarationPath(
            fileIndex,
            unit.header.version,
        ) { unit.compilationDirectory() } ?: return null
        // Prefix-map sources are authenticated by the scope and may be relative. Let the same
        // normalizer validate both forms; it rejects traversal and non-canonical results.
        return runCatching { FullTreeScopeControl.normalizeSourcePath(scope, raw) }.getOrNull()
    }

    private fun lexicalContext(unit: FunctionDwarfUnit, record: FullTreeDwarfDieRecord): List<String> {
        val chain = ArrayDeque<String>()
        var parent = record.nearestRetainedParentOffset
        var seen = 0
        while (parent != null) {
            if (seen++ >= MAXIMUM_SOURCE_IDENTITY_CONTEXT_DEPTH) {
                throw FullTreeControlException("source-identity lexical context exceeds its depth bound")
            }
            val current = unit.index.find(parent) ?: break
            if (current.tag in setOf(DW_TAG_NAMESPACE, DW_TAG_CLASS_TYPE, DW_TAG_STRUCTURE_TYPE, DW_TAG_UNION_TYPE)) {
                val name = current.optionalUniqueAttribute(DW_AT_NAME, "DW_AT_name")?.let {
                    FullTreeDwarfForms.decodeString(it.value, unit.sections, unit.stringOffsetsBase, unit.header.offsetSize, controlLimits, "lexical context name", 16_384)
                }
                if (name != null) {
                    val tag = current.tag.toString(16)
                    val componentBytes = sourceIdentityUtf8ByteLength(tag) + 1L + sourceIdentityUtf8ByteLength(name)
                    chargeRowScratch(componentBytes, "lexical-context component")
                    chain.addFirst("$tag:$name")
                }
            }
            parent = current.nearestRetainedParentOffset
        }
        return chain.toList()
    }

    private fun nearestContainingSubprogram(unit: FunctionDwarfUnit, parent: FullTreeDwarfDieRecord): FullTreeDwarfDieRecord? {
        var current: FullTreeDwarfDieRecord? = parent
        var depth = 0
        while (current != null && depth++ < MAXIMUM_SOURCE_IDENTITY_CONTEXT_DEPTH) {
            if (current.tag == DW_TAG_SUBPROGRAM) return current
            current = current.nearestRetainedParentOffset?.let(unit.index::find)
        }
        return null
    }

    private fun enclosingInlinePath(
        unit: FunctionDwarfUnit,
        record: FullTreeDwarfDieRecord,
        reasons: MutableSet<String>,
        edges: MutableList<FullTreeSourceIdentityEdge>,
    ): List<String>? {
        val result = ArrayList<String>()
        var parent = record.nearestRetainedParentOffset?.let(unit.index::find)
        var traversalDepth = 0
        var inlineDepth = 1 // include this inline instance in the bounded ancestry
        var child = record
        while (parent != null) {
            if (traversalDepth++ >= MAXIMUM_SOURCE_IDENTITY_CONTEXT_DEPTH) {
                throw FullTreeControlException("source-identity inline ancestry traversal exceeds its depth bound")
            }
            if (parent.tag == DW_TAG_INLINED_SUBROUTINE) {
                addStructuralEdge(
                    physical(unit, child),
                    physical(unit, parent),
                    FullTreeSourceIdentityEdgeKind.INLINE_OWNER,
                    edges,
                )
                child = parent
                inlineDepth++
                if (inlineDepth > producerLimits.maximumReferenceChainEntries) {
                    throw FullTreeControlException(
                        "source-identity inline ancestry exceeds ${producerLimits.maximumReferenceChainEntries} DIE entries",
                    )
                }
                val anchor = anchorFields(
                    unit,
                    parent,
                    FullTreeSourceAnchorKind.INLINE_INSTANCE,
                    edges,
                    reasons,
                    physical(unit, parent),
                )?.candidateId(FullTreeSourceAnchorKind.INLINE_INSTANCE)
                if (anchor == null) return null
                result.add(0, anchor)
            }
            parent = parent.nearestRetainedParentOffset?.let(unit.index::find)
        }
        return result
    }

    private fun typeDeclPath(unit: FunctionDwarfUnit, record: FullTreeDwarfDieRecord): String? =
        declarationPath(unit, record, DW_AT_DECL_FILE, "DW_AT_decl_file")

    private fun unitForRecord(record: FullTreeDwarfDieRecord): FunctionDwarfUnit {
        val header = findHeader(record.offset)
        return if (header.offset == owner.header.offset) owner else repository.load(header)
    }

    private fun findHeader(offset: Long): FullTreeDwarfCompilationUnitHeader {
        return sourceIdentityCompilationUnitAt(offset, allHeaders)
    }

    private fun physical(unit: FunctionDwarfUnit, record: FullTreeDwarfDieRecord): FullTreeSourcePhysicalDie {
        val inventory = unitByOffset[unit.header.offset]
            ?: throw FullTreeControlException("source-identity target has no inventory unit")
        budget.charge(inventory.controlString("id").toByteArray(StandardCharsets.UTF_8).size.toLong() + 96L, "source-identity physical locator")
        return FullTreeSourcePhysicalDie(
            richArtifactSha256 = richArtifactSha256,
            unitId = inventory.controlString("id"),
            section = ".debug_info",
            compilationUnitOffset = canonicalHex(unit.header.offset),
            dieOffset = canonicalHex(record.offset),
        )
    }

    private fun chargeRowScratch(bytes: Long, label: String) {
        val scratch = activeRowScratchBudget
            ?: throw FullTreeControlException("source-identity $label has no active row-scratch admission")
        scratch.charge(bytes, label)
    }

    private fun chargeRowScratchText(label: String, vararg fragments: String) {
        var bytes = 0L
        fragments.forEach { fragment ->
            bytes = try {
                Math.addExact(bytes, sourceIdentityUtf8ByteLength(fragment))
            } catch (failure: ArithmeticException) {
                throw FullTreeControlException("source-identity $label text size overflows", failure)
            }
        }
        chargeRowScratch(bytes, label)
    }
}

/** Counts encoded UTF-8 bytes without materializing a byte array for an untrusted descriptor. */
private fun sourceIdentityUtf8ByteLength(value: String): Long {
    var bytes = 0L
    var index = 0
    while (index < value.length) {
        val current = value[index]
        val byteCount = when {
            Character.isHighSurrogate(current) && index + 1 < value.length &&
                Character.isLowSurrogate(value[index + 1]) -> {
                index++
                4L
            }
            current.code <= 0x7f -> 1L
            current.code <= 0x7ff -> 2L
            else -> 3L
        }
        bytes = try {
            Math.addExact(bytes, byteCount)
        } catch (failure: ArithmeticException) {
            throw FullTreeControlException("source-identity descriptor byte length overflows", failure)
        }
        index++
    }
    return bytes
}

private fun sourceIdentityRetainedTags(): Set<Long> = setOf(
    DW_TAG_SUBPROGRAM,
    DW_TAG_INLINED_SUBROUTINE,
    DW_TAG_FORMAL_PARAMETER,
    DW_TAG_UNSPECIFIED_PARAMETERS,
    DW_TAG_GNU_TEMPLATE_PARAMETER_PACK,
    DW_TAG_GNU_FORMAL_PARAMETER_PACK,
    DW_TAG_TEMPLATE_TYPE_PARAMETER,
    DW_TAG_TEMPLATE_VALUE_PARAMETER,
    DW_TAG_NAMESPACE,
    DW_TAG_CLASS_TYPE,
    DW_TAG_STRUCTURE_TYPE,
    DW_TAG_UNION_TYPE,
    DW_TAG_ENUMERATION_TYPE,
    DW_TAG_BASE_TYPE,
    DW_TAG_POINTER_TYPE,
    DW_TAG_LVALUE_REFERENCE_TYPE,
    DW_TAG_RVALUE_REFERENCE_TYPE,
    DW_TAG_CONST_TYPE,
    DW_TAG_VOLATILE_TYPE,
    DW_TAG_RESTRICT_TYPE,
    DW_TAG_TYPEDEF,
    DW_TAG_UNSPECIFIED_TYPE,
    DW_TAG_ARRAY_TYPE,
    DW_TAG_SUBROUTINE_TYPE,
    DW_TAG_STRING_TYPE,
    DW_TAG_SET_TYPE,
    DW_TAG_PACKED_TYPE,
    DW_TAG_PTR_TO_MEMBER_TYPE,
    DW_TAG_ATOMIC_TYPE,
)

private val SOURCE_ENTITY_TAGS = setOf(DW_TAG_SUBPROGRAM, DW_TAG_INLINED_SUBROUTINE)

private enum class TemplateParameterState { NONE, PATTERN, INSTANCE, UNKNOWN }

private fun sourceIdentityAttributeContext(attribute: FullTreeDwarfAbbreviationAttribute): FullTreeDwarfFormContext =
    when (attribute.name) {
        DW_AT_ENCODING, DW_AT_BYTE_SIZE, DW_AT_TYPE, DW_AT_CALL_FILE, DW_AT_CALL_LINE, DW_AT_CALL_COLUMN,
        DW_AT_DECL_FILE, DW_AT_DECL_LINE, DW_AT_DECL_COLUMN, DW_AT_DECLARATION, DW_AT_INLINE, DW_AT_CONST_VALUE,
        -> FullTreeDwarfFormContext.CONSTANT
        DW_AT_RANGES -> FullTreeDwarfFormContext.RANGE_LIST
        else -> functionAttributeContext(attribute)
    }

private fun canonicalUnsignedHex(value: ULong): String = "0x" + value.toString(16)

private fun dwarfAttributeLabel(name: Long): String = when (name) {
    DW_AT_TYPE -> "DW_AT_type"
    DW_AT_SPECIFICATION -> "DW_AT_specification"
    DW_AT_ABSTRACT_ORIGIN -> "DW_AT_abstract_origin"
    else -> "DW_AT_0x${name.toString(16)}"
}

internal fun canonicalSourceIdentityBuiltinName(name: String): String {
    val normalized = name.trim().split(Regex("\\s+")).filter(String::isNotEmpty).joinToString(" ")
    if (normalized.isEmpty()) return normalized
    val tokens = normalized.split(' ')
    val counts = tokens.groupingBy { it }.eachCount()
    if (counts.any { (token, count) -> count > 1 && token != "long" } || (counts["long"] ?: 0) > 2) return normalized
    if ("signed" in tokens && "unsigned" in tokens) return normalized
    val tokenSet = tokens.toSet()
    val longCount = counts["long"] ?: 0
    return when {
        "char" in tokenSet -> when {
            tokenSet.any { it !in setOf("signed", "unsigned", "char") } -> normalized
            "unsigned" in tokenSet -> "unsigned char"
            "signed" in tokenSet -> "signed char"
            else -> "char"
        }
        "float" in tokenSet -> if (tokenSet == setOf("float")) "float" else normalized
        "double" in tokenSet -> when {
            tokenSet == setOf("double") -> "double"
            tokenSet == setOf("long", "double") && longCount == 1 -> "long double"
            else -> normalized
        }
        tokenSet.any { it !in setOf("signed", "unsigned", "short", "long", "int") } -> normalized
        ("short" in tokenSet && "long" in tokenSet) -> normalized
        else -> {
            val base = when {
                longCount == 2 -> "long long"
                longCount == 1 -> "long"
                "short" in tokenSet -> "short"
                else -> "int"
            }
            if ("unsigned" in tokenSet) "unsigned $base" else base
        }
    }
}

private const val MAXIMUM_SOURCE_IDENTITY_BYTES = MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES
private const val MAXIMUM_SOURCE_IDENTITY_CONTEXT_DEPTH = 256
private const val MAXIMUM_DWARF_PARAMETERS = 1_024
private const val MAXIMUM_DWARF_TEMPLATE_PARAMETERS = 1_024
private const val DW_TAG_INLINED_SUBROUTINE = 0x1dL
private const val DW_TAG_FORMAL_PARAMETER = 0x05L
private const val DW_TAG_UNSPECIFIED_PARAMETERS = 0x18L
private const val DW_TAG_GNU_TEMPLATE_PARAMETER_PACK = 0x4107L
private const val DW_TAG_GNU_FORMAL_PARAMETER_PACK = 0x4108L
private const val DW_TAG_TEMPLATE_TYPE_PARAMETER = 0x2fL
private const val DW_TAG_TEMPLATE_VALUE_PARAMETER = 0x30L
private const val DW_TAG_NAMESPACE = 0x39L
private const val DW_TAG_CLASS_TYPE = 0x02L
private const val DW_TAG_STRUCTURE_TYPE = 0x13L
private const val DW_TAG_UNION_TYPE = 0x17L
private const val DW_TAG_ENUMERATION_TYPE = 0x04L
private const val DW_TAG_BASE_TYPE = 0x24L
private const val DW_ATE_SIGNED = 0x05L
private const val DW_ATE_SIGNED_CHAR = 0x06L
private const val DW_ATE_BOOLEAN = 0x02L
private const val DW_ATE_UNSIGNED = 0x07L
private const val DW_ATE_UNSIGNED_CHAR = 0x08L
private const val DW_TAG_POINTER_TYPE = 0x0fL
private const val DW_TAG_LVALUE_REFERENCE_TYPE = 0x10L
private const val DW_TAG_RVALUE_REFERENCE_TYPE = 0x42L
private const val DW_TAG_CONST_TYPE = 0x26L
private const val DW_TAG_VOLATILE_TYPE = 0x35L
private const val DW_TAG_RESTRICT_TYPE = 0x37L
private const val DW_TAG_TYPEDEF = 0x16L
private const val DW_TAG_UNSPECIFIED_TYPE = 0x3bL
private const val DW_TAG_ARRAY_TYPE = 0x01L
private const val DW_TAG_SUBROUTINE_TYPE = 0x15L
private const val DW_TAG_STRING_TYPE = 0x12L
private const val DW_TAG_SET_TYPE = 0x20L
private const val DW_TAG_PACKED_TYPE = 0x2dL
private const val DW_TAG_PTR_TO_MEMBER_TYPE = 0x1fL
private const val DW_TAG_ATOMIC_TYPE = 0x47L
private const val DW_AT_ENCODING = 0x3eL
private const val DW_AT_BYTE_SIZE = 0x0bL
private const val DW_AT_TYPE = 0x49L
private const val DW_AT_CALL_COLUMN = 0x57L
private const val DW_AT_CALL_FILE = 0x58L
private const val DW_AT_CALL_LINE = 0x59L
