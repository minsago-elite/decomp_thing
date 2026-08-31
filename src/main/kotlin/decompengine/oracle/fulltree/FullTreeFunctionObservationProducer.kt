package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.util.Collections
import java.util.LinkedHashMap
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Independent implementation ceilings for one artifact-backed function-observation shard. */
internal data class FullTreeFunctionObservationProducerLimits(
    val dieLimits: FullTreeDwarfDieLimits = FullTreeDwarfDieLimits(
        maximumPhysicalRecords = 10_000_000L,
        maximumNonNullRecords = 5_000_000,
        maximumAttributes = 50_000_000L,
        maximumTreeDepth = 65_536,
        maximumRetainedBytes = 64L * 1024L * 1024L,
    ),
    val lineTableLimits: FullTreeDwarfLineTableLimits = FullTreeDwarfLineTableLimits(),
    val accumulatorLimits: FullTreeFunctionObservationAccumulatorLimits =
        FullTreeFunctionObservationAccumulatorLimits(),
    val elfLayoutLimits: FullTreeElfLayoutLimits = FullTreeElfLayoutLimits(),
    val maximumReferenceChainEntries: Int = 32,
    val maximumCachedCompilationUnits: Int = 2,
) {
    init {
        require(maximumReferenceChainEntries in 1..32)
        require(maximumCachedCompilationUnits in 1..32)
        Math.multiplyExact(dieLimits.maximumRetainedBytes, maximumCachedCompilationUnits.toLong())
    }
}

/** Immutable identity and canonical document produced by the bounded in-memory reference sink. */
internal data class FullTreeFunctionObservationShardGeneration(
    val shardId: String,
    val inputSha256: String,
    val inventoryArtifactSha256: String,
    val richArtifactSha256: String,
    val outputSha256: String,
    val outputBytes: Long,
    val entities: Long,
    val scannedDies: Long,
    val document: JsonObject,
)

/** Canonical control snapshots required by either observation sink. */
internal class FullTreeFunctionObservationAuthenticatedInputs internal constructor(
    val inventory: JsonObject,
    val inventoryArtifactSha256: String,
    val shard: FullTreeFunctionObservationShardInput,
)

/** Artifact identities and exact traversal counts returned before a sink may publish output. */
internal data class FullTreeFunctionObservationArtifactScan(
    val richArtifactSha256: String,
    val scannedDies: Long,
    val subprograms: Long,
)

private data class FullTreeFunctionObservationTraversalCounts(
    val scannedDies: Long,
    val subprograms: Long,
)

/**
 * Artifact-backed Kotlin/JVM reference producer for historical function-observation v3 facts.
 *
 * The inventory is read as canonical bytes, checked against the authenticated scope, and then
 * independently reconciled with every compilation-unit header/root in the rich artifact. Only
 * after that reconciliation may a requested shard scan contribute evidence. This in-memory sink
 * is intentionally limited to small parity fixtures; release-sized shards use the file-backed
 * SQLite projection so the authenticated 512 MiB envelope bound never becomes a heap bound.
 * Python and ACP are deliberately absent from either trust boundary.
 */
internal object FullTreeFunctionObservationProducer {
    fun generateShard(
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        scratchParent: Path,
        controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
    ): FullTreeFunctionObservationShardGeneration = generateShardWithLimits(
        richArtifact,
        inventoryPath,
        scope,
        shardId,
        scratchParent,
        controlLimits,
        FullTreeFunctionObservationProducerLimits(),
    )

    internal fun generateShardWithLimits(
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        scratchParent: Path,
        controlLimits: FullTreeControlLimits,
        producerLimits: FullTreeFunctionObservationProducerLimits =
            FullTreeFunctionObservationProducerLimits(),
    ): FullTreeFunctionObservationShardGeneration {
        FullTreeScopeControl.validate(scope, controlLimits)
        val modeledReferenceBytes = requireScannerResidentBudget(scope.document, producerLimits)
        val inputs = authenticateShardInputs(inventoryPath, scope, shardId, controlLimits)
        val effectiveProducerLimits = producerLimits.copy(
            accumulatorLimits = boundedAccumulatorLimits(
                producerLimits.accumulatorLimits,
                scope.document,
                modeledReferenceBytes,
            ),
        )
        val accumulator = FullTreeFunctionObservationAccumulator(
            inputs.shard,
            effectiveProducerLimits.accumulatorLimits,
        )
        val scan = scanAuthenticatedShardWithLimits(
            richArtifact = richArtifact,
            scope = scope,
            inputs = inputs,
            scratchParent = scratchParent,
            controlLimits = controlLimits,
            producerLimits = effectiveProducerLimits,
            recordScannedDies = accumulator::recordScannedDies,
            accept = accumulator::accept,
        )
        val document = accumulator.finish(
            inventoryIndexSha256 = inputs.inventory.controlString("indexSha256"),
            richArtifactSha256 = scan.richArtifactSha256,
            scopeSha256 = scope.sha256,
        )
        FullTreeFunctionObservations.validateEnvelope(
            document,
            scope.document,
            scope.sha256,
            inputs.inventory,
            inputs.inventoryArtifactSha256,
            inputs.shard,
        )
        val outputBytes = try {
            FullTreeFunctionObservations.canonicalEnvelopeBytes(document)
        } catch (failure: Exception) {
            throw FullTreeControlException(
                "function-observation output cannot be encoded as canonical JSON",
                failure,
            )
        }
        val counts = document.controlObject("counts")
        val entities = Math.addExact(
            counts.controlLong("emittedRvas"),
            counts.controlLong("nonEmitted"),
        )
        return FullTreeFunctionObservationShardGeneration(
            shardId = inputs.shard.identifier,
            inputSha256 = inputs.shard.inputSha256,
            inventoryArtifactSha256 = inputs.inventoryArtifactSha256,
            richArtifactSha256 = scan.richArtifactSha256,
            outputSha256 = OracleArtifacts.sha256(outputBytes),
            outputBytes = outputBytes.size.toLong(),
            entities = entities,
            scannedDies = counts.controlLong("scannedDies"),
            document = document,
        )
    }

    internal fun authenticateShardInputs(
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
        checkpoint: (String) -> Unit = {},
    ): FullTreeFunctionObservationAuthenticatedInputs {
        FullTreeScopeControl.validate(scope, controlLimits)
        checkpoint("after authenticating function-observation scope")
        val (inventory, inventoryBytes) = readCanonicalControlObject(
            inventoryPath,
            controlLimits.maximumInventoryBytes,
            "full-tree inventory",
            "full-tree-inventory",
        )
        FullTreeInventoryControl.validate(inventory, scope, controlLimits)
        checkpoint("after authenticating function-observation inventory")
        val inventoryArtifactSha256 = OracleArtifacts.sha256(inventoryBytes)
        val shard = FullTreeFunctionObservations.shardInputs(
            inventory,
            inventoryArtifactSha256,
            scope.document,
            scope.sha256,
        ).singleOrNull { it.identifier == shardId }
            ?: throw FullTreeControlException(
                "function-observation shard is absent from the authenticated inventory: $shardId",
            )
        return FullTreeFunctionObservationAuthenticatedInputs(
            inventory,
            inventoryArtifactSha256,
            shard,
        )
    }

    internal fun scanAuthenticatedShardWithLimits(
        richArtifact: Path,
        scope: AuthenticatedFullTreeScope,
        inputs: FullTreeFunctionObservationAuthenticatedInputs,
        scratchParent: Path,
        controlLimits: FullTreeControlLimits,
        producerLimits: FullTreeFunctionObservationProducerLimits =
            FullTreeFunctionObservationProducerLimits(),
        checkpoint: (String) -> Unit = {},
        recordScannedDies: (Long) -> Unit,
        accept: (FullTreeObservedSubprogram) -> Unit,
    ): FullTreeFunctionObservationArtifactScan {
        FullTreeScopeControl.validate(scope, controlLimits)
        requireStableDirectory(scratchParent, "function-observation scratch parent")
        requireScannerResidentBudget(scope.document, producerLimits)
        val authenticatedShard = FullTreeFunctionObservations.shardInputs(
            inputs.inventory,
            inputs.inventoryArtifactSha256,
            scope.document,
            scope.sha256,
        ).singleOrNull { it.identifier == inputs.shard.identifier }
            ?: throw FullTreeControlException(
                "function-observation scan input is outside the authenticated inventory",
            )
        if (
            authenticatedShard.inputSha256 != inputs.shard.inputSha256 ||
            authenticatedShard.units != inputs.shard.units
        ) {
            throw FullTreeControlException("function-observation scan input is not authenticated")
        }
        StableControlFile.open(
            richArtifact,
            controlLimits.maximumRichArtifactBytes,
            "rich artifact",
        ).use { artifact ->
            val richArtifactSha256 = artifact.sha256(checkpoint, "rich artifact")
            if (richArtifactSha256 != scope.document.controlObject("oracle").controlString("richArtifactSha256")) {
                throw FullTreeControlException("rich artifact does not match the full-tree scope")
            }
            val observedUnits = FullTreeDwarfCompilationUnits.read(
                artifact,
                scratchParent,
                scope.document,
                controlLimits,
                checkpoint,
            )
            checkpoint("after authenticating rich-artifact compilation units")
            authenticateInventoryAgainstArtifact(inputs.inventory, observedUnits, scope.document)
            val layout = FullTreeElfLayout.scanLayout(
                artifact,
                "rich artifact",
                producerLimits.elfLayoutLimits,
                checkpoint,
            )
            val executable = FullTreeElfExecutableMembership.fromSorted(layout.executableRanges)

            val scan = FullTreeDwarfSections.open(
                artifact,
                scratchParent,
                controlLimits,
                FullTreeDwarfSections.FUNCTION_OBSERVATION_SECTION_NAMES,
            ).use { sections ->
                scanSections(
                    sections = sections,
                    layout = layout,
                    executable = executable,
                    inventory = inputs.inventory,
                    shard = inputs.shard,
                    scope = scope,
                    controlLimits = controlLimits,
                    producerLimits = producerLimits,
                    checkpoint = checkpoint,
                    recordScannedDies = recordScannedDies,
                    accept = accept,
                )
            }
            artifact.verifyUnchanged("rich artifact after function observation")
            return FullTreeFunctionObservationArtifactScan(
                richArtifactSha256 = richArtifactSha256,
                scannedDies = scan.scannedDies,
                subprograms = scan.subprograms,
            )
        }
    }

    private fun scanSections(
        sections: FullTreeDwarfSections,
        layout: FullTreeElfCoreLayout,
        executable: FullTreeElfExecutableMembership,
        inventory: JsonObject,
        shard: FullTreeFunctionObservationShardInput,
        scope: AuthenticatedFullTreeScope,
        controlLimits: FullTreeControlLimits,
        producerLimits: FullTreeFunctionObservationProducerLimits,
        checkpoint: (String) -> Unit,
        recordScannedDies: (Long) -> Unit,
        accept: (FullTreeObservedSubprogram) -> Unit,
    ): FullTreeFunctionObservationTraversalCounts {
        val info = sections.required(".debug_info")
        val parseBudget = FullTreeDwarfParseBudget(controlLimits.maximumDwarfParseSteps, checkpoint)
        val inventoryUnits = inventory.controlArray("units").controlObjects("inventory units")
        val headers = readAllHeaders(info, inventoryUnits.size, parseBudget)
        val headersByOffset = headers.associateBy { it.offset }
        val repository = FunctionDwarfUnitRepository(
            sections,
            headers,
            controlLimits,
            producerLimits,
            parseBudget,
        )
        var scannedDies = 0L
        var subprograms = 0L
        shard.units.forEach { unit ->
            val offset = parseDwarfOffset(unit.controlString("dwarfOffset"), "inventory DWARF offset")
            val header = headersByOffset[offset]
                ?: throw FullTreeControlException(
                    "inventory compilation-unit offset is absent from the rich artifact: ${unit.controlString("id")}",
            )
            val owner = repository.load(header)
            recordScannedDies(owner.index.physicalRecordCount)
            scannedDies = Math.addExact(scannedDies, owner.index.physicalRecordCount)
            owner.index.recordsInPhysicalOrder.forEach { record ->
                if (record.tag == DW_TAG_SUBPROGRAM && !record.truthy(DW_AT_DECLARATION, "DW_AT_declaration")) {
                    accept(
                        observeSubprogram(
                            owner,
                            record,
                            unit,
                            repository,
                            layout,
                            executable,
                            scope.document,
                            producerLimits,
                        ),
                    )
                    subprograms = Math.addExact(subprograms, 1L)
                }
            }
        }
        return FullTreeFunctionObservationTraversalCounts(scannedDies, subprograms)
    }

    private fun observeSubprogram(
        owner: FunctionDwarfUnit,
        record: FullTreeDwarfDieRecord,
        inventoryUnit: JsonObject,
        repository: FunctionDwarfUnitRepository,
        layout: FullTreeElfCoreLayout,
        executable: FullTreeElfExecutableMembership,
        scope: JsonObject,
        producerLimits: FullTreeFunctionObservationProducerLimits,
    ): FullTreeObservedSubprogram {
        val chain = repository.referenceChain(owner, record, producerLimits.maximumReferenceChainEntries)
        val aliases = observeNames(record, chain, inventoryUnit.controlString("id"))
        val declaration = observeDeclaration(
            owner,
            chain,
            inventoryUnit.controlString("sourcePath"),
            scope,
            producerLimits.lineTableLimits,
        )
        val start = observeStart(owner, record)
        val rva = start?.takeIf { it >= layout.imageBase }?.let { address ->
            val candidate = address - layout.imageBase
            candidate.takeIf(executable::contains)
        }
        val inline = record.optionalIntegral(DW_AT_INLINE, "DW_AT_inline")
        return FullTreeObservedSubprogram(
            unitId = inventoryUnit.controlString("id"),
            dieOffset = record.offset.toULong(),
            rvas = rva?.let(::listOf) ?: emptyList(),
            aliases = aliases,
            declaration = declaration,
            inlineWithoutEmittedRange = inline == 1UL || inline == 3UL,
        )
    }

    private fun observeNames(
        original: FullTreeDwarfDieRecord,
        chain: List<ResolvedFunctionDie>,
        unitId: String,
    ): List<FullTreeObservedFunctionAlias> {
        val byName = LinkedHashMap<String, LinkedHashMap<String, FullTreeObservedFunctionEvidence>>()
        for (source in chain) {
            for ((attributeName, attributeLabel) in FUNCTION_NAME_ATTRIBUTES) {
                val attribute = source.record.optionalUniqueAttribute(attributeName, attributeLabel) ?: continue
                val locator = "rich:.debug_info:die=${canonicalHex(original.offset)}:" +
                    "$attributeLabel@${canonicalHex(source.record.offset)}"
                val name = FullTreeDwarfForms.decodeString(
                    attribute.value,
                    source.unit.sections,
                    source.unit.stringOffsetsBase,
                    source.unit.header.offsetSize,
                    source.unit.controlLimits,
                    locator,
                    maximumCharacters = 16_384,
                )
                byName.getOrPut(name) { LinkedHashMap() }[locator] =
                    FullTreeObservedFunctionEvidence(locator, unitId)
            }
        }
        if (byName.isEmpty()) {
            throw FullTreeControlException(
                "non-declaration DWARF subprogram ${canonicalHex(original.offset)} has no resolvable name",
            )
        }
        return byName.map { (name, evidence) ->
            FullTreeObservedFunctionAlias(name, Collections.unmodifiableList(evidence.values.toList()))
        }
    }

    private fun observeDeclaration(
        owner: FunctionDwarfUnit,
        chain: List<ResolvedFunctionDie>,
        unitSourcePath: String,
        scope: JsonObject,
        lineLimits: FullTreeDwarfLineTableLimits,
    ): JsonObject {
        val fileIndex = chain.firstIntegral(DW_AT_DECL_FILE, "DW_AT_decl_file")
        val line = chain.firstIntegral(DW_AT_DECL_LINE, "DW_AT_decl_line")
        val column = chain.firstIntegral(DW_AT_DECL_COLUMN, "DW_AT_decl_column")
        val rawPath = fileIndex?.let { index ->
            owner.lineTable(lineLimits)?.resolveDeclarationPath(
                boundedLong(index, "DWARF declaration file"),
                owner.header.version,
            ) { owner.compilationDirectory() }
        }
        var sourcePath: String? = null
        var externalPathSha256: String? = null
        if (rawPath != null && rawPath.startsWith('/')) {
            try {
                sourcePath = FullTreeScopeControl.normalizeSourcePath(scope, rawPath)
            } catch (_: FullTreeControlException) {
                externalPathSha256 = OracleArtifacts.sha256(rawPath.toByteArray(StandardCharsets.UTF_8))
            }
        }
        return JsonObject(
            mapOf(
                "column" to jsonUnsigned(column, "DWARF declaration column"),
                "externalPathSha256" to (externalPathSha256?.let(::JsonPrimitive) ?: JsonNull),
                "fileIndex" to jsonUnsigned(fileIndex, "DWARF declaration file"),
                "line" to jsonUnsigned(line, "DWARF declaration line"),
                "sourcePath" to (sourcePath?.let(::JsonPrimitive) ?: JsonNull),
                "unitSourcePath" to JsonPrimitive(unitSourcePath),
            ),
        )
    }

    private fun observeStart(
        owner: FunctionDwarfUnit,
        record: FullTreeDwarfDieRecord,
    ): ULong? {
        var rangeResolved = false
        var rangeStart: ULong? = null
        fun range(): ULong? {
            if (!rangeResolved) {
                rangeStart = owner.rangeStart(record)
                rangeResolved = true
            }
            return rangeStart
        }

        val entry = record.optionalUniqueAttribute(DW_AT_ENTRY_PC, "DW_AT_entry_pc")
        if (entry != null) {
            return when (val value = entry.value) {
                is FullTreeDwarfAddressValue -> value.rawValue
                is FullTreeDwarfAddressIndexValue -> owner.resolveAddress(value)
                is FullTreeDwarfUnsignedConstantValue -> checkedAddressAdd(
                    owner.lowPc(record) ?: range()
                        ?: throw FullTreeControlException(
                            "DW_AT_entry_pc on ${canonicalHex(record.offset)} has no function base",
                        ),
                    value.rawValue,
                    "DW_AT_entry_pc",
                )
                is FullTreeDwarfSignedConstantValue -> {
                    if (value.rawValue < 0L) {
                        throw FullTreeControlException("DW_AT_entry_pc is outside unsigned 64-bit range")
                    }
                    checkedAddressAdd(
                        owner.lowPc(record) ?: range()
                            ?: throw FullTreeControlException(
                                "DW_AT_entry_pc on ${canonicalHex(record.offset)} has no function base",
                            ),
                        value.rawValue.toULong(),
                        "DW_AT_entry_pc",
                    )
                }
                else -> throw FullTreeControlException("DW_AT_entry_pc has an unsupported DWARF form class")
            }
        }
        return owner.lowPc(record) ?: range()
    }

    private fun authenticateInventoryAgainstArtifact(
        inventory: JsonObject,
        observed: List<FullTreeDwarfCompilationUnit>,
        scope: JsonObject,
    ) {
        val inventoryUnits = inventory.controlArray("units").controlObjects("inventory units")
        if (observed.size != inventoryUnits.size) {
            throw FullTreeControlException(
                "full-tree inventory compilation-unit count differs from the rich artifact",
            )
        }
        val byOffset = observed.associateBy { it.offset }
        if (byOffset.size != observed.size) {
            throw FullTreeControlException("rich artifact repeats a compilation-unit offset")
        }
        inventoryUnits.forEach { unit ->
            val offset = parseDwarfOffset(unit.controlString("dwarfOffset"), "inventory DWARF offset")
            val fact = byOffset[offset]
                ?: throw FullTreeControlException("inventory compilation-unit offset is absent from the rich artifact")
            val sourcePath = FullTreeScopeControl.normalizeSourcePath(scope, fact.rawPath)
            val producer = fact.producer?.let {
                JsonPrimitive(OracleArtifacts.sha256(it.toByteArray(StandardCharsets.UTF_8)))
            } ?: JsonNull
            val language = fact.language?.let(::JsonPrimitive) ?: JsonNull
            if (
                unit.controlLong("addressSize") != fact.addressSize.toLong() ||
                unit.controlLong("dwarfVersion") != fact.version.toLong() ||
                unit["language"] != language ||
                unit["producerSha256"] != producer ||
                unit.controlString("rawPathSha256") !=
                OracleArtifacts.sha256(fact.rawPath.toByteArray(StandardCharsets.UTF_8)) ||
                unit.controlString("sourcePath") != sourcePath
            ) {
                throw FullTreeControlException(
                    "inventory compilation-unit metadata differs from the rich artifact: ${unit.controlString("id")}",
                )
            }
        }
        if (byOffset.keys != inventoryUnits.mapTo(hashSetOf()) {
                parseDwarfOffset(it.controlString("dwarfOffset"), "inventory DWARF offset")
            }
        ) {
            throw FullTreeControlException("full-tree inventory does not cover the exact rich-artifact CU set")
        }
    }

    private fun readAllHeaders(
        info: FullTreeDwarfSection,
        expectedUnits: Int,
        parseBudget: FullTreeDwarfParseBudget,
    ): List<FullTreeDwarfCompilationUnitHeader> {
        if (expectedUnits <= 0) throw FullTreeControlException("full-tree inventory has no compilation units")
        val iterator = FullTreeDwarfCompilationUnitHeaders(info, expectedUnits.toLong(), parseBudget)
        val result = ArrayList<FullTreeDwarfCompilationUnitHeader>(expectedUnits)
        while (iterator.hasNext()) result += iterator.next()
        if (result.size != expectedUnits) {
            throw FullTreeControlException("full-tree inventory does not cover every DWARF compilation unit")
        }
        return Collections.unmodifiableList(result)
    }

    private fun boundedAccumulatorLimits(
        configured: FullTreeFunctionObservationAccumulatorLimits,
        scope: JsonObject,
        modeledReferenceBytes: Long,
    ): FullTreeFunctionObservationAccumulatorLimits {
        val perShard = scope.controlObject("bounds").controlObject("perShard")
        val entityBound = perShard.controlLong("entities")
        if (entityBound <= 0L) {
            throw FullTreeControlException("authenticated function-observation entity bound is invalid")
        }
        val maximumEntities = minOf(entityBound, configured.maximumEntities.toLong(), Int.MAX_VALUE.toLong()).toInt()
        val residentBytes = perShard.controlLong("maximumResidentBytes")
        val remainingResidentBytes = residentBytes - modeledReferenceBytes
        val maximumEnvelopeBytes = minOf(
            perShard.controlLong("serializedBytes"),
            FUNCTION_OBSERVATION_MAXIMUM_ENVELOPE_BYTES,
        )
        val serializedModelBytes = try {
            Math.multiplyExact(maximumEnvelopeBytes, 4L)
        } catch (_: ArithmeticException) {
            Long.MAX_VALUE
        }
        val maximumRetainedBytes = minOf(
            configured.maximumRetainedBytes,
            remainingResidentBytes / 2L,
            serializedModelBytes,
        )
        if (maximumRetainedBytes <= 0L) {
            throw FullTreeControlException(
                "function-observation accumulator has no authenticated resident-byte budget",
            )
        }
        return configured.copy(
            maximumEntities = maximumEntities,
            maximumEmittedRvas = minOf(configured.maximumEmittedRvas, maximumEntities),
            maximumNonEmittedGroups = minOf(configured.maximumNonEmittedGroups, maximumEntities),
            maximumRetainedBytes = maximumRetainedBytes,
        )
    }

    private fun requireScannerResidentBudget(
        scope: JsonObject,
        producerLimits: FullTreeFunctionObservationProducerLimits,
    ): Long {
        val cachedUnits = producerLimits.maximumCachedCompilationUnits.toLong()
        val modeledReferenceBytes = Math.addExact(
            Math.multiplyExact(
                producerLimits.dieLimits.maximumRetainedBytes,
                Math.addExact(
                    producerLimits.maximumReferenceChainEntries,
                    producerLimits.maximumCachedCompilationUnits,
                ).toLong(),
            ),
            Math.multiplyExact(
                modeledLineTableRetainedBytes(producerLimits.lineTableLimits),
                cachedUnits,
            ),
        )
        if (
            modeledReferenceBytes > scope.controlObject("bounds").controlObject("perShard")
                .controlLong("maximumResidentBytes")
        ) {
            throw FullTreeControlException(
                "function-observation DIE/reference cache model exceeds the authenticated resident-byte bound",
            )
        }
        return modeledReferenceBytes
    }
}

private fun modeledLineTableRetainedBytes(limits: FullTreeDwarfLineTableLimits): Long {
    val decodedPaths = Math.multiplyExact(limits.maximumAggregatePathBytes, 2L)
    val entries = Math.addExact(limits.maximumDirectories.toLong(), limits.maximumFiles.toLong())
    val entryObjects = Math.multiplyExact(entries, MODELED_LINE_TABLE_ENTRY_BYTES)
    return Math.addExact(Math.addExact(decodedPaths, entryObjects), MODELED_LINE_TABLE_BYTES)
}

/** Shared bounded DWARF function-DIE repository used by both full-tree observations and v1 composition. */
internal class FunctionDwarfUnitRepository(
    private val sections: FullTreeDwarfSections,
    private val headers: List<FullTreeDwarfCompilationUnitHeader>,
    private val controlLimits: FullTreeControlLimits,
    private val producerLimits: FullTreeFunctionObservationProducerLimits,
    private val parseBudget: FullTreeDwarfParseBudget,
) {
    private val info = sections.required(".debug_info")
    private val abbreviations = sections.required(".debug_abbrev")
    private val cache = object : LinkedHashMap<Long, FunctionDwarfUnit>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, FunctionDwarfUnit>): Boolean =
            size > producerLimits.maximumCachedCompilationUnits
    }

    fun load(header: FullTreeDwarfCompilationUnitHeader): FunctionDwarfUnit = cache[header.offset] ?: run {
        val index = FullTreeDwarfDies.readCompilationUnit(
            info,
            abbreviations,
            header,
            controlLimits,
            producerLimits.dieLimits,
            parseBudget,
            contextForAttribute = ::functionAttributeContext,
            retainRecord = { tag, depth -> depth == 0 || tag == DW_TAG_SUBPROGRAM },
        )
        FunctionDwarfUnit(
            header,
            index,
            controlLimits,
            sections,
            parseBudget,
        ).also { cache[header.offset] = it }
    }

    fun referenceChain(
        owner: FunctionDwarfUnit,
        original: FullTreeDwarfDieRecord,
        maximumEntries: Int,
    ): List<ResolvedFunctionDie> {
        val result = ArrayList<ResolvedFunctionDie>()
        val pending = ArrayDeque<ResolvedFunctionDie>()
        val seen = HashSet<Long>()
        val scheduled = HashSet<Long>()
        val chainUnits = HashMap<Long, FunctionDwarfUnit>()
        chainUnits[owner.header.offset] = owner
        scheduled += original.offset
        pending += ResolvedFunctionDie(owner, original)
        while (pending.isNotEmpty()) {
            val current = pending.removeFirst()
            if (!seen.add(current.record.offset)) continue
            result += current
            if (result.size > maximumEntries) {
                throw FullTreeControlException(
                    "DWARF reference chain from DIE ${canonicalHex(original.offset)} exceeds $maximumEntries entries",
                )
            }
            for ((attributeName, attributeLabel) in REFERENCE_ATTRIBUTES) {
                val attribute = current.record.optionalUniqueAttribute(attributeName, attributeLabel)
                    ?: continue
                val reference = attribute.value as? FullTreeDwarfReferenceValue
                    ?: throw FullTreeControlException(
                        "cannot resolve $attributeLabel from DIE ${canonicalHex(original.offset)}",
                    )
                val target = current.unit.header.resolveReference(info, reference)
                if (!scheduled.add(target)) continue
                if (scheduled.size > maximumEntries) {
                    throw FullTreeControlException(
                        "DWARF reference chain from DIE ${canonicalHex(original.offset)} " +
                            "exceeds $maximumEntries entries",
                    )
                }
                val targetHeader = headerContaining(target)
                val targetUnit = chainUnits.getOrPut(targetHeader.offset) { load(targetHeader) }
                pending += ResolvedFunctionDie(
                    targetUnit,
                    targetUnit.index.required(target, attributeLabel),
                )
            }
        }
        return Collections.unmodifiableList(result)
    }

    private fun headerContaining(offset: Long): FullTreeDwarfCompilationUnitHeader {
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
        throw FullTreeControlException("DWARF global reference is outside every compilation unit")
    }
}

internal class FunctionDwarfUnit(
    val header: FullTreeDwarfCompilationUnitHeader,
    val index: FullTreeDwarfDieIndex,
    val controlLimits: FullTreeControlLimits,
    val sections: FullTreeDwarfSections,
    private val parseBudget: FullTreeDwarfParseBudget,
) {
    val stringOffsetsBase: Long? = index.root.optionalNonNegativeLong(
        DW_AT_STR_OFFSETS_BASE,
        "DW_AT_str_offsets_base",
    )
    private val addressBase: Long? = index.root.optionalNonNegativeLong(DW_AT_ADDR_BASE, "DW_AT_addr_base")
    private val rnglistsBase: Long? = index.root.optionalNonNegativeLong(
        DW_AT_RNGLISTS_BASE,
        "DW_AT_rnglists_base",
    )
    private val statementList: Long? = index.root.optionalNonNegativeLong(DW_AT_STMT_LIST, "DW_AT_stmt_list")
    private var cachedCompilationDirectory: String? = null
    private var compilationDirectoryResolved = false
    private var cachedLineTable: FullTreeDwarfLineTable? = null
    private var lineTableResolved = false
    private var cachedAddressResolver: FullTreeDwarfAddressResolver? = null
    private var addressResolverResolved = false
    private var cachedRangeResolver: FullTreeDwarfRangeListResolver? = null

    fun compilationDirectory(): String? {
        if (!compilationDirectoryResolved) {
            cachedCompilationDirectory = index.root.optionalUniqueAttribute(DW_AT_COMP_DIR, "DW_AT_comp_dir")?.let {
                FullTreeDwarfForms.decodeString(
                    it.value,
                    sections,
                    stringOffsetsBase,
                    header.offsetSize,
                    controlLimits,
                    "DWARF compilation directory",
                    maximumCharacters = 16_384,
                )
            }
            compilationDirectoryResolved = true
        }
        return cachedCompilationDirectory
    }

    fun lineTable(
        limits: FullTreeDwarfLineTableLimits,
    ): FullTreeDwarfLineTable? {
        if (!lineTableResolved) {
            val line = sections.optional(".debug_line")
            cachedLineTable = if (statementList == null || line == null) {
                null
            } else {
                FullTreeDwarfLineTables.read(
                    FullTreeDwarfLineTableSections(
                        line = line,
                        strings = sections.optional(".debug_str"),
                        lineStrings = sections.optional(".debug_line_str"),
                        stringOffsets = sections.optional(".debug_str_offsets"),
                    ),
                    statementList,
                    header.offsetSize,
                    stringOffsetsBase,
                    parseBudget,
                    limits,
                )
            }
            lineTableResolved = true
        }
        return cachedLineTable
    }

    fun resolveAddress(value: FullTreeDwarfAddressIndexValue): ULong {
        if (!addressResolverResolved) {
            val base = addressBase
                ?: throw FullTreeControlException("indexed DWARF address requires DW_AT_addr_base")
            val addressSection = sections.optional(".debug_addr")
                ?: throw FullTreeControlException("indexed DWARF address requires .debug_addr")
            cachedAddressResolver = FullTreeDwarfAddressResolver(
                addressSection,
                base,
                header.version,
                header.offsetSize,
                header.addressSize,
            )
            addressResolverResolved = true
        }
        return checkNotNull(cachedAddressResolver).resolve(value)
    }

    fun lowPc(record: FullTreeDwarfDieRecord): ULong? =
        record.optionalUniqueAttribute(DW_AT_LOW_PC, "DW_AT_low_pc")?.let { attribute ->
            when (val value = attribute.value) {
                is FullTreeDwarfAddressValue -> value.rawValue
                is FullTreeDwarfAddressIndexValue -> resolveAddress(value)
                else -> throw FullTreeControlException("DW_AT_low_pc must have address class")
            }
        }

    fun rangeStart(
        record: FullTreeDwarfDieRecord,
    ): ULong? {
        val ranges = record.optionalUniqueAttribute(DW_AT_RANGES, "DW_AT_ranges") ?: return null
        val resolver = cachedRangeResolver ?: FullTreeDwarfRangeListResolver(
            version = header.version,
            addressSize = header.addressSize,
            offsetSize = header.offsetSize,
            debugRanges = sections.optional(".debug_ranges"),
            debugRnglists = sections.optional(".debug_rnglists"),
            rnglistsBase = rnglistsBase,
            parseBudget = parseBudget,
        ).also { cachedRangeResolver = it }
        val input = resolver.resolve(ranges.value)
        val addressResolver = if (addressBase != null) addressResolverOrNull() else null
        return FullTreeDwarfRanges.firstNonEmptyStart(
            input,
            addressResolver,
            compilationUnitLowPc = lowPc(index.root),
            parseBudget,
        )
    }

    private fun addressResolverOrNull(): FullTreeDwarfAddressResolver? {
        if (!addressResolverResolved) {
            val base = addressBase ?: return null
            val addressSection = sections.optional(".debug_addr") ?: return null
            cachedAddressResolver = FullTreeDwarfAddressResolver(
                addressSection,
                base,
                header.version,
                header.offsetSize,
                header.addressSize,
            )
            addressResolverResolved = true
        }
        return cachedAddressResolver
    }
}

internal data class ResolvedFunctionDie(
    val unit: FunctionDwarfUnit,
    val record: FullTreeDwarfDieRecord,
)

internal fun functionAttributeContext(attribute: FullTreeDwarfAbbreviationAttribute): FullTreeDwarfFormContext =
    when (attribute.name) {
        DW_AT_RANGES -> FullTreeDwarfFormContext.RANGE_LIST
        DW_AT_ENTRY_PC,
        DW_AT_CONST_VALUE,
        DW_AT_DECL_FILE,
        DW_AT_DECL_LINE,
        DW_AT_DECL_COLUMN,
        DW_AT_DECLARATION,
        DW_AT_INLINE,
        -> FullTreeDwarfFormContext.CONSTANT
        else -> FullTreeDwarfFormContext.GENERAL
    }

internal fun FullTreeDwarfDieRecord.truthy(name: Long, label: String): Boolean =
    optionalUniqueAttribute(name, label)?.value?.let { value ->
        when (value) {
            is FullTreeDwarfNumericValue -> value.value != 0L
            is FullTreeDwarfUnsignedConstantValue -> value.rawValue != 0UL
            is FullTreeDwarfSignedConstantValue -> value.rawValue != 0L
            else -> throw FullTreeControlException("$label is not an integral DWARF attribute")
        }
    } ?: false

internal fun FullTreeDwarfDieRecord.optionalIntegral(name: Long, label: String): ULong? =
    optionalUniqueAttribute(name, label)?.value?.let { value ->
        when (value) {
            is FullTreeDwarfNumericValue -> {
                if (value.value < 0L) throw FullTreeControlException("$label is negative")
                value.value.toULong()
            }
            is FullTreeDwarfUnsignedConstantValue -> value.rawValue
            is FullTreeDwarfSignedConstantValue -> {
                if (value.rawValue < 0L) throw FullTreeControlException("$label is negative")
                value.rawValue.toULong()
            }
            else -> throw FullTreeControlException("$label is not an integral DWARF attribute")
        }
    }

internal fun FullTreeDwarfDieRecord.optionalNonNegativeLong(name: Long, label: String): Long? =
    optionalIntegral(name, label)?.let { boundedLong(it, label) }

private fun List<ResolvedFunctionDie>.firstIntegral(name: Long, label: String): ULong? {
    forEach { source ->
        source.record.optionalIntegral(name, label)?.let { return it }
    }
    return null
}

private fun jsonUnsigned(value: ULong?, label: String) =
    value?.let { JsonPrimitive(boundedLong(it, label)) } ?: JsonNull

private fun boundedLong(value: ULong, label: String): Long {
    if (value > Long.MAX_VALUE.toULong()) {
        throw FullTreeControlException("$label exceeds the supported integer range")
    }
    return value.toLong()
}

private fun parseDwarfOffset(value: String, label: String): Long {
    if (!value.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]*)"))) {
        throw FullTreeControlException("$label is not canonical")
    }
    val parsed = value.removePrefix("0x").toULongOrNull(16)
        ?: throw FullTreeControlException("$label exceeds unsigned 64-bit range")
    return boundedLong(parsed, label)
}

internal fun checkedAddressAdd(left: ULong, right: ULong, label: String): ULong {
    if (right > ULong.MAX_VALUE - left) {
        throw FullTreeControlException("$label overflows unsigned 64-bit address space")
    }
    return left + right
}

internal fun canonicalHex(value: Long): String {
    if (value < 0L) throw FullTreeControlException("DWARF offset is negative")
    return "0x${value.toString(16)}"
}

internal const val DW_TAG_SUBPROGRAM = 0x2eL
internal const val DW_AT_NAME = 0x03L
internal const val DW_AT_STMT_LIST = 0x10L
internal const val DW_AT_LOW_PC = 0x11L
internal const val DW_AT_COMP_DIR = 0x1bL
internal const val DW_AT_CONST_VALUE = 0x1cL
internal const val DW_AT_INLINE = 0x20L
internal const val DW_AT_ABSTRACT_ORIGIN = 0x31L
internal const val DW_AT_DECL_COLUMN = 0x39L
internal const val DW_AT_DECL_FILE = 0x3aL
internal const val DW_AT_DECL_LINE = 0x3bL
internal const val DW_AT_DECLARATION = 0x3cL
internal const val DW_AT_SPECIFICATION = 0x47L
internal const val DW_AT_ENTRY_PC = 0x52L
internal const val DW_AT_RANGES = 0x55L
internal const val DW_AT_LINKAGE_NAME = 0x6eL
internal const val DW_AT_STR_OFFSETS_BASE = 0x72L
internal const val DW_AT_ADDR_BASE = 0x73L
internal const val DW_AT_RNGLISTS_BASE = 0x74L
internal const val DW_AT_MIPS_LINKAGE_NAME = 0x2007L

internal val FUNCTION_NAME_ATTRIBUTES = listOf(
    DW_AT_LINKAGE_NAME to "DW_AT_linkage_name",
    DW_AT_MIPS_LINKAGE_NAME to "DW_AT_MIPS_linkage_name",
    DW_AT_NAME to "DW_AT_name",
)
private val REFERENCE_ATTRIBUTES = listOf(
    DW_AT_ABSTRACT_ORIGIN to "DW_AT_abstract_origin",
    DW_AT_SPECIFICATION to "DW_AT_specification",
)
private const val FUNCTION_OBSERVATION_MAXIMUM_ENVELOPE_BYTES = 64L * 1024L * 1024L
private const val MODELED_LINE_TABLE_BYTES = 1024L
private const val MODELED_LINE_TABLE_ENTRY_BYTES = 128L
