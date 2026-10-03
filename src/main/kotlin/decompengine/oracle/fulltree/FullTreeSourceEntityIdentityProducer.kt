package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.charset.StandardCharsets
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
)

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
    ): FullTreeSourceEntityIdentityScan {
        FullTreeScopeControl.validate(scope, controlLimits)
        requireStableDirectory(scratchParent, "source-identity scratch parent")
        val inputs = FullTreeFunctionObservationProducer.authenticateShardInputs(
            inventoryPath,
            scope,
            shardId,
            controlLimits,
            checkpoint,
        )
        val perShard = scope.document.controlObject("bounds").controlObject("perShard")
        // The authenticated per-shard entity ceiling applies to this census. The separate
        // 20,000-function limit belongs to function projection and is not a census cap.
        val maximumFacts = perShard.controlLong("entities")
        val maximumSerializedBytes = minOf(
            perShard.controlLong("serializedBytes"),
            MAXIMUM_SOURCE_IDENTITY_BYTES,
        )
        val maximumFactBytes = minOf(
            perShard.controlLong("maximumResidentBytes") / 4L,
            maximumSerializedBytes,
            MAXIMUM_SOURCE_IDENTITY_BYTES,
        )
        val lineLimits = producerLimits.lineTableLimits
        val modeledLineBytesPerUnit = try {
            Math.addExact(
                Math.addExact(
                    Math.multiplyExact(lineLimits.maximumAggregatePathBytes, 2L),
                    Math.multiplyExact(
                        Math.addExact(lineLimits.maximumDirectories.toLong(), lineLimits.maximumFiles.toLong()),
                        128L,
                    ),
                ),
                1_024L,
            )
        } catch (failure: ArithmeticException) {
            throw FullTreeControlException("source-identity line-table working-set model overflows", failure)
        }
        val modeledLineBytes = Math.multiplyExact(
            modeledLineBytesPerUnit,
            producerLimits.maximumCachedCompilationUnits.toLong(),
        )
        val maximumRepositoryBytes = try {
            Math.subtractExact(
                Math.subtractExact(
                    Math.subtractExact(perShard.controlLong("maximumResidentBytes"), modeledLineBytes),
                    maximumFactBytes,
                ),
                maximumSerializedBytes,
            )
        } catch (failure: ArithmeticException) {
            throw FullTreeControlException("source-identity working-set model overflows", failure)
        }
        if (maximumFacts <= 0L || maximumFactBytes <= 0L) {
            throw FullTreeControlException("authenticated source-identity bounds are empty")
        }
        if (maximumRepositoryBytes <= 0L) {
            throw FullTreeControlException("source-identity scanner has no authenticated retained-unit working-set budget")
        }

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
                controlLimits,
                checkpoint,
            )
            FullTreeFunctionObservationProducer.authenticateInventoryAgainstArtifact(
                inputs.inventory,
                observedUnits,
                scope.document,
            )
            val unitDocuments = inputs.inventory.controlArray("units").controlObjects("inventory units")
            val unitByOffset = unitDocuments.associateBy {
                parseDwarfOffset(it.controlString("dwarfOffset"), "inventory DWARF offset")
            }
            if (unitByOffset.size != unitDocuments.size) {
                throw FullTreeControlException("authenticated inventory repeats a DWARF compilation-unit offset")
            }
            val headerParseBudget = FullTreeDwarfParseBudget(controlLimits.maximumDwarfParseSteps, checkpoint)
            var scannedDies = 0L
            val budget = SourceIdentityRetentionBudget(maximumFacts, maximumFactBytes)
            val anchorClaims = SourceIdentityAnchorClaims(budget)
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
                    unitDocuments.size,
                    headerParseBudget,
                )
                val headersByOffset = headers.associateBy { it.offset }
                val retainedTags = sourceIdentityRetainedTags()
                val maximumRetainedBytes = minOf(
                    producerLimits.dieLimits.maximumRetainedBytes,
                    maximumRepositoryBytes / (2L * producerLimits.maximumCachedCompilationUnits),
                )
                if (maximumRetainedBytes <= 0L) {
                    throw FullTreeControlException("source-identity retained-unit budget is empty")
                }
                val boundedProducerLimits = producerLimits.copy(
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
                    maximumRetainedWorkingSetBytes = maximumRepositoryBytes,
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
                    if (scannedDies > producerLimits.dieLimits.maximumPhysicalRecords) {
                        throw FullTreeControlException("source-identity shard exceeds its physical-DIE bound")
                    }

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
                            producerLimits = producerLimits,
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
            }
            artifact.verifyUnchanged("source-identity scan")
            val ordered = FullTreeSourceEntityFact.deterministicOrder(facts)
            val maximumBaselineBytes = canonicalSourceEntityFactsByteLength(ordered)
            if (maximumBaselineBytes > maximumSerializedBytes) {
                throw FullTreeControlException("canonical source-identity output exceeds its authenticated byte bound")
            }
            val collisionReport = anchorClaims.collisionReport()
            val collisionExpansionBytes = sourceIdentityCollisionExpansionUpperBound(ordered, collisionReport.byCandidateId)
            budget.charge(collisionExpansionBytes, "source-identity collision evidence")
            if (collisionExpansionBytes > maximumSerializedBytes - maximumBaselineBytes) {
                throw FullTreeControlException("source-identity collision evidence exceeds its authenticated output bound")
            }
            val collisionAdjusted = markUnprovedAnchorCollisions(ordered, collisionReport)
            val finalBytes = canonicalSourceEntityFacts(collisionAdjusted)
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
            )
        }
    }

    private fun markUnprovedAnchorCollisions(
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
            )
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

private data class SourceIdentityAnchorCollisionReport(
    val byCandidateId: Map<String, List<String>>,
)

/** Includes anchors used only as inline callees/owners, not just census rows. */
private class SourceIdentityAnchorClaims(
    private val budget: SourceIdentityRetentionBudget,
) {
    private val claims = HashMap<String, MutableSet<String>>()

    fun claim(kind: FullTreeSourceAnchorKind, candidateId: String, physical: FullTreeSourcePhysicalDie) {
        val sourceEntityId = physical.sourceEntityId(kind)
        val prior = claims[candidateId]
        if (prior?.contains(sourceEntityId) == true) return
        budget.charge(candidateId.length.toLong() + sourceEntityId.length.toLong() + 128L, "source-anchor collision index")
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
): Long {
    var total = 0L
    try {
        facts.forEach { fact ->
            val fields = fact.semanticAnchorFields
            val candidateIds = listOfNotNull(
                fact.semanticAnchorCandidateId,
                fields?.inlineCalleeAnchorCandidateId,
                fields?.inlineOwnerAnchorCandidateId,
                fields?.templatePatternAnchorCandidateId,
            ).distinct()
            var copiedIds = 0L
            candidateIds.forEach { candidateId ->
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

private class SourceIdentityRetentionBudget(
    private val maximumFacts: Long,
    private val maximumBytes: Long,
) {
    private var facts = 0L
    private var bytes = 0L

    fun charge(bytesToAdd: Long, label: String) {
        if (bytesToAdd < 0L) throw FullTreeControlException("$label size is negative")
        bytes = try {
            Math.addExact(bytes, bytesToAdd)
        } catch (failure: ArithmeticException) {
            throw FullTreeControlException("$label size overflows", failure)
        }
        if (bytes > maximumBytes) throw FullTreeControlException("source-identity retained facts exceed their byte bound")
    }

    fun retain(fact: FullTreeSourceEntityFact) {
        if (facts >= maximumFacts) throw FullTreeControlException("source-identity census exceeds its entity bound")
        val serialized = canonicalSourceEntityFacts(listOf(fact)).size.toLong()
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
    private val anchorCache = HashMap<String, FullTreeSourceAnchorFields?>()
    private val anchorStack = LinkedHashSet<String>()

    fun fact(record: FullTreeDwarfDieRecord): FullTreeSourceEntityFact? {
        val physical = physical(owner, record)
        val edgeList = ArrayList<FullTreeSourceIdentityEdge>()
        val reasonCodes = sortedSetOf<String>()
        collectReferenceGraph(owner, record, physical, edgeList, reasonCodes)
        if (edgeList.any { it.state == FullTreeSourceIdentityEdgeState.CYCLIC }) reasonCodes += "ambiguous-reference-cycle"
        if (edgeList.any { it.state in setOf(FullTreeSourceIdentityEdgeState.MISSING_TARGET, FullTreeSourceIdentityEdgeState.MALFORMED, FullTreeSourceIdentityEdgeState.UNSUPPORTED, FullTreeSourceIdentityEdgeState.OVER_BOUND) }) {
            reasonCodes += "unknown-reference-edge"
        }
        val isInline = record.tag == DW_TAG_INLINED_SUBROUTINE
        val directChildren = owner.directChildren(record)
        val templateFormals = directChildren.filter { it.tag == DW_TAG_TEMPLATE_TYPE_PARAMETER || it.tag == DW_TAG_TEMPLATE_VALUE_PARAMETER }
        val templateState = templateState(owner, templateFormals, edgeList, reasonCodes)
        val kind = when {
            isInline -> FullTreeSourceEntityKind.INLINE_INSTANCE
            templateState == TemplateParameterState.PATTERN -> FullTreeSourceEntityKind.TEMPLATE_PATTERN
            templateState == TemplateParameterState.INSTANCE -> FullTreeSourceEntityKind.TEMPLATE_INSTANCE
            templateState == TemplateParameterState.UNKNOWN -> FullTreeSourceEntityKind.UNRESOLVED
            record.truthy(DW_AT_DECLARATION, "DW_AT_declaration") -> FullTreeSourceEntityKind.DECLARATION_ONLY
            owner.functionStart(record) == null -> FullTreeSourceEntityKind.NO_RANGE_DEFINITION
            else -> FullTreeSourceEntityKind.UNRESOLVED
        }
        // Ordinary emitted functions are already represented by the emitted-RVA observation. The
        // census adds only source identities that otherwise disappear or need an explicit relation.
        if (!isInline && kind == FullTreeSourceEntityKind.UNRESOLVED && templateFormals.isEmpty()) return null
        if (edgeList.any { it.state == FullTreeSourceIdentityEdgeState.CYCLIC }) reasonCodes += "ambiguous-reference-cycle"
        if (edgeList.any { it.state in setOf(FullTreeSourceIdentityEdgeState.MISSING_TARGET, FullTreeSourceIdentityEdgeState.MALFORMED, FullTreeSourceIdentityEdgeState.UNSUPPORTED, FullTreeSourceIdentityEdgeState.OVER_BOUND) }) {
            reasonCodes += "unknown-reference-edge"
        }
        val fields = kind.anchorKind()?.let { anchorFields(owner, record, it, edgeList, reasonCodes, physical) }
        val anchorId = kind.anchorKind()?.let { anchorKind -> fields?.let { candidate ->
            val preimageBytes = OracleJson.canonicalBytes(candidate.canonicalJson())
            budget.charge(preimageBytes.size.toLong(), "source-anchor preimage")
            candidate.candidateId(anchorKind)
        } }
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

    private fun anchorFields(
        dieUnit: FunctionDwarfUnit,
        record: FullTreeDwarfDieRecord,
        kind: FullTreeSourceAnchorKind,
        edges: MutableList<FullTreeSourceIdentityEdge>,
        reasons: MutableSet<String>,
        physical: FullTreeSourcePhysicalDie,
    ): FullTreeSourceAnchorFields? {
        val key = physical.locator() + ":" + kind.wireValue
        if (anchorCache.containsKey(key)) return anchorCache[key]
        if (!anchorStack.add(key)) {
            reasons += "ambiguous-reference-cycle"
            return null
        }
        try {
            val baseRecord: FullTreeDwarfDieRecord? = if (record.tag == DW_TAG_INLINED_SUBROUTINE) {
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
            if (baseRecord == null) return null
            val baseUnit = if (baseRecord === record) dieUnit else unitForRecord(baseRecord)
            val sourcePath = declarationPath(baseUnit, baseRecord, DW_AT_DECL_FILE, "DW_AT_decl_file")
            val declFile = baseRecord.optionalNonNegativeLong(DW_AT_DECL_FILE, "DW_AT_decl_file")
            val declLine = baseRecord.optionalNonNegativeLong(DW_AT_DECL_LINE, "DW_AT_decl_line")
            val declColumn = baseRecord.optionalNonNegativeLong(DW_AT_DECL_COLUMN, "DW_AT_decl_column")
            val sourceName = baseRecord.optionalUniqueAttribute(DW_AT_NAME, "DW_AT_name")?.let { attr ->
                FullTreeDwarfForms.decodeString(attr.value, baseUnit.sections, baseUnit.stringOffsetsBase, baseUnit.header.offsetSize, controlLimits, "source identity DW_AT_name", 16_384)
            }
            if (sourceName == null) reasons += "unknown-source-name"
            val lexical = lexicalContext(baseUnit, baseRecord)
            val baseInventory = unitByOffset[baseUnit.header.offset] ?: inventoryUnit
            val language = baseInventory["language"]?.takeUnless { it == kotlinx.serialization.json.JsonNull }
                ?.let { (it as kotlinx.serialization.json.JsonPrimitive).longOrNull }
            val signature = signature(baseUnit, baseRecord, edges, reasons)
            var templateFormalDescriptors: List<String>? = null
            var patternAnchorId: String? = null
            var actualArguments: List<String>? = null
            if (kind == FullTreeSourceAnchorKind.TEMPLATE_PATTERN || kind == FullTreeSourceAnchorKind.TEMPLATE_INSTANCE) {
                val formals = baseUnit.directChildren(baseRecord).filter { it.tag == DW_TAG_TEMPLATE_TYPE_PARAMETER || it.tag == DW_TAG_TEMPLATE_VALUE_PARAMETER }
                if (formals.size > MAXIMUM_DWARF_TEMPLATE_PARAMETERS) {
                    throw FullTreeControlException("source-identity template parameters exceed their 1,024-entry bound")
                }
                if (kind == FullTreeSourceAnchorKind.TEMPLATE_PATTERN) {
                    if (formals.isEmpty() || templateState(baseUnit, formals, edges, reasons) != TemplateParameterState.PATTERN) {
                        reasons += "unknown-template-pattern-formals"
                        return null
                    }
                    val values = arrayListOf<String>()
                    formals.forEach { formal ->
                        addStructuralEdge(physical(baseUnit, baseRecord), physical(baseUnit, formal), FullTreeSourceIdentityEdgeKind.TEMPLATE_FORMAL, edges)
                        val name = formal.optionalUniqueAttribute(DW_AT_NAME, "DW_AT_name")?.let {
                            FullTreeDwarfForms.decodeString(it.value, baseUnit.sections, baseUnit.stringOffsetsBase, baseUnit.header.offsetSize, controlLimits, "template formal name", 16_384)
                        }
                        val descriptor = if (formal.tag == DW_TAG_TEMPLATE_TYPE_PARAMETER) {
                            "type-formal:${name ?: "unnamed"}"
                        } else {
                            val declaredType = sourceReferenceAttribute(
                                baseUnit, formal, DW_AT_TYPE,
                                FullTreeSourceIdentityEdgeKind.TEMPLATE_FORMAL, edges, reasons,
                            )?.let { typeDescriptor(baseUnit, formal, it, edges, FullTreeSourceIdentityEdgeKind.TEMPLATE_FORMAL, reasons) }
                            if (declaredType == null) {
                                reasons += "unknown-template-formal-type"
                                return null
                            }
                            "value-formal:$declaredType:${name ?: "unnamed"}"
                        }
                        budget.charge(descriptor.toByteArray(StandardCharsets.UTF_8).size.toLong(), "template formal descriptor")
                        values += descriptor
                    }
                    templateFormalDescriptors = values
                } else {
                    val args = arrayListOf<String>()
                    formals.forEach { formal ->
                        val descriptor = when (formal.tag) {
                            DW_TAG_TEMPLATE_TYPE_PARAMETER -> sourceReferenceAttribute(
                                baseUnit, formal, DW_AT_TYPE,
                                FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT, edges, reasons,
                            )
                                ?.let { typeDescriptor(baseUnit, formal, it, edges, FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT, reasons) }
                                ?.let { "type-argument:$it" }
                            DW_TAG_TEMPLATE_VALUE_PARAMETER -> {
                                val type = sourceReferenceAttribute(
                                    baseUnit, formal, DW_AT_TYPE,
                                    FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT, edges, reasons,
                                )
                                    ?.let { typeDescriptor(baseUnit, formal, it, edges, FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT, reasons) }
                                val value = integralDescriptor(formal.optionalUniqueAttribute(DW_AT_CONST_VALUE, "DW_AT_const_value")?.value)
                                if (type == null || value == null) null else "value-argument:type=$type:value=$value"
                            }
                            else -> null
                        }
                        if (descriptor == null) reasons += "unknown-template-argument" else {
                            budget.charge(descriptor.toByteArray(StandardCharsets.UTF_8).size.toLong(), "template actual argument")
                            args += descriptor
                        }
                    }
                    actualArguments = args.takeIf { it.size == formals.size }
                    val patternAttr = listOf(DW_AT_SPECIFICATION, DW_AT_ABSTRACT_ORIGIN).mapNotNull { attrName ->
                        sourceReferenceAttribute(
                            baseUnit, baseRecord, attrName,
                            if (attrName == DW_AT_SPECIFICATION) FullTreeSourceIdentityEdgeKind.SPECIFICATION
                            else FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN,
                            edges, reasons,
                        )
                    }
                    if (patternAttr.size == 1) {
                        val target = referenceEdge(baseUnit, baseRecord, patternAttr.single(),
                            if (patternAttr.single().name == DW_AT_SPECIFICATION) FullTreeSourceIdentityEdgeKind.SPECIFICATION else FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN,
                            physical, edges)
                        if (target != null && target.second.tag == DW_TAG_SUBPROGRAM) {
                            val patternFormals = target.first.directChildren(target.second).filter {
                                it.tag == DW_TAG_TEMPLATE_TYPE_PARAMETER || it.tag == DW_TAG_TEMPLATE_VALUE_PARAMETER
                            }
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
                callLine = record.optionalNonNegativeLong(DW_AT_CALL_LINE, "DW_AT_call_line")
                callColumn = record.optionalNonNegativeLong(DW_AT_CALL_COLUMN, "DW_AT_call_column")
                if (callFile == null || callLine == null) reasons += "unknown-inline-callsite"
                inlinePath = enclosingInlinePath(owner, record, reasons)
            }
            if (sourcePath == null || declLine == null || language == null || signature == null) {
                reasons += "source-anchor-incomplete"
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
            anchorCache[key] = fields
            fields.candidateId(kind)?.let { anchorClaims.claim(kind, it, physical) }
            return fields
        } finally {
            anchorStack.remove(key)
        }
    }

    private fun signature(
        unit: FunctionDwarfUnit,
        record: FullTreeDwarfDieRecord,
        edges: MutableList<FullTreeSourceIdentityEdge>,
        reasons: MutableSet<String>,
    ): List<String>? {
        val result = arrayListOf<String>()
        val returnTypeAttributes = record.attributesNamed(DW_AT_TYPE)
        val returnType = sourceReferenceAttribute(
            unit, record, DW_AT_TYPE, FullTreeSourceIdentityEdgeKind.TYPE, edges, reasons,
        )
        if (returnTypeAttributes.isEmpty()) {
            result += "return:void"
        } else if (returnType == null) {
            // A duplicated reference attribute is not evidence of a void return type.
            reasons += "unknown-return-type"
            return null
        } else {
            val value = typeDescriptor(unit, record, returnType, edges, FullTreeSourceIdentityEdgeKind.TYPE, reasons)
                ?: return null
            result += "return:$value"
        }
        val parameters = unit.directChildren(record).filter { it.tag == DW_TAG_FORMAL_PARAMETER || it.tag == DW_TAG_UNSPECIFIED_PARAMETERS }
        if (parameters.size > MAXIMUM_DWARF_PARAMETERS) {
            throw FullTreeControlException("source-identity function parameters exceed their 1,024-entry bound")
        }
        parameters.forEach { parameter ->
            if (parameter.tag == DW_TAG_UNSPECIFIED_PARAMETERS) {
                result += "varargs"
            } else {
                val type = sourceReferenceAttribute(
                    unit, parameter, DW_AT_TYPE, FullTreeSourceIdentityEdgeKind.TYPE, edges, reasons,
                )
                if (type == null) {
                    reasons += "unknown-parameter-type"
                    return null
                }
                val descriptor = typeDescriptor(unit, parameter, type, edges, FullTreeSourceIdentityEdgeKind.TYPE, reasons)
                    ?: return null
                result += "parameter:$descriptor"
            }
        }
        return result
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
    ): FullTreeSourceAnchorKind? {
        if (record.tag != DW_TAG_SUBPROGRAM) return null
        val formals = unit.directChildren(record).filter {
            it.tag == DW_TAG_TEMPLATE_TYPE_PARAMETER || it.tag == DW_TAG_TEMPLATE_VALUE_PARAMETER
        }
        return when (templateState(unit, formals, edges, reasons)) {
            TemplateParameterState.INSTANCE -> FullTreeSourceAnchorKind.TEMPLATE_INSTANCE
            TemplateParameterState.PATTERN -> FullTreeSourceAnchorKind.TEMPLATE_PATTERN
            TemplateParameterState.UNKNOWN -> null
            TemplateParameterState.NONE -> when {
                record.truthy(DW_AT_DECLARATION, "DW_AT_declaration") -> FullTreeSourceAnchorKind.DECLARATION_ONLY
                unit.functionStart(record) == null -> FullTreeSourceAnchorKind.NO_RANGE_DEFINITION
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
            return describeType(ref.first, ref.second, seen, depth + 1, reasons, edges)?.let { "$label<$it>" }
        }
        return when (record.tag) {
            DW_TAG_BASE_TYPE -> {
                val encoding = record.optionalNonNegativeLong(DW_AT_ENCODING, "DW_AT_encoding") ?: return null
                val bytes = record.optionalNonNegativeLong(DW_AT_BYTE_SIZE, "DW_AT_byte_size") ?: return null
                name?.let { "base:${canonicalBuiltinName(it)}:encoding=$encoding:bytes=$bytes" }
            }
            DW_TAG_POINTER_TYPE -> nested("pointer")
            DW_TAG_LVALUE_REFERENCE_TYPE -> nested("lvalue-reference")
            DW_TAG_RVALUE_REFERENCE_TYPE -> nested("rvalue-reference")
            DW_TAG_CONST_TYPE -> nested("const")
            DW_TAG_VOLATILE_TYPE -> nested("volatile")
            DW_TAG_RESTRICT_TYPE -> nested("restrict")
            DW_TAG_TYPEDEF -> name?.let { typedef -> nested("typedef:$typedef") }
            DW_TAG_CLASS_TYPE, DW_TAG_STRUCTURE_TYPE, DW_TAG_UNION_TYPE, DW_TAG_ENUMERATION_TYPE -> {
                val tag = when (record.tag) {
                    DW_TAG_CLASS_TYPE -> "class"
                    DW_TAG_STRUCTURE_TYPE -> "struct"
                    DW_TAG_UNION_TYPE -> "union"
                    else -> "enum"
                }
                name?.let { "$tag:$it:${typeDeclPath(unit, record)}:${record.optionalNonNegativeLong(DW_AT_DECL_LINE, "DW_AT_decl_line") ?: "?"}" }
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
            targetUnit to targetUnit.index.required(targetOffset, "source identity ${dwarfAttributeLabel(attribute.name)} target")
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
                        retainEdge(
                            edges,
                            prior.copy(
                                target = null,
                                state = FullTreeSourceIdentityEdgeState.CYCLIC,
                                reasonCode = "reference-cycle",
                            ),
                        )
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
        return if (raw.startsWith('/')) {
            runCatching { FullTreeScopeControl.normalizeSourcePath(scope, raw) }.getOrNull()
        } else null
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
            if (current.tag == DW_TAG_NAMESPACE || current.tag == DW_TAG_CLASS_TYPE || current.tag == DW_TAG_STRUCTURE_TYPE) {
                val name = current.optionalUniqueAttribute(DW_AT_NAME, "DW_AT_name")?.let {
                    FullTreeDwarfForms.decodeString(it.value, unit.sections, unit.stringOffsetsBase, unit.header.offsetSize, controlLimits, "lexical context name", 16_384)
                }
                if (name != null) chain.addFirst(current.tag.toString(16) + ":" + name)
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

    private fun enclosingInlinePath(unit: FunctionDwarfUnit, record: FullTreeDwarfDieRecord, reasons: MutableSet<String>): List<String>? {
        val result = ArrayList<String>()
        var parent = record.nearestRetainedParentOffset?.let(unit.index::find)
        var traversalDepth = 0
        var inlineDepth = 1 // include this inline instance in the bounded ancestry
        while (parent != null) {
            if (traversalDepth++ >= MAXIMUM_SOURCE_IDENTITY_CONTEXT_DEPTH) {
                throw FullTreeControlException("source-identity inline ancestry traversal exceeds its depth bound")
            }
            if (parent.tag == DW_TAG_INLINED_SUBROUTINE) {
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
                    mutableListOf(),
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

    private fun typeDeclPath(unit: FunctionDwarfUnit, record: FullTreeDwarfDieRecord): String =
        declarationPath(unit, record, DW_AT_DECL_FILE, "DW_AT_decl_file") ?: "?"

    private fun unitForRecord(record: FullTreeDwarfDieRecord): FunctionDwarfUnit {
        val header = findHeader(record.offset)
        return if (header.offset == owner.header.offset) owner else repository.load(header)
    }

    private fun findHeader(offset: Long): FullTreeDwarfCompilationUnitHeader {
        var low = 0
        var high = allHeaders.lastIndex
        while (low <= high) {
            val middle = low + (high - low) / 2
            val header = allHeaders[middle]
            when {
                offset < header.offset -> high = middle - 1
                offset >= header.endOffset -> low = middle + 1
                else -> return header
            }
        }
        throw FullTreeControlException("source-identity reference is outside every validated CU")
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
}

private fun sourceIdentityRetainedTags(): Set<Long> = setOf(
    DW_TAG_SUBPROGRAM,
    DW_TAG_INLINED_SUBROUTINE,
    DW_TAG_FORMAL_PARAMETER,
    DW_TAG_UNSPECIFIED_PARAMETERS,
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

private fun integralDescriptor(value: FullTreeDwarfFormValue?): String? = when (value) {
    is FullTreeDwarfNumericValue -> value.value.toString()
    is FullTreeDwarfUnsignedConstantValue -> value.rawValue.toString()
    is FullTreeDwarfSignedConstantValue -> value.rawValue.toString()
    else -> null
}

private fun dwarfAttributeLabel(name: Long): String = when (name) {
    DW_AT_TYPE -> "DW_AT_type"
    DW_AT_SPECIFICATION -> "DW_AT_specification"
    DW_AT_ABSTRACT_ORIGIN -> "DW_AT_abstract_origin"
    else -> "DW_AT_0x${name.toString(16)}"
}

private fun canonicalBuiltinName(name: String): String = when (name) {
    "signed int" -> "int"
    "short int", "signed short", "signed short int" -> "short"
    "unsigned short int" -> "unsigned short"
    "long int", "signed long", "signed long int" -> "long"
    "unsigned long int" -> "unsigned long"
    "long long int", "signed long long", "signed long long int" -> "long long"
    "unsigned long long int" -> "unsigned long long"
    else -> name
}

private const val MAXIMUM_SOURCE_IDENTITY_BYTES = 256L * 1024L * 1024L
private const val MAXIMUM_SOURCE_IDENTITY_CONTEXT_DEPTH = 256
private const val MAXIMUM_DWARF_PARAMETERS = 1_024
private const val MAXIMUM_DWARF_TEMPLATE_PARAMETERS = 1_024
private const val DW_TAG_INLINED_SUBROUTINE = 0x1dL
private const val DW_TAG_FORMAL_PARAMETER = 0x05L
private const val DW_TAG_UNSPECIFIED_PARAMETERS = 0x18L
private const val DW_TAG_TEMPLATE_TYPE_PARAMETER = 0x2fL
private const val DW_TAG_TEMPLATE_VALUE_PARAMETER = 0x30L
private const val DW_TAG_NAMESPACE = 0x39L
private const val DW_TAG_CLASS_TYPE = 0x02L
private const val DW_TAG_STRUCTURE_TYPE = 0x13L
private const val DW_TAG_UNION_TYPE = 0x17L
private const val DW_TAG_ENUMERATION_TYPE = 0x04L
private const val DW_TAG_BASE_TYPE = 0x24L
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
