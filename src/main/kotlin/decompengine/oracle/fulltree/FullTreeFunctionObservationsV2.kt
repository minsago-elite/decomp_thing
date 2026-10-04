package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Collections
import java.util.TreeMap
import java.util.TreeSet
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

internal class FullTreeFunctionObservationV2Exception(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

internal data class FullTreeFunctionObservationV2StreamResult(
    val outputSha256: String,
    val outputBytes: Long,
    val emitted: Long,
    val nonEmitted: Long,
    val sourceEntities: Long,
    val scannedDies: Long,
    val databaseHighWaterBytes: Long,
)

/** Identity of the additive observation contract. The v1 schema and policy stay frozen. */
internal object FullTreeFunctionObservationsV2 {
    const val SCHEMA_NAME = "full-tree-function-observations-v2"
    // Match OracleJson.StrictJsonLimits' shared 64 MiB canonical-document hard ceiling. Every v2
    // sink, composer, validator, and run publisher applies this cap together with authenticated
    // per-shard output bounds; this does not silently diverge from the strict JSON layer.
    const val MAXIMUM_CANONICAL_BYTES = 64L * 1024L * 1024L
    const val MAXIMUM_JSON_NODES = 1_000_000

    val producerPolicy: JsonObject = JsonObject(
        mapOf(
            "id" to JsonPrimitive("full-tree-function-observations"),
            "version" to JsonPrimitive(4),
            "identityReconciliation" to JsonPrimitive("full-run-anchor-claims-v1"),
            "sourceEntityId" to JsonPrimitive("artifact-unit-section-cu-die-kind-v1"),
            "semanticAnchorCandidate" to JsonPrimitive("typed-source-tuple-v2-column-excluded"),
            "candidateHashesProveIdentity" to JsonPrimitive(false),
            "legacySourceEntityCoverage" to JsonPrimitive(false),
            "maximumCanonicalBytes" to JsonPrimitive(MAXIMUM_CANONICAL_BYTES),
            "maximumJsonNodes" to JsonPrimitive(MAXIMUM_JSON_NODES),
        ),
    )

    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256(SCHEMA_NAME, producerPolicy)
    }

    /** Compose a v2 document from the frozen emitted-function projection and accepted census facts. */
    fun composeEnvelope(
        v1: JsonObject,
        sourceFacts: List<FullTreeSourceEntityFact>,
        reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
        maximumBytes: Long,
    ): JsonObject {
        require(maximumBytes in 1L..16L * 1024L * 1024L * 1024L)
        val facts = FullTreeSourceEntityFact.deterministicOrder(sourceFacts)
        facts.forEach(::validateSourceEntityForV2)
        reconciliation.validateSourceEntityPopulation(v1.v2Object("shard").v2String("id"), facts)
        validateDirectAnchorEvidence(facts, reconciliation)
        validateInlineAnchorEvidence(facts, reconciliation)
        validateCollisionEvidence(facts, reconciliation)
        if (facts.map { it.sourceEntityId }.toSet().size != facts.size) {
            v2Fail("observation-v2 sourceEntityIds are not unique")
        }
        if (facts.map { it.physicalDie }.toSet().size != facts.size) {
            v2Fail("observation-v2 physical DIE locators are not unique")
        }
        val baseCounts = v1.v2Object("counts")
        val counts = JsonObject(
            baseCounts.toMutableMap().apply {
                put("sourceEntities", JsonPrimitive(facts.size))
                put("sourceEntitiesByKind", countKinds(facts))
                put("sourceEntitiesByObservability", countObservability(facts))
                put("sourceEntitiesByDenominatorDisposition", countDisposition(facts))
                put("anchorClaims", JsonPrimitive(reconciliation.claimCount))
                put("anchorCandidateCount", JsonPrimitive(reconciliation.candidateCount))
                put("anchorCollisionCandidateCount", JsonPrimitive(reconciliation.collisionCandidateCount))
            },
        )
        val oracle = JsonObject(v1.v2Object("oracle").toMutableMap().apply {
            put("configurationSha256", JsonPrimitive(configurationSha256))
        })
        val result = JsonObject(
            v1.toMutableMap().apply {
                put("counts", counts)
                put("oracle", oracle)
                put("schemaVersion", JsonPrimitive(2))
                put("sourceEntities", JsonArray(facts.map(FullTreeSourceEntityFact::canonicalJson)))
                put("identityReconciliation", reconciliation.canonicalJson())
            },
        )
        val bytes = canonicalEnvelopeBytes(result, maximumBytes)
        if (bytes.size.toLong() > maximumBytes) v2Fail("observation-v2 exceeds its authenticated byte bound")
        return result
    }

    /** Keep producer and both sinks within the exact per-string bounds in the v2 schema. */
    fun validateSourceEntityForV2(fact: FullTreeSourceEntityFact) {
        val fields = fact.semanticAnchorFields ?: return
        if (fields.sourcePath?.let(::sourceIdentityJsonCodePointLength)?.let { it > 4_096 } == true) {
            v2Fail("source path exceeds the observation-v2 schema character bound")
        }
        listOfNotNull(fields.sourceName, fields.authenticatedSourceRevision, fields.inlineCallFile)
            .forEach { value ->
                if (sourceIdentityJsonCodePointLength(value) > MAXIMUM_SOURCE_IDENTITY_DESCRIPTOR_CHARACTERS) {
                    v2Fail("completed source-identity descriptor exceeds the observation-v2 schema character bound")
                }
            }
        val descriptors = sequenceOf(
            fields.lexicalContext.asSequence(),
            fields.signature.orEmpty().asSequence(),
            fields.templateFormalParameters.orEmpty().asSequence(),
            fields.templateActualArguments.orEmpty().asSequence(),
        ).flatten()
        if (descriptors.any { sourceIdentityJsonCodePointLength(it) > MAXIMUM_SOURCE_IDENTITY_DESCRIPTOR_CHARACTERS }) {
            v2Fail("completed source-identity descriptor exceeds the observation-v2 schema character bound")
        }
        if (fields.lexicalContext.size > MAXIMUM_SOURCE_IDENTITY_LEXICAL_CONTEXT_ITEMS ||
            (fields.signature?.size ?: 0) > MAXIMUM_SOURCE_IDENTITY_SIGNATURE_ITEMS ||
            (fields.templateFormalParameters?.size ?: 0) > MAXIMUM_SOURCE_IDENTITY_SIGNATURE_ITEMS ||
            (fields.templateActualArguments?.size ?: 0) > MAXIMUM_SOURCE_IDENTITY_SIGNATURE_ITEMS
        ) {
            v2Fail("source-identity descriptor list exceeds the observation-v2 schema item bound")
        }
    }

    fun canonicalEnvelopeBytes(document: JsonObject, maximumBytes: Long = MAXIMUM_CANONICAL_BYTES): ByteArray = try {
        val boundedBytes = minOf(maximumBytes, MAXIMUM_CANONICAL_BYTES).toInt()
        OracleJson.canonicalBytes(
            document,
            StrictJsonLimits(
                maximumInputBytes = boundedBytes,
                maximumCanonicalBytes = boundedBytes,
                maximumDepth = 128,
                maximumNodes = MAXIMUM_JSON_NODES,
                maximumStringBytes = MAXIMUM_SOURCE_IDENTITY_ROW_BYTES.toInt(),
                maximumTotalStringBytes = boundedBytes,
            ),
        )
    } catch (failure: Exception) {
        throw FullTreeFunctionObservationV2Exception("function observation-v2 cannot be canonicalized", failure)
    }

    /** Strictly validates the schema, old emitted projection, source-fact semantics and run binding. */
    fun validateEnvelope(
        document: JsonObject,
        scope: AuthenticatedFullTreeScope,
        inventory: JsonObject,
        inventoryArtifactSha256: String,
        shard: FullTreeFunctionObservationShardInput,
        reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
        controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
        checkpoint: (String) -> Unit = {},
    ) {
        try {
            FullTreeScopeControl.validate(scope, controlLimits)
        } catch (failure: Exception) {
            throw FullTreeFunctionObservationV2Exception("observation-v2 scope authentication failed", failure)
        }
        val scopeDocument = scope.document
        try {
            OracleSchemas.validate(SCHEMA_NAME, document)
        } catch (failure: Exception) {
            throw FullTreeFunctionObservationV2Exception("function observation-v2 schema validation failed", failure)
        }
        val counts = document.v2Object("counts")
        val sourceRows = document.v2Array("sourceEntities").mapIndexed { index, element ->
            element as? JsonObject ?: v2Fail("source entity $index is not an object")
        }
        val facts = sourceRows.mapIndexed { index, row ->
            try {
                FullTreeSourceEntityFact.fromCanonicalJson(row, "source entity $index")
            } catch (failure: FullTreeFunctionObservationV2Exception) {
                throw failure
            } catch (failure: Exception) {
                throw FullTreeFunctionObservationV2Exception("source entity $index is invalid", failure)
            }
        }
        val ids = HashSet<String>()
        facts.forEach { if (!ids.add(it.sourceEntityId)) v2Fail("duplicate sourceEntityId") }
        val physicalDies = HashSet<FullTreeSourcePhysicalDie>()
        facts.forEach { if (!physicalDies.add(it.physicalDie)) v2Fail("duplicate physical DIE locator") }
        if (facts != FullTreeSourceEntityFact.deterministicOrder(facts)) {
            v2Fail("observation-v2 source entities are not canonically ordered")
        }
        reconciliation.validateSourceEntityPopulation(shard.identifier, facts, checkpoint)
        validateDirectAnchorEvidence(facts, reconciliation)
        validateInlineAnchorEvidence(facts, reconciliation)
        validateCollisionEvidence(facts, reconciliation)
        if (counts.v2Long("sourceEntities") != facts.size.toLong() ||
            counts.v2Object("sourceEntitiesByKind") != countKinds(facts) ||
            counts.v2Object("sourceEntitiesByObservability") != countObservability(facts) ||
            counts.v2Object("sourceEntitiesByDenominatorDisposition") != countDisposition(facts)
        ) {
            v2Fail("observation-v2 source entity counts do not reconcile")
        }
        if (
            counts.v2Long("anchorClaims") != reconciliation.claimCount ||
            counts.v2Long("anchorCandidateCount") != reconciliation.candidateCount ||
            counts.v2Long("anchorCollisionCandidateCount") != reconciliation.collisionCandidateCount ||
            document.v2Object("identityReconciliation") != reconciliation.canonicalJson()
        ) {
            v2Fail("observation-v2 full-run identity reconciliation does not match")
        }
        val oracle = document.v2Object("oracle")
        if (oracle.v2String("configurationSha256") != configurationSha256) {
            v2Fail("observation-v2 configuration digest differs")
        }
        val emittedRvas = document.v2Array("emitted").map { (it as JsonObject).v2String("rva") }.toSet()
        if (emittedRvas.size != document.v2Array("emitted").size) {
            v2Fail("observation-v2 emitted RVA population contains duplicates")
        }
        val locatorIndex = V2ArtifactLocatorIndex.create(inventory, shard)
        facts.forEach { fact ->
            fact.linkedEmittedRva?.let { rva ->
                if (rva !in emittedRvas) v2Fail("source entity links to an absent emitted RVA")
            }
            val sourceRevision = fact.semanticAnchorFields?.authenticatedSourceRevision
            val authenticatedRevision = scope.sourceLock.v2Object("revision").v2String("commit")
            if (fact.semanticAnchorFields != null && sourceRevision != authenticatedRevision) {
                v2Fail("source anchor revision is absent or differs from the authenticated source lock")
            }
            if (fact.semanticAnchorFields?.authenticatedSourceFileSha256 != null) {
                v2Fail("source anchor file digest has no authenticated per-file evidence")
            }
            locatorIndex.validate(fact, oracle.v2String("richArtifactSha256"))
            fact.semanticAnchorFields?.templatePatternAnchorCandidateId?.let { patternCandidateId ->
                val boundToReferencedPattern = fact.edges.any { edge ->
                    edge.kind in setOf(
                        FullTreeSourceIdentityEdgeKind.SPECIFICATION,
                        FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN,
                    ) && edge.target?.let { target ->
                        reconciliation.hasTemplatePatternClaim(
                            patternCandidateId,
                            target.sourceEntityId(FullTreeSourceAnchorKind.TEMPLATE_PATTERN),
                        )
                    } == true
                }
                if (!boundToReferencedPattern) {
                    v2Fail("template-pattern candidate is not bound to a referenced pattern DIE")
                }
            }
            if (fact.kind == FullTreeSourceEntityKind.TEMPLATE_INSTANCE &&
                fact.semanticAnchorFields?.templatePatternAnchorCandidateId == null &&
                (fact.identityObservability !in setOf(
                    FullTreeIdentityObservability.UNKNOWN,
                    FullTreeIdentityObservability.AMBIGUOUS,
                ) || fact.reasonCodes.none {
                    it == "unknown-template-pattern-reference" || it == "ambiguous-template-pattern-reference"
                })
            ) {
                v2Fail("missing generic-pattern relation is not preserved as unknown or ambiguous evidence")
            }
        }
        validateLegacyProjection(document, scopeDocument, scope.sha256, inventory, inventoryArtifactSha256, shard)
        val perShard = scopeDocument.v2Object("bounds").v2Object("perShard")
        val projectedEntities = Math.addExact(
            Math.addExact(counts.v2Long("emittedRvas"), counts.v2Long("nonEmitted")),
            facts.size.toLong(),
        )
        if (projectedEntities > perShard.v2Long("entities")) {
            v2Fail("observation-v2 exceeds its authenticated per-shard entity bound")
        }
        if (canonicalEnvelopeBytes(document, perShard.v2Long("serializedBytes")).size.toLong() >
            perShard.v2Long("serializedBytes")
        ) {
            v2Fail("observation-v2 exceeds its authenticated serialized-byte bound")
        }
    }

    private fun validateCollisionEvidence(
        facts: List<FullTreeSourceEntityFact>,
        reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
    ) {
        val collisionReasons = setOf("duplicate-source-anchor-unproven", "ambiguous-related-source-anchor")
        facts.forEach { fact ->
            val fields = fact.semanticAnchorFields
            val directIds = fact.semanticAnchorCandidateId
                ?.let(reconciliation.collisionIdsByCandidate::get)
                .orEmpty()
            val relatedCandidateIds = listOfNotNull(
                fields?.inlineCalleeAnchorCandidateId,
                fields?.inlineOwnerAnchorCandidateId,
                fields?.templatePatternAnchorCandidateId,
            ) + fields?.inlinePathAnchorCandidateIds.orEmpty()
            val relatedIds = relatedCandidateIds.flatMap { candidate ->
                reconciliation.collisionIdsByCandidate[candidate].orEmpty()
            }
            val expectedIds = (directIds + relatedIds).distinct().sorted()
            if (fact.candidateCollisionSourceEntityIds != expectedIds) {
                v2Fail("source anchor collision IDs do not match the authenticated full-run anchor claims")
            }
            if (directIds.isNotEmpty() && fact.sourceEntityId !in directIds) {
                v2Fail("colliding source row is not an authenticated direct anchor claimant")
            }
            if (expectedIds.isEmpty()) {
                if (fact.reasonCodes.any { it in collisionReasons }) {
                    v2Fail("source entity claims collision evidence absent from the authenticated full-run claims")
                }
            } else {
                val expectedReason = if (directIds.isNotEmpty()) {
                    "duplicate-source-anchor-unproven"
                } else {
                    "ambiguous-related-source-anchor"
                }
                if (fact.identityObservability != FullTreeIdentityObservability.AMBIGUOUS ||
                    expectedReason !in fact.reasonCodes ||
                    fact.reasonCodes.any { it in collisionReasons && it != expectedReason }
                ) {
                    v2Fail("source anchor collision is not retained as the exact ambiguous evidence")
                }
            }
        }
    }

    private fun validateDirectAnchorEvidence(
        facts: List<FullTreeSourceEntityFact>,
        reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
    ) {
        facts.forEach { fact ->
            val candidateId = fact.semanticAnchorCandidateId ?: return@forEach
            if (!reconciliation.hasAnchorClaim(candidateId, fact.sourceEntityId)) {
                v2Fail("source anchor candidate is not an authenticated direct anchor claimant for this physical DIE claim")
            }
        }
    }

    /**
     * Inline fields name other DIE anchors. Their hashes are candidates only, so the full-run
     * receipt retains a bounded typed subset proving each candidate was claimed for one of the
     * corresponding edge targets.
     */
    private fun validateInlineAnchorEvidence(
        facts: List<FullTreeSourceEntityFact>,
        reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
    ) {
        facts.forEach { fact ->
            if (fact.kind != FullTreeSourceEntityKind.INLINE_INSTANCE) return@forEach
            val fields = fact.semanticAnchorFields ?: return@forEach
            val resolvedEdges = fact.edges.filter {
                it.state == FullTreeSourceIdentityEdgeState.RESOLVED && it.target != null
            }
            val referenceEdges = resolvedEdges.filter {
                it.kind == FullTreeSourceIdentityEdgeKind.SPECIFICATION ||
                    it.kind == FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN
            }
            val ownerEdges = resolvedEdges.filter { it.kind == FullTreeSourceIdentityEdgeKind.INLINE_OWNER }

            fun hasClaim(
                candidateId: String,
                edges: List<FullTreeSourceIdentityEdge>,
                allowedKinds: List<FullTreeSourceAnchorKind>,
            ): Boolean = edges.any { edge ->
                val target = edge.target ?: return@any false
                allowedKinds.any { kind ->
                    reconciliation.hasInlineRelatedAnchorClaim(
                        candidateId,
                        target.sourceEntityId(kind),
                        kind,
                    )
                }
            }

            fields.inlineCalleeAnchorCandidateId?.let { candidate ->
                if (!hasClaim(candidate, referenceEdges, FullTreeSourceAnchorKind.entries)) {
                    v2Fail("inline callee candidate is not bound to a referenced DIE anchor claim")
                }
            }
            fields.inlineOwnerAnchorCandidateId?.let { candidate ->
                val ownerKinds = FullTreeSourceAnchorKind.entries.filter {
                    it != FullTreeSourceAnchorKind.INLINE_INSTANCE
                }
                if (!hasClaim(candidate, ownerEdges, ownerKinds)) {
                    v2Fail("inline owner candidate is not bound to a referenced DIE anchor claim")
                }
            }
            fields.inlinePathAnchorCandidateIds.orEmpty().forEach { candidate ->
                if (!hasClaim(candidate, ownerEdges, listOf(FullTreeSourceAnchorKind.INLINE_INSTANCE))) {
                    v2Fail("inline path candidate is not bound to a referenced inline DIE anchor claim")
                }
            }
        }
    }

    private fun validateLegacyProjection(
        document: JsonObject,
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        inventoryArtifactSha256: String,
        shard: FullTreeFunctionObservationShardInput,
    ) {
        val originalCounts = document.v2Object("counts")
        val legacyCounts = JsonObject(originalCounts.filterKeys {
            it in setOf("emittedRvas", "nonEmitted", "nonEmittedDies", "scannedDies", "units")
        })
        val legacyOracle = JsonObject(document.v2Object("oracle").toMutableMap().apply {
            put("configurationSha256", JsonPrimitive(FullTreeFunctionObservations.configurationSha256))
        })
        val projection = JsonObject(
            mapOf(
                "counts" to legacyCounts,
                "emitted" to document.v2Element("emitted"),
                "nonEmitted" to document.v2Element("nonEmitted"),
                "oracle" to legacyOracle,
                "schemaVersion" to JsonPrimitive(1),
                "shard" to document.v2Element("shard"),
            ),
        )
        FullTreeFunctionObservations.validateEnvelope(
            projection,
            scope,
            scopeSha256,
            inventory,
            inventoryArtifactSha256,
            shard,
        )
    }

    private class V2ArtifactLocatorIndex private constructor(
        private val allUnits: Map<String, JsonObject>,
        private val unitOffsets: List<Pair<String, ULong>>,
        private val shardUnitIds: Set<String>,
    ) {
        fun validate(fact: FullTreeSourceEntityFact, richArtifactSha256: String) {
            fun validate(die: FullTreeSourcePhysicalDie, mustBeInShard: Boolean) {
                if (die.richArtifactSha256 != richArtifactSha256) v2Fail("source DIE belongs to another artifact")
                val unit = allUnits[die.unitId] ?: v2Fail("source DIE unit is outside the authenticated inventory")
                if (parseDwarfOffset(unit.v2String("dwarfOffset"), "observation-v2 locator") !=
                    parseDwarfOffset(die.compilationUnitOffset, "observation-v2 locator")
                ) v2Fail("source DIE CU offset differs from its authenticated unit")
                if (mustBeInShard && die.unitId !in shardUnitIds) {
                    v2Fail("source entity is outside its authenticated shard")
                }
            }
            validate(fact.physicalDie, true)
            fact.edges.forEach { edge ->
                // The bounded #1466 reference graph can retain edges whose source is a traversed
                // related DIE, including a unit outside this row's shard. Authenticate every locator
                // against the complete inventory; only the census row itself is shard-local.
                validate(edge.source, false)
                edge.target?.let { validate(it, false) }
                if (edge.state == FullTreeSourceIdentityEdgeState.RESOLVED) {
                    val hasForm = edge.referenceForm != null
                    val hasRawValue = edge.rawReference != null
                    val isStructuralKind = edge.kind == FullTreeSourceIdentityEdgeKind.TYPE ||
                        edge.kind == FullTreeSourceIdentityEdgeKind.TEMPLATE_FORMAL ||
                        edge.kind == FullTreeSourceIdentityEdgeKind.TEMPLATE_ARGUMENT ||
                        edge.kind == FullTreeSourceIdentityEdgeKind.INLINE_OWNER
                    if (hasForm != hasRawValue ||
                        (!hasForm && !isStructuralKind)
                    ) {
                        v2Fail("resolved typed reference omits its form or raw offset")
                    }
                }
                if (edge.state == FullTreeSourceIdentityEdgeState.RESOLVED && edge.referenceForm != null) {
                    val target = edge.target ?: v2Fail("resolved typed reference has no target locator")
                    val form = edge.referenceForm?.removePrefix("0x")?.toULongOrNull(16)
                        ?: v2Fail("typed reference form is malformed")
                    val raw = edge.rawReference?.removePrefix("0x")?.toULongOrNull(16)
                        ?: v2Fail("typed reference raw value is malformed")
                    val maximumRawValue = fullTreeDwarfReferenceFormMaximumRawValue(form)
                    if (maximumRawValue != null && raw > maximumRawValue) {
                        v2Fail("typed reference raw value exceeds its fixed-width DWARF form")
                    }
                    val sourceCu = edge.source.compilationUnitOffset.removePrefix("0x").toULong(16)
                    val targetOffset = target.dieOffset.removePrefix("0x").toULong(16)
                    when (form) {
                        FULL_TREE_DW_FORM_REF1.toULong(),
                        FULL_TREE_DW_FORM_REF2.toULong(),
                        FULL_TREE_DW_FORM_REF4.toULong(),
                        FULL_TREE_DW_FORM_REF8.toULong(),
                        FULL_TREE_DW_FORM_REF_UDATA.toULong(),
                        -> {
                            if (raw > ULong.MAX_VALUE - sourceCu || target.unitId != edge.source.unitId ||
                                targetOffset != sourceCu + raw
                            ) {
                                v2Fail("compilation-unit reference target differs from its raw offset")
                            }
                        }
                        FULL_TREE_DW_FORM_REF_ADDR.toULong() -> {
                            val expectedUnit = unitAtOrBefore(raw)
                            if (targetOffset != raw || target.unitId != expectedUnit) {
                                v2Fail(".debug_info reference target differs from its raw absolute offset")
                            }
                        }
                        else -> v2Fail("resolved typed reference uses an unsupported DWARF reference form")
                    }
                }
            }
            // This checks that the supplied edge graph is internally rooted at its census DIE.
            // The run publisher re-executes source extraction against the authenticated artifact
            // to verify every structural and typed edge against raw DWARF ancestry and references.
            val edgesBySource = fact.edges.groupBy { it.source }
            val reachable = HashSet<FullTreeSourcePhysicalDie>()
            val pending = ArrayDeque<FullTreeSourcePhysicalDie>()
            reachable += fact.physicalDie
            pending.addLast(fact.physicalDie)
            while (pending.isNotEmpty()) {
                val source = pending.removeFirst()
                edgesBySource[source].orEmpty().forEach { edge ->
                    if (edge.state == FullTreeSourceIdentityEdgeState.RESOLVED) {
                        val target = edge.target ?: v2Fail("resolved typed reference has no target locator")
                        if (reachable.add(target)) pending.addLast(target)
                    }
                }
            }
            if (fact.edges.any { it.source !in reachable }) {
                v2Fail("source-identity edge graph is detached from its source entity DIE")
            }
        }

        private fun unitAtOrBefore(offset: ULong): String? {
            var lower = 0
            var upper = unitOffsets.size
            while (lower < upper) {
                val middle = (lower + upper) ushr 1
                if (unitOffsets[middle].second <= offset) lower = middle + 1 else upper = middle
            }
            if (lower == 0) return null
            val selectedOffset = unitOffsets[lower - 1].second
            var firstEqualLower = 0
            var firstEqualUpper = lower
            while (firstEqualLower < firstEqualUpper) {
                val middle = (firstEqualLower + firstEqualUpper) ushr 1
                if (unitOffsets[middle].second < selectedOffset) firstEqualLower = middle + 1
                else firstEqualUpper = middle
            }
            return unitOffsets[firstEqualLower].first
        }

        companion object {
            fun create(inventory: JsonObject, shard: FullTreeFunctionObservationShardInput): V2ArtifactLocatorIndex {
                val units = inventory.v2Array("units").map { it as JsonObject }
                val allUnits = units.associateBy { it.v2String("id") }
                val unitOffsets = units.map { unit ->
                    unit.v2String("id") to parseDwarfOffset(
                        unit.v2String("dwarfOffset"),
                        "observation-v2 locator",
                    ).toULong()
                }.sortedBy { it.second }
                return V2ArtifactLocatorIndex(
                    allUnits = allUnits,
                    unitOffsets = unitOffsets,
                    shardUnitIds = shard.units.map { it.v2String("id") }.toSet(),
                )
            }
        }
    }

    private fun countKinds(facts: List<FullTreeSourceEntityFact>): JsonObject = countObject(
        FullTreeSourceEntityKind.entries.map { it.wireValue to facts.count { fact -> fact.kind == it }.toLong() },
    )

    private fun countObservability(facts: List<FullTreeSourceEntityFact>): JsonObject = countObject(
        FullTreeIdentityObservability.entries.map { state ->
            state.wireValue to facts.count { it.identityObservability == state }.toLong()
        },
    )

    private fun countDisposition(facts: List<FullTreeSourceEntityFact>): JsonObject = countObject(
        FullTreeDenominatorDisposition.entries.map { disposition ->
            disposition.wireValue to facts.count { it.denominatorDisposition == disposition }.toLong()
        },
    )

    private fun countObject(values: List<Pair<String, Long>>): JsonObject = JsonObject(
        values.sortedBy { it.first }.associate { (key, value) -> key to JsonPrimitive(value) },
    )
}

private fun sourceIdentityJsonCodePointLength(value: String): Int = value.codePointCount(0, value.length)

internal fun fullTreeDwarfReferenceFormMaximumRawValue(form: ULong): ULong? = when (form) {
    FULL_TREE_DW_FORM_REF1.toULong() -> 0xffuL
    FULL_TREE_DW_FORM_REF2.toULong() -> 0xffffuL
    FULL_TREE_DW_FORM_REF4.toULong() -> 0xffff_ffffuL
    else -> null
}

internal const val MAXIMUM_SOURCE_IDENTITY_DESCRIPTOR_CHARACTERS = 16_384
private const val MAXIMUM_SOURCE_IDENTITY_LEXICAL_CONTEXT_ITEMS = 256
private const val MAXIMUM_SOURCE_IDENTITY_SIGNATURE_ITEMS = 1_025

/** Full-run, bounded anchor population, including ordinary source definitions omitted from census rows. */
internal class FullTreeFunctionObservationV2AnchorIndex(
    private val maximumClaims: Long,
    private val maximumRetainedBytes: Long,
) {
    private val claims = TreeMap<String, TreeSet<String>>(FULL_TREE_CODE_POINT_ORDER)
    private val templatePatternClaims = HashSet<Pair<String, String>>()
    private val inlineRelatedClaims = HashSet<FullTreeFunctionObservationV2TypedAnchorClaim>()
    private val sourceEntityPopulations = TreeMap<String, FullTreeFunctionObservationV2SourceEntityPopulationClaim>(
        FULL_TREE_CODE_POINT_ORDER,
    )
    private var claimCount = 0L
    private var retainedBytes = 0L
    private var frozenReconciliation: FullTreeFunctionObservationV2IdentityReconciliation? = null

    init {
        require(maximumClaims > 0L && maximumRetainedBytes > 0L)
    }

    fun accept(candidateId: String, physicalClaimId: String) = accept(null, candidateId, physicalClaimId)

    fun accept(kind: FullTreeSourceAnchorKind?, candidateId: String, physicalClaimId: String) {
        if (frozenReconciliation != null) v2Fail("full-run anchor claims are already reconciled")
        if (!V2_SHA256.matches(candidateId) || !V2_SHA256.matches(physicalClaimId)) {
            v2Fail("full-run anchor claim is malformed")
        }
        val prior = claims[candidateId]
        val claimExists = prior?.contains(physicalClaimId) == true
        val patternClaim = kind == FullTreeSourceAnchorKind.TEMPLATE_PATTERN
        val patternClaimExists = !patternClaim || (candidateId to physicalClaimId) in templatePatternClaims
        if (claimExists && patternClaimExists) return
        val claimCharge = if (claimExists) 0L else 64L + candidateId.length + physicalClaimId.length + 96L
        val patternClaimCharge = if (patternClaim && !patternClaimExists) TEMPLATE_PATTERN_CLAIM_INDEX_BYTES else 0L
        val charge = Math.addExact(claimCharge, patternClaimCharge)
        val nextCount = if (claimExists) claimCount else Math.addExact(claimCount, 1L)
        val nextBytes = Math.addExact(retainedBytes, charge)
        if (nextCount > maximumClaims || nextBytes > maximumRetainedBytes) {
            v2Fail("full-run anchor claim population exceeds its authenticated working-set bound")
        }
        // Admission precedes any new key, set, or ID insertion.
        retainedBytes = nextBytes
        claimCount = nextCount
        if (!claimExists) claims.getOrPut(candidateId) { TreeSet(FULL_TREE_CODE_POINT_ORDER) }.add(physicalClaimId)
        if (patternClaim && !patternClaimExists) templatePatternClaims.add(candidateId to physicalClaimId)
    }

    /** Retain only typed anchor claims actually named by this scanner-owned inline fact. */
    fun acceptInlineRelatedClaims(fact: FullTreeSourceEntityFact) {
        if (frozenReconciliation != null) v2Fail("full-run anchor claims are already reconciled")
        if (fact.kind != FullTreeSourceEntityKind.INLINE_INSTANCE) return
        val fields = fact.semanticAnchorFields ?: return
        val resolvedEdges = fact.edges.filter {
            it.state == FullTreeSourceIdentityEdgeState.RESOLVED && it.target != null
        }
        val referenceEdges = resolvedEdges.filter {
            it.kind == FullTreeSourceIdentityEdgeKind.SPECIFICATION ||
                it.kind == FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN
        }
        val ownerEdges = resolvedEdges.filter { it.kind == FullTreeSourceIdentityEdgeKind.INLINE_OWNER }

        fun acceptReferencedClaim(
            candidateId: String,
            edges: List<FullTreeSourceIdentityEdge>,
            allowedKinds: List<FullTreeSourceAnchorKind>,
            label: String,
        ) {
            val matching = edges.flatMap { edge ->
                val target = edge.target ?: return@flatMap emptyList()
                allowedKinds.mapNotNull { kind ->
                    val physicalClaimId = target.sourceEntityId(kind)
                    if (claims[candidateId]?.contains(physicalClaimId) == true) {
                        FullTreeFunctionObservationV2TypedAnchorClaim(candidateId, physicalClaimId, kind)
                    } else {
                        null
                    }
                }
            }.toSet()
            if (matching.isEmpty()) {
                v2Fail("inline $label candidate is not backed by a typed claim on a referenced DIE")
            }
            matching.forEach { claim ->
                if (inlineRelatedClaims.add(claim)) {
                    val nextBytes = Math.addExact(retainedBytes, INLINE_RELATED_CLAIM_INDEX_BYTES)
                    if (nextBytes > maximumRetainedBytes) {
                        inlineRelatedClaims.remove(claim)
                        v2Fail("inline anchor claim subset exceeds its authenticated working-set bound")
                    }
                    retainedBytes = nextBytes
                }
            }
        }

        fields.inlineCalleeAnchorCandidateId?.let {
            acceptReferencedClaim(it, referenceEdges, FullTreeSourceAnchorKind.entries, "callee")
        }
        fields.inlineOwnerAnchorCandidateId?.let {
            acceptReferencedClaim(
                it,
                ownerEdges,
                FullTreeSourceAnchorKind.entries.filter { kind -> kind != FullTreeSourceAnchorKind.INLINE_INSTANCE },
                "owner",
            )
        }
        fields.inlinePathAnchorCandidateIds.orEmpty().forEach {
            acceptReferencedClaim(
                it,
                ownerEdges,
                listOf(FullTreeSourceAnchorKind.INLINE_INSTANCE),
                "path",
            )
        }
    }

    /** Bind each shard's exact extracted physical census without retaining a second row-ID map. */
    fun acceptSourceEntityPopulation(
        shardId: String,
        facts: List<FullTreeSourceEntityFact>,
        checkpoint: (String) -> Unit = {},
    ) {
        if (frozenReconciliation != null) v2Fail("full-run anchor claims are already reconciled")
        if (shardId.isBlank() || shardId in sourceEntityPopulations) {
            v2Fail("full-run source-entity population shard is malformed or duplicated")
        }
        val nextBytes = Math.addExact(retainedBytes, SOURCE_ENTITY_POPULATION_CLAIM_BYTES)
        if (nextBytes > maximumRetainedBytes) {
            v2Fail("full-run source-entity population proofs exceed their authenticated working-set bound")
        }
        val claim = sourceEntityPopulationClaim(facts, checkpoint)
        retainedBytes = nextBytes
        sourceEntityPopulations[shardId] = claim
    }

    fun reconciliation(
        checkpoint: (String) -> Unit = {},
    ): FullTreeFunctionObservationV2IdentityReconciliation {
        frozenReconciliation?.let { return it }
        checkpoint("before full-run anchor population hashing")
        val digest = MessageDigest.getInstance("SHA-256")
        var populationBytes = 3L
        fun update(value: String) = digest.update(value.toByteArray(StandardCharsets.UTF_8))
        if (claimCount == 0L) {
            update("[]\n")
        } else {
            update("[\n")
            var row = 0L
            claims.forEach { (candidate, ids) -> ids.forEach { id ->
                if (row % FULL_RUN_RECONCILIATION_CHECKPOINT_INTERVAL == 0L) {
                    checkpoint("while hashing full-run anchor claims")
                }
                if (row++ > 0L) update(",\n")
                update("  {\n    \"candidateId\": ")
                val candidateBytes = OracleJson.canonicalBytes(JsonPrimitive(candidate))
                digest.update(candidateBytes, 0, candidateBytes.size - 1)
                update(",\n    \"physicalClaimId\": ")
                val idBytes = OracleJson.canonicalBytes(JsonPrimitive(id))
                digest.update(idBytes, 0, idBytes.size - 1)
                update("\n  }")
                populationBytes = Math.addExact(populationBytes, 128L + candidateBytes.size + idBytes.size)
            } }
            update("\n]\n")
        }
        checkpoint("after hashing full-run anchor claims")
        if (populationBytes > maximumRetainedBytes) {
            v2Fail("full-run anchor population digest exceeds its bounded canonical-byte budget")
        }
        var reportCharge = 0L
        var collisionCount = 0L
        var candidateIndex = 0L
        claims.forEach { (candidate, ids) ->
            if (candidateIndex++ % FULL_RUN_RECONCILIATION_CHECKPOINT_INTERVAL == 0L) {
                checkpoint("while sizing the full-run collision report")
            }
            if (ids.size > 1) {
                collisionCount = Math.addExact(collisionCount, 1L)
                reportCharge = Math.addExact(reportCharge, 64L + candidate.length + ids.size.toLong() * 8L)
            }
        }
        if (Math.addExact(retainedBytes, reportCharge) > maximumRetainedBytes) {
            v2Fail("full-run collision report exceeds its bounded retained-working-set budget")
        }
        retainedBytes = Math.addExact(retainedBytes, reportCharge)
        val immutableCollisions = LinkedHashMap<String, List<String>>()
        var copiedIds = 0L
        claims.forEach { (candidate, ids) ->
            if (ids.size > 1) {
                val retainedIds = ArrayList<String>(ids.size)
                ids.forEach { id ->
                    if (copiedIds++ % FULL_RUN_RECONCILIATION_CHECKPOINT_INTERVAL == 0L) {
                        checkpoint("while materializing full-run collision IDs")
                    }
                    retainedIds += id
                }
                immutableCollisions[candidate] = Collections.unmodifiableList(retainedIds)
            }
        }
        checkpoint("after materializing the full-run collision report")
        val result = FullTreeFunctionObservationV2IdentityReconciliation(
            populationSha256 = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) },
            claimCount = claimCount,
            candidateCount = claims.size.toLong(),
            collisionCandidateCount = collisionCount,
            collisionIdsByCandidate = Collections.unmodifiableMap(immutableCollisions),
        )
        // Bounded typed subsets let envelope validation bind pattern and inline candidates to
        // referenced DIEs without retaining the full claim index in the returned receipt.
        result.bindTemplatePatternClaims(Collections.unmodifiableSet(templatePatternClaims))
        result.bindInlineRelatedClaims(Collections.unmodifiableSet(inlineRelatedClaims))
        result.bindSourceEntityPopulations(Collections.unmodifiableMap(sourceEntityPopulations))
        result.bindAnchorClaims(Collections.unmodifiableMap(claims))
        frozenReconciliation = result
        return result
    }
}

private val V2_SHA256 = Regex("[0-9a-f]{64}")

internal data class FullTreeFunctionObservationV2TypedAnchorClaim(
    val candidateId: String,
    val physicalClaimId: String,
    val kind: FullTreeSourceAnchorKind,
)

internal data class FullTreeFunctionObservationV2SourceEntityPopulationClaim(
    val sourceEntityCount: Long,
    val populationSha256: String,
)

internal data class FullTreeFunctionObservationV2IdentityReconciliation(
    val populationSha256: String,
    val claimCount: Long,
    val candidateCount: Long,
    val collisionCandidateCount: Long,
    val collisionIdsByCandidate: Map<String, List<String>>,
) {
    private var templatePatternClaims: Set<Pair<String, String>> = emptySet()
    private var inlineRelatedClaims: Set<FullTreeFunctionObservationV2TypedAnchorClaim> = emptySet()
    private var sourceEntityPopulations: Map<String, FullTreeFunctionObservationV2SourceEntityPopulationClaim> = emptyMap()
    private var anchorClaims: Map<String, out Set<String>> = emptyMap()

    init {
        require(populationSha256.matches(Regex("[0-9a-f]{64}")))
        require(claimCount >= 0L && candidateCount >= 0L && collisionCandidateCount >= 0L)
        require(candidateCount <= claimCount && collisionCandidateCount <= candidateCount)
    }

    fun canonicalJson(): JsonObject = JsonObject(
        mapOf(
            "algorithm" to JsonPrimitive("full-run-anchor-claims-v1"),
            "populationSha256" to JsonPrimitive(populationSha256),
            "claimCount" to JsonPrimitive(claimCount),
            "candidateCount" to JsonPrimitive(candidateCount),
            "collisionCandidateCount" to JsonPrimitive(collisionCandidateCount),
        ),
    )

    internal fun hasTemplatePatternClaim(candidateId: String, physicalClaimId: String): Boolean =
        (candidateId to physicalClaimId) in templatePatternClaims

    internal fun bindTemplatePatternClaims(claims: Set<Pair<String, String>>) {
        check(templatePatternClaims.isEmpty())
        templatePatternClaims = claims
    }

    internal fun hasInlineRelatedAnchorClaim(
        candidateId: String,
        physicalClaimId: String,
        kind: FullTreeSourceAnchorKind,
    ): Boolean = FullTreeFunctionObservationV2TypedAnchorClaim(candidateId, physicalClaimId, kind) in inlineRelatedClaims

    internal fun bindInlineRelatedClaims(claims: Set<FullTreeFunctionObservationV2TypedAnchorClaim>) {
        check(inlineRelatedClaims.isEmpty())
        inlineRelatedClaims = claims
    }

    internal fun bindSourceEntityPopulations(
        populations: Map<String, FullTreeFunctionObservationV2SourceEntityPopulationClaim>,
    ) {
        check(sourceEntityPopulations.isEmpty())
        sourceEntityPopulations = populations
    }

    internal fun bindAnchorClaims(claims: Map<String, out Set<String>>) {
        check(anchorClaims.isEmpty())
        anchorClaims = claims
    }

    internal fun hasAnchorClaim(candidateId: String, physicalClaimId: String): Boolean =
        anchorClaims[candidateId]?.contains(physicalClaimId) == true

    internal fun validateSourceEntityPopulation(
        shardId: String,
        facts: List<FullTreeSourceEntityFact>,
        checkpoint: (String) -> Unit = {},
    ) {
        val expected = sourceEntityPopulations[shardId]
            ?: v2Fail("source-entity physical DIE population has no authenticated scan receipt")
        if (sourceEntityPopulationClaim(facts, checkpoint) != expected) {
            v2Fail("source-entity physical DIE locators differ from the authenticated scan receipt")
        }
    }
}

private const val TEMPLATE_PATTERN_CLAIM_INDEX_BYTES = 96L
private const val INLINE_RELATED_CLAIM_INDEX_BYTES = 96L
private const val SOURCE_ENTITY_POPULATION_CLAIM_BYTES = 128L
private const val FULL_RUN_RECONCILIATION_CHECKPOINT_INTERVAL = 4_096L

private fun sourceEntityPopulationClaim(
    facts: List<FullTreeSourceEntityFact>,
    checkpoint: (String) -> Unit = {},
): FullTreeFunctionObservationV2SourceEntityPopulationClaim {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update("full-run-observation-v2-source-entities-v1\n".toByteArray(StandardCharsets.US_ASCII))
    facts.forEachIndexed { index, fact ->
        if (index.toLong() % FULL_RUN_RECONCILIATION_CHECKPOINT_INTERVAL == 0L) {
            checkpoint("while hashing authenticated source-entity physical locators")
        }
        digest.update(fact.sourceEntityId.toByteArray(StandardCharsets.US_ASCII))
        digest.update('\n'.code.toByte())
    }
    return FullTreeFunctionObservationV2SourceEntityPopulationClaim(
        sourceEntityCount = facts.size.toLong(),
        populationSha256 = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) },
    )
}

internal fun reconcileObservationV2Facts(
    facts: List<FullTreeSourceEntityFact>,
    reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
    checkpoint: ((String) -> Unit)? = null,
): List<FullTreeSourceEntityFact> {
    val normalized = facts.mapIndexed { index, fact ->
        if (index.toLong() % FULL_RUN_RECONCILIATION_CHECKPOINT_INTERVAL == 0L) {
            checkpoint?.invoke("while normalizing shard source-anchor collision evidence")
        }
        observationV2CollisionNeutralFact(fact)
    }
    return FullTreeSourceEntityIdentityProducer.markUnprovedAnchorCollisions(
        FullTreeSourceEntityFact.deterministicOrder(normalized, checkpoint),
        SourceIdentityAnchorCollisionReport(reconciliation.collisionIdsByCandidate),
        checkpoint,
    )
}

/** Preflight the exact collision-neutral array before accounting for the full-run additions. */
internal fun observationV2CollisionNeutralSourceEntityFactsByteLength(
    facts: List<FullTreeSourceEntityFact>,
    maximumCanonicalBytes: Long,
    checkpoint: ((String) -> Unit)? = null,
): Long {
    require(maximumCanonicalBytes in 1L..MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES)
    if (facts.isEmpty()) {
        if (3L > maximumCanonicalBytes) v2Fail("canonical source-identity output exceeds its authenticated byte bound")
        return 3L
    }
    var size = 4L
    facts.forEachIndexed { index, fact ->
        if (index.toLong() % FULL_RUN_RECONCILIATION_CHECKPOINT_INTERVAL == 0L) {
            checkpoint?.invoke("while preflighting collision-neutral source entities")
        }
        val neutral = observationV2CollisionNeutralFact(fact)
        val bytes = OracleJson.canonicalBytes(
            neutral.canonicalJson(),
            sourceIdentityRowJsonLimits(maximumCanonicalBytes),
        )
        val lineBreaks = bytes.count { it == '\n'.code.toByte() }
        check(lineBreaks > 0) { "canonical source-identity row has no final newline" }
        size = Math.addExact(size, bytes.size.toLong() - 1L)
        size = Math.addExact(size, 2L)
        size = Math.addExact(size, Math.multiplyExact((lineBreaks - 1).toLong(), 2L))
        size = Math.addExact(size, 1L)
        if (index != facts.lastIndex) size = Math.addExact(size, 1L)
        if (size > maximumCanonicalBytes) {
            v2Fail("collision-neutral source-entity output exceeds its authenticated byte bound")
        }
    }
    return size
}

private fun observationV2CollisionNeutralFact(fact: FullTreeSourceEntityFact): FullTreeSourceEntityFact {
    val collisionReasons = setOf("duplicate-source-anchor-unproven", "ambiguous-related-source-anchor")
    val retainedReasons = fact.reasonCodes.filterNot { it in collisionReasons }
    if (retainedReasons == fact.reasonCodes && fact.candidateCollisionSourceEntityIds.isEmpty()) return fact
    return fact.copy(
        identityObservability = observationV2BaseObservability(fact, retainedReasons),
        candidateCollisionSourceEntityIds = emptyList(),
        reasonCodes = retainedReasons,
    )
}

/** Bounds the temporary neutralized row list retained while full-run collisions are reapplied. */
internal fun observationV2CollisionNeutralFactCopyUpperBound(
    facts: List<FullTreeSourceEntityFact>,
    maximumCanonicalBytes: Long,
    checkpoint: ((String) -> Unit)? = null,
): Long {
    var total = Math.addExact(64L, Math.multiplyExact(facts.size.toLong(), 8L))
    facts.forEachIndexed { index, fact ->
        if (index.toLong() % FULL_RUN_RECONCILIATION_CHECKPOINT_INTERVAL == 0L) {
            checkpoint?.invoke("while sizing collision-neutral source entity copies")
        }
        val neutral = observationV2CollisionNeutralFact(fact)
        if (neutral !== fact) {
            val rowBytes = canonicalSourceEntityFactsByteLength(listOf(fact), maximumCanonicalBytes, checkpoint)
            total = Math.addExact(
                total,
                Math.addExact(rowBytes, SOURCE_IDENTITY_RETAINED_CHARGE_OVERHEAD_BYTES),
            )
        }
    }
    return total
}

private fun observationV2BaseObservability(
    fact: FullTreeSourceEntityFact,
    reasonCodes: List<String>,
): FullTreeIdentityObservability {
    val ambiguousEdges = fact.edges.any { it.state == FullTreeSourceIdentityEdgeState.CYCLIC }
    val unknownEdges = fact.edges.any {
        it.state == FullTreeSourceIdentityEdgeState.MISSING_TARGET ||
            it.state == FullTreeSourceIdentityEdgeState.MALFORMED ||
            it.state == FullTreeSourceIdentityEdgeState.UNSUPPORTED
    }
    return when {
        reasonCodes.any { it.startsWith("ambiguous-") } || ambiguousEdges -> FullTreeIdentityObservability.AMBIGUOUS
        fact.kind == FullTreeSourceEntityKind.DECLARATION_ONLY ||
            "declaration-only-no-definition" in reasonCodes -> FullTreeIdentityObservability.UNOBSERVABLE
        reasonCodes.any { it.startsWith("unknown-") } || unknownEdges -> FullTreeIdentityObservability.UNKNOWN
        fact.semanticAnchorCandidateId != null -> FullTreeIdentityObservability.OBSERVABLE
        else -> FullTreeIdentityObservability.UNKNOWN
    }
}

private fun JsonObject.v2Element(name: String): JsonElement = get(name) ?: v2Fail("missing field $name")
private fun JsonObject.v2Object(name: String): JsonObject = v2Element(name) as? JsonObject ?: v2Fail("$name is not an object")
private fun JsonObject.v2Array(name: String): List<JsonElement> = (v2Element(name) as? JsonArray)?.toList() ?: v2Fail("$name is not an array")
private fun JsonObject.v2String(name: String): String = (get(name) as? JsonPrimitive)?.takeIf { it.isString }?.content ?: v2Fail("$name is not a string")
private fun JsonObject.v2Long(name: String): Long = (get(name) as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull ?: v2Fail("$name is not an integer")
private fun v2Fail(message: String): Nothing = throw FullTreeFunctionObservationV2Exception(message)
