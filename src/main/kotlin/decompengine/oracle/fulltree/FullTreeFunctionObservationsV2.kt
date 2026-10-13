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
        checkpoint: (String) -> Unit = {},
    ): JsonObject {
        require(maximumBytes in 1L..16L * 1024L * 1024L * 1024L)
        val facts = FullTreeSourceEntityFact.deterministicOrder(sourceFacts, checkpoint)
        facts.forEachIndexed { index, fact ->
            if (index % 4_096 == 0) checkpoint("while validating source facts for envelope composition")
            validateSourceEntityForV2(fact, checkpoint)
        }
        reconciliation.validateSourceEntityPopulation(v1.v2Object("shard").v2String("id"), facts, checkpoint)
        validateDirectAnchorEvidence(facts, reconciliation, checkpoint)
        validateInlineAnchorEvidence(facts, reconciliation, checkpoint)
        validateCollisionEvidence(facts, reconciliation, checkpoint)
        val sourceIds = HashSet<String>()
        val physicalDies = HashSet<FullTreeSourcePhysicalDie>()
        facts.forEachIndexed { index, fact ->
            if (index % 4_096 == 0) checkpoint("while checking source-fact uniqueness")
            if (!sourceIds.add(fact.sourceEntityId)) v2Fail("observation-v2 sourceEntityIds are not unique")
            if (!physicalDies.add(fact.physicalDie)) v2Fail("observation-v2 physical DIE locators are not unique")
        }
        val baseCounts = v1.v2Object("counts")
        val counts = JsonObject(
            baseCounts.toMutableMap().apply {
                put("sourceEntities", JsonPrimitive(facts.size))
                put("sourceEntitiesByKind", countKinds(facts, checkpoint))
                put("sourceEntitiesByObservability", countObservability(facts, checkpoint))
                put("sourceEntitiesByDenominatorDisposition", countDisposition(facts, checkpoint))
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
                put("sourceEntities", JsonArray(facts.mapIndexed { index, fact ->
                    if (index % 4_096 == 0) checkpoint("while serializing source facts for envelope composition")
                    fact.canonicalJson(checkpoint)
                }))
                put("identityReconciliation", reconciliation.canonicalJson())
            },
        )
        val bytes = canonicalEnvelopeBytes(result, maximumBytes, checkpoint)
        if (bytes.size.toLong() > maximumBytes) v2Fail("observation-v2 exceeds its authenticated byte bound")
        return result
    }

    /** Keep producer and both sinks within the exact per-string bounds in the v2 schema. */
    fun validateSourceEntityForV2(
        fact: FullTreeSourceEntityFact,
        checkpoint: (String) -> Unit = {},
    ) {
        val fields = fact.semanticAnchorFields ?: return
        checkpoint("before validating source-entity descriptors")
        if (fields.sourcePath?.let(::sourceIdentityJsonCodePointLength)?.let { it > 4_096 } == true) {
            v2Fail("source path exceeds the observation-v2 schema character bound")
        }
        listOfNotNull(fields.sourceName, fields.authenticatedSourceRevision, fields.inlineCallFile)
            .forEachIndexed { index, value ->
                if (index % 64 == 0) checkpoint("while validating source-entity descriptors")
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
        descriptors.forEachIndexed { index, descriptor ->
            if (index % 64 == 0) checkpoint("while validating source-identity descriptor lists")
            if (sourceIdentityJsonCodePointLength(descriptor) > MAXIMUM_SOURCE_IDENTITY_DESCRIPTOR_CHARACTERS) {
                v2Fail("completed source-identity descriptor exceeds the observation-v2 schema character bound")
            }
        }
        if (fields.lexicalContext.size > MAXIMUM_SOURCE_IDENTITY_LEXICAL_CONTEXT_ITEMS ||
            (fields.signature?.size ?: 0) > MAXIMUM_SOURCE_IDENTITY_SIGNATURE_ITEMS ||
            (fields.templateFormalParameters?.size ?: 0) > MAXIMUM_SOURCE_IDENTITY_SIGNATURE_ITEMS ||
            (fields.templateActualArguments?.size ?: 0) > MAXIMUM_SOURCE_IDENTITY_SIGNATURE_ITEMS
        ) {
            v2Fail("source-identity descriptor list exceeds the observation-v2 schema item bound")
        }
        checkpoint("after validating source-entity descriptors")
    }

    /** Enforce that every claimed denominator link names an emitted row from this shard. */
    internal fun validateSourceEntityEmittedRvaLink(
        fact: FullTreeSourceEntityFact,
        containsEmittedRva: (String) -> Boolean,
    ) {
        val linkedRva = fact.linkedEmittedRva
        val isLinked = fact.denominatorDisposition == FullTreeDenominatorDisposition.EMITTED_RVA_LINK
        if (isLinked != (linkedRva != null)) {
            v2Fail("source entity emitted-RVA link and denominator disposition differ")
        }
        if (linkedRva != null && !containsEmittedRva(linkedRva)) {
            v2Fail("source entity links to an absent emitted RVA")
        }
    }

    fun canonicalEnvelopeBytes(
        document: JsonObject,
        maximumBytes: Long = MAXIMUM_CANONICAL_BYTES,
        checkpoint: (String) -> Unit = {},
    ): ByteArray = try {
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
            checkpoint,
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
            checkpoint("before validating observation-v2 JSON schema")
            OracleSchemas.validate(SCHEMA_NAME, document)
            checkpoint("after validating observation-v2 JSON schema")
        } catch (failure: Exception) {
            throw FullTreeFunctionObservationV2Exception("function observation-v2 schema validation failed", failure)
        }
        val counts = document.v2Object("counts")
        val sourceRows = document.v2Array("sourceEntities")
        val facts = ArrayList<FullTreeSourceEntityFact>(sourceRows.size)
        sourceRows.forEachIndexed { index, element ->
            if (index % 4_096 == 0) checkpoint("while decoding observation-v2 source entities")
            val row = element as? JsonObject ?: v2Fail("source entity $index is not an object")
            try {
                facts += FullTreeSourceEntityFact.fromCanonicalJson(row, "source entity $index", checkpoint)
            } catch (failure: FullTreeFunctionObservationV2Exception) {
                throw failure
            } catch (failure: Exception) {
                throw FullTreeFunctionObservationV2Exception("source entity $index is invalid", failure)
            }
        }
        val ids = HashSet<String>()
        facts.forEachIndexed { index, fact ->
            if (index % 4_096 == 0) checkpoint("while checking observation-v2 source entity IDs")
            if (!ids.add(fact.sourceEntityId)) v2Fail("duplicate sourceEntityId")
        }
        val physicalDies = HashSet<FullTreeSourcePhysicalDie>()
        facts.forEachIndexed { index, fact ->
            if (index % 4_096 == 0) checkpoint("while checking observation-v2 physical DIE locators")
            if (!physicalDies.add(fact.physicalDie)) v2Fail("duplicate physical DIE locator")
        }
        val orderedFacts = FullTreeSourceEntityFact.deterministicOrder(facts, checkpoint)
        if (facts.indices.any { index ->
                if (index % 4_096 == 0) checkpoint("while checking observation-v2 source ordering")
                facts[index] !== orderedFacts[index]
            }
        ) {
            v2Fail("observation-v2 source entities are not canonically ordered")
        }
        reconciliation.validateSourceEntityPopulation(
            shard.identifier,
            facts,
            checkpoint,
            scopeDocument.v2Object("bounds").v2Object("perShard").v2Long("serializedBytes"),
        )
        validateDirectAnchorEvidence(facts, reconciliation, checkpoint)
        validateInlineAnchorEvidence(facts, reconciliation, checkpoint)
        validateCollisionEvidence(facts, reconciliation, checkpoint)
        if (counts.v2Long("sourceEntities") != facts.size.toLong() ||
            counts.v2Object("sourceEntitiesByKind") != countKinds(facts, checkpoint) ||
            counts.v2Object("sourceEntitiesByObservability") != countObservability(facts, checkpoint) ||
            counts.v2Object("sourceEntitiesByDenominatorDisposition") != countDisposition(facts, checkpoint)
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
        val emittedRows = document.v2Array("emitted")
        val emittedRvas = HashSet<String>()
        emittedRows.forEachIndexed { index, row ->
            if (index % 4_096 == 0) checkpoint("while indexing observation-v2 emitted RVAs")
            if (!emittedRvas.add((row as JsonObject).v2String("rva"))) {
                v2Fail("observation-v2 emitted RVA population contains duplicates")
            }
        }
        if (emittedRvas.size != emittedRows.size) {
            v2Fail("observation-v2 emitted RVA population contains duplicates")
        }
        val locatorIndex = V2ArtifactLocatorIndex.create(inventory, shard, checkpoint)
        facts.forEachIndexed { index, fact ->
            if (index % 4_096 == 0) checkpoint("while validating observation-v2 source entities")
            validateSourceEntityForV2(fact, checkpoint)
            validateSourceEntityEmittedRvaLink(fact, emittedRvas::contains)
            val sourceRevision = fact.semanticAnchorFields?.authenticatedSourceRevision
            val authenticatedRevision = scope.sourceLock.v2Object("revision").v2String("commit")
            if (fact.semanticAnchorFields != null && sourceRevision != authenticatedRevision) {
                v2Fail("source anchor revision is absent or differs from the authenticated source lock")
            }
            if (fact.semanticAnchorFields?.authenticatedSourceFileSha256 != null) {
                v2Fail("source anchor file digest has no authenticated per-file evidence")
            }
            locatorIndex.validate(fact, oracle.v2String("richArtifactSha256"), checkpoint)
            fact.semanticAnchorFields?.templatePatternAnchorCandidateId?.let { patternCandidateId ->
                var boundToReferencedPattern = false
                fact.edges.forEachIndexed { edgeIndex, edge ->
                    if (edgeIndex % 16 == 0) checkpoint("while binding source pattern candidates to typed edges")
                    if (!boundToReferencedPattern && edge.kind in setOf(
                        FullTreeSourceIdentityEdgeKind.SPECIFICATION,
                        FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN,
                    ) && edge.target?.let { target ->
                        reconciliation.hasTemplatePatternClaim(
                            patternCandidateId,
                            target.sourceEntityId(FullTreeSourceAnchorKind.TEMPLATE_PATTERN),
                        )
                    } == true
                    ) boundToReferencedPattern = true
                }
                if (!boundToReferencedPattern) {
                    v2Fail("template-pattern candidate is not bound to a referenced pattern DIE")
                }
            }
            if (fact.kind == FullTreeSourceEntityKind.TEMPLATE_INSTANCE &&
                fact.semanticAnchorFields?.templatePatternAnchorCandidateId == null &&
                ((fact.identityObservability !in setOf(
                    FullTreeIdentityObservability.UNKNOWN,
                    FullTreeIdentityObservability.AMBIGUOUS,
                ) && !(fact.identityObservability == FullTreeIdentityObservability.UNOBSERVABLE &&
                    "declaration-only-no-definition" in fact.reasonCodes)) || fact.reasonCodes.none {
                    it == "unknown-template-pattern-reference" || it == "ambiguous-template-pattern-reference"
                })
            ) {
                v2Fail("missing generic-pattern relation is not preserved as unknown or ambiguous evidence")
            }
        }
        validateLegacyProjection(
            document,
            scopeDocument,
            scope.sha256,
            inventory,
            inventoryArtifactSha256,
            shard,
            checkpoint,
        )
        val perShard = scopeDocument.v2Object("bounds").v2Object("perShard")
        val projectedEntities = Math.addExact(
            Math.addExact(counts.v2Long("emittedRvas"), counts.v2Long("nonEmitted")),
            facts.size.toLong(),
        )
        if (projectedEntities > perShard.v2Long("entities")) {
            v2Fail("observation-v2 exceeds its authenticated per-shard entity bound")
        }
        if (canonicalEnvelopeBytes(document, perShard.v2Long("serializedBytes"), checkpoint).size.toLong() >
            perShard.v2Long("serializedBytes")
        ) {
            v2Fail("observation-v2 exceeds its authenticated serialized-byte bound")
        }
    }

    private fun validateCollisionEvidence(
        facts: List<FullTreeSourceEntityFact>,
        reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
        checkpoint: (String) -> Unit,
    ) {
        facts.forEachIndexed { index, fact ->
            if (index % 4_096 == 0) checkpoint("while validating source collision evidence")
            validateCollisionEvidence(fact, reconciliation, checkpoint)
        }
    }

    internal fun validateSourceEntityEvidence(
        fact: FullTreeSourceEntityFact,
        reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
        checkpoint: (String) -> Unit = {},
    ) {
        validateSourceEntityForV2(fact, checkpoint)
        validateDirectAnchorEvidence(fact, reconciliation)
        validateInlineAnchorEvidence(fact, reconciliation, checkpoint)
        validateCollisionEvidence(fact, reconciliation, checkpoint)
    }

    private fun validateCollisionEvidence(
        fact: FullTreeSourceEntityFact,
        reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
        checkpoint: (String) -> Unit,
    ) {
        checkpoint("before validating source collision evidence")
        val collisionReasons = setOf("duplicate-source-anchor-unproven", "ambiguous-related-source-anchor")
        val fields = fact.semanticAnchorFields
        val directIds = fact.semanticAnchorCandidateId
            ?.let(reconciliation.collisionIdsByCandidate::get)
            .orEmpty()
        val relatedCandidateIds = sequenceOf(
            sequenceOf(fields?.inlineCalleeAnchorCandidateId, fields?.inlineOwnerAnchorCandidateId,
                fields?.templatePatternAnchorCandidateId).filterNotNull(),
            fields?.inlinePathAnchorCandidateIds.orEmpty().asSequence(),
        ).flatten()
        val relatedIds = ArrayList<String>()
        relatedCandidateIds.forEachIndexed { index, candidate ->
            if (index % 64 == 0) checkpoint("while validating related collision candidates")
            reconciliation.collisionIdsByCandidate[candidate].orEmpty().forEachIndexed { idIndex, id ->
                if (idIndex % 4_096 == 0) checkpoint("while collecting related collision claimants")
                relatedIds += id
            }
        }
        val expectedIds = sortedUniqueSourceIds(
            sequenceOf(directIds.asSequence(), relatedIds.asSequence()).flatten(),
            checkpoint,
        )
        if (fact.candidateCollisionSourceEntityIds != expectedIds) {
            v2Fail("source anchor collision IDs do not match the authenticated full-run anchor claims")
        }
        if (directIds.isNotEmpty() && !sourceIdContains(directIds, fact.sourceEntityId, checkpoint)) {
            v2Fail("colliding source row is not an authenticated direct anchor claimant")
        }
        if (expectedIds.isEmpty()) {
            if (fact.reasonCodes.withIndex().any { (index, reason) ->
                    if (index % 64 == 0) checkpoint("while checking source collision reasons")
                    reason in collisionReasons
                }
            ) {
                v2Fail("source entity claims collision evidence absent from the authenticated full-run claims")
            }
        } else {
            val expectedReason = if (directIds.isNotEmpty()) {
                "duplicate-source-anchor-unproven"
            } else {
                "ambiguous-related-source-anchor"
            }
            var containsExpected = false
            var containsUnexpectedCollisionReason = false
            fact.reasonCodes.forEachIndexed { index, reason ->
                if (index % 64 == 0) checkpoint("while validating source collision reason details")
                if (reason == expectedReason) containsExpected = true
                if (reason in collisionReasons && reason != expectedReason) containsUnexpectedCollisionReason = true
            }
            if (fact.identityObservability != FullTreeIdentityObservability.AMBIGUOUS ||
                !containsExpected || containsUnexpectedCollisionReason
            ) {
                v2Fail("source anchor collision is not retained as the exact ambiguous evidence")
            }
        }
        checkpoint("after validating source collision evidence")
    }

    private fun validateDirectAnchorEvidence(
        facts: List<FullTreeSourceEntityFact>,
        reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
        checkpoint: (String) -> Unit,
    ) {
        facts.forEachIndexed { index, fact ->
            if (index % 4_096 == 0) checkpoint("while validating direct source-anchor claims")
            validateDirectAnchorEvidence(fact, reconciliation)
        }
    }

    private fun sortedUniqueSourceIds(values: Sequence<String>, checkpoint: (String) -> Unit): List<String> {
        val sorted = TreeSet(FULL_TREE_CODE_POINT_ORDER)
        values.forEachIndexed { index, value ->
            if (index % 4_096 == 0) checkpoint("while reconciling source collision claimant IDs")
            sorted.add(value)
        }
        val result = ArrayList<String>(sorted.size)
        sorted.forEachIndexed { index, value ->
            if (index % 4_096 == 0) checkpoint("while ordering source collision claimant IDs")
            result += value
        }
        return result
    }

    private fun sourceIdContains(
        values: List<String>,
        expected: String,
        checkpoint: (String) -> Unit,
    ): Boolean {
        values.forEachIndexed { index, value ->
            if (index % 4_096 == 0) checkpoint("while checking direct collision claimant membership")
            if (value == expected) return true
        }
        return false
    }

    private fun validateDirectAnchorEvidence(
        fact: FullTreeSourceEntityFact,
        reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
    ) {
        val candidateId = fact.semanticAnchorCandidateId ?: return
        if (!reconciliation.hasAnchorClaim(candidateId, fact.sourceEntityId)) {
            v2Fail("source anchor candidate is not an authenticated direct anchor claimant for this physical DIE claim")
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
        checkpoint: (String) -> Unit,
    ) {
        facts.forEachIndexed { index, fact ->
            if (index % 4_096 == 0) checkpoint("while validating inline source-anchor claims")
            validateInlineAnchorEvidence(fact, reconciliation, checkpoint)
        }
    }

    private fun validateInlineAnchorEvidence(
        fact: FullTreeSourceEntityFact,
        reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
        checkpoint: (String) -> Unit,
    ) {
        checkpoint("before validating inline source-anchor claims")
        if (fact.kind != FullTreeSourceEntityKind.INLINE_INSTANCE) return
        val fields = fact.semanticAnchorFields ?: return
        val referenceEdges = ArrayList<FullTreeSourceIdentityEdge>()
        val ownerEdges = ArrayList<FullTreeSourceIdentityEdge>()
        fact.edges.forEachIndexed { index, edge ->
            if (index % 16 == 0) checkpoint("while indexing inline source-anchor edges")
            if (edge.state != FullTreeSourceIdentityEdgeState.RESOLVED || edge.target == null) return@forEachIndexed
            if (edge.kind == FullTreeSourceIdentityEdgeKind.SPECIFICATION ||
                edge.kind == FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN
            ) referenceEdges += edge
            if (edge.kind == FullTreeSourceIdentityEdgeKind.INLINE_OWNER) ownerEdges += edge
        }

        fun hasClaim(
            candidateId: String,
            edges: List<FullTreeSourceIdentityEdge>,
            allowedKinds: List<FullTreeSourceAnchorKind>,
        ): Boolean {
            edges.forEachIndexed { index, edge ->
                if (index % 16 == 0) checkpoint("while matching inline candidate to typed claims")
                val target = edge.target ?: return@forEachIndexed
                allowedKinds.forEach { kind ->
                    if (reconciliation.hasInlineRelatedAnchorClaim(
                            candidateId,
                            target.sourceEntityId(kind),
                            kind,
                    )) return true
                }
            }
            return false
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
        fields.inlinePathAnchorCandidateIds.orEmpty().forEachIndexed { index, candidate ->
            if (index % 64 == 0) checkpoint("while validating inline path anchor claims")
            if (!hasClaim(candidate, ownerEdges, listOf(FullTreeSourceAnchorKind.INLINE_INSTANCE))) {
                v2Fail("inline path candidate is not bound to a referenced inline DIE anchor claim")
            }
        }
        checkpoint("after validating inline source-anchor claims")
    }

    private fun validateLegacyProjection(
        document: JsonObject,
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        inventoryArtifactSha256: String,
        shard: FullTreeFunctionObservationShardInput,
        checkpoint: (String) -> Unit,
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
            checkpoint,
        )
    }

    private class V2ArtifactLocatorIndex private constructor(
        private val allUnits: Map<String, JsonObject>,
        private val unitOffsets: List<Pair<String, ULong>>,
        private val shardUnitIds: Set<String>,
    ) {
        fun validate(
            fact: FullTreeSourceEntityFact,
            richArtifactSha256: String,
            checkpoint: (String) -> Unit,
        ) {
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
            fact.edges.forEachIndexed { index, edge ->
                if (index % 16 == 0) checkpoint("while validating typed source-entity locators")
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
                if (edge.referenceForm != null && edge.rawReference != null) {
                    val form = edge.referenceForm.removePrefix("0x").toULongOrNull(16)
                        ?: v2Fail("typed reference form is malformed")
                    val maximumRawValue = fullTreeDwarfReferenceFormMaximumRawValue(form)
                    if (maximumRawValue != null) {
                        val raw = edge.rawReference.removePrefix("0x").toULongOrNull(16)
                            ?: v2Fail("typed reference raw value exceeds its fixed-width DWARF form")
                        if (raw > maximumRawValue) {
                            v2Fail("typed reference raw value exceeds its fixed-width DWARF form")
                        }
                    }
                }
                if (edge.state == FullTreeSourceIdentityEdgeState.UNSUPPORTED) {
                    val form = edge.referenceForm?.removePrefix("0x")?.toULongOrNull(16)
                        ?: v2Fail("unsupported typed reference omits its decoded form")
                    if (edge.rawReference == null || form !in SUPPORTED_UNSUPPORTED_REFERENCE_FORMS) {
                        v2Fail("unsupported typed reference uses a form the producer does not classify as unsupported")
                    }
                }
                if (edge.state == FullTreeSourceIdentityEdgeState.RESOLVED && edge.referenceForm != null) {
                    val target = edge.target ?: v2Fail("resolved typed reference has no target locator")
                    val form = edge.referenceForm?.removePrefix("0x")?.toULongOrNull(16)
                        ?: v2Fail("typed reference form is malformed")
                    val raw = edge.rawReference?.removePrefix("0x")?.toULongOrNull(16)
                        ?: v2Fail("typed reference raw value is malformed")
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
            // The run publisher re-executes source extraction against the authenticated artifact
            // to verify every structural and typed edge against raw DWARF ancestry and references.
            // Direct DW_AT_type edges from signature formals are kept without a redundant
            // parent-to-formal edge to stay within the per-entity edge bound. Those edges may be
            // disconnected in this transport graph, but only typed TYPE references qualify and
            // the authenticated publisher must rederive their formal ancestry from raw DWARF.
            val edgesBySource = fact.edges.groupBy { it.source }
            val reachable = HashSet<FullTreeSourcePhysicalDie>()
            val pending = ArrayDeque<FullTreeSourcePhysicalDie>()
            reachable += fact.physicalDie
            pending.addLast(fact.physicalDie)
            while (pending.isNotEmpty()) {
                if (reachable.size % 16 == 0) checkpoint("while checking source-entity edge reachability")
                val source = pending.removeFirst()
                edgesBySource[source].orEmpty().forEachIndexed { edgeIndex, edge ->
                    if (edgeIndex % 16 == 0) checkpoint("while checking source-entity edge reachability")
                    if (edge.state == FullTreeSourceIdentityEdgeState.RESOLVED) {
                        val target = edge.target ?: v2Fail("resolved typed reference has no target locator")
                        if (reachable.add(target)) pending.addLast(target)
                    }
                }
            }
            if (fact.edges.withIndex().any { (index, edge) ->
                    if (index % 16 == 0) checkpoint("while checking source-entity edge connectivity")
                    edge.source !in reachable &&
                        (edge.kind != FullTreeSourceIdentityEdgeKind.TYPE ||
                            edge.referenceForm == null || edge.rawReference == null)
                }
            ) {
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
            fun create(
                inventory: JsonObject,
                shard: FullTreeFunctionObservationShardInput,
                checkpoint: (String) -> Unit,
            ): V2ArtifactLocatorIndex {
                val rawUnits = inventory.v2Array("units")
                val units = ArrayList<JsonObject>(rawUnits.size)
                rawUnits.forEachIndexed { index, value ->
                    if (index % 4_096 == 0) checkpoint("while indexing inventory units for locators")
                    units += value as JsonObject
                }
                val allUnits = HashMap<String, JsonObject>(units.size)
                val unitOffsets = ArrayList<Pair<String, ULong>>(units.size)
                units.forEachIndexed { index, unit ->
                    if (index % 4_096 == 0) checkpoint("while binding inventory locator units")
                    allUnits[unit.v2String("id")] = unit
                    unitOffsets += unit.v2String("id") to parseDwarfOffset(
                        unit.v2String("dwarfOffset"),
                        "observation-v2 locator",
                    ).toULong()
                }
                var comparisons = 0
                unitOffsets.sortWith { left, right ->
                    if (++comparisons % 4_096 == 0) checkpoint("while sorting inventory locator offsets")
                    left.second.compareTo(right.second)
                }
                val shardUnitIds = HashSet<String>(shard.units.size)
                shard.units.forEachIndexed { index, unit ->
                    if (index % 4_096 == 0) checkpoint("while binding shard locator units")
                    shardUnitIds += unit.v2String("id")
                }
                return V2ArtifactLocatorIndex(
                    allUnits = allUnits,
                    unitOffsets = unitOffsets,
                    shardUnitIds = shardUnitIds,
                )
            }
        }
    }

    private fun countKinds(facts: List<FullTreeSourceEntityFact>, checkpoint: (String) -> Unit): JsonObject {
        val counts = FullTreeSourceEntityKind.entries.associateWith { 0L }.toMutableMap()
        facts.forEachIndexed { index, fact ->
            if (index % 4_096 == 0) checkpoint("while counting source entities by kind")
            counts[fact.kind] = Math.addExact(counts.getValue(fact.kind), 1L)
        }
        return countObject(counts.map { (kind, count) -> kind.wireValue to count })
    }

    private fun countObservability(
        facts: List<FullTreeSourceEntityFact>,
        checkpoint: (String) -> Unit,
    ): JsonObject {
        val counts = FullTreeIdentityObservability.entries.associateWith { 0L }.toMutableMap()
        facts.forEachIndexed { index, fact ->
            if (index % 4_096 == 0) checkpoint("while counting source entities by observability")
            counts[fact.identityObservability] = Math.addExact(counts.getValue(fact.identityObservability), 1L)
        }
        return countObject(counts.map { (state, count) -> state.wireValue to count })
    }

    private fun countDisposition(
        facts: List<FullTreeSourceEntityFact>,
        checkpoint: (String) -> Unit,
    ): JsonObject {
        val counts = FullTreeDenominatorDisposition.entries.associateWith { 0L }.toMutableMap()
        facts.forEachIndexed { index, fact ->
            if (index % 4_096 == 0) checkpoint("while counting source entities by disposition")
            counts[fact.denominatorDisposition] = Math.addExact(counts.getValue(fact.denominatorDisposition), 1L)
        }
        return countObject(counts.map { (disposition, count) -> disposition.wireValue to count })
    }

    private fun countObject(values: List<Pair<String, Long>>): JsonObject = JsonObject(
        values.sortedBy { it.first }.associate { (key, value) -> key to JsonPrimitive(value) },
    )
}

private fun sourceIdentityJsonCodePointLength(value: String): Int = value.codePointCount(0, value.length)

internal fun fullTreeDwarfReferenceFormMaximumRawValue(form: ULong): ULong? = when (form) {
    FULL_TREE_DW_FORM_REF1.toULong() -> 0xffuL
    FULL_TREE_DW_FORM_REF2.toULong() -> 0xffffuL
    FULL_TREE_DW_FORM_REF4.toULong(), FULL_TREE_DW_FORM_REF_SUP4.toULong() -> 0xffff_ffffuL
    else -> null
}

private val SUPPORTED_UNSUPPORTED_REFERENCE_FORMS = setOf(
    FULL_TREE_DW_FORM_REF_SUP4.toULong(),
    FULL_TREE_DW_FORM_REF_SIG8.toULong(),
    FULL_TREE_DW_FORM_REF_SUP8.toULong(),
    FULL_TREE_DW_FORM_GNU_REF_ALT.toULong(),
)

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
    fun acceptInlineRelatedClaims(fact: FullTreeSourceEntityFact, checkpoint: (String) -> Unit = {}) {
        if (frozenReconciliation != null) v2Fail("full-run anchor claims are already reconciled")
        if (fact.kind != FullTreeSourceEntityKind.INLINE_INSTANCE) return
        val fields = fact.semanticAnchorFields ?: return
        val referenceEdges = ArrayList<FullTreeSourceIdentityEdge>()
        val ownerEdges = ArrayList<FullTreeSourceIdentityEdge>()
        fact.edges.forEachIndexed { index, edge ->
            if (index % 16 == 0) checkpoint("while indexing full-run inline anchor edges")
            if (edge.state != FullTreeSourceIdentityEdgeState.RESOLVED || edge.target == null) return@forEachIndexed
            if (edge.kind == FullTreeSourceIdentityEdgeKind.SPECIFICATION ||
                edge.kind == FullTreeSourceIdentityEdgeKind.ABSTRACT_ORIGIN
            ) referenceEdges += edge
            if (edge.kind == FullTreeSourceIdentityEdgeKind.INLINE_OWNER) ownerEdges += edge
        }

        fun acceptReferencedClaim(
            candidateId: String,
            edges: List<FullTreeSourceIdentityEdge>,
            allowedKinds: List<FullTreeSourceAnchorKind>,
            label: String,
        ) {
            val matching = LinkedHashSet<FullTreeFunctionObservationV2TypedAnchorClaim>()
            edges.forEachIndexed { edgeIndex, edge ->
                if (edgeIndex % 16 == 0) checkpoint("while matching full-run inline anchor references")
                val target = edge.target ?: return@forEachIndexed
                allowedKinds.forEachIndexed { kindIndex, kind ->
                    if (kindIndex % 4 == 0) checkpoint("while checking full-run inline anchor kinds")
                    val physicalClaimId = target.sourceEntityId(kind)
                    if (claims[candidateId]?.contains(physicalClaimId) == true) {
                        matching += FullTreeFunctionObservationV2TypedAnchorClaim(candidateId, physicalClaimId, kind)
                    }
                }
            }
            if (matching.isEmpty()) {
                v2Fail("inline $label candidate is not backed by a typed claim on a referenced DIE")
            }
            matching.forEachIndexed { index, claim ->
                if (index % 64 == 0) checkpoint("while retaining full-run inline related claims")
                if (claim !in inlineRelatedClaims) {
                    val nextBytes = Math.addExact(retainedBytes, INLINE_RELATED_CLAIM_INDEX_BYTES)
                    if (nextBytes > maximumRetainedBytes) {
                        v2Fail("inline anchor claim subset exceeds its authenticated working-set bound")
                    }
                    retainedBytes = nextBytes
                    inlineRelatedClaims.add(claim)
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
        fields.inlinePathAnchorCandidateIds.orEmpty().forEachIndexed { index, candidate ->
            if (index % 64 == 0) checkpoint("while accepting full-run inline path claims")
            acceptReferencedClaim(
                candidate,
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
        maximumCanonicalBytes: Long = MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES,
    ) {
        if (frozenReconciliation != null) v2Fail("full-run anchor claims are already reconciled")
        if (shardId.isBlank() || shardId in sourceEntityPopulations) {
            v2Fail("full-run source-entity population shard is malformed or duplicated")
        }
        val nextBytes = Math.addExact(retainedBytes, SOURCE_ENTITY_POPULATION_CLAIM_BYTES)
        if (nextBytes > maximumRetainedBytes) {
            v2Fail("full-run source-entity population proofs exceed their authenticated working-set bound")
        }
        val claim = sourceEntityPopulationClaim(facts, maximumCanonicalBytes, checkpoint)
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
        maximumCanonicalBytes: Long = MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES,
    ) {
        val expected = sourceEntityPopulations[shardId]
            ?: v2Fail("source-entity physical DIE population has no authenticated scan receipt")
        if (sourceEntityPopulationClaim(facts, maximumCanonicalBytes, checkpoint) != expected) {
            v2Fail("source-entity canonical facts differ from the authenticated scan receipt")
        }
    }

    internal fun newSourceEntityPopulationStreamValidator(
        shardId: String,
        maximumCanonicalBytes: Long,
        checkpoint: (String) -> Unit = {},
    ): FullTreeFunctionObservationV2SourceEntityPopulationStreamValidator {
        require(maximumCanonicalBytes in 1L..MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES)
        val expected = sourceEntityPopulations[shardId]
            ?: v2Fail("source-entity physical DIE population has no authenticated scan receipt")
        return FullTreeFunctionObservationV2SourceEntityPopulationStreamValidator(
            expected,
            maximumCanonicalBytes,
            checkpoint,
            this,
        )
    }
}

/** Validates SQLite's indexed row stream and authenticated population receipt without retaining rows. */
internal class FullTreeFunctionObservationV2SourceEntityPopulationStreamValidator internal constructor(
    private val expected: FullTreeFunctionObservationV2SourceEntityPopulationClaim,
    private val maximumCanonicalBytes: Long,
    private val checkpoint: (String) -> Unit,
    private val reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
) {
    private val digest = MessageDigest.getInstance("SHA-256")
    private var canonicalBytes = 0L
    private var bytesSinceCheckpoint = 0
    private var count = 0L
    private var finished = false
    private var lastSortKey: List<String>? = null

    fun accept(fact: FullTreeSourceEntityFact) {
        check(!finished) { "source-entity receipt stream is already finished" }
        checkpoint("before validating a SQLite source-entity receipt row")
        FullTreeFunctionObservationsV2.validateSourceEntityEvidence(fact, reconciliation, checkpoint)
        val sortKey = listOf(
            fact.kind.wireValue,
            fact.semanticAnchorCandidateId ?: "~",
            fact.physicalDie.unitId,
            fact.physicalDie.compilationUnitOffset,
            fact.physicalDie.dieOffset,
        )
        val previous = lastSortKey
        if (previous != null && compareSourceEntitySortKeys(previous, sortKey) >= 0) {
            v2Fail("SQLite source entities are not in canonical observation-v2 order")
        }
        lastSortKey = sortKey

        if (count == 0L) {
            write("[\n".toByteArray(StandardCharsets.US_ASCII))
        } else {
            write(",\n".toByteArray(StandardCharsets.US_ASCII))
        }
        val neutral = observationV2CollisionNeutralFact(fact, checkpoint)
        val row = OracleJson.canonicalBytes(
            neutral.canonicalJson(checkpoint),
            sourceIdentityRowJsonLimits(maximumCanonicalBytes),
            checkpoint,
        )
        if (row.isEmpty() || row.last() != '\n'.code.toByte()) {
            v2Fail("canonical source-entity scan-receipt row has no final newline")
        }
        write("  ".toByteArray(StandardCharsets.US_ASCII))
        var segmentStart = 0
        for (index in 0 until row.lastIndex) {
            if (index % (64 * 1024) == 0) checkpoint("while streaming a SQLite source-entity receipt row")
            if (row[index] == '\n'.code.toByte()) {
                write(row, segmentStart, index + 1 - segmentStart)
                write("  ".toByteArray(StandardCharsets.US_ASCII))
                segmentStart = index + 1
            }
        }
        write(row, segmentStart, row.lastIndex - segmentStart)
        count = Math.addExact(count, 1L)
        if (count % FULL_RUN_RECONCILIATION_CHECKPOINT_INTERVAL == 0L) {
            checkpoint("while validating SQLite source-entity scan receipts")
        }
    }

    fun finish() {
        check(!finished) { "source-entity receipt stream is already finished" }
        finished = true
        if (count == 0L) {
            write("[]\n".toByteArray(StandardCharsets.US_ASCII))
        } else {
            write("\n]\n".toByteArray(StandardCharsets.US_ASCII))
        }
        if (count != expected.sourceEntityCount) {
            v2Fail("SQLite source-entity count differs from the authenticated scan receipt")
        }
        val innerSha256 = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val populationDigest = MessageDigest.getInstance("SHA-256")
        populationDigest.update("full-run-observation-v2-source-entities-v2\n".toByteArray(StandardCharsets.US_ASCII))
        populationDigest.update(count.toString().toByteArray(StandardCharsets.US_ASCII))
        populationDigest.update('\n'.code.toByte())
        populationDigest.update(innerSha256.toByteArray(StandardCharsets.US_ASCII))
        val populationSha256 = populationDigest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
        if (populationSha256 != expected.populationSha256) {
            v2Fail("source-entity canonical facts differ from the authenticated scan receipt")
        }
    }

    private fun write(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size) {
        if (length <= 0) return
        val next = try {
            Math.addExact(canonicalBytes, length.toLong())
        } catch (failure: ArithmeticException) {
            throw FullTreeFunctionObservationV2Exception("collision-neutral source entities byte count overflows", failure)
        }
        if (next > maximumCanonicalBytes) {
            v2Fail("collision-neutral source entities exceed the authenticated scan-receipt byte bound")
        }
        var written = 0
        while (written < length) {
            val chunk = minOf(64 * 1024 - bytesSinceCheckpoint, length - written)
            digest.update(bytes, offset + written, chunk)
            written += chunk
            bytesSinceCheckpoint += chunk
            if (bytesSinceCheckpoint == 64 * 1024) {
                checkpoint("while hashing SQLite source-entity receipt bytes")
                bytesSinceCheckpoint = 0
            }
        }
        canonicalBytes = next
    }

    private fun compareSourceEntitySortKeys(left: List<String>, right: List<String>): Int {
        for (index in left.indices) {
            val result = left[index].compareTo(right[index])
            if (result != 0) return result
        }
        return 0
    }
}

private const val TEMPLATE_PATTERN_CLAIM_INDEX_BYTES = 96L
private const val INLINE_RELATED_CLAIM_INDEX_BYTES = 96L
private const val SOURCE_ENTITY_POPULATION_CLAIM_BYTES = 128L
private const val FULL_RUN_RECONCILIATION_CHECKPOINT_INTERVAL = 4_096L

private fun sourceEntityPopulationClaim(
    facts: List<FullTreeSourceEntityFact>,
    maximumCanonicalBytes: Long,
    checkpoint: (String) -> Unit = {},
): FullTreeFunctionObservationV2SourceEntityPopulationClaim {
    val canonicalFactsSha256 = observationV2CollisionNeutralSourceEntitiesSha256(
        facts,
        maximumCanonicalBytes,
        checkpoint,
    )
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update("full-run-observation-v2-source-entities-v2\n".toByteArray(StandardCharsets.US_ASCII))
    digest.update(facts.size.toString().toByteArray(StandardCharsets.US_ASCII))
    digest.update('\n'.code.toByte())
    digest.update(canonicalFactsSha256.toByteArray(StandardCharsets.US_ASCII))
    return FullTreeFunctionObservationV2SourceEntityPopulationClaim(
        sourceEntityCount = facts.size.toLong(),
        populationSha256 = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) },
    )
}

/**
 * Hash the canonical, collision-neutral source facts without retaining a whole shard byte array.
 * Collision evidence is independently derived from authenticated full-run anchor claims; this
 * receipt binds the remaining extracted row fields and does not use candidate hashes as identity.
 */
internal fun observationV2CollisionNeutralSourceEntitiesSha256(
    facts: List<FullTreeSourceEntityFact>,
    maximumCanonicalBytes: Long,
    checkpoint: (String) -> Unit = {},
): String {
    require(maximumCanonicalBytes in 1L..MAXIMUM_SOURCE_IDENTITY_CANONICAL_BYTES)
    val ordered = FullTreeSourceEntityFact.deterministicOrder(facts, checkpoint)
    val digest = MessageDigest.getInstance("SHA-256")
    var canonicalBytes = 0L

    fun write(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size) {
        if (length <= 0) return
        val next = Math.addExact(canonicalBytes, length.toLong())
        if (next > maximumCanonicalBytes) {
            v2Fail("collision-neutral source entities exceed the authenticated scan-receipt byte bound")
        }
        var written = 0
        while (written < length) {
            val count = minOf(64 * 1024, length - written)
            digest.update(bytes, offset + written, count)
            written += count
            checkpoint("while hashing collision-neutral source-entity bytes")
        }
        canonicalBytes = next
    }

    fun writeAscii(value: String) = write(value.toByteArray(StandardCharsets.US_ASCII))
    if (ordered.isEmpty()) {
        writeAscii("[]\n")
    } else {
        writeAscii("[\n")
        ordered.forEachIndexed { index, fact ->
            if (index.toLong() % FULL_RUN_RECONCILIATION_CHECKPOINT_INTERVAL == 0L) {
                checkpoint("while hashing collision-neutral source-entity scan receipts")
            }
            val neutral = observationV2CollisionNeutralFact(fact, checkpoint)
            val row = OracleJson.canonicalBytes(
                neutral.canonicalJson(checkpoint),
                sourceIdentityRowJsonLimits(maximumCanonicalBytes),
                checkpoint,
            )
            if (row.isEmpty() || row.last() != '\n'.code.toByte()) {
                v2Fail("canonical source-entity scan-receipt row has no final newline")
            }
            writeAscii("  ")
            var segmentStart = 0
            for (rowIndex in 0 until row.lastIndex) {
                if (rowIndex % (64 * 1024) == 0) {
                    checkpoint("while streaming collision-neutral source-entity receipt bytes")
                }
                if (row[rowIndex] == '\n'.code.toByte()) {
                    write(row, segmentStart, rowIndex + 1 - segmentStart)
                    writeAscii("  ")
                    segmentStart = rowIndex + 1
                }
            }
            write(row, segmentStart, row.lastIndex - segmentStart)
            if (index != ordered.lastIndex) write(byteArrayOf(','.code.toByte()))
            writeAscii("\n")
        }
        writeAscii("]\n")
    }
    return digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
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
        observationV2CollisionNeutralFact(fact, checkpoint)
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
        val neutral = observationV2CollisionNeutralFact(fact, checkpoint)
        val bytes = OracleJson.canonicalBytes(
            neutral.canonicalJson(checkpoint ?: {}),
            sourceIdentityRowJsonLimits(maximumCanonicalBytes),
            checkpoint ?: {},
        )
        val lineBreaks = countCanonicalLineBreaks(
            bytes,
            checkpoint,
            "while measuring collision-neutral source-entity row bytes",
        )
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

private fun observationV2CollisionNeutralFact(
    fact: FullTreeSourceEntityFact,
    checkpoint: ((String) -> Unit)? = null,
): FullTreeSourceEntityFact {
    checkpoint?.invoke("before neutralizing source-entity collision fields")
    val collisionReasons = setOf("duplicate-source-anchor-unproven", "ambiguous-related-source-anchor")
    val retainedReasons = ArrayList<String>(fact.reasonCodes.size)
    var removedCollisionReason = false
    fact.reasonCodes.forEachIndexed { index, reason ->
        if (index % 64 == 0) checkpoint?.invoke("while removing collision reason codes")
        if (reason !in collisionReasons) retainedReasons += reason else removedCollisionReason = true
    }
    if (!removedCollisionReason && fact.candidateCollisionSourceEntityIds.isEmpty()) {
        checkpoint?.invoke("after neutralizing source-entity collision fields")
        return fact
    }
    val result = fact.copy(
        identityObservability = observationV2BaseObservability(fact, retainedReasons, checkpoint ?: {}),
        candidateCollisionSourceEntityIds = emptyList(),
        reasonCodes = retainedReasons,
        checkpoint = checkpoint ?: {},
    )
    checkpoint?.invoke("after neutralizing source-entity collision fields")
    return result
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
        val neutral = observationV2CollisionNeutralFact(fact, checkpoint)
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
    checkpoint: (String) -> Unit,
): FullTreeIdentityObservability {
    var ambiguousEdges = false
    var unknownEdges = false
    fact.edges.forEachIndexed { index, edge ->
        if (index % 16 == 0) checkpoint("while reconciling collision-neutral source observability")
        if (edge.state == FullTreeSourceIdentityEdgeState.CYCLIC) ambiguousEdges = true
        if (edge.state == FullTreeSourceIdentityEdgeState.MISSING_TARGET ||
            edge.state == FullTreeSourceIdentityEdgeState.MALFORMED ||
            edge.state == FullTreeSourceIdentityEdgeState.UNSUPPORTED
        ) unknownEdges = true
    }
    var ambiguousReasons = false
    var unknownReasons = false
    var declarationReason = false
    reasonCodes.forEachIndexed { index, reason ->
        if (index % 64 == 0) checkpoint("while checking collision-neutral source reasons")
        if (reason.startsWith("ambiguous-")) ambiguousReasons = true
        if (reason.startsWith("unknown-")) unknownReasons = true
        if (reason == "declaration-only-no-definition") declarationReason = true
    }
    return when {
        ambiguousReasons || ambiguousEdges -> FullTreeIdentityObservability.AMBIGUOUS
        fact.kind == FullTreeSourceEntityKind.DECLARATION_ONLY ||
            declarationReason -> FullTreeIdentityObservability.UNOBSERVABLE
        unknownReasons || unknownEdges -> FullTreeIdentityObservability.UNKNOWN
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
