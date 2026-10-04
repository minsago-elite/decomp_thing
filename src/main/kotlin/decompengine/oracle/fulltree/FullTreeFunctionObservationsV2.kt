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
    private const val MAXIMUM_CANONICAL_BYTES = 64L * 1024L * 1024L

    val producerPolicy: JsonObject = JsonObject(
        mapOf(
            "id" to JsonPrimitive("full-tree-function-observations"),
            "version" to JsonPrimitive(4),
            "identityReconciliation" to JsonPrimitive("full-run-anchor-claims-v1"),
            "sourceEntityId" to JsonPrimitive("artifact-unit-section-cu-die-kind-v1"),
            "semanticAnchorCandidate" to JsonPrimitive("typed-source-tuple-v2-column-excluded"),
            "candidateHashesProveIdentity" to JsonPrimitive(false),
            "legacySourceEntityCoverage" to JsonPrimitive(false),
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
        if (facts.map { it.sourceEntityId }.toSet().size != facts.size) {
            v2Fail("observation-v2 sourceEntityIds are not unique")
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

    fun canonicalEnvelopeBytes(document: JsonObject, maximumBytes: Long = MAXIMUM_CANONICAL_BYTES): ByteArray = try {
        val boundedBytes = minOf(maximumBytes, MAXIMUM_CANONICAL_BYTES).toInt()
        OracleJson.canonicalBytes(
            document,
            StrictJsonLimits(
                maximumInputBytes = boundedBytes,
                maximumCanonicalBytes = boundedBytes,
                maximumDepth = 128,
                maximumNodes = 1_000_000,
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
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        inventoryArtifactSha256: String,
        shard: FullTreeFunctionObservationShardInput,
        reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
    ) {
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
        if (facts != FullTreeSourceEntityFact.deterministicOrder(facts)) {
            v2Fail("observation-v2 source entities are not canonically ordered")
        }
        if (reconcileObservationV2Facts(facts, reconciliation) != facts) {
            v2Fail("observation-v2 collision states do not match the authenticated full-run anchor claims")
        }
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
        facts.forEach { fact ->
            fact.linkedEmittedRva?.let { rva ->
                if (rva !in emittedRvas) v2Fail("source entity links to an absent emitted RVA")
            }
            validateArtifactLocators(fact, inventory, oracle.v2String("richArtifactSha256"), shard)
            if (fact.candidateCollisionSourceEntityIds.isNotEmpty() &&
                (fact.identityObservability != FullTreeIdentityObservability.AMBIGUOUS ||
                    fact.reasonCodes.none { it in setOf("duplicate-source-anchor-unproven", "ambiguous-related-source-anchor") })
            ) {
                v2Fail("source anchor collision is not retained as ambiguous evidence")
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
        validateLegacyProjection(document, scope, scopeSha256, inventory, inventoryArtifactSha256, shard)
        val perShard = scope.v2Object("bounds").v2Object("perShard")
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

    private fun validateArtifactLocators(
        fact: FullTreeSourceEntityFact,
        inventory: JsonObject,
        richArtifactSha256: String,
        shard: FullTreeFunctionObservationShardInput,
    ) {
        val allUnits = inventory.v2Array("units").map { it as JsonObject }.associateBy { it.v2String("id") }
        val unitOffsets = allUnits.values.map { unit ->
            unit.v2String("id") to unit.v2String("dwarfOffset").removePrefix("0x").toULong(16)
        }
        fun validate(die: FullTreeSourcePhysicalDie, mustBeInShard: Boolean) {
            if (die.richArtifactSha256 != richArtifactSha256) v2Fail("source DIE belongs to another artifact")
            val unit = allUnits[die.unitId] ?: v2Fail("source DIE unit is outside the authenticated inventory")
            if (parseDwarfOffset(unit.v2String("dwarfOffset"), "observation-v2 locator") !=
                die.compilationUnitOffset.removePrefix("0x").toULong(16)
            ) v2Fail("source DIE CU offset differs from its authenticated unit")
            if (mustBeInShard && shard.units.none { it.v2String("id") == die.unitId }) {
                v2Fail("source entity is outside its authenticated shard")
            }
        }
        validate(fact.physicalDie, true)
        fact.edges.forEach { edge ->
            if (edge.source != fact.physicalDie) v2Fail("source edge owner differs from its source entity")
            validate(edge.source, true)
            edge.target?.let { validate(it, false) }
            if (edge.referenceForm != null || edge.rawReference != null) {
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
                        val expectedUnit = unitOffsets.filter { (_, offset) -> offset <= raw }
                            .maxByOrNull { it.second }?.first
                        if (targetOffset != raw || target.unitId != expectedUnit) {
                            v2Fail(".debug_info reference target differs from its raw absolute offset")
                        }
                    }
                    else -> v2Fail("resolved typed reference uses an unsupported DWARF reference form")
                }
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

/** Full-run, bounded anchor population, including ordinary source definitions omitted from census rows. */
internal class FullTreeFunctionObservationV2AnchorIndex(
    private val maximumClaims: Long,
    private val maximumRetainedBytes: Long,
) {
    private val claims = TreeMap<String, TreeSet<String>>(FULL_TREE_CODE_POINT_ORDER)
    private var claimCount = 0L
    private var retainedBytes = 0L

    init {
        require(maximumClaims > 0L && maximumRetainedBytes > 0L)
    }

    fun accept(candidateId: String, physicalClaimId: String) {
        if (!candidateId.matches(Regex("[0-9a-f]{64}")) || !physicalClaimId.matches(Regex("[0-9a-f]{64}"))) {
            v2Fail("full-run anchor claim is malformed")
        }
        val prior = claims[candidateId]
        if (prior?.contains(physicalClaimId) == true) return
        val charge = 64L + candidateId.length + physicalClaimId.length + 96L
        val nextCount = Math.addExact(claimCount, 1L)
        val nextBytes = Math.addExact(retainedBytes, charge)
        if (nextCount > maximumClaims || nextBytes > maximumRetainedBytes) {
            v2Fail("full-run anchor claim population exceeds its authenticated working-set bound")
        }
        // Admission precedes any new key, set, or ID insertion.
        retainedBytes = nextBytes
        claimCount = nextCount
        claims.getOrPut(candidateId) { TreeSet(FULL_TREE_CODE_POINT_ORDER) }.add(physicalClaimId)
    }

    fun reconciliation(): FullTreeFunctionObservationV2IdentityReconciliation {
        val digest = MessageDigest.getInstance("SHA-256")
        var populationBytes = 3L
        fun update(value: String) = digest.update(value.toByteArray(StandardCharsets.UTF_8))
        if (claimCount == 0L) {
            update("[]\n")
        } else {
            update("[\n")
            var row = 0L
            claims.forEach { (candidate, ids) -> ids.forEach { id ->
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
        if (populationBytes > maximumRetainedBytes) {
            v2Fail("full-run anchor population digest exceeds its bounded canonical-byte budget")
        }
        val collisions = claims.filterValues { it.size > 1 }
        var reportCharge = 0L
        collisions.forEach { (candidate, ids) ->
            reportCharge = Math.addExact(reportCharge, 64L + candidate.length + ids.size.toLong() * 8L)
        }
        if (Math.addExact(retainedBytes, reportCharge) > maximumRetainedBytes) {
            v2Fail("full-run collision report exceeds its bounded retained-working-set budget")
        }
        retainedBytes = Math.addExact(retainedBytes, reportCharge)
        val immutableCollisions = LinkedHashMap<String, List<String>>()
        collisions.forEach { (candidate, ids) -> immutableCollisions[candidate] = Collections.unmodifiableList(ids.toList()) }
        return FullTreeFunctionObservationV2IdentityReconciliation(
            populationSha256 = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) },
            claimCount = claimCount,
            candidateCount = claims.size.toLong(),
            collisionCandidateCount = immutableCollisions.size.toLong(),
            collisionIdsByCandidate = Collections.unmodifiableMap(immutableCollisions),
        )
    }
}

internal data class FullTreeFunctionObservationV2IdentityReconciliation(
    val populationSha256: String,
    val claimCount: Long,
    val candidateCount: Long,
    val collisionCandidateCount: Long,
    val collisionIdsByCandidate: Map<String, List<String>>,
) {
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
}

internal fun reconcileObservationV2Facts(
    facts: List<FullTreeSourceEntityFact>,
    reconciliation: FullTreeFunctionObservationV2IdentityReconciliation,
): List<FullTreeSourceEntityFact> = FullTreeSourceEntityIdentityProducer.markUnprovedAnchorCollisions(
    FullTreeSourceEntityFact.deterministicOrder(facts),
    SourceIdentityAnchorCollisionReport(reconciliation.collisionIdsByCandidate),
)

private fun JsonObject.v2Element(name: String): JsonElement = get(name) ?: v2Fail("missing field $name")
private fun JsonObject.v2Object(name: String): JsonObject = v2Element(name) as? JsonObject ?: v2Fail("$name is not an object")
private fun JsonObject.v2Array(name: String): List<JsonElement> = (v2Element(name) as? JsonArray)?.toList() ?: v2Fail("$name is not an array")
private fun JsonObject.v2String(name: String): String = (get(name) as? JsonPrimitive)?.takeIf { it.isString }?.content ?: v2Fail("$name is not a string")
private fun JsonObject.v2Long(name: String): Long = (get(name) as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull ?: v2Fail("$name is not an integer")
private fun v2Fail(message: String): Nothing = throw FullTreeFunctionObservationV2Exception(message)
