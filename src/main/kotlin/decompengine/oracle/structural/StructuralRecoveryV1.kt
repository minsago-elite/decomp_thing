package decompengine.oracle.structural

import decompengine.oracle.core.OracleSchemas
import java.math.BigDecimal
import java.math.RoundingMode
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Deterministic JVM implementation of the historical structural-recovery v1
 * fixture scorer. Production adapter replay is deliberately outside this API:
 * digest-bound fixtures are useful differential evidence, but are not a
 * substitute for an authenticated production exporter/verifier.
 */
object StructuralRecoveryV1 {
    fun scoreFixture(
        oracle: StructuralOracleV1,
        recovered: RecoveredStructureV1,
        boundary: StructuralBoundaryMappingV1,
        identityMap: StructuralIdentityMapV1,
        target: StructuralTargetAbiV1,
        limits: StructuralRecoveryV1Limits = StructuralRecoveryV1Limits(),
    ): JsonObject {
        if (oracle.document.field("scope", "structural oracle") != JsonPrimitive("fixture") ||
            recovered.document.field("scope", "recovered structure") != JsonPrimitive("fixture")
        ) structuralFail("fixture scorer refuses production-scoped evidence")
        preflight(oracle, recovered, boundary, identityMap, target, limits)

        val oracleEntities = entityMap(oracle.document.field("entities", "structural oracle"))
        val recoveredEntities = entityMap(recovered.document.field("entities", "recovered structure"))
        validateIdentityUniverses(oracleEntities, recoveredEntities, boundary)
        identityMap.recoveredToOracle.forEach { (recoveredKey, oracleId) ->
            if (StructuralEntityKey(recoveredKey.kind, oracleId) !in oracleEntities) {
                structuralFail("identity map references an absent oracle entity")
            }
            if (recoveredKey !in recoveredEntities) structuralFail("identity map references an absent recovered entity")
        }
        boundary.recoveredToOracle.forEach { (recoveredId, oracleId) ->
            if (StructuralEntityKey("function", recoveredId) in recoveredEntities &&
                StructuralEntityKey("function", oracleId) !in oracleEntities
            ) structuralFail("selected boundary mapping references an absent structural oracle function")
        }

        val details = arrayListOf<JsonObject>()
        val consumedRecoveredEntities = hashSetOf<StructuralEntityKey>()
        oracleEntities.entries.sortedWith { left, right ->
            StructuralRecoveryV1Contract.ENTITY_KEY_ORDER.compare(left.key, right.key)
        }.forEach { (oracleKey, oracleEntity) ->
            val recoveredId = mappedRecoveredId(oracleKey, boundary, identityMap)
            val recoveredKey = recoveredId?.let { StructuralEntityKey(oracleKey.kind, it) }
            val recoveredEntity = recoveredKey?.let(recoveredEntities::get)
            if (recoveredEntity != null) consumedRecoveredEntities += recoveredKey
            val recoveredFacts = recoveredEntity?.field("facts", "recovered entity")
                ?.requireArray("recovered entity.facts", limits.maximumFactsPerEntity, 1)
                ?.map { it as JsonObject }
                ?.associateBy(::factSlot).orEmpty()
            val consumedFactSlots = hashSetOf<Pair<String, String>>()
            val outcomes = arrayListOf<JsonObject>()
            sortedFacts(oracleEntity, limits).forEach { oracleFact ->
                val slot = factSlot(oracleFact)
                val recoveredFact = recoveredFacts[slot]
                if (recoveredFact != null) consumedFactSlots += slot
                val observability = oracleFact.field("observability", "oracle fact").requireString("oracle fact.observability", 64)
                var normalized: JsonElement = JsonNull
                var mappingVerified: JsonElement = JsonNull
                val outcome = when {
                    observability == "oracle-unobservable" -> "oracle-unobservable"
                    recoveredFact == null || recoveredFact.field("state", "recovered fact") == JsonPrimitive("recovered-unknown") ->
                        "recovered-unknown"
                    else -> {
                        val normalization = normalizeRecoveredValue(
                            slot.first,
                            recoveredFact.field("value", "recovered fact") as JsonObject,
                            boundary,
                            identityMap,
                        )
                        normalized = normalization.first
                        mappingVerified = normalization.second?.let(::JsonPrimitive) ?: JsonNull
                        factOutcome(
                            slot.first,
                            oracleFact.field("value", "oracle fact") as JsonObject,
                            normalization.first,
                            normalization.second,
                        )
                    }
                }
                outcomes += factResult(
                    dimension = slot.first,
                    slot = slot.second,
                    oracleFact = oracleFact,
                    recoveredFact = recoveredFact,
                    outcome = outcome,
                    normalizedRecoveredValue = normalized,
                    referenceMappingVerified = mappingVerified,
                )
            }
            if (recoveredEntity != null) {
                sortedFacts(recoveredEntity, limits).forEach { recoveredFact ->
                    if (factSlot(recoveredFact) !in consumedFactSlots) outcomes += fabricatedFact(recoveredFact)
                }
            }
            val sortedOutcomes = outcomes.sortedWith(FACT_RESULT_ORDER)
            details += JsonObject(
                mapOf(
                    "kind" to JsonPrimitive(oracleKey.kind),
                    "oracleId" to JsonPrimitive(oracleKey.id),
                    "recoveredId" to (if (recoveredEntity == null) JsonNull else JsonPrimitive(recoveredId)),
                    "facts" to JsonArray(sortedOutcomes),
                ),
            )
        }

        recoveredEntities.entries.sortedWith { left, right ->
            StructuralRecoveryV1Contract.ENTITY_KEY_ORDER.compare(left.key, right.key)
        }.forEach { (recoveredKey, recoveredEntity) ->
            if (recoveredKey in consumedRecoveredEntities) return@forEach
            val mapped = mappedOracleId(recoveredKey, boundary, identityMap)
            val mappedKey = mapped?.let { StructuralEntityKey(recoveredKey.kind, it) }
            details += JsonObject(
                mapOf(
                    "kind" to JsonPrimitive(recoveredKey.kind),
                    "oracleId" to (if (mappedKey != null && mappedKey in oracleEntities) JsonPrimitive(mapped) else JsonNull),
                    "recoveredId" to JsonPrimitive(recoveredKey.id),
                    "facts" to JsonArray(sortedFacts(recoveredEntity, limits).map(::fabricatedFact)),
                ),
            )
        }

        val measuredDetails = details.map { entity ->
            JsonObject(entity + ("metric" to metricForFacts(entity.field("facts", "report entity") as JsonArray)))
        }.sortedWith(ENTITY_RESULT_ORDER)
        val oracleHeader = oracle.document.field("oracle", "structural oracle") as JsonObject
        val boundaryOracle = oracleHeader.field("boundaryOracle", "structural oracle.oracle") as JsonObject
        val model = recovered.document.field("model", "recovered structure") as JsonObject
        val identityHeader = identityMap.document.field("map", "structural identity map") as JsonObject
        val report = JsonObject(
            mapOf(
                "schemaVersion" to JsonPrimitive(1),
                "oracle" to JsonObject(
                    mapOf(
                        "id" to oracleHeader.field("id", "structural oracle.oracle"),
                        "scope" to oracle.document.field("scope", "structural oracle"),
                        "sha256" to JsonPrimitive(oracle.snapshot.sha256),
                        "artifactManifestSha256" to oracleHeader.field("artifactManifestSha256", "structural oracle.oracle"),
                        "boundaryOracleId" to boundaryOracle.field("id", "structural oracle.oracle.boundaryOracle"),
                    ),
                ),
                "model" to JsonObject(
                    mapOf(
                        "id" to model.field("id", "recovered structure.model"),
                        "scope" to recovered.document.field("scope", "recovered structure"),
                        "sha256" to JsonPrimitive(recovered.snapshot.sha256),
                        "payloadSha256" to JsonPrimitive(recovered.payloadSha256),
                        "verification" to FIXTURE_VERIFICATION,
                        "provenance" to recovered.document.field("provenance", "recovered structure"),
                    ),
                ),
                "targetAbi" to targetBinding(target),
                "normalizationProfile" to oracle.document.field("normalizationProfile", "structural oracle"),
                "boundaryMapping" to JsonObject(
                    mapOf(
                        "scoreSha256" to JsonPrimitive(boundary.snapshot.sha256),
                        "twin" to JsonPrimitive(boundary.twin),
                        "projectionAdapter" to JsonObject(
                            mapOf(
                                "id" to JsonPrimitive(boundary.projectionAdapterId),
                                "version" to JsonPrimitive(boundary.projectionAdapterVersion),
                                "objectFormat" to JsonPrimitive(boundary.objectFormat),
                            ),
                        ),
                        "selectedFunctionCount" to JsonPrimitive(boundary.oracleToRecovered.size),
                    ),
                ),
                "identityMapping" to JsonObject(
                    mapOf(
                        "id" to identityHeader.field("id", "structural identity map.map"),
                        "sha256" to JsonPrimitive(identityMap.snapshot.sha256),
                        "mappingCount" to JsonPrimitive(identityMap.recoveredToOracle.size),
                        "verification" to JsonPrimitive("fixture-payload-digest-only"),
                        "productionVerified" to JsonPrimitive(false),
                    ),
                ),
                "policy" to reportPolicy(limits),
                "dimensions" to JsonArray(
                    StructuralRecoveryV1Contract.DIMENSIONS.map { dimension ->
                        JsonObject(mapOf("dimension" to JsonPrimitive(dimension)) + metricForDimension(dimension, measuredDetails))
                    },
                ),
                "aggregate" to metricForDimension(null, measuredDetails),
                "entities" to JsonArray(measuredDetails),
            ),
        )
        validateFixtureReport(report, target, limits)
        canonicalStructuralReportBytes(report, limits.maximumReportBytes)
        return report
    }

    fun validateFixtureReport(
        report: JsonObject,
        target: StructuralTargetAbiV1,
        limits: StructuralRecoveryV1Limits = StructuralRecoveryV1Limits(),
    ) {
        validateReportHeaders(report, target, limits)
        validateReportBody(report, target, limits)
    }

    fun canonicalReportBytes(
        report: JsonObject,
        target: StructuralTargetAbiV1,
        limits: StructuralRecoveryV1Limits = StructuralRecoveryV1Limits(),
    ): ByteArray {
        validateFixtureReport(report, target, limits)
        return canonicalStructuralReportBytes(report, limits.maximumReportBytes)
    }

    fun publishFixtureReport(
        path: Path,
        report: JsonObject,
        target: StructuralTargetAbiV1,
        limits: StructuralRecoveryV1Limits = StructuralRecoveryV1Limits(),
    ): StructuralPublishedReportV1 {
        val bytes = canonicalReportBytes(report, target, limits)
        return StructuralRecoveryV1Publication.publish(path, bytes, limits.maximumReportBytes)
    }

}

private val FIXTURE_VERIFICATION = JsonObject(
    mapOf(
        "status" to JsonPrimitive("fixture-digest-only"),
        "payloadDigestVerified" to JsonPrimitive(true),
        "identityMapPayloadDigestVerified" to JsonPrimitive(true),
        "adapterReplayVerified" to JsonPrimitive(false),
        "productionVerified" to JsonPrimitive(false),
    ),
)

private val FACT_RESULT_ORDER = Comparator<JsonObject> { left, right ->
    compareCodePoints(left.getValue("dimension").jsonString(), right.getValue("dimension").jsonString())
        .takeIf { it != 0 }
        ?: compareCodePoints(left.getValue("slot").jsonString(), right.getValue("slot").jsonString())
            .takeIf { it != 0 }
        ?: compareCodePoints(left.getValue("outcome").jsonString(), right.getValue("outcome").jsonString())
}

private val ENTITY_RESULT_ORDER = Comparator<JsonObject> { left, right ->
    compareCodePoints(left.getValue("kind").jsonString(), right.getValue("kind").jsonString())
        .takeIf { it != 0 }
        ?: compareCodePoints(left["oracleId"].nullableJsonString.orEmpty(), right["oracleId"].nullableJsonString.orEmpty())
            .takeIf { it != 0 }
        ?: compareCodePoints(left["recoveredId"].nullableJsonString.orEmpty(), right["recoveredId"].nullableJsonString.orEmpty())
}

private fun entityMap(value: JsonElement): Map<StructuralEntityKey, JsonObject> =
    (value as JsonArray).associate { raw ->
        val item = raw as JsonObject
        StructuralEntityKey(item.getValue("kind").jsonString(), item.getValue("id").jsonString()) to item
    }

private fun sortedFacts(entity: JsonObject, limits: StructuralRecoveryV1Limits): List<JsonObject> =
    entity.field("facts", "structural entity").requireArray("structural entity.facts", limits.maximumFactsPerEntity, 1)
        .map { it as JsonObject }
        .sortedWith { left, right ->
            compareCodePoints(left.getValue("dimension").jsonString(), right.getValue("dimension").jsonString())
                .takeIf { it != 0 }
                ?: compareCodePoints(left.getValue("slot").jsonString(), right.getValue("slot").jsonString())
                    .takeIf { it != 0 }
                ?: compareCodePoints(left.getValue("id").jsonString(), right.getValue("id").jsonString())
        }

private fun factSlot(fact: JsonElement): Pair<String, String> {
    fact as JsonObject
    return fact.getValue("dimension").jsonString() to fact.getValue("slot").jsonString()
}

private fun mappedRecoveredId(
    key: StructuralEntityKey,
    boundary: StructuralBoundaryMappingV1,
    identityMap: StructuralIdentityMapV1,
): String? = if (key.kind == "function") boundary.oracleToRecovered[key.id] else identityMap.oracleToRecovered[key]

private fun mappedOracleId(
    key: StructuralEntityKey,
    boundary: StructuralBoundaryMappingV1,
    identityMap: StructuralIdentityMapV1,
): String? = if (key.kind == "function") boundary.recoveredToOracle[key.id] else identityMap.recoveredToOracle[key]

private fun normalizeRecoveredValue(
    dimension: String,
    value: JsonObject,
    boundary: StructuralBoundaryMappingV1,
    identityMap: StructuralIdentityMapV1,
): Pair<JsonObject, Boolean?> {
    val source = value.getValue("source").jsonScalarString()
    val mapping = when {
        dimension == "call.internal" -> Triple("function:", "function", boundary.recoveredToOracle[source.removePrefix("function:")])
        dimension == "global.reference" -> Triple(
            "global:",
            "global",
            identityMap.recoveredToOracle[StructuralEntityKey("global", source.removePrefix("global:"))],
        )
        dimension in StructuralRecoveryV1Contract.TYPE_REFERENCE_DIMENSIONS && source.startsWith("type-entity:") -> Triple(
            "type-entity:",
            "type",
            identityMap.recoveredToOracle[StructuralEntityKey("type", source.removePrefix("type-entity:"))],
        )
        else -> null
    }
    if (mapping == null) return value to null
    if (mapping.third == null) return value to false
    return JsonObject(mapOf("source" to JsonPrimitive(mapping.first + mapping.third), "abi" to value.getValue("abi"))) to true
}

private fun factOutcome(
    dimension: String,
    oracleValue: JsonObject,
    recoveredValue: JsonObject,
    mappingVerified: Boolean?,
): String = when {
    mappingVerified == false -> "contradicted"
    oracleValue == recoveredValue -> "exact"
    dimension in StructuralRecoveryV1Contract.ABI_EQUIVALENT_DIMENSIONS &&
        oracleValue.getValue("abi") != JsonNull && oracleValue.getValue("abi") == recoveredValue.getValue("abi") ->
        "abi-equivalent"
    else -> "contradicted"
}

private fun factResult(
    dimension: String,
    slot: String,
    oracleFact: JsonObject,
    recoveredFact: JsonObject?,
    outcome: String,
    normalizedRecoveredValue: JsonElement,
    referenceMappingVerified: JsonElement,
): JsonObject = JsonObject(
    mapOf(
        "dimension" to JsonPrimitive(dimension),
        "slot" to JsonPrimitive(slot),
        "oracleFactId" to oracleFact.getValue("id"),
        "recoveredFactId" to (recoveredFact?.get("id") ?: JsonNull),
        "outcome" to JsonPrimitive(outcome),
        "oracleValue" to oracleFact.getValue("value"),
        "recoveredValue" to (recoveredFact?.get("value") ?: JsonNull),
        "normalizedRecoveredValue" to normalizedRecoveredValue,
        "referenceMappingVerified" to referenceMappingVerified,
        "oracleEvidence" to oracleFact.getValue("evidence"),
        "recoveredEvidence" to (recoveredFact?.get("evidence") ?: JsonArray(emptyList())),
    ),
)

private fun fabricatedFact(recoveredFact: JsonObject): JsonObject = JsonObject(
    mapOf(
        "dimension" to recoveredFact.getValue("dimension"),
        "slot" to recoveredFact.getValue("slot"),
        "oracleFactId" to JsonNull,
        "recoveredFactId" to recoveredFact.getValue("id"),
        "outcome" to JsonPrimitive("fabricated"),
        "oracleValue" to JsonNull,
        "recoveredValue" to recoveredFact.getValue("value"),
        "normalizedRecoveredValue" to JsonNull,
        "referenceMappingVerified" to JsonNull,
        "oracleEvidence" to JsonArray(emptyList()),
        "recoveredEvidence" to recoveredFact.getValue("evidence"),
    ),
)

private fun reportPolicy(limits: StructuralRecoveryV1Limits): JsonObject = JsonObject(
    mapOf(
        "identitySelection" to JsonPrimitive(StructuralRecoveryV1Contract.IDENTITY_SELECTION_POLICY),
        "abiEquivalence" to JsonPrimitive(StructuralRecoveryV1Contract.ABI_EQUIVALENCE_POLICY),
        "sourceNormalization" to JsonPrimitive(StructuralRecoveryV1Contract.SOURCE_NORMALIZATION_POLICY),
        "outcomeLattice" to JsonArray(StructuralRecoveryV1Contract.OUTCOMES.map(::JsonPrimitive)),
        "limits" to limits.reportPolicy(),
    ),
)

private fun targetBinding(target: StructuralTargetAbiV1): JsonObject = JsonObject(
    mapOf("id" to JsonPrimitive(target.id), "sha256" to JsonPrimitive(target.snapshot.sha256)),
)

private fun metricForDimension(dimension: String?, details: List<JsonObject>): JsonObject {
    val facts = details.flatMap { (it.getValue("facts") as JsonArray).map { fact -> fact as JsonObject } }
        .filter { dimension == null || it.getValue("dimension").jsonString() == dimension }
    return metricForFacts(JsonArray(facts))
}

private fun metricForFacts(facts: JsonArray): JsonObject {
    val counts = StructuralRecoveryV1Contract.OUTCOMES.associateWith { 0 }.toMutableMap()
    var oracleDenominator = 0
    var recoveredDenominator = 0
    facts.forEach { raw ->
        val fact = raw as JsonObject
        counts.compute(fact.getValue("outcome").jsonString()) { _, count -> (count ?: 0) + 1 }
        if (fact.getValue("oracleFactId") != JsonNull) oracleDenominator++
        if (fact.getValue("recoveredFactId") != JsonNull) recoveredDenominator++
    }
    val oraclePartition = StructuralRecoveryV1Contract.OUTCOMES.filter { it != "fabricated" }.sumOf(counts::getValue)
    if (oraclePartition != oracleDenominator) structuralFail("structural oracle denominator partition drift")
    val credit = counts.getValue("exact") + counts.getValue("abi-equivalent")
    return JsonObject(
        mapOf(
            "oracleDenominator" to JsonPrimitive(oracleDenominator),
            "recoveredDenominator" to JsonPrimitive(recoveredDenominator),
            "observableOracleCount" to JsonPrimitive(oracleDenominator - counts.getValue("oracle-unobservable")),
            "unobservableOracleCount" to JsonPrimitive(counts.getValue("oracle-unobservable")),
            "outcomes" to JsonObject(counts.mapValues { JsonPrimitive(it.value) }),
            "credit" to ratio(credit, oracleDenominator),
            "claimPrecision" to ratio(credit, recoveredDenominator),
        ),
    )
}

private fun ratio(numerator: Int, denominator: Int): JsonObject = JsonObject(
    mapOf(
        "numerator" to JsonPrimitive(numerator),
        "denominator" to JsonPrimitive(denominator),
        "value" to if (denominator == 0) JsonNull else JsonPrimitive(
            // Python v1 rounds the binary64 quotient, not the exact rational.
            BigDecimal(numerator.toDouble() / denominator.toDouble())
                .setScale(6, RoundingMode.HALF_EVEN)
                .toDouble(),
        ),
    ),
)

private fun JsonElement.jsonString(): String =
    (this as? JsonPrimitive)?.takeIf { it.isString }?.content ?: structuralFail("expected a JSON string")

private fun JsonElement.jsonScalarString(): String =
    (this as? JsonPrimitive)?.content ?: structuralFail("expected a JSON scalar")

private val JsonElement?.nullableJsonString: String?
    get() = if (this == null || this == JsonNull) null else this.jsonString()

private fun preflight(
    oracle: StructuralOracleV1,
    recovered: RecoveredStructureV1,
    boundary: StructuralBoundaryMappingV1,
    identityMap: StructuralIdentityMapV1,
    target: StructuralTargetAbiV1,
    limits: StructuralRecoveryV1Limits,
) {
    val totalInputBytes = listOf(
        oracle.snapshot.size,
        recovered.snapshot.size,
        boundary.snapshot.size,
        boundary.upstreamOracleSnapshot.size,
        identityMap.snapshot.size,
        target.snapshot.size,
    ).fold(0L) { total, size -> Math.addExact(total, size.toLong()) }
    if (totalInputBytes > limits.maximumTotalInputBytes) structuralFail("scorer inputs exceed the aggregate input budget")
    val oracleEntities = oracle.document.getValue("entities") as JsonArray
    val recoveredEntities = recovered.document.getValue("entities") as JsonArray
    val totalEntities = Math.addExact(oracleEntities.size, recoveredEntities.size)
    if (totalEntities > limits.maximumTotalEntities) structuralFail("scorer inputs exceed the aggregate entity budget")
    val oracleFacts = oracleEntities.flatMap { ((it as JsonObject).getValue("facts") as JsonArray).toList() }
    val recoveredFacts = recoveredEntities.flatMap { ((it as JsonObject).getValue("facts") as JsonArray).toList() }
    val totalFacts = Math.addExact(oracleFacts.size, recoveredFacts.size)
    if (totalFacts > limits.maximumTotalFacts) structuralFail("scorer inputs exceed the aggregate fact budget")
    var totalEvidence = 0L
    (oracleFacts + recoveredFacts).forEach { raw ->
        totalEvidence = Math.addExact(totalEvidence, ((raw as JsonObject).getValue("evidence") as JsonArray).size.toLong())
    }
    (identityMap.document.getValue("mappings") as JsonArray).forEach { raw ->
        totalEvidence = Math.addExact(totalEvidence, ((raw as JsonObject).getValue("evidence") as JsonArray).size.toLong())
    }
    if (totalEvidence > limits.maximumTotalEvidence) structuralFail("scorer inputs exceed the aggregate evidence budget")
    if (totalFacts > limits.maximumReportEntries) structuralFail("projected structural report exceeds the entry budget")
    var projection = Math.addExact(65_536L, Math.multiplyExact(totalEntities.toLong(), 512L))
    (oracleFacts + recoveredFacts).forEach { fact ->
        projection = Math.addExact(projection, Math.addExact(1_024L, Math.multiplyExact(2L, estimateJsonBytes(fact))))
        if (projection > limits.maximumProjectedReportBytes) {
            structuralFail("projected structural report exceeds the preconstruction byte budget")
        }
    }
}

private fun estimateJsonBytes(value: JsonElement): Long = when (value) {
    JsonNull -> 4L
    is JsonPrimitive -> when {
        value.isString -> Math.addExact(2L, Math.multiplyExact(value.content.codePointLength().toLong(), 8L))
        value.content in setOf("true", "false") -> 5L
        value.content.any { it in ".eE" } -> 32L
        else -> 24L
    }
    is JsonArray -> value.fold(Math.addExact(2L, value.size.toLong())) { total, item ->
        Math.addExact(total, estimateJsonBytes(item))
    }
    is JsonObject -> value.entries.fold(Math.addExact(2L, value.size.toLong())) { total, (key, item) ->
        Math.addExact(total, Math.addExact(estimateJsonBytes(JsonPrimitive(key)), estimateJsonBytes(item)))
    }
}

private fun validateIdentityUniverses(
    oracleEntities: Map<StructuralEntityKey, JsonObject>,
    recoveredEntities: Map<StructuralEntityKey, JsonObject>,
    boundary: StructuralBoundaryMappingV1,
) {
    val oracleFunctions = oracleEntities.keys.filterTo(hashSetOf()) { it.kind == "function" }.mapTo(hashSetOf()) { it.id }
    val recoveredFunctions = recoveredEntities.keys.filterTo(hashSetOf()) { it.kind == "function" }.mapTo(hashSetOf()) { it.id }
    if ((oracleFunctions - boundary.oracleFunctionIds).isNotEmpty()) {
        structuralFail("structural oracle function is absent from the selected boundary oracle universe")
    }
    if ((boundary.oracleFunctionIds - oracleFunctions).isNotEmpty()) {
        structuralFail("structural oracle omits functions from the selected boundary oracle universe")
    }
    val extraRecovered = recoveredFunctions - boundary.recoveredFunctionIds
    if ((extraRecovered intersect boundary.ignoredRecoveredIds).isNotEmpty()) {
        structuralFail("recovered structural function is excluded by the selected boundary report")
    }
    if (extraRecovered.isNotEmpty()) structuralFail("recovered structural function is absent from the selected recovered universe")
    if ((boundary.recoveredFunctionIds - recoveredFunctions).isNotEmpty()) {
        structuralFail("recovered structure omits functions from the selected recovered universe")
    }
    listOf(oracleEntities to false, recoveredEntities to true).forEach { (entities, recoveredSide) ->
        entities.forEach { (key, entity) ->
            (entity.getValue("facts") as JsonArray).forEach { raw ->
                val fact = raw as JsonObject
                val dimension = fact.getValue("dimension").jsonString()
                val slot = fact.getValue("slot").jsonString()
                if (key.kind == "function") {
                    slotRva(dimension, slot)?.let { rva ->
                        if (boundary.executableRvaRanges.none { (start, end) -> rva >= start && rva < end }) {
                            structuralFail("structural call/reference site is outside the selected executable ranges")
                        }
                    }
                }
                val value = fact.getValue("value")
                if (value == JsonNull) return@forEach
                val source = (value as JsonObject).getValue("source").jsonScalarString()
                when {
                    dimension == "call.internal" -> {
                        val endpoint = source.removePrefix("function:")
                        val universe = if (recoveredSide) boundary.recoveredFunctionIds else boundary.oracleFunctionIds
                        if (endpoint !in universe) structuralFail("internal-call endpoint is absent from the selected boundary universe")
                    }
                    dimension == "global.reference" -> if (StructuralEntityKey("global", source.removePrefix("global:")) !in entities) {
                        structuralFail("global-reference endpoint is absent from its structural entity universe")
                    }
                    dimension in StructuralRecoveryV1Contract.TYPE_REFERENCE_DIMENSIONS && source.startsWith("type-entity:") ->
                        if (StructuralEntityKey("type", source.removePrefix("type-entity:")) !in entities) {
                            structuralFail("type endpoint is absent from its structural entity universe")
                        }
                }
            }
        }
    }
}

private fun slotRva(dimension: String, slot: String): ULong? = when {
    dimension.startsWith("call.") -> StructuralRecoveryV1Contract.CALL_SLOT.matchEntire(slot)?.groupValues?.get(1)?.removePrefix("0x")?.toULong(16)
    dimension == "global.reference" -> StructuralRecoveryV1Contract.GLOBAL_REFERENCE_SLOT.matchEntire(slot)?.groupValues?.get(1)
        ?.removePrefix("0x")?.toULong(16)
    else -> null
}

private fun validateReportHeaders(
    report: JsonObject,
    target: StructuralTargetAbiV1,
    limits: StructuralRecoveryV1Limits,
) {
    try {
        OracleSchemas.validate("structural-score", report)
    } catch (failure: Exception) {
        throw StructuralRecoveryV1Exception("structural score report fails the bundled schema", failure)
    }
    report.requireObject(
        "structural score report",
        setOf(
            "schemaVersion",
            "oracle",
            "model",
            "targetAbi",
            "normalizationProfile",
            "boundaryMapping",
            "identityMapping",
            "policy",
            "dimensions",
            "aggregate",
            "entities",
        ),
    )
    requireSchemaVersion(report, "structural score report")
    val oracle = report.field("oracle", "structural score report").requireObject(
        "structural score report.oracle",
        setOf("id", "scope", "sha256", "artifactManifestSha256", "boundaryOracleId"),
    )
    val model = report.field("model", "structural score report").requireObject(
        "structural score report.model",
        setOf("id", "scope", "sha256", "payloadSha256", "verification", "provenance"),
    )
    oracle.field("id", "structural score report.oracle").requireIdentifier("structural score report.oracle.id", limits)
    oracle.field("sha256", "structural score report.oracle").requireSha256("structural score report.oracle.sha256")
    oracle.field("boundaryOracleId", "structural score report.oracle")
        .requireIdentifier("structural score report.oracle.boundaryOracleId", limits)
    model.field("id", "structural score report.model").requireIdentifier("structural score report.model.id", limits)
    model.field("sha256", "structural score report.model").requireSha256("structural score report.model.sha256")
    model.field("payloadSha256", "structural score report.model").requireSha256("structural score report.model.payloadSha256")
    val scope = oracle.field("scope", "structural score report.oracle")
        .requireString("structural score report.oracle.scope", 32)
    val modelScope = model.field("scope", "structural score report.model")
        .requireString("structural score report.model.scope", 32)
    if (scope !in setOf("fixture", "production") || modelScope != scope) {
        structuralFail("structural score oracle and model scopes must agree")
    }
    if (scope == "production") {
        structuralFail("production structural reports require a separate trusted adapter-replay verifier")
    }
    val verification = model.field("verification", "structural score report.model").requireObject(
        "structural score report.model.verification",
        setOf(
            "status",
            "payloadDigestVerified",
            "identityMapPayloadDigestVerified",
            "adapterReplayVerified",
            "productionVerified",
        ),
    )
    verification.field("status", "structural score report.model.verification")
        .requireString("structural score report.model.verification.status", 64)
    listOf("payloadDigestVerified", "identityMapPayloadDigestVerified", "adapterReplayVerified", "productionVerified")
        .forEach { key -> verification.field(key, "structural score report.model.verification").requireBoolean("model.verification.$key") }
    if (verification != FIXTURE_VERIFICATION) structuralFail("structural score verification contradicts its evidence scope")
    if (oracle.field("artifactManifestSha256", "structural score report.oracle") != JsonNull) {
        structuralFail("oracle manifest provenance contradicts the report scope")
    }

    validateTargetBinding(report.field("targetAbi", "structural score report"), "structural score report.targetAbi", target)
    val normalization = validateNormalizationProfile(
        report.field("normalizationProfile", "structural score report"),
        "structural score report.normalizationProfile",
    )
    val identity = report.field("identityMapping", "structural score report").requireObject(
        "structural score report.identityMapping",
        setOf("id", "sha256", "mappingCount", "verification", "productionVerified"),
    )
    identity.field("id", "structural score report.identityMapping")
        .requireIdentifier("structural score report.identityMapping.id", limits)
    identity.field("sha256", "structural score report.identityMapping")
        .requireSha256("structural score report.identityMapping.sha256")
    identity.field("mappingCount", "structural score report.identityMapping")
        .requireInt("structural score report.identityMapping.mappingCount", 0, limits.maximumMappings)
    if (identity.field("verification", "structural score report.identityMapping") != JsonPrimitive("fixture-payload-digest-only") ||
        identity.field("productionVerified", "structural score report.identityMapping") != JsonPrimitive(false)
    ) structuralFail("identity-map verification contradicts the report scope")

    val boundary = report.field("boundaryMapping", "structural score report").requireObject(
        "structural score report.boundaryMapping",
        setOf("scoreSha256", "twin", "projectionAdapter", "selectedFunctionCount"),
    )
    boundary.field("scoreSha256", "structural score report.boundaryMapping")
        .requireSha256("structural score report.boundaryMapping.scoreSha256")
    val twin = boundary.field("twin", "structural score report.boundaryMapping")
        .requireString("structural score report.boundaryMapping.twin", 32)
    if (twin !in setOf("rich", "stripped")) structuralFail("structural score boundary twin is invalid")
    boundary.field("selectedFunctionCount", "structural score report.boundaryMapping")
        .requireInt("structural score report.boundaryMapping.selectedFunctionCount", 0, limits.maximumMappings)
    val projection = boundary.field("projectionAdapter", "structural score report.boundaryMapping").requireObject(
        "structural score report.boundaryMapping.projectionAdapter",
        setOf("id", "version", "objectFormat"),
    )
    val expectedProjection = JsonObject(
        mapOf(
            "id" to JsonPrimitive(StructuralRecoveryV1Contract.BOUNDARY_PROJECTION_ADAPTER_ID),
            "version" to JsonPrimitive(StructuralRecoveryV1Contract.BOUNDARY_PROJECTION_ADAPTER_VERSION),
            "objectFormat" to JsonPrimitive(target.objectFormat),
        ),
    )
    if (projection != expectedProjection || target.objectFormat != "ELF") {
        structuralFail("structural score projection adapter does not match the supplied target")
    }

    val provenance = model.field("provenance", "structural score report.model").requireObject(
        "structural score report.model.provenance",
        setOf("inputBinary", "exporter", "loader", "targetAbi", "normalizationProfile", "boundaryScore", "identityMap"),
    )
    val input = provenance.field("inputBinary", "structural score report.model.provenance").requireObject(
        "structural score report.model.provenance.inputBinary",
        setOf("sha256", "sizeBytes"),
    )
    input.field("sha256", "structural score report.model.provenance.inputBinary")
        .requireSha256("structural score report.model.provenance.inputBinary.sha256")
    input.field("sizeBytes", "structural score report.model.provenance.inputBinary")
        .requireInteger("structural score report.model.provenance.inputBinary.sizeBytes", java.math.BigInteger.ONE)
    validateToolIdentity(
        provenance.field("exporter", "structural score report.model.provenance"),
        "structural score report.model.provenance.exporter",
        limits,
    )
    val loader = provenance.field("loader", "structural score report.model.provenance").requireObject(
        "structural score report.model.provenance.loader",
        setOf("id", "version", "executableSha256", "configurationSha256", "imageBase"),
    )
    validateToolIdentity(
        JsonObject(loader.filterKeys { it != "imageBase" }),
        "structural score report.model.provenance.loader",
        limits,
    )
    loader.field("imageBase", "structural score report.model.provenance.loader")
        .requireAddress("structural score report.model.provenance.loader.imageBase", target.maximumAddress)
    if (provenance.field("targetAbi", "structural score report.model.provenance") != report.field("targetAbi", "structural score report")) {
        structuralFail("structural report target provenance is internally inconsistent")
    }
    val provenanceNormalization = validateNormalizationProfile(
        provenance.field("normalizationProfile", "structural score report.model.provenance"),
        "structural score report.model.provenance.normalizationProfile",
    )
    if (provenanceNormalization != normalization) {
        structuralFail("structural report normalization-profile provenance is internally inconsistent")
    }
    val provenanceBoundary = provenance.field("boundaryScore", "structural score report.model.provenance").requireObject(
        "structural score report.model.provenance.boundaryScore",
        setOf("sha256", "twin", "projectionAdapter"),
    )
    val provenanceProjection = provenanceBoundary.field(
        "projectionAdapter",
        "structural score report.model.provenance.boundaryScore",
    ).requireObject(
        "structural score report.model.provenance.boundaryScore.projectionAdapter",
        setOf("id", "version"),
    )
    val expectedBoundaryProvenance = JsonObject(
        mapOf(
            "sha256" to boundary.getValue("scoreSha256"),
            "twin" to boundary.getValue("twin"),
            "projectionAdapter" to JsonObject(
                mapOf("id" to projection.getValue("id"), "version" to projection.getValue("version")),
            ),
        ),
    )
    if (provenanceBoundary != expectedBoundaryProvenance ||
        provenanceProjection != JsonObject(
            mapOf(
                "id" to JsonPrimitive(StructuralRecoveryV1Contract.BOUNDARY_PROJECTION_ADAPTER_ID),
                "version" to JsonPrimitive(StructuralRecoveryV1Contract.BOUNDARY_PROJECTION_ADAPTER_VERSION),
            ),
        )
    ) structuralFail("structural report boundary provenance is internally inconsistent")
    val provenanceIdentity = provenance.field("identityMap", "structural score report.model.provenance")
        .requireObject("structural score report.model.provenance.identityMap", setOf("sha256"))
    if (provenanceIdentity != JsonObject(mapOf("sha256" to identity.getValue("sha256")))) {
        structuralFail("structural report identity-map provenance is internally inconsistent")
    }
    val policy = report.field("policy", "structural score report").requireObject(
        "structural score report.policy",
        setOf("identitySelection", "abiEquivalence", "sourceNormalization", "outcomeLattice", "limits"),
    )
    if (policy != reportPolicy(limits)) structuralFail("structural score report policy does not match the checked scorer contract")
}

private fun validateReportBody(
    report: JsonObject,
    target: StructuralTargetAbiV1,
    limits: StructuralRecoveryV1Limits,
) {
    val dimensions = report.field("dimensions", "structural score report")
        .requireArray(
            "structural score report.dimensions",
            StructuralRecoveryV1Contract.DIMENSIONS.size,
            StructuralRecoveryV1Contract.DIMENSIONS.size,
        )
    dimensions.forEachIndexed { index, raw ->
        val expected = StructuralRecoveryV1Contract.DIMENSIONS[index]
        validateMetric(raw, "structural score report.dimensions[$index]", expected, limits)
    }
    validateMetric(report.field("aggregate", "structural score report"), "structural score report.aggregate", null, limits)

    val entities = report.field("entities", "structural score report")
        .requireArray("structural score report.entities", limits.maximumTotalEntities, 1)
    val validated = arrayListOf<JsonObject>()
    val oracleEntities = hashSetOf<StructuralEntityKey>()
    val recoveredEntities = hashSetOf<StructuralEntityKey>()
    val recoveredToOracle = linkedMapOf<StructuralEntityKey, String>()
    var previousEntity: Triple<String, String, String>? = null
    var totalFacts = 0
    var totalEvidence = 0L
    entities.forEachIndexed { entityIndex, raw ->
        val path = "structural score report.entities[$entityIndex]"
        val entity = raw.requireObject(path, setOf("kind", "oracleId", "recoveredId", "metric", "facts"))
        val kind = entity.field("kind", path).requireString("$path.kind", 32)
        if (kind !in setOf("function", "global", "type")) structuralFail("$path.kind is invalid")
        val oracleId = entity.field("oracleId", path).nullableIdentifier("$path.oracleId", limits)
        val recoveredId = entity.field("recoveredId", path).nullableIdentifier("$path.recoveredId", limits)
        if (oracleId == null && recoveredId == null) structuralFail("$path has no stable identity")
        if (oracleId != null && !oracleEntities.add(StructuralEntityKey(kind, oracleId))) {
            structuralFail("structural score report duplicates an oracle entity identity")
        }
        if (recoveredId != null && !recoveredEntities.add(StructuralEntityKey(kind, recoveredId))) {
            structuralFail("structural score report duplicates a recovered entity identity")
        }
        val entityKey = Triple(kind, oracleId.orEmpty(), recoveredId.orEmpty())
        if (previousEntity != null && compareEntityResultKeys(entityKey, previousEntity) <= 0) {
            structuralFail("structural score report entities are not in canonical code-point order")
        }
        previousEntity = entityKey
        if (oracleId != null && recoveredId != null) recoveredToOracle[StructuralEntityKey(kind, recoveredId)] = oracleId
        validateMetric(entity.field("metric", path), "$path.metric", null, limits)
        val facts = entity.field("facts", path).requireArray("$path.facts", limits.maximumFactsPerEntity, 1)
        totalFacts = Math.addExact(totalFacts, facts.size)
        if (totalFacts > limits.maximumReportEntries) structuralFail("structural score report exceeds the aggregate fact limit")
        val seenOracleFactIds = hashSetOf<String>()
        val seenRecoveredFactIds = hashSetOf<String>()
        val seenSlots = hashSetOf<Pair<String, String>>()
        var previousFact: Triple<String, String, String>? = null
        facts.forEachIndexed { factIndex, factRaw ->
            val factPath = "$path.facts[$factIndex]"
            val fact = factRaw.requireObject(
                factPath,
                setOf(
                    "dimension",
                    "slot",
                    "oracleFactId",
                    "recoveredFactId",
                    "outcome",
                    "oracleValue",
                    "recoveredValue",
                    "normalizedRecoveredValue",
                    "referenceMappingVerified",
                    "oracleEvidence",
                    "recoveredEvidence",
                ),
            )
            val dimension = fact.field("dimension", factPath).requireString("$factPath.dimension", 128)
            val outcome = fact.field("outcome", factPath).requireString("$factPath.outcome", 64)
            if (dimension !in StructuralRecoveryV1Contract.DIMENSIONS || outcome !in StructuralRecoveryV1Contract.OUTCOMES) {
                structuralFail("$factPath uses an unsupported dimension or outcome")
            }
            val slot = fact.field("slot", factPath).requireIdentifier("$factPath.slot", limits)
            if (!seenSlots.add(dimension to slot)) structuralFail("$path duplicates a fact dimension and slot")
            val factKey = Triple(dimension, slot, outcome)
            if (previousFact != null && compareFactResultKeys(factKey, previousFact) <= 0) {
                structuralFail("$path.facts are not in canonical code-point order")
            }
            previousFact = factKey
            fact.field("oracleFactId", factPath).nullableIdentifier("$factPath.oracleFactId", limits)?.let {
                if (!seenOracleFactIds.add(it)) structuralFail("$path duplicates oracleFactId")
            }
            fact.field("recoveredFactId", factPath).nullableIdentifier("$factPath.recoveredFactId", limits)?.let {
                if (!seenRecoveredFactIds.add(it)) structuralFail("$path duplicates recoveredFactId")
            }
            listOf("oracleEvidence", "recoveredEvidence").forEach { side ->
                val evidence = fact.field(side, factPath).requireArray("$factPath.$side", limits.maximumEvidencePerFact)
                totalEvidence = Math.addExact(totalEvidence, evidence.size.toLong())
                if (totalEvidence > limits.maximumTotalEvidence) {
                    structuralFail("structural score report exceeds the aggregate evidence limit")
                }
            }
        }
        validated += entity
    }

    val boundary = report.getValue("boundaryMapping") as JsonObject
    val identity = report.getValue("identityMapping") as JsonObject
    val selectedFunctionCount = boundary.getValue("selectedFunctionCount").requireInt("selectedFunctionCount", 0, limits.maximumMappings)
    val mappingCount = identity.getValue("mappingCount").requireInt("mappingCount", 0, limits.maximumMappings)
    val actualSelected = validated.count {
        it.getValue("kind") == JsonPrimitive("function") && it.getValue("oracleId") != JsonNull && it.getValue("recoveredId") != JsonNull
    }
    val actualIdentity = validated.count {
        it.getValue("kind").jsonString() in setOf("global", "type") &&
            it.getValue("oracleId") != JsonNull && it.getValue("recoveredId") != JsonNull
    }
    if (selectedFunctionCount != actualSelected) {
        structuralFail("structural score selected-function count disagrees with its entity rows")
    }
    if (mappingCount != actualIdentity) structuralFail("structural score identity-mapping count disagrees with its entity rows")

    validated.forEachIndexed { entityIndex, entity ->
        val path = "structural score report.entities[$entityIndex]"
        val facts = entity.getValue("facts") as JsonArray
        facts.forEachIndexed { factIndex, raw ->
            validateReportFact(
                raw,
                "$path.facts[$factIndex]",
                entity.getValue("kind").jsonString(),
                recoveredToOracle,
                oracleEntities,
                recoveredEntities,
                target,
                limits,
            )
        }
        val expected = metricForFacts(facts)
        if (!jsonNumericallyEquivalent(entity.getValue("metric"), expected)) {
            structuralFail("$path.metric does not match its fact rows")
        }
    }
    StructuralRecoveryV1Contract.DIMENSIONS.forEachIndexed { index, dimension ->
        val expected = JsonObject(mapOf("dimension" to JsonPrimitive(dimension)) + metricForDimension(dimension, validated))
        if (!jsonNumericallyEquivalent(dimensions[index], expected)) {
            structuralFail("structural score metric for $dimension is inconsistent")
        }
    }
    val expectedAggregate = metricForDimension(null, validated)
    if (!jsonNumericallyEquivalent(report.getValue("aggregate"), expectedAggregate)) {
        structuralFail("structural score aggregate is inconsistent")
    }
}

private fun validateMetric(
    value: JsonElement,
    path: String,
    dimension: String?,
    limits: StructuralRecoveryV1Limits,
): JsonObject {
    val keys = mutableSetOf(
        "oracleDenominator",
        "recoveredDenominator",
        "observableOracleCount",
        "unobservableOracleCount",
        "outcomes",
        "credit",
        "claimPrecision",
    )
    if (dimension != null) keys += "dimension"
    val metric = value.requireObject(path, keys)
    if (dimension != null && metric.field("dimension", path) != JsonPrimitive(dimension)) {
        structuralFail("$path.dimension is inconsistent")
    }
    listOf("oracleDenominator", "recoveredDenominator", "observableOracleCount", "unobservableOracleCount")
        .forEach { metric.field(it, path).requireInt("$path.$it", 0, limits.maximumReportEntries) }
    val outcomes = metric.field("outcomes", path).requireObject("$path.outcomes", StructuralRecoveryV1Contract.OUTCOMES.toSet())
    StructuralRecoveryV1Contract.OUTCOMES.forEach {
        outcomes.field(it, "$path.outcomes").requireInt("$path.outcomes.$it", 0, limits.maximumReportEntries)
    }
    listOf("credit", "claimPrecision").forEach { key ->
        val ratio = metric.field(key, path).requireObject("$path.$key", setOf("numerator", "denominator", "value"))
        ratio.field("numerator", "$path.$key").requireInt("$path.$key.numerator", 0, limits.maximumReportEntries)
        ratio.field("denominator", "$path.$key").requireInt("$path.$key.denominator", 0, limits.maximumReportEntries)
        val ratioValue = ratio.field("value", "$path.$key")
        if (ratioValue != JsonNull) {
            val primitive = ratioValue as? JsonPrimitive ?: structuralFail("$path.$key.value must be null or a finite ratio")
            if (primitive.isString || primitive.content in setOf("true", "false")) {
                structuralFail("$path.$key.value must be null or a finite ratio")
            }
            val number = primitive.content.toDoubleOrNull()
            if (number == null || !number.isFinite() || number !in 0.0..1.0) {
                structuralFail("$path.$key.value must be null or a finite ratio")
            }
        }
    }
    return metric
}

private fun validateReportFact(
    value: JsonElement,
    path: String,
    entityKind: String,
    recoveredToOracle: Map<StructuralEntityKey, String>,
    oracleEntityIds: Set<StructuralEntityKey>,
    recoveredEntityIds: Set<StructuralEntityKey>,
    target: StructuralTargetAbiV1,
    limits: StructuralRecoveryV1Limits,
) {
    val item = value as JsonObject
    val dimension = item.getValue("dimension").jsonString()
    val outcome = item.getValue("outcome").jsonString()
    if (StructuralRecoveryV1Contract.DIMENSION_ENTITY_KIND[dimension] != entityKind) {
        structuralFail("$path.dimension is incompatible with its report entity kind")
    }
    validateSlot(dimension, item.getValue("slot"), "$path.slot", target, limits)
    val oracleFactId = item.getValue("oracleFactId").nullableIdentifier("$path.oracleFactId", limits)
    val recoveredFactId = item.getValue("recoveredFactId").nullableIdentifier("$path.recoveredFactId", limits)
    val oracleValue = item.getValue("oracleValue").nullableReportValue("$path.oracleValue", dimension, target, limits)
    val recoveredValue = item.getValue("recoveredValue").nullableReportValue("$path.recoveredValue", dimension, target, limits)
    val normalizedValue = item.getValue("normalizedRecoveredValue")
        .nullableReportValue("$path.normalizedRecoveredValue", dimension, target, limits)
    oracleValue?.let { validateReferenceEndpoint(dimension, it, oracleEntityIds, "$path.oracleValue") }
    recoveredValue?.let { validateReferenceEndpoint(dimension, it, recoveredEntityIds, "$path.recoveredValue") }
    val verifiedElement = item.getValue("referenceMappingVerified")
    val verified = if (verifiedElement == JsonNull) null else verifiedElement.requireBoolean("$path.referenceMappingVerified")
    when (outcome) {
        "exact", "abi-equivalent", "contradicted" -> {
            if (oracleFactId == null || recoveredFactId == null || oracleValue == null || recoveredValue == null || normalizedValue == null) {
                structuralFail("$path has impossible concrete-outcome nullability")
            }
            val expected = normalizeReportRecoveredValue(dimension, recoveredValue, recoveredToOracle)
            if (normalizedValue != expected.first || verified != expected.second) {
                structuralFail("$path has an inconsistent normalized comparison binding")
            }
            if (outcome != factOutcome(dimension, oracleValue, expected.first, expected.second)) {
                structuralFail("$path.outcome does not match its normalized values")
            }
        }
        "recovered-unknown" -> if (oracleFactId == null || oracleValue == null || recoveredValue != null) {
            structuralFail("$path has impossible recovered-unknown nullability")
        }
        "oracle-unobservable" -> if (oracleFactId == null || oracleValue != null) {
            structuralFail("$path has impossible oracle-unobservable nullability")
        }
        "fabricated" -> if (oracleFactId != null || oracleValue != null || recoveredFactId == null) {
            structuralFail("$path has impossible fabricated nullability")
        }
    }
    if (outcome !in setOf("exact", "abi-equivalent", "contradicted") && (normalizedValue != null || verified != null)) {
        structuralFail("$path carries a comparison binding for an outcome without a comparison")
    }
    listOf("oracleEvidence" to oracleFactId, "recoveredEvidence" to recoveredFactId).forEach { (key, factId) ->
        val evidence = item.getValue(key).requireArray("$path.$key", limits.maximumEvidencePerFact)
        val seen = hashSetOf<Pair<String, String>>()
        evidence.forEachIndexed { index, raw ->
            val evidencePath = "$path.$key[$index]"
            val evidenceItem = raw.requireObject(evidencePath, setOf("kind", "locator"))
            val kind = evidenceItem.field("kind", evidencePath).requireString("$evidencePath.kind", 128)
            val locator = evidenceItem.field("locator", evidencePath)
                .requireString("$evidencePath.locator", limits.maximumTextCharacters)
            if (!seen.add(kind to locator)) structuralFail("$path.$key contains duplicate evidence")
        }
        if ((factId == null) != evidence.isEmpty()) structuralFail("$path has inconsistent fact identity and evidence")
    }
    if (oracleFactId == null && oracleValue != null) structuralFail("$path has a value without an oracle fact identity")
    if (recoveredFactId == null && recoveredValue != null) structuralFail("$path has a value without a recovered fact identity")
}

private fun JsonElement.nullableIdentifier(path: String, limits: StructuralRecoveryV1Limits): String? =
    if (this == JsonNull) null else requireIdentifier(path, limits)

private fun JsonElement.nullableReportValue(
    path: String,
    dimension: String,
    target: StructuralTargetAbiV1,
    limits: StructuralRecoveryV1Limits,
): JsonObject? = if (this == JsonNull) null else validateStructuralValue(this, path, dimension, target, limits)

private fun normalizeReportRecoveredValue(
    dimension: String,
    value: JsonObject,
    recoveredToOracle: Map<StructuralEntityKey, String>,
): Pair<JsonObject, Boolean?> {
    val source = value.getValue("source").jsonScalarString()
    val reference = when {
        dimension == "call.internal" -> "function" to "function:"
        dimension == "global.reference" -> "global" to "global:"
        dimension in StructuralRecoveryV1Contract.TYPE_REFERENCE_DIMENSIONS && source.startsWith("type-entity:") ->
            "type" to "type-entity:"
        else -> null
    } ?: return value to null
    val oracleId = recoveredToOracle[StructuralEntityKey(reference.first, source.removePrefix(reference.second))]
        ?: return value to false
    return JsonObject(
        mapOf("source" to JsonPrimitive(reference.second + oracleId), "abi" to value.getValue("abi")),
    ) to true
}

private fun validateReferenceEndpoint(
    dimension: String,
    value: JsonObject,
    universe: Set<StructuralEntityKey>,
    path: String,
) {
    val source = value.getValue("source").jsonScalarString()
    val reference = when {
        dimension == "call.internal" -> "function" to "function:"
        dimension == "global.reference" -> "global" to "global:"
        dimension in StructuralRecoveryV1Contract.TYPE_REFERENCE_DIMENSIONS && source.startsWith("type-entity:") ->
            "type" to "type-entity:"
        else -> null
    } ?: return
    if (StructuralEntityKey(reference.first, source.removePrefix(reference.second)) !in universe) {
        structuralFail("$path.source references an entity absent from the report universe")
    }
}

private fun compareEntityResultKeys(left: Triple<String, String, String>, right: Triple<String, String, String>): Int =
    compareCodePoints(left.first, right.first).takeIf { it != 0 }
        ?: compareCodePoints(left.second, right.second).takeIf { it != 0 }
        ?: compareCodePoints(left.third, right.third)

private fun compareFactResultKeys(left: Triple<String, String, String>, right: Triple<String, String, String>): Int =
    compareCodePoints(left.first, right.first).takeIf { it != 0 }
        ?: compareCodePoints(left.second, right.second).takeIf { it != 0 }
        ?: compareCodePoints(left.third, right.third)

private fun jsonNumericallyEquivalent(left: JsonElement, right: JsonElement): Boolean = when {
    left is JsonObject && right is JsonObject ->
        left.keys == right.keys && left.keys.all { jsonNumericallyEquivalent(left.getValue(it), right.getValue(it)) }
    left is JsonArray && right is JsonArray ->
        left.size == right.size && left.indices.all { jsonNumericallyEquivalent(left[it], right[it]) }
    left is JsonPrimitive && right is JsonPrimitive -> {
        if (left.isString || right.isString || left.content in setOf("true", "false") || right.content in setOf("true", "false")) {
            left == right
        } else {
            try {
                BigDecimal(left.content).compareTo(BigDecimal(right.content)) == 0
            } catch (_: NumberFormatException) {
                left == right
            }
        }
    }
    else -> left == right
}
