package decompengine.oracle.structural

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import decompengine.oracle.core.OracleArtifacts
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** A source value already typed by a trusted capture adapter; display text is not accepted here. */
sealed interface StructuralRecoveredSourceV1 {
    data class Text(val value: String) : StructuralRecoveredSourceV1
    data class Integer(val value: BigInteger) : StructuralRecoveredSourceV1
    data class BooleanValue(val value: Boolean) : StructuralRecoveredSourceV1
}

enum class StructuralRecoveredFactStateV1 { RECOVERED, RECOVERED_UNKNOWN }

data class StructuralRecoveredFactObservationV1(
    val dimension: String,
    val slot: String,
    val state: StructuralRecoveredFactStateV1,
    val value: StructuralRecoveredSourceV1? = null,
    val abi: JsonElement = JsonNull,
    val evidence: List<StructuralRecoveredEvidenceV1>,
)

data class StructuralRecoveredEvidenceV1(val kind: String, val locator: String)

/**
 * The census includes function entities only to carry global.reference facts, whose frozen v1
 * ownership is function-scoped. No function ABI or call dimensions are accepted here.
 */
data class StructuralRecoveredEntityObservationV1(
    val kind: String,
    val id: String,
    val facts: List<StructuralRecoveredFactObservationV1>,
)

class StructuralGlobalTypeProjectionV1 internal constructor(
    val projectedEntities: JsonArray,
    unprojectableEntityKeys: List<StructuralEntityKey>,
    inputEntityKeys: List<StructuralEntityKey>,
) {
    val unprojectableEntityKeys: List<StructuralEntityKey> = unprojectableEntityKeys.toList()
    val inputEntityKeys: List<StructuralEntityKey> = inputEntityKeys.toList()

    val entityCensusConserved: Boolean
        get() = projectedEntities.size + unprojectableEntityKeys.size == inputEntityKeys.size

    /** True only for the supplied census; it says nothing about entities omitted by the caller. */
    val allInputEntitiesProjectable: Boolean
        get() = inputEntityKeys.isNotEmpty() && entityCensusConserved && unprojectableEntityKeys.isEmpty()

    /** Guard for fixture-side use only; passing it is not production authority or full-population proof. */
    fun requireAllInputEntitiesProjectableForFixtureScoring(): JsonArray {
        if (!allInputEntitiesProjectable) {
            structuralFail("supplied recovered census is empty or has unprojectable entities; fixture scoring is forbidden")
        }
        return projectedEntities
    }
}

/** Projects typed recovered observations into the existing frozen recovered-structure v1 rows. */
object StructuralGlobalTypeRecoveredProjectionV1 {
    fun project(
        entities: List<StructuralRecoveredEntityObservationV1>,
        target: StructuralTargetAbiV1,
        limits: StructuralRecoveryV1Limits = StructuralRecoveryV1Limits(),
    ): StructuralGlobalTypeProjectionV1 {
        if (entities.size > limits.maximumEntities) structuralFail("recovered G/T entity census exceeds entity limit")
        preflight(entities, limits)
        val seen = hashSetOf<StructuralEntityKey>()
        var totalFacts = 0
        var totalEvidence = 0
        val projected = arrayListOf<JsonObject>()
        val unknown = arrayListOf<StructuralEntityKey>()
        val keys = arrayListOf<StructuralEntityKey>()
        entities.forEach { entity ->
            val key = StructuralEntityKey(entity.kind, entity.id)
            if (entity.kind !in setOf("function", "global", "type")) structuralFail("unsupported recovered entity kind")
            if (entity.id.length > limits.maximumIdentifierCharacters ||
                !StructuralRecoveryV1Contract.IDENTIFIER.matches(entity.id)
            ) structuralFail("invalid recovered entity ID")
            if (!seen.add(key)) structuralFail("duplicate recovered entity identity: ${entity.kind}/${entity.id}")
            keys += key
            if (entity.facts.isEmpty()) {
                unknown += key
                return@forEach
            }
            if (entity.facts.size > limits.maximumFactsPerEntity) structuralFail("entity exceeds recovered fact limit")
            totalFacts = Math.addExact(totalFacts, entity.facts.size)
            if (totalFacts > limits.maximumFacts) structuralFail("recovered observations exceed fact limit")
            val seenSlots = hashSetOf<Pair<String, String>>()
            val factRows = entity.facts.sortedWith { left, right ->
                StructuralRecoveryV1Contract.CODE_POINT_ORDER.compare(left.dimension, right.dimension)
                    .takeIf { it != 0 } ?: StructuralRecoveryV1Contract.CODE_POINT_ORDER.compare(left.slot, right.slot)
            }.map { fact ->
                val expectedKind = StructuralRecoveryV1Contract.DIMENSION_ENTITY_KIND[fact.dimension]
                    ?: structuralFail("unsupported recovered dimension: ${fact.dimension}")
                if (expectedKind != entity.kind) structuralFail("${fact.dimension} is incompatible with ${entity.kind} entities")
                if (entity.kind == "function" && fact.dimension != "global.reference") {
                    structuralFail("function entity may carry only global.reference observations in this projection")
                }
                if (fact.slot.isBlank() || fact.slot.length > limits.maximumIdentifierCharacters) structuralFail("invalid recovered fact slot")
                if (!seenSlots.add(fact.dimension to fact.slot)) structuralFail("duplicate recovered dimension/slot")
                val value = when (fact.state) {
                    StructuralRecoveredFactStateV1.RECOVERED -> {
                        val source = fact.value ?: structuralFail("recovered observation requires a typed source value")
                        JsonObject(mapOf("source" to source.toJson(), "abi" to fact.abi))
                    }
                    StructuralRecoveredFactStateV1.RECOVERED_UNKNOWN -> {
                        if (fact.value != null || fact.abi != JsonNull) structuralFail("recovered-unknown cannot carry a value")
                        JsonNull
                    }
                }
                if (fact.evidence.isEmpty() || fact.evidence.size > limits.maximumEvidencePerFact) {
                    structuralFail("recovered observation evidence count is invalid")
                }
                totalEvidence = Math.addExact(totalEvidence, fact.evidence.size)
                if (totalEvidence > limits.maximumTotalEvidence) structuralFail("recovered observations exceed evidence limit")
                val evidenceRows = fact.evidence.sortedWith { left, right ->
                    StructuralRecoveryV1Contract.CODE_POINT_ORDER.compare(left.kind, right.kind)
                        .takeIf { it != 0 } ?: StructuralRecoveryV1Contract.CODE_POINT_ORDER.compare(left.locator, right.locator)
                }.map { JsonObject(mapOf("kind" to JsonPrimitive(it.kind), "locator" to JsonPrimitive(it.locator))) }
                if (evidenceRows.toSet().size != evidenceRows.size) structuralFail("duplicate recovered observation evidence")
                val factId = "gt-${StructuralRecoveryV1Contract.sha256Hex(fact.dimension + "\u0000" + fact.slot)}"
                JsonObject(
                    mapOf(
                        "id" to JsonPrimitive(factId),
                        "slot" to JsonPrimitive(fact.slot),
                        "dimension" to JsonPrimitive(fact.dimension),
                        "state" to JsonPrimitive(if (fact.state == StructuralRecoveredFactStateV1.RECOVERED) "recovered" else "recovered-unknown"),
                        "value" to value,
                        "evidence" to JsonArray(evidenceRows),
                    ),
                )
            }
            projected += JsonObject(
                mapOf("kind" to JsonPrimitive(entity.kind), "id" to JsonPrimitive(entity.id), "facts" to JsonArray(factRows)),
            )
        }
        val sortedProjected = projected.sortedWith { left, right ->
            StructuralRecoveryV1Contract.ENTITY_KEY_ORDER.compare(left.entityKey(), right.entityKey())
        }
        val sortedUnknown = unknown.sortedWith(StructuralRecoveryV1Contract.ENTITY_KEY_ORDER)
        val sortedKeys = keys.sortedWith(StructuralRecoveryV1Contract.ENTITY_KEY_ORDER)
        val json = JsonArray(sortedProjected)
        // Reuse the frozen validator, including canonical target slots and typed value rules.
        if (json.isNotEmpty()) validateEntities(json, "projected recovered structure.entities", true, target, limits)
        val result = StructuralGlobalTypeProjectionV1(json, sortedUnknown, sortedKeys)
        check(result.entityCensusConserved)
        return result
    }

    private fun StructuralRecoveredSourceV1.toJson(): JsonPrimitive = when (this) {
        is StructuralRecoveredSourceV1.Text -> JsonPrimitive(value)
        is StructuralRecoveredSourceV1.Integer -> JsonPrimitive(value)
        is StructuralRecoveredSourceV1.BooleanValue -> JsonPrimitive(value)
    }

    private fun JsonObject.entityKey(): StructuralEntityKey = StructuralEntityKey(
        (getValue("kind") as JsonPrimitive).content,
        (getValue("id") as JsonPrimitive).content,
    )

    private fun StructuralRecoveryV1Contract.sha256Hex(value: String): String =
        OracleArtifacts.sha256(value.toByteArray(StandardCharsets.UTF_8))

    private fun preflight(entities: List<StructuralRecoveredEntityObservationV1>, limits: StructuralRecoveryV1Limits) {
        var facts = 0
        var evidence = 0
        var textBytes = 0L
        var abiNodes = 0L
        var estimatedOutputBytes = 0L
        fun addText(value: String, maximum: Int, label: String) {
            if (value.length > maximum) structuralFail("$label exceeds configured character limit")
            var index = 0
            while (index < value.length) {
                val character = value[index]
                when {
                    Character.isHighSurrogate(character) -> {
                        if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) {
                            structuralFail("$label contains malformed UTF-16")
                        }
                        index += 2
                    }
                    Character.isLowSurrogate(character) -> structuralFail("$label contains malformed UTF-16")
                    else -> index += 1
                }
            }
            val bytes = value.toByteArray(StandardCharsets.UTF_8).size.toLong()
            textBytes = Math.addExact(textBytes, bytes)
            // JSON escaping expands a control character to six ASCII bytes; applying that
            // worst-case factor before any row is allocated also bounds quoted strings.
            estimatedOutputBytes = Math.addExact(estimatedOutputBytes, Math.addExact(Math.multiplyExact(bytes, 6L), 16L))
            if (textBytes > limits.maximumJsonInputBytes) structuralFail("recovered observation text exceeds input byte limit")
            if (estimatedOutputBytes > minOf(limits.maximumReportBytes.toLong(), limits.maximumProjectedReportBytes)) {
                structuralFail("recovered projection exceeds configured output byte limit")
            }
        }
        fun visit(value: JsonElement, depth: Int) {
            if (depth > 64) structuralFail("ABI projection exceeds JSON depth limit")
            abiNodes = Math.addExact(abiNodes, 1L)
            if (abiNodes > limits.maximumFacts.toLong() * 32L) structuralFail("ABI projections exceed JSON node limit")
            estimatedOutputBytes = Math.addExact(estimatedOutputBytes, 8L)
            when (value) {
                is JsonObject -> value.forEach { (key, child) -> addText(key, limits.maximumTextCharacters, "ABI key"); visit(child, depth + 1) }
                is JsonArray -> value.forEach { visit(it, depth + 1) }
                is JsonPrimitive -> {
                    if (value.isString) {
                        addText(value.content, limits.maximumTextCharacters, "ABI text")
                    } else if (value.content.length > limits.maximumJsonNumberCharacters) {
                        structuralFail("ABI numeric primitive exceeds configured number limit")
                    }
                }
            }
            if (estimatedOutputBytes > minOf(limits.maximumReportBytes.toLong(), limits.maximumProjectedReportBytes)) {
                structuralFail("recovered projection exceeds configured output byte limit")
            }
        }
        entities.forEach { entity ->
            addText(entity.kind, 32, "entity kind")
            addText(entity.id, limits.maximumIdentifierCharacters, "entity ID")
            if (entity.facts.size > limits.maximumFactsPerEntity) structuralFail("entity exceeds recovered fact limit")
            facts = Math.addExact(facts, entity.facts.size)
            if (facts > limits.maximumFacts || facts > limits.maximumTotalFacts) structuralFail("recovered observations exceed fact limit")
            entity.facts.forEach { fact ->
                estimatedOutputBytes = Math.addExact(estimatedOutputBytes, 128L)
                addText(fact.dimension, 128, "dimension")
                addText(fact.slot, limits.maximumIdentifierCharacters, "slot")
                when (val source = fact.value) {
                    is StructuralRecoveredSourceV1.Text -> addText(source.value, limits.maximumTextCharacters, "source text")
                    is StructuralRecoveredSourceV1.Integer -> {
                        val maxBitsBeforeDecimalConversion = limits.maximumJsonNumberCharacters.toLong() * 4L
                        if (source.value.bitLength().toLong() > maxBitsBeforeDecimalConversion ||
                            source.value.toString().length > limits.maximumJsonNumberCharacters
                        ) structuralFail("integer source exceeds configured number limit")
                    }
                    is StructuralRecoveredSourceV1.BooleanValue, null -> Unit
                }
                if (fact.evidence.isEmpty()) structuralFail("observation evidence must not be empty")
                visit(fact.abi, 0)
                if (fact.evidence.size > limits.maximumEvidencePerFact) structuralFail("observation exceeds evidence limit")
                evidence = Math.addExact(evidence, fact.evidence.size)
                if (evidence > limits.maximumTotalEvidence) structuralFail("recovered observations exceed evidence limit")
                fact.evidence.forEach { row ->
                    estimatedOutputBytes = Math.addExact(estimatedOutputBytes, 24L)
                    addText(row.kind, 128, "evidence kind")
                    addText(row.locator, limits.maximumTextCharacters, "evidence locator")
                }
            }
            estimatedOutputBytes = Math.addExact(estimatedOutputBytes, 48L)
            if (estimatedOutputBytes > minOf(limits.maximumReportBytes.toLong(), limits.maximumProjectedReportBytes)) {
                structuralFail("recovered projection exceeds configured output byte limit")
            }
        }
    }
}
