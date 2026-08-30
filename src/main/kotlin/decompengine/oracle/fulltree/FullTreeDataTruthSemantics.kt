package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.math.BigInteger
import java.security.MessageDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class FullTreeDataTruthException(message: String) : IllegalArgumentException(message)

data class FullTreeDataTruthPartition(
    val globals: List<JsonObject>,
    val types: List<JsonObject>,
)

/**
 * Pure canonical semantics shared by full-tree data-truth generation and validation.
 *
 * This object deliberately has no filesystem, process, database, or ACP dependency. Callers must
 * authenticate observations before passing them here and must independently validate/publish the
 * resulting documents.
 */
object FullTreeDataTruthSemantics {
    const val REFERENCE_SAMPLE_LIMIT: Int = 16

    fun typeIdentity(item: JsonObject, limits: StrictJsonLimits = StrictJsonLimits()): String {
        val declaration = declarationKey(item)
        val observableLocation = declaration.isObservableLocation()
        val identity = linkedMapOf<String, JsonElement>()
        if (observableLocation) {
            identity["tag"] = item.required("tag")
            identity["context"] = item.required("context")
            identity["name"] = item.required("name")
            identity["declaration"] = declaration
            val name = item.required("name").nullableString()
            val context = item.required("context").jsonArray.map { it.jsonPrimitive.content }
            when {
                name?.contains("lambda at ") == true || "DW_TAG_subprogram:(anonymous)" in context ->
                    identity["producerObservationId"] = item.required("id")
                name?.contains("anonymous namespace") == true || context.any { "anonymous namespace" in it } ->
                    identity["producerUnitId"] = item.required("unitId")
            }
        } else {
            identity["observationId"] = item.required("id")
        }
        return canonicalSha256(JsonObject(identity), limits)
    }

    fun globalIdentity(item: JsonObject, limits: StrictJsonLimits = StrictJsonLimits()): String {
        val declaration = declarationKey(item)
        val identity = when {
            item.required("addressRva") !is JsonNull -> JsonObject(mapOf("rva" to item.required("addressRva")))
            declaration.isObservableLocation() -> JsonObject(
                mapOf(
                    "names" to item.required("names"),
                    "declaration" to declaration,
                ),
            )
            else -> JsonObject(mapOf("observationId" to item.required("id")))
        }
        return canonicalSha256(identity, limits)
    }

    fun uniqueValues(
        records: Iterable<JsonObject>,
        field: String,
        limits: StrictJsonLimits = StrictJsonLimits(),
    ): List<JsonElement> {
        val unique = sortedMapOf<CanonicalBytes, JsonElement>()
        records.forEach { record ->
            val value = record.required(field)
            unique[CanonicalBytes(OracleJson.canonicalBytes(value, limits))] = value
        }
        return unique.values.toList()
    }

    fun oneCompatible(
        records: List<JsonObject>,
        field: String,
        identity: String,
        limits: StrictJsonLimits = StrictJsonLimits(),
    ): JsonElement? {
        val known = sortedMapOf<CanonicalBytes, JsonElement>()
        records.forEach { record ->
            val value = record.required(field)
            if (value !is JsonNull && value.nullableString() != "unknown") {
                known[CanonicalBytes(OracleJson.canonicalBytes(value, limits))] = value
            }
        }
        if (known.size > 1) {
            throw FullTreeDataTruthException("incompatible $field definitions for $identity")
        }
        return known.values.singleOrNull()
    }

    fun mergeTypeReferences(
        references: Iterable<JsonObject>,
        identity: String,
        limits: StrictJsonLimits = StrictJsonLimits(),
    ): JsonObject {
        val records = references.toList()
        if (records.isEmpty()) throw FullTreeDataTruthException("type reference population is empty for $identity")
        val modifiers = records.mapTo(sortedSetOf()) {
            CanonicalBytes(OracleJson.canonicalBytes(it.required("modifierTags"), limits))
        }
        val reasons = records.mapTo(linkedSetOf()) { it.required("reasonCode") }
        if (modifiers.size != 1 || reasons.size != 1) {
            throw FullTreeDataTruthException("incompatible type references for $identity")
        }

        val candidatesByBytes = sortedMapOf<CanonicalBytes, JsonObject>()
        records.filter { it.required("targetTypeId") !is JsonNull }.forEach { record ->
            val candidate = JsonObject(
                mapOf(
                    "targetOwnerShardId" to record.required("targetOwnerShardId"),
                    "targetTypeId" to record.required("targetTypeId"),
                ),
            )
            candidatesByBytes[CanonicalBytes(OracleJson.canonicalBytes(candidate, limits))] = candidate
        }
        var orderedCandidates = candidatesByBytes.values.toList()
        val targets = orderedCandidates.mapTo(linkedSetOf()) { it.required("targetTypeId").jsonPrimitive.content }

        val selected: JsonObject
        val resolutionCode: String
        when {
            targets.isEmpty() -> {
                selected = records.first()
                resolutionCode = "unresolved"
            }
            targets.size == 1 -> {
                selected = records.first { it.required("targetTypeId") !is JsonNull }
                resolutionCode = "exact-dwarf-offset"
            }
            else -> {
                val sourceAligned = records
                    .filter { it.required("_targetQuality").nullableString() == "source-aligned" }
                    .mapNotNullTo(linkedSetOf()) { it.required("targetTypeId").nullableString() }
                val otherQualities = records
                    .filter { it.required("targetTypeId").nullableString() !in sourceAligned }
                    .mapTo(linkedSetOf()) { it.required("_targetQuality").nullableString() }
                if (sourceAligned.size == 1 && otherQualities.all { it == "producer-declaration" }) {
                    val selectedId = sourceAligned.single()
                    selected = records.first { it.required("targetTypeId").nullableString() == selectedId }
                    resolutionCode = "odr-member-sole-source-aligned-target"
                } else {
                    selected = JsonObject(
                        records.first().toMutableMap().apply {
                            this["reasonCode"] = JsonPrimitive("ambiguous-authenticated-targets")
                            this["targetOwnerShardId"] = JsonNull
                            this["targetTypeId"] = JsonNull
                        },
                    )
                    resolutionCode = "unresolved-authenticated-target-set"
                }
            }
        }

        val evidenceOffsets = records
            .flatMap { it.required("evidenceDieOffsets").jsonArray }
            .map { it.jsonPrimitive.content }
            .distinct()
            .sortedBy(::hexOffset)
        val selectedTarget = selected.required("targetTypeId").nullableString()
        if (selectedTarget != null) {
            orderedCandidates = orderedCandidates.sortedWith(
                compareBy<JsonObject> { it.required("targetTypeId").jsonPrimitive.content != selectedTarget }
                    .thenBy { CanonicalBytes(OracleJson.canonicalBytes(it, limits)) },
            )
        }

        val merged = linkedMapOf<String, JsonElement>(
            "evidenceDieOffsets" to JsonArray(evidenceOffsets.take(REFERENCE_SAMPLE_LIMIT).map(::JsonPrimitive)),
            "modifierTags" to selected.required("modifierTags"),
            "reasonCode" to selected.required("reasonCode"),
            "resolutionCode" to JsonPrimitive(resolutionCode),
            "targetOwnerShardId" to selected.required("targetOwnerShardId"),
            "targetTypeId" to selected.required("targetTypeId"),
        )
        if (orderedCandidates.size > 1) {
            merged["candidateTargetCount"] = JsonPrimitive(orderedCandidates.size)
            merged["candidateTargets"] = JsonArray(orderedCandidates.take(REFERENCE_SAMPLE_LIMIT))
            merged["candidateTargetsSha256"] = JsonPrimitive(
                canonicalSha256(JsonArray(orderedCandidates), limits),
            )
        }
        if (evidenceOffsets.size > REFERENCE_SAMPLE_LIMIT) {
            merged["evidenceDieOffsetCount"] = JsonPrimitive(evidenceOffsets.size)
            merged["evidenceDieOffsetsSha256"] = JsonPrimitive(
                canonicalSha256(JsonArray(evidenceOffsets.map(::JsonPrimitive)), limits),
            )
        }
        return JsonObject(merged)
    }

    fun partitionTruthEntities(
        globals: List<JsonObject>,
        types: List<JsonObject>,
        entityByteBudget: Int,
        limits: StrictJsonLimits = StrictJsonLimits(),
    ): List<FullTreeDataTruthPartition> {
        if (entityByteBudget < 1) throw FullTreeDataTruthException("data truth partition budget is invalid")
        val partitions = mutableListOf<FullTreeDataTruthPartition>()
        var partitionGlobals = mutableListOf<JsonObject>()
        var partitionTypes = mutableListOf<JsonObject>()
        var estimatedBytes = 0L

        fun add(kind: EntityKind, item: JsonObject) {
            val itemBytes = OracleJson.canonicalBytes(item, limits).size.toLong() + 1L
            if (estimatedBytes > 0L && estimatedBytes + itemBytes > entityByteBudget.toLong()) {
                partitions += FullTreeDataTruthPartition(partitionGlobals.toList(), partitionTypes.toList())
                partitionGlobals = mutableListOf()
                partitionTypes = mutableListOf()
                estimatedBytes = 0L
            }
            when (kind) {
                EntityKind.GLOBAL -> partitionGlobals += item
                EntityKind.TYPE -> partitionTypes += item
            }
            estimatedBytes = Math.addExact(estimatedBytes, itemBytes)
        }

        globals.forEach { add(EntityKind.GLOBAL, it) }
        types.forEach { add(EntityKind.TYPE, it) }
        if (partitionGlobals.isNotEmpty() || partitionTypes.isNotEmpty()) {
            partitions += FullTreeDataTruthPartition(partitionGlobals.toList(), partitionTypes.toList())
        }
        return partitions.ifEmpty { listOf(FullTreeDataTruthPartition(emptyList(), emptyList())) }
    }

    fun canonicalSha256(element: JsonElement, limits: StrictJsonLimits = StrictJsonLimits()): String =
        MessageDigest.getInstance("SHA-256")
            .digest(OracleJson.canonicalBytes(element, limits))
            .joinToString("") { byte -> "%02x".format(byte) }

    private fun declarationKey(item: JsonObject): JsonObject {
        val declaration = item.required("declaration").jsonObject
        return JsonObject(
            linkedMapOf(
                "sourcePath" to declaration.required("sourcePath"),
                "externalPathSha256" to declaration.required("externalPathSha256"),
                "line" to declaration.required("line"),
                "column" to declaration.required("column"),
            ),
        )
    }

    private fun JsonObject.isObservableLocation(): Boolean =
        required("sourcePath") !is JsonNull || required("externalPathSha256") !is JsonNull

    private fun hexOffset(value: String): BigInteger {
        if (!value.startsWith("0x") || value.length <= 2) {
            throw FullTreeDataTruthException("invalid DWARF offset: $value")
        }
        return try {
            BigInteger(value.substring(2), 16)
        } catch (failure: NumberFormatException) {
            throw FullTreeDataTruthException("invalid DWARF offset: $value")
        }
    }

    private enum class EntityKind { GLOBAL, TYPE }
}

private class CanonicalBytes(bytes: ByteArray) : Comparable<CanonicalBytes> {
    private val value = bytes.copyOf()

    override fun compareTo(other: CanonicalBytes): Int {
        val common = minOf(value.size, other.value.size)
        for (index in 0 until common) {
            val comparison = (value[index].toInt() and 0xff).compareTo(other.value[index].toInt() and 0xff)
            if (comparison != 0) return comparison
        }
        return value.size.compareTo(other.value.size)
    }

    override fun equals(other: Any?): Boolean = other is CanonicalBytes && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()
}

private fun JsonObject.required(name: String): JsonElement =
    this[name] ?: throw FullTreeDataTruthException("required data-truth field is absent: $name")

private fun JsonElement.nullableString(): String? = when (this) {
    JsonNull -> null
    is JsonPrimitive -> if (isString) content else null
    else -> null
}
