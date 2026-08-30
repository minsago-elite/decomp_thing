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
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class FullTreeDataTruthException(message: String, cause: Throwable? = null) : IllegalArgumentException(message, cause)

data class FullTreeDataTruthPartition(
    val globals: List<JsonObject>,
    val types: List<JsonObject>,
)

data class FullTreeTypeTarget(
    val identity: String,
    val ownerUnitId: String,
    val quality: String,
) {
    init {
        require(identity.matches(Regex("[0-9a-f]{64}"))) { "type target identity is invalid" }
        require(ownerUnitId.isNotBlank()) { "type target owner unit is blank" }
        require(quality in setOf("source-aligned", "producer-declaration", "producer-definition")) {
            "type target quality is invalid"
        }
    }
}

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

    fun typeLayout(item: JsonObject): JsonObject {
        val members = item.required("members").jsonArray.map { element ->
            val member = element.jsonObject
            JsonObject(
                linkedMapOf(
                    "kind" to member.required("kind"),
                    "name" to member.required("name"),
                    "byteOffset" to member.required("byteOffset"),
                    "bitOffset" to member.required("bitOffset"),
                    "bitSize" to member.required("bitSize"),
                    "value" to member.required("value"),
                    "virtuality" to member.required("virtuality"),
                    "typeReference" to member.required("typeReference").jsonObject.let { reference ->
                        JsonObject(
                            linkedMapOf(
                                "modifierTags" to reference.required("modifierTags"),
                                "reasonCode" to reference.required("reasonCode"),
                            ),
                        )
                    },
                ),
            )
        }
        return JsonObject(
            linkedMapOf(
                "alignment" to item.required("alignment"),
                "byteSize" to item.required("byteSize"),
                "members" to JsonArray(members),
            ),
        )
    }

    fun resolveTypeReference(
        reference: JsonArray,
        targetLookup: (aggregateDieOffset: String) -> FullTreeTypeTarget?,
        unitToShard: Map<String, String>,
    ): JsonObject {
        if (reference.size != 4) throw FullTreeDataTruthException("raw type reference must have four fields")
        val immediateOffset = reference[0].nullableString()
        val aggregateOffset = reference[1].nullableString()
        val modifierTags = reference[2]
        val reasonCode = reference[3]
        immediateOffset?.let(::hexOffset)
        if (aggregateOffset == null) {
            return JsonObject(
                linkedMapOf(
                    "evidenceDieOffsets" to JsonArray(immediateOffset?.let { listOf(JsonPrimitive(it)) }.orEmpty()),
                    "modifierTags" to modifierTags,
                    "reasonCode" to reasonCode,
                    "resolutionCode" to JsonPrimitive("unresolved"),
                    "targetOwnerShardId" to JsonNull,
                    "targetTypeId" to JsonNull,
                    "_targetQuality" to JsonNull,
                ),
            )
        }
        if (immediateOffset == null) {
            throw FullTreeDataTruthException("aggregate type reference has no immediate DWARF offset")
        }
        hexOffset(aggregateOffset)
        val target = targetLookup(aggregateOffset)
            ?: throw FullTreeDataTruthException(
                "aggregate reference $aggregateOffset is outside the authenticated type index",
            )
        val ownerShard = unitToShard[target.ownerUnitId]
            ?: throw FullTreeDataTruthException("type target owner is outside the authenticated inventory")
        val offsets = listOfNotNull(immediateOffset, aggregateOffset).distinct().sortedBy(::hexOffset)
        return JsonObject(
            linkedMapOf(
                "evidenceDieOffsets" to JsonArray(offsets.map(::JsonPrimitive)),
                "modifierTags" to modifierTags,
                "reasonCode" to JsonNull,
                "resolutionCode" to JsonPrimitive("exact-dwarf-offset"),
                "targetOwnerShardId" to JsonPrimitive(ownerShard),
                "targetTypeId" to JsonPrimitive("type-${target.identity.take(32)}"),
                "_targetQuality" to JsonPrimitive(target.quality),
            ),
        )
    }

    fun mergeTypeObservations(
        identity: String,
        observations: List<JsonObject>,
        targetLookup: (aggregateDieOffset: String) -> FullTreeTypeTarget?,
        unitToShard: Map<String, String>,
        limits: StrictJsonLimits = StrictJsonLimits(),
    ): JsonObject {
        requireIdentity(identity, "type")
        if (observations.isEmpty()) throw FullTreeDataTruthException("type observation population is empty")
        val records = observations.map { item ->
            JsonObject(item.toMutableMap().apply {
                this["members"] = JsonArray(item.required("members").jsonArray.map { memberElement ->
                    val member = memberElement.jsonObject
                    JsonObject(member.toMutableMap().apply {
                        this["typeReference"] = resolveTypeReference(
                            member.required("typeReference").jsonArray,
                            targetLookup,
                            unitToShard,
                        )
                    })
                })
            })
        }
        val definitions = records.filterNot { it.requiredBoolean("declarationOnly") }
        val layouts = definitions.mapTo(sortedSetOf()) {
            CanonicalBytes(OracleJson.canonicalBytes(typeLayout(it), limits))
        }
        if (layouts.size > 1) {
            throw FullTreeDataTruthException("incompatible aggregate definitions for type-${identity.take(32)}")
        }
        val layoutRecords = definitions.ifEmpty { records }
        val first = layoutRecords.first()
        val firstMembers = first.required("members").jsonArray
        val members = firstMembers.mapIndexed { index, memberElement ->
            val member = memberElement.jsonObject
            JsonObject(member.toMutableMap().apply {
                this["typeReference"] = mergeTypeReferences(
                    layoutRecords.map { record ->
                        val recordMembers = record.required("members").jsonArray
                        if (recordMembers.size != firstMembers.size) {
                            throw FullTreeDataTruthException(
                                "incompatible aggregate definitions for type-${identity.take(32)}",
                            )
                        }
                        recordMembers[index].jsonObject.required("typeReference").jsonObject
                    },
                    "type-${identity.take(32)}-member-$index",
                    limits,
                )
            })
        }
        val owner = records.map { it.required("unitId").jsonPrimitive.content }.minOrNull()
            ?: throw FullTreeDataTruthException("type observation has no owner")
        val observable = definitions.isNotEmpty() && first.required("byteSize") !is JsonNull
        return JsonObject(
            linkedMapOf(
                "alignment" to first.required("alignment"),
                "byteSize" to first.required("byteSize"),
                "context" to first.required("context"),
                "declarations" to JsonArray(uniqueValues(records, "declaration", limits)),
                "id" to JsonPrimitive("type-${identity.take(32)}"),
                "members" to JsonArray(members),
                "name" to first.required("name"),
                "observationIds" to JsonArray(
                    records.map { it.required("id").jsonPrimitive.content }.sorted().map(::JsonPrimitive),
                ),
                "ownerUnitId" to JsonPrimitive(owner),
                "population" to JsonPrimitive(if (observable) "scored" else "unobservable"),
                "reasonCode" to if (observable) JsonNull else JsonPrimitive("declaration-only-or-size-unobservable"),
                "tag" to first.required("tag"),
            ),
        )
    }

    fun mergeGlobalObservations(
        identity: String,
        observations: List<JsonObject>,
        targetLookup: (aggregateDieOffset: String) -> FullTreeTypeTarget?,
        unitToShard: Map<String, String>,
        limits: StrictJsonLimits = StrictJsonLimits(),
    ): JsonObject {
        requireIdentity(identity, "global")
        if (observations.isEmpty()) throw FullTreeDataTruthException("global observation population is empty")
        val owner = observations.map { it.required("unitId").jsonPrimitive.content }.minOrNull()
            ?: throw FullTreeDataTruthException("global observation has no owner")
        val address = oneCompatible(observations, "addressRva", identity, limits)
        val references = observations.map { item ->
            resolveTypeReference(item.required("typeReference").jsonArray, targetLookup, unitToShard)
        }
        val names = observations
            .flatMap { it.required("names").jsonArray.map { name -> name.jsonPrimitive.content } }
            .distinct()
            .sortedWith(CODE_POINT_STRING_COMPARATOR)
        return JsonObject(
            linkedMapOf(
                "addressRva" to (address ?: JsonNull),
                "alignment" to (oneCompatible(observations, "alignment", identity, limits) ?: JsonNull),
                "declarations" to JsonArray(uniqueValues(observations, "declaration", limits)),
                "external" to JsonPrimitive(
                    oneCompatible(observations, "external", identity, limits)?.strictBoolean("external") ?: false,
                ),
                "id" to JsonPrimitive("global-${identity.take(32)}"),
                "mutability" to JsonPrimitive(
                    oneCompatible(observations, "mutability", identity, limits)?.strictString("mutability") ?: "unknown",
                ),
                "names" to JsonArray(names.map(::JsonPrimitive)),
                "observationIds" to JsonArray(
                    observations.map { it.required("id").jsonPrimitive.content }.sorted().map(::JsonPrimitive),
                ),
                "ownerUnitId" to JsonPrimitive(owner),
                "population" to JsonPrimitive(if (address != null) "scored" else "unobservable"),
                "reasonCode" to if (address != null) JsonNull else observations.first().required("reasonCode"),
                "size" to (oneCompatible(observations, "size", identity, limits) ?: JsonNull),
                "tls" to JsonPrimitive(
                    oneCompatible(observations, "tls", identity, limits)?.strictBoolean("tls") ?: false,
                ),
                "typeReference" to mergeTypeReferences(references, "global-${identity.take(32)}", limits),
                "visibility" to JsonPrimitive(
                    oneCompatible(observations, "visibility", identity, limits)?.strictString("visibility") ?: "unknown",
                ),
            ),
        )
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

    private fun requireIdentity(value: String, label: String) {
        if (!value.matches(Regex("[0-9a-f]{64}"))) {
            throw FullTreeDataTruthException("$label identity is invalid")
        }
    }

    private enum class EntityKind { GLOBAL, TYPE }

    private val CODE_POINT_STRING_COMPARATOR = Comparator<String> { left, right ->
        var leftOffset = 0
        var rightOffset = 0
        while (leftOffset < left.length && rightOffset < right.length) {
            val leftCodePoint = Character.codePointAt(left, leftOffset)
            val rightCodePoint = Character.codePointAt(right, rightOffset)
            if (leftCodePoint != rightCodePoint) return@Comparator leftCodePoint.compareTo(rightCodePoint)
            leftOffset += Character.charCount(leftCodePoint)
            rightOffset += Character.charCount(rightCodePoint)
        }
        (left.length - leftOffset).compareTo(right.length - rightOffset)
    }
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

private fun JsonObject.requiredBoolean(name: String): Boolean = required(name).strictBoolean(name)

private fun JsonElement.strictBoolean(label: String): Boolean {
    val primitive = this as? JsonPrimitive
        ?: throw FullTreeDataTruthException("$label is not a Boolean")
    return primitive.booleanOrNull
        ?: throw FullTreeDataTruthException("$label is not a Boolean")
}

private fun JsonElement.strictString(label: String): String {
    val primitive = this as? JsonPrimitive
        ?: throw FullTreeDataTruthException("$label is not a string")
    if (!primitive.isString) throw FullTreeDataTruthException("$label is not a string")
    return primitive.content
}
