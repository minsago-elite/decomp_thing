package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

class FullTreeDataObservationShardInput internal constructor(
    val identifier: String,
    val inputSha256: String,
    units: List<JsonObject>,
) {
    val units: List<JsonObject> = Collections.unmodifiableList(ArrayList(units))

    init {
        require(identifier.matches(Regex("[a-z0-9]+(?:-[a-z0-9]+)*"))) {
            "invalid full-tree data observation shard identifier"
        }
        require(inputSha256.matches(Regex("[0-9a-f]{64}"))) {
            "invalid full-tree data observation input digest"
        }
        require(this.units.isNotEmpty()) { "full-tree data observation shard has no units" }
    }
}

/** Kotlin-owned bindings and semantic validation for data-observation shards. */
object FullTreeDataObservations {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256("full-tree-data-observations", POLICY)
    }

    fun shardInputs(
        inventory: JsonObject,
        scopeSha256: String,
        richArtifactSha256: String,
    ): List<FullTreeDataObservationShardInput> {
        requireSha256(scopeSha256, "scope")
        requireSha256(richArtifactSha256, "rich artifact")
        val inventoryIndexSha256 = inventory.requiredString("indexSha256")
        requireSha256(inventoryIndexSha256, "inventory index")
        val unitRecords = inventory.requiredArray("units")
            .mapIndexed { index, value -> value.requiredObject("inventory unit $index") }
        if (unitRecords.map { it.requiredString("id") }.distinct().size != unitRecords.size) {
            throw FullTreeDataTruthException("inventory data observation unit identifiers are not unique")
        }
        val units = unitRecords.associateBy { it.requiredString("id") }
        val inputs = inventory.requiredArray("shards").mapIndexed { index, value ->
            val shard = value.requiredObject("inventory shard $index")
            val identifier = shard.requiredString("id")
            val records = shard.requiredArray("unitIds").map { unitId ->
                val id = unitId.requiredString("inventory shard unit ID")
                units[id] ?: throw FullTreeDataTruthException(
                    "inventory shard $identifier references unknown unit $id",
                )
            }
            if (records.map { it.requiredString("id") }.distinct().size != records.size) {
                throw FullTreeDataTruthException("inventory shard $identifier repeats a unit")
            }
            val payload = JsonObject(
                mapOf(
                    "configurationSha256" to JsonPrimitive(configurationSha256),
                    "inventoryIndexSha256" to JsonPrimitive(inventoryIndexSha256),
                    "richArtifactSha256" to JsonPrimitive(richArtifactSha256),
                    "scopeSha256" to JsonPrimitive(scopeSha256),
                    "shardId" to JsonPrimitive(identifier),
                    "units" to JsonArray(records),
                ),
            )
            FullTreeDataObservationShardInput(
                identifier,
                OracleArtifacts.sha256(OracleJson.canonicalBytes(payload)),
                records,
            )
        }
        if (inputs.isEmpty()) throw FullTreeDataTruthException("inventory has no data observation shards")
        if (inputs.map { it.identifier }.distinct().size != inputs.size) {
            throw FullTreeDataTruthException("inventory data observation shard identifiers are not unique")
        }
        return inputs
    }

    fun validateShard(
        document: JsonObject,
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        shard: FullTreeDataObservationShardInput,
    ) {
        try {
            OracleSchemas.validate("full-tree-data-observations", document)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data observations fail schema validation: ${failure.message}", failure)
        }
        val richArtifactSha256 = scope.requiredObject("oracle").requiredString("richArtifactSha256")
        val authenticatedShard = shardInputs(inventory, scopeSha256, richArtifactSha256)
            .singleOrNull { it.identifier == shard.identifier }
            ?: throw FullTreeDataTruthException("data observation shard is outside the authenticated inventory")
        if (
            shard.inputSha256 != authenticatedShard.inputSha256 ||
            shard.units != authenticatedShard.units
        ) {
            throw FullTreeDataTruthException("data observation shard input is not authenticated")
        }
        val expectedOracle = JsonObject(
            mapOf(
                "configurationSha256" to JsonPrimitive(configurationSha256),
                "inventoryIndexSha256" to JsonPrimitive(inventory.requiredString("indexSha256")),
                "richArtifactSha256" to JsonPrimitive(richArtifactSha256),
                "scopeSha256" to JsonPrimitive(scopeSha256),
            ),
        )
        val expectedShard = JsonObject(
            mapOf(
                "id" to JsonPrimitive(shard.identifier),
                "inputSha256" to JsonPrimitive(shard.inputSha256),
            ),
        )
        if (document.requiredObject("oracle") != expectedOracle || document.requiredObject("shard") != expectedShard) {
            throw FullTreeDataTruthException("data observation bindings do not match")
        }

        val globals = document.requiredArray("globals").objects("data observation global")
        val types = document.requiredArray("types").objects("data observation type")
        requireOrderedById(globals, "globals")
        requireOrderedById(types, "types")
        val unitIds = shard.units.mapTo(hashSetOf()) { it.requiredString("id") }
        if ((globals + types).any { it.requiredString("unitId") !in unitIds }) {
            throw FullTreeDataTruthException("data observation owner is outside its shard")
        }

        val members = types.flatMap { it.requiredArray("members").objects("data observation member") }
        val expectedCounts = JsonObject(
            mapOf(
                "bases" to JsonPrimitive(members.count { it.requiredString("kind") == "base" }),
                "enumerators" to JsonPrimitive(members.count { it.requiredString("kind") == "enumerator" }),
                "fields" to JsonPrimitive(members.count { it.requiredString("kind") == "field" }),
                "globals" to JsonPrimitive(globals.size),
                "scannedDies" to JsonPrimitive(document.requiredObject("counts").requiredLong("scannedDies")),
                "types" to JsonPrimitive(types.size),
                "units" to JsonPrimitive(shard.units.size),
            ),
        )
        if (document.requiredObject("counts") != expectedCounts) {
            throw FullTreeDataTruthException("data observation counts do not reconcile")
        }
    }

    private fun requireOrderedById(records: List<JsonObject>, label: String) {
        val identifiers = records.map { it.requiredString("id") }
        if (identifiers != identifiers.sorted()) {
            throw FullTreeDataTruthException("data observation $label are not ordered")
        }
    }

    private fun requireSha256(value: String, label: String) {
        if (!value.matches(Regex("[0-9a-f]{64}"))) {
            throw FullTreeDataTruthException("$label digest is invalid")
        }
    }

    private val POLICY = JsonObject(
        mapOf(
            "id" to JsonPrimitive("full-tree-data-observations"),
            "version" to JsonPrimitive(6),
            "globals" to JsonPrimitive("non-declaration-static-storage-or-linkage-bearing-dwarf-variables"),
            "types" to JsonPrimitive("class-struct-union-enum-definitions-and-declarations"),
            "typeReferences" to JsonPrimitive(
                "compact-immediate-and-aggregate-dwarf-offsets-with-modifier-chain-or-closed-reason",
            ),
            "flags" to JsonPrimitive("dwarf-boolean-and-integral-forms-normalized-to-boolean"),
        ),
    )
}

internal fun JsonObject.requiredElement(name: String): JsonElement =
    this[name] ?: throw FullTreeDataTruthException("required JSON field is absent: $name")

internal fun JsonObject.requiredObject(name: String): JsonObject =
    requiredElement(name).requiredObject(name)

internal fun JsonObject.requiredArray(name: String): JsonArray =
    requiredElement(name) as? JsonArray
        ?: throw FullTreeDataTruthException("required JSON field is not an array: $name")

internal fun JsonObject.requiredString(name: String): String = requiredElement(name).requiredString(name)

internal fun JsonObject.requiredLong(name: String): Long {
    val primitive = requiredElement(name) as? JsonPrimitive
        ?: throw FullTreeDataTruthException("required JSON field is not an integer: $name")
    if (primitive.isString || primitive.booleanOrNull != null || !INTEGER_TOKEN.matches(primitive.content)) {
        throw FullTreeDataTruthException("required JSON field is not an integer: $name")
    }
    return primitive.longOrNull
        ?: throw FullTreeDataTruthException("required JSON integer is outside the supported range: $name")
}

internal fun JsonElement.requiredObject(label: String): JsonObject = this as? JsonObject
    ?: throw FullTreeDataTruthException("$label is not an object")

internal fun JsonElement.requiredString(label: String): String {
    val primitive = this as? JsonPrimitive
        ?: throw FullTreeDataTruthException("$label is not a string")
    if (!primitive.isString) throw FullTreeDataTruthException("$label is not a string")
    return primitive.content
}

internal fun JsonArray.objects(label: String): List<JsonObject> =
    mapIndexed { index, element -> element.requiredObject("$label $index") }

private val INTEGER_TOKEN = Regex("-?(?:0|[1-9][0-9]*)")
