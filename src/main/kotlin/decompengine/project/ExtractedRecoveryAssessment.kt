package decompengine.project

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Neither historical extraction labels nor schema-2 declarations are scored evidence. */
internal fun RecoveredProgramModel.unassessedRecoveryAssessment(
    modelSha256: String = sha256(toJson().toByteArray(Charsets.UTF_8)),
): JsonObject {
    require(modelSha256.matches(Regex("[0-9a-f]{64}")))
    val identities = (functions.map { it.id } + globals.map { it.id } + types.map { it.id }).sorted()
    require(identities.size == identities.toSet().size) { "recovery assessment requires unique entity identities" }
    return JsonObject(mapOf(
        "schemaVersion" to JsonPrimitive(1),
        "state" to JsonPrimitive("unassessed"),
        "modelSchemaVersion" to JsonPrimitive(schemaVersion),
        "modelSha256" to JsonPrimitive(modelSha256),
        "unassessedEntityIds" to JsonArray(identities.map(::JsonPrimitive)),
        "assessedEntityIds" to JsonArray(emptyList()),
    ))
}
