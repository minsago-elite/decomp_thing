package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/** Diagnostic record consistency only; even consistent records cannot authorize START or prove live absence. */
internal fun requireGccCliLinkedRecord(bytes: ByteArray, file: String, operationId: String,
    intentSha256: String, previousSha256: String): JsonObject {
    val (provider, payload) = checkNotNull(CLI_LINKED_RECORDS[file]) { "unknown CLI journal record: $file" }
    val record = OracleJson.parseCanonical(bytes).jsonObject
    val base = setOf("provider", "schemaVersion", "operationId", "intentSha256", "previousSha256", "complete", "releaseEligible", "recordSha256")
    require(record.keys == base + if (payload == null) emptySet() else setOf(payload, "${payload}Sha256")) {
        "CLI linked record has missing or unexpected fields: $file"
    }
    require(record.getValue("provider") == JsonPrimitive(provider) && record.getValue("schemaVersion") == JsonPrimitive(1))
    require(record.getValue("operationId") == JsonPrimitive(operationId) && record.getValue("intentSha256") == JsonPrimitive(intentSha256) &&
        record.getValue("previousSha256") == JsonPrimitive(previousSha256)) { "CLI journal lineage differs: $file" }
    require(record.getValue("complete") == JsonPrimitive(false) && record.getValue("releaseEligible") == JsonPrimitive(false))
    require(record.getValue("recordSha256") == JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(record - "recordSha256"))))) {
        "CLI record checksum differs: $file"
    }
    payload?.let { name ->
        val value = record.getValue(name)
        require(value is JsonObject) { "CLI record payload must be an object: $file" }
        require(record.getValue("${name}Sha256") == JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(value)))) {
            "CLI payload checksum differs: $file"
        }
    }
    return record
}

private val CLI_LINKED_RECORDS = mapOf(
    "attachment.json" to ("gcc-bundled-command-attached-v1" to "attachment"),
    "start-authorized.json" to ("gcc-bundled-command-start-authorized-v1" to null),
    "execution.json" to ("gcc-bundled-command-executed-v1" to "execution"),
    "export-assessment.json" to ("gcc-bundled-command-export-assessed-v1" to "assessment"),
    "interrupt-authorized.json" to ("gcc-bundled-command-interrupt-authorized-v1" to "authorization"),
    "interrupted-execution.json" to ("gcc-bundled-command-interrupted-v1" to "execution"),
    "interrupted-prefix-assessment.json" to ("gcc-bundled-command-prefix-assessed-v1" to "assessment"),
    "analysis-state-captured.json" to ("gcc-bundled-interrupted-state-captured-v1" to "analysisState"),
    "resume-prepared.json" to ("gcc-bundled-resume-prepared-v1" to "resume"),
    "resume-attachment.json" to ("gcc-bundled-resume-attached-v1" to "attachment"),
    "resume-start-authorized.json" to ("gcc-bundled-resume-start-authorized-v1" to null),
    "resume-execution.json" to ("gcc-bundled-resume-executed-v1" to "execution"),
    "resume-export-assessment.json" to ("gcc-bundled-resume-export-assessed-v1" to "assessment"),
    "planner-prepared.json" to ("gcc-bundled-planner-prepared-v1" to "planner"),
    "planner-attachment.json" to ("gcc-bundled-planner-attached-v1" to "attachment"),
    "planner-start-authorized.json" to ("gcc-bundled-planner-start-authorized-v1" to null),
    "planner-execution.json" to ("gcc-bundled-planner-executed-v1" to "execution"),
    "planner-assessment.json" to ("gcc-bundled-planner-assessed-v1" to "assessment"),
)
