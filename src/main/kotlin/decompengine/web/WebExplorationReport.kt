package decompengine.web

import decompengine.exploration.EXPLORATION_FAILURE_SCHEMA
import decompengine.exploration.explorationFailureLimitation
import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.*
import java.security.MessageDigest

/** Version-one presentation of legacy success and versioned failure records; never acceptance evidence. */
internal fun webExplorationReport(jobId: String, runId: String, bytes: ByteArray?, basePath: String = "/"): JsonObject {
    var state = "unknown"
    var summary: JsonObject? = null
    var producerSchemaVersion: Int? = null
    var limitation = "Report bytes are missing, inaccessible or changed during the bounded read."
    if (bytes != null) {
        try {
            require(bytes.size <= 1_048_576)
            val root = OracleJson.parse(bytes).jsonObject
            if (root["schema"]?.jsonPrimitive?.contentOrNull == EXPLORATION_FAILURE_SCHEMA) {
                if (root["schemaVersion"]?.jsonPrimitive?.intOrNull == 1) {
                    limitation = explorationFailureLimitation(root)
                    state = "partial"
                    producerSchemaVersion = 1
                } else {
                    state = "unsupported"; limitation = "This adapter does not support the declared exploration producer schema."
                }
            } else if ("schemaVersion" in root || "schema_version" in root) {
                state = "unsupported"; limitation = "This adapter does not support the declared exploration producer schema."
            } else if (!root.keys.containsAll(setOf("candidateCount", "coverageIncreased", "baselineOutputSignatures", "expandedOutputSignatures", "newOutputSignatures", "angr", "confidence", "candidates", "observations"))) {
                state = "partial"; limitation = "Required producer fields are absent; no summary is inferred."
            } else {
                fun count(objectValue: JsonObject, name: String): String {
                    val value = objectValue.getValue(name).jsonPrimitive
                    require(!value.isString && value.content.matches(Regex("0|[1-9][0-9]{0,19}")) && value.content.toULongOrNull() != null)
                    return value.content
                }
                val candidateCount = count(root, "candidateCount")
                require(candidateCount.toULong() == root.getValue("candidates").jsonArray.size.toULong())
                root.getValue("observations").jsonArray
                require(root.getValue("coverageIncreased").jsonPrimitive.booleanOrNull != null)
                count(root, "baselineOutputSignatures")
                root.getValue("newOutputSignatures").jsonArray.forEach { require(it.jsonPrimitive.isString) }
                val confidence = root.getValue("confidence").jsonObject
                val score = confidence.getValue("score").jsonPrimitive
                require(!score.isString && score.doubleOrNull?.let { it.isFinite() && it in 0.0..1.0 } == true)
                summary = buildJsonObject {
                    put("candidateCount", candidateCount); put("expandedOutputSignatures", count(root, "expandedOutputSignatures"))
                    put("confidence", buildJsonObject {
                        put("score", score)
                        for (name in listOf("inputCount", "sourceCount", "outputSignatureCount", "newOutputSignatureCount")) put(name, count(confidence, name))
                        for (name in listOf("sandboxed", "networkIsolated")) put(name, requireNotNull(confidence.getValue(name).jsonPrimitive.booleanOrNull))
                    })
                }
                state = "available"; limitation = "Observed sample breadth and producer-reported isolation are not proof of equivalence or independent containment verification."
            }
        } catch (_: Exception) {
            state = "invalid"; summary = null; limitation = "Report bytes are malformed or exceed this adapter's structural limits."
        }
    }
    val digest = bytes?.let { MessageDigest.getInstance("SHA-256").digest(it).take(16).joinToString("") { b -> "%02x".format(b) } }
    return buildJsonObject {
        put("reportId", "exploration_${digest ?: "unavailable"}")
        put("binding", buildJsonObject { put("jobId", jobId); put("runId", runId); put("revisionId", JsonNull) })
        put("reportType", "exploration"); put("adapterVersion", 1)
        put("producerSchemaVersion", producerSchemaVersion?.let { JsonPrimitive(it) } ?: JsonNull)
        put("state", state); put("authority", "observations"); put("sourceArtifact", bytes?.let { WebExplorationArtifact.descriptor(jobId, runId, it, basePath) } ?: JsonNull)
        put("acceptance", "not-evaluated"); put("acceptanceArtifactId", JsonNull)
        put("limitations", JsonArray(listOf(JsonPrimitive(limitation))))
        put("summary", summary ?: JsonNull)
    }
}
