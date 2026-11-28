package decompengine.web

import decompengine.exploration.EXPLORATION_FAILURE_SCHEMA
import decompengine.exploration.EXPLORATION_PREPARATION_FAILURE_SCHEMA
import decompengine.exploration.explorationFailureLimitation
import decompengine.exploration.explorationPreparationFailureLimitation
import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.*
import java.security.MessageDigest

internal data class WebExplorationClassification(
    val state: String,
    val producerSchemaVersion: Int?,
    val summary: JsonObject?,
    val limitation: String,
    val root: JsonObject?,
    val bytesCaptured: Boolean,
    /** True only when the captured bytes pass the redacted report projection that the JSON download serves. */
    val downloadAvailable: Boolean = false,
)

/** Classifies the exact bounded capture without inventing attempt or artifact identity. */
internal fun classifyWebExploration(bytes: ByteArray?): WebExplorationClassification {
    var state = "unknown"
    var summary: JsonObject? = null
    var producerSchemaVersion: Int? = null
    var limitation = "Report bytes are missing, inaccessible or changed during the bounded read."
    var parsedRoot: JsonObject? = null
    if (bytes != null) {
        try {
            require(bytes.size <= 1_048_576)
            val root = OracleJson.parse(bytes).jsonObject
            parsedRoot = root
            // Declarations are closed syntax: schema and state are JSON strings, versions JSON numbers.
            fun declaredText(name: String): String? = root[name]?.let { require(it is JsonPrimitive && it.isString); it.content }
            fun declaredVersion(name: String): Int? = root[name]?.let {
                require(it is JsonPrimitive && !it.isString); requireNotNull(it.intOrNull)
            }
            val schema = declaredText("schema")
            val schemaVersion = declaredVersion("schemaVersion")
            val legacyFields = setOf("candidateCount", "coverageIncreased", "baselineOutputSignatures", "expandedOutputSignatures",
                "newOutputSignatures", "angr", "confidence", "candidates", "observations")
            // Recognize the producer by schema and version only; `state` is a payload value of a recognized version.
            val versionedSuccess = schema == "decomp-exploration" && schemaVersion == 2
            val requiredFields = if (versionedSuccess)
                legacyFields + setOf("schema", "schemaVersion", "state", "retainedInputs", "retainedInputsOmitted")
            else legacyFields
            if (versionedSuccess) {
                producerSchemaVersion = 2
                // Only the producer's `complete` value is known; a missing state is incomplete, any other value malformed.
                require(declaredText("state")?.let { it == "complete" } ?: true)
            }
            if (schema == EXPLORATION_FAILURE_SCHEMA || schema == EXPLORATION_PREPARATION_FAILURE_SCHEMA) {
                if (schemaVersion == 1) {
                    producerSchemaVersion = 1
                    limitation = if (schema == EXPLORATION_FAILURE_SCHEMA) explorationFailureLimitation(root)
                        else explorationPreparationFailureLimitation(root)
                    state = "partial"
                } else {
                    state = "unsupported"; limitation = "This adapter does not support the declared exploration producer schema."
                }
            } else if (("schema" in root || "schemaVersion" in root || "schema_version" in root) && !versionedSuccess) {
                state = "unsupported"; limitation = "This adapter does not support the declared exploration producer schema."
            } else if (!root.keys.containsAll(requiredFields)) {
                // Present fields must still be well typed, and a producer that declares `complete` must carry every field.
                checkPresentExplorationFields(root)
                require(!versionedSuccess || "state" !in root)
                state = "partial"; limitation = "Required producer fields are absent; no summary is inferred."
            } else {
                if (versionedSuccess) {
                    require(root.keys == requiredFields)
                    val retained = root.getValue("retainedInputs").jsonArray
                    val candidates = root.getValue("candidates").jsonArray
                    require(retained.size <= 1000 && candidates.size + retained.size <= 1000)
                    val candidateIds = candidates.map { candidate ->
                        candidate.jsonObject.getValue("id").jsonPrimitive.content.also {
                            require(it.isNotEmpty() && it.length <= 128)
                        }
                    }
                    require(candidateIds.distinct().size == candidateIds.size)
                    val retainedIds = HashSet<String>()
                    retained.forEach { item ->
                        val input = item.jsonObject
                        require(input.keys == setOf("id", "args", "stdinHex"))
                        val id = input.getValue("id").jsonPrimitive.content
                        require(id.isNotEmpty() && id.length <= 128 && retainedIds.add(id))
                        require("retained:$id" !in candidateIds)
                        val args = input.getValue("args").jsonArray
                        require(args.size <= 256 && args.all { it.jsonPrimitive.isString && it.jsonPrimitive.content.length <= 8192 })
                        val stdinHex = input.getValue("stdinHex").jsonPrimitive.content
                        require(stdinHex.length % 2 == 0 && stdinHex.length <= 524_288 && stdinHex.matches(Regex("(?:[0-9a-f]{2})*")))
                    }
                    val omitted = root.getValue("retainedInputsOmitted").jsonPrimitive
                    val omittedCount = omitted.intOrNull
                    require(!omitted.isString && omittedCount?.let { it in 0..10_000 } == true)
                    require(retained.size + requireNotNull(omittedCount) <= 10_000)
                }
                val candidateCount = count(root, "candidateCount")
                require(candidateCount.toULong() == root.getValue("candidates").jsonArray.size.toULong())
                root.getValue("observations").jsonArray
                boolean(root, "coverageIncreased")
                count(root, "baselineOutputSignatures")
                val newSignatures = root.getValue("newOutputSignatures").jsonArray
                newSignatures.forEach { require(it.jsonPrimitive.isString) }
                val confidence = root.getValue("confidence").jsonObject
                require(count(confidence, "newOutputSignatureCount").toULong() == newSignatures.size.toULong())
                val score = confidence.getValue("score").jsonPrimitive
                require(!score.isString && score.doubleOrNull?.let { it.isFinite() && it in 0.0..1.0 } == true)
                summary = buildJsonObject {
                    put("candidateCount", candidateCount)
                    put("expandedOutputSignatures", count(root, "expandedOutputSignatures"))
                    put("confidence", buildJsonObject {
                        put("score", score)
                        for (name in listOf("inputCount", "sourceCount", "outputSignatureCount", "newOutputSignatureCount")) put(name, count(confidence, name))
                        for (name in listOf("sandboxed", "networkIsolated")) put(name, boolean(confidence, name))
                    })
                }
                state = "available"; limitation = "Observed sample breadth and producer-reported isolation are not proof of equivalence or independent containment verification."
            }
        } catch (_: Exception) {
            state = "invalid"; summary = null; limitation = "Report bytes are malformed or exceed this adapter's structural limits."
        }
    }
    return WebExplorationClassification(state, producerSchemaVersion, summary, limitation, parsedRoot, bytes != null)
}

private fun count(objectValue: JsonObject, name: String): String {
    val value = objectValue.getValue(name).jsonPrimitive
    require(!value.isString && value.content.matches(Regex("0|[1-9][0-9]{0,19}")) && value.content.toULongOrNull() != null)
    return value.content
}

private fun boolean(objectValue: JsonObject, name: String): Boolean {
    val value = objectValue.getValue(name).jsonPrimitive
    require(!value.isString)
    return requireNotNull(value.booleanOrNull)
}

/** A partial report withholds its summary, but any field it does carry must have the producer's JSON type. */
private fun checkPresentExplorationFields(root: JsonObject) {
    for (name in listOf("candidateCount", "baselineOutputSignatures", "expandedOutputSignatures")) if (name in root) count(root, name)
    if ("coverageIncreased" in root) boolean(root, "coverageIncreased")
    root["newOutputSignatures"]?.let { values -> values.jsonArray.forEach { require(it.jsonPrimitive.isString) } }
    root["candidates"]?.jsonArray
    root["observations"]?.jsonArray
    root["retainedInputs"]?.jsonArray
    root["retainedInputsOmitted"]?.let { count(root, "retainedInputsOmitted") }
    root["confidence"]?.jsonObject?.let { confidence ->
        confidence["score"]?.let { score ->
            require(score is JsonPrimitive && !score.isString && score.doubleOrNull?.let { it.isFinite() && it in 0.0..1.0 } == true)
        }
        for (name in listOf("inputCount", "sourceCount", "outputSignatureCount", "newOutputSignatureCount")) if (name in confidence) count(confidence, name)
        for (name in listOf("sandboxed", "networkIsolated")) if (name in confidence) boolean(confidence, name)
    }
}

/** Captures a selected report once; only read failures become unknown rather than invalid. */
internal fun captureWebExploration(read: () -> ByteArray): WebExplorationClassification {
    val bytes = try { read() } catch (_: Exception) { null }
    return classifyWebExploration(bytes)
}

/**
 * Legacy HTML capture: classify the exact bytes, then display rows only from the redacted report projection that
 * the JSON download serves. When that projection is unavailable the rows and the download link are withheld.
 */
internal fun captureWebExplorationPresentation(policy: WebRedactionPolicy, read: () -> ByteArray): WebExplorationClassification {
    val bytes = try { read() } catch (_: Exception) { null }
    val classification = classifyWebExploration(bytes)
    val projected = bytes?.let {
        try { WebReportProjection.project(false, it, policy) } catch (failure: Exception) {
            if (failure is java.util.concurrent.CancellationException || failure is InterruptedException) throw failure
            null
        }
    }
    val root = projected?.let { runCatching { OracleJson.parse(it) as? JsonObject }.getOrNull() }
    return classification.copy(root = root, downloadAvailable = projected != null)
}

/** Version-one presentation of legacy success and versioned failure records; never acceptance evidence. */
internal fun webExplorationReport(jobId: String, runId: String, bytes: ByteArray?, basePath: String = "/"): JsonObject {
    val classification = classifyWebExploration(bytes)
    val digest = bytes?.let { MessageDigest.getInstance("SHA-256").digest(it).take(16).joinToString("") { b -> "%02x".format(b) } }
    return buildJsonObject {
        put("reportId", "exploration_${digest ?: "unavailable"}")
        put("binding", buildJsonObject { put("jobId", jobId); put("runId", runId); put("revisionId", JsonNull) })
        put("reportType", "exploration"); put("adapterVersion", 1)
        put("producerSchemaVersion", classification.producerSchemaVersion?.let { JsonPrimitive(it) } ?: JsonNull)
        put("state", classification.state); put("authority", "observations"); put("sourceArtifact", bytes?.let { WebExplorationArtifact.descriptor(jobId, runId, it, basePath) } ?: JsonNull)
        put("acceptance", "not-evaluated"); put("acceptanceArtifactId", JsonNull)
        put("limitations", JsonArray(listOf(JsonPrimitive(classification.limitation))))
        put("summary", classification.summary ?: JsonNull)
        put("validationCases", JsonNull); put("validationFailure", JsonNull)
    }
}
