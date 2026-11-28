package decompengine.web

import decompengine.exploration.EXPLORATION_FAILURE_SCHEMA
import decompengine.exploration.EXPLORATION_PREPARATION_FAILURE_SCHEMA
import decompengine.exploration.explorationFailureLimitation
import decompengine.exploration.explorationPreparationFailureLimitation
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*
import java.security.MessageDigest

internal data class WebExplorationClassification(
    val state: String,
    val producerSchemaVersion: Int?,
    val summary: JsonObject?,
    val limitation: String,
    val bytesCaptured: Boolean,
    /** True only when the captured bytes pass the redacted report projection that the JSON download serves. */
    val downloadAvailable: Boolean = false,
    /** Exact validated baseline count for the legacy page; the closed v1 exploration summary does not carry it. */
    val baselineOutputSignatures: String? = null,
    /** Legacy page rows for an `available` report; null when the redacted projection cannot supply them. */
    val rows: List<WebExplorationRow>? = null,
    val candidateTotal: Int = 0,
)

/** How a displayed candidate was paired with an observation; decided on the original, unredacted identifiers. */
internal enum class WebExplorationAttribution { MATCHED, UNMATCHED, AMBIGUOUS_CANDIDATE, AMBIGUOUS_OBSERVATION }

/** Program output prepared for display: decoded, redacted, then clipped. [byteCount] is the recorded output length. */
internal data class WebExplorationOutput(val byteCount: Int, val preview: String, val clipped: Boolean)

/** One legacy candidate row. Every field comes from the redacted projection; the pairing does not. */
internal data class WebExplorationRow(
    val candidate: JsonObject?,
    val observation: JsonObject?,
    val attribution: WebExplorationAttribution,
    val stdout: WebExplorationOutput?,
)

/** Classifies the exact bounded capture without inventing attempt or artifact identity. */
internal fun classifyWebExploration(bytes: ByteArray?): WebExplorationClassification = classifyCapturedExploration(bytes).first

/** The classification and, for parsed bytes, the original root. The original root never leaves this file. */
private fun classifyCapturedExploration(bytes: ByteArray?): Pair<WebExplorationClassification, JsonObject?> {
    var state = "unknown"
    var summary: JsonObject? = null
    var baseline: String? = null
    var producerSchemaVersion: Int? = null
    var limitation = "Report bytes are missing, inaccessible or changed during the bounded read."
    var parsedRoot: JsonObject? = null
    if (bytes != null) {
        try {
            require(bytes.size <= 1_048_576)
            // Parse with the projection's nesting bound: an `available` report must also be projectable for display.
            val root = OracleJson.parse(bytes, StrictJsonLimits(maximumDepth = WebReportProjection.MAXIMUM_REPORT_DEPTH)).jsonObject
            parsedRoot = root
            // Declarations are closed syntax: schema and state are JSON strings, versions JSON numbers.
            fun declaredText(name: String): String? = root[name]?.let { require(it is JsonPrimitive && it.isString); it.content }
            fun declaredVersion(name: String): Int? = root[name]?.let {
                require(it is JsonPrimitive && !it.isString); requireNotNull(it.intOrNull)
            }
            val schema = declaredText("schema")
            val schemaVersion = declaredVersion("schemaVersion")
            // Recognize the producer by schema and version only; `state` is a payload value of a recognized version.
            val versionedSuccess = schema == "decomp-exploration" && schemaVersion == 2
            val requiredFields = if (versionedSuccess) LEGACY_FIELDS + VERSIONED_FIELDS else LEGACY_FIELDS
            if (versionedSuccess) {
                // Only the producer's `complete` value is known; a missing state is incomplete, any other value malformed.
                require(declaredText("state")?.let { it == "complete" } ?: true)
            }
            if (schema == EXPLORATION_FAILURE_SCHEMA || schema == EXPLORATION_PREPARATION_FAILURE_SCHEMA) {
                if (schemaVersion == 1) {
                    limitation = if (schema == EXPLORATION_FAILURE_SCHEMA) explorationFailureLimitation(root)
                        else explorationPreparationFailureLimitation(root)
                    // Report the producer version only once the failure record itself validated.
                    state = "partial"; producerSchemaVersion = 1
                } else {
                    state = "unsupported"; limitation = "This adapter does not support the declared exploration producer schema."
                }
            } else if (("schema" in root || "schemaVersion" in root || "schema_version" in root) && !versionedSuccess) {
                state = "unsupported"; limitation = "This adapter does not support the declared exploration producer schema."
            } else {
                // One set of producer-type checks for every present field, whether or not the report is complete.
                checkPresentExplorationFields(root, versionedSuccess)
                if (versionedSuccess) require(root.keys.all { it in requiredFields })
                if (!root.keys.containsAll(requiredFields)) {
                    // A producer that declares `complete` must carry every field.
                    require(!versionedSuccess || "state" !in root)
                    state = "partial"; limitation = "Required producer fields are absent; no summary is inferred."
                } else {
                    if (versionedSuccess) {
                        val retained = root.getValue("retainedInputs").jsonArray
                        val candidates = root.getValue("candidates").jsonArray
                        require(candidates.size + retained.size <= 1000)
                        val candidateIds = candidates.map { it.jsonObject.getValue("id").jsonPrimitive.content }.toSet()
                        retained.forEach { require("retained:${it.jsonObject.getValue("id").jsonPrimitive.content}" !in candidateIds) }
                        require(retained.size.toULong() + count(root, "retainedInputsOmitted").toULong() <= 10_000u)
                        // Cross-field rules of the SPA's retained-case reader: every observation names a candidate,
                        // and the reported sources, including the retained-regression source, stay within 64.
                        require(root.getValue("observations").jsonArray.all {
                            it.jsonObject.getValue("candidateId").jsonPrimitive.content in candidateIds
                        })
                        val sources = candidates.map { it.jsonObject.getValue("source").jsonPrimitive.content }.toSet() +
                            (if (retained.isEmpty()) emptySet() else setOf("RETAINED_REGRESSION"))
                        require(sources.size <= 64)
                    }
                    val candidateCount = count(root, "candidateCount")
                    require(candidateCount.toULong() == root.getValue("candidates").jsonArray.size.toULong())
                    val newSignatures = root.getValue("newOutputSignatures").jsonArray
                    val confidence = root.getValue("confidence").jsonObject
                    require(count(confidence, "newOutputSignatureCount").toULong() == newSignatures.size.toULong())
                    val score = confidence.getValue("score").jsonPrimitive
                    summary = buildJsonObject {
                        put("candidateCount", candidateCount)
                        put("expandedOutputSignatures", count(root, "expandedOutputSignatures"))
                        put("confidence", buildJsonObject {
                            put("score", score)
                            for (name in listOf("inputCount", "sourceCount", "outputSignatureCount", "newOutputSignatureCount")) put(name, count(confidence, name))
                            for (name in listOf("sandboxed", "networkIsolated")) put(name, boolean(confidence, name))
                        })
                    }
                    baseline = count(root, "baselineOutputSignatures")
                    state = "available"; limitation = "Observed sample breadth and producer-reported isolation are not proof of equivalence or independent containment verification."
                }
                if (versionedSuccess) producerSchemaVersion = 2
            }
        } catch (_: Exception) {
            // Malformed bytes are not evidence of any producer version, so `invalid` never reports one.
            state = "invalid"; summary = null; baseline = null; producerSchemaVersion = null
            limitation = "Report bytes are malformed or exceed this adapter's structural limits."
        }
    }
    return WebExplorationClassification(state, producerSchemaVersion, summary, limitation, bytes != null,
        baselineOutputSignatures = baseline) to parsedRoot
}

private val LEGACY_FIELDS = setOf("candidateCount", "coverageIncreased", "baselineOutputSignatures", "expandedOutputSignatures",
    "newOutputSignatures", "angr", "confidence", "candidates", "observations")
private val VERSIONED_FIELDS = setOf("schema", "schemaVersion", "state", "retainedInputs", "retainedInputsOmitted")
private val LOWER_HEX = Regex("(?:[0-9a-f]{2})*")

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

private fun text(value: JsonElement): String {
    require(value is JsonPrimitive && value.isString)
    return value.content
}

private fun identity(value: JsonElement): String = text(value).also { require(it.isNotEmpty() && it.length <= 128) }

private val CANDIDATE_FIELDS = setOf("id", "source", "args", "stdinHex")
private val OBSERVATION_FIELDS = setOf("candidateId", "signature", "exitCode", "stdoutHex", "stderrHex", "networkIsolated")
private val EXIT_CODE = Regex("-?(?:0|[1-9][0-9]{0,9})")

/**
 * One version-two candidate as the producer writes it and the SPA's retained-case reader (`explorationCases.ts`)
 * requires it: exactly these fields, a non-empty identity and source of at most 128 characters, at most 256 string
 * arguments and lowercase hexadecimal stdin. Returns the identity and source for the per-list checks.
 */
private fun checkVersionedCandidate(element: JsonElement): Pair<String, String> {
    val candidate = element.jsonObject
    require(candidate.keys == CANDIDATE_FIELDS)
    val source = text(candidate.getValue("source"))
    require(source.isNotEmpty() && source.length <= 128)
    val args = candidate.getValue("args").jsonArray
    require(args.size <= 256)
    args.forEach(::text)
    require(text(candidate.getValue("stdinHex")).matches(LOWER_HEX))
    return identity(candidate.getValue("id")) to source
}

/**
 * One version-two observation, matching the SPA reader: exactly these fields, a 32-bit integer exit code, a literal
 * boolean isolation flag, lowercase hexadecimal streams and the `exit:stdout:stderr` signature they determine.
 */
private fun checkVersionedObservation(element: JsonElement): String {
    val observation = element.jsonObject
    require(observation.keys == OBSERVATION_FIELDS)
    val candidateId = text(observation.getValue("candidateId"))
    require(candidateId.length <= 128)
    val exitToken = observation.getValue("exitCode").jsonPrimitive
    require(!exitToken.isString && exitToken.content.matches(EXIT_CODE))
    val exitCode = requireNotNull(exitToken.content.toIntOrNull())
    boolean(observation, "networkIsolated")
    val stdoutHex = text(observation.getValue("stdoutHex"))
    val stderrHex = text(observation.getValue("stderrHex"))
    require(stdoutHex.matches(LOWER_HEX) && stderrHex.matches(LOWER_HEX))
    require(text(observation.getValue("signature")) == "$exitCode:$stdoutHex:$stderrHex")
    return candidateId
}

/**
 * The producer's JSON type for every field a report carries. A partial report withholds its summary, but a field it
 * does carry is checked exactly as in a complete one; only presence and cross-field consistency are complete-only.
 */
private fun checkPresentExplorationFields(root: JsonObject, versioned: Boolean) {
    for (name in listOf("candidateCount", "baselineOutputSignatures", "expandedOutputSignatures")) if (name in root) count(root, name)
    if ("coverageIncreased" in root) boolean(root, "coverageIncreased")
    root["newOutputSignatures"]?.let { values -> values.jsonArray.forEach(::text) }
    // The producer writes angr diagnostics as an object, or null when angr did not run.
    root["angr"]?.let { require(it is JsonObject || it is JsonNull) }
    // Version-two rows have exactly the producer's fields and types; legacy rows stay display-tolerant.
    root["candidates"]?.jsonArray?.let { candidates ->
        if (versioned) {
            require(candidates.size <= 1000)
            val rows = candidates.map(::checkVersionedCandidate)
            require(rows.map { it.first }.toSet().size == rows.size && rows.map { it.second }.toSet().size <= 64)
        }
    }
    root["observations"]?.jsonArray?.let { observations ->
        if (versioned) {
            require(observations.size <= 1000)
            val ids = observations.map(::checkVersionedObservation)
            require(ids.toSet().size == ids.size)
        }
    }
    root["retainedInputs"]?.jsonArray?.let { retained ->
        require(retained.size <= 1000)
        val ids = HashSet<String>()
        retained.forEach { item ->
            val input = item.jsonObject
            require(input.keys == setOf("id", "args", "stdinHex"))
            require(ids.add(identity(input.getValue("id"))))
            val args = input.getValue("args").jsonArray
            require(args.size <= 256 && args.all { text(it).length <= 8192 })
            val stdinHex = text(input.getValue("stdinHex"))
            require(stdinHex.length <= 524_288 && stdinHex.matches(LOWER_HEX))
        }
    }
    if ("retainedInputsOmitted" in root) require(count(root, "retainedInputsOmitted").toULong() <= 10_000u)
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

/** Legacy HTML capture: one bounded read, then [presentWebExploration]. */
internal fun captureWebExplorationPresentation(policy: WebRedactionPolicy, read: () -> ByteArray): WebExplorationClassification {
    val bytes = try { read() } catch (_: Exception) { null }
    return presentWebExploration(policy, bytes)
}

/**
 * Classifies the exact bytes, then builds display rows only from the redacted projection that the JSON download
 * serves. Candidates are paired with observations by their original identifiers, because distinct identifiers can
 * redact to the same text; the rows then carry only projected fields. Without a projection the rows are withheld.
 */
internal fun presentWebExploration(policy: WebRedactionPolicy, bytes: ByteArray?): WebExplorationClassification {
    val (classification, original) = classifyCapturedExploration(bytes)
    val projected = bytes?.let {
        try { WebReportProjection.project(false, it, policy) } catch (failure: Exception) {
            if (failure is java.util.concurrent.CancellationException || failure is InterruptedException) throw failure
            null
        }
    }
    val rows = if (classification.state == "available" && original != null && projected != null)
        explorationRows(original, projected, policy) else null
    return classification.copy(downloadAvailable = projected != null, rows = rows,
        candidateTotal = (original?.get("candidates") as? JsonArray)?.size ?: 0)
}

private const val DISPLAYED_CANDIDATES = 50
private const val STDOUT_PREVIEW_CHARACTERS = 48

private fun explorationRows(original: JsonObject, projectedBytes: ByteArray, policy: WebRedactionPolicy): List<WebExplorationRow>? {
    val projected = try {
        OracleJson.parse(projectedBytes, WebReportProjection.reportLimits(WebReportProjection.MAXIMUM_REPORT_BYTES.toInt())) as? JsonObject
    } catch (failure: Exception) {
        if (failure is java.util.concurrent.CancellationException || failure is InterruptedException) throw failure
        null
    } ?: return null
    val originalCandidates = original["candidates"] as? JsonArray ?: return null
    val originalObservations = original["observations"] as? JsonArray ?: return null
    val candidates = projected["candidates"] as? JsonArray ?: return null
    val observations = projected["observations"] as? JsonArray ?: return null
    // The projection rewrites values in place, so equal positions pair an original row with its redacted row.
    if (candidates.size != originalCandidates.size || observations.size != originalObservations.size) return null
    fun originalId(element: JsonElement, name: String): String? =
        ((element as? JsonObject)?.get(name) as? JsonPrimitive)?.takeIf { it.isString && it.content.isNotEmpty() }?.content
    val candidateIdCounts = originalCandidates.mapNotNull { originalId(it, "id") }.groupingBy { it }.eachCount()
    val observationIndexes = originalObservations.withIndex()
        .mapNotNull { (index, element) -> originalId(element, "candidateId")?.let { it to index } }
        .groupBy({ it.first }, { it.second })
    return originalCandidates.take(DISPLAYED_CANDIDATES).mapIndexed { index, element ->
        val id = originalId(element, "id")
        val matches = id?.let { observationIndexes[it] }.orEmpty()
        val attribution = when {
            id == null -> WebExplorationAttribution.UNMATCHED
            candidateIdCounts.getValue(id) > 1 -> WebExplorationAttribution.AMBIGUOUS_CANDIDATE
            matches.isEmpty() -> WebExplorationAttribution.UNMATCHED
            matches.size > 1 -> WebExplorationAttribution.AMBIGUOUS_OBSERVATION
            else -> WebExplorationAttribution.MATCHED
        }
        val observation = if (attribution == WebExplorationAttribution.MATCHED) observations[matches.single()] as? JsonObject else null
        WebExplorationRow(candidates[index] as? JsonObject, observation, attribution,
            observation?.let { explorationOutput(it["stdoutHex"], policy) })
    }
}

private val DISPLAY_HEX = Regex("(?:[0-9a-fA-F]{2})*")
private val DISPLAY_CONTROL = Regex("[\\p{Cntrl}&&[^\\t]]")

/**
 * Hexadecimal output is only an encoding: a configured value the program printed is plaintext once decoded, so the
 * policy applies to the decoded text, again after control characters are mapped, and only then is the text clipped.
 */
private fun explorationOutput(value: JsonElement?, policy: WebRedactionPolicy): WebExplorationOutput? {
    val hex = (value as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
    if (!hex.matches(DISPLAY_HEX)) return null
    val bytes = ByteArray(hex.length / 2) { ((Character.digit(hex[it * 2], 16) shl 4) or Character.digit(hex[it * 2 + 1], 16)).toByte() }
    val decoded = policy.text(bytes.decodeToString())
    // Removing `\r` can join two halves of a configured value, so the mapped text is redacted again.
    val display = policy.text(decoded.replace("\n", "↵").replace("\r", "").replace(DISPLAY_CONTROL, "·"))
    if (display.length <= STDOUT_PREVIEW_CHARACTERS) return WebExplorationOutput(bytes.size, display, false)
    val end = if (display[STDOUT_PREVIEW_CHARACTERS - 1].isHighSurrogate()) STDOUT_PREVIEW_CHARACTERS - 1 else STDOUT_PREVIEW_CHARACTERS
    return WebExplorationOutput(bytes.size, display.substring(0, end), true)
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
