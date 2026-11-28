package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.RecoveryStatus
import java.util.Locale
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Passive projection of exact supplied bytes. Even production-shaped input and a successful
 * derivation grant no authority: only the existing owning admission can retain this overlay.
 * Extracted model bytes and all overall entity recovery assessments remain unchanged.
 */
internal object StructuralSelectedFunctionAssessmentV1 {
    const val SCOPE = "selected-function-starts-and-surviving-symbol-identities-with-complete-model-census"
    const val MAXIMUM_BYTES = 64 * 1024 * 1024

    fun derive(programModelBytes: ByteArray, selectedBoundaryScoreBytes: ByteArray, checkpoint: (String) -> Unit = {}): ByteArray {
        fun check(stage: String) {
            selectedAssessmentCheckpoint()
            checkpoint(stage)
            selectedAssessmentCheckpoint()
        }
        check("before selected assessment inputs")
        require(programModelBytes.size in 1..StructuralBoundaryReplayRequestV1.MAXIMUM_MODEL_BYTES &&
            selectedBoundaryScoreBytes.size in 1..MAXIMUM_BYTES) { "selected assessment input exceeds its byte bound" }
        val scoreBytes = selectedBoundaryScoreBytes.copyOf()
        val score = OracleJson.parseCanonical(scoreBytes, SELECTED_ASSESSMENT_LIMITS) { check("selected score: $it") }.assessmentObject()
        check("after selected score parsing")
        score.assessmentKeys(SCORE_FIELDS)
        require(score["provider"] == JsonPrimitive("structural-selected-boundary-production-score-v1") &&
            score["schemaVersion"] == JsonPrimitive(1) &&
            score["scope"] == JsonPrimitive("model-provenance-and-selected-function-boundaries") &&
            score["admittedDomains"] == JsonArray(DOMAINS.map(::JsonPrimitive)) &&
            score["unavailableDomains"] == JsonArray(UNAVAILABLE.map(::JsonPrimitive)) &&
            score["productionVerified"] == JsonPrimitive(true) && score["scored"] == JsonPrimitive(true) &&
            score["complete"] == JsonPrimitive(false) && score["releaseEligible"] == JsonPrimitive(false)) {
            "selected assessment source envelope differs from its scoped production contract"
        }
        score.assessmentText("profileId")
        BINDING_FIELDS.filter { it.endsWith("Sha256") }.forEach { score.assessmentDigest(it) }
        check("before canonical model parsing")
        val snapshot = CanonicalProgramModelStreaming.readCanonical(programModelBytes, StructuralBoundaryReplayWorkerV1.MODEL_LIMITS)
        check("after canonical model parsing")
        val model = snapshot.model
        require(score.assessmentDigest("programModelSha256") == snapshot.sha256 &&
            score.assessmentLong("programModelBytes") == snapshot.sizeBytes.toLong() &&
            score.assessmentDigest("inputSha256") == model.inputSha256) {
            "selected assessment score does not bind the exact canonical model and input"
        }
        val observation = score.getValue("boundaryObservation").assessmentObject()
        observation.assessmentKeys(OBSERVATION_FIELDS)
        require(observation["provider"] == JsonPrimitive("selected-twin-boundary-observation-v1") &&
            observation["schemaVersion"] == JsonPrimitive(1) && observation["twin"] == JsonPrimitive("stripped") &&
            listOf("programModelSha256", "programModelBytes", "inputSha256", "functionOracleSha256")
                .all { observation[it] == score[it] } &&
            listOf("complete", "scored", "releaseEligible").all { observation[it] == JsonPrimitive(false) }) {
            "selected assessment observation differs from its model, oracle, or authority scope"
        }
        // The retained observation uses the structural pretty/ASCII wire format, not OracleJson's
        // UTF-8 canonical format used by the enclosing score and this passive overlay.
        check("before source observation encoding")
        val observationWire = StructuralJsonEncoder(MAXIMUM_BYTES, pretty = true, ensureAscii = true).encode(observation)
        check("after source observation encoding")
        require(OracleArtifacts.sha256(observationWire) == score.assessmentDigest("boundaryObservationSha256")) {
            "selected assessment observation digest differs from its exact wire bytes"
        }
        val binding = score.getValue("fullExportBinding").assessmentObject()
        require(OracleArtifacts.sha256(OracleJson.canonicalBytes(binding, SELECTED_ASSESSMENT_LIMITS) {
            check("full-export binding: $it")
        }) == score.assessmentDigest("fullExportBindingSha256")) { "selected assessment full-export binding digest differs" }
        val boundModel = binding.getValue("programModel").assessmentObject()
        val target = binding.getValue("targetDescriptor").assessmentObject()
        val imageBase = observation.assessmentRva("selectedModelImageBase")
        require(binding["profileId"] == score["profileId"] &&
            binding.getValue("inputBinary").assessmentObject().assessmentDigest("sha256") == model.inputSha256 &&
            boundModel.assessmentDigest("sha256") == snapshot.sha256 &&
            boundModel.assessmentLong("bytes") == snapshot.sizeBytes.toLong() &&
            boundModel.assessmentLong("functionCount") == model.functions.size.toLong() &&
            target.assessmentRva("imageBase") == imageBase) { "selected assessment export lineage differs from its exact model" }

        val result = observation.getValue("result").assessmentObject()
        result.assessmentKeys(RESULT_FIELDS)
        check("before function accuracy derivation")
        val measurements = StructuralFunctionAccuracyV1.derive(observation)
        check("after function accuracy derivation")
        val functions = model.functions.associateBy { it.id }
        val starts = linkedMapOf<String, FunctionStart>()
        val rawRanges = observation["executableRvaRanges"] as? JsonArray
            ?: throw IllegalArgumentException("selected assessment executable ranges must be an array")
        require(rawRanges.size in 1..256) { "selected assessment executable ranges exceed the oracle range bound" }
        val ranges = rawRanges.map { element ->
            check("while validating executable ranges")
            val row = element.assessmentObject()
            row.assessmentKeys(setOf("start", "endExclusive"))
            val start = row.assessmentRva("start")
            val end = row.assessmentRva("endExclusive")
            require(start < end) { "selected assessment executable range is empty" }
            start to end
        }
        require(ranges.zipWithNext().all { (left, right) -> left.second <= right.first }) {
            "selected assessment executable ranges overlap or are unordered"
        }
        for ((partition, outcome) in listOf("exactMatches" to "exact", "nearMisses" to "near-miss",
            "falsePositives" to "unmatched", "ignoredExcludedRecoveries" to "excluded")) {
            result.assessmentRows(partition).forEachIndexed { index, row ->
                check("while joining recovered functions")
                val id = row.assessmentText("recoveredId")
                val function = requireNotNull(functions[id]) { "selected finding refers to an absent model function" }
                require(function.address >= imageBase && row.assessmentRva("recoveredRva") == function.address - imageBase &&
                    ranges.any { (start, end) -> function.address - imageBase >= start && function.address - imageBase < end } &&
                    row.assessmentText("recoveredName") == function.name &&
                    row.assessmentText("recoveredStatus") == function.status.assessmentStatus()) {
                    "selected finding differs from its exact model name, extraction state, or normalized address"
                }
                require(starts.put(id, FunctionStart(outcome, "/result/$partition", index)) == null) {
                    "selected assessment has duplicate recovered function identities"
                }
            }
        }
        require(starts.keys == functions.keys) { "selected assessment omitted recovered model functions" }

        val bindings = JsonObject(BINDING_FIELDS.associateWith { score.getValue(it) } + mapOf(
            "modelSchemaVersion" to JsonPrimitive(model.schemaVersion),
            "selectedBoundaryScoreSha256" to JsonPrimitive(OracleArtifacts.sha256(scoreBytes))))
        val startMetrics = measurements.getValue("functionStarts").assessmentObject()
        val identityMetrics = measurements.getValue("survivingSymbolIdentity").assessmentObject()
        val ratios = JsonObject(mapOf(
            "exactStartPrecision" to ratio(startMetrics.getValue("precision").assessmentObject(), "recovered-function-starts"),
            "exactStartRecall" to ratio(startMetrics.getValue("recall").assessmentObject(), "oracle-function-starts"),
            "survivingSymbolIdentity" to ratio(identityMetrics.getValue("identityRecovery").assessmentObject(), "surviving-oracle-aliases")))
        val entityCount = model.functions.size + model.globals.size + model.types.size
        val skeleton = JsonObject(mapOf(
            "provider" to JsonPrimitive("structural-selected-function-assessment-v1"), "schemaVersion" to JsonPrimitive(1),
            "scope" to JsonPrimitive(SCOPE), "authority" to JsonPrimitive("passive-derived-overlay"),
            "recoveryAssessmentState" to JsonPrimitive("unassessed"), "complete" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false), "calibration" to JsonObject(mapOf(
                "state" to JsonPrimitive("uncalibrated"), "probability" to JsonNull)),
            "unavailableDomains" to JsonArray(UNAVAILABLE.map(::JsonPrimitive)), "bindings" to bindings,
            "entities" to JsonArray(emptyList()), "oracleOnlyFunctions" to JsonArray(emptyList()),
            "excludedOracleFunctions" to JsonArray(emptyList()), "sourceObservation" to observation,
            "measurements" to measurements, "ratios" to ratios,
            "population" to JsonObject(mapOf("unit" to JsonPrimitive("model-entities"),
                "modelEntityCount" to JsonPrimitive(entityCount), "functionCount" to JsonPrimitive(model.functions.size),
                "globalCount" to JsonPrimitive(model.globals.size), "typeCount" to JsonPrimitive(model.types.size),
                "unassessedEntityCount" to JsonPrimitive(entityCount), "functionsWithScopedFindings" to JsonPrimitive(model.functions.size)))))
        // Preflight the complete expansion before allocating entity rows or per-entity alias arrays.
        // Existing source/measurement trees are already bounded, but their combined output is not.
        val budget = AssessmentProjectionBudget { check("while budgeting complete assessment output") }
        budget.charge(skeleton)
        budget.add(1, 0) // Canonical trailing newline.
        if (entityCount > 0) budget.add(3, 0) // Replace the empty top-level entity array's brackets.
        fun reserveEntity(kind: String, id: String, status: RecoveryStatus, start: FunctionStart?) {
            check("while budgeting model entities")
            budget.charge(entity(kind, "", status, start, emptyList()), indentation = 2)
            budget.chargeTextDelta(id)
            budget.add(6, 0) // Element indentation, newline, and a conservative final comma.
        }
        model.functions.forEach { reserveEntity("function", it.id, it.status, starts.getValue(it.id)) }
        model.globals.forEach { reserveEntity("global", it.id, it.status, null) }
        model.types.forEach { reserveEntity("type", it.id, it.status, null) }
        val aliases = identityMetrics.assessmentRows("symbols")
        val functionsWithAliases = hashSetOf<String>()
        aliases.forEachIndexed { index, row ->
            check("while budgeting surviving-symbol joins")
            if (row["recoveredId"] != JsonNull) {
                val id = row.assessmentText("recoveredId")
                require(id in functions) { "selected alias refers to an absent model function" }
                if (functionsWithAliases.add(id)) budget.add(7, 0) // Nested [] -> multiline array.
                budget.add(index.toString().length.toLong() + 10L, 1)
            }
        }
        val oracleOnly = result.assessmentRows("falseNegatives")
        val excluded = observation.assessmentRows("excludedFunctions")
        for ((rows, partition) in listOf(oracleOnly to "/result/falseNegatives", excluded to "/excludedFunctions")) {
            if (rows.isNotEmpty()) budget.add(3, 0)
            rows.forEachIndexed { index, row ->
                check("while budgeting oracle pointers")
                budget.charge(oraclePointer(row, partition, index), indentation = 2)
                budget.add(6, 0)
            }
        }
        check("after complete assessment output budget")
        val aliasRows = hashMapOf<String, MutableList<Int>>()
        aliases.forEachIndexed { index, row ->
            check("while materializing surviving-symbol joins")
            if (row["recoveredId"] != JsonNull) aliasRows.getOrPut(row.assessmentText("recoveredId")) { arrayListOf() }.add(index)
        }
        val entities = ArrayList<JsonObject>(entityCount)
        model.functions.forEach { check("while materializing function census"); entities += entity("function", it.id, it.status, starts.getValue(it.id), aliasRows[it.id].orEmpty()) }
        model.globals.forEach { check("while materializing global census"); entities += entity("global", it.id, it.status, null, emptyList()) }
        model.types.forEach { check("while materializing type census"); entities += entity("type", it.id, it.status, null, emptyList()) }
        // Model canonical order is deterministic within each kind, including historical schemas.
        val overlay = JsonObject(skeleton + mapOf("entities" to JsonArray(entities),
            "oracleOnlyFunctions" to JsonArray(oracleOnly.mapIndexed { index, row -> check("while materializing oracle-only pointers"); oraclePointer(row, "/result/falseNegatives", index) }),
            "excludedOracleFunctions" to JsonArray(excluded.mapIndexed { index, row -> check("while materializing excluded oracle pointers"); oraclePointer(row, "/excludedFunctions", index) })))
        check("before selected assessment encoding")
        return OracleJson.canonicalBytes(overlay, SELECTED_ASSESSMENT_LIMITS) { check("selected assessment encoding: $it") }
            .also { check("after selected assessment encoding") }
    }

    private fun entity(kind: String, id: String, status: RecoveryStatus, start: FunctionStart?, aliases: List<Int>): JsonObject {
        selectedAssessmentCheckpoint()
        return JsonObject(mapOf("kind" to JsonPrimitive(kind), "id" to JsonPrimitive(id),
            "extractionStatus" to JsonPrimitive(status.assessmentStatus()), "recoveryAssessment" to JsonPrimitive("unassessed"),
            "functionStart" to (start?.json() ?: JsonNull), "survivingSymbolRows" to JsonArray(aliases.map(::JsonPrimitive))))
    }

    private fun oraclePointer(row: JsonObject, partition: String, index: Int): JsonObject {
        selectedAssessmentCheckpoint()
        return JsonObject(mapOf("oracleId" to JsonPrimitive(row.assessmentText("oracleId")),
            "sourcePartition" to JsonPrimitive(partition), "sourceIndex" to JsonPrimitive(index)))
    }

    private fun ratio(source: JsonObject, unit: String): JsonObject {
        val numerator = source.assessmentLong("numerator")
        val denominator = source.assessmentLong("denominator")
        require(numerator in 0..denominator) { "selected assessment ratio has inconsistent counts" }
        return JsonObject(mapOf("unit" to JsonPrimitive(unit), "numerator" to JsonPrimitive(numerator),
            "denominator" to JsonPrimitive(denominator),
            "value" to if (denominator == 0L) JsonNull else JsonPrimitive(numerator.toDouble() / denominator)))
    }

    private data class FunctionStart(val outcome: String, val partition: String, val index: Int) {
        fun json() = JsonObject(mapOf("outcome" to JsonPrimitive(outcome), "sourcePartition" to JsonPrimitive(partition),
            "sourceIndex" to JsonPrimitive(index)))
    }

    private val DOMAINS = listOf("model-provenance", "function-boundaries", "surviving-symbol-identities")
    private val UNAVAILABLE = listOf("interfaces", "calls", "globals", "types", "calibration")
    private val BINDING_FIELDS = setOf("profileId", "inputSha256", "programModelSha256", "programModelBytes",
        "fullExportBindingSha256", "functionOracleSha256", "boundaryObservationSha256", "replayRequestSha256",
        "replayAttachmentSha256", "replayExecutionSha256", "replayCaptureSha256", "replayMetadataSha256")
    private val SCORE_FIELDS = BINDING_FIELDS + setOf("provider", "schemaVersion", "scope", "admittedDomains",
        "fullExportBinding", "boundaryObservation", "productionVerified", "scored", "complete", "releaseEligible", "unavailableDomains")
    private val OBSERVATION_FIELDS = setOf("provider", "schemaVersion", "functionOracleSha256", "twin", "inputSha256",
        "programModelSha256", "programModelBytes", "selectedModelImageBase", "executableRvaRanges", "nearMissBytes",
        "policy", "programModelParserLimits", "excludedFunctions", "recoveredOutcomeCounts", "result", "complete", "scored", "releaseEligible")
    private val RESULT_FIELDS = setOf("exactMatches", "nearMisses", "falsePositives", "falseNegatives",
        "ignoredExcludedRecoveries", "nearMatchAssignment", "boundaries", "nameRecovery")
}

/** Conservatively counts the complete pretty canonical expansion before census/alias materialization. */
private class AssessmentProjectionBudget(private val checkpoint: () -> Unit) {
    private var bytes = 0L
    private var nodes = 0L
    private var stringBytes = 0L

    fun add(extraBytes: Long, extraNodes: Long, extraStringBytes: Long = 0) {
        checkpoint()
        bytes += extraBytes
        nodes += extraNodes
        stringBytes += extraStringBytes
        require(bytes <= StructuralSelectedFunctionAssessmentV1.MAXIMUM_BYTES && nodes <= SELECTED_ASSESSMENT_LIMITS.maximumNodes &&
            stringBytes <= SELECTED_ASSESSMENT_LIMITS.maximumTotalStringBytes) {
            "selected assessment projection exceeds its complete output budget"
        }
    }

    fun chargeTextDelta(text: String) { val cost = textCost(text); add(cost.first - 2, 0, cost.second) }

    fun charge(value: JsonElement, indentation: Int = 0) {
        checkpoint()
        when (value) {
            is JsonObject -> {
                require(indentation < SELECTED_ASSESSMENT_LIMITS.maximumDepth) { "selected assessment projection exceeds its depth budget" }
                add(if (value.isEmpty()) 2 else 3L + indentation * 2L + value.size - 1, 1)
                value.forEach { (key, child) ->
                    val cost = textCost(key)
                    add((indentation + 1) * 2L + cost.first + 3, 0, cost.second)
                    charge(child, indentation + 1)
                }
            }
            is JsonArray -> {
                require(indentation < SELECTED_ASSESSMENT_LIMITS.maximumDepth) { "selected assessment projection exceeds its depth budget" }
                add(if (value.isEmpty()) 2 else 3L + indentation * 2L + value.size - 1, 1)
                value.forEach { add((indentation + 1) * 2L + 1, 0); charge(it, indentation + 1) }
            }
            is JsonPrimitive -> if (value.isString) {
                val cost = textCost(value.content)
                add(cost.first, 1, cost.second)
            } else {
                // Floating-point canonical spelling can differ in width from JsonPrimitive.content.
                add(OracleJson.canonicalBytes(value, SELECTED_ASSESSMENT_LIMITS).size.toLong() - 1, 1)
            }
        }
    }

    private fun textCost(value: String): Pair<Long, Long> {
        var bytes = 2L
        var rawBytes = 0L
        var index = 0
        while (index < value.length) {
            if (index and 1023 == 0) checkpoint()
            val char = value[index++]
            rawBytes += when { char.code < 0x80 -> 1; char.code < 0x800 -> 2; Character.isHighSurrogate(char) -> 4; else -> 3 }
            bytes += when (char) {
                '"', '\\', '\b', '\u000c', '\n', '\r', '\t' -> 2
                else -> when {
                    char.code < 0x20 -> 6
                    char.code < 0x80 -> 1
                    char.code < 0x800 -> 2
                    Character.isHighSurrogate(char) -> { index++; 4 }
                    else -> 3
                }
            }
        }
        require(rawBytes <= SELECTED_ASSESSMENT_LIMITS.maximumStringBytes) {
            "selected assessment projection string exceeds its output budget"
        }
        return bytes to rawBytes
    }
}

private fun selectedAssessmentCheckpoint() {
    if (Thread.currentThread().isInterrupted) throw InterruptedException("selected function assessment interrupted")
}
private fun RecoveryStatus.assessmentStatus() = name.lowercase(Locale.ROOT)
private fun JsonElement.assessmentObject() = this as? JsonObject
    ?: throw IllegalArgumentException("selected assessment requires an object")
private fun JsonObject.assessmentKeys(expected: Set<String>) {
    require(keys == expected) { "selected assessment fields differ from the closed contract" }
}
private fun JsonObject.assessmentText(field: String): String = (this[field] as? JsonPrimitive)
    ?.takeIf { it.isString && it.content.isNotEmpty() }?.content
    ?: throw IllegalArgumentException("selected assessment $field must be a nonempty string")
private fun JsonObject.assessmentDigest(field: String): String = assessmentText(field).also {
    require(it.matches(Regex("[0-9a-f]{64}"))) { "selected assessment $field must be a SHA-256 digest" }
}
private fun JsonObject.assessmentLong(field: String): Long {
    val value = this[field] as? JsonPrimitive ?: throw IllegalArgumentException("selected assessment $field must be an integer")
    require(!value.isString && value.content.matches(Regex("0|[1-9][0-9]*"))) { "selected assessment $field must be nonnegative" }
    return requireNotNull(value.content.toLongOrNull()) { "selected assessment $field exceeds its integer bound" }
}
private fun JsonObject.assessmentRva(field: String): ULong = assessmentText(field).let {
    require(it.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})"))) { "selected assessment $field must be a canonical unsigned address" }
    it.substring(2).toULong(16)
}
private fun JsonObject.assessmentRows(field: String): List<JsonObject> {
    val value = this[field] as? JsonArray ?: throw IllegalArgumentException("selected assessment $field must be an array")
    return value.map { selectedAssessmentCheckpoint(); it.assessmentObject() }
}
private val SELECTED_ASSESSMENT_LIMITS = StrictJsonLimits(maximumInputBytes = StructuralSelectedFunctionAssessmentV1.MAXIMUM_BYTES,
    maximumCanonicalBytes = StructuralSelectedFunctionAssessmentV1.MAXIMUM_BYTES, maximumNodes = 1_000_000,
    maximumStringBytes = 16 * 1024 * 1024, maximumTotalStringBytes = 48 * 1024 * 1024)
