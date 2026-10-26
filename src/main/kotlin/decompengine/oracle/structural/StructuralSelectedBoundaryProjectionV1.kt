package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

data class StructuralSelectedOracleFunctionV1(val id: String, val rva: ULong)
data class StructuralSelectedRecoveredFunctionV1(val id: String, val rva: ULong, val status: String)

/** Original exclusion evidence is retained, including both twins' alias availability. */
class StructuralSelectedBoundaryExclusionV1 internal constructor(
    val id: String,
    val rva: ULong?,
    val kind: String,
    val reason: String,
    evidence: JsonObject,
) {
    private val snapshot = OracleJson.canonicalBytes(evidence, PROJECTION_LIMITS)
    val evidence: JsonObject get() = OracleJson.parseCanonical(snapshot, PROJECTION_LIMITS).jsonObject
    val canonicalEvidenceBytes: ByteArray get() = snapshot.copyOf()
}

class StructuralSelectedIgnoredRecoveryV1 internal constructor(
    val id: String,
    val rva: ULong,
    val oracleId: String,
    val status: String,
    evidence: JsonObject,
) {
    private val snapshot = OracleJson.canonicalBytes(evidence, PROJECTION_LIMITS)
    val evidence: JsonObject get() = OracleJson.parseCanonical(snapshot, PROJECTION_LIMITS).jsonObject
    val canonicalEvidenceBytes: ByteArray get() = snapshot.copyOf()
}

/**
 * The complete selected function partitions and their already-selected correspondence. This is
 * mapping evidence, never admission of the CALLS domain. In particular, the internal pure parsers
 * cannot confer production authority, even when their input repeats a production report's flags.
 */
class StructuralSelectedBoundaryProjectionV1 private constructor(
    observationBytes: ByteArray,
    reportBytes: ByteArray?,
    inputs: VerifiedStructuralInputsV1?,
) {
    // A Kotlin synthetic constructor bridge must still consume the live capability. A caller-
    // supplied boolean or serialized report cannot turn the pure projection into admitted evidence.
    val productionVerified: Boolean
    private val observationSnapshot = observationBytes.copyOf()
    private val reportSnapshot = reportBytes?.copyOf()
    private val observation = OracleJson.parse(observationSnapshot, PROJECTION_LIMITS).jsonObject
    private val report = reportSnapshot?.let { OracleJson.parseCanonical(it, PROJECTION_LIMITS).jsonObject }

    val twin: String
    val inputSha256: String
    val programModelSha256: String
    val programModelBytes: Long
    val functionOracleSha256: String
    val selectedModelImageBase: ULong
    val boundaryObservationSha256: String = OracleArtifacts.sha256(observationSnapshot)
    val boundaryScoreSha256: String? = reportSnapshot?.let(OracleArtifacts::sha256)
    val profileId: String?
    val fullExportBindingSha256: String?
    val executableRvaRanges: List<Pair<ULong, ULong>>
    /** Scored populations include false negatives/positives, regardless of whether they have calls. */
    val oracleFunctions: Map<String, StructuralSelectedOracleFunctionV1>
    val recoveredFunctions: Map<String, StructuralSelectedRecoveredFunctionV1>
    val oracleToRecovered: Map<String, String>
    val recoveredToOracle: Map<String, String>
    val excludedFunctions: Map<String, StructuralSelectedBoundaryExclusionV1>
    val ignoredRecoveries: Map<String, StructuralSelectedIgnoredRecoveryV1>
    val excludedOracleIds: Set<String>
    val ignoredRecoveredIds: Set<String>
    val canonicalObservationBytes: ByteArray get() = observationSnapshot.copyOf()
    val canonicalBoundaryReportBytes: ByteArray? get() = reportSnapshot?.copyOf()

    init {
        require(observation.keys == OBSERVATION_FIELDS) { "selected observation has missing or unknown fields" }
        require(observationSnapshot.contentEquals(encodeObservation(observation))) {
            "selected observation is not in its canonical byte form"
        }
        listOf("complete", "scored", "releaseEligible").forEach {
            require(observation[it] == JsonPrimitive(false)) { "selected observation cannot claim scoring authority" }
        }
        // Validates disjoint complete partitions, exact/near deltas, exclusion identity and all counts.
        // It does not rematch addresses or names, or turn an unauthenticated observation into authority.
        StructuralFunctionAccuracyV1.derive(observation)
        twin = observation.projectionText("twin")
        inputSha256 = observation.projectionSha("inputSha256")
        programModelSha256 = observation.projectionSha("programModelSha256")
        programModelBytes = observation.projectionModelBytes()
        functionOracleSha256 = observation.projectionSha("functionOracleSha256")
        selectedModelImageBase = observation.projectionRva("selectedModelImageBase")
        observation.projectionObject("policy")
        observation.projectionObject("programModelParserLimits")
        val rangeRows = observation.projectionRows("executableRvaRanges")
        require(rangeRows.size in 1..256) { "selected executable ranges exceed the oracle range bound" }
        val ranges = rangeRows.map { row ->
            require(row.keys == setOf("start", "endExclusive")) { "invalid selected executable range fields" }
            row.projectionRva("start") to row.projectionRva("endExclusive")
        }
        require(ranges.isNotEmpty() && ranges.all { (start, end) -> start < end } &&
            ranges.zipWithNext().all { (left, right) -> left.second <= right.first }) {
            "selected executable ranges must be ordered, nonempty and nonoverlapping"
        }
        executableRvaRanges = immutableList(ranges)
        fun requireExecutable(rva: ULong) {
            require(ranges.any { (start, end) -> rva >= start && rva < end }) {
                "selected function is outside its executable ranges"
            }
        }
        val oracle = linkedMapOf<String, StructuralSelectedOracleFunctionV1>()
        val recovered = linkedMapOf<String, StructuralSelectedRecoveredFunctionV1>()
        val forward = linkedMapOf<String, String>()
        val reverse = linkedMapOf<String, String>()
        fun addOracle(row: JsonObject) {
            val record = StructuralSelectedOracleFunctionV1(row.projectionText("oracleId"), row.projectionRva("oracleRva"))
            requireExecutable(record.rva)
            check(oracle.put(record.id, record) == null)
        }
        fun addRecovered(row: JsonObject) {
            val record = StructuralSelectedRecoveredFunctionV1(row.projectionText("recoveredId"),
                row.projectionRva("recoveredRva"), row.projectionText("recoveredStatus"))
            requireExecutable(record.rva)
            check(recovered.put(record.id, record) == null)
        }
        val result = observation.projectionObject("result")
        for (partition in listOf("exactMatches", "nearMisses")) for (row in result.projectionRows(partition)) {
            addOracle(row)
            addRecovered(row)
            val oracleId = row.projectionText("oracleId")
            val recoveredId = row.projectionText("recoveredId")
            check(forward.put(oracleId, recoveredId) == null && reverse.put(recoveredId, oracleId) == null)
        }
        result.projectionRows("falseNegatives").forEach(::addOracle)
        result.projectionRows("falsePositives").forEach(::addRecovered)
        val exclusions = observation.projectionRows("excludedFunctions").associate { row ->
            val id = row.projectionText("oracleId")
            val rva = if (row["rva"] == JsonNull) null else row.projectionRva("rva")
            rva?.let(::requireExecutable)
            id to StructuralSelectedBoundaryExclusionV1(id, rva, row.projectionText("kind"), row.projectionText("reason"), row)
        }
        val ignored = result.projectionRows("ignoredExcludedRecoveries").associate { row ->
            val id = row.projectionText("recoveredId")
            val rva = row.projectionRva("recoveredRva")
            requireExecutable(rva)
            id to StructuralSelectedIgnoredRecoveryV1(id, rva, row.projectionText("oracleId"),
                row.projectionText("recoveredStatus"), row)
        }
        oracleFunctions = immutableMap(oracle)
        recoveredFunctions = immutableMap(recovered)
        oracleToRecovered = immutableMap(forward)
        recoveredToOracle = immutableMap(reverse)
        excludedFunctions = immutableMap(exclusions)
        ignoredRecoveries = immutableMap(ignored)
        excludedOracleIds = Collections.unmodifiableSet(LinkedHashSet(exclusions.keys))
        ignoredRecoveredIds = Collections.unmodifiableSet(LinkedHashSet(ignored.keys))
        if (report != null) {
            require(report["provider"] == JsonPrimitive("structural-selected-boundary-production-score-v1") &&
                report["schemaVersion"] == JsonPrimitive(1) &&
                report["scope"] == JsonPrimitive("model-provenance-and-selected-function-boundaries") &&
                report["productionVerified"] == JsonPrimitive(true) && report["scored"] == JsonPrimitive(true) &&
                report["complete"] == JsonPrimitive(false) && report["releaseEligible"] == JsonPrimitive(false)) {
                "invalid selected boundary report envelope"
            }
            require(report.projectionObject("boundaryObservation") == observation &&
                report.projectionSha("boundaryObservationSha256") == boundaryObservationSha256 &&
                report.projectionSha("inputSha256") == inputSha256 &&
                report.projectionSha("programModelSha256") == programModelSha256 &&
                report.projectionModelBytes() == programModelBytes &&
                report.projectionSha("functionOracleSha256") == functionOracleSha256) {
                "selected boundary report substitutes an observation or commitment"
            }
            profileId = report.projectionText("profileId")
            fullExportBindingSha256 = report.projectionSha("fullExportBindingSha256")
            require(OracleArtifacts.sha256(OracleJson.canonicalBytes(report.projectionObject("fullExportBinding"),
                PROJECTION_LIMITS)) == fullExportBindingSha256) { "selected boundary export binding digest differs" }
        } else {
            require(inputs == null) { "production projection requires the admitted report" }
            profileId = null
            fullExportBindingSha256 = null
        }
        if (inputs != null) {
            inputs.requireDomain(StructuralReplayDomainV1.MODEL_PROVENANCE)
            inputs.requireDomain(StructuralReplayDomainV1.FUNCTION_BOUNDARIES)
            require(reportSnapshot != null && reportSnapshot.contentEquals(
                StructuralProductionReplayContract.scoreSelectedBoundary(inputs))) {
                "selected boundary projection replaces the admitted report snapshot"
            }
            require(profileId == inputs.profileId && inputSha256 == inputs.inputSha256 &&
                programModelSha256 == inputs.programModelSha256 && programModelBytes == inputs.programModelBytes &&
                fullExportBindingSha256 == OracleArtifacts.sha256(inputs.fullExportBindingBytes)) {
                "selected boundary projection differs from its live model admission"
            }
            require(OracleJson.canonicalBytes(checkNotNull(report).projectionObject("fullExportBinding"),
                PROJECTION_LIMITS).contentEquals(inputs.fullExportBindingBytes)) {
                "selected boundary projection replaces the admitted export snapshot"
            }
        }
        productionVerified = inputs != null
    }

    companion object {
        /** The only production entry consumes the exact live capability, with no replacement bytes. */
        fun project(inputs: VerifiedStructuralInputsV1): StructuralSelectedBoundaryProjectionV1 {
            inputs.requireDomain(StructuralReplayDomainV1.MODEL_PROVENANCE)
            inputs.requireDomain(StructuralReplayDomainV1.FUNCTION_BOUNDARIES)
            val bytes = StructuralProductionReplayContract.scoreSelectedBoundary(inputs)
            return parseReport(bytes, inputs)
        }

        /** Pure fixture/review projection. Never supplies production or call-scoring authority. */
        internal fun fromObservation(bytes: ByteArray): StructuralSelectedBoundaryProjectionV1 =
            StructuralSelectedBoundaryProjectionV1(bytes, null, null)

        /** Production-looking serialized flags do not confer authority on this pure parser. */
        internal fun fromReport(bytes: ByteArray): StructuralSelectedBoundaryProjectionV1 =
            parseReport(bytes, null)

        private fun parseReport(bytes: ByteArray, inputs: VerifiedStructuralInputsV1?): StructuralSelectedBoundaryProjectionV1 {
            val snapshot = bytes.copyOf()
            val report = OracleJson.parseCanonical(snapshot, PROJECTION_LIMITS).jsonObject
            return StructuralSelectedBoundaryProjectionV1(encodeObservation(report.projectionObject("boundaryObservation")),
                snapshot, inputs)
        }
    }
}

private val PROJECTION_LIMITS = StructuralProductionReplayContract.FUNCTION_ACCURACY_LIMITS
private val OBSERVATION_FIELDS = setOf("provider", "schemaVersion", "functionOracleSha256", "twin", "inputSha256",
    "programModelSha256", "programModelBytes", "selectedModelImageBase", "executableRvaRanges", "nearMissBytes",
    "policy", "programModelParserLimits", "excludedFunctions", "recoveredOutcomeCounts", "result", "complete", "scored", "releaseEligible")
private fun encodeObservation(value: JsonObject): ByteArray =
    StructuralJsonEncoder(PROJECTION_LIMITS.maximumCanonicalBytes, pretty = true, ensureAscii = true).encode(value)
private fun <T> immutableList(values: List<T>): List<T> = Collections.unmodifiableList(ArrayList(values))
private fun <K, V> immutableMap(values: Map<K, V>): Map<K, V> = Collections.unmodifiableMap(LinkedHashMap(values))
private fun JsonObject.projectionObject(field: String): JsonObject =
    requireNotNull(this[field] as? JsonObject) { "selected projection $field must be an object" }
private fun JsonObject.projectionRows(field: String): List<JsonObject> =
    requireNotNull(this[field] as? JsonArray) { "selected projection $field must be an array" }.map {
        requireNotNull(it as? JsonObject) { "selected projection $field must contain objects" }
    }
private fun JsonObject.projectionText(field: String): String {
    val value = requireNotNull(this[field] as? JsonPrimitive) { "selected projection $field must be a string" }
    require(value.isString && value.content.isNotEmpty()) { "selected projection $field must be a nonempty string" }
    return value.content
}
private fun JsonObject.projectionSha(field: String): String = projectionText(field).also {
    require(it.matches(Regex("[0-9a-f]{64}"))) { "selected projection $field must be a canonical SHA-256" }
}
private fun JsonObject.projectionRva(field: String): ULong = projectionText(field).let {
    require(it.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})"))) { "selected projection $field must be a canonical address" }
    it.removePrefix("0x").toULong(16)
}
private fun JsonObject.projectionModelBytes(): Long {
    val value = requireNotNull(this["programModelBytes"] as? JsonPrimitive) { "missing selected program model size" }
    require(!value.isString && value.content.matches(Regex("[1-9][0-9]*"))) { "invalid selected program model size" }
    val count = requireNotNull(value.content.toLongOrNull()) { "selected program model size overflows" }
    require(count <= StructuralBoundaryReplayV1Limits.HARD_MAXIMUM_PROGRAM_MODEL_BYTES) { "selected program model exceeds byte limit" }
    return count
}
