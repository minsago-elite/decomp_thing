package decompengine.oracle.structural

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Pure metrics over a selected observation. No threshold, benchmark identity or production authority
 * is inferred here: the caller must own the independently admitted observation. Source pointers refer
 * to that complete observation, which must be retained with this projection.
 */
internal object StructuralFunctionAccuracyV1 {
    fun derive(observation: JsonObject): JsonObject {
        // Bound the supplied tree before materializing indexes or expanding per-alias output.
        OracleJson.canonicalBytes(observation, ACCURACY_JSON_LIMITS)
        require(observation["provider"] == JsonPrimitive("selected-twin-boundary-observation-v1") &&
            observation["schemaVersion"] == JsonPrimitive(1)) { "unsupported selected function observation" }
        val twin = observation.accuracyText("twin")
        require(twin in setOf("rich", "stripped")) { "invalid selected function twin" }
        val nearBound = observation.accuracyCount("nearMissBytes")
        require(nearBound in 1..4096) { "invalid near-match bound" }
        val result = observation.accuracyObject("result")
        val exact = result.accuracyRows("exactMatches")
        val near = result.accuracyRows("nearMisses")
        val unmatchedRecovered = result.accuracyRows("falsePositives")
        val unmatchedOracle = result.accuracyRows("falseNegatives")
        val ignored = result.accuracyRows("ignoredExcludedRecoveries")
        val excluded = observation.accuracyRows("excludedFunctions")
        val oracle = linkedMapOf<String, AccuracyOracleFunction>()
        val oracleRvas = hashSetOf<ULong>()
        val recovered = linkedMapOf<String, AccuracyRecoveredFunction>()
        val recoveredByRva = hashMapOf<ULong, AccuracyRecoveredFunction>()
        val statuses = mutableMapOf("recovered" to 0, "partial" to 0, "failed" to 0, "synthetic" to 0)
        val exactIds = hashMapOf<String, String>()

        fun addOracle(row: JsonObject, isExcluded: Boolean): AccuracyOracleFunction {
            val id = row.accuracyText("oracleId")
            val rvaField = if (isExcluded) "rva" else "oracleRva"
            val rva = if (isExcluded && row[rvaField] == JsonNull) null else row.accuracyRva(rvaField)
            val exclusion = if (isExcluded) JsonObject(mapOf(
                "kind" to JsonPrimitive(row.accuracyText("kind")),
                "reason" to JsonPrimitive(row.accuracyText("reason")),
            )) else null
            if (exclusion != null) {
                val kind = exclusion.accuracyText("kind")
                require(kind in setOf("compiler-generated", "inlined") &&
                    (kind == "inlined") == (rva == null)) { "invalid function exclusion address or kind" }
            }
            val aliases = row.accuracyRows(if (isExcluded) "aliases" else "oracleAliases", 256)
            require(aliases.isNotEmpty()) { "oracle function has no aliases" }
            val names = hashSetOf<String>()
            val surviving = arrayListOf<String>()
            for (alias in aliases) {
                val name = alias.accuracyText("name")
                require(name.codePointLength() <= 4096 && names.add(name)) { "duplicate or oversized oracle alias" }
                val availability = if (isExcluded) {
                    val availabilityByTwin = alias.accuracyObject("availability")
                    require(availabilityByTwin.keys == setOf("rich", "stripped")) { "invalid excluded alias availability" }
                    for (selected in listOf("rich", "stripped")) {
                        require(availabilityByTwin.accuracyText(selected) in ACCURACY_AVAILABILITY)
                    }
                    availabilityByTwin.accuracyText(twin)
                } else alias.accuracyText("availability")
                require(availability in ACCURACY_AVAILABILITY) { "invalid oracle alias availability" }
                if (availability == "surviving") {
                    require(rva != null) { "surviving alias has no oracle RVA" }
                    surviving += name
                }
            }
            val function = AccuracyOracleFunction(id, rva, surviving, exclusion)
            require(oracle.size < ACCURACY_MAXIMUM_FUNCTIONS && oracle.putIfAbsent(id, function) == null &&
                (rva == null || oracleRvas.add(rva))) { "duplicate or excessive oracle function partition" }
            return function
        }

        fun addRecovered(row: JsonObject, isIgnored: Boolean): AccuracyRecoveredFunction {
            val function = AccuracyRecoveredFunction(row.accuracyText("recoveredId"), row.accuracyRva("recoveredRva"),
                row.accuracyText("recoveredName"), row.accuracyText("recoveredStatus"), isIgnored)
            require(function.status in statuses) { "invalid recovered function status" }
            require(recovered.size < ACCURACY_MAXIMUM_FUNCTIONS && recovered.putIfAbsent(function.id, function) == null &&
                recoveredByRva.putIfAbsent(function.rva, function) == null) { "duplicate or excessive recovered function partition" }
            statuses[function.status] = statuses.getValue(function.status) + 1
            return function
        }

        excluded.forEach { addOracle(it, true) }
        var nearDistance = 0
        for ((rows, kind) in listOf(exact to "exact", near to "near")) for (row in rows) {
            val reference = addOracle(row, false)
            val candidate = addRecovered(row, false)
            require(row["matchKind"] == JsonPrimitive(kind)) { "match kind differs from its partition" }
            val oracleRva = checkNotNull(reference.rva)
            val distance = if (candidate.rva >= oracleRva) candidate.rva - oracleRva else oracleRva - candidate.rva
            require(if (kind == "exact") distance == 0UL else distance in 1UL..nearBound.toULong()) {
                "function address differs from its exact or near partition"
            }
            val delta = if (candidate.rva >= oracleRva) distance.toLong() else -distance.toLong()
            require(row["deltaBytes"] == JsonPrimitive(delta)) { "function match delta differs from its addresses" }
            if (kind == "exact") exactIds[reference.id] = candidate.id else nearDistance += distance.toInt()
        }
        unmatchedOracle.forEach { addOracle(it, false) }
        unmatchedRecovered.forEach { addRecovered(it, false) }
        for (row in ignored) {
            val candidate = addRecovered(row, true)
            val reference = requireNotNull(oracle[row.accuracyText("oracleId")]) { "ignored function lacks an exclusion" }
            val exclusion = requireNotNull(reference.exclusion) { "ignored recovery is scoreable" }
            require(reference.rva == candidate.rva && exclusion["kind"] == JsonPrimitive("compiler-generated") &&
                row["exclusionKind"] == exclusion["kind"] && row["exclusionReason"] == exclusion["reason"]) {
                "ignored recovery differs from its exclusion"
            }
        }
        for (reference in oracle.values) {
            val candidate = reference.rva?.let(recoveredByRva::get) ?: continue
            require(if (reference.exclusion != null) candidate.ignored else exactIds[reference.id] == candidate.id) {
                "recovered address is in the wrong exact or excluded partition"
            }
        }
        val referenceCount = exact.size + near.size + unmatchedOracle.size
        val scoredRecoveredCount = exact.size + near.size + unmatchedRecovered.size
        val counts = mapOf("referenceCount" to referenceCount, "rawRecoveredCount" to recovered.size,
            "scoredRecoveredCount" to scoredRecoveredCount, "ignoredExcludedCount" to ignored.size,
            "exactMatches" to exact.size, "nearMisses" to near.size, "truePositives" to exact.size + near.size,
            "falsePositives" to unmatchedRecovered.size, "falseNegatives" to unmatchedOracle.size,
            "nearMissDistanceBytes" to nearDistance)
        val boundaries = result.accuracyObject("boundaries")
        counts.forEach { (field, count) -> require(boundaries.accuracyCount(field) == count) {
            "boundary count $field differs from the complete partitions"
        } }
        require(oracle.size == referenceCount + excluded.size && recovered.size == scoredRecoveredCount + ignored.size)
        val observedStatuses = observation.accuracyObject("recoveredOutcomeCounts")
        require(observedStatuses.keys == statuses.keys && statuses.all { (status, count) ->
            observedStatuses.accuracyCount(status) == count
        }) { "recovered outcome counts differ from the complete partitions" }

        val symbols = arrayListOf<JsonObject>()
        val budget = AccuracyProjectionBudget()
        var identityExact = 0
        var identityMismatch = 0
        var identityMissing = 0
        for (reference in oracle.values.sortedWith { left, right ->
            (left.rva == null).compareTo(right.rva == null).takeIf { it != 0 }
                ?: (left.rva ?: 0UL).compareTo(right.rva ?: 0UL).takeIf { it != 0 }
                ?: compareCodePoints(left.id, right.id)
        }) for (name in reference.survivingNames.sortedWith { left, right -> compareCodePoints(left, right) }) {
            val rva = checkNotNull(reference.rva)
            val candidate = recoveredByRva[rva]
            budget.symbol(reference, name, candidate)
            val outcome = when {
                candidate == null -> { identityMissing++; "missing" }
                candidate.name != name -> { identityMismatch++; "name-mismatch" }
                else -> { identityExact++; "exact" }
            }
            symbols += JsonObject(mapOf(
                "oracleId" to JsonPrimitive(reference.id), "name" to JsonPrimitive(name),
                "rva" to JsonPrimitive("0x${rva.toString(16)}"), "oracleExcluded" to JsonPrimitive(reference.exclusion != null),
                "exclusion" to (reference.exclusion ?: JsonNull), "outcome" to JsonPrimitive(outcome),
                "recoveredId" to (candidate?.let { JsonPrimitive(it.id) } ?: JsonNull),
                "recoveredRva" to (candidate?.let { JsonPrimitive("0x${it.rva.toString(16)}") } ?: JsonNull),
                "recoveredName" to (candidate?.let { JsonPrimitive(it.name) } ?: JsonNull),
                "recoveredStatus" to (candidate?.let { JsonPrimitive(it.status) } ?: JsonNull),
            ))
        }
        val report = JsonObject(mapOf(
            "provider" to JsonPrimitive("structural-function-accuracy-v1"), "schemaVersion" to JsonPrimitive(1),
            "twin" to JsonPrimitive(twin),
            "sourcePartitions" to JsonObject(listOf("exactMatches", "nearMisses", "falsePositives", "falseNegatives",
                "ignoredExcludedRecoveries").associateWith { JsonPrimitive("/result/$it") } +
                ("excludedFunctions" to JsonPrimitive("/excludedFunctions"))),
            "oraclePopulation" to JsonObject(mapOf(
                "totalFunctions" to JsonPrimitive(oracle.size), "scoreableFunctions" to JsonPrimitive(referenceCount),
                "excludedFunctions" to JsonPrimitive(excluded.size),
                "compilerGenerated" to JsonPrimitive(excluded.count { it["kind"] == JsonPrimitive("compiler-generated") }),
                "inlined" to JsonPrimitive(excluded.count { it["kind"] == JsonPrimitive("inlined") }),
            )),
            "functionStarts" to JsonObject(mapOf(
                "referenceCount" to JsonPrimitive(referenceCount), "rawRecoveredCount" to JsonPrimitive(recovered.size),
                "scoredRecoveredCount" to JsonPrimitive(scoredRecoveredCount), "ignoredExcludedCount" to JsonPrimitive(ignored.size),
                "exactMatches" to JsonPrimitive(exact.size), "nearMisses" to JsonPrimitive(near.size),
                "falsePositives" to JsonPrimitive(scoredRecoveredCount - exact.size),
                "falseNegatives" to JsonPrimitive(referenceCount - exact.size),
                "precision" to accuracyRatio(exact.size, scoredRecoveredCount),
                "recall" to accuracyRatio(exact.size, referenceCount),
            )),
            "survivingSymbolIdentity" to JsonObject(mapOf(
                "populationDefinition" to JsonPrimitive("all selected-twin surviving oracle aliases, including excluded functions, looked up at the exact oracle RVA"),
                "population" to JsonPrimitive(symbols.size), "exact" to JsonPrimitive(identityExact),
                "nameMismatch" to JsonPrimitive(identityMismatch), "missing" to JsonPrimitive(identityMissing),
                "identityRecovery" to accuracyRatio(identityExact, symbols.size), "symbols" to JsonArray(symbols),
            )),
        ))
        OracleJson.canonicalBytes(report, ACCURACY_JSON_LIMITS)
        return report
    }
}

private const val ACCURACY_MAXIMUM_FUNCTIONS = 20_000
private const val ACCURACY_MAXIMUM_BYTES = 64 * 1024 * 1024
private val ACCURACY_AVAILABILITY = setOf("surviving", "removed", "not-observable")
private val ACCURACY_JSON_LIMITS = StrictJsonLimits(maximumInputBytes = ACCURACY_MAXIMUM_BYTES,
    maximumCanonicalBytes = ACCURACY_MAXIMUM_BYTES, maximumNodes = 1_000_000,
    maximumStringBytes = 16 * 1024 * 1024, maximumTotalStringBytes = 48 * 1024 * 1024)
private data class AccuracyOracleFunction(val id: String, val rva: ULong?, val survivingNames: List<String>, val exclusion: JsonObject?)
private data class AccuracyRecoveredFunction(val id: String, val rva: ULong, val name: String, val status: String, val ignored: Boolean)

/** Charge expansion before creating each row; long exclusion reasons may repeat for many aliases. */
private class AccuracyProjectionBudget {
    private var bytes = 16_384L
    private var nodes = 128

    fun symbol(reference: AccuracyOracleFunction, name: String, candidate: AccuracyRecoveredFunction?) {
        bytes += 1024 // Fixed keys, punctuation, addresses, enums and indentation allowance.
        nodes += 13 // Object, ten fields and the two optional exclusion-object fields.
        for (text in listOfNotNull(reference.id, name, reference.exclusion?.accuracyText("reason"), candidate?.id, candidate?.name)) {
            bytes += escapedUtf8Bytes(text)
        }
        require(bytes <= ACCURACY_MAXIMUM_BYTES && nodes <= 1_000_000) { "function accuracy population exceeds the output budget" }
    }

    private fun escapedUtf8Bytes(text: String): Long {
        var bytes = 2L // Quotes; valid surrogate pairing was checked by the bounded input encoder.
        var index = 0
        while (index < text.length) {
            val character = text[index++]
            bytes += when (character) {
                '"', '\\', '\b', '\u000c', '\n', '\r', '\t' -> 2
                else -> when {
                    character.code < 0x20 -> 6
                    character.code < 0x80 -> 1
                    character.code < 0x800 -> 2
                    Character.isHighSurrogate(character) -> { index++; 4 }
                    else -> 3
                }
            }
        }
        return bytes
    }
}

private fun JsonObject.accuracyObject(field: String): JsonObject =
    requireNotNull(this[field] as? JsonObject) { "function accuracy $field must be an object" }
private fun JsonObject.accuracyRows(field: String, maximum: Int = ACCURACY_MAXIMUM_FUNCTIONS): List<JsonObject> {
    val rows = requireNotNull(this[field] as? JsonArray) { "function accuracy $field must be an array" }
    require(rows.size <= maximum) { "function accuracy $field exceeds its population bound" }
    return rows.map { requireNotNull(it as? JsonObject) { "function accuracy $field row must be an object" } }
}
private fun JsonObject.accuracyText(field: String): String {
    val value = requireNotNull(this[field] as? JsonPrimitive) { "function accuracy $field must be a string" }
    require(value.isString && value.content.isNotEmpty()) { "function accuracy $field must be a nonempty string" }
    return value.content
}
private fun JsonObject.accuracyCount(field: String): Int {
    val value = requireNotNull(this[field] as? JsonPrimitive) { "function accuracy $field must be an integer" }
    require(!value.isString && value.content.matches(Regex("0|[1-9][0-9]*"))) { "function accuracy $field must be nonnegative" }
    return requireNotNull(value.content.toIntOrNull()) { "function accuracy $field exceeds its count bound" }
}
private fun JsonObject.accuracyRva(field: String): ULong {
    val value = accuracyText(field)
    require(value.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})"))) { "function accuracy $field must be a canonical unsigned RVA" }
    return value.substring(2).toULong(16)
}
private fun accuracyRatio(numerator: Int, denominator: Int): JsonObject = JsonObject(mapOf(
    "numerator" to JsonPrimitive(numerator), "denominator" to JsonPrimitive(denominator),
))
