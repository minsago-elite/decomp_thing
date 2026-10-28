package decompengine.oracle.gcc

import decompengine.oracle.core.OracleJson
import decompengine.oracle.structural.StructuralProductionReplayContract
import decompengine.oracle.structural.VerifiedStructuralInputsV1
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/** GCC acceptance policy applied only to measurements derived from the live admitted model. */
internal object GccDriverProductionFunctionAccuracyV1 {
    const val SCORE_NAME = "gcc-driver-production-function-accuracy.json"
    const val SCOPE = "selected-function-starts-and-surviving-symbol-identities"

    fun create(inputs: VerifiedStructuralInputsV1): ByteArray {
        require(inputs.profileId == "gcc-driver-16.2.0") { "function accuracy requires the authenticated GCC driver" }
        val scoreBytes = StructuralProductionReplayContract.scoreFunctionAccuracy(inputs)
        val score = OracleJson.parseCanonical(scoreBytes, StructuralProductionReplayContract.FUNCTION_ACCURACY_LIMITS).jsonObject
        require(score["functionOracleSha256"] == JsonPrimitive(GccDriverStructuralBoundaryEvidenceV1.FUNCTION_ORACLE_SHA256)) {
            "function accuracy does not use the independently pinned GCC oracle"
        }
        val measurements = score.getValue("measurements").jsonObject
        val starts = measurements.getValue("functionStarts").jsonObject
        val symbols = measurements.getValue("survivingSymbolIdentity").jsonObject
        val exact = starts.getValue("exactMatches").jsonPrimitive.long
        val precisionAccepted = meetsExactStartThreshold(exact, starts.getValue("scoredRecoveredCount").jsonPrimitive.long)
        val recallAccepted = meetsExactStartThreshold(exact, starts.getValue("referenceCount").jsonPrimitive.long)
        val identityAccepted = meetsIdentityThreshold(symbols.getValue("exact").jsonPrimitive.long,
            symbols.getValue("population").jsonPrimitive.long)
        return OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-driver-production-function-accuracy-v1"),
            "schemaVersion" to JsonPrimitive(1),
            "scope" to JsonPrimitive(SCOPE),
            "score" to score,
            "acceptance" to JsonObject(mapOf(
                "functionStarts" to JsonObject(mapOf(
                    "minimumPercent" to JsonPrimitive(95),
                    "precisionAccepted" to JsonPrimitive(precisionAccepted),
                    "recallAccepted" to JsonPrimitive(recallAccepted),
                    "accepted" to JsonPrimitive(precisionAccepted && recallAccepted),
                )),
                "survivingSymbolIdentity" to JsonObject(mapOf(
                    "requiredPercent" to JsonPrimitive(100),
                    "accepted" to JsonPrimitive(identityAccepted),
                )),
            )),
            "benchmarkAccepted" to JsonPrimitive(precisionAccepted && recallAccepted && identityAccepted),
            "complete" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false),
        )), StructuralProductionReplayContract.FUNCTION_ACCURACY_LIMITS)
    }

    /** Integer comparison avoids rounding a below-threshold measurement up to 95 percent. */
    internal fun meetsExactStartThreshold(exact: Long, denominator: Long): Boolean {
        require(exact >= 0 && denominator >= 0 && exact <= denominator)
        return denominator > 0 && java.math.BigInteger.valueOf(exact).multiply(java.math.BigInteger.valueOf(20)) >=
            java.math.BigInteger.valueOf(denominator).multiply(java.math.BigInteger.valueOf(19))
    }

    internal fun meetsIdentityThreshold(exact: Long, population: Long): Boolean {
        require(exact >= 0 && population >= 0 && exact <= population)
        return population > 0 && exact == population
    }
}
