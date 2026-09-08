package decompengine.assessment

import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Describes fixed heuristics without promoting them into calibrated assessments. */
internal enum class HeuristicScoreInterpretation(private val kind: String) {
    STRUCTURAL_RECOVERY("structural-recovery"),
    EXPLORATION_BREADTH("exploration-breadth");

    fun toJson(): String = JsonObject(mapOf(
        "schemaVersion" to JsonPrimitive(1),
        "kind" to JsonPrimitive(kind),
        "calibrationStatus" to JsonPrimitive("uncalibrated"),
        "calibratedProbability" to JsonNull,
        "calibrationArtifactSha256" to JsonNull,
        "empiricalSampleCount" to JsonNull,
    )).toString()
}
