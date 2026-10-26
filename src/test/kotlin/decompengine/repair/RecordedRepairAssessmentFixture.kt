package decompengine.repair

import decompengine.project.ModulePlanJson
import decompengine.project.ProgramAnalysisResult
import decompengine.project.RECOVERY_MARKDOWN_IMPLEMENTATION_MARKER
import decompengine.project.ReconstructionAdapters
import decompengine.project.ReconstructionProfile
import decompengine.project.RecoveryAssessmentProjectionV1
import decompengine.project.assessmentReportMaximumBytes
import decompengine.project.renderRecoveryAssessmentMarkdownPrefix
import decompengine.project.sha256
import java.nio.file.Path
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText

/** Authored imported claims with a synthetic overlay digest; never a capability or qualification. */
internal fun installRecordedSelectedRepairAssessment(project: Path, profile: ReconstructionProfile) {
    fun path(role: String) = project.resolve(profile.layout.declaration(role).materialize())
    fun counts(vararg values: Pair<String, Long>) = JsonObject(values.associate { it.first to JsonPrimitive(it.second) })
    fun ratio(unit: String, numerator: Long, denominator: Long) = JsonObject(mapOf(
        "unit" to JsonPrimitive(unit), "numerator" to JsonPrimitive(numerator),
        "denominator" to JsonPrimitive(denominator), "value" to JsonPrimitive(numerator.toDouble() / denominator),
    ))
    val analysis = ProgramAnalysisResult(path("program-model-evidence").readBytes())
    val plan = ModulePlanJson.readCanonical(path("module-plan-evidence").readBytes(), 64 * 1024 * 1024)
    val confidencePath = path("confidence-evidence")
    val confidence = Json.parseToJsonElement(confidencePath.readText()).jsonObject
    val ordinary = confidence.getValue("recoveryAssessment").jsonObject
    val functions = ordinary.getValue("population").jsonObject.getValue("functionCount").jsonPrimitive.content.toLong()
    require(functions >= 1 && plan.modules.single { it.id == "alpha" }.functionIds.size == 1)
    val starts = JsonObject(counts("rawRecoveredCount" to functions, "scoredRecoveredCount" to 1L,
        "ignoredExcludedCount" to functions - 1, "exactMatches" to 1L, "nearMisses" to 0L, "falsePositives" to 0L,
        "falseNegatives" to 1L, "oracleFunctionCount" to functions + 1, "scoreableOracleFunctionCount" to 2L,
        "excludedOracleFunctionCount" to functions - 1, "oracleOnlyFunctionCount" to 1L) + mapOf(
        "precision" to ratio("recovered-function-starts", 1, 1), "recall" to ratio("oracle-function-starts", 1, 2)))
    val aliases = JsonObject(counts("population" to 4L, "exact" to 1L, "nameMismatch" to 1L, "missing" to 2L) +
        ("identityRecovery" to ratio("surviving-oracle-aliases", 1, 4)))
    val source = JsonObject(mapOf("sha256" to JsonPrimitive("d".repeat(64)), "bytes" to JsonPrimitive(1),
        "schemaVersion" to JsonPrimitive(1),
        "scope" to JsonPrimitive("selected-function-starts-and-surviving-symbol-identities-with-complete-model-census")))
    val modules = JsonArray(ordinary.getValue("modules").jsonArray.map { item ->
        val module = item.jsonObject
        val exact = if (module.getValue("moduleId") == JsonPrimitive("alpha")) 1L else 0L
        val raw = module.getValue("population").jsonObject.getValue("functionCount").jsonPrimitive.content.toLong()
        JsonObject(module + ("candidateMeasurements" to counts("rawRecoveredCount" to raw,
            "scoredRecoveredCount" to exact, "ignoredExcludedCount" to raw - exact, "exactMatches" to exact,
            "nearMisses" to 0L, "unmatchedCount" to 0L, "survivingAliasCount" to 2 * exact,
            "exactSurvivingAliasCount" to exact, "mismatchedSurvivingAliasCount" to exact)))
    })
    val recorded = JsonObject(ordinary + mapOf(
        "bindings" to JsonObject(ordinary.getValue("bindings").jsonObject + ("sourceOverlay" to source)),
        "modules" to modules,
        "measurements" to JsonObject(mapOf("functionStarts" to starts, "survivingSymbolIdentity" to aliases)),
        "unassigned" to counts("oracleFunctionCount" to functions + 1, "oracleOnlyFunctionCount" to 1L,
            "excludedOracleFunctionCount" to functions - 1, "survivingAliasCount" to 2L),
    ))
    val projection = RecoveryAssessmentProjectionV1.parsePassive(recorded.toString().toByteArray(), analysis, plan)
    require(projection.verificationDisposition(analysis, plan) == "recorded-origin-unverified")
    val confidenceBytes = (JsonObject(confidence + mapOf("recoveryAssessment" to projection.document,
        "recoveryAssessmentSha256" to JsonPrimitive(projection.sha256))).toString() + "\n").toByteArray()
    confidencePath.writeBytes(confidenceBytes)
    val unresolvedPath = path("unresolved-evidence")
    val unresolvedBefore = unresolvedPath.readText()
    val marker = RECOVERY_MARKDOWN_IMPLEMENTATION_MARKER
    require(marker in unresolvedBefore && unresolvedBefore.indexOf(marker) == unresolvedBefore.lastIndexOf(marker))
    val recoveryPrefix = renderRecoveryAssessmentMarkdownPrefix(analysis.model, projection,
        ReconstructionAdapters.resolve(profile).requiresUnresolvedOutput(profile), assessmentReportMaximumBytes(profile)) {}
    unresolvedPath.writeText(recoveryPrefix + marker + unresolvedBefore.substringAfter(marker))
    val changedHashes = mapOf(profile.layout.declaration("confidence-evidence").materialize() to sha256(confidenceBytes),
        profile.layout.declaration("unresolved-evidence").materialize() to sha256(unresolvedPath.readBytes()))
    val manifestPath = project.resolve("source_tree_manifest.json")
    val manifest = Json.parseToJsonElement(manifestPath.readText()).jsonObject
    manifestPath.writeText(JsonObject(manifest + mapOf(
        "recordedRecoverySummary" to projection.publicSummary(sha256(confidenceBytes)).toJsonObject(),
        "files" to JsonArray(manifest.getValue("files").jsonArray.map { item ->
            val digest = changedHashes[item.jsonObject.getValue("path").jsonPrimitive.content]
            if (digest == null) item else JsonObject(item.jsonObject + ("sha256" to JsonPrimitive(digest)))
        }),
    )).toString() + "\n")
}
