package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.project.RecoveredProgramModel
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Exact fixture byte pair used to test the future host-owned model/finding join. */
internal class FixtureStructuralFindingJoinBindingV1 private constructor(
    val programModelSha256: String,
    val inputBinarySha256: String,
    val scoreReportSha256: String,
    val recoveredModelId: String,
    val recoveredModelPayloadSha256: String,
    val boundaryMappingSha256: String,
    val identityMappingSha256: String,
) {
    fun matches(other: FixtureStructuralFindingJoinBindingV1): Boolean =
        programModelSha256 == other.programModelSha256 &&
            inputBinarySha256 == other.inputBinarySha256 &&
            scoreReportSha256 == other.scoreReportSha256 &&
            recoveredModelId == other.recoveredModelId &&
            recoveredModelPayloadSha256 == other.recoveredModelPayloadSha256 &&
            boundaryMappingSha256 == other.boundaryMappingSha256 &&
            identityMappingSha256 == other.identityMappingSha256

    companion object {
        fun capture(
            programModelBytes: ByteArray,
            scoreReport: JsonObject,
            target: StructuralTargetAbiV1,
        ): FixtureStructuralFindingJoinBindingV1 {
            val snapshot = CanonicalProgramModelStreaming.readCanonical(programModelBytes)
            StructuralRecoveryV1.validateFixtureReport(scoreReport, target)
            requireFixtureReport(scoreReport)
            val model = scoreReport.getValue("model").jsonObject
            val provenance = model.getValue("provenance").jsonObject
            val inputBinarySha256 = provenance.getValue("inputBinary").jsonObject
                .getValue("sha256").jsonPrimitive.content
            require(inputBinarySha256 == snapshot.model.inputSha256) {
                "fixture structural findings refer to a different input binary"
            }
            return FixtureStructuralFindingJoinBindingV1(
                programModelSha256 = OracleArtifacts.sha256(programModelBytes),
                inputBinarySha256 = inputBinarySha256,
                scoreReportSha256 = OracleArtifacts.sha256(StructuralRecoveryV1.canonicalReportBytes(scoreReport, target)),
                recoveredModelId = model.getValue("id").jsonPrimitive.content,
                recoveredModelPayloadSha256 = model.getValue("payloadSha256").jsonPrimitive.content,
                boundaryMappingSha256 = scoreReport.getValue("boundaryMapping").jsonObject
                    .getValue("scoreSha256").jsonPrimitive.content,
                identityMappingSha256 = scoreReport.getValue("identityMapping").jsonObject
                    .getValue("sha256").jsonPrimitive.content,
            )
        }
    }
}

internal data class JoinedStructuralEntityFindingV1(
    val kind: String,
    val entityId: String,
    val oracleId: String?,
    val facts: List<JsonObject>,
    /** Fixture findings never alter extracted-model recovery assessment. */
    val recoveryAssessment: String = "unassessed",
) {
    val outcomes: List<String>
        get() = facts.map { it.getValue("outcome").jsonPrimitive.content }
}

internal data class OracleOnlyStructuralEntityFindingV1(
    val kind: String,
    val oracleId: String,
    val facts: List<JsonObject>,
)

internal data class FixtureStructuralFindingJoinV1(
    val programModelSha256: String,
    val inputBinarySha256: String,
    val scoreReportSha256: String,
    val entities: List<JoinedStructuralEntityFindingV1>,
    val oracleOnlyEntities: List<OracleOnlyStructuralEntityFindingV1>,
    val recoveryAssessmentState: String = "unassessed",
    val authority: String = "fixture-only",
)

/** Conservative population view of a verified fixture join, for report-consumer tests. */
internal data class FixtureStructuralAssessmentPopulationV1(
    val programModelSha256: String,
    val scoreReportSha256: String,
    val modelEntityCount: Int,
    val entitiesWithFindings: Int,
    val missingFindingEntities: List<Pair<String, String>>,
    val recoveredOutcomeCounts: Map<String, Int>,
    val oracleOnlyEntityCount: Int,
    val oracleOnlyOutcomeCounts: Map<String, Int>,
    val recoveryAssessmentState: String = "unassessed",
    val authority: String = "fixture-only",
) {
    fun toJson(): JsonObject = JsonObject(linkedMapOf(
        "schemaVersion" to JsonPrimitive(1),
        "authority" to JsonPrimitive(authority),
        "recoveryAssessmentState" to JsonPrimitive(recoveryAssessmentState),
        "programModelSha256" to JsonPrimitive(programModelSha256),
        "scoreReportSha256" to JsonPrimitive(scoreReportSha256),
        "modelEntityCount" to JsonPrimitive(modelEntityCount),
        "entitiesWithFindings" to JsonPrimitive(entitiesWithFindings),
        "missingFindingEntities" to JsonArray(missingFindingEntities.map { (kind, id) ->
            JsonObject(mapOf("kind" to JsonPrimitive(kind), "id" to JsonPrimitive(id)))
        }),
        "recoveredOutcomeCounts" to JsonObject(recoveredOutcomeCounts.mapValues { JsonPrimitive(it.value) }),
        "oracleOnlyEntityCount" to JsonPrimitive(oracleOnlyEntityCount),
        "oracleOnlyOutcomeCounts" to JsonObject(oracleOnlyOutcomeCounts.mapValues { JsonPrimitive(it.value) }),
    ))
}

/**
 * Fixture-only join contract. A production join still requires the unavailable host-created
 * [VerifiedStructuralInputsV1] capability from the production replay owner. This path can never
 * mark extracted entities assessed or publish production evidence.
 */
internal object StructuralRecoveryAssessmentJoinV1 {
    fun summarizeFixture(join: FixtureStructuralFindingJoinV1): FixtureStructuralAssessmentPopulationV1 {
        require(join.authority == "fixture-only" && join.recoveryAssessmentState == "unassessed" &&
            join.entities.all { it.recoveryAssessment == "unassessed" }) {
            "fixture finding summary cannot promote extraction to assessed recovery"
        }
        fun counts(outcomes: Sequence<String>): Map<String, Int> {
            val counted = StructuralRecoveryV1Contract.OUTCOMES.associateWith { 0 }.toMutableMap()
            outcomes.forEach { outcome ->
                require(outcome in counted) { "fixture finding summary has an unsupported outcome" }
                counted[outcome] = Math.addExact(counted.getValue(outcome), 1)
            }
            return counted.toMap()
        }
        val missing = join.entities.filter { it.facts.isEmpty() }
            .map { it.kind to it.entityId }
        return FixtureStructuralAssessmentPopulationV1(
            programModelSha256 = join.programModelSha256,
            scoreReportSha256 = join.scoreReportSha256,
            modelEntityCount = join.entities.size,
            entitiesWithFindings = join.entities.size - missing.size,
            missingFindingEntities = missing,
            recoveredOutcomeCounts = counts(join.entities.asSequence().flatMap { it.outcomes.asSequence() }),
            oracleOnlyEntityCount = join.oracleOnlyEntities.size,
            oracleOnlyOutcomeCounts = counts(join.oracleOnlyEntities.asSequence().flatMap { entity ->
                entity.facts.asSequence().map { it.getValue("outcome").jsonPrimitive.content }
            }),
        )
    }

    fun joinFixture(
        programModelBytes: ByteArray,
        scoreReport: JsonObject,
        target: StructuralTargetAbiV1,
        binding: FixtureStructuralFindingJoinBindingV1,
    ): FixtureStructuralFindingJoinV1 {
        val snapshot = CanonicalProgramModelStreaming.readCanonical(programModelBytes)
        StructuralRecoveryV1.validateFixtureReport(scoreReport, target)
        requireFixtureReport(scoreReport)
        val currentBinding = FixtureStructuralFindingJoinBindingV1.capture(programModelBytes, scoreReport, target)
        require(currentBinding.matches(binding)) {
            "fixture structural findings are stale or do not match the exact model and score bytes"
        }

        val model = snapshot.model
        require(model.schemaVersion == 2) { "structural finding joins require schema-2 extracted models" }
        val modelEntities = modelEntities(model)
        val scoreEntities = scoreReport.getValue("entities").jsonArray
            .map { it.jsonObject }
        val findingsByEntity = linkedMapOf<Pair<String, String>, JsonObject>()
        val oracleOnly = arrayListOf<OracleOnlyStructuralEntityFindingV1>()
        for (entity in scoreEntities) {
            val kind = entity.getValue("kind").jsonPrimitive.content
            val oracleId = entity["oracleId"]?.takeIf { it != JsonNull }?.jsonPrimitive?.content
            val recoveredId = entity["recoveredId"]?.takeIf { it != JsonNull }?.jsonPrimitive?.content
            val facts = entity.getValue("facts").jsonArray.map { it.jsonObject }
            if (recoveredId == null) {
                if (oracleId != null) oracleOnly += OracleOnlyStructuralEntityFindingV1(kind, oracleId, facts)
                continue
            }
            val key = kind to recoveredId
            require(key in modelEntities) {
                "fixture structural finding references an entity absent from the exact program model: $kind/$recoveredId"
            }
            require(findingsByEntity.put(key, entity) == null) {
                "fixture structural findings contain a duplicate stable entity identity: $kind/$recoveredId"
            }
        }

        val joined = modelEntities.sortedWith(compareBy<Pair<String, String>> { it.first }.thenBy { it.second })
            .map { (kind, entityId) ->
                val finding = findingsByEntity[kind to entityId]
                val facts = finding?.getValue("facts")?.jsonArray?.map { it.jsonObject }.orEmpty()
                JoinedStructuralEntityFindingV1(
                    kind = kind,
                    entityId = entityId,
                    oracleId = finding?.get("oracleId")?.takeIf { it != JsonNull }?.jsonPrimitive?.content,
                    facts = facts,
                )
            }

        return FixtureStructuralFindingJoinV1(
            programModelSha256 = binding.programModelSha256,
            inputBinarySha256 = binding.inputBinarySha256,
            scoreReportSha256 = binding.scoreReportSha256,
            entities = joined,
            oracleOnlyEntities = oracleOnly.sortedWith(compareBy<OracleOnlyStructuralEntityFindingV1> { it.kind }.thenBy { it.oracleId }),
        )
    }

    private fun modelEntities(model: RecoveredProgramModel): Set<Pair<String, String>> = buildSet {
        model.functions.forEach { add("function" to it.id) }
        model.globals.forEach { add("global" to it.id) }
        model.types.forEach { add("type" to it.id) }
    }
}

private fun requireFixtureReport(scoreReport: JsonObject) {
    val oracle = scoreReport.getValue("oracle").jsonObject
    require(oracle.getValue("scope") == JsonPrimitive("fixture")) {
        "fixture structural finding join refuses a non-fixture oracle"
    }
    val model = scoreReport.getValue("model").jsonObject
    require(model.getValue("scope") == JsonPrimitive("fixture")) {
        "fixture structural finding join refuses non-fixture scope"
    }
    val identity = scoreReport.getValue("identityMapping").jsonObject
    require(identity.getValue("productionVerified") == JsonPrimitive(false) &&
        identity.getValue("verification") == JsonPrimitive("fixture-payload-digest-only")
    ) { "fixture structural findings cannot assert production identity authority" }
}
