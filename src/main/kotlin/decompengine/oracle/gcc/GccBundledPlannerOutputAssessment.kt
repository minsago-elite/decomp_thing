package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.ModulePlanJson
import decompengine.project.ProgramModelJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Assessment of supplied captured bytes, never an execution permit or filesystem capture. */
internal class GccBundledPlannerOutputAssessment private constructor(plan: ByteArray, assessment: ByteArray) {
    private val retainedPlan = plan.copyOf()
    private val retainedAssessment = assessment.copyOf()
    val planBytes: ByteArray get() = retainedPlan.copyOf()
    val canonicalBytes: ByteArray get() = retainedAssessment.copyOf()

    companion object {
        fun assess(request: GccBundledPlannerRequest, capturedModel: ByteArray,
            capturedPlan: ByteArray, capturedMetadata: ByteArray): GccBundledPlannerOutputAssessment {
            require(capturedModel.size == request.modelBytes && OracleArtifacts.sha256(capturedModel) == request.modelSha256)
            val model = ProgramModelJson.readCanonical(capturedModel)
            require(model.inputSha256 == request.inputSha256 && model.functions.size.toLong() == request.functionCount)
            require(model.functions.size.toLong() + model.globals.size + model.types.size <= request.maximumEntities)
            val plan = ModulePlanJson.readCanonical(capturedPlan, request.maximumPlanBytes)
            ModulePlanJson.requireExactOwnership(plan, model, request.layout, request.maximumFunctionsPerModule)
            val metadata = OracleJson.parseCanonical(capturedMetadata, METADATA_LIMITS).jsonObject
            val work = metadata.getValue("sparseWorkUnits").jsonPrimitive
            require(!work.isString && work.content.matches(Regex("0|[1-9][0-9]*")))
            val workUnits = work.content.toLong()
            require(workUnits in 1..request.maximumWorkUnits)
            val fields = mapOf(
                "schemaVersion" to JsonPrimitive(1),
                "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
                "requestSha256" to JsonPrimitive(OracleArtifacts.sha256(request.canonicalBytes)),
                "operationRequestSha256" to JsonPrimitive(request.operationRequestSha256),
                "profilePolicySha256" to JsonPrimitive(request.profilePolicySha256),
                "modelSha256" to JsonPrimitive(request.modelSha256),
                "planSha256" to JsonPrimitive(OracleArtifacts.sha256(capturedPlan)),
                "planBytes" to JsonPrimitive(capturedPlan.size),
                "functionCount" to JsonPrimitive(model.functions.size),
                "globalCount" to JsonPrimitive(model.globals.size), "typeCount" to JsonPrimitive(model.types.size),
                "moduleCount" to JsonPrimitive(plan.modules.size), "sparseWorkUnits" to JsonPrimitive(workUnits),
            )
            val expected = OracleJson.canonicalBytes(JsonObject(fields +
                ("provider" to JsonPrimitive("gcc-bundled-planner-output-v1"))), METADATA_LIMITS)
            require(expected.contentEquals(capturedMetadata)) { "planner metadata differs from captured output bindings" }
            val assessment = OracleJson.canonicalBytes(JsonObject(fields + mapOf(
                "provider" to JsonPrimitive("gcc-bundled-planner-byte-assessment-v1"),
                "authority" to JsonPrimitive("non-authoritative-byte-assessment"),
                "workerOutputSha256" to JsonPrimitive(OracleArtifacts.sha256(capturedMetadata)),
            )), METADATA_LIMITS)
            return GccBundledPlannerOutputAssessment(capturedPlan, assessment)
        }
    }
}

private val METADATA_LIMITS = StrictJsonLimits(maximumInputBytes = 256 * 1024, maximumCanonicalBytes = 256 * 1024,
    maximumDepth = 4, maximumNodes = 128, maximumStringBytes = 256, maximumTotalStringBytes = 8192,
    maximumNumberCharacters = 32)
