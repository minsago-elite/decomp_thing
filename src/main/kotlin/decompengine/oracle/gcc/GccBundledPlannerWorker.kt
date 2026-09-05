package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.DeterministicModulePlanner
import decompengine.project.ProgramModelJson
import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileDeclaration
import decompengine.project.ProjectFileRole
import decompengine.project.ProjectLayoutProfile
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Immutable computation request. Only the contained launcher may supply execution authority. */
internal class GccBundledPlannerRequest(
    val modelPath: Path,
    val outputDirectory: Path,
    val modelBytes: Int,
    val modelSha256: String,
    val inputSha256: String,
    val functionCount: Long,
    val operationRequestSha256: String,
    val profilePolicySha256: String,
    val layout: ProjectLayoutProfile,
    val maximumFunctionsPerModule: Int,
    val maximumEntities: Int,
    val maximumDependencyEdges: Long,
    val maximumWorkUnits: Long,
    val maximumPlanBytes: Int = MAXIMUM_PLANNER_ARTIFACT_BYTES,
) {
    init {
        requireGccBundledOperationPath(modelPath)
        requireGccBundledOperationPath(outputDirectory)
        require(!modelPath.startsWith(outputDirectory) && !outputDirectory.startsWith(modelPath))
        require(modelBytes in 1..MAXIMUM_PLANNER_ARTIFACT_BYTES && maximumPlanBytes in 1..MAXIMUM_PLANNER_ARTIFACT_BYTES)
        require(functionCount in 1..10_000_000 && maximumFunctionsPerModule in 1..10_000_000)
        require(maximumEntities in 1..10_000_000 && maximumDependencyEdges in 1..1_000_000_000L && maximumWorkUnits in 1..10_000_000_000L)
        require(functionCount <= maximumEntities)
        listOf(modelSha256, inputSha256, operationRequestSha256, profilePolicySha256).forEach {
            require(it.matches(Regex("[a-f0-9]{64}"))) { "planner request has an invalid digest" }
        }
        layout.declaration("module-implementation")
        layout.declaration("module-interface")
    }

    val canonicalBytes: ByteArray get() = OracleJson.canonicalBytes(JsonObject(mapOf(
        "provider" to JsonPrimitive("gcc-bundled-planner-request-v1"),
        "schemaVersion" to JsonPrimitive(1),
        "modelPath" to JsonPrimitive(modelPath.toString()),
        "outputDirectory" to JsonPrimitive(outputDirectory.toString()),
        "modelBytes" to JsonPrimitive(modelBytes), "modelSha256" to JsonPrimitive(modelSha256),
        "inputSha256" to JsonPrimitive(inputSha256), "functionCount" to JsonPrimitive(functionCount),
        "operationRequestSha256" to JsonPrimitive(operationRequestSha256),
        "profilePolicySha256" to JsonPrimitive(profilePolicySha256),
        "layout" to OracleJson.parse(layout.canonicalJson().toByteArray()),
        "maximumFunctionsPerModule" to JsonPrimitive(maximumFunctionsPerModule),
        "maximumEntities" to JsonPrimitive(maximumEntities),
        "maximumDependencyEdges" to JsonPrimitive(maximumDependencyEdges),
        "maximumWorkUnits" to JsonPrimitive(maximumWorkUnits),
        "maximumPlanBytes" to JsonPrimitive(maximumPlanBytes),
    )), PLANNER_REQUEST_LIMITS)

    companion object {
        fun fromProfile(
            profile: GccRetainedCompilerEngineProfile,
            engineId: String,
            exported: GccBundledExecutedOperation,
            operationRequestSha256: String,
            modelPath: Path,
            outputDirectory: Path,
        ): GccBundledPlannerRequest {
            val policy = profile.policyBytes()
            val reconstruction = profile.suite.reconstructionProfile()
            return GccBundledPlannerRequest(modelPath, outputDirectory, exported.assessment.programModelBytes,
                exported.assessment.programModelSha256, profile.suite.engine(engineId).strippedArtifact.sha256,
                exported.assessment.functionCount, operationRequestSha256, OracleArtifacts.sha256(policy),
                reconstruction.layout, reconstruction.budgets.maximumFunctionsPerModule,
                reconstruction.budgets.plannerMaximumEntities, reconstruction.budgets.plannerMaximumDependencyEdges,
                reconstruction.budgets.plannerMaximumWorkUnits).also { profile.requireCurrent() }
        }

        fun parse(bytes: ByteArray): GccBundledPlannerRequest {
            val root = OracleJson.parseCanonical(bytes, PLANNER_REQUEST_LIMITS).jsonObject
            fun string(key: String): String {
                val value = root.getValue(key).jsonPrimitive
                require(value.isString)
                return value.content
            }
            fun number(key: String): Long {
                val value = root.getValue(key).jsonPrimitive
                require(!value.isString && value.content.matches(Regex("0|[1-9][0-9]*")))
                return value.content.toLong()
            }
            fun integer(key: String) = Math.toIntExact(number(key))
            require(string("provider") == "gcc-bundled-planner-request-v1" && integer("schemaVersion") == 1)
            val layout = root.getValue("layout").jsonObject
            require(layout.keys == setOf("schemaVersion", "files"))
            val files = layout.getValue("files").jsonArray.map { element ->
                val entry = element.jsonObject
                require(entry.keys == setOf("id", "pathTemplate", "roles", "contentKind"))
                fun text(key: String) = entry.getValue(key).jsonPrimitive.let { require(it.isString); it.content }
                val roles = entry.getValue("roles").jsonArray.map { value ->
                    require(value.jsonPrimitive.isString)
                    ProjectFileRole.fromWireName(value.jsonPrimitive.content)
                }
                require(roles.size == roles.toSet().size)
                ProjectFileDeclaration(text("id"), text("pathTemplate"), roles.toSet(), ProjectContentKind.fromWireName(text("contentKind")))
            }
            val version = layout.getValue("schemaVersion").jsonPrimitive
            require(!version.isString && version.content == "1")
            return GccBundledPlannerRequest(Path.of(string("modelPath")), Path.of(string("outputDirectory")),
                integer("modelBytes"), string("modelSha256"), string("inputSha256"), number("functionCount"),
                string("operationRequestSha256"), string("profilePolicySha256"), ProjectLayoutProfile(1, files),
                integer("maximumFunctionsPerModule"), integer("maximumEntities"), number("maximumDependencyEdges"),
                number("maximumWorkUnits"), integer("maximumPlanBytes")).also {
                require(it.canonicalBytes.contentEquals(bytes)) { "planner request is not its exact canonical representation" }
            }
        }
    }
}

/** Child computation only. Output files do not attest containment, resources, or release eligibility. */
internal object GccBundledPlannerWorker {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 2) { "planner worker requires request path and digest" }
        require(arguments[1].matches(Regex("[a-f0-9]{64}")))
        val requestBytes = readStablePlannerFile(Path.of(arguments[0]), PLANNER_REQUEST_LIMITS.maximumInputBytes)
        require(OracleArtifacts.sha256(requestBytes) == arguments[1]) { "planner request differs from launch binding" }
        val request = GccBundledPlannerRequest.parse(requestBytes)
        val modelBytes = readStablePlannerFile(request.modelPath, request.modelBytes)
        require(modelBytes.size == request.modelBytes && OracleArtifacts.sha256(modelBytes) == request.modelSha256) {
            "planner model differs from captured export"
        }
        val model = ProgramModelJson.readCanonical(modelBytes)
        require(model.inputSha256 == request.inputSha256 && model.functions.size.toLong() == request.functionCount) {
            "planner model differs from selected engine or function population"
        }
        val run = DeterministicModulePlanner(request.maximumFunctionsPerModule, request.layout, request.maximumEntities,
            request.maximumDependencyEdges, request.maximumWorkUnits).planWithComplexity(model)
        val plan = run.plan.toJson().toByteArray(Charsets.UTF_8)
        require(plan.size in 1..request.maximumPlanBytes) { "planner output exceeds its byte ceiling" }
        val metadata = OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-bundled-planner-output-v1"),
            "schemaVersion" to JsonPrimitive(1), "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
            "requestSha256" to JsonPrimitive(arguments[1]),
            "operationRequestSha256" to JsonPrimitive(request.operationRequestSha256),
            "profilePolicySha256" to JsonPrimitive(request.profilePolicySha256),
            "modelSha256" to JsonPrimitive(request.modelSha256), "planSha256" to JsonPrimitive(OracleArtifacts.sha256(plan)),
            "planBytes" to JsonPrimitive(plan.size), "functionCount" to JsonPrimitive(model.functions.size),
            "globalCount" to JsonPrimitive(model.globals.size), "typeCount" to JsonPrimitive(model.types.size),
            "moduleCount" to JsonPrimitive(run.plan.modules.size),
            "sparseWorkUnits" to JsonPrimitive(run.complexity.sparseWorkUnits),
        )))
        requireGccBundledOperationPath(request.outputDirectory)
        require(request.outputDirectory.toRealPath() == request.outputDirectory && Files.isDirectory(request.outputDirectory, LinkOption.NOFOLLOW_LINKS))
        // CREATE_NEW preserves prior and partial results; only a successful host-validated invocation may be consumed.
        publishPlannerFile(request.outputDirectory.resolve("module_plan.json"), plan)
        publishPlannerFile(request.outputDirectory.resolve("planner-output.json"), metadata)
    }
}

private fun readStablePlannerFile(path: Path, maximum: Int): ByteArray {
    requireGccBundledOperationPath(path)
    require(path.toRealPath() == path) { "planner input path contains indirection" }
    val before = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    require(before.isRegularFile && before.size() in 1..maximum.toLong()) { "planner input is outside its file bound" }
    val bytes = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { it.readNBytes(maximum + 1) }
    val after = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    require(bytes.size.toLong() == before.size() && before.fileKey() == after.fileKey() &&
        before.size() == after.size() && before.lastModifiedTime() == after.lastModifiedTime()) { "planner input changed during read" }
    return bytes
}

private fun publishPlannerFile(path: Path, bytes: ByteArray) {
    FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { channel ->
        val buffer = ByteBuffer.wrap(bytes)
        while (buffer.hasRemaining()) channel.write(buffer)
        channel.force(true)
    }
    FileChannel.open(path.parent, StandardOpenOption.READ).use { it.force(true) }
}

private const val MAXIMUM_PLANNER_ARTIFACT_BYTES = 512 * 1024 * 1024
private val PLANNER_REQUEST_LIMITS = StrictJsonLimits(maximumInputBytes = 256 * 1024, maximumCanonicalBytes = 256 * 1024,
    maximumDepth = 16, maximumNodes = 8192, maximumStringBytes = 4096, maximumTotalStringBytes = 192 * 1024,
    maximumNumberCharacters = 32)

internal fun gccBundledPlannerControlName(operationRequestSha256: String, exportReceiptSha256: String): String {
    require(listOf(operationRequestSha256, exportReceiptSha256).all { it.matches(Regex("[a-f0-9]{64}")) })
    return "control-" + OracleArtifacts.sha256("gcc-bundled-planner-control-v1\n$operationRequestSha256\n$exportReceiptSha256".toByteArray())
}
