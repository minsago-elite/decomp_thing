package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Immutable result-pointer document for a captured, deliberately unscored full export. */
internal object GccBundledFullExportCliResultV2 {
    const val TREE_MANIFEST_NAME = "full-export-tree-manifest.json"
    const val MAXIMUM_TREE_MANIFEST_BYTES = 64 * 1024 * 1024
    private val TREE_MANIFEST_JSON_LIMITS = StrictJsonLimits(
        maximumInputBytes = MAXIMUM_TREE_MANIFEST_BYTES,
        maximumCanonicalBytes = MAXIMUM_TREE_MANIFEST_BYTES,
        maximumNodes = 1_000_000,
        maximumStringBytes = 4 * 1024 * 1024,
        maximumTotalStringBytes = 32 * 1024 * 1024,
    )

    fun create(
        operationId: String,
        requestSha256: String,
        journalPath: java.nio.file.Path,
        programModelPath: java.nio.file.Path,
        programModelSha256: String,
        programModelBytes: Long,
        functionCount: Long,
        exportAssessmentReceiptSha256: String,
        executionReceiptSha256: String,
        structuralBindingPath: java.nio.file.Path,
        structuralBindingBytes: ByteArray,
        treeManifestPath: java.nio.file.Path,
        treeManifestBytes: ByteArray,
        outputTreeSha256: String,
        operationWallTime: JsonObject,
    ): ByteArray {
        require(operationId.matches(Regex("[a-f0-9]{64}"))) { "full-export operation ID is invalid" }
        listOf(
            requestSha256, programModelSha256, exportAssessmentReceiptSha256,
            executionReceiptSha256, outputTreeSha256,
        ).forEach { require(it.matches(Regex("[a-f0-9]{64}"))) { "full-export result digest is invalid" } }
        require(programModelBytes > 0L && functionCount > 0L) { "full-export model inventory is empty" }
        listOf(journalPath, programModelPath, structuralBindingPath, treeManifestPath).forEach { path ->
            require(path.isAbsolute && path.normalize() == path) { "full-export result paths must be absolute and normalized" }
        }
        require(structuralBindingPath.parent == treeManifestPath.parent &&
            structuralBindingPath.fileName.toString() == "structural-full-export-binding.json" &&
            treeManifestPath.fileName.toString() == TREE_MANIFEST_NAME
        ) { "full-export evidence pointers must name the immutable files in one result directory" }
        require(structuralBindingBytes.isNotEmpty() && structuralBindingBytes.size <= 256 * 1024) {
            "structural full-export binding exceeds its publication bound"
        }
        val binding = OracleJson.parseCanonical(structuralBindingBytes).jsonObject
        require(binding.getValue("provider").jsonPrimitive.content == "gcc-compiler-engine-structural-full-export-binding-v2" &&
            binding.getValue("schemaVersion").jsonPrimitive.content == "2" &&
            binding.getValue("outputTreeSha256").jsonPrimitive.content == outputTreeSha256
        ) { "structural binding does not match the captured full-export tree" }
        val boundModel = binding.getValue("programModel").jsonObject
        require(boundModel.getValue("sha256").jsonPrimitive.content == programModelSha256 &&
            boundModel.getValue("bytes").jsonPrimitive.content == programModelBytes.toString() &&
            boundModel.getValue("functionCount").jsonPrimitive.content == functionCount.toString()
        ) { "CLI model pointer differs from the profile-bound full-export model" }

        require(treeManifestBytes.isNotEmpty() && treeManifestBytes.size <= MAXIMUM_TREE_MANIFEST_BYTES) {
            "full-export tree manifest exceeds its publication bound"
        }
        val treeManifest = OracleJson.parseCanonical(treeManifestBytes, TREE_MANIFEST_JSON_LIMITS).jsonObject
        require(treeManifest.keys == setOf("outputTreeSha256", "tree")) {
            "full-export tree manifest does not match its closed schema"
        }
        val manifestTree = treeManifest.getValue("tree").jsonObject
        require(manifestTree.keys == setOf(
            "kind", "stateSha256", "progressSha256", "language", "compilerSpec",
            "programModelSha256", "programModelBytes", "sidecars",
        )) { "full-export output tree does not match its closed schema" }
        val manifestTreeBytes = OracleJson.canonicalBytes(manifestTree, TREE_MANIFEST_JSON_LIMITS)
        val stateSha256 = manifestTree.getValue("stateSha256").jsonPrimitive
        val progressSha256 = manifestTree.getValue("progressSha256").jsonPrimitive
        val language = manifestTree.getValue("language").jsonPrimitive
        val compilerSpec = manifestTree.getValue("compilerSpec").jsonPrimitive
        require(stateSha256.isString && stateSha256.content.matches(Regex("[a-f0-9]{64}")) &&
            progressSha256.isString && progressSha256.content.matches(Regex("[a-f0-9]{64}")) &&
            language.isString && language.content.isNotBlank() &&
            compilerSpec.isString && compilerSpec.content.isNotBlank()
        ) { "full-export output tree contains invalid state, progress, or loader identity" }
        require(manifestTree.getValue("sidecars") is JsonObject) {
            "full-export output tree sidecar inventory is not an object"
        }
        require(treeManifest.getValue("outputTreeSha256").jsonPrimitive.content == outputTreeSha256 &&
            manifestTree.getValue("kind").jsonPrimitive.content == "gcc-bundled-full-export-output-tree-v2" &&
            OracleArtifacts.sha256(manifestTreeBytes) == outputTreeSha256
        ) { "retained full-export tree manifest does not bind the captured output tree" }
        require(manifestTree.getValue("programModelSha256").jsonPrimitive.content == programModelSha256 &&
            manifestTree.getValue("programModelBytes").jsonPrimitive.longOrNull == programModelBytes
        ) { "retained full-export tree model differs from the profile-bound model" }
        return OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-bundled-cli-full-export-result-v2"),
            "schemaVersion" to JsonPrimitive(2),
            "complete" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false),
            "scored" to JsonPrimitive(false),
            "operationId" to JsonPrimitive(operationId),
            "requestSha256" to JsonPrimitive(requestSha256),
            "journal" to JsonPrimitive(journalPath.toString()),
            "programModel" to JsonPrimitive(programModelPath.toString()),
            "programModelSha256" to JsonPrimitive(programModelSha256),
            "programModelBytes" to JsonPrimitive(programModelBytes),
            "functionCount" to JsonPrimitive(functionCount),
            "outputTreeSha256" to JsonPrimitive(outputTreeSha256),
            "outputTreeManifest" to JsonPrimitive(treeManifestPath.toString()),
            "outputTreeManifestSha256" to JsonPrimitive(OracleArtifacts.sha256(treeManifestBytes)),
            "exportAssessmentReceiptSha256" to JsonPrimitive(exportAssessmentReceiptSha256),
            "executionReceiptSha256" to JsonPrimitive(executionReceiptSha256),
            "structuralBinding" to JsonPrimitive(structuralBindingPath.toString()),
            "structuralBindingSha256" to JsonPrimitive(OracleArtifacts.sha256(structuralBindingBytes)),
            "operationWallTime" to operationWallTime,
            "scratchDisposition" to JsonPrimitive("retained; structural replay and release eligibility unqualified"),
        )))
    }
}
