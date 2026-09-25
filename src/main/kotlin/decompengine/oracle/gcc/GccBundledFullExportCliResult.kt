package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Immutable result-pointer document for a captured, deliberately unscored full export. */
internal object GccBundledFullExportCliResultV2 {
    const val TREE_MANIFEST_NAME = "full-export-tree-manifest.json"
    const val MAXIMUM_TREE_MANIFEST_BYTES = 64 * 1024 * 1024

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
