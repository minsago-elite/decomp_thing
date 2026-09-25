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
        require(binding.keys == BINDING_KEYS &&
            binding.requiredString("provider", "structural binding") ==
            "gcc-compiler-engine-structural-full-export-binding-v2" &&
            binding.requiredLong("schemaVersion", "structural binding") == 2L
        ) { "structural binding does not match its closed schema" }
        val profileId = binding.requiredString("profileId", "structural binding")
        require(profileId.matches(Regex("[a-z0-9][a-z0-9._-]{0,127}"))) {
            "structural binding profile ID is invalid"
        }
        val profileVersion = binding.requiredString("profileVersion", "structural binding")
        require(profileVersion.matches(Regex("[A-Za-z0-9._+-]{1,64}"))) {
            "structural binding profile version is invalid"
        }
        require(binding.requiredString("sourceRevision", "structural binding").matches(Regex("[a-f0-9]{40}"))) {
            "structural binding source revision is invalid"
        }
        val compilerEngineProfileSha256 = binding.requiredDigest("compilerEngineProfileSha256", "structural binding")
        binding.requiredDigest("artifactManifestSha256", "structural binding")
        require(binding.requiredDigest("outputTreeSha256", "structural binding") == outputTreeSha256) {
            "structural binding does not match the captured full-export tree"
        }

        val targetDescriptor = binding.getValue("targetDescriptor") as? JsonObject
            ?: throw IllegalArgumentException("structural binding target descriptor must be an object")
        require(targetDescriptor.keys == TARGET_DESCRIPTOR_KEYS) {
            "structural binding target descriptor does not match its closed schema"
        }
        require(binding.requiredDigest("targetDescriptorSha256", "structural binding") ==
            OracleArtifacts.sha256(OracleJson.canonicalBytes(targetDescriptor))
        ) { "structural binding target descriptor digest is invalid" }
        val loaderLanguage = targetDescriptor.requiredString("ghidraLanguage", "target descriptor")
        val loaderCompilerSpec = targetDescriptor.requiredString("ghidraCompilerSpec", "target descriptor")
        require(targetDescriptor.requiredString("imageBase", "target descriptor").matches(Regex("0x[0-9a-f]+"))) {
            "structural binding target image base is invalid"
        }
        targetDescriptor.requiredDigest("executableRangesSha256", "target descriptor")

        val inputBinary = binding.getValue("inputBinary") as? JsonObject
            ?: throw IllegalArgumentException("structural binding input binary must be an object")
        require(inputBinary.keys == INPUT_BINARY_KEYS) {
            "structural binding input binary does not match its closed schema"
        }
        inputBinary.requiredDigest("sha256", "structural binding input binary")
        require(inputBinary.requiredLong("bytes", "structural binding input binary") > 0L) {
            "structural binding input binary size is invalid"
        }

        val exporter = binding.getValue("exporter") as? JsonObject
            ?: throw IllegalArgumentException("structural binding exporter must be an object")
        require(exporter.keys == EXPORTER_KEYS && exporter.requiredString("recoveryMode", "structural binding exporter") == "full") {
            "structural binding exporter does not match its closed full-recovery schema"
        }
        exporter.requiredDigest("sha256", "structural binding exporter")
        require(exporter.requiredLong("bytes", "structural binding exporter") > 0L) {
            "structural binding exporter size is invalid"
        }

        val ghidraArchive = binding.getValue("ghidraArchive") as? JsonObject
            ?: throw IllegalArgumentException("structural binding Ghidra archive must be an object")
        require(ghidraArchive.keys == BINARY_KEYS) {
            "structural binding Ghidra archive does not match its closed schema"
        }
        ghidraArchive.requiredDigest("sha256", "structural binding Ghidra archive")
        require(ghidraArchive.requiredLong("bytes", "structural binding Ghidra archive") > 0L) {
            "structural binding Ghidra archive size is invalid"
        }

        val boundModel = binding.getValue("programModel").jsonObject
        require(boundModel.keys == PROGRAM_MODEL_KEYS &&
            boundModel.requiredDigest("sha256", "structural binding program model") == programModelSha256 &&
            boundModel.requiredLong("bytes", "structural binding program model") == programModelBytes &&
            boundModel.requiredLong("functionCount", "structural binding program model") == functionCount
        ) { "CLI model pointer differs from the profile-bound full-export model" }

        val lineage = binding.getValue("receiptLineage") as? JsonObject
            ?: throw IllegalArgumentException("structural binding receipt lineage must be an object")
        require(lineage.keys == RECEIPT_LINEAGE_KEYS &&
            lineage.requiredString("provider", "structural binding receipt lineage") ==
            "gcc-bundled-full-export-receipt-lineage-v1" &&
            lineage.requiredLong("schemaVersion", "structural binding receipt lineage") == 1L &&
            lineage.requiredString("engineId", "structural binding receipt lineage") == "cc1" &&
            lineage.requiredString("operationId", "structural binding receipt lineage") == operationId &&
            lineage.requiredDigest("intentSha256", "structural binding receipt lineage") == requestSha256 &&
            lineage.requiredDigest("compilerEngineProfileSha256", "structural binding receipt lineage") ==
            compilerEngineProfileSha256 &&
            lineage.requiredDigest("executionReceiptSha256", "structural binding receipt lineage") == executionReceiptSha256 &&
            lineage.requiredDigest("exportAssessmentReceiptSha256", "structural binding receipt lineage") ==
            exportAssessmentReceiptSha256
        ) { "full-export result identity differs from its authenticated receipt lineage" }
        lineage.requiredDigest("executionPayloadSha256", "structural binding receipt lineage")
        lineage.requiredDigest("exportAssessmentSha256", "structural binding receipt lineage")
        require(binding.requiredDigest("receiptLineageSha256", "structural binding") ==
            OracleArtifacts.sha256(OracleJson.canonicalBytes(lineage))
        ) { "structural binding receipt-lineage digest is invalid" }

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
        require(manifestTree.getValue("language").jsonPrimitive.content == loaderLanguage &&
            manifestTree.getValue("compilerSpec").jsonPrimitive.content == loaderCompilerSpec
        ) { "retained full-export loader identity differs from the profile-bound target" }
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

    private val BINDING_KEYS = setOf(
        "provider", "schemaVersion", "profileId", "profileVersion", "sourceRevision",
        "compilerEngineProfileSha256", "artifactManifestSha256", "targetDescriptor",
        "targetDescriptorSha256", "inputBinary", "exporter", "ghidraArchive", "programModel",
        "outputTreeSha256", "receiptLineage", "receiptLineageSha256",
    )
    private val TARGET_DESCRIPTOR_KEYS = setOf(
        "id", "architecture", "abi", "machine", "osAbi", "elfClass", "dataEncoding", "pointerBits",
        "elfType", "ghidraLanguage", "ghidraCompilerSpec", "imageBase", "executableRangesSha256",
    )
    private val INPUT_BINARY_KEYS = setOf("sha256", "bytes")
    private val BINARY_KEYS = setOf("sha256", "bytes")
    private val EXPORTER_KEYS = setOf("sha256", "bytes", "recoveryMode")
    private val PROGRAM_MODEL_KEYS = setOf("sha256", "bytes", "functionCount")
    private val RECEIPT_LINEAGE_KEYS = setOf(
        "provider", "schemaVersion", "operationId", "intentSha256", "engineId",
        "compilerEngineProfileSha256", "executionReceiptSha256", "executionPayloadSha256",
        "exportAssessmentReceiptSha256", "exportAssessmentSha256",
    )
}

private fun JsonObject.requiredString(name: String, label: String): String =
    (this[name] as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.content
        ?: throw IllegalArgumentException("$label.$name must be a string")

private fun JsonObject.requiredLong(name: String, label: String): Long =
    (this[name] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
        ?: throw IllegalArgumentException("$label.$name must be an integer")

private fun JsonObject.requiredDigest(name: String, label: String): String =
    requiredString(name, label).also { value ->
        require(value.matches(Regex("[a-f0-9]{64}"))) { "$label.$name must be a SHA-256 digest" }
    }
