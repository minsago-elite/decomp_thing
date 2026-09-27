package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.charset.StandardCharsets
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

/** Immutable host snapshot of a completed full-recovery export. It is evidence input, not a score capability. */
internal class GccBundledFullExportSnapshot internal constructor(
    val inputSha256: String,
    val inputBytes: Long,
    val exporterSha256: String,
    val exporterBytes: Long,
    val analysisToolSha256: String,
    val analysisToolBytes: Long,
    val language: String,
    val compilerSpec: String,
    val stateSha256: String,
    val progressSha256: String,
    val programModelSha256: String,
    val programModelBytes: Long,
    val functionCount: Long,
    val recovered: Long,
    val partial: Long,
    val failed: Long,
    val reused: Long,
    val outputTreeSha256: String,
    val outputFileCount: Long,
    val capturedBytes: Long,
    programModel: ByteArray,
    sidecarManifest: ByteArray,
) {
    private val model = programModel.copyOf()
    private val sidecars = sidecarManifest.copyOf()
    private val assessment = fullAssessmentBytes(
        inputSha256, inputBytes, exporterSha256, exporterBytes, analysisToolSha256, analysisToolBytes,
        language, compilerSpec, stateSha256, progressSha256, programModelSha256,
        programModelBytes, functionCount, recovered, partial, failed, reused, outputTreeSha256, outputFileCount,
        capturedBytes,
    )
    val programModel: ByteArray get() = model.copyOf()
    val sidecarManifest: ByteArray get() = sidecars.copyOf()
    val assessmentBytes: ByteArray get() = assessment.copyOf()

    init {
        require(programModelBytes == model.size.toLong() && OracleArtifacts.sha256(model) == programModelSha256)
        require(outputTreeSha256.matches(Regex("[a-f0-9]{64}")))
    }
}

private fun fullAssessmentBytes(
    inputSha256: String,
    inputBytes: Long,
    exporterSha256: String,
    exporterBytes: Long,
    analysisToolSha256: String,
    analysisToolBytes: Long,
    language: String,
    compilerSpec: String,
    stateSha256: String,
    progressSha256: String,
    programModelSha256: String,
    programModelBytes: Long,
    functionCount: Long,
    recovered: Long,
    partial: Long,
    failed: Long,
    reused: Long,
    outputTreeSha256: String,
    outputFileCount: Long,
    capturedBytes: Long,
): ByteArray {
    val fields = JsonObject(linkedMapOf(
        "provider" to JsonPrimitive("gcc-bundled-descriptor-full-export-assessment-v2"),
        "schemaVersion" to JsonPrimitive(2),
        "byteAssessmentAuthority" to JsonPrimitive("non-authoritative-byte-assessment"),
        "complete" to JsonPrimitive(false),
        "releaseEligible" to JsonPrimitive(false),
        "recoveryMode" to JsonPrimitive("full"),
        "inputSha256" to JsonPrimitive(inputSha256),
        "inputBytes" to JsonPrimitive(inputBytes),
        "exporterSha256" to JsonPrimitive(exporterSha256),
        "exporterBytes" to JsonPrimitive(exporterBytes),
        "analysisToolSha256" to JsonPrimitive(analysisToolSha256),
        "analysisToolBytes" to JsonPrimitive(analysisToolBytes),
        "language" to JsonPrimitive(language),
        "compilerSpec" to JsonPrimitive(compilerSpec),
        "stateSha256" to JsonPrimitive(stateSha256),
        "progressSha256" to JsonPrimitive(progressSha256),
        "programModelSha256" to JsonPrimitive(programModelSha256),
        "programModelBytes" to JsonPrimitive(programModelBytes),
        "functionCount" to JsonPrimitive(functionCount),
        "recovered" to JsonPrimitive(recovered),
        "partial" to JsonPrimitive(partial),
        "failed" to JsonPrimitive(failed),
        "reused" to JsonPrimitive(reused),
        "outputTreeSha256" to JsonPrimitive(outputTreeSha256),
        "outputFileCount" to JsonPrimitive(outputFileCount),
        "capturedBytes" to JsonPrimitive(capturedBytes),
    ))
    return OracleJson.canonicalBytes(JsonObject(fields + (
        "assessmentSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(fields)))
    )))
}

/** Captures full-mode sidecars after the caller has established worker absence and retained the run lease. */
internal object GccBundledFullExportCapture {
    internal const val MAXIMUM_FULL_FUNCTION_RECORD_BYTES = 64 * 1024 * 1024
    internal const val MAXIMUM_FULL_EVIDENCE_RECORD_BYTES = 1024 * 1024
    internal const val MAXIMUM_FULL_FUNCTIONS = 512L * 256L
    internal const val MAXIMUM_MODEL_BYTES = 512 * 1024 * 1024
    internal const val MAXIMUM_FULL_RECORD_JSON_NODES = 1_000_000
    private const val MAXIMUM_SIDECAR_FILES = 300_000
    private val FUNCTION_ID = Regex("fn_[0-9a-f]{16}")
    private val FUNCTION_FIELDS = listOf(
        "id", "name", "address", "prototype", "extractionStatus", "recoveryAssessment", "calls",
        "referencedGlobals", "strings", "decompiledC",
    )
    private val GLOBAL_FIELDS = listOf(
        "id", "name", "address", "type", "initializer", "extractionStatus", "recoveryAssessment",
    )
    private val TYPE_FIELDS = listOf("id", "declaration", "sourceAddress", "extractionStatus", "recoveryAssessment")
    private val FUNCTION_ARRAY_FIELDS = setOf("calls", "referencedGlobals", "strings")
    private const val TYPE_C_NAME = "[A-Za-z_][A-Za-z0-9_]*"
    private val COMPOSITE_TYPE = Regex("typedef struct ($TYPE_C_NAME) \\{ unsigned char _data\\[([1-9][0-9]{0,9})]; } ($TYPE_C_NAME);")
    private val ENUM_TYPE = Regex("typedef int ($TYPE_C_NAME);")
    private val SCALAR_TYPE = Regex("typedef unsigned char ($TYPE_C_NAME)\\[([1-9][0-9]{0,9})];")
    // appendFailure retains at most 2,048 UTF-16 units plus "..." for each phase.
    // Calls, data references and types contribute three phases; only failed decompilation adds a fourth.
    private const val MAXIMUM_FAILURE_PHASE_UNITS = 2048
    private const val TRUNCATED_FAILURE_PHASE_UNITS = MAXIMUM_FAILURE_PHASE_UNITS + 3
    private const val MAXIMUM_PARTIAL_FAILURE_UNITS = 3 * TRUNCATED_FAILURE_PHASE_UNITS + 2 * 2
    private const val MAXIMUM_FAILED_FAILURE_UNITS = 4 * TRUNCATED_FAILURE_PHASE_UNITS + 3 * 2

    fun capture(
        run: LinuxDescriptor,
        expectedReports: LinuxFileIdentity,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccBundledFullExportSnapshot {
        val byRole = artifacts.associateBy { it.role }
        require(byRole.size == artifacts.size) { "GCC full export capture contains duplicate invocation roles" }
        val expectedInput = byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).sha256
        val expectedInputBytes = byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).bytes
        val expectedExporter = byRole.getValue(GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE).sha256
        val expectedExporterBytes = byRole.getValue(GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE).bytes
        val expectedAnalysisTool = byRole.getValue(GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE).sha256
        val expectedAnalysisToolBytes = byRole.getValue(GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE).bytes
        return LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { reports ->
            require(reports.identity.copy(linkCount = expectedReports.linkCount) == expectedReports) {
                "GCC full export reports directory changed identity"
            }
            val expectedReportNames = setOf(
                "program_model.json.export", "program_model.json", "program_model.json.progress.json",
            )
            require(LinuxFilesystemSyscalls.directoryEntryNames(reports, expectedReportNames.size + 1).toSet() ==
                expectedReportNames
            ) { "GCC full export reports contain missing, extra or uncommitted entries" }
            LinuxFilesystemSyscalls.openDirectoryAt(reports.fd, "program_model.json.export").use { export ->
                requireFullDirectory(export, reports.identity)
                val expectedTop = setOf("state.json", "planning-batches", "functions", "globals", "types", "failures")
                val topNames = LinuxFilesystemSyscalls.directoryEntryNames(export, expectedTop.size + 1).toSet()
                require(topNames == expectedTop) { "GCC full export contains missing or unexpected export-state entries" }
                LinuxFilesystemSyscalls.openDirectoryAt(export.fd, "planning-batches").use { planning ->
                    requireFullDirectory(planning, reports.identity)
                    require(LinuxFilesystemSyscalls.directoryEntryNames(planning, 1).isEmpty()) {
                        "GCC full export cannot contain planning checkpoints"
                    }
                    LinuxFilesystemSyscalls.openDirectoryAt(export.fd, "functions").use { functions ->
                        requireFullDirectory(functions, reports.identity)
                        LinuxFilesystemSyscalls.openDirectoryAt(export.fd, "globals").use { globals ->
                            requireFullDirectory(globals, reports.identity)
                            LinuxFilesystemSyscalls.openDirectoryAt(export.fd, "types").use { types ->
                                requireFullDirectory(types, reports.identity)
                                LinuxFilesystemSyscalls.openDirectoryAt(export.fd, "failures").use { failures ->
                                    requireFullDirectory(failures, reports.identity)
                                    captureStableOutputs(
                                        run, reports, export, planning, functions, globals, types, failures,
                                        expectedReports, expectedInput, expectedExporter, expectedAnalysisTool,
                                        expectedInputBytes, expectedExporterBytes, expectedAnalysisToolBytes,
                                        topNames, limits,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private fun captureStableOutputs(
        run: LinuxDescriptor,
        reports: LinuxDescriptor,
        export: LinuxDescriptor,
        planning: LinuxDescriptor,
        functions: LinuxDescriptor,
        globals: LinuxDescriptor,
        types: LinuxDescriptor,
        failures: LinuxDescriptor,
        expectedReports: LinuxFileIdentity,
        expectedInput: String,
        expectedExporter: String,
        expectedAnalysisTool: String,
        expectedInputBytes: Long,
        expectedExporterBytes: Long,
        expectedAnalysisToolBytes: Long,
        expectedTop: Set<String>,
        limits: GccResumeByteValidationLimits,
    ): GccBundledFullExportSnapshot {
        val capture = GccBoundExportFiles(limits.transitionAggregateBytes)
        val stateBytes = capture.read(export, "state.json", limits.exporterStateBytes)
        val target = requireFullState(stateBytes, expectedInput, expectedExporter, expectedAnalysisTool)
        val progressBytes = capture.read(reports, "program_model.json.progress.json", limits.progressBytes)
        val progress = requireFullProgress(progressBytes)
        require(progress.reused == 0L) { "fresh full GCC export unexpectedly reused function records" }
        val model = capture.read(reports, "program_model.json", minOf(limits.assembledModelBytes, MAXIMUM_MODEL_BYTES))
        requireFullModelHeader(model, expectedInput)
        val modelVerifier = ExactByteVerifier(model, "GCC full program model", MAXIMUM_MODEL_BYTES)
        modelVerifier.accept("{\n  \"schemaVersion\": 2,\n  \"inputSha256\": \"$expectedInput\",\n  \"functions\": [\n")

        val functionNames = captureDirectoryFiles(functions, MAXIMUM_FULL_FUNCTIONS, MAXIMUM_FULL_FUNCTION_RECORD_BYTES)
        require(functionNames.size.toLong() == progress.total &&
            functionNames.all { it.matches(Regex("fn_[0-9a-f]{16}\\.json")) }
        ) { "GCC full export function records differ from the completed progress inventory" }
        val globalNames = captureDirectoryFiles(globals, MAXIMUM_FULL_FUNCTIONS, MAXIMUM_FULL_EVIDENCE_RECORD_BYTES)
        require(globalNames.all { it.matches(Regex("global_[0-9a-f]{16}\\.json")) }) {
            "GCC full export global record names are invalid"
        }
        val typeNames = captureDirectoryFiles(types, MAXIMUM_FULL_FUNCTIONS, MAXIMUM_FULL_EVIDENCE_RECORD_BYTES)
        require(typeNames.all { it.matches(Regex("type_[0-9a-f]{64}\\.json")) }) {
            "GCC full export type record names are invalid"
        }
        val failureNames = captureDirectoryFiles(failures, progress.total, MAXIMUM_FULL_EVIDENCE_RECORD_BYTES)
        require(failureNames.all { it.matches(Regex("fn_[0-9a-f]{16}\\.json")) && it in functionNames }) {
            "GCC full export failure records do not identify exported functions"
        }
        val entries = linkedMapOf<String, JsonObject>()
        val functionStatuses = linkedMapOf<String, String>()
        val globalIds = globalNames.mapTo(hashSetOf()) { it.removeSuffix(".json") }
        val sourceAddresses = hashSetOf<String>()
        val referencedGlobalIds = hashSetOf<String>()
        fun addFiles(prefix: String, directory: LinuxDescriptor, names: List<String>, maximum: Int,
            includedInModel: Boolean = false) {
            require(entries.size + names.size <= MAXIMUM_SIDECAR_FILES) {
                "GCC full export sidecar inventory exceeds its manifest bound"
            }
            for ((index, name) in names.withIndex()) {
                val bytes = capture.read(directory, name, maximum)
                when (prefix) {
                    "functions" -> functionStatuses[name.removeSuffix(".json")] =
                        requireFullFunctionRecord(bytes, name.removeSuffix(".json"), globalIds, sourceAddresses, referencedGlobalIds)
                    "globals" -> sourceAddresses += requireFullGlobalRecord(bytes, name.removeSuffix(".json"))
                    "types" -> requireFullTypeRecord(bytes, name.removeSuffix(".json"), sourceAddresses)
                    "failures" -> requireFullFailureRecord(
                        bytes, name.removeSuffix(".json"), functionStatuses[name.removeSuffix(".json")],
                    )
                }
                if (includedInModel) modelVerifier.acceptRecord(bytes, index + 1 == names.size)
                entries["$prefix/$name"] = fileCommitment(bytes)
            }
        }
        addFiles("functions", functions, functionNames, MAXIMUM_FULL_FUNCTION_RECORD_BYTES, includedInModel = true)
        modelVerifier.accept("  ],\n  \"globals\": [\n")
        require(functionStatuses.values.count { it == "recovered" }.toLong() == progress.recovered &&
            functionStatuses.values.count { it == "partial" }.toLong() == progress.partial &&
            functionStatuses.values.count { it == "failed" }.toLong() == progress.failed
        ) { "GCC full function outcomes differ from completed progress counts" }
        addFiles("globals", globals, globalNames, MAXIMUM_FULL_EVIDENCE_RECORD_BYTES, includedInModel = true)
        require(referencedGlobalIds == globalIds) {
            "GCC full export contains orphaned global sidecars not referenced by any captured function"
        }
        modelVerifier.accept("  ],\n  \"types\": [\n")
        addFiles("types", types, typeNames, MAXIMUM_FULL_EVIDENCE_RECORD_BYTES, includedInModel = true)
        modelVerifier.accept("  ]\n}\n")
        modelVerifier.finish()
        addFiles("failures", failures, failureNames, MAXIMUM_FULL_EVIDENCE_RECORD_BYTES)
        require(failureNames.map { it.removeSuffix(".json") }.toSet() ==
            functionStatuses.filterValues { it != "recovered" }.keys
        ) { "GCC full failure records differ from partial and failed function outcomes" }

        capture.verify()
        require(LinuxFilesystemSyscalls.directoryEntryNames(export, expectedTop.size + 1).toSet() == expectedTop) {
            "GCC full export state inventory changed during capture"
        }
        require(LinuxFilesystemSyscalls.directoryEntryNames(planning, 1).isEmpty()) {
            "GCC planning checkpoint inventory changed during full export capture"
        }
        requireDirectoryNames(functions, functionNames.toSet())
        requireDirectoryNames(globals, globalNames.toSet())
        requireDirectoryNames(types, typeNames.toSet())
        requireDirectoryNames(failures, failureNames.toSet())
        requireNamedDirectory(run, "reports", reports, expectedReports, LinuxFilesystemSyscalls.identity(run.fd))
        requireNamedDirectory(reports, "program_model.json.export", export, export.identity, reports.identity)
        requireNamedDirectory(export, "planning-batches", planning, planning.identity, reports.identity)
        requireNamedDirectory(export, "functions", functions, functions.identity, reports.identity)
        requireNamedDirectory(export, "globals", globals, globals.identity, reports.identity)
        requireNamedDirectory(export, "types", types, types.identity, reports.identity)
        requireNamedDirectory(export, "failures", failures, failures.identity, reports.identity)
        val modelName = "program_model.json"
        val expectedReportNames = setOf("program_model.json.export", modelName, "$modelName.progress.json")
        require(LinuxFilesystemSyscalls.directoryEntryNames(reports, expectedReportNames.size + 1).toSet() ==
            expectedReportNames
        ) {
            "GCC full export reports contain missing, extra or uncommitted entries"
        }

        val manifestLimits = GccBundledFullExportCliResultV2.TREE_MANIFEST_JSON_LIMITS
        val sidecarManifest = OracleJson.canonicalBytes(JsonObject(entries), manifestLimits)
        val outputTree = JsonObject(linkedMapOf(
            "kind" to JsonPrimitive("gcc-bundled-full-export-output-tree-v2"),
            "stateSha256" to JsonPrimitive(OracleArtifacts.sha256(stateBytes)),
            "progressSha256" to JsonPrimitive(OracleArtifacts.sha256(progressBytes)),
            "language" to JsonPrimitive(target.language),
            "compilerSpec" to JsonPrimitive(target.compilerSpec),
            "programModelSha256" to JsonPrimitive(OracleArtifacts.sha256(model)),
            "programModelBytes" to JsonPrimitive(model.size),
            "sidecars" to OracleJson.parseCanonical(sidecarManifest, manifestLimits),
        ))
        val treeBytes = OracleJson.canonicalBytes(outputTree, manifestLimits)
        val treeSha = OracleArtifacts.sha256(treeBytes)
        return GccBundledFullExportSnapshot(
            inputSha256 = expectedInput,
            inputBytes = expectedInputBytes,
            exporterSha256 = expectedExporter,
            exporterBytes = expectedExporterBytes,
            analysisToolSha256 = expectedAnalysisTool,
            analysisToolBytes = expectedAnalysisToolBytes,
            language = target.language,
            compilerSpec = target.compilerSpec,
            stateSha256 = OracleArtifacts.sha256(stateBytes),
            progressSha256 = OracleArtifacts.sha256(progressBytes),
            programModelSha256 = OracleArtifacts.sha256(model),
            programModelBytes = model.size.toLong(),
            functionCount = progress.total,
            recovered = progress.recovered,
            partial = progress.partial,
            failed = progress.failed,
            reused = progress.reused,
            outputTreeSha256 = treeSha,
            outputFileCount = entries.size.toLong() + 3L,
            capturedBytes = capture.bytes,
            programModel = model,
            sidecarManifest = OracleJson.canonicalBytes(JsonObject(linkedMapOf(
                "outputTreeSha256" to JsonPrimitive(treeSha),
                "tree" to outputTree,
            )), manifestLimits),
        )
    }

    private fun captureDirectoryFiles(
        directory: LinuxDescriptor,
        maximumCount: Long,
        maximumBytes: Int,
    ): List<String> {
        require(maximumBytes in 1..MAXIMUM_FULL_FUNCTION_RECORD_BYTES)
        val names = LinuxFilesystemSyscalls.directoryEntryNames(directory, minOf(maximumCount + 1, Int.MAX_VALUE.toLong()).toInt())
        require(names.size.toLong() <= maximumCount && names.distinct().size == names.size) {
            "GCC full export directory exceeds its file-count bound or contains duplicate names"
        }
        for (name in names) {
            require(name.endsWith(".json") && name.length <= 256 && name.none { it == '/' || it == '\\' || it.code < 32 }) {
                "GCC full export contains an unsafe sidecar file name"
            }
        }
        return names.sorted()
    }

    private fun requireFullState(
        bytes: ByteArray,
        expectedInput: String,
        expectedExporter: String,
        expectedAnalysisTool: String,
    ): GccBundledFullExportTarget {
        require(bytes.isNotEmpty() && bytes.last() == '\n'.code.toByte() && bytes.none { it == '\r'.code.toByte() }) {
            "GCC full exporter state is not a complete LF-terminated record"
        }
        val root = OracleJson.parse(bytes).jsonObject
        require(root.keys == setOf(
            "schemaVersion", "exporterVersion", "exporterSha256", "analysisToolSha256", "recoveryMode",
            "inputSha256", "language", "compilerSpec", "semanticStateBinding",
        )) { "GCC full exporter state fields are invalid" }
        require(number(root, "schemaVersion") == 2L && number(root, "exporterVersion") == 11L &&
            string(root, "recoveryMode") == "full" && root.getValue("semanticStateBinding") == JsonNull &&
            string(root, "inputSha256") == expectedInput && string(root, "exporterSha256") == expectedExporter &&
            string(root, "analysisToolSha256") == expectedAnalysisTool
        ) { "GCC full exporter state differs from its authenticated invocation" }
        require(string(root, "language").matches(Regex("[A-Za-z0-9_.:+-]{1,256}")) &&
            string(root, "compilerSpec").matches(Regex("[A-Za-z0-9_.:+-]{1,256}"))) {
            "GCC full exporter target identity is invalid"
        }
        val target = GccBundledFullExportTarget(string(root, "language"), string(root, "compilerSpec"))
        // The validated hashes and target identities need no JSON escaping. Match the pinned
        // exporter's field order and compact encoding before committing the original bytes.
        requireExactExporterRecord(bytes, buildString {
            append("{\"schemaVersion\":2,\"exporterVersion\":").append(number(root, "exporterVersion"))
            append(",\"exporterSha256\":\"").append(expectedExporter)
            append("\",\"analysisToolSha256\":\"").append(expectedAnalysisTool)
            append("\",\"recoveryMode\":\"full\",\"inputSha256\":\"").append(expectedInput)
            append("\",\"language\":\"").append(target.language)
            append("\",\"compilerSpec\":\"").append(target.compilerSpec)
            append("\",\"semanticStateBinding\":null}\n")
        }, "state")
        return target
    }

    private fun requireFullProgress(bytes: ByteArray): FullProgress {
        require(bytes.isNotEmpty() && bytes.last() == '\n'.code.toByte() && bytes.none { it == '\r'.code.toByte() }) {
            "GCC full exporter progress is not a complete LF-terminated record"
        }
        val root = OracleJson.parse(bytes).jsonObject
        require(root.keys == setOf(
            "schemaVersion", "phase", "completed", "total", "recovered", "partial", "failed", "reused", "currentFunction",
        )) { "GCC full exporter progress fields are invalid" }
        val total = number(root, "total")
        val completed = number(root, "completed")
        val recovered = number(root, "recovered")
        val partial = number(root, "partial")
        val failed = number(root, "failed")
        val reused = number(root, "reused")
        require(number(root, "schemaVersion") == 1L && string(root, "phase") == "complete" &&
            root.getValue("currentFunction") == JsonNull && total in 1..MAXIMUM_FULL_FUNCTIONS &&
            completed == total && recovered + partial + failed == total && reused in 0..total
        ) { "GCC full exporter progress is incomplete or is not bound to its state" }
        requireExactExporterRecord(bytes, buildString {
            append("{\"schemaVersion\":1,\"phase\":\"complete\",\"completed\":").append(completed)
            append(",\"total\":").append(total)
            append(",\"recovered\":").append(recovered)
            append(",\"partial\":").append(partial)
            append(",\"failed\":").append(failed)
            append(",\"reused\":").append(reused)
            append(",\"currentFunction\":null}\n")
        }, "progress")
        return FullProgress(total, recovered, partial, failed, reused)
    }

    private fun requireExactExporterRecord(bytes: ByteArray, rendered: String, label: String) {
        require(bytes.contentEquals(rendered.toByteArray(StandardCharsets.UTF_8))) {
            "GCC full exporter $label is not in the exact exporter-defined compact byte form"
        }
    }

    private fun requireFullModelHeader(model: ByteArray, inputSha256: String) {
        val prefix = "{\n  \"schemaVersion\": 2,\n  \"inputSha256\": \"$inputSha256\",\n  \"functions\": [\n".toByteArray(StandardCharsets.UTF_8)
        val suffix = "  ]\n}\n".toByteArray(StandardCharsets.UTF_8)
        require(model.size >= prefix.size + suffix.size && model.copyOfRange(0, prefix.size).contentEquals(prefix) &&
            model.copyOfRange(model.size - suffix.size, model.size).contentEquals(suffix)
        ) { "GCC full program model does not have the exporter-bound input envelope" }
    }

    private fun requireFullFunctionRecord(
        bytes: ByteArray,
        expectedId: String,
        globalIds: Set<String>,
        sourceAddresses: MutableSet<String>,
        referencedGlobalIds: MutableSet<String>,
    ): String {
        val root = strictRecordObject(bytes, MAXIMUM_FULL_FUNCTION_RECORD_BYTES, "function record")
        val status = string(root, "extractionStatus")
        require(root.keys == setOf(
            "id", "name", "address", "prototype", "extractionStatus", "recoveryAssessment", "calls",
            "referencedGlobals", "strings", "decompiledC",
        ) && string(root, "id") == expectedId &&
            status in setOf("recovered", "partial", "failed") &&
            string(root, "recoveryAssessment") == "unassessed"
        ) { "GCC full function record is malformed or is bound to another identity" }
        require(hasProducerFunctionPrototype(string(root, "name"), string(root, "prototype"))) {
            "GCC full function prototype does not contain its producer-rendered name"
        }
        val source = root.getValue("decompiledC")
        require(if (status == "failed") source == JsonNull else source is JsonPrimitive && source.isString) {
            "GCC full function decompiledC contradicts its extraction status"
        }
        val calls = root["calls"] as? JsonArray
            ?: throw IllegalArgumentException("GCC full function calls must be an array")
        require(calls.all { it is JsonPrimitive && it.isString && FUNCTION_ID.matches(it.content) }) {
            "GCC full function calls contains an invalid function identity"
        }
        val references = root["referencedGlobals"] as? JsonArray
            ?: throw IllegalArgumentException("GCC full function referencedGlobals must be an array")
        require(references.all { it is JsonPrimitive && it.isString && it.content in globalIds }) {
            "GCC full function referencedGlobals contains an absent or invalid global identity"
        }
        references.forEach { referencedGlobalIds += (it as JsonPrimitive).content }
        val address = string(root, "address")
        require(canonicalAddress(address) && expectedId == "fn_" + address.removePrefix("0x").padStart(16, '0')) {
            "GCC full function record identity does not match its canonical 64-bit address"
        }
        sourceAddresses += address
        requirePrettyExporterRecord(bytes, root, "function", FUNCTION_FIELDS, FUNCTION_ARRAY_FIELDS, "decompiledC")
        return status
    }

    /**
     * FunctionDB.getPrototypeString(false, false) concatenates the return display name, a space,
     * getName(), and parenthesized parameter display text. Those raw display names may themselves
     * contain spaces and parentheses: validate a possible literal rendering boundary, not a unique
     * C declarator. A linear matcher keeps long or repetitive retained strings within their bounds.
     */
    private fun hasProducerFunctionPrototype(name: String, prototype: String): Boolean {
        if (name.isEmpty() || !prototype.endsWith(')')) return false
        val marker = " $name("
        // At least one return-display character precedes the marker; ')' follows it.
        if (marker.length > prototype.length - 2) return false
        val fallback = IntArray(marker.length)
        var matched = 0
        for (index in 1 until marker.length) {
            while (matched > 0 && marker[index] != marker[matched]) matched = fallback[matched - 1]
            if (marker[index] == marker[matched]) matched++
            fallback[index] = matched
        }
        matched = 0
        for (index in 1 until prototype.lastIndex) {
            while (matched > 0 && prototype[index] != marker[matched]) matched = fallback[matched - 1]
            if (prototype[index] == marker[matched]) matched++
            if (matched == marker.length) return true
        }
        return false
    }

    private fun requireFullGlobalRecord(bytes: ByteArray, expectedId: String): String {
        val root = requireFullNamedRecord(bytes, expectedId, "recovered", setOf(
            "id", "name", "address", "type", "initializer", "extractionStatus", "recoveryAssessment",
        ))
        val address = string(root, "address")
        require(canonicalAddress(address) && expectedId == "global_" + address.removePrefix("0x").padStart(16, '0')) {
            "GCC full global record identity does not match its canonical 64-bit address"
        }
        requirePrettyExporterRecord(bytes, root, "global", GLOBAL_FIELDS, nullableField = "initializer")
        return address
    }

    private fun requireFullTypeRecord(bytes: ByteArray, expectedId: String, sourceAddresses: Set<String>) {
        val root = requireFullNamedRecord(bytes, expectedId, "partial", setOf(
            "id", "declaration", "sourceAddress", "extractionStatus", "recoveryAssessment",
        ))
        val address = string(root, "sourceAddress")
        require(canonicalAddress(address) && address in sourceAddresses) {
            "GCC full type sourceAddress is not a captured function or global address"
        }
        val declaration = string(root, "declaration")
        val prefix = "/* Ghidra type "
        val pathEnd = declaration.indexOf(" */ ", prefix.length)
        require(declaration.startsWith(prefix) && pathEnd > prefix.length) {
            "GCC full type declaration does not retain its encoded Ghidra type path"
        }
        val encodedPath = declaration.substring(prefix.length, pathEnd)
        val path = OracleJson.parse(encodedPath.toByteArray(StandardCharsets.UTF_8), StrictJsonLimits(
            maximumInputBytes = MAXIMUM_FULL_EVIDENCE_RECORD_BYTES,
            maximumCanonicalBytes = MAXIMUM_FULL_EVIDENCE_RECORD_BYTES,
            maximumDepth = 1,
            maximumNodes = 1,
            maximumStringBytes = MAXIMUM_FULL_EVIDENCE_RECORD_BYTES,
            maximumTotalStringBytes = MAXIMUM_FULL_EVIDENCE_RECORD_BYTES,
        ))
        require(path is JsonPrimitive && path.isString && encodedPath == fullTypePathJson(path.content)) {
            "GCC full type path does not use the exporter's canonical comment-safe encoding"
        }
        require(expectedId == "type_" + OracleArtifacts.sha256(path.content.toByteArray(StandardCharsets.UTF_8))) {
            "GCC full type identity does not match its retained Ghidra type path"
        }
        val suffix = declaration.substring(pathEnd + " */ ".length)
        val composite = COMPOSITE_TYPE.matchEntire(suffix)
        val enumeration = ENUM_TYPE.matchEntire(suffix)
        val scalar = SCALAR_TYPE.matchEntire(suffix)
        require(enumeration != null ||
            (composite != null && composite.groupValues[1] == composite.groupValues[3] &&
                composite.groupValues[2].toIntOrNull()?.let { it > 0 } == true) ||
            (scalar != null && scalar.groupValues[2].toIntOrNull()?.let { it > 0 } == true)
        ) { "GCC full type declaration suffix differs from the exporter typedef templates" }
        val declaredName = checkNotNull(composite ?: enumeration ?: scalar).groupValues[1]
        require(hasProducerTypeName(path.content, declaredName, expectedId)) {
            "GCC full type declaration name differs from retained Ghidra path"
        }
        requirePrettyExporterRecord(bytes, root, "type", TYPE_FIELDS)
    }

    /**
     * DataTypePath appends the raw type name, so slash-containing names permit several splits.
     * CategoryPath escapes slashes but not existing backslashes; an escaped trailing slash can
     * itself be the type boundary. Keep every renderable prefix without unescaping the raw suffix.
     */
    private fun hasProducerTypeName(path: String, declaredName: String, id: String): Boolean {
        if (!path.startsWith('/')) return false
        // Sanitization emits one ASCII character per Unicode code point. Therefore only one raw
        // suffix can have this literal sanitized name's length; compare it once, in reverse.
        var literalStart = path.length
        for (index in declaredName.indices.reversed()) {
            if (literalStart == 0) { literalStart = -1; break }
            val point = path.codePointBefore(literalStart)
            val sanitized = when (point) {
                in 'A'.code..'Z'.code, in 'a'.code..'z'.code, in '0'.code..'9'.code, '_'.code -> point.toChar()
                else -> '_'
            }
            if (sanitized != declaredName[index]) { literalStart = -1; break }
            literalStart -= Character.charCount(point)
        }
        val recovered = declaredName == "recovered_$id"
        fun matches(start: Int): Boolean = start == literalStart ||
            (recovered && (start == path.length || path[start] in '0'..'9'))
        if (matches(1)) return true // Root category.
        var nonblankComponent = false
        for (index in 1 until path.length) {
            val character = path[index]
            if (character == '/') {
                // DataTypePath adds a delimiter only if the category does not already end in '/'.
                if (nonblankComponent && path[index - 1] != '/' && matches(index + 1)) return true
                // Keeping a backslash/slash pair within a category component preserves every
                // possible prefix: splitting it cannot rescue an otherwise blank component.
                if (path[index - 1] != '\\') {
                    if (!nonblankComponent) return false
                    nonblankComponent = false
                }
            } else if (!Character.isWhitespace(character)) {
                nonblankComponent = true
            }
        }
        return false
    }

    /** Matches ExportProgramModel.json(path), with every slash escaped for a C comment. */
    private fun fullTypePathJson(path: String): String = buildString {
        append('"')
        for (character in path) when (character) {
            '\\' -> append("\\\\")
            '"' -> append("\\\"")
            '/' -> append("\\/")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (character.code < 0x20) {
                append("\\u").append(character.code.toString(16).padStart(4, '0'))
            } else append(character)
        }
        append('"')
    }

    private fun canonicalAddress(address: String): Boolean =
        address.length in 3..18 && address.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]*)"))

    private fun requireFullNamedRecord(
        bytes: ByteArray,
        expectedId: String,
        expectedStatus: String,
        expectedKeys: Set<String>,
    ): JsonObject {
        val root = strictRecordObject(bytes, MAXIMUM_FULL_EVIDENCE_RECORD_BYTES, "evidence record")
        require(root.keys == expectedKeys && string(root, "id") == expectedId &&
            string(root, "extractionStatus") == expectedStatus &&
            string(root, "recoveryAssessment") == "unassessed"
        ) { "GCC full evidence record is malformed or is bound to another identity" }
        return root
    }

    private fun requireFullFailureRecord(bytes: ByteArray, expectedId: String, expectedStatus: String?) {
        val root = strictRecordObject(bytes, MAXIMUM_FULL_EVIDENCE_RECORD_BYTES, "failure record")
        require(root.keys == setOf("schemaVersion", "functionId", "status", "message") &&
            number(root, "schemaVersion") == 1L && string(root, "functionId") == expectedId &&
            string(root, "status") in setOf("partial", "failed") && string(root, "status") == expectedStatus
        ) { "GCC full failure record is malformed or is bound to another function" }
        val message = string(root, "message")
        require(message.isNotBlank()) { "GCC full failure message must not be blank" }
        // appendFailure replaces CR/LF and applies Java String.trim before each retained phase.
        // Match that ASCII/control trim precisely; other Unicode whitespace can occur in diagnostics.
        require(message.none { it == '\r' || it == '\n' } && message == message.trim { it <= ' ' }) {
            "GCC full failure message contradicts producer normalization"
        }
        val maximumUnits = if (expectedStatus == "failed") MAXIMUM_FAILED_FAILURE_UNITS else MAXIMUM_PARTIAL_FAILURE_UNITS
        require(message.length <= maximumUnits) { "GCC full failure message exceeds its producer UTF-16 bound" }
        require(hasProducerFailurePhases(message, expectedStatus == "failed")) {
            "GCC full failure message contradicts producer phase bounds"
        }
        require(message.toByteArray(StandardCharsets.UTF_8).size <= MAXIMUM_FULL_EVIDENCE_RECORD_BYTES) {
            "GCC full failure message exceeds its byte bound"
        }
        requireExporterSerialization(bytes, "failure") { verifier ->
            verifier.accept("{\"schemaVersion\":1,\"functionId\":")
            verifier.acceptExporterString(expectedId)
            verifier.accept(",\"status\":")
            verifier.acceptExporterString(string(root, "status"))
            verifier.accept(",\"message\":")
            verifier.acceptExporterString(message)
            verifier.accept("}\n")
        }
    }

    /**
     * Exception details may contain delimiters and even phase labels. Accept any bounded partition
     * whose actual phases occur once in producer order, allowing successful evidence phases to be
     * absent. The pinned Ghidra PrettyPrinter supplies non-null C on successful decompilation, so a
     * full failed record must end with decompilation; a partial record has only evidence failures.
     * Each phase scans the text once using a sliding window: O(4 * message.length), after its bound.
     */
    private fun hasProducerFailurePhases(message: String, failed: Boolean): Boolean {
        val exceptionLabels = listOf(
            "call recovery failed:", "data-reference recovery failed:",
            "type recovery failed:", "decompilation failed:",
        )
        val reachable = BooleanArray(message.length).also { it[0] = true }
        for (phase in 0..(if (failed) 3 else 2)) {
            val starts = BooleanArray(message.length)
            val minimumEnds = IntArray(message.length + 1)
            val exactEnds = BooleanArray(message.length + 1)
            // getSimpleName may be empty (anonymous exceptions). After Java trim, that gives the
            // exact exception label. Named exceptions/details follow one space; class names and
            // exception details are not inferred from the retained diagnostic.
            fun recognize(start: Int, label: String, separator: String) {
                if (!message.startsWith(label, start)) return
                val labelEnd = start + label.length
                exactEnds[labelEnd] = true
                if (message.startsWith(separator, labelEnd)) {
                    val minimumEnd = labelEnd + separator.length + 1
                    if (minimumEnd <= message.length) {
                        starts[start] = true
                        minimumEnds[minimumEnd]++
                    }
                }
            }
            for (start in message.indices) if (reachable[start]) {
                recognize(start, exceptionLabels[phase], " ")
                if (phase == 3) recognize(start, "decompilation failed or timed out", ": ")
            }
            val nextStarts = BooleanArray(message.length)
            var shortStartCount = 0
            for (end in 1..message.length) {
                shortStartCount += minimumEnds[end]
                val expired = end - MAXIMUM_FAILURE_PHASE_UNITS - 1
                if (expired >= 0 && starts[expired]) shortStartCount--
                if (message[end - 1] <= ' ') continue
                val finalPhase = end == message.length
                if (!finalPhase && (end + 1 >= message.length || message[end] != ';' || message[end + 1] != ' ')) continue
                val truncatedStart = end - TRUNCATED_FAILURE_PHASE_UNITS
                val truncated = truncatedStart >= 0 && starts[truncatedStart] &&
                    message[end - 3] == '.' && message[end - 2] == '.' && message[end - 1] == '.'
                if (exactEnds[end] || shortStartCount > 0 || truncated) {
                    if (finalPhase && (phase == 3) == failed) return true
                    val next = end + 2
                    if (next < message.length) nextStarts[next] = true
                }
            }
            // Retain earlier starts to permit skipped successful phases, but add new starts only
            // after scanning this phase so it cannot contribute twice to the same partition.
            for (start in message.indices) if (nextStarts[start]) reachable[start] = true
        }
        return false
    }

    private fun requirePrettyExporterRecord(
        bytes: ByteArray,
        root: JsonObject,
        label: String,
        fields: List<String>,
        arrayFields: Set<String> = emptySet(),
        nullableField: String? = null,
    ) = requireExporterSerialization(bytes, label) { verifier ->
        verifier.accept("    {\n")
        fields.forEachIndexed { index, field ->
            if (index > 0) verifier.accept(",\n")
            verifier.accept("      \"$field\": ")
            val value = root.getValue(field)
            when {
                field in arrayFields -> {
                    val values = value as? JsonArray
                        ?: throw IllegalArgumentException("GCC full $label exporter serialization requires a $field array")
                    verifier.accept("[")
                    var previous: String? = null
                    values.forEachIndexed { itemIndex, item ->
                        require(item is JsonPrimitive && item.isString) {
                            "GCC full $label exporter serialization requires strings in $field"
                        }
                        // ExportProgramModel uses Java TreeSet: unique, ascending UTF-16 String order.
                        require(previous?.let { it < item.content } != false) {
                            "GCC full $label exporter serialization requires strictly ordered $field"
                        }
                        if (itemIndex > 0) verifier.accept(", ")
                        verifier.acceptExporterString(item.content)
                        previous = item.content
                    }
                    verifier.accept("]")
                }
                field == nullableField && value == JsonNull -> verifier.accept("null")
                else -> verifier.acceptExporterString(string(root, field))
            }
        }
        verifier.accept("\n    }")
    }

    private fun requireExporterSerialization(bytes: ByteArray, label: String, emit: (ExactByteVerifier) -> Unit) {
        try {
            val verifier = ExactByteVerifier(bytes, "GCC full $label exporter serialization", bytes.size)
            emit(verifier)
            verifier.finish()
        } catch (failure: GccCompilerEngineResumeEvidenceException) {
            throw IllegalArgumentException("GCC full $label exporter serialization differs from its producer", failure)
        }
    }

    /** Incrementally matches ExportProgramModel.json without allocating a second expanded record. */
    private fun ExactByteVerifier.acceptExporterString(value: String) {
        accept("\"")
        val chunk = StringBuilder(4096)
        var index = 0
        while (index < value.length) {
            val character = value[index++]
            when (character) {
                '\\' -> chunk.append("\\\\")
                '"' -> chunk.append("\\\"")
                '\n' -> chunk.append("\\n")
                '\r' -> chunk.append("\\r")
                '\t' -> chunk.append("\\t")
                else -> if (character.code < 0x20) {
                    chunk.append("\\u").append(character.code.toString(16).padStart(4, '0'))
                } else {
                    chunk.append(character)
                    // Strict JSON parsing already validated Unicode; keep a surrogate pair in one UTF-8 chunk.
                    if (character.isHighSurrogate() && index < value.length && value[index].isLowSurrogate()) {
                        chunk.append(value[index++])
                    }
                }
            }
            if (chunk.length >= 4096) {
                accept(chunk.toString())
                chunk.setLength(0)
            }
        }
        if (chunk.isNotEmpty()) accept(chunk.toString())
        accept("\"")
    }

    private fun strictRecordObject(bytes: ByteArray, maximumBytes: Int, label: String): JsonObject {
        require(bytes.isNotEmpty() && bytes.size <= maximumBytes) { "GCC full $label exceeds its byte bound" }
        val parsed = OracleJson.parse(bytes, StrictJsonLimits(
            maximumInputBytes = maximumBytes,
            maximumCanonicalBytes = maximumBytes,
            maximumDepth = 16,
            maximumNodes = MAXIMUM_FULL_RECORD_JSON_NODES,
            maximumStringBytes = maximumBytes,
            maximumTotalStringBytes = maximumBytes,
        ))
        return parsed as? JsonObject ?: throw IllegalArgumentException("GCC full $label is not a JSON object")
    }

    private fun fileCommitment(bytes: ByteArray) = JsonObject(mapOf(
        "bytes" to JsonPrimitive(bytes.size),
        "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)),
    ))

    private fun requireFullDirectory(directory: LinuxDescriptor, parent: LinuxFileIdentity) {
        val identity = LinuxFilesystemSyscalls.identity(directory.fd)
        require(identity.isDirectory && !identity.isSymbolicLink && identity.uid == parent.uid &&
            identity.mountId == parent.mountId && identity.mode.permissions and 0x12 == 0
        ) { "GCC full export directory is not private on the retained mount" }
    }

    private fun requireNamedDirectory(
        parent: LinuxDescriptor,
        name: String,
        expected: LinuxDescriptor,
        expectedIdentity: LinuxFileIdentity,
        owner: LinuxFileIdentity,
    ) {
        LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name).use { actual ->
            require(actual.identity == expected.identity && LinuxFilesystemSyscalls.identity(expected.fd) == expected.identity &&
                actual.identity.copy(linkCount = expectedIdentity.linkCount) == expectedIdentity &&
                actual.identity.uid == owner.uid && actual.identity.mountId == owner.mountId
            ) { "GCC full export directory changed during capture" }
        }
    }

    private fun requireDirectoryNames(directory: LinuxDescriptor, expected: Set<String>) {
        require(LinuxFilesystemSyscalls.directoryEntryNames(directory, expected.size + 1).toSet() == expected) {
            "GCC full export sidecar inventory changed during capture"
        }
    }

    private fun string(root: JsonObject, name: String): String {
        val value = root[name] as? JsonPrimitive ?: throw IllegalArgumentException("GCC full exporter $name is invalid")
        require(value.isString) { "GCC full exporter $name is invalid" }
        return value.content
    }

    private fun number(root: JsonObject, name: String): Long {
        val value = root[name] as? JsonPrimitive ?: throw IllegalArgumentException("GCC full exporter $name is invalid")
        require(!value.isString) { "GCC full exporter $name is invalid" }
        return value.longOrNull ?: throw IllegalArgumentException("GCC full exporter $name is invalid")
    }

    private data class FullProgress(val total: Long, val recovered: Long, val partial: Long, val failed: Long, val reused: Long)
}

internal data class GccBundledFullExportTarget(val language: String, val compilerSpec: String)
