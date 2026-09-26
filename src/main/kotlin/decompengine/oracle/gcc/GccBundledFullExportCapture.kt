package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.charset.StandardCharsets
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
    private const val MAXIMUM_FULL_FUNCTION_RECORD_BYTES = 64 * 1024 * 1024
    internal const val MAXIMUM_FULL_FUNCTIONS = 512L * 256L
    private const val MAXIMUM_MODEL_BYTES = 512 * 1024 * 1024
    private const val MAXIMUM_SIDECAR_FILES = 300_000

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
        val globalNames = captureDirectoryFiles(globals, MAXIMUM_FULL_FUNCTIONS, 1024 * 1024)
        require(globalNames.all { it.matches(Regex("global_[0-9a-f]{16}\\.json")) }) {
            "GCC full export global record names are invalid"
        }
        val typeNames = captureDirectoryFiles(types, MAXIMUM_FULL_FUNCTIONS, 1024 * 1024)
        require(typeNames.all { it.matches(Regex("type_[0-9a-f]{64}\\.json")) }) {
            "GCC full export type record names are invalid"
        }
        val failureNames = captureDirectoryFiles(failures, progress.total, 1024 * 1024)
        require(failureNames.all { it.matches(Regex("fn_[0-9a-f]{16}\\.json")) && it in functionNames }) {
            "GCC full export failure records do not identify exported functions"
        }
        val entries = linkedMapOf<String, JsonObject>()
        val functionStatuses = linkedMapOf<String, String>()
        fun addFiles(prefix: String, directory: LinuxDescriptor, names: List<String>, maximum: Int,
            includedInModel: Boolean = false) {
            require(entries.size + names.size <= MAXIMUM_SIDECAR_FILES) {
                "GCC full export sidecar inventory exceeds its manifest bound"
            }
            for ((index, name) in names.withIndex()) {
                val bytes = capture.read(directory, name, maximum)
                when (prefix) {
                    "functions" -> functionStatuses[name.removeSuffix(".json")] =
                        requireFullFunctionRecord(bytes, name.removeSuffix(".json"))
                    "globals" -> requireFullNamedRecord(bytes, name.removeSuffix(".json"), setOf(
                        "id", "name", "address", "type", "initializer", "extractionStatus", "recoveryAssessment",
                    ))
                    "types" -> requireFullNamedRecord(bytes, name.removeSuffix(".json"), setOf(
                        "id", "declaration", "sourceAddress", "extractionStatus", "recoveryAssessment",
                    ))
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
        addFiles("globals", globals, globalNames, 1024 * 1024, includedInModel = true)
        modelVerifier.accept("  ],\n  \"types\": [\n")
        addFiles("types", types, typeNames, 1024 * 1024, includedInModel = true)
        modelVerifier.accept("  ]\n}\n")
        modelVerifier.finish()
        addFiles("failures", failures, failureNames, 1024 * 1024)
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
        require(number(root, "schemaVersion") == 2L && number(root, "exporterVersion") == 10L &&
            string(root, "recoveryMode") == "full" && root.getValue("semanticStateBinding") == JsonNull &&
            string(root, "inputSha256") == expectedInput && string(root, "exporterSha256") == expectedExporter &&
            string(root, "analysisToolSha256") == expectedAnalysisTool
        ) { "GCC full exporter state differs from its authenticated invocation" }
        require(string(root, "language").matches(Regex("[A-Za-z0-9_.:+-]{1,256}")) &&
            string(root, "compilerSpec").matches(Regex("[A-Za-z0-9_.:+-]{1,256}"))) {
            "GCC full exporter target identity is invalid"
        }
        return GccBundledFullExportTarget(string(root, "language"), string(root, "compilerSpec"))
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
        return FullProgress(total, recovered, partial, failed, reused)
    }

    private fun requireFullModelHeader(model: ByteArray, inputSha256: String) {
        val prefix = "{\n  \"schemaVersion\": 2,\n  \"inputSha256\": \"$inputSha256\",\n  \"functions\": [\n".toByteArray(StandardCharsets.UTF_8)
        val suffix = "  ]\n}\n".toByteArray(StandardCharsets.UTF_8)
        require(model.size >= prefix.size + suffix.size && model.copyOfRange(0, prefix.size).contentEquals(prefix) &&
            model.copyOfRange(model.size - suffix.size, model.size).contentEquals(suffix)
        ) { "GCC full program model does not have the exporter-bound input envelope" }
    }

    private fun requireFullFunctionRecord(bytes: ByteArray, expectedId: String): String {
        val root = strictRecordObject(bytes, MAXIMUM_FULL_FUNCTION_RECORD_BYTES, "function record")
        val status = string(root, "extractionStatus")
        require(root.keys == setOf(
            "id", "name", "address", "prototype", "extractionStatus", "recoveryAssessment", "calls",
            "referencedGlobals", "strings", "decompiledC",
        ) && string(root, "id") == expectedId &&
            status in setOf("recovered", "partial", "failed") &&
            string(root, "recoveryAssessment") == "unassessed"
        ) { "GCC full function record is malformed or is bound to another identity" }
        return status
    }

    private fun requireFullNamedRecord(bytes: ByteArray, expectedId: String, expectedKeys: Set<String>) {
        val root = strictRecordObject(bytes, 1024 * 1024, "evidence record")
        require(root.keys == expectedKeys && string(root, "id") == expectedId &&
            string(root, "extractionStatus") in setOf("recovered", "partial") &&
            string(root, "recoveryAssessment") == "unassessed"
        ) { "GCC full evidence record is malformed or is bound to another identity" }
    }

    private fun requireFullFailureRecord(bytes: ByteArray, expectedId: String, expectedStatus: String?) {
        val root = strictRecordObject(bytes, 1024 * 1024, "failure record")
        require(root.keys == setOf("schemaVersion", "functionId", "status", "message") &&
            number(root, "schemaVersion") == 1L && string(root, "functionId") == expectedId &&
            string(root, "status") in setOf("partial", "failed") && string(root, "status") == expectedStatus
        ) { "GCC full failure record is malformed or is bound to another function" }
    }

    private fun strictRecordObject(bytes: ByteArray, maximumBytes: Int, label: String): JsonObject {
        require(bytes.isNotEmpty() && bytes.size <= maximumBytes) { "GCC full $label exceeds its byte bound" }
        val parsed = OracleJson.parse(bytes, StrictJsonLimits(
            maximumInputBytes = maximumBytes,
            maximumCanonicalBytes = maximumBytes,
            maximumDepth = 16,
            maximumNodes = 1_000_000,
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
