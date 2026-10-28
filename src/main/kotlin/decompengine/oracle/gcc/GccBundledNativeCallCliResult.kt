package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.DescriptorBoundStateFaultInjector
import decompengine.oracle.core.DescriptorBoundStateSnapshot
import decompengine.acp.LinuxDescriptor
import java.nio.file.Path
import kotlinx.serialization.json.*

/** Immutable pointers to retained native observations; qualification and cold recovery remain open. */
internal object GccBundledNativeCallCliResult {
    fun create(operation: GccBundledNativeCallOperation, binding: ByteArray, journal: Path, run: Path,
        output: Path, operationWallTime: JsonObject, replay: GccBundledMachineCallReplayOperation? = null): ByteArray {
        listOf(journal, run, output).forEach { require(it.isAbsolute && it.normalize() == it) }
        require(binding.contentEquals(GccNativeCallReceiptLineage.createBinding(operation))) {
            "native CLI binding belongs to another operation"
        }
        val intent = OracleJson.parseCanonical(operation.intentBytes).jsonObject
        val snapshot = operation.snapshot
        val model = operation.model
        require(replay == null || replay.native === operation) { "native replay belongs to another captured operation" }
        val replayFields = replay?.let {
            mapOf(
                "structuralReplayBinding" to JsonPrimitive(output.resolve(GccBundledNativeStructuralEvidenceV1.BINDING_NAME).toString()),
                "structuralReplayBindingSha256" to JsonPrimitive(OracleArtifacts.sha256(GccBundledNativeStructuralEvidenceV1.create(it))),
                "selectedBoundaryScore" to JsonPrimitive(output.resolve(GccBundledNativeStructuralEvidenceV1.BOUNDARY_NAME).toString()),
                "selectedBoundaryScoreSha256" to JsonPrimitive(OracleArtifacts.sha256(
                    decompengine.oracle.structural.StructuralProductionReplayContract.scoreSelectedBoundary(it.selectedInputs))),
                "independentMachineCallReport" to JsonPrimitive(output.resolve(GccBundledMachineCallReplayOutputCapture.REPORT_NAME).toString()),
                "independentMachineCallReportSha256" to JsonPrimitive(OracleArtifacts.sha256(it.capture.reportBytes)),
                "callAuthority" to JsonPrimitive("unavailable-pending-population-and-external-composition"),
            )
        } ?: emptyMap()
        return OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive(if (replay == null) "gcc-bundled-cli-native-call-result-v1" else "gcc-bundled-cli-native-call-result-v2"),
            "schemaVersion" to JsonPrimitive(if (replay == null) 1 else 2),
            "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
            "operationId" to intent.getValue("operationId"),
            "requestSha256" to JsonPrimitive(OracleArtifacts.sha256(operation.intentBytes)),
            "journal" to JsonPrimitive(journal.toString()),
            "programModel" to JsonPrimitive(run.resolve("reports/program_model.json").toString()),
            "programModelSha256" to JsonPrimitive(model.programModelSha256), "programModelBytes" to JsonPrimitive(model.programModelBytes),
            "functionCount" to JsonPrimitive(model.functionCount), "outputTreeSha256" to JsonPrimitive(model.outputTreeSha256),
            "outputTreeManifest" to JsonPrimitive(output.resolve(GccBundledFullExportCliResultV2.TREE_MANIFEST_NAME).toString()),
            "outputTreeManifestSha256" to JsonPrimitive(OracleArtifacts.sha256(model.sidecarManifest)),
            "nativeObservations" to JsonPrimitive(run.resolve("reports/native-calls-v1/native-calls.json").toString()),
            "nativeObservationsSha256" to JsonPrimitive(snapshot.summary.observationsSha256),
            "nativeObservationsBytes" to JsonPrimitive(snapshot.summary.observationsBytes),
            "nativeManifest" to JsonPrimitive(run.resolve("reports/native-calls-v1/manifest.json").toString()),
            "nativeManifestSha256" to JsonPrimitive(OracleArtifacts.sha256(snapshot.manifestBytes)),
            "nativeBinding" to JsonPrimitive(output.resolve("native-call-observation-binding.json").toString()),
            "nativeBindingSha256" to JsonPrimitive(OracleArtifacts.sha256(binding)),
            "executionReceiptSha256" to JsonPrimitive(OracleArtifacts.sha256(operation.executionReceiptBytes)),
            "nativeAssessmentReceiptSha256" to JsonPrimitive(OracleArtifacts.sha256(operation.nativeAssessmentReceiptBytes)),
            "operationWallTime" to operationWallTime,
            "scratchDisposition" to JsonPrimitive("retained; native observations unscored; release and cold recovery unqualified"),
        ) + replayFields))
    }
}

/** The durable marker is the commit point. No cancellable validation follows it. */
internal object GccBundledNativeCallCliPublication {
    fun publishResultMarker(output: LinuxDescriptor, resultBytes: ByteArray, beforeCommit: () -> Unit,
        faultInjector: DescriptorBoundStateFaultInjector? = null): DescriptorBoundStateSnapshot {
        val retainedBytes = resultBytes.copyOf()
        val result = OracleJson.parseCanonical(retainedBytes).jsonObject
        val version = result.getValue("schemaVersion").jsonPrimitive.intOrNull
        require(version in setOf(1, 2) &&
            result.getValue("provider") == JsonPrimitive("gcc-bundled-cli-native-call-result-v$version") &&
            result.getValue("complete") == JsonPrimitive(false) && result.getValue("scored") == JsonPrimitive(false) &&
            result.getValue("releaseEligible") == JsonPrimitive(false)) { "native marker must remain an unscored byte result" }
        beforeCommit()
        return DescriptorBoundAtomicStateFile.publishNoReplace(output, "result.json", retainedBytes, 256 * 1024, faultInjector)
    }
}
