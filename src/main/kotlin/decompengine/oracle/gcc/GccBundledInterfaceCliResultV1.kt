package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.DescriptorBoundStateFaultInjector
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Path
import kotlinx.serialization.json.*

/** Archived commitments describe a genuine live capture; archived bytes cannot recreate ownership. */
internal object GccBundledInterfaceCliResultV1 {
    const val BINDING_NAME = "interface-observation-binding.json"
    const val MAXIMUM_BINDING_BYTES = 256 * 1024

    fun binding(operation: GccBundledInterfaceOperation): ByteArray {
        operation.requireCurrent()
        val snapshot = operation.snapshot
        val model = snapshot.model
        val intentBytes = operation.intentBytes
        val intent = OracleJson.parseCanonical(intentBytes).jsonObject
        require(intent.text("provider") == "gcc-bundled-operation-intent-v6" && intent.number("schemaVersion") == 6L &&
            intent.text("engineId") == "driver" && intent.text("runKind") == "fresh-control")
        val runtime = intent.getValue("bundledRuntime").jsonObject
        require(runtime.text("provider") == "bundled-ghidra-java-api-runtime-v9")
        val component = GccBundledInterfaceRuntimeIdentityV1.parse(runtime.getValue("interfaceCollector").jsonObject)
        require(component.closureSha256 == snapshot.runtime.componentClosureSha256 &&
            component.listingCollectorSha256 == snapshot.runtime.listingCollectorSha256 &&
            component.inferredCollectorSha256 == snapshot.runtime.inferredCollectorSha256 &&
            component.typeGraphSha256 == snapshot.runtime.typeGraphSha256 && component.wrapperSha256 == snapshot.runtime.wrapperSha256 &&
            component.nativeDecompilerSha256 == snapshot.runtime.nativeDecompilerSha256)
        val profile = intent.getValue("plannerProfile").jsonObject
        require(profile.digest("profileSha256") == snapshot.target.profileSha256)
        val cli = intent.getValue("cliInvocation").jsonObject
        require(cli.text("provider") == "gcc-bundled-cli-invocation-v3" && cli.number("schemaVersion") == 3L &&
            cli.text("engineId") == "driver")
        val argv = cli.getValue("argv").jsonArray
        require(argv.size in 3..33 && argv.first() == JsonPrimitive("gcc-engine-interface-observations"))
        require(GccBundledCliOptions.parse(argv.drop(1).map { it.jsonPrimitive.let { item ->
            require(item.isString); item.content
        } }, nativeInterfaceObservations = true).engineId == "driver")
        val artifacts = intent.getValue("artifacts").jsonArray.map { it.jsonObject }
        fun artifact(role: String, bytes: Long, sha256: String) {
            val selected = artifacts.single { it.text("role") == role }
            require(selected.number("bytes") == bytes && selected.digest("sha256") == sha256)
        }
        artifact("engine-binary", model.inputBytes, model.inputSha256)
        artifact("exporter-source", model.exporterBytes, model.exporterSha256)
        artifact("ghidra-archive", model.analysisToolBytes, model.analysisToolSha256)
        val operationId = intent.digest("operationId")
        val intentSha256 = OracleArtifacts.sha256(intentBytes)
        val executionBytes = operation.executionReceiptBytes
        val assessmentBytes = operation.assessmentReceiptBytes
        val execution = record(executionBytes, "gcc-bundled-command-executed-v1", "execution", operationId, intentSha256)
        val assessment = record(assessmentBytes, "gcc-bundled-command-export-assessed-v1", "assessment", operationId, intentSha256)
        require(assessment.first.digest("previousSha256") == OracleArtifacts.sha256(executionBytes))
        val outcome = execution.second
        require(outcome.text("provider") == "kotlin-lease-contained-command-execution-v1" && outcome.number("schemaVersion") == 1L &&
            outcome.number("childExitCode") == 0L && outcome.boolean("unitAbsent") && outcome.boolean("cgroupAbsent") &&
            outcome.boolean("processesAbsent") && !outcome.boolean("releaseEligible"))
        require(outcome.digest("executionSha256") == OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(outcome - "executionSha256"))))
        val workerOutcome = outcome.getValue("outcome").jsonObject
        require(workerOutcome.number("stdoutBytes") == snapshot.stdoutByteCount &&
            workerOutcome.number("stderrBytes") == snapshot.stderrByteCount) {
            "owned interface stream byte counts differ from the authenticated worker outcome"
        }
        val assessed = assessment.second
        require(assessed.text("provider") == "gcc-bundled-descriptor-inferred-interface-assessment-v1" &&
            assessed.number("schemaVersion") == 1L && !assessed.boolean("complete") && !assessed.boolean("scored") &&
            !assessed.boolean("productionInterfacesAdmitted") && !assessed.boolean("releaseEligible") &&
            assessed.boolean("completeObservedNativeCensus") && assessed["operationWallTime"] is JsonObject)
        require(assessed.digest("assessmentSha256") == OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(assessed - "assessmentSha256"))))
        val captured = OracleJson.parseCanonical(snapshot.assessmentBytes).jsonObject
        require(JsonObject(assessed - setOf("assessmentSha256", "operationWallTime")) == JsonObject(captured - "assessmentSha256")) {
            "interface receipt substitutes the captured byte assessment"
        }
        val lineage = JsonObject(mapOf(
            "operationId" to JsonPrimitive(operationId), "intentSha256" to JsonPrimitive(intentSha256),
            "executionReceiptSha256" to JsonPrimitive(OracleArtifacts.sha256(executionBytes)),
            "executionPayloadSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(outcome))),
            "assessmentReceiptSha256" to JsonPrimitive(OracleArtifacts.sha256(assessmentBytes)),
            "assessmentSha256" to JsonPrimitive(assessed.digest("assessmentSha256")),
        ))
        val binding = OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-bundled-interface-observation-binding-v1"), "schemaVersion" to JsonPrimitive(1),
            "complete" to JsonPrimitive(false), "authoritativeOracleEvidence" to JsonPrimitive(false),
            "productionInterfacesAdmitted" to JsonPrimitive(false), "scored" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
            "completeObservedNativeCensus" to JsonPrimitive(true),
            "interfaceAuthority" to JsonPrimitive("unavailable-raw-recovery-only"),
            "component" to runtime.getValue("interfaceCollector"), "captureAssessment" to captured,
            "fullExportTreeManifestSha256" to JsonPrimitive(OracleArtifacts.sha256(model.sidecarManifest)),
            "receiptLineage" to lineage,
            "receiptLineageSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(lineage))),
        )))
        require(binding.size <= MAXIMUM_BINDING_BYTES)
        operation.requireCurrent()
        return binding
    }

    fun result(operation: GccBundledInterfaceOperation, binding: ByteArray, journal: Path, run: Path,
        output: Path, operationWallTime: JsonObject): ByteArray {
        operation.requireCurrent()
        require(binding.contentEquals(this.binding(operation))) { "interface binding belongs to another live capture" }
        listOf(journal, run, output).forEach { require(it.isAbsolute && it.normalize() == it) }
        val snapshot = operation.snapshot
        val intent = OracleJson.parseCanonical(operation.intentBytes).jsonObject
        return OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-bundled-cli-interface-observation-result-v1"), "schemaVersion" to JsonPrimitive(1),
            "complete" to JsonPrimitive(false), "authoritativeOracleEvidence" to JsonPrimitive(false),
            "productionInterfacesAdmitted" to JsonPrimitive(false), "scored" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
            "completeObservedNativeCensus" to JsonPrimitive(true),
            "interfaceAuthority" to JsonPrimitive("unavailable-raw-recovery-only"),
            "operationId" to intent.getValue("operationId"), "requestSha256" to JsonPrimitive(OracleArtifacts.sha256(operation.intentBytes)),
            "journal" to JsonPrimitive(journal.toString()),
            "programModel" to JsonPrimitive(run.resolve("reports/program_model.json").toString()),
            "programModelSha256" to JsonPrimitive(snapshot.model.programModelSha256),
            "programModelBytes" to JsonPrimitive(snapshot.model.programModelBytes),
            "outputTreeManifest" to JsonPrimitive(output.resolve(GccBundledFullExportCliResultV2.TREE_MANIFEST_NAME).toString()),
            "outputTreeManifestSha256" to JsonPrimitive(OracleArtifacts.sha256(snapshot.model.sidecarManifest)),
            "listingObservations" to JsonPrimitive(run.resolve("reports/native-interfaces-v1/native-interfaces.json").toString()),
            "listingObservationsSha256" to JsonPrimitive(snapshot.summary.bindings.listingSha256),
            "listingManifest" to JsonPrimitive(run.resolve("reports/native-interfaces-v1/manifest.json").toString()),
            "listingManifestSha256" to JsonPrimitive(snapshot.summary.bindings.listingManifestSha256),
            "inferredObservations" to JsonPrimitive(run.resolve("reports/native-inferred-interfaces-v1/native-inferred-interfaces.json").toString()),
            "inferredObservationsSha256" to JsonPrimitive(snapshot.summary.manifest.sha256),
            "inferredManifest" to JsonPrimitive(run.resolve("reports/native-inferred-interfaces-v1/manifest.json").toString()),
            "inferredManifestSha256" to JsonPrimitive(OracleArtifacts.sha256(snapshot.inferredManifestBytes)),
            "interfaceBinding" to JsonPrimitive(output.resolve(BINDING_NAME).toString()),
            "interfaceBindingSha256" to JsonPrimitive(OracleArtifacts.sha256(binding)),
            "executionReceiptSha256" to JsonPrimitive(OracleArtifacts.sha256(operation.executionReceiptBytes)),
            "assessmentReceiptSha256" to JsonPrimitive(OracleArtifacts.sha256(operation.assessmentReceiptBytes)),
            "capturedBytes" to JsonPrimitive(snapshot.capturedBytes), "operationWallTime" to operationWallTime,
            "scratchDisposition" to JsonPrimitive("retained; complete raw observed census; ABI scoring and cold recovery unavailable"),
        )))
    }

    fun publishResultMarker(output: LinuxDescriptor, result: ByteArray, beforeCommit: () -> Unit,
        faultInjector: DescriptorBoundStateFaultInjector? = null) {
        val bytes = result.copyOf()
        val document = OracleJson.parseCanonical(bytes).jsonObject
        require(document.text("provider") == "gcc-bundled-cli-interface-observation-result-v1" &&
            document.number("schemaVersion") == 1L && !document.boolean("complete") &&
            !document.boolean("productionInterfacesAdmitted") && !document.boolean("scored") &&
            !document.boolean("authoritativeOracleEvidence") && !document.boolean("releaseEligible"))
        beforeCommit()
        DescriptorBoundAtomicStateFile.publishNoReplace(output, "result.json", bytes, 256 * 1024, faultInjector)
    }

    private fun record(bytes: ByteArray, provider: String, payloadName: String, operationId: String,
        intentSha256: String): Pair<JsonObject, JsonObject> {
        val document = OracleJson.parseCanonical(bytes).jsonObject
        require(document.keys == setOf("provider", "schemaVersion", "operationId", "intentSha256", "previousSha256",
            "complete", "releaseEligible", payloadName, "${payloadName}Sha256", "recordSha256"))
        require(document.text("provider") == provider && document.number("schemaVersion") == 1L &&
            document.digest("operationId") == operationId && document.digest("intentSha256") == intentSha256 &&
            !document.boolean("complete") && !document.boolean("releaseEligible"))
        document.digest("previousSha256")
        val payload = document.getValue(payloadName).jsonObject
        require(document.digest("${payloadName}Sha256") == OracleArtifacts.sha256(OracleJson.canonicalBytes(payload)))
        require(document.digest("recordSha256") == OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(document - "recordSha256"))))
        return document to payload
    }

    private fun JsonObject.text(name: String) = getValue(name).jsonPrimitive.let { require(it.isString); it.content }
    private fun JsonObject.number(name: String) = getValue(name).jsonPrimitive.let { require(!it.isString); requireNotNull(it.longOrNull) }
    private fun JsonObject.boolean(name: String) = getValue(name).jsonPrimitive.let { require(!it.isString); requireNotNull(it.booleanOrNull) }
    private fun JsonObject.digest(name: String) = text(name).also { require(it.matches(Regex("[a-f0-9]{64}"))) }
}
