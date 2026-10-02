package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

/** Self-consistent receipt chain retained by the completed contained full-export operation. */
internal class GccDriverStructuralFullExportReceiptLineageV1 private constructor(
    private val storedBytes: ByteArray,
) {
    val canonicalBytes: ByteArray get() = storedBytes.copyOf()
    val sha256: String = OracleArtifacts.sha256(storedBytes)

    companion object {
        fun validate(
            operation: GccBundledFullExportOperation,
            expectedCompilerEngineProfileSha256: String,
        ): GccDriverStructuralFullExportReceiptLineageV1 {
            require(!operation.complete && !operation.releaseEligible) {
                "GCC full-export operation unexpectedly grants completion or release eligibility"
            }
            val intentBytes = operation.intentBytes
            val intent = OracleJson.parseCanonical(intentBytes) as? JsonObject
                ?: throw IllegalArgumentException("GCC full-export intent is not a canonical object")
            val intentSha256 = OracleArtifacts.sha256(intentBytes)
            val operationId = intent.string("operationId")
            require(operationId.matches(Regex("[a-f0-9]{64}"))) { "GCC full-export operation ID is invalid" }
            val schemaVersion = intent.long("schemaVersion")
            val provider = intent.string("provider")
            require(schemaVersion == 2L && provider == "gcc-bundled-operation-intent-v2" &&
                intent.string("engineId") == "cc1"
            ) { "GCC full-export intent is not the pinned cc1 compiler-engine operation" }
            val plannerProfile = intent.getValue("plannerProfile").jsonObject
            require(plannerProfile.string("profileSha256") == expectedCompilerEngineProfileSha256) {
                "GCC full-export intent does not bind the authenticated compiler-engine profile"
            }
            require(intent.string("runKind") == "fresh-control") {
                "GCC full export was not authorized as a fresh uninterrupted operation"
            }
            require(intent.getValue("bundledRuntime").jsonObject.string("provider") == "bundled-ghidra-java-api-runtime-v5") {
                "GCC full export intent does not select the pinned full-recovery runtime"
            }

            val artifacts = intent.getValue("artifacts").jsonArray.map { it.jsonObject }
            fun artifact(role: String): Pair<Long, String> {
                val records = artifacts.filter { it.string("role") == role }
                require(records.size == 1) { "GCC full-export intent must bind one $role artifact" }
                val record = records.single()
                val bytes = record.long("bytes")
                val digest = record.string("sha256")
                require(bytes > 0L && digest.matches(Regex("[a-f0-9]{64}"))) {
                    "GCC full-export intent $role artifact identity is invalid"
                }
                return bytes to digest
            }
            val engine = artifact("engine-binary")
            val exporter = artifact("exporter-source")
            val ghidraArchive = artifact("ghidra-archive")
            require(engine.first == operation.snapshot.inputBytes && engine.second == operation.snapshot.inputSha256 &&
                exporter.first == operation.snapshot.exporterBytes && exporter.second == operation.snapshot.exporterSha256 &&
                ghidraArchive.first == operation.snapshot.analysisToolBytes && ghidraArchive.second == operation.snapshot.analysisToolSha256
            ) { "GCC full-export snapshot differs from the artifacts in its operation intent" }

            val executionBytes = operation.executionReceiptBytes
            val exportBytes = operation.exportAssessmentReceiptBytes
            val executionRecord = readRecord(
                executionBytes, "gcc-bundled-command-executed-v1", "execution", operationId, intentSha256,
            )
            val exportRecord = readRecord(
                exportBytes, "gcc-bundled-command-export-assessed-v1", "assessment", operationId, intentSha256,
            )
            require(exportRecord.record.string("previousSha256") == OracleArtifacts.sha256(executionBytes)) {
                "GCC export assessment receipt does not descend from its execution receipt"
            }
            require(executionRecord.record.string("previousSha256").matches(Regex("[a-f0-9]{64}"))) {
                "GCC execution receipt has an invalid predecessor digest"
            }

            val execution = executionRecord.payload
            require(execution.string("provider") == "kotlin-lease-contained-command-execution-v1" &&
                execution.long("schemaVersion") == 1L && execution.long("childExitCode") == 0L &&
                execution.bool("unitAbsent") && execution.bool("cgroupAbsent") && execution.bool("processesAbsent") &&
                !execution.bool("releaseEligible")
            ) { "GCC full-export execution receipt does not prove successful worker absence" }
            val executionUnsigned = JsonObject(execution - "executionSha256")
            require(execution.string("executionSha256") == OracleArtifacts.sha256(OracleJson.canonicalBytes(executionUnsigned))) {
                "GCC contained execution record digest is invalid"
            }

            val assessment = exportRecord.payload
            val captured = OracleJson.parseCanonical(operation.snapshot.assessmentBytes).jsonObject
            require(assessment.string("provider") == "gcc-bundled-descriptor-full-export-assessment-v2" &&
                assessment.long("schemaVersion") == 2L && assessment.string("recoveryMode") == "full" &&
                !assessment.bool("complete") && !assessment.bool("releaseEligible") &&
                assessment["operationWallTime"] is JsonObject
            ) { "GCC full-export assessment receipt has an invalid authority or operation binding" }
            require(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(assessment - "assessmentSha256"))) ==
                assessment.string("assessmentSha256")
            ) { "GCC full-export assessment digest is invalid" }
            require(JsonObject(assessment - setOf("assessmentSha256", "operationWallTime")) ==
                JsonObject(captured - "assessmentSha256")
            ) { "GCC full-export assessment receipt differs from its captured snapshot" }

            val fields = JsonObject(linkedMapOf(
                "provider" to JsonPrimitive("gcc-bundled-full-export-receipt-lineage-v1"),
                "schemaVersion" to JsonPrimitive(1),
                "operationId" to JsonPrimitive(operationId),
                "intentSha256" to JsonPrimitive(intentSha256),
                "engineId" to JsonPrimitive("cc1"),
                "compilerEngineProfileSha256" to JsonPrimitive(expectedCompilerEngineProfileSha256),
                "executionReceiptSha256" to JsonPrimitive(OracleArtifacts.sha256(executionBytes)),
                "executionPayloadSha256" to JsonPrimitive(executionRecord.payloadSha256),
                "exportAssessmentReceiptSha256" to JsonPrimitive(OracleArtifacts.sha256(exportBytes)),
                "exportAssessmentSha256" to JsonPrimitive(assessment.string("assessmentSha256")),
            ))
            return GccDriverStructuralFullExportReceiptLineageV1(OracleJson.canonicalBytes(fields))
        }

        private data class ParsedRecord(
            val record: JsonObject,
            val payload: JsonObject,
            val payloadSha256: String,
        )

        private fun readRecord(
            bytes: ByteArray,
            expectedProvider: String,
            payloadName: String,
            operationId: String,
            intentSha256: String,
        ): ParsedRecord {
            val record = OracleJson.parseCanonical(bytes) as? JsonObject
                ?: throw IllegalArgumentException("GCC operation receipt is not a canonical object")
            val expectedFields = setOf(
                "provider", "schemaVersion", "operationId", "intentSha256", "previousSha256", "complete",
                "releaseEligible", payloadName, "${payloadName}Sha256", "recordSha256",
            )
            require(record.keys == expectedFields && record.string("provider") == expectedProvider &&
                record.long("schemaVersion") == 1L && record.string("operationId") == operationId &&
                record.string("intentSha256") == intentSha256 && !record.bool("complete") && !record.bool("releaseEligible")
            ) { "GCC operation receipt identity or fields are invalid" }
            val payload = record.getValue(payloadName) as? JsonObject
                ?: throw IllegalArgumentException("GCC operation receipt payload is not an object")
            val payloadSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(payload))
            require(record.string("${payloadName}Sha256") == payloadSha256) {
                "GCC operation receipt payload digest is invalid"
            }
            require(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(record - "recordSha256"))) ==
                record.string("recordSha256")
            ) { "GCC operation receipt digest is invalid" }
            return ParsedRecord(record, payload, payloadSha256)
        }
    }
}

private fun JsonObject.string(name: String): String = getValue(name).jsonPrimitive.content
private fun JsonObject.long(name: String): Long = getValue(name).jsonPrimitive.longOrNull
    ?: throw IllegalArgumentException("GCC operation field $name is not an integer")
private fun JsonObject.bool(name: String): Boolean = getValue(name).jsonPrimitive.booleanOrNull
    ?: throw IllegalArgumentException("GCC operation field $name is not a boolean")
