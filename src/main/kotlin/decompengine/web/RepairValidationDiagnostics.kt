package decompengine.web

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.parseGeneratedCValidationFailureRecord
import decompengine.project.sha256
import decompengine.repair.RepairRecordedValidationDiagnostic
import decompengine.repair.RepairHistoryIdentityReferences
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull

/** Finite presentation labels only; raw receipt, exception and peer text never enter this view. */
internal data class RecordedRepairValidationDiagnosticView(
    val state: RepairEvidenceArtifactState,
    val reason: String? = null,
    val phase: String? = null,
    val inputIndex: Int? = null,
    val inputCount: Int? = null,
)

/** Byte capture may be shared by path. This integrity decision must run for each invocation. */
internal fun checkedRecordedRepairValidationDiagnostic(binding: RepairRecordedValidationDiagnostic,
    receiptBytes: ByteArray?, diagnosticBytes: ByteArray?): RecordedRepairValidationDiagnosticView {
    if (receiptBytes == null || diagnosticBytes == null || receiptBytes.isEmpty() || diagnosticBytes.isEmpty())
        return RecordedRepairValidationDiagnosticView(RepairEvidenceArtifactState.UNAVAILABLE)
    return runCatching {
        require(receiptBytes.size.toLong() == binding.receiptBytes && sha256(receiptBytes) == binding.receiptSha256)
        require(diagnosticBytes.size == binding.diagnosticBytes && sha256(diagnosticBytes) == binding.diagnosticSha256)
        val diagnostic = parseGeneratedCValidationFailureRecord(diagnosticBytes)
        val invocation = requireNotNull(diagnostic.invocation)
        require(invocation.commitmentSha256() == binding.invocationSha256)
        require(RepairHistoryIdentityReferences(binding.regressionCorpusSha256).revision(invocation.candidateRevisionId) == binding.candidate)
        require(diagnostic.receiptSha256 == binding.receiptSha256 &&
            diagnostic.sourceRevisionSha256 == binding.sourceRevisionSha256 &&
            diagnostic.profileSha256 == binding.profileSha256 && diagnostic.indexSha256 == binding.indexSha256 &&
            diagnostic.regressionCorpusSha256 == binding.regressionCorpusSha256 &&
            diagnostic.runtimeSha256 == binding.runtimeSha256 && diagnostic.classification == binding.failureKind)
        val primary = OracleJson.parse(receiptBytes, StrictJsonLimits(maximumInputBytes = 16 * 1024 * 1024,
            maximumCanonicalBytes = 16 * 1024 * 1024, maximumDepth = 20, maximumNodes = 1_000_000,
            maximumStringBytes = 16 * 1024 * 1024, maximumTotalStringBytes = 16 * 1024 * 1024)) as? JsonObject
            ?: error("validation receipt object type")
        require(primary.keys == setOf("schemaVersion", "provider", "profileId", "profileSha256", "indexSha256",
            "sourceRevisionSha256", "regressionCorpusSha256", "runtimeSha256", "runtimeConfiguration",
            "behaviorBudgetEvidence", "sourceSnapshot", "buildOutputLink", "originalExecutable", "rebuiltExecutable",
            "inputs", "scopes", "outcome", "caseCount", "matches", "cleanupVerified", "assurance"))
        fun text(name: String) = (primary.getValue(name) as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: error("validation receipt text type")
        fun scalar(name: String) = (primary.getValue(name) as? JsonPrimitive)?.takeUnless { it.isString }
            ?: error("validation receipt scalar type")
        require(scalar("schemaVersion").intOrNull == 2 && text("provider") == "generated-c-linux-bubblewrap-cgroup-v1")
        require(text("sourceRevisionSha256") == binding.sourceRevisionSha256 && text("profileSha256") == binding.profileSha256 &&
            text("indexSha256") == binding.indexSha256 && text("regressionCorpusSha256") == binding.regressionCorpusSha256 &&
            text("runtimeSha256") == binding.runtimeSha256)
        require(text("outcome") == binding.failureKind.name.lowercase().replace('_', '-') &&
            text("assurance") == "strict-contained" && scalar("cleanupVerified").booleanOrNull == binding.cleanupVerified)
        require((primary.getValue("inputs") as? JsonArray)?.size == diagnostic.inputCount)
        require(scalar("matches").booleanOrNull == false)
        val completed = requireNotNull(scalar("caseCount").intOrNull)
        require(completed in 0..diagnostic.inputCount)
        require(diagnostic.inputIndex == null || diagnostic.inputIndex == completed)
        RecordedRepairValidationDiagnosticView(RepairEvidenceArtifactState.AVAILABLE, diagnostic.reason.wireName,
            diagnostic.phase.wireName, diagnostic.inputIndex, diagnostic.inputCount)
    }.getOrElse { RecordedRepairValidationDiagnosticView(RepairEvidenceArtifactState.CORRUPT) }
}
