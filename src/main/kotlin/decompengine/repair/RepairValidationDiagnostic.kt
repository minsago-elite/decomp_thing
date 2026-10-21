package decompengine.repair

import decompengine.oracle.core.OracleJson
import decompengine.project.sha256
import java.nio.file.Path
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull

/** One graph-owned call. Identical source and receipt bytes do not identify an invocation. */
data class RepairValidationInvocation(
    val id: String,
    val runId: String,
    val candidateRevisionId: String,
    val sourceRevisionSha256: String,
    val profileSha256: String,
    val indexSha256: String,
    val regressionCorpusSha256: String,
) {
    init {
        require(id.matches(Regex("validation_[0-9a-f]{32}")))
        require(runId.matches(Regex("run_[0-9]{8}")))
        require(candidateRevisionId.matches(Regex("(?:root_[0-9a-f]{24}|revision_[0-9]{8}_[0-9a-f]{16})")))
        require(listOf(sourceRevisionSha256, profileSha256, indexSha256, regressionCorpusSha256).all(::validationDigest))
    }

    internal fun toJsonObject(): JsonObject = JsonObject(mapOf(
        "id" to JsonPrimitive(id), "runId" to JsonPrimitive(runId),
        "candidateRevisionId" to JsonPrimitive(candidateRevisionId),
        "sourceRevisionSha256" to JsonPrimitive(sourceRevisionSha256),
        "profileSha256" to JsonPrimitive(profileSha256), "indexSha256" to JsonPrimitive(indexSha256),
        "regressionCorpusSha256" to JsonPrimitive(regressionCorpusSha256),
    ))

    internal fun commitmentSha256(): String = sha256(OracleJson.canonicalBytes(toJsonObject()))
}

/** Returned only after publication; paths here remain provider inputs, never reader authority. */
data class RepairValidationDiagnosticPublication(
    val invocation: RepairValidationInvocation,
    val runtimeSha256: String,
    val receiptPath: Path,
    val receiptSha256: String,
    val receiptBytes: Long,
    val diagnosticPath: Path,
    val diagnosticSha256: String,
    val diagnosticBytes: Int,
    val failureKind: RepairValidationFailureKind,
    val cleanupVerified: Boolean,
)

/** Portable canonical correlation only; it never supplies validation or release acceptance. */
data class RepairValidationDiagnosticBinding(
    val invocation: RepairValidationInvocation,
    val runtimeSha256: String,
    val receiptPath: String,
    val receiptSha256: String,
    val receiptBytes: Long,
    val diagnosticPath: String,
    val diagnosticSha256: String,
    val diagnosticBytes: Int,
    val failureKind: RepairValidationFailureKind,
    val cleanupVerified: Boolean,
) {
    init {
        require(listOf(runtimeSha256, receiptSha256, diagnosticSha256).all(::validationDigest))
        require(receiptBytes in 1..64L * 1024 * 1024 && diagnosticBytes in 1..4096)
        require(validationReportPath(receiptPath) && validationReportPath(diagnosticPath))
        require(receiptPath != diagnosticPath)
        require(diagnosticPath.substringAfterLast('/') == "${invocation.id}.validation-failure.json")
        require(cleanupVerified == (failureKind != RepairValidationFailureKind.CLEANUP_UNVERIFIED))
    }

    internal fun toJsonObject(): JsonObject = JsonObject(mapOf(
        "schemaVersion" to JsonPrimitive(1), "invocation" to invocation.toJsonObject(),
        "runtimeSha256" to JsonPrimitive(runtimeSha256), "receiptPath" to JsonPrimitive(receiptPath),
        "receiptSha256" to JsonPrimitive(receiptSha256), "receiptBytes" to JsonPrimitive(receiptBytes),
        "diagnosticPath" to JsonPrimitive(diagnosticPath), "diagnosticSha256" to JsonPrimitive(diagnosticSha256),
        "diagnosticBytes" to JsonPrimitive(diagnosticBytes), "failureKind" to JsonPrimitive(failureKind.name.lowercase()),
        "cleanupVerified" to JsonPrimitive(cleanupVerified),
    ))

    internal fun requireRetainedBudget(maximumBytes: Long) {
        require(maximumBytes >= 0 && receiptBytes + 2L * diagnosticBytes <= minOf(maximumBytes, 64L * 1024 * 1024)) {
            "validation diagnostic copies exceed the retained receipt byte bound"
        }
    }
}

internal fun parseRepairValidationInvocation(value: JsonObject): RepairValidationInvocation {
    require(value.keys == setOf("id", "runId", "candidateRevisionId", "sourceRevisionSha256",
        "profileSha256", "indexSha256", "regressionCorpusSha256"))
    return RepairValidationInvocation(value.validationText("id"), value.validationText("runId"),
        value.validationText("candidateRevisionId"), value.validationText("sourceRevisionSha256"),
        value.validationText("profileSha256"), value.validationText("indexSha256"), value.validationText("regressionCorpusSha256"))
}

internal fun parseRepairValidationDiagnosticBinding(value: JsonObject): RepairValidationDiagnosticBinding {
    require(value.keys == setOf("schemaVersion", "invocation", "runtimeSha256", "receiptPath", "receiptSha256",
        "receiptBytes", "diagnosticPath", "diagnosticSha256", "diagnosticBytes", "failureKind", "cleanupVerified"))
    require(value.validationNumber("schemaVersion").intOrNull == 1)
    val kind = value.validationText("failureKind")
    require(kind in RepairValidationFailureKind.entries.map { it.name.lowercase() })
    return RepairValidationDiagnosticBinding(
        parseRepairValidationInvocation(value.getValue("invocation") as? JsonObject ?: error("validation invocation type")),
        value.validationText("runtimeSha256"), value.validationText("receiptPath"), value.validationText("receiptSha256"),
        requireNotNull(value.validationNumber("receiptBytes").longOrNull), value.validationText("diagnosticPath"),
        value.validationText("diagnosticSha256"), requireNotNull(value.validationNumber("diagnosticBytes").intOrNull),
        RepairValidationFailureKind.valueOf(kind.uppercase()),
        requireNotNull(value.validationNumber("cleanupVerified").booleanOrNull),
    )
}

/** All semantic readers use the same association predicates, with their own graph lookup. */
internal fun requireRepairValidationDiagnosticAssociation(
    binding: RepairValidationDiagnosticBinding,
    runId: String,
    profileSha256: String,
    indexSha256: String,
    corpusSha256: String,
    candidateRevisionId: String,
    candidateSourceSha256: String,
) {
    val invocation = binding.invocation
    require(invocation.runId == runId && invocation.profileSha256 == profileSha256 &&
        invocation.indexSha256 == indexSha256 && invocation.regressionCorpusSha256 == corpusSha256 &&
        invocation.candidateRevisionId == candidateRevisionId && invocation.sourceRevisionSha256 == candidateSourceSha256) {
        "validation diagnostic is cross-paired with its selected run or candidate"
    }
}

/** Auxiliary getter, pairing and retention failures must not replace the original exception. */
internal fun retainRepairValidationDiagnostic(failure: Exception, invocation: RepairValidationInvocation,
    retain: (RepairValidationDiagnosticPublication) -> Unit) {
    try {
        val provider = failure.suppressed.filterIsInstance<RepairValidationFailureEvidence>().singleOrNull() ?: return
        val publication = provider.diagnosticPublication ?: return
        require(publication.invocation == invocation && publication.receiptPath == provider.receiptPath &&
            publication.receiptSha256 == provider.receiptSha256 && publication.failureKind == provider.failureKind &&
            publication.cleanupVerified == provider.cleanupVerified)
        retain(publication)
    } catch (retention: Throwable) {
        if (retention !== failure) failure.addSuppressed(retention)
    }
}

private fun validationDigest(value: String): Boolean = value.matches(Regex("[0-9a-f]{64}"))
private fun validationReportPath(value: String): Boolean {
    val parts = value.split('/')
    return value.length <= 4096 && parts.size in 2..32 && parts.first() == "reports" &&
        parts.drop(1).all { it != "." && it != ".." && it.matches(Regex("[A-Za-z0-9._-]{1,160}")) } &&
        parts[1] !in setOf("repair-revisions", "runs", "source-tree") && value != "reports/repair_history.json"
}
private fun JsonObject.validationText(name: String): String =
    (getValue(name) as? JsonPrimitive)?.takeIf { it.isString }?.content ?: error("validation text type")
private fun JsonObject.validationNumber(name: String): JsonPrimitive =
    (getValue(name) as? JsonPrimitive)?.takeUnless { it.isString } ?: error("validation scalar type")
