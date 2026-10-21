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
    val schemaVersion: Int = 1,
) {
    init {
        require(schemaVersion in 1..2)
        require(listOf(runtimeSha256, receiptSha256, diagnosticSha256).all(::validationDigest))
        require(receiptBytes in 1..64L * 1024 * 1024 && diagnosticBytes in 1..4096)
        require(validationReportPath(receiptPath) && validationReportPath(diagnosticPath))
        require(receiptPath != diagnosticPath)
        require(diagnosticPath.substringAfterLast('/') == "${invocation.id}.validation-failure.json")
        if (schemaVersion >= 2) require(receiptPath == "reports/${invocation.id}.validation.json" &&
            diagnosticPath == "reports/${invocation.id}.validation-failure.json")
        require(cleanupVerified == (failureKind != RepairValidationFailureKind.CLEANUP_UNVERIFIED))
    }

    internal fun toJsonObject(): JsonObject = JsonObject(mapOf(
        "schemaVersion" to JsonPrimitive(schemaVersion), "invocation" to invocation.toJsonObject(),
        "runtimeSha256" to JsonPrimitive(runtimeSha256), "receiptPath" to JsonPrimitive(receiptPath),
        "receiptSha256" to JsonPrimitive(receiptSha256), "receiptBytes" to JsonPrimitive(receiptBytes),
        "diagnosticPath" to JsonPrimitive(diagnosticPath), "diagnosticSha256" to JsonPrimitive(diagnosticSha256),
        "diagnosticBytes" to JsonPrimitive(diagnosticBytes), "failureKind" to JsonPrimitive(failureKind.name.lowercase()),
        "cleanupVerified" to JsonPrimitive(cleanupVerified),
    ))

    internal fun requireRetainedBudget(maximumBytes: Long) {
        val within = if (schemaVersion == 1) receiptBytes + 2L * diagnosticBytes <= minOf(maximumBytes, 64L * 1024 * 1024)
            else receiptBytes + diagnosticBytes <= 64L * 1024 * 1024 &&
                2L * (receiptBytes + diagnosticBytes) <= maximumBytes
        require(maximumBytes >= 0 && within) {
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
    val version = requireNotNull(value.validationNumber("schemaVersion").intOrNull).also { require(it in 1..2) }
    val kind = value.validationText("failureKind")
    require(kind in RepairValidationFailureKind.entries.map { it.name.lowercase() })
    return RepairValidationDiagnosticBinding(
        parseRepairValidationInvocation(value.getValue("invocation") as? JsonObject ?: error("validation invocation type")),
        value.validationText("runtimeSha256"), value.validationText("receiptPath"), value.validationText("receiptSha256"),
        requireNotNull(value.validationNumber("receiptBytes").longOrNull), value.validationText("diagnosticPath"),
        value.validationText("diagnosticSha256"), requireNotNull(value.validationNumber("diagnosticBytes").intOrNull),
        RepairValidationFailureKind.valueOf(kind.uppercase()),
        requireNotNull(value.validationNumber("cleanupVerified").booleanOrNull),
        version,
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
    expectedReceiptPath: Path? = null, expectedDiagnosticPath: Path? = null,
    retain: (RepairValidationDiagnosticPublication) -> Unit) {
    try {
        val provider = failure.suppressed.filterIsInstance<RepairValidationFailureEvidence>().singleOrNull() ?: return
        val publication = provider.diagnosticPublication ?: return
        require(publication.invocation == invocation && publication.receiptPath == provider.receiptPath &&
            publication.receiptSha256 == provider.receiptSha256 && publication.failureKind == provider.failureKind &&
            publication.cleanupVerified == provider.cleanupVerified)
        require((expectedReceiptPath == null) == (expectedDiagnosticPath == null))
        if (expectedReceiptPath != null) require(publication.receiptPath == expectedReceiptPath &&
            publication.diagnosticPath == expectedDiagnosticPath)
        retain(publication)
    } catch (retention: Throwable) {
        if (retention !== failure && failure.suppressed.none { it === retention }) {
            // Status classification reads one top-level provider marker. An auxiliary marker
            // must not become a second provider for the original validation failure.
            failure.addSuppressed(if (retention is RepairValidationFailureEvidence)
                IllegalStateException("validation diagnostic retention failed", retention) else retention)
        }
    }
}

/** Source files may be operator-selected; canonical names never depend on that source namespace. */
internal class RepairValidationDiagnosticRetention internal constructor(
    private val publication: RepairValidationDiagnosticPublication,
    val binding: RepairValidationDiagnosticBinding,
) {
    fun retain(read: (Path, Long) -> ByteArray, write: (String, ByteArray) -> Unit,
        readRetained: (String, Long) -> ByteArray) {
        val primary = read(publication.receiptPath, binding.receiptBytes)
        require(primary.size.toLong() == binding.receiptBytes && sha256(primary) == binding.receiptSha256)
        val diagnostic = read(publication.diagnosticPath, binding.diagnosticBytes.toLong())
        require(diagnostic.size == binding.diagnosticBytes && sha256(diagnostic) == binding.diagnosticSha256)
        val primaryName = "${binding.invocation.id}.validation.json"
        val diagnosticName = "${binding.invocation.id}.validation-failure.json"
        write(primaryName, primary)
        write(diagnosticName, diagnostic)
        require(readRetained(primaryName, binding.receiptBytes).contentEquals(primary))
        require(readRetained(diagnosticName, binding.diagnosticBytes.toLong()).contentEquals(diagnostic))
    }
}

internal fun planRepairValidationDiagnosticRetention(publication: RepairValidationDiagnosticPublication,
    maximumBytes: Long): RepairValidationDiagnosticRetention {
    val primary = publication.receiptPath.toAbsolutePath().normalize()
    val diagnostic = publication.diagnosticPath.toAbsolutePath().normalize()
    require(primary.parent == diagnostic.parent)
    val primaryName = primary.fileName.toString()
    require(primaryName.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}\\.validation\\.json")))
    require(diagnostic.fileName.toString() == primaryName.removeSuffix(".validation.json") + ".validation-failure.json")
    val id = publication.invocation.id
    val binding = RepairValidationDiagnosticBinding(publication.invocation, publication.runtimeSha256,
        "reports/$id.validation.json", publication.receiptSha256, publication.receiptBytes,
        "reports/$id.validation-failure.json", publication.diagnosticSha256, publication.diagnosticBytes,
        publication.failureKind, publication.cleanupVerified, schemaVersion = 2)
    binding.requireRetainedBudget(maximumBytes)
    return RepairValidationDiagnosticRetention(publication.copy(receiptPath = primary, diagnosticPath = diagnostic), binding)
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
