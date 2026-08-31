package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Path
import java.util.Base64
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

/**
 * Caller-controlled limits can only lower the fixed LLVM reference-evidence ceilings.
 * They cannot relax a format, identity, schema, or semantic check.
 */
class LlvmBehaviorReferenceLimits(
    val maximumCorpusBytes: Int = MAXIMUM_CORPUS_BYTES,
    val maximumReportBytes: Int = MAXIMUM_REPORT_BYTES,
    val maximumMatrixBytes: Int = MAXIMUM_MATRIX_BYTES,
    val maximumManifestBytes: Int = MAXIMUM_MANIFEST_BYTES,
    val maximumJsonDepth: Int = MAXIMUM_JSON_DEPTH,
    val maximumJsonNodes: Int = MAXIMUM_JSON_NODES,
    val maximumDecodedBlobBytes: Int = MAXIMUM_DECODED_BLOB_BYTES,
    val maximumDecodedInputBytesPerCase: Int = MAXIMUM_DECODED_INPUT_BYTES_PER_CASE,
    val maximumRetainedReportBytes: Int = MAXIMUM_RETAINED_REPORT_BYTES,
) {
    init {
        require(maximumCorpusBytes in 1..MAXIMUM_CORPUS_BYTES) { "maximumCorpusBytes may only lower the fixed ceiling" }
        require(maximumReportBytes in 1..MAXIMUM_REPORT_BYTES) { "maximumReportBytes may only lower the fixed ceiling" }
        require(maximumMatrixBytes in 1..MAXIMUM_MATRIX_BYTES) { "maximumMatrixBytes may only lower the fixed ceiling" }
        require(maximumManifestBytes in 1..MAXIMUM_MANIFEST_BYTES) {
            "maximumManifestBytes may only lower the fixed ceiling"
        }
        require(maximumJsonDepth in 1..MAXIMUM_JSON_DEPTH) { "maximumJsonDepth may only lower the fixed ceiling" }
        require(maximumJsonNodes in 1..MAXIMUM_JSON_NODES) { "maximumJsonNodes may only lower the fixed ceiling" }
        require(maximumDecodedBlobBytes in 1..MAXIMUM_DECODED_BLOB_BYTES) {
            "maximumDecodedBlobBytes may only lower the fixed ceiling"
        }
        require(maximumDecodedInputBytesPerCase in 1..MAXIMUM_DECODED_INPUT_BYTES_PER_CASE) {
            "maximumDecodedInputBytesPerCase may only lower the fixed ceiling"
        }
        require(maximumRetainedReportBytes in 1..MAXIMUM_RETAINED_REPORT_BYTES) {
            "maximumRetainedReportBytes may only lower the fixed ceiling"
        }
    }

    private companion object {
        const val MAXIMUM_CORPUS_BYTES = 16 * 1024 * 1024
        const val MAXIMUM_REPORT_BYTES = 64 * 1024 * 1024
        const val MAXIMUM_MATRIX_BYTES = 1024 * 1024
        const val MAXIMUM_MANIFEST_BYTES = 4 * 1024 * 1024
        const val MAXIMUM_JSON_DEPTH = 64
        const val MAXIMUM_JSON_NODES = 250_000
        const val MAXIMUM_DECODED_BLOB_BYTES = 16 * 1024 * 1024
        const val MAXIMUM_DECODED_INPUT_BYTES_PER_CASE = 16 * 1024 * 1024
        const val MAXIMUM_RETAINED_REPORT_BYTES = 32 * 1024 * 1024
    }
}

class LlvmBehaviorReferenceEvidenceException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * Authenticated, read-only reference evidence. This result does not execute Clang, compare a
 * reconstruction, score behavior, or authorize a release.
 */
sealed interface LlvmBehaviorReferenceEvidence {
    val corpusId: String
    val corpusSha256: String
    val reportSha256: String
    val diagnosticMatrixSha256: String
    val diagnosticMatrixSelfSha256: String
    val artifactManifestSha256: String
    val executableBytes: Long
    val executableSha256: String
    val sandboxSha256: String
    val caseIds: List<String>
    val diagnosticOwners: Map<String, String>
}

/** Fixed-production entry point. No caller-supplied parser, policy, identity, or digest is accepted. */
object LlvmBehaviorReferenceEvidenceVerifier {
    fun verify(
        corpusPath: Path,
        reportPath: Path,
        diagnosticMatrixPath: Path,
        artifactManifestPath: Path,
    ): LlvmBehaviorReferenceEvidence = AuthenticatedEvidence(
        corpusPath,
        reportPath,
        diagnosticMatrixPath,
        artifactManifestPath,
        LlvmBehaviorReferenceLimits(),
    )

    fun verify(
        corpusPath: Path,
        reportPath: Path,
        diagnosticMatrixPath: Path,
        artifactManifestPath: Path,
        limits: LlvmBehaviorReferenceLimits,
    ): LlvmBehaviorReferenceEvidence = AuthenticatedEvidence(
        corpusPath,
        reportPath,
        diagnosticMatrixPath,
        artifactManifestPath,
        limits,
    )

    /*
     * This implementation deliberately accepts only raw production paths and lowering limits.
     * Consequently, even a JVM caller that reaches its non-public class through reflection cannot
     * supply parsed JSON, a claimed digest, or prevalidated state: construction performs the same
     * complete authentication as the public verifier.
     */
    @Suppress("UNCHECKED_CAST")
    private class AuthenticatedEvidence(
        corpusPath: Path,
        reportPath: Path,
        diagnosticMatrixPath: Path,
        artifactManifestPath: Path,
        limits: LlvmBehaviorReferenceLimits,
    ) : LlvmBehaviorReferenceEvidence {
        override val corpusId: String
        override val corpusSha256: String
        override val reportSha256: String
        override val diagnosticMatrixSha256: String
        override val diagnosticMatrixSelfSha256: String
        override val artifactManifestSha256: String
        override val executableBytes: Long
        override val executableSha256: String
        override val sandboxSha256: String
        override val caseIds: List<String>
        override val diagnosticOwners: Map<String, String>

        init {
            val authenticated = authenticateEvidence(
                corpusPath,
                reportPath,
                diagnosticMatrixPath,
                artifactManifestPath,
                limits,
            )
            check(authenticated.size == AUTHENTICATED_FIELD_COUNT)
            corpusId = authenticated[0] as String
            corpusSha256 = authenticated[1] as String
            reportSha256 = authenticated[2] as String
            diagnosticMatrixSha256 = authenticated[3] as String
            diagnosticMatrixSelfSha256 = authenticated[4] as String
            artifactManifestSha256 = authenticated[5] as String
            executableBytes = authenticated[6] as Long
            executableSha256 = authenticated[7] as String
            sandboxSha256 = authenticated[8] as String
            caseIds = Collections.unmodifiableList(ArrayList(authenticated[9] as List<String>))
            diagnosticOwners = Collections.unmodifiableMap(LinkedHashMap(authenticated[10] as Map<String, String>))
        }
    }
}

private fun authenticateEvidence(
    corpusPath: Path,
    reportPath: Path,
    diagnosticMatrixPath: Path,
    artifactManifestPath: Path,
    limits: LlvmBehaviorReferenceLimits,
): Array<Any> {
    try {
                    val corpusSnapshot = OracleArtifacts.read(
                        corpusPath,
                        OracleArtifactLimits(limits.maximumCorpusBytes),
                    )
                    val reportSnapshot = OracleArtifacts.read(
                        reportPath,
                        OracleArtifactLimits(limits.maximumReportBytes),
                    )
                    val matrixSnapshot = OracleArtifacts.read(
                        diagnosticMatrixPath,
                        OracleArtifactLimits(limits.maximumMatrixBytes),
                    )
                    val manifestSnapshot = OracleArtifacts.read(
                        artifactManifestPath,
                        OracleArtifactLimits(limits.maximumManifestBytes),
                    )

                    val corpus = parseCanonicalObject(
                        corpusSnapshot.bytes,
                        jsonLimits(limits, limits.maximumCorpusBytes),
                        "LLVM behavior corpus",
                    )
                    val report = parseCanonicalObject(
                        reportSnapshot.bytes,
                        jsonLimits(limits, limits.maximumReportBytes),
                        "LLVM behavior report",
                    )
                    val matrix = parseCanonicalObject(
                        matrixSnapshot.bytes,
                        jsonLimits(limits, limits.maximumMatrixBytes),
                        "Clang diagnostic matrix",
                    )
                    val manifest = parseCanonicalObject(
                        manifestSnapshot.bytes,
                        jsonLimits(limits, limits.maximumManifestBytes),
                        "LLVM artifact manifest",
                    )

                    validateCorpus(corpus, limits)
                    validateReport(report, limits)
                    validateManifest(manifest, corpus, report)
                    validateReportPair(corpus, corpusSnapshot.sha256, report)
                    val matrixSelfSha256 = validateDiagnosticMatrix(matrix, corpus, corpusSnapshot.sha256)

                    // Schema checks remain mandatory; the schema-v1 migration test binds the
                    // corrected 128 MiB executable ceiling at both boundaries.
                    OracleSchemas.validate("behavior-corpus", corpus)
                    OracleSchemas.validate("behavior-corpus-report", report)
                    OracleSchemas.validate("clang-diagnostic-matrix", matrix)
                    OracleSchemas.validate("oracle-manifest", manifest)

                    requireReferenceFileDigest(corpusSnapshot.sha256, EXPECTED_CORPUS_SHA256, "behavior corpus")
                    requireReferenceFileDigest(reportSnapshot.sha256, EXPECTED_REPORT_SHA256, "behavior report")
                    requireReferenceFileDigest(matrixSnapshot.sha256, EXPECTED_MATRIX_FILE_SHA256, "diagnostic matrix")
                    requireReferenceFileDigest(
                        manifestSnapshot.sha256,
                        EXPECTED_MANIFEST_SHA256,
                        "artifact manifest",
                    )

                    reauthenticate(corpusPath, corpusSnapshot.size, corpusSnapshot.sha256, limits.maximumCorpusBytes, "corpus")
                    reauthenticate(reportPath, reportSnapshot.size, reportSnapshot.sha256, limits.maximumReportBytes, "report")
                    reauthenticate(
                        diagnosticMatrixPath,
                        matrixSnapshot.size,
                        matrixSnapshot.sha256,
                        limits.maximumMatrixBytes,
                        "diagnostic matrix",
                    )
                    reauthenticate(
                        artifactManifestPath,
                        manifestSnapshot.size,
                        manifestSnapshot.sha256,
                        limits.maximumManifestBytes,
                        "artifact manifest",
                    )

                    val executable = corpus.requiredObject("executable", "behavior corpus")
                    return arrayOf(
                        corpus.requiredString("id", "behavior corpus"),
                        corpusSnapshot.sha256,
                        reportSnapshot.sha256,
                        matrixSnapshot.sha256,
                        matrixSelfSha256,
                        manifestSnapshot.sha256,
                        executable.requiredLong("bytes", "behavior corpus executable"),
                        executable.requiredString("sha256", "behavior corpus executable"),
                        sha256(OracleJson.canonicalBytes(corpus.requiredObject("sandbox", "behavior corpus"))),
                        EXPECTED_CASE_IDS,
                        EXPECTED_DIAGNOSTIC_OWNERS,
                    )
    } catch (failure: LlvmBehaviorReferenceEvidenceException) {
        throw failure
    } catch (failure: Exception) {
        throw LlvmBehaviorReferenceEvidenceException(
            "LLVM behavior reference evidence verification failed: " +
                (failure.message ?: failure.javaClass.simpleName),
            failure,
        )
    }
}

private fun parseCanonicalObject(bytes: ByteArray, limits: StrictJsonLimits, label: String): JsonObject {
    val parsed = try {
        OracleJson.parseCanonical(bytes, limits)
    } catch (failure: Exception) {
        evidenceFail("$label is not strict canonical bounded JSON", failure)
    }
    return parsed as? JsonObject ?: evidenceFail("$label root must be an object")
}

private fun jsonLimits(limits: LlvmBehaviorReferenceLimits, maximumBytes: Int): StrictJsonLimits = StrictJsonLimits(
    maximumInputBytes = maximumBytes,
    maximumCanonicalBytes = maximumBytes,
    maximumDepth = limits.maximumJsonDepth,
    maximumNodes = limits.maximumJsonNodes,
    maximumStringBytes = maximumBytes,
    maximumTotalStringBytes = maximumBytes,
    maximumNumberCharacters = 64,
)

private fun validateCorpus(corpus: JsonObject, limits: LlvmBehaviorReferenceLimits) {
    corpus.requireExactFields(
        setOf(
            "schemaVersion",
            "scope",
            "id",
            "executable",
            "sandbox",
            "environment",
            "limits",
            "directories",
            "normalizations",
            "cases",
        ),
        "behavior corpus",
    )
    requireExactInteger(corpus, "schemaVersion", 1, "behavior corpus")
    requireExactString(corpus, "scope", "production", "behavior corpus")
    requireExactString(corpus, "id", EXPECTED_CORPUS_ID, "behavior corpus")

    val executable = corpus.requiredObject("executable", "behavior corpus")
    executable.requireExactFields(setOf("bytes", "sha256"), "behavior corpus executable")
    executable.requireLong("bytes", 1, MAXIMUM_EXECUTABLE_BYTES, "behavior corpus executable")
    executable.requireDigest("sha256", "behavior corpus executable")

    val sandbox = corpus.requiredObject("sandbox", "behavior corpus")
    validateSandbox(sandbox, "behavior corpus sandbox")
    if (sha256(OracleJson.canonicalBytes(sandbox)) != EXPECTED_SANDBOX_SHA256) {
        evidenceFail("behavior corpus sandbox differs from the reviewed exact executor policy")
    }

    validateBaseEnvironment(corpus.requiredObject("environment", "behavior corpus"), "behavior corpus environment")
    if (corpus.requiredObject("environment", "behavior corpus") != EXPECTED_BASE_ENVIRONMENT) {
        evidenceFail("behavior corpus base environment differs from the reviewed profile")
    }

    val policyLimits = corpus.requiredObject("limits", "behavior corpus")
    validateExecutionLimits(policyLimits, "behavior corpus limits")
    if (policyLimits != EXPECTED_EXECUTION_LIMITS) {
        evidenceFail("behavior corpus execution limits differ from the reviewed profile")
    }

    val directories = corpus.requiredArray("directories", "behavior corpus").strings("behavior corpus directories")
    requireSortedUnique(directories, "behavior corpus directories")
    if (directories != EXPECTED_DIRECTORIES) evidenceFail("behavior corpus directories differ from the reviewed profile")
    val requiredDirectories = LinkedHashSet(directories)
    directories.forEach { addParents(it, requiredDirectories) }

    val normalizationRecords = corpus.requiredArray("normalizations", "behavior corpus")
    if (normalizationRecords.isNotEmpty()) {
        evidenceFail("the reviewed LLVM behavior corpus must not declare output normalizations")
    }

    val cases = corpus.requiredArray("cases", "behavior corpus")
    if (cases.size != EXPECTED_CASE_IDS.size) {
        evidenceFail("behavior corpus must contain exactly ${EXPECTED_CASE_IDS.size} reviewed cases")
    }
    val caseIds = ArrayList<String>(cases.size)
    val globalCategories = LinkedHashSet<String>()
    cases.forEachIndexed { caseIndex, rawCase ->
        val label = "behavior corpus case[$caseIndex]"
        val case = rawCase.asObject(label)
        case.requireExactFields(
            setOf("id", "categories", "arguments", "environment", "stdin", "inputs", "expected"),
            label,
        )
        val caseId = case.requiredIdentifier("id", label)
        caseIds += caseId
        val categories = case.requiredArray("categories", label).strings("$label categories")
        if (categories.isEmpty() || categories.size > 32) evidenceFail("$label categories count is invalid")
        categories.forEach { requireIdentifier(it, "$label category") }
        requireSortedUnique(categories, "$label categories")
        globalCategories += categories
        if (globalCategories.size > 256) evidenceFail("behavior corpus category union exceeds 256")

        val arguments = case.requiredArray("arguments", label)
        if (arguments.size > 4096) evidenceFail("$label arguments exceed 4096")
        arguments.forEachIndexed { index, argument ->
            val text = argument.asString("$label argument[$index]")
            if (text.length > 4096) evidenceFail("$label argument[$index] exceeds 4096 characters")
            validatePlaceholders(text, "$label argument[$index]")
        }
        validateVariables(case.requiredObject("environment", label), "$label environment")
        validateBlob(case.requiredObject("stdin", label), "$label stdin", limits.maximumDecodedBlobBytes)

        val inputs = case.requiredArray("inputs", label)
        if (inputs.size > 256) evidenceFail("$label inputs exceed 256")
        val inputPaths = ArrayList<String>(inputs.size)
        var totalInputBytes = 0L
        inputs.forEachIndexed { inputIndex, rawInput ->
            val inputLabel = "$label input[$inputIndex]"
            val input = rawInput.asObject(inputLabel)
            input.requireExactFields(setOf("path", "bytes", "sha256", "base64", "executable"), inputLabel)
            val relative = requireRelativePath(input.requiredString("path", inputLabel), "$inputLabel path")
            input.requiredBoolean("executable", inputLabel)
            val decodedBytes = validateBlob(input, inputLabel, limits.maximumDecodedBlobBytes, setOf("path", "executable"))
            if (decodedBytes > EXPECTED_FILE_BYTES_LIMIT) evidenceFail("$inputLabel exceeds the execution file-byte limit")
            totalInputBytes = checkedAdd(totalInputBytes, decodedBytes.toLong(), "$label decoded input bytes")
            inputPaths += relative
        }
        if (totalInputBytes > limits.maximumDecodedInputBytesPerCase || totalInputBytes > EXPECTED_WORKSPACE_BYTES_LIMIT) {
            evidenceFail("$label decoded inputs exceed the bounded per-case workspace policy")
        }
        requireSortedUnique(inputPaths, "$label input paths")
        val caseDirectories = LinkedHashSet(requiredDirectories)
        inputPaths.forEach { addParents(it, caseDirectories) }
        if (inputPaths.any(caseDirectories::contains)) evidenceFail("$label inputs conflict with required directories")
        if (caseDirectories.size + inputPaths.size > EXPECTED_WORKSPACE_ENTRIES_LIMIT) {
            evidenceFail("$label inputs exceed the workspace-entry limit")
        }

        val expected = case.requiredObject("expected", label)
        expected.requireExactFields(setOf("exitCode", "stdout", "stderr", "artifacts"), "$label expected")
        expected.requireLong("exitCode", 0, 255, "$label expected")
        validateStream(
            expected.requiredObject("stdout", "$label expected"),
            "$label expected stdout",
            minOf(limits.maximumDecodedBlobBytes, EXPECTED_STDOUT_LIMIT),
        )
        validateStream(
            expected.requiredObject("stderr", "$label expected"),
            "$label expected stderr",
            minOf(limits.maximumDecodedBlobBytes, EXPECTED_STDERR_LIMIT),
        )

        val artifacts = expected.requiredArray("artifacts", "$label expected")
        if (artifacts.size > 256) evidenceFail("$label expected artifacts exceed 256")
        val artifactPaths = ArrayList<String>(artifacts.size)
        artifacts.forEachIndexed { artifactIndex, rawArtifact ->
            val artifactLabel = "$label expected artifact[$artifactIndex]"
            val artifact = rawArtifact.asObject(artifactLabel)
            artifact.requireExactFields(setOf("path", "present", "bytes", "sha256", "base64", "mode"), artifactLabel)
            artifactPaths += requireRelativePath(artifact.requiredString("path", artifactLabel), "$artifactLabel path")
            val present = artifact.requiredBoolean("present", artifactLabel)
            if (present) {
                validateBlob(artifact, artifactLabel, minOf(limits.maximumDecodedBlobBytes, EXPECTED_ARTIFACT_LIMIT), setOf("path", "present", "mode"))
                requireReadableMode(artifact.requiredString("mode", artifactLabel), "$artifactLabel mode")
            } else {
                listOf("bytes", "sha256", "base64", "mode").forEach { field ->
                    if (artifact[field] != JsonNull) evidenceFail("$artifactLabel absent data field $field must be null")
                }
            }
        }
        requireSortedUnique(artifactPaths, "$label expected artifact paths")
        if (inputPaths.toSet().intersect(artifactPaths.toSet()).isNotEmpty()) {
            evidenceFail("$label input and artifact paths overlap")
        }
        if (artifactPaths.any(caseDirectories::contains)) {
            evidenceFail("$label expected artifacts conflict with required directories")
        }
    }
    requireSortedUnique(caseIds, "behavior corpus case IDs")
    if (caseIds != EXPECTED_CASE_IDS) evidenceFail("behavior corpus case membership or order differs from the reviewed profile")
}

private fun validateReport(report: JsonObject, limits: LlvmBehaviorReferenceLimits) {
    report.requireExactFields(
        setOf("schemaVersion", "corpus", "executable", "sandbox", "limits", "summary", "cases"),
        "behavior report",
    )
    requireExactInteger(report, "schemaVersion", 1, "behavior report")
    val corpusIdentity = report.requiredObject("corpus", "behavior report")
    corpusIdentity.requireExactFields(setOf("id", "sha256"), "behavior report corpus identity")
    requireExactString(corpusIdentity, "id", EXPECTED_CORPUS_ID, "behavior report corpus identity")
    corpusIdentity.requireDigest("sha256", "behavior report corpus identity")

    val executable = report.requiredObject("executable", "behavior report")
    executable.requireExactFields(setOf("bytes", "sha256"), "behavior report executable")
    executable.requireLong("bytes", 1, MAXIMUM_EXECUTABLE_BYTES, "behavior report executable")
    executable.requireDigest("sha256", "behavior report executable")
    validateSandbox(report.requiredObject("sandbox", "behavior report"), "behavior report sandbox")
    validateExecutionLimits(report.requiredObject("limits", "behavior report"), "behavior report limits")

    val summary = report.requiredObject("summary", "behavior report")
    summary.requireExactFields(setOf("cases", "passed", "categories"), "behavior report summary")
    requireExactInteger(summary, "cases", EXPECTED_CASE_IDS.size.toLong(), "behavior report summary")
    requireExactInteger(summary, "passed", EXPECTED_CASE_IDS.size.toLong(), "behavior report summary")
    val summaryCategories = summary.requiredArray("categories", "behavior report summary").strings("behavior report categories")
    summaryCategories.forEach { requireIdentifier(it, "behavior report category") }
    requireSortedUnique(summaryCategories, "behavior report categories")

    val cases = report.requiredArray("cases", "behavior report")
    if (cases.size != EXPECTED_CASE_IDS.size) evidenceFail("behavior report must contain exactly 48 cases")
    val caseIds = ArrayList<String>(cases.size)
    var retainedBytes = 0L
    cases.forEachIndexed { caseIndex, rawCase ->
        val label = "behavior report case[$caseIndex]"
        val case = rawCase.asObject(label)
        case.requireExactFields(setOf("id", "status", "exitCode", "stdout", "stderr", "artifacts"), label)
        caseIds += case.requiredIdentifier("id", label)
        requireExactString(case, "status", "passed", label)
        case.requireLong("exitCode", 0, 255, label)
        retainedBytes = checkedAdd(
            retainedBytes,
            validateStream(
                case.requiredObject("stdout", label),
                "$label stdout",
                minOf(limits.maximumDecodedBlobBytes, EXPECTED_STDOUT_LIMIT),
            ).toLong(),
            "behavior report retained bytes",
        )
        retainedBytes = checkedAdd(
            retainedBytes,
            validateStream(
                case.requiredObject("stderr", label),
                "$label stderr",
                minOf(limits.maximumDecodedBlobBytes, EXPECTED_STDERR_LIMIT),
            ).toLong(),
            "behavior report retained bytes",
        )
        if (retainedBytes > limits.maximumRetainedReportBytes) {
            evidenceFail("behavior report exceeds the aggregate retained-evidence byte limit")
        }
        val artifacts = case.requiredArray("artifacts", label)
        if (artifacts.size > 256) evidenceFail("$label artifacts exceed 256")
        val paths = ArrayList<String>(artifacts.size)
        artifacts.forEachIndexed { artifactIndex, rawArtifact ->
            val artifactLabel = "$label artifact[$artifactIndex]"
            val artifact = rawArtifact.asObject(artifactLabel)
            artifact.requireExactFields(setOf("path", "present", "bytes", "sha256", "base64", "mode"), artifactLabel)
            paths += requireRelativePath(artifact.requiredString("path", artifactLabel), "$artifactLabel path")
            if (artifact.requiredBoolean("present", artifactLabel)) {
                retainedBytes = checkedAdd(
                    retainedBytes,
                    validateBlob(
                        artifact,
                        artifactLabel,
                        minOf(limits.maximumDecodedBlobBytes, EXPECTED_ARTIFACT_LIMIT),
                        setOf("path", "present", "mode"),
                    ).toLong(),
                    "behavior report retained bytes",
                )
                requireReadableMode(artifact.requiredString("mode", artifactLabel), "$artifactLabel mode")
            } else {
                listOf("bytes", "sha256", "base64", "mode").forEach { field ->
                    if (artifact[field] != JsonNull) evidenceFail("$artifactLabel absent data field $field must be null")
                }
            }
            if (retainedBytes > limits.maximumRetainedReportBytes) {
                evidenceFail("behavior report exceeds the aggregate retained-evidence byte limit")
            }
        }
        requireSortedUnique(paths, "$label artifact paths")
    }
    requireSortedUnique(caseIds, "behavior report case IDs")
    if (caseIds != EXPECTED_CASE_IDS) evidenceFail("behavior report case membership or order differs")
}

private fun validateReportPair(corpus: JsonObject, corpusSha256: String, report: JsonObject) {
    val reportCorpus = report.requiredObject("corpus", "behavior report")
    if (reportCorpus.requiredString("id", "behavior report corpus") != EXPECTED_CORPUS_ID ||
        reportCorpus.requiredString("sha256", "behavior report corpus") != corpusSha256
    ) {
        evidenceFail("behavior report does not identify the exact canonical corpus bytes")
    }
    listOf("executable", "sandbox", "limits").forEach { field ->
        if (report[field] != corpus[field]) evidenceFail("behavior report $field differs from its corpus")
    }
    val corpusCases = corpus.requiredArray("cases", "behavior corpus")
    val reportCases = report.requiredArray("cases", "behavior report")
    val categoryUnion = corpusCases.flatMap { raw ->
        raw.asObject("behavior corpus case").requiredArray("categories", "behavior corpus case").strings("case categories")
    }.toSortedSet().toList()
    val reportCategories = report.requiredObject("summary", "behavior report")
        .requiredArray("categories", "behavior report summary")
        .strings("behavior report categories")
    if (reportCategories != categoryUnion) evidenceFail("behavior report category union differs from its corpus")
    corpusCases.indices.forEach { index ->
        val corpusCase = corpusCases[index].asObject("behavior corpus case[$index]")
        val reportCase = reportCases[index].asObject("behavior report case[$index]")
        if (corpusCase.requiredString("id", "behavior corpus case[$index]") !=
            reportCase.requiredString("id", "behavior report case[$index]")
        ) {
            evidenceFail("behavior report case order differs from its corpus")
        }
        val expected = corpusCase.requiredObject("expected", "behavior corpus case[$index]")
        listOf("exitCode", "stdout", "stderr", "artifacts").forEach { field ->
            if (reportCase[field] != expected[field]) {
                evidenceFail("behavior report case ${EXPECTED_CASE_IDS[index]} $field differs from its corpus")
            }
        }
    }
}

private fun validateManifest(manifest: JsonObject, corpus: JsonObject, report: JsonObject) {
    val oracle = manifest.requiredObject("oracle", "LLVM artifact manifest")
    requireExactString(oracle, "id", EXPECTED_MANIFEST_ORACLE_ID, "LLVM artifact manifest oracle")
    requireExactString(oracle, "version", EXPECTED_LLVM_VERSION, "LLVM artifact manifest oracle")
    requireExactString(oracle, "sourceRevision", EXPECTED_LLVM_SOURCE_REVISION, "LLVM artifact manifest oracle")
    val stripped = manifest.requiredObject("artifacts", "LLVM artifact manifest")
        .requiredObject("stripped", "LLVM artifact manifest artifacts")
    requireExactString(stripped, "path", EXPECTED_STRIPPED_PATH, "LLVM stripped artifact")
    val manifestExecutable = JsonObject(
        linkedMapOf(
            "bytes" to stripped.requiredElement("bytes", "LLVM stripped artifact"),
            "sha256" to stripped.requiredElement("sha256", "LLVM stripped artifact"),
        ),
    )
    if (corpus.requiredObject("executable", "behavior corpus") != manifestExecutable) {
        evidenceFail("behavior corpus executable differs from the authenticated manifest stripped artifact")
    }
    if (report.requiredObject("executable", "behavior report") != manifestExecutable) {
        evidenceFail("behavior report executable differs from the authenticated manifest stripped artifact")
    }
}

private fun validateDiagnosticMatrix(matrix: JsonObject, corpus: JsonObject, corpusSha256: String): String {
    matrix.requireExactFields(
        setOf("schemaVersion", "id", "corpusSha256", "policy", "cases", "matrixSha256"),
        "Clang diagnostic matrix",
    )
    requireExactInteger(matrix, "schemaVersion", 1, "Clang diagnostic matrix")
    requireExactString(matrix, "id", EXPECTED_MATRIX_ID, "Clang diagnostic matrix")
    if (matrix.requiredString("corpusSha256", "Clang diagnostic matrix") != corpusSha256) {
        evidenceFail("Clang diagnostic matrix does not bind the exact corpus bytes")
    }
    val policy = matrix.requiredObject("policy", "Clang diagnostic matrix")
    policy.requireExactFields(
        setOf("locale", "terminalWidth", "forbiddenNormalizations", "pathNormalization"),
        "Clang diagnostic policy",
    )
    if (policy != EXPECTED_DIAGNOSTIC_POLICY) evidenceFail("Clang diagnostic policy differs from the reviewed policy")

    val withoutHash = JsonObject(matrix.filterKeys { it != "matrixSha256" })
    val calculatedSelfHash = sha256(OracleJson.canonicalBytes(withoutHash))
    if (matrix.requiredString("matrixSha256", "Clang diagnostic matrix") != calculatedSelfHash) {
        evidenceFail("Clang diagnostic matrix self hash differs")
    }

    val corpusCases = corpus.requiredArray("cases", "behavior corpus").associate { raw ->
        val case = raw.asObject("behavior corpus case")
        case.requiredString("id", "behavior corpus case") to case
    }
    val diagnosticCorpusIds = corpusCases.values.filter { case ->
        "diagnostics" in case.requiredArray("categories", "behavior corpus case").strings("case categories")
    }.map { it.requiredString("id", "behavior corpus case") }.sorted()
    if (diagnosticCorpusIds != EXPECTED_DIAGNOSTIC_IDS) {
        evidenceFail("behavior corpus diagnostic membership differs from the reviewed matrix")
    }

    val cases = matrix.requiredArray("cases", "Clang diagnostic matrix")
    if (cases.size != EXPECTED_DIAGNOSTIC_IDS.size) evidenceFail("Clang diagnostic matrix must contain exactly 16 cases")
    val caseIds = ArrayList<String>(cases.size)
    val mismatchIds = LinkedHashSet<String>()
    cases.forEachIndexed { index, rawCase ->
        val label = "Clang diagnostic case[$index]"
        val case = rawCase.asObject(label)
        case.requireExactFields(
            setOf(
                "id",
                "ownerSubsystem",
                "categories",
                "exitCode",
                "stdoutSha256",
                "stderrSha256",
                "normalizations",
                "mismatchIds",
            ),
            label,
        )
        val id = case.requiredString("id", label)
        caseIds += id
        val source = corpusCases[id] ?: evidenceFail("$label does not identify a corpus case")
        if (case.requiredString("ownerSubsystem", label) != EXPECTED_DIAGNOSTIC_OWNERS[id]) {
            evidenceFail("$label owner subsystem differs")
        }
        if (case.requiredArray("categories", label) != source.requiredArray("categories", "behavior corpus case $id")) {
            evidenceFail("$label categories differ from the corpus")
        }
        val expected = source.requiredObject("expected", "behavior corpus case $id")
        if (case.requiredElement("exitCode", label) != expected.requiredElement("exitCode", "behavior corpus case $id")) {
            evidenceFail("$label exit code differs from the corpus")
        }
        listOf("stdout", "stderr").forEach { stream ->
            val expectedStream = expected.requiredObject(stream, "behavior corpus case $id")
            if (case.requiredString("${stream}Sha256", label) != expectedStream.requiredString("sha256", "$id $stream")) {
                evidenceFail("$label $stream digest differs from the corpus")
            }
        }
        val normalizations = case.requiredObject("normalizations", label)
        normalizations.requireExactFields(setOf("stdout", "stderr"), "$label normalizations")
        listOf("stdout", "stderr").forEach { stream ->
            if (normalizations.requiredArray(stream, "$label normalizations") !=
                expected.requiredObject(stream, "behavior corpus case $id").requiredArray("normalizations", "$id $stream")
            ) {
                evidenceFail("$label $stream normalizations differ from the corpus")
            }
        }
        val ids = case.requiredObject("mismatchIds", label)
        ids.requireExactFields(MISMATCH_FIELDS, "$label mismatch IDs")
        MISMATCH_FIELDS.forEach { field ->
            val expectedId = diagnosticMismatchId(id, field)
            if (ids.requiredString(field, "$label mismatch IDs") != expectedId) {
                evidenceFail("$label mismatch identity for $field differs")
            }
            if (!mismatchIds.add(expectedId)) evidenceFail("Clang diagnostic mismatch identities are not globally unique")
        }
    }
    if (caseIds != EXPECTED_DIAGNOSTIC_IDS) evidenceFail("Clang diagnostic case membership or order differs")
    return calculatedSelfHash
}

private fun validateSandbox(sandbox: JsonObject, label: String) {
    sandbox.requireExactFields(
        setOf(
            "backend",
            "resourcePolicyVersion",
            "oomScoreAdjustment",
            "imageDigest",
            "platform",
            "isolation",
            "imageEnvironment",
            "preExecArgv",
            "environmentLauncher",
            "keeperArgv",
            "setupArgv",
            "collectorArgv",
            "targetUser",
            "controlClient",
            "engineProfile",
        ),
        label,
    )
    requireExactString(sandbox, "backend", "oci-container-v1", label)
    requireExactInteger(sandbox, "resourcePolicyVersion", 1, label)
    requireExactInteger(sandbox, "oomScoreAdjustment", 500, label)
    if (!IMAGE_DIGEST.matches(sandbox.requiredString("imageDigest", label))) evidenceFail("$label image digest is invalid")
    if (!PLATFORM.matches(sandbox.requiredString("platform", label))) evidenceFail("$label platform is invalid")
    requireExactString(sandbox, "isolation", EXPECTED_ISOLATION, label)
    validateImageEnvironment(sandbox.requiredArray("imageEnvironment", label), "$label image environment")
    listOf("preExecArgv", "keeperArgv", "setupArgv", "collectorArgv").forEach { field ->
        validateHelperArgv(sandbox.requiredArray(field, label), "$label $field")
    }
    requireAbsolutePath(sandbox.requiredString("environmentLauncher", label), "$label environment launcher")
    if (!NUMERIC_USER.matches(sandbox.requiredString("targetUser", label))) evidenceFail("$label target user is invalid")
    val controlClient = sandbox.requiredObject("controlClient", label)
    controlClient.requireExactFields(setOf("bytes", "sha256", "version"), "$label control client")
    controlClient.requireLong("bytes", 1, MAXIMUM_EXECUTABLE_BYTES, "$label control client")
    controlClient.requireDigest("sha256", "$label control client")
    val version = controlClient.requiredString("version", "$label control client")
    if (version.isEmpty() || version.length > 512) evidenceFail("$label control client version is invalid")

    val engine = sandbox.requiredObject("engineProfile", label)
    engine.requireExactFields(ENGINE_FIELDS, "$label engine profile")
    listOf(
        "product",
        "serverVersion",
        "serverCommit",
        "kernelVersion",
        "cgroupDriver",
        "storageDriver",
        "containerRuntime",
        "containerRuntimePath",
        "containerRuntimeVersion",
        "containerRuntimeCommit",
        "volumePlugin",
    ).forEach { field ->
        val value = engine.requiredString(field, "$label engine profile")
        if (value.isEmpty() || value.length > 256) evidenceFail("$label engine profile $field is invalid")
    }
    if (!API_VERSION.matches(engine.requiredString("apiVersion", "$label engine profile"))) {
        evidenceFail("$label engine API version is invalid")
    }
    requireExactString(engine, "operatingSystem", "linux", "$label engine profile")
    val architecture = engine.requiredString("architecture", "$label engine profile")
    if (architecture.isEmpty() || architecture.length > 64) evidenceFail("$label engine architecture is invalid")
    requireExactInteger(engine, "cgroupVersion", 2, "$label engine profile")
    engine.requireDigest("componentsSha256", "$label engine profile")
    engine.requireDigest("containerRuntimeFeaturesSha256", "$label engine profile")
    val securityOptions = engine.requiredArray("securityOptions", "$label engine profile").strings("$label security options")
    requireSortedUnique(securityOptions, "$label security options")
    if (!securityOptions.containsAll(REQUIRED_SECURITY_OPTIONS)) evidenceFail("$label omits mandatory security options")
    requireExactString(engine, "volumePlugin", "local", "$label engine profile")
}

private fun validateExecutionLimits(value: JsonObject, label: String) {
    value.requireExactFields(EXECUTION_LIMIT_FIELDS, label)
    value.requireLong("timeoutMilliseconds", 1, 30_000, label)
    value.requireLong("stdoutBytes", 0, 16L * 1024 * 1024, label)
    value.requireLong("stderrBytes", 0, 16L * 1024 * 1024, label)
    val artifact = value.requireLong("artifactBytes", 0, 16L * 1024 * 1024, label)
    val memory = value.requireLong("memoryBytes", 64L * 1024 * 1024, 8L * 1024 * 1024 * 1024, label)
    val file = value.requireLong("fileBytes", 1, 16L * 1024 * 1024, label)
    value.requireLong("openFiles", 16, 4096, label)
    value.requireLong("processes", 1, 4096, label)
    value.requireLong("cpuSeconds", 1, 30, label)
    val workspace = value.requireLong("workspaceBytes", 1, 64L * 1024 * 1024, label)
    value.requireLong("workspaceEntries", 1, 4096, label)
    if (workspace > memory || file > workspace || artifact > workspace || artifact > file) {
        evidenceFail("$label has inconsistent file, artifact, workspace, or memory bounds")
    }
}

private fun validateBaseEnvironment(value: JsonObject, label: String) {
    value.requireExactFields(setOf("clearInherited", "variables"), label)
    if (!value.requiredBoolean("clearInherited", label)) evidenceFail("$label must clear inherited variables")
    validateVariables(value.requiredObject("variables", label), "$label variables")
}

private fun validateVariables(value: JsonObject, label: String) {
    if (value.size > 256) evidenceFail("$label exceeds 256 variables")
    val names = value.keys.toList()
    requireSortedUnique(names, "$label names")
    value.forEach { (name, rawValue) ->
        if (!ENVIRONMENT_NAME.matches(name)) evidenceFail("$label contains invalid variable name $name")
        val text = rawValue.asString("$label $name")
        if (text.length > 4096) evidenceFail("$label $name exceeds 4096 characters")
        validatePlaceholders(text, "$label $name")
    }
}

private fun validateImageEnvironment(value: JsonArray, label: String) {
    if (value.size > 256) evidenceFail("$label exceeds 256 entries")
    val names = ArrayList<String>(value.size)
    value.forEachIndexed { index, element ->
        val entry = element.asString("$label[$index]")
        if (entry.isEmpty() || entry.length > 16_384) evidenceFail("$label[$index] is invalid")
        val separator = entry.indexOf('=')
        if (separator <= 0) evidenceFail("$label[$index] is not NAME=value")
        val name = entry.substring(0, separator)
        if (!ENVIRONMENT_NAME.matches(name)) evidenceFail("$label[$index] has an invalid name")
        if (name in FORBIDDEN_ENVIRONMENT_NAMES || FORBIDDEN_ENVIRONMENT_PREFIXES.any(name::startsWith)) {
            evidenceFail("$label[$index] uses a forbidden prelaunch variable")
        }
        names += name
    }
    if (names.size != names.toSet().size) evidenceFail("$label contains duplicate variable names")
}

private fun validateHelperArgv(value: JsonArray, label: String) {
    if (value.isEmpty() || value.size > 4096) evidenceFail("$label count is invalid")
    value.forEachIndexed { index, element ->
        val argument = element.asString("$label[$index]")
        if (argument.length > 8192) evidenceFail("$label[$index] exceeds 8192 characters")
        if (index == 0) requireAbsolutePath(argument, "$label[0]")
    }
}

private fun validateStream(value: JsonObject, label: String, maximumBytes: Int): Int {
    val decoded = validateBlob(value, label, maximumBytes, setOf("normalizations"))
    val normalizations = value.requiredArray("normalizations", label).strings("$label normalizations")
    if (normalizations.isNotEmpty()) evidenceFail("$label must not apply output normalization")
    return decoded
}

private fun validateBlob(
    value: JsonObject,
    label: String,
    maximumBytes: Int,
    additionalFields: Set<String> = emptySet(),
): Int {
    value.requireExactFields(setOf("bytes", "sha256", "base64") + additionalFields, label)
    val expectedBytes = value.requireLong("bytes", 0, maximumBytes.toLong(), label).toInt()
    val expectedDigest = value.requiredString("sha256", label)
    if (!SHA256.matches(expectedDigest)) evidenceFail("$label SHA-256 is invalid")
    val encoded = value.requiredString("base64", label)
    val expectedEncodedCharacters = ((expectedBytes.toLong() + 2L) / 3L) * 4L
    if (expectedEncodedCharacters > Int.MAX_VALUE || encoded.length.toLong() != expectedEncodedCharacters) {
        evidenceFail("$label base64 encoded length differs before decoding")
    }
    val decoded = try {
        Base64.getDecoder().decode(encoded)
    } catch (failure: IllegalArgumentException) {
        evidenceFail("$label is not canonical base64", failure)
    }
    if (decoded.size != expectedBytes || Base64.getEncoder().encodeToString(decoded) != encoded) {
        evidenceFail("$label base64 is not canonical or has the declared byte length")
    }
    if (sha256(decoded) != expectedDigest) evidenceFail("$label SHA-256 differs from decoded bytes")
    return decoded.size
}

private fun requireReadableMode(mode: String, label: String) {
    if (!MODE.matches(mode) || (mode.substring(2).toInt(8) and 0b100_000_000) == 0) {
        evidenceFail("$label must be a canonical owner-readable mode")
    }
}

private fun requireRelativePath(value: String, label: String): String {
    if (value.isEmpty() || value.length > 4096 || value.startsWith('/') || value.contains('\\')) {
        evidenceFail("$label must be a normalized relative POSIX path")
    }
    val parts = value.split('/')
    if (parts.any { it.isEmpty() || it == "." || it == ".." } || parts.joinToString("/") != value) {
        evidenceFail("$label must be a normalized relative POSIX path")
    }
    return value
}

private fun requireAbsolutePath(value: String, label: String) {
    if (!value.startsWith('/') || value == "/" || value.startsWith("//") || value.contains('\\')) {
        evidenceFail("$label must be a normalized non-root absolute path")
    }
    val parts = value.removePrefix("/").split('/')
    if (parts.any { it.isEmpty() || it == "." || it == ".." }) {
        evidenceFail("$label must be a normalized non-root absolute path")
    }
}

private fun addParents(path: String, result: MutableSet<String>) {
    var offset = path.lastIndexOf('/')
    while (offset > 0) {
        result += path.substring(0, offset)
        offset = path.lastIndexOf('/', offset - 1)
    }
}

private fun validatePlaceholders(value: String, label: String) {
    PLACEHOLDER.findAll(value).forEach { match ->
        if (match.groupValues[1] !in setOf("workspace", "oracle")) evidenceFail("$label has an unknown placeholder")
    }
    val stripped = PLACEHOLDER.replace(value, "")
    if ('{' in stripped || '}' in stripped) evidenceFail("$label has a malformed placeholder")
}

private fun diagnosticMismatchId(caseId: String, field: String): String =
    "clang-diagnostic-${sha256("$caseId:$field".encodeToByteArray()).take(32)}"

private fun requireReferenceFileDigest(actual: String, expected: String, label: String) {
    if (actual != expected) evidenceFail("$label bytes differ from the checked reference")
}

private fun reauthenticate(path: Path, expectedSize: Int, expectedSha256: String, maximumBytes: Int, label: String) {
    val terminal = OracleArtifacts.read(path, OracleArtifactLimits(maximumBytes))
    if (terminal.size != expectedSize || terminal.sha256 != expectedSha256) {
        evidenceFail("$label changed before terminal acceptance")
    }
}

private fun checkedAdd(left: Long, right: Long, label: String): Long {
    if (right < 0 || left > Long.MAX_VALUE - right) evidenceFail("$label overflow")
    return left + right
}

private fun sha256(bytes: ByteArray): String = OracleArtifacts.sha256(bytes)

private fun JsonObject.requireExactFields(expected: Set<String>, label: String) {
    if (keys != expected) evidenceFail("$label fields differ: expected ${expected.sorted()}, got ${keys.sorted()}")
}

private fun JsonObject.requiredElement(name: String, label: String): JsonElement =
    this[name] ?: evidenceFail("$label is missing $name")

private fun JsonObject.requiredObject(name: String, label: String): JsonObject =
    requiredElement(name, label).asObject("$label.$name")

private fun JsonObject.requiredArray(name: String, label: String): JsonArray =
    requiredElement(name, label) as? JsonArray ?: evidenceFail("$label.$name must be an array")

private fun JsonObject.requiredString(name: String, label: String): String =
    requiredElement(name, label).asString("$label.$name")

private fun JsonObject.requiredBoolean(name: String, label: String): Boolean {
    val primitive = requiredElement(name, label) as? JsonPrimitive ?: evidenceFail("$label.$name must be boolean")
    if (primitive.isString) evidenceFail("$label.$name must be boolean")
    return primitive.booleanOrNull ?: evidenceFail("$label.$name must be boolean")
}

private fun JsonObject.requiredLong(name: String, label: String): Long {
    val primitive = requiredElement(name, label) as? JsonPrimitive ?: evidenceFail("$label.$name must be integer")
    if (primitive.isString || !INTEGER.matches(primitive.content)) evidenceFail("$label.$name must be integer")
    return primitive.longOrNull ?: evidenceFail("$label.$name must be a supported integer")
}

private fun JsonObject.requireLong(name: String, minimum: Long, maximum: Long, label: String): Long {
    val value = requiredLong(name, label)
    if (value !in minimum..maximum) evidenceFail("$label.$name is outside $minimum..$maximum")
    return value
}

private fun JsonObject.requireDigest(name: String, label: String): String {
    val value = requiredString(name, label)
    if (!SHA256.matches(value)) evidenceFail("$label.$name must be lowercase SHA-256")
    return value
}

private fun JsonObject.requiredIdentifier(name: String, label: String): String =
    requiredString(name, label).also { requireIdentifier(it, "$label.$name") }

private fun JsonElement.asObject(label: String): JsonObject = this as? JsonObject ?: evidenceFail("$label must be an object")

private fun JsonElement.asString(label: String): String {
    val primitive = this as? JsonPrimitive ?: evidenceFail("$label must be a string")
    if (!primitive.isString) evidenceFail("$label must be a string")
    return primitive.content
}

private fun JsonArray.strings(label: String): List<String> = mapIndexed { index, value -> value.asString("$label[$index]") }

private fun requireExactString(value: JsonObject, field: String, expected: String, label: String) {
    if (value.requiredString(field, label) != expected) evidenceFail("$label.$field differs from the fixed value")
}

private fun requireExactInteger(value: JsonObject, field: String, expected: Long, label: String) {
    if (value.requiredLong(field, label) != expected) evidenceFail("$label.$field differs from the fixed value")
}

private fun requireIdentifier(value: String, label: String) {
    if (value.length > 128 || !IDENTIFIER.matches(value)) evidenceFail("$label is not a canonical identifier")
}

private fun requireSortedUnique(values: List<String>, label: String) {
    if (values != values.toSortedSet().toList()) evidenceFail("$label must be sorted and unique")
}

private fun evidenceFail(message: String, cause: Throwable? = null): Nothing =
    throw LlvmBehaviorReferenceEvidenceException(message, cause)

private const val AUTHENTICATED_FIELD_COUNT = 11
private const val MAXIMUM_EXECUTABLE_BYTES = 128L * 1024 * 1024
private const val EXPECTED_CORPUS_ID = "clang-22-1-6-driver-behavior"
private const val EXPECTED_MATRIX_ID = "clang-22.1.6-diagnostics-v1"
private const val EXPECTED_MANIFEST_ORACLE_ID = "clang-driver-22.1.6"
private const val EXPECTED_LLVM_VERSION = "22.1.6"
private const val EXPECTED_LLVM_SOURCE_REVISION = "fc4aad7b5db3fff421df9a9637605b9ca5667881"
private const val EXPECTED_STRIPPED_PATH = "artifacts/clang-driver.stripped"
private const val EXPECTED_SANDBOX_SHA256 = "e4991450d10843e2fce6bc430a8876682fd831b3c4768b7fb757d7ee158638fa"
private const val EXPECTED_CORPUS_SHA256 = "acaa7b33c390b2c9fde15b4e21b0a899ffff62fe98ce22226866272b4efe8d5b"
private const val EXPECTED_REPORT_SHA256 = "e9595bfd941c406d2c8fff618986e60dc0b810f1c384848b3ba540020ca00a6f"
private const val EXPECTED_MATRIX_FILE_SHA256 = "9e3b3223e014de49e0df50892556ae4649f819d5571751378ed9bfd12d684b2d"
private const val EXPECTED_MANIFEST_SHA256 = "5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40"
private const val EXPECTED_ISOLATION =
    "network-none-readonly-root-cap-drop-all-no-new-privileges-pid-ipc-private-cgroup-bounds"
private const val EXPECTED_STDOUT_LIMIT = 1024 * 1024
private const val EXPECTED_STDERR_LIMIT = 1024 * 1024
private const val EXPECTED_ARTIFACT_LIMIT = 16 * 1024 * 1024
private const val EXPECTED_FILE_BYTES_LIMIT = 16 * 1024 * 1024
private const val EXPECTED_WORKSPACE_BYTES_LIMIT = 32 * 1024 * 1024
private const val EXPECTED_WORKSPACE_ENTRIES_LIMIT = 1024

private val EXPECTED_DIRECTORIES = listOf("include", "quoted", "system", "tmp")
private val EXPECTED_BASE_ENVIRONMENT = JsonObject(
    linkedMapOf(
        "clearInherited" to JsonPrimitive(true),
        "variables" to JsonObject(
            linkedMapOf(
                "HOME" to JsonPrimitive("/nonexistent"),
                "LANG" to JsonPrimitive("C"),
                "LC_ALL" to JsonPrimitive("C"),
                "PATH" to JsonPrimitive("/usr/bin:/bin"),
                "SOURCE_DATE_EPOCH" to JsonPrimitive("1779182222"),
                "TMPDIR" to JsonPrimitive("/workspace/tmp"),
                "TZ" to JsonPrimitive("UTC"),
            ),
        ),
    ),
)
private val EXPECTED_EXECUTION_LIMITS = JsonObject(
    linkedMapOf(
        "artifactBytes" to JsonPrimitive(EXPECTED_ARTIFACT_LIMIT),
        "cpuSeconds" to JsonPrimitive(10),
        "fileBytes" to JsonPrimitive(EXPECTED_FILE_BYTES_LIMIT),
        "memoryBytes" to JsonPrimitive(1024L * 1024 * 1024),
        "openFiles" to JsonPrimitive(128),
        "processes" to JsonPrimitive(128),
        "stderrBytes" to JsonPrimitive(EXPECTED_STDERR_LIMIT),
        "stdoutBytes" to JsonPrimitive(EXPECTED_STDOUT_LIMIT),
        "timeoutMilliseconds" to JsonPrimitive(10_000),
        "workspaceBytes" to JsonPrimitive(EXPECTED_WORKSPACE_BYTES_LIMIT),
        "workspaceEntries" to JsonPrimitive(EXPECTED_WORKSPACE_ENTRIES_LIMIT),
    ),
)
private val EXPECTED_DIAGNOSTIC_POLICY = JsonObject(
    linkedMapOf(
        "forbiddenNormalizations" to JsonArray(
            listOf(
                "diagnostic-wording",
                "identifier",
                "line-column",
                "option-name",
                "ordering",
                "severity",
            ).map(::JsonPrimitive),
        ),
        "locale" to JsonPrimitive("C"),
        "pathNormalization" to JsonPrimitive("only exact authenticated workspace/oracle roots"),
        "terminalWidth" to JsonPrimitive("non-tty-no-width"),
    ),
)
private val EXPECTED_CASE_IDS = Collections.unmodifiableList(
    listOf(
        "assemble-invalid",
        "assemble-valid",
        "compile-c-standard",
        "compile-cxx-standard",
        "compile-file",
        "compile-stdin",
        "diagnostic-color-always",
        "diagnostic-color-never",
        "diagnostic-error-limit",
        "diagnostic-fixit",
        "diagnostic-invalid-option",
        "diagnostic-missing-include",
        "diagnostic-syntax",
        "diagnostic-template-backtrace",
        "diagnostic-warning-option",
        "driver-missing-linker",
        "driver-print-commands",
        "emit-assembly",
        "emit-llvm-ir",
        "help-driver",
        "include-cycle-guarded",
        "include-framework-order",
        "include-search-order",
        "include-trace",
        "link-program",
        "link-undefined-symbol",
        "metadata-resource-dir",
        "metadata-target",
        "metadata-version",
        "modules-flag-supported",
        "objective-c-syntax",
        "pch-reuse-valid",
        "pch-reuse-wrong-target",
        "precompile-header",
        "preprocess-dependencies",
        "preprocess-file",
        "preprocess-macro-state",
        "preprocess-malformed-macro",
        "preprocess-pragma-once",
        "preprocess-stdin",
        "response-file",
        "response-file-nested",
        "response-file-quoted-paths",
        "response-file-recursion",
        "response-file-stdin",
        "target-i386-object",
        "target-unsupported-aarch64",
        "target-x86-macros",
    ),
)
private val EXPECTED_DIAGNOSTIC_OWNERS = Collections.unmodifiableMap(
    linkedMapOf(
        "assemble-invalid" to "clang-integrated-assembler",
        "diagnostic-color-always" to "clang-diagnostics-renderer",
        "diagnostic-color-never" to "clang-diagnostics-renderer",
        "diagnostic-error-limit" to "clang-diagnostics-engine",
        "diagnostic-fixit" to "clang-parser",
        "diagnostic-invalid-option" to "clang-driver-options",
        "diagnostic-missing-include" to "clang-lex",
        "diagnostic-syntax" to "clang-parser",
        "diagnostic-template-backtrace" to "clang-sema",
        "diagnostic-warning-option" to "clang-sema",
        "driver-missing-linker" to "clang-driver-toolchain",
        "link-undefined-symbol" to "clang-driver-linker",
        "pch-reuse-wrong-target" to "clang-serialization",
        "preprocess-malformed-macro" to "clang-lex",
        "response-file-recursion" to "clang-driver-response-files",
        "target-unsupported-aarch64" to "clang-driver-targets",
    ),
)
private val EXPECTED_DIAGNOSTIC_IDS = EXPECTED_DIAGNOSTIC_OWNERS.keys.sorted()
private val MISMATCH_FIELDS = setOf("exitCode", "order", "stderr", "stdout")
private val REQUIRED_SECURITY_OPTIONS = setOf(
    "name=cgroupns",
    "name=rootless",
    "name=seccomp,profile=builtin",
)
private val EXECUTION_LIMIT_FIELDS = setOf(
    "timeoutMilliseconds",
    "stdoutBytes",
    "stderrBytes",
    "artifactBytes",
    "memoryBytes",
    "fileBytes",
    "openFiles",
    "processes",
    "cpuSeconds",
    "workspaceBytes",
    "workspaceEntries",
)
private val ENGINE_FIELDS = setOf(
    "product",
    "serverVersion",
    "serverCommit",
    "apiVersion",
    "operatingSystem",
    "architecture",
    "kernelVersion",
    "componentsSha256",
    "cgroupVersion",
    "cgroupDriver",
    "storageDriver",
    "securityOptions",
    "containerRuntime",
    "containerRuntimePath",
    "containerRuntimeVersion",
    "containerRuntimeCommit",
    "containerRuntimeFeaturesSha256",
    "volumePlugin",
)
private val FORBIDDEN_ENVIRONMENT_NAMES = setOf(
    "BASH_ENV",
    "CDPATH",
    "ENV",
    "GCONV_PATH",
    "IFS",
    "LOCPATH",
    "NLSPATH",
    "PYTHONHOME",
    "PYTHONPATH",
    "RUBYOPT",
    "SHELLOPTS",
)
private val FORBIDDEN_ENVIRONMENT_PREFIXES = listOf("GLIBC_", "LD_", "MALLOC_", "PERL5")
private val SHA256 = Regex("[0-9a-f]{64}")
private val IMAGE_DIGEST = Regex("sha256:[0-9a-f]{64}")
private val PLATFORM = Regex("[a-z0-9]+/[a-z0-9_]+")
private val API_VERSION = Regex("[0-9]+\\.[0-9]+")
private val NUMERIC_USER = Regex("[1-9][0-9]*:[1-9][0-9]*")
private val IDENTIFIER = Regex("[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
private val ENVIRONMENT_NAME = Regex("[A-Za-z_][A-Za-z0-9_]*")
private val MODE = Regex("0o[4-7][0-7]{2}")
private val INTEGER = Regex("-?(?:0|[1-9][0-9]*)")
private val PLACEHOLDER = Regex("\\{([^{}]+)}")
