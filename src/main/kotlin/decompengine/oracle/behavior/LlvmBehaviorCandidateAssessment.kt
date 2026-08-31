package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.util.Base64
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

class LlvmBehaviorCandidateAssessmentException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * A derived diagnostic for caller-supplied candidate observations. It is deliberately not oracle
 * evidence, a score, or a release decision. All byte arrays and collections are defensive views.
 */
sealed interface LlvmBehaviorCandidateAssessment {
    val authority: String
    val releaseEligible: Boolean
    val referenceCorpusId: String
    val referenceCorpusSha256: String
    val referenceReportSha256: String
    val referenceDiagnosticMatrixSha256: String
    val referenceDiagnosticMatrixSelfSha256: String
    val referenceArtifactManifestSha256: String
    val referenceSandboxSha256: String
    val candidateExecutableBytes: Long
    val candidateExecutableSha256: String
    val observationSha256: String
    val ownershipSha256: String
    val observedCases: Int
    val notRunCases: Int
    val infrastructureFailedCases: Int
    val matchingObservedCases: Int
    val mismatchingObservedCases: Int
    val mismatches: List<LlvmBehaviorCandidateMismatch>
    val assessmentSha256: String
    val operatorSummary: String
    val canonicalBytes: ByteArray
}

/** An immutable mismatch identity derived only by the fixed comparison implementation. */
sealed interface LlvmBehaviorCandidateMismatch {
    val mismatchId: String
    val caseId: String
    val kind: String
    val artifactPath: String?
    val ownerSubsystem: String
    val failureCode: String?
}

/**
 * Fixed raw-path one-shot entry point. It accepts no parsed document, claimed digest, policy,
 * ownership map, runner, clock, verdict, mismatch identity, or prevalidated capability.
 */
object LlvmBehaviorCandidateAssessmentVerifier {
    fun assess(
        corpusPath: Path,
        referenceReportPath: Path,
        diagnosticMatrixPath: Path,
        artifactManifestPath: Path,
        candidateExecutablePath: Path,
        candidateObservationsPath: Path,
        ownershipPath: Path,
    ): LlvmBehaviorCandidateAssessment = DerivedAssessment(
        corpusPath,
        referenceReportPath,
        diagnosticMatrixPath,
        artifactManifestPath,
        candidateExecutablePath,
        candidateObservationsPath,
        ownershipPath,
    )

    /*
     * Even reflective JVM construction can provide only the same seven raw Paths. Construction
     * invokes the complete production authentication and derivation; there is no parsed-state or
     * claimed-result constructor.
     */
    private class DerivedAssessment(
        corpusPath: Path,
        referenceReportPath: Path,
        diagnosticMatrixPath: Path,
        artifactManifestPath: Path,
        candidateExecutablePath: Path,
        candidateObservationsPath: Path,
        ownershipPath: Path,
    ) : LlvmBehaviorCandidateAssessment {
        private val storedCanonicalBytes: ByteArray

        override val authority: String
        override val releaseEligible: Boolean
        override val referenceCorpusId: String
        override val referenceCorpusSha256: String
        override val referenceReportSha256: String
        override val referenceDiagnosticMatrixSha256: String
        override val referenceDiagnosticMatrixSelfSha256: String
        override val referenceArtifactManifestSha256: String
        override val referenceSandboxSha256: String
        override val candidateExecutableBytes: Long
        override val candidateExecutableSha256: String
        override val observationSha256: String
        override val ownershipSha256: String
        override val observedCases: Int
        override val notRunCases: Int
        override val infrastructureFailedCases: Int
        override val matchingObservedCases: Int
        override val mismatchingObservedCases: Int
        override val mismatches: List<LlvmBehaviorCandidateMismatch>
        override val assessmentSha256: String
        override val operatorSummary: String

        override val canonicalBytes: ByteArray
            get() = storedCanonicalBytes.copyOf()

        init {
            val derived = deriveAssessment(
                corpusPath,
                referenceReportPath,
                diagnosticMatrixPath,
                artifactManifestPath,
                candidateExecutablePath,
                candidateObservationsPath,
                ownershipPath,
            )
            authority = NON_AUTHORITY
            releaseEligible = false
            referenceCorpusId = derived.referenceCorpusId
            referenceCorpusSha256 = derived.referenceCorpusSha256
            referenceReportSha256 = derived.referenceReportSha256
            referenceDiagnosticMatrixSha256 = derived.referenceDiagnosticMatrixSha256
            referenceDiagnosticMatrixSelfSha256 = derived.referenceDiagnosticMatrixSelfSha256
            referenceArtifactManifestSha256 = derived.referenceArtifactManifestSha256
            referenceSandboxSha256 = derived.referenceSandboxSha256
            candidateExecutableBytes = derived.candidateExecutable.size
            candidateExecutableSha256 = derived.candidateExecutable.sha256
            observationSha256 = derived.observationSha256
            ownershipSha256 = derived.ownershipSha256
            observedCases = derived.observedCases
            notRunCases = derived.notRunCases
            infrastructureFailedCases = derived.infrastructureFailedCases
            matchingObservedCases = derived.matchingObservedCases
            mismatchingObservedCases = derived.mismatchingObservedCases
            mismatches = Collections.unmodifiableList(
                derived.mismatches.map(::ImmutableMismatch),
            )
            storedCanonicalBytes = derived.canonicalBytes.copyOf()
            assessmentSha256 = OracleArtifacts.sha256(storedCanonicalBytes)
            operatorSummary = buildOperatorSummary(
                observedCases,
                matchingObservedCases,
                mismatchingObservedCases,
                notRunCases,
                infrastructureFailedCases,
                mismatches.size,
                assessmentSha256,
            )
        }
    }

    private class ImmutableMismatch(source: MismatchRecord) : LlvmBehaviorCandidateMismatch {
        override val mismatchId: String = source.mismatchId
        override val caseId: String = source.caseId
        override val kind: String = source.kind.wire
        override val artifactPath: String? = source.artifactPath
        override val ownerSubsystem: String = source.ownerSubsystem
        override val failureCode: String? = source.failureCode
    }
}

/** Closed kinds used in the length-framed non-diagnostic mismatch identity domain. */
internal enum class LlvmBehaviorCandidateMismatchKind(val wire: String) {
    ARTIFACT_CONTENT("artifact-content"),
    ARTIFACT_MODE("artifact-mode"),
    ARTIFACT_PRESENCE("artifact-presence"),
    EXECUTION("execution"),
    EXIT_CODE("exitCode"),
    STDERR("stderr"),
    STDOUT("stdout"),
    UNEXPECTED_ARTIFACT("unexpected-artifact"),
}

/**
 * Deterministic identity primitive exposed internally for frozen framing/collision tests. This is
 * not an assessment factory and confers no oracle or release authority.
 */
internal fun llvmBehaviorCandidateMismatchId(
    referenceCorpusSha256: String,
    caseId: String,
    kind: LlvmBehaviorCandidateMismatchKind,
    artifactPath: String? = null,
): String {
    require(SHA256.matches(referenceCorpusSha256)) { "reference corpus digest is invalid" }
    require(IDENTIFIER.matches(caseId)) { "case ID is invalid" }
    val requiresPath = kind in ARTIFACT_KINDS
    require(requiresPath == (artifactPath != null)) { "artifact path presence differs from mismatch kind" }
    artifactPath?.let(::requireCandidateRelativePath)

    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(MISMATCH_ID_DOMAIN.toByteArray(StandardCharsets.UTF_8))
    val components = ArrayList<String>(4)
    components += referenceCorpusSha256
    components += caseId
    components += kind.wire
    if (artifactPath != null) components += artifactPath
    components.forEach { component ->
        val bytes = component.toByteArray(StandardCharsets.UTF_8)
        require(bytes.size.toLong() <= 0xffff_ffffL) { "mismatch identity component is too large" }
        digest.update(
            ByteBuffer.allocate(4)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(bytes.size)
                .array(),
        )
        digest.update(bytes)
    }
    return "clang-behavior-${digest.digest().toHex().take(32)}"
}

private fun deriveAssessment(
    corpusPath: Path,
    referenceReportPath: Path,
    diagnosticMatrixPath: Path,
    artifactManifestPath: Path,
    candidateExecutablePath: Path,
    candidateObservationsPath: Path,
    ownershipPath: Path,
): DerivedFields {
    try {
        val reference = LlvmBehaviorReferenceEvidenceVerifier.verify(
            corpusPath,
            referenceReportPath,
            diagnosticMatrixPath,
            artifactManifestPath,
        )

        val referenceReportSnapshot = OracleArtifacts.read(
            referenceReportPath,
            OracleArtifactLimits(MAXIMUM_REFERENCE_REPORT_BYTES),
        )
        if (referenceReportSnapshot.sha256 != reference.reportSha256) {
            candidateFail("reference report changed after fixed reference authentication")
        }
        val referenceReport = parseCandidateCanonicalObject(
            referenceReportSnapshot.bytes,
            MAXIMUM_REFERENCE_REPORT_BYTES,
            "reference behavior report",
        )
        OracleSchemas.validate("behavior-corpus-report", referenceReport)

        val candidateExecutable = snapshotCandidateExecutable(candidateExecutablePath)
        val observationSnapshot = OracleArtifacts.read(
            candidateObservationsPath,
            OracleArtifactLimits(MAXIMUM_OBSERVATION_BYTES),
        )
        val ownershipSnapshot = OracleArtifacts.read(
            ownershipPath,
            OracleArtifactLimits(MAXIMUM_OWNERSHIP_BYTES),
        )
        if (ownershipSnapshot.sha256 != EXPECTED_OWNERSHIP_SHA256) {
            candidateFail("behavior-case ownership bytes differ from the reviewed artifact")
        }

        val observations = parseCandidateCanonicalObject(
            observationSnapshot.bytes,
            MAXIMUM_OBSERVATION_BYTES,
            "candidate observations",
        )
        val ownership = parseCandidateCanonicalObject(
            ownershipSnapshot.bytes,
            MAXIMUM_OWNERSHIP_BYTES,
            "behavior-case ownership",
        )
        OracleSchemas.validate("llvm-behavior-candidate-observations", observations)
        OracleSchemas.validate("llvm-behavior-case-ownership", ownership)

        val owners = validateOwnership(ownership, reference)
        val comparison = compareObservations(
            observations,
            referenceReport,
            reference,
            candidateExecutable,
            owners,
        )

        val canonical = renderAssessment(
            reference,
            candidateExecutable,
            observationSnapshot.sha256,
            ownershipSnapshot.sha256,
            comparison,
        )

        // Terminal acceptance reauthenticates both reference authority and every caller input.
        val terminalReference = LlvmBehaviorReferenceEvidenceVerifier.verify(
            corpusPath,
            referenceReportPath,
            diagnosticMatrixPath,
            artifactManifestPath,
        )
        if (!sameReference(reference, terminalReference)) {
            candidateFail("fixed reference evidence changed before terminal assessment acceptance")
        }
        reauthenticateArtifact(
            referenceReportPath,
            referenceReportSnapshot.size,
            referenceReportSnapshot.sha256,
            MAXIMUM_REFERENCE_REPORT_BYTES,
            "reference report",
        )
        reauthenticateArtifact(
            candidateObservationsPath,
            observationSnapshot.size,
            observationSnapshot.sha256,
            MAXIMUM_OBSERVATION_BYTES,
            "candidate observations",
        )
        reauthenticateArtifact(
            ownershipPath,
            ownershipSnapshot.size,
            ownershipSnapshot.sha256,
            MAXIMUM_OWNERSHIP_BYTES,
            "behavior-case ownership",
        )
        val terminalExecutable = snapshotCandidateExecutable(candidateExecutablePath)
        if (terminalExecutable != candidateExecutable) {
            candidateFail("candidate executable changed before terminal assessment acceptance")
        }

        return DerivedFields(
            reference.corpusId,
            reference.corpusSha256,
            reference.reportSha256,
            reference.diagnosticMatrixSha256,
            reference.diagnosticMatrixSelfSha256,
            reference.artifactManifestSha256,
            reference.sandboxSha256,
            candidateExecutable,
            observationSnapshot.sha256,
            ownershipSnapshot.sha256,
            comparison.observedCases,
            comparison.notRunCases,
            comparison.infrastructureFailedCases,
            comparison.matchingObservedCases,
            comparison.mismatchingObservedCases,
            comparison.mismatches,
            canonical,
        )
    } catch (failure: LlvmBehaviorCandidateAssessmentException) {
        throw failure
    } catch (failure: Exception) {
        throw LlvmBehaviorCandidateAssessmentException(
            "LLVM candidate observation assessment failed: " +
                (failure.message ?: failure.javaClass.simpleName),
            failure,
        )
    }
}

private fun validateOwnership(
    ownership: JsonObject,
    reference: LlvmBehaviorReferenceEvidence,
): Map<String, String> {
    ownership.candidateRequireFields(setOf("schemaVersion", "id", "reference", "cases"), "ownership")
    ownership.candidateRequireInteger("schemaVersion", 1, 1, "ownership")
    ownership.candidateRequireString("id", EXPECTED_OWNERSHIP_ID, "ownership")
    val identity = ownership.candidateObject("reference", "ownership")
    identity.candidateRequireFields(setOf("corpusId", "corpusSha256"), "ownership reference")
    identity.candidateRequireString("corpusId", reference.corpusId, "ownership reference")
    identity.candidateRequireString("corpusSha256", reference.corpusSha256, "ownership reference")

    val cases = ownership.candidateArray("cases", "ownership")
    if (cases.size != reference.caseIds.size) candidateFail("ownership must contain exactly 48 cases")
    val owners = LinkedHashMap<String, String>(cases.size)
    cases.forEachIndexed { index, raw ->
        val label = "ownership case[$index]"
        val item = raw.candidateObject(label)
        item.candidateRequireFields(setOf("id", "ownerSubsystem"), label)
        val caseId = item.candidateString("id", label)
        val owner = item.candidateString("ownerSubsystem", label)
        requireCandidateIdentifier(caseId, "$label ID")
        requireCandidateIdentifier(owner, "$label owner")
        if (caseId != reference.caseIds[index]) candidateFail("ownership case order or membership differs")
        if (owners.put(caseId, owner) != null) candidateFail("ownership contains a duplicate case")
    }
    reference.diagnosticOwners.forEach { (caseId, expectedOwner) ->
        if (owners[caseId] != expectedOwner) {
            candidateFail("ownership differs from authenticated diagnostic ownership for $caseId")
        }
    }
    if (owners.keys.toList() != reference.caseIds) candidateFail("ownership has no exact 48-case map")
    return Collections.unmodifiableMap(owners)
}

private fun compareObservations(
    observations: JsonObject,
    referenceReport: JsonObject,
    reference: LlvmBehaviorReferenceEvidence,
    executable: CandidateExecutableSnapshot,
    owners: Map<String, String>,
): ComparisonResult {
    observations.candidateRequireFields(setOf("schemaVersion", "reference", "candidateExecutable", "cases"), "observations")
    observations.candidateRequireInteger("schemaVersion", 1, 1, "observations")

    val referenceIdentity = observations.candidateObject("reference", "observations")
    referenceIdentity.candidateRequireFields(
        setOf(
            "corpusId",
            "corpusSha256",
            "reportSha256",
            "diagnosticMatrixSha256",
            "diagnosticMatrixSelfSha256",
            "artifactManifestSha256",
            "sandboxSha256",
        ),
        "observation reference",
    )
    referenceIdentity.candidateRequireString("corpusId", reference.corpusId, "observation reference")
    referenceIdentity.candidateRequireString("corpusSha256", reference.corpusSha256, "observation reference")
    referenceIdentity.candidateRequireString("reportSha256", reference.reportSha256, "observation reference")
    referenceIdentity.candidateRequireString(
        "diagnosticMatrixSha256",
        reference.diagnosticMatrixSha256,
        "observation reference",
    )
    referenceIdentity.candidateRequireString(
        "diagnosticMatrixSelfSha256",
        reference.diagnosticMatrixSelfSha256,
        "observation reference",
    )
    referenceIdentity.candidateRequireString(
        "artifactManifestSha256",
        reference.artifactManifestSha256,
        "observation reference",
    )
    referenceIdentity.candidateRequireString("sandboxSha256", reference.sandboxSha256, "observation reference")

    val executableIdentity = observations.candidateObject("candidateExecutable", "observations")
    executableIdentity.candidateRequireFields(setOf("bytes", "sha256"), "candidate executable identity")
    if (executableIdentity.candidateLong("bytes", "candidate executable identity") != executable.size ||
        executableIdentity.candidateString("sha256", "candidate executable identity") != executable.sha256
    ) {
        candidateFail("candidate observations do not bind the exact candidate executable bytes")
    }

    val referenceCases = referenceReport.candidateArray("cases", "reference report")
    val candidateCases = observations.candidateArray("cases", "observations")
    if (referenceCases.size != reference.caseIds.size || candidateCases.size != reference.caseIds.size) {
        candidateFail("reference and candidate case denominators must both be exactly 48")
    }

    var retainedBytes = 0L
    var observed = 0
    var notRun = 0
    var infrastructureFailed = 0
    var matchingObserved = 0
    var mismatchingObserved = 0
    val mismatches = ArrayList<MismatchRecord>()

    candidateCases.forEachIndexed { index, rawCandidateCase ->
        val caseId = reference.caseIds[index]
        val owner = owners[caseId] ?: candidateFail("ownership has no exact owner for $caseId")
        val candidateCase = rawCandidateCase.candidateObject("candidate case[$index]")
        val referenceCase = referenceCases[index].candidateObject("reference case[$index]")
        if (referenceCase.candidateString("id", "reference case[$index]") != caseId ||
            candidateCase.candidateString("id", "candidate case[$index]") != caseId
        ) {
            candidateFail("candidate case denominator membership or order differs at index $index")
        }
        when (val status = candidateCase.candidateString("status", "candidate case[$index]")) {
            "observed" -> {
                observed++
                val before = mismatches.size
                retainedBytes = compareObservedCase(
                    caseId,
                    owner,
                    referenceCase,
                    candidateCase,
                    retainedBytes,
                    mismatches,
                )
                if (mismatches.size == before) matchingObserved++ else mismatchingObserved++
            }
            "not-run" -> {
                notRun++
                candidateCase.candidateRequireFields(setOf("id", "status", "failureCode"), "candidate case[$index]")
                val failureCode = candidateCase.candidateString("failureCode", "candidate case[$index]")
                if (failureCode !in NOT_RUN_FAILURE_CODES) candidateFail("not-run failure code is not closed")
                mismatches += mismatch(
                    reference.corpusSha256,
                    caseId,
                    LlvmBehaviorCandidateMismatchKind.EXECUTION,
                    null,
                    owner,
                    failureCode,
                    diagnostic = false,
                )
            }
            "infrastructure-failed" -> {
                infrastructureFailed++
                candidateCase.candidateRequireFields(setOf("id", "status", "failureCode"), "candidate case[$index]")
                val failureCode = candidateCase.candidateString("failureCode", "candidate case[$index]")
                if (failureCode !in INFRASTRUCTURE_FAILURE_CODES) {
                    candidateFail("infrastructure failure code is not closed")
                }
                mismatches += mismatch(
                    reference.corpusSha256,
                    caseId,
                    LlvmBehaviorCandidateMismatchKind.EXECUTION,
                    null,
                    owner,
                    failureCode,
                    diagnostic = false,
                )
            }
            else -> candidateFail("candidate case[$index] has unsupported status $status")
        }
    }

    if (observed + notRun + infrastructureFailed != reference.caseIds.size ||
        matchingObserved + mismatchingObserved != observed
    ) {
        candidateFail("derived candidate case counts are inconsistent")
    }
    val sorted = mismatches.sortedWith(
        compareBy<MismatchRecord> { it.mismatchId }
            .thenBy { it.caseId }
            .thenBy { it.kind.wire }
            .thenBy { it.artifactPath ?: "" },
    )
    val identities = HashSet<String>(sorted.size)
    sorted.forEach { record ->
        if (!identities.add(record.mismatchId)) {
            candidateFail("derived mismatch identity collision: ${record.mismatchId}")
        }
    }
    return ComparisonResult(
        observed,
        notRun,
        infrastructureFailed,
        matchingObserved,
        mismatchingObserved,
        Collections.unmodifiableList(ArrayList(sorted)),
    )
}

private fun compareObservedCase(
    caseId: String,
    owner: String,
    referenceCase: JsonObject,
    candidateCase: JsonObject,
    initialRetainedBytes: Long,
    mismatches: MutableList<MismatchRecord>,
): Long {
    candidateCase.candidateRequireFields(
        setOf("id", "status", "exitCode", "stdout", "stderr", "artifacts"),
        "candidate observed case $caseId",
    )
    var retainedBytes = initialRetainedBytes
    val diagnostic = caseId in DIAGNOSTIC_CASE_IDS
    val candidateExit = candidateCase.candidateRequireInteger("exitCode", 0, 255, "candidate case $caseId")
    val referenceExit = referenceCase.candidateRequireInteger("exitCode", 0, 255, "reference case $caseId")
    if (candidateExit != referenceExit) {
        mismatches += mismatch(
            EXPECTED_REFERENCE_CORPUS_SHA256,
            caseId,
            LlvmBehaviorCandidateMismatchKind.EXIT_CODE,
            null,
            owner,
            null,
            diagnostic,
        )
    }

    listOf(
        "stdout" to LlvmBehaviorCandidateMismatchKind.STDOUT,
        "stderr" to LlvmBehaviorCandidateMismatchKind.STDERR,
    ).forEach { (field, kind) ->
        val candidateBlob = validateCandidateBlob(
            candidateCase.candidateObject(field, "candidate case $caseId"),
            "candidate case $caseId $field",
        )
        retainedBytes = candidateCheckedAdd(retainedBytes, candidateBlob.content.size.toLong(), "candidate retained bytes")
        if (retainedBytes > MAXIMUM_RETAINED_OBSERVATION_BYTES) {
            candidateFail("candidate observations exceed the aggregate decoded-byte limit")
        }
        val referenceBlob = validateReferenceBlob(
            referenceCase.candidateObject(field, "reference case $caseId"),
            "reference case $caseId $field",
        )
        if (!MessageDigest.isEqual(candidateBlob.content, referenceBlob.content)) {
            mismatches += mismatch(
                EXPECTED_REFERENCE_CORPUS_SHA256,
                caseId,
                kind,
                null,
                owner,
                null,
                diagnostic,
            )
        }
    }

    val referenceArtifacts = referenceCase.candidateArray("artifacts", "reference case $caseId")
    val candidateArtifacts = candidateCase.candidateArray("artifacts", "candidate case $caseId")
    if (referenceArtifacts.size > MAXIMUM_ARTIFACTS_PER_CASE || candidateArtifacts.size > MAXIMUM_ARTIFACTS_PER_CASE) {
        candidateFail("candidate case $caseId exceeds the artifact-count bound")
    }
    val candidateByPath = LinkedHashMap<String, CandidateArtifact>(candidateArtifacts.size)
    candidateArtifacts.forEachIndexed { index, rawCandidateArtifact ->
        val candidateArtifact = rawCandidateArtifact.candidateObject("candidate artifact $caseId[$index]")
        val candidatePath = candidateArtifact.candidateString("path", "candidate artifact $caseId[$index]")
        requireCandidateRelativePath(candidatePath)
        val candidatePresent = candidateArtifact.candidateBoolean("present", "candidate artifact $caseId[$index]")
        val parsed = if (candidatePresent) {
            candidateArtifact.candidateRequireFields(
                setOf("path", "present", "bytes", "sha256", "base64", "mode"),
                "candidate artifact $caseId[$index]",
            )
            val candidateBlob = validateCandidateBlob(
                candidateArtifact,
                "candidate artifact $caseId[$index]",
                setOf("path", "present", "mode"),
            )
            retainedBytes = candidateCheckedAdd(retainedBytes, candidateBlob.content.size.toLong(), "candidate retained bytes")
            if (retainedBytes > MAXIMUM_RETAINED_OBSERVATION_BYTES) {
                candidateFail("candidate observations exceed the aggregate decoded-byte limit")
            }
            val candidateMode = candidateArtifact.candidateString("mode", "candidate artifact $caseId[$index]")
            if (!MODE.matches(candidateMode)) candidateFail("candidate artifact mode is invalid")
            CandidateArtifact(true, candidateBlob.content, candidateMode)
        } else {
            validateAbsentArtifact(candidateArtifact, "candidate artifact $caseId[$index]")
            CandidateArtifact(false, null, null)
        }
        if (candidateByPath.put(candidatePath, parsed) != null) {
            candidateFail("candidate case $caseId contains a duplicate artifact path")
        }
    }
    if (candidateByPath.keys.toList() != candidateByPath.keys.sorted()) {
        candidateFail("candidate case $caseId artifact paths must be sorted")
    }

    referenceArtifacts.forEachIndexed { index, rawReferenceArtifact ->
        val referenceArtifact = rawReferenceArtifact.candidateObject("reference artifact $caseId[$index]")
        val referencePath = referenceArtifact.candidateString("path", "reference artifact $caseId[$index]")
        requireCandidateRelativePath(referencePath)
        val referencePresent = referenceArtifact.candidateBoolean("present", "reference artifact $caseId[$index]")
        val candidate = candidateByPath.remove(referencePath)
        val candidatePresent = candidate?.present ?: false
        if (candidatePresent != referencePresent) {
            mismatches += mismatch(
                EXPECTED_REFERENCE_CORPUS_SHA256,
                caseId,
                LlvmBehaviorCandidateMismatchKind.ARTIFACT_PRESENCE,
                referencePath,
                owner,
                null,
                diagnostic = false,
            )
        }
        if (candidatePresent && referencePresent) {
            val referenceBlob = validateReferenceBlob(
                referenceArtifact,
                "reference artifact $caseId[$index]",
                setOf("path", "present", "mode"),
            )
            if (!MessageDigest.isEqual(candidate.content!!, referenceBlob.content)) {
                mismatches += mismatch(
                    EXPECTED_REFERENCE_CORPUS_SHA256,
                    caseId,
                    LlvmBehaviorCandidateMismatchKind.ARTIFACT_CONTENT,
                    referencePath,
                    owner,
                    null,
                    diagnostic = false,
                )
            }
            val referenceMode = referenceArtifact.candidateString("mode", "reference artifact $caseId[$index]")
            if (candidate.mode != referenceMode) {
                mismatches += mismatch(
                    EXPECTED_REFERENCE_CORPUS_SHA256,
                    caseId,
                    LlvmBehaviorCandidateMismatchKind.ARTIFACT_MODE,
                    referencePath,
                    owner,
                    null,
                    diagnostic = false,
                )
            }
        }
    }
    candidateByPath.forEach { (unexpectedPath, artifact) ->
        if (!artifact.present) {
            candidateFail("candidate case $caseId declares an unobserved unexpected artifact")
        }
        mismatches += mismatch(
            EXPECTED_REFERENCE_CORPUS_SHA256,
            caseId,
            LlvmBehaviorCandidateMismatchKind.UNEXPECTED_ARTIFACT,
            unexpectedPath,
            owner,
            null,
            diagnostic = false,
        )
    }
    return retainedBytes
}

private fun validateCandidateBlob(
    value: JsonObject,
    label: String,
    extraFields: Set<String> = emptySet(),
): ValidatedBlob {
    value.candidateRequireFields(setOf("bytes", "sha256", "base64") + extraFields, label)
    val declaredBytes = value.candidateRequireInteger("bytes", 0, MAXIMUM_DECODED_BLOB_BYTES.toLong(), label).toInt()
    val digest = value.candidateString("sha256", label)
    if (!SHA256.matches(digest)) candidateFail("$label digest is invalid")
    val base64 = value.candidateString("base64", label)
    val expectedEncodedLength = ((declaredBytes.toLong() + 2L) / 3L) * 4L
    if (expectedEncodedLength > MAXIMUM_BASE64_CHARACTERS || base64.length.toLong() != expectedEncodedLength) {
        candidateFail("$label base64 length differs from its declared byte length")
    }
    if (!BASE64.matches(base64)) candidateFail("$label base64 alphabet or padding is invalid")
    val decoded = try {
        Base64.getDecoder().decode(base64)
    } catch (failure: IllegalArgumentException) {
        candidateFail("$label base64 is invalid", failure)
    }
    if (decoded.size != declaredBytes || Base64.getEncoder().encodeToString(decoded) != base64) {
        candidateFail("$label base64 is not canonical or does not match its declared length")
    }
    if (OracleArtifacts.sha256(decoded) != digest) candidateFail("$label digest differs from decoded bytes")
    return ValidatedBlob(decoded)
}

private fun validateReferenceBlob(
    value: JsonObject,
    label: String,
    extraFields: Set<String> = emptySet(),
): ValidatedBlob {
    val normalizations = if ("normalizations" in value) setOf("normalizations") else emptySet()
    if (normalizations.isNotEmpty()) {
        val array = value.candidateArray("normalizations", label)
        if (array.isNotEmpty()) candidateFail("authenticated reference unexpectedly declares a normalization")
    }
    val stripped = JsonObject(value.filterKeys { it != "normalizations" })
    return validateCandidateBlob(stripped, label, extraFields)
}

private fun validateAbsentArtifact(value: JsonObject, label: String) {
    value.candidateRequireFields(setOf("path", "present", "bytes", "sha256", "base64", "mode"), label)
    listOf("bytes", "sha256", "base64", "mode").forEach { field ->
        if (value[field] != JsonNull) candidateFail("$label absent field $field must be null")
    }
}

private fun mismatch(
    corpusSha256: String,
    caseId: String,
    kind: LlvmBehaviorCandidateMismatchKind,
    artifactPath: String?,
    owner: String,
    failureCode: String?,
    diagnostic: Boolean,
): MismatchRecord {
    val id = if (diagnostic && kind in DIAGNOSTIC_MATRIX_KINDS) {
        val field = when (kind) {
            LlvmBehaviorCandidateMismatchKind.EXIT_CODE -> "exitCode"
            LlvmBehaviorCandidateMismatchKind.STDOUT -> "stdout"
            LlvmBehaviorCandidateMismatchKind.STDERR -> "stderr"
            else -> candidateFail("diagnostic matrix identity requested for a non-matrix kind")
        }
        "clang-diagnostic-${OracleArtifacts.sha256("$caseId:$field".encodeToByteArray()).take(32)}"
    } else {
        llvmBehaviorCandidateMismatchId(corpusSha256, caseId, kind, artifactPath)
    }
    return MismatchRecord(id, caseId, kind, artifactPath, owner, failureCode)
}

private fun renderAssessment(
    reference: LlvmBehaviorReferenceEvidence,
    executable: CandidateExecutableSnapshot,
    observationSha256: String,
    ownershipSha256: String,
    comparison: ComparisonResult,
): ByteArray {
    val mismatchJson = comparison.mismatches.map { record ->
        JsonObject(
            linkedMapOf(
                "mismatchId" to JsonPrimitive(record.mismatchId),
                "caseId" to JsonPrimitive(record.caseId),
                "kind" to JsonPrimitive(record.kind.wire),
                "artifactPath" to (record.artifactPath?.let(::JsonPrimitive) ?: JsonNull),
                "ownerSubsystem" to JsonPrimitive(record.ownerSubsystem),
                "failureCode" to (record.failureCode?.let(::JsonPrimitive) ?: JsonNull),
            ),
        )
    }
    val document = JsonObject(
        linkedMapOf(
            "schemaVersion" to JsonPrimitive(1),
            "authority" to JsonPrimitive(NON_AUTHORITY),
            "releaseEligible" to JsonPrimitive(false),
            "reference" to JsonObject(
                linkedMapOf(
                    "corpusId" to JsonPrimitive(reference.corpusId),
                    "corpusSha256" to JsonPrimitive(reference.corpusSha256),
                    "reportSha256" to JsonPrimitive(reference.reportSha256),
                    "diagnosticMatrixSha256" to JsonPrimitive(reference.diagnosticMatrixSha256),
                    "diagnosticMatrixSelfSha256" to JsonPrimitive(reference.diagnosticMatrixSelfSha256),
                    "artifactManifestSha256" to JsonPrimitive(reference.artifactManifestSha256),
                    "sandboxSha256" to JsonPrimitive(reference.sandboxSha256),
                ),
            ),
            "candidateExecutable" to JsonObject(
                linkedMapOf(
                    "bytes" to JsonPrimitive(executable.size),
                    "sha256" to JsonPrimitive(executable.sha256),
                ),
            ),
            "inputs" to JsonObject(
                linkedMapOf(
                    "observationSha256" to JsonPrimitive(observationSha256),
                    "ownershipId" to JsonPrimitive(EXPECTED_OWNERSHIP_ID),
                    "ownershipSha256" to JsonPrimitive(ownershipSha256),
                ),
            ),
            "summary" to JsonObject(
                linkedMapOf(
                    "cases" to JsonPrimitive(EXPECTED_CASE_COUNT),
                    "observed" to JsonPrimitive(comparison.observedCases),
                    "notRun" to JsonPrimitive(comparison.notRunCases),
                    "infrastructureFailed" to JsonPrimitive(comparison.infrastructureFailedCases),
                    "matchingObserved" to JsonPrimitive(comparison.matchingObservedCases),
                    "mismatchingObserved" to JsonPrimitive(comparison.mismatchingObservedCases),
                    "mismatchRecords" to JsonPrimitive(comparison.mismatches.size),
                ),
            ),
            "mismatches" to JsonArray(mismatchJson),
        ),
    )
    OracleSchemas.validate("llvm-behavior-comparison-assessment", document)
    return OracleJson.canonicalBytes(document, ASSESSMENT_JSON_LIMITS)
}

private fun snapshotCandidateExecutable(path: Path): CandidateExecutableSnapshot {
    val normalized = path.toAbsolutePath().normalize()
    val parent = normalized.parent ?: candidateFail("candidate executable path must name a file")
    if (parent.toRealPath() != parent) candidateFail("candidate executable parent path may not contain symbolic links")
    val parentBefore = candidateFileAttributes(parent, "candidate executable parent")
    if (!parentBefore.isDirectory || parentBefore.isSymbolicLink || parentBefore.fileKey() == null) {
        candidateFail("candidate executable parent must be a real directory with stable identity")
    }
    val parentPermissions = trustedCandidatePermissions(parent, "candidate executable parent")
    val before = candidateFileAttributes(normalized, "candidate executable")
    if (!before.isRegularFile || before.isSymbolicLink || before.fileKey() == null) {
        candidateFail("candidate executable must be a regular non-symbolic file with stable identity")
    }
    val permissions = trustedCandidatePermissions(normalized, "candidate executable")
    if (before.size() !in 1..MAXIMUM_CANDIDATE_EXECUTABLE_BYTES) {
        candidateFail("candidate executable is empty or exceeds the byte limit")
    }
    val digest = MessageDigest.getInstance("SHA-256")
    try {
        FileChannel.open(normalized, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
            val buffer = ByteBuffer.allocate(EXECUTABLE_READ_BUFFER_BYTES)
            var total = 0L
            while (true) {
                buffer.clear()
                val read = channel.read(buffer)
                if (read < 0) break
                if (read == 0) continue
                total = candidateCheckedAdd(total, read.toLong(), "candidate executable bytes")
                if (total > MAXIMUM_CANDIDATE_EXECUTABLE_BYTES) candidateFail("candidate executable exceeds the byte limit")
                digest.update(buffer.array(), 0, read)
            }
            if (total != before.size() || channel.size() != before.size()) {
                candidateFail("candidate executable changed size during snapshot")
            }
        }
    } catch (failure: LlvmBehaviorCandidateAssessmentException) {
        throw failure
    } catch (failure: Exception) {
        candidateFail("candidate executable could not be read", failure)
    }
    val after = candidateFileAttributes(normalized, "candidate executable")
    val parentAfter = candidateFileAttributes(parent, "candidate executable parent")
    if (
        !sameFileVersion(before, after) || !sameDirectoryVersion(parentBefore, parentAfter) ||
        permissions != trustedCandidatePermissions(normalized, "candidate executable") ||
        parentPermissions != trustedCandidatePermissions(parent, "candidate executable parent")
    ) {
        candidateFail("candidate executable identity, parent, or permissions changed during snapshot")
    }
    return CandidateExecutableSnapshot(before.size(), digest.digest().toHex())
}

private fun candidateFileAttributes(path: Path, label: String): BasicFileAttributes = try {
    Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
} catch (failure: Exception) {
    candidateFail("$label metadata is unavailable", failure)
}

private fun sameFileVersion(left: BasicFileAttributes, right: BasicFileAttributes): Boolean =
    left.fileKey() == right.fileKey() &&
        left.size() == right.size() &&
        left.lastModifiedTime() == right.lastModifiedTime() &&
        left.isRegularFile == right.isRegularFile &&
        left.isSymbolicLink == right.isSymbolicLink

private fun sameDirectoryVersion(left: BasicFileAttributes, right: BasicFileAttributes): Boolean =
    left.fileKey() == right.fileKey() &&
        left.lastModifiedTime() == right.lastModifiedTime() &&
        left.isDirectory && right.isDirectory &&
        !left.isSymbolicLink && !right.isSymbolicLink

private fun trustedCandidatePermissions(path: Path, label: String): Set<PosixFilePermission> {
    val permissions = try {
        Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS)
    } catch (failure: Exception) {
        candidateFail("$label POSIX permissions are unavailable", failure)
    }
    if (
        PosixFilePermission.GROUP_WRITE in permissions ||
        PosixFilePermission.OTHERS_WRITE in permissions
    ) {
        candidateFail("$label may not be writable by group or other principals")
    }
    return HashSet(permissions)
}

private fun parseCandidateCanonicalObject(bytes: ByteArray, maximumBytes: Int, label: String): JsonObject {
    val parsed = try {
        OracleJson.parseCanonical(
            bytes,
            StrictJsonLimits(
                maximumInputBytes = maximumBytes,
                maximumCanonicalBytes = maximumBytes,
                maximumDepth = MAXIMUM_JSON_DEPTH,
                maximumNodes = MAXIMUM_JSON_NODES,
                maximumStringBytes = maximumBytes,
                maximumTotalStringBytes = maximumBytes,
                maximumNumberCharacters = 32,
            ),
        )
    } catch (failure: Exception) {
        candidateFail("$label is not strict canonical bounded JSON", failure)
    }
    return parsed as? JsonObject ?: candidateFail("$label root must be an object")
}

private fun reauthenticateArtifact(
    path: Path,
    expectedSize: Int,
    expectedSha256: String,
    maximumBytes: Int,
    label: String,
) {
    val terminal = OracleArtifacts.read(path, OracleArtifactLimits(maximumBytes))
    if (terminal.size != expectedSize || terminal.sha256 != expectedSha256) {
        candidateFail("$label changed before terminal assessment acceptance")
    }
}

private fun sameReference(
    left: LlvmBehaviorReferenceEvidence,
    right: LlvmBehaviorReferenceEvidence,
): Boolean =
    left.corpusId == right.corpusId &&
        left.corpusSha256 == right.corpusSha256 &&
        left.reportSha256 == right.reportSha256 &&
        left.diagnosticMatrixSha256 == right.diagnosticMatrixSha256 &&
        left.diagnosticMatrixSelfSha256 == right.diagnosticMatrixSelfSha256 &&
        left.artifactManifestSha256 == right.artifactManifestSha256 &&
        left.executableBytes == right.executableBytes &&
        left.executableSha256 == right.executableSha256 &&
        left.sandboxSha256 == right.sandboxSha256 &&
        left.caseIds == right.caseIds &&
        left.diagnosticOwners == right.diagnosticOwners

private fun buildOperatorSummary(
    observed: Int,
    matching: Int,
    mismatching: Int,
    notRun: Int,
    infrastructureFailed: Int,
    mismatchRecords: Int,
    assessmentSha256: String,
): String =
    "NON-AUTHORITATIVE caller-supplied candidate observation comparison: " +
        "$EXPECTED_CASE_COUNT cases; observed=$observed (matching=$matching, mismatching=$mismatching); " +
        "not-run=$notRun; infrastructure-failed=$infrastructureFailed; " +
        "mismatch-records=$mismatchRecords; releaseEligible=false; assessmentSha256=$assessmentSha256"

private fun requireCandidateRelativePath(value: String) {
    val utf8Bytes = value.toByteArray(StandardCharsets.UTF_8).size
    if (value.isEmpty() || utf8Bytes > MAXIMUM_PATH_BYTES || value.startsWith('/') ||
        value.contains('\\') || value.contains("//")
    ) {
        candidateFail("artifact path must be a bounded normalized relative POSIX path")
    }
    if (value.split('/').any { it.isEmpty() || it == "." || it == ".." }) {
        candidateFail("artifact path must be a normalized relative POSIX path")
    }
}

private fun requireCandidateIdentifier(value: String, label: String) {
    if (!IDENTIFIER.matches(value) || value.toByteArray(StandardCharsets.UTF_8).size > MAXIMUM_IDENTIFIER_BYTES) {
        candidateFail("$label is invalid")
    }
}

private fun candidateCheckedAdd(left: Long, right: Long, label: String): Long {
    if (right < 0L || left > Long.MAX_VALUE - right) candidateFail("$label overflow")
    return left + right
}

private fun JsonObject.candidateRequireFields(expected: Set<String>, label: String) {
    if (keys != expected) candidateFail("$label fields differ: expected ${expected.sorted()}, got ${keys.sorted()}")
}

private fun JsonObject.candidateElement(name: String, label: String): JsonElement =
    this[name] ?: candidateFail("$label is missing $name")

private fun JsonObject.candidateObject(name: String, label: String): JsonObject =
    candidateElement(name, label).candidateObject("$label.$name")

private fun JsonElement.candidateObject(label: String): JsonObject =
    this as? JsonObject ?: candidateFail("$label must be an object")

private fun JsonObject.candidateArray(name: String, label: String): JsonArray =
    candidateElement(name, label) as? JsonArray ?: candidateFail("$label.$name must be an array")

private fun JsonObject.candidateString(name: String, label: String): String {
    val primitive = candidateElement(name, label) as? JsonPrimitive ?: candidateFail("$label.$name must be a string")
    if (!primitive.isString) candidateFail("$label.$name must be a string")
    return primitive.content
}

private fun JsonObject.candidateRequireString(name: String, expected: String, label: String) {
    if (candidateString(name, label) != expected) candidateFail("$label.$name differs from the fixed value")
}

private fun JsonObject.candidateBoolean(name: String, label: String): Boolean {
    val primitive = candidateElement(name, label) as? JsonPrimitive ?: candidateFail("$label.$name must be boolean")
    if (primitive.isString) candidateFail("$label.$name must be boolean")
    return primitive.booleanOrNull ?: candidateFail("$label.$name must be boolean")
}

private fun JsonObject.candidateLong(name: String, label: String): Long {
    val primitive = candidateElement(name, label) as? JsonPrimitive ?: candidateFail("$label.$name must be integer")
    if (primitive.isString || !INTEGER.matches(primitive.content)) candidateFail("$label.$name must be integer")
    return primitive.longOrNull ?: candidateFail("$label.$name is outside the integer range")
}

private fun JsonObject.candidateRequireInteger(
    name: String,
    minimum: Long,
    maximum: Long,
    label: String,
): Long {
    val value = candidateLong(name, label)
    if (value !in minimum..maximum) candidateFail("$label.$name is outside the allowed range")
    return value
}

private fun candidateFail(message: String, cause: Throwable? = null): Nothing =
    throw LlvmBehaviorCandidateAssessmentException(message, cause)

private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private data class CandidateExecutableSnapshot(val size: Long, val sha256: String)
private data class ValidatedBlob(val content: ByteArray)
private data class CandidateArtifact(val present: Boolean, val content: ByteArray?, val mode: String?)
private data class MismatchRecord(
    val mismatchId: String,
    val caseId: String,
    val kind: LlvmBehaviorCandidateMismatchKind,
    val artifactPath: String?,
    val ownerSubsystem: String,
    val failureCode: String?,
)

private data class ComparisonResult(
    val observedCases: Int,
    val notRunCases: Int,
    val infrastructureFailedCases: Int,
    val matchingObservedCases: Int,
    val mismatchingObservedCases: Int,
    val mismatches: List<MismatchRecord>,
)

private data class DerivedFields(
    val referenceCorpusId: String,
    val referenceCorpusSha256: String,
    val referenceReportSha256: String,
    val referenceDiagnosticMatrixSha256: String,
    val referenceDiagnosticMatrixSelfSha256: String,
    val referenceArtifactManifestSha256: String,
    val referenceSandboxSha256: String,
    val candidateExecutable: CandidateExecutableSnapshot,
    val observationSha256: String,
    val ownershipSha256: String,
    val observedCases: Int,
    val notRunCases: Int,
    val infrastructureFailedCases: Int,
    val matchingObservedCases: Int,
    val mismatchingObservedCases: Int,
    val mismatches: List<MismatchRecord>,
    val canonicalBytes: ByteArray,
)

private const val NON_AUTHORITY = "non-authoritative-caller-supplied-observations-v1"
private const val MISMATCH_ID_DOMAIN = "decomp-clang-behavior-mismatch-v1"
private const val EXPECTED_OWNERSHIP_ID = "clang-22-1-6-behavior-case-ownership-v1"
private const val EXPECTED_OWNERSHIP_SHA256 = "f403a57b1712df43d7043b3593f38aa705005136edfd97a78691e273c9a46c5f"
private const val EXPECTED_REFERENCE_CORPUS_SHA256 = "acaa7b33c390b2c9fde15b4e21b0a899ffff62fe98ce22226866272b4efe8d5b"
private const val EXPECTED_CASE_COUNT = 48
private const val MAXIMUM_REFERENCE_REPORT_BYTES = 64 * 1024 * 1024
private const val MAXIMUM_OBSERVATION_BYTES = 64 * 1024 * 1024
private const val MAXIMUM_OWNERSHIP_BYTES = 256 * 1024
private const val MAXIMUM_CANDIDATE_EXECUTABLE_BYTES = 128L * 1024L * 1024L
private const val MAXIMUM_DECODED_BLOB_BYTES = 16 * 1024 * 1024
private const val MAXIMUM_RETAINED_OBSERVATION_BYTES = 32L * 1024L * 1024L
private const val MAXIMUM_BASE64_CHARACTERS = 22_369_624L
private const val MAXIMUM_ARTIFACTS_PER_CASE = 256
private const val MAXIMUM_PATH_BYTES = 4096
private const val MAXIMUM_IDENTIFIER_BYTES = 128
private const val MAXIMUM_JSON_DEPTH = 32
private const val MAXIMUM_JSON_NODES = 100_000
private const val EXECUTABLE_READ_BUFFER_BYTES = 1024 * 1024

private val ASSESSMENT_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 16 * 1024 * 1024,
    maximumCanonicalBytes = 16 * 1024 * 1024,
    maximumDepth = 16,
    maximumNodes = 250_000,
    maximumStringBytes = MAXIMUM_PATH_BYTES,
    maximumTotalStringBytes = 8 * 1024 * 1024,
    maximumNumberCharacters = 32,
)
private val SHA256 = Regex("[0-9a-f]{64}")
private val IDENTIFIER = Regex("[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
private val INTEGER = Regex("0|-?[1-9][0-9]*")
private val MODE = Regex("0o[4-7][0-7]{2}")
private val BASE64 = Regex("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
private val ARTIFACT_KINDS = setOf(
    LlvmBehaviorCandidateMismatchKind.ARTIFACT_CONTENT,
    LlvmBehaviorCandidateMismatchKind.ARTIFACT_MODE,
    LlvmBehaviorCandidateMismatchKind.ARTIFACT_PRESENCE,
    LlvmBehaviorCandidateMismatchKind.UNEXPECTED_ARTIFACT,
)
private val DIAGNOSTIC_MATRIX_KINDS = setOf(
    LlvmBehaviorCandidateMismatchKind.EXIT_CODE,
    LlvmBehaviorCandidateMismatchKind.STDOUT,
    LlvmBehaviorCandidateMismatchKind.STDERR,
)
private val NOT_RUN_FAILURE_CODES = setOf("blocked-by-infrastructure-failure", "not-requested")
private val INFRASTRUCTURE_FAILURE_CODES = setOf(
    "candidate-unexecutable",
    "collection-failed",
    "process-launch-failed",
    "resource-limit",
    "runner-failed",
    "sandbox-failed",
    "timeout",
)
private val DIAGNOSTIC_CASE_IDS = setOf(
    "assemble-invalid",
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
    "link-undefined-symbol",
    "pch-reuse-wrong-target",
    "preprocess-malformed-macro",
    "response-file-recursion",
    "target-unsupported-aarch64",
)
