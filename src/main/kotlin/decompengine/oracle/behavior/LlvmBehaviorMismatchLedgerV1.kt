package decompengine.oracle.behavior

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.DescriptorBoundStateFaultInjector
import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Caller annotations are retained metadata; even an accepted annotation confers no authority. */
data class LlvmBehaviorMismatchAnnotationV1(
    val mismatchId: String,
    val disposition: String,
    val rationale: String,
)

/** The minimum byte/count budgets accommodate a complete maximum-size comparison-v1 assessment. */
data class LlvmBehaviorMismatchLedgerLimitsV1(
    val maximumEvents: Int = 64,
    val maximumLedgerBytes: Int = 64 * 1024 * 1024,
    val maximumCumulativeAssessmentBytes: Long = 32L * 1024 * 1024,
    val maximumMismatchOccurrences: Int = 3_225_600,
    val maximumCumulativeRationaleBytes: Long = 16L * 1024 * 1024,
) {
    init {
        require(maximumEvents in 1..64) { "ledger event limit must be between one and 64" }
        require(maximumLedgerBytes in MINIMUM_LEDGER_BYTES..HARD_LEDGER_BYTES) {
            "ledger byte limit must accommodate a complete comparison-v1 assessment"
        }
        require(maximumCumulativeAssessmentBytes in MAXIMUM_ASSESSMENT_BYTES.toLong()..HARD_LEDGER_BYTES.toLong()) {
            "ledger assessment budget must accommodate a complete comparison-v1 assessment"
        }
        require(maximumMismatchOccurrences in MAXIMUM_ASSESSMENT_MISMATCHES..3_225_600) {
            "ledger occurrence budget must accommodate the comparison-v1 mismatch population"
        }
        require(maximumCumulativeRationaleBytes in MINIMUM_RATIONALE_BYTES..HARD_LEDGER_BYTES.toLong()) {
            "ledger rationale budget must accommodate the generated unresolved population"
        }
    }
}

/**
 * An immutable integrity result, not a recovered comparison or execution capability. Historical
 * comparison bytes and caller annotations never become oracle, scoring, or release evidence.
 */
sealed interface LlvmBehaviorMismatchLedgerV1 {
    val ledgerSha256: String
    val canonicalBytes: ByteArray
    val eventCount: Int
    val mismatchOccurrences: Int
    val acceptedAnnotationCount: Int
    val unresolvedAnnotationCount: Int
    val authority: String
    val releaseEligible: Boolean
    val scoringAuthority: Boolean
}

/**
 * One lineage per owner-controlled directory. Publication takes a nonblocking directory lock and
 * uses fixed sequence names, so competing descendants cannot replace a committed snapshot. The
 * directory owner must exclude unrelated same-UID pathname mutation, as required by the underlying
 * descriptor-bound publication primitive. No directory or external process is created here.
 */
object LlvmBehaviorMismatchLedgerV1Store {
    fun append(
        assessment: LlvmBehaviorCandidateAssessment,
        previous: LlvmBehaviorMismatchLedgerV1? = null,
        annotations: List<LlvmBehaviorMismatchAnnotationV1> = emptyList(),
        limits: LlvmBehaviorMismatchLedgerLimitsV1 = LlvmBehaviorMismatchLedgerLimitsV1(),
    ): LlvmBehaviorMismatchLedgerV1 {
        val prior = previous?.let { validateLedger(it.canonicalBytes, it.ledgerSha256, limits) }
        val assessmentBytes = assessment.canonicalBytes
        require(assessmentBytes.size <= MAXIMUM_ASSESSMENT_BYTES) { "comparison assessment exceeds its v1 byte limit" }
        require(OracleArtifacts.sha256(assessmentBytes) == assessment.assessmentSha256) {
            "sealed comparison bytes differ from their derived identity"
        }
        val parsed = validateAssessment(assessmentBytes)
        require(parsed.document.string("authority") == assessment.authority && !assessment.releaseEligible) {
            "ledger accepts only the existing non-authoritative comparison result"
        }
        require(parsed.document.obj("reference") == reference(assessment) &&
            parsed.document.obj("candidateExecutable").string("sha256") == assessment.candidateExecutableSha256 &&
            parsed.document.obj("inputs").string("observationSha256") == assessment.observationSha256 &&
            parsed.document.obj("inputs").string("ownershipSha256") == assessment.ownershipSha256) {
            "sealed comparison identity differs from its preserved bytes"
        }
        val scope = scope(parsed.document)
        require(prior == null || prior.scope == scope) { "ledger reference or ownership scope changed" }
        require(annotations.size <= parsed.mismatches.size) { "ledger has extra mismatch annotations" }
        val mismatchIds = parsed.mismatches.map { it.string("mismatchId") }.toSet()
        val supplied = LinkedHashMap<String, LlvmBehaviorMismatchAnnotationV1>()
        annotations.forEach { annotation ->
            require(supplied.put(annotation.mismatchId, annotation) == null) { "ledger has duplicate mismatch annotations" }
            require(annotation.mismatchId in mismatchIds) {
                "ledger annotation names an unknown mismatch"
            }
            require(annotation.disposition in setOf("accepted", "unresolved")) { "unsupported mismatch disposition" }
            requireRationale(annotation.rationale)
        }
        val records = parsed.mismatches.map { mismatch ->
            val annotation = supplied[mismatch.string("mismatchId")]
            JsonObject(linkedMapOf(
                "mismatchId" to mismatch.getValue("mismatchId"),
                "disposition" to JsonPrimitive(annotation?.disposition ?: "unresolved"),
                "rationale" to JsonPrimitive(annotation?.rationale ?: DEFAULT_RATIONALE),
                "origin" to JsonPrimitive(if (annotation == null) "generated-unresolved" else "caller-annotation"),
            ))
        }
        if (prior != null && prior.events.any {
                it.string("assessmentSha256") == assessment.assessmentSha256 && it.getValue("annotations") == JsonArray(records)
            }) return DerivedLedger(prior)
        val priorEvents = prior?.events ?: emptyList()
        require(priorEvents.size < limits.maximumEvents) { "ledger exceeds its cumulative event limit" }
        require(Math.addExact(prior?.summary?.long("retainedAssessmentBytes") ?: 0L, assessmentBytes.size.toLong()) <=
            limits.maximumCumulativeAssessmentBytes) { "ledger exceeds its cumulative assessment byte limit" }
        require(Math.addExact(prior?.summary?.int("mismatchOccurrences") ?: 0, records.size) <=
            limits.maximumMismatchOccurrences) { "ledger exceeds its cumulative mismatch occurrence limit" }
        val newRationaleBytes = records.sumOf { rationaleSize(it.string("rationale")).toLong() }
        require(Math.addExact(prior?.summary?.long("retainedRationaleBytes") ?: 0L, newRationaleBytes) <=
            limits.maximumCumulativeRationaleBytes) { "ledger exceeds its cumulative rationale byte limit" }
        val eventId = eventId(assessment.assessmentSha256, records)
        val event = JsonObject(linkedMapOf(
            "sequence" to JsonPrimitive(priorEvents.size + 1),
            "previousLedgerSha256" to (prior?.sha256?.let(::JsonPrimitive) ?: JsonNull),
            "eventId" to JsonPrimitive(eventId),
            "assessmentSha256" to JsonPrimitive(assessment.assessmentSha256),
            "assessmentBytes" to JsonPrimitive(assessmentBytes.size),
            "assessmentBase64" to JsonPrimitive(Base64.getEncoder().encodeToString(assessmentBytes)),
            "candidateExecutableSha256" to JsonPrimitive(assessment.candidateExecutableSha256),
            "annotations" to JsonArray(records),
        ))
        val bytes = render(scope, priorEvents + event, limits)
        val derived = validateLedger(bytes, OracleArtifacts.sha256(bytes), limits)
        require(derived.events.take(priorEvents.size) == priorEvents) { "ledger did not preserve its exact previous history" }
        return DerivedLedger(derived)
    }

    /** The expected digest is an external integrity pin; it does not grant comparison authority. */
    fun verify(
        path: Path,
        expectedLedgerSha256: String,
        limits: LlvmBehaviorMismatchLedgerLimitsV1 = LlvmBehaviorMismatchLedgerLimitsV1(),
    ): LlvmBehaviorMismatchLedgerV1 {
        val snapshot = OracleArtifacts.readCanonical(path, OracleArtifactLimits(limits.maximumLedgerBytes), jsonLimits(limits))
        return DerivedLedger(validateLedger(snapshot.bytes, expectedLedgerSha256, limits))
    }

    fun publish(
        directory: Path,
        assessment: LlvmBehaviorCandidateAssessment,
        previous: LlvmBehaviorMismatchLedgerV1? = null,
        annotations: List<LlvmBehaviorMismatchAnnotationV1> = emptyList(),
        limits: LlvmBehaviorMismatchLedgerLimitsV1 = LlvmBehaviorMismatchLedgerLimitsV1(),
    ): LlvmBehaviorMismatchLedgerV1 = publish(directory, assessment, previous, annotations, limits, null)

    /** Existing publication fault points exercise exact-byte crash recovery without a custom writer. */
    internal fun publish(
        directory: Path,
        assessment: LlvmBehaviorCandidateAssessment,
        previous: LlvmBehaviorMismatchLedgerV1?,
        annotations: List<LlvmBehaviorMismatchAnnotationV1>,
        limits: LlvmBehaviorMismatchLedgerLimitsV1,
        faultInjector: DescriptorBoundStateFaultInjector?,
    ): LlvmBehaviorMismatchLedgerV1 {
        val root = directory.toAbsolutePath().normalize()
        require(root.toRealPath() == root) { "ledger directory may not contain symbolic links" }
        LinuxFilesystemSyscalls.openRoot(root).use { descriptor ->
            DescriptorBoundAtomicStateFile.requireOwnerOnlyParent(descriptor)
            require(LinuxFilesystemSyscalls.tryExclusiveLock(descriptor)) { "ledger directory is already locked" }
            try {
                val names = LinuxFilesystemSyscalls.directoryEntryNames(descriptor, limits.maximumEvents + 2)
                val snapshotNames = names.filter { SNAPSHOT_NAME.matches(it) }.sorted()
                require(snapshotNames == (1..snapshotNames.size).map(::snapshotName)) {
                    "ledger directory has holes or unsupported snapshot names"
                }
                require(snapshotNames.size <= limits.maximumEvents) { "ledger directory exceeds its event limit" }
                val temporaryNames = names - snapshotNames.toSet()
                val pendingName = DescriptorBoundAtomicStateFile.temporaryName(snapshotName(snapshotNames.size + 1))
                require(temporaryNames.isEmpty() || temporaryNames == listOf(pendingName)) {
                    "ledger directory contains alien entries or conflicting publication residue"
                }
                if (previous != null) {
                    val stored = DescriptorBoundAtomicStateFile.readManifestOrNull(
                        descriptor, snapshotName(previous.eventCount), limits.maximumLedgerBytes,
                    ) ?: error("previous ledger snapshot is not published in this directory")
                    require(MessageDigest.isEqual(stored.bytes, previous.canonicalBytes)) {
                        "previous published ledger differs from the supplied integrity snapshot"
                    }
                    validateLedger(stored.bytes, previous.ledgerSha256, limits)
                }
                val ledger = append(assessment, previous, annotations, limits)
                val suppliedHead = previous?.eventCount ?: 0
                require(snapshotNames.size == suppliedHead ||
                    (snapshotNames.size == ledger.eventCount && ledger.eventCount == suppliedHead + 1)) {
                    "supplied previous ledger is stale relative to the latest published head"
                }
                if (snapshotNames.isNotEmpty()) {
                    val latest = DescriptorBoundAtomicStateFile.readManifestOrNull(
                        descriptor, snapshotNames.last(), limits.maximumLedgerBytes,
                    ) ?: error("latest ledger snapshot disappeared")
                    val expected = if (snapshotNames.size == suppliedHead) requireNotNull(previous) else ledger
                    require(MessageDigest.isEqual(latest.bytes, expected.canonicalBytes)) {
                        "latest published head differs from the supplied lineage"
                    }
                    validateLedger(latest.bytes, expected.ledgerSha256, limits)
                }
                require(temporaryNames.isEmpty() || pendingName == DescriptorBoundAtomicStateFile.temporaryName(snapshotName(ledger.eventCount))) {
                    "pending ledger publication differs from the requested next event"
                }
                val stored = DescriptorBoundAtomicStateFile.publishManifestNoReplace(
                    descriptor, snapshotName(ledger.eventCount), ledger.canonicalBytes, limits.maximumLedgerBytes, faultInjector,
                )
                require(MessageDigest.isEqual(stored.bytes, ledger.canonicalBytes)) { "published ledger differs from its derived bytes" }
                return DerivedLedger(validateLedger(stored.bytes, ledger.ledgerSha256, limits))
            } finally {
                LinuxFilesystemSyscalls.unlock(descriptor)
            }
        }
    }

    private class DerivedLedger(private val value: ValidatedLedger) : LlvmBehaviorMismatchLedgerV1 {
        override val ledgerSha256: String = value.sha256
        override val canonicalBytes: ByteArray get() = value.bytes.copyOf()
        override val eventCount: Int = value.events.size
        override val mismatchOccurrences: Int = value.summary.int("mismatchOccurrences")
        override val acceptedAnnotationCount: Int = value.summary.int("acceptedAnnotations")
        override val unresolvedAnnotationCount: Int = value.summary.int("unresolvedAnnotations")
        override val authority: String = LEDGER_AUTHORITY
        override val releaseEligible: Boolean = false
        override val scoringAuthority: Boolean = false
    }
}

private data class ValidatedLedger(
    val bytes: ByteArray,
    val sha256: String,
    val scope: JsonObject,
    val events: List<JsonObject>,
    val summary: JsonObject,
)

private data class ParsedAssessment(val document: JsonObject, val mismatches: List<JsonObject>)

private fun validateLedger(bytes: ByteArray, expectedSha256: String, limits: LlvmBehaviorMismatchLedgerLimitsV1): ValidatedLedger {
    require(SHA256.matches(expectedSha256)) { "ledger integrity pin must be lowercase SHA-256" }
    require(bytes.size <= limits.maximumLedgerBytes) { "ledger exceeds its byte limit" }
    require(OracleArtifacts.sha256(bytes) == expectedSha256) { "ledger differs from its external integrity pin" }
    val root = OracleJson.parseCanonical(bytes, jsonLimits(limits)).jsonObject
    OracleSchemas.validate(SCHEMA_NAME, root)
    val events = root.getValue("events").jsonArray.map { it.jsonObject }
    require(events.size in 1..limits.maximumEvents) { "ledger exceeds its cumulative event limit" }
    val ledgerScope = root.obj("scope")
    // Check declared cumulative budgets before expanding any embedded base64 or assessment JSON.
    ledgerDocument(ledgerScope, events, limits)
    val seenEvents = HashSet<String>()
    val stableIdentities = HashMap<String, JsonObject>()
    var previousHash: String? = null
    events.forEachIndexed { index, event ->
        require(event.int("sequence") == index + 1) { "ledger event sequence is not contiguous" }
        require(event.getValue("previousLedgerSha256") == (previousHash?.let(::JsonPrimitive) ?: JsonNull)) {
            "ledger previous history digest differs from its exact prefix"
        }
        val size = event.int("assessmentBytes")
        require(size in 1..MAXIMUM_ASSESSMENT_BYTES) { "retained assessment exceeds comparison-v1 byte limit" }
        val encoded = event.string("assessmentBase64")
        require(encoded.length.toLong() == 4L * ((size.toLong() + 2) / 3)) { "retained assessment base64 length differs from its size" }
        val assessmentBytes = Base64.getDecoder().decode(encoded)
        require(assessmentBytes.size == size && Base64.getEncoder().encodeToString(assessmentBytes) == encoded) {
            "retained assessment encoding is not canonical"
        }
        require(OracleArtifacts.sha256(assessmentBytes) == event.string("assessmentSha256")) { "retained assessment digest differs from its bytes" }
        val parsed = validateAssessment(assessmentBytes)
        require(scope(parsed.document) == ledgerScope) { "ledger reference or ownership scope changed" }
        require(event.string("candidateExecutableSha256") == parsed.document.obj("candidateExecutable").string("sha256")) {
            "ledger candidate identity differs from its retained assessment"
        }
        val annotations = event.getValue("annotations").jsonArray.map { it.jsonObject }
        require(annotations.map { it.string("mismatchId") } == parsed.mismatches.map { it.string("mismatchId") }) {
            "ledger annotations differ from the complete retained mismatch population"
        }
        annotations.forEach { annotation ->
            requireRationale(annotation.string("rationale"))
            if (annotation.string("origin") == "generated-unresolved") {
                require(annotation.string("disposition") == "unresolved" && annotation.string("rationale") == DEFAULT_RATIONALE) {
                    "generated annotation cannot adjudicate a mismatch"
                }
            }
        }
        parsed.mismatches.forEach { mismatch ->
            val identity = JsonObject(mismatch - "failureCode")
            val preceding = stableIdentities.putIfAbsent(mismatch.string("mismatchId"), identity)
            require(preceding == null || preceding == identity) { "stable mismatch identity changed across ledger events" }
        }
        require(event.string("eventId") == eventId(event.string("assessmentSha256"), annotations)) { "ledger event identity differs from its assessment and annotations" }
        require(seenEvents.add(event.string("eventId"))) { "ledger contains a duplicate annotation event" }
        previousHash = OracleArtifacts.sha256(render(ledgerScope, events.take(index + 1), limits))
    }
    require(root == ledgerDocument(ledgerScope, events, limits)) { "ledger summary or previous-history binding differs from its retained events" }
    return ValidatedLedger(bytes.copyOf(), expectedSha256, ledgerScope, events.toList(), root.obj("summary"))
}

private fun validateAssessment(bytes: ByteArray): ParsedAssessment {
    val document = OracleJson.parseCanonical(bytes, assessmentJsonLimits()).jsonObject
    OracleSchemas.validate("llvm-behavior-comparison-assessment", document)
    val mismatches = document.getValue("mismatches").jsonArray.map { it.jsonObject }
    val ids = mismatches.map { it.string("mismatchId") }
    require(ids == ids.distinct().sorted()) { "retained mismatch identities are not sorted and unique" }
    val corpus = document.obj("reference").string("corpusSha256")
    mismatches.forEach { mismatch ->
        val kind = LlvmBehaviorCandidateMismatchKind.entries.single { it.wire == mismatch.string("kind") }
        val path = mismatch.getValue("artifactPath").let { if (it == JsonNull) null else it.jsonPrimitive.content }
        val expected = if (mismatch.string("caseId") in DIAGNOSTIC_CASE_IDS && kind in DIAGNOSTIC_KINDS) {
            require(path == null) { "diagnostic mismatch has an artifact path" }
            "clang-diagnostic-" + OracleArtifacts.sha256("${mismatch.string("caseId")}:${kind.wire}".encodeToByteArray()).take(32)
        } else llvmBehaviorCandidateMismatchId(corpus, mismatch.string("caseId"), kind, path)
        require(mismatch.string("mismatchId") == expected) { "retained mismatch identity differs from its semantic fields" }
        require((kind == LlvmBehaviorCandidateMismatchKind.EXECUTION) == (mismatch.getValue("failureCode") != JsonNull)) {
            "retained mismatch failure code differs from its kind"
        }
        if (kind == LlvmBehaviorCandidateMismatchKind.EXECUTION) {
            require(mismatch.string("failureCode") in NOT_RUN_CODES + INFRASTRUCTURE_CODES) {
                "retained execution mismatch has an unsupported failure code"
            }
        }
    }
    val grouped = mismatches.groupBy { it.string("caseId") }
    require(grouped.values.none { rows -> rows.any { it.string("kind") == "execution" } && rows.size != 1 }) {
        "retained case mixes execution failure with observed mismatches"
    }
    val summary = document.obj("summary")
    require(summary.int("observed") + summary.int("notRun") + summary.int("infrastructureFailed") == summary.int("cases") &&
        summary.int("matchingObserved") + summary.int("mismatchingObserved") == summary.int("observed") &&
        summary.int("mismatchRecords") == mismatches.size &&
        mismatches.count { it.string("kind") == "execution" && it.string("failureCode") in NOT_RUN_CODES } == summary.int("notRun") &&
        mismatches.count { it.string("kind") == "execution" && it.string("failureCode") in INFRASTRUCTURE_CODES } == summary.int("infrastructureFailed") &&
        grouped.values.count { rows -> rows.none { it.string("kind") == "execution" } } == summary.int("mismatchingObserved")) {
        "retained comparison counts differ from its mismatch population"
    }
    return ParsedAssessment(document, mismatches)
}

private fun ledgerDocument(scope: JsonObject, events: List<JsonObject>, limits: LlvmBehaviorMismatchLedgerLimitsV1): JsonObject {
    require(events.size in 1..limits.maximumEvents) { "ledger exceeds its cumulative event limit" }
    var assessmentBytes = 0L
    var rationaleBytes = 0L
    var occurrences = 0
    var accepted = 0
    val candidates = HashSet<String>()
    val assessments = HashSet<String>()
    val mismatches = HashSet<String>()
    events.forEach { event ->
        assessmentBytes = Math.addExact(assessmentBytes, event.int("assessmentBytes").toLong())
        require(assessmentBytes <= limits.maximumCumulativeAssessmentBytes) { "ledger exceeds its cumulative assessment byte limit" }
        assessments += event.string("assessmentSha256")
        val annotations = event.getValue("annotations").jsonArray
        occurrences = Math.addExact(occurrences, annotations.size)
        require(occurrences <= limits.maximumMismatchOccurrences) { "ledger exceeds its cumulative mismatch occurrence limit" }
        annotations.forEach { raw ->
            val annotation = raw.jsonObject
            rationaleBytes = Math.addExact(rationaleBytes, rationaleSize(annotation.string("rationale")).toLong())
            require(rationaleBytes <= limits.maximumCumulativeRationaleBytes) { "ledger exceeds its cumulative rationale byte limit" }
            if (annotation.string("disposition") == "accepted") accepted++
            mismatches += annotation.string("mismatchId")
        }
        candidates += event.string("candidateExecutableSha256")
    }
    return JsonObject(linkedMapOf(
        "schemaVersion" to JsonPrimitive(1),
        "authority" to JsonPrimitive(LEDGER_AUTHORITY),
        "releaseEligible" to JsonPrimitive(false),
        "scoringAuthority" to JsonPrimitive(false),
        "annotationAuthority" to JsonPrimitive("untrusted-metadata-only"),
        "scope" to scope,
        "previousLedgerSha256" to events.last().getValue("previousLedgerSha256"),
        "summary" to JsonObject(linkedMapOf(
            "annotationEvents" to JsonPrimitive(events.size),
            "distinctAssessments" to JsonPrimitive(assessments.size),
            "distinctCandidateExecutables" to JsonPrimitive(candidates.size),
            "distinctMismatchIds" to JsonPrimitive(mismatches.size),
            "mismatchOccurrences" to JsonPrimitive(occurrences),
            "acceptedAnnotations" to JsonPrimitive(accepted),
            "unresolvedAnnotations" to JsonPrimitive(occurrences - accepted),
            "retainedAssessmentBytes" to JsonPrimitive(assessmentBytes),
            "retainedRationaleBytes" to JsonPrimitive(rationaleBytes),
        )),
        "events" to JsonArray(events),
    ))
}

private fun render(scope: JsonObject, events: List<JsonObject>, limits: LlvmBehaviorMismatchLedgerLimitsV1): ByteArray =
    OracleJson.canonicalBytes(ledgerDocument(scope, events, limits), jsonLimits(limits))

private fun scope(assessment: JsonObject): JsonObject = JsonObject(linkedMapOf(
    "reference" to assessment.getValue("reference"),
    "ownershipId" to assessment.obj("inputs").getValue("ownershipId"),
    "ownershipSha256" to assessment.obj("inputs").getValue("ownershipSha256"),
))

private fun reference(value: LlvmBehaviorCandidateAssessment): JsonObject = JsonObject(linkedMapOf(
    "corpusId" to JsonPrimitive(value.referenceCorpusId),
    "corpusSha256" to JsonPrimitive(value.referenceCorpusSha256),
    "reportSha256" to JsonPrimitive(value.referenceReportSha256),
    "diagnosticMatrixSha256" to JsonPrimitive(value.referenceDiagnosticMatrixSha256),
    "diagnosticMatrixSelfSha256" to JsonPrimitive(value.referenceDiagnosticMatrixSelfSha256),
    "artifactManifestSha256" to JsonPrimitive(value.referenceArtifactManifestSha256),
    "sandboxSha256" to JsonPrimitive(value.referenceSandboxSha256),
))

private fun eventId(assessmentSha256: String, annotations: List<JsonObject>): String = OracleArtifacts.sha256(
    OracleJson.canonicalBytes(JsonObject(linkedMapOf(
        "domain" to JsonPrimitive("decomp-llvm-mismatch-annotation-event-v1"),
        "assessmentSha256" to JsonPrimitive(assessmentSha256),
        "annotations" to JsonArray(annotations),
    )), jsonLimits(LlvmBehaviorMismatchLedgerLimitsV1())),
)

private fun requireRationale(value: String) {
    require(value.length in 1..4096) { "mismatch rationale exceeds its character limit" }
    require(value.isNotBlank() && '\u0000' !in value) { "mismatch rationale must be nonblank and contain no NUL" }
    require(rationaleSize(value) <= 4096) { "mismatch rationale exceeds its byte limit" }
}

private fun rationaleSize(value: String): Int {
    val bytes = value.encodeToByteArray()
    require(bytes.decodeToString(throwOnInvalidSequence = true) == value) { "mismatch rationale is not valid Unicode" }
    return bytes.size
}

private fun snapshotName(sequence: Int): String = "ledger-${sequence.toString().padStart(4, '0')}.json"
private fun JsonObject.obj(name: String): JsonObject = getValue(name).jsonObject
private fun JsonObject.string(name: String): String = getValue(name).jsonPrimitive.content
private fun JsonObject.int(name: String): Int = getValue(name).jsonPrimitive.int
private fun JsonObject.long(name: String): Long = getValue(name).jsonPrimitive.content.toLong()

private fun jsonLimits(limits: LlvmBehaviorMismatchLedgerLimitsV1) = StrictJsonLimits(
    maximumInputBytes = limits.maximumLedgerBytes,
    maximumCanonicalBytes = limits.maximumLedgerBytes,
    maximumDepth = 24,
    maximumNodes = 1_000_000,
    maximumStringBytes = 22_369_624,
    maximumTotalStringBytes = limits.maximumLedgerBytes,
    maximumNumberCharacters = 32,
)

private fun assessmentJsonLimits() = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_ASSESSMENT_BYTES,
    maximumCanonicalBytes = MAXIMUM_ASSESSMENT_BYTES,
    maximumDepth = 16,
    maximumNodes = 500_000,
    maximumStringBytes = 4096,
    maximumTotalStringBytes = MAXIMUM_ASSESSMENT_BYTES,
    maximumNumberCharacters = 32,
)

private const val SCHEMA_NAME = "llvm-behavior-mismatch-ledger-v1"
private const val LEDGER_AUTHORITY = "integrity-only-retained-comparison-and-annotations-v1"
private const val MAXIMUM_ASSESSMENT_BYTES = 16 * 1024 * 1024
private const val MAXIMUM_ASSESSMENT_MISMATCHES = 50_400
private const val HARD_LEDGER_BYTES = 64 * 1024 * 1024
private const val MINIMUM_LEDGER_BYTES = 40 * 1024 * 1024
private const val DEFAULT_RATIONALE = "No adjudication was supplied; this mismatch remains unresolved."
private const val MINIMUM_RATIONALE_BYTES = 4L * 1024 * 1024
private val SHA256 = Regex("[0-9a-f]{64}")
private val SNAPSHOT_NAME = Regex("ledger-[0-9]{4}\\.json")
private val DIAGNOSTIC_KINDS = setOf(LlvmBehaviorCandidateMismatchKind.EXIT_CODE, LlvmBehaviorCandidateMismatchKind.STDOUT, LlvmBehaviorCandidateMismatchKind.STDERR)
private val DIAGNOSTIC_CASE_IDS = setOf(
    "assemble-invalid", "diagnostic-color-always", "diagnostic-color-never", "diagnostic-error-limit",
    "diagnostic-fixit", "diagnostic-invalid-option", "diagnostic-missing-include", "diagnostic-syntax",
    "diagnostic-template-backtrace", "diagnostic-warning-option", "driver-missing-linker", "link-undefined-symbol",
    "pch-reuse-wrong-target", "preprocess-malformed-macro", "response-file-recursion", "target-unsupported-aarch64",
)
private val NOT_RUN_CODES = setOf("blocked-by-infrastructure-failure", "not-requested")
private val INFRASTRUCTURE_CODES = setOf(
    "candidate-unexecutable", "collection-failed", "process-launch-failed", "resource-limit", "runner-failed",
    "sandbox-failed", "timeout",
)
