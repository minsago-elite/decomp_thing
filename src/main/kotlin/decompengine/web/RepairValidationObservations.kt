package decompengine.web

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.sha256
import decompengine.project.requireRecordedRepairValidationSandbox
import decompengine.project.requireRecordedRepairValidationOutputQuota
import decompengine.project.requireRecordedRepairValidationRuntime
import decompengine.project.requireRecordedRepairValidationSourceSnapshot
import decompengine.project.ReconstructionProfiles
import decompengine.repair.RepairRecordedValidationObservation
import decompengine.repair.RepairValidationObservedOutcome
import decompengine.repair.requireRepairValidationDiffRole
import decompengine.repair.repairValidationDiffInputIds
import decompengine.repair.RepairValidationAssurance
import decompengine.repair.RepairHistoryIdentityReferences
import decompengine.repair.RepairRecordedIdentity
import java.util.Collections
import kotlinx.serialization.json.longOrNull
import java.security.MessageDigest
import java.util.HexFormat
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull

/** Receipt integrity and closed operation labels, not case comparison or release qualification. */
internal data class RecordedRepairValidationObservationView(
    val primaryState: RepairEvidenceArtifactState,
    val diffState: RepairEvidenceArtifactState? = null,
    val outcome: RepairValidationObservedOutcome? = null,
    val inputCount: Int? = null,
    val completedCasePairs: Int? = null,
    val casePage: RecordedRepairValidationCasePage? = null,
)

internal fun checkedRecordedRepairValidationObservation(binding: RepairRecordedValidationObservation,
    primaryBytes: ByteArray?, diffBytes: ByteArray?, casePageNumber: Int = 1): RecordedRepairValidationObservationView {
    require(casePageNumber > 0)
    if (primaryBytes == null || primaryBytes.isEmpty())
        return RecordedRepairValidationObservationView(RepairEvidenceArtifactState.UNAVAILABLE)
    var expectedInputIds: List<String> = emptyList()
    val primary = runCatching {
        require(primaryBytes.size.toLong() == binding.primary.bytes && sha256(primaryBytes) == binding.primary.sha256 &&
            binding.primary.sha256 == binding.proof.evidenceSha256)
        val root = parseNormalValidationJson(primaryBytes)
        require(root.keys == setOf("schemaVersion", "provider", "profileId", "profileSha256", "indexSha256",
            "sourceRevisionSha256", "regressionCorpusSha256", "runtimeSha256", "runtimeConfiguration",
            "behaviorBudgetEvidence", "sourceSnapshot", "buildOutputLink", "originalExecutable", "rebuiltExecutable",
            "inputs", "scopes", "outcome", "caseCount", "matches", "cleanupVerified", "assurance"))
        fun text(name: String) = (root.getValue(name) as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: error("validation receipt text type")
        fun scalar(name: String) = (root.getValue(name) as? JsonPrimitive)?.takeUnless { it.isString }
            ?: error("validation receipt scalar type")
        require(scalar("schemaVersion").intOrNull == 2 && text("provider") == "generated-c-linux-bubblewrap-cgroup-v1")
        val proof = binding.proof
        require(proof.cleanupVerified && proof.assurance == RepairValidationAssurance.STRICT_CONTAINED)
        when (binding.outcome) {
            RepairValidationObservedOutcome.COMPILE_FAILED -> require(proof.rebuiltBinarySha256 == null)
            RepairValidationObservedOutcome.COMPILE_VALID -> require(proof.originalBinarySha256 == null && proof.rebuiltBinarySha256 != null)
            RepairValidationObservedOutcome.BEHAVIOR_CHECKED -> require(proof.originalBinarySha256 != null && proof.rebuiltBinarySha256 != null)
        }
        require(text("sourceRevisionSha256") == proof.sourceRevisionSha256 && text("profileSha256") == proof.profileSha256 &&
            text("indexSha256") == proof.indexSha256 && text("regressionCorpusSha256") == proof.regressionCorpusSha256 &&
            text("runtimeSha256") == proof.runtimeSha256 && text("assurance") == "strict-contained" &&
            scalar("cleanupVerified").booleanOrNull == true)
        require(text("outcome") == binding.outcome.name.lowercase().replace('_', '-'))
        fun executable(name: String, expected: String?) {
            val element = root.getValue(name)
            if (expected == null) require(element is JsonNull) else {
                val hash = ((element as? JsonObject)?.get("sha256") as? JsonPrimitive)?.takeIf { it.isString }?.content
                require(hash == expected)
            }
        }
        executable("originalExecutable", proof.originalBinarySha256)
        executable("rebuiltExecutable", proof.rebuiltBinarySha256)
        val inputRows = requireNotNull(root.getValue("inputs") as? JsonArray)
        expectedInputIds = inputRows.map { row -> ((row as? JsonObject)?.get("id") as? JsonPrimitive)
            ?.takeIf { it.isString }?.content ?: error("validation input identity type") }
        require(expectedInputIds.distinct().size == expectedInputIds.size && expectedInputIds == expectedInputIds.sorted())
        require(recordedNormalValidationCorpusSha256(inputRows) == proof.regressionCorpusSha256)
        val inputs = inputRows.size
        val completed = requireNotNull(scalar("caseCount").intOrNull)
        val matches = requireNotNull(scalar("matches").booleanOrNull)
        requireRepairValidationDiffRole(binding.outcome, matches, binding.diff != null)
        require(root.getValue("scopes") is JsonArray)
        if (binding.outcome == RepairValidationObservedOutcome.BEHAVIOR_CHECKED)
            require(inputs > 0 && completed == inputs)
        else require(completed == 0 && !matches)
        RecordedRepairValidationObservationView(RepairEvidenceArtifactState.AVAILABLE,
            outcome = binding.outcome, inputCount = inputs, completedCasePairs = completed,
            casePage = checkedRecordedRepairValidationCases(binding, root, inputRows, expectedInputIds, casePageNumber))
    }.getOrElse { RecordedRepairValidationObservationView(RepairEvidenceArtifactState.CORRUPT) }
    if (primary.primaryState != RepairEvidenceArtifactState.AVAILABLE) return primary
    val diff = binding.diff ?: return primary
    val state = if (diffBytes == null || diffBytes.isEmpty()) RepairEvidenceArtifactState.UNAVAILABLE else {
        if (runCatching {
            require(diffBytes.size.toLong() == diff.bytes && sha256(diffBytes) == diff.sha256)
            require(repairValidationDiffInputIds(parseNormalValidationJson(diffBytes)) == expectedInputIds)
        }.isSuccess) RepairEvidenceArtifactState.AVAILABLE else RepairEvidenceArtifactState.CORRUPT
    }
    return primary.copy(diffState = state)
}

internal enum class RecordedRepairValidationCaseState { AVAILABLE, UNAVAILABLE, CORRUPT, OUT_OF_RANGE }
internal enum class RecordedRepairValidationCaseOutcome { MATCHED, MISMATCH, COMPILE_FAILED, COMPILE_ONLY }

/** At most 128 output bytes per stream, from an explicitly selected checked receipt. */
internal data class RecordedRepairValidationPreview(
    val totalBytes: Long,
    val prefixBytes: Int,
    val hex: String,
    val text: String?,
    val textBytes: Int?,
) {
    val truncated: Boolean get() = totalBytes > prefixBytes
}

/** Closed comparison and bounded output prefixes. Commands, host paths and raw input IDs stay private. */
internal data class RecordedRepairValidationCase(
    val identity: RepairRecordedIdentity,
    val ordinal: Int,
    val outcome: RecordedRepairValidationCaseOutcome,
    val exitCodeMatches: Boolean? = null,
    val stdoutMatches: Boolean? = null,
    val stderrMatches: Boolean? = null,
    val originalStdoutBytes: Long? = null,
    val rebuiltStdoutBytes: Long? = null,
    val originalStderrBytes: Long? = null,
    val rebuiltStderrBytes: Long? = null,
    val originalStdoutPreview: RecordedRepairValidationPreview? = null,
    val rebuiltStdoutPreview: RecordedRepairValidationPreview? = null,
    val originalStderrPreview: RecordedRepairValidationPreview? = null,
    val rebuiltStderrPreview: RecordedRepairValidationPreview? = null,
)

internal class RecordedRepairValidationCasePage(
    val state: RecordedRepairValidationCaseState,
    val pageNumber: Int,
    val totalPages: Int = 1,
    val inputCount: Int = 0,
    val matchedCount: Int? = null,
    cases: List<RecordedRepairValidationCase> = emptyList(),
) {
    val cases: List<RecordedRepairValidationCase> = Collections.unmodifiableList(ArrayList(cases))
}

private const val RECORDED_VALIDATION_CASES_PER_PAGE = 20
private val RECORDED_VALIDATION_CASE_DIGEST = Regex("[0-9a-f]{64}")

/** The normal receipt is already source/corpus/proof-bound by the caller. Fatal receipts use a separate projection. */
private fun checkedRecordedRepairValidationCases(binding: RepairRecordedValidationObservation,
    root: JsonObject, inputs: JsonArray, ids: List<String>, pageNumber: Int): RecordedRepairValidationCasePage {
    val scopes = root.getValue("scopes") as? JsonArray
        ?: return RecordedRepairValidationCasePage(RecordedRepairValidationCaseState.CORRUPT, pageNumber)
    if (scopes.isEmpty()) return RecordedRepairValidationCasePage(RecordedRepairValidationCaseState.UNAVAILABLE, pageNumber)
    val context = binding.context
        ?: return RecordedRepairValidationCasePage(RecordedRepairValidationCaseState.UNAVAILABLE, pageNumber)
    if (binding.outcome == RepairValidationObservedOutcome.BEHAVIOR_CHECKED && binding.expectedObservationsSha256 == null)
        return RecordedRepairValidationCasePage(RecordedRepairValidationCaseState.UNAVAILABLE, pageNumber)
    return runCatching {
        val behavior = binding.outcome == RepairValidationObservedOutcome.BEHAVIOR_CHECKED
        val profile = ReconstructionProfiles.named(context.profileId)
        require((root.getValue("profileId") as? JsonPrimitive)?.content == context.profileId)
        val (sourceMount, outputMount) = requireRecordedRepairValidationRuntime(
            root.getValue("runtimeConfiguration"), binding.proof.runtimeSha256, context.profileId)
        val sourceQuota = requireRecordedRepairValidationSourceSnapshot(root.getValue("sourceSnapshot"),
            binding.proof.sourceRevisionSha256, context.budget, profile.layout.declaration("build-definition").materialize())
        val outputQuota = requireRecordedRepairValidationOutputQuota(root.getValue("buildOutputLink"))
        require(sourceQuota.getValue("mountId") != outputQuota.getValue("mountId") &&
            sourceQuota.getValue("mountPathSha256") != outputQuota.getValue("mountPathSha256") &&
            sourceQuota.getValue("mountPathSha256") == JsonPrimitive(sha256(sourceMount.toString().toByteArray(Charsets.UTF_8))) &&
            outputQuota.getValue("mountPathSha256") == JsonPrimitive(sha256(outputMount.toString().toByteArray(Charsets.UTF_8))))
        require(scopes.size.toLong() == if (behavior) 1L + 2L * inputs.size else 1L)
        data class Output(val exit: Int, val stdout: Pair<String, Long>, val stderr: Pair<String, Long>)
        fun text(value: JsonElement): String = (value as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: error("validation case text type")
        fun positive(value: JsonElement) = (value as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull?.let { it > 0 } == true
        fun manifest(field: String): String {
            val executable = root.getValue(field) as? JsonObject ?: error("validation case executable type")
            return text(executable.getValue("runtimeManifestSha256")).also {
                require(it.matches(RECORDED_VALIDATION_CASE_DIGEST))
            }
        }
        val manifests = if (behavior) mapOf("reference" to manifest("originalExecutable"),
            "candidate" to manifest("rebuiltExecutable")) else emptyMap()
        fun scope(index: Int, role: String, input: String?): Output {
            val scope = scopes[index] as? JsonObject ?: error("validation case scope type")
            require(scope.keys == setOf("role", "inputId", "output", "sandboxSha256", "sandboxFields", "writableQuota", "cleanupVerified"))
            require(text(scope.getValue("role")) == role &&
                (if (input == null) scope.getValue("inputId") is JsonNull else text(scope.getValue("inputId")) == input))
            require((scope.getValue("cleanupVerified") as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull == true)
            require(text(scope.getValue("sandboxSha256")).matches(RECORDED_VALIDATION_CASE_DIGEST))
            val fields = scope.getValue("sandboxFields") as? JsonArray ?: error("validation sandbox fields type")
            fields.forEach { field ->
                val pair = field as? JsonArray ?: error("validation sandbox field type")
                require(pair.size == 2); pair.forEach { text(it) }
            }
            val quota = scope.getValue("writableQuota") as? JsonObject ?: error("validation writable quota type")
            require(quota.keys == setOf("provider", "mountId", "maximumBytes", "maximumEntries", "mountPathSha256"))
            require(text(quota.getValue("provider")) == "dedicated-tmpfs-size+nr_inodes" &&
                listOf("mountId", "maximumBytes", "maximumEntries").all { positive(quota.getValue(it)) } &&
                text(quota.getValue("mountPathSha256")).matches(RECORDED_VALIDATION_CASE_DIGEST))
            require(quota == outputQuota)
            val output = scope.getValue("output") as? JsonObject ?: error("validation case output type")
            require(output.keys == setOf("command", "exitCode", "stdoutBase64", "stderrBase64", "networkIsolated"))
            val command = output.getValue("command") as? JsonArray ?: error("validation case command type")
            require(command.isNotEmpty())
            command.forEach { text(it) }
            require((output.getValue("networkIsolated") as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull == true)
            val exit = (output.getValue("exitCode") as? JsonPrimitive)?.takeUnless { it.isString }?.intOrNull
            require(exit != null && exit in 0..127)
            requireRecordedRepairValidationSandbox(scope, manifests[role])
            return Output(exit, recordedValidationEncodedBytes(output.getValue("stdoutBase64")),
                recordedValidationEncodedBytes(output.getValue("stderrBase64")))
        }
        val build = scope(0, "build", null)
        require(if (binding.outcome == RepairValidationObservedOutcome.COMPILE_FAILED) build.exit != 0 else build.exit == 0)
        val pages = maxOf(1, (inputs.size + RECORDED_VALIDATION_CASES_PER_PAGE - 1) / RECORDED_VALIDATION_CASES_PER_PAGE)
        val from = (pageNumber.toLong() - 1L) * RECORDED_VALIDATION_CASES_PER_PAGE
        val identities = RepairHistoryIdentityReferences(binding.proof.regressionCorpusSha256)
        val rows = ArrayList<RecordedRepairValidationCase>()
        val referenceDigest = MessageDigest.getInstance("SHA-256")
        if (behavior) referenceDigest.update((binding.proof.originalBinarySha256 + "\n").toByteArray(Charsets.UTF_8))
        var matches = 0
        for (index in ids.indices) {
            val first = if (behavior) scope(1 + 2 * index, "reference", ids[index]) else null
            val second = if (behavior) scope(2 + 2 * index, "candidate", ids[index]) else null
            if (first != null) referenceDigest.update(buildString {
                append(ids[index].length).append(':').append(ids[index]).append(':').append(first.exit).append(':')
                append(recordedValidationOutputSha256(first.stdout.first)).append(':')
                append(recordedValidationOutputSha256(first.stderr.first)).append('\n')
            }.toByteArray(Charsets.UTF_8))
            val exitEqual = first?.let { it.exit == requireNotNull(second).exit }
            val stdoutEqual = first?.let { it.stdout.first == requireNotNull(second).stdout.first }
            val stderrEqual = first?.let { it.stderr.first == requireNotNull(second).stderr.first }
            val matched = exitEqual == true && stdoutEqual == true && stderrEqual == true
            if (matched) matches++
            if (index.toLong() < from || index.toLong() >= from + RECORDED_VALIDATION_CASES_PER_PAGE) continue
            val outcome = when {
                binding.outcome == RepairValidationObservedOutcome.COMPILE_FAILED -> RecordedRepairValidationCaseOutcome.COMPILE_FAILED
                !behavior -> RecordedRepairValidationCaseOutcome.COMPILE_ONLY
                matched -> RecordedRepairValidationCaseOutcome.MATCHED
                else -> RecordedRepairValidationCaseOutcome.MISMATCH
            }
            rows += RecordedRepairValidationCase(identities.case(ids[index]), index + 1, outcome, exitEqual, stdoutEqual,
                stderrEqual, first?.stdout?.second, second?.stdout?.second, first?.stderr?.second, second?.stderr?.second,
                first?.stdout?.let(::recordedValidationPreview), second?.stdout?.let(::recordedValidationPreview),
                first?.stderr?.let(::recordedValidationPreview), second?.stderr?.let(::recordedValidationPreview))
        }
        val declared = (root.getValue("matches") as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull
        if (behavior) require(HexFormat.of().formatHex(referenceDigest.digest()) == binding.expectedObservationsSha256)
        require(declared == (behavior && ids.isNotEmpty() && matches == ids.size))
        if (pageNumber > pages) RecordedRepairValidationCasePage(RecordedRepairValidationCaseState.OUT_OF_RANGE,
            pageNumber, pages, ids.size)
        else RecordedRepairValidationCasePage(RecordedRepairValidationCaseState.AVAILABLE, pageNumber, pages,
            ids.size, matches.takeIf { behavior }, rows)
    }.getOrElse { RecordedRepairValidationCasePage(RecordedRepairValidationCaseState.CORRUPT, pageNumber) }
}

/** Hash complete canonical output in bounded groups, rather than allocating another complete decoded stream. */
private fun recordedValidationOutputSha256(encoded: String): String {
    val digest = MessageDigest.getInstance("SHA-256")
    var offset = 0
    while (offset < encoded.length) {
        val end = minOf(encoded.length, offset + 8192)
        digest.update(java.util.Base64.getDecoder().decode(encoded.substring(offset, end)))
        offset = end
    }
    return HexFormat.of().formatHex(digest.digest())
}

/** Decode only bounded complete base64 groups; full-byte comparison above never uses this prefix. */
private fun recordedValidationPreview(encoded: Pair<String, Long>): RecordedRepairValidationPreview {
    val count = minOf(encoded.second, 128L).toInt()
    val characters = minOf(encoded.first.length, ((count + 2) / 3) * 4)
    val bytes = java.util.Base64.getDecoder().decode(encoded.first.substring(0, characters)).copyOf(count)
    val hexadecimal = "0123456789abcdef"
    val hex = buildString {
        bytes.forEachIndexed { index, byte ->
            if (index > 0) append(if (index % 16 == 0) '\n' else ' ')
            val value = byte.toInt() and 255
            append(hexadecimal[value ushr 4]); append(hexadecimal[value and 15])
        }
    }
    val input = java.nio.ByteBuffer.wrap(bytes)
    val output = java.nio.CharBuffer.allocate(count)
    val decoder = Charsets.UTF_8.newDecoder()
        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
    // A truncated UTF-8 suffix stays undecoded; malformed bytes are never replaced or dropped.
    val result = decoder.decode(input, output, encoded.second == count.toLong())
    val textBytes = input.position().takeIf { result.isUnderflow }
    val text = textBytes?.let {
        output.flip()
        val decoded = output.toString()
        buildString {
            var position = 0
            while (position < decoded.length) {
                val c = Character.codePointAt(decoded, position)
                position += Character.charCount(c)
                when (c) {
                    '\\'.code -> append("\\\\")
                    '\r'.code -> append("\\r")
                    '\n'.code -> append("\\n\n")
                    '\t'.code -> append("\\t")
                    else -> {
                        val category = Character.getType(c)
                        if (Character.isISOControl(c) || category == Character.FORMAT.toInt() ||
                            category == Character.LINE_SEPARATOR.toInt() || category == Character.PARAGRAPH_SEPARATOR.toInt()) {
                            val digits = if (c > 65535) 8 else 4
                            append(if (digits == 8) "\\U" else "\\u")
                            var shift = (digits - 1) * 4
                            while (shift >= 0) { append(hexadecimal[(c ushr shift) and 15]); shift -= 4 }
                        } else appendCodePoint(c)
                    }
                }
            }
        }
    }
    return RecordedRepairValidationPreview(encoded.second, count, hex, text, textBytes)
}

/** Canonical base64 has one spelling per byte sequence, so equality needs no decoded payload copy. */
private fun recordedValidationEncodedBytes(value: JsonElement): Pair<String, Long> {
    val encoded = (value as? JsonPrimitive)?.takeIf { it.isString }?.content ?: error("validation output base64 type")
    require(encoded.length % 4 == 0)
    val padding = if (encoded.endsWith("==")) 2 else if (encoded.endsWith('=')) 1 else 0
    val end = encoded.length - padding
    fun sextet(c: Char): Int = when (c) {
        in 'A'..'Z' -> c.code - 'A'.code
        in 'a'..'z' -> c.code - 'a'.code + 26
        in '0'..'9' -> c.code - '0'.code + 52
        '+' -> 62
        '/' -> 63
        else -> error("validation output base64 alphabet")
    }
    for (index in 0 until end) sextet(encoded[index])
    if (padding == 2) require((sextet(encoded[end - 1]) and 15) == 0)
    if (padding == 1) require((sextet(encoded[end - 1]) and 3) == 0)
    return encoded to (encoded.length.toLong() / 4L * 3L - padding)
}

/** Same corpus framing as the producer, without constructing a whole decoded/hex input payload. */
internal fun recordedNormalValidationCorpusSha256(rows: JsonArray): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val hexadecimal = "0123456789abcdef".toByteArray(Charsets.US_ASCII)
    val buffer = ByteArray(8192)
    var buffered = 0
    fun flush() { if (buffered != 0) { digest.update(buffer, 0, buffered); buffered = 0 } }
    fun ascii(value: String) { flush(); digest.update(value.toByteArray(Charsets.US_ASCII)) }
    fun text(value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        ascii("${bytes.size}:"); digest.update(bytes)
    }
    fun hex(value: Int) {
        buffer[buffered++] = hexadecimal[(value ushr 4) and 15]
        buffer[buffered++] = hexadecimal[value and 15]
        if (buffered == buffer.size) flush()
    }
    fun sextet(value: Char): Int = when (value) {
        in 'A'..'Z' -> value.code - 'A'.code
        in 'a'..'z' -> value.code - 'a'.code + 26
        in '0'..'9' -> value.code - '0'.code + 52
        '+' -> 62
        '/' -> 63
        else -> error("validation input base64 alphabet")
    }
    for (element in rows) {
        val row = element as? JsonObject ?: error("validation input type")
        require(row.keys == setOf("id", "args", "stdinBase64"))
        fun field(name: String) = (row.getValue(name) as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: error("validation input text type")
        text(field("id")); ascii("|")
        val arguments = row.getValue("args") as? JsonArray ?: error("validation input argument type")
        ascii("${arguments.size}|")
        for (argument in arguments) {
            text((argument as? JsonPrimitive)?.takeIf { it.isString }?.content ?: error("validation argument text type"))
            ascii("|")
        }
        val encoded = field("stdinBase64")
        require(encoded.length % 4 == 0)
        val padding = if (encoded.endsWith("==")) 2 else if (encoded.endsWith('=')) 1 else 0
        ascii("${encoded.length / 4 * 3 - padding}:")
        for (offset in encoded.indices step 4) {
            val a = sextet(encoded[offset]); val b = sextet(encoded[offset + 1])
            val c = encoded[offset + 2]; val d = encoded[offset + 3]
            val last = offset + 4 == encoded.length
            if (c == '=') {
                require(last && d == '=' && (b and 15) == 0)
                hex((a shl 2) or (b ushr 4))
            } else {
                val third = sextet(c)
                if (d == '=') {
                    require(last && (third and 3) == 0)
                    hex((a shl 2) or (b ushr 4)); hex((b shl 4) or (third ushr 2))
                } else {
                    val fourth = sextet(d)
                    hex((a shl 2) or (b ushr 4)); hex((b shl 4) or (third ushr 2)); hex((third shl 6) or fourth)
                }
            }
        }
        ascii("\n")
    }
    flush()
    return HexFormat.of().formatHex(digest.digest())
}

internal fun parseNormalValidationJson(bytes: ByteArray): JsonObject {
    require(bytes.size.toLong() in 1..MAXIMUM_RECORDED_REPAIR_EVIDENCE_REQUEST_BYTES)
    return OracleJson.parse(bytes, StrictJsonLimits(maximumInputBytes = bytes.size, maximumCanonicalBytes = bytes.size,
        maximumDepth = 20, maximumNodes = 1_000_000, maximumStringBytes = bytes.size,
        maximumTotalStringBytes = bytes.size)) as? JsonObject ?: error("validation artifact object type")
}
