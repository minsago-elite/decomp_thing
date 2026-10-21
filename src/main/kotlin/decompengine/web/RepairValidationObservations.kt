package decompengine.web

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.sha256
import decompengine.repair.RepairRecordedValidationObservation
import decompengine.repair.RepairValidationObservedOutcome
import decompengine.repair.RepairValidationAssurance
import java.security.MessageDigest
import java.util.HexFormat
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
)

internal fun checkedRecordedRepairValidationObservation(binding: RepairRecordedValidationObservation,
    primaryBytes: ByteArray?, diffBytes: ByteArray?): RecordedRepairValidationObservationView {
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
        require(binding.diff == null || !matches)
        require(root.getValue("scopes") is JsonArray)
        if (binding.outcome == RepairValidationObservedOutcome.BEHAVIOR_CHECKED)
            require(inputs > 0 && completed == inputs)
        else require(completed == 0 && !matches)
        RecordedRepairValidationObservationView(RepairEvidenceArtifactState.AVAILABLE,
            outcome = binding.outcome, inputCount = inputs, completedCasePairs = completed)
    }.getOrElse { RecordedRepairValidationObservationView(RepairEvidenceArtifactState.CORRUPT) }
    if (primary.primaryState != RepairEvidenceArtifactState.AVAILABLE) return primary
    val diff = binding.diff ?: return primary
    val state = if (diffBytes == null || diffBytes.isEmpty()) RepairEvidenceArtifactState.UNAVAILABLE else {
        if (runCatching {
            require(diffBytes.size.toLong() == diff.bytes && sha256(diffBytes) == diff.sha256)
            val root = parseNormalValidationJson(diffBytes)
            require(root.keys == setOf("id", "matches", "cases"))
            require((root.getValue("id") as? JsonPrimitive)?.isString == true)
            require((root.getValue("matches") as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull == false)
            val cases = root.getValue("cases") as? JsonArray ?: error("derived validation cases type")
            val ids = cases.map { row -> ((row as? JsonObject)?.get("id") as? JsonPrimitive)
                ?.takeIf { it.isString }?.content ?: error("derived validation case identity type") }
            require(ids == expectedInputIds)
        }.isSuccess) RepairEvidenceArtifactState.AVAILABLE else RepairEvidenceArtifactState.CORRUPT
    }
    return primary.copy(diffState = state)
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

private fun parseNormalValidationJson(bytes: ByteArray): JsonObject {
    require(bytes.size.toLong() in 1..MAXIMUM_RECORDED_REPAIR_EVIDENCE_REQUEST_BYTES)
    return OracleJson.parse(bytes, StrictJsonLimits(maximumInputBytes = bytes.size, maximumCanonicalBytes = bytes.size,
        maximumDepth = 20, maximumNodes = 1_000_000, maximumStringBytes = bytes.size,
        maximumTotalStringBytes = bytes.size)) as? JsonObject ?: error("validation artifact object type")
}
