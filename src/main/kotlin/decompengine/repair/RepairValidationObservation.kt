package decompengine.repair

import java.nio.file.Path
import java.io.OutputStream
import java.io.OutputStreamWriter
import java.security.MessageDigest
import java.util.Collections
import java.util.HexFormat
import decompengine.project.sha256
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull

/** Returned validation operation, independent of the later candidate acceptance decision. */
enum class RepairValidationObservedOutcome { COMPILE_FAILED, COMPILE_VALID, BEHAVIOR_CHECKED }

/** A primary receipt and a derived diff have distinct roles even when both are JSON. */
data class RepairValidationObservedArtifact(val path: String, val sha256: String, val bytes: Long) {
    init {
        require((validationReportPath(path) || validationObservationDiffPath(path)) &&
            validationDigest(sha256) && bytes in 1..64L * 1024 * 1024)
    }

    internal fun toJsonObject() = JsonObject(mapOf("path" to JsonPrimitive(path),
        "sha256" to JsonPrimitive(sha256), "bytes" to JsonPrimitive(bytes)))
}

internal const val REPAIR_VALIDATION_DIFF_PREFIX = "reports/repair-revisions/validation-diffs/"
private val VALIDATION_DIFF_NAME = Regex("([0-9a-f]{64})\\.json")
private val VALIDATION_DIFF_TEMP = Regex("\\.([0-9a-f]{64}\\.json)\\.repair-atomic\\.tmp")

internal fun repairValidationDiffPath(digest: String): String {
    require(validationDigest(digest))
    return REPAIR_VALIDATION_DIFF_PREFIX + digest + ".json"
}

internal fun validationObservationDiffPath(path: String): Boolean =
    path.startsWith(REPAIR_VALIDATION_DIFF_PREFIX) && VALIDATION_DIFF_NAME.matches(path.removePrefix(REPAIR_VALIDATION_DIFF_PREFIX))

/** One new directory entry at the revision root; its own population is at most runs + attempts. */
internal fun repairValidationDiffDirectoryEntryLimit(budget: RepairResourceBudget): Int =
    Math.addExact(Math.multiplyExact(budget.maximumRevisionNodes, 2), 16)

internal data class RepairValidationDiffOrphan(val targetName: String, val observedName: String, val sha256: String)
internal data class RepairValidationDiffDirectoryPlan(val temporaryTargets: List<String>, val orphans: List<RepairValidationDiffOrphan>)

/** Admit every name before any cleanup. Only exact, content-addressed application roles are owned. */
internal fun planRepairValidationDiffDirectory(names: List<String>, retained: List<RepairValidationObservedArtifact>,
    maximumEntries: Int): RepairValidationDiffDirectoryPlan {
    require(maximumEntries >= 0 && names.size <= maximumEntries && names.distinct().size == names.size)
    val active = linkedMapOf<String, String>()
    val temporaries = ArrayList<String>()
    for (name in names) {
        val temporary = VALIDATION_DIFF_TEMP.matchEntire(name)
        if (temporary != null) { temporaries += temporary.groupValues[1]; continue }
        val base = name.removeSuffix(".cleanup")
        require(VALIDATION_DIFF_NAME.matches(base)) { "validation diff directory contains an unowned entry" }
        require(active.putIfAbsent(base, name) == null) { "validation diff has both active and quarantined entries" }
    }
    val retainedByName = linkedMapOf<String, RepairValidationObservedArtifact>()
    retained.forEach { artifact ->
        require(artifact.path == repairValidationDiffPath(artifact.sha256))
        val name = artifact.sha256 + ".json"
        val previous = retainedByName.putIfAbsent(name, artifact)
        require(previous == null || previous == artifact)
        require(active[name] == name) { "retained validation diff is missing or quarantined" }
    }
    return RepairValidationDiffDirectoryPlan(Collections.unmodifiableList(ArrayList(temporaries)),
        Collections.unmodifiableList(active.filterKeys { it !in retainedByName }.map { (base, observed) ->
            RepairValidationDiffOrphan(base, observed, base.removeSuffix(".json"))
        }))
}

/** The provider emits a derived role exactly for nonmatching normal behavior. */
internal fun requireRepairValidationDiffRole(outcome: RepairValidationObservedOutcome, matches: Boolean, hasDiff: Boolean) {
    require(if (outcome == RepairValidationObservedOutcome.BEHAVIOR_CHECKED) hasDiff == !matches else !hasDiff && !matches) {
        "normal validation match flag and derived role disagree"
    }
}

/** Cleanup's quarantine guard verifies the exact admitted payload twice before unlink. */
internal fun reserveRepairValidationDiffCleanupBytes(bytes: Long, remaining: Long): Long {
    require(bytes in 1..64L * 1024 * 1024 && remaining in 0..2L * 64 * 1024 * 1024)
    if (bytes > remaining / 2) throw RepairBudgetExceededException("validation diff cleanup exceeds its evidence allowance")
    return remaining - 2L * bytes
}

internal data class RepairValidationPublishedArtifact(val path: Path, val sha256: String, val bytes: Long)

/** Commit the exact writer encoding without allocating a second whole UTF-8 payload. */
internal fun repairValidationPublishedTextArtifact(path: Path, text: String): RepairValidationPublishedArtifact {
    val digest = MessageDigest.getInstance("SHA-256")
    var bytes = 0L
    val sink = object : OutputStream() {
        override fun write(value: Int) { digest.update(value.toByte()); bytes = Math.addExact(bytes, 1L) }
        override fun write(value: ByteArray, offset: Int, length: Int) {
            digest.update(value, offset, length)
            bytes = Math.addExact(bytes, length.toLong())
        }
    }
    OutputStreamWriter(sink, Charsets.UTF_8).use { it.write(text) }
    return RepairValidationPublishedArtifact(path, HexFormat.of().formatHex(digest.digest()), bytes)
}

/** Recorded proof correlation only; this value cannot accept a revision or grant execution. */
data class RepairValidationObservation(
    val invocation: RepairValidationInvocation,
    val proof: RepairValidationProof,
    val outcome: RepairValidationObservedOutcome,
    val primary: RepairValidationObservedArtifact,
    val diff: RepairValidationObservedArtifact? = null,
) {
    val comparisonPolicy: String get() = "exact-bytes-v1"

    init {
        require(proof.sourceRevisionSha256 == invocation.sourceRevisionSha256 &&
            proof.profileSha256 == invocation.profileSha256 && proof.indexSha256 == invocation.indexSha256 &&
            proof.regressionCorpusSha256 == invocation.regressionCorpusSha256)
        require(proof.cleanupVerified && proof.assurance == RepairValidationAssurance.STRICT_CONTAINED)
        require(validationDigest(proof.runtimeSha256) && validationDigest(proof.evidenceSha256))
        require(proof.originalBinarySha256 == null || validationDigest(proof.originalBinarySha256))
        require(proof.rebuiltBinarySha256 == null || validationDigest(proof.rebuiltBinarySha256))
        require(primary.sha256 == proof.evidenceSha256)
        require(primary.path == "reports/${invocation.id}.validation.json")
        require(outcome != RepairValidationObservedOutcome.COMPILE_FAILED || proof.rebuiltBinarySha256 == null)
        require(outcome != RepairValidationObservedOutcome.COMPILE_VALID ||
            proof.originalBinarySha256 == null && proof.rebuiltBinarySha256 != null)
        require(outcome != RepairValidationObservedOutcome.BEHAVIOR_CHECKED ||
            proof.originalBinarySha256 != null && proof.rebuiltBinarySha256 != null)
        require(diff == null || outcome == RepairValidationObservedOutcome.BEHAVIOR_CHECKED &&
            diff.path == repairValidationDiffPath(diff.sha256))
    }

    internal fun requireRetainedBudget(maximumBytes: Long) {
        val pairBytes = primary.bytes + (diff?.bytes ?: 0)
        require(maximumBytes >= 0 && pairBytes <= 64L * 1024 * 1024 && 2L * pairBytes <= maximumBytes) {
            "validation observation exceeds the retained evidence byte bound"
        }
    }

    internal fun toJsonObject() = JsonObject(mapOf(
        "schemaVersion" to JsonPrimitive(1), "invocation" to invocation.toJsonObject(),
        "proof" to Json.parseToJsonElement(proof.toStateJson()), "outcome" to JsonPrimitive(outcome.name.lowercase()),
        "comparisonPolicy" to JsonPrimitive(comparisonPolicy), "primary" to primary.toJsonObject(),
        "diff" to (diff?.toJsonObject() ?: JsonNull),
    ))
}

/** Canonical and archive readers enforce the same selected-run association independently. */
internal fun requireRepairValidationObservationAssociation(observation: RepairValidationObservation,
    runId: String, profileSha256: String, indexSha256: String, corpusSha256: String,
    candidateRevisionId: String, candidateSourceSha256: String, originalBinarySha256: String?) {
    val invocation = observation.invocation
    require(invocation.runId == runId && invocation.profileSha256 == profileSha256 &&
        invocation.indexSha256 == indexSha256 && invocation.regressionCorpusSha256 == corpusSha256 &&
        invocation.candidateRevisionId == candidateRevisionId && invocation.sourceRevisionSha256 == candidateSourceSha256 &&
        observation.proof.originalBinarySha256 == originalBinarySha256) {
        "validation observation is cross-paired with its selected run or candidate"
    }
}

/** Authenticate reported bytes before retaining fixed canonical roles, then allow the owning commit. */
internal class RepairValidationObservationRetention internal constructor(
    val observation: RepairValidationObservation,
    private val sources: List<Pair<RepairValidationPublishedArtifact, RepairValidationObservedArtifact>>,
) {
    fun retain(read: (Path, Long) -> ByteArray, write: (String, ByteArray) -> Unit,
        readRetained: (String, Long) -> ByteArray) {
        val captured = sources.map { (source, target) ->
            val bytes = read(source.path, target.bytes)
            require(bytes.size.toLong() == target.bytes && sha256(bytes) == target.sha256)
            target to bytes
        }
        captured.forEach { (target, bytes) -> write(target.path.removePrefix("reports/"), bytes) }
        captured.forEach { (target, bytes) ->
            require(readRetained(target.path.removePrefix("reports/"), target.bytes).contentEquals(bytes))
        }
    }
}

internal fun planRepairValidationObservationRetention(invocation: RepairValidationInvocation,
    proof: RepairValidationProof, outcome: RepairValidationObservedOutcome,
    primary: RepairValidationPublishedArtifact, diff: RepairValidationPublishedArtifact?,
    maximumBytes: Long): RepairValidationObservationRetention {
    val primaryPath = primary.path.toAbsolutePath().normalize()
    val primaryName = primaryPath.fileName.toString()
    require(primaryName.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}\\.validation\\.json")))
    val normalizedPrimary = primary.copy(path = primaryPath)
    val normalizedDiff = diff?.let {
        val path = it.path.toAbsolutePath().normalize()
        require(path.parent == primaryPath.parent &&
            path.fileName.toString() == primaryName.removeSuffix(".validation.json") + ".diff.json")
        it.copy(path = path)
    }
    fun artifact(value: RepairValidationPublishedArtifact, suffix: String) = RepairValidationObservedArtifact(
        if (suffix == "diff") repairValidationDiffPath(value.sha256) else "reports/${invocation.id}.validation.json",
        value.sha256, value.bytes)
    val observation = RepairValidationObservation(invocation, proof, outcome, artifact(normalizedPrimary, "validation"),
        normalizedDiff?.let { artifact(it, "diff") })
    observation.requireRetainedBudget(maximumBytes)
    val sources = listOf(normalizedPrimary to observation.primary) +
        (normalizedDiff?.let { listOf(it to requireNotNull(observation.diff)) } ?: emptyList())
    return RepairValidationObservationRetention(observation, sources)
}

/** Copies caller lists; every entry consists solely of immutable typed values. */
class RepairValidationObservationLog(entries: List<RepairValidationObservation>) {
    val entries: List<RepairValidationObservation> = Collections.unmodifiableList(ArrayList(entries))

    init {
        require(this.entries.map { it.invocation.id }.distinct().size == this.entries.size)
        require(this.entries.map { it.invocation.candidateRevisionId }.distinct().size == this.entries.size)
    }

    internal fun appended(value: RepairValidationObservation) = RepairValidationObservationLog(entries + value)
    internal fun toJsonArray() = JsonArray(entries.map { it.toJsonObject() })
    override fun equals(other: Any?): Boolean = other is RepairValidationObservationLog && entries == other.entries
    override fun hashCode(): Int = entries.hashCode()
    override fun toString(): String = "RepairValidationObservationLog(size=${entries.size})"

    companion object { val EMPTY = RepairValidationObservationLog(emptyList()) }
}

internal fun parseRepairValidationObservation(value: JsonObject): RepairValidationObservation {
    require(value.keys == setOf("schemaVersion", "invocation", "proof", "outcome", "comparisonPolicy", "primary", "diff"))
    require(value.validationNumber("schemaVersion").longOrNull == 1L)
    require(value.validationText("comparisonPolicy") == "exact-bytes-v1")
    val outcome = value.validationText("outcome")
    require(outcome in RepairValidationObservedOutcome.entries.map { it.name.lowercase() })
    val proof = value.getValue("proof") as? JsonObject ?: error("validation observation proof type")
    require(proof.keys == setOf("sourceRevisionSha256", "profileSha256", "indexSha256", "regressionCorpusSha256",
        "originalBinarySha256", "rebuiltBinarySha256", "runtimeSha256", "evidenceSha256", "cleanupVerified", "assurance"))
    for (field in proof.keys - setOf("cleanupVerified", "originalBinarySha256", "rebuiltBinarySha256")) proof.validationText(field)
    for (field in setOf("originalBinarySha256", "rebuiltBinarySha256"))
        if (proof.getValue(field) !is JsonNull) proof.validationText(field)
    require(proof.validationNumber("cleanupVerified").booleanOrNull == true)
    require(proof.validationText("assurance") == "strict_contained")
    fun artifact(element: kotlinx.serialization.json.JsonElement): RepairValidationObservedArtifact {
        val artifact = element as? JsonObject ?: error("validation observation artifact type")
        require(artifact.keys == setOf("path", "sha256", "bytes"))
        return RepairValidationObservedArtifact(artifact.validationText("path"), artifact.validationText("sha256"),
            requireNotNull(artifact.validationNumber("bytes").longOrNull))
    }
    return RepairValidationObservation(parseRepairValidationInvocation(value.getValue("invocation").jsonObject),
        parseRepairValidationProof(proof), RepairValidationObservedOutcome.valueOf(outcome.uppercase()),
        artifact(value.getValue("primary")), value.getValue("diff").takeUnless { it is JsonNull }?.let(::artifact))
}

internal fun parseRepairValidationObservationLog(value: JsonArray, maximumEntries: Long): RepairValidationObservationLog {
    require(maximumEntries >= 0 && value.size.toLong() <= maximumEntries)
    return RepairValidationObservationLog(value.map { parseRepairValidationObservation(it as? JsonObject
        ?: error("validation observation type")) })
}
