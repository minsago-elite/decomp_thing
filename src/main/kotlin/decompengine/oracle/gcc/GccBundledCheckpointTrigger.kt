package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Fresh planning threshold; neither a detached progress record nor this trigger proves interruption. */
internal class GccBundledCheckpointTrigger(val minimumCompletedFunctions: Long) {
    private var observed: GccExportProgressAssessment? = null
    private val policy = OracleJson.canonicalBytes(JsonObject(mapOf(
        "provider" to JsonPrimitive("gcc-bundled-planning-interrupt-policy-v1"),
        "minimumCompletedFunctions" to JsonPrimitive(minimumCompletedFunctions),
    )))
    val policyBytes: ByteArray get() = policy.copyOf()

    init {
        require(minimumCompletedFunctions in 512L..Long.MAX_VALUE && minimumCompletedFunctions % 512L == 0L) {
            "GCC interruption threshold must be a positive whole planning batch"
        }
    }

    fun observe(progress: GccExportProgressAssessment?): ByteArray? {
        check(observed == null) { "GCC checkpoint trigger was already selected" }
        if (progress == null) return null
        require(progress.reused == 0L) { "fresh GCC progress unexpectedly reused prior records" }
        if (progress.phase != "planning" || progress.completed < minimumCompletedFunctions ||
            progress.completed >= progress.total) return null
        require(progress.completed % 512L == 0L) { "GCC planning progress is not at a whole checkpoint" }
        observed = progress
        return OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-bundled-planning-interrupt-trigger-v1"),
            "stateSha256" to JsonPrimitive(progress.stateSha256),
            "progressSha256" to JsonPrimitive(progress.artifactSha256),
            "completed" to JsonPrimitive(progress.completed),
            "total" to JsonPrimitive(progress.total),
        )))
    }

    fun requireUnchangedStoppedPrefix(expected: GccInterruptedPrefixAssessment, current: GccInterruptedPrefixAssessment) {
        require(assessStoppedPrefix(current).contentEquals(assessStoppedPrefix(expected))) {
            "GCC retained export prefix differs from its stopped assessment"
        }
    }

    fun assessStoppedPrefix(prefix: GccInterruptedPrefixAssessment, planningPrefixSha256: String? = null, inFlightArtifacts: ByteArray? = null,
        capturedProgress: ByteArray? = null, effectiveProgress: ByteArray? = null): ByteArray {
        require(planningPrefixSha256 == null || planningPrefixSha256.matches(Regex("[a-f0-9]{64}")))
        require((capturedProgress == null) == (effectiveProgress == null)) { "GCC stopped progress evidence must be paired" }
        if (effectiveProgress != null) require(OracleArtifacts.sha256(effectiveProgress) == prefix.progressSha256) {
            "GCC effective progress differs from the stopped assessment"
        }
        val trigger = checkNotNull(observed) { "GCC interruption lacks its selected planning trigger" }
        require(prefix.stateSha256 == trigger.stateSha256 && prefix.functionCount == trigger.total &&
            prefix.completed >= trigger.completed && prefix.completed < prefix.functionCount && prefix.reused == 0L
        ) { "GCC stopped prefix does not extend the observed fresh planning checkpoint" }
        val unsigned = JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-bundled-stopped-prefix-assessment-v1"),
            "byteAssessmentAuthority" to JsonPrimitive(prefix.authority),
            "stateSha256" to JsonPrimitive(prefix.stateSha256),
            "triggerProgressSha256" to JsonPrimitive(trigger.artifactSha256),
            "progressSha256" to JsonPrimitive(prefix.progressSha256),
            "functionCount" to JsonPrimitive(prefix.functionCount),
            "completed" to JsonPrimitive(prefix.completed),
            "observedBatchCount" to JsonPrimitive(prefix.observedBatchCount),
            "declaredInventorySha256" to JsonPrimitive(prefix.declaredInventorySha256),
            "partial" to JsonPrimitive(prefix.partial), "failed" to JsonPrimitive(prefix.failed),
            "reused" to JsonPrimitive(prefix.reused),
            "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
        ) + (planningPrefixSha256?.let { mapOf("planningPrefixSha256" to JsonPrimitive(it)) } ?: emptyMap()) +
            (inFlightArtifacts?.let { mapOf(
                "inFlightArtifacts" to OracleJson.parseCanonical(it),
                "inFlightArtifactsSha256" to JsonPrimitive(OracleArtifacts.sha256(it)),
            ) } ?: emptyMap()) + (capturedProgress?.let { mapOf(
                "capturedProgressUtf8" to JsonPrimitive(it.toString(Charsets.UTF_8)),
                "capturedProgressSha256" to JsonPrimitive(OracleArtifacts.sha256(it)),
                "effectiveProgressUtf8" to JsonPrimitive(checkNotNull(effectiveProgress).toString(Charsets.UTF_8)),
                "effectiveProgressDerived" to JsonPrimitive(!it.contentEquals(effectiveProgress)),
            ) } ?: emptyMap()))
        return OracleJson.canonicalBytes(JsonObject(unsigned + ("assessmentSha256" to
            JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned))))))
    }
}
