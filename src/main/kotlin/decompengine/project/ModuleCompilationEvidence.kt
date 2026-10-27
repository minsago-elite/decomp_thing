package decompengine.project

import java.util.Collections
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

/** Compiler facts and retained proof are distinct from a live coordinator-issued acceptance permit. */
internal class ModuleCompilationEvidence(
    val sourceSha256: String,
    command: List<String>,
    val outcome: String,
    val returnCode: Int?,
    val diagnosticsSha256: String,
    val diagnosticsBytes: Long,
    containedProof: JsonObject? = null,
    internal val liveAuthority: VerifiedContainedModuleCompilation? = null,
) {
    val command: List<String> = Collections.unmodifiableList(ArrayList(command))
    val containedProof: JsonObject? = containedProof?.let { Json.parseToJsonElement(it.toString()).jsonObject }
    val passed: Boolean get() = outcome == "passed" && returnCode == 0
    val recordedAssurance: String get() = if (containedProof == null) "historical-local-host" else "recorded-contained-module"

    init {
        require(liveAuthority == null || this.containedProof != null) { "module compiler permit lacks retained proof" }
        if (this.containedProof != null) ContainedModuleCompilationProof.verify(this)
    }

    fun authorizesAcceptance(expectedSourceSha256: String, expectedProfileSha256: String, expectedPolicyId: String): Boolean {
        val authority = liveAuthority ?: return false
        if (!passed || sourceSha256 != expectedSourceSha256 || containedProof == null) return false
        ContainedModuleCompilationProof.verify(this)
        return authority.matches(this, expectedSourceSha256, expectedProfileSha256, expectedPolicyId)
    }

    // Preserve the exact historical six-field representation when no contained proof exists.
    fun toJson(): String = buildString {
        append("{\"sourceSha256\":\"").append(sourceSha256).append("\",\"command\":[")
        append(command.joinToString(",") { JsonPrimitive(it).toString() })
        append("],\"outcome\":\"").append(outcome).append("\",\"returnCode\":")
        append(returnCode ?: "null")
        append(",\"diagnosticsSha256\":\"").append(diagnosticsSha256)
        append("\",\"diagnosticsBytes\":").append(diagnosticsBytes)
        containedProof?.let { append(",\"containedProof\":").append(it) }
        append('}')
    }

    companion object {
        private val HISTORICAL_FIELDS = setOf("sourceSha256", "command", "outcome", "returnCode", "diagnosticsSha256", "diagnosticsBytes")
        private val OUTCOMES = setOf("passed", "failed", "failed-to-start", "timed-out", "source-changed", "output-limit-exceeded")
        private val DIGEST = Regex("[0-9a-f]{64}")

        /** Recorded JSON never issues live authority, including a structurally valid contained proof. */
        fun decode(value: JsonObject, checkpointVersion: Int, profile: ReconstructionProfile, sourcePath: String,
            expectedSourceSha256: String, accepted: Boolean): ModuleCompilationEvidence {
            require(checkpointVersion in 2..7) { "unsupported module compiler checkpoint version" }
            require(value.keys == HISTORICAL_FIELDS || checkpointVersion == 7 &&
                value.keys == HISTORICAL_FIELDS + "containedProof") { "module compiler evidence has unsupported fields" }
            fun text(name: String): String = (value[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
                ?: throw IllegalArgumentException("module compiler $name must be a string")
            val source = text("sourceSha256")
            require(DIGEST.matches(source) && source == expectedSourceSha256) { "module compiler evidence does not bind the checkpoint source" }
            val command = value.getValue("command").jsonArray.map { item ->
                (item as? JsonPrimitive)?.takeIf { it.isString }?.content
                    ?: throw IllegalArgumentException("module compiler argument must be a string")
            }
            val policy = ReconstructionCompilationPolicies.resolve(profile)
            require(command == policy.commandForCheckpoint(profile, sourcePath, checkpointVersion)) {
                "module compiler command differs from its reconstruction profile"
            }
            val outcome = text("outcome")
            require(outcome in OUTCOMES) { "module compiler outcome is unsupported" }
            val code = value.getValue("returnCode").let { item ->
                if (item is JsonNull) null else {
                    val parsed = (item as? JsonPrimitive)?.takeUnless { it.isString }?.intOrNull
                        ?: throw IllegalArgumentException("module compiler return code must be an integer or null")
                    require(parsed >= 0) { "module compiler return code is invalid" }
                    parsed
                }
            }
            require(!accepted || outcome == "passed" && code == 0) { "accepted module did not pass its compiler gate" }
            val diagnostics = text("diagnosticsSha256")
            require(DIGEST.matches(diagnostics)) { "module compiler diagnostic commitment is invalid" }
            val bytes = (value["diagnosticsBytes"] as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull
                ?: throw IllegalArgumentException("module compiler diagnostic byte count must be an integer")
            require(bytes in 0..profile.budgets.buildMaximumOutputBytes) { "module compiler diagnostics exceed the profile budget" }
            val proof = value["containedProof"]?.let {
                it as? JsonObject ?: throw IllegalArgumentException("module compiler contained proof must be an object")
            }
            require(checkpointVersion < 7 || !accepted || proof != null) {
                "current accepted module lacks contained compiler proof"
            }
            val evidence = ModuleCompilationEvidence(source, command, outcome, code, diagnostics, bytes, proof)
            if (proof != null) {
                require(proof["profileId"] == JsonPrimitive(profile.id) && proof["profileSha256"] == JsonPrimitive(profile.sha256) &&
                    proof["policyId"] == JsonPrimitive(policy.id)) { "contained compiler proof differs from its reconstruction profile or policy" }
                ContainedModuleCompilationProof.verify(evidence)
            }
            return evidence
        }
    }
}
