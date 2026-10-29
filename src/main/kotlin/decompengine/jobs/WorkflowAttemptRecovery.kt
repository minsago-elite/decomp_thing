package decompengine.jobs

import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.MessageDigest

/** An explicit recovery command. Retry always creates a new attempt; resume continues a verified checkpoint. */
enum class WorkflowRecoveryMode(val wireName: String) { RETRY("retry"), RESUME("resume") }

/** What a verified resume restores. Project evidence alone never implies a restored agent conversation. */
enum class WorkflowResumeRestoration(val wireName: String) { AGENT_SESSION("agent-session"), PROJECT_EVIDENCE("project-evidence") }

/**
 * Durable provenance of a recovery attempt, recorded atomically with the attempt and its keyed receipt.
 * The checkpoint digest identifies trusted workflow-owned evidence; it is not execution, validation or acceptance authority.
 */
data class WorkflowAttemptRecovery(
    val mode: WorkflowRecoveryMode,
    val restores: WorkflowResumeRestoration? = null,
    val checkpointSha256: String? = null,
) {
    init {
        when (mode) {
            WorkflowRecoveryMode.RETRY -> require(restores == null && checkpointSha256 == null) { "a retry restores no checkpoint" }
            WorkflowRecoveryMode.RESUME -> require(restores != null && checkpointSha256?.matches(SHA256) == true) {
                "a resume requires a verified checkpoint identity and restoration scope"
            }
        }
    }

    internal fun encode(): JsonObject = buildJsonObject {
        put("mode", mode.wireName)
        put("restores", restores?.wireName?.let(::JsonPrimitive) ?: JsonNull)
        put("checkpointSha256", checkpointSha256?.let(::JsonPrimitive) ?: JsonNull)
    }

    companion object {
        internal fun decode(value: JsonObject): WorkflowAttemptRecovery {
            require(value.keys == setOf("mode", "restores", "checkpointSha256")) { "invalid workflow recovery fields" }
            fun text(name: String): String? = when (val field = value.getValue(name)) {
                JsonNull -> null
                is JsonPrimitive -> field.takeIf(JsonPrimitive::isString)?.content ?: error("workflow recovery string required")
                else -> error("workflow recovery string required")
            }
            return WorkflowAttemptRecovery(
                WorkflowRecoveryMode.entries.single { it.wireName == text("mode") },
                text("restores")?.let { name -> WorkflowResumeRestoration.entries.single { it.wireName == name } },
                text("checkpointSha256"),
            )
        }
    }
}

/**
 * Recovery replay identity binds only caller-observable intent: the exact predecessor attempt and its
 * version, the mode and the expected input revision. Server-selected limits/harness never make a replay conflict.
 */
internal fun workflowRecoveryIntentSha256(expectedRunVersion: String, previousRunId: String,
    mode: WorkflowRecoveryMode, inputRevisionId: String?): String {
    require(VERSION.matches(expectedRunVersion) && VERSION.matches(previousRunId)) { "invalid workflow recovery identity" }
    inputRevisionId?.let { require(VERSION.matches(it)) { "invalid workflow recovery input revision" } }
    val intent = buildJsonObject {
        put("expectedRunVersion", expectedRunVersion); put("previousRunId", previousRunId)
        put("mode", mode.wireName); put("inputRevisionId", inputRevisionId)
    }
    return MessageDigest.getInstance("SHA-256")
        .digest("decomp-workflow-recover-intent-v1\u0000".toByteArray(Charsets.US_ASCII) + OracleJson.canonicalBytes(intent))
        .joinToString("") { "%02x".format(it) }
}

private val VERSION = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
private val SHA256 = Regex("[0-9a-f]{64}")
