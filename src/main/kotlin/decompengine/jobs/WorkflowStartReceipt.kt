package decompengine.jobs

import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.MessageDigest

/** Storage identity only; never execution, validation, acceptance, or scheduling authority. */
data class WorkflowStartReceipt(
    val runId: String,
    val requestKeyDigest: String,
    val expectedRequestVersion: String,
    val intentSha256: String,
) {
    internal fun encode(): JsonObject = buildJsonObject {
        put("runId", runId); put("requestKeyDigest", requestKeyDigest)
        put("expectedRequestVersion", expectedRequestVersion); put("intentSha256", intentSha256)
    }

    internal fun validate(attempt: WorkflowAttempt) {
        require(runId == attempt.runId && DIGEST.matches(requestKeyDigest) && DIGEST.matches(intentSha256)) {
            "invalid workflow start receipt identity"
        }
        require(VERSION.matches(expectedRequestVersion)) { "invalid workflow start request version" }
        require(intentSha256 == workflowStartIntentSha256(expectedRequestVersion, NewWorkflowAttempt(
            attempt.workflow, attempt.limits, attempt.inputRevisionId, attempt.harnessCapabilityId, attempt.previousRunId,
            recovery = attempt.recovery, scope = attempt.scope,
        ))) { "workflow start receipt intent differs from its attempt" }
    }

    companion object {
        internal fun decode(value: JsonObject): WorkflowStartReceipt {
            require(value.keys == setOf("runId", "requestKeyDigest", "expectedRequestVersion", "intentSha256")) {
                "invalid workflow start receipt fields"
            }
            fun string(name: String): String = (value.getValue(name) as? JsonPrimitive)
                ?.takeIf(JsonPrimitive::isString)?.content ?: error("workflow start receipt string required")
            return WorkflowStartReceipt(string("runId"), string("requestKeyDigest"),
                string("expectedRequestVersion"), string("intentSha256"))
        }
    }
}

/** Scoped to the durable job, not a listener/session lifetime; authorization is the service caller's duty. */
internal fun workflowStartKeyDigest(jobId: String, requestKey: String): String {
    require(jobId.matches(Regex("[0-9a-f]{32}"))) { "invalid workflow start job identity" }
    if (!requestKey.matches(Regex("[A-Za-z0-9_-]{16,128}"))) {
        throw WorkflowStoreException("INVALID_IDEMPOTENCY_KEY", "The workflow start request key is invalid.")
    }
    return sha("decomp-workflow-start-key-v1\u0000$jobId\u0000$requestKey".toByteArray(Charsets.US_ASCII))
}

internal fun workflowStartIntentSha256(expectedRequestVersion: String, request: NewWorkflowAttempt): String {
    require(VERSION.matches(expectedRequestVersion)) { "invalid workflow start request version" }
    // A recovery command has its own closed intent; a plain start's existing digest is unchanged.
    request.recovery?.let { recovery ->
        return workflowRecoveryIntentSha256(expectedRequestVersion, checkNotNull(request.previousRunId), recovery.mode, request.inputRevisionId)
    }
    val intent = buildJsonObject {
        put("expectedRequestVersion", expectedRequestVersion)
        put("workflow", request.workflow.wireName); put("inputRevisionId", request.inputRevisionId)
        put("harnessCapabilityId", request.harnessCapabilityId); put("previousRunId", request.previousRunId)
        put("limits", buildJsonObject {
            put("wallClockMs", request.limits.wallClockMs.toString()); put("idleMs", request.limits.idleMs.toString())
            put("maxOutputBytes", request.limits.maxOutputBytes.toString()); put("maxToolCalls", request.limits.maxToolCalls.toString())
        })
        // Absent for starts without a scope, so receipts recorded before scopes existed keep their digest.
        request.scope?.let { put("scope", it.encode()) }
    }
    return sha("decomp-workflow-start-intent-v1\u0000".toByteArray(Charsets.US_ASCII) + OracleJson.canonicalBytes(intent))
}

internal data class WorkflowStartResult(val snapshot: WorkflowJobSnapshot, val attempt: WorkflowAttempt, val replayed: Boolean)

private val VERSION = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
private val DIGEST = Regex("[0-9a-f]{64}")
private fun sha(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
    .joinToString("") { "%02x".format(it) }
