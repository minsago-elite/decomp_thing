package decompengine.web

import decompengine.jobs.WorkflowAttempt
import kotlinx.serialization.json.*

/** A stored attempt is not evidence of acceptance unless its trusted publication reference exists. */
internal fun webRun(run: WorkflowAttempt): JsonObject = buildJsonObject {
    fun nullable(name: String, value: String?) { put(name, value?.let(::JsonPrimitive) ?: JsonNull) }
    put("runId", run.runId); put("jobId", run.jobId); put("workflow", run.workflow.wireName)
    put("state", run.state.wireName); put("version", run.version); put("createdAt", run.createdAt.toString())
    nullable("startedAt", run.startedAt?.toString()); nullable("endedAt", run.endedAt?.toString())
    nullable("previousRunId", run.previousRunId); nullable("inputRevisionId", run.inputRevisionId)
    nullable("resultRevisionId", run.acceptedRevision?.revisionId ?: run.candidate?.revisionId)
    put("acceptance", if (run.acceptedRevision != null) "accepted" else "not-evaluated")
    nullable("harnessCapabilityId", run.harnessCapabilityId); nullable("terminalReason", run.terminalReason?.name)
    put("limits", buildJsonObject {
        put("wallClockMs", run.limits.wallClockMs.toString()); put("idleMs", run.limits.idleMs.toString())
        put("maxOutputBytes", run.limits.maxOutputBytes.toString()); put("maxToolCalls", run.limits.maxToolCalls.toString())
    })
    put("usage", run.usage?.let { usage -> buildJsonObject {
        fun count(name: String, value: ULong?) { put(name, value?.let { JsonPrimitive(it.toString()) } ?: JsonNull) }
        count("inputTokens", usage.inputTokens); count("outputTokens", usage.outputTokens)
        count("cachedInputTokens", usage.cachedInputTokens); count("toolCalls", usage.toolCalls); count("wallClockMs", usage.wallClockMs)
    } } ?: JsonNull)
}
