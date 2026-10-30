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
    // Recovery provenance states what a resume restored; a retry restores nothing from its predecessor.
    put("recovery", run.recovery?.let { recovery -> buildJsonObject {
        put("mode", recovery.mode.wireName)
        put("restores", recovery.restores?.wireName?.let(::JsonPrimitive) ?: JsonNull)
        put("checkpointSha256", recovery.checkpointSha256?.let(::JsonPrimitive) ?: JsonNull)
    } } ?: JsonNull)
    put("limits", buildJsonObject {
        put("wallClockMs", run.limits.wallClockMs.toString()); put("idleMs", run.limits.idleMs.toString())
        put("maxOutputBytes", run.limits.maxOutputBytes.toString()); put("maxToolCalls", run.limits.maxToolCalls.toString())
    })
    put("usage", run.usage?.let { usage -> buildJsonObject {
        fun count(name: String, value: ULong?) { put(name, value?.let { JsonPrimitive(it.toString()) } ?: JsonNull) }
        count("inputTokens", usage.inputTokens); count("outputTokens", usage.outputTokens)
        count("cachedInputTokens", usage.cachedInputTokens); count("toolCalls", usage.toolCalls); count("wallClockMs", usage.wallClockMs)
    } } ?: JsonNull)
    put("configuration", run.configuration?.let(::webRunConfiguration) ?: JsonNull)
}

/** The admission record as stored: identities, versions and a digest only, never configuration content. */
internal fun webRunConfiguration(value: decompengine.jobs.WorkflowAttemptConfiguration): JsonObject = buildJsonObject {
    put("optionId", value.optionId); put("mode", value.mode)
    put("executesBinary", value.executesBinary); put("contactsAgent", value.contactsAgent)
    put("requiredTools", JsonArray(value.requiredTools.map(::JsonPrimitive))); put("input", value.input)
    put("limitsAdjustable", value.limitsAdjustable)
    put("harness", value.harness?.let { harness -> buildJsonObject {
        put("kind", harness.kind)
        put("implementationId", harness.implementationId?.let(::JsonPrimitive) ?: JsonNull)
        put("agentContractVersion", harness.agentContractVersion)
        put("protocolVersion", harness.protocolVersion?.let(::JsonPrimitive) ?: JsonNull)
        put("sdkVersion", harness.sdkVersion?.let(::JsonPrimitive) ?: JsonNull)
        put("configurationSha256", harness.configurationSha256?.let(::JsonPrimitive) ?: JsonNull)
        put("deprecated", harness.deprecated)
    } } ?: JsonNull)
    // Retain the parent's required v1 placeholder for older clients; only reconstruction carries profile authority.
    put("profileId", JsonNull)
    put("reconstruction", value.reconstruction?.let { reconstruction -> buildJsonObject {
        put("profileId", reconstruction.profileId); put("profileSha256", reconstruction.profileSha256)
        put("maxContextCharacters", reconstruction.maxContextCharacters?.let { JsonPrimitive(it.toString()) } ?: JsonNull)
    } } ?: JsonNull)
}
