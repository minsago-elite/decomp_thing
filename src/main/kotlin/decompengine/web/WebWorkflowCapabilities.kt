package decompengine.web

import decompengine.jobs.WorkflowKind
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

internal fun DurableWebWorkflowInput.wireName(): String = when (this) {
    DurableWebWorkflowInput.NONE -> "none"
    DurableWebWorkflowInput.ACCEPTED_OPTIONAL -> "accepted-optional"
    DurableWebWorkflowInput.RECORDED_REQUIRED -> "recorded-required"
}

/** Stable public identity of one launchable option, distinct from the harness identity it submits. */
internal fun webWorkflowCapabilityId(adapter: DurableWebWorkflowAdapter): String =
    "workflow-${adapter.workflow.wireName}-${checkNotNull(adapter.launch).mode.wireName}"

/**
 * Per-option workflow capabilities from registrations and the last prerequisite snapshot. `supported`
 * needs a registered production adapter and every declared prerequisite; a probe that did not finish
 * is `unknown`. Inert registrations without launch facts keep the general preview refusal.
 */
internal fun webWorkflowCapabilities(adapters: List<DurableWebWorkflowAdapter>, readiness: WebHarnessReadiness): List<JsonObject> {
    val described = adapters.filter { it.launch != null }
    if (described.isEmpty()) return listOf(capability("workflows", "unavailable", "PREVIEW_UNAVAILABLE",
        "Workflow actions are unavailable in this preview.", emptyList(), null, null, null))
    val options = described.map { adapter ->
        val launch = checkNotNull(adapter.launch)
        val prerequisites = readiness.prerequisites
        val unmet = prerequisites?.unmet(adapter.requirements)
        val (state, reason, message) = when {
            adapter.requirements.isNotEmpty() && prerequisites == null -> Triple("unknown", readiness.reasonCode ?: "PROBE_FAILED",
                "Runtime prerequisites could not be determined, so this workflow's availability is unknown. Refresh readiness to check again.")
            // An unchecked prerequisite (passive page load) is unknown, never supported.
            unmet != null -> Triple(if (unmet.unknown) "unknown" else "unavailable", unmet.reasonCode, unmet.message)
            else -> Triple("supported", null, "Every prerequisite this workflow declares was present at the last readiness check.")
        }
        capability(webWorkflowCapabilityId(adapter), state, reason, message, listOf(adapter.workflow),
            if (launch.contactsAgent) WEB_AGENT_CONTRACT_VERSION else null, adapter.limits, buildJsonObject {
                put("harnessCapabilityId", adapter.harnessCapabilityId?.let(::JsonPrimitive) ?: JsonNull)
                put("mode", launch.mode.wireName)
                put("executesBinary", launch.executesBinary)
                put("contactsAgent", launch.contactsAgent)
                put("requiredTools", JsonArray(launch.requiredTools.map(::JsonPrimitive)))
                put("input", adapter.input.wireName())
                put("limitsAdjustable", adapter.limitsAdjustable)
            })
    }
    val missing = WorkflowKind.entries.filter { kind -> described.none { it.workflow == kind } }.map { kind ->
        capability("workflow-${kind.wireName}", "unsupported", "WORKFLOW_NOT_IMPLEMENTED",
            "This server has no standalone ${kind.wireName} workflow. Reconstruction and repair build and validate their own candidates.",
            listOf(kind), null, null, null)
    }
    return options + missing
}

private fun capability(id: String, state: String, reason: String?, message: String, workflows: List<WorkflowKind>,
    agentContractVersion: Int?, limits: decompengine.jobs.WorkflowExecutionLimits?, launch: JsonObject?): JsonObject = buildJsonObject {
    put("id", id)
    put("state", state)
    put("reasonCode", reason?.let(::JsonPrimitive) ?: JsonNull)
    put("message", message)
    put("workflows", JsonArray(workflows.map { JsonPrimitive(it.wireName) }))
    put("agentContractVersion", agentContractVersion?.let(::JsonPrimitive) ?: JsonNull)
    put("limits", limits?.let { value -> buildJsonObject {
        put("wallClockMs", value.wallClockMs.toString()); put("idleMs", value.idleMs.toString())
        put("maxOutputBytes", value.maxOutputBytes.toString()); put("maxToolCalls", value.maxToolCalls.toString())
    } } ?: JsonNull)
    put("launch", launch ?: JsonNull)
}

/**
 * Prerequisites for one start request. Starting is an explicit operator action: when the selected
 * option needs the sandbox, its other prerequisites hold and the passive snapshot left the helpers
 * unchecked, this runs the bounded helper check now. No agent is needed for options that do not
 * contact one, and an unregistered option keeps the passive facts for the service to refuse.
 */
internal fun webAdmissionPrerequisites(
    adapters: List<DurableWebWorkflowAdapter>, request: decompengine.jobs.NewWorkflowAttempt,
    passive: WebWorkflowPrerequisites?, inspectSandbox: () -> WebPrerequisite,
): WebWorkflowPrerequisites? = webAdmissionPrerequisites(adapters, request.workflow, request.harnessCapabilityId, passive, inspectSandbox)

/** Same rule for a recovery command, selected by the predecessor's recorded workflow and harness. */
internal fun webAdmissionPrerequisites(
    adapters: List<DurableWebWorkflowAdapter>, workflow: WorkflowKind, harnessCapabilityId: String?,
    passive: WebWorkflowPrerequisites?, inspectSandbox: () -> WebPrerequisite,
): WebWorkflowPrerequisites? {
    val facts = passive ?: return null
    val adapter = adapters.firstOrNull { it.workflow == workflow && it.harnessCapabilityId == harnessCapabilityId }
        ?: adapters.singleOrNull { it.workflow == workflow }.takeIf { harnessCapabilityId == null }
        ?: return facts
    if (WebWorkflowRequirement.SANDBOX !in adapter.requirements || !facts.sandbox.unknown) return facts
    if (facts.copy(sandbox = WebPrerequisite.AVAILABLE).unmet(adapter.requirements) != null) return facts
    return facts.copy(sandbox = inspectSandbox())
}
