package decompengine.web

import decompengine.jobs.WorkflowAttemptConfiguration
import decompengine.jobs.WorkflowAttemptHarness
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

/**
 * Stable public identity of one launchable option, distinct from the harness identity it submits. Agent
 * options name their harness, so options for different harnesses of one workflow never share an identity.
 */
internal fun webWorkflowCapabilityId(adapter: DurableWebWorkflowAdapter): String = optionId(adapter.workflow, checkNotNull(adapter.launch))

private fun optionId(workflow: WorkflowKind, launch: DurableWebWorkflowLaunch): String =
    "workflow-${workflow.wireName}-${launch.mode.wireName}" + (launch.harness?.let { "-${it.wireName}" } ?: "")

/**
 * Per-option workflow capabilities from registrations and the last prerequisite snapshot. `supported`
 * needs a registered production adapter and every declared prerequisite; a probe that did not finish
 * is `unknown`. Inert registrations without launch facts keep the general preview refusal. Each agent
 * workflow also reports the built-in harness, which has no registration, as an `unsupported` option.
 */
internal fun webWorkflowCapabilities(adapters: List<DurableWebWorkflowAdapter>, readiness: WebHarnessReadiness): List<JsonObject> {
    val described = adapters.filter { it.launch != null }
    if (described.isEmpty()) return listOf(capability("workflows", "unavailable", "PREVIEW_UNAVAILABLE",
        "Workflow actions are unavailable in this preview.", emptyList(), null, null, null))
    val prerequisites = readiness.prerequisites
    // Supported operations per harness are this server's registrations, never an assumed product matrix.
    val operations = described.mapNotNull { adapter -> adapter.launch?.harness?.let { it to adapter.workflow } }
        .groupBy({ it.first }, { it.second })
    val options = described.map { adapter ->
        val launch = checkNotNull(adapter.launch)
        val unmet = prerequisites?.unmet(adapter.requirements, launch.harness)
        val (state, reason, message) = when {
            adapter.requirements.isNotEmpty() && prerequisites == null -> Triple("unknown", readiness.reasonCode ?: "PROBE_FAILED",
                "Runtime prerequisites could not be determined, so this workflow's availability is unknown. Refresh readiness to check again.")
            // An unchecked prerequisite (passive page load) is unknown, never supported.
            unmet != null -> Triple(if (unmet.unknown) "unknown" else "unavailable", unmet.reasonCode, unmet.message)
            else -> Triple("supported", null, "Every prerequisite this workflow declares was present at the last readiness check.")
        }
        capability(webWorkflowCapabilityId(adapter), state, reason, message, listOf(adapter.workflow),
            if (launch.contactsAgent) WEB_AGENT_CONTRACT_VERSION else null, adapter.limits,
            launchFacts(adapter.harnessCapabilityId, launch, adapter.input, adapter.limitsAdjustable,
                launch.harness?.let { harnessFacts(it, prerequisites, operations[it].orEmpty()) }))
    }
    // The built-in harness is shown, never selectable: the same launch shape, an unsupported state and no registration.
    val builtin = described.filter { it.launch?.harness == WebAgentHarness.ACP }.map { adapter ->
        val launch = checkNotNull(adapter.launch)
        val facts = WebWorkflowPrerequisites.BUILTIN_UNSUPPORTED
        capability("workflow-${adapter.workflow.wireName}-agent-${WebAgentHarness.BUILTIN.wireName}", "unsupported", facts.reasonCode,
            facts.message, listOf(adapter.workflow), WEB_AGENT_CONTRACT_VERSION, adapter.limits,
            launchFacts(WebAgentHarness.BUILTIN.capabilityId, launch, adapter.input, adapter.limitsAdjustable,
                harnessFacts(WebAgentHarness.BUILTIN, prerequisites, emptyList())))
    }
    val missing = WorkflowKind.entries.filter { kind -> described.none { it.workflow == kind } }.map { kind ->
        capability("workflow-${kind.wireName}", "unsupported", "WORKFLOW_NOT_IMPLEMENTED",
            "This server has no standalone ${kind.wireName} workflow. Reconstruction and repair build and validate their own candidates.",
            listOf(kind), null, null, null)
    }
    return options + builtin + missing
}

private fun launchFacts(harnessCapabilityId: String?, launch: DurableWebWorkflowLaunch, input: DurableWebWorkflowInput,
    limitsAdjustable: Boolean, harness: JsonObject?): JsonObject = buildJsonObject {
    put("harnessCapabilityId", harnessCapabilityId?.let(::JsonPrimitive) ?: JsonNull)
    put("mode", launch.mode.wireName)
    put("executesBinary", launch.executesBinary)
    put("contactsAgent", launch.contactsAgent)
    put("requiredTools", JsonArray(launch.requiredTools.map(::JsonPrimitive)))
    put("input", input.wireName())
    put("limitsAdjustable", limitsAdjustable)
    put("harness", harness ?: JsonNull)
}

/**
 * Transport-neutral harness facts: the harness kind is provenance, not a user-facing protocol choice.
 * Implementation identity comes only from a resolved configuration; credentials, paths and
 * configuration values are never read into this projection.
 */
private fun harnessFacts(harness: WebAgentHarness, prerequisites: WebWorkflowPrerequisites?, operations: List<WorkflowKind>): JsonObject {
    val provenance = prerequisites?.harnesses?.get(harness)?.provenance
    return buildJsonObject {
        put("kind", harness.wireName)
        put("implementationId", provenance?.implementationId?.let(::JsonPrimitive) ?: JsonNull)
        put("protocolVersion", provenance?.protocolVersion?.let(::JsonPrimitive) ?: JsonNull)
        put("deprecated", harness.deprecated)
        put("operations", JsonArray(WorkflowKind.entries.filter { it in operations }.map { JsonPrimitive(it.wireName) }))
    }
}

/**
 * The server-validated configuration recorded with a newly admitted attempt. Harness provenance is the
 * admission-time resolution of the option's single harness; a caller can neither supply nor change it.
 */
internal fun webAttemptConfiguration(adapter: DurableWebWorkflowAdapter, prerequisites: WebWorkflowPrerequisites?): WorkflowAttemptConfiguration? {
    val launch = adapter.launch ?: return null
    val harness = launch.harness?.let { selected ->
        val provenance = prerequisites?.harnesses?.get(selected)?.provenance
        WorkflowAttemptHarness(selected.wireName, provenance?.implementationId, provenance?.agentContractVersion ?: WEB_AGENT_CONTRACT_VERSION,
            provenance?.protocolVersion, provenance?.sdkVersion, provenance?.configurationSha256, selected.deprecated)
    }
    return WorkflowAttemptConfiguration(webWorkflowCapabilityId(adapter), launch.mode.wireName, launch.executesBinary,
        launch.contactsAgent, launch.requiredTools, adapter.input.wireName(), adapter.limitsAdjustable, harness)
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
): WebWorkflowPrerequisites? {
    val facts = passive ?: return null
    val adapter = adapters.firstOrNull { it.workflow == request.workflow && it.harnessCapabilityId == request.harnessCapabilityId }
        ?: return facts
    if (WebWorkflowRequirement.SANDBOX !in adapter.requirements || !facts.sandbox.unknown) return facts
    if (facts.copy(sandbox = WebPrerequisite.AVAILABLE).unmet(adapter.requirements, adapter.launch?.harness) != null) return facts
    return facts.copy(sandbox = inspectSandbox())
}
