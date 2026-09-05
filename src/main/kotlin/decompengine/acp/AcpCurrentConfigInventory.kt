package decompengine.acp

import com.agentclientprotocol.annotations.UnstableApi
import com.agentclientprotocol.model.SessionConfigOption
import com.agentclientprotocol.model.SessionConfigSelectOptions
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind

/** Additional freshness restriction; the exact initial advertisement remains required authority. */
@OptIn(UnstableApi::class)
internal fun requireCurrentSessionConfigPreference(
    options: List<SessionConfigOption>,
    preference: AcpSessionConfigPreference,
    index: Int,
) {
    val option = options.singleOrNull { it.id.value == preference.id }
    val supported = when (val value = preference.value) {
        is AcpSessionConfigValue.BooleanValue -> option is SessionConfigOption.BooleanOption
        is AcpSessionConfigValue.Select -> option is SessionConfigOption.Select && when (val choices = option.options) {
            is SessionConfigSelectOptions.Flat -> choices.options.count { it.value.value == value.valueId } == 1
            is SessionConfigSelectOptions.Grouped -> choices.groups.sumOf { group ->
                group.options.count { it.value.value == value.valueId }
            } == 1
        }
    }
    if (!supported) throw AgentExecutionException(AgentFailure(
        AgentFailureKind.CONFIGURATION,
        "ACP configured option no longer has an unambiguous match in the current session inventory",
        details = mapOf("preference" to "configOption", "preferenceIndex" to index.toString(),
            "reason" to "currentInventoryMismatch"),
    ))
}
