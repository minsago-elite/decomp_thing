package decompengine.acp

import com.agentclientprotocol.annotations.UnstableApi
import com.agentclientprotocol.model.SessionConfigOption
import com.agentclientprotocol.model.SessionConfigSelectOptions
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.jobs.ProgressRedactor
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive

/** Additional freshness restriction; the exact initial advertisement remains required authority. */
@OptIn(UnstableApi::class)
internal fun requireCurrentSessionConfigPreference(
    options: List<SessionConfigOption>,
    preference: AcpSessionConfigPreference,
    index: Int,
    sensitiveValues: Collection<String> = emptyList(),
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
    if (supported) return
    val redactor = ProgressRedactor(sensitiveValues)
    fun preview(values: Sequence<String>): String {
        val bounded = values.take(5).toList()
        val text = JsonArray(bounded.take(4).map { JsonPrimitive(redactor.text(it, 48)) }).toString()
        return text + if (bounded.size > 4) " (more choices omitted)" else ""
    }
    val optionIds = preview(options.asSequence().map { it.id.value })
    val values = when (option) {
        is SessionConfigOption.Select -> preview(when (val choices = option.options) {
            is SessionConfigSelectOptions.Flat -> choices.options.asSequence().map { it.value.value }
            is SessionConfigSelectOptions.Grouped -> choices.groups.asSequence().flatMap { it.options.asSequence() }.map { it.value.value }
        })
        is SessionConfigOption.BooleanOption -> "[false,true]"
        else -> "unavailable or ambiguous"
    }
    throw AgentExecutionException(AgentFailure(
        AgentFailureKind.CONFIGURATION,
        "ACP configured option no longer has an unambiguous match in the current session inventory. " +
            "Current option ID previews: $optionIds; value previews: $values",
        details = mapOf("preference" to "configOption", "preferenceIndex" to index.toString(),
            "reason" to "currentInventoryMismatch"),
    ))
}
