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

/** Screen the whole setter diagnostic, including fixed labels; keep protocol control metadata. */
internal fun sessionPreferenceSetterFailure(
    kind: String,
    index: Int?,
    sensitiveValues: Collection<String>,
    privatePreferences: Collection<String>,
    rpcCode: String? = null,
): AgentExecutionException = AgentExecutionException(AgentFailure(
    AgentFailureKind.PROTOCOL,
    redactedSessionPreferenceDiagnostic(
        if (rpcCode == null) "ACP session preference setter returned an invalid response"
        else "ACP session preference setter was rejected",
        "", sensitiveValues, privatePreferences,
    ),
    details = buildMap {
        put("preference", kind)
        index?.let { put("preferenceIndex", it.toString()) }
        rpcCode?.let { put("rpcCode", it) }
    },
))

/** A setter replaces the complete inventory; prior applied values must remain selectable too. */
@OptIn(UnstableApi::class)
internal fun requireAppliedSessionConfigPreferences(
    options: List<SessionConfigOption>,
    configuredPrefix: List<AcpSessionConfigPreference>,
    sensitiveValues: Collection<String>,
    privatePreferences: Collection<String>,
    invalidResponse: (Int) -> AgentExecutionException,
) {
    // Preserve the original response-consistency failures before the additional freshness check.
    configuredPrefix.forEachIndexed { index, preference ->
        val matches = options.filter { it.id.value == preference.id }
        if (matches.size != 1) throw invalidResponse(index)
        val applied = matches.single()
        val consistent = when (val requested = preference.value) {
            is AcpSessionConfigValue.Select ->
                applied is SessionConfigOption.Select && applied.currentValue.value == requested.valueId
            is AcpSessionConfigValue.BooleanValue ->
                applied is SessionConfigOption.BooleanOption && applied.currentValue == requested.value
        }
        if (!consistent) throw invalidResponse(index)
    }
    configuredPrefix.forEachIndexed { index, preference ->
        requireCurrentSessionConfigPreference(options, preference, index, sensitiveValues, privatePreferences)
    }
}

/** Additional freshness restriction; the exact initial advertisement remains required authority. */
@OptIn(UnstableApi::class)
internal fun requireCurrentSessionConfigPreference(
    options: List<SessionConfigOption>,
    preference: AcpSessionConfigPreference,
    index: Int,
    sensitiveValues: Collection<String> = emptyList(),
    privatePreferences: Collection<String> = listOfNotNull(preference.id, (preference.value as? AcpSessionConfigValue.Select)?.valueId),
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
    fun preview(values: Sequence<String>) = previewSessionChoices(values, sensitiveValues, privatePreferences)
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
        redactedSessionPreferenceDiagnostic(
            "ACP configured option no longer has an unambiguous match in the current session inventory.",
            " Current option ID previews: $optionIds; value previews: $values",
            sensitiveValues, privatePreferences,
        ),
        details = mapOf("preference" to "configOption", "preferenceIndex" to index.toString(),
            "reason" to "currentInventoryMismatch"),
    ))
}

/** Labels, boolean literals and hint boundaries are part of the privacy-checked message. */
internal fun redactedSessionPreferenceDiagnostic(
    base: String,
    hint: String,
    sensitiveValues: Collection<String>,
    privatePreferences: Collection<String>,
): String {
    val redactor = ProgressRedactor(sensitiveValues, privatePreferences)
    fun publishable(value: String): Boolean = value.isNotBlank() &&
        sensitiveValues.none { it.isNotEmpty() && value.contains(it) } &&
        privatePreferences.none { it.isNotEmpty() && value.contains(it) }
    // Leave room for the existing truncation marker within a 1,024-character diagnostic.
    val complete = redactor.text(base + hint, 1000)
    if (publishable(complete)) return complete
    val safeBase = redactor.text(base, 1000)
    if (publishable(safeBase)) return safeBase
    // Raw whitespace-only environment values are checked above even though the shared
    // progress policy ignores them. A single nonblank indicator cannot reproduce them.
    return redactor.nonBlankText("", 1000)
}

/** Complete configured identifiers used only as additional redaction inputs. */
internal fun AcpSessionPreferences.privateIdentifiers(): List<String> =
    listOfNotNull(modelId, modeId) + configOptions.flatMap {
        listOfNotNull(it.id, (it.value as? AcpSessionConfigValue.Select)?.valueId)
    }

/** Display-only previews; never selection tokens or authority for a setter. */
internal fun previewSessionChoices(values: Sequence<String>, sensitiveValues: Collection<String>,
    privatePreferences: Collection<String> = emptyList()): String {
    val redactor = ProgressRedactor(sensitiveValues, privatePreferences)
    val bounded = values.take(5).toList()
    val text = JsonArray(bounded.take(4).map { JsonPrimitive(redactor.text(it, 48)) }).toString()
    val formatted = text + if (bounded.size > 4) " (more choices omitted)" else ""
    // Redaction markers, JSON quoting and omission text can synthesize a configured secret.
    // No fixed replacement is safe for arbitrary identifiers; omit this display-only hint.
    return if (redactor.leaks(formatted) || privatePreferences.any { it.isNotEmpty() && formatted.contains(it) }) "" else formatted
}
