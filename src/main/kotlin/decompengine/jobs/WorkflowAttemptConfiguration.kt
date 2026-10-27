package decompengine.jobs

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.put

/**
 * Non-secret agent harness provenance resolved by the server when an attempt was admitted. It never
 * carries configuration text, paths, credentials or environment values; the configuration digest is
 * the canonical digest the harness factory computed, so a later configuration change is visible.
 */
data class WorkflowAttemptHarness(
    val kind: String,
    val implementationId: String?,
    val agentContractVersion: Int,
    val protocolVersion: Int?,
    val sdkVersion: String?,
    val configurationSha256: String?,
    val deprecated: Boolean,
) {
    init {
        require(kind in HARNESS_KINDS) { "unknown recorded harness kind" }
        require(implementationId == null || IMPLEMENTATION.matches(implementationId)) { "invalid recorded harness implementation" }
        require(agentContractVersion in 1..65_535 && (protocolVersion == null || protocolVersion in 1..65_535))
        require(sdkVersion == null || SDK_VERSION.matches(sdkVersion)) { "invalid recorded harness SDK version" }
        require(configurationSha256 == null || DIGEST.matches(configurationSha256)) { "invalid recorded harness configuration digest" }
    }

    internal fun encode(): JsonObject = buildJsonObject {
        put("kind", kind); put("implementationId", implementationId); put("agentContractVersion", agentContractVersion)
        put("protocolVersion", protocolVersion); put("sdkVersion", sdkVersion); put("configurationSha256", configurationSha256)
        put("deprecated", deprecated)
    }

    internal companion object {
        val HARNESS_KINDS = setOf("acp", "legacy-openai")
        fun decode(value: JsonObject): WorkflowAttemptHarness {
            require(value.keys == setOf("kind", "implementationId", "agentContractVersion", "protocolVersion", "sdkVersion",
                "configurationSha256", "deprecated")) { "invalid recorded harness fields" }
            return WorkflowAttemptHarness(value.text("kind"), value.optionalText("implementationId"), value.integer("agentContractVersion"),
                value.optionalInteger("protocolVersion"), value.optionalText("sdkVersion"), value.optionalText("configurationSha256"),
                value.flag("deprecated"))
        }
    }
}

/**
 * The server-validated configuration an attempt was admitted with. It is recorded atomically with the
 * attempt and never rewritten, so a later server configuration change creates a different record on a
 * new attempt instead of mutating past provenance.
 */
data class WorkflowAttemptConfiguration(
    val optionId: String,
    val mode: String,
    val executesBinary: Boolean,
    val contactsAgent: Boolean,
    val requiredTools: List<String>,
    val input: String,
    val limitsAdjustable: Boolean,
    val harness: WorkflowAttemptHarness?,
    val profileId: String? = null,
) {
    init {
        require(OPTION.matches(optionId)) { "invalid recorded option identity" }
        require(mode in MODES && contactsAgent == (mode == "agent")) { "invalid recorded launch mode" }
        require((harness != null) == contactsAgent) { "recorded harness provenance must match agent contact" }
        require(requiredTools.size <= 8 && requiredTools.distinct() == requiredTools && requiredTools.all { it in TOOLS })
        require(input in INPUTS) { "invalid recorded input policy" }
        require(profileId == null || PROFILE.matches(profileId)) { "invalid recorded profile identity" }
    }

    internal fun encode(): JsonObject = buildJsonObject {
        put("optionId", optionId); put("mode", mode); put("executesBinary", executesBinary); put("contactsAgent", contactsAgent)
        put("requiredTools", JsonArray(requiredTools.map(::JsonPrimitive))); put("input", input)
        put("limitsAdjustable", limitsAdjustable); put("harness", harness?.encode() ?: JsonNull)
        put("profileId", profileId)
    }

    internal companion object {
        private val MODES = setOf("tools", "agent", "evidence-only")
        private val INPUTS = setOf("none", "accepted-optional", "recorded-required")
        private val TOOLS = setOf("sandbox", "ghidra", "agent-harness", "c-toolchain", "angr")

        fun decode(value: JsonObject): WorkflowAttemptConfiguration {
            require(value.keys == setOf("optionId", "mode", "executesBinary", "contactsAgent", "requiredTools", "input",
                "limitsAdjustable", "harness", "profileId")) { "invalid recorded configuration fields" }
            val tools = (value.getValue("requiredTools") as? JsonArray ?: error("tool list required")).map { it.textValue() }
            return WorkflowAttemptConfiguration(value.text("optionId"), value.text("mode"), value.flag("executesBinary"),
                value.flag("contactsAgent"), tools, value.text("input"), value.flag("limitsAdjustable"),
                value.objectOrNull("harness")?.let(WorkflowAttemptHarness::decode), value.optionalText("profileId"))
        }
    }
}

private val OPTION = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
private val IMPLEMENTATION = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
private val PROFILE = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
private val SDK_VERSION = Regex("[0-9A-Za-z][0-9A-Za-z.+-]{0,63}")
private val DIGEST = Regex("[0-9a-f]{64}")

private fun JsonElement.textValue(): String = (this as? JsonPrimitive)?.takeIf { it.isString }?.content ?: error("string required")
private fun JsonObject.text(key: String): String = getValue(key).textValue()
private fun JsonObject.optionalText(key: String): String? = getValue(key).takeUnless { it == JsonNull }?.textValue()
private fun JsonObject.flag(key: String): Boolean =
    (getValue(key) as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull ?: error("boolean required")
private fun JsonObject.integer(key: String): Int =
    (getValue(key) as? JsonPrimitive)?.takeUnless { it.isString }?.intOrNull ?: error("integer required")
private fun JsonObject.optionalInteger(key: String): Int? = if (getValue(key) == JsonNull) null else integer(key)
private fun JsonObject.objectOrNull(key: String): JsonObject? =
    getValue(key).takeUnless { it == JsonNull }?.let { it as? JsonObject ?: error("object required") }
