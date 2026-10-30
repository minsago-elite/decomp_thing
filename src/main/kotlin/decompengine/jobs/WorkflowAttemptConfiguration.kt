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
 * Bounded reconstruction scope a start may request. The deterministic planner still owns every module
 * boundary; a scope can only lower the per-module agent context budget, never select or order modules.
 */
data class WorkflowReconstructionScope(val maxContextCharacters: ULong) {
    init { require(maxContextCharacters in 1uL..MAXIMUM_CONTEXT_CHARACTERS) { "invalid reconstruction scope" } }

    internal fun encode(): JsonObject = buildJsonObject { put("maxContextCharacters", maxContextCharacters.toString()) }

    internal companion object {
        const val MAXIMUM_CONTEXT_CHARACTERS: ULong = 16_777_216uL
        fun decode(value: JsonObject): WorkflowReconstructionScope {
            require(value.keys == setOf("maxContextCharacters")) { "invalid reconstruction scope fields" }
            return WorkflowReconstructionScope(value.decimal("maxContextCharacters"))
        }
    }
}

/**
 * The reconstruction profile and effective per-module context budget an attempt ran with. A
 * different profile digest means a different deterministic plan; a different budget or harness
 * means retained module checkpoints are regenerated rather than reused.
 */
data class WorkflowAttemptReconstruction(val profileId: String, val profileSha256: String, val maxContextCharacters: ULong?) {
    init {
        require(PROFILE.matches(profileId) && DIGEST.matches(profileSha256)) { "invalid recorded reconstruction profile" }
        require(maxContextCharacters == null || maxContextCharacters in 1uL..WorkflowReconstructionScope.MAXIMUM_CONTEXT_CHARACTERS)
    }

    internal fun encode(): JsonObject = buildJsonObject {
        put("profileId", profileId); put("profileSha256", profileSha256); put("maxContextCharacters", maxContextCharacters?.toString())
    }

    internal companion object {
        fun decode(value: JsonObject): WorkflowAttemptReconstruction {
            require(value.keys == setOf("profileId", "profileSha256", "maxContextCharacters")) { "invalid recorded reconstruction fields" }
            return WorkflowAttemptReconstruction(value.text("profileId"), value.text("profileSha256"),
                if (value.getValue("maxContextCharacters") == JsonNull) null else value.decimal("maxContextCharacters"))
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
    val reconstruction: WorkflowAttemptReconstruction? = null,
) {
    init {
        require(OPTION.matches(optionId)) { "invalid recorded option identity" }
        require(mode in MODES && contactsAgent == (mode == "agent")) { "invalid recorded launch mode" }
        require((harness != null) == contactsAgent) { "recorded harness provenance must match agent contact" }
        require(requiredTools.size <= 8 && requiredTools.distinct() == requiredTools && requiredTools.all { it in TOOLS })
        require(input in INPUTS) { "invalid recorded input policy" }
        require(reconstruction?.maxContextCharacters == null || contactsAgent) { "only agent reconstruction records a context budget" }
    }

    internal fun encode(): JsonObject = buildJsonObject {
        put("optionId", optionId); put("mode", mode); put("executesBinary", executesBinary); put("contactsAgent", contactsAgent)
        put("requiredTools", JsonArray(requiredTools.map(::JsonPrimitive))); put("input", input)
        put("limitsAdjustable", limitsAdjustable); put("harness", harness?.encode() ?: JsonNull)
        put("reconstruction", reconstruction?.encode() ?: JsonNull)
    }

    internal companion object {
        private val MODES = setOf("tools", "agent", "evidence-only")
        private val INPUTS = setOf("none", "accepted-optional", "recorded-required")
        private val TOOLS = setOf("sandbox", "ghidra", "agent-harness", "c-toolchain", "angr")

        private val BASE_FIELDS = setOf("optionId", "mode", "executesBinary", "contactsAgent", "requiredTools", "input",
            "limitsAdjustable", "harness")

        /**
         * Accepts the current record and the earlier one with a `profileId` field, which no admission ever set to
         * a value; that earlier record carries no reconstruction profile digest, so it decodes as unrecorded.
         */
        fun decode(value: JsonObject): WorkflowAttemptConfiguration {
            val current = value.keys == BASE_FIELDS + "reconstruction"
            val earlier = value.keys == BASE_FIELDS + "profileId" && value.getValue("profileId") == JsonNull
            require(current || earlier) { "invalid recorded configuration fields" }
            val tools = (value.getValue("requiredTools") as? JsonArray ?: error("tool list required")).map { it.textValue() }
            return WorkflowAttemptConfiguration(value.text("optionId"), value.text("mode"), value.flag("executesBinary"),
                value.flag("contactsAgent"), tools, value.text("input"), value.flag("limitsAdjustable"),
                value.objectOrNull("harness")?.let(WorkflowAttemptHarness::decode),
                if (current) value.objectOrNull("reconstruction")?.let(WorkflowAttemptReconstruction::decode) else null)
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
private fun JsonObject.decimal(key: String): ULong = text(key).let { value ->
    require(value.matches(Regex("0|[1-9][0-9]{0,19}"))) { "decimal required" }; value.toULong()
}
private fun JsonObject.flag(key: String): Boolean =
    (getValue(key) as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull ?: error("boolean required")
private fun JsonObject.integer(key: String): Int =
    (getValue(key) as? JsonPrimitive)?.takeUnless { it.isString }?.intOrNull ?: error("integer required")
private fun JsonObject.optionalInteger(key: String): Int? = if (getValue(key) == JsonNull) null else integer(key)
private fun JsonObject.objectOrNull(key: String): JsonObject? =
    getValue(key).takeUnless { it == JsonNull }?.let { it as? JsonObject ?: error("object required") }
