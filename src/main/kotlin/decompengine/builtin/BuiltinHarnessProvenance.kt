package decompengine.builtin

import decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION
import decompengine.builtin.provider.MODEL_PROVIDER_CONTRACT_VERSION
import kotlinx.serialization.json.*

/** Portable configuration identity. Credentials, environment names and endpoint/state paths stay private. */
class BuiltinHarnessProvenance internal constructor(
    val configurationSha256: String,
    val model: String,
    val fixtureOnly: Boolean,
) {
    val implementationId = "builtin-captured-repair-v1"
    val provider = "openai-compatible"
    val agentContractVersion = AGENT_EXECUTION_CONTRACT_VERSION
    val providerContractVersion = MODEL_PROVIDER_CONTRACT_VERSION
    init {
        require(configurationSha256.matches(Regex("[a-f0-9]{64}")))
        require(model.matches(Regex("[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}")))
    }
    internal fun json() = buildJsonObject {
        put("schemaVersion", 1); put("harness", "builtin"); put("implementationId", implementationId)
        put("agentContractVersion", agentContractVersion); put("providerContractVersion", providerContractVersion)
        put("provider", provider); put("model", model); put("configurationSha256", configurationSha256)
        put("fixtureOnly", fixtureOnly)
    }
    val stableDescriptor: String get() = "agent-harness-v1:builtin:contract-$agentContractVersion:" +
        "provider-$provider:provider-contract-$providerContractVersion:implementation-$implementationId:" +
        "configuration-$configurationSha256:${if (fixtureOnly) "fixture" else "configured"}"
    override fun equals(other: Any?) = other is BuiltinHarnessProvenance && configurationSha256 == other.configurationSha256 &&
        model == other.model && fixtureOnly == other.fixtureOnly
    override fun hashCode() = 31 * (31 * configurationSha256.hashCode() + model.hashCode()) + fixtureOnly.hashCode()
    override fun toString() = "BuiltinHarnessProvenance($stableDescriptor)"
}

internal fun parseBuiltinHarnessProvenance(value: JsonElement): BuiltinHarnessProvenance {
    val root = value.jsonObject
    val parsed = BuiltinHarnessProvenance(root.getValue("configurationSha256").jsonPrimitive.content,
        root.getValue("model").jsonPrimitive.content, root.getValue("fixtureOnly").jsonPrimitive.boolean)
    require(parsed.json() == root) { "built-in factory provenance has invalid or extra fields" }
    return parsed
}
