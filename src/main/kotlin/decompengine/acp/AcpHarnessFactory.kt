package decompengine.acp

import decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION
import decompengine.agent.AgentHarness
import decompengine.repair.HttpOpenAiCompatibleRepairClient
import decompengine.repair.RepairClientAgentHarness
import java.util.Collections

enum class AcpHarnessKind { ACP, LEGACY_OPENAI }

/** Stable, non-secret identity for the selected agent-execution boundary. */
data class AcpHarnessProvenance(
    val harness: String,
    val implementationId: String,
    val agentExecutionContractVersion: Int,
    val acpProtocolVersion: Int?,
    val acpSdkVersion: String?,
    val configurationSha256: String?,
    val deprecated: Boolean,
) {
    init {
        require(harness in setOf(ACP_HARNESS_NAME, LEGACY_OPENAI_HARNESS_NAME)) {
            "unknown harness provenance: $harness"
        }
        require(implementationId.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"))) {
            "harness implementation id is invalid"
        }
        require(agentExecutionContractVersion == AGENT_EXECUTION_CONTRACT_VERSION) {
            "unsupported agent execution contract version"
        }
        require(acpProtocolVersion == null || acpProtocolVersion == ACP_STABLE_PROTOCOL_VERSION) {
            "unsupported ACP protocol provenance"
        }
        require(acpSdkVersion == null || acpSdkVersion == ACP_KOTLIN_SDK_VERSION) {
            "unsupported ACP SDK provenance"
        }
        require(configurationSha256 == null || configurationSha256.matches(Regex("[0-9a-f]{64}"))) {
            "harness configuration digest must be lowercase SHA-256"
        }
        when (harness) {
            ACP_HARNESS_NAME -> require(
                !deprecated &&
                    acpProtocolVersion == ACP_STABLE_PROTOCOL_VERSION &&
                    acpSdkVersion == ACP_KOTLIN_SDK_VERSION &&
                    configurationSha256 != null
            ) { "ACP harness provenance must bind its protocol, SDK, and configuration" }
            LEGACY_OPENAI_HARNESS_NAME -> require(
                deprecated &&
                    acpProtocolVersion == null &&
                    acpSdkVersion == null &&
                    configurationSha256 == null
            ) { "legacy OpenAI harness provenance must be deprecated and must not claim ACP metadata" }
        }
    }

    /** A canonical identifier suitable for checkpoints and archive metadata. */
    val stableDescriptor: String = listOf(
        "agent-harness-v1",
        harness,
        "contract-$agentExecutionContractVersion",
        acpProtocolVersion?.let { "acp-$it" } ?: "acp-none",
        acpSdkVersion?.let { "sdk-$it" } ?: "sdk-none",
        "implementation-$implementationId",
        configurationSha256?.let { "configuration-$it" } ?: "configuration-none",
        if (deprecated) "deprecated" else "supported",
    ).joinToString(":")
}

/**
 * Immutable harness resolution. [createHarness] creates a fresh execution adapter so callers do
 * not accidentally share sticky cleanup state between unrelated workflows.
 */
class AcpHarnessSelection internal constructor(
    val kind: AcpHarnessKind,
    val configuration: AcpProcessConfiguration?,
    val provenance: AcpHarnessProvenance,
    private val harnessProvider: () -> AgentHarness,
) {
    fun createHarness(): AgentHarness = harnessProvider()
}

/**
 * Application-owned harness resolver.
 *
 * ACP is the default. Its complete process and containment authority comes from one bounded,
 * strict JSON document named by `ACP_CONFIG_FILE`. The legacy HTTP adapter remains available only
 * through the explicit `ACP_HARNESS=legacy-openai` compatibility selection.
 */
object AcpHarnessFactory {
    fun fromEnvironment(environment: Map<String, String> = System.getenv()): AcpHarnessSelection {
        val selected = environment[ACP_HARNESS_ENVIRONMENT] ?: ACP_HARNESS_NAME
        require(selected.isNotBlank()) { "$ACP_HARNESS_ENVIRONMENT must not be blank" }

        return when (selected) {
            ACP_HARNESS_NAME -> acpSelection(environment)
            LEGACY_OPENAI_HARNESS_NAME -> legacySelection(environment)
            else -> throw IllegalArgumentException(
                "unknown $ACP_HARNESS_ENVIRONMENT value " +
                    "(expected exactly $ACP_HARNESS_NAME or $LEGACY_OPENAI_HARNESS_NAME; " +
                    "direct is no longer supported)",
            )
        }
    }

    fun requireAcp(environment: Map<String, String> = System.getenv()): AcpProcessConfiguration {
        val selection = fromEnvironment(environment)
        require(selection.kind == AcpHarnessKind.ACP && selection.configuration != null) {
            "ACP harness required; remove $ACP_HARNESS_ENVIRONMENT or set it to $ACP_HARNESS_NAME"
        }
        return selection.configuration
    }

    private fun acpSelection(environment: Map<String, String>): AcpHarnessSelection {
        val obsolete = OBSOLETE_ACP_ENVIRONMENT.firstOrNull(environment::containsKey)
        require(obsolete == null) {
            "$obsolete is obsolete; provision ACP through the bounded $ACP_CONFIG_FILE_ENVIRONMENT document"
        }
        val configuredPath = environment[ACP_CONFIG_FILE_ENVIRONMENT]
            ?: throw IllegalArgumentException(
                "$ACP_CONFIG_FILE_ENVIRONMENT is required because ACP is the default harness",
            )
        require(configuredPath.isNotBlank()) { "$ACP_CONFIG_FILE_ENVIRONMENT must not be blank" }
        val provisioned = AcpHarnessProvisioning.load(configuredPath, environment)
        val configuration = provisioned.configuration
        val provenance = AcpHarnessProvenance(
            harness = ACP_HARNESS_NAME,
            implementationId = configuration.implementationId,
            agentExecutionContractVersion = AGENT_EXECUTION_CONTRACT_VERSION,
            acpProtocolVersion = ACP_STABLE_PROTOCOL_VERSION,
            acpSdkVersion = ACP_KOTLIN_SDK_VERSION,
            configurationSha256 = provisioned.canonicalSha256,
            deprecated = false,
        )
        return AcpHarnessSelection(AcpHarnessKind.ACP, configuration, provenance) {
            AcpAgentHarness(configuration)
        }
    }

    private fun legacySelection(environment: Map<String, String>): AcpHarnessSelection {
        val selectedEnvironment = LinkedHashMap<String, String>()
        LEGACY_OPENAI_ENVIRONMENT.forEach { name ->
            environment[name]?.let { selectedEnvironment[name] = it }
        }
        val frozenEnvironment = Collections.unmodifiableMap(selectedEnvironment)
        val provenance = AcpHarnessProvenance(
            harness = LEGACY_OPENAI_HARNESS_NAME,
            implementationId = "legacy-openai-compatible",
            agentExecutionContractVersion = AGENT_EXECUTION_CONTRACT_VERSION,
            acpProtocolVersion = null,
            acpSdkVersion = null,
            configurationSha256 = null,
            deprecated = true,
        )
        return AcpHarnessSelection(AcpHarnessKind.LEGACY_OPENAI, null, provenance) {
            RepairClientAgentHarness(HttpOpenAiCompatibleRepairClient.fromEnvironment(frozenEnvironment))
        }
    }
}

private const val ACP_HARNESS_ENVIRONMENT = "ACP_HARNESS"
private const val ACP_CONFIG_FILE_ENVIRONMENT = "ACP_CONFIG_FILE"
private const val ACP_HARNESS_NAME = "acp"
private const val LEGACY_OPENAI_HARNESS_NAME = "legacy-openai"
private val LEGACY_OPENAI_ENVIRONMENT = listOf("BASE_URL", "API_KEY", "MODEL", "REASONING_EFFORT")
private val OBSOLETE_ACP_ENVIRONMENT = listOf(
    "ACP_AGENT_EXECUTABLE",
    "ACP_AGENT_ARGS",
    "ACP_PERMISSION_MODE",
    "ACP_TIMEOUT_SECONDS",
)
