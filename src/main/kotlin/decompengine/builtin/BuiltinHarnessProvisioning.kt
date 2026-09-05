package decompengine.builtin

import decompengine.agent.readPrivateConfigurationFile
import decompengine.builtin.provider.*
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*
import java.nio.file.Path
import java.time.Duration

internal class BuiltinProvisioningException : IllegalArgumentException("Built-in harness configuration unavailable or invalid")

internal class BuiltinProvisioningPreflight(val journalReady: Boolean, val limits: BuiltinLoopLimits,
    val provenance: BuiltinHarnessProvenance) {
    val capturedRepair = true
    val reconstruction = false
    val terminalTools = false
    val checkpointResume = false
    val authenticationChecked = false
    val releaseQualified = false
    val externalValidationRequired = true
}

/** A frozen, application-owned selection. Every adapter uses the validated provider and tool implementation. */
internal class ProvisionedBuiltinHarness internal constructor(
    private val providerConfiguration: OpenAiCompatibleConfiguration,
    private val journalDirectory: Path,
    private val journalFactory: BuiltinRepairJournalFactory,
    private val limits: BuiltinLoopLimits,
    val provenance: BuiltinHarnessProvenance,
) {
    fun createCapturedRepairHarness(): BuiltinCapturedRepairHarness = BuiltinCapturedRepairHarness(
        OpenAiCompatibleModelProvider(providerConfiguration), limits, secrets = listOf(providerConfiguration.apiKey),
        journalFactory = journalFactory,
    ).bindFactoryProvenance(provenance)

    /** Filesystem/configuration checks only; does not contact the provider or create journal entries. */
    fun preflight(): BuiltinProvisioningPreflight = BuiltinProvisioningPreflight(
        runCatching { BuiltinJournal.verifyParent(journalDirectory.resolve("preflight.jsonl")); true }.getOrDefault(false),
        limits, provenance,
    )
    override fun toString() = "ProvisionedBuiltinHarness(redacted)"
}

/** Strict private provisioning seam; the operator-facing shared factory is wired after workflow qualification. */
internal object BuiltinHarnessProvisioning {
    fun load(configuredPath: String, environment: Map<String, String>): ProvisionedBuiltinHarness =
        load(configuredPath, environment, fixtureOnly = false)

    /** Numeric-loopback HTTP is only available in the explicitly labeled internal fixture path. */
    internal fun loadLoopbackFixture(configuredPath: String, environment: Map<String, String>): ProvisionedBuiltinHarness =
        load(configuredPath, environment, fixtureOnly = true)

    private fun load(configuredPath: String, environment: Map<String, String>, fixtureOnly: Boolean): ProvisionedBuiltinHarness = try {
        val path = absolutePath(configuredPath)
        val document = OracleJson.parse(readPrivateConfigurationFile(path, CONFIG_BYTES, "BUILTIN_CONFIG_FILE"), JSON_LIMITS).jsonObject
        document.keysExactly("schemaVersion", "provider", "journal", "loop")
        require(document.integer("schemaVersion") == 1L)
        val provider = document.getValue("provider").jsonObject
        provider.keysExactly("kind", "baseUrl", "model", "apiKeyEnvironment")
        require(provider.text("kind") == "openai-compatible")
        val environmentName = provider.text("apiKeyEnvironment")
        require(environmentName.matches(Regex("[A-Za-z_][A-Za-z0-9_]{0,127}")))
        val credential = requireNotNull(environment[environmentName])
        val configuration = OpenAiCompatibleConfiguration(provider.text("baseUrl"), provider.text("model"), credential,
            supportsTools = true, allowLoopbackHttp = fixtureOnly)
        if (fixtureOnly) require(configuration.endpoint.scheme == "http")
        val loop = parseLoop(document.getValue("loop").jsonObject)
        val journal = document.getValue("journal").jsonObject
        journal.keysExactly("directory", "maximumBytes", "maximumRecordBytes", "maximumRecords")
        val directory = absolutePath(journal.text("directory"))
        val provenance = BuiltinHarnessProvenance(checkpointHash(OracleJson.canonicalBytes(document, JSON_LIMITS)),
            configuration.model, fixtureOnly)
        require(!provenance.json().toString().contains(credential))
        val journalFactory = BuiltinRepairJournalFactory(directory, provenance.provider, provenance.model,
            journal.integer("maximumBytes"), journal.int("maximumRecordBytes"), journal.int("maximumRecords"), provenance)
        // The archive producer has tighter limits than the lower-level journal's generic hard caps.
        require(journal.integer("maximumBytes") <= 64L * 1024 * 1024 && journal.int("maximumRecordBytes") <= 8 * 1024 * 1024 &&
            journal.int("maximumRecords") <= 10_000)
        ProvisionedBuiltinHarness(configuration, directory, journalFactory, loop, provenance)
    } catch (_: Exception) { throw BuiltinProvisioningException() }

    private fun parseLoop(value: JsonObject): BuiltinLoopLimits {
        value.keysExactly("maxContextBytes", "maxToolResultBytes", "maxIdenticalActions", "maxTraceRecords", "maxInputTokens",
            "maxOutputTokens", "maximumEvidenceBytes", "contextHistoryReserveBytes", "provider")
        val provider = value.getValue("provider").jsonObject
        provider.keysExactly("connectTimeoutMillis", "requestTimeoutMillis", "streamIdleTimeoutMillis", "overallTimeoutMillis",
            "maxRequestBytes", "maxResponseBytes", "maxEventBytes", "maxToolCalls", "maxOutputTokens", "maxRetries",
            "retryBaseDelayMillis", "maxRetryDelayMillis")
        fun duration(name: String) = Duration.ofMillis(provider.integer(name))
        val calls = ModelCallLimits(duration("connectTimeoutMillis"), duration("requestTimeoutMillis"),
            duration("streamIdleTimeoutMillis"), duration("overallTimeoutMillis"), provider.int("maxRequestBytes"),
            provider.int("maxResponseBytes"), provider.int("maxEventBytes"), provider.int("maxToolCalls"),
            provider.int("maxOutputTokens"), provider.int("maxRetries"), duration("retryBaseDelayMillis"), duration("maxRetryDelayMillis"))
        return BuiltinLoopLimits(value.int("maxContextBytes"), value.int("maxToolResultBytes"), value.int("maxIdenticalActions"),
            value.int("maxTraceRecords"), value.integer("maxInputTokens"), value.integer("maxOutputTokens"),
            value.integer("maximumEvidenceBytes"), value.int("contextHistoryReserveBytes"), calls)
    }

    private fun absolutePath(value: String): Path {
        require(value.toByteArray(Charsets.UTF_8).size <= 4096)
        return Path.of(value).also { require(it.isAbsolute && it.normalize() == it) }
    }
    private fun JsonObject.keysExactly(vararg names: String) = require(keys == names.toSet())
    private fun JsonObject.text(name: String) = getValue(name).jsonPrimitive.also { require(it.isString) }.content
    private fun JsonObject.integer(name: String): Long {
        val value = getValue(name).jsonPrimitive
        require(!value.isString && value.content.matches(Regex("-?(0|[1-9][0-9]*)")))
        return value.long
    }
    private fun JsonObject.int(name: String) = integer(name).also { require(it in Int.MIN_VALUE..Int.MAX_VALUE) }.toInt()
    private const val CONFIG_BYTES = 64 * 1024
    private val JSON_LIMITS = StrictJsonLimits(CONFIG_BYTES, CONFIG_BYTES, 8, 256, 8192, 32 * 1024, 20)
}
