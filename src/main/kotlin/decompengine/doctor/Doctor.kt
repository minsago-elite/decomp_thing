package decompengine.doctor

import decompengine.acp.AcpHarnessFactory
import decompengine.acp.AcpHarnessKind
import decompengine.acp.AcpHarnessSelection
import decompengine.acp.AcpAgentHarness
import decompengine.acp.AcpPreflightWorkflow
import decompengine.agent.AgentExecutionException
import decompengine.analysis.BundledGhidra
import decompengine.project.ReconstructionAdapters
import decompengine.project.ReconstructionHostSafetyLimits
import decompengine.project.ReconstructionProfile
import decompengine.project.ReconstructionProfiles
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.Locale
import java.util.concurrent.CancellationException
import kotlin.io.path.createDirectories
import kotlin.io.path.isDirectory
import kotlin.io.path.pathString

data class DoctorOptions(
    val outputDir: Path,
    val toolsOnly: Boolean = false,
    val harnessOverride: String? = null,
    val workflowOverride: AcpPreflightWorkflow? = null,
) {
    init {
        require(!toolsOnly || harnessOverride == null) {
            "doctor --tools-only cannot be combined with --harness"
        }
        require(!toolsOnly || workflowOverride == null) {
            "doctor --tools-only cannot be combined with --workflow"
        }
    }
}

data class DoctorCheck(
    val name: String,
    val passed: Boolean,
    val detail: String,
)

data class DoctorReport(val checks: List<DoctorCheck>) {
    val passed: Boolean = checks.all(DoctorCheck::passed)
}

fun interface CommandProbe {
    fun run(command: List<String>, workingDirectory: Path?): CommandProbeResult
}

data class CommandProbeResult(val exitCode: Int, val output: String)

fun interface ConnectivityProbe {
    fun check(baseUrl: URI, apiKey: String): String
}

class Doctor(
    private val environment: Map<String, String> = System.getenv(),
    private val commandProbe: CommandProbe = SystemCommandProbe,
    private val connectivityProbe: ConnectivityProbe = HttpConnectivityProbe(),
) {
    fun inspect(options: DoctorOptions): DoctorReport = inspect(options, ReconstructionProfiles.default)

    fun inspect(
        options: DoctorOptions,
        profile: ReconstructionProfile,
        hostSafetyLimits: ReconstructionHostSafetyLimits = ReconstructionHostSafetyLimits.DEFAULT,
    ): DoctorReport {
        requireDoctorActive()
        hostSafetyLimits.requireAllows(profile.budgets)
        val diagnostics = ReconstructionAdapters.resolve(profile).diagnostics.prepare(profile)
        val hostProbeLimits = CommandProbeLimits()
        val toolchainLimits = hostProbeLimits.copy(
            maximumWallClockMillis = minOf(hostProbeLimits.maximumWallClockMillis, profile.budgets.buildWallClockMillis),
            maximumOutputBytes = minOf(hostProbeLimits.maximumOutputBytes.toLong(), profile.budgets.buildMaximumOutputBytes).toInt(),
        )
        val exportLimits = hostProbeLimits.copy(
            maximumWallClockMillis = minOf(hostProbeLimits.maximumWallClockMillis, profile.budgets.exportWallClockMillis),
        )
        val checks = mutableListOf<DoctorCheck>()
        checks += executableCheck("Java", listOf("java", "-version"), "Install a Java 21 runtime and ensure java is on PATH.")
        val toolchainBudget = CommandProbeBudget(toolchainLimits)
        val toolchainProbe = boundedProbe(toolchainBudget)
        for (probe in diagnostics.versionProbes) {
            checks += executableCheck(probe.name, probe.command, probe.remediation, toolchainProbe)
        }
        checks += executableCheck("binutils/readelf", listOf("readelf", "--version"), "Install binutils and ensure readelf is on PATH.")
        checks += executableCheck("binutils/strings", listOf("strings", "--version"), "Install binutils and ensure strings is on PATH.")
        checks += executableCheck("Python", listOf("python3", "--version"), "Install Python 3 and ensure python3 is on PATH.")
        val angrPython = environment["ANGR_PYTHON"]?.takeIf(String::isNotBlank) ?: "python3"
        checks += executableCheck("angr", listOf(angrPython, "-c", "import angr"), "Install angr for the configured Python interpreter or set ANGR_PYTHON.")
        checks += ghidraCheck(exportLimits)
        checks += diagnostics.checkCapabilities(toolchainProbe, toolchainBudget::checkpoint)
        requireDoctorActive()
        checks += bubblewrapCheck()
        checks += outputCheck(options.outputDir)
        checks += DoctorCheck("reconstruction profile", true, "Selected ${profile.id}; sha256=${profile.sha256}")
        checks += DoctorCheck("diagnostic limits", true,
            "Local command ceiling: ${hostProbeLimits.maximumWallClockMillis} ms and ${hostProbeLimits.maximumOutputBytes} combined output bytes; " +
                "toolchain group: ${toolchainLimits.maximumWallClockMillis} ms and ${toolchainLimits.maximumOutputBytes} combined output bytes; " +
                "bundled Ghidra preparation/probe: ${exportLimits.maximumWallClockMillis} ms; " +
                "command cleanup allowance: ${hostProbeLimits.cleanupMillis} ms. " +
                if (commandProbe is BudgetedCommandProbe) "Owned command execution enforces these limits."
                else "Injected command callbacks receive cooperative before/after checks only.")
        if (!options.toolsOnly) {
            val harnessSelection = runCatching {
                AcpHarnessFactory.fromEnvironment(withHarnessOverride(options.harnessOverride))
            }.onFailure { requireDoctorActive(it) }
            checks += agentHarnessChecks(
                harnessSelection,
                options.workflowOverride ?: AcpPreflightWorkflow.ALL,
            )
            if (harnessSelection.getOrNull()?.kind == AcpHarnessKind.LEGACY_OPENAI) {
                checks += llmChecks()
            }
        }
        requireDoctorActive()
        return DoctorReport(checks)
    }

    private fun executableCheck(
        name: String,
        command: List<String>,
        remediation: String,
        probe: CommandProbe = boundedProbe(CommandProbeBudget(CommandProbeLimits())),
    ): DoctorCheck = try {
        requireDoctorActive()
        val result = probe.run(command, null)
        if (result.exitCode == 0) DoctorCheck(name, true, result.output.firstLineOr("available"))
        else DoctorCheck(name, false, "$remediation Probe exited ${result.exitCode}: ${result.output.firstLineOr("no output")}")
    } catch (failure: Exception) {
        requireDoctorActive(failure)
        DoctorCheck(name, false, "$remediation ${failure.message.orEmpty()}".trim())
    }

    private fun boundedProbe(budget: CommandProbeBudget): CommandProbe = CommandProbe { command, directory ->
        budget.checkpoint("before command probe")
        val result = if (commandProbe is BudgetedCommandProbe) {
            commandProbe.run(command, directory, budget)
        } else {
            commandProbe.run(command, directory).also {
                budget.checkpoint("after injected command probe")
                chargeInjectedOutput(it.output, budget)
            }
        }
        budget.checkpoint("after command probe")
        result
    }

    private fun agentHarnessChecks(
        selection: Result<AcpHarnessSelection>,
        workflow: AcpPreflightWorkflow,
    ): List<DoctorCheck> = selection.fold(
        onSuccess = { resolved ->
            when (resolved.kind) {
                AcpHarnessKind.ACP -> {
                    val selectionCheck = DoctorCheck(
                        "ACP harness",
                        true,
                        "Selected ${resolved.provenance.stableDescriptor}",
                    )
                    val preflightCheck = try {
                        val harness = resolved.createHarness() as? AcpAgentHarness
                            ?: error("ACP factory returned a non-ACP harness")
                        val result = harness.preflight(workflow)
                        DoctorCheck(
                            "ACP preflight",
                            true,
                            result.stableDescriptor,
                        )
                    } catch (failure: Exception) {
                        requireDoctorActive(failure)
                        DoctorCheck(
                            "ACP preflight",
                            false,
                            preflightFailureDetail(failure),
                        )
                    }
                    listOf(selectionCheck, preflightCheck)
                }
                AcpHarnessKind.LEGACY_OPENAI -> listOf(
                    DoctorCheck(
                        "ACP harness",
                        true,
                        "Selected ${resolved.provenance.stableDescriptor}; migrate to the default ACP harness.",
                    ),
                )
            }
        },
        onFailure = { failure ->
            requireDoctorActive(failure)
            listOf(
                DoctorCheck(
                    "ACP harness",
                    false,
                    "ACP is the default agent harness and its provisioning is invalid: ${failure.message.orEmpty()}",
                ),
            )
        },
    )

    private fun withHarnessOverride(harnessOverride: String?): Map<String, String> =
        if (harnessOverride == null) {
            environment
        } else {
            object : Map<String, String> by environment {
                override fun containsKey(key: String): Boolean =
                    key == "ACP_HARNESS" || environment.containsKey(key)

                override fun get(key: String): String? =
                    if (key == "ACP_HARNESS") harnessOverride else environment[key]
            }
        }

    private fun preflightFailureDetail(failure: Exception): String {
        val execution = failure as? AgentExecutionException
            ?: return "ACP preflight failed before a session was created; verify the authenticated provisioning and sandbox."
        val safeDetails = execution.failure.details.entries
            .filter { (name, _) -> name in PREFLIGHT_DIAGNOSTIC_FIELDS }
            .sortedBy { it.key }
            .joinToString(",") { (name, value) -> "$name=$value" }
        return buildString {
            append("ACP preflight failed before a session was created: kind=")
            append(execution.failure.kind.name.lowercase(Locale.ROOT))
            if (safeDetails.isNotEmpty()) {
                append("; ")
                append(safeDetails)
            }
            append(". Verify the configured agent's stable-v1 support, required capabilities, and sandbox cleanup.")
        }
    }

    private fun ghidraCheck(limits: CommandProbeLimits): DoctorCheck = try {
        val budget = CommandProbeBudget(limits)
        budget.checkpoint("before bundled Ghidra preparation")
        val command = BundledGhidra.locate().probeCommand(budget::checkpoint)
        val result = boundedProbe(budget).run(command, null)
        if (result.exitCode == 0) {
            DoctorCheck("Ghidra", true, "Bundled Ghidra ${BundledGhidra.VERSION} direct API initialized successfully")
        } else {
            DoctorCheck("Ghidra", false, "Bundled Ghidra could not initialize; verify the application JDK and bundle. ${result.output.firstLineOr("exit ${result.exitCode}")}")
        }
    } catch (failure: Exception) {
        requireDoctorActive(failure)
        DoctorCheck("Ghidra", false, "Bundled Ghidra is unavailable; reinstall the complete application distribution. ${failure.message}")
    }

    private fun bubblewrapCheck(): DoctorCheck {
        val executable = Path.of("/usr/bin/bwrap")
        return if (Files.isExecutable(executable)) {
            DoctorCheck("bubblewrap", true, "executable at ${executable.pathString}; runtime isolation is verified again before binary execution")
        } else {
            DoctorCheck("bubblewrap", false, "Install bubblewrap at ${executable.pathString}; analyzed binary execution requires a sandbox boundary.")
        }
    }

    private fun outputCheck(output: Path): DoctorCheck {
        requireDoctorActive()
        val normalized = output.toAbsolutePath().normalize()
        return try {
            normalized.createDirectories()
            require(normalized.isDirectory()) { "path is not a directory" }
            val probe = Files.createTempFile(normalized, ".doctor-", ".tmp")
            Files.delete(probe)
            requireDoctorActive()
            DoctorCheck("output directory", true, "writable at ${normalized.pathString}")
        } catch (failure: Exception) {
            requireDoctorActive(failure)
            DoctorCheck("output directory", false, "Make ${normalized.pathString} an existing writable directory: ${failure.message}")
        }
    }

    private fun llmChecks(): List<DoctorCheck> {
        val baseUrlText = environment["BASE_URL"].orEmpty().trim()
        val apiKey = environment["API_KEY"].orEmpty()
        val model = environment["MODEL"].orEmpty().trim()
        val baseUrl = runCatching { URI.create(baseUrlText) }.getOrNull()
        val validBaseUrl = baseUrl != null && baseUrl.scheme in setOf("http", "https") && !baseUrl.host.isNullOrBlank()
        val checks = mutableListOf(
            DoctorCheck("LLM base URL", validBaseUrl, if (validBaseUrl) "configured for ${baseUrl.scheme}://${baseUrl.host}" else "Set BASE_URL to an absolute HTTP(S) OpenAI-compatible API URL."),
            DoctorCheck("LLM API key", apiKey.isNotBlank(), if (apiKey.isNotBlank()) "configured (value redacted)" else "Set API_KEY; its value will not be printed or persisted."),
            DoctorCheck("LLM model", model.isNotBlank(), if (model.isNotBlank()) "configured as $model" else "Set MODEL to an available model identifier."),
        )
        val reasoning = environment["REASONING_EFFORT"]?.trim().orEmpty()
        if (reasoning.isNotEmpty()) {
            val supported = reasoning in setOf("none", "minimal", "low", "medium", "high", "xhigh")
            checks += DoctorCheck("reasoning effort", supported, if (supported) "configured as $reasoning" else "Use none, minimal, low, medium, high, or xhigh.")
        }
        checks += if (validBaseUrl && apiKey.isNotBlank()) {
            runCatching { connectivityProbe.check(requireNotNull(baseUrl), apiKey) }.fold(
                onSuccess = { DoctorCheck("LLM connectivity", true, it) },
                onFailure = {
                    requireDoctorActive(it)
                    DoctorCheck("LLM connectivity", false, "Could not authenticate to ${baseUrl.host}: ${it.message}. Check BASE_URL, API_KEY, proxy, and network access.")
                },
            )
        } else {
            DoctorCheck("LLM connectivity", false, "Connectivity was not attempted because BASE_URL or API_KEY is invalid.")
        }
        return checks
    }
}

private object SystemCommandProbe : BudgetedCommandProbe by BoundedSystemCommandProbe()

private fun requireDoctorActive(failure: Throwable? = null) {
    if (failure is InterruptedException || failure is CancellationException || failure is Error) throw failure
    if (Thread.currentThread().isInterrupted) {
        throw InterruptedException("Doctor inspection cancelled").also { if (failure != null) it.initCause(failure) }
    }
}

/** Legacy injected callbacks own their allocation; count UTF-8 without making another full output copy. */
private fun chargeInjectedOutput(output: String, budget: CommandProbeBudget) {
    var offset = 0
    while (offset < output.length) {
        budget.checkpoint("while checking injected command output")
        var bytes = 0
        val end = minOf(output.length, offset + 1024)
        while (offset < end) {
            val character = output[offset++]
            bytes += when {
                character.code < 0x80 -> 1
                character.code < 0x800 -> 2
                character.isHighSurrogate() && offset < output.length && output[offset].isLowSurrogate() -> {
                    offset++
                    4
                }
                character.isSurrogate() -> 1 // Charset UTF-8's replacement for an unpaired UTF-16 code unit.
                else -> 3
            }
        }
        budget.consumeOutputBytes(bytes)
    }
}

private class HttpConnectivityProbe(
    private val client: HttpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(),
) : ConnectivityProbe {
    override fun check(baseUrl: URI, apiKey: String): String {
        val endpoint = URI.create(baseUrl.toString().trimEnd('/') + "/models")
        val request = HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(10))
            .header("Authorization", "Bearer $apiKey")
            .GET()
            .build()
        val response = client.send(request, HttpResponse.BodyHandlers.discarding())
        check(response.statusCode() in 200..299) { "GET /models returned HTTP ${response.statusCode()}" }
        return "authenticated GET /models succeeded with HTTP ${response.statusCode()}"
    }
}

private fun String.firstLineOr(fallback: String): String = lineSequence().firstOrNull { it.isNotBlank() }?.trim() ?: fallback

private val PREFLIGHT_DIAGNOSTIC_FIELDS = setOf(
    "exitCode",
    "missingCapabilities",
    "offeredVersion",
    "remainingPids",
    "requestedVersion",
    "sandboxCleanupVerified",
    "supportedVersions",
)
