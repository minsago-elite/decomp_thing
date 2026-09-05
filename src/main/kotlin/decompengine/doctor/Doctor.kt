package decompengine.doctor

import decompengine.acp.AcpHarnessFactory
import decompengine.acp.AcpHarnessKind
import decompengine.acp.AcpHarnessSelection
import decompengine.acp.AcpAgentHarness
import decompengine.acp.AcpPreflightWorkflow
import decompengine.agent.AgentExecutionException
import decompengine.analysis.BundledGhidra
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.Locale
import kotlin.io.path.createDirectories
import kotlin.io.path.isDirectory
import kotlin.io.path.pathString
import kotlin.io.path.writeText

data class DoctorOptions(
    val outputDir: Path,
    val toolsOnly: Boolean = false,
    val harnessOverride: String? = null,
    val workflowOverride: AcpPreflightWorkflow? = null,
    val showAuthMethods: Boolean = false,
) {
    init {
        require(!toolsOnly || !showAuthMethods) { "doctor --tools-only cannot be combined with --auth-methods" }
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
    fun inspect(options: DoctorOptions): DoctorReport {
        val checks = mutableListOf<DoctorCheck>()
        checks += executableCheck("Java", listOf("java", "-version"), "Install a Java 21 runtime and ensure java is on PATH.")
        checks += executableCheck("GCC", listOf("gcc", "--version"), "Install GCC and ensure gcc is on PATH.")
        checks += executableCheck("Make", listOf("make", "--version"), "Install Make and ensure make is on PATH.")
        checks += executableCheck("binutils/readelf", listOf("readelf", "--version"), "Install binutils and ensure readelf is on PATH.")
        checks += executableCheck("binutils/strings", listOf("strings", "--version"), "Install binutils and ensure strings is on PATH.")
        checks += executableCheck("Python", listOf("python3", "--version"), "Install Python 3 and ensure python3 is on PATH.")
        val angrPython = environment["ANGR_PYTHON"]?.takeIf(String::isNotBlank) ?: "python3"
        checks += executableCheck("angr", listOf(angrPython, "-c", "import angr"), "Install angr for the configured Python interpreter or set ANGR_PYTHON.")
        checks += ghidraCheck()
        checks += sanitizerCheck()
        checks += bubblewrapCheck()
        checks += outputCheck(options.outputDir)
        if (!options.toolsOnly) {
            val harnessSelection = runCatching {
                AcpHarnessFactory.fromEnvironment(withHarnessOverride(options.harnessOverride))
            }
            checks += agentHarnessChecks(
                harnessSelection,
                options.workflowOverride ?: AcpPreflightWorkflow.ALL,
                options.showAuthMethods,
            )
            if (harnessSelection.getOrNull()?.kind == AcpHarnessKind.LEGACY_OPENAI && !options.showAuthMethods) {
                checks += llmChecks()
            }
        }
        return DoctorReport(checks)
    }

    private fun executableCheck(name: String, command: List<String>, remediation: String): DoctorCheck =
        runCatching { commandProbe.run(command, null) }.fold(
            onSuccess = { result ->
                if (result.exitCode == 0) DoctorCheck(name, true, result.output.firstLineOr("available"))
                else DoctorCheck(name, false, "$remediation Probe exited ${result.exitCode}: ${result.output.firstLineOr("no output")}")
            },
            onFailure = { DoctorCheck(name, false, "$remediation ${it.message.orEmpty()}".trim()) },
        )

    private fun agentHarnessChecks(
        selection: Result<AcpHarnessSelection>,
        workflow: AcpPreflightWorkflow,
        showAuthMethods: Boolean,
    ): List<DoctorCheck> = selection.fold(
        onSuccess = { resolved ->
            when (resolved.kind) {
                AcpHarnessKind.ACP -> {
                    val selectionCheck = DoctorCheck(
                        "ACP harness",
                        true,
                        "Selected ${resolved.provenance.stableDescriptor}",
                    )
                    val authChecks = mutableListOf<DoctorCheck>()
                    val preflightCheck = try {
                        val harness = resolved.createHarness() as? AcpAgentHarness
                            ?: error("ACP factory returned a non-ACP harness")
                        val result = harness.preflight(workflow)
                        if (showAuthMethods) {
                            if (result.authentication.methods.isEmpty()) authChecks += DoctorCheck(
                                "ACP authentication methods", true, "No authentication methods advertised; no login attempted.")
                            result.authentication.methods.forEachIndexed { index, method ->
                                fun quoted(value: String) = kotlinx.serialization.json.JsonPrimitive(value).toString()
                                authChecks += DoctorCheck("ACP authentication method ${index + 1}", true,
                                    "id preview=${quoted(method.idPreview)}; variant=${method.variant}; " +
                                        "name=${quoted(method.namePreview)}; " +
                                        "description=${quoted(method.descriptionPreview.orEmpty())}; login unsupported; no login attempted.")
                            }
                        }
                        DoctorCheck(
                            "ACP preflight",
                            true,
                            result.stableDescriptor,
                        )
                    } catch (failure: Exception) {
                        DoctorCheck(
                            "ACP preflight",
                            false,
                            preflightFailureDetail(failure),
                        )
                    }
                    listOf(selectionCheck, preflightCheck) + authChecks
                }
                AcpHarnessKind.LEGACY_OPENAI -> if (showAuthMethods) listOf(DoctorCheck(
                    "ACP authentication methods", false, "--auth-methods requires the ACP harness; no login attempted."
                )) else listOf(
                    DoctorCheck(
                        "ACP harness",
                        true,
                        "Selected ${resolved.provenance.stableDescriptor}; migrate to the default ACP harness.",
                    ),
                )
            }
        },
        onFailure = { failure ->
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

    private fun ghidraCheck(): DoctorCheck {
        return runCatching { commandProbe.run(BundledGhidra.locate().probeCommand(), null) }.fold(
            onSuccess = { result ->
                if (result.exitCode == 0) {
                    DoctorCheck("Ghidra", true, "Bundled Ghidra ${BundledGhidra.VERSION} direct API initialized successfully")
                } else {
                    DoctorCheck("Ghidra", false, "Bundled Ghidra could not initialize; verify the application JDK and bundle. ${result.output.firstLineOr("exit ${result.exitCode}")}")
                }
            },
            onFailure = { DoctorCheck("Ghidra", false, "Bundled Ghidra is unavailable; reinstall the complete application distribution. ${it.message}") },
        )
    }

    private fun sanitizerCheck(): DoctorCheck {
        val directory = runCatching { Files.createTempDirectory("llm-bin-patch-doctor-") }.getOrElse {
            return DoctorCheck("GCC sanitizers", false, "Could not create a temporary directory to test AddressSanitizer/UBSan: ${it.message}")
        }
        return try {
            val source = directory.resolve("probe.c")
            val binary = directory.resolve("probe")
            source.writeText("int main(void) { return 0; }\n")
            val compile = commandProbe.run(
                listOf("gcc", "-std=c11", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", source.pathString, "-o", binary.pathString),
                directory,
            )
            if (compile.exitCode != 0) {
                DoctorCheck("GCC sanitizers", false, "GCC could not link an AddressSanitizer/UBSan probe; install sanitizer runtime libraries. ${compile.output.firstLineOr("no compiler output")}")
            } else {
                val run = commandProbe.run(listOf(binary.pathString), directory)
                if (run.exitCode == 0) DoctorCheck("GCC sanitizers", true, "AddressSanitizer and UBSan probe compiled and ran")
                else DoctorCheck("GCC sanitizers", false, "The sanitizer probe exited ${run.exitCode}; verify sanitizer runtime libraries. ${run.output.firstLineOr("no output")}")
            }
        } catch (failure: Exception) {
            DoctorCheck("GCC sanitizers", false, "Could not compile and run the sanitizer probe: ${failure.message}")
        } finally {
            directory.toFile().deleteRecursively()
        }
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
        val normalized = output.toAbsolutePath().normalize()
        return try {
            normalized.createDirectories()
            require(normalized.isDirectory()) { "path is not a directory" }
            val probe = Files.createTempFile(normalized, ".doctor-", ".tmp")
            Files.delete(probe)
            DoctorCheck("output directory", true, "writable at ${normalized.pathString}")
        } catch (failure: Exception) {
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
                onFailure = { DoctorCheck("LLM connectivity", false, "Could not authenticate to ${baseUrl.host}: ${it.message}. Check BASE_URL, API_KEY, proxy, and network access.") },
            )
        } else {
            DoctorCheck("LLM connectivity", false, "Connectivity was not attempted because BASE_URL or API_KEY is invalid.")
        }
        return checks
    }
}

private object SystemCommandProbe : CommandProbe {
    override fun run(command: List<String>, workingDirectory: Path?): CommandProbeResult {
        val process = ProcessBuilder(command)
            .directory(workingDirectory?.toFile())
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        return CommandProbeResult(process.waitFor(), output)
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
