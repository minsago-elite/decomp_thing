package decompengine.doctor

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import kotlin.io.path.createDirectories
import kotlin.io.path.isDirectory
import kotlin.io.path.pathString
import kotlin.io.path.writeText

data class DoctorOptions(
    val outputDir: Path,
    val toolsOnly: Boolean = false,
)

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
        checks += acpHarnessCheck()
        if (!options.toolsOnly) checks += llmChecks()
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

    private fun acpHarnessCheck(): DoctorCheck {
        val harness = environment["ACP_HARNESS"]?.trim()?.lowercase() ?: return DoctorCheck("ACP harness", true, "not configured (DIRECT); set ACP_HARNESS=acp to enable ACP agent harness")
        if (harness != "acp") return DoctorCheck("ACP harness", true, "harness=$harness (DIRECT)")
        val executableText = environment["ACP_AGENT_EXECUTABLE"]?.trim().orEmpty()
        if (executableText.isBlank()) return DoctorCheck("ACP harness", false, "ACP_HARNESS=acp requires ACP_AGENT_EXECUTABLE to be an absolute path to the agent executable")
        val executable = try { Path.of(executableText).toAbsolutePath().normalize() } catch (e: Exception) { return DoctorCheck("ACP harness", false, "ACP_AGENT_EXECUTABLE is not a valid path: ${e.message}") }
        if (!Files.isRegularFile(executable) || !Files.isReadable(executable)) return DoctorCheck("ACP harness", false, "ACP agent executable not found or not readable at $executable")
        if (!executable.isAbsolute) return DoctorCheck("ACP harness", false, "ACP_AGENT_EXECUTABLE must be absolute: $executable")
        val argsText = environment["ACP_AGENT_ARGS"]?.trim().orEmpty()
        if ('\u0000' in argsText) return DoctorCheck("ACP harness", false, "ACP_AGENT_ARGS must not contain NUL")
        val permissionMode = environment["ACP_PERMISSION_MODE"]?.trim() ?: "default-deny"
        if (permissionMode != "default-deny") return DoctorCheck("ACP harness", false, "ACP_PERMISSION_MODE must be default-deny, got $permissionMode")
        val timeoutText = environment["ACP_TIMEOUT_SECONDS"]?.trim().orEmpty()
        if (timeoutText.isNotBlank()) {
            val seconds = timeoutText.toLongOrNull()
            if (seconds == null || seconds !in 1..3600) return DoctorCheck("ACP harness", false, "ACP_TIMEOUT_SECONDS must be a number in 1..3600")
        }
        val probe = runCatching { commandProbe.run(listOf(executable.toString(), "--version"), null) }
        val probeDetail = probe.fold(
            onSuccess = { if (it.exitCode == 0) "executable resolves and --version succeeded" else "executable found at $executable (probe exit ${it.exitCode})" },
            onFailure = { "executable found at $executable (probe failed: ${it.message})" },
        )
        return DoctorCheck("ACP harness", true, "acp configured: $executable ${argsText.take(80)}; $probeDetail; permission=$permissionMode; stdio JSON-RPC, no shell parsing, bounded env, timeouts=${timeoutText.ifBlank { "default" }}")
    }

    private fun ghidraCheck(): DoctorCheck {
        val home = environment["GHIDRA_HOME"]?.trim()?.takeIf(String::isNotEmpty)?.let(Path::of)
            ?: return DoctorCheck("Ghidra", false, "Set GHIDRA_HOME to a Ghidra installation containing support/analyzeHeadless.")
        val executable = home.resolve("support/analyzeHeadless")
        if (!Files.isExecutable(executable)) {
            return DoctorCheck("Ghidra", false, "No executable analyzeHeadless at ${executable.pathString}; correct GHIDRA_HOME or install Ghidra.")
        }
        return runCatching { commandProbe.run(listOf(executable.pathString), home) }.fold(
            onSuccess = { result ->
                if (result.exitCode == 0 || result.output.contains("analyzeHeadless", ignoreCase = true)) {
                    DoctorCheck("Ghidra", true, "analyzeHeadless launched successfully at ${executable.pathString}")
                } else {
                    DoctorCheck("Ghidra", false, "analyzeHeadless exists but could not launch; verify Ghidra's Java configuration. ${result.output.firstLineOr("exit ${result.exitCode}")}")
                }
            },
            onFailure = { DoctorCheck("Ghidra", false, "analyzeHeadless exists but could not launch; verify Ghidra's Java configuration. ${it.message}") },
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
