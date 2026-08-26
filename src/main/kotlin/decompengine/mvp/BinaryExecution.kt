package decompengine.mvp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.time.Duration
import java.util.UUID
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.isRegularFile
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.writeText

data class BinaryExecutionResult(
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
    val isolation: BinaryIsolation,
) {
    val combined: String = stdout + stderr
}

data class BinaryIsolation(
    val boundary: String,
    val networkIsolated: Boolean,
    val credentialsIsolated: Boolean,
) {
    fun requireSecure(): BinaryIsolation {
        if (!networkIsolated || !credentialsIsolated) {
            throw MvpPatchException("binary execution boundary lacks required network or credential isolation: $this")
        }
        return this
    }

    override fun toString(): String =
        "$boundary; networkIsolated=$networkIsolated; credentialsIsolated=$credentialsIsolated"
}

fun interface BinaryExecutionBoundary {
    fun execute(executable: Path, workingDirectory: Path, environment: Map<String, String>): BinaryExecutionResult
}

object BinaryExecutionBoundaryFactory {
    fun fromEnvironment(environment: Map<String, String> = System.getenv()): BinaryExecutionBoundary {
        val runnerDir = environment["BINARY_RUNNER_DIR"]?.trim()?.takeIf(String::isNotEmpty)
        return if (runnerDir != null) {
            SpoolBinaryExecutionBoundary(Path.of(runnerDir))
        } else {
            BubblewrapBinaryExecutionBoundary()
        }
    }
}

class BubblewrapBinaryExecutionBoundary(
    private val bwrap: Path = Path.of("/usr/bin/bwrap"),
    private val timeout: Path = Path.of("/usr/bin/timeout"),
    private val duration: Duration = Duration.ofSeconds(5),
) : BinaryExecutionBoundary {
    override fun execute(executable: Path, workingDirectory: Path, environment: Map<String, String>): BinaryExecutionResult {
        validateEnvironment(environment)
        val executablePath = executable.toAbsolutePath().normalize()
        val directory = workingDirectory.toAbsolutePath().normalize()
        if (!Files.isExecutable(bwrap) || !Files.isExecutable(timeout)) {
            throw MvpPatchException("bubblewrap execution boundary is unavailable; configure BINARY_RUNNER_DIR or install bubblewrap")
        }
        if (!probeNetworkNamespace()) {
            throw MvpPatchException("bubblewrap cannot create the required network namespace; use the separate Compose runner")
        }
        val command = mutableListOf(
            timeout.pathString, "${duration.toSeconds()}s", bwrap.pathString,
            "--unshare-net", "--die-with-parent", "--clearenv",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/lib", "/lib",
        )
        if (Path.of("/lib64").exists()) command += listOf("--ro-bind", "/lib64", "/lib64")
        command += listOf("--dir", "/tmp", "--ro-bind", directory.pathString, directory.pathString, "--chdir", directory.pathString)
        environment.toSortedMap().forEach { (key, value) -> command += listOf("--setenv", key, value) }
        command += executablePath.pathString
        val process = ProcessBuilder(command).apply { environment().clear() }.start()
        val stdout = process.inputStream.bufferedReader().readText()
        val stderr = process.errorStream.bufferedReader().readText()
        return BinaryExecutionResult(
            process.waitFor(), stdout, stderr,
            BinaryIsolation("bubblewrap user/mount/network namespaces with a cleared environment", true, true),
        )
    }

    private fun probeNetworkNamespace(): Boolean = runCatching {
        val command = mutableListOf(
            timeout.pathString, "3s", bwrap.pathString, "--unshare-net", "--die-with-parent", "--clearenv",
            "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib",
        )
        if (Path.of("/lib64").exists()) command += listOf("--ro-bind", "/lib64", "/lib64")
        command += listOf("--dir", "/tmp", "/usr/bin/true")
        ProcessBuilder(command).apply { environment().clear() }.start().run {
            inputStream.readBytes(); errorStream.readBytes(); waitFor() == 0
        }
    }.getOrDefault(false)
}

class SpoolBinaryExecutionBoundary(
    controlDirectory: Path,
    private val responseTimeout: Duration = Duration.ofSeconds(15),
) : BinaryExecutionBoundary {
    private val requests = controlDirectory.toAbsolutePath().normalize().resolve("requests").createDirectories()
    private val responses = controlDirectory.toAbsolutePath().normalize().resolve("responses").createDirectories()

    override fun execute(executable: Path, workingDirectory: Path, environment: Map<String, String>): BinaryExecutionResult {
        validateEnvironment(environment)
        val id = UUID.randomUUID().toString()
        val request = buildJsonObject {
            put("id", id)
            put("executable", executable.toAbsolutePath().normalize().pathString)
            put("workingDirectory", workingDirectory.toAbsolutePath().normalize().pathString)
            put("environment", JsonObject(environment.toSortedMap().mapValues { JsonPrimitive(it.value) }))
        }
        atomicWrite(requests.resolve("$id.json"), request.toString())
        val responsePath = responses.resolve("$id.json")
        val deadline = System.nanoTime() + responseTimeout.toNanos()
        while (!responsePath.exists() && System.nanoTime() < deadline) Thread.sleep(20)
        if (!responsePath.exists()) throw MvpPatchException("isolated binary runner timed out waiting for request $id")
        val response = Json.parseToJsonElement(responsePath.readText()).jsonObject
        Files.deleteIfExists(responsePath)
        response["error"]?.jsonPrimitive?.contentOrNull?.let { throw MvpPatchException("isolated binary runner rejected execution: $it") }
        return BinaryExecutionResult(
            exitCode = response.getValue("exitCode").jsonPrimitive.int,
            stdout = response.getValue("stdout").jsonPrimitive.content,
            stderr = response.getValue("stderr").jsonPrimitive.content,
            isolation = BinaryIsolation(
                boundary = response.getValue("boundary").jsonPrimitive.content,
                networkIsolated = response.getValue("networkIsolated").jsonPrimitive.boolean,
                credentialsIsolated = response.getValue("credentialsIsolated").jsonPrimitive.boolean,
            ).requireSecure(),
        )
    }
}

class BinaryRunnerService(
    controlDirectory: Path,
    allowedRoots: List<Path>,
    private val networkIsolated: Boolean,
    private val processTimeout: Duration = Duration.ofSeconds(5),
) {
    private val requests = controlDirectory.toAbsolutePath().normalize().resolve("requests").createDirectories()
    private val responses = controlDirectory.toAbsolutePath().normalize().resolve("responses").createDirectories()
    private val processing = controlDirectory.toAbsolutePath().normalize().resolve("processing").createDirectories()
    private val roots = allowedRoots.map { it.toAbsolutePath().normalize() }

    fun runForever() {
        require(networkIsolated) { "runner refuses to start unless its container network is explicitly disabled" }
        while (!Thread.currentThread().isInterrupted) {
            if (!processOne()) Thread.sleep(50)
        }
    }

    fun processOne(): Boolean {
        val requestPath = Files.list(requests).use { stream ->
            stream.filter { it.fileName.toString().endsWith(".json") }.sorted().findFirst().orElse(null)
        } ?: return false
        val claimed = processing.resolve(requestPath.fileName)
        try {
            moveAtomically(requestPath, claimed)
        } catch (_: Exception) {
            return false
        }
        val id = claimed.fileName.toString().removeSuffix(".json")
        val response = runCatching { executeRequest(claimed.readText()) }.getOrElse { failure ->
            buildJsonObject { put("error", failure.message ?: failure.javaClass.simpleName) }
        }
        atomicWrite(responses.resolve("$id.json"), response.toString())
        Files.deleteIfExists(claimed)
        return true
    }

    private fun executeRequest(text: String): JsonObject {
        require(networkIsolated) { "runner network isolation is not active" }
        val request = Json.parseToJsonElement(text).jsonObject
        val executable = authorize(Path.of(request.getValue("executable").jsonPrimitive.content), executable = true)
        val directory = authorize(Path.of(request.getValue("workingDirectory").jsonPrimitive.content), executable = false)
        val suppliedEnvironment = request["environment"]?.jsonObject?.mapValues { it.value.jsonPrimitive.content }.orEmpty()
        validateEnvironment(suppliedEnvironment)
        val process = ProcessBuilder("/usr/bin/timeout", "${processTimeout.toSeconds()}s", executable.pathString)
            .directory(directory.toFile())
            .redirectErrorStream(false)
            .apply {
                environment().clear()
                environment().putAll(suppliedEnvironment)
            }
            .start()
        val stdout = process.inputStream.bufferedReader().readText()
        val stderr = process.errorStream.bufferedReader().readText()
        val exit = process.waitFor()
        return buildJsonObject {
            put("exitCode", exit)
            put("stdout", stdout)
            put("stderr", stderr)
            put("boundary", "separate read-only runner container with a cleared environment")
            put("networkIsolated", networkIsolated)
            put("credentialsIsolated", true)
        }
    }

    private fun authorize(path: Path, executable: Boolean): Path {
        require(path.isAbsolute) { "runner paths must be absolute: $path" }
        val normalized = path.normalize()
        val real = if (normalized.exists()) normalized.toRealPath() else normalized
        require(roots.any { root -> real.startsWith(root.toRealPath()) }) { "path is outside runner roots: $path" }
        if (executable) require(real.isRegularFile() && Files.isExecutable(real)) { "executable is not a runnable regular file: $path" }
        else require(Files.isDirectory(real)) { "working directory is not a directory: $path" }
        return real
    }
}

private val ALLOWED_BINARY_ENVIRONMENT = setOf("ASAN_OPTIONS", "UBSAN_OPTIONS", "LC_ALL", "LANG", "TZ")

private fun validateEnvironment(environment: Map<String, String>) {
    val rejected = environment.keys - ALLOWED_BINARY_ENVIRONMENT
    require(rejected.isEmpty()) { "binary environment contains unauthorized keys: ${rejected.sorted().joinToString()}" }
}

private fun atomicWrite(path: Path, text: String) {
    val temporary = path.resolveSibling(".${path.fileName}.${UUID.randomUUID()}.tmp")
    temporary.writeText(text)
    moveAtomically(temporary, path)
}

private fun moveAtomically(source: Path, target: Path) {
    try {
        Files.move(source, target, StandardCopyOption.ATOMIC_MOVE)
    } catch (_: Exception) {
        Files.move(source, target)
    }
}
