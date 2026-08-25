package decompengine.validation

import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.io.path.writeText

data class ProcessInput(
    val id: String,
    val args: List<String> = emptyList(),
    val stdin: ByteArray = ByteArray(0),
) {
    override fun equals(other: Any?): Boolean =
        other is ProcessInput && id == other.id && args == other.args && stdin.contentEquals(other.stdin)

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + args.hashCode()
        result = 31 * result + stdin.contentHashCode()
        return result
    }
}

data class ProcessOutput(
    val exitCode: Int,
    val stdout: ByteArray,
    val stderr: ByteArray,
    val sandboxCommand: List<String>,
    val networkIsolated: Boolean = true,
) {
    override fun equals(other: Any?): Boolean =
        other is ProcessOutput &&
            exitCode == other.exitCode &&
            stdout.contentEquals(other.stdout) &&
            stderr.contentEquals(other.stderr) &&
            sandboxCommand == other.sandboxCommand &&
            networkIsolated == other.networkIsolated

    override fun hashCode(): Int {
        var result = exitCode
        result = 31 * result + stdout.contentHashCode()
        result = 31 * result + stderr.contentHashCode()
        result = 31 * result + sandboxCommand.hashCode()
        result = 31 * result + networkIsolated.hashCode()
        return result
    }
}

data class BehaviorCaseResult(
    val input: ProcessInput,
    val original: ProcessOutput,
    val rebuilt: ProcessOutput,
) {
    val exitCodeMatches: Boolean = original.exitCode == rebuilt.exitCode
    val stdoutMatches: Boolean = original.stdout.contentEquals(rebuilt.stdout)
    val stderrMatches: Boolean = original.stderr.contentEquals(rebuilt.stderr)
    val matches: Boolean = exitCodeMatches && stdoutMatches && stderrMatches
}

data class BehaviorComparisonReport(
    val id: String,
    val originalBinary: Path,
    val rebuiltBinary: Path,
    val cases: List<BehaviorCaseResult>,
    val reportPath: Path,
) {
    val matches: Boolean = cases.all { it.matches }
    val networkIsolated: Boolean = cases.all { it.original.networkIsolated && it.rebuilt.networkIsolated }
}

class BehaviorMismatchException(message: String) : RuntimeException(message)

class SandboxUnavailableException(message: String) : RuntimeException(message)

object BwrapCapability {
    private val cache = ConcurrentHashMap<String, Boolean>()

    fun networkIsolationSupported(bwrapPath: Path, timeoutPath: Path): Boolean =
        cache.computeIfAbsent("${bwrapPath.pathString}|${timeoutPath.pathString}") {
            probe(bwrapPath, timeoutPath)
        }

    fun resetCache() {
        cache.clear()
    }

    private fun probe(bwrapPath: Path, timeoutPath: Path): Boolean {
        if (!bwrapPath.exists() || !timeoutPath.exists()) return false
        val command = listOf(
            timeoutPath.pathString,
            "3s",
            bwrapPath.pathString,
            "--unshare-net",
            "--die-with-parent",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
            "--dir",
            "/tmp",
            "/usr/bin/true",
        )
        return try {
            val process = ProcessBuilder(command)
                .redirectErrorStream(true)
                .start()
            process.inputStream.readBytes()
            process.waitFor() == 0
        } catch (_: Exception) {
            false
        }
    }
}

class SandboxRunner(
    private val timeout: Duration = Duration.ofSeconds(5),
    private val bwrapPath: Path = Path.of("/usr/bin/bwrap"),
    private val timeoutPath: Path = Path.of("/usr/bin/timeout"),
    private val networkIsolation: Boolean = BwrapCapability.networkIsolationSupported(bwrapPath, timeoutPath),
) {
    fun networkIsolationSupported(): Boolean = networkIsolation

    fun run(executable: Path, input: ProcessInput): ProcessOutput {
        if (!bwrapPath.exists()) {
            throw SandboxUnavailableException("bubblewrap not found at ${bwrapPath.pathString}; sandboxed execution is mandatory")
        }
        val executableDir = executable.toAbsolutePath().parent
        val command = mutableListOf(
            timeoutPath.pathString,
            "${timeout.toSeconds()}s",
            bwrapPath.pathString,
        )
        if (networkIsolation) {
            command += "--unshare-net"
        }
        command += listOf(
            "--die-with-parent",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--dir",
            "/tmp",
            "--ro-bind",
            executableDir.pathString,
            executableDir.pathString,
            "--chdir",
            executableDir.pathString,
            executable.toAbsolutePath().pathString,
        )
        command += input.args

        val process = ProcessBuilder(command)
            .redirectErrorStream(false)
            .start()
        process.outputStream.use { it.write(input.stdin) }
        val stdout = process.inputStream.readBytes()
        val stderr = process.errorStream.readBytes()
        val exitCode = process.waitFor()
        return ProcessOutput(
            exitCode = exitCode,
            stdout = stdout,
            stderr = stderr,
            sandboxCommand = command,
            networkIsolated = networkIsolation,
        )
    }
}

class BehaviorComparator(private val sandbox: SandboxRunner = SandboxRunner()) {
    fun compare(
        id: String,
        originalBinary: Path,
        rebuiltBinary: Path,
        cases: List<ProcessInput>,
        reportsDir: Path,
    ): BehaviorComparisonReport {
        val report = evaluate(id, originalBinary, rebuiltBinary, cases, reportsDir)
        if (!report.matches) {
            throw BehaviorMismatchException("behavior comparison failed for $id; see ${report.reportPath.pathString}")
        }
        return report
    }

    fun evaluate(
        id: String,
        originalBinary: Path,
        rebuiltBinary: Path,
        cases: List<ProcessInput>,
        reportsDir: Path,
    ): BehaviorComparisonReport {
        require(cases.isNotEmpty()) { "at least one behavior case is required" }
        reportsDir.createDirectories()
        val results = cases.map { input ->
            BehaviorCaseResult(
                input = input,
                original = sandbox.run(originalBinary, input),
                rebuilt = sandbox.run(rebuiltBinary, input),
            )
        }
        val report = BehaviorComparisonReport(
            id = id,
            originalBinary = originalBinary,
            rebuiltBinary = rebuiltBinary,
            cases = results,
            reportPath = reportsDir.resolve("$id.behavior.json"),
        )
        report.reportPath.writeText(report.toJson())
        return report
    }
}

private fun BehaviorComparisonReport.toJson(): String = """
{
  "id": "${id.escapeJson()}",
  "sandbox": "bubblewrap",
  "networkIsolated": $networkIsolated,
  "originalBinary": "${originalBinary.pathString.escapeJson()}",
  "rebuiltBinary": "${rebuiltBinary.pathString.escapeJson()}",
  "matches": $matches,
  "cases": [
${cases.joinToString(",\n") { it.toJson().prependIndent("    ") }}
  ]
}
""".trimIndent() + "\n"

private fun BehaviorCaseResult.toJson(): String = """
{
  "id": "${input.id.escapeJson()}",
  "args": [${input.args.joinToString(", ") { "\"${it.escapeJson()}\"" }}],
  "stdinHex": "${input.stdin.toHex()}",
  "matches": $matches,
  "exitCodeMatches": $exitCodeMatches,
  "stdoutMatches": $stdoutMatches,
  "stderrMatches": $stderrMatches,
  "original": ${original.toJson()},
  "rebuilt": ${rebuilt.toJson()}
}
""".trimIndent()

private fun ProcessOutput.toJson(): String = """
{
  "exitCode": $exitCode,
  "stdoutHex": "${stdout.toHex()}",
  "stderrHex": "${stderr.toHex()}",
  "networkIsolated": $networkIsolated,
  "sandboxCommand": [${sandboxCommand.joinToString(", ") { "\"${it.escapeJson()}\"" }}]
}
""".trimIndent()

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun String.escapeJson(): String =
    buildString {
        for (char in this@escapeJson) {
            when (char) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> append(char)
            }
        }
    }
