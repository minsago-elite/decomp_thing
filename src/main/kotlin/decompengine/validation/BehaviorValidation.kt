package decompengine.validation

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
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

class BehaviorOutputLimitException(message: String) : RuntimeException(message)

class BehaviorExecutionTimeoutException(message: String) : RuntimeException(message)

data class SandboxOutputLimits(
    val maximumStdoutBytes: Long = 8L * 1024 * 1024,
    val maximumStderrBytes: Long = 8L * 1024 * 1024,
    val maximumAggregateBytes: Long = 16L * 1024 * 1024,
) {
    init {
        require(maximumStdoutBytes in 1 until Int.MAX_VALUE.toLong())
        require(maximumStderrBytes in 1 until Int.MAX_VALUE.toLong())
        require(maximumAggregateBytes >= maxOf(maximumStdoutBytes, maximumStderrBytes) &&
            maximumAggregateBytes < Int.MAX_VALUE.toLong())
    }
}

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

/**
 * Lightweight compatibility runner for local validation and tests.
 *
 * This is deliberately not a production repair-validation authority: it has no verified cgroup
 * pids/memory/filesystem quota. Production repair strategies must supply their own contained
 * [decompengine.repair.RepairValidationStrategy] implementation.
 */
class SandboxRunner(
    private val timeout: Duration = Duration.ofSeconds(5),
    private val bwrapPath: Path = Path.of("/usr/bin/bwrap"),
    private val timeoutPath: Path = Path.of("/usr/bin/timeout"),
    private val networkIsolation: Boolean = BwrapCapability.networkIsolationSupported(bwrapPath, timeoutPath),
    private val outputLimits: SandboxOutputLimits = SandboxOutputLimits(),
) {
    fun networkIsolationSupported(): Boolean = networkIsolation

    fun run(executable: Path, input: ProcessInput): ProcessOutput {
        if (!bwrapPath.exists()) {
            throw SandboxUnavailableException("bubblewrap not found at ${bwrapPath.pathString}; sandboxed execution is mandatory")
        }
        val absoluteExecutable = executable.toAbsolutePath().normalize()
        val command = mutableListOf(
            timeoutPath.pathString,
            "${maxOf(1L, timeout.toSeconds())}s",
            bwrapPath.pathString,
        )
        if (networkIsolation) {
            command += "--unshare-net"
        }
        command += listOf(
            "--unshare-pid",
            "--new-session",
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
            "--dir",
            "/program",
            "--ro-bind",
            absoluteExecutable.pathString,
            "/program/executable",
            "--chdir",
            "/tmp",
            "/program/executable",
        )
        command += input.args

        val builder = ProcessBuilder(command).redirectErrorStream(false)
        builder.environment().clear()
        builder.environment()["PATH"] = "/usr/bin"
        val process = builder.start()
        val executor = Executors.newFixedThreadPool(3) { runnable ->
            Thread(runnable, "behavior-process-io").apply { isDaemon = true }
        }
        val aggregate = AtomicLong()
        val stdoutFuture = executor.submit<ByteArray> {
            readBounded(process.inputStream, "stdout", outputLimits.maximumStdoutBytes, aggregate)
        }
        val stderrFuture = executor.submit<ByteArray> {
            readBounded(process.errorStream, "stderr", outputLimits.maximumStderrBytes, aggregate)
        }
        val stdinFuture = executor.submit<Unit> { process.outputStream.use { it.write(input.stdin) } }
        var primaryFailure: Throwable? = null
        try {
            val deadline = runCatching { Math.addExact(System.nanoTime(), timeout.toNanos()) }
                .getOrDefault(Long.MAX_VALUE)
            while (process.isAlive || !stdoutFuture.isDone || !stderrFuture.isDone || !stdinFuture.isDone) {
                completedFailure(stdoutFuture)?.let { throw it }
                completedFailure(stderrFuture)?.let { throw it }
                completedFailure(stdinFuture)?.let { throw it }
                if (System.nanoTime() >= deadline) {
                    throw BehaviorExecutionTimeoutException(
                        "sandboxed behavior execution exceeded ${timeout.toMillis()} ms",
                    )
                }
                Thread.sleep(5)
            }
            val exitCode = process.exitValue()
            val stdout = awaitIo(stdoutFuture)
            val stderr = awaitIo(stderrFuture)
            awaitIo(stdinFuture)
            return ProcessOutput(
                exitCode = exitCode,
                stdout = stdout,
                stderr = stderr,
                sandboxCommand = command,
                networkIsolated = networkIsolation,
            )
        } catch (failure: Throwable) {
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            primaryFailure = failure
            throw failure
        } finally {
            var cleanupFailure: Throwable? = null
            fun cleanup(action: () -> Unit) {
                try {
                    action()
                } catch (failure: Throwable) {
                    val existing = cleanupFailure
                    if (existing == null) cleanupFailure = failure else existing.addSuppressed(failure)
                }
            }
            if (primaryFailure != null || process.isAlive) {
                cleanup { terminateProcessTree(process) }
            }
            cleanup { process.outputStream.close() }
            cleanup { process.inputStream.close() }
            cleanup { process.errorStream.close() }
            listOf(stdinFuture, stdoutFuture, stderrFuture).forEach { it.cancel(true) }
            executor.shutdownNow()
            cleanupFailure?.let { failure ->
                val primary = primaryFailure
                if (primary != null) primary.addSuppressed(failure) else throw failure
            }
        }
    }

    private fun readBounded(
        input: InputStream,
        label: String,
        maximumBytes: Long,
        aggregate: AtomicLong,
    ): ByteArray {
        input.use { stream ->
            val output = ByteArrayOutputStream(minOf(maximumBytes.toInt(), 8192))
            val buffer = ByteArray(8192)
            var streamBytes = 0L
            while (true) {
                val count = stream.read(buffer)
                if (count < 0) return output.toByteArray()
                streamBytes = Math.addExact(streamBytes, count.toLong())
                val aggregateBytes = aggregate.addAndGet(count.toLong())
                if (streamBytes > maximumBytes) {
                    throw BehaviorOutputLimitException(
                        "sandboxed behavior $label exceeds $maximumBytes bytes",
                    )
                }
                if (aggregateBytes > outputLimits.maximumAggregateBytes) {
                    throw BehaviorOutputLimitException(
                        "sandboxed behavior output exceeds ${outputLimits.maximumAggregateBytes} aggregate bytes",
                    )
                }
                output.write(buffer, 0, count)
            }
        }
    }

    private fun completedFailure(future: Future<*>): Throwable? {
        if (!future.isDone) return null
        return try {
            future.get()
            null
        } catch (failure: ExecutionException) {
            failure.cause ?: failure
        }
    }

    private fun <T> awaitIo(future: Future<T>): T = try {
        future.get()
    } catch (failure: ExecutionException) {
        throw failure.cause ?: failure
    }

    private fun terminateProcessTree(process: Process) {
        val descendants = process.toHandle().descendants().toList().asReversed()
        descendants.forEach { it.destroy() }
        process.destroy()
        if (!process.waitFor(250, TimeUnit.MILLISECONDS)) {
            descendants.forEach { if (it.isAlive) it.destroyForcibly() }
            process.destroyForcibly()
            require(process.waitFor(2, TimeUnit.SECONDS)) { "sandboxed behavior process did not terminate" }
        }
    }
}

class BehaviorComparator(
    private val sandbox: SandboxRunner = SandboxRunner(),
    private val maximumAggregateOutputBytes: Long = Long.MAX_VALUE,
) {
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
        var aggregateOutputBytes = 0L
        fun runBounded(binary: Path, input: ProcessInput): ProcessOutput {
            val output = sandbox.run(binary, input)
            aggregateOutputBytes = Math.addExact(
                aggregateOutputBytes,
                Math.addExact(output.stdout.size.toLong(), output.stderr.size.toLong()),
            )
            if (aggregateOutputBytes > maximumAggregateOutputBytes) {
                throw BehaviorOutputLimitException(
                    "behavior comparison output exceeds $maximumAggregateOutputBytes aggregate bytes",
                )
            }
            return output
        }
        val results = cases.map { input ->
            BehaviorCaseResult(
                input = input,
                original = runBounded(originalBinary, input),
                rebuilt = runBounded(rebuiltBinary, input),
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
