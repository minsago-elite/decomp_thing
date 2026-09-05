package decompengine.validation

import decompengine.project.writeProjectEvidenceAtomically
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
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

data class ProcessOutput @JvmOverloads constructor(
    val exitCode: Int,
    val stdout: ByteArray,
    val stderr: ByteArray,
    val sandboxCommand: List<String>,
    val networkIsolated: Boolean = true,
    val completionEvidence: JsonObject? = null,
) {
    override fun equals(other: Any?): Boolean =
        other is ProcessOutput &&
            exitCode == other.exitCode &&
            stdout.contentEquals(other.stdout) &&
            stderr.contentEquals(other.stderr) &&
            sandboxCommand == other.sandboxCommand &&
            networkIsolated == other.networkIsolated && completionEvidence == other.completionEvidence

    override fun hashCode(): Int {
        var result = exitCode
        result = 31 * result + stdout.contentHashCode()
        result = 31 * result + stderr.contentHashCode()
        result = 31 * result + sandboxCommand.hashCode()
        result = 31 * result + networkIsolated.hashCode()
        result = 31 * result + (completionEvidence?.hashCode() ?: 0)
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

class BehaviorExecutionOutcomeException(message: String) : RuntimeException(message)

internal fun rejectReservedWrapperExit(exitCode: Int) {
    if (exitCode !in 0..123) {
        throw BehaviorExecutionOutcomeException(
            "local wrapper exit $exitCode lacks unambiguous application completion evidence",
        )
    }
}

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
    private val launcherPath = Path.of("/bin/sh").toRealPath()
    fun networkIsolationSupported(): Boolean = networkIsolation

    internal fun evidencePolicy(capture: BehaviorEvidenceCapture): JsonObject {
        require(timeout.toMillis() > 0L && Duration.ofMillis(timeout.toMillis()) == timeout) {
            "behavior evidence requires a positive whole-millisecond timeout"
        }
        if (!bwrapPath.exists()) {
            throw SandboxUnavailableException("bubblewrap not found at ${bwrapPath.pathString}; sandboxed execution is mandatory")
        }
        return JsonObject(mapOf(
            "assurance" to JsonPrimitive("local-path-stability-checks-not-production-authority"),
            "environment" to JsonObject(mapOf("PATH" to JsonPrimitive("/usr/bin"))),
            "workingDirectory" to JsonPrimitive("/tmp"),
            "networkIsolationRequested" to JsonPrimitive(networkIsolation),
            "timeoutMillis" to JsonPrimitive(timeout.toMillis()),
            "maximumStdoutBytes" to JsonPrimitive(outputLimits.maximumStdoutBytes),
            "maximumStderrBytes" to JsonPrimitive(outputLimits.maximumStderrBytes),
            "maximumAggregateBytes" to JsonPrimitive(outputLimits.maximumAggregateBytes),
            "bubblewrap" to JsonObject(capture.executable(bwrapPath) +
                ("path" to JsonPrimitive(bwrapPath.toAbsolutePath().normalize().toString()))),
            "timeout" to JsonObject(capture.executable(timeoutPath) +
                ("path" to JsonPrimitive(timeoutPath.toAbsolutePath().normalize().toString()))),
            "completionLauncher" to JsonObject(capture.executable(launcherPath) +
                ("path" to JsonPrimitive(launcherPath.toString()))),
            "maximumCompletionBytes" to JsonPrimitive(MAXIMUM_BUBBLEWRAP_COMPLETION_BYTES),
        ))
    }

    fun run(executable: Path, input: ProcessInput): ProcessOutput = runWithFiles(executable, input, emptyMap())

    internal fun runWithFiles(executable: Path, input: ProcessInput, files: Map<String, Path>): ProcessOutput {
        val deadline = runCatching { Math.addExact(System.nanoTime(), timeout.toNanos()) }.getOrDefault(Long.MAX_VALUE)
        val directory = java.nio.file.Files.createTempDirectory("behavior-completion-")
        val channel = directory.resolve("status.jsonl")
        try {
            java.nio.file.Files.createFile(channel)
            return runWithCompletion(executable, input, files, channel, deadline)
        } finally {
            java.nio.file.Files.deleteIfExists(channel)
            java.nio.file.Files.deleteIfExists(directory)
        }
    }

    private fun runWithCompletion(executable: Path, input: ProcessInput, files: Map<String, Path>, channel: Path, deadline: Long): ProcessOutput {
        if (!bwrapPath.exists()) {
            throw SandboxUnavailableException("bubblewrap not found at ${bwrapPath.pathString}; sandboxed execution is mandatory")
        }
        val command = behaviorSandboxCommand(executable, input.args, timeout.toMillis(), bwrapPath, timeoutPath, networkIsolation, files)

        val launchCommand = completionLaunchCommand(command, launcherPath, channel)
        val builder = ProcessBuilder(launchCommand).redirectErrorStream(false)
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
            while (process.isAlive || !stdoutFuture.isDone || !stderrFuture.isDone || !stdinFuture.isDone) {
                require(java.nio.file.Files.size(channel) <= MAXIMUM_BUBBLEWRAP_COMPLETION_BYTES) { "completion channel exceeds its bound" }
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
            val completionBytes = java.nio.file.Files.newInputStream(channel).use { it.readNBytes(MAXIMUM_BUBBLEWRAP_COMPLETION_BYTES + 1) }
            try {
                parseBubblewrapCompletion(completionBytes, exitCode)
            } catch (failure: IllegalArgumentException) {
                throw BehaviorExecutionOutcomeException(failure.message ?: "completion evidence is unavailable")
            }
            if (System.nanoTime() >= deadline) throw BehaviorExecutionTimeoutException("completion capture exceeded the behavior deadline")
            return ProcessOutput(
                exitCode = exitCode,
                stdout = stdout,
                stderr = stderr,
                sandboxCommand = command,
                networkIsolated = networkIsolation,
                completionEvidence = JsonObject(mapOf(
                    "channelPath" to JsonPrimitive(channel.toString()),
                    "statusHex" to JsonPrimitive(java.util.HexFormat.of().formatHex(completionBytes)),
                    "launchCommand" to kotlinx.serialization.json.JsonArray(launchCommand.map(::JsonPrimitive)),
                )),
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
    private val maximumAggregateOutputBytes: Long = 16L * 1024 * 1024,
) {
    fun compare(
        id: String,
        originalBinary: Path,
        rebuiltBinary: Path,
        cases: List<ProcessInput>,
        reportsDir: Path,
        project: BehaviorProjectContext? = null,
        fileInputs: Map<String, Map<String, Path>> = emptyMap(),
        expectedCorpusSha256: String? = null,
    ): BehaviorComparisonReport {
        val report = evaluate(id, originalBinary, rebuiltBinary, cases, reportsDir, project, fileInputs, expectedCorpusSha256)
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
        project: BehaviorProjectContext? = null,
        fileInputs: Map<String, Map<String, Path>> = emptyMap(),
        expectedCorpusSha256: String? = null,
    ): BehaviorComparisonReport {
        require(expectedCorpusSha256 == null || expectedCorpusSha256.matches(Regex("[0-9a-f]{64}"))) {
            "expected behavior corpus digest must be a lowercase SHA-256"
        }
        require(id.matches(Regex("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"))) { "behavior report ID must be a safe filename component" }
        require(cases.size in 1..1024) { "between one and 1024 behavior cases are required" }
        require(cases.map { it.id }.distinct().size == cases.size) { "behavior case IDs must be unique" }
        require(cases.all { input -> input.id.isNotEmpty() && input.id.length <= 256 && input.args.size <= 256 &&
            input.args.all { it.length <= 64 * 1024 && '\u0000' !in it } }) { "behavior case fields exceed their bounds" }
        require(cases.sumOf { it.stdin.size.toLong() } <= 8L * 1024 * 1024 &&
            cases.sumOf { input -> input.args.sumOf { it.toByteArray().size.toLong() } } <= 1024L * 1024
        ) { "behavior corpus exceeds its byte bound" }
        val inputs = cases.map { ProcessInput(it.id, it.args.toList(), it.stdin.clone()) }
        require(fileInputs.keys.all { id -> inputs.any { it.id == id } }) { "file inputs reference an unknown behavior case" }
        val boundFiles = fileInputs.mapValues { it.value.toMap() }
        reportsDir.createDirectories()
        val capture = BehaviorEvidenceCapture()
        val fileRecords = captureBehaviorFileInputs(boundFiles, capture)
        if (expectedCorpusSha256 != null) {
            require(BehaviorEvidence.inputCorpusSha256(inputs, fileRecords) == expectedCorpusSha256) {
                "behavior corpus differs from the required corpus digest"
            }
        }
        val originalIdentity = capture.executable(originalBinary)
        val rebuiltIdentity = capture.executable(rebuiltBinary)
        val comparisonLimit = minOf(maximumAggregateOutputBytes, 16L * 1024 * 1024)
        require(comparisonLimit > 0L) { "behavior comparison output bound must be positive" }
        val policy = JsonObject(sandbox.evidencePolicy(capture) +
            ("maximumComparisonOutputBytes" to JsonPrimitive(comparisonLimit)))
        val projectRevision = project?.let { capture.project(it, originalIdentity, rebuiltBinary) }
        var aggregateOutputBytes = 0L
        fun runBounded(binary: Path, input: ProcessInput): ProcessOutput {
            capture.requireCurrent()
            val output = sandbox.runWithFiles(binary, input, boundFiles[input.id].orEmpty())
            capture.requireCurrent()
            aggregateOutputBytes = Math.addExact(
                aggregateOutputBytes,
                Math.addExact(output.stdout.size.toLong(), output.stderr.size.toLong()),
            )
            if (aggregateOutputBytes > comparisonLimit) {
                throw BehaviorOutputLimitException(
                    "behavior comparison output exceeds $comparisonLimit aggregate bytes",
                )
            }
            return output
        }
        val results = inputs.map { input ->
            BehaviorCaseResult(
                input = input,
                original = runBounded(originalBinary, input),
                rebuilt = runBounded(rebuiltBinary, input),
            )
        }
        val report = BehaviorComparisonReport(
            id = id,
            originalBinary = originalBinary.toAbsolutePath().normalize(),
            rebuiltBinary = rebuiltBinary.toAbsolutePath().normalize(),
            cases = results,
            reportPath = reportsDir.resolve("$id.behavior.json"),
        )
        if (project != null) {
            require(capture.project(project, originalIdentity, rebuiltBinary) == projectRevision) {
                "behavior project changed during execution"
            }
        }
        capture.requireCurrent()
        val encoded = BehaviorEvidence.encode(Json.parseToJsonElement(report.toJson()).jsonObject,
            originalIdentity, rebuiltIdentity, policy, projectRevision, fileRecords)
        require(encoded.toByteArray().size <= BehaviorEvidence.MAXIMUM_REPORT_BYTES) { "behavior report exceeds its byte bound" }
        capture.requireCurrent()
        writeProjectEvidenceAtomically(report.reportPath, encoded)
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
  "completionEvidence": ${completionEvidence ?: "null"},
  "exitCode": $exitCode,
  "stdoutHex": "${stdout.toHex()}",
  "stderrHex": "${stderr.toHex()}",
  "networkIsolated": $networkIsolated,
  "sandboxCommand": [${sandboxCommand.joinToString(", ") { "\"${it.escapeJson()}\"" }}]
}
""".trimIndent()

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun String.escapeJson(): String = JsonPrimitive(this).toString().removeSurrounding("\"")
