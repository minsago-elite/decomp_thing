package decompengine.analysis

import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/**
 * Runs bundle hashing, traversal and properties parsing outside the caller thread. A blocked
 * filesystem read can then be cancelled by stopping this helper process at the admitted deadline.
 */
internal class BundledGhidraVerificationProcess(
    private val commandFactory: (Path) -> List<String> = ::verificationCommand,
    private val processStarter: (List<String>, Path) -> Process = ::startVerificationProcess,
    private val captureExecutor: Executor = CAPTURE_EXECUTOR,
    private val maximumStdoutBytes: Int = MAXIMUM_INVENTORY_BYTES,
    private val maximumStderrBytes: Int = MAXIMUM_DIAGNOSTIC_BYTES,
    private val maximumWallMillis: Long = MAXIMUM_WALL_MILLIS,
) {
    init {
        require(maximumStdoutBytes in 1..MAXIMUM_INVENTORY_BYTES)
        require(maximumStderrBytes in 1..MAXIMUM_DIAGNOSTIC_BYTES)
        require(maximumWallMillis in 1..MAXIMUM_WALL_MILLIS)
    }

    fun verifyAndGetLibraries(root: Path, checkpoint: (String) -> Unit): List<Path> {
        val normalizedRoot = root.toAbsolutePath().normalize()
        checkpoint("before starting bundled Ghidra verifier")
        val started = System.nanoTime()
        val maximumNanos = TimeUnit.MILLISECONDS.toNanos(maximumWallMillis)
        val launch = try {
            CompletableFuture.supplyAsync({
                val command = commandFactory(normalizedRoot)
                require(command.isNotEmpty() && command.all { it.isNotEmpty() && it.none(::isControl) }) {
                    "bundled Ghidra verifier command is empty or ambiguous"
                }
                processStarter(command, normalizedRoot)
            }, LAUNCH_EXECUTOR)
        } catch (failure: RejectedExecutionException) {
            throw GhidraAnalysisException("bundled Ghidra verifier launch capacity is exhausted", failure)
        }
        val process = try {
            var launched: Process? = null
            while (launched == null) {
                checkpoint("while starting bundled Ghidra verifier")
                val elapsed = System.nanoTime() - started
                if (elapsed < 0 || elapsed >= maximumNanos) {
                    throw GhidraAnalysisException("bundled Ghidra verification exceeded $maximumWallMillis milliseconds")
                }
                try {
                    launched = launch.get(minOf(POLL_NANOS, maximumNanos - elapsed), TimeUnit.NANOSECONDS)
                } catch (_: java.util.concurrent.TimeoutException) {
                    // The admitted deadline also covers command preparation and process launch.
                } catch (failure: ExecutionException) {
                    throw failure.cause ?: failure
                }
            }
            checkNotNull(launched)
        } catch (failure: Throwable) {
            // A blocked launch can finish after the caller has timed out. Reap that late worker.
            launch.whenComplete { lateProcess, _ ->
                if (lateProcess != null) runCatching { stopWorker(lateProcess) }
            }
            throw failure
        }
        var stdout: CompletableFuture<ByteArray>? = null
        var stderr: CompletableFuture<ByteArray>? = null
        var primaryFailure: Throwable? = null
        try {
            stdout = drainAsync(process.inputStream, maximumStdoutBytes, process, "inventory")
            stderr = drainAsync(process.errorStream, maximumStderrBytes, process, "diagnostic")
            process.outputStream.close()
            while (process.isAlive) {
                checkpoint("while waiting for bundled Ghidra verification")
                val elapsed = System.nanoTime() - started
                if (elapsed < 0 || elapsed >= maximumNanos) {
                    throw GhidraAnalysisException("bundled Ghidra verification exceeded $maximumWallMillis milliseconds")
                }
                process.waitFor(minOf(POLL_NANOS, maximumNanos - elapsed), TimeUnit.NANOSECONDS)
            }
            checkpoint("after bundled Ghidra verifier exit")
            val outputBytes = awaitCapture(checkNotNull(stdout), "bundled Ghidra verifier inventory")
            val diagnosticBytes = awaitCapture(checkNotNull(stderr), "bundled Ghidra verifier diagnostics")
            if (process.exitValue() != 0) {
                val diagnostic = String(diagnosticBytes, StandardCharsets.UTF_8)
                    .replace('\n', ' ').replace('\r', ' ').take(MAXIMUM_DIAGNOSTIC_MESSAGE_CHARACTERS)
                throw IllegalArgumentException(
                    "bundled Ghidra verification worker exited ${process.exitValue()}" +
                        if (diagnostic.isBlank()) "" else ": $diagnostic",
                )
            }
            return parseInventory(outputBytes, normalizedRoot).also {
                checkpoint("after reading bundled Ghidra library inventory")
            }
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            var cleanupFailure: Throwable? = null
            fun recordCleanupFailure(failure: Throwable) {
                val previous = cleanupFailure
                if (previous == null) cleanupFailure = failure else previous.addSuppressed(failure)
            }
            fun closeStream(close: () -> Unit) {
                try {
                    close()
                } catch (failure: Throwable) {
                    recordCleanupFailure(failure)
                }
            }
            try {
                stopWorker(process)
            } catch (failure: Throwable) {
                recordCleanupFailure(failure)
            }
            listOfNotNull(stdout, stderr).forEach { task ->
                if (!task.isDone) task.cancel(true)
            }
            closeStream { process.inputStream.close() }
            closeStream { process.errorStream.close() }
            closeStream { process.outputStream.close() }
            cleanupFailure?.let { failure ->
                val original = primaryFailure
                if (original == null) throw failure else original.addSuppressed(failure)
            }
        }
    }

    private fun drainAsync(
        input: java.io.InputStream,
        maximumBytes: Int,
        process: Process,
        label: String,
    ): CompletableFuture<ByteArray> = try {
        CompletableFuture.supplyAsync({
            input.use {
                val bytes = it.readNBytes(maximumBytes + 1)
                if (bytes.size > maximumBytes) {
                    process.destroyForcibly()
                    throw IOException("bundled Ghidra verifier $label exceeded $maximumBytes bytes")
                }
                bytes
            }
        }, captureExecutor)
    } catch (failure: RejectedExecutionException) {
        throw GhidraAnalysisException("bundled Ghidra verifier capture capacity is exhausted", failure)
    }

    private fun awaitCapture(task: CompletableFuture<ByteArray>, label: String): ByteArray = try {
        task.get(CAPTURE_DRAIN_MILLIS, TimeUnit.MILLISECONDS)
    } catch (failure: ExecutionException) {
        throw failure.cause ?: failure
    } catch (failure: java.util.concurrent.TimeoutException) {
        throw GhidraAnalysisException("$label did not close within its bounded drain allowance", failure)
    }

    private fun parseInventory(bytes: ByteArray, root: Path): List<Path> {
        val text = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (failure: Exception) {
            throw IllegalArgumentException("bundled Ghidra verifier inventory is not valid UTF-8", failure)
        }
        require(text.endsWith('\n')) { "bundled Ghidra verifier inventory is incomplete" }
        val lines = text.split('\n')
        require(lines.size >= 4 && lines[0] == INVENTORY_PROVIDER && lines[1] == BundledGhidra.VERSION && lines.last().isEmpty()) {
            "bundled Ghidra verifier inventory has an unsupported format"
        }
        val relativePaths = lines.subList(2, lines.lastIndex)
        require(relativePaths.size in 1..MAXIMUM_JAR_COUNT && relativePaths == relativePaths.distinct().sorted()) {
            "bundled Ghidra verifier inventory is empty, oversized, duplicated or unsorted"
        }
        val libraries = relativePaths.map { raw ->
            require(raw.isNotEmpty() && raw.none(::isControl) && File.pathSeparatorChar !in raw) {
                "bundled Ghidra verifier inventory contains an ambiguous path"
            }
            val relative = Path.of(raw)
            require(!relative.isAbsolute && relative.normalize() == relative &&
                relative.parent?.fileName?.toString() == "lib" && relative.fileName.toString().endsWith(".jar")) {
                "bundled Ghidra verifier inventory contains a non-library path"
            }
            val absolute = root.resolve(relative).normalize()
            require(absolute.startsWith(root) && absolute != root) { "bundled Ghidra verifier inventory escapes its root" }
            absolute
        }
        return libraries
    }

    private fun stopWorker(process: Process) {
        val interruptedOnEntry = Thread.interrupted()
        var interruptedDuringCleanup = false
        try {
            if (process.isAlive) {
                process.destroyForcibly()
                try {
                    if (!process.waitFor(FORCE_EXIT_WAIT_MILLIS, TimeUnit.MILLISECONDS)) {
                        throw GhidraAnalysisException("bundled Ghidra verifier did not stop within its cleanup allowance")
                    }
                } catch (interrupted: InterruptedException) {
                    interruptedDuringCleanup = true
                    process.destroyForcibly()
                    throw GhidraAnalysisException("bundled Ghidra verifier cleanup was interrupted", interrupted)
                }
            }
        } finally {
            if (interruptedOnEntry || interruptedDuringCleanup) Thread.currentThread().interrupt()
        }
    }

    companion object {
        internal const val INVENTORY_PROVIDER = "decomp-bundled-ghidra-verifier-v1"
        const val MAXIMUM_INVENTORY_BYTES = 4 * 1024 * 1024
        const val MAXIMUM_DIAGNOSTIC_BYTES = 64 * 1024
        const val MAXIMUM_DIAGNOSTIC_MESSAGE_CHARACTERS = 2048
        const val MAXIMUM_JAR_COUNT = 32768
        val MAXIMUM_WALL_MILLIS = TimeUnit.HOURS.toMillis(1)
        const val FORCE_EXIT_WAIT_MILLIS = 5_000L
        const val CAPTURE_DRAIN_MILLIS = 5_000L
        val POLL_NANOS = TimeUnit.MILLISECONDS.toNanos(25)
        private val LAUNCH_EXECUTOR = ThreadPoolExecutor(
            0, 2, 60L, TimeUnit.SECONDS, SynchronousQueue(),
            { task -> Thread(task, "bundled-ghidra-verifier-launch").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        )
        private val CAPTURE_EXECUTOR = ThreadPoolExecutor(
            0, 16, 60L, TimeUnit.SECONDS, SynchronousQueue(),
            { task -> Thread(task, "bundled-ghidra-verifier-capture").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        )
    }
}

/** Small trusted IPC endpoint; all bundle reads happen in this killable process. */
internal object BundledGhidraVerificationWorker {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 1) { "bundle verifier requires one installation root" }
        val root = Path.of(arguments.single()).toAbsolutePath().normalize()
        val bundle = BundledGhidra.at(root)
        val libraries = bundle.verifiedLibraryPaths {}
        val output = System.out
        output.write("${BundledGhidraVerificationProcess.INVENTORY_PROVIDER}\n${BundledGhidra.VERSION}\n".toByteArray(StandardCharsets.UTF_8))
        libraries.forEach { path ->
            val relative = root.relativize(path).joinToString("/")
            require(relative.none(::isControl) && File.pathSeparatorChar !in relative)
            output.write(relative.toByteArray(StandardCharsets.UTF_8))
            output.write('\n'.code)
        }
        output.flush()
    }
}

private fun verificationCommand(root: Path): List<String> {
    val java = Path.of(System.getProperty("java.home"), "bin", if (File.separatorChar == '\\') "java.exe" else "java")
        .toAbsolutePath().normalize()
    require(Files.isExecutable(java)) { "The application JDK has no executable Java verifier: $java" }
    val classPath = listOf(BundledGhidra::class.java, Unit::class.java)
        .map { type -> Path.of(type.protectionDomain.codeSource.location.toURI()).toAbsolutePath().normalize() }
        .distinct()
    val entries = classPath.map(Path::toString)
    require(entries.none { File.pathSeparatorChar in it || it.any(::isControl) }) {
        "bundled Ghidra verifier classpath contains an ambiguous path"
    }
    return listOf(
        java.toString(), "-Xmx256m", "-XX:MaxMetaspaceSize=128m", "-XX:+DisableAttachMechanism",
        "-Dfile.encoding=UTF-8", "-Duser.language=en", "-Duser.country=US",
        "-cp", entries.joinToString(File.pathSeparator), BundledGhidraVerificationWorker::class.java.name, root.toString(),
    )
}

private fun startVerificationProcess(command: List<String>, root: Path): Process =
    ProcessBuilder(command).directory(root.toFile()).apply {
        environment().remove("CLASSPATH")
        environment().remove("JAVA_TOOL_OPTIONS")
        environment().remove("JDK_JAVA_OPTIONS")
        environment().remove("_JAVA_OPTIONS")
    }.start()

private fun isControl(character: Char): Boolean = character.code < 0x20 || character.code == 0x7f
