package decompengine.analysis

import decompengine.binary.BoundedElfMetadataInspection
import decompengine.binary.BoundedElfMetadataLimits
import decompengine.binary.BoundedElfMetadataLimitException
import decompengine.binary.BoundedElfMetadataReader
import decompengine.binary.BoundedElfMetadataUsage
import decompengine.binary.ElfMetadata
import decompengine.binary.InvalidElfException
import decompengine.binary.SymbolBinding
import decompengine.binary.SymbolInventory
import decompengine.binary.SymbolKind
import decompengine.binary.UnresolvedSymbol
import decompengine.oracle.fulltree.FullTreeControlException
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.Collections
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/**
 * Runs descriptor-authenticated ELF metadata reads in a killable JVM. Checkpoints still enforce
 * parser work and elapsed limits; process isolation also bounds a native pread that ignores thread
 * interruption.
 */
internal class BoundedElfMetadataInspectionProcess(
    private val commandFactory: (Path, BoundedElfMetadataLimits) -> List<String> = ::metadataWorkerCommand,
    private val processStarter: (List<String>, Path) -> Process = ::startMetadataWorker,
    private val captureExecutor: Executor = CAPTURE_EXECUTOR,
    private val maximumStderrBytes: Int = MAXIMUM_DIAGNOSTIC_BYTES,
    private val maximumWallMillis: Long = MAXIMUM_WALL_MILLIS,
) {
    init {
        require(maximumStderrBytes in 1..MAXIMUM_DIAGNOSTIC_BYTES)
        require(maximumWallMillis in 1..MAXIMUM_WALL_MILLIS)
    }

    fun inspect(
        inputPath: Path,
        limits: BoundedElfMetadataLimits,
        checkpoint: (String) -> Unit,
    ): BoundedElfMetadataInspection {
        val path = inputPath.toAbsolutePath().normalize()
        val started = System.nanoTime()
        val maximumNanos = TimeUnit.MILLISECONDS.toNanos(minOf(maximumWallMillis, limits.maximumWallClockMillis))
        checkpoint("before starting bounded ELF metadata worker")
        val command = commandFactory(path, limits)
        require(command.isNotEmpty() && command.all(String::isNotEmpty)) {
            "bounded ELF metadata worker command is empty"
        }
        checkpoint("before launching bounded ELF metadata worker")
        val launch = try {
            CompletableFuture.supplyAsync({ processStarter(command, path.parent ?: path) }, LAUNCH_EXECUTOR)
        } catch (failure: RejectedExecutionException) {
            throw GhidraAnalysisException("bounded ELF metadata worker launch capacity is exhausted", failure)
        }
        val process = try {
            var startedProcess: Process? = null
            while (startedProcess == null) {
                checkpoint("while launching bounded ELF metadata worker")
                val remaining = remainingNanos(started, maximumNanos, "before worker launch")
                try {
                    startedProcess = launch.get(minOf(POLL_NANOS, remaining), TimeUnit.NANOSECONDS)
                } catch (_: java.util.concurrent.TimeoutException) {
                    // The admitted metadata deadline includes command preparation and process launch.
                } catch (failure: ExecutionException) {
                    throw failure.cause ?: failure
                }
            }
            startedProcess
        } catch (failure: Throwable) {
            launch.whenComplete { lateProcess, _ ->
                if (lateProcess != null) runCatching { stopWorker(lateProcess) }
            }
            throw failure
        }

        var stdout: CompletableFuture<ByteArray>? = null
        var stderr: CompletableFuture<ByteArray>? = null
        var primaryFailure: Throwable? = null
        try {
            val maximumResultBytes = Math.addExact(limits.maximumModeledMetadataBytes, MAXIMUM_PROTOCOL_OVERHEAD_BYTES)
                .toInt()
            stdout = drainAsync(process.inputStream, maximumResultBytes, process, "result")
            stderr = drainAsync(process.errorStream, maximumStderrBytes, process, "diagnostic")
            process.outputStream.close()
            while (process.isAlive) {
                checkpoint("while waiting for bounded ELF metadata worker")
                val remaining = remainingNanos(started, maximumNanos, "while waiting for worker")
                process.waitFor(minOf(POLL_NANOS, remaining), TimeUnit.NANOSECONDS)
            }
            checkpoint("after bounded ELF metadata worker exit")
            val result = awaitCapture(checkNotNull(stdout), "bounded ELF metadata result", started, maximumNanos, checkpoint)
            val diagnostic = awaitCapture(checkNotNull(stderr), "bounded ELF metadata diagnostic", started, maximumNanos, checkpoint)
            val exitCode = process.exitValue()
            if (exitCode != 0) {
                val text = String(diagnostic, StandardCharsets.UTF_8)
                    .replace('\n', ' ').replace('\r', ' ').take(MAXIMUM_DIAGNOSTIC_MESSAGE_CHARACTERS)
                throw GhidraAnalysisException(
                    "bounded ELF metadata worker exited $exitCode" + if (text.isBlank()) "" else ": $text",
                )
            }
            val decodeCheckpoint: (String) -> Unit = { stage ->
                checkpoint(stage)
                remainingNanos(started, maximumNanos, stage)
            }
            val inspection = MetadataInspectionProtocol.decode(result, limits, decodeCheckpoint)
            checkpoint("after bounded ELF metadata result validation")
            remainingNanos(started, maximumNanos, "after worker result validation")
            return inspection
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            var cleanupFailure: Throwable? = null
            fun cleanup(action: () -> Unit) {
                try {
                    action()
                } catch (failure: Throwable) {
                    val original = primaryFailure ?: cleanupFailure
                    if (original == null) cleanupFailure = failure else original.addSuppressed(failure)
                }
            }
            cleanup { stopWorker(process) }
            listOfNotNull(stdout, stderr).forEach { task ->
                if (!task.isDone) cleanup { task.cancel(true) }
            }
            cleanup { process.inputStream.close() }
            cleanup { process.errorStream.close() }
            cleanup { process.outputStream.close() }
            cleanupFailure?.let { throw it }
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
                    throw IOException("bounded ELF metadata worker $label exceeded $maximumBytes bytes")
                }
                bytes
            }
        }, captureExecutor)
    } catch (failure: RejectedExecutionException) {
        throw GhidraAnalysisException("bounded ELF metadata worker capture capacity is exhausted", failure)
    }

    private fun awaitCapture(
        task: CompletableFuture<ByteArray>,
        label: String,
        started: Long,
        maximumNanos: Long,
        checkpoint: (String) -> Unit,
    ): ByteArray {
        val drainStarted = System.nanoTime()
        val drainAllowance = TimeUnit.MILLISECONDS.toNanos(CAPTURE_DRAIN_MILLIS)
        while (true) {
            checkpoint("while collecting $label")
            val operationRemaining = remainingNanos(started, maximumNanos, "while collecting worker output")
            val drainElapsed = System.nanoTime() - drainStarted
            if (drainElapsed < 0 || drainElapsed >= drainAllowance) {
                throw GhidraAnalysisException("$label did not close within its bounded drain allowance")
            }
            val remaining = minOf(operationRemaining, drainAllowance - drainElapsed)
            try {
                return task.get(minOf(POLL_NANOS, remaining), TimeUnit.NANOSECONDS)
            } catch (_: java.util.concurrent.TimeoutException) {
                if (task.isDone) return task.get()
            } catch (failure: ExecutionException) {
                throw failure.cause ?: failure
            }
        }
    }

    private fun remainingNanos(started: Long, maximumNanos: Long, stage: String): Long {
        val elapsed = System.nanoTime() - started
        if (elapsed < 0 || elapsed >= maximumNanos) {
            throw GhidraAnalysisException("bounded ELF metadata inspection exceeded its wall-clock limit $stage")
        }
        return maximumNanos - elapsed
    }

    private fun stopWorker(process: Process) {
        val interruptedOnEntry = Thread.interrupted()
        var interruptedDuringCleanup = false
        try {
            if (process.isAlive) {
                process.destroyForcibly()
                try {
                    if (!process.waitFor(FORCE_EXIT_WAIT_MILLIS, TimeUnit.MILLISECONDS)) {
                        throw GhidraAnalysisException("bounded ELF metadata worker did not stop within its cleanup allowance")
                    }
                } catch (interrupted: InterruptedException) {
                    interruptedDuringCleanup = true
                    process.destroyForcibly()
                    throw GhidraAnalysisException("bounded ELF metadata worker cleanup was interrupted", interrupted)
                }
            }
        } finally {
            if (interruptedOnEntry || interruptedDuringCleanup) Thread.currentThread().interrupt()
        }
    }

    companion object {
        const val MAXIMUM_DIAGNOSTIC_BYTES = 64 * 1024
        const val MAXIMUM_DIAGNOSTIC_MESSAGE_CHARACTERS = 2048
        const val MAXIMUM_PROTOCOL_OVERHEAD_BYTES = 1024L * 1024L
        const val FORCE_EXIT_WAIT_MILLIS = 5_000L
        const val CAPTURE_DRAIN_MILLIS = 5_000L
        val MAXIMUM_WALL_MILLIS = TimeUnit.MINUTES.toMillis(10)
        val POLL_NANOS = TimeUnit.MILLISECONDS.toNanos(25)
        private val LAUNCH_EXECUTOR = ThreadPoolExecutor(
            0, 2, 60L, TimeUnit.SECONDS, SynchronousQueue(),
            { task -> Thread(task, "elf-metadata-worker-launch").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        )
        private val CAPTURE_EXECUTOR = ThreadPoolExecutor(
            0, 4, 60L, TimeUnit.SECONDS, SynchronousQueue(),
            { task -> Thread(task, "elf-metadata-worker-capture").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        )
    }
}

internal object BoundedElfMetadataInspectionWorker {
    @JvmStatic
    fun main(arguments: Array<String>) {
        val output = DataOutputStream(BufferedOutputStream(System.out))
        try {
            require(arguments.size == 12) { "bounded ELF metadata worker requires one path and eleven limits" }
            val path = Path.of(arguments[0])
            val limits = BoundedElfMetadataLimits(
                maximumInputBytes = arguments[1].toLong(),
                maximumSectionHeaders = arguments[2].toInt(),
                maximumScannedSymbols = arguments[3].toLong(),
                maximumRetainedSymbols = arguments[4].toInt(),
                maximumNameBytes = arguments[5].toInt(),
                maximumNameByteVisits = arguments[6].toLong(),
                maximumRetainedNameBytes = arguments[7].toLong(),
                maximumModeledMetadataBytes = arguments[8].toLong(),
                maximumMetadataReadBytes = arguments[9].toLong(),
                maximumWorkUnits = arguments[10].toLong(),
                maximumWallClockMillis = arguments[11].toLong(),
            )
            val inspection = try {
                WorkerResult.Success(BoundedElfMetadataReader.read(path, limits))
            } catch (failure: Exception) {
                WorkerResult.Failure(failure)
            }
            MetadataInspectionProtocol.write(output, inspection)
            output.flush()
        } catch (failure: Exception) {
            // Invalid worker arguments are a protocol failure; never emit diagnostics on stdout.
            System.err.println("bounded ELF metadata worker failed: ${failure.message ?: failure.javaClass.simpleName}")
            throw failure
        }
    }
}

private sealed interface WorkerResult {
    data class Success(val inspection: BoundedElfMetadataInspection) : WorkerResult
    data class Failure(val cause: Exception) : WorkerResult
}

private object MetadataInspectionProtocol {
    private const val MAGIC = 0x454c464d
    private const val VERSION = 1
    private const val SUCCESS = 0
    private const val FAILURE = 1
    private const val FAILURE_LIMIT = 1
    private const val FAILURE_INVALID_ELF = 2
    private const val FAILURE_INPUT = 3
    private const val FAILURE_OTHER = 4

    fun write(output: DataOutputStream, result: WorkerResult) {
        output.writeInt(MAGIC)
        output.writeInt(VERSION)
        when (result) {
            is WorkerResult.Success -> {
                output.writeByte(SUCCESS)
                writeInspection(output, result.inspection)
            }
            is WorkerResult.Failure -> {
                output.writeByte(FAILURE)
                val cause = result.cause
                val kind = when (cause) {
                    is BoundedElfMetadataLimitException -> FAILURE_LIMIT
                    is InvalidElfException -> FAILURE_INVALID_ELF
                    is FullTreeControlException -> FAILURE_INPUT
                    else -> FAILURE_OTHER
                }
                output.writeByte(kind)
                output.writeUTF((cause.message ?: cause.javaClass.simpleName).take(BoundedElfMetadataInspectionProcess.MAXIMUM_DIAGNOSTIC_MESSAGE_CHARACTERS))
            }
        }
    }

    fun decode(
        bytes: ByteArray,
        limits: BoundedElfMetadataLimits,
        checkpoint: (String) -> Unit,
    ): BoundedElfMetadataInspection {
        try {
            checkpoint("before decoding bounded ELF metadata worker result")
            return DataInputStream(BufferedInputStream(ByteArrayInputStream(bytes))).use { input ->
                require(input.readInt() == MAGIC && input.readInt() == VERSION) {
                    "bounded ELF metadata worker returned an unsupported protocol"
                }
                when (input.readUnsignedByte()) {
                    SUCCESS -> readInspection(input, limits, checkpoint).also {
                        require(input.available() == 0) { "bounded ELF metadata worker returned trailing data" }
                    }
                    FAILURE -> {
                        val kind = input.readUnsignedByte()
                        val message = input.readUTF()
                        require(input.available() == 0) { "bounded ELF metadata worker returned trailing failure data" }
                        when (kind) {
                            FAILURE_LIMIT -> throw BoundedElfMetadataLimitException(message)
                            FAILURE_INVALID_ELF -> throw InvalidElfException(message)
                            FAILURE_INPUT -> throw FullTreeControlException(message)
                            FAILURE_OTHER -> throw GhidraAnalysisException("bounded ELF metadata inspection failed: $message")
                            else -> throw GhidraAnalysisException("bounded ELF metadata worker returned an unknown failure kind")
                        }
                    }
                    else -> throw GhidraAnalysisException("bounded ELF metadata worker returned an unknown result kind")
                }
            }
        } catch (failure: GhidraAnalysisException) {
            throw failure
        } catch (failure: BoundedElfMetadataLimitException) {
            throw failure
        } catch (failure: InvalidElfException) {
            throw failure
        } catch (failure: FullTreeControlException) {
            throw failure
        } catch (failure: Exception) {
            throw GhidraAnalysisException("bounded ELF metadata worker returned an invalid result", failure)
        }
    }

    private fun writeInspection(output: DataOutputStream, inspection: BoundedElfMetadataInspection) {
        output.writeLong(inspection.inputBytes)
        output.writeUTF(inspection.inputSha256)
        val metadata = inspection.metadata
        output.writeUTF(metadata.format)
        output.writeUTF(metadata.endianness)
        output.writeInt(metadata.elfVersion.toInt())
        output.writeUTF(metadata.osAbi)
        output.writeUTF(metadata.objectType)
        output.writeUTF(metadata.machine)
        output.writeLong(metadata.entryPoint.toLong())
        output.writeShort(metadata.elfHeaderSize.toInt())
        output.writeShort(metadata.programHeaderCount.toInt())
        output.writeShort(metadata.sectionHeaderCount.toInt())
        output.writeShort(metadata.sectionNameTableIndex.toInt())
        val usage = inspection.usage
        output.writeLong(usage.sectionHeadersVisited)
        output.writeLong(usage.symbolsScanned)
        output.writeLong(usage.symbolsRetained)
        output.writeLong(usage.nameBytesVisited)
        output.writeLong(usage.retainedNameBytes)
        output.writeLong(usage.modeledMetadataBytes)
        output.writeLong(usage.metadataReadBytes)
        output.writeLong(usage.workUnits)
        writeSymbols(output, inspection.symbolInventory.functions)
        writeSymbols(output, inspection.symbolInventory.objects)
        writeSymbols(output, inspection.symbolInventory.other)
    }

    private fun readInspection(
        input: DataInputStream,
        limits: BoundedElfMetadataLimits,
        checkpoint: (String) -> Unit,
    ): BoundedElfMetadataInspection {
        checkpoint("before decoding bounded ELF metadata inventory")
        val inputBytes = input.readLong()
        val inputSha256 = input.readUTF()
        val metadata = ElfMetadata(
            format = input.readUTF(),
            endianness = input.readUTF(),
            elfVersion = input.readInt().toUInt(),
            osAbi = input.readUTF(),
            objectType = input.readUTF(),
            machine = input.readUTF(),
            entryPoint = input.readLong().toULong(),
            elfHeaderSize = input.readShort().toUShort(),
            programHeaderCount = input.readShort().toUShort(),
            sectionHeaderCount = input.readShort().toUShort(),
            sectionNameTableIndex = input.readShort().toUShort(),
        )
        val usage = BoundedElfMetadataUsage(
            sectionHeadersVisited = input.readLong(),
            symbolsScanned = input.readLong(),
            symbolsRetained = input.readLong(),
            nameBytesVisited = input.readLong(),
            retainedNameBytes = input.readLong(),
            modeledMetadataBytes = input.readLong(),
            metadataReadBytes = input.readLong(),
            workUnits = input.readLong(),
        )
        val functions = readSymbols(input, limits.maximumRetainedSymbols, "function", checkpoint)
        val objects = readSymbols(input, limits.maximumRetainedSymbols - functions.size, "object", checkpoint)
        val other = readSymbols(
            input,
            limits.maximumRetainedSymbols - functions.size - objects.size,
            "other",
            checkpoint,
        )
        val inventory = SymbolInventory(functions, objects, other)
        validate(inputBytes, inputSha256, metadata, usage, inventory, limits, checkpoint)
        return BoundedElfMetadataInspection(metadata, inventory, inputBytes, inputSha256, usage)
    }

    private fun writeSymbols(output: DataOutputStream, symbols: List<UnresolvedSymbol>) {
        output.writeInt(symbols.size)
        symbols.forEach { symbol ->
            output.writeUTF(symbol.name)
            output.writeByte(symbol.kind.ordinal)
            output.writeByte(symbol.binding.ordinal)
            output.writeLong(symbol.size.toLong())
        }
    }

    private fun readSymbols(
        input: DataInputStream,
        remainingLimit: Int,
        label: String,
        checkpoint: (String) -> Unit,
    ): List<UnresolvedSymbol> {
        val count = input.readInt()
        require(count in 0..remainingLimit) { "bounded ELF metadata symbol count exceeds its selected limit" }
        return Collections.unmodifiableList(List(count) {
            if (it % CHECKPOINT_INTERVAL == 0) checkpoint("while decoding bounded ELF metadata $label symbols")
            val name = input.readUTF()
            val kind = SymbolKind.entries.getOrNull(input.readUnsignedByte())
                ?: throw GhidraAnalysisException("bounded ELF metadata worker returned an unknown symbol kind")
            val binding = SymbolBinding.entries.getOrNull(input.readUnsignedByte())
                ?: throw GhidraAnalysisException("bounded ELF metadata worker returned an unknown symbol binding")
            UnresolvedSymbol(name, kind, binding, input.readLong().toULong())
        })
    }

    private fun validate(
        inputBytes: Long,
        inputSha256: String,
        metadata: ElfMetadata,
        usage: BoundedElfMetadataUsage,
        inventory: SymbolInventory,
        limits: BoundedElfMetadataLimits,
        checkpoint: (String) -> Unit,
    ) {
        require(inputBytes in 1..limits.maximumInputBytes && inputSha256.matches(Regex("[0-9a-f]{64}"))) {
            "bounded ELF metadata worker returned an invalid input identity"
        }
        require(metadata.format in setOf("ELF32", "ELF64") && metadata.endianness in setOf("little", "big")) {
            "bounded ELF metadata worker returned an invalid ELF class or endianness"
        }
        val symbols = inventory.functions.size + inventory.objects.size + inventory.other.size
        require(symbols.toLong() == usage.symbolsRetained) {
            "bounded ELF metadata worker returned an inconsistent symbol inventory"
        }
        var encodedNameBytes = 0L
        var validatedSymbols = 0
        listOf(
            inventory.functions to SymbolKind.FUNCTION,
            inventory.objects to SymbolKind.OBJECT,
            inventory.other to SymbolKind.OTHER,
        ).forEach { (category, expectedKind) ->
            category.forEach { symbol ->
                if (validatedSymbols++ % CHECKPOINT_INTERVAL == 0) {
                    checkpoint("while validating bounded ELF metadata symbols")
                }
                require(symbol.kind == expectedKind) {
                    "bounded ELF metadata worker returned an inconsistent symbol category"
                }
                val nameBytes = symbol.name.toByteArray(StandardCharsets.UTF_8).size.toLong()
                require(nameBytes in 1..limits.maximumNameBytes.toLong()) {
                    "bounded ELF metadata worker returned a symbol name outside its selected limit"
                }
                encodedNameBytes = Math.addExact(encodedNameBytes, nameBytes)
            }
        }
        require(encodedNameBytes <= limits.maximumRetainedNameBytes &&
            usage.sectionHeadersVisited in 0..(limits.maximumSectionHeaders.toLong() + 2L) &&
            usage.symbolsScanned in 0..limits.maximumScannedSymbols &&
            usage.symbolsRetained in 0..limits.maximumRetainedSymbols.toLong() &&
            usage.nameBytesVisited in 0..limits.maximumNameByteVisits &&
            usage.retainedNameBytes in 0..limits.maximumRetainedNameBytes &&
            usage.modeledMetadataBytes in BoundedElfMetadataLimits.MINIMUM_MODELED_METADATA_BYTES..limits.maximumModeledMetadataBytes &&
            usage.metadataReadBytes in 0..limits.maximumMetadataReadBytes &&
            usage.workUnits in 0..limits.maximumWorkUnits) {
            "bounded ELF metadata worker exceeded or misreported a selected parser limit"
        }
    }

    private const val CHECKPOINT_INTERVAL = 64
}

private fun metadataWorkerCommand(path: Path, limits: BoundedElfMetadataLimits): List<String> {
    val java = Path.of(System.getProperty("java.home"), "bin", if (File.separatorChar == '\\') "java.exe" else "java")
        .toAbsolutePath().normalize()
    require(Files.isExecutable(java)) { "application JDK has no executable metadata worker: $java" }
    val entries = listOf(
        BoundedElfMetadataInspectionWorker::class.java,
        decompengine.binary.BoundedElfMetadataReader::class.java,
        decompengine.oracle.fulltree.StableControlFile::class.java,
        com.sun.jna.Native::class.java,
        Unit::class.java,
    ).map { type ->
        Path.of(type.protectionDomain.codeSource.location.toURI()).toAbsolutePath().normalize()
    }.distinct()
    require(entries.isNotEmpty() && entries.none { File.pathSeparatorChar in it.toString() }) {
        "bounded ELF metadata worker classpath contains an ambiguous path"
    }
    return listOf(
        java.toString(), "-Xmx256m", "-XX:MaxMetaspaceSize=128m", "-XX:+DisableAttachMechanism",
        "-Dfile.encoding=UTF-8", "-Duser.language=en", "-Duser.country=US",
        "-cp", entries.joinToString(File.pathSeparator), BoundedElfMetadataInspectionWorker::class.java.name,
        path.toString(), limits.maximumInputBytes.toString(), limits.maximumSectionHeaders.toString(),
        limits.maximumScannedSymbols.toString(), limits.maximumRetainedSymbols.toString(),
        limits.maximumNameBytes.toString(), limits.maximumNameByteVisits.toString(),
        limits.maximumRetainedNameBytes.toString(), limits.maximumModeledMetadataBytes.toString(),
        limits.maximumMetadataReadBytes.toString(), limits.maximumWorkUnits.toString(),
        limits.maximumWallClockMillis.toString(),
    )
}

private fun startMetadataWorker(command: List<String>, directory: Path): Process {
    val builder = ProcessBuilder(command).directory(directory.toFile())
    builder.environment().clear()
    return builder.start()
}
