package decompengine.analysis

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.FileSystems
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Native model acquisition belongs to a bounded fixed process, not the caller's cooperative parser. */
internal class BoundedProgramModelAcquisitionProcess(
    private val commandFactory: (Path, Path, Long, Long) -> List<String> = ::modelAcquisitionCommand,
    private val processStarter: (List<String>, Path) -> Process = ::startModelAcquisition,
    private val launch: BoundedAnalysisProcessLaunch = MODEL_ACQUISITION_LAUNCH,
    private val ownership: ProgramModelAcquisitionOwnership = MODEL_ACQUISITION_OWNERSHIP,
    private val captureExecutor: Executor = MODEL_ACQUISITION_CAPTURE,
    private val controlExecutor: Executor = MODEL_ACQUISITION_CONTROL,
    private val cleanupMillis: Long = MAXIMUM_CLEANUP_MILLIS,
) {
    init { require(cleanupMillis in 1..MAXIMUM_CLEANUP_MILLIS) }

    fun read(path: Path, workDirectory: Path, maximumBytes: Long, maximumResidentBytes: Long,
        deadline: AnalysisDeadline): ByteArray {
        require(maximumBytes in 1..MAXIMUM_MODEL_BYTES)
        val residentLimit = minOf(maximumResidentBytes, MAXIMUM_WORKER_RESIDENT_BYTES)
        require(residentLimit >= MINIMUM_WORKER_RESIDENT_BYTES) {
            "program-model acquisition resident budget is below its fixed native minimum"
        }
        require(path.fileSystem === FileSystems.getDefault() && workDirectory.fileSystem === FileSystems.getDefault()) {
            "program-model acquisition requires the default filesystem; provider paths cannot be transferred as host path strings"
        }
        deadline.checkpoint("before bounded program-model acquisition")
        // Preserve the caller's filesystem traversal. Lexically normalizing a symlink followed
        // by '..' would make the helper read a different ordinary host file.
        val absolutePath = path.toAbsolutePath()
        val work = workDirectory.toAbsolutePath()
        val owner = ownership.reserve(cleanupMillis, controlExecutor)
        var primaryFailure: Throwable? = null
        try {
            owner.capture(owner.stdout, captureExecutor) { stream ->
                readModelFrame(stream, maximumBytes, deadline)
            }
            owner.capture(owner.stderr, captureExecutor) { stream ->
                readDiagnostic(stream, deadline)
            }
            owner.startControl()
            owner.launchAttempted.set(true)
            val process = launch.startWithAdmission(deadline::checkpoint, {
                val command = try {
                    val command = commandFactory(absolutePath, work, maximumBytes, residentLimit)
                    require(command.isNotEmpty() && command.all { it.isNotEmpty() && '\u0000' !in it }) {
                        "program-model acquisition command is empty or ambiguous"
                    }
                    command
                } catch (failure: Throwable) {
                    owner.launchFailed(failure)
                    throw failure
                }
                try {
                    AnalysisNativeIoHelper.beforeLaunch(command)
                    processStarter(command, work).also { process ->
                        owner.accept(process)
                        AnalysisNativeIoHelper.launchReturned(command, process)
                    }
                }
                catch (failure: Throwable) {
                    // A native starter can throw after side effects; no returned handle proves no absence.
                    AnalysisNativeIoHelper.launchUnknown(command)
                    owner.launchUnknown(failure)
                    throw failure
                }
            }, { owner.abandon() }, owner::launchFailed)
            var drainStarted: Long? = null
            while (true) {
                deadline.checkpoint("while acquiring exported program model")
                if (process.isAlive) owner.failure.get()?.let { throw captureFailure(it) }
                if (!process.isAlive) {
                    if (drainStarted == null) drainStarted = System.nanoTime()
                    if (owner.stdout.result.isDone && owner.stderr.result.isDone) break
                    val elapsed = System.nanoTime() - drainStarted
                    if (elapsed < 0 || elapsed >= TimeUnit.MILLISECONDS.toNanos(MAXIMUM_DRAIN_MILLIS)) {
                        throw GhidraAnalysisException("program-model acquisition streams did not finish within their drain allowance")
                    }
                }
                val wait = minOf(POLL_NANOS, deadline.remainingNanos("while waiting for model acquisition"))
                if (process.isAlive) process.waitFor(wait, TimeUnit.NANOSECONDS)
                else TimeUnit.NANOSECONDS.sleep(wait)
            }
            val diagnostic = completed(owner.stderr.result)
            if (process.exitValue() != 0) {
                val message = String(diagnostic, Charsets.UTF_8).replace('\n', ' ').replace('\r', ' ').take(2048)
                throw IllegalArgumentException("Ghidra program model acquisition failed with exit code ${process.exitValue()}" +
                    if (message.isBlank()) "" else ": $message")
            }
            val model = completed(owner.stdout.result)
            deadline.checkpoint("after bounded program-model acquisition")
            return model
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            owner.finishUnsubmittedCaptures()
            if (!owner.launchAttempted.get()) owner.launchFailed(IOException("model acquisition launch was not admitted"))
            owner.abandon()
            val interruptedOnEntry = Thread.interrupted()
            var interruptedDuringCleanup = false
            try {
                val cutoff = owner.cleanupCutoff()
                while (!owner.quiescent()) {
                    val remaining = remainingUntil(cutoff)
                    if (remaining == 0L) break
                    try {
                        if (owner.cleanupFinished.isDone) TimeUnit.NANOSECONDS.sleep(minOf(POLL_NANOS, remaining))
                        else owner.cleanupFinished.get(minOf(POLL_NANOS, remaining), TimeUnit.NANOSECONDS)
                    }
                    catch (_: java.util.concurrent.TimeoutException) { }
                    catch (_: InterruptedException) { interruptedDuringCleanup = true }
                    catch (failure: ExecutionException) { break }
                }
                val cleanupFailure = if (owner.quiescent()) null else owner.cleanupProblem.get()
                    ?: GhidraAnalysisException("program-model acquisition cleanup is unconfirmed; ownership and capacity are retained")
                if (cleanupFailure != null) {
                    owner.markUnconfirmed(cleanupFailure)
                    if (primaryFailure == null) throw cleanupFailure else primaryFailure.addSuppressed(cleanupFailure)
                }
            } finally {
                if (interruptedOnEntry || interruptedDuringCleanup) Thread.currentThread().interrupt()
            }
        }
    }

    private fun readModelFrame(stream: InputStream, maximumBytes: Long, deadline: AnalysisDeadline): ByteArray {
        val input = DataInputStream(BufferedInputStream(stream, MODEL_CHUNK_BYTES))
        require(input.readInt() == MODEL_FRAME_MAGIC && input.readInt() == MODEL_FRAME_VERSION) {
            "program-model acquisition returned an unsupported frame"
        }
        val length = input.readLong()
        require(length in 1..maximumBytes && length <= Int.MAX_VALUE) {
            "Ghidra program model exceeds its authenticated parser bound"
        }
        deadline.checkpoint("before allocating admitted model bytes")
        val bytes = ByteArray(length.toInt())
        val digest = MessageDigest.getInstance("SHA-256")
        var offset = 0
        while (offset < bytes.size) {
            deadline.checkpoint("before receiving model chunk")
            val count = input.read(bytes, offset, minOf(MODEL_CHUNK_BYTES, bytes.size - offset))
            require(count > 0) { "program-model acquisition returned incomplete model bytes" }
            digest.update(bytes, offset, count)
            offset += count
        }
        deadline.checkpoint("before validating acquired model footer")
        require(input.readInt() == MODEL_FRAME_END) { "program-model acquisition footer is unavailable" }
        val commitment = ByteArray(32)
        input.readFully(commitment)
        require(MessageDigest.isEqual(digest.digest(), commitment)) { "program-model acquisition digest does not match captured bytes" }
        require(input.read() == -1) { "program-model acquisition returned trailing bytes" }
        deadline.checkpoint("after receiving exported model bytes")
        return bytes
    }

    private fun readDiagnostic(stream: InputStream, deadline: AnalysisDeadline): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (true) {
            deadline.checkpoint("while receiving model acquisition diagnostics")
            val count = stream.read(buffer)
            if (count == -1) return output.toByteArray()
            require(count > 0 && count <= MAXIMUM_DIAGNOSTIC_BYTES - output.size()) {
                "program-model acquisition diagnostics exceeded their byte bound"
            }
            output.write(buffer, 0, count)
        }
    }

    private fun <T> completed(future: CompletableFuture<T>): T = try { future.get() }
        catch (failure: ExecutionException) { throw captureFailure(failure.cause ?: failure) }

    private fun captureFailure(failure: Throwable): Throwable = if (failure is IOException)
        IllegalArgumentException("Ghidra program model acquisition returned an incomplete result", failure) else failure

    companion object {
        const val MAXIMUM_MODEL_BYTES = 512L * 1024 * 1024
        const val MAXIMUM_WORKER_RESIDENT_BYTES = 256L * 1024 * 1024
        const val MINIMUM_WORKER_RESIDENT_BYTES = 64L * 1024 * 1024
        const val MAXIMUM_DIAGNOSTIC_BYTES = 64 * 1024
        const val MAXIMUM_CLEANUP_MILLIS = 5_000L
        const val MAXIMUM_DRAIN_MILLIS = 5_000L
    }
}

/** Strong references remain here while launch, process absence, or stream closure is unknown. */
internal class ProgramModelAcquisitionOwnership(private val maximumInvocations: Int = 2) {
    private val owners = linkedSetOf<ModelAcquisitionOwner>()
    init { require(maximumInvocations in 1..2) }
    @Synchronized internal fun reserve(cleanupMillis: Long, executor: Executor): ModelAcquisitionOwner {
        require(owners.none { it.unconfirmed.get() }) {
            "program-model acquisition is unavailable while previous cleanup is unconfirmed"
        }
        if (owners.size >= maximumInvocations) throw GhidraAnalysisException("program-model acquisition capacity is exhausted")
        return ModelAcquisitionOwner(this, cleanupMillis, executor).also(owners::add)
    }
    @Synchronized internal fun release(owner: ModelAcquisitionOwner) {
        if (owner.quiescent()) owners.remove(owner)
    }
    @Synchronized internal fun retainedInvocations(): Int = owners.size
}

internal class ModelCapture<T> {
    val submitted = AtomicBoolean(false)
    val result = CompletableFuture<T>()
    val finished = AtomicBoolean(false)
    val closed = AtomicBoolean(false)
    val retainedStream = AtomicReference<InputStream?>()
}

internal class ModelAcquisitionOwner(
    private val ownership: ProgramModelAcquisitionOwnership,
    private val cleanupMillis: Long,
    private val controlExecutor: Executor,
) {
    val stdout = ModelCapture<ByteArray>()
    val stderr = ModelCapture<ByteArray>()
    val launchAttempted = AtomicBoolean(false)
    val failure = AtomicReference<Throwable?>()
    val cleanupProblem = AtomicReference<Throwable?>()
    val unconfirmed = AtomicBoolean(false)
    val cleanupFinished = CompletableFuture<Unit>()
    private val process = CompletableFuture<Process>()
    private val launchSettled = AtomicBoolean(false)
    private val absent = AtomicBoolean(false)
    private val stdinClosed = AtomicBoolean(false)
    private val closing = AtomicBoolean(false)
    private val controlStarted = AtomicBoolean(false)
    private val controlFinished = AtomicBoolean(false)
    private val cutoff = AtomicReference<Long?>()
    private val handles = ConcurrentHashMap<Long, ProcessHandle>()
    private val retainedStdin = AtomicReference<OutputStream?>()

    fun accept(started: Process) {
        launchSettled.set(true)
        process.complete(started)
    }
    fun launchFailed(cause: Throwable) {
        if (process.completeExceptionally(cause)) {
            launchSettled.set(true); absent.set(true); stdinClosed.set(true)
            releaseIfQuiescent()
        }
    }
    fun launchUnknown(cause: Throwable) {
        process.completeExceptionally(cause)
        launchSettled.set(true)
        markUnconfirmed(cause)
    }
    fun <T> capture(job: ModelCapture<T>, executor: Executor, read: (InputStream) -> T) {
        check(job.submitted.compareAndSet(false, true))
        try {
            executor.execute {
                var stream: InputStream? = null
                var value: T? = null
                var problem: Throwable? = null
                try {
                    val child = process.get()
                    stream = if (job === stdout) child.inputStream else child.errorStream
                    job.retainedStream.set(stream)
                    if (closing.get()) throw IOException("program-model acquisition was abandoned before capture")
                    value = read(stream)
                } catch (caught: Throwable) {
                    problem = if (caught is ExecutionException) caught.cause ?: caught else caught
                    failure.compareAndSet(null, problem)
                } finally {
                    try { stream?.close(); job.closed.set(true); job.retainedStream.set(null) }
                    catch (caught: Throwable) {
                        cleanupProblem.compareAndSet(null, caught)
                        if (problem == null) problem = caught else problem.addSuppressed(caught)
                    }
                    job.finished.set(true)
                    releaseIfQuiescent()
                }
                val caught = problem
                if (caught == null) {
                    @Suppress("UNCHECKED_CAST") job.result.complete(value as T)
                } else job.result.completeExceptionally(caught)
            }
        } catch (caught: RejectedExecutionException) {
            job.closed.set(true); job.finished.set(true)
            throw GhidraAnalysisException("program-model acquisition capture capacity is exhausted", caught)
        }
    }
    fun finishUnsubmittedCaptures() {
        listOf(stdout, stderr).forEach { job ->
            if (!job.submitted.get()) {
                job.closed.set(true)
                job.finished.set(true)
            }
        }
    }
    fun startControl() {
        if (!controlStarted.compareAndSet(false, true)) return
        try { controlExecutor.execute(::control) }
        catch (caught: RejectedExecutionException) {
            controlFinished.set(true)
            cleanupProblem.compareAndSet(null, caught)
            throw GhidraAnalysisException("program-model acquisition control capacity is exhausted", caught)
        }
    }
    fun abandon() {
        closing.set(true)
        cleanupCutoff()
        if (!controlStarted.get()) runCatching { startControl() }.exceptionOrNull()?.let { cleanupProblem.compareAndSet(null, it) }
    }
    fun cleanupCutoff(): Long = cutoff.updateAndGet { it ?: System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(cleanupMillis) }!!
    fun markUnconfirmed(cause: Throwable) { unconfirmed.set(true); cleanupProblem.compareAndSet(null, cause) }
    fun quiescent(): Boolean = launchSettled.get() && absent.get() && stdinClosed.get() &&
        stdout.finished.get() && stdout.closed.get() && stderr.finished.get() && stderr.closed.get() && controlFinished.get()
    private fun releaseIfQuiescent() { if (quiescent()) ownership.release(this) }

    private fun control() {
        try {
            val child = try { process.get() }
                catch (_: ExecutionException) { null }
            if (child != null) {
                var completeInventory = true
                try {
                    val handle = child.toHandle()
                    handles[handle.pid()] = handle
                    while (!closing.get()) {
                        observe(child)
                        TimeUnit.NANOSECONDS.sleep(POLL_NANOS)
                    }
                    observe(child)
                } catch (caught: Throwable) {
                    completeInventory = false
                    controllerFailure(caught)
                }
                // Observation or close failure must not skip a stop attempt for known children.
                handles.values.forEach { handle ->
                    try { if (handle.isAlive) handle.destroyForcibly() }
                    catch (caught: Throwable) { controllerFailure(caught) }
                }
                if (handles.isEmpty()) {
                    // This fallback can close native streams; it stays in this owned task.
                    try { if (child.isAlive) child.destroyForcibly() }
                    catch (caught: Throwable) { controllerFailure(caught) }
                }
                // Blocking native closes stay on this bounded owned task, never the caller.
                try {
                    val stdin = child.outputStream
                    retainedStdin.set(stdin)
                    stdin.close()
                    stdinClosed.set(true)
                    retainedStdin.set(null)
                } catch (caught: Throwable) { controllerFailure(caught) }
                while (handles.values.any { it.isAlive }) {
                    if (remainingUntil(cleanupCutoff()) == 0L) markUnconfirmed(
                        GhidraAnalysisException("program-model acquisition process absence remains unproved"))
                    TimeUnit.NANOSECONDS.sleep(POLL_NANOS)
                }
                if (completeInventory && !child.isAlive) absent.set(true)
            }
            while (!stdout.finished.get() || !stderr.finished.get()) {
                if (remainingUntil(cleanupCutoff()) == 0L) markUnconfirmed(
                    GhidraAnalysisException("program-model acquisition stream quiescence remains unproved"))
                TimeUnit.NANOSECONDS.sleep(POLL_NANOS)
            }
        } catch (caught: Throwable) {
            controllerFailure(caught)
        } finally {
            controlFinished.set(true)
            releaseIfQuiescent()
            if (!cleanupFinished.isDone) cleanupFinished.complete(Unit)
        }
    }
    private fun controllerFailure(caught: Throwable) {
        failure.compareAndSet(null, caught)
        closing.set(true)
        markUnconfirmed(caught)
    }
    private fun observe(child: Process) {
        child.toHandle().descendants().use { descendants ->
            descendants.forEach { handle ->
                require(handles.size < 32 || handles.containsKey(handle.pid())) { "program-model helper process inventory exceeds its bound" }
                handles[handle.pid()] = handle
            }
        }
    }
}

/**
 * Compatibility endpoint for direct JVM fixtures. Production uses the pinned native endpoint;
 * this JVM's RSS observation is diagnostic. Partial output remains speculative until its footer.
 */
internal object BoundedProgramModelAcquisitionWorker {
    @JvmStatic fun main(arguments: Array<String>) {
        try {
            require(arguments.size == 3) { "model acquisition requires one path and two byte limits" }
            val path = Path.of(arguments[0])
            val maximumBytes = arguments[1].toLong()
            val residentLimit = arguments[2].toLong()
            require(path.isAbsolute)
            require(maximumBytes in 1..BoundedProgramModelAcquisitionProcess.MAXIMUM_MODEL_BYTES)
            require(residentLimit in BoundedProgramModelAcquisitionProcess.MINIMUM_WORKER_RESIDENT_BYTES..
                BoundedProgramModelAcquisitionProcess.MAXIMUM_WORKER_RESIDENT_BYTES)
            val output = DataOutputStream(BufferedOutputStream(System.out, MODEL_CHUNK_BYTES))
            writeStableModel(path, maximumBytes, output) { requireWorkerResidentBudget(residentLimit) }
            output.flush()
        } catch (caught: Exception) {
            System.err.println("Ghidra program model acquisition failed: ${(caught.message ?: caught.javaClass.simpleName).take(2048)}")
            kotlin.system.exitProcess(2)
        }
    }
    internal fun writeStableModel(path: Path, maximumBytes: Long, output: DataOutputStream, checkpoint: () -> Unit) {
        checkpoint()
        val before = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        require(before.isRegularFile && before.size() in 1..maximumBytes) {
            "Ghidra program model exceeds its authenticated parser bound"
        }
        FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
            require(channel.size() == before.size()) { "Ghidra program model changed while being opened" }
            output.writeInt(MODEL_FRAME_MAGIC); output.writeInt(MODEL_FRAME_VERSION); output.writeLong(before.size())
            val buffer = ByteBuffer.allocate(MODEL_CHUNK_BYTES)
            val digest = MessageDigest.getInstance("SHA-256")
            var total = 0L
            while (total < before.size()) {
                checkpoint()
                buffer.clear(); buffer.limit(minOf(MODEL_CHUNK_BYTES.toLong(), before.size() - total).toInt())
                val count = channel.read(buffer)
                require(count > 0) { "Ghidra program model changed while being read" }
                output.write(buffer.array(), 0, count)
                digest.update(buffer.array(), 0, count)
                total += count
            }
            checkpoint()
            require(channel.read(ByteBuffer.allocate(1)) == -1) { "Ghidra program model changed while being read" }
            val after = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            require(after.isRegularFile && before.fileKey() == after.fileKey() && before.size() == after.size() &&
                before.lastModifiedTime() == after.lastModifiedTime() && total == before.size() && channel.size() == before.size()) {
                "Ghidra program model changed while being read"
            }
            checkpoint()
            output.writeInt(MODEL_FRAME_END); output.write(digest.digest())
        }
    }
}

private const val MODEL_FRAME_MAGIC = 0x4d4f444c
private const val MODEL_FRAME_VERSION = 1
private const val MODEL_FRAME_END = 0x454e444d
private const val MODEL_CHUNK_BYTES = 64 * 1024
private val POLL_NANOS = TimeUnit.MILLISECONDS.toNanos(25)
private val MODEL_ACQUISITION_OWNERSHIP = ProgramModelAcquisitionOwnership()
private val MODEL_ACQUISITION_LAUNCH = BoundedAnalysisProcessLaunch()
private fun modelExecutor(threads: Int, name: String): Executor = ThreadPoolExecutor(
    0, threads, 60L, TimeUnit.SECONDS, SynchronousQueue(),
    { task -> Thread(task, name).apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy(),
)
private val MODEL_ACQUISITION_CAPTURE = modelExecutor(4, "program-model-acquisition-capture")
private val MODEL_ACQUISITION_CONTROL = modelExecutor(2, "program-model-acquisition-control")
private fun remainingUntil(cutoff: Long): Long = (cutoff - System.nanoTime()).coerceAtLeast(0L)

private fun modelAcquisitionCommand(path: Path, work: Path, maximumBytes: Long, residentLimit: Long): List<String> {
    require(work.fileSystem === FileSystems.getDefault())
    return AnalysisNativeIoHelper.modelCommand(path, maximumBytes, residentLimit)
}
private fun startModelAcquisition(command: List<String>, work: Path): Process =
    ProcessBuilder(command).directory(work.toFile()).apply {
        environment().clear()
    }.start()

private fun requireWorkerResidentBudget(maximumBytes: Long) {
    // This observation belongs only to the compatibility JVM endpoint. It is not a hard limit;
    // production's fixed native endpoint inherits a verified address-space cap before exec.
    if (!System.getProperty("os.name").equals("Linux", ignoreCase = true)) return
    val bytes = Files.newInputStream(Path.of("/proc/self/status")).use { it.readNBytes(16 * 1024 + 1) }
    require(bytes.size <= 16 * 1024) { "model worker resident-memory observation exceeds its bound" }
    val line = String(bytes, Charsets.US_ASCII).lineSequence().firstOrNull { it.startsWith("VmRSS:") }
        ?: error("model worker resident-memory observation is unavailable")
    val resident = line.trim().split(Regex("\\s+"))[1].toLong() * 1024L
    require(resident <= maximumBytes) { "program-model acquisition exceeded $maximumBytes resident bytes" }
}
