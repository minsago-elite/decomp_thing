package decompengine.analysis

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.channels.Channels
import java.nio.file.Files
import java.nio.file.FileSystems
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.NoSuchFileException
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
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
import java.util.concurrent.atomic.AtomicLong

/**
 * The fixed helper owns native report staging, and can never replace a published report. Only
 * complete, closed staging is passed to the caller. The caller's final rename is a separate,
 * non-revocable commit boundary; this class does not promise deadline enforcement for that rename.
 */
internal class BoundedAnalysisArtifactStagingProcess(
    private val commandFactory: (Path, Long) -> List<String> = ::reportStagingCommand,
    private val processStarter: (List<String>) -> Process = ::startReportStaging,
    private val launch: BoundedAnalysisProcessLaunch = REPORT_STAGING_LAUNCH,
    private val ownership: AnalysisArtifactStagingOwnership = REPORT_STAGING_OWNERSHIP,
    private val transferExecutor: Executor = REPORT_STAGING_TRANSFER,
    private val captureExecutor: Executor = REPORT_STAGING_CAPTURE,
    private val controlExecutor: Executor = REPORT_STAGING_CONTROL,
    private val cleanupMillis: Long = MAXIMUM_CLEANUP_MILLIS,
    private val deleteStaged: (Path) -> Unit = { Files.deleteIfExists(it) },
) {
    init { require(cleanupMillis in 1..MAXIMUM_CLEANUP_MILLIS) }

    fun withStagedReport(
        parent: Path,
        maximumBytes: Long,
        checkpoint: (String) -> Unit,
        render: (OutputStream) -> Unit,
        publish: (Path) -> Unit,
    ) {
        require(maximumBytes in 1..MAXIMUM_REPORT_BYTES)
        require(parent.fileSystem === FileSystems.getDefault()) {
            "native report staging requires the default filesystem; provider paths cannot be transferred as host path strings"
        }
        checkpoint("before admitting native report staging")
        // Generating this name performs no filesystem operation. A delayed creator is confined
        // to its own candidate, rather than a path reused by the next invocation.
        // This is invocation uniqueness, not a secret path-authority token. Avoid SecureRandom's
        // first-use entropy-device I/O on the caller; CREATE_NEW collision refusal remains strict.
        val name = UUID(STAGING_NAME_NONCE, STAGING_NAME_SEQUENCE.updateAndGet(Math::incrementExact))
        // Preserve the supplied directory's filesystem traversal, including a symlink followed
        // by '..'. Lexically normalizing that prefix could silently choose another directory.
        val staged = parent.toAbsolutePath().resolve(".json-report-stage-$name.tmp")
        val owner = ownership.reserve(staged, maximumBytes, checkpoint, cleanupMillis, deleteStaged)
        var primaryFailure: Throwable? = null
        try {
            owner.startCaptures(captureExecutor)
            owner.startTransfer(transferExecutor)
            owner.startControl(controlExecutor)
            owner.launchAttempted.set(true)
            launch.startWithAdmission(checkpoint, {
                val command = try {
                    commandFactory(staged, maximumBytes).also { selected ->
                        require(selected.isNotEmpty() && selected.all { it.isNotEmpty() && '\u0000' !in it }) {
                            "native report staging command is empty or ambiguous"
                        }
                    }
                } catch (failure: Throwable) { owner.launchFailed(failure); throw failure }
                try {
                    AnalysisNativeIoHelper.beforeLaunch(command)
                    processStarter(command).also { process ->
                        owner.accept(process)
                        AnalysisNativeIoHelper.launchReturned(command, process)
                    }
                }
                catch (failure: Throwable) {
                    AnalysisNativeIoHelper.launchUnknown(command)
                    owner.launchUnknown(failure)
                    throw failure
                }
            }, { owner.abandon() }, owner::launchFailed)
            // Settle candidate creation before invoking rendering callbacks. An ordinary render
            // or quota refusal must not race an unfinished native create and poison capacity.
            owner.awaitCreated()
            render(owner.output)
            owner.output.close()
            owner.awaitPrepared()
            checkpoint("after native report staging")
            publish(staged)
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            owner.finishUnsubmitted()
            if (!owner.launchAttempted.get()) owner.launchFailed(IOException("report staging launch was not admitted"))
            owner.abandon()
            val interruptedOnEntry = Thread.interrupted()
            var interruptedDuringCleanup = false
            try {
                val cutoff = owner.cleanupCutoff()
                while (!owner.quiescent()) {
                    val remaining = stagingRemaining(cutoff)
                    if (remaining == 0L) break
                    try {
                        if (owner.controlFinished.get()) TimeUnit.NANOSECONDS.sleep(minOf(STAGING_POLL_NANOS, remaining))
                        else owner.cleanupFinished.get(minOf(STAGING_POLL_NANOS, remaining), TimeUnit.NANOSECONDS)
                    } catch (_: java.util.concurrent.TimeoutException) { }
                    catch (_: InterruptedException) { interruptedDuringCleanup = true }
                    catch (_: ExecutionException) { break }
                }
                if (!owner.quiescent()) {
                    val cleanupFailure = owner.cleanupProblem.get() ?: GhidraAnalysisException(
                        "native report staging cleanup is unconfirmed; ownership and capacity are retained")
                    owner.markUnconfirmed(cleanupFailure)
                    if (primaryFailure == null) throw cleanupFailure
                    else if (cleanupFailure !== primaryFailure) primaryFailure.addSuppressed(cleanupFailure)
                }
            } finally {
                if (interruptedOnEntry || interruptedDuringCleanup) Thread.currentThread().interrupt()
            }
        }
    }

    companion object {
        const val MAXIMUM_REPORT_BYTES = 32L * 1024 * 1024
        const val MAXIMUM_CLEANUP_MILLIS = 5_000L
    }
}

/** Unknown launches and blocked closes/deletion retain both their references and bounded slots. */
internal class AnalysisArtifactStagingOwnership(private val maximumInvocations: Int = 2) {
    private val owners = linkedSetOf<AnalysisArtifactStagingOwner>()
    init { require(maximumInvocations in 1..2) }
    @Synchronized internal fun reserve(staged: Path, maximumBytes: Long, checkpoint: (String) -> Unit,
        cleanupMillis: Long, deleteStaged: (Path) -> Unit): AnalysisArtifactStagingOwner {
        require(owners.none { it.unconfirmed.get() }) {
            "native report staging is unavailable while previous cleanup is unconfirmed"
        }
        if (owners.size >= maximumInvocations) throw GhidraAnalysisException("native report staging capacity is exhausted")
        return AnalysisArtifactStagingOwner(this, staged, maximumBytes, checkpoint, cleanupMillis, deleteStaged).also(owners::add)
    }
    @Synchronized internal fun release(owner: AnalysisArtifactStagingOwner) { if (owner.quiescent()) owners.remove(owner) }
    @Synchronized internal fun retainedInvocations(): Int = owners.size
}

private sealed interface ReportStagingChunk {
    data class Bytes(val value: ByteArray) : ReportStagingChunk
    data object End : ReportStagingChunk
}

internal class AnalysisArtifactStagingOwner(
    private val ownership: AnalysisArtifactStagingOwnership,
    private val staged: Path,
    private val maximumBytes: Long,
    private val checkpoint: (String) -> Unit,
    private val cleanupMillis: Long,
    private val deleteStaged: (Path) -> Unit,
) {
    val launchAttempted = AtomicBoolean(false)
    val cleanupProblem = AtomicReference<Throwable?>()
    val unconfirmed = AtomicBoolean(false)
    val controlFinished = AtomicBoolean(false)
    val cleanupFinished = CompletableFuture<Unit>()
    private val process = CompletableFuture<Process>()
    private val launchSettled = AtomicBoolean(false)
    private val absent = AtomicBoolean(false)
    private val deleted = AtomicBoolean(false)
    private val closing = AtomicBoolean(false)
    private val failure = AtomicReference<Throwable?>()
    private val cutoff = AtomicReference<Long?>()
    private val handles = ConcurrentHashMap<Long, ProcessHandle>()
    private val chunks = ArrayBlockingQueue<ReportStagingChunk>(1)
    private val transferSubmitted = AtomicBoolean(false)
    private val transferFinished = AtomicBoolean(false)
    private val stdinClosed = AtomicBoolean(false)
    private val stdoutSubmitted = AtomicBoolean(false)
    private val stdoutFinished = AtomicBoolean(false)
    private val stdoutClosed = AtomicBoolean(false)
    private val stderrSubmitted = AtomicBoolean(false)
    private val stderrFinished = AtomicBoolean(false)
    private val stderrClosed = AtomicBoolean(false)
    private val controlSubmitted = AtomicBoolean(false)
    private val sent = CompletableFuture<ReportStagingReceipt>()
    private val received = CompletableFuture<ReportStagingReceipt>()
    private val diagnostic = CompletableFuture<ByteArray>()
    private val prepared = CompletableFuture<Unit>()
    private val retainedStdin = AtomicReference<OutputStream?>()
    private val retainedStdout = AtomicReference<InputStream?>()
    private val retainedStderr = AtomicReference<InputStream?>()
    private val createdIdentity = AtomicReference<String?>()
    private val nativeCreationStarted = AtomicBoolean(false)
    private var queuedBytes = 0L
    private var inputEnded = false

    val output: OutputStream = object : OutputStream() {
        override fun write(value: Int) = write(byteArrayOf(value.toByte()), 0, 1)
        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            java.util.Objects.checkFromIndexSize(offset, length, bytes.size)
            check(!inputEnded) { "native report staging input is closed" }
            require(length.toLong() <= maximumBytes - queuedBytes) { "native report staging exceeds its byte allowance" }
            var position = offset
            var remaining = length
            while (remaining > 0) {
                val amount = minOf(STAGING_CHUNK_BYTES, remaining)
                enqueue(ReportStagingChunk.Bytes(bytes.copyOfRange(position, position + amount)))
                queuedBytes += amount
                position += amount
                remaining -= amount
            }
        }
        override fun close() {
            if (inputEnded) return
            inputEnded = true
            enqueue(ReportStagingChunk.End)
        }
    }

    private fun enqueue(chunk: ReportStagingChunk) {
        while (true) {
            checkpoint("while transferring native report staging bytes")
            failure.get()?.let { throw it }
            check(!closing.get()) { "native report staging was abandoned" }
            if (chunks.offer(chunk, 25, TimeUnit.MILLISECONDS)) return
        }
    }
    fun accept(child: Process) { launchSettled.set(true); process.complete(child) }
    fun launchFailed(cause: Throwable) {
        if (process.completeExceptionally(cause)) {
            launchSettled.set(true); absent.set(true)
            // This callback means the supplier was never admitted, or command preparation failed
            // before start. No helper created a candidate; deleting a guessed path is unnecessary.
            deleted.set(true)
            releaseIfQuiescent()
        }
    }
    fun launchUnknown(cause: Throwable) {
        process.completeExceptionally(cause)
        launchSettled.set(true)
        markUnconfirmed(cause)
    }

    private fun isQualifiedProcessPipe(stream: OutputStream): Boolean =
        System.getProperty("os.name").equals("Linux", ignoreCase = true) && Runtime.version().feature() == 21 &&
            stream.javaClass.name == "java.lang.ProcessImpl\$ProcessPipeOutputStream" &&
            stream.javaClass.classLoader == null && stream.javaClass.module.name == "java.base"

    fun startTransfer(executor: Executor) {
        transferSubmitted.set(true)
        try { executor.execute {
            var stream: OutputStream? = null
            var receipt: ReportStagingReceipt? = null
            var problem: Throwable? = null
            try {
                val child = process.get()
                stream = child.outputStream
                retainedStdin.set(stream)
                val output = DataOutputStream(stream)
                output.writeInt(STAGING_MAGIC); output.writeInt(STAGING_VERSION)
                output.flush()
                val digest = MessageDigest.getInstance("SHA-256")
                var total = 0L
                while (true) {
                    if (closing.get()) throw IOException("native report staging transfer was abandoned")
                    val chunk = chunks.poll(25, TimeUnit.MILLISECONDS) ?: continue
                    if (chunk === ReportStagingChunk.End) break
                    val bytes = (chunk as ReportStagingChunk.Bytes).value
                    require(bytes.size.toLong() <= maximumBytes - total)
                    output.writeInt(bytes.size); output.write(bytes)
                    digest.update(bytes); total += bytes.size
                }
                receipt = ReportStagingReceipt(total, digest.digest())
                output.writeInt(0); output.writeLong(total); output.write(receipt.sha256); output.flush()
            } catch (caught: Throwable) {
                problem = stagingCause(caught)
                failure.compareAndSet(null, problem)
            } finally {
                try { stream?.close(); stdinClosed.set(true); retainedStdin.set(null) }
                catch (caught: Throwable) {
                    cleanupProblem.compareAndSet(null, caught)
                    if (problem == null) problem = caught else if (problem !== caught) problem.addSuppressed(caught)
                    // A killed JDK process can replace its pipe with a closed stream while
                    // buffered bytes remain. Its first close fails while flushing; one further
                    // close in this same retained task can acknowledge actual closure for that
                    // qualified JDK pipe. Generic filters can return a no-op second close after
                    // an underlying failure, so their closure remains unconfirmed. A blocked
                    // or persistently failing close never renews cleanup.
                    if (caught is Exception && stream != null && isQualifiedProcessPipe(stream)) try {
                        stream.close()
                        stdinClosed.set(true)
                        retainedStdin.set(null)
                    } catch (second: Throwable) {
                        if (second !== caught) caught.addSuppressed(second)
                    }
                }
                transferFinished.set(true)
                releaseIfQuiescent()
            }
            if (problem == null) sent.complete(requireNotNull(receipt)) else sent.completeExceptionally(problem)
        } } catch (caught: RejectedExecutionException) {
            transferFinished.set(true); stdinClosed.set(true)
            throw GhidraAnalysisException("native report staging transfer capacity is exhausted", caught)
        }
    }
    fun startCaptures(executor: Executor) {
        startCapture(executor, true)
        startCapture(executor, false)
    }
    private fun startCapture(executor: Executor, stdout: Boolean) {
        val submitted = if (stdout) stdoutSubmitted else stderrSubmitted
        val finished = if (stdout) stdoutFinished else stderrFinished
        val closed = if (stdout) stdoutClosed else stderrClosed
        val retained = if (stdout) retainedStdout else retainedStderr
        submitted.set(true)
        try { executor.execute {
            var stream: InputStream? = null
            var receipt: ReportStagingReceipt? = null
            var bytes: ByteArray? = null
            var problem: Throwable? = null
            try {
                val child = process.get()
                stream = if (stdout) child.inputStream else child.errorStream
                retained.set(stream)
                if (stdout) receipt = readStagingReceipt(stream, maximumBytes,
                    { nativeCreationStarted.set(true) }, { createdIdentity.set(it) })
                else {
                    bytes = stream.readNBytes(STAGING_DIAGNOSTIC_BYTES + 1)
                    require(bytes.size <= STAGING_DIAGNOSTIC_BYTES) { "native report staging diagnostic allowance exceeded" }
                    require(stream.read() == -1) { "native report staging diagnostics are incomplete" }
                }
            } catch (caught: Throwable) {
                problem = stagingCause(caught)
                failure.compareAndSet(null, problem)
            } finally {
                try { stream?.close(); closed.set(true); retained.set(null) }
                catch (caught: Throwable) { cleanupProblem.compareAndSet(null, caught); if (problem == null) problem = caught else problem.addSuppressed(caught) }
                finished.set(true)
                releaseIfQuiescent()
            }
            if (stdout) {
                if (problem == null) received.complete(requireNotNull(receipt)) else received.completeExceptionally(problem)
            } else {
                if (problem == null) diagnostic.complete(requireNotNull(bytes)) else diagnostic.completeExceptionally(problem)
            }
        } } catch (caught: RejectedExecutionException) {
            finished.set(true); closed.set(true)
            throw GhidraAnalysisException("native report staging capture capacity is exhausted", caught)
        }
    }
    fun startControl(executor: Executor) {
        controlSubmitted.set(true)
        try { executor.execute(::control) }
        catch (caught: RejectedExecutionException) {
            controlFinished.set(true)
            markUnconfirmed(caught)
            throw GhidraAnalysisException("native report staging control capacity is exhausted", caught)
        }
    }
    fun awaitPrepared() {
        while (true) {
            checkpoint("while waiting for native report staging completion")
            failure.get()?.let { throw it }
            try { prepared.get(25, TimeUnit.MILLISECONDS); break }
            catch (_: java.util.concurrent.TimeoutException) { }
            catch (caught: ExecutionException) { throw stagingCause(caught) }
        }
        val expected = sent.get()
        val actual = received.get()
        require(expected.bytes == actual.bytes && MessageDigest.isEqual(expected.sha256, actual.sha256)) {
            "native report staging receipt does not match the transferred bytes"
        }
    }
    fun awaitCreated() {
        while (createdIdentity.get() == null) {
            checkpoint("while waiting for native report staging creation")
            failure.get()?.let { throw it }
            TimeUnit.NANOSECONDS.sleep(STAGING_POLL_NANOS)
        }
        checkpoint("after native report staging creation")
    }
    fun finishUnsubmitted() {
        if (!transferSubmitted.get()) { transferFinished.set(true); stdinClosed.set(true) }
        if (!stdoutSubmitted.get()) { stdoutFinished.set(true); stdoutClosed.set(true) }
        if (!stderrSubmitted.get()) { stderrFinished.set(true); stderrClosed.set(true) }
        if (!controlSubmitted.get()) {
            // No controller can prove deletion/absence; retain the owner instead of inventing it.
            controlFinished.set(true)
        }
    }
    fun abandon() { closing.set(true); cleanupCutoff() }
    fun cleanupCutoff(): Long = cutoff.updateAndGet { it ?: System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(cleanupMillis) }!!
    fun markUnconfirmed(cause: Throwable) { unconfirmed.set(true); cleanupProblem.compareAndSet(null, cause) }
    private fun streamsQuiescent(): Boolean = transferFinished.get() && stdinClosed.get() &&
        stdoutFinished.get() && stdoutClosed.get() && stderrFinished.get() && stderrClosed.get()
    fun quiescent(): Boolean = launchSettled.get() && absent.get() && streamsQuiescent() && deleted.get() && controlFinished.get()
    private fun releaseIfQuiescent() { if (quiescent()) ownership.release(this) }

    private fun control() {
        try {
            val child = try { process.get() } catch (_: ExecutionException) { null }
            var inventoryComplete = true
            if (child != null) {
                try {
                    val handle = child.toHandle()
                    handles[handle.pid()] = handle
                    while (!closing.get()) {
                        observe(child)
                        if (!child.isAlive && handles.values.none { it.isAlive } && streamsQuiescent() &&
                            sent.isDone && received.isDone && diagnostic.isDone) {
                            if (child.exitValue() != 0) {
                                failure.compareAndSet(null, GhidraAnalysisException(
                                    "native report staging helper failed with exit code ${child.exitValue()}"))
                                closing.set(true)
                                cleanupCutoff()
                                continue
                            }
                            absent.set(true)
                            prepared.complete(Unit)
                            // No process can add descendants after this complete absence proof.
                            // Keep the artifact lease without re-enumerating a recyclable PID.
                            while (!closing.get()) TimeUnit.NANOSECONDS.sleep(STAGING_POLL_NANOS)
                            break
                        }
                        TimeUnit.NANOSECONDS.sleep(STAGING_POLL_NANOS)
                    }
                    if (!absent.get()) observe(child)
                } catch (caught: Throwable) {
                    inventoryComplete = false
                    failure.compareAndSet(null, caught)
                    closing.set(true)
                    cleanupCutoff()
                }
                handles.values.forEach { handle ->
                    try { if (handle.isAlive) handle.destroyForcibly() }
                    catch (caught: Throwable) { markUnconfirmed(caught); inventoryComplete = false }
                }
                if (handles.isEmpty()) {
                    try { if (child.isAlive) child.destroyForcibly() }
                    catch (caught: Throwable) { markUnconfirmed(caught) }
                }
                while (handles.values.any { it.isAlive }) {
                    if (stagingRemaining(cleanupCutoff()) == 0L) markUnconfirmed(
                        GhidraAnalysisException("native report staging process absence remains unproved"))
                    TimeUnit.NANOSECONDS.sleep(STAGING_POLL_NANOS)
                }
                if (inventoryComplete && !child.isAlive) absent.set(true)
            }
            while (!streamsQuiescent()) {
                if (stagingRemaining(cleanupCutoff()) == 0L) markUnconfirmed(
                    GhidraAnalysisException("native report staging stream quiescence remains unproved"))
                TimeUnit.NANOSECONDS.sleep(STAGING_POLL_NANOS)
            }
            if (absent.get() && !deleted.get()) {
                // Native deletion stays on this capped retained task. If it blocks or fails,
                // the caller's cleanup window ends without releasing this owner or candidate.
                require(!nativeCreationStarted.get() || createdIdentity.get() != null) {
                    "native report staging creation outcome is unconfirmed; candidate and capacity are retained"
                }
                val current = try { Files.readAttributes(staged, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS) }
                    catch (_: NoSuchFileException) { null }
                if (current != null) {
                    val expected = createdIdentity.get()
                    require(expected != null && current.isRegularFile && current.fileKey()?.toString() == expected) {
                        "native report staging candidate ownership is unconfirmed; candidate and capacity are retained"
                    }
                    deleteStaged(staged)
                }
                deleted.set(true)
            }
        } catch (caught: Throwable) {
            failure.compareAndSet(null, caught)
            prepared.completeExceptionally(caught)
            markUnconfirmed(caught)
        } finally {
            controlFinished.set(true)
            releaseIfQuiescent()
            cleanupFinished.complete(Unit)
        }
    }
    private fun observe(child: Process) {
        child.toHandle().descendants().use { descendants -> descendants.forEach { handle ->
            require(handles.size < 32 || handles.containsKey(handle.pid())) { "native report staging process inventory exceeds its bound" }
            handles[handle.pid()] = handle
        } }
    }
}

private data class ReportStagingReceipt(val bytes: Long, val sha256: ByteArray)
private fun readStagingReceipt(stream: InputStream, maximumBytes: Long, opening: () -> Unit,
    created: (String) -> Unit): ReportStagingReceipt {
    val input = DataInputStream(BufferedInputStream(stream, 128))
    require(input.readInt() == STAGING_MAGIC && input.readInt() == STAGING_VERSION) { "native report staging receipt version is unsupported" }
    require(input.readInt() == STAGING_OPENING) { "native report staging opening proof is unavailable" }
    opening()
    require(input.readInt() == STAGING_CREATED) { "native report staging creation proof is unavailable" }
    val keyLength = input.readInt()
    require(keyLength in 1..256) { "native report staging creation identity exceeds its bound" }
    val keyBytes = ByteArray(keyLength)
    input.readFully(keyBytes)
    require(keyBytes.all { it.toInt() in 0x20..0x7e }) { "native report staging creation identity is ambiguous" }
    created(String(keyBytes, Charsets.US_ASCII))
    require(input.readInt() == STAGING_COMPLETE) { "native report staging completion proof is unavailable" }
    val bytes = input.readLong()
    require(bytes in 1..maximumBytes) { "native report staging receipt exceeds its byte allowance" }
    val digest = ByteArray(32)
    input.readFully(digest)
    require(input.read() == -1) { "native report staging returned trailing receipt bytes" }
    return ReportStagingReceipt(bytes, digest)
}

/**
 * Compatibility endpoint for direct JVM fixtures. Production uses the pinned native endpoint;
 * this JVM's periodic RSS observation is diagnostic and does not enforce a native memory cap.
 */
internal object BoundedAnalysisArtifactStagingWorker {
    @JvmStatic fun main(arguments: Array<String>) {
        try {
            require(arguments.size == 2) { "report staging requires a unique candidate and byte allowance" }
            val staged = Path.of(arguments[0])
            val maximumBytes = arguments[1].toLong()
            require(staged.isAbsolute &&
                staged.fileName.toString().matches(Regex("\\.json-report-stage-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.tmp"))) {
                "report staging candidate is not a unique private name"
            }
            require(maximumBytes in 1..BoundedAnalysisArtifactStagingProcess.MAXIMUM_REPORT_BYTES)
            stage(staged, maximumBytes, System.`in`, System.out)
        } catch (caught: Exception) {
            System.err.println("native report staging failed: ${(caught.message ?: caught.javaClass.simpleName).take(2048)}")
            kotlin.system.exitProcess(2)
        }
    }
    internal fun stage(staged: Path, maximumBytes: Long, inputStream: InputStream, receiptStream: OutputStream) {
        requireStagingResidentBudget()
        val input = DataInputStream(BufferedInputStream(inputStream, STAGING_CHUNK_BYTES))
        require(input.readInt() == STAGING_MAGIC && input.readInt() == STAGING_VERSION) { "report staging input version is unsupported" }
        val receipt = DataOutputStream(receiptStream)
        // This marker precedes every candidate/directory native operation. If creation is killed
        // before its identity is returned, absence of the process cannot settle that transaction.
        receipt.writeInt(STAGING_MAGIC); receipt.writeInt(STAGING_VERSION); receipt.writeInt(STAGING_OPENING); receipt.flush()
        Files.createDirectories(requireNotNull(staged.parent))
        val digest = MessageDigest.getInstance("SHA-256")
        var total = 0L
        var completedDigest: ByteArray? = null
        Files.newByteChannel(staged,
            setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")),
        ).use { channel ->
            val attributes = Files.readAttributes(staged, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            require(attributes.isRegularFile)
            val identityText = requireNotNull(attributes.fileKey()).toString()
            require(identityText.length in 1..256 && identityText.all { it.code in 0x20..0x7e }) {
                "report staging filesystem has no bounded file identity"
            }
            val identity = identityText.toByteArray(Charsets.US_ASCII)
            receipt.writeInt(STAGING_CREATED)
            receipt.writeInt(identity.size); receipt.write(identity); receipt.flush()
            BufferedOutputStream(Channels.newOutputStream(channel), STAGING_CHUNK_BYTES).use { output ->
                val buffer = ByteArray(STAGING_CHUNK_BYTES)
                while (true) {
                    requireStagingResidentBudget()
                    val length = input.readInt()
                    if (length == 0) break
                    require(length in 1..STAGING_CHUNK_BYTES && length.toLong() <= maximumBytes - total) {
                        "report staging input exceeds its chunk or byte allowance"
                    }
                    input.readFully(buffer, 0, length)
                    output.write(buffer, 0, length)
                    digest.update(buffer, 0, length)
                    total += length
                }
                require(total in 1..maximumBytes && input.readLong() == total) { "report staging input length does not match" }
                val expected = ByteArray(32)
                input.readFully(expected)
                val actual = digest.digest()
                require(MessageDigest.isEqual(expected, actual) && input.read() == -1) { "report staging input digest or EOF does not match" }
                output.flush()
                // Receipt publication happens only after the output channel has actually closed.
                completedDigest = actual
            }
        }
        requireStagingResidentBudget()
        receipt.writeInt(STAGING_COMPLETE); receipt.writeLong(total)
        receipt.write(requireNotNull(completedDigest))
        receipt.flush()
    }
}

private const val STAGING_MAGIC = 0x53544752
private const val STAGING_VERSION = 1
private const val STAGING_OPENING = 0x4f50454e
private const val STAGING_CREATED = 0x43524541
private const val STAGING_COMPLETE = 0x434f4d50
private const val STAGING_CHUNK_BYTES = 8 * 1024
private const val STAGING_DIAGNOSTIC_BYTES = 4 * 1024
private val STAGING_POLL_NANOS = TimeUnit.MILLISECONDS.toNanos(25)
private val STAGING_NAME_NONCE = System.nanoTime()
private val STAGING_NAME_SEQUENCE = AtomicLong()
private val REPORT_STAGING_OWNERSHIP = AnalysisArtifactStagingOwnership()
private val REPORT_STAGING_LAUNCH = BoundedAnalysisProcessLaunch()
private fun stagingExecutor(threads: Int, name: String): Executor = ThreadPoolExecutor(
    0, threads, 60L, TimeUnit.SECONDS, SynchronousQueue(),
    { task -> Thread(task, name).apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy(),
)
private val REPORT_STAGING_TRANSFER = stagingExecutor(2, "analysis-report-staging-transfer")
private val REPORT_STAGING_CAPTURE = stagingExecutor(4, "analysis-report-staging-capture")
private val REPORT_STAGING_CONTROL = stagingExecutor(2, "analysis-report-staging-control")
private fun stagingRemaining(cutoff: Long): Long = (cutoff - System.nanoTime()).coerceAtLeast(0L)
private fun stagingCause(caught: Throwable): Throwable = if (caught is ExecutionException) caught.cause ?: caught else caught

private fun reportStagingCommand(staged: Path, maximumBytes: Long): List<String> {
    return AnalysisNativeIoHelper.reportCommand(staged, maximumBytes)
}
private fun startReportStaging(command: List<String>): Process = ProcessBuilder(command).apply {
    // The fixed static endpoint requires no inherited environment or external runtime.
    environment().clear()
}.start()
private fun requireStagingResidentBudget() {
    if (!System.getProperty("os.name").equals("Linux", ignoreCase = true)) return
    val bytes = Files.newInputStream(Path.of("/proc/self/status")).use { it.readNBytes(16 * 1024 + 1) }
    require(bytes.size <= 16 * 1024)
    val line = String(bytes, Charsets.US_ASCII).lineSequence().firstOrNull { it.startsWith("VmRSS:") }
        ?: error("report staging resident-memory observation is unavailable")
    val resident = line.trim().split(Regex("\\s+"))[1].toLong() * 1024L
    require(resident <= 64L * 1024 * 1024) { "report staging exceeded its 64 MiB resident allowance" }
}
