package decompengine.acp

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Platform
import com.sun.jna.Pointer
import com.sun.jna.Structure
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes

/** Invocation-owned observations only; never used for admission or deadlines. */
internal class RuntimeCopyStatistics {
    enum class Operation { CHECK, READ, WRITE, FSYNC }
    /** Inclusive phase observations and retained leaf counters; never admission facts. */
    class Prefix private constructor(private val budget: (Long) -> LongArray) {
        enum class Phase { ENTRY, PREPARE, VALIDATE, VALIDATION_PINNING, VALIDATION_RECHECK,
            VALIDATION_DELETE, LAUNCH, LAUNCH_PINNING, LAUNCH_CLEANUP, BOUNDARY_CLOSE }
        enum class Owner { PREPARE, VALIDATE, LAUNCH }
        enum class Failure { TIMEOUT, CANCELLED, ERROR, OTHER }
        private val ownerThread = Thread.currentThread()
        private val entered = LongArray(Phase.entries.size) { -1 }
        private val exited = LongArray(Phase.entries.size) { -1 }
        private val remainingAtEntry = LongArray(Phase.entries.size) { -1 }
        private val remainingAtExit = LongArray(Phase.entries.size) { -1 }
        private val states = IntArray(Phase.entries.size) // 0 unseen, 1 active, 2 returned, 3 threw
        private val owners = arrayOfNulls<RuntimeCopyStatistics>(Owner.entries.size)
        private var firstFailure = -1
        private var failureObserved = false
        private var firstFailureKind = -1
        private var failureElapsed = -1L
        private var failureRemaining = -1L
        private var lastEntered = -1
        private var lastReturned = -1
        private val stack = IntArray(32)
        private var depth = 0
        @Volatile private var supported = true
        private var emitted = false

        private inline fun observe(action: () -> Unit) {
            try {
                if (Thread.currentThread() !== ownerThread) { supported = false; return }
                action()
            } catch (_: Throwable) { supported = false }
        }
        fun start(phase: Phase) = observe {
            val i = phase.ordinal
            if (states[i] != 0) { supported = false; return@observe }
            if (depth == stack.size) { supported = false; return@observe }
            stack[depth++] = i
            states[i] = 1
            lastEntered = i
            val sample = budget(System.nanoTime())
            entered[i] = sample[0]; remainingAtEntry[i] = sample[1]
        }
        fun finish(phase: Phase, returned: Boolean) = observe {
            val i = phase.ordinal
            if (states[i] != 1 || depth == 0 || stack[depth - 1] != i) { supported = false; return@observe }
            depth--
            val sample = budget(System.nanoTime())
            exited[i] = sample[0]; remainingAtExit[i] = sample[1]
            states[i] = if (returned) 2 else 3
            if (returned) lastReturned = i
            if (sample[0] < entered[i]) supported = false
        }
        fun failure(phase: Phase?, kind: Failure = Failure.OTHER) = observe {
            if (!failureObserved) {
                failureObserved = true
                firstFailure = phase?.ordinal ?: -1
                firstFailureKind = kind.ordinal
                val sample = budget(System.nanoTime())
                failureElapsed = sample[0]; failureRemaining = sample[1]
            }
        }
        fun failureCurrent(kind: Failure = Failure.OTHER) = observe {
            failure(Phase.entries.getOrNull(if (depth > 0) stack[depth - 1] else -1), kind)
        }
        fun statistics(owner: Owner): RuntimeCopyStatistics? = try {
            statisticsWith(owner) { RuntimeCopyStatistics() }
        } catch (_: Throwable) { supported = false; null }
        // Private allocation-only control seam; production always hardwires the constructor above.
        private fun statisticsWith(owner: Owner, allocate: () -> RuntimeCopyStatistics): RuntimeCopyStatistics? = try {
            allocate().also { retain(owner, it) }
        } catch (_: Throwable) { supported = false; null }
        fun retain(owner: Owner, statistics: RuntimeCopyStatistics) = observe {
            if (owners[owner.ordinal] != null) supported = false
            else owners[owner.ordinal] = statistics
        }
        internal inline fun <T> measure(phase: Phase, action: () -> T): T {
            start(phase)
            var returned = false
            try {
                val result = action()
                returned = true
                return result
            } catch (failure: Throwable) {
                this.failure(phase, if (failure is Error) Failure.ERROR else Failure.OTHER)
                throw failure
            } finally { finish(phase, returned) }
        }
        fun failureDiagnostic(): IOException? {
            var diagnostic: IOException? = null
            observe {
                if (emitted) return@observe
                emitted = true
                val phases = Phase.entries.joinToString(";") { phase ->
                    val i = phase.ordinal
                    // Exceptional inclusive spans are unknown, never invented normal timings.
                    val duration = if (states[i] == 2 && entered[i] >= 0 && exited[i] >= entered[i])
                        (exited[i] - entered[i]).toString() else "unknown"
                    "${phase.name}:${states[i]},entryNs=${entered[i]},exitNs=${exited[i]}," +
                        "remainingEntryNs=${remainingAtEntry[i]},remainingExitNs=${remainingAtExit[i]},inclusiveNs=$duration"
                }
                val leaves = Owner.entries.joinToString(";") { owner ->
                    val statistics = owners[owner.ordinal]
                    if (statistics == null) "${owner.name}:unobserved"
                    else "${owner.name}:COPY[${statistics.copy.summary()}],HASH[${statistics.hash.summary()}]"
                }
                val first = Phase.entries.getOrNull(firstFailure)?.name ?: "unobserved"
                diagnostic = IOException("acp-prelaunch-prefix-observation-v1;supported=$supported;" +
                    "firstObservedFailure=$first,kind=${Failure.entries.getOrNull(firstFailureKind)?.name ?: "unobserved"}," +
                    "failureElapsedNs=$failureElapsed,failureRemainingNs=$failureRemaining;" +
                    "lastEntered=${Phase.entries.getOrNull(lastEntered)?.name ?: "unobserved"};" +
                    "lastReturned=${Phase.entries.getOrNull(lastReturned)?.name ?: "unobserved"};" +
                    "states=0-unseen/1-active/2-returned/3-threw;inclusive-overlap-do-not-sum;" +
                    "cleanup-return-is-not-cleanup-proof;other-counters=unsupported;" +
                    "coverage=phase-and-existing-loop-only;unobserved-work=not-attributed;" +
                    "first-failure-time=observation-not-throw-instant;phases[$phases];leaves[$leaves]")
            }
            return diagnostic
        }
        companion object {
            fun create(budget: (Long) -> LongArray): Prefix? = try {
                Prefix(budget).also { it.start(Phase.ENTRY); it.finish(Phase.ENTRY, true) }
            } catch (_: Throwable) { null }
        }
    }
    inner class Bucket {
        private val calls = LongArray(Operation.entries.size)
        private val nanos = LongArray(Operation.entries.size)
        private var readBytes = 0L
        private var writtenBytes = 0L
        private var filesStarted = 0L
        private var filesCompleted = 0L
        private var supported = true
        private fun add(left: Long, right: Long): Long {
            if (right < 0 || left > Long.MAX_VALUE - right) { supported = false; return left }
            return left + right
        }
        fun started() { filesStarted = add(filesStarted, 1) }
        fun completed() { filesCompleted = add(filesCompleted, 1) }
        fun read(bytes: Long) { if (bytes > 0) readBytes = add(readBytes, bytes) }
        fun written(bytes: Long) { if (bytes > 0) writtenBytes = add(writtenBytes, bytes) }
        internal inline fun <T> measure(operation: Operation, action: () -> T): T {
            val before = try { System.nanoTime() } catch (_: Throwable) {
                supported = false
                return action()
            }
            try { return action() } finally {
                try {
                    val elapsed = System.nanoTime() - before
                    if (elapsed <= 0) supported = false
                    calls[operation.ordinal] = add(calls[operation.ordinal], 1)
                    nanos[operation.ordinal] = add(nanos[operation.ordinal], elapsed)
                } catch (_: Throwable) { supported = false }
            }
        }
        fun summary(): String = "observed=${filesStarted > 0},supported=$supported,files=$filesStarted/$filesCompleted,readBytes=$readBytes," +
            "writtenBytes=$writtenBytes," + Operation.entries.joinToString(",") { "${it.name}=${calls[it.ordinal]}/${nanos[it.ordinal]}ns" }
    }
    val copy = Bucket()
    val hash = Bucket()

}

private inline fun <T> measuredCopyOperation(
    statistics: RuntimeCopyStatistics.Bucket?,
    operation: RuntimeCopyStatistics.Operation,
    action: () -> T,
): T = if (statistics == null) action() else statistics.measure(operation, action)

/** Keep the existing read buffer bound and permit only one byte beyond the remaining allowance. */
internal fun boundedDescriptorReadRequest(maximumBytes: Int, consumed: Long, bufferBytes: Int): Long {
    require(maximumBytes >= 0 && consumed >= 0 && consumed <= maximumBytes.toLong() && bufferBytes > 0)
    return minOf(bufferBytes.toLong(), maximumBytes.toLong() - consumed + 1L)
}

/**
 * The small Linux descriptor/syscall surface used by the ACP filesystem and process boundaries.
 *
 * Java NIO does not expose descriptor-relative no-replace/exchange renames, nor a way to reopen an
 * already-authorized O_PATH descriptor for reading, or race-free pidfd signaling. Keeping this
 * boundary small makes unsupported hosts fail closed instead of silently falling back to pathname
 * I/O or numeric-PID signaling.
 */
internal object LinuxFilesystemSyscalls {
    private val libc: LibC by lazy { Native.load(Platform.C_LIBRARY_NAME, LibC::class.java) }
    // Register one call site against the existing proxy's library, never an identity/approval cache.
    private val ownedStatxDirectReady: Boolean by lazy {
        try {
            Native.register(LinuxOwnedStatxDirect::class.java, Native.getNativeLibrary(libc))
            true
        } catch (_: Throwable) {
            false // Keep the original proxy/backend/fallback behavior if optional registration is unavailable.
        }
    }
    private val ownedMountPollDirectReady: Boolean by lazy {
        try {
            Native.register(LinuxOwnedMountPollDirect::class.java, Native.getNativeLibrary(libc))
            true
        } catch (_: Throwable) {
            false // Optional dispatch optimization; preserve the original poll backend on failure.
        }
    }

    fun requireSupported(path: Path) {
        val operatingSystem = System.getProperty("os.name", "")
        val architecture = System.getProperty("os.arch", "")
        if (operatingSystem != "Linux" || architecture !in SUPPORTED_ARCHITECTURES) {
            throw IOException("Linux openat/renameat2 support is unavailable on this platform")
        }
        if (path.fileSystem != FileSystems.getDefault()) {
            throw IOException("Linux openat/renameat2 support requires the default filesystem provider")
        }
        if (!Files.isDirectory(PROCESS_FD_DIRECTORY) || !Files.isDirectory(PROCESS_FD_INFO_DIRECTORY)) {
            throw IOException("the /proc/self descriptor filesystem is unavailable")
        }
        try {
            // Empty path operands must produce ENOENT when renameat2 is present. Unlike a generated
            // probe name, an empty path can never resolve to or mutate a filesystem entry.
            renameAt2(
                AT_FDCWD,
                "",
                AT_FDCWD,
                "",
                RENAME_NOREPLACE,
            )
            throw IOException("renameat2 safety probe unexpectedly changed a filesystem entry")
        } catch (failure: LinuxSyscallException) {
            if (failure.errno != ENOENT) {
                throw IOException("Linux renameat2 is unavailable (errno=${failure.errno})", failure)
            }
        } catch (failure: UnsatisfiedLinkError) {
            throw IOException(
                "Linux renameat2 native linkage is unavailable: ${failure.message.orEmpty().take(1024)}",
                failure,
            )
        }
    }

    /** Requires race-free process signaling for ordered sandbox cleanup; there is no kill(2) fallback. */
    fun requirePidfdSupported() {
        try {
            openProcessHandle(ProcessHandle.current().pid()).use { handle ->
                require(handle.pid == ProcessHandle.current().pid())
                if (!signalProcess(handle, 0)) {
                    throw IOException("Linux pidfd process cleanup probe lost its live process")
                }
            }
        } catch (failure: UnsatisfiedLinkError) {
            throw IOException("Linux pidfd process cleanup is unavailable", failure)
        }
    }

    fun openProcessHandle(pid: Long): LinuxProcessDescriptor {
        require(pid in 1..Int.MAX_VALUE.toLong()) { "process id is invalid" }
        val fd = retryOnInterrupted("open sandbox process handle") {
            libc.pidfd_open(pid.toInt(), 0).toLong()
        }.toInt()
        if (fd < 0) throw syscallFailure("open sandbox process handle")
        return LinuxProcessDescriptor(fd, pid)
    }

    /** Gracefully signals the exact process pinned by [handle]. */
    fun terminateProcess(handle: LinuxProcessDescriptor): Boolean = signalProcess(handle, SIGTERM)

    /** Forcibly signals the exact process pinned by [handle]. */
    fun killProcess(handle: LinuxProcessDescriptor): Boolean = signalProcess(handle, SIGKILL)

    /** Tests the exact pidfd-pinned process without signaling a later process that reused its PID. */
    fun processExists(handle: LinuxProcessDescriptor): Boolean = signalProcess(handle, 0)

    /** Tests pidfd readiness without reaping or consulting a reusable numeric PID. */
    fun processExited(handle: LinuxProcessDescriptor): Boolean = handle.signalWhileOpen { descriptor ->
        val pollDescriptor = Memory(POLLFD_BYTES.toLong())
        pollDescriptor.setInt(0, descriptor)
        pollDescriptor.setShort(Int.SIZE_BYTES.toLong(), POLLIN.toShort())
        pollDescriptor.setShort((Int.SIZE_BYTES + Short.SIZE_BYTES).toLong(), 0)
        while (true) {
            val result = libc.poll(pollDescriptor, NativeLong(1), 0)
            if (result >= 0) {
                val events = pollDescriptor.getShort(
                    (Int.SIZE_BYTES + Short.SIZE_BYTES).toLong(),
                ).toInt() and 0xffff
                if (events and POLLNVAL != 0) {
                    throw IOException("Linux pidfd readiness probe observed an invalid descriptor")
                }
                return@signalWhileOpen result > 0 && events and (POLLIN or POLLHUP or POLLERR) != 0
            }
            if (Native.getLastError() != EINTR) throw syscallFailure("inspect sandbox process exit")
        }
        @Suppress("UNREACHABLE_CODE")
        false
    }

    /** Checks the original mountinfo handle's event epoch without rereading its metadata. */
    fun mountMetadataChanged(handle: LinuxDescriptor): Boolean = handle.whileOpen { descriptor ->
        val polled = Memory(POLLFD_BYTES.toLong())
        polled.setInt(0, descriptor)
        polled.setShort(Int.SIZE_BYTES.toLong(), (POLLPRI or POLLERR).toShort())
        polled.setShort((Int.SIZE_BYTES + Short.SIZE_BYTES).toLong(), 0)
        while (true) {
            val result = libc.poll(polled, NativeLong(1), 0)
            if (result >= 0) {
                val events = polled.getShort((Int.SIZE_BYTES + Short.SIZE_BYTES).toLong()).toInt() and 0xffff
                if (events and (POLLNVAL or POLLHUP) != 0) throw IOException("mountinfo event descriptor is invalid")
                return@whileOpen result > 0 && events and (POLLPRI or POLLERR) != 0
            }
            if (Native.getLastError() != EINTR) throw syscallFailure("inspect host mount metadata events")
        }
        @Suppress("UNREACHABLE_CODE")
        false
    }

    /** Owns only eight scratch bytes; the event descriptor remains borrowed from its scope. */
    class MountMetadataPollScratch(private val handle: LinuxDescriptor) : AutoCloseable {
        private var closed = false
        // Diagnostic-only token/scalars: never reuse prior query facts or change its outcome.
        private var failurePrimary: Throwable? = null
        private var failureResult = 0
        private var failureEvents = 0
        private var failureError = 0
        private var failureHasEvents = false
        private val descriptorCount = NativeLong(1)
        private val encodedPollfd = ByteArray(POLLFD_BYTES)
        private val pollfdFields = ByteBuffer.wrap(encodedPollfd).order(ByteOrder.nativeOrder())
        // Allocate this callback once, not at each protected checkpoint.
        private val pollAction: (Int) -> Long = { descriptor -> pollDescriptor(descriptor, null) }
        // Allocate native storage last: no subsequent callback/object initialization can fail.
        private val polled = Memory(POLLFD_BYTES.toLong())

        /** Production has no query argument and hardwires the native poll below. */
        @Synchronized
        fun poll(): Long {
            failurePrimary = null
            check(!closed) { "mount event poll scratch is closed" }
            return handle.whileOpen(pollAction)
        }

        // Private reflection seam mirrors the statx-query controls: never a production permit.
        @Synchronized
        private fun pollWith(query: (Memory) -> Int): Long {
            failurePrimary = null
            check(!closed) { "mount event poll scratch is closed" }
            return handle.whileOpen { descriptor -> pollDescriptor(descriptor, query) }
        }

        private fun pollDescriptor(descriptor: Int, query: ((Memory) -> Int)?): Long {
            // Reset the same complete pollfd once before the original EINTR loop, in one JNI write.
            pollfdFields.putInt(0, descriptor)
            pollfdFields.putShort(Int.SIZE_BYTES, (POLLPRI or POLLERR).toShort())
            pollfdFields.putShort(Int.SIZE_BYTES + Short.SIZE_BYTES, 0)
            polled.write(0, encodedPollfd, 0, encodedPollfd.size)
            while (true) {
                val result = if (query == null) {
                    val backend = libc // Preserve original libc loading failure before optional registration.
                    if (ownedMountPollDirectReady) LinuxOwnedMountPollDirect.poll(polled, descriptorCount, 0)
                    else backend.poll(polled, descriptorCount, 0)
                } else query(polled)
                // Capture errno before any other native memory/cleanup operation can alter it.
                val error = if (result < 0) Native.getLastError() else 0
                if (result >= 0) {
                    val events = polled.getShort((Int.SIZE_BYTES + Short.SIZE_BYTES).toLong()).toInt() and 0xffff
                    if (events and (POLLNVAL or POLLHUP) != 0) {
                        failureResult = result
                        failureEvents = events
                        failureHasEvents = true
                        val failure = IOException("mountinfo event descriptor is invalid")
                        failurePrimary = failure
                        throw failure
                    }
                    return (result.toLong() shl 32) or events.toLong()
                }
                if (error != EINTR) {
                    failureResult = result
                    failureError = error
                    failureHasEvents = false
                    val failure = LinuxSyscallException("inspect host mount metadata events", error)
                    failurePrimary = failure
                    throw failure
                }
            }
        }

        /**
         * Same owner's immediate catch consumes only our exact newly constructed failure once.
         * Constructor -> throw -> Boundary catch adds no suppression entries. Foreign/query/closed
         * failures have no token. No lock, exception-graph access, native read or errno lookup.
         */
        fun claimFailureObservation(failure: Throwable): FailureObservation? {
            if (failurePrimary !== failure) return null
            failurePrimary = null
            return FailureObservation(failureResult, if (failureHasEvents) failureEvents else null,
                if (failureHasEvents) null else failureError)
        }

        class FailureObservation(val result: Int, val events: Int?, val error: Int?)

        @Synchronized
        override fun close() {
            if (closed) return
            closed = true
            failurePrimary = null
            polled.close()
        }
    }

    fun mountMetadataPollChanged(observation: Long): Boolean =
        observation ushr 32 > 0 && observation.toInt() and (POLLPRI or POLLERR) != 0

    /** Signals the pinned process, never a later process reusing its numeric PID. */
    private fun signalProcess(handle: LinuxProcessDescriptor, signal: Int): Boolean =
        handle.signalWhileOpen { descriptor ->
            var result: Boolean? = null
            while (result == null) {
                if (libc.pidfd_send_signal(descriptor, signal, null, 0) == 0) {
                    result = true
                    continue
                }
                when (val error = Native.getLastError()) {
                    EINTR -> continue
                    ESRCH -> result = false
                    else -> throw LinuxSyscallException("kill pinned sandbox boundary process", error)
                }
            }
            result
        }

    fun openRoot(path: Path): LinuxDescriptor = openDescriptor(
        AT_FDCWD,
        path.toString(),
        O_RDONLY or O_DIRECTORY or O_NOFOLLOW or O_CLOEXEC,
        0,
        "open workspace root",
    )

    /** Null means unsupported ABI/kernel only; pathname and permission failures never select fallback. */
    internal fun openConstrainedPathAt(parent: LinuxDescriptor, relative: String): LinuxDescriptor? {
        if (!supportsConstrainedPathAbi(System.getProperty("os.name", ""),
                System.getProperty("os.arch", ""), Native.POINTER_SIZE, NativeLong.SIZE)) return null
        if (relative.isEmpty() || relative.startsWith('/') ||
            relative.split('/').any { it.isEmpty() || it == "." || it == ".." }) {
            throw IOException("constrained root lookup requires a canonical relative path")
        }
        return parent.whileOpen { parentFd ->
            Memory(24).use { how ->
                how.clear()
                how.setLong(0, (O_PATH or O_NOFOLLOW or O_CLOEXEC).toLong())
                how.setLong(8, 0L)
                how.setLong(16, 0x0eL) // BENEATH | NO_SYMLINKS | NO_MAGICLINKS
                val raw = boundedConstrainedPathAttempt {
                    val result = libc.syscall(NativeLong(437), NativeLong(parentFd.toLong()), relative,
                        how, NativeLong(24)).toLong()
                    // No native operation may intervene before errno capture.
                    result to if (result < 0) Native.getLastError() else 0
                } ?: return@use null
                if (raw > Int.MAX_VALUE) throw IOException("openat2 returned an invalid descriptor")
                val fd = raw.toInt()
                // Own the returned FD before identity inspection or any other throwing operation.
                try {
                    LinuxDescriptor(fd, identity(fd))
                } catch (failure: Throwable) {
                    close(fd)
                    throw failure
                }
            }
        }
    }

    internal fun supportsConstrainedPathAbi(os: String, architecture: String, pointerBytes: Int,
        nativeLongBytes: Int): Boolean = os == "Linux" && architecture in SUPPORTED_ARCHITECTURES &&
        pointerBytes == 8 && nativeLongBytes == 8

    /** Fixed shared retry budget; enclosing scope retains its existing callback/checkpoint positions. */
    internal fun boundedConstrainedPathAttempt(attempt: () -> Pair<Long, Int>): Long? {
        repeat(8) {
            val (result, error) = attempt()
            if (result >= 0) return result
            when (error) {
                ENOSYS -> return null
                EINTR, EWOULDBLOCK -> Unit // EAGAIN is the same Linux errno as EWOULDBLOCK.
                else -> throw LinuxSyscallException("authenticate runtime root with openat2", error)
            }
        }
        throw IOException("constrained runtime root lookup exhausted its retry budget")
    }

    /** Reads hard filesystem byte/inode capacities through an already-pinned directory. */
    fun filesystemCapacity(directory: LinuxDescriptor): LinuxFilesystemCapacity =
        directory.whileOpen { descriptor ->
            val before = identity(descriptor)
            if (!before.isDirectory || before.isSymbolicLink) {
                throw IOException("filesystem capacity requires an authenticated directory")
            }
            val statistics = LinuxStatVfs()
            call("inspect filesystem capacity") { libc.fstatvfs(descriptor, statistics) }
            statistics.read()
            val fragmentBytes = statistics.fragmentBytes.toLong()
            val blocks = statistics.blocks.toLong()
            val availableBlocks = statistics.availableBlocks.toLong()
            val totalInodes = statistics.totalInodes.toLong()
            val availableInodes = statistics.availableInodes.toLong()
            val maximumNameBytes = statistics.maximumNameBytes.toLong()
            if (
                fragmentBytes <= 0L || blocks <= 0L || availableBlocks !in 0L..blocks ||
                totalInodes <= 0L || availableInodes !in 0L..totalInodes ||
                maximumNameBytes <= 0L
            ) throw IOException("filesystem returned unusable capacity counters")
            val totalBytes = multiplyCapacity(fragmentBytes, blocks, "filesystem byte capacity")
            val availableBytes = multiplyCapacity(
                fragmentBytes,
                availableBlocks,
                "filesystem available-byte capacity",
            )
            val after = identity(descriptor)
            if (before.key != after.key || before.mountId != after.mountId || !after.isDirectory) {
                throw IOException("filesystem directory identity changed while capacity was inspected")
            }
            LinuxFilesystemCapacity(
                fragmentBytes = fragmentBytes,
                totalBytes = totalBytes,
                availableBytes = availableBytes,
                totalInodes = totalInodes,
                availableInodes = availableInodes,
                maximumNameBytes = maximumNameBytes,
                readOnly = statistics.flags.toLong() and STATVFS_READ_ONLY != 0L,
            )
        }

    fun openDirectoryAt(parentFd: Int, name: String): LinuxDescriptor = openDescriptor(
        parentFd,
        name,
        O_RDONLY or O_DIRECTORY or O_NOFOLLOW or O_CLOEXEC,
        0,
        "open workspace directory",
    )

    fun openDirectoryAt(parentFd: Int, name: ByteArray): LinuxDescriptor = openDescriptor(
        parentFd,
        name,
        O_RDONLY or O_DIRECTORY or O_NOFOLLOW or O_CLOEXEC,
        0,
        "open workspace directory",
    )

    fun openAbsolutePathOrNull(path: Path): LinuxDescriptor? = try {
        openDescriptor(
            AT_FDCWD,
            path.toString(),
            O_PATH or O_NOFOLLOW or O_CLOEXEC,
            0,
            "inspect absolute filesystem entry",
        )
    } catch (failure: LinuxSyscallException) {
        if (failure.errno == ENOENT) null else throw failure
    }

    /** Follows only the kernel-owned `/proc/<pid>/exe` magic link for process attestation. */
    fun openProcessExecutable(pid: Long): LinuxDescriptor {
        require(pid in 1..Int.MAX_VALUE.toLong()) { "process id is invalid" }
        return openDescriptor(
            AT_FDCWD,
            "/proc/$pid/exe",
            O_PATH or O_CLOEXEC,
            0,
            "inspect sandbox process executable",
        )
    }

    fun openPathAtOrNull(parentFd: Int, name: String): LinuxDescriptor? = try {
        openDescriptor(
            parentFd,
            name,
            O_PATH or O_NOFOLLOW or O_CLOEXEC,
            0,
            "inspect filesystem entry",
        )
    } catch (failure: LinuxSyscallException) {
        if (failure.errno == ENOENT) null else throw failure
    }

    fun openPathAtOrNull(parentFd: Int, name: ByteArray): LinuxDescriptor? = try {
        openDescriptor(
            parentFd,
            name,
            O_PATH or O_NOFOLLOW or O_CLOEXEC,
            0,
            "inspect filesystem entry",
        )
    } catch (failure: LinuxSyscallException) {
        if (failure.errno == ENOENT) null else throw failure
    }

    /** Opens one existing regular file below an already-pinned directory without following links. */
    fun openRegularFileAtOrNull(parentFd: Int, name: String): LinuxDescriptor? {
        requireDescriptorRelativeName(name)
        val opened = try {
            openDescriptor(
                parentFd,
                name,
                O_PATH or O_NOFOLLOW or O_CLOEXEC,
                0,
                "open descriptor-relative regular file",
            )
        } catch (failure: LinuxSyscallException) {
            if (failure.errno == ENOENT) return null
            throw failure
        }
        return authenticateNamedRegularFile(parentFd, name, opened, "descriptor-relative regular file")
    }

    /** Byte-preserving counterpart for Git paths that are not valid UTF-8. */
    fun openRegularFileAtOrNull(parentFd: Int, name: ByteArray): LinuxDescriptor? {
        requireDescriptorRelativeName(name)
        val opened = try {
            openDescriptor(
                parentFd,
                name,
                O_PATH or O_NOFOLLOW or O_CLOEXEC,
                0,
                "open descriptor-relative regular file",
            )
        } catch (failure: LinuxSyscallException) {
            if (failure.errno == ENOENT) return null
            throw failure
        }
        return authenticateNamedRegularFile(parentFd, name, opened, "descriptor-relative regular file")
    }

    /** Opens the regular file pinned by [authorized] rather than resolving its workspace pathname again. */
    fun openReadableFrom(authorized: LinuxDescriptor): LinuxDescriptor = reopenRegularFile(
        authorized,
        O_RDONLY or O_NONBLOCK or O_CLOEXEC,
        "open authorized filesystem entry for reading",
    )

    /** Reopens an owned authenticated regular file without changing its access timestamp. */
    fun openReadableWithoutAtimeFrom(authorized: LinuxDescriptor): LinuxDescriptor = reopenRegularFile(
        authorized,
        O_RDONLY or O_NONBLOCK or O_NOATIME or O_CLOEXEC,
        "open authorized filesystem entry for metadata-neutral reading",
    )

    /** Reopens an authenticated regular file for writes without resolving its mutable name again. */
    fun reopenWritable(authorized: LinuxDescriptor): LinuxDescriptor = reopenRegularFile(
        authorized,
        O_WRONLY or O_NONBLOCK or O_CLOEXEC,
        "open authorized filesystem entry for writing",
    )

    /** Reopens an authenticated regular file for read/write locking or state access. */
    fun reopenReadWrite(authorized: LinuxDescriptor): LinuxDescriptor = reopenRegularFile(
        authorized,
        O_RDWR or O_NONBLOCK or O_CLOEXEC,
        "open authorized filesystem entry for reading and writing",
    )

    /** Creates an unnamed inode, so every failure before [linkTemporaryAt] is residue-free. */
    fun createTemporaryAt(parentFd: Int): LinuxDescriptor = openDescriptor(
        parentFd,
        ".",
        O_WRONLY or O_TMPFILE or O_CLOEXEC,
        OWNER_READ_WRITE,
        "create secure unnamed temporary file",
    )

    /** Creates one named regular file below an already-pinned private directory. */
    fun createRegularFile(parentFd: Int, name: String, mode: Int): LinuxDescriptor {
        requireDescriptorRelativeName(name)
        val opened = openDescriptor(
            parentFd,
            name,
            O_WRONLY or O_CREAT or O_EXCL or O_NONBLOCK or O_NOFOLLOW or O_CLOEXEC,
            mode,
            "create secure private regular file",
        )
        return authenticateNamedRegularFile(parentFd, name, opened, "created private regular file")
    }

    fun linkTemporaryAt(temporary: LinuxDescriptor, parentFd: Int, name: String) {
        call("materialize secure temporary file") {
            libc.linkat(temporary.fd, "", parentFd, name, AT_EMPTY_PATH)
        }
    }

    fun reserveDescriptors(count: Int): LinuxDescriptorReserve {
        require(count > 0) { "descriptor reserve count must be positive" }
        val descriptors = ArrayDeque<LinuxDescriptor>(count)
        try {
            repeat(count) {
                descriptors.addLast(
                    openDescriptor(
                        AT_FDCWD,
                        NULL_DEVICE.toString(),
                        O_RDONLY or O_CLOEXEC,
                        0,
                        "reserve filesystem transaction descriptor",
                    ),
                )
            }
            return LinuxDescriptorReserve(descriptors)
        } catch (failure: Throwable) {
            descriptors.forEach { descriptor -> descriptor.close() }
            throw failure
        }
    }

    fun read(descriptor: LinuxDescriptor, maximumBytes: Int, cancellationCheck: () -> Unit): ByteArray {
        val output = ByteArrayOutputStream(minOf(maximumBytes, BUFFER_BYTES))
        val buffer = Memory(BUFFER_BYTES.toLong())
        var total = 0L
        while (true) {
            cancellationCheck()
            val count = retryOnInterrupted("read authorized filesystem entry") {
                libc.read(descriptor.fd, buffer, NativeLong(boundedDescriptorReadRequest(maximumBytes, total, BUFFER_BYTES))).toLong()
            }
            if (count == 0L) break
            if (count < 0L) throw syscallFailure("read authorized filesystem entry")
            total += count
            if (total > maximumBytes.toLong()) {
                throw LinuxResourceLimitException()
            }
            output.write(buffer.getByteArray(0, count.toInt()))
        }
        return output.toByteArray()
    }

    /** Reads at most [maximumBytes] from the start of an already-pinned regular file. */
    fun readPrefix(authorized: LinuxDescriptor, maximumBytes: Int): ByteArray {
        require(maximumBytes >= 0) { "prefix byte limit must not be negative" }
        if (maximumBytes == 0) return ByteArray(0)
        openReadableFrom(authorized).use { readable ->
            val buffer = Memory(maximumBytes.toLong())
            val count = retryOnInterrupted("read authenticated filesystem prefix") {
                libc.read(readable.fd, buffer, NativeLong(maximumBytes.toLong())).toLong()
            }
            if (count < 0L) throw syscallFailure("read authenticated filesystem prefix")
            return buffer.getByteArray(0, count.toInt())
        }
    }

    /** Copies bytes from the already-pinned regular-file descriptor into a private snapshot. */
    fun copyReadableTo(
        authorized: LinuxDescriptor,
        output: OutputStream,
        maximumBytes: Long,
        statistics: RuntimeCopyStatistics.Bucket? = null,
        cancellationCheck: () -> Unit = {},
    ): Long {
        require(maximumBytes >= 0) { "copy byte budget must not be negative" }
        statistics?.started()
        openReadableFrom(authorized).use { readable ->
            Memory(BUFFER_BYTES.toLong()).use { buffer ->
                var total = 0L
                var copyBuffer: ByteArray? = null
                while (true) {
                    measuredCopyOperation(statistics, RuntimeCopyStatistics.Operation.CHECK) { cancellationCheck() }
                    val count = measuredCopyOperation(statistics, RuntimeCopyStatistics.Operation.READ) {
                        retryOnInterrupted("copy authenticated runtime file") {
                            libc.read(readable.fd, buffer, NativeLong(BUFFER_BYTES.toLong())).toLong()
                        }
                    }
                    statistics?.read(count)
                    if (count == 0L) { statistics?.completed(); return total }
                    if (count < 0L) throw syscallFailure("copy authenticated runtime file")
                    total = Math.addExact(total, count)
                    if (total > maximumBytes) throw LinuxResourceLimitException()
                    measuredCopyOperation(statistics, RuntimeCopyStatistics.Operation.WRITE) {
                        val length = count.toInt()
                        val previous = copyBuffer
                        // Preserve small-file allocation size; a later larger short read grows once
                        // to the fixed read bound. No payload array is allocated for EOF/refusal.
                        val bytes = if (previous != null && previous.size >= length) previous
                            else ByteArray(if (previous == null) length else BUFFER_BYTES).also { copyBuffer = it }
                        buffer.read(0, bytes, 0, length)
                        output.write(bytes, 0, length)
                    }
                    statistics?.written(count)
                    measuredCopyOperation(statistics, RuntimeCopyStatistics.Operation.CHECK) { cancellationCheck() }
                }
            }
        }
    }

    /** Copies between two already-open file descriptions without resolving a destination path. */
    fun copyReadableTo(
        authorized: LinuxDescriptor,
        destination: LinuxDescriptor,
        maximumBytes: Long,
        statistics: RuntimeCopyStatistics.Bucket? = null,
        cancellationCheck: () -> Unit = {},
    ): Long {
        require(maximumBytes >= 0) { "copy byte budget must not be negative" }
        statistics?.started()
        openReadableFrom(authorized).use { readable ->
            Memory(BUFFER_BYTES.toLong()).use { buffer ->
                var total = 0L
                while (true) {
                    measuredCopyOperation(statistics, RuntimeCopyStatistics.Operation.CHECK) { cancellationCheck() }
                    val count = measuredCopyOperation(statistics, RuntimeCopyStatistics.Operation.READ) {
                        retryOnInterrupted("copy authenticated runtime file") {
                            libc.read(readable.fd, buffer, NativeLong(BUFFER_BYTES.toLong())).toLong()
                        }
                    }
                    statistics?.read(count)
                    if (count == 0L) {
                        measuredCopyOperation(statistics, RuntimeCopyStatistics.Operation.CHECK) { cancellationCheck() }
                        measuredCopyOperation(statistics, RuntimeCopyStatistics.Operation.FSYNC) {
                            call("synchronize private runtime file") { libc.fsync(destination.fd) }
                        }
                        measuredCopyOperation(statistics, RuntimeCopyStatistics.Operation.CHECK) { cancellationCheck() }
                        statistics?.completed()
                        return total
                    }
                    if (count < 0L) throw syscallFailure("copy authenticated runtime file")
                    total = Math.addExact(total, count)
                    if (total > maximumBytes) throw LinuxResourceLimitException()
                    var offset = 0L
                    while (offset < count) {
                        val written = measuredCopyOperation(statistics, RuntimeCopyStatistics.Operation.WRITE) {
                            retryOnInterrupted("write private runtime file") {
                                libc.write(
                                    destination.fd,
                                    buffer.share(offset),
                                    NativeLong(count - offset),
                                ).toLong()
                            }
                        }
                        if (written <= 0L) throw syscallFailure("write private runtime file")
                        statistics?.written(written)
                        offset += written
                        measuredCopyOperation(statistics, RuntimeCopyStatistics.Operation.CHECK) { cancellationCheck() }
                    }
                }
            }
        }
    }

    /** `/proc/self/fd` is used only while this process still owns [descriptor]. */
    fun descriptorPath(descriptor: LinuxDescriptor): Path = descriptorPath(descriptor.fd)

    /** Flushes an authenticated regular file or directory through its already-open descriptor. */
    fun synchronize(descriptor: LinuxDescriptor) {
        descriptor.whileOpen { fd ->
            val before = identity(fd)
            requireSynchronizableIdentity(descriptor.identity, before)
            call("synchronize authenticated filesystem entry") { libc.fsync(fd) }
            val after = identity(fd)
            if (!sameDescriptorObject(before, after)) {
                throw IOException("filesystem entry identity changed while it was synchronized")
            }
        }
    }

    /**
     * Attempts one nonblocking, open-file-description-scoped exclusive lock acquisition.
     *
     * Callers own retry timing and deadlines. This primitive never waits in the kernel for another
     * lock holder, and retries only an interrupted syscall.
     */
    fun tryExclusiveLock(descriptor: LinuxDescriptor): Boolean = descriptor.whileOpen { fd ->
        val before = identity(fd)
        requireLockableIdentity(descriptor.identity, before)
        var acquired: Boolean? = null
        while (acquired == null) {
            if (libc.flock(fd, LOCK_EX or LOCK_NB) == 0) {
                acquired = true
                continue
            }
            when (val error = Native.getLastError()) {
                EINTR -> continue
                EWOULDBLOCK -> acquired = false
                else -> throw LinuxSyscallException("acquire nonblocking exclusive filesystem lock", error)
            }
        }
        try {
            val after = identity(fd)
            if (!sameDescriptorObject(before, after)) {
                throw IOException("filesystem entry identity changed while acquiring its lock")
            }
            acquired
        } catch (failure: Throwable) {
            if (acquired == true) {
                try {
                    unlockDescriptor(fd)
                } catch (unlockFailure: Throwable) {
                    failure.addSuppressed(unlockFailure)
                }
            }
            throw failure
        }
    }

    /** Releases an exclusive lock held by this descriptor's open file description. */
    fun unlock(descriptor: LinuxDescriptor) {
        descriptor.whileOpen { fd ->
            val before = identity(fd)
            requireLockableIdentity(descriptor.identity, before)
            unlockDescriptor(fd)
            val after = identity(fd)
            if (!sameDescriptorObject(before, after)) {
                throw IOException("filesystem entry identity changed while releasing its lock")
            }
        }
    }

    fun write(descriptor: LinuxDescriptor, content: ByteArray, cancellationCheck: () -> Unit) {
        val buffer = Memory(maxOf(1, minOf(content.size, BUFFER_BYTES)).toLong())
        var offset = 0
        while (offset < content.size) {
            cancellationCheck()
            val amount = minOf(content.size - offset, BUFFER_BYTES)
            buffer.write(0, content, offset, amount)
            val written = retryOnInterrupted("write secure temporary file") {
                libc.write(descriptor.fd, buffer, NativeLong(amount.toLong())).toLong()
            }
            if (written <= 0L) throw syscallFailure("write secure temporary file")
            offset += written.toInt()
        }
        call("synchronize secure temporary file") { libc.fsync(descriptor.fd) }
    }

    fun chmod(descriptor: LinuxDescriptor, mode: Int) {
        call("set secure temporary file mode") { libc.fchmod(descriptor.fd, mode) }
    }

    /**
     * Changes the mode of the regular file or directory already pinned by an O_PATH [authorized]
     * descriptor. Linux rejects `fchmod(O_PATH)` with EBADF, so reopen the kernel-owned
     * `/proc/self/fd` magic link and authenticate that new file description before mutating it.
     * The mutable workspace pathname is never resolved again.
     */
    fun chmodPinned(authorized: LinuxDescriptor, mode: Int) {
        val before = identity(authorized.fd)
        if (
            before.key != authorized.identity.key ||
            before.mountId != authorized.identity.mountId ||
            before.isSymbolicLink ||
            (!before.isRegularFile && !before.isDirectory)
        ) {
            throw IOException("pinned filesystem entry identity changed before setting its mode")
        }
        val flags = O_RDONLY or O_CLOEXEC or if (before.isDirectory) O_DIRECTORY else O_NONBLOCK
        val reopened = openDescriptor(
            AT_FDCWD,
            descriptorPath(authorized.fd).toString(),
            flags,
            0,
            "reopen pinned filesystem entry for mode update",
        )
        reopened.use {
            val reopenedBefore = identity(reopened.fd)
            if (!samePinnedObject(before, reopenedBefore)) {
                throw IOException("pinned filesystem entry identity changed while reopening for mode update")
            }
            call("set pinned filesystem entry mode") { libc.fchmod(reopened.fd, mode) }
            val reopenedAfter = identity(reopened.fd)
            val authorizedAfter = identity(authorized.fd)
            if (
                !samePinnedObject(before, reopenedAfter) ||
                !samePinnedObject(reopenedAfter, authorizedAfter) ||
                reopenedAfter.mode.permissions != mode.permissions
            ) {
                throw IOException("pinned filesystem entry identity changed while setting its mode")
            }
        }
    }

    fun extendedAttributeNames(
        descriptor: LinuxDescriptor,
        cancellationCheck: () -> Unit = {},
    ): List<String> {
        cancellationCheck()
        val path = descriptorPath(descriptor.fd).toString()
        val required = retryOnInterrupted("inspect filesystem metadata") {
            libc.listxattr(path, null, NativeLong(0)).toLong()
        }
        if (required < 0L) throw syscallFailure("inspect filesystem metadata")
        if (required == 0L) return emptyList()
        if (required > MAXIMUM_XATTR_NAME_BYTES) {
            throw IOException("filesystem metadata list exceeds the broker limit")
        }
        cancellationCheck()
        val names = Memory(required)
        val actual = retryOnInterrupted("inspect filesystem metadata") {
            libc.listxattr(path, names, NativeLong(required)).toLong()
        }
        if (actual < 0L) throw syscallFailure("inspect filesystem metadata")
        cancellationCheck()
        val result = names.getByteArray(0, actual.toInt())
            .split(0)
            .filter { it.isNotEmpty() }
            .map { bytes ->
                cancellationCheck()
                bytes.toByteArray().toString(Charsets.UTF_8)
            }
        if (result.size > MAXIMUM_XATTR_NAMES) {
            throw IOException("filesystem metadata contains too many extended attributes")
        }
        return result
    }

    fun extendedAttributeValue(
        descriptor: LinuxDescriptor,
        name: String,
        maximumBytes: Int = MAXIMUM_XATTR_VALUE_BYTES,
        cancellationCheck: () -> Unit = {},
    ): ByteArray {
        cancellationCheck()
        require(name.isNotEmpty() && '\u0000' !in name) { "extended attribute name is invalid" }
        require(maximumBytes > 0) { "extended attribute value limit must be positive" }
        val path = descriptorPath(descriptor.fd).toString()
        val required = retryOnInterrupted("inspect filesystem metadata value") {
            libc.getxattr(path, name, null, NativeLong(0)).toLong()
        }
        if (required < 0L) throw syscallFailure("inspect filesystem metadata value")
        if (required > maximumBytes.toLong()) {
            throw IOException("filesystem metadata value exceeds the broker limit")
        }
        if (required == 0L) return ByteArray(0)
        cancellationCheck()
        val value = Memory(required)
        val actual = retryOnInterrupted("inspect filesystem metadata value") {
            libc.getxattr(path, name, value, NativeLong(required)).toLong()
        }
        if (actual < 0L || actual != required) {
            throw IOException("filesystem metadata value changed while it was inspected")
        }
        cancellationCheck()
        return value.getByteArray(0, actual.toInt())
    }

    fun renameNoReplace(parentFd: Int, from: String, to: String) {
        renameAt2(parentFd, from, parentFd, to, RENAME_NOREPLACE)
    }

    fun renameNoReplace(fromParentFd: Int, from: String, toParentFd: Int, to: String) {
        renameAt2(fromParentFd, from, toParentFd, to, RENAME_NOREPLACE)
    }

    fun exchange(parentFd: Int, first: String, second: String) {
        renameAt2(parentFd, first, parentFd, second, RENAME_EXCHANGE)
    }

    fun unlinkIfPresent(parentFd: Int, name: String) {
        unlink(parentFd, name, missingIsSuccess = true)
    }

    fun unlink(parentFd: Int, name: String) {
        unlink(parentFd, name, missingIsSuccess = false)
    }

    fun removeDirectory(parentFd: Int, name: String) {
        while (true) {
            val result = libc.unlinkat(parentFd, name, AT_REMOVEDIR)
            if (result == 0) return
            val error = Native.getLastError()
            if (error != EINTR) throw LinuxSyscallException("remove secure private directory", error)
        }
    }

    /** Creates one exact private child without resolving the parent pathname again. */
    fun createDirectory(parentFd: Int, name: String, mode: Int) {
        require(name.isNotEmpty() && name != "." && name != ".." && '/' !in name && '\u0000' !in name) {
            "descriptor-relative directory name is invalid"
        }
        call("create secure private directory") { libc.mkdirat(parentFd, name, mode) }
    }

    /** Lists names through this JVM's already-open directory descriptor, never a host pathname. */
    fun directoryEntryNames(
        directory: LinuxDescriptor,
        maximumEntries: Int = MAXIMUM_PRIVATE_DIRECTORY_ENTRIES,
        cancellationCheck: () -> Unit = {},
    ): List<String> {
        require(maximumEntries > 0) { "directory entry limit must be positive" }
        return Files.newDirectoryStream(descriptorPath(directory.fd)).use { entries ->
            val names = ArrayList<String>(minOf(maximumEntries, 1024))
            for (entry in entries) {
                cancellationCheck()
                if (names.size >= maximumEntries) throw LinuxResourceLimitException()
                val name = entry.fileName.toString()
                if (name.isEmpty() || name == "." || name == ".." || '/' in name || '\u0000' in name) {
                    throw IOException("private directory contains an invalid entry name")
                }
                names += name
            }
            names
        }
    }

    private fun unlink(parentFd: Int, name: String, missingIsSuccess: Boolean) {
        while (true) {
            val result = libc.unlinkat(parentFd, name, 0)
            if (result == 0) return
            when (val error = Native.getLastError()) {
                EINTR -> continue
                ENOENT -> if (missingIsSuccess) return else throw LinuxSyscallException(
                    "remove secure temporary file",
                    error,
                )
                else -> throw LinuxSyscallException("remove secure temporary file", error)
            }
        }
    }

    fun identity(fd: Int): LinuxFileIdentity = descriptorStatxIdentity(fd) ?: descriptorProcIdentity(fd)

    /** Scope-owned query storage only; fd ownership and every fresh observation stay with the caller. */
    class StatxIdentityScratch : AutoCloseable {
        private var closed = false
        // Explicit NUL storage avoids per-call JNA NativeString allocation; allocate before native ownership.
        private val emptyPath = byteArrayOf(0)
        // Heap-only decoding storage is allocated before the existing single native owner.
        private val decodedStatistics = ByteArray(STATX_BYTES.toInt())
        private val decodedView = ByteBuffer.wrap(decodedStatistics).order(ByteOrder.nativeOrder())
        private val statistics = Memory(STATX_BYTES)

        @Synchronized
        fun identity(fd: Int): LinuxFileIdentity {
            check(!closed) { "descriptor identity scratch is closed" }
            return queryIdentity(fd, null, null)
        }

        // Script only through reflection in controls; production always uses libc and the proc fallback.
        @Synchronized
        private fun identityWith(fd: Int, query: (Memory) -> Long, fallback: () -> LinuxFileIdentity): LinuxFileIdentity {
            check(!closed) { "descriptor identity scratch is closed" }
            return queryIdentity(fd, query, fallback)
        }

        private fun queryIdentity(fd: Int, query: ((Memory) -> Long)?, fallback: (() -> LinuxFileIdentity)?): LinuxFileIdentity {
            val observed = descriptorStatxQueryOrNull {
                retryOnInterrupted("inspect pinned descriptor identity") {
                    statistics.clear() // Reset all 256 bytes even after an interrupted syscall.
                    emptyPath[0] = 0 // A fresh explicit empty pathname on every attempt; never NULL.
                    if (query == null) {
                        val proxy = libc // Preserve the original first library-load failure before optional registration.
                        if (ownedStatxDirectReady) LinuxOwnedStatxDirect.statx(fd, emptyPath,
                            AT_EMPTY_PATH or AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS or STATX_MNT_ID, statistics).toLong()
                        else proxy.statx(fd, emptyPath, AT_EMPTY_PATH or AT_SYMLINK_NOFOLLOW,
                            STATX_BASIC_STATS or STATX_MNT_ID, statistics).toLong()
                    } else query(statistics)
                }
            }
            return (if (observed == null) null else {
                statistics.read(0, decodedStatistics, 0, decodedStatistics.size)
                decodeDescriptorStatxIdentity(decodedView)
            }) ?: if (fallback == null) descriptorProcIdentity(fd) else fallback()
        }

        @Synchronized
        override fun close() {
            if (closed) return
            closed = true
            statistics.close()
        }
    }

    // Same field interpretation as the generic decoder, over the just-copied owned snapshot.
    private fun decodeDescriptorStatxIdentity(statistics: ByteBuffer): LinuxFileIdentity? {
        if (statistics.getInt(0) and STATX_IDENTITY_MASK != STATX_IDENTITY_MASK) return null
        val mountId = statistics.getLong(0x90)
        if (mountId <= 0) throw IOException("descriptor statx returned an invalid mount identity")
        val major = statistics.getInt(0x88).toLong() and 0xffffffffL
        val minor = statistics.getInt(0x8c).toLong() and 0xffffffffL
        // Linux dev_t encoding, including synthetic Btrfs subvolume st_dev identities.
        val device = ((major and 0xfffL) shl 8) or ((major and 0xfffff000L) shl 32) or
            (minor and 0xffL) or ((minor and 0xffffff00L) shl 12)
        val mode = statistics.getShort(0x1c).toInt() and 0xffff
        val type = mode and 0xf000
        return LinuxFileIdentity(
            LinuxFileKey(device, statistics.getLong(0x20)), mode,
            statistics.getInt(0x14), statistics.getInt(0x18), statistics.getInt(0x10), mountId,
            isRegularFile = type == 0x8000, isDirectory = type == 0x4000, isSymbolicLink = type == 0xa000,
        )
    }

    /** One descriptor-relative query preserves live checks without repeated stat/fdinfo reads. */
    private fun descriptorStatxIdentity(fd: Int): LinuxFileIdentity? = Memory(STATX_BYTES).use { statistics ->
        statistics.clear()
        descriptorStatxQueryOrNull {
            retryOnInterrupted("inspect pinned descriptor identity") {
                libc.statx(fd, "", AT_EMPTY_PATH or AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS or STATX_MNT_ID, statistics).toLong()
            }
        } ?: return@use null
        decodeDescriptorStatxIdentity(statistics)
    }

    private inline fun descriptorStatxQueryOrNull(query: () -> Long): Long? = try {
        query()
    } catch (_: UnsatisfiedLinkError) {
        // Older libc implementations may lack the statx entry point altogether.
        null
    } catch (failure: LinuxSyscallException) {
        // The interrupted-syscall helper throws for every other negative result.
        if (failure.errno == EPERM || failure.errno == ENOSYS || failure.errno == EOPNOTSUPP) null else throw failure
    }

    private fun decodeDescriptorStatxIdentity(statistics: Memory): LinuxFileIdentity? {
        if (statistics.getInt(0) and STATX_IDENTITY_MASK != STATX_IDENTITY_MASK) return null
        val mountId = statistics.getLong(0x90)
        if (mountId <= 0) throw IOException("descriptor statx returned an invalid mount identity")
        val major = statistics.getInt(0x88).toLong() and 0xffffffffL
        val minor = statistics.getInt(0x8c).toLong() and 0xffffffffL
        // Linux dev_t encoding, including synthetic Btrfs subvolume st_dev identities.
        val device = ((major and 0xfffL) shl 8) or ((major and 0xfffff000L) shl 32) or
            (minor and 0xffL) or ((minor and 0xffffff00L) shl 12)
        val mode = statistics.getShort(0x1c).toInt() and 0xffff
        val type = mode and 0xf000
        return LinuxFileIdentity(
            LinuxFileKey(device, statistics.getLong(0x20)), mode,
            statistics.getInt(0x14), statistics.getInt(0x18), statistics.getInt(0x10), mountId,
            isRegularFile = type == 0x8000, isDirectory = type == 0x4000, isSymbolicLink = type == 0xa000,
        )
    }

    /** Compatibility path for kernels/libc that cannot return all requested statx identity fields. */
    private fun descriptorProcIdentity(fd: Int): LinuxFileIdentity {
        val path = descriptorPath(fd)
        val basic = Files.readAttributes(path, BasicFileAttributes::class.java)
        val unix = Files.readAttributes(path, "unix:dev,ino,mode,uid,gid,nlink")
        return LinuxFileIdentity(
            key = LinuxFileKey(
                device = (unix.getValue("dev") as Number).toLong(),
                inode = (unix.getValue("ino") as Number).toLong(),
            ),
            mode = (unix.getValue("mode") as Number).toInt(),
            uid = (unix.getValue("uid") as Number).toInt(),
            gid = (unix.getValue("gid") as Number).toInt(),
            linkCount = (unix.getValue("nlink") as Number).toInt(),
            mountId = descriptorMountId(fd),
            isRegularFile = basic.isRegularFile,
            isDirectory = basic.isDirectory,
            isSymbolicLink = basic.isSymbolicLink,
        )
    }

    private fun openDescriptor(parentFd: Int, path: String, flags: Int, mode: Int, operation: String): LinuxDescriptor {
        val fd = retryOnInterrupted(operation) { libc.openat(parentFd, path, flags, mode).toLong() }.toInt()
        if (fd < 0) throw syscallFailure(operation)
        return try {
            LinuxDescriptor(fd, identity(fd))
        } catch (failure: Throwable) {
            close(fd)
            throw failure
        }
    }

    private fun openDescriptor(parentFd: Int, path: ByteArray, flags: Int, mode: Int, operation: String): LinuxDescriptor {
        requireDescriptorRelativeName(path)
        val nativePath = Memory(path.size.toLong() + 1)
        try {
            nativePath.write(0, path, 0, path.size)
            nativePath.setByte(path.size.toLong(), 0)
            val fd = retryOnInterrupted(operation) { libc.openat(parentFd, nativePath, flags, mode).toLong() }.toInt()
            if (fd < 0) throw syscallFailure(operation)
            return try {
                LinuxDescriptor(fd, identity(fd))
            } catch (failure: Throwable) {
                close(fd)
                throw failure
            }
        } finally {
            nativePath.close()
        }
    }

    /** Reopens only the kernel-pinned object, never the mutable name that originally selected it. */
    private fun reopenRegularFile(
        authorized: LinuxDescriptor,
        flags: Int,
        operation: String,
    ): LinuxDescriptor = authorized.whileOpen { authorizedFd ->
        val authorizedBefore = identity(authorizedFd)
        requireRegularIdentity(authorized.identity, authorizedBefore, operation)
        val reopened = openDescriptor(
            AT_FDCWD,
            descriptorPath(authorizedFd).toString(),
            flags,
            0,
            operation,
        )
        try {
            val reopenedIdentity = identity(reopened.fd)
            val authorizedAfter = identity(authorizedFd)
            requireRegularIdentity(authorizedBefore, reopenedIdentity, operation)
            if (!sameDescriptorObject(reopenedIdentity, authorizedAfter)) {
                throw IOException("authorized regular-file identity changed while it was reopened")
            }
            reopened
        } catch (failure: Throwable) {
            reopened.close()
            throw failure
        }
    }

    /** Authenticates that a named open still denotes the regular file returned to the caller. */
    private fun authenticateNamedRegularFile(
        parentFd: Int,
        name: String,
        opened: LinuxDescriptor,
        description: String,
    ): LinuxDescriptor = authenticateNamedRegularFile(opened, description) {
        openPathAtOrNull(parentFd, name)
    }

    private fun authenticateNamedRegularFile(
        parentFd: Int,
        name: ByteArray,
        opened: LinuxDescriptor,
        description: String,
    ): LinuxDescriptor = authenticateNamedRegularFile(opened, description) {
        openPathAtOrNull(parentFd, name)
    }

    private inline fun authenticateNamedRegularFile(
        opened: LinuxDescriptor,
        description: String,
        openNamed: () -> LinuxDescriptor?,
    ): LinuxDescriptor = try {
        val openedBefore = identity(opened.fd)
        requireRegularIdentity(opened.identity, openedBefore, "authenticate $description")
        val named = openNamed() ?: throw IOException("$description disappeared while it was authenticated")
        named.use {
            val namedIdentity = identity(named.fd)
            val openedAfter = identity(opened.fd)
            if (!namedIdentity.isRegularFile || namedIdentity.isDirectory || namedIdentity.isSymbolicLink) {
                throw IOException("authenticate $description requires an authenticated regular file")
            }
            if (!sameDescriptorObject(openedBefore, namedIdentity)) {
                throw LinuxNamedRegularFileReplacedException()
            }
            if (!sameDescriptorObject(namedIdentity, openedAfter)) {
                throw LinuxNamedRegularFileReplacedException()
            }
        }
        opened
    } catch (failure: Throwable) {
        opened.close()
        throw failure
    }

    private fun requireDescriptorRelativeName(name: String) {
        require(name.isNotEmpty() && name != "." && name != ".." && '/' !in name && '\u0000' !in name) {
            "descriptor-relative regular-file name is invalid"
        }
    }

    private fun requireDescriptorRelativeName(name: ByteArray) {
        require(name.isNotEmpty() && name.none { it == 0.toByte() } && name.none { it == '/'.code.toByte() } &&
            !name.contentEquals(byteArrayOf('.'.code.toByte())) &&
            !name.contentEquals(byteArrayOf('.'.code.toByte(), '.'.code.toByte()))) {
            "descriptor-relative regular-file name is invalid"
        }
    }

    private fun requireRegularIdentity(
        expected: LinuxFileIdentity,
        actual: LinuxFileIdentity,
        operation: String,
    ) {
        if (
            !sameDescriptorObject(expected, actual) ||
            !actual.isRegularFile ||
            actual.isDirectory ||
            actual.isSymbolicLink
        ) {
            throw IOException("$operation requires an authenticated regular file")
        }
    }

    private fun requireSynchronizableIdentity(expected: LinuxFileIdentity, actual: LinuxFileIdentity) {
        if (
            !sameDescriptorObject(expected, actual) ||
            actual.isSymbolicLink ||
            (!actual.isRegularFile && !actual.isDirectory)
        ) {
            throw IOException("synchronization requires an authenticated regular file or directory")
        }
    }

    private fun requireLockableIdentity(expected: LinuxFileIdentity, actual: LinuxFileIdentity) {
        if (
            !sameDescriptorObject(expected, actual) ||
            actual.isSymbolicLink ||
            (!actual.isRegularFile && !actual.isDirectory)
        ) {
            throw IOException("filesystem locking requires an authenticated regular file or directory")
        }
    }

    private fun unlockDescriptor(fd: Int) {
        call("release exclusive filesystem lock") { libc.flock(fd, LOCK_UN) }
    }

    private fun renameAt2(oldParentFd: Int, oldName: String, newParentFd: Int, newName: String, flags: Int) {
        call("install secure temporary file") {
            libc.renameat2(oldParentFd, oldName, newParentFd, newName, flags)
        }
    }

    private inline fun call(operation: String, invocation: () -> Int) {
        while (true) {
            val result = invocation()
            if (result == 0) return
            val error = Native.getLastError()
            if (error != EINTR) throw LinuxSyscallException(operation, error)
        }
    }

    private inline fun retryOnInterrupted(operation: String, invocation: () -> Long): Long {
        while (true) {
            val result = invocation()
            if (result >= 0L) return result
            val error = Native.getLastError()
            if (error != EINTR) throw LinuxSyscallException(operation, error)
        }
    }

    private fun syscallFailure(operation: String): LinuxSyscallException =
        LinuxSyscallException(operation, Native.getLastError())

    private fun multiplyCapacity(left: Long, right: Long, label: String): Long = try {
        Math.multiplyExact(left, right)
    } catch (failure: ArithmeticException) {
        throw IOException("$label exceeds the supported signed range", failure)
    }

    private fun samePinnedObject(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
        first.key == second.key &&
            first.mountId == second.mountId &&
            first.uid == second.uid &&
            first.gid == second.gid &&
            first.linkCount == second.linkCount &&
            first.isRegularFile == second.isRegularFile &&
            first.isDirectory == second.isDirectory &&
            first.isSymbolicLink == second.isSymbolicLink

    private fun sameDescriptorObject(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
        first.key == second.key &&
            first.mountId == second.mountId &&
            first.isRegularFile == second.isRegularFile &&
            first.isDirectory == second.isDirectory &&
            first.isSymbolicLink == second.isSymbolicLink

    private fun close(fd: Int) {
        while (libc.close(fd) != 0 && Native.getLastError() == EINTR) {
            // POSIX leaves close-after-EINTR semantics implementation-specific. Linux closes the descriptor.
            return
        }
    }

    private fun descriptorPath(fd: Int): Path = PROCESS_FD_DIRECTORY.resolve(fd.toString())

    /** A cross-process magic-link to the exact open file description retained by this JVM. */
    fun stableDescriptorPath(fd: Int): Path = Path.of(
        "/proc",
        ProcessHandle.current().pid().toString(),
        "fd",
        fd.toString(),
    )

    private fun descriptorMountId(fd: Int): Long {
        val prefix = "mnt_id:\t"
        val line = Files.readAllLines(PROCESS_FD_INFO_DIRECTORY.resolve(fd.toString()))
            .firstOrNull { it.startsWith(prefix) }
            ?: throw IOException("descriptor mount identity is unavailable")
        return line.removePrefix(prefix).trim().toLongOrNull()
            ?: throw IOException("descriptor mount identity is invalid")
    }

    private interface LibC : Library {
        fun syscall(number: NativeLong, directoryFd: NativeLong, path: String, how: Pointer, size: NativeLong): NativeLong
        fun openat(directoryFd: Int, path: String, flags: Int, mode: Int): Int
        fun openat(directoryFd: Int, path: Pointer, flags: Int, mode: Int): Int
        fun close(fd: Int): Int
        fun read(fd: Int, buffer: Pointer, count: NativeLong): NativeLong
        fun write(fd: Int, buffer: Pointer, count: NativeLong): NativeLong
        fun fsync(fd: Int): Int
        fun flock(fd: Int, operation: Int): Int
        fun fchmod(fd: Int, mode: Int): Int
        fun linkat(oldDirectoryFd: Int, oldPath: String, newDirectoryFd: Int, newPath: String, flags: Int): Int
        fun renameat2(oldDirectoryFd: Int, oldPath: String, newDirectoryFd: Int, newPath: String, flags: Int): Int
        fun unlinkat(directoryFd: Int, path: String, flags: Int): Int
        fun mkdirat(directoryFd: Int, path: String, mode: Int): Int
        fun pidfd_open(pid: Int, flags: Int): Int
        fun pidfd_send_signal(pidfd: Int, signal: Int, info: Pointer?, flags: Int): Int
        fun poll(descriptors: Pointer, count: NativeLong, timeoutMilliseconds: Int): Int
        fun listxattr(path: String, list: Pointer?, size: NativeLong): NativeLong
        fun getxattr(path: String, name: String, value: Pointer?, size: NativeLong): NativeLong
        fun fstatvfs(fd: Int, statistics: LinuxStatVfs): Int
        fun statx(fd: Int, path: String, flags: Int, mask: Int, statistics: Pointer): Int
        fun statx(fd: Int, path: ByteArray, flags: Int, mask: Int, statistics: Pointer): Int
    }

    /** Linux/glibc 64-bit `struct statvfs`; older spare[6] layouts have the same size/alignment. */
    @Structure.FieldOrder(
        "blockBytes",
        "fragmentBytes",
        "blocks",
        "freeBlocks",
        "availableBlocks",
        "totalInodes",
        "freeInodes",
        "availableInodes",
        "filesystemId",
        "flags",
        "maximumNameBytes",
        "filesystemType",
        "spare",
    )
    class LinuxStatVfs : Structure() {
        @JvmField var blockBytes: NativeLong = NativeLong(0)
        @JvmField var fragmentBytes: NativeLong = NativeLong(0)
        @JvmField var blocks: NativeLong = NativeLong(0)
        @JvmField var freeBlocks: NativeLong = NativeLong(0)
        @JvmField var availableBlocks: NativeLong = NativeLong(0)
        @JvmField var totalInodes: NativeLong = NativeLong(0)
        @JvmField var freeInodes: NativeLong = NativeLong(0)
        @JvmField var availableInodes: NativeLong = NativeLong(0)
        @JvmField var filesystemId: NativeLong = NativeLong(0)
        @JvmField var flags: NativeLong = NativeLong(0)
        @JvmField var maximumNameBytes: NativeLong = NativeLong(0)
        @JvmField var filesystemType: Int = 0
        @JvmField var spare: IntArray = IntArray(5)
    }

    private const val AT_FDCWD = -100
    private const val O_RDONLY = 0
    private const val O_WRONLY = 1
    private const val O_RDWR = 2
    private const val O_CREAT = 0x40
    private const val O_EXCL = 0x80
    private const val O_NONBLOCK = 0x800
    private const val O_NOATIME = 0x40000
    private const val O_DIRECTORY = 0x10000
    private const val O_NOFOLLOW = 0x20000
    private const val O_CLOEXEC = 0x80000
    private const val O_PATH = 0x200000
    private const val O_TMPFILE = 0x410000
    private const val OWNER_READ_WRITE = 0x180 // 0600
    private const val AT_EMPTY_PATH = 0x1000
    private const val AT_SYMLINK_NOFOLLOW = 0x100
    private const val STATX_BYTES = 256L
    private const val STATX_BASIC_STATS = 0x7ff
    private const val STATX_MNT_ID = 0x1000
    private const val STATX_IDENTITY_MASK = 0x111f // TYPE | MODE | NLINK | UID | GID | INO | MNT_ID
    private const val AT_REMOVEDIR = 0x200
    private const val RENAME_NOREPLACE = 1
    private const val RENAME_EXCHANGE = 2
    private const val EINTR = 4
    private const val EPERM = 1
    private const val ENOSYS = 38
    private const val EOPNOTSUPP = 95
    private const val EWOULDBLOCK = 11
    private const val LOCK_EX = 2
    private const val LOCK_NB = 4
    private const val LOCK_UN = 8
    internal const val ESRCH = 3
    private const val SIGTERM = 15
    private const val SIGKILL = 9
    private const val POLLIN = 0x001
    private const val POLLPRI = 0x002
    private const val POLLERR = 0x008
    private const val POLLHUP = 0x010
    private const val POLLNVAL = 0x020
    private const val POLLFD_BYTES = 8
    private const val STATVFS_READ_ONLY = 1L
    internal const val ENOENT = 2
    internal const val EEXIST = 17
    internal const val ENOTDIR = 20
    internal const val ENOSPC = 28
    internal const val ELOOP = 40
    private const val BUFFER_BYTES = 16 * 1024
    private const val MAXIMUM_XATTR_NAME_BYTES = 1024L * 1024L
    private const val MAXIMUM_XATTR_NAMES = 1024
    private const val MAXIMUM_XATTR_VALUE_BYTES = 1024 * 1024
    private const val MAXIMUM_PRIVATE_DIRECTORY_ENTRIES = 100_000
    private val PROCESS_FD_DIRECTORY = Path.of("/proc/self/fd")
    private val PROCESS_FD_INFO_DIRECTORY = Path.of("/proc/self/fdinfo")
    private val NULL_DEVICE = Path.of("/dev/null")
    private val SUPPORTED_ARCHITECTURES = setOf("amd64", "x86_64", "aarch64")
}

internal data class LinuxFileKey(val device: Long, val inode: Long)

internal data class LinuxFilesystemCapacity(
    val fragmentBytes: Long,
    val totalBytes: Long,
    val availableBytes: Long,
    val totalInodes: Long,
    val availableInodes: Long,
    val maximumNameBytes: Long,
    val readOnly: Boolean,
)

internal data class LinuxFileIdentity(
    val key: LinuxFileKey,
    val mode: Int,
    val uid: Int,
    val gid: Int,
    val linkCount: Int,
    val mountId: Long,
    val isRegularFile: Boolean,
    val isDirectory: Boolean,
    val isSymbolicLink: Boolean,
)

internal val Int.permissions: Int
    get() = this and 0xfff

internal class LinuxDescriptor(
    val fd: Int,
    val identity: LinuxFileIdentity,
) : AutoCloseable {
    private var ownsDescriptor = true

    /** Holds descriptor ownership across a syscall so close cannot expose a reused fd number. */
    @Synchronized
    internal fun <T> whileOpen(action: (Int) -> T): T {
        check(ownsDescriptor) { "Linux filesystem descriptor is closed" }
        return action(fd)
    }

    @Synchronized
    override fun close() {
        if (!ownsDescriptor) return
        ownsDescriptor = false
        // The descriptor boundary owns close; errors cannot make retrying close safe on Linux.
        try {
            NativeClose.close(fd)
        } catch (_: Throwable) {
            // close is terminal ownership release and must never turn a completed transaction into failure.
        }
    }
}

internal class LinuxProcessDescriptor internal constructor(
    private val fd: Int,
    val pid: Long,
) : AutoCloseable {
    private var ownsDescriptor = true

    /** Holds the ownership lock across the syscall so close cannot expose a reused fd number. */
    @Synchronized
    fun signalWhileOpen(signal: (Int) -> Boolean): Boolean {
        if (!ownsDescriptor) return false
        return signal(fd)
    }

    @Synchronized
    override fun close() {
        if (!ownsDescriptor) return
        ownsDescriptor = false
        try {
            NativeClose.close(fd)
        } catch (_: Throwable) {
            // Linux closes a descriptor even when close reports EINTR; retrying risks another fd.
        }
    }
}

internal class LinuxDescriptorReserve(
    private val descriptors: ArrayDeque<LinuxDescriptor>,
) : AutoCloseable {
    fun release(count: Int) {
        repeat(minOf(count, descriptors.size)) {
            descriptors.removeLast().close()
        }
    }

    override fun close() {
        while (descriptors.isNotEmpty()) {
            descriptors.removeLast().close()
        }
    }
}

/** Avoid exposing libc outside the syscall object while keeping [LinuxDescriptor] independently closeable. */
private object NativeClose {
    private interface LibC : Library {
        fun close(fd: Int): Int
    }

    private val libc: LibC by lazy { Native.load(Platform.C_LIBRARY_NAME, LibC::class.java) }

    fun close(fd: Int) {
        libc.close(fd)
    }
}

internal class LinuxSyscallException(
    operation: String,
    val errno: Int,
) : IOException("$operation failed with errno $errno")

internal class LinuxResourceLimitException : IOException("filesystem read exceeds configured size limit")

/** A regular name changed between two authenticated opens; callers may retry live observations. */
internal class LinuxNamedRegularFileReplacedException : IOException("named regular file changed during authentication")

private fun Map<String, Any>.getValue(name: String): Any =
    this[name] ?: throw IOException("filesystem provider did not expose unix:$name")

private fun ByteArray.split(delimiter: Byte): List<List<Byte>> {
    val result = mutableListOf<List<Byte>>()
    var start = 0
    for (index in indices) {
        if (this[index] == delimiter) {
            result += slice(start until index)
            start = index + 1
        }
    }
    if (start < size) result += slice(start until size)
    return result
}
