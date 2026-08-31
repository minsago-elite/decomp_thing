package decompengine.acp

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Platform
import com.sun.jna.Pointer
import com.sun.jna.StringArray
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.FileSystems
import java.nio.file.Path
import java.time.Duration

/**
 * One bounded, non-interactive Linux control-plane command.
 *
 * This is an internal mechanism, not an execution or scoring authority. The command is created as
 * a fresh session leader by `posix_spawn(3)`, so timeout/error cleanup can address its process
 * group while the unreaped leader still reserves the numeric group id. This does not prove
 * whole-tree cleanup: a descendant can deliberately create another session/process group, and
 * only a separately verified cgroup boundary can close that gap. The executable itself must be
 * authenticated by the caller; this layer deliberately accepts no claimed digest.
 */
internal data class LinuxBoundedSessionCommand(
    val arguments: List<String>,
    val environment: Map<String, String>,
    val workingDirectory: Path = Path.of("/"),
    val timeout: Duration,
    val maximumStdoutBytes: Int,
    val maximumStderrBytes: Int,
) {
    init {
        require(arguments.isNotEmpty() && arguments.size <= MAXIMUM_ARGUMENTS) {
            "bounded session command must contain 1..$MAXIMUM_ARGUMENTS arguments"
        }
        require(arguments.all(::portableNativeString)) {
            "bounded session command contains an invalid native argument"
        }
        val executable = try {
            Path.of(arguments.first())
        } catch (failure: Exception) {
            throw IllegalArgumentException("bounded session executable path is invalid", failure)
        }
        require(
            executable.isAbsolute && executable.normalize() == executable && executable.fileName != null &&
                executable.toString() == arguments.first(),
        ) {
            "bounded session executable path must be exact, normalized, absolute, and name a file"
        }
        require(arguments.sumOf { it.toByteArray(StandardCharsets.UTF_8).size.toLong() } <= MAXIMUM_ARGUMENT_BYTES) {
            "bounded session command arguments exceed their byte limit"
        }
        require(environment.size <= MAXIMUM_ENVIRONMENT_BINDINGS) {
            "bounded session environment contains too many bindings"
        }
        require(environment.keys.all { it.matches(PORTABLE_ENVIRONMENT_NAME) }) {
            "bounded session environment contains an invalid name"
        }
        require(environment.entries.all { portableNativeString(it.value) }) {
            "bounded session environment contains an invalid value"
        }
        require(environment.entries.sumOf {
            it.key.toByteArray(StandardCharsets.UTF_8).size.toLong() +
                it.value.toByteArray(StandardCharsets.UTF_8).size.toLong() + 1L
        } <= MAXIMUM_ENVIRONMENT_BYTES) {
            "bounded session environment exceeds its byte limit"
        }
        require(workingDirectory == Path.of("/")) {
            "bounded session working directory must be the immutable filesystem root"
        }
        require(!timeout.isZero && !timeout.isNegative && timeout <= MAXIMUM_TIMEOUT) {
            "bounded session timeout exceeds its hard ceiling"
        }
        require(maximumStdoutBytes in 0..MAXIMUM_CAPTURE_BYTES) {
            "bounded session stdout limit exceeds its hard ceiling"
        }
        require(maximumStderrBytes in 0..MAXIMUM_CAPTURE_BYTES) {
            "bounded session stderr limit exceeds its hard ceiling"
        }
    }
}

internal data class LinuxBoundedSessionResult(
    val exitCode: Int?,
    val signal: Int?,
    val stdout: ByteArray,
    val stderr: ByteArray,
)

internal open class LinuxBoundedSessionException(message: String, cause: Throwable? = null) :
    IOException(message, cause)

internal class LinuxBoundedSessionTimeoutException(message: String) :
    LinuxBoundedSessionException(message)

internal class LinuxBoundedSessionOutputLimitException(message: String) :
    LinuxBoundedSessionException(message)

internal class LinuxBoundedSessionCleanupException(message: String, cause: Throwable? = null) :
    LinuxBoundedSessionException(message, cause)

internal object LinuxBoundedSessionProcess {
    fun execute(command: LinuxBoundedSessionCommand): LinuxBoundedSessionResult {
        requireSupported(command.workingDirectory)
        val native = NativeSessionCommand(command, NonAuthoritativeSessionTestHook.NONE)
        return native.execute()
    }

    /** Internal hostile-test seam. It cannot inject output, exit status, facts, or authority. */
    @JvmSynthetic
    internal fun executeForNonAuthoritativeTest(
        command: LinuxBoundedSessionCommand,
        hook: NonAuthoritativeSessionTestHook,
    ): LinuxBoundedSessionResult {
        requireSupported(command.workingDirectory)
        return NativeSessionCommand(command, hook).execute()
    }

    private fun requireSupported(path: Path) {
        if (System.getProperty("os.name", "") != "Linux" || path.fileSystem != FileSystems.getDefault()) {
            throw LinuxBoundedSessionException("bounded session execution requires the Linux default filesystem")
        }
        LinuxFilesystemSyscalls.requirePidfdSupported()
    }
}

internal data class NonAuthoritativeSessionTestHook(
    val forcePidfdOpenFailure: Boolean = false,
    val spawnedPidObserver: (Long) -> Unit = {},
) {
    companion object {
        val NONE = NonAuthoritativeSessionTestHook()
    }
}

private class NativeSessionCommand(
    private val command: LinuxBoundedSessionCommand,
    private val testHook: NonAuthoritativeSessionTestHook,
) {
    private val libc: SessionLibC = Native.load(Platform.C_LIBRARY_NAME, SessionLibC::class.java)
    private val attributes = Memory(OPAQUE_NATIVE_STORAGE_BYTES)
    private val fileActions = Memory(OPAQUE_NATIVE_STORAGE_BYTES)
    private var attributesInitialized = false
    private var fileActionsInitialized = false
    private var stdinFd = -1
    private var stdoutReadFd = -1
    private var stdoutWriteFd = -1
    private var stderrReadFd = -1
    private var stderrWriteFd = -1
    private val reservedStandardDescriptors = mutableListOf<Int>()
    private var pid = -1
    private var processHandle: LinuxProcessDescriptor? = null
    private var reaped = false

    fun execute(): LinuxBoundedSessionResult {
        var primary: Throwable? = null
        try {
            prepareNativeState()
            spawn()
            closeParentWriteEnds()
            makeParentReadEndsNonblocking()
            val captured = capture()
            // The exited, unreaped session leader still reserves its process-group id. SIGKILL is
            // therefore directed at that exact group before the numeric id can be reused.
            signalGroup(SIGKILL)
            val status = reapExitedLeader()
            return LinuxBoundedSessionResult(
                exitCode = if (waitExited(status)) waitExitStatus(status) else null,
                signal = if (waitSignaled(status)) waitTermSignal(status) else null,
                stdout = captured.first,
                stderr = captured.second,
            )
        } catch (failure: Throwable) {
            primary = failure
            if (pid > 0 && !reaped) {
                try {
                    killAndReapLeader()
                } catch (cleanupFailure: Throwable) {
                    val aggregate = LinuxBoundedSessionCleanupException(
                        "bounded session failed and its leader could not be killed and reaped",
                        cleanupFailure,
                    )
                    aggregate.addSuppressed(failure)
                    primary = aggregate
                }
            }
            throw primary
        } finally {
            closeFd(stdoutReadFd)
            stdoutReadFd = -1
            closeFd(stdoutWriteFd)
            stdoutWriteFd = -1
            closeFd(stderrReadFd)
            stderrReadFd = -1
            closeFd(stderrWriteFd)
            stderrWriteFd = -1
            closeFd(stdinFd)
            stdinFd = -1
            reservedStandardDescriptors.forEach(::closeFd)
            reservedStandardDescriptors.clear()
            processHandle?.close()
            processHandle = null
            if (fileActionsInitialized) libc.posix_spawn_file_actions_destroy(fileActions)
            if (attributesInitialized) libc.posix_spawnattr_destroy(attributes)
        }
    }

    private fun prepareNativeState() {
        nativeResult("initialize spawn attributes", libc.posix_spawnattr_init(attributes))
        attributesInitialized = true
        val defaults = Memory(SIGSET_BYTES)
        val mask = Memory(SIGSET_BYTES)
        syscallResult("initialize default signal set", libc.sigfillset(defaults))
        syscallResult("exclude SIGKILL from default signal set", libc.sigdelset(defaults, SIGKILL))
        syscallResult("exclude SIGSTOP from default signal set", libc.sigdelset(defaults, SIGSTOP))
        syscallResult("initialize empty signal mask", libc.sigemptyset(mask))
        nativeResult("configure default signals", libc.posix_spawnattr_setsigdefault(attributes, defaults))
        nativeResult("configure signal mask", libc.posix_spawnattr_setsigmask(attributes, mask))
        nativeResult(
            "configure bounded session",
            libc.posix_spawnattr_setflags(
                attributes,
                (POSIX_SPAWN_SETSID or POSIX_SPAWN_SETSIGDEF or POSIX_SPAWN_SETSIGMASK).toShort(),
            ),
        )

        nativeResult("initialize spawn file actions", libc.posix_spawn_file_actions_init(fileActions))
        fileActionsInitialized = true
        reservedStandardDescriptors += reserveClosedStandardDescriptors(
            descriptorIsOpen = ::descriptorIsOpen,
            openNullReadWrite = ::openNullReadWrite,
            closeDescriptor = ::closeFd,
        )
        stdinFd = openNullInput()
        val stdoutPipe = createPipe("stdout")
        stdoutReadFd = stdoutPipe.first
        stdoutWriteFd = stdoutPipe.second
        val stderrPipe = createPipe("stderr")
        stderrReadFd = stderrPipe.first
        stderrWriteFd = stderrPipe.second

        nativeResult("bind bounded session stdin", libc.posix_spawn_file_actions_adddup2(fileActions, stdinFd, 0))
        nativeResult(
            "bind bounded session stdout",
            libc.posix_spawn_file_actions_adddup2(fileActions, stdoutWriteFd, 1),
        )
        nativeResult(
            "bind bounded session stderr",
            libc.posix_spawn_file_actions_adddup2(fileActions, stderrWriteFd, 2),
        )
        listOf(stdinFd, stdoutReadFd, stdoutWriteFd, stderrReadFd, stderrWriteFd)
            .filter { it > 2 }
            .distinct()
            .forEach { descriptor ->
                nativeResult(
                    "close surplus bounded session descriptor",
                    libc.posix_spawn_file_actions_addclose(fileActions, descriptor),
                )
            }
        nativeResult(
            "close inherited bounded session descriptors",
            libc.posix_spawn_file_actions_addclosefrom_np(fileActions, 3),
        )
        nativeResult(
            "configure bounded session working directory",
            libc.posix_spawn_file_actions_addchdir_np(fileActions, command.workingDirectory.toString()),
        )
    }

    private fun spawn() {
        val pidStorage = Memory(Int.SIZE_BYTES.toLong())
        val arguments = StringArray(command.arguments.toTypedArray(), StandardCharsets.UTF_8.name())
        val environment = command.environment.entries
            .sortedBy { it.key }
            .map { (name, value) -> "$name=$value" }
        val environmentArray = StringArray(environment.toTypedArray(), StandardCharsets.UTF_8.name())
        val result = libc.posix_spawn(
            pidStorage,
            command.arguments.first(),
            fileActions,
            attributes,
            arguments,
            environmentArray,
        )
        nativeResult("start bounded session", result)
        pid = pidStorage.getInt(0)
        if (pid <= 0) throw LinuxBoundedSessionException("bounded session returned an invalid process id")
        testHook.spawnedPidObserver(pid.toLong())
        processHandle = try {
            if (testHook.forcePidfdOpenFailure) {
                throw LinuxBoundedSessionException("forced non-authoritative pidfd-open test failure")
            }
            LinuxFilesystemSyscalls.openProcessHandle(pid.toLong())
        } catch (failure: Throwable) {
            // The outer failure path owns signaling and waitpid reaping even without a pidfd.
            throw LinuxBoundedSessionException("bounded session leader could not be pidfd-pinned", failure)
        }
    }

    private fun capture(): Pair<ByteArray, ByteArray> {
        val stdout = BoundedNativeCapture("stdout", command.maximumStdoutBytes)
        val stderr = BoundedNativeCapture("stderr", command.maximumStderrBytes)
        val deadline = addDeadline(System.nanoTime(), command.timeout.toNanos())
        var leaderExited = false
        var postExitDeadline: Long? = null
        while (true) {
            stdout.drain(libc, stdoutReadFd).also { if (it) stdoutReadFd = -1 }
            stderr.drain(libc, stderrReadFd).also { if (it) stderrReadFd = -1 }
            leaderExited = leaderExited || requireNotNull(processHandle).let(
                LinuxFilesystemSyscalls::processExited,
            )
            if (leaderExited) {
                if (postExitDeadline == null) {
                    // No successful command is allowed to leave a same-session writer behind.
                    // The zombie leader still reserves the exact process-group number here.
                    signalGroup(SIGKILL)
                    postExitDeadline = addDeadline(System.nanoTime(), CLEANUP_TIMEOUT.toNanos())
                }
                if (stdoutReadFd < 0 && stderrReadFd < 0) {
                    return stdout.bytes() to stderr.bytes()
                }
            }
            val now = System.nanoTime()
            if (!leaderExited && now >= deadline) {
                throw LinuxBoundedSessionTimeoutException(
                    "bounded session exceeded ${command.timeout.toMillis()} ms",
                )
            }
            if (leaderExited && now >= requireNotNull(postExitDeadline)) {
                throw LinuxBoundedSessionCleanupException(
                    "bounded session pipes remained open after its leader exited",
                )
            }
            val pollMillis = if (leaderExited) {
                POST_EXIT_PIPE_POLL_MILLIS
            } else {
                minOf(
                    ACTIVE_POLL_MILLIS.toLong(),
                    maxOf(0L, (deadline - now + 999_999L) / 1_000_000L),
                ).toInt()
            }
            pollReadable(stdoutReadFd, stderrReadFd, pollMillis)
        }
    }

    private fun pollReadable(stdoutFd: Int, stderrFd: Int, timeoutMillis: Int) {
        val descriptors = listOf(stdoutFd, stderrFd).filter { it >= 0 }
        if (descriptors.isEmpty()) {
            if (timeoutMillis > 0) Thread.sleep(timeoutMillis.toLong())
            return
        }
        val poll = Memory((descriptors.size * POLLFD_BYTES).toLong())
        descriptors.forEachIndexed { index, descriptor ->
            val offset = (index * POLLFD_BYTES).toLong()
            poll.setInt(offset, descriptor)
            poll.setShort(offset + Int.SIZE_BYTES, POLLIN.toShort())
            poll.setShort(offset + Int.SIZE_BYTES + Short.SIZE_BYTES, 0)
        }
        while (true) {
            val result = libc.poll(poll, NativeLong(descriptors.size.toLong()), timeoutMillis)
            if (result >= 0) {
                descriptors.indices.forEach { index ->
                    val revents = poll.getShort(
                        (index * POLLFD_BYTES + Int.SIZE_BYTES + Short.SIZE_BYTES).toLong(),
                    ).toInt() and 0xffff
                    if (revents and POLLNVAL != 0) {
                        throw LinuxBoundedSessionException("bounded session poll observed an invalid descriptor")
                    }
                }
                return
            }
            if (Native.getLastError() != EINTR) throw syscallFailure("poll bounded session")
        }
    }

    private fun killAndReapLeader() {
        val deadline = addDeadline(System.nanoTime(), CLEANUP_TIMEOUT.toNanos())
        var lastFailure: Throwable? = null
        closeParentWriteEnds()
        try {
            makeParentReadEndsNonblocking()
        } catch (failure: Throwable) {
            lastFailure = failure
            // A failed transition leaves the access mode unknown. Closing both read ends is the
            // only bounded choice; cleanup must never call read(2) on a possibly blocking pipe.
            closeFd(stdoutReadFd)
            stdoutReadFd = -1
            closeFd(stderrReadFd)
            stderrReadFd = -1
        }
        while (true) {
            try {
                // pid remains a reserved child identity until waitpid succeeds. Never use the
                // negative group id after reap, when it could have been assigned to another group.
                signalGroup(SIGKILL)
                processHandle?.let { LinuxFilesystemSyscalls.killProcess(it) }
                drainWithoutRetaining(stdoutReadFd)
                drainWithoutRetaining(stderrReadFd)
                val rootExited = processHandle?.let(LinuxFilesystemSyscalls::processExited)
                    ?: leaderExitedWithoutReaping()
                if (rootExited) {
                    reapExitedLeader()
                    return
                }
            } catch (failure: Throwable) {
                lastFailure = failure
            }
            if (System.nanoTime() >= deadline) {
                throw LinuxBoundedSessionCleanupException(
                    "bounded session leader did not exit after pre-reap SIGKILL",
                    lastFailure,
                )
            }
            Thread.sleep(CLEANUP_POLL_MILLIS)
        }
    }

    private fun signalGroup(signal: Int) {
        while (true) {
            if (libc.kill(-pid, signal) == 0) return
            when (val error = Native.getLastError()) {
                EINTR -> continue
                ESRCH -> return
                else -> throw LinuxSyscallException("signal bounded session process group", error)
            }
        }
    }

    private fun reapExitedLeader(): Int {
        val status = Memory(Int.SIZE_BYTES.toLong())
        val deadline = addDeadline(System.nanoTime(), CLEANUP_TIMEOUT.toNanos())
        while (true) {
            val result = libc.waitpid(pid, status, WNOHANG)
            when {
                result == pid -> {
                    reaped = true
                    return status.getInt(0)
                }
                result == 0 -> {
                    if (System.nanoTime() >= deadline) {
                        throw LinuxBoundedSessionCleanupException("bounded session leader was not reapable")
                    }
                    Thread.sleep(CLEANUP_POLL_MILLIS)
                }
                Native.getLastError() == EINTR -> continue
                else -> throw syscallFailure("reap bounded session leader")
            }
        }
    }

    /** waitpid(WNOHANG) would reap; `/proc` state keeps the child reserved for group signaling. */
    private fun leaderExitedWithoutReaping(): Boolean {
        val stat = try {
            java.nio.file.Files.readString(Path.of("/proc", pid.toString(), "stat"))
        } catch (failure: java.nio.file.NoSuchFileException) {
            return true
        } catch (failure: IOException) {
            throw LinuxBoundedSessionException("cannot inspect unpinned bounded session leader", failure)
        }
        if (stat.toByteArray(StandardCharsets.UTF_8).size > MAXIMUM_PROC_STAT_BYTES) {
            throw LinuxBoundedSessionException("unpinned bounded session leader stat exceeds its bound")
        }
        val commandEnd = stat.lastIndexOf(") ")
        if (commandEnd < 0 || commandEnd + 2 >= stat.length) {
            throw LinuxBoundedSessionException("unpinned bounded session leader stat is malformed")
        }
        return stat[commandEnd + 2] in setOf('Z', 'X', 'x')
    }

    private fun createPipe(label: String): Pair<Int, Int> {
        val descriptors = Memory((2 * Int.SIZE_BYTES).toLong())
        syscallResult("create bounded session $label pipe", libc.pipe2(descriptors, O_CLOEXEC))
        return descriptors.getInt(0) to descriptors.getInt(Int.SIZE_BYTES.toLong())
    }

    private fun openNullInput(): Int {
        while (true) {
            val result = libc.open(NULL_DEVICE, O_RDONLY or O_CLOEXEC)
            if (result >= 0) return result
            if (Native.getLastError() != EINTR) throw syscallFailure("open bounded session null input")
        }
    }

    private fun openNullReadWrite(): Int {
        while (true) {
            val result = libc.open(NULL_DEVICE, O_RDWR or O_CLOEXEC)
            if (result >= 0) return result
            if (Native.getLastError() != EINTR) throw syscallFailure("reserve bounded session standard descriptor")
        }
    }

    private fun descriptorIsOpen(descriptor: Int): Boolean {
        val result = libc.fcntl(descriptor, F_GETFD, 0)
        if (result >= 0) return true
        if (Native.getLastError() == EBADF) return false
        throw syscallFailure("inspect bounded session standard descriptor")
    }

    private fun makeParentReadEndsNonblocking() {
        listOf(stdoutReadFd, stderrReadFd).filter { it >= 0 }.forEach { descriptor ->
            val flags = libc.fcntl(descriptor, F_GETFL, 0)
            if (flags < 0) throw syscallFailure("inspect bounded session pipe flags")
            if (libc.fcntl(descriptor, F_SETFL, flags or O_NONBLOCK) < 0) {
                throw syscallFailure("set bounded session pipe nonblocking")
            }
        }
    }

    private fun closeParentWriteEnds() {
        closeFd(stdinFd)
        stdinFd = -1
        closeFd(stdoutWriteFd)
        stdoutWriteFd = -1
        closeFd(stderrWriteFd)
        stderrWriteFd = -1
    }

    private fun drainWithoutRetaining(descriptor: Int) {
        if (descriptor < 0) return
        val buffer = Memory(CAPTURE_CHUNK_BYTES.toLong())
        while (true) {
            val count = libc.read(descriptor, buffer, NativeLong(CAPTURE_CHUNK_BYTES.toLong())).toLong()
            when {
                count > 0L -> continue
                count == 0L -> return
                Native.getLastError() == EINTR -> continue
                Native.getLastError() in setOf(EAGAIN, EWOULDBLOCK) -> return
                else -> throw syscallFailure("drain bounded session pipe during cleanup")
            }
        }
    }

    private fun closeFd(descriptor: Int) {
        if (descriptor < 0) return
        // On Linux, close owns the descriptor even when interrupted; never retry a reused number.
        libc.close(descriptor)
    }

    private fun nativeResult(operation: String, result: Int) {
        if (result != 0) throw LinuxBoundedSessionException("$operation failed with errno $result")
    }

    private fun syscallResult(operation: String, result: Int) {
        if (result != 0) throw syscallFailure(operation)
    }

    private fun syscallFailure(operation: String): LinuxSyscallException =
        LinuxSyscallException(operation, Native.getLastError())
}

private class BoundedNativeCapture(
    private val label: String,
    private val maximumBytes: Int,
) {
    private val output = ByteArrayOutputStream(minOf(maximumBytes, CAPTURE_CHUNK_BYTES))
    private val buffer = Memory(CAPTURE_CHUNK_BYTES.toLong())

    /** Returns true after EOF and closes the caller's ownership logically. */
    fun drain(libc: SessionLibC, descriptor: Int): Boolean {
        if (descriptor < 0) return true
        while (true) {
            val count = libc.read(descriptor, buffer, NativeLong(CAPTURE_CHUNK_BYTES.toLong())).toLong()
            when {
                count > 0L -> {
                    if (count > maximumBytes.toLong() - output.size().toLong()) {
                        throw LinuxBoundedSessionOutputLimitException(
                            "bounded session $label exceeded $maximumBytes bytes",
                        )
                    }
                    output.write(buffer.getByteArray(0, count.toInt()))
                }
                count == 0L -> {
                    libc.close(descriptor)
                    return true
                }
                Native.getLastError() == EINTR -> continue
                Native.getLastError() in setOf(EAGAIN, EWOULDBLOCK) -> return false
                else -> throw LinuxSyscallException("read bounded session $label", Native.getLastError())
            }
        }
    }

    fun bytes(): ByteArray = output.toByteArray()
}

private interface SessionLibC : Library {
    fun open(path: String, flags: Int): Int
    fun close(fd: Int): Int
    fun read(fd: Int, buffer: Pointer, count: NativeLong): NativeLong
    fun pipe2(descriptors: Pointer, flags: Int): Int
    fun fcntl(fd: Int, command: Int, argument: Int): Int
    fun poll(descriptors: Pointer, count: NativeLong, timeoutMilliseconds: Int): Int
    fun kill(pid: Int, signal: Int): Int
    fun waitpid(pid: Int, status: Pointer, options: Int): Int
    fun sigfillset(set: Pointer): Int
    fun sigemptyset(set: Pointer): Int
    fun sigdelset(set: Pointer, signal: Int): Int
    fun posix_spawnattr_init(attributes: Pointer): Int
    fun posix_spawnattr_destroy(attributes: Pointer): Int
    fun posix_spawnattr_setflags(attributes: Pointer, flags: Short): Int
    fun posix_spawnattr_setsigdefault(attributes: Pointer, signals: Pointer): Int
    fun posix_spawnattr_setsigmask(attributes: Pointer, signals: Pointer): Int
    fun posix_spawn_file_actions_init(actions: Pointer): Int
    fun posix_spawn_file_actions_destroy(actions: Pointer): Int
    fun posix_spawn_file_actions_adddup2(actions: Pointer, descriptor: Int, target: Int): Int
    fun posix_spawn_file_actions_addclose(actions: Pointer, descriptor: Int): Int
    fun posix_spawn_file_actions_addclosefrom_np(actions: Pointer, firstDescriptor: Int): Int
    fun posix_spawn_file_actions_addchdir_np(actions: Pointer, path: String): Int
    fun posix_spawn(
        pid: Pointer,
        path: String,
        actions: Pointer,
        attributes: Pointer,
        arguments: Pointer,
        environment: Pointer,
    ): Int
}

/**
 * Reserves only missing standard descriptor numbers before any pipe is allocated. This closes the
 * ordered-dup2 collision in which a pipe endpoint could otherwise be allocated as fd 0, 1, or 2.
 * The callbacks are internal so hostile tests can cover closed-stdio layouts without closing the
 * Gradle worker's own standard descriptors; they convey no process result or authority.
 */
internal fun reserveClosedStandardDescriptors(
    descriptorIsOpen: (Int) -> Boolean,
    openNullReadWrite: () -> Int,
    closeDescriptor: (Int) -> Unit,
): List<Int> {
    val reserved = mutableListOf<Int>()
    try {
        for (target in 0..2) {
            if (descriptorIsOpen(target)) continue
            val opened = openNullReadWrite()
            if (opened != target) {
                if (opened >= 0) closeDescriptor(opened)
                throw LinuxBoundedSessionException(
                    "closed standard descriptor $target was not reserved at its exact number",
                )
            }
            reserved += opened
        }
        return reserved
    } catch (failure: Throwable) {
        reserved.asReversed().forEach(closeDescriptor)
        throw failure
    }
}

private fun portableNativeString(value: String): Boolean =
    '\u0000' !in value && value.toByteArray(StandardCharsets.UTF_8).size <= MAXIMUM_NATIVE_STRING_BYTES

private fun addDeadline(start: Long, duration: Long): Long =
    if (Long.MAX_VALUE - start < duration) Long.MAX_VALUE else start + duration

private fun waitExited(status: Int): Boolean = status and 0x7f == 0
private fun waitExitStatus(status: Int): Int = status ushr 8 and 0xff
private fun waitSignaled(status: Int): Boolean = status and 0x7f in 1..0x7e
private fun waitTermSignal(status: Int): Int = status and 0x7f

private val PORTABLE_ENVIRONMENT_NAME = Regex("[A-Za-z_][A-Za-z0-9_]*")
private val MAXIMUM_TIMEOUT: Duration = Duration.ofSeconds(30)
private val CLEANUP_TIMEOUT: Duration = Duration.ofSeconds(5)
private const val MAXIMUM_ARGUMENTS = 64
private const val MAXIMUM_ARGUMENT_BYTES = 64L * 1024L
private const val MAXIMUM_NATIVE_STRING_BYTES = 16 * 1024
private const val MAXIMUM_ENVIRONMENT_BINDINGS = 64
private const val MAXIMUM_ENVIRONMENT_BYTES = 64L * 1024L
private const val MAXIMUM_CAPTURE_BYTES = 1024 * 1024
private const val CAPTURE_CHUNK_BYTES = 64 * 1024
private const val OPAQUE_NATIVE_STORAGE_BYTES = 4096L
private const val SIGSET_BYTES = 128L
private const val POLLFD_BYTES = 8
private const val ACTIVE_POLL_MILLIS = 25
private const val POST_EXIT_PIPE_POLL_MILLIS = 5
private const val CLEANUP_POLL_MILLIS = 5L
private const val POSIX_SPAWN_SETSIGDEF = 0x04
private const val POSIX_SPAWN_SETSIGMASK = 0x08
private const val POSIX_SPAWN_SETSID = 0x80
private const val O_RDONLY = 0
private const val O_RDWR = 2
private const val O_NONBLOCK = 0x800
private const val O_CLOEXEC = 0x80000
private const val F_GETFD = 1
private const val F_GETFL = 3
private const val F_SETFL = 4
private const val POLLIN = 0x001
private const val POLLNVAL = 0x020
private const val WNOHANG = 1
private const val SIGKILL = 9
private const val SIGSTOP = 19
private const val EINTR = 4
private const val EAGAIN = 11
private const val EWOULDBLOCK = 11
private const val EPERM = 1
private const val ESRCH = 3
private const val EBADF = 9
private const val MAXIMUM_PROC_STAT_BYTES = 16 * 1024
private const val NULL_DEVICE = "/dev/null"
