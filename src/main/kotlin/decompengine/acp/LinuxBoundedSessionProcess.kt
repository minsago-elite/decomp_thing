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
import java.util.Collections
import java.util.LinkedHashMap

/**
 * One bounded, non-interactive Linux control-plane command.
 *
 * This is an internal mechanism, not an execution or scoring authority. The command is created as
 * a fresh session leader by `posix_spawn(3)`, so timeout/error cleanup can address its process
 * group while the unreaped leader still reserves the numeric group id. This does not prove
 * whole-tree cleanup: a descendant can deliberately create another session/process group, and
 * only a separately verified cgroup boundary can close that gap. The executable itself must be
 * authenticated by the caller; this layer deliberately accepts no claimed digest.
 *
 * One monotonic deadline covers native setup, spawn, capture, pipe closure, and successful reap.
 * Deadline checks bracket native calls and every retry. Terminal descriptor/attribute release is
 * not safely preemptible or retryable, and JNA cannot preempt one native syscall that has already
 * entered the kernel; a late return is rejected at the following safe ownership checkpoint.
 */
internal class LinuxBoundedSessionCommand(
    arguments: List<String>,
    environment: Map<String, String>,
    val workingDirectory: Path = Path.of("/"),
    val timeout: Duration,
    val maximumStdoutBytes: Int,
    val maximumStderrBytes: Int,
) {
    val arguments: List<String> = Collections.unmodifiableList(arguments.toList())
    val environment: Map<String, String> = Collections.unmodifiableMap(LinkedHashMap(environment))

    init {
        require(this.arguments.isNotEmpty() && this.arguments.size <= MAXIMUM_ARGUMENTS) {
            "bounded session command must contain 1..$MAXIMUM_ARGUMENTS arguments"
        }
        require(this.arguments.all(::portableNativeString)) {
            "bounded session command contains an invalid native argument"
        }
        val executable = try {
            Path.of(this.arguments.first())
        } catch (failure: Exception) {
            throw IllegalArgumentException("bounded session executable path is invalid", failure)
        }
        require(
            executable.isAbsolute && executable.normalize() == executable && executable.fileName != null &&
                executable.toString() == this.arguments.first(),
        ) {
            "bounded session executable path must be exact, normalized, absolute, and name a file"
        }
        require(
            this.arguments.sumOf { it.toByteArray(StandardCharsets.UTF_8).size.toLong() } <=
                MAXIMUM_ARGUMENT_BYTES,
        ) {
            "bounded session command arguments exceed their byte limit"
        }
        require(this.environment.size <= MAXIMUM_ENVIRONMENT_BINDINGS) {
            "bounded session environment contains too many bindings"
        }
        require(this.environment.keys.all { it.matches(PORTABLE_ENVIRONMENT_NAME) }) {
            "bounded session environment contains an invalid name"
        }
        require(this.environment.entries.all { portableNativeString(it.value) }) {
            "bounded session environment contains an invalid value"
        }
        require(this.environment.entries.sumOf {
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
        val deadline = commandDeadline(command)
        requireSupported(command.workingDirectory)
        val native = NativeSessionCommand(command, NonAuthoritativeSessionTestHook.NONE)
        return native.execute(deadline)
    }

    /**
     * Internal hostile-test seam. It cannot inject output, exit status, facts, or authority, and
     * deliberately cannot replace the monotonic clock or any native call. A libc/clock seam would
     * become a module-callable process-control surface rather than merely observing a real child.
     */
    @JvmSynthetic
    internal fun executeForNonAuthoritativeTest(
        command: LinuxBoundedSessionCommand,
        hook: NonAuthoritativeSessionTestHook,
    ): LinuxBoundedSessionResult {
        val deadline = commandDeadline(command)
        requireSupported(command.workingDirectory)
        return NativeSessionCommand(command, hook).execute(deadline)
    }

    private fun commandDeadline(command: LinuxBoundedSessionCommand): Long =
        addDeadline(System.nanoTime(), command.timeout.toNanos())

    private fun requireSupported(path: Path) {
        if (System.getProperty("os.name", "") != "Linux" || path.fileSystem != FileSystems.getDefault()) {
            throw LinuxBoundedSessionException("bounded session execution requires the Linux default filesystem")
        }
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

    fun execute(commandDeadline: Long): LinuxBoundedSessionResult {
        var primary: Throwable? = null
        try {
            requireDeadline(commandDeadline, DeadlinePhase.COMMAND)
            requirePidfdSupported(commandDeadline)
            prepareNativeState(commandDeadline)
            spawn(commandDeadline)
            requireDeadline(commandDeadline, DeadlinePhase.COMMAND)
            closeParentWriteEnds()
            requireDeadline(commandDeadline, DeadlinePhase.COMMAND)
            makeParentReadEndsNonblocking(commandDeadline)
            val captured = capture(commandDeadline)
            // The exited, unreaped session leader still reserves its process-group id. SIGKILL is
            // therefore directed at that exact group before the numeric id can be reused.
            signalGroup(SIGKILL, commandDeadline, DeadlinePhase.COMMAND)
            val status = reapExitedLeader(commandDeadline, DeadlinePhase.COMMAND)
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
                    // A failed command gets one emergency-cleanup budget. Every signal, exit
                    // probe, and reap below shares this exact deadline; none may compose a new
                    // grace window.
                    val cleanupDeadline = addDeadline(System.nanoTime(), CLEANUP_TIMEOUT.toNanos())
                    killAndReapLeader(cleanupDeadline)
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

    private fun prepareNativeState(deadline: Long) {
        requireDeadline(deadline, DeadlinePhase.COMMAND)
        val attributesResult = libc.posix_spawnattr_init(attributes)
        if (attributesResult == 0) attributesInitialized = true
        requireDeadline(deadline, DeadlinePhase.COMMAND)
        nativeResult("initialize spawn attributes", attributesResult)
        val defaults = Memory(SIGSET_BYTES)
        val mask = Memory(SIGSET_BYTES)
        requireDeadline(deadline, DeadlinePhase.COMMAND)
        commandSyscallResult(deadline, "initialize default signal set") { libc.sigfillset(defaults) }
        commandSyscallResult(deadline, "exclude SIGKILL from default signal set") {
            libc.sigdelset(defaults, SIGKILL)
        }
        commandSyscallResult(deadline, "exclude SIGSTOP from default signal set") {
            libc.sigdelset(defaults, SIGSTOP)
        }
        commandSyscallResult(deadline, "initialize empty signal mask") { libc.sigemptyset(mask) }
        commandNativeResult(deadline, "configure default signals") {
            libc.posix_spawnattr_setsigdefault(attributes, defaults)
        }
        commandNativeResult(deadline, "configure signal mask") {
            libc.posix_spawnattr_setsigmask(attributes, mask)
        }
        commandNativeResult(
            deadline,
            "configure bounded session",
        ) {
            libc.posix_spawnattr_setflags(
                attributes,
                (POSIX_SPAWN_SETSID or POSIX_SPAWN_SETSIGDEF or POSIX_SPAWN_SETSIGMASK).toShort(),
            )
        }

        requireDeadline(deadline, DeadlinePhase.COMMAND)
        val fileActionsResult = libc.posix_spawn_file_actions_init(fileActions)
        if (fileActionsResult == 0) fileActionsInitialized = true
        requireDeadline(deadline, DeadlinePhase.COMMAND)
        nativeResult("initialize spawn file actions", fileActionsResult)
        reservedStandardDescriptors += reserveClosedStandardDescriptors(
            descriptorIsOpen = { descriptorIsOpen(it, deadline) },
            openNullReadWrite = { openNullReadWrite(deadline) },
            closeDescriptor = ::closeFd,
        )
        stdinFd = openNullInput(deadline)
        val stdoutPipe = createPipe("stdout", deadline)
        stdoutReadFd = stdoutPipe.first
        stdoutWriteFd = stdoutPipe.second
        val stderrPipe = createPipe("stderr", deadline)
        stderrReadFd = stderrPipe.first
        stderrWriteFd = stderrPipe.second

        commandNativeResult(deadline, "bind bounded session stdin") {
            libc.posix_spawn_file_actions_adddup2(fileActions, stdinFd, 0)
        }
        commandNativeResult(
            deadline,
            "bind bounded session stdout",
        ) {
            libc.posix_spawn_file_actions_adddup2(fileActions, stdoutWriteFd, 1)
        }
        commandNativeResult(
            deadline,
            "bind bounded session stderr",
        ) {
            libc.posix_spawn_file_actions_adddup2(fileActions, stderrWriteFd, 2)
        }
        listOf(stdinFd, stdoutReadFd, stdoutWriteFd, stderrReadFd, stderrWriteFd)
            .filter { it > 2 }
            .distinct()
            .forEach { descriptor ->
                commandNativeResult(
                    deadline,
                    "close surplus bounded session descriptor",
                ) {
                    libc.posix_spawn_file_actions_addclose(fileActions, descriptor)
                }
            }
        commandNativeResult(
            deadline,
            "close inherited bounded session descriptors",
        ) {
            libc.posix_spawn_file_actions_addclosefrom_np(fileActions, 3)
        }
        commandNativeResult(
            deadline,
            "configure bounded session working directory",
        ) {
            libc.posix_spawn_file_actions_addchdir_np(fileActions, command.workingDirectory.toString())
        }
    }

    private fun spawn(deadline: Long) {
        requireDeadline(deadline, DeadlinePhase.COMMAND)
        val pidStorage = Memory(Int.SIZE_BYTES.toLong())
        val arguments = StringArray(command.arguments.toTypedArray(), StandardCharsets.UTF_8.name())
        val environment = command.environment.entries
            .sortedBy { it.key }
            .map { (name, value) -> "$name=$value" }
        val environmentArray = StringArray(environment.toTypedArray(), StandardCharsets.UTF_8.name())
        requireDeadline(deadline, DeadlinePhase.COMMAND)
        val result = libc.posix_spawn(
            pidStorage,
            command.arguments.first(),
            fileActions,
            attributes,
            arguments,
            environmentArray,
        )
        if (result == 0) {
            // Record a successfully returned child before checking the deadline: a late spawn is
            // mutation-committed and must enter the outer kill/reap path rather than orphaning it.
            pid = pidStorage.getInt(0)
        }
        requireDeadline(deadline, DeadlinePhase.COMMAND)
        nativeResult("start bounded session", result)
        if (pid <= 0) throw LinuxBoundedSessionException("bounded session returned an invalid process id")
        testHook.spawnedPidObserver(pid.toLong())
        requireDeadline(deadline, DeadlinePhase.COMMAND)
        processHandle = try {
            if (testHook.forcePidfdOpenFailure) {
                throw LinuxBoundedSessionException("forced non-authoritative pidfd-open test failure")
            }
            openProcessHandle(pid.toLong(), deadline)
        } catch (failure: Throwable) {
            if (failure is LinuxBoundedSessionTimeoutException) throw failure
            // The outer failure path owns signaling and waitpid reaping even without a pidfd.
            throw LinuxBoundedSessionException("bounded session leader could not be pidfd-pinned", failure)
        }
    }

    private fun capture(deadline: Long): Pair<ByteArray, ByteArray> {
        val stdout = BoundedNativeCapture("stdout", command.maximumStdoutBytes, command.timeout)
        val stderr = BoundedNativeCapture("stderr", command.maximumStderrBytes, command.timeout)
        var leaderExited = false
        var exitedGroupSignaled = false
        while (true) {
            requireDeadline(deadline, DeadlinePhase.COMMAND)
            stdout.drain(libc, stdoutReadFd, deadline).also { if (it) stdoutReadFd = -1 }
            stderr.drain(libc, stderrReadFd, deadline).also { if (it) stderrReadFd = -1 }
            leaderExited = leaderExited || processExited(
                requireNotNull(processHandle),
                deadline,
                DeadlinePhase.COMMAND,
            )
            if (leaderExited) {
                if (!exitedGroupSignaled) {
                    // No successful command is allowed to leave a same-session writer behind.
                    // The zombie leader still reserves the exact process-group number here.
                    signalGroup(SIGKILL, deadline, DeadlinePhase.COMMAND)
                    exitedGroupSignaled = true
                }
                if (stdoutReadFd < 0 && stderrReadFd < 0) {
                    requireDeadline(deadline, DeadlinePhase.COMMAND)
                    return stdout.bytes() to stderr.bytes()
                }
            }
            val maximumPollMillis = if (leaderExited) {
                POST_EXIT_PIPE_POLL_MILLIS
            } else {
                ACTIVE_POLL_MILLIS
            }
            pollReadable(stdoutReadFd, stderrReadFd, maximumPollMillis, deadline)
        }
    }

    private fun pollReadable(stdoutFd: Int, stderrFd: Int, maximumPollMillis: Int, deadline: Long) {
        requireDeadline(deadline, DeadlinePhase.COMMAND)
        val descriptors = listOf(stdoutFd, stderrFd).filter { it >= 0 }
        if (descriptors.isEmpty()) {
            sleepWithinDeadline(deadline, maximumPollMillis.toLong(), DeadlinePhase.COMMAND)
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
            requireDeadline(deadline, DeadlinePhase.COMMAND)
            val timeoutMillis = remainingPollMilliseconds(deadline, maximumPollMillis)
            val result = libc.poll(poll, NativeLong(descriptors.size.toLong()), timeoutMillis)
            val error = if (result < 0) Native.getLastError() else 0
            requireDeadline(deadline, DeadlinePhase.COMMAND)
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
            if (error != EINTR) throw LinuxSyscallException("poll bounded session", error)
            // poll(2) does not promise to preserve its relative timeout after EINTR. Re-enter with
            // a freshly computed remainder of the one absolute command deadline.
            requireDeadline(deadline, DeadlinePhase.COMMAND)
        }
    }

    private fun killAndReapLeader(deadline: Long) {
        var lastFailure: Throwable? = null
        closeParentWriteEnds()
        // Output is already unusable on this failure path. Close both read ends instead of
        // draining them: a descendant that escaped the session and continuously writes to an
        // inherited pipe must not be able to keep cleanup inside read(2) beyond its deadline.
        closeFd(stdoutReadFd)
        stdoutReadFd = -1
        closeFd(stderrReadFd)
        stderrReadFd = -1
        while (true) {
            try {
                // pid remains a reserved child identity until waitpid succeeds. Never use the
                // negative group id after reap, when it could have been assigned to another group.
                signalGroup(SIGKILL, deadline, DeadlinePhase.CLEANUP)
                processHandle?.let { signalProcess(it, SIGKILL, deadline, DeadlinePhase.CLEANUP) }
                val rootExited = processHandle?.let {
                    processExited(it, deadline, DeadlinePhase.CLEANUP)
                } ?: leaderExitedWithoutReaping(deadline)
                if (rootExited) {
                    reapExitedLeader(deadline, DeadlinePhase.CLEANUP)
                    return
                }
            } catch (failure: Throwable) {
                lastFailure = failure
            }
            if (deadlineExpired(deadline)) {
                throw LinuxBoundedSessionCleanupException(
                    "bounded session leader did not exit after pre-reap SIGKILL",
                    lastFailure,
                )
            }
            sleepWithinDeadline(deadline, CLEANUP_POLL_MILLIS, DeadlinePhase.CLEANUP)
        }
    }

    private fun signalGroup(signal: Int, deadline: Long, phase: DeadlinePhase) {
        while (true) {
            requireDeadline(deadline, phase)
            val result = libc.kill(-pid, signal)
            val error = if (result != 0) Native.getLastError() else 0
            requireDeadline(deadline, phase)
            if (result == 0) return
            when (error) {
                EINTR -> {
                    requireDeadline(deadline, phase)
                    continue
                }
                ESRCH -> return
                else -> throw LinuxSyscallException("signal bounded session process group", error)
            }
        }
    }

    private fun reapExitedLeader(deadline: Long, phase: DeadlinePhase): Int {
        val status = Memory(Int.SIZE_BYTES.toLong())
        var attempted = false
        while (true) {
            // Even an expired deadline gets one WNOHANG attempt so a zombie already waiting for
            // us is reaped before the deadline failure escapes. Every retry is deadline-gated.
            if (attempted) requireDeadline(deadline, phase)
            val result = libc.waitpid(pid, status, WNOHANG)
            val error = if (result < 0) Native.getLastError() else 0
            attempted = true
            when {
                result == pid -> {
                    reaped = true
                    requireDeadline(deadline, phase)
                    return status.getInt(0)
                }
                result == 0 -> {
                    requireDeadline(deadline, phase)
                    sleepWithinDeadline(deadline, CLEANUP_POLL_MILLIS, phase)
                }
                error == EINTR -> requireDeadline(deadline, phase)
                else -> {
                    requireDeadline(deadline, phase)
                    throw LinuxSyscallException("reap bounded session leader", error)
                }
            }
        }
    }

    /** waitpid(WNOHANG) would reap; `/proc` state keeps the child reserved for group signaling. */
    private fun leaderExitedWithoutReaping(deadline: Long): Boolean {
        requireDeadline(deadline, DeadlinePhase.CLEANUP)
        val stat = try {
            java.nio.file.Files.readString(Path.of("/proc", pid.toString(), "stat"))
        } catch (failure: java.nio.file.NoSuchFileException) {
            return true
        } catch (failure: IOException) {
            throw LinuxBoundedSessionException("cannot inspect unpinned bounded session leader", failure)
        }
        requireDeadline(deadline, DeadlinePhase.CLEANUP)
        if (stat.toByteArray(StandardCharsets.UTF_8).size > MAXIMUM_PROC_STAT_BYTES) {
            throw LinuxBoundedSessionException("unpinned bounded session leader stat exceeds its bound")
        }
        val commandEnd = stat.lastIndexOf(") ")
        if (commandEnd < 0 || commandEnd + 2 >= stat.length) {
            throw LinuxBoundedSessionException("unpinned bounded session leader stat is malformed")
        }
        return stat[commandEnd + 2] in setOf('Z', 'X', 'x')
    }

    private fun createPipe(label: String, deadline: Long): Pair<Int, Int> {
        requireDeadline(deadline, DeadlinePhase.COMMAND)
        val descriptors = Memory((2 * Int.SIZE_BYTES).toLong())
        val nativeResult = libc.pipe2(descriptors, O_CLOEXEC)
        val error = if (nativeResult != 0) Native.getLastError() else 0
        if (nativeResult == 0) {
            val pipe = descriptors.getInt(0) to descriptors.getInt(Int.SIZE_BYTES.toLong())
            try {
                requireDeadline(deadline, DeadlinePhase.COMMAND)
                return pipe
            } catch (failure: Throwable) {
                closeFd(pipe.first)
                closeFd(pipe.second)
                throw failure
            }
        }
        requireDeadline(deadline, DeadlinePhase.COMMAND)
        throw LinuxSyscallException("create bounded session $label pipe", error)
    }

    private fun openNullInput(deadline: Long): Int {
        while (true) {
            requireDeadline(deadline, DeadlinePhase.COMMAND)
            val result = libc.open(NULL_DEVICE, O_RDONLY or O_CLOEXEC)
            if (result >= 0) return requireDescriptorBeforeDeadline(result, deadline)
            val error = Native.getLastError()
            requireDeadline(deadline, DeadlinePhase.COMMAND)
            if (error != EINTR) throw LinuxSyscallException("open bounded session null input", error)
        }
    }

    private fun openNullReadWrite(deadline: Long): Int {
        while (true) {
            requireDeadline(deadline, DeadlinePhase.COMMAND)
            val result = libc.open(NULL_DEVICE, O_RDWR or O_CLOEXEC)
            if (result >= 0) return requireDescriptorBeforeDeadline(result, deadline)
            val error = Native.getLastError()
            requireDeadline(deadline, DeadlinePhase.COMMAND)
            if (error != EINTR) {
                throw LinuxSyscallException("reserve bounded session standard descriptor", error)
            }
        }
    }

    private fun descriptorIsOpen(descriptor: Int, deadline: Long): Boolean {
        while (true) {
            requireDeadline(deadline, DeadlinePhase.COMMAND)
            val result = libc.fcntl(descriptor, F_GETFD, 0)
            if (result >= 0) {
                requireDeadline(deadline, DeadlinePhase.COMMAND)
                return true
            }
            val error = Native.getLastError()
            requireDeadline(deadline, DeadlinePhase.COMMAND)
            when (error) {
                EBADF -> return false
                EINTR -> requireDeadline(deadline, DeadlinePhase.COMMAND)
                else -> throw LinuxSyscallException("inspect bounded session standard descriptor", error)
            }
        }
    }

    private fun makeParentReadEndsNonblocking(deadline: Long) {
        listOf(stdoutReadFd, stderrReadFd).filter { it >= 0 }.forEach { descriptor ->
            val flags = retryFcntl(descriptor, F_GETFL, 0, deadline, "inspect bounded session pipe flags")
            retryFcntl(
                descriptor,
                F_SETFL,
                flags or O_NONBLOCK,
                deadline,
                "set bounded session pipe nonblocking",
            )
        }
    }

    /*
     * These small pidfd operations intentionally remain private to the bounded runner. The generic
     * LinuxFilesystemSyscalls variants expose no absolute-deadline contract and own their EINTR
     * retries internally, so calling them here would reopen an unbounded retry path. Adding a
     * caller-supplied clock/native callback or a public process-signaling overload would widen the
     * authority surface solely for this control-plane command.
     */
    private fun requirePidfdSupported(deadline: Long) {
        try {
            openProcessHandle(ProcessHandle.current().pid(), deadline).use { handle ->
                if (!signalProcess(handle, 0, deadline, DeadlinePhase.COMMAND)) {
                    throw LinuxBoundedSessionException("Linux pidfd process cleanup probe lost its live process")
                }
            }
        } catch (failure: LinuxBoundedSessionTimeoutException) {
            throw failure
        } catch (failure: Throwable) {
            throw LinuxBoundedSessionException("Linux pidfd process cleanup is unavailable", failure)
        }
    }

    private fun openProcessHandle(processId: Long, deadline: Long): LinuxProcessDescriptor {
        require(processId in 1..Int.MAX_VALUE.toLong()) { "process id is invalid" }
        while (true) {
            requireDeadline(deadline, DeadlinePhase.COMMAND)
            val descriptor = libc.pidfd_open(processId.toInt(), 0)
            if (descriptor >= 0) {
                val handle = LinuxProcessDescriptor(descriptor, processId)
                try {
                    requireDeadline(deadline, DeadlinePhase.COMMAND)
                    return handle
                } catch (failure: Throwable) {
                    handle.close()
                    throw failure
                }
            }
            val error = Native.getLastError()
            requireDeadline(deadline, DeadlinePhase.COMMAND)
            when (error) {
                EINTR -> requireDeadline(deadline, DeadlinePhase.COMMAND)
                else -> throw LinuxSyscallException("open bounded session process handle", error)
            }
        }
    }

    private fun signalProcess(
        handle: LinuxProcessDescriptor,
        signal: Int,
        deadline: Long,
        phase: DeadlinePhase,
    ): Boolean = handle.signalWhileOpen { descriptor ->
        while (true) {
            requireDeadline(deadline, phase)
            val result = libc.pidfd_send_signal(descriptor, signal, null, 0)
            val error = if (result != 0) Native.getLastError() else 0
            requireDeadline(deadline, phase)
            if (result == 0) return@signalWhileOpen true
            when (error) {
                EINTR -> requireDeadline(deadline, phase)
                ESRCH -> return@signalWhileOpen false
                else -> throw LinuxSyscallException("signal bounded session process handle", error)
            }
        }
        @Suppress("UNREACHABLE_CODE")
        false
    }

    private fun processExited(
        handle: LinuxProcessDescriptor,
        deadline: Long,
        phase: DeadlinePhase,
    ): Boolean = handle.signalWhileOpen { descriptor ->
        val pollDescriptor = Memory(POLLFD_BYTES.toLong())
        pollDescriptor.setInt(0, descriptor)
        pollDescriptor.setShort(Int.SIZE_BYTES.toLong(), POLLIN.toShort())
        pollDescriptor.setShort((Int.SIZE_BYTES + Short.SIZE_BYTES).toLong(), 0)
        while (true) {
            requireDeadline(deadline, phase)
            val result = libc.poll(pollDescriptor, NativeLong(1), 0)
            val error = if (result < 0) Native.getLastError() else 0
            requireDeadline(deadline, phase)
            if (result >= 0) {
                val events = pollDescriptor.getShort(
                    (Int.SIZE_BYTES + Short.SIZE_BYTES).toLong(),
                ).toInt() and 0xffff
                if (events and POLLNVAL != 0) {
                    throw LinuxBoundedSessionException(
                        "bounded session process-handle poll observed an invalid descriptor",
                    )
                }
                return@signalWhileOpen result > 0 && events and (POLLIN or POLLHUP or POLLERR) != 0
            }
            when (error) {
                EINTR -> requireDeadline(deadline, phase)
                else -> throw LinuxSyscallException("inspect bounded session process exit", error)
            }
        }
        @Suppress("UNREACHABLE_CODE")
        false
    }

    private fun retryFcntl(
        descriptor: Int,
        operation: Int,
        argument: Int,
        deadline: Long,
        label: String,
    ): Int {
        while (true) {
            requireDeadline(deadline, DeadlinePhase.COMMAND)
            val result = libc.fcntl(descriptor, operation, argument)
            if (result >= 0) {
                requireDeadline(deadline, DeadlinePhase.COMMAND)
                return result
            }
            val error = Native.getLastError()
            requireDeadline(deadline, DeadlinePhase.COMMAND)
            when (error) {
                EINTR -> requireDeadline(deadline, DeadlinePhase.COMMAND)
                else -> throw LinuxSyscallException(label, error)
            }
        }
    }

    private fun requireDescriptorBeforeDeadline(descriptor: Int, deadline: Long): Int = try {
        requireDeadline(deadline, DeadlinePhase.COMMAND)
        descriptor
    } catch (failure: Throwable) {
        closeFd(descriptor)
        throw failure
    }

    private inline fun commandNativeResult(deadline: Long, operation: String, invocation: () -> Int) {
        requireDeadline(deadline, DeadlinePhase.COMMAND)
        val result = invocation()
        requireDeadline(deadline, DeadlinePhase.COMMAND)
        nativeResult(operation, result)
    }

    private inline fun commandSyscallResult(deadline: Long, operation: String, invocation: () -> Int) {
        requireDeadline(deadline, DeadlinePhase.COMMAND)
        val result = invocation()
        val error = if (result != 0) Native.getLastError() else 0
        requireDeadline(deadline, DeadlinePhase.COMMAND)
        if (result != 0) {
            throw LinuxSyscallException(operation, error)
        }
    }

    private fun remainingPollMilliseconds(deadline: Long, maximumMilliseconds: Int): Int {
        val remaining = remainingNanos(deadline)
        if (remaining <= 0L) requireDeadline(deadline, DeadlinePhase.COMMAND)
        return minOf(maximumMilliseconds.toLong(), remaining / NANOS_PER_MILLISECOND).toInt()
    }

    private fun sleepWithinDeadline(deadline: Long, maximumMilliseconds: Long, phase: DeadlinePhase) {
        requireDeadline(deadline, phase)
        val sleepMilliseconds = minOf(
            maximumMilliseconds,
            maxOf(0L, remainingNanos(deadline) / NANOS_PER_MILLISECOND),
        )
        if (sleepMilliseconds > 0L) {
            Thread.sleep(sleepMilliseconds)
        } else {
            Thread.onSpinWait()
        }
        requireDeadline(deadline, phase)
    }

    private fun requireDeadline(deadline: Long, phase: DeadlinePhase) {
        if (!deadlineExpired(deadline)) return
        when (phase) {
            DeadlinePhase.COMMAND -> throw LinuxBoundedSessionTimeoutException(
                "bounded session exceeded ${command.timeout.toMillis()} ms",
            )
            DeadlinePhase.CLEANUP -> throw LinuxBoundedSessionCleanupException(
                "bounded session emergency cleanup exceeded ${CLEANUP_TIMEOUT.toMillis()} ms",
            )
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

    private fun closeFd(descriptor: Int) {
        if (descriptor < 0) return
        // On Linux, close owns the descriptor even when interrupted; never retry a reused number.
        libc.close(descriptor)
    }

    private fun nativeResult(operation: String, result: Int) {
        if (result != 0) throw LinuxBoundedSessionException("$operation failed with errno $result")
    }

}

private class BoundedNativeCapture(
    private val label: String,
    private val maximumBytes: Int,
    private val timeout: Duration,
) {
    private val output = ByteArrayOutputStream(minOf(maximumBytes, CAPTURE_CHUNK_BYTES))
    private val buffer = Memory(CAPTURE_CHUNK_BYTES.toLong())

    /** Returns true after EOF and closes the caller's ownership logically. */
    fun drain(libc: SessionLibC, descriptor: Int, deadline: Long): Boolean {
        if (descriptor < 0) return true
        while (true) {
            requireCommandDeadline(deadline, timeout)
            val count = libc.read(descriptor, buffer, NativeLong(CAPTURE_CHUNK_BYTES.toLong())).toLong()
            val error = if (count < 0L) Native.getLastError() else 0
            requireCommandDeadline(deadline, timeout)
            when {
                count > 0L -> {
                    if (count > maximumBytes.toLong() - output.size().toLong()) {
                        throw LinuxBoundedSessionOutputLimitException(
                            "bounded session $label exceeded $maximumBytes bytes",
                        )
                    }
                    output.write(buffer.getByteArray(0, count.toInt()))
                    requireCommandDeadline(deadline, timeout)
                }
                count == 0L -> {
                    libc.close(descriptor)
                    return true
                }
                error == EINTR -> continue
                error in setOf(EAGAIN, EWOULDBLOCK) -> return false
                else -> throw LinuxSyscallException("read bounded session $label", error)
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
    fun pidfd_open(pid: Int, flags: Int): Int
    fun pidfd_send_signal(pidfd: Int, signal: Int, info: Pointer?, flags: Int): Int
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

/** nanoTime arithmetic is intentionally wrapping; signed subtraction is safe for these <=30s spans. */
private fun addDeadline(start: Long, duration: Long): Long = start + duration

private fun remainingNanos(deadline: Long): Long = deadline - System.nanoTime()

private fun deadlineExpired(deadline: Long): Boolean = remainingNanos(deadline) <= 0L

private fun requireCommandDeadline(deadline: Long, timeout: Duration) {
    if (deadlineExpired(deadline)) {
        throw LinuxBoundedSessionTimeoutException(
            "bounded session exceeded ${timeout.toMillis()} ms",
        )
    }
}

private fun waitExited(status: Int): Boolean = status and 0x7f == 0
private fun waitExitStatus(status: Int): Int = status ushr 8 and 0xff
private fun waitSignaled(status: Int): Boolean = status and 0x7f in 1..0x7e
private fun waitTermSignal(status: Int): Int = status and 0x7f

private val PORTABLE_ENVIRONMENT_NAME = Regex("[A-Za-z_][A-Za-z0-9_]*")
private val MAXIMUM_TIMEOUT: Duration = Duration.ofSeconds(30)
private val CLEANUP_TIMEOUT: Duration = Duration.ofSeconds(5)
private enum class DeadlinePhase { COMMAND, CLEANUP }
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
private const val NANOS_PER_MILLISECOND = 1_000_000L
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
private const val POLLERR = 0x008
private const val POLLHUP = 0x010
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
