package decompengine.git

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Platform
import com.sun.jna.Pointer
import com.sun.jna.StringArray
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.LockSupport

/**
 * Linux control-plane containment for the trusted Git executable, not a sandbox for hostile code.
 * Like ACP's LinuxBoundedSessionProcess, posix_spawn creates a fresh session atomically. Unlike
 * ProcessBuilder, we own waitpid: the unreaped leader reserves its group ID even after it exits.
 * Every return/error kills that group BEFORE reaping, including children holding inherited pipes.
 * No capture threads or external setsid/kill executable are involved. A deliberately escaping
 * descendant (setsid/setpgid) requires a separate cgroup boundary; imported helpers remain refused.
 */
internal class GitSessionProcess(
    private val arguments: List<String>,
    private val environment: Map<String, String>,
    private val directory: Path,
    private val invocation: GitInvocation,
) {
    private val deadline = System.nanoTime() + invocation.limits.timeout.toNanos()
    private val libc = Native.load(Platform.C_LIBRARY_NAME, GitSessionLibC::class.java)
    private val attributes = Memory(4096)
    private val actions = Memory(4096)
    private var attributesReady = false
    private var actionsReady = false
    private val descriptors = mutableSetOf<Int>()
    private var pid = -1
    private var reaped = false

    fun execute(): GitCommandResult {
        try {
            checkBound()
            if (System.getProperty("os.name") != "Linux" || Native.LONG_SIZE != 8 || Native.POINTER_SIZE != 8 ||
                System.getProperty("os.arch") !in setOf("amd64", "x86_64", "aarch64")) {
                throw IOException("Git session execution requires Linux LP64")
            }
            // Fail closed rather than allowing ordered dup2 actions to collide with missing stdio.
            for (fd in 0..2) if (libc.fcntl(fd, F_GETFD, 0) < 0) throw IOException("Git session requires open standard descriptors")
            nativeResult(libc.posix_spawnattr_init(attributes)); attributesReady = true
            nativeResult(libc.posix_spawn_file_actions_init(actions)); actionsReady = true
            Memory(128).use { defaults ->
                Memory(128).use { mask ->
                    nativeResult(libc.sigfillset(defaults))
                    nativeResult(libc.sigdelset(defaults, 9))
                    nativeResult(libc.sigdelset(defaults, 19))
                    nativeResult(libc.sigemptyset(mask))
                    nativeResult(libc.posix_spawnattr_setsigdefault(attributes, defaults))
                    nativeResult(libc.posix_spawnattr_setsigmask(attributes, mask))
                }
            }
            // glibc POSIX_SPAWN_SETSID | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK.
            nativeResult(libc.posix_spawnattr_setflags(attributes, 0x8c.toShort()))
            val stdin = libc.open("/dev/null", O_CLOEXEC)
            if (stdin < 0) throw IOException("Git session stdin failed")
            descriptors += stdin
            val stdout = pipe()
            val stderr = pipe()
            nativeResult(libc.posix_spawn_file_actions_adddup2(actions, stdin, 0))
            nativeResult(libc.posix_spawn_file_actions_adddup2(actions, stdout.second, 1))
            nativeResult(libc.posix_spawn_file_actions_adddup2(actions, stderr.second, 2))
            nativeResult(libc.posix_spawn_file_actions_addclosefrom_np(actions, 3))
            nativeResult(libc.posix_spawn_file_actions_addchdir_np(actions, directory.toString()))
            checkBound()
            Memory(4).use { storage ->
                StringArray(arguments.toTypedArray(), "UTF-8").use { argv ->
                    StringArray(environment.map { (key, value) -> "$key=$value" }.toTypedArray(), "UTF-8").use { env ->
                        val result = libc.posix_spawn(storage, arguments.first(), actions, attributes, argv, env)
                        // Record ownership before rejecting even a late successful spawn.
                        if (result == 0) pid = storage.getInt(0)
                        nativeResult(result)
                    }
                }
            }
            checkBound()
            if (pid <= 0) throw IOException("Git session returned an invalid process ID")
            close(stdin); close(stdout.second); close(stderr.second)
            for (fd in listOf(stdout.first, stderr.first)) {
                val flags = libc.fcntl(fd, F_GETFL, 0)
                if (flags < 0 || libc.fcntl(fd, F_SETFL, flags or O_NONBLOCK) < 0) throw IOException("Git session pipe setup failed")
            }
            return capture(stdout.first, stderr.first)
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            throw GitCommandException(GitCommandException.Kind.INTERRUPTED, "Git was interrupted.")
        } catch (failure: GitCommandException) {
            throw failure
        } catch (failure: IOException) {
            throw GitCommandException(GitCommandException.Kind.START_FAILED, "Git session execution failed.")
        } finally {
            // Cleanup must not be abandoned because the caller was interrupted.
            val interrupted = Thread.interrupted()
            try {
                if (pid > 0 && !reaped) killAndReap()
            } finally {
                descriptors.toList().forEach(::close)
                if (actionsReady) libc.posix_spawn_file_actions_destroy(actions)
                if (attributesReady) libc.posix_spawnattr_destroy(attributes)
                actions.close(); attributes.close()
                if (interrupted) Thread.currentThread().interrupt()
            }
        }
    }

    private fun capture(stdoutFd: Int, stderrFd: Int): GitCommandResult {
        val stdout = Capture(stdoutFd, invocation.limits.maxStdoutBytes)
        val stderr = Capture(stderrFd, invocation.limits.maxStderrBytes)
        var groupStopped = false
        Memory(8192).use { chunk ->
            Memory(16).use { poll ->
                while (true) {
                    checkBound()
                    // One chunk per stream per turn prevents stdout starving stderr/deadline checks.
                    stdout.read(chunk); stderr.read(chunk)
                    if (stderr.overflowed || (stdout.overflowed && !invocation.truncateStdout)) {
                        throw GitCommandException(GitCommandException.Kind.OUTPUT_LIMIT, "Git output exceeded its bound.")
                    }
                    val exited = leaderExited()
                    if (!groupStopped && (exited || stdout.overflowed)) {
                        signalGroup(deadline)
                        groupStopped = true
                    }
                    if (exited && stdout.eof && stderr.eof) {
                        // Signal before waitpid, while the zombie still pins the group number.
                        signalGroup(deadline)
                        val status = reap(deadline)
                        checkBound()
                        val truncated = stdout.overflowed && invocation.truncateStdout
                        val exit = if (truncated) -1 else if (status and 0x7f == 0) status ushr 8 and 0xff else 128 + (status and 0x7f)
                        return GitCommandResult(exit, stdout.bytes(), stderr.bytes(), truncated)
                    }
                    val active = listOf(stdout, stderr).filter { !it.eof }
                    active.forEachIndexed { index, stream ->
                        val offset = index * 8L
                        poll.setInt(offset, stream.fd); poll.setShort(offset + 4, 1); poll.setShort(offset + 6, 0)
                    }
                    val remaining = deadline - System.nanoTime()
                    checkBound()
                    val result = libc.poll(poll, NativeLong(active.size.toLong()), minOf(20L, maxOf(0L, remaining / 1_000_000)).toInt())
                    if (result < 0 && Native.getLastError() != EINTR) throw IOException("Git session poll failed")
                }
            }
        }
    }

    private inner class Capture(val fd: Int, private val limit: Int) {
        private val buffer = ByteArrayOutputStream(minOf(limit, 8192))
        var eof = false
        var overflowed = false
        fun read(chunk: Memory) {
            if (eof) return
            checkBound()
            val count = libc.read(fd, chunk, NativeLong(8192)).toLong()
            val error = if (count < 0) Native.getLastError() else 0
            checkBound()
            when {
                count > 0 -> {
                    val retained = minOf(count.toInt(), limit - buffer.size())
                    buffer.write(chunk.getByteArray(0, retained))
                    if (retained < count) overflowed = true
                }
                count == 0L -> { eof = true; close(fd) }
                error != EINTR && error != EAGAIN -> throw IOException("Git session read failed")
            }
        }
        fun bytes(): ByteArray = buffer.toByteArray()
    }

    /** An unreaped child cannot disappear or have its PID reused; do not call waitpid here. */
    private fun leaderExited(): Boolean {
        val stat = Files.readString(Path.of("/proc", pid.toString(), "stat"))
        val end = stat.lastIndexOf(") ")
        if (end < 0 || end + 2 >= stat.length) throw IOException("Git session state is invalid")
        return stat[end + 2] in setOf('Z', 'X', 'x')
    }

    private fun signalGroup(until: Long) {
        while (true) {
            val result = libc.kill(-pid, 9)
            val error = if (result != 0) Native.getLastError() else 0
            if (result == 0 || error == ESRCH) return
            if (error != EINTR || until - System.nanoTime() <= 0) throw IOException("Git session cleanup signal failed")
        }
    }

    private fun killAndReap() {
        // One emergency budget, not a fresh wait for every descriptor or descendant.
        val cleanupDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        // No reader threads: closing our nonblocking descriptors cannot strand a capture reader.
        descriptors.toList().forEach(::close)
        try {
            signalGroup(cleanupDeadline)
            reap(cleanupDeadline)
        } catch (failure: IOException) {
            throw GitCommandException(GitCommandException.Kind.START_FAILED, "Git process cleanup did not complete.")
        }
    }

    private fun reap(until: Long): Int = Memory(4).use { status ->
        while (true) {
            val result = libc.waitpid(pid, status, WNOHANG)
            if (result == pid) { reaped = true; return status.getInt(0) }
            if (result < 0 && Native.getLastError() != EINTR) throw IOException("Git session reap failed")
            if (until - System.nanoTime() <= 0) throw IOException("Git session cleanup deadline expired")
            LockSupport.parkNanos(1_000_000)
        }
        @Suppress("UNREACHABLE_CODE")
        0
    }

    private fun pipe(): Pair<Int, Int> = Memory(8).use { storage ->
        if (libc.pipe2(storage, O_CLOEXEC) != 0) throw IOException("Git session pipe failed")
        val pair = storage.getInt(0) to storage.getInt(4)
        descriptors += pair.first; descriptors += pair.second
        pair
    }

    private fun close(fd: Int) { if (descriptors.remove(fd)) libc.close(fd) }
    private fun nativeResult(result: Int) { if (result != 0) throw IOException("Git session native setup failed") }
    private fun checkBound() {
        if (Thread.currentThread().isInterrupted) throw InterruptedException()
        if (deadline - System.nanoTime() <= 0) throw GitCommandException(GitCommandException.Kind.TIMED_OUT, "Git did not finish within its time bound.")
    }

    private companion object {
        const val O_CLOEXEC = 0x80000
        const val O_NONBLOCK = 0x800
        const val F_GETFD = 1
        const val F_GETFL = 3
        const val F_SETFL = 4
        const val WNOHANG = 1
        const val EINTR = 4
        const val EAGAIN = 11
        const val ESRCH = 3
    }
}

private interface GitSessionLibC : Library {
    fun open(path: String, flags: Int): Int
    fun close(fd: Int): Int
    fun pipe2(descriptors: Pointer, flags: Int): Int
    fun read(fd: Int, buffer: Pointer, count: NativeLong): NativeLong
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
    fun posix_spawn_file_actions_addclosefrom_np(actions: Pointer, firstDescriptor: Int): Int
    fun posix_spawn_file_actions_addchdir_np(actions: Pointer, path: String): Int
    fun posix_spawn(pid: Pointer, path: String, actions: Pointer, attributes: Pointer, arguments: Pointer, environment: Pointer): Int
}
