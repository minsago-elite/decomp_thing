package decompengine.acp

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Platform
import com.sun.jna.Pointer
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes

/**
 * The small Linux syscall surface used by [AcpFilesystemBroker].
 *
 * Java NIO does not expose descriptor-relative no-replace/exchange renames, nor a way to reopen an
 * already-authorized O_PATH descriptor for reading. Keeping this boundary small makes unsupported
 * hosts fail closed instead of silently falling back to path-based I/O.
 */
internal object LinuxFilesystemSyscalls {
    private val libc: LibC by lazy { Native.load(Platform.C_LIBRARY_NAME, LibC::class.java) }

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
            if (failure.errno != ENOENT) throw IOException("Linux renameat2 is unavailable", failure)
        } catch (failure: UnsatisfiedLinkError) {
            throw IOException("Linux renameat2 is unavailable", failure)
        }
    }

    fun openRoot(path: Path): LinuxDescriptor = openDescriptor(
        AT_FDCWD,
        path.toString(),
        O_RDONLY or O_DIRECTORY or O_NOFOLLOW or O_CLOEXEC,
        0,
        "open workspace root",
    )

    fun openDirectoryAt(parentFd: Int, name: String): LinuxDescriptor = openDescriptor(
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

    /** Opens the regular file pinned by [authorized] rather than resolving its workspace pathname again. */
    fun openReadableFrom(authorized: LinuxDescriptor): LinuxDescriptor {
        val reopened = openDescriptor(
            AT_FDCWD,
            descriptorPath(authorized.fd).toString(),
            O_RDONLY or O_NONBLOCK or O_CLOEXEC,
            0,
            "open authorized filesystem entry for reading",
        )
        if (
            reopened.identity.key != authorized.identity.key ||
            reopened.identity.mountId != authorized.identity.mountId
        ) {
            reopened.close()
            throw IOException("authorized descriptor identity changed while reopening")
        }
        return reopened
    }

    /** Creates an unnamed inode, so every failure before [linkTemporaryAt] is residue-free. */
    fun createTemporaryAt(parentFd: Int): LinuxDescriptor = openDescriptor(
        parentFd,
        ".",
        O_WRONLY or O_TMPFILE or O_CLOEXEC,
        OWNER_READ_WRITE,
        "create secure unnamed temporary file",
    )

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
                libc.read(descriptor.fd, buffer, NativeLong(BUFFER_BYTES.toLong())).toLong()
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

    fun extendedAttributeNames(descriptor: LinuxDescriptor): List<String> {
        val path = descriptorPath(descriptor.fd).toString()
        val required = retryOnInterrupted("inspect filesystem metadata") {
            libc.listxattr(path, null, NativeLong(0)).toLong()
        }
        if (required < 0L) throw syscallFailure("inspect filesystem metadata")
        if (required == 0L) return emptyList()
        if (required > MAXIMUM_XATTR_NAME_BYTES) {
            throw IOException("filesystem metadata list exceeds the broker limit")
        }
        val names = Memory(required)
        val actual = retryOnInterrupted("inspect filesystem metadata") {
            libc.listxattr(path, names, NativeLong(required)).toLong()
        }
        if (actual < 0L) throw syscallFailure("inspect filesystem metadata")
        return names.getByteArray(0, actual.toInt())
            .split(0)
            .filter { it.isNotEmpty() }
            .map { bytes -> bytes.toByteArray().toString(Charsets.UTF_8) }
    }

    fun renameNoReplace(parentFd: Int, from: String, to: String) {
        renameAt2(parentFd, from, parentFd, to, RENAME_NOREPLACE)
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

    fun identity(fd: Int): LinuxFileIdentity {
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

    private fun close(fd: Int) {
        while (libc.close(fd) != 0 && Native.getLastError() == EINTR) {
            // POSIX leaves close-after-EINTR semantics implementation-specific. Linux closes the descriptor.
            return
        }
    }

    private fun descriptorPath(fd: Int): Path = PROCESS_FD_DIRECTORY.resolve(fd.toString())

    private fun descriptorMountId(fd: Int): Long {
        val prefix = "mnt_id:\t"
        val line = Files.readAllLines(PROCESS_FD_INFO_DIRECTORY.resolve(fd.toString()))
            .firstOrNull { it.startsWith(prefix) }
            ?: throw IOException("descriptor mount identity is unavailable")
        return line.removePrefix(prefix).trim().toLongOrNull()
            ?: throw IOException("descriptor mount identity is invalid")
    }

    private interface LibC : Library {
        fun openat(directoryFd: Int, path: String, flags: Int, mode: Int): Int
        fun close(fd: Int): Int
        fun read(fd: Int, buffer: Pointer, count: NativeLong): NativeLong
        fun write(fd: Int, buffer: Pointer, count: NativeLong): NativeLong
        fun fsync(fd: Int): Int
        fun fchmod(fd: Int, mode: Int): Int
        fun linkat(oldDirectoryFd: Int, oldPath: String, newDirectoryFd: Int, newPath: String, flags: Int): Int
        fun renameat2(oldDirectoryFd: Int, oldPath: String, newDirectoryFd: Int, newPath: String, flags: Int): Int
        fun unlinkat(directoryFd: Int, path: String, flags: Int): Int
        fun listxattr(path: String, list: Pointer?, size: NativeLong): NativeLong
    }

    private const val AT_FDCWD = -100
    private const val O_RDONLY = 0
    private const val O_WRONLY = 1
    private const val O_NONBLOCK = 0x800
    private const val O_DIRECTORY = 0x10000
    private const val O_NOFOLLOW = 0x20000
    private const val O_CLOEXEC = 0x80000
    private const val O_PATH = 0x200000
    private const val O_TMPFILE = 0x410000
    private const val OWNER_READ_WRITE = 0x180 // 0600
    private const val AT_EMPTY_PATH = 0x1000
    private const val RENAME_NOREPLACE = 1
    private const val RENAME_EXCHANGE = 2
    private const val EINTR = 4
    internal const val ENOENT = 2
    internal const val EEXIST = 17
    internal const val ENOTDIR = 20
    internal const val ELOOP = 40
    private const val BUFFER_BYTES = 16 * 1024
    private const val MAXIMUM_XATTR_NAME_BYTES = 1024L * 1024L
    private val PROCESS_FD_DIRECTORY = Path.of("/proc/self/fd")
    private val PROCESS_FD_INFO_DIRECTORY = Path.of("/proc/self/fdinfo")
    private val NULL_DEVICE = Path.of("/dev/null")
    private val SUPPORTED_ARCHITECTURES = setOf("amd64", "x86_64", "aarch64")
}

internal data class LinuxFileKey(val device: Long, val inode: Long)

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
