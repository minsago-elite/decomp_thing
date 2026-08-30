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
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes

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
        cancellationCheck: () -> Unit = {},
    ): Long {
        require(maximumBytes >= 0) { "copy byte budget must not be negative" }
        openReadableFrom(authorized).use { readable ->
            val buffer = Memory(BUFFER_BYTES.toLong())
            var total = 0L
            while (true) {
                cancellationCheck()
                val count = retryOnInterrupted("copy authenticated runtime file") {
                    libc.read(readable.fd, buffer, NativeLong(BUFFER_BYTES.toLong())).toLong()
                }
                if (count == 0L) return total
                if (count < 0L) throw syscallFailure("copy authenticated runtime file")
                total = Math.addExact(total, count)
                if (total > maximumBytes) throw LinuxResourceLimitException()
                output.write(buffer.getByteArray(0, count.toInt()))
                cancellationCheck()
            }
        }
    }

    /** Copies between two already-open file descriptions without resolving a destination path. */
    fun copyReadableTo(
        authorized: LinuxDescriptor,
        destination: LinuxDescriptor,
        maximumBytes: Long,
        cancellationCheck: () -> Unit = {},
    ): Long {
        require(maximumBytes >= 0) { "copy byte budget must not be negative" }
        openReadableFrom(authorized).use { readable ->
            val buffer = Memory(BUFFER_BYTES.toLong())
            var total = 0L
            while (true) {
                cancellationCheck()
                val count = retryOnInterrupted("copy authenticated runtime file") {
                    libc.read(readable.fd, buffer, NativeLong(BUFFER_BYTES.toLong())).toLong()
                }
                if (count == 0L) {
                    cancellationCheck()
                    call("synchronize private runtime file") { libc.fsync(destination.fd) }
                    cancellationCheck()
                    return total
                }
                if (count < 0L) throw syscallFailure("copy authenticated runtime file")
                total = Math.addExact(total, count)
                if (total > maximumBytes) throw LinuxResourceLimitException()
                var offset = 0L
                while (offset < count) {
                    val written = retryOnInterrupted("write private runtime file") {
                        libc.write(
                            destination.fd,
                            buffer.share(offset),
                            NativeLong(count - offset),
                        ).toLong()
                    }
                    if (written <= 0L) throw syscallFailure("write private runtime file")
                    offset += written
                    cancellationCheck()
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
    ): LinuxDescriptor = try {
        val openedBefore = identity(opened.fd)
        requireRegularIdentity(opened.identity, openedBefore, "authenticate $description")
        val named = openPathAtOrNull(parentFd, name)
            ?: throw IOException("$description disappeared while it was authenticated")
        named.use {
            val namedIdentity = identity(named.fd)
            val openedAfter = identity(opened.fd)
            requireRegularIdentity(openedBefore, namedIdentity, "authenticate $description")
            if (!sameDescriptorObject(namedIdentity, openedAfter)) {
                throw IOException("$description identity changed while it was authenticated")
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
        fun openat(directoryFd: Int, path: String, flags: Int, mode: Int): Int
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
        fun listxattr(path: String, list: Pointer?, size: NativeLong): NativeLong
        fun getxattr(path: String, name: String, value: Pointer?, size: NativeLong): NativeLong
        fun fstatvfs(fd: Int, statistics: LinuxStatVfs): Int
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
    private const val AT_REMOVEDIR = 0x200
    private const val RENAME_NOREPLACE = 1
    private const val RENAME_EXCHANGE = 2
    private const val EINTR = 4
    private const val EWOULDBLOCK = 11
    private const val LOCK_EX = 2
    private const val LOCK_NB = 4
    private const val LOCK_UN = 8
    internal const val ESRCH = 3
    private const val SIGTERM = 15
    private const val SIGKILL = 9
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
