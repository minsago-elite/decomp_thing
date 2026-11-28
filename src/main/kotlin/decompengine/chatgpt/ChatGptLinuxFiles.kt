package decompengine.chatgpt

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Platform
import com.sun.jna.Pointer
import java.nio.ByteOrder
import java.nio.file.Path
import java.util.UUID

/**
 * Linux LP64 little-endian x86-64/aarch64 only, libc statx required. No pathname fallback.
 * statx uses the fixed 256-byte Linux UAPI structure (linux/stat.h), not ABI-dependent struct stat.
 * Trusted ancestors are owned by root or geteuid(), without group/other write permission.
 * Same-effective-user and root attackers are outside this boundary. Syscall latency is not bounded.
 */
internal class ChatGptLinuxFiles(
    private val operation: ChatGptStoreOperation,
    private val hook: (Stage) -> Unit = {},
) {
    internal enum class Stage {
        DIRECTORY_OPENED, LOCK_OPENED, LOCK_ACQUIRED, DATA_OPENED, READ_CHUNK, READ_COMPLETE,
        TEMP_CREATED, WRITE_CHUNK, BEFORE_FILE_SYNC, AFTER_FILE_SYNC, BEFORE_RENAME,
        AFTER_RENAME, BEFORE_DIRECTORY_SYNC, AFTER_DIRECTORY_SYNC, BEFORE_TEMP_CLEANUP,
    }
    internal data class Identity(val deviceMajor: Int, val deviceMinor: Int, val mount: Long, val inode: Long,
        val mode: Int, val uid: Long, val links: Long, val size: Long)

    private val libc: LibC = load()
    private val openFlags = openFlagsForArchitecture(System.getProperty("os.arch"))
    private val FILE_FLAGS = openFlags.first
    private val DIRECTORY_FLAGS = openFlags.second
    private val uid = Integer.toUnsignedLong(libc.geteuid())
    private val descriptors = mutableListOf<Int>()
    private val chain = mutableListOf<Triple<Int, String, Int>>()
    private var directory = -1
    private var lock = -1

    private fun stage(stage: Stage) { operation.check(); hook(stage); operation.check() }
    private fun fail(): Nothing = throw StoreFailure("ChatGPT private filesystem validation failed")
    private fun syscall(result: Int): Int { if (result < 0) fail(); return result }
    private fun own(fd: Int): Int = syscall(fd).also { descriptors.add(it) }

    fun open(path: Path) {
        operation.check()
        require(path.isAbsolute && path.nameCount > 0)
        var parent = own(libc.openat(AT_FDCWD, "/", DIRECTORY_FLAGS, 0))
        validateDirectory(identity(parent), uid, false)
        for ((index, part) in path.withIndex()) {
            operation.check()
            val name = part.toString()
            require(name != "." && name != ".." && '\u0000' !in name)
            var fd = libc.openat(parent, name, DIRECTORY_FLAGS, 0)
            if (fd < 0 && Native.getLastError() == ENOENT) {
                operation.check()
                if (libc.mkdirat(parent, name, 0x1c0) < 0 && Native.getLastError() != EEXIST) fail()
                operation.check()
                syscall(libc.fsync(parent))
                fd = libc.openat(parent, name, DIRECTORY_FLAGS, 0)
            }
            val child = own(fd)
            validateDirectory(identity(child), uid, index == path.nameCount - 1)
            sameEntry(parent, name, child)
            chain.add(Triple(parent, name, child))
            parent = child
        }
        directory = parent
        stage(Stage.DIRECTORY_OPENED)
        verifyChain()
        operation.check()
        lock = own(libc.openat(directory, LOCK, FILE_FLAGS or O_RDWR or O_CREAT, 0x180))
        validateFile(identity(lock), uid)
        stage(Stage.LOCK_OPENED)
        while (true) {
            operation.check()
            if (libc.flock(lock, LOCK_EX or LOCK_NB) == 0) break
            if (Native.getLastError() !in setOf(EAGAIN, EINTR)) fail()
            operation.pause()
        }
        stage(Stage.LOCK_ACQUIRED)
        verify()
        operation.check()
        syscall(libc.fsync(directory)) // also persists a newly created stable lock entry
    }

    fun verify() {
        operation.check()
        verifyChain()
        validateFile(identity(lock), uid)
        sameEntry(directory, LOCK, lock)
    }

    private fun verifyChain() {
        operation.check()
        for ((index, entry) in chain.withIndex()) {
            operation.check()
            validateDirectory(identity(entry.first), uid, false)
            validateDirectory(identity(entry.third), uid, index == chain.lastIndex)
            sameEntry(entry.first, entry.second, entry.third)
        }
    }

    fun read(maxBytes: Int): ByteArray? {
        verify()
        operation.check()
        val fd = libc.openat(directory, DATA, FILE_FLAGS, 0)
        if (fd < 0) { if (Native.getLastError() == ENOENT) return null; fail() }
        return descriptor(fd) {
            val before = identity(fd)
            validateFile(before, uid)
            sameEntry(directory, DATA, fd)
            if (before.size !in 1..maxBytes.toLong()) throw StoreInputFailure("ChatGPT credential document size is invalid")
            stage(Stage.DATA_OPENED)
            val bytes = ByteArray(before.size.toInt())
            Memory(CHUNK.toLong()).use { buffer ->
                var position = 0
                while (position < bytes.size) {
                    operation.check()
                    val count = libc.read(fd, buffer, NativeLong(minOf(CHUNK, bytes.size - position).toLong())).toLong()
                    if (count <= 0 || count > minOf(CHUNK, bytes.size - position)) fail()
                    buffer.read(0, bytes, position, count.toInt())
                    position += count.toInt()
                    stage(Stage.READ_CHUNK)
                }
                operation.check()
                if (libc.read(fd, buffer, NativeLong(1)).toLong() != 0L) fail()
            }
            stage(Stage.READ_COMPLETE)
            val after = identity(fd)
            validateFile(after, uid)
            if (before != after) fail()
            sameEntry(directory, DATA, fd)
            verify()
            bytes
        }
    }

    fun write(bytes: ByteArray) {
        verify()
        val name = ".credentials-${UUID.randomUUID()}.tmp"
        operation.check()
        val fd = syscall(libc.openat(directory, name, FILE_FLAGS or O_WRONLY or O_CREAT or O_EXCL, 0x180))
        var renamed = false
        var createdIdentity: Identity? = null
        var primary: Throwable? = null
        try {
            descriptor(fd) {
                createdIdentity = identity(fd)
                validateFile(requireNotNull(createdIdentity), uid)
                sameEntry(directory, name, fd)
                stage(Stage.TEMP_CREATED)
                Memory(CHUNK.toLong()).use { buffer ->
                    var position = 0
                    while (position < bytes.size) {
                        operation.check()
                        val amount = minOf(CHUNK, bytes.size - position)
                        buffer.write(0, bytes, position, amount)
                        val count = libc.write(fd, buffer, NativeLong(amount.toLong())).toLong()
                        if (count <= 0 || count > amount) fail()
                        position += count.toInt()
                        stage(Stage.WRITE_CHUNK)
                    }
                }
                stage(Stage.BEFORE_FILE_SYNC)
                syscall(libc.fsync(fd))
                stage(Stage.AFTER_FILE_SYNC)
                verify()
                validateFile(identity(fd), uid)
                if (identity(fd).size != bytes.size.toLong()) fail()
                sameEntry(directory, name, fd)
                verifyExistingData()
                stage(Stage.BEFORE_RENAME)
                verify() // test hooks cannot bypass descriptor/name checks
                sameEntry(directory, name, fd)
                validateFile(identity(fd), uid)
                verifyExistingData()
                syscall(libc.renameat(directory, name, directory, DATA))
                renamed = true
                stage(Stage.AFTER_RENAME)
                validateFile(identity(fd), uid)
                sameEntry(directory, DATA, fd)
                stage(Stage.BEFORE_DIRECTORY_SYNC)
                syscall(libc.fsync(directory))
                stage(Stage.AFTER_DIRECTORY_SYNC)
                verify()
                sameEntry(directory, DATA, fd)
            }
        } catch (t: Throwable) { primary = t; throw t }
        finally {
            if (!renamed) {
                // Cleanup must run even when the operation budget is exhausted. Preserve primary failure.
                try {
                    hook(Stage.BEFORE_TEMP_CLEANUP)
                    val created = createdIdentity ?: fail()
                    if (!sameInode(stat(directory, name, AT_SYMLINK_NOFOLLOW), created)) fail()
                    if (libc.unlinkat(directory, name, 0) < 0 && Native.getLastError() != ENOENT) fail()
                } catch (t: Throwable) { if (primary == null) throw t }
            }
        }
    }

    private fun verifyExistingData() {
        operation.check()
        val fd = libc.openat(directory, DATA, FILE_FLAGS, 0)
        if (fd < 0) { if (Native.getLastError() == ENOENT) return; fail() }
        descriptor(fd) { validateFile(identity(fd), uid); sameEntry(directory, DATA, fd) }
    }

    private fun sameEntry(parent: Int, name: String, fd: Int) {
        val entry = stat(parent, name, AT_SYMLINK_NOFOLLOW)
        val opened = identity(fd)
        if (!sameInode(entry, opened)) fail()
    }

    private fun sameInode(a: Identity, b: Identity) = a.deviceMajor == b.deviceMajor &&
        a.deviceMinor == b.deviceMinor && a.mount == b.mount && a.inode == b.inode

    private fun identity(fd: Int) = stat(fd, "", AT_EMPTY_PATH or AT_SYMLINK_NOFOLLOW)
    private fun stat(fd: Int, name: String, flags: Int): Identity {
        Memory(256).use { buffer ->
            buffer.clear()
            syscall(libc.statx(fd, name, flags, STATX_MASK, buffer))
            if (buffer.getInt(0) and STATX_MASK != STATX_MASK) fail()
            return Identity(buffer.getInt(136), buffer.getInt(140), buffer.getLong(144), buffer.getLong(32),
                buffer.getShort(28).toInt() and 0xffff, Integer.toUnsignedLong(buffer.getInt(20)),
                Integer.toUnsignedLong(buffer.getInt(16)), buffer.getLong(40))
        }
    }

    private inline fun <T> descriptor(fd: Int, action: () -> T): T {
        var primary: Throwable? = null
        try { return action() } catch (t: Throwable) { primary = t; throw t }
        finally { if (libc.close(fd) != 0 && primary == null) fail() }
    }

    /** Close once in reverse acquisition order; Linux close must never be retried after EINTR. */
    fun close() {
        var failed = false
        for (fd in descriptors.asReversed()) if (libc.close(fd) != 0) failed = true
        descriptors.clear()
        if (failed) throw StoreFailure("ChatGPT private filesystem cleanup failed")
    }

    private interface LibC : Library {
        fun geteuid(): Int
        fun openat(directory: Int, name: String, flags: Int, mode: Int): Int
        fun mkdirat(directory: Int, name: String, mode: Int): Int
        fun statx(directory: Int, name: String, flags: Int, mask: Int, buffer: Pointer): Int
        fun flock(fd: Int, operation: Int): Int
        fun read(fd: Int, buffer: Pointer, size: NativeLong): NativeLong
        fun write(fd: Int, buffer: Pointer, size: NativeLong): NativeLong
        fun fsync(fd: Int): Int
        fun renameat(from: Int, name: String, to: Int, replacement: String): Int
        fun unlinkat(directory: Int, name: String, flags: Int): Int
        fun close(fd: Int): Int
    }

    companion object {
        const val DATA = "credentials-v1.json"
        const val LOCK = "credentials-v1.lock"
        private const val CHUNK = 16384
        private const val AT_FDCWD = -100
        private const val AT_EMPTY_PATH = 0x1000
        private const val AT_SYMLINK_NOFOLLOW = 0x100
        private const val STATX_MASK = 0x130f // TYPE | MODE | NLINK | UID | INO | SIZE | MNT_ID
        private const val O_WRONLY = 1
        private const val O_RDWR = 2
        private const val O_CREAT = 0x40
        private const val O_EXCL = 0x80
        private const val LOCK_EX = 2
        private const val LOCK_NB = 4
        private const val EAGAIN = 11
        private const val EINTR = 4
        private const val ENOENT = 2
        private const val EEXIST = 17

        /** Linux UAPI arch/arm64/include/uapi/asm/fcntl.h overrides the generic flags. */
        internal fun openFlagsForArchitecture(architecture: String): Pair<Int, Int> {
            val (noFollow, directory) = when (architecture) {
                "amd64", "x86_64" -> 0x20000 to 0x10000
                "aarch64" -> 0x8000 to 0x4000
                else -> throw StoreFailure("ChatGPT private filesystem is unsupported")
            }
            val file = noFollow or 0x80000 or 0x800 // NOFOLLOW | CLOEXEC | NONBLOCK
            return file to (file or directory)
        }

        internal fun validateDirectory(a: Identity, uid: Long, privateDirectory: Boolean) {
            require(a.mode and 0xf000 == 0x4000 && a.uid in setOf(0L, uid))
            require(if (privateDirectory) a.uid == uid && a.mode and 0xfff == 0x1c0 else a.mode and 0x12 == 0)
        }
        internal fun validateFile(a: Identity, uid: Long) {
            require(a.mode and 0xf000 == 0x8000 && a.mode and 0xfff == 0x180 && a.uid == uid && a.links == 1L)
        }
        private fun load(): LibC {
            if (!Platform.isLinux() || Native.POINTER_SIZE != 8 || Native.LONG_SIZE != 8 ||
                ByteOrder.nativeOrder() != ByteOrder.LITTLE_ENDIAN ||
                System.getProperty("os.arch") !in setOf("amd64", "x86_64", "aarch64"))
                throw StoreFailure("ChatGPT private filesystem is unsupported")
            return Native.load(Platform.C_LIBRARY_NAME, LibC::class.java, mapOf(Library.OPTION_STRING_ENCODING to "UTF-8"))
        }
    }
}
