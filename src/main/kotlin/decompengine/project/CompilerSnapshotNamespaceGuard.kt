package decompengine.project

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Platform
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/**
 * Fail-closed mutation history for the entire compiler snapshot, not just manifest names.
 * Install before inventory/pinning and retain through object/log capture. An added then removed
 * header, shadow header or precompiled sidecar invalidates the attempt even if both inventories
 * match. This supplements, NEVER replaces, the per-input kernel leases/byte authentication.
 *
 * One nonblocking CLOEXEC inotify descriptor serves the bounded directory population. Watches
 * are installed top-down, including selected entries in all ancestors: changing a path while a
 * descendant watch is being installed is therefore itself recorded. No background dispatcher or
 * asynchronous WatchService queue can race the final synchronous kernel-queue drain.
 */
internal class CompilerSnapshotNamespaceGuard private constructor(private val descriptor: Int) : AutoCloseable {
    // null means every child name; ancestor watches select only the next path component.
    private val watches = mutableMapOf<Int, ByteArray?>()
    private val identities = linkedMapOf<Path, Map<String, Any>>()
    private var failed = false
    private var closed = false

    fun requireUnchanged() {
        check(!closed && !failed) { "module compiler namespace guard is unavailable" }
        try {
            // Authenticate directory identities too; watches follow inodes, not path strings.
            identities.forEach { (path, expected) -> require(identity(path) == expected) {
                "module compiler namespace directory changed"
            } }
            Memory(READ_BYTES.toLong()).use { buffer ->
                var reads = 0
                while (true) {
                    require(++reads <= MAXIMUM_READS) { "module compiler namespace event budget exceeded" }
                    val count = libc.read(descriptor, buffer, NativeLong(READ_BYTES.toLong())).toLong()
                    val error = if (count < 0) Native.getLastError() else 0
                    when {
                        count > 0 -> {
                            require(count <= READ_BYTES) { "invalid module compiler namespace event read" }
                            inspect(buffer, count.toInt())
                        }
                        count < 0 && error == EAGAIN -> return
                        count < 0 && error == EINTR -> continue
                        else -> error("module compiler namespace monitor failed (errno=$error)")
                    }
                }
            }
        } catch (failure: Throwable) {
            failed = true
            throw failure
        }
    }

    private fun inspect(buffer: Memory, count: Int) {
        var offset = 0
        while (offset < count) {
            require(count - offset >= HEADER_BYTES) { "truncated module compiler namespace event" }
            val watch = buffer.getInt(offset.toLong())
            val mask = buffer.getInt((offset + 4).toLong())
            val length = buffer.getInt((offset + 12).toLong())
            require(length in 0..(count - offset - HEADER_BYTES)) { "invalid module compiler namespace event length" }
            require(watch >= 0 && mask and (IN_Q_OVERFLOW or IN_IGNORED or IN_UNMOUNT) == 0 && watches.containsKey(watch)) {
                "module compiler namespace mutation history was lost"
            }
            val selected = watches[watch]
            // A nameless event concerns the watched directory itself and always invalidates it.
            require(length > 0 && selected != null) { "module compiler snapshot namespace mutated" }
            val padded = buffer.getByteArray((offset + HEADER_BYTES).toLong(), length)
            val end = padded.indexOf(0)
            require(end >= 0) { "unterminated module compiler namespace event name" }
            require(!padded.copyOf(end).contentEquals(selected)) { "module compiler snapshot ancestor mutated" }
            offset += HEADER_BYTES + length
        }
    }

    private fun watch(path: Path, selected: ByteArray?) {
        require(Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) && path.toRealPath() == path) {
            "module compiler namespace directory is not canonical"
        }
        val before = identity(path)
        val watch = libc.inotify_add_watch(descriptor, path.toString(), MUTATION_MASK or IN_ONLYDIR or IN_DONT_FOLLOW)
        require(watch >= 0 && !watches.containsKey(watch)) { "cannot watch module compiler namespace (errno=${Native.getLastError()})" }
        watches[watch] = selected
        require(identity(path) == before) { "module compiler namespace changed while registering watch" }
        identities[path] = before
    }

    override fun close() {
        if (!closed) {
            closed = true
            libc.close(descriptor)
        }
    }

    companion object {
        // Same directory census ceiling as the worker inventory; one FD, not one per directory.
        private const val MAXIMUM_ENTRIES = 4096 * 4
        private const val READ_BYTES = 64 * 1024
        private const val MAXIMUM_READS = 16
        private const val HEADER_BYTES = 16
        private const val EAGAIN = 11
        private const val EINTR = 4
        private const val IN_Q_OVERFLOW = 0x4000
        private const val IN_IGNORED = 0x8000
        private const val IN_UNMOUNT = 0x2000
        private const val IN_ONLYDIR = 0x01000000
        private const val IN_DONT_FOLLOW = 0x02000000
        // MODIFY, ATTRIB, CLOSE_WRITE, MOVED_FROM/TO, CREATE, DELETE, DELETE_SELF, MOVE_SELF.
        private const val MUTATION_MASK = 0x00000fce
        private val libc: NamespaceLibC by lazy { Native.load(Platform.C_LIBRARY_NAME, NamespaceLibC::class.java) }

        fun open(root: Path): CompilerSnapshotNamespaceGuard {
            require(System.getProperty("os.name") == "Linux" && root.isAbsolute && root.normalize() == root && root.parent != null) {
                "module compiler namespace guard requires a canonical Linux snapshot"
            }
            require(Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) && root.toRealPath() == root) {
                "module compiler snapshot root is not a canonical directory"
            }
            val descriptor = libc.inotify_init1(0x800 or 0x80000) // O_NONBLOCK | O_CLOEXEC
            require(descriptor >= 0) { "cannot open module compiler namespace monitor (errno=${Native.getLastError()})" }
            val guard = CompilerSnapshotNamespaceGuard(descriptor)
            try {
                var ancestor = root.root
                root.forEach { component ->
                    guard.watch(ancestor, component.toString().toByteArray(Charsets.UTF_8))
                    ancestor = ancestor.resolve(component)
                }
                var entries = 0
                // Files.walk is depth-first; a directory is watched before its children are visited.
                Files.walk(root, 32).use { paths -> paths.forEach { path ->
                    require(++entries <= MAXIMUM_ENTRIES) { "module compiler namespace inventory exceeds its bound" }
                    if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                        require(root.relativize(path).nameCount < 32) { "module compiler namespace exceeds its depth bound" }
                        guard.watch(path, null)
                    }
                } }
                guard.requireUnchanged()
                return guard
            } catch (failure: Throwable) {
                guard.close()
                throw failure
            }
        }

        private fun identity(path: Path): Map<String, Any> =
            // Do not compare ancestor ctime/mtime: unrelated sibling output creation is legitimate.
            Files.readAttributes(path, "unix:dev,ino,mode,uid,gid", LinkOption.NOFOLLOW_LINKS)

        private interface NamespaceLibC : Library {
            fun inotify_init1(flags: Int): Int
            fun inotify_add_watch(descriptor: Int, path: String, mask: Int): Int
            fun read(descriptor: Int, buffer: Memory, count: NativeLong): NativeLong
            fun close(descriptor: Int): Int
        }
    }
}
