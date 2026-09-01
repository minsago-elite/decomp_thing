package decompengine.oracle.fulltree

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Platform
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.io.InputStream
import java.lang.reflect.InvocationTargetException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileTime
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.util.EnumSet
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeControlException(message: String, cause: Throwable? = null) : IllegalArgumentException(message, cause)

/**
 * Explicit implementation bounds for the Kotlin/JVM full-tree control plane.
 *
 * Archive-index and DWARF-metadata byte budgets charge exact UTF-8 payload bytes plus a fixed
 * per-record allowance. They bound attacker-controlled materialization but are not a JVM
 * resident-set guarantee; object-layout overhead and the cooperating process remain outside that
 * model. XZ decoder memory and on-disk DWARF scratch have independent enforced limits.
 */
data class FullTreeControlLimits(
    val maximumScopeBytes: Int = 1024 * 1024,
    val maximumSourceLockBytes: Int = 4 * 1024 * 1024,
    val maximumArtifactManifestBytes: Int = 32 * 1024 * 1024,
    val maximumBuildRecordBytes: Int = 4 * 1024 * 1024,
    val maximumInventoryBytes: Int = 32 * 1024 * 1024,
    val maximumSourceInventoryBytes: Int = 32 * 1024 * 1024,
    val maximumRichArtifactBytes: Long = 1024L * 1024L * 1024L,
    val maximumSourceArchiveBytes: Long = 512L * 1024L * 1024L,
    val maximumExpandedArchiveBytes: Long = 8L * 1024L * 1024L * 1024L,
    val maximumArchiveMembers: Int = 200_000,
    val maximumArchiveMetadataBytes: Int = 1024 * 1024,
    val maximumArchiveEntryBytes: Long = 512L * 1024L * 1024L,
    val maximumArchivePathBytes: Int = 4096,
    val maximumArchiveComponentBytes: Int = 255,
    val maximumArchiveLinkBytes: Int = 255,
    val maximumArchiveIndexBytes: Long = 64L * 1024L * 1024L,
    val maximumArchiveSelectedBytes: Int = 1024 * 1024,
    val maximumXzDecoderMemoryKiB: Int = 256 * 1024,
    val maximumDwarfSectionBytes: Long = 4L * 1024L * 1024L * 1024L,
    val maximumDwarfScratchBytes: Long = 8L * 1024L * 1024L * 1024L,
    val maximumDwarfMetadataBytes: Long = 256L * 1024L * 1024L,
    val maximumDwarfAttributeBytes: Int = 16 * 1024 * 1024,
    val maximumDwarfParseSteps: Long = 100_000_000L,
    val maximumCompilationUnits: Int = 1_000_000,
    val maximumAbbreviationDeclarationsPerUnit: Int = 100_000,
    val maximumAbbreviationAttributesPerUnit: Int = 10_000,
    val maximumWorkers: Int = 32,
) {
    init {
        require(maximumScopeBytes in 1..64 * 1024 * 1024)
        require(maximumSourceLockBytes in 1..64 * 1024 * 1024)
        require(maximumArtifactManifestBytes in 1..64 * 1024 * 1024)
        require(maximumBuildRecordBytes in 1..64 * 1024 * 1024)
        require(maximumInventoryBytes in 1..64 * 1024 * 1024)
        require(maximumSourceInventoryBytes in 1..64 * 1024 * 1024)
        require(maximumRichArtifactBytes in 1L..1024L * 1024L * 1024L)
        require(maximumSourceArchiveBytes in 1L..512L * 1024L * 1024L)
        require(maximumExpandedArchiveBytes in 1L..8L * 1024L * 1024L * 1024L)
        require(maximumArchiveMembers in 1..200_000)
        require(maximumArchiveMetadataBytes in 1..1024 * 1024)
        require(maximumArchiveEntryBytes in 1L..512L * 1024L * 1024L)
        require(maximumArchivePathBytes in 1..4096)
        require(maximumArchiveComponentBytes in 1..255)
        require(maximumArchiveLinkBytes in 1..255)
        require(maximumArchiveIndexBytes in 1L..64L * 1024L * 1024L)
        require(maximumArchiveSelectedBytes in 0..1024 * 1024)
        require(maximumXzDecoderMemoryKiB in 1..256 * 1024)
        require(maximumDwarfSectionBytes in 1L..8L * 1024L * 1024L * 1024L)
        require(maximumDwarfScratchBytes in 1L..16L * 1024L * 1024L * 1024L)
        require(maximumDwarfMetadataBytes in 1L..1024L * 1024L * 1024L)
        require(maximumDwarfAttributeBytes in 1..64 * 1024 * 1024)
        require(maximumDwarfParseSteps in 1L..1_000_000_000L)
        require(maximumCompilationUnits in 1..1_000_000)
        require(maximumAbbreviationDeclarationsPerUnit in 1..1_000_000)
        require(maximumAbbreviationAttributesPerUnit in 1..100_000)
        require(maximumWorkers in 1..32)
    }
}

internal val FULL_TREE_CODE_POINT_ORDER: Comparator<String> = Comparator { left, right ->
    var leftOffset = 0
    var rightOffset = 0
    while (leftOffset < left.length && rightOffset < right.length) {
        val leftPoint = Character.codePointAt(left, leftOffset)
        val rightPoint = Character.codePointAt(right, rightOffset)
        if (leftPoint != rightPoint) return@Comparator leftPoint.compareTo(rightPoint)
        leftOffset += Character.charCount(leftPoint)
        rightOffset += Character.charCount(rightPoint)
    }
    (left.length - leftOffset).compareTo(right.length - rightOffset)
}

internal fun readCanonicalControlObject(
    path: Path,
    maximumBytes: Int,
    label: String,
    schemaName: String? = null,
): Pair<JsonObject, ByteArray> {
    val bytes = try {
        OracleArtifacts.read(path, OracleArtifactLimits(maximumBytes)).bytes
    } catch (failure: Exception) {
        throw FullTreeControlException("cannot read authenticated $label", failure)
    }
    if (bytes.isEmpty()) throw FullTreeControlException("$label must not be empty")
    val document = try {
        OracleJson.parseCanonical(bytes, controlJsonLimits(maximumBytes)) as? JsonObject
            ?: throw FullTreeControlException("$label root must be an object")
    } catch (failure: FullTreeControlException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeControlException("$label is not strict canonical JSON", failure)
    }
    if (schemaName != null) {
        try {
            OracleSchemas.validate(schemaName, document)
        } catch (failure: Exception) {
            throw FullTreeControlException("$label fails its bundled schema", failure)
        }
    }
    return document to bytes
}

internal fun snapshotControlObject(
    value: JsonObject,
    maximumBytes: Int,
    label: String,
    schemaName: String? = null,
): Pair<JsonObject, ByteArray> {
    val bytes = try {
        OracleJson.canonicalBytes(value, controlJsonLimits(maximumBytes))
    } catch (failure: Exception) {
        throw FullTreeControlException("$label exceeds strict JSON limits", failure)
    }
    val snapshot = try {
        OracleJson.parseCanonical(bytes, controlJsonLimits(maximumBytes)) as JsonObject
    } catch (failure: Exception) {
        throw FullTreeControlException("$label cannot be snapshotted as strict canonical JSON", failure)
    }
    if (schemaName != null) {
        try {
            OracleSchemas.validate(schemaName, snapshot)
        } catch (failure: Exception) {
            throw FullTreeControlException("$label fails its bundled schema", failure)
        }
    }
    return snapshot to bytes
}

internal fun controlJsonLimits(maximumBytes: Int): StrictJsonLimits = StrictJsonLimits(
    maximumInputBytes = maximumBytes,
    maximumCanonicalBytes = maximumBytes,
    maximumDepth = 128,
    maximumNodes = 1_000_000,
    maximumStringBytes = minOf(maximumBytes, 1024 * 1024),
    maximumTotalStringBytes = maximumBytes,
)

internal fun publishCanonicalControl(
    path: Path,
    document: JsonObject,
    maximumBytes: Int,
): ByteArray {
    val bytes = try {
        OracleJson.canonicalBytes(document, controlJsonLimits(maximumBytes))
    } catch (failure: Exception) {
        throw FullTreeControlException("control-plane output exceeds its canonical byte limit", failure)
    }
    try {
        OracleArtifacts.publishAtomically(path, bytes, OracleArtifactLimits(maximumBytes))
    } catch (failure: Exception) {
        throw FullTreeControlException("cannot atomically publish control-plane output", failure)
    }
    return bytes
}

internal fun requireDistinctControlOutput(
    output: Path,
    vararg inputs: Pair<String, Path>,
) {
    val normalizedOutput = output.toAbsolutePath().normalize()
    inputs.forEach { (label, input) ->
        if (normalizedOutput == input.toAbsolutePath().normalize()) {
            throw FullTreeControlException("control-plane output must not replace its $label input")
        }
    }
}

/** Stable bounded access to a descriptor-selected authenticated input. */
internal class StableControlFile private constructor(
    private val authenticatedSize: Long,
    private val maximumBytes: Long,
    private val label: String,
    private val parentChain: StableControlParentChain,
    private val name: String,
    private val readable: LinuxDescriptor,
    private val parentIdentity: LinuxFileIdentity,
    private val selectedIdentity: LinuxFileIdentity,
    private val readableIdentity: LinuxFileIdentity,
    private val lastModifiedTime: FileTime,
    private val selectedChangeTime: FileTime,
    private val mutationWatch: MutationRegistration,
    private val readLease: ReadLeaseRegistration,
) : AutoCloseable {
    private val initialSha256: String
    private var closed = false

    val size: Long
        get() = authenticatedSize

    init {
        requireCurrentMetadata("$label initial selection")
        initialSha256 = digest({}, "$label initial authentication")
        requireCurrentMetadata("$label initial authentication")
    }

    @Synchronized
    fun readAt(position: Long, destination: ByteArray, offset: Int, length: Int): Int {
        if (offset < 0 || length < 0 || offset > destination.size - length) {
            throw IndexOutOfBoundsException()
        }
        if (position < 0L || position > size) {
            throw FullTreeControlException("large control input read position exceeds its authenticated file")
        }
        if (length == 0) return 0
        if (position == size) return -1
        val requested = minOf(
            length.toLong(),
            size - position,
            STABLE_CONTROL_BUFFER_BYTES.toLong(),
        ).toInt()
        val read = readDescriptorAt(position, destination, offset, requested)
        if (read <= 0) throw FullTreeControlException("large control input ended during positional reading")
        return read
    }

    @Synchronized
    fun sha256(
        checkpoint: (String) -> Unit = {},
        label: String = "large control input",
    ): String = digest(checkpoint, label)

    private fun digest(
        checkpoint: (String) -> Unit,
        label: String,
    ): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(STABLE_CONTROL_BUFFER_BYTES)
        var position = 0L
        while (position < size) {
            val requested = minOf(buffer.size.toLong(), size - position).toInt()
            val read = readDescriptorAt(position, buffer, 0, requested)
            if (read <= 0) throw FullTreeControlException("large control input ended while hashing")
            digest.update(buffer, 0, read)
            position = Math.addExact(position, read.toLong())
            checkpoint("while hashing $label")
            mutationWatch.requireQuiet(label)
        }
        checkpoint("after hashing $label")
        mutationWatch.requireQuiet(label)
        return digest.digest().hex()
    }

    @Synchronized
    fun readExactly(offset: Long, length: Int, label: String): ByteArray {
        if (offset < 0L || length < 0 || offset > size - length.toLong()) {
            throw FullTreeControlException("$label range exceeds its authenticated input")
        }
        val result = ByteArray(length)
        var position = offset
        var destinationOffset = 0
        while (destinationOffset < result.size) {
            val read = readDescriptorAt(position, result, destinationOffset, result.size - destinationOffset)
            if (read <= 0) throw FullTreeControlException("$label ended during a bounded read")
            position = Math.addExact(position, read.toLong())
            destinationOffset += read
        }
        return result
    }

    @Synchronized
    fun slice(offset: Long = 0L, length: Long = size): InputStream {
        if (offset < 0L || length < 0L || offset > size - length) {
            throw FullTreeControlException("large control input slice exceeds its authenticated file")
        }
        return object : InputStream() {
            private var position = offset
            private var remaining = length

            override fun read(): Int {
                val single = ByteArray(1)
                return if (read(single, 0, 1) < 0) -1 else single[0].toInt() and 0xff
            }

            override fun read(bytes: ByteArray, offsetInArray: Int, lengthInArray: Int): Int {
                if (offsetInArray < 0 || lengthInArray < 0 || offsetInArray > bytes.size - lengthInArray) {
                    throw IndexOutOfBoundsException()
                }
                if (lengthInArray == 0) return 0
                if (remaining == 0L) return -1
                val requested = minOf(lengthInArray.toLong(), remaining).toInt()
                val read = this@StableControlFile.readAt(position, bytes, offsetInArray, requested)
                if (read <= 0) throw FullTreeControlException("large control input ended during streaming")
                position = Math.addExact(position, read.toLong())
                remaining -= read.toLong()
                return read
            }
        }
    }

    @Synchronized
    fun requireSingleLink(label: String) {
        check(!closed) { "stable control file is closed" }
        readLease.requireHeld(label)
        val current = readable.whileOpen(LinuxFilesystemSyscalls::identity)
        if (current.linkCount != 1 || selectedIdentity.linkCount != 1) {
            throw FullTreeControlException("$label must remain a single-link regular file")
        }
        requireCurrentMetadata(label)
    }

    @Synchronized
    fun verifyUnchanged(label: String) {
        requireCurrentMetadata("$label before terminal authentication")
        val terminalSha256 = digest({}, "$label terminal authentication")
        requireCurrentMetadata("$label after terminal authentication")
        if (terminalSha256 != initialSha256) {
            throw FullTreeControlException("$label changed bytes during use")
        }
    }

    private fun readDescriptorAt(position: Long, destination: ByteArray, offset: Int, length: Int): Int {
        check(!closed) { "stable control file is closed" }
        readLease.requireHeld(label)
        mutationWatch.requireQuiet(label)
        requireStableContentChangeTime(label)
        val requested = minOf(length, STABLE_CONTROL_BUFFER_BYTES)
        val bytes = PositionedReader.read(readable, position, requested)
        requireStableContentChangeTime(label)
        mutationWatch.requireQuiet(label)
        readLease.requireHeld(label)
        bytes.copyInto(destination, offset)
        return bytes.size
    }

    private fun requireStableContentChangeTime(label: String) {
        if (descriptorChangeTime(readable, label) != selectedChangeTime) {
            throw FullTreeControlException("$label changed inode ctime while descriptor-bound bytes were in use")
        }
    }

    private fun requireCurrentMetadata(description: String) {
        check(!closed) { "stable control file is closed" }
        readLease.requireHeld(description)
        mutationWatch.requireQuiet(description)
        val currentReadable = readable.whileOpen(LinuxFilesystemSyscalls::identity)
        if (!sameStableControlIdentity(selectedIdentity, currentReadable) ||
            !sameStableControlIdentity(readableIdentity, currentReadable)
        ) {
            throw FullTreeControlException("$description retained read descriptor changed identity or metadata")
        }
        requireStableControlFile(currentReadable, description)
        val currentParent = openCurrentParent(description)
        currentParent.use { parent ->
            val currentParentIdentity = parent.whileOpen(LinuxFilesystemSyscalls::identity)
            if (!sameStableControlParentIdentity(parentIdentity, currentParentIdentity)) {
                throw FullTreeControlException("$description parent path changed identity or metadata")
            }
            requireStableControlParent(currentParentIdentity, "$description parent")
            val named = try {
                parent.whileOpen { parentFd ->
                    LinuxFilesystemSyscalls.openRegularFileAtOrNull(parentFd, name)
                }
            } catch (failure: Exception) {
                throw FullTreeControlException("$description named file cannot be authenticated", failure)
            } ?: throw FullTreeControlException("$description named file disappeared")
            named.use {
                val namedIdentity = named.whileOpen(LinuxFilesystemSyscalls::identity)
                if (!sameStableControlIdentity(selectedIdentity, namedIdentity)) {
                    throw FullTreeControlException("$description named file changed identity or metadata")
                }
            }
        }
        val attributes = descriptorAttributes(readable, description)
        val currentChangeTime = descriptorChangeTime(readable, description)
        if (
            attributes.size() != size || attributes.size() !in 1L..maximumBytes ||
            attributes.lastModifiedTime() != lastModifiedTime || !attributes.isRegularFile ||
            attributes.isSymbolicLink || currentChangeTime != selectedChangeTime
        ) {
            throw FullTreeControlException("$description changed size, type, timestamps, or retained read state")
        }
        mutationWatch.requireQuiet(description)
        readLease.requireHeld(description)
    }

    private fun openCurrentParent(description: String): LinuxDescriptor {
        var current: LinuxDescriptor? = null
        try {
            val openedRoot = LinuxFilesystemSyscalls.openRoot(STABLE_CONTROL_FILESYSTEM_ROOT)
            current = openedRoot
            val currentRootIdentity = openedRoot.whileOpen(LinuxFilesystemSyscalls::identity)
            if (!sameStableControlParentIdentity(parentChain.rootIdentity, currentRootIdentity)) {
                throw FullTreeControlException("$description filesystem root changed identity or metadata")
            }
            parentChain.components.forEach { component ->
                val openedParent = checkNotNull(current)
                val openedChild = openedParent.whileOpen { parentFd ->
                    LinuxFilesystemSyscalls.openDirectoryAt(parentFd, component.name)
                }
                openedParent.close()
                current = openedChild
                val childIdentity = openedChild.whileOpen(LinuxFilesystemSyscalls::identity)
                if (!sameStableControlParentIdentity(component.identity, childIdentity)) {
                    throw FullTreeControlException(
                        "$description parent component ${component.name} changed identity or metadata",
                    )
                }
            }
            val result = checkNotNull(current)
            current = null
            return result
        } catch (failure: FullTreeControlException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeControlException("$description parent path cannot be authenticated", failure)
        } finally {
            current?.close()
        }
    }

    private fun descriptorAttributes(descriptor: LinuxDescriptor, label: String): BasicFileAttributes = try {
        descriptor.whileOpen { fd ->
            Files.readAttributes(
                LinuxFilesystemSyscalls.stableDescriptorPath(fd),
                BasicFileAttributes::class.java,
            )
        }
    } catch (failure: Exception) {
        throw FullTreeControlException("$label descriptor attributes are unavailable", failure)
    }

    private fun descriptorChangeTime(descriptor: LinuxDescriptor, label: String): FileTime = try {
        descriptor.whileOpen { fd ->
            val attributes = Files.readAttributes(
                LinuxFilesystemSyscalls.stableDescriptorPath(fd),
                "unix:ctime",
            )
            attributes["ctime"] as? FileTime
                ?: throw FullTreeControlException("$label descriptor change time is unavailable")
        }
    } catch (failure: FullTreeControlException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeControlException("$label descriptor change time is unavailable", failure)
    }

    private fun requireStableControlParent(identity: LinuxFileIdentity, label: String) {
        if (
            !identity.isDirectory || identity.isRegularFile || identity.isSymbolicLink ||
            identity.linkCount < 1 || identity.mode and UNTRUSTED_CONTROL_WRITE_MODE != 0
        ) {
            throw FullTreeControlException("$label must be an identified directory without untrusted writes")
        }
    }

    private fun requireStableControlFile(identity: LinuxFileIdentity, label: String) {
        if (
            !identity.isRegularFile || identity.isDirectory || identity.isSymbolicLink ||
            identity.linkCount < 1 || identity.mode and UNTRUSTED_CONTROL_WRITE_MODE != 0
        ) {
            throw FullTreeControlException("$label must be an identified regular file without untrusted writes")
        }
    }

    private fun sameStableControlIdentity(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
        first.key == second.key &&
            first.mountId == second.mountId &&
            first.mode == second.mode &&
            first.uid == second.uid &&
            first.gid == second.gid &&
            first.linkCount == second.linkCount &&
            first.isRegularFile == second.isRegularFile &&
            first.isDirectory == second.isDirectory &&
            first.isSymbolicLink == second.isSymbolicLink

    /** Child-directory membership may change a directory's nlink without changing this pinned parent. */
    private fun sameStableControlParentIdentity(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
        first.key == second.key &&
            first.mountId == second.mountId &&
            first.mode == second.mode &&
            first.uid == second.uid &&
            first.gid == second.gid &&
            first.isRegularFile == second.isRegularFile &&
            first.isDirectory == second.isDirectory &&
            first.isSymbolicLink == second.isSymbolicLink

    private class StableControlParentChain(
        val rootIdentity: LinuxFileIdentity,
        val components: List<StableControlParentComponent>,
    )

    private class StableControlParentComponent(
        val name: String,
        val identity: LinuxFileIdentity,
    )

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        readLease.release()
        readable.close()
        mutationWatch.release()
    }

    private object PositionedReader {
        private val libc: PositionedReadLibC by lazy {
            Native.load(Platform.C_LIBRARY_NAME, PositionedReadLibC::class.java)
        }

        fun read(
            descriptor: LinuxDescriptor,
            position: Long,
            length: Int,
        ): ByteArray = Memory(length.toLong()).use { buffer ->
            var count: Long
            var error: Int
            while (true) {
                count = descriptor.whileOpen { fd ->
                    libc.pread(fd, buffer, NativeLong(length.toLong()), NativeLong(position)).toLong()
                }
                error = if (count < 0L) Native.getLastError() else 0
                if (count >= 0L || error != EINTR) break
            }
            if (count < 0L) {
                throw FullTreeControlException(
                    "descriptor-bound positional read failed with errno $error",
                )
            }
            if (count > length.toLong()) {
                throw FullTreeControlException("descriptor-bound positional read exceeded its requested byte range")
            }
            if (count == 0L) ByteArray(0) else buffer.getByteArray(0L, count.toInt())
        }

        private interface PositionedReadLibC : Library {
            fun pread(fd: Int, buffer: Memory, count: NativeLong, offset: NativeLong): NativeLong
        }

        private const val EINTR = 4
    }

    /**
     * Same-owner mutable inputs require kernel exclusion, not timestamp or fsnotify inference.
     *
     * Every same-UID source retains a Linux read lease for the guard lifetime. A dedicated daemon
     * thread owns the standard SIGIO lease-break signal and consumes it synchronously with
     * sigwait(3), so a hostile break request cannot deliver fatal SIGIO to an arbitrary JVM
     * thread. Standard signals may coalesce, so one notification conservatively poisons every
     * active lease. Every source outside the host-root trust boundary must acquire the kernel
     * exclusion. Permission checks cannot make an arbitrary foreign-owned file safe because its
     * owner may retain a descriptor or shared mapping after visible write permission is revoked.
     * A non-root process may use an unleased uid-0 file only when descriptor-relative access
     * checking proves its own credentials cannot write it; host root is already part of the TCB
     * because it can control the JVM directly.
     */
    private interface ReadLeaseRegistration {
        fun requireHeld(label: String)
        fun release()
    }

    private object ReadLeaseMonitor {
        private val libc: LeaseLibC by lazy { Native.load(Platform.C_LIBRARY_NAME, LeaseLibC::class.java) }
        private val ready = CountDownLatch(1)
        private val registrations = LinkedHashSet<Registration>()
        @Volatile private var monitorTid = -1
        @Volatile private var monitorFailure: Throwable? = null

        private class Registration(
            private val descriptor: LinuxDescriptor,
            private val leased: Boolean,
            private val broken: AtomicBoolean = AtomicBoolean(false),
        ) : ReadLeaseRegistration {
            override fun requireHeld(label: String) {
                if (!leased) return
                synchronized(ReadLeaseMonitor) {
                    requireMonitorAvailable(label)
                    if (this !in registrations || broken.get()) {
                        throw FullTreeControlException("$label read lease was broken")
                    }
                }
                val current = descriptor.whileOpen { fd -> libc.fcntl(fd, F_GETLEASE, 0) }
                if (current != F_RDLCK) {
                    broken.set(true)
                    throw FullTreeControlException("$label read lease is no longer held")
                }
            }

            override fun release() {
                broken.set(true)
                if (!leased) return
                descriptor.whileOpen { fd -> runCatching { libc.fcntl(fd, F_SETLEASE, F_UNLCK) } }
                synchronized(ReadLeaseMonitor) { registrations.remove(this) }
            }

            fun markBroken() = broken.set(true)
        }

        init {
            Thread.ofPlatform().daemon(true).name("stable-control-file-lease-monitor").start {
                val signals = Memory(SIGSET_BYTES.toLong())
                try {
                    if (libc.sigemptyset(signals) != 0 || libc.sigaddset(signals, LEASE_BREAK_SIGNAL) != 0) {
                        throw FullTreeControlException("cannot initialize stable-file lease signal set")
                    }
                    val maskResult = libc.pthread_sigmask(SIG_BLOCK, signals, null)
                    if (maskResult != 0) {
                        throw FullTreeControlException(
                            "cannot block stable-file lease signal (error=$maskResult)",
                        )
                    }
                    monitorTid = libc.gettid()
                    if (monitorTid <= 0) {
                        throw FullTreeControlException("stable-file lease monitor has no Linux thread id")
                    }
                } catch (failure: Throwable) {
                    monitorFailure = failure
                } finally {
                    ready.countDown()
                }
                if (monitorFailure != null) return@start
                val received = Memory(Int.SIZE_BYTES.toLong())
                while (true) {
                    val result = libc.sigwait(signals, received)
                    if (result != 0 || received.getInt(0L) != LEASE_BREAK_SIGNAL) {
                        synchronized(this) {
                            monitorFailure = FullTreeControlException(
                                "stable-file lease monitor stopped (error=$result)",
                            )
                            markAllBroken()
                        }
                        return@start
                    }
                    synchronized(this) { markAllBroken() }
                }
            }
        }

        fun acquire(
            descriptor: LinuxDescriptor,
            identity: LinuxFileIdentity,
            label: String,
        ): ReadLeaseRegistration {
            val effectiveUid = libc.geteuid()
            if (effectiveUid != 0 && identity.uid != effectiveUid) {
                if (identity.uid != 0) {
                    throw FullTreeControlException(
                        "$label has an unsupported foreign non-root owner and cannot be leased",
                    )
                }
                val writeDenied = descriptor.whileOpen { fd -> effectiveWriteAccessDenied(fd, label) }
                if (!writeDenied) {
                    throw FullTreeControlException(
                        "$label is host-root-owned but remains writable by the effective credentials",
                    )
                }
                return Registration(descriptor, leased = false)
            }
            awaitReady(label)
            val registration = Registration(descriptor, leased = true)
            synchronized(this) {
                requireMonitorAvailable(label)
                registrations.add(registration)
            }
            try {
                descriptor.whileOpen { fd ->
                    val owner = Memory(2L * Int.SIZE_BYTES)
                    owner.setInt(0L, F_OWNER_TID)
                    owner.setInt(Int.SIZE_BYTES.toLong(), monitorTid)
                    fcntlPointer(fd, F_SETOWN_EX, owner, "$label lease signal owner")
                    fcntlInt(fd, F_SETSIG, LEASE_BREAK_SIGNAL, "$label lease signal")
                    fcntlInt(fd, F_SETLEASE, F_RDLCK, "$label read lease")
                    if (libc.fcntl(fd, F_GETLEASE, 0) != F_RDLCK) {
                        throw FullTreeControlException("$label read lease was broken during acquisition")
                    }
                }
                registration.requireHeld(label)
                return registration
            } catch (failure: Throwable) {
                registration.markBroken()
                synchronized(this) { registrations.remove(registration) }
                descriptor.whileOpen { fd -> runCatching { libc.fcntl(fd, F_SETLEASE, F_UNLCK) } }
                if (failure is FullTreeControlException) throw failure
                throw FullTreeControlException("cannot acquire $label read lease", failure)
            }
        }

        private fun awaitReady(label: String) {
            try {
                ready.await()
            } catch (failure: InterruptedException) {
                Thread.currentThread().interrupt()
                throw FullTreeControlException("interrupted while starting $label read-lease monitor", failure)
            }
        }

        private fun requireMonitorAvailable(label: String) {
            monitorFailure?.let { failure ->
                throw FullTreeControlException("$label read-lease monitor is unavailable", failure)
            }
            if (monitorTid <= 0) throw FullTreeControlException("$label read-lease monitor is unavailable")
        }

        private fun markAllBroken() {
            registrations.forEach(Registration::markBroken)
        }

        private fun effectiveWriteAccessDenied(fd: Int, label: String): Boolean {
            val result = libc.syscall(
                NativeLong(SYS_FACCESSAT2.toLong()),
                fd,
                "",
                W_OK,
                AT_EMPTY_PATH or AT_EACCESS,
            ).toLong()
            if (result == 0L) return false
            val error = Native.getLastError()
            if (error == EACCES) return true
            throw FullTreeControlException(
                "cannot prove $label lacks effective write authority (errno=$error)",
            )
        }

        private fun fcntlInt(fd: Int, command: Int, argument: Int, label: String) {
            if (libc.fcntl(fd, command, argument) < 0) {
                val error = Native.getLastError()
                throw FullTreeControlException("cannot establish $label (errno=$error)")
            }
        }

        private fun fcntlPointer(fd: Int, command: Int, argument: Memory, label: String) {
            if (libc.fcntl(fd, command, argument) < 0) {
                val error = Native.getLastError()
                throw FullTreeControlException("cannot establish $label (errno=$error)")
            }
        }

        private interface LeaseLibC : Library {
            fun fcntl(fd: Int, command: Int, argument: Int): Int
            fun fcntl(fd: Int, command: Int, argument: Memory): Int
            fun geteuid(): Int
            fun gettid(): Int
            fun syscall(number: NativeLong, fd: Int, path: String, mode: Int, flags: Int): NativeLong
            fun sigemptyset(set: Memory): Int
            fun sigaddset(set: Memory, signal: Int): Int
            fun pthread_sigmask(how: Int, set: Memory, previous: Memory?): Int
            fun sigwait(set: Memory, signal: Memory): Int
        }

        private const val SIGSET_BYTES = 128
        private const val SIG_BLOCK = 0
        // Standard SIGIO cannot exhaust the realtime queue and fall back to fatal process delivery.
        // F_OWNER_TID confines it to the monitor thread, where it remains blocked for sigwait(3).
        private const val LEASE_BREAK_SIGNAL = 29 // Linux SIGIO on x86-64 and aarch64.
        private const val F_OWNER_TID = 0
        private const val F_SETSIG = 10
        private const val F_SETOWN_EX = 15
        private const val F_SETLEASE = 1024
        private const val F_GETLEASE = 1025
        private const val F_RDLCK = 0
        private const val F_UNLCK = 2
        private const val SYS_FACCESSAT2 = 439
        private const val W_OK = 2
        private const val AT_EACCESS = 0x200
        private const val AT_EMPTY_PATH = 0x1000
        private const val EACCES = 13
    }

    private interface MutationRegistration {
        fun requireQuiet(label: String)
        fun release()
    }

    private class CompositeMutationRegistration(
        private val registrations: List<MutationRegistration>,
    ) : MutationRegistration {
        override fun requireQuiet(label: String) {
            registrations.forEach { registration -> registration.requireQuiet(label) }
        }

        override fun release() {
            registrations.asReversed().forEach { registration -> runCatching { registration.release() } }
        }
    }

    /** One process-wide inotify descriptor multiplexes every stable-file parent and inode watch. */
    private object MutationMonitor {
        private val libc: InotifyLibC by lazy { Native.load(Platform.C_LIBRARY_NAME, InotifyLibC::class.java) }
        private var descriptor = -1
        private var buffer: Memory? = null
        private var nextRegistrationId = 1L
        private val registrations = HashMap<Long, Registration>()
        private val watches = HashMap<Int, WatchBinding>()
        private val retiredWatches = HashSet<Int>()

        private class Registration(
            val id: Long,
            val selectedNameBytes: ByteArray,
            var parentWatch: Int = -1,
            var fileWatch: Int = -1,
            var changed: Boolean = false,
        ) : MutationRegistration {
            override fun requireQuiet(label: String) {
                MutationMonitor.requireQuiet(this, label)
            }

            override fun release() {
                MutationMonitor.release(this)
            }
        }

        private class WatchBinding(
            val kind: WatchKind,
            val registrations: MutableSet<Long> = LinkedHashSet(),
        )

        private enum class WatchKind { PARENT, FILE }

        @Synchronized
        fun register(
            parent: LinuxDescriptor,
            selected: LinuxDescriptor,
            name: String,
            label: String,
        ): MutationRegistration {
            ensureOpen(label)
            drain(label)
            val registration = Registration(nextRegistrationId++, name.toByteArray(Charsets.UTF_8))
            registrations[registration.id] = registration
            try {
                val parentWatch = parent.whileOpen { fd ->
                    libc.inotify_add_watch(
                        descriptor,
                        LinuxFilesystemSyscalls.stableDescriptorPath(fd).toString(),
                        PARENT_MUTATION_MASK,
                    )
                }
                if (parentWatch < 0) {
                    throw FullTreeControlException(
                        "cannot register $label parent mutation watch (errno=${Native.getLastError()})",
                    )
                }
                bind(parentWatch, WatchKind.PARENT, registration.id, label)
                registration.parentWatch = parentWatch

                val fileWatch = selected.whileOpen { fd ->
                    libc.inotify_add_watch(
                        descriptor,
                        LinuxFilesystemSyscalls.stableDescriptorPath(fd).toString(),
                        FILE_MUTATION_MASK,
                    )
                }
                if (fileWatch < 0 || fileWatch == parentWatch) {
                    throw FullTreeControlException(
                        "cannot register $label file mutation watch (errno=${Native.getLastError()})",
                    )
                }
                bind(fileWatch, WatchKind.FILE, registration.id, label)
                registration.fileWatch = fileWatch
                drain(label)
                if (registration.changed) {
                    throw FullTreeControlException("$label mutated while its watches were registered")
                }
                return registration
            } catch (failure: Throwable) {
                registrations.remove(registration.id)
                unbind(registration.parentWatch, registration.id)
                unbind(registration.fileWatch, registration.id)
                throw failure
            }
        }

        @Synchronized
        fun requireQuiet(registration: Registration, label: String) {
            if (registrations[registration.id] !== registration) {
                throw FullTreeControlException("$label mutation watch is no longer registered")
            }
            drain(label)
            if (registration.changed) {
                throw FullTreeControlException("$label mutated while descriptor-bound bytes were in use")
            }
        }

        @Synchronized
        fun release(registration: Registration) {
            if (registrations.remove(registration.id) !== registration) return
            runCatching { drain("stable control file") }
            unbind(registration.parentWatch, registration.id)
            unbind(registration.fileWatch, registration.id)
        }

        private fun ensureOpen(label: String) {
            if (descriptor >= 0) return
            val opened = libc.inotify_init1(O_NONBLOCK or O_CLOEXEC)
            if (opened < 0) {
                throw FullTreeControlException("cannot open $label mutation monitor (errno=${Native.getLastError()})")
            }
            descriptor = opened
            buffer = try {
                Memory(INOTIFY_READ_BYTES.toLong())
            } catch (failure: Throwable) {
                descriptor = -1
                libc.close(opened)
                throw failure
            }
        }

        private fun bind(watch: Int, kind: WatchKind, registrationId: Long, label: String) {
            val binding = watches[watch]
            if (binding != null && binding.kind != kind) {
                markAllChanged()
                throw FullTreeControlException("$label mutation monitor reused an incompatible watch")
            }
            watches.getOrPut(watch) { WatchBinding(kind) }.registrations.add(registrationId)
        }

        private fun unbind(watch: Int, registrationId: Long) {
            if (watch < 0) return
            val binding = watches[watch] ?: return
            binding.registrations.remove(registrationId)
            if (binding.registrations.isNotEmpty()) return
            watches.remove(watch)
            retiredWatches.add(watch)
            val result = libc.inotify_rm_watch(descriptor, watch)
            if (result != 0 && Native.getLastError() != EINVAL) markAllChanged()
            runCatching { drain("stable control file") }
        }

        private fun drain(label: String) {
            val ownedBuffer = buffer ?: throw FullTreeControlException("$label mutation monitor is unavailable")
            while (true) {
                val count = libc.read(descriptor, ownedBuffer, NativeLong(INOTIFY_READ_BYTES.toLong())).toLong()
                val error = if (count < 0L) Native.getLastError() else 0
                when {
                    count > 0L -> inspectEvents(ownedBuffer, count.toInt(), label)
                    count == 0L -> {
                        markAllChanged()
                        throw FullTreeControlException("$label mutation monitor ended unexpectedly")
                    }
                    error == EINTR -> continue
                    error == EAGAIN -> return
                    else -> {
                        markAllChanged()
                        throw FullTreeControlException("$label mutation monitor failed with errno $error")
                    }
                }
            }
        }

        private fun inspectEvents(buffer: Memory, count: Int, label: String) {
            var offset = 0
            while (offset < count) {
                if (count - offset < INOTIFY_EVENT_HEADER_BYTES) malformedEvent(label, "truncated")
                val watch = buffer.getInt(offset.toLong())
                val mask = buffer.getInt((offset + Int.SIZE_BYTES).toLong())
                val nameLength = buffer.getInt((offset + 3 * Int.SIZE_BYTES).toLong())
                if (nameLength < 0 || nameLength > count - offset - INOTIFY_EVENT_HEADER_BYTES) {
                    malformedEvent(label, "invalid-length")
                }
                if (watch == INOTIFY_QUEUE_WATCH || mask and IN_Q_OVERFLOW != 0) {
                    markAllChanged()
                } else {
                    dispatchEvent(buffer, offset, watch, mask, nameLength, label)
                }
                offset = Math.addExact(offset, Math.addExact(INOTIFY_EVENT_HEADER_BYTES, nameLength))
            }
        }

        private fun dispatchEvent(
            buffer: Memory,
            offset: Int,
            watch: Int,
            mask: Int,
            nameLength: Int,
            label: String,
        ) {
            val binding = watches[watch]
            if (binding == null) {
                if (watch in retiredWatches && mask and IN_IGNORED != 0) {
                    retiredWatches.remove(watch)
                    return
                }
                markAllChanged()
                return
            }
            if (mask and IN_IGNORED != 0) {
                binding.registrations.forEach { registrations[it]?.changed = true }
                watches.remove(watch)
                return
            }
            if (binding.kind == WatchKind.FILE) {
                binding.registrations.forEach { registrations[it]?.changed = true }
            } else {
                if (nameLength == 0) {
                    binding.registrations.forEach { registrations[it]?.changed = true }
                    return
                }
                val paddedName = buffer.getByteArray(
                    (offset + INOTIFY_EVENT_HEADER_BYTES).toLong(),
                    nameLength,
                )
                val terminator = paddedName.indexOf(0)
                if (terminator < 0) malformedEvent(label, "unterminated-name")
                val eventName = paddedName.copyOf(terminator)
                binding.registrations.forEach { id ->
                    val registration = registrations[id]
                    if (registration != null && eventName.contentEquals(registration.selectedNameBytes)) {
                        registration.changed = true
                    }
                }
            }
        }

        private fun malformedEvent(label: String, detail: String): Nothing {
            markAllChanged()
            throw FullTreeControlException("$label mutation monitor returned a $detail event")
        }

        private fun markAllChanged() {
            registrations.values.forEach { it.changed = true }
        }

        private interface InotifyLibC : Library {
            fun inotify_init1(flags: Int): Int
            fun inotify_add_watch(descriptor: Int, path: String, mask: Int): Int
            fun inotify_rm_watch(descriptor: Int, watch: Int): Int
            fun read(descriptor: Int, buffer: Memory, count: NativeLong): NativeLong
            fun close(descriptor: Int): Int
        }

        private const val INOTIFY_READ_BYTES = 64 * 1024
        private const val INOTIFY_EVENT_HEADER_BYTES = 4 * Int.SIZE_BYTES
        private const val INOTIFY_QUEUE_WATCH = -1
        private const val O_NONBLOCK = 0x800
        private const val O_CLOEXEC = 0x80000
        private const val EAGAIN = 11
        private const val EINTR = 4
        private const val EINVAL = 22
        private const val IN_MODIFY = 0x00000002
        private const val IN_ATTRIB = 0x00000004
        private const val IN_CLOSE_WRITE = 0x00000008
        private const val IN_MOVED_FROM = 0x00000040
        private const val IN_MOVED_TO = 0x00000080
        private const val IN_CREATE = 0x00000100
        private const val IN_DELETE = 0x00000200
        private const val IN_DELETE_SELF = 0x00000400
        private const val IN_MOVE_SELF = 0x00000800
        private const val IN_Q_OVERFLOW = 0x00004000
        private const val IN_IGNORED = 0x00008000
        private const val IN_ONLYDIR = 0x01000000
        private const val FILE_MUTATION_MASK =
            IN_MODIFY or IN_ATTRIB or IN_CLOSE_WRITE or IN_DELETE_SELF or IN_MOVE_SELF
        private const val PARENT_MUTATION_MASK =
            IN_ONLYDIR or FILE_MUTATION_MASK or IN_MOVED_FROM or IN_MOVED_TO or IN_CREATE or IN_DELETE
    }

    private enum class OpenFaultPoint {
        AFTER_FILE_PINNED,
    }

    companion object {
        fun open(path: Path, maximumBytes: Long, label: String): StableControlFile =
            openDescriptorBound(path, maximumBytes, label, null)

        private fun openDescriptorBound(
            path: Path,
            maximumBytes: Long,
            label: String,
            faultInjector: ((OpenFaultPoint) -> Unit)?,
        ): StableControlFile {
            val normalized = path.toAbsolutePath().normalize()
            if (normalized.fileName == null || normalized.parent == null) {
                throw FullTreeControlException("$label must name a file")
            }
            if (maximumBytes <= 0L) {
                throw FullTreeControlException("$label maximum byte limit must be positive")
            }
            val directoryDescriptors = ArrayDeque<LinuxDescriptor>()
            var selected: LinuxDescriptor? = null
            var readable: LinuxDescriptor? = null
            var mutationWatch: MutationRegistration? = null
            var readLease: ReadLeaseRegistration? = null
            try {
                LinuxFilesystemSyscalls.requireSupported(normalized)
                if (Path.of(normalized.toString()).toAbsolutePath().normalize() != normalized) {
                    throw FullTreeControlException(
                        "$label path cannot be represented without changing its exact Linux name bytes",
                    )
                }
                val selectedName = normalized.fileName.toString()
                val parentComponentNames = normalized.parent.map { component -> component.toString() }
                if (parentComponentNames.size > STABLE_CONTROL_MAXIMUM_PARENT_COMPONENTS) {
                    throw FullTreeControlException(
                        "$label parent path exceeds the stable component limit " +
                            "$STABLE_CONTROL_MAXIMUM_PARENT_COMPONENTS",
                    )
                }
                val openedRoot = LinuxFilesystemSyscalls.openRoot(STABLE_CONTROL_FILESYSTEM_ROOT)
                directoryDescriptors.addLast(openedRoot)
                val rootIdentity = openedRoot.whileOpen(LinuxFilesystemSyscalls::identity)
                requireStableControlDirectory(rootIdentity, "$label filesystem root")
                val parentComponents = ArrayList<StableControlParentComponent>(parentComponentNames.size)
                parentComponentNames.forEach { componentName ->
                    val openedDirectory = directoryDescriptors.last().whileOpen { parentFd ->
                        LinuxFilesystemSyscalls.openDirectoryAt(parentFd, componentName)
                    }
                    directoryDescriptors.addLast(openedDirectory)
                    val componentIdentity = openedDirectory.whileOpen(LinuxFilesystemSyscalls::identity)
                    requireStableControlDirectory(componentIdentity, "$label parent component $componentName")
                    parentComponents += StableControlParentComponent(componentName, componentIdentity)
                }
                val parentChain = StableControlParentChain(rootIdentity, parentComponents)
                val openedParent = directoryDescriptors.last()
                val parentIdentity = openedParent.whileOpen(LinuxFilesystemSyscalls::identity)
                requireStableControlParent(parentIdentity, "$label parent")
                val openedSelected = openedParent.whileOpen { parentFd ->
                    LinuxFilesystemSyscalls.openRegularFileAtOrNull(
                        parentFd,
                        selectedName,
                    )
                } ?: throw FullTreeControlException("$label is unavailable")
                selected = openedSelected
                val selectedIdentity = openedSelected.whileOpen(LinuxFilesystemSyscalls::identity)
                requireStableControlFile(selectedIdentity, label)
                val attributes = descriptorAttributes(openedSelected, label)
                if (attributes.size() !in 1L..maximumBytes) {
                    throw FullTreeControlException("$label must contain 1..$maximumBytes bytes")
                }
                val selectedChangeTime = descriptorChangeTime(openedSelected, label)
                val openedMutationWatch = registerMutationWatches(
                    directoryDescriptors.toList(),
                    parentComponentNames,
                    openedSelected,
                    selectedName,
                    label,
                )
                mutationWatch = openedMutationWatch
                requirePinnedParentChain(
                    directoryDescriptors.toList(),
                    parentChain,
                    label,
                )
                openedMutationWatch.requireQuiet(label)
                val watchedIdentity = openedSelected.whileOpen(LinuxFilesystemSyscalls::identity)
                val watchedAttributes = descriptorAttributes(openedSelected, label)
                if (
                    !sameStableControlIdentity(selectedIdentity, watchedIdentity) ||
                    watchedAttributes.size() != attributes.size() ||
                    watchedAttributes.lastModifiedTime() != attributes.lastModifiedTime() ||
                    descriptorChangeTime(openedSelected, label) != selectedChangeTime
                ) {
                    throw FullTreeControlException("$label mutated while its descriptor watches were installed")
                }
                faultInjector?.invoke(OpenFaultPoint.AFTER_FILE_PINNED)
                val openedReadable = LinuxFilesystemSyscalls.openReadableFrom(openedSelected)
                readable = openedReadable
                val readableIdentity = openedReadable.whileOpen(LinuxFilesystemSyscalls::identity)
                if (!sameStableControlIdentity(selectedIdentity, readableIdentity)) {
                    throw FullTreeControlException("$label readable descriptor differs from its selected inode")
                }
                if (descriptorChangeTime(openedReadable, label) != selectedChangeTime) {
                    throw FullTreeControlException("$label mutated while its readable descriptor was opened")
                }
                val openedReadLease = ReadLeaseMonitor.acquire(openedReadable, readableIdentity, label)
                readLease = openedReadLease
                openedMutationWatch.requireQuiet(label)
                if (
                    !sameStableControlIdentity(
                        selectedIdentity,
                        openedReadable.whileOpen(LinuxFilesystemSyscalls::identity),
                    ) || descriptorChangeTime(openedReadable, label) != selectedChangeTime
                ) {
                    throw FullTreeControlException("$label mutated before its read lease was established")
                }
                val constructor = StableControlFile::class.java.declaredConstructors.single {
                    !it.isSynthetic && it.parameterCount == STABLE_CONTROL_CONSTRUCTOR_PARAMETERS
                }
                check(constructor.trySetAccessible())
                val result = try {
                    constructor.newInstance(
                        attributes.size(),
                        maximumBytes,
                        label,
                        parentChain,
                        selectedName,
                        openedReadable,
                        parentIdentity,
                        selectedIdentity,
                        readableIdentity,
                        attributes.lastModifiedTime(),
                        selectedChangeTime,
                        openedMutationWatch,
                        openedReadLease,
                    ) as StableControlFile
                } catch (failure: InvocationTargetException) {
                    throw failure.targetException
                }
                openedSelected.close()
                selected = null
                closeDirectories(directoryDescriptors)
                readable = null
                mutationWatch = null
                readLease = null
                return result
            } catch (failure: Throwable) {
                val ownedLease = readLease
                if (ownedLease != null) ownedLease.release()
                readable?.close()
                selected?.close()
                closeDirectories(directoryDescriptors)
                mutationWatch?.release()
                if (failure is FullTreeControlException) throw failure
                throw FullTreeControlException("cannot open $label through its pinned descriptor", failure)
            }
        }

        private fun registerMutationWatches(
            directoryDescriptors: List<LinuxDescriptor>,
            parentComponentNames: List<String>,
            selected: LinuxDescriptor,
            selectedName: String,
            label: String,
        ): MutationRegistration {
            check(directoryDescriptors.size == parentComponentNames.size + 1)
            val registrations = ArrayDeque<MutationRegistration>()
            try {
                parentComponentNames.forEachIndexed { index, componentName ->
                    registrations.addLast(
                        MutationMonitor.register(
                            directoryDescriptors[index],
                            selected,
                            componentName,
                            label,
                        ),
                    )
                }
                registrations.addLast(
                    MutationMonitor.register(
                        directoryDescriptors.last(),
                        selected,
                        selectedName,
                        label,
                    ),
                )
                return CompositeMutationRegistration(registrations.toList())
            } catch (failure: Throwable) {
                registrations.asReversed().forEach { registration -> runCatching { registration.release() } }
                throw failure
            }
        }

        private fun requirePinnedParentChain(
            directoryDescriptors: List<LinuxDescriptor>,
            parentChain: StableControlParentChain,
            label: String,
        ) {
            check(directoryDescriptors.size == parentChain.components.size + 1)
            directoryDescriptors.forEachIndexed { index, descriptor ->
                val expected = if (index == 0) {
                    parentChain.rootIdentity
                } else {
                    parentChain.components[index - 1].identity
                }
                val current = descriptor.whileOpen(LinuxFilesystemSyscalls::identity)
                if (!sameStableControlParentIdentity(expected, current)) {
                    throw FullTreeControlException("$label parent descriptor chain changed identity or metadata")
                }
                requireStableControlDirectory(current, "$label parent descriptor component")
            }
            parentChain.components.forEachIndexed { index, component ->
                val named = directoryDescriptors[index].whileOpen { parentFd ->
                    LinuxFilesystemSyscalls.openDirectoryAt(parentFd, component.name)
                }
                named.use {
                    val namedIdentity = named.whileOpen(LinuxFilesystemSyscalls::identity)
                    if (!sameStableControlParentIdentity(component.identity, namedIdentity)) {
                        throw FullTreeControlException(
                            "$label parent component ${component.name} moved while its watch was installed",
                        )
                    }
                }
            }
        }

        private fun closeDirectories(directoryDescriptors: ArrayDeque<LinuxDescriptor>) {
            while (directoryDescriptors.isNotEmpty()) directoryDescriptors.removeLast().close()
        }

        private fun descriptorAttributes(
            descriptor: LinuxDescriptor,
            label: String,
        ): BasicFileAttributes = try {
            descriptor.whileOpen { fd ->
                Files.readAttributes(
                    LinuxFilesystemSyscalls.stableDescriptorPath(fd),
                    BasicFileAttributes::class.java,
                )
            }
        } catch (failure: Exception) {
            throw FullTreeControlException("$label descriptor attributes are unavailable", failure)
        }

        private fun descriptorChangeTime(descriptor: LinuxDescriptor, label: String): FileTime = try {
            descriptor.whileOpen { fd ->
                val attributes = Files.readAttributes(
                    LinuxFilesystemSyscalls.stableDescriptorPath(fd),
                    "unix:ctime",
                )
                attributes["ctime"] as? FileTime
                    ?: throw FullTreeControlException("$label descriptor change time is unavailable")
            }
        } catch (failure: FullTreeControlException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeControlException("$label descriptor change time is unavailable", failure)
        }

        private fun sameStableControlIdentity(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
            first.key == second.key &&
                first.mountId == second.mountId &&
                first.mode == second.mode &&
                first.uid == second.uid &&
                first.gid == second.gid &&
                first.linkCount == second.linkCount &&
                first.isRegularFile == second.isRegularFile &&
                first.isDirectory == second.isDirectory &&
                first.isSymbolicLink == second.isSymbolicLink

        private fun sameStableControlParentIdentity(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
            first.key == second.key &&
                first.mountId == second.mountId &&
                first.mode == second.mode &&
                first.uid == second.uid &&
                first.gid == second.gid &&
                first.isRegularFile == second.isRegularFile &&
                first.isDirectory == second.isDirectory &&
                first.isSymbolicLink == second.isSymbolicLink

        private fun requireStableControlDirectory(identity: LinuxFileIdentity, label: String) {
            if (
                !identity.isDirectory || identity.isRegularFile || identity.isSymbolicLink ||
                identity.linkCount < 1
            ) {
                throw FullTreeControlException("$label must be an identified directory")
            }
        }

        private fun requireStableControlParent(identity: LinuxFileIdentity, label: String) {
            if (
                !identity.isDirectory || identity.isRegularFile || identity.isSymbolicLink ||
                identity.linkCount < 1 || identity.mode and UNTRUSTED_CONTROL_WRITE_MODE != 0
            ) {
                throw FullTreeControlException("$label must be an identified directory without untrusted writes")
            }
        }

        private fun requireStableControlFile(identity: LinuxFileIdentity, label: String) {
            if (
                !identity.isRegularFile || identity.isDirectory || identity.isSymbolicLink ||
                identity.linkCount < 1 || identity.mode and UNTRUSTED_CONTROL_WRITE_MODE != 0
            ) {
                throw FullTreeControlException("$label must be an identified regular file without untrusted writes")
            }
        }
    }
}

internal fun requireStableDirectory(path: Path, label: String): Pair<Path, Any> {
    val normalized = path.toAbsolutePath().normalize()
    val attributes = try {
        Files.readAttributes(normalized, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    } catch (failure: Exception) {
        throw FullTreeControlException("$label is unavailable", failure)
    }
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
        throw FullTreeControlException("$label must be an identified real directory")
    }
    if (normalized.toRealPath() != normalized) throw FullTreeControlException("$label path contains a symbolic link")
    val permissions = Files.getFileAttributeView(
        normalized,
        PosixFileAttributeView::class.java,
        LinkOption.NOFOLLOW_LINKS,
    )?.readAttributes()?.permissions()
        ?: throw FullTreeControlException("$label requires POSIX permissions")
    if (permissions.any { it in UNTRUSTED_CONTROL_WRITE_PERMISSIONS }) {
        throw FullTreeControlException("$label is writable by an untrusted principal")
    }
    return normalized to attributes.fileKey()
}

internal fun JsonObject.controlObject(name: String): JsonObject = this[name] as? JsonObject
    ?: throw FullTreeControlException("control document field $name is not an object")

internal fun JsonObject.controlArray(name: String): JsonArray = this[name] as? JsonArray
    ?: throw FullTreeControlException("control document field $name is not an array")

internal fun JsonObject.controlString(name: String): String {
    val primitive = this[name] as? JsonPrimitive
        ?: throw FullTreeControlException("control document field $name is not a string")
    if (!primitive.isString) throw FullTreeControlException("control document field $name is not a string")
    return primitive.content
}

internal fun JsonObject.controlLong(name: String): Long {
    val primitive = this[name] as? JsonPrimitive
        ?: throw FullTreeControlException("control document field $name is not an integer")
    if (primitive.isString || primitive.content.any { it in ".eE" }) {
        throw FullTreeControlException("control document field $name is not an integer")
    }
    return primitive.content.toLongOrNull()
        ?: throw FullTreeControlException("control document field $name exceeds the supported integer range")
}

internal fun JsonArray.controlObjects(label: String): List<JsonObject> = map { value ->
    value as? JsonObject ?: throw FullTreeControlException("$label contains a non-object")
}

internal fun JsonElement.controlString(label: String): String {
    val primitive = this as? JsonPrimitive
        ?: throw FullTreeControlException("$label is not a string")
    if (!primitive.isString) throw FullTreeControlException("$label is not a string")
    return primitive.content
}

internal fun requireControlDigest(value: String, label: String) {
    if (!value.matches(CONTROL_SHA256)) throw FullTreeControlException("$label digest is invalid")
}

internal fun ByteArray.hex(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private val CONTROL_SHA256 = Regex("[0-9a-f]{64}")
private val STABLE_CONTROL_FILESYSTEM_ROOT = Path.of("/")
private const val STABLE_CONTROL_BUFFER_BYTES = 1024 * 1024
private const val STABLE_CONTROL_CONSTRUCTOR_PARAMETERS = 13
private const val STABLE_CONTROL_MAXIMUM_PARENT_COMPONENTS = 256
private const val UNTRUSTED_CONTROL_WRITE_MODE = 0x12 // group/other write
private val UNTRUSTED_CONTROL_WRITE_PERMISSIONS: Set<PosixFilePermission> = EnumSet.of(
    PosixFilePermission.GROUP_WRITE,
    PosixFilePermission.OTHERS_WRITE,
)
