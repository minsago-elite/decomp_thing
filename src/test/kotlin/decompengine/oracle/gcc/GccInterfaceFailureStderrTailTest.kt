package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.FileTime
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.json.*
import kotlin.test.*

/** Test-side qualifier support only. A checked raw range has no collector, outcome or cleanup authority. */
internal object GccInterfaceFailureStderrTail {
    const val FILE_NAME = "contained-command.stderr"
    const val MAXIMUM_SOURCE_BYTES = 64L * 1024 * 1024
    const val MAXIMUM_TAIL_BYTES = 16 * 1024
    private const val ATTRIBUTES = "unix:dev,ino,nlink,size,lastModifiedTime,ctime,mode,uid,gid"

    internal class Capture internal constructor(
        val sourceTotalBytes: Long,
        val sourceOffset: Long,
        bytes: ByteArray,
        val sourceMetadataSha256: String,
    ) {
        private val retained = bytes.copyOf()
        val bytes: ByteArray get() = retained.copyOf()
        val capturedBytes: Int get() = retained.size
        val sha256: String = OracleArtifacts.sha256(retained)
        fun metadata(): JsonObject = JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-interface-failed-stderr-raw-tail-v1"),
            "authority" to JsonPrimitive("diagnostic-only"), "stream" to JsonPrimitive("stderr"),
            "sourceTotalBytes" to JsonPrimitive(sourceTotalBytes), "sourceOffset" to JsonPrimitive(sourceOffset),
            "capturedBytes" to JsonPrimitive(capturedBytes), "captureLimitBytes" to JsonPrimitive(MAXIMUM_TAIL_BYTES),
            "sha256" to JsonPrimitive(sha256), "sourceMetadataSha256" to JsonPrimitive(sourceMetadataSha256),
            "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false), "productionInterfacesAdmitted" to JsonPrimitive(false),
            "limitation" to JsonPrimitive("raw range only; may start mid-line or mid-UTF-8; omitted bytes may contain other records and later output may displace any collector diagnostic; no collector authentication, frame parsing, outcome or cleanup claim"),
        ))
    }

    /** A null return means that the fixed name is absent, never a zero-byte stream. */
    fun capture(reports: LinuxDescriptor): Capture? = captureWithReader(reports) { channel, buffer, offset ->
        channel.read(buffer, offset)
    }

    /** Narrow test-side read seam; the qualifier always uses the real positional FileChannel reader. */
    internal fun captureWithReader(reports: LinuxDescriptor,
        read: (FileChannel, ByteBuffer, Long) -> Int): Capture? = reports.whileOpen { reportsFd ->
        val directoryIdentity = LinuxFilesystemSyscalls.identity(reportsFd)
        require(directoryIdentity == reports.identity && directoryIdentity.isDirectory && !directoryIdentity.isSymbolicLink &&
            directoryIdentity.mode.permissions == 0x1c0) { "stderr reports directory is not the retained private directory" }
        val directoryMetadata = metadata(reports)
        val selected = LinuxFilesystemSyscalls.openRegularFileAtOrNull(reportsFd, FILE_NAME) ?: return@whileOpen null
        selected.use { file ->
            val identity = LinuxFilesystemSyscalls.identity(file.fd)
            requirePrivateFile(identity, directoryIdentity)
            val before = metadata(file)
            requireSnapshot(identity, before)
            val total = (before.getValue("size") as Number).toLong()
            require(total in 0..MAXIMUM_SOURCE_BYTES) { "stderr source exceeds its unchanged whole-stream ceiling" }
            val raw = LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(file).use { readable ->
                // Intentionally follow only the owned kernel FD link, not a mutable filesystem name.
                FileChannel.open(LinuxFilesystemSyscalls.stableDescriptorPath(readable.fd), READ).use { channel ->
                    readRange(total) { buffer, offset -> read(channel, buffer, offset) }
                }
            }
            val metadataBytes = OracleJson.canonicalBytes(JsonObject(mapOf(
                "fileIdentity" to identityJson(identity), "fileAttributes" to attributesJson(before),
                "reportsIdentity" to identityJson(directoryIdentity), "reportsAttributes" to attributesJson(directoryMetadata),
            )))
            val captured = Capture(total, total - raw.size, raw, OracleArtifacts.sha256(metadataBytes))
            // All injected reads have finished. These checks precede checked metadata publication.
            require(LinuxFilesystemSyscalls.identity(file.fd) == identity && metadata(file) == before) {
                "stderr descriptor identity or complete metadata changed during range capture"
            }
            requirePrivateFile(LinuxFilesystemSyscalls.identity(file.fd), directoryIdentity)
            requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(reportsFd, FILE_NAME)) {
                "stderr name disappeared during range capture"
            }.use { named ->
                require(LinuxFilesystemSyscalls.identity(named.fd) == identity && metadata(named) == before) {
                    "stderr name no longer selects the captured file"
                }
            }
            require(LinuxFilesystemSyscalls.identity(reportsFd) == directoryIdentity && metadata(reports) == directoryMetadata) {
                "stderr reports directory changed during range capture"
            }
            captured
        }
    }

    /** Exact bounded range; EOF, zero progress and inconsistent position/count are refusals. */
    internal fun readRange(total: Long, read: (ByteBuffer, Long) -> Int): ByteArray {
        require(total in 0..MAXIMUM_SOURCE_BYTES)
        val count = minOf(total, MAXIMUM_TAIL_BYTES.toLong()).toInt()
        val bytes = ByteArray(count)
        val buffer = ByteBuffer.wrap(bytes)
        val offset = total - count
        while (buffer.hasRemaining()) {
            val position = buffer.position()
            val remaining = buffer.remaining()
            val readBytes = read(buffer, offset + position)
            require(readBytes in 1..remaining && buffer.position() == position + readBytes) {
                "stderr tail was truncated or made no exact positive read progress"
            }
        }
        return bytes
    }

    /** Prefix failure cannot prevent the independent raw-tail attempt or replace the original error. */
    fun retainBestEffort(primary: Throwable, prefixes: () -> Unit, tail: () -> Unit,
        tailUnavailable: (Throwable) -> Unit) {
        try { prefixes() } catch (failure: Throwable) { secondary(primary, failure) }
        try { tail() } catch (failure: Throwable) {
            secondary(primary, failure)
            try { tailUnavailable(failure) } catch (publicationFailure: Throwable) { secondary(primary, publicationFailure) }
        }
    }

    fun unavailable(reason: String): JsonObject {
        require(reason in setOf("absent", "capture-or-publication-failed", "not-attempted-reports-unavailable"))
        return JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-interface-failed-stderr-raw-tail-unavailable-v1"),
            "authority" to JsonPrimitive("diagnostic-only"), "stream" to JsonPrimitive("stderr"),
            "reason" to JsonPrimitive(reason), "captureLimitBytes" to JsonPrimitive(MAXIMUM_TAIL_BYTES),
            "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false), "productionInterfacesAdmitted" to JsonPrimitive(false),
        ))
    }

    private fun secondary(primary: Throwable, failure: Throwable) {
        if (failure !== primary) primary.addSuppressed(failure)
    }
    private fun metadata(descriptor: LinuxDescriptor): Map<String, Any> =
        Files.readAttributes(LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd), ATTRIBUTES)
    private fun requirePrivateFile(file: LinuxFileIdentity, reports: LinuxFileIdentity) {
        require(file.isRegularFile && !file.isDirectory && !file.isSymbolicLink && file.linkCount == 1 &&
            file.mode.permissions in setOf(0x100, 0x180) && file.uid == reports.uid && file.gid == reports.gid &&
            file.mountId == reports.mountId) { "stderr must be one private owned regular file on the retained mount" }
    }
    private fun requireSnapshot(identity: LinuxFileIdentity, values: Map<String, Any>) {
        require(values.keys == setOf("dev", "ino", "nlink", "size", "lastModifiedTime", "ctime", "mode", "uid", "gid"))
        require((values.getValue("dev") as Number).toLong() == identity.key.device &&
            (values.getValue("ino") as Number).toLong() == identity.key.inode &&
            (values.getValue("nlink") as Number).toInt() == identity.linkCount &&
            (values.getValue("mode") as Number).toInt() == identity.mode &&
            (values.getValue("uid") as Number).toInt() == identity.uid &&
            (values.getValue("gid") as Number).toInt() == identity.gid)
        require(values.getValue("lastModifiedTime") is FileTime && values.getValue("ctime") is FileTime)
    }
    private fun identityJson(value: LinuxFileIdentity) = JsonObject(mapOf(
        "device" to JsonPrimitive(value.key.device), "inode" to JsonPrimitive(value.key.inode),
        "mountId" to JsonPrimitive(value.mountId), "mode" to JsonPrimitive(value.mode),
        "uid" to JsonPrimitive(value.uid), "gid" to JsonPrimitive(value.gid), "links" to JsonPrimitive(value.linkCount),
    ))
    private fun attributesJson(values: Map<String, Any>) = JsonObject(values.mapValues { (_, value) -> when (value) {
        is Number -> JsonPrimitive(value.toLong())
        is FileTime -> JsonPrimitive(value.toString().also { require(it.length <= 128) })
        else -> error("unexpected stderr metadata value")
    } })
}

/** Actual descriptor fixtures plus the same exact-range seam used by the failure-only qualifier. */
class GccInterfaceFailureStderrTailTest {
    @Test
    fun `empty small and exact length tails retain exact raw commitments`() {
        for (size in listOf(0, 1, 91, GccInterfaceFailureStderrTail.MAXIMUM_TAIL_BYTES)) fixture { root, reports ->
            val bytes = ByteArray(size) { (it % 251).toByte() }
            write(root, bytes)
            val captured = requireNotNull(GccInterfaceFailureStderrTail.capture(reports))
            assertEquals(size.toLong(), captured.sourceTotalBytes)
            assertEquals(0L, captured.sourceOffset)
            assertContentEquals(bytes, captured.bytes)
            captured.bytes.fill(0)
            assertContentEquals(bytes, captured.bytes)
            assertEquals(OracleArtifacts.sha256(bytes), captured.sha256)
            assertTrue(captured.sourceMetadataSha256.matches(Regex("[a-f0-9]{64}")))
            assertEquals(captured.metadata(), requireNotNull(GccInterfaceFailureStderrTail.capture(reports)).metadata())
            assertFalse(captured.metadata().getValue("complete").jsonPrimitive.boolean)
        }
    }

    @Test
    fun `finite stderr beyond prefix and at exact ceiling retains only its final range`() {
        for (size in listOf(16L * 1024 * 1024 + 12345, GccInterfaceFailureStderrTail.MAXIMUM_SOURCE_BYTES)) fixture { root, reports ->
            val tail = ByteArray(GccInterfaceFailureStderrTail.MAXIMUM_TAIL_BYTES) { ((it * 7) % 251).toByte() }
            val marker = "DECOMP_INFERRED_FAILURE_V1 {\"raw-only-control\":true}\n".toByteArray()
            marker.copyInto(tail, tail.size - marker.size)
            val path = write(root, byteArrayOf())
            FileChannel.open(path, WRITE).use { channel ->
                channel.position(size - tail.size)
                val buffer = ByteBuffer.wrap(tail)
                while (buffer.hasRemaining()) channel.write(buffer)
            }
            val captured = requireNotNull(GccInterfaceFailureStderrTail.capture(reports))
            assertEquals(size, captured.sourceTotalBytes)
            assertEquals(size - tail.size, captured.sourceOffset)
            assertEquals(tail.size, captured.capturedBytes)
            assertContentEquals(tail, captured.bytes)
            assertEquals(OracleArtifacts.sha256(tail), captured.sha256)
        }
    }

    @Test
    fun `one byte over whole ceiling is refused before any range read`() {
        fixture { root, reports ->
            val path = write(root, byteArrayOf())
            FileChannel.open(path, WRITE).use { channel ->
                channel.position(GccInterfaceFailureStderrTail.MAXIMUM_SOURCE_BYTES)
                channel.write(ByteBuffer.wrap(byteArrayOf(1)))
            }
            var reads = 0
            assertFails { GccInterfaceFailureStderrTail.captureWithReader(reports) { _, _, _ -> reads++; error("must not read") } }
            assertEquals(0, reads)
        }
        assertFails { GccInterfaceFailureStderrTail.readRange(-1) { _, _ -> error("must not read") } }
    }

    @Test
    fun `range reader refuses early EOF zero progress and inconsistent positive counts`() {
        assertFails { GccInterfaceFailureStderrTail.readRange(9) { _, _ -> -1 } }
        assertFails { GccInterfaceFailureStderrTail.readRange(9) { _, _ -> 0 } }
        assertFails { GccInterfaceFailureStderrTail.readRange(9) { _, _ -> 1 } }
        assertFails { GccInterfaceFailureStderrTail.readRange(9) { buffer, _ -> buffer.put(1); 2 } }
        val positions = arrayListOf<Long>()
        val total = GccInterfaceFailureStderrTail.MAXIMUM_TAIL_BYTES.toLong() + 7
        val observed = GccInterfaceFailureStderrTail.readRange(total) { buffer, offset ->
            positions += offset
            val count = minOf(137, buffer.remaining())
            repeat(count) { buffer.put(((offset + it) % 251).toByte()) }
            count
        }
        assertEquals(7L, positions.first())
        assertTrue(positions.zipWithNext().all { (first, second) -> second > first })
        assertContentEquals(ByteArray(GccInterfaceFailureStderrTail.MAXIMUM_TAIL_BYTES) { ((it + 7) % 251).toByte() }, observed)
        assertContentEquals(byteArrayOf(), GccInterfaceFailureStderrTail.readRange(0) { _, _ -> error("empty range must not read") })
    }

    @Test
    fun `initial absence symlink directory hardlink and public metadata are distinct from empty stderr`() {
        fixture { _, reports -> assertNull(GccInterfaceFailureStderrTail.capture(reports)) }
        for (mutation in listOf<(Path) -> Unit>(
            { path -> Files.delete(path); Files.createDirectory(path) },
            { path -> val other = path.resolveSibling("other"); Files.write(other, byteArrayOf(1)); Files.delete(path); Files.createSymbolicLink(path, other) },
            { path -> Files.createLink(path.resolveSibling("alias"), path) },
            { path -> Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r-----")) },
        )) fixture { root, reports ->
            mutation(write(root, byteArrayOf(1)))
            // Re-select the reports directory after this initial fixture arrangement, so
            // nonregular rejection tests the fixed file rather than an earlier directory pin.
            LinuxFilesystemSyscalls.openRoot(root).use { current ->
                assertFails { GccInterfaceFailureStderrTail.capture(current) }
            }
        }
    }

    @Test
    fun `post selection append truncate overwrite hardlink and mode changes reject checked metadata`() {
        for (mutate in listOf<(Path) -> Unit>(
            { path -> FileChannel.open(path, WRITE).use { it.position(32); it.write(ByteBuffer.wrap(byteArrayOf(1))) } },
            { path -> FileChannel.open(path, WRITE).use { it.truncate(4) } },
            { path -> Files.write(path, ByteArray(32) { 9 }) },
            { path -> val time = Files.getLastModifiedTime(path); Files.write(path, ByteArray(32) { 9 }); Files.setLastModifiedTime(path, time) },
            { path -> Files.setLastModifiedTime(path, FileTime.fromMillis(Files.getLastModifiedTime(path).toMillis() + 2000)) },
            { path -> Files.createLink(path.resolveSibling("late-alias"), path) },
            { path -> Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------")) },
        )) fixture { root, reports ->
            val path = write(root, ByteArray(32) { it.toByte() })
            var changed = false
            var observedChannel: FileChannel? = null
            assertFails {
                GccInterfaceFailureStderrTail.captureWithReader(reports) { channel, buffer, offset ->
                    observedChannel = channel
                    if (!changed) { changed = true; mutate(path) }
                    channel.read(buffer, offset)
                }
            }
            assertTrue(changed)
            assertFalse(requireNotNull(observedChannel).isOpen)
            reports.whileOpen { assertTrue(LinuxFilesystemSyscalls.identity(it).isDirectory) }
        }
    }

    @Test
    fun `named unlink replacement and symlink after selection reject still readable old descriptor`() {
        for (mutate in listOf<(Path) -> Unit>(
            { path -> Files.delete(path) },
            { path -> val replacement = path.resolveSibling("replacement"); Files.write(replacement, ByteArray(32) { it.toByte() }); privateFile(replacement); Files.move(replacement, path, REPLACE_EXISTING) },
            { path -> val saved = path.resolveSibling("saved"); Files.move(path, saved); Files.createSymbolicLink(path, saved) },
        )) fixture { root, reports ->
            val path = write(root, ByteArray(32) { it.toByte() })
            var selectedBytes: ByteArray? = null
            var channelSeen: FileChannel? = null
            var changed = false
            assertFails {
                GccInterfaceFailureStderrTail.captureWithReader(reports) { channel, buffer, offset ->
                    channelSeen = channel
                    if (!changed) { changed = true; mutate(path) }
                    val count = channel.read(buffer, offset)
                    selectedBytes = buffer.array().copyOf()
                    count
                }
            }
            assertTrue(changed)
            assertContentEquals(ByteArray(32) { it.toByte() }, selectedBytes)
            assertFalse(requireNotNull(channelSeen).isOpen)
        }
    }

    @Test
    fun `preselection changes are selected bytes while later reports metadata changes are rejected`() {
        fixture { root, reports ->
            val path = write(root, byteArrayOf(1))
            Files.write(path, byteArrayOf(7, 8, 9))
            assertContentEquals(byteArrayOf(7, 8, 9), requireNotNull(GccInterfaceFailureStderrTail.capture(reports)).bytes)
            assertFails {
                GccInterfaceFailureStderrTail.captureWithReader(reports) { channel, buffer, offset ->
                    Files.write(root.resolve("new-report"), byteArrayOf(0))
                    channel.read(buffer, offset)
                }
            }
        }
    }

    @Test
    fun `mid UTF8 duplicate truncated and displaced marker bytes remain uninterpreted raw data`() {
        val marker = "DECOMP_INFERRED_FAILURE_V1 {\"diagnostic-only\":true}\n".toByteArray()
        val invalidUtf8 = ByteArray(GccInterfaceFailureStderrTail.MAXIMUM_TAIL_BYTES + 5) { 'x'.code.toByte() }.also {
            it[4] = 0xe2.toByte(); it[5] = 0x82.toByte(); it[6] = 0xac.toByte()
        }
        for (source in listOf(invalidUtf8, marker + marker + "DECOMP_INFERRED_FAIL".toByteArray(),
            marker + ByteArray(GccInterfaceFailureStderrTail.MAXIMUM_TAIL_BYTES + 1) { 'z'.code.toByte() })) fixture { root, reports ->
            write(root, source)
            val captured = requireNotNull(GccInterfaceFailureStderrTail.capture(reports))
            assertContentEquals(source.takeLast(GccInterfaceFailureStderrTail.MAXIMUM_TAIL_BYTES).toByteArray(), captured.bytes)
            val metadata = captured.metadata()
            assertEquals(setOf("provider", "authority", "stream", "sourceTotalBytes", "sourceOffset", "capturedBytes", "captureLimitBytes",
                "sha256", "sourceMetadataSha256", "complete", "scored", "releaseEligible", "productionInterfacesAdmitted", "limitation"), metadata.keys)
            assertEquals(JsonPrimitive("diagnostic-only"), metadata["authority"])
            for (flag in listOf("complete", "scored", "releaseEligible", "productionInterfacesAdmitted"))
                assertEquals(JsonPrimitive(false), metadata[flag])
        }
    }

    @Test
    fun `prefix failure still captures tail and preserves original primary with cleanup`() {
        fixture { root, reports ->
            write(root, "last raw bytes".toByteArray())
            val primary = IllegalStateException("original qualification failure")
            val prefixFailure = IllegalArgumentException("prefix publication failed")
            var captured: GccInterfaceFailureStderrTail.Capture? = null
            GccInterfaceFailureStderrTail.retainBestEffort(primary,
                prefixes = { throw prefixFailure },
                tail = { captured = GccInterfaceFailureStderrTail.capture(reports) },
                tailUnavailable = { error("tail succeeded") })
            assertContentEquals("last raw bytes".toByteArray(), requireNotNull(captured).bytes)
            assertContentEquals(arrayOf<Throwable>(prefixFailure), primary.suppressed)
            val thrown = assertFailsWith<IllegalStateException> { throw primary }
            assertSame(primary, thrown)
            reports.whileOpen { assertTrue(LinuxFilesystemSyscalls.identity(it).isDirectory) }
        }
    }

    @Test
    fun `tail capture and publication failures stay secondary and report unavailable without checked metadata`() {
        val primary = IllegalStateException("primary")
        val prefixFailure = IllegalArgumentException("prefix")
        val tailFailure = IllegalArgumentException("tail")
        val publicationFailure = IllegalArgumentException("unavailable publication")
        var attempted = false
        GccInterfaceFailureStderrTail.retainBestEffort(primary, { throw prefixFailure },
            { attempted = true; throw tailFailure }, { failure -> assertSame(tailFailure, failure); throw publicationFailure })
        assertTrue(attempted)
        assertContentEquals(arrayOf<Throwable>(prefixFailure, tailFailure, publicationFailure), primary.suppressed)
        for (reason in listOf("absent", "capture-or-publication-failed", "not-attempted-reports-unavailable")) {
            val metadata = GccInterfaceFailureStderrTail.unavailable(reason)
            assertEquals(JsonPrimitive(reason), metadata["reason"])
            assertFalse("sha256" in metadata || "sourceOffset" in metadata || "capturedBytes" in metadata)
            assertEquals(JsonPrimitive(false), metadata["productionInterfacesAdmitted"])
        }
        GccInterfaceFailureStderrTail.retainBestEffort(primary, { throw primary }, {}, { error("tail succeeded") })
        assertEquals(3, primary.suppressed.size)
    }

    @Test
    fun `closed reports descriptor is refused without a path based fallback`() {
        fixture { root, reports ->
            write(root, byteArrayOf(1))
            reports.close()
            assertFailsWith<IllegalStateException> { GccInterfaceFailureStderrTail.capture(reports) }
        }
    }

    private fun fixture(action: (Path, LinuxDescriptor) -> Unit) {
        val base = Files.createDirectories(Path.of("build", "interface-failure-tail-controls"))
        val root = Files.createTempDirectory(base, "tail-").toRealPath()
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try { LinuxFilesystemSyscalls.openRoot(root).use { action(root, it) } }
        finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun write(root: Path, bytes: ByteArray): Path = root.resolve(GccInterfaceFailureStderrTail.FILE_NAME).also {
        Files.write(it, bytes); privateFile(it)
    }
    private fun privateFile(path: Path) { Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------")) }
}
