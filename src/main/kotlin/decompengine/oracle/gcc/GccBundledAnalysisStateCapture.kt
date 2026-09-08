package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal data class GccAnalysisStateCaptureLimits(
    val maximumEntries: Int = 32768,
    val maximumTotalBytes: Long = 1024L * 1024 * 1024 * 1024,
    val maximumFileBytes: Long = maximumTotalBytes,
    val maximumDepth: Int = 32,
    val maximumWallMillis: Long = 300_000,
) {
    init {
        require(maximumEntries in 1..32768 && maximumDepth in 1..32)
        require(maximumTotalBytes in 1L..1024L * 1024 * 1024 * 1024 && maximumFileBytes in 1L..maximumTotalBytes)
        require(maximumWallMillis in 1L..86_400_000)
    }
}

/** A historical byte/inode manifest; this object grants no resume, lease or process authority. */
internal class GccBundledAnalysisStateSnapshot internal constructor(
    val entryCount: Long,
    val totalBytes: Long,
    canonicalBytes: ByteArray,
) {
    private val bytes = canonicalBytes.copyOf()
    val canonicalBytes: ByteArray get() = bytes.copyOf()
    val sha256: String = OracleArtifacts.sha256(bytes)
}

internal object GccBundledAnalysisStateCapture {
    fun capture(
        run: LinuxDescriptor,
        expectedState: LinuxFileIdentity,
        limits: GccAnalysisStateCaptureLimits = GccAnalysisStateCaptureLimits(),
    ): GccBundledAnalysisStateSnapshot = LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "state").use { state ->
        require(state.identity.copy(linkCount = expectedState.linkCount) == expectedState) { "GCC analysis-state root changed identity" }
        Collector(state, limits).capture().also {
            LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "state").use { current ->
                require(current.identity == state.identity && LinuxFilesystemSyscalls.identity(state.fd) == state.identity) {
                    "GCC analysis-state root changed during capture"
                }
            }
        }
    }

    private class Collector(private val root: LinuxDescriptor, private val limits: GccAnalysisStateCaptureLimits) {
        private val started = System.nanoTime()
        private val entries = linkedMapOf<String, Entry>()
        private val membership = linkedMapOf<String, List<String>>()
        private var bytes = 0L

        fun capture(): GccBundledAnalysisStateSnapshot {
            val rootMetadata = metadata(root)
            scan(root, "", 0)
            require(entries.isNotEmpty() && bytes > 0L) { "GCC resume state must contain nonempty file data" }
            verify(root, "")
            require(metadata(root) == rootMetadata) { "GCC state root metadata changed during capture" }
            val unsigned = JsonObject(mapOf(
                "provider" to JsonPrimitive("gcc-bundled-analysis-state-manifest-v1"),
                "schemaVersion" to JsonPrimitive(1),
                "authority" to JsonPrimitive("non-authoritative-byte-assessment"),
                "root" to identity(root.identity),
                "rootMetadata" to metadataDocument(rootMetadata),
                "entryCount" to JsonPrimitive(entries.size),
                "totalBytes" to JsonPrimitive(bytes),
                "entries" to JsonArray(entries.map { (path, entry) -> JsonObject(mapOf(
                    "path" to JsonPrimitive(path), "identity" to identity(entry.identity),
                    "metadata" to metadataDocument(entry.metadata),
                    "bytes" to JsonPrimitive(entry.bytes), "sha256" to JsonPrimitive(entry.sha256),
                )) }),
            ))
            val encoded = OracleJson.canonicalBytes(unsigned, JSON_LIMITS)
            budget()
            return GccBundledAnalysisStateSnapshot(entries.size.toLong(), bytes, encoded)
        }

        private fun scan(directory: LinuxDescriptor, relative: String, depth: Int) {
            budget()
            requireDirectory(directory.identity)
            val names = LinuxFilesystemSyscalls.directoryEntryNames(directory, limits.maximumEntries + 1).sorted()
            require(names.size <= limits.maximumEntries - entries.size) { "GCC state exceeds its entry bound" }
            membership[relative] = names
            for (name in names) {
                budget()
                require(name.isNotBlank() && name != "." && name != ".." && name.toByteArray().size <= 255 &&
                    name.none { it.code < 32 || it.code == 127 || it == ':' || it == '\\' || it == '/' }) { "GCC state path is invalid" }
                val path = if (relative.isEmpty()) name else "$relative/$name"
                require(depth < limits.maximumDepth && path.toByteArray().size <= 4096) { "GCC state exceeds its path/depth bound" }
                require(entries.size < limits.maximumEntries) { "GCC state exceeds its entry bound" }
                val selected = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, name)) { "GCC state entry disappeared" }
                selected.use { descriptor ->
                    val id = descriptor.identity
                    requireOwned(id)
                    if (id.isDirectory) {
                        LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, name).use { child ->
                            require(child.identity == id) { "GCC state directory was replaced" }
                            entries[path] = Entry(id, metadata(descriptor), 0, "")
                            scan(child, path, depth + 1)
                        }
                    } else {
                        require(id.isRegularFile && !id.isSymbolicLink && id.linkCount == 1) { "GCC state contains a linked or special file" }
                        val before = metadata(descriptor)
                        val size = before.getValue("size") as Long
                        require(size in 0..limits.maximumFileBytes && size <= limits.maximumTotalBytes - bytes) { "GCC state exceeds its byte bound" }
                        bytes += size
                        val digest = MessageDigest.getInstance("SHA-256")
                        var read = 0L
                        LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(descriptor).use { readable ->
                            FileChannel.open(LinuxFilesystemSyscalls.stableDescriptorPath(readable.fd), StandardOpenOption.READ).use { channel ->
                                val buffer = ByteBuffer.allocate(65536)
                                while (true) {
                                    budget()
                                    buffer.clear()
                                    val count = channel.read(buffer)
                                    if (count < 0) break
                                    read += count
                                    require(read <= size) { "GCC state file grew during capture" }
                                    digest.update(buffer.array(), 0, count)
                                }
                            }
                        }
                        require(read == size && metadata(descriptor) == before && LinuxFilesystemSyscalls.identity(descriptor.fd) == id) {
                            "GCC state file changed during capture"
                        }
                        entries[path] = Entry(id, before, size, digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) })
                    }
                }
            }
        }

        private fun verify(directory: LinuxDescriptor, relative: String) {
            budget()
            val expectedNames = membership.getValue(relative)
            require(LinuxFilesystemSyscalls.directoryEntryNames(directory, limits.maximumEntries + 1).sorted() == expectedNames) {
                "GCC state membership changed during capture"
            }
            for (name in expectedNames) {
                budget()
                val path = if (relative.isEmpty()) name else "$relative/$name"
                val expected = entries.getValue(path)
                requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, name)).use { entry ->
                    require(entry.identity == expected.identity) { "GCC state entry identity changed during capture" }
                    require(metadata(entry) == expected.metadata) { "GCC state entry metadata changed during capture" }
                    if (entry.identity.isDirectory) {
                        LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, name).use { child ->
                            require(child.identity == expected.identity) { "GCC state directory changed during verification" }
                            verify(child, path)
                        }
                    }
                }
            }
        }

        private fun requireDirectory(id: LinuxFileIdentity) {
            requireOwned(id)
            require(id.isDirectory && !id.isSymbolicLink) { "GCC state directory is invalid" }
        }
        private fun requireOwned(id: LinuxFileIdentity) {
            require(id.uid == root.identity.uid && id.mountId == root.identity.mountId && id.mode.permissions and 0x12 == 0) {
                "GCC state entry ownership, permissions or mount differ"
            }
        }
        private fun budget() {
            require(System.nanoTime() - started < TimeUnit.MILLISECONDS.toNanos(limits.maximumWallMillis)) { "GCC state capture exceeded its wall-clock bound" }
        }
    }

    private data class Entry(val identity: LinuxFileIdentity, val metadata: Map<String, Any>, val bytes: Long, val sha256: String)
    private fun metadata(descriptor: LinuxDescriptor): Map<String, Any> =
        Files.readAttributes(LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd), "unix:size,lastModifiedTime,ctime")
    private fun metadataDocument(metadata: Map<String, Any>) = JsonObject(metadata.mapValues { JsonPrimitive(it.value.toString()) })
    private fun identity(id: LinuxFileIdentity) = JsonObject(mapOf(
        "device" to JsonPrimitive(id.key.device), "inode" to JsonPrimitive(id.key.inode),
        "mountId" to JsonPrimitive(id.mountId), "uid" to JsonPrimitive(id.uid), "gid" to JsonPrimitive(id.gid),
        "mode" to JsonPrimitive(id.mode.permissions), "linkCount" to JsonPrimitive(id.linkCount),
        "kind" to JsonPrimitive(if (id.isDirectory) "directory" else "file"),
    ))
    internal val JSON_LIMITS = StrictJsonLimits(maximumInputBytes = 64 * 1024 * 1024, maximumCanonicalBytes = 64 * 1024 * 1024,
        maximumDepth = 8, maximumNodes = 1_000_000, maximumStringBytes = 4096, maximumTotalStringBytes = 64 * 1024 * 1024)
}
