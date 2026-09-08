package decompengine.builtin

import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentWorkspacePath
import decompengine.builtin.provider.boundedProviderJson
import decompengine.builtin.provider.parseProviderObject
import kotlinx.serialization.json.*
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions

/** Private project-source evidence; runtime credentials and provider configuration never enter this store. */
class BuiltinSourceStoreConfiguration(
    val directory: Path,
    val maximumStoredBytes: Long = 256L * 1024 * 1024,
    val maximumEntries: Int = 10_000,
    val maximumSnapshotBytes: Long = 32L * 1024 * 1024,
    val maximumSnapshotFiles: Int = 256,
    val maximumFileBytes: Int = 256 * 1024,
    val maximumManifestBytes: Int = 1024 * 1024,
) {
    init {
        require(directory.isAbsolute && directory.normalize() == directory)
        require(maximumStoredBytes in 1024..1024L * 1024 * 1024 && maximumEntries in 2..100_000)
        require(maximumSnapshotBytes in 1..256L * 1024 * 1024 && maximumSnapshotBytes <= maximumStoredBytes)
        require(maximumSnapshotFiles in 1..100_000 && maximumFileBytes in 1..32 * 1024 * 1024)
        require(maximumManifestBytes in 512..32 * 1024 * 1024)
    }
    internal fun limitBinding() = listOf(maximumStoredBytes, maximumEntries, maximumSnapshotBytes,
        maximumSnapshotFiles, maximumFileBytes, maximumManifestBytes).joinToString(":")
    override fun toString() = "BuiltinSourceStoreConfiguration(redacted)"
}

/** Immutable content-addressed blobs and manifests, with a single bounded admission lock. */
internal class BuiltinSourceStore(
    private val configuration: BuiltinSourceStoreConfiguration,
    private val request: AgentExecutionRequest,
    private val excludedDirectories: Set<Path>,
    secrets: List<String>,
) {
    private val secrets = secrets.filter { it.isNotEmpty() }.flatMap {
        listOf(it, JsonPrimitive(it).toString().drop(1).dropLast(1))
    }.distinct()

    fun save(files: Map<AgentWorkspacePath, ByteArray>, expectedSha256: String, control: BuiltinExecutionControl) = locked(control) {
        val snapshot = snapshot(files, control)
        check(snapshot.sha256 == expectedSha256)
        val manifest = manifest(snapshot)
        val desired = linkedMapOf("snapshot-${snapshot.sha256}.json" to manifest)
        snapshot.files.forEach { entry -> desired.putIfAbsent("blob-${entry.sha256}.bin", files.getValue(entry.path)) }
        val existing = inventory(control)
        var newBytes = 0L
        var newEntries = 0
        desired.forEach { (name, bytes) ->
            control.checkpoint()
            if (name in existing) check(read(name, bytes.size, control).contentEquals(bytes))
            else { newBytes += bytes.size; newEntries++ }
        }
        check(newBytes <= configuration.maximumStoredBytes - existing.values.sum())
        check(newEntries <= configuration.maximumEntries - existing.size)
        // Blobs are forced first. An interrupted publication never creates a usable partial manifest.
        desired.filterKeys { it.startsWith("blob-") }.forEach { (name, bytes) ->
            if (name !in existing) write(name, bytes, control)
        }
        val manifestName = "snapshot-${snapshot.sha256}.json"
        if (manifestName !in existing) write(manifestName, manifest, control)
        forceDirectory()
    }

    fun load(expectedSha256: String, control: BuiltinExecutionControl): Map<AgentWorkspacePath, ByteArray> = locked(control) {
        check(expectedSha256.matches(Regex("[a-f0-9]{64}")))
        inventory(control) // Include interrupted/unreferenced entries in the physical storage bound.
        val raw = read("snapshot-$expectedSha256.json", configuration.maximumManifestBytes, control)
        val value = parseProviderObject(raw.decodeToString(throwOnInvalidSequence = true), configuration.maximumManifestBytes)
        check(value.keys == setOf("version", "sourceSha256", "files") && value["version"] == JsonPrimitive(1))
        check(value["sourceSha256"] == JsonPrimitive(expectedSha256))
        val entries = value.getValue("files").jsonArray
        check(entries.size <= configuration.maximumSnapshotFiles)
        val files = linkedMapOf<AgentWorkspacePath, ByteArray>()
        var total = 0L
        entries.forEach { element ->
            control.checkpoint()
            val entry = element.jsonObject
            check(entry.keys == setOf("root", "path", "bytes", "sha256"))
            val path = AgentWorkspacePath(entry.getValue("root").jsonPrimitive.content, entry.getValue("path").jsonPrimitive.content)
            check(path !in files)
            val size = entry.getValue("bytes").jsonPrimitive.long
            check(size in 0..configuration.maximumFileBytes.toLong() && size <= configuration.maximumSnapshotBytes - total)
            total += size
            val hash = entry.getValue("sha256").jsonPrimitive.content
            check(hash.matches(Regex("[a-f0-9]{64}")))
            val bytes = read("blob-$hash.bin", size.toInt(), control)
            check(bytes.size.toLong() == size && checkpointHash(bytes) == hash)
            files[path] = bytes
        }
        val snapshot = snapshot(files, control)
        check(snapshot.sha256 == expectedSha256 && raw.contentEquals(manifest(snapshot)))
        files
    }

    private fun snapshot(files: Map<AgentWorkspacePath, ByteArray>, control: BuiltinExecutionControl): BuiltinWorkspaceSnapshot {
        check(files.size <= configuration.maximumSnapshotFiles)
        var total = 0L
        files.forEach { (path, bytes) ->
            control.checkpoint()
            check(bytes.size <= configuration.maximumFileBytes && bytes.size <= configuration.maximumSnapshotBytes - total)
            total += bytes.size
            check(request.workspaceRoots.any { it.id == path.rootId })
            val text = bytes.decodeToString(throwOnInvalidSequence = true)
            check(secrets.none { it in text || it in path.rootId || it in path.relativePath })
        }
        return BuiltinWorkspaceSnapshot.capture(files, configuration.maximumSnapshotBytes)
    }

    private fun manifest(snapshot: BuiltinWorkspaceSnapshot) = boundedProviderJson(configuration.maximumManifestBytes) { out ->
        out.writeStartObject(); out.writeNumberField("version", 1); out.writeStringField("sourceSha256", snapshot.sha256)
        out.writeArrayFieldStart("files")
        snapshot.files.forEach { entry ->
            out.writeStartObject(); out.writeStringField("root", entry.path.rootId); out.writeStringField("path", entry.path.relativePath)
            out.writeNumberField("bytes", entry.bytes); out.writeStringField("sha256", entry.sha256); out.writeEndObject()
        }
        out.writeEndArray(); out.writeEndObject()
    }

    private fun inventory(control: BuiltinExecutionControl): Map<String, Long> {
        val entries = mutableMapOf<String, Long>()
        var total = 0L
        Files.newDirectoryStream(configuration.directory).use { stream ->
            for (path in stream) {
                control.checkpoint()
                if (path.fileName.toString() == ".lock") continue
                check(entries.size < configuration.maximumEntries)
                val name = path.fileName.toString()
                check(name.matches(Regex("(?:blob-[a-f0-9]{64}\\.bin|snapshot-[a-f0-9]{64}\\.json)")))
                val attrs = attributes(path)
                check(attrs.size() <= configuration.maximumStoredBytes - total)
                total += attrs.size(); entries[name] = attrs.size()
            }
        }
        return entries
    }

    private fun read(name: String, maximumBytes: Int, control: BuiltinExecutionControl): ByteArray {
        val path = configuration.directory.resolve(name)
        val before = attributes(path)
        check(before.size() <= maximumBytes)
        return FileChannel.open(path, READ, NOFOLLOW_LINKS).use { channel ->
            check(channel.size() == before.size())
            val buffer = ByteBuffer.allocate(before.size().toInt())
            while (buffer.hasRemaining()) { control.checkpoint(); check(channel.read(buffer) > 0) }
            check(channel.read(ByteBuffer.allocate(1)) == -1)
            val after = attributes(path)
            check(after.fileKey() == before.fileKey() && after.size() == before.size() && after.lastModifiedTime() == before.lastModifiedTime())
            buffer.array()
        }
    }

    private fun write(name: String, bytes: ByteArray, control: BuiltinExecutionControl) {
        val path = configuration.directory.resolve(name)
        FileChannel.open(path, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS), permissions).use { channel ->
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) { control.checkpoint(); check(channel.write(buffer) > 0) }
            channel.force(true)
        }
        check(attributes(path).size() == bytes.size.toLong())
    }

    private fun <T> locked(control: BuiltinExecutionControl, block: () -> T): T = try {
        control.checkpoint()
        val directory = configuration.directory
        check(directory.toRealPath() == directory)
        check(excludedDirectories.none { directory.startsWith(it) || it.startsWith(directory) })
        check(Files.getPosixFilePermissions(directory, NOFOLLOW_LINKS) == PosixFilePermissions.fromString("rwx------"))
        check(Files.getOwner(directory) == java.nio.file.FileSystems.getDefault().userPrincipalLookupService.lookupPrincipalByName(System.getProperty("user.name")))
        request.workspaceRoots.forEach {
            check(!directory.startsWith(it.path.toAbsolutePath().normalize()))
            if (Files.exists(it.path)) check(!directory.startsWith(it.path.toRealPath()))
        }
        val lockPath = directory.resolve(".lock")
        FileChannel.open(lockPath, setOf(CREATE, READ, WRITE, NOFOLLOW_LINKS), permissions).use { channel ->
            val before = attributes(lockPath); check(before.size() == 0L && channel.size() == 0L)
            (channel.tryLock() ?: error("Source store is active")).use {
                val result = block()
                check(attributes(lockPath).fileKey() == before.fileKey())
                result
            }
        }
    } catch (_: Exception) {
        control.checkpoint() // Preserve cancellation/deadline classification across storage operations.
        throw BuiltinJournalException()
    }

    private fun attributes(path: Path): BasicFileAttributes {
        val value = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        check(value.isRegularFile && value.fileKey() != null && Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) == 1)
        check(Files.getPosixFilePermissions(path, NOFOLLOW_LINKS) == PosixFilePermissions.fromString("rw-------"))
        return value
    }
    private fun forceDirectory() = FileChannel.open(configuration.directory, READ).use { it.force(true) }
    private val permissions get() = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
}
