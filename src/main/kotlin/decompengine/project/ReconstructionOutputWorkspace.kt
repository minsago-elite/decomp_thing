package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.util.UUID
import kotlinx.serialization.json.*

internal class ReconstructionOutputBusyException : IllegalStateException("another reconstruction owns this output directory")

/** Routes generated state by input identity while preserving the original receipt-bound active paths. */
internal class ReconstructionOutputWorkspace private constructor(
    private val root: Path,
    private val ownerKey: Any,
    private val channel: FileChannel,
    private val lock: FileLock,
    val inputSha256: String,
) : AutoCloseable {
    private var closed = false

    private fun activate() {
        recoverSwitch()
        val archiveEntries = presentEntries(root)
        val current = readObject(root.resolve(ACTIVE))?.let {
            require(it.keys == setOf("schemaVersion", "inputSha256") && it["schemaVersion"] == JsonPrimitive(1))
            it.getValue("inputSha256").jsonPrimitive.content.also { key -> require(HASH.matches(key)) }
        } ?: inferInput()
        if (current == inputSha256) {
            writeActive()
            return
        }
        if (archiveEntries.isEmpty() && !Files.exists(cacheRoot(), NOFOLLOW_LINKS)) {
            writeActive()
            return
        }
        val fromKey = current ?: "unidentified-${UUID.randomUUID()}"
        val previous = cacheDirectory(fromKey)
        val incoming = cacheDirectory(inputSha256)
        require(previous != incoming)
        val restoreEntries = presentEntries(incoming)
        val transaction = buildJsonObject {
            put("schemaVersion", 1)
            put("from", fromKey)
            put("to", inputSha256)
            put("phase", "archive")
            put("archiveEntries", JsonArray(archiveEntries.map(::JsonPrimitive)))
            put("restoreEntries", JsonArray(restoreEntries.map(::JsonPrimitive)))
        }
        writeObject(root.resolve(SWITCH), transaction)
        recoverSwitch()
    }

    private fun inferInput(): String? {
        val identities = listOf("analysis/reports/program_model.json", "source-tree/reports/program_model.json", "reconstruction.json")
            .mapNotNull { relative ->
                var path = root
                for (part in Path.of(relative)) {
                    path = path.resolve(part)
                    if (!Files.exists(path, NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) return@mapNotNull null
                }
                if (!Files.isRegularFile(path, NOFOLLOW_LINKS)) return@mapNotNull null
                val prefix = Files.newInputStream(path, READ, NOFOLLOW_LINKS).use { it.readNBytes(4096) }.toString(Charsets.UTF_8)
                Regex("\"inputSha256\"\\s*:\\s*\"([0-9a-f]{64})\"").find(prefix)?.groupValues?.get(1)
            }.distinct()
        return identities.singleOrNull()
    }

    private fun recoverSwitch() {
        val transaction = readObject(root.resolve(SWITCH)) ?: return
        require(transaction.keys == setOf("schemaVersion", "from", "to", "phase", "archiveEntries", "restoreEntries"))
        require(transaction["schemaVersion"] == JsonPrimitive(1))
        val from = transaction.getValue("from").jsonPrimitive.content
        val to = transaction.getValue("to").jsonPrimitive.content
        require(KEY.matches(from) && HASH.matches(to) && from != to)
        val phase = transaction.getValue("phase").jsonPrimitive.content
        require(phase in setOf("archive", "restore"))
        fun entries(key: String): List<String> = transaction.getValue(key).jsonArray.map { it.jsonPrimitive.content }.also {
            require(it.size <= ENTRIES.size && it.distinct().size == it.size && it.all(ENTRIES::contains))
        }
        val archiveEntries = entries("archiveEntries")
        val restoreEntries = entries("restoreEntries")
        val outgoing = cacheDirectory(from)
        val incoming = cacheDirectory(to)
        if (phase == "archive") {
            moveEntries(root, outgoing, archiveEntries)
            writeObject(root.resolve(SWITCH), JsonObject(transaction + ("phase" to JsonPrimitive("restore"))))
        }
        moveEntries(incoming, root, restoreEntries)
        writeObject(root.resolve(ACTIVE), buildJsonObject { put("schemaVersion", 1); put("inputSha256", to) })
        Files.delete(root.resolve(SWITCH))
        sync(root)
    }

    private fun moveEntries(source: Path, target: Path, entries: List<String>) {
        for (name in entries) {
            val from = source.resolve(name)
            val to = target.resolve(name)
            val hasSource = Files.exists(from, NOFOLLOW_LINKS)
            val hasTarget = Files.exists(to, NOFOLLOW_LINKS)
            require(!(hasSource && hasTarget)) { "input switch has conflicting preserved entries: $name" }
            require(hasSource || hasTarget) { "input switch is missing a preserved entry: $name" }
            require(!Files.isSymbolicLink(from) && !Files.isSymbolicLink(to)) { "input switch entries must not be links" }
            if (hasSource) {
                Files.move(from, to, ATOMIC_MOVE)
                sync(source); sync(target)
            }
        }
    }

    private fun cacheRoot(): Path = root.resolve(CACHE)
    private fun cacheDirectory(key: String): Path {
        require(KEY.matches(key))
        val cache = cacheRoot()
        if (!Files.exists(cache, NOFOLLOW_LINKS)) Files.createDirectory(cache)
        require(Files.isDirectory(cache, NOFOLLOW_LINKS)) { "input cache must be an ordinary directory" }
        val directory = cache.resolve(key)
        if (!Files.exists(directory, NOFOLLOW_LINKS)) Files.createDirectory(directory)
        require(Files.isDirectory(directory, NOFOLLOW_LINKS)) { "input cache entry must be an ordinary directory" }
        return directory
    }

    private fun presentEntries(directory: Path): List<String> = ENTRIES.filter {
        val path = directory.resolve(it)
        require(!Files.isSymbolicLink(path)) { "generated reconstruction entries must not be links" }
        Files.exists(path, NOFOLLOW_LINKS)
    }

    private fun writeActive() = writeObject(root.resolve(ACTIVE), buildJsonObject {
        put("schemaVersion", 1); put("inputSha256", inputSha256)
    })

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        try { if (lock.isValid) lock.release() } finally {
            try { channel.close() } finally { synchronized(OWNERS) { OWNERS.remove(ownerKey) } }
        }
    }

    companion object {
        internal const val ACTIVE = ".reconstruction-active-input.json"
        internal const val SWITCH = ".reconstruction-input-switch.json"
        internal const val CACHE = "input-cache"
        internal val ENTRIES = listOf("analysis", "source-tree", "source-tree.zip", "reconstruction.json", "reconstruction_progress.json", "exploration.json", ModuleCompilerFeedbackStore.DIRECTORY)
        private val HASH = Regex("[0-9a-f]{64}")
        private val KEY = Regex("[0-9a-f]{64}|unidentified-[0-9a-f-]{36}")
        private val OWNERS = mutableSetOf<Any>()

        fun open(root: Path, input: Path): ReconstructionOutputWorkspace {
            require(Files.isRegularFile(input)) { "reconstruction input must be a regular file" }
            Files.createDirectories(root)
            require(Files.isDirectory(root, NOFOLLOW_LINKS)) { "reconstruction output must be an ordinary directory" }
            val attributes = Files.readAttributes(root, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
            val key = root.fileSystem to (attributes.fileKey() ?: root.toRealPath())
            synchronized(OWNERS) { if (!OWNERS.add(key)) throw ReconstructionOutputBusyException() }
            var channel: FileChannel? = null
            var lease: ReconstructionOutputWorkspace? = null
            try {
                channel = FileChannel.open(root.resolve(".reconstruction.lock"), CREATE, WRITE, NOFOLLOW_LINKS)
                val lock = channel.tryLock() ?: throw ReconstructionOutputBusyException()
                val digest = MessageDigest.getInstance("SHA-256")
                Files.newInputStream(input).use { stream ->
                    val bytes = ByteArray(65536)
                    while (true) { val count = stream.read(bytes); if (count < 0) break; digest.update(bytes, 0, count) }
                }
                val inputSha = digest.digest().joinToString("") { "%02x".format(it) }
                lease = ReconstructionOutputWorkspace(root, key, channel, lock, inputSha)
                lease.activate()
                return lease
            } catch (failure: Throwable) {
                if (lease != null) lease.close() else {
                    try { channel?.close() } finally { synchronized(OWNERS) { OWNERS.remove(key) } }
                }
                throw failure
            }
        }

        private fun readObject(path: Path): JsonObject? {
            if (!Files.exists(path, NOFOLLOW_LINKS)) return null
            require(Files.isRegularFile(path, NOFOLLOW_LINKS)) { "input state must be an ordinary file" }
            val bytes = Files.newInputStream(path, READ, NOFOLLOW_LINKS).use { it.readNBytes(16_385) }
            return OracleJson.parse(bytes, StrictJsonLimits(maximumInputBytes = 16_384)).jsonObject
        }

        private fun writeObject(path: Path, value: JsonObject) {
            require(!Files.isSymbolicLink(path))
            val temporary = Files.createTempFile(path.parent, ".input-state-", ".tmp")
            try {
                FileChannel.open(temporary, WRITE, NOFOLLOW_LINKS).use { channel ->
                    val buffer = ByteBuffer.wrap(value.toString().toByteArray(Charsets.UTF_8))
                    while (buffer.hasRemaining()) channel.write(buffer)
                    channel.force(true)
                }
                Files.move(temporary, path, ATOMIC_MOVE, REPLACE_EXISTING)
                sync(path.parent)
            } finally { Files.deleteIfExists(temporary) }
        }
        private fun sync(directory: Path) { FileChannel.open(directory, READ).use { it.force(true) } }
    }
}
