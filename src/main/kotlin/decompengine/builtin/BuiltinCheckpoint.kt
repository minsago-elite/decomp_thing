package decompengine.builtin

import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentWorkspacePath
import decompengine.builtin.provider.boundedProviderJson
import decompengine.builtin.provider.parseProviderObject
import decompengine.builtin.provider.writeProviderValue
import kotlinx.serialization.json.*
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.Collections

data class BuiltinSourceFile(val path: AgentWorkspacePath, val bytes: Long, val sha256: String)

/** Hashes actual staged bytes supplied by a trusted tool session; contains no restorable source text. */
class BuiltinWorkspaceSnapshot private constructor(files: List<BuiltinSourceFile>, val sha256: String) {
    val files: List<BuiltinSourceFile> = Collections.unmodifiableList(ArrayList(files))
    companion object {
        fun capture(files: Map<AgentWorkspacePath, ByteArray>, maximumBytes: Long = 32L * 1024 * 1024): BuiltinWorkspaceSnapshot {
            require(maximumBytes in 1..256L * 1024 * 1024 && files.size <= 100_000)
            var total = 0L
            val entries = files.entries.sortedWith(compareBy({ it.key.rootId }, { it.key.relativePath })).map { (path, bytes) ->
                require(bytes.size <= maximumBytes - total); total += bytes.size
                BuiltinSourceFile(path, bytes.size.toLong(), checkpointHash(bytes))
            }
            val encoded = boundedProviderJson(32 * 1024 * 1024) { out ->
                out.writeStartArray()
                entries.forEach {
                    out.writeStartObject(); out.writeStringField("root", it.path.rootId); out.writeStringField("path", it.path.relativePath)
                    out.writeNumberField("bytes", it.bytes); out.writeStringField("sha256", it.sha256); out.writeEndObject()
                }
                out.writeEndArray()
            }
            return BuiltinWorkspaceSnapshot(entries, checkpointHash(encoded))
        }
    }
}

/** A reference to a separately persisted commitment. It is not a path or provider-controlled input. */
data class BuiltinCheckpointReference(val records: Int, val headSha256: String) {
    init { require(records in 1..100_000 && headSha256.matches(Regex("[a-f0-9]{64}"))) }
    internal val fileName get() = "checkpoint-$records-$headSha256.json"
}

enum class BuiltinCheckpointAction { CONTINUE, SUSPEND }

/** Workflow-owned private directory, separate from the journal directory and every tool workspace. */
class BuiltinCheckpointConfiguration internal constructor(
    val directory: Path,
    val decide: (modelCalls: Int, toolCalls: Int) -> BuiltinCheckpointAction,
    internal val clock: java.time.Clock,
) {
    constructor(directory: Path, decide: (modelCalls: Int, toolCalls: Int) -> BuiltinCheckpointAction = { _, _ -> BuiltinCheckpointAction.CONTINUE }) :
        this(directory, decide, java.time.Clock.systemUTC())
    init { require(directory.isAbsolute && directory.normalize() == directory) }
    override fun toString() = "BuiltinCheckpointConfiguration(redacted)"
}

internal class BuiltinCheckpointStore(
    private val configuration: BuiltinCheckpointConfiguration,
    private val journal: BuiltinJournalConfiguration,
    private val request: AgentExecutionRequest,
) {
    fun publish(commitment: BuiltinJournalCommitment): BuiltinCheckpointReference = guarded {
        verifyDirectory()
        val reference = BuiltinCheckpointReference(commitment.records, commitment.headSha256)
        val payload = encode(commitment)
        FileChannel.open(configuration.directory.resolve(reference.fileName), setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use { channel ->
            val buffer = ByteBuffer.wrap(payload)
            while (buffer.hasRemaining()) check(channel.write(buffer) > 0)
            channel.force(true)
        }
        FileChannel.open(configuration.directory, READ).use { it.force(true) }
        reference
    }

    fun read(reference: BuiltinCheckpointReference): BuiltinJournalCommitment = guarded {
        verifyDirectory()
        val path = configuration.directory.resolve(reference.fileName)
        val before = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        check(before.isRegularFile && before.size() in 1..1024 && before.fileKey() != null)
        check(Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) == 1)
        check(Files.getPosixFilePermissions(path, NOFOLLOW_LINKS) == PosixFilePermissions.fromString("rw-------"))
        val raw = FileChannel.open(path, READ, NOFOLLOW_LINKS).use { channel ->
            val buffer = ByteBuffer.allocate(1025)
            while (buffer.hasRemaining() && channel.read(buffer) >= 0) { }
            check(buffer.position().toLong() == before.size()); buffer.array().copyOf(buffer.position())
        }
        val after = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        check(after.fileKey() == before.fileKey() && after.size() == before.size() && after.lastModifiedTime() == before.lastModifiedTime())
        val value = parseProviderObject(raw.decodeToString(throwOnInvalidSequence = true), 1024)
        check(value.keys == setOf("version", "records", "bytes", "headSha256"))
        check(value["version"] == JsonPrimitive(1))
        val commitment = BuiltinJournalCommitment(value.getValue("records").jsonPrimitive.int,
            value.getValue("bytes").jsonPrimitive.long, value.getValue("headSha256").jsonPrimitive.content)
        check(commitment.records == reference.records && commitment.headSha256 == reference.headSha256)
        check(raw.contentEquals(encode(commitment)))
        commitment
    }

    private fun verifyDirectory() {
        val directory = configuration.directory
        check(directory != journal.path.parent && directory.toRealPath() == directory)
        check(Files.getPosixFilePermissions(directory, NOFOLLOW_LINKS) == PosixFilePermissions.fromString("rwx------"))
        check(Files.getOwner(directory) == java.nio.file.FileSystems.getDefault().userPrincipalLookupService.lookupPrincipalByName(System.getProperty("user.name")))
        request.workspaceRoots.forEach { root ->
            check(!directory.startsWith(root.path.toAbsolutePath().normalize()))
            if (Files.exists(root.path)) check(!directory.startsWith(root.path.toRealPath()))
        }
    }

    private fun encode(value: BuiltinJournalCommitment) = boundedProviderJson(1024) { out ->
        out.writeStartObject(); out.writeNumberField("version", 1); out.writeNumberField("records", value.records)
        out.writeNumberField("bytes", value.bytes); out.writeStringField("headSha256", value.headSha256); out.writeEndObject()
    }
}

internal inline fun <T> guarded(block: () -> T): T = try { block() } catch (_: Exception) { throw BuiltinJournalException() }
internal fun checkpointHash(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
internal fun checkpointStateHash(value: JsonObject, maximumBytes: Int): String = checkpointHash(boundedProviderJson(maximumBytes) {
    fun sorted(element: JsonElement): JsonElement = when (element) {
        is JsonObject -> JsonObject(element.toSortedMap().mapValues { sorted(it.value) })
        is JsonArray -> JsonArray(element.map(::sorted))
        else -> element
    }
    it.writeProviderValue(sorted(value))
})
