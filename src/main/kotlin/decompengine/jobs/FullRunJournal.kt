package decompengine.jobs

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.sha256
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import java.time.Instant
import kotlinx.serialization.json.*

/** Complete, redacted observation history. This log never grants source/checkpoint authority. */
internal class FullRunJournal private constructor(
    val directory: Path,
    private val runId: String,
    private val workflow: String,
    private val firstSequence: Long,
    private val maximumBytes: Long,
) : AutoCloseable {
    private val startedAt = Instant.now().toString()
    private val events = FileChannel.open(directory.resolve("events.jsonl"), CREATE_NEW, WRITE, NOFOLLOW_LINKS)
    private var bytes = 0L
    private var count = 0L
    private var previous = ZERO_HASH
    private var complete = true
    private var closed = false
    private var lastPhase: String? = null

    init {
        try { publishMetadata("running") } catch (failure: Exception) { events.close(); throw failure }
    }

    @Synchronized
    fun append(event: JsonObject) {
        check(!closed)
        try {
            require(event.getValue("runId").jsonPrimitive.content == runId)
            require(event.getValue("sequence").jsonPrimitive.long == firstSequence + count)
            val envelope = buildJsonObject {
                put("schemaVersion", 1)
                put("previousSha256", previous)
                put("event", event)
            }.toString().toByteArray(Charsets.UTF_8)
            require(envelope.size <= MAXIMUM_RECORD_BYTES) { "run record exceeds its byte limit" }
            require(bytes + envelope.size + 1 <= maximumBytes) { "complete run journal reached its byte limit" }
            val buffer = ByteBuffer.wrap(envelope + byteArrayOf(10))
            while (buffer.hasRemaining()) events.write(buffer)
            events.force(true)
            bytes += envelope.size + 1
            previous = sha256(envelope)
            count++
            if (event["kind"]?.jsonPrimitive?.content == "workflow_phase") {
                lastPhase = event["phase"]?.jsonPrimitive?.content
            }
        } catch (failure: Exception) {
            complete = false
            throw failure
        }
    }

    private fun publishMetadata(state: String) {
        val metadata = buildJsonObject {
            put("schemaVersion", 1)
            put("displayOnly", true)
            put("runId", runId)
            put("workflow", workflow)
            put("startedAt", startedAt)
            put("processId", ProcessHandle.current().pid())
            put("state", state)
            put("complete", complete && state == "closed")
            put("firstSequence", firstSequence)
            put("eventCount", count)
            put("eventBytes", bytes)
            put("lastSha256", previous)
            put("maximumBytes", maximumBytes)
            lastPhase?.let { put("lastPhase", it) }
        }.toString()
        val temporary = Files.createTempFile(directory, ".run-", ".tmp")
        try {
            FileChannel.open(temporary, WRITE, NOFOLLOW_LINKS).use { channel ->
                val buffer = ByteBuffer.wrap(metadata.toByteArray(Charsets.UTF_8))
                while (buffer.hasRemaining()) channel.write(buffer)
                channel.force(true)
            }
            Files.move(temporary, directory.resolve("run.json"), ATOMIC_MOVE, REPLACE_EXISTING)
            FileChannel.open(directory, READ).use { it.force(true) }
        } finally { Files.deleteIfExists(temporary) }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        try { events.force(true) } finally { events.close() }
        publishMetadata(if (complete) "closed" else "logging-failed")
    }

    companion object {
        const val DIRECTORY = "run-history"
        const val MAXIMUM_RECORD_BYTES = 64 * 1024
        const val MAXIMUM_RUN_BYTES = 256L * 1024 * 1024
        private const val ZERO_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
        private val RUN_ID = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

        fun create(root: Path, runId: String, workflow: String, firstSequence: Long,
                   maximumBytes: Long = MAXIMUM_RUN_BYTES): FullRunJournal {
            require(RUN_ID.matches(runId))
            require(maximumBytes in 4096..MAXIMUM_RUN_BYTES)
            val runs = root.resolve(DIRECTORY)
            if (!Files.exists(runs, NOFOLLOW_LINKS)) {
                Files.createDirectory(runs, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            }
            require(Files.isDirectory(runs, NOFOLLOW_LINKS)) { "run history directory must not be a link" }
            val directory = Files.createDirectory(runs.resolve(runId),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            return FullRunJournal(directory, runId, workflow, firstSequence, maximumBytes)
        }

        fun directory(root: Path, runId: String): Path {
            require(RUN_ID.matches(runId)) { "run id must be a lowercase UUID" }
            require(Files.isDirectory(root, NOFOLLOW_LINKS) && Files.isDirectory(root.resolve(DIRECTORY), NOFOLLOW_LINKS))
            val directory = root.resolve(DIRECTORY).resolve(runId)
            require(Files.isDirectory(directory, NOFOLLOW_LINKS)) { "run directory is absent or linked" }
            return directory
        }

        fun metadata(directory: Path): JsonObject {
            val path = directory.resolve("run.json")
            require(Files.isRegularFile(path, NOFOLLOW_LINKS) && Files.size(path) <= 16 * 1024)
            val bytes = Files.newInputStream(path, READ, NOFOLLOW_LINKS).use { it.readNBytes(16 * 1024 + 1) }
            val value = OracleJson.parse(bytes, StrictJsonLimits(maximumInputBytes = 16 * 1024)).jsonObject
            require(value["schemaVersion"] == JsonPrimitive(1) && value["displayOnly"] == JsonPrimitive(true))
            require(value.getValue("runId").jsonPrimitive.content == directory.fileName.toString())
            require(value.getValue("workflow").jsonPrimitive.content.matches(Regex("[a-z][a-z0-9-]{0,63}")))
            Instant.parse(value.getValue("startedAt").jsonPrimitive.content)
            require(value.getValue("firstSequence").jsonPrimitive.long >= 0)
            require(value.getValue("state").jsonPrimitive.content in setOf("running", "closed", "logging-failed"))
            value["lastPhase"]?.let { require(it.jsonPrimitive.content.matches(Regex("[a-z_]{1,64}"))) }
            return value
        }
    }
}

/** Streaming reader also supports tailing: incomplete final records wait for their newline. */
internal class FullRunEventReader(private val directory: Path) : AutoCloseable {
    private val initial = FullRunJournal.metadata(directory)
    private val path = directory.resolve("events.jsonl")
    private val channel: FileChannel
    private val buffer = ByteBuffer.allocate(8192).apply { limit(0) }
    private val line = ByteArrayOutputStream()
    private var previous = "0".repeat(64)
    private var count = 0L
    private var bytes = 0L

    init {
        require(Files.isRegularFile(path, NOFOLLOW_LINKS))
        channel = FileChannel.open(path, READ, NOFOLLOW_LINKS)
    }

    fun next(): JsonObject? {
        while (true) {
            if (!buffer.hasRemaining()) {
                buffer.clear()
                val read = channel.read(buffer)
                buffer.flip()
                if (read <= 0) return null
            }
            val byte = buffer.get()
            require(++bytes <= FullRunJournal.MAXIMUM_RUN_BYTES) { "run history exceeds its byte limit" }
            if (byte.toInt() != 10) {
                require(line.size() < FullRunJournal.MAXIMUM_RECORD_BYTES) { "run record exceeds its byte limit" }
                line.write(byte.toInt())
                continue
            }
            val encoded = line.toByteArray()
            line.reset()
            val envelope = OracleJson.parse(encoded,
                StrictJsonLimits(maximumInputBytes = FullRunJournal.MAXIMUM_RECORD_BYTES)).jsonObject
            require(envelope.keys == setOf("schemaVersion", "previousSha256", "event"))
            require(envelope.getValue("schemaVersion") == JsonPrimitive(1))
            require(envelope.getValue("previousSha256").jsonPrimitive.content == previous) { "run history hash chain differs" }
            val event = envelope.getValue("event").jsonObject
            require(event.getValue("runId") == initial.getValue("runId")) { "run history contains another run" }
            require(event.getValue("sequence").jsonPrimitive.long == initial.getValue("firstSequence").jsonPrimitive.long + count) {
                "run history sequence is incomplete or reordered"
            }
            count++
            previous = sha256(encoded)
            return event
        }
    }

    fun verifyEnd(): JsonObject {
        val metadata = FullRunJournal.metadata(directory)
        require(line.size() == 0) { "run history ends with a partial record" }
        if (metadata.getValue("state").jsonPrimitive.content == "closed") {
            require(metadata.getValue("complete") == JsonPrimitive(true))
            require(metadata.getValue("eventCount").jsonPrimitive.long == count)
            require(metadata.getValue("eventBytes").jsonPrimitive.long == bytes)
            require(metadata.getValue("lastSha256").jsonPrimitive.content == previous)
        }
        return metadata
    }

    override fun close() = channel.close()
}
