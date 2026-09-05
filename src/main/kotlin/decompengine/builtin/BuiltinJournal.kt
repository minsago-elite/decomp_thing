package decompengine.builtin

import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.builtin.provider.boundedProviderJson
import decompengine.builtin.provider.parseProviderObject
import decompengine.builtin.provider.writeProviderValue
import kotlinx.serialization.json.*
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest

/** Trusted workflow identities, never inferred from provider prose or a transcript being inspected. */
class BuiltinJournalIdentity(
    val provider: String,
    val model: String,
    val sourceSha256: String,
    val stageSha256: String,
    val acceptedRevisionSha256: String,
    val factoryProvenance: BuiltinHarnessProvenance? = null,
) {
    init {
        require(provider.matches(Regex("[A-Za-z0-9._/-]{1,128}")))
        require(model.matches(Regex("[A-Za-z0-9._/:-]{1,256}")))
        listOf(sourceSha256, stageSha256, acceptedRevisionSha256).forEach { require(it.matches(Regex("[a-f0-9]{64}"))) }
        factoryProvenance?.let { require(it.provider == provider && it.model == model) }
    }
    override fun toString() = "BuiltinJournalIdentity(redacted)"
}

/** A fresh file in an existing private workflow directory outside every tool workspace. */
class BuiltinJournalConfiguration(
    val path: Path,
    val identity: BuiltinJournalIdentity,
    val maximumBytes: Long = 64L * 1024 * 1024,
    val maximumRecordBytes: Int = 8 * 1024 * 1024,
    val maximumRecords: Int = 10_000,
) {
    init {
        require(path.isAbsolute && path.normalize() == path)
        require(maximumBytes in 1024..256L * 1024 * 1024)
        require(maximumRecordBytes in 512..32 * 1024 * 1024 && maximumRecordBytes <= maximumBytes)
        require(maximumRecords in 2..100_000)
    }
    override fun toString() = "BuiltinJournalConfiguration(redacted)"
}

data class BuiltinJournalCommitment(val records: Int, val bytes: Long, val headSha256: String)
data class BuiltinJournalEvidence(val commitment: BuiltinJournalCommitment, val complete: Boolean, val indeterminate: Boolean)

internal enum class BuiltinJournalKind {
    START, STATE, CHECKPOINT, RESUME, MODEL_REQUEST, MODEL_RETRY, MODEL_RESPONSE, POLICY,
    TOOL_REQUEST, TOOL_RESULT, VALIDATION_REQUEST, VALIDATION_RESULT, TERMINAL,
}

/** No raw failure causes, paths, configuration or payloads escape through execution receipts. */
internal class BuiltinJournalException : RuntimeException("Built-in journal unavailable or invalid")

internal class BuiltinJournal private constructor(
    private val configuration: BuiltinJournalConfiguration,
    private val channel: FileChannel,
    private val lock: FileLock,
    private val fileKey: Any,
    private val secrets: List<String>,
) : AutoCloseable {
    private var count = 0
    private var bytes = 0L
    private var head = "0".repeat(64)
    private var pending: BuiltinJournalKind? = null
    private var terminal = false
    private var broken = false
    val evidence get() = BuiltinJournalEvidence(BuiltinJournalCommitment(count, bytes, head), terminal && !broken, pending != null)

    @Synchronized
    fun append(kind: BuiltinJournalKind, payload: JsonObject = buildJsonObject {}): Unit = guarded {
        check(!broken && !terminal && count < configuration.maximumRecords)
        verifyFile(configuration.path, fileKey)
        check(channel.size() == bytes && channel.position() == bytes)
        val nextPending = transition(pending, kind, count)
        // Bound the original representation as well as the redacted one, before persistence.
        encode(payload, configuration.maximumRecordBytes)
        val redacted = redact(payload).jsonObject
        val body = buildJsonObject {
            put("version", 1); put("sequence", count); put("previous", head)
            put("kind", kind.name); put("payload", redacted)
        }
        val checksum = hash(encode(body, configuration.maximumRecordBytes))
        val frame = encode(JsonObject(body + ("sha256" to JsonPrimitive(checksum))), configuration.maximumRecordBytes) + byteArrayOf(10)
        check(frame.size <= configuration.maximumBytes - bytes)
        val buffer = ByteBuffer.wrap(frame)
        while (buffer.hasRemaining()) check(channel.write(buffer) > 0)
        channel.force(true)
        verifyFile(configuration.path, fileKey)
        count++; bytes += frame.size; head = checksum; pending = nextPending
        terminal = kind == BuiltinJournalKind.TERMINAL
    }

    private fun redact(value: JsonElement): JsonElement = when (value) {
        is JsonObject -> {
            val pairs = value.entries.map { redactString(it.key) to redact(it.value) }
            check(pairs.map { it.first }.distinct().size == pairs.size)
            JsonObject(pairs.toMap())
        }
        is JsonArray -> JsonArray(value.map(::redact))
        is JsonPrimitive -> if (value.isString) JsonPrimitive(redactString(value.content)) else value
    }

    private fun redactString(value: String): String {
        // Match against the original string. Replacing iteratively can expose overlapping secrets.
        val result = StringBuilder()
        var index = 0
        while (index < value.length) {
            val secret = secrets.firstOrNull { value.startsWith(it, index) }
            if (secret == null) result.append(value[index++])
            else {
                var end = index + secret.length
                var scan = index + 1
                while (scan < end) {
                    secrets.forEach { if (value.startsWith(it, scan)) end = maxOf(end, scan + it.length) }
                    scan++
                }
                result.append("[REDACTED]"); index = end
            }
        }
        return result.toString()
    }

    private inline fun <T> guarded(block: () -> T): T = try { block() } catch (_: Exception) {
        broken = true
        throw BuiltinJournalException()
    }

    override fun close(): Unit = guarded { try { lock.release() } finally { channel.close() } }

    companion object {
        fun open(configuration: BuiltinJournalConfiguration, request: AgentExecutionRequest, secrets: List<String>): BuiltinJournal {
            var channel: FileChannel? = null
            try {
                verifyParent(configuration.path)
                val parent = configuration.path.parent
                request.workspaceRoots.forEach {
                    val root = it.path.toAbsolutePath().normalize()
                    check(!parent.startsWith(root))
                    if (Files.exists(root)) check(!parent.startsWith(root.toRealPath()))
                }
                channel = FileChannel.open(configuration.path, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS),
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
                val lock = channel.tryLock() ?: error("Locked")
                val key = Files.readAttributes(configuration.path, BasicFileAttributes::class.java, NOFOLLOW_LINKS).fileKey()
                    ?: error("File identity unavailable")
                val redactionPatterns = secrets.filter { it.isNotEmpty() }.flatMap {
                    listOf(it, JsonPrimitive(it).toString().drop(1).dropLast(1))
                }.distinct().sortedByDescending { it.length }
                val journal = BuiltinJournal(configuration, channel, lock, key, redactionPatterns)
                val identity = identity(configuration.identity, AgentExecutionRequestBinding.capture(request))
                // Identities must remain usable for exact trusted comparison; do not persist secret-bearing configuration.
                check(journal.redact(identity) == identity)
                journal.append(BuiltinJournalKind.START, identity)
                FileChannel.open(parent, READ).use { it.force(true) }
                return journal
            } catch (_: Exception) {
                try { channel?.close() } catch (_: Exception) { }
                throw BuiltinJournalException()
            }
        }

        /** Inspection only. No side effect or session restart is performed by reading a journal. */
        fun inspect(configuration: BuiltinJournalConfiguration, binding: AgentExecutionRequestBinding,
            expected: BuiltinJournalCommitment): BuiltinJournalInspection {
            try {
                verifyParent(configuration.path)
                val key = Files.readAttributes(configuration.path, BasicFileAttributes::class.java, NOFOLLOW_LINKS).fileKey() ?: error("No identity")
                verifyFile(configuration.path, key)
                FileChannel.open(configuration.path, READ, WRITE, NOFOLLOW_LINKS).use { channel ->
                    (channel.tryLock() ?: error("Active writer")).use {
                        check(expected.bytes in 1..configuration.maximumBytes && expected.records in 1..configuration.maximumRecords)
                        check(channel.size() == expected.bytes)
                        val records = mutableListOf<JsonObject>()
                        var previous = "0".repeat(64)
                        var pending: BuiltinJournalKind? = null
                        var terminal = false
                        val contentDigest = MessageDigest.getInstance("SHA-256")
                        val input = java.io.BufferedInputStream(java.nio.channels.Channels.newInputStream(channel))
                        val frame = java.io.ByteArrayOutputStream()
                        while (true) {
                            val next = input.read()
                            if (next < 0) break
                            check(!terminal && records.size < configuration.maximumRecords)
                            if (next != 10) {
                                check(frame.size() < configuration.maximumRecordBytes); frame.write(next); continue
                            }
                            val raw = frame.toByteArray(); frame.reset()
                            contentDigest.update(raw); contentDigest.update(10.toByte())
                            val record = parseProviderObject(raw.decodeToString(throwOnInvalidSequence = true), configuration.maximumRecordBytes)
                            check(record.keys == setOf("version", "sequence", "previous", "kind", "payload", "sha256"))
                            check(record["version"] == JsonPrimitive(1) && record["sequence"] == JsonPrimitive(records.size))
                            check(record["previous"] == JsonPrimitive(previous))
                            val checksum = hash(encode(JsonObject(record - "sha256"), configuration.maximumRecordBytes))
                            check(record["sha256"] == JsonPrimitive(checksum))
                            check(raw.contentEquals(encode(record, configuration.maximumRecordBytes)))
                            val kind = BuiltinJournalKind.valueOf(record.getValue("kind").jsonPrimitive.content)
                            pending = transition(pending, kind, records.size)
                            record.getValue("payload").jsonObject
                            if (records.isEmpty()) check(record["payload"] == identity(configuration.identity, binding))
                            records += record; previous = checksum; terminal = kind == BuiltinJournalKind.TERMINAL
                        }
                        check(frame.size() == 0 && records.size == expected.records && previous == expected.headSha256)
                        verifyFile(configuration.path, key)
                        return BuiltinJournalInspection(records.toList(), terminal, pending != null,
                            contentDigest.digest().joinToString("") { byte -> "%02x".format(byte) })
                    }
                }
            } catch (_: Exception) { throw BuiltinJournalException() }
        }

        /** Revalidate the entire inspected file under a new exclusive lock before retaining append authority. */
        fun reopenCheckpoint(configuration: BuiltinJournalConfiguration, request: AgentExecutionRequest,
            expected: BuiltinJournalCommitment, secrets: List<String>): Pair<BuiltinJournal, JsonObject> {
            var channel: FileChannel? = null
            try {
                val inspection = inspect(configuration, AgentExecutionRequestBinding.capture(request), expected)
                check(inspection.endsAtCheckpoint)
                channel = FileChannel.open(configuration.path, READ, WRITE, NOFOLLOW_LINKS)
                val lock = channel.tryLock() ?: error("Active writer")
                val key = Files.readAttributes(configuration.path, BasicFileAttributes::class.java, NOFOLLOW_LINKS).fileKey() ?: error("No identity")
                verifyParent(configuration.path); verifyFile(configuration.path, key)
                check(channel.size() == expected.bytes)
                val digest = MessageDigest.getInstance("SHA-256")
                val buffer = ByteBuffer.allocate(8192)
                var read = 0L
                while (true) {
                    buffer.clear()
                    val size = channel.read(buffer)
                    if (size < 0) break
                    check(size > 0 && size <= expected.bytes - read)
                    read += size; digest.update(buffer.array(), 0, size)
                }
                check(read == expected.bytes && digest.digest().joinToString("") { "%02x".format(it) } == inspection.contentSha256)
                verifyFile(configuration.path, key)
                val patterns = secrets.filter { it.isNotEmpty() }.flatMap {
                    listOf(it, JsonPrimitive(it).toString().drop(1).dropLast(1))
                }.distinct().sortedByDescending { it.length }
                val journal = BuiltinJournal(configuration, channel, lock, key, patterns)
                journal.count = expected.records; journal.bytes = expected.bytes; journal.head = expected.headSha256
                return journal to inspection.records.last().getValue("payload").jsonObject
            } catch (_: Exception) {
                try { channel?.close() } catch (_: Exception) { }
                throw BuiltinJournalException()
            }
        }

        private fun transition(pending: BuiltinJournalKind?, kind: BuiltinJournalKind, count: Int): BuiltinJournalKind? {
            check((count == 0) == (kind == BuiltinJournalKind.START))
            return when (kind) {
                BuiltinJournalKind.MODEL_REQUEST, BuiltinJournalKind.TOOL_REQUEST, BuiltinJournalKind.VALIDATION_REQUEST -> {
                    check(pending == null); kind
                }
                BuiltinJournalKind.MODEL_RESPONSE -> { check(pending == BuiltinJournalKind.MODEL_REQUEST); null }
                BuiltinJournalKind.MODEL_RETRY -> { check(pending == BuiltinJournalKind.MODEL_REQUEST); pending }
                BuiltinJournalKind.TOOL_RESULT -> { check(pending == BuiltinJournalKind.TOOL_REQUEST); null }
                BuiltinJournalKind.VALIDATION_RESULT -> { check(pending == BuiltinJournalKind.VALIDATION_REQUEST); null }
                BuiltinJournalKind.CHECKPOINT -> { check(pending == null); null }
                else -> pending // Terminal failure never resolves an indeterminate operation.
            }
        }

        internal fun identity(value: BuiltinJournalIdentity, binding: AgentExecutionRequestBinding) = buildJsonObject {
            put("contractVersion", binding.contractVersion); put("requestSha256", binding.requestSha256)
            put("accessPolicySha256", binding.accessPolicySha256); put("provider", value.provider); put("model", value.model)
            put("sourceSha256", value.sourceSha256); put("stageSha256", value.stageSha256)
            put("acceptedRevisionSha256", value.acceptedRevisionSha256)
            value.factoryProvenance?.let { put("factoryProvenance", it.json()) }
        }

        /** Pure archive inspection: no path lookup, lock acquisition, truncation or recovery effect. */
        internal fun inspectRecords(records: JsonArray, expectedIdentity: JsonObject, expected: BuiltinJournalCommitment,
            maximumRecordBytes: Int, maximumBytes: Long, maximumRecords: Int): BuiltinJournalInspection = guarded {
            check(records.size == expected.records && expected.records in 1..maximumRecords && expected.bytes in 1..maximumBytes)
            var previous = "0".repeat(64)
            var pending: BuiltinJournalKind? = null
            var terminal = false
            var bytes = 0L
            val contentDigest = MessageDigest.getInstance("SHA-256")
            val verified = records.mapIndexed { index, element ->
                check(!terminal)
                val record = element.jsonObject
                check(record.keys == setOf("version", "sequence", "previous", "kind", "payload", "sha256"))
                check(record["version"] == JsonPrimitive(1) && record["sequence"] == JsonPrimitive(index))
                check(record["previous"] == JsonPrimitive(previous))
                val checksum = hash(encode(JsonObject(record - "sha256"), maximumRecordBytes))
                check(record["sha256"] == JsonPrimitive(checksum))
                val kind = BuiltinJournalKind.valueOf(record.getValue("kind").jsonPrimitive.content)
                pending = transition(pending, kind, index)
                record.getValue("payload").jsonObject
                if (index == 0) check(record["payload"] == expectedIdentity)
                val raw = encode(record, maximumRecordBytes)
                check(raw.size.toLong() + 1 <= maximumBytes - bytes)
                bytes += raw.size + 1
                contentDigest.update(raw); contentDigest.update(10.toByte())
                previous = checksum; terminal = kind == BuiltinJournalKind.TERMINAL
                record
            }
            check(bytes == expected.bytes && previous == expected.headSha256)
            BuiltinJournalInspection(verified, terminal, pending != null, contentDigest.digest().joinToString("") { "%02x".format(it) })
        }

        internal fun verifyParent(path: Path) {
            val parent = path.parent
            check(parent.toRealPath() == parent)
            check(Files.getPosixFilePermissions(parent, NOFOLLOW_LINKS) == PosixFilePermissions.fromString("rwx------"))
            check(Files.getOwner(parent) == java.nio.file.FileSystems.getDefault().userPrincipalLookupService.lookupPrincipalByName(System.getProperty("user.name")))
        }

        private fun verifyFile(path: Path, key: Any) {
            val attrs = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
            check(attrs.isRegularFile && attrs.fileKey() == key)
            check(Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) == 1)
            check(Files.getPosixFilePermissions(path, NOFOLLOW_LINKS) == PosixFilePermissions.fromString("rw-------"))
        }

        private fun encode(value: JsonObject, maximumBytes: Int) = boundedProviderJson(maximumBytes) { it.writeCanonical(value) }
        private fun com.fasterxml.jackson.core.JsonGenerator.writeCanonical(value: JsonElement, depth: Int = 0) {
            check(depth <= 64)
            when (value) {
                is JsonObject -> {
                    writeStartObject()
                    value.toSortedMap().forEach { (key, child) -> writeFieldName(key); writeCanonical(child, depth + 1) }
                    writeEndObject()
                }
                is JsonArray -> { writeStartArray(); value.forEach { writeCanonical(it, depth + 1) }; writeEndArray() }
                else -> writeProviderValue(value)
            }
        }
        private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }
}

internal class BuiltinJournalInspection(val records: List<JsonObject>, val complete: Boolean, val indeterminate: Boolean, val contentSha256: String) {
    // A checkpoint followed by any operation is not a restart authorization. Workflow restoration is a separate capability.
    val endsAtCheckpoint get() = records.lastOrNull()?.get("kind") == JsonPrimitive(BuiltinJournalKind.CHECKPOINT.name) && !indeterminate
    override fun toString() = "BuiltinJournalInspection(records=${records.size}, complete=$complete, indeterminate=$indeterminate)"
}
