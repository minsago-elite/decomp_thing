package decompengine.web

import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption.APPEND
import java.nio.file.StandardOpenOption.CREATE
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant

/** Closed vocabulary of sensitive web actions. New mutations add a value here and call [WebAuditLog.record]. */
internal enum class WebAuditAction(val wireName: String) {
    SESSION_START("session.start"),
    SESSION_END("session.end"),
    JOB_UPLOAD("job.upload"),
    JOB_UPDATE("job.update"),
    JOB_DELETE("job.delete"),
    RUN_START("run.start"),
    RUN_CANCEL("run.cancel"),
    RUN_RECOVER("run.recover"),
    PROGRESS_PIN("run.progress-pin"),
    AGENT_PREFLIGHT("agent.preflight"),
    OPERATOR_INSPECTION("operator.auth-inspection"),
    SUPPORT_EXPORT("support.export"),
    ;

    companion object {
        fun fromWire(value: String): WebAuditAction? = entries.firstOrNull { it.wireName == value }
    }
}

internal enum class WebAuditOutcome(val wireName: String) {
    /** The mutation was admitted and applied (or queued) as a new command. */
    ACCEPTED("accepted"),
    /** An idempotent replay returned the original result; nothing new was applied. */
    REPLAYED("replayed"),
    /** Authorization, validation, precondition or capacity refused the request before any change. */
    REJECTED("rejected"),
    /** The server failed after admission; the outcome of any change is reported by the target's state. */
    FAILED("failed"),
    ;

    companion object {
        fun fromWire(value: String): WebAuditOutcome? = entries.firstOrNull { it.wireName == value }
        fun of(status: Int, replayed: Boolean): WebAuditOutcome = when {
            status in 200..399 && replayed -> REPLAYED
            status in 200..399 -> ACCEPTED
            status in 400..499 -> REJECTED
            else -> FAILED
        }
    }
}

/** Actor identity is a domain-separated digest of the authorization-owned session identity, never a credential. */
internal data class WebAuditActor(val kind: String, val sessionDigest: String?) {
    init {
        require(kind in setOf("browser_session", "unauthenticated", "operator"))
        require((kind == "browser_session") == (sessionDigest != null))
        require(sessionDigest == null || sessionDigest.matches(HEX64))
    }

    companion object {
        val UNAUTHENTICATED = WebAuditActor("unauthenticated", null)
        val OPERATOR = WebAuditActor("operator", null)
        fun browserSession(sessionId: String): WebAuditActor {
            require(sessionId.matches(HEX64)) { "invalid session identity" }
            val digest = MessageDigest.getInstance("SHA-256")
                .digest("decomp-web-audit-actor-v1\u0000$sessionId".toByteArray(Charsets.US_ASCII))
                .joinToString("") { "%02x".format(it) }
            return WebAuditActor("browser_session", digest)
        }
    }
}

/**
 * Target identities are closed-syntax public IDs. `expectedVersion` is the client precondition
 * (If-Match) and `resultVersion` the version the response reported; both are opaque versions.
 */
internal data class WebAuditTarget(
    val jobId: String? = null,
    val runId: String? = null,
    val expectedVersion: String? = null,
    val resultVersion: String? = null,
) {
    /** Values outside their closed syntax are dropped rather than stored. */
    fun sanitized() = WebAuditTarget(
        jobId?.takeIf(JOB_ID::matches), runId?.takeIf(OPAQUE_ID::matches),
        expectedVersion?.takeIf(OPAQUE_ID::matches), resultVersion?.takeIf(OPAQUE_ID::matches),
    )
}

internal data class WebAuditEntry(
    val sequence: Long,
    val recordedAt: Instant,
    val requestId: String?,
    val actor: WebAuditActor,
    val action: WebAuditAction,
    val target: WebAuditTarget,
    val outcome: WebAuditOutcome,
    val status: Int,
    val reasonCode: String?,
) {
    fun toJson(): JsonObject = buildJsonObject {
        put("sequence", sequence.toString())
        put("recordedAt", recordedAt.toString())
        put("requestId", requestId?.let(::JsonPrimitive) ?: JsonNull)
        put("actor", buildJsonObject {
            put("kind", actor.kind)
            put("sessionDigest", actor.sessionDigest?.let(::JsonPrimitive) ?: JsonNull)
        })
        put("action", action.wireName)
        put("target", buildJsonObject {
            put("jobId", target.jobId?.let(::JsonPrimitive) ?: JsonNull)
            put("runId", target.runId?.let(::JsonPrimitive) ?: JsonNull)
            put("expectedVersion", target.expectedVersion?.let(::JsonPrimitive) ?: JsonNull)
            put("resultVersion", target.resultVersion?.let(::JsonPrimitive) ?: JsonNull)
        })
        put("outcome", outcome.wireName)
        put("status", status)
        put("reasonCode", reasonCode?.let(::JsonPrimitive) ?: JsonNull)
    }

    companion object {
        fun parse(line: String): WebAuditEntry {
            val value = kotlinx.serialization.json.Json.parseToJsonElement(line).jsonObject
            require(value.keys == setOf("schemaVersion", "entry") && value.getValue("schemaVersion").jsonPrimitive.intOrNull == 1)
            val entry = value.getValue("entry").jsonObject
            fun text(objectValue: JsonObject, name: String): String? = (objectValue.getValue(name) as? JsonPrimitive)
                ?.takeIf { it !is JsonNull }?.also { require(it.isString) }?.content
            val actor = entry.getValue("actor").jsonObject
            val target = entry.getValue("target").jsonObject
            val sequence = checkNotNull(text(entry, "sequence")).toLong().also { require(it > 0) }
            val parsedTarget = WebAuditTarget(text(target, "jobId"), text(target, "runId"),
                text(target, "expectedVersion"), text(target, "resultVersion"))
            require(parsedTarget.sanitized() == parsedTarget)
            val reason = text(entry, "reasonCode")
            require(reason == null || reason.matches(REASON_CODE))
            val requestId = text(entry, "requestId")
            require(requestId == null || requestId.matches(REQUEST_ID))
            val status = checkNotNull(entry.getValue("status").jsonPrimitive.intOrNull).also { require(it in 100..599) }
            return WebAuditEntry(sequence, Instant.parse(checkNotNull(text(entry, "recordedAt"))), requestId,
                WebAuditActor(checkNotNull(text(actor, "kind")), text(actor, "sessionDigest")),
                checkNotNull(WebAuditAction.fromWire(checkNotNull(text(entry, "action")))), parsedTarget,
                checkNotNull(WebAuditOutcome.fromWire(checkNotNull(text(entry, "outcome")))), status, reason)
        }
    }
}

/** A bounded read; omitted counts are exact for rotated prefixes and explicit for unreadable segments. */
internal data class WebAuditPage(
    val entries: List<WebAuditEntry>,
    val omittedBefore: Long,
    val unrecordedEntries: Long,
    val complete: Boolean,
) {
    fun toJson(): JsonObject = buildJsonObject {
        put("entries", buildJsonArray { entries.forEach { add(it.toJson()) } })
        put("omittedEntries", omittedBefore.toString())
        put("unrecordedEntries", unrecordedEntries.toString())
        put("complete", complete)
    }
}

/**
 * Durable append-only audit of sensitive web actions, stored beside job storage under one web
 * owner. Each record is fsync'd before the call returns; two fixed-size segments bound retention,
 * and rotation advances the exact omitted-prefix count. Recording never throws into the request
 * path: a write that cannot be made durable is counted and reported by [read] instead.
 *
 * Every stored field is closed syntax (enumerated action/outcome/actor kind, hexadecimal digests,
 * public IDs, numeric status and an upper-case reason code), so no request text, credential,
 * filename or host path can be persisted here.
 */
internal class WebAuditLog(
    root: Path,
    private val clock: Clock = Clock.systemUTC(),
    private val segmentEntries: Int = DEFAULT_SEGMENT_ENTRIES,
    private val prepareStorage: () -> Unit = {},
) {
    init { require(segmentEntries in 1..65_536) }
    private val directory = root.toAbsolutePath().normalize().resolve(DIRECTORY)
    private val current = directory.resolve("current.jsonl")
    private val previous = directory.resolve("previous.jsonl")
    private val lock = Any()
    private var opened = false
    private var nextSequence = 1L
    private var currentEntries = 0
    private var unrecorded = 0L

    fun record(
        actor: WebAuditActor,
        action: WebAuditAction,
        target: WebAuditTarget,
        outcome: WebAuditOutcome,
        status: Int,
        reasonCode: String?,
        requestId: String?,
    ): WebAuditEntry? = synchronized(lock) {
        try {
            open()
            val entry = WebAuditEntry(nextSequence, clock.instant(), requestId?.takeIf(REQUEST_ID::matches), actor, action,
                target.sanitized(), outcome, status.takeIf { it in 100..599 } ?: 500, reasonCode?.takeIf(REASON_CODE::matches))
            if (currentEntries >= segmentEntries) rotate()
            val line = (buildJsonObject { put("schemaVersion", 1); put("entry", entry.toJson()) }.toString() + "\n")
                .toByteArray(Charsets.UTF_8)
            check(line.size <= MAXIMUM_LINE_BYTES)
            FileChannel.open(current, CREATE, WRITE, APPEND, NOFOLLOW_LINKS).use { channel ->
                val buffer = ByteBuffer.wrap(line)
                while (buffer.hasRemaining()) channel.write(buffer)
                channel.force(true)
            }
            nextSequence++
            currentEntries++
            entry
        } catch (failure: Exception) {
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            unrecorded++
            null
        }
    }

    /** Newest-last entries, optionally scoped to one job, at most [limit] of them. */
    fun read(jobId: String? = null, limit: Int = 200): WebAuditPage = synchronized(lock) {
        require(limit in 1..MAXIMUM_READ_ENTRIES)
        var complete = true
        val segments = listOf(previous, current).map { path ->
            try { readSegment(path) } catch (_: Exception) { complete = false; emptyList() }
        }
        val all = segments.flatten()
        val first = all.firstOrNull()?.sequence ?: if (opened) nextSequence else 1L
        val scoped = if (jobId == null) all else all.filter { it.target.jobId == jobId }
        val selected = scoped.takeLast(limit)
        if (selected.size < scoped.size) complete = false
        WebAuditPage(selected, first - 1, unrecorded, complete && unrecorded == 0L)
    }

    private fun open() {
        if (opened) return
        prepareStorage()
        Files.createDirectories(directory)
        require(Files.isDirectory(directory, NOFOLLOW_LINKS)) { "audit storage is not a directory" }
        discardTornTail()
        val existing = readSegment(current)
        val older = if (existing.isEmpty()) readSegment(previous) else emptyList()
        nextSequence = ((existing.lastOrNull() ?: older.lastOrNull())?.sequence ?: 0L) + 1
        currentEntries = existing.size
        opened = true
    }

    /** An append interrupted before its newline must not merge with the next record. */
    private fun discardTornTail() {
        if (Files.notExists(current, NOFOLLOW_LINKS)) return
        FileChannel.open(current, READ, WRITE, NOFOLLOW_LINKS).use { channel ->
            var end = channel.size()
            val one = ByteBuffer.allocate(1)
            while (end > 0) {
                one.clear()
                channel.read(one, end - 1)
                if (one.get(0) == '\n'.code.toByte()) break
                end--
            }
            if (end != channel.size()) { channel.truncate(end); channel.force(true) }
        }
    }

    private fun rotate() {
        Files.move(current, previous, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        FileChannel.open(directory, READ).use { it.force(true) }
        currentEntries = 0
    }

    private fun readSegment(path: Path): List<WebAuditEntry> {
        if (Files.notExists(path, NOFOLLOW_LINKS)) return emptyList()
        require(Files.isRegularFile(path, NOFOLLOW_LINKS)) { "audit segment is not a regular file" }
        val limit = segmentEntries.toLong() * MAXIMUM_LINE_BYTES
        val bytes = FileChannel.open(path, READ, NOFOLLOW_LINKS).use { channel ->
            require(channel.size() <= limit) { "audit segment exceeds its bound" }
            val buffer = ByteBuffer.allocate(channel.size().toInt())
            while (buffer.hasRemaining() && channel.read(buffer) >= 0) Unit
            buffer.array()
        }
        val text = bytes.toString(Charsets.UTF_8)
        // A torn final line from an interrupted append is ignored; any other malformed line fails the segment.
        val parsed = text.split('\n').dropLast(1).filter(String::isNotEmpty).map(WebAuditEntry::parse)
        require(parsed.zipWithNext().all { (a, b) -> b.sequence == a.sequence + 1 }) { "audit segment sequence is inconsistent" }
        return parsed
    }

    companion object {
        const val DIRECTORY = ".web-audit"
        const val DEFAULT_SEGMENT_ENTRIES = 2048
        const val MAXIMUM_READ_ENTRIES = 500
        private const val MAXIMUM_LINE_BYTES = 1024
    }
}

private val HEX64 = Regex("[0-9a-f]{64}")
private val JOB_ID = Regex("[a-f0-9]{32}")
private val OPAQUE_ID = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
private val REASON_CODE = Regex("[A-Z][A-Z0-9_]{0,63}")
private val REQUEST_ID = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
