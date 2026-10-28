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
import java.nio.file.SecureDirectoryStream
import java.nio.file.NoSuchFileException
import java.nio.file.attribute.BasicFileAttributeView
import java.nio.file.attribute.BasicFileAttributes
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
    OPERATOR_INSPECTION_CANCEL("operator.auth-inspection-cancel"),
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
 * Target identities are closed-syntax public IDs (or commitments to unrecognized requested runs).
 * The HTTP recorder commits client preconditions in `expectedVersion`; `resultVersion` is server-owned.
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

/** A bounded read; counts cover known omissions, while unknown scoped retention/loss makes it incomplete. */
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
 * public IDs, numeric status and an upper-case reason code). Callers must supply server-owned
 * metadata or commitments: syntax alone does not make arbitrary request bytes credential-free.
 * [WebAuditRecorder] owns that projection for HTTP requests.
 */
internal class WebAuditLog(
    root: Path,
    private val clock: Clock = Clock.systemUTC(),
    private val segmentEntries: Int = DEFAULT_SEGMENT_ENTRIES,
    private val prepareStorage: () -> Unit = {},
    // Test seam for append faults; production writes the whole buffer.
    private val append: (FileChannel, ByteBuffer) -> Unit = { channel, buffer -> while (buffer.hasRemaining()) channel.write(buffer) },
    // Test seam observing directory syncs; production forces the directory to stable storage.
    private val syncDirectory: ((Path) -> Unit)? = null,
) {
    init { require(segmentEntries in 1..65_536) }
    private val storeRoot = root.toAbsolutePath().normalize()
    private val directory = storeRoot.resolve(DIRECTORY)
    // Session and refused-request entries made before any job storage exists are held here (bounded) and
    // written first once storage appears: auditing never creates job storage by itself.
    private val pending = ArrayDeque<WebAuditEntry>()
    private val current = directory.resolve("current.jsonl")
    private val previous = directory.resolve("previous.jsonl")
    private val lock = Any()
    private var opened = false
    private var nextSequence = 1L
    private var currentEntries = 0
    private var unrecorded = 0L
    private var directoryIdentity: Any? = null
    private var knownLoss = false

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
            fun entry(sequence: Long) = WebAuditEntry(sequence, clock.instant(), requestId?.takeIf(REQUEST_ID::matches), actor, action,
                target.sanitized(), outcome, status.takeIf { it in 100..599 } ?: 500, reasonCode?.takeIf(REASON_CODE::matches))
            if (!opened && !Files.isDirectory(storeRoot, NOFOLLOW_LINKS)) {
                if (pending.size >= MAXIMUM_PENDING_ENTRIES) {
                    unrecorded++
                    // The first storage-backed flush must retain this loss across restart too.
                    knownLoss = true
                    return null
                }
                return entry((pending.lastOrNull()?.sequence ?: 0L) + 1).also(pending::addLast)
            }
            withDirectory(create = true) { dir ->
                open(dir)
                flushPending(dir)
                entry(nextSequence).also { appendEntry(dir, it) }
            }
        } catch (failure: Exception) {
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            unrecorded++
            knownLoss = true
            // Reopen before the next write: open() discards any torn tail a failed truncation left behind.
            opened = false
            null
        }
    }

    private fun appendEntry(dir: SecureDirectoryStream<Path>, entry: WebAuditEntry) {
        // Durable intent precedes append/rotation. If anything fails or the process dies, this
        // sticky marker keeps exports incomplete after restart, even without a sequence gap.
        writeLossState(dir, true)
        if (currentEntries >= segmentEntries) rotate(dir)
        val line = (buildJsonObject { put("schemaVersion", 1); put("entry", entry.toJson()) }.toString() + "\n")
            .toByteArray(Charsets.UTF_8)
        check(line.size <= MAXIMUM_LINE_BYTES)
        val created = !exists(dir, current.fileName)
        channel(dir, current.fileName, setOf(CREATE, WRITE, NOFOLLOW_LINKS)).use { channel ->
            val boundary = channel.size()
            try {
                channel.position(boundary)
                append(channel, ByteBuffer.wrap(line))
                channel.force(true)
            } catch (failure: Exception) {
                // Restore the last complete record so a later append never extends a torn line.
                try { channel.truncate(boundary); channel.force(true) } catch (cleanup: Exception) { failure.addSuppressed(cleanup) }
                throw failure
            }
        }
        // A newly created segment (first append, or after rotation) is durable only once its directory entry is.
        if (created) sync(dir, directory)
        nextSequence++
        currentEntries++
        if (!knownLoss) writeLossState(dir, false)
    }

    /** Write held pre-storage entries in order, renumbered after any entries already on disk. */
    private fun flushPending(dir: SecureDirectoryStream<Path>) {
        while (pending.isNotEmpty()) {
            appendEntry(dir, pending.first().copy(sequence = nextSequence))
            pending.removeFirst()
        }
    }

    /** Newest-last entries, optionally scoped to one job, at most [limit] of them. */
    fun read(jobId: String? = null, limit: Int = 200): WebAuditPage = synchronized(lock) {
        require(limit in 1..MAXIMUM_READ_ENTRIES)
        var complete = true
        val persisted = try {
            if (directoryIdentity == null &&
                (!Files.isDirectory(storeRoot, NOFOLLOW_LINKS) ||
                    (Files.notExists(directory, NOFOLLOW_LINKS) && pending.isEmpty()))) emptyList()
            else withDirectory(create = pending.isNotEmpty()) { dir ->
                if (pending.isNotEmpty()) { open(dir); flushPending(dir) }
                if (hasLoss(dir)) knownLoss = true
                listOf(previous, current).flatMap { path ->
                    try { readSegment(dir, path.fileName) } catch (_: Exception) { complete = false; emptyList() }
                }
            }
        } catch (_: Exception) { complete = false; opened = false; emptyList() }
        val all = persisted + if (persisted.isEmpty()) pending.toList() else emptyList()
        val first = all.firstOrNull()?.sequence ?: if (opened) nextSequence else 1L
        val scoped = if (jobId == null) all else all.filter { it.target.jobId == jobId }
        val selected = scoped.takeLast(limit)
        val windowOmitted = (scoped.size - selected.size).toLong()
        // Rotated entries have no retained job identity: never count the global prefix as
        // job-specific omissions, nor claim a scoped history is complete when it is unknown.
        val rotated = first - 1
        if (windowOmitted > 0 || rotated > 0) complete = false
        val losses = maxOf(unrecorded, if (knownLoss) 1L else 0L)
        WebAuditPage(selected, (if (jobId == null) rotated else 0L) + windowOmitted,
            losses, complete && losses == 0L)
    }

    private fun open(dir: SecureDirectoryStream<Path>) {
        if (opened) return
        if (hasLoss(dir)) knownLoss = true
        discardTornTail(dir)
        val existing = readSegment(dir, current.fileName)
        val older = if (existing.isEmpty()) readSegment(dir, previous.fileName) else emptyList()
        nextSequence = ((existing.lastOrNull() ?: older.lastOrNull())?.sequence ?: 0L) + 1
        currentEntries = existing.size
        opened = true
    }

    /** An append interrupted before its newline must not merge with the next record. */
    private fun discardTornTail(dir: SecureDirectoryStream<Path>) {
        if (!exists(dir, current.fileName)) return
        channel(dir, current.fileName, setOf(READ, WRITE, NOFOLLOW_LINKS)).use { channel ->
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

    private fun rotate(dir: SecureDirectoryStream<Path>) {
        dir.move(current.fileName, dir, previous.fileName)
        sync(dir, directory)
        currentEntries = 0
    }

    /** All segment/marker operations are relative to a no-follow directory handle. The identity
     * check rejects replacement between requests; the handle prevents rebinding during a request.
     * Providers without secure directory handles fail closed (read reports incomplete auditing).
     */
    private fun <T> withDirectory(create: Boolean, block: (SecureDirectoryStream<Path>) -> T): T {
        if (create && !opened) prepareStorage()
        require(Files.isDirectory(storeRoot, NOFOLLOW_LINKS)) { "audit root is not a directory" }
        Files.newDirectoryStream(storeRoot).use { rootStream ->
            val root = rootStream as? SecureDirectoryStream<Path> ?: error("secure audit storage is unavailable")
            if (create && Files.notExists(directory, NOFOLLOW_LINKS) && directoryIdentity == null) {
                Files.createDirectory(directory)
                sync(root, storeRoot)
            }
            root.newDirectoryStream(Path.of(DIRECTORY), NOFOLLOW_LINKS).use { dir ->
                val identity = dir.getFileAttributeView(BasicFileAttributeView::class.java).readAttributes().fileKey()
                require(identity != null && (directoryIdentity == null || identity == directoryIdentity)) {
                    "audit directory was replaced"
                }
                directoryIdentity = identity
                val result = block(dir)
                require(attributes(root, Path.of(DIRECTORY)).fileKey() == identity) { "audit directory was replaced" }
                return result
            }
        }
    }

    private fun attributes(dir: SecureDirectoryStream<Path>, path: Path): BasicFileAttributes =
        dir.getFileAttributeView(path, BasicFileAttributeView::class.java, NOFOLLOW_LINKS).readAttributes()

    private fun exists(dir: SecureDirectoryStream<Path>, path: Path): Boolean = try {
        attributes(dir, path)
        true
    } catch (_: NoSuchFileException) { false }

    private fun channel(dir: SecureDirectoryStream<Path>, path: Path, options: Set<java.nio.file.OpenOption>): FileChannel {
        val opened = dir.newByteChannel(path, options)
        return opened as? FileChannel ?: run { opened.close(); error("durable audit channels are unavailable") }
    }

    private fun hasLoss(dir: SecureDirectoryStream<Path>): Boolean {
        if (!exists(dir, LOSS_MARKER)) return false
        return channel(dir, LOSS_MARKER, setOf(READ, NOFOLLOW_LINKS)).use { channel ->
            val state = ByteBuffer.allocate(1)
            channel.size() != 1L || channel.read(state) != 1 || state.get(0) != '0'.code.toByte()
        }
    }

    private fun writeLossState(dir: SecureDirectoryStream<Path>, incomplete: Boolean) {
        val created = !exists(dir, LOSS_MARKER)
        channel(dir, LOSS_MARKER, setOf(CREATE, WRITE, NOFOLLOW_LINKS)).use { channel ->
            val state = ByteBuffer.wrap(byteArrayOf((if (incomplete) '1' else '0').code.toByte()))
            while (state.hasRemaining()) channel.write(state)
            channel.truncate(1)
            channel.force(true)
        }
        if (created) sync(dir, directory)
    }

    private fun sync(dir: SecureDirectoryStream<Path>, path: Path) {
        if (syncDirectory != null) syncDirectory.invoke(path)
        else channel(dir, Path.of("."), setOf(READ, NOFOLLOW_LINKS)).use { it.force(true) }
    }

    private fun readSegment(dir: SecureDirectoryStream<Path>, path: Path): List<WebAuditEntry> {
        if (!exists(dir, path)) return emptyList()
        require(attributes(dir, path).isRegularFile) { "audit segment is not a regular file" }
        val limit = segmentEntries.toLong() * MAXIMUM_LINE_BYTES
        val bytes = channel(dir, path, setOf(READ, NOFOLLOW_LINKS)).use { channel ->
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
        const val MAXIMUM_PENDING_ENTRIES = 256
        private const val MAXIMUM_LINE_BYTES = 1024
        private val LOSS_MARKER = Path.of("incomplete")
    }
}

private val HEX64 = Regex("[0-9a-f]{64}")
private val JOB_ID = Regex("[a-f0-9]{32}")
private val OPAQUE_ID = Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
private val REASON_CODE = Regex("[A-Z][A-Z0-9_]{0,63}")
private val REQUEST_ID = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
