package decompengine.agent

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
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.Collections
import kotlinx.serialization.json.*

/** Loading is attempted only for a completed, cleanup-verified conversation with exact identity. */
enum class AgentSessionResumePolicy {
    LOAD_OR_NEW_WHEN_UNSUPPORTED,
    /** Explicit operator/workflow policy; the journal records that conversation state was discarded. */
    NEW_SESSION_FROM_PROJECT_EVIDENCE,
}

/** A recovery decision must not be converted into an unresolved candidate or overwritten source. */
class AgentSessionRecoveryException(message: String, cause: Throwable? = null) : IllegalStateException(message, cause)

/** Workflow-owned local continuation input. The directory is never supplied to the ACP peer. */
class AgentSessionContinuation(
    val directory: Path,
    val workflowSha256: String,
    val taskId: String,
    workspaceFiles: Map<AgentWorkspacePath, String?>,
    val acceptedRevisionSha256: String? = null,
    val policy: AgentSessionResumePolicy = AgentSessionResumePolicy.LOAD_OR_NEW_WHEN_UNSUPPORTED,
) {
    val workspaceFiles: Map<AgentWorkspacePath, String?> = Collections.unmodifiableMap(LinkedHashMap(workspaceFiles))
    init {
        require(directory.isAbsolute && directory == directory.normalize()) { "session directory must be absolute and normalized" }
        requireSessionDigest(workflowSha256)
        require(taskId.isNotBlank() && taskId.toByteArray().size <= 256) { "invalid session task identity" }
        acceptedRevisionSha256?.let(::requireSessionDigest)
        require(this.workspaceFiles.size in 1..4096) { "session workspace inventory exceeds its bound" }
        this.workspaceFiles.values.filterNotNull().forEach(::requireSessionDigest)
    }

    internal fun bindingSha256(): String = sessionDigest(OracleJson.canonicalBytes(buildJsonObject {
        put("directory", directory.toString())
        put("workflowSha256", workflowSha256)
        put("taskId", taskId)
        put("policy", policy.name)
        put("acceptedRevisionSha256", acceptedRevisionSha256?.let(::JsonPrimitive) ?: JsonNull)
        put("workspaceFiles", filesJson(workspaceFiles))
    }))
}

/**
 * Local crash journal, held outside agent file grants. This coordinates cooperative workflow
 * writers; it is not an oracle receipt, remote session store, credential or process-cleanup proof.
 * Atomic fsynced snapshots retain all bounded turn/decision records and the last durable event.
 */
class AgentSessionJournal private constructor(
    private val continuation: AgentSessionContinuation,
    private val channel: FileChannel,
    private val lock: FileLock,
    private val directoryKey: Any?,
    private val lockKey: Any?,
    private var state: JsonObject,
) : AutoCloseable {
    private var closed = false
    private val path get() = continuation.directory.resolve("session.json")

    val sessionId: String? get() = state.optionalText("sessionId")
    val completedTurns: Int get() = state.getValue("turns").jsonArray.size
    val lastDurableEventSequence: Long get() = state.getValue("lastEventSequence").jsonPrimitive.long
    val decision: String? get() = state.optionalText("decision")
    val acceptedRevisionSha256: String? get() = state.optionalText("acceptedRevisionSha256")

    /** Must run before process launch and before any workspace mutation is enabled. */
    @Synchronized
    fun reconcileWorkspace(roots: List<AgentWorkspaceRoot>, checkActive: () -> Unit = {}) {
        requireCurrent()
        if (state.optionalText("phase") == "QUARANTINED") error("session is quarantined; inspect retained evidence before a new workflow")
        if (!state.getValue("cleanupVerified").jsonPrimitive.boolean) {
            quarantine("previous-process-cleanup-unverified")
            error("previous ACP process cleanup is unverified; reconcile its contained lifecycle before restarting")
        }
        val expected = parseFiles(state.getValue("workspaceFiles").jsonArray)
        val observed = captureWorkspaceFiles(expected.keys, roots, checkActive)
        val mismatched = expected.filter { (file, digest) -> observed[file] != digest }
        if (mismatched.isNotEmpty()) {
            val manifest = buildJsonObject {
                put("reason", "unexplained-workspace-edits")
                put("expected", filesJson(mismatched))
                put("observed", filesJson(observed.filterKeys { it in mismatched }))
            }
            atomicWrite(continuation.directory.resolve("quarantine.json"), OracleJson.canonicalBytes(manifest))
            quarantine("unexplained-workspace-edits")
            error("ACP session workspace differs from its durable accepted/baseline hashes; edits are quarantined for inspection")
        }
        // A workflow may update read-only evidence only through a changed workflow identity.
        require(expected == continuation.workspaceFiles) { "continuation inventory differs from the durable project evidence" }
        require(state.optionalText("acceptedRevisionSha256") == continuation.acceptedRevisionSha256) {
            "continuation accepted revision differs from the durable acceptance record"
        }
    }

    /** Peer identity and capabilities are exact data, not authentication supplied by the peer. */
    @Synchronized
    fun chooseSession(identity: Map<String, String>, loadAdvertised: Boolean): String? {
        requireCurrent()
        require(identity.size in 1..32 && identity.all { (key, value) -> key.length <= 128 && value.toByteArray().size <= 4096 })
        val identityDocument = JsonObject(identity.toSortedMap().mapValues { JsonPrimitive(it.value) })
        val identitySha256 = sessionDigest(OracleJson.canonicalBytes(identityDocument))
        val previousIdentity = state.optionalText("agentIdentitySha256")
        if (previousIdentity != null && previousIdentity != identitySha256) {
            quarantine("agent-configuration-protocol-capability-identity-mismatch")
            error("configured or negotiated ACP session identity changed; persisted conversation is quarantined")
        }
        if (state.optionalText("phase") == "LOAD_FAILED" &&
            continuation.policy != AgentSessionResumePolicy.NEW_SESSION_FROM_PROJECT_EVIDENCE
        ) error("ACP session/load previously failed; explicitly select a new session from project evidence")
        val previous = sessionId
        val canLoad = previous != null && loadAdvertised &&
            state.optionalText("phase") in setOf("TURN_FINISHED", "ACCEPTED", "REJECTED", "SESSION_READY") &&
            continuation.policy == AgentSessionResumePolicy.LOAD_OR_NEW_WHEN_UNSUPPORTED
        val selected = when {
            continuation.policy == AgentSessionResumePolicy.NEW_SESSION_FROM_PROJECT_EVIDENCE -> "new-explicit-project-evidence"
            previous == null -> "new-initial"
            !loadAdvertised -> "new-load-unsupported-project-evidence"
            canLoad -> "load-advertised-completed-session"
            else -> "new-interrupted-turn-project-evidence"
        }
        change(
            "agentIdentitySha256" to JsonPrimitive(identitySha256),
            "agentIdentity" to identityDocument,
            "decision" to JsonPrimitive(selected),
            "decisions" to appendBounded(state.getValue("decisions").jsonArray, buildJsonObject {
                put("decision", selected)
                put("previousSessionIdSha256", previous?.let { JsonPrimitive(sessionDigest(it.toByteArray())) } ?: JsonNull)
                put("conversationRestored", false)
            }),
        )
        return previous.takeIf { canLoad }
    }

    @Synchronized
    fun sessionReady(id: String, restored: Boolean) {
        require(id.isNotBlank() && id.toByteArray().size <= 4096) { "session reference exceeds its bound" }
        change(
            "sessionId" to JsonPrimitive(id),
            "conversationRestored" to JsonPrimitive(restored),
            "decisions" to JsonArray(state.getValue("decisions").jsonArray.mapIndexed { index, decision ->
                if (index == state.getValue("decisions").jsonArray.lastIndex)
                    JsonObject(decision.jsonObject + ("conversationRestored" to JsonPrimitive(restored))) else decision
            }),
            "phase" to JsonPrimitive("SESSION_READY"),
        )
    }

    @Synchronized
    fun loadFailed() = change(
        "phase" to JsonPrimitive("LOAD_FAILED"),
        "decision" to JsonPrimitive("load-failed-no-implicit-fallback"),
    )

    @Synchronized
    fun processStarting(requestSha256: String) {
        requireSessionDigest(requestSha256)
        change(
            "pendingRequestSha256" to JsonPrimitive(requestSha256),
            "cleanupVerified" to JsonPrimitive(false),
            "lastEventSequence" to JsonPrimitive(-1L),
        )
    }

    @Synchronized
    fun promptStarting() = change("phase" to JsonPrimitive("PROMPT_RUNNING"))

    @Synchronized
    fun event(event: AgentExecutionEvent) {
        require(event.sequence > lastDurableEventSequence) { "session events must be strictly ordered" }
        change("lastEventSequence" to JsonPrimitive(event.sequence))
    }

    /** Called only after the invocation's process, filesystem and terminal cleanup have completed. */
    @Synchronized
    fun finishTurn(receipt: AgentExecutionReceipt, cleanupVerified: Boolean) {
        val requestSha256 = receipt.requestBinding.requestSha256
        require(state.optionalText("pendingRequestSha256") == requestSha256) { "session receipt belongs to another request" }
        val returned = (receipt.outcome as? AgentExecutionOutcome.Returned)?.result
        val finished = cleanupVerified && returned?.stopReason in setOf(AgentStopReason.COMPLETED, AgentStopReason.NO_CHANGES)
        val phase = if (state.optionalText("phase") in setOf("LOAD_FAILED", "QUARANTINED")) state.optionalText("phase")!!
            else if (finished) "TURN_FINISHED" else "TURN_INTERRUPTED"
        val updates = linkedMapOf<String, JsonElement>(
            "cleanupVerified" to JsonPrimitive(cleanupVerified),
            "phase" to JsonPrimitive(phase),
        )
        if (finished) updates["turns"] = appendBounded(state.getValue("turns").jsonArray, buildJsonObject {
            put("requestSha256", requestSha256)
            put("sessionId", requireNotNull(sessionId))
            put("lastEventSequence", lastDurableEventSequence)
            put("outcome", requireNotNull(returned).stopReason.name)
        })
        change(*updates.entries.map { it.key to it.value }.toTypedArray())
    }

    private fun quarantine(reason: String) = change(
        "phase" to JsonPrimitive("QUARANTINED"),
        "decision" to JsonPrimitive(reason),
    )

    @Synchronized
    private fun change(vararg values: Pair<String, JsonElement>) {
        requireCurrent()
        val next = JsonObject(state.toMutableMap().apply { values.forEach { (key, value) -> this[key] = value } })
        val bytes = encoded(next)
        require(bytes.size <= MAXIMUM_BYTES) { "session journal exceeds its durable byte bound" }
        atomicWrite(path, bytes)
        state = next
        requireCurrent()
    }

    private fun requireCurrent() {
        check(!closed) { "session journal is closed" }
        check(lock.isValid && directoryKey == Files.readAttributes(continuation.directory, "basic:fileKey", NOFOLLOW_LINKS)["fileKey"]) {
            "session journal directory identity changed"
        }
        requirePrivate(continuation.directory, directory = true)
        val lockPath = continuation.directory.resolve("session.lock")
        requirePrivate(lockPath, directory = false)
        check(lockKey == Files.readAttributes(lockPath, "basic:fileKey", NOFOLLOW_LINKS)["fileKey"]) {
            "session journal lock identity changed"
        }
        requirePrivate(path, directory = false)
        check(Files.size(path) <= MAXIMUM_BYTES && Files.readAllBytes(path).contentEquals(encoded(state))) {
            "session journal changed outside its current owner"
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        try { lock.release() } finally { channel.close() }
    }

    companion object {
        private const val MAXIMUM_BYTES = 1024 * 1024
        private const val MAXIMUM_RECORDS = 256
        private val limits = StrictJsonLimits(maximumInputBytes = MAXIMUM_BYTES)
        private val keys = setOf(
            "schemaVersion", "workflowSha256", "taskId", "workspaceFiles", "acceptedRevisionSha256",
            "acceptedRequestSha256", "acceptedReceiptSha256", "agentIdentitySha256", "agentIdentity", "sessionId",
            "phase", "decision", "decisions", "conversationRestored", "cleanupVerified",
            "pendingRequestSha256", "lastEventSequence", "turns",
        )

        fun open(continuation: AgentSessionContinuation): AgentSessionJournal {
            createPrivateDirectory(continuation.directory)
            val key = Files.readAttributes(continuation.directory, "basic:fileKey", NOFOLLOW_LINKS)["fileKey"]
            val lockPath = continuation.directory.resolve("session.lock")
            val channel = FileChannel.open(lockPath, setOf(CREATE, WRITE, NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            val lock = try {
                requirePrivate(lockPath, directory = false)
                requireNotNull(channel.tryLock()) { "another process owns this ACP session journal" }
            }
                catch (failure: Throwable) { channel.close(); throw failure }
            try {
                // An interrupted publication is unresolved evidence, even if the old record reads.
                for (name in listOf("session.json.pending", "quarantine.json.pending")) {
                    require(!Files.exists(continuation.directory.resolve(name), NOFOLLOW_LINKS)) {
                        "incomplete session publication requires inspection"
                    }
                }
                val path = continuation.directory.resolve("session.json")
                val state = if (Files.exists(path, NOFOLLOW_LINKS)) {
                    requirePrivate(path, directory = false)
                    require(Files.size(path) <= MAXIMUM_BYTES) { "session journal exceeds its byte bound" }
                    val parsed = OracleJson.parseCanonical(Files.readAllBytes(path), limits).jsonObject
                    require(parsed.keys == keys + "sha256") { "session journal has unknown or missing fields" }
                    val inner = JsonObject(parsed - "sha256")
                    require(parsed.getValue("sha256").jsonPrimitive.content == sessionDigest(OracleJson.canonicalBytes(inner))) {
                        "session journal commitment mismatch"
                    }
                    require(inner.getValue("schemaVersion") == JsonPrimitive(1))
                    require(inner.getValue("turns").jsonArray.size <= MAXIMUM_RECORDS && inner.getValue("decisions").jsonArray.size <= MAXIMUM_RECORDS)
                    parseFiles(inner.getValue("workspaceFiles").jsonArray)
                    require(inner.getValue("workflowSha256").jsonPrimitive.content == continuation.workflowSha256 &&
                        inner.getValue("taskId").jsonPrimitive.content == continuation.taskId) {
                        "session journal belongs to a different workflow or task"
                    }
                    inner
                } else buildJsonObject {
                    put("schemaVersion", 1)
                    put("workflowSha256", continuation.workflowSha256)
                    put("taskId", continuation.taskId)
                    put("workspaceFiles", filesJson(continuation.workspaceFiles))
                    put("acceptedRevisionSha256", continuation.acceptedRevisionSha256?.let(::JsonPrimitive) ?: JsonNull)
                    listOf("acceptedRequestSha256", "acceptedReceiptSha256", "agentIdentitySha256", "agentIdentity", "sessionId", "decision", "pendingRequestSha256").forEach { put(it, JsonNull) }
                    put("phase", "NEW")
                    put("decisions", JsonArray(emptyList()))
                    put("conversationRestored", false)
                    put("cleanupVerified", true)
                    put("lastEventSequence", -1L)
                    put("turns", JsonArray(emptyList()))
                }.also {
                    val bytes = encoded(it)
                    require(bytes.size <= MAXIMUM_BYTES) { "initial session inventory exceeds the durable journal byte bound" }
                    atomicWrite(path, bytes)
                }
                return AgentSessionJournal(continuation, channel, lock, key,
                    Files.readAttributes(lockPath, "basic:fileKey", NOFOLLOW_LINKS)["fileKey"], state)
            } catch (failure: Throwable) { lock.release(); channel.close(); throw failure }
        }

        /**
         * The workflow calls this only after independently verifying the accepted checkpoint and
         * its invocation receipt. Replaying the same acceptance after a crash is a zero-write no-op.
         */
        fun recordAcceptance(
            continuation: AgentSessionContinuation,
            roots: List<AgentWorkspaceRoot>,
            requestSha256: String,
            receiptSha256: String,
            acceptedRevisionSha256: String,
        ) {
            listOf(requestSha256, receiptSha256, acceptedRevisionSha256).forEach(::requireSessionDigest)
            if (!Files.exists(continuation.directory.resolve("session.json"), NOFOLLOW_LINKS)) return
            open(continuation).use { journal ->
                require(continuation.acceptedRevisionSha256 == acceptedRevisionSha256) { "acceptance identity differs from continuation" }
                require(captureWorkspaceFiles(continuation.workspaceFiles.keys, roots) == continuation.workspaceFiles) {
                    "accepted source differs from its independently validated checkpoint"
                }
                val state = journal.state
                require(state.optionalText("phase") !in setOf("QUARANTINED", "LOAD_FAILED")) { "session requires recovery before acceptance" }
                if (state.optionalText("acceptedRequestSha256") == requestSha256 &&
                    state.optionalText("acceptedRevisionSha256") == acceptedRevisionSha256 &&
                    state.optionalText("acceptedReceiptSha256") == receiptSha256
                ) {
                    require(parseFiles(state.getValue("workspaceFiles").jsonArray) == continuation.workspaceFiles) {
                        "replayed acceptance inventory differs from its durable acknowledgement"
                    }
                    return
                }
                require(state.getValue("cleanupVerified").jsonPrimitive.boolean &&
                    state.optionalText("pendingRequestSha256") == requestSha256 &&
                    state.getValue("turns").jsonArray.any { it.jsonObject.getValue("requestSha256").jsonPrimitive.content == requestSha256 }) {
                    "accepted checkpoint has no matching completed cleanup-verified session turn"
                }
                journal.change(
                    "phase" to JsonPrimitive("ACCEPTED"),
                    "workspaceFiles" to filesJson(continuation.workspaceFiles),
                    "acceptedRevisionSha256" to JsonPrimitive(acceptedRevisionSha256),
                    "acceptedRequestSha256" to JsonPrimitive(requestSha256),
                    "acceptedReceiptSha256" to JsonPrimitive(receiptSha256),
                )
            }
        }

        /** A rejected candidate changes no accepted identity, but may leave a workflow-authored baseline. */
        fun recordRejection(
            continuation: AgentSessionContinuation,
            roots: List<AgentWorkspaceRoot>,
            requestSha256: String,
        ) {
            if (!Files.exists(continuation.directory.resolve("session.json"), NOFOLLOW_LINKS)) return
            open(continuation).use { journal ->
                require(journal.state.optionalText("phase") !in setOf("QUARANTINED", "LOAD_FAILED")) { "session requires recovery before rejection" }
                require(journal.state.getValue("cleanupVerified").jsonPrimitive.boolean &&
                    journal.state.optionalText("pendingRequestSha256") == requestSha256) {
                    "rejected checkpoint has no matching cleanup-verified invocation"
                }
                require(captureWorkspaceFiles(continuation.workspaceFiles.keys, roots) == continuation.workspaceFiles)
                journal.change("workspaceFiles" to filesJson(continuation.workspaceFiles))
            }
        }

        private fun encoded(state: JsonObject): ByteArray = OracleJson.canonicalBytes(JsonObject(state + (
            "sha256" to JsonPrimitive(sessionDigest(OracleJson.canonicalBytes(state)))
        )))

        private fun appendBounded(array: JsonArray, value: JsonObject): JsonArray {
            require(array.size < MAXIMUM_RECORDS) { "session history is full; retain it and start a distinct workflow" }
            return JsonArray(array + value)
        }

        private fun atomicWrite(path: Path, bytes: ByteArray) {
            val temporary = path.resolveSibling(path.fileName.toString() + ".pending")
            require(!Files.exists(temporary, NOFOLLOW_LINKS)) { "incomplete session publication requires inspection" }
            FileChannel.open(temporary, CREATE_NEW, WRITE, NOFOLLOW_LINKS).use { channel ->
                Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("rw-------"))
                val buffer = ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) channel.write(buffer)
                channel.force(true)
            }
            Files.move(temporary, path, ATOMIC_MOVE, REPLACE_EXISTING)
            FileChannel.open(path.parent, READ).use { it.force(true) }
        }

        private fun createPrivateDirectory(path: Path) {
            var current = path.root
            path.forEach { part ->
                current = current.resolve(part)
                require(!Files.isSymbolicLink(current)) { "session directory has a linked ancestor" }
            }
            Files.createDirectories(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            requirePrivate(path, directory = true)
        }

        private fun requirePrivate(path: Path, directory: Boolean) {
            val attributes = Files.readAttributes(path, "unix:mode,nlink", NOFOLLOW_LINKS)
            val mode = (attributes["mode"] as Number).toInt()
            require(!Files.isSymbolicLink(path) && if (directory) Files.isDirectory(path, NOFOLLOW_LINKS) else Files.isRegularFile(path, NOFOLLOW_LINKS))
            require(mode and 0x3f == 0 && (directory || (attributes["nlink"] as Number).toLong() == 1L)) {
                "session evidence must have private permissions and unaliased files"
            }
        }

        /** At most 32 MiB across the inventory, 16 MiB per member, checked every 64 KiB. */
        fun captureWorkspaceFiles(
            files: Collection<AgentWorkspacePath>,
            roots: List<AgentWorkspaceRoot>,
            checkActive: () -> Unit = {},
        ): Map<AgentWorkspacePath, String?> {
            require(files.size in 1..4096 && files.distinct().size == files.size)
            var remaining = 32L * 1024 * 1024
            val started = System.nanoTime()
            fun checkBudget() {
                checkActive()
                check(System.nanoTime() - started < 10_000_000_000L) { "session inventory exceeded its ten-second deadline" }
            }
            return files.associateWith { file ->
                checkBudget()
                val path = file.resolve(roots)
                var ancestor = path.root
                path.forEach { part ->
                    ancestor = ancestor.resolve(part)
                    require(!Files.isSymbolicLink(ancestor)) { "session workspace evidence has a linked ancestor" }
                }
                if (!Files.exists(path, NOFOLLOW_LINKS)) null else {
                    require(Files.isRegularFile(path, NOFOLLOW_LINKS)) { "session workspace member is not a regular file" }
                    val expected = Files.size(path)
                    require(expected <= 16L * 1024 * 1024 && expected <= remaining) { "session workspace exceeds its aggregate or per-file byte bound" }
                    val digest = MessageDigest.getInstance("SHA-256")
                    var observed = 0L
                    FileChannel.open(path, READ, NOFOLLOW_LINKS).use { input ->
                        val buffer = ByteBuffer.allocate(64 * 1024)
                        while (true) {
                            checkBudget()
                            buffer.clear()
                            val count = input.read(buffer)
                            if (count < 0) break
                            observed += count
                            remaining -= count
                            require(observed <= 16L * 1024 * 1024 && remaining >= 0) { "session workspace grew beyond its hash budget" }
                            buffer.flip()
                            digest.update(buffer)
                        }
                    }
                    require(observed == expected && Files.size(path) == expected) { "session workspace changed during hashing" }
                    digest.digest().joinToString("") { "%02x".format(it) }
                }
            }
        }
    }
}

private fun filesJson(files: Map<AgentWorkspacePath, String?>): JsonArray = JsonArray(
    files.entries.sortedWith(compareBy({ it.key.rootId }, { it.key.relativePath })).map { (file, digest) ->
        buildJsonObject {
            put("rootId", file.rootId)
            put("path", file.relativePath)
            put("sha256", digest?.let(::JsonPrimitive) ?: JsonNull)
        }
    },
)

private fun parseFiles(array: JsonArray): Map<AgentWorkspacePath, String?> {
    require(array.size in 1..4096)
    val result = linkedMapOf<AgentWorkspacePath, String?>()
    array.forEach { element ->
        val item = element.jsonObject
        require(item.keys == setOf("rootId", "path", "sha256"))
        val path = AgentWorkspacePath(item.getValue("rootId").jsonPrimitive.content, item.getValue("path").jsonPrimitive.content)
        val digest = item.optionalText("sha256")
        digest?.let(::requireSessionDigest)
        require(path !in result)
        result[path] = digest
    }
    require(filesJson(result) == array) { "session file inventory is not canonical" }
    return result
}

private fun JsonObject.optionalText(key: String): String? = getValue(key).let {
    if (it == JsonNull) null else it.jsonPrimitive.content
}
private fun requireSessionDigest(value: String) = require(value.matches(Regex("[a-f0-9]{64}"))) { "invalid session digest" }
private fun sessionDigest(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
