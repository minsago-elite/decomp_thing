package decompengine.jobs

import decompengine.agent.*
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.CREATE
import java.nio.file.StandardOpenOption.WRITE
import java.security.MessageDigest
import java.time.Instant
import java.util.ArrayDeque
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference

/**
 * Bounded display projection of the workflow's separate authoritative invocation receipts.
 * Callbacks only normalize and enqueue; one owned writer publishes atomic snapshots. An overloaded
 * view drops records with explicit sequence gaps and counters, never backpressures protocol I/O.
 */
class AgentProgressJournal(
    private val reportsDirectory: Path,
    private val workflow: String,
    sensitiveValues: Collection<String> = emptyList(),
    private val maximumEvents: Int = 256,
    private val maximumQueuedEvents: Int = 128,
    private val maximumSnapshotBytes: Int = 512 * 1024,
    private val onPhase: (AgentWorkflowPhase) -> Unit = {},
) : AgentWorkflowProgress, AutoCloseable {
    private val monitor = Object()
    private val queue = ArrayDeque<JsonObject>()
    private val retained = ArrayDeque<JsonObject>()
    private val redactor = ProgressRedactor(sensitiveValues)
    private val failure = AtomicReference<Throwable?>()
    private val runId = UUID.randomUUID().toString()
    private var sequence = 0L
    private var queueDropped = 0L
    private var historyDropped = 0L
    private var closed = false
    private var dirty = false
    private val lockChannel: FileChannel
    private val writerLock: java.nio.channels.FileLock
    private val writer: Thread

    init {
        require(workflow.matches(Regex("[a-z][a-z0-9-]{0,63}"))) { "invalid progress workflow" }
        require(maximumEvents in 1..1024 && maximumQueuedEvents in 1..1024)
        require(maximumSnapshotBytes in 4096..MAXIMUM_READ_BYTES)
        Files.createDirectories(reportsDirectory)
        lockChannel = FileChannel.open(reportsDirectory.resolve("agent-progress.lock"), CREATE, WRITE, NOFOLLOW_LINKS)
        writerLock = try {
            requireNotNull(lockChannel.tryLock()) { "another workflow owns the progress journal" }
        } catch (problem: Throwable) {
            lockChannel.close()
            throw problem
        }
        try {
            val previous = read(reportsDirectory)
            if (previous != null) {
                sequence = previous.getValue("nextSequence").jsonPrimitive.long
                queueDropped = previous.getValue("queueDropped").jsonPrimitive.long
                historyDropped = previous.getValue("historyDropped").jsonPrimitive.long
                previous.getValue("events").jsonArray.forEach { retained.add(it.jsonObject) }
                while (retained.size > maximumEvents) { retained.removeFirst(); historyDropped++ }
            }
            writer = Thread(::writeLoop, "decomp-progress-$workflow").apply { isDaemon = true; start() }
            enqueue("run_started") { put("status", "running") }
        } catch (problem: Throwable) {
            writerLock.release()
            lockChannel.close()
            throw problem
        }
    }

    override fun beginTask(taskId: String, request: AgentExecutionRequest): AgentTaskProgress =
        beginCorrelatedTask(taskId, request, null)

    override fun beginTask(taskId: String, request: AgentExecutionRequest, workflowRunId: String): AgentTaskProgress {
        require(workflowRunId.isNotBlank() && workflowRunId.length <= 4096)
        return beginCorrelatedTask(taskId, request, workflowRunId)
    }

    private fun beginCorrelatedTask(taskId: String, request: AgentExecutionRequest, workflowRunId: String?): AgentTaskProgress {
        val safeTaskId = redactor.text(taskId)
        val binding = AgentExecutionRequestBinding.capture(request)
        val turnId = UUID.randomUUID().toString()
        fun post(kind: String, body: JsonObjectBuilder.() -> Unit) = enqueue(kind) {
            put("taskId", safeTaskId)
            put("taskIdSha256", digest(taskId))
            put("turnId", turnId)
            put("requestSha256", binding.requestSha256)
            workflowRunId?.let { put("workflowRunId", redactor.text(it)); put("workflowRunIdSha256", digest(it)) }
            body()
        }
        post("task_started") { put("phase", "agent_running") }
        return object : AgentTaskProgress {
            private var finished = false
            private var previousSequence = -1L
            // Raw chunks stay bounded and are not persisted. Whole-message redaction prevents a
            // credential split across chunks from leaking a prefix through the live projection.
            private val messages = linkedMapOf<String, StringBuilder?>()
            // Once an untracked message has lost a prefix, later capacity must not admit its
            // continuation as a complete message. Fail closed for new IDs for this task.
            private var messageAdmissionExhausted = false

            @Synchronized
            override fun event(event: AgentExecutionEvent) {
                check(!finished) { "progress received an event after task completion" }
                require(event.sequence > previousSequence) { "progress events must be ordered" }
                val gap = event.sequence != previousSequence + 1
                previousSequence = event.sequence
                if (gap) {
                    messages.replaceAll { _, _ -> null }
                    messageAdmissionExhausted = true
                }
                post(when (event) {
                    is AgentMessageEvent -> "message"
                    is AgentContextUsageEvent -> "context_usage"
                    is AgentPlanEvent -> "plan"
                    is AgentToolEvent -> "tool"
                    is AgentPermissionEvent -> "permission"
                    is AgentFileChangeEvent -> "file_change"
                }) {
                    put("agentSequence", event.sequence)
                    put("sourceSequenceGap", gap)
                    when (event) {
                        is AgentContextUsageEvent -> {
                            // Decimal text preserves 64-bit counts in browser JSON consumers.
                            put("contextUsedTokens", event.usedTokens.toString())
                            put("contextWindowTokens", event.contextWindowTokens.toString())
                            event.costAmount?.let { put("reportedCostAmount", it.toString()) }
                            event.costCurrency?.let { put("reportedCostCurrency", redactor.text(it)) }
                        }
                        is AgentMessageEvent -> {
                            val messageIdDigest = digest(event.messageId)
                            val messageKey = event.role.name + ":" + messageIdDigest
                            put("messageIdSha256", messageIdDigest)
                            put("role", event.role.name.lowercase())
                            put("completed", event.completed)
                            put("chunkCharacters", event.textDelta.length)
                            put("contentSha256", digest(event.textDelta))
                            if (messageKey !in messages && !messageAdmissionExhausted) {
                                if (messages.size < 16) messages[messageKey] = StringBuilder()
                                else messageAdmissionExhausted = true
                            }
                            put("messageTrackingExhausted", messageAdmissionExhausted)
                            messages[messageKey]?.let { buffer ->
                                if (buffer.length.toLong() + event.textDelta.length > MAXIMUM_MESSAGE_CHARACTERS) {
                                    messages[messageKey] = null
                                } else buffer.append(event.textDelta)
                            }
                            if (event.completed) {
                                val message = messages.remove(messageKey)
                                put("textOmitted", message == null)
                                message?.let { put("text", redactor.text(it.toString())) }
                            }
                        }
                        is AgentPlanEvent -> {
                            put("entryCount", event.entries.size)
                            put("entriesTruncated", event.entries.size > 8)
                            put("entries", buildJsonArray {
                                event.entries.take(8).forEach { entry -> add(buildJsonObject {
                                    put("idSha256", digest(entry.id))
                                    put("status", entry.status.name.lowercase())
                                    put("text", redactor.text(entry.description, 160))
                                }) }
                            })
                        }
                        is AgentToolEvent -> {
                            put("toolCallIdSha256", digest(event.toolCallId))
                            put("status", event.status.name.lowercase())
                            put("text", redactor.text(event.title))
                        }
                        is AgentPermissionEvent -> {
                            put("permissionIdSha256", digest(event.requestId))
                            put("decision", event.decision.name.lowercase())
                            event.reason?.let { put("text", redactor.text(it)) }
                        }
                        is AgentFileChangeEvent -> {
                            put("path", redactor.text(event.change.path.relativePath))
                            put("change", event.change.kind.name.lowercase())
                            event.change.afterSha256?.let { put("afterSha256", it) }
                        }
                    }
                }
            }

            @Synchronized
            override fun complete(receipt: AgentExecutionReceipt) {
                check(!finished) { "progress task already completed" }
                require(receipt.requestBinding == binding) { "progress receipt belongs to another request" }
                finished = true
                messages.clear()
                post("agent_finished") {
                    put("validationPending", true)
                    when (val outcome = receipt.outcome) {
                        is AgentExecutionOutcome.Returned -> {
                            put("stopReason", outcome.result.stopReason.name.lowercase())
                            outcome.result.session?.let { put("sessionIdSha256", digest(it.sessionId)) }
                            outcome.result.usage?.let { usage ->
                                usage.inputTokens?.let { put("inputTokens", it) }
                                usage.outputTokens?.let { put("outputTokens", it) }
                                usage.cachedInputTokens?.let { put("cachedInputTokens", it) }
                                usage.toolCalls?.let { put("toolCalls", it) }
                                usage.wallClock?.let { put("wallClock", it.toString()) }
                            }
                        }
                        is AgentExecutionOutcome.Failed -> {
                            put("failureKind", outcome.failure.kind.name.lowercase())
                            outcome.failure.session?.let { put("sessionIdSha256", digest(it.sessionId)) }
                            // Arbitrary exception text can contain credentials; retain classification.
                        }
                    }
                }
            }
        }
    }

    override fun phase(phase: AgentWorkflowPhase, taskId: String?, acceptedRevisionSha256: String?) {
        require(acceptedRevisionSha256 == null || acceptedRevisionSha256.matches(Regex("[a-f0-9]{64}")))
        require(acceptedRevisionSha256 == null || phase == AgentWorkflowPhase.ACCEPTED)
        enqueue("workflow_phase") {
            put("phase", phase.name.lowercase())
            taskId?.let { put("taskId", redactor.text(it)); put("taskIdSha256", digest(it)) }
            acceptedRevisionSha256?.let { put("acceptedRevisionSha256", it) }
        }
        onPhase(phase)
    }

    override fun runState(observation: AgentWorkflowRunObservation) {
        enqueue("workflow_run_state") {
            put("phase", observation.phase.name.lowercase())
            put("workflowRunId", redactor.text(observation.workflowRunId))
            put("workflowRunIdSha256", digest(observation.workflowRunId))
            observation.revisionId?.let { put("revisionId", redactor.text(it)); put("revisionIdSha256", digest(it)) }
            observation.taskId?.let { put("taskId", redactor.text(it)); put("taskIdSha256", digest(it)) }
            observation.acceptedRevisionSha256?.let { put("acceptedRevisionSha256", it) }
        }
        onPhase(observation.phase)
    }

    private fun enqueue(kind: String, body: JsonObjectBuilder.() -> Unit) = synchronized(monitor) {
        check(!closed) { "progress journal is closed" }
        failure.get()?.let { throw IllegalStateException("progress journal persistence failed", it) }
        val record = buildJsonObject {
            put("sequence", sequence++)
            put("runId", runId)
            put("workflow", workflow)
            put("time", Instant.now().toString())
            put("kind", kind)
            body()
        }
        if (queue.size >= maximumQueuedEvents) queueDropped++ else queue.add(record)
        dirty = true
        monitor.notifyAll()
    }

    private fun writeLoop() {
        try {
            while (true) {
                val snapshot = synchronized(monitor) {
                    while (!dirty && !closed) monitor.wait()
                    if (!dirty && closed) return
                    while (queue.isNotEmpty()) retained.add(queue.removeFirst())
                    while (retained.size > maximumEvents) { retained.removeFirst(); historyDropped++ }
                    dirty = false
                    var bytes = snapshot().toString().toByteArray(Charsets.UTF_8)
                    while (bytes.size > maximumSnapshotBytes && retained.isNotEmpty()) {
                        retained.removeFirst(); historyDropped++
                        bytes = snapshot().toString().toByteArray(Charsets.UTF_8)
                    }
                    check(bytes.size <= maximumSnapshotBytes) { "progress snapshot exceeds its limit" }
                    bytes
                }
                val temporary = Files.createTempFile(reportsDirectory, ".agent-progress-", ".tmp")
                try {
                    FileChannel.open(temporary, WRITE, NOFOLLOW_LINKS).use { channel ->
                        val buffer = java.nio.ByteBuffer.wrap(snapshot)
                        while (buffer.hasRemaining()) channel.write(buffer)
                        channel.force(true)
                    }
                    Files.move(temporary, reportsDirectory.resolve(FILE_NAME), ATOMIC_MOVE, REPLACE_EXISTING)
                    FileChannel.open(reportsDirectory, java.nio.file.StandardOpenOption.READ).use { it.force(true) }
                } finally {
                    Files.deleteIfExists(temporary)
                }
            }
        } catch (problem: Throwable) { failure.set(problem) }
    }

    private fun snapshot(): JsonObject = buildJsonObject {
        put("schemaVersion", 1)
        put("displayOnly", true)
        put("nextSequence", sequence)
        put("queueDropped", queueDropped)
        put("historyDropped", historyDropped)
        put("truncated", queueDropped > 0 || historyDropped > 0)
        put("events", JsonArray(retained.toList()))
    }

    override fun close() {
        synchronized(monitor) { closed = true; monitor.notifyAll() }
        writer.join(5_000)
        // Do not release a lock while a live writer could still publish a snapshot.
        check(!writer.isAlive) { "progress writer did not stop within five seconds" }
        if (writerLock.isValid) writerLock.release()
        if (lockChannel.isOpen) lockChannel.close()
        failure.get()?.let { throw IllegalStateException("progress journal persistence failed", it) }
    }

    companion object {
        const val FILE_NAME = "agent-progress.json"
        internal const val MAXIMUM_READ_BYTES = 2 * 1024 * 1024
        private const val MAXIMUM_MESSAGE_CHARACTERS = 8192

        fun read(reportsDirectory: Path): JsonObject? {
            val path = reportsDirectory.resolve(FILE_NAME)
            if (!Files.exists(path, NOFOLLOW_LINKS)) return null
            require(Files.isRegularFile(path, NOFOLLOW_LINKS)) { "progress snapshot is not a regular file" }
            val bytes = Files.newInputStream(path, NOFOLLOW_LINKS).use { it.readNBytes(MAXIMUM_READ_BYTES + 1) }
            return decode(bytes)
        }

        /** Decode bytes already obtained through the caller's storage authority boundary.
         * This validates the bounded display journal, not workflow acceptance or event completeness.
         */
        internal fun decode(bytes: ByteArray): JsonObject {
            require(bytes.size <= MAXIMUM_READ_BYTES) { "progress snapshot exceeds the read limit" }
            val result = OracleJson.parse(bytes, StrictJsonLimits(
                maximumInputBytes = MAXIMUM_READ_BYTES,
                maximumCanonicalBytes = MAXIMUM_READ_BYTES,
                maximumDepth = 32,
                maximumNodes = 65_536,
                maximumStringBytes = 16 * 1024,
                maximumTotalStringBytes = MAXIMUM_READ_BYTES,
            )).jsonObject
            require(result.getValue("schemaVersion").jsonPrimitive.int == 1)
            require(result.getValue("displayOnly").jsonPrimitive.boolean)
            require(result.getValue("events").jsonArray.size <= 1024)
            val next = result.getValue("nextSequence").jsonPrimitive.long
            require(next >= 0 && next < Long.MAX_VALUE)
            val queueDropped = result.getValue("queueDropped").jsonPrimitive.long
            val historyDropped = result.getValue("historyDropped").jsonPrimitive.long
            val retainedCount = result.getValue("events").jsonArray.size.toLong()
            // Subtract only after checking bounds, so hostile counters cannot overflow a sum.
            require(queueDropped in 0..next && historyDropped in 0..(next - queueDropped)) {
                "progress snapshot contains invalid omission counts"
            }
            require(next - queueDropped - historyDropped == retainedCount) {
                "progress snapshot does not account for every sequence"
            }
            require(result.getValue("truncated").jsonPrimitive.boolean == (queueDropped > 0 || historyDropped > 0)) {
                "progress snapshot contains an inconsistent truncation marker"
            }
            var previous = -1L
            result.getValue("events").jsonArray.forEach {
                val sequence = it.jsonObject.getValue("sequence").jsonPrimitive.long
                require(sequence > previous && sequence < next) { "progress snapshot contains unordered events" }
                previous = sequence
            }
            // History eviction removes a prefix of admitted events. Any later gaps
            // must therefore be queue drops, never history drops.
            val firstRetained = result.getValue("events").jsonArray.firstOrNull()
                ?.jsonObject?.getValue("sequence")?.jsonPrimitive?.long ?: next
            require(historyDropped <= firstRetained) {
                "progress snapshot history omissions exceed the evicted prefix"
            }
            return result
        }

        private fun digest(text: String): String = MessageDigest.getInstance("SHA-256")
            .digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}

/** Bounded previews only; invocation artifacts continue to retain content commitments. */
internal class ProgressRedactor(values: Collection<String>) {
    private val secrets = values.filter { it.isNotBlank() }.distinct().sortedByDescending(String::length)
    init {
        require(secrets.size <= 4096 && secrets.sumOf { it.length.toLong() } <= 1024 * 1024) {
            "progress redaction values exceed the configured limit"
        }
    }

    fun text(value: String, maximumCharacters: Int = 512): String {
        // Do not take a raw prefix: that can expose a partial configured secret.
        if (value.length > 16_384) return "[oversized text omitted]"
        var safe = value
        secrets.forEach { safe = safe.replace(it, "[redacted]") }
        safe = safe.replace(Regex("(?i)(bearer\\s+)[^\\s,;]+"), "$1[redacted]")
            .replace(Regex("(?i)((?:api[_-]?key|access[_-]?token|password|secret|authorization)\\s*[:=]\\s*)[^\\s,;]+"), "$1[redacted]")
            .replace(Regex("(?:sk-|ghp_|github_pat_)[A-Za-z0-9_-]+"), "[redacted]")
            .replace(Regex("[\\p{Cntrl}&&[^\\n\\t]]"), "")
        return if (safe.length <= maximumCharacters) safe else safe.take(maximumCharacters) + "… [preview truncated]"
    }
}
