package decompengine.agent

import java.nio.file.Path
import java.time.Duration
import java.util.Collections
import java.util.concurrent.atomic.AtomicBoolean

const val AGENT_EXECUTION_CONTRACT_VERSION: Int = 1

/** A named workspace made available to an agent. Paths are canonicalized before a request is created. */
data class AgentWorkspaceRoot(
    val id: String,
    val path: Path,
) {
    init {
        require(id.matches(Regex("[A-Za-z][A-Za-z0-9._-]*"))) { "workspace root id is invalid: $id" }
        require(path.isAbsolute) { "workspace root must be absolute: $path" }
        require(path == path.normalize()) { "workspace root must be normalized: $path" }
    }
}

/** A transport-neutral path. It never carries a host path outside a declared workspace root. */
data class AgentWorkspacePath(
    val rootId: String,
    val relativePath: String,
) {
    init {
        require(rootId.isNotBlank()) { "workspace path root id must not be blank" }
        require(relativePath.isNotBlank()) { "workspace relative path must not be blank" }
        val path = Path.of(relativePath)
        require(!path.isAbsolute) { "workspace path must be relative: $relativePath" }
        require(path.normalize().toString() == relativePath && !path.startsWith("..")) {
            "workspace path must be normalized and contained: $relativePath"
        }
    }

    fun resolve(roots: Collection<AgentWorkspaceRoot>): Path {
        val root = roots.singleOrNull { it.id == rootId }
            ?: throw IllegalArgumentException("unknown workspace root: $rootId")
        val resolved = root.path.resolve(relativePath).normalize()
        require(resolved.startsWith(root.path)) { "workspace path escapes root $rootId: $relativePath" }
        return resolved
    }
}

enum class AgentOperation {
    READ_FILE,
    WRITE_FILE,
    CREATE_FILE,
    DELETE_FILE,
    EXECUTE_COMMAND,
    REQUEST_PERMISSION,
    ACCESS_NETWORK,
}

class AgentPathRule(
    val path: AgentWorkspacePath,
    operations: Collection<AgentOperation>,
    val recursive: Boolean = false,
) {
    val operations: Set<AgentOperation> = immutableSet(operations)

    init {
        require(this.operations.isNotEmpty()) { "path rule operations must not be empty" }
        require(this.operations.all { it in FILE_OPERATIONS }) {
            "path rules may contain only file operations"
        }
    }

    internal fun matches(candidate: AgentWorkspacePath, operation: AgentOperation): Boolean {
        if (candidate.rootId != path.rootId || operation !in operations) return false
        if (!recursive) return candidate.relativePath == path.relativePath
        return Path.of(candidate.relativePath).startsWith(Path.of(path.relativePath))
    }

    private companion object {
        val FILE_OPERATIONS = setOf(
            AgentOperation.READ_FILE,
            AgentOperation.WRITE_FILE,
            AgentOperation.CREATE_FILE,
            AgentOperation.DELETE_FILE,
        )
    }
}

class AgentAccessPolicy(
    pathRules: Collection<AgentPathRule>,
    allowedOperations: Collection<AgentOperation> = pathRules.flatMap { it.operations }.toSet(),
) {
    val pathRules: List<AgentPathRule> = immutableList(pathRules)
    val allowedOperations: Set<AgentOperation> = immutableSet(allowedOperations)

    init {
        require(this.pathRules.flatMap { it.operations }.all { it in this.allowedOperations }) {
            "path rule grants an operation absent from the global allowlist"
        }
    }

    fun allows(path: AgentWorkspacePath, operation: AgentOperation): Boolean =
        operation in allowedOperations && pathRules.any { it.matches(path, operation) }
}

/** Context is copied into the request as immutable text and is never a writable workspace artifact. */
data class AgentContextInput(
    val id: String,
    val content: String,
    val mediaType: String = "text/plain",
    val description: String? = null,
) {
    init {
        require(id.isNotBlank()) { "context input id must not be blank" }
        require(mediaType.isNotBlank()) { "context input media type must not be blank" }
    }
}

data class AgentExecutionLimits(
    val wallClockTimeout: Duration = Duration.ofMinutes(20),
    val idleTimeout: Duration = Duration.ofMinutes(2),
    val maxTurns: Int = 64,
    val maxToolCalls: Int = 256,
    val maxOutputBytes: Long = 8L * 1024 * 1024,
    val maxInputTokens: Long? = null,
    val maxOutputTokens: Long? = null,
) {
    init {
        require(!wallClockTimeout.isZero && !wallClockTimeout.isNegative) { "wall-clock timeout must be positive" }
        require(!idleTimeout.isZero && !idleTimeout.isNegative) { "idle timeout must be positive" }
        require(maxTurns > 0) { "maximum turns must be positive" }
        require(maxToolCalls > 0) { "maximum tool calls must be positive" }
        require(maxOutputBytes > 0) { "maximum output bytes must be positive" }
        require(maxInputTokens == null || maxInputTokens > 0) { "maximum input tokens must be positive" }
        require(maxOutputTokens == null || maxOutputTokens > 0) { "maximum output tokens must be positive" }
    }
}

fun interface AgentCancellation {
    fun isCancellationRequested(): Boolean

    companion object {
        val NONE = AgentCancellation { false }
    }
}

class AgentCancellationSource {
    private val cancelled = AtomicBoolean(false)
    val cancellation: AgentCancellation = AgentCancellation(cancelled::get)

    fun cancel(): Boolean = cancelled.compareAndSet(false, true)
}

enum class AgentWorkflow { REPAIR, RECONSTRUCTION }

/** Workflow-owned lineage. A captured subset of source files is not an accepted project revision. */
data class AgentWorkflowIdentity(
    val workflow: AgentWorkflow,
    val taskId: String,
    val acceptedRevisionSha256: String,
    val promptSha256: String,
) {
    val schemaVersion: Int = 1

    init {
        require(taskId.matches(Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"))) { "invalid workflow task identity" }
        require(listOf(acceptedRevisionSha256, promptSha256).all { it.matches(Regex("[a-f0-9]{64}")) }) {
            "invalid workflow lineage digest"
        }
    }
}

class AgentExecutionRequest(
    val objective: String,
    workspaceRoots: Collection<AgentWorkspaceRoot>,
    contextInputs: Collection<AgentContextInput> = emptyList(),
    val accessPolicy: AgentAccessPolicy,
    val limits: AgentExecutionLimits = AgentExecutionLimits(),
    val cancellation: AgentCancellation = AgentCancellation.NONE,
    val workflowIdentity: AgentWorkflowIdentity? = null,
) {
    val schemaVersion: Int = AGENT_EXECUTION_CONTRACT_VERSION
    val workspaceRoots: List<AgentWorkspaceRoot> = immutableList(workspaceRoots)
    val contextInputs: List<AgentContextInput> = immutableList(contextInputs)

    init {
        require(objective.isNotBlank()) { "agent objective must not be blank" }
        require(this.workspaceRoots.isNotEmpty()) { "agent request must declare at least one workspace root" }
        require(this.workspaceRoots.map { it.id }.distinct().size == this.workspaceRoots.size) {
            "workspace root ids must be unique"
        }
        require(this.contextInputs.map { it.id }.distinct().size == this.contextInputs.size) {
            "context input ids must be unique"
        }
        val rootIds = this.workspaceRoots.mapTo(mutableSetOf()) { it.id }
        require(accessPolicy.pathRules.all { it.path.rootId in rootIds }) {
            "access policy references an unknown workspace root"
        }
    }
}

data class AgentSessionReference(
    val harnessId: String,
    val sessionId: String,
    val resumeReference: String? = null,
) {
    init {
        require(harnessId.isNotBlank()) { "session harness id must not be blank" }
        require(sessionId.isNotBlank()) { "session id must not be blank" }
    }
}

enum class AgentMessageRole { ASSISTANT, USER, SYSTEM }

sealed interface AgentExecutionEvent {
    val sequence: Long
}

data class AgentMessageEvent(
    override val sequence: Long,
    val messageId: String,
    val role: AgentMessageRole,
    val textDelta: String,
    val completed: Boolean = false,
) : AgentExecutionEvent {
    init {
        require(sequence >= 0) { "event sequence must not be negative" }
        require(messageId.isNotBlank()) { "message id must not be blank" }
    }
}

enum class AgentPlanStatus { PENDING, IN_PROGRESS, COMPLETED, CANCELLED }

data class AgentPlanEntry(
    val id: String,
    val description: String,
    val status: AgentPlanStatus,
) {
    init {
        require(id.isNotBlank()) { "plan entry id must not be blank" }
        require(description.isNotBlank()) { "plan entry description must not be blank" }
    }
}

class AgentPlanEvent(
    override val sequence: Long,
    entries: Collection<AgentPlanEntry>,
) : AgentExecutionEvent {
    val entries: List<AgentPlanEntry> = immutableList(entries)

    init {
        require(sequence >= 0) { "event sequence must not be negative" }
        require(this.entries.isNotEmpty()) { "plan update must include at least one entry" }
    }
}

enum class AgentToolStatus { PENDING, IN_PROGRESS, SUCCEEDED, FAILED, CANCELLED }

class AgentToolEvent(
    override val sequence: Long,
    val toolCallId: String,
    val title: String,
    val status: AgentToolStatus,
    details: Map<String, String> = emptyMap(),
) : AgentExecutionEvent {
    val details: Map<String, String> = immutableMap(details)

    init {
        require(sequence >= 0) { "event sequence must not be negative" }
        require(toolCallId.isNotBlank()) { "tool call id must not be blank" }
        require(title.isNotBlank()) { "tool title must not be blank" }
    }
}

enum class AgentPermissionDecision { ALLOW_ONCE, ALLOW_SESSION, DENY, CANCELLED }

data class AgentPermissionEvent(
    override val sequence: Long,
    val requestId: String,
    val decision: AgentPermissionDecision,
    val selectedOptionId: String? = null,
    val reason: String? = null,
) : AgentExecutionEvent {
    init {
        require(sequence >= 0) { "event sequence must not be negative" }
        require(requestId.isNotBlank()) { "permission request id must not be blank" }
    }
}

enum class AgentFileChangeKind { CREATED, MODIFIED, DELETED }

data class AgentFileChange(
    val path: AgentWorkspacePath,
    val kind: AgentFileChangeKind,
    val beforeSha256: String?,
    val afterSha256: String?,
    val sizeBytes: Long? = null,
) {
    init {
        require(beforeSha256 == null || beforeSha256.isSha256()) { "before digest must be SHA-256" }
        require(afterSha256 == null || afterSha256.isSha256()) { "after digest must be SHA-256" }
        require(sizeBytes == null || sizeBytes >= 0) { "changed file size must not be negative" }
        when (kind) {
            AgentFileChangeKind.CREATED -> require(beforeSha256 == null && afterSha256 != null) {
                "created files require only an after digest"
            }
            AgentFileChangeKind.MODIFIED -> require(beforeSha256 != null && afterSha256 != null && beforeSha256 != afterSha256) {
                "modified files require distinct before and after digests"
            }
            AgentFileChangeKind.DELETED -> require(beforeSha256 != null && afterSha256 == null) {
                "deleted files require only a before digest"
            }
        }
    }
}

data class AgentFileChangeEvent(
    override val sequence: Long,
    val change: AgentFileChange,
) : AgentExecutionEvent {
    init {
        require(sequence >= 0) { "event sequence must not be negative" }
    }
}

enum class AgentStopReason { COMPLETED, NO_CHANGES, REFUSED, CANCELLED, LIMIT_EXHAUSTED }

data class AgentUsage(
    val inputTokens: Long? = null,
    val outputTokens: Long? = null,
    val cachedInputTokens: Long? = null,
    val toolCalls: Int? = null,
    val wallClock: Duration? = null,
) {
    init {
        require(listOfNotNull(inputTokens, outputTokens, cachedInputTokens).all { it >= 0 }) {
            "token usage must not be negative"
        }
        require(toolCalls == null || toolCalls >= 0) { "tool-call usage must not be negative" }
        require(wallClock == null || !wallClock.isNegative) { "wall-clock usage must not be negative" }
    }
}

class AgentExecutionResult(
    val stopReason: AgentStopReason,
    val summary: String? = null,
    changes: Collection<AgentFileChange> = emptyList(),
    val session: AgentSessionReference? = null,
    val usage: AgentUsage? = null,
) {
    val changes: List<AgentFileChange> = immutableList(changes)

    init {
        require(this.changes.map { it.path }.distinct().size == this.changes.size) {
            "an execution result may report each workspace path only once"
        }
        require(stopReason != AgentStopReason.NO_CHANGES || this.changes.isEmpty()) {
            "a no-change result cannot report file changes"
        }
    }
}

enum class AgentFailureKind {
    INVALID_REQUEST,
    CONFIGURATION,
    AUTHENTICATION,
    AUTHORIZATION,
    UNAVAILABLE,
    TRANSPORT,
    PROTOCOL,
    WORKSPACE_VIOLATION,
    TIMEOUT,
    PROCESS_CRASH,
    RESOURCE_EXHAUSTED,
    INTERNAL,
}

class AgentFailure(
    val kind: AgentFailureKind,
    val message: String,
    val retryable: Boolean = false,
    val session: AgentSessionReference? = null,
    details: Map<String, String> = emptyMap(),
) {
    val details: Map<String, String> = immutableMap(details)

    init {
        require(message.isNotBlank()) { "agent failure message must not be blank" }
    }
}

class AgentExecutionException(
    val failure: AgentFailure,
    cause: Throwable? = null,
    val receipt: AgentExecutionReceipt? = null,
) : RuntimeException(failure.message, cause)

fun interface AgentHarness {
    fun execute(
        request: AgentExecutionRequest,
        onEvent: (AgentExecutionEvent) -> Unit,
    ): AgentExecutionResult

    /**
     * Executes one request and returns its terminal outcome together with evidence produced by the
     * same invocation. Providers override this method when they can supply provider evidence.
     *
     * The default preserves the version-1 SAM surface for legacy harnesses. It deliberately wraps
     * ordinary exceptions as evidence-free failures so production callers never need a racy
     * post-execution lookup merely to retain a terminal outcome.
     */
    fun executeReceipt(
        request: AgentExecutionRequest,
        onEvent: (AgentExecutionEvent) -> Unit,
    ): AgentExecutionReceipt = captureAgentExecutionReceipt(request) {
        execute(request, onEvent)
    }

    fun implementationIdentifier(): String? = null
}

fun AgentHarness.execute(request: AgentExecutionRequest): AgentExecutionResult = execute(request) { }

fun AgentHarness.executeReceipt(request: AgentExecutionRequest): AgentExecutionReceipt =
    executeReceipt(request) { }

private fun String.isSha256(): Boolean = length == 64 && all { it in '0'..'9' || it in 'a'..'f' }

private fun <T> immutableList(values: Collection<T>): List<T> =
    Collections.unmodifiableList(ArrayList(values))

private fun <T> immutableSet(values: Collection<T>): Set<T> =
    Collections.unmodifiableSet(LinkedHashSet(values))

private fun <K, V> immutableMap(values: Map<K, V>): Map<K, V> =
    Collections.unmodifiableMap(LinkedHashMap(values))
