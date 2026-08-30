package decompengine.acp

import com.agentclientprotocol.model.FileSystemCapability
import com.agentclientprotocol.model.ReadTextFileResponse
import com.agentclientprotocol.model.WriteTextFileResponse
import com.agentclientprotocol.protocol.AcpExpectedError
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentOperation
import decompengine.agent.AgentWorkspacePath
import decompengine.repair.BoundedRepairOutput
import decompengine.repair.RepairBudgetExceededException
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.InvalidPathException
import java.nio.file.Path
import java.security.MessageDigest
import java.util.TreeMap

/**
 * Namespace-only workspace path used by captured ACP repair.
 *
 * The production outer sandbox creates an empty directory at this path. No host directory is
 * mounted there: source reads and writes are served exclusively by [AcpCapturedRepairFilesystem].
 */
internal val ACP_CAPTURED_REPAIR_WORKSPACE: Path = Path.of("/decomp-acp-captured/project")

/**
 * In-memory ACP filesystem callbacks backed by the repair authority's bounded mutation sink.
 *
 * Every accepted write reaches [BoundedRepairOutput] before it becomes visible to a later read.
 * Consequently per-file, distinct-patch, aggregate-patch, and logical-workspace limits are
 * enforced during the callback rather than discovered by an after-the-fact host snapshot.
 */
internal class AcpCapturedRepairFilesystem(
    initialFilesCandidate: Map<String, ByteArray>,
    private val output: BoundedRepairOutput,
) {
    private val lock = Any()
    private val initialFiles = TreeMap<String, ByteArray>().apply {
        initialFilesCandidate.forEach { (path, bytes) -> put(path, bytes.copyOf()) }
    }
    private val currentFiles = TreeMap<String, ByteArray>().apply {
        this@AcpCapturedRepairFilesystem.initialFiles.forEach { (path, bytes) -> put(path, bytes.copyOf()) }
    }
    private var session: CapturedSession? = null

    init {
        require(this.initialFiles.keys ==
            this.initialFiles.keys.map(::normalizedCapturedAcpPath).distinct().toSet()
        ) {
            "captured ACP inputs contain a non-canonical path"
        }
    }

    /** Fails before the ACP process starts when captured inputs cannot satisfy the text bridge. */
    fun preflight(request: AgentExecutionRequest, limits: AcpFilesystemLimits) = synchronized(lock) {
        validateRequest(request)
        initialFiles.forEach { (path, bytes) ->
            if (bytes.size > limits.maximumReadBytes) {
                throw AgentExecutionException(
                    AgentFailure(
                        AgentFailureKind.RESOURCE_EXHAUSTED,
                        "captured ACP source exceeds the configured read limit: $path",
                    ),
                )
            }
            try {
                decodeCapturedUtf8(bytes)
            } catch (failure: CharacterCodingException) {
                throw AgentExecutionException(
                    AgentFailure(
                        AgentFailureKind.WORKSPACE_VIOLATION,
                        "captured ACP source is not valid UTF-8: $path",
                    ),
                    failure,
                )
            }
        }
    }

    fun open(
        request: AgentExecutionRequest,
        limits: AcpFilesystemLimits,
        audit: AcpFilesystemAuditRecorder,
    ): AcpFilesystemSession = synchronized(lock) {
        check(session == null) { "captured ACP filesystem is already open" }
        validateRequest(request)
        CapturedSession(request, limits, audit).also { session = it }
    }

    private fun validateRequest(request: AgentExecutionRequest) {
        require(request.workspaceRoots.size == 1) { "captured ACP repair requires exactly one workspace root" }
        require(request.workspaceRoots.single().path == ACP_CAPTURED_REPAIR_WORKSPACE) {
            "captured ACP repair requires its private namespace-only workspace root"
        }
        require(request.accessPolicy.allowedOperations.all { operation ->
            operation == AgentOperation.READ_FILE || operation == AgentOperation.WRITE_FILE
        }) { "captured ACP repair permits only file reads and replacements" }
        require(request.accessPolicy.pathRules.none { it.recursive }) {
            "captured ACP repair requires exact file rules"
        }
        require(request.accessPolicy.pathRules.all { rule -> rule.path.relativePath in initialFiles }) {
            "captured ACP repair policy references an unstaged path"
        }
    }

    fun changes(): List<AgentFileChange> = synchronized(lock) {
        val opened = checkNotNull(session) { "captured ACP filesystem was not opened" }
        check(opened.isClosed()) { "captured ACP filesystem changes are not final" }
        val rootId = opened.rootId
        currentFiles.entries.mapNotNull { (relativePath, after) ->
            val before = initialFiles.getValue(relativePath)
            if (before.contentEquals(after)) return@mapNotNull null
            AgentFileChange(
                path = AgentWorkspacePath(rootId, relativePath),
                kind = AgentFileChangeKind.MODIFIED,
                beforeSha256 = sha256Captured(before),
                afterSha256 = sha256Captured(after),
                sizeBytes = after.size.toLong(),
            )
        }
    }

    private inner class CapturedSession(
        private val request: AgentExecutionRequest,
        private val limits: AcpFilesystemLimits,
        private val audit: AcpFilesystemAuditRecorder,
    ) : AcpFilesystemSession {
        val rootId: String = request.workspaceRoots.single().id
        private var closed = false

        override val capability: FileSystemCapability? = run {
            val readEnabled = request.accessPolicy.pathRules.any { rule ->
                AgentOperation.READ_FILE in rule.operations &&
                    AgentOperation.READ_FILE in request.accessPolicy.allowedOperations
            }
            val writeEnabled = hasEffectiveFilesystemWriteCapability(
                request.accessPolicy.pathRules,
                request.accessPolicy.allowedOperations,
            )
            if (readEnabled || writeEnabled) {
                FileSystemCapability(readTextFile = readEnabled, writeTextFile = writeEnabled)
            } else {
                null
            }
        }

        override suspend fun readTextFile(
            sessionId: String,
            requestedPath: String,
            line: UInt?,
            limit: UInt?,
        ): ReadTextFileResponse = synchronized(lock) {
            var policyPath: AgentWorkspacePath? = null
            try {
                checkOpen()
                checkpointCancellation()
                policyPath = resolve(requestedPath)
                if (!request.accessPolicy.allows(policyPath, AgentOperation.READ_FILE)) {
                    rejectCaptured(AcpFilesystemAuditReason.POLICY_DENIED,
                        "filesystem read is outside the workflow allowlist")
                }
                val bytes = currentFiles[policyPath.relativePath]
                    ?: rejectCaptured(AcpFilesystemAuditReason.NOT_FOUND,
                        "filesystem read target does not exist")
                if (bytes.size > limits.maximumReadBytes) {
                    rejectCaptured(AcpFilesystemAuditReason.RESOURCE_LIMIT,
                        "filesystem read exceeds the configured size limit")
                }
                val content = selectCapturedLines(decodeCapturedUtf8(bytes), line, limit)
                audit.record(
                    sessionId,
                    READ_METHOD,
                    requestedPath,
                    policyPath,
                    AcpFilesystemAuditOutcome.ALLOWED,
                    AcpFilesystemAuditReason.COMPLETED,
                )
                ReadTextFileResponse(content)
            } catch (rejected: CapturedFilesystemRejected) {
                audit.record(
                    sessionId,
                    READ_METHOD,
                    requestedPath,
                    policyPath,
                    AcpFilesystemAuditOutcome.DENIED,
                    rejected.reason,
                )
                throw AcpExpectedError(rejected.safeMessage)
            } catch (_: CharacterCodingException) {
                audit.record(
                    sessionId,
                    READ_METHOD,
                    requestedPath,
                    policyPath,
                    AcpFilesystemAuditOutcome.DENIED,
                    AcpFilesystemAuditReason.INVALID_TEXT,
                )
                throw AcpExpectedError("filesystem read target is not valid UTF-8 text")
            }
        }

        override suspend fun writeTextFile(
            sessionId: String,
            requestedPath: String,
            content: String,
        ): WriteTextFileResponse = synchronized(lock) {
            var policyPath: AgentWorkspacePath? = null
            try {
                checkOpen()
                checkpointCancellation()
                policyPath = resolve(requestedPath)
                if (!request.accessPolicy.allows(policyPath, AgentOperation.WRITE_FILE)) {
                    rejectCaptured(AcpFilesystemAuditReason.POLICY_DENIED,
                        "filesystem write is outside the workflow allowlist")
                }
                if (policyPath.relativePath !in currentFiles) {
                    rejectCaptured(AcpFilesystemAuditReason.NOT_FOUND,
                        "captured repair may only replace an existing source file")
                }
                val encoded = encodeCapturedUtf8(content, limits.maximumWriteBytes)
                try {
                    // BoundedRepairOutput checks every dynamic repair quota before retaining bytes.
                    output.replace(policyPath.relativePath, encoded)
                } catch (_: RepairBudgetExceededException) {
                    rejectCaptured(AcpFilesystemAuditReason.RESOURCE_LIMIT,
                        "filesystem write exceeds the repair capture budget")
                }
                currentFiles[policyPath.relativePath] = encoded.copyOf()
                audit.record(
                    sessionId,
                    WRITE_METHOD,
                    requestedPath,
                    policyPath,
                    AcpFilesystemAuditOutcome.ALLOWED,
                    AcpFilesystemAuditReason.COMPLETED,
                )
                WriteTextFileResponse()
            } catch (rejected: CapturedFilesystemRejected) {
                audit.record(
                    sessionId,
                    WRITE_METHOD,
                    requestedPath,
                    policyPath,
                    AcpFilesystemAuditOutcome.DENIED,
                    rejected.reason,
                )
                throw AcpExpectedError(rejected.safeMessage)
            } catch (_: CharacterCodingException) {
                audit.record(
                    sessionId,
                    WRITE_METHOD,
                    requestedPath,
                    policyPath,
                    AcpFilesystemAuditOutcome.DENIED,
                    AcpFilesystemAuditReason.INVALID_TEXT,
                )
                throw AcpExpectedError("filesystem write content is not valid Unicode text")
            }
        }

        override fun close() = synchronized(lock) {
            closed = true
        }

        fun isClosed(): Boolean = closed

        private fun checkOpen() {
            check(!closed) { "captured ACP filesystem is closed" }
        }

        private fun checkpointCancellation() {
            if (request.cancellation.isCancellationRequested()) {
                rejectCaptured(AcpFilesystemAuditReason.CANCELLED, "filesystem operation was cancelled")
            }
        }

        private fun resolve(raw: String): AgentWorkspacePath {
            val absolute = try {
                Path.of(raw)
            } catch (_: InvalidPathException) {
                rejectCaptured(AcpFilesystemAuditReason.INVALID_PATH, "filesystem path is invalid")
            }
            if (!absolute.isAbsolute || absolute != absolute.normalize()) {
                rejectCaptured(AcpFilesystemAuditReason.INVALID_PATH,
                    "filesystem path must be absolute and normalized")
            }
            if (!absolute.startsWith(ACP_CAPTURED_REPAIR_WORKSPACE) ||
                absolute == ACP_CAPTURED_REPAIR_WORKSPACE
            ) {
                rejectCaptured(AcpFilesystemAuditReason.OUTSIDE_WORKSPACE,
                    "filesystem path is outside the authorized workspace")
            }
            val relative = ACP_CAPTURED_REPAIR_WORKSPACE.relativize(absolute)
                .toString()
                .replace(absolute.fileSystem.separator, "/")
            return try {
                AgentWorkspacePath(rootId, relative)
            } catch (_: IllegalArgumentException) {
                rejectCaptured(AcpFilesystemAuditReason.INVALID_PATH,
                    "filesystem path is not a normalized workspace path")
            }
        }
    }

    private companion object {
        const val READ_METHOD = "fs/read_text_file"
        const val WRITE_METHOD = "fs/write_text_file"
    }
}

private class CapturedFilesystemRejected(
    val reason: AcpFilesystemAuditReason,
    val safeMessage: String,
) : RuntimeException(safeMessage)

private fun rejectCaptured(reason: AcpFilesystemAuditReason, safeMessage: String): Nothing =
    throw CapturedFilesystemRejected(reason, safeMessage)

private fun normalizedCapturedAcpPath(value: String): String {
    require(value.isNotBlank() && '\\' !in value && !value.startsWith('/')) {
        "invalid captured ACP path: $value"
    }
    require(value.split('/').none { it.isEmpty() || it == "." || it == ".." }) {
        "invalid captured ACP path: $value"
    }
    return value
}

private fun decodeCapturedUtf8(content: ByteArray): String = StandardCharsets.UTF_8.newDecoder()
    .onMalformedInput(CodingErrorAction.REPORT)
    .onUnmappableCharacter(CodingErrorAction.REPORT)
    .decode(ByteBuffer.wrap(content))
    .toString()

private fun encodeCapturedUtf8(content: String, maximumBytes: Int): ByteArray {
    val encoded = StandardCharsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .encode(CharBuffer.wrap(content))
    if (encoded.remaining() > maximumBytes) {
        rejectCaptured(AcpFilesystemAuditReason.RESOURCE_LIMIT,
            "filesystem write exceeds the configured size limit")
    }
    return ByteArray(encoded.remaining()).also(encoded::get)
}

private fun selectCapturedLines(text: String, line: UInt?, limit: UInt?): String {
    val firstLine = line?.toLong() ?: 1L
    if (firstLine == 0L) {
        rejectCaptured(AcpFilesystemAuditReason.INVALID_ARGUMENT,
            "filesystem read line must be one-based")
    }
    val maximumLines = limit?.toLong() ?: Long.MAX_VALUE
    if (maximumLines == 0L) return ""
    var cursor = 0
    var currentLine = 1L
    while (currentLine < firstLine) {
        val newline = text.indexOf('\n', cursor)
        if (newline < 0) return ""
        cursor = newline + 1
        currentLine++
    }
    if (maximumLines == Long.MAX_VALUE) return text.substring(cursor)
    var end = cursor
    var selected = 0L
    while (selected < maximumLines && end < text.length) {
        val newline = text.indexOf('\n', end)
        if (newline < 0) {
            end = text.length
            break
        }
        end = newline + 1
        selected++
    }
    return text.substring(cursor, end)
}

private fun sha256Captured(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
    .digest(bytes)
    .joinToString("") { byte -> "%02x".format(byte) }
