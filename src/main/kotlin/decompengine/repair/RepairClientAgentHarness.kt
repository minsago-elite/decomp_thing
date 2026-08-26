package decompengine.repair

import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeEvent
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentHarness
import decompengine.agent.AgentMessageEvent
import decompengine.agent.AgentMessageRole
import decompengine.agent.AgentOperation
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentToolEvent
import decompengine.agent.AgentToolStatus
import decompengine.agent.AgentUsage
import decompengine.agent.AgentWorkspacePath
import decompengine.project.sha256
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import kotlin.io.path.exists
import kotlin.io.path.isDirectory
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText

/**
 * Compatibility bridge for the original one-shot HTTP client.
 *
 * New reconstruction and repair code use [AgentHarness] and observe in-workspace changes. Only this bridge knows
 * that the legacy provider returns replacements in message content.
 */
class RepairClientAgentHarness(
    private val client: RepairClient,
) : AgentHarness {
    override fun implementationIdentifier(): String? = client.modelIdentifier()

    override fun execute(
        request: AgentExecutionRequest,
        onEvent: (AgentExecutionEvent) -> Unit,
    ): AgentExecutionResult {
        if (request.cancellation.isCancellationRequested()) {
            return AgentExecutionResult(AgentStopReason.CANCELLED, "cancelled before the legacy request started")
        }
        if (request.workspaceRoots.size != 1) {
            fail(AgentFailureKind.INVALID_REQUEST, "legacy repair adapter requires exactly one workspace root")
        }
        val root = request.workspaceRoots.single()
        if (!root.path.isDirectory()) {
            fail(AgentFailureKind.INVALID_REQUEST, "workspace root is not a directory: ${root.path}")
        }
        val readablePaths = request.accessPolicy.pathRules
            .filter { AgentOperation.READ_FILE in it.operations && !it.recursive }
            .map { it.path }
            .distinct()
        val projectFiles = readablePaths.mapNotNull { path ->
            val resolved = path.resolve(request.workspaceRoots)
            if (resolved.exists()) path.relativePath to resolved.readText() else null
        }.toMap()
        val failureKind = request.contextInputs.singleOrNull { it.id == FAILURE_KIND_CONTEXT_ID }?.content
            ?.trim()?.takeIf(String::isNotEmpty) ?: "agent-execution"
        val prompt = buildString {
            append(request.objective.trim())
            request.contextInputs.filterNot { it.id == FAILURE_KIND_CONTEXT_ID }.forEach { context ->
                append("\n\nImmutable context ").append(context.id).append(" [").append(context.mediaType).append("]:\n")
                append(context.content)
            }
        }
        onEvent(AgentToolEvent(0, "legacy-repair-request", "Request source changes", AgentToolStatus.IN_PROGRESS))
        val started = System.nanoTime()
        val response = try {
            client.requestRepair(RepairRequest(failureKind, prompt, projectFiles, emptyList()))
        } catch (failure: InterruptedException) {
            Thread.currentThread().interrupt()
            throw AgentExecutionException(
                AgentFailure(AgentFailureKind.TRANSPORT, "legacy repair request was interrupted", retryable = true),
                failure,
            )
        } catch (failure: IOException) {
            throw AgentExecutionException(
                AgentFailure(AgentFailureKind.TRANSPORT, failure.message ?: "legacy repair transport failed", retryable = true),
                failure,
            )
        } catch (failure: AgentExecutionException) {
            throw failure
        } catch (failure: Exception) {
            throw AgentExecutionException(
                AgentFailure(AgentFailureKind.PROTOCOL, failure.message ?: "legacy repair response was invalid"),
                failure,
            )
        }
        val elapsed = java.time.Duration.ofNanos(System.nanoTime() - started)
        if (request.cancellation.isCancellationRequested()) {
            return AgentExecutionResult(AgentStopReason.CANCELLED, "cancelled before workspace changes were applied")
        }
        if (elapsed > request.limits.wallClockTimeout) {
            return AgentExecutionResult(
                AgentStopReason.LIMIT_EXHAUSTED,
                "legacy request exceeded the wall-clock limit",
                usage = AgentUsage(wallClock = elapsed),
            )
        }
        if (response.patches.isEmpty()) {
            onEvent(AgentToolEvent(1, "legacy-repair-request", "Request source changes", AgentToolStatus.SUCCEEDED))
            return AgentExecutionResult(
                AgentStopReason.NO_CHANGES,
                response.summary,
                usage = AgentUsage(toolCalls = 1, wallClock = elapsed),
            )
        }
        val changes = applyPatches(request, response.patches)
        if (changes.isEmpty()) {
            onEvent(AgentToolEvent(1, "legacy-repair-request", "Request source changes", AgentToolStatus.SUCCEEDED))
            return AgentExecutionResult(
                AgentStopReason.NO_CHANGES,
                response.summary,
                usage = AgentUsage(toolCalls = 1, wallClock = elapsed),
            )
        }
        changes.forEachIndexed { index, change -> onEvent(AgentFileChangeEvent(index.toLong() + 1, change)) }
        val finalSequence = changes.size.toLong() + 1
        onEvent(AgentToolEvent(finalSequence, "legacy-repair-request", "Request source changes", AgentToolStatus.SUCCEEDED))
        onEvent(AgentMessageEvent(finalSequence + 1, "legacy-repair-summary", AgentMessageRole.ASSISTANT, response.summary, completed = true))
        return AgentExecutionResult(
            stopReason = AgentStopReason.COMPLETED,
            summary = response.summary,
            changes = changes,
            usage = AgentUsage(toolCalls = 1, wallClock = elapsed),
        )
    }

    private fun applyPatches(request: AgentExecutionRequest, patches: List<SourcePatch>): List<AgentFileChange> {
        if (patches.map { it.relativePath }.distinct().size != patches.size) {
            fail(AgentFailureKind.PROTOCOL, "legacy repair response changes a file more than once")
        }
        val root = request.workspaceRoots.single()
        data class Staged(
            val path: AgentWorkspacePath,
            val target: java.nio.file.Path,
            val temporary: java.nio.file.Path,
            val before: ByteArray?,
        )
        data class Authorized(
            val path: AgentWorkspacePath,
            val target: java.nio.file.Path,
            val before: ByteArray?,
            val replacement: String,
        )

        val authorized = patches.map { patch ->
            val path = runCatching { AgentWorkspacePath(root.id, patch.relativePath) }.getOrElse { failure ->
                throw AgentExecutionException(
                    AgentFailure(AgentFailureKind.WORKSPACE_VIOLATION, "invalid changed path: ${patch.relativePath}"),
                    failure,
                )
            }
            val target = path.resolve(request.workspaceRoots)
            val required = if (target.exists()) AgentOperation.WRITE_FILE else AgentOperation.CREATE_FILE
            if (!request.accessPolicy.allows(path, required)) {
                fail(AgentFailureKind.WORKSPACE_VIOLATION, "agent attempted an unauthorized $required: ${patch.relativePath}")
            }
            if (!target.parent.isDirectory()) {
                fail(AgentFailureKind.WORKSPACE_VIOLATION, "changed file parent is not an authorized directory: ${patch.relativePath}")
            }
            val before = target.takeIf { it.exists() }?.readBytes()
            Authorized(path, target, before, patch.replacement)
        }.filterNot { change -> change.before?.contentEquals(change.replacement.toByteArray()) == true }
        val staged = mutableListOf<Staged>()
        try {
            authorized.forEach { change ->
                val temporary = Files.createTempFile(change.target.parent, ".${change.target.fileName}.", ".agent-change")
                staged += Staged(change.path, change.target, temporary, change.before)
                temporary.writeText(change.replacement)
            }
        } catch (failure: Exception) {
            staged.forEach { change -> runCatching { Files.deleteIfExists(change.temporary) } }
            throw AgentExecutionException(
                AgentFailure(AgentFailureKind.INTERNAL, "could not stage legacy workspace changes"),
                failure,
            )
        }
        try {
            staged.forEach { change ->
                runCatching {
                    Files.move(change.temporary, change.target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                }.getOrElse {
                    Files.move(change.temporary, change.target, StandardCopyOption.REPLACE_EXISTING)
                }
            }
        } catch (failure: Exception) {
            staged.forEach { change ->
                runCatching {
                    if (change.before == null) Files.deleteIfExists(change.target)
                    else Files.write(change.target, change.before)
                }
                runCatching { Files.deleteIfExists(change.temporary) }
            }
            throw AgentExecutionException(
                AgentFailure(AgentFailureKind.INTERNAL, "could not install legacy workspace changes"),
                failure,
            )
        }
        return staged.map { change ->
            val after = change.target.readBytes()
            val beforeDigest = change.before?.let(::sha256)
            val afterDigest = sha256(after)
            AgentFileChange(
                path = change.path,
                kind = if (change.before == null) AgentFileChangeKind.CREATED else AgentFileChangeKind.MODIFIED,
                beforeSha256 = beforeDigest,
                afterSha256 = afterDigest,
                sizeBytes = after.size.toLong(),
            )
        }
    }

    private fun fail(kind: AgentFailureKind, message: String): Nothing =
        throw AgentExecutionException(AgentFailure(kind, message))

    companion object {
        const val FAILURE_KIND_CONTEXT_ID = "decompengine.failure-kind"
    }
}
