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
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/**
 * Compatibility bridge for the original one-shot HTTP client.
 *
 * New reconstruction and repair code use [AgentHarness] and observe in-workspace changes. Only this bridge knows
 * that the legacy provider returns replacements in message content.
 */
class RepairClientAgentHarness(
    private val client: RepairClient,
) : CapturedRepairAgentHarness {
    override fun implementationIdentifier(): String? = client.modelIdentifier()

    override fun execute(
        request: AgentExecutionRequest,
        onEvent: (AgentExecutionEvent) -> Unit,
    ): AgentExecutionResult = throw AgentExecutionException(
        AgentFailure(
            AgentFailureKind.CONFIGURATION,
            "legacy repair client requires strict captured staging; host-directory execution is disabled",
        )
    )

    override fun executeCaptured(
        request: AgentExecutionRequest,
        initialFiles: Map<String, ByteArray>,
        output: BoundedRepairOutput,
        onEvent: (AgentExecutionEvent) -> Unit,
    ): AgentExecutionResult {
        if (request.cancellation.isCancellationRequested()) {
            return AgentExecutionResult(AgentStopReason.CANCELLED, "cancelled before the legacy request started")
        }
        if (request.workspaceRoots.size != 1) {
            fail(AgentFailureKind.INVALID_REQUEST, "legacy repair adapter requires exactly one workspace root")
        }
        val readablePaths = request.accessPolicy.pathRules
            .filter { AgentOperation.READ_FILE in it.operations && !it.recursive }
            .map { it.path }
            .distinct()
        val projectFiles = readablePaths.associate { path ->
            val bytes = initialFiles[path.relativePath]
                ?: fail(AgentFailureKind.WORKSPACE_VIOLATION, "captured source is absent: ${path.relativePath}")
            path.relativePath to decodeCapturedSource(path.relativePath, bytes)
        }
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
            requestLegacyRepair(
                failureKind,
                prompt,
                projectFiles,
                RepairClientInvocation(output.resourceBudget, request.limits, request.cancellation),
            )
        } catch (_: RepairTransportCancelledException) {
            return AgentExecutionResult(AgentStopReason.CANCELLED, "legacy repair transport was cancelled")
        }
        val elapsed = java.time.Duration.ofNanos(System.nanoTime() - started)
        if (request.cancellation.isCancellationRequested()) {
            return AgentExecutionResult(AgentStopReason.CANCELLED, "cancelled before captured changes were accepted")
        }
        if (elapsed > request.limits.wallClockTimeout) {
            return AgentExecutionResult(
                AgentStopReason.LIMIT_EXHAUSTED,
                "legacy request exceeded the wall-clock limit",
                usage = AgentUsage(wallClock = elapsed),
            )
        }
        require(response.patches.map { it.relativePath }.distinct().size == response.patches.size) {
            "legacy repair response changes a file more than once"
        }
        val rootId = request.workspaceRoots.single().id
        val changes = response.patches.mapNotNull { patch ->
            val path = try {
                AgentWorkspacePath(rootId, patch.relativePath)
            } catch (failure: Exception) {
                throw AgentExecutionException(
                    AgentFailure(AgentFailureKind.WORKSPACE_VIOLATION, "invalid changed path: ${patch.relativePath}"),
                    failure,
                )
            }
            if (!request.accessPolicy.allows(path, AgentOperation.WRITE_FILE)) {
                fail(AgentFailureKind.WORKSPACE_VIOLATION, "agent attempted an unauthorized write: ${patch.relativePath}")
            }
            val before = initialFiles[path.relativePath]
                ?: fail(AgentFailureKind.WORKSPACE_VIOLATION, "agent attempted to create a repair source: ${patch.relativePath}")
            val after = patch.replacement.toByteArray(Charsets.UTF_8)
            if (before.contentEquals(after)) return@mapNotNull null
            output.replace(path.relativePath, after)
            AgentFileChange(
                path,
                AgentFileChangeKind.MODIFIED,
                sha256(before),
                sha256(after),
                after.size.toLong(),
            )
        }
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
        onEvent(AgentMessageEvent(finalSequence + 1, "legacy-repair-summary", AgentMessageRole.ASSISTANT,
            response.summary, completed = true))
        return AgentExecutionResult(
            AgentStopReason.COMPLETED,
            response.summary,
            changes,
            usage = AgentUsage(toolCalls = 1, wallClock = elapsed),
        )
    }

    private fun requestLegacyRepair(
        failureKind: String,
        prompt: String,
        projectFiles: Map<String, String>,
        invocation: RepairClientInvocation,
    ): RepairResponse = try {
        client.requestRepair(RepairRequest(failureKind, prompt, projectFiles, emptyList()), invocation)
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
    } catch (failure: RepairTransportCancelledException) {
        throw failure
    } catch (failure: RepairBudgetExceededException) {
        throw failure
    } catch (failure: Exception) {
        throw AgentExecutionException(
            AgentFailure(AgentFailureKind.PROTOCOL, failure.message ?: "legacy repair response was invalid"),
            failure,
        )
    }

    private fun fail(kind: AgentFailureKind, message: String): Nothing =
        throw AgentExecutionException(AgentFailure(kind, message))

    private fun decodeCapturedSource(relativePath: String, bytes: ByteArray): String = try {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (failure: CharacterCodingException) {
        throw AgentExecutionException(
            AgentFailure(
                AgentFailureKind.WORKSPACE_VIOLATION,
                "captured source is not valid UTF-8: $relativePath",
            ),
            failure,
        )
    }

    companion object {
        const val FAILURE_KIND_CONTEXT_ID = "decompengine.failure-kind"
    }
}
