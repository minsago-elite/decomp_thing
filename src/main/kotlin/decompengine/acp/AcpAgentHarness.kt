package decompengine.acp

import com.agentclientprotocol.annotations.UnstableApi
import com.agentclientprotocol.client.Client
import com.agentclientprotocol.client.ClientInfo
import com.agentclientprotocol.client.ClientSession
import com.agentclientprotocol.client.UnsupportedProtocolVersionException
import com.agentclientprotocol.common.ClientSessionOperations
import com.agentclientprotocol.common.Event
import com.agentclientprotocol.common.SessionCreationParameters
import com.agentclientprotocol.model.AgentCapabilities
import com.agentclientprotocol.model.ClientCapabilities
import com.agentclientprotocol.model.ContentBlock
import com.agentclientprotocol.model.CreateTerminalResponse
import com.agentclientprotocol.model.EnvVariable
import com.agentclientprotocol.model.Implementation
import com.agentclientprotocol.model.KillTerminalCommandResponse
import com.agentclientprotocol.model.PermissionOption
import com.agentclientprotocol.model.PermissionOptionKind
import com.agentclientprotocol.model.PlanEntryStatus
import com.agentclientprotocol.model.PromptResponse
import com.agentclientprotocol.model.RequestPermissionOutcome
import com.agentclientprotocol.model.RequestPermissionResponse
import com.agentclientprotocol.model.ReadTextFileResponse
import com.agentclientprotocol.model.ReleaseTerminalResponse
import com.agentclientprotocol.model.SessionUpdate
import com.agentclientprotocol.model.StopReason
import com.agentclientprotocol.model.ToolCallStatus
import com.agentclientprotocol.model.TerminalOutputResponse
import com.agentclientprotocol.model.WaitForTerminalExitResponse
import com.agentclientprotocol.model.WriteTextFileResponse
import com.agentclientprotocol.protocol.AcpExpectedError
import com.agentclientprotocol.protocol.JsonRpcException
import com.agentclientprotocol.protocol.Protocol
import com.agentclientprotocol.rpc.JsonRpcErrorCode
import com.agentclientprotocol.rpc.decodeJsonRpcMessage
import com.agentclientprotocol.transport.StdioTransport
import decompengine.agent.AgentCancellation
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
import decompengine.agent.AgentPermissionDecision
import decompengine.agent.AgentPermissionEvent
import decompengine.agent.AgentPlanEntry
import decompengine.agent.AgentPlanEvent
import decompengine.agent.AgentPlanStatus
import decompengine.agent.AgentSessionReference
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentToolEvent
import decompengine.agent.AgentToolStatus
import decompengine.agent.AgentUsage
import decompengine.agent.AgentWorkspacePath
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.path.isDirectory
import kotlin.io.path.isRegularFile
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Stable ACP v1 adapter for the provider-neutral [AgentHarness] boundary.
 *
 * Every execution starts one explicitly configured process, negotiates only protocol version 1,
 * opens one session, executes one prompt turn, and tears the complete process tree down.
 */
class AcpAgentHarness(
    private val configuration: AcpProcessConfiguration,
) : AgentHarness {
    private val unresolvedCleanupFailure = AtomicReference<AgentExecutionException?>()
    private val diagnostics = AtomicReference<AcpProcessDiagnostics?>()
    private val filesystemAudit = AtomicReference<List<AcpFilesystemAuditRecord>>(emptyList())
    private val terminalAudit = AtomicReference<List<AcpTerminalAuditRecord>>(emptyList())
    private val permissionAudit = AtomicReference<List<AcpPermissionAuditRecord>>(emptyList())
    private val sandboxEvidence = AtomicReference<AcpSandboxEvidence?>()

    override fun implementationIdentifier(): String = configuration.implementationId

    fun latestDiagnostics(): AcpProcessDiagnostics? = diagnostics.get()

    /** Metadata-only filesystem decisions from the latest execution on this harness. */
    fun latestFilesystemAudit(): List<AcpFilesystemAuditRecord> = filesystemAudit.get()

    /** Metadata-only terminal lifecycle and authorization decisions from the latest execution. */
    fun latestTerminalAudit(): List<AcpTerminalAuditRecord> = terminalAudit.get()

    /** Metadata-only ACP permission decisions from the latest execution. */
    fun latestPermissionAudit(): List<AcpPermissionAuditRecord> = permissionAudit.get()

    fun latestSandboxEvidence(): AcpSandboxEvidence? = sandboxEvidence.get()

    @OptIn(UnstableApi::class)
    override fun execute(
        request: AgentExecutionRequest,
        onEvent: (AgentExecutionEvent) -> Unit,
    ): AgentExecutionResult {
        unresolvedCleanupFailure.get()?.let { throw it }
        diagnostics.set(null)
        filesystemAudit.set(emptyList())
        terminalAudit.set(emptyList())
        permissionAudit.set(emptyList())
        sandboxEvidence.set(null)
        validateRequest(request)
        if (request.cancellation.isCancellationRequested()) {
            return AgentExecutionResult(AgentStopReason.CANCELLED, "cancelled before the ACP process started")
        }

        val startedAt = System.nanoTime()
        val wallDeadline = MonotonicDeadline(request.limits.wallClockTimeout)
        val before = try {
            WorkspaceSnapshot.capture(
                request,
                WorkspaceSnapshotBudget(request.cancellation, wallDeadline, honorCancellation = true),
            )
        } catch (_: WorkspaceSnapshotCancelled) {
            return AgentExecutionResult(AgentStopReason.CANCELLED, "cancelled during the initial workspace snapshot")
        } catch (_: WorkspaceSnapshotTimedOut) {
            throw workspaceSnapshotTimeout("initial", null)
        }
        if (request.cancellation.isCancellationRequested()) {
            return AgentExecutionResult(AgentStopReason.CANCELLED, "cancelled before the ACP process started")
        }
        if (wallDeadline.hasExpired()) throw workspaceSnapshotTimeout("initial", null)
        val emitter = SequencedEventEmitter(onEvent)
        val translator = AcpEventTranslator(request, emitter, configuration.implementationId)
        val protocolReference = AtomicReference<Protocol?>()
        val protocolScopeReference = AtomicReference<CoroutineScope?>()
        val filesystemReference = AtomicReference<AcpFilesystemBroker?>()
        val terminalReference = AtomicReference<AcpTerminalBroker?>()
        val filesystemAuditRecorder = AcpFilesystemAuditRecorder()
        val permissionAuditRecorder = AcpPermissionAuditRecorder()
        var runningReference: RunningAcpProcess? = null
        var terminalAuditRecorderReference: AcpTerminalAuditRecorder? = null
        var outcome: PromptOutcome? = null
        var primaryFailure: Throwable? = null
        var cleanupFailure: AgentExecutionException? = null

        fun recordPrimaryFailure(failure: Throwable) {
            val current = primaryFailure
            when {
                current == null -> primaryFailure = failure
                current === failure -> Unit
                failure is Error && current !is Error -> {
                    failure.addSuppressed(current)
                    primaryFailure = failure
                }
                else -> current.addSuppressed(failure)
            }
        }

        fun recordCleanupFailure(message: String, failure: Throwable) {
            if (failure is Error) {
                recordPrimaryFailure(failure)
                return
            }
            val mapped = AgentExecutionException(
                AgentFailure(
                    AgentFailureKind.INTERNAL,
                    message,
                    session = translator.sessionReference(),
                ),
                failure,
            )
            if (cleanupFailure == null) cleanupFailure = mapped else cleanupFailure?.addSuppressed(mapped)
        }

        var processDiagnostics: AcpProcessDiagnostics? = null
        val sandboxExecution = try {
            ProductionAcpSandboxExecution(
                configuration,
                request,
                translator.activity,
                wallDeadline,
            )
        } catch (cancelled: RequestedAcpCancellation) {
            return AgentExecutionResult(
                AgentStopReason.CANCELLED,
                "cancelled during ${cancelled.phase}",
            )
        } catch (failure: AgentExecutionException) {
            if (failure.containsCleanupProofFailure()) {
                unresolvedCleanupFailure.compareAndSet(null, failure)
                throw requireNotNull(unresolvedCleanupFailure.get())
            }
            throw failure
        }
        try {
            // This guard begins with the first operation after a successful outer launch. Even
            // evidence/recorder construction failures therefore cannot bypass boundary cleanup.
            val running = sandboxExecution.running.also { runningReference = it }
            val terminalAuditRecorder = AcpTerminalAuditRecorder(
                networkIsolated = sandboxExecution.networkIsolated,
            ).also { terminalAuditRecorderReference = it }
            try {
                sandboxEvidence.set(
                    sandboxExecution.evidence(
                        configuration.terminalPolicy?.takeIf {
                            AgentOperation.EXECUTE_COMMAND in request.accessPolicy.allowedOperations
                        },
                        outerProcessOutput = running.outputEvidence(),
                    ),
                )
                outcome = runBlocking {
                    runProtocol(
                        request = request,
                        running = running,
                        translator = translator,
                        wallDeadline = wallDeadline,
                        protocolReference = protocolReference,
                        protocolScopeReference = protocolScopeReference,
                        filesystemAuditRecorder = filesystemAuditRecorder,
                        filesystemReference = filesystemReference,
                        terminalAuditRecorder = terminalAuditRecorder,
                        terminalReference = terminalReference,
                        permissionAuditRecorder = permissionAuditRecorder,
                        sandboxExecution = sandboxExecution,
                    )
                }
            } catch (failure: Throwable) {
                recordPrimaryFailure(failure)
            }
            running.failure.get()?.let { terminal ->
                if (primaryFailure == null) {
                    if (terminal is AcpMalformedFrameFailure || terminal is AcpOutputLimitFailure) {
                        primaryFailure = terminal
                    }
                } else if (
                    primaryFailure is AcpTerminalFailure &&
                    terminalFailurePriority(terminal) > terminalFailurePriority(primaryFailure)
                ) {
                    primaryFailure = terminal
                }
            }

            try {
                terminalReference.getAndSet(null)?.close()
            } catch (failure: Throwable) {
                recordCleanupFailure("ACP terminal sandbox cleanup was not proven", failure)
            }
            try {
                filesystemReference.getAndSet(null)?.close()
            } catch (failure: Throwable) {
                recordCleanupFailure("ACP filesystem broker cleanup failed", failure)
            }
            try {
                processDiagnostics = runBlocking {
                    running.shutdown(
                        protocolReference.get(),
                        protocolScopeReference.get(),
                        configuration.timeouts.shutdown,
                    )
                }
            } catch (failure: Throwable) {
                recordPrimaryFailure(failure)
            }
            if (processDiagnostics != null) {
                try {
                    sandboxEvidence.set(
                        sandboxExecution.evidence(
                            configuration.terminalPolicy?.takeIf {
                                AgentOperation.EXECUTE_COMMAND in request.accessPolicy.allowedOperations
                            },
                            terminalAuditRecorder.snapshot(),
                            running.outputEvidence(),
                        ),
                    )
                } catch (failure: Throwable) {
                    recordPrimaryFailure(failure)
                }
            }
        } catch (failure: Throwable) {
            // This path covers failures in the lifecycle scaffolding itself (for example an Error
            // while constructing a recorder) before the normal protocol cleanup block is reached.
            recordPrimaryFailure(failure)
            try {
                terminalReference.getAndSet(null)?.close()
            } catch (cleanup: Throwable) {
                recordCleanupFailure("ACP terminal sandbox cleanup was not proven", cleanup)
            }
            try {
                filesystemReference.getAndSet(null)?.close()
            } catch (cleanup: Throwable) {
                recordCleanupFailure("ACP filesystem broker cleanup failed", cleanup)
            }
            runningReference?.let { running ->
                if (processDiagnostics == null) {
                    try {
                        processDiagnostics = runBlocking {
                            running.shutdown(
                                protocolReference.get(),
                                protocolScopeReference.get(),
                                configuration.timeouts.shutdown,
                            )
                        }
                    } catch (cleanup: Throwable) {
                        recordPrimaryFailure(cleanup)
                    }
                }
            }
        } finally {
            try {
                sandboxExecution.close()
            } catch (failure: Throwable) {
                processDiagnostics = processDiagnostics?.copy(sandboxCleanupVerified = false)
                recordCleanupFailure("ACP sandbox boundary cleanup was not proven", failure)
            } finally {
                // Publish every bounded recorder independently. Evidence construction and boundary
                // cleanup failures must not erase the diagnostic trail needed to audit teardown.
                try {
                    filesystemAudit.set(filesystemAuditRecorder.snapshot())
                } catch (failure: Throwable) {
                    recordPrimaryFailure(failure)
                }
                try {
                    terminalAudit.set(terminalAuditRecorderReference?.snapshot().orEmpty())
                } catch (failure: Throwable) {
                    recordPrimaryFailure(failure)
                }
                try {
                    permissionAudit.set(permissionAuditRecorder.snapshot())
                } catch (failure: Throwable) {
                    recordPrimaryFailure(failure)
                }
            }
        }
        val running = requireNotNull(runningReference)
        processDiagnostics?.let(diagnostics::set)
        val completedDiagnostics = processDiagnostics
        running.failure.get()?.let { terminal ->
            if (terminal is AcpOutputLimitFailure && (
                    primaryFailure == null ||
                        primaryFailure is RequestedAcpCancellation ||
                        primaryFailure is AcpTerminalFailure &&
                        terminalFailurePriority(terminal) > terminalFailurePriority(primaryFailure)
                )
            ) {
                // The aggregate budget remains authoritative through the final stdout/stderr
                // drains. In particular, a clean prompt response cannot turn a shutdown-stage
                // overflow into a successful result.
                primaryFailure = terminal
            } else if (primaryFailure == null && terminal is AcpMalformedFrameFailure) {
                primaryFailure = terminal
            }
        }
        if (
            completedDiagnostics != null &&
            primaryFailure == null &&
            outcome != null &&
            !completedDiagnostics.rootTerminationRequested &&
            completedDiagnostics.exitCode != null &&
            completedDiagnostics.exitCode != 0
        ) {
            primaryFailure = AcpProcessExitedFailure(completedDiagnostics.exitCode)
        }
        if (
            completedDiagnostics != null &&
            primaryFailure is AcpTerminalFailure &&
            primaryFailure !is AcpMalformedFrameFailure &&
            primaryFailure !is AcpOutputLimitFailure &&
            primaryFailure !is AcpProcessExitedFailure &&
            !completedDiagnostics.rootTerminationRequested &&
            completedDiagnostics.exitCode != null &&
            completedDiagnostics.exitCode != 0
        ) {
            primaryFailure = AcpProcessExitedFailure(completedDiagnostics.exitCode)
        }
        if (primaryFailure is RequestedAcpCancellation) {
            outcome = PromptOutcome(AgentStopReason.CANCELLED, null, "cancelled by caller")
            primaryFailure = null
        }
        val processCleanupFailure = if (completedDiagnostics == null) {
            AgentExecutionException(
                AgentFailure(
                    AgentFailureKind.INTERNAL,
                    "ACP process shutdown did not produce cleanup diagnostics",
                    session = translator.sessionReference(),
                ),
            )
        } else if (
            completedDiagnostics.remainingProcessIds.isEmpty() &&
            completedDiagnostics.sandboxCleanupVerified
        ) {
            null
        } else {
            AgentExecutionException(
                AgentFailure(
                    AgentFailureKind.INTERNAL,
                    "ACP subprocess tree did not terminate within the configured shutdown timeout",
                    details = mapOf(
                        "pid" to completedDiagnostics.pid.toString(),
                        "remainingPids" to completedDiagnostics.remainingProcessIds.joinToString(","),
                        "sandboxCleanupVerified" to completedDiagnostics.sandboxCleanupVerified.toString(),
                    ),
                ),
            )
        }
        if (cleanupFailure == null) cleanupFailure = processCleanupFailure
        else processCleanupFailure?.let { cleanupFailure.addSuppressed(it) }

        val fatalCleanup = cleanupFailure
        (primaryFailure as? Error)?.let { fatal ->
            fatalCleanup?.let { cleanup ->
                unresolvedCleanupFailure.compareAndSet(null, cleanup)
                fatal.addSuppressed(cleanup)
            }
            throw fatal
        }
        if (fatalCleanup != null) {
            primaryFailure?.let(fatalCleanup::addSuppressed)
            unresolvedCleanupFailure.compareAndSet(null, fatalCleanup)
            throw requireNotNull(unresolvedCleanupFailure.get())
        }
        val completedPrimaryFailure = primaryFailure
        if (completedPrimaryFailure != null) {
            throw mapFailure(completedPrimaryFailure, running, translator.sessionReference())
        }

        val finished = requireNotNull(outcome)
        val changes = try {
            val finalBudget = WorkspaceSnapshotBudget(
                request.cancellation,
                wallDeadline,
                // A cancellation already accepted by the prompt still needs an accurate final change set.
                honorCancellation = finished.stopReason != AgentStopReason.CANCELLED,
            )
            val finalSnapshot = WorkspaceSnapshot.capture(request, finalBudget)
            before.diff(finalSnapshot, request, finalBudget)
        } catch (_: WorkspaceSnapshotCancelled) {
            throw AgentExecutionException(
                AgentFailure(
                    AgentFailureKind.UNAVAILABLE,
                    "ACP execution was cancelled while capturing final workspace state; changes are indeterminate",
                    session = translator.sessionReference(),
                    details = mapOf("phase" to "final-workspace-snapshot"),
                ),
            )
        } catch (_: WorkspaceSnapshotTimedOut) {
            throw workspaceSnapshotTimeout("final", translator.sessionReference())
        }
        changes.forEach { change -> emitter.emit { sequence -> AgentFileChangeEvent(sequence, change) } }
        translator.completeMessages()
        translator.callbackFailure.get()?.let { throw it }

        val stopReason = when {
            finished.stopReason == AgentStopReason.COMPLETED && changes.isEmpty() -> AgentStopReason.NO_CHANGES
            else -> finished.stopReason
        }
        val elapsed = Duration.ofNanos((System.nanoTime() - startedAt).coerceAtLeast(0))
        val usage = finished.response?.usage?.let { acp ->
            try {
                AgentUsage(
                    inputTokens = acp.inputTokens,
                    outputTokens = acp.outputTokens,
                    cachedInputTokens = acp.cachedReadTokens,
                    toolCalls = translator.toolCallCount(),
                    wallClock = elapsed,
                )
            } catch (invalid: IllegalArgumentException) {
                throw AgentExecutionException(
                    AgentFailure(
                        AgentFailureKind.PROTOCOL,
                        "ACP agent returned invalid prompt usage: ${invalid.message}",
                        session = translator.sessionReference(),
                    ),
                    invalid,
                )
            }
        } ?: AgentUsage(toolCalls = translator.toolCallCount(), wallClock = elapsed)
        val limited = tokenLimitExceeded(request, usage)

        return AgentExecutionResult(
            stopReason = if (limited) AgentStopReason.LIMIT_EXHAUSTED else stopReason,
            summary = translator.summary().ifBlank { finished.summary },
            changes = changes,
            session = translator.sessionReference(),
            usage = usage,
        )
    }

    @OptIn(UnstableApi::class)
    private suspend fun runProtocol(
        request: AgentExecutionRequest,
        running: RunningAcpProcess,
        translator: AcpEventTranslator,
        wallDeadline: MonotonicDeadline,
        protocolReference: AtomicReference<Protocol?>,
        protocolScopeReference: AtomicReference<CoroutineScope?>,
        filesystemAuditRecorder: AcpFilesystemAuditRecorder,
        filesystemReference: AtomicReference<AcpFilesystemBroker?>,
        terminalAuditRecorder: AcpTerminalAuditRecorder,
        terminalReference: AtomicReference<AcpTerminalBroker?>,
        permissionAuditRecorder: AcpPermissionAuditRecorder,
        sandboxExecution: ProductionAcpSandboxExecution,
    ): PromptOutcome {
        val protocolScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        protocolScopeReference.set(protocolScope)
        val transport = StdioTransport(
            parentScope = protocolScope,
            ioDispatcher = Dispatchers.IO,
            input = running.stdoutFrames(
                configuration.maximumFrameBytes.coerceAtMost(request.limits.maxOutputBytes.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()),
            ),
            output = running::writeFrame,
            name = "decomp-engine-acp-v1",
        )
        val protocol = Protocol(protocolScope, transport)
        protocolReference.set(protocol)
        transport.onError { error -> running.fail(AcpTransportFailure("ACP stdio transport failed", error)) }
        transport.onClose { running.fail(AcpEofFailure("ACP stdout closed")) }
        val client = Client(protocol)
        protocol.start()
        val filesystem = AcpFilesystemBroker.open(
            request,
            configuration.filesystemLimits,
            filesystemAuditRecorder,
        )
        filesystemReference.set(filesystem)
        val terminal = sandboxExecution.openTerminalBroker(
            request = request,
            cancellation = request.cancellation,
            configuredPolicy = configuration.terminalPolicy,
            agentEnvironment = configuration.environment,
            audit = terminalAuditRecorder,
        )
        terminalReference.set(terminal)
        val permission = AcpPermissionBroker(
            request,
            request.cancellation,
            configuration.permissionDecider,
            permissionAuditRecorder,
        )

        val agentInfo = awaitPhase(
            phase = "initialize",
            phaseDeadline = MonotonicDeadline(configuration.timeouts.startup),
            wallDeadline = wallDeadline,
            running = running,
            cancellation = request.cancellation,
            operationScope = protocolScope,
        ) {
            client.initialize(
                ClientInfo(
                    protocolVersion = ACP_STABLE_PROTOCOL_VERSION,
                    capabilities = ClientCapabilities(
                        fs = filesystem.capability,
                        terminal = terminal.capability,
                    ),
                    implementation = Implementation("decomp_engine", "0.1.0"),
                    supportedProtocolVersions = setOf(ACP_STABLE_PROTOCOL_VERSION),
                ),
            )
        }
        if (agentInfo.protocolVersion != ACP_STABLE_PROTOCOL_VERSION) {
            throw AcpProtocolFailure(
                "ACP SDK accepted unexpected protocol version ${agentInfo.protocolVersion}",
            )
        }
        validateCapabilities(agentInfo.capabilities, request)

        val primaryRoot = request.workspaceRoots.first()
        val additionalRoots = request.workspaceRoots.drop(1).map { it.path.toString() }
        val session = awaitPhase(
            phase = "session/new",
            phaseDeadline = MonotonicDeadline(configuration.timeouts.request),
            wallDeadline = wallDeadline,
            running = running,
            cancellation = request.cancellation,
            operationScope = protocolScope,
        ) {
            client.newSession(
                SessionCreationParameters(
                    cwd = primaryRoot.path.toString(),
                    mcpServers = emptyList(),
                    additionalDirectories = additionalRoots.ifEmpty { null },
                ),
            ) { sessionId, _ ->
                // The SDK resolves params.sessionId before dispatching client operations. Bind
                // the raw transport guard here so a forged session cannot be rejected inside
                // the SDK without also becoming a fatal protocol outcome for this execution.
                running.bindSession(sessionId.value)
                translator.recordSession(sessionId.value)
                terminal.bindSession(sessionId.value)
                PolicyClientOperations(
                    translator,
                    filesystem,
                    terminal,
                    permission,
                    sessionId.value,
                )
            }
        }
        running.bindSession(session.sessionId.value)
        translator.recordSession(session.sessionId.value)
        terminal.bindSession(session.sessionId.value)
        val outcome = runPrompt(
            request,
            session,
            running,
            translator,
            terminal,
            filesystemAuditRecorder,
            permissionAuditRecorder,
            wallDeadline,
            protocolScope,
        )
        terminal.throwIfFailed()
        filesystemAuditRecorder.failure()?.let { throw it }
        permissionAuditRecorder.failure()?.let { throw it }
        if (!outcome.hostCancellation) terminal.finishSession(session.sessionId.value)
        return outcome
    }

    private suspend fun <T> awaitPhase(
        phase: String,
        phaseDeadline: MonotonicDeadline,
        wallDeadline: MonotonicDeadline,
        running: RunningAcpProcess,
        cancellation: AgentCancellation,
        operationScope: CoroutineScope,
        operation: suspend () -> T,
    ): T {
        val pending = operationScope.async { operation() }
        while (true) {
            if (pending.isCompleted) return pending.await()
            if (cancellation.isCancellationRequested()) {
                pending.cancel()
                throw RequestedAcpCancellation(phase)
            }
            running.failure.get()?.let { terminal ->
                val drained = withTimeoutOrNull(configuration.timeouts.transportDrainGrace.toMillis()) {
                    Awaited(pending.await())
                }
                if (drained != null) return drained.value
                pending.cancel()
                throw terminal
            }
            val now = System.nanoTime()
            val wallExpired = wallDeadline.hasExpired(now)
            if (phaseDeadline.hasExpired(now) || wallExpired) {
                pending.cancel()
                throw AcpPhaseTimeout(if (wallExpired) "wall-clock" else phase)
            }
            delay(POLL_INTERVAL_MILLIS)
        }
        @Suppress("UNREACHABLE_CODE")
        error("unreachable")
    }

    private suspend fun runPrompt(
        request: AgentExecutionRequest,
        session: ClientSession,
        running: RunningAcpProcess,
        translator: AcpEventTranslator,
        terminal: AcpTerminalBroker,
        filesystemAudit: AcpFilesystemAuditRecorder,
        permissionAudit: AcpPermissionAuditRecorder,
        wallDeadline: MonotonicDeadline,
        operationScope: CoroutineScope,
    ): PromptOutcome {
        val requestDeadline = MonotonicDeadline(configuration.timeouts.request)
        val promptResponse = AtomicReference<PromptResponse?>()
        val promptJob = operationScope.async {
            session.prompt(listOf(ContentBlock.Text(renderPrompt(request)))).collect { event ->
                when (event) {
                    is Event.SessionUpdateEvent -> {
                        // Prompt updates arrive on this event flow, not necessarily through
                        // ClientSessionOperations.notify. Bind in wire order so a following
                        // terminal callback cannot overtake its ToolCallContent.Terminal update.
                        terminal.observeToolCall(session.sessionId.value, event.update)
                        translator.onUpdate(event.update)
                    }
                    is Event.PromptResponseEvent -> {
                        if (!promptResponse.compareAndSet(null, event.response)) {
                            throw AcpProtocolFailure("ACP agent sent more than one final session/prompt response")
                        }
                    }
                }
            }
            promptResponse.get() ?: throw AcpProtocolFailure("ACP session/prompt ended without a stop reason")
        }

        while (true) {
            try {
                terminal.throwIfFailed()
                filesystemAudit.failure()?.let { throw it }
                permissionAudit.failure()?.let { throw it }
            } catch (failure: Throwable) {
                cancelPrompt(session, promptJob, operationScope)
                throw failure
            }
            if (promptJob.isCompleted) {
                val response = promptJob.await()
                terminal.throwIfFailed()
                filesystemAudit.failure()?.let { throw it }
                permissionAudit.failure()?.let { throw it }
                return PromptOutcome(response.stopReason.toContractStopReason(), response)
            }
            translator.callbackFailure.get()?.let { callbackFailure ->
                cancelPrompt(session, promptJob, operationScope)
                throw callbackFailure
            }
            translator.limitFailure.get()?.let { limitSummary ->
                cancelPrompt(session, promptJob, operationScope)
                return PromptOutcome(AgentStopReason.LIMIT_EXHAUSTED, null, limitSummary)
            }
            if (request.cancellation.isCancellationRequested()) {
                cancelPrompt(session, promptJob, operationScope)
                return PromptOutcome(
                    AgentStopReason.CANCELLED,
                    null,
                    "cancelled by caller",
                    hostCancellation = true,
                )
            }
            running.failure.get()?.let { processFailure ->
                val drained = withTimeoutOrNull(configuration.timeouts.transportDrainGrace.toMillis()) {
                    Awaited(promptJob.await())
                }
                if (drained != null) {
                    val response = drained.value
                    terminal.throwIfFailed()
                    filesystemAudit.failure()?.let { throw it }
                    permissionAudit.failure()?.let { throw it }
                    return PromptOutcome(response.stopReason.toContractStopReason(), response)
                }
                promptJob.cancel()
                throw processFailure
            }

            val now = System.nanoTime()
            if (requestDeadline.hasExpired(now) || wallDeadline.hasExpired(now)) {
                cancelPrompt(session, promptJob, operationScope)
                throw AcpPhaseTimeout(if (wallDeadline.hasExpired()) "wall-clock" else "session/prompt")
            }
            if (elapsedSince(translator.activity.lastActivityNanos.get(), now) >= request.limits.idleTimeout) {
                cancelPrompt(session, promptJob, operationScope)
                throw AcpIdleTimeout(request.limits.idleTimeout)
            }
            delay(POLL_INTERVAL_MILLIS)
        }
        @Suppress("UNREACHABLE_CODE")
        error("unreachable")
    }

    private suspend fun cancelPrompt(session: ClientSession, promptJob: Job, operationScope: CoroutineScope) {
        val deadline = MonotonicDeadline(configuration.timeouts.cancellationGrace)
        val cancelJob = operationScope.async { session.cancel() }
        val cancelMillis = deadline.remainingMillis()
        if (cancelMillis > 0) {
            try {
                withTimeoutOrNull(cancelMillis) { cancelJob.await() }
            } catch (_: Exception) {
                // Cancellation is advisory; protocol/runtime exceptions do not weaken teardown.
                // VM Errors deliberately escape rather than being converted into an ordinary denial.
            }
        }
        cancelJob.cancel()
        promptJob.cancel()
        awaitWithin(promptJob, deadline)
    }

    private suspend fun awaitWithin(job: Job, deadline: MonotonicDeadline) {
        val remainingMillis = deadline.remainingMillis()
        if (remainingMillis > 0) withTimeoutOrNull(remainingMillis) { job.join() }
    }

    private fun validateRequest(request: AgentExecutionRequest) {
        request.workspaceRoots.forEach { root ->
            if (!root.path.isDirectory()) {
                throw AgentExecutionException(
                    AgentFailure(
                        AgentFailureKind.INVALID_REQUEST,
                        "ACP workspace root is not a directory: ${root.path}",
                        details = mapOf("rootId" to root.id, "path" to root.path.toString()),
                    ),
                )
            }
        }
    }

    private fun workspaceSnapshotTimeout(
        phase: String,
        session: AgentSessionReference?,
    ): AgentExecutionException = AgentExecutionException(
        AgentFailure(
            AgentFailureKind.TIMEOUT,
            "ACP $phase workspace snapshot exceeded the execution wall-clock timeout",
            retryable = phase == "initial",
            session = session,
            details = mapOf("phase" to "$phase-workspace-snapshot"),
        ),
    )

    private fun validateCapabilities(capabilities: AgentCapabilities, request: AgentExecutionRequest) {
        val required = configuration.requiredAgentCapabilities.toMutableSet()
        if (request.workspaceRoots.size > 1) required += AcpRequiredAgentCapability.ADDITIONAL_DIRECTORIES
        val missing = required.filterNot { capability -> capabilities.supports(capability) }
        if (missing.isNotEmpty()) {
            throw AgentExecutionException(
                AgentFailure(
                    AgentFailureKind.CONFIGURATION,
                    "ACP agent is missing required v1 capabilities: ${missing.joinToString { it.diagnosticName }}",
                    details = mapOf("missingCapabilities" to missing.joinToString(",") { it.diagnosticName }),
                ),
            )
        }
    }

    private fun mapFailure(
        failure: Throwable,
        running: RunningAcpProcess,
        session: AgentSessionReference?,
    ): AgentExecutionException {
        if (failure is Error) throw failure
        if (failure is AgentExecutionException) return failure
        if (failure is RequestedAcpCancellation) {
            return AgentExecutionException(
                AgentFailure(
                    AgentFailureKind.INTERNAL,
                    "ACP cancellation escaped result handling during ${failure.phase}",
                    session = session,
                ),
                failure,
            )
        }
        if (failure is UnsupportedProtocolVersionException) {
            return AgentExecutionException(
                AgentFailure(
                    AgentFailureKind.PROTOCOL,
                    "ACP agent selected unsupported protocol version ${failure.offeredVersion}; this client supports stable v1 only",
                    session = session,
                    details = mapOf(
                        "requestedVersion" to failure.requestedVersion.toString(),
                        "offeredVersion" to failure.offeredVersion.toString(),
                        "supportedVersions" to ACP_STABLE_PROTOCOL_VERSION.toString(),
                    ),
                ),
                failure,
            )
        }
        if (failure is JsonRpcException) {
            val authentication = failure.code == JsonRpcErrorCode.AUTH_REQUIRED.code
            return AgentExecutionException(
                AgentFailure(
                    if (authentication) AgentFailureKind.AUTHENTICATION else AgentFailureKind.PROTOCOL,
                    if (authentication) {
                        "ACP agent requires authentication before session creation; configure the external agent before using this non-interactive harness"
                    } else {
                        "ACP agent returned JSON-RPC error ${failure.code}: ${failure.message}"
                    },
                    retryable = authentication,
                    session = session,
                    details = mapOf("rpcCode" to failure.code.toString()),
                ),
                failure,
            )
        }
        if (failure is AcpPhaseTimeout || failure is AcpIdleTimeout) {
            return AgentExecutionException(
                AgentFailure(
                    AgentFailureKind.TIMEOUT,
                    failure.message ?: "ACP execution timed out",
                    retryable = true,
                    session = session,
                    details = mapOf("pid" to running.process.pid().toString()),
                ),
                failure,
            )
        }
        if (failure is AcpOutputLimitFailure) {
            return AgentExecutionException(
                AgentFailure(
                    AgentFailureKind.RESOURCE_EXHAUSTED,
                    failure.message ?: "ACP stdout limit exceeded",
                    session = session,
                    details = mapOf("pid" to running.process.pid().toString()),
                ),
                failure,
            )
        }
        if (
            failure is AcpMalformedFrameFailure ||
            failure is AcpProtocolFailure ||
            failure is AcpExpectedError ||
            failure is SerializationException
        ) {
            return AgentExecutionException(
                AgentFailure(
                    AgentFailureKind.PROTOCOL,
                    failure.message ?: "malformed ACP v1 message",
                    session = session,
                    details = mapOf("pid" to running.process.pid().toString()),
                ),
                failure,
            )
        }
        if (failure is AcpProcessExitedFailure) {
            return AgentExecutionException(
                AgentFailure(
                    if (failure.exitCode == 0) AgentFailureKind.TRANSPORT else AgentFailureKind.PROCESS_CRASH,
                    "ACP process exited before the protocol exchange completed (exit ${failure.exitCode})",
                    retryable = failure.exitCode != 0,
                    session = session,
                    details = mapOf("pid" to running.process.pid().toString(), "exitCode" to failure.exitCode.toString()),
                ),
                failure,
            )
        }
        if (failure is AcpTerminalFailure || failure is CancellationException || failure is IOException) {
            val exitCode = running.exitCode()
            return AgentExecutionException(
                AgentFailure(
                    if (exitCode != null && exitCode != 0) AgentFailureKind.PROCESS_CRASH else AgentFailureKind.TRANSPORT,
                    failure.message ?: "ACP stdio transport closed unexpectedly",
                    retryable = true,
                    session = session,
                    details = buildMap {
                        put("pid", running.process.pid().toString())
                        if (exitCode != null) put("exitCode", exitCode.toString())
                    },
                ),
                failure,
            )
        }
        return AgentExecutionException(
            AgentFailure(
                AgentFailureKind.INTERNAL,
                failure.message ?: "unexpected ACP client failure",
                session = session,
                details = mapOf("exception" to failure.javaClass.name),
            ),
            failure,
        )
    }
}

/**
 * Hardwired production containment for one harness execution. Its constructor accepts policy
 * data only; no caller-supplied boundary, launcher, or test mode can reach the harness.
 */
private class ProductionAcpSandboxExecution(
    private val configuration: AcpProcessConfiguration,
    request: AgentExecutionRequest,
    activity: ProtocolActivity,
    wallDeadline: MonotonicDeadline,
) : AutoCloseable {
    private val boundary: LinuxBubblewrapBoundary
    private val executionCheck: () -> Unit = {
        if (request.cancellation.isCancellationRequested()) {
            throw RequestedAcpCancellation("sandbox launch")
        }
        if (wallDeadline.hasExpired()) throw AcpPhaseTimeout("wall-clock")
    }
    val running: RunningAcpProcess
    val networkIsolated: Boolean get() = boundary.networkIsolated

    init {
        if (!Files.isRegularFile(configuration.executable) || !Files.isExecutable(configuration.executable)) {
            throw AgentExecutionException(
                AgentFailure(
                    AgentFailureKind.CONFIGURATION,
                    "configured ACP executable is missing or not executable: ${configuration.executable}",
                    details = mapOf("executable" to configuration.executable.toString()),
                ),
            )
        }
        val sandboxConfiguration = configuration.sandboxBoundary ?: throw AgentExecutionException(
            AgentFailure(
                AgentFailureKind.CONFIGURATION,
                "production ACP execution requires the verified Linux bubblewrap/cgroup-v2 sandbox boundary",
            ),
        )
        boundary = try {
            LinuxBubblewrapBoundary.prepare(
                sandboxConfiguration,
                cancellationCheck = executionCheck,
            )
        } catch (failure: Exception) {
            if (failure is RequestedAcpCancellation) throw failure
            if (failure is AcpPhaseTimeout) {
                throw AgentExecutionException(
                    AgentFailure(
                        AgentFailureKind.TIMEOUT,
                        failure.message ?: "ACP execution exceeded its wall-clock timeout during sandbox preparation",
                        retryable = true,
                    ),
                    failure,
                )
            }
            if (failure is AgentExecutionException) throw failure
            if (failure.containsCleanupProofFailure()) {
                throw AgentExecutionException(
                    AgentFailure(
                        AgentFailureKind.INTERNAL,
                        "ACP sandbox preparation failed and cleanup was not proven",
                    ),
                    failure,
                )
            }
            throw AgentExecutionException(
                AgentFailure(
                    AgentFailureKind.CONFIGURATION,
                    "ACP process sandbox boundary is unavailable or could not be verified",
                    details = mapOf("provider" to "bubblewrap+systemd-cgroup-v2"),
                ),
                failure,
            )
        }
        running = try {
            val executableMount = AcpSandboxReadOnlyMount(
                configuration.executable,
                configuration.executable,
                configuration.expectedExecutableManifestSha256,
            )
            boundary.validateReadOnlyMounts(
                listOf(executableMount) + sandboxConfiguration.agentRuntimeMounts,
                executionCheck,
            )
            val sandboxed = boundary.launch(
                AcpSandboxLaunch(
                    command = configuration.command(),
                    environment = configuration.environmentValues(),
                    workingDirectory = sandboxConfiguration.agentWorkingDirectory,
                    resourceLimits = sandboxConfiguration.agentResourceLimits,
                    maximumWallDuration = request.limits.wallClockTimeout,
                    readOnlyMounts = listOf(executableMount) + sandboxConfiguration.agentRuntimeMounts,
                    stagingRoots = emptyList(),
                    purpose = AcpSandboxLaunchPurpose.OUTER_AGENT,
                    emptyDirectories = request.workspaceRoots.map { it.path },
                ),
                mergeError = false,
                cancellationCheck = executionCheck,
            )
            RunningAcpProcess(
                process = sandboxed.process,
                sandboxed = sandboxed,
                containment = AcpProcessContainment.LINUX_BUBBLEWRAP_CGROUP_V2,
                maximumStderrBytes = configuration.maximumStderrBytes,
                maximumProducedOutputBytes = request.limits.maxOutputBytes,
                activity = activity,
            )
        } catch (failure: Throwable) {
            val cleanupFailure = try {
                boundary.close()
                null
            } catch (cleanup: Throwable) {
                cleanup
            }
            if (failure is Error) {
                cleanupFailure?.let(failure::addSuppressed)
                throw failure
            }
            if (cleanupFailure is Error) {
                cleanupFailure.addSuppressed(failure)
                throw cleanupFailure
            }
            if (cleanupFailure != null) {
                cleanupFailure.addSuppressed(failure)
                throw AgentExecutionException(
                    AgentFailure(
                        AgentFailureKind.INTERNAL,
                        "ACP launch failed and sandbox cleanup was not proven",
                    ),
                    cleanupFailure,
                )
            }
            throw mapLaunchFailure(failure)
        }
    }

    fun openTerminalBroker(
        request: AgentExecutionRequest,
        cancellation: AgentCancellation,
        configuredPolicy: AcpTerminalExecutionPolicy?,
        agentEnvironment: Map<String, AcpEnvironmentValue>,
        audit: AcpTerminalAuditRecorder,
    ): AcpTerminalBroker = boundary.openTerminalBroker(
        request,
        cancellation,
        configuredPolicy,
        agentEnvironment,
        audit,
        executionCheck,
    )

    fun evidence(
        policy: AcpTerminalExecutionPolicy?,
        terminalAudit: Collection<AcpTerminalAuditRecord> = emptyList(),
        outerProcessOutput: AcpProducedOutputEvidence? = null,
    ): AcpSandboxEvidence = boundary.evidence(
        policy,
        terminalAudit,
        outerProcessOutput,
        executionCheck,
    )

    override fun close() = boundary.close()

    private fun mapLaunchFailure(failure: Throwable): Throwable = when (failure) {
        is RequestedAcpCancellation, is AgentExecutionException -> failure
        is AcpPhaseTimeout -> AgentExecutionException(
            AgentFailure(
                AgentFailureKind.TIMEOUT,
                failure.message ?: "ACP execution exceeded its wall-clock timeout during sandbox launch",
                retryable = true,
            ),
            failure,
        )
        is AcpCleanupProofFailure -> AgentExecutionException(
            AgentFailure(
                AgentFailureKind.INTERNAL,
                "ACP launch failed and sandbox cleanup was not proven",
            ),
            failure,
        )
        is IOException -> AgentExecutionException(
            AgentFailure(
                AgentFailureKind.CONFIGURATION,
                "failed to launch configured ACP executable: ${configuration.executable}",
                details = mapOf("executable" to configuration.executable.toString()),
            ),
            failure,
        )
        is IllegalArgumentException -> AgentExecutionException(
            AgentFailure(AgentFailureKind.CONFIGURATION, "configured ACP sandbox authority is invalid"),
            failure,
        )
        is IllegalStateException -> AgentExecutionException(
            AgentFailure(
                AgentFailureKind.CONFIGURATION,
                "configured ACP sandbox authority changed before launch",
            ),
            failure,
        )
        else -> failure
    }
}

private class RunningAcpProcess(
    val process: Process,
    private val sandboxed: AcpContainedProcess?,
    private val containment: AcpProcessContainment,
    maximumStderrBytes: Int,
    maximumProducedOutputBytes: Long,
    private val activity: ProtocolActivity,
) {
    val failure = AtomicReference<AcpTerminalFailure?>()
    private val requestIds = JsonRpcRequestTracker()
    private val sessionId = AtomicReference<String?>()
    private val closing = AtomicBoolean(false)
    private val shutdownStarted = AtomicBoolean(false)
    private val producedOutput = ProducedOutputBudget(maximumProducedOutputBytes) {
        terminateForOutputLimit(maximumProducedOutputBytes)
    }
    private val stdoutInput = process.inputStream
    private val stdoutOwnership = AtomicReference(StdoutOwnership.UNCLAIMED)
    private val stdoutNaturallyDrained = AtomicBoolean(false)
    private val stdoutDrainFinished = CompletableFuture<Unit>()
    private val stderrCapture = BoundedStderrCapture(maximumStderrBytes, producedOutput)
    private val stderrNaturallyDrained = AtomicBoolean(false)
    private val stderrDrainFinished = CompletableFuture<Unit>()
    private val stderrThread = Thread.ofVirtual().name("decomp-engine-acp-stderr-${process.pid()}").start {
        try {
            stderrNaturallyDrained.set(stderrCapture.drain(process.errorStream))
        } finally {
            stderrDrainFinished.complete(Unit)
        }
    }

    init {
        process.onExit().thenAccept { exited ->
            if (!closing.get()) fail(AcpProcessExitedFailure(exited.exitValue()))
        }
    }

    fun fail(terminal: AcpTerminalFailure) {
        // Readers keep draining after shutdown starts. A produced-output overflow is a latched
        // policy outcome, not an incidental transport error, and must remain observable even
        // when it is discovered during those final drains.
        if (closing.get() && terminal !is AcpOutputLimitFailure) return
        failure.updateAndGet { current ->
            if (current == null || terminalFailurePriority(terminal) > terminalFailurePriority(current)) terminal else current
        }
    }

    fun bindSession(value: String) {
        if (value.isBlank()) throw AcpProtocolFailure("ACP session id is empty")
        while (true) {
            val existing = sessionId.get()
            if (existing == value) return
            if (existing != null) throw AcpProtocolFailure("ACP execution was rebound across sessions")
            if (sessionId.compareAndSet(null, value)) return
        }
    }

    fun stdoutFrames(maximumFrameBytes: Int): Flow<String> = flow {
        check(stdoutOwnership.compareAndSet(StdoutOwnership.UNCLAIMED, StdoutOwnership.FRAME_CONSUMER)) {
            "ACP stdout already has an active consumer"
        }
        val frame = ByteArrayOutputStream()
        try {
            while (true) {
                val next = try {
                    stdoutInput.read()
                } catch (io: IOException) {
                    if (closing.get()) break
                    val terminal = AcpTransportFailure("failed reading ACP stdout", io)
                    fail(terminal)
                    throw terminal
                }
                if (next < 0) {
                    if (!closing.get()) {
                        val terminal = if (frame.size() == 0) {
                            AcpEofFailure("ACP stdout reached EOF")
                        } else {
                            AcpMalformedFrameFailure("ACP stdout ended in an unterminated JSON-RPC frame")
                        }
                        fail(terminal)
                    }
                    break
                }
                producedOutput.record(1)
                failure.get()?.takeIf { it is AcpOutputLimitFailure }?.let { throw it }
                if (closing.get()) {
                    frame.reset()
                    continue
                }
                if (next == '\n'.code) {
                    val line = try {
                        decodeUtf8(frame.toByteArray())
                    } catch (terminal: AcpMalformedFrameFailure) {
                        fail(terminal)
                        throw terminal
                    }
                    frame.reset()
                    if (line.isBlank()) {
                        val terminal = AcpMalformedFrameFailure("ACP stdout contained an empty JSON-RPC frame")
                        fail(terminal)
                        throw terminal
                    }
                    try {
                        val validated = validateStrictJsonRpcFrame(line)
                        validateInboundSession(validated)
                        requestIds.acceptInbound(validated)?.let(::bindSession)
                        decodeJsonRpcMessage(line)
                    } catch (malformed: Exception) {
                        val detail = malformed.message?.lineSequence()?.firstOrNull()?.take(MAX_PROTOCOL_DIAGNOSTIC_CHARS)
                        val terminal = AcpMalformedFrameFailure(
                            "ACP stdout contained malformed JSON-RPC${detail?.let { ": $it" }.orEmpty()}",
                            malformed,
                        )
                        fail(terminal)
                        throw terminal
                    }
                    activity.touch()
                    emit(line)
                } else {
                    frame.write(next)
                    if (frame.size() > maximumFrameBytes) {
                        val terminal = AcpOutputLimitFailure("ACP stdout frame exceeded the ${maximumFrameBytes}-byte frame limit")
                        fail(terminal)
                        throw terminal
                    }
                }
            }
        } finally {
            stdoutOwnership.compareAndSet(StdoutOwnership.FRAME_CONSUMER, StdoutOwnership.UNCLAIMED)
            if (closing.get()) startShutdownStdoutDrain()
        }
    }

    private fun validateInboundSession(frame: ValidatedJsonRpcFrame) {
        val expected = sessionId.get()
        val encoded = frame.paramsSessionId
        if (expected == null) {
            if (encoded != null || frame.method in ACP_V1_SESSION_SCOPED_CLIENT_METHODS) {
                throw AcpProtocolFailure("ACP inbound session callback arrived before session establishment")
            }
            return
        }
        if (encoded == null) {
            if (frame.method in ACP_V1_SESSION_SCOPED_CLIENT_METHODS) {
                throw AcpProtocolFailure("ACP inbound session callback requires string params.sessionId")
            }
            return
        }
        val supplied = encoded as? JsonPrimitive
        if (supplied == null || !supplied.isString) {
            throw AcpProtocolFailure("ACP inbound JSON-RPC sessionId must be a string")
        }
        if (supplied.content != expected) {
            throw AcpProtocolFailure("ACP inbound JSON-RPC message crossed session boundaries")
        }
    }

    suspend fun writeFrame(frame: String) {
        withContext(Dispatchers.IO) {
            requestIds.acceptOutbound(validateStrictJsonRpcFrame(frame))
            val bytes = "$frame\n".toByteArray(StandardCharsets.UTF_8)
            process.outputStream.write(bytes)
            process.outputStream.flush()
        }
    }

    suspend fun shutdown(
        protocol: Protocol?,
        protocolScope: CoroutineScope?,
        timeout: Duration,
    ): AcpProcessDiagnostics {
        if (!shutdownStarted.compareAndSet(false, true)) {
            return diagnostics(
                forcedTermination = false,
                rootTerminationRequested = false,
                remaining = liveTree().map { it.pid() },
                sandboxCleanupVerified = false,
            )
        }
        val knownHandles = LinkedHashSet<ProcessHandle>()
        knownHandles += process.toHandle()
        knownHandles += process.toHandle().descendants().toList()
        closing.set(true)
        startShutdownStdoutDrain()
        // Reserve one sixth each for protocol close, graceful exit, TERM, KILL, stdout drain,
        // and stderr drain. Stream ownership transfer never overlaps the protocol consumer.
        val shutdownDeadline = MonotonicDeadline(timeout)
        val sliceMillis = (timeout.toMillis() / 6).coerceAtLeast(1)
        val closeMillis = minOf(sliceMillis, shutdownDeadline.remainingMillis())
        if (closeMillis > 0) withTimeoutOrNull(closeMillis) { runCatching { protocol?.close() } }
        protocolScope?.cancel("ACP execution finished")
        startShutdownStdoutDrain()
        runCatching { process.outputStream.close() }

        knownHandles += process.toHandle().descendants().toList()
        val termination = TerminationState(process.pid())

        if (!awaitExit(knownHandles, minOf(sliceMillis, shutdownDeadline.remainingMillis()))) {
            destroyContainedTree(knownHandles, forcibly = false, termination)
            if (!awaitExit(
                    knownHandles,
                    minOf(sliceMillis, shutdownDeadline.remainingMillis()),
                    terminateNewDescendantsForcibly = false,
                    termination = termination,
                )
            ) {
                destroyContainedTree(knownHandles, forcibly = true, termination)
                awaitExit(
                    knownHandles,
                    minOf(sliceMillis, shutdownDeadline.remainingMillis()),
                    terminateNewDescendantsForcibly = true,
                    termination = termination,
                )
            }
        }

        startShutdownStdoutDrain()
        val stdoutMillis = minOf(sliceMillis, shutdownDeadline.remainingMillis())
        if (stdoutMillis > 0) {
            withContext(Dispatchers.IO) {
                runCatching { stdoutDrainFinished.get(stdoutMillis, java.util.concurrent.TimeUnit.MILLISECONDS) }
            }
        }
        if (!stdoutDrainFinished.isDone) {
            // A still-blocked frame consumer owns the same raw stream. Closing it releases that
            // sole owner; its finally block performs the ordered handoff and completes the drain.
            runCatching { stdoutInput.close() }
            startShutdownStdoutDrain()
            val finalStdoutMillis = minOf(sliceMillis, shutdownDeadline.remainingMillis())
            if (finalStdoutMillis > 0) {
                withContext(Dispatchers.IO) {
                    runCatching {
                        stdoutDrainFinished.get(finalStdoutMillis, java.util.concurrent.TimeUnit.MILLISECONDS)
                    }
                }
            }
        }
        runCatching { stdoutInput.close() }
        if (!stdoutDrainFinished.isDone || !stdoutNaturallyDrained.get()) {
            fail(
                AcpOutputLimitFailure(
                    "ACP stdout shutdown drain did not complete; produced-output accounting is indeterminate",
                ),
            )
        }
        val stderrMillis = minOf(sliceMillis, shutdownDeadline.remainingMillis())
        if (stderrMillis > 0) {
            withContext(Dispatchers.IO) {
                runCatching {
                    stderrDrainFinished.get(stderrMillis, java.util.concurrent.TimeUnit.MILLISECONDS)
                }
            }
        }
        if (!stderrDrainFinished.isDone || !stderrNaturallyDrained.get()) {
            // Closing the descriptor is only an unblocking fallback; it is never accepted as
            // evidence that all produced stderr bytes were observed.
            runCatching { process.errorStream.close() }
            val finalStderrMillis = minOf(sliceMillis, shutdownDeadline.remainingMillis())
            if (finalStderrMillis > 0) withContext(Dispatchers.IO) { stderrThread.join(finalStderrMillis) }
            fail(
                AcpOutputLimitFailure(
                    "ACP stderr shutdown drain did not reach EOF; produced-output accounting is indeterminate",
                ),
            )
        } else {
            runCatching { process.errorStream.close() }
        }
        val containedSandbox = sandboxed
        val sandboxCleanupVerified = if (containedSandbox == null) {
            false
        } else {
            runCatching {
                containedSandbox.awaitCleanup(
                    Duration.ofMillis(shutdownDeadline.remainingMillis().coerceAtLeast(1L)),
                )
            }.isSuccess
        }
        val remaining = knownHandles.filter { it.isAlive }.map { it.pid() }.sorted()
        return diagnostics(
            termination.anyRequested,
            termination.rootRequested,
            remaining,
            sandboxCleanupVerified,
        )
    }

    fun exitCode(): Int? = if (process.isAlive) null else try {
        process.exitValue()
    } catch (_: IllegalThreadStateException) {
        null
    }

    fun outputEvidence(): AcpProducedOutputEvidence = AcpProducedOutputEvidence(
        maximumBytes = producedOutput.maximumBytes,
        observedBytes = producedOutput.observedBytes(),
        limitExceeded = producedOutput.exceeded(),
    )

    private fun startShutdownStdoutDrain() {
        if (!closing.get() ||
            !stdoutOwnership.compareAndSet(StdoutOwnership.UNCLAIMED, StdoutOwnership.SHUTDOWN_DRAIN)
        ) return
        Thread.ofVirtual().name("decomp-engine-acp-stdout-drain-${process.pid()}").start {
            val buffer = ByteArray(8192)
            try {
                while (true) {
                    val count = stdoutInput.read(buffer)
                    if (count < 0) {
                        stdoutNaturallyDrained.set(true)
                        break
                    }
                    producedOutput.record(count)
                }
            } catch (_: IOException) {
                // Shutdown closes the shared descriptor only after its bounded drain window.
            } finally {
                stdoutDrainFinished.complete(Unit)
            }
        }
    }

    private fun terminateForOutputLimit(maximumBytes: Long) {
        val terminal = AcpOutputLimitFailure(
            "ACP aggregate stdout and stderr exceeded the ${maximumBytes}-byte execution limit",
        )
        fail(terminal)
        try {
            sandboxed?.destroyForcibly() ?: process.destroyForcibly()
        } catch (failure: Exception) {
            terminal.addSuppressed(failure)
            // Keep a direct process-handle fallback even when the stronger cgroup kill reported
            // an error; shutdown still requires the cgroup cleanup proof before returning.
            runCatching { process.destroyForcibly() }
        }
    }

    private suspend fun awaitExit(
        handles: MutableSet<ProcessHandle>,
        timeoutMillis: Long,
        terminateNewDescendantsForcibly: Boolean? = null,
        termination: TerminationState? = null,
    ): Boolean {
        val deadline = MonotonicDeadline(Duration.ofMillis(timeoutMillis))
        while (!deadline.hasExpired()) {
            discoverDescendants(handles)
            terminateNewDescendantsForcibly?.let { forcibly ->
                destroyContainedTree(handles, forcibly, requireNotNull(termination))
            }
            if (handles.none { it.isAlive }) return true
            delay(minOf(POLL_INTERVAL_MILLIS, deadline.remainingMillis()).coerceAtLeast(1))
        }
        discoverDescendants(handles)
        return handles.none { it.isAlive }
    }

    private fun discoverDescendants(handles: MutableSet<ProcessHandle>) {
        handles.filter { it.isAlive }.forEach { parent ->
            try {
                handles += parent.descendants().toList()
            } catch (_: SecurityException) {
                // The verified cgroup remains authoritative if ProcessHandle enumeration is denied.
            }
        }
    }

    private fun destroyTree(
        handles: Collection<ProcessHandle>,
        forcibly: Boolean,
        termination: TerminationState,
    ) {
        handles.toList().asReversed().filter { it.isAlive }.forEach { handle ->
            val accepted = try {
                if (forcibly) handle.destroyForcibly() else handle.destroy()
            } catch (_: Exception) {
                false
            }
            if (accepted) termination.record(handle.pid())
        }
    }

    private fun destroyContainedTree(
        handles: Collection<ProcessHandle>,
        forcibly: Boolean,
        termination: TerminationState,
    ) {
        val contained = sandboxed
        if (contained == null) {
            destroyTree(handles, forcibly, termination)
            return
        }
        val wasAlive = process.isAlive
        runCatching {
            if (forcibly) contained.destroyForcibly() else contained.destroy()
        }
        if (wasAlive) termination.record(process.pid())
    }

    private fun liveTree(): List<ProcessHandle> =
        (process.toHandle().descendants().toList() + process.toHandle()).filter { it.isAlive }

    private fun diagnostics(
        forcedTermination: Boolean,
        rootTerminationRequested: Boolean,
        remaining: List<Long>,
        sandboxCleanupVerified: Boolean,
    ): AcpProcessDiagnostics =
        AcpProcessDiagnostics(
            pid = process.pid(),
            exitCode = exitCode(),
            stderr = stderrCapture.text(),
            stderrTruncated = stderrCapture.truncated(),
            producedOutputBytes = producedOutput.observedBytes(),
            producedOutputLimitBytes = producedOutput.maximumBytes,
            outputLimitExceeded = producedOutput.exceeded(),
            forcedTermination = forcedTermination || producedOutput.exceeded(),
            rootTerminationRequested = rootTerminationRequested || producedOutput.exceeded(),
            remainingProcessIds = remaining.sorted(),
            containment = containment.name,
            networkIsolated = containment == AcpProcessContainment.LINUX_BUBBLEWRAP_CGROUP_V2,
            sandboxCleanupVerified = sandboxCleanupVerified,
        )
}

private enum class StdoutOwnership { UNCLAIMED, FRAME_CONSUMER, SHUTDOWN_DRAIN }

private class TerminationState(private val rootPid: Long) {
    var anyRequested: Boolean = false
        private set
    var rootRequested: Boolean = false
        private set

    fun record(pid: Long) {
        anyRequested = true
        if (pid == rootPid) rootRequested = true
    }
}

private class ProducedOutputBudget(
    val maximumBytes: Long,
    private val onExceeded: () -> Unit,
) {
    private val observed = AtomicLong(0)
    private val limitExceeded = AtomicBoolean(false)

    init {
        require(maximumBytes > 0) { "maximum produced output must be positive" }
    }

    fun record(count: Int) {
        require(count >= 0) { "produced output count must not be negative" }
        if (count == 0) return
        val increment = count.toLong()
        val total = observed.updateAndGet { current ->
            if (current > Long.MAX_VALUE - increment) Long.MAX_VALUE else current + increment
        }
        if (total > maximumBytes && limitExceeded.compareAndSet(false, true)) onExceeded()
    }

    fun observedBytes(): Long = observed.get()
    fun exceeded(): Boolean = limitExceeded.get()
}

private class BoundedStderrCapture(
    private val maximumBytes: Int,
    private val producedOutput: ProducedOutputBudget,
) {
    private val retained = ByteArrayOutputStream()
    private var observed = 0L

    fun drain(input: java.io.InputStream): Boolean {
        val buffer = ByteArray(8192)
        while (true) {
            val count = try {
                input.read(buffer)
            } catch (_: IOException) {
                return false
            }
            if (count < 0) return true
            producedOutput.record(count)
            synchronized(this) {
                observed = if (observed > Long.MAX_VALUE - count.toLong()) Long.MAX_VALUE else observed + count
                val available = maximumBytes - retained.size()
                if (available > 0) retained.write(buffer, 0, count.coerceAtMost(available))
            }
        }
    }

    @Synchronized
    fun text(): String = retained.toByteArray().toString(StandardCharsets.UTF_8)

    @Synchronized
    fun truncated(): Boolean = observed > retained.size()
}

private class ProtocolActivity {
    val lastActivityNanos = AtomicLong(System.nanoTime())
    fun touch() {
        lastActivityNanos.set(System.nanoTime())
    }
}

private class SequencedEventEmitter(private val consumer: (AgentExecutionEvent) -> Unit) {
    private val sequence = AtomicLong(0)

    @Synchronized
    fun emit(factory: (Long) -> AgentExecutionEvent) {
        consumer(factory(sequence.getAndIncrement()))
    }
}

@OptIn(UnstableApi::class)
private class AcpEventTranslator(
    private val request: AgentExecutionRequest,
    private val emitter: SequencedEventEmitter,
    private val implementationId: String,
) {
    val activity = ProtocolActivity()
    val callbackFailure = AtomicReference<AgentExecutionException?>()
    val limitFailure = AtomicReference<String?>()
    private val sessionId = AtomicReference<String?>()
    private val messageIds = ConcurrentHashMap<AgentMessageRole, String>()
    private val toolTitles = ConcurrentHashMap<String, String>()
    private val toolIds = ConcurrentHashMap.newKeySet<String>()
    private val summary = StringBuilder()
    private val permissionCounter = AtomicLong(0)

    fun recordSession(value: String) {
        if (value.isBlank()) throw AcpProtocolFailure("ACP agent returned an empty session id")
        sessionId.compareAndSet(null, value)
    }

    fun sessionReference(): AgentSessionReference? = sessionId.get()?.let {
        AgentSessionReference(implementationId, it)
    }

    fun toolCallCount(): Int = toolIds.size

    @Synchronized
    fun summary(): String = summary.toString()

    fun onUpdate(update: SessionUpdate) {
        activity.touch()
        try {
            when (update) {
                is SessionUpdate.AgentMessageChunk -> emitMessage(AgentMessageRole.ASSISTANT, update.messageId?.value, update.content)
                is SessionUpdate.UserMessageChunk -> emitMessage(AgentMessageRole.USER, update.messageId?.value, update.content)
                is SessionUpdate.AgentThoughtChunk -> Unit
                is SessionUpdate.PlanUpdate -> {
                    if (update.entries.isNotEmpty()) {
                        val entries = update.entries.mapIndexed { index, entry ->
                            val content = requirePeerText("plan entry content", entry.content)
                            AgentPlanEntry(
                                id = "plan-${index + 1}-${shortDigest(content)}",
                                description = content,
                                status = entry.status.toContractStatus(),
                            )
                        }
                        emitter.emit { sequence ->
                            AgentPlanEvent(sequence, entries)
                        }
                    }
                }
                is SessionUpdate.ToolCall -> {
                    val id = requirePeerText("tool call id", update.toolCallId.value)
                    val title = requirePeerText("tool call title", update.title)
                    toolIds += id
                    toolTitles[id] = title
                    checkToolLimit()
                    emitter.emit { sequence ->
                        AgentToolEvent(
                            sequence,
                            id,
                            title,
                            (update.status ?: ToolCallStatus.PENDING).toContractStatus(),
                            details = buildMap { update.kind?.let { put("kind", it.name.lowercase()) } },
                        )
                    }
                }
                is SessionUpdate.ToolCallUpdate -> {
                    val id = requirePeerText("tool call id", update.toolCallId.value)
                    toolIds += id
                    val title = update.title?.let { requirePeerText("tool call title", it) }
                        ?: toolTitles[id]
                        ?: "ACP tool call"
                    toolTitles[id] = title
                    checkToolLimit()
                    emitter.emit { sequence ->
                        AgentToolEvent(
                            sequence,
                            id,
                            title,
                            (update.status ?: ToolCallStatus.IN_PROGRESS).toContractStatus(),
                            details = buildMap { update.kind?.let { put("kind", it.name.lowercase()) } },
                        )
                    }
                }
                else -> Unit
            }
        } catch (failure: Exception) {
            val wrapped = when (failure) {
                is AgentExecutionException -> failure
                is AcpProtocolFailure, is SerializationException -> AgentExecutionException(
                    AgentFailure(
                        AgentFailureKind.PROTOCOL,
                        failure.message ?: "ACP agent sent an invalid session update",
                        session = sessionReference(),
                    ),
                    failure,
                )
                else -> AgentExecutionException(
                    AgentFailure(
                        AgentFailureKind.INTERNAL,
                        "ACP event consumer failed: ${failure.message ?: failure.javaClass.simpleName}",
                        session = sessionReference(),
                    ),
                    failure,
                )
            }
            callbackFailure.compareAndSet(null, wrapped)
            throw wrapped
        }
    }

    fun onPermission(toolCall: SessionUpdate.ToolCallUpdate, resolved: AcpResolvedPermission) {
        activity.touch()
        val requestId = "permission-${toolCall.toolCallId.value}-${permissionCounter.incrementAndGet()}"
        val decision = when (resolved.selected?.kind) {
            PermissionOptionKind.ALLOW_ONCE -> AgentPermissionDecision.ALLOW_ONCE
            PermissionOptionKind.ALLOW_ALWAYS -> AgentPermissionDecision.ALLOW_SESSION
            PermissionOptionKind.REJECT_ONCE, PermissionOptionKind.REJECT_ALWAYS -> AgentPermissionDecision.DENY
            null -> AgentPermissionDecision.CANCELLED
        }
        emitter.emit { sequence ->
            AgentPermissionEvent(
                sequence = sequence,
                requestId = requestId,
                decision = decision,
                selectedOptionId = resolved.selected?.optionId,
                reason = resolved.auditReason.name.lowercase().replace('_', '-'),
            )
        }
    }

    fun completeMessages() {
        messageIds.entries.sortedBy { it.key.ordinal }.forEach { (role, id) ->
            emitter.emit { sequence -> AgentMessageEvent(sequence, id, role, "", completed = true) }
        }
    }

    private fun emitMessage(role: AgentMessageRole, providedId: String?, content: ContentBlock) {
        val text = when (content) {
            is ContentBlock.Text -> content.text
            is ContentBlock.ResourceLink -> "[resource: ${content.name}]"
            is ContentBlock.Image -> "[image: ${content.mimeType}]"
            is ContentBlock.Audio -> "[audio: ${content.mimeType}]"
            is ContentBlock.Resource -> "[embedded resource]"
        }
        val id = providedId?.let { requirePeerText("message id", it) }
            ?: messageIds.computeIfAbsent(role) { "acp-${role.name.lowercase()}-message" }
        messageIds[role] = id
        if (role == AgentMessageRole.ASSISTANT) synchronized(this) {
            val room = SUMMARY_CHARACTER_LIMIT - summary.length
            if (room > 0) summary.append(text.take(room))
        }
        emitter.emit { sequence -> AgentMessageEvent(sequence, id, role, text) }
    }

    private fun checkToolLimit() {
        if (toolIds.size > request.limits.maxToolCalls) {
            limitFailure.compareAndSet(
                null,
                "ACP agent exceeded the ${request.limits.maxToolCalls}-tool-call execution limit",
            )
        }
    }

    private fun requirePeerText(field: String, value: String): String {
        if (value.isBlank()) throw AcpProtocolFailure("ACP agent returned an empty $field")
        return value
    }
}

private class PolicyClientOperations(
    private val translator: AcpEventTranslator,
    private val filesystem: AcpFilesystemBroker,
    private val terminal: AcpTerminalBroker,
    private val permission: AcpPermissionBroker,
    private val sessionId: String,
) : ClientSessionOperations {
    override suspend fun fsReadTextFile(
        path: String,
        line: UInt?,
        limit: UInt?,
        _meta: JsonElement?,
    ): ReadTextFileResponse = filesystem.readTextFile(sessionId, path, line, limit)

    override suspend fun fsWriteTextFile(
        path: String,
        content: String,
        _meta: JsonElement?,
    ): WriteTextFileResponse = filesystem.writeTextFile(sessionId, path, content)

    override suspend fun terminalCreate(
        command: String,
        args: List<String>,
        cwd: String?,
        env: List<EnvVariable>,
        outputByteLimit: ULong?,
        _meta: JsonElement?,
    ): CreateTerminalResponse = terminal.create(sessionId, command, args, cwd, env, outputByteLimit)

    override suspend fun terminalOutput(
        terminalId: String,
        _meta: JsonElement?,
    ): TerminalOutputResponse = terminal.output(sessionId, terminalId)

    override suspend fun terminalWaitForExit(
        terminalId: String,
        _meta: JsonElement?,
    ): WaitForTerminalExitResponse = terminal.waitForExit(sessionId, terminalId)

    override suspend fun terminalKill(
        terminalId: String,
        _meta: JsonElement?,
    ): KillTerminalCommandResponse = terminal.kill(sessionId, terminalId)

    override suspend fun terminalRelease(
        terminalId: String,
        _meta: JsonElement?,
    ): ReleaseTerminalResponse = terminal.release(sessionId, terminalId)

    override suspend fun requestPermissions(
        toolCall: SessionUpdate.ToolCallUpdate,
        permissions: List<PermissionOption>,
        _meta: JsonElement?,
    ): RequestPermissionResponse {
        // Permission callbacks carry a real ToolCallUpdate. Validate and account it before the
        // terminal broker may bind or release any terminal authority.
        translator.onUpdate(toolCall)
        terminal.observeToolCall(sessionId, toolCall)
        val resolved = permission.decide(sessionId, toolCall, permissions)
        translator.onPermission(toolCall, resolved)
        return resolved.response
    }

    override suspend fun notify(notification: SessionUpdate, _meta: JsonElement?) {
        terminal.observeToolCall(sessionId, notification)
        translator.onUpdate(notification)
    }
}

private data class FileState(val sha256: String, val size: Long)

private class WorkspaceSnapshotBudget(
    private val cancellation: AgentCancellation,
    private val wallDeadline: MonotonicDeadline,
    private val honorCancellation: Boolean,
) {
    fun checkpoint() {
        if (honorCancellation && cancellation.isCancellationRequested()) throw WorkspaceSnapshotCancelled()
        if (wallDeadline.hasExpired()) throw WorkspaceSnapshotTimedOut()
    }
}

private class WorkspaceSnapshotCancelled : RuntimeException()
private class WorkspaceSnapshotTimedOut : RuntimeException()

private class WorkspaceSnapshot private constructor(
    private val files: Map<AgentWorkspacePath, FileState>,
) {
    fun diff(
        after: WorkspaceSnapshot,
        request: AgentExecutionRequest,
        budget: WorkspaceSnapshotBudget,
    ): List<AgentFileChange> {
        return (files.keys + after.files.keys)
            .distinct()
            .sortedWith(compareBy(AgentWorkspacePath::rootId, AgentWorkspacePath::relativePath))
            .mapNotNull { path ->
                budget.checkpoint()
                val beforeState = files[path]
                val afterState = after.files[path]
                if (beforeState == afterState) return@mapNotNull null
                val kind = when {
                    beforeState == null -> AgentFileChangeKind.CREATED
                    afterState == null -> AgentFileChangeKind.DELETED
                    else -> AgentFileChangeKind.MODIFIED
                }
                val operation = when (kind) {
                    AgentFileChangeKind.CREATED -> AgentOperation.CREATE_FILE
                    AgentFileChangeKind.MODIFIED -> AgentOperation.WRITE_FILE
                    AgentFileChangeKind.DELETED -> AgentOperation.DELETE_FILE
                }
                if (!request.accessPolicy.allows(path, operation)) {
                    throw AgentExecutionException(
                        AgentFailure(
                            AgentFailureKind.WORKSPACE_VIOLATION,
                            "ACP agent changed a path without $operation authority: ${path.rootId}:${path.relativePath}",
                            details = mapOf("rootId" to path.rootId, "relativePath" to path.relativePath),
                        ),
                    )
                }
                AgentFileChange(
                    path = path,
                    kind = kind,
                    beforeSha256 = beforeState?.sha256,
                    afterSha256 = afterState?.sha256,
                    sizeBytes = afterState?.size,
                )
            }
    }

    companion object {
        fun capture(request: AgentExecutionRequest, budget: WorkspaceSnapshotBudget): WorkspaceSnapshot {
            val tracked = LinkedHashSet<Pair<String, Path>>()
            request.accessPolicy.pathRules.forEach { rule ->
                budget.checkpoint()
                val root = request.workspaceRoots.single { it.id == rule.path.rootId }
                val target = rule.path.resolve(request.workspaceRoots)
                if (rule.recursive && target.isDirectory(LinkOption.NOFOLLOW_LINKS)) {
                    Files.walk(target).use { paths ->
                        val iterator = paths.iterator()
                        while (true) {
                            budget.checkpoint()
                            if (!iterator.hasNext()) break
                            val candidate = iterator.next()
                            if (candidate.isRegularFile(LinkOption.NOFOLLOW_LINKS)) tracked += root.id to candidate
                        }
                    }
                } else if (target.isRegularFile(LinkOption.NOFOLLOW_LINKS)) {
                    tracked += root.id to target
                }
            }
            val states = LinkedHashMap<AgentWorkspacePath, FileState>()
            tracked.forEach { (rootId, absolute) ->
                budget.checkpoint()
                val root = request.workspaceRoots.single { it.id == rootId }
                val relative = root.path.relativize(absolute).toString().replace(absolute.fileSystem.separator, "/")
                val path = AgentWorkspacePath(rootId, relative)
                states[path] = hashFile(absolute, budget)
            }
            return WorkspaceSnapshot(states)
        }

        private fun hashFile(path: Path, budget: WorkspaceSnapshotBudget): FileState {
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(WORKSPACE_HASH_BUFFER_BYTES)
            var size = 0L
            Files.newInputStream(path).use { input ->
                while (true) {
                    budget.checkpoint()
                    val count = input.read(buffer)
                    if (count < 0) break
                    digest.update(buffer, 0, count)
                    size += count
                }
            }
            budget.checkpoint()
            return FileState(digest.digest().toHex(), size)
        }
    }
}

private data class PromptOutcome(
    val stopReason: AgentStopReason,
    val response: PromptResponse?,
    val summary: String? = null,
    val hostCancellation: Boolean = false,
)

private data class Awaited<T>(val value: T)

private open class AcpTerminalFailure(message: String, cause: Throwable? = null) : IOException(message, cause)
private class AcpTransportFailure(message: String, cause: Throwable? = null) : AcpTerminalFailure(message, cause)
private class AcpEofFailure(message: String) : AcpTerminalFailure(message)
private class AcpMalformedFrameFailure(message: String, cause: Throwable? = null) : AcpTerminalFailure(message, cause)
private class AcpOutputLimitFailure(message: String) : AcpTerminalFailure(message)
private class AcpProcessExitedFailure(val exitCode: Int) : AcpTerminalFailure("ACP process exited with code $exitCode")
internal class AcpProtocolFailure(message: String) : IllegalStateException(message)
private class AcpPhaseTimeout(phase: String) : RuntimeException("ACP $phase exceeded its configured timeout")
private class AcpIdleTimeout(timeout: Duration) : RuntimeException("ACP session/prompt was idle for ${timeout.toMillis()} ms")
private class RequestedAcpCancellation(val phase: String) : RuntimeException("ACP execution cancelled during $phase")

@OptIn(UnstableApi::class)
private fun AgentCapabilities.supports(capability: AcpRequiredAgentCapability): Boolean = when (capability) {
    AcpRequiredAgentCapability.LOAD_SESSION -> loadSession
    AcpRequiredAgentCapability.PROMPT_IMAGE -> promptCapabilities.image
    AcpRequiredAgentCapability.PROMPT_AUDIO -> promptCapabilities.audio
    AcpRequiredAgentCapability.PROMPT_EMBEDDED_CONTEXT -> promptCapabilities.embeddedContext
    AcpRequiredAgentCapability.MCP_HTTP -> mcpCapabilities.http
    AcpRequiredAgentCapability.MCP_SSE -> mcpCapabilities.sse
    AcpRequiredAgentCapability.ADDITIONAL_DIRECTORIES -> sessionCapabilities.additionalDirectories != null
}

private fun StopReason.toContractStopReason(): AgentStopReason = when (this) {
    StopReason.END_TURN -> AgentStopReason.COMPLETED
    StopReason.MAX_TOKENS, StopReason.MAX_TURN_REQUESTS -> AgentStopReason.LIMIT_EXHAUSTED
    StopReason.REFUSAL -> AgentStopReason.REFUSED
    StopReason.CANCELLED -> AgentStopReason.CANCELLED
}

private fun ToolCallStatus.toContractStatus(): AgentToolStatus = when (this) {
    ToolCallStatus.PENDING -> AgentToolStatus.PENDING
    ToolCallStatus.IN_PROGRESS -> AgentToolStatus.IN_PROGRESS
    ToolCallStatus.COMPLETED -> AgentToolStatus.SUCCEEDED
    ToolCallStatus.FAILED -> AgentToolStatus.FAILED
}

private fun PlanEntryStatus.toContractStatus(): AgentPlanStatus = when (this) {
    PlanEntryStatus.PENDING -> AgentPlanStatus.PENDING
    PlanEntryStatus.IN_PROGRESS -> AgentPlanStatus.IN_PROGRESS
    PlanEntryStatus.COMPLETED -> AgentPlanStatus.COMPLETED
}

private fun renderPrompt(request: AgentExecutionRequest): String = buildString {
    appendLine(request.objective)
    if (request.contextInputs.isNotEmpty()) {
        appendLine()
        appendLine("Context inputs (immutable):")
        request.contextInputs.forEach { context ->
            append("--- ").append(context.id).append(" [").append(context.mediaType).append(']')
            context.description?.let { append(" — ").append(it) }
            appendLine()
            appendLine(context.content)
        }
    }
}

private fun tokenLimitExceeded(request: AgentExecutionRequest, usage: AgentUsage): Boolean =
    request.limits.maxInputTokens?.let { (usage.inputTokens ?: 0) > it } == true ||
        request.limits.maxOutputTokens?.let { (usage.outputTokens ?: 0) > it } == true

private fun decodeUtf8(bytes: ByteArray): String = try {
    StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()
} catch (malformed: Exception) {
    throw AcpMalformedFrameFailure("ACP stdout contained invalid UTF-8", malformed)
}

private fun validateStrictJsonRpcFrame(line: String): ValidatedJsonRpcFrame {
    val root = STRICT_JSON.parseToJsonElement(line)
    val message = root as? JsonObject ?: throw SerializationException("JSON-RPC frame must be an object")
    val version = message["jsonrpc"] as? JsonPrimitive
    if (version == null || !version.isString || version.content != "2.0") {
        throw SerializationException("JSON-RPC frame must declare string jsonrpc=2.0")
    }

    val hasMethod = "method" in message
    val hasId = "id" in message
    val hasResult = "result" in message
    val hasError = "error" in message
    if (hasMethod) {
        val method = message["method"] as? JsonPrimitive
        if (method == null || !method.isString || method.content.isBlank()) {
            throw SerializationException("JSON-RPC request method must be a non-empty string")
        }
        if (hasResult || hasError) {
            throw SerializationException("JSON-RPC request cannot contain result or error")
        }
        val params = message["params"]
        params?.let {
            if (params !is JsonObject && params !is JsonArray) {
                throw SerializationException("JSON-RPC params must be an object or array")
            }
        }
        val paramsSessionId = (params as? JsonObject)?.get("sessionId")
        if (hasId) {
            val id = message.getValue("id")
            validateJsonRpcId(id)
            return ValidatedJsonRpcFrame(
                JsonRpcFrameKind.REQUEST,
                id,
                method.content,
                paramsSessionId,
                null,
                false,
            )
        }
        return ValidatedJsonRpcFrame(
            JsonRpcFrameKind.NOTIFICATION,
            null,
            method.content,
            paramsSessionId,
            null,
            false,
        )
    } else {
        if (!hasId || hasResult == hasError) {
            throw SerializationException("JSON-RPC response must contain id and exactly one of result or error")
        }
        if ("params" in message) {
            throw SerializationException("JSON-RPC response cannot contain params")
        }
        validateJsonRpcId(message.getValue("id"))
        if (hasError && message["error"] !is JsonObject) {
            throw SerializationException("JSON-RPC error must be an object")
        }
        return ValidatedJsonRpcFrame(
            JsonRpcFrameKind.RESPONSE,
            message.getValue("id"),
            null,
            null,
            (message["result"] as? JsonObject)?.get("sessionId"),
            hasError,
        )
    }
}

private fun validateJsonRpcId(id: JsonElement) {
    if (
        id !== JsonNull &&
        (id !is JsonPrimitive || (!id.isString && id.content.toBigDecimalOrNull() == null))
    ) {
        throw SerializationException("JSON-RPC id must be a string, number, or null")
    }
}

private enum class JsonRpcFrameKind { REQUEST, NOTIFICATION, RESPONSE }

private data class ValidatedJsonRpcFrame(
    val kind: JsonRpcFrameKind,
    val id: JsonElement?,
    val method: String?,
    val paramsSessionId: JsonElement?,
    val resultSessionId: JsonElement?,
    val errorResponse: Boolean,
)

private class JsonRpcRequestTracker {
    private val pendingOutboundIds = ConcurrentHashMap.newKeySet<String>()
    private val pendingSessionCreationId = AtomicReference<String?>()

    fun acceptOutbound(frame: ValidatedJsonRpcFrame) {
        if (frame.kind != JsonRpcFrameKind.REQUEST) return
        val id = requireNotNull(frame.id)
        val key = canonicalJsonRpcId(id)
        if (!pendingOutboundIds.add(key)) {
            throw AcpProtocolFailure("ACP client attempted to reuse pending JSON-RPC request id ${renderJsonRpcId(id)}")
        }
        if (frame.method == SESSION_NEW_METHOD && !pendingSessionCreationId.compareAndSet(null, key)) {
            pendingOutboundIds.remove(key)
            throw AcpProtocolFailure("ACP client attempted concurrent session creation")
        }
    }

    /** Returns the newly established session id before the stdout reader can consume another frame. */
    fun acceptInbound(frame: ValidatedJsonRpcFrame): String? {
        if (frame.kind != JsonRpcFrameKind.RESPONSE) return null
        val id = requireNotNull(frame.id)
        val key = canonicalJsonRpcId(id)
        if (!pendingOutboundIds.remove(key)) {
            throw AcpProtocolFailure(
                "ACP agent returned an unknown or duplicate JSON-RPC response id ${renderJsonRpcId(id)}",
            )
        }
        if (!consumeSessionCreationId(key)) return null
        if (frame.errorResponse) return null
        val encoded = frame.resultSessionId
            ?: throw AcpProtocolFailure("ACP session/new response omitted string result.sessionId")
        val sessionId = encoded as? JsonPrimitive
        if (sessionId == null || !sessionId.isString || sessionId.content.isBlank()) {
            throw AcpProtocolFailure("ACP session/new response has invalid string result.sessionId")
        }
        return sessionId.content
    }

    private fun consumeSessionCreationId(key: String): Boolean {
        while (true) {
            val pending = pendingSessionCreationId.get() ?: return false
            if (pending != key) return false
            // AtomicReference CAS compares object identity. Use the exact reference loaded above,
            // not the independently canonicalized but value-equal inbound id string.
            if (pendingSessionCreationId.compareAndSet(pending, null)) return true
        }
    }

    private fun canonicalJsonRpcId(id: JsonElement): String = id.toString()

    private fun renderJsonRpcId(id: JsonElement): String =
        id.toString().take(MAX_PROTOCOL_DIAGNOSTIC_CHARS)
}

private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).toHex()

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun shortDigest(value: String): String = sha256(value.toByteArray(StandardCharsets.UTF_8)).take(12)

private fun terminalFailurePriority(failure: Throwable?): Int = when (failure) {
    is AcpOutputLimitFailure -> 60
    is AcpMalformedFrameFailure -> 50
    is AcpProcessExitedFailure -> if (failure.exitCode == 0) 20 else 40
    is AcpEofFailure -> 10
    is AcpTransportFailure -> 30
    else -> 0
}

private fun Throwable.containsCleanupProofFailure(): Boolean {
    val pending = ArrayDeque<Throwable>()
    val visited = java.util.Collections.newSetFromMap(
        java.util.IdentityHashMap<Throwable, Boolean>(),
    )
    pending.addLast(this)
    while (pending.isNotEmpty()) {
        val current = pending.removeFirst()
        if (!visited.add(current)) continue
        if (current is AcpCleanupProofFailure) return true
        current.cause?.let(pending::addLast)
        current.suppressed.forEach(pending::addLast)
    }
    return false
}

private class MonotonicDeadline(timeout: Duration) {
    private val startedAt = System.nanoTime()
    private val timeoutNanos = try {
        timeout.toNanos()
    } catch (_: ArithmeticException) {
        Long.MAX_VALUE
    }

    fun hasExpired(now: Long = System.nanoTime()): Boolean = elapsedNanos(now) >= timeoutNanos

    fun remainingMillis(now: Long = System.nanoTime()): Long {
        val remaining = (timeoutNanos - elapsedNanos(now)).coerceAtLeast(0)
        return remaining / NANOS_PER_MILLI + if (remaining % NANOS_PER_MILLI == 0L) 0 else 1
    }

    private fun elapsedNanos(now: Long): Long = (now - startedAt).coerceAtLeast(0)
}

private fun elapsedSince(then: Long, now: Long): Duration = Duration.ofNanos((now - then).coerceAtLeast(0))

private const val POLL_INTERVAL_MILLIS = 10L
private const val NANOS_PER_MILLI = 1_000_000L
private const val MAX_PROTOCOL_DIAGNOSTIC_CHARS = 256
private const val SESSION_NEW_METHOD = "session/new"
private const val WORKSPACE_HASH_BUFFER_BYTES = 64 * 1024
private const val SUMMARY_CHARACTER_LIMIT = 64 * 1024
// Pinned acp-jvm 0.30.1 Client handlers whose request model carries AcpWithSessionId. Elicitation
// create/complete and protocol cancellation are intentionally absent because they are global.
private val ACP_V1_SESSION_SCOPED_CLIENT_METHODS = setOf(
    "session/request_permission",
    "fs/read_text_file",
    "fs/write_text_file",
    "terminal/create",
    "terminal/kill",
    "terminal/output",
    "terminal/release",
    "terminal/wait_for_exit",
    "session/update",
)
private val STRICT_JSON = Json { isLenient = false }
