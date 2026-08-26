package decompengine.acp

import com.agentclientprotocol.model.CreateTerminalResponse
import com.agentclientprotocol.model.EnvVariable
import com.agentclientprotocol.model.KillTerminalCommandResponse
import com.agentclientprotocol.model.ReleaseTerminalResponse
import com.agentclientprotocol.model.SessionUpdate
import com.agentclientprotocol.model.TerminalExitStatus
import com.agentclientprotocol.model.TerminalOutputResponse
import com.agentclientprotocol.model.ToolCallContent
import com.agentclientprotocol.model.WaitForTerminalExitResponse
import com.agentclientprotocol.protocol.AcpExpectedError
import decompengine.agent.AgentCancellation
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentOperation
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.InvalidPathException
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import java.util.Collections
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

enum class AcpTerminalAuditOutcome { ALLOWED, DENIED, FAILED }

enum class AcpTerminalAuditReason {
    LAUNCH_AUTHORIZED,
    CREATED,
    OUTPUT_OBSERVED,
    EXIT_OBSERVED,
    KILLED,
    RELEASED,
    TOOL_BOUND,
    CAPABILITY_DISABLED,
    WORKFLOW_POLICY_DENIED,
    COMMAND_DENIED,
    INVALID_ARGUMENT,
    INVALID_WORKING_DIRECTORY,
    SECRET_ENVIRONMENT_DENIED,
    TERMINAL_LIMIT,
    OUTPUT_LIMIT,
    TIMEOUT,
    CANCELLED,
    UNKNOWN_TERMINAL,
    UNBOUND_TERMINAL,
    CROSS_SESSION,
    TOOL_BINDING_CONFLICT,
    UNRELEASED_TERMINAL,
    LAUNCH_FAILED,
    POST_COMMIT_FAILED,
    CLEANUP_FAILED,
    SESSION_TEARDOWN,
}

/** Command text, argv, environment values, output, and host paths are deliberately absent. */
data class AcpTerminalAuditRecord(
    val sequence: Long,
    val sessionId: String,
    val method: String,
    val requestSha256: String,
    val terminalIdSha256: String?,
    val toolCallIdSha256: String?,
    val outcome: AcpTerminalAuditOutcome,
    val reason: AcpTerminalAuditReason,
    val networkIsolated: Boolean,
    val retainedOutputBytes: Int?,
    val producedOutputBytes: Long?,
    val outputTruncated: Boolean?,
)

internal class AcpTerminalAuditRecorder(
    private val networkIsolated: Boolean = false,
    private val maximumRecords: Int = MAXIMUM_TERMINAL_AUDIT_RECORDS,
) {
    private val records = mutableListOf<AcpTerminalAuditRecord>()
    private var sequence = 0L
    private var overflowFailure: AcpProtocolFailure? = null

    init {
        require(maximumRecords > 0) { "maximum terminal audit records must be positive" }
    }

    fun record(
        sessionId: String,
        method: String,
        request: String,
        terminalId: String?,
        toolCallId: String?,
        outcome: AcpTerminalAuditOutcome,
        reason: AcpTerminalAuditReason,
        retainedOutputBytes: Int? = null,
        producedOutputBytes: Long? = null,
        outputTruncated: Boolean? = null,
    ) = synchronized(records) {
        if (overflowFailure != null) return@synchronized
        if (records.size >= maximumRecords) {
            overflowFailure = AcpProtocolFailure(
                "ACP terminal audit exceeded the $maximumRecords-record evidence limit",
            )
            return@synchronized
        }
        records += AcpTerminalAuditRecord(
            sequence = sequence++,
            sessionId = sessionId,
            method = method,
            requestSha256 = terminalSha256(request),
            terminalIdSha256 = terminalId?.let(::terminalSha256),
            toolCallIdSha256 = toolCallId?.let(::terminalSha256),
            outcome = outcome,
            reason = reason,
            networkIsolated = networkIsolated,
            retainedOutputBytes = retainedOutputBytes,
            producedOutputBytes = producedOutputBytes,
            outputTruncated = outputTruncated,
        )
    }

    fun snapshot(): List<AcpTerminalAuditRecord> = synchronized(records) {
        Collections.unmodifiableList(ArrayList(records))
    }

    fun failure(): AcpProtocolFailure? = synchronized(records) { overflowFailure }
}

internal sealed class AcpTerminalBroker protected constructor(
    private val request: AgentExecutionRequest,
    private val cancellation: AgentCancellation,
    private val policy: AcpTerminalExecutionPolicy?,
    private val audit: AcpTerminalAuditRecorder,
    private val executionCheck: () -> Unit = {},
) : AutoCloseable {
    private val scheduler: ScheduledExecutorService? = policy?.let {
        Executors.newSingleThreadScheduledExecutor(daemonThreadFactory("acp-terminal-scheduler"))
    }
    private val outputExecutor: ExecutorService? = policy?.let {
        Executors.newFixedThreadPool(
            it.limits.maximumConcurrentTerminals,
            daemonThreadFactory("acp-terminal-output"),
        )
    }
    private val lock = Any()
    private val terminals = LinkedHashMap<String, ManagedTerminal>()
    private val pendingCreates = LinkedHashSet<CompletableFuture<Unit>>()
    private val fatalFailure = AtomicReference<AcpProtocolFailure?>()
    private val fatalCleanupFailure = AtomicReference<AcpCleanupProofFailure?>()
    private var sessionId: String? = null
    private var terminalCreates = 0
    private var closed = false
    private var closeProofFailure: AcpCleanupProofFailure? = null

    /** Frozen once before initialize; callbacks still perform complete authorization. */
    val capability: Boolean = policy != null

    init {
        scheduler?.scheduleWithFixedDelay(
            {
                if (cancellation.isCancellationRequested()) {
                    terminateAll(TerminalTermination.CANCELLED)
                } else {
                    try {
                        executionCheck()
                    } catch (_: Exception) {
                        // The harness reports the execution-wide timeout. The broker independently
                        // prevents a terminal that was already launched from outliving that budget.
                        // VM Errors deliberately escape this scheduler callback.
                        terminateAll(TerminalTermination.TIMEOUT)
                    }
                }
            },
            CANCELLATION_POLL_MILLIS,
            CANCELLATION_POLL_MILLIS,
            TimeUnit.MILLISECONDS,
        )
    }

    fun bindSession(value: String) = synchronized(lock) {
        if (value.isBlank()) throw AcpProtocolFailure("ACP terminal session id is empty")
        val existing = sessionId
        if (existing == null) sessionId = value
        else if (existing != value) failProtocol("ACP terminal broker was reused across sessions")
    }

    suspend fun create(
        callbackSessionId: String,
        command: String,
        args: List<String>,
        cwd: String?,
        env: List<EnvVariable>,
        outputByteLimit: ULong?,
    ): CreateTerminalResponse {
        var requestDigestInput = REJECTED_TERMINAL_REQUEST_DIGEST_INPUT
        var reservation: CompletableFuture<Unit>? = null
        var reservationReleaseProven = true
        val terminalDeadline = policy?.let { TerminalDeadline(it.limits.maximumDuration) }
        try {
            requireTerminalWireValues(command, args, cwd, env)
            requestDigestInput = canonicalTerminalRequest(command, args, cwd, env, outputByteLimit)
            checkpoint(callbackSessionId)
            val activePolicy = policy ?: reject(
                AcpTerminalAuditReason.CAPABILITY_DISABLED,
                "ACP terminal execution is disabled",
            )
            val createDeadline = requireNotNull(terminalDeadline)
            checkpointCreate(callbackSessionId, createDeadline)
            if (AgentOperation.EXECUTE_COMMAND !in request.accessPolicy.allowedOperations) {
                reject(AcpTerminalAuditReason.WORKFLOW_POLICY_DENIED, "workflow policy denies terminal execution")
            }
            val requestedEnvironment = requireEnvironment(env)
            val requestedWorkingDirectory = requirePath(cwd)
            val rule = activePolicy.commandRules.singleOrNull { candidate ->
                candidate.command == command &&
                    candidate.arguments == args &&
                    candidate.workingDirectory == requestedWorkingDirectory &&
                    candidate.environment == requestedEnvironment
            } ?: reject(AcpTerminalAuditReason.COMMAND_DENIED, "terminal command is outside the exact workflow policy")
            rule.environment.keys.firstOrNull(::isCredentialEnvironmentName)?.let {
                reject(AcpTerminalAuditReason.SECRET_ENVIRONMENT_DENIED, "terminal credential environment is denied")
            }
            activePolicy.stagingRoots.forEach { grant ->
                checkpointCreate(callbackSessionId, createDeadline)
                grant.stagingRoot.requireCurrentIdentity(executionCheck)
            }
            val workingRoot = activePolicy.stagingRoots.singleOrNull {
                it.stagingRoot.path == rule.workingDirectory
            } ?: reject(
                AcpTerminalAuditReason.INVALID_WORKING_DIRECTORY,
                "terminal working directory does not resolve to one exact staging authority",
            )
            if (rule.workingDirectory != workingRoot.sandboxPath) {
                reject(
                    AcpTerminalAuditReason.INVALID_WORKING_DIRECTORY,
                    "terminal working directory is not the exact workflow staging root",
                )
            }

            reservation = synchronized(lock) {
                requireSession(callbackSessionId)
                if (closed) reject(AcpTerminalAuditReason.CANCELLED, "terminal session is closed")
                if (cancellation.isCancellationRequested()) {
                    reject(AcpTerminalAuditReason.CANCELLED, "terminal request was cancelled")
                }
                if (terminals.size + pendingCreates.size >= activePolicy.limits.maximumConcurrentTerminals ||
                    terminalCreates + pendingCreates.size >= activePolicy.limits.maximumTerminalCreates
                ) {
                    reject(AcpTerminalAuditReason.TERMINAL_LIMIT, "terminal count limit exceeded")
                }
                CompletableFuture<Unit>().also(pendingCreates::add)
            }
            checkpointCreate(callbackSessionId, createDeadline)
            val terminalId = newTerminalId(callbackSessionId)
            var authorizationRecorded = false
            reservationReleaseProven = false
            val sandboxed = try {
                launchSandbox(
                    AcpSandboxLaunch(
                        command = listOf(rule.command) + rule.arguments,
                        environment = rule.environment,
                        workingDirectory = rule.workingDirectory,
                        resourceLimits = activePolicy.limits.resourceLimits,
                        maximumWallDuration = createDeadline.remainingDuration(),
                        readOnlyMounts = listOf(rule.executable) + rule.runtimeMounts,
                        stagingRoots = activePolicy.stagingRoots,
                    ),
                    mergeError = true,
                    cancellationCheck = {
                        checkpointCreate(callbackSessionId, createDeadline)
                    },
                    beforeAuthorizationCommit = {
                        checkpointCreate(callbackSessionId, createDeadline)
                        synchronized(lock) {
                            requireSession(callbackSessionId)
                            if (closed || cancellation.isCancellationRequested()) {
                                reject(AcpTerminalAuditReason.CANCELLED, "terminal session is closed or cancelled")
                            }
                            if (createDeadline.hasExpired()) {
                                reject(AcpTerminalAuditReason.TIMEOUT, "terminal launch exceeded its wall timeout")
                            }
                            audit.record(
                                callbackSessionId,
                                CREATE_METHOD,
                                requestDigestInput,
                                terminalId,
                                null,
                                AcpTerminalAuditOutcome.ALLOWED,
                                AcpTerminalAuditReason.LAUNCH_AUTHORIZED,
                            )
                            throwIfFailed()
                            authorizationRecorded = true
                        }
                    },
                )
            } catch (failure: AcpCleanupProofFailure) {
                fatalCleanupFailure.compareAndSet(null, failure)
                throw failure
            } catch (_: IOException) {
                reservationReleaseProven = true
                reject(AcpTerminalAuditReason.LAUNCH_FAILED, "terminal sandbox failed safely")
            } catch (failure: Throwable) {
                // The boundary does not return until every pre-commit resource is cleaned. A
                // cleanup-proof failure above deliberately retains the pending reservation.
                reservationReleaseProven = true
                throw failure
            }
            val terminal: ManagedTerminal
            var installedTerminal: ManagedTerminal? = null
            var terminalCreateCounted = false
            try {
                check(authorizationRecorded) {
                    "terminal sandbox crossed its start gate without a write-ahead authorization audit"
                }
                var postCommitTermination: TerminalTermination? = null
                synchronized(lock) {
                    val retainedLimit = outputByteLimit?.let { requested ->
                        minOf(requested, activePolicy.limits.maximumRetainedOutputBytes.toULong()).toInt()
                    } ?: activePolicy.limits.maximumRetainedOutputBytes
                    terminal = ManagedTerminal(
                        id = terminalId,
                        sandboxed = sandboxed,
                        retainedOutputLimit = retainedLimit,
                        limits = activePolicy.limits,
                        remainingDuration = createDeadline.remainingDuration(),
                        outputExecutor = requireNotNull(outputExecutor),
                        scheduler = requireNotNull(scheduler),
                        onOutputLimit = { limited ->
                            val snapshot = limited.output.snapshot()
                            audit.record(
                                callbackSessionId,
                                CREATE_METHOD,
                                requestDigestInput,
                                limited.id,
                                limited.toolCallId.get(),
                                AcpTerminalAuditOutcome.FAILED,
                                AcpTerminalAuditReason.OUTPUT_LIMIT,
                                snapshot.bytes.size,
                                snapshot.producedBytes,
                                snapshot.truncated,
                            )
                        },
                        onAutomaticTermination = { limited, termination ->
                            val reason = when (termination) {
                                TerminalTermination.TIMEOUT -> AcpTerminalAuditReason.TIMEOUT
                                TerminalTermination.CANCELLED -> AcpTerminalAuditReason.CANCELLED
                                TerminalTermination.TEARDOWN -> null
                                else -> null
                            }
                            if (reason != null) {
                                audit.record(
                                    callbackSessionId,
                                    TERMINATION_METHOD,
                                    limited.id,
                                    limited.id,
                                    limited.toolCallId.get(),
                                    if (termination == TerminalTermination.TEARDOWN) {
                                        AcpTerminalAuditOutcome.ALLOWED
                                    } else {
                                        AcpTerminalAuditOutcome.FAILED
                                    },
                                    reason,
                                )
                            }
                        },
                        onCleanupFailure = { failure ->
                            fatalCleanupFailure.compareAndSet(null, failure)
                        },
                    )
                    terminals[terminalId] = terminal
                    installedTerminal = terminal
                    try {
                        audit.record(
                            callbackSessionId,
                            CREATE_METHOD,
                            requestDigestInput,
                            terminalId,
                            null,
                            AcpTerminalAuditOutcome.ALLOWED,
                            AcpTerminalAuditReason.CREATED,
                        )
                        throwIfFailed()
                        terminal.start()
                    } catch (failure: Throwable) {
                        terminals.remove(terminalId, terminal)
                        throw failure
                    }
                    postCommitTermination = when {
                        createDeadline.hasExpired() -> TerminalTermination.TIMEOUT
                        closed || cancellation.isCancellationRequested() -> TerminalTermination.CANCELLED
                        else -> null
                    }
                    terminalCreates++
                    terminalCreateCounted = true
                    reservationReleaseProven = true
                    releaseCreateReservation(requireNotNull(reservation))
                }
                postCommitTermination?.let(terminal::requestTermination)
            } catch (failure: Throwable) {
                synchronized(lock) {
                    if (!terminalCreateCounted) {
                        terminalCreates++
                    }
                }
                installedTerminal?.let { installed ->
                    synchronized(lock) { terminals.remove(installed.id, installed) }
                }
                val cleanupFailures = mutableListOf<Throwable>()
                runCatching { sandboxed.destroyForcibly() }.exceptionOrNull()?.let(cleanupFailures::add)
                runCatching { sandboxed.awaitCleanup(SANDBOX_CLEANUP_TIMEOUT) }
                    .exceptionOrNull()
                    ?.let(cleanupFailures::add)
                if (cleanupFailures.isNotEmpty()) {
                    audit.record(
                        callbackSessionId,
                        CREATE_METHOD,
                        requestDigestInput,
                        terminalId,
                        null,
                        AcpTerminalAuditOutcome.FAILED,
                        AcpTerminalAuditReason.CLEANUP_FAILED,
                    )
                    val cleanup = AcpCleanupProofFailure(
                        "terminal launch initialization failed and sandbox cleanup was not proven",
                        cleanupFailures.first(),
                    )
                    cleanupFailures.drop(1).forEach(cleanup::addSuppressed)
                    fatalCleanupFailure.compareAndSet(null, cleanup)
                    if (failure is Error) {
                        failure.addSuppressed(cleanup)
                        throw failure
                    }
                    val cleanupError = cleanupFailures.firstOrNull { it is Error } as? Error
                    if (cleanupError != null) {
                        cleanupError.addSuppressed(failure)
                        cleanupFailures.filter { it !== cleanupError }.forEach(cleanupError::addSuppressed)
                        throw cleanupError
                    }
                    cleanup.addSuppressed(failure)
                    throw cleanup
                }
                reservationReleaseProven = true
                audit.record(
                    callbackSessionId,
                    CREATE_METHOD,
                    requestDigestInput,
                    terminalId,
                    null,
                    AcpTerminalAuditOutcome.FAILED,
                    AcpTerminalAuditReason.POST_COMMIT_FAILED,
                )
                when (failure) {
                    is Error, is AcpProtocolFailure, is AcpCleanupProofFailure -> throw failure
                    else -> throw TerminalPostCommitFailure(failure)
                }
            }
            return CreateTerminalResponse(terminalId)
        } catch (rejected: TerminalRejected) {
            audit.record(
                callbackSessionId,
                CREATE_METHOD,
                requestDigestInput,
                null,
                null,
                AcpTerminalAuditOutcome.DENIED,
                rejected.reason,
            )
            throw AcpExpectedError(rejected.safeMessage)
        } catch (_: InvalidPathException) {
            audit.record(
                callbackSessionId,
                CREATE_METHOD,
                requestDigestInput,
                null,
                null,
                AcpTerminalAuditOutcome.DENIED,
                AcpTerminalAuditReason.INVALID_ARGUMENT,
            )
            throw AcpExpectedError("terminal request contains an invalid path")
        } catch (failure: AcpCleanupProofFailure) {
            throw failure
        } catch (failure: AcpProtocolFailure) {
            throw failure
        } catch (_: TerminalPostCommitFailure) {
            throw AcpExpectedError("terminal sandbox committed but initialization failed safely")
        } catch (failure: IOException) {
            audit.record(
                callbackSessionId,
                CREATE_METHOD,
                requestDigestInput,
                null,
                null,
                AcpTerminalAuditOutcome.FAILED,
                AcpTerminalAuditReason.LAUNCH_FAILED,
            )
            throw AcpExpectedError("terminal sandbox failed safely")
        } catch (_: IllegalStateException) {
            audit.record(
                callbackSessionId,
                CREATE_METHOD,
                requestDigestInput,
                null,
                null,
                AcpTerminalAuditOutcome.FAILED,
                AcpTerminalAuditReason.LAUNCH_FAILED,
            )
            throw AcpExpectedError("terminal staging authority changed and launch failed safely")
        } finally {
            if (reservationReleaseProven) reservation?.let(::releaseCreateReservation)
        }
    }

    /** Implemented only by the production Linux boundary's private broker. */
    protected abstract fun launchSandbox(
        launch: AcpSandboxLaunch,
        mergeError: Boolean,
        cancellationCheck: () -> Unit,
        beforeAuthorizationCommit: () -> Unit,
    ): AcpContainedProcess

    suspend fun output(callbackSessionId: String, terminalId: String): TerminalOutputResponse {
        val terminal = requireTerminal(callbackSessionId, terminalId, OUTPUT_METHOD)
        val snapshot = terminal.output.snapshot()
        audit.record(
            callbackSessionId,
            OUTPUT_METHOD,
            terminalId,
            terminalId,
            terminal.toolCallId.get(),
            AcpTerminalAuditOutcome.ALLOWED,
            AcpTerminalAuditReason.OUTPUT_OBSERVED,
            snapshot.bytes.size,
            snapshot.producedBytes,
            snapshot.truncated,
        )
        throwIfFailed()
        return TerminalOutputResponse(
            output = snapshot.text,
            truncated = snapshot.truncated,
            exitStatus = terminal.completion.getNow(null)?.toExitStatus(),
        )
    }

    suspend fun waitForExit(callbackSessionId: String, terminalId: String): WaitForTerminalExitResponse {
        val terminal = requireTerminal(callbackSessionId, terminalId, WAIT_METHOD)
        val completion = terminal.awaitCompletion(cancellation)
        val snapshot = terminal.output.snapshot()
        audit.record(
            callbackSessionId,
            WAIT_METHOD,
            terminalId,
            terminalId,
            terminal.toolCallId.get(),
            AcpTerminalAuditOutcome.ALLOWED,
            AcpTerminalAuditReason.EXIT_OBSERVED,
            snapshot.bytes.size,
            snapshot.producedBytes,
            snapshot.truncated,
        )
        throwIfFailed()
        return completion.toWaitResponse()
    }

    suspend fun kill(callbackSessionId: String, terminalId: String): KillTerminalCommandResponse {
        val terminal = requireTerminal(callbackSessionId, terminalId, KILL_METHOD, honorCancellation = false)
        terminal.requestTermination(TerminalTermination.KILLED)
        terminal.awaitCompletion(cancellation, honorCancellation = false)
        val snapshot = terminal.output.snapshot()
        audit.record(
            callbackSessionId,
            KILL_METHOD,
            terminalId,
            terminalId,
            terminal.toolCallId.get(),
            AcpTerminalAuditOutcome.ALLOWED,
            AcpTerminalAuditReason.KILLED,
            snapshot.bytes.size,
            snapshot.producedBytes,
            snapshot.truncated,
        )
        throwIfFailed()
        return KillTerminalCommandResponse()
    }

    suspend fun release(callbackSessionId: String, terminalId: String): ReleaseTerminalResponse {
        val terminal = requireTerminal(callbackSessionId, terminalId, RELEASE_METHOD, honorCancellation = false)
        terminal.requestTermination(TerminalTermination.RELEASED)
        try {
            terminal.awaitCompletion(cancellation, honorCancellation = false)
        } catch (failure: AcpCleanupProofFailure) {
            fatalCleanupFailure.compareAndSet(null, failure)
            audit.record(
                callbackSessionId,
                RELEASE_METHOD,
                terminalId,
                terminalId,
                terminal.toolCallId.get(),
                AcpTerminalAuditOutcome.FAILED,
                AcpTerminalAuditReason.CLEANUP_FAILED,
            )
            throw failure
        }
        val removed = synchronized(lock) { terminals.remove(terminalId) === terminal }
        if (!removed) {
            audit.record(
                callbackSessionId,
                RELEASE_METHOD,
                terminalId,
                terminalId,
                terminal.toolCallId.get(),
                AcpTerminalAuditOutcome.DENIED,
                AcpTerminalAuditReason.UNKNOWN_TERMINAL,
            )
            throw AcpExpectedError("unknown or released ACP terminal id")
        }
        val snapshot = terminal.output.snapshot()
        audit.record(
            callbackSessionId,
            RELEASE_METHOD,
            terminalId,
            terminalId,
            terminal.toolCallId.get(),
            AcpTerminalAuditOutcome.ALLOWED,
            AcpTerminalAuditReason.RELEASED,
            snapshot.bytes.size,
            snapshot.producedBytes,
            snapshot.truncated,
        )
        throwIfFailed()
        return ReleaseTerminalResponse()
    }

    /** Binds client-created terminal ids only to terminal content from this exact ACP session. */
    fun observeToolCall(callbackSessionId: String, update: SessionUpdate) {
        val toolCallId: String
        val content: List<ToolCallContent>
        when (update) {
            is SessionUpdate.ToolCall -> {
                toolCallId = update.toolCallId.value
                content = update.content.orEmpty()
            }
            is SessionUpdate.ToolCallUpdate -> {
                toolCallId = update.toolCallId.value
                content = update.content.orEmpty()
            }
            else -> return
        }
        val terminalContents = content.filterIsInstance<ToolCallContent.Terminal>()
        // General tool-call validation belongs to the event translator. A disabled terminal
        // broker must not intercept unrelated updates (and thereby turn their protocol error
        // into an unanswered notification). Terminal-specific checks begin only when terminal
        // content is actually present.
        if (terminalContents.isEmpty()) return
        if (toolCallId.isBlank()) failProtocol("ACP terminal tool-call id is empty")
        terminalContents.forEach { terminalContent ->
            val terminalId = terminalContent.terminalId
            var newlyBound = false
            val terminal = synchronized(lock) {
                requireSession(callbackSessionId)
                val found = terminals[terminalId]
                    ?: failProtocol("ACP tool call referenced an unknown or cross-session terminal")
                val existing = found.toolCallId.get()
                if (existing == null) {
                    found.toolCallId.set(toolCallId)
                    newlyBound = true
                } else if (existing != toolCallId) {
                    audit.record(
                        callbackSessionId,
                        UPDATE_METHOD,
                        "$toolCallId\u0000$terminalId",
                        terminalId,
                        toolCallId,
                        AcpTerminalAuditOutcome.DENIED,
                        AcpTerminalAuditReason.TOOL_BINDING_CONFLICT,
                    )
                    failProtocol("ACP terminal id was rebound to a different tool call")
                }
                found
            }
            if (newlyBound) {
                audit.record(
                    callbackSessionId,
                    UPDATE_METHOD,
                    "$toolCallId\u0000$terminalId",
                    terminalId,
                    toolCallId,
                    AcpTerminalAuditOutcome.ALLOWED,
                    AcpTerminalAuditReason.TOOL_BOUND,
                )
                throwIfFailed()
            }
        }
    }

    /** Normal prompt completion requires every created terminal to have been bound and released. */
    fun finishSession(callbackSessionId: String) {
        synchronized(lock) { requireSession(callbackSessionId) }
        throwIfFailed()
        val (remaining, inFlightCreates) = synchronized(lock) {
            terminals.values.toList() to pendingCreates.size
        }
        if (inFlightCreates != 0) {
            failProtocol("ACP agent ended the session while terminal creation was still in flight")
        }
        if (remaining.isNotEmpty()) {
            val unbound = remaining.any { it.toolCallId.get() == null }
            terminateAll(TerminalTermination.TEARDOWN)
            val reason = if (unbound) {
                AcpTerminalAuditReason.UNBOUND_TERMINAL
            } else {
                AcpTerminalAuditReason.UNRELEASED_TERMINAL
            }
            remaining.forEach { terminal ->
                audit.record(
                    callbackSessionId,
                    FINISH_METHOD,
                    terminal.id,
                    terminal.id,
                    terminal.toolCallId.get(),
                    AcpTerminalAuditOutcome.FAILED,
                    reason,
                )
            }
            failProtocol(
                if (unbound) "ACP agent left an orphan terminal without tool-call binding"
                else "ACP agent ended the session without releasing every terminal",
            )
        }
    }

    private fun requireTerminal(
        callbackSessionId: String,
        terminalId: String,
        method: String,
        honorCancellation: Boolean = true,
    ): ManagedTerminal {
        try {
            if (honorCancellation) {
                checkpoint(callbackSessionId)
            } else {
                synchronized(lock) { requireSession(callbackSessionId) }
                throwIfFailed()
            }
            val terminal = synchronized(lock) { terminals[terminalId] }
                ?: reject(AcpTerminalAuditReason.UNKNOWN_TERMINAL, "unknown or released ACP terminal id")
            if (terminal.toolCallId.get() == null) {
                reject(AcpTerminalAuditReason.UNBOUND_TERMINAL, "ACP terminal has not been bound to its tool call")
            }
            return terminal
        } catch (rejected: TerminalRejected) {
            audit.record(
                callbackSessionId,
                method,
                terminalId,
                terminalId,
                null,
                AcpTerminalAuditOutcome.DENIED,
                rejected.reason,
            )
            throw AcpExpectedError(rejected.safeMessage)
        }
    }

    private fun checkpoint(callbackSessionId: String) {
        synchronized(lock) {
            requireSession(callbackSessionId)
            if (closed) reject(AcpTerminalAuditReason.CANCELLED, "terminal session is closed")
        }
        throwIfFailed()
        checkpointCancellation()
        executionCheck()
        throwIfFailed()
    }

    /** Lets the harness terminate a hung prompt after a callback latched a fatal broker failure. */
    fun throwIfFailed() {
        fatalCleanupFailure.get()?.let { throw it }
        audit.failure()?.let { auditFailure ->
            fatalFailure.compareAndSet(null, auditFailure)
        }
        fatalFailure.get()?.let { throw it }
    }

    private fun checkpointCreate(callbackSessionId: String, deadline: TerminalDeadline) {
        checkpoint(callbackSessionId)
        if (deadline.hasExpired()) {
            reject(AcpTerminalAuditReason.TIMEOUT, "terminal launch exceeded its wall timeout")
        }
    }

    private fun checkpointCancellation() {
        if (cancellation.isCancellationRequested()) {
            terminateAll(TerminalTermination.CANCELLED)
            reject(AcpTerminalAuditReason.CANCELLED, "terminal request was cancelled")
        }
    }

    private fun requireSession(callbackSessionId: String) {
        val expected = sessionId ?: throw AcpProtocolFailure("ACP terminal broker session is not initialized")
        if (expected != callbackSessionId) {
            audit.record(
                callbackSessionId,
                SESSION_METHOD,
                callbackSessionId,
                null,
                null,
                AcpTerminalAuditOutcome.DENIED,
                AcpTerminalAuditReason.CROSS_SESSION,
            )
            failProtocol("ACP terminal callback crossed session boundaries")
        }
    }

    private fun failProtocol(message: String): Nothing {
        val failure = AcpProtocolFailure(message)
        fatalFailure.compareAndSet(null, failure)
        throw failure
    }

    private fun terminateAll(reason: TerminalTermination) {
        val snapshot = synchronized(lock) { terminals.values.toList() }
        snapshot.forEach { it.requestTermination(reason) }
    }

    private fun releaseCreateReservation(reservation: CompletableFuture<Unit>) {
        val removed = synchronized(lock) { pendingCreates.remove(reservation) }
        if (removed) reservation.complete(Unit)
    }

    override fun close() {
        val pending = synchronized(lock) {
            if (closed) {
                closeProofFailure?.let { throw it }
                if (terminals.isEmpty() && pendingCreates.isEmpty()) return
            } else {
                closed = true
            }
            pendingCreates.toList()
        }
        val failures = mutableListOf<Throwable>()
        fatalCleanupFailure.get()?.let(failures::add)
        val pendingWait = try {
            policy?.limits?.maximumDuration?.plus(SANDBOX_CLEANUP_TIMEOUT)
                ?: SANDBOX_CLEANUP_TIMEOUT
        } catch (_: ArithmeticException) {
            Duration.ofNanos(Long.MAX_VALUE)
        }
        val pendingDeadline = TerminalDeadline(pendingWait)
        pending.forEach { create ->
            try {
                create.get(pendingDeadline.remainingMillis(), TimeUnit.MILLISECONDS)
            } catch (failure: Exception) {
                failures += IOException("in-flight ACP terminal launch did not finish cleanup", failure)
            }
        }
        fatalCleanupFailure.get()?.let { failure ->
            if (failures.none { it === failure }) failures += failure
        }
        val snapshot = synchronized(lock) { terminals.values.toList() }
        val auditSession = synchronized(lock) { sessionId }.orEmpty()
        snapshot.forEach { terminal ->
            runCatching { terminal.requestTermination(TerminalTermination.TEARDOWN) }
                .exceptionOrNull()
                ?.let(failures::add)
        }
        val cleaned = mutableListOf<ManagedTerminal>()
        snapshot.forEach { terminal ->
            try {
                terminal.awaitCompletionBlocking(policy?.limits?.terminationGrace ?: Duration.ofMillis(250))
                cleaned += terminal
                val output = terminal.output.snapshot()
                audit.record(
                    auditSession,
                    TERMINATION_METHOD,
                    terminal.id,
                    terminal.id,
                    terminal.toolCallId.get(),
                    AcpTerminalAuditOutcome.ALLOWED,
                    AcpTerminalAuditReason.SESSION_TEARDOWN,
                    output.bytes.size,
                    output.producedBytes,
                    output.truncated,
                )
            } catch (failure: Throwable) {
                failures += failure
                val output = terminal.output.snapshot()
                audit.record(
                    auditSession,
                    TERMINATION_METHOD,
                    terminal.id,
                    terminal.id,
                    terminal.toolCallId.get(),
                    AcpTerminalAuditOutcome.FAILED,
                    AcpTerminalAuditReason.CLEANUP_FAILED,
                    output.bytes.size,
                    output.producedBytes,
                    output.truncated,
                )
            }
        }
        scheduler?.shutdownNow()
        outputExecutor?.shutdownNow()
        try {
            if (scheduler?.awaitTermination(EXECUTOR_SHUTDOWN_MILLIS, TimeUnit.MILLISECONDS) == false) {
                failures += IOException("ACP terminal scheduler did not terminate")
            }
            if (outputExecutor?.awaitTermination(EXECUTOR_SHUTDOWN_MILLIS, TimeUnit.MILLISECONDS) == false) {
                failures += IOException("ACP terminal output executor did not terminate")
            }
        } catch (failure: InterruptedException) {
            Thread.currentThread().interrupt()
            failures += failure
        }
        synchronized(lock) {
            cleaned.forEach { terminal -> terminals.remove(terminal.id, terminal) }
        }
        if (failures.isNotEmpty()) {
            val primary = AcpCleanupProofFailure(
                "one or more ACP terminal sandboxes did not clean up",
                failures.first(),
            )
            failures.drop(1).forEach(primary::addSuppressed)
            synchronized(lock) { closeProofFailure = primary }
            throw primary
        }
    }

}

private enum class TerminalTermination { KILLED, RELEASED, TIMEOUT, OUTPUT_LIMIT, CANCELLED, TEARDOWN }

private data class TerminalCompletion(
    val exitCode: UInt?,
    val signal: String?,
) {
    fun toExitStatus(): TerminalExitStatus = TerminalExitStatus(exitCode = exitCode, signal = signal)
    fun toWaitResponse(): WaitForTerminalExitResponse = WaitForTerminalExitResponse(exitCode = exitCode, signal = signal)
}

private class ManagedTerminal(
    val id: String,
    private val sandboxed: AcpContainedProcess,
    retainedOutputLimit: Int,
    private val limits: AcpTerminalLimits,
    private val remainingDuration: Duration,
    private val outputExecutor: ExecutorService,
    private val scheduler: ScheduledExecutorService,
    private val onOutputLimit: (ManagedTerminal) -> Unit,
    private val onAutomaticTermination: (ManagedTerminal, TerminalTermination) -> Unit,
    private val onCleanupFailure: (AcpCleanupProofFailure) -> Unit,
) {
    val process: Process get() = sandboxed.process
    val toolCallId = AtomicReference<String?>()
    val output = BoundedTerminalOutput(retainedOutputLimit, limits.maximumProducedOutputBytes)
    val completion = CompletableFuture<TerminalCompletion>()
    private val termination = AtomicReference<TerminalTermination?>()
    private val forced = AtomicBoolean(false)
    private val started = AtomicBoolean(false)

    fun start() {
        check(started.compareAndSet(false, true)) { "ACP terminal monitoring was already started" }
        process.outputStream.close()
        val timeout = scheduler.schedule(
            { requestTermination(TerminalTermination.TIMEOUT) },
            remainingDuration.toMillis().coerceAtLeast(1L),
            TimeUnit.MILLISECONDS,
        )
        try {
            outputExecutor.execute {
                try {
                    try {
                        output.drain(process.inputStream) {
                            observeOutputLimit()
                        }
                    } catch (_: IOException) {
                        // Exit status and bounded retained output remain authoritative.
                    }
                    val exitCode = try {
                        process.waitFor()
                    } catch (interrupted: InterruptedException) {
                        Thread.currentThread().interrupt()
                        sandboxed.destroyForcibly()
                        throw IOException("terminal output waiter was interrupted", interrupted)
                    }
                    val requested = termination.get()
                    sandboxed.awaitCleanup(SANDBOX_CLEANUP_TIMEOUT)
                    completion.complete(
                        if (requested == null) TerminalCompletion(exitCode.toUInt(), null)
                        else TerminalCompletion(null, if (forced.get()) "SIGKILL" else "SIGTERM"),
                    )
                } catch (failure: Exception) {
                    if (failure is AcpCleanupProofFailure) onCleanupFailure(failure)
                    completion.completeExceptionally(failure)
                } catch (failure: Error) {
                    // A VM Error is never normalized into an ordinary terminal failure. Best-effort
                    // containment cleanup is attached, the future records the Error, and the worker's
                    // uncaught-error handler still observes the original fatal condition.
                    try {
                        sandboxed.destroyForcibly()
                        sandboxed.awaitCleanup(SANDBOX_CLEANUP_TIMEOUT)
                    } catch (cleanupFailure: Exception) {
                        failure.addSuppressed(cleanupFailure)
                        if (cleanupFailure is AcpCleanupProofFailure) onCleanupFailure(cleanupFailure)
                    }
                    completion.completeExceptionally(failure)
                    throw failure
                }
            }
        } catch (failure: Throwable) {
            timeout.cancel(false)
            throw failure
        }
    }

    private fun observeOutputLimit() {
        // The output limit is an observed policy outcome even if the root already exited while a
        // descendant still held the pipe. Latch it before auditing and contain the full sandbox.
        val claimed = termination.compareAndSet(null, TerminalTermination.OUTPUT_LIMIT)
        onOutputLimit(this)
        if (claimed) terminateClaimed(TerminalTermination.OUTPUT_LIMIT)
    }

    fun requestTermination(reason: TerminalTermination): Boolean {
        if (!process.isAlive || !termination.compareAndSet(null, reason)) return false
        terminateClaimed(reason)
        return true
    }

    private fun terminateClaimed(reason: TerminalTermination) {
        onAutomaticTermination(this, reason)
        var softFailure: Throwable? = null
        try {
            sandboxed.destroy()
        } catch (failure: Throwable) {
            softFailure = failure
        }
        try {
            scheduler.schedule(
                {
                    if (!completion.isDone) {
                        forced.set(true)
                        sandboxed.destroyForcibly()
                    }
                },
                limits.terminationGrace.toMillis(),
                TimeUnit.MILLISECONDS,
            )
        } catch (_: RejectedExecutionException) {
            forced.set(true)
            sandboxed.destroyForcibly()
        }
        softFailure?.let { throw it }
    }

    suspend fun awaitCompletion(
        cancellation: AgentCancellation,
        honorCancellation: Boolean = true,
    ): TerminalCompletion = withContext(Dispatchers.IO) {
        while (true) {
            if (honorCancellation && cancellation.isCancellationRequested()) {
                requestTermination(TerminalTermination.CANCELLED)
            }
            try {
                return@withContext completion.get(AWAIT_POLL_MILLIS, TimeUnit.MILLISECONDS)
            } catch (_: TimeoutException) {
                continue
            } catch (failure: ExecutionException) {
                val cause = failure.cause
                if (cause is Error) throw cause
                if (cause is AcpCleanupProofFailure) throw cause
                throw IOException("terminal completion failed", cause)
            }
        }
        @Suppress("UNREACHABLE_CODE")
        error("unreachable")
    }

    fun awaitCompletionBlocking(grace: Duration) {
        try {
            completion.get(
                maxOf(1L, grace.plus(SANDBOX_CLEANUP_TIMEOUT).toMillis()),
                TimeUnit.MILLISECONDS,
            )
        } catch (first: Exception) {
            val fatal = (first as? ExecutionException)?.cause as? Error
            if (fatal != null) throw fatal
            forced.set(true)
            val forceFailure = runCatching { sandboxed.destroyForcibly() }.exceptionOrNull()
            try {
                completion.get(
                    maxOf(1L, grace.plus(SANDBOX_CLEANUP_TIMEOUT).toMillis()),
                    TimeUnit.MILLISECONDS,
                )
            } catch (second: Exception) {
                val failure = AcpCleanupProofFailure("terminal sandbox cleanup was not proven", second)
                failure.addSuppressed(first)
                forceFailure?.let(failure::addSuppressed)
                throw failure
            }
            forceFailure?.let { throw IOException("terminal force-termination failed", it) }
        }
    }
}

private data class OutputSnapshot(
    val text: String,
    val bytes: ByteArray,
    val producedBytes: Long,
    val truncated: Boolean,
)

private class BoundedTerminalOutput(
    private val capacity: Int,
    private val maximumProducedBytes: Long,
) {
    private var retained = ByteArray(0)
    private var observed = 0L
    private var limitSignalled = false

    fun drain(input: java.io.InputStream, onLimit: () -> Unit) {
        val buffer = ByteArray(8192)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) return
            var signal = false
            synchronized(this) {
                observed = if (observed > Long.MAX_VALUE - count) Long.MAX_VALUE else observed + count
                if (!limitSignalled && observed > maximumProducedBytes) {
                    limitSignalled = true
                    signal = true
                }
                if (capacity > 0) {
                    val combined = ByteArray(minOf(capacity, retained.size + count))
                    val keepFromOld = minOf(retained.size, maxOf(0, combined.size - count))
                    if (keepFromOld > 0) {
                        retained.copyInto(
                            combined,
                            0,
                            retained.size - keepFromOld,
                            retained.size,
                        )
                    }
                    val keepNew = combined.size - keepFromOld
                    buffer.copyInto(combined, keepFromOld, count - keepNew, count)
                    retained = combined
                }
            }
            if (signal) onLimit()
        }
    }

    @Synchronized
    fun snapshot(): OutputSnapshot {
        var offset = 0
        while (offset < retained.size && retained[offset].toInt() and 0xc0 == 0x80) offset++
        val completeCharacters = retained.copyOfRange(offset, retained.size)
        return OutputSnapshot(
            text = completeCharacters.toString(StandardCharsets.UTF_8),
            bytes = completeCharacters,
            producedBytes = observed,
            truncated = observed > completeCharacters.size.toLong(),
        )
    }
}

private class TerminalRejected(
    val reason: AcpTerminalAuditReason,
    val safeMessage: String,
) : RuntimeException(safeMessage)

private class TerminalPostCommitFailure(cause: Throwable) : RuntimeException(
    "terminal sandbox initialization failed after authorization commit",
    cause,
)

private fun reject(reason: AcpTerminalAuditReason, safeMessage: String): Nothing =
    throw TerminalRejected(reason, safeMessage)

private fun requireEnvironment(values: List<EnvVariable>): Map<String, String> {
    val result = LinkedHashMap<String, String>()
    values.forEach { variable ->
        if (!variable.name.matches(Regex("[A-Za-z_][A-Za-z0-9_]*")) || '\u0000' in variable.value) {
            reject(AcpTerminalAuditReason.INVALID_ARGUMENT, "terminal environment is invalid")
        }
        if (result.putIfAbsent(variable.name, variable.value) != null) {
            reject(AcpTerminalAuditReason.INVALID_ARGUMENT, "terminal environment contains a duplicate name")
        }
        if (isCredentialEnvironmentName(variable.name)) {
            reject(AcpTerminalAuditReason.SECRET_ENVIRONMENT_DENIED, "terminal credential environment is denied")
        }
    }
    return result
}

private fun requirePath(value: String?): Path {
    if (value == null) reject(AcpTerminalAuditReason.INVALID_WORKING_DIRECTORY, "terminal cwd must be explicit")
    val path = Path.of(value)
    if (!path.isAbsolute || path != path.normalize()) {
        reject(AcpTerminalAuditReason.INVALID_WORKING_DIRECTORY, "terminal cwd must be absolute and normalized")
    }
    return path
}

private fun newTerminalId(sessionId: String): String =
    "term-${terminalSha256(sessionId).take(12)}-${UUID.randomUUID()}"

private fun canonicalTerminalRequest(
    command: String,
    args: List<String>,
    cwd: String?,
    env: List<EnvVariable>,
    outputLimit: ULong?,
): String {
    if (args.size >= MAXIMUM_TERMINAL_WIRE_BINDINGS) {
        reject(AcpTerminalAuditReason.INVALID_ARGUMENT, "terminal argv exceeds its authenticated count limit")
    }
    if (env.size > MAXIMUM_TERMINAL_WIRE_BINDINGS) {
        reject(AcpTerminalAuditReason.INVALID_ARGUMENT, "terminal environment exceeds its authenticated count limit")
    }
    val commandBytes = boundedTerminalField(command, MAXIMUM_TERMINAL_WIRE_BYTES, "command")
    var argumentBytes = commandBytes.size.toLong() + 1L
    val encodedArguments = args.map { argument ->
        boundedTerminalField(argument, MAXIMUM_TERMINAL_WIRE_BYTES, "argument").also { bytes ->
            argumentBytes = saturatingTerminalAdd(argumentBytes, bytes.size.toLong() + 1L)
            if (argumentBytes > MAXIMUM_TERMINAL_WIRE_BYTES) {
                reject(AcpTerminalAuditReason.INVALID_ARGUMENT, "terminal argv exceeds its authenticated byte limit")
            }
        }
    }
    val cwdBytes = cwd?.let {
        boundedTerminalField(it, MAXIMUM_TERMINAL_WIRE_BYTES, "working directory")
    }
    var environmentBytes = 0L
    val encodedEnvironment = env.map { variable ->
        val name = boundedTerminalField(variable.name, MAXIMUM_TERMINAL_WIRE_BYTES, "environment name")
        val value = boundedTerminalField(variable.value, MAXIMUM_TERMINAL_WIRE_BYTES, "environment value")
        environmentBytes = saturatingTerminalAdd(
            environmentBytes,
            name.size.toLong() + value.size.toLong() + 2L,
        )
        if (environmentBytes > MAXIMUM_TERMINAL_WIRE_BYTES) {
            reject(AcpTerminalAuditReason.INVALID_ARGUMENT, "terminal environment exceeds its authenticated byte limit")
        }
        name to value
    }
    return buildString {
        append("terminal-request-v2;")
        appendCanonicalField("command", commandBytes)
        append("args-count:").append(encodedArguments.size).append(';')
        encodedArguments.forEach { appendCanonicalField("arg", it) }
        if (cwdBytes == null) append("cwd:null;") else appendCanonicalField("cwd", cwdBytes)
        append("env-count:").append(encodedEnvironment.size).append(';')
        encodedEnvironment.forEach { (name, value) ->
            appendCanonicalField("env-name", name)
            appendCanonicalField("env-value", value)
        }
        append("output-limit:")
        if (outputLimit == null) append("null") else append(outputLimit)
        append(';')
    }
}

private fun requireTerminalWireValues(
    command: String,
    args: List<String>,
    cwd: String?,
    env: List<EnvVariable>,
) {
    if ('\u0000' in command || args.any { '\u0000' in it } || cwd?.contains('\u0000') == true ||
        env.any { '\u0000' in it.name || '\u0000' in it.value }
    ) {
        reject(AcpTerminalAuditReason.INVALID_ARGUMENT, "terminal request contains NUL")
    }
}

private fun boundedTerminalField(value: String, maximumBytes: Long, field: String): ByteArray {
    if (value.length.toLong() > maximumBytes || value.hasUnpairedSurrogate()) {
        reject(AcpTerminalAuditReason.INVALID_ARGUMENT, "terminal $field is not a bounded Unicode value")
    }
    val encoded = value.toByteArray(StandardCharsets.UTF_8)
    if (encoded.size.toLong() > maximumBytes) {
        reject(AcpTerminalAuditReason.INVALID_ARGUMENT, "terminal $field exceeds its authenticated byte limit")
    }
    return encoded
}

private fun String.hasUnpairedSurrogate(): Boolean {
    var index = 0
    while (index < length) {
        val current = this[index]
        when {
            Character.isHighSurrogate(current) -> {
                if (index + 1 >= length || !Character.isLowSurrogate(this[index + 1])) return true
                index += 2
            }
            Character.isLowSurrogate(current) -> return true
            else -> index++
        }
    }
    return false
}

private fun StringBuilder.appendCanonicalField(tag: String, bytes: ByteArray) {
    append(tag.length).append(':').append(tag)
    append(':').append(bytes.size).append(':').append(terminalSha256(bytes)).append(';')
}

private fun saturatingTerminalAdd(left: Long, right: Long): Long =
    if (left > Long.MAX_VALUE - right) Long.MAX_VALUE else left + right

private class TerminalDeadline(timeout: Duration) {
    private val startedAt = System.nanoTime()
    private val timeoutNanos = try {
        timeout.toNanos()
    } catch (_: ArithmeticException) {
        Long.MAX_VALUE
    }

    fun hasExpired(now: Long = System.nanoTime()): Boolean = elapsed(now) >= timeoutNanos

    fun remainingMillis(now: Long = System.nanoTime()): Long {
        val remaining = (timeoutNanos - elapsed(now)).coerceAtLeast(1L)
        return if (remaining > Long.MAX_VALUE - 999_999L) {
            Long.MAX_VALUE / 1_000_000L
        } else {
            ((remaining + 999_999L) / 1_000_000L).coerceAtLeast(1L)
        }
    }

    fun remainingDuration(): Duration = Duration.ofMillis(remainingMillis())

    private fun elapsed(now: Long): Long = (now - startedAt).coerceAtLeast(0L)
}

private fun daemonThreadFactory(prefix: String): java.util.concurrent.ThreadFactory {
    val counter = java.util.concurrent.atomic.AtomicLong(0)
    return java.util.concurrent.ThreadFactory { task ->
        Thread(task, "$prefix-${counter.incrementAndGet()}").apply { isDaemon = true }
    }
}

private fun terminalSha256(value: String): String =
    terminalSha256(value.toByteArray(Charsets.UTF_8))

private fun terminalSha256(value: ByteArray): String =
    MessageDigest.getInstance("SHA-256")
        .digest(value)
        .joinToString("") { "%02x".format(it) }

private const val CREATE_METHOD = "terminal/create"
private const val OUTPUT_METHOD = "terminal/output"
private const val WAIT_METHOD = "terminal/wait_for_exit"
private const val KILL_METHOD = "terminal/kill"
private const val RELEASE_METHOD = "terminal/release"
private const val UPDATE_METHOD = "session/update"
private const val FINISH_METHOD = "session/finish"
private const val TERMINATION_METHOD = "terminal/automatic_termination"
private const val SESSION_METHOD = "terminal/session"
private const val CANCELLATION_POLL_MILLIS = 20L
private const val MAXIMUM_TERMINAL_AUDIT_RECORDS = 4096
private const val MAXIMUM_TERMINAL_WIRE_BINDINGS = 1024
private const val MAXIMUM_TERMINAL_WIRE_BYTES = 1024L * 1024L
private const val REJECTED_TERMINAL_REQUEST_DIGEST_INPUT = "terminal-request-v2:rejected-before-canonicalization"
private const val AWAIT_POLL_MILLIS = 20L
private const val EXECUTOR_SHUTDOWN_MILLIS = 500L
private val SANDBOX_CLEANUP_TIMEOUT = Duration.ofSeconds(4)
