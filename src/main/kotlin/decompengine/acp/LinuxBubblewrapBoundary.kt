package decompengine.acp

import decompengine.agent.AgentCancellation
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentOperation
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import java.math.BigDecimal
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileTime
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.time.Duration
import java.util.Collections
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** A fatal failure to prove that a sandbox scope/tree or one of its pinned resources is gone. */
internal class AcpCleanupProofFailure(
    message: String,
    cause: Throwable? = null,
) : IOException(message, cause)

data class AcpSandboxAuthorityEvidence(
    val rootId: String,
    val rootPathSha256: String,
    val mode: AcpSandboxRootMode,
    val quota: AcpStagingQuotaEvidence?,
)

data class AcpSecurityExecutableEvidence(
    val role: String,
    val canonicalPathSha256: String,
    val contentSha256: String,
    val mode: Int,
    val metadataSha256: String,
)

data class AcpSandboxMountEvidence(
    val sourcePathSha256: String,
    val destinationPathSha256: String,
    val manifestSha256: String,
    val device: Long,
    val inode: Long,
    val mode: Int,
    val directory: Boolean,
)

data class AcpSandboxStartGateEvidence(
    val descriptor: Int,
    val waiterExecutableSha256: String,
    val helperProtocolSha256: String,
    val positiveByteRequired: Boolean,
)

data class AcpSandboxEnvironmentEvidence(
    val sandboxPathSha256: String,
    val bindingNamesSha256: String,
    val bindingCount: Int,
    val encodedBytes: Long,
    val device: Long,
    val inode: Long,
    val mountId: Long,
    val mode: Int,
    val linkCount: Int,
)

data class AcpSandboxRlimitEvidence(
    val processesSoft: Long,
    val processesHard: Long,
    val openFilesSoft: Long,
    val openFilesHard: Long,
    val fileBytesSoft: Long,
    val fileBytesHard: Long,
    val coreBytesSoft: Long,
    val coreBytesHard: Long,
    val addressSpaceSoft: Long,
    val addressSpaceHard: Long,
    val cpuSecondsSoft: Long,
    val cpuSecondsHard: Long,
)

data class AcpCgroupControllerEvidence(
    val pidsMax: Long,
    val memoryMaxBytes: Long,
    val memorySwapMaxBytes: Long,
    val cpuQuotaMicros: Long,
    val cpuPeriodMicros: Long,
    val memoryOomGroup: Boolean,
    val runtimeMaxMicros: Long,
    val timeoutStopMicros: Long,
)

/** Metadata-only aggregate pipe-output accounting for the outer ACP process. */
data class AcpProducedOutputEvidence(
    val maximumBytes: Long,
    val observedBytes: Long,
    val limitExceeded: Boolean,
) {
    init {
        require(maximumBytes > 0) { "produced-output limit must be positive" }
        require(observedBytes >= 0) { "produced-output count must not be negative" }
    }
}

enum class AcpSandboxLaunchPurpose { OUTER_AGENT, TERMINAL }

data class AcpSandboxLaunchEvidence(
    val purpose: AcpSandboxLaunchPurpose,
    val resourceLimits: AcpSandboxResourceLimits,
    val controllers: AcpCgroupControllerEvidence,
    val commandSha256: String,
    val startGate: AcpSandboxStartGateEvidence,
    val environment: AcpSandboxEnvironmentEvidence,
    val effectiveRlimits: AcpSandboxRlimitEvidence,
    val executableMount: AcpSandboxMountEvidence,
    val runtimeMounts: List<AcpSandboxMountEvidence>,
)

/** Metadata-only proof of the boundary frozen for one harness execution. */
class AcpSandboxEvidence internal constructor(
    val provider: String,
    val providerVersion: String,
    val providerExecutableSha256: String,
    val providerExecutableMode: Int,
    val resourceLimiterSha256: String,
    val scopeSupervisorSha256: String,
    val scopeInspectorSha256: String,
    val environmentFdOpenerSha256: String,
    securityExecutables: Collection<AcpSecurityExecutableEvidence>,
    val outerAgentLimits: AcpSandboxResourceLimits,
    val runtimeClosureLimits: AcpRuntimeClosureLimits,
    val cgroupV2PidsLimited: Boolean,
    val cgroupV2MemoryLimited: Boolean,
    val cgroupV2CpuLimited: Boolean,
    val networkIsolated: Boolean,
    val outerAgentContained: Boolean,
    val nestedUserNamespacesDisabled: Boolean,
    val newSession: Boolean,
    val dieWithParent: Boolean,
    val policySha256: String?,
    val terminalLimits: AcpTerminalLimits?,
    launches: Collection<AcpSandboxLaunchEvidence>,
    authorities: Collection<AcpSandboxAuthorityEvidence>,
    terminalAudit: Collection<AcpTerminalAuditRecord>,
    val outerProcessOutput: AcpProducedOutputEvidence? = null,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
) {
    val maximumRecordedLaunches: Int = MAXIMUM_SANDBOX_EVIDENCE_LAUNCHES
    val maximumRecordedRuntimeMounts: Int = MAXIMUM_SANDBOX_EVIDENCE_RUNTIME_MOUNTS
    val maximumCanonicalMetadataBytes: Long = MAXIMUM_SANDBOX_EVIDENCE_BYTES
    init {
        cancellationCheck()
        require(securityExecutables.size <= MAXIMUM_SANDBOX_SECURITY_EXECUTABLES) {
            "sandbox evidence exceeds the security-executable count limit"
        }
        require(launches.size <= MAXIMUM_SANDBOX_EVIDENCE_LAUNCHES) {
            "sandbox evidence exceeds the launch count limit"
        }
        val runtimeMountCount = launches.fold(0) { total, launch ->
            cancellationCheck()
            Math.addExact(total, launch.runtimeMounts.size)
        }
        require(runtimeMountCount <= MAXIMUM_SANDBOX_EVIDENCE_RUNTIME_MOUNTS) {
            "sandbox evidence exceeds the aggregate runtime-mount count limit"
        }
        require(authorities.size <= MAXIMUM_SANDBOX_ROOTS) {
            "sandbox evidence exceeds the authority count limit"
        }
        require(terminalAudit.size <= MAXIMUM_SANDBOX_EVIDENCE_AUDIT_RECORDS) {
            "sandbox evidence exceeds the terminal-audit count limit"
        }
        launches.forEach { launch ->
            cancellationCheck()
            require(launch.runtimeMounts.size <= MAXIMUM_SANDBOX_MOUNTS + 1) {
                "sandbox launch evidence exceeds the runtime-mount count limit"
            }
        }
    }

    val securityExecutables: List<AcpSecurityExecutableEvidence> = Collections.unmodifiableList(
        ArrayList(securityExecutables.sortedWith { left, right ->
            cancellationCheck()
            left.role.compareTo(right.role)
        }),
    )
    val launches: List<AcpSandboxLaunchEvidence> = Collections.unmodifiableList(
        launches.map { launch ->
            cancellationCheck()
            launch.copy(runtimeMounts = Collections.unmodifiableList(
                launch.runtimeMounts.sortedWith(
                    Comparator { left, right ->
                        cancellationCheck()
                        compareValuesBy(
                            left,
                            right,
                            AcpSandboxMountEvidence::destinationPathSha256,
                            AcpSandboxMountEvidence::sourcePathSha256,
                        )
                    },
                ),
            ))
        },
    )
    val authorities: List<AcpSandboxAuthorityEvidence> = Collections.unmodifiableList(
        ArrayList(authorities.sortedWith { left, right ->
            cancellationCheck()
            left.rootId.compareTo(right.rootId)
        }),
    )
    val terminalAudit: List<AcpTerminalAuditRecord> = Collections.unmodifiableList(
        ArrayList(terminalAudit.sortedWith { left, right ->
            cancellationCheck()
            left.sequence.compareTo(right.sequence)
        }),
    )
    /** Canonical metadata-only binding of every effective containment and terminal authority field. */
    val evidenceSha256: String = canonicalSandboxEvidenceDigest(this, cancellationCheck)
}

internal enum class AcpProcessContainment {
    LINUX_BUBBLEWRAP_CGROUP_V2,
}

internal data class AcpSandboxLaunch(
    val command: List<String>,
    val environment: Map<String, String>,
    val workingDirectory: Path,
    val resourceLimits: AcpSandboxResourceLimits,
    val maximumWallDuration: Duration,
    val readOnlyMounts: List<AcpSandboxReadOnlyMount>,
    val stagingRoots: List<AcpSandboxRootGrant>,
    val purpose: AcpSandboxLaunchPurpose = AcpSandboxLaunchPurpose.TERMINAL,
    /** Private empty namespace anchors, never host binds. Used for ACP session cwd declarations. */
    val emptyDirectories: List<Path> = emptyList(),
) {
    init {
        require(!maximumWallDuration.isZero && !maximumWallDuration.isNegative) {
            "sandbox maximum wall duration must be positive"
        }
        require(command.isNotEmpty() && command.size <= MAXIMUM_SANDBOX_ARGUMENTS) {
            "sandbox command argument count is invalid"
        }
        require(readOnlyMounts.size <= MAXIMUM_SANDBOX_MOUNTS) {
            "sandbox launch exceeds the runtime mount-count limit"
        }
        require(stagingRoots.size <= MAXIMUM_SANDBOX_ROOTS) {
            "sandbox launch exceeds the staging-root count limit"
        }
        require(emptyDirectories.size <= MAXIMUM_SANDBOX_EMPTY_DIRECTORIES) {
            "sandbox launch exceeds the empty-anchor count limit"
        }
        require(environment.size <= MAXIMUM_SANDBOX_ENVIRONMENT_BINDINGS) {
            "sandbox launch exceeds the environment binding-count limit"
        }
        require(command.none { '\u0000' in it }) { "sandbox command arguments may not contain NUL" }
        val encodedArgumentBytes = command.fold(0L) { total, argument ->
            Math.addExact(total, utf8Length(argument) + 1L)
        }
        require(encodedArgumentBytes <= MAXIMUM_SANDBOX_ARGUMENT_BYTES) {
            "sandbox command arguments exceed the authenticated byte limit"
        }
    }
}

internal fun interface AcpSandboxCommandObserver {
    fun beforeStart(command: List<String>)
}

internal enum class AcpSandboxLaunchStage {
    DURING_RUNTIME_CLOSURE,
    BEFORE_SCOPE_START,
    AFTER_ROOT_PROCESS_HANDLE_OPEN,
    DURING_SCOPE_VERIFICATION,
    AFTER_SCOPE_ATTACHED_BEFORE_SETUP_ATTESTATION,
    DURING_SETUP_ATTESTATION,
    AFTER_SETUP_WAITER_BEFORE_BIND_ATTESTATION,
    DURING_BIND_ATTESTATION,
    DURING_RLIMIT_ATTESTATION,
    AFTER_SETUP_BIND_ATTESTATION_BEFORE_RELEASE,
}

/** Deterministic test seam for cancellation and cleanup at the actual authorization boundary. */
internal fun interface AcpSandboxLaunchHook {
    fun at(stage: AcpSandboxLaunchStage)
}

internal enum class AcpSandboxCleanupStage {
    SCOPE_SIGNAL,
    ROOT_PROCESS_SIGNAL,
    SCOPE,
    RUNTIME_SNAPSHOTS,
    CONTROL_DIRECTORY,
}

/** Fault seam; an injected failure is recorded but never skips the real cleanup action. */
internal fun interface AcpSandboxCleanupHook {
    fun at(stage: AcpSandboxCleanupStage)
}

internal data class AcpSandboxScopeIdentity(val unitName: String, val cgroupPath: Path)

internal fun interface AcpSandboxScopeObserver {
    fun verified(identity: AcpSandboxScopeIdentity)
}

private class LaunchEvidenceReservation(val evidence: AcpSandboxLaunchEvidence) {
    val committed = AtomicBoolean(false)
}

internal interface AcpContainedProcess {
    val process: Process
    fun destroy()
    fun destroyForcibly()
    fun awaitCleanup(timeout: Duration)
}

/** One systemd scope and its gated bubblewrap process. */
internal class AcpSandboxedProcess internal constructor(
    override val process: Process,
    private val rootProcessHandle: LinuxProcessDescriptor,
    private val scope: VerifiedSystemdScope,
    private val cleanupAfterScope: () -> Unit,
    private val onCleanupProven: (AcpSandboxedProcess) -> Unit,
    private val onCleanupFailed: (AcpCleanupProofFailure) -> Unit,
    private val cleanupHook: AcpSandboxCleanupHook?,
) : AcpContainedProcess {
    private val cleanup = CompletableFuture<Unit>()
    private val rootProcessHandleClosed = AtomicBoolean(false)
    internal val scopeIdentity: AcpSandboxScopeIdentity get() = scope.identity

    init {
        process.onExit().whenComplete { _, _ ->
            val failures = mutableListOf<Throwable>()
            try {
                val scopeCleaned = runCleanupStep(
                    failures,
                    AcpSandboxCleanupStage.SCOPE,
                    cleanupHook,
                    scope::requireCleaned,
                )
                if (scopeCleaned) {
                    runCleanupStep(
                        failures,
                        AcpSandboxCleanupStage.RUNTIME_SNAPSHOTS,
                        cleanupHook,
                        cleanupAfterScope,
                    )
                } else {
                    failures += IOException(
                        "runtime snapshots retained because scope cleanup was not proven",
                    )
                }
            } finally {
                if (failures.isEmpty()) {
                    try {
                        onCleanupProven(this)
                        closeRootProcessHandle()
                        cleanup.complete(Unit)
                    } catch (failure: Throwable) {
                        closeRootProcessHandle()
                        val proofFailure = AcpCleanupProofFailure(
                            "sandbox cleanup bookkeeping failed",
                            failure,
                        )
                        onCleanupFailed(proofFailure)
                        cleanup.completeExceptionally(proofFailure)
                    }
                } else {
                    val primary = AcpCleanupProofFailure(
                        "sandbox process cleanup proof failed",
                        failures.first(),
                    )
                    failures.drop(1).forEach(primary::addSuppressed)
                    onCleanupFailed(primary)
                    cleanup.completeExceptionally(primary)
                }
            }
        }
    }

    override fun destroy() = signal(force = false)

    override fun destroyForcibly() = signal(force = true)

    private fun signal(force: Boolean) {
        val failures = mutableListOf<Throwable>()
        try {
            cleanupHook?.at(AcpSandboxCleanupStage.SCOPE_SIGNAL)
            if (force) scope.killAll() else scope.terminateAll()
        } catch (failure: Throwable) {
            failures += failure
        }
        try {
            cleanupHook?.at(AcpSandboxCleanupStage.ROOT_PROCESS_SIGNAL)
            if (force) {
                LinuxFilesystemSyscalls.killProcess(rootProcessHandle)
            } else {
                LinuxFilesystemSyscalls.terminateProcess(rootProcessHandle)
            }
        } catch (failure: Throwable) {
            failures += failure
        }
        if (failures.isNotEmpty()) {
            val primary = IOException("sandbox termination signaling was not fully applied", failures.first())
            failures.drop(1).forEach(primary::addSuppressed)
            throw primary
        }
    }

    override fun awaitCleanup(timeout: Duration) {
        try {
            cleanup.get(maxOf(1L, timeout.toMillis()), TimeUnit.MILLISECONDS)
        } catch (failure: java.util.concurrent.ExecutionException) {
            val cause = failure.cause
            if (cause is AcpCleanupProofFailure) throw cause
            throw AcpCleanupProofFailure("sandbox scope did not clean up completely", cause ?: failure)
        } catch (failure: Exception) {
            throw AcpCleanupProofFailure("sandbox scope did not clean up completely", failure)
        }
    }

    fun cleanupSucceeded(): Boolean = cleanup.isDone && !cleanup.isCompletedExceptionally

    /** Re-attempts the retained scope/resource proof without erasing the original fatal result. */
    fun retryCleanupProof() {
        scope.requireCleaned()
        cleanupAfterScope()
        onCleanupProven(this)
        closeRootProcessHandle()
    }

    private fun closeRootProcessHandle() {
        if (rootProcessHandleClosed.compareAndSet(false, true)) rootProcessHandle.close()
    }
}

/**
 * Production Linux boundary. Bubblewrap supplies namespace/mount isolation; a verified transient
 * systemd scope supplies atomic cgroup-v2 pids, memory, and CPU limits. There is no fallback.
 */
internal class LinuxBubblewrapBoundary private constructor(
    private val configuration: AcpLinuxSandboxConfiguration,
    private val bubblewrap: PinnedSecurityExecutable,
    private val resourceLimiter: PinnedSecurityExecutable,
    private val scopeSupervisor: PinnedSecurityExecutable,
    private val scopeInspector: PinnedSecurityExecutable,
    private val environmentFdOpener: PinnedSecurityExecutable,
    private val sandboxGateHelperMount: AcpSandboxReadOnlyMount,
    private val sandboxGateHelperSha256: String,
    private val busEndpoint: PinnedSystemdBusEndpoint,
    private val launcherMounts: List<PinnedReadOnlyMount>,
    private val forbiddenRuntimeFiles: Set<ForbiddenRuntimeFile>,
    private val controlDirectory: PinnedControlDirectory,
    val evidenceBase: AcpSandboxEvidence,
    private val observer: AcpSandboxCommandObserver?,
    private val launchHook: AcpSandboxLaunchHook?,
    private val cleanupHook: AcpSandboxCleanupHook?,
    private val scopeObserver: AcpSandboxScopeObserver?,
) : AutoCloseable {
    val networkIsolated: Boolean = true
    private val active = ConcurrentHashMap.newKeySet<AcpSandboxedProcess>()
    private val unresolvedLaunches = ConcurrentHashMap.newKeySet<RetainedLaunchCleanup>()
    private val successfulLaunches =
        Collections.synchronizedList(mutableListOf<LaunchEvidenceReservation>())
    private var launchEvidenceRuntimeMounts = 0
    private val closed = AtomicBoolean(false)
    private val closeFailure = AtomicReference<AcpCleanupProofFailure?>()

    fun validateReadOnlyMounts(
        mounts: Collection<AcpSandboxReadOnlyMount>,
        cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
    ) {
        closeFailure.get()?.let { throw it }
        try {
            cancellationCheck()
            val pinned = pinMounts(
                mounts,
                configuration.runtimeClosureLimits,
                forbiddenRuntimeFiles,
                controlDirectory,
                cancellationCheck = cancellationCheck,
            )
            try {
                pinned.forEach { mount ->
                    cancellationCheck()
                    mount.requireUnchanged(cancellationCheck)
                }
            } finally {
                deletePinnedMounts(pinned)
            }
        } catch (failure: AcpCleanupProofFailure) {
            closeFailure.compareAndSet(null, failure)
            throw failure
        }
    }

    /**
     * Opens the only production terminal broker implementation. Callers supply policy data, never
     * an execution boundary or launcher; this already-verified boundary remains the final launch
     * authority for the complete broker lifetime.
     */
    fun openTerminalBroker(
        request: AgentExecutionRequest,
        cancellation: AgentCancellation,
        configuredPolicy: AcpTerminalExecutionPolicy?,
        agentEnvironment: Map<String, AcpEnvironmentValue>,
        audit: AcpTerminalAuditRecorder,
        cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
    ): AcpTerminalBroker {
        closeFailure.get()?.let { throw it }
        val effectivePolicy = configuredPolicy?.takeIf {
            AgentOperation.EXECUTE_COMMAND in request.accessPolicy.allowedOperations
        }
        if (effectivePolicy != null) {
            cancellationCheck()
            val requestRoots = request.workspaceRoots.associateBy { it.id }
            effectivePolicy.stagingRoots.forEach { grant ->
                cancellationCheck()
                val requestRoot = requestRoots[grant.stagingRoot.rootId]
                    ?: throw IllegalArgumentException("terminal staging root is absent from the workflow request")
                require(requestRoot.path == grant.stagingRoot.path) {
                    "terminal staging root path differs from the workflow request"
                }
                require(
                    grant.mode == AcpSandboxRootMode.READ_ONLY || grant.stagingRoot.quotaProof != null,
                ) { "writable terminal staging root lacks verified aggregate quota authority" }
                grant.stagingRoot.requireCurrentIdentity(cancellationCheck)
            }
            val rawSecrets = agentEnvironment.values.asSequence()
                .filter { it.provenance == AcpEnvironmentProvenance.SECRET }
                .map(AcpEnvironmentValue::value)
                .filter(String::isNotEmpty)
                .toSet()
            effectivePolicy.commandRules.forEach { rule ->
                cancellationCheck()
                val authority = terminalAuthorityStrings(rule, effectivePolicy.stagingRoots)
                val leaked = rawSecrets.firstOrNull { secret ->
                    cancellationCheck()
                    authority.any { value ->
                        cancellationCheck()
                        secret in value
                    }
                }
                require(leaked == null) {
                    "terminal policy contains raw bytes from a secret ACP environment binding"
                }
                validateReadOnlyMounts(
                    listOf(rule.executable) + rule.runtimeMounts,
                    cancellationCheck,
                )
            }
        }
        return VerifiedTerminalBroker(
            request,
            cancellation,
            effectivePolicy,
            audit,
            cancellationCheck,
        )
    }

    private inner class VerifiedTerminalBroker(
        request: AgentExecutionRequest,
        cancellation: AgentCancellation,
        policy: AcpTerminalExecutionPolicy?,
        audit: AcpTerminalAuditRecorder,
        executionCheck: () -> Unit,
    ) : AcpTerminalBroker(request, cancellation, policy, audit, executionCheck) {
        override fun launchSandbox(
            launch: AcpSandboxLaunch,
            mergeError: Boolean,
            cancellationCheck: () -> Unit,
            beforeAuthorizationCommit: () -> Unit,
        ): AcpContainedProcess = this@LinuxBubblewrapBoundary.launch(
            launch,
            mergeError,
            cancellationCheck,
            beforeAuthorizationCommit,
        )
    }

    fun launch(
        launch: AcpSandboxLaunch,
        mergeError: Boolean,
        cancellationCheck: () -> Unit,
    ): AcpSandboxedProcess = launch(
        launch,
        mergeError,
        cancellationCheck,
        beforeAuthorizationCommit = {},
    )

    fun launch(
        launch: AcpSandboxLaunch,
        mergeError: Boolean,
        cancellationCheck: () -> Unit,
        beforeAuthorizationCommit: () -> Unit,
    ): AcpSandboxedProcess {
        closeFailure.get()?.let { throw it }
        if (closed.get()) throw IOException("ACP sandbox boundary is closed")
        launch.stagingRoots.forEach { grant ->
            if (grant.mode == AcpSandboxRootMode.READ_WRITE && grant.stagingRoot.quotaProof == null) {
                throw IOException("writable sandbox staging root lacks verified aggregate quota authority")
            }
        }
        launchCheckpoint(AcpSandboxLaunchStage.DURING_RUNTIME_CLOSURE, cancellationCheck)
        requireBoundaryUnchanged(cancellationCheck)
        var launchMounts = emptyList<PinnedReadOnlyMount>()
        var environmentFile: SandboxEnvironmentFile? = null
        var scopeController: SystemdScopeController? = null
        var process: Process? = null
        var rootProcessHandle: LinuxProcessDescriptor? = null
        var sandboxed: AcpSandboxedProcess? = null
        var launchEvidenceReservation: LaunchEvidenceReservation? = null
        try {
            launchMounts = pinMounts(
                listOf(sandboxGateHelperMount) + launch.readOnlyMounts,
                configuration.runtimeClosureLimits,
                forbiddenRuntimeFiles,
                controlDirectory,
                cancellationCheck = {
                    launchCheckpoint(AcpSandboxLaunchStage.DURING_RUNTIME_CLOSURE, cancellationCheck)
                },
            )
            val launchGateHelper = launchMounts.singleOrNull {
                it.mount.destination == ACP_SANDBOX_GATE_HELPER_PATH
            } ?: throw IOException("sandbox launch lacks its private static gate-helper snapshot")
            launchGateHelper.requireStaticGateHelper(
                sandboxGateHelperSha256,
                cancellationCheck,
            )
            val createdEnvironment = SandboxEnvironmentFile.create(
                controlDirectory,
                launch.environment,
                cancellationCheck,
            )
            environmentFile = createdEnvironment
            val unitName = "decomp-acp-${UUID.randomUUID()}.scope"
            val createdScopeController = SystemdScopeController(
                scopeSupervisor,
                scopeInspector,
                busEndpoint,
                bubblewrap,
                unitName,
                launch.resourceLimits,
                launch.maximumWallDuration,
            )
            scopeController = createdScopeController
            createdScopeController.requireUnitAbsent(cancellationCheck)
            val bubblewrapCommand = buildBubblewrapCommand(
                launch,
                launchMounts,
                createdEnvironment,
                cancellationCheck,
            )
            val duplicatedCommand = environmentFdOpenerCommand(
                createdEnvironment.materializedSource,
                bubblewrapCommand,
            )
            val command = resourceLimiterCommand(
                launch.resourceLimits,
                createdScopeController.wrap(duplicatedCommand),
                cancellationCheck,
            )
            observer?.beforeStart(Collections.unmodifiableList(command))

            val builder = ProcessBuilder(command)
                .redirectInput(ProcessBuilder.Redirect.PIPE)
                .redirectOutput(ProcessBuilder.Redirect.PIPE)
                .redirectError(ProcessBuilder.Redirect.PIPE)
            if (mergeError) builder.redirectErrorStream(true)
            builder.environment().clear()
            builder.environment().putAll(busEndpoint.controlEnvironment)
            launchHook?.at(AcpSandboxLaunchStage.BEFORE_SCOPE_START)
            cancellationCheck()
            val started = try {
                builder.start()
            } catch (failure: IOException) {
                throw IOException("failed to launch the verified systemd/bubblewrap boundary", failure)
            }
            process = started
            val openedRootProcessHandle = LinuxFilesystemSyscalls.openProcessHandle(started.pid())
            rootProcessHandle = openedRootProcessHandle
            launchHook?.at(AcpSandboxLaunchStage.AFTER_ROOT_PROCESS_HANDLE_OPEN)
            if (!started.isAlive) {
                openedRootProcessHandle.close()
                rootProcessHandle = null
                throw IOException("sandbox boundary exited before its process descriptor was bound")
            }
            val verifiedScope = createdScopeController.verifyAttached(started) {
                launchCheckpoint(AcpSandboxLaunchStage.DURING_SCOPE_VERIFICATION, cancellationCheck)
            }
            scopeObserver?.verified(verifiedScope.identity)
            val created = AcpSandboxedProcess(
                started,
                openedRootProcessHandle,
                verifiedScope,
                cleanupAfterScope = {
                    cleanupLaunchResources(launchMounts, createdEnvironment)
                },
                onCleanupProven = { cleaned -> active.remove(cleaned) },
                onCleanupFailed = { failure -> closeFailure.compareAndSet(null, failure) },
                cleanupHook = cleanupHook,
            )
            rootProcessHandle = null
            sandboxed = created
            active += created
            if (created.cleanupSucceeded()) active.remove(created)
            launchHook?.at(AcpSandboxLaunchStage.AFTER_SCOPE_ATTACHED_BEFORE_SETUP_ATTESTATION)
            cancellationCheck()

            val executableMount = launchMounts.singleOrNull {
                it.mount.destination.toString() == launch.command.firstOrNull()
            } ?: throw IOException("sandbox command executable is not an exact authenticated runtime mount")
            executableMount.requireNativeExecveatTarget(cancellationCheck)
            var setupWaiter = verifiedScope.requireSetupWaiter(
                launchGateHelper.setupAttestation(),
                executableMount.setupAttestation(),
                createdEnvironment.setupAttestation(),
                launch.command,
                launch.workingDirectory,
                cancellationCheck = {
                    launchCheckpoint(AcpSandboxLaunchStage.DURING_SETUP_ATTESTATION, cancellationCheck)
                },
            )
            val setupWaiterPid = setupWaiter.helperPid
            launchHook?.at(AcpSandboxLaunchStage.AFTER_SETUP_WAITER_BEFORE_BIND_ATTESTATION)
            cancellationCheck()
            requireBoundaryUnchanged(cancellationCheck)
            launchMounts.forEach { it.requireUnchanged(cancellationCheck) }
            launch.stagingRoots.forEach {
                cancellationCheck()
                it.stagingRoot.requireCurrentIdentity(cancellationCheck)
            }
            createdEnvironment.requireCurrentIdentity(cancellationCheck)
            requireSandboxVisibleBindings(
                setupWaiterPid,
                (launcherMounts + launchMounts).distinctBy { it.mount.destination },
                launch.stagingRoots,
                createdEnvironment,
                cancellationCheck = {
                    launchCheckpoint(AcpSandboxLaunchStage.DURING_BIND_ATTESTATION, cancellationCheck)
                },
            )
            var effectiveRlimits = requireExactRlimits(setupWaiterPid, launch.resourceLimits) {
                launchCheckpoint(AcpSandboxLaunchStage.DURING_RLIMIT_ATTESTATION, cancellationCheck)
            }
            launchHook?.at(AcpSandboxLaunchStage.AFTER_SETUP_BIND_ATTESTATION_BEFORE_RELEASE)
            cancellationCheck()
            requireBoundaryUnchanged(cancellationCheck)
            launchMounts.forEach { it.requireUnchanged(cancellationCheck) }
            launch.stagingRoots.forEach {
                cancellationCheck()
                it.stagingRoot.requireCurrentIdentity(cancellationCheck)
            }
            createdEnvironment.requireCurrentIdentity(cancellationCheck)
            requireSandboxVisibleBindings(
                setupWaiterPid,
                (launcherMounts + launchMounts).distinctBy { it.mount.destination },
                launch.stagingRoots,
                createdEnvironment,
                cancellationCheck = {
                    launchCheckpoint(AcpSandboxLaunchStage.DURING_BIND_ATTESTATION, cancellationCheck)
                },
            )
            effectiveRlimits = requireExactRlimits(setupWaiterPid, launch.resourceLimits) {
                launchCheckpoint(AcpSandboxLaunchStage.DURING_RLIMIT_ATTESTATION, cancellationCheck)
            }
            setupWaiter = verifiedScope.requireSetupWaiter(
                launchGateHelper.setupAttestation(),
                executableMount.setupAttestation(),
                createdEnvironment.setupAttestation(),
                launch.command,
                launch.workingDirectory,
                setupWaiter,
                cancellationCheck = {
                    launchCheckpoint(AcpSandboxLaunchStage.DURING_SETUP_ATTESTATION, cancellationCheck)
                },
            )
            createdEnvironment.unlinkAndProveAnonymous(cancellationCheck)
            launchGateHelper.sealMountedSingleFileSnapshot(cancellationCheck)
            executableMount.sealMountedSingleFileSnapshot(cancellationCheck)
            requireBoundaryUnchanged(cancellationCheck)
            launchMounts.forEach { it.requireUnchanged(cancellationCheck) }
            launch.stagingRoots.forEach {
                cancellationCheck()
                it.stagingRoot.requireCurrentIdentity(cancellationCheck)
            }
            createdEnvironment.requireCurrentIdentity(cancellationCheck)
            requireSandboxVisibleBindings(
                setupWaiterPid,
                (launcherMounts + launchMounts).distinctBy { it.mount.destination },
                launch.stagingRoots,
                createdEnvironment,
                cancellationCheck = {
                    launchCheckpoint(AcpSandboxLaunchStage.DURING_BIND_ATTESTATION, cancellationCheck)
                },
            )
            effectiveRlimits = requireExactRlimits(setupWaiterPid, launch.resourceLimits) {
                launchCheckpoint(AcpSandboxLaunchStage.DURING_RLIMIT_ATTESTATION, cancellationCheck)
            }
            verifiedScope.requireSetupWaiter(
                launchGateHelper.setupAttestation(),
                executableMount.setupAttestation(),
                createdEnvironment.setupAttestation(),
                launch.command,
                launch.workingDirectory,
                setupWaiter,
                cancellationCheck = {
                    launchCheckpoint(AcpSandboxLaunchStage.DURING_SETUP_ATTESTATION, cancellationCheck)
                },
            )
            val launchEvidence = AcpSandboxLaunchEvidence(
                purpose = launch.purpose,
                resourceLimits = launch.resourceLimits,
                controllers = verifiedScope.controllers,
                commandSha256 = canonicalStringDigest(launch.command, cancellationCheck),
                startGate = AcpSandboxStartGateEvidence(
                    descriptor = 0,
                    waiterExecutableSha256 = sandboxGateHelperSha256,
                    helperProtocolSha256 = sha256(STATIC_GATE_HELPER_PROTOCOL),
                    positiveByteRequired = true,
                ),
                environment = createdEnvironment.evidence(),
                effectiveRlimits = effectiveRlimits,
                executableMount = executableMount.evidence(),
                runtimeMounts = buildList {
                    val destinations = HashSet<Path>()
                    (launcherMounts.asSequence() + launchMounts.asSequence()).forEach { mount ->
                        cancellationCheck()
                        if (destinations.add(mount.mount.destination)) add(mount.evidence())
                    }
                },
            )
            val authorizationStream = started.outputStream
            // Reserve bounded metadata capacity before the broker's one-way authorization
            // decision. The broker callback is the final fallible policy/audit operation; no
            // cancellation or authorization check follows it.
            val reservation = reserveSuccessfulLaunchEvidence(launchEvidence)
            launchEvidenceReservation = reservation
            cancellationCheck()
            beforeAuthorizationCommit()
            // No fallible operation or cancellation/policy check follows the broker's
            // write-ahead authorization decision before the one-byte commit attempt.
            reservation.committed.set(true)
            launchEvidenceReservation = null
            commitSandboxAuthorization(authorizationStream)
            return created
        } catch (failure: Throwable) {
            launchEvidenceReservation?.let(::releaseSuccessfulLaunchEvidence)
            val cleanupFailures = mutableListOf<Throwable>()
            val created = sandboxed
            if (created != null) {
                try {
                    created.destroyForcibly()
                } catch (cleanupFailure: Throwable) {
                    cleanupFailures += cleanupFailure
                }
                try {
                    created.awaitCleanup(CLEANUP_TIMEOUT)
                } catch (cleanupFailure: Throwable) {
                    cleanupFailures += cleanupFailure
                }
            } else {
                val started = process
                val scopeCleaned = if (started != null) {
                    val cleaned = runCleanupStep(
                        cleanupFailures,
                        AcpSandboxCleanupStage.SCOPE,
                        cleanupHook,
                    ) {
                        requireNotNull(scopeController).requireKilledAndRemovedIfPresent(
                            started,
                            rootProcessHandle,
                        )
                    }
                    cleaned
                } else true
                val snapshotsCleaned = if (scopeCleaned) {
                    runCleanupStep(
                        cleanupFailures,
                        AcpSandboxCleanupStage.RUNTIME_SNAPSHOTS,
                        cleanupHook,
                    ) { cleanupLaunchResources(launchMounts, environmentFile) }
                } else {
                    cleanupFailures += IOException(
                        "launch runtime snapshots retained because scope cleanup was not proven",
                    )
                    false
                }
                if (!scopeCleaned || !snapshotsCleaned) {
                    unresolvedLaunches += RetainedLaunchCleanup(
                        started,
                        rootProcessHandle,
                        scopeController,
                        launchMounts,
                        environmentFile,
                    )
                    rootProcessHandle = null
                } else {
                    rootProcessHandle?.close()
                    rootProcessHandle = null
                }
            }
            if (cleanupFailures.isNotEmpty()) {
                val cleanup = AcpCleanupProofFailure(
                    "sandbox launch failed and cleanup could not be proven",
                    cleanupFailures.first(),
                )
                cleanupFailures.drop(1).forEach(cleanup::addSuppressed)
                cleanup.addSuppressed(failure)
                closeFailure.compareAndSet(null, cleanup)
                throw cleanup
            }
            if (failure is AcpCleanupProofFailure) {
                closeFailure.compareAndSet(null, failure)
            }
            throw failure
        }
    }

    fun evidence(
        policy: AcpTerminalExecutionPolicy?,
        terminalAudit: Collection<AcpTerminalAuditRecord> = emptyList(),
        outerProcessOutput: AcpProducedOutputEvidence? = null,
        cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
    ): AcpSandboxEvidence = AcpSandboxEvidence(
        provider = evidenceBase.provider,
        providerVersion = evidenceBase.providerVersion,
        providerExecutableSha256 = evidenceBase.providerExecutableSha256,
        providerExecutableMode = evidenceBase.providerExecutableMode,
        resourceLimiterSha256 = evidenceBase.resourceLimiterSha256,
        scopeSupervisorSha256 = evidenceBase.scopeSupervisorSha256,
        scopeInspectorSha256 = evidenceBase.scopeInspectorSha256,
        environmentFdOpenerSha256 = evidenceBase.environmentFdOpenerSha256,
        securityExecutables = evidenceBase.securityExecutables,
        outerAgentLimits = configuration.agentResourceLimits,
        runtimeClosureLimits = configuration.runtimeClosureLimits,
        cgroupV2PidsLimited = true,
        cgroupV2MemoryLimited = true,
        cgroupV2CpuLimited = true,
        networkIsolated = true,
        outerAgentContained = true,
        nestedUserNamespacesDisabled = true,
        newSession = true,
        dieWithParent = true,
        policySha256 = policy?.policyDigest(cancellationCheck),
        terminalLimits = policy?.limits,
        launches = synchronized(successfulLaunches) {
            cancellationCheck()
            successfulLaunches.asSequence()
                .filter { reservation ->
                    cancellationCheck()
                    reservation.committed.get()
                }
                .map { reservation ->
                    cancellationCheck()
                    reservation.evidence
                }
                .toList()
        },
        authorities = policy?.stagingRoots.orEmpty().map { grant ->
            cancellationCheck()
            AcpSandboxAuthorityEvidence(
                rootId = grant.stagingRoot.rootId,
                rootPathSha256 = sha256(grant.stagingRoot.path.toString()),
                mode = grant.mode,
                quota = grant.stagingRoot.quotaProof?.evidence,
            )
        },
        terminalAudit = terminalAudit,
        outerProcessOutput = outerProcessOutput,
        cancellationCheck = cancellationCheck,
    )

    private fun reserveSuccessfulLaunchEvidence(
        evidence: AcpSandboxLaunchEvidence,
    ): LaunchEvidenceReservation =
        synchronized(successfulLaunches) {
            if (successfulLaunches.size >= MAXIMUM_SANDBOX_EVIDENCE_LAUNCHES) {
                throw IOException("sandbox launch evidence exceeds the authenticated count limit")
            }
            if (launchEvidenceRuntimeMounts + evidence.runtimeMounts.size >
                MAXIMUM_SANDBOX_EVIDENCE_RUNTIME_MOUNTS
            ) {
                throw IOException("sandbox launch evidence exceeds the aggregate runtime-mount count limit")
            }
            launchEvidenceRuntimeMounts += evidence.runtimeMounts.size
            LaunchEvidenceReservation(evidence).also(successfulLaunches::add)
        }

    private fun releaseSuccessfulLaunchEvidence(reservation: LaunchEvidenceReservation) =
        synchronized(successfulLaunches) {
            if (!reservation.committed.get() && successfulLaunches.remove(reservation)) {
                launchEvidenceRuntimeMounts -= reservation.evidence.runtimeMounts.size
            }
        }

    override fun close() {
        closed.compareAndSet(false, true)
        val failures = mutableListOf<Throwable>()
        closeFailure.get()?.let(failures::add)
        val snapshot = active.toList()
        snapshot.forEach { process ->
            runCatching { process.destroyForcibly() }.exceptionOrNull()?.let(failures::add)
        }
        snapshot.forEach { process ->
            try {
                process.awaitCleanup(CLEANUP_TIMEOUT)
                active.remove(process)
            } catch (failure: Throwable) {
                failures += failure
                try {
                    process.retryCleanupProof()
                    active.remove(process)
                } catch (retryFailure: Throwable) {
                    failures += retryFailure
                }
            }
        }
        if (active.isNotEmpty()) {
            failures += IOException("sandbox boundary still has ${active.size} uncleaned scope(s)")
        }
        unresolvedLaunches.toList().forEach { retained ->
            try {
                if (retained.retry()) unresolvedLaunches.remove(retained)
            } catch (failure: Throwable) {
                failures += failure
            }
        }
        if (unresolvedLaunches.isNotEmpty()) {
            failures += IOException(
                "sandbox boundary retains ${unresolvedLaunches.size} failed-launch cleanup proof(s)",
            )
        }
        if (active.isEmpty() && unresolvedLaunches.isEmpty()) {
            runCleanupStep(failures, AcpSandboxCleanupStage.RUNTIME_SNAPSHOTS, cleanupHook) {
                deletePinnedMounts(launcherMounts)
            }
            runCleanupStep(failures, AcpSandboxCleanupStage.CONTROL_DIRECTORY, cleanupHook) {
                controlDirectory.deleteAndProve()
            }
        } else {
            failures += IOException(
                "launcher closure and control directory retained behind unresolved sandbox cleanup",
            )
        }
        if (failures.isNotEmpty()) {
            val primary = AcpCleanupProofFailure(
                "ACP sandbox boundary cleanup was not proven",
                failures.first(),
            )
            failures.drop(1).forEach(primary::addSuppressed)
            closeFailure.set(primary)
            throw primary
        }
    }

    private fun requireBoundaryUnchanged(cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT) {
        cancellationCheck()
        bubblewrap.requireUnchanged(cancellationCheck)
        resourceLimiter.requireUnchanged(cancellationCheck)
        scopeSupervisor.requireUnchanged(cancellationCheck)
        scopeInspector.requireUnchanged(cancellationCheck)
        environmentFdOpener.requireUnchanged(cancellationCheck)
        busEndpoint.requireUnchanged(cancellationCheck)
        launcherMounts.forEach { it.requireUnchanged(cancellationCheck) }
        cancellationCheck()
    }

    private fun launchCheckpoint(stage: AcpSandboxLaunchStage, cancellationCheck: () -> Unit) {
        launchHook?.at(stage)
        cancellationCheck()
    }

    /**
     * The script is a fixed boundary primitive: no request-derived bytes are parsed as shell
     * syntax. It opens only the already-pinned private environment bootstrap as fd 4 and then
     * execs bubblewrap. The static helper inside the completed sandbox owns the one-byte gate.
     */
    private fun environmentFdOpenerCommand(
        environmentSource: Path,
        scopedCommand: List<String>,
    ): List<String> =
        buildList {
            add(environmentFdOpener.path.toString())
            add("--noprofile")
            add("--norc")
            add("-c")
            add(ENVIRONMENT_FD_OPENER_SCRIPT)
            add(ENVIRONMENT_FD_OPENER_ARG0)
            add(environmentSource.toString())
            addAll(scopedCommand)
        }

    private fun resourceLimiterCommand(
        limits: AcpSandboxResourceLimits,
        scopedCommand: List<String>,
        cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
    ): List<String> = buildList {
        cancellationCheck()
        add(resourceLimiter.path.toString())
        // RLIMIT_NPROC is host-real-UID scoped, so it is only a loose defense-in-depth backstop.
        // The verified cgroup pids.max is the exact sandbox process-tree authority.
        val nprocBackstop = nprocBackstop(limits.maximumProcesses, cancellationCheck)
        add("--nproc=$nprocBackstop:$nprocBackstop")
        add("--nofile=${limits.maximumOpenFiles}:${limits.maximumOpenFiles}")
        add("--fsize=${limits.maximumFileBytes}:${limits.maximumFileBytes}")
        add("--core=0:0")
        add("--as=${limits.maximumAddressSpaceBytes}:${limits.maximumAddressSpaceBytes}")
        add("--cpu=${limits.maximumCpuSeconds}:${limits.maximumCpuSeconds}")
        add("--")
        addAll(scopedCommand)
    }

    private fun buildBubblewrapCommand(
        launch: AcpSandboxLaunch,
        launchMounts: List<PinnedReadOnlyMount>,
        environmentFile: SandboxEnvironmentFile,
        cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
    ): List<String> = buildList {
        cancellationCheck()
        add(bubblewrap.path.toString())
        addAll(acpBubblewrapIsolationArguments())

        if (launcherMounts.size + launchMounts.size > MAXIMUM_SANDBOX_MOUNTS + 1) {
            throw IOException("combined sandbox runtime mounts exceed the authenticated count limit")
        }
        val mountsByDestination = LinkedHashMap<Path, PinnedReadOnlyMount>()
        (launcherMounts.asSequence() + launchMounts.asSequence()).forEach { pinned ->
            cancellationCheck()
            val existing = mountsByDestination.putIfAbsent(pinned.mount.destination, pinned)
            if (existing != null && (
                    existing.mount.source != pinned.mount.source ||
                        existing.mount.expectedManifestSha256 != pinned.mount.expectedManifestSha256
                    )
            ) throw IOException("sandbox runtime mounts conflict with the launcher closure")
        }
        val allMounts = mountsByDestination.values.toList()
        val authorityPaths = SandboxPathIndex()
        allMounts.forEach { pinned ->
            cancellationCheck()
            if (!authorityPaths.addIfNonOverlapping(pinned.mount.destination, cancellationCheck)) {
                throw IOException("sandbox runtime mounts overlap the launcher closure")
            }
        }
        launch.stagingRoots.forEach { grant ->
            cancellationCheck()
            if (!authorityPaths.addIfNonOverlapping(grant.sandboxPath, cancellationCheck)) {
                throw IOException("sandbox staging authority overlaps a runtime mount or another staging root")
            }
        }
        cancellationCheck()
        requireProtectedLauncherClosure(launch, launchMounts, cancellationCheck)
        cancellationCheck()
        val emptyDirectories = LinkedHashSet<Path>().also { unique ->
            launch.emptyDirectories.forEach { directory ->
                cancellationCheck()
                unique.add(directory)
            }
        }.toList()
        emptyDirectories.forEach { directory ->
            cancellationCheck()
            if (!directory.isAbsolute || directory != directory.normalize() || directory == Path.of("/") ||
                directory == Path.of("/proc") || directory.startsWith(Path.of("/proc")) ||
                directory == Path.of("/dev") || directory.startsWith(Path.of("/dev"))
            ) throw IOException("sandbox empty-directory anchor is invalid")
            if (authorityPaths.overlaps(directory, cancellationCheck)) {
                throw IOException("sandbox empty-directory anchor overlaps another authority")
            }
        }
        destinationParents(
            allMounts.map { it.mount.destination } +
                launch.stagingRoots.map { it.sandboxPath } +
                emptyDirectories,
            cancellationCheck,
        ).forEach { directory ->
            cancellationCheck()
            add("--dir")
            add(directory.toString())
        }
        emptyDirectories.sortedWith { left, right ->
            cancellationCheck()
            left.nameCount.compareTo(right.nameCount).takeIf { it != 0 }
                ?: compareCheckpointed(left.toString(), right.toString(), cancellationCheck)
        }.forEach { directory ->
            cancellationCheck()
            add("--dir")
            add(directory.toString())
        }
        allMounts.forEach { pinned ->
            cancellationCheck()
            add("--ro-bind")
            add(pinned.effectiveSource.toString())
            add(pinned.mount.destination.toString())
        }
        launch.stagingRoots.forEach { grant ->
            cancellationCheck()
            grant.stagingRoot.requireCurrentIdentity(cancellationCheck)
            add(if (grant.mode == AcpSandboxRootMode.READ_ONLY) "--ro-bind" else "--bind")
            add(grant.stagingRoot.path.toString())
            add(grant.sandboxPath.toString())
        }
        environmentFile.requireCurrentIdentity(cancellationCheck)
        add("--ro-bind-fd")
        add(SANDBOX_GATE_ENVIRONMENT_FD.toString())
        add(environmentFile.sandboxPath.toString())
        add("--chdir")
        add(launch.workingDirectory.toString())
        add("--")
        add(ACP_SANDBOX_GATE_HELPER_PATH.toString())
        add(environmentFile.sandboxPath.toString())
        addAll(launch.command)
    }

    private fun requireProtectedLauncherClosure(
        launch: AcpSandboxLaunch,
        launchMounts: List<PinnedReadOnlyMount>,
        cancellationCheck: () -> Unit,
    ) {
        val trustedOuterDestinations = if (launch.purpose == AcpSandboxLaunchPurpose.OUTER_AGENT) {
            configuration.agentRuntimeMounts.mapTo(mutableSetOf()) {
                cancellationCheck()
                it.destination
            }
        } else emptySet()
        val unauthorizedMount = launchMounts.firstOrNull { pinned ->
            cancellationCheck()
            pinned.mount.destination != ACP_SANDBOX_GATE_HELPER_PATH &&
                pinned.mount.destination !in trustedOuterDestinations &&
                PROTECTED_LOADER_DESTINATIONS.any { protected ->
                    cancellationCheck()
                    pathsOverlap(pinned.mount.destination, protected)
                }
        }
        if (unauthorizedMount != null) {
            throw IOException(
                "request runtime mount overlaps a protected loader/helper destination: " +
                    unauthorizedMount.mount.destination,
            )
        }
        val unauthorizedRoot = launch.stagingRoots.firstOrNull { grant ->
            cancellationCheck()
            PROTECTED_LOADER_DESTINATIONS.any {
                cancellationCheck()
                pathsOverlap(grant.sandboxPath, it)
            }
        }
        if (unauthorizedRoot != null) {
            throw IOException("staging authority overlaps a protected loader/helper destination")
        }
        val unauthorizedAnchor = launch.emptyDirectories.firstOrNull { directory ->
            cancellationCheck()
            PROTECTED_LOADER_DESTINATIONS.any {
                cancellationCheck()
                pathsOverlap(directory, it)
            }
        }
        if (unauthorizedAnchor != null) {
            throw IOException("empty workspace anchor overlaps a protected loader/helper destination")
        }
    }

    companion object {
        fun prepare(
            configuration: AcpLinuxSandboxConfiguration,
            observer: AcpSandboxCommandObserver? = null,
            launchHook: AcpSandboxLaunchHook? = null,
            cleanupHook: AcpSandboxCleanupHook? = null,
            scopeObserver: AcpSandboxScopeObserver? = null,
            cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
        ): LinuxBubblewrapBoundary {
            cancellationCheck()
            requireLinuxCgroupV2()
            LinuxFilesystemSyscalls.requirePidfdSupported()
            cancellationCheck()
            val bubblewrap = PinnedSecurityExecutable.pin(
                configuration.bubblewrapExecutable,
                "bubblewrap",
                configuration.expectedBubblewrapSha256,
                cancellationCheck,
            )
            val resourceLimiter = PinnedSecurityExecutable.pin(
                configuration.resourceLimiterExecutable,
                "resource limiter",
                configuration.expectedResourceLimiterSha256,
                cancellationCheck,
            )
            val scopeSupervisor = PinnedSecurityExecutable.pin(
                configuration.scopeSupervisorExecutable,
                "scope supervisor",
                configuration.expectedScopeSupervisorSha256,
                cancellationCheck,
            )
            val scopeInspector = PinnedSecurityExecutable.pin(
                configuration.scopeInspectorExecutable,
                "scope inspector",
                configuration.expectedScopeInspectorSha256,
                cancellationCheck,
            )
            val environmentFdOpener = PinnedSecurityExecutable.pin(
                configuration.environmentFdOpenerExecutable,
                "environment fd opener",
                configuration.expectedEnvironmentFdOpenerSha256,
                cancellationCheck,
            )
            val bus = PinnedSystemdBusEndpoint.pin(
                configuration.systemdUserRuntimeDirectory,
                cancellationCheck,
            )
            val version = probeBubblewrap(bubblewrap.path, cancellationCheck)
            probeResourceLimiter(resourceLimiter.path, cancellationCheck)
            probeSystemd(scopeSupervisor, scopeInspector, bus, cancellationCheck)
            probeEnvironmentFdOpener(environmentFdOpener.path, cancellationCheck)
            val forbidden = forbiddenRuntimeFiles(
                cancellationCheck,
                bubblewrap,
                resourceLimiter,
                scopeSupervisor,
                scopeInspector,
                environmentFdOpener,
            )
            val helperMount = AcpSandboxReadOnlyMount.trustedInternal(
                configuration.sandboxGateHelperExecutable,
                ACP_SANDBOX_GATE_HELPER_PATH,
                configuration.expectedSandboxGateHelperManifestSha256,
            )
            val controlDirectory = createControlDirectory(configuration.runtimeClosureLimits)
            val pinnedLauncher = mutableListOf<PinnedReadOnlyMount>()
            var helperValidation: PinnedReadOnlyMount? = null
            var helperMode = 0
            var helperMetadataSha256 = ""
            try {
                helperValidation = pinMounts(
                    listOf(helperMount),
                    configuration.runtimeClosureLimits,
                    forbidden,
                    controlDirectory,
                    allowUserOwnedSnapshot = true,
                    cancellationCheck = cancellationCheck,
                ).single()
                requireNotNull(helperValidation).requireStaticGateHelper(
                    configuration.expectedSandboxGateHelperSha256,
                    cancellationCheck,
                )
                helperMode = requireNotNull(helperValidation).expectedIdentity.mode
                helperMetadataSha256 = requireNotNull(helperValidation).expectedIdentity.metadataSha256
                requireNotNull(helperValidation).deleteSnapshot()
                helperValidation = null
                pinnedLauncher += pinMounts(
                    configuration.launcherRuntimeMounts,
                    configuration.runtimeClosureLimits,
                    forbidden,
                    controlDirectory,
                    allowUserOwnedSnapshot = false,
                    cancellationCheck = cancellationCheck,
                )
                cancellationCheck()
            } catch (failure: Throwable) {
                val resourceCleanupFailures = mutableListOf<Throwable>()
                helperValidation?.let { validation ->
                    runCatching { validation.deleteSnapshot() }.exceptionOrNull()
                        ?.let(resourceCleanupFailures::add)
                }
                runCatching { deletePinnedMounts(pinnedLauncher) }.exceptionOrNull()
                    ?.let(resourceCleanupFailures::add)
                val controlCleanup = if (resourceCleanupFailures.isEmpty()) {
                    runCatching { controlDirectory.deleteAndProve() }.exceptionOrNull()
                } else {
                    IOException("sandbox control directory retained behind unresolved runtime cleanup")
                }
                if (failure is AcpCleanupProofFailure || resourceCleanupFailures.isNotEmpty() || controlCleanup != null) {
                    val cleanup = if (failure is AcpCleanupProofFailure) {
                        failure
                    } else {
                        AcpCleanupProofFailure(
                            "sandbox preparation failed and private cleanup was not proven",
                            requireNotNull(resourceCleanupFailures.firstOrNull() ?: controlCleanup),
                        ).also { it.addSuppressed(failure) }
                    }
                    resourceCleanupFailures
                        .filterNot { it === cleanup.cause }
                        .forEach(cleanup::addSuppressed)
                    controlCleanup?.takeUnless { it === cleanup.cause }?.let(cleanup::addSuppressed)
                    throw cleanup
                }
                throw failure
            }
            return LinuxBubblewrapBoundary(
                configuration,
                bubblewrap,
                resourceLimiter,
                scopeSupervisor,
                scopeInspector,
                environmentFdOpener,
                helperMount,
                configuration.expectedSandboxGateHelperSha256,
                bus,
                pinnedLauncher.toList(),
                forbidden,
                controlDirectory,
                AcpSandboxEvidence(
                    provider = "bubblewrap+systemd-cgroup-v2",
                    providerVersion = version,
                    providerExecutableSha256 = bubblewrap.sha256,
                    providerExecutableMode = bubblewrap.mode,
                    resourceLimiterSha256 = resourceLimiter.sha256,
                    scopeSupervisorSha256 = scopeSupervisor.sha256,
                    scopeInspectorSha256 = scopeInspector.sha256,
                    environmentFdOpenerSha256 = environmentFdOpener.sha256,
                    securityExecutables = listOf(
                        bubblewrap.evidence("bubblewrap"),
                        resourceLimiter.evidence("resource-limiter"),
                        scopeSupervisor.evidence("scope-supervisor"),
                        scopeInspector.evidence("scope-inspector"),
                        environmentFdOpener.evidence("environment-fd-opener"),
                        AcpSecurityExecutableEvidence(
                            role = "sandbox-gate-helper",
                            canonicalPathSha256 = sha256(configuration.sandboxGateHelperExecutable.toString()),
                            contentSha256 = configuration.expectedSandboxGateHelperSha256,
                            mode = helperMode,
                            metadataSha256 = helperMetadataSha256,
                        ),
                    ),
                    outerAgentLimits = configuration.agentResourceLimits,
                    runtimeClosureLimits = configuration.runtimeClosureLimits,
                    cgroupV2PidsLimited = true,
                    cgroupV2MemoryLimited = true,
                    cgroupV2CpuLimited = true,
                    networkIsolated = true,
                    outerAgentContained = true,
                    nestedUserNamespacesDisabled = true,
                    newSession = true,
                    dieWithParent = true,
                    policySha256 = null,
                    terminalLimits = null,
                    launches = emptyList(),
                    authorities = emptyList(),
                    terminalAudit = emptyList(),
                    cancellationCheck = cancellationCheck,
                ),
                observer,
                launchHook,
                cleanupHook,
                scopeObserver,
            )
        }

        private fun requireLinuxCgroupV2() {
            if (System.getProperty("os.name", "") != "Linux") {
                throw IOException("the ACP process sandbox requires Linux")
            }
            val controllers = CGROUP_ROOT.resolve("cgroup.controllers")
            if (!Files.isRegularFile(controllers)) throw IOException("cgroup v2 is unavailable")
            val available = Files.readString(controllers).trim().split(Regex("\\s+")).toSet()
            if (!available.containsAll(setOf("pids", "memory", "cpu"))) {
                throw IOException("cgroup v2 pids, memory, and cpu controllers are required")
            }
        }

        private fun createControlDirectory(limits: AcpRuntimeClosureLimits): PinnedControlDirectory =
            PinnedControlDirectory.create(limits)
    }
}

/** Strong references retained until a failed pre-verification launch can be cleaned in order. */
private class RetainedLaunchCleanup(
    private val process: Process?,
    private val rootProcessHandle: LinuxProcessDescriptor?,
    private val scopeController: SystemdScopeController?,
    private val launchMounts: List<PinnedReadOnlyMount>,
    private val environmentFile: SandboxEnvironmentFile?,
) {
    fun retry(): Boolean {
        val retainedProcess = process
        if (retainedProcess != null) {
            val controller = scopeController
                ?: throw AcpCleanupProofFailure("failed launch lost its scope cleanup authority")
            try {
                controller.requireKilledAndRemovedIfPresent(retainedProcess, rootProcessHandle)
            } catch (failure: Throwable) {
                throw AcpCleanupProofFailure(
                    "failed launch scope cleanup remains unproven",
                    failure,
                )
            }
        }
        try {
            cleanupLaunchResources(launchMounts, environmentFile)
        } catch (failure: Throwable) {
            throw AcpCleanupProofFailure(
                "failed launch runtime-snapshot cleanup remains unproven",
                failure,
            )
        }
        rootProcessHandle?.close()
        return true
    }
}

private fun cleanupLaunchResources(
    launchMounts: List<PinnedReadOnlyMount>,
    environmentFile: SandboxEnvironmentFile?,
) {
    val failures = mutableListOf<Throwable>()
    try {
        deletePinnedMounts(launchMounts)
    } catch (failure: Throwable) {
        failures += failure
    }
    try {
        environmentFile?.closeAndProve()
    } catch (failure: Throwable) {
        failures += failure
    }
    if (failures.isNotEmpty()) {
        val primary = AcpCleanupProofFailure(
            "sandbox launch resource cleanup was not proven",
            failures.first(),
        )
        failures.drop(1).forEach(primary::addSuppressed)
        throw primary
    }
}

/** A factory-created mode-0700 control directory pinned by parent/name and open descriptors. */
private class PinnedControlDirectory private constructor(
    val path: Path,
    private val parentPath: Path,
    private val parent: LinuxDescriptor,
    private val descriptor: LinuxDescriptor,
    private val originalName: String,
    private var currentName: String,
    private val cleanupLimits: AcpRuntimeClosureLimits,
) {
    private val expectedKey = descriptor.identity.key
    private val expectedMountId = descriptor.identity.mountId
    private var deleted = false
    private var cleanupFailure: AcpCleanupProofFailure? = null

    fun requireCurrent() {
        if (deleted) throw IOException("sandbox control directory is already deleted")
        requireDirectoryDescriptorIdentity(descriptor, expectedKey, expectedMountId, CONTROL_DIRECTORY_MODE)
        requireDirectoryDescriptorIdentity(parent, parent.identity.key, parent.identity.mountId, null)
        LinuxFilesystemSyscalls.openRoot(parentPath).use { currentParent ->
            if (currentParent.identity.key != parent.identity.key ||
                currentParent.identity.mountId != parent.identity.mountId
            ) throw IOException("sandbox control-directory parent pathname changed")
        }
        LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, currentName).use { named ->
            if (named.identity.key != expectedKey || named.identity.mountId != expectedMountId) {
                throw IOException("sandbox control-directory pathname changed")
            }
        }
        if (currentName != originalName) requireNameAbsent(parent.fd, originalName)
    }

    fun createChild(prefix: String): PinnedPrivateTree {
        requireCurrent()
        require(prefix.length >= 3 && '/' !in prefix && '\u0000' !in prefix) {
            "private runtime snapshot prefix is invalid"
        }
        val name = "$prefix${UUID.randomUUID()}"
        val created = path.resolve(name)
        var child: LinuxDescriptor? = null
        var directoryCreated = false
        try {
            LinuxFilesystemSyscalls.createDirectory(descriptor.fd, name, CONTROL_DIRECTORY_MODE)
            directoryCreated = true
            child = LinuxFilesystemSyscalls.openDirectoryAt(descriptor.fd, name)
            LinuxFilesystemSyscalls.chmod(child, CONTROL_DIRECTORY_MODE)
            val childIdentity = LinuxFilesystemSyscalls.identity(child.fd)
            if (childIdentity.uid != currentUid() ||
                childIdentity.mountId != expectedMountId ||
                childIdentity.mode.permissions != CONTROL_DIRECTORY_MODE
            ) throw IOException("private runtime snapshot directory is not an exact mode-0700 child")
            LinuxFilesystemSyscalls.openRoot(created).use { byPath ->
                if (byPath.identity.key != child.identity.key ||
                    byPath.identity.mountId != child.identity.mountId
                ) throw IOException("private runtime snapshot pathname changed during creation")
            }
            return PinnedPrivateTree(this, created, name, child, cleanupLimits).also { child = null }
        } catch (failure: Throwable) {
            val cleanup = runCatching {
                val opened = child
                if (opened != null) {
                    deletePrivateTreeContents(opened, cleanupLimits)
                    removeExactEmptyDirectory(descriptor, name, opened, opened.identity.key)
                } else if (directoryCreated) {
                    throw IOException(
                        "private runtime snapshot child was created but its identity could not be pinned; " +
                            "the unresolved entry is retained",
                    )
                }
            }.exceptionOrNull()
            child?.close()
            if (cleanup != null) {
                throw AcpCleanupProofFailure(
                    "private runtime snapshot initialization cleanup was not proven",
                    cleanup,
                ).also { it.addSuppressed(failure) }
            }
            throw failure
        }
    }

    @Synchronized
    fun deleteAndProve() {
        if (deleted) {
            cleanupFailure?.let { throw it }
            return
        }
        val priorFailure = cleanupFailure
        try {
            requireCurrent()
            // A failed launch can leave attacker-created residue beside the pinned resources. Drain
            // only this already-authenticated directory through its retained descriptor and the same
            // aggregate entry/byte/depth limits used for private runtime cleanup. A pathname
            // replacement fails requireCurrent() above and is never traversed or removed.
            deletePrivateTreeContents(descriptor, cleanupLimits)
            val quarantine = ".decomp-acp-control-delete-${UUID.randomUUID()}"
            LinuxFilesystemSyscalls.renameNoReplace(parent.fd, currentName, quarantine)
            currentName = quarantine
            requireDirectoryDescriptorIdentity(descriptor, expectedKey, expectedMountId, CONTROL_DIRECTORY_MODE)
            LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, quarantine).use { selected ->
                if (selected.identity.key != expectedKey || selected.identity.mountId != expectedMountId) {
                    throw IOException("sandbox control-directory cleanup selected a replacement")
                }
            }
            requireNameAbsent(parent.fd, originalName)
            LinuxFilesystemSyscalls.removeDirectory(parent.fd, quarantine)
            if (LinuxFilesystemSyscalls.identity(descriptor.fd).linkCount != 0) {
                throw IOException("sandbox control-directory descriptor remains linked after cleanup")
            }
            requireNameAbsent(parent.fd, quarantine)
            requireNameAbsent(parent.fd, originalName)
            descriptor.close()
            parent.close()
            deleted = true
        } catch (failure: Throwable) {
            val proof = if (failure is AcpCleanupProofFailure) failure else {
                AcpCleanupProofFailure("sandbox control-directory cleanup was not proven", failure)
            }
            cleanupFailure = proof
            throw proof
        }
        // A retry may finish deleting the restored original directory, but successful remediation
        // cannot turn an earlier unproved cleanup into an ordinary success for this boundary.
        priorFailure?.let { throw it }
    }

    fun requireChildParent(): LinuxDescriptor {
        requireCurrent()
        return descriptor
    }

    companion object {
        fun create(cleanupLimits: AcpRuntimeClosureLimits): PinnedControlDirectory {
            val parentPath = Path.of("/tmp")
            val parent = LinuxFilesystemSyscalls.openRoot(parentPath)
            var descriptor: LinuxDescriptor? = null
            var createdName: String? = null
            try {
                val name = ".decomp-acp-control-${UUID.randomUUID()}"
                LinuxFilesystemSyscalls.createDirectory(parent.fd, name, CONTROL_DIRECTORY_MODE)
                createdName = name
                val directory = parentPath.resolve(name)
                val opened = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name)
                descriptor = opened
                LinuxFilesystemSyscalls.chmod(opened, CONTROL_DIRECTORY_MODE)
                val openedIdentity = LinuxFilesystemSyscalls.identity(opened.fd)
                if (openedIdentity.uid != currentUid() ||
                    openedIdentity.mode.permissions != CONTROL_DIRECTORY_MODE ||
                    openedIdentity.mountId != parent.identity.mountId
                ) throw IOException("sandbox control directory is not a private mode-0700 child of /tmp")
                LinuxFilesystemSyscalls.openRoot(directory).use { byPath ->
                    if (byPath.identity.key != opened.identity.key ||
                        byPath.identity.mountId != opened.identity.mountId
                    ) throw IOException("sandbox control-directory pathname changed during creation")
                }
                return PinnedControlDirectory(
                    directory,
                    parentPath,
                    parent,
                    opened,
                    name,
                    name,
                    cleanupLimits,
                ).also { descriptor = null; createdName = null }
            } catch (failure: Throwable) {
                val cleanup = runCatching {
                    val opened = descriptor
                    val name = createdName
                    if (opened != null && name != null) {
                        removeExactEmptyDirectory(parent, name, opened, opened.identity.key)
                    } else if (name != null) {
                        throw IOException(
                            "sandbox control directory was created but its identity could not be pinned; " +
                                "the unresolved entry is retained",
                        )
                    }
                }.exceptionOrNull()
                descriptor?.close()
                parent.close()
                if (cleanup != null) {
                    throw AcpCleanupProofFailure(
                        "sandbox control-directory initialization cleanup was not proven",
                        cleanup,
                    ).also { it.addSuppressed(failure) }
                }
                throw failure
            }
        }
    }
}

private class PinnedPrivateTree(
    private val parent: PinnedControlDirectory,
    val path: Path,
    private val originalName: String,
    private val descriptor: LinuxDescriptor,
    private val cleanupLimits: AcpRuntimeClosureLimits,
) {
    private val expectedKey = descriptor.identity.key
    private val expectedMountId = descriptor.identity.mountId
    private var currentName = originalName
    private var deleted = false
    private var cleanupFailure: AcpCleanupProofFailure? = null

    private fun requireCurrentTree(): LinuxDescriptor {
        if (deleted) throw IOException("private runtime snapshot is already deleted")
        val parentDescriptor = parent.requireChildParent()
        requireDirectoryDescriptorIdentity(descriptor, expectedKey, expectedMountId, null)
        LinuxFilesystemSyscalls.openDirectoryAt(parentDescriptor.fd, currentName).use { byName ->
            if (byName.identity.key != expectedKey || byName.identity.mountId != expectedMountId) {
                throw IOException("private runtime snapshot pathname changed")
            }
        }
        if (currentName != originalName) requireNameAbsent(parentDescriptor.fd, originalName)
        return parentDescriptor
    }

    fun requireRootDirectory(): LinuxDescriptor {
        cleanupFailure?.let { throw it }
        requireCurrentTree()
        return descriptor
    }

    /**
     * Removes the exact single-file snapshot root while both its descriptor and the already-created
     * sandbox bind retain the inode. No pathname is trusted after the descriptor comparison.
     */
    @Synchronized
    fun unlinkExactRoot(expected: LinuxDescriptor) {
        cleanupFailure?.let { throw it }
        requireCurrentTree()
        val rootName = "root"
        val quarantine = ".decomp-acp-mounted-unlink-${UUID.randomUUID()}"
        var quarantined = false
        var unlinked = false
        try {
            LinuxFilesystemSyscalls.openPathAtOrNull(descriptor.fd, rootName).use { selected ->
                if (selected == null || selected.identity.key != expected.identity.key ||
                    selected.identity.mountId != expected.identity.mountId ||
                    !selected.identity.isRegularFile || selected.identity.isSymbolicLink
                ) throw IOException("private mounted snapshot root changed before unlink")
            }
            LinuxFilesystemSyscalls.renameNoReplace(descriptor.fd, rootName, quarantine)
            quarantined = true
            LinuxFilesystemSyscalls.openPathAtOrNull(descriptor.fd, quarantine).use { selected ->
                if (selected == null || selected.identity.key != expected.identity.key ||
                    selected.identity.mountId != expected.identity.mountId
                ) throw IOException("private mounted snapshot quarantine selected a replacement")
            }
            requireNameAbsent(descriptor.fd, rootName)
            LinuxFilesystemSyscalls.unlink(descriptor.fd, quarantine)
            unlinked = true
            if (LinuxFilesystemSyscalls.identity(expected.fd).linkCount != 0) {
                throw IOException("private mounted snapshot inode remains linked")
            }
            requireNameAbsent(descriptor.fd, rootName)
            requireNameAbsent(descriptor.fd, quarantine)
        } catch (failure: Throwable) {
            if (quarantined && !unlinked) {
                try {
                    LinuxFilesystemSyscalls.renameNoReplace(descriptor.fd, quarantine, rootName)
                } catch (restoreFailure: Throwable) {
                    failure.addSuppressed(restoreFailure)
                }
            }
            throw failure
        }
    }

    @Synchronized
    fun deleteAndProve() {
        cleanupFailure?.let { throw it }
        if (deleted) return
        try {
            val parentDescriptor = requireCurrentTree()
            deletePrivateTreeContents(descriptor, cleanupLimits)
            val quarantine = ".decomp-acp-runtime-delete-${UUID.randomUUID()}"
            LinuxFilesystemSyscalls.renameNoReplace(parentDescriptor.fd, currentName, quarantine)
            currentName = quarantine
            LinuxFilesystemSyscalls.openDirectoryAt(parentDescriptor.fd, quarantine).use { selected ->
                if (selected.identity.key != expectedKey || selected.identity.mountId != expectedMountId) {
                    throw IOException("private runtime snapshot cleanup selected a replacement")
                }
            }
            requireNameAbsent(parentDescriptor.fd, originalName)
            LinuxFilesystemSyscalls.removeDirectory(parentDescriptor.fd, quarantine)
            if (LinuxFilesystemSyscalls.identity(descriptor.fd).linkCount != 0) {
                throw IOException("private runtime snapshot descriptor remains linked after cleanup")
            }
            requireNameAbsent(parentDescriptor.fd, quarantine)
            requireNameAbsent(parentDescriptor.fd, originalName)
            descriptor.close()
            deleted = true
        } catch (failure: Throwable) {
            val proof = if (failure is AcpCleanupProofFailure) failure else {
                AcpCleanupProofFailure("private runtime snapshot cleanup was not proven", failure)
            }
            cleanupFailure = proof
            throw proof
        }
    }
}

/** Per-launch environment bytes retained only by descriptor and one private bootstrap name. */
private class SandboxEnvironmentFile private constructor(
    private val controlDirectory: PinnedControlDirectory,
    private val descriptor: LinuxDescriptor,
    private val originalName: String,
    val identity: LinuxFileIdentity,
    private val bindingNamesSha256: String,
    private val bindingCount: Int,
    private val encodedBytes: Long,
    private val expectedContentSha256: String,
) {
    val materializedSource: Path get() = controlDirectory.path.resolve(currentName)
    val sandboxPath: Path get() = ACP_SANDBOX_ENVIRONMENT_PATH
    val expectedLinkCount: Int get() = if (linked) 1 else 0

    fun setupAttestation(): AcpSetupFileAttestation = AcpSetupFileAttestation(
        destination = sandboxPath,
        device = identity.key.device,
        inode = identity.key.inode,
        expectedLinkCount = expectedLinkCount,
    )

    private var currentName = originalName
    private var linked = true
    private var closed = false
    private var cleanupFailure: AcpCleanupProofFailure? = null

    fun requireCurrentIdentity(cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT) {
        cancellationCheck()
        cleanupFailure?.let { throw it }
        if (closed) throw IOException("sandbox environment descriptor is closed")
        controlDirectory.requireCurrent()
        val current = LinuxFilesystemSyscalls.identity(descriptor.fd)
        val expectedLinks = if (linked) 1 else 0
        if (current.key != identity.key || current.mountId != identity.mountId ||
            !current.isRegularFile || current.isSymbolicLink || current.uid != currentUid() ||
            current.mode.permissions != SANDBOX_ENVIRONMENT_FILE_MODE || current.linkCount != expectedLinks
        ) throw IOException("sandbox environment descriptor identity changed")
        if (sha256(
                descriptor,
                MAXIMUM_SANDBOX_ENVIRONMENT_BYTES.toLong(),
                cancellationCheck,
            ) != expectedContentSha256
        ) {
            throw IOException("sandbox environment bytes changed")
        }
        val parent = controlDirectory.requireChildParent()
        LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, currentName).use { named ->
            if (linked) {
                if (named == null || named.identity.key != identity.key ||
                    named.identity.mountId != identity.mountId || named.identity.linkCount != 1
                ) throw IOException("sandbox environment bootstrap name changed")
            } else if (named != null) {
                throw IOException("sandbox environment bootstrap name reappeared")
            }
        }
        if (!linked || currentName != originalName) requireNameAbsent(parent.fd, originalName)
    }

    @Synchronized
    fun unlinkAndProveAnonymous(cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT) {
        cleanupFailure?.let { throw it }
        if (!linked) {
            requireCurrentIdentity(cancellationCheck)
            return
        }
        requireCurrentIdentity(cancellationCheck)
        val parent = controlDirectory.requireChildParent()
        val quarantine = ".decomp-acp-environment-unlink-${UUID.randomUUID()}"
        LinuxFilesystemSyscalls.renameNoReplace(parent.fd, currentName, quarantine)
        currentName = quarantine
        try {
            requireCurrentIdentity(cancellationCheck)
            LinuxFilesystemSyscalls.unlink(parent.fd, quarantine)
            linked = false
            requireCurrentIdentity(cancellationCheck)
        } catch (failure: Throwable) {
            if (linked && currentName == quarantine) {
                try {
                    LinuxFilesystemSyscalls.renameNoReplace(parent.fd, quarantine, originalName)
                    currentName = originalName
                } catch (restoreFailure: Throwable) {
                    failure.addSuppressed(restoreFailure)
                }
            }
            throw failure
        }
    }

    fun evidence(): AcpSandboxEnvironmentEvidence = AcpSandboxEnvironmentEvidence(
        sandboxPathSha256 = sha256(sandboxPath.toString()),
        bindingNamesSha256 = bindingNamesSha256,
        bindingCount = bindingCount,
        encodedBytes = encodedBytes,
        device = identity.key.device,
        inode = identity.key.inode,
        mountId = identity.mountId,
        mode = identity.mode,
        linkCount = LinuxFilesystemSyscalls.identity(descriptor.fd).linkCount,
    ).also {
        if (linked || it.linkCount != 0) {
            throw IOException("sandbox environment evidence requires an unlinked pinned inode")
        }
    }

    @Synchronized
    fun closeAndProve() {
        cleanupFailure?.let { throw it }
        if (closed) return
        try {
            if (linked) unlinkAndProveAnonymous()
            requireCurrentIdentity()
            descriptor.close()
            closed = true
        } catch (failure: Throwable) {
            val proof = AcpCleanupProofFailure("sandbox environment cleanup was not proven", failure)
            cleanupFailure = proof
            throw proof
        }
    }

    companion object {
        fun create(
            controlDirectory: PinnedControlDirectory,
            environment: Map<String, String>,
            cancellationCheck: () -> Unit,
        ): SandboxEnvironmentFile {
            cancellationCheck()
            validateSandboxEnvironment(environment, cancellationCheck)
            val content = canonicalSandboxEnvironment(environment, cancellationCheck)
            cancellationCheck()
            if (environment.size > MAXIMUM_SANDBOX_ENVIRONMENT_BINDINGS ||
                content.size > MAXIMUM_SANDBOX_ENVIRONMENT_BYTES
            ) throw IOException("sandbox environment exceeds the static helper limits")
            val parent = controlDirectory.requireChildParent()
            var descriptor: LinuxDescriptor? = null
            var materializedName: String? = null
            try {
                val created = LinuxFilesystemSyscalls.createTemporaryAt(parent.fd)
                descriptor = created
                LinuxFilesystemSyscalls.chmod(created, SANDBOX_ENVIRONMENT_FILE_MODE)
                LinuxFilesystemSyscalls.write(created, content, cancellationCheck)
                val identity = LinuxFilesystemSyscalls.identity(created.fd)
                if (!identity.isRegularFile || identity.isSymbolicLink || identity.uid != currentUid() ||
                    identity.mode.permissions != SANDBOX_ENVIRONMENT_FILE_MODE || identity.linkCount != 0 ||
                    identity.mountId != parent.identity.mountId
                ) throw IOException("sandbox environment inode is not a private regular file")
                val name = ".decomp-acp-environment-${UUID.randomUUID()}"
                LinuxFilesystemSyscalls.linkTemporaryAt(created, parent.fd, name)
                materializedName = name
                val initialized = SandboxEnvironmentFile(
                    controlDirectory,
                    created,
                    name,
                    identity,
                    canonicalStringDigest(sortedStrings(environment.keys, cancellationCheck), cancellationCheck),
                    environment.size,
                    content.size.toLong(),
                    MessageDigest.getInstance("SHA-256").digest(content).toHex(),
                )
                descriptor = null
                initialized.requireCurrentIdentity(cancellationCheck)
                return initialized
            } catch (failure: Throwable) {
                val cleanup = runCatching {
                    val opened = descriptor
                    val name = materializedName
                    if (opened != null && name != null) {
                        LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name).use { selected ->
                            if (selected == null || selected.identity.key != opened.identity.key) {
                                throw IOException("sandbox environment initialization selected a replacement")
                            }
                        }
                        LinuxFilesystemSyscalls.unlink(parent.fd, name)
                        if (LinuxFilesystemSyscalls.identity(opened.fd).linkCount != 0) {
                            throw IOException("sandbox environment initialization residue remains linked")
                        }
                    }
                }.exceptionOrNull()
                descriptor?.close()
                if (cleanup != null) {
                    throw AcpCleanupProofFailure(
                        "sandbox environment initialization cleanup was not proven",
                        cleanup,
                    ).also { it.addSuppressed(failure) }
                }
                throw failure
            }
        }
    }
}

private fun validateSandboxEnvironment(
    environment: Map<String, String>,
    cancellationCheck: () -> Unit,
) {
    if (environment.size > MAXIMUM_SANDBOX_ENVIRONMENT_BINDINGS) {
        throw IOException("sandbox environment exceeds the static helper binding-count limit")
    }
    var encodedBytes = 0L
    environment.forEach { (name, value) ->
        cancellationCheck()
        if (name.length > MAXIMUM_SANDBOX_ENVIRONMENT_BYTES ||
            !name.matches(Regex("[A-Za-z_][A-Za-z0-9_]*")) ||
            isSandboxHelperControlEnvironmentName(name)
        ) throw IOException("sandbox environment contains a reserved or invalid name: $name")
        if (value.length > MAXIMUM_SANDBOX_ENVIRONMENT_BYTES) {
            throw IOException("sandbox environment exceeds the static helper byte limit")
        }
        if ('\u0000' in value) throw IOException("sandbox environment values may not contain NUL")
        encodedBytes = Math.addExact(
            encodedBytes,
            utf8Length(name, cancellationCheck) + utf8Length(value, cancellationCheck) + 2L,
        )
        if (encodedBytes > MAXIMUM_SANDBOX_ENVIRONMENT_BYTES) {
            throw IOException("sandbox environment exceeds the static helper byte limit")
        }
    }
}

private fun canonicalSandboxEnvironment(
    environment: Map<String, String>,
    cancellationCheck: () -> Unit,
): ByteArray {
    val output = ByteArrayOutputStream(minOf(MAXIMUM_SANDBOX_ENVIRONMENT_BYTES, 8192))
    environment.entries.sortedWith { left, right ->
        compareCheckpointed(left.key, right.key, cancellationCheck)
    }.forEach { (name, value) ->
        cancellationCheck()
        writeUtf8Chunks(output, name, cancellationCheck)
        output.write('='.code)
        writeUtf8Chunks(output, value, cancellationCheck)
        output.write(0)
        if (output.size() > MAXIMUM_SANDBOX_ENVIRONMENT_BYTES) {
            throw IOException("sandbox environment exceeds the static helper byte limit")
        }
    }
    cancellationCheck()
    return output.toByteArray()
}

private fun writeUtf8Chunks(
    output: ByteArrayOutputStream,
    value: String,
    cancellationCheck: () -> Unit,
) {
    var offset = 0
    while (offset < value.length) {
        cancellationCheck()
        var end = minOf(value.length, offset + ENVIRONMENT_ENCODING_CHARACTER_CHUNK)
        if (end < value.length && Character.isHighSurrogate(value[end - 1]) &&
            Character.isLowSurrogate(value[end])
        ) end--
        output.write(value.substring(offset, end).toByteArray(Charsets.UTF_8))
        if (output.size() > MAXIMUM_SANDBOX_ENVIRONMENT_BYTES) {
            throw IOException("sandbox environment exceeds the static helper byte limit")
        }
        offset = end
    }
}

private fun requireDirectoryDescriptorIdentity(
    descriptor: LinuxDescriptor,
    expectedKey: LinuxFileKey,
    expectedMountId: Long,
    exactPermissions: Int?,
) {
    val current = LinuxFilesystemSyscalls.identity(descriptor.fd)
    if (current.key != expectedKey || current.mountId != expectedMountId ||
        !current.isDirectory || current.isSymbolicLink ||
        current.uid != descriptor.identity.uid || current.gid != descriptor.identity.gid ||
        (exactPermissions != null && current.mode.permissions != exactPermissions)
    ) throw IOException("private directory descriptor identity changed")
}

private fun requireNameAbsent(parentFd: Int, name: String) {
    LinuxFilesystemSyscalls.openPathAtOrNull(parentFd, name).use { current ->
        if (current != null) throw IOException("private cleanup name unexpectedly exists: $name")
    }
}

private fun removeExactEmptyDirectory(
    parent: LinuxDescriptor,
    name: String,
    directory: LinuxDescriptor,
    expectedKey: LinuxFileKey,
) {
    if (LinuxFilesystemSyscalls.directoryEntryNames(directory, maximumEntries = 1).isNotEmpty()) {
        throw IOException("private directory is not empty at removal")
    }
    val quarantine = ".decomp-acp-dir-delete-${UUID.randomUUID()}"
    LinuxFilesystemSyscalls.renameNoReplace(parent.fd, name, quarantine)
    LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, quarantine).use { selected ->
        if (selected.identity.key != expectedKey || selected.identity.mountId != directory.identity.mountId) {
            throw IOException("private directory cleanup selected a replacement")
        }
    }
    requireNameAbsent(parent.fd, name)
    LinuxFilesystemSyscalls.removeDirectory(parent.fd, quarantine)
    if (LinuxFilesystemSyscalls.identity(directory.fd).linkCount != 0) {
        throw IOException("private directory descriptor remains linked after removal")
    }
    requireNameAbsent(parent.fd, quarantine)
    requireNameAbsent(parent.fd, name)
}

/** Descriptor-relative bounded cleanup. Budget excess retains the pinned tree and fails closed. */
internal fun deletePrivateTreeContents(
    directory: LinuxDescriptor,
    limits: AcpRuntimeClosureLimits,
) {
    deletePrivateTreeContents(directory, PrivateCleanupBudget(limits), depth = 0)
}

private fun deletePrivateTreeContents(
    directory: LinuxDescriptor,
    budget: PrivateCleanupBudget,
    depth: Int,
) {
    budget.enterDirectory(depth)
    LinuxFilesystemSyscalls.chmod(directory, CONTROL_DIRECTORY_MODE)
    val directoryMountId = LinuxFilesystemSyscalls.identity(directory.fd).mountId
    val names = LinuxFilesystemSyscalls.directoryEntryNames(
        directory,
        budget.maximumNamesForOneDirectory(),
    )
    budget.accountNames(names)
    names.sorted().forEach { name ->
        val opened = LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, name)
            ?: throw IOException("private cleanup entry disappeared before quarantine")
        opened.use { child ->
            budget.accountEntry(child)
            if (child.identity.isSymbolicLink ||
                (!child.identity.isDirectory && !child.identity.isRegularFile)
            ) throw IOException("private cleanup tree contains a link or special entry")
            if (child.identity.mountId != directoryMountId) {
                throw IOException("private cleanup tree crosses a mount boundary")
            }
            val quarantine = ".decomp-acp-entry-delete-${UUID.randomUUID()}"
            LinuxFilesystemSyscalls.renameNoReplace(directory.fd, name, quarantine)
            LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, quarantine).use { selected ->
                if (selected == null || selected.identity.key != child.identity.key ||
                    selected.identity.mountId != child.identity.mountId
                ) throw IOException("private cleanup quarantine selected a replacement entry")
            }
            requireNameAbsent(directory.fd, name)
            if (child.identity.isDirectory) {
                LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, quarantine).use { childDirectory ->
                    if (childDirectory.identity.key != child.identity.key ||
                        childDirectory.identity.mountId != child.identity.mountId
                    ) throw IOException("private cleanup directory changed after quarantine")
                    deletePrivateTreeContents(childDirectory, budget, depth + 1)
                    LinuxFilesystemSyscalls.removeDirectory(directory.fd, quarantine)
                    if (LinuxFilesystemSyscalls.identity(childDirectory.fd).linkCount != 0) {
                        throw IOException("private cleanup directory remains linked")
                    }
                }
            } else {
                if (child.identity.linkCount != 1) {
                    throw IOException("private cleanup file unexpectedly has multiple links")
                }
                LinuxFilesystemSyscalls.unlink(directory.fd, quarantine)
                if (LinuxFilesystemSyscalls.identity(child.fd).linkCount != 0) {
                    throw IOException("private cleanup file remains linked")
                }
            }
            requireNameAbsent(directory.fd, quarantine)
            requireNameAbsent(directory.fd, name)
        }
    }
}

private class PrivateCleanupBudget(private val limits: AcpRuntimeClosureLimits) {
    private var entries = 0
    private var bytes = 0L

    fun enterDirectory(depth: Int) {
        if (depth > limits.maximumDepth) {
            throw LinuxResourceLimitException()
        }
    }

    fun maximumNamesForOneDirectory(): Int {
        val remaining = limits.maximumEntries - entries
        return maxOf(1, remaining)
    }

    fun accountNames(names: Collection<String>) {
        names.forEach { name -> accountBytes(name.toByteArray(Charsets.UTF_8).size.toLong()) }
    }

    fun accountEntry(descriptor: LinuxDescriptor) {
        val identity = descriptor.identity
        entries = Math.addExact(entries, 1)
        if (entries > limits.maximumEntries) throw LinuxResourceLimitException()
        if (identity.isRegularFile) {
            accountBytes(Files.size(LinuxFilesystemSyscalls.descriptorPath(descriptor)))
        }
    }

    private fun accountBytes(amount: Long) {
        bytes = Math.addExact(bytes, amount)
        if (bytes > limits.maximumUserOwnedFileBytes) throw LinuxResourceLimitException()
    }
}

private class SystemdScopeController(
    private val supervisor: PinnedSecurityExecutable,
    private val inspector: PinnedSecurityExecutable,
    private val bus: PinnedSystemdBusEndpoint,
    private val bubblewrap: PinnedSecurityExecutable,
    private val unitName: String,
    private val limits: AcpSandboxResourceLimits,
    maximumWallDuration: Duration,
) {
    private val runtimeMaximum = maximumWallDuration.plus(CLEANUP_TIMEOUT)
    @Volatile
    private var knownCgroupPath: Path? = null

    fun requireUnitAbsent(cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT) {
        cancellationCheck()
        if (show(cancellationCheck)["LoadState"] != "not-found") {
            throw IOException("random ACP sandbox scope name is already in use")
        }
        cancellationCheck()
    }

    fun wrap(command: List<String>): List<String> = buildList {
        add(supervisor.path.toString())
        add("--user")
        add("--scope")
        add("--quiet")
        add("--collect")
        add("--expand-environment=no")
        add("--unit=$unitName")
        add("--property=TasksMax=${limits.maximumProcesses}")
        add("--property=MemoryMax=${limits.maximumAddressSpaceBytes}")
        add("--property=MemorySwapMax=0")
        // systemd's supported transient-unit contract is OOMPolicy=kill; the effective
        // cgroup authority is independently verified as memory.oom.group=1 below.
        add("--property=OOMPolicy=kill")
        add("--property=CPUQuota=100%")
        add("--property=KillMode=control-group")
        add("--property=SendSIGKILL=yes")
        add("--property=RuntimeMaxSec=${runtimeMaximum.toMillis()}ms")
        add("--property=TimeoutStopSec=${CLEANUP_TIMEOUT.toMillis()}ms")
        add("--property=Delegate=no")
        add("--")
        addAll(command)
    }

    fun verifyAttached(
        process: Process,
        cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
    ): VerifiedSystemdScope {
        val deadline = System.nanoTime() + SCOPE_START_TIMEOUT.toNanos()
        var lastFailure: Throwable? = null
        while (System.nanoTime() < deadline) {
            cancellationCheck()
            if (!process.isAlive) throw IOException("sandbox boundary exited before cgroup verification")
            try {
                val manager = requireManagerProperties(show(cancellationCheck))
                val cgroupPath = validateControlGroupPath(manager.controlGroup)
                val controllers = requireActualControllers(cgroupPath, process.pid(), manager, cancellationCheck)
                cancellationCheck()
                return VerifiedSystemdScope(
                    inspector,
                    bus,
                    bubblewrap,
                    unitName,
                    cgroupPath,
                    controllers,
                    process.pid(),
                )
            } catch (failure: IOException) {
                lastFailure = failure
                cancellationCheck()
                Thread.sleep(SCOPE_POLL_MILLIS)
            }
        }
        throw IOException("sandbox cgroup scope could not be verified", lastFailure)
    }

    fun requireKilledAndRemovedIfPresent(
        process: Process,
        rootProcessHandle: LinuxProcessDescriptor?,
    ) {
        val deadline = System.nanoTime() + CLEANUP_TIMEOUT.toNanos()
        var lastFailure: Throwable? = null
        // No request byte has been authorized yet. Terminating the exact Process object first is
        // therefore safe and closes the narrow interval in which cancellation can arrive after
        // ProcessBuilder.start() but before systemd publishes the unit's ControlGroup property.
        val rootSignalFailure = try {
            if (rootProcessHandle == null) {
                if (process.isAlive) IOException("failed sandbox launch has no pinned root-process handle") else null
            } else {
                LinuxFilesystemSyscalls.killProcess(rootProcessHandle)
                null
            }
        } catch (failure: IOException) {
            failure
        }
        while (System.nanoTime() < deadline) {
            val iterationFailures = mutableListOf<IOException>()
            rootSignalFailure?.let(iterationFailures::add)
            val before = try {
                show()
            } catch (failure: IOException) {
                iterationFailures += failure
                null
            }
            if (before?.get("Id") == unitName) {
                before["ControlGroup"]
                    ?.takeIf(String::isNotBlank)
                    ?.let { controlGroup ->
                        try {
                            rememberControlGroupPath(controlGroup)
                        } catch (failure: IOException) {
                            iterationFailures += failure
                        }
                    }
            }
            knownCgroupPath?.let { cgroup ->
                try {
                    killPinnedBubblewrapProcesses(cgroup, bubblewrap)
                } catch (failure: IOException) {
                    iterationFailures += failure
                }
            }
            listOf(
                listOf("kill", "--kill-whom=all", "--signal=SIGKILL", unitName),
                listOf("stop", unitName),
                listOf("reset-failed", unitName),
            ).forEach { arguments ->
                try {
                    systemctl(inspector, bus, arguments)
                } catch (failure: IOException) {
                    iterationFailures += failure
                }
            }
            val after = try {
                show()
            } catch (failure: IOException) {
                iterationFailures += failure
                null
            }
            val exactCgroup = knownCgroupPath
            if (after?.get("LoadState") == "not-found" && exactCgroup != null &&
                !Files.exists(exactCgroup, LinkOption.NOFOLLOW_LINKS) && !process.isAlive
            ) return
            if (after?.get("LoadState") == "not-found" && exactCgroup == null &&
                !process.isAlive
            ) {
                try {
                    if (findCgroupDirectoriesForUnit(unitName).isEmpty()) return
                } catch (failure: IOException) {
                    iterationFailures += failure
                }
            }
            if (exactCgroup == null) {
                iterationFailures += IOException(
                    "failed sandbox scope has not exposed an exact cgroup path or absence proof",
                )
            }
            if (iterationFailures.isNotEmpty()) {
                lastFailure = IOException(
                    "failed sandbox scope cleanup attempt was not proven",
                    iterationFailures.first(),
                ).also { aggregate -> iterationFailures.drop(1).forEach(aggregate::addSuppressed) }
            }
            Thread.sleep(SCOPE_POLL_MILLIS)
        }
        throw IOException("failed sandbox launch left a scope or cgroup that could not be proven absent", lastFailure)
    }

    private fun show(
        cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
    ): Map<String, String> = systemctlShow(inspector, bus, unitName, cancellationCheck)

    private fun requireManagerProperties(properties: Map<String, String>): VerifiedScopeManager {
        val runtimeMaxMicros = parseSystemdDurationMicros(properties["RuntimeMaxUSec"])
        val timeoutStopMicros = parseSystemdDurationMicros(properties["TimeoutStopUSec"])
        val mismatches = buildList {
            if (properties["Id"] != unitName) add("Id")
            if (properties["LoadState"] != "loaded") add("LoadState")
            if (properties["ActiveState"] !in setOf("active", "activating")) add("ActiveState")
            if (properties["TasksMax"] != limits.maximumProcesses.toString()) add("TasksMax")
            if (properties["MemoryMax"] != limits.maximumAddressSpaceBytes.toString()) add("MemoryMax")
            if (properties["MemorySwapMax"] != "0") add("MemorySwapMax")
            if (properties["OOMPolicy"] != "kill") add("OOMPolicy")
            if (properties["KillMode"] != "control-group") add("KillMode")
            if (properties["SendSIGKILL"] != "yes") add("SendSIGKILL")
            if (runtimeMaxMicros != runtimeMaximum.toNanos() / 1_000L) add("RuntimeMaxUSec")
            if (timeoutStopMicros != CLEANUP_TIMEOUT.toNanos() / 1_000L) add("TimeoutStopUSec")
            if (properties["Delegate"] != "no") add("Delegate")
        }
        if (mismatches.isNotEmpty()) {
            throw IOException(
                "systemd scope metadata does not match the sandbox policy: ${mismatches.joinToString(",")}",
            )
        }
        val cpu = properties["CPUQuotaPerSecUSec"].orEmpty()
        if (cpu !in setOf("1s", "1000000us")) {
            throw IOException("systemd scope CPU quota is not finite and verified")
        }
        val controlGroup = properties["ControlGroup"].orEmpty().ifBlank {
            throw IOException("systemd scope did not report its cgroup")
        }
        val verifiedRuntimeMaxMicros = requireNotNull(runtimeMaxMicros)
        val verifiedTimeoutStopMicros = requireNotNull(timeoutStopMicros)
        return VerifiedScopeManager(controlGroup, verifiedRuntimeMaxMicros, verifiedTimeoutStopMicros)
    }

    private fun validateControlGroupPath(controlGroup: String): Path {
        val path = rememberControlGroupPath(controlGroup)
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            throw IOException("systemd scope cgroup is missing")
        }
        return path
    }

    private fun rememberControlGroupPath(controlGroup: String): Path {
        val path = controlGroupPathForCleanup(controlGroup)
        if (path.fileName?.toString() != unitName) {
            throw IOException("systemd scope cgroup path is not bound to its exact unit name")
        }
        val prior = knownCgroupPath
        if (prior != null && prior != path) {
            throw IOException("systemd scope cgroup path changed")
        }
        knownCgroupPath = path
        return path
    }

    private fun requireActualControllers(
        cgroup: Path,
        pid: Long,
        manager: VerifiedScopeManager,
        cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
    ): AcpCgroupControllerEvidence {
        cancellationCheck()
        val processCgroup = Files.readString(Path.of("/proc/$pid/cgroup"))
            .lineSequence()
            .singleOrNull { it.startsWith("0::") }
            ?.removePrefix("0::")
            ?: throw IOException("sandbox process is not in a cgroup-v2 leaf")
        if (CGROUP_ROOT.resolve(processCgroup.removePrefix("/")).normalize() != cgroup) {
            throw IOException("sandbox process is not attached to the reported systemd scope")
        }
        val pidsMax = Files.readString(cgroup.resolve("pids.max")).trim().toLongOrNull()
        if (pidsMax != limits.maximumProcesses.toLong()) {
            throw IOException("sandbox cgroup pids.max does not match policy")
        }
        val memoryMax = Files.readString(cgroup.resolve("memory.max")).trim().toLongOrNull()
        if (memoryMax != limits.maximumAddressSpaceBytes) {
            throw IOException("sandbox cgroup memory.max does not match policy")
        }
        val memorySwapMax = Files.readString(cgroup.resolve("memory.swap.max")).trim().toLongOrNull()
        if (memorySwapMax != 0L) {
            throw IOException("sandbox cgroup swap is not disabled")
        }
        val memoryOomGroup = Files.readString(cgroup.resolve("memory.oom.group")).trim()
        if (memoryOomGroup != "1") {
            throw IOException("sandbox cgroup does not atomically contain OOM failure")
        }
        val cpu = Files.readString(cgroup.resolve("cpu.max")).trim().split(Regex("\\s+"))
        val quota = cpu.getOrNull(0)?.toLongOrNull()
        val period = cpu.getOrNull(1)?.toLongOrNull()
        if (cpu.size != 2 || quota == null || period == null || quota <= 0 || quota != period) {
            throw IOException("sandbox cgroup CPU quota is not the verified 100 percent policy")
        }
        if (Files.readString(cgroup.resolve("cgroup.procs")).lineSequence().none { it.trim() == pid.toString() }) {
            throw IOException("sandbox leader is absent from the verified cgroup")
        }
        val populated = Files.readString(cgroup.resolve("cgroup.events"))
            .lineSequence()
            .filter { ' ' in it }
            .associate { line -> line.substringBefore(' ') to line.substringAfter(' ') }["populated"]
        if (populated != "1") throw IOException("sandbox cgroup is not populated by the gated process")
        cancellationCheck()
        return AcpCgroupControllerEvidence(
            pidsMax = pidsMax,
            memoryMaxBytes = memoryMax,
            memorySwapMaxBytes = memorySwapMax,
            cpuQuotaMicros = quota,
            cpuPeriodMicros = period,
            memoryOomGroup = true,
            runtimeMaxMicros = manager.runtimeMaxMicros,
            timeoutStopMicros = manager.timeoutStopMicros,
        )
    }
}

private data class VerifiedScopeManager(
    val controlGroup: String,
    val runtimeMaxMicros: Long,
    val timeoutStopMicros: Long,
)

internal class VerifiedSystemdScope(
    private val inspector: PinnedSecurityExecutable,
    private val bus: PinnedSystemdBusEndpoint,
    private val bubblewrap: PinnedSecurityExecutable,
    private val unitName: String,
    private val cgroupPath: Path,
    val controllers: AcpCgroupControllerEvidence,
    private val leaderPid: Long,
) {
    val identity: AcpSandboxScopeIdentity = AcpSandboxScopeIdentity(unitName, cgroupPath)

    /** Proves the fully mounted static helper and its pre-opened target/environment descriptors. */
    fun requireSetupWaiter(
        helperMount: AcpSetupFileAttestation,
        executableMount: AcpSetupFileAttestation,
        environmentFile: AcpSetupFileAttestation,
        targetCommand: List<String>,
        workingDirectory: Path,
        previous: AcpSetupWaiter? = null,
        cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
    ): AcpSetupWaiter {
        val deadline = System.nanoTime() + SCOPE_START_TIMEOUT.toNanos()
        var lastFailure: Throwable? = null
        while (System.nanoTime() < deadline) {
            cancellationCheck()
            try {
                val cgroupPids = Files.readAllLines(cgroupPath.resolve("cgroup.procs"))
                    .mapNotNull { it.trim().toLongOrNull() }
                    .toSet()
                val helperPids = cgroupPids.filter { pid ->
                    cancellationCheck()
                    try {
                        LinuxFilesystemSyscalls.openProcessExecutable(pid).use { executable ->
                            executable.identity.key.device == helperMount.device &&
                                executable.identity.key.inode == helperMount.inode &&
                                executable.identity.linkCount == helperMount.expectedLinkCount
                        }
                    } catch (_: Exception) {
                        cancellationCheck()
                        false
                    }
                }
                val waiters = helperPids.filter { pid ->
                    cancellationCheck()
                    try {
                            isBlockedRead(
                                readBoundedProcBytes(
                                    Path.of("/proc/$pid/syscall"),
                                    MAXIMUM_PROC_SYSCALL_BYTES,
                                    cancellationCheck,
                                ).toString(Charsets.UTF_8).trim(),
                                0,
                            ) && hasExactGateBootstrapEnvironment(pid, workingDirectory, cancellationCheck)
                    } catch (_: Exception) {
                        cancellationCheck()
                        false
                    }
                }
                if (waiters.size != 1) {
                    throw IOException("sandbox cgroup does not contain exactly one static gate helper waiter")
                }
                val pid = waiters.single()
                val innerBubblewrapPid = readParentPid(pid, cancellationCheck)
                requirePinnedExecutable(
                    innerBubblewrapPid,
                    bubblewrap,
                    "inner bubblewrap init",
                    cancellationCheck,
                )
                val outerBubblewrapPid = readParentPid(innerBubblewrapPid, cancellationCheck)
                requirePinnedExecutable(
                    outerBubblewrapPid,
                    bubblewrap,
                    "outer bubblewrap monitor",
                    cancellationCheck,
                )
                if (outerBubblewrapPid != leaderPid) {
                    throw IOException("sandbox helper is not descended from the verified scope leader")
                }
                val startTime = readProcessStartTime(pid, cancellationCheck)
                val innerStartTime = readProcessStartTime(innerBubblewrapPid, cancellationCheck)
                val outerStartTime = readProcessStartTime(outerBubblewrapPid, cancellationCheck)
                val current = AcpSetupWaiter(
                    pid,
                    startTime,
                    innerBubblewrapPid,
                    innerStartTime,
                    outerBubblewrapPid,
                    outerStartTime,
                )
                if (previous != null && current != previous) {
                    throw IOException("sandbox gate-helper process topology changed before release")
                }
                val helperVisibleMount = readSandboxMountInfo(pid, cancellationCheck).singleOrNull {
                    it.mountPoint == helperMount.destination
                } ?: throw IOException("sandbox gate-helper executable mount is absent or ambiguous")
                LinuxFilesystemSyscalls.openProcessExecutable(pid).use { executable ->
                    if (executable.identity.key.device != helperMount.device ||
                        executable.identity.key.inode != helperMount.inode ||
                        executable.identity.mountId != helperVisibleMount.mountId ||
                        executable.identity.linkCount != helperMount.expectedLinkCount
                    ) throw IOException("sandbox gate-helper executable is not its exact pinned mount")
                }
                val expectedArgv = listOf(
                    ACP_SANDBOX_GATE_HELPER_PATH.toString(),
                    ACP_SANDBOX_ENVIRONMENT_PATH.toString(),
                ) + targetCommand
                if (readProcessArguments(pid, cancellationCheck) != expectedArgv) {
                    throw IOException("sandbox gate-helper argv differs from the authorized target")
                }
                requireEmptyCapabilitiesAndPrivateNamespaces(pid, cancellationCheck)
                requireOpenedSandboxFile(
                    pid,
                    SANDBOX_GATE_TARGET_FD,
                    executableMount.destination,
                    executableMount.device,
                    executableMount.inode,
                    readOnly = true,
                    expectedLinkCount = executableMount.expectedLinkCount,
                    cancellationCheck = cancellationCheck,
                )
                requireOpenedSandboxFile(
                    pid,
                    SANDBOX_GATE_ENVIRONMENT_FD,
                    environmentFile.destination,
                    environmentFile.device,
                    environmentFile.inode,
                    readOnly = true,
                    expectedLinkCount = environmentFile.expectedLinkCount,
                    cancellationCheck = cancellationCheck,
                )
                val stillMember = Files.readAllLines(cgroupPath.resolve("cgroup.procs"))
                    .mapNotNull { it.trim().toLongOrNull() }
                    .toSet()
                if (!stillMember.containsAll(setOf(pid, innerBubblewrapPid, outerBubblewrapPid))) {
                    throw IOException("authorization-helper topology left the verified cgroup")
                }
                cancellationCheck()
                return current
            } catch (failure: IOException) {
                lastFailure = failure
            }
            cancellationCheck()
            Thread.sleep(SCOPE_POLL_MILLIS)
        }
        throw IOException("sandbox did not prove the static gate-helper setup waiter", lastFailure)
    }

    fun terminateAll() {
        signalAll("SIGTERM")
    }

    fun killAll() {
        signalAll("SIGKILL")
    }

    /** A collected unit is a benign signal race only when both independent absence proofs agree. */
    private fun signalAll(signal: String) {
        val failures = mutableListOf<IOException>()
        try {
            killPinnedBubblewrapProcesses(cgroupPath, bubblewrap)
        } catch (failure: IOException) {
            failures += failure
        }
        try {
            systemctl(inspector, bus, listOf("kill", "--kill-whom=all", "--signal=$signal", unitName))
        } catch (failure: IOException) {
            failures += failure
        }
        if (failures.isEmpty()) return
        try {
            val after = systemctlShow(inspector, bus, unitName)
            if (after["LoadState"] == "not-found" &&
                !Files.exists(cgroupPath, LinkOption.NOFOLLOW_LINKS)
            ) return
        } catch (verificationFailure: IOException) {
            failures.first().addSuppressed(verificationFailure)
        }
        val primary = IOException("sandbox scope signal failed without an exact cleanup proof", failures.first())
        failures.drop(1).forEach(primary::addSuppressed)
        throw primary
    }

    fun requireCleaned() {
        val deadline = System.nanoTime() + CLEANUP_TIMEOUT.toNanos()
        while (System.nanoTime() < deadline) {
            val properties = systemctlShow(inspector, bus, unitName)
            if (properties["LoadState"] == "not-found" && !Files.exists(cgroupPath, LinkOption.NOFOLLOW_LINKS)) return
            killAll()
            runCatching { systemctl(inspector, bus, listOf("stop", unitName)) }
            Thread.sleep(SCOPE_POLL_MILLIS)
        }
        val populated = if (Files.exists(cgroupPath.resolve("cgroup.events"))) {
            Files.readString(cgroupPath.resolve("cgroup.events")).contains("populated 1")
        } else false
        throw IOException("sandbox scope cleanup was not proven (populated=$populated)")
    }
}

internal data class AcpSetupWaiter(
    val helperPid: Long,
    val helperStartTime: Long,
    val innerBubblewrapPid: Long,
    val innerBubblewrapStartTime: Long,
    val outerBubblewrapPid: Long,
    val outerBubblewrapStartTime: Long,
)

/** Only immutable identity facts cross from private pinned resources into scope attestation. */
internal data class AcpSetupFileAttestation(
    val destination: Path,
    val device: Long,
    val inode: Long,
    val expectedLinkCount: Int,
)

private fun readProcessStartTime(
    pid: Long,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): Long {
    val record = readBoundedProcBytes(
        Path.of("/proc/$pid/stat"),
        MAXIMUM_PROC_STATUS_BYTES,
        cancellationCheck,
    ).toString(Charsets.UTF_8)
    val suffix = record.substringAfterLast(") ", missingDelimiterValue = "")
    return suffix.split(' ').getOrNull(19)?.toLongOrNull()
        ?: throw IOException("sandbox process start-time identity is unavailable")
}

private fun readProcessArguments(
    pid: Long,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): List<String> {
    val bytes = readBoundedProcBytes(
        Path.of("/proc/$pid/cmdline"),
        MAXIMUM_PROC_CMDLINE_BYTES,
        cancellationCheck,
    )
    if (bytes.isEmpty() || bytes.last() != 0.toByte()) {
        throw IOException("sandbox gate-helper command line is malformed")
    }
    val arguments = bytes.toString(Charsets.UTF_8).split('\u0000').dropLast(1)
    if (arguments.size > MAXIMUM_SANDBOX_ARGUMENTS) {
        throw IOException("sandbox gate-helper command line has too many arguments")
    }
    return arguments
}

private fun hasExactGateBootstrapEnvironment(
    pid: Long,
    workingDirectory: Path,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): Boolean {
    val actual = readBoundedProcBytes(
        Path.of("/proc/$pid/environ"),
        MAXIMUM_PROC_ENVIRONMENT_BYTES,
        cancellationCheck,
    )
    val expected = "PWD=$workingDirectory\u0000".toByteArray(Charsets.UTF_8)
    return actual.contentEquals(expected)
}

private fun requireEmptyCapabilitiesAndPrivateNamespaces(
    pid: Long,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
) {
    val status = readBoundedProcLines(
        Path.of("/proc/$pid/status"),
        MAXIMUM_PROC_STATUS_BYTES,
        MAXIMUM_PROC_STATUS_LINES,
        cancellationCheck,
    )
        .filter { ':' in it }
        .associate { it.substringBefore(':') to it.substringAfter(':').trim() }
    listOf("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb").forEach { name ->
        if (status[name]?.toULongOrNull(16) != 0UL) {
            throw IOException("sandbox gate helper retains Linux capability $name")
        }
    }
    listOf("user", "mnt", "pid", "net", "ipc", "uts").forEach { namespace ->
        val host = Files.readSymbolicLink(Path.of("/proc/self/ns/$namespace"))
        val sandbox = Files.readSymbolicLink(Path.of("/proc/$pid/ns/$namespace"))
        if (host == sandbox) throw IOException("sandbox gate helper did not isolate the $namespace namespace")
    }
}

private fun requireOpenedSandboxFile(
    pid: Long,
    descriptor: Int,
    destination: Path,
    expectedDevice: Long,
    expectedInode: Long,
    readOnly: Boolean,
    expectedLinkCount: Int? = null,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
) {
    cancellationCheck()
    val fdPath = Path.of("/proc/$pid/fd/$descriptor")
    val unix = Files.readAttributes(fdPath, "unix:dev,ino,mode,nlink")
    if ((unix.getValue("dev") as Number).toLong() != expectedDevice ||
        (unix.getValue("ino") as Number).toLong() != expectedInode ||
        (unix.getValue("mode") as Number).toInt() and 0xf000 != 0x8000 ||
        (expectedLinkCount != null && (unix.getValue("nlink") as Number).toInt() != expectedLinkCount)
    ) throw IOException("sandbox gate helper opened an unexpected descriptor $descriptor")
    val info = readBoundedProcLines(
        Path.of("/proc/$pid/fdinfo/$descriptor"),
        MAXIMUM_PROC_FDINFO_BYTES,
        MAXIMUM_PROC_FDINFO_LINES,
        cancellationCheck,
    )
        .filter { ':' in it }
        .associate { it.substringBefore(':') to it.substringAfter(':').trim() }
    if (info["pos"] != "0") throw IOException("sandbox gate-helper descriptor is not positioned at zero")
    val flags = info["flags"]?.toLongOrNull(8)
        ?: throw IOException("sandbox gate-helper descriptor flags are unavailable")
    if (readOnly && flags and 3L != 0L) {
        throw IOException("sandbox gate-helper descriptor is writable")
    }
    val descriptorMountId = info["mnt_id"]?.toLongOrNull()
        ?: throw IOException("sandbox gate-helper descriptor mount identity is unavailable")
    val visibleMount = readSandboxMountInfo(pid, cancellationCheck).singleOrNull { it.mountPoint == destination }
        ?: throw IOException("sandbox gate-helper descriptor destination is not one exact mount")
    if (visibleMount.mountId != descriptorMountId) {
        throw IOException("sandbox gate-helper descriptor is not bound to its expected mount")
    }
}

private fun isPinnedExecutable(
    pid: Long,
    executable: PinnedSecurityExecutable,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): Boolean {
    cancellationCheck()
    val current = Path.of("/proc/$pid/exe").toRealPath()
    val identity = readIdentity(current, cancellationCheck)
    return identity.device == executable.identity.device &&
        identity.inode == executable.identity.inode &&
        identity.mountId == executable.identity.mountId
}

private fun requirePinnedExecutable(
    pid: Long,
    executable: PinnedSecurityExecutable,
    label: String,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
) {
    if (!isPinnedExecutable(pid, executable, cancellationCheck)) {
        throw IOException("$label is not the pinned executable")
    }
}

private fun readParentPid(
    pid: Long,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): Long = readBoundedProcLines(
    Path.of("/proc/$pid/status"),
    MAXIMUM_PROC_STATUS_BYTES,
    MAXIMUM_PROC_STATUS_LINES,
    cancellationCheck,
)
    .firstOrNull { it.startsWith("PPid:") }
    ?.substringAfter(':')
    ?.trim()
    ?.toLongOrNull()
    ?: throw IOException("sandbox process parent identity is unavailable")

private fun killPinnedBubblewrapProcesses(cgroupPath: Path, bubblewrap: PinnedSecurityExecutable) {
    val deadline = System.nanoTime() + CLEANUP_TIMEOUT.toNanos()
    while (System.nanoTime() < deadline) {
        if (!Files.exists(cgroupPath, LinkOption.NOFOLLOW_LINKS)) return
        val cgroupPids = Files.readAllLines(cgroupPath.resolve("cgroup.procs"))
            .mapNotNull { it.trim().toLongOrNull() }
            .toSet()
        val bubblewrapPids = cgroupPids.mapNotNull { pid ->
            val startTime = try {
                readProcessStartTime(pid)
            } catch (_: IOException) {
                return@mapNotNull null
            }
            val pinned = try {
                isPinnedExecutable(pid, bubblewrap)
            } catch (_: Exception) {
                false
            }
            if (pinned) pid to startTime else null
        }
        if (bubblewrapPids.isEmpty()) return
        bubblewrapPids.forEach { (pid, expectedStartTime) ->
            val handle = try {
                LinuxFilesystemSyscalls.openProcessHandle(pid)
            } catch (failure: LinuxSyscallException) {
                if (failure.errno == LinuxFilesystemSyscalls.ESRCH) return@forEach
                throw failure
            }
            handle.use {
                val stillMember = try {
                    Files.readAllLines(cgroupPath.resolve("cgroup.procs"))
                        .mapNotNull { value -> value.trim().toLongOrNull() }
                        .contains(pid)
                } catch (_: IOException) {
                    false
                }
                val sameProcess = if (stillMember) {
                    try {
                        readProcessStartTime(pid) == expectedStartTime && isPinnedExecutable(pid, bubblewrap)
                    } catch (_: Exception) {
                        false
                    }
                } else false
                // The pidfd pins the pre-open process, but the post-open start-time/cgroup/exe
                // checks prove it is the same authorized bwrap before any signal is sent.
                if (sameProcess) LinuxFilesystemSyscalls.killProcess(handle)
            }
        }
        Thread.sleep(SCOPE_POLL_MILLIS)
    }
    throw IOException("pinned bubblewrap processes survived ordered pre-release cleanup")
}

private fun requireExactRlimits(
    pid: Long,
    limits: AcpSandboxResourceLimits,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): AcpSandboxRlimitEvidence {
    cancellationCheck()
    val lines = readBoundedProcLines(
        Path.of("/proc/$pid/limits"),
        MAXIMUM_PROC_LIMITS_BYTES,
        MAXIMUM_PROC_LIMITS_LINES,
        cancellationCheck,
    )
    fun values(label: String): Pair<Long, Long> {
        val fields = lines.firstOrNull { it.startsWith(label) }
            ?.removePrefix(label)
            ?.trim()
            ?.split(Regex("\\s+"))
            ?: throw IOException("sandbox process limit is absent: $label")
        if (fields.size < 2) throw IOException("sandbox process limit is malformed: $label")
        val soft = fields[0].toLongOrNull()
            ?: throw IOException("sandbox process limit is not finite: $label")
        val hard = fields[1].toLongOrNull()
            ?: throw IOException("sandbox process hard limit is not finite: $label")
        return soft to hard
    }

    val processes = values("Max processes")
    val openFiles = values("Max open files")
    val fileBytes = values("Max file size")
    val coreBytes = values("Max core file size")
    val addressSpace = values("Max address space")
    val cpuSeconds = values("Max cpu time")
    if (processes.first != processes.second || processes.first < limits.maximumProcesses.toLong() ||
        openFiles != (limits.maximumOpenFiles.toLong() to limits.maximumOpenFiles.toLong()) ||
        fileBytes != (limits.maximumFileBytes to limits.maximumFileBytes) ||
        coreBytes != (0L to 0L) ||
        addressSpace != (limits.maximumAddressSpaceBytes to limits.maximumAddressSpaceBytes) ||
        cpuSeconds != (limits.maximumCpuSeconds.toLong() to limits.maximumCpuSeconds.toLong())
    ) throw IOException("sandbox process limits do not exactly match the verified launch policy")
    cancellationCheck()
    return AcpSandboxRlimitEvidence(
        processesSoft = processes.first,
        processesHard = processes.second,
        openFilesSoft = openFiles.first,
        openFilesHard = openFiles.second,
        fileBytesSoft = fileBytes.first,
        fileBytesHard = fileBytes.second,
        coreBytesSoft = coreBytes.first,
        coreBytesHard = coreBytes.second,
        addressSpaceSoft = addressSpace.first,
        addressSpaceHard = addressSpace.second,
        cpuSecondsSoft = cpuSeconds.first,
        cpuSecondsHard = cpuSeconds.second,
    )
}

/** Pure command fragment so mandatory isolation is regression-tested even on unsupported hosts. */
internal fun acpBubblewrapIsolationArguments(): List<String> = listOf(
    "--unshare-all",
    // Required explicitly before --disable-userns, even though --unshare-all includes it.
    "--unshare-user",
    "--new-session",
    "--die-with-parent",
    "--clearenv",
    "--disable-userns",
    "--assert-userns-disabled",
    "--cap-drop",
    "ALL",
    "--hostname",
    "decomp-acp",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--tmpfs",
    "/tmp",
    "--chmod",
    "1777",
    "/tmp",
)

/**
 * One-way authorization commit. Once a write is attempted, IOException cannot distinguish
 * "not delivered" from "delivered and peer closed", so it must not be reported as a denied
 * launch. The contained process exit/transport result is the only post-commit outcome.
 */
internal fun commitSandboxAuthorization(output: OutputStream) {
    try {
        output.write(START_GATE_RELEASE_BYTE)
        output.flush()
    } catch (_: IOException) {
        // Outcome is intentionally nonthrowing after the one-byte commit attempt.
    }
}

private fun linuxDeviceMajor(device: Long): Long =
    (device ushr 8 and 0xfffL) or (device ushr 32 and 0xfffff000L)

private fun linuxDeviceMinor(device: Long): Long =
    (device and 0xffL) or (device ushr 12 and 0xffffff00L)

private fun isBlockedRead(syscallRecord: String, descriptor: Int): Boolean {
    val fields = syscallRecord.split(Regex("\\s+"))
    if (fields.size < 4) return false
    val expectedRead = when (System.getProperty("os.arch", "")) {
        "amd64", "x86_64" -> 0L
        "aarch64" -> 63L
        else -> return false
    }
    return parseProcNumber(fields[0]) == expectedRead &&
        parseProcNumber(fields[1]) == descriptor.toLong() &&
        parseProcNumber(fields[3]) == 1L
}

private fun parseProcNumber(value: String): Long? = when {
    value.startsWith("0x") -> value.removePrefix("0x").toLongOrNull(16)
    else -> value.toLongOrNull()
}

private fun controlGroupPathForCleanup(controlGroup: String): Path {
    val relative = try {
        Path.of(controlGroup)
    } catch (failure: RuntimeException) {
        throw IOException("systemd returned an invalid cgroup path", failure)
    }
    if (!controlGroup.startsWith('/') || relative.any { it.toString() == ".." }) {
        throw IOException("systemd returned an invalid cgroup path")
    }
    val path = CGROUP_ROOT.resolve(controlGroup.removePrefix("/")).normalize()
    if (!path.startsWith(CGROUP_ROOT) || path == CGROUP_ROOT) {
        throw IOException("systemd returned an unsafe cgroup path")
    }
    return path
}

/**
 * Exhaustively proves that no cgroup-v2 directory retains the random transient-unit name.
 *
 * This is used only when cancellation wins before systemd publishes ControlGroup. The walk never
 * supplies a path to a signal operation: a match merely prevents an absence proof. Aggregate
 * entry/depth caps make a hostile or unexpectedly large hierarchy fail closed.
 */
private fun findCgroupDirectoriesForUnit(unitName: String): List<Path> {
    require(unitName.matches(Regex("decomp-acp-[0-9a-f-]+\\.scope"))) {
        "sandbox scope unit name is not safe for cgroup absence verification"
    }
    val matches = mutableListOf<Path>()
    val pending = ArrayDeque<Pair<Path, Int>>()
    pending.add(CGROUP_ROOT to 0)
    var entries = 0
    while (pending.isNotEmpty()) {
        val (directory, depth) = pending.removeFirst()
        Files.newDirectoryStream(directory).use { children ->
            for (child in children) {
                entries = Math.addExact(entries, 1)
                if (entries > MAXIMUM_CGROUP_CLEANUP_SEARCH_ENTRIES) {
                    throw IOException("cgroup search exceeds its aggregate entry limit")
                }
                if (!Files.isDirectory(child, LinkOption.NOFOLLOW_LINKS)) continue
                val normalized = child.toAbsolutePath().normalize()
                if (!normalized.startsWith(CGROUP_ROOT)) {
                    throw IOException("cgroup search escaped the cgroup-v2 root")
                }
                if (normalized.fileName?.toString() == unitName) matches.add(normalized)
                if (depth >= MAXIMUM_CGROUP_CLEANUP_SEARCH_DEPTH) {
                    Files.newDirectoryStream(normalized).use { descendants ->
                        if (descendants.any { Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) }) {
                            throw IOException("cgroup search exceeds its depth limit")
                        }
                    }
                } else {
                    pending.add(normalized to depth + 1)
                }
            }
        }
    }
    return matches
}

internal class PinnedSystemdBusEndpoint private constructor(
    val controlEnvironment: Map<String, String>,
    private val runtimeDirectory: Path,
    private val runtimeIdentity: PinnedFileIdentity,
    private val busPath: Path,
    private val busIdentity: PinnedFileIdentity,
) {
    fun requireUnchanged(cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT) {
        cancellationCheck()
        if (readIdentity(runtimeDirectory, cancellationCheck) != runtimeIdentity ||
            readIdentity(busPath, cancellationCheck) != busIdentity
        ) {
            throw IOException("systemd user bus endpoint changed")
        }
    }

    companion object {
        fun pin(
            runtimeDirectory: Path,
            cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
        ): PinnedSystemdBusEndpoint {
            cancellationCheck()
            val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
            val runtime = readIdentity(runtimeDirectory, cancellationCheck)
            if (!Files.isDirectory(runtimeDirectory, LinkOption.NOFOLLOW_LINKS) ||
                runtime.uid != uid || runtime.mode.permissions != 0x1c0
            ) throw IOException("systemd user runtime directory must be a real mode-0700 directory owned by this user")
            val busPath = runtimeDirectory.resolve("bus")
            val bus = readIdentity(busPath, cancellationCheck)
            val basic = Files.readAttributes(busPath, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            if (!basic.isOther || bus.uid != uid) throw IOException("systemd user bus must be this user's Unix socket")
            return PinnedSystemdBusEndpoint(
                mapOf(
                    "XDG_RUNTIME_DIR" to runtimeDirectory.toString(),
                    "DBUS_SESSION_BUS_ADDRESS" to "unix:path=$busPath",
                ),
                runtimeDirectory,
                runtime,
                busPath,
                bus,
            )
        }
    }
}

internal data class PinnedFileIdentity(
    val device: Long,
    val inode: Long,
    val mountId: Long,
    val mode: Int,
    val uid: Int,
    val size: Long,
    val modifiedMillis: Long,
    val metadataSha256: String,
)

internal class PinnedSecurityExecutable private constructor(
    val path: Path,
    val sha256: String,
    val mode: Int,
    val identity: PinnedFileIdentity,
) {
    fun evidence(role: String): AcpSecurityExecutableEvidence = AcpSecurityExecutableEvidence(
        role = role,
        canonicalPathSha256 = sha256(path.toString()),
        contentSha256 = sha256,
        mode = mode,
        metadataSha256 = identity.metadataSha256,
    )

    fun requireUnchanged(cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT) {
        val current = pinExecutable(path, cancellationCheck)
        if (current.first != identity || current.second != sha256) {
            throw IOException("verified security executable changed: $path")
        }
    }

    companion object {
        fun pin(
            path: Path,
            label: String,
            expectedSha256: String,
            cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
        ): PinnedSecurityExecutable {
            val (identity, digest) = pinExecutable(path, cancellationCheck)
            if (digest != expectedSha256) {
                throw IOException("configured $label digest does not match the expected SHA-256")
            }
            return PinnedSecurityExecutable(path, digest, identity.mode, identity)
        }
    }
}

private data class ForbiddenRuntimeFile(
    val device: Long,
    val inode: Long,
    val size: Long,
    val sha256: String,
)

private data class RuntimeManifest(
    val rootIdentity: PinnedFileIdentity,
    val manifestSha256: String,
    val recursivelyRootOwnedAndImmutable: Boolean,
    val rootDirectory: Boolean,
)

private class PinnedReadOnlyMount private constructor(
    val mount: AcpSandboxReadOnlyMount,
    private val manifest: RuntimeManifest,
    private val limits: AcpRuntimeClosureLimits,
    private val forbidden: Set<ForbiddenRuntimeFile>,
    private val verificationSource: Path,
    private val sourceDescriptor: LinuxDescriptor,
    private val snapshotContainer: PinnedPrivateTree?,
    private val descriptorSha256: String?,
) {
    private var mountedSnapshotUnlinked = false
    val expectedIdentity: PinnedFileIdentity get() = manifest.rootIdentity
    fun evidence(): AcpSandboxMountEvidence = AcpSandboxMountEvidence(
        sourcePathSha256 = sha256(mount.source.toString()),
        destinationPathSha256 = sha256(mount.destination.toString()),
        manifestSha256 = manifest.manifestSha256,
        device = manifest.rootIdentity.device,
        inode = manifest.rootIdentity.inode,
        mode = manifest.rootIdentity.mode,
        directory = manifest.rootDirectory,
    )
    /**
     * Root-owned closures are immutable; user-owned closures are mounted only from their private,
     * non-writable snapshot. The open descriptor remains the identity anchor for revalidation.
     * Cross-process /proc fd paths are deliberately not used: bwrap's user namespace may deny
     * those paths, and a failure must never be mistaken for a verified launch.
     */
    val effectiveSource: Path = verificationSource

    val expectedLinkCount: Int
        get() = if (mountedSnapshotUnlinked) 0 else sourceDescriptor.identity.linkCount

    fun setupAttestation(): AcpSetupFileAttestation = AcpSetupFileAttestation(
        destination = mount.destination,
        device = expectedIdentity.device,
        inode = expectedIdentity.inode,
        expectedLinkCount = expectedLinkCount,
    )

    fun requireUnchanged(cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT) {
        cancellationCheck()
        val current = LinuxFilesystemSyscalls.identity(sourceDescriptor.fd)
        if (current.key.device != manifest.rootIdentity.device ||
            current.key.inode != manifest.rootIdentity.inode ||
            current.mountId != manifest.rootIdentity.mountId ||
            current.mode != manifest.rootIdentity.mode ||
            current.uid != manifest.rootIdentity.uid ||
            current.isRegularFile == manifest.rootDirectory ||
            current.isDirectory != manifest.rootDirectory || current.isSymbolicLink ||
            (mountedSnapshotUnlinked && current.linkCount != 0)
        ) throw IOException("pinned sandbox runtime descriptor changed")
        if (mountedSnapshotUnlinked) {
            val expectedDigest = descriptorSha256
                ?: throw IOException("sealed runtime snapshot lacks a pinned content digest")
            if (sha256(sourceDescriptor, limits.maximumUserOwnedFileBytes, cancellationCheck) != expectedDigest) {
                throw IOException("sealed runtime snapshot bytes changed")
            }
            return
        }
        if (manifest.recursivelyRootOwnedAndImmutable) {
            if (readIdentity(verificationSource, cancellationCheck) != manifest.rootIdentity) {
                throw IOException("root-owned runtime closure root changed: ${mount.destination}")
            }
        } else if (buildRuntimeManifest(
                verificationSource,
                limits,
                forbidden,
                allowPrivateControlSource = snapshotContainer != null,
                cancellationCheck = cancellationCheck,
            ) != manifest
        ) {
            throw IOException("authenticated runtime closure changed: ${mount.destination}")
        }
    }

    fun requireStaticGateHelper(
        expectedSha256: String,
        cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
    ) {
        if (manifest.rootDirectory) throw IOException("sandbox gate helper must be one regular file")
        val bytes = readPinnedBytes(sourceDescriptor, MAXIMUM_GATE_HELPER_BYTES, cancellationCheck)
        verifyStaticSandboxGateHelper(
            bytes,
            expectedSha256,
            manifest.rootIdentity.mode,
            cancellationCheck,
        )
    }

    fun requireNativeExecveatTarget(cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT) {
        if (manifest.rootDirectory) throw IOException("sandbox command executable must be one regular file")
        cancellationCheck()
        val prefix = readPinnedPrefix(sourceDescriptor, 4)
        if (!prefix.contentEquals(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))) {
            throw IOException(
                "sandbox command executable must be a native ELF file; scripts require an explicitly " +
                    "authenticated interpreter executable with the script passed as data argv",
            )
        }
    }

    @Synchronized
    fun sealMountedSingleFileSnapshot(
        cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
    ) {
        if (snapshotContainer == null || mountedSnapshotUnlinked) {
            requireUnchanged(cancellationCheck)
            return
        }
        if (manifest.rootDirectory) {
            throw IOException("a directory runtime snapshot cannot be anonymously sealed")
        }
        snapshotContainer.unlinkExactRoot(sourceDescriptor)
        mountedSnapshotUnlinked = true
        requireUnchanged(cancellationCheck)
    }

    fun deleteSnapshot() {
        val failures = mutableListOf<Throwable>()
        runCatching { sourceDescriptor.close() }.exceptionOrNull()?.let(failures::add)
        snapshotContainer?.let { container ->
            runCatching { container.deleteAndProve() }.exceptionOrNull()?.let(failures::add)
        }
        if (failures.isNotEmpty()) {
            val primary = AcpCleanupProofFailure("pinned sandbox runtime cleanup failed", failures.first())
            failures.drop(1).forEach(primary::addSuppressed)
            throw primary
        }
    }

    companion object {
        fun pin(
            mount: AcpSandboxReadOnlyMount,
            limits: AcpRuntimeClosureLimits,
            forbidden: Set<ForbiddenRuntimeFile>,
            controlDirectory: PinnedControlDirectory,
            allowUserOwnedSnapshot: Boolean,
            cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
        ): PinnedReadOnlyMount {
            cancellationCheck()
            val configuredManifest = buildRuntimeManifest(
                mount.source,
                limits,
                forbidden,
                cancellationCheck = cancellationCheck,
            )
            if (configuredManifest.recursivelyRootOwnedAndImmutable) {
                requireCanonicalRootOwnedPath(mount.source, cancellationCheck)
                mount.expectedManifestSha256?.let { expected ->
                    if (expected != configuredManifest.manifestSha256) {
                        throw IOException("root-owned runtime manifest does not match its expected SHA-256")
                    }
                }
                val descriptor = requirePinnedDescriptor(mount.source, configuredManifest.rootIdentity)
                return PinnedReadOnlyMount(
                    mount,
                    configuredManifest,
                    limits,
                    forbidden,
                    mount.source,
                    descriptor,
                    snapshotContainer = null,
                    descriptorSha256 = null,
                )
            }
            if (!allowUserOwnedSnapshot) {
                throw IOException("security launcher runtime must be recursively root-owned and immutable")
            }
            val expected = mount.expectedManifestSha256
                ?: throw IOException("user-owned runtime mount requires an expected manifest SHA-256")
            val snapshot = stagePrivateRuntimeSnapshot(
                mount.source,
                limits,
                controlDirectory,
                cancellationCheck,
            )
            try {
                val copiedManifest = buildRuntimeManifest(
                    snapshot.source,
                    limits,
                    forbidden,
                    allowPrivateControlSource = true,
                    cancellationCheck = cancellationCheck,
                )
                if (copiedManifest.manifestSha256 != expected) {
                    throw IOException("user-owned runtime snapshot does not match its expected SHA-256")
                }
                hardenPrivateSnapshot(snapshot.container, cancellationCheck)
                val hardenedManifest = buildRuntimeManifest(
                    snapshot.source,
                    limits,
                    forbidden,
                    allowPrivateControlSource = true,
                    cancellationCheck = cancellationCheck,
                )
                val descriptor = requirePinnedDescriptor(snapshot.source, hardenedManifest.rootIdentity)
                val descriptorDigest = if (hardenedManifest.rootDirectory) null else {
                    sha256(descriptor, limits.maximumUserOwnedFileBytes, cancellationCheck)
                }
                return PinnedReadOnlyMount(
                    mount,
                    hardenedManifest,
                    limits,
                    forbidden,
                    snapshot.source,
                    descriptor,
                    snapshot.container,
                    descriptorDigest,
                )
            } catch (failure: Throwable) {
                val cleanupFailure = runCatching { snapshot.container.deleteAndProve() }.exceptionOrNull()
                if (cleanupFailure != null) {
                    throw AcpCleanupProofFailure(
                        "sandbox runtime snapshot validation failed and cleanup was not proven",
                        cleanupFailure,
                    ).also { it.addSuppressed(failure) }
                }
                throw failure
            }
        }
    }
}

private data class SandboxVisibleMount(
    val mountId: Long,
    val mountPoint: Path,
    val options: Set<String>,
)

private fun requireSandboxVisibleBindings(
    waiterPid: Long,
    runtimeMounts: Collection<PinnedReadOnlyMount>,
    stagingRoots: Collection<AcpSandboxRootGrant>,
    environmentFile: SandboxEnvironmentFile,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
) {
    cancellationCheck()
    val processRoot = Path.of("/proc", waiterPid.toString(), "root")
    if (!Files.exists(processRoot)) throw IOException("sandbox waiter root disappeared before bind attestation")
    val mounts = readSandboxMountInfo(waiterPid, cancellationCheck)
    runtimeMounts.forEach { pinned ->
        cancellationCheck()
        requireSandboxVisibleBindIdentity(
            processRoot,
            mounts,
            pinned.mount.destination,
            pinned.expectedIdentity.device,
            pinned.expectedIdentity.inode,
            pinned.expectedIdentity.mode,
            readOnly = true,
        )
    }
    stagingRoots.forEach { grant ->
        cancellationCheck()
        val expected = grant.stagingRoot.identity
        requireSandboxVisibleBindIdentity(
            processRoot,
            mounts,
            grant.sandboxPath,
            expected.key.device,
            expected.key.inode,
            expected.mode,
            readOnly = grant.mode == AcpSandboxRootMode.READ_ONLY,
        )
    }
    environmentFile.requireCurrentIdentity(cancellationCheck)
    cancellationCheck()
    requireSandboxVisibleBindIdentity(
        processRoot,
        mounts,
        environmentFile.sandboxPath,
        environmentFile.identity.key.device,
        environmentFile.identity.key.inode,
        environmentFile.identity.mode,
        readOnly = true,
    )
    cancellationCheck()
}

private fun requireSandboxVisibleBindIdentity(
    processRoot: Path,
    mounts: List<SandboxVisibleMount>,
    destination: Path,
    expectedDevice: Long,
    expectedInode: Long,
    expectedMode: Int,
    readOnly: Boolean,
) {
    val record = mounts.singleOrNull { it.mountPoint == destination }
        ?: throw IOException("sandbox bind destination is absent or ambiguous: $destination")
    val expectedOption = if (readOnly) "ro" else "rw"
    if (expectedOption !in record.options || (if (readOnly) "rw" else "ro") in record.options) {
        throw IOException("sandbox bind mode does not match policy: $destination")
    }
    val relative = destination.toString().removePrefix("/")
    val visiblePath = if (relative.isEmpty()) processRoot else processRoot.resolve(relative)
    val basic = Files.readAttributes(
        visiblePath,
        BasicFileAttributes::class.java,
        LinkOption.NOFOLLOW_LINKS,
    )
    if (basic.isSymbolicLink || (!basic.isDirectory && !basic.isRegularFile)) {
        throw IOException("sandbox bind target has an unexpected file type: $destination")
    }
    val unix = Files.readAttributes(
        visiblePath,
        "unix:dev,ino,mode",
        LinkOption.NOFOLLOW_LINKS,
    )
    val actualDevice = (unix.getValue("dev") as Number).toLong()
    val actualInode = (unix.getValue("ino") as Number).toLong()
    val actualMode = (unix.getValue("mode") as Number).toInt()
    if (actualDevice != expectedDevice || actualInode != expectedInode || actualMode != expectedMode) {
        throw IOException("sandbox-visible bind identity does not match its pinned host identity: $destination")
    }
}

private fun readSandboxMountInfo(
    waiterPid: Long,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): List<SandboxVisibleMount> =
    readBoundedProcLines(
        Path.of("/proc", waiterPid.toString(), "mountinfo"),
        MAXIMUM_PROC_MOUNTINFO_BYTES,
        MAXIMUM_PROC_MOUNTINFO_LINES,
        cancellationCheck,
    ).map { line ->
        cancellationCheck()
        val separator = line.indexOf(" - ")
        if (separator <= 0) throw IOException("sandbox mountinfo contains a malformed record")
        val left = line.substring(0, separator).split(' ')
        if (left.size < 6) throw IOException("sandbox mountinfo record is incomplete")
        val mountPoint = decodeMountInfoPath(left[4])
        if (!mountPoint.isAbsolute || mountPoint != mountPoint.normalize()) {
            throw IOException("sandbox mountinfo contains an unsafe mountpoint")
        }
        val mountId = left[0].toLongOrNull()
            ?: throw IOException("sandbox mountinfo mount identity is invalid")
        SandboxVisibleMount(mountId, mountPoint, left[5].split(',').filter(String::isNotBlank).toSet())
    }

private fun readBoundedProcLines(
    path: Path,
    maximumBytes: Int,
    maximumLines: Int,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): List<String> {
    val text = readBoundedProcBytes(path, maximumBytes, cancellationCheck).toString(Charsets.UTF_8)
    cancellationCheck()
    val lines = text.lineSequence().filter(String::isNotEmpty).take(maximumLines + 1).toList()
    if (lines.size > maximumLines) throw IOException("proc metadata has too many records: $path")
    return lines
}

private fun readBoundedProcBytes(
    path: Path,
    maximumBytes: Int,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): ByteArray {
    require(maximumBytes > 0) { "proc metadata byte limit must be positive" }
    cancellationCheck()
    val content = Files.newInputStream(path).use { input ->
        val output = ByteArrayOutputStream(minOf(maximumBytes + 1, 8192))
        val buffer = ByteArray(8192)
        while (output.size() <= maximumBytes) {
            cancellationCheck()
            val count = input.read(buffer, 0, minOf(buffer.size, maximumBytes + 1 - output.size()))
            if (count < 0) break
            output.write(buffer, 0, count)
        }
        output.toByteArray()
    }
    if (content.size > maximumBytes) throw IOException("proc metadata exceeds its byte limit: $path")
    cancellationCheck()
    return content
}

private fun decodeMountInfoPath(encoded: String): Path {
    val decoded = StringBuilder(encoded.length)
    var index = 0
    while (index < encoded.length) {
        val current = encoded[index]
        if (current != '\\') {
            decoded.append(current)
            index++
            continue
        }
        if (index + 3 >= encoded.length) throw IOException("sandbox mountinfo contains a truncated escape")
        val escape = encoded.substring(index + 1, index + 4)
        val value = when (escape) {
            "040" -> ' '
            "011" -> '\t'
            "012" -> '\n'
            "134" -> '\\'
            else -> throw IOException("sandbox mountinfo contains an unsupported escape")
        }
        decoded.append(value)
        index += 4
    }
    return try {
        Path.of(decoded.toString())
    } catch (failure: RuntimeException) {
        throw IOException("sandbox mountinfo contains an invalid mountpoint", failure)
    }
}

/** All policy-controlled strings that can carry raw bytes into a terminal sandbox. */
private fun terminalAuthorityStrings(
    rule: AcpTerminalCommandRule,
    stagingRoots: Collection<AcpSandboxRootGrant>,
): Sequence<String> = sequence {
    yield(rule.command)
    yieldAll(rule.arguments)
    yield(rule.workingDirectory.toString())
    rule.environment.toSortedMap().forEach { (name, value) ->
        yield(name)
        yield(value)
    }
    (listOf(rule.executable) + rule.runtimeMounts).forEach { mount ->
        yield(mount.source.toString())
        yield(mount.destination.toString())
        mount.expectedManifestSha256?.let { yield(it) }
    }
    stagingRoots.forEach { grant ->
        yield(grant.stagingRoot.rootId)
        yield(grant.stagingRoot.path.toString())
        yield(grant.sandboxPath.toString())
    }
}

private fun buildRuntimeManifest(
    source: Path,
    limits: AcpRuntimeClosureLimits,
    forbidden: Set<ForbiddenRuntimeFile>,
    allowPrivateControlSource: Boolean = false,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): RuntimeManifest {
    cancellationCheck()
    val basic = Files.readAttributes(source, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    if (basic.isSymbolicLink || (!basic.isRegularFile && !basic.isDirectory)) {
        throw IOException("sandbox runtime source must be a real file or directory: $source")
    }
    if (!allowPrivateControlSource && basic.isDirectory &&
        (source in BROAD_RUNTIME_DIRECTORY_ROOTS || source.parent in BROAD_RUNTIME_DIRECTORY_PARENTS)
    ) {
        throw IOException("sandbox runtime may not expose a broad host data directory: $source")
    }
    val paths = if (basic.isDirectory) {
        Files.walk(source, limits.maximumDepth).use { stream ->
            stream.peek { cancellationCheck() }.limit(limits.maximumEntries.toLong() + 1L).toList()
        }.also {
            if (it.size > limits.maximumEntries) throw IOException("sandbox runtime closure has too many entries")
            it.filter { path ->
                Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) &&
                    source.relativize(path).nameCount == limits.maximumDepth
            }.forEach { boundaryDirectory ->
                cancellationCheck()
                Files.newDirectoryStream(boundaryDirectory).use { children ->
                    if (children.iterator().hasNext()) {
                        throw IOException("sandbox runtime closure exceeds its authenticated depth limit")
                    }
                }
            }
        }.sortedBy { source.relativize(it).toString() }
    } else listOf(source)
    val entries = paths.map { path ->
        cancellationCheck()
        Triple(
            path,
            readIdentity(path, cancellationCheck),
            Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS),
        )
    }
    val rootMountId = entries.first().second.mountId
    if (entries.any { (_, identity, _) -> identity.mountId != rootMountId }) {
        throw IOException("sandbox runtime closure crosses a mount boundary")
    }
    val rootOwned = entries.all { (path, identity, entryBasic) ->
        cancellationCheck()
        identity.uid == 0 &&
            (entryBasic.isSymbolicLink || identity.mode.permissions and 0x12 == 0) &&
            !Files.isWritable(path) &&
            hasSafeSandboxTrustExtendedAttributes(path, identity, cancellationCheck)
    }
    var userBytes = 0L
    val digest = MessageDigest.getInstance("SHA-256")
    entries.forEach { (path, identity, entryBasic) ->
        cancellationCheck()
        val type = when {
            entryBasic.isRegularFile -> "file"
            entryBasic.isDirectory -> "directory"
            entryBasic.isSymbolicLink -> throw IOException(
                "sandbox runtime closure contains a symbolic link; mount canonical targets explicitly",
            )
            else -> throw IOException("sandbox runtime closure contains a special filesystem entry")
        }
        val relative = if (path == source) "." else source.relativize(path).toString()
        digest.update(
            (
                "$relative\u0000$type\u0000${identity.mode.permissions}\u0000${identity.uid}\u0000" +
                    "${identity.size}\u0000${identity.metadataSha256}\u0000"
                ).toByteArray(),
        )
        if (entryBasic.isRegularFile) {
            val candidateForbidden = forbidden.filter { it.size == identity.size }
            val mustHash = !rootOwned || candidateForbidden.isNotEmpty()
            if (!rootOwned) {
                userBytes = Math.addExact(userBytes, identity.size)
                if (userBytes > limits.maximumUserOwnedFileBytes) {
                    throw IOException("user-owned sandbox runtime closure exceeds its authenticated byte limit")
                }
            }
            if (mustHash) {
                val fileDigest = sha256(path, cancellationCheck)
                digest.update(fileDigest.toByteArray())
                if (candidateForbidden.any { forbiddenFile ->
                    (forbiddenFile.device == identity.device && forbiddenFile.inode == identity.inode) ||
                        forbiddenFile.sha256 == fileDigest
                }) throw IOException("sandbox runtime closure exposes a security-boundary executable")
            }
        }
    }
    cancellationCheck()
    return RuntimeManifest(
        readIdentity(source, cancellationCheck),
        digest.digest().toHex(),
        rootOwned,
        basic.isDirectory,
    )
}

/**
 * Computes the versioned runtime manifest digest to pin in configuration. Call this during trusted
 * provisioning, persist the result, and never recompute it from an untrusted launch-time tree.
 */
fun calculateAcpRuntimeManifestSha256(
    source: Path,
    limits: AcpRuntimeClosureLimits = AcpRuntimeClosureLimits(),
): String {
    LinuxFilesystemSyscalls.requireSupported(source)
    return buildRuntimeManifest(source, limits, emptySet()).manifestSha256
}

private fun pinMounts(
    mounts: Collection<AcpSandboxReadOnlyMount>,
    limits: AcpRuntimeClosureLimits,
    forbidden: Set<ForbiddenRuntimeFile>,
    controlDirectory: PinnedControlDirectory,
    allowUserOwnedSnapshot: Boolean = true,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): List<PinnedReadOnlyMount> {
    cancellationCheck()
    if (mounts.size > MAXIMUM_SANDBOX_MOUNTS + 1) {
        throw IOException("sandbox runtime mounts exceed the authenticated count limit")
    }
    val unique = LinkedHashMap<Path, AcpSandboxReadOnlyMount>()
    mounts.forEach { mount ->
        cancellationCheck()
        val existing = unique.putIfAbsent(mount.destination, mount)
        if (existing != null && (
                existing.source != mount.source ||
                    existing.expectedManifestSha256 != mount.expectedManifestSha256
                )
        ) {
            throw IOException("conflicting sandbox runtime mount: ${mount.destination}")
        }
    }
    val pinned = mutableListOf<PinnedReadOnlyMount>()
    try {
        unique.values.forEach { mount ->
            cancellationCheck()
            pinned += PinnedReadOnlyMount.pin(
                mount,
                limits,
                forbidden,
                controlDirectory,
                allowUserOwnedSnapshot,
                cancellationCheck,
            )
        }
        return pinned
    } catch (failure: Throwable) {
        val cleanupFailures = pinned.mapNotNull { mount ->
            runCatching { mount.deleteSnapshot() }.exceptionOrNull()
        }
        if (cleanupFailures.isNotEmpty()) {
            val cleanup = AcpCleanupProofFailure(
                "sandbox runtime pinning failed and partial snapshot cleanup was not proven",
                cleanupFailures.first(),
            )
            cleanupFailures.drop(1).forEach(cleanup::addSuppressed)
            cleanup.addSuppressed(failure)
            throw cleanup
        }
        throw failure
    }
}

private fun deletePinnedMounts(mounts: Collection<PinnedReadOnlyMount>) {
    val failures = mutableListOf<Throwable>()
    mounts.forEach { mount ->
        try {
            mount.deleteSnapshot()
        } catch (failure: Throwable) {
            failures += failure
        }
    }
    if (failures.isNotEmpty()) {
        val primary = AcpCleanupProofFailure(
            "sandbox runtime descriptor/snapshot cleanup failed",
            failures.first(),
        )
        failures.drop(1).forEach(primary::addSuppressed)
        throw primary
    }
}

private inline fun runCleanupStep(
    failures: MutableList<Throwable>,
    stage: AcpSandboxCleanupStage,
    hook: AcpSandboxCleanupHook?,
    action: () -> Unit,
): Boolean {
    try {
        hook?.at(stage)
    } catch (failure: Throwable) {
        failures += failure
    }
    try {
        action()
        return true
    } catch (failure: Throwable) {
        failures += failure
        return false
    }
}

private data class PrivateRuntimeSnapshot(val container: PinnedPrivateTree, val source: Path)

private data class RuntimeSnapshotBudget(
    var entries: Int = 0,
    var bytes: Long = 0,
)

private fun stagePrivateRuntimeSnapshot(
    source: Path,
    limits: AcpRuntimeClosureLimits,
    controlDirectory: PinnedControlDirectory,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): PrivateRuntimeSnapshot {
    cancellationCheck()
    val container = controlDirectory.createChild("runtime-")
    val destination = container.path.resolve("root")
    try {
        LinuxFilesystemSyscalls.chmod(container.requireRootDirectory(), CONTROL_DIRECTORY_MODE)
        val root = LinuxFilesystemSyscalls.openAbsolutePathOrNull(source)
            ?: throw IOException("sandbox runtime source disappeared")
        root.use {
            val budget = RuntimeSnapshotBudget()
            copyRuntimeNode(
                descriptor = root,
                destinationParent = container.requireRootDirectory(),
                destinationName = "root",
                rootMountId = root.identity.mountId,
                depth = 0,
                limits = limits,
                budget = budget,
                cancellationCheck = cancellationCheck,
            )
        }
        return PrivateRuntimeSnapshot(container, destination)
    } catch (failure: Throwable) {
        val cleanupFailure = runCatching { container.deleteAndProve() }.exceptionOrNull()
        if (cleanupFailure != null) {
            throw AcpCleanupProofFailure(
                "sandbox runtime snapshot copy failed and cleanup was not proven",
                cleanupFailure,
            ).also { it.addSuppressed(failure) }
        }
        throw failure
    }
}

private fun copyRuntimeNode(
    descriptor: LinuxDescriptor,
    destinationParent: LinuxDescriptor,
    destinationName: String,
    rootMountId: Long,
    depth: Int,
    limits: AcpRuntimeClosureLimits,
    budget: RuntimeSnapshotBudget,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
) {
    cancellationCheck()
    if (descriptor.identity.mountId != rootMountId) {
        throw IOException("sandbox runtime snapshot crosses a mount boundary")
    }
    budget.entries = Math.addExact(budget.entries, 1)
    if (budget.entries > limits.maximumEntries) {
        throw IOException("sandbox runtime snapshot has too many entries")
    }
    when {
        descriptor.identity.isDirectory -> {
            LinuxFilesystemSyscalls.createDirectory(destinationParent.fd, destinationName, CONTROL_DIRECTORY_MODE)
            val destination = LinuxFilesystemSyscalls.openDirectoryAt(destinationParent.fd, destinationName)
            val names = LinuxFilesystemSyscalls.directoryEntryNames(
                descriptor,
                limits.maximumEntries,
                cancellationCheck,
            ).sorted()
            if (names.isNotEmpty() && depth >= limits.maximumDepth) {
                destination.close()
                throw IOException("sandbox runtime snapshot exceeds its depth limit")
            }
            destination.use { targetDirectory ->
                names.forEach { name ->
                    cancellationCheck()
                    val child = LinuxFilesystemSyscalls.openPathAtOrNull(descriptor.fd, name)
                        ?: throw IOException("sandbox runtime entry disappeared while being snapshotted")
                    child.use {
                        if (child.identity.isSymbolicLink ||
                            (!child.identity.isDirectory && !child.identity.isRegularFile)
                        ) throw IOException("sandbox runtime snapshot contains a link or special entry")
                        copyRuntimeNode(
                            child,
                            targetDirectory,
                            name,
                            rootMountId,
                            depth + 1,
                            limits,
                            budget,
                            cancellationCheck,
                        )
                    }
                }
                LinuxFilesystemSyscalls.chmod(targetDirectory, descriptor.identity.mode.permissions)
            }
        }
        descriptor.identity.isRegularFile -> {
            val remaining = limits.maximumUserOwnedFileBytes - budget.bytes
            if (remaining < 0) throw IOException("sandbox runtime snapshot exceeds its byte limit")
            LinuxFilesystemSyscalls.createRegularFile(
                destinationParent.fd,
                destinationName,
                SANDBOX_ENVIRONMENT_FILE_MODE,
            ).use { output ->
                budget.bytes = Math.addExact(
                    budget.bytes,
                    LinuxFilesystemSyscalls.copyReadableTo(
                        descriptor,
                        output,
                        remaining,
                        cancellationCheck,
                    ),
                )
                LinuxFilesystemSyscalls.chmod(output, descriptor.identity.mode.permissions)
            }
        }
        else -> throw IOException("sandbox runtime snapshot source is not a regular file or directory")
    }
}

private fun hardenPrivateSnapshot(
    container: PinnedPrivateTree,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
) {
    cancellationCheck()
    val outer = container.requireRootDirectory()
    requireDirectoryDescriptorIdentity(
        outer,
        outer.identity.key,
        outer.identity.mountId,
        CONTROL_DIRECTORY_MODE,
    )
    LinuxFilesystemSyscalls.openPathAtOrNull(outer.fd, "root").use { mountedRoot ->
        if (mountedRoot == null || mountedRoot.identity.isSymbolicLink ||
            (!mountedRoot.identity.isDirectory && !mountedRoot.identity.isRegularFile)
        ) throw IOException("private runtime snapshot root disappeared while hardening")
        hardenPrivateSnapshotNode(mountedRoot, cancellationCheck)
    }
    // The mounted subtree is immutable, while its identity-pinned outer directory deliberately
    // remains owner-only writable for descriptor-relative quarantine/unlink during cleanup.
    requireDirectoryDescriptorIdentity(
        outer,
        outer.identity.key,
        outer.identity.mountId,
        CONTROL_DIRECTORY_MODE,
    )
}

private fun hardenPrivateSnapshotNode(
    descriptor: LinuxDescriptor,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
) {
    cancellationCheck()
    if (descriptor.identity.isDirectory) {
        LinuxFilesystemSyscalls.directoryEntryNames(
            descriptor,
            cancellationCheck = cancellationCheck,
        ).sorted().forEach { name ->
            val child = LinuxFilesystemSyscalls.openPathAtOrNull(descriptor.fd, name)
                ?: throw IOException("private runtime snapshot entry disappeared while hardening")
            child.use { hardenPrivateSnapshotNode(it, cancellationCheck) }
        }
    }
    val withoutWrite = descriptor.identity.mode.permissions and 0x92.inv()
    val requiredOwner = if (descriptor.identity.isDirectory) 0x140 else 0x100
    LinuxFilesystemSyscalls.chmodPinned(descriptor, withoutWrite or requiredOwner)
}

private fun requirePinnedDescriptor(source: Path, expected: PinnedFileIdentity): LinuxDescriptor {
    val descriptor = LinuxFilesystemSyscalls.openAbsolutePathOrNull(source)
        ?: throw IOException("sandbox runtime source disappeared before descriptor pinning")
    if (descriptor.identity.key.device != expected.device ||
        descriptor.identity.key.inode != expected.inode ||
        descriptor.identity.mountId != expected.mountId
    ) {
        descriptor.close()
        throw IOException("sandbox runtime source changed before descriptor pinning")
    }
    return descriptor
}

private fun forbiddenRuntimeFiles(
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
    vararg mandatory: PinnedSecurityExecutable,
): Set<ForbiddenRuntimeFile> {
    val explicit = mandatory.map { executable ->
        cancellationCheck()
        ForbiddenRuntimeFile(
            executable.identity.device,
            executable.identity.inode,
            executable.identity.size,
            executable.sha256,
        )
    }
    val namespaceTools = NAMESPACE_TOOL_PATHS.mapNotNull { path ->
        cancellationCheck()
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return@mapNotNull null
        val real = path.toRealPath()
        val identity = readIdentity(real, cancellationCheck)
        ForbiddenRuntimeFile(
            identity.device,
            identity.inode,
            identity.size,
            sha256(real, cancellationCheck),
        )
    }
    return (explicit + namespaceTools).toSet()
}

private fun pinExecutable(
    path: Path,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): Pair<PinnedFileIdentity, String> {
    cancellationCheck()
    requireCanonicalRootOwnedPath(path, cancellationCheck)
    val basic = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    val identity = readIdentity(path, cancellationCheck)
    if (!basic.isRegularFile || basic.isSymbolicLink || !Files.isExecutable(path)) {
        throw IOException("security boundary path must be a real executable file: $path")
    }
    if (identity.uid != 0 || identity.mode.permissions and 0x12 != 0) {
        throw IOException("security boundary executable must be root-owned and not group/world writable: $path")
    }
    return identity to sha256(path, cancellationCheck)
}

private fun requireCanonicalRootOwnedPath(
    path: Path,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
) {
    cancellationCheck()
    val real = try {
        path.toRealPath()
    } catch (failure: IOException) {
        throw IOException("security boundary path cannot be resolved canonically: $path", failure)
    }
    if (real != path) throw IOException("security boundary path must be canonical and contain no symbolic links: $path")
    var current = path.root ?: throw IOException("security boundary path must be absolute: $path")
    val chain = buildList {
        add(current)
        path.forEach { component ->
            current = current.resolve(component)
            add(current)
        }
    }
    chain.forEach { ancestor ->
        cancellationCheck()
        val basic = Files.readAttributes(
            ancestor,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        if (basic.isSymbolicLink) {
            throw IOException("security boundary path contains a symbolic-link ancestor: $ancestor")
        }
        val identity = readIdentity(ancestor, cancellationCheck)
        if (identity.uid != 0 || identity.mode.permissions and 0x12 != 0) {
            throw IOException(
                "security boundary path ancestors must be root-owned and not group/world writable: $ancestor",
            )
        }
        if (Files.isWritable(ancestor)) {
            throw IOException("security boundary path is writable by the current process: $ancestor")
        }
        requireSafeSandboxTrustExtendedAttributes(ancestor)
    }
}

/**
 * Rejects metadata that can grant write or executable authority. Stable SELinux/SMACK labels and
 * ordinary root-owned user attributes are permitted, but [readIdentity] binds every name/value in
 * the pinned metadata digest so a later change invalidates the identity.
 */
internal fun requireSafeSandboxTrustExtendedAttributes(path: Path) {
    val descriptor = LinuxFilesystemSyscalls.openAbsolutePathOrNull(path)
        ?: throw IOException("trusted sandbox path disappeared while inspecting metadata: $path")
    descriptor.use {
        val unsafe = LinuxFilesystemSyscalls.extendedAttributeNames(descriptor)
            .firstOrNull(FORBIDDEN_SANDBOX_TRUST_XATTRS::contains)
        if (unsafe != null) {
            throw IOException("trusted sandbox path has authority-bearing extended metadata $unsafe: $path")
        }
    }
}

private fun hasSafeSandboxTrustExtendedAttributes(
    path: Path,
    expected: PinnedFileIdentity,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): Boolean {
    cancellationCheck()
    val descriptor = LinuxFilesystemSyscalls.openAbsolutePathOrNull(path)
        ?: throw IOException("sandbox runtime entry disappeared while inspecting metadata: $path")
    descriptor.use {
        if (descriptor.identity.key.device != expected.device ||
            descriptor.identity.key.inode != expected.inode ||
            descriptor.identity.mountId != expected.mountId
        ) throw IOException("sandbox runtime entry changed while inspecting metadata: $path")
        return LinuxFilesystemSyscalls.extendedAttributeNames(descriptor, cancellationCheck)
            .none(FORBIDDEN_SANDBOX_TRUST_XATTRS::contains)
    }
}

private fun readIdentity(
    path: Path,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): PinnedFileIdentity {
    cancellationCheck()
    val unix = Files.readAttributes(
        path,
        "unix:dev,ino,mode,uid,size,lastModifiedTime",
        LinkOption.NOFOLLOW_LINKS,
    )
    val descriptor = LinuxFilesystemSyscalls.openAbsolutePathOrNull(path)
        ?: throw IOException("sandbox boundary path disappeared: $path")
    descriptor.use {
        if (descriptor.identity.key.device != (unix.getValue("dev") as Number).toLong() ||
            descriptor.identity.key.inode != (unix.getValue("ino") as Number).toLong()
        ) throw IOException("sandbox boundary path changed while its identity was pinned: $path")
        return PinnedFileIdentity(
            device = descriptor.identity.key.device,
            inode = descriptor.identity.key.inode,
            mountId = descriptor.identity.mountId,
            mode = (unix.getValue("mode") as Number).toInt(),
            uid = (unix.getValue("uid") as Number).toInt(),
            size = (unix.getValue("size") as Number).toLong(),
            modifiedMillis = (unix.getValue("lastModifiedTime") as FileTime).toMillis(),
            metadataSha256 = sandboxMetadataSha256(descriptor, cancellationCheck),
        )
    }
}

private fun sandboxMetadataSha256(
    descriptor: LinuxDescriptor,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): String {
    val digest = MessageDigest.getInstance("SHA-256")
    LinuxFilesystemSyscalls.extendedAttributeNames(descriptor, cancellationCheck).sorted().forEach { name ->
        cancellationCheck()
        val value = LinuxFilesystemSyscalls.extendedAttributeValue(
            descriptor,
            name,
            cancellationCheck = cancellationCheck,
        )
        digest.update(name.length.toString().toByteArray(Charsets.UTF_8))
        digest.update(0.toByte())
        digest.update(name.toByteArray(Charsets.UTF_8))
        digest.update(0.toByte())
        digest.update(value.size.toString().toByteArray(Charsets.UTF_8))
        digest.update(0.toByte())
        digest.update(value)
        digest.update(0.toByte())
    }
    return digest.digest().toHex()
}

private fun probeBubblewrap(
    path: Path,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): String {
    val version = probe(path, listOf("--version"), "bubblewrap version", cancellationCheck).trim()
    val match = Regex("^bubblewrap ([0-9]+(?:\\.[0-9]+){1,2})$").matchEntire(version)
        ?: throw IOException("configured bubblewrap returned an unrecognized version")
    val help = probe(path, listOf("--help"), "bubblewrap features", cancellationCheck)
    REQUIRED_BUBBLEWRAP_OPTIONS.forEach { option ->
        if (option !in help) throw IOException("configured bubblewrap does not support required option $option")
    }
    return match.groupValues[1]
}

private fun probeResourceLimiter(
    path: Path,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
) {
    if (!probe(
            path,
            listOf("--version"),
            "resource limiter version",
            cancellationCheck,
        ).lineSequence().first().startsWith("prlimit from util-linux ")
    ) {
        throw IOException("configured resource limiter is not util-linux prlimit")
    }
    val help = probe(path, listOf("--help"), "resource limiter features", cancellationCheck)
    REQUIRED_PRLIMIT_OPTIONS.forEach { if (it !in help) throw IOException("resource limiter lacks $it") }
}

private fun verifyStaticSandboxGateHelper(
    bytes: ByteArray,
    expectedSha256: String,
    mode: Int,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
) {
    cancellationCheck()
    if (bytes.size !in 1..MAXIMUM_GATE_HELPER_BYTES ||
        MessageDigest.getInstance("SHA-256").digest(bytes).toHex() != expectedSha256
    ) throw IOException("sandbox gate helper bytes do not match the configured digest")
    if (mode.permissions and 0x49 == 0) {
        throw IOException("sandbox gate helper is not executable")
    }
    if (bytes.size < 64 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
        bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte() ||
        bytes[4] != 2.toByte() || bytes[5] != 1.toByte()
    ) throw IOException("sandbox gate helper must be a little-endian ELF64 executable")
    val elf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    val machine = elf.getShort(18).toInt() and 0xffff
    val expectedMachine = when (System.getProperty("os.arch", "")) {
        "amd64", "x86_64" -> 62
        "aarch64" -> 183
        else -> throw IOException("sandbox gate helper architecture is unsupported")
    }
    if (machine != expectedMachine) throw IOException("sandbox gate helper architecture does not match the host")
    val programOffset = elf.getLong(32)
    val programEntrySize = elf.getShort(54).toInt() and 0xffff
    val programCount = elf.getShort(56).toInt() and 0xffff
    if (programEntrySize < 56 || programCount <= 0 || programOffset < 0) {
        throw IOException("sandbox gate helper has an invalid program-header table")
    }
    repeat(programCount) { index ->
        cancellationCheck()
        val offset = Math.addExact(programOffset, Math.multiplyExact(index.toLong(), programEntrySize.toLong()))
        if (offset > bytes.size.toLong() - programEntrySize) {
            throw IOException("sandbox gate helper program headers exceed the file")
        }
        val type = elf.getInt(offset.toInt())
        if (type == ELF_PT_INTERP) throw IOException("sandbox gate helper must not have PT_INTERP")
        if (type == ELF_PT_DYNAMIC) {
            val dynamicOffset = elf.getLong(offset.toInt() + 8)
            val dynamicSize = elf.getLong(offset.toInt() + 32)
            if (dynamicOffset < 0 || dynamicSize < 0 || dynamicSize % 16L != 0L ||
                dynamicOffset > bytes.size.toLong() - dynamicSize
            ) throw IOException("sandbox gate helper dynamic table is malformed")
            var sawTerminator = false
            var cursor = dynamicOffset
            while (cursor < dynamicOffset + dynamicSize) {
                cancellationCheck()
                when (elf.getLong(cursor.toInt())) {
                    ELF_DT_NULL -> {
                        sawTerminator = true
                        break
                    }
                    ELF_DT_NEEDED -> throw IOException("sandbox gate helper must not have DT_NEEDED")
                }
                cursor += 16L
            }
            if (!sawTerminator) throw IOException("sandbox gate helper dynamic table is unterminated")
        }
    }
}

private fun probeSystemd(
    supervisor: PinnedSecurityExecutable,
    inspector: PinnedSecurityExecutable,
    bus: PinnedSystemdBusEndpoint,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
) {
    if (!probe(
            supervisor.path,
            listOf("--version"),
            "scope supervisor version",
            cancellationCheck,
        ).startsWith("systemd ")
    ) {
        throw IOException("configured scope supervisor is not systemd-run")
    }
    val help = probe(supervisor.path, listOf("--help"), "scope supervisor features", cancellationCheck)
    listOf("--scope", "--user", "--property", "--unit", "--collect", "--expand-environment").forEach {
        if (it !in help) throw IOException("scope supervisor lacks required option $it")
    }
    val manager = systemctl(
        inspector,
        bus,
        listOf("show", "--property=Version", "--value"),
        cancellationCheck = cancellationCheck,
    )
    if (!isValidSystemdManagerVersionOutput(manager.output)) {
        throw IOException("systemd user manager is unavailable")
    }
}

internal fun isValidSystemdManagerVersionOutput(output: String): Boolean {
    val version = when {
        output.endsWith("\r\n") -> output.dropLast(2)
        output.endsWith('\n') -> output.dropLast(1)
        else -> output
    }
    return version.length in 1..MAXIMUM_SYSTEMD_MANAGER_VERSION_BYTES &&
        version.matches(Regex("[0-9][0-9A-Za-z.+~:_-]*"))
}

/** Proves that the fixed launcher opens only the supplied environment descriptor path as fd 4. */
private fun probeEnvironmentFdOpener(
    path: Path,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
) {
    cancellationCheck()
    LinuxFilesystemSyscalls.openRoot(Path.of("/tmp")).use { parent ->
        LinuxFilesystemSyscalls.createTemporaryAt(parent.fd).use { probeFile ->
            LinuxFilesystemSyscalls.chmod(probeFile, SANDBOX_ENVIRONMENT_FILE_MODE)
            LinuxFilesystemSyscalls.write(
                probeFile,
                ENVIRONMENT_FD_OPENER_PROBE_OUTPUT.toByteArray(),
                cancellationCheck,
            )
            val command = listOf(
                path.toString(),
                "--noprofile",
                "--norc",
                "-c",
                ENVIRONMENT_FD_OPENER_SCRIPT,
                ENVIRONMENT_FD_OPENER_ARG0,
                LinuxFilesystemSyscalls.stableDescriptorPath(probeFile.fd).toString(),
                path.toString(),
                "--noprofile",
                "--norc",
                "-c",
                ENVIRONMENT_FD_OPENER_PROBE_SCRIPT,
            )
            val process = ProcessBuilder(command).redirectErrorStream(true).also { builder ->
                builder.environment().clear()
            }.let { builder ->
                cancellationCheck()
                builder.start()
            }
            awaitTrustedProcess(process, PROBE_TIMEOUT, cancellationCheck, "environment-fd launcher")
            val output = process.inputStream.readNBytes(MAXIMUM_PROBE_BYTES + 1).toString(Charsets.UTF_8)
            if (process.exitValue() != 0 || output != ENVIRONMENT_FD_OPENER_PROBE_OUTPUT) {
                throw IOException("environment-fd launcher did not preserve exact fd-4 semantics")
            }
        }
    }
}

private data class CommandResult(val exitCode: Int, val output: String)

private fun probe(
    path: Path,
    arguments: List<String>,
    label: String,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): String {
    cancellationCheck()
    val builder = ProcessBuilder(listOf(path.toString()) + arguments).redirectErrorStream(true)
    builder.environment().clear()
    val process = builder.start()
    awaitTrustedProcess(process, PROBE_TIMEOUT, cancellationCheck, "$label probe")
    val bytes = process.inputStream.readNBytes(MAXIMUM_PROBE_BYTES + 1)
    if (process.exitValue() != 0 || bytes.size > MAXIMUM_PROBE_BYTES) throw IOException("$label probe failed")
    return bytes.toString(Charsets.UTF_8)
}

private fun systemctlShow(
    inspector: PinnedSecurityExecutable,
    bus: PinnedSystemdBusEndpoint,
    unitName: String,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): Map<String, String> {
    val result = systemctl(
        inspector,
        bus,
        listOf(
            "show",
            unitName,
            "--property=Id,LoadState,ActiveState,ControlGroup,TasksMax,MemoryMax," +
                "MemorySwapMax,OOMPolicy,CPUQuotaPerSecUSec,KillMode,SendSIGKILL," +
                "RuntimeMaxUSec,TimeoutStopUSec,Delegate",
        ),
        allowedExitCodes = setOf(0, 1, 4),
        cancellationCheck = cancellationCheck,
    )
    return result.output.lineSequence()
        .filter { '=' in it }
        .associate { it.substringBefore('=') to it.substringAfter('=') }
}

private fun parseSystemdDurationMicros(value: String?): Long? {
    val text = value?.trim().orEmpty()
    if (text.isEmpty()) return null
    val component = Regex("([0-9]+(?:\\.[0-9]+)?)(us|µs|μs|ms|s|min|h|d|w|month|y)")
    var total = BigDecimal.ZERO
    return try {
        text.split(Regex("[ \\t]+")).forEach { token ->
            val match = component.matchEntire(token) ?: return null
            val multiplier = when (match.groupValues[2]) {
                "us", "µs", "μs" -> 1L
                "ms" -> 1_000L
                "s" -> 1_000_000L
                "min" -> 60_000_000L
                "h" -> 3_600_000_000L
                "d" -> 86_400_000_000L
                "w" -> 604_800_000_000L
                "month" -> 2_629_800_000_000L
                "y" -> 31_557_600_000_000L
                else -> return null
            }
            total = total.add(
                BigDecimal(match.groupValues[1]).multiply(BigDecimal.valueOf(multiplier)),
            )
        }
        total.longValueExact()
    } catch (_: ArithmeticException) {
        null
    } catch (_: NumberFormatException) {
        null
    }
}

private fun systemctl(
    inspector: PinnedSecurityExecutable,
    bus: PinnedSystemdBusEndpoint,
    arguments: List<String>,
    allowedExitCodes: Set<Int> = setOf(0),
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): CommandResult {
    cancellationCheck()
    inspector.requireUnchanged(cancellationCheck)
    bus.requireUnchanged(cancellationCheck)
    val builder = ProcessBuilder(listOf(inspector.path.toString(), "--user") + arguments).redirectErrorStream(true)
    builder.environment().clear()
    builder.environment().putAll(bus.controlEnvironment)
    val process = builder.start()
    awaitTrustedProcess(process, SYSTEMD_CONTROL_TIMEOUT, cancellationCheck, "systemd scope control")
    val bytes = process.inputStream.readNBytes(MAXIMUM_PROBE_BYTES + 1)
    if (process.exitValue() !in allowedExitCodes || bytes.size > MAXIMUM_PROBE_BYTES) {
        throw IOException("systemd scope control failed safely")
    }
    inspector.requireUnchanged(cancellationCheck)
    bus.requireUnchanged(cancellationCheck)
    return CommandResult(process.exitValue(), bytes.toString(Charsets.UTF_8))
}

private fun awaitTrustedProcess(
    process: Process,
    timeout: Duration,
    cancellationCheck: () -> Unit,
    label: String,
) {
    val deadline = System.nanoTime() + timeout.toNanos()
    try {
        while (process.isAlive && System.nanoTime() < deadline) {
            cancellationCheck()
            process.waitFor(TRUSTED_PROCESS_POLL_MILLIS, TimeUnit.MILLISECONDS)
        }
        cancellationCheck()
        if (process.isAlive) throw IOException("$label timed out")
    } catch (failure: Throwable) {
        process.destroyForcibly()
        try {
            process.waitFor(PROBE_CLEANUP_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            failure.addSuppressed(interrupted)
        }
        throw failure
    }
}

private class SandboxPathIndex {
    private class Node {
        var terminal = false
        val children = HashMap<String, Node>()
    }

    private val root = Node()

    fun addIfNonOverlapping(path: Path, cancellationCheck: () -> Unit): Boolean {
        var node = root
        path.forEach { component ->
            cancellationCheck()
            if (node.terminal) return false
            node = node.children.getOrPut(component.toString(), ::Node)
        }
        if (node.terminal || node.children.isNotEmpty()) return false
        node.terminal = true
        return true
    }

    fun overlaps(path: Path, cancellationCheck: () -> Unit): Boolean {
        var node = root
        path.forEach { component ->
            cancellationCheck()
            if (node.terminal) return true
            node = node.children[component.toString()] ?: return false
        }
        return node.terminal || node.children.isNotEmpty()
    }
}

private fun destinationParents(
    destinations: Collection<Path>,
    cancellationCheck: () -> Unit,
): List<Path> {
    val reserved = setOf(Path.of("/proc"), Path.of("/dev"), Path.of("/tmp"))
    val parents = LinkedHashSet<Path>()
    destinations.forEach { destination ->
        cancellationCheck()
        var current = destination.parent
        while (current != null && current != Path.of("/")) {
            cancellationCheck()
            if (current !in reserved) {
                parents.add(current)
                if (parents.size > MAXIMUM_SANDBOX_PARENT_DIRECTORIES) {
                    throw IOException("sandbox destination parents exceed the command-construction limit")
                }
            }
            current = current.parent
        }
    }
    cancellationCheck()
    return parents.sortedWith { left, right ->
        cancellationCheck()
        left.nameCount.compareTo(right.nameCount).takeIf { it != 0 }
            ?: compareCheckpointed(left.toString(), right.toString(), cancellationCheck)
    }
}

private fun pathsOverlap(first: Path, second: Path): Boolean =
    first == second || first.startsWith(second) || second.startsWith(first)

private fun currentUid(): Int =
    (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()

private fun nprocBackstop(
    sandboxMaximum: Int,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): Int {
    cancellationCheck()
    val currentUid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
    var currentTasks = 0L
    Files.newDirectoryStream(Path.of("/proc")).use { entries ->
        entries.forEach entryLoop@ { entry ->
            cancellationCheck()
            if (entry.fileName.toString().all(Char::isDigit)) {
                val owner = try {
                    (Files.getAttribute(entry, "unix:uid") as Number).toInt()
                } catch (_: java.nio.file.NoSuchFileException) {
                    return@entryLoop
                }
                if (owner == currentUid) {
                    val tasks = try {
                        Files.newDirectoryStream(entry.resolve("task"))
                    } catch (_: java.nio.file.NoSuchFileException) {
                        return@entryLoop
                    }
                    tasks.use { taskEntries ->
                        taskEntries.forEach { _ ->
                            cancellationCheck()
                            currentTasks = Math.addExact(currentTasks, 1L)
                        }
                    }
                }
            }
        }
    }
    // RLIMIT_NPROC is real-UID/global and counts Linux tasks, not just process leaders. Keep a
    // generous finite headroom so it cannot replace or interfere with the exact cgroup pids.max.
    val headroom = maxOf(1024L, sandboxMaximum.toLong() * 16L)
    return Math.addExact(currentTasks, headroom)
        .coerceAtMost(Int.MAX_VALUE.toLong())
        .toInt()
}

/** Bounded canonical text used only as a deterministic sort key for one already-bounded rule. */
private class BoundedCanonicalText(
    private val maximumBytes: Long,
    private val cancellationCheck: () -> Unit,
) {
    private val output = StringBuilder()
    private var encodedBytes = 0L

    fun field(name: String, value: Any?) {
        val text = value?.toString() ?: "<null>"
        append("${name.length}:")
        append(name)
        append("${text.length}:")
        append(text)
        append(";")
    }

    private fun append(value: String) {
        forEachUtf8Chunk(value, cancellationCheck) { chunk, bytes ->
            encodedBytes = Math.addExact(encodedBytes, bytes.size.toLong())
            if (encodedBytes > maximumBytes) {
                throw IllegalArgumentException("canonical policy metadata exceeds the byte limit")
            }
            output.append(chunk)
        }
    }

    fun finish(): String {
        cancellationCheck()
        return output.toString()
    }
}

/** Incremental canonical digest: request-derived metadata is never assembled into one large String. */
private class CanonicalMetadataDigest(
    private val maximumBytes: Long,
    private val cancellationCheck: () -> Unit,
) {
    private val digest = MessageDigest.getInstance("SHA-256")
    private var encodedBytes = 0L

    fun field(name: String, value: Any?) {
        val text = value?.toString() ?: "<null>"
        append("${name.length}:")
        append(name)
        append("${text.length}:")
        append(text)
        append(";")
    }

    fun value(value: String) {
        append("${value.length}:")
        append(value)
        append(";")
    }

    private fun append(value: String) {
        forEachUtf8Chunk(value, cancellationCheck) { _, bytes ->
            encodedBytes = Math.addExact(encodedBytes, bytes.size.toLong())
            if (encodedBytes > maximumBytes) {
                throw IllegalArgumentException("canonical sandbox metadata exceeds the byte limit")
            }
            digest.update(bytes)
        }
    }

    fun finish(): String {
        cancellationCheck()
        return digest.digest().toHex()
    }
}

private inline fun forEachUtf8Chunk(
    value: String,
    cancellationCheck: () -> Unit,
    consume: (String, ByteArray) -> Unit,
) {
    var offset = 0
    while (offset < value.length) {
        cancellationCheck()
        var end = minOf(value.length, offset + CANONICAL_TEXT_CHARACTER_CHUNK)
        if (end < value.length && Character.isHighSurrogate(value[end - 1]) &&
            Character.isLowSurrogate(value[end])
        ) {
            end--
        }
        val chunk = value.substring(offset, end)
        consume(chunk, chunk.toByteArray(Charsets.UTF_8))
        offset = end
    }
    cancellationCheck()
}

private fun compareCheckpointed(
    left: String,
    right: String,
    cancellationCheck: () -> Unit,
): Int {
    val comparedLength = minOf(left.length, right.length)
    for (index in 0 until comparedLength) {
        if (index and (CANONICAL_TEXT_CHARACTER_CHUNK - 1) == 0) cancellationCheck()
        val difference = left[index].compareTo(right[index])
        if (difference != 0) return difference
    }
    cancellationCheck()
    return left.length.compareTo(right.length)
}

private fun sortedStrings(
    values: Collection<String>,
    cancellationCheck: () -> Unit,
): List<String> = values.sortedWith { left, right ->
    compareCheckpointed(left, right, cancellationCheck)
}

internal fun AcpTerminalExecutionPolicy.policyDigest(
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): String {
    cancellationCheck()
    val canonicalRules = commandRules.map { rule ->
        cancellationCheck()
        canonicalTerminalRuleSortKey(rule, cancellationCheck) to rule
    }
    require(canonicalRules.map { it.first }.distinct().size == canonicalRules.size) {
        "terminal command rules must have distinct canonical authority"
    }
    val sortedRules = canonicalRules.sortedWith { left, right ->
        compareCheckpointed(left.first, right.first, cancellationCheck)
    }
    val digest = CanonicalMetadataDigest(MAXIMUM_TERMINAL_POLICY_AUTHORITY_BYTES * 2L, cancellationCheck)
    digest.field("schema", "acp-terminal-policy-v2")
    stagingRoots.sortedWith { left, right ->
        compareCheckpointed(left.stagingRoot.rootId, right.stagingRoot.rootId, cancellationCheck)
    }.forEachIndexed { index, grant ->
        cancellationCheck()
        digest.field("root[$index].id", grant.stagingRoot.rootId)
        digest.field("root[$index].path", grant.stagingRoot.path)
        digest.field("root[$index].mode", grant.mode)
        digest.field("root[$index].device", grant.stagingRoot.identity.key.device)
        digest.field("root[$index].inode", grant.stagingRoot.identity.key.inode)
        digest.field("root[$index].mount", grant.stagingRoot.identity.mountId)
        val quota = grant.stagingRoot.quotaProof?.evidence
        digest.field("root[$index].quota.provider", quota?.provider)
        digest.field("root[$index].quota.mount", quota?.mountId)
        digest.field("root[$index].quota.bytes", quota?.maximumBytes)
        digest.field("root[$index].quota.entries", quota?.maximumEntries)
        digest.field("root[$index].quota.path", quota?.mountPathSha256)
    }
    digest.field("limits.concurrent", limits.maximumConcurrentTerminals)
    digest.field("limits.creates", limits.maximumTerminalCreates)
    digest.field("limits.retainedOutput", limits.maximumRetainedOutputBytes)
    digest.field("limits.producedOutput", limits.maximumProducedOutputBytes)
    digest.field("limits.duration", limits.maximumDuration)
    digest.field("limits.terminationGrace", limits.terminationGrace)
    digest.field("limits.processes", limits.resourceLimits.maximumProcesses)
    digest.field("limits.openFiles", limits.resourceLimits.maximumOpenFiles)
    digest.field("limits.fileBytes", limits.resourceLimits.maximumFileBytes)
    digest.field("limits.addressSpace", limits.resourceLimits.maximumAddressSpaceBytes)
    digest.field("limits.cpuSeconds", limits.resourceLimits.maximumCpuSeconds)
    sortedRules.forEachIndexed { ruleIndex, (_, rule) ->
        cancellationCheck()
        digest.field("rule[$ruleIndex].command", rule.command)
        digest.field("rule[$ruleIndex].cwd", rule.workingDirectory)
        digest.field("rule[$ruleIndex].executable.source", rule.executable.source)
        digest.field("rule[$ruleIndex].executable.destination", rule.executable.destination)
        digest.field("rule[$ruleIndex].executable.manifest", rule.executable.expectedManifestSha256)
        digest.field("rule[$ruleIndex].argv.count", rule.arguments.size)
        rule.arguments.forEachIndexed { argumentIndex, argument ->
            cancellationCheck()
            digest.field("rule[$ruleIndex].argv[$argumentIndex]", argument)
        }
        val environment = rule.environment.entries.sortedWith { left, right ->
            compareCheckpointed(left.key, right.key, cancellationCheck)
        }
        digest.field("rule[$ruleIndex].env.count", environment.size)
        environment.forEachIndexed { environmentIndex, (name, value) ->
            cancellationCheck()
            digest.field("rule[$ruleIndex].env[$environmentIndex].name", name)
            digest.field(
                "rule[$ruleIndex].env[$environmentIndex].valueHash",
                sha256(value, cancellationCheck),
            )
        }
        val runtimeMounts = canonicalRuntimeMounts(rule.runtimeMounts, cancellationCheck)
        digest.field("rule[$ruleIndex].mount.count", runtimeMounts.size)
        runtimeMounts.forEachIndexed { mountIndex, mount ->
            cancellationCheck()
            digest.field("rule[$ruleIndex].mount[$mountIndex].source", mount.source)
            digest.field("rule[$ruleIndex].mount[$mountIndex].destination", mount.destination)
            digest.field("rule[$ruleIndex].mount[$mountIndex].manifest", mount.expectedManifestSha256)
        }
    }
    return digest.finish()
}

private fun canonicalTerminalRuleSortKey(
    rule: AcpTerminalCommandRule,
    cancellationCheck: () -> Unit,
): String {
    val output = BoundedCanonicalText(MAXIMUM_TERMINAL_POLICY_AUTHORITY_BYTES, cancellationCheck)
    output.field("command", rule.command)
    output.field("cwd", rule.workingDirectory)
    output.field("executable.source", rule.executable.source)
    output.field("executable.destination", rule.executable.destination)
    output.field("executable.manifest", rule.executable.expectedManifestSha256)
    output.field("argv.count", rule.arguments.size)
    rule.arguments.forEachIndexed { index, argument ->
        cancellationCheck()
        output.field("argv[$index]", argument)
    }
    val environment = rule.environment.entries.sortedWith { left, right ->
        compareCheckpointed(left.key, right.key, cancellationCheck)
    }
    output.field("env.count", environment.size)
    environment.forEachIndexed { index, (name, value) ->
        cancellationCheck()
        output.field("env[$index].name", name)
        output.field("env[$index].value", value)
    }
    val mounts = canonicalRuntimeMounts(rule.runtimeMounts, cancellationCheck)
    output.field("mount.count", mounts.size)
    mounts.forEachIndexed { index, mount ->
        cancellationCheck()
        output.field("mount[$index].source", mount.source)
        output.field("mount[$index].destination", mount.destination)
        output.field("mount[$index].manifest", mount.expectedManifestSha256)
    }
    return output.finish()
}

private fun canonicalRuntimeMounts(
    mounts: Collection<AcpSandboxReadOnlyMount>,
    cancellationCheck: () -> Unit,
): List<AcpSandboxReadOnlyMount> = mounts.sortedWith { left, right ->
    cancellationCheck()
    compareCheckpointed(left.destination.toString(), right.destination.toString(), cancellationCheck)
        .takeIf { it != 0 }
        ?: compareCheckpointed(left.source.toString(), right.source.toString(), cancellationCheck)
            .takeIf { it != 0 }
        ?: compareCheckpointed(
            left.expectedManifestSha256.orEmpty(),
            right.expectedManifestSha256.orEmpty(),
            cancellationCheck,
        )
}

private fun canonicalStringDigest(
    values: Collection<String>,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): String {
    require(values.size <= MAXIMUM_SANDBOX_ARGUMENTS) {
        "canonical string collection exceeds the authenticated count limit"
    }
    val digest = CanonicalMetadataDigest(MAXIMUM_SANDBOX_ARGUMENT_BYTES * 2L, cancellationCheck)
    values.forEach { value ->
        cancellationCheck()
        digest.value(value)
    }
    return digest.finish()
}

private fun canonicalSandboxEvidenceDigest(
    evidence: AcpSandboxEvidence,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): String {
    val digest = CanonicalMetadataDigest(MAXIMUM_SANDBOX_EVIDENCE_BYTES, cancellationCheck)
    fun field(name: String, value: Any?) = digest.field(name, value)
    fun resource(prefix: String, limits: AcpSandboxResourceLimits) {
        cancellationCheck()
        digest.field("$prefix.processes", limits.maximumProcesses)
        digest.field("$prefix.openFiles", limits.maximumOpenFiles)
        digest.field("$prefix.fileBytes", limits.maximumFileBytes)
        digest.field("$prefix.addressSpace", limits.maximumAddressSpaceBytes)
        digest.field("$prefix.cpuSeconds", limits.maximumCpuSeconds)
    }
    digest.field("provider", evidence.provider)
    digest.field("providerVersion", evidence.providerVersion)
    digest.field("providerDigest", evidence.providerExecutableSha256)
    digest.field("providerMode", evidence.providerExecutableMode)
    digest.field("resourceLimiterDigest", evidence.resourceLimiterSha256)
    digest.field("scopeSupervisorDigest", evidence.scopeSupervisorSha256)
    digest.field("scopeInspectorDigest", evidence.scopeInspectorSha256)
    digest.field("environmentFdOpenerDigest", evidence.environmentFdOpenerSha256)
    evidence.securityExecutables.forEachIndexed { index, tool ->
        field("tool[$index].role", tool.role)
        field("tool[$index].path", tool.canonicalPathSha256)
        field("tool[$index].digest", tool.contentSha256)
        field("tool[$index].mode", tool.mode)
        field("tool[$index].metadata", tool.metadataSha256)
    }
    resource("outer", evidence.outerAgentLimits)
    field("closure.entries", evidence.runtimeClosureLimits.maximumEntries)
    field("closure.bytes", evidence.runtimeClosureLimits.maximumUserOwnedFileBytes)
    field("closure.depth", evidence.runtimeClosureLimits.maximumDepth)
    field("cgroup.pids", evidence.cgroupV2PidsLimited)
    field("cgroup.memory", evidence.cgroupV2MemoryLimited)
    field("cgroup.cpu", evidence.cgroupV2CpuLimited)
    field("network", evidence.networkIsolated)
    field("outerContained", evidence.outerAgentContained)
    field("nestedUserns", evidence.nestedUserNamespacesDisabled)
    field("newSession", evidence.newSession)
    field("dieWithParent", evidence.dieWithParent)
    field("evidence.maximumLaunches", evidence.maximumRecordedLaunches)
    field("evidence.maximumRuntimeMounts", evidence.maximumRecordedRuntimeMounts)
    field("evidence.maximumCanonicalBytes", evidence.maximumCanonicalMetadataBytes)
    field("outerOutput.limit", evidence.outerProcessOutput?.maximumBytes)
    field("outerOutput.observed", evidence.outerProcessOutput?.observedBytes)
    field("outerOutput.exceeded", evidence.outerProcessOutput?.limitExceeded)
    field("terminal.policy", evidence.policySha256)
    evidence.terminalLimits?.let { limits ->
        field("terminal.concurrent", limits.maximumConcurrentTerminals)
        field("terminal.creates", limits.maximumTerminalCreates)
        field("terminal.retainedOutput", limits.maximumRetainedOutputBytes)
        field("terminal.producedOutput", limits.maximumProducedOutputBytes)
        field("terminal.duration", limits.maximumDuration.toNanos())
        field("terminal.terminationGrace", limits.terminationGrace.toNanos())
        resource("terminal.resource", limits.resourceLimits)
    }
    evidence.launches.forEachIndexed { launchIndex, launch ->
        field("launch[$launchIndex].purpose", launch.purpose)
        field("launch[$launchIndex].command", launch.commandSha256)
        field("launch[$launchIndex].gate.descriptor", launch.startGate.descriptor)
        field("launch[$launchIndex].gate.waiter", launch.startGate.waiterExecutableSha256)
        field("launch[$launchIndex].gate.protocol", launch.startGate.helperProtocolSha256)
        field("launch[$launchIndex].gate.positiveByte", launch.startGate.positiveByteRequired)
        field("launch[$launchIndex].environment.path", launch.environment.sandboxPathSha256)
        field("launch[$launchIndex].environment.names", launch.environment.bindingNamesSha256)
        field("launch[$launchIndex].environment.count", launch.environment.bindingCount)
        field("launch[$launchIndex].environment.bytes", launch.environment.encodedBytes)
        field("launch[$launchIndex].environment.device", launch.environment.device)
        field("launch[$launchIndex].environment.inode", launch.environment.inode)
        field("launch[$launchIndex].environment.mount", launch.environment.mountId)
        field("launch[$launchIndex].environment.mode", launch.environment.mode)
        field("launch[$launchIndex].environment.links", launch.environment.linkCount)
        field("launch[$launchIndex].executable.source", launch.executableMount.sourcePathSha256)
        field("launch[$launchIndex].executable.destination", launch.executableMount.destinationPathSha256)
        field("launch[$launchIndex].executable.manifest", launch.executableMount.manifestSha256)
        field("launch[$launchIndex].executable.device", launch.executableMount.device)
        field("launch[$launchIndex].executable.inode", launch.executableMount.inode)
        field("launch[$launchIndex].executable.mode", launch.executableMount.mode)
        field("launch[$launchIndex].executable.directory", launch.executableMount.directory)
        resource("launch[$launchIndex].resource", launch.resourceLimits)
        field("launch[$launchIndex].pids", launch.controllers.pidsMax)
        field("launch[$launchIndex].memory", launch.controllers.memoryMaxBytes)
        field("launch[$launchIndex].swap", launch.controllers.memorySwapMaxBytes)
        field("launch[$launchIndex].cpuQuota", launch.controllers.cpuQuotaMicros)
        field("launch[$launchIndex].cpuPeriod", launch.controllers.cpuPeriodMicros)
        field("launch[$launchIndex].oomGroup", launch.controllers.memoryOomGroup)
        field("launch[$launchIndex].runtimeMax", launch.controllers.runtimeMaxMicros)
        field("launch[$launchIndex].timeoutStop", launch.controllers.timeoutStopMicros)
        field("launch[$launchIndex].rlimit.processes.soft", launch.effectiveRlimits.processesSoft)
        field("launch[$launchIndex].rlimit.processes.hard", launch.effectiveRlimits.processesHard)
        field("launch[$launchIndex].rlimit.nofile.soft", launch.effectiveRlimits.openFilesSoft)
        field("launch[$launchIndex].rlimit.nofile.hard", launch.effectiveRlimits.openFilesHard)
        field("launch[$launchIndex].rlimit.fsize.soft", launch.effectiveRlimits.fileBytesSoft)
        field("launch[$launchIndex].rlimit.fsize.hard", launch.effectiveRlimits.fileBytesHard)
        field("launch[$launchIndex].rlimit.core.soft", launch.effectiveRlimits.coreBytesSoft)
        field("launch[$launchIndex].rlimit.core.hard", launch.effectiveRlimits.coreBytesHard)
        field("launch[$launchIndex].rlimit.as.soft", launch.effectiveRlimits.addressSpaceSoft)
        field("launch[$launchIndex].rlimit.as.hard", launch.effectiveRlimits.addressSpaceHard)
        field("launch[$launchIndex].rlimit.cpu.soft", launch.effectiveRlimits.cpuSecondsSoft)
        field("launch[$launchIndex].rlimit.cpu.hard", launch.effectiveRlimits.cpuSecondsHard)
        launch.runtimeMounts.forEachIndexed { mountIndex, mount ->
            field("launch[$launchIndex].mount[$mountIndex].source", mount.sourcePathSha256)
            field("launch[$launchIndex].mount[$mountIndex].destination", mount.destinationPathSha256)
            field("launch[$launchIndex].mount[$mountIndex].manifest", mount.manifestSha256)
            field("launch[$launchIndex].mount[$mountIndex].device", mount.device)
            field("launch[$launchIndex].mount[$mountIndex].inode", mount.inode)
            field("launch[$launchIndex].mount[$mountIndex].mode", mount.mode)
            field("launch[$launchIndex].mount[$mountIndex].directory", mount.directory)
        }
    }
    evidence.authorities.forEachIndexed { index, authority ->
        field("authority[$index].id", authority.rootId)
        field("authority[$index].path", authority.rootPathSha256)
        field("authority[$index].mode", authority.mode)
        field("authority[$index].quota.provider", authority.quota?.provider)
        field("authority[$index].quota.mount", authority.quota?.mountId)
        field("authority[$index].quota.bytes", authority.quota?.maximumBytes)
        field("authority[$index].quota.entries", authority.quota?.maximumEntries)
        field("authority[$index].quota.path", authority.quota?.mountPathSha256)
    }
    evidence.terminalAudit.forEachIndexed { index, record ->
        field("terminalAudit[$index].sequence", record.sequence)
        field("terminalAudit[$index].session", record.sessionId)
        field("terminalAudit[$index].method", record.method)
        field("terminalAudit[$index].request", record.requestSha256)
        field("terminalAudit[$index].terminal", record.terminalIdSha256)
        field("terminalAudit[$index].tool", record.toolCallIdSha256)
        field("terminalAudit[$index].outcome", record.outcome)
        field("terminalAudit[$index].reason", record.reason)
        field("terminalAudit[$index].network", record.networkIsolated)
        field("terminalAudit[$index].retained", record.retainedOutputBytes)
        field("terminalAudit[$index].produced", record.producedOutputBytes)
        field("terminalAudit[$index].truncated", record.outputTruncated)
    }
    return digest.finish()
}

private fun sha256(value: String): String =
    MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8)).toHex()

private fun sha256(value: String, cancellationCheck: () -> Unit): String {
    val digest = MessageDigest.getInstance("SHA-256")
    forEachUtf8Chunk(value, cancellationCheck) { _, bytes -> digest.update(bytes) }
    return digest.digest().toHex()
}

private fun sha256(
    path: Path,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): String = Files.newInputStream(path).use { input ->
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(1024 * 1024)
    while (true) {
        cancellationCheck()
        val count = input.read(buffer)
        if (count < 0) break
        digest.update(buffer, 0, count)
    }
    cancellationCheck()
    digest.digest().toHex()
}

private fun sha256(
    descriptor: LinuxDescriptor,
    maximumBytes: Long,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): String {
    val digest = MessageDigest.getInstance("SHA-256")
    LinuxFilesystemSyscalls.copyReadableTo(
        descriptor,
        object : OutputStream() {
            override fun write(value: Int) {
                digest.update(value.toByte())
            }

            override fun write(content: ByteArray, offset: Int, length: Int) {
                digest.update(content, offset, length)
            }
        },
        maximumBytes,
        cancellationCheck,
    )
    return digest.digest().toHex()
}

private fun readPinnedBytes(
    descriptor: LinuxDescriptor,
    maximumBytes: Int,
    cancellationCheck: () -> Unit = NO_SANDBOX_CHECKPOINT,
): ByteArray =
    LinuxFilesystemSyscalls.openReadableFrom(descriptor).use { readable ->
        LinuxFilesystemSyscalls.read(readable, maximumBytes, cancellationCheck)
    }

private fun readPinnedPrefix(descriptor: LinuxDescriptor, maximumBytes: Int): ByteArray =
    LinuxFilesystemSyscalls.readPrefix(descriptor, maximumBytes)

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private val REQUIRED_BUBBLEWRAP_OPTIONS = listOf(
    "--unshare-all", "--unshare-user", "--new-session", "--die-with-parent", "--clearenv",
    "--disable-userns", "--assert-userns-disabled", "--proc", "--dev", "--tmpfs", "--cap-drop",
    "--hostname", "--chmod", "--dir", "--ro-bind", "--bind", "--ro-bind-fd", "--chdir",
)
private val REQUIRED_PRLIMIT_OPTIONS = listOf("--nproc", "--nofile", "--fsize", "--core", "--as", "--cpu")
private val NAMESPACE_TOOL_PATHS = listOf(
    Path.of("/usr/bin/bwrap"), Path.of("/usr/bin/unshare"), Path.of("/usr/bin/nsenter"),
    Path.of("/usr/bin/newuidmap"), Path.of("/usr/bin/newgidmap"),
)
private val BROAD_RUNTIME_DIRECTORY_ROOTS = listOf(
    Path.of("/home"), Path.of("/root"), Path.of("/etc"), Path.of("/run"), Path.of("/var"),
    Path.of("/tmp"), Path.of("/mnt"), Path.of("/media"),
)
private val BROAD_RUNTIME_DIRECTORY_PARENTS = setOf(
    Path.of("/home"), Path.of("/mnt"), Path.of("/media"),
)
private val PROTECTED_LOADER_DESTINATIONS = listOf(
    ACP_INTERNAL_SANDBOX_ROOT,
    Path.of("/etc/ld.so.preload"),
    Path.of("/etc/ld.so.cache"),
    Path.of("/etc/ld.so.conf"),
    Path.of("/etc/ld.so.conf.d"),
    Path.of("/lib"),
    Path.of("/lib64"),
    Path.of("/usr/lib"),
    Path.of("/usr/lib64"),
)
private val FORBIDDEN_SANDBOX_TRUST_XATTRS = setOf(
    "system.posix_acl_access",
    "system.posix_acl_default",
    "system.nfs4_acl",
    "system.richacl",
    "security.capability",
)
private val CGROUP_ROOT = Path.of("/sys/fs/cgroup")
private val NO_SANDBOX_CHECKPOINT: () -> Unit = {}
private val PROBE_TIMEOUT = Duration.ofSeconds(3)
private val PROBE_CLEANUP_TIMEOUT = Duration.ofSeconds(1)
private val SYSTEMD_CONTROL_TIMEOUT = Duration.ofSeconds(3)
private val SCOPE_START_TIMEOUT = Duration.ofSeconds(3)
private val CLEANUP_TIMEOUT = Duration.ofSeconds(3)
private const val SCOPE_POLL_MILLIS = 20L
private const val TRUSTED_PROCESS_POLL_MILLIS = 20L
private const val MAXIMUM_PROBE_BYTES = 32 * 1024
private const val MAXIMUM_GATE_HELPER_BYTES = 4 * 1024 * 1024
private const val MAXIMUM_SYSTEMD_MANAGER_VERSION_BYTES = 128
internal const val MAXIMUM_SANDBOX_ARGUMENTS = 1024
internal const val MAXIMUM_SANDBOX_ARGUMENT_BYTES = 1024L * 1024L
private const val MAXIMUM_PROC_CMDLINE_BYTES = 1024 * 1024
private const val MAXIMUM_PROC_ENVIRONMENT_BYTES = 1024 * 1024
private const val MAXIMUM_PROC_STATUS_BYTES = 1024 * 1024
private const val MAXIMUM_PROC_STATUS_LINES = 4096
private const val MAXIMUM_PROC_FDINFO_BYTES = 64 * 1024
private const val MAXIMUM_PROC_FDINFO_LINES = 1024
private const val MAXIMUM_PROC_SYSCALL_BYTES = 4096
private const val MAXIMUM_PROC_LIMITS_BYTES = 1024 * 1024
private const val MAXIMUM_PROC_LIMITS_LINES = 4096
private const val MAXIMUM_PROC_MOUNTINFO_BYTES = 4 * 1024 * 1024
private const val MAXIMUM_PROC_MOUNTINFO_LINES = 4096
private const val MAXIMUM_CGROUP_CLEANUP_SEARCH_ENTRIES = 100_000
private const val MAXIMUM_CGROUP_CLEANUP_SEARCH_DEPTH = 64
private const val MAXIMUM_SANDBOX_PARENT_DIRECTORIES = 4096
private const val ENVIRONMENT_ENCODING_CHARACTER_CHUNK = 4096
private const val CANONICAL_TEXT_CHARACTER_CHUNK = 4096
private const val ELF_PT_DYNAMIC = 2
private const val ELF_PT_INTERP = 3
private const val ELF_DT_NULL = 0L
private const val ELF_DT_NEEDED = 1L
private const val CONTROL_DIRECTORY_MODE = 0x1c0 // 0700
private const val SANDBOX_ENVIRONMENT_FILE_MODE = 0x180 // 0600
private val ACP_SANDBOX_GATE_HELPER_PATH = ACP_INTERNAL_SANDBOX_ROOT.resolve("gate-helper")
private val ACP_SANDBOX_ENVIRONMENT_PATH = ACP_INTERNAL_SANDBOX_ROOT.resolve("environment")
private const val SANDBOX_GATE_TARGET_FD = 3
private const val SANDBOX_GATE_ENVIRONMENT_FD = 4
private const val START_GATE_RELEASE_BYTE = 'G'.code
private const val STATIC_GATE_HELPER_PROTOCOL =
    "decomp-acp-static-gate-v2:empty-or-exact-cwd-PWD;fd0-one-byte-G;fd3-target;fd4-unlinked-env;execveat"
private const val ENVIRONMENT_FD_OPENER_ARG0 = "decomp-acp-environment-fd"
private const val ENVIRONMENT_FD_OPENER_SCRIPT =
    "exec 4<\"\$1\" || exit 125; shift; exec \"\$@\""
private const val ENVIRONMENT_FD_OPENER_PROBE_OUTPUT = "fd4-ok"
private const val ENVIRONMENT_FD_OPENER_PROBE_SCRIPT =
    "IFS= read -r -N 6 -u 4 value || exit 120; " +
        "[[ \"\$value\" == fd4-ok ]] || exit 121; printf fd4-ok"
