package decompengine.oracle.gcc

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.fulltree.FullTreeDiskScratchBorrowedRunRoot
import decompengine.oracle.fulltree.KotlinContainedCommandInterruption
import decompengine.oracle.fulltree.FullTreeDiskScratchAuthority
import decompengine.oracle.fulltree.FullTreeDiskScratchLease
import decompengine.oracle.fulltree.FullTreeDiskScratchRunRoot
import decompengine.oracle.fulltree.FullTreeDiskScratchStage
import decompengine.oracle.fulltree.FullTreeFunctionObservationRuntimeMount
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandCleanup
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandExecution
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandExecutionException
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandInput
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandLauncher
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandResources
import decompengine.oracle.fulltree.calculateFullTreeObservationRuntimeManifestSha256
import java.nio.file.Path

private object GCC_BUNDLED_PREPARED_OPERATION_PERMIT

internal class GccBundledExecutedOperation(
    executionReceiptBytes: ByteArray,
    exportAssessmentReceiptBytes: ByteArray,
    val assessment: GccCompletedRunAssessment,
) {
    val complete: Boolean = false
    val releaseEligible: Boolean = false
    private val execution = executionReceiptBytes.copyOf()
    private val exportAssessment = exportAssessmentReceiptBytes.copyOf()
    val executionReceiptBytes: ByteArray get() = execution.copyOf()
    val exportAssessmentReceiptBytes: ByteArray get() = exportAssessment.copyOf()
}

internal class GccBundledInterruptedOperation(
    executionReceiptBytes: ByteArray,
    prefixAssessmentReceiptBytes: ByteArray,
    val assessment: GccInterruptedPrefixAssessment,
    val analysisState: GccBundledAnalysisStateSnapshot,
    analysisStateReceiptBytes: ByteArray,
) {
    val complete: Boolean = false
    val releaseEligible: Boolean = false
    private val execution = executionReceiptBytes.copyOf()
    private val prefix = prefixAssessmentReceiptBytes.copyOf()
    private val state = analysisStateReceiptBytes.copyOf()
    val analysisStateReceiptBytes: ByteArray get() = state.copyOf()
    val executionReceiptBytes: ByteArray get() = execution.copyOf()
    val prefixAssessmentReceiptBytes: ByteArray get() = prefix.copyOf()
}

internal class GccBundledPreparedOperation internal constructor(
    val intent: GccBundledOperationIntent,
    private val inputs: GccBundledOperationInputs,
    private val journal: GccBundledOperationJournal,
    private val lease: FullTreeDiskScratchLease,
    private val runRoot: FullTreeDiskScratchRunRoot,
    private val directories: Map<String, LinuxFileIdentity>,
    definitionBytes: ByteArray,
    constructionPermit: Any,
) : AutoCloseable {
    val authority: String = "gcc-bundled-live-prepared-operation-v1"
    val complete: Boolean = false
    val startAuthorized: Boolean = false
    val releaseEligible: Boolean = false
    private val definition = definitionBytes.copyOf()
    private val prepared = journal.preparedBytes
    private val diskEvidence = lease.evidence.canonicalBytes()
    private var closed = false
    private var poisoned = false
    private var executionAttempted = false
    private var retainedInterruption: GccBundledInterruptedOperation? = null
    private var resumeAttempted = false
    private var retainedExport: GccBundledInterruptedExportSnapshot? = null
    private var retainedControlIdentity: LinuxFileIdentity? = null
    private var retainedTrigger: GccBundledCheckpointTrigger? = null
    private var pendingCleanup: KotlinSystemdCgroupCommandCleanup? = null

    val definitionBytes: ByteArray
        get() = definition.copyOf()
    val preparedReceiptBytes: ByteArray
        get() = prepared.copyOf()
    val diskEvidenceBytes: ByteArray
        get() = diskEvidence.copyOf()

    init {
        check(constructionPermit === GCC_BUNDLED_PREPARED_OPERATION_PERMIT) { "GCC prepared operation requires retained coordinator ownership" }
    }

    @Synchronized
    fun requireCurrent() {
        check(!closed && !poisoned) { "GCC bundled prepared operation is closed or poisoned" }
        check(!executionAttempted) { "GCC bundled prepared operation has already entered execution" }
        try {
            inputs.verify("before prepared operation revalidation")
            journal.verify("before prepared operation revalidation")
            requirePreparedLayout()
            inputs.verify("after prepared operation revalidation")
            journal.verify("after prepared operation revalidation")
            requirePreparedLayout()
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    @Synchronized
    fun execute(): GccBundledExecutedOperation = executeRun(GccCompilerEngineContainmentRunKind.FRESH_CONTROL, null) { borrowed, execution ->
        val receipt = journal.recordExecution(execution.canonicalBytes)
        val captured = borrowed.withPinnedDescriptor { descriptor ->
            GccBundledExportCapture.capture(descriptor, directories.getValue("reports"), intent.artifacts)
        }
        inputs.verify("after GCC export capture")
        lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
        val exportReceipt = journal.recordExportAssessment(captured.canonicalBytes)
        GccBundledExecutedOperation(receipt, exportReceipt, captured.assessment)
    }

    @Synchronized
    fun executeUntilCheckpoint(minimumCompletedFunctions: Long): GccBundledInterruptedOperation {
        val trigger = GccBundledCheckpointTrigger(minimumCompletedFunctions)
        var stoppedExport: GccBundledInterruptedExportSnapshot? = null
        var stoppedControl: LinuxFileIdentity? = null
        return executeRun(GccCompilerEngineContainmentRunKind.INTERRUPTED, trigger) { borrowed, execution ->
            val receipt = journal.recordInterruptedExecution(execution.canonicalBytes)
            val snapshot = borrowed.withPinnedDescriptor { descriptor ->
                GccBundledExportCapture.captureInterruptedSnapshot(descriptor, directories.getValue("reports"), intent.artifacts)
            }
            val prefix = snapshot.assessment
            val assessment = trigger.assessStoppedPrefix(prefix, snapshot.planningPrefixSha256, snapshot.inFlightArtifacts)
            stoppedExport = snapshot
            stoppedControl = execution.controlDirectoryIdentity
            inputs.verify("after GCC interrupted prefix capture")
            lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
            val prefixReceipt = journal.recordInterruptedPrefixAssessment(assessment)
            val state = borrowed.withPinnedDescriptor { descriptor ->
                GccBundledAnalysisStateCapture.capture(descriptor, directories.getValue("state"), analysisStateLimits())
            }
            inputs.verify("after stopped GCC analysis-state capture")
            lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
            val stateReceipt = journal.recordInterruptedAnalysisState(state)
            GccBundledInterruptedOperation(receipt, prefixReceipt, prefix, state, stateReceipt)
        }.also {
            retainedInterruption = it
            retainedTrigger = trigger
            retainedExport = checkNotNull(stoppedExport)
            retainedControlIdentity = stoppedControl
        }
    }

    /** Retained-owner check only; does not authorize another START or accept detached checkpoint bytes. */
    @Synchronized
    fun requireInterruptedStateCurrent() {
        check(!closed && !poisoned) { "GCC bundled prepared operation is closed or poisoned" }
        check(!resumeAttempted) { "GCC operation has already entered resume" }
        val retained = checkNotNull(retainedInterruption) { "GCC operation has no retained completed interruption" }
        try {
            inputs.verify("before retained GCC checkpoint revalidation")
            journal.verify("before retained GCC checkpoint revalidation")
            lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
            lease.withCurrentOperationRunRootBeforeLaunch(runRoot) { borrowed ->
                requireRetainedCheckpoint(borrowed, retained)
            }
            inputs.verify("after retained GCC checkpoint revalidation")
            journal.verify("after retained GCC checkpoint revalidation")
            lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    private fun requireRetainedCheckpoint(borrowed: FullTreeDiskScratchBorrowedRunRoot, retained: GccBundledInterruptedOperation) {
        borrowed.withPinnedDescriptor { descriptor ->
            GccBundledAnalysisStateCapture.requireUnchanged(
                descriptor, directories.getValue("state"), retained.analysisState, analysisStateLimits(),
            )
            val current = GccBundledExportCapture.captureInterruptedSnapshot(descriptor, directories.getValue("reports"), intent.artifacts)
            checkNotNull(retainedTrigger).requireUnchangedStoppedPrefix(retained.assessment, current.assessment)
            val expected = checkNotNull(retainedExport)
            require(current.planningPrefixSha256 == expected.planningPrefixSha256 &&
                current.inFlightArtifacts.contentEquals(expected.inFlightArtifacts)) {
                "GCC retained checkpoint or in-flight fragment bytes changed"
            }
        }
    }

    /** One second execution under the same live owner; detached receipts cannot authorize resume. */
    @Synchronized
    fun resume(): GccBundledExecutedOperation {
        requireInterruptedStateCurrent()
        require(intent.bundledRuntime.invocationVersion == 3) { "GCC resume requires an interrupted v3 control layout" }
        val retained = checkNotNull(retainedInterruption)
        val prefix = checkNotNull(retainedExport)
        val oldControl = checkNotNull(retainedControlIdentity) { "GCC interruption lacks its retained control identity" }
        resumeAttempted = true
        try {
            val original = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definition)
            val runtime = GccBundledGhidraRuntime(intent.bundledRuntime.root, intent.bundledRuntime.classPath, invocationVersion = 4)
            val state = original.analysisState.copy(mode = GccCompilerEngineAnalysisStateMode.RESUME_MANIFEST,
                manifestSha256 = retained.analysisState.sha256, entryCount = retained.analysisState.entryCount,
                totalBytes = retained.analysisState.totalBytes)
            val resumedBytes = GccCompilerEngineContainmentContract.assessDefinition(GccCompilerEngineContainmentRequest(
                original.engineId, GccCompilerEngineContainmentRunKind.RESUMED, original.artifacts, state,
                runtime.command(original.artifacts, state, original.outputLease), original.environment,
                original.outputLease, original.budgets, runtime,
            )).canonicalBytes
            val resumed = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(resumedBytes)
            val configuration = deriveRuntimeConfiguration(resumed, inputs.classPathEntries)
            val runtimeMount = FullTreeFunctionObservationRuntimeMount(runtime.root, runtime.root,
                calculateFullTreeObservationRuntimeManifestSha256(runtime.root))
            val mountedInputs = intent.artifacts.filter { it.role in setOf(
                GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY, GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE,
            ) }.map { KotlinSystemdCgroupCommandInput(it.path, it.bytes, it.sha256) }
            journal.recordResumePrepared(resumedBytes)
            return lease.withCurrentOperationRunRootForContainedExecution(runRoot) { borrowed ->
                requireRetainedCheckpoint(borrowed, retained)
                val stateIdentity = borrowed.withPinnedDescriptor { descriptor ->
                    LinuxFilesystemSyscalls.openDirectoryAt(descriptor.fd, "state").use { it.identity }
                }
                val execution = KotlinSystemdCgroupCommandLauncher.execute(
                    borrowed = borrowed, configuration = configuration, unitName = resumed.unitName,
                    expectedControlGroup = resumed.expectedControlGroup, nonce = resumed.bindingSha256,
                    command = resumed.command, environment = resumed.environment, readOnlyInputs = mountedInputs,
                    runtimeMounts = listOf(runtimeMount), resources = KotlinSystemdCgroupCommandResources(
                        resumed.budgets.wallClockMillis, resumed.budgets.maximumResidentBytes, resumed.budgets.pidsMax,
                        minOf(intent.diskPolicy.maximumFilesystemBytes, 1024L * 1024 * 1024),
                    ), deploymentClosureSha256 = inputs.deploymentClosureSha256,
                    controlDirectoryName = runtime.resumeControlDirectoryName(state, resumed.outputLease),
                    readOnlyControlDirectories = mapOf(checkNotNull(intent.bundledRuntime.freshControlDirectoryName(borrowed.path)) to oldControl),
                    readOnlyStateDirectory = stateIdentity,
                    beforeStart = { attachment ->
                        inputs.verify("before GCC resume START")
                        journal.verify("before GCC resume START")
                        lease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                        requireRetainedCheckpoint(borrowed, retained)
                        journal.recordResumeAttachment(attachment.canonicalBytes)
                        journal.recordResumeStartAuthorization()
                        inputs.verify("after durable GCC resume START authorization")
                        requireRetainedCheckpoint(borrowed, retained)
                        journal.verify("before GCC resume START delivery")
                        lease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                    },
                )
                lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
                inputs.verify("after GCC resume and cgroup absence")
                val receipt = journal.recordResumeExecution(execution.canonicalBytes)
                val captured = borrowed.withPinnedDescriptor { descriptor ->
                    GccBundledAnalysisStateCapture.requireUnchanged(descriptor, directories.getValue("state"), retained.analysisState, analysisStateLimits())
                    GccBundledExportCapture.captureResumed(descriptor, directories.getValue("reports"), intent.artifacts, prefix)
                }
                inputs.verify("after resumed GCC export capture")
                lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
                val exportReceipt = journal.recordResumeExportAssessment(captured.canonicalBytes)
                GccBundledExecutedOperation(receipt, exportReceipt, captured.assessment)
            }
        } catch (failure: Throwable) {
            poisoned = true
            if (failure is KotlinSystemdCgroupCommandExecutionException) pendingCleanup = failure.cleanup
            throw failure
        }
    }

    private fun analysisStateLimits() = GccAnalysisStateCaptureLimits(
        maximumEntries = minOf(intent.diskPolicy.maximumFilesystemInodes, 32768L).toInt(),
        maximumTotalBytes = intent.diskPolicy.maximumFilesystemBytes,
        maximumWallMillis = intent.budgets.wallClockMillis,
    )

    private fun <T> executeRun(
        kind: GccCompilerEngineContainmentRunKind,
        trigger: GccBundledCheckpointTrigger?,
        afterAbsence: (FullTreeDiskScratchBorrowedRunRoot, KotlinSystemdCgroupCommandExecution) -> T,
    ): T {
        requireCurrent()
        require(intent.runKind == kind) { "GCC bundled execution kind differs from the prepared intent" }
        require(intent.bundledRuntime.invocationVersion in 2..3) { "GCC contained execution requires explicitly bound JVM home and temporary paths" }
        executionAttempted = true
        try {
            val validated = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definition)
            val configuration = deriveRuntimeConfiguration(validated, inputs.classPathEntries)
            val bundle = intent.bundledRuntime.root
            val runtimeMount = FullTreeFunctionObservationRuntimeMount(
                bundle, bundle, calculateFullTreeObservationRuntimeManifestSha256(bundle),
            )
            val mountedInputs = intent.artifacts.filter { it.role in setOf(
                GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY,
                GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE,
            ) }.map { KotlinSystemdCgroupCommandInput(it.path, it.bytes, it.sha256) }
            return lease.withCurrentOperationRunRootForContainedExecution(runRoot) { borrowed ->
                val interruption = trigger?.let { selected -> KotlinContainedCommandInterruption(
                    selected.policyBytes,
                    pollTrigger = {
                        selected.observe(borrowed.withPinnedDescriptor { descriptor ->
                            GccBundledExportCapture.observeProgress(descriptor, directories.getValue("reports"), intent.artifacts)
                        })
                    },
                    authorizeDurably = { authorization ->
                        inputs.verify("before GCC interruption authorization")
                        lease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                        journal.recordInterruptionAuthorization(authorization)
                        inputs.verify("after durable GCC interruption authorization")
                        journal.verify("before GCC interruption delivery")
                        lease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                    },
                ) }
                val execution = KotlinSystemdCgroupCommandLauncher.execute(
                    borrowed = borrowed,
                    configuration = configuration,
                    unitName = validated.unitName,
                    expectedControlGroup = validated.expectedControlGroup,
                    nonce = validated.bindingSha256,
                    command = validated.command,
                    environment = validated.environment,
                    readOnlyInputs = mountedInputs,
                    runtimeMounts = listOf(runtimeMount),
                    resources = KotlinSystemdCgroupCommandResources(
                        intent.budgets.wallClockMillis, intent.budgets.maximumResidentBytes, intent.budgets.pidsMax,
                        minOf(intent.diskPolicy.maximumFilesystemBytes, 1024L * 1024 * 1024),
                    ),
                    deploymentClosureSha256 = inputs.deploymentClosureSha256,
                    interruption = interruption,
                    controlDirectoryName = intent.bundledRuntime.freshControlDirectoryName(borrowed.path),
                    beforeStart = { attachment ->
                        inputs.verify("before GCC command START")
                        lease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                        journal.recordAttachment(attachment.canonicalBytes)
                        journal.recordStartAuthorization()
                        inputs.verify("after durable GCC command START authorization")
                        journal.verify("before GCC command START delivery")
                        lease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                    },
                )
                lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
                inputs.verify("after GCC command and cgroup absence")
                afterAbsence(borrowed, execution)
            }
        } catch (failure: Throwable) {
            poisoned = true
            if (failure is KotlinSystemdCgroupCommandExecutionException) pendingCleanup = failure.cleanup
            throw failure
        }
    }

    private fun requirePreparedLayout() {
        lease.withCurrentOperationRunRootBeforeLaunch(runRoot) { borrowed ->
            borrowed.withPinnedDescriptor { descriptor ->
                require(LinuxFilesystemSyscalls.directoryEntryNames(descriptor, directories.size + 1).toSet() == directories.keys) {
                    "GCC prepared run membership changed"
                }
                for ((name, expected) in directories) {
                    LinuxFilesystemSyscalls.openDirectoryAt(descriptor.fd, name).use { selected ->
                        require(LinuxFilesystemSyscalls.identity(selected.fd) == expected &&
                            LinuxFilesystemSyscalls.directoryEntryNames(selected, 1).isEmpty()
                        ) { "GCC prepared $name directory changed" }
                    }
                }
            }
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        pendingCleanup?.let { cleanup ->
            cleanup.closeAndProveAbsent()
            check(cleanup.absenceProved) { "GCC bundled command absence remains unproved; retaining disk and input ownership" }
            pendingCleanup = null
        }
        closed = true
        var failure: Throwable? = null
        fun record(next: Throwable) {
            val first = failure
            if (first == null) failure = next else if (next !== first) first.addSuppressed(next)
        }
        runCatching { lease.abandonForRecovery() }.exceptionOrNull()?.let(::record)
        runCatching { journal.close() }.exceptionOrNull()?.let(::record)
        runCatching { inputs.close() }.exceptionOrNull()?.let(::record)
        failure?.let { throw it }
    }
}

internal object GccBundledOperationCoordinator {
    fun prepareNew(
        intent: GccBundledOperationIntent,
        journalRoot: Path,
        provisionedMount: Path,
    ): GccBundledPreparedOperation {
        requireGccBundledOperationPath(journalRoot)
        requireGccBundledOperationPath(provisionedMount)
        require(journalRoot.toRealPath() == journalRoot && provisionedMount.toRealPath() == provisionedMount) {
            "GCC bundled operation roots must be canonical existing directories"
        }
        require(!journalRoot.startsWith(provisionedMount) && !provisionedMount.startsWith(journalRoot)) {
            "GCC bundled journal and dedicated scratch must be disjoint"
        }
        var inputs: GccBundledOperationInputs? = null
        var journal: GccBundledOperationJournal? = null
        var lease: FullTreeDiskScratchLease? = null
        try {
            val openedInputs = GccBundledOperationInputs.open(intent, listOf(journalRoot, provisionedMount))
            inputs = openedInputs
            val openedJournal = GccBundledOperationJournal.create(journalRoot, intent.operationId, intent.canonicalBytes)
            journal = openedJournal
            val openedLease = FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(provisionedMount, intent.diskOperation(), intent.diskPolicy)
            lease = openedLease
            openedInputs.verify("before GCC dedicated lease publication")
            openedLease.requireCurrent(FullTreeDiskScratchStage.AUTHORIZED)
            openedJournal.recordLease(openedLease.evidence)
            openedLease.requireCurrent(FullTreeDiskScratchStage.AUTHORIZED)
            val runRoot = openedLease.createEmptyOperationRunRoot()
            val directories = linkedMapOf<String, LinuxFileIdentity>()
            val definition = openedLease.withCurrentOperationRunRootBeforeLaunch(runRoot) { borrowed ->
                borrowed.withPinnedDescriptor { descriptor ->
                    require(LinuxFilesystemSyscalls.directoryEntryNames(descriptor, 1).isEmpty()) { "new GCC prepared run is not empty" }
                    for (name in listOf("state", "reports", "tmp")) {
                        LinuxFilesystemSyscalls.createDirectory(descriptor.fd, name, 448)
                        LinuxFilesystemSyscalls.openDirectoryAt(descriptor.fd, name).use { child ->
                            LinuxFilesystemSyscalls.chmod(child, 448)
                            val identity = LinuxFilesystemSyscalls.identity(child.fd)
                            require(identity.uid == descriptor.identity.uid && identity.mountId == descriptor.identity.mountId &&
                                identity.mode.permissions == 448 && identity.isDirectory && !identity.isSymbolicLink &&
                                LinuxFilesystemSyscalls.directoryEntryNames(child, 1).isEmpty()
                            ) { "new GCC prepared directory is not private on the dedicated mount" }
                            LinuxFilesystemSyscalls.synchronize(child)
                            directories[name] = identity
                        }
                    }
                    LinuxFilesystemSyscalls.synchronize(descriptor)
                    val identity = LinuxFilesystemSyscalls.identity(descriptor.fd)
                    val policy = intent.diskPolicy
                    val output = GccCompilerEngineOutputLeaseIdentity(
                        borrowed.path, identity.key.device, identity.key.inode, identity.mountId,
                        identity.uid, identity.gid, identity.mode.permissions, policy.requiredAvailableBytes,
                        policy.maximumFilesystemBytes, policy.requiredAvailableInodes, policy.maximumFilesystemInodes,
                    )
                    val state = GccCompilerEngineAnalysisStateIdentity(
                        GccCompilerEngineAnalysisStateMode.FRESH_EMPTY, borrowed.path.resolve("state"), null, 0, 0,
                    )
                    GccCompilerEngineContainmentContract.assessDefinition(GccCompilerEngineContainmentRequest(
                        intent.engineId, intent.runKind, intent.artifacts, state,
                        intent.bundledRuntime.command(intent.artifacts, state, output), intent.environment,
                        output, intent.budgets, intent.bundledRuntime,
                    )).canonicalBytes
                }
            }
            openedInputs.verify("before GCC prepared operation publication")
            openedJournal.recordPrepared(definition, openedInputs.deploymentClosureSha256)
            val prepared = GccBundledPreparedOperation(
                intent, openedInputs, openedJournal, openedLease, runRoot,
                java.util.Map.copyOf(directories), definition, GCC_BUNDLED_PREPARED_OPERATION_PERMIT,
            )
            prepared.requireCurrent()
            inputs = null
            journal = null
            lease = null
            return prepared
        } catch (failure: Throwable) {
            runCatching { lease?.abandonForRecovery() }.exceptionOrNull()?.takeIf { it !== failure }?.let(failure::addSuppressed)
            runCatching { journal?.close() }.exceptionOrNull()?.takeIf { it !== failure }?.let(failure::addSuppressed)
            runCatching { inputs?.close() }.exceptionOrNull()?.takeIf { it !== failure }?.let(failure::addSuppressed)
            throw failure
        }
    }
}
