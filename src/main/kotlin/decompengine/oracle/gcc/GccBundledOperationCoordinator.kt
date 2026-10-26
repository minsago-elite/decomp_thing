package decompengine.oracle.gcc

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.fulltree.ContainedCommandOperationDeadline
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.structural.StructuralBoundaryReplayRequestV1
import decompengine.oracle.structural.StructuralBoundaryReplayWorkerV1
import decompengine.oracle.structural.StructuralProductionReplayContract
import decompengine.oracle.structural.StructuralReplayAdapterRegistry
import decompengine.oracle.structural.VerifiedStructuralInputsV1
import decompengine.oracle.structural.FrozenNativeRecoveredCallPopulationV1
import decompengine.oracle.structural.StructuralSelectedBoundaryProjectionV1
import decompengine.oracle.structural.StructuralNativeExternalCallProjectionV1
import decompengine.oracle.structural.StructuralNativeExternalCallProjectionResultV1
import decompengine.oracle.machinecalls.IndependentMachineCallRequestV1
import decompengine.oracle.machinecalls.IndependentMachineCallWorkerV1
import decompengine.oracle.machinecalls.MachineCallFileV1
import decompengine.oracle.machinecalls.MachineCallLimitsV1
import decompengine.oracle.machinecalls.MachineCallRuntimeV1
import decompengine.oracle.externalcalls.*
import decompengine.oracle.fulltree.StableControlFile
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
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
import decompengine.oracle.fulltree.KotlinContainedCommandRetainedInput
import decompengine.oracle.fulltree.ContainedCommandRetainedInputVisibility
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandInput
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandLauncher
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandResources
import decompengine.oracle.fulltree.calculateFullTreeObservationRuntimeManifestSha256
import decompengine.oracle.fulltree.OracleNativeLibraries
import decompengine.oracle.fulltree.isolatedObservationJvmTemporaryArguments
import java.nio.file.Path

private object GCC_BUNDLED_PREPARED_OPERATION_PERMIT

internal fun requireGccFullExportBindingMatchesOperation(
    binding: GccDriverStructuralFullExportBindingV2,
    exported: GccBundledFullExportOperation,
    operationId: String,
) {
    val snapshot = exported.snapshot
    val bindingBytes = binding.canonicalBytes
    require(OracleArtifacts.sha256(bindingBytes) == binding.sha256) {
        "structural full-export binding bytes differ from their digest"
    }
    val bound = OracleJson.parseCanonical(bindingBytes) as JsonObject
    val boundModel = bound.getValue("programModel") as JsonObject
    val boundLineage = bound.getValue("receiptLineage") as JsonObject
    require(boundModel["sha256"] == JsonPrimitive(snapshot.programModelSha256) &&
        boundModel["bytes"] == JsonPrimitive(snapshot.programModelBytes) &&
        boundModel["functionCount"] == JsonPrimitive(snapshot.functionCount) &&
        bound["outputTreeSha256"] == JsonPrimitive(snapshot.outputTreeSha256) &&
        boundLineage["operationId"] == JsonPrimitive(operationId) &&
        boundLineage["intentSha256"] == JsonPrimitive(OracleArtifacts.sha256(exported.intentBytes)) &&
        boundLineage["executionReceiptSha256"] ==
            JsonPrimitive(OracleArtifacts.sha256(exported.executionReceiptBytes)) &&
        boundLineage["exportAssessmentReceiptSha256"] ==
            JsonPrimitive(OracleArtifacts.sha256(exported.exportAssessmentReceiptBytes))
    ) { "structural full-export binding belongs to a different contained operation" }
}

internal class GccBundledPlannedOperation(executionReceipt: ByteArray, assessmentReceipt: ByteArray,
    captured: GccBundledCapturedPlannerOutput) {
    private val execution = executionReceipt.copyOf()
    private val assessment = assessmentReceipt.copyOf()
    private val plan = captured.planBytes
    val executionReceiptBytes: ByteArray get() = execution.copyOf()
    val plannerAssessmentReceiptBytes: ByteArray get() = assessment.copyOf()
    val planBytes: ByteArray get() = plan.copyOf()
    val complete: Boolean = false
    val releaseEligible: Boolean = false
}

internal class GccBundledExecutedOperation(
    executionReceiptBytes: ByteArray,
    exportAssessmentReceiptBytes: ByteArray,
    private val captured: GccBundledExportAssessment,
) {
    val assessment: GccCompletedRunAssessment get() = captured.assessment
    /** Exact bytes captured and validated before the execution result was returned. */
    val programModelBytes: ByteArray get() = captured.programModelBytes
    val complete: Boolean = false
    val releaseEligible: Boolean = false
    private val execution = executionReceiptBytes.copyOf()
    private val exportAssessment = exportAssessmentReceiptBytes.copyOf()
    val executionReceiptBytes: ByteArray get() = execution.copyOf()
    val exportAssessmentReceiptBytes: ByteArray get() = exportAssessment.copyOf()
}

internal class GccBundledFullExportOperation(
    intentBytes: ByteArray,
    executionReceiptBytes: ByteArray,
    exportAssessmentReceiptBytes: ByteArray,
    val snapshot: GccBundledFullExportSnapshot,
    constructionPermit: Any,
) {
    val complete: Boolean = false
    val releaseEligible: Boolean = false
    private val intent = intentBytes.copyOf()
    private val execution = executionReceiptBytes.copyOf()
    private val exportAssessment = exportAssessmentReceiptBytes.copyOf()
    val intentBytes: ByteArray get() = intent.copyOf()
    val executionReceiptBytes: ByteArray get() = execution.copyOf()
    val exportAssessmentReceiptBytes: ByteArray get() = exportAssessment.copyOf()

    init {
        check(constructionPermit === GCC_BUNDLED_PREPARED_OPERATION_PERMIT) {
            "GCC full export requires retained coordinator ownership"
        }
    }
}

/** Issued only after a second contained worker replays the frozen recovered model. */
internal class GccBundledStructuralReplayOperation(
    val profile: GccDriverStructuralInputsV1,
    val export: GccDriverStructuralAuthenticatedFullExportV1,
    val request: StructuralBoundaryReplayRequestV1,
    val capture: GccBundledStructuralReplayCapture,
    attachmentBytes: ByteArray,
    executionBytes: ByteArray,
    constructionPermit: Any,
) {
    private val attachment = attachmentBytes.copyOf()
    private val execution = executionBytes.copyOf()
    val attachmentBytes: ByteArray get() = attachment.copyOf()
    val executionBytes: ByteArray get() = execution.copyOf()
    init {
        check(constructionPermit === GCC_BUNDLED_PREPARED_OPERATION_PERMIT) {
            "structural replay requires retained live coordinator ownership"
        }
    }
}

/** Host-owned recovery selection, issued before any boundary/profile oracle is opened. */
internal class GccBundledNativeClaimFreezeOperation(
    val native: GccBundledNativeCallOperation,
    val population: FrozenNativeRecoveredCallPopulationV1,
    val externalClaims: FrozenNativeExternalClaimsSnapshotV1,
    constructionPermit: Any,
) {
    private val binding: ByteArray
    val canonicalBytes: ByteArray get() = binding.copyOf()
    val claimsSha256: String
    init {
        check(constructionPermit === GCC_BUNDLED_PREPARED_OPERATION_PERMIT) {
            "native claim freeze requires retained live coordinator ownership"
        }
        val summary = native.snapshot.summary
        require(population.observationsSha256 == summary.observationsSha256 &&
            population.rawObservationBytes.size.toLong() == summary.observationsBytes &&
            population.rawManifestBytes.contentEquals(native.snapshot.manifestBytes) &&
            population.programModelSha256 == native.model.programModelSha256 &&
            population.programModelBytes == native.model.programModelBytes &&
            population.inputSha256 == native.model.inputSha256 &&
            population.rawRecordCount == summary.records && population.rawSiteCount.toLong() == summary.scanSummary.sites) {
            "native claim freeze substitutes its exact captured model, observations or census"
        }
        requireGccDualNativeFreezeMatches(population, externalClaims, summary.bindings)
        claimsSha256 = OracleArtifacts.sha256(population.canonicalEvidenceBytes)
        binding = OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-native-recovered-claim-freeze-v2"), "schemaVersion" to JsonPrimitive(2),
            "phase" to JsonPrimitive("after-native-absence-before-boundary-oracle"),
            "nativeBindingSha256" to JsonPrimitive(OracleArtifacts.sha256(GccNativeCallReceiptLineage.createBinding(native))),
            "inputSha256" to JsonPrimitive(population.inputSha256),
            "programModelSha256" to JsonPrimitive(population.programModelSha256),
            "programModelBytes" to JsonPrimitive(native.model.programModelBytes),
            "nativeObservationsSha256" to JsonPrimitive(population.observationsSha256),
            "nativeObservationsBytes" to JsonPrimitive(summary.observationsBytes),
            "nativeManifestSha256" to JsonPrimitive(OracleArtifacts.sha256(native.snapshot.manifestBytes)),
            "rawRecordCount" to JsonPrimitive(population.rawRecordCount), "rawSiteCount" to JsonPrimitive(population.rawSiteCount),
            "claimsSha256" to JsonPrimitive(claimsSha256),
            "externalClaimsSha256" to JsonPrimitive(externalClaims.evidenceSha256),
            "externalClaimsBytes" to JsonPrimitive(externalClaims.evidenceBytes),
            "externalClaimsPolicySha256" to JsonPrimitive(externalClaims.policySha256),
            "callAuthority" to JsonPrimitive("unavailable-pending-population-and-external-composition"),
            "negativeCompleteness" to JsonPrimitive(false), "scored" to JsonPrimitive(false),
            "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
        )))
    }
}

/** Real post-freeze producer execution. Call-domain scoring is deliberately not granted here. */
internal class GccBundledMachineCallReplayOperation(
    val frozenNativeClaims: GccBundledNativeClaimFreezeOperation,
    val selectedInputs: VerifiedStructuralInputsV1,
    val request: IndependentMachineCallRequestV1,
    val capture: GccBundledMachineCallReplayCapture,
    attachmentBytes: ByteArray,
    executionBytes: ByteArray,
    constructionPermit: Any,
) {
    val native: GccBundledNativeCallOperation get() = frozenNativeClaims.native
    private val attachment = attachmentBytes.copyOf()
    private val execution = executionBytes.copyOf()
    private val projectedPopulation: ByteArray
    val attachmentBytes: ByteArray get() = attachment.copyOf()
    val executionBytes: ByteArray get() = execution.copyOf()
    val projectedPopulationBytes: ByteArray get() = projectedPopulation.copyOf()
    init {
        check(constructionPermit === GCC_BUNDLED_PREPARED_OPERATION_PERMIT) {
            "independent machine-call replay requires retained live coordinator ownership"
        }
        require(selectedInputs.inputSha256 == native.model.inputSha256 &&
            selectedInputs.programModelSha256 == native.model.programModelSha256 &&
            selectedInputs.programModelBytes == native.model.programModelBytes) {
            "independent producer mapping differs from the paired native model"
        }
        projectedPopulation = frozenNativeClaims.population.project(StructuralSelectedBoundaryProjectionV1.project(selectedInputs))
        require(OracleArtifacts.sha256(frozenNativeClaims.population.canonicalEvidenceBytes) == frozenNativeClaims.claimsSha256)
    }
}

/** Same-process combined execution. Held source descriptors remain live through final publication. */
internal class GccBundledExternalCallReplayOperation(
    val machine: GccBundledMachineCallReplayOperation,
    val independentRequest: IndependentExternalCallRequestV1,
    val recoveredRequest: RecoveredExternalNamespaceRequestV1,
    val independentCapture: GccBundledExternalCallReplayCapture,
    val recoveredCapture: GccBundledExternalCallReplayCapture,
    independentAttachment: ByteArray, independentExecution: ByteArray,
    recoveredAttachment: ByteArray, recoveredExecution: ByteArray,
    val pair: ElfExternalNamespacePairV1,
    heldSources: List<StableControlFile>,
    private val deadline: ContainedCommandOperationDeadline,
    constructionPermit: Any,
) : AutoCloseable {
    private val sources = heldSources.toList()
    private val ia = independentAttachment.copyOf()
    private val ie = independentExecution.copyOf()
    private val ra = recoveredAttachment.copyOf()
    private val re = recoveredExecution.copyOf()
    private var closed = false
    val projection: StructuralNativeExternalCallProjectionResultV1
    val independentAttachmentBytes: ByteArray get() = ia.copyOf()
    val independentExecutionBytes: ByteArray get() = ie.copyOf()
    val recoveredAttachmentBytes: ByteArray get() = ra.copyOf()
    val recoveredExecutionBytes: ByteArray get() = re.copyOf()
    init {
        check(constructionPermit === GCC_BUNDLED_PREPARED_OPERATION_PERMIT) {
            "external call replay requires retained live coordinator ownership"
        }
        require(independentRequest.sourceReport.sha256 == OracleArtifacts.sha256(machine.capture.reportBytes) &&
            independentRequest.sourceRequest.sha256 == OracleArtifacts.sha256(machine.request.canonicalBytes) &&
            independentRequest.runtime == machine.request.runtime && recoveredRequest.runtime == machine.request.runtime &&
            recoveredRequest.expectedNativeBindings == machine.native.snapshot.summary.bindings &&
            independentRequest.richFile == machine.request.richFile && recoveredRequest.richFile == machine.request.richFile)
        requireGccExternalExecutionLineage(independentRequest.canonicalBytes, ia, ie)
        requireGccExternalExecutionLineage(recoveredRequest.canonicalBytes, ra, re)
        requireCurrent()
        projection = StructuralNativeExternalCallProjectionV1.project(machine.frozenNativeClaims.population,
            machine.frozenNativeClaims.externalClaims, StructuralSelectedBoundaryProjectionV1.project(machine.selectedInputs),
            machine.capture.reportBytes, independentCapture.reportBytes, recoveredCapture.reportBytes, pair.richNamespace) { deadline.requireCurrent() }
        requireCurrent()
    }
    fun requireCurrent() {
        check(!closed)
        deadline.requireCurrent()
        pair.requireCurrent()
        sources.forEach { it.verifyUnchanged("external call retained source") }
        // Callback-free metadata pass after the final descriptor hashing callback.
        requireFinalMetadata()
    }
    fun requireFinalMetadata() {
        check(!closed)
        sources.forEach { it.requirePathAndIdentity("external call final source identity") }
    }
    override fun close() {
        if (!closed) {
            closed = true
            var failure: Throwable? = null
            sources.asReversed().forEach { source -> try { source.close() } catch (e: Throwable) {
                if (failure == null) failure = e else failure!!.addSuppressed(e)
            } }
            failure?.let { throw it }
        }
    }
}

/** Retained native collection provenance; no scored or release authority is granted. */
internal class GccBundledNativeCallOperation(
    intentBytes: ByteArray,
    executionReceiptBytes: ByteArray,
    nativeAssessmentReceiptBytes: ByteArray,
    val model: GccBundledFullExportSnapshot,
    val snapshot: GccBundledNativeCallSnapshot,
    constructionPermit: Any,
) {
    val complete = false
    val scored = false
    val releaseEligible = false
    private val intent = intentBytes.copyOf()
    private val execution = executionReceiptBytes.copyOf()
    private val assessment = nativeAssessmentReceiptBytes.copyOf()
    val intentBytes: ByteArray get() = intent.copyOf()
    val executionReceiptBytes: ByteArray get() = execution.copyOf()
    val nativeAssessmentReceiptBytes: ByteArray get() = assessment.copyOf()

    init {
        check(constructionPermit === GCC_BUNDLED_PREPARED_OPERATION_PERMIT) {
            "GCC native call operation requires retained coordinator ownership"
        }
        val selected = OracleJson.parseCanonical(intent).let { it as JsonObject }
        require(selected["engineId"] == JsonPrimitive(snapshot.target.engineId) &&
            snapshot.target.inputSha256 == model.inputSha256 && snapshot.target.inputBytes == model.inputBytes &&
            snapshot.summary.bindings.programModelSha256 == model.programModelSha256 &&
            snapshot.summary.bindings.programModelBytes == model.programModelBytes) {
            "native operation differs from its retained target or paired model"
        }
    }
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
    private var operationDeadline: ContainedCommandOperationDeadline? = null
    private var retainedInterruption: GccBundledInterruptedOperation? = null
    private var resumeAttempted = false
    private var retainedExport: GccBundledInterruptedExportSnapshot? = null
    private var retainedControlIdentity: LinuxFileIdentity? = null
    private var retainedTrigger: GccBundledCheckpointTrigger? = null
    private var pendingCleanup: KotlinSystemdCgroupCommandCleanup? = null
    private var completedExport: GccBundledExecutedOperation? = null
    private var completedFullExport: GccBundledFullExportOperation? = null
    private var completedNativeCalls: GccBundledNativeCallOperation? = null
    private var completedInterfaces: GccBundledInterfaceOperation? = null
    private var pendingInterfaceToken: Any? = null
    private var pendingInterfaceIssuance: GccBundledInterfaceIssuanceV1? = null
    private val completedControls = linkedMapOf<String, LinuxFileIdentity>()
    private var plannerAttempted = false
    private var completedPlan: GccBundledPlannedOperation? = null
    private var cliPublicationAttempted = false

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
    fun execute(): GccBundledExecutedOperation {
        check(intent.bundledRuntime.recoveryMode == "planning") { "planning execution cannot consume a full-recovery runtime" }
        return executeRun(GccCompilerEngineContainmentRunKind.FRESH_CONTROL, null) { borrowed, execution ->
            val receipt = journal.recordExecution(execution.canonicalBytes)
            val captured = borrowed.withPinnedDescriptor { descriptor ->
                GccBundledExportCapture.capture(descriptor, directories.getValue("reports"), intent.artifacts)
            }
            inputs.verify("after GCC export capture")
            lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
            val exportReceipt = journal.recordExportAssessment(bindWallTime(captured.canonicalBytes))
            GccBundledExecutedOperation(receipt, exportReceipt, captured)
        }.also { completedExport = it }
    }

    /** Executes the versioned full-recovery exporter and snapshots its output after worker absence. */
    @Synchronized
    fun executeFullExport(): GccBundledFullExportOperation {
        intent.requireFullExportExecution()
        return executeRun(GccCompilerEngineContainmentRunKind.FRESH_CONTROL, null) { borrowed, execution ->
            val receipt = journal.recordExecution(execution.canonicalBytes)
            val captured = borrowed.withPinnedDescriptor { descriptor ->
                GccBundledFullExportCapture.capture(descriptor, directories.getValue("reports"), intent.artifacts,
                    expectedDecompilerWorkers = intent.bundledRuntime.decompilerWorkerCount)
            }
            inputs.verify("after GCC full export snapshot")
            lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
            val exportReceipt = journal.recordExportAssessment(bindWallTime(captured.assessmentBytes))
            GccBundledFullExportOperation(
                intent.canonicalBytes, receipt, exportReceipt, captured,
                GCC_BUNDLED_PREPARED_OPERATION_PERMIT,
            )
        }.also { completedFullExport = it }
    }

    /** Diagnostic execution produces only contained execution evidence, never a full-export capability. */
    @Synchronized
    fun executeRuntimeDiagnostic(): Path {
        check(intent.bundledRuntime.runtimeDiagnostics) { "runtime diagnostics require the explicit diagnostic runtime" }
        return executeRun(GccCompilerEngineContainmentRunKind.FRESH_CONTROL, null) { _, execution ->
            journal.recordExecution(execution.canonicalBytes)
            inputs.verify("after GCC diagnostic execution")
            lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
            journal.path.resolve("execution.json")
        }
    }

    /** Captures both outputs only after the contained worker and its cgroup are absent. */
    @Synchronized
    fun executeNativeCallObservations(): GccBundledNativeCallOperation {
        check(intent.bundledRuntime.invocationVersion == 8 && intent.engineId in setOf("cc1", "driver") &&
            intent.runKind == GccCompilerEngineContainmentRunKind.FRESH_CONTROL && intent.cliInvocation != null
        ) { "native observations require the retained fresh pinned cc1 or driver CLI operation" }
        return executeRun(GccCompilerEngineContainmentRunKind.FRESH_CONTROL, null) { borrowed, execution ->
            val receipt = journal.recordExecution(execution.canonicalBytes)
            val deadline = checkNotNull(operationDeadline)
            val target = inputs.nativeCallTargetEvidence { deadline.requireCurrent() }
            val captured = borrowed.withPinnedDescriptor { descriptor ->
                val model = GccBundledFullExportCapture.captureWithNativeCallSibling(
                    descriptor, directories.getValue("reports"), intent.artifacts,
                    checkpoint = { deadline.requireCurrent() },
                )
                val controlName = checkNotNull(intent.bundledRuntime.freshControlDirectoryName(borrowed.path))
                val native = GccBundledNativeCallCapture.capture(
                    descriptor, directories.getValue("reports"), controlName,
                    checkNotNull(execution.controlDirectoryIdentity), model,
                    checkNotNull(intent.bundledRuntime.nativeCallCollector).sourceSha256, target,
                    checkpoint = { deadline.requireCurrent() },
                )
                model to native
            }
            inputs.verify("after GCC native call snapshot")
            lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
            val assessment = journal.recordExportAssessment(bindWallTime(captured.second.assessmentBytes))
            GccBundledNativeCallOperation(intent.canonicalBytes, receipt, assessment,
                captured.first, captured.second, GCC_BUNDLED_PREPARED_OPERATION_PERMIT)
        }.also { completedNativeCalls = it }
    }

    /** This route freezes only recovered observations; it opens no structural or interface oracle. */
    @Synchronized
    fun executeInterfaceObservations(): GccBundledInterfaceOperation {
        intent.requireInterfaceExecution()
        GccBundledOperationCoordinator.requireFactoryInterfaceOwner(this)
        return executeRun(GccCompilerEngineContainmentRunKind.FRESH_CONTROL, null) { borrowed, execution ->
            val receipt = journal.recordExecution(execution.canonicalBytes)
            val deadline = checkNotNull(operationDeadline)
            val target = inputs.interfaceTargetEvidence { deadline.requireCurrent() }
            val component = checkNotNull(intent.bundledRuntime.interfaceCollector)
            val runtime = GccBundledInterfaceCaptureBindingsV1(component.listingCollectorSha256,
                component.inferredCollectorSha256, component.typeGraphSha256, component.wrapperSha256,
                component.nativeDecompilerSha256, inputs.deploymentClosureSha256,
                inputs.ghidraRuntimeIdentitySha256, component.closureSha256)
            val captured = borrowed.withPinnedDescriptor { descriptor ->
                GccBundledInferredInterfaceCapture.capture(descriptor, directories.getValue("reports"),
                    checkNotNull(intent.bundledRuntime.freshControlDirectoryName(borrowed.path)),
                    checkNotNull(execution.controlDirectoryIdentity), intent.artifacts, target, runtime,
                    checkpoint = { deadline.requireCurrent() })
            }
            inputs.verify("after complete interface capture")
            lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
            val assessment = journal.recordExportAssessment(bindWallTime(captured.assessmentBytes))
            journal.verify("before interface operation issuance")
            inputs.verify("before interface operation issuance")
            lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
            borrowed.withPinnedDescriptor { descriptor ->
                GccBundledInferredInterfaceCapture.requireUnchanged(descriptor, captured, intent.artifacts) {
                    deadline.requireCurrent()
                }
            }
            // No mutable callback follows the complete capture sweep. The unobservable token
            // exists only while this synchronized owner transitions the exact capture once.
            val token = Any()
            check(pendingInterfaceToken == null && pendingInterfaceIssuance == null && completedInterfaces == null)
            pendingInterfaceToken = token
            pendingInterfaceIssuance = GccBundledInterfaceIssuanceV1(captured, intent.canonicalBytes, receipt, assessment)
            try {
                GccBundledOperationCoordinator.issueInterfaceOperation(this, token)
            } finally {
                pendingInterfaceToken = null
                pendingInterfaceIssuance = null
            }
        }.also { completedInterfaces = it }
    }

    /** Called only after factory membership checks; a guessed or reused token cannot claim data. */
    @Synchronized
    internal fun takeInterfaceIssuance(token: Any): GccBundledInterfaceIssuanceV1 {
        check(!closed && !poisoned && executionAttempted && completedInterfaces == null)
        intent.requireInterfaceExecution()
        check(pendingInterfaceToken != null && pendingInterfaceToken === token) { "interface capture was not issued by this live owner" }
        val pending = checkNotNull(pendingInterfaceIssuance)
        pendingInterfaceToken = null
        pendingInterfaceIssuance = null
        return pending
    }

    @Synchronized
    internal fun requireCompletedInterfaceOperation(operation: GccBundledInterfaceOperation) {
        check(!closed && !poisoned && completedInterfaces === operation && pendingInterfaceToken == null &&
            pendingInterfaceIssuance == null) { "interface operation is not the live owner's completed capture" }
        intent.requireInterfaceExecution()
    }

    @Synchronized
    internal fun requireInterfaceOwnerClosed() {
        check(closed && pendingInterfaceToken == null && pendingInterfaceIssuance == null) {
            "interface owner membership may be revoked only after closure"
        }
    }

    @Synchronized
    fun executeUntilCheckpoint(minimumCompletedFunctions: Long): GccBundledInterruptedOperation {
        check(intent.bundledRuntime.invocationVersion !in setOf(8, 9)) { "native observation collection does not support checkpoint or resume" }
        intent.cliInvocation?.requireCheckpointSelection(minimumCompletedFunctions)
        val trigger = GccBundledCheckpointTrigger(minimumCompletedFunctions)
        var stoppedExport: GccBundledInterruptedExportSnapshot? = null
        var stoppedControl: LinuxFileIdentity? = null
        return executeRun(GccCompilerEngineContainmentRunKind.INTERRUPTED, trigger) { borrowed, execution ->
            val receipt = journal.recordInterruptedExecution(execution.canonicalBytes)
            val snapshot = borrowed.withPinnedDescriptor { descriptor ->
                GccBundledExportCapture.captureInterruptedSnapshot(descriptor, directories.getValue("reports"), intent.artifacts)
            }
            val prefix = snapshot.assessment
            val assessment = trigger.assessStoppedPrefix(prefix, snapshot.planningPrefixSha256, snapshot.inFlightArtifacts,
                snapshot.capturedProgress, snapshot.effectiveProgress)
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
        operationDeadline?.requireCurrent()
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
                current.inFlightArtifacts.contentEquals(expected.inFlightArtifacts) &&
                checkNotNull(current.capturedProgress).contentEquals(checkNotNull(expected.capturedProgress))) {
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
                runtime.command(original.artifacts, state, original.outputLease, GccCompilerEngineContainmentRunKind.RESUMED), original.environment,
                original.outputLease, original.budgets.copy(wallClockMillis = checkNotNull(operationDeadline)
                    .remainingWholeSecondsMillis(original.budgets.wallClockMillis)), runtime,
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
                        checkNotNull(operationDeadline).remainingWholeSecondsMillis(resumed.budgets.wallClockMillis),
                        resumed.budgets.maximumResidentBytes, resumed.budgets.pidsMax,
                        minOf(intent.diskPolicy.maximumFilesystemBytes, 1024L * 1024 * 1024),
                    ), deploymentClosureSha256 = inputs.deploymentClosureSha256,
                    controlDirectoryName = runtime.resumeControlDirectoryName(state, resumed.outputLease),
                    readOnlyControlDirectories = mapOf(checkNotNull(intent.bundledRuntime.freshControlDirectoryName(borrowed.path)) to oldControl),
                    readOnlyStateDirectory = stateIdentity,
                    operationDeadline = operationDeadline,
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
                val exportReceipt = journal.recordResumeExportAssessment(bindWallTime(captured.canonicalBytes))
                completedControls[runtime.resumeControlDirectoryName(state, resumed.outputLease)] =
                    checkNotNull(execution.controlDirectoryIdentity)
                GccBundledExecutedOperation(receipt, exportReceipt, captured)
            }.also { checkNotNull(operationDeadline).requireCurrent(); completedExport = it }
        } catch (failure: Throwable) {
            poisoned = true
            if (failure is KotlinSystemdCgroupCommandExecutionException) pendingCleanup = failure.cleanup
            throw failure
        }
    }

    /** Plans only this owner's successfully captured export; detached results cannot authorize execution. */
    @Synchronized
    fun plan(): GccBundledPlannedOperation {
        check(!closed && !poisoned && !plannerAttempted) { "GCC planner owner is closed, poisoned, or already used" }
        val exported = checkNotNull(completedExport) { "GCC planning requires this owner's completed export" }
        check(intent.bundledRuntime.invocationVersion == 3) { "GCC planning requires separate retained control directories" }
        plannerAttempted = true
        try {
            val deadline = checkNotNull(operationDeadline)
            deadline.requireCurrent()
            inputs.verify("before GCC planner preparation")
            journal.verify("before GCC planner preparation")
            lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
            val original = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definition)
            val configuration = deriveRuntimeConfiguration(original, inputs.classPathEntries)
            val controlName = gccBundledPlannerControlName(intent.requestSha256, OracleArtifacts.sha256(exported.exportAssessmentReceiptBytes))
            val controlPath = original.outputLease.path.resolve(controlName)
            val request = inputs.plannerRequest(intent, exported, original.outputLease.path.resolve("reports/program_model.json"),
                controlPath.resolve("reports"))
            val requestBytes = request.canonicalBytes
            val requestSha = OracleArtifacts.sha256(requestBytes)
            val requestPath = journal.path.resolve("planner-request.json")
            val runtime = intent.bundledRuntime.root
            val runtimeMount = FullTreeFunctionObservationRuntimeMount(runtime, runtime,
                calculateFullTreeObservationRuntimeManifestSha256(runtime))
            val unit = "decomp-gcc-planner-${requestSha.take(32)}.scope"
            val command = listOf(configuration.javaExecutable.toString(),
                "-Xmx${intent.budgets.maximumResidentBytes / (1024 * 1024) * 3 / 4}m", "-XX:+DisableAttachMechanism",
                "-Duser.home=${controlPath.resolve("state")}", "-Djava.io.tmpdir=${controlPath.resolve("tmp")}",
                "-cp", inputs.classPathEntries.indices.joinToString(java.io.File.pathSeparator) {
                    controlPath.resolve("runtime/classpath-$it.jar").toString()
                }, GccBundledPlannerWorker::class.java.name, requestPath.toString(), requestSha)
            journal.recordPlannerPrepared(requestBytes)
            return lease.withCurrentOperationRunRootForContainedExecution(runRoot) { borrowed ->
                fun requireCapturedModel() {
                    deadline.requireCurrent()
                    val current = borrowed.withPinnedDescriptor { descriptor ->
                        val prefix = retainedExport
                        if (prefix == null) GccBundledExportCapture.capture(descriptor, directories.getValue("reports"), intent.artifacts)
                        else GccBundledExportCapture.captureResumed(descriptor, directories.getValue("reports"), intent.artifacts, prefix)
                    }
                    require(current.programModelBytes.contentEquals(exported.programModelBytes)) { "GCC captured model changed before planning" }
                    deadline.requireCurrent()
                }
                requireCapturedModel()
                val protectedDirectories = borrowed.withPinnedDescriptor { descriptor ->
                    listOf("state", "reports").associateWith { name ->
                        LinuxFilesystemSyscalls.openDirectoryAt(descriptor.fd, name).use { it.identity }
                    }
                }
                val maximumFileBytes = minOf(intent.diskPolicy.maximumFilesystemBytes, 1024L * 1024 * 1024)
                val execution = KotlinSystemdCgroupCommandLauncher.execute(
                    borrowed, configuration, unit, original.expectedControlGroup.substringBeforeLast('/') + "/" + unit,
                    requestSha, command, original.environment,
                    listOf(KotlinSystemdCgroupCommandInput(requestPath, requestBytes.size.toLong(), requestSha)),
                    listOf(runtimeMount), KotlinSystemdCgroupCommandResources(
                        deadline.remainingWholeSecondsMillis(intent.budgets.wallClockMillis), intent.budgets.maximumResidentBytes,
                        intent.budgets.pidsMax, maximumFileBytes), inputs.deploymentClosureSha256,
                    controlDirectoryName = controlName, readOnlyControlDirectories = completedControls.toMap(),
                    readOnlyStateDirectory = protectedDirectories.getValue("state"),
                    readOnlyReportsDirectory = protectedDirectories.getValue("reports"), operationDeadline = deadline,
                    beforeStart = { attachment ->
                        inputs.verify("before GCC planner START")
                        journal.verify("before GCC planner START")
                        lease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                        requireCapturedModel()
                        journal.recordPlannerAttachment(attachment.canonicalBytes)
                        journal.recordPlannerStartAuthorization()
                        inputs.verify("after durable GCC planner START authorization")
                        requireCapturedModel()
                        journal.verify("before GCC planner START delivery")
                        lease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                        deadline.requireCurrent()
                    },
                )
                lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
                inputs.verify("after GCC planner and cgroup absence")
                val executionReceipt = journal.recordPlannerExecution(execution.canonicalBytes)
                val logLimit = minOf(maximumFileBytes, 64L * 1024 * 1024).toInt()
                deadline.requireCurrent()
                val capturedModel = exported.programModelBytes
                deadline.requireCurrent()
                val captured = borrowed.withPinnedDescriptor { descriptor ->
                    GccBundledPlannerOutputCapture.capture(descriptor, controlName, checkNotNull(execution.controlDirectoryIdentity),
                        request, capturedModel, logLimit, logLimit) { deadline.requireCurrent() }
                }
                inputs.verify("after GCC planner output capture")
                lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
                val assessmentReceipt = journal.recordPlannerAssessment(bindWallTime(captured.canonicalBytes))
                GccBundledPlannedOperation(executionReceipt, assessmentReceipt, captured)
            }.also { deadline.requireCurrent(); completedPlan = it }
        } catch (failure: Throwable) {
            poisoned = true
            if (failure is KotlinSystemdCgroupCommandExecutionException) pendingCleanup = failure.cleanup
            throw failure
        }
    }

    /** Publishes bounded result pointers under the same owner/deadline; model and plan remain on the leased scratch. */
    @Synchronized
    fun publishCliResult(): Path {
        check(!closed && !poisoned && !cliPublicationAttempted)
        val cli = checkNotNull(intent.cliInvocation) { "operation has no bound CLI output" }
        val exported = checkNotNull(completedExport)
        val planned = checkNotNull(completedPlan) { "operation has no completed owned plan" }
        cliPublicationAttempted = true
        try {
            val deadline = checkNotNull(operationDeadline)
            deadline.requireCurrent()
            inputs.verify("before CLI result publication")
            journal.verify("before CLI result publication")
            lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
            val original = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definition)
            val plannerControl = gccBundledPlannerControlName(intent.requestSha256, OracleArtifacts.sha256(exported.exportAssessmentReceiptBytes))
            val document = OracleJson.canonicalBytes(JsonObject(mapOf(
                "provider" to JsonPrimitive("gcc-bundled-cli-result-v1"), "schemaVersion" to JsonPrimitive(1),
                "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
                "operationId" to JsonPrimitive(intent.operationId), "requestSha256" to JsonPrimitive(intent.requestSha256),
                "journal" to JsonPrimitive(journal.path.toString()),
                "programModel" to JsonPrimitive(original.outputLease.path.resolve("reports/program_model.json").toString()),
                "programModelSha256" to JsonPrimitive(exported.assessment.programModelSha256),
                "modulePlan" to JsonPrimitive(original.outputLease.path.resolve(plannerControl).resolve("reports/module_plan.json").toString()),
                "modulePlanSha256" to JsonPrimitive(OracleArtifacts.sha256(planned.planBytes)),
                "exportReceiptSha256" to JsonPrimitive(OracleArtifacts.sha256(exported.exportAssessmentReceiptBytes)),
                "plannerExecutionReceiptSha256" to JsonPrimitive(OracleArtifacts.sha256(planned.executionReceiptBytes)),
                "plannerAssessmentReceiptSha256" to JsonPrimitive(OracleArtifacts.sha256(planned.plannerAssessmentReceiptBytes)),
                "operationWallTime" to deadline.snapshot(),
                "scratchDisposition" to JsonPrimitive("retained; release and cold recovery unqualified"),
            )))
            LinuxFilesystemSyscalls.openRoot(cli.options.output).use { output ->
                cli.requireCurrent()
                decompengine.oracle.core.DescriptorBoundAtomicStateFile.publishNoReplace(output, "result.json", document, 256 * 1024)
                cli.requireCurrent()
            }
            inputs.verify("after CLI result publication")
            journal.verify("after CLI result publication")
            lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
            deadline.requireCurrent()
            return cli.options.output.resolve("result.json")
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    /** Oracle truth is admitted only after recovery stopped and its complete model was frozen. */
    private fun replayFullExportBoundary(
        snapshot: GccBundledFullExportSnapshot,
        authenticated: GccDriverStructuralAuthenticatedFullExportV1,
        nativeFreeze: GccBundledNativeClaimFreezeOperation? = null,
    ): VerifiedStructuralInputsV1 {
        val cli = checkNotNull(intent.cliInvocation)
        val deadline = checkNotNull(operationDeadline)
        val nativeOperation = nativeFreeze?.native
        authenticated.requireSameSnapshot(snapshot)
        require(nativeOperation == null || nativeOperation.model === snapshot) {
            "native boundary replay must use its exact paired model snapshot"
        }
        val profile = GccDriverStructuralInputsV1.load(cli.options.profile.parent, "driver")
        val oraclePath = profile.root.resolve("function-recovery-oracle.json")
        val oracleBytes = 12_558_460
        val original = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definition)
        val configuration = deriveRuntimeConfiguration(original, inputs.classPathEntries)
        val controlName = "control-" + OracleArtifacts.sha256(
            ("structural-boundary-replay-v1\n" + intent.requestSha256 + "\n" + authenticated.binding.sha256).toByteArray(),
        )
        val controlPath = original.outputLease.path.resolve(controlName)
        val request = StructuralBoundaryReplayRequestV1(
            original.outputLease.path.resolve("reports/program_model.json"),
            Math.toIntExact(authenticated.programModelBytes), authenticated.programModelSha256,
            profile.strippedBinary.sha256, oraclePath, oracleBytes,
            GccDriverStructuralBoundaryEvidenceV1.FUNCTION_ORACLE_SHA256, profile.imageBase,
            controlPath.resolve("reports"), intent.requestSha256, authenticated.binding.sha256,
        )
        val requestBytes = request.canonicalBytes
        val requestSha = OracleArtifacts.sha256(requestBytes)
        val requestPath = cli.options.output.resolve("structural-replay-request.json")
        fun publish(name: String, bytes: ByteArray) {
            deadline.requireCurrent()
            LinuxFilesystemSyscalls.openRoot(cli.options.output).use { output ->
                cli.requireCurrent()
                DescriptorBoundAtomicStateFile.publishNoReplace(output, name, bytes, 256 * 1024)
                cli.requireCurrent()
            }
            deadline.requireCurrent()
        }
        publish(requestPath.fileName.toString(), requestBytes)
        val runtime = intent.bundledRuntime.root
        val runtimeMount = FullTreeFunctionObservationRuntimeMount(runtime, runtime,
            calculateFullTreeObservationRuntimeManifestSha256(runtime))
        val unit = "decomp-structural-${requestSha.take(32)}.scope"
        val command = listOf(configuration.javaExecutable.toString(),
            "-Xmx${minOf(intent.budgets.maximumResidentBytes / (1024 * 1024) * 3 / 4, 3072)}m",
            "-XX:+DisableAttachMechanism", "-Duser.home=${controlPath.resolve("state")}",
            "-Djava.io.tmpdir=${controlPath.resolve("tmp")}", "-cp",
            inputs.classPathEntries.indices.joinToString(java.io.File.pathSeparator) {
                controlPath.resolve("runtime/classpath-$it.jar").toString()
            }, StructuralBoundaryReplayWorkerV1::class.java.name, requestPath.toString(), requestSha)
        try {
            return lease.withCurrentOperationRunRootForContainedExecution(runRoot) { borrowed ->
                val frozenReports = borrowed.withPinnedDescriptor { run ->
                    GccBundledReplayReportsV1.capture(run, directories.getValue("reports"), nativeOperation != null)
                }
                fun requireFrozenModel() {
                    deadline.requireCurrent()
                    inputs.verify("before structural replay")
                    journal.verify("before structural replay")
                    borrowed.withPinnedDescriptor { run ->
                        nativeOperation?.let { native ->
                            GccBundledNativeCallCapture.requireUnchanged(run, native.snapshot, native.model,
                                intent.artifacts, checkpoint = { deadline.requireCurrent() })
                        }
                        LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { reports ->
                            frozenReports.requireCurrent(reports)
                            val files = GccBoundExportFiles(authenticated.programModelBytes) { deadline.requireCurrent() }
                            val actual = files.read(reports, "program_model.json", request.modelBytes)
                            require(actual.size == request.modelBytes && OracleArtifacts.sha256(actual) == request.modelSha256) {
                                "structural replay model differs from the immutable recovered snapshot"
                            }
                            files.verify()
                            frozenReports.requireCurrent(reports)
                        }
                    }
                }
                requireFrozenModel()
                val protectedDirectories = borrowed.withPinnedDescriptor { run ->
                    listOf("state", "reports").associateWith { name ->
                        LinuxFilesystemSyscalls.openDirectoryAt(run.fd, name).use { it.identity }
                    }
                }
                var attachmentBytes: ByteArray? = null
                val execution = KotlinSystemdCgroupCommandLauncher.execute(
                    borrowed, configuration, unit, original.expectedControlGroup.substringBeforeLast('/') + "/" + unit,
                    requestSha, command, original.environment,
                    listOf(KotlinSystemdCgroupCommandInput(requestPath, requestBytes.size.toLong(), requestSha),
                        KotlinSystemdCgroupCommandInput(oraclePath, oracleBytes.toLong(), request.functionOracleSha256)),
                    listOf(runtimeMount), KotlinSystemdCgroupCommandResources(
                        deadline.remainingWholeSecondsMillis(minOf(intent.budgets.wallClockMillis, 300_000)),
                        minOf(intent.budgets.maximumResidentBytes, 4L * 1024 * 1024 * 1024),
                        intent.budgets.pidsMax, GccBundledStructuralReplayOutputCapture.MAXIMUM_OBSERVATION_BYTES.toLong()),
                    inputs.deploymentClosureSha256, controlDirectoryName = controlName,
                    readOnlyControlDirectories = completedControls.toMap(),
                    readOnlyStateDirectory = protectedDirectories.getValue("state"),
                    readOnlyReportsDirectory = protectedDirectories.getValue("reports"), operationDeadline = deadline,
                    beforeStart = { attachment ->
                        lease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                        requireFrozenModel()
                        attachmentBytes = attachment.canonicalBytes
                        publish("structural-replay-attachment.json", attachment.canonicalBytes)
                        publish("structural-replay-start-authorized.json", OracleJson.canonicalBytes(JsonObject(mapOf(
                            "provider" to JsonPrimitive("structural-replay-start-authorized-v1"),
                            "operationRequestSha256" to JsonPrimitive(intent.requestSha256),
                            "requestSha256" to JsonPrimitive(requestSha),
                            "attachmentSha256" to JsonPrimitive(OracleArtifacts.sha256(attachment.canonicalBytes)),
                            "fullExportBindingSha256" to JsonPrimitive(authenticated.binding.sha256),
                        ) + (nativeFreeze?.let { mapOf("nativeClaimFreezeSha256" to
                            JsonPrimitive(OracleArtifacts.sha256(it.canonicalBytes))) } ?: emptyMap()))))
                        requireFrozenModel()
                        lease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                    },
                )
                lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
                requireFrozenModel()
                publish("structural-replay-execution.json", execution.canonicalBytes)
                val captured = borrowed.withPinnedDescriptor { run ->
                    GccBundledStructuralReplayOutputCapture.capture(run, controlName,
                        checkNotNull(execution.controlDirectoryIdentity), request) { deadline.requireCurrent() }
                }
                lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
                requireFrozenModel()
                publish("structural-replay-output.json", captured.metadataBytes)
                publish("structural-replay-capture.json", captured.assessmentBytes)
                completedControls[controlName] = checkNotNull(execution.controlDirectoryIdentity)
                val replay = GccBundledStructuralReplayOperation(profile, authenticated, request, captured,
                    checkNotNull(attachmentBytes), execution.canonicalBytes, GCC_BUNDLED_PREPARED_OPERATION_PERMIT)
                StructuralReplayAdapterRegistry.production.admitSelectedBoundary(replay).also { deadline.requireCurrent() }
            }
        } catch (failure: Throwable) {
            poisoned = true
            if (failure is KotlinSystemdCgroupCommandExecutionException) pendingCleanup = failure.cleanup
            throw failure
        }
    }

    /** Publishes the immutable model; only supported, independently replayed dimensions are scored. */
    @Synchronized
    fun publishFullExportCliResult(authenticatedExport: GccDriverStructuralAuthenticatedFullExportV1): Path {
        check(!closed && !poisoned && !cliPublicationAttempted)
        check(intent.bundledRuntime.recoveryMode == "full" && intent.bundledRuntime.invocationVersion in setOf(5, 6)) {
            "structural binding publication requires a full-recovery operation"
        }
        val cli = checkNotNull(intent.cliInvocation) { "operation has no bound CLI output" }
        val exported = checkNotNull(completedFullExport) { "operation has no captured full export" }
        cliPublicationAttempted = true
        try {
            val deadline = checkNotNull(operationDeadline)
            deadline.requireCurrent()
            inputs.verify("before full-export binding publication")
            journal.verify("before full-export binding publication")
            lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
            val original = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definition)
            val snapshot = exported.snapshot
            authenticatedExport.requireSameSnapshot(snapshot)
            check(!authenticatedExport.scored && !authenticatedExport.releaseEligible) {
                "full-export input provenance cannot grant score or release authority"
            }
            val binding = authenticatedExport.binding
            requireGccFullExportBindingMatchesOperation(binding, exported, intent.operationId)
            val bindingBytes = binding.canonicalBytes
            val bindingName = "structural-full-export-binding.json"
            val manifestName = GccBundledFullExportCliResultV2.TREE_MANIFEST_NAME
            val manifestBytes = snapshot.sidecarManifest
            val modelPath = original.outputLease.path.resolve("reports/program_model.json")
            val bindingPath = cli.options.output.resolve(bindingName)
            val manifestPath = cli.options.output.resolve(manifestName)
            val boundaryEvidence = if (intent.engineId == "driver") {
                GccDriverStructuralBoundaryEvidenceV1.capture(
                    GccDriverStructuralInputsV1.load(cli.options.profile.parent, "driver"), authenticatedExport,
                )
            } else null
            val verifiedBoundaryInputs = if (boundaryEvidence != null) {
                replayFullExportBoundary(exported.snapshot, authenticatedExport).also { verified ->
                    val scored = OracleJson.parse(StructuralProductionReplayContract.scoreSelectedBoundary(verified),
                        GccBundledFullExportCliResultV2.TREE_MANIFEST_JSON_LIMITS) as JsonObject
                    require(scored["boundaryObservationSha256"] == JsonPrimitive(
                        OracleArtifacts.sha256(boundaryEvidence.observationBytes))) {
                        "contained boundary replay differs from independent host observation"
                    }
                }
            } else null
            deadline.requireCurrent()
            val resultBytes = GccBundledFullExportCliResultV2.create(
                operationId = intent.operationId,
                requestSha256 = intent.requestSha256,
                journalPath = journal.path,
                programModelPath = modelPath,
                programModelSha256 = snapshot.programModelSha256,
                programModelBytes = snapshot.programModelBytes,
                functionCount = snapshot.functionCount,
                exportAssessmentReceiptSha256 = OracleArtifacts.sha256(exported.exportAssessmentReceiptBytes),
                executionReceiptSha256 = OracleArtifacts.sha256(exported.executionReceiptBytes),
                structuralBindingPath = bindingPath,
                structuralBindingBytes = bindingBytes,
                treeManifestPath = manifestPath,
                treeManifestBytes = manifestBytes,
                outputTreeSha256 = snapshot.outputTreeSha256,
                operationWallTime = deadline.snapshot(),
                verifiedBoundaryInputs = verifiedBoundaryInputs,
            )
            LinuxFilesystemSyscalls.openRoot(cli.options.output).use { output ->
                cli.requireCurrent()
                DescriptorBoundAtomicStateFile.publishManifestNoReplace(
                    output,
                    manifestName,
                    manifestBytes,
                    GccBundledFullExportCliResultV2.MAXIMUM_TREE_MANIFEST_BYTES,
                )
                cli.requireCurrent()
                DescriptorBoundAtomicStateFile.publishNoReplace(output, bindingName, bindingBytes, 256 * 1024)
                boundaryEvidence?.let { evidence ->
                    authenticatedExport.requireSameSnapshot(snapshot)
                    cli.requireCurrent()
                    DescriptorBoundAtomicStateFile.publishManifestNoReplace(
                        output, GccDriverStructuralBoundaryEvidenceV1.OBSERVATION_NAME,
                        evidence.observationBytes, GccDriverStructuralBoundaryEvidenceV1.MAXIMUM_OBSERVATION_BYTES,
                    )
                    cli.requireCurrent()
                    DescriptorBoundAtomicStateFile.publishNoReplace(
                        output, GccDriverStructuralBoundaryEvidenceV1.BINDING_NAME,
                        evidence.bindingBytes, GccDriverStructuralBoundaryEvidenceV1.MAXIMUM_BINDING_BYTES,
                    )
                }
                verifiedBoundaryInputs?.let { verified ->
                    authenticatedExport.requireSameSnapshot(snapshot)
                    cli.requireCurrent()
                    DescriptorBoundAtomicStateFile.publishManifestNoReplace(output,
                        GccBundledFullExportCliResultV2.PRODUCTION_BOUNDARY_SCORE_NAME,
                        StructuralProductionReplayContract.scoreSelectedBoundary(verified),
                        GccBundledStructuralReplayOutputCapture.MAXIMUM_OBSERVATION_BYTES)
                    cli.requireCurrent()
                    DescriptorBoundAtomicStateFile.publishManifestNoReplace(output,
                        GccDriverProductionFunctionAccuracyV1.SCORE_NAME,
                        GccDriverProductionFunctionAccuracyV1.create(verified),
                        GccBundledStructuralReplayOutputCapture.MAXIMUM_OBSERVATION_BYTES)
                }
                inputs.verify("after full-export binding publication")
                journal.verify("after full-export binding publication")
                lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
                deadline.requireCurrent()
                DescriptorBoundAtomicStateFile.publishNoReplace(output, "result.json", resultBytes, 256 * 1024)
                cli.requireCurrent()
            }
            inputs.verify("after full-export result publication")
            journal.verify("after full-export result publication")
            lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
            deadline.requireCurrent()
            return cli.options.output.resolve("result.json")
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    /** Introduces rich/oracle inputs only after the recovered native population has been frozen. */
    private fun replayNativeMachineCalls(
        frozenNativeClaims: GccBundledNativeClaimFreezeOperation,
        selected: VerifiedStructuralInputsV1,
        profile: GccDriverStructuralInputsV1,
    ): GccBundledMachineCallReplayOperation {
        val native = frozenNativeClaims.native
        val cli = checkNotNull(intent.cliInvocation)
        val deadline = checkNotNull(operationDeadline)
        require(intent.engineId == "driver" && native.snapshot.target.engineId == "driver")
        require(selected.programModelSha256 == native.model.programModelSha256 &&
            selected.inputSha256 == profile.strippedBinary.sha256)
        val original = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definition)
        val configuration = deriveRuntimeConfiguration(original, inputs.classPathEntries)
        val nativeBinding = GccNativeCallReceiptLineage.createBinding(native)
        val controlName = "control-" + OracleArtifacts.sha256(
            ("independent-machine-calls-v1\n" + intent.requestSha256 + "\n" +
                OracleArtifacts.sha256(nativeBinding)).toByteArray())
        val controlPath = original.outputLease.path.resolve(controlName)
        fun artifact(role: GccCompilerEngineContainmentArtifactRole) = intent.artifacts.single { it.role == role }
        val archive = artifact(GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE)
        val bridge = artifact(GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR)
        val manifest = artifact(GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST)
        val request = IndependentMachineCallRequestV1(
            MachineCallFileV1(profile.root.resolve("artifacts/gcc-driver.full"), profile.fullBinary.bytes,
                profile.fullBinary.sha256),
            MachineCallFileV1(profile.root.resolve("function-recovery-oracle.json"), 12_558_460,
                GccDriverStructuralBoundaryEvidenceV1.FUNCTION_ORACLE_SHA256),
            profile.artifactManifestSha256,
            MachineCallRuntimeV1(intent.bundledRuntime.root, archive.path, archive.sha256, archive.bytes,
                bridge.sha256, manifest.sha256, "x86:LE:64:default", "4.8"),
            controlPath.resolve("reports").resolve(GccBundledMachineCallReplayOutputCapture.REPORT_NAME),
            MachineCallLimitsV1(maximumWallMillis = deadline.remainingWholeSecondsMillis(300_000)),
        )
        val requestBytes = request.canonicalBytes
        val requestSha = OracleArtifacts.sha256(requestBytes)
        val requestPath = cli.options.output.resolve("independent-machine-call-request.json")
        fun publish(name: String, bytes: ByteArray) {
            deadline.requireCurrent()
            LinuxFilesystemSyscalls.openRoot(cli.options.output).use { output ->
                cli.requireCurrent()
                DescriptorBoundAtomicStateFile.publishNoReplace(output, name, bytes, 256 * 1024)
                cli.requireCurrent()
            }
            deadline.requireCurrent()
        }
        publish(requestPath.fileName.toString(), requestBytes)
        val runtime = intent.bundledRuntime.root
        val runtimeMount = FullTreeFunctionObservationRuntimeMount(runtime, runtime,
            calculateFullTreeObservationRuntimeManifestSha256(runtime))
        val unit = "decomp-machine-calls-${requestSha.take(32)}.scope"
        val command = listOf(configuration.javaExecutable.toString(),
            "-Xmx${minOf(intent.budgets.maximumResidentBytes / (1024 * 1024) * 3 / 4, 3072)}m",
            "-XX:+DisableAttachMechanism", "-Duser.home=${controlPath.resolve("state")}") +
            isolatedObservationJvmTemporaryArguments(controlPath,
                configuration.javaRuntime.destination.resolve(OracleNativeLibraries.relativeDirectory)) + listOf("-cp",
            inputs.classPathEntries.indices.joinToString(java.io.File.pathSeparator) {
                controlPath.resolve("runtime/classpath-$it.jar").toString()
            }, IndependentMachineCallWorkerV1::class.java.name, requestPath.toString(), requestSha)
        try {
            return StableControlFile.open(request.richFile.path, request.richFile.bytes, "independent rich ELF").use { rich ->
                StableControlFile.open(request.canonicalOracle.path, request.canonicalOracle.bytes,
                    "independent canonical oracle").use { oracle ->
                    require(rich.size == request.richFile.bytes && rich.authenticatedSha256 == request.richFile.sha256 &&
                        oracle.size == request.canonicalOracle.bytes && oracle.authenticatedSha256 == request.canonicalOracle.sha256)
                    lease.withCurrentOperationRunRootForContainedExecution(runRoot) { borrowed ->
                        fun requireFrozenInputs() {
                            deadline.requireCurrent()
                            inputs.verify("independent machine-call replay")
                            journal.verify("independent machine-call replay")
                            rich.verifyUnchanged("independent machine-call rich ELF")
                            oracle.verifyUnchanged("independent machine-call canonical oracle")
                            borrowed.withPinnedDescriptor { run ->
                                GccBundledNativeCallCapture.requireUnchanged(run, native.snapshot, native.model,
                                    intent.artifacts, checkpoint = { deadline.requireCurrent() })
                            }
                            deadline.requireCurrent()
                        }
                        requireFrozenInputs()
                        val protectedDirectories = borrowed.withPinnedDescriptor { run ->
                            listOf("state", "reports").associateWith { name ->
                                LinuxFilesystemSyscalls.openDirectoryAt(run.fd, name).use { it.identity }
                            }
                        }
                        var attachmentBytes: ByteArray? = null
                        val execution = KotlinSystemdCgroupCommandLauncher.execute(
                            borrowed, configuration, unit, original.expectedControlGroup.substringBeforeLast('/') + "/" + unit,
                            requestSha, command, original.environment,
                            listOf(KotlinSystemdCgroupCommandInput(requestPath, requestBytes.size.toLong(), requestSha),
                                KotlinSystemdCgroupCommandInput(request.richFile.path, request.richFile.bytes, request.richFile.sha256),
                                KotlinSystemdCgroupCommandInput(request.canonicalOracle.path, request.canonicalOracle.bytes,
                                    request.canonicalOracle.sha256),
                                KotlinSystemdCgroupCommandInput(archive.path, archive.bytes, archive.sha256)),
                            listOf(runtimeMount), KotlinSystemdCgroupCommandResources(
                                deadline.remainingWholeSecondsMillis(request.limits.maximumWallMillis),
                                minOf(intent.budgets.maximumResidentBytes, 4L * 1024 * 1024 * 1024),
                                intent.budgets.pidsMax, request.limits.maximumOutputBytes.toLong()),
                            inputs.deploymentClosureSha256, controlDirectoryName = controlName,
                            readOnlyControlDirectories = completedControls.toMap(),
                            readOnlyStateDirectory = protectedDirectories.getValue("state"),
                            readOnlyReportsDirectory = protectedDirectories.getValue("reports"), operationDeadline = deadline,
                            retainedInputVisibility = emptyList(),
                            beforeStart = { attachment ->
                                lease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                                requireFrozenInputs()
                                attachmentBytes = attachment.canonicalBytes
                                publish("independent-machine-call-attachment.json", attachment.canonicalBytes)
                                publish("independent-machine-call-start-authorized.json", OracleJson.canonicalBytes(JsonObject(mapOf(
                                    "provider" to JsonPrimitive("independent-machine-call-start-authorized-v1"),
                                    "operationRequestSha256" to JsonPrimitive(intent.requestSha256),
                                    "requestSha256" to JsonPrimitive(requestSha),
                                    "attachmentSha256" to JsonPrimitive(OracleArtifacts.sha256(attachment.canonicalBytes)),
                                    "nativeBindingSha256" to JsonPrimitive(OracleArtifacts.sha256(nativeBinding)),
                                    "nativeClaimFreezeSha256" to JsonPrimitive(OracleArtifacts.sha256(frozenNativeClaims.canonicalBytes)),
                                    "nativeClaimsSha256" to JsonPrimitive(frozenNativeClaims.claimsSha256),
                                    "programModelSha256" to JsonPrimitive(selected.programModelSha256),
                                    "selectedBoundaryScoreSha256" to JsonPrimitive(OracleArtifacts.sha256(
                                        StructuralProductionReplayContract.scoreSelectedBoundary(selected))),
                                ))))
                                requireFrozenInputs()
                                lease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                            })
                        lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
                        requireFrozenInputs()
                        publish("independent-machine-call-execution.json", execution.canonicalBytes)
                        val captured = borrowed.withPinnedDescriptor { run ->
                            GccBundledMachineCallReplayOutputCapture.capture(run, controlName,
                                checkNotNull(execution.controlDirectoryIdentity), request) { deadline.requireCurrent() }
                        }
                        lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
                        requireFrozenInputs()
                        publish("independent-machine-call-capture.json", captured.assessmentBytes)
                        completedControls[controlName] = checkNotNull(execution.controlDirectoryIdentity)
                        GccBundledMachineCallReplayOperation(frozenNativeClaims, selected, request, captured,
                            checkNotNull(attachmentBytes), execution.canonicalBytes, GCC_BUNDLED_PREPARED_OPERATION_PERMIT)
                    }
                }
            }
        } catch (failure: Throwable) {
            poisoned = true
            if (failure is KotlinSystemdCgroupCommandExecutionException) pendingCleanup = failure.cleanup
            throw failure
        }
    }

    /** Both fixed workers consume independently selected inputs; recovery never sees call-oracle rows. */
    private fun replayNativeExternalCalls(machine: GccBundledMachineCallReplayOperation,
        profile: GccDriverStructuralInputsV1): GccBundledExternalCallReplayOperation {
        val cli = checkNotNull(intent.cliInvocation)
        val deadline = checkNotNull(operationDeadline)
        val original = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definition)
        val configuration = deriveRuntimeConfiguration(original, inputs.classPathEntries)
        val sources = arrayListOf<StableControlFile>()
        var transferred = false
        var pendingFailure: Throwable? = null
        fun hold(file: MachineCallFileV1, label: String): StableControlFile =
            StableControlFile.openWithCheckpoint(file.path, file.bytes, label, checkpoint = { deadline.requireCurrent() }).also {
                sources += it
                require(it.size == file.bytes && it.authenticatedSha256 == file.sha256)
                it.requireSingleLink(label)
            }
        fun publish(name: String, bytes: ByteArray) {
            deadline.requireCurrent()
            LinuxFilesystemSyscalls.openRoot(cli.options.output).use { output ->
                cli.requireCurrent()
                DescriptorBoundAtomicStateFile.publishNoReplace(output, name, bytes, 256 * 1024)
                cli.requireCurrent()
            }
        }
        try {
            val machineRequestPath = cli.options.output.resolve("independent-machine-call-request.json")
            val sourceRequest = MachineCallFileV1(machineRequestPath, machine.request.canonicalBytes.size.toLong(),
                OracleArtifacts.sha256(machine.request.canonicalBytes))
            val sourceReport = MachineCallFileV1(machine.request.outputPath, machine.capture.reportBytes.size.toLong(),
                OracleArtifacts.sha256(machine.capture.reportBytes))
            hold(sourceRequest, "original contained machine-call request")
            hold(sourceReport, "original contained machine-call report")
            val frozen = machine.frozenNativeClaims.externalClaims
            val nativeManifest = MachineCallFileV1(original.outputLease.path.resolve("reports/native-calls-v1/manifest.json"),
                frozen.manifestBytes, frozen.manifestSha256)
            val nativeObservations = MachineCallFileV1(original.outputLease.path.resolve("reports/native-calls-v1/native-calls.json"),
                frozen.observationBytes, frozen.observationsSha256)
            val nativeManifestFile = hold(nativeManifest, "frozen original native manifest")
            val nativeObservationFile = hold(nativeObservations, "frozen original native stream")
            // Actual held-descriptor reread is mandatory; neither saved bindings nor snapshots can replace sources.
            val refrozen = FrozenNativeExternalClaimsV1.freeze(
                nativeManifestFile.readExactly(0, Math.toIntExact(nativeManifestFile.size), "native manifest re-freeze") { deadline.requireCurrent() },
                nativeObservationFile.readExactly(0, Math.toIntExact(nativeObservationFile.size), "native stream re-freeze") { deadline.requireCurrent() },
                machine.native.snapshot.summary.bindings, checkpoint = { deadline.requireCurrent() })
            require(refrozen.canonicalEvidenceBytes.contentEquals(frozen.canonicalEvidenceBytes))
            requireGccDualNativeFreezeMatches(machine.frozenNativeClaims.population, refrozen, machine.native.snapshot.summary.bindings)
            // Profile and pair metadata are opened only after both recovery selections already exist.
            val manifestFile = StableControlFile.openWithCheckpoint(profile.root.resolve("oracle-manifest.json"), 2L * 1024 * 1024,
                "external namespace artifact manifest", checkpoint = { deadline.requireCurrent() }).also { sources += it }
            require(manifestFile.authenticatedSha256 == profile.artifactManifestSha256)
            manifestFile.requireSingleLink("external namespace artifact manifest")
            val artifactManifest = MachineCallFileV1(profile.root.resolve("oracle-manifest.json"), manifestFile.size, profile.artifactManifestSha256)
            val rich = hold(machine.request.richFile, "external namespace rich ELF")
            val strippedInput = intent.artifacts.single { it.role == GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY }
            val strippedFile = MachineCallFileV1(strippedInput.path, strippedInput.bytes, strippedInput.sha256)
            val stripped = hold(strippedFile, "external namespace stripped ELF")
            val pair = ElfExternalNamespacePairV1.prove(manifestFile, profile.artifactManifestSha256, rich, stripped,
                checkpoint = { deadline.requireCurrent() })
            return lease.withCurrentOperationRunRootForContainedExecution(runRoot) { borrowed ->
                fun requireFrozenInputs() {
                    deadline.requireCurrent()
                    inputs.verify("native external replay")
                    journal.verify("native external replay")
                    pair.requireCurrent()
                    sources.forEach { it.verifyUnchanged("native external source") }
                    borrowed.withPinnedDescriptor { run ->
                        GccBundledNativeCallCapture.requireUnchanged(run, machine.native.snapshot, machine.native.model, intent.artifacts) { deadline.requireCurrent() }
                        GccBundledMachineCallReplayOutputCapture.requireUnchanged(run, machine.capture)
                    }
                    sources.forEach { it.requirePathAndIdentity("native external final source metadata") }
                    deadline.requireCurrent()
                }
                val runtime = intent.bundledRuntime.root
                val runtimeMount = FullTreeFunctionObservationRuntimeMount(runtime, runtime,
                    calculateFullTreeObservationRuntimeManifestSha256(runtime))
                val archive = intent.artifacts.single { it.role == GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE }
                val nativeBinding = OracleArtifacts.sha256(GccNativeCallReceiptLineage.createBinding(machine.native))
                fun control(prefix: String) = "control-" + OracleArtifacts.sha256(
                    (prefix + "\n" + intent.requestSha256 + "\n" + nativeBinding).toByteArray())
                val independentControl = control("independent-external-calls-v1")
                val independent = IndependentExternalCallRequestV1(machine.request.richFile, sourceReport, sourceRequest,
                    machine.request.runtime, original.outputLease.path.resolve(independentControl).resolve("reports")
                        .resolve(GccBundledExternalCallReplayOutputCapture.INDEPENDENT_NAME),
                    ExternalCallLimitsV1(maximumWallMillis = deadline.remainingWholeSecondsMillis(300_000)))
                data class Executed(val attachment: ByteArray, val execution: ByteArray, val capture: GccBundledExternalCallReplayCapture)
                fun execute(prefix: String, controlName: String, worker: String, requestBytes: ByteArray,
                    mountedInputs: List<MachineCallFileV1>, visibleRetainedInputs: List<MachineCallFileV1>, maximumWallMillis: Long, maximumOutputBytes: Int,
                    capture: (decompengine.acp.LinuxDescriptor, LinuxFileIdentity) -> GccBundledExternalCallReplayCapture): Executed {
                    val requestSha = OracleArtifacts.sha256(requestBytes)
                    val requestPath = cli.options.output.resolve("$prefix-request.json")
                    publish(requestPath.fileName.toString(), requestBytes)
                    val path = original.outputLease.path.resolve(controlName)
                    val command = listOf(configuration.javaExecutable.toString(),
                        "-Xmx${minOf(intent.budgets.maximumResidentBytes / (1024 * 1024) * 3 / 4, 3072)}m",
                        "-XX:+DisableAttachMechanism", "-Duser.home=${path.resolve("state")}") +
                        isolatedObservationJvmTemporaryArguments(path,
                            configuration.javaRuntime.destination.resolve(OracleNativeLibraries.relativeDirectory)) + listOf("-cp",
                        inputs.classPathEntries.indices.joinToString(java.io.File.pathSeparator) {
                            path.resolve("runtime/classpath-$it.jar").toString()
                        }, worker, requestPath.toString(), requestSha)
                    requireFrozenInputs()
                    val directories = borrowed.withPinnedDescriptor { run -> listOf("state", "reports").associateWith {
                        LinuxFilesystemSyscalls.openDirectoryAt(run.fd, it).use { directory -> directory.identity }
                    } }
                    val visibility = visibleRetainedInputs.map { file ->
                        require(file.path.startsWith(original.outputLease.path))
                        KotlinContainedCommandRetainedInput(original.outputLease.path.relativize(file.path).toString(), file.bytes, file.sha256)
                    }
                    val visibilityDocument = ContainedCommandRetainedInputVisibility(controlName,
                        completedControls.keys + setOf("state", "reports"), visibility).canonicalIdentity()
                    var attachment: ByteArray? = null
                    val unit = "decomp-external-calls-${requestSha.take(32)}.scope"
                    val execution = KotlinSystemdCgroupCommandLauncher.execute(borrowed, configuration, unit,
                        original.expectedControlGroup.substringBeforeLast('/') + "/" + unit, requestSha, command, original.environment,
                        (listOf(MachineCallFileV1(requestPath, requestBytes.size.toLong(), requestSha),
                            MachineCallFileV1(archive.path, archive.bytes, archive.sha256)) + mountedInputs).distinctBy { it.path }
                            .map { KotlinSystemdCgroupCommandInput(it.path, it.bytes, it.sha256) },
                        listOf(runtimeMount), KotlinSystemdCgroupCommandResources(
                            deadline.remainingWholeSecondsMillis(maximumWallMillis),
                            minOf(intent.budgets.maximumResidentBytes, 4L * 1024 * 1024 * 1024), intent.budgets.pidsMax,
                            maximumOutputBytes.toLong()), inputs.deploymentClosureSha256,
                        controlDirectoryName = controlName, readOnlyControlDirectories = completedControls.toMap(),
                        readOnlyStateDirectory = directories.getValue("state"), readOnlyReportsDirectory = directories.getValue("reports"),
                        operationDeadline = deadline, retainedInputVisibility = visibility, beforeStart = { actual ->
                            lease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                            requireFrozenInputs()
                            attachment = actual.canonicalBytes
                            publish("$prefix-attachment.json", actual.canonicalBytes)
                            publish("$prefix-start-authorized.json", OracleJson.canonicalBytes(JsonObject(mapOf(
                                "provider" to JsonPrimitive("$prefix-start-authorized-v1"),
                                "operationRequestSha256" to JsonPrimitive(intent.requestSha256),
                                "requestSha256" to JsonPrimitive(requestSha),
                                "attachmentSha256" to JsonPrimitive(OracleArtifacts.sha256(actual.canonicalBytes)),
                                "nativeClaimFreezeSha256" to JsonPrimitive(OracleArtifacts.sha256(machine.frozenNativeClaims.canonicalBytes)),
                                "nativeExternalClaimsSha256" to JsonPrimitive(frozen.evidenceSha256),
                                "pairProofSha256" to JsonPrimitive(pair.receiptSha256),
                                "retainedInputVisibility" to visibilityDocument,
                                "retainedInputVisibilitySha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(visibilityDocument)))))))
                            requireFrozenInputs()
                            lease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                        })
                    lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
                    requireFrozenInputs()
                    publish("$prefix-execution.json", execution.canonicalBytes)
                    val captured = borrowed.withPinnedDescriptor { run -> capture(run, checkNotNull(execution.controlDirectoryIdentity)) }
                    requireFrozenInputs()
                    borrowed.withPinnedDescriptor { run -> GccBundledExternalCallReplayOutputCapture.requireUnchanged(run, captured) }
                    publish("$prefix-capture.json", captured.assessmentBytes)
                    completedControls[controlName] = checkNotNull(execution.controlDirectoryIdentity)
                    return Executed(checkNotNull(attachment), execution.canonicalBytes, captured)
                }
                // Source report is visible only through its retained read-only completed control directory.
                val independentRun = execute("independent-external-call", independentControl,
                    IndependentExternalCallWorkerV1::class.java.name, independent.canonicalBytes,
                    listOf(independent.richFile, independent.sourceRequest), listOf(independent.sourceReport), independent.limits.maximumWallMillis,
                    independent.limits.maximumOutputBytes) { run, identity ->
                    GccBundledExternalCallReplayOutputCapture.captureIndependent(run, independentControl, identity, independent) { deadline.requireCurrent() }
                }
                val recoveredControl = control("recovered-external-calls-v1")
                val recovered = RecoveredExternalNamespaceRequestV1(nativeManifest, nativeObservations, artifactManifest,
                    machine.request.richFile, strippedFile, machine.native.snapshot.summary.bindings, machine.request.runtime,
                    original.outputLease.path.resolve(recoveredControl).resolve("reports")
                        .resolve(GccBundledExternalCallReplayOutputCapture.RECOVERED_NAME),
                    RecoveredExternalNamespaceLimitsV1(maximumWallMillis = deadline.remainingWholeSecondsMillis(300_000)))
                // Raw native files are visible through the retained read-only reports directory; no call-oracle input is supplied.
                val recoveredRun = execute("recovered-external-call", recoveredControl,
                    RecoveredExternalNamespaceWorkerV1::class.java.name, recovered.canonicalBytes,
                    listOf(recovered.artifactManifest, recovered.richFile, recovered.strippedFile),
                    listOf(recovered.nativeManifest, recovered.nativeObservations), recovered.limits.maximumWallMillis,
                    recovered.limits.maximumOutputBytes) { run, identity ->
                    GccBundledExternalCallReplayOutputCapture.captureRecovered(run, recoveredControl, identity, recovered,
                        refrozen, pair) { deadline.requireCurrent() }
                }
                requireFrozenInputs()
                borrowed.withPinnedDescriptor { run ->
                    GccBundledExternalCallReplayOutputCapture.requireUnchanged(run, independentRun.capture)
                    GccBundledExternalCallReplayOutputCapture.requireUnchanged(run, recoveredRun.capture)
                }
                GccBundledExternalCallReplayOperation(machine, independent, recovered, independentRun.capture, recoveredRun.capture,
                    independentRun.attachment, independentRun.execution, recoveredRun.attachment, recoveredRun.execution,
                    pair, sources, deadline, GCC_BUNDLED_PREPARED_OPERATION_PERMIT).also { transferred = true }
            }
        } catch (failure: Throwable) {
            pendingFailure = failure
            poisoned = true
            if (failure is KotlinSystemdCgroupCommandExecutionException) pendingCleanup = failure.cleanup
            throw failure
        } finally {
            if (!transferred) {
                var closeFailure: Throwable? = null
                sources.asReversed().forEach { source -> try { source.close() } catch (failure: Throwable) {
                    if (closeFailure == null) closeFailure = failure else closeFailure!!.addSuppressed(failure)
                } }
                closeFailure?.let { failure ->
                    val primary = pendingFailure
                    if (primary == null) throw failure else primary.addSuppressed(failure)
                }
            }
        }
    }

    /** Publishes immutable raw commitments; no source/boundary/interface oracle is opened. */
    @Synchronized
    fun publishInterfaceCliResult(): Path {
        check(!closed && !poisoned && !cliPublicationAttempted)
        intent.requireInterfaceExecution()
        val cli = checkNotNull(intent.cliInvocation)
        val operation = checkNotNull(completedInterfaces) { "operation has no completed interface capture" }
        operation.requireCurrent()
        cliPublicationAttempted = true
        try {
            val deadline = checkNotNull(operationDeadline)
            val snapshot = operation.snapshot
            fun requireCapturedOutputs() {
                deadline.requireCurrent()
                operation.requireCurrent()
                inputs.verify("before interface result publication")
                journal.verify("before interface result publication")
                cli.requireCurrent()
                lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
                lease.withCurrentOperationRunRootBeforeLaunch(runRoot) { borrowed ->
                    borrowed.withPinnedDescriptor { descriptor ->
                        GccBundledInferredInterfaceCapture.requireUnchanged(descriptor, snapshot, intent.artifacts) {
                            deadline.requireCurrent()
                        }
                    }
                }
            }
            requireCapturedOutputs()
            val binding = GccBundledInterfaceCliResultV1.binding(operation)
            val treeManifest = snapshot.model.sidecarManifest
            val original = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definition)
            val result = GccBundledInterfaceCliResultV1.result(operation, binding, journal.path, original.outputLease.path,
                cli.options.output, deadline.snapshot())
            val metadataBytes = treeManifest.size.toLong() + binding.size + result.size
            require(snapshot.capturedBytes <= 1024L * 1024 * 1024 - metadataBytes) {
                "interface capture and published commitments exceed their shared byte allowance"
            }
            LinuxFilesystemSyscalls.openRoot(cli.options.output).use { output ->
                cli.requireCurrent()
                DescriptorBoundAtomicStateFile.publishNoReplace(output, GccBundledInterfaceCliResultV1.BINDING_NAME,
                    binding, GccBundledInterfaceCliResultV1.MAXIMUM_BINDING_BYTES)
                DescriptorBoundAtomicStateFile.publishManifestNoReplace(output, GccBundledFullExportCliResultV2.TREE_MANIFEST_NAME,
                    treeManifest, GccBundledFullExportCliResultV2.MAXIMUM_TREE_MANIFEST_BYTES)
                GccBundledInterfaceCliResultV1.publishResultMarker(output, result, beforeCommit = ::requireCapturedOutputs)
            }
            return cli.options.output.resolve("result.json")
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    /** Result pointers bind the unchanged model tree and native bytes under this same owner. */
    @Synchronized
    fun publishNativeCallCliResult(): Path {
        check(!closed && !poisoned && !cliPublicationAttempted)
        check(intent.bundledRuntime.invocationVersion == 8)
        val cli = checkNotNull(intent.cliInvocation)
        val operation = checkNotNull(completedNativeCalls) { "operation has no completed native capture" }
        cliPublicationAttempted = true
        var externalReplay: GccBundledExternalCallReplayOperation? = null
        try {
            val deadline = checkNotNull(operationDeadline)
            val original = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definition)
            fun requireCapturedOutputs() {
                deadline.requireCurrent()
                inputs.verify("before native result publication")
                journal.verify("before native result publication")
                lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
                lease.withCurrentOperationRunRootBeforeLaunch(runRoot) { borrowed ->
                    borrowed.withPinnedDescriptor { descriptor ->
                        GccBundledNativeCallCapture.requireUnchanged(descriptor, operation.snapshot,
                            operation.model, intent.artifacts, checkpoint = { deadline.requireCurrent() })
                    }
                }
                deadline.requireCurrent()
            }
            requireCapturedOutputs()
            val binding = GccNativeCallReceiptLineage.createBinding(operation)
            val bindingName = "native-call-observation-binding.json"
            val treeName = GccBundledFullExportCliResultV2.TREE_MANIFEST_NAME
            var boundaryEvidence: GccDriverStructuralBoundaryEvidenceV1? = null
            var selectedProfile: GccDriverStructuralInputsV1? = null
            val replay = if (intent.engineId == "driver") {
                // Recovery selection is frozen before loading profile, boundary or oracle data.
                val population = lease.withCurrentOperationRunRootBeforeLaunch(runRoot) { borrowed ->
                    borrowed.withPinnedDescriptor { run ->
                        GccBundledNativeCallCapture.freezeRecoveredClaims(run, operation.snapshot, operation.model,
                            intent.artifacts, checkpoint = { deadline.requireCurrent() })
                    }
                }
                requireCapturedOutputs()
                val externalClaims = FrozenNativeExternalClaimsV1.freeze(population.rawManifestBytes,
                    population.rawObservationBytes, operation.snapshot.summary.bindings,
                    checkpoint = { deadline.requireCurrent() })
                requireCapturedOutputs()
                val frozenClaims = GccBundledNativeClaimFreezeOperation(operation, population, externalClaims,
                    GCC_BUNDLED_PREPARED_OPERATION_PERMIT)
                requireCapturedOutputs()
                LinuxFilesystemSyscalls.openRoot(cli.options.output).use { output ->
                    cli.requireCurrent()
                    DescriptorBoundAtomicStateFile.publishManifestNoReplace(output, GccBundledNativeStructuralEvidenceV1.CLAIMS_NAME,
                        population.canonicalEvidenceBytes, 64 * 1024 * 1024)
                    DescriptorBoundAtomicStateFile.publishManifestNoReplace(output, GccBundledExternalCallEvidenceV1.EXTERNAL_CLAIMS_NAME,
                        externalClaims.canonicalEvidenceBytes, 64 * 1024 * 1024)
                    DescriptorBoundAtomicStateFile.publishNoReplace(output, GccBundledNativeStructuralEvidenceV1.FREEZE_NAME,
                        frozenClaims.canonicalBytes, 256 * 1024)
                    cli.requireCurrent()
                }
                requireCapturedOutputs()
                val profile = GccDriverStructuralInputsV1.load(cli.options.profile.parent, "driver")
                selectedProfile = profile
                val authenticated = GccDriverStructuralAuthenticatedFullExportV1.captureNative(profile, operation)
                val hostBoundary = GccDriverStructuralBoundaryEvidenceV1.capture(profile, authenticated)
                boundaryEvidence = hostBoundary
                requireCapturedOutputs()
                val selected = replayFullExportBoundary(operation.model, authenticated, frozenClaims)
                val score = OracleJson.parse(StructuralProductionReplayContract.scoreSelectedBoundary(selected),
                    decompengine.oracle.core.StrictJsonLimits(maximumInputBytes = 64 * 1024 * 1024,
                        maximumCanonicalBytes = 64 * 1024 * 1024, maximumNodes = 1_000_000,
                        maximumStringBytes = 16 * 1024 * 1024, maximumTotalStringBytes = 48 * 1024 * 1024)) as JsonObject
                require(score["boundaryObservationSha256"] == JsonPrimitive(OracleArtifacts.sha256(hostBoundary.observationBytes))) {
                    "native contained boundary replay differs from the independent host observation"
                }
                requireCapturedOutputs()
                replayNativeMachineCalls(frozenClaims, selected, profile).also { requireCapturedOutputs() }
            } else null
            externalReplay = replay?.let { replayNativeExternalCalls(it, checkNotNull(selectedProfile)) }
            val external = externalReplay
            fun requireAllCapturedOutputs() {
                external?.requireCurrent()
                requireCapturedOutputs()
                external?.requireFinalMetadata()
                lease.withCurrentOperationRunRootBeforeLaunch(runRoot) { borrowed -> borrowed.withPinnedDescriptor { run ->
                    external?.let {
                        GccBundledMachineCallReplayOutputCapture.requireUnchanged(run, it.machine.capture)
                        GccBundledExternalCallReplayOutputCapture.requireUnchanged(run, it.independentCapture)
                        GccBundledExternalCallReplayOutputCapture.requireUnchanged(run, it.recoveredCapture)
                    }
                } }
                cli.requireCurrent()
            }
            requireAllCapturedOutputs()
            val replayBinding = replay?.let(GccBundledNativeStructuralEvidenceV1::create)
            val result = GccBundledNativeCallCliResult.create(operation, binding,
                journal.path, original.outputLease.path, cli.options.output, deadline.snapshot(), replay, external)
            LinuxFilesystemSyscalls.openRoot(cli.options.output).use { output ->
                cli.requireCurrent()
                DescriptorBoundAtomicStateFile.publishManifestNoReplace(output, treeName,
                    operation.model.sidecarManifest, GccBundledFullExportCliResultV2.MAXIMUM_TREE_MANIFEST_BYTES)
                DescriptorBoundAtomicStateFile.publishNoReplace(output, bindingName, binding, 256 * 1024)
                replay?.let {
                    val boundary = checkNotNull(boundaryEvidence)
                    DescriptorBoundAtomicStateFile.publishManifestNoReplace(output, GccBundledNativeStructuralEvidenceV1.POPULATION_NAME,
                        it.projectedPopulationBytes, 64 * 1024 * 1024)
                    DescriptorBoundAtomicStateFile.publishManifestNoReplace(output, GccDriverStructuralBoundaryEvidenceV1.OBSERVATION_NAME,
                        boundary.observationBytes, GccDriverStructuralBoundaryEvidenceV1.MAXIMUM_OBSERVATION_BYTES)
                    DescriptorBoundAtomicStateFile.publishNoReplace(output, GccDriverStructuralBoundaryEvidenceV1.BINDING_NAME,
                        boundary.bindingBytes, GccDriverStructuralBoundaryEvidenceV1.MAXIMUM_BINDING_BYTES)
                    DescriptorBoundAtomicStateFile.publishNoReplace(output, GccBundledNativeStructuralEvidenceV1.BINDING_NAME,
                        checkNotNull(replayBinding), 256 * 1024)
                    DescriptorBoundAtomicStateFile.publishNoReplace(output, GccBundledNativeStructuralEvidenceV1.MODEL_BINDING_NAME,
                        it.selectedInputs.fullExportBindingBytes, 256 * 1024)
                    DescriptorBoundAtomicStateFile.publishManifestNoReplace(output, GccBundledNativeStructuralEvidenceV1.BOUNDARY_NAME,
                        StructuralProductionReplayContract.scoreSelectedBoundary(it.selectedInputs), 64 * 1024 * 1024)
                    DescriptorBoundAtomicStateFile.publishManifestNoReplace(output, GccBundledMachineCallReplayOutputCapture.REPORT_NAME,
                        it.capture.reportBytes, it.request.limits.maximumOutputBytes)
                }
                external?.let {
                    for ((name, bytes) in GccBundledExternalCallEvidenceV1.payloads(it)) {
                        requireAllCapturedOutputs()
                        DescriptorBoundAtomicStateFile.publishManifestNoReplace(output, name, bytes, 64 * 1024 * 1024)
                    }
                }
                GccBundledNativeCallCliPublication.publishResultMarker(output, result,
                    beforeCommit = { requireAllCapturedOutputs() })
            }
            return cli.options.output.resolve("result.json")
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        } finally {
            externalReplay?.close()
        }
    }

    private fun bindWallTime(assessmentBytes: ByteArray): ByteArray {
        val assessment = OracleJson.parseCanonical(assessmentBytes) as JsonObject
        val fields = assessment - "assessmentSha256" + ("operationWallTime" to checkNotNull(operationDeadline).snapshot())
        return OracleJson.canonicalBytes(JsonObject(fields + ("assessmentSha256" to
            JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(fields)))))))
    }

    private fun analysisStateLimits() = GccAnalysisStateCaptureLimits(
        maximumEntries = minOf(intent.diskPolicy.maximumFilesystemInodes, 32768L).toInt(),
        maximumTotalBytes = intent.diskPolicy.maximumFilesystemBytes,
        maximumWallMillis = operationDeadline?.remainingMillis(intent.budgets.wallClockMillis) ?: intent.budgets.wallClockMillis,
    )

    private fun <T> executeRun(
        kind: GccCompilerEngineContainmentRunKind,
        trigger: GccBundledCheckpointTrigger?,
        afterAbsence: (FullTreeDiskScratchBorrowedRunRoot, KotlinSystemdCgroupCommandExecution) -> T,
    ): T {
        requireCurrent()
        require(intent.runKind == kind) { "GCC bundled execution kind differs from the prepared intent" }
        require(intent.bundledRuntime.invocationVersion in 2..3 || intent.bundledRuntime.invocationVersion in 5..9) {
            "GCC contained execution requires an explicitly bound fresh JVM runtime"
        }
        executionAttempted = true
        operationDeadline = ContainedCommandOperationDeadline(intent.budgets.wallClockMillis)
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
                        checkNotNull(operationDeadline).remainingWholeSecondsMillis(intent.budgets.wallClockMillis),
                        intent.budgets.maximumResidentBytes, intent.budgets.pidsMax,
                        minOf(intent.diskPolicy.maximumFilesystemBytes, 1024L * 1024 * 1024),
                        processorCount = intent.bundledRuntime.processorCount,
                    ),
                    deploymentClosureSha256 = inputs.deploymentClosureSha256,
                    interruption = interruption,
                    operationDeadline = operationDeadline,
                    controlDirectoryName = intent.bundledRuntime.freshControlDirectoryName(borrowed.path),
                    beforeStart = { attachment ->
                        inputs.verify("before GCC command START")
                        lease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                        requireFreshNativeReports(borrowed)
                        journal.recordAttachment(attachment.canonicalBytes)
                        journal.recordStartAuthorization()
                        inputs.verify("after durable GCC command START authorization")
                        journal.verify("before GCC command START delivery")
                        lease.requireCurrentOperationRunRootAfterScopeAttachment(runRoot)
                        requireFreshNativeReports(borrowed)
                    },
                )
                lease.requireCurrentOperationRunRootAfterCgroupAbsence(runRoot)
                inputs.verify("after GCC command and cgroup absence")
                intent.bundledRuntime.freshControlDirectoryName(borrowed.path)?.let { name ->
                    completedControls[name] = checkNotNull(execution.controlDirectoryIdentity)
                }
                afterAbsence(borrowed, execution).also { checkNotNull(operationDeadline).requireCurrent() }
            }.also { checkNotNull(operationDeadline).requireCurrent() }
        } catch (failure: Throwable) {
            poisoned = true
            if (failure is KotlinSystemdCgroupCommandExecutionException) pendingCleanup = failure.cleanup
            throw failure
        }
    }

    private fun requireFreshNativeReports(borrowed: FullTreeDiskScratchBorrowedRunRoot) {
        if (intent.bundledRuntime.invocationVersion !in setOf(8, 9)) return
        borrowed.withPinnedDescriptor { run ->
            LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { reports ->
                require(reports.identity == directories.getValue("reports") &&
                    LinuxFilesystemSyscalls.directoryEntryNames(reports, 1).isEmpty()) {
                    "native collector output must be absent before START"
                }
            }
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
        pendingInterfaceToken = null
        pendingInterfaceIssuance = null
        if (intent.bundledRuntime.invocationVersion == 9) GccBundledOperationCoordinator.revokeClosedInterfaceOwner(this)
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
    private val interfaceMembershipLock = Any()
    private val interfaceOwners = java.util.IdentityHashMap<GccBundledPreparedOperation, Boolean>()
    private val interfaceOperations = java.util.IdentityHashMap<GccBundledInterfaceOperation, GccBundledPreparedOperation>()

    internal fun requireFactoryInterfaceOwner(owner: GccBundledPreparedOperation) {
        synchronized(interfaceMembershipLock) {
            check(interfaceOwners.containsKey(owner)) { "interface operation requires a factory-owned live prepared owner" }
        }
    }

    internal fun issueInterfaceOperation(owner: GccBundledPreparedOperation, token: Any): GccBundledInterfaceOperation {
        requireFactoryInterfaceOwner(owner)
        val pending = owner.takeInterfaceIssuance(token)
        val operation = GccBundledInterfaceOperation(pending.snapshot, pending.intent, pending.execution, pending.assessment)
        synchronized(interfaceMembershipLock) {
            check(interfaceOwners.containsKey(owner)) { "interface owner was revoked during issuance" }
            check(interfaceOperations.values.none { it === owner }) { "interface owner already issued a capture" }
            interfaceOperations[operation] = owner
        }
        return operation
    }

    internal fun requireOwnedInterfaceOperation(operation: GccBundledInterfaceOperation) {
        val owner = synchronized(interfaceMembershipLock) {
            checkNotNull(interfaceOperations[operation]) { "interface result lacks factory-owned identity" }
        }
        // Never hold the membership lock while acquiring the owner's monitor.
        owner.requireCompletedInterfaceOperation(operation)
        synchronized(interfaceMembershipLock) {
            check(interfaceOwners.containsKey(owner) && interfaceOperations[operation] === owner) {
                "interface result membership has been revoked"
            }
        }
    }

    internal fun revokeClosedInterfaceOwner(owner: GccBundledPreparedOperation) {
        owner.requireInterfaceOwnerClosed()
        synchronized(interfaceMembershipLock) {
            interfaceOwners.remove(owner)
            interfaceOperations.entries.removeIf { it.value === owner }
        }
    }

    fun prepareNew(
        intent: GccBundledOperationIntent,
        journalRoot: Path,
        provisionedMount: Path,
    ): GccBundledPreparedOperation {
        requireGccBundledOperationPath(journalRoot)
        requireGccBundledOperationPath(provisionedMount)
        intent.cliInvocation?.let {
            require(journalRoot == it.options.output.resolve("journal") && provisionedMount == it.options.scratch) {
                "coordinator roots differ from bound CLI selection"
            }
        }
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
                        intent.bundledRuntime.command(intent.artifacts, state, output, intent.runKind), intent.environment,
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
            if (intent.bundledRuntime.invocationVersion == 9) {
                intent.requireInterfaceExecution()
                synchronized(interfaceMembershipLock) {
                    check(!interfaceOwners.containsKey(prepared))
                    interfaceOwners[prepared] = true
                }
            }
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
