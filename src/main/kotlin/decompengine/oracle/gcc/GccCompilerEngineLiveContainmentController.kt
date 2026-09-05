package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemCapacity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.DescriptorBoundStateFaultInjector
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.FullTreeFunctionObservationClassPathEntry
import decompengine.oracle.fulltree.FullTreeFunctionObservationIsolationConfiguration
import decompengine.oracle.fulltree.FullTreeFunctionObservationRuntimeMount
import decompengine.oracle.fulltree.KotlinSystemdCgroupBootLauncher
import decompengine.oracle.fulltree.KotlinSystemdCgroupBootLaunchException
import decompengine.oracle.fulltree.KotlinSystemdCgroupBootOwner
import decompengine.oracle.fulltree.KotlinSystemdCgroupBootResources
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.fulltree.calculateFullTreeObservationRuntimeManifestSha256
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

internal class GccCompilerEngineLiveContainmentException(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

internal enum class LiveContainmentPreAttachmentRollbackFaultPoint {
    AFTER_DEFINITION_QUARANTINE,
    AFTER_MARKER_PUBLICATION,
    AFTER_DIRECTORY_QUARANTINE,
    AFTER_MARKER_EXTRACTION,
    AFTER_DIRECTORY_REMOVAL,
    AFTER_PROOF_REMOVAL,
}

internal fun interface LiveContainmentPreAttachmentRollbackFaultInjector {
    fun hit(point: LiveContainmentPreAttachmentRollbackFaultPoint)
}

/**
 * Historical, non-release terminal result from one Kotlin-owned containment operation.
 *
 * The bytes are useful for audit and in-process terminal-publication retry only; this checkpoint
 * has no cold reopen path. They do not prove that a compiler engine ran, authorize START, release
 * an output lease, or make a benchmark result eligible for publication.
 */
private object GCC_LIVE_TERMINAL_ABSENCE_PERMIT

private class LiveContainmentTerminalProof(
    val bindingSha256: String,
    val journalDirectory: Path,
    attachedReceiptBytes: ByteArray,
    absenceReceiptBytes: ByteArray,
) {
    private val attached = attachedReceiptBytes.copyOf()
    private val absence = absenceReceiptBytes.copyOf()

    val unitAttachedReceiptBytes: ByteArray
        get() = attached.copyOf()
    val terminalAbsenceReceiptBytes: ByteArray
        get() = absence.copyOf()
}

internal class GccCompilerEngineLiveTerminalAbsence private constructor(
    opaqueOwnership: Any,
    constructionPermit: Any,
) {
    init {
        check(constructionPermit === GCC_LIVE_TERMINAL_ABSENCE_PERMIT) {
            "GCC live terminal absence requires one proved cleanup"
        }
    }

    private val proof: LiveContainmentTerminalProof =
        (opaqueOwnership as? LiveContainmentOwnership)?.terminalProofForResult()
            ?: error("GCC live terminal absence requires one proved cleanup")
    val authority: String = LIVE_TERMINAL_AUTHORITY
    val complete: Boolean = false
    val releaseEligible: Boolean = false
    val startAuthorized: Boolean = false
    val bindingSha256: String = proof.bindingSha256
    val journalDirectory: Path = proof.journalDirectory

    val unitAttachedReceiptBytes: ByteArray
        get() = proof.unitAttachedReceiptBytes
    val terminalAbsenceReceiptBytes: ByteArray
        get() = proof.terminalAbsenceReceiptBytes

    companion object {
        internal fun fromProvedCleanup(opaqueOwnership: Any): GccCompilerEngineLiveTerminalAbsence =
            GccCompilerEngineLiveTerminalAbsence(
                opaqueOwnership,
                GCC_LIVE_TERMINAL_ABSENCE_PERMIT,
            )
    }
}

private object GCC_LIVE_ATTACHED_OWNER_PERMIT

/**
 * Linear ownership of one exact systemd/cgroup-v2 scope retained at the BOOT barrier.
 *
 * This type deliberately has no START, command execution, export, scoring, publication, or lease
 * release method. [closeAndProveAbsent] is the only state transition: it performs whole-cgroup
 * cleanup through the retained descriptor/pidfd-backed owner, proves the exact unit and every
 * same-name cgroup absent, durably records that terminal fact, and then releases local locks.
 */
internal class GccCompilerEngineLiveAttachedAtBoot private constructor(
    opaqueOwnership: Any,
    constructionPermit: Any,
) : AutoCloseable {
    init {
        check(constructionPermit === GCC_LIVE_ATTACHED_OWNER_PERMIT) {
            "GCC live BOOT ownership requires one verified launch"
        }
    }

    private val ownership: LiveContainmentOwnership =
        opaqueOwnership as? LiveContainmentOwnership
            ?: error("GCC live BOOT ownership requires one verified launch")
    val authority: String = LIVE_BOOT_AUTHORITY
    val complete: Boolean = false
    val releaseEligible: Boolean = false
    val startAuthorized: Boolean = false
    val bindingSha256: String = ownership.definition.bindingSha256
    val unitName: String = ownership.definition.unitName
    val journalDirectory: Path = ownership.journal.path
    private val attachedBytes = ownership.attachedReceiptBytes.copyOf()
    val unitAttachedReceiptBytes: ByteArray
        get() = attachedBytes.copyOf()

    init {
        ownership.requireCurrentAtBoot()
    }

    @Synchronized
    fun requireCurrentAtBoot() = ownership.requireCurrentAtBoot()

    @Synchronized
    fun closeAndProveAbsent(): GccCompilerEngineLiveTerminalAbsence =
        ownership.closeAndProveAbsent()

    override fun close() {
        closeAndProveAbsent()
    }

    companion object {
        internal fun fromVerifiedLaunch(opaqueOwnership: Any): GccCompilerEngineLiveAttachedAtBoot =
            GccCompilerEngineLiveAttachedAtBoot(opaqueOwnership, GCC_LIVE_ATTACHED_OWNER_PERMIT)
    }
}

/**
 * Raw-path, fixed-policy host entry point for the A10 BOOT-only containment checkpoint.
 *
 * The caller supplies only a path to canonical definition bytes. Every path named by those bytes
 * is opened, hashed, bounded, and retained by Kotlin. Runtime mounts are fixed by this controller
 * and committed by the live receipt. No caller-supplied process observer, launcher, receipt,
 * analyzer, ACP artifact, or policy callback can enter this boundary.
 */
internal object GccCompilerEngineLiveContainmentController {
    fun attachAtBoot(definitionPath: Path): GccCompilerEngineLiveAttachedAtBoot =
        translateLiveContainmentFailure("attach the GCC compiler-engine scope at BOOT") {
            LiveContainmentOwnership.attach(definitionPath)
        }
}

private class LiveContainmentOwnership private constructor(
    val definition: GccCompilerEngineValidatedContainmentDefinition,
    private val definitionBytes: ByteArray,
    private val inputs: AuthenticatedLiveContainmentInputs,
    val journal: LiveContainmentJournal,
    private val bootOwner: KotlinSystemdCgroupBootOwner,
    attachedReceiptBytes: ByteArray,
) {
    val attachedReceiptBytes: ByteArray = attachedReceiptBytes.copyOf()
    private var terminalResult: GccCompilerEngineLiveTerminalAbsence? = null
    private var terminalProof: LiveContainmentTerminalProof? = null
    private var retainedAbsenceBytes: ByteArray? = null
    private var operationActive = false
    private var resourcesClosed = false

    fun requireCurrentAtBoot() {
        check(!resourcesClosed) { "GCC live containment owner is closed" }
        check(terminalResult == null) { "GCC live containment owner is terminal" }
        check(!operationActive) { "GCC live containment operation is already active" }
        operationActive = true
        try {
            inputs.verify("while GCC scope is retained at BOOT")
            journal.requireBootLayout()
            bootOwner.requireCurrentAtBoot()
            journal.requirePublished(ATTACHED_RECEIPT_FILE, attachedReceiptBytes)
            inputs.verify("after GCC BOOT attachment revalidation")
            journal.requireBootLayout()
        } finally {
            operationActive = false
        }
    }

    fun closeAndProveAbsent(): GccCompilerEngineLiveTerminalAbsence {
        terminalResult?.let { return it }
        check(!resourcesClosed) { "GCC live containment owner is closed without terminal proof" }
        check(!operationActive) { "GCC live containment operation is already active" }
        operationActive = true
        try {
            val absenceBytes = retainedAbsenceBytes ?: GccCompilerEngineContainmentContract
                .prepareLiveOwnerTerminalAbsenceReceipt(
                    definitionBytes,
                    attachedReceiptBytes,
                    bootOwner,
                    inputs.deploymentClosureSha256,
                ).also { retainedAbsenceBytes = it }
            // Preparing and retaining the immutable candidate precedes destructive cleanup. If
            // auxiliary descriptor release fails after absence was already proved, a retry can
            // finish the generic owner's terminal transition and publish these exact bytes.
            bootOwner.closeAndProveAbsent()
            // Cleanup authority is independent of mutable caller inputs. Only after the cgroup is
            // absent do we require the retained journal/output/state bindings needed to publish.
            journal.requireTerminalPublishableLayout()
            journal.requirePublished(DEFINITION_FILE, definitionBytes)
            journal.requirePublished(ATTACHED_RECEIPT_FILE, attachedReceiptBytes)
            journal.publish(ABSENCE_RECEIPT_FILE, absenceBytes)
            journal.requirePublished(DEFINITION_FILE, definitionBytes)
            journal.requirePublished(ATTACHED_RECEIPT_FILE, attachedReceiptBytes)
            journal.requirePublished(ABSENCE_RECEIPT_FILE, absenceBytes)
            journal.requireTerminalFinalLayout()
            GccCompilerEngineContainmentContract.assessTerminalAbsence(
                definitionBytes,
                attachedReceiptBytes,
                absenceBytes,
            )
            terminalProof = LiveContainmentTerminalProof(
                definition.bindingSha256,
                journal.path,
                attachedReceiptBytes,
                absenceBytes,
            )
            val result = GccCompilerEngineLiveTerminalAbsence.fromProvedCleanup(this)
            terminalResult = result
            closeResources()
            return result
        } finally {
            operationActive = false
        }
    }

    fun terminalProofForResult(): LiveContainmentTerminalProof =
        terminalProof ?: error("GCC live terminal absence requires one proved cleanup")

    private fun closeResources() {
        if (resourcesClosed) return
        var failure: Throwable? = null
        fun record(next: Throwable) {
            val first = failure
            if (first == null) failure = next else if (next !== first) first.addSuppressed(next)
        }
        runCatching { journal.close() }.exceptionOrNull()?.let(::record)
        runCatching { inputs.close() }.exceptionOrNull()?.let(::record)
        // Linux descriptor close is terminal even when a preceding unlock/sync reports failure;
        // never retry through possibly reused descriptor numbers.
        resourcesClosed = true
        failure?.let { throw it }
    }

    companion object {
        fun attach(definitionPath: Path): GccCompilerEngineLiveAttachedAtBoot {
            var inputs: AuthenticatedLiveContainmentInputs? = null
            var journal: LiveContainmentJournal? = null
            var bootOwner: KotlinSystemdCgroupBootOwner? = null
            var attachedReceipt: ByteArray? = null
            var attachedPublished = false
            var launchEntered = false
            try {
                val openedInputs = AuthenticatedLiveContainmentInputs.open(definitionPath)
                inputs = openedInputs
                val definition = openedInputs.definition
                val requestedResources = requireSupportedCheckpoint(definition)
                val runtime = deriveRuntimeConfiguration(definition, openedInputs.classPathEntries)
                val openedJournal = LiveContainmentJournal.create(definition)
                journal = openedJournal
                openedInputs.verify("before durable GCC definition publication")
                openedJournal.publish(DEFINITION_FILE, openedInputs.definitionBytes)
                openedJournal.requirePreparedLayout()
                openedInputs.verify("after durable GCC definition publication")
                launchEntered = true
                val launched = KotlinSystemdCgroupBootLauncher.launch(
                    configuration = runtime,
                    scratchParent = definition.analysisState.path,
                    unitName = definition.unitName,
                    expectedControlGroup = definition.expectedControlGroup,
                    nonce = definition.bindingSha256,
                    requestedResources = requestedResources,
                    deploymentClosureSha256 = openedInputs.deploymentClosureSha256,
                )
                bootOwner = launched
                openedInputs.verify("before GCC UNIT_ATTACHED-at-BOOT receipt")
                openedJournal.requirePreAttachmentLayout()
                val receipt = GccCompilerEngineContainmentContract.renderLiveUnitAttachedAtBootReceipt(
                    openedInputs.definitionBytes,
                    launched,
                    openedInputs.deploymentClosureSha256,
                )
                attachedReceipt = receipt
                openedJournal.publish(ATTACHED_RECEIPT_FILE, receipt)
                attachedPublished = true
                launched.requireCurrentAtBoot()
                openedJournal.requirePublished(ATTACHED_RECEIPT_FILE, receipt)
                openedJournal.requireBootLayout()
                openedInputs.verify("after GCC UNIT_ATTACHED-at-BOOT receipt")

                val ownership = LiveContainmentOwnership(
                    definition,
                    openedInputs.definitionBytes,
                    openedInputs,
                    openedJournal,
                    launched,
                    receipt,
                )
                val result = GccCompilerEngineLiveAttachedAtBoot.fromVerifiedLaunch(ownership)
                bootOwner = null
                journal = null
                inputs = null
                return result
            } catch (failure: Throwable) {
                fun suppress(next: Throwable) {
                    if (next !== failure) failure.addSuppressed(next)
                }
                val owner = bootOwner
                val receipt = attachedReceipt
                val currentJournal = journal
                val currentInputs = inputs
                var durableAttachment = attachedPublished
                var attachmentPhaseClassified = attachedPublished || receipt == null
                if (!durableAttachment && receipt != null && currentJournal != null) {
                    val classification = runCatching {
                        currentJournal.completeAttachmentPublicationIfPresent(receipt)
                    }
                    classification.exceptionOrNull()?.let(::suppress)
                    classification.getOrNull()?.let { recovered ->
                        durableAttachment = recovered
                        attachmentPhaseClassified = true
                    }
                }
                var preAttachmentOwnerAbsent = owner == null && (
                    !launchEntered ||
                        failure is KotlinSystemdCgroupBootLaunchException &&
                        failure.preAttachmentRollbackSafe
                    )
                if (owner != null) {
                    val terminalCandidate = if (
                        durableAttachment && receipt != null && currentJournal != null && currentInputs != null
                    ) {
                        runCatching {
                            GccCompilerEngineContainmentContract.prepareLiveOwnerTerminalAbsenceReceipt(
                                currentInputs.definitionBytes,
                                receipt,
                                owner,
                                currentInputs.deploymentClosureSha256,
                            )
                        }
                    } else {
                        null
                    }
                    terminalCandidate?.exceptionOrNull()?.let(::suppress)
                    var cleanup = runCatching { owner.closeAndProveAbsent() }
                    cleanup.exceptionOrNull()?.let(::suppress)
                    if (cleanup.isFailure) {
                        cleanup = runCatching { owner.closeAndProveAbsent() }
                        cleanup.exceptionOrNull()?.let(::suppress)
                    }
                    preAttachmentOwnerAbsent = cleanup.isSuccess
                    if (durableAttachment && cleanup.isSuccess) {
                        terminalCandidate?.getOrNull()?.let { absence ->
                            runCatching {
                                val exactReceipt = checkNotNull(receipt)
                                val exactJournal = checkNotNull(currentJournal)
                                val exactInputs = checkNotNull(currentInputs)
                                exactJournal.requireTerminalPublishableLayout()
                                exactJournal.requirePublished(DEFINITION_FILE, exactInputs.definitionBytes)
                                exactJournal.requirePublished(ATTACHED_RECEIPT_FILE, exactReceipt)
                                exactJournal.publish(ABSENCE_RECEIPT_FILE, absence)
                                exactJournal.requirePublished(DEFINITION_FILE, exactInputs.definitionBytes)
                                exactJournal.requirePublished(ATTACHED_RECEIPT_FILE, exactReceipt)
                                exactJournal.requirePublished(ABSENCE_RECEIPT_FILE, absence)
                                exactJournal.requireTerminalFinalLayout()
                            }.exceptionOrNull()?.let(::suppress)
                        }
                    }
                }
                if (!durableAttachment && attachmentPhaseClassified && preAttachmentOwnerAbsent) {
                    runCatching { journal?.rollbackBeforeAttachment() }
                        .exceptionOrNull()?.let(::suppress)
                }
                runCatching { journal?.close() }.exceptionOrNull()?.let(::suppress)
                runCatching { inputs?.close() }.exceptionOrNull()?.let(::suppress)
                throw failure
            }
        }
    }
}

private class AuthenticatedLiveContainmentInputs private constructor(
    private val definitionGuard: StableControlFile,
    val definitionBytes: ByteArray,
    val definition: GccCompilerEngineValidatedContainmentDefinition,
    private val deploymentReference: GccKotlinBootClasspathReference,
    private val bundledRuntime: GccBundledGhidraRetainedRuntime?,
    private val guards: List<Pair<String, StableControlFile>>,
    val classPathEntries: List<FullTreeFunctionObservationClassPathEntry>,
) : AutoCloseable {
    val deploymentClosureSha256: String = bundledRuntime?.let { runtime ->
        gccBundledLiveDeploymentClosureSha256(
            deploymentReference.closureSha256,
            runtime.deploymentClosureSha256,
            runtime.runtimeIdentitySha256,
        )
    } ?: deploymentReference.closureSha256

    fun verify(label: String) {
        definitionGuard.verifyUnchanged("GCC containment definition $label")
        deploymentReference.verify(label)
        bundledRuntime?.verify(label)
        guards.forEach { (name, guard) -> guard.verifyUnchanged("$name $label") }
    }

    override fun close() {
        var failure: Throwable? = null
        (guards.map { it.second }.asReversed() + definitionGuard).forEach { guard ->
            runCatching { guard.close() }.exceptionOrNull()?.let { next ->
                val first = failure
                if (first == null) failure = next else if (next !== first) first.addSuppressed(next)
            }
        }
        runCatching { deploymentReference.close() }.exceptionOrNull()?.let { next ->
            val first = failure
            if (first == null) failure = next else if (next !== first) first.addSuppressed(next)
        }
        runCatching { bundledRuntime?.close() }.exceptionOrNull()?.let { next ->
            val first = failure
            if (first == null) failure = next else if (next !== first) first.addSuppressed(next)
        }
        failure?.let { throw it }
    }

    companion object {
        fun open(definitionPath: Path): AuthenticatedLiveContainmentInputs {
            var definitionGuard: StableControlFile? = null
            var deploymentReference: GccKotlinBootClasspathReference? = null
            var bundledRuntime: GccBundledGhidraRetainedRuntime? = null
            val opened = ArrayDeque<Pair<String, StableControlFile>>()
            try {
                val rawDefinition = StableControlFile.open(
                    definitionPath,
                    MAXIMUM_LIVE_DEFINITION_BYTES.toLong(),
                    "GCC containment definition",
                )
                definitionGuard = rawDefinition
                val definitionBytes = rawDefinition.readExactly(
                    0L,
                    rawDefinition.size.toInt(),
                    "GCC containment definition",
                )
                val definition = GccCompilerEngineContainmentContract
                    .parseDefinitionForLiveController(definitionBytes)
                requireSupportedCheckpoint(definition)
                if (definitionPath.toAbsolutePath().normalize().startsWith(definition.outputLease.path)) {
                    liveContainmentFail("GCC containment definition must remain outside the output lease")
                }
                bundledRuntime = definition.bundledRuntime?.let { GccBundledGhidraRetainedRuntime.open(definition) }
                definition.artifacts.forEach { artifact ->
                    val label = "GCC containment artifact ${artifact.role.wireName}"
                    val guard = StableControlFile.open(artifact.path, artifact.bytes, label)
                    opened.addFirst(label to guard)
                    if (guard.size != artifact.bytes || guard.sha256(label = "$label at authorization") != artifact.sha256) {
                        liveContainmentFail("$label differs from its exact definition identity")
                    }
                }
                val manifestArtifact = definition.artifacts.single {
                    it.role == GccCompilerEngineContainmentArtifactRole.BOOT_KEEPER_CLASSPATH
                }
                if (manifestArtifact.bytes > MAXIMUM_CLASSPATH_MANIFEST_BYTES) {
                    liveContainmentFail("GCC BOOT-keeper class-path manifest exceeds fixed policy")
                }
                val manifestGuard = opened.single { (label, _) ->
                    label.endsWith(GccCompilerEngineContainmentArtifactRole.BOOT_KEEPER_CLASSPATH.wireName)
                }.second
                val manifestBytes = manifestGuard.readExactly(
                    0L,
                    manifestGuard.size.toInt(),
                    "GCC BOOT-keeper class-path manifest",
                )
                val entries = parseBootClassPathManifest(
                    manifestBytes,
                    definition.outputLease.path,
                    definition.artifacts.map { it.path }.toSet(),
                )
                val reference = GccKotlinBootClasspathReference.open()
                deploymentReference = reference
                reference.requireCandidateIdentities(entries.map { it.bytes to it.sha256 })
                val classPath = entries.mapIndexed { index, entry ->
                    val label = "GCC BOOT-keeper class-path entry $index"
                    val guard = StableControlFile.open(entry.path, entry.bytes, label)
                    opened.addFirst(label to guard)
                    if (guard.size != entry.bytes || guard.sha256(label = "$label at authorization") != entry.sha256) {
                        liveContainmentFail("$label differs from its exact manifest identity")
                    }
                    FullTreeFunctionObservationClassPathEntry(entry.path, entry.sha256)
                }
                rawDefinition.verifyUnchanged("after GCC input authentication")
                return AuthenticatedLiveContainmentInputs(
                    rawDefinition,
                    definitionBytes,
                    definition,
                    reference,
                    bundledRuntime,
                    Collections.unmodifiableList(opened.toList()),
                    Collections.unmodifiableList(classPath),
                ).also {
                    definitionGuard = null
                    deploymentReference = null
                    bundledRuntime = null
                }
            } catch (failure: Throwable) {
                opened.forEach { (_, guard) ->
                    runCatching { guard.close() }.exceptionOrNull()
                        ?.takeIf { it !== failure }?.let(failure::addSuppressed)
                }
                runCatching { deploymentReference?.close() }
                    .exceptionOrNull()?.takeIf { it !== failure }?.let(failure::addSuppressed)
                runCatching { bundledRuntime?.close() }
                    .exceptionOrNull()?.takeIf { it !== failure }?.let(failure::addSuppressed)
                runCatching { definitionGuard?.close() }
                    .exceptionOrNull()?.takeIf { it !== failure }?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

internal class LiveContainmentJournal private constructor(
    val path: Path,
    private val definition: GccCompilerEngineValidatedContainmentDefinition,
    private val outputLease: LinuxDescriptor,
    private val analysisState: LinuxDescriptor,
    private val directory: LinuxDescriptor,
    initialRollbackPhase: PreAttachmentRollbackPhase = PreAttachmentRollbackPhase.LINKED,
) : AutoCloseable {
    private val definitionBytes = definition.canonicalBytes
    private val rollbackMarkerBytes = preAttachmentRollbackMarkerBytes(definition)
    private val outputIdentity = outputLease.identity
    private val stateIdentity = analysisState.identity
    private val directoryIdentity = directory.identity
    private var rollbackPhase = initialRollbackPhase
    private var closed = false

    fun publish(
        name: String,
        bytes: ByteArray,
        faultInjector: DescriptorBoundStateFaultInjector? = null,
    ) {
        check(!closed) { "GCC live containment journal is closed" }
        requireCurrentBindings()
        DescriptorBoundAtomicStateFile.publishNoReplace(
            directory,
            name,
            bytes,
            MAXIMUM_LIVE_STATE_BYTES,
            faultInjector,
        )
        requireCurrentBindings()
    }

    fun requirePublished(name: String, bytes: ByteArray) {
        check(!closed) { "GCC live containment journal is closed" }
        requireCurrentBindings()
        val persisted = DescriptorBoundAtomicStateFile.readOrNull(
            directory,
            name,
            MAXIMUM_LIVE_STATE_BYTES,
        ) ?: liveContainmentFail("GCC containment journal is missing $name")
        if (!MessageDigest.isEqual(persisted.bytes, bytes)) {
            liveContainmentFail("GCC containment journal $name has different immutable bytes")
        }
        requireCurrentBindings()
    }

    fun requirePreparedLayout() {
        requireCurrentBindings()
        requireExactNames(analysisState, emptySet(), "fresh GCC analysis state")
        requireExactNames(
            directory,
            setOf(DEFINITION_FILE),
            "prepared GCC containment journal",
        )
        requireExactNames(
            outputLease,
            setOf(definition.analysisState.path.fileName.toString(), path.fileName.toString()),
            "prepared GCC output lease",
        )
    }

    /** Completes only an exact attachment target/temporary already selected by this operation. */
    fun completeAttachmentPublicationIfPresent(attachedBytes: ByteArray): Boolean {
        requireCurrentBindings()
        requirePublished(DEFINITION_FILE, definitionBytes)
        val temporary = DescriptorBoundAtomicStateFile.temporaryName(ATTACHED_RECEIPT_FILE)
        val names = boundedNames(directory, 4, "GCC journal attachment classification")
        val members = names.toSet()
        if (names.size != members.size) {
            liveContainmentFail("GCC journal attachment classification contains duplicate names")
        }
        return when (members) {
            setOf(DEFINITION_FILE) -> false
            setOf(DEFINITION_FILE, ATTACHED_RECEIPT_FILE),
            setOf(DEFINITION_FILE, temporary),
            -> {
                publish(ATTACHED_RECEIPT_FILE, attachedBytes)
                requirePublished(ATTACHED_RECEIPT_FILE, attachedBytes)
                requireExactNames(
                    directory,
                    setOf(DEFINITION_FILE, ATTACHED_RECEIPT_FILE),
                    "recovered UNIT_ATTACHED GCC containment journal",
                )
                true
            }
            else -> liveContainmentFail("GCC journal attachment phase is not safely classifiable")
        }
    }

    fun requirePreAttachmentLayout() {
        requireCurrentBindings()
        val stateNames = boundedNames(analysisState, 2, "live GCC analysis state")
        if (stateNames.size != 1 || !stateNames.single().matches(PRIVATE_RUN_DIRECTORY)) {
            liveContainmentFail("live GCC analysis state differs from the one retained BOOT run tree")
        }
        requireExactNames(
            directory,
            setOf(DEFINITION_FILE),
            "pre-attachment GCC containment journal",
        )
        requireExactNames(
            outputLease,
            setOf(definition.analysisState.path.fileName.toString(), path.fileName.toString()),
            "pre-attachment GCC output lease",
        )
    }

    fun requireBootLayout() {
        requireCurrentBindings()
        val stateNames = boundedNames(analysisState, 2, "live GCC analysis state")
        if (stateNames.size != 1 || !stateNames.single().matches(PRIVATE_RUN_DIRECTORY)) {
            liveContainmentFail("live GCC analysis state differs from the one retained BOOT run tree")
        }
        requireExactNames(
            directory,
            setOf(DEFINITION_FILE, ATTACHED_RECEIPT_FILE),
            "UNIT_ATTACHED GCC containment journal",
        )
        requireExactNames(
            outputLease,
            setOf(definition.analysisState.path.fileName.toString(), path.fileName.toString()),
            "UNIT_ATTACHED GCC output lease",
        )
    }

    fun requireTerminalPublishableLayout() {
        requireCurrentBindings()
        requireExactNames(analysisState, emptySet(), "terminal GCC analysis state")
        val names = boundedNames(directory, 4, "terminal GCC containment journal")
        val allowedBefore = setOf(DEFINITION_FILE, ATTACHED_RECEIPT_FILE)
        val allowedAfter = allowedBefore + ABSENCE_RECEIPT_FILE
        val allowedRecovery = allowedBefore + DescriptorBoundAtomicStateFile.temporaryName(
            ABSENCE_RECEIPT_FILE,
        )
        if (
            names.toSet() !in setOf(allowedBefore, allowedAfter, allowedRecovery) ||
            names.size != names.toSet().size
        ) {
            liveContainmentFail("terminal GCC containment journal contains unexpected residue")
        }
        requireExactNames(
            outputLease,
            setOf(definition.analysisState.path.fileName.toString(), path.fileName.toString()),
            "terminal GCC output lease",
        )
    }

    fun requireTerminalFinalLayout() {
        requireCurrentBindings()
        requireExactNames(analysisState, emptySet(), "final terminal GCC analysis state")
        requireExactNames(
            directory,
            setOf(DEFINITION_FILE, ATTACHED_RECEIPT_FILE, ABSENCE_RECEIPT_FILE),
            "final terminal GCC containment journal",
        )
        requireExactNames(
            outputLease,
            setOf(definition.analysisState.path.fileName.toString(), path.fileName.toString()),
            "final terminal GCC output lease",
        )
    }

    /**
     * Removes only this journal's exact canonical pre-attachment definition state.
     *
     * The operation is retryable, including by a later process, after every durable boundary. It
     * refuses attached state, unknown residue, a nonempty analysis tree, or any changed binding.
     * An exact definition-bound rollback marker follows the directory into quarantine and is
     * moved back to the output lease before directory removal, so every recovery phase remains
     * independently authenticated.
     */
    fun rollbackBeforeAttachment(
        faultInjector: LiveContainmentPreAttachmentRollbackFaultInjector? = null,
    ) {
        check(!closed) { "GCC live containment journal is closed" }
        if (rollbackPhase == PreAttachmentRollbackPhase.LINKED) {
            requireCurrentBindings()
            requireExactNames(analysisState, emptySet(), "pre-attachment rollback analysis state")
            val definitionTemporary = DescriptorBoundAtomicStateFile.temporaryName(DEFINITION_FILE)
            val markerTemporary = DescriptorBoundAtomicStateFile.temporaryName(ROLLBACK_MARKER_FILE)
            val names = boundedNames(directory, 3, "pre-attachment rollback journal")
            val members = names.toSet()
            if (
                names.size != members.size ||
                members !in setOf(
                    emptySet(),
                    setOf(DEFINITION_FILE),
                    setOf(definitionTemporary),
                    setOf(ROLLBACK_DEFINITION_QUARANTINE_FILE),
                    setOf(ROLLBACK_MARKER_FILE),
                    setOf(markerTemporary),
                )
            ) {
                liveContainmentFail("pre-attachment GCC containment journal has non-rollback state")
            }
            val member = members.singleOrNull()
            if (member == DEFINITION_FILE || member == definitionTemporary) {
                requireExactManagedFile(
                    directory,
                    member,
                    definitionBytes,
                    "pre-attachment GCC definition residue",
                )
                LinuxFilesystemSyscalls.renameNoReplace(
                    directory.fd,
                    member,
                    ROLLBACK_DEFINITION_QUARANTINE_FILE,
                )
                LinuxFilesystemSyscalls.synchronize(directory)
                faultInjector?.hit(
                    LiveContainmentPreAttachmentRollbackFaultPoint.AFTER_DEFINITION_QUARANTINE,
                )
            }
            if (
                member == DEFINITION_FILE || member == definitionTemporary ||
                member == ROLLBACK_DEFINITION_QUARANTINE_FILE
            ) {
                unlinkExactManagedFile(
                    directory,
                    ROLLBACK_DEFINITION_QUARANTINE_FILE,
                    definitionBytes,
                    "pre-attachment GCC definition residue",
                )
                LinuxFilesystemSyscalls.synchronize(directory)
            }
            publish(ROLLBACK_MARKER_FILE, rollbackMarkerBytes)
            requirePublished(ROLLBACK_MARKER_FILE, rollbackMarkerBytes)
            requireExactNames(
                directory,
                setOf(ROLLBACK_MARKER_FILE),
                "marked pre-attachment GCC containment journal",
            )
            faultInjector?.hit(LiveContainmentPreAttachmentRollbackFaultPoint.AFTER_MARKER_PUBLICATION)
            requireExactNames(analysisState, emptySet(), "emptied pre-attachment GCC analysis state")
            val stateName = definition.analysisState.path.fileName.toString()
            val journalName = path.fileName.toString()
            requireExactNames(
                outputLease,
                setOf(stateName, journalName),
                "linked pre-attachment GCC output lease",
            )
            LinuxFilesystemSyscalls.renameNoReplace(
                outputLease.fd,
                journalName,
                preAttachmentRollbackDirectoryName(definition.bindingSha256),
            )
            rollbackPhase = PreAttachmentRollbackPhase.QUARANTINED
            LinuxFilesystemSyscalls.synchronize(outputLease)
            faultInjector?.hit(LiveContainmentPreAttachmentRollbackFaultPoint.AFTER_DIRECTORY_QUARANTINE)
        }
        if (rollbackPhase == PreAttachmentRollbackPhase.QUARANTINED) {
            val quarantine = preAttachmentRollbackDirectoryName(definition.bindingSha256)
            requireRollbackBindings(quarantine)
            requireExactNames(
                directory,
                setOf(ROLLBACK_MARKER_FILE),
                "quarantined pre-attachment GCC journal",
            )
            requireExactManagedFile(
                directory,
                ROLLBACK_MARKER_FILE,
                rollbackMarkerBytes,
                "quarantined pre-attachment GCC rollback marker",
            )
            requireExactNames(analysisState, emptySet(), "quarantined pre-attachment GCC analysis state")
            requireExactNames(
                outputLease,
                setOf(definition.analysisState.path.fileName.toString(), quarantine),
                "quarantined pre-attachment GCC output lease",
            )
            LinuxFilesystemSyscalls.renameNoReplace(
                directory.fd,
                ROLLBACK_MARKER_FILE,
                outputLease.fd,
                preAttachmentRollbackProofName(definition.bindingSha256),
            )
            rollbackPhase = PreAttachmentRollbackPhase.MARKER_EXTRACTED
            LinuxFilesystemSyscalls.synchronize(directory)
            LinuxFilesystemSyscalls.synchronize(outputLease)
            faultInjector?.hit(LiveContainmentPreAttachmentRollbackFaultPoint.AFTER_MARKER_EXTRACTION)
        }
        if (rollbackPhase == PreAttachmentRollbackPhase.MARKER_EXTRACTED) {
            val quarantine = preAttachmentRollbackDirectoryName(definition.bindingSha256)
            val proof = preAttachmentRollbackProofName(definition.bindingSha256)
            requireRollbackBindings(quarantine)
            requireExactNames(directory, emptySet(), "emptied quarantined pre-attachment GCC journal")
            requireExactManagedFile(
                outputLease,
                proof,
                rollbackMarkerBytes,
                "extracted pre-attachment GCC rollback proof",
            )
            requireExactNames(
                outputLease,
                setOf(definition.analysisState.path.fileName.toString(), quarantine, proof),
                "proof-bearing pre-attachment GCC output lease",
            )
            LinuxFilesystemSyscalls.removeDirectory(outputLease.fd, quarantine)
            rollbackPhase = PreAttachmentRollbackPhase.DIRECTORY_REMOVED
            val after = LinuxFilesystemSyscalls.identity(directory.fd)
            if (!sameUnlinkedDirectory(after, directoryIdentity)) {
                liveContainmentFail("pre-attachment GCC journal was not exactly removed")
            }
            LinuxFilesystemSyscalls.synchronize(outputLease)
            faultInjector?.hit(LiveContainmentPreAttachmentRollbackFaultPoint.AFTER_DIRECTORY_REMOVAL)
        }
        if (rollbackPhase == PreAttachmentRollbackPhase.DIRECTORY_REMOVED) {
            val proof = preAttachmentRollbackProofName(definition.bindingSha256)
            requireDirectoryRemovedRollbackLayout(proof)
            unlinkExactManagedFile(
                outputLease,
                proof,
                rollbackMarkerBytes,
                "extracted pre-attachment GCC rollback proof",
            )
            rollbackPhase = PreAttachmentRollbackPhase.REMOVED
            LinuxFilesystemSyscalls.synchronize(outputLease)
            faultInjector?.hit(LiveContainmentPreAttachmentRollbackFaultPoint.AFTER_PROOF_REMOVAL)
        }
        requireRemovedRollbackLayout()
    }

    private fun requireExactManagedFile(
        parent: LinuxDescriptor,
        name: String,
        expectedBytes: ByteArray,
        label: String,
    ) {
        val persisted = DescriptorBoundAtomicStateFile.readOrNull(
            parent,
            name,
            MAXIMUM_LIVE_STATE_BYTES,
        ) ?: liveContainmentFail("$label is missing")
        if (!MessageDigest.isEqual(persisted.bytes, expectedBytes)) {
            liveContainmentFail("$label has different bytes")
        }
    }

    private fun unlinkExactManagedFile(
        parent: LinuxDescriptor,
        name: String,
        expectedBytes: ByteArray,
        label: String,
    ) {
        DescriptorBoundAtomicStateFile.inspectOrNull(
            parent,
            name,
            MAXIMUM_LIVE_STATE_BYTES,
        )?.use { inspection ->
            if (!MessageDigest.isEqual(inspection.bytes, expectedBytes)) {
                liveContainmentFail("$label has different bytes")
            }
            LinuxFilesystemSyscalls.unlink(parent.fd, name)
            val after = LinuxFilesystemSyscalls.identity(inspection.descriptor.fd)
            if (!sameUnlinkedFile(after, inspection.identity)) {
                liveContainmentFail("$label was not exactly unlinked")
            }
            LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name)?.use {
                liveContainmentFail("$label remains named")
            }
            Unit
        } ?: liveContainmentFail("$label disappeared")
    }

    private fun requireCurrentBindings() {
        requireRollbackBindings(path.fileName.toString())
    }

    private fun requireRollbackBindings(journalName: String) {
        val currentOutput = LinuxFilesystemSyscalls.identity(outputLease.fd)
        requireExactDirectoryIdentity(currentOutput, outputIdentity, "GCC output lease")
        val selectedOutput = LinuxFilesystemSyscalls.openRoot(definition.outputLease.path)
        selectedOutput.use {
            requireExactDirectoryIdentity(selectedOutput.identity, outputIdentity, "named GCC output lease")
        }
        val capacity = LinuxFilesystemSyscalls.filesystemCapacity(outputLease)
        requireOutputCapacity(capacity, definition.outputLease)

        val currentState = LinuxFilesystemSyscalls.identity(analysisState.fd)
        requireManagedChild(currentState, stateIdentity, outputIdentity, "GCC analysis state")
        LinuxFilesystemSyscalls.openDirectoryAt(
            outputLease.fd,
            definition.analysisState.path.fileName.toString(),
        ).use { selected ->
            requireManagedChild(selected.identity, stateIdentity, outputIdentity, "named GCC analysis state")
        }

        val currentDirectory = LinuxFilesystemSyscalls.identity(directory.fd)
        requireManagedChild(currentDirectory, directoryIdentity, outputIdentity, "GCC containment journal")
        LinuxFilesystemSyscalls.openDirectoryAt(outputLease.fd, journalName).use { selected ->
            requireManagedChild(
                selected.identity,
                directoryIdentity,
                outputIdentity,
                "named GCC containment journal",
            )
        }
    }

    private fun requireRemovedRollbackLayout() {
        if (rollbackPhase != PreAttachmentRollbackPhase.REMOVED) {
            liveContainmentFail("pre-attachment GCC journal rollback is incomplete")
        }
        val currentOutput = LinuxFilesystemSyscalls.identity(outputLease.fd)
        requireExactDirectoryIdentity(currentOutput, outputIdentity, "GCC output lease after rollback")
        val selectedOutput = LinuxFilesystemSyscalls.openRoot(definition.outputLease.path)
        selectedOutput.use {
            requireExactDirectoryIdentity(
                selectedOutput.identity,
                outputIdentity,
                "named GCC output lease after rollback",
            )
        }
        requireOutputCapacity(
            LinuxFilesystemSyscalls.filesystemCapacity(outputLease),
            definition.outputLease,
        )
        val currentState = LinuxFilesystemSyscalls.identity(analysisState.fd)
        requireManagedChild(currentState, stateIdentity, outputIdentity, "GCC analysis state after rollback")
        LinuxFilesystemSyscalls.openDirectoryAt(
            outputLease.fd,
            definition.analysisState.path.fileName.toString(),
        ).use { selected ->
            requireManagedChild(
                selected.identity,
                stateIdentity,
                outputIdentity,
                "named GCC analysis state after rollback",
            )
        }
        requireExactNames(analysisState, emptySet(), "removed pre-attachment GCC analysis state")
        requireExactNames(
            outputLease,
            setOf(definition.analysisState.path.fileName.toString()),
            "rolled-back GCC output lease",
        )
        if (!sameUnlinkedDirectory(LinuxFilesystemSyscalls.identity(directory.fd), directoryIdentity)) {
            liveContainmentFail("removed pre-attachment GCC journal descriptor changed")
        }
    }

    private fun requireDirectoryRemovedRollbackLayout(proof: String) {
        val currentOutput = LinuxFilesystemSyscalls.identity(outputLease.fd)
        requireExactDirectoryIdentity(currentOutput, outputIdentity, "GCC output lease after journal removal")
        val currentState = LinuxFilesystemSyscalls.identity(analysisState.fd)
        requireManagedChild(currentState, stateIdentity, outputIdentity, "GCC analysis state after journal removal")
        requireExactNames(analysisState, emptySet(), "journal-removed GCC analysis state")
        requireExactManagedFile(
            outputLease,
            proof,
            rollbackMarkerBytes,
            "journal-removed pre-attachment GCC rollback proof",
        )
        requireExactNames(
            outputLease,
            setOf(definition.analysisState.path.fileName.toString(), proof),
            "journal-removed GCC output lease",
        )
        if (!sameUnlinkedDirectory(LinuxFilesystemSyscalls.identity(directory.fd), directoryIdentity)) {
            liveContainmentFail("removed pre-attachment GCC journal descriptor changed")
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        fun release(descriptor: LinuxDescriptor) {
            runCatching { LinuxFilesystemSyscalls.unlock(descriptor) }.exceptionOrNull()?.let { next ->
                val first = failure
                if (first == null) failure = next else if (next !== first) first.addSuppressed(next)
            }
            runCatching { descriptor.close() }.exceptionOrNull()?.let { next ->
                val first = failure
                if (first == null) failure = next else if (next !== first) first.addSuppressed(next)
            }
        }
        release(directory)
        release(analysisState)
        release(outputLease)
        failure?.let { throw it }
    }

    companion object {
        internal fun create(
            definition: GccCompilerEngineValidatedContainmentDefinition,
        ): LiveContainmentJournal {
            val leasePath = definition.outputLease.path
            if (
                leasePath.toRealPath() != leasePath ||
                definition.analysisState.path.parent != leasePath
            ) liveContainmentFail("GCC output lease and analysis state must be canonical direct ancestors")
            LinuxFilesystemSyscalls.requireSupported(leasePath)
            var output: LinuxDescriptor? = null
            var state: LinuxDescriptor? = null
            var journal: LinuxDescriptor? = null
            var outputLocked = false
            var stateLocked = false
            var journalLocked = false
            try {
                val openedOutput = LinuxFilesystemSyscalls.openRoot(leasePath)
                output = openedOutput
                requireOutputLeaseIdentity(openedOutput.identity, definition.outputLease)
                requireOutputCapacity(
                    LinuxFilesystemSyscalls.filesystemCapacity(openedOutput),
                    definition.outputLease,
                )
                if (!LinuxFilesystemSyscalls.tryExclusiveLock(openedOutput)) {
                    liveContainmentFail("GCC output lease is already locked")
                }
                outputLocked = true
                val stateName = definition.analysisState.path.fileName.toString()
                val journalName = journalDirectoryName(definition.bindingSha256)
                val quarantineName = preAttachmentRollbackDirectoryName(definition.bindingSha256)
                val proofName = preAttachmentRollbackProofName(definition.bindingSha256)
                val outputNames = boundedNames(openedOutput, 4, "GCC output lease at journal creation")
                val outputMembers = outputNames.toSet()
                if (outputNames.size != outputMembers.size) {
                    liveContainmentFail("GCC output lease contains duplicate member names")
                }
                val recoveryPhase = when (outputMembers) {
                    setOf(stateName) -> null
                    setOf(stateName, journalName) -> PreAttachmentRollbackPhase.LINKED
                    setOf(stateName, quarantineName) -> PreAttachmentRollbackPhase.QUARANTINED
                    setOf(stateName, quarantineName, proofName) ->
                        PreAttachmentRollbackPhase.MARKER_EXTRACTED
                    setOf(stateName, proofName) -> PreAttachmentRollbackPhase.DIRECTORY_REMOVED
                    else -> liveContainmentFail("GCC output lease contains non-journal residue")
                }
                val openedState = LinuxFilesystemSyscalls.openDirectoryAt(openedOutput.fd, stateName)
                state = openedState
                requireFreshAnalysisState(openedState, openedOutput.identity)
                if (!LinuxFilesystemSyscalls.tryExclusiveLock(openedState)) {
                    liveContainmentFail("GCC analysis state is already locked")
                }
                stateLocked = true
                requireExactNames(openedState, emptySet(), "fresh GCC analysis state")

                if (recoveryPhase == PreAttachmentRollbackPhase.DIRECTORY_REMOVED) {
                    unlinkExactManagedStateFile(
                        openedOutput,
                        proofName,
                        preAttachmentRollbackMarkerBytes(definition),
                        "recovered pre-attachment GCC rollback proof",
                    )
                    LinuxFilesystemSyscalls.synchronize(openedOutput)
                    requireExactNames(openedOutput, setOf(stateName), "recovered GCC output lease")
                } else if (recoveryPhase != null) {
                    val selectedName = if (recoveryPhase == PreAttachmentRollbackPhase.LINKED) {
                        journalName
                    } else {
                        quarantineName
                    }
                    val openedJournal = LinuxFilesystemSyscalls.openDirectoryAt(
                        openedOutput.fd,
                        selectedName,
                    )
                    journal = openedJournal
                    requireManagedChild(
                        openedJournal.identity,
                        openedJournal.identity,
                        openedOutput.identity,
                        "recoverable GCC containment journal",
                    )
                    if (!LinuxFilesystemSyscalls.tryExclusiveLock(openedJournal)) {
                        liveContainmentFail("recoverable GCC containment journal is already locked")
                    }
                    journalLocked = true
                    val recovery = LiveContainmentJournal(
                        leasePath.resolve(journalName),
                        definition,
                        openedOutput,
                        openedState,
                        openedJournal,
                        recoveryPhase,
                    )
                    output = null
                    state = null
                    journal = null
                    outputLocked = false
                    stateLocked = false
                    journalLocked = false
                    try {
                        recovery.rollbackBeforeAttachment()
                    } catch (failure: Throwable) {
                        runCatching { recovery.close() }.exceptionOrNull()
                            ?.takeIf { it !== failure }?.let(failure::addSuppressed)
                        throw failure
                    }
                    recovery.close()
                    return create(definition)
                }

                LinuxFilesystemSyscalls.createDirectory(openedOutput.fd, journalName, OWNER_DIRECTORY_MODE)
                val openedJournal = LinuxFilesystemSyscalls.openDirectoryAt(openedOutput.fd, journalName)
                journal = openedJournal
                LinuxFilesystemSyscalls.chmod(openedJournal, OWNER_DIRECTORY_MODE)
                requireManagedChild(
                    openedJournal.identity,
                    openedJournal.identity,
                    openedOutput.identity,
                    "created GCC containment journal",
                )
                if (!LinuxFilesystemSyscalls.tryExclusiveLock(openedJournal)) {
                    liveContainmentFail("GCC containment journal is already locked")
                }
                journalLocked = true
                LinuxFilesystemSyscalls.synchronize(openedJournal)
                LinuxFilesystemSyscalls.synchronize(openedOutput)
                val result = LiveContainmentJournal(
                    leasePath.resolve(journalName),
                    definition,
                    openedOutput,
                    openedState,
                    openedJournal,
                )
                result.requireCurrentBindings()
                output = null
                state = null
                journal = null
                return result
            } catch (failure: Throwable) {
                if (journalLocked) journal?.let { runCatching { LinuxFilesystemSyscalls.unlock(it) } }
                if (stateLocked) state?.let { runCatching { LinuxFilesystemSyscalls.unlock(it) } }
                if (outputLocked) output?.let { runCatching { LinuxFilesystemSyscalls.unlock(it) } }
                runCatching { journal?.close() }
                runCatching { state?.close() }
                runCatching { output?.close() }
                throw failure
            }
        }
    }
}

internal data class BootClassPathManifestEntry(
    val path: Path,
    val bytes: Long,
    val sha256: String,
)

internal fun parseBootClassPathManifest(
    bytes: ByteArray,
    outputLease: Path,
    artifactPaths: Set<Path>,
): List<BootClassPathManifestEntry> {
    val root = try {
        OracleJson.parseCanonical(bytes, CLASSPATH_JSON_LIMITS) as? JsonObject
            ?: liveContainmentFail("GCC BOOT-keeper class-path manifest must be an object")
    } catch (failure: GccCompilerEngineLiveContainmentException) {
        throw failure
    } catch (failure: Throwable) {
        throw GccCompilerEngineLiveContainmentException(
            "GCC BOOT-keeper class-path manifest is not strict canonical JSON",
            failure,
        )
    }
    if (root.keys != CLASSPATH_MANIFEST_FIELDS) {
        liveContainmentFail("GCC BOOT-keeper class-path manifest has an unexpected shape")
    }
    requireManifestInteger(root, "schemaVersion", 1L)
    requireManifestString(root, "provider", CLASSPATH_MANIFEST_PROVIDER)
    val array = root["entries"] as? JsonArray
        ?: liveContainmentFail("GCC BOOT-keeper class-path entries must be an array")
    if (array.isEmpty() || array.size > MAXIMUM_CLASSPATH_ENTRIES) {
        liveContainmentFail("GCC BOOT-keeper class path exceeds its fixed entry bound")
    }
    var aggregate = 0L
    val paths = hashSetOf<Path>()
    return Collections.unmodifiableList(array.mapIndexed { index, element ->
        val entry = element as? JsonObject
            ?: liveContainmentFail("GCC BOOT-keeper class-path entry $index must be an object")
        if (entry.keys != CLASSPATH_ENTRY_FIELDS) {
            liveContainmentFail("GCC BOOT-keeper class-path entry $index has an unexpected shape")
        }
        val pathString = manifestString(entry, "path")
        val path = try {
            Path.of(pathString)
        } catch (failure: IllegalArgumentException) {
            liveContainmentFail("GCC BOOT-keeper class-path entry $index path is invalid")
        }
        if (
            !path.isAbsolute || path.normalize() != path || path.parent == null ||
            path.fileName.toString().endsWith(".jar").not() ||
            path.startsWith(outputLease) || path in artifactPaths || !paths.add(path)
        ) liveContainmentFail("GCC BOOT-keeper class-path entry $index path is not permitted")
        val size = manifestLong(entry, "bytes")
        if (size !in 1L..MAXIMUM_CLASSPATH_ENTRY_BYTES) {
            liveContainmentFail("GCC BOOT-keeper class-path entry $index bytes exceed fixed policy")
        }
        aggregate = try {
            Math.addExact(aggregate, size)
        } catch (_: ArithmeticException) {
            liveContainmentFail("GCC BOOT-keeper class-path bytes overflow")
        }
        if (aggregate > MAXIMUM_AGGREGATE_CLASSPATH_BYTES) {
            liveContainmentFail("GCC BOOT-keeper class path exceeds its aggregate byte bound")
        }
        val digest = manifestString(entry, "sha256")
        if (!digest.matches(SHA256)) {
            liveContainmentFail("GCC BOOT-keeper class-path entry $index digest is invalid")
        }
        BootClassPathManifestEntry(path, size, digest)
    })
}

internal fun deriveRuntimeConfiguration(
    definition: GccCompilerEngineValidatedContainmentDefinition,
    classPath: List<FullTreeFunctionObservationClassPathEntry>,
): FullTreeFunctionObservationIsolationConfiguration {
    val byRole = definition.artifacts.associateBy(GccCompilerEngineContainmentArtifactIdentity::role)
    val java = byRole.getValue(GccCompilerEngineContainmentArtifactRole.JAVA_EXECUTABLE)
    val javaRoot = java.path.parent?.parent
        ?: liveContainmentFail("GCC Java executable has no derivable runtime root")
    if (javaRoot == Path.of("/") || javaRoot.toRealPath() != javaRoot) {
        liveContainmentFail("GCC Java runtime root is not canonical")
    }
    val manifestCache = mutableMapOf<Path, String>()
    fun runtimeMount(source: Path, destination: Path): FullTreeFunctionObservationRuntimeMount =
        FullTreeFunctionObservationRuntimeMount(
            source,
            destination,
            manifestCache.getOrPut(source) {
                calculateFullTreeObservationRuntimeManifestSha256(source)
            },
        )
    val systemMounts = FIXED_SYSTEM_LIBRARY_DESTINATIONS.mapNotNull { destination ->
        if (!Files.isDirectory(destination, LinkOption.NOFOLLOW_LINKS) && !Files.isDirectory(destination)) {
            null
        } else {
            val source = destination.toRealPath()
            runtimeMount(source, destination)
        }
    }
    if (systemMounts.isEmpty()) liveContainmentFail("GCC host has no fixed system-library runtime mounts")
    val uid = definition.outputLease.uid
    return FullTreeFunctionObservationIsolationConfiguration(
        javaExecutable = java.path,
        javaRuntime = runtimeMount(javaRoot, KOTLIN_RUNTIME_DESTINATION),
        systemLibraryMounts = systemMounts,
        bubblewrapExecutable = byRole.getValue(
            GccCompilerEngineContainmentArtifactRole.BUBBLEWRAP_EXECUTABLE,
        ).path,
        resourceLimiterExecutable = byRole.getValue(
            GccCompilerEngineContainmentArtifactRole.RESOURCE_LIMITER_EXECUTABLE,
        ).path,
        scopeSupervisorExecutable = byRole.getValue(
            GccCompilerEngineContainmentArtifactRole.SYSTEMD_RUN_EXECUTABLE,
        ).path,
        scopeInspectorExecutable = byRole.getValue(
            GccCompilerEngineContainmentArtifactRole.SYSTEMCTL_EXECUTABLE,
        ).path,
        systemdBusControllerExecutable = byRole.getValue(
            GccCompilerEngineContainmentArtifactRole.SYSTEMD_BUSCTL_EXECUTABLE,
        ).path,
        systemdUserRuntimeDirectory = Path.of("/run/user/$uid"),
        workerClassPath = classPath,
        expectedJavaSha256 = java.sha256,
        expectedBubblewrapSha256 = byRole.getValue(
            GccCompilerEngineContainmentArtifactRole.BUBBLEWRAP_EXECUTABLE,
        ).sha256,
        expectedResourceLimiterSha256 = byRole.getValue(
            GccCompilerEngineContainmentArtifactRole.RESOURCE_LIMITER_EXECUTABLE,
        ).sha256,
        expectedScopeSupervisorSha256 = byRole.getValue(
            GccCompilerEngineContainmentArtifactRole.SYSTEMD_RUN_EXECUTABLE,
        ).sha256,
        expectedScopeInspectorSha256 = byRole.getValue(
            GccCompilerEngineContainmentArtifactRole.SYSTEMCTL_EXECUTABLE,
        ).sha256,
        expectedSystemdBusControllerSha256 = byRole.getValue(
            GccCompilerEngineContainmentArtifactRole.SYSTEMD_BUSCTL_EXECUTABLE,
        ).sha256,
    )
}

private fun requireSupportedCheckpoint(
    definition: GccCompilerEngineValidatedContainmentDefinition,
): KotlinSystemdCgroupBootResources {
    if (
        definition.runKind == GccCompilerEngineContainmentRunKind.RESUMED ||
        definition.analysisState.mode != GccCompilerEngineAnalysisStateMode.FRESH_EMPTY
    ) {
        liveContainmentFail(
            "the BOOT-only controller does not yet authenticate or authorize resume-state restoration",
        )
    }
    if (definition.outputLease.uid != currentUid()) {
        liveContainmentFail("GCC output lease belongs to a different user-systemd manager")
    }
    if (definition.budgets.wallClockMillis % 1_000L != 0L) {
        liveContainmentFail("the BOOT-only controller requires a whole-second wall-clock budget")
    }
    return try {
        KotlinSystemdCgroupBootResources(
            definition.budgets.wallClockMillis,
            definition.budgets.maximumResidentBytes,
            definition.budgets.pidsMax,
        )
    } catch (failure: IllegalArgumentException) {
        throw GccCompilerEngineLiveContainmentException(
            "the containment budgets are outside the Kotlin BOOT policy",
            failure,
        )
    }
}

private fun requireOutputLeaseIdentity(
    actual: LinuxFileIdentity,
    expected: GccCompilerEngineOutputLeaseIdentity,
) {
    if (
        !actual.isDirectory || actual.isRegularFile || actual.isSymbolicLink ||
        actual.key.device != expected.device || actual.key.inode != expected.inode ||
        actual.mountId != expected.mountId || actual.uid != expected.uid || actual.gid != expected.gid ||
        actual.mode.permissions != expected.permissions || expected.permissions != OWNER_DIRECTORY_MODE
    ) liveContainmentFail("GCC output lease differs from its exact descriptor identity")
}

private fun requireOutputCapacity(
    actual: LinuxFilesystemCapacity,
    expected: GccCompilerEngineOutputLeaseIdentity,
) {
    if (
        actual.readOnly || actual.availableBytes < expected.requiredAvailableBytes ||
        actual.totalBytes > expected.maximumFilesystemBytes ||
        actual.availableInodes < expected.requiredAvailableInodes ||
        actual.totalInodes > expected.maximumFilesystemInodes
    ) liveContainmentFail(
        "GCC output lease differs from its bounded capacity policy " +
            "(readOnly=${actual.readOnly}, availableBytes=${actual.availableBytes}, " +
            "requiredAvailableBytes=${expected.requiredAvailableBytes}, totalBytes=${actual.totalBytes}, " +
            "maximumFilesystemBytes=${expected.maximumFilesystemBytes}, " +
            "availableInodes=${actual.availableInodes}, " +
            "requiredAvailableInodes=${expected.requiredAvailableInodes}, " +
            "totalInodes=${actual.totalInodes}, maximumFilesystemInodes=${expected.maximumFilesystemInodes})",
    )
}

private fun requireFreshAnalysisState(actual: LinuxDescriptor, parent: LinuxFileIdentity) {
    requireManagedChild(actual.identity, actual.identity, parent, "GCC analysis state")
}

private fun requireManagedChild(
    actual: LinuxFileIdentity,
    expected: LinuxFileIdentity,
    parent: LinuxFileIdentity,
    label: String,
) {
    if (
        !sameDirectoryIdentity(actual, expected) || !actual.isDirectory ||
        actual.isRegularFile || actual.isSymbolicLink ||
        actual.uid != currentUid() || actual.gid != parent.gid || actual.mountId != parent.mountId ||
        actual.mode.permissions != OWNER_DIRECTORY_MODE
    ) liveContainmentFail("$label is not the exact owner-only child directory")
}

private fun requireExactDirectoryIdentity(
    actual: LinuxFileIdentity,
    expected: LinuxFileIdentity,
    label: String,
) {
    if (
        !sameDirectoryIdentity(actual, expected) || !actual.isDirectory ||
        actual.isRegularFile || actual.isSymbolicLink ||
        actual.uid != currentUid() || actual.mode.permissions != OWNER_DIRECTORY_MODE
    ) liveContainmentFail("$label changed its exact descriptor identity")
}

private fun sameDirectoryIdentity(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
    first.key == second.key && first.mountId == second.mountId &&
        first.uid == second.uid && first.gid == second.gid &&
        first.mode.permissions == second.mode.permissions &&
        first.isDirectory && second.isDirectory &&
        !first.isRegularFile && !second.isRegularFile &&
        !first.isSymbolicLink && !second.isSymbolicLink

private fun sameUnlinkedFile(actual: LinuxFileIdentity, expected: LinuxFileIdentity): Boolean =
    actual.key == expected.key && actual.mountId == expected.mountId &&
        actual.uid == expected.uid && actual.gid == expected.gid &&
        actual.mode.permissions == expected.mode.permissions && actual.linkCount == 0 &&
        actual.isRegularFile && expected.isRegularFile &&
        !actual.isDirectory && !expected.isDirectory &&
        !actual.isSymbolicLink && !expected.isSymbolicLink

private fun sameUnlinkedDirectory(actual: LinuxFileIdentity, expected: LinuxFileIdentity): Boolean =
    actual.key == expected.key && actual.mountId == expected.mountId &&
        actual.uid == expected.uid && actual.gid == expected.gid &&
        actual.mode.permissions == expected.mode.permissions && actual.linkCount == 0 &&
        actual.isDirectory && expected.isDirectory &&
        !actual.isRegularFile && !expected.isRegularFile &&
        !actual.isSymbolicLink && !expected.isSymbolicLink

private fun requireExactNames(directory: LinuxDescriptor, expected: Set<String>, label: String) {
    val names = boundedNames(directory, expected.size + 1, label)
    if (names.size != expected.size || names.toSet() != expected) {
        liveContainmentFail("$label has unexpected members")
    }
}

private fun unlinkExactManagedStateFile(
    parent: LinuxDescriptor,
    name: String,
    expectedBytes: ByteArray,
    label: String,
) {
    DescriptorBoundAtomicStateFile.inspectOrNull(
        parent,
        name,
        MAXIMUM_LIVE_STATE_BYTES,
    )?.use { inspection ->
        if (!MessageDigest.isEqual(inspection.bytes, expectedBytes)) {
            liveContainmentFail("$label has different bytes")
        }
        LinuxFilesystemSyscalls.unlink(parent.fd, name)
        val after = LinuxFilesystemSyscalls.identity(inspection.descriptor.fd)
        if (!sameUnlinkedFile(after, inspection.identity)) {
            liveContainmentFail("$label was not exactly unlinked")
        }
        LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name)?.use {
            liveContainmentFail("$label remains named")
        }
        Unit
    } ?: liveContainmentFail("$label disappeared")
}

private fun boundedNames(directory: LinuxDescriptor, maximum: Int, label: String): List<String> = try {
    LinuxFilesystemSyscalls.directoryEntryNames(directory, maximum)
} catch (failure: Throwable) {
    throw GccCompilerEngineLiveContainmentException("cannot enumerate $label within its hard bound", failure)
}

private fun requireManifestString(root: JsonObject, name: String, expected: String) {
    if (manifestString(root, name) != expected) {
        liveContainmentFail("GCC BOOT-keeper class-path manifest field $name differs")
    }
}

private fun requireManifestInteger(root: JsonObject, name: String, expected: Long) {
    if (manifestLong(root, name) != expected) {
        liveContainmentFail("GCC BOOT-keeper class-path manifest field $name differs")
    }
}

private fun manifestString(root: JsonObject, name: String): String {
    val value = root[name] as? JsonPrimitive
    if (value == null || !value.isString) {
        liveContainmentFail("GCC BOOT-keeper class-path field $name must be a string")
    }
    return value.content
}

private fun manifestLong(root: JsonObject, name: String): Long {
    val value = root[name] as? JsonPrimitive
    if (value == null || value.isString || value.content.any { it in ".eE" }) {
        liveContainmentFail("GCC BOOT-keeper class-path field $name must be an integer")
    }
    return value.longOrNull
        ?: liveContainmentFail("GCC BOOT-keeper class-path field $name exceeds the integer range")
}

private fun journalDirectoryName(bindingSha256: String): String =
    ".gcc-containment-${bindingSha256.take(32)}"

private fun preAttachmentRollbackDirectoryName(bindingSha256: String): String =
    ".gcc-containment-rollback-${bindingSha256.take(32)}"

private fun preAttachmentRollbackProofName(bindingSha256: String): String =
    "gcc-containment-rollback-proof-${bindingSha256.take(32)}.json"

private fun preAttachmentRollbackMarkerBytes(
    definition: GccCompilerEngineValidatedContainmentDefinition,
): ByteArray = OracleJson.canonicalBytes(
    JsonObject(
        linkedMapOf(
            "schemaVersion" to JsonPrimitive(1),
            "provider" to JsonPrimitive("gcc-pre-attachment-journal-rollback-v1"),
            "bindingSha256" to JsonPrimitive(definition.bindingSha256),
            "definitionSha256" to JsonPrimitive(OracleArtifacts.sha256(definition.canonicalBytes)),
        ),
    ),
)

private fun currentUid(): Int =
    (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()

private inline fun <T> translateLiveContainmentFailure(label: String, action: () -> T): T = try {
    action()
} catch (failure: GccCompilerEngineLiveContainmentException) {
    throw failure
} catch (failure: Throwable) {
    throw GccCompilerEngineLiveContainmentException("cannot $label: ${failure.message}", failure)
}

private fun liveContainmentFail(message: String): Nothing =
    throw GccCompilerEngineLiveContainmentException(message)

private const val LIVE_BOOT_AUTHORITY = "kotlin-live-systemd-cgroup-boot-owner-v1"
private const val LIVE_TERMINAL_AUTHORITY = "kotlin-proved-systemd-cgroup-terminal-absence-v1"
private const val OWNER_DIRECTORY_MODE = 0x1c0 // 0700
private const val MAXIMUM_LIVE_DEFINITION_BYTES = 1024 * 1024
private const val MAXIMUM_LIVE_STATE_BYTES = 1024 * 1024
private const val MAXIMUM_CLASSPATH_MANIFEST_BYTES = 1024L * 1024L
private const val MAXIMUM_CLASSPATH_ENTRIES = 512
private const val MAXIMUM_CLASSPATH_ENTRY_BYTES = 1024L * 1024L * 1024L
private const val MAXIMUM_AGGREGATE_CLASSPATH_BYTES = 2L * 1024L * 1024L * 1024L
private const val CLASSPATH_MANIFEST_PROVIDER = "gcc-kotlin-boot-classpath-manifest-v1"
private const val DEFINITION_FILE = "definition.json"
private const val ATTACHED_RECEIPT_FILE = "unit-attached.json"
private const val ABSENCE_RECEIPT_FILE = "terminal-absence.json"
private const val ROLLBACK_DEFINITION_QUARANTINE_FILE = "rollback-definition-pre-attachment.json"
private const val ROLLBACK_MARKER_FILE = "rollback-pre-attachment.json"
private val SHA256 = Regex("[0-9a-f]{64}")
private val PRIVATE_RUN_DIRECTORY = Regex("\\.function-observation-run-[0-9a-f]{32}")
private val KOTLIN_RUNTIME_DESTINATION = Path.of("/decomp-runtime/java")
private val FIXED_SYSTEM_LIBRARY_DESTINATIONS = listOf("/lib", "/lib64", "/usr/lib", "/usr/lib64")
    .map(Path::of)
private val CLASSPATH_MANIFEST_FIELDS = setOf("schemaVersion", "provider", "entries")
private val CLASSPATH_ENTRY_FIELDS = setOf("path", "bytes", "sha256")
private val CLASSPATH_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_CLASSPATH_MANIFEST_BYTES.toInt(),
    maximumCanonicalBytes = MAXIMUM_CLASSPATH_MANIFEST_BYTES.toInt(),
    maximumDepth = 6,
    maximumNodes = 4096,
    maximumStringBytes = 64 * 1024,
    maximumTotalStringBytes = 512 * 1024,
    maximumNumberCharacters = 32,
)

private enum class PreAttachmentRollbackPhase {
    LINKED,
    QUARANTINED,
    MARKER_EXTRACTED,
    DIRECTORY_REMOVED,
    REMOVED,
}
