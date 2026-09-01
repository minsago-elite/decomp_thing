package decompengine.oracle.behavior

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.DescriptorBoundStateInspection
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull

class LlvmBehaviorHostedContainerV1OperationJournalException(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

/**
 * Durable code-only checkpoints for a future hosted-container controller.
 *
 * These names describe orchestration positions only. A journal transition authenticates no input,
 * image, container, worker, publication, or attestation fact and grants no authority to do so.
 */
enum class LlvmBehaviorHostedContainerV1OperationPhase(val wireName: String) {
    RECOVERED("recovered"),
    INPUT_AUTHENTICATED("input-authenticated"),
    IMAGE_AUTHENTICATED("image-authenticated"),
    CREATE_ARMED("create-armed"),
    CONTAINER_VERIFIED("container-verified"),
    WORKER_COMPLETED("worker-completed"),
    STAGED_PAIR_VERIFIED("staged-pair-verified"),
    CONTAINER_ABSENCE_PROVED("container-absence-proved"),
    FINAL_PAIR_PUBLISHED("final-pair-published"),
    COMPLETE_AWAITING_ATTESTATION("complete-awaiting-attestation"),
    CLEANUP_REQUIRED("cleanup-required"),
}

/**
 * One locked, append-only lifecycle journal.
 *
 * Every mutation is deliberately fact-free. The future controller that owns authenticated inputs,
 * the container runtime, cleanup, and publication must perform those operations independently.
 * This owner cannot accept their parsed results and cannot turn its phase names into evidence. Its
 * deterministic [containerName] is only a cold-recovery locator. Image ID, container ID, and
 * staging identities remain unbound and require a separately reviewed live coordinator.
 */
sealed interface LlvmBehaviorHostedContainerV1OperationJournalOwner : AutoCloseable {
    val authority: String
    val operationId: String
    val requestSha256: String
    val bindingSha256: String
    val latestTransitionSha256: String
    val phase: LlvmBehaviorHostedContainerV1OperationPhase
    val containerName: String
    val journalRootPathSha256: String
    val canonicalBindingBytes: ByteArray

    val acpRole: String
    val acpOracleAccess: String
    val oracleAuthority: Boolean
    val acpAuthority: Boolean
    val workflowAuthority: Boolean
    val admissionAuthority: Boolean
    val startAuthority: Boolean
    val containmentAuthority: Boolean
    val executionAuthority: Boolean
    val observationAuthority: Boolean
    val scoringAuthority: Boolean
    val publicationAuthority: Boolean
    val attestationAuthority: Boolean
    val releaseAuthority: Boolean
    val parsedFactsAccepted: Boolean
    val engineAccepted: Boolean
    val runnerAccepted: Boolean
    val imageIdentityBound: Boolean
    val containerIdentityBound: Boolean
    val stagingIdentitiesBound: Boolean
    val executionClaimed: Boolean
    val releaseEligible: Boolean

    fun recordInputAuthenticated(): LlvmBehaviorHostedContainerV1OperationPhase
    fun recordImageAuthenticated(): LlvmBehaviorHostedContainerV1OperationPhase
    fun armCreate(): LlvmBehaviorHostedContainerV1OperationPhase
    fun recordContainerVerified(): LlvmBehaviorHostedContainerV1OperationPhase
    fun recordWorkerCompleted(): LlvmBehaviorHostedContainerV1OperationPhase
    fun recordStagedPairVerified(): LlvmBehaviorHostedContainerV1OperationPhase
    fun recordContainerAbsenceProved(): LlvmBehaviorHostedContainerV1OperationPhase
    fun recordFinalPairPublished(): LlvmBehaviorHostedContainerV1OperationPhase
    fun recordCompleteAwaitingAttestation(): LlvmBehaviorHostedContainerV1OperationPhase
    fun requireCleanup(): LlvmBehaviorHostedContainerV1OperationPhase

    override fun close()
}

/**
 * Opens a journal from one raw, already-absolute root path.
 *
 * The root is the whole operation namespace: it must already be a canonical owner-owned mode-0700
 * directory beneath a non-writable trusted parent. No operation id, parsed fact, receipt, engine,
 * runner, ACP artifact, or claimed digest is accepted from the caller.
 */
object LlvmBehaviorHostedContainerV1OperationJournal {
    fun open(journalRootPath: Path): LlvmBehaviorHostedContainerV1OperationJournalOwner =
        translateJournalFailures("open hosted-container v1 operation journal") {
            BoundOwner(journalRootPath)
        }

    private class BoundOwner(
        journalRootPath: Path,
    ) : LlvmBehaviorHostedContainerV1OperationJournalOwner {
        private val opened = openBoundJournal(journalRootPath)
        private var history = opened.history
        private var closed = false
        private var poisoned = false

        override val authority: String
            get() = JOURNAL_AUTHORITY
        override val operationId: String
            get() = opened.binding.operationId
        override val requestSha256: String
            get() = opened.binding.requestSha256
        override val bindingSha256: String
            get() = opened.binding.bindingSha256
        override val latestTransitionSha256: String
            @Synchronized get() = history.latest.transitionSha256
        override val phase: LlvmBehaviorHostedContainerV1OperationPhase
            @Synchronized get() = history.phase
        override val containerName: String
            get() = opened.binding.containerName
        override val journalRootPathSha256: String
            get() = opened.binding.journalRootPathSha256
        override val canonicalBindingBytes: ByteArray
            get() = opened.binding.canonicalBytes()

        override val acpRole: String
            get() = ACP_ROLE
        override val acpOracleAccess: String
            get() = ACP_ORACLE_ACCESS
        override val oracleAuthority: Boolean
            get() = false
        override val acpAuthority: Boolean
            get() = false
        override val workflowAuthority: Boolean
            get() = false
        override val admissionAuthority: Boolean
            get() = false
        override val startAuthority: Boolean
            get() = false
        override val containmentAuthority: Boolean
            get() = false
        override val executionAuthority: Boolean
            get() = false
        override val observationAuthority: Boolean
            get() = false
        override val scoringAuthority: Boolean
            get() = false
        override val publicationAuthority: Boolean
            get() = false
        override val attestationAuthority: Boolean
            get() = false
        override val releaseAuthority: Boolean
            get() = false
        override val parsedFactsAccepted: Boolean
            get() = false
        override val engineAccepted: Boolean
            get() = false
        override val runnerAccepted: Boolean
            get() = false
        override val imageIdentityBound: Boolean
            get() = false
        override val containerIdentityBound: Boolean
            get() = false
        override val stagingIdentitiesBound: Boolean
            get() = false
        override val executionClaimed: Boolean
            get() = false
        override val releaseEligible: Boolean
            get() = false

        override fun recordInputAuthenticated() = append(
            LlvmBehaviorHostedContainerV1OperationPhase.INPUT_AUTHENTICATED,
        )

        override fun recordImageAuthenticated() = append(
            LlvmBehaviorHostedContainerV1OperationPhase.IMAGE_AUTHENTICATED,
        )

        override fun armCreate() = append(LlvmBehaviorHostedContainerV1OperationPhase.CREATE_ARMED)

        override fun recordContainerVerified() = append(
            LlvmBehaviorHostedContainerV1OperationPhase.CONTAINER_VERIFIED,
        )

        override fun recordWorkerCompleted() = append(
            LlvmBehaviorHostedContainerV1OperationPhase.WORKER_COMPLETED,
        )

        override fun recordStagedPairVerified() = append(
            LlvmBehaviorHostedContainerV1OperationPhase.STAGED_PAIR_VERIFIED,
        )

        override fun recordContainerAbsenceProved() = append(
            LlvmBehaviorHostedContainerV1OperationPhase.CONTAINER_ABSENCE_PROVED,
        )

        override fun recordFinalPairPublished() = append(
            LlvmBehaviorHostedContainerV1OperationPhase.FINAL_PAIR_PUBLISHED,
        )

        override fun recordCompleteAwaitingAttestation() = append(
            LlvmBehaviorHostedContainerV1OperationPhase.COMPLETE_AWAITING_ATTESTATION,
        )

        override fun requireCleanup() = append(
            LlvmBehaviorHostedContainerV1OperationPhase.CLEANUP_REQUIRED,
        )

        @Synchronized
        private fun append(
            target: LlvmBehaviorHostedContainerV1OperationPhase,
        ): LlvmBehaviorHostedContainerV1OperationPhase = translateJournalFailures(
            "append hosted-container v1 operation phase ${target.wireName}",
        ) {
            checkOpen()
            try {
                history = opened.journal.append(target)
                history.phase
            } catch (failure: Throwable) {
                poisoned = true
                throw failure
            }
        }

        private fun checkOpen() {
            check(!closed) { "hosted-container v1 operation journal owner is closed" }
            check(!poisoned) { "hosted-container v1 operation journal owner is poisoned" }
        }

        @Synchronized
        override fun close() {
            if (closed) return
            closed = true
            opened.journal.close()
        }
    }
}

private class HostedContainerOperationBinding private constructor(
    val schemaVersion: Int,
    val provider: String,
    val authority: String,
    val operationId: String,
    val requestSha256: String,
    val containerName: String,
    val journalRootPathSha256: String,
    val bindingSha256: String,
) {
    init {
        if (
            schemaVersion != BINDING_SCHEMA_VERSION || provider != JOURNAL_PROVIDER ||
            authority != JOURNAL_AUTHORITY || operationId != requestSha256 ||
            !operationId.matches(SHA256) || !journalRootPathSha256.matches(SHA256) ||
            containerName != hostedContainerName(operationId) || !containerName.matches(CONTAINER_NAME) ||
            !bindingSha256.matches(SHA256)
        ) journalFail("hosted-container v1 operation binding has invalid identities")
        if (requestSha256 != sha256(canonical(requestDocument(journalRootPathSha256)))) {
            journalFail("hosted-container v1 operation request hash is invalid")
        }
        if (bindingSha256 != sha256(canonicalBytes(includeSelfHash = false))) {
            journalFail("hosted-container v1 operation binding self hash is invalid")
        }
    }

    fun canonicalBytes(): ByteArray = canonicalBytes(includeSelfHash = true)

    private fun canonicalBytes(includeSelfHash: Boolean): ByteArray = canonical(
        JsonObject(
            buildMap {
                put("acpBoundary", STATIC_ACP_BOUNDARY)
                put("authority", JsonPrimitive(authority))
                if (includeSelfHash) put("bindingSha256", JsonPrimitive(bindingSha256))
                put("claims", FALSE_CLAIMS)
                put("containerName", JsonPrimitive(containerName))
                put("journalRootPathSha256", JsonPrimitive(journalRootPathSha256))
                put("operationId", JsonPrimitive(operationId))
                put("provider", JsonPrimitive(provider))
                put("requestSha256", JsonPrimitive(requestSha256))
                put("schemaVersion", JsonPrimitive(schemaVersion))
            },
        ),
    )

    companion object {
        fun create(journalRootPathSha256: String): HostedContainerOperationBinding {
            val requestSha256 = sha256(canonical(requestDocument(journalRootPathSha256)))
            val provisional = bindingDocument(
                requestSha256,
                journalRootPathSha256,
                bindingSha256 = null,
            )
            return HostedContainerOperationBinding(
                BINDING_SCHEMA_VERSION,
                JOURNAL_PROVIDER,
                JOURNAL_AUTHORITY,
                requestSha256,
                requestSha256,
                hostedContainerName(requestSha256),
                journalRootPathSha256,
                sha256(canonical(provisional)),
            )
        }

        fun parseCanonical(bytes: ByteArray): HostedContainerOperationBinding = translateJournalFailures(
            "parse hosted-container v1 operation binding",
        ) {
            val root = OracleJson.parseCanonical(bytes, JOURNAL_JSON_LIMITS) as? JsonObject
                ?: journalFail("hosted-container v1 operation binding must be an object")
            root.requireExactKeys(BINDING_FIELDS, "hosted-container v1 operation binding")
            if (root.requiredObject("acpBoundary") != STATIC_ACP_BOUNDARY) {
                journalFail("hosted-container v1 operation binding has a different ACP boundary")
            }
            if (root.requiredObject("claims") != FALSE_CLAIMS) {
                journalFail("hosted-container v1 operation binding has non-false claims")
            }
            HostedContainerOperationBinding(
                root.requiredInt("schemaVersion"),
                root.requiredString("provider"),
                root.requiredString("authority"),
                root.requiredString("operationId"),
                root.requiredString("requestSha256"),
                root.requiredString("containerName"),
                root.requiredString("journalRootPathSha256"),
                root.requiredString("bindingSha256"),
            )
        }

        private fun requestDocument(journalRootPathSha256: String): JsonObject = JsonObject(
            mapOf(
                "acpBoundary" to STATIC_ACP_BOUNDARY,
                "authority" to JsonPrimitive(JOURNAL_AUTHORITY),
                "claims" to FALSE_CLAIMS,
                "journalRootPathSha256" to JsonPrimitive(journalRootPathSha256),
                "provider" to JsonPrimitive(REQUEST_PROVIDER),
                "schemaVersion" to JsonPrimitive(REQUEST_SCHEMA_VERSION),
            ),
        )

        private fun bindingDocument(
            requestSha256: String,
            journalRootPathSha256: String,
            bindingSha256: String?,
        ): JsonObject = JsonObject(
            buildMap {
                put("acpBoundary", STATIC_ACP_BOUNDARY)
                put("authority", JsonPrimitive(JOURNAL_AUTHORITY))
                bindingSha256?.let { put("bindingSha256", JsonPrimitive(it)) }
                put("claims", FALSE_CLAIMS)
                put("containerName", JsonPrimitive(hostedContainerName(requestSha256)))
                put("journalRootPathSha256", JsonPrimitive(journalRootPathSha256))
                put("operationId", JsonPrimitive(requestSha256))
                put("provider", JsonPrimitive(JOURNAL_PROVIDER))
                put("requestSha256", JsonPrimitive(requestSha256))
                put("schemaVersion", JsonPrimitive(BINDING_SCHEMA_VERSION))
            },
        )
    }
}

private class HostedContainerOperationTransition private constructor(
    val schemaVersion: Int,
    val provider: String,
    val authority: String,
    val operationId: String,
    val bindingSha256: String,
    val sequence: Int,
    val phase: LlvmBehaviorHostedContainerV1OperationPhase,
    val previousTransitionSha256: String,
    val transitionSha256: String,
) {
    val fileName: String
        get() = transitionFileName(sequence)

    init {
        if (
            schemaVersion != TRANSITION_SCHEMA_VERSION || provider != JOURNAL_PROVIDER ||
            authority != JOURNAL_AUTHORITY || !operationId.matches(SHA256) ||
            !bindingSha256.matches(SHA256) || !previousTransitionSha256.matches(SHA256) ||
            !transitionSha256.matches(SHA256) || sequence !in 0 until MAXIMUM_TRANSITIONS
        ) journalFail("hosted-container v1 operation transition has invalid identities")
        if (sequence == 0) {
            if (
                phase != LlvmBehaviorHostedContainerV1OperationPhase.RECOVERED ||
                previousTransitionSha256 != ZERO_SHA256
            ) journalFail("recovered transition has an invalid chain position")
        } else if (previousTransitionSha256 == ZERO_SHA256) {
            journalFail("hosted-container v1 operation transition has no predecessor")
        }
        if (transitionSha256 != sha256(canonicalBytes(includeSelfHash = false))) {
            journalFail("hosted-container v1 operation transition self hash is invalid")
        }
    }

    fun canonicalBytes(): ByteArray = canonicalBytes(includeSelfHash = true)

    private fun canonicalBytes(includeSelfHash: Boolean): ByteArray = canonical(
        JsonObject(
            buildMap {
                put("authority", JsonPrimitive(authority))
                put("bindingSha256", JsonPrimitive(bindingSha256))
                put("claims", FALSE_CLAIMS)
                put("operationId", JsonPrimitive(operationId))
                put("phase", JsonPrimitive(phase.wireName))
                put("previousTransitionSha256", JsonPrimitive(previousTransitionSha256))
                put("provider", JsonPrimitive(provider))
                put("schemaVersion", JsonPrimitive(schemaVersion))
                put("sequence", JsonPrimitive(sequence))
                if (includeSelfHash) put("transitionSha256", JsonPrimitive(transitionSha256))
            },
        ),
    )

    companion object {
        fun initial(binding: HostedContainerOperationBinding): HostedContainerOperationTransition = create(
            binding,
            0,
            LlvmBehaviorHostedContainerV1OperationPhase.RECOVERED,
            ZERO_SHA256,
        )

        fun next(
            binding: HostedContainerOperationBinding,
            previous: HostedContainerOperationTransition,
            phase: LlvmBehaviorHostedContainerV1OperationPhase,
        ): HostedContainerOperationTransition {
            if (phase !in allowedNextPhases(previous.phase)) {
                journalFail(
                    "hosted-container v1 phase ${previous.phase.wireName} cannot advance to ${phase.wireName}",
                )
            }
            return create(binding, previous.sequence + 1, phase, previous.transitionSha256)
        }

        private fun create(
            binding: HostedContainerOperationBinding,
            sequence: Int,
            phase: LlvmBehaviorHostedContainerV1OperationPhase,
            previousTransitionSha256: String,
        ): HostedContainerOperationTransition {
            val provisional = transitionDocument(
                binding.operationId,
                binding.bindingSha256,
                sequence,
                phase,
                previousTransitionSha256,
                transitionSha256 = null,
            )
            return HostedContainerOperationTransition(
                TRANSITION_SCHEMA_VERSION,
                JOURNAL_PROVIDER,
                JOURNAL_AUTHORITY,
                binding.operationId,
                binding.bindingSha256,
                sequence,
                phase,
                previousTransitionSha256,
                sha256(canonical(provisional)),
            )
        }

        fun parseCanonical(bytes: ByteArray): HostedContainerOperationTransition = translateJournalFailures(
            "parse hosted-container v1 operation transition",
        ) {
            val root = OracleJson.parseCanonical(bytes, JOURNAL_JSON_LIMITS) as? JsonObject
                ?: journalFail("hosted-container v1 operation transition must be an object")
            root.requireExactKeys(TRANSITION_FIELDS, "hosted-container v1 operation transition")
            if (root.requiredObject("claims") != FALSE_CLAIMS) {
                journalFail("hosted-container v1 operation transition has non-false claims")
            }
            val phaseName = root.requiredString("phase")
            val phase = LlvmBehaviorHostedContainerV1OperationPhase.entries.singleOrNull {
                it.wireName == phaseName
            } ?: journalFail("hosted-container v1 operation transition has an unknown phase")
            HostedContainerOperationTransition(
                root.requiredInt("schemaVersion"),
                root.requiredString("provider"),
                root.requiredString("authority"),
                root.requiredString("operationId"),
                root.requiredString("bindingSha256"),
                root.requiredInt("sequence"),
                phase,
                root.requiredString("previousTransitionSha256"),
                root.requiredString("transitionSha256"),
            )
        }

        private fun transitionDocument(
            operationId: String,
            bindingSha256: String,
            sequence: Int,
            phase: LlvmBehaviorHostedContainerV1OperationPhase,
            previousTransitionSha256: String,
            transitionSha256: String?,
        ): JsonObject = JsonObject(
            buildMap {
                put("authority", JsonPrimitive(JOURNAL_AUTHORITY))
                put("bindingSha256", JsonPrimitive(bindingSha256))
                put("claims", FALSE_CLAIMS)
                put("operationId", JsonPrimitive(operationId))
                put("phase", JsonPrimitive(phase.wireName))
                put("previousTransitionSha256", JsonPrimitive(previousTransitionSha256))
                put("provider", JsonPrimitive(JOURNAL_PROVIDER))
                put("schemaVersion", JsonPrimitive(TRANSITION_SCHEMA_VERSION))
                put("sequence", JsonPrimitive(sequence))
                transitionSha256?.let { put("transitionSha256", JsonPrimitive(it)) }
            },
        )
    }
}

private data class HostedContainerOperationHistory(
    val binding: HostedContainerOperationBinding,
    val transitions: List<HostedContainerOperationTransition>,
) {
    val latest: HostedContainerOperationTransition
        get() = transitions.lastOrNull()
            ?: journalFail("hosted-container v1 operation has no durable phase")
    val phase: LlvmBehaviorHostedContainerV1OperationPhase
        get() = latest.phase

    companion object {
        fun validatePrefix(
            expectedBinding: HostedContainerOperationBinding,
            actualBinding: HostedContainerOperationBinding,
            transitions: List<HostedContainerOperationTransition>,
        ): HostedContainerOperationHistory {
            if (!actualBinding.canonicalBytes().contentEquals(expectedBinding.canonicalBytes())) {
                journalFail("hosted-container v1 operation journal is bound to a different root")
            }
            if (transitions.size > MAXIMUM_TRANSITIONS) {
                journalFail("hosted-container v1 operation journal has too many transitions")
            }
            var previous: HostedContainerOperationTransition? = null
            transitions.forEachIndexed { index, actual ->
                val expected = if (index == 0) {
                    HostedContainerOperationTransition.initial(expectedBinding)
                } else {
                    HostedContainerOperationTransition.next(
                        expectedBinding,
                        checkNotNull(previous),
                        actual.phase,
                    )
                }
                if (
                    actual.fileName != transitionFileName(index) ||
                    !actual.canonicalBytes().contentEquals(expected.canonicalBytes())
                ) journalFail("hosted-container v1 operation transition chain is invalid")
                previous = actual
            }
            return HostedContainerOperationHistory(actualBinding, transitions.toList())
        }
    }
}

private data class OpenedJournal(
    val journal: HostedContainerDescriptorOperationJournal,
    val binding: HostedContainerOperationBinding,
    val history: HostedContainerOperationHistory,
)

private fun openBoundJournal(journalRootPath: Path): OpenedJournal {
    requireExactRawPath(journalRootPath)
    val binding = HostedContainerOperationBinding.create(pathCommitment(journalRootPath))
    val authority = JournalRoot.open(journalRootPath)
    val journal = HostedContainerDescriptorOperationJournal(binding, authority)
    try {
        journal.completeExactPendingPublication()
        return OpenedJournal(journal, binding, journal.initialize())
    } catch (failure: Throwable) {
        runCatching { journal.close() }.exceptionOrNull()?.let(failure::addSuppressed)
        throw failure
    }
}

private class JournalRoot private constructor(
    private val path: Path,
    private val parentPath: Path,
    private val parent: LinuxDescriptor,
    private val rootName: String,
    val descriptor: LinuxDescriptor,
) : AutoCloseable {
    private var closed = false
    private var poisoned = false

    @Synchronized
    fun requireBound() {
        check(!closed) { "hosted-container v1 journal root is closed" }
        check(!poisoned) { "hosted-container v1 journal root is poisoned" }
        try {
            requireRootBinding()
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    private fun requireRootBinding() {
        requireTrustedParent(LinuxFilesystemSyscalls.identity(parent.fd), parent.identity)
        if (!Files.isSameFile(parentPath, LinuxFilesystemSyscalls.descriptorPath(parent))) {
            journalFail("hosted-container v1 journal parent pathname changed")
        }
        val currentRoot = LinuxFilesystemSyscalls.identity(descriptor.fd)
        requirePinnedManagedDirectory(currentRoot, descriptor.identity, "hosted-container v1 journal root")
        val selected = try {
            LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, rootName)
        } catch (failure: Exception) {
            journalFail("hosted-container v1 journal root was detached: ${failure.message}")
        }
        selected.use {
            if (!sameDirectory(LinuxFilesystemSyscalls.identity(selected.fd), currentRoot)) {
                journalFail("hosted-container v1 journal root changed identity")
            }
        }
        if (!Files.isSameFile(path, LinuxFilesystemSyscalls.descriptorPath(descriptor))) {
            journalFail("hosted-container v1 journal root pathname changed")
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        runCatching { LinuxFilesystemSyscalls.unlock(descriptor) }.exceptionOrNull()?.let { failure = it }
        runCatching { descriptor.close() }.exceptionOrNull()?.let { closeFailure ->
            failure = failure?.also { it.addSuppressed(closeFailure) } ?: closeFailure
        }
        runCatching { parent.close() }.exceptionOrNull()?.let { closeFailure ->
            failure = failure?.also { it.addSuppressed(closeFailure) } ?: closeFailure
        }
        failure?.let { throw it }
    }

    companion object {
        fun open(path: Path): JournalRoot {
            if (
                !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) || path.toRealPath() != path ||
                path.parent == null
            ) journalFail("hosted-container v1 journal root must be a canonical non-root directory")
            LinuxFilesystemSyscalls.requireSupported(path)
            val parentPath = path.parent
            if (parentPath.toRealPath() != parentPath) {
                journalFail("hosted-container v1 journal root parent must be canonical")
            }
            val parent = LinuxFilesystemSyscalls.openRoot(parentPath)
            val root = try {
                LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, path.fileName.toString())
            } catch (failure: Throwable) {
                runCatching { parent.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
            var locked = false
            try {
                requireTrustedParent(LinuxFilesystemSyscalls.identity(parent.fd), parent.identity)
                requirePinnedManagedDirectory(
                    LinuxFilesystemSyscalls.identity(root.fd),
                    root.identity,
                    "hosted-container v1 journal root",
                )
                if (!LinuxFilesystemSyscalls.tryExclusiveLock(root)) {
                    journalFail("hosted-container v1 journal root is already locked")
                }
                locked = true
                LinuxFilesystemSyscalls.synchronize(root)
                LinuxFilesystemSyscalls.synchronize(parent)
                return JournalRoot(path, parentPath, parent, path.fileName.toString(), root).also {
                    it.requireBound()
                }
            } catch (failure: Throwable) {
                if (locked) {
                    runCatching { LinuxFilesystemSyscalls.unlock(root) }
                        .exceptionOrNull()?.let(failure::addSuppressed)
                }
                runCatching { root.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                runCatching { parent.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

private class HostedContainerDescriptorOperationJournal(
    private val expectedBinding: HostedContainerOperationBinding,
    private val authority: JournalRoot,
) : AutoCloseable {
    private val directory: LinuxDescriptor
        get() = authority.descriptor
    private var closed = false
    private var poisoned = false

    @Synchronized
    fun initialize(): HostedContainerOperationHistory = boundOperation {
        var current = loadPrefix()
        if (current == null) {
            DescriptorBoundAtomicStateFile.publishNoReplace(
                directory,
                BINDING_FILE,
                expectedBinding.canonicalBytes(),
                MAXIMUM_RECORD_BYTES,
            )
            current = loadPrefix()
                ?: journalFail("hosted-container v1 binding publication disappeared")
        }
        if (current.transitions.isEmpty()) {
            val initial = HostedContainerOperationTransition.initial(expectedBinding)
            DescriptorBoundAtomicStateFile.publishNoReplace(
                directory,
                initial.fileName,
                initial.canonicalBytes(),
                MAXIMUM_RECORD_BYTES,
            )
            current = loadPrefix()
                ?: journalFail("hosted-container v1 recovered transition disappeared")
        }
        requirePhased(current)
    }

    @Synchronized
    fun append(
        target: LlvmBehaviorHostedContainerV1OperationPhase,
    ): HostedContainerOperationHistory = boundOperation {
        val current = requirePhased(
            loadPrefix() ?: journalFail("hosted-container v1 operation journal is empty"),
        )
        if (current.phase == target) return@boundOperation current
        val next = HostedContainerOperationTransition.next(expectedBinding, current.latest, target)
        DescriptorBoundAtomicStateFile.publishNoReplace(
            directory,
            next.fileName,
            next.canonicalBytes(),
            MAXIMUM_RECORD_BYTES,
        )
        requirePhased(
            loadPrefix() ?: journalFail("hosted-container v1 operation transition disappeared"),
        ).also { completed ->
            if (completed.phase != target) {
                journalFail("hosted-container v1 operation did not reach ${target.wireName}")
            }
        }
    }

    /** Completes at most one exact immutable publication and never invents recovery bytes. */
    @Synchronized
    fun completeExactPendingPublication() = boundOperation {
        val names = entryNames()
        val pendingNames = names.filter(::isAtomicStateName)
        if (pendingNames.size > 1) {
            journalFail("hosted-container v1 operation journal has multiple pending publications")
        }
        val pendingName = pendingNames.singleOrNull()
        if (pendingName == null) {
            loadPrefix()
            // Covers death after rename but before the final parent-directory fsync.
            LinuxFilesystemSyscalls.synchronize(directory)
            return@boundOperation
        }
        val targetName = atomicTargetName(pendingName)
        if (targetName in names) {
            journalFail("hosted-container v1 journal has a target and its pending publication")
        }
        if (targetName == BINDING_FILE) {
            if (names != listOf(pendingName)) {
                journalFail("pending hosted-container v1 binding has unbound residue")
            }
            inspectRequired(pendingName).use { pending ->
                requireExactBinding(HostedContainerOperationBinding.parseCanonical(pending.bytes))
                completePending(targetName, pending)
            }
        } else {
            val prefix = loadPrefix(allowedAtomicTarget = targetName)
                ?: journalFail("pending hosted-container v1 transition has no binding")
            val expectedSequence = prefix.transitions.size
            if (targetName != transitionFileName(expectedSequence)) {
                journalFail("pending hosted-container v1 transition is not contiguous")
            }
            inspectRequired(pendingName).use { pending ->
                val actual = HostedContainerOperationTransition.parseCanonical(pending.bytes)
                val expected = if (expectedSequence == 0) {
                    HostedContainerOperationTransition.initial(expectedBinding)
                } else {
                    HostedContainerOperationTransition.next(expectedBinding, prefix.latest, actual.phase)
                }
                if (
                    actual.fileName != targetName ||
                    !actual.canonicalBytes().contentEquals(expected.canonicalBytes())
                ) journalFail("pending hosted-container v1 transition is not the exact next record")
                completePending(targetName, pending)
            }
        }
        loadPrefix() ?: journalFail("hosted-container v1 cold completion lost its journal")
    }

    private fun completePending(targetName: String, pending: DescriptorBoundStateInspection) {
        DescriptorBoundAtomicStateFile.completeExistingTemporaryNoReplace(
            directory,
            targetName,
            pending,
            MAXIMUM_RECORD_BYTES,
        )
    }

    private fun loadPrefix(allowedAtomicTarget: String? = null): HostedContainerOperationHistory? {
        val names = entryNames()
        if (names.isEmpty()) return null
        val allowedAtomicName = allowedAtomicTarget?.let(DescriptorBoundAtomicStateFile::temporaryName)
        val atomicNames = names.filter(::isAtomicStateName)
        if (atomicNames.any { it != allowedAtomicName }) {
            journalFail("hosted-container v1 operation journal requires exact cold recovery")
        }
        if (names.any { name ->
                name != BINDING_FILE && !name.matches(TRANSITION_FILE_NAME) && name != allowedAtomicName
            }
        ) journalFail("hosted-container v1 operation journal contains an unowned entry")
        val bindingSnapshot = DescriptorBoundAtomicStateFile.readOrNull(
            directory,
            BINDING_FILE,
            MAXIMUM_RECORD_BYTES,
        ) ?: journalFail("hosted-container v1 operation journal is missing its binding")
        val actualBinding = HostedContainerOperationBinding.parseCanonical(bindingSnapshot.bytes)
        requireExactBinding(actualBinding)
        val transitionNames = names.filter(TRANSITION_FILE_NAME::matches).sorted()
        val transitions = transitionNames.map { name ->
            val snapshot = DescriptorBoundAtomicStateFile.readOrNull(
                directory,
                name,
                MAXIMUM_RECORD_BYTES,
            ) ?: journalFail("hosted-container v1 operation transition disappeared")
            HostedContainerOperationTransition.parseCanonical(snapshot.bytes).also { transition ->
                if (transition.fileName != name) {
                    journalFail("hosted-container v1 operation transition occupies the wrong name")
                }
            }
        }
        return HostedContainerOperationHistory.validatePrefix(expectedBinding, actualBinding, transitions)
    }

    private fun entryNames(): List<String> {
        val names = LinuxFilesystemSyscalls.directoryEntryNames(
            directory,
            MAXIMUM_JOURNAL_ENTRIES + 1,
        ).sorted()
        if (names.size > MAXIMUM_JOURNAL_ENTRIES) {
            journalFail("hosted-container v1 operation journal exceeds its entry bound")
        }
        return names
    }

    private fun inspectRequired(name: String): DescriptorBoundStateInspection =
        DescriptorBoundAtomicStateFile.inspectOrNull(directory, name, MAXIMUM_RECORD_BYTES)
            ?: journalFail("hosted-container v1 operation journal entry disappeared: $name")

    private fun requireExactBinding(actual: HostedContainerOperationBinding) {
        if (!actual.canonicalBytes().contentEquals(expectedBinding.canonicalBytes())) {
            journalFail("hosted-container v1 operation journal is bound to a different root")
        }
    }

    private fun requirePhased(
        history: HostedContainerOperationHistory,
    ): HostedContainerOperationHistory {
        if (history.transitions.isEmpty()) {
            journalFail("hosted-container v1 operation journal is missing its recovered phase")
        }
        return history
    }

    private inline fun <T> boundOperation(action: () -> T): T {
        checkOpen()
        return try {
            authority.requireBound()
            val result = action()
            authority.requireBound()
            result
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    private fun checkOpen() {
        check(!closed) { "hosted-container v1 operation journal is closed" }
        check(!poisoned) { "hosted-container v1 operation journal is poisoned" }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        authority.close()
    }
}

private fun allowedNextPhases(
    phase: LlvmBehaviorHostedContainerV1OperationPhase,
): Set<LlvmBehaviorHostedContainerV1OperationPhase> = when (phase) {
    LlvmBehaviorHostedContainerV1OperationPhase.RECOVERED -> setOf(
        LlvmBehaviorHostedContainerV1OperationPhase.INPUT_AUTHENTICATED,
    )
    LlvmBehaviorHostedContainerV1OperationPhase.INPUT_AUTHENTICATED -> setOf(
        LlvmBehaviorHostedContainerV1OperationPhase.IMAGE_AUTHENTICATED,
    )
    LlvmBehaviorHostedContainerV1OperationPhase.IMAGE_AUTHENTICATED -> setOf(
        LlvmBehaviorHostedContainerV1OperationPhase.CREATE_ARMED,
    )
    LlvmBehaviorHostedContainerV1OperationPhase.CREATE_ARMED -> setOf(
        LlvmBehaviorHostedContainerV1OperationPhase.CONTAINER_VERIFIED,
        LlvmBehaviorHostedContainerV1OperationPhase.CLEANUP_REQUIRED,
    )
    LlvmBehaviorHostedContainerV1OperationPhase.CONTAINER_VERIFIED -> setOf(
        LlvmBehaviorHostedContainerV1OperationPhase.WORKER_COMPLETED,
        LlvmBehaviorHostedContainerV1OperationPhase.CLEANUP_REQUIRED,
    )
    LlvmBehaviorHostedContainerV1OperationPhase.WORKER_COMPLETED -> setOf(
        LlvmBehaviorHostedContainerV1OperationPhase.STAGED_PAIR_VERIFIED,
        LlvmBehaviorHostedContainerV1OperationPhase.CLEANUP_REQUIRED,
    )
    LlvmBehaviorHostedContainerV1OperationPhase.STAGED_PAIR_VERIFIED -> setOf(
        LlvmBehaviorHostedContainerV1OperationPhase.CONTAINER_ABSENCE_PROVED,
        LlvmBehaviorHostedContainerV1OperationPhase.CLEANUP_REQUIRED,
    )
    LlvmBehaviorHostedContainerV1OperationPhase.CONTAINER_ABSENCE_PROVED -> setOf(
        LlvmBehaviorHostedContainerV1OperationPhase.FINAL_PAIR_PUBLISHED,
    )
    LlvmBehaviorHostedContainerV1OperationPhase.FINAL_PAIR_PUBLISHED -> setOf(
        LlvmBehaviorHostedContainerV1OperationPhase.COMPLETE_AWAITING_ATTESTATION,
    )
    LlvmBehaviorHostedContainerV1OperationPhase.COMPLETE_AWAITING_ATTESTATION,
    LlvmBehaviorHostedContainerV1OperationPhase.CLEANUP_REQUIRED,
    -> emptySet()
}

private fun atomicTargetName(pendingName: String): String {
    if (pendingName == DescriptorBoundAtomicStateFile.temporaryName(BINDING_FILE)) return BINDING_FILE
    val match = ATOMIC_TRANSITION_FILE_NAME.matchEntire(pendingName)
        ?: journalFail("hosted-container v1 operation journal has an unknown pending publication")
    return "transition-${match.groupValues[1]}.json"
}

private fun transitionFileName(sequence: Int): String {
    if (sequence !in 0 until MAXIMUM_TRANSITIONS) {
        journalFail("hosted-container v1 transition sequence is out of range")
    }
    return "transition-${sequence.toString().padStart(4, '0')}.json"
}

private fun isAtomicStateName(name: String): Boolean = name.startsWith('.') && name.endsWith(".atomic")

private fun requireExactRawPath(path: Path) {
    if (!path.isAbsolute || path.normalize() != path || path.parent == null) {
        journalFail("hosted-container v1 journal root path must already be absolute and normalized")
    }
}

private fun pathCommitment(path: Path): String = sha256(path.toString().toByteArray(Charsets.UTF_8))

private fun hostedContainerName(operationId: String): String {
    if (!operationId.matches(SHA256)) journalFail("hosted-container v1 operation id is invalid")
    return CONTAINER_NAME_PREFIX + operationId
}

private fun requirePinnedManagedDirectory(
    actual: LinuxFileIdentity,
    expected: LinuxFileIdentity,
    label: String,
) {
    val uid = currentUid()
    if (
        !sameDirectory(actual, expected) || actual.uid != uid ||
        actual.mode.permissions != OWNER_DIRECTORY_MODE
    ) journalFail("$label is not a pinned owner-only directory")
}

private fun requireTrustedParent(actual: LinuxFileIdentity, expected: LinuxFileIdentity) {
    val uid = currentUid()
    if (
        !sameDirectory(actual, expected) || actual.uid !in setOf(0, uid) ||
        actual.mode.permissions and GROUP_OR_OTHER_WRITE_MODE != 0
    ) journalFail("hosted-container v1 journal root has an untrusted parent")
}

private fun sameDirectory(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
    first.key == second.key && first.mountId == second.mountId &&
        first.uid == second.uid && first.gid == second.gid &&
        first.isDirectory && second.isDirectory &&
        !first.isRegularFile && !second.isRegularFile &&
        !first.isSymbolicLink && !second.isSymbolicLink

private fun currentUid(): Int =
    (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()

private fun canonical(document: JsonObject): ByteArray =
    OracleJson.canonicalBytes(document, JOURNAL_JSON_LIMITS)

private fun sha256(bytes: ByteArray): String = OracleArtifacts.sha256(bytes)

private fun JsonObject.requireExactKeys(expected: Set<String>, label: String) {
    if (keys != expected) journalFail("$label fields are not exact")
}

private fun JsonObject.requiredObject(name: String): JsonObject = this[name] as? JsonObject
    ?: journalFail("hosted-container v1 journal field is not an object: $name")

private fun JsonObject.requiredString(name: String): String {
    val value = this[name] as? JsonPrimitive
        ?: journalFail("hosted-container v1 journal field is not a string: $name")
    if (!value.isString) journalFail("hosted-container v1 journal field is not a string: $name")
    return value.content
}

private fun JsonObject.requiredInt(name: String): Int {
    val value = this[name] as? JsonPrimitive
        ?: journalFail("hosted-container v1 journal field is not an integer: $name")
    if (value.isString) journalFail("hosted-container v1 journal field is not an integer: $name")
    return value.intOrNull
        ?: journalFail("hosted-container v1 journal field is not an integer: $name")
}

private inline fun <T> translateJournalFailures(label: String, action: () -> T): T = try {
    action()
} catch (failure: LlvmBehaviorHostedContainerV1OperationJournalException) {
    throw failure
} catch (failure: Exception) {
    throw LlvmBehaviorHostedContainerV1OperationJournalException(
        "$label failed: ${failure.message ?: failure::class.java.simpleName}",
        failure,
    )
}

private fun journalFail(message: String): Nothing =
    throw LlvmBehaviorHostedContainerV1OperationJournalException(message)

private const val BINDING_SCHEMA_VERSION = 1
private const val REQUEST_SCHEMA_VERSION = 1
private const val TRANSITION_SCHEMA_VERSION = 1
private const val JOURNAL_PROVIDER = "kotlin-llvm-behavior-hosted-container-v1-operation-journal-v1"
private const val REQUEST_PROVIDER = "kotlin-llvm-behavior-hosted-container-v1-operation-request-v1"
private const val JOURNAL_AUTHORITY =
    "non-authoritative-code-only-llvm-behavior-hosted-container-v1-operation-journal"
private const val ACP_ROLE = "first-class-candidate-producer-operator"
private const val ACP_ORACLE_ACCESS = "read-only-oracle-input"
private const val CONTAINER_NAME_PREFIX = "decomp-llvm-behavior-v1-"

private const val OWNER_DIRECTORY_MODE = 0x1c0 // 0700
private const val GROUP_OR_OTHER_WRITE_MODE = 0x12 // 0022
private const val MAXIMUM_RECORD_BYTES = 64 * 1024
private const val MAXIMUM_TRANSITIONS = 11
private const val MAXIMUM_JOURNAL_ENTRIES = 1 + MAXIMUM_TRANSITIONS + 1
private const val BINDING_FILE = "binding.json"
private val ZERO_SHA256 = "0".repeat(64)
private val SHA256 = Regex("[0-9a-f]{64}")
private val CONTAINER_NAME = Regex("[a-z0-9][a-z0-9_.-]{0,127}")
private val TRANSITION_FILE_NAME = Regex("transition-[0-9]{4}\\.json")
private val ATOMIC_TRANSITION_FILE_NAME = Regex("\\.transition-([0-9]{4})\\.json\\.atomic")

private val JOURNAL_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_RECORD_BYTES,
    maximumCanonicalBytes = MAXIMUM_RECORD_BYTES,
    maximumDepth = 6,
    maximumNodes = 128,
    maximumStringBytes = 4096,
    maximumTotalStringBytes = 32 * 1024,
    maximumNumberCharacters = 16,
)

private val STATIC_ACP_BOUNDARY = JsonObject(
    mapOf(
        "authority" to JsonPrimitive(false),
        "oracleAccess" to JsonPrimitive(ACP_ORACLE_ACCESS),
        "role" to JsonPrimitive(ACP_ROLE),
    ),
)

private val FALSE_CLAIMS = JsonObject(
    mapOf(
        "acpAuthority" to JsonPrimitive(false),
        "admissionAuthority" to JsonPrimitive(false),
        "attestationAuthority" to JsonPrimitive(false),
        "containmentAuthority" to JsonPrimitive(false),
        "containerIdentityBound" to JsonPrimitive(false),
        "engineAccepted" to JsonPrimitive(false),
        "executionAuthority" to JsonPrimitive(false),
        "executionClaimed" to JsonPrimitive(false),
        "imageIdentityBound" to JsonPrimitive(false),
        "observationAuthority" to JsonPrimitive(false),
        "oracleAuthority" to JsonPrimitive(false),
        "parsedFactsAccepted" to JsonPrimitive(false),
        "publicationAuthority" to JsonPrimitive(false),
        "releaseAuthority" to JsonPrimitive(false),
        "releaseEligible" to JsonPrimitive(false),
        "runnerAccepted" to JsonPrimitive(false),
        "scoringAuthority" to JsonPrimitive(false),
        "startAuthority" to JsonPrimitive(false),
        "stagingIdentitiesBound" to JsonPrimitive(false),
        "workflowAuthority" to JsonPrimitive(false),
    ),
)

private val BINDING_FIELDS = setOf(
    "acpBoundary",
    "authority",
    "bindingSha256",
    "claims",
    "containerName",
    "journalRootPathSha256",
    "operationId",
    "provider",
    "requestSha256",
    "schemaVersion",
)

private val TRANSITION_FIELDS = setOf(
    "authority",
    "bindingSha256",
    "claims",
    "operationId",
    "phase",
    "previousTransitionSha256",
    "provider",
    "schemaVersion",
    "sequence",
    "transitionSha256",
)
