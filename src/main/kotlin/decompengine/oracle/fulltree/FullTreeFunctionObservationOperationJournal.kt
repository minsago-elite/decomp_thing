package decompengine.oracle.fulltree

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxSyscallException
import decompengine.acp.permissions
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.DescriptorBoundStateInspection
import decompengine.oracle.core.DescriptorBoundStateFaultInjector
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class FullTreeFunctionObservationOperationJournalException(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

/** Immutable request preimage and deterministic names shared by every operation-owned resource. */
internal class FullTreeFunctionObservationOperationBinding private constructor(
    val schemaVersion: Int,
    val provider: String,
    val operationId: String,
    val requestSha256: String,
    val shardId: String,
    val shardInputSha256: String,
    val scopeSha256: String,
    val inventoryArtifactSha256: String,
    val richArtifactSha256: String,
    val isolationSha256: String,
    val outputPathSha256: String,
    val requiredAvailableBytes: Long,
    val maximumFilesystemBytes: Long,
    val requiredAvailableInodes: Long,
    val maximumFilesystemInodes: Long,
    val journalDirectoryName: String,
    val leaseDirectoryName: String,
    val leaseReleaseQuarantineDirectoryName: String,
    val leaseFailureQuarantineDirectoryName: String,
    val runDirectoryName: String,
    val runQuarantineDirectoryName: String,
    val unitName: String,
    val outputStageName: String,
    val bindingSha256: String,
) {
    init {
        if (
            schemaVersion != OPERATION_BINDING_SCHEMA_VERSION || provider != OPERATION_PROVIDER ||
            !operationId.matches(SHA256) || !requestSha256.matches(SHA256) ||
            !shardId.matches(SHARD_IDENTIFIER) || !shardInputSha256.matches(SHA256) ||
            !scopeSha256.matches(SHA256) || !inventoryArtifactSha256.matches(SHA256) ||
            !richArtifactSha256.matches(SHA256) || !isolationSha256.matches(SHA256) ||
            !outputPathSha256.matches(SHA256) || !bindingSha256.matches(SHA256)
        ) journalFail("function-observation operation binding has invalid identities")
        if (
            requiredAvailableBytes <= 0L || maximumFilesystemBytes < requiredAvailableBytes ||
            requiredAvailableInodes < MINIMUM_LEASE_INODES ||
            maximumFilesystemInodes < requiredAvailableInodes
        ) journalFail("function-observation operation binding has invalid disk policy")
        if (
            journalDirectoryName != journalDirectoryName(operationId) ||
            leaseDirectoryName != leaseDirectoryName(operationId) ||
            leaseReleaseQuarantineDirectoryName != leaseReleaseQuarantineDirectoryName(operationId) ||
            leaseFailureQuarantineDirectoryName != leaseFailureQuarantineDirectoryName(operationId) ||
            runDirectoryName != runDirectoryName(operationId) ||
            runQuarantineDirectoryName != runQuarantineDirectoryName(operationId) ||
            unitName != unitName(operationId) || outputStageName != outputStageName(operationId)
        ) journalFail("function-observation operation binding has non-derived runtime names")
        if (
            requestSha256 != ZERO_SHA256 && requestSha256 != sha256(canonicalRequestBytes()) ||
            requestSha256 == ZERO_SHA256 && bindingSha256 != ZERO_SHA256
        ) {
            journalFail("function-observation operation request hash is invalid")
        }
        if (bindingSha256 != ZERO_SHA256 && bindingSha256 != sha256(canonicalBytes(includeSelfHash = false))) {
            journalFail("function-observation operation binding self hash is invalid")
        }
    }

    fun canonicalBytes(): ByteArray = canonicalBytes(includeSelfHash = true)

    fun diskOperation(): FullTreeDiskScratchOperation = FullTreeDiskScratchOperation(
        operationId,
        requestSha256,
        shardId,
        scopeSha256,
    )

    fun diskPolicy(): FullTreeDiskScratchPolicy = FullTreeDiskScratchPolicy(
        requiredAvailableBytes,
        maximumFilesystemBytes,
        requiredAvailableInodes,
        maximumFilesystemInodes,
    )

    private fun canonicalBytes(includeSelfHash: Boolean): ByteArray = OracleJson.canonicalBytes(
        JsonObject(
            buildMap {
                if (includeSelfHash) put("bindingSha256", JsonPrimitive(bindingSha256))
                put("journalDirectoryName", JsonPrimitive(journalDirectoryName))
                put("isolationSha256", JsonPrimitive(isolationSha256))
                put("inventoryArtifactSha256", JsonPrimitive(inventoryArtifactSha256))
                put("leaseDirectoryName", JsonPrimitive(leaseDirectoryName))
                put("leaseFailureQuarantineDirectoryName", JsonPrimitive(leaseFailureQuarantineDirectoryName))
                put("leaseReleaseQuarantineDirectoryName", JsonPrimitive(leaseReleaseQuarantineDirectoryName))
                put("maximumFilesystemBytes", JsonPrimitive(maximumFilesystemBytes))
                put("maximumFilesystemInodes", JsonPrimitive(maximumFilesystemInodes))
                put("operationId", JsonPrimitive(operationId))
                put("outputPathSha256", JsonPrimitive(outputPathSha256))
                put("outputStageName", JsonPrimitive(outputStageName))
                put("provider", JsonPrimitive(provider))
                put("requestSha256", JsonPrimitive(requestSha256))
                put("requiredAvailableBytes", JsonPrimitive(requiredAvailableBytes))
                put("requiredAvailableInodes", JsonPrimitive(requiredAvailableInodes))
                put("runDirectoryName", JsonPrimitive(runDirectoryName))
                put("runQuarantineDirectoryName", JsonPrimitive(runQuarantineDirectoryName))
                put("schemaVersion", JsonPrimitive(schemaVersion))
                put("shardInputSha256", JsonPrimitive(shardInputSha256))
                put("scopeSha256", JsonPrimitive(scopeSha256))
                put("shardId", JsonPrimitive(shardId))
                put("richArtifactSha256", JsonPrimitive(richArtifactSha256))
                put("unitName", JsonPrimitive(unitName))
            },
        ),
        OPERATION_JSON_LIMITS,
    )

    internal fun canonicalBytesWithoutSelfHashForTest(): ByteArray = canonicalBytes(includeSelfHash = false)

    internal fun canonicalRequestBytesForTest(): ByteArray = canonicalRequestBytes()

    private fun canonicalRequestBytes(): ByteArray = OracleJson.canonicalBytes(
        JsonObject(
            mapOf(
                "inventoryArtifactSha256" to JsonPrimitive(inventoryArtifactSha256),
                "isolationSha256" to JsonPrimitive(isolationSha256),
                "maximumFilesystemBytes" to JsonPrimitive(maximumFilesystemBytes),
                "maximumFilesystemInodes" to JsonPrimitive(maximumFilesystemInodes),
                "operationId" to JsonPrimitive(operationId),
                "outputPathSha256" to JsonPrimitive(outputPathSha256),
                "provider" to JsonPrimitive(OPERATION_REQUEST_PROVIDER),
                "requiredAvailableBytes" to JsonPrimitive(requiredAvailableBytes),
                "requiredAvailableInodes" to JsonPrimitive(requiredAvailableInodes),
                "richArtifactSha256" to JsonPrimitive(richArtifactSha256),
                "schemaVersion" to JsonPrimitive(OPERATION_REQUEST_SCHEMA_VERSION),
                "scopeSha256" to JsonPrimitive(scopeSha256),
                "shardId" to JsonPrimitive(shardId),
                "shardInputSha256" to JsonPrimitive(shardInputSha256),
            ),
        ),
        OPERATION_JSON_LIMITS,
    )

    internal companion object {
        fun create(
            operationId: String,
            shardId: String,
            shardInputSha256: String,
            scopeSha256: String,
            inventoryArtifactSha256: String,
            richArtifactSha256: String,
            isolationSha256: String,
            output: Path,
            diskPolicy: FullTreeDiskScratchPolicy,
        ): FullTreeFunctionObservationOperationBinding {
            val normalizedOutput = output.toAbsolutePath().normalize()
            if (!normalizedOutput.isAbsolute || normalizedOutput.parent == null) {
                journalFail("function-observation operation output path is invalid")
            }
            val arguments = BindingArguments(
                operationId,
                shardId,
                shardInputSha256,
                scopeSha256,
                inventoryArtifactSha256,
                richArtifactSha256,
                isolationSha256,
                sha256(normalizedOutput.toString().toByteArray(Charsets.UTF_8)),
                diskPolicy,
            )
            val requestSha256 = sha256(arguments.binding(ZERO_SHA256, ZERO_SHA256).canonicalRequestBytes())
            val provisional = arguments.binding(requestSha256, ZERO_SHA256)
            return arguments.binding(
                requestSha256,
                sha256(provisional.canonicalBytes(includeSelfHash = false)),
            )
        }

        fun parseCanonical(bytes: ByteArray): FullTreeFunctionObservationOperationBinding =
            translateJournalFailures("parse function-observation operation binding") {
                val root = OracleJson.parseCanonical(bytes, OPERATION_JSON_LIMITS) as? JsonObject
                    ?: journalFail("function-observation operation binding must be an object")
                root.requireExactKeys(OPERATION_BINDING_FIELDS, "function-observation operation binding")
                FullTreeFunctionObservationOperationBinding(
                    schemaVersion = root.journalInt("schemaVersion"),
                    provider = root.journalString("provider"),
                    operationId = root.journalString("operationId"),
                    requestSha256 = root.journalString("requestSha256"),
                    shardId = root.journalString("shardId"),
                    shardInputSha256 = root.journalString("shardInputSha256"),
                    scopeSha256 = root.journalString("scopeSha256"),
                    inventoryArtifactSha256 = root.journalString("inventoryArtifactSha256"),
                    richArtifactSha256 = root.journalString("richArtifactSha256"),
                    isolationSha256 = root.journalString("isolationSha256"),
                    outputPathSha256 = root.journalString("outputPathSha256"),
                    requiredAvailableBytes = root.journalLong("requiredAvailableBytes"),
                    maximumFilesystemBytes = root.journalLong("maximumFilesystemBytes"),
                    requiredAvailableInodes = root.journalLong("requiredAvailableInodes"),
                    maximumFilesystemInodes = root.journalLong("maximumFilesystemInodes"),
                    journalDirectoryName = root.journalString("journalDirectoryName"),
                    leaseDirectoryName = root.journalString("leaseDirectoryName"),
                    leaseReleaseQuarantineDirectoryName =
                        root.journalString("leaseReleaseQuarantineDirectoryName"),
                    leaseFailureQuarantineDirectoryName =
                        root.journalString("leaseFailureQuarantineDirectoryName"),
                    runDirectoryName = root.journalString("runDirectoryName"),
                    runQuarantineDirectoryName = root.journalString("runQuarantineDirectoryName"),
                    unitName = root.journalString("unitName"),
                    outputStageName = root.journalString("outputStageName"),
                    bindingSha256 = root.journalString("bindingSha256"),
                ).also { binding ->
                    if (binding.bindingSha256 == ZERO_SHA256) {
                        journalFail("function-observation operation binding cannot retain its provisional hash")
                    }
                }
            }
    }

    private data class BindingArguments(
        val operationId: String,
        val shardId: String,
        val shardInputSha256: String,
        val scopeSha256: String,
        val inventoryArtifactSha256: String,
        val richArtifactSha256: String,
        val isolationSha256: String,
        val outputPathSha256: String,
        val diskPolicy: FullTreeDiskScratchPolicy,
    ) {
        fun binding(requestSha256: String, selfHash: String) = FullTreeFunctionObservationOperationBinding(
            schemaVersion = OPERATION_BINDING_SCHEMA_VERSION,
            provider = OPERATION_PROVIDER,
            operationId = operationId,
            requestSha256 = requestSha256,
            shardId = shardId,
            shardInputSha256 = shardInputSha256,
            scopeSha256 = scopeSha256,
            inventoryArtifactSha256 = inventoryArtifactSha256,
            richArtifactSha256 = richArtifactSha256,
            isolationSha256 = isolationSha256,
            outputPathSha256 = outputPathSha256,
            requiredAvailableBytes = diskPolicy.requiredAvailableBytes,
            maximumFilesystemBytes = diskPolicy.maximumFilesystemBytes,
            requiredAvailableInodes = diskPolicy.requiredAvailableInodes,
            maximumFilesystemInodes = diskPolicy.maximumFilesystemInodes,
            journalDirectoryName = journalDirectoryName(operationId),
            leaseDirectoryName = leaseDirectoryName(operationId),
            leaseReleaseQuarantineDirectoryName = leaseReleaseQuarantineDirectoryName(operationId),
            leaseFailureQuarantineDirectoryName = leaseFailureQuarantineDirectoryName(operationId),
            runDirectoryName = runDirectoryName(operationId),
            runQuarantineDirectoryName = runQuarantineDirectoryName(operationId),
            unitName = unitName(operationId),
            outputStageName = outputStageName(operationId),
            bindingSha256 = selfHash,
        )
    }
}

internal enum class FullTreeFunctionObservationOperationPhase(val wireName: String) {
    PREPARING("preparing"),
    LEASED("leased"),
    UNIT_ATTACHED("unit-attached"),
    CGROUP_ABSENT("cgroup-absent"),
    PUBLISHED("published"),
    COMPLETE("complete"),
    RECOVERED_ABORT("recovered-abort"),
    ;

    val terminal: Boolean
        get() = this == COMPLETE || this == RECOVERED_ABORT

    companion object {
        fun fromWireName(value: String): FullTreeFunctionObservationOperationPhase =
            entries.singleOrNull { it.wireName == value }
                ?: journalFail("function-observation operation phase is invalid")
    }
}

/** One immutable, self-hashed link in an append-only operation transition chain. */
internal class FullTreeFunctionObservationOperationTransition private constructor(
    val schemaVersion: Int,
    val provider: String,
    val operationId: String,
    val bindingSha256: String,
    val sequence: Int,
    val previousTransitionSha256: String,
    val phase: FullTreeFunctionObservationOperationPhase,
    val diskEvidenceSha256: String?,
    val outputSha256: String?,
    val outputBytes: Long?,
    val transitionSha256: String,
) {
    init {
        if (
            schemaVersion != OPERATION_TRANSITION_SCHEMA_VERSION || provider != OPERATION_PROVIDER ||
            !operationId.matches(SHA256) || !bindingSha256.matches(SHA256) ||
            sequence !in 0..MAXIMUM_OPERATION_TRANSITIONS || !previousTransitionSha256.matches(SHA256) ||
            diskEvidenceSha256?.matches(SHA256) == false || outputSha256?.matches(SHA256) == false ||
            outputBytes != null && outputBytes <= 0L || !transitionSha256.matches(SHA256)
        ) journalFail("function-observation operation transition has invalid fields")
        when (phase) {
            FullTreeFunctionObservationOperationPhase.PREPARING -> if (
                sequence != 0 || previousTransitionSha256 != ZERO_SHA256 ||
                diskEvidenceSha256 != null || outputSha256 != null || outputBytes != null
            ) journalFail("preparing transition has invalid state")

            FullTreeFunctionObservationOperationPhase.LEASED,
            FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
            -> if (diskEvidenceSha256 == null || outputSha256 != null || outputBytes != null) {
                journalFail("leased operation transition has invalid evidence")
            }

            FullTreeFunctionObservationOperationPhase.CGROUP_ABSENT,
            FullTreeFunctionObservationOperationPhase.PUBLISHED,
            FullTreeFunctionObservationOperationPhase.COMPLETE,
            -> if (diskEvidenceSha256 == null || outputSha256 == null || outputBytes == null) {
                journalFail("post-worker operation transition lacks exact evidence")
            }

            FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT -> if (
                outputSha256 != null || outputBytes != null
            ) journalFail("recovered-abort transition must not retain released output evidence")
        }
        if (
            transitionSha256 != ZERO_SHA256 &&
            transitionSha256 != sha256(canonicalBytes(includeSelfHash = false))
        ) journalFail("function-observation operation transition self hash is invalid")
    }

    val fileName: String
        get() = transitionFileName(sequence)

    fun canonicalBytes(): ByteArray = canonicalBytes(includeSelfHash = true)

    internal fun canonicalBytesWithoutSelfHashForTest(): ByteArray = canonicalBytes(includeSelfHash = false)

    private fun canonicalBytes(includeSelfHash: Boolean): ByteArray = OracleJson.canonicalBytes(
        JsonObject(
            buildMap {
                put("bindingSha256", JsonPrimitive(bindingSha256))
                put("diskEvidenceSha256", diskEvidenceSha256?.let(::JsonPrimitive) ?: JsonNull)
                put("operationId", JsonPrimitive(operationId))
                put("outputBytes", outputBytes?.let(::JsonPrimitive) ?: JsonNull)
                put("outputSha256", outputSha256?.let(::JsonPrimitive) ?: JsonNull)
                put("phase", JsonPrimitive(phase.wireName))
                put("previousTransitionSha256", JsonPrimitive(previousTransitionSha256))
                put("provider", JsonPrimitive(provider))
                put("schemaVersion", JsonPrimitive(schemaVersion))
                put("sequence", JsonPrimitive(sequence))
                if (includeSelfHash) put("transitionSha256", JsonPrimitive(transitionSha256))
            },
        ),
        OPERATION_JSON_LIMITS,
    )

    internal companion object {
        fun initial(binding: FullTreeFunctionObservationOperationBinding):
            FullTreeFunctionObservationOperationTransition = create(
                binding,
                sequence = 0,
                previousTransitionSha256 = ZERO_SHA256,
                phase = FullTreeFunctionObservationOperationPhase.PREPARING,
                diskEvidenceSha256 = null,
                outputSha256 = null,
                outputBytes = null,
            )

        fun next(
            binding: FullTreeFunctionObservationOperationBinding,
            previous: FullTreeFunctionObservationOperationTransition,
            phase: FullTreeFunctionObservationOperationPhase,
            diskEvidenceSha256: String? = previous.diskEvidenceSha256,
            outputSha256: String? = previous.outputSha256,
            outputBytes: Long? = previous.outputBytes,
        ): FullTreeFunctionObservationOperationTransition {
            requireTransitionAllowed(previous.phase, phase)
            if (
                previous.operationId != binding.operationId ||
                previous.bindingSha256 != binding.bindingSha256
            ) journalFail("operation transition is cross-paired with a different binding")
            return create(
                binding,
                Math.addExact(previous.sequence, 1),
                previous.transitionSha256,
                phase,
                diskEvidenceSha256,
                outputSha256,
                outputBytes,
            ).also { requireEvidenceContinuity(previous, it) }
        }

        fun parseCanonical(bytes: ByteArray): FullTreeFunctionObservationOperationTransition =
            translateJournalFailures("parse function-observation operation transition") {
                val root = OracleJson.parseCanonical(bytes, OPERATION_JSON_LIMITS) as? JsonObject
                    ?: journalFail("function-observation operation transition must be an object")
                root.requireExactKeys(OPERATION_TRANSITION_FIELDS, "function-observation operation transition")
                FullTreeFunctionObservationOperationTransition(
                    schemaVersion = root.journalInt("schemaVersion"),
                    provider = root.journalString("provider"),
                    operationId = root.journalString("operationId"),
                    bindingSha256 = root.journalString("bindingSha256"),
                    sequence = root.journalInt("sequence"),
                    previousTransitionSha256 = root.journalString("previousTransitionSha256"),
                    phase = FullTreeFunctionObservationOperationPhase.fromWireName(root.journalString("phase")),
                    diskEvidenceSha256 = root.journalOptionalString("diskEvidenceSha256"),
                    outputSha256 = root.journalOptionalString("outputSha256"),
                    outputBytes = root.journalOptionalLong("outputBytes"),
                    transitionSha256 = root.journalString("transitionSha256"),
                ).also { transition ->
                    if (transition.transitionSha256 == ZERO_SHA256) {
                        journalFail("function-observation operation transition cannot retain its provisional hash")
                    }
                }
            }

        private fun create(
            binding: FullTreeFunctionObservationOperationBinding,
            sequence: Int,
            previousTransitionSha256: String,
            phase: FullTreeFunctionObservationOperationPhase,
            diskEvidenceSha256: String?,
            outputSha256: String?,
            outputBytes: Long?,
        ): FullTreeFunctionObservationOperationTransition {
            val arguments = TransitionArguments(
                binding,
                sequence,
                previousTransitionSha256,
                phase,
                diskEvidenceSha256,
                outputSha256,
                outputBytes,
            )
            val provisional = arguments.transition(ZERO_SHA256)
            return arguments.transition(sha256(provisional.canonicalBytes(includeSelfHash = false)))
        }
    }

    private data class TransitionArguments(
        val binding: FullTreeFunctionObservationOperationBinding,
        val sequence: Int,
        val previousTransitionSha256: String,
        val phase: FullTreeFunctionObservationOperationPhase,
        val diskEvidenceSha256: String?,
        val outputSha256: String?,
        val outputBytes: Long?,
    ) {
        fun transition(selfHash: String) = FullTreeFunctionObservationOperationTransition(
            schemaVersion = OPERATION_TRANSITION_SCHEMA_VERSION,
            provider = OPERATION_PROVIDER,
            operationId = binding.operationId,
            bindingSha256 = binding.bindingSha256,
            sequence = sequence,
            previousTransitionSha256 = previousTransitionSha256,
            phase = phase,
            diskEvidenceSha256 = diskEvidenceSha256,
            outputSha256 = outputSha256,
            outputBytes = outputBytes,
            transitionSha256 = selfHash,
        )
    }
}

internal class FullTreeFunctionObservationOperationHistory private constructor(
    val binding: FullTreeFunctionObservationOperationBinding,
    val transitions: List<FullTreeFunctionObservationOperationTransition>,
) {
    val latest: FullTreeFunctionObservationOperationTransition?
        get() = transitions.lastOrNull()

    internal companion object {
        fun validate(
            binding: FullTreeFunctionObservationOperationBinding,
            transitions: List<FullTreeFunctionObservationOperationTransition>,
        ): FullTreeFunctionObservationOperationHistory {
            if (transitions.size > MAXIMUM_OPERATION_TRANSITIONS + 1) {
                journalFail("function-observation operation history exceeds its transition bound")
            }
            transitions.forEachIndexed { index, transition ->
                if (
                    transition.sequence != index || transition.fileName != transitionFileName(index) ||
                    transition.operationId != binding.operationId ||
                    transition.bindingSha256 != binding.bindingSha256
                ) journalFail("function-observation operation history has a mismatched transition")
                if (index == 0) {
                    if (transition.phase != FullTreeFunctionObservationOperationPhase.PREPARING) {
                        journalFail("function-observation operation history does not begin with preparing")
                    }
                } else {
                    val previous = transitions[index - 1]
                    if (transition.previousTransitionSha256 != previous.transitionSha256) {
                        journalFail("function-observation operation transition chain is broken")
                    }
                    requireTransitionAllowed(previous.phase, transition.phase)
                    requireEvidenceContinuity(previous, transition)
                }
            }
            return FullTreeFunctionObservationOperationHistory(binding, transitions.toList())
        }
    }
}

/**
 * One process-wide namespace authority for parallel operation journals below a durable root.
 *
 * The root lock is retained for this object's lifetime while individual journal locks prevent two
 * callers from owning one operation. All child creation and selection is descriptor-relative and
 * revalidated against the retained root/name binding. Opening the authority synchronizes the
 * preprovisioned root and its parent before use. The deployment must exclude a same-UID actor that
 * ignores the root lock and replaces the root pathname itself.
 */
internal class FullTreeFunctionObservationJournalAuthority private constructor(
    private val path: Path,
    private val parentPath: Path,
    private val parent: LinuxDescriptor,
    private val rootName: String,
    private val root: LinuxDescriptor,
) : AutoCloseable {
    private var activeJournals = 0
    private var closed = false
    private var poisoned = false

    @Synchronized
    fun createNew(
        binding: FullTreeFunctionObservationOperationBinding,
    ): FullTreeFunctionObservationOperationJournal = acquire(binding, create = true)
        ?: error("new function-observation journal was not created")

    @Synchronized
    fun openExisting(
        binding: FullTreeFunctionObservationOperationBinding,
    ): FullTreeFunctionObservationOperationJournal? = acquire(binding, create = false)

    private fun acquire(
        binding: FullTreeFunctionObservationOperationBinding,
        create: Boolean,
    ): FullTreeFunctionObservationOperationJournal? {
        checkOpen()
        requireRootBindingOrPoison()
        var child: LinuxDescriptor? = null
        var childLocked = false
        try {
            if (create) {
                LinuxFilesystemSyscalls.openPathAtOrNull(root.fd, binding.journalDirectoryName)?.use {
                    journalFail("function-observation operation journal already exists")
                }
                LinuxFilesystemSyscalls.createDirectory(
                    root.fd,
                    binding.journalDirectoryName,
                    OWNER_DIRECTORY_MODE,
                )
            }
            child = try {
                LinuxFilesystemSyscalls.openDirectoryAt(root.fd, binding.journalDirectoryName)
            } catch (failure: LinuxSyscallException) {
                if (!create && failure.errno == LinuxFilesystemSyscalls.ENOENT) return null
                throw failure
            }
            if (create) {
                LinuxFilesystemSyscalls.chmod(child, OWNER_DIRECTORY_MODE)
            }
            val childIdentity = LinuxFilesystemSyscalls.identity(child.fd)
            requireManagedDirectory(childIdentity, root.identity, "function-observation journal directory")
            requireNamedChild(binding.journalDirectoryName, childIdentity)
            // Covers new mkdir state and a prior process that exposed state before its final sync.
            LinuxFilesystemSyscalls.synchronize(child)
            LinuxFilesystemSyscalls.synchronize(root)
            if (!LinuxFilesystemSyscalls.tryExclusiveLock(child)) {
                journalFail("function-observation operation journal is already locked")
            }
            childLocked = true
            requireRootBindingOrPoison()
            requireNamedChild(binding.journalDirectoryName, childIdentity)
            activeJournals = Math.addExact(activeJournals, 1)
            return FullTreeFunctionObservationOperationJournal(binding, this, child)
        } catch (failure: Throwable) {
            if (childLocked) {
                child?.let { locked ->
                    runCatching { LinuxFilesystemSyscalls.unlock(locked) }
                        .exceptionOrNull()?.let(failure::addSuppressed)
                }
            }
            child?.let { opened ->
                runCatching { opened.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            }
            throw failure
        }
    }

    @Synchronized
    internal fun requireBound(name: String, expected: LinuxFileIdentity) {
        checkOpen()
        requireRootBindingOrPoison()
        requireNamedChild(name, expected)
    }

    @Synchronized
    internal fun releaseJournal() {
        check(activeJournals > 0) { "function-observation journal authority has no active journal" }
        activeJournals -= 1
    }

    private fun requireRootBinding() {
        val currentParent = LinuxFilesystemSyscalls.identity(parent.fd)
        requireTrustedJournalParent(currentParent, parent.identity)
        if (!Files.isSameFile(parentPath, LinuxFilesystemSyscalls.descriptorPath(parent))) {
            journalFail("function-observation journal parent pathname changed")
        }
        val current = LinuxFilesystemSyscalls.identity(root.fd)
        requireManagedDirectory(current, root.identity, "function-observation journal root")
        val selected = try {
            LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, rootName)
        } catch (failure: LinuxSyscallException) {
            if (failure.errno == LinuxFilesystemSyscalls.ENOENT) {
                journalFail("function-observation journal root was detached")
            }
            throw failure
        }
        selected.use {
            if (!sameDirectory(LinuxFilesystemSyscalls.identity(selected.fd), current)) {
                journalFail("function-observation journal root changed identity")
            }
        }
        if (!Files.isSameFile(path, LinuxFilesystemSyscalls.descriptorPath(root))) {
            journalFail("function-observation journal root pathname changed")
        }
    }

    private fun requireRootBindingOrPoison() {
        try {
            requireRootBinding()
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    private fun requireNamedChild(name: String, expected: LinuxFileIdentity) {
        val selected = try {
            LinuxFilesystemSyscalls.openDirectoryAt(root.fd, name)
        } catch (failure: LinuxSyscallException) {
            if (failure.errno == LinuxFilesystemSyscalls.ENOENT) {
                journalFail("function-observation journal directory was detached")
            }
            throw failure
        }
        selected.use {
            val current = LinuxFilesystemSyscalls.identity(selected.fd)
            requireManagedDirectory(current, root.identity, "function-observation journal directory")
            if (!sameDirectory(current, expected)) {
                journalFail("function-observation journal directory changed identity")
            }
        }
    }

    private fun checkOpen() {
        check(!closed) { "function-observation journal authority is closed" }
        check(!poisoned) { "function-observation journal authority is poisoned" }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        check(activeJournals == 0) { "function-observation journal authority still owns active journals" }
        closed = true
        var failure: Throwable? = null
        runCatching { LinuxFilesystemSyscalls.unlock(root) }.exceptionOrNull()?.let { failure = it }
        runCatching { root.close() }.exceptionOrNull()?.let { closeFailure ->
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        runCatching { parent.close() }.exceptionOrNull()?.let { closeFailure ->
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        failure?.let { throw it }
    }

    internal companion object {
        fun open(path: Path): FullTreeFunctionObservationJournalAuthority {
            val normalized = path.toAbsolutePath().normalize()
            if (
                !normalized.isAbsolute || normalized.parent == null ||
                !Files.isDirectory(normalized, LinkOption.NOFOLLOW_LINKS) ||
                normalized.toRealPath() != normalized
            ) journalFail("function-observation journal root must be a canonical non-root directory")
            LinuxFilesystemSyscalls.requireSupported(normalized)
            val parentPath = normalized.parent
            if (parentPath.toRealPath() != parentPath) {
                journalFail("function-observation journal root parent must be canonical")
            }
            val parent = LinuxFilesystemSyscalls.openRoot(parentPath)
            val root = try {
                LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, normalized.fileName.toString())
            } catch (failure: Throwable) {
                parent.close()
                throw failure
            }
            var locked = false
            try {
                requireTrustedJournalParent(LinuxFilesystemSyscalls.identity(parent.fd), parent.identity)
                requireManagedDirectory(
                    LinuxFilesystemSyscalls.identity(root.fd),
                    root.identity,
                    "function-observation journal root",
                )
                if (!LinuxFilesystemSyscalls.tryExclusiveLock(root)) {
                    journalFail("function-observation journal root is already locked")
                }
                locked = true
                LinuxFilesystemSyscalls.synchronize(root)
                LinuxFilesystemSyscalls.synchronize(parent)
                return FullTreeFunctionObservationJournalAuthority(
                    normalized,
                    parentPath,
                    parent,
                    normalized.fileName.toString(),
                    root,
                ).also {
                    it.requireRootBinding()
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

internal enum class FullTreeFunctionObservationColdCompletionKind {
    NONE,
    BINDING,
    TRANSITION,
}

internal data class FullTreeFunctionObservationColdCompletion(
    val kind: FullTreeFunctionObservationColdCompletionKind,
    val history: FullTreeFunctionObservationOperationHistory?,
)

/**
 * Root-authorized append-only journal for one operation.
 *
 * This type is intentionally not wired to the runner, cleanup, publication, or release evidence.
 * It records and recovers only immutable journal publications; it never treats the record chain as
 * authority to kill a unit, delete scratch, revoke output, or certify a release.
 */
internal class FullTreeFunctionObservationOperationJournal internal constructor(
    private val expectedBinding: FullTreeFunctionObservationOperationBinding,
    private val authority: FullTreeFunctionObservationJournalAuthority,
    private val directory: LinuxDescriptor,
) : AutoCloseable {
    private var closed = false
    private var poisoned = false

    @Synchronized
    fun initialize(
        faultInjector: DescriptorBoundStateFaultInjector? = null,
    ): FullTreeFunctionObservationOperationHistory = boundOperation {
        DescriptorBoundAtomicStateFile.publishNoReplace(
            directory,
            OPERATION_BINDING_FILE,
            expectedBinding.canonicalBytes(),
            MAXIMUM_OPERATION_RECORD_BYTES,
            faultInjector,
        )
        val initial = FullTreeFunctionObservationOperationTransition.initial(expectedBinding)
        DescriptorBoundAtomicStateFile.publishNoReplace(
            directory,
            initial.fileName,
            initial.canonicalBytes(),
            MAXIMUM_OPERATION_RECORD_BYTES,
            faultInjector,
        )
        loadRequired()
    }

    @Synchronized
    fun append(
        transition: FullTreeFunctionObservationOperationTransition,
        faultInjector: DescriptorBoundStateFaultInjector? = null,
    ): FullTreeFunctionObservationOperationHistory = boundOperation {
        val current = loadRequired(allowedAtomicTarget = transition.fileName)
        current.transitions.getOrNull(transition.sequence)?.let { existing ->
            if (!existing.canonicalBytes().contentEquals(transition.canonicalBytes())) {
                journalFail("function-observation journal sequence already has different immutable bytes")
            }
            DescriptorBoundAtomicStateFile.publishNoReplace(
                directory,
                transition.fileName,
                transition.canonicalBytes(),
                MAXIMUM_OPERATION_RECORD_BYTES,
                faultInjector,
            )
            return@boundOperation loadRequired()
        }
        if (transition.sequence != current.transitions.size) {
            journalFail("function-observation journal append sequence is not next")
        }
        FullTreeFunctionObservationOperationHistory.validate(
            expectedBinding,
            current.transitions + transition,
        )
        DescriptorBoundAtomicStateFile.publishNoReplace(
            directory,
            transition.fileName,
            transition.canonicalBytes(),
            MAXIMUM_OPERATION_RECORD_BYTES,
            faultInjector,
        )
        loadRequired()
    }

    @Synchronized
    fun loadOrNull(): FullTreeFunctionObservationOperationHistory? = boundOperation {
        loadOrNull(allowedAtomicTarget = null)
    }

    /** Completes at most one exact, parsed journal temporary and touches no external resource. */
    @Synchronized
    fun completeExactPendingPublication(
        faultInjector: DescriptorBoundStateFaultInjector? = null,
        afterInspection: (() -> Unit)? = null,
    ): FullTreeFunctionObservationColdCompletion = boundOperation {
        val names = entryNames()
        val atomicNames = names.filter(::isAtomicStateName)
        if (atomicNames.size > 1) {
            journalFail("function-observation operation journal contains multiple pending publications")
        }
        val atomicName = atomicNames.singleOrNull()
        if (atomicName == null) {
            loadOrNull(allowedAtomicTarget = null)
            // A prior process may have died after rename and before its directory sync.
            LinuxFilesystemSyscalls.synchronize(directory)
            return@boundOperation FullTreeFunctionObservationColdCompletion(
                FullTreeFunctionObservationColdCompletionKind.NONE,
                loadOrNull(allowedAtomicTarget = null),
            )
        }
        val targetName = when {
            atomicName == DescriptorBoundAtomicStateFile.temporaryName(OPERATION_BINDING_FILE) ->
                OPERATION_BINDING_FILE
            atomicName.matches(ATOMIC_TRANSITION_FILE_NAME) ->
                atomicName.removePrefix(".").removeSuffix(".atomic")
            else -> journalFail("function-observation operation journal contains an unknown pending publication")
        }
        if (targetName in names) {
            journalFail("function-observation operation journal contains a target and its pending publication")
        }
        if (targetName == OPERATION_BINDING_FILE) {
            if (names != listOf(atomicName)) {
                journalFail("pending function-observation binding has unbound journal residue")
            }
            inspectRequired(atomicName).use { pending ->
                val parsed = FullTreeFunctionObservationOperationBinding.parseCanonical(pending.bytes)
                requireDirectoryBinding(parsed)
                afterInspection?.invoke()
                DescriptorBoundAtomicStateFile.completeExistingTemporaryNoReplace(
                    directory,
                    OPERATION_BINDING_FILE,
                    pending,
                    MAXIMUM_OPERATION_RECORD_BYTES,
                    faultInjector,
                )
            }
            return@boundOperation FullTreeFunctionObservationColdCompletion(
                FullTreeFunctionObservationColdCompletionKind.BINDING,
                loadRequired(),
            )
        } else {
            val prefix = loadRequired(allowedAtomicTarget = targetName)
            inspectRequired(atomicName).use { pending ->
                val transition = FullTreeFunctionObservationOperationTransition.parseCanonical(pending.bytes)
                if (transition.fileName != targetName || transition.sequence != prefix.transitions.size) {
                    journalFail("pending function-observation transition is not the exact next sequence")
                }
                FullTreeFunctionObservationOperationHistory.validate(
                    expectedBinding,
                    prefix.transitions + transition,
                )
                afterInspection?.invoke()
                DescriptorBoundAtomicStateFile.completeExistingTemporaryNoReplace(
                    directory,
                    targetName,
                    pending,
                    MAXIMUM_OPERATION_RECORD_BYTES,
                    faultInjector,
                )
            }
            return@boundOperation FullTreeFunctionObservationColdCompletion(
                FullTreeFunctionObservationColdCompletionKind.TRANSITION,
                loadRequired(),
            )
        }
    }

    private fun loadOrNull(
        allowedAtomicTarget: String?,
    ): FullTreeFunctionObservationOperationHistory? {
        val names = entryNames()
        if (names.isEmpty()) return null
        val allowedAtomicName = allowedAtomicTarget?.let(DescriptorBoundAtomicStateFile::temporaryName)
        val atomicNames = names.filter(::isAtomicStateName)
        if (atomicNames.any { it != allowedAtomicName }) {
            journalFail("function-observation operation journal requires exact atomic-publication recovery")
        }
        if (names.any {
                it != OPERATION_BINDING_FILE && !it.matches(TRANSITION_FILE_NAME) && it != allowedAtomicName
            }
        ) {
            journalFail("function-observation operation journal contains an unowned entry")
        }
        val bindingSnapshot = DescriptorBoundAtomicStateFile.readOrNull(
            directory,
            OPERATION_BINDING_FILE,
            MAXIMUM_OPERATION_RECORD_BYTES,
        ) ?: journalFail("function-observation operation journal is missing its binding")
        val actualBinding = FullTreeFunctionObservationOperationBinding.parseCanonical(bindingSnapshot.bytes)
        requireDirectoryBinding(actualBinding)
        val transitions = names.filter(TRANSITION_FILE_NAME::matches).map { name ->
            val snapshot = DescriptorBoundAtomicStateFile.readOrNull(
                directory,
                name,
                MAXIMUM_OPERATION_RECORD_BYTES,
            ) ?: journalFail("function-observation operation transition disappeared")
            FullTreeFunctionObservationOperationTransition.parseCanonical(snapshot.bytes).also { transition ->
                if (transition.fileName != name) {
                    journalFail("function-observation operation transition occupies the wrong name")
                }
            }
        }
        return FullTreeFunctionObservationOperationHistory.validate(expectedBinding, transitions)
    }

    private fun loadRequired(
        allowedAtomicTarget: String? = null,
    ): FullTreeFunctionObservationOperationHistory {
        val history = loadOrNull(allowedAtomicTarget)
            ?: journalFail("function-observation operation journal is empty")
        return history
    }

    private fun entryNames(): List<String> {
        val names = LinuxFilesystemSyscalls.directoryEntryNames(
            directory,
            MAXIMUM_JOURNAL_ENTRIES + 1,
        ).sorted()
        if (names.size > MAXIMUM_JOURNAL_ENTRIES) {
            journalFail("function-observation operation journal exceeds its entry bound")
        }
        return names
    }

    private fun inspectRequired(name: String): DescriptorBoundStateInspection =
        DescriptorBoundAtomicStateFile.inspectOrNull(
            directory,
            name,
            MAXIMUM_OPERATION_RECORD_BYTES,
        ) ?: journalFail("function-observation operation journal entry disappeared: $name")

    private fun requireDirectoryBinding(actual: FullTreeFunctionObservationOperationBinding) {
        if (
            actual.journalDirectoryName != expectedBinding.journalDirectoryName ||
            !actual.canonicalBytes().contentEquals(expectedBinding.canonicalBytes())
        ) journalFail("function-observation operation journal is bound to a different request")
        authority.requireBound(expectedBinding.journalDirectoryName, directory.identity)
    }

    private inline fun <T> boundOperation(action: () -> T): T {
        checkOpen()
        return try {
            requireDirectoryBinding(expectedBinding)
            val result = action()
            requireDirectoryBinding(expectedBinding)
            result
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    private fun checkOpen() {
        check(!closed) { "function-observation operation journal is closed" }
        check(!poisoned) { "function-observation operation journal is poisoned" }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        runCatching { LinuxFilesystemSyscalls.unlock(directory) }.exceptionOrNull()?.let { failure = it }
        runCatching { directory.close() }.exceptionOrNull()?.let { closeFailure ->
            if (failure == null) failure = closeFailure else failure.addSuppressed(closeFailure)
        }
        runCatching { authority.releaseJournal() }.exceptionOrNull()?.let { releaseFailure ->
            if (failure == null) failure = releaseFailure else failure.addSuppressed(releaseFailure)
        }
        failure?.let { throw it }
    }
}

internal fun journalDirectoryName(operationId: String): String =
    ".function-observation-operation-$operationId"

internal fun leaseDirectoryName(operationId: String): String = ".decomp-oracle-lease-$operationId"

internal fun leaseReleaseQuarantineDirectoryName(operationId: String): String =
    ".decomp-oracle-lease-release-$operationId"

internal fun leaseFailureQuarantineDirectoryName(operationId: String): String =
    ".decomp-oracle-lease-failed-$operationId"

internal fun runDirectoryName(operationId: String): String = ".function-observation-run-$operationId"

internal fun runQuarantineDirectoryName(operationId: String): String =
    ".function-observation-run-abort-$operationId"

internal fun unitName(operationId: String): String = "decomp-oracle-function-$operationId.scope"

internal fun outputStageName(operationId: String): String = ".function-observation-output-$operationId.atomic"

internal fun transitionFileName(sequence: Int): String {
    if (sequence !in 0..MAXIMUM_OPERATION_TRANSITIONS) {
        journalFail("function-observation operation transition sequence is out of range")
    }
    return "transition-${sequence.toString().padStart(4, '0')}.json"
}

private fun isAtomicStateName(name: String): Boolean = name.startsWith('.') && name.endsWith(".atomic")

private fun requireManagedDirectory(
    actual: LinuxFileIdentity,
    parent: LinuxFileIdentity,
    label: String,
) {
    val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
    if (
        !actual.isDirectory || actual.isRegularFile || actual.isSymbolicLink ||
        actual.mountId != parent.mountId || actual.uid != uid || parent.uid != uid ||
        actual.mode.permissions != OWNER_DIRECTORY_MODE
    ) journalFail("$label is not an owner-only directory on its authorized filesystem")
}

private fun requireTrustedJournalParent(actual: LinuxFileIdentity, expected: LinuxFileIdentity) {
    val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
    if (
        !sameDirectory(actual, expected) || actual.uid !in setOf(0, uid) ||
        actual.mode.permissions and GROUP_OR_OTHER_WRITE_MODE != 0
    ) journalFail("function-observation journal root has an untrusted parent")
}

private fun sameDirectory(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
    first.key == second.key && first.mountId == second.mountId &&
        first.uid == second.uid && first.gid == second.gid &&
        first.isDirectory && second.isDirectory &&
        !first.isRegularFile && !second.isRegularFile &&
        !first.isSymbolicLink && !second.isSymbolicLink

private fun requireEvidenceContinuity(
    previous: FullTreeFunctionObservationOperationTransition,
    next: FullTreeFunctionObservationOperationTransition,
) {
    when (val previousDisk = previous.diskEvidenceSha256) {
        null -> if (
            next.diskEvidenceSha256 != null &&
            next.phase != FullTreeFunctionObservationOperationPhase.LEASED
        ) journalFail("function-observation operation introduced disk evidence outside leased")

        else -> if (next.diskEvidenceSha256 != previousDisk) {
            journalFail("function-observation operation changed its disk evidence")
        }
    }
    if (next.phase == FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT) {
        if (next.outputSha256 != null || next.outputBytes != null) {
            journalFail("recovered function-observation operation retained output evidence")
        }
        return
    }
    val previousOutputSha256 = previous.outputSha256
    val previousOutputBytes = previous.outputBytes
    if (previousOutputSha256 == null && previousOutputBytes == null) {
        if (
            next.outputSha256 != null &&
            next.phase != FullTreeFunctionObservationOperationPhase.CGROUP_ABSENT
        ) journalFail("function-observation operation introduced output evidence before cgroup absence")
    } else if (
        next.outputSha256 != previousOutputSha256 || next.outputBytes != previousOutputBytes
    ) {
        journalFail("function-observation operation changed its output evidence")
    }
}

private fun requireTransitionAllowed(
    previous: FullTreeFunctionObservationOperationPhase,
    next: FullTreeFunctionObservationOperationPhase,
) {
    val expected = when (previous) {
        FullTreeFunctionObservationOperationPhase.PREPARING ->
            setOf(FullTreeFunctionObservationOperationPhase.LEASED)
        FullTreeFunctionObservationOperationPhase.LEASED ->
            setOf(FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED)
        FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED ->
            setOf(FullTreeFunctionObservationOperationPhase.CGROUP_ABSENT)
        FullTreeFunctionObservationOperationPhase.CGROUP_ABSENT ->
            setOf(FullTreeFunctionObservationOperationPhase.PUBLISHED)
        FullTreeFunctionObservationOperationPhase.PUBLISHED ->
            setOf(FullTreeFunctionObservationOperationPhase.COMPLETE)
        FullTreeFunctionObservationOperationPhase.COMPLETE,
        FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT,
        -> emptySet()
    }
    if (next != FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT && next !in expected) {
        journalFail("function-observation operation transition is not monotonic")
    }
    if (next == FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT && previous.terminal) {
        journalFail("terminal function-observation operation cannot be aborted again")
    }
}

private fun JsonObject.requireExactKeys(expected: Set<String>, label: String) {
    if (keys != expected) journalFail("$label has unexpected fields")
}

private fun JsonObject.journalString(name: String): String {
    val value = this[name] as? JsonPrimitive ?: journalFail("operation field $name must be a string")
    if (!value.isString) journalFail("operation field $name must be a string")
    return value.content
}

private fun JsonObject.journalOptionalString(name: String): String? {
    val value = this[name] ?: journalFail("operation field $name is missing")
    if (value == JsonNull) return null
    val primitive = value as? JsonPrimitive ?: journalFail("operation field $name must be a string or null")
    if (!primitive.isString) journalFail("operation field $name must be a string or null")
    return primitive.content
}

private fun JsonObject.journalLong(name: String): Long {
    val value = this[name] as? JsonPrimitive ?: journalFail("operation field $name must be an integer")
    if (value.isString) journalFail("operation field $name must be an integer")
    return value.content.toLongOrNull() ?: journalFail("operation field $name must be an integer")
}

private fun JsonObject.journalOptionalLong(name: String): Long? {
    val value = this[name] ?: journalFail("operation field $name is missing")
    if (value == JsonNull) return null
    val primitive = value as? JsonPrimitive ?: journalFail("operation field $name must be an integer or null")
    if (primitive.isString) journalFail("operation field $name must be an integer or null")
    return primitive.content.toLongOrNull() ?: journalFail("operation field $name must be an integer or null")
}

private fun JsonObject.journalInt(name: String): Int {
    val value = journalLong(name)
    if (value !in Int.MIN_VALUE..Int.MAX_VALUE) journalFail("operation field $name is outside the integer range")
    return value.toInt()
}

private inline fun <T> translateJournalFailures(label: String, action: () -> T): T = try {
    action()
} catch (failure: FullTreeFunctionObservationOperationJournalException) {
    throw failure
} catch (failure: Throwable) {
    throw FullTreeFunctionObservationOperationJournalException("cannot $label: ${failure.message}", failure)
}

private fun sha256(bytes: ByteArray): String = OracleArtifacts.sha256(bytes)

private fun journalFail(message: String): Nothing =
    throw FullTreeFunctionObservationOperationJournalException(message)

private const val OPERATION_BINDING_SCHEMA_VERSION = 1
private const val OPERATION_REQUEST_SCHEMA_VERSION = 1
private const val OPERATION_TRANSITION_SCHEMA_VERSION = 1
private const val OPERATION_PROVIDER = "kotlin-function-observation-operation-v1"
private const val OPERATION_REQUEST_PROVIDER = "kotlin-function-observation-request-v1"
private const val MINIMUM_LEASE_INODES = 4L
private const val OWNER_DIRECTORY_MODE = 0x1c0 // 0700
private const val GROUP_OR_OTHER_WRITE_MODE = 0x12 // 0022
private const val MAXIMUM_OPERATION_TRANSITIONS = 8
private const val MAXIMUM_OPERATION_RECORD_BYTES = 64 * 1024
private const val MAXIMUM_JOURNAL_ENTRIES = MAXIMUM_OPERATION_TRANSITIONS + 4
private const val OPERATION_BINDING_FILE = "binding.json"
private val ZERO_SHA256 = "0".repeat(64)
private val SHA256 = Regex("[0-9a-f]{64}")
private val SHARD_IDENTIFIER = Regex("[a-z0-9]+(?:-[a-z0-9]+)*")
private val TRANSITION_FILE_NAME = Regex("transition-[0-9]{4}\\.json")
private val ATOMIC_TRANSITION_FILE_NAME = Regex("\\.transition-[0-9]{4}\\.json\\.atomic")
private val OPERATION_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 64 * 1024,
    maximumCanonicalBytes = 64 * 1024,
    maximumDepth = 4,
    maximumNodes = 64,
    maximumStringBytes = 1024,
    maximumTotalStringBytes = 16 * 1024,
    maximumNumberCharacters = 32,
)
private val OPERATION_BINDING_FIELDS = setOf(
    "bindingSha256",
    "inventoryArtifactSha256",
    "isolationSha256",
    "journalDirectoryName",
    "leaseDirectoryName",
    "leaseFailureQuarantineDirectoryName",
    "leaseReleaseQuarantineDirectoryName",
    "maximumFilesystemBytes",
    "maximumFilesystemInodes",
    "operationId",
    "outputPathSha256",
    "outputStageName",
    "provider",
    "requestSha256",
    "requiredAvailableBytes",
    "requiredAvailableInodes",
    "runDirectoryName",
    "runQuarantineDirectoryName",
    "schemaVersion",
    "shardInputSha256",
    "scopeSha256",
    "shardId",
    "richArtifactSha256",
    "unitName",
)
private val OPERATION_TRANSITION_FIELDS = setOf(
    "bindingSha256",
    "diskEvidenceSha256",
    "operationId",
    "outputBytes",
    "outputSha256",
    "phase",
    "previousTransitionSha256",
    "provider",
    "schemaVersion",
    "sequence",
    "transitionSha256",
)
