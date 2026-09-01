package decompengine.oracle.behavior

import decompengine.acp.LinuxBoundedSessionCommand
import decompengine.acp.LinuxBoundedSessionProcess
import java.nio.file.Path
import java.time.Duration
import java.util.ArrayList
import java.util.Collections

internal enum class LlvmBehaviorHostedContainerV1DockerSessionFailureKind {
    CONTROL_COMMAND_FAILED,
}

internal class LlvmBehaviorHostedContainerV1DockerSessionException(
    val kind: LlvmBehaviorHostedContainerV1DockerSessionFailureKind,
    message: String,
    cause: Throwable? = null,
) : IllegalStateException(message, cause)

/** Cross-bound, defensive, non-authoritative result of only the worker-image inspect slot. */
internal sealed interface LlvmBehaviorHostedWorkerImageV1RawInspectToken {
    val imageId: String
    val operationId: String
    val journalBindingSha256: String
    val journalRootPathSha256: String
    val bytes: ByteArray
}

/** Cross-bound, defensive, non-authoritative result of only the exact-ID container inspect slot. */
internal sealed interface LlvmBehaviorHostedContainerV1RawInspectToken {
    val containerId: String
    val imageId: String
    val operationId: String
    val journalBindingSha256: String
    val journalRootPathSha256: String
    val bytes: ByteArray
}

/** Cross-bound, non-authoritative result of only the exact-name inventory slot. */
internal sealed interface LlvmBehaviorHostedContainerV1ExactNameInventoryToken {
    val operationId: String
    val journalBindingSha256: String
    val journalRootPathSha256: String
    val projection: LlvmBehaviorHostedContainerV1InventoryOutputProjection
}

/** Cross-bound, non-authoritative result of only the exact-operation-label inventory slot. */
internal sealed interface LlvmBehaviorHostedContainerV1ExactOperationLabelInventoryToken {
    val operationId: String
    val journalBindingSha256: String
    val journalRootPathSha256: String
    val projection: LlvmBehaviorHostedContainerV1InventoryOutputProjection
}

/**
 * Kotlin/JVM owner for the read-only Docker slots implemented so far.
 *
 * The only executable and endpoint come from the descriptor-pinned [PinnedDockerRuntimeBindings]
 * transferred to [open]. There is no generic command, runner, parser callback, environment,
 * socket, CREATE, START, wait, exec, removal, or durable-name-absence surface. In particular, raw
 * image inspect bytes cannot authorize CREATE: pre-create image-config verification does not yet
 * exist, and a hostile image can request daemon-side volume materialization. ACP remains the
 * first-class candidate producer/operator. This mechanism grants ACP and itself no oracle,
 * reference, validation, START, containment, scoring, certification, publication, or release
 * authority.
 */
internal sealed interface LlvmBehaviorHostedContainerV1DockerSession : AutoCloseable {
    val acpRole: String
    val acpOracleAccess: String
    val oracleAuthority: Boolean
    val referenceAuthority: Boolean
    val validationAuthority: Boolean
    val startAuthority: Boolean
    val containmentAuthority: Boolean
    val scoringAuthority: Boolean
    val certificationAuthority: Boolean
    val publicationAuthority: Boolean
    val releaseAuthority: Boolean

    fun inspectWorkerImage(
        plan: LlvmBehaviorHostedContainerV1DockerControlPlan,
    ): LlvmBehaviorHostedWorkerImageV1RawInspectToken

    fun inspectCandidateContainer(
        plan: LlvmBehaviorHostedContainerV1RetainedDockerControlPlan,
    ): LlvmBehaviorHostedContainerV1RawInspectToken

    fun inventoryExactName(
        plan: LlvmBehaviorHostedContainerV1DockerControlPlan,
    ): LlvmBehaviorHostedContainerV1ExactNameInventoryToken

    fun inventoryExactOperationLabel(
        plan: LlvmBehaviorHostedContainerV1DockerControlPlan,
    ): LlvmBehaviorHostedContainerV1ExactOperationLabelInventoryToken

    companion object {
        fun open(bindings: PinnedDockerRuntimeBindings): LlvmBehaviorHostedContainerV1DockerSession =
            BoundDockerSession(bindings)
    }
}

private class BoundDockerSession(
    private val bindings: PinnedDockerRuntimeBindings,
) : LlvmBehaviorHostedContainerV1DockerSession {
    private var closed = false

    override val acpRole: String
        get() = "first-class-candidate-producer-operator"
    override val acpOracleAccess: String
        get() = "none"
    override val oracleAuthority: Boolean
        get() = false
    override val referenceAuthority: Boolean
        get() = false
    override val validationAuthority: Boolean
        get() = false
    override val startAuthority: Boolean
        get() = false
    override val containmentAuthority: Boolean
        get() = false
    override val scoringAuthority: Boolean
        get() = false
    override val certificationAuthority: Boolean
        get() = false
    override val publicationAuthority: Boolean
        get() = false
    override val releaseAuthority: Boolean
        get() = false

    @Synchronized
    override fun inspectWorkerImage(
        plan: LlvmBehaviorHostedContainerV1DockerControlPlan,
    ): LlvmBehaviorHostedWorkerImageV1RawInspectToken {
        checkOpen()
        return executeFixedSlot(
            bindings = bindings,
            arguments = plan.imageInspectArguments,
            maximumStdoutBytes = MAXIMUM_INSPECT_STDOUT_BYTES,
            label = "worker-image inspect",
            parse = { bytes -> workerImageInspectToken(plan, bytes) },
        )
    }

    @Synchronized
    override fun inspectCandidateContainer(
        plan: LlvmBehaviorHostedContainerV1RetainedDockerControlPlan,
    ): LlvmBehaviorHostedContainerV1RawInspectToken {
        checkOpen()
        return executeFixedSlot(
            bindings = bindings,
            arguments = plan.candidateContainerInspectArguments,
            maximumStdoutBytes = MAXIMUM_INSPECT_STDOUT_BYTES,
            label = "candidate-container exact-ID inspect",
            parse = { bytes -> candidateContainerInspectToken(plan, bytes) },
        )
    }

    @Synchronized
    override fun inventoryExactName(
        plan: LlvmBehaviorHostedContainerV1DockerControlPlan,
    ): LlvmBehaviorHostedContainerV1ExactNameInventoryToken {
        checkOpen()
        return executeFixedSlot(
            bindings = bindings,
            arguments = plan.exactNameInventoryArguments,
            maximumStdoutBytes = MAXIMUM_INVENTORY_STDOUT_BYTES,
            label = "exact-name container inventory",
            parse = { bytes ->
                exactNameInventoryToken(
                    plan,
                    LlvmBehaviorHostedContainerV1DockerOutput.parseInventory(bytes),
                )
            },
        )
    }

    @Synchronized
    override fun inventoryExactOperationLabel(
        plan: LlvmBehaviorHostedContainerV1DockerControlPlan,
    ): LlvmBehaviorHostedContainerV1ExactOperationLabelInventoryToken {
        checkOpen()
        return executeFixedSlot(
            bindings = bindings,
            arguments = plan.exactOperationLabelInventoryArguments,
            maximumStdoutBytes = MAXIMUM_INVENTORY_STDOUT_BYTES,
            label = "exact-operation-label container inventory",
            parse = { bytes ->
                exactOperationLabelInventoryToken(
                    plan,
                    LlvmBehaviorHostedContainerV1DockerOutput.parseInventory(bytes),
                )
            },
        )
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        bindings.close()
    }

    private fun checkOpen() {
        if (closed) dockerSessionFail("hosted Docker session is closed")
    }
}

private class BoundWorkerImageInspectToken(
    override val imageId: String,
    override val operationId: String,
    override val journalBindingSha256: String,
    override val journalRootPathSha256: String,
    rawBytes: ByteArray,
) : LlvmBehaviorHostedWorkerImageV1RawInspectToken {
    private val frozenBytes = rawBytes.copyOf()

    override val bytes: ByteArray
        get() = frozenBytes.copyOf()
}

private class BoundCandidateContainerInspectToken(
    override val containerId: String,
    override val imageId: String,
    override val operationId: String,
    override val journalBindingSha256: String,
    override val journalRootPathSha256: String,
    rawBytes: ByteArray,
) : LlvmBehaviorHostedContainerV1RawInspectToken {
    private val frozenBytes = rawBytes.copyOf()

    override val bytes: ByteArray
        get() = frozenBytes.copyOf()
}

private class BoundExactNameInventoryToken(
    override val operationId: String,
    override val journalBindingSha256: String,
    override val journalRootPathSha256: String,
    projection: LlvmBehaviorHostedContainerV1InventoryOutputProjection,
) : LlvmBehaviorHostedContainerV1ExactNameInventoryToken {
    override val projection = frozenInventoryProjection(projection)
}

private class BoundExactOperationLabelInventoryToken(
    override val operationId: String,
    override val journalBindingSha256: String,
    override val journalRootPathSha256: String,
    projection: LlvmBehaviorHostedContainerV1InventoryOutputProjection,
) : LlvmBehaviorHostedContainerV1ExactOperationLabelInventoryToken {
    override val projection = frozenInventoryProjection(projection)
}

private fun workerImageInspectToken(
    plan: LlvmBehaviorHostedContainerV1DockerControlPlan,
    rawBytes: ByteArray,
): LlvmBehaviorHostedWorkerImageV1RawInspectToken = BoundWorkerImageInspectToken(
    imageId = plan.imageId,
    operationId = plan.operationId,
    journalBindingSha256 = plan.journalBindingSha256,
    journalRootPathSha256 = plan.journalRootPathSha256,
    rawBytes = rawBytes,
)

private fun candidateContainerInspectToken(
    plan: LlvmBehaviorHostedContainerV1RetainedDockerControlPlan,
    rawBytes: ByteArray,
): LlvmBehaviorHostedContainerV1RawInspectToken = BoundCandidateContainerInspectToken(
    containerId = plan.expectation.containerId,
    imageId = plan.expectation.imageId,
    operationId = plan.operationId,
    journalBindingSha256 = plan.journalBindingSha256,
    journalRootPathSha256 = plan.journalRootPathSha256,
    rawBytes = rawBytes,
)

private fun exactNameInventoryToken(
    plan: LlvmBehaviorHostedContainerV1DockerControlPlan,
    projection: LlvmBehaviorHostedContainerV1InventoryOutputProjection,
): LlvmBehaviorHostedContainerV1ExactNameInventoryToken = BoundExactNameInventoryToken(
    operationId = plan.operationId,
    journalBindingSha256 = plan.journalBindingSha256,
    journalRootPathSha256 = plan.journalRootPathSha256,
    projection = projection,
)

private fun exactOperationLabelInventoryToken(
    plan: LlvmBehaviorHostedContainerV1DockerControlPlan,
    projection: LlvmBehaviorHostedContainerV1InventoryOutputProjection,
): LlvmBehaviorHostedContainerV1ExactOperationLabelInventoryToken =
    BoundExactOperationLabelInventoryToken(
        operationId = plan.operationId,
        journalBindingSha256 = plan.journalBindingSha256,
        journalRootPathSha256 = plan.journalRootPathSha256,
        projection = projection,
    )

private inline fun <T> executeFixedSlot(
    bindings: PinnedDockerRuntimeBindings,
    arguments: List<String>,
    maximumStdoutBytes: Int,
    label: String,
    parse: (ByteArray) -> T,
): T {
    try {
        bindings.requireCurrent()
        val result = LinuxBoundedSessionProcess.execute(
            fixedCommand(bindings, arguments, maximumStdoutBytes),
        )
        bindings.requireCurrent()
        requireSuccessfulResult(result.exitCode, result.signal, result.stderr, label)
        val parsed = parse(result.stdout)
        bindings.requireCurrent()
        return parsed
    } catch (failure: Throwable) {
        val wrapped = wrapControlFailure(label, failure)
        try {
            bindings.requireCurrent()
        } catch (bindingFailure: Throwable) {
            if (bindingFailure !== failure) wrapped.addSuppressed(bindingFailure)
        }
        throw wrapped
    }
}

private fun fixedCommand(
    bindings: PinnedDockerRuntimeBindings,
    arguments: List<String>,
    maximumStdoutBytes: Int,
) = LinuxBoundedSessionCommand(
    arguments = listOf(bindings.executableDescriptorPath.toString()) + arguments,
    environment = bindings.environment,
    workingDirectory = Path.of("/"),
    timeout = CONTROL_COMMAND_TIMEOUT,
    maximumStdoutBytes = maximumStdoutBytes,
    maximumStderrBytes = MAXIMUM_DIAGNOSTIC_STDERR_BYTES,
)

private fun requireSuccessfulResult(
    exitCode: Int?,
    signal: Int?,
    stderr: ByteArray,
    label: String,
) {
    if (signal != null || exitCode != 0) {
        dockerSessionFail("$label control client did not exit successfully")
    }
    if (stderr.isNotEmpty()) {
        dockerSessionFail("$label control client emitted diagnostic stderr")
    }
}

private fun wrapControlFailure(
    label: String,
    failure: Throwable,
): LlvmBehaviorHostedContainerV1DockerSessionException =
    if (failure is LlvmBehaviorHostedContainerV1DockerSessionException) {
        failure
    } else {
        LlvmBehaviorHostedContainerV1DockerSessionException(
            kind = LlvmBehaviorHostedContainerV1DockerSessionFailureKind.CONTROL_COMMAND_FAILED,
            message = "$label control command failed",
            cause = failure,
        )
    }

private fun frozenInventoryProjection(
    projection: LlvmBehaviorHostedContainerV1InventoryOutputProjection,
) = LlvmBehaviorHostedContainerV1InventoryOutputProjection(
    Collections.unmodifiableList(ArrayList(projection.containerIds)),
)

private fun dockerSessionFail(message: String, cause: Throwable? = null): Nothing =
    throw LlvmBehaviorHostedContainerV1DockerSessionException(
        kind = LlvmBehaviorHostedContainerV1DockerSessionFailureKind.CONTROL_COMMAND_FAILED,
        message = message,
        cause = cause,
    )

private val CONTROL_COMMAND_TIMEOUT: Duration = Duration.ofSeconds(30)
private const val MAXIMUM_INSPECT_STDOUT_BYTES = 1024 * 1024
private const val MAXIMUM_INVENTORY_STDOUT_BYTES = 16 * 65
private const val MAXIMUM_DIAGNOSTIC_STDERR_BYTES = 64 * 1024
