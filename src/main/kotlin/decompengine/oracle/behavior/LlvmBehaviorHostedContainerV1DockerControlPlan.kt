package decompengine.oracle.behavior

import java.nio.charset.StandardCharsets
import java.nio.file.FileSystems
import java.nio.file.Path
import java.util.ArrayList
import java.util.Collections

internal class LlvmBehaviorHostedContainerV1DockerControlPlanException(message: String) :
    IllegalArgumentException(message)

/** Journal-derived identity plus untrusted structural values for pre-create rendering. */
internal class LlvmBehaviorHostedContainerV1PreCreateExpectation private constructor(
    binding: HostedContainerPreCreateBinding,
) {
    private val frozenBinding = binding
    val imageId: String = binding.imageId
    val containerName: String = binding.containerName
    val operationId: String = binding.operationId
    val journalBindingSha256: String = binding.journalBindingSha256
    val journalRootPathSha256: String = binding.journalRootPathSha256
    val uid: Int = binding.uid
    val gid: Int = binding.gid
    val inputsSource: Path = binding.inputsPath
    val stageOutputSource: Path = binding.stageOutputPath

    internal fun requireUnchanged(): HostedContainerPreCreateBinding {
        val current = requirePreCreateValues(
            imageId = imageId,
            operationId = operationId,
            containerName = containerName,
            journalBindingSha256 = journalBindingSha256,
            journalRootPathSha256 = journalRootPathSha256,
            uid = uid,
            gid = gid,
            inputsSource = inputsSource,
            stageOutputSource = stageOutputSource,
        )
        if (!samePreCreateBinding(current, frozenBinding)) {
            controlPlanFail("pre-create expectation changed after journal binding")
        }
        return frozenBinding
    }

    companion object {
        fun fromJournal(
            journalOwner: LlvmBehaviorHostedContainerV1OperationJournalOwner,
            imageId: String,
            uid: Int,
            gid: Int,
            inputsSource: Path,
            stageOutputSource: Path,
        ): LlvmBehaviorHostedContainerV1PreCreateExpectation =
            LlvmBehaviorHostedContainerV1PreCreateExpectation(
                requirePreCreateValues(
                    imageId = imageId,
                    operationId = journalOwner.operationId,
                    containerName = journalOwner.containerName,
                    journalBindingSha256 = journalOwner.bindingSha256,
                    journalRootPathSha256 = journalOwner.journalRootPathSha256,
                    uid = uid,
                    gid = gid,
                    inputsSource = inputsSource,
                    stageOutputSource = stageOutputSource,
                ),
            )
    }
}

/**
 * Immutable pre-create Docker CLI argument suffixes for hosted-container v1.
 *
 * This is an internal, code-only rendering. It selects no executable or endpoint, runs no
 * process, accepts no worker command arguments, parses no Docker inspect or inventory output,
 * and establishes no image, container, START, cleanup, containment, observation, publication,
 * admission, or release fact or authority. ACP remains the first-class candidate
 * producer/operator outside this renderer. The image identity, user, and paths remain untrusted
 * structural inputs here; the operation identity is copied only from the durable journal owner.
 */
internal class LlvmBehaviorHostedContainerV1DockerControlPlan private constructor(
    private val binding: HostedContainerPreCreateBinding,
    createArguments: List<String>,
    imageInspectArguments: List<String>,
    inspectByDurableNameArguments: List<String>,
    exactNameInventoryArguments: List<String>,
    exactOperationLabelInventoryArguments: List<String>,
) {
    val imageId: String = binding.imageId
    val containerName: String = binding.containerName
    val operationId: String = binding.operationId
    val journalBindingSha256: String = binding.journalBindingSha256
    val journalRootPathSha256: String = binding.journalRootPathSha256
    val createArguments: List<String> = immutableArguments(createArguments, "container create")
    val imageInspectArguments: List<String> = immutableArguments(imageInspectArguments, "image inspect")
    val inspectByDurableNameArguments: List<String> =
        immutableArguments(inspectByDurableNameArguments, "container inspect-by-durable-name")
    val exactNameInventoryArguments: List<String> =
        immutableArguments(exactNameInventoryArguments, "exact-name container inventory")
    val exactOperationLabelInventoryArguments: List<String> =
        immutableArguments(exactOperationLabelInventoryArguments, "exact-operation-label container inventory")

    /**
     * Structurally retains one candidate full-ID line shaped like Docker create stdout.
     *
     * Parsing this syntax neither proves that the bytes came from Docker nor claims that CREATE
     * succeeded. The future live coordinator must bind the invocation, exit status, stderr,
     * endpoint, and returned bytes before consuming this structural plan.
     */
    fun retainCreatedContainer(
        createStdoutBytes: ByteArray,
    ): LlvmBehaviorHostedContainerV1RetainedDockerControlPlan {
        return LlvmBehaviorHostedContainerV1RetainedDockerControlPlan.fromCreatedContainer(
            binding,
            createStdoutBytes,
        )
    }

    companion object {
        fun render(
            expectation: LlvmBehaviorHostedContainerV1PreCreateExpectation,
        ): LlvmBehaviorHostedContainerV1DockerControlPlan {
            val binding = expectation.requireUnchanged()

            val operationLabel = "$OPERATION_LABEL=${binding.operationId}"
            val nameFilter = "name=^/${binding.containerName}\$"
            val labelFilter = "label=$operationLabel"
            return LlvmBehaviorHostedContainerV1DockerControlPlan(
                binding = binding,
                createArguments = listOf(
                    "container",
                    "create",
                    "--pull=never",
                    "--platform=$REQUIRED_PLATFORM",
                    "--name=${binding.containerName}",
                    "--hostname=$HOSTNAME",
                    "--label=$operationLabel",
                    "--user=${binding.uid}:${binding.gid}",
                    "--workdir=/",
                    "--attach=stdout",
                    "--attach=stderr",
                    "--env=LC_ALL=C",
                    "--env=PATH=$PATH_VALUE",
                    "--env=SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH",
                    "--env=TZ=UTC",
                    "--network=none",
                    "--ipc=private",
                    "--cgroupns=private",
                    "--read-only",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--security-opt=seccomp=builtin",
                    "--runtime=runc",
                    "--init=false",
                    "--restart=no",
                    "--log-driver=none",
                    "--oom-score-adj=0",
                    "--memory=$MEMORY_BYTES",
                    "--memory-swap=$MEMORY_BYTES",
                    "--pids-limit=$PIDS_LIMIT",
                    "--cpu-period=$CPU_PERIOD_MICROSECONDS",
                    "--cpu-quota=$CPU_QUOTA_MICROSECONDS",
                    "--shm-size=$SHARED_MEMORY_BYTES",
                    "--ulimit=core=0:0",
                    "--ulimit=fsize=$FILE_SIZE_LIMIT_BYTES:$FILE_SIZE_LIMIT_BYTES",
                    "--ulimit=nofile=$OPEN_FILE_LIMIT:$OPEN_FILE_LIMIT",
                    "--mount=type=bind,source=${binding.inputsSource}," +
                        "target=/inputs,readonly,bind-propagation=rprivate",
                    "--mount=type=bind,source=${binding.stageOutputSource}," +
                        "target=/stage-output,bind-propagation=rprivate",
                    "--tmpfs=/work:rw,nosuid,nodev,exec,size=$WORK_TMPFS_BYTES," +
                        "nr_inodes=$WORK_TMPFS_INODES,mode=0700,uid=${binding.uid},gid=${binding.gid}",
                    "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=$TEMPORARY_TMPFS_BYTES," +
                        "nr_inodes=$TEMPORARY_TMPFS_INODES,mode=1777",
                    "--tmpfs=/decomp-jna:rw,nosuid,nodev,exec,size=$JNA_TMPFS_BYTES," +
                        "nr_inodes=$JNA_TMPFS_INODES,mode=0700,uid=${binding.uid},gid=${binding.gid}",
                    binding.imageId,
                ),
                imageInspectArguments = listOf(
                    "image",
                    "inspect",
                    "--platform=$REQUIRED_PLATFORM",
                    binding.imageId,
                ),
                inspectByDurableNameArguments = listOf("container", "inspect", binding.containerName),
                exactNameInventoryArguments = listOf(
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--filter=$nameFilter",
                    "--format=$EXACT_INVENTORY_FORMAT",
                ),
                exactOperationLabelInventoryArguments = listOf(
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--filter=$labelFilter",
                    "--format=$EXACT_INVENTORY_FORMAT",
                ),
            )
        }

        /**
         * Syntax-only lookup for one full ID obtained from a bounded name or label inventory.
         * A nonempty inventory is a cleanup blocker; this list neither authenticates the object
         * nor authorizes its removal.
         */
        fun inspectById(containerId: String): List<String> = immutableArguments(
            listOf("container", "inspect", requireContainerId(containerId)),
            "container inspect-by-inventory-ID",
        )
    }
}

/** Exact-ID-only read-only inspect suffix produced after structural create-stdout parsing. */
internal class LlvmBehaviorHostedContainerV1RetainedDockerControlPlan private constructor(
    binding: HostedContainerPreCreateBinding,
    containerId: String,
) {
    val operationId: String = binding.operationId
    val journalBindingSha256: String = binding.journalBindingSha256
    val journalRootPathSha256: String = binding.journalRootPathSha256
    val expectation = LlvmBehaviorHostedContainerV1Expectation(
        imageId = binding.imageId,
        containerId = requireContainerId(containerId),
        containerName = binding.containerName,
        uid = binding.uid,
        gid = binding.gid,
        inputsSource = binding.inputsPath,
        stageOutputSource = binding.stageOutputPath,
    )
    val candidateContainerInspectArguments: List<String> = immutableArguments(
        listOf("container", "inspect", expectation.containerId),
        "candidate-container inspect",
    )

    companion object {
        internal fun fromCreatedContainer(
            binding: HostedContainerPreCreateBinding,
            createStdoutBytes: ByteArray,
        ): LlvmBehaviorHostedContainerV1RetainedDockerControlPlan =
            LlvmBehaviorHostedContainerV1RetainedDockerControlPlan(
                binding,
                LlvmBehaviorHostedContainerV1DockerOutput.parseCreate(createStdoutBytes).containerId,
            )
    }
}

internal class HostedContainerPreCreateBinding internal constructor(
    val imageId: String,
    val containerName: String,
    val operationId: String,
    val journalBindingSha256: String,
    val journalRootPathSha256: String,
    val uid: Int,
    val gid: Int,
    val inputsSource: String,
    val stageOutputSource: String,
    val inputsPath: Path,
    val stageOutputPath: Path,
)

private fun samePreCreateBinding(
    left: HostedContainerPreCreateBinding,
    right: HostedContainerPreCreateBinding,
): Boolean =
    left.imageId == right.imageId && left.containerName == right.containerName &&
        left.operationId == right.operationId && left.journalBindingSha256 == right.journalBindingSha256 &&
        left.journalRootPathSha256 == right.journalRootPathSha256 && left.uid == right.uid && left.gid == right.gid &&
        left.inputsSource == right.inputsSource && left.stageOutputSource == right.stageOutputSource &&
        left.inputsPath == right.inputsPath && left.stageOutputPath == right.stageOutputPath

private fun requirePreCreateValues(
    imageId: String,
    operationId: String,
    containerName: String,
    journalBindingSha256: String,
    journalRootPathSha256: String,
    uid: Int,
    gid: Int,
    inputsSource: Path,
    stageOutputSource: Path,
): HostedContainerPreCreateBinding {
    if (!imageId.matches(IMAGE_ID)) controlPlanFail("worker image ID is malformed")
    if (!operationId.matches(SHA256) || !journalBindingSha256.matches(SHA256) ||
        !journalRootPathSha256.matches(SHA256)
    ) {
        controlPlanFail("journal-derived pre-create identity is malformed")
    }
    val nameOperationId = CONTAINER_NAME.matchEntire(containerName)?.groupValues?.get(1)
        ?: controlPlanFail("container name is not journal-derived")
    if (nameOperationId != operationId) controlPlanFail("container name and operation ID are cross-paired")
    if (uid <= 0 || gid <= 0) controlPlanFail("worker UID and GID must be non-root")
    val renderedInputs = requirePortableBindSource(inputsSource, "inputs")
    val renderedStageOutput = requirePortableBindSource(stageOutputSource, "stage output")
    if (renderedInputs == renderedStageOutput) controlPlanFail("bind sources must be distinct")
    return HostedContainerPreCreateBinding(
        imageId = imageId,
        containerName = containerName,
        operationId = operationId,
        journalBindingSha256 = journalBindingSha256,
        journalRootPathSha256 = journalRootPathSha256,
        uid = uid,
        gid = gid,
        inputsSource = renderedInputs,
        stageOutputSource = renderedStageOutput,
        inputsPath = Path.of(renderedInputs),
        stageOutputPath = Path.of(renderedStageOutput),
    )
}

private fun requireContainerId(containerId: String): String {
    if (!containerId.matches(CONTAINER_ID)) controlPlanFail("created container ID is malformed")
    return containerId
}

private fun requirePortableBindSource(path: Path, label: String): String {
    val rendered = path.toString()
    if (
        path.fileSystem != FileSystems.getDefault() || !path.isAbsolute || path.normalize() != path ||
        path.parent == null || rendered == "/" ||
        !rendered.matches(PORTABLE_BIND_SOURCE)
    ) {
        controlPlanFail("$label bind source is not a portable Docker --mount source")
    }
    if (rendered.toByteArray(StandardCharsets.UTF_8).size > MAXIMUM_BIND_SOURCE_UTF8_BYTES) {
        controlPlanFail("$label bind source exceeds $MAXIMUM_BIND_SOURCE_UTF8_BYTES UTF-8 bytes")
    }
    return rendered
}

private fun immutableArguments(arguments: List<String>, label: String): List<String> {
    if (arguments.size !in 2..MAXIMUM_ARGUMENT_COUNT) controlPlanFail("$label argument count is out of bounds")
    var totalBytes = 0
    arguments.forEachIndexed { index, argument ->
        val bytes = argument.toByteArray(StandardCharsets.UTF_8).size
        if (argument.isEmpty() || '\u0000' in argument || bytes > MAXIMUM_ARGUMENT_UTF8_BYTES) {
            controlPlanFail("$label argument $index is invalid")
        }
        totalBytes = Math.addExact(totalBytes, bytes)
        if (totalBytes > MAXIMUM_ARGUMENTS_UTF8_BYTES) {
            controlPlanFail("$label arguments exceed the aggregate UTF-8 bound")
        }
    }
    return Collections.unmodifiableList(ArrayList(arguments))
}

private fun controlPlanFail(message: String): Nothing =
    throw LlvmBehaviorHostedContainerV1DockerControlPlanException(message)

private const val REQUIRED_PLATFORM = "linux/amd64"
private const val HOSTNAME = "llvm-hosted-build"
private const val OPERATION_LABEL = "dev.decompengine.llvm-behavior-hosted-operation"
private const val PATH_VALUE = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
private const val SOURCE_DATE_EPOCH = "1779182222"

private const val MEMORY_BYTES = 4L * 1024L * 1024L * 1024L
private const val PIDS_LIMIT = 512L
private const val CPU_QUOTA_MICROSECONDS = 200_000L
private const val CPU_PERIOD_MICROSECONDS = 100_000L
private const val SHARED_MEMORY_BYTES = 64L * 1024L * 1024L
private const val FILE_SIZE_LIMIT_BYTES = 2_147_483_648L
private const val OPEN_FILE_LIMIT = 1024L

private const val WORK_TMPFS_BYTES = 16L * 1024L * 1024L * 1024L
private const val WORK_TMPFS_INODES = 1_000_000L
private const val TEMPORARY_TMPFS_BYTES = 256L * 1024L * 1024L
private const val TEMPORARY_TMPFS_INODES = 4096L
private const val JNA_TMPFS_BYTES = 16L * 1024L * 1024L
private const val JNA_TMPFS_INODES = 128L

private const val MAXIMUM_BIND_SOURCE_UTF8_BYTES = 4095
private const val MAXIMUM_ARGUMENT_COUNT = 63
private const val MAXIMUM_ARGUMENT_UTF8_BYTES = 8192
private const val MAXIMUM_ARGUMENTS_UTF8_BYTES = 63 * 1024

private const val EXACT_INVENTORY_FORMAT = "{{.ID}}"
private val IMAGE_ID = Regex("sha256:[0-9a-f]{64}")
private val SHA256 = Regex("[0-9a-f]{64}")
private val CONTAINER_ID = Regex("[0-9a-f]{64}")
private val CONTAINER_NAME = Regex("decomp-llvm-behavior-v1-([0-9a-f]{64})")
private val PORTABLE_BIND_SOURCE = Regex("/[A-Za-z0-9._+@%:=-]+(?:/[A-Za-z0-9._+@%:=-]+)*")
