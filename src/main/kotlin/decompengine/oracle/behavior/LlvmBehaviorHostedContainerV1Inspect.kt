package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

internal class LlvmBehaviorHostedContainerV1InspectException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** Caller-owned identities which the raw Docker inspect records must exactly repeat. */
internal data class LlvmBehaviorHostedContainerV1Expectation(
    val imageId: String,
    val containerId: String,
    val containerName: String,
    val uid: Int,
    val gid: Int,
    val inputsSource: Path,
    val stageOutputSource: Path,
) {
    init {
        if (!imageId.matches(IMAGE_ID)) hostedContainerInspectFail("expected worker image ID is malformed")
        if (!containerId.matches(CONTAINER_ID)) hostedContainerInspectFail("expected container ID is malformed")
        if (!containerName.matches(CONTAINER_NAME)) hostedContainerInspectFail("expected container name is malformed")
        if (uid <= 0 || gid <= 0) hostedContainerInspectFail("worker UID and GID must both be non-root")
        requireBindSource(inputsSource, "inputs")
        requireBindSource(stageOutputSource, "stage output")
        if (inputsSource == stageOutputSource) {
            hostedContainerInspectFail("inputs and stage-output bind sources must be distinct")
        }
    }
}

/** Immutable, non-authoritative projection of the accepted derived worker image inspect record. */
internal data class LlvmBehaviorHostedWorkerImageV1Projection(
    val imageId: String,
    val platform: String,
    val rootfsLayerCount: Int,
    val rootfsProjectionSha256: String,
    val executionProjectionSha256: String,
)

/** Immutable, non-authoritative projection of the accepted stopped container inspect record. */
internal data class LlvmBehaviorHostedContainerV1Projection(
    val containerId: String,
    val containerName: String,
    val imageId: String,
    val user: String,
    val state: String,
    val mountCount: Int,
    val memoryBytes: Long,
    val memorySwapBytes: Long,
    val pidsLimit: Long,
    val cpuQuotaMicroseconds: Long,
    val cpuPeriodMicroseconds: Long,
    val sharedMemoryBytes: Long,
    val ulimitCount: Int,
    val preStartProjectionSha256: String,
)

internal data class LlvmBehaviorHostedContainerV1Inspection(
    val image: LlvmBehaviorHostedWorkerImageV1Projection,
    val container: LlvmBehaviorHostedContainerV1Projection,
)

/**
 * Strictly parses raw `docker image inspect` and `docker container inspect` JSON.
 *
 * The result is a structural projection only. The caller remains responsible for authenticating
 * the expected image ID, the Docker endpoint, the input paths, and every later START/cleanup fact.
 */
internal object LlvmBehaviorHostedContainerV1Inspect {
    fun inspect(
        imageInspectBytes: ByteArray,
        containerInspectBytes: ByteArray,
        expectation: LlvmBehaviorHostedContainerV1Expectation,
    ): LlvmBehaviorHostedContainerV1Inspection {
        val imageRecord = parseOneInspectRecord(imageInspectBytes, "worker image inspect")
        val image = verifyImage(imageRecord, expectation)
        val containerRecord = parseOneInspectRecord(containerInspectBytes, "worker container inspect")
        val container = verifyContainer(containerRecord, expectation)
        return LlvmBehaviorHostedContainerV1Inspection(image, container)
    }
}

private fun verifyImage(
    image: JsonObject,
    expectation: LlvmBehaviorHostedContainerV1Expectation,
): LlvmBehaviorHostedWorkerImageV1Projection {
    requireExact(image.inspectString("Id", "worker image"), expectation.imageId, "worker image ID")
    requireExact(image.inspectString("Os", "worker image"), REQUIRED_OS, "worker image OS")
    requireExact(
        image.inspectString("Architecture", "worker image"),
        REQUIRED_ARCHITECTURE,
        "worker image architecture",
    )
    requireAbsentNullOrEmptyString(image, "Variant", "worker image")

    val rootfs = image.inspectObject("RootFS", "worker image")
    requireExact(rootfs.inspectString("Type", "worker image rootfs"), "layers", "worker image rootfs type")
    val layers = rootfs.inspectArray("Layers", "worker image rootfs")
    if (layers.isEmpty() || layers.size > MAXIMUM_ROOTFS_LAYERS) {
        hostedContainerInspectFail("worker image rootfs must contain 1..$MAXIMUM_ROOTFS_LAYERS layers")
    }
    val layerIds = layers.mapIndexed { index, value ->
        value.inspectString("worker image rootfs layer $index").also { layer ->
            if (!layer.matches(IMAGE_ID)) hostedContainerInspectFail("worker image rootfs layer $index is malformed")
        }
    }
    if (layerIds.toSet().size != layerIds.size) {
        hostedContainerInspectFail("worker image rootfs layers contain a duplicate")
    }

    val config = image.inspectObject("Config", "worker image")
    verifyImageConfig(config)
    val rootfsProjection = JsonObject(
        mapOf(
            "layers" to JsonArray(layerIds.map(::JsonPrimitive)),
            "type" to JsonPrimitive("layers"),
        ),
    )
    return LlvmBehaviorHostedWorkerImageV1Projection(
        imageId = expectation.imageId,
        platform = REQUIRED_PLATFORM,
        rootfsLayerCount = layerIds.size,
        rootfsProjectionSha256 = canonicalSha256(rootfsProjection),
        executionProjectionSha256 = canonicalSha256(imageExecutionProjection()),
    )
}

private fun verifyImageConfig(config: JsonObject) {
    requireExactStringList(config, "Entrypoint", EXPECTED_ENTRYPOINT, "worker image config")
    requireNullOrEmptyArray(config, "Cmd", "worker image config")
    requireExactEnvironment(config, EXPECTED_IMAGE_ENVIRONMENT, "worker image config")
    requireExact(config.inspectString("User", "worker image config", allowEmpty = true), "", "worker image user")
    requireExact(
        config.inspectString("WorkingDir", "worker image config", allowEmpty = true),
        EXPECTED_IMAGE_WORKING_DIRECTORY,
        "worker image working directory",
    )

    requireNullOrEmptyObject(config, "Volumes", "worker image config")
    requireAbsentOrNull(config, "Healthcheck", "worker image config")
    requireAbsentNullOrEmptyString(config, "StopSignal", "worker image config")
    requireAbsentOrNull(config, "StopTimeout", "worker image config")
    requireNullOrEmptyArray(config, "Shell", "worker image config")
    requireNullOrEmptyArray(config, "OnBuild", "worker image config")
    requireNullOrEmptyObject(config, "ExposedPorts", "worker image config")
    requireExactStringObject(config, "Labels", EXPECTED_IMAGE_LABELS, "worker image config")
    requireAbsentNullOrEmptyString(config, "Hostname", "worker image config")
    requireAbsentNullOrEmptyString(config, "Domainname", "worker image config")
    requireAbsentNullOrEmptyString(config, "Image", "worker image config")
    listOf(
        "AttachStdin",
        "AttachStdout",
        "AttachStderr",
        "Tty",
        "OpenStdin",
        "StdinOnce",
        "ArgsEscaped",
        "NetworkDisabled",
    )
        .forEach { field -> requireAbsentOrFalse(config, field, "worker image config") }
}

private fun verifyContainer(
    container: JsonObject,
    expectation: LlvmBehaviorHostedContainerV1Expectation,
): LlvmBehaviorHostedContainerV1Projection {
    requireExact(container.inspectString("Id", "worker container"), expectation.containerId, "container ID")
    requireExact(
        container.inspectString("Name", "worker container"),
        "/${expectation.containerName}",
        "container name",
    )
    requireExact(container.inspectString("Image", "worker container"), expectation.imageId, "container image ID")
    requireExact(container.inspectString("Path", "worker container"), EXPECTED_ENTRYPOINT.first(), "container path")
    requireExactStringList(container, "Args", EXPECTED_ENTRYPOINT.drop(1), "worker container")
    requireExact(container.inspectLong("RestartCount", "worker container"), 0L, "container restart count")
    requireAbsentNullOrEmptyString(container, "LogPath", "worker container")
    requireNullOrEmptyArray(container, "ExecIDs", "worker container")
    requireExact(container.inspectString("Platform", "worker container"), REQUIRED_OS, "container platform")

    val state = container.inspectObject("State", "worker container")
    verifyCreatedState(state)
    val config = container.inspectObject("Config", "worker container")
    verifyContainerConfig(config, expectation)
    val hostConfig = container.inspectObject("HostConfig", "worker container")
    verifyHostConfig(hostConfig, expectation)
    verifyRuntimeMounts(container.inspectArray("Mounts", "worker container"), expectation)
    verifyNetworkSettings(container.inspectObject("NetworkSettings", "worker container"))

    val user = "${expectation.uid}:${expectation.gid}"
    return LlvmBehaviorHostedContainerV1Projection(
        containerId = expectation.containerId,
        containerName = expectation.containerName,
        imageId = expectation.imageId,
        user = user,
        state = CREATED_STATE,
        mountCount = EXPECTED_MOUNT_COUNT,
        memoryBytes = MEMORY_BYTES,
        memorySwapBytes = MEMORY_SWAP_BYTES,
        pidsLimit = PIDS_LIMIT,
        cpuQuotaMicroseconds = CPU_QUOTA_MICROSECONDS,
        cpuPeriodMicroseconds = CPU_PERIOD_MICROSECONDS,
        sharedMemoryBytes = SHARED_MEMORY_BYTES,
        ulimitCount = EXPECTED_ULIMITS.size,
        preStartProjectionSha256 = canonicalSha256(containerPreStartProjection(expectation)),
    )
}

private fun verifyCreatedState(state: JsonObject) {
    requireExact(state.inspectString("Status", "worker container state"), CREATED_STATE, "container state")
    listOf("Running", "Paused", "Restarting", "OOMKilled", "Dead").forEach { field ->
        requireExact(state.inspectBoolean(field, "worker container state"), false, "container state $field")
    }
    listOf("Pid", "ExitCode").forEach { field ->
        requireExact(state.inspectLong(field, "worker container state"), 0L, "container state $field")
    }
    requireExact(state.inspectString("Error", "worker container state", allowEmpty = true), "", "container state error")
    listOf("StartedAt", "FinishedAt").forEach { field ->
        requireExact(state.inspectString(field, "worker container state"), ZERO_DOCKER_TIMESTAMP, "container $field")
    }
    requireAbsentOrNull(state, "Health", "worker container state")
    requireAbsentOrFalse(state, "RemovalInProgress", "worker container state")
    state["CheckpointedAt"]?.let {
        requireExact(it.inspectString("worker container checkpoint time"), ZERO_DOCKER_TIMESTAMP, "checkpoint time")
    }
}

private fun verifyContainerConfig(
    config: JsonObject,
    expectation: LlvmBehaviorHostedContainerV1Expectation,
) {
    requireExact(config.inspectString("Image", "worker container config"), expectation.imageId, "config image ID")
    requireExactStringList(config, "Entrypoint", EXPECTED_ENTRYPOINT, "worker container config")
    requireNullOrEmptyArray(config, "Cmd", "worker container config")
    requireExactEnvironment(config, EXPECTED_CONTAINER_ENVIRONMENT, "worker container config")
    requireExact(
        config.inspectString("User", "worker container config"),
        "${expectation.uid}:${expectation.gid}",
        "container user",
    )
    requireExact(
        config.inspectString("WorkingDir", "worker container config", allowEmpty = true),
        EXPECTED_WORKING_DIRECTORY,
        "container working directory",
    )
    requireExact(config.inspectString("Hostname", "worker container config"), EXPECTED_HOSTNAME, "container hostname")
    requireExact(
        config.inspectString("Domainname", "worker container config", allowEmpty = true),
        "",
        "container domain name",
    )
    mapOf(
        "AttachStdin" to false,
        "AttachStdout" to true,
        "AttachStderr" to true,
        "Tty" to false,
        "OpenStdin" to false,
        "StdinOnce" to false,
    ).forEach { (field, expected) ->
        requireExact(config.inspectBoolean(field, "worker container config"), expected, "container config $field")
    }
    requireNullOrEmptyObject(config, "Volumes", "worker container config")
    requireAbsentOrNull(config, "Healthcheck", "worker container config")
    requireNullOrEmptyObject(config, "ExposedPorts", "worker container config")
    requireExactStringObject(config, "Labels", EXPECTED_IMAGE_LABELS, "worker container config")
    requireNullOrEmptyArray(config, "Shell", "worker container config")
    requireNullOrEmptyArray(config, "OnBuild", "worker container config")
    requireAbsentNullOrEmptyString(config, "StopSignal", "worker container config")
    requireAbsentOrNull(config, "StopTimeout", "worker container config")
    requireAbsentOrFalse(config, "ArgsEscaped", "worker container config")
    requireAbsentOrFalse(config, "NetworkDisabled", "worker container config")
    requireAbsentNullOrEmptyString(config, "MacAddress", "worker container config")
}

private fun verifyHostConfig(
    host: JsonObject,
    expectation: LlvmBehaviorHostedContainerV1Expectation,
) {
    val exactStrings = mapOf(
        "NetworkMode" to "none",
        "IpcMode" to "private",
        "CgroupnsMode" to "private",
        "PidMode" to "",
        "UTSMode" to "",
        "UsernsMode" to "",
        "CgroupParent" to "",
        "Cgroup" to "",
        "ContainerIDFile" to "",
        "VolumeDriver" to "",
        "Isolation" to "",
        "Runtime" to EXPECTED_RUNTIME,
    )
    exactStrings.forEach { (field, expected) ->
        requireExact(host.inspectString(field, "worker host config", allowEmpty = true), expected, "host config $field")
    }
    mapOf(
        "ReadonlyRootfs" to true,
        "Privileged" to false,
        "PublishAllPorts" to false,
        "AutoRemove" to false,
        "Init" to false,
    ).forEach { (field, expected) ->
        requireExact(host.inspectBoolean(field, "worker host config"), expected, "host config $field")
    }

    requireExactStringList(host, "CapDrop", listOf("ALL"), "worker host config")
    requireNullOrEmptyArray(host, "CapAdd", "worker host config")
    requireExactStringList(host, "SecurityOpt", EXPECTED_SECURITY_OPTIONS, "worker host config")
    requireNullOrEmptyArray(host, "Binds", "worker host config")
    requireNullOrEmptyArray(host, "VolumesFrom", "worker host config")
    requireNullOrEmptyArray(host, "Devices", "worker host config")
    requireNullOrEmptyArray(host, "DeviceCgroupRules", "worker host config")
    requireNullOrEmptyArray(host, "DeviceRequests", "worker host config")
    verifyUlimits(host.inspectArray("Ulimits", "worker host config"))

    requireExact(host.inspectLong("Memory", "worker host config"), MEMORY_BYTES, "host memory limit")
    requireExact(host.inspectLong("MemorySwap", "worker host config"), MEMORY_SWAP_BYTES, "host memory-swap limit")
    requireExact(host.inspectLong("PidsLimit", "worker host config"), PIDS_LIMIT, "host PID limit")
    requireExact(host.inspectLong("CpuQuota", "worker host config"), CPU_QUOTA_MICROSECONDS, "host CPU quota")
    requireExact(host.inspectLong("CpuPeriod", "worker host config"), CPU_PERIOD_MICROSECONDS, "host CPU period")
    requireExact(host.inspectLong("ShmSize", "worker host config"), SHARED_MEMORY_BYTES, "host shared-memory limit")
    requireExact(host.inspectLong("OomScoreAdj", "worker host config"), OOM_SCORE_ADJUSTMENT, "host OOM adjustment")
    requireAbsentNullOrFalse(host, "OomKillDisable", "worker host config")

    EXACT_ZERO_RESOURCE_FIELDS.forEach { field ->
        requireExact(host.inspectLong(field, "worker host config"), 0L, "host resource field $field")
    }
    EXACT_EMPTY_RESOURCE_FIELDS.forEach { field ->
        requireExact(host.inspectString(field, "worker host config", allowEmpty = true), "", "host resource field $field")
    }
    EXACT_EMPTY_RESOURCE_ARRAY_FIELDS.forEach { field ->
        requireNullOrEmptyArray(host, field, "worker host config")
    }
    requireAbsentOrNull(host, "MemorySwappiness", "worker host config")
    OPTIONAL_ZERO_RESOURCE_FIELDS.forEach { field -> requireAbsentNullOrZero(host, field, "worker host config") }

    verifyExactRestartPolicy(host.inspectObject("RestartPolicy", "worker host config"))
    verifyExactLogConfig(host.inspectObject("LogConfig", "worker host config"))
    listOf("Dns", "DnsOptions", "DnsSearch", "ExtraHosts", "GroupAdd", "Links").forEach { field ->
        requireNullOrEmptyArray(host, field, "worker host config")
    }
    listOf("PortBindings", "StorageOpt", "Sysctls").forEach { field ->
        requireNullOrEmptyObject(host, field, "worker host config")
    }
    requireOptionalZeroConsoleSize(host)
    requireRequiredPathSubset(host, "MaskedPaths", REQUIRED_MASKED_PATHS)
    requireRequiredPathSubset(host, "ReadonlyPaths", REQUIRED_READONLY_PATHS)

    verifyRequestedBindMounts(host.inspectArray("Mounts", "worker host config"), expectation)
    verifyTmpfs(host.inspectObject("Tmpfs", "worker host config"), expectation)
}

private fun verifyExactRestartPolicy(policy: JsonObject) {
    if (policy.keys != setOf("Name", "MaximumRetryCount")) {
        hostedContainerInspectFail("worker restart policy contains unexpected fields")
    }
    requireExact(policy.inspectString("Name", "worker restart policy"), "no", "worker restart policy")
    requireExact(policy.inspectLong("MaximumRetryCount", "worker restart policy"), 0L, "worker restart retry count")
}

private fun verifyExactLogConfig(config: JsonObject) {
    if (config.keys != setOf("Type", "Config")) {
        hostedContainerInspectFail("worker log config contains unexpected fields")
    }
    requireExact(config.inspectString("Type", "worker log config"), "none", "worker log driver")
    if (config.inspectObject("Config", "worker log config").isNotEmpty()) {
        hostedContainerInspectFail("worker log driver options must be empty")
    }
}

private fun verifyUlimits(entries: JsonArray) {
    if (entries.size != EXPECTED_ULIMITS.size) {
        hostedContainerInspectFail("worker ulimit set has the wrong size")
    }
    val byName = entries.associateUniqueObjectsBy("Name", "worker ulimit")
    if (byName.keys != EXPECTED_ULIMITS.keys) hostedContainerInspectFail("worker ulimit names differ from the fixed set")
    EXPECTED_ULIMITS.forEach { (name, ceiling) ->
        val entry = byName.getValue(name)
        if (entry.keys != setOf("Name", "Soft", "Hard")) {
            hostedContainerInspectFail("worker ulimit $name contains unexpected fields")
        }
        requireExact(entry.inspectLong("Soft", "worker ulimit $name"), ceiling, "worker ulimit $name soft ceiling")
        requireExact(entry.inspectLong("Hard", "worker ulimit $name"), ceiling, "worker ulimit $name hard ceiling")
    }
}

private fun verifyRequestedBindMounts(
    mounts: JsonArray,
    expectation: LlvmBehaviorHostedContainerV1Expectation,
) {
    if (mounts.size != 2) hostedContainerInspectFail("worker host config must request exactly two bind mounts")
    val byTarget = mounts.associateUniqueObjectsBy("Target", "worker host bind request")
    if (byTarget.keys != EXPECTED_BIND_TARGETS) {
        hostedContainerInspectFail("worker host bind request destinations differ from the fixed set")
    }
    verifyRequestedBind(
        byTarget.getValue(INPUTS_TARGET),
        expectation.inputsSource.toString(),
        INPUTS_TARGET,
        readOnly = true,
    )
    verifyRequestedBind(
        byTarget.getValue(STAGE_OUTPUT_TARGET),
        expectation.stageOutputSource.toString(),
        STAGE_OUTPUT_TARGET,
        readOnly = false,
    )
}

private fun verifyRequestedBind(
    mount: JsonObject,
    source: String,
    target: String,
    readOnly: Boolean,
) {
    requireExact(mount.inspectString("Type", "worker host bind request"), "bind", "bind mount type")
    requireExact(mount.inspectString("Source", "worker host bind request"), source, "bind mount source")
    requireExact(mount.inspectString("Target", "worker host bind request"), target, "bind mount target")
    if (readOnly) {
        requireExact(mount.inspectBoolean("ReadOnly", "worker host bind request"), true, "bind mount access")
    } else {
        requireAbsentOrFalse(mount, "ReadOnly", "worker host bind request")
    }
    requireAbsentNullOrEmptyString(mount, "Consistency", "worker host bind request")
    val options = mount.inspectObject("BindOptions", "worker host bind request")
    listOf("VolumeOptions", "TmpfsOptions", "ImageOptions").forEach { field ->
        requireAbsentOrNull(mount, field, "worker host bind request")
    }
    requireExact(options.inspectString("Propagation", "worker host bind options"), "rprivate", "bind propagation")
    listOf("NonRecursive", "CreateMountpoint", "ReadOnlyNonRecursive", "ReadOnlyForceRecursive").forEach { field ->
        requireAbsentOrFalse(options, field, "worker host bind options")
    }
}

private fun verifyTmpfs(
    tmpfs: JsonObject,
    expectation: LlvmBehaviorHostedContainerV1Expectation,
) {
    if (tmpfs.keys != EXPECTED_TMPFS_TARGETS) {
        hostedContainerInspectFail("worker tmpfs destinations differ from the fixed set")
    }
    requireExactOptionSet(
        tmpfs.inspectString(WORK_TARGET, "worker tmpfs"),
        setOf(
            "rw",
            "nosuid",
            "nodev",
            "exec",
            "size=$WORK_TMPFS_BYTES",
            "nr_inodes=$WORK_TMPFS_INODES",
            "mode=0700",
            "uid=${expectation.uid}",
            "gid=${expectation.gid}",
        ),
        WORK_TARGET,
    )
    requireExactOptionSet(
        tmpfs.inspectString(TEMPORARY_TARGET, "worker tmpfs"),
        setOf(
            "rw",
            "nosuid",
            "nodev",
            "noexec",
            "size=$TEMPORARY_TMPFS_BYTES",
            "nr_inodes=$TEMPORARY_TMPFS_INODES",
            "mode=1777",
        ),
        TEMPORARY_TARGET,
    )
    requireExactOptionSet(
        tmpfs.inspectString(JNA_TARGET, "worker tmpfs"),
        setOf(
            "rw",
            "nosuid",
            "nodev",
            "exec",
            "size=$JNA_TMPFS_BYTES",
            "nr_inodes=$JNA_TMPFS_INODES",
            "mode=0700",
            "uid=${expectation.uid}",
            "gid=${expectation.gid}",
        ),
        JNA_TARGET,
    )
}

private fun requireExactOptionSet(value: String, expected: Set<String>, target: String) {
    val options = value.split(',')
    if (options.any { it.isEmpty() || it.trim() != it } || options.toSet().size != options.size || options.toSet() != expected) {
        hostedContainerInspectFail("worker tmpfs $target options differ from the fixed set")
    }
}

private fun verifyRuntimeMounts(
    mounts: JsonArray,
    expectation: LlvmBehaviorHostedContainerV1Expectation,
) {
    if (mounts.size != EXPECTED_BIND_TARGETS.size) {
        hostedContainerInspectFail("worker resolved runtime mount set must contain exactly two bind mounts")
    }
    val byDestination = mounts.associateUniqueObjectsBy("Destination", "worker runtime mount")
    if (byDestination.keys != EXPECTED_BIND_TARGETS) {
        hostedContainerInspectFail("worker resolved runtime bind destinations differ from the fixed set")
    }
    verifyRuntimeBind(
        byDestination.getValue(INPUTS_TARGET),
        expectation.inputsSource.toString(),
        INPUTS_TARGET,
        writable = false,
    )
    verifyRuntimeBind(
        byDestination.getValue(STAGE_OUTPUT_TARGET),
        expectation.stageOutputSource.toString(),
        STAGE_OUTPUT_TARGET,
        writable = true,
    )
}

private fun verifyRuntimeBind(
    mount: JsonObject,
    source: String,
    destination: String,
    writable: Boolean,
) {
    requireExact(mount.inspectString("Type", "worker runtime bind"), "bind", "runtime bind type")
    requireExact(mount.inspectString("Source", "worker runtime bind"), source, "runtime bind source")
    requireExact(mount.inspectString("Destination", "worker runtime bind"), destination, "runtime bind destination")
    requireExact(mount.inspectBoolean("RW", "worker runtime bind"), writable, "runtime bind access")
    requireExact(
        mount.inspectString("Mode", "worker runtime bind", allowEmpty = true),
        "",
        "runtime bind mode",
    )
    requireExact(mount.inspectString("Propagation", "worker runtime bind"), "rprivate", "runtime bind propagation")
    requireAbsentNullOrEmptyString(mount, "Name", "worker runtime bind")
    requireAbsentNullOrEmptyString(mount, "Driver", "worker runtime bind")
}

private fun verifyNetworkSettings(settings: JsonObject) {
    requireAbsentNullOrEmptyString(settings, "SandboxID", "worker network settings")
    requireAbsentNullOrEmptyString(settings, "SandboxKey", "worker network settings")
    requireNullOrEmptyObject(settings, "Ports", "worker network settings")
    val networks = settings.inspectObject("Networks", "worker network settings")
    if (networks.keys != setOf("none")) hostedContainerInspectFail("worker must be attached only to the none network")
    val none = networks.inspectObject("none", "worker network settings")
    listOf(
        "NetworkID",
        "EndpointID",
        "Gateway",
        "IPAddress",
        "MacAddress",
        "IPv6Gateway",
        "GlobalIPv6Address",
    ).forEach { field -> requireAbsentNullOrEmptyString(none, field, "worker none network") }
    listOf("IPPrefixLen", "GlobalIPv6PrefixLen").forEach { field ->
        none[field]?.let { requireExact(it.inspectLong("worker none network $field"), 0L, "worker none network $field") }
    }
    requireNullOrEmptyArray(none, "Aliases", "worker none network")
    requireNullOrEmptyArray(none, "Links", "worker none network")
    requireNullOrEmptyArray(none, "DNSNames", "worker none network")
    requireAbsentOrNull(none, "IPAMConfig", "worker none network")
    requireNullOrEmptyObject(none, "DriverOpts", "worker none network")
    requireAbsentNullOrZero(none, "GwPriority", "worker none network")
}

private fun requireExactEnvironment(config: JsonObject, expected: Map<String, String>, label: String) {
    val environment = config.inspectArray("Env", label).mapIndexed { index, element ->
        element.inspectString("$label environment $index").also { binding ->
            if ('\u0000' in binding || '=' !in binding || binding.startsWith('=')) {
                hostedContainerInspectFail("$label environment $index is malformed")
            }
        }
    }
    val names = environment.map { it.substringBefore('=') }
    if (names.toSet().size != names.size) hostedContainerInspectFail("$label environment contains duplicate names")
    if (names.any(::isForbiddenEnvironmentName)) hostedContainerInspectFail("$label environment contains a loader or shell hook")
    val actual = environment.associate { it.substringBefore('=') to it.substringAfter('=', missingDelimiterValue = "") }
    if (actual != expected) hostedContainerInspectFail("$label environment differs from the fixed safe set")
}

private fun isForbiddenEnvironmentName(name: String): Boolean {
    val upper = name.uppercase()
    return upper in FORBIDDEN_ENVIRONMENT_NAMES || FORBIDDEN_ENVIRONMENT_PREFIXES.any(upper::startsWith)
}

private fun imageExecutionProjection(): JsonObject = JsonObject(
    mapOf(
        "absentExecutionFields" to stringJsonArray(
            "healthcheck",
            "onBuild",
            "shell",
            "stopSignal",
            "stopTimeout",
            "volumes",
        ),
        "cmd" to JsonArray(emptyList()),
        "entrypoint" to JsonArray(EXPECTED_ENTRYPOINT.map(::JsonPrimitive)),
        "environment" to JsonObject(EXPECTED_IMAGE_ENVIRONMENT.mapValues { JsonPrimitive(it.value) }),
        "labels" to JsonObject(EXPECTED_IMAGE_LABELS.mapValues { JsonPrimitive(it.value) }),
        "platform" to JsonPrimitive(REQUIRED_PLATFORM),
        "user" to JsonPrimitive(""),
        "workingDirectory" to JsonPrimitive(EXPECTED_IMAGE_WORKING_DIRECTORY),
    ),
)

private fun containerPreStartProjection(expectation: LlvmBehaviorHostedContainerV1Expectation): JsonObject = JsonObject(
    mapOf(
        "containerId" to JsonPrimitive(expectation.containerId),
        "containerName" to JsonPrimitive(expectation.containerName),
        "execution" to JsonObject(
            mapOf(
                "cmd" to JsonArray(emptyList()),
                "entrypoint" to JsonArray(EXPECTED_ENTRYPOINT.map(::JsonPrimitive)),
                "environment" to JsonObject(
                    EXPECTED_CONTAINER_ENVIRONMENT.mapValues { JsonPrimitive(it.value) },
                ),
                "gid" to JsonPrimitive(expectation.gid),
                "hostname" to JsonPrimitive(EXPECTED_HOSTNAME),
                "labels" to JsonObject(EXPECTED_IMAGE_LABELS.mapValues { JsonPrimitive(it.value) }),
                "uid" to JsonPrimitive(expectation.uid),
                "workingDirectory" to JsonPrimitive(EXPECTED_WORKING_DIRECTORY),
            ),
        ),
        "imageId" to JsonPrimitive(expectation.imageId),
        "mounts" to JsonArray(
            listOf(
                JsonObject(
                    mapOf(
                        "destination" to JsonPrimitive(INPUTS_TARGET),
                        "kind" to JsonPrimitive("bind"),
                        "readOnly" to JsonPrimitive(true),
                        "source" to JsonPrimitive(expectation.inputsSource.toString()),
                    ),
                ),
                JsonObject(
                    mapOf(
                        "destination" to JsonPrimitive(STAGE_OUTPUT_TARGET),
                        "kind" to JsonPrimitive("bind"),
                        "readOnly" to JsonPrimitive(false),
                        "source" to JsonPrimitive(expectation.stageOutputSource.toString()),
                    ),
                ),
                tmpfsProjection(
                    WORK_TARGET,
                    WORK_TMPFS_BYTES,
                    WORK_TMPFS_INODES,
                    "0700",
                    expectation.uid,
                    expectation.gid,
                    executable = true,
                ),
                tmpfsProjection(
                    TEMPORARY_TARGET,
                    TEMPORARY_TMPFS_BYTES,
                    TEMPORARY_TMPFS_INODES,
                    "1777",
                    null,
                    null,
                    executable = false,
                ),
                tmpfsProjection(
                    JNA_TARGET,
                    JNA_TMPFS_BYTES,
                    JNA_TMPFS_INODES,
                    "0700",
                    expectation.uid,
                    expectation.gid,
                    executable = true,
                ),
            ),
        ),
        "resources" to JsonObject(
            mapOf(
                "cpuPeriodMicroseconds" to JsonPrimitive(CPU_PERIOD_MICROSECONDS),
                "cpuQuotaMicroseconds" to JsonPrimitive(CPU_QUOTA_MICROSECONDS),
                "memoryBytes" to JsonPrimitive(MEMORY_BYTES),
                "memorySwapBytes" to JsonPrimitive(MEMORY_SWAP_BYTES),
                "pidsLimit" to JsonPrimitive(PIDS_LIMIT),
                "sharedMemoryBytes" to JsonPrimitive(SHARED_MEMORY_BYTES),
            ),
        ),
        "security" to JsonObject(
            mapOf(
                "capDrop" to stringJsonArray("ALL"),
                "cgroupNamespace" to JsonPrimitive("private"),
                "ipcNamespace" to JsonPrimitive("private"),
                "networkMode" to JsonPrimitive("none"),
                "pidNamespace" to JsonPrimitive("private"),
                "privileged" to JsonPrimitive(false),
                "readOnlyRoot" to JsonPrimitive(true),
                "runtime" to JsonPrimitive(EXPECTED_RUNTIME),
                "securityOptions" to JsonArray(EXPECTED_SECURITY_OPTIONS.map(::JsonPrimitive)),
            ),
        ),
        "state" to JsonPrimitive(CREATED_STATE),
        "ulimits" to JsonObject(
            EXPECTED_ULIMITS.toSortedMap().mapValues { (_, ceiling) ->
                JsonObject(
                    mapOf(
                        "hard" to JsonPrimitive(ceiling),
                        "soft" to JsonPrimitive(ceiling),
                    ),
                )
            },
        ),
    ),
)

private fun tmpfsProjection(
    destination: String,
    bytes: Long,
    inodes: Long,
    mode: String,
    uid: Int?,
    gid: Int?,
    executable: Boolean,
): JsonObject = JsonObject(
    buildMap {
        put("bytes", JsonPrimitive(bytes))
        put("destination", JsonPrimitive(destination))
        put("executable", JsonPrimitive(executable))
        put("inodes", JsonPrimitive(inodes))
        put("kind", JsonPrimitive("tmpfs"))
        put("mode", JsonPrimitive(mode))
        put("nodev", JsonPrimitive(true))
        put("nosuid", JsonPrimitive(true))
        if (uid != null) put("uid", JsonPrimitive(uid))
        if (gid != null) put("gid", JsonPrimitive(gid))
    },
)

private fun stringJsonArray(vararg values: String): JsonArray = JsonArray(values.map(::JsonPrimitive))

private fun canonicalSha256(value: JsonElement): String = OracleArtifacts.sha256(OracleJson.canonicalBytes(value, INSPECT_LIMITS))

private fun parseOneInspectRecord(bytes: ByteArray, label: String): JsonObject {
    val parsed = try {
        OracleJson.parse(bytes, INSPECT_LIMITS)
    } catch (failure: Exception) {
        throw LlvmBehaviorHostedContainerV1InspectException("$label is not strict bounded JSON", failure)
    }
    val records = parsed as? JsonArray ?: hostedContainerInspectFail("$label root must be an array")
    if (records.size != 1) hostedContainerInspectFail("$label must contain exactly one record")
    return records.single() as? JsonObject ?: hostedContainerInspectFail("$label record must be an object")
}

private fun requireBindSource(path: Path, label: String) {
    if (!path.isAbsolute || path.normalize() != path || path.parent == null || path.toString() == "/" || '\u0000' in path.toString()) {
        hostedContainerInspectFail("expected $label bind source must be an absolute normalized non-root path")
    }
}

private fun JsonArray.associateUniqueObjectsBy(field: String, label: String): Map<String, JsonObject> {
    val result = LinkedHashMap<String, JsonObject>()
    forEachIndexed { index, element ->
        val record = element as? JsonObject ?: hostedContainerInspectFail("$label $index must be an object")
        val key = record.inspectString(field, "$label $index")
        if (result.put(key, record) != null) hostedContainerInspectFail("$label contains duplicate $field $key")
    }
    return result
}

private fun JsonObject.inspectObject(name: String, label: String): JsonObject = this[name] as? JsonObject
    ?: hostedContainerInspectFail("$label.$name must be an object")

private fun JsonObject.inspectArray(name: String, label: String): JsonArray = this[name] as? JsonArray
    ?: hostedContainerInspectFail("$label.$name must be an array")

private fun JsonObject.inspectString(name: String, label: String, allowEmpty: Boolean = false): String =
    (this[name] ?: hostedContainerInspectFail("$label.$name is missing")).inspectString("$label.$name", allowEmpty)

private fun JsonElement.inspectString(label: String, allowEmpty: Boolean = false): String {
    val primitive = this as? JsonPrimitive ?: hostedContainerInspectFail("$label must be a string")
    if (!primitive.isString || (!allowEmpty && primitive.content.isEmpty()) || '\u0000' in primitive.content) {
        hostedContainerInspectFail("$label must be ${if (allowEmpty) "a" else "a non-empty"} string without NUL")
    }
    return primitive.content
}

private fun JsonObject.inspectBoolean(name: String, label: String): Boolean {
    val primitive = this[name] as? JsonPrimitive ?: hostedContainerInspectFail("$label.$name must be a boolean")
    if (primitive.isString) hostedContainerInspectFail("$label.$name must be a boolean")
    return primitive.booleanOrNull ?: hostedContainerInspectFail("$label.$name must be a boolean")
}

private fun JsonObject.inspectLong(name: String, label: String): Long =
    (this[name] ?: hostedContainerInspectFail("$label.$name is missing")).inspectLong("$label.$name")

private fun JsonElement.inspectLong(label: String): Long {
    val primitive = this as? JsonPrimitive ?: hostedContainerInspectFail("$label must be an integer")
    if (primitive.isString || primitive.content.any { it in ".eE" }) hostedContainerInspectFail("$label must be an integer")
    return primitive.longOrNull ?: hostedContainerInspectFail("$label exceeds the supported integer range")
}

private fun requireExactStringList(config: JsonObject, name: String, expected: List<String>, label: String) {
    val actual = config.inspectArray(name, label).mapIndexed { index, value -> value.inspectString("$label.$name[$index]") }
    if (actual != expected) hostedContainerInspectFail("$label.$name differs from the fixed sequence")
}

private fun requireNullOrEmptyArray(config: JsonObject, name: String, label: String) {
    when (val value = config[name]) {
        null, JsonNull -> Unit
        is JsonArray -> if (value.isNotEmpty()) hostedContainerInspectFail("$label.$name must be empty")
        else -> hostedContainerInspectFail("$label.$name must be null or an empty array")
    }
}

private fun requireNullOrEmptyObject(config: JsonObject, name: String, label: String) {
    when (val value = config[name]) {
        null, JsonNull -> Unit
        is JsonObject -> if (value.isNotEmpty()) hostedContainerInspectFail("$label.$name must be empty")
        else -> hostedContainerInspectFail("$label.$name must be null or an empty object")
    }
}

private fun requireExactStringObject(
    config: JsonObject,
    name: String,
    expected: Map<String, String>,
    label: String,
) {
    val value = config[name] as? JsonObject ?: hostedContainerInspectFail("$label.$name must be an object")
    val actual = value.mapValues { (field, element) -> element.inspectString("$label.$name.$field") }
    if (actual != expected) hostedContainerInspectFail("$label.$name differs from the fixed safe object")
}

private fun requireAbsentOrNull(config: JsonObject, name: String, label: String) {
    if (config[name] != null && config[name] != JsonNull) hostedContainerInspectFail("$label.$name must be absent or null")
}

private fun requireAbsentNullOrEmptyString(config: JsonObject, name: String, label: String) {
    when (val value = config[name]) {
        null, JsonNull -> Unit
        is JsonPrimitive -> if (!value.isString || value.content.isNotEmpty()) {
            hostedContainerInspectFail("$label.$name must be absent, null, or empty")
        }
        else -> hostedContainerInspectFail("$label.$name must be absent, null, or empty")
    }
}

private fun requireAbsentOrFalse(config: JsonObject, name: String, label: String) {
    when (val value = config[name]) {
        null -> Unit
        is JsonPrimitive -> if (value.isString || value.booleanOrNull != false) {
            hostedContainerInspectFail("$label.$name must be absent or false")
        }
        else -> hostedContainerInspectFail("$label.$name must be absent or false")
    }
}

private fun requireAbsentNullOrFalse(config: JsonObject, name: String, label: String) {
    when (val value = config[name]) {
        null, JsonNull -> Unit
        is JsonPrimitive -> if (value.isString || value.booleanOrNull != false) {
            hostedContainerInspectFail("$label.$name must be absent, null, or false")
        }
        else -> hostedContainerInspectFail("$label.$name must be absent, null, or false")
    }
}

private fun requireAbsentNullOrZero(config: JsonObject, name: String, label: String) {
    when (val value = config[name]) {
        null, JsonNull -> Unit
        else -> if (value.inspectLong("$label.$name") != 0L) {
            hostedContainerInspectFail("$label.$name must be absent, null, or zero")
        }
    }
}

private fun requireOptionalZeroConsoleSize(host: JsonObject) {
    when (val value = host["ConsoleSize"]) {
        null, JsonNull -> Unit
        is JsonArray -> {
            if (value.size != 2 || value.any { it.inspectLong("worker host console size") != 0L }) {
                hostedContainerInspectFail("worker host console size must be [0,0]")
            }
        }
        else -> hostedContainerInspectFail("worker host console size must be absent, null, or [0,0]")
    }
}

private fun requireRequiredPathSubset(host: JsonObject, name: String, required: Set<String>) {
    val values = host.inspectArray(name, "worker host config").mapIndexed { index, value ->
        value.inspectString("worker host config.$name[$index]")
    }
    if (values.toSet().size != values.size || !values.toSet().containsAll(required)) {
        hostedContainerInspectFail("worker host config.$name weakens the required kernel paths")
    }
}

private fun <T> requireExact(actual: T, expected: T, label: String) {
    if (actual != expected) hostedContainerInspectFail("$label differs from the fixed value")
}

private fun hostedContainerInspectFail(message: String): Nothing =
    throw LlvmBehaviorHostedContainerV1InspectException(message)

private const val REQUIRED_OS = "linux"
private const val REQUIRED_ARCHITECTURE = "amd64"
private const val REQUIRED_PLATFORM = "$REQUIRED_OS/$REQUIRED_ARCHITECTURE"
private const val CREATED_STATE = "created"
private const val ZERO_DOCKER_TIMESTAMP = "0001-01-01T00:00:00Z"
private const val EXPECTED_WORKING_DIRECTORY = "/"
private const val EXPECTED_IMAGE_WORKING_DIRECTORY = ""
private const val EXPECTED_HOSTNAME = "llvm-hosted-build"
private const val EXPECTED_RUNTIME = "runc"

private const val INPUTS_TARGET = "/inputs"
private const val STAGE_OUTPUT_TARGET = "/stage-output"
private const val WORK_TARGET = "/work"
private const val TEMPORARY_TARGET = "/tmp"
private const val JNA_TARGET = "/decomp-jna"
private const val EXPECTED_MOUNT_COUNT = 5

private const val MEMORY_BYTES = 4L * 1024L * 1024L * 1024L
private const val MEMORY_SWAP_BYTES = MEMORY_BYTES
private const val PIDS_LIMIT = 512L
private const val CPU_QUOTA_MICROSECONDS = 200_000L
private const val CPU_PERIOD_MICROSECONDS = 100_000L
private const val SHARED_MEMORY_BYTES = 64L * 1024L * 1024L
private const val OOM_SCORE_ADJUSTMENT = 0L

private const val WORK_TMPFS_BYTES = 16L * 1024L * 1024L * 1024L
private const val WORK_TMPFS_INODES = 1_000_000L
private const val TEMPORARY_TMPFS_BYTES = 256L * 1024L * 1024L
private const val TEMPORARY_TMPFS_INODES = 4096L
private const val JNA_TMPFS_BYTES = 16L * 1024L * 1024L
private const val JNA_TMPFS_INODES = 128L

private val EXPECTED_ENTRYPOINT = listOf(
    "/decomp-jdk/bin/java",
    "-Djna.nosys=true",
    "-Djna.tmpdir=/decomp-jna",
    "-cp",
    "/decomp-app/lib/*",
    "decompengine.oracle.behavior.LlvmBehaviorHostedCleanBuildV2InnerWorkerMain",
)
private val EXPECTED_IMAGE_ENVIRONMENT = mapOf(
    "PATH" to "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
)
private val EXPECTED_CONTAINER_ENVIRONMENT = mapOf(
    "LC_ALL" to "C",
    "PATH" to "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "SOURCE_DATE_EPOCH" to "1779182222",
    "TZ" to "UTC",
)
private val EXPECTED_IMAGE_LABELS = mapOf("org.opencontainers.image.version" to "24.04")
private val EXPECTED_SECURITY_OPTIONS = listOf("no-new-privileges", "seccomp=builtin")
private val EXPECTED_ULIMITS = mapOf(
    "core" to 0L,
    "fsize" to 2_147_483_648L,
    "nofile" to 1024L,
)
private val EXPECTED_BIND_TARGETS = setOf(INPUTS_TARGET, STAGE_OUTPUT_TARGET)
private val EXPECTED_TMPFS_TARGETS = setOf(WORK_TARGET, TEMPORARY_TARGET, JNA_TARGET)
private val REQUIRED_MASKED_PATHS = setOf(
    "/proc/interrupts",
    "/proc/kcore",
    "/proc/keys",
    "/proc/timer_list",
    "/sys/firmware",
)
private val REQUIRED_READONLY_PATHS = setOf("/proc/sys", "/proc/sysrq-trigger")

private val EXACT_ZERO_RESOURCE_FIELDS = setOf(
    "NanoCpus",
    "CpuShares",
    "CpuRealtimePeriod",
    "CpuRealtimeRuntime",
    "MemoryReservation",
    "BlkioWeight",
    "CpuCount",
    "CpuPercent",
    "IOMaximumIOps",
    "IOMaximumBandwidth",
)
private val EXACT_EMPTY_RESOURCE_FIELDS = setOf("CpusetCpus", "CpusetMems")
private val EXACT_EMPTY_RESOURCE_ARRAY_FIELDS = setOf(
    "BlkioWeightDevice",
    "BlkioDeviceReadBps",
    "BlkioDeviceWriteBps",
    "BlkioDeviceReadIOps",
    "BlkioDeviceWriteIOps",
)
private val OPTIONAL_ZERO_RESOURCE_FIELDS = setOf(
    "Annotations",
    "CpuBurst",
    "KernelMemory",
    "KernelMemoryTCP",
    "CpuWeight",
)
private val FORBIDDEN_ENVIRONMENT_NAMES = setOf(
    "BASH_ENV",
    "CLASSPATH",
    "ENV",
    "GCONV_PATH",
    "HOSTALIASES",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "LOCPATH",
    "NLSPATH",
    "PROMPT_COMMAND",
    "RES_OPTIONS",
    "_JAVA_OPTIONS",
)
private val FORBIDDEN_ENVIRONMENT_PREFIXES = listOf("GLIBC_", "LD_", "MALLOC_", "PERL5", "PYTHON")

private val IMAGE_ID = Regex("sha256:[0-9a-f]{64}")
private val CONTAINER_ID = Regex("[0-9a-f]{64}")
private val CONTAINER_NAME = Regex("[a-z0-9][a-z0-9_.-]{0,127}")
private const val MAXIMUM_INSPECT_BYTES = 2 * 1024 * 1024
private const val MAXIMUM_ROOTFS_LAYERS = 256
private val INSPECT_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_INSPECT_BYTES,
    maximumCanonicalBytes = MAXIMUM_INSPECT_BYTES,
    maximumDepth = 32,
    maximumNodes = 20_000,
    maximumStringBytes = 64 * 1024,
    maximumTotalStringBytes = 1024 * 1024,
)
