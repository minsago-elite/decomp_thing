package decompengine.oracle.behavior

import decompengine.oracle.core.OracleJson
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class LlvmBehaviorHostedContainerV1InspectTest {
    @Test
    fun `raw and canonical inspect records produce the same immutable structural projection`() {
        val fixture = InspectFixture()

        val raw = LlvmBehaviorHostedContainerV1Inspect.inspect(
            rawInspectBytes(fixture.image),
            rawInspectBytes(fixture.container),
            fixture.expectation,
        )
        val canonical = LlvmBehaviorHostedContainerV1Inspect.inspect(
            OracleJson.canonicalBytes(JsonArray(listOf(fixture.image))),
            OracleJson.canonicalBytes(JsonArray(listOf(fixture.container))),
            fixture.expectation,
        )

        assertEquals(canonical, raw)
        assertEquals(IMAGE_ID, raw.image.imageId)
        assertEquals("linux/amd64", raw.image.platform)
        assertEquals(2, raw.image.rootfsLayerCount)
        assertEquals(CONTAINER_ID, raw.container.containerId)
        assertEquals(CONTAINER_NAME, raw.container.containerName)
        assertEquals(OPERATION_ID, raw.container.operationId)
        assertEquals(IMAGE_ID, raw.container.imageId)
        assertEquals("1001:1002", raw.container.user)
        assertEquals("created", raw.container.state)
        assertEquals(5, raw.container.mountCount)
        assertEquals(4L * 1024L * 1024L * 1024L, raw.container.memoryBytes)
        assertEquals(raw.container.memoryBytes, raw.container.memorySwapBytes)
        assertEquals(512, raw.container.pidsLimit)
        assertEquals(200_000, raw.container.cpuQuotaMicroseconds)
        assertEquals(100_000, raw.container.cpuPeriodMicroseconds)
        assertEquals(64L * 1024L * 1024L, raw.container.sharedMemoryBytes)
        assertEquals(3, raw.container.ulimitCount)
        listOf(
            raw.image.rootfsProjectionSha256,
            raw.image.executionProjectionSha256,
            raw.container.preStartProjectionSha256,
        ).forEach { sha256 -> assertTrue(sha256.matches(Regex("[0-9a-f]{64}"))) }
        listOf(raw.image, raw.container, raw).forEach { projection ->
            assertTrue(
                projection.javaClass.declaredFields.none { field ->
                    field.type == Boolean::class.java || field.type == Boolean::class.javaObjectType
                },
            )
        }
    }

    @Test
    fun `parser rejects unbounded malformed duplicate and non-singleton inspect responses`() {
        val fixture = InspectFixture()
        val validImage = rawInspectBytes(fixture.image)
        val validContainer = rawInspectBytes(fixture.container)
        val malformed = listOf(
            "empty image array" to "[]".encodeToByteArray(),
            "multiple image records" to OracleJson.canonicalBytes(JsonArray(listOf(fixture.image, fixture.image))),
            "object image root" to OracleJson.canonicalBytes(fixture.image),
            "non-object image record" to "[0]".encodeToByteArray(),
            "oversized image response" to ByteArray(2 * 1024 * 1024 + 1) { ' '.code.toByte() },
            "duplicate image key" to
                "[{\"Id\":\"$IMAGE_ID\",\"Id\":\"$IMAGE_ID\"}]".encodeToByteArray(),
        )
        malformed.forEach { (label, bytes) ->
            assertFailsWith<LlvmBehaviorHostedContainerV1InspectException>(label) {
                LlvmBehaviorHostedContainerV1Inspect.inspect(bytes, validContainer, fixture.expectation)
            }
        }
        listOf(
            "empty container array" to "[]".encodeToByteArray(),
            "multiple container records" to
                OracleJson.canonicalBytes(JsonArray(listOf(fixture.container, fixture.container))),
            "object container root" to OracleJson.canonicalBytes(fixture.container),
            "oversized container response" to ByteArray(2 * 1024 * 1024 + 1) { ' '.code.toByte() },
        ).forEach { (label, bytes) ->
            assertFailsWith<LlvmBehaviorHostedContainerV1InspectException>(label) {
                LlvmBehaviorHostedContainerV1Inspect.inspect(validImage, bytes, fixture.expectation)
            }
        }
    }

    @Test
    fun `image inspect rejects identity platform rootfs and inherited execution mutations`() {
        val fixture = InspectFixture()
        val config = fixture.image.objectField("Config")
        val rootfs = fixture.image.objectField("RootFS")
        val mutations = listOf(
            "image ID" to fixture.image.withField("Id", JsonPrimitive("sha256:${"9".repeat(64)}")),
            "image OS" to fixture.image.withField("Os", JsonPrimitive("windows")),
            "image architecture" to fixture.image.withField("Architecture", JsonPrimitive("arm64")),
            "image variant" to fixture.image.withField("Variant", JsonPrimitive("v8")),
            "rootfs type" to fixture.image.withField("RootFS", rootfs.withField("Type", JsonPrimitive("layers+foreign"))),
            "duplicate layer" to fixture.image.withField(
                "RootFS",
                rootfs.withField("Layers", JsonArray(listOf(JsonPrimitive(LAYER_ONE), JsonPrimitive(LAYER_ONE)))),
            ),
            "shell entrypoint" to fixture.image.withField(
                "Config",
                config.withField("Entrypoint", stringArray("/bin/sh", "-c", "java -jar worker.jar")),
            ),
            "image command" to fixture.image.withField("Config", config.withField("Cmd", stringArray("--caller-arg"))),
            "loader hook" to fixture.image.withField(
                "Config",
                config.withField("Env", stringArray(PATH_BINDING, "LD_PRELOAD=/inputs/evil.so")),
            ),
            "extra safe-looking environment" to fixture.image.withField(
                "Config",
                config.withField("Env", stringArray(PATH_BINDING, "HOME=/inputs")),
            ),
            "duplicate environment" to fixture.image.withField(
                "Config",
                config.withField("Env", stringArray(PATH_BINDING, "PATH=/tmp")),
            ),
            "inherited image user" to fixture.image.withField("Config", config.withField("User", JsonPrimitive("root"))),
            "inherited working directory" to
                fixture.image.withField("Config", config.withField("WorkingDir", JsonPrimitive("/workspace"))),
            "implicit volume" to fixture.image.withField(
                "Config",
                config.withField("Volumes", JsonObject(mapOf("/workspace" to JsonObject(emptyMap())))),
            ),
            "healthcheck" to fixture.image.withField(
                "Config",
                config.withField("Healthcheck", JsonObject(mapOf("Test" to stringArray("CMD-SHELL", "true")))),
            ),
            "stop signal" to fixture.image.withField("Config", config.withField("StopSignal", JsonPrimitive("SIGKILL"))),
            "stop timeout" to fixture.image.withField("Config", config.withField("StopTimeout", JsonPrimitive(1))),
            "shell wrapper" to fixture.image.withField("Config", config.withField("Shell", stringArray("/bin/sh", "-c"))),
            "on-build hook" to fixture.image.withField("Config", config.withField("OnBuild", stringArray("RUN id"))),
            "unexpected inherited label" to fixture.image.withField(
                "Config",
                config.withField(
                    "Labels",
                    JsonObject(
                        mapOf(
                            "org.opencontainers.image.version" to JsonPrimitive("24.04"),
                            "hook" to JsonPrimitive("unexpected"),
                        ),
                    ),
                ),
            ),
        )

        mutations.forEach { (label, image) -> fixture.assertImageRejected(label, image) }
    }

    @Test
    fun `container inspect rejects identity state launcher environment and implicit config mutations`() {
        val fixture = InspectFixture()
        val state = fixture.container.objectField("State")
        val config = fixture.container.objectField("Config")
        val mutations = listOf(
            "container ID" to fixture.container.withField("Id", JsonPrimitive("8".repeat(64))),
            "container name" to fixture.container.withField("Name", JsonPrimitive("/cross-pair")),
            "container image" to fixture.container.withField("Image", JsonPrimitive("sha256:${"7".repeat(64)}")),
            "missing container platform" to JsonObject(fixture.container - "Platform"),
            "wrong container platform" to fixture.container.withField("Platform", JsonPrimitive("windows")),
            "container path" to fixture.container.withField("Path", JsonPrimitive("/bin/sh")),
            "container args" to fixture.container.withField("Args", stringArray("-c", "exec java")),
            "restart count" to fixture.container.withField("RestartCount", JsonPrimitive(1)),
            "daemon log path" to fixture.container.withField("LogPath", JsonPrimitive("/var/lib/docker/log")),
            "running state" to fixture.container.withField("State", state.withField("Running", JsonPrimitive(true))),
            "wrong status" to fixture.container.withField("State", state.withField("Status", JsonPrimitive("exited"))),
            "nonzero pid" to fixture.container.withField("State", state.withField("Pid", JsonPrimitive(42))),
            "OOM state" to fixture.container.withField("State", state.withField("OOMKilled", JsonPrimitive(true))),
            "started timestamp" to fixture.container.withField(
                "State",
                state.withField("StartedAt", JsonPrimitive("2026-09-01T00:00:00Z")),
            ),
            "exec residue" to fixture.container.withField("ExecIDs", stringArray("exec-id")),
            "health state" to fixture.container.withField(
                "State",
                state.withField("Health", JsonObject(mapOf("Status" to JsonPrimitive("starting")))),
            ),
            "config image cross-pair" to fixture.container.withField(
                "Config",
                config.withField("Image", JsonPrimitive("sha256:${"6".repeat(64)}")),
            ),
            "config command" to fixture.container.withField("Config", config.withField("Cmd", stringArray("arg"))),
            "root user" to fixture.container.withField("Config", config.withField("User", JsonPrimitive("0:0"))),
            "wrong working directory" to
                fixture.container.withField("Config", config.withField("WorkingDir", JsonPrimitive("/work"))),
            "random hostname" to
                fixture.container.withField("Config", config.withField("Hostname", JsonPrimitive("caller-host"))),
            "stdin attachment" to fixture.container.withField(
                "Config",
                config.withField("AttachStdin", JsonPrimitive(true)),
            ),
            "stdout disabled" to fixture.container.withField(
                "Config",
                config.withField("AttachStdout", JsonPrimitive(false)),
            ),
            "container loader hook" to fixture.container.withField(
                "Config",
                config.withField(
                    "Env",
                    stringArray(
                        PATH_BINDING,
                        "LC_ALL=C",
                        "SOURCE_DATE_EPOCH=1779182222",
                        "TZ=UTC",
                        "JAVA_TOOL_OPTIONS=-agentlib:jdwp",
                    ),
                ),
            ),
            "container volume" to fixture.container.withField(
                "Config",
                config.withField("Volumes", JsonObject(mapOf("/var/run" to JsonObject(emptyMap())))),
            ),
            "container healthcheck" to fixture.container.withField(
                "Config",
                config.withField("Healthcheck", JsonObject(mapOf("Test" to stringArray("NONE")))),
            ),
            "missing operation label" to fixture.container.withField(
                "Config",
                config.withField("Labels", fixture.imageLabels()),
            ),
            "cross-paired operation label" to fixture.container.withField(
                "Config",
                config.withField(
                    "Labels",
                    fixture.containerLabels().withField(OPERATION_LABEL, JsonPrimitive("f".repeat(64))),
                ),
            ),
            "container stop timeout" to fixture.container.withField(
                "Config",
                config.withField("StopTimeout", JsonPrimitive(1)),
            ),
        )

        mutations.forEach { (label, container) -> fixture.assertContainerRejected(label, container) }
    }

    @Test
    fun `host config rejects containment-sensitive device logging restart and resource mutations`() {
        val fixture = InspectFixture()
        val host = fixture.container.objectField("HostConfig")
        val restart = host.objectField("RestartPolicy")
        val log = host.objectField("LogConfig")
        val mutations = listOf(
            "writable root" to host.withField("ReadonlyRootfs", JsonPrimitive(false)),
            "bridge network" to host.withField("NetworkMode", JsonPrimitive("bridge")),
            "host IPC" to host.withField("IpcMode", JsonPrimitive("host")),
            "host PID" to host.withField("PidMode", JsonPrimitive("host")),
            "host cgroup" to host.withField("CgroupnsMode", JsonPrimitive("host")),
            "host UTS" to host.withField("UTSMode", JsonPrimitive("host")),
            "host user namespace" to host.withField("UsernsMode", JsonPrimitive("host")),
            "capability not dropped" to host.withField("CapDrop", JsonArray(emptyList())),
            "capability added" to host.withField("CapAdd", stringArray("SYS_ADMIN")),
            "missing builtin seccomp" to host.withField("SecurityOpt", stringArray("no-new-privileges")),
            "privileged" to host.withField("Privileged", JsonPrimitive(true)),
            "device" to host.withField(
                "Devices",
                JsonArray(listOf(JsonObject(mapOf("PathOnHost" to JsonPrimitive("/dev/kvm"))))),
            ),
            "device request" to host.withField(
                "DeviceRequests",
                JsonArray(listOf(JsonObject(mapOf("Driver" to JsonPrimitive("nvidia"))))),
            ),
            "restart policy" to host.withField("RestartPolicy", restart.withField("Name", JsonPrimitive("always"))),
            "retry policy residue" to host.withField(
                "RestartPolicy",
                restart.withField("MaximumRetryCount", JsonPrimitive(1)),
            ),
            "daemon logging" to host.withField("LogConfig", log.withField("Type", JsonPrimitive("json-file"))),
            "log options" to host.withField(
                "LogConfig",
                log.withField("Config", JsonObject(mapOf("max-size" to JsonPrimitive("10m")))),
            ),
            "auto remove" to host.withField("AutoRemove", JsonPrimitive(true)),
            "init process" to host.withField("Init", JsonPrimitive(true)),
            "legacy bind" to host.withField("Binds", stringArray("/:/host:rw")),
            "volumes from" to host.withField("VolumesFrom", stringArray("foreign")),
            "memory" to host.withField("Memory", JsonPrimitive(1)),
            "additional swap" to host.withField("MemorySwap", JsonPrimitive(8L * 1024 * 1024 * 1024)),
            "PID bound" to host.withField("PidsLimit", JsonPrimitive(0)),
            "CPU quota" to host.withField("CpuQuota", JsonPrimitive(0)),
            "CPU period" to host.withField("CpuPeriod", JsonPrimitive(50_000)),
            "shared memory" to host.withField("ShmSize", JsonPrimitive(1024)),
            "OOM protection" to host.withField("OomScoreAdj", JsonPrimitive(-1000)),
            "container annotation" to host.withField(
                "Annotations",
                JsonObject(mapOf("caller" to JsonPrimitive("unreviewed"))),
            ),
            "alternate nano CPU controller" to host.withField("NanoCpus", JsonPrimitive(2_000_000_000)),
            "memory reservation" to host.withField("MemoryReservation", JsonPrimitive(1024)),
            "memory swappiness" to host.withField("MemorySwappiness", JsonPrimitive(100)),
            "unreviewed ulimit" to host.withField(
                "Ulimits",
                JsonArray(
                    listOf(
                        JsonObject(
                            mapOf(
                                "Name" to JsonPrimitive("nofile"),
                                "Soft" to JsonPrimitive(1_000_000),
                                "Hard" to JsonPrimitive(1_000_000),
                            ),
                        ),
                    ),
                ),
            ),
            "wrong nofile ceiling" to host.withField(
                "Ulimits",
                JsonArray(
                    host.arrayField("Ulimits").map { value ->
                        val entry = value as JsonObject
                        if (entry.stringField("Name") == "nofile") {
                            entry.withField("Hard", JsonPrimitive(2048))
                        } else {
                            entry
                        }
                    },
                ),
            ),
            "duplicate ulimit" to host.withField(
                "Ulimits",
                JsonArray(host.arrayField("Ulimits") + host.arrayField("Ulimits").first()),
            ),
            "malformed ulimit" to host.withField(
                "Ulimits",
                JsonArray(
                    host.arrayField("Ulimits").map { value ->
                        val entry = value as JsonObject
                        if (entry.stringField("Name") == "core") {
                            entry.withField("Soft", JsonPrimitive("0"))
                        } else {
                            entry
                        }
                    },
                ),
            ),
            "weakened masked paths" to host.withField("MaskedPaths", stringArray("/proc/kcore")),
            "weakened read-only paths" to host.withField("ReadonlyPaths", JsonArray(emptyList())),
        )

        mutations.forEach { (label, mutatedHost) ->
            fixture.assertContainerRejected(label, fixture.container.withField("HostConfig", mutatedHost))
        }
    }

    @Test
    fun `mount and network mutations cannot escape the fixed five-mount request`() {
        val fixture = InspectFixture()
        val host = fixture.container.objectField("HostConfig")
        val requests = host.arrayField("Mounts")
        val inputRequest = requests[0] as JsonObject
        val stageRequest = requests[1] as JsonObject
        val tmpfs = host.objectField("Tmpfs")
        val runtimeMounts = fixture.container.arrayField("Mounts")
        val runtimeInput = runtimeMounts[0] as JsonObject
        val runtimeStage = runtimeMounts[1] as JsonObject
        val networkSettings = fixture.container.objectField("NetworkSettings")
        val networks = networkSettings.objectField("Networks")
        val noneNetwork = networks.objectField("none")

        val hostMutations = listOf(
            "missing input request" to host.withField("Mounts", JsonArray(listOf(stageRequest))),
            "extra bind request" to host.withField(
                "Mounts",
                JsonArray(
                    requests + JsonObject(
                        mapOf(
                            "Type" to JsonPrimitive("bind"),
                            "Source" to JsonPrimitive("/var/run/docker.sock"),
                            "Target" to JsonPrimitive("/var/run/docker.sock"),
                            "ReadOnly" to JsonPrimitive(false),
                            "BindOptions" to JsonObject(mapOf("Propagation" to JsonPrimitive("rprivate"))),
                        ),
                    ),
                ),
            ),
            "writable inputs" to host.withField(
                "Mounts",
                JsonArray(listOf(inputRequest.withField("ReadOnly", JsonPrimitive(false)), stageRequest)),
            ),
            "read-only stage" to host.withField(
                "Mounts",
                JsonArray(listOf(inputRequest, stageRequest.withField("ReadOnly", JsonPrimitive(true)))),
            ),
            "wrong input source" to host.withField(
                "Mounts",
                JsonArray(listOf(inputRequest.withField("Source", JsonPrimitive("/workspace")), stageRequest)),
            ),
            "shared propagation" to host.withField(
                "Mounts",
                JsonArray(
                    listOf(
                        inputRequest.withField(
                            "BindOptions",
                            inputRequest.objectField("BindOptions").withField("Propagation", JsonPrimitive("rshared")),
                        ),
                        stageRequest,
                    ),
                ),
            ),
            "cluster options on bind" to host.withField(
                "Mounts",
                JsonArray(
                    listOf(
                        inputRequest.withField("ClusterOptions", JsonObject(emptyMap())),
                        stageRequest,
                    ),
                ),
            ),
            "bind request with tmpfs options" to host.withField(
                "Mounts",
                JsonArray(
                    listOf(
                        inputRequest.withField(
                            "TmpfsOptions",
                            JsonObject(mapOf("SizeBytes" to JsonPrimitive(1024))),
                        ),
                        stageRequest,
                    ),
                ),
            ),
            "missing work tmpfs" to host.withField("Tmpfs", JsonObject(tmpfs - "/work")),
            "extra tmpfs" to host.withField("Tmpfs", JsonObject(tmpfs + ("/run" to JsonPrimitive("rw")))),
            "work noexec" to host.withField(
                "Tmpfs",
                tmpfs.withField("/work", JsonPrimitive(tmpfs.stringField("/work").replace(",exec,", ",noexec,"))),
            ),
            "work too small" to host.withField(
                "Tmpfs",
                tmpfs.withField("/work", JsonPrimitive(tmpfs.stringField("/work").replace("17179869184", "2147483648"))),
            ),
            "tmp executable" to host.withField(
                "Tmpfs",
                tmpfs.withField("/tmp", JsonPrimitive(tmpfs.stringField("/tmp").replace("noexec", "exec"))),
            ),
            "JNA noexec" to host.withField(
                "Tmpfs",
                tmpfs.withField("/decomp-jna", JsonPrimitive(tmpfs.stringField("/decomp-jna").replace("exec", "noexec"))),
            ),
            "duplicate tmpfs option" to host.withField(
                "Tmpfs",
                tmpfs.withField("/tmp", JsonPrimitive(tmpfs.stringField("/tmp") + ",nodev")),
            ),
        )
        hostMutations.forEach { (label, mutatedHost) ->
            fixture.assertContainerRejected(label, fixture.container.withField("HostConfig", mutatedHost))
        }

        listOf(
            "missing resolved input" to JsonArray(listOf(runtimeStage)),
            "extra resolved tmpfs" to JsonArray(
                runtimeMounts + JsonObject(
                    mapOf(
                        "Type" to JsonPrimitive("tmpfs"),
                        "Source" to JsonPrimitive(""),
                        "Destination" to JsonPrimitive("/tmp"),
                        "Mode" to JsonPrimitive(""),
                        "RW" to JsonPrimitive(true),
                        "Propagation" to JsonPrimitive(""),
                    ),
                ),
            ),
            "resolved input writable" to
                JsonArray(listOf(runtimeInput.withField("RW", JsonPrimitive(true)), runtimeStage)),
            "resolved input mode" to
                JsonArray(listOf(runtimeInput.withField("Mode", JsonPrimitive("ro")), runtimeStage)),
            "resolved stage source" to JsonArray(
                listOf(runtimeInput, runtimeStage.withField("Source", JsonPrimitive("/tmp/cross-pair"))),
            ),
        ).forEach { (label, mounts) ->
            fixture.assertContainerRejected(label, fixture.container.withField("Mounts", mounts))
        }

        listOf(
            "bridge network record" to networkSettings.withField(
                "Networks",
                JsonObject(mapOf("bridge" to noneNetwork)),
            ),
            "assigned endpoint" to networkSettings.withField(
                "Networks",
                JsonObject(
                    mapOf("none" to noneNetwork.withField("EndpointID", JsonPrimitive("endpoint"))),
                ),
            ),
            "published port" to networkSettings.withField(
                "Ports",
                JsonObject(mapOf("80/tcp" to JsonArray(emptyList()))),
            ),
            "network sandbox ID" to networkSettings.withField("SandboxID", JsonPrimitive("sandbox-id")),
            "network sandbox key" to networkSettings.withField("SandboxKey", JsonPrimitive("/var/run/netns/worker")),
            "none network IPAM" to networkSettings.withField(
                "Networks",
                JsonObject(
                    mapOf(
                        "none" to noneNetwork.withField(
                            "IPAMConfig",
                            JsonObject(mapOf("IPv4Address" to JsonPrimitive("127.0.0.2"))),
                        ),
                    ),
                ),
            ),
        ).forEach { (label, settings) ->
            fixture.assertContainerRejected(label, fixture.container.withField("NetworkSettings", settings))
        }
    }

    @Test
    fun `expectation rejects malformed identities root users and ambiguous bind paths`() {
        fun invalid(
            imageId: String = IMAGE_ID,
            containerId: String = CONTAINER_ID,
            name: String = CONTAINER_NAME,
            uid: Int = 1001,
            gid: Int = 1002,
            inputs: Path = INPUTS_SOURCE,
            stage: Path = STAGE_SOURCE,
        ) {
            assertFailsWith<LlvmBehaviorHostedContainerV1InspectException> {
                LlvmBehaviorHostedContainerV1Expectation(imageId, containerId, name, uid, gid, inputs, stage)
            }
        }

        invalid(imageId = "latest")
        invalid(containerId = "short")
        invalid(name = "/caller/name")
        invalid(name = "safe-looking-caller-name")
        invalid(uid = 0)
        invalid(gid = 0)
        invalid(inputs = Path.of("relative"))
        invalid(inputs = Path.of("/var/lib/decomp/../escape"))
        invalid(inputs = Path.of("/var/lib/decomp/unsafe,mount"))
        invalid(inputs = Path.of("/var/lib/decomp/unsafe mount"))
        invalid(inputs = INPUTS_SOURCE, stage = INPUTS_SOURCE)
    }
}

private class InspectFixture {
    val expectation = LlvmBehaviorHostedContainerV1Expectation(
        imageId = IMAGE_ID,
        containerId = CONTAINER_ID,
        containerName = CONTAINER_NAME,
        uid = 1001,
        gid = 1002,
        inputsSource = INPUTS_SOURCE,
        stageOutputSource = STAGE_SOURCE,
    )

    val image: JsonObject = JsonObject(
        mapOf(
            "Id" to JsonPrimitive(IMAGE_ID),
            "Os" to JsonPrimitive("linux"),
            "Architecture" to JsonPrimitive("amd64"),
            "Variant" to JsonPrimitive(""),
            "RootFS" to JsonObject(
                mapOf(
                    "Type" to JsonPrimitive("layers"),
                    "Layers" to stringArray(LAYER_ONE, LAYER_TWO),
                ),
            ),
            "Config" to imageConfig(),
        ),
    )

    val container: JsonObject = JsonObject(
        mapOf(
            "Id" to JsonPrimitive(CONTAINER_ID),
            "Name" to JsonPrimitive("/$CONTAINER_NAME"),
            "Image" to JsonPrimitive(IMAGE_ID),
            "Path" to JsonPrimitive(ENTRYPOINT.first()),
            "Args" to JsonArray(ENTRYPOINT.drop(1).map(::JsonPrimitive)),
            "RestartCount" to JsonPrimitive(0),
            "Platform" to JsonPrimitive("linux"),
            "LogPath" to JsonPrimitive(""),
            "ExecIDs" to JsonNull,
            "State" to createdState(),
            "Config" to containerConfig(),
            "HostConfig" to hostConfig(),
            "Mounts" to runtimeMounts(),
            "NetworkSettings" to networkSettings(),
        ),
    )

    fun assertImageRejected(label: String, mutatedImage: JsonObject) {
        assertFailsWith<LlvmBehaviorHostedContainerV1InspectException>(label) {
            LlvmBehaviorHostedContainerV1Inspect.inspect(
                rawInspectBytes(mutatedImage),
                rawInspectBytes(container),
                expectation,
            )
        }
    }

    fun assertContainerRejected(label: String, mutatedContainer: JsonObject) {
        assertFailsWith<LlvmBehaviorHostedContainerV1InspectException>(label) {
            LlvmBehaviorHostedContainerV1Inspect.inspect(
                rawInspectBytes(image),
                rawInspectBytes(mutatedContainer),
                expectation,
            )
        }
    }

    private fun imageConfig(): JsonObject = JsonObject(
        mapOf(
            "Entrypoint" to JsonArray(ENTRYPOINT.map(::JsonPrimitive)),
            "Cmd" to JsonNull,
            "Env" to stringArray(PATH_BINDING),
            "User" to JsonPrimitive(""),
            "WorkingDir" to JsonPrimitive(""),
            "Volumes" to JsonNull,
            "Healthcheck" to JsonNull,
            "StopSignal" to JsonPrimitive(""),
            "Shell" to JsonNull,
            "OnBuild" to JsonNull,
            "ExposedPorts" to JsonNull,
            "Labels" to imageLabels(),
            "Hostname" to JsonPrimitive(""),
            "Domainname" to JsonPrimitive(""),
            "Image" to JsonPrimitive(""),
            "AttachStdin" to JsonPrimitive(false),
            "AttachStdout" to JsonPrimitive(false),
            "AttachStderr" to JsonPrimitive(false),
            "Tty" to JsonPrimitive(false),
            "OpenStdin" to JsonPrimitive(false),
            "StdinOnce" to JsonPrimitive(false),
            "ArgsEscaped" to JsonPrimitive(false),
        ),
    )

    private fun createdState(): JsonObject = JsonObject(
        mapOf(
            "Status" to JsonPrimitive("created"),
            "Running" to JsonPrimitive(false),
            "Paused" to JsonPrimitive(false),
            "Restarting" to JsonPrimitive(false),
            "OOMKilled" to JsonPrimitive(false),
            "Dead" to JsonPrimitive(false),
            "Pid" to JsonPrimitive(0),
            "ExitCode" to JsonPrimitive(0),
            "Error" to JsonPrimitive(""),
            "StartedAt" to JsonPrimitive(ZERO_TIMESTAMP),
            "FinishedAt" to JsonPrimitive(ZERO_TIMESTAMP),
            "Health" to JsonNull,
            "RemovalInProgress" to JsonPrimitive(false),
        ),
    )

    private fun containerConfig(): JsonObject = JsonObject(
        mapOf(
            "Image" to JsonPrimitive(IMAGE_ID),
            "Entrypoint" to JsonArray(ENTRYPOINT.map(::JsonPrimitive)),
            "Cmd" to JsonArray(emptyList()),
            "Env" to stringArray(
                "TZ=UTC",
                PATH_BINDING,
                "SOURCE_DATE_EPOCH=1779182222",
                "LC_ALL=C",
            ),
            "User" to JsonPrimitive("1001:1002"),
            "WorkingDir" to JsonPrimitive("/"),
            "Hostname" to JsonPrimitive("llvm-hosted-build"),
            "Domainname" to JsonPrimitive(""),
            "AttachStdin" to JsonPrimitive(false),
            "AttachStdout" to JsonPrimitive(true),
            "AttachStderr" to JsonPrimitive(true),
            "Tty" to JsonPrimitive(false),
            "OpenStdin" to JsonPrimitive(false),
            "StdinOnce" to JsonPrimitive(false),
            "Volumes" to JsonNull,
            "Healthcheck" to JsonNull,
            "ExposedPorts" to JsonNull,
            "Labels" to containerLabels(),
            "Shell" to JsonNull,
            "OnBuild" to JsonNull,
            "StopSignal" to JsonPrimitive(""),
            "ArgsEscaped" to JsonPrimitive(false),
            "NetworkDisabled" to JsonPrimitive(false),
            "MacAddress" to JsonPrimitive(""),
        ),
    )

    private fun hostConfig(): JsonObject = JsonObject(
        buildMap {
            put("NetworkMode", JsonPrimitive("none"))
            put("IpcMode", JsonPrimitive("private"))
            put("CgroupnsMode", JsonPrimitive("private"))
            put("PidMode", JsonPrimitive(""))
            put("UTSMode", JsonPrimitive(""))
            put("UsernsMode", JsonPrimitive(""))
            put("CgroupParent", JsonPrimitive(""))
            put("Cgroup", JsonPrimitive(""))
            put("ContainerIDFile", JsonPrimitive(""))
            put("VolumeDriver", JsonPrimitive(""))
            put("Isolation", JsonPrimitive(""))
            put("Runtime", JsonPrimitive("runc"))
            put("ReadonlyRootfs", JsonPrimitive(true))
            put("Privileged", JsonPrimitive(false))
            put("PublishAllPorts", JsonPrimitive(false))
            put("AutoRemove", JsonPrimitive(false))
            put("Init", JsonPrimitive(false))
            put("CapDrop", stringArray("ALL"))
            put("CapAdd", JsonNull)
            put("SecurityOpt", stringArray("no-new-privileges", "seccomp=builtin"))
            put("Binds", JsonNull)
            put("VolumesFrom", JsonNull)
            put("Devices", JsonArray(emptyList()))
            put("DeviceCgroupRules", JsonNull)
            put("DeviceRequests", JsonNull)
            put(
                "Ulimits",
                JsonArray(
                    listOf(
                        ulimit("nofile", 1024),
                        ulimit("core", 0),
                        ulimit("fsize", 2_147_483_648L),
                    ),
                ),
            )
            put("Memory", JsonPrimitive(4L * 1024L * 1024L * 1024L))
            put("MemorySwap", JsonPrimitive(4L * 1024L * 1024L * 1024L))
            put("PidsLimit", JsonPrimitive(512))
            put("CpuQuota", JsonPrimitive(200_000))
            put("CpuPeriod", JsonPrimitive(100_000))
            put("ShmSize", JsonPrimitive(64L * 1024L * 1024L))
            put("OomScoreAdj", JsonPrimitive(0))
            put("OomKillDisable", JsonNull)
            listOf(
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
            ).forEach { put(it, JsonPrimitive(0)) }
            put("CpusetCpus", JsonPrimitive(""))
            put("CpusetMems", JsonPrimitive(""))
            listOf(
                "BlkioWeightDevice",
                "BlkioDeviceReadBps",
                "BlkioDeviceWriteBps",
                "BlkioDeviceReadIOps",
                "BlkioDeviceWriteIOps",
            ).forEach { put(it, JsonArray(emptyList())) }
            put("MemorySwappiness", JsonNull)
            put(
                "RestartPolicy",
                JsonObject(
                    mapOf(
                        "Name" to JsonPrimitive("no"),
                        "MaximumRetryCount" to JsonPrimitive(0),
                    ),
                ),
            )
            put(
                "LogConfig",
                JsonObject(
                    mapOf(
                        "Type" to JsonPrimitive("none"),
                        "Config" to JsonObject(emptyMap()),
                    ),
                ),
            )
            put("Dns", JsonNull)
            put("DnsOptions", JsonArray(emptyList()))
            put("DnsSearch", JsonArray(emptyList()))
            put("ExtraHosts", JsonNull)
            put("GroupAdd", JsonNull)
            put("Links", JsonNull)
            put("PortBindings", JsonObject(emptyMap()))
            put("StorageOpt", JsonNull)
            put("Sysctls", JsonNull)
            put("Annotations", JsonObject(emptyMap()))
            put("ConsoleSize", JsonArray(listOf(JsonPrimitive(0), JsonPrimitive(0))))
            put(
                "MaskedPaths",
                stringArray("/sys/firmware", "/proc/timer_list", "/proc/keys", "/proc/kcore", "/proc/interrupts"),
            )
            put("ReadonlyPaths", stringArray("/proc/sysrq-trigger", "/proc/sys"))
            put("Mounts", requestedBinds())
            put("Tmpfs", tmpfs())
        },
    )

    private fun requestedBinds(): JsonArray = JsonArray(
        listOf(
            JsonObject(
                mapOf(
                    "Type" to JsonPrimitive("bind"),
                    "Source" to JsonPrimitive(INPUTS_SOURCE.toString()),
                    "Target" to JsonPrimitive("/inputs"),
                    "ReadOnly" to JsonPrimitive(true),
                    "Consistency" to JsonPrimitive(""),
                    "BindOptions" to JsonObject(
                        mapOf(
                            "Propagation" to JsonPrimitive("rprivate"),
                            "NonRecursive" to JsonPrimitive(false),
                        ),
                    ),
                ),
            ),
            JsonObject(
                mapOf(
                    "Type" to JsonPrimitive("bind"),
                    "Source" to JsonPrimitive(STAGE_SOURCE.toString()),
                    "Target" to JsonPrimitive("/stage-output"),
                    "Consistency" to JsonPrimitive(""),
                    "BindOptions" to JsonObject(
                        mapOf(
                            "Propagation" to JsonPrimitive("rprivate"),
                            "NonRecursive" to JsonPrimitive(false),
                        ),
                    ),
                ),
            ),
        ),
    )

    private fun tmpfs(): JsonObject = JsonObject(
        mapOf(
            "/work" to JsonPrimitive(
                "gid=1002,nr_inodes=1000000,exec,size=17179869184,nodev,uid=1001,rw,mode=0700,nosuid",
            ),
            "/tmp" to JsonPrimitive("mode=1777,noexec,nr_inodes=4096,nodev,size=268435456,nosuid,rw"),
            "/decomp-jna" to JsonPrimitive(
                "exec,nosuid,size=16777216,gid=1002,nodev,nr_inodes=128,rw,uid=1001,mode=0700",
            ),
        ),
    )

    private fun runtimeMounts(): JsonArray = JsonArray(
        listOf(
            JsonObject(
                mapOf(
                    "Type" to JsonPrimitive("bind"),
                    "Name" to JsonPrimitive(""),
                    "Source" to JsonPrimitive(INPUTS_SOURCE.toString()),
                    "Destination" to JsonPrimitive("/inputs"),
                    "Driver" to JsonPrimitive(""),
                    "Mode" to JsonPrimitive(""),
                    "RW" to JsonPrimitive(false),
                    "Propagation" to JsonPrimitive("rprivate"),
                ),
            ),
            JsonObject(
                mapOf(
                    "Type" to JsonPrimitive("bind"),
                    "Name" to JsonPrimitive(""),
                    "Source" to JsonPrimitive(STAGE_SOURCE.toString()),
                    "Destination" to JsonPrimitive("/stage-output"),
                    "Driver" to JsonPrimitive(""),
                    "Mode" to JsonPrimitive(""),
                    "RW" to JsonPrimitive(true),
                    "Propagation" to JsonPrimitive("rprivate"),
                ),
            ),
        ),
    )

    private fun networkSettings(): JsonObject = JsonObject(
        mapOf(
            "SandboxID" to JsonPrimitive(""),
            "SandboxKey" to JsonPrimitive(""),
            "Ports" to JsonNull,
            "Networks" to JsonObject(
                mapOf(
                    "none" to JsonObject(
                        mapOf(
                            "NetworkID" to JsonPrimitive(""),
                            "EndpointID" to JsonPrimitive(""),
                            "Gateway" to JsonPrimitive(""),
                            "IPAddress" to JsonPrimitive(""),
                            "MacAddress" to JsonPrimitive(""),
                            "IPv6Gateway" to JsonPrimitive(""),
                            "GlobalIPv6Address" to JsonPrimitive(""),
                            "IPPrefixLen" to JsonPrimitive(0),
                            "GlobalIPv6PrefixLen" to JsonPrimitive(0),
                            "Aliases" to JsonNull,
                            "Links" to JsonNull,
                            "DNSNames" to JsonNull,
                            "IPAMConfig" to JsonNull,
                            "DriverOpts" to JsonNull,
                            "GwPriority" to JsonPrimitive(0),
                        ),
                    ),
                ),
            ),
        ),
    )

    fun imageLabels(): JsonObject = JsonObject(
        mapOf("org.opencontainers.image.version" to JsonPrimitive("24.04")),
    )

    fun containerLabels(): JsonObject = JsonObject(
        imageLabels() + (OPERATION_LABEL to JsonPrimitive(OPERATION_ID)),
    )

    private fun ulimit(name: String, ceiling: Long): JsonObject = JsonObject(
        mapOf(
            "Name" to JsonPrimitive(name),
            "Soft" to JsonPrimitive(ceiling),
            "Hard" to JsonPrimitive(ceiling),
        ),
    )
}

private fun rawInspectBytes(record: JsonObject): ByteArray {
    val canonical = OracleJson.canonicalBytes(JsonArray(listOf(record))).decodeToString()
    return " \n$canonical\n ".encodeToByteArray()
}

private fun stringArray(vararg values: String): JsonArray = JsonArray(values.map(::JsonPrimitive))

private fun JsonObject.objectField(name: String): JsonObject = getValue(name) as JsonObject

private fun JsonObject.arrayField(name: String): JsonArray = getValue(name) as JsonArray

private fun JsonObject.stringField(name: String): String = (getValue(name) as JsonPrimitive).content

private fun JsonObject.withField(name: String, value: JsonElement): JsonObject =
    JsonObject(toMutableMap().apply { this[name] = value })

private const val IMAGE_ID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
private const val CONTAINER_ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
private const val OPERATION_ID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
private const val CONTAINER_NAME = "decomp-llvm-behavior-v1-$OPERATION_ID"
private const val OPERATION_LABEL = "dev.decompengine.llvm-behavior-hosted-operation"
private const val LAYER_ONE = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
private const val LAYER_TWO = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
private const val ZERO_TIMESTAMP = "0001-01-01T00:00:00Z"
private const val PATH_BINDING = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
private val INPUTS_SOURCE = Path.of("/var/lib/decomp/operations/op-0123456789abcdef/inputs")
private val STAGE_SOURCE = Path.of("/var/lib/decomp/operations/op-0123456789abcdef/stage-output")
private val ENTRYPOINT = listOf(
    "/decomp-jdk/bin/java",
    "-Djna.nosys=true",
    "-Djna.tmpdir=/decomp-jna",
    "-cp",
    "/decomp-app/lib/*",
    "decompengine.oracle.behavior.LlvmBehaviorHostedCleanBuildV2InnerWorkerMain",
)
