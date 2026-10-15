package decompengine.oracle.behavior

import decompengine.analysis.AnalysisDeadline
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.lang.reflect.InvocationTargetException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/** Actual child-kernel controls; these listeners are not authenticated Docker daemons. */
class LlvmBehaviorNativeRuntimeListenerContinuityV3Test {
    @Test
    fun `strict listener retains one actual child across five requests and final check`() {
        ListenerContinuityFixture().use { fixture ->
            fixture.start()
            fixture.image().use { image ->
                val deadline = listenerDeadline()
                fixture.bindings(deadline).use { binding ->
                    val facts = listenerMeasurement(binding, image, deadline)
                    fixture.awaitEvent("five-completed")
                    listenerTerminal(binding, deadline)
                    assertEquals(fixture.expectedRequests(), fixture.requests())
                    val observed = assertNotNull(facts["observedListenerContinuity"] as? JsonObject)
                    assertEquals(setOf("schemaVersion", "identityKind", "pid", "uid", "gid", "identifierNamespace",
                        "peerHandleMechanism", "fixedExchangeCount", "sameListenerSnapshot", "retentionBoundary",
                        "daemonExecutableApproved", "httpResponderIdentityProved"), observed.keys)
                    assertEquals(JsonPrimitive(1), observed["schemaVersion"])
                    assertEquals(JsonPrimitive("linux-af-unix-listener-credential-snapshot"), observed["identityKind"])
                    assertEquals(JsonPrimitive(fixture.pid), observed["pid"])
                    assertEquals(JsonPrimitive(fixture.uid), observed["uid"])
                    assertEquals(JsonPrimitive(fixture.gid), observed["gid"])
                    assertEquals(JsonPrimitive("observer"), observed["identifierNamespace"])
                    assertEquals(JsonPrimitive("SO_PEERPIDFD"), observed["peerHandleMechanism"])
                    assertEquals(JsonPrimitive(5), observed["fixedExchangeCount"])
                    assertEquals(JsonPrimitive(true), observed["sameListenerSnapshot"])
                    assertEquals(JsonPrimitive("final-factory-guard"), observed["retentionBoundary"])
                    assertEquals(JsonPrimitive(false), observed["daemonExecutableApproved"])
                    assertEquals(JsonPrimitive(false), observed["httpResponderIdentityProved"])
                    assertFalse(observed.keys.any { it.contains("fd", ignoreCase = true) })
                    val responsePids = fixture.events().filter { it["kind"] == JsonPrimitive("request") }
                        .map { it.getValue("pid").jsonPrimitive.long }.toSet()
                    assertEquals(setOf(fixture.pid), responsePids)
                    assertTrue(fixture.isAlive())
                }
            }
        }
    }

    @Test
    fun `inherited same listener relisten changes actual peer before any GET bytes`() {
        ListenerContinuityFixture("handoff").use { fixture ->
            fixture.start()
            fixture.image().use { image ->
                val deadline = listenerDeadline()
                fixture.bindings(deadline).use { binding ->
                    val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> {
                        listenerMeasurement(binding, image, deadline)
                    }
                    assertTrue(failure.message.orEmpty().contains("listener", ignoreCase = true), failure.message)
                    val original = fixture.awaitEvent("ready")
                    val handoff = fixture.awaitEvent("handoff")
                    val refused = fixture.awaitEvent("eof-before-request")
                    assertEquals(original["dev"], handoff["dev"])
                    assertEquals(original["ino"], handoff["ino"])
                    assertEquals(JsonPrimitive(fixture.pid), handoff["parent"])
                    assertTrue(handoff.getValue("pid").jsonPrimitive.long != fixture.pid)
                    assertTrue(fixture.isAlive(), "original listener A must still be alive during refusal")
                    assertEquals(JsonPrimitive(1), refused["number"])
                    assertEquals(JsonPrimitive(0), refused["bytes"])
                    assertEquals(listOf("HEAD /_ping"), fixture.requests())
                }
            }
        }
    }

    @Test
    fun `listener exit after five replies refuses final publication guard`() {
        ListenerContinuityFixture().use { fixture ->
            fixture.start()
            fixture.image().use { image ->
                val deadline = listenerDeadline()
                fixture.bindings(deadline).use { binding ->
                    listenerMeasurement(binding, image, deadline)
                    fixture.awaitEvent("five-completed")
                    fixture.stopAndAwaitExit()
                    val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> {
                        listenerTerminal(binding, deadline)
                    }
                    assertTrue(failure.message.orEmpty().contains("listener", ignoreCase = true), failure.message)
                    assertEquals(fixture.expectedRequests(), fixture.requests())
                }
            }
        }
    }

    @Test
    fun `stalled real child HEAD preserves deadline and closes owned client descriptor`() {
        ListenerContinuityFixture("stall-head").use { fixture ->
            fixture.start()
            fixture.image().use { image ->
                val deadline = listenerDeadline(250)
                val binding = fixture.bindings(deadline)
                val executableDescriptor = binding.executableDescriptorPath
                val started = System.nanoTime()
                binding.use {
                    assertFails { listenerMeasurement(binding, image, deadline) }
                }
                assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) < 2500)
                fixture.awaitEvent("stalled-client-closed")
                assertEquals(listOf("HEAD /_ping"), fixture.requests())
                assertFalse(Files.exists(executableDescriptor))
            }
        }
    }

    @Test
    fun `full actual Unix backlog expires original deadline without any HEAD bytes`() {
        val before = openPidfds()
        ListenerContinuityFixture("backlog-stall").use { fixture ->
            fixture.start()
            val backlog = fixture.awaitEvent("backlog-filled")
            assertEquals(JsonPrimitive(2), backlog["queued"])
            assertEquals(JsonPrimitive(11), backlog["connectErrno"])
            fixture.image().use { image ->
                val deadline = listenerDeadline(250)
                val binding = fixture.bindings(deadline)
                val executableDescriptor = binding.executableDescriptorPath
                val started = System.nanoTime()
                binding.use {
                    val failure = assertFails { listenerMeasurement(binding, image, deadline) }
                    assertTrue(failure.message.orEmpty().contains("exceeded"), failure.message)
                    assertTrue(failure.message.orEmpty().contains("connect"), failure.message)
                }
                assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) < 2500)
                assertTrue(fixture.requests().isEmpty())
                assertTrue(fixture.events().none { it["kind"] == JsonPrimitive("accepted") })
                assertTrue(fixture.isAlive(), "backlog timeout must not signal the peer")
                assertFalse(Files.exists(executableDescriptor))
            }
        }
        assertEquals(before, openPidfds(), "backlog refusal must release all client pidfd ownership")
    }

    @Test
    fun `interrupt during actual stalled HEAD read closes client without signalling peer`() {
        val before = openPidfds()
        ListenerContinuityFixture("stall-head").use { fixture ->
            fixture.start()
            fixture.image().use { image ->
                val deadline = listenerDeadline()
                val binding = fixture.bindings(deadline)
                val executableDescriptor = binding.executableDescriptorPath
                binding.use {
                    val failure = AtomicReference<Throwable>()
                    val worker = Thread {
                        try {
                            listenerMeasurement(binding, image, deadline)
                            failure.set(AssertionError("stalled measurement returned before cancellation"))
                        } catch (caught: Throwable) {
                            failure.set(caught)
                        }
                    }.apply { isDaemon = true; name = "unscored-listener-read-cancellation"; start() }
                    try {
                        val request = fixture.awaitEvent("request")
                        assertEquals(JsonPrimitive("HEAD /_ping"), request["request"])
                        worker.interrupt()
                        worker.join(3000)
                        assertFalse(worker.isAlive, "cancelled in-flight listener read must finish within three seconds")
                        assertTrue(failure.get() is InterruptedException, failure.get()?.toString())
                        fixture.awaitEvent("stalled-client-closed")
                        assertEquals(listOf("HEAD /_ping"), fixture.requests())
                        assertTrue(fixture.isAlive(), "caller interruption must not signal the peer")
                    } finally {
                        if (worker.isAlive) {
                            worker.interrupt()
                            worker.join(3000)
                        }
                        assertFalse(worker.isAlive, "test must retain no measurement worker")
                    }
                }
                assertFalse(Files.exists(executableDescriptor))
            }
        }
        assertEquals(before, openPidfds(), "cancelled read must release all listener pidfd ownership")
    }

    @Test
    fun `completed listener terminal check respects original caller cancellation`() {
        ListenerContinuityFixture().use { fixture ->
            fixture.start()
            fixture.image().use { image ->
                val deadline = listenerDeadline()
                fixture.bindings(deadline).use { binding ->
                    listenerMeasurement(binding, image, deadline)
                    fixture.awaitEvent("five-completed")
                    try {
                        Thread.currentThread().interrupt()
                        assertFailsWith<InterruptedException> { listenerTerminal(binding, deadline) }
                    } finally {
                        Thread.interrupted()
                    }
                    assertEquals(fixture.expectedRequests(), fixture.requests())
                }
            }
        }
    }

    @Test
    fun `completed listener terminal check uses the original elapsed deadline`() {
        ListenerContinuityFixture().use { fixture ->
            fixture.start()
            fixture.image().use { image ->
                val deadline = listenerDeadline(1000)
                fixture.bindings(deadline).use { binding ->
                    listenerMeasurement(binding, image, deadline)
                    fixture.awaitEvent("five-completed")
                    Thread.sleep(1050)
                    assertFails { listenerTerminal(binding, deadline) }
                    assertEquals(fixture.expectedRequests(), fixture.requests())
                }
            }
        }
    }

    @Test
    fun `repeated real inherited listener refusal releases every owned pidfd`() {
        val before = openPidfds()
        repeat(3) {
            ListenerContinuityFixture("handoff").use { fixture ->
                fixture.start()
                fixture.image().use { image ->
                    val deadline = listenerDeadline()
                    fixture.bindings(deadline).use { binding ->
                        assertFailsWith<PinnedDockerRuntimeBindingsException> {
                            listenerMeasurement(binding, image, deadline)
                        }
                        fixture.awaitEvent("eof-before-request")
                    }
                }
            }
            assertEquals(before, openPidfds(), "refused continuity must not retain pidfd ownership")
        }
    }

    @Test
    fun `strict child transport retains duplicate header and trailing body refusal`() {
        listOf("duplicate-header", "trailing-body").forEach { mode ->
            ListenerContinuityFixture(mode).use { fixture ->
                fixture.start()
                fixture.image().use { image ->
                    val deadline = listenerDeadline()
                    fixture.bindings(deadline).use { binding ->
                        assertFails(mode) { listenerMeasurement(binding, image, deadline) }
                        assertEquals(listOf("HEAD /_ping", "GET /version"), fixture.requests())
                    }
                }
            }
        }
    }
}

private fun listenerDeadline(millis: Long = 5000): AnalysisDeadline =
    AnalysisDeadline.start(TimeUnit.MILLISECONDS.toNanos(millis), "actual child listener continuity control")

private fun listenerMeasurement(
    binding: PinnedDockerRuntimeBindings,
    image: LlvmBehaviorNativeOciImageV2.MeasuredImage,
    deadline: AnalysisDeadline,
): JsonObject = listenerInvoke("measureNativeRuntimeV2", binding, image, deadline) as JsonObject

private fun listenerTerminal(binding: PinnedDockerRuntimeBindings, deadline: AnalysisDeadline) {
    listenerInvoke("verifyNativeRuntimeV2Terminal", binding, deadline)
}

private fun listenerInvoke(name: String, vararg args: Any): Any? {
    val bridge = PinnedDockerRuntimeBindings.Companion::class.java.declaredMethods.single { it.name == name }
    assertTrue(bridge.trySetAccessible())
    return try {
        bridge.invoke(PinnedDockerRuntimeBindings.Companion, *args)
    } catch (failure: InvocationTargetException) {
        throw failure.targetException
    }
}

private fun openPidfds(): Int = Files.list(Path.of("/proc/self/fd")).use { entries ->
    entries.filter { descriptor ->
        runCatching { Files.readSymbolicLink(descriptor).toString() == "anon_inode:[pidfd]" }.getOrDefault(false)
    }.count().toInt()
}

private class ListenerContinuityFixture(private val mode: String = "good") : AutoCloseable {
    private val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/nrm")), "v")
        .toAbsolutePath().normalize()
    private val client = root.resolve("client")
    private val config = root.resolve("config")
    private val socket = root.resolve("r/s")
    private val layout = root.resolve("oci")
    private val exportRoot = root.resolve("export")
    private val payload = root.resolve("payload")
    private var process: Process? = null
    private val configSha: String
    private val layerSha: String
    val pid: Long get() = checkNotNull(process).pid()
    val uid: Long get() = (Files.getAttribute(root, "unix:uid") as Number).toLong()
    val gid: Long get() = (Files.getAttribute(root, "unix:gid") as Number).toLong()

    init {
        listOf(root, config, socket.parent, layout, exportRoot, payload, root.resolve("home"), root.resolve("tmp"),
            root.resolve("cache")).forEach {
            Files.createDirectories(it)
            Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
        }
        Files.writeString(client, "unscored strict listener fixture client\n")
        Files.setPosixFilePermissions(client, PosixFilePermissions.fromString("r-x------"))
        Files.createDirectories(payload.resolve("bin"))
        Files.writeString(payload.resolve("bin/tool"), "retained listener control namespace\n")
        val layerPath = root.resolve("layer.tar")
        tar(layerPath, payload, listOf("bin"))
        val layer = Files.readAllBytes(layerPath)
        layerSha = OracleArtifacts.sha256(layer)
        val configBytes = ("{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{\"type\":\"layers\"," +
            "\"diff_ids\":[\"sha256:$layerSha\"]}}").encodeToByteArray()
        configSha = OracleArtifacts.sha256(configBytes)
        val manifest = ("{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\"," +
            "\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"sha256:$configSha\"," +
            "\"size\":${configBytes.size}},\"layers\":[{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar\"," +
            "\"digest\":\"sha256:$layerSha\",\"size\":${layer.size}}]}").encodeToByteArray()
        val manifestSha = OracleArtifacts.sha256(manifest)
        listOf(layout, exportRoot).forEach { destination ->
            Files.createDirectories(destination.resolve("blobs/sha256"))
            Files.write(destination.resolve("blobs/sha256/$layerSha"), layer)
            Files.write(destination.resolve("blobs/sha256/$configSha"), configBytes)
            Files.write(destination.resolve("blobs/sha256/$manifestSha"), manifest)
            Files.writeString(destination.resolve("oci-layout"), "{\"imageLayoutVersion\":\"1.0.0\"}")
            Files.writeString(destination.resolve("index.json"), "{\"schemaVersion\":2,\"manifests\":[{" +
                "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:$manifestSha\"," +
                "\"size\":${manifest.size}}]}")
        }
        Files.writeString(exportRoot.resolve("manifest.json"), "[{\"Config\":\"blobs/sha256/$configSha\"," +
            "\"RepoTags\":null,\"Layers\":[\"blobs/sha256/$layerSha\"]}]")
        tar(root.resolve("export.tar"), exportRoot, listOf("oci-layout", "index.json", "manifest.json", "blobs"))
    }

    fun start() {
        val resource = Path.of("src/test/resources/nativecalls/native-runtime-listener-v3.py").toAbsolutePath()
        val builder = ProcessBuilder("python3", "-B", resource.toString(), root.toString(), mode, configSha, layerSha)
            .redirectErrorStream(true).redirectOutput(root.resolve("child.log").toFile())
        builder.environment().apply {
            put("PYTHONDONTWRITEBYTECODE", "1")
            put("HOME", root.resolve("home").toString())
            put("XDG_CACHE_HOME", root.resolve("cache").toString())
            put("TMPDIR", root.resolve("tmp").toString())
        }
        process = builder.start()
        val ready = awaitEvent("ready")
        assertEquals(JsonPrimitive(pid), ready["pid"])
    }

    fun image(): LlvmBehaviorNativeOciImageV2.MeasuredImage = LlvmBehaviorNativeOciImageV2.openLayout(layout)

    fun bindings(deadline: AnalysisDeadline): PinnedDockerRuntimeBindings {
        // Authenticate only this tiny unscored client, then enable the exact private strict branch.
        // The production V3 bridge retains its independent fixed Docker client release pin.
        val bridge = PinnedDockerRuntimeBindings.Companion::class.java.declaredMethods.single {
            it.name == "captureWithCheckpoint" && it.parameterCount == 8
        }
        assertTrue(bridge.trySetAccessible())
        return try {
            bridge.invoke(PinnedDockerRuntimeBindings.Companion, client, Files.size(client),
                OracleArtifacts.sha256(Files.readAllBytes(client)), 1024L, config, socket,
                deadline::checkpoint, true) as PinnedDockerRuntimeBindings
        } catch (failure: InvocationTargetException) {
            throw failure.targetException
        }
    }

    fun events(): List<JsonObject> = if (!Files.exists(root.resolve("events.jsonl"))) emptyList() else {
        Files.readString(root.resolve("events.jsonl")).substringBeforeLast('\n', "").lineSequence()
            .filter(String::isNotBlank).map { OracleJson.parse(it.encodeToByteArray()) as JsonObject }.toList()
    }

    fun requests(): List<String> = events().filter { it["kind"] == JsonPrimitive("request") }
        .map { it.getValue("request").jsonPrimitive.content }

    fun expectedRequests(): List<String> = listOf("HEAD /_ping", "GET /version", "GET /info",
        "GET /v1.55/images/sha256:$configSha/json", "GET /v1.55/images/sha256:$configSha/get")

    fun awaitEvent(kind: String): JsonObject {
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() < until) {
            events().firstOrNull { it["kind"] == JsonPrimitive(kind) }?.let { return it }
            check(process?.isAlive != false) { "child exited before $kind: ${Files.readString(root.resolve("child.log"))}" }
            Thread.sleep(10)
        }
        error("child did not record $kind: ${events()}")
    }

    fun isAlive(): Boolean = process?.isAlive == true

    fun stopAndAwaitExit() {
        Files.writeString(root.resolve("stop"), "stop\n")
        assertTrue(checkNotNull(process).waitFor(2, TimeUnit.SECONDS), "child listener must exit on stop")
        assertEquals(0, checkNotNull(process).exitValue(), Files.readString(root.resolve("child.log")))
    }

    override fun close() {
        val owned = process
        if (owned != null) {
            val descendants = owned.descendants().use { it.toList() }
            Files.writeString(root.resolve("stop"), "stop\n")
            if (!owned.waitFor(2, TimeUnit.SECONDS)) {
                descendants.forEach { it.destroy() }
                owned.destroy()
                if (!owned.waitFor(2, TimeUnit.SECONDS)) {
                    descendants.forEach { it.destroyForcibly() }
                    owned.destroyForcibly()
                    assertTrue(owned.waitFor(2, TimeUnit.SECONDS))
                }
            }
            assertFalse(owned.isAlive, "test listener A must be reaped")
            assertTrue(descendants.none { it.isAlive }, "test inherited listener B must be reaped")
        }
        Files.walk(root).use { entries -> entries.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
    }

    private fun tar(output: Path, directory: Path, names: List<String>) {
        val child = ProcessBuilder(listOf("tar", "--format=ustar", "--sort=name", "--mtime=@0", "--owner=0",
            "--group=0", "--numeric-owner", "-cf", output.toString(), "-C", directory.toString()) + names)
            .redirectErrorStream(true).start()
        val log = child.inputStream.readBytes()
        check(child.waitFor(5, TimeUnit.SECONDS) && child.exitValue() == 0) { String(log) }
    }
}
