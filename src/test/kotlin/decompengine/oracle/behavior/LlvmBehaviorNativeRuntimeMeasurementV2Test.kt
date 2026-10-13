package decompengine.oracle.behavior

import decompengine.analysis.AnalysisDeadline
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeControlException
import com.sun.jna.Native
import com.sun.jna.NativeLong
import java.io.ByteArrayOutputStream
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Proxy
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.jar.JarFile
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Real Unix sockets and GNU tar controls, deliberately not scored Docker or containment evidence. */
class LlvmBehaviorNativeRuntimeMeasurementV2Test {
    @Test
    fun `quiet endpoint watch remains owned after all five requests until final verification and close`() {
        NativeMeasurementFixture().use { fixture ->
            fixture.start()
            fixture.image().use { image -> fixture.bindings().use { binding ->
                val deadline = AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(5), "retained quiet terminal fixture")
                privateMeasurement(binding, image, deadline = deadline)
                fixture.requireFinished()
                privateTerminal(binding, deadline)
                privateTerminal(binding, deadline)
                assertEquals(5, fixture.requests.size)
            } }
        }
    }

    @Test
    fun `post exchange socket ABA client replacement and config contamination refuse final candidate binding`() {
        listOf("socket", "client", "config").forEach { kind ->
            NativeMeasurementFixture().use { fixture ->
                fixture.start()
                fixture.image().use { image -> fixture.bindings().use { binding ->
                    val deadline = AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(5), "late $kind mutation")
                    privateMeasurement(binding, image, deadline = deadline)
                    fixture.requireFinished()
                    fixture.mutateAfterExchange(kind)
                    val mutation = if (kind == "client") {
                        assertFailsWith<FullTreeControlException>(kind) { privateTerminal(binding, deadline) }
                    } else {
                        assertFailsWith<PinnedDockerRuntimeBindingsException>(kind) { privateTerminal(binding, deadline) }
                    }
                    assertTrue(mutation.message.orEmpty().contains(kind), mutation.message)
                    val poisoned = assertFailsWith<PinnedDockerRuntimeBindingsException> { privateTerminal(binding, deadline) }
                    assertTrue(poisoned.message.orEmpty().contains("poisoned"))
                    assertEquals(5, fixture.requests.size)
                } }
            }
        }
    }

    @Test
    fun `missing or closed retained watch refuses final verification`() {
        listOf("missing", "closed").forEach { kind ->
            NativeMeasurementFixture().use { fixture ->
                fixture.start()
                fixture.image().use { image -> fixture.bindings().use { binding ->
                    val deadline = AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(5), "unknown watch fixture")
                    privateMeasurement(binding, image, deadline = deadline)
                    fixture.requireFinished()
                    val stateField = binding.javaClass.getDeclaredField("endpointState").apply { isAccessible = true }
                    val state = stateField.get(binding)
                    val watchField = state.javaClass.getDeclaredField("nativeMeasurementWatch").apply { isAccessible = true }
                    val watch = watchField.get(state) as AutoCloseable
                    try {
                        if (kind == "missing") watchField.set(state, null) else watch.close()
                        assertFailsWith<PinnedDockerRuntimeBindingsException>(kind) { privateTerminal(binding, deadline) }
                        assertEquals(5, fixture.requests.size)
                    } finally {
                        // Restore only the test's saved owner so ordinary close can release it.
                        if (kind == "missing") watchField.set(state, watch)
                    }
                } }
            }
        }
    }

    @Test
    fun `terminal verification uses the original deadline after completed HTTP exchange`() {
        NativeMeasurementFixture().use { fixture ->
            fixture.start()
            fixture.image().use { image -> fixture.bindings().use { binding ->
                val deadline = AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(2), "shared terminal deadline")
                privateMeasurement(binding, image, deadline = deadline)
                fixture.requireFinished()
                Thread.sleep(2100)
                assertFails { privateTerminal(binding, deadline) }
                assertEquals(5, fixture.requests.size)
            } }
        }
    }

    @Test
    fun `terminal caller cancellation refuses publication after completed HTTP exchange`() {
        NativeMeasurementFixture().use { fixture ->
            fixture.start()
            fixture.image().use { image -> fixture.bindings().use { binding ->
                val deadline = AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(5), "terminal cancellation")
                privateMeasurement(binding, image, deadline = deadline)
                fixture.requireFinished()
                try {
                    Thread.currentThread().interrupt()
                    assertFailsWith<InterruptedException> { privateTerminal(binding, deadline) }
                } finally {
                    Thread.interrupted()
                }
                assertEquals(5, fixture.requests.size)
            } }
        }
    }

    @Test
    fun `late watch close failure preserves original exception and releases control descriptors`() {
        NativeMeasurementFixture().use { fixture ->
            fixture.start()
            fixture.image().use { image ->
                val binding = fixture.bindings()
                val descriptorPath = binding.executableDescriptorPath
                val original = IllegalStateException("original measurement failure")
                val failure = assertFailsWith<IllegalStateException> {
                    binding.use {
                        privateMeasurement(binding, image)
                        fixture.requireFinished()
                        fixture.mutateAfterExchange("socket")
                        throw original
                    }
                }
                assertSame(original, failure)
                assertTrue(failure.suppressed.any { it is PinnedDockerRuntimeBindingsException })
                assertFalse(Files.exists(descriptorPath))
                binding.close()
            }
        }
    }

    @Test
    fun `sustained interrupted nonblocking watch reads refuse terminal return and still close owned descriptors`() {
        NativeMeasurementFixture().use { fixture ->
            fixture.start()
            fixture.image().use { image ->
                val binding = fixture.bindings()
                val descriptorPath = binding.executableDescriptorPath
                val deadline = AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(5), "bounded interrupted watch")
                privateMeasurement(binding, image, deadline = deadline)
                fixture.requireFinished()
                val stateField = binding.javaClass.getDeclaredField("endpointState").apply { isAccessible = true }
                val state = stateField.get(binding)
                val watchField = state.javaClass.getDeclaredField("nativeMeasurementWatch").apply { isAccessible = true }
                val watch = watchField.get(state)
                val libcField = watch.javaClass.getDeclaredField("libc").apply { isAccessible = true }
                val originalLibc = libcField.get(watch)
                val reads = AtomicInteger()
                val closes = AtomicInteger()
                // Private, unscored reflection replaces only read outcomes; close still calls real libc.
                val interrupted = Proxy.newProxyInstance(libcField.type.classLoader, arrayOf(libcField.type)) { _, method, args ->
                    if (method.name == "read") {
                        reads.incrementAndGet()
                        Native.setLastError(4) // Linux EINTR.
                        NativeLong(-1)
                    } else {
                        if (method.name == "close") closes.incrementAndGet()
                        check(method.trySetAccessible())
                        try { method.invoke(originalLibc, *(args ?: emptyArray())) }
                        catch (failure: InvocationTargetException) { throw failure.targetException }
                    }
                }
                libcField.set(watch, interrupted)
                val failure = assertFailsWith<PinnedDockerRuntimeBindingsException> {
                    binding.use { privateTerminal(binding, deadline) }
                }
                assertTrue(failure.message.orEmpty().contains("bounded interruption"))
                assertEquals(8, reads.get(), "four terminal attempts and four close attempts")
                assertEquals(1, closes.get(), "real owned inotify fd must close despite drain failure")
                assertTrue(failure.suppressed.any { it is PinnedDockerRuntimeBindingsException })
                assertFalse(Files.exists(descriptorPath))
                binding.close()
                assertEquals(5, fixture.requests.size)
            }
        }
    }

    @Test
    fun `actual Unix export bytes are bound to raw GNU tar OCI with only five fixed read requests`() {
        NativeMeasurementFixture().use { fixture ->
            fixture.start()
            fixture.image().use { image ->
                fixture.bindings().use { binding ->
                    val result = privateMeasurement(binding, image)
                    assertEquals(JsonPrimitive(image.configSha256), result["exportConfigSha256"])
                    assertEquals(JsonPrimitive(image.namespaceSha256), result["exportMergedNamespaceSha256"])
                    assertEquals(JsonPrimitive(OracleArtifacts.sha256(fixture.export)), result["exportSha256"])
                    assertEquals(5, fixture.requests.size)
                    assertEquals(listOf(
                        "HEAD /_ping", "GET /version", "GET /info",
                        "GET /v1.55/images/sha256:${image.configSha256}/json",
                        "GET /v1.55/images/sha256:${image.configSha256}/get",
                    ), fixture.requests)
                    assertFails { privateMeasurement(binding, image) }
                }
            }
            fixture.requireFinished()
        }
    }

    @Test
    fun `duplicate JSON and case insensitive duplicate HTTP fields are rejected`() {
        listOf("duplicate-json", "duplicate-header", "chunk-extension", "trailing-body", "wrong-inspect").forEach { behavior ->
            NativeMeasurementFixture(behavior).use { fixture ->
                fixture.start()
                fixture.image().use { image -> fixture.bindings().use { binding ->
                    assertFails(behavior) { privateMeasurement(binding, image) }
                } }
            }
        }
    }

    @Test
    fun `exported layer bytes rather than inspect strings reject image substitution`() {
        NativeMeasurementFixture("substituted-export").use { fixture ->
            fixture.start()
            fixture.image().use { image -> fixture.bindings().use { binding ->
                assertFailsWith<LlvmBehaviorNativeOciImageV2Exception> { privateMeasurement(binding, image) }
            } }
            assertEquals(5, fixture.requests.size, "inspect passed; refusal must use the actual export")
        }
    }

    @Test
    fun `one monotonic deadline bounds a stalled actual Unix response`() {
        NativeMeasurementFixture("stall-head").use { fixture ->
            fixture.start()
            fixture.image().use { image -> fixture.bindings().use { binding ->
                val start = System.nanoTime()
                assertFails { privateMeasurement(binding, image, 150) }
                assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(1))
            } }
            assertTrue(fixture.requestSeen.await(1, TimeUnit.SECONDS))
        }
    }

    @Test
    fun `caller cancellation closes actual blocked response ownership promptly`() {
        NativeMeasurementFixture("stall-head").use { fixture ->
            fixture.start()
            fixture.image().use { image -> fixture.bindings().use { binding ->
                val failure = AtomicReference<Throwable>()
                val worker = Thread {
                    try { privateMeasurement(binding, image) } catch (caught: Throwable) { failure.set(caught) }
                }
                worker.start()
                assertTrue(fixture.requestSeen.await(1, TimeUnit.SECONDS))
                worker.interrupt()
                worker.join(1000)
                assertFalse(worker.isAlive, "cancelled private socket measurement retained a live caller")
                assertTrue(failure.get() is InterruptedException)
            } }
        }
    }

    @Test
    fun `transient socket rename across fixed operations and retained raw input replacement fail`() {
        listOf("swap-socket", "swap-input").forEach { behavior ->
            NativeMeasurementFixture(behavior).use { fixture ->
                fixture.start()
                fixture.image().use { image -> fixture.bindings().use { binding ->
                    assertFails(behavior) { privateMeasurement(binding, image) }
                } }
            }
        }
    }

    @Test
    fun `measurement candidate cannot be relabelled as approved authority and copies bytes`() {
        val fields = linkedMapOf(
            "artifactKind" to JsonPrimitive("native-runtime-measurement-candidate"),
            "authority" to JsonPrimitive("unapproved-raw-measurement-only"),
        )
        val forbidden = listOf("oracleAuthority", "runtimeProfileApproved", "startAuthorized", "containmentProved",
            "scoringAuthority", "releaseEligible")
        forbidden.forEach { fields[it] = JsonPrimitive(false) }
        val candidate = LlvmBehaviorNativeRuntimeMeasurementV2Candidate.measured(JsonObject(fields), {})
        val bytes = candidate.canonicalBytes()
        bytes.fill(0)
        assertEquals(candidate.sha256, OracleArtifacts.sha256(candidate.canonicalBytes()))
        forbidden.forEach { key ->
            assertFailsWith<LlvmBehaviorNativeRuntimeMeasurementV2Exception> {
                LlvmBehaviorNativeRuntimeMeasurementV2Candidate.measured(JsonObject(fields + (key to JsonPrimitive(true))), {})
            }
        }
    }
    @Test
    fun `actual compiled ELF RUNPATH is local while inherited RPATH retains the dependency chain`() {
        listOf(false, true).forEach { inherited ->
            StaticElfFixture().use { fixture ->
                fixture.compileChain(inherited)
                fixture.image().use { image ->
                    val facts = privateElfClosure(image, "/subject/executable")
                    val nodes = facts["nodes"] as JsonArray
                    assertEquals(JsonPrimitive(false), facts["libraryClosureQualified"])
                    assertEquals(JsonPrimitive(false), facts["loaderBuiltInDirectoriesQualified"])
                    assertEquals(JsonPrimitive(inherited), facts["staticGraphCompleteUnderStatedModel"])
                    assertTrue(nodes.any { (it as JsonObject)["resolvedPath"] == JsonPrimitive("/lib/libleaf.so") })
                    val edges = facts["edges"] as JsonArray
                    assertTrue(edges.any { (it as JsonObject)["needed"] == JsonPrimitive("libmiddle.so") })
                    if (!inherited) assertTrue((facts["incompleteReasons"] as JsonArray).any { it.toString().contains("libleaf.so") })
                }
            }
        }
    }


    @Test
    fun `shared library ORIGIN retains the first symlink load pathname`() {
        StaticElfFixture().use { fixture ->
            fixture.compileSymlinkChain()
            fixture.image().use { image ->
                val facts = privateElfClosure(image, "/subject/executable")
                assertEquals(JsonPrimitive(true), facts["staticGraphCompleteUnderStatedModel"])
                val nodes = facts["nodes"] as JsonArray
                assertTrue(nodes.any { (it as JsonObject)["resolvedPath"] == JsonPrimitive("/store/libmiddle.so") })
                assertTrue(nodes.any { (it as JsonObject)["resolvedPath"] == JsonPrimitive("/alias/libleaf.so") })
                val edge = (facts["edges"] as JsonArray).map { it as JsonObject }.single { it["needed"] == JsonPrimitive("libleaf.so") }
                assertTrue((edge["searches"] as JsonArray).any { (it as JsonObject)["path"] == JsonPrimitive("/alias/libleaf.so") })
            }
        }
    }

    @Test
    fun `already loaded SONAME wins over a second requester RUNPATH in a compiled diamond`() {
        StaticElfFixture().use { fixture ->
            fixture.compileDiamond()
            fixture.image().use { image ->
                val facts = privateElfClosure(image, "/subject/executable")
                assertEquals(JsonPrimitive(true), facts["staticGraphCompleteUnderStatedModel"])
                val nodes = facts["nodes"] as JsonArray
                assertFalse(nodes.any { (it as JsonObject)["resolvedPath"] == JsonPrimitive("/other/libleaf.so") })
                val edge = (facts["edges"] as JsonArray).map { it as JsonObject }.single {
                    it["requester"].toString().contains("libmiddle.so") && it["needed"] == JsonPrimitive("libleaf.so")
                }
                assertEquals(JsonPrimitive("previously-loaded-DT_NEEDED-or-SONAME"),
                    ((edge["searches"] as JsonArray).single() as JsonObject)["provenance"])
            }
        }
    }

    @Test
    fun `ELF string table larger than range ceiling reads only needed strings and rejects invalid mappings`() {
        val original = syntheticElf(5 * 1024 * 1024)
        StaticElfFixture().use { fixture ->
            fixture.write("subject/executable", original)
            fixture.image().use { image ->
                val facts = privateElfClosure(image, "/subject/executable")
                assertEquals(JsonPrimitive(false), facts["staticGraphCompleteUnderStatedModel"])
                assertEquals(JsonArray(listOf(JsonPrimitive("libmissing.so"))),
                    ((facts["nodes"] as JsonArray).single() as JsonObject)["needed"])
            }
        }
        val mutations: List<(ByteBuffer) -> Unit> = listOf(
            { it.putLong(32, Long.MAX_VALUE - 8) },
            { it.putLong(72, Long.MAX_VALUE) },
            { it.putLong(256 + 8, Long.MAX_VALUE) },
            { it.putLong(288 + 8, 5L * 1024 * 1024) },
            { it.putShort(56, 3); val dynamic = original.copyOfRange(120, 176); it.position(176); it.put(dynamic) },
            { it.putShort(18, 3) },
        )
        mutations.forEach { mutate ->
            StaticElfFixture().use { fixture ->
                val changed = original.copyOf()
                mutate(ByteBuffer.wrap(changed).order(ByteOrder.LITTLE_ENDIAN))
                fixture.write("subject/executable", changed)
                fixture.image().use { image -> assertFails { privateElfClosure(image, "/subject/executable") } }
            }
        }
    }

    @Test
    fun `real glibc cache layouts retain all hardware candidates without claiming unique selection`() {
        listOf(false, true).forEach { legacy ->
            StaticElfFixture().use { fixture ->
                fixture.write("subject/executable", syntheticElf(1024))
                fixture.write("lib/base.so", syntheticElf(1024, null))
                fixture.write("lib/optimized.so", syntheticElf(1024, null))
                fixture.write("etc/ld.so.cache", syntheticCache(legacy, true))
                fixture.image().use { image ->
                    val facts = privateElfClosure(image, "/subject/executable")
                    val cache = facts["loaderCache"] as JsonObject
                    assertEquals(JsonPrimitive(legacy), cache["legacyCompatibilityPrefix"])
                    assertEquals(JsonPrimitive(false), facts["staticGraphCompleteUnderStatedModel"])
                    val edge = (facts["edges"] as JsonArray).single() as JsonObject
                    assertEquals(2, (edge["candidates"] as JsonArray).size)
                    assertEquals(JsonPrimitive(false), edge["selectionUniqueUnderStatedModel"])
                    assertTrue((edge["searches"] as JsonArray).any { (it as JsonObject)["hwcapUnsigned"] == JsonPrimitive("4611686018427387904") })
                }
            }
        }
        StaticElfFixture().use { fixture ->
            fixture.write("subject/executable", syntheticElf(1024))
            fixture.write("lib/base.so", syntheticElf(1024, null))
            fixture.write("etc/ld.so.cache", syntheticCache(false, false))
            fixture.image().use { image ->
                val facts = privateElfClosure(image, "/subject/executable")
                assertEquals(JsonPrimitive(true), facts["staticGraphCompleteUnderStatedModel"])
                assertEquals(JsonPrimitive(false), facts["libraryClosureQualified"])
            }
        }
        val mutations: List<(ByteBuffer) -> Unit> = listOf(
            { it.putInt(20, Int.MAX_VALUE) },
            { it.putInt(52, 0) },
            { it.put(28, 3.toByte()) },
            { it.putInt(32, Int.MAX_VALUE) },
        )
        mutations.forEach { mutate ->
            StaticElfFixture().use { fixture ->
                fixture.write("subject/executable", syntheticElf(1024))
                val cache = syntheticCache(false, false)
                mutate(ByteBuffer.wrap(cache).order(ByteOrder.LITTLE_ENDIAN))
                fixture.write("etc/ld.so.cache", cache)
                fixture.image().use { image -> assertFails { privateElfClosure(image, "/subject/executable") } }
            }
        }
    }



    @Test
    fun `isolated copied official codecs reject artifact drift and identical byte helper shadows`() {
        PackedMeasurementGuardFixture().use { fixture ->
            val accepted = fixture.codecProbe("official", null)
            assertTrue(accepted.contains("CODEC_GUARD_ACCEPTED"))
            listOf(
                "org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream\$Builder",
                "org.apache.commons.io.build.AbstractStreamBuilder",
                "io.airlift.compress.zstd.ZstdFrameDecompressor",
            ).forEachIndexed { index, helper ->
                val rejected = fixture.codecProbe("shadow-$index", helper)
                assertTrue(rejected.contains("GUARD_REJECTED"))
                assertTrue(rejected.contains("native codec helper is shadowed outside its fixed deployment"))
                assertTrue(rejected.contains("HELPER_ORIGIN=$helper:"))
                assertTrue(rejected.contains("shadow-$index.jar"))
            }
            val duplicate = fixture.codecProbe("duplicate-shadow", "org.apache.commons.io.build.AbstractStreamBuilder", duplicate = true)
            assertTrue(duplicate.contains("native codec helper is shadowed outside its fixed deployment"))
            val drifted = fixture.codecProbe("artifact-drift", null, drift = true)
            assertTrue(drifted.contains("native codec differs from its fixed official artifact bytes"))
        }
    }

    @Test
    fun `synthetic packed own application closure rejects missing duplicate and shadowed operational helpers`() {
        PackedMeasurementGuardFixture().use { fixture ->
            val companion = "decompengine/oracle/behavior/LlvmBehaviorNativeOciImageV2\$MeasuredImage\$Companion.class"
            val endpoint = "decompengine/oracle/behavior/PinnedDockerRuntimeBindings\$PinnedDockerEndpointState.class"
            val positive = fixture.appProbe("cached-fixture-positive")
            assertTrue(positive.contains("SYNTHETIC_APP_CLOSURE_ACCEPTED"))
            assertTrue(positive.contains("FIXTURE_ONLY_CACHED_BASELINE_NOT_INSTALLED_PROOF"))
            val missing = fixture.appProbe("missing-companion", missing = companion)
            assertTrue(missing.contains("measurement application's class closure falls back outside its own JAR"))
            val duplicate = fixture.appProbe("duplicate-entry", duplicate = companion)
            assertTrue(duplicate.contains("measurement application JAR contains duplicate or unbounded entries"))
            for ((index, helper) in listOf(companion, endpoint).withIndex()) {
                val shadowed = fixture.appProbe("app-shadow-$index", shadow = helper)
                assertTrue(shadowed.contains("measurement operational class"))
                assertTrue(shadowed.contains("is shadowed outside the own application JAR"))
                assertTrue(shadowed.contains(helper.removeSuffix(".class").replace('/', '.')))
                assertTrue(shadowed.contains("app-shadow-$index-shadow.jar"))
            }
        }
    }

    @Test
    fun `actual ldconfig generates independently parsed new and compatible container caches`() {
        listOf("new", "compat").forEach { format ->
            StaticElfFixture().use { fixture ->
                fixture.compileAndGenerateCache(format)
                fixture.image().use { image ->
                    val facts = privateElfClosure(image, "/subject/executable")
                    val cache = facts["loaderCache"] as JsonObject
                    assertEquals(JsonPrimitive(true), cache["present"])
                    assertEquals(JsonPrimitive(format == "compat"), cache["legacyCompatibilityPrefix"])
                    assertEquals(JsonPrimitive("glibc-ld.so.cache-1.1"), cache["format"])
                    assertEquals(JsonPrimitive(false), facts["libraryClosureQualified"])
                    val edge = (facts["edges"] as JsonArray).map { it as JsonObject }.single { it["needed"] == JsonPrimitive("libmissing.so") }
                    assertEquals(JsonPrimitive("/lib/libmissing.so"),
                        ((edge["candidates"] as JsonArray).single() as JsonObject)["resolvedPath"])
                    assertEquals(JsonPrimitive("ld.so.cache"),
                        ((edge["searches"] as JsonArray).single() as JsonObject)["provenance"])
                }
            }
        }
    }

    @Test
    fun `production factory rejects classes directory before attempting supplied filesystem or socket paths`() {
        val absent = Path.of("build/nrm/absent-factory-input")
        val failure = assertFailsWith<LlvmBehaviorNativeRuntimeMeasurementV2Exception> {
            LlvmBehaviorNativeRuntimeMeasurementV2.measure(absent, absent, absent, absent)
        }
        assertTrue(failure.message.orEmpty().contains("own installed application JAR"))
        assertFalse(Files.exists(absent))
    }

    @Test
    fun `fixed native factory bridge rejects a tiny client before any actual socket connection`() {
        NativeMeasurementFixture().use { fixture ->
            fixture.start()
            val failure = assertFails { fixture.captureFixedWithTinyClient() }
            assertTrue(failure.message.orEmpty().contains("byte length"))
            assertFalse(fixture.connectionAccepted.await(50, TimeUnit.MILLISECONDS))
            assertTrue(fixture.requests.isEmpty())
        }
    }

}

private fun privateMeasurement(
    binding: PinnedDockerRuntimeBindings,
    image: LlvmBehaviorNativeOciImageV2.MeasuredImage,
    maximumMillis: Long = 5000,
    deadline: AnalysisDeadline = AnalysisDeadline.start(TimeUnit.MILLISECONDS.toNanos(maximumMillis), "test raw runtime measurement"),
): JsonObject {
    // Test-only reflection into the exact private consuming bridge allows a tiny fake client pin.
    // The production factory accepts only the independently fixed Docker release executable bytes.
    val bridge = PinnedDockerRuntimeBindings.Companion::class.java.declaredMethods.single {
        it.name == "measureNativeRuntimeV2"
    }
    assertTrue(bridge.trySetAccessible())
    return try {
        bridge.invoke(PinnedDockerRuntimeBindings.Companion, binding, image, deadline) as JsonObject
    } catch (failure: InvocationTargetException) {
        throw failure.targetException
    }
}

private fun privateTerminal(binding: PinnedDockerRuntimeBindings, deadline: AnalysisDeadline) {
    // Test-only reflection reaches the exact private production terminal gate, never a new hook.
    val bridge = PinnedDockerRuntimeBindings.Companion::class.java.declaredMethods.single {
        it.name == "verifyNativeRuntimeV2Terminal"
    }
    assertTrue(bridge.trySetAccessible())
    try {
        bridge.invoke(PinnedDockerRuntimeBindings.Companion, binding, deadline)
    } catch (failure: InvocationTargetException) {
        throw failure.targetException
    }
}

private class NativeMeasurementFixture(private val behavior: String = "good") : AutoCloseable {
    // Keep sockaddr_un below Linux's 108-byte ceiling even in nested repository worktrees.
    private val parent = Path.of("build/nrm").toAbsolutePath().normalize()
    private val root = Files.createTempDirectory(Files.createDirectories(parent), "c")
    private val client = root.resolve("client")
    private val config = root.resolve("config")
    private val runtime = root.resolve("r")
    private val socket = runtime.resolve("s")
    private val layout = root.resolve("oci")
    private val exportRoot = root.resolve("export")
    private val payload = root.resolve("payload")
    private val server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
    private val current = AtomicReference<SocketChannel>()
    private val finished = CountDownLatch(1)
    val requestSeen = CountDownLatch(1)
    val connectionAccepted = CountDownLatch(1)
    val requests = java.util.Collections.synchronizedList(ArrayList<String>())
    val export: ByteArray
    private val configSha: String
    private val layerSha: String
    private val failure = AtomicReference<Throwable>()
    private var worker: Thread? = null

    init {
        listOf(root, config, runtime, layout, exportRoot, payload).forEach {
            Files.createDirectories(it)
            Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
        }
        Files.writeString(client, "unscored fixture client\n")
        Files.setPosixFilePermissions(client, PosixFilePermissions.fromString("r-x------"))
        Files.createDirectories(payload.resolve("bin"))
        Files.writeString(payload.resolve("bin/tool"), "retained exact native fixture bytes\n")
        val layer = root.resolve("layer.tar")
        tar(layer, payload, listOf("bin"))
        val layerBytes = Files.readAllBytes(layer)
        layerSha = OracleArtifacts.sha256(layerBytes)
        val configBytes = "{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[\"sha256:$layerSha\"]}}".encodeToByteArray()
        configSha = OracleArtifacts.sha256(configBytes)
        val manifestBytes = "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"sha256:$configSha\",\"size\":${configBytes.size}},\"layers\":[{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar\",\"digest\":\"sha256:$layerSha\",\"size\":${layerBytes.size}}]}".encodeToByteArray()
        val manifestSha = OracleArtifacts.sha256(manifestBytes)
        for (destination in listOf(layout, exportRoot)) {
            Files.createDirectories(destination.resolve("blobs/sha256"))
            Files.write(destination.resolve("blobs/sha256/$layerSha"), layerBytes)
            Files.write(destination.resolve("blobs/sha256/$configSha"), configBytes)
            Files.write(destination.resolve("blobs/sha256/$manifestSha"), manifestBytes)
            Files.writeString(destination.resolve("oci-layout"), "{\"imageLayoutVersion\":\"1.0.0\"}")
            Files.writeString(destination.resolve("index.json"), "{\"schemaVersion\":2,\"manifests\":[{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:$manifestSha\",\"size\":${manifestBytes.size}}]}")
        }
        Files.writeString(exportRoot.resolve("manifest.json"), "[{\"Config\":\"blobs/sha256/$configSha\",\"RepoTags\":null,\"Layers\":[\"blobs/sha256/$layerSha\"]}]")
        val exported = root.resolve("export.tar")
        tar(exported, exportRoot, listOf("oci-layout", "index.json", "manifest.json", "blobs"))
        export = Files.readAllBytes(exported)
        server.bind(UnixDomainSocketAddress.of(socket))
    }

    fun captureFixedWithTinyClient(): PinnedDockerRuntimeBindings {
        val bridge = PinnedDockerRuntimeBindings.Companion::class.java.declaredMethods.single { it.name == "captureForNativeRuntimeV2" }
        assertTrue(bridge.trySetAccessible())
        return try {
            bridge.invoke(PinnedDockerRuntimeBindings.Companion, client, config, socket,
                AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(2), "test fixed factory tiny pin")) as PinnedDockerRuntimeBindings
        } catch (failure: InvocationTargetException) { throw failure.targetException }
    }

    fun image() = LlvmBehaviorNativeOciImageV2.openLayout(layout)
    fun bindings() = PinnedDockerRuntimeBindings.capture(client, Files.size(client),
        OracleArtifacts.sha256(Files.readAllBytes(client)), 1024, config, socket)

    fun mutateAfterExchange(kind: String) {
        when (kind) {
            "socket" -> {
                val displaced = runtime.resolve("moved")
                Files.move(socket, displaced, StandardCopyOption.ATOMIC_MOVE)
                Files.move(displaced, socket, StandardCopyOption.ATOMIC_MOVE)
            }
            "client" -> {
                Files.move(client, root.resolve("client-displaced"), StandardCopyOption.ATOMIC_MOVE)
                Files.writeString(client, "substituted fixture client\n")
                Files.setPosixFilePermissions(client, PosixFilePermissions.fromString("r-x------"))
            }
            "config" -> Files.writeString(config.resolve("config.json"), "{}")
            else -> error("unknown private fixture mutation")
        }
    }

    fun start() {
        worker = Thread {
            try {
                repeat(5) { number ->
                    server.accept().use { channel ->
                        current.set(channel)
                        connectionAccepted.countDown()
                        val request = readRequest(channel)
                        requests += request.substringBefore(" HTTP/1.1")
                        requestSeen.countDown()
                        if (behavior == "stall-head") {
                            val data = ByteBuffer.allocate(1)
                            while (channel.read(data) >= 0) data.clear()
                            return@Thread
                        }
                        if (number == 1 && behavior == "swap-socket") {
                            val moved = runtime.resolve("moved.sock")
                            Files.move(socket, moved)
                            Files.move(moved, socket)
                        }
                        if (number == 4 && behavior == "swap-input") {
                            val input = layout.resolve("index.json")
                            Files.move(input, layout.resolve("old-index"))
                            Files.copy(layout.resolve("old-index"), input)
                        }
                        val response = when (number) {
                            0 -> HEAD_RESPONSE.encodeToByteArray()
                            1 -> jsonResponse(if (behavior == "duplicate-json") "{\"Version\":\"29.7.2\",\"Version\":\"29.7.2\"}" else VERSION)
                            2 -> jsonResponse(INFO)
                            3 -> jsonResponse("{\"Id\":\"sha256:${if (behavior == "wrong-inspect") "0".repeat(64) else configSha}\",\"Os\":\"linux\",\"Architecture\":\"amd64\",\"RootFS\":{\"Type\":\"layers\",\"Layers\":[\"sha256:$layerSha\"]}}")
                            else -> exportResponse()
                        }
                        val source = ByteBuffer.wrap(response)
                        while (source.hasRemaining()) channel.write(source)
                        current.set(null)
                    }
                }
            } catch (caught: Throwable) { failure.set(caught) } finally { finished.countDown() }
        }.apply { isDaemon = true; name = "unscored-native-measurement-peer"; start() }
    }

    private fun jsonResponse(json: String): ByteArray {
        val body = json.encodeToByteArray()
        val duplicate = if (behavior == "duplicate-header") "content-length: ${body.size}\r\n" else ""
        val trailing = if (behavior == "trailing-body") "extra" else ""
        return ("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: ${body.size}\r\n$duplicate\r\n" + json + trailing).encodeToByteArray()
    }

    private fun exportResponse(): ByteArray {
        val body = export.copyOf()
        if (behavior == "substituted-export") body[body.size / 2] = (body[body.size / 2].toInt() xor 1).toByte()
        val result = ByteArrayOutputStream()
        result.write("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/x-tar\r\nTransfer-Encoding: chunked\r\n\r\n".encodeToByteArray())
        var offset = 0
        while (offset < body.size) {
            val count = minOf(733, body.size - offset)
            val extension = if (behavior == "chunk-extension") ";ignored=value" else ""
            result.write("${count.toString(16)}$extension\r\n".encodeToByteArray())
            result.write(body, offset, count)
            result.write("\r\n".encodeToByteArray())
            offset += count
        }
        result.write("0\r\n\r\n".encodeToByteArray())
        return result.toByteArray()
    }

    private fun readRequest(channel: SocketChannel): String {
        val result = ByteArrayOutputStream()
        val buffer = ByteBuffer.allocate(1024)
        while (true) {
            buffer.clear()
            val read = channel.read(buffer)
            check(read > 0)
            result.write(buffer.array(), 0, read)
            check(result.size() <= 8192)
            val text = result.toString(Charsets.US_ASCII)
            if (text.endsWith("\r\n\r\n")) return text.substringBefore("\r\n")
        }
    }

    fun requireFinished() {
        assertTrue(finished.await(2, TimeUnit.SECONDS))
        failure.get()?.let { throw AssertionError("unscored Unix fixture failed", it) }
    }

    override fun close() {
        current.getAndSet(null)?.close()
        server.close()
        worker?.join(2000)
        check(worker?.isAlive != true) { "unscored fixture retained its socket worker" }
        Files.walk(root).use { entries -> entries.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
    }

    private fun tar(output: Path, directory: Path, names: List<String>) {
        val process = ProcessBuilder(listOf("tar", "--format=ustar", "--sort=name", "--mtime=@0", "--owner=0",
            "--group=0", "--numeric-owner", "-cf", output.toString(), "-C", directory.toString()) + names)
            .redirectErrorStream(true).start()
        val log = process.inputStream.readBytes()
        check(process.waitFor(5, TimeUnit.SECONDS) && process.exitValue() == 0) { String(log) }
    }
}

private const val VERSION = "{\"Version\":\"29.7.2\",\"ApiVersion\":\"1.55\",\"Os\":\"linux\",\"Arch\":\"amd64\",\"GitCommit\":\"6a43e3d\"}"
private const val INFO = "{\"ServerVersion\":\"29.7.2\",\"OSType\":\"linux\",\"Driver\":\"overlay2\",\"CgroupVersion\":\"2\",\"SecurityOptions\":[\"name=rootless\"]}"
private const val HEAD_RESPONSE = "HTTP/1.1 200 OK\r\nApi-Version: 1.55\r\nBuilder-Version: 2\r\nCache-Control: no-cache, no-store, must-revalidate\r\nConnection: close\r\nContent-Length: 0\r\nContent-Type: text/plain; charset=utf-8\r\nDate: Tue, 13 Oct 2026 00:00:00 GMT\r\nDocker-Experimental: false\r\nOstype: linux\r\nPragma: no-cache\r\nServer: Docker/29.7.2 (linux)\r\nSwarm: inactive\r\n\r\n"

private fun privateElfClosure(image: LlvmBehaviorNativeOciImageV2.MeasuredImage, subject: String): JsonObject {
    val method = LlvmBehaviorNativeRuntimeMeasurementV2::class.java.declaredMethods.single { it.name == "measureElfClosure" }
    assertTrue(method.trySetAccessible())
    val deadline = AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(10), "test static ELF closure")
    return try {
        method.invoke(LlvmBehaviorNativeRuntimeMeasurementV2, image, subject, deadline::checkpoint) as JsonObject
    } catch (failure: InvocationTargetException) { throw failure.targetException }
}

private fun syntheticElf(stringBytes: Int, needed: String? = "libmissing.so"): ByteArray {
    val bytes = ByteArray(512 + stringBytes)
    val data = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    data.put(byteArrayOf(0x7f, 69, 76, 70, 2, 1, 1))
    data.putShort(16, 3); data.putShort(18, 62); data.putInt(20, 1)
    data.putLong(32, 64); data.putShort(52, 64); data.putShort(54, 56); data.putShort(56, 2)
    data.putInt(64, 1); data.putLong(64 + 8, 0); data.putLong(64 + 16, 0)
    data.putLong(64 + 32, bytes.size.toLong()); data.putLong(64 + 40, bytes.size.toLong()); data.putLong(64 + 48, 1)
    data.putInt(120, 2); data.putLong(120 + 8, 256); data.putLong(120 + 16, 256)
    data.putLong(120 + 32, 64); data.putLong(120 + 40, 64)
    data.putLong(256, 5); data.putLong(264, 512)
    data.putLong(272, 10); data.putLong(280, stringBytes.toLong())
    if (needed != null) {
        val stringOffset = stringBytes - needed.length - 1
        data.putLong(288, 1); data.putLong(296, stringOffset.toLong())
        needed.encodeToByteArray().copyInto(bytes, 512 + stringOffset)
    }
    return bytes
}

private fun syntheticCache(legacy: Boolean, hardware: Boolean): ByteArray {
    val base = if (legacy) 16 else 0
    val names = listOf("libmissing.so", "/lib/base.so") + if (hardware) listOf("/lib/optimized.so", "x86-64-v3") else emptyList()
    val count = if (hardware) 2 else 1
    val stringStart = 48 + count * 24
    val offsets = ArrayList<Int>()
    val strings = ByteArrayOutputStream()
    names.forEach { name -> offsets += stringStart + strings.size(); strings.write(name.encodeToByteArray()); strings.write(0) }
    val extension = if (hardware) ((base + stringStart + strings.size() + 3) / 4) * 4 else 0
    val bytes = ByteArray(if (hardware) extension + 28 else base + stringStart + strings.size())
    val data = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    if (legacy) "ld.so-1.7.0".encodeToByteArray().copyInto(bytes)
    "glibc-ld.so.cache1.1".encodeToByteArray().copyInto(bytes, base)
    data.putInt(base + 20, count); data.putInt(base + 24, strings.size()); data.put(base + 28, 2.toByte())
    repeat(count) { index ->
        val position = base + 48 + index * 24
        data.putInt(position, 0x303); data.putInt(position + 4, offsets[0]); data.putInt(position + 8, offsets[index + 1])
        if (hardware && index == 1) data.putLong(position + 16, 1L shl 62)
    }
    strings.toByteArray().copyInto(bytes, base + stringStart)
    if (hardware) {
        data.putInt(base + 32, extension); data.putInt(extension, -358342284); data.putInt(extension + 4, 1)
        data.putInt(extension + 8, 1); data.putInt(extension + 16, extension + 24); data.putInt(extension + 20, 4)
        data.putInt(extension + 24, offsets[3])
    }
    return bytes
}

private class StaticElfFixture : AutoCloseable {
    private val parent = Files.createDirectories(Path.of("build/nrm").toAbsolutePath().normalize())
    private val root = Files.createTempDirectory(parent, "elf-")
    private val payload = Files.createDirectory(root.resolve("payload"))
    private val layout = Files.createDirectory(root.resolve("oci"))

    fun write(path: String, bytes: ByteArray) {
        val selected = payload.resolve(path)
        Files.createDirectories(selected.parent)
        Files.write(selected, bytes)
    }

    fun compileChain(inherited: Boolean) {
        val sources = Files.createDirectory(root.resolve("sources"))
        Files.createDirectories(payload.resolve("lib")); Files.createDirectories(payload.resolve("subject"))
        Files.writeString(sources.resolve("leaf.c"), "int leaf(void) { return 7; }\n")
        Files.writeString(sources.resolve("middle.c"), "extern int leaf(void); int middle(void) { return leaf(); }\n")
        Files.writeString(sources.resolve("main.c"), "extern int middle(void); void _start(void) { (void)middle(); }\n")
        run(listOf("cc", "-nostdlib", "-shared", "-fPIC", "-Wl,-soname,libleaf.so", sources.resolve("leaf.c").toString(), "-o", payload.resolve("lib/libleaf.so").toString()))
        run(listOf("cc", "-nostdlib", "-shared", "-fPIC", "-Wl,-soname,libmiddle.so", sources.resolve("middle.c").toString(), "-L${payload.resolve("lib")}", "-lleaf", "-o", payload.resolve("lib/libmiddle.so").toString()))
        run(listOf("cc", "-nostdlib", sources.resolve("main.c").toString(), "-L${payload.resolve("lib")}", "-lmiddle", "-Wl,-e,_start,--allow-shlib-undefined,--dynamic-linker,/lib/loader.so", "-Wl,-rpath,\$ORIGIN/../lib", if (inherited) "-Wl,--disable-new-dtags" else "-Wl,--enable-new-dtags", "-o", payload.resolve("subject/executable").toString()))
        // A real compiled ELF control stands in for a loader without being executed or qualified.
        run(listOf("cc", "-nostdlib", "-shared", "-fPIC", "-Wl,-soname,ld-fixture.so.2", sources.resolve("leaf.c").toString(), "-o", payload.resolve("lib/loader.so").toString()))
    }



    fun compileAndGenerateCache(format: String) {
        val sources = Files.createDirectory(root.resolve("sources"))
        Files.createDirectories(payload.resolve("lib")); Files.createDirectories(payload.resolve("etc"))
        Files.createDirectories(payload.resolve("var/cache/ldconfig"))
        Files.writeString(sources.resolve("cached.c"), "extern int puts(const char *); int cached(void) { return puts(\"tiny benign ELF cache fixture\"); }\n")
        run(listOf("cc", "-shared", "-fPIC", "-Wl,-soname,libmissing.so", sources.resolve("cached.c").toString(), "-o", payload.resolve("lib/libmissing.so").toString()))
        write("subject/executable", syntheticElf(1024))
        Files.writeString(payload.resolve("etc/ld.so.conf"), "/lib\n")
        val cacheTool = listOf("/usr/sbin/ldconfig", "/sbin/ldconfig", "/usr/bin/ldconfig")
            .map { Path.of(it) }.firstOrNull { Files.isRegularFile(it) && Files.isExecutable(it) }
            ?: error("real cache control requires ldconfig at a fixed supported distribution path")
        val resolvedCacheTool = cacheTool.toRealPath()
        assertTrue(Files.size(resolvedCacheTool) in 1L..16L * 1024 * 1024)
        println("LDCONFIG_CONTROL_TOOL selected=$cacheTool resolved=$resolvedCacheTool " +
            "bytes=${Files.size(resolvedCacheTool)} sha256=${OracleArtifacts.sha256(Files.readAllBytes(resolvedCacheTool))} format=$format")
        // Both the main cache and optional auxiliary cache are beneath this new controlled root;
        // chroot_canon remains rooted there even when unprivileged chroot itself is unavailable.
        run(listOf(resolvedCacheTool.toString(), "-r", payload.toString(), "-C", "/etc/ld.so.cache", "-f", "/etc/ld.so.conf", "-X", "-i", "--format=$format"))
        assertTrue(Files.isRegularFile(payload.resolve("etc/ld.so.cache")))
    }

    fun compileSymlinkChain() {
        compileChain(false)
        val sources = root.resolve("sources")
        run(listOf("cc", "-nostdlib", "-shared", "-fPIC", "-Wl,-soname,libmiddle.so", "-Wl,-rpath,\$ORIGIN", sources.resolve("middle.c").toString(), "-L${payload.resolve("lib")}", "-lleaf", "-o", payload.resolve("lib/libmiddle.so").toString()))
        Files.createDirectories(payload.resolve("alias")); Files.createDirectories(payload.resolve("store"))
        Files.move(payload.resolve("lib/libmiddle.so"), payload.resolve("store/libmiddle.so"))
        Files.createSymbolicLink(payload.resolve("alias/libmiddle.so"), Path.of("/store/libmiddle.so"))
        Files.copy(payload.resolve("lib/libleaf.so"), payload.resolve("alias/libleaf.so"))
        // Use the retained /store compiler input; the measured dynamic path remains /alias.
        run(listOf("cc", "-nostdlib", sources.resolve("main.c").toString(), payload.resolve("store/libmiddle.so").toString(), "-Wl,-e,_start,--allow-shlib-undefined,--dynamic-linker,/lib/loader.so", "-Wl,-rpath,/alias", "-o", payload.resolve("subject/executable").toString()))
    }

    fun compileDiamond() {
        compileChain(false)
        val sources = root.resolve("sources")
        run(listOf("cc", "-nostdlib", "-shared", "-fPIC", "-Wl,-soname,libmiddle.so", "-Wl,-rpath,/other", sources.resolve("middle.c").toString(), "-L${payload.resolve("lib")}", "-lleaf", "-o", payload.resolve("lib/libmiddle.so").toString()))
        Files.createDirectories(payload.resolve("other"))
        Files.writeString(sources.resolve("other.c"), "int leaf(void) { return 99; }\n")
        run(listOf("cc", "-nostdlib", "-shared", "-fPIC", "-Wl,-soname,libleaf.so", sources.resolve("other.c").toString(), "-o", payload.resolve("other/libleaf.so").toString()))
        Files.writeString(sources.resolve("main.c"), "extern int middle(void); extern int leaf(void); void _start(void) { (void)middle(); (void)leaf(); }\n")
        run(listOf("cc", "-nostdlib", sources.resolve("main.c").toString(), "-L${payload.resolve("lib")}", "-lmiddle", "-lleaf", "-Wl,-e,_start,--allow-shlib-undefined,--dynamic-linker,/lib/loader.so", "-Wl,-rpath,\$ORIGIN/../lib", "-o", payload.resolve("subject/executable").toString()))
    }

    fun image(): LlvmBehaviorNativeOciImageV2.MeasuredImage {
        val layer = root.resolve("layer.tar")
        run(listOf("tar", "--format=ustar", "--sort=name", "--mtime=@0", "--owner=0", "--group=0", "--numeric-owner", "-cf", layer.toString(), "-C", payload.toString(), "."))
        val bytes = Files.readAllBytes(layer)
        val layerSha = OracleArtifacts.sha256(bytes)
        val config = "{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[\"sha256:$layerSha\"]}}".encodeToByteArray()
        val configSha = OracleArtifacts.sha256(config)
        val manifest = "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"sha256:$configSha\",\"size\":${config.size}},\"layers\":[{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar\",\"digest\":\"sha256:$layerSha\",\"size\":${bytes.size}}]}".encodeToByteArray()
        val manifestSha = OracleArtifacts.sha256(manifest)
        Files.createDirectories(layout.resolve("blobs/sha256"))
        for ((sha, content) in listOf(layerSha to bytes, configSha to config, manifestSha to manifest)) Files.write(layout.resolve("blobs/sha256/$sha"), content)
        Files.writeString(layout.resolve("oci-layout"), "{\"imageLayoutVersion\":\"1.0.0\"}")
        Files.writeString(layout.resolve("index.json"), "{\"schemaVersion\":2,\"manifests\":[{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:$manifestSha\",\"size\":${manifest.size}}]}")
        return LlvmBehaviorNativeOciImageV2.openLayout(layout)
    }

    private fun run(command: List<String>) {
        val log = root.resolve("tool.log")
        val process = ProcessBuilder(command).directory(root.toFile()).redirectErrorStream(true).redirectOutput(log.toFile()).apply {
            environment().clear()
            environment().putAll(mapOf("PATH" to "/usr/bin:/bin", "LC_ALL" to "C", "HOME" to root.toString(), "TMPDIR" to root.toString()))
        }.start()
        if (!process.waitFor(5, TimeUnit.SECONDS)) {
            val children = process.descendants().use { it.toList() }
            children.asReversed().forEach { it.destroyForcibly() }
            process.destroyForcibly()
            check(process.waitFor(1, TimeUnit.SECONDS) && children.none { it.isAlive }) { "benign compiler/tar/ldconfig control retained a process" }
            error("benign compiler/tar control exceeded its five-second ceiling")
        }
        check(process.exitValue() == 0) { Files.newInputStream(log).use { String(it.readNBytes(4096)) } }
    }

    override fun close() {
        Files.walk(root).use { entries -> entries.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
    }
}

/** Test-only child entry; it invokes real private guards but never the runtime transport or START. */
object NativeMeasurementDeploymentGuardProbe {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 3)
        val kind = arguments[0]
        val selected = Path.of(arguments[1]).toAbsolutePath().normalize()
        val helper = arguments[2]
        val deadline = AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(30), "test packed private class-origin guard")
        val checkpoint: (String) -> Unit = deadline::checkpoint
        try {
            if (helper.isNotEmpty()) {
                val type = Class.forName(helper, false, LlvmBehaviorNativeRuntimeMeasurementV2::class.java.classLoader)
                println("HELPER_ORIGIN=$helper:${type.protectionDomain.codeSource.location}")
            }
            if (kind == "codec") {
                val owner = Class.forName("decompengine.oracle.behavior.LlvmBehaviorNativeRuntimeMeasurementV2\$PinnedMeasurementCodecs")
                val companionField = owner.getDeclaredField("Companion").apply { check(trySetAccessible()) }
                val companion = companionField.get(null)
                val open = companion.javaClass.declaredMethods.single { it.name == "open" }.apply { check(trySetAccessible()) }
                val codecs = open.invoke(companion, selected, checkpoint) as AutoCloseable
                codecs.use {
                    val current = codecs.javaClass.declaredMethods.single { it.name == "requireCurrent" }.apply { check(trySetAccessible()) }
                    current.invoke(codecs, checkpoint)
                    for (name in listOf("io.airlift.compress.zstd.ZstdInputStream",
                        "org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream",
                        "org.apache.commons.io.build.AbstractStreamBuilder", "org.apache.commons.lang3.StringUtils")) {
                        val type = Class.forName(name, false, NativeMeasurementDeploymentGuardProbe::class.java.classLoader)
                        println("CODEC_ORIGIN=$name:${type.protectionDomain.codeSource.location}")
                    }
                    val facts = codecs.javaClass.declaredMethods.single { it.name == "getFacts" }.apply { check(trySetAccessible()) }
                    println("CODEC_FIXED_INPUT_FACTS=${facts.invoke(codecs)}")
                }
                println("CODEC_GUARD_ACCEPTED")
            } else {
                require(kind == "app")
                println("FIXTURE_ONLY_CACHED_BASELINE_NOT_INSTALLED_PROOF")
                for (name in listOf("decompengine.oracle.behavior.LlvmBehaviorNativeRuntimeMeasurementV2",
                    "decompengine.oracle.behavior.LlvmBehaviorNativeOciImageV2", "decompengine.oracle.behavior.PinnedDockerRuntimeBindings")) {
                    val type = Class.forName(name, false, NativeMeasurementDeploymentGuardProbe::class.java.classLoader)
                    println("APP_ORIGIN=$name:${type.protectionDomain.codeSource.location}")
                }
                val guard = LlvmBehaviorNativeRuntimeMeasurementV2::class.java.declaredMethods.single { it.name == "requireOwnMeasurementClasses" }.apply { check(trySetAccessible()) }
                guard.invoke(LlvmBehaviorNativeRuntimeMeasurementV2, selected, checkpoint)
                println("SYNTHETIC_APP_CLOSURE_ACCEPTED")
            }
        } catch (failure: Throwable) {
            var cause = failure
            while (cause is InvocationTargetException && cause.targetException != null) cause = cause.targetException
            if (cause.javaClass.name == "decompengine.oracle.behavior.LlvmBehaviorNativeRuntimeMeasurementV2Exception") {
                println("GUARD_REJECTED=${cause.javaClass.name}:${cause.message}")
            } else {
                println("UNRELATED_FAILURE=${cause.javaClass.name}:${cause.message}")
                cause.printStackTrace()
                kotlin.system.exitProcess(3)
            }
        }
    }
}

private class PackedMeasurementGuardFixture : AutoCloseable {
    private val parent = Files.createDirectories(Path.of("build/native-runtime-verification/packed-origin-controls").toAbsolutePath().normalize())
    private val root = Files.createTempDirectory(parent, "g")
    private val codecDirectory = Files.createDirectory(root.resolve("codecs"))
    private val currentApplication = Path.of(LlvmBehaviorNativeRuntimeMeasurementV2::class.java.protectionDomain.codeSource.location.toURI())
    private val baselineApplication = Path.of(decompengine.oracle.fulltree.StableControlFile::class.java.protectionDomain.codeSource.location.toURI())
    private val originalClasspath = System.getProperty("java.class.path").split(java.io.File.pathSeparator).map { Path.of(it).toAbsolutePath().normalize() }
    private val applicationClasses = LinkedHashMap<String, ByteArray>()
    private val codecs = listOf(
        Triple("aircompressor-2.0.3.jar", "io.airlift.compress.zstd.ZstdInputStream", "b86bb66f610079e0bf790d62e2ff68853eb0dc4748a6d68ae28bce92b68094aa"),
        Triple("commons-compress-1.28.0.jar", "org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream", "e1522945218456f3649a39bc4afd70ce4bd466221519dba7d378f2141a4642ca"),
        Triple("commons-io-2.20.0.jar", "org.apache.commons.io.build.AbstractStreamBuilder", "df90bba0fe3cb586b7f164e78fe8f8f4da3f2dd5c27fa645f888100ccc25dd72"),
        Triple("commons-lang3-3.18.0.jar", "org.apache.commons.lang3.StringUtils", "4eeeae8d20c078abb64b015ec158add383ac581571cddc45c68f0c9ae0230720"),
    )

    init {
        for ((filename, className, expected) in codecs) {
            val origin = Path.of(Class.forName(className, false, NativeMeasurementDeploymentGuardProbe::class.java.classLoader).protectionDomain.codeSource.location.toURI())
            assertEquals(expected, OracleArtifacts.sha256(Files.readAllBytes(origin)))
            Files.copy(origin, codecDirectory.resolve(filename))
        }
        // Deliberately cached/synthetic: actual current three-source classes overlay cached baseline
        // application outputs. This supports negative guard regression only, never installed proof.
        val javaOutputs = originalClasspath.filter { it.toString().endsWith("/build/classes/java/main") && Files.isDirectory(it) }
        for (directory in (javaOutputs + listOf(baselineApplication, currentApplication)).distinct()) {
            assertTrue(Files.isDirectory(directory), "packed fixture requires explicit classes-directory inputs: $directory (current=$currentApplication baseline=$baselineApplication)")
            val prefix = directory.resolve("decompengine")
            if (!Files.isDirectory(prefix)) continue
            Files.walk(prefix).use { files ->
                files.filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".class") }.sorted().forEach { file ->
                    val name = directory.relativize(file).toString().replace(java.io.File.separatorChar, '/')
                    assertTrue(Files.size(file) in 1L..4 * 1024 * 1024)
                    applicationClasses[name] = Files.readAllBytes(file)
                }
            }
        }
        assertTrue(applicationClasses.size in 1..25_000)
        assertTrue(applicationClasses.values.sumOf { it.size.toLong() } <= 256L * 1024 * 1024)
    }

    fun codecProbe(label: String, helper: String?, duplicate: Boolean = false, drift: Boolean = false): String {
        val selectedCodecs = if (drift) {
            val directory = Files.createDirectory(root.resolve("drifted"))
            codecs.forEach { (filename) -> Files.copy(codecDirectory.resolve(filename), directory.resolve(filename)) }
            val artifact = directory.resolve("aircompressor-2.0.3.jar")
            val bytes = Files.readAllBytes(artifact)
            bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
            Files.write(artifact, bytes)
            directory
        } else codecDirectory
        val first = ArrayList<Path>()
        if (helper != null) {
            val name = helper.replace('.', '/') + ".class"
            val original = codecClass(name)
            val shadow = root.resolve("$label.jar")
            zip(shadow, listOf(name to original) + if (duplicate) listOf(name to original) else emptyList())
            first.add(shadow)
        }
        first += codecs.map { (filename) -> selectedCodecs.resolve(filename) }
        return runChild(label, first + originalClasspath, "codec", selectedCodecs, helper.orEmpty())
    }

    fun appProbe(label: String, missing: String? = null, duplicate: String? = null, shadow: String? = null): String {
        val jar = root.resolve("$label.jar")
        val members = applicationClasses.filterKeys { it != missing }.map { it.key to it.value }.toMutableList()
        if (duplicate != null) members += duplicate to applicationClasses.getValue(duplicate)
        zip(jar, members)
        val first = ArrayList<Path>()
        if (shadow != null) {
            val shadowJar = root.resolve("$label-shadow.jar")
            zip(shadowJar, listOf(shadow to applicationClasses.getValue(shadow)))
            first.add(shadowJar)
        }
        first.add(jar)
        first += codecs.map { (filename) -> codecDirectory.resolve(filename) }
        return runChild(label, first + originalClasspath, "app", jar, shadow?.removeSuffix(".class")?.replace('/', '.').orEmpty())
    }

    private fun codecClass(name: String): ByteArray {
        for ((filename) in codecs) {
            JarFile(codecDirectory.resolve(filename).toFile(), false).use { jar ->
                val entry = jar.getJarEntry(name)
                if (entry != null) return jar.getInputStream(entry).use { it.readNBytes(entry.size.toInt() + 1) }.also { assertEquals(entry.size.toInt(), it.size) }
            }
        }
        error("official codec helper is absent: $name")
    }

    private fun zip(path: Path, members: List<Pair<String, ByteArray>>) {
        // Commons' ZIP writer permits deliberate duplicate entries; java.util.zip refuses to
        // produce that malformed archive and would test the fixture rather than the real guard.
        ZipArchiveOutputStream(path).use { output ->
            members.forEach { (name, bytes) ->
                val entry = ZipArchiveEntry(name).apply { time = 0; size = bytes.size.toLong() }
                output.putArchiveEntry(entry); output.write(bytes); output.closeArchiveEntry()
            }
        }
    }

    private fun runChild(label: String, classpath: List<Path>, kind: String, selected: Path, helper: String): String {
        val log = root.resolve("$label.log")
        val tmp = Files.createDirectory(root.resolve("$label-tmp"))
        val javaExecutable = Path.of(System.getProperty("java.home"), "bin", "java")
        val command = listOf(javaExecutable.toString(), "-XX:-UsePerfData", "-Xmx512m", "-Djava.io.tmpdir=$tmp", "-Djna.tmpdir=$tmp", "-cp",
            classpath.joinToString(java.io.File.pathSeparator), NativeMeasurementDeploymentGuardProbe::class.java.name, kind, selected.toString(), helper)
        val process = ProcessBuilder(command).directory(root.toFile()).redirectErrorStream(true).redirectOutput(log.toFile()).apply {
            environment().clear()
            environment().putAll(mapOf("PATH" to "/usr/bin:/bin", "LC_ALL" to "C", "HOME" to root.toString(), "TMPDIR" to tmp.toString(),
                "XDG_CACHE_HOME" to tmp.toString(), "XDG_CONFIG_HOME" to tmp.toString(), "XDG_STATE_HOME" to tmp.toString()))
        }.start()
        if (!process.waitFor(45, TimeUnit.SECONDS)) {
            val children = process.descendants().use { it.toList() }
            children.asReversed().forEach { it.destroyForcibly() }; process.destroyForcibly()
            check(process.waitFor(1, TimeUnit.SECONDS) && children.none { it.isAlive }) { "packed control retained a process" }
            error("packed class-origin control exceeded its 45-second ceiling")
        }
        assertTrue(Files.size(log) <= 64 * 1024, "packed control output exceeds its bound")
        val text = Files.readString(log)
        println("PACKED_ORIGIN_CONTROL=$label\n$text")
        assertEquals(0, process.exitValue(), text)
        val evidence = JsonObject(linkedMapOf("label" to JsonPrimitive(label), "kind" to JsonPrimitive(kind),
            "fixtureOnly" to JsonPrimitive(true), "productionInstalledProof" to JsonPrimitive(false),
            "childExit" to JsonPrimitive(process.exitValue()), "childPid" to JsonPrimitive(process.pid()),
            "childObservedAbsent" to JsonPrimitive(!process.isAlive), "selectedArtifactSha256" to JsonPrimitive(if (Files.isRegularFile(selected)) OracleArtifacts.sha256(Files.readAllBytes(selected)) else "directory"),
            "output" to JsonPrimitive(text)))
        Files.write(parent.resolve("$label.json"), OracleJson.canonicalBytes(evidence, NATIVE_MEASUREMENT_JSON_LIMITS))
        return text
    }

    override fun close() {
        Files.walk(root).use { files -> files.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
    }
}
