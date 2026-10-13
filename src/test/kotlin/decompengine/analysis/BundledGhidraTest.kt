package decompengine.analysis

import decompengine.oracle.fulltree.inControlTemporaryDirectory
import decompengine.project.sha256
import decompengine.project.RecoveredCallSitesTest
import decompengine.oracle.gcc.GccCompilerEngineProfiles
import decompengine.oracle.gcc.authenticateGhidraInstallation
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class BundledGhidraTest {
    @Test
    fun `shared worker command rejects empty duplicate and ambiguous classpaths`() {
        val java = Path.of("/runtime/bin/java")
        val release = Path.of("/application/ghidra")
        val bridge = Path.of("/application/bridge.jar")
        for (entries in listOf(emptyList(), listOf(bridge, bridge), listOf(Path.of("/application/part:other.jar")))) {
            assertFailsWith<IllegalArgumentException> { GhidraWorkerCommand.prefix(java, release, entries) }
        }
    }

    @Test
    fun `all call site regressions have JUnit discoverable void signatures`() {
        val methods = RecoveredCallSitesTest::class.java.declaredMethods.filter {
            it.isAnnotationPresent(org.junit.jupiter.api.Test::class.java)
        }
        assertEquals(7, methods.size)
        methods.forEach { assertEquals(Void.TYPE, it.returnType, it.name) }
    }

    @Test
    fun `worker command links bundled libraries and preserves separated script arguments`() = withFixture { root ->
        val bundle = fixture(root.resolve("app bundle"))
        val input = root.resolve("input with spaces")
        val invocation = GhidraInvocation(root.resolve("project"), "fixture", input, root.resolve("scripts"), listOf(
            GhidraPostScript("Export.java", listOf("argument with spaces", "--not-a-worker-option")),
        ))
        val command = bundle.analysisCommand(invocation)
        assertTrue(BundledGhidra.WORKER_CLASS in command)
        assertTrue(command[command.indexOf("-cp") + 1].contains("decomp-ghidra-bridge.jar"))
        assertTrue(command[command.indexOf("-cp") + 1].contains("Base.jar"))
        assertFalse(command.any { it.contains("analyzeHeadless") || it.contains("AnalyzeHeadless") })
        assertEquals(listOf("Export.java", "2", "argument with spaces", "--not-a-worker-option"), command.takeLast(4))
        assertTrue(input.toAbsolutePath().toString() in command)
    }

    @Test
    fun `missing corrupt extra and linked bundle files fail before worker launch`() = withFixture { root ->
        val bundle = fixture(root.resolve("bundle"))
        bundle.verify()
        val library = bundle.release.resolve("Ghidra/Features/Base/lib/Base.jar")
        library.writeText("modified")
        assertFailsWith<IllegalArgumentException> { bundle.probeCommand() }
        library.writeText("library fixture")
        val extra = bundle.root.resolve("extra.jar").also { it.writeText("unindexed") }
        assertFailsWith<IllegalArgumentException> { bundle.probeCommand() }
        Files.delete(extra)
        Files.delete(library)
        assertFailsWith<IllegalArgumentException> { bundle.probeCommand() }
        Files.createSymbolicLink(library, bundle.root.resolve("decomp-ghidra-bridge.jar"))
        assertFailsWith<IllegalArgumentException> { bundle.probeCommand() }
    }

    @Test
    fun `invalid duplicate and escaping checksum records are rejected`() = withFixture { root ->
        val bundle = fixture(root.resolve("bundle"))
        val manifest = bundle.root.resolve("bundle.sha256")
        val valid = manifest.readText()
        listOf("invalid\n", valid + valid, "${"0".repeat(64)}  ../escape\n").forEach { invalid ->
            manifest.writeText(invalid)
            assertFailsWith<IllegalArgumentException> { bundle.probeCommand() }
        }
        Files.delete(manifest)
        val error = assertFailsWith<IllegalArgumentException> { bundle.probeCommand() }
        assertTrue(error.message.orEmpty().contains("complete application distribution"))
    }

    @Test
    fun `incompatible release is rejected even with matching checksum inventory`() = withFixture { root ->
        val bundle = fixture(root.resolve("bundle"), version = "0.0.0")
        assertFailsWith<IllegalArgumentException> { bundle.probeCommand() }
    }

    @Test
    fun `installed worker initializes outside the application directory without an external installation`() = withFixture { root ->
        assumeTrue(System.getenv("RUN_REAL_GHIDRA") == "true", "installed Ghidra API probe is opt-in")
        val bundle = BundledGhidra.locate()
        assertTrue(bundle.root.toString().contains("install/llm_bin_patch/libexec/ghidra"))
        val output = root.resolve("probe.log")
        val process = ProcessBuilder(bundle.probeCommand()).directory(root.toFile()).apply {
            environment().remove("GHIDRA_HOME")
            redirectErrorStream(true)
            redirectOutput(output.toFile())
        }.start()
        try {
            assertTrue(process.waitFor(60, TimeUnit.SECONDS), "bundled Ghidra probe timed out")
            assertEquals(0, process.exitValue(), output.readText())
            assertTrue(output.readText().contains("Bundled Ghidra direct API ready: ${BundledGhidra.VERSION}"))
            bundle.verify()
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor()
        }
    }

    @Test
    fun `installed release retains exact original GCC provenance archive bytes and tree`() {
        assumeTrue(System.getenv("RUN_REAL_GHIDRA") == "true", "installed Ghidra provenance check is opt-in")
        val bundle = BundledGhidra.locate()
        val toolchain = GccCompilerEngineProfiles.load(Path.of("oracle/gcc/16.2.0/compiler-engines.json")).analysis
        val authentication = toolchain.authenticateGhidraInstallation(
            Path.of(System.getProperty("decompengine.ghidra.provenanceArchive")), bundle.release,
        )
        assertEquals(BundledGhidra.ARCHIVE_SHA256, authentication.archiveSha256)
        assertEquals(bundle.release, authentication.home)
        assertTrue(authentication.fileCount > 1000)
    }

    @Test
    fun `passive JVM sampler bounds transport and preserves blocked or failed worker outcomes`() = inControlTemporaryDirectory { root ->
        val workerSource = Path.of("ghidra-bridge/src/main/java/decompengine/ghidra/BundledGhidraWorker.java").readText()
        val helperStart = workerSource.indexOf("final class JvmMxBeanDiagnostics {")
        assertTrue(helperStart >= 0)
        val helper = root.resolve("JvmMxBeanDiagnostics.java")
        helper.writeText("package decompengine.ghidra;\n" + workerSource.substring(helperStart))
        val harness = root.resolve("JvmDiagnosticsHarness.java").also { it.writeText(diagnosticsHarness) }
        val classes = root.resolve("classes").createDirectories()
        val compilerOutput = java.io.ByteArrayOutputStream()
        val compiler = checkNotNull(javax.tools.ToolProvider.getSystemJavaCompiler())
        assertEquals(0, compiler.run(null, compilerOutput, compilerOutput,
            "-encoding", "UTF-8", "-Xlint:all", "-Werror", "-d", classes.toString(), helper.toString(), harness.toString()),
            compilerOutput.toString(Charsets.UTF_8))
        val home = root.resolve("home").createDirectories()
        val temporary = root.resolve("tmp").createDirectories()
        val output = root.resolve("sampler.log")
        val process = ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx128m", "-XX:ActiveProcessorCount=4",
            "-Duser.home=$home", "-Djava.io.tmpdir=$temporary", "-XX:-UsePerfData", "-cp", classes.toString(),
            "decompengine.ghidra.JvmDiagnosticsHarness",
        ).directory(root.toFile()).apply {
            environment()["JAVA_TOOL_OPTIONS"] = "-Duser.home=$home -Djava.io.tmpdir=$temporary -XX:-UsePerfData"
            environment().remove("JDK_JAVA_OPTIONS")
            environment().remove("_JAVA_OPTIONS")
            for (name in listOf("TMPDIR", "TMP", "TEMP", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "npm_config_cache")) {
                environment()[name] = temporary.toString()
            }
            redirectErrorStream(true)
            redirectOutput(output.toFile())
        }.start()
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "sampler harness exceeded 30 seconds")
            assertEquals(0, process.exitValue(), output.readText())
            val evidence = output.readText()
            assertEquals(9, evidence.lineSequence().count { it.startsWith("PASS ") }, evidence)
            println(evidence)
        } finally {
            if (process.isAlive) {
                process.destroyForcibly()
                assertTrue(process.waitFor(5, TimeUnit.SECONDS), "sampler harness survived cleanup")
            }
        }
    }

    private val diagnosticsHarness = """
        package decompengine.ghidra;
        import java.nio.charset.StandardCharsets;
        import java.util.*;
        import java.util.concurrent.*;
        import java.util.concurrent.atomic.*;

        public final class JvmDiagnosticsHarness {
            private static void require(boolean condition, String message) {
                if (!condition) throw new AssertionError(message);
            }
            private static void await(CountDownLatch latch) throws Exception {
                require(latch.await(3, TimeUnit.SECONDS), "latch timed out");
            }
            private static void pause(CountDownLatch latch) {
                try { latch.await(); }
                catch (InterruptedException failure) { throw new AssertionError(failure); }
            }
            private static final class Frames implements JvmMxBeanDiagnostics.Sink {
                final List<byte[]> frames = Collections.synchronizedList(new ArrayList<>());
                final Semaphore written = new Semaphore(0);
                final CountDownLatch terminal = new CountDownLatch(1);
                public void write(byte[] frame) {
                    frames.add(frame.clone());
                    written.release();
                    if (text(frame).contains("\"kind\":\"terminal\"")) terminal.countDown();
                }
                String all() { synchronized (frames) { return String.join("", frames.stream().map(JvmDiagnosticsHarness::text).toList()); } }
                void validate() throws Exception {
                    long bytes = 0;
                    long previousElapsed = 0;
                    synchronized (frames) {
                        require(frames.size() <= 640, "record limit");
                        for (int index = 0; index < frames.size(); index++) {
                            byte[] frame = frames.get(index);
                            bytes += frame.length;
                            require(frame.length <= 4096, "frame limit");
                            String value = StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(frame)).toString();
                            require(value.startsWith("\n" + JvmMxBeanDiagnostics.PREFIX) && value.endsWith("\n"), "framing");
                            require(value.indexOf('\n', 1) == value.length() - 1, "unescaped newline");
                            require(value.contains("\"sequence\":" + index + ","), "sequence gap");
                            var elapsed = java.util.regex.Pattern.compile("\\\"elapsedNanos\\\":([0-9]+)").matcher(value);
                            require(elapsed.find(), "elapsed field");
                            long now = Long.parseLong(elapsed.group(1));
                            require(now >= previousElapsed, "elapsed regressed");
                            previousElapsed = now;
                            if (value.contains("\"kind\":\"terminal\"")) {
                                require(index == frames.size() - 1, "record after terminal");
                                require(value.contains("\"shutdownDrainConfirmed\":false"), "invented drain authority");
                            }
                        }
                    }
                    require(bytes <= 5L * 1024 * 1024, "total byte limit");
                }
            }
            private static String text(byte[] bytes) { return new String(bytes, StandardCharsets.UTF_8); }
            private static class Metrics implements JvmMxBeanDiagnostics.Metrics {
                final Set<String> threads = ConcurrentHashMap.newKeySet();
                public Map<String, Object> initial() {
                    threads.add(Thread.currentThread().getName());
                    Map<String, Object> result = JvmMxBeanDiagnostics.object();
                    result.put("jvmName", "VM \"雪\"\nname");
                    result.put("jvmVendor", null);
                    result.put("jvmVersion", "fixture");
                    result.put("javaVersion", "21");
                    result.put("processors", 4);
                    result.put("heap", null);
                    result.put("collectors", List.of("fixture collector"));
                    return result;
                }
                public Map<String, Object> sample() {
                    threads.add(Thread.currentThread().getName());
                    Map<String, Object> result = JvmMxBeanDiagnostics.object();
                    result.put("jvmCpuNanos", null);
                    result.put("heap", null);
                    result.put("pools", null);
                    result.put("collectors", null);
                    return result;
                }
            }
            private static JvmMxBeanDiagnostics create(JvmMxBeanDiagnostics.Metrics metrics, JvmMxBeanDiagnostics.Sink sink, long interval) {
                JvmMxBeanDiagnostics result = new JvmMxBeanDiagnostics(metrics, sink, System::nanoTime, interval);
                result.start();
                return result;
            }
            private static void normal() throws Exception {
                Metrics metrics = new Metrics(); Frames frames = new Frames();
                CountDownLatch sampled = new CountDownLatch(1);
                JvmMxBeanDiagnostics sampler = create(metrics, frame -> {
                    frames.write(frame);
                    if (text(frame).contains("\"kind\":\"sample\"")) sampled.countDown();
                }, TimeUnit.MILLISECONDS.toNanos(2));
                await(sampled);
                sampler.phase(JvmMxBeanDiagnostics.Phase.EXPORTER, "ExportProgramModel.java");
                sampler.finish(true);
                await(frames.terminal); frames.validate();
                require(frames.all().contains("\"jvmCpuNanos\":null"), "unavailable CPU not explicit");
                require(frames.all().contains("VM \\\"雪\\\"\\nname"), "UTF-8/JSON escaping");
                require(frames.all().contains("\"outcome\":\"success\""), "success changed");
                require(metrics.threads.equals(Set.of("bundled-ghidra-jvm-diagnostics")), "metrics ran on producer");
                require(JvmMxBeanDiagnostics.SAMPLE_NANOS == TimeUnit.SECONDS.toNanos(15), "production cadence");
                System.out.println("PASS normal-null-metrics-encoding-one-daemon");
            }
            private static void stalledMetrics() throws Exception {
                CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
                Metrics metrics = new Metrics() { public Map<String, Object> initial() { entered.countDown(); pause(release); return super.initial(); } };
                Frames frames = new Frames(); JvmMxBeanDiagnostics sampler = create(metrics, frames, Long.MAX_VALUE);
                await(entered);
                long began = System.nanoTime();
                for (int index = 0; index < 40; index++) sampler.phase(JvmMxBeanDiagnostics.Phase.GUARD, null);
                require(System.nanoTime() - began < TimeUnit.SECONDS.toNanos(1), "producer blocked");
                sampler.finish(false);
                require(System.nanoTime() - began < TimeUnit.SECONDS.toNanos(1), "stalled metrics delayed outcome");
                release.countDown(); await(frames.terminal); frames.validate();
                String all = frames.all();
                require(all.contains("queue_saturation") && all.contains("drain_timeout"), "loss not reported");
                require(all.contains("\"outcome\":\"failure\"") && all.contains("\"priorRecordsComplete\":false"), "failure outcome changed");
                require(frames.frames.stream().filter(f -> text(f).contains("\"kind\":\"phase\"")).count() == 14, "pending ordinary queue not bounded at14");
                System.out.println("PASS stalled-metrics-queue-reserves-failure-outcome");
            }
            private static void blockedSink() throws Exception {
                CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
                Frames frames = new Frames();
                JvmMxBeanDiagnostics sampler = create(new Metrics(), frame -> { entered.countDown(); pause(release); frames.write(frame); }, Long.MAX_VALUE);
                await(entered); long began = System.nanoTime();
                sampler.phase(JvmMxBeanDiagnostics.Phase.GUARD, null);
                sampler.finish(true);
                sampler.finish(false); // A repeated finalizer cannot rewrite the original outcome.
                require(System.nanoTime() - began < TimeUnit.SECONDS.toNanos(1), "blocked sink delayed worker");
                release.countDown(); await(frames.terminal); frames.validate();
                require(frames.all().contains("drain_timeout") && frames.all().contains("\"outcome\":\"success\""), "blocked sink/repeated finalizer outcome");
                System.out.println("PASS blocked-output-bounded-drain-idempotent-outcome");
            }
            private static void failedSink() throws Exception {
                CountDownLatch attempted = new CountDownLatch(1); AtomicInteger writes = new AtomicInteger();
                JvmMxBeanDiagnostics sampler = create(new Metrics(), frame -> {
                    writes.incrementAndGet(); attempted.countDown(); throw new java.io.IOException("fixture output failure");
                }, Long.MAX_VALUE);
                await(attempted);
                RuntimeException original = new RuntimeException("original worker failure");
                try { try { throw original; } finally { sampler.finish(false); } }
                catch (RuntimeException observed) { require(observed == original, "diagnostics replaced worker failure"); }
                require(writes.get() == 1, "output failure recursively retried");
                System.out.println("PASS failed-output-preserves-original-exception");
            }
            private static void cap() throws Exception {
                Frames frames = new Frames(); JvmMxBeanDiagnostics sampler = create(new Metrics(), frames, Long.MAX_VALUE);
                require(frames.written.tryAcquire(3, TimeUnit.SECONDS), "initial frame");
                for (int attempts = 0; frames.frames.size() < 639 && attempts < 1500; attempts++) {
                    sampler.phase(JvmMxBeanDiagnostics.Phase.GUARD, null);
                    frames.written.tryAcquire(10, TimeUnit.MILLISECONDS);
                }
                require(frames.frames.size() == 639, "ordinary cap and truncation reserve");
                for (int index = 0; index < 20; index++) sampler.phase(JvmMxBeanDiagnostics.Phase.FINALIZATION, null);
                sampler.finish(true); await(frames.terminal); frames.validate();
                require(frames.frames.size() == 640, "terminal reserve");
                require(frames.all().contains("record_limit"), "record cap not reported");
                System.out.println("PASS record-byte-frame-terminal-bounds");
            }
            private static void oversized() throws Exception {
                Metrics metrics = new Metrics() { public Map<String, Object> initial() {
                    Map<String, Object> result = super.initial();
                    result.put("collectors", Collections.nCopies(16, "雪".repeat(80)));
                    return result;
                } };
                Frames frames = new Frames(); JvmMxBeanDiagnostics sampler = create(metrics, frames, Long.MAX_VALUE);
                sampler.finish(true); await(frames.terminal); frames.validate();
                require(frames.all().contains("frame_limit") && !frames.all().contains("雪"), "oversized UTF-8 frame leaked");
                System.out.println("PASS oversized-UTF8-record-is-explicit-loss");
            }
            private static void interrupted() throws Exception {
                CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
                Frames frames = new Frames();
                JvmMxBeanDiagnostics sampler = create(new Metrics(), frame -> { entered.countDown(); pause(release); frames.write(frame); }, Long.MAX_VALUE);
                await(entered);
                Thread.currentThread().interrupt(); sampler.finish(false);
                require(Thread.interrupted(), "original interrupt not preserved");
                release.countDown(); await(frames.terminal); frames.validate();
                require(frames.all().contains("drain_timeout"), "interrupted drain not reported");
                sampler.phase(JvmMxBeanDiagnostics.Phase.GUARD, null);
                require(text(frames.frames.get(frames.frames.size() - 1)).contains("\"kind\":\"terminal\""), "late producer changed terminal");
                System.out.println("PASS interrupted-drain-sealed-admission-terminal-last");
            }
            private static void concurrentClose() throws Exception {
                var queueField = JvmMxBeanDiagnostics.class.getDeclaredField("queue");
                queueField.setAccessible(true);
                for (int iteration = 0; iteration < 20; iteration++) {
                    Frames frames = new Frames();
                    JvmMxBeanDiagnostics sampler = create(new Metrics(), frames, Long.MAX_VALUE);
                    CountDownLatch firstOffered = new CountDownLatch(1);
                    Thread producer = new Thread(() -> {
                        sampler.phase(JvmMxBeanDiagnostics.Phase.GUARD, null);
                        firstOffered.countDown();
                        for (int index = 0; index < 200; index++) sampler.phase(JvmMxBeanDiagnostics.Phase.GUARD, null);
                    });
                    producer.start(); await(firstOffered); sampler.finish(true);
                    producer.join(2000); require(!producer.isAlive(), "phase producer failed to stop");
                    await(frames.terminal); frames.validate();
                    require(((Deque<?>) queueField.get(sampler)).isEmpty(), "admitted event stranded after terminal");
                }
                System.out.println("PASS concurrent-producers-close-no-stranded-records");
            }
            private static void actualJdk() throws Exception {
                Frames frames = new Frames(); CountDownLatch sampled = new CountDownLatch(1);
                JvmMxBeanDiagnostics sampler = create(new JvmMxBeanDiagnostics.JdkMetrics(), frame -> {
                    frames.write(frame);
                    if (text(frame).contains("\"kind\":\"sample\"")) sampled.countDown();
                }, TimeUnit.MILLISECONDS.toNanos(2));
                await(sampled); sampler.finish(true); await(frames.terminal); frames.validate();
                require(frames.all().contains("\"pools\":[") && frames.all().contains("\"postGc\":"), "real JDK pool metrics absent");
                require(!frames.all().contains("frame_limit"), "real JDK sample exceeds atomic frame");
                System.out.print(frames.all());
                System.out.println("PASS actual-JDK-MXBeans-available-without-attach-or-GC");
            }
            public static void main(String[] arguments) throws Exception {
                normal(); stalledMetrics(); blockedSink(); failedSink(); cap(); oversized(); interrupted(); concurrentClose(); actualJdk();
            }
        }
    """.trimIndent()

    private fun fixture(root: Path, version: String = BundledGhidra.VERSION): BundledGhidra {
        val files = mapOf(
            "decomp-ghidra-bridge.jar" to "bridge fixture",
            "ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/Features/Base/lib/Base.jar" to "library fixture",
            "ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/application.properties" to "application.version=$version\napplication.release.name=PUBLIC\n",
        )
        files.forEach { (relative, content) ->
            root.resolve(relative).also { it.parent.createDirectories(); it.writeText(content) }
        }
        root.resolve("bundle.sha256").writeText(files.toSortedMap().entries.joinToString("") { (relative, content) ->
            "${sha256(content.toByteArray())}  $relative\n"
        })
        return BundledGhidra.at(root)
    }

    private fun withFixture(block: (Path) -> Unit) {
        val root = createTempDirectory("bundled-ghidra-test-")
        try {
            block(root)
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}
