package decompengine.analysis

import decompengine.oracle.fulltree.inControlTemporaryDirectory
import decompengine.project.sha256
import decompengine.project.RecoveredCallSitesTest
import decompengine.oracle.gcc.GccCompilerEngineProfiles
import decompengine.oracle.gcc.authenticateGhidraInstallation
import decompengine.oracle.gcc.GccBundledGhidraDeploymentReference
import decompengine.oracle.fulltree.inControlTemporaryDirectory
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.jar.JarFile
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
import org.junit.jupiter.api.parallel.ResourceLock
import org.junit.jupiter.api.parallel.Resources

@ResourceLock(Resources.SYSTEM_PROPERTIES)
class BundledGhidraTest {
    @Test
    fun `installed native collector source and complete compiled closure match the production reference`() {
        assumeTrue(System.getenv("RUN_REAL_GHIDRA") == "true" || System.getenv("RUN_REAL_GHIDRA_NATIVE_CALLS") == "true",
            "installed native collector packaging check is opt-in")
        val repository = Path.of(System.getProperty("user.dir")).toRealPath()
        val evidenceParent = repository.resolve("build/native-call-packaging-tests")
        Files.createDirectories(evidenceParent)
        val work = Files.createTempDirectory(evidenceParent, "installed-native-")
        try {
            val processHome = Files.createDirectory(work.resolve("home"))
            val temporary = Files.createDirectory(work.resolve("tmp"))
            val cache = Files.createDirectory(work.resolve("cache"))
            val sourceName = "ghidra-bridge/src/main/java/ExportNativeCallsV1.java"
            val source = repository.resolve(sourceName).toRealPath()
            assertFalse(Files.exists(repository.resolve("src/main/resources/ghidra_scripts/ExportNativeCallsV1.java"), LinkOption.NOFOLLOW_LINKS),
                "native collector resource must be generated from its compiled Java source")
            val inventoryLog = work.resolve("tracked-source.log")
            val inventory = ProcessBuilder("git", "ls-files", "--", "*ExportNativeCallsV1.java")
                .directory(repository.toFile()).apply {
                    environment()["HOME"] = processHome.toString()
                    environment()["TMPDIR"] = temporary.toString()
                    environment()["XDG_CACHE_HOME"] = cache.toString()
                    environment()["GIT_CONFIG_NOSYSTEM"] = "1"
                    redirectErrorStream(true)
                    redirectOutput(inventoryLog.toFile())
                }.start()
            try {
                assertTrue(inventory.waitFor(10, TimeUnit.SECONDS), "tracked collector source inventory timed out")
                assertEquals(0, inventory.exitValue(), inventoryLog.readText())
                assertEquals(listOf(sourceName), inventoryLog.readText().lineSequence().filter(String::isNotBlank).toList(),
                    "the collector must have one tracked source and no tracked resource copy")
            } finally {
                if (inventory.isAlive) inventory.destroyForcibly()
                assertTrue(inventory.waitFor(5, TimeUnit.SECONDS), "tracked source inventory could not be reaped")
            }
            val installed = repository.resolve("build/install/llm_bin_patch").toRealPath()
            val libraries = Files.list(installed.resolve("lib")).use { paths -> paths.filter {
                Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) && it.fileName.toString().endsWith(".jar")
            }.sorted().limit(513).toList() }
            assertTrue(libraries.size in 1..512)
            val application = libraries.single { path -> JarFile(path.toFile(), false).use {
                it.getJarEntry("decompengine/oracle/gcc/GccBundledGhidraDeploymentReference.class") != null
            } }
            val tests = Path.of(BundledGhidraInstalledNativeCollectorProbe::class.java.protectionDomain.codeSource.location.toURI()).toRealPath()
            assertTrue(Files.isDirectory(tests), "installed probe must come from the test class directory")
            val compiledClasses = repository.resolve("ghidra-bridge/build/classes/java/main").toRealPath()
            val log = work.resolve("installed-native-reference.log")
            val command = listOf(Path.of(System.getProperty("java.home"), "bin/java").toString(),
                "-Duser.home=$processHome", "-Djava.io.tmpdir=$temporary", "-Djna.tmpdir=$temporary", "-XX:-UsePerfData",
                "-Ddecompengine.oracle.nativeLibraryDirectory=${installed.resolve("libexec/oracle-native")}",
                "-cp", (listOf(tests) + libraries).joinToString(File.pathSeparator),
                BundledGhidraInstalledNativeCollectorProbe::class.java.name,
                application.toString(), installed.resolve("libexec/ghidra").toString(), source.toString(), compiledClasses.toString())
            val process = ProcessBuilder(command).directory(work.toFile()).apply {
                for (name in listOf("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH", "GHIDRA_HOME")) environment().remove(name)
                environment()["HOME"] = processHome.toString()
                environment()["TMPDIR"] = temporary.toString()
                environment()["XDG_CONFIG_HOME"] = processHome.toString()
                environment()["XDG_DATA_HOME"] = processHome.toString()
                environment()["XDG_CACHE_HOME"] = cache.toString()
                redirectErrorStream(true)
                redirectOutput(log.toFile())
            }.start()
            try {
                assertTrue(process.waitFor(30, TimeUnit.SECONDS), "installed native reference check timed out")
                assertTrue(Files.size(log) <= 64 * 1024, "installed native reference diagnostics exceeded the bound")
                val diagnostic = log.readText()
                assertEquals(0, process.exitValue(), diagnostic)
                assertTrue(diagnostic.lineSequence().any { it.startsWith("installed-native-collector-reference-verified:") }, diagnostic)
            } finally {
                if (process.isAlive) process.destroyForcibly()
                assertTrue(process.waitFor(5, TimeUnit.SECONDS), "installed native reference check could not be reaped")
                process.outputStream.close()
                process.inputStream.close()
                process.errorStream.close()
            }
        } finally {
            Files.walk(work).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
    @Test
    fun `compiled export guard admits owned candidates but rejects unknown names malformed framing and failed exports`() {
        val root = Path.of("build/bundled-export-guard-tests").toAbsolutePath().createDirectories()
        val work = Files.createTempDirectory(root, "guard-")
        fun source(name: String, text: String): Path = work.resolve(name).also {
            it.parent.createDirectories()
            it.writeText(text.trimIndent())
        }
        val scriptStub = source("ghidra/app/script/GhidraScript.java", """
            package ghidra.app.script;
            public abstract class GhidraScript {
                public static String[] arguments;
                public static final java.util.List<String> invocations = new java.util.ArrayList<>();
                public static boolean fail;
                protected Object currentProgram, monitor;
                protected abstract void run() throws Exception;
                public final void execute() throws Exception { run(); }
                protected String[] getScriptArgs() { return arguments; }
                protected void runScript(String name, String[] args) throws Exception {
                    if (fail) throw new IllegalStateException("export failed");
                    invocations.add(name + ":" + java.util.Arrays.toString(args));
                }
            }
        """)
        val workerStub = source("decompengine/ghidra/BundledGhidraWorker.java", """
            package decompengine.ghidra;
            public final class BundledGhidraWorker {
                public static boolean completed;
                public static void exportsCompleted() { completed = true; }
                public static void diagnosticsGuard() {}
                public static void diagnosticsExporter(String name) {}
                public static void diagnosticsFinalization() {}
            }
        """)
        val nativeStub = source("ExportNativeCallsV1.java", """
            public final class ExportNativeCallsV1 {
                public static void collect(Object program, Object monitor, String[] args) {
                    ghidra.app.script.GhidraScript.invocations.add("native:" + java.util.Arrays.toString(args));
                }
            }
        """)
        val probe = source("GuardProbe.java", """
            import ghidra.app.script.GhidraScript;
            import decompengine.ghidra.BundledGhidraWorker;
            public final class GuardProbe {
                private static void check(boolean valid) {
                    if (!valid) throw new AssertionError("bundled export guard contract failed");
                }
                private static void prepare(String... args) {
                    GhidraScript.arguments = args;
                    GhidraScript.invocations.clear();
                    GhidraScript.fail = false;
                    BundledGhidraWorker.completed = false;
                }
                public static void verify() throws Exception {
                    for (String name : new String[] {"ExportProgramModel.java", "ExportProgramModelOwned.java",
                            "ExportRecoveredCallSites.java", "ExportDecompiledC.java", "ExportNativeCallsV1.class"}) {
                        prepare(name, "2", "argument with spaces", "--not-an-option");
                        new RunBundledExports().execute();
                        check(BundledGhidraWorker.completed);
                        String target = name.equals("ExportNativeCallsV1.class") ? "native" : name;
                        check(GhidraScript.invocations.equals(java.util.List.of(
                            target + ":[argument with spaces, --not-an-option]")));
                    }
                    // The actual ordinary model/call pair must preserve the candidate protocol.
                    prepare("ExportProgramModelOwned.java", "6", "exporter-hash", "tool-hash", "full",
                        "/reports/program_model.json", "owned-model-candidate-v1", "/reports/.model.candidate",
                        "ExportRecoveredCallSites.java", "4", "calls-hash", "tool-hash",
                        "/reports/.model.candidate", "/reports/.calls.candidate");
                    new RunBundledExports().execute();
                    check(BundledGhidraWorker.completed && GhidraScript.invocations.size() == 2);
                    check(GhidraScript.invocations.get(0).endsWith(
                        "owned-model-candidate-v1, /reports/.model.candidate]"));
                    check(GhidraScript.invocations.get(1).endsWith(
                        "/reports/.model.candidate, /reports/.calls.candidate]"));
                    for (String[] args : new String[][] {
                        {}, {"ExportProgramModelOwned.java"}, {"ExportProgramModelOwned.java", "-1"},
                        {"ExportProgramModelOwned.java", "17"}, {"ExportProgramModelOwned.java", "1"},
                        {"ExportProgramModelOwned.java", "not-a-count"}, {"Unknown.java", "0"},
                        {"../ExportProgramModelOwned.java", "0"}, {"ExportProgramModelOwned.class", "0"},
                        {"ExportProgramModelOwned.java.extra", "0"}, {"ExportNativeCallsV1.java", "0"}
                    }) {
                        prepare(args);
                        try {
                            new RunBundledExports().execute();
                            throw new AssertionError("invalid exporter invocation was accepted");
                        } catch (IllegalArgumentException expected) {
                            check(!BundledGhidraWorker.completed && GhidraScript.invocations.isEmpty());
                        }
                    }
                    prepare("ExportProgramModelOwned.java", "0", "ExportRecoveredCallSites.java", "0");
                    GhidraScript.fail = true;
                    try {
                        new RunBundledExports().execute();
                        throw new AssertionError("export failure was swallowed");
                    } catch (IllegalStateException expected) {
                        check(expected.getMessage().equals("export failed"));
                        check(!BundledGhidraWorker.completed && GhidraScript.invocations.isEmpty());
                    }
                }
            }
        """)
        val guard = Path.of("ghidra-bridge/src/main/java/RunBundledExports.java").toAbsolutePath()
        val compiler = checkNotNull(javax.tools.ToolProvider.getSystemJavaCompiler())
        assertEquals(0, compiler.run(null, null, null, "-proc:none", "-encoding", "UTF-8", "-d", work.toString(),
            scriptStub.toString(), workerStub.toString(), nativeStub.toString(), guard.toString(), probe.toString()))
        java.net.URLClassLoader(arrayOf(work.toUri().toURL()), null).use { loader ->
            loader.loadClass("GuardProbe").getMethod("verify").invoke(null)
        }
    }

    @Test
    fun `shared worker command rejects empty duplicate and ambiguous classpaths`() {
        val java = Path.of("/runtime/bin/java")
        val release = Path.of("/application/ghidra")
        val bridge = Path.of("/application/bridge.jar")
        for (entries in listOf(emptyList(), listOf(bridge, bridge), listOf(Path.of("/application/part:other.jar")))) {
            assertFailsWith<IllegalArgumentException> { GhidraWorkerCommand.prefix(java, release, entries) }
        }
        val prefix = GhidraWorkerCommand.prefix(java, release, listOf(bridge))
        assertFalse(prefix.any { it.startsWith("-Duser.home=") || it.startsWith("-Djava.io.tmpdir=") || it.startsWith("-Djna.tmpdir=") })
        assertFalse("-XX:-UsePerfData" in prefix, "contained runtimes own their exact shared-prefix policy")
    }

    @Test
    fun `ordinary worker forwards only normalized parent directories without changing its resource policy`() = withFixture { root ->
        val bundle = fixture(root.resolve("bundle"))
        val workingDirectory = Path.of("").toAbsolutePath().normalize()
        val home = root.resolve("parent home = kept").createDirectories()
        val temporary = root.resolve("parent temp").createDirectories()
        val nativeTemporary = root.resolve("native temp").createDirectories()
        withParentDirectoryProperties(mapOf(
            "user.home" to workingDirectory.relativize(home).toString(),
            "java.io.tmpdir" to temporary.toString(),
            "jna.tmpdir" to workingDirectory.relativize(nativeTemporary).toString(),
            "decompengine.unrelated.parent.property" to "not-forwarded",
        )) {
            val command = bundle.probeCommand()
            assertEquals(listOf(
                "-Duser.home=$home", "-Djava.io.tmpdir=$temporary", "-Djna.tmpdir=$nativeTemporary",
            ), command.filter { it.startsWith("-Duser.home=") || it.startsWith("-Djava.io.tmpdir=") || it.startsWith("-Djna.tmpdir=") })
            assertEquals(1, command.count { it == "-XX:-UsePerfData" })
            assertTrue("-Xmx2G" in command)
            assertTrue("-Xshare:off" in command)
            assertFalse(command.any { it.contains("decompengine.unrelated.parent.property") || it.contains("not-forwarded") })
            assertEquals("probe", command.last())
        }
    }

    @Test
    fun `ordinary worker does not invent an absent JNA directory`() = withFixture { root ->
        val bundle = fixture(root.resolve("bundle"))
        withParentDirectoryProperties(mapOf("jna.tmpdir" to null)) {
            assertFalse(bundle.probeCommand().any { it.startsWith("-Djna.tmpdir=") })
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
    fun `installed worker requires the exact parent permit before Ghidra initialization`() {
        assumeTrue(System.getenv("RUN_REAL_GHIDRA") == "true", "installed Ghidra launch permit check is opt-in")
        inControlTemporaryDirectory { root ->
            // Authenticate once, then reuse the same installed bridge/classpath for every gate control.
            val probe = BundledGhidra.locate().probeCommand()
            assertEquals("probe", probe.last())
            assertEquals(BundledGhidra.WORKER_CLASS, probe[probe.lastIndex - 2])
            assertFalse("await-parent-launch" in probe, "legacy probe commands must remain ungated")
            val ready = "Bundled Ghidra direct API ready: ${BundledGhidra.VERSION}"
            val cases = listOf("valid" to "1\n", "eof" to "", "wrong-token" to "0\n", "wrong-terminator" to "1x", "truncated" to "1")
            for ((name, permit) in cases) {
                val valid = name == "valid"
                val work = root.resolve(name).createDirectories()
                val home = work.resolve("home").createDirectories()
                val temporary = work.resolve("tmp").createDirectories()
                val cache = work.resolve("cache").createDirectories()
                val output = work.resolve("probe.log")
                // Rejected permits must fail before even inspecting the release. If initialization
                // moves before the gate, this missing path causes a different failure immediately.
                val missingRelease = work.resolve("deliberately-missing-release")
                assertFalse(Files.exists(missingRelease))
                val release = if (valid) probe[probe.lastIndex - 1] else missingRelease.toString()
                val directoryNames = listOf("user.home", "java.io.tmpdir", "jna.tmpdir")
                val command = listOf(probe.first(), "-Duser.home=$home", "-Djava.io.tmpdir=$temporary", "-Djna.tmpdir=$temporary") +
                    probe.drop(1).dropLast(2).filterNot { option -> directoryNames.any { option.startsWith("-D$it=") } } +
                    listOf(release, "await-parent-launch", probe.last())
                val process = ProcessBuilder(command).directory(work.toFile()).apply {
                    environment().remove("GHIDRA_HOME")
                    environment()["TMPDIR"] = temporary.toString()
                    environment()["XDG_CACHE_HOME"] = cache.toString()
                    redirectErrorStream(true)
                    redirectOutput(output.toFile())
                }.start()
                try {
                    assertFalse(process.waitFor(250, TimeUnit.MILLISECONDS), "$name worker exited before receiving a permit")
                    assertFalse(output.readText().contains(ready), "$name worker reported readiness before parent authorization")
                    process.outputStream.use { it.write(permit.toByteArray(Charsets.US_ASCII)) }
                    assertTrue(process.waitFor(if (valid) 60 else 10, TimeUnit.SECONDS), "$name gated probe timed out")
                    val diagnostic = output.readText()
                    assertEquals(if (valid) 0 else 1, process.exitValue(), diagnostic)
                    if (valid) {
                        assertTrue(diagnostic.contains(ready), diagnostic)
                        assertFalse(diagnostic.contains("Parent did not authorize"), diagnostic)
                    } else {
                        assertTrue(diagnostic.lineSequence().any {
                            it == "java.lang.IllegalStateException: Parent did not authorize bundled analysis launch"
                        }, diagnostic)
                        assertFalse(diagnostic.contains(ready), diagnostic)
                    }
                } finally {
                    if (process.isAlive) process.destroyForcibly()
                    try {
                        assertTrue(process.waitFor(5, TimeUnit.SECONDS), "$name probe could not be reaped")
                    } finally {
                        process.outputStream.close()
                        process.inputStream.close()
                        process.errorStream.close()
                    }
                }
            }
        }
    }

    @Test
    fun `installed release retains exact original GCC provenance archive bytes and tree`() {
        assumeTrue(System.getenv("RUN_REAL_GHIDRA") == "true", "installed Ghidra provenance check is opt-in")
        val bundle = BundledGhidra.locate()
        val toolchain = GccCompilerEngineProfiles.load(Path.of("oracle/gcc/16.2.0/compiler-engines-exporter17.json")).analysis
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
            private static void phaseAndAwait(JvmMxBeanDiagnostics sampler, Frames frames, String exporter) throws Exception {
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
                while (System.nanoTime() < deadline) {
                    sampler.phase(JvmMxBeanDiagnostics.Phase.EXPORTER, exporter);
                    long attemptDeadline = Math.min(deadline, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(50));
                    while (System.nanoTime() < attemptDeadline) {
                        if (frames.all().contains(exporter)) return;
                        Thread.sleep(1);
                    }
                }
                throw new AssertionError("phase event missing: " + exporter);
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
                phaseAndAwait(sampler, frames, "ExportProgramModelOwned.java");
                phaseAndAwait(sampler, frames, "ExportNativeCallsV1.class");
                sampler.finish(true);
                await(frames.terminal); frames.validate();
                require(frames.all().contains("\"exporter\":\"ExportProgramModelOwned.java\""), "owned program-model exporter phase missing");
                require(frames.all().contains("\"exporter\":\"ExportNativeCallsV1.class\""), "native-call exporter phase missing");
                require(!frames.all().contains("internal_failure"), "known exporter rejected by diagnostics phase validation");
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
        val parent = Path.of("build/bundled-ghidra-directory-tests").toAbsolutePath().normalize().createDirectories()
        val root = createTempDirectory(parent, "bundled-ghidra-test-")
        try {
            val home = root.resolve("home").createDirectories()
            val temporary = root.resolve("tmp").createDirectories()
            withParentDirectoryProperties(mapOf(
                "user.home" to home.toString(), "java.io.tmpdir" to temporary.toString(), "jna.tmpdir" to temporary.toString(),
            )) { block(root) }
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun withParentDirectoryProperties(values: Map<String, String?>, block: () -> Unit) {
        val previous = values.keys.associateWith(System::getProperty)
        try {
            values.forEach { (name, value) -> if (value == null) System.clearProperty(name) else System.setProperty(name, value) }
            block()
        } finally {
            previous.forEach { (name, value) -> if (value == null) System.clearProperty(name) else System.setProperty(name, value) }
        }
    }
}

/** Runs with test classes and installed JARs only; development reference overrides are absent. */
object BundledGhidraInstalledNativeCollectorProbe {
    @JvmStatic
    fun main(arguments: Array<String>) {
        check(arguments.size == 4)
        val expectedApplication = Path.of(arguments[0]).toRealPath()
        val expectedBundle = Path.of(arguments[1]).toRealPath()
        val trackedSource = Path.of(arguments[2]).toRealPath()
        val compiledClasses = Path.of(arguments[3]).toRealPath()
        val application = Path.of(GccBundledGhidraDeploymentReference::class.java.protectionDomain.codeSource.location.toURI()).toRealPath()
        check(application == expectedApplication && Files.isRegularFile(application, LinkOption.NOFOLLOW_LINKS)) {
            "native collector probe did not load the exact installed application JAR"
        }
        check(System.getProperty("decompengine.oracle.gcc.bundledGhidraReference") == null &&
            System.getProperty("decompengine.oracle.gcc.bundledGhidraRoot") == null) {
            "installed native reference check cannot use development fallbacks"
        }
        GccBundledGhidraDeploymentReference.open().use { deployment ->
            check(deployment.bundleRoot == expectedBundle)
            val reference = deployment.reference
            val collector = checkNotNull(reference.nativeCallCollector) { "installed reference has no native collector identity" }
            fun collectorClass(name: String): Boolean = name.substringAfterLast('/').let {
                it.startsWith("ExportNativeCallsV1") && it.endsWith(".class")
            }
            val declaredClasses = reference.entries.values.filter { it.path.startsWith("scripts/") && collectorClass(it.path) }
                .associateBy { it.path }
            check("scripts/ExportNativeCallsV1.class" in declaredClasses && declaredClasses.size > 1) {
                "installed reference omits the collector's primary or nested compiled classes"
            }
            val actualClasses = Files.list(expectedBundle.resolve("scripts")).use { paths ->
                paths.filter { collectorClass(it.fileName.toString()) }.limit(513).toList()
            }
            check(actualClasses.size in 2..512)
            check(actualClasses.map { "scripts/${it.fileName}" }.toSet() == declaredClasses.keys) {
                "installed collector classes differ from the complete declared closure"
            }
            val compiled = Files.list(compiledClasses).use { paths -> paths.filter { collectorClass(it.fileName.toString()) }.limit(513).toList() }
            check(compiled.size in 2..512 && compiled.map { "scripts/${it.fileName}" }.toSet() == declaredClasses.keys) {
                "installed native collector closure omits or adds classes from the actual Java compilation"
            }
            for (path in actualClasses) {
                check(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && path.toRealPath() == path)
                val entry = declaredClasses.getValue("scripts/${path.fileName}")
                val expectedBytes = checkNotNull(entry.bytes)
                check(entry.kind == "file" && expectedBytes == Files.size(path) && expectedBytes in 1..128L * 1024 * 1024)
                val bytes = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { it.readNBytes(expectedBytes.toInt() + 1) }
                check(bytes.size.toLong() == entry.bytes && sha256(bytes) == entry.sha256) {
                    "installed native collector class does not match its independent identity: ${entry.path}"
                }
                val compiledPath = compiledClasses.resolve(path.fileName)
                check(Files.isRegularFile(compiledPath, LinkOption.NOFOLLOW_LINKS) && compiledPath.toRealPath() == compiledPath &&
                    Files.size(compiledPath) == expectedBytes)
                val compiledBytes = Files.newInputStream(compiledPath, LinkOption.NOFOLLOW_LINKS).use { it.readNBytes(expectedBytes.toInt() + 1) }
                check(compiledBytes.contentEquals(bytes)) { "installed collector bytes differ from their actual Java compilation" }
            }
            val primary = declaredClasses.getValue("scripts/ExportNativeCallsV1.class")
            check(primary.bytes == collector.classBytes && primary.sha256 == collector.classSha256)
            JarFile(expectedBundle.resolve("decomp-ghidra-bridge.jar").toFile(), false).use { bridge ->
                val entries = bridge.entries().asSequence().take(200_001).toList()
                check(entries.size <= 200_000 && entries.none { collectorClass(it.name) }) {
                    "bridge JAR contains duplicate native collector implementations"
                }
            }
            check(Files.isRegularFile(trackedSource, LinkOption.NOFOLLOW_LINKS) && Files.size(trackedSource) in 1..4L * 1024 * 1024)
            val sourceBytes = Files.newInputStream(trackedSource, LinkOption.NOFOLLOW_LINKS).use { it.readNBytes(4 * 1024 * 1024 + 1) }
            check(sourceBytes.size.toLong() == collector.sourceBytes && sha256(sourceBytes) == collector.sourceSha256)
            JarFile(application.toFile(), false).use { jar ->
                val entries = jar.entries().asSequence().take(200_001).toList()
                check(entries.size <= 200_000 && entries.none { collectorClass(it.name) })
                val resource = entries.single { it.name == "ghidra_scripts/ExportNativeCallsV1.java" }
                check(!resource.isDirectory && resource.size == collector.sourceBytes)
                val packaged = jar.getInputStream(resource).use { it.readNBytes(4 * 1024 * 1024 + 1) }
                check(packaged.contentEquals(sourceBytes) && sha256(packaged) == collector.sourceSha256) {
                    "installed native collector resource was not generated from the single tracked Java source"
                }
            }
            deployment.verify("after installed native collector source and complete class closure checks")
            println("installed-native-collector-reference-verified:${reference.closureSha256}:classes=${actualClasses.size}")
        }
    }
}
