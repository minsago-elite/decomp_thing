package decompengine.testing

import decompengine.testing.ChildJvm.withLauncherJavaOpts
import decompengine.testing.ChildJvm.withRepositoryTemporary
import java.lang.management.ManagementFactory
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Test-launched HotSpot children must not write `/tmp/hsperfdata_*` or other files outside the repository (#2001). */
class ChildJvmTest {
    private val repositoryRoot: Path = Path.of(assertNotNull(System.getProperty("decompengine.test.repositoryRoot"),
        "Gradle must name the repository root for test JVMs")).toRealPath()

    private fun run(command: List<String>): String {
        val process = ProcessBuilder(command).redirectErrorStream(true)
            .apply { environment().clear() }.withRepositoryTemporary().start()
        try {
            val output = process.inputStream.readNBytes(64 * 1024).decodeToString()
            assertTrue(process.waitFor(60, TimeUnit.SECONDS), "child JVM did not exit: $output")
            assertEquals(0, process.exitValue(), output)
            return output
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor(5, TimeUnit.SECONDS)
        }
    }

    @Test
    fun `a java child with a cleared environment disables perf data and keeps the repository temporary root`() {
        val output = run(ChildJvm.command("-cp", System.getProperty("java.class.path"), ChildJvmProbe::class.java.name))
        val report = output.lines().filter { '=' in it }.associate { it.substringBefore('=') to it.substringAfter('=') }
        assertEquals("true", report["noPerfData"], output)
        assertEquals("false", report["hsperfdata"], output)
        val parentTemporary = Path.of(ChildJvm.temporaryDirectory).toRealPath().toString()
        assertEquals(parentTemporary, report["java.io.tmpdir"]?.let { Path.of(it).toRealPath().toString() }, output)
        assertEquals(parentTemporary, report["jna.tmpdir"]?.let { Path.of(it).toRealPath().toString() }, output)
        assertEquals(parentTemporary, report["TMPDIR"]?.let { Path.of(it).toRealPath().toString() }, output)
        assertTrue(Path.of(parentTemporary).startsWith(repositoryRoot.resolve("build")), parentTemporary)
    }

    @Test
    fun `a JDK tool child forwards the same options to its JVM`() {
        val command = ChildJvm.toolCommand("javap", "-J-XX:+PrintCommandLineFlags", "-version")
        assertEquals(ChildJvm.options().map { "-J$it" }, command.subList(1, 1 + ChildJvm.options().size))
        assertTrue(ChildJvm.NO_PERF_DATA in run(command).split(Regex("\\s+")), "javap JVM kept perf data")
    }

    /**
     * Runs the real Gradle-generated start script against a fake `JAVA_HOME` whose `java` prints its argv, so the
     * assertion covers the script's whole `xargs`/`sed`/`eval` option parser. `POSIXLY_CORRECT=1` makes the `echo`
     * behind `xargs` honour `\c`, which would drop the separator and join two options unless the launcher
     * environment removes it.
     */
    @Test
    fun `launcher JAVA_OPTS survive the start script's parser with spaces quotes and POSIXLY_CORRECT backslash-c`() {
        val launcher = repositoryRoot.resolve("build/install/llm_bin_patch/bin/llm_bin_patch")
        assertTrue(Files.isExecutable(launcher), "installDist must provide $launcher")
        val root = Files.createDirectories(Path.of(ChildJvm.temporaryDirectory).resolve("launcher parser ${System.nanoTime()}"))
        assertTrue(root.toRealPath().startsWith(repositoryRoot.resolve("build")), root.toString())
        val fakeJava = Files.createDirectories(root.resolve("jdk/bin")).resolve("java")
        Files.writeString(fakeJava, "#!/bin/sh\nfor argument in \"\$@\"; do printf '%s\\n' \"\$argument\"; done\n")
        fakeJava.toFile().setExecutable(true, true)
        val spaced = Files.createDirectories(root.resolve("with space's \"dir\""))
        val options = listOf("-Xmx64m", ChildJvm.NO_PERF_DATA, "-Djava.io.tmpdir=$spaced", "-Dprobe=a\\cb \$HOME \\\\n",
            "-Dnext=after-backslash-c")
        val process = ProcessBuilder(launcher.toString(), "launcher-argument").redirectErrorStream(true).apply {
            environment().clear()
            environment().putAll(mapOf("PATH" to "/usr/bin:/bin", "JAVA_HOME" to root.resolve("jdk").toString(),
                "POSIXLY_CORRECT" to "1"))
        }.withRepositoryTemporary().withLauncherJavaOpts(options).start()
        val output = process.inputStream.readNBytes(256 * 1024).decodeToString()
        assertTrue(process.waitFor(30, TimeUnit.SECONDS), output)
        assertEquals(0, process.exitValue(), output)
        val argv = output.lines().dropLastWhile(String::isEmpty)
        assertEquals(options, argv.take(options.size), "start script altered the JVM options: $argv")
        assertEquals("launcher-argument", argv.last())
        assertFailsWith<IllegalArgumentException> { ChildJvm.launcherJavaOpts(listOf("-Dbad=a\nb")) }
    }

    /** Synthetic sources for each launch form the scan must recognise or ignore. */
    @Test
    fun `launch scan recognises JDK launch forms and ignores comments and string fixtures`() {
        fun kinds(source: String) = JdkLaunchScan.scan(source).sites.map { it.kind }
        val direct = JdkLaunchScan.Kind.DIRECT_JDK
        assertEquals(listOf(direct), kinds("""val p = ProcessBuilder("java", "-cp", cp, "Main")"""))
        assertEquals(listOf(direct), kinds("""val p = Runtime.getRuntime().exec(arrayOf("/usr/lib/jvm/bin/javap", "-p"))"""))
        assertEquals(listOf(direct), kinds("""val p = ProcessBuilder(ProcessHandle.current().info().command().get(), "-version")"""))
        assertEquals(listOf(direct), kinds("""val p = ProcessBuilder(javaBin.resolve("java").toString(), "-version")"""))
        assertEquals(listOf(direct), kinds("""val p = ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString())"""))
        assertEquals(listOf(direct), kinds("""val p = ProcessExecutor(listOf("${'$'}{home}/bin/java", "-version"))"""))
        // A wrapper executable can still start a JVM; its later arguments are resolved like an executable.
        assertEquals(listOf(direct), kinds(
            "val java = Path.of(System.getProperty(\"java.home\"), \"bin\", \"java\")\n" +
                "val p = ProcessBuilder(\"unshare\", \"--user\", \"--\", java.toString(), \"-version\")"))
        assertEquals(listOf(JdkLaunchScan.Kind.OPAQUE_IN_JDK_FILE), kinds("fun run(vararg tool: String) =\n" +
            "  ProcessBuilder(\"timeout\", \"5\", *tool)\nval home = System.getProperty(\"java.home\")"))
        // A command assembled in a same-file variable is resolved to its executable.
        assertEquals(listOf(direct), kinds(
            "val command = listOf(Path.of(System.getProperty(\"java.home\"), \"bin\", \"java\").toString())\n" +
                "val p = ProcessBuilder(command)"))
        assertEquals(listOf(JdkLaunchScan.Kind.NON_JDK_LITERAL), kinds(
            "val SETFACL = Path.of(\"/usr/bin/setfacl\")\nval p = ProcessBuilder(SETFACL.toString(), \"-m\")\n" +
                "val home = System.getProperty(\"java.home\")"))
        // A command passed in from elsewhere in a JDK-referencing file is not trusted without review.
        assertEquals(listOf(JdkLaunchScan.Kind.OPAQUE_IN_JDK_FILE), kinds("fun start(command: List<String>) = ProcessBuilder(command)\n" +
            "val home = System.getProperty(\"java.home\")"))
        // An unrelated ChildJvm mention next to a raw launch does not satisfy the check.
        assertEquals(listOf(direct), kinds("val flag = ChildJvm.NO_PERF_DATA\n" +
            "val p = ProcessBuilder(Path.of(System.getProperty(\"java.home\"), \"bin\", \"java\").toString())"))
        assertEquals(listOf(JdkLaunchScan.Kind.CHILD_JVM), kinds("val p = ProcessBuilder(ChildJvm.command(\"-cp\", cp))"))
        assertEquals(listOf(JdkLaunchScan.Kind.CHILD_JVM), kinds("val p = ProcessBuilder(*ChildJvm.toolCommand(\"javap\").toTypedArray())"))
        assertEquals(listOf(JdkLaunchScan.Kind.NON_JDK_LITERAL), kinds("val p = ProcessBuilder(\"mkfifo\", path.toString())"))
        // Only the executable expression decides: a JDK name in a later argument is data.
        assertEquals(listOf(JdkLaunchScan.Kind.NON_JDK_LITERAL), kinds("val p = ProcessBuilder(\"printf\", \"%s\", \"java\")"))
        // The exec(String) overload runs the first word of its command line.
        assertEquals(listOf(direct), kinds("val p = Runtime.getRuntime().exec(\"java -version\")"))
        assertEquals(listOf(JdkLaunchScan.Kind.NON_JDK_LITERAL), kinds("val p = Runtime.getRuntime().exec(\"printf java\")"))
        assertEquals(listOf(JdkLaunchScan.Kind.CHILD_JVM), kinds(
            "val p = ProcessBuilder(\"prlimit\", \"--nofile=64:64\", \"--\", *ChildJvm.command().toTypedArray(), \"-cp\", cp)"))
        // Wrappers: only the wrapped executable position counts.
        assertEquals(listOf(direct), kinds("val p = ProcessBuilder(\"env\", \"java\", \"-version\", ChildJvm.command().toString())"))
        assertEquals(listOf(JdkLaunchScan.Kind.NON_JDK_LITERAL), kinds("val p = ProcessBuilder(\"env\", \"printf\", \"%s\", \"java\")"))
        assertEquals(listOf(direct), kinds("val p = ProcessBuilder(\"env\", \"-i\", \"A=1\", \"-u\", \"B\", \"--\", \"java\", \"-version\")"))
        assertEquals(listOf(direct), kinds("val p = ProcessBuilder(\"timeout\", \"-k\", \"1\", \"5s\", \"java\", \"-version\")"))
        assertEquals(listOf(JdkLaunchScan.Kind.NON_JDK_LITERAL), kinds("val p = ProcessBuilder(\"timeout\", \"5s\", \"printf\", \"java\")"))
        assertEquals(listOf(direct), kinds("val p = ProcessBuilder(\"unshare\", \"--propagation\", \"private\", \"-m\", \"java\")"))
        assertEquals(listOf(direct), kinds("val p = ProcessBuilder(\"setsid\", \"-w\", \"java\", \"-version\")"))
        // An unmodelled wrapper or wrapper form is opaque, not trusted.
        assertEquals(listOf(JdkLaunchScan.Kind.NON_JDK), kinds("val p = ProcessBuilder(\"nice\", \"-n\", \"5\", \"printf\", \"x\")"))
        assertEquals(listOf(JdkLaunchScan.Kind.OPAQUE_IN_JDK_FILE), kinds(
            "val p = ProcessBuilder(\"env\", \"-S\", \"printf x\")\nval home = System.getProperty(\"java.home\")"))
        assertEquals(listOf(JdkLaunchScan.Kind.OPAQUE_IN_JDK_FILE), kinds(
            "val p = ProcessBuilder(\"prlimit\", \"-n64\", \"printf\")\nval home = System.getProperty(\"java.home\")"))
        // An identifier declared more than once, or shadowed by a parameter, is never resolved.
        assertEquals(listOf(JdkLaunchScan.Kind.OPAQUE_IN_JDK_FILE), kinds(
            "val tool = \"java\"\nfun run() {\n    val tool = \"true\"\n    ProcessBuilder(tool).start()\n}"))
        assertEquals(listOf(JdkLaunchScan.Kind.OPAQUE_IN_JDK_FILE), kinds(
            "val tool = \"true\"\nfun run(tool: String) = ProcessBuilder(tool)\nval home = System.getProperty(\"java.home\")"))
        // exec(String) keeps scalar semantics through an alias and splits on StringTokenizer whitespace.
        assertEquals(listOf(direct), kinds("val cmd = \"java -version\"\nval p = Runtime.getRuntime().exec(cmd)"))
        assertEquals(listOf(direct), kinds("val p = Runtime.getRuntime().exec(\"\"\"java\n-version\"\"\")"))
        assertEquals(listOf(direct), kinds("val p = Runtime.getRuntime().exec(\"\"\"java\t-version\"\"\")"))
        assertEquals(listOf(JdkLaunchScan.Kind.OPAQUE_IN_JDK_FILE), kinds(
            "val p = Runtime.getRuntime().exec(\"\${'$'}tool -version\")\nval home = System.getProperty(\"java.home\")"))
        // The lexically enclosing function owns a launch, even after a local function declared above it.
        val owned = JdkLaunchScan.scan("fun outer() {\n    fun helper() = 1\n    fun other() {\n        helper()\n    }\n" +
            "    ProcessBuilder(listOf(\"a\", \"b\", \"c\", \"d\", \"e\", \"f\", \"g\", \"h\", \"i\", \"j\", \"k\", \"l\", \"m\")).start()\n}").sites.single()
        assertEquals("outer", owned.function)
        // The full executable expression is kept in the key.
        assertEquals("listOf(\"a\",\"b\",\"c\",\"d\",\"e\",\"f\",\"g\",\"h\",\"i\",\"j\",\"k\",\"l\",\"m\")", owned.executable)
        // Anchors name the enclosing function and the executable, not the line.
        val anchored = JdkLaunchScan.scan("fun `launches a probe`() {\n  val p = ProcessBuilder(command)\n}\n" +
            "val home = System.getProperty(\"java.home\")").sites.single()
        assertEquals("F.kt :: `launches a probe` :: command", anchored.anchor("F.kt"))
        // Comments and string fixture data are not launches.
        assertEquals(emptyList(), kinds("// ProcessBuilder(Path.of(System.getProperty(\"java.home\"), \"bin\", \"java\").toString())\n" +
            "/* Runtime.getRuntime().exec(\"java\") /* nested */ */"))
        assertEquals(emptyList(), kinds("val fixture = \"ProcessBuilder(\\\"java\\\", \\\"-version\\\")\"\n" +
            "val raw = \"\"\"Runtime.getRuntime().exec(\"java\")\"\"\"\nval quote = '\"'\nfun `name's \"test\"`() = Unit"))
        assertEquals(listOf(JdkLaunchScan.Kind.NON_JDK), kinds("val p = ProcessBuilder(command) // java.home"))
    }

    /**
     * Every launch in src/test that can start a JDK executable must take its command from [ChildJvm]. The sites
     * listed here were reviewed one by one, keyed by file, enclosing function and executable expression: they start
     * a JVM with an explicit `-XX:-UsePerfData` and a private repository-local temporary root, start a Gradle start
     * script through `withLauncherJavaOpts`, or run a non-JDK tool whose command the scan cannot see. Unrelated
     * non-JDK launches never need an entry; a new JDK-capable site cannot take over a reviewed one.
     */
    @Test
    fun `every test-launched JDK child takes its command from ChildJvm unless reviewed`() {
        val reviewed: Map<String, Pair<Int, String>> = mapOf(
            "InstalledReconstructionCliTest.kt :: `installed CLI validates profile selection before creating reconstruction output` :: listOf(launcher.toString(),\"reconstruct\") + case.first" to (1 to START_SCRIPT),
            "acp/LinuxBubblewrapBoundaryTest.kt :: `private controls reject native bind aliases and late callback exposure without denying disjoint grants` :: \"unshare\"" to (1 to PRIVATE_ROOT),
            "acp/LinuxBubblewrapBoundaryTest.kt :: `private controls reject native bind aliases and late callback exposure without denying disjoint grants` :: java.toString()" to (1 to PRIVATE_ROOT),
            "acp/LinuxBubblewrapBoundaryTest.kt :: `unproved partial control creation poisons all later authority admission without descriptor leaks` :: Path.of(System.getProperty(\"java.home\"),\"bin\",\"java\").toString()" to (1 to PRIVATE_ROOT),
            "acp/LinuxBubblewrapBoundaryTest.kt :: command :: *argv" to (1 to NON_JDK),
            "acp/LinuxBubblewrapBoundaryTest.kt :: runDirectGate :: listOf( GATE_HELPER.toString(), stdinDispositionArgument, environmentPath.toString(), target.toString(), ) + targetArguments" to (1 to NON_JDK),
            "analysis/BoundedProgramModelAcquisitionProcessTest.kt :: main :: workerCommand(root,\"fifo\")" to (1 to PRIVATE_ROOT),
            "analysis/BoundedProgramModelAcquisitionProcessTest.kt :: start :: command" to (1 to PRIVATE_ROOT),
            "analysis/BundledGhidraTest.kt :: `installed native collector source and complete compiled closure match the production reference` :: command" to (1 to PRIVATE_ROOT),
            "analysis/BundledGhidraTest.kt :: `installed worker initializes outside the application directory without an external installation` :: bundle.probeCommand()" to (1 to PRODUCTION),
            "analysis/BundledGhidraTest.kt :: `installed worker requires the exact parent permit before Ghidra initialization` :: command" to (1 to PRIVATE_ROOT),
            "analysis/BundledGhidraTest.kt :: `passive JVM sampler bounds transport and preserves blocked or failed worker outcomes` :: Path.of(System.getProperty(\"java.home\"),\"bin\",\"java\").toString()" to (1 to PRIVATE_ROOT),
            "oracle/behavior/LlvmBehaviorHostedWorkerImageLiveIntegrationTest.kt :: execute :: command" to (1 to NON_JDK),
            "oracle/behavior/LlvmBehaviorNativeHelperBuildV2Test.kt :: `compiler child environment clears inherited include and tool redirection` :: command" to (1 to PRIVATE_ROOT),
            "oracle/behavior/LlvmBehaviorNativeHelperDeploymentReferenceV1Test.kt :: probe :: command" to (1 to PRIVATE_ROOT),
            "oracle/behavior/LlvmBehaviorNativeRuntimeMeasurementV2Test.kt :: run :: command" to (1 to PRIVATE_ROOT),
            "oracle/behavior/LlvmBehaviorNativeRuntimeMeasurementV2Test.kt :: runChild :: command" to (1 to PRIVATE_ROOT),
            "oracle/externalcalls/IndependentExternalCallWorkerV1Test.kt :: freshWorker :: Path.of(System.getProperty(\"java.home\"),\"bin/java\").toString()" to (1 to PRIVATE_ROOT),
            "oracle/fulltree/FullTreeFunctionObservationIsolatedRunnerTest.kt :: `fresh JNA bootstrap stays inside exact temporary directory without creating home caches` :: listOf(javaExecutable.toString(), ChildJvm.NO_PERF_DATA,\"-Duser.home=\$run\") + arguments + listOf(\"-classpath\", jnaJar.toString(),\"com.sun.jna.Native\")" to (1 to PRIVATE_ROOT),
            "oracle/fulltree/FullTreeFunctionObservationIsolatedRunnerTest.kt :: availableConfiguration :: systemctl.toString()" to (1 to NON_JDK),
            "oracle/fulltree/FullTreeFunctionObservationIsolatedRunnerTest.kt :: runTestSystemctl :: listOf(configuration.scopeInspectorExecutable.toString(),\"--user\") + arguments" to (1 to NON_JDK),
            "oracle/fulltree/FullTreeFunctionObservationIsolatedRunnerTest.kt :: startOccupiedObservationUnit :: configuration.scopeSupervisorExecutable.toString()" to (1 to NON_JDK),
            "oracle/fulltree/FullTreeWorkerFailureOwnershipTest.kt :: assertFailurePreservesParentTree :: command" to (1 to PRIVATE_ROOT),
            "oracle/fulltree/KotlinContainedCommandKeeperTest.kt :: withLocalKeeper :: arguments" to (1 to PRIVATE_ROOT),
            "oracle/fulltree/OracleNativeLibrariesTest.kt :: noexecNamespace :: prefix + listOf(tools[2].toString(),\"--noheadings\",\"--output\",\"OPTIONS\",\"--mountpoint\", target)" to (1 to NON_JDK),
            "oracle/fulltree/OracleNativeLibrariesTest.kt :: runJava :: prefix + listOf(Path.of(System.getProperty(\"java.home\"),\"bin\",\"java\").toString(),\"-XX:-UsePerfData\",\"-Duser.home=\$root\") + arguments" to (1 to PRIVATE_ROOT),
            "oracle/gcc/GccBundledGhidraDeploymentReferenceTest.kt :: runInstalledProbe :: command" to (1 to PRIVATE_ROOT),
            "oracle/gcc/GccInstalledCliInvocation.kt :: invokeInstalledGccCli :: selectedCommand" to (1 to START_SCRIPT),
            "oracle/machinecalls/IndependentMachineCallWorkerV1Test.kt :: `pinned bundled runtime initializes and decodes bytes in a fresh worker JVM` :: Path.of(System.getProperty(\"java.home\"),\"bin/java\").toString()" to (1 to PRIVATE_ROOT),
            "project/GhidraReferencedBytesExporterTest.kt :: run :: arguments" to (1 to PRIVATE_ROOT),
            "project/NativeCallCollectorRealTest.kt :: run :: arguments" to (1 to PRIVATE_ROOT),
            "project/NativeInferredInterfaceCollectorRealTest.kt :: run :: arguments" to (1 to PRIVATE_ROOT),
            "project/NativeInterfaceCollectorRealTest.kt :: run :: arguments" to (1 to PRIVATE_ROOT),
        )
        val sources = repositoryRoot.resolve("src/test/kotlin/decompengine")
        val found = mutableMapOf<String, MutableList<String>>()
        val kinds = mutableMapOf<JdkLaunchScan.Kind, Int>()
        val fileFacts = mutableMapOf<String, JdkLaunchScan.Scan>()
        Files.walk(sources).use { paths ->
            paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) && it.toString().endsWith(".kt") }
                .filter { it.fileName.toString() !in setOf("ChildJvm.kt", "ChildJvmTest.kt", "JdkLaunchScan.kt") }
                .sorted().forEach { file ->
                    val relative = sources.relativize(file).toString()
                    val scan = JdkLaunchScan.scan(Files.readString(file))
                    fileFacts[relative] = scan
                    scan.sites.forEach { site ->
                        kinds.merge(site.kind, 1, Int::plus)
                        if (site.kind == JdkLaunchScan.Kind.DIRECT_JDK || site.kind == JdkLaunchScan.Kind.OPAQUE_IN_JDK_FILE) {
                            found.getOrPut(site.anchor(relative)) { mutableListOf() } += "$relative:${site.line} (${site.kind})"
                        }
                    }
                }
        }
        assertTrue((kinds[JdkLaunchScan.Kind.CHILD_JVM] ?: 0) >= 20, "launch scan found too few ChildJvm launches: $kinds")
        val problems = mutableListOf<String>()
        found.toSortedMap().forEach { (anchor, sites) ->
            val expected = reviewed[anchor]?.first ?: 0
            if (sites.size > expected) problems += "unreviewed JDK-capable launch at ${sites.joinToString()}: build its command " +
                "with ChildJvm.command/toolCommand, or after review add  \"$anchor\" to (${sites.size} to <reason>)"
        }
        reviewed.forEach { (anchor, entry) ->
            val actual = found[anchor].orEmpty().size
            if (actual != entry.first) problems += "reviewed launch \"$anchor\" expects ${entry.first} site(s) but found $actual; " +
                "update or remove its entry"
            val file = anchor.substringBefore(" :: ")
            val facts = fileFacts[file]
            if (entry.second == PRIVATE_ROOT && facts?.namesPerfFlag != true) problems += "$file no longer names -XX:-UsePerfData"
            if (entry.second == START_SCRIPT && facts?.code?.contains("withLauncherJavaOpts") != true) {
                problems += "$file no longer uses withLauncherJavaOpts"
            }
        }
        assertTrue(problems.isEmpty(), problems.joinToString("\n"))
    }

    private companion object {
        const val PRIVATE_ROOT = "explicit -XX:-UsePerfData with a private temporary root"
        const val START_SCRIPT = "Gradle start script with withLauncherJavaOpts"
        const val NON_JDK = "non-JDK tool command built in a variable"
        const val PRODUCTION = "JVM command built by production code, which owns its options"
    }
}

/** Reports the launch settings a [ChildJvm] child observed. */
object ChildJvmProbe {
    @JvmStatic
    fun main(arguments: Array<String>) {
        val noPerfData = ChildJvm.NO_PERF_DATA in ManagementFactory.getRuntimeMXBean().inputArguments
        val hsperfdata = Path.of("/tmp", "hsperfdata_${System.getProperty("user.name")}", ProcessHandle.current().pid().toString())
        println("noPerfData=$noPerfData")
        println("hsperfdata=${Files.exists(hsperfdata, LinkOption.NOFOLLOW_LINKS)}")
        println("java.io.tmpdir=${System.getProperty("java.io.tmpdir")}")
        println("jna.tmpdir=${System.getProperty("jna.tmpdir")}")
        println("TMPDIR=${System.getenv("TMPDIR")}")
    }
}
