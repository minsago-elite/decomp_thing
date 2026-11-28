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
        // A wrapper executable can still start a JVM.
        assertEquals(listOf(JdkLaunchScan.Kind.OPAQUE_IN_JDK_FILE), kinds(
            "val java = Path.of(System.getProperty(\"java.home\"), \"bin\", \"java\")\n" +
                "val p = ProcessBuilder(\"unshare\", \"--user\", \"--\", java.toString(), \"-version\")"))
        // A command assembled elsewhere in a JDK-referencing file is not trusted without review.
        assertEquals(listOf(JdkLaunchScan.Kind.OPAQUE_IN_JDK_FILE), kinds(
            "val command = listOf(Path.of(System.getProperty(\"java.home\"), \"bin\", \"java\").toString())\n" +
                "val p = ProcessBuilder(command)"))
        // An unrelated ChildJvm mention next to a raw launch does not satisfy the check.
        assertEquals(listOf(direct), kinds("val flag = ChildJvm.NO_PERF_DATA\n" +
            "val p = ProcessBuilder(Path.of(System.getProperty(\"java.home\"), \"bin\", \"java\").toString())"))
        assertEquals(listOf(JdkLaunchScan.Kind.CHILD_JVM), kinds("val p = ProcessBuilder(ChildJvm.command(\"-cp\", cp))"))
        assertEquals(listOf(JdkLaunchScan.Kind.CHILD_JVM), kinds("val p = ProcessBuilder(*ChildJvm.toolCommand(\"javap\").toTypedArray())"))
        assertEquals(listOf(JdkLaunchScan.Kind.NON_JDK_LITERAL), kinds("val p = ProcessBuilder(\"mkfifo\", path.toString())"))
        // Comments and string fixture data are not launches.
        assertEquals(emptyList(), kinds("// ProcessBuilder(Path.of(System.getProperty(\"java.home\"), \"bin\", \"java\").toString())\n" +
            "/* Runtime.getRuntime().exec(\"java\") /* nested */ */"))
        assertEquals(emptyList(), kinds("val fixture = \"ProcessBuilder(\\\"java\\\", \\\"-version\\\")\"\n" +
            "val raw = \"\"\"Runtime.getRuntime().exec(\"java\")\"\"\"\nval quote = '\"'\nfun `name's \"test\"`() = Unit"))
        assertEquals(listOf(JdkLaunchScan.Kind.NON_JDK), kinds("val p = ProcessBuilder(command) // java.home"))
    }

    /**
     * Every launch in src/test that can start a JDK executable must take its command from [ChildJvm]. Files listed
     * here were reviewed: their remaining launches either start a JVM with an explicit `-XX:-UsePerfData` and a
     * private repository-local temporary root, start a Gradle start script through `withLauncherJavaOpts`, or run a
     * non-JDK tool whose command the scan cannot see. Counts are exact, so a new launch in one of them needs review.
     */
    @Test
    fun `every test-launched JDK child takes its command from ChildJvm unless reviewed`() {
        val privateRoot = "explicit -XX:-UsePerfData with a private temporary root"
        val startScript = "Gradle start script with withLauncherJavaOpts"
        val nonJdk = "non-JDK tool command built in a variable"
        val reviewed = mapOf(
            "InstalledReconstructionCliTest.kt" to (1 to startScript),
            "oracle/gcc/GccInstalledCliInvocation.kt" to (1 to startScript),
            "acp/LinuxBubblewrapBoundaryTest.kt" to (8 to privateRoot),
            "analysis/BoundedProgramModelAcquisitionProcessTest.kt" to (2 to privateRoot),
            "analysis/BundledGhidraTest.kt" to (4 to privateRoot),
            "oracle/behavior/LlvmBehaviorNativeHelperBuildV2Test.kt" to (1 to privateRoot),
            "oracle/behavior/LlvmBehaviorNativeHelperDeploymentReferenceV1Test.kt" to (1 to privateRoot),
            "oracle/behavior/LlvmBehaviorNativeRuntimeMeasurementV2Test.kt" to (2 to privateRoot),
            "oracle/externalcalls/IndependentExternalCallWorkerV1Test.kt" to (1 to privateRoot),
            "oracle/fulltree/FullTreeFunctionObservationIsolatedRunnerTest.kt" to (4 to privateRoot),
            "oracle/fulltree/FullTreeWorkerFailureOwnershipTest.kt" to (1 to privateRoot),
            "oracle/fulltree/KotlinContainedCommandKeeperTest.kt" to (1 to privateRoot),
            "oracle/fulltree/OracleNativeLibrariesTest.kt" to (2 to privateRoot),
            "oracle/gcc/GccBundledGhidraDeploymentReferenceTest.kt" to (1 to privateRoot),
            "oracle/machinecalls/IndependentMachineCallWorkerV1Test.kt" to (1 to privateRoot),
            "project/GhidraReferencedBytesExporterTest.kt" to (1 to privateRoot),
            "project/NativeCallCollectorRealTest.kt" to (1 to privateRoot),
            "project/NativeInferredInterfaceCollectorRealTest.kt" to (1 to privateRoot),
            "project/NativeInterfaceCollectorRealTest.kt" to (1 to privateRoot),
            "oracle/behavior/LlvmBehaviorHostedWorkerImageLiveIntegrationTest.kt" to (1 to nonJdk),
            "oracle/gcc/GccBundledContainedExecutionTest.kt" to (1 to nonJdk),
            "oracle/gcc/GccCompilerEngineLiveContainmentControllerTest.kt" to (1 to nonJdk),
        )
        val sources = repositoryRoot.resolve("src/test/kotlin/decompengine")
        val unreviewed = mutableMapOf<String, Pair<List<Int>, Boolean>>()
        val kinds = mutableMapOf<JdkLaunchScan.Kind, Int>()
        Files.walk(sources).use { paths ->
            paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) && it.toString().endsWith(".kt") }
                .filter { it.fileName.toString() !in setOf("ChildJvm.kt", "ChildJvmTest.kt", "JdkLaunchScan.kt") }
                .sorted().forEach { file ->
                    val scan = JdkLaunchScan.scan(Files.readString(file))
                    scan.sites.forEach { kinds.merge(it.kind, 1, Int::plus) }
                    val open = scan.sites.filter {
                        it.kind == JdkLaunchScan.Kind.DIRECT_JDK || it.kind == JdkLaunchScan.Kind.OPAQUE_IN_JDK_FILE
                    }
                    if (open.isNotEmpty()) unreviewed[sources.relativize(file).toString()] = open.map { it.line } to
                        (scan.namesPerfFlag || "withLauncherJavaOpts" in scan.code)
                }
        }
        assertTrue((kinds[JdkLaunchScan.Kind.CHILD_JVM] ?: 0) >= 20, "launch scan found too few ChildJvm launches: $kinds")
        val mismatched = (reviewed.keys + unreviewed.keys).sorted().mapNotNull { file ->
            val expected = reviewed[file]?.first ?: 0
            val actual = unreviewed[file]?.first.orEmpty()
            if (expected == actual.size) null else "$file: expected $expected reviewed launch(es), found ${actual.size} at lines $actual"
        }
        assertTrue(mismatched.isEmpty(), "JDK-capable launches must use ChildJvm or be reviewed here:\n" + mismatched.joinToString("\n"))
        val flagless = reviewed.filter { (file, entry) -> entry.second != nonJdk && unreviewed[file]?.second != true }.keys
        assertTrue(flagless.isEmpty(), "reviewed JVM launch files no longer name -XX:-UsePerfData: $flagless")
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
