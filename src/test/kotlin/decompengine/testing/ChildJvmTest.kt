package decompengine.testing

import decompengine.testing.ChildJvm.withRepositoryTemporary
import java.lang.management.ManagementFactory
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.io.path.readLines
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

    @Test
    fun `launcher JAVA_OPTS survive the start script's xargs split with spaces and quotes in paths`() {
        val spaced = Files.createDirectories(Path.of(ChildJvm.temporaryDirectory).resolve("with space's \"dir\""))
        assertTrue(spaced.toRealPath().startsWith(repositoryRoot.resolve("build")), spaced.toString())
        val options = listOf("-Xmx64m", ChildJvm.NO_PERF_DATA, "-Djava.io.tmpdir=$spaced", "-Dprobe=a\\b \$HOME")
        // The same split the Gradle-generated start scripts perform before exec'ing java.
        val process = ProcessBuilder("/bin/sh", "-c", "printf '%s\\n' \"\$OPTS\" | xargs -n1").redirectErrorStream(true)
            .apply { environment().clear(); environment()["PATH"] = "/usr/bin:/bin"; environment()["OPTS"] = ChildJvm.launcherJavaOpts(options) }
            .withRepositoryTemporary().start()
        val output = process.inputStream.readNBytes(64 * 1024).decodeToString()
        assertTrue(process.waitFor(30, TimeUnit.SECONDS), output)
        assertEquals(0, process.exitValue(), output)
        assertEquals(options, output.lines().dropLastWhile(String::isEmpty))
        assertFailsWith<IllegalArgumentException> { ChildJvm.launcherJavaOpts(listOf("-Dbad=a\nb")) }
    }

    /**
     * Every place a test resolves a launcher from the running JDK must name the perf-data flag (directly, through
     * [ChildJvm], or in the command it builds within the next few lines), unless it only hands the executable to
     * production launch code, which owns its own JVM options.
     */
    @Test
    fun `every test-launched JDK child names the perf-data flag`() {
        val launcher = Regex("""getProperty\("java\.home"\)\)?(?:\.toRealPath\(\))?,\s*"bin(?:", "|/)(java|javap|javac)"""")
        val handedToProduction = mapOf(
            "oracle/fulltree/FullTreeFunctionObservationIsolatedRunnerTest.kt" to 2,
            "oracle/gcc/GccBundledContainedExecutionTest.kt" to 1,
            "oracle/gcc/GccBundledOperationCoordinatorTest.kt" to 1,
            "oracle/gcc/GccCompilerEngineLiveContainmentControllerTest.kt" to 1,
            "oracle/gcc/GccSignedSourceQualificationTest.kt" to 1,
        )
        val sources = repositoryRoot.resolve("src/test/kotlin/decompengine")
        val found = mutableMapOf<String, Int>()
        val unflagged = mutableListOf<String>()
        Files.walk(sources).use { paths ->
            paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) && it.toString().endsWith(".kt") }
                .filter { it.fileName.toString() !in setOf("ChildJvm.kt", "ChildJvmTest.kt") }
                .sorted().forEach { file ->
                    val lines = file.readLines()
                    lines.forEachIndexed { index, line ->
                        if (!launcher.containsMatchIn(line)) return@forEachIndexed
                        val relative = sources.relativize(file).toString()
                        found[relative] = (found[relative] ?: 0) + 1
                        val window = lines.subList(index, minOf(lines.size, index + 4)).joinToString("\n")
                        if (listOf("-XX:-UsePerfData", "ChildJvm.").none(window::contains)) unflagged += "$relative:${index + 1}"
                    }
                }
        }
        // Sites that launch through ChildJvm no longer spell the launcher path; the rest must still be found.
        assertTrue(found.size >= 10, "launcher scan found too few sites; the pattern no longer matches: $found")
        handedToProduction.forEach { (file, count) ->
            assertEquals(count, unflagged.count { it.startsWith("$file:") },
                "$file no longer hands exactly $count JDK executable(s) to production code; review and update this list")
        }
        val unexpected = unflagged.filter { site -> handedToProduction.keys.none { site.startsWith("$it:") } }
        assertTrue(unexpected.isEmpty(), "test-launched JDK children without -XX:-UsePerfData: $unexpected")
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
