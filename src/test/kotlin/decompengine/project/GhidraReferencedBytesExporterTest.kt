package decompengine.project

import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class GhidraReferencedBytesExporterTest {
    @Test
    fun `bundled public APIs preserve exact memory bytes missing spans widths and prepass bounds`() {
        val bundleSetting = System.getProperty("decompengine.ghidra.bundle")
        assumeTrue(bundleSetting != null, "bundled Ghidra qualification supplies its authenticated bundle")
        val repository = Path.of(System.getProperty("user.dir")).toRealPath()
        val bundle = Path.of(requireNotNull(bundleSetting)).toRealPath()
        val jars = Files.walk(bundle).use { paths ->
            paths.filter { Files.isRegularFile(it) && it.toString().endsWith(".jar") }.sorted().toList()
        }
        assertTrue(jars.isNotEmpty())
        val parent = repository.resolve("build/referenced-byte-exporter-tests")
        Files.createDirectories(parent)
        val work = Files.createTempDirectory(parent, "public-api-")
        val classes = Files.createDirectory(work.resolve("classes"))
        val temporary = Files.createDirectory(work.resolve("tmp"))
        val classpath = (jars + listOf(classes)).joinToString(File.pathSeparator)
        fun run(name: String, arguments: List<String>) {
            val log = work.resolve("$name.log")
            val process = ProcessBuilder(arguments).directory(repository.toFile()).apply {
                environment()["TMPDIR"] = temporary.toString()
                for (key in listOf("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH", "GHIDRA_HOME")) {
                    environment().remove(key)
                }
                redirectErrorStream(true)
                redirectOutput(log.toFile())
            }.start()
            try {
                assertTrue(process.waitFor(60, TimeUnit.SECONDS), "$name timed out: $log")
                assertEquals(0, process.exitValue(), log.readText())
            } finally {
                if (process.isAlive) process.destroyForcibly()
                assertTrue(process.waitFor(5, TimeUnit.SECONDS))
            }
        }
        val javaBin = Path.of(System.getProperty("java.home"), "bin")
        run("compile", listOf(javaBin.resolve("javac").toString(), "-J-Djava.io.tmpdir=$temporary", "-proc:none",
            "-cp", classpath, "-d", classes.toString(),
            repository.resolve("src/main/resources/ghidra_scripts/ExportProgramModel.java").toString(),
            repository.resolve("src/test/resources/ghidra/ReferencedBytesProbe.java").toString(),
            repository.resolve("src/test/resources/ghidra/ControlledByteListingProbe.java").toString()))
        run("probe", listOf(javaBin.resolve("java").toString(), "-Djava.io.tmpdir=$temporary", "-XX:-UsePerfData",
            "-cp", classpath, "ReferencedBytesProbe"))
        assertTrue(work.resolve("probe.log").readText().contains("referenced byte API probe passed"))
        val applicationRoots = Files.walk(bundle).use { paths ->
            paths.filter { Files.isRegularFile(it) && it.fileName.toString() == "application.properties" &&
                it.parent.fileName.toString() == "Ghidra" }.map { it.parent.parent }.toList()
        }
        assertEquals(1, applicationRoots.size, "exactly one bundled application root")
        val home = Files.createDirectory(work.resolve("home"))
        run("controlled-listing", listOf(javaBin.resolve("java").toString(), "-Djava.io.tmpdir=$temporary",
            "-Duser.home=$home", "-Djava.util.prefs.userRoot=$home/prefs", "-Djna.tmpdir=$temporary", "-XX:-UsePerfData",
            "-cp", classpath, "ControlledByteListingProbe", applicationRoots.single().toString()))
        assertTrue(work.resolve("controlled-listing.log").readText().contains("controlled real listing passed"))
    }
}
