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
    fun `bundled public APIs preserve exact bytes widths and deterministic bounded omission controls`() = runProbes(owned = false)

    @Test
    fun `owned bundled APIs exercise typed extraction addressed slots and bounded indirect evidence`() = runProbes(owned = true)

    private fun runProbes(owned: Boolean) {
        if (owned) assumeTrue(System.getenv("RUN_REAL_GHIDRA") == "true", "active owned API and listing qualification requires explicit lane opt-in")
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
        val work = Files.createTempDirectory(parent, if (owned) "owned-api-" else "public-api-")
        val exporterName = if (owned) "ExportProgramModelOwned" else "ExportProgramModel"
        val byteProbe = if (owned) "OwnedExporterReferencedBytesProbe" else "ReferencedBytesProbe"
        val listingProbe = if (owned) "OwnedExporterControlledListingProbe" else "ControlledByteListingProbe"
        val exporterSource = repository.resolve("src/main/resources/ghidra_scripts/$exporterName.java")
        val exporterHash = sha256(Files.readAllBytes(exporterSource))
        val packaged = checkNotNull(javaClass.getResourceAsStream("/ghidra_scripts/$exporterName.java")).use { it.readBytes() }
        assertEquals(exporterHash, sha256(packaged), "compile exactly the active packaged resource")
        Files.writeString(work.resolve("exporter-source.sha256"), "$exporterHash  $exporterSource\n")
        val classes = Files.createDirectory(work.resolve("classes"))
        val temporary = Files.createDirectory(work.resolve("tmp"))
        val home = Files.createDirectory(work.resolve("home"))
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
        run("compile", listOf(javaBin.resolve("javac").toString(), "-J-Djava.io.tmpdir=$temporary", "-J-Duser.home=$home", "-J-Djava.util.prefs.userRoot=$home/prefs",
            "-J-Djna.tmpdir=$temporary", "-J-XX:-UsePerfData", "-proc:none",
            "-cp", classpath, "-d", classes.toString(),
            exporterSource.toString(),
            repository.resolve("src/main/resources/ghidra_scripts/ExportRecoveredCallSites.java").toString(),
            repository.resolve("src/test/resources/ghidra/$byteProbe.java").toString(),
            repository.resolve("src/test/resources/ghidra/$listingProbe.java").toString()) +
            if (owned) listOf(repository.resolve("src/test/resources/ghidra/OwnedExporterPrototypeProbe.java").toString()) else emptyList())
        run("probe", listOf(javaBin.resolve("java").toString(), "-Djava.io.tmpdir=$temporary", "-Duser.home=$home", "-Djava.util.prefs.userRoot=$home/prefs",
            "-Djna.tmpdir=$temporary", "-XX:-UsePerfData", "-cp", classpath, byteProbe, work.resolve("byte-controls").toString()))
        val probeLog = work.resolve("probe.log").readText()
        assertTrue(probeLog.contains(if (owned) "owned indirect referenced byte API probe passed" else "referenced byte API probe passed"))
        assertTrue(probeLog.contains("production catch thread-only interruption controls passed"))
        if (owned) {
            assertTrue(probeLog.contains("owned mixed indirect and metadata exhaustion controls passed"))
            assertTrue(probeLog.contains("owned malformed addressed component fallback controls passed"))
        }
        assertTrue(probeLog.contains("omission controls passed: local32 model4096 bytes65536 work65536 deterministic dedup true-cutoff fallback"))
        val applicationRoots = Files.walk(bundle).use { paths ->
            paths.filter { Files.isRegularFile(it) && it.fileName.toString() == "application.properties" &&
                it.parent.fileName.toString() == "Ghidra" }.map { it.parent.parent }.toList()
        }
        assertEquals(1, applicationRoots.size, "exactly one bundled application root")
        run("controlled-listing", listOf(javaBin.resolve("java").toString(), "-Djava.io.tmpdir=$temporary",
            "-Duser.home=$home", "-Djava.util.prefs.userRoot=$home/prefs", "-Djna.tmpdir=$temporary", "-XX:-UsePerfData",
            "-cp", classpath, listingProbe, applicationRoots.single().toString(), work.toString()))
        assertTrue(work.resolve("controlled-listing.log").readText().contains("controlled real listing passed"))
        if (owned) {
            assertTrue(work.resolve("controlled-listing.log").readText().contains("owned addressed primitive and indirect origin controls passed"))
            run("typed-prototype", listOf(javaBin.resolve("java").toString(), "-Djava.io.tmpdir=$temporary", "-Duser.home=$home",
                "-Djava.util.prefs.userRoot=$home/prefs", "-Djna.tmpdir=$temporary", "-XX:-UsePerfData", "-cp", classpath,
                "OwnedExporterPrototypeProbe", work.resolve("prototype-controls").toString()))
            val typedLog = work.resolve("typed-prototype.log").readText()
            assertTrue(typedLog.contains("owned typed prototype API probe passed"))
            assertTrue(typedLog.contains("owned builtin alias extraction and fallback controls passed"))
            assertTrue(typedLog.contains("owned enum extraction bounds before rendering passed"))
            assertTrue(typedLog.contains("owned catalog resume full output and 512 batch commitments passed"))
            assertTrue(typedLog.contains("owned initialization cleanup and native timeout classification controls passed"))
            assertTrue(typedLog.contains("owned prototype bounds and cancellation passed"))
            assertTrue(typedLog.contains("owned deterministic type closure and immutable coverage controls passed"))
            assertTrue(typedLog.contains("owned full status schema refusal and checkpoint binding controls passed"))
            assertEquals(exporterHash, sha256(Files.readAllBytes(exporterSource)), "source remained exact during probe execution")
        }
    }
}
