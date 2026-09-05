package decompengine.analysis

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
