package decompengine.integration

import decompengine.binary.ElfMetadataReader
import decompengine.validation.BehaviorComparator
import decompengine.validation.ProcessInput
import decompengine.exploration.AutomaticExplorer
import decompengine.exploration.CandidateInput
import decompengine.exploration.CandidateSource
import decompengine.exploration.StaticHintGenerator
import decompengine.exploration.AngrExplorer
import kotlin.io.path.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.isExecutable
import kotlin.io.path.pathString
import kotlin.io.path.readBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RealBinaryIntegrationTest {
    private val fixtureDir = Path("src/test/fixtures/c")

    @Test
    fun `ELF metadata is extracted from a real compiled binary fixture`() {
        val tempDir = createTempDirectory("real-elf-")
        val binary = compileFixture(tempDir, "hello_world")

        val metadata = ElfMetadataReader.read(binary.readBytes())

        assertEquals("ELF64", metadata.format)
        assertEquals("little", metadata.endianness)
        assertEquals("x86-64", metadata.machine)
        assertTrue(metadata.entryPoint > 0UL)
    }

    @Test
    fun `real hello-world binaries match byte-for-byte under sandbox`() {
        val tempDir = createTempDirectory("real-hello-")
        val original = compileFixture(tempDir.resolve("original"), "hello_world")
        val rebuilt = compileFixture(tempDir.resolve("rebuilt"), "hello_world")

        val report = BehaviorComparator().compare(
            id = "real_hello_world",
            originalBinary = original,
            rebuiltBinary = rebuilt,
            cases = listOf(ProcessInput(id = "default")),
            reportsDir = tempDir.resolve("reports"),
        )

        assertTrue(report.matches)
        assertEquals("hello, world\n", report.cases.single().original.stdout.decodeToString())
        assertTrue(report.reportPath.exists())
    }

    @Test
    fun `real argv binary matches byte-for-byte under sandbox`() {
        val tempDir = createTempDirectory("real-argv-")
        val original = compileFixture(tempDir.resolve("original"), "argv_echo")
        val rebuilt = compileFixture(tempDir.resolve("rebuilt"), "argv_echo")

        val report = BehaviorComparator().compare(
            id = "real_argv_echo",
            originalBinary = original,
            rebuiltBinary = rebuilt,
            cases = listOf(
                ProcessInput(id = "no_args"),
                ProcessInput(id = "two_args", args = listOf("alpha", "beta")),
            ),
            reportsDir = tempDir.resolve("reports"),
        )

        assertTrue(report.matches)
        assertEquals("argc=3\narg1=alpha\narg2=beta\n", report.cases.last().rebuilt.stdout.decodeToString())
    }

    @Test
    fun `real stdin branching binary gains output coverage from generated inputs`() {
        val tempDir = createTempDirectory("real-exploration-")
        val binary = compileFixture(tempDir, "stdin_branching")
        val seed = listOf(CandidateInput("empty", CandidateSource.SEED))

        val report = AutomaticExplorer(angrExplorer = RealFixtureAngrExplorer())
            .explore(binary, seed, tempDir.resolve("reports"))

        assertTrue(report.coverage.increased)
        assertTrue(report.coverage.expandedSignatures.size >= 3)
        assertTrue(report.candidates.any { it.source == CandidateSource.STATIC_HINT })
        assertTrue(report.candidates.any { it.source == CandidateSource.ANGR && it.stdin.decodeToString() == "open\n" })
        assertTrue(report.confidence.score > 0.5)
    }

    @Test
    fun `real binary static hints are produced by strings`() {
        val tempDir = createTempDirectory("real-static-")
        val binary = compileFixture(tempDir, "stdin_branching")

        val candidates = StaticHintGenerator().generate(binary)

        assertTrue(candidates.any { it.args.contains("secret") })
        assertTrue(candidates.any { it.stdin.decodeToString() == "open\n" })
    }

    private class RealFixtureAngrExplorer : AngrExplorer {
        override fun generate(binaryPath: java.nio.file.Path): List<CandidateInput> =
            listOf(
                CandidateInput("angr_secret_arg", CandidateSource.ANGR, args = listOf("secret")),
                CandidateInput("angr_open_stdin", CandidateSource.ANGR, stdin = "open\n".toByteArray()),
            )
    }

    private fun compileFixture(tempDir: java.nio.file.Path, name: String): java.nio.file.Path {
        val buildDir = tempDir.createDirectories()
        val sourcePath = fixtureDir.resolve("$name.c")
        val binaryPath = buildDir.resolve(name)
        val process = ProcessBuilder("gcc", sourcePath.pathString, "-o", binaryPath.pathString)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        check(exitCode == 0) { "gcc failed for $name: $output" }
        check(binaryPath.exists() && binaryPath.isExecutable()) { "gcc did not create executable $binaryPath" }
        return binaryPath
    }
}
