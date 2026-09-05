package decompengine.project

import decompengine.analysis.GhidraJvmAnalyzer
import decompengine.binary.ElfMetadataReader
import kotlin.io.path.ExperimentalPathApi
import kotlin.io.path.Path
import kotlin.io.path.createTempDirectory
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText
import kotlin.io.path.exists
import kotlin.io.path.isExecutable
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.relativeTo
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ReconstructionPipelineTest {
    @Test
    fun `ELF metadata extraction works in Kotlin backend`() {
        val metadata = ElfMetadataReader.read(elfFixture())

        assertEquals("ELF64", metadata.format)
        assertEquals("little", metadata.endianness)
        assertEquals("Linux", metadata.osAbi)
        assertEquals("executable", metadata.objectType)
        assertEquals("x86-64", metadata.machine)
        assertEquals(0x401000UL, metadata.entryPoint)
        assertEquals(2.toUShort(), metadata.programHeaderCount)
        assertEquals(5.toUShort(), metadata.sectionHeaderCount)
    }

    @Test
    fun `Ghidra analysis delegates to the program model adapter and captures report`() {
        val tempDir = createTempDirectory("reconstruction-ghidra-")
        val binary = tempDir.resolve("hello").also { it.writeBytes(elfFixture()) }
        val analyzer = testAnalyzer()

        val analysis = analyzer.analyze(binary, tempDir.resolve("analysis"))

        assertEquals(0, analysis.returnCode)
        assertEquals("x86-64", analysis.metadata.machine)
        assertTrue(analysis.reportPath.readText().contains("\"tool\": \"ghidra-jvm\""))
        assertTrue(analysis.reportsDir.resolve("ghidra_stdout.log").readText().startsWith("fake ghidra analyzed"))
    }

    @OptIn(ExperimentalPathApi::class)
    @Test
    fun `initial C project layout is stable`() {
        val tempDir = createTempDirectory("reconstruction-layout-")
        val binary = tempDir.resolve("hello").also { it.writeBytes(elfFixture()) }
        val analysis = testAnalyzer().analyze(binary, tempDir.resolve("analysis"))

        val projectDir = RecompilableProjectGenerator.generate(analysis, tempDir.resolve("project"))
        val files = projectDir.listDirectoryEntries()
            .flatMap { root ->
                if (root.toFile().isDirectory) root.toFile().walkTopDown().filter { it.isFile }.map { it.toPath() }.toList()
                else listOf(root)
            }
            .map { it.relativeTo(projectDir).pathString }
            .sorted()

        assertEquals(
            listOf(
                "Makefile",
                "UNRESOLVED.md",
                "include/decomp_types.h",
                "include/modules/decomp.h",
                "reports/analysis.json",
                "reports/confidence.json",
                "reports/module_plan.json",
                "reports/modules/decomp.json",
                "reports/program_model.json",
                "reports/toolchain.json",
                "reports/unresolved.json",
                "source_tree_manifest.json",
                "src/main.c",
                "src/modules/decomp.c",
                "src/modules/decomp_internal.h",
            ),
            files,
        )
    }

    @Test
    fun `make completes and build log is captured`() {
        val tempDir = createTempDirectory("reconstruction-build-")
        val binary = tempDir.resolve("hello").also { it.writeBytes(elfFixture()) }
        val analysis = testAnalyzer().analyze(binary, tempDir.resolve("analysis"))
        val projectDir = RecompilableProjectGenerator.generate(analysis, tempDir.resolve("project"))

        val report = MakeProjectBuilder.build(projectDir)

        assertEquals(0, report.returnCode)
        assertTrue(projectDir.resolve("build/reconstructed").exists())
        assertTrue(report.logPath.readText().contains("exit_code=0"))
    }

    @Test
    fun `reconstruction pipeline generates buildable project`() {
        val tempDir = createTempDirectory("reconstruction-pipeline-")
        val binary = tempDir.resolve("hello").also { it.writeBytes(elfFixture()) }

        val report = ReconstructionPipeline(testAnalyzer()).generate(binary, tempDir.resolve("reconstruction"))

        assertEquals(tempDir.resolve("reconstruction/project"), report.projectDir)
        assertTrue(report.projectDir.resolve("Makefile").exists())
        assertTrue(report.projectDir.resolve("reports/build.log").exists())
        assertTrue(report.projectDir.resolve("build/reconstructed").isExecutable())
    }

    @Test
    fun `unresolved symbol report is emitted`() {
        val tempDir = createTempDirectory("reconstruction-unresolved-")
        val binary = tempDir.resolve("hello").also { it.writeBytes(elfFixture()) }
        val analysis = testAnalyzer().analyze(binary, tempDir.resolve("analysis"))
        val projectDir = RecompilableProjectGenerator.generate(analysis, tempDir.resolve("project"))

        val report = projectDir.resolve("reports/unresolved.json").readText()
        assertTrue(report.contains("\"unresolvedFunctionCount\""))
        assertTrue(report.contains("\"unresolvedObjectCount\""))
        assertTrue(report.contains("\"functions\""))
        assertTrue(report.contains("\"objects\""))
        assertTrue(report.contains("does not imply behavioral equivalence"))
    }

    private fun testAnalyzer(): GhidraJvmAnalyzer =
        GhidraJvmAnalyzer { binary, output ->
            val reports = output.resolve("reports").createDirectories()
            reports.resolve("ghidra_stdout.log").writeText("fake ghidra analyzed test fixture\n")
            reports.resolve("ghidra_stderr.log").writeText("")
            RecoveredProgramModel(
                inputSha256 = sha256(java.nio.file.Files.readAllBytes(binary)),
                functions = listOf(RecoveredFunction(
                    id = stableFunctionId(0x401000UL), name = "decomp_engine_main", address = 0x401000UL,
                    prototype = "int decomp_engine_main(void)", status = RecoveryStatus.SYNTHETIC,
                )),
            ).also { reports.resolve("program_model.json").writeText(it.toJson()) }
        }

    private fun elfFixture(): ByteArray {
        val bytes = ByteArray(64)
        bytes[0] = 0x7f
        bytes[1] = 'E'.code.toByte()
        bytes[2] = 'L'.code.toByte()
        bytes[3] = 'F'.code.toByte()
        bytes[4] = 2
        bytes[5] = 1
        bytes[6] = 1
        bytes[7] = 3
        putShort(bytes, 16, 2)
        putShort(bytes, 18, 62)
        putInt(bytes, 20, 1)
        putLong(bytes, 24, 0x401000)
        putLong(bytes, 32, 64)
        putLong(bytes, 40, 0)
        putInt(bytes, 48, 0)
        putShort(bytes, 52, 64)
        putShort(bytes, 54, 56)
        putShort(bytes, 56, 2)
        putShort(bytes, 58, 64)
        putShort(bytes, 60, 5)
        putShort(bytes, 62, 4)
        return bytes
    }

    private fun putShort(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = value.toByte()
        bytes[offset + 1] = (value ushr 8).toByte()
    }

    private fun putInt(bytes: ByteArray, offset: Int, value: Int) {
        repeat(4) { index -> bytes[offset + index] = (value ushr (index * 8)).toByte() }
    }

    private fun putLong(bytes: ByteArray, offset: Int, value: Long) {
        repeat(8) { index -> bytes[offset + index] = (value ushr (index * 8)).toByte() }
    }
}
