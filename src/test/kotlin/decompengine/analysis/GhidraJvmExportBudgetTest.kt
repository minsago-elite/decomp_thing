package decompengine.analysis

import decompengine.jobs.elfFixture
import decompengine.project.ExportBudgetedProgramModelAnalyzer
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.ProgramModelAnalyzer
import decompengine.project.ReconstructionBudgets
import decompengine.project.RecoveredProgramModel
import decompengine.project.sha256
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class GhidraJvmExportBudgetTest {
    @Test
    fun `budget binding rejects an unsupported analyzer without invoking it`() {
        var analyzed = false
        val analyzer = GhidraJvmAnalyzer { _, _ ->
            analyzed = true
            error("unsupported analyzer must not start")
        }

        val failure = assertFailsWith<IllegalArgumentException> {
            analyzer.withExportBudgets(GeneratedCMakeReconstructionProfile.descriptor.budgets)
        }

        assertTrue(failure.message.orEmpty().contains("cannot apply reconstruction export budgets"))
        assertFalse(analyzed)
    }

    @Test
    fun `bound wrapper passes requested budgets and uses the returned analyzer`() {
        val root = createTempDirectory("jvm-export-budget-")
        try {
            val bytes = elfFixture()
            val binary = root.resolve("authored.elf").also { it.writeBytes(bytes) }
            val output = root.resolve("analysis")
            val requested = GeneratedCMakeReconstructionProfile.descriptor.budgets.copy(exportWallClockMillis = 1_234)
            val model = RecoveredProgramModel(inputSha256 = sha256(bytes), functions = emptyList())
            var appliedBudgets: ReconstructionBudgets? = null
            val calls = mutableListOf<Pair<Path, Path>>()
            val analyzer = GhidraJvmAnalyzer(object : ExportBudgetedProgramModelAnalyzer {
                override fun analyze(binaryPath: Path, workDir: Path): RecoveredProgramModel =
                    error("the wrapper must use the returned analyzer")

                override fun withExportBudgets(budgets: ReconstructionBudgets): ProgramModelAnalyzer {
                    appliedBudgets = budgets
                    return ProgramModelAnalyzer { input, work ->
                        calls += input to work
                        work.resolve("reports").createDirectories().resolve("program_model.json").writeText(model.toJson())
                        model
                    }
                }
            })

            val bounded = analyzer.withExportBudgets(requested)

            assertEquals(requested, appliedBudgets)
            assertTrue(calls.isEmpty())
            assertFalse(output.exists())
            val analysis = bounded.analyze(binary, output)
            assertEquals(listOf(binary to output), calls)
            assertSame(model, analysis.programModel)
            assertEquals("x86-64", analysis.metadata.machine)
            assertTrue(analysis.reportPath.readText().contains("\"tool\": \"ghidra-jvm\""))
        } finally {
            root.toFile().deleteRecursively()
        }
    }
}
