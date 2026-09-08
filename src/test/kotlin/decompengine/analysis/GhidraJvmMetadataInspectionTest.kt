package decompengine.analysis

import decompengine.binary.BoundedElfMetadataLimits
import decompengine.jobs.elfFixture
import decompengine.oracle.fulltree.inControlTemporaryDirectory
import decompengine.oracle.fulltree.writeElf
import decompengine.project.ExportBudgetedProgramModelAnalyzer
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.ProgramModelAnalyzer
import decompengine.project.ReconstructionBudgets
import decompengine.project.RecoveredProgramModel
import decompengine.project.sha256
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

class GhidraJvmMetadataInspectionTest {
    @Test
    fun `analysis report records authenticated metadata identity limits and usage`() = inControlTemporaryDirectory { root ->
        val bytes = elfFixture()
        val input = writeElf(root.resolve("authored.elf"), bytes)
        val requested = GeneratedCMakeReconstructionProfile.descriptor.budgets.copy(
            exportMaximumResidentBytes = 32L * 1024 * 1024,
            exportWallClockMillis = 5_000,
        )
        val analyzer = GhidraJvmAnalyzer(budgetCapable { _, _ -> model(sha256(bytes)) }).withExportBudgets(requested)

        val analysis = analyzer.analyze(input, root.resolve("analysis"))

        val report = Json.parseToJsonElement(analysis.reportPath.readText()).jsonObject
        assertEquals(sha256(bytes), report.getValue("metadataInputSha256").jsonPrimitive.content)
        assertEquals(bytes.size.toLong(), report.getValue("metadataInputBytes").jsonPrimitive.long)
        val inspection = report.getValue("metadataInspection").jsonObject
        val limits = inspection.getValue("limits").jsonObject
        assertEquals(requested.exportMaximumResidentBytes, limits.getValue("maximumModeledMetadataBytes").jsonPrimitive.long)
        assertEquals(requested.exportWallClockMillis, limits.getValue("maximumWallClockMillis").jsonPrimitive.long)
        val usage = inspection.getValue("usage").jsonObject
        assertEquals(0L, usage.getValue("symbolsScanned").jsonPrimitive.long)
        assertTrue(usage.getValue("metadataReadBytes").jsonPrimitive.long > 0)
        assertTrue(analysis.symbolInventory.isEmpty)
    }

    @Test
    fun `different model input identity prevents analysis report publication`() = inControlTemporaryDirectory { root ->
        val input = writeElf(root.resolve("authored.elf"), elfFixture())
        val output = root.resolve("analysis")
        val analyzer = GhidraJvmAnalyzer { _, _ -> model("a".repeat(64)) }

        val failure = assertFailsWith<IllegalArgumentException> { analyzer.analyze(input, output) }

        assertTrue(failure.message.orEmpty().contains("input identity does not match"))
        assertFalse(output.resolve("reports/ghidra_analysis.json").exists())
    }

    @Test
    fun `metadata cannot receive a fresh timeout after export consumes the shared budget`() = inControlTemporaryDirectory { root ->
        val bytes = elfFixture()
        val input = writeElf(root.resolve("authored.elf"), bytes)
        val output = root.resolve("analysis")
        var exported = false
        val analyzer = GhidraJvmAnalyzer(budgetCapable { _, _ ->
            Thread.sleep(300)
            exported = true
            model(sha256(bytes))
        }).withExportBudgets(GeneratedCMakeReconstructionProfile.descriptor.budgets.copy(exportWallClockMillis = 250))

        val failure = assertFailsWith<GhidraAnalysisException> { analyzer.analyze(input, output) }

        assertTrue(exported)
        assertTrue(failure.message.orEmpty().contains("analysis and metadata exceeded 250 milliseconds after export"))
        assertFalse(output.resolve("reports/ghidra_analysis.json").exists())
    }

    @Test
    fun `insufficient metadata working set is rejected before analyzer budget binding`() {
        var bound = false
        val analyzer = GhidraJvmAnalyzer(object : ExportBudgetedProgramModelAnalyzer {
            override fun analyze(binaryPath: Path, workDir: Path): RecoveredProgramModel = error("must not analyze")
            override fun withExportBudgets(budgets: ReconstructionBudgets): ProgramModelAnalyzer {
                bound = true
                error("insufficient metadata working set must be rejected first")
            }
        })

        assertFailsWith<IllegalArgumentException> {
            analyzer.withExportBudgets(GeneratedCMakeReconstructionProfile.descriptor.budgets.copy(
                exportMaximumResidentBytes = BoundedElfMetadataLimits.MINIMUM_MODELED_METADATA_BYTES - 1,
            ))
        }
        assertFalse(bound)
    }

    private fun budgetCapable(operation: (Path, Path) -> RecoveredProgramModel) = object : ExportBudgetedProgramModelAnalyzer {
        override fun analyze(binaryPath: Path, workDir: Path): RecoveredProgramModel = error("must use bound analyzer")
        override fun withExportBudgets(budgets: ReconstructionBudgets): ProgramModelAnalyzer = ProgramModelAnalyzer(operation)
    }

    private fun model(inputSha256: String) = RecoveredProgramModel(inputSha256 = inputSha256, functions = emptyList())
}
