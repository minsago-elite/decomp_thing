package decompengine.project

import decompengine.analysis.GhidraAnalysisException
import decompengine.analysis.GhidraInvocation
import java.time.Duration
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

class GhidraExportBudgetBindingTest {
    @Test
    fun `bound analyzers apply requested and stricter existing deadlines to an owned worker`() {
        data class Case(val configuredMillis: Long, val requestedMillis: Long, val configuredBytes: Long, val requestedBytes: Long)
        val smallResidentLimit = 64L * 1024 * 1024
        val cases = listOf(
            Case(5_000, 250, smallResidentLimit * 2, smallResidentLimit),
            Case(250, 5_000, smallResidentLimit, smallResidentLimit * 2),
        )
        for (case in cases) {
            val root = createTempDirectory("export-budget-deadline-")
            try {
                val input = root.resolve("authored-input.txt").also { it.writeText("Authored local export input\n") }
                val work = root.resolve("analysis")
                val invocations = mutableListOf<GhidraInvocation>()
                val toolIdentity = "b".repeat(64)
                val analyzer: ExportBudgetedProgramModelAnalyzer = GhidraHeadlessProgramModelAnalyzer(
                    commandFactory = { invocation ->
                        invocations += invocation
                        listOf("/bin/sleep", "10")
                    },
                    limits = GhidraProgramModelExportLimits(
                        wallClockTimeout = Duration.ofMillis(case.configuredMillis),
                        terminationGrace = Duration.ofMillis(100),
                        maximumResidentBytes = case.configuredBytes,
                        maximumDiagnosticBytesPerStream = 32,
                    ),
                    analysisToolSha256 = toolIdentity,
                    recoveryMode = GhidraProgramModelRecoveryMode.PLANNING,
                )
                val bounded = analyzer.withExportBudgets(GeneratedCMakeReconstructionProfile.descriptor.budgets.copy(
                    exportWallClockMillis = case.requestedMillis,
                    exportMaximumResidentBytes = case.requestedBytes,
                ))
                assertTrue(invocations.isEmpty())
                assertFalse(work.exists())

                val failure = assertFailsWith<GhidraAnalysisException> { bounded.analyze(input, work) }

                assertTrue(failure.message.orEmpty().contains("exceeded 250 milliseconds"))
                val invocation = invocations.single()
                assertEquals(input, invocation.input)
                assertEquals(listOf(toolIdentity, "planning"), invocation.postScripts.single().arguments.subList(1, 3))
                val usage = Json.parseToJsonElement(work.resolve("reports/ghidra_resource_usage.json").readText()).jsonObject
                assertEquals(250L, usage.getValue("wallClockMillisLimit").jsonPrimitive.long)
                assertEquals(smallResidentLimit, usage.getValue("maximumResidentBytesLimit").jsonPrimitive.long)
                assertEquals(32L, usage.getValue("maximumDiagnosticBytesPerStream").jsonPrimitive.long)
                assertFalse(work.resolve("reports/program_model.json").exists())
            } finally {
                root.toFile().deleteRecursively()
            }
        }
    }

    @Test
    fun `binding preserves the configured diagnostic stream limit during export`() {
        val root = createTempDirectory("export-budget-diagnostics-")
        try {
            val input = root.resolve("authored-input.txt").also { it.writeText("Authored local export input\n") }
            val work = root.resolve("analysis")
            val analyzer: ExportBudgetedProgramModelAnalyzer = GhidraHeadlessProgramModelAnalyzer(
                commandFactory = { listOf("/usr/bin/printf", "0123456789") },
                limits = GhidraProgramModelExportLimits(maximumDiagnosticBytesPerStream = 8),
            )
            val bounded = analyzer.withExportBudgets(GeneratedCMakeReconstructionProfile.descriptor.budgets)

            val failure = assertFailsWith<GhidraAnalysisException> { bounded.analyze(input, work) }

            assertTrue(failure.message.orEmpty().contains("8 diagnostic bytes"))
            assertEquals("01234567", work.resolve("reports/ghidra_stdout.log").readText())
            assertEquals("", work.resolve("reports/ghidra_stderr.log").readText())
            assertFalse(work.resolve("reports/program_model.json").exists())
        } finally {
            root.toFile().deleteRecursively()
        }
    }
}
