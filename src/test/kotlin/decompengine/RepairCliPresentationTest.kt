package decompengine

import decompengine.repair.*
import decompengine.validation.*
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.*

class RepairCliPresentationTest {
    @Test
    fun `repair CLI reports unavailable validation without exposing an exception stack`() {
        val root = createTempDirectory("repair-cli-unavailable-")
        val process = ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-Djava.io.tmpdir=${System.getProperty("java.io.tmpdir")}", "-cp", System.getProperty("java.class.path"),
            "decompengine.MainKt", "repair", root.resolve("original").toString(), root.resolve("project").toString())
            .apply { environment().clear() }.start()
        try {
            assertTrue(process.waitFor(10, TimeUnit.SECONDS))
            val stderr = process.errorStream.readNBytes(32 * 1024).decodeToString()
            assertEquals(1, process.exitValue(), stderr)
            assertTrue(stderr.startsWith("repair unavailable or failed:"), stderr)
            assertFalse(stderr.contains("Exception in thread"), stderr)
            assertFalse(java.nio.file.Files.exists(root.resolve("project/reports/repair-revisions/graph.json")))
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor(5, TimeUnit.SECONDS)
        }
    }

    @Test
    fun `an unsuccessful durable run cannot claim success from a matching report or prior accepted head`() {
        RepairRunStatus.entries.filter { it != RepairRunStatus.FULLY_ACCEPTED }.forEach { status ->
            val shown = presentRepairOutcome(outcome(status, report()))
            assertEquals(1, shown.exitCode, status.name)
            assertTrue(shown.lines.first().contains(status.name.lowercase()))
            assertFalse(shown.lines.any { it.startsWith("repair passed") })
        }
    }

    @Test
    fun `accepted presentation requires a complete nonempty matching report`() {
        assertEquals(0, presentRepairOutcome(outcome(RepairRunStatus.FULLY_ACCEPTED, report())).exitCode)
        listOf(null, report().copy(cases = emptyList()), report(matched = false)).forEach { validation ->
            assertEquals(1, presentRepairOutcome(outcome(RepairRunStatus.FULLY_ACCEPTED, validation)).exitCode)
        }
    }

    @Test
    fun `console history is bounded and never prints peer summaries diagnostics or prompts`() {
        val iteration = RepairIteration(1, "private failure", "private prompt", "private summary", emptyList(), emptyList(),
            after = RepairEvidence("private kind", "private diagnostics", "/private/path"),
            disposition = RepairAttemptDisposition.PROVISIONAL)
        val shown = presentRepairOutcome(outcome(RepairRunStatus.ITERATION_EXHAUSTED, null).copy(
            iterations = (1..40).map { iteration.copy(index = it) }))
        assertEquals(23, shown.lines.size)
        assertTrue(shown.lines.any { it.contains("20 earlier iterations omitted") })
        assertTrue(shown.lines.any { it == "repair iteration 40: provisional" })
        assertFalse(shown.lines.joinToString("\n").contains("private"))
    }

    private fun outcome(status: RepairRunStatus, report: BehaviorComparisonReport?) = RepairRunOutcome(emptyList(), report,
        RepairRunState("run_00000001", status, "baseline", "earlier-accepted-head", null, "a".repeat(64), 2, 2, 1, 2))

    private fun report(matched: Boolean = true) = BehaviorComparisonReport("fixture", Path.of("reference"), Path.of("candidate"),
        listOf(BehaviorCaseResult(ProcessInput("case"),
            ProcessOutput(0, "ordinary".toByteArray(), byteArrayOf(), listOf("fixture")),
            ProcessOutput(0, (if (matched) "ordinary" else "different").toByteArray(), byteArrayOf(), listOf("fixture")))),
        Path.of("report.json"))
}
