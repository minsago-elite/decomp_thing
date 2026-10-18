package decompengine

import decompengine.repair.*
import decompengine.validation.*
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.*

class RepairCliPresentationTest {
    @Test
    fun `repair usage diagnostics admit secrets before printing complete terminal framing`() {
        val usage = "usage: llm_bin_patch repair <original-binary> <project-dir> [--reports <directory>] [--max-iterations <count>] [--explore] [--harness acp|legacy-openai]"
        val bytes = ByteArrayOutputStream()
        PrintStream(bytes, true, Charsets.UTF_8).use { output ->
            val secret = "SYNTHETIC_REPAIR_KEY"
            for (argument in listOf("--unknown=$secret", secret)) {
                assertEquals(2, renderRepairUsageError("unexpected argument: $argument", listOf(secret), output))
                assertEquals("unexpected argument: ${argument.replace(secret, "[redacted]")}\n$usage\n",
                    bytes.toString(Charsets.UTF_8))
                assertFalse(bytes.toString(Charsets.UTF_8).contains(secret))
                bytes.reset()
            }
            assertEquals(2, renderRepairUsageError("unexpected argument: public", emptyList(), output))
            assertEquals("unexpected argument: public\n$usage\n", bytes.toString(Charsets.UTF_8))
            bytes.reset()
            val formatted = "Bearer synthetic-bearer; Authorization: Basic c3ludGhldGlj; password=synthetic-password"
            assertEquals(2, renderRepairUsageError(formatted, emptyList(), output))
            listOf("synthetic-bearer", "c3ludGhldGlj", "synthetic-password").forEach {
                assertFalse(bytes.toString(Charsets.UTF_8).contains(it))
            }
            bytes.reset()
            assertEquals(2, renderRepairUsageError("private\u000Cargument", listOf("privateargument"), output))
            assertEquals("[redacted]\n$usage\n", bytes.toString(Charsets.UTF_8))
            bytes.reset()
            for (value in listOf("usage: llm_bin_patch repair", "boundary\nusage:", "legacy-openai]\n")) {
                assertEquals(2, renderRepairUsageError("boundary", listOf(value), output))
                assertFalse(bytes.toString(Charsets.UTF_8).contains(value), "terminal framing exposed $value")
                bytes.reset()
            }
            assertEquals(2, renderRepairUsageError("fooX", listOf("foo", "[redacted]X"), output))
            assertFalse(bytes.toString(Charsets.UTF_8).contains("foo"))
            assertFalse(bytes.toString(Charsets.UTF_8).contains("[redacted]X"))
            bytes.reset()
            val tooMany = object : AbstractCollection<String>() {
                override val size: Int = 4097
                override fun iterator(): Iterator<String> = error("rejected inventory must not be iterated")
            }
            for (values in listOf(tooMany, listOf("x".repeat(1024 * 1024 + 1)))) {
                assertEquals(2, renderRepairUsageError("PRIVATE_REPAIR_ARGUMENT", values, output))
                assertEquals("", bytes.toString(Charsets.UTF_8))
            }
            assertEquals(2, renderRepairUsageError("x".repeat(16_385), emptyList(), output))
            assertEquals("", bytes.toString(Charsets.UTF_8))
        }
    }

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
        assertEquals(24, shown.lines.size)
        assertTrue(shown.lines.any { it.contains("20 earlier iterations omitted") })
        assertTrue(shown.lines.any { it == "repair iteration 40: provisional" })
        assertFalse(shown.lines.joinToString("\n").contains("private"))
    }

    private fun outcome(status: RepairRunStatus, report: BehaviorComparisonReport?) = RepairRunOutcome(emptyList(), report,
        RepairRunState("run_00000001", status, "baseline", "earlier-accepted-head", null, "a".repeat(64), 2, 2, 1, 2,
            rollbackFailureAttemptId = if (status == RepairRunStatus.ROLLBACK_FAILED) "revision_fixture" else null,
            rollbackResolution = if (status == RepairRunStatus.ROLLBACK_FAILED) RepairRollbackState.RESTORE_FAILED_UNRESOLVED else null))

    private fun report(matched: Boolean = true) = BehaviorComparisonReport("fixture", Path.of("reference"), Path.of("candidate"),
        listOf(BehaviorCaseResult(ProcessInput("case"),
            ProcessOutput(0, "ordinary".toByteArray(), byteArrayOf(), listOf("fixture")),
            ProcessOutput(0, (if (matched) "ordinary" else "different").toByteArray(), byteArrayOf(), listOf("fixture")))),
        Path.of("report.json"))
}
