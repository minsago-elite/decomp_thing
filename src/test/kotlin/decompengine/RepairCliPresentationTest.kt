package decompengine

import decompengine.repair.*
import decompengine.validation.*
import decompengine.jobs.ProgressRedactor
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.Charset
import java.nio.charset.CharsetDecoder
import java.nio.charset.CharsetEncoder
import java.nio.charset.CoderResult
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.*

class RepairCliPresentationTest {
    @Test
    fun `repair action masks preparation failures before dispatch and retains status and cleanup`() {
        val secret = "SYNTHETIC_REPAIR_PREPARATION"
        val bytes = ByteArrayOutputStream()
        PrintStream(bytes, true, Charsets.UTF_8).use { output ->
            val stages = listOf("exploration", "runtime", "presentation")
            for (failedStage in stages) for (failure in listOf(
                java.io.IOException("$failedStage: $secret"),
                IllegalArgumentException("$failedStage: $secret"),
                NumberFormatException("$failedStage: $secret"),
            )) {
                val entered = mutableListOf<String>()
                var closed = false
                assertEquals(1, runRepairCliAction(listOf(secret), output) {
                    AutoCloseable { closed = true }.use {
                        for (stage in stages) {
                            entered += stage
                            if (stage == failedStage) throw failure
                        }
                        0
                    }
                })
                assertEquals(stages.take(stages.indexOf(failedStage) + 1), entered)
                assertTrue(closed)
                val diagnostic = bytes.toString(Charsets.UTF_8)
                assertTrue(diagnostic.startsWith("repair unavailable or failed:"), diagnostic)
                assertFalse(diagnostic.contains("usage:"), diagnostic)
                assertFalse(diagnostic.contains(secret), diagnostic)
                assertFalse(diagnostic.contains("Exception"), diagnostic)
                bytes.reset()
            }
            val configurationFailure = assertFailsWith<RepairCliConfigurationException> {
                prepareRepairCliConfiguration(Path.of("synthetic-repair-history.json"), "invalid-harness")
            }
            assertIs<IllegalArgumentException>(configurationFailure.cause)
            assertEquals(2, runRepairCliAction(emptyList(), output) { throw configurationFailure })
            assertTrue(bytes.toString(Charsets.UTF_8).contains(WorkflowCliCommand.REPAIR.usage))
            bytes.reset()
            val suppliedValues = mutableListOf(secret)
            val originalConfigurationFailure = IllegalArgumentException("invalid $secret")
            val privateConfigurationFailure = RepairCliConfigurationException(originalConfigurationFailure)
            assertSame(originalConfigurationFailure, privateConfigurationFailure.cause)
            assertEquals(2, runRepairCliAction(suppliedValues, output) {
                suppliedValues.clear()
                throw privateConfigurationFailure
            })
            assertTrue(bytes.toString(Charsets.UTF_8).contains(WorkflowCliCommand.REPAIR.usage))
            assertFalse(bytes.toString(Charsets.UTF_8).contains(secret))
            bytes.reset()
            for (status in 0..2) {
                assertEquals(status, runRepairCliAction(emptyList(), output) { status })
                assertEquals("", bytes.toString(Charsets.UTF_8))
            }
            var dispatched = false
            val rejected = object : AbstractCollection<String>() {
                override val size: Int = 4097
                override fun iterator(): Iterator<String> = error("$secret must not be read")
            }
            assertEquals(1, runRepairCliAction(rejected, output) { dispatched = true; 0 })
            assertFalse(dispatched)
            assertEquals("", bytes.toString(Charsets.UTF_8))
            val initiallyInterrupted = Thread.interrupted()
            try {
                assertEquals(1, runRepairCliAction(listOf(secret), output) { throw InterruptedException(secret) })
                assertTrue(Thread.currentThread().isInterrupted)
                assertFalse(bytes.toString(Charsets.UTF_8).contains(secret))
            } finally {
                Thread.interrupted()
                if (initiallyInterrupted) Thread.currentThread().interrupt()
            }
            bytes.reset()
            val fatal = AssertionError(secret)
            assertSame(fatal, assertFailsWith<AssertionError> {
                runRepairCliAction(listOf(secret), output) { throw fatal }
            })
            assertEquals("", bytes.toString(Charsets.UTF_8))
        }
    }

    @Test
    fun `CLI encoding cannot reconstruct secrets through replacement or a lossy codec alias`() {
        val secret = "a?b"
        val hash = "1".repeat(64)
        val lossy = object : Charset("synthetic-lossy", emptyArray()) {
            override fun contains(cs: Charset) = cs === this
            override fun newDecoder(): CharsetDecoder = object : CharsetDecoder(this, 1f, 1f) {
                override fun decodeLoop(input: ByteBuffer, output: CharBuffer): CoderResult {
                    while (input.hasRemaining()) {
                        if (!output.hasRemaining()) return CoderResult.OVERFLOW
                        output.put((input.get().toInt() and 255).toChar())
                    }
                    return CoderResult.UNDERFLOW
                }
            }
            override fun newEncoder(): CharsetEncoder = object : CharsetEncoder(this, 1f, 1f) {
                override fun encodeLoop(input: CharBuffer, output: ByteBuffer): CoderResult {
                    while (input.hasRemaining()) {
                        val unit = input.get(input.position())
                        if (unit.code > 127 && unit != '€') return CoderResult.unmappableForLength(1)
                        if (!output.hasRemaining()) return CoderResult.OVERFLOW
                        input.get()
                        output.put((if (unit == '€') '?' else unit).code.toByte())
                    }
                    return CoderResult.UNDERFLOW
                }
            }
        }
        for ((charset, raw) in listOf(Charsets.US_ASCII to "a€b", Charsets.UTF_8 to "a\uD800b", lossy to "a€b")) {
            val baseline = ByteArrayOutputStream()
            PrintStream(baseline, true, charset).use { it.print("$raw\n") }
            assertEquals("$secret\n", baseline.toString(Charsets.US_ASCII))
            val bytes = ByteArrayOutputStream()
            PrintStream(bytes, true, charset).use { output ->
                val shown = RepairCliPresentation(0, listOf(raw))
                assertEquals(1, renderRepairPresentation(shown, listOf(secret), output))
                assertEquals(RepairCliPresentation(0, listOf(raw)), shown)
                assertEquals("", bytes.toString())
                assertFailsWith<decompengine.mvp.MvpPatchException> {
                    renderReconstructionSuccess(raw, "archive.zip", hash, listOf(secret), output)
                }
                assertEquals("", bytes.toString())
                assertEquals(2, renderWorkflowUsageError(WorkflowCliCommand.RECONSTRUCT, raw, listOf(secret), output))
                assertEquals("${WorkflowCliCommand.RECONSTRUCT.usage}\n", bytes.toString(Charsets.US_ASCII))
                bytes.reset()
                renderWorkflowFailure(WorkflowCliCommand.PATCH, raw, ProgressRedactor(listOf(secret)), output)
                renderWorkflowProvenance(WorkflowCliCommand.PATCH, raw, ProgressRedactor(listOf(secret)), output)
                assertEquals("", bytes.toString())
                assertEquals(0, runDoctorCliAction(listOf(secret), output, output) {
                    decompengine.doctor.DoctorReport(listOf(decompengine.doctor.DoctorCheck(raw, true, "available")))
                })
                assertEquals("Environment check passed (1 checks)\n", bytes.toString(Charsets.US_ASCII))
                assertFalse(bytes.toString(Charsets.US_ASCII).contains(secret))
            }
        }
        for (charset in listOf(Charsets.UTF_8, Charsets.UTF_16)) {
            val bytes = ByteArrayOutputStream()
            PrintStream(bytes, true, charset).use { output ->
                repeat(2) {
                    assertEquals(0, renderRepairPresentation(RepairCliPresentation(0, listOf("public € 😀")), listOf(secret), output))
                }
                assertEquals("public € 😀\n".repeat(2), bytes.toString(charset))
            }
        }
        val masked = ByteArrayOutputStream()
        PrintStream(masked, true, Charsets.US_ASCII).use { output ->
            assertEquals(0, renderRepairPresentation(RepairCliPresentation(0, listOf("a€b")), listOf("a€b"), output))
            assertEquals("[REDACTED]\n", masked.toString(Charsets.US_ASCII))
        }
        for (count in listOf(8190, 8191)) {
            val bytes = ByteArrayOutputStream()
            PrintStream(bytes, true, Charsets.UTF_16).use { output ->
                assertEquals(if (count == 8190) 0 else 1,
                    renderRepairPresentation(RepairCliPresentation(0, listOf("x".repeat(count))), emptyList(), output))
                assertEquals(if (count == 8190) 16_384 else 0, bytes.size())
            }
        }
    }

    @Test
    fun `repair result projection preserves typed outcomes and masks complete private display frames`() {
        val bytes = ByteArrayOutputStream()
        PrintStream(bytes, true, Charsets.UTF_8).use { output ->
            for (status in RepairRunStatus.entries) {
                val result = outcome(status, report())
                val shown = presentRepairOutcome(result)
                val snapshot = shown.copy(lines = shown.lines.toList())
                assertEquals(shown.exitCode, renderRepairPresentation(shown, emptyList(), output))
                assertEquals(shown.lines.joinToString("") { "$it\n" }, bytes.toString(Charsets.UTF_8))
                assertEquals(snapshot, shown)
                assertEquals(status, result.runState.status)
                bytes.reset()
            }
            val shown = presentRepairOutcome(outcome(RepairRunStatus.ITERATION_EXHAUSTED, null))
            val snapshot = shown.copy(lines = shown.lines.toList())
            val completion = "repair did not establish full acceptance; inspect durable repair state and retained reports"
            assertEquals(1, renderRepairPresentation(shown, listOf(completion, "run_00000001"), output))
            assertFalse(bytes.toString(Charsets.UTF_8).contains(completion))
            assertFalse(bytes.toString(Charsets.UTF_8).contains("run_00000001"))
            assertTrue(bytes.toString(Charsets.UTF_8).contains("[REDACTED]"))
            assertEquals(snapshot, shown)
            bytes.reset()
            assertEquals(2, renderRepairPresentation(RepairCliPresentation(2, listOf("first", "second", "last")),
                listOf("first\nsecond"), output))
            assertEquals("[REDACTED]\n[REDACTED]\nlast\n", bytes.toString(Charsets.UTF_8))
            bytes.reset()
            assertEquals(0, renderRepairPresentation(RepairCliPresentation(0, listOf("first", "last")),
                listOf("first\nlast\n"), output))
            assertEquals("[REDACTED]\n[REDACTED]\n", bytes.toString(Charsets.UTF_8))
            bytes.reset()
            assertEquals(1, renderRepairPresentation(RepairCliPresentation(1,
                listOf("Bearer synthetic-token", "Authorization: Basic c3ludGhldGlj", "password=synthetic-password")),
                emptyList(), output))
            listOf("synthetic-token", "c3ludGhldGlj", "synthetic-password").forEach {
                assertFalse(bytes.toString(Charsets.UTF_8).contains(it))
            }
        }
    }

    @Test
    fun `repair result refusal emits no partial payload and preserves interruption and fatal errors`() {
        val bytes = ByteArrayOutputStream()
        PrintStream(bytes, true, Charsets.UTF_8).use { output ->
            val valid = RepairCliPresentation(0, listOf("PRIVATE_RESULT"))
            val tooMany = object : AbstractCollection<String>() {
                override val size: Int = 4097
                override fun iterator(): Iterator<String> = error("rejected inventory must not be iterated")
            }
            val broken = object : AbstractCollection<String>() {
                override val size: Int = 1
                override fun iterator(): Iterator<String> = throw IllegalArgumentException("PRIVATE_INVENTORY_FAILURE")
            }
            for (values in listOf(tooMany, broken, listOf("x".repeat(1024 * 1024 + 1)))) {
                assertEquals(1, renderRepairPresentation(valid, values, output))
                assertEquals("", bytes.toString(Charsets.UTF_8))
            }
            val deceptiveLines = object : List<String> by listOf("") {
                override fun iterator(): Iterator<String> = List(33) { "" }.iterator()
            }
            for (shown in listOf(RepairCliPresentation(0, List(33) { "" }),
                RepairCliPresentation(0, deceptiveLines), RepairCliPresentation(-1, listOf("PRIVATE_STATUS")),
                RepairCliPresentation(0, listOf("é".repeat(9000))))) {
                assertEquals(1, renderRepairPresentation(shown, emptyList(), output))
                assertEquals("", bytes.toString(Charsets.UTF_8))
            }
            assertEquals(1, renderRepairPresentation(RepairCliPresentation(0, listOf("xa".repeat(3000))), listOf("x"), output))
            assertEquals("", bytes.toString(Charsets.UTF_8))
            for (shown in listOf(RepairCliPresentation(0, listOf("first\nsecond")),
                RepairCliPresentation(0, listOf("Authorization: Basic", "synthetic-token")))) {
                assertEquals(1, renderRepairPresentation(shown, emptyList(), output))
                assertEquals("", bytes.toString(Charsets.UTF_8))
            }
            assertEquals(1, renderRepairPresentation(valid, listOf("\u0000\n"), output))
            assertEquals("", bytes.toString(Charsets.UTF_8))
            val initiallyInterrupted = Thread.interrupted()
            try {
                val interrupted = object : AbstractCollection<String>() {
                    override val size: Int = 1
                    override fun iterator(): Iterator<String> = throw InterruptedException("PRIVATE_INTERRUPTED_RESULT")
                }
                assertEquals(1, renderRepairPresentation(valid, interrupted, output))
                assertTrue(Thread.currentThread().isInterrupted)
                assertEquals("", bytes.toString(Charsets.UTF_8))
            } finally {
                Thread.interrupted()
                if (initiallyInterrupted) Thread.currentThread().interrupt()
            }
            val fatal = AssertionError("PRIVATE_FATAL_RESULT")
            val fatalValues = object : AbstractCollection<String>() {
                override val size: Int = 1
                override fun iterator(): Iterator<String> = throw fatal
            }
            assertSame(fatal, assertFailsWith<AssertionError> { renderRepairPresentation(valid, fatalValues, output) })
            assertEquals("", bytes.toString(Charsets.UTF_8))
            assertEquals(0, renderRepairPresentation(RepairCliPresentation(0, List(32) { "line" }), emptyList(), output))
            assertEquals("line\n".repeat(32), bytes.toString(Charsets.UTF_8))
        }
    }

    @Test
    fun `repair exploration projects the complete bounded count summary`() {
        val bytes = ByteArrayOutputStream()
        PrintStream(bytes, true, Charsets.UTF_8).use { output ->
            val expected = "exploration retained 3 regression input(s) across 7 observed output signature(s)\n"
            renderRepairExplorationSummary(3, 7, ProgressRedactor(emptyList()), output)
            assertEquals(expected, bytes.toString(Charsets.UTF_8))
            bytes.reset()
            for (value in listOf(expected, "exploration retained", "3 regression input(s) across 7")) {
                renderRepairExplorationSummary(3, 7, ProgressRedactor(listOf(value)), output)
                assertFalse(bytes.toString(Charsets.UTF_8).contains(value))
                assertTrue(bytes.toString(Charsets.UTF_8).contains("[redacted]"))
                assertTrue(bytes.toString(Charsets.UTF_8).endsWith("\n"))
                bytes.reset()
            }
            renderRepairExplorationSummary(3, 7, ProgressRedactor(listOf(expected, "[redacted]\n")), output)
            assertEquals("\n", bytes.toString(Charsets.UTF_8))
            bytes.reset()
            renderRepairExplorationSummary(3, 7, ProgressRedactor(listOf("\u0000\n")), output)
            assertEquals("", bytes.toString(Charsets.UTF_8))
            assertFailsWith<IllegalArgumentException> { renderRepairExplorationSummary(-1, 0, ProgressRedactor(emptyList()), output) }
            assertEquals("", bytes.toString(Charsets.UTF_8))
        }
    }

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
            for (value in listOf("usage: llm_bin_patch repair", "legacy-openai]\n")) {
                assertEquals(2, renderRepairUsageError("boundary", listOf(value), output))
                assertEquals("boundary\n$usage\n", bytes.toString(Charsets.UTF_8))
                bytes.reset()
            }
            assertEquals(2, renderRepairUsageError("boundary", listOf("boundary\nusage:"), output))
            assertEquals("$usage\n", bytes.toString(Charsets.UTF_8))
            bytes.reset()
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
