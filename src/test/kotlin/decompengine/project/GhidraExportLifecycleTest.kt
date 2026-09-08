package decompengine.project

import decompengine.analysis.GhidraAnalysisException
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class GhidraExportLifecycleTest {
    @Test
    fun `diagnostic limits retain bounded stdout and stderr before rejecting export`() {
        for (stderr in listOf(false, true)) {
            val work = createTempDirectory("export-diagnostic-cap-").resolve("analysis")
            val command = if (stderr) listOf("/bin/sh", "-c", "printf 0123456789 >&2")
                else listOf("/usr/bin/printf", "0123456789")
            val analyzer = GhidraHeadlessProgramModelAnalyzer({ command },
                GhidraProgramModelExportLimits(maximumDiagnosticBytesPerStream = 8))
            val failure = assertFailsWith<GhidraAnalysisException> { analyzer.analyze(Path.of("unused-authored-input"), work) }
            assertTrue(failure.message.orEmpty().contains("8 diagnostic bytes"))
            val selected = if (stderr) "stderr" else "stdout"
            val other = if (stderr) "stdout" else "stderr"
            assertEquals("01234567", work.resolve("reports/ghidra_$selected.log").readText())
            assertEquals(0, work.resolve("reports/ghidra_$other.log").readBytes().size)
            assertTrue(work.resolve("reports/ghidra_resource_usage.json").readText().contains("\"diagnosticLimitExceeded\":true"))
        }
    }

    @Test
    fun `cancelled export terminates its owned worker`() {
        val root = createTempDirectory("export-cancellation-")
        val ready = root.resolve("ready")
        val work = root.resolve("analysis")
        val command = listOf("/bin/sh", "-c", "printf '%s\\n' \"\$\$\" > \"\$1\"; exec /bin/sleep 10",
            "authored-export", ready.toString())
        val analyzer = GhidraHeadlessProgramModelAnalyzer({ command }, GhidraProgramModelExportLimits())
        val failure = AtomicReference<Throwable?>()
        val worker = Thread {
            try { analyzer.analyze(root.resolve("unused-authored-input"), work) }
            catch (error: Throwable) { failure.set(error) }
        }
        var process: ProcessHandle? = null
        try {
            worker.start()
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            var pid: Long? = null
            while (pid == null && worker.isAlive && System.nanoTime() < deadline) {
                pid = if (ready.exists()) ready.readText().trim().toLongOrNull() else null
                if (pid == null) Thread.sleep(5)
            }
            process = ProcessHandle.of(requireNotNull(pid) { "export did not start: ${failure.get()}" }).orElseThrow()
            assertTrue(process.isAlive)
            worker.interrupt()
            worker.join(5_000)
            assertFalse(worker.isAlive)
            assertIs<InterruptedException>(failure.get())
            assertFalse(process.isAlive)
            assertFalse(work.resolve("reports/program_model.json").exists())
        } finally {
            process?.let { if (it.isAlive) it.destroyForcibly() }
            if (worker.isAlive) worker.interrupt()
            worker.join(5_000)
        }
    }

    @Test
    fun `prelaunch export cancellation creates no workspace`() {
        val work = createTempDirectory("export-prelaunch-cancel-").resolve("analysis")
        val analyzer = GhidraHeadlessProgramModelAnalyzer({ error("must not construct a command") })
        val failure = AtomicReference<Throwable?>()
        val worker = Thread {
            Thread.currentThread().interrupt()
            try { analyzer.analyze(Path.of("unused-authored-input"), work) }
            catch (error: Throwable) { failure.set(error) }
        }
        worker.start()
        worker.join(5_000)
        assertFalse(worker.isAlive)
        assertIs<InterruptedException>(failure.get())
        assertFalse(work.exists())
    }
}
