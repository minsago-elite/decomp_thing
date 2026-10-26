package decompengine.web

import decompengine.jobs.WorkflowExecutionLimits
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

/** Filesystem-only controls: no workflow, helper, binary or agent is dispatched. */
class WebWorkflowExecutionTest {
    @TempDir
    lateinit var root: Path

    @Test
    fun `output metering distinguishes absent output from an invalid reports root`() {
        assertEquals(0L, meter(root.resolve("not-created")).outputBytes())
        assertEquals(0L, meter(Files.createDirectory(root.resolve("empty"))).outputBytes())
        val file = Files.write(root.resolve("not-a-directory"), ByteArray(4096))
        assertNull(meter(file).outputBytes(), "a replaced report root is not empty output")
        assertNull(meter(file.resolve("child")).outputBytes(), "an unreadable path is not empty output")
        val reports = Files.createDirectory(root.resolve("reports"))
        Files.write(reports.resolve("result"), ByteArray(17))
        assertEquals(17L, meter(reports).outputBytes())
        val link = Files.createSymbolicLink(root.resolve("link"), reports)
        assertNull(meter(link).outputBytes(), "a linked report root cannot prove the attempt's retained bytes")
        assertNull(WorkflowExecutionMeter(reports, toolCallsMetered = false, maximumEntries = 1).outputBytes())
    }

    @Test
    fun `completion cannot accept output whose report root was replaced`() {
        val reports = Files.createDirectory(root.resolve("replaced"))
        val (result, _) = BoundedWorkflowExecutor().run(
            WorkflowExecutionLimits(60_000uL, 60_000uL, 1024uL, 0uL), meter(reports),
        ) {
            Files.delete(reports)
            Files.write(reports, ByteArray(4096))
        }
        assertEquals(WorkflowLimitExhaustion.OUTPUT_BYTES, assertIs<BoundedWorkflowResult.Exhausted>(result).limit)
    }

    private fun meter(path: Path) = WorkflowExecutionMeter(path, toolCallsMetered = false)
}
