package decompengine.web

import decompengine.jobs.WorkflowExecutionLimits
import decompengine.agent.AgentToolEvent
import decompengine.agent.AgentToolStatus
import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame

/** Filesystem-only controls: no workflow, helper, binary or agent is dispatched. */
@ExtendWith(RecoveryMatrixEvidence::class)
class WebWorkflowExecutionTest {
    private lateinit var root: Path

    @BeforeEach
    fun createFixture() { root = recoveryMatrixTempDirectory("workflow-meter-") }

    @AfterEach
    fun removeFixture() { root.toFile().deleteRecursively() }

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

    @Test
    fun `exceptional completion still classifies a breached tool-call limit`() {
        val meter = meter(root, toolCallsMetered = true)
        val invocation = meter.invocation()
        val failure = IllegalStateException("agent failed after its second tool call")

        val (result, usage) = BoundedWorkflowExecutor().run(
            WorkflowExecutionLimits(60_000uL, 60_000uL, 1024uL, 1uL), meter,
        ) {
            repeat(2) { invocation.observe(AgentToolEvent(it.toLong(), "call-$it", "inert", AgentToolStatus.SUCCEEDED)) }
            throw failure
        }

        assertEquals(WorkflowLimitExhaustion.TOOL_CALLS, assertIs<BoundedWorkflowResult.Exhausted>(result).limit)
        assertEquals(2uL, usage.toolCalls)
    }

    @Test
    fun `exceptional completion remains a failure when no limit was breached`() {
        val meter = meter(root, toolCallsMetered = true)
        val failure = IllegalStateException("ordinary child failure")

        val (result, _) = BoundedWorkflowExecutor().run(
            WorkflowExecutionLimits(60_000uL, 60_000uL, 1024uL, 1uL), meter,
        ) { throw failure }

        assertSame(failure, assertIs<BoundedWorkflowResult.Threw>(result).failure)
    }

    private fun meter(path: Path, toolCallsMetered: Boolean = false) =
        WorkflowExecutionMeter(path, toolCallsMetered = toolCallsMetered)
}
