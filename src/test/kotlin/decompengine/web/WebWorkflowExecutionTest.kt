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
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith

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

    @Test
    fun `cancellation after publication admission waits for the atomic decision`() {
        val limits = WorkflowExecutionLimits(60_000uL, 60_000uL, 1024uL, 0uL)
        val meter = meter(root)
        val admitted = CountDownLatch(1)
        val release = CountDownLatch(1)
        val result = AtomicReference<Pair<BoundedWorkflowResult<String>, decompengine.jobs.WorkflowUsage>?>(null)
        val failure = AtomicReference<Throwable?>(null)
        val interruptStillSet = AtomicBoolean(true)
        val caller = Thread {
            try {
                result.set(BoundedWorkflowExecutor(pollMillis = 5, outputPollMillis = 10).run(limits, meter) {
                    meter.admitPublication(limits)
                    admitted.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                    "published"
                })
                interruptStillSet.set(Thread.currentThread().isInterrupted)
            } catch (caught: Throwable) { failure.set(caught) }
        }
        caller.start()
        assertEquals(true, admitted.await(5, TimeUnit.SECONDS), "publication admission was not reached")
        caller.interrupt()
        Thread.sleep(25)
        assertEquals(true, caller.isAlive, "the admitted publication must finish before the caller returns")
        release.countDown()
        caller.join(5_000)
        assertEquals(false, caller.isAlive, "executor did not finish after publication was released")
        assertNull(failure.get())
        assertEquals("published", assertIs<BoundedWorkflowResult.Returned<String>>(result.get()?.first).value)
        assertEquals(false, interruptStillSet.get(), "the committed publication resolves the raced cancellation as completion")
    }

    @Test
    fun `cancellation before publication admission closes the admission gate`() {
        val limits = WorkflowExecutionLimits(60_000uL, 60_000uL, 1024uL, 0uL)
        val meter = meter(root)
        meter.beginExecution(System.nanoTime())
        assertTrue(meter.requestCancellationBeforePublication())
        assertFailsWith<InterruptedException> { meter.admitPublication(limits) }
        assertFalse(meter.publicationDecisionIsAdmitted())
    }

    @Test
    fun `pending publication failure takes precedence over caller cancellation`() {
        val limits = WorkflowExecutionLimits(60_000uL, 60_000uL, 1024uL, 0uL)
        val childStarted = CountDownLatch(1)
        val pending = decompengine.project.ReconstructionPublicationPendingException()
        val failure = AtomicReference<Throwable?>()
        val caller = Thread {
            try {
                BoundedWorkflowExecutor(pollMillis = 5, outputPollMillis = 10).run(limits, meter(root)) {
                    childStarted.countDown()
                    try { CountDownLatch(1).await() } catch (_: InterruptedException) { throw pending }
                }
            } catch (caught: Throwable) { failure.set(caught) }
        }
        caller.start()
        assertTrue(childStarted.await(5, TimeUnit.SECONDS))
        caller.interrupt()
        caller.join(5_000)
        assertFalse(caller.isAlive, "executor did not join the cancelled child")
        assertSame(pending, failure.get(), "uncertain rollback must remain visible to the durable service")
    }

    @Test
    fun `pending publication failure takes precedence over exhausted limit`() {
        val childStarted = CountDownLatch(1)
        val pending = decompengine.project.ReconstructionPublicationPendingException()
        var measurements = 0
        val metered = WorkflowExecutionMeter(root, toolCallsMetered = false, outputBytesOverride = {
            if (++measurements == 1) 0L else 2L
        })
        val failure = AtomicReference<Throwable?>()
        val caller = Thread {
            try {
                BoundedWorkflowExecutor(pollMillis = 5, outputPollMillis = 10).run(
                    WorkflowExecutionLimits(60_000uL, 60_000uL, 1uL, 0uL), metered,
                ) {
                    childStarted.countDown()
                    try { CountDownLatch(1).await() } catch (_: InterruptedException) { throw pending }
                }
            } catch (caught: Throwable) { failure.set(caught) }
        }
        caller.start()
        assertTrue(childStarted.await(5, TimeUnit.SECONDS))
        caller.join(5_000)
        assertFalse(caller.isAlive, "executor did not stop the over-limit child")
        assertSame(pending, failure.get(), "uncertain rollback must not be collapsed into LIMIT_EXHAUSTED")
    }

    @Test
    fun `publication deadline is sampled after the final output walk`() {
        var now = 0L
        val meter = WorkflowExecutionMeter(
            root, toolCallsMetered = false, nanoTime = { now },
            outputBytesOverride = { now += TimeUnit.MILLISECONDS.toNanos(2_000); 0L },
        )
        meter.beginExecution(now)
        val failure = assertFailsWith<WorkflowPublicationLimitExceeded> {
            meter.admitPublication(WorkflowExecutionLimits(1_000uL, 1_000uL, 1024uL, 0uL))
        }
        assertEquals(WorkflowLimitExhaustion.WALL_CLOCK, failure.limit)
        assertFalse(meter.publicationDecisionIsAdmitted())
    }

    @Test
    fun `publication idle limit is sampled after the final output walk`() {
        var now = 0L
        val meter = WorkflowExecutionMeter(
            root, toolCallsMetered = false, nanoTime = { now },
            outputBytesOverride = { now += TimeUnit.MILLISECONDS.toNanos(2_000); 0L },
        )
        meter.beginExecution(now)
        val failure = assertFailsWith<WorkflowPublicationLimitExceeded> {
            meter.admitPublication(WorkflowExecutionLimits(5_000uL, 1_000uL, 1024uL, 0uL))
        }
        assertEquals(WorkflowLimitExhaustion.IDLE, failure.limit)
        assertFalse(meter.publicationDecisionIsAdmitted())
    }

    @Test
    fun `generic completion deadline includes its final output walk`() {
        val (result, measurements, _) = completeAfterOnePeriodicSample(
            WorkflowExecutionLimits(5_000uL, 4_000uL, 1024uL, 0uL),
            wallWalkMillis = 6_000,
        )
        assertEquals(3, measurements, "initial, one periodic, then exactly one final output walk")
        assertEquals(WorkflowLimitExhaustion.WALL_CLOCK, assertIs<BoundedWorkflowResult.Exhausted>(result).limit)
    }

    @Test
    fun `generic completion idle limit includes its final output walk`() {
        val (result, measurements, _) = completeAfterOnePeriodicSample(
            WorkflowExecutionLimits(5_000uL, 1_000uL, 1024uL, 0uL),
            wallWalkMillis = 2_000,
        )
        assertEquals(3, measurements, "initial, one periodic, then exactly one final output walk")
        assertEquals(WorkflowLimitExhaustion.IDLE, assertIs<BoundedWorkflowResult.Exhausted>(result).limit)
    }

    /** Holds the child until its first periodic sample, then advances time only on final measurement. */
    private fun completeAfterOnePeriodicSample(
        limits: WorkflowExecutionLimits,
        wallWalkMillis: Long,
    ): Triple<BoundedWorkflowResult<String>, Int, Long> {
        var now = 0L
        var measurements = 0
        val periodicSampleReached = CountDownLatch(1)
        val releaseChild = CountDownLatch(1)
        val meter = WorkflowExecutionMeter(
            root,
            toolCallsMetered = false,
            nanoTime = { now },
            outputBytesOverride = {
                measurements++
                when (measurements) {
                    1 -> 0L // Executor's initial baseline, before the child starts.
                    2 -> {
                        periodicSampleReached.countDown()
                        check(releaseChild.await(5, TimeUnit.SECONDS))
                        0L // The child is still alive, so this is definitely a periodic sample.
                    }
                    3 -> {
                        now += TimeUnit.MILLISECONDS.toNanos(wallWalkMillis)
                        0L // The child has returned; this is the final bounded output walk.
                    }
                    else -> error("unexpected output measurement #$measurements")
                }
            },
        )
        val result = AtomicReference<BoundedWorkflowResult<String>?>()
        val failure = AtomicReference<Throwable?>()
        val runner = Thread {
            try {
                result.set(BoundedWorkflowExecutor(
                    pollMillis = 5, outputPollMillis = 5, nanoTime = { now },
                ).run(limits, meter) {
                    check(periodicSampleReached.await(5, TimeUnit.SECONDS))
                    releaseChild.countDown()
                    "complete"
                }.first)
            } catch (caught: Throwable) { failure.set(caught) }
        }
        runner.start()
        runner.join(5_000)
        releaseChild.countDown()
        assertFalse(runner.isAlive, "bounded executor did not finish")
        assertNull(failure.get())
        return Triple(checkNotNull(result.get()), measurements, now)
    }

    private fun meter(path: Path, toolCallsMetered: Boolean = false) =
        WorkflowExecutionMeter(path, toolCallsMetered = toolCallsMetered)
}
