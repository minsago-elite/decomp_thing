package decompengine.acp

import decompengine.agent.AgentCancellation
import decompengine.agent.AgentCancellationSource
import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentExecutionLimits
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentWorkspaceRoot
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Timeout

@Timeout(10)
class AcpExecutionSchedulerTest {
    @Test
    fun `busy workspace cannot block a different workspace from spare global capacity`() = withWorkers { workers ->
        val scheduler = scheduler(active = 2, queued = 1, queuedPerWorkspace = 1)
        val first = scheduler.admit("workspace-a")
        val waiting = workers.submit(Callable { scheduler.admit("workspace-a") })
        awaitQueued(scheduler, 1)
        val different = scheduler.admit("workspace-b")
        assertEquals(AcpSchedulingSnapshot(2, 1, 2, 0), scheduler.snapshot())
        different.finish()
        assertFalse(waiting.isDone)
        first.finish()
        waiting.get(2, TimeUnit.SECONDS).finish()
        assertEmpty(scheduler)
    }

    @Test
    fun `eligible waiters are admitted in arrival order`() = withWorkers { workers ->
        val scheduler = scheduler(active = 1)
        val first = scheduler.admit("workspace-a")
        val second = workers.submit(Callable { scheduler.admit("workspace-b") })
        awaitQueued(scheduler, 1)
        val third = workers.submit(Callable { scheduler.admit("workspace-c") })
        awaitQueued(scheduler, 2)
        first.finish()
        val secondPermit = second.get(2, TimeUnit.SECONDS)
        assertFalse(third.isDone)
        secondPermit.finish()
        third.get(2, TimeUnit.SECONDS).finish()
        assertEmpty(scheduler)
    }

    @Test
    fun `workspace and global queues reject overload without growing`() = withWorkers { workers ->
        val scheduler = scheduler(active = 1, queued = 2, queuedPerWorkspace = 1)
        val first = scheduler.admit("workspace-a")
        val cancellation = AgentCancellationSource()
        val second = workers.submit(Callable { scheduler.acquire("workspace-a", cancellation.cancellation) { false } })
        awaitQueued(scheduler, 1)
        assertSchedulingFailure(AgentFailureKind.RESOURCE_EXHAUSTED, "queueCapacity") {
            scheduler.admit("workspace-a")
        }
        val third = workers.submit(Callable { scheduler.acquire("workspace-b", cancellation.cancellation) { false } })
        awaitQueued(scheduler, 2)
        assertSchedulingFailure(AgentFailureKind.RESOURCE_EXHAUSTED, "queueCapacity") {
            scheduler.admit("workspace-c")
        }
        assertEquals(2, scheduler.snapshot().queued)
        cancellation.cancel()
        assertNull(second.get(2, TimeUnit.SECONDS))
        assertNull(third.get(2, TimeUnit.SECONDS))
        first.finish()
        assertEmpty(scheduler)
    }

    @Test
    fun `queued cancellation removes only that waiter and preserves eligible successor`() = withWorkers { workers ->
        val scheduler = scheduler(active = 1)
        val first = scheduler.admit("workspace-a")
        val cancellation = AgentCancellationSource()
        val cancelled = workers.submit(Callable { scheduler.acquire("workspace-b", cancellation.cancellation) { false } })
        awaitQueued(scheduler, 1)
        val successor = workers.submit(Callable { scheduler.admit("workspace-c") })
        awaitQueued(scheduler, 2)
        cancellation.cancel()
        assertNull(cancelled.get(2, TimeUnit.SECONDS))
        assertEquals(AcpSchedulingSnapshot(1, 1, 1, 0), scheduler.snapshot())
        first.finish()
        successor.get(2, TimeUnit.SECONDS).finish()
        assertEmpty(scheduler)
    }

    @Test
    fun `blocked caller observers cannot hold scheduler capacity or block other work`() = withWorkers { workers ->
        for (blockCancellation in listOf(false, true)) {
            val scheduler = scheduler(active = 2)
            val first = scheduler.admit("workspace-a")
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val calls = AtomicInteger()
            fun observer(): Boolean {
                if (calls.incrementAndGet() == 2) {
                    entered.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                }
                return false
            }
            val waiting = workers.submit(Callable {
                scheduler.acquire("workspace-a",
                    if (blockCancellation) AgentCancellation { observer() } else AgentCancellation.NONE,
                    if (blockCancellation) ({ false }) else ({ observer() }))
            })
            try {
                assertTrue(entered.await(2, TimeUnit.SECONDS))
                // The waiter remains queued while its observer blocks. Releasing the first
                // permit and reading scheduler state must remain responsive independently.
                val independent = workers.submit(Callable { scheduler.admit("workspace-b").finish() })
                independent.get(1, TimeUnit.SECONDS)
                val releaseFirst = workers.submit(Callable { first.finish(); scheduler.snapshot() })
                assertEquals(AcpSchedulingSnapshot(0, 1, 0, 0), releaseFirst.get(1, TimeUnit.SECONDS))
                release.countDown()
                assertNotNull(waiting.get(2, TimeUnit.SECONDS)).finish()
                scheduler.admit("workspace-c").finish()
                assertEmpty(scheduler)
            } finally {
                release.countDown()
                first.finish()
            }
        }
    }

    @Test
    fun `queue position is reserved before the first observer blocks`() = withWorkers { workers ->
        val scheduler = scheduler(active = 1, queued = 1, queuedPerWorkspace = 1)
        val first = scheduler.admit("workspace-a")
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        val cancelled = AtomicBoolean()
        fun observer(): Boolean {
            if (calls.incrementAndGet() == 1) {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS))
            }
            return cancelled.get()
        }
        val waiting = workers.submit(Callable {
            scheduler.acquire("workspace-b", AgentCancellation { observer() }) { false }
        })
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            // The reservation precedes the blocked observer, so the caller is queued and
            // charged against the queue bounds while its observer is still blocked.
            assertEquals(1, scheduler.snapshot().queued)
            assertSchedulingFailure(AgentFailureKind.RESOURCE_EXHAUSTED, "queueCapacity") {
                scheduler.acquire("workspace-c", AgentCancellation.NONE) { false }
            }
            release.countDown()
            cancelled.set(true)
            assertNull(waiting.get(2, TimeUnit.SECONDS))
            first.finish()
            assertEmpty(scheduler)
        } finally {
            release.countDown()
            first.finish()
        }
    }

    @Test
    fun `slow observer keeps its reserved place ahead of later callers`() = withWorkers { workers ->
        val scheduler = scheduler(active = 1)
        val first = scheduler.admit("workspace-a")
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        fun observer(): Boolean {
            if (calls.incrementAndGet() == 1) {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS))
            }
            return false
        }
        val slow = workers.submit(Callable {
            scheduler.acquire("workspace-b", AgentCancellation { observer() }) { false }
        })
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertEquals(1, scheduler.snapshot().queued)
            val successor = workers.submit(Callable { scheduler.admit("workspace-c") })
            awaitQueued(scheduler, 2)
            release.countDown()
            first.finish()
            // Capacity goes to the reserved head even though its observer was slow; the
            // later caller stays queued behind it.
            val slowPermit = assertNotNull(slow.get(2, TimeUnit.SECONDS))
            assertFalse(successor.isDone)
            slowPermit.finish()
            successor.get(2, TimeUnit.SECONDS).finish()
            assertEmpty(scheduler)
        } finally {
            release.countDown()
            first.finish()
        }
    }

    @Test
    fun `concurrent cancellation churn reclaims every permit within both caps`() = withWorkers { workers ->
        val scheduler = AcpExecutionScheduler(AcpSchedulingLimits(
            maximumActive = 4,
            maximumActivePerWorkspace = 2,
            maximumQueued = 64,
            maximumQueuedPerWorkspace = 16,
        ))
        val active = AtomicInteger()
        val groupActive = List(3) { AtomicInteger() }
        val started = CountDownLatch(1)
        val tasks = (0 until 48).map { index ->
            workers.submit(Callable {
                assertTrue(started.await(2, TimeUnit.SECONDS))
                val group = index % groupActive.size
                val cancelAfter = if (index % 7 == 0) 2 else Int.MAX_VALUE
                var observations = 0
                val permit = scheduler.acquire("workspace-$group", AgentCancellation {
                    observations += 1
                    observations >= cancelAfter
                }) { false } ?: return@Callable
                try {
                    assertTrue(active.incrementAndGet() <= 4)
                    assertTrue(groupActive[group].incrementAndGet() <= 2)
                    Thread.sleep(2)
                } finally {
                    groupActive[group].decrementAndGet()
                    active.decrementAndGet()
                    permit.finish()
                }
            })
        }
        started.countDown()
        tasks.forEach { it.get(3, TimeUnit.SECONDS) }
        assertEquals(0, active.get())
        assertTrue(groupActive.all { it.get() == 0 })
        assertEmpty(scheduler)
    }

    @Test
    fun `observer time consumes queue deadline even with spare capacity`() {
        val scheduler = scheduler(active = 1, queueWait = Duration.ofMillis(25))
        assertSchedulingFailure(AgentFailureKind.TIMEOUT, "queueDeadline") {
            scheduler.acquire("workspace", AgentCancellation {
                Thread.sleep(40)
                false
            }) { false }
        }
        assertEmpty(scheduler)
    }

    @Test
    fun `pre-cancelled requests never acquire capacity`() {
        val scheduler = scheduler(active = 1)
        assertNull(scheduler.acquire("workspace", AgentCancellation { true }) { false })
        assertEmpty(scheduler)
    }

    @Test
    fun `production harness records queue timeout before filesystem or process authority`() {
        val workspace = Path.of("/decomp-scheduler-fixture", UUID.randomUUID().toString())
        val request = AgentExecutionRequest(
            "exercise admission only",
            listOf(AgentWorkspaceRoot("project", workspace)),
            accessPolicy = AgentAccessPolicy(emptyList()),
            limits = AgentExecutionLimits(wallClockTimeout = Duration.ofMillis(75)),
        )
        val occupied = productionAcpExecutionScheduler.admit(workspace.toString())
        try {
            // Neither path exists and no sandbox is provisioned: any pre-admission filesystem
            // or process work would produce a different failure instead of this queue receipt.
            val harness = AcpAgentHarness(AcpProcessConfiguration(workspace.resolve("agent")))
            val receipt = harness.executeReceipt(request) { error("unadmitted execution emitted an event") }
            val failure = assertIs<AgentExecutionOutcome.Failed>(receipt.outcome).failure
            assertEquals(AgentFailureKind.TIMEOUT, failure.kind)
            assertEquals(mapOf("phase" to "scheduler", "reason" to "requestDeadline"), failure.details)
            assertEquals(AgentExecutionRequestBinding.capture(request), receipt.requestBinding)
            val evidence = assertIs<AcpInvocationEvidenceSnapshot>(receipt.providerEvidence)
            assertEquals(AcpExecutionLifecyclePhase.REQUEST_BOUND, evidence.phaseReached)
            assertEquals(AcpExecutionCleanupDisposition.NOT_REQUIRED, evidence.cleanupDisposition)
            assertNull(evidence.diagnostics)
            assertNull(evidence.sandboxEvidence)
            assertNull(evidence.negotiatedAgent)
            assertTrue(evidence.completeness.allPolicyAuditsComplete)
            assertTrue(evidence.filesystemAudit.isEmpty())
            assertTrue(evidence.terminalAudit.isEmpty())
            assertTrue(evidence.permissionAudit.isEmpty())
        } finally {
            occupied.finish()
        }
    }

    @Test
    fun `interruption cancels queued admission and preserves interrupt status`() {
        val scheduler = scheduler(active = 1)
        val first = scheduler.admit("workspace-a")
        val preserved = AtomicBoolean()
        val cancelled = AtomicBoolean()
        val thread = Thread {
            cancelled.set(scheduler.acquire("workspace-b", AgentCancellation.NONE) { false } == null)
            preserved.set(Thread.currentThread().isInterrupted)
        }
        thread.start()
        try {
            awaitQueued(scheduler, 1)
            thread.interrupt()
            thread.join(2_000)
            assertFalse(thread.isAlive)
            assertTrue(cancelled.get())
            assertTrue(preserved.get())
        } finally {
            thread.interrupt()
            first.finish()
            thread.join(2_000)
        }
        assertEmpty(scheduler)
    }

    @Test
    fun `original execution deadline expires while queued`() = withWorkers { workers ->
        val scheduler = scheduler(active = 1)
        val first = scheduler.admit("workspace-a")
        val expired = AtomicBoolean()
        val waiting = workers.submit(Callable {
            scheduler.acquire("workspace-b", AgentCancellation.NONE, expired::get)
        })
        awaitQueued(scheduler, 1)
        expired.set(true)
        val failure = assertFailsWith<ExecutionException> { waiting.get(2, TimeUnit.SECONDS) }.cause
        assertTrue(failure is AgentExecutionException)
        assertEquals(AgentFailureKind.TIMEOUT, failure.failure.kind)
        assertEquals("requestDeadline", failure.failure.details["reason"])
        first.finish()
        assertEmpty(scheduler)
    }

    @Test
    fun `queue wait has a finite deadline independent of request timeout`() = withWorkers { workers ->
        val scheduler = scheduler(active = 1, queueWait = Duration.ofMillis(75))
        val first = scheduler.admit("workspace-a")
        val waiting = workers.submit(Callable {
            assertSchedulingFailure(AgentFailureKind.TIMEOUT, "queueDeadline") { scheduler.admit("workspace-b") }
        })
        waiting.get(2, TimeUnit.SECONDS)
        first.finish()
        assertEmpty(scheduler)
    }

    @Test
    fun `unverified cleanup reserves its slot and prevents reuse of its workspace`() {
        val scheduler = scheduler(active = 2)
        val unresolved = scheduler.admit("workspace-a")
        unresolved.finish(cleanupUnverified = true)
        unresolved.finish() // An accidental second release must not undo quarantine.
        val failure = assertSchedulingFailure(AgentFailureKind.UNAVAILABLE, "cleanupUnverified") {
            scheduler.admit("workspace-a")
        }
        assertFalse(failure.failure.retryable)
        val clean = scheduler.admit("workspace-b")
        clean.finish()
        assertEquals(AcpSchedulingSnapshot(1, 0, 1, 1), scheduler.snapshot())
        val other = scheduler.admit("workspace-b")
        other.finish(cleanupUnverified = true)
        assertSchedulingFailure(AgentFailureKind.UNAVAILABLE, "cleanupUnverified") {
            scheduler.admit("workspace-c")
        }
        assertEquals(AcpSchedulingSnapshot(2, 0, 2, 2), scheduler.snapshot())
    }

    @Test
    fun `queue observer failure releases queue capacity`() = withWorkers { workers ->
        val scheduler = scheduler(active = 1)
        val first = scheduler.admit("workspace-a")
        val fail = AtomicBoolean()
        val waiting = workers.submit(Callable {
            scheduler.acquire("workspace-b", AgentCancellation.NONE) {
                check(!fail.get()) { "synthetic cancellation observer failure" }
                false
            }
        })
        awaitQueued(scheduler, 1)
        fail.set(true)
        assertTrue(assertFailsWith<ExecutionException> { waiting.get(2, TimeUnit.SECONDS) }.cause is IllegalStateException)
        assertEquals(0, scheduler.snapshot().queued)
        first.finish()
        scheduler.admit("workspace-b").finish()
        assertEmpty(scheduler)
    }

    @Test
    fun `concurrent success and failures reclaim every permit within both caps`() = withWorkers { workers ->
        val scheduler = AcpExecutionScheduler(AcpSchedulingLimits(
            maximumActive = 4,
            maximumActivePerWorkspace = 2,
            maximumQueued = 64,
            maximumQueuedPerWorkspace = 16,
        ))
        val active = AtomicInteger()
        val groupActive = List(3) { AtomicInteger() }
        val started = CountDownLatch(1)
        val tasks = (0 until 48).map { index ->
            workers.submit(Callable {
                assertTrue(started.await(2, TimeUnit.SECONDS))
                val group = index % groupActive.size
                val permit = scheduler.admit("workspace-$group")
                try {
                    assertTrue(active.incrementAndGet() <= 4)
                    assertTrue(groupActive[group].incrementAndGet() <= 2)
                    Thread.sleep(2)
                    if (index % 5 == 0) throw SyntheticWorkFailure()
                } catch (_: SyntheticWorkFailure) {
                    // A provider failure still crosses the same cleanup/release boundary.
                } finally {
                    groupActive[group].decrementAndGet()
                    active.decrementAndGet()
                    permit.finish()
                    permit.finish()
                }
            })
        }
        started.countDown()
        tasks.forEach { it.get(3, TimeUnit.SECONDS) }
        assertEquals(0, active.get())
        assertTrue(groupActive.all { it.get() == 0 })
        assertEmpty(scheduler)
    }

    @Test
    fun `spare capacity is reserved before the first observer can block`() = withWorkers { workers ->
        val scheduler = scheduler(active = 1, queued = 1, queuedPerWorkspace = 1)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val first = workers.submit(Callable {
            scheduler.acquire("workspace-a", AgentCancellation {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS))
                false
            }) { false }
        })
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertEquals(AcpSchedulingSnapshot(1, 0, 1, 0), scheduler.snapshot())
            val later = workers.submit(Callable { scheduler.admit("workspace-b") })
            awaitQueued(scheduler, 1)
            assertFalse(later.isDone)
            release.countDown()
            val permit = assertNotNull(first.get(2, TimeUnit.SECONDS))
            assertFalse(later.isDone)
            permit.finish()
            later.get(2, TimeUnit.SECONDS).finish()
            assertEmpty(scheduler)
        } finally {
            release.countDown()
        }
    }

    @Test
    fun `fair timed contention refreshes a reserved slot without an uncontended probe`() = withWorkers { workers ->
        val timedCalls = AtomicInteger()
        val contended = object : java.util.concurrent.locks.ReentrantLock(true) {
            override fun tryLock(timeout: Long, unit: TimeUnit): Boolean {
                if (timeout == 0L) return false
                timedCalls.incrementAndGet()
                return super.tryLock(timeout, unit)
            }
        }
        val scheduler = AcpExecutionScheduler(AcpSchedulingLimits(maximumActive = 1,
            maximumQueueWait = Duration.ofSeconds(3)), lock = contended)
        val first = scheduler.admit("workspace-a")
        val observedReservation = AtomicBoolean()
        val pending = workers.submit(Callable {
            scheduler.acquire("workspace-b", AgentCancellation {
                val snapshot = scheduler.snapshot()
                if (snapshot.active == 1 && snapshot.queued == 0) observedReservation.set(true)
                false
            }) { false }
        })
        awaitQueued(scheduler, 1)
        first.finish()
        val permit = assertNotNull(pending.get(2, TimeUnit.SECONDS))
        assertTrue(observedReservation.get(), "fresh observations must follow the capacity reservation")
        assertTrue(timedCalls.get() > 0)
        permit.finish()
        assertEmpty(scheduler)
    }

    @Test
    fun `cancelled and expired calls precede full ingress and quarantine failures`() = withWorkers { workers ->
        val scheduler = scheduler(active = 1, queued = 1, queuedPerWorkspace = 1)
        val first = scheduler.admit("workspace-a")
        val cancellation = AgentCancellationSource()
        val queued = workers.submit(Callable { scheduler.acquire("workspace-b", cancellation.cancellation) { false } })
        awaitQueued(scheduler, 1)
        assertNull(scheduler.acquire("workspace-c", AgentCancellation { true }) { false })
        assertSchedulingFailure(AgentFailureKind.TIMEOUT, "requestDeadline") {
            scheduler.acquire("workspace-c", AgentCancellation.NONE) { true }
        }
        assertEquals(AcpSchedulingSnapshot(1, 1, 1, 0), scheduler.snapshot())
        cancellation.cancel()
        assertNull(queued.get(2, TimeUnit.SECONDS))
        first.finish()
        assertEmpty(scheduler)
        val retained = scheduler.admit("workspace-q")
        retained.finish(cleanupUnverified = true)
        assertNull(scheduler.acquire("workspace-q", AgentCancellation { true }) { false })
        assertSchedulingFailure(AgentFailureKind.TIMEOUT, "requestDeadline") {
            scheduler.acquire("workspace-q", AgentCancellation.NONE) { true }
        }
        assertEquals(AcpSchedulingSnapshot(1, 0, 1, 1), scheduler.snapshot())
    }

    @Test
    fun `observer failure cancellation and expiry release unused active reservations`() {
        val scheduler = scheduler(active = 1, queued = 1, queuedPerWorkspace = 1)
        val original = IllegalStateException("synthetic observer failure")
        val thrown = assertFailsWith<IllegalStateException> {
            scheduler.acquire("workspace-a", AgentCancellation { throw original }) { false }
        }
        kotlin.test.assertSame(original, thrown)
        assertEmpty(scheduler)
        assertNull(scheduler.acquire("workspace-a", AgentCancellation { true }) { false })
        assertEmpty(scheduler)
        assertSchedulingFailure(AgentFailureKind.TIMEOUT, "requestDeadline") {
            scheduler.acquire("workspace-a", AgentCancellation.NONE) { true }
        }
        assertEmpty(scheduler)
        scheduler.admit("workspace-b").finish()
        assertEmpty(scheduler)
    }

    @Test
    fun `quarantine invalidates an unused same workspace reservation before grant`() = withWorkers { workers ->
        val scheduler = AcpExecutionScheduler(AcpSchedulingLimits(maximumActive = 2,
            maximumActivePerWorkspace = 2, maximumQueued = 2, maximumQueuedPerWorkspace = 2))
        val active = scheduler.admit("workspace-a")
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val pending = workers.submit(Callable {
            scheduler.acquire("workspace-a", AgentCancellation {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS))
                false
            }) { false }
        })
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertEquals(AcpSchedulingSnapshot(2, 0, 1, 0), scheduler.snapshot())
            active.finish(cleanupUnverified = true)
            release.countDown()
            val thrown = assertFailsWith<ExecutionException> { pending.get(2, TimeUnit.SECONDS) }
            val failure = assertIs<AgentExecutionException>(thrown.cause)
            assertEquals(AgentFailureKind.UNAVAILABLE, failure.failure.kind)
            assertEquals(mapOf("phase" to "scheduler", "reason" to "cleanupUnverified"), failure.failure.details)
            assertFalse(failure.failure.retryable)
            assertEquals(AcpSchedulingSnapshot(1, 0, 1, 1), scheduler.snapshot())
            scheduler.admit("workspace-b").finish()
            assertEquals(AcpSchedulingSnapshot(1, 0, 1, 1), scheduler.snapshot())
        } finally {
            release.countDown()
            active.finish()
        }
    }

    @Test
    fun `initial mutex contenders are bounded and expire without needing that mutex`() = withWorkers { workers ->
        val clock = java.util.concurrent.atomic.AtomicLong()
        val attempting = CountDownLatch(2)
        val releaseAttempts = CountDownLatch(1)
        val seen = java.util.concurrent.ConcurrentHashMap.newKeySet<Thread>()
        val held = object : java.util.concurrent.locks.ReentrantLock(true) {
            override fun tryLock(timeout: Long, unit: TimeUnit): Boolean {
                if (seen.add(Thread.currentThread())) {
                    attempting.countDown()
                    check(releaseAttempts.await(5, TimeUnit.SECONDS))
                }
                return super.tryLock(timeout, unit)
            }
        }
        val budget = Duration.ofSeconds(1)
        val scheduler = AcpExecutionScheduler(AcpSchedulingLimits(maximumActive = 1,
            maximumQueued = 1, maximumQueuedPerWorkspace = 1, maximumQueueWait = budget),
            lock = held, nanoTime = clock::get)
        held.lock()
        try {
            val calls = (0..1).map { index -> workers.submit(Callable {
                scheduler.acquire("workspace-$index", AgentCancellation.NONE) { false }
            }) }
            assertTrue(attempting.await(2, TimeUnit.SECONDS))
            assertSchedulingFailure(AgentFailureKind.RESOURCE_EXHAUSTED, "queueCapacity") {
                scheduler.acquire("workspace-extra", AgentCancellation.NONE) { false }
            }
            clock.set(budget.toNanos() + 1)
            releaseAttempts.countDown()
            for (call in calls) {
                val thrown = assertFailsWith<ExecutionException> { call.get(2, TimeUnit.SECONDS) }
                val failure = assertIs<AgentExecutionException>(thrown.cause)
                assertEquals(AgentFailureKind.TIMEOUT, failure.failure.kind)
                assertEquals(mapOf("phase" to "scheduler", "reason" to "queueDeadline"), failure.failure.details)
            }
            assertEmpty(scheduler)
        } finally {
            releaseAttempts.countDown()
            held.unlock()
        }
        scheduler.admit("workspace-fresh").finish()
        assertEmpty(scheduler)
    }

    @Test
    fun `interruption cancels initial mutex admission and preserves the caller flag`() = withWorkers { workers ->
        val attempting = CountDownLatch(1)
        val caller = java.util.concurrent.atomic.AtomicReference<Thread>()
        val held = object : java.util.concurrent.locks.ReentrantLock(true) {
            override fun tryLock(timeout: Long, unit: TimeUnit): Boolean {
                caller.set(Thread.currentThread())
                attempting.countDown()
                return super.tryLock(timeout, unit)
            }
        }
        val scheduler = AcpExecutionScheduler(AcpSchedulingLimits(maximumActive = 1), lock = held)
        held.lock()
        try {
            val pending = workers.submit(Callable {
                val permit = scheduler.acquire("workspace-a", AgentCancellation.NONE) { false }
                permit to Thread.currentThread().isInterrupted
            })
            assertTrue(attempting.await(2, TimeUnit.SECONDS))
            caller.get().interrupt()
            val result = pending.get(2, TimeUnit.SECONDS)
            assertNull(result.first)
            assertTrue(result.second)
            assertEmpty(scheduler)
        } finally {
            held.unlock()
        }
        scheduler.admit("workspace-fresh").finish()
        assertEmpty(scheduler)
    }

    private class SyntheticWorkFailure : RuntimeException()

    private fun scheduler(
        active: Int,
        queued: Int = 16,
        queuedPerWorkspace: Int = 8,
        queueWait: Duration = Duration.ofSeconds(3),
    ) = AcpExecutionScheduler(AcpSchedulingLimits(
        maximumActive = active,
        maximumQueued = queued,
        maximumQueuedPerWorkspace = queuedPerWorkspace,
        maximumQueueWait = queueWait,
    ))

    private fun AcpExecutionScheduler.admit(group: String): AcpExecutionScheduler.Permit =
        assertNotNull(acquire(group, AgentCancellation.NONE) { false })

    private fun assertEmpty(scheduler: AcpExecutionScheduler) =
        assertEquals(AcpSchedulingSnapshot(0, 0, 0, 0), scheduler.snapshot())

    private fun awaitQueued(scheduler: AcpExecutionScheduler, count: Int) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (scheduler.snapshot().queued != count && System.nanoTime() < deadline) Thread.sleep(2)
        assertEquals(count, scheduler.snapshot().queued)
    }

    private fun assertSchedulingFailure(
        kind: AgentFailureKind,
        reason: String,
        operation: () -> Unit,
    ): AgentExecutionException = assertFailsWith<AgentExecutionException>(block = operation).also {
        assertEquals(kind, it.failure.kind)
        assertEquals(mapOf("phase" to "scheduler", "reason" to reason), it.failure.details)
    }

    private fun withWorkers(block: (ExecutorService) -> Unit) {
        val workers = Executors.newFixedThreadPool(8)
        try {
            block(workers)
        } finally {
            workers.shutdownNow()
            assertTrue(workers.awaitTermination(2, TimeUnit.SECONDS), "scheduler waiters must not outlive the test")
        }
    }
}
